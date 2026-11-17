//! Smart auto-healing local Telegram SOCKS5 proxy (`127.0.0.1:10809`) + built-in `TG-WS` WebSocket
//! bridge (`wss://kws{1..5}.web.telegram.org/apiws` with TLS ClientHello fragmentation).
//!
//! User adds `tg://socks?server=127.0.0.1&port=10809` to Telegram ONCE. For every connection:
//! 1. If destination is a Telegram DC and `TG-WS` direct WebSocket over TLS 443 is verified ≤ 1400 ms,
//!    tunnels MTProto bytes as binary WebSocket frames straight to Telegram's official web servers
//!    (zero third-party proxy, minimal latency!).
//! 2. Otherwise (including Telegram voice/video call relays, or if `kws*.web.telegram.org` is blocked),
//!    automatically connects via the fastest verified ≤ 1400 ms SOCKS5 proxy in our live pool,
//!    instantaneously failing over to #2, #3 if the primary drops!
//! 3. If the local VPN core (`127.0.0.1:10808`) is running, also uses it as an ultra-fast fallback.

use crate::net_util::{
    resolve_host_resilient, socks5_connect, FragmentedTcpStream, TLS_CONFIG_VERIFIED,
};
use crate::tg_checker::{
    build_obfuscated2_init, build_req_pq_multi_frame, validate_res_pq_payload, VerifiedTgProxy,
};
use cipher::StreamCipher;
use rustls::pki_types::ServerName;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

/// Map official Telegram datacenter IPv4 address -> DC number (1..=5) for `kws{N}.web.telegram.org`.
pub fn telegram_ip_to_dc(ip: Ipv4Addr) -> Option<u8> {
    let o = ip.octets();
    match (o[0], o[1], o[2]) {
        (149, 154, 175) => Some(1), // DC1 Miami
        (149, 154, 167) => {
            if o[3] >= 80 {
                Some(4) // DC4 Amsterdam
            } else {
                Some(2) // DC2 Amsterdam
            }
        }
        (149, 154, 164) | (149, 154, 165) | (149, 154, 166) => Some(2),
        (149, 154, 171) => Some(5), // DC5 Singapore
        (91, 108, 56) => Some(5),
        (91, 108, 4) => Some(4),
        (91, 108, 8) | (91, 108, 12) | (91, 108, 16) => Some(2),
        (91, 108, 58) => Some(1),
        (185, 76, 151) => Some(2),
        _ => None,
    }
}

fn kws_host_for_dc(dc: u8) -> &'static str {
    match dc {
        1 => "kws1.web.telegram.org",
        2 => "kws2.web.telegram.org",
        3 => "kws3.web.telegram.org",
        4 => "kws4.web.telegram.org",
        5 => "kws5.web.telegram.org",
        _ => "kws2.web.telegram.org",
    }
}

async fn open_tg_ws_stream(
    dc: u8,
    connect_budget: Duration,
) -> Result<(tokio_rustls::client::TlsStream<FragmentedTcpStream>, Vec<u8>), String> {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;
    use rand::Rng;

    let host = kws_host_for_dc(dc);
    let start = Instant::now();
    let ips = resolve_host_resilient(host).await?;
    let ip = ips
        .into_iter()
        .find(|i| i.is_ipv4())
        .ok_or_else(|| format!("no IPv4 for {host}"))?;

    let rem = connect_budget
        .saturating_sub(start.elapsed())
        .max(Duration::from_millis(300));
    let tcp = timeout(rem, TcpStream::connect(SocketAddr::new(ip, 443)))
        .await
        .map_err(|_| "kws tcp timeout".to_string())?
        .map_err(|e| e.to_string())?;
    let _ = tcp.set_nodelay(true);
    let frag = FragmentedTcpStream::new(tcp, true);

    let sni = ServerName::try_from(host.to_string()).map_err(|e| e.to_string())?;
    let connector = TlsConnector::from(TLS_CONFIG_VERIFIED.clone());
    let rem = connect_budget
        .saturating_sub(start.elapsed())
        .max(Duration::from_millis(300));
    let mut tls = timeout(rem, connector.connect(sni, frag))
        .await
        .map_err(|_| "kws tls timeout".to_string())?
        .map_err(|e| e.to_string())?;

    let mut ws_key = [0u8; 16];
    rand::thread_rng().fill(&mut ws_key);
    let key_b64 = B64.encode(ws_key);
    let upgrade = format!(
        "GET /apiws HTTP/1.1\r\n\
         Host: {host}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: {key_b64}\r\n\
         Sec-WebSocket-Version: 13\r\n\
         Sec-WebSocket-Protocol: binary\r\n\
         Origin: https://web.telegram.org\r\n\
         User-Agent: Mozilla/5.0 (Linux; Android 12) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36\r\n\r\n"
    );

    let rem = connect_budget
        .saturating_sub(start.elapsed())
        .max(Duration::from_millis(300));
    timeout(rem, tls.write_all(upgrade.as_bytes()))
        .await
        .map_err(|_| "kws ws write timeout".to_string())?
        .map_err(|e| e.to_string())?;

    // Read HTTP 101 Switching Protocols header cleanly
    let mut hdr = Vec::with_capacity(512);
    let mut tmp = [0u8; 512];
    let hdr_end = loop {
        let rem = connect_budget
            .saturating_sub(start.elapsed())
            .max(Duration::from_millis(250));
        let n = timeout(rem, tls.read(&mut tmp))
            .await
            .map_err(|_| "kws ws upgrade timeout".to_string())?
            .map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("kws ws upgrade EOF".into());
        }
        hdr.extend_from_slice(&tmp[..n]);
        if let Some(pos) = hdr.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        if hdr.len() > 8192 {
            return Err("kws ws header > 8KiB".into());
        }
    };
    let status_line = String::from_utf8_lossy(&hdr[..hdr_end.min(48)]);
    if !status_line.contains(" 101 ") {
        return Err(format!("kws ws rejected: {}", status_line.trim()));
    }
    let leftover = hdr[hdr_end..].to_vec();
    Ok((tls, leftover))
}

/// Real end-to-end verification of `wss://kws2.web.telegram.org/apiws` using a genuine
/// MTProto `obfuscated2` + `req_pq_multi -> resPQ` exchange within `max_rtt_ms` (1400 ms)!
pub async fn probe_tg_ws_direct(max_rtt_ms: u32) -> Result<u32, String> {
    let budget = Duration::from_millis(max_rtt_ms.clamp(300, 3000) as u64);
    let start = Instant::now();
    let deadline = start + budget;

    let (mut ws, _leftover) = open_tg_ws_stream(2, budget).await?;

    let (obf_hdr, mut enc, mut dec) = build_obfuscated2_init(None, true, 2);
    let (mut pq_frame, nonce) = build_req_pq_multi_frame(true);
    enc.apply_keystream(&mut pq_frame);

    // Send obfuscated2 64B header + req_pq_multi as RFC 6455 binary WebSocket frames
    ws_send_binary(&mut ws, &obf_hdr, deadline).await?;
    ws_send_binary(&mut ws, &pq_frame, deadline).await?;

    let mut plain = Vec::with_capacity(256);
    while plain.len() < 44 {
        let data = ws_recv_binary(&mut ws, deadline).await?;
        let idx = plain.len();
        plain.extend_from_slice(&data);
        dec.apply_keystream(&mut plain[idx..]);
        if plain.len() >= 4 {
            let need = u32::from_le_bytes(plain[0..4].try_into().unwrap()) as usize;
            if !(40..=4096).contains(&need) {
                return Err(format!("kws bad resPQ len {need}"));
            }
            if plain.len() >= 4 + need {
                break;
            }
        }
    }
    let need = u32::from_le_bytes(plain[0..4].try_into().unwrap()) as usize;
    while plain.len() < 4 + need {
        let data = ws_recv_binary(&mut ws, deadline).await?;
        let idx = plain.len();
        plain.extend_from_slice(&data);
        dec.apply_keystream(&mut plain[idx..]);
    }
    validate_res_pq_payload(&plain[4..4 + need], &nonce)?;

    let rtt = start.elapsed().as_millis() as u32;
    if rtt > max_rtt_ms {
        return Err(format!("kws rtt {rtt}ms > {max_rtt_ms}ms"));
    }
    Ok(rtt)
}

async fn ws_send_binary<S: tokio::io::AsyncWrite + Unpin>(
    ws: &mut S,
    data: &[u8],
    deadline: Instant,
) -> Result<(), String> {
    let frame = encode_ws_client_binary_frame(data);
    let rem = deadline.saturating_duration_since(Instant::now());
    if rem.is_zero() {
        return Err("ws send deadline".into());
    }
    timeout(rem, ws.write_all(&frame))
        .await
        .map_err(|_| "ws raw write timeout".to_string())?
        .map_err(|e| e.to_string())?;
    let rem = deadline.saturating_duration_since(Instant::now());
    timeout(rem, ws.flush())
        .await
        .map_err(|_| "ws flush timeout".to_string())?
        .map_err(|e| e.to_string())?;
    Ok(())
}

fn encode_ws_client_binary_frame(payload: &[u8]) -> Vec<u8> {
    use rand::Rng;
    let mut mask = [0u8; 4];
    rand::thread_rng().fill(&mut mask);

    let len = payload.len();
    let mut out = Vec::with_capacity(14 + len);
    out.push(0x82); // FIN=1, opcode=2 (Binary)
    if len <= 125 {
        out.push(0x80 | (len as u8)); // MASK=1
    } else if len <= 65535 {
        out.push(0x80 | 126);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push(0x80 | 127);
        out.extend_from_slice(&(len as u64).to_be_bytes());
    }
    out.extend_from_slice(&mask);
    for (i, &b) in payload.iter().enumerate() {
        out.push(b ^ mask[i & 3]);
    }
    out
}

async fn read_ws_server_frame<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
) -> Result<(u8, Vec<u8>), String> {
    let mut h2 = [0u8; 2];
    stream.read_exact(&mut h2).await.map_err(|e| e.to_string())?;
    let opcode = h2[0] & 0x0f;
    let masked = (h2[1] & 0x80) != 0;
    let len7 = (h2[1] & 0x7f) as usize;
    let payload_len = if len7 == 126 {
        let mut b = [0u8; 2];
        stream.read_exact(&mut b).await.map_err(|e| e.to_string())?;
        u16::from_be_bytes(b) as usize
    } else if len7 == 127 {
        let mut b = [0u8; 8];
        stream.read_exact(&mut b).await.map_err(|e| e.to_string())?;
        let v = u64::from_be_bytes(b);
        if v > 4 * 1024 * 1024 {
            return Err("ws frame > 4MiB".into());
        }
        v as usize
    } else {
        len7
    };
    let mut mask = [0u8; 4];
    if masked {
        stream.read_exact(&mut mask).await.map_err(|e| e.to_string())?;
    }
    let mut payload = vec![0u8; payload_len];
    if payload_len > 0 {
        stream
            .read_exact(&mut payload)
            .await
            .map_err(|e| e.to_string())?;
        if masked {
            for (i, b) in payload.iter_mut().enumerate() {
                *b ^= mask[i & 3];
            }
        }
    }
    Ok((opcode, payload))
}

async fn ws_recv_binary<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    ws: &mut S,
    deadline: Instant,
) -> Result<Vec<u8>, String> {
    loop {
        let rem = deadline.saturating_duration_since(Instant::now());
        if rem.is_zero() {
            return Err("ws recv deadline".into());
        }
        let (opcode, payload) = timeout(rem, read_ws_server_frame(ws))
            .await
            .map_err(|_| "ws recv timeout".to_string())??;
        match opcode {
            0x01 | 0x02 | 0x00 => {
                if !payload.is_empty() {
                    return Ok(payload);
                }
            }
            0x09 => {
                let mut pong = encode_ws_client_binary_frame(&payload);
                pong[0] = 0x8A;
                let _ = ws.write_all(&pong).await;
            }
            0x08 => return Err("ws closed by Telegram kws".into()),
            _ => {}
        }
    }
}

pub struct TgLocalBridge {
    pub running: AtomicBool,
    pub ws_available: AtomicBool,
    pub ws_rtt_ms: AtomicU32,
    pub port: AtomicU32,
    pub active_sessions: AtomicU64,
    pub relayed_bytes: AtomicU64,
    pub socks_pool: RwLock<Vec<VerifiedTgProxy>>,
    pub stop_notify: Notify,
}

impl Default for TgLocalBridge {
    fn default() -> Self {
        Self {
            running: AtomicBool::new(false),
            ws_available: AtomicBool::new(false),
            ws_rtt_ms: AtomicU32::new(0),
            port: AtomicU32::new(10809),
            active_sessions: AtomicU64::new(0),
            relayed_bytes: AtomicU64::new(0),
            socks_pool: RwLock::new(Vec::new()),
            stop_notify: Notify::new(),
        }
    }
}

impl TgLocalBridge {
    pub fn update_pool(&self, proxies: &[VerifiedTgProxy]) {
        let mut socks_only: Vec<VerifiedTgProxy> = proxies
            .iter()
            .filter(|p| p.kind == "socks5")
            .cloned()
            .collect();
        socks_only.sort_by_key(|p| p.rtt_ms);
        if let Ok(mut guard) = self.socks_pool.write() {
            *guard = socks_only;
        }
    }

    pub fn stop(&self) {
        if self.running.swap(false, Ordering::SeqCst) {
            self.stop_notify.notify_waiters();
        }
    }
}

/// Spawn the lightweight local auto-healing Telegram SOCKS5 bridge on `127.0.0.1:listen_port`.
pub async fn start_tg_bridge(bridge: Arc<TgLocalBridge>, listen_port: u16, max_rtt_ms: u32) -> Result<u16, String> {
    if bridge.running.load(Ordering::SeqCst) {
        return Ok(bridge.port.load(Ordering::Relaxed) as u16);
    }

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), listen_port);
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|e| format!("bind 127.0.0.1:{listen_port}: {e}"))?;
    let bound_port = listener.local_addr().map(|a| a.port()).unwrap_or(listen_port);

    bridge.port.store(bound_port as u32, Ordering::Relaxed);
    bridge.running.store(true, Ordering::SeqCst);

    // Probe TG-WS direct path in background so startup is instant
    let b_probe = bridge.clone();
    tokio::spawn(async move {
        match probe_tg_ws_direct(max_rtt_ms).await {
            Ok(ms) => {
                b_probe.ws_rtt_ms.store(ms, Ordering::Relaxed);
                b_probe.ws_available.store(true, Ordering::Relaxed);
            }
            Err(_) => {
                b_probe.ws_available.store(false, Ordering::Relaxed);
            }
        }
    });

    let b_loop = bridge.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = b_loop.stop_notify.notified() => {
                    break;
                }
                acc = listener.accept() => {
                    match acc {
                        Ok((client, _)) => {
                            let bc = b_loop.clone();
                            tokio::spawn(async move {
                                bc.active_sessions.fetch_add(1, Ordering::Relaxed);
                                let _ = handle_socks5_client(client, &bc).await;
                                bc.active_sessions.fetch_sub(1, Ordering::Relaxed);
                            });
                        }
                        Err(_) => {
                            tokio::time::sleep(Duration::from_millis(50)).await;
                        }
                    }
                }
            }
            if !b_loop.running.load(Ordering::SeqCst) {
                break;
            }
        }
        b_loop.running.store(false, Ordering::SeqCst);
    });

    Ok(bound_port)
}

async fn handle_socks5_client(mut client: TcpStream, bridge: &TgLocalBridge) -> Result<(), String> {
    let _ = client.set_nodelay(true);

    // 1. Read SOCKS5 greeting
    let mut g_hdr = [0u8; 2];
    timeout(Duration::from_secs(5), client.read_exact(&mut g_hdr))
        .await
        .map_err(|_| "greet timeout".to_string())?
        .map_err(|e| e.to_string())?;
    if g_hdr[0] != 0x05 {
        return Err("not socks5".into());
    }
    let mut methods = vec![0u8; g_hdr[1] as usize];
    client
        .read_exact(&mut methods)
        .await
        .map_err(|e| e.to_string())?;
    client
        .write_all(&[0x05, 0x00])
        .await
        .map_err(|e| e.to_string())?;

    // 2. Read CONNECT request
    let mut req_hdr = [0u8; 4];
    timeout(Duration::from_secs(5), client.read_exact(&mut req_hdr))
        .await
        .map_err(|_| "req timeout".to_string())?
        .map_err(|e| e.to_string())?;
    if req_hdr[0] != 0x05 || req_hdr[1] != 0x01 {
        let _ = client
            .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await;
        return Err("unsupported cmd".into());
    }

    let (target_host, target_v4): (String, Option<Ipv4Addr>) = match req_hdr[3] {
        0x01 => {
            let mut b = [0u8; 4];
            client.read_exact(&mut b).await.map_err(|e| e.to_string())?;
            let ip = Ipv4Addr::from(b);
            (ip.to_string(), Some(ip))
        }
        0x03 => {
            let mut l = [0u8; 1];
            client.read_exact(&mut l).await.map_err(|e| e.to_string())?;
            let mut d = vec![0u8; l[0] as usize];
            client.read_exact(&mut d).await.map_err(|e| e.to_string())?;
            let s = String::from_utf8(d).map_err(|e| e.to_string())?;
            let v4 = s.parse::<Ipv4Addr>().ok();
            (s, v4)
        }
        0x04 => {
            let mut b = [0u8; 16];
            client.read_exact(&mut b).await.map_err(|e| e.to_string())?;
            let ip = std::net::Ipv6Addr::from(b);
            (ip.to_string(), None)
        }
        _ => return Err("bad atyp".into()),
    };

    let mut pb = [0u8; 2];
    client.read_exact(&mut pb).await.map_err(|e| e.to_string())?;
    let target_port = u16::from_be_bytes(pb);

    let _ = client.set_nodelay(true);

    // Path 1: Direct TG-WS WebSocket bridge for Telegram DC port 443 traffic
    if target_port == 443 && bridge.ws_available.load(Ordering::Relaxed) {
        if let Some(dc) = target_v4.and_then(telegram_ip_to_dc) {
            if let Ok((ws_tls, leftover)) = open_tg_ws_stream(dc, Duration::from_millis(2500)).await
            {
                client
                    .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await
                    .map_err(|e| e.to_string())?;
                return relay_tcp_with_ws(client, ws_tls, leftover, bridge).await;
            }
        }
    }

    // Path 2: Auto-failover across top verified <= 1400 ms SOCKS5 proxies (also supports TG calls!)
    let pool: Vec<VerifiedTgProxy> = bridge
        .socks_pool
        .read()
        .map(|g| g.iter().take(5).cloned().collect())
        .unwrap_or_default();

    for p in &pool {
        let Ok(ips) = resolve_host_resilient(&p.host).await else {
            continue;
        };
        let Some(ip) = ips.into_iter().find(|i| i.is_ipv4()) else {
            continue;
        };
        let auth = if p.username.is_empty() {
            None
        } else {
            Some((p.username.as_str(), p.password.as_str()))
        };
        if let Ok(mut upstream) = socks5_connect(
            SocketAddr::new(ip, p.port),
            auth,
            &target_host,
            target_port,
            Duration::from_millis(2400),
        )
        .await
        {
            client
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .map_err(|e| e.to_string())?;
            if let Ok((up, down)) =
                tokio::io::copy_bidirectional_with_sizes(&mut client, &mut upstream, 8192, 8192)
                    .await
            {
                bridge.relayed_bytes.fetch_add(up + down, Ordering::Relaxed);
            }
            return Ok(());
        }
    }

    // Path 3: Active local VPN core SOCKS5 on 127.0.0.1:10808 if running (uses session auth!)
    let local_vpn = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 10808);
    let sess_auth = crate::net_util::local_socks_auth_for(local_vpn);
    let sess_auth_ref = sess_auth.as_ref().map(|(u, p)| (u.as_str(), p.as_str()));
    if let Ok(mut upstream) = socks5_connect(
        local_vpn,
        sess_auth_ref,
        &target_host,
        target_port,
        Duration::from_millis(2000),
    )
    .await
    {
        client
            .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .map_err(|e| e.to_string())?;
        if let Ok((up, down)) =
            tokio::io::copy_bidirectional_with_sizes(&mut client, &mut upstream, 8192, 8192).await
        {
            bridge.relayed_bytes.fetch_add(up + down, Ordering::Relaxed);
        }
        return Ok(());
    }

    // Path 4: Last-resort try TG-WS even if initial probe wasn't cached yet
    if let Some(dc) = target_v4.and_then(telegram_ip_to_dc) {
        if let Ok((ws_tls, leftover)) = open_tg_ws_stream(dc, Duration::from_millis(3000)).await {
            bridge.ws_available.store(true, Ordering::Relaxed);
            client
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .map_err(|e| e.to_string())?;
            return relay_tcp_with_ws(client, ws_tls, leftover, bridge).await;
        }
    }

    let _ = client
        .write_all(&[0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await;
    Err("all TG bridge upstreams failed".into())
}

fn encode_ws_client_control_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
    use rand::Rng;
    let body = if payload.len() > 125 {
        &payload[..125]
    } else {
        payload
    };
    let mut mask = [0u8; 4];
    rand::thread_rng().fill(&mut mask);
    let mut out = Vec::with_capacity(6 + body.len());
    out.push(0x80 | (opcode & 0x0f));
    out.push(0x80 | (body.len() as u8));
    out.extend_from_slice(&mask);
    for (i, b) in body.iter().enumerate() {
        out.push(*b ^ mask[i & 3]);
    }
    out
}

async fn relay_tcp_with_ws(
    client: TcpStream,
    ws_tls: tokio_rustls::client::TlsStream<FragmentedTcpStream>,
    leftover: Vec<u8>,
    bridge: &TgLocalBridge,
) -> Result<(), String> {
    let (mut c_rd, mut c_wr) = tokio::io::split(client);
    let (w_rd_raw, mut w_wr) = tokio::io::split(ws_tls);
    // Preserve every single byte piggybacked after `HTTP/1.1 101 Switching Protocols`!
    let mut w_rd = tokio::io::AsyncReadExt::chain(std::io::Cursor::new(leftover), w_rd_raw);
    let (pong_tx, mut pong_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(4);

    let c2w = async {
        // Compact 8 KiB buffer (halves idle per-socket RAM vs 16 KiB with identical MTProto speed!)
        let mut buf = vec![0u8; 8192];
        let mut total = 0u64;
        let mut init_rem = 64usize;
        let mut init_buf = Vec::with_capacity(64);
        loop {
            tokio::select! {
                Some(ping_payload) = pong_rx.recv() => {
                    // RFC 6455 §5.5.2: answer server Ping (0x09) with masked Pong (0x0A) so long TG sessions never drop!
                    let pong = encode_ws_client_control_frame(0x0A, &ping_payload);
                    if w_wr.write_all(&pong).await.is_err() || w_wr.flush().await.is_err() {
                        break;
                    }
                }
                rd = c_rd.read(&mut buf) => {
                    let n = match rd {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    // Telegram kws1..5 requires the 64-byte obfuscated2 header as its own initial WS frame!
                    if init_rem > 0 {
                        let take = n.min(init_rem);
                        init_buf.extend_from_slice(&buf[..take]);
                        init_rem -= take;
                        if init_rem == 0 {
                            let f1 = encode_ws_client_binary_frame(&init_buf);
                            if w_wr.write_all(&f1).await.is_err() {
                                break;
                            }
                            if n > take {
                                let f2 = encode_ws_client_binary_frame(&buf[take..n]);
                                if w_wr.write_all(&f2).await.is_err() {
                                    break;
                                }
                            }
                            let _ = w_wr.flush().await;
                        }
                        total += n as u64;
                        continue;
                    }
                    let frame = encode_ws_client_binary_frame(&buf[..n]);
                    if w_wr.write_all(&frame).await.is_err() {
                        break;
                    }
                    let _ = w_wr.flush().await;
                    total += n as u64;
                }
            }
        }
        total
    };

    let w2c = async {
        let mut total = 0u64;
        loop {
    let Ok((opcode, payload)) =
                timeout(Duration::from_secs(360), read_ws_server_frame_half(&mut w_rd))
                    .await
                    .map_err(|_| String::new())
                    .and_then(|r| r)
            else {
                break;
            };
            match opcode {
                0x00 | 0x01 | 0x02 => {
                    if !payload.is_empty() {
                        if c_wr.write_all(&payload).await.is_err() {
                            break;
                        }
                        total += payload.len() as u64;
                    }
                }
                0x09 => {
                    let _ = pong_tx.try_send(payload);
                }
                0x08 => break,
                _ => {}
            }
        }
        total
    };

    tokio::select! {
        b = c2w => { bridge.relayed_bytes.fetch_add(b, Ordering::Relaxed); }
        b = w2c => { bridge.relayed_bytes.fetch_add(b, Ordering::Relaxed); }
    }
    Ok(())
}

async fn read_ws_server_frame_half<R: tokio::io::AsyncRead + Unpin>(
    stream: &mut R,
) -> Result<(u8, Vec<u8>), String> {
    let mut h2 = [0u8; 2];
    stream.read_exact(&mut h2).await.map_err(|e| e.to_string())?;
    let opcode = h2[0] & 0x0f;
    let masked = (h2[1] & 0x80) != 0;
    let len7 = (h2[1] & 0x7f) as usize;
    let payload_len = if len7 == 126 {
        let mut b = [0u8; 2];
        stream.read_exact(&mut b).await.map_err(|e| e.to_string())?;
        u16::from_be_bytes(b) as usize
    } else if len7 == 127 {
        let mut b = [0u8; 8];
        stream.read_exact(&mut b).await.map_err(|e| e.to_string())?;
        let v = u64::from_be_bytes(b);
        if v > 4 * 1024 * 1024 {
            return Err("ws frame too large".into());
        }
        v as usize
    } else {
        len7
    };
    let mut mask = [0u8; 4];
    if masked {
        stream.read_exact(&mut mask).await.map_err(|e| e.to_string())?;
    }
    let mut payload = vec![0u8; payload_len];
    if payload_len > 0 {
        stream
            .read_exact(&mut payload)
            .await
            .map_err(|e| e.to_string())?;
        if masked {
            for (i, b) in payload.iter_mut().enumerate() {
                *b ^= mask[i & 3];
            }
        }
    }
    Ok((opcode, payload))
}
