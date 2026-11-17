//! Censorship-resistant networking primitives:
//! - DNS-over-HTTPS (DoH) directly to literal IPs (1.1.1.1, 1.0.0.1, 8.8.8.8, 9.9.9.9)
//! - TLS ClientHello record fragmentation (splits first TLS Handshake record into small TLS records
//!   so TSPU SNI filters cannot reassemble single-record ClientHello signatures)
//! - Lightweight HTTP/1.1 client (GET/POST/PATCH, chunked & Content-Length, redirects, optional SOCKS5,
//!   optional custom SNI / insecure-bootstrap for SurfEasy API)
//! - Automatic GitHub raw -> jsDelivr (cdn / fastly / gcore) mirror cascade.

use once_cell::sync::Lazy;
use rand::Rng;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use url::Url;

/// Shared verified WebPKI TLS 1.3/1.2 client config (HTTP/1.1).
pub static TLS_CONFIG_VERIFIED: Lazy<Arc<ClientConfig>> = Lazy::new(|| {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut cfg = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(cfg)
});

/// Certificate verifier ONLY for SurfEasy discovery API bootstrap with masked/empty SNI
/// (exactly as official opera-proxy does; actual proxy servers are verified against Opera CA/hostname).
#[derive(Debug)]
struct NoVerifyCert;

impl ServerCertVerifier for NoVerifyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

pub static TLS_CONFIG_MASKED_SNI: Lazy<Arc<ClientConfig>> = Lazy::new(|| {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut cfg = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifyCert))
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    cfg.enable_sni = true;
    Arc::new(cfg)
});

/// In-memory TTL DNS cache to avoid redundant DoH lookups.
static DNS_CACHE: Lazy<RwLock<HashMap<String, (Vec<IpAddr>, Instant)>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

/// Wraps a `TcpStream` and splits the very first TLS ClientHello record (`0x16 0x03 0x01/0x03 len`)
/// into multiple valid, small TLS handshake records flushed separately over `TCP_NODELAY`.
/// Standard TLS 1.2/1.3 servers reassemble multi-record ClientHello seamlessly per RFC 8446 §5.1,
/// while stateless/shallow DPI boxes inspecting the first record for full SNI let it pass.
pub struct FragmentedTcpStream {
    inner: TcpStream,
    fragment_enabled: bool,
    first_write_done: bool,
    staged: Vec<u8>,
    staged_pos: usize,
    pending_orig_len: usize,
}

impl FragmentedTcpStream {
    pub fn new(stream: TcpStream, fragment_enabled: bool) -> Self {
        let _ = stream.set_nodelay(true);
        Self {
            inner: stream,
            fragment_enabled,
            first_write_done: false,
            staged: Vec::new(),
            staged_pos: 0,
            pending_orig_len: 0,
        }
    }
}

/// Rewrite a single TLS Handshake record (0x16, ver_hi, ver_lo, len_hi, len_lo, payload...)
/// into several smaller valid TLS Handshake records (12..42 bytes each for first 5 splits).
fn split_tls_client_hello(buf: &[u8]) -> Option<Vec<u8>> {
    if buf.len() < 16 || buf[0] != 0x16 || buf[1] != 0x03 {
        return None;
    }
    let rec_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    if 5 + rec_len > buf.len() || rec_len < 24 {
        return None;
    }
    let ver_hi = buf[1];
    let ver_lo = buf[2];
    let payload = &buf[5..5 + rec_len];
    let tail = &buf[5 + rec_len..];

    let mut out = Vec::with_capacity(buf.len() + 64);
    let mut rng = rand::thread_rng();
    let mut offset = 0usize;
    let mut splits = 0usize;
    while offset < payload.len() {
        let rem = payload.len() - offset;
        let chunk_len = if splits < 8 && rem > 20 {
            let pick = rng.gen_range(14..=38);
            pick.min(rem)
        } else {
            rem
        };
        out.push(0x16);
        out.push(ver_hi);
        out.push(ver_lo);
        out.extend_from_slice(&(chunk_len as u16).to_be_bytes());
        out.extend_from_slice(&payload[offset..offset + chunk_len]);
        offset += chunk_len;
        splits += 1;
    }
    out.extend_from_slice(tail);
    Some(out)
}

impl AsyncRead for FragmentedTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for FragmentedTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.as_mut().get_mut();

        // Drain any already-staged fragmented TLS records in small TCP writes
        if this.staged_pos < this.staged.len() {
            while this.staged_pos < this.staged.len() {
                let rem = this.staged.len() - this.staged_pos;
                let step = rem.min(47);
                match Pin::new(&mut this.inner)
                    .poll_write(cx, &this.staged[this.staged_pos..this.staged_pos + step])
                {
                    Poll::Ready(Ok(0)) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "zero write during TLS fragment",
                        )));
                    }
                    Poll::Ready(Ok(n)) => this.staged_pos += n,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            let orig = this.pending_orig_len;
            this.staged.clear();
            this.staged_pos = 0;
            this.pending_orig_len = 0;
            return Poll::Ready(Ok(orig));
        }

        if this.fragment_enabled && !this.first_write_done {
            this.first_write_done = true;
            if let Some(rewritten) = split_tls_client_hello(buf) {
                this.staged = rewritten;
                this.staged_pos = 0;
                this.pending_orig_len = buf.len();
                while this.staged_pos < this.staged.len() {
                    let rem = this.staged.len() - this.staged_pos;
                    let step = rem.min(47);
                    match Pin::new(&mut this.inner)
                        .poll_write(cx, &this.staged[this.staged_pos..this.staged_pos + step])
                    {
                        Poll::Ready(Ok(0)) => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "zero write during TLS fragment",
                            )));
                        }
                        Poll::Ready(Ok(n)) => this.staged_pos += n,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                }
                this.staged.clear();
                this.staged_pos = 0;
                this.pending_orig_len = 0;
                return Poll::Ready(Ok(buf.len()));
            }
        }

        Pin::new(&mut this.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Resolve domain via anti-spoof DoH servers by direct literal IP (no UDP port 53 poison),
/// falling back to system DNS if DoH IPs are unreachable in restrictive networks.
pub async fn resolve_host_resilient(host: &str) -> Result<Vec<IpAddr>, String> {
    if let Ok(ip) = host.trim_matches(|c| c == '[' || c == ']').parse::<IpAddr>() {
        return Ok(vec![ip]);
    }
    let key = host.to_ascii_lowercase();
    if let Ok(cache) = DNS_CACHE.read() {
        if let Some((ips, ts)) = cache.get(&key) {
            if ts.elapsed() < Duration::from_secs(300) && !ips.is_empty() {
                return Ok(ips.clone());
            }
        }
    }

    // Try anti-spoof DoH JSON over literal IPs in RF-optimal order:
    // Google (8.8.8.8) -> Quad9 (9.9.9.9) -> Yandex DoH (77.88.8.8, works under RF mobile
    // whitelists; skipped for domains filtered in RF) -> Google secondary -> Cloudflare.
    let skip_ru_doh = key.contains("cloudflare")
        || key.contains("sec-tunnel")
        || key.contains("opera")
        || key.contains("telegram");
    let doh_targets: &[(Ipv4Addr, &str, &str, bool)] = &[
        (Ipv4Addr::new(8, 8, 8, 8), "dns.google", "/resolve", false),
        (Ipv4Addr::new(9, 9, 9, 9), "dns.quad9.net", "/dns-query", false),
        (
            Ipv4Addr::new(77, 88, 8, 8),
            "common.dns.yandex.net",
            "/dns-query",
            true,
        ),
        (Ipv4Addr::new(8, 8, 4, 4), "dns.google", "/resolve", false),
        (Ipv4Addr::new(1, 1, 1, 1), "cloudflare-dns.com", "/dns-query", false),
    ];

    for (ip, sni, path, is_ru_resolver) in doh_targets {
        if *is_ru_resolver && skip_ru_doh {
            continue;
        }
        if let Ok(mut ips) = doh_query_a(*ip, sni, path, &key).await {
            ips.retain(|addr| match addr {
                IpAddr::V4(v4) => {
                    let o = v4.octets();
                    !v4.is_private()
                        && !v4.is_loopback()
                        && !v4.is_link_local()
                        && !v4.is_unspecified()
                        && o[0] != 0
                        && o[0] < 224
                }
                IpAddr::V6(v6) => !v6.is_loopback() && !v6.is_unspecified(),
            });
            if !ips.is_empty() {
                if let Ok(mut cache) = DNS_CACHE.write() {
                    cache.insert(key, (ips.clone(), Instant::now()));
                }
                return Ok(ips);
            }
        }
    }

    // Fallback to OS resolver (important under strict mobile carrier white-lists)
    if let Ok(Ok(iter)) = timeout(
        Duration::from_millis(2500),
        tokio::net::lookup_host((host, 443u16)),
    )
    .await
    {
        let mut ips: Vec<IpAddr> = iter.map(|sa| sa.ip()).collect();
        ips.dedup();
        // Filter RFC1918/loopback/CGNAT/link-local spoofed responses for public domains
        ips.retain(|ip| match ip {
            IpAddr::V4(v4) => {
                let o = v4.octets();
                !v4.is_private()
                    && !v4.is_loopback()
                    && !v4.is_link_local()
                    && !v4.is_unspecified()
                    && o[0] != 0
                    && o[0] < 224
                    && !(o[0] == 100 && (64..=127).contains(&o[1]))
            }
            IpAddr::V6(v6) => !v6.is_loopback() && !v6.is_unspecified(),
        });
        if !ips.is_empty() {
            if let Ok(mut cache) = DNS_CACHE.write() {
                cache.insert(key, (ips.clone(), Instant::now()));
            }
            return Ok(ips);
        }
    }

    Err(format!("DNS resolve failed for {host}"))
}

async fn doh_query_a(
    resolver_ip: Ipv4Addr,
    sni: &str,
    path: &str,
    domain: &str,
) -> Result<Vec<IpAddr>, String> {
    let addr = SocketAddr::new(IpAddr::V4(resolver_ip), 443);
    let tcp = timeout(Duration::from_millis(1600), TcpStream::connect(addr))
        .await
        .map_err(|_| "doh connect timeout".to_string())?
        .map_err(|e| e.to_string())?;
    let frag = FragmentedTcpStream::new(tcp, true);
    let server_name = ServerName::try_from(sni.to_string()).map_err(|e| e.to_string())?;
    let connector = TlsConnector::from(TLS_CONFIG_VERIFIED.clone());
    let mut tls = timeout(Duration::from_millis(1900), connector.connect(server_name, frag))
        .await
        .map_err(|_| "doh tls timeout".to_string())?
        .map_err(|e| e.to_string())?;

    let encoded_name: String =
        url::form_urlencoded::byte_serialize(domain.as_bytes()).collect();
    let req = format!(
        "GET {path}?name={encoded_name}&type=A HTTP/1.1\r\nHost: {sni}\r\nAccept: application/dns-json\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
    );
    timeout(Duration::from_millis(2000), tls.write_all(req.as_bytes()))
        .await
        .map_err(|_| "doh write timeout".to_string())?
        .map_err(|e| e.to_string())?;

    let resp = read_http_response(&mut tls, 64 * 1024, Duration::from_millis(3000)).await?;
    if resp.status != 200 {
        return Err(format!("doh http {}", resp.status));
    }
    let val: serde_json::Value = serde_json::from_slice(&resp.body).map_err(|e| e.to_string())?;
    let mut ips = Vec::new();
    if let Some(answers) = val.get("Answer").and_then(|a| a.as_array()) {
        for ans in answers {
            let rtype = ans.get("type").and_then(|t| t.as_u64()).unwrap_or(0);
            if rtype == 1 || rtype == 28 {
                if let Some(data) = ans.get("data").and_then(|d| d.as_str()) {
                    if let Ok(ip) = data.trim().parse::<IpAddr>() {
                        if !ips.contains(&ip) {
                            ips.push(ip);
                        }
                    }
                }
            }
        }
    }
    Ok(ips)
}

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

#[derive(Debug, Clone)]
pub struct HttpRequestOptions {
    pub method: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
    pub timeout: Duration,
    pub max_bytes: usize,
    pub fragment_tls: bool,
    pub socks5_proxy: Option<SocketAddr>,
    pub sni_override: Option<String>,
    pub insecure_masked_sni: bool,
    pub fixed_ip: Option<IpAddr>,
}

impl Default for HttpRequestOptions {
    fn default() -> Self {
        Self {
            method: "GET".to_string(),
            headers: Vec::new(),
            body: None,
            timeout: Duration::from_secs(10),
            max_bytes: 5 * 1024 * 1024,
            fragment_tls: true,
            socks5_proxy: None,
            sni_override: None,
            insecure_masked_sni: false,
            fixed_ip: None,
        }
    }
}

/// Connect through a SOCKS5 proxy (optional username/password auth) to `target_host:target_port`.
pub async fn socks5_connect(
    proxy_addr: SocketAddr,
    auth: Option<(&str, &str)>,
    target_host: &str,
    target_port: u16,
    connect_timeout: Duration,
) -> Result<TcpStream, String> {
    let deadline = Instant::now() + connect_timeout;
    let mut stream = timeout(connect_timeout, TcpStream::connect(proxy_addr))
        .await
        .map_err(|_| "socks5 tcp timeout".to_string())?
        .map_err(|e| format!("socks5 tcp: {e}"))?;
    let _ = stream.set_nodelay(true);

    // Greeting
    let greeting: &[u8] = if auth.is_some() {
        &[0x05, 0x02, 0x00, 0x02]
    } else {
        &[0x05, 0x01, 0x00]
    };
    let rem = deadline.saturating_duration_since(Instant::now()).max(Duration::from_millis(200));
    timeout(rem, stream.write_all(greeting))
        .await
        .map_err(|_| "socks5 greet write timeout".to_string())?
        .map_err(|e| e.to_string())?;

    let mut method_reply = [0u8; 2];
    let rem = deadline.saturating_duration_since(Instant::now()).max(Duration::from_millis(200));
    timeout(rem, stream.read_exact(&mut method_reply))
        .await
        .map_err(|_| "socks5 greet read timeout".to_string())?
        .map_err(|e| e.to_string())?;
    if method_reply[0] != 0x05 {
        return Err("not a socks5 server".to_string());
    }

    match method_reply[1] {
        0x00 => {}
        0x02 => {
            let (u, p) = auth.ok_or_else(|| "socks5 requires auth".to_string())?;
            if u.len() > 255 || p.len() > 255 {
                return Err("socks5 credentials too long".to_string());
            }
            let mut pkt = Vec::with_capacity(3 + u.len() + p.len());
            pkt.push(0x01);
            pkt.push(u.len() as u8);
            pkt.extend_from_slice(u.as_bytes());
            pkt.push(p.len() as u8);
            pkt.extend_from_slice(p.as_bytes());
            let rem = deadline.saturating_duration_since(Instant::now()).max(Duration::from_millis(200));
            timeout(rem, stream.write_all(&pkt))
                .await
                .map_err(|_| "socks5 auth write timeout".to_string())?
                .map_err(|e| e.to_string())?;
            let mut auth_rep = [0u8; 2];
            let rem = deadline.saturating_duration_since(Instant::now()).max(Duration::from_millis(200));
            timeout(rem, stream.read_exact(&mut auth_rep))
                .await
                .map_err(|_| "socks5 auth read timeout".to_string())?
                .map_err(|e| e.to_string())?;
            if auth_rep[1] != 0x00 {
                return Err("socks5 auth rejected".to_string());
            }
        }
        code => return Err(format!("socks5 unsupported method 0x{code:02x}")),
    }

    // CONNECT request
    let clean_host = target_host.trim_matches(|c| c == '[' || c == ']');
    let mut req = Vec::with_capacity(32 + clean_host.len());
    req.extend_from_slice(&[0x05, 0x01, 0x00]);
    if let Ok(v4) = clean_host.parse::<Ipv4Addr>() {
        req.push(0x01);
        req.extend_from_slice(&v4.octets());
    } else if let Ok(IpAddr::V6(v6)) = clean_host.parse::<IpAddr>() {
        req.push(0x04);
        req.extend_from_slice(&v6.octets());
    } else {
        let hb = clean_host.as_bytes();
        if hb.len() > 255 {
            return Err("socks5 host too long".to_string());
        }
        req.push(0x03);
        req.push(hb.len() as u8);
        req.extend_from_slice(hb);
    }
    req.extend_from_slice(&target_port.to_be_bytes());

    let rem = deadline.saturating_duration_since(Instant::now()).max(Duration::from_millis(200));
    timeout(rem, stream.write_all(&req))
        .await
        .map_err(|_| "socks5 connect write timeout".to_string())?
        .map_err(|e| e.to_string())?;

    let mut rep_hdr = [0u8; 4];
    let rem = deadline.saturating_duration_since(Instant::now()).max(Duration::from_millis(200));
    timeout(rem, stream.read_exact(&mut rep_hdr))
        .await
        .map_err(|_| "socks5 connect reply timeout".to_string())?
        .map_err(|e| e.to_string())?;
    if rep_hdr[0] != 0x05 || rep_hdr[1] != 0x00 {
        return Err(format!("socks5 connect failed rep=0x{:02x}", rep_hdr[1]));
    }

    // Drain bound address + port
    let skip_len = match rep_hdr[3] {
        0x01 => 4 + 2,
        0x04 => 16 + 2,
        0x03 => {
            let mut dlen = [0u8; 1];
            let rem = deadline.saturating_duration_since(Instant::now()).max(Duration::from_millis(200));
            timeout(rem, stream.read_exact(&mut dlen))
                .await
                .map_err(|_| "socks5 atyp3 timeout".to_string())?
                .map_err(|e| e.to_string())?;
            dlen[0] as usize + 2
        }
        a => return Err(format!("socks5 bad atyp 0x{a:02x}")),
    };
    let mut skip = vec![0u8; skip_len];
    let rem = deadline.saturating_duration_since(Instant::now()).max(Duration::from_millis(200));
    timeout(rem, stream.read_exact(&mut skip))
        .await
        .map_err(|_| "socks5 bind drain timeout".to_string())?
        .map_err(|e| e.to_string())?;

    Ok(stream)
}

/// Execute an HTTP/1.1 or HTTPS/1.1 request (following up to 4 redirects on GET).
pub async fn http_request(url_str: &str, opts: &HttpRequestOptions) -> Result<HttpResponse, String> {
    let mut current = url_str.to_string();
    for hop in 0..5 {
        let resp = http_request_once(&current, opts).await?;
        if matches!(resp.status, 301 | 302 | 303 | 307 | 308) && opts.method == "GET" && hop < 4 {
            if let Some(loc) = resp.header("location") {
                if let Ok(base) = Url::parse(&current) {
                    if let Ok(next) = base.join(loc.trim()) {
                        current = next.to_string();
                        continue;
                    }
                }
            }
        }
        return Ok(resp);
    }
    Err("too many redirects".to_string())
}

pub async fn http_request_once(
    url_str: &str,
    opts: &HttpRequestOptions,
) -> Result<HttpResponse, String> {
    let parsed = Url::parse(url_str).map_err(|e| format!("bad url: {e}"))?;
    let is_https = parsed.scheme() == "https";
    if !is_https && parsed.scheme() != "http" {
        return Err(format!("unsupported scheme: {}", parsed.scheme()));
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| "missing host".to_string())?
        .to_string();
    let port = parsed.port_or_known_default().unwrap_or(if is_https { 443 } else { 80 });

    let start = Instant::now();
    let tcp = if let Some(proxy) = opts.socks5_proxy {
        socks5_connect(proxy, None, &host, port, opts.timeout).await?
    } else if let Some(ip) = opts.fixed_ip {
        timeout(opts.timeout, TcpStream::connect(SocketAddr::new(ip, port)))
            .await
            .map_err(|_| "connect timeout".to_string())?
            .map_err(|e| e.to_string())?
    } else {
        let ips = resolve_host_resilient(&host).await?;
        let mut connected = None;
        let mut last_err = String::from("no ips");
        for ip in ips.iter().take(3) {
            let per_try = (opts.timeout / 2).max(Duration::from_millis(2500));
            match timeout(per_try, TcpStream::connect(SocketAddr::new(*ip, port))).await {
                Ok(Ok(s)) => {
                    connected = Some(s);
                    break;
                }
                Ok(Err(e)) => last_err = e.to_string(),
                Err(_) => last_err = "connect timeout".to_string(),
            }
        }
        connected.ok_or(last_err)?
    };

    let mut path_and_query = parsed.path().to_string();
    if path_and_query.is_empty() {
        path_and_query.push('/');
    }
    if let Some(q) = parsed.query() {
        path_and_query.push('?');
        path_and_query.push_str(q);
    }

    let host_header = if (is_https && port == 443) || (!is_https && port == 80) {
        host.clone()
    } else {
        format!("{host}:{port}")
    };

    let mut raw_req = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nAccept-Encoding: identity\r\n",
        opts.method, path_and_query, host_header
    );
    let mut has_ua = false;
    for (k, v) in &opts.headers {
        if k.eq_ignore_ascii_case("user-agent") {
            has_ua = true;
        }
        if k.eq_ignore_ascii_case("host") || k.eq_ignore_ascii_case("connection") {
            continue;
        }
        raw_req.push_str(&format!("{k}: {v}\r\n"));
    }
    if !has_ua {
        raw_req.push_str(
            "User-Agent: Mozilla/5.0 (Linux; Android 12; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36\r\n",
        );
    }
    if let Some(body) = &opts.body {
        raw_req.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    raw_req.push_str("\r\n");

    let rem = || {
        opts.timeout
            .saturating_sub(start.elapsed())
            .max(Duration::from_millis(500))
    };

    if is_https {
        let sni_str = opts
            .sni_override
            .as_deref()
            .unwrap_or(&host)
            .trim_matches(|c| c == '[' || c == ']');
        let server_name = ServerName::try_from(sni_str.to_string())
            .map_err(|e| format!("bad sni {sni_str}: {e}"))?;
        let cfg = if opts.insecure_masked_sni {
            TLS_CONFIG_MASKED_SNI.clone()
        } else {
            TLS_CONFIG_VERIFIED.clone()
        };
        let frag = FragmentedTcpStream::new(tcp, opts.fragment_tls && opts.socks5_proxy.is_none());
        let connector = TlsConnector::from(cfg);
        let mut tls = timeout(rem(), connector.connect(server_name, frag))
            .await
            .map_err(|_| "tls handshake timeout".to_string())?
            .map_err(|e| format!("tls error: {e}"))?;

        timeout(rem(), tls.write_all(raw_req.as_bytes()))
            .await
            .map_err(|_| "http write timeout".to_string())?
            .map_err(|e| e.to_string())?;
        if let Some(body) = &opts.body {
            timeout(rem(), tls.write_all(body))
                .await
                .map_err(|_| "http body write timeout".to_string())?
                .map_err(|e| e.to_string())?;
        }
        timeout(rem(), tls.flush())
            .await
            .map_err(|_| "http flush timeout".to_string())?
            .map_err(|e| e.to_string())?;
        read_http_response(&mut tls, opts.max_bytes, rem()).await
    } else {
        let mut stream = tcp;
        timeout(rem(), stream.write_all(raw_req.as_bytes()))
            .await
            .map_err(|_| "http write timeout".to_string())?
            .map_err(|e| e.to_string())?;
        if let Some(body) = &opts.body {
            timeout(rem(), stream.write_all(body))
                .await
                .map_err(|_| "http body write timeout".to_string())?
                .map_err(|e| e.to_string())?;
        }
        read_http_response(&mut stream, opts.max_bytes, rem()).await
    }
}

pub async fn read_http_response<S: AsyncRead + Unpin>(
    stream: &mut S,
    max_bytes: usize,
    read_timeout: Duration,
) -> Result<HttpResponse, String> {
    let deadline = Instant::now() + read_timeout;
    let mut raw = Vec::with_capacity(8192);
    let mut chunk = [0u8; 8192];
    let header_end;

    loop {
        let rem = deadline.saturating_duration_since(Instant::now());
        if rem.is_zero() {
            return Err("http response header timeout".to_string());
        }
        let n = timeout(rem, stream.read(&mut chunk))
            .await
            .map_err(|_| "http read timeout".to_string())?
            .map_err(|e| format!("http read: {e}"))?;
        if n == 0 {
            return Err("unexpected EOF before HTTP headers".to_string());
        }
        raw.extend_from_slice(&chunk[..n]);
        if let Some(pos) = find_subslice(&raw, b"\r\n\r\n") {
            header_end = pos + 4;
            break;
        }
        if raw.len() > 65536 {
            return Err("HTTP headers exceed 64 KiB".to_string());
        }
    }

    let hdr_text = String::from_utf8_lossy(&raw[..header_end - 4]);
    let mut lines = hdr_text.split("\r\n");
    let status_line = lines.next().ok_or_else(|| "empty status line".to_string())?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| format!("bad status line: {status_line}"))?;

    let mut headers = Vec::new();
    let mut content_length: Option<usize> = None;
    let mut is_chunked = false;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_string();
            let val = v.trim().to_string();
            if key.eq_ignore_ascii_case("content-length") {
                content_length = val.parse().ok();
            } else if key.eq_ignore_ascii_case("transfer-encoding")
                && val.to_ascii_lowercase().contains("chunked")
            {
                is_chunked = true;
            }
            headers.push((key, val));
        }
    }

    let mut body_raw = raw[header_end..].to_vec();
    let target_len = content_length.map(|cl| cl.min(max_bytes));

    loop {
        if let Some(tl) = target_len {
            if body_raw.len() >= tl {
                body_raw.truncate(tl);
                break;
            }
        }
        if body_raw.len() >= max_bytes {
            body_raw.truncate(max_bytes);
            break;
        }
        if is_chunked && find_subslice(&body_raw, b"0\r\n\r\n").is_some() {
            break;
        }
        let rem = deadline.saturating_duration_since(Instant::now());
        if rem.is_zero() {
            if content_length.is_none() && !body_raw.is_empty() {
                break;
            }
            return Err("http body timeout".to_string());
        }
        match timeout(rem, stream.read(&mut chunk)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => body_raw.extend_from_slice(&chunk[..n]),
            Ok(Err(e)) => {
                // Graceful CloseNotify omission (common on some servers after full body)
                if !body_raw.is_empty() && content_length.is_none() {
                    break;
                }
                return Err(format!("http body read: {e}"));
            }
            Err(_) => {
                if !body_raw.is_empty() && content_length.is_none() {
                    break;
                }
                return Err("http body read timeout".to_string());
            }
        }
    }

    let body = if is_chunked {
        decode_chunked(&body_raw, max_bytes)
    } else {
        body_raw
    };

    Ok(HttpResponse {
        status,
        headers,
        body,
    })
}

fn decode_chunked(input: &[u8], max_bytes: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < input.len() && out.len() < max_bytes {
        let Some(rel_end) = find_subslice(&input[pos..], b"\r\n") else {
            break;
        };
        let size_line = String::from_utf8_lossy(&input[pos..pos + rel_end]);
        let hex_part = size_line.split(';').next().unwrap_or("").trim();
        let Ok(chunk_size) = usize::from_str_radix(hex_part, 16) else {
            break;
        };
        pos += rel_end + 2;
        if chunk_size == 0 {
            break;
        }
        let avail = (input.len().saturating_sub(pos)).min(chunk_size);
        let take = avail.min(max_bytes - out.len());
        out.extend_from_slice(&input[pos..pos + take]);
        pos += avail;
        if pos + 2 <= input.len() && &input[pos..pos + 2] == b"\r\n" {
            pos += 2;
        } else {
            break;
        }
    }
    out
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Generate resilient CDN mirror candidates `(url, short_tag)` for a GitHub raw URL so updates
/// succeed fast even when `raw.githubusercontent.com` is throttled or blocked by an RF ISP.
pub fn expand_mirror_urls_tagged(url: &str) -> Vec<(String, &'static str)> {
    let mut out = vec![(url.to_string(), "raw")];
    // Pattern: https://raw.githubusercontent.com/{owner}/{repo}/{branch_or_refs}/{path}
    if let Some(rest) = url.strip_prefix("https://raw.githubusercontent.com/") {
        let rest = rest.replace("/refs/heads/", "/");
        let parts: Vec<&str> = rest.splitn(4, '/').collect();
        if parts.len() == 4 {
            let (owner, repo, branch, path) = (parts[0], parts[1], parts[2], parts[3]);
            // Gcore CDN FIRST among mirrors — has direct local Russian/CIS edge PoPs!
            out.push((
                format!("https://gcore.jsdelivr.net/gh/{owner}/{repo}@{branch}/{path}"),
                "gcore",
            ));
            out.push((
                format!("https://cdn.jsdelivr.net/gh/{owner}/{repo}@{branch}/{path}"),
                "jsdelivr",
            ));
            // Independent non-GitHub Codeberg mirror for igareck RF Whitelist repo
            if owner.eq_ignore_ascii_case("igareck") && repo.eq_ignore_ascii_case("vpn-configs-for-russia") {
                out.push((
                    format!("https://codeberg.org/igareck/vpn-configs-for-russia/raw/branch/{branch}/{path}"),
                    "codeberg",
                ));
            }
            out.push((
                format!("https://fastly.jsdelivr.net/gh/{owner}/{repo}@{branch}/{path}"),
                "fastly",
            ));
        }
    }
    out
}

pub fn expand_mirror_urls(url: &str) -> Vec<String> {
    expand_mirror_urls_tagged(url)
        .into_iter()
        .map(|(u, _)| u)
        .collect()
}

/// Decoded custom subscription fetch output (Remnawave, Shuka, Marzban, Happ, 3x-ui, Hiddify,
/// PasarGuard, Outline, V2Board, raw GitHub/Codeberg).
#[derive(Debug, Clone, Default)]
pub struct SubscriptionFetchResult {
    pub body: String,
    pub profile_title: String,
    pub userinfo: String,
    pub via_tag: String,
}

fn looks_like_html_portal(body: &str) -> bool {
    let sample: String = body.trim_start().chars().take(512).collect::<String>().to_ascii_lowercase();
    (sample.starts_with("<!doctype html")
        || sample.starts_with("<html")
        || sample.contains("<head>")
        || sample.contains("<body"))
        && !body.contains("\nvless://")
        && !body.contains("\nvmess://")
        && !body.contains("\ntrojan://")
        && !body.contains("\nss://")
        && !body.contains("\nhy2://")
        && !body.contains("\nhysteria2://")
        && !body.contains("\ntg://proxy")
}

/// Extract embedded subscription URL from an HTML portal page (e.g. `happ://add/https://...`,
/// `v2raytun://import/https://...`, `sing-box://import-remote-profile?url=...`).
fn extract_sub_url_from_html(html: &str) -> Option<String> {
    for marker in [
        "happ://add/",
        "v2raytun://import/",
        "hiddify://import/",
        "streisand://import/",
    ] {
        if let Some(idx) = html.find(marker) {
            let after = &html[idx + marker.len()..];
            let end = after
                .find(|c: char| matches!(c, '"' | '\'' | '<' | '>' | '#' | ' ' | '\r' | '\n'))
                .unwrap_or(after.len());
            let cand = percent_encoding::percent_decode_str(&after[..end])
                .decode_utf8_lossy()
                .trim()
                .to_string();
            if cand.starts_with("https://") || cand.starts_with("http://") {
                return Some(cand);
            }
        }
    }
    None
}

fn decode_profile_title_header(resp: &HttpResponse) -> String {
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    use base64::Engine;

    let raw = resp
        .header("profile-title")
        .or_else(|| resp.header("x-profile-title"))
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    if raw.is_empty() {
        return String::new();
    }
    let decoded = if let Some(b64) = raw
        .strip_prefix("base64:")
        .or_else(|| raw.strip_prefix("BASE64:"))
    {
        let clean = b64.trim();
        let unpad = clean.trim_end_matches('=');
        STANDARD
            .decode(clean)
            .or_else(|_| URL_SAFE.decode(clean))
            .or_else(|_| STANDARD_NO_PAD.decode(unpad))
            .or_else(|_| URL_SAFE_NO_PAD.decode(unpad))
            .ok()
            .and_then(|b| String::from_utf8(b).ok())
            .unwrap_or(raw)
    } else {
        percent_encoding::percent_decode_str(&raw)
            .decode_utf8_lossy()
            .into_owned()
    };
    decoded
        .chars()
        .filter(|c| !c.is_control())
        .take(52)
        .collect::<String>()
        .trim()
        .to_string()
}

fn format_subscription_userinfo(resp: &HttpResponse) -> String {
    let Some(raw) = resp.header("subscription-userinfo") else {
        return String::new();
    };
    let mut upload: u64 = 0;
    let mut download: u64 = 0;
    let mut total: u64 = 0;
    let mut expire: u64 = 0;
    for part in raw.split(';') {
        if let Some((k, v)) = part.trim().split_once('=') {
            let val: u64 = v.trim().parse().unwrap_or(0);
            match k.trim().to_ascii_lowercase().as_str() {
                "upload" => upload = val,
                "download" => download = val,
                "total" => total = val,
                "expire" => expire = val,
                _ => {}
            }
        }
    }
    let mut parts = Vec::new();
    if total > 0 {
        let used_gb = (upload.saturating_add(download)) as f64 / (1024.0 * 1024.0 * 1024.0);
        let tot_gb = total as f64 / (1024.0 * 1024.0 * 1024.0);
        if tot_gb < 90_000.0 {
            parts.push(format!("{used_gb:.1}/{tot_gb:.0} ГБ"));
        } else {
            parts.push("Безлимит".to_string());
        }
    }
    if expire > 1_600_000_000 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if expire > now {
            let days = (expire - now) / 86_400;
            if days > 3650 {
                parts.push("бессрочно".to_string());
            } else if days >= 1 {
                parts.push(format!("ещё {days} дн."));
            } else {
                let hrs = ((expire - now) / 3600).max(1);
                parts.push(format!("ещё {hrs} ч."));
            }
        } else {
            parts.push("истекла".to_string());
        }
    }
    parts.join(" · ")
}

async fn http_request_follow_6(url_str: &str, opts: &HttpRequestOptions) -> Result<HttpResponse, String> {
    let mut current = url_str.to_string();
    for hop in 0..7 {
        let resp = http_request_once(&current, opts).await?;
        if matches!(resp.status, 301 | 302 | 303 | 307 | 308) && opts.method == "GET" && hop < 6 {
            if let Some(loc) = resp.header("location") {
                if let Ok(base) = Url::parse(&current) {
                    if let Ok(next) = base.join(loc.trim()) {
                        current = next.to_string();
                        continue;
                    }
                }
            }
        }
        return Ok(resp);
    }
    Err("слишком много редиректов".to_string())
}

/// Fetch any custom VPN/TG subscription URL using authentic VPN-client User-Agents
/// (`v2rayNG/1.9.30` -> `Happ/2.6.0/Android` -> `SFA/1.11.4`) so panels such as
/// Remnawave, Marzban, Happ, 3x-ui, PasarGuard, Hiddify, and V2Board return raw
/// subscription payloads + `profile-title` instead of browser HTML portals.
pub async fn fetch_subscription_smart(
    url: &str,
    socks5_proxy: Option<SocketAddr>,
    max_bytes: usize,
) -> Result<SubscriptionFetchResult, String> {
    const CLIENT_UAS: &[(&str, &str)] = &[
        ("v2rayNG/1.9.30", "v2rayNG"),
        ("Happ/2.6.0/Android", "Happ"),
        ("SFA/1.11.4 (Android)", "sing-box"),
    ];

    let mut last_err = String::from("нет ответа");
    let mut html_fallback_url: Option<String> = None;

    // Build transport modes: tunnel first (if active), then direct+TLS-fragment, then direct plain
    let mut modes: Vec<(Option<SocketAddr>, bool, &str)> = Vec::new();
    if let Some(p) = socks5_proxy {
        modes.push((Some(p), false, "tunnel"));
    }
    modes.push((None, true, "direct+frag"));
    modes.push((None, false, "direct"));

    for (ua, ua_tag) in CLIENT_UAS {
        for (proxy, frag, net_tag) in &modes {
            let opts = HttpRequestOptions {
                timeout: Duration::from_millis(7500),
                max_bytes,
                fragment_tls: *frag,
                socks5_proxy: *proxy,
                headers: vec![
                    ("User-Agent".into(), (*ua).to_string()),
                    ("Accept".into(), "*/*".into()),
                ],
                ..Default::default()
            };
            match http_request_follow_6(url, &opts).await {
                Ok(r) if r.status == 200 && !r.body.is_empty() => {
                    let body = r.text();
                    if looks_like_html_portal(&body) {
                        if html_fallback_url.is_none() {
                            html_fallback_url = extract_sub_url_from_html(&body);
                        }
                        last_err = format!("панель вернула HTML-страницу ({ua_tag})");
                        break; // Switch to next User-Agent immediately (network worked!)
                    }
                    return Ok(SubscriptionFetchResult {
                        profile_title: decode_profile_title_header(&r),
                        userinfo: format_subscription_userinfo(&r),
                        body,
                        via_tag: format!("{ua_tag}/{net_tag}"),
                    });
                }
                Ok(r) => {
                    last_err = format!("HTTP {} ({ua_tag})", r.status);
                    if (400..500).contains(&r.status) {
                        break; // Client/UA rejection -> try next UA
                    }
                }
                Err(e) => {
                    last_err = format!("{net_tag}: {e}");
                }
            }
        }
    }

    // If panel returned an HTML portal embedding `happ://add/https://.../sub/...`, fetch that link!
    if let Some(sub_url) = html_fallback_url {
        if sub_url != url {
            let opts = HttpRequestOptions {
                timeout: Duration::from_millis(7500),
                max_bytes,
                fragment_tls: true,
                socks5_proxy,
                headers: vec![
                    ("User-Agent".into(), "v2rayNG/1.9.30".into()),
                    ("Accept".into(), "*/*".into()),
                ],
                ..Default::default()
            };
            if let Ok(r) = http_request_follow_6(&sub_url, &opts).await {
                if r.status == 200 && !r.body.is_empty() {
                    let body = r.text();
                    if !looks_like_html_portal(&body) {
                        return Ok(SubscriptionFetchResult {
                            profile_title: decode_profile_title_header(&r),
                            userinfo: format_subscription_userinfo(&r),
                            body,
                            via_tag: "portal->v2rayNG".into(),
                        });
                    }
                }
            }
        }
    }

    Err(last_err)
}

/// Fetch text and return `(body, mirror_tag)` for detailed diagnostics.
pub async fn fetch_text_resilient_tagged(
    url: &str,
    socks5_proxy: Option<SocketAddr>,
    max_bytes: usize,
) -> Result<(String, &'static str), String> {
    let mirrors = expand_mirror_urls_tagged(url);
    let mut last_err = String::from("нет зеркал");

    // If a working VPN/SOCKS tunnel is currently active, try fetching directly through it first
    if let Some(proxy) = socks5_proxy {
        let opts = HttpRequestOptions {
            timeout: Duration::from_millis(5500),
            max_bytes,
            fragment_tls: false,
            socks5_proxy: Some(proxy),
            ..Default::default()
        };
        match http_request(&mirrors[0].0, &opts).await {
            Ok(r) if r.status == 200 && !r.body.is_empty() => return Ok((r.text(), "tunnel")),
            Ok(r) => last_err = format!("tunnel HTTP {}", r.status),
            Err(e) => last_err = format!("tunnel: {e}"),
        }
    }

    // Direct resilient cascade with anti-spoof DoH + TLS ClientHello fragmentation
    for (m, tag) in &mirrors {
        let opts = HttpRequestOptions {
            timeout: Duration::from_millis(4800),
            max_bytes,
            fragment_tls: true,
            socks5_proxy: None,
            ..Default::default()
        };
        match http_request(m, &opts).await {
            Ok(r) if r.status == 200 && !r.body.is_empty() => return Ok((r.text(), *tag)),
            Ok(r) => last_err = format!("{tag}: HTTP {}", r.status),
            Err(e) => last_err = format!("{tag}: {e}"),
        }
    }

    Err(last_err)
}

/// Fetch text from a URL using active SOCKS5 proxy (if provided), then direct + TLS fragment,
/// cascading automatically across CDN mirrors on error.
pub async fn fetch_text_resilient(
    url: &str,
    socks5_proxy: Option<SocketAddr>,
    max_bytes: usize,
) -> Result<String, String> {
    fetch_text_resilient_tagged(url, socks5_proxy, max_bytes)
        .await
        .map(|(body, _)| body)
}
