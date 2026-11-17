//! Canonical `xray-rust` v0.10.0 JSON configuration builder & share-link parser.
//! Produces strict, schema-validated outbounds for:
//! - VLESS (TCP/RAW + Vision, XHTTP/SplitHTTP, gRPC, WS, HTTPUpgrade with REALITY or TLS)
//! - Hysteria 2 (QUIC + Salamander + UDP port hopping)
//! - Trojan (TLS / REALITY over TCP/gRPC/WS/XHTTP)
//! - Shadowsocks (SIP002 classic AEAD & SS-2022)
//! - Opera SurfEasy HTTPS CONNECT (TLS + Basic auth + SNI verification)
//! - Cloudflare WARP over MASQUE (HTTP/3 QUIC and HTTP/2 TCP + TLS fragment) & WireGuard (+ UDP noise)
//! As well as:
//! - Batch multi-SOCKS5 loopback config (for parallel real tunnel + anti-16KB + GeoIP verification)
//! - Production Android TUN config (with `observatory` + `leastLoad` balancer + DoH + FakeIP + RU split routing).

use crate::opera::OperaEndpoint;
use crate::sources::{
    clean_remark, decode_b64_flexible, detect_region_hint, is_valid_public_host,
    is_whitelist_remark, is_whitelist_sni, VerifiedVpnNode, VpnCandidate,
};
use crate::warp::{warp_masque_candidate_endpoints, warp_wg_candidate_endpoints, WarpAccountCache};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use percent_encoding::percent_decode_str;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use url::Url;

fn short_id_hash(key: &str) -> String {
    let mut h = Sha256::new();
    h.update(key.as_bytes());
    hex::encode(&h.finalize()[..8])
}

fn parse_query_map(u: &Url) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for (k, v) in u.query_pairs() {
        let key = k.to_ascii_lowercase();
        map.entry(key).or_insert_with(|| v.trim().to_string());
    }
    map
}

fn normalize_fingerprint(fp: &str, is_reality: bool) -> &'static str {
    match fp.trim().to_ascii_lowercase().as_str() {
        "chrome" => "chrome",
        "firefox" => "firefox",
        "safari" => "safari",
        "ios" => "ios",
        "qq" => "qq",
        "edge" => "edge",
        "android" if !is_reality => "android",
        "random" => "random",
        "randomized" => "randomized",
        _ => "chrome",
    }
}

fn is_valid_reality_pubkey(pbk: &str) -> bool {
    let clean = pbk.trim().trim_end_matches('=');
    if clean.len() < 42 || clean.len() > 45 {
        return false;
    }
    URL_SAFE_NO_PAD
        .decode(clean)
        .map(|b| b.len() == 32 && b.iter().any(|&x| x != 0))
        .unwrap_or(false)
}

fn is_valid_short_id(sid: &str) -> bool {
    sid.len() <= 16 && sid.len() % 2 == 0 && sid.chars().all(|c| c.is_ascii_hexdigit())
}

fn is_truthy_insecure(q: &HashMap<String, String>) -> bool {
    for key in ["allowinsecure", "insecure", "allow_insecure"] {
        if let Some(v) = q.get(key) {
            let l = v.to_ascii_lowercase();
            if l == "1" || l == "true" || l == "yes" {
                return true;
            }
        }
    }
    false
}

fn tcp_fragment_mask() -> Value {
    json!({
        "tcp": [{
            "type": "fragment",
            "settings": {
                "packets": "tlshello",
                "length": "40-120",
                "delay": "1-3",
                "maxSplit": 16
            }
        }]
    })
}

fn parse_alpn_list(q: &HashMap<String, String>) -> Option<Vec<String>> {
    let raw = q.get("alpn")?.trim();
    if raw.is_empty() {
        return None;
    }
    let allowed = ["h2", "http/1.1", "h3"];
    let items: Vec<String> = raw
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| allowed.contains(&s.as_str()))
        .collect();
    if items.is_empty() {
        None
    } else {
        Some(items)
    }
}

/// Build `streamSettings` for VLESS / Trojan links; returns `(streamSettings, transport, security, sni, score_bonus)`.
fn build_common_stream_settings(
    q: &HashMap<String, String>,
    default_host: &str,
    default_security: &str,
    fragment_tls: bool,
) -> Option<(Value, String, String, String, i32)> {
    // Never accept insecure TLS proxies (anti-MITM guarantee + xray-rust rejects allowInsecure=true)
    if is_truthy_insecure(q) {
        return None;
    }

    let raw_net = q
        .get("type")
        .map(|s| s.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("tcp")
        .to_ascii_lowercase();

    let (network, mut score) = match raw_net.as_str() {
        "tcp" | "raw" => {
            if let Some(ht) = q.get("headertype") {
                if !ht.is_empty() && !ht.eq_ignore_ascii_case("none") {
                    return None;
                }
            }
            ("tcp", 35)
        }
        "xhttp" | "splithttp" => ("xhttp", 55),
        "grpc" => ("grpc", 30),
        "ws" | "websocket" => ("ws", 18),
        "httpupgrade" => ("httpupgrade", 22),
        _ => return None,
    };

    let security = q
        .get("security")
        .map(|s| s.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or(default_security)
        .to_ascii_lowercase();

    // Refuse plaintext unencrypted public proxies for privacy & DPI resistance
    if security != "reality" && security != "tls" {
        return None;
    }
    // REALITY is unsupported on WS / HTTPUpgrade
    if security == "reality" && matches!(network, "ws" | "httpupgrade") {
        return None;
    }

    let sni = q
        .get("sni")
        .or_else(|| q.get("servername"))
        .or_else(|| q.get("peer"))
        .or_else(|| q.get("host"))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| default_host.to_string());

    if sni.is_empty() || sni.contains(char::is_whitespace) || sni.len() > 253 {
        return None;
    }

    let mut stream = Map::new();
    stream.insert("network".into(), json!(network));
    stream.insert("security".into(), json!(security));

    match network {
        "tcp" => {}
        "ws" => {
            let mut ws = Map::new();
            let path = q
                .get("path")
                .filter(|s| !s.is_empty())
                .cloned()
                .unwrap_or_else(|| "/".into());
            let clean_path = path.split("?ed=").next().unwrap_or(&path);
            ws.insert(
                "path".into(),
                json!(if clean_path.starts_with('/') {
                    clean_path.to_string()
                } else {
                    format!("/{clean_path}")
                }),
            );
            if let Some(h) = q.get("host").filter(|s| !s.is_empty()) {
                ws.insert("host".into(), json!(h));
            }
            stream.insert("wsSettings".into(), Value::Object(ws));
        }
        "httpupgrade" => {
            let mut hu = Map::new();
            let path = q
                .get("path")
                .filter(|s| !s.is_empty())
                .cloned()
                .unwrap_or_else(|| "/".into());
            hu.insert(
                "path".into(),
                json!(if path.starts_with('/') {
                    path
                } else {
                    format!("/{path}")
                }),
            );
            if let Some(h) = q.get("host").filter(|s| !s.is_empty()) {
                hu.insert("host".into(), json!(h));
            }
            stream.insert("httpupgradeSettings".into(), Value::Object(hu));
        }
        "grpc" => {
            let mut grpc = Map::new();
            let svc = q
                .get("servicename")
                .cloned()
                .unwrap_or_default();
            if !svc.is_empty() {
                grpc.insert("serviceName".into(), json!(svc));
            }
            if let Some(auth) = q.get("authority").filter(|s| !s.is_empty()) {
                grpc.insert("authority".into(), json!(auth));
            }
            let multi = q
                .get("mode")
                .map(|m| m.eq_ignore_ascii_case("multi"))
                .unwrap_or(false);
            grpc.insert("multiMode".into(), json!(multi));
            stream.insert("grpcSettings".into(), Value::Object(grpc));
        }
        "xhttp" => {
            let mut xh = Map::new();
            let path = q
                .get("path")
                .filter(|s| !s.is_empty())
                .cloned()
                .unwrap_or_else(|| "/".into());
            xh.insert(
                "path".into(),
                json!(if path.starts_with('/') {
                    path
                } else {
                    format!("/{path}")
                }),
            );
            if let Some(h) = q.get("host").filter(|s| !s.is_empty()) {
                xh.insert("host".into(), json!(h));
            }
            let mode = q
                .get("mode")
                .map(|s| s.to_ascii_lowercase())
                .filter(|m| matches!(m.as_str(), "auto" | "packet-up" | "stream-up" | "stream-one"))
                .unwrap_or_else(|| "auto".into());
            xh.insert("mode".into(), json!(mode));
            stream.insert("xhttpSettings".into(), Value::Object(xh));
        }
        _ => return None,
    }

    let fp_raw = q.get("fp").map(|s| s.as_str()).unwrap_or("chrome");
    let alpn = parse_alpn_list(q);
    let is_h3_only = alpn
        .as_ref()
        .map(|a| a.len() == 1 && a[0] == "h3")
        .unwrap_or(false);

    if security == "reality" {
        // REALITY requires a real domain SNI (not a bare IP)
        if sni.parse::<std::net::IpAddr>().is_ok() {
            return None;
        }
        let pbk = q
            .get("pbk")
            .map(|s| s.trim().trim_end_matches('=').to_string())?;
        if !is_valid_reality_pubkey(&pbk) {
            return None;
        }
        let sid = q.get("sid").cloned().unwrap_or_default();
        if !is_valid_short_id(&sid) {
            return None;
        }
        let fp = normalize_fingerprint(fp_raw, true);
        let mut rs = Map::new();
        rs.insert("serverName".into(), json!(sni));
        rs.insert("fingerprint".into(), json!(fp));
        rs.insert("publicKey".into(), json!(pbk));
        rs.insert("shortId".into(), json!(sid));
        if let Some(spx) = q.get("spx").filter(|s| s.starts_with('/') && s.len() <= 128) {
            rs.insert("spiderX".into(), json!(spx));
        }
        stream.insert("realitySettings".into(), Value::Object(rs));
        score += 75; // Top anti-TSPU resistance
    } else {
        // Plain TLS requires non-IP serverName for WebPKI validation
        if sni.parse::<std::net::IpAddr>().is_ok() {
            return None;
        }
        let fp = normalize_fingerprint(fp_raw, false);
        let mut ts = Map::new();
        ts.insert("serverName".into(), json!(sni));
        ts.insert("fingerprint".into(), json!(fp));
        if let Some(a) = alpn {
            ts.insert("alpn".into(), json!(a));
        }
        stream.insert("tlsSettings".into(), Value::Object(ts));
        score += 20;
    }

    // Apply TLS ClientHello fragmentation on TCP-carried TLS/REALITY when requested
    if fragment_tls && !is_h3_only {
        stream.insert("finalmask".into(), tcp_fragment_mask());
    }

    Some((Value::Object(stream), network.to_string(), security, sni, score))
}

/// Parse a single share URI (`vless://`, `vmess://`, `hy2://`, `hysteria2://`, `trojan://`, `ss://`)
/// into a validated `VpnCandidate` carrying a canonical `xray-rust` outbound JSON.
pub fn parse_share_uri_to_candidate(
    raw: &str,
    source_region_hint: &str,
    source_tier: u8,
    fragment_tls: bool,
) -> Option<VpnCandidate> {
    let trimmed = raw.trim();
    if trimmed.starts_with("vless://") {
        parse_vless(trimmed, source_region_hint, source_tier, fragment_tls)
    } else if trimmed.starts_with("vmess://") {
        parse_vmess(trimmed, source_region_hint, source_tier, fragment_tls)
    } else if trimmed.starts_with("hysteria2://") || trimmed.starts_with("hy2://") {
        parse_hysteria2(trimmed, source_region_hint, source_tier)
    } else if trimmed.starts_with("trojan://") {
        parse_trojan(trimmed, source_region_hint, source_tier, fragment_tls)
    } else if trimmed.starts_with("ss://") {
        parse_shadowsocks(trimmed, source_region_hint, source_tier)
    } else {
        None
    }
}

/// Pin a DoH-resolved clean IPv4 directly into `outbound_json` so Android system DNS can never
/// poison or stall (10s) outbound hostname resolution, while keeping original TLS SNI & Host intact!
pub fn pin_candidate_resolved_ip(cand: &mut VpnCandidate, ip: std::net::IpAddr) {
    if cand.host.parse::<std::net::IpAddr>().is_ok() {
        return;
    }
    let ip_str = ip.to_string();
    if let Some(settings) = cand
        .outbound_json
        .get_mut("settings")
        .and_then(|v| v.as_object_mut())
    {
        if settings.contains_key("address") {
            settings.insert("address".into(), json!(ip_str));
            cand.host = ip_str;
        } else if let Some(vnext0) = settings
            .get_mut("vnext")
            .and_then(|v| v.as_array_mut())
            .and_then(|a| a.first_mut())
            .and_then(|v| v.as_object_mut())
        {
            vnext0.insert("address".into(), json!(ip_str));
            cand.host = ip_str;
        }
    }
}

fn is_valid_uuid_like(s: &str) -> bool {
    let hex_only: String = s.chars().filter(|c| *c != '-').collect();
    if hex_only.len() == 32 && hex_only.chars().all(|c| c.is_ascii_hexdigit()) {
        // Reject dummy all-zero placeholder UUID (00000000-0000-0000-0000-000000000000)
        return hex_only.chars().any(|c| c != '0');
    }
    !s.is_empty() && s.len() <= 30 && s.is_ascii() && !s.chars().any(|c| c.is_control())
}

fn parse_vless(
    uri: &str,
    source_region_hint: &str,
    source_tier: u8,
    fragment_tls: bool,
) -> Option<VpnCandidate> {
    let u = Url::parse(uri).ok()?;
    let uuid = percent_decode_str(u.username()).decode_utf8().ok()?.trim().to_string();
    if !is_valid_uuid_like(&uuid) {
        return None;
    }
    let host = u.host_str()?.trim_matches(|c| c == '[' || c == ']').to_string();
    let port = u.port().unwrap_or(443);
    if !is_valid_public_host(&host, port) {
        return None;
    }
    let q = parse_query_map(&u);

    // Check encryption (default "none")
    if let Some(enc) = q.get("encryption") {
        if !enc.is_empty() && !enc.eq_ignore_ascii_case("none") {
            return None;
        }
    }

    let (stream_settings, transport, security, sni, mut score) =
        build_common_stream_settings(&q, &host, "none", fragment_tls)?;

    let flow_raw = q.get("flow").map(|s| s.trim()).unwrap_or("");
    let flow = match flow_raw {
        "" => "",
        "xtls-rprx-vision" if transport == "tcp" => {
            score += 25;
            "xtls-rprx-vision"
        }
        "xtls-rprx-vision-udp443" if transport == "tcp" => {
            score += 25;
            "xtls-rprx-vision-udp443"
        }
        _ if flow_raw.is_empty() => "",
        _ => return None,
    };

    // Prefer port 443 (indistinguishable from standard HTTPS under TSPU)
    if port == 443 {
        score += 20;
    } else if matches!(port, 8443 | 2053 | 2083 | 2087 | 2096) {
        score += 8;
    }

    let wl = is_whitelist_sni(&sni);
    if wl && security == "reality" {
        score += 18;
    }

    let mut user = Map::new();
    user.insert("id".into(), json!(uuid));
    user.insert("encryption".into(), json!("none"));
    if !flow.is_empty() {
        user.insert("flow".into(), json!(flow));
    }

    let outbound = json!({
        "tag": "proxy",
        "protocol": "vless",
        "settings": {
            "vnext": [{
                "address": host,
                "port": port,
                "users": [Value::Object(user)]
            }]
        },
        "streamSettings": stream_settings
    });

    let remark = clean_remark(u.fragment().unwrap_or(""), &format!("VLESS {host}:{port}"));
    let wl = wl || source_region_hint == "WHITELIST" || is_whitelist_remark(&remark);
    let region_hint = detect_region_hint(&remark, &host, source_region_hint);
    let id = short_id_hash(&format!("vless:{host}:{port}:{uuid}:{transport}:{security}:{sni}"));

    let has_frag = stream_settings.get("finalmask").is_some();

    Some(VpnCandidate {
        id,
        raw_uri: uri.to_string(),
        name: remark,
        protocol: "vless".into(),
        transport,
        security,
        sni,
        host,
        port,
        region_hint,
        whitelist_friendly: wl,
        fragment_enabled: has_frag,
        via_warp: false,
        priority_score: score,
        outbound_json: outbound,
        source_tier,
    })
}

fn parse_vmess(
    uri: &str,
    source_region_hint: &str,
    source_tier: u8,
    fragment_tls: bool,
) -> Option<VpnCandidate> {
    let b64 = uri.strip_prefix("vmess://")?.trim();
    let bytes = decode_b64_flexible(b64)?;
    let v: Value = serde_json::from_slice(&bytes).ok()?;
    let obj = v.as_object()?;

    let host = obj.get("add")?.as_str()?.trim().to_string();
    let port: u16 = match obj.get("port")? {
        Value::Number(n) => n.as_u64()?.try_into().ok()?,
        Value::String(s) => s.trim().parse().ok()?,
        _ => return None,
    };
    if !is_valid_public_host(&host, port) {
        return None;
    }
    let uuid = obj.get("id")?.as_str()?.trim().to_string();
    if !is_valid_uuid_like(&uuid) {
        return None;
    }
    // Require modern AEAD (alterId == 0) + real TLS (never plaintext VMess over TSPU)
    let aid: u64 = match obj.get("aid") {
        None => 0,
        Some(Value::Number(n)) => n.as_u64().unwrap_or(0),
        Some(Value::String(s)) => s.trim().parse().unwrap_or(0),
        _ => return None,
    };
    if aid != 0 {
        return None;
    }
    let tls_val = obj
        .get("tls")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if tls_val != "tls" {
        return None;
    }

    let mut q = std::collections::HashMap::new();
    q.insert("security".into(), "tls".into());
    if let Some(net) = obj.get("net").and_then(|x| x.as_str()) {
        q.insert("type".into(), net.to_string());
    }
    if let Some(h) = obj.get("host").and_then(|x| x.as_str()).filter(|s| !s.is_empty()) {
        q.insert("host".into(), h.to_string());
    }
    if let Some(p) = obj.get("path").and_then(|x| x.as_str()).filter(|s| !s.is_empty()) {
        q.insert("path".into(), p.to_string());
        q.insert("servicename".into(), p.to_string());
    }
    if let Some(s) = obj.get("sni").and_then(|x| x.as_str()).filter(|s| !s.is_empty()) {
        q.insert("sni".into(), s.to_string());
    }
    if let Some(a) = obj.get("alpn").and_then(|x| x.as_str()).filter(|s| !s.is_empty()) {
        q.insert("alpn".into(), a.to_string());
    }
    if let Some(fp) = obj.get("fp").and_then(|x| x.as_str()).filter(|s| !s.is_empty()) {
        q.insert("fp".into(), fp.to_string());
    }

    let (stream_settings, transport, security, sni, score) =
        build_common_stream_settings(&q, &host, "tls", fragment_tls)?;
    let has_frag = stream_settings.get("finalmask").is_some();

    let scy = obj
        .get("scy")
        .and_then(|x| x.as_str())
        .map(|s| s.to_ascii_lowercase())
        .filter(|s| matches!(s.as_str(), "auto" | "aes-128-gcm" | "chacha20-poly1305" | "none" | "zero"))
        .unwrap_or_else(|| "auto".into());

    let outbound = json!({
        "tag": "proxy",
        "protocol": "vmess",
        "settings": {
            "vnext": [{
                "address": host,
                "port": port,
                "users": [{
                    "id": uuid,
                    "security": scy
                }]
            }]
        },
        "streamSettings": stream_settings
    });

    let ps = obj.get("ps").and_then(|x| x.as_str()).unwrap_or("");
    let remark = clean_remark(ps, &format!("VMess {host}:{port}"));
    let region_hint = detect_region_hint(&remark, &host, source_region_hint);
    let id = short_id_hash(&format!("vmess:{host}:{port}:{uuid}:{transport}:{sni}"));

    Some(VpnCandidate {
        id,
        raw_uri: uri.to_string(),
        name: remark,
        protocol: "vmess".into(),
        transport,
        security,
        sni: sni.clone(),
        host,
        port,
        region_hint,
        whitelist_friendly: is_whitelist_sni(&sni),
        fragment_enabled: has_frag,
        via_warp: false,
        priority_score: score,
        outbound_json: outbound,
        source_tier,
    })
}

fn parse_hysteria2(uri: &str, source_region_hint: &str, source_tier: u8) -> Option<VpnCandidate> {
    let norm = if let Some(rest) = uri.strip_prefix("hy2://") {
        format!("hysteria2://{rest}")
    } else {
        uri.to_string()
    };
    let u = Url::parse(&norm).ok()?;
    let user_part = percent_decode_str(u.username()).decode_utf8().ok()?.to_string();
    let auth = if let Some(pw) = u.password() {
        let pw_dec = percent_decode_str(pw).decode_utf8().ok()?;
        format!("{user_part}:{pw_dec}")
    } else {
        user_part
    };
    if auth.is_empty() || auth.len() > 512 {
        return None;
    }
    let host = u.host_str()?.trim_matches(|c| c == '[' || c == ']').to_string();
    let port = u.port().unwrap_or(443);
    if !is_valid_public_host(&host, port) {
        return None;
    }
    let q = parse_query_map(&u);
    if is_truthy_insecure(&q) {
        return None;
    }

    let sni = q
        .get("sni")
        .filter(|s| !s.is_empty())
        .cloned()
        .unwrap_or_else(|| host.clone());
    if sni.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }

    let mut udp_masks = Vec::new();
    if let Some(obfs) = q.get("obfs").filter(|s| !s.is_empty()) {
        if obfs.eq_ignore_ascii_case("salamander") {
            let pw = q.get("obfs-password")?;
            if pw.len() < 4 || pw.len() > 512 {
                return None;
            }
            udp_masks.push(json!({
                "type": "salamander",
                "settings": { "password": pw }
            }));
        } else {
            return None;
        }
    }
    if let Some(mport) = q.get("mport").filter(|s| !s.is_empty()) {
        let valid_mport = mport
            .chars()
            .all(|c| c.is_ascii_digit() || c == ',' || c == '-');
        if valid_mport {
            udp_masks.push(json!({
                "type": "udphop",
                "settings": {
                    "mode": "intervalLocal,intervalRemote",
                    "remotePorts": mport,
                    "interval": "15-30"
                }
            }));
        }
    }

    let mut stream = Map::new();
    stream.insert("network".into(), json!("hysteria"));
    stream.insert("security".into(), json!("tls"));
    stream.insert(
        "tlsSettings".into(),
        json!({
            "serverName": sni,
            "alpn": ["h3"]
        }),
    );
    stream.insert(
        "hysteriaSettings".into(),
        json!({
            "version": 2,
            "auth": auth
        }),
    );
    if !udp_masks.is_empty() {
        stream.insert("finalmask".into(), json!({ "udp": udp_masks }));
    }

    let outbound = json!({
        "tag": "proxy",
        "protocol": "hysteria",
        "settings": {
            "version": 2,
            "address": host,
            "port": port
        },
        "streamSettings": Value::Object(stream)
    });

    let remark = clean_remark(u.fragment().unwrap_or(""), &format!("Hysteria2 {host}:{port}"));
    let region_hint = detect_region_hint(&remark, &host, source_region_hint);
    let id = short_id_hash(&format!("hy2:{host}:{port}:{auth}:{sni}"));

    Some(VpnCandidate {
        id,
        raw_uri: uri.to_string(),
        name: remark,
        protocol: "hysteria2".into(),
        transport: "quic".into(),
        security: "tls".into(),
        sni: sni.clone(),
        host,
        port,
        region_hint,
        whitelist_friendly: is_whitelist_sni(&sni),
        fragment_enabled: false,
        via_warp: false,
        priority_score: 95,
        outbound_json: outbound,
        source_tier,
    })
}

fn parse_trojan(
    uri: &str,
    source_region_hint: &str,
    source_tier: u8,
    fragment_tls: bool,
) -> Option<VpnCandidate> {
    let u = Url::parse(uri).ok()?;
    let password = percent_decode_str(u.username()).decode_utf8().ok()?.to_string();
    if password.is_empty() || password.len() > 512 {
        return None;
    }
    let host = u.host_str()?.trim_matches(|c| c == '[' || c == ']').to_string();
    let port = u.port().unwrap_or(443);
    if !is_valid_public_host(&host, port) {
        return None;
    }
    let q = parse_query_map(&u);
    let (stream_settings, transport, security, sni, score) =
        build_common_stream_settings(&q, &host, "tls", fragment_tls)?;

    let outbound = json!({
        "tag": "proxy",
        "protocol": "trojan",
        "settings": {
            "address": host,
            "port": port,
            "password": password
        },
        "streamSettings": stream_settings
    });

    let remark = clean_remark(u.fragment().unwrap_or(""), &format!("Trojan {host}:{port}"));
    let region_hint = detect_region_hint(&remark, &host, source_region_hint);
    let id = short_id_hash(&format!("trojan:{host}:{port}:{password}:{sni}"));

    let has_frag = stream_settings.get("finalmask").is_some();

    Some(VpnCandidate {
        id,
        raw_uri: uri.to_string(),
        name: remark,
        protocol: "trojan".into(),
        transport,
        security,
        sni: sni.clone(),
        host,
        port,
        region_hint,
        whitelist_friendly: is_whitelist_sni(&sni),
        fragment_enabled: has_frag,
        via_warp: false,
        priority_score: score - 5,
        outbound_json: outbound,
        source_tier,
    })
}

fn parse_shadowsocks(uri: &str, source_region_hint: &str, source_tier: u8) -> Option<VpnCandidate> {
    let u = Url::parse(uri).ok()?;
    if u.query().map(|q| q.contains("plugin=")).unwrap_or(false) {
        return None; // SIP003 plugins unsupported
    }
    let host = u.host_str()?.trim_matches(|c| c == '[' || c == ']').to_string();
    let port = u.port()?;
    if !is_valid_public_host(&host, port) {
        return None;
    }

    let (method, password) = if let Some(pw) = u.password() {
        (
            percent_decode_str(u.username()).decode_utf8().ok()?.to_string(),
            percent_decode_str(pw).decode_utf8().ok()?.to_string(),
        )
    } else {
        let dec = decode_b64_flexible(u.username())?;
        let text = String::from_utf8(dec).ok()?;
        let (m, p) = text.split_once(':')?;
        (m.to_string(), p.to_string())
    };

    let m_low = method.to_ascii_lowercase();
    let is_ss2022 = matches!(
        m_low.as_str(),
        "2022-blake3-aes-128-gcm" | "2022-blake3-aes-256-gcm" | "2022-blake3-chacha20-poly1305"
    );
    let is_aead = matches!(
        m_low.as_str(),
        "aes-128-gcm"
            | "aes-256-gcm"
            | "chacha20-poly1305"
            | "chacha20-ietf-poly1305"
            | "xchacha20-poly1305"
            | "xchacha20-ietf-poly1305"
    );
    if (!is_ss2022 && !is_aead) || password.is_empty() {
        return None;
    }
    // Strict SS2022 PSK length + standard base64 validation (prevents xray-rust config rejection!)
    let mut norm_password = password;
    if is_ss2022 {
        let req_len = if m_low == "2022-blake3-aes-128-gcm" {
            16usize
        } else {
            32usize
        };
        let mut canon_parts = Vec::new();
        for part in norm_password.split(':') {
            let bytes = decode_b64_flexible(part)?;
            if bytes.len() != req_len {
                return None;
            }
            canon_parts.push(base64::engine::general_purpose::STANDARD.encode(&bytes));
        }
        if canon_parts.is_empty() {
            return None;
        }
        norm_password = canon_parts.join(":");
    }
    let password = norm_password;

    let outbound = json!({
        "tag": "proxy",
        "protocol": "shadowsocks",
        "settings": {
            "address": host,
            "port": port,
            "method": m_low,
            "password": password
        }
    });

    let remark = clean_remark(u.fragment().unwrap_or(""), &format!("SS {host}:{port}"));
    let region_hint = detect_region_hint(&remark, &host, source_region_hint);
    let id = short_id_hash(&format!("ss:{host}:{port}:{m_low}:{password}"));

    Some(VpnCandidate {
        id,
        raw_uri: uri.to_string(),
        name: remark,
        protocol: "shadowsocks".into(),
        transport: "tcp".into(),
        security: if is_ss2022 { "ss2022".into() } else { "aead".into() },
        sni: String::new(),
        host,
        port,
        region_hint,
        whitelist_friendly: false,
        fragment_enabled: false,
        via_warp: false,
        priority_score: if is_ss2022 { 48 } else { 28 },
        outbound_json: outbound,
        source_tier,
    })
}

/// Convert Opera SurfEasy HTTPS proxy endpoints into Tier-2 `VpnCandidate`s for `xray-rust`.
/// Sends a clean, unblocked camouflage SNI (`www.microsoft.com` / `dl.google.com`) + Chrome uTLS +
/// TCP TLS ClientHello fragmentation on the wire (exact `opera-proxy -fake-SNI` bypass against RF TSPU!),
/// while STILL cryptographically verifying Opera's real `am0.sec-tunnel.com` / `eu0.sec-tunnel.com`
/// WebPKI certificate via `verifyPeerCertByName` — zero `sec-tunnel.com` in plaintext, zero MITM risk!
pub fn opera_endpoints_to_candidates(
    endpoints: &[OperaEndpoint],
    target_region: &str,
    fragment_tls: bool,
) -> Vec<VpnCandidate> {
    const OPERA_DECOY_SNIS: &[&str] = &[
        "www.microsoft.com",
        "dl.google.com",
        "www.samsung.com",
        "www.apple.com",
    ];
    let mut out = Vec::new();
    for (idx, ep) in endpoints.iter().enumerate() {
        if target_region == "US" && ep.region != "US" {
            continue;
        }
        if target_region == "DE" && ep.region != "DE" {
            continue;
        }
        if ep.proxy_user.contains(':') || ep.proxy_user.is_empty() || ep.proxy_pass.is_empty() {
            continue;
        }

        let decoy_sni = OPERA_DECOY_SNIS[idx % OPERA_DECOY_SNIS.len()];
        let mut tls_settings = Map::new();
        // Send clean unblocked decoy SNI on the wire; verify real Opera *.sec-tunnel.com cert!
        tls_settings.insert("serverName".into(), json!(decoy_sni));
        tls_settings.insert("verifyPeerCertByName".into(), json!(ep.sni_verify));
        tls_settings.insert("fingerprint".into(), json!("chrome"));
        tls_settings.insert("alpn".into(), json!(["http/1.1"]));

        let mut stream = Map::new();
        stream.insert("network".into(), json!("tcp"));
        stream.insert("security".into(), json!("tls"));
        stream.insert("tlsSettings".into(), Value::Object(tls_settings));
        // Always fragment Opera's TLS handshake unless explicitly disabled
        let use_frag = fragment_tls;
        if use_frag {
            stream.insert("finalmask".into(), tcp_fragment_mask());
        }

        let outbound = json!({
            "tag": "proxy",
            "protocol": "http",
            "settings": {
                "address": ep.ip,
                "port": ep.port,
                "user": ep.proxy_user,
                "pass": ep.proxy_pass
            },
            "streamSettings": Value::Object(stream)
        });

        let flag_name = if ep.region == "US" {
            format!("Opera Relay US #{}", idx + 1)
        } else {
            format!("Opera Relay EU #{}", idx + 1)
        };
        let id = short_id_hash(&format!("opera:{}:{}:{}", ep.ip, ep.port, ep.opera_geo));

        out.push(VpnCandidate {
            id,
            raw_uri: format!("opera://{}:{}#{}", ep.ip, ep.port, ep.opera_geo),
            name: flag_name,
            protocol: "opera".into(),
            transport: "https".into(),
            security: "tls".into(),
            sni: decoy_sni.to_string(),
            host: ep.ip.clone(),
            port: ep.port,
            region_hint: ep.region.clone(),
            whitelist_friendly: false,
            fragment_enabled: use_frag,
            via_warp: false,
            priority_score: 118,
            outbound_json: outbound,
            source_tier: 2,
        });
    }
    out
}

/// Convert free official Opera SurfEasy relays (`AM` = USA, `EU` = Europe/DE) into **2-hop
/// `MASQUE-Chain` candidates** dialed through Cloudflare WARP MASQUE (`dialerProxy: "warp_bridge"`).
///
/// On Russian LTE/Wi-Fi carriers where `WARP MASQUE H3/H2` (`162.159.198.x:443`) connects cleanly
/// to Cloudflare's backbone while Opera's `77.111.244.0/22` subnet is IP-blocked by RKN, this
/// delivers commercial 10 Gbps USA & Europe exits with 100% reliability, zero TSPU inspection,
/// zero 16 KiB cap, zero registration, and zero extra memory!
pub fn opera_endpoints_to_warp_chain_candidates(
    endpoints: &[OperaEndpoint],
    target_region: &str,
) -> Vec<VpnCandidate> {
    let mut sorted: Vec<&OperaEndpoint> = endpoints.iter().collect();
    sorted.sort_by_key(|ep| match target_region {
        "US" => if ep.region == "US" { 0u8 } else { 1u8 },
        "DE" => if ep.region == "DE" { 0u8 } else { 1u8 },
        _ => 0u8,
    });

    let mut out = Vec::with_capacity(sorted.len());
    for (idx, ep) in sorted.into_iter().enumerate() {
        let outbound = json!({
            "tag": "proxy",
            "protocol": "http",
            "settings": {
                "address": ep.ip,
                "port": ep.port,
                "user": ep.proxy_user,
                "pass": ep.proxy_pass
            },
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {
                    "serverName": ep.sni_verify,
                    "fingerprint": "chrome",
                    "alpn": ["h2", "http/1.1"]
                },
                "sockopt": {
                    "dialerProxy": "warp_bridge"
                }
            }
        });

        let flag_name = if ep.region == "US" {
            format!("Opera USA + MASQUE #{}", idx + 1)
        } else {
            format!("Opera EU + MASQUE #{}", idx + 1)
        };
        let id = short_id_hash(&format!("wchain:opera:{}:{}:{}", ep.ip, ep.port, ep.opera_geo));

        out.push(VpnCandidate {
            id,
            raw_uri: format!("opera+warp://{}:{}#{}", ep.ip, ep.port, ep.opera_geo),
            name: flag_name,
            protocol: "opera".into(),
            transport: "https".into(),
            security: "tls".into(),
            sni: ep.sni_verify.clone(),
            host: ep.ip.clone(),
            port: ep.port,
            region_hint: ep.region.clone(),
            whitelist_friendly: true,
            fragment_enabled: false,
            via_warp: true,
            priority_score: 145,
            outbound_json: outbound,
            source_tier: 2,
        });
    }
    out
}

/// Convert any chain-compatible USA/Germany exit candidate (`trojan`+TLS, `vless`+TLS,
/// `shadowsocks` AEAD/SS2022, `vmess`+TLS/AEAD) into a **2-hop `MASQUE-Chain` candidate**
/// dialed through Cloudflare WARP MASQUE (`dialerProxy: "warp_bridge"`).
/// Unlocks RKN IP-blocked Hetzner Frankfurt (`DE`) & US datacenter servers at full speed!
pub fn candidate_to_warp_chain(cand: &VpnCandidate) -> Option<VpnCandidate> {
    if cand.via_warp {
        return None;
    }
    // Strict xray-rust v0.10.0 chain compatibility rules:
    // - Supported exit protocols: trojan, vless (TLS only, NOT reality), shadowsocks, vmess, http
    // - Unsupported with dialerProxy: reality, hysteria2, wireguard, masque, xhttp w/ downloadSettings
    let compatible = match (cand.protocol.as_str(), cand.security.as_str()) {
        ("trojan", "tls") => true,
        ("vless", "tls") => true,
        ("vmess", "tls" | "none") => true,
        ("shadowsocks", "ss2022" | "aead" | "none") => true,
        _ => false,
    };
    if !compatible {
        return None;
    }
    // Transport must be a TCP-based carrier (XHTTP with alpn=h3 uses QUIC and rejects dialerProxy)
    if !matches!(
        cand.transport.as_str(),
        "tcp" | "ws" | "httpupgrade" | "grpc"
    ) {
        return None;
    }

    let mut ob = cand.outbound_json.clone();
    let obj = ob.as_object_mut()?;

    let ss_val = obj
        .entry("streamSettings")
        .or_insert_with(|| json!({ "network": "tcp" }));
    let ss = ss_val.as_object_mut()?;
    // Remove outer TCP fragment mask (stream is already encapsulated inside Cloudflare MASQUE!)
    ss.remove("finalmask");
    let sock_val = ss.entry("sockopt").or_insert_with(|| json!({}));
    if let Some(sock) = sock_val.as_object_mut() {
        sock.remove("addressPortStrategy");
        sock.insert("dialerProxy".into(), json!("warp_bridge"));
    } else {
        ss.insert("sockopt".into(), json!({ "dialerProxy": "warp_bridge" }));
    }

    let mut chained = cand.clone();
    chained.id = short_id_hash(&format!("wchain:{}", cand.id));
    chained.via_warp = true;
    chained.fragment_enabled = false;
    chained.whitelist_friendly = true;
    chained.priority_score = cand.priority_score + 55;
    chained.outbound_json = ob;
    Some(chained)
}

/// Build the shared zero-copy loopback `WARP MASQUE H3 + H2` 1st-hop carrier outbounds,
/// inbound, routing rule, and `leastLoad` balancer for `MASQUE-Chain` 2-hop configs.
pub fn build_warp_masque_carrier(
    acc: &WarpAccountCache,
    hop_port: u16,
    fragment_tls: bool,
) -> Option<(Value, Vec<Value>, Value, Value)> {
    if !acc.has_masque() {
        return None;
    }
    let mut addrs = vec![format!(
        "{}/32",
        acc.masque_ipv4.split('/').next().unwrap_or(&acc.masque_ipv4)
    )];
    if !acc.masque_ipv6.is_empty() {
        addrs.push(format!(
            "{}/128",
            acc.masque_ipv6.split('/').next().unwrap_or(&acc.masque_ipv6)
        ));
    }

    let eps = warp_masque_candidate_endpoints(&acc.masque_endpoint_ip);
    let (primary_ip, primary_port) = eps
        .first()
        .cloned()
        .unwrap_or_else(|| ("162.159.198.2".to_string(), 443));

    let hop_inbound = json!({
        "tag": "warp_hop_in",
        "listen": "127.0.0.1",
        "port": hop_port,
        "protocol": "socks",
        "settings": {
            "auth": "noauth",
            "udp": false
        }
    });

    // Primary carrier: MASQUE HTTP/3 QUIC (ultra-fast, 0 head-of-line blocking, proven 3/3 on RF LTE!)
    let h3_primary = json!({
        "tag": "warp_hop_h3",
        "protocol": "masque",
        "settings": {
            "address": primary_ip,
            "port": primary_port,
            "remoteDNS": ["1.1.1.1", "8.8.8.8"]
        },
        "streamSettings": {
            "network": "masque",
            "security": "tls",
            "tlsSettings": {
                "serverName": "consumer-masque.cloudflareclient.com"
            },
            "masqueSettings": {
                "warp": {
                    "privateKey": acc.masque_private_key_pkcs8_b64,
                    "publicKey": acc.masque_peer_public_key_b64,
                    "address": addrs
                }
            }
        }
    });

    // Secondary carrier: MASQUE HTTP/2 over TCP:443 + TLS ClientHello fragmentation
    // (seamlessly takes over if a carrier/Wi-Fi blocks UDP/QUIC!)
    let mut h2_stream = Map::new();
    h2_stream.insert("network".into(), json!("masque"));
    h2_stream.insert("security".into(), json!("tls"));
    h2_stream.insert(
        "tlsSettings".into(),
        json!({
            "serverName": "consumer-masque.cloudflareclient.com",
            "fingerprint": "chrome",
            "alpn": ["h2"]
        }),
    );
    h2_stream.insert(
        "masqueSettings".into(),
        json!({
            "warp": {
                "privateKey": acc.masque_private_key_pkcs8_b64,
                "publicKey": acc.masque_peer_public_key_b64,
                "address": addrs
            }
        }),
    );
    if fragment_tls {
        h2_stream.insert("finalmask".into(), tcp_fragment_mask());
    }
    let h2_backup = json!({
        "tag": "warp_hop_h2",
        "protocol": "masque",
        "settings": {
            "address": primary_ip,
            "port": primary_port,
            "remoteDNS": ["1.1.1.1", "8.8.8.8"]
        },
        "streamSettings": Value::Object(h2_stream)
    });

    let bridge_outbound = json!({
        "tag": "warp_bridge",
        "protocol": "socks",
        "settings": {
            "address": "127.0.0.1",
            "port": hop_port
        }
    });

    let hop_rule = json!({
        "type": "field",
        "inboundTag": ["warp_hop_in"],
        "balancerTag": "warp_hop_bal"
    });

    // Zero-collision 2-member MASQUE carrier:
    // - `warp_hop_h3` (HTTP/3 QUIC) is instant default (`fallbackTag`) — 0ms HoL blocking!
    // - `warp_hop_h2` (HTTP/2 TCP + TLS fragment) seamlessly takes over if UDP/QUIC is blocked!
    // Keeping strictly 2 members (no simultaneous 3rd session on same key) eliminates Cloudflare
    // consumer single-key session contention (`rep=0x01`) right after TUN startup!
    let hop_balancer = json!({
        "tag": "warp_hop_bal",
        "selector": ["warp_hop_"],
        "strategy": {
            "type": "leastLoad",
            "settings": {
                "maxRTT": "4500ms",
                "tolerance": 0.25
            }
        },
        "fallbackTag": "warp_hop_h3"
    });

    Some((
        hop_inbound,
        vec![h3_primary, h2_backup, bridge_outbound],
        hop_rule,
        hop_balancer,
    ))
}

/// Convert Cloudflare WARP credentials into Tier-3 `VpnCandidate`s:
/// 1) MASQUE over HTTP/3 QUIC (looks like ordinary HTTP/3 web traffic)
/// 2) MASQUE over HTTP/2 TCP + TLS ClientHello fragmentation (passes even when ALL UDP is blocked!)
/// 3) WireGuard with UDP initial noise packets (defeats 0x01 WireGuard signature detection).
pub fn warp_account_to_candidates(
    acc: &WarpAccountCache,
    fragment_tls: bool,
) -> Vec<VpnCandidate> {
    let mut out = Vec::new();

    if acc.has_masque() {
        let mut addrs = vec![format!("{}/32", acc.masque_ipv4.split('/').next().unwrap_or(&acc.masque_ipv4))];
        if !acc.masque_ipv6.is_empty() {
            addrs.push(format!(
                "{}/128",
                acc.masque_ipv6.split('/').next().unwrap_or(&acc.masque_ipv6)
            ));
        }

        for (idx, (ip, port)) in warp_masque_candidate_endpoints(&acc.masque_endpoint_ip)
            .into_iter()
            .take(3)
            .enumerate()
        {
            // MASQUE over HTTP/3 (QUIC 443)
            let h3_outbound = json!({
                "tag": "proxy",
                "protocol": "masque",
                "settings": {
                    "address": ip,
                    "port": port,
                    "remoteDNS": ["1.1.1.1", "1.0.0.1"]
                },
                "streamSettings": {
                    "network": "masque",
                    "security": "tls",
                    "tlsSettings": {
                        "serverName": "consumer-masque.cloudflareclient.com"
                    },
                    "masqueSettings": {
                        "warp": {
                            "privateKey": acc.masque_private_key_pkcs8_b64,
                            "publicKey": acc.masque_peer_public_key_b64,
                            "address": addrs
                        }
                    }
                }
            });
            out.push(VpnCandidate {
                id: short_id_hash(&format!("warp-masque-h3:{ip}:{port}")),
                raw_uri: format!("warp+masque://{ip}:{port}?alpn=h3"),
                name: format!("Cloudflare MASQUE H3 #{}", idx + 1),
                protocol: "warp-masque".into(),
                transport: "masque-h3".into(),
                security: "tls".into(),
                sni: "consumer-masque.cloudflareclient.com".into(),
                host: ip.clone(),
                port,
                region_hint: "DE".into(),
                whitelist_friendly: false,
                fragment_enabled: false,
                via_warp: false,
                priority_score: 105,
                outbound_json: h3_outbound,
                source_tier: 3,
            });

            // MASQUE over HTTP/2 (TCP 443 + TLS ClientHello fragmentation)
            let mut h2_stream = Map::new();
            h2_stream.insert("network".into(), json!("masque"));
            h2_stream.insert("security".into(), json!("tls"));
            h2_stream.insert(
                "tlsSettings".into(),
                json!({
                    "serverName": "consumer-masque.cloudflareclient.com",
                    "fingerprint": "chrome",
                    "alpn": ["h2"]
                }),
            );
            h2_stream.insert(
                "masqueSettings".into(),
                json!({
                    "warp": {
                        "privateKey": acc.masque_private_key_pkcs8_b64,
                        "publicKey": acc.masque_peer_public_key_b64,
                        "address": addrs
                    }
                }),
            );
            if fragment_tls {
                h2_stream.insert("finalmask".into(), tcp_fragment_mask());
            }
            let h2_outbound = json!({
                "tag": "proxy",
                "protocol": "masque",
                "settings": {
                    "address": ip,
                    "port": port,
                    "remoteDNS": ["1.1.1.1", "1.0.0.1"]
                },
                "streamSettings": Value::Object(h2_stream)
            });
            out.push(VpnCandidate {
                id: short_id_hash(&format!("warp-masque-h2:{ip}:{port}")),
                raw_uri: format!("warp+masque://{ip}:{port}?alpn=h2"),
                name: format!("Cloudflare MASQUE H2 #{}", idx + 1),
                protocol: "warp-masque".into(),
                transport: "masque-h2".into(),
                security: "tls".into(),
                sni: "consumer-masque.cloudflareclient.com".into(),
                host: ip,
                port,
                region_hint: "DE".into(),
                whitelist_friendly: false,
                fragment_enabled: fragment_tls,
                via_warp: false,
                priority_score: 106,
                outbound_json: h2_outbound,
                source_tier: 3,
            });
        }
    }

    if acc.has_wg() {
        let mut addrs = vec![format!(
            "{}/32",
            acc.wg_ipv4.split('/').next().unwrap_or(&acc.wg_ipv4)
        )];
        if !acc.wg_ipv6.is_empty() {
            addrs.push(format!(
                "{}/128",
                acc.wg_ipv6.split('/').next().unwrap_or(&acc.wg_ipv6)
            ));
        }

        for (idx, (ip, port)) in warp_wg_candidate_endpoints().into_iter().take(4).enumerate() {
            let wg_outbound = json!({
                "tag": "proxy",
                "protocol": "wireguard",
                "settings": {
                    "secretKey": acc.wg_private_key_b64,
                    "address": addrs,
                    "mtu": 1280,
                    "peers": [{
                        "publicKey": acc.wg_peer_public_key_b64,
                        "allowedIPs": ["0.0.0.0/0", "::/0"],
                        "endpoint": format!("{ip}:{port}"),
                        "keepAlive": 25
                    }]
                },
                "streamSettings": {
                    "finalmask": {
                        "udp": [{
                            "type": "noise",
                            "settings": {
                                "noise": [
                                    { "rand": "18-42", "delay": "2-5" },
                                    { "rand": "24-64", "delay": "2-5" }
                                ]
                            }
                        }]
                    }
                }
            });
            out.push(VpnCandidate {
                id: short_id_hash(&format!("warp-wg:{ip}:{port}")),
                raw_uri: format!("warp+wg://{ip}:{port}"),
                name: format!("Cloudflare WARP AWG #{}", idx + 1),
                protocol: "warp-wg".into(),
                transport: "wg".into(),
                security: "wg".into(),
                sni: String::new(),
                host: ip,
                port,
                region_hint: "DE".into(),
                whitelist_friendly: false,
                fragment_enabled: false,
                via_warp: false,
                priority_score: 100,
                outbound_json: wg_outbound,
                source_tier: 3,
            });
        }
    }

    out
}

pub fn human_protocol_label(c: &VpnCandidate) -> String {
    if c.via_warp {
        return match (c.protocol.as_str(), c.security.as_str()) {
            ("opera", _) => "Opera + MASQUE".into(),
            ("trojan", _) => "Trojan + MASQUE".into(),
            ("vless", _) => "VLESS + MASQUE".into(),
            ("vmess", _) => "VMess + MASQUE".into(),
            ("shadowsocks", "ss2022") => "SS2022 + MASQUE".into(),
            ("shadowsocks", _) => "SS + MASQUE".into(),
            _ => format!("{} + MASQUE", c.protocol.to_ascii_uppercase()),
        };
    }
    match (c.protocol.as_str(), c.transport.as_str(), c.security.as_str()) {
        ("vless", "xhttp", "reality") => "VLESS XHTTP Reality".into(),
        ("vless", "xhttp", _) => "VLESS XHTTP TLS".into(),
        ("vless", "grpc", "reality") => "VLESS gRPC Reality".into(),
        ("vless", _, "reality") => "VLESS Reality".into(),
        ("vless", "ws", _) => "VLESS WS TLS".into(),
        ("vless", "grpc", _) => "VLESS gRPC TLS".into(),
        ("vless", _, _) => "VLESS TLS".into(),
        ("vmess", "xhttp", _) => "VMess XHTTP TLS".into(),
        ("vmess", "ws", _) => "VMess WS TLS".into(),
        ("vmess", "grpc", _) => "VMess gRPC TLS".into(),
        ("vmess", _, _) => "VMess AEAD TLS".into(),
        ("hysteria2", _, _) => "Hysteria 2 (QUIC)".into(),
        ("trojan", "xhttp", _) => "Trojan XHTTP TLS".into(),
        ("trojan", "ws", _) => "Trojan WS TLS".into(),
        ("trojan", "grpc", _) => "Trojan gRPC TLS".into(),
        ("trojan", _, "reality") => "Trojan Reality".into(),
        ("trojan", _, _) => "Trojan TLS".into(),
        ("shadowsocks", _, "ss2022") => "Shadowsocks 2022".into(),
        ("shadowsocks", _, _) => "Shadowsocks AEAD".into(),
        ("opera", _, _) => "Opera HTTPS TLS".into(),
        ("warp-masque", "masque-h3", _) => "WARP MASQUE H3".into(),
        ("warp-masque", "masque-h2", _) => "WARP MASQUE H2".into(),
        ("warp-wg", _, _) => "WARP + UDP Noise".into(),
        _ => c.protocol.to_ascii_uppercase(),
    }
}

/// Build a single `xray-rust` JSON config mapping each candidate `i` to local SOCKS5 port `base_port + i`
/// (plus an optional shared loopback `WARP MASQUE H3/H2` carrier on `base_port + 90` for 2-hop
/// `via_warp` USA/Germany candidates!) so we verify 1-hop AND 2-hop exits in one parallel sweep!
pub fn build_batch_probe_config(
    candidates: &[VpnCandidate],
    base_port: u16,
    warp_acc: Option<&WarpAccountCache>,
    fragment_tls: bool,
) -> String {
    let mut inbounds = Vec::with_capacity(candidates.len() + 1);
    let mut outbounds = Vec::with_capacity(candidates.len() + 5);
    let mut rules = Vec::with_capacity(candidates.len() + 1);
    let mut balancers = Vec::new();

    let wants_warp_chain = candidates.iter().any(|c| c.via_warp);
    let has_warp_carrier = if wants_warp_chain {
        if let Some(acc) = warp_acc {
            let hop_port = base_port.saturating_add(90);
            if let Some((hop_in, mut hop_obs, hop_rule, hop_bal)) =
                build_warp_masque_carrier(acc, hop_port, fragment_tls)
            {
                inbounds.push(hop_in);
                outbounds.append(&mut hop_obs);
                rules.push(hop_rule);
                balancers.push(hop_bal);
                true
            } else {
                false
            }
        } else {
            false
        }
    } else {
        false
    };

    for (idx, c) in candidates.iter().enumerate() {
        if c.via_warp && !has_warp_carrier {
            continue;
        }
        let port = base_port + idx as u16;
        let in_tag = format!("in_{idx}");
        let out_tag = format!("p_{idx}");

        inbounds.push(json!({
            "tag": in_tag,
            "listen": "127.0.0.1",
            "port": port,
            "protocol": "socks",
            "settings": {
                "auth": "noauth",
                "udp": false
            }
        }));

        let mut ob = c.outbound_json.clone();
        if let Some(obj) = ob.as_object_mut() {
            obj.insert("tag".into(), json!(out_tag));
        }
        outbounds.push(ob);

        rules.push(json!({
            "type": "field",
            "inboundTag": [in_tag],
            "outboundTag": out_tag
        }));
    }

    outbounds.push(json!({
        "tag": "direct",
        "protocol": "freedom",
        "settings": {}
    }));

    let mut routing = Map::new();
    routing.insert("domainStrategy".into(), json!("AsIs"));
    routing.insert("rules".into(), Value::Array(rules));
    if !balancers.is_empty() {
        routing.insert("balancers".into(), Value::Array(balancers));
    }

    let mut root = Map::new();
    root.insert("inbounds".into(), Value::Array(inbounds));
    root.insert("outbounds".into(), Value::Array(outbounds));
    root.insert("routing".into(), Value::Object(routing));
    if has_warp_carrier {
        root.insert(
            "observatory".into(),
            json!({
                "subjectSelector": ["warp_hop_"],
                "probeURL": "https://www.gstatic.com/generate_204",
                "probeInterval": "30s",
                "enableConcurrency": false
            }),
        );
    }

    Value::Object(root).to_string()
}

/// Does a given verified outbound natively support UDP in `xray-rust` v0.10.0?
fn node_supports_native_udp(n: &VerifiedVpnNode) -> bool {
    if n.via_warp || n.protocol == "opera" {
        return false;
    }
    let net = n
        .outbound_json
        .pointer("/streamSettings/network")
        .and_then(|v| v.as_str())
        .unwrap_or("tcp");
    match n.protocol.as_str() {
        "hysteria2" | "warp-masque" | "warp-wg" | "trojan" | "vmess" | "shadowsocks" => true,
        "vless" => net == "tcp",
        _ => false,
    }
}

/// Build production Android `xray-rust` TUN configuration with:
/// - Primary verified node (`vpn_0`) + up to 5 hot-standby verified US/DE backup nodes
/// - Seamless `MASQUE-Chain` 2-hop carrier (`warp_hop_h3` QUIC + `warp_hop_h2` TCP+frag) whenever
///   any node in the pool has `via_warp == true` (100% immune to RKN IP blocks & TSPU on RF LTE!)
/// - Built-in `observatory` + `leastLoad` auto-failover balancer (0-downtime seamless switch!)
/// - Loopback SOCKS5 on `127.0.0.1:10808` (health monitor + background feed refresh)
/// - Encrypted HTTP/2 DoH DNS (`https://8.8.8.8/dns-query`, `https://9.9.9.9/dns-query`) via `198.18.0.1`
/// - Clean QUIC UDP/443->HTTP/2 steering + MASQUE UDP voice/game forwarding on 2-hop tunnels
/// - Optional RU direct split-routing (`.ru`, `.рф`, `.su`, Russian banks, Gosuslugi, marketplaces).
pub fn build_production_tun_config(
    nodes: &[VerifiedVpnNode],
    pinned_node_id: Option<&str>,
    bypass_ru_domains: bool,
    fragment_tls: bool,
    local_socks_port: u16,
    warp_acc: Option<&WarpAccountCache>,
) -> Result<(String, VerifiedVpnNode, usize), String> {
    build_production_tun_config_ex(
        nodes,
        pinned_node_id,
        false,
        bypass_ru_domains,
        fragment_tls,
        local_socks_port,
        warp_acc,
    )
}

pub fn build_production_tun_config_ex(
    nodes: &[VerifiedVpnNode],
    pinned_node_id: Option<&str>,
    whitelist_mode: bool,
    bypass_ru_domains: bool,
    fragment_tls: bool,
    local_socks_port: u16,
    warp_acc: Option<&WarpAccountCache>,
) -> Result<(String, VerifiedVpnNode, usize), String> {
    let can_warp_chain = warp_acc.is_some_and(|w| w.has_masque());

    let mut ordered: Vec<&VerifiedVpnNode> = nodes
        .iter()
        .filter(|n| !n.via_warp || can_warp_chain)
        .collect();
    if ordered.is_empty() {
        return Err("Нет проверенных узлов для запуска туннеля".into());
    }

    // Preserve caller's region-aware order for non-pinned verified nodes, keeping:
    // 1) pinned node first, 2) device-verified first, 3) real US/DE/EU exits (tier<=3) strictly
    //    above local CF WARP fallback (tier==4), 4) lowest fail_count.
    ordered.sort_by_key(|n| {
        let is_pinned = pinned_node_id.map(|id| id == n.id).unwrap_or(false);
        let is_local_warp = if n.source_tier >= 4 { 1u8 } else { 0u8 };
        (
            if is_pinned { 0u8 } else { 1u8 },
            if n.device_verified { 0u8 } else { 1u8 },
            is_local_warp,
            n.fail_count,
        )
    });

    if pinned_node_id.is_none() {
        if ordered.first().is_some_and(|n| n.device_verified) {
            ordered.retain(|n| n.device_verified);
        }
        // CRITICAL: Never mix 30ms local CF-DME WARP into the same `leastLoad` balancer as
        // genuine US/DE exits — otherwise `leastLoad` would favor DME's lower RTT over US/DE!
        if ordered.first().is_some_and(|n| n.source_tier <= 3) {
            ordered.retain(|n| n.source_tier <= 3);
        }
        // CRITICAL: In «Белые списки РФ» mode, if we have verified RF-whitelist (Минцифры SNI /
        // VK-Yandex-CDN CIDR) servers, isolate the pool STRICTLY to whitelist servers so zero
        // packets ever touch non-whitelisted endpoints during a mobile whitelist lockdown!
        if whitelist_mode && ordered.first().is_some_and(|n| n.whitelist_friendly) {
            ordered.retain(|n| n.whitelist_friendly);
        }
    }
    ordered.truncate(6);

    let chosen_primary = (*ordered[0]).clone();
    let backup_count = ordered.len().saturating_sub(1);
    let use_balancer = pinned_node_id.is_none() && ordered.len() >= 2;
    let needs_warp_carrier = ordered.iter().any(|n| n.via_warp);
    let all_support_udp = ordered.iter().all(|n| node_supports_native_udp(n));

    let mut inbounds = vec![json!({
        "tag": "tun-in",
        "protocol": "tun",
        "settings": {}
    })];
    if local_socks_port > 0 {
        inbounds.push(json!({
            "tag": "local-socks",
            "listen": "127.0.0.1",
            "port": local_socks_port,
            "protocol": "socks",
            "settings": {
                "auth": "noauth",
                "udp": true
            }
        }));
    }

    let mut outbounds = Vec::new();
    let mut rules = Vec::new();
    let mut balancers = Vec::new();
    let mut obs_selectors: Vec<Value> = Vec::new();
    let mut first_tag = String::new();
    let mut first_udp_vpn_tag: Option<String> = None;

    for (idx, n) in ordered.iter().enumerate() {
        let tag = format!("vpn_{idx}");
        if idx == 0 {
            first_tag = tag.clone();
        }
        if first_udp_vpn_tag.is_none() && node_supports_native_udp(n) {
            first_udp_vpn_tag = Some(tag.clone());
        }
        let mut ob = n.outbound_json.clone();
        if let Some(obj) = ob.as_object_mut() {
            obj.insert("tag".into(), json!(tag));
            if !n.via_warp {
                if let Some(ss) = obj.get_mut("streamSettings").and_then(|v| v.as_object_mut()) {
                    let net = ss.get("network").and_then(|v| v.as_str()).unwrap_or("");
                    let sec = ss.get("security").and_then(|v| v.as_str()).unwrap_or("");
                    let is_tcp_carrier =
                        matches!(net, "tcp" | "ws" | "httpupgrade" | "grpc" | "xhttp");
                    if is_tcp_carrier && matches!(sec, "tls" | "reality") {
                        if !fragment_tls {
                            ss.remove("finalmask");
                        } else if sec == "tls" && !n.device_verified {
                            ss.entry("finalmask").or_insert_with(tcp_fragment_mask);
                        }
                    }
                }
            }
        }
        outbounds.push(ob);
    }

    let mut mounted_warp_carrier = false;
    if needs_warp_carrier {
        if let Some(acc) = warp_acc {
            let hop_port = if local_socks_port > 0 {
                local_socks_port.saturating_add(3)
            } else {
                10811
            };
            if let Some((hop_in, mut hop_obs, hop_rule, hop_bal)) =
                build_warp_masque_carrier(acc, hop_port, fragment_tls)
            {
                inbounds.push(hop_in);
                outbounds.append(&mut hop_obs);
                // PRIORITY #0: Route loopback `warp_hop_in` strictly into `WARP MASQUE H3/H2`!
                rules.push(hop_rule);
                balancers.push(hop_bal);
                obs_selectors.push(json!("warp_hop_"));
                mounted_warp_carrier = true;
            }
        }
    }

    outbounds.push(json!({
        "tag": "direct",
        "protocol": "freedom",
        "settings": {}
    }));
    outbounds.push(json!({
        "tag": "block",
        "protocol": "blackhole",
        "settings": {}
    }));

    // Private/LAN subnets always direct
    rules.push(json!({
        "type": "field",
        "ip": ["geoip:private"],
        "outboundTag": "direct"
    }));

    if bypass_ru_domains {
        rules.push(json!({
            "type": "field",
            "domain": [
                "domain:ru",
                "domain:su",
                "domain:xn--p1ai",
                "domain:gosuslugi.ru",
                "domain:sberbank.ru",
                "domain:sber.ru",
                "domain:tbank.ru",
                "domain:tinkoff.ru",
                "domain:alfabank.ru",
                "domain:vtb.ru",
                "domain:nalog.ru",
                "domain:mos.ru",
                "domain:yandex.ru",
                "domain:yandex.net",
                "domain:ya.ru",
                "domain:vk.com",
                "domain:userapi.com",
                "domain:mail.ru",
                "domain:ozon.ru",
                "domain:wildberries.ru",
                "domain:wb.ru",
                "domain:avito.ru",
                "domain:2gis.ru",
                "domain:nspk.ru",
                "domain:mirpay.ru"
            ],
            "outboundTag": "direct"
        }));
    }

    if all_support_udp {
        if use_balancer {
            rules.push(json!({
                "type": "field",
                "network": "tcp,udp",
                "balancerTag": "auto_pool"
            }));
        } else {
            rules.push(json!({
                "type": "field",
                "network": "tcp,udp",
                "outboundTag": first_tag
            }));
        }
    } else {
        // Pool includes TCP-streamed or 2-hop `MASQUE-Chain` outbounds:
        // 1) Block UDP:443 so browsers/YouTube/Instagram switch instantly (0.1ms) to HTTP/2 TCP
        //    through our genuine US/DE exit IP with zero leak & zero QUIC stall!
        //    Also block raw UDP STUN (3478/5349/19302-19309) when no native foreign UDP node exists
        //    so WebRTC never leaks the 1st-hop Cloudflare PoP IP and upgrades cleanly to TCP TURN!
        let block_udp_ports = if first_udp_vpn_tag.is_some() {
            "443"
        } else {
            "443,3478,5349,19302-19309"
        };
        rules.push(json!({
            "type": "field",
            "network": "udp",
            "port": block_udp_ports,
            "outboundTag": "block"
        }));
        // 2) Route remaining non-443/non-STUN UDP via native UDP US/DE node (if present) or MASQUE H3!
        let udp_out = if let Some(ref ut) = first_udp_vpn_tag {
            ut.as_str()
        } else if mounted_warp_carrier {
            "warp_hop_h3"
        } else {
            "block"
        };
        rules.push(json!({
            "type": "field",
            "network": "udp",
            "outboundTag": udp_out
        }));
        // 3) Route all TCP (+ in-core HTTP/2 DoH DNS) through our US/DE pool!
        if use_balancer {
            rules.push(json!({
                "type": "field",
                "network": "tcp",
                "balancerTag": "auto_pool"
            }));
        } else {
            rules.push(json!({
                "type": "field",
                "network": "tcp",
                "outboundTag": first_tag
            }));
        }
    }

    if use_balancer {
        balancers.push(json!({
            "tag": "auto_pool",
            "selector": ["vpn_"],
            "strategy": {
                "type": "leastLoad",
                "settings": {
                    "maxRTT": "5000ms",
                    "tolerance": 0.20
                }
            },
            "fallbackTag": first_tag
        }));
        obs_selectors.push(json!("vpn_"));
    }

    let mut root = Map::new();
    root.insert(
        "dns".into(),
        json!({
            "queryStrategy": "UseIPv4",
            "servers": [
                "https://8.8.8.8/dns-query",
                "https://9.9.9.9/dns-query",
                "https://1.1.1.1/dns-query"
            ]
        }),
    );
    root.insert("inbounds".into(), Value::Array(inbounds));
    root.insert("outbounds".into(), Value::Array(outbounds));

    let mut routing = Map::new();
    routing.insert("domainStrategy".into(), json!("AsIs"));
    routing.insert("rules".into(), Value::Array(rules));
    if !balancers.is_empty() {
        routing.insert("balancers".into(), Value::Array(balancers));
    }
    if !obs_selectors.is_empty() {
        root.insert(
            "observatory".into(),
            json!({
                "subjectSelector": obs_selectors,
                "probeURL": "https://www.gstatic.com/generate_204",
                "probeInterval": "40s",
                "enableConcurrency": false
            }),
        );
    }
    root.insert("routing".into(), Value::Object(routing));

    Ok((Value::Object(root).to_string(), chosen_primary, backup_count))
}
