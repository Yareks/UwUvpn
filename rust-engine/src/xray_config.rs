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

/// Normalize `pcs` / `pinSHA256` / `pinnedPeerCertSha256` into Xray's comma-separated 64-hex SHA-256 format.
fn parse_pinned_cert_sha256(q: &HashMap<String, String>) -> Option<String> {
    let raw = q
        .get("pcs")
        .or_else(|| q.get("pinsha256"))
        .or_else(|| q.get("pin_sha256"))
        .or_else(|| q.get("pinnedpeercertsha256"))?
        .trim();
    if raw.is_empty() {
        return None;
    }
    let mut pins: Vec<String> = Vec::new();
    for item in raw.split([',', ';']) {
        let t = item.trim();
        if t.is_empty() {
            continue;
        }
        let t = t
            .strip_prefix("sha256/")
            .or_else(|| t.strip_prefix("sha256:"))
            .or_else(|| t.strip_prefix("SHA256:"))
            .unwrap_or(t);
        let hex_clean: String = t.chars().filter(|c| *c != ':' && *c != '-').collect();
        if hex_clean.len() == 64 && hex_clean.chars().all(|c| c.is_ascii_hexdigit()) {
            pins.push(hex_clean.to_ascii_lowercase());
        } else if let Some(bytes) = decode_b64_flexible(t) {
            if bytes.len() == 32 {
                pins.push(hex::encode(bytes));
            }
        }
    }
    pins.dedup();
    if pins.is_empty() {
        None
    } else {
        Some(pins.join(","))
    }
}

/// Sanitize XHTTP `extra` JSON query param (`xmux`, `xPadding*`, `scMax*`, `noGRPCHeader`, `downloadSettings`).
fn parse_xhttp_extra(q: &HashMap<String, String>) -> Option<Value> {
    let raw = q.get("extra")?.trim();
    if raw.is_empty() || raw.len() > 8192 {
        return None;
    }
    let val: Value = serde_json::from_str(raw).ok()?;
    let obj = val.as_object()?;
    const ALLOWED_EXTRA_KEYS: &[&str] = &[
        "headers",
        "xPaddingBytes",
        "xPaddingObfsMode",
        "xPaddingKey",
        "xPaddingHeader",
        "xPaddingPlacement",
        "xPaddingMethod",
        "uplinkHTTPMethod",
        "sessionIDPlacement",
        "sessionIDKey",
        "sessionIDTable",
        "sessionIDLength",
        "seqPlacement",
        "seqKey",
        "uplinkDataPlacement",
        "uplinkDataKey",
        "uplinkChunkSize",
        "noGRPCHeader",
        "noSSEHeader",
        "scMaxEachPostBytes",
        "scMinPostsIntervalMs",
        "scMaxConcurrentPosts",
        "scMaxBufferedPosts",
        "scStreamUpServerSecs",
        "serverMaxHeaderBytes",
        "xmux",
        "downloadSettings",
    ];
    let mut clean = Map::new();
    for (k, v) in obj {
        if ALLOWED_EXTRA_KEYS.contains(&k.as_str()) {
            clean.insert(k.clone(), v.clone());
        }
    }
    if clean.is_empty() {
        None
    } else {
        Some(Value::Object(clean))
    }
}

/// Build `streamSettings` for VLESS / Trojan links; returns `(streamSettings, transport, security, sni, score_bonus)`.
fn build_common_stream_settings(
    q: &HashMap<String, String>,
    default_host: &str,
    default_security: &str,
    fragment_tls: bool,
) -> Option<(Value, String, String, String, i32)> {
    build_common_stream_settings_ex(q, default_host, default_security, fragment_tls, false)
}

fn build_common_stream_settings_ex(
    q: &HashMap<String, String>,
    default_host: &str,
    default_security: &str,
    fragment_tls: bool,
    allow_vless_pq_none_security: bool,
) -> Option<(Value, String, String, String, i32)> {
    let cert_pin = parse_pinned_cert_sha256(q);
    // Reject unverified `allowInsecure=1` UNLESS a cryptographic SHA-256 certificate pin (`pcs`/`pinSHA256`)
    // is supplied (in Xray/Happ, a pinned leaf SHA-256 replaces CA check with zero MITM risk!).
    if is_truthy_insecure(q) && cert_pin.is_none() {
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

    // Refuse plaintext unencrypted public proxies unless protected by VLESS post-quantum ML-KEM-768 encryption
    let is_pq_none = allow_vless_pq_none_security && security == "none";
    if security != "reality" && security != "tls" && !is_pq_none {
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

    if !is_pq_none && (sni.is_empty() || sni.contains(char::is_whitespace) || sni.len() > 253) {
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
            // Keep `?ed=2048`/`?ed=2560` intact inside `path` — `xray-rust` enables 0-RTT WS early data!
            ws.insert(
                "path".into(),
                json!(if path.starts_with('/') {
                    path
                } else {
                    format!("/{path}")
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
            if let Some(extra) = parse_xhttp_extra(q) {
                xh.insert("extra".into(), extra);
                score += 10;
            }
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
        if sni.parse::<std::net::IpAddr>().is_ok() {
            return None;
        }
        let pbk = q
            .get("pbk")
            .or_else(|| q.get("password"))
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
        // Post-quantum ML-DSA-65 REALITY certificate verification (`pqv` / `mldsa65Verify`)
        if let Some(pqv) = q
            .get("pqv")
            .or_else(|| q.get("mldsa65verify"))
            .map(|s| s.trim())
            .filter(|s| !s.is_empty() && s.len() <= 4096)
        {
            rs.insert("mldsa65Verify".into(), json!(pqv));
            score += 12;
        }
        stream.insert("realitySettings".into(), Value::Object(rs));
        score += 75;
    } else if security == "tls" {
        // Plain WebPKI TLS requires non-IP serverName; pinned SHA-256 leaf certs work on IPs too!
        if sni.parse::<std::net::IpAddr>().is_ok() && cert_pin.is_none() {
            return None;
        }
        let fp = normalize_fingerprint(fp_raw, false);
        let mut ts = Map::new();
        if sni.parse::<std::net::IpAddr>().is_err() {
            ts.insert("serverName".into(), json!(sni));
        }
        ts.insert("fingerprint".into(), json!(fp));
        if let Some(a) = alpn {
            ts.insert("alpn".into(), json!(a));
        }
        if let Some(pin) = cert_pin {
            ts.insert("pinnedPeerCertSha256".into(), json!(pin));
        }
        if let Some(vcn) = q
            .get("vcn")
            .or_else(|| q.get("verifypeercertbyname"))
            .map(|s| s.trim())
            .filter(|s| !s.is_empty() && s.len() <= 253)
        {
            ts.insert("verifyPeerCertByName".into(), json!(vcn));
        }
        stream.insert("tlsSettings".into(), Value::Object(ts));
        score += 20;
    } else {
        // Post-quantum `mlkem768x25519plus` VLESS-encrypted stream (anti-TSPU 2026)
        score += 68;
    }

    // Apply TLS ClientHello fragmentation on TCP-carried TLS/REALITY when requested
    if fragment_tls && !is_h3_only && matches!(security.as_str(), "tls" | "reality") {
        stream.insert("finalmask".into(), tcp_fragment_mask());
    }

    Some((Value::Object(stream), network.to_string(), security, sni, score))
}

/// Parse a single share URI (`vless://`, `vmess://`, `hy2://`, `hysteria2://`, `trojan://`,
/// `ss://`, `wireguard://`, `wg://`, `socks5://`, `socks://`, `https://user:pass@host:port`)
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
    } else if trimmed.starts_with("wireguard://") || trimmed.starts_with("wg://") {
        parse_wireguard(trimmed, source_region_hint, source_tier)
    } else if trimmed.starts_with("socks5://") || trimmed.starts_with("socks://") {
        parse_socks5(trimmed, source_region_hint, source_tier)
    } else if trimmed.starts_with("https://") && trimmed.contains('@') {
        parse_https_proxy(trimmed, source_region_hint, source_tier, fragment_tls)
    } else {
        None
    }
}

/// Convert a raw Xray-core JSON configuration object (`{"remarks":"...","outbounds":[...]}`) or
/// standalone outbound object (`{"protocol":"vless","settings":...,"streamSettings":...}`) returned
/// by Happ / Remnawave / Marzban JSON subscriptions into validated Tier-0 `VpnCandidate`s!
pub fn parse_xray_json_config_to_candidates(
    cfg: &Value,
    fallback_name: &str,
    source_region_hint: &str,
    source_tier: u8,
) -> Vec<VpnCandidate> {
    let mut out = Vec::new();
    let root_remark = cfg
        .get("remarks")
        .or_else(|| cfg.get("remark"))
        .or_else(|| cfg.get("name"))
        .and_then(|v| v.as_str())
        .unwrap_or(fallback_name);

    let items: Vec<&Value> = if let Some(arr) = cfg.get("outbounds").and_then(|v| v.as_array()) {
        arr.iter().collect()
    } else if cfg.get("protocol").is_some() {
        vec![cfg]
    } else {
        return out;
    };

    for (idx, item) in items.into_iter().enumerate() {
        let Some(obj) = item.as_object() else {
            continue;
        };
        let Some(proto_raw) = obj.get("protocol").and_then(|v| v.as_str()) else {
            continue;
        };
        let proto_lc = proto_raw.trim().to_ascii_lowercase();
        if matches!(
            proto_lc.as_str(),
            "freedom" | "blackhole" | "dns" | "loopback" | "dokodemo-door"
        ) {
            continue;
        }
        if !matches!(
            proto_lc.as_str(),
            "vless" | "vmess" | "trojan" | "shadowsocks" | "hysteria" | "wireguard" | "socks" | "http" | "masque"
        ) {
            continue;
        }

        // Reject allowInsecure=true unless replaced by pinnedPeerCertSha256
        let mut clean_ob = obj.clone();
        clean_ob.remove("sendThrough");
        clean_ob.remove("proxySettings");
        if let Some(ss) = clean_ob
            .get_mut("streamSettings")
            .and_then(|v| v.as_object_mut())
        {
            if let Some(so) = ss.get_mut("sockopt").and_then(|v| v.as_object_mut()) {
                // Prevent untrusted JSON outbound from referencing missing dialerProxy tags
                so.remove("dialerProxy");
                so.remove("interface");
            }
            if let Some(ts) = ss.get_mut("tlsSettings").and_then(|v| v.as_object_mut()) {
                let has_pin = ts
                    .get("pinnedPeerCertSha256")
                    .and_then(|v| v.as_str())
                    .is_some_and(|s| !s.trim().is_empty());
                let insec = ts
                    .get("allowInsecure")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                if insec && !has_pin {
                    continue;
                }
                ts.remove("allowInsecure");
            }
        }
        clean_ob.insert("tag".into(), json!("proxy"));

        // Extract host & port from standard Xray settings forms
        let settings = clean_ob.get("settings");
        let (host, port) = extract_host_port_from_xray_settings(settings).unwrap_or_default();
        if !is_valid_public_host(&host, port) {
            continue;
        }

        let outbound_val = Value::Object(clean_ob);
        let transport = outbound_val
            .pointer("/streamSettings/network")
            .and_then(|v| v.as_str())
            .unwrap_or("tcp")
            .to_ascii_lowercase();
        let security = outbound_val
            .pointer("/streamSettings/security")
            .and_then(|v| v.as_str())
            .unwrap_or("none")
            .to_ascii_lowercase();
        let sni = outbound_val
            .pointer("/streamSettings/realitySettings/serverName")
            .or_else(|| outbound_val.pointer("/streamSettings/tlsSettings/serverName"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let has_frag = outbound_val.pointer("/streamSettings/finalmask").is_some();

        let tag_label = obj
            .get("tag")
            .and_then(|v| v.as_str())
            .filter(|t| !t.is_empty() && *t != "proxy")
            .unwrap_or("");
        let label_raw = if !root_remark.is_empty() && idx == 0 {
            root_remark.to_string()
        } else if !tag_label.is_empty() {
            tag_label.to_string()
        } else {
            format!("{} {host}:{port}", proto_lc.to_ascii_uppercase())
        };
        let name = clean_remark(&label_raw, &format!("{} {host}:{port}", proto_lc.to_ascii_uppercase()));
        let norm_proto = if proto_lc == "hysteria" {
            "hysteria2".to_string()
        } else {
            proto_lc
        };
        let ob_str = outbound_val.to_string();
        let id = short_id_hash(&format!("xjson:{ob_str}"));
        let wl = is_whitelist_sni(&sni) || is_whitelist_remark(&name);
        let region_hint = detect_region_hint(&name, &host, source_region_hint);

        out.push(VpnCandidate {
            id: id.clone(),
            raw_uri: format!("xray-json://{host}:{port}/{id}#{}", urlencoding_simple(&name)),
            name,
            protocol: norm_proto,
            transport,
            security: security.clone(),
            sni,
            host,
            port,
            region_hint,
            whitelist_friendly: wl,
            fragment_enabled: has_frag,
            via_warp: false,
            priority_score: if security == "reality" { 165 } else { 135 },
            outbound_json: outbound_val,
            source_tier,
        });
    }
    out
}

fn urlencoding_simple(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn extract_host_port_from_xray_settings(settings: Option<&Value>) -> Option<(String, u16)> {
    let st = settings?.as_object()?;
    if let (Some(a), Some(p)) = (
        st.get("address").and_then(|v| v.as_str()),
        st.get("port").and_then(|v| v.as_u64()),
    ) {
        return Some((a.trim().to_string(), u16::try_from(p).ok()?));
    }
    if let Some(vn) = st
        .get("vnext")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .and_then(|v| v.as_object())
    {
        let a = vn.get("address")?.as_str()?.trim().to_string();
        let p = u16::try_from(vn.get("port")?.as_u64()?).ok()?;
        return Some((a, p));
    }
    if let Some(sv) = st
        .get("servers")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .and_then(|v| v.as_object())
    {
        let a = sv.get("address")?.as_str()?.trim().to_string();
        let p = u16::try_from(sv.get("port")?.as_u64()?).ok()?;
        return Some((a, p));
    }
    if let Some(ep) = st
        .get("peers")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .and_then(|v| v.get("endpoint"))
        .and_then(|v| v.as_str())
    {
        let (h, ps) = ep.rsplit_once(':')?;
        return Some((
            h.trim_matches(|c| c == '[' || c == ']').to_string(),
            ps.parse().ok()?,
        ));
    }
    None
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
        } else if let Some(peer0) = settings
            .get_mut("peers")
            .and_then(|v| v.as_array_mut())
            .and_then(|a| a.first_mut())
            .and_then(|v| v.as_object_mut())
        {
            let ep = if ip.is_ipv6() {
                format!("[{ip_str}]:{}", cand.port)
            } else {
                format!("{ip_str}:{}", cand.port)
            };
            peer0.insert("endpoint".into(), json!(ep));
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

    // Support both standard `"none"` and Xray 2025/2026 post-quantum `"mlkem768x25519plus.*"` VLESS encryption!
    let encryption = match q.get("encryption").map(|s| s.trim()) {
        None | Some("") => "none".to_string(),
        Some(e) if e.eq_ignore_ascii_case("none") => "none".to_string(),
        Some(e)
            if e.starts_with("mlkem768x25519plus.")
                && e.len() <= 512
                && !e.chars().any(|c| c.is_whitespace() || c.is_control()) =>
        {
            e.to_string()
        }
        _ => return None,
    };
    let is_pq_enc = encryption != "none";

    let (stream_settings, transport, security, sni, mut score) =
        build_common_stream_settings_ex(&q, &host, "none", fragment_tls, is_pq_enc)?;

    let flow_raw = q.get("flow").map(|s| s.trim()).unwrap_or("");
    let flow = match flow_raw {
        "" => "",
        "xtls-rprx-vision" if matches!(transport.as_str(), "tcp" | "xhttp") => {
            score += 25;
            "xtls-rprx-vision"
        }
        "xtls-rprx-vision-udp443" if matches!(transport.as_str(), "tcp" | "xhttp") => {
            score += 25;
            "xtls-rprx-vision-udp443"
        }
        _ if flow_raw.is_empty() => "",
        _ => return None,
    };

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
    user.insert("encryption".into(), json!(encryption));
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
        .filter(|s| matches!(s.as_str(), "auto" | "aes-128-gcm" | "chacha20-poly1305"))
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
    let hy2_pin = parse_pinned_cert_sha256(&q);
    if is_truthy_insecure(&q) && hy2_pin.is_none() {
        return None;
    }

    let sni = q
        .get("sni")
        .filter(|s| !s.is_empty())
        .cloned()
        .unwrap_or_else(|| host.clone());
    if sni.parse::<std::net::IpAddr>().is_ok() && hy2_pin.is_none() {
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
    let mut hy2_tls = Map::new();
    if sni.parse::<std::net::IpAddr>().is_err() {
        hy2_tls.insert("serverName".into(), json!(sni));
    }
    hy2_tls.insert("alpn".into(), json!(["h3"]));
    if let Some(pin) = hy2_pin {
        hy2_tls.insert("pinnedPeerCertSha256".into(), json!(pin));
    }
    stream.insert("tlsSettings".into(), Value::Object(hy2_tls));
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
        priority_score: if is_ss2022 { 56 } else { 32 },
        outbound_json: outbound,
        source_tier,
    })
}

/// Parse `wireguard://PRIVATE_KEY@HOST:PORT?publickey=PUB&address=10.x.y.z/32&presharedkey=...&mtu=1280#Name`
/// (and `wg://...`) into a native `xray-rust` `wireguard` outbound with automatic anti-DPI UDP noise!
fn parse_wireguard(uri: &str, source_region_hint: &str, source_tier: u8) -> Option<VpnCandidate> {
    let norm = if let Some(rest) = uri.strip_prefix("wg://") {
        format!("wireguard://{rest}")
    } else {
        uri.to_string()
    };
    let u = Url::parse(&norm).ok()?;
    let priv_raw = percent_decode_str(u.username()).decode_utf8().ok()?.trim().to_string();
    let priv_bytes = decode_b64_flexible(&priv_raw)?;
    if priv_bytes.len() != 32 {
        return None;
    }
    let secret_key = base64::engine::general_purpose::STANDARD.encode(&priv_bytes);

    let host = u.host_str()?.trim_matches(|c| c == '[' || c == ']').to_string();
    let port = u.port().unwrap_or(51820);
    if !is_valid_public_host(&host, port) {
        return None;
    }

    let q = parse_query_map(&u);
    // Reject non-zero `reserved` bytes (unsupported by xray-rust v0.10.0)
    if let Some(res) = q.get("reserved").filter(|s| !s.is_empty()) {
        let nums: Vec<u8> = res
            .trim_matches(|c| c == '[' || c == ']')
            .split(',')
            .filter_map(|p| p.trim().parse::<u8>().ok())
            .collect();
        if !nums.is_empty() && nums.iter().any(|&b| b != 0) {
            return None;
        }
    }
    let pub_raw = q
        .get("publickey")
        .or_else(|| q.get("pbk"))
        .or_else(|| q.get("peer_public_key"))?;
    let pub_bytes = decode_b64_flexible(pub_raw)?;
    if pub_bytes.len() != 32 {
        return None;
    }
    let peer_pub = base64::engine::general_purpose::STANDARD.encode(&pub_bytes);

    let mut addrs: Vec<String> = Vec::new();
    if let Some(addr_raw) = q.get("address").or_else(|| q.get("ip")) {
        for part in addr_raw.split(',') {
            let t = part.trim();
            if t.is_empty() {
                continue;
            }
            let (ip_part, prefix_opt) = match t.split_once('/') {
                Some((a, p)) => (a.trim(), Some(p.trim())),
                None => (t, None),
            };
            if let Ok(ip) = ip_part.parse::<std::net::IpAddr>() {
                let def_p = if ip.is_ipv4() { 32u8 } else { 128u8 };
                let pfx = prefix_opt
                    .and_then(|p| p.parse::<u8>().ok())
                    .filter(|&p| p <= def_p)
                    .unwrap_or(def_p);
                addrs.push(format!("{ip}/{pfx}"));
            }
        }
    }
    if addrs.is_empty() {
        addrs.push("10.66.66.2/32".into());
    }

    let mtu: u16 = q
        .get("mtu")
        .and_then(|s| s.parse::<u16>().ok())
        .filter(|&m| (1200..=1420).contains(&m))
        .unwrap_or(1280);

    let endpoint = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };

    let mut peer = Map::new();
    peer.insert("publicKey".into(), json!(peer_pub));
    peer.insert("allowedIPs".into(), json!(["0.0.0.0/0", "::/0"]));
    peer.insert("endpoint".into(), json!(endpoint));
    peer.insert("keepAlive".into(), json!(25));
    if let Some(psk_raw) = q.get("presharedkey").or_else(|| q.get("psk")).filter(|s| !s.is_empty()) {
        if let Some(psk_b) = decode_b64_flexible(psk_raw) {
            if psk_b.len() == 32 {
                peer.insert(
                    "preSharedKey".into(),
                    json!(base64::engine::general_purpose::STANDARD.encode(&psk_b)),
                );
            }
        }
    }

    let outbound = json!({
        "tag": "proxy",
        "protocol": "wireguard",
        "settings": {
            "secretKey": secret_key,
            "address": addrs,
            "mtu": mtu,
            "peers": [Value::Object(peer)]
        },
        "streamSettings": {
            "finalmask": {
                "udp": [{
                    "type": "noise",
                    "settings": {
                        "noise": [
                            { "rand": "18-44", "delay": "2-5" },
                            { "rand": "28-68", "delay": "2-5" }
                        ]
                    }
                }]
            }
        }
    });

    let remark = clean_remark(u.fragment().unwrap_or(""), &format!("WireGuard {host}:{port}"));
    let region_hint = detect_region_hint(&remark, &host, source_region_hint);
    let id = short_id_hash(&format!("wg:{host}:{port}:{peer_pub}"));

    Some(VpnCandidate {
        id,
        raw_uri: uri.to_string(),
        name: remark,
        protocol: "wireguard".into(),
        transport: "wg".into(),
        security: "wg".into(),
        sni: String::new(),
        host,
        port,
        region_hint,
        whitelist_friendly: false,
        fragment_enabled: false,
        via_warp: false,
        priority_score: 78,
        outbound_json: outbound,
        source_tier,
    })
}

/// Parse `socks5://[user:pass@]host:port#Name` (including v2rayNG Base64 userinfo) into a native
/// `xray-rust` `socks` outbound (also chainable through 2-hop Cloudflare MASQUE!).
fn parse_socks5(uri: &str, source_region_hint: &str, source_tier: u8) -> Option<VpnCandidate> {
    let u = Url::parse(uri).ok()?;
    let host = u.host_str()?.trim_matches(|c| c == '[' || c == ']').to_string();
    let port = u.port()?;
    if !is_valid_public_host(&host, port) {
        return None;
    }

    let mut user = String::new();
    let mut pass = String::new();
    if !u.username().is_empty() {
        if let Some(pw) = u.password() {
            user = percent_decode_str(u.username()).decode_utf8().ok()?.to_string();
            pass = percent_decode_str(pw).decode_utf8().ok()?.to_string();
        } else if let Some(dec) = decode_b64_flexible(u.username()) {
            if let Ok(s) = String::from_utf8(dec) {
                if let Some((usr, pwd)) = s.split_once(':') {
                    user = usr.to_string();
                    pass = pwd.to_string();
                }
            }
        }
    }
    if user.len() > 255 || pass.len() > 255 || (user.is_empty() != pass.is_empty()) {
        return None;
    }

    let mut settings = Map::new();
    settings.insert("address".into(), json!(host));
    settings.insert("port".into(), json!(port));
    if !user.is_empty() && !pass.is_empty() {
        settings.insert("user".into(), json!(user));
        settings.insert("pass".into(), json!(pass));
    }

    let q = parse_query_map(&u);
    let wants_tls = q
        .get("security")
        .map(|s| s.eq_ignore_ascii_case("tls"))
        .unwrap_or(false);

    let (outbound, sec) = if wants_tls {
        let sni = q
            .get("sni")
            .filter(|s| !s.is_empty())
            .cloned()
            .unwrap_or_else(|| host.clone());
        if sni.parse::<std::net::IpAddr>().is_ok() {
            return None;
        }
        (
            json!({
                "tag": "proxy",
                "protocol": "socks",
                "settings": Value::Object(settings),
                "streamSettings": {
                    "network": "tcp",
                    "security": "tls",
                    "tlsSettings": {
                        "serverName": sni,
                        "fingerprint": "chrome"
                    }
                }
            }),
            "tls".to_string(),
        )
    } else {
        (
            json!({
                "tag": "proxy",
                "protocol": "socks",
                "settings": Value::Object(settings),
                "streamSettings": { "network": "tcp" }
            }),
            "none".to_string(),
        )
    };

    let remark = clean_remark(u.fragment().unwrap_or(""), &format!("SOCKS5 {host}:{port}"));
    let region_hint = detect_region_hint(&remark, &host, source_region_hint);
    let id = short_id_hash(&format!("socks5:{host}:{port}:{user}"));

    Some(VpnCandidate {
        id,
        raw_uri: uri.to_string(),
        name: remark,
        protocol: "socks".into(),
        transport: "tcp".into(),
        security: sec,
        sni: String::new(),
        host,
        port,
        region_hint,
        whitelist_friendly: false,
        fragment_enabled: false,
        via_warp: false,
        priority_score: if !user.is_empty() { 42 } else { 24 },
        outbound_json: outbound,
        source_tier,
    })
}

/// Parse explicit HTTPS CONNECT proxy `https://user:pass@host:port#Name` into a native `xray-rust`
/// `http`+TLS outbound (with Chrome uTLS + optional TLS ClientHello fragmentation).
fn parse_https_proxy(
    uri: &str,
    source_region_hint: &str,
    source_tier: u8,
    fragment_tls: bool,
) -> Option<VpnCandidate> {
    let u = Url::parse(uri).ok()?;
    if u.path() != "/" && !u.path().is_empty() {
        return None; // Subscription URL, not a proxy endpoint
    }
    let user = percent_decode_str(u.username()).decode_utf8().ok()?.to_string();
    let pass = percent_decode_str(u.password()?).decode_utf8().ok()?.to_string();
    if user.is_empty() || pass.is_empty() || user.contains(':') {
        return None;
    }
    let host = u.host_str()?.trim_matches(|c| c == '[' || c == ']').to_string();
    let port = u.port().unwrap_or(443);
    if !is_valid_public_host(&host, port) {
        return None;
    }
    let q = parse_query_map(&u);
    let sni = q
        .get("sni")
        .filter(|s| !s.is_empty())
        .cloned()
        .unwrap_or_else(|| host.clone());
    if sni.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }

    let mut stream = Map::new();
    stream.insert("network".into(), json!("tcp"));
    stream.insert("security".into(), json!("tls"));
    stream.insert(
        "tlsSettings".into(),
        json!({
            "serverName": sni,
            "fingerprint": "chrome",
            "alpn": ["h2", "http/1.1"]
        }),
    );
    if fragment_tls {
        stream.insert("finalmask".into(), tcp_fragment_mask());
    }

    let outbound = json!({
        "tag": "proxy",
        "protocol": "http",
        "settings": {
            "address": host,
            "port": port,
            "user": user,
            "pass": pass
        },
        "streamSettings": Value::Object(stream)
    });

    let remark = clean_remark(u.fragment().unwrap_or(""), &format!("HTTPS {host}:{port}"));
    let region_hint = detect_region_hint(&remark, &host, source_region_hint);
    let id = short_id_hash(&format!("https-proxy:{host}:{port}:{user}:{sni}"));

    Some(VpnCandidate {
        id,
        raw_uri: uri.to_string(),
        name: remark,
        protocol: "http".into(),
        transport: "https".into(),
        security: "tls".into(),
        sni: sni.clone(),
        host,
        port,
        region_hint,
        whitelist_friendly: is_whitelist_sni(&sni),
        fragment_enabled: fragment_tls,
        via_warp: false,
        priority_score: 68,
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
        match target_region {
            "US" if ep.region != "US" => continue,
            "DE" | "NL" | "EU" if !matches!(ep.region.as_str(), "DE" | "NL") => continue,
            "SG" | "JP" if ep.region != "SG" => continue,
            _ => {}
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

        let flag_name = match ep.region.as_str() {
            "US" => format!("Opera Relay US #{}", idx + 1),
            "SG" => format!("Opera Relay Asia #{}", idx + 1),
            _ => format!("Opera Relay EU #{}", idx + 1),
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
            priority_score: 98,
            outbound_json: outbound,
            source_tier: 2,
        });
    }
    out
}

/// Convert free official Opera SurfEasy relays (`AM` = USA, `EU` = Europe/NL, `AS` = Asia/SG) into
/// **2-hop `MASQUE-Chain` candidates** dialed through Cloudflare WARP MASQUE (`dialerProxy: "warp_bridge"`).
pub fn opera_endpoints_to_warp_chain_candidates(
    endpoints: &[OperaEndpoint],
    target_region: &str,
) -> Vec<VpnCandidate> {
    let mut sorted: Vec<&OperaEndpoint> = endpoints.iter().collect();
    sorted.sort_by_key(|ep| match target_region {
        "US" | "CA" => if ep.region == "US" { 0u8 } else { 1u8 },
        "SG" | "JP" => if ep.region == "SG" { 0u8 } else { 1u8 },
        "NL" | "DE" | "EU" | "FI" | "GB" | "FR" | "SE" | "PL" | "CH" => {
            if matches!(ep.region.as_str(), "NL" | "DE") { 0u8 } else { 1u8 }
        }
        _ => match ep.region.as_str() {
            "NL" | "DE" => 0u8,
            "US" => 1u8,
            _ => 2u8,
        },
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

        let flag_name = match ep.region.as_str() {
            "US" => format!("Opera USA + MASQUE #{}", idx + 1),
            "SG" => format!("Opera Asia + MASQUE #{}", idx + 1),
            _ => format!("Opera EU + MASQUE #{}", idx + 1),
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
            // Never mark MASQUE-chained nodes whitelist_friendly (`consumer-masque.cloudflareclient.com`
            // is not a Russian mobile carrier whitelist SNI).
            whitelist_friendly: false,
            fragment_enabled: false,
            via_warp: true,
            priority_score: 112,
            outbound_json: outbound,
            source_tier: 2,
        });
    }
    out
}

/// Convert any chain-compatible foreign exit candidate (`trojan`+TLS, `vless`+TLS,
/// `shadowsocks` AEAD/SS2022, `vmess`+TLS, `socks5`, `http`+TLS) into a **2-hop `MASQUE-Chain`**
/// dialed through Cloudflare WARP MASQUE (`dialerProxy: "warp_bridge"`).
pub fn candidate_to_warp_chain(cand: &VpnCandidate) -> Option<VpnCandidate> {
    if cand.via_warp {
        return None;
    }
    let compatible = match (cand.protocol.as_str(), cand.security.as_str()) {
        ("trojan", "tls") => true,
        ("vless", "tls") => true,
        ("vmess", "tls" | "none") => true,
        ("shadowsocks", "ss2022" | "aead" | "none") => true,
        ("socks", "tls" | "none") => true,
        ("http", "tls") => true,
        _ => false,
    };
    if !compatible {
        return None;
    }
    if !matches!(
        cand.transport.as_str(),
        "tcp" | "ws" | "httpupgrade" | "grpc" | "https"
    ) {
        return None;
    }

    // Skip Cloudflare-fronted Worker domains (Cloudflare blocks WARP -> CF Worker hairpins)
    let h_low = cand.host.to_ascii_lowercase();
    let s_low = cand.sni.to_ascii_lowercase();
    if h_low.contains("workers.dev")
        || h_low.contains("pages.dev")
        || h_low.contains(".cf.")
        || s_low.contains("workers.dev")
        || s_low.contains("pages.dev")
    {
        return None;
    }

    let mut ob = cand.outbound_json.clone();
    let obj = ob.as_object_mut()?;

    let ss_val = obj
        .entry("streamSettings")
        .or_insert_with(|| json!({ "network": "tcp" }));
    let ss = ss_val.as_object_mut()?;
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
    chained.whitelist_friendly = false;
    chained.priority_score = cand.priority_score + 48;
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

    let hop_pass = {
        let mut b = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut b);
        hex::encode(b)
    };
    let hop_inbound = json!({
        "tag": "warp_hop_in",
        "listen": "127.0.0.1",
        "port": hop_port,
        "protocol": "socks",
        "settings": {
            "auth": "password",
            "accounts": [{ "user": "whop", "pass": hop_pass }],
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
                },
                "xmux": {
                    "hKeepAlivePeriod": 25
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
            "port": hop_port,
            "user": "whop",
            "pass": hop_pass
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
            .take(4)
            .enumerate()
        {
            // 1) MASQUE over HTTP/3 (QUIC :443 / :8443 / :500)
            let h3_outbound = json!({
                "tag": "proxy",
                "protocol": "masque",
                "settings": {
                    "address": ip,
                    "port": port,
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
            out.push(VpnCandidate {
                id: short_id_hash(&format!("warp-masque-h3:{ip}:{port}")),
                raw_uri: format!("warp+masque://{ip}:{port}?alpn=h3"),
                name: format!("Cloudflare MASQUE H3 :{port} #{}", idx + 1),
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
                priority_score: 108,
                outbound_json: h3_outbound,
                source_tier: 3,
            });

            // 2) MASQUE over HTTP/3 + UDP Anti-DPI Noise (defeats QUIC Initial signature rules!)
            if idx == 0 {
                let h3_noise_outbound = json!({
                    "tag": "proxy",
                    "protocol": "masque",
                    "settings": {
                        "address": ip,
                        "port": port,
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
                        },
                        "finalmask": {
                            "udp": [{
                                "type": "noise",
                                "settings": {
                                    "noise": [
                                        { "rand": "16-40", "delay": "1-4" },
                                        { "rand": "24-56", "delay": "2-5" }
                                    ]
                                }
                            }]
                        }
                    }
                });
                out.push(VpnCandidate {
                    id: short_id_hash(&format!("warp-masque-h3-noise:{ip}:{port}")),
                    raw_uri: format!("warp+masque://{ip}:{port}?alpn=h3&mask=noise"),
                    name: format!("Cloudflare MASQUE H3 + Noise :{port}"),
                    protocol: "warp-masque".into(),
                    transport: "masque-h3-noise".into(),
                    security: "tls".into(),
                    sni: "consumer-masque.cloudflareclient.com".into(),
                    host: ip.clone(),
                    port,
                    region_hint: "DE".into(),
                    whitelist_friendly: false,
                    fragment_enabled: false,
                    via_warp: false,
                    priority_score: 107,
                    outbound_json: h3_noise_outbound,
                    source_tier: 3,
                });
            }

            // 3) MASQUE over HTTP/2 (TCP + TLS ClientHello fragmentation — works even when UDP blocked!)
            if port == 443 || port == 8443 {
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
                        "remoteDNS": ["1.1.1.1", "8.8.8.8"]
                    },
                    "streamSettings": Value::Object(h2_stream)
                });
                out.push(VpnCandidate {
                    id: short_id_hash(&format!("warp-masque-h2:{ip}:{port}")),
                    raw_uri: format!("warp+masque://{ip}:{port}?alpn=h2"),
                    name: format!("Cloudflare MASQUE H2 :{port} #{}", idx + 1),
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
                    priority_score: 109,
                    outbound_json: h2_outbound,
                    source_tier: 3,
                });
            }
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
            ("socks", _) => "SOCKS5 + MASQUE".into(),
            ("http", _) => "HTTPS + MASQUE".into(),
            _ => format!("{} + MASQUE", c.protocol.to_ascii_uppercase()),
        };
    }
    match (c.protocol.as_str(), c.transport.as_str(), c.security.as_str()) {
        ("vless", "xhttp", "reality") => "VLESS XHTTP Reality".into(),
        ("vless", "xhttp", _) => "VLESS XHTTP TLS".into(),
        ("vless", "grpc", "reality") => "VLESS gRPC Reality".into(),
        ("vless", "httpupgrade", "reality") => "VLESS HTTPUp Reality".into(),
        ("vless", _, "reality") => "VLESS Reality".into(),
        ("vless", "httpupgrade", _) => "VLESS HTTPUpgrade TLS".into(),
        ("vless", "ws", _) => "VLESS WS TLS".into(),
        ("vless", "grpc", _) => "VLESS gRPC TLS".into(),
        ("vless", _, _) => "VLESS TLS".into(),
        ("vmess", "xhttp", _) => "VMess XHTTP TLS".into(),
        ("vmess", "httpupgrade", _) => "VMess HTTPUpgrade TLS".into(),
        ("vmess", "ws", _) => "VMess WS TLS".into(),
        ("vmess", "grpc", _) => "VMess gRPC TLS".into(),
        ("vmess", _, _) => "VMess AEAD TLS".into(),
        ("hysteria2", _, _) => "Hysteria 2 (QUIC)".into(),
        ("trojan", "xhttp", _) => "Trojan XHTTP TLS".into(),
        ("trojan", "httpupgrade", _) => "Trojan HTTPUpgrade TLS".into(),
        ("trojan", "ws", _) => "Trojan WS TLS".into(),
        ("trojan", "grpc", _) => "Trojan gRPC TLS".into(),
        ("trojan", _, "reality") => "Trojan Reality".into(),
        ("trojan", _, _) => "Trojan TLS".into(),
        ("shadowsocks", _, "ss2022") => "Shadowsocks 2022".into(),
        ("shadowsocks", _, _) => "Shadowsocks AEAD".into(),
        ("wireguard", _, _) => "WireGuard + Noise".into(),
        ("socks", _, "tls") => "SOCKS5 TLS".into(),
        ("socks", _, _) => "SOCKS5 Proxy".into(),
        ("http", _, _) => "HTTPS CONNECT TLS".into(),
        ("opera", _, _) => "Opera HTTPS TLS".into(),
        ("warp-masque", "masque-h3-noise", _) => "WARP MASQUE H3 + Noise".into(),
        ("warp-masque", "masque-h3", _) => "WARP MASQUE H3".into(),
        ("warp-masque", "masque-h2", _) => "WARP MASQUE H2".into(),
        ("warp-wg", _, _) => "WARP AWG Noise".into(),
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
    if n.via_warp || matches!(n.protocol.as_str(), "opera" | "http" | "socks") {
        return false;
    }
    let net = n
        .outbound_json
        .pointer("/streamSettings/network")
        .and_then(|v| v.as_str())
        .unwrap_or("tcp");
    match n.protocol.as_str() {
        "hysteria2" | "warp-masque" | "warp-wg" | "wireguard" | "trojan" | "vmess"
        | "shadowsocks" => true,
        "vless" => net == "tcp",
        _ => false,
    }
}

/// Curated domestic Russian services for smart split-tunneling (`РФ-сайты напрямую`).
/// Never includes blanket `domain:ru` so IP-checkers (`2ip.ru`) show the real VPN exit IP
/// and RKN-blocked `.ru` media/forums open cleanly through the VPN tunnel!
pub const CURATED_RU_DIRECT_DOMAINS: &[&str] = &[
    // Госуслуги, ФНС, городские сервисы
    "domain:gosuslugi.ru",
    "domain:gu-st.ru",
    "domain:esia.gosuslugi.ru",
    "domain:nalog.ru",
    "domain:mos.ru",
    "domain:emias.info",
    "domain:spb.ru",
    // Банки РФ, СБП, Мир Pay
    "domain:sberbank.ru",
    "domain:sber.ru",
    "domain:sberdevices.ru",
    "domain:tbank.ru",
    "domain:tinkoff.ru",
    "domain:cdn-tinkoff.ru",
    "domain:alfabank.ru",
    "domain:vtb.ru",
    "domain:gazprombank.ru",
    "domain:raiffeisen.ru",
    "domain:sovcombank.ru",
    "domain:rshb.ru",
    "domain:pochtabank.ru",
    "domain:psbank.ru",
    "domain:yoomoney.ru",
    "domain:yookassa.ru",
    "domain:nspk.ru",
    "domain:mirpay.ru",
    "domain:cbr.ru",
    // Маркетплейсы, доставка, классифайды, транспорт
    "domain:ozon.ru",
    "domain:ozone.ru",
    "domain:ozonusercontent.com",
    "domain:wildberries.ru",
    "domain:wb.ru",
    "domain:wbbasket.ru",
    "domain:avito.ru",
    "domain:avito.st",
    "domain:kuper.ru",
    "domain:samokat.ru",
    "domain:cdek.ru",
    "domain:pochta.ru",
    "domain:rzd.ru",
    "domain:tutu.ru",
    "domain:aeroflot.ru",
    "domain:s7.ru",
    "domain:2gis.ru",
    "domain:2gis.com",
    "domain:hh.ru",
    // Яндекс (веб-сервисы и статика — БЕЗ `yandex.net`, чтобы Yandex DoH `dot.dns.yandex.net` НЕ утекал к провайдеру!), VK, OK, Mail.ru, Max, Rutube
    "domain:yandex.ru",
    "domain:yastatic.net",
    "domain:ya.ru",
    "domain:kinopoisk.ru",
    "domain:dzen.ru",
    "domain:vk.com",
    "domain:vk.ru",
    "domain:vkvideo.ru",
    "domain:userapi.com",
    "domain:vkuser.net",
    "domain:mycdn.me",
    "domain:ok.ru",
    "domain:okcdn.ru",
    "domain:mail.ru",
    "domain:imgsmail.ru",
    "domain:max.ru",
    "domain:oneme.ru",
    "domain:rutube.ru",
    "domain:rtbcdn.ru",
    // Операторы связи, ретейл, доставка, кинотеатры, RuStore и гос.сервисы РФ
    "domain:mts.ru",
    "domain:mtsbank.ru",
    "domain:megafon.ru",
    "domain:beeline.ru",
    "domain:t2.ru",
    "domain:tele2.ru",
    "domain:rt.ru",
    "domain:uralsib.ru",
    "domain:mkb.ru",
    "domain:tochka.com",
    "domain:domclick.ru",
    "domain:nalog.gov.ru",
    "domain:sfr.gov.ru",
    "domain:fssp.gov.ru",
    "domain:mosreg.ru",
    "domain:rustore.ru",
    "domain:vkplay.ru",
    "domain:lamoda.ru",
    "domain:dns-shop.ru",
    "domain:mvideo.ru",
    "domain:eldorado.ru",
    "domain:citilink.ru",
    "domain:lemanapro.ru",
    "domain:magnit.ru",
    "domain:5ka.ru",
    "domain:perekrestok.ru",
    "domain:vprok.ru",
    "domain:vkusvill.ru",
    "domain:dodopizza.ru",
    "domain:auto.ru",
    "domain:drom.ru",
    "domain:drive2.ru",
    "domain:cian.ru",
    "domain:pik.ru",
    "domain:gismeteo.ru",
    "domain:okko.tv",
    "domain:ivi.ru",
    "domain:wink.ru",
    "domain:premier.one",
    "domain:start.ru",
    "domain:kion.ru",
    "domain:smotrim.ru",
    "domain:rbc.ru",
    "domain:ria.ru",
    "domain:kommersant.ru",
    // Расширенный пакет банков, СБП, доставки, авиа/ЖД, аптек, сервисов и игр РФ (v1.7)
    "domain:psbank.ru",
    "domain:otpbank.ru",
    "domain:akbars.ru",
    "domain:bspb.ru",
    "domain:sinara.ru",
    "domain:rencredit.ru",
    "domain:rsb.ru",
    "domain:domrfbank.ru",
    "domain:domrf.ru",
    "domain:mtsmoney.ru",
    "domain:ozon.bank",
    "domain:wb.bank",
    "domain:moex.com",
    "domain:crpt.ru",
    "domain:chestnyznak.ru",
    "domain:goskey.ru",
    "domain:pochta.ru",
    "domain:cdek.ru",
    "domain:boxberry.ru",
    "domain:dellin.ru",
    "domain:pecom.ru",
    "domain:aeroflot.ru",
    "domain:pobeda.aero",
    "domain:s7.ru",
    "domain:utair.ru",
    "domain:tutu.ru",
    "domain:ostrovok.ru",
    "domain:sutochno.ru",
    "domain:kuper.ru",
    "domain:sbermarket.ru",
    "domain:megamarket.ru",
    "domain:samokat.ru",
    "domain:edadeal.ru",
    "domain:lenta.com",
    "domain:auchan.ru",
    "domain:metro-cc.ru",
    "domain:dixy.ru",
    "domain:kb.ru",
    "domain:krasnoeibeloe.ru",
    "domain:fix-price.com",
    "domain:vseinstrumenti.ru",
    "domain:petrovich.ru",
    "domain:sportmaster.ru",
    "domain:detmir.ru",
    "domain:goldapple.ru",
    "domain:letu.ru",
    "domain:rivegauche.ru",
    "domain:kari.com",
    "domain:vkusnoitochka.ru",
    "domain:burgerkingrus.ru",
    "domain:rostics.ru",
    "domain:apteka.ru",
    "domain:eapteka.ru",
    "domain:gorzdrav.org",
    "domain:invitro.ru",
    "domain:gemotest.ru",
    "domain:prodoctorov.ru",
    "domain:yota.ru",
    "domain:dom.ru",
    "domain:ertelecom.ru",
    "domain:ttk.ru",
    "domain:2gis.ru",
    "domain:2gis.com",
    "domain:hh.ru",
    "domain:superjob.ru",
    "domain:habr.com",
    "domain:pikabu.ru",
    "domain:dtf.ru",
    "domain:vc.ru",
    "domain:ixbt.com",
    "domain:cyber.sports.ru",
    "domain:sports.ru",
    "domain:championat.com",
    "domain:litres.ru",
    "domain:zvuk.com",
    "domain:uma.media",
    "domain:lesta.ru",
    "domain:tanki.su",
    "domain:korabli.su",
    "domain:youla.ru",
];

/// Guaranteed-via-VPN international services (AI, messengers, social, streaming, games, dev/design,
/// privacy & geo-restricted vendor portals) — routed explicitly through Dual-Channel `vpn_main`
/// BEFORE `CURATED_RU_DIRECT_DOMAINS` so 100% of restricted/geo-blocked services work seamlessly!
pub const GUARANTEED_VPN_SERVICE_DOMAINS: &[&str] = &[
    // ИИ и нейросети (ChatGPT, Sora, Claude, Gemini, Grok, Perplexity, Cursor, Copilot, Midjourney, Suno)
    "domain:openai.com",
    "domain:chatgpt.com",
    "domain:oaistatic.com",
    "domain:oaiusercontent.com",
    "domain:sora.com",
    "domain:anthropic.com",
    "domain:claude.ai",
    "domain:claudeusercontent.com",
    "domain:gemini.google.com",
    "domain:aistudio.google.com",
    "domain:notebooklm.google.com",
    "domain:generativelanguage.googleapis.com",
    "domain:labs.google",
    "domain:deepmind.google",
    "domain:x.ai",
    "domain:grok.com",
    "domain:perplexity.ai",
    "domain:midjourney.com",
    "domain:cursor.sh",
    "domain:cursor.com",
    "domain:githubcopilot.com",
    "domain:huggingface.co",
    "domain:civitai.com",
    "domain:elevenlabs.io",
    "domain:suno.com",
    "domain:suno.ai",
    "domain:udio.com",
    "domain:runwayml.com",
    "domain:poe.com",
    "domain:character.ai",
    "domain:mistral.ai",
    "domain:cohere.com",
    "domain:replicate.com",
    "domain:blackforestlabs.ai",
    // Соцсети, звонки и мессенджеры (Discord, Instagram, Threads, FB, WhatsApp, X, TikTok, Reddit, Signal)
    "domain:discord.com",
    "domain:discord.gg",
    "domain:discord.media",
    "domain:discordapp.com",
    "domain:discordapp.net",
    "domain:discordstatus.com",
    "domain:instagram.com",
    "domain:cdninstagram.com",
    "domain:threads.net",
    "domain:facebook.com",
    "domain:fbcdn.net",
    "domain:messenger.com",
    "domain:meta.com",
    "domain:meta.ai",
    "domain:whatsapp.com",
    "domain:whatsapp.net",
    "domain:x.com",
    "domain:twitter.com",
    "domain:twimg.com",
    "domain:t.co",
    "domain:tiktok.com",
    "domain:tiktokv.com",
    "domain:tiktokcdn.com",
    "domain:tiktokcdn-eu.com",
    "domain:tiktokcdn-us.com",
    "domain:byteoversea.com",
    "domain:musical.ly",
    "domain:reddit.com",
    "domain:redd.it",
    "domain:redditmedia.com",
    "domain:redditstatic.com",
    "domain:linkedin.com",
    "domain:licdn.com",
    "domain:patreon.com",
    "domain:pinterest.com",
    "domain:pinimg.com",
    "domain:signal.org",
    "domain:viber.com",
    "domain:snapchat.com",
    "domain:bsky.app",
    "domain:quora.com",
    "domain:medium.com",
    "domain:substack.com",
    "domain:guilded.gg",
    // Музыка, стриминг и кино (Spotify, Twitch, SoundCloud, Netflix, Crunchyroll, Disney+, Deezer)
    "domain:spotify.com",
    "domain:scdn.co",
    "domain:spotifycdn.com",
    "domain:twitch.tv",
    "domain:ttvnw.net",
    "domain:jtvnw.net",
    "domain:soundcloud.com",
    "domain:sndcdn.com",
    "domain:netflix.com",
    "domain:nflxvideo.net",
    "domain:nflximg.net",
    "domain:nflxso.net",
    "domain:crunchyroll.com",
    "domain:disneyplus.com",
    "domain:max.com",
    "domain:deezer.com",
    "domain:tidal.com",
    "domain:vimeo.com",
    "domain:dailymotion.com",
    // Игры и лаунчеры (Brawl Stars/Supercell, Roblox, Riot/Valorant/LoL, Steam, Epic, EA, Minecraft, PSN, GFN)
    "domain:supercell.com",
    "domain:supercellid.com",
    "domain:brawlstarsgame.com",
    "domain:clashroyale.com",
    "domain:clashofclans.com",
    "domain:roblox.com",
    "domain:rbxcdn.com",
    "domain:riotgames.com",
    "domain:leagueoflegends.com",
    "domain:playvalorant.com",
    "domain:pvp.net",
    "domain:steamcommunity.com",
    "domain:epicgames.com",
    "domain:fortnite.com",
    "domain:unrealengine.com",
    "domain:ea.com",
    "domain:battle.net",
    "domain:blizzard.com",
    "domain:minecraft.net",
    "domain:mojang.com",
    "domain:xbox.com",
    "domain:xboxlive.com",
    "domain:playstation.com",
    "domain:playstation.net",
    "domain:faceit.com",
    "domain:modrinth.com",
    "domain:curseforge.com",
    "domain:nexusmods.com",
    "domain:geforcenow.com",
    "domain:nvidia.com",
    "domain:vrchat.com",
    // Работа, дизайн, облака, разработка и медиа (Notion, Canva, Figma, Miro, Jira, JetBrains, Adobe, Intel)
    "domain:notion.so",
    "domain:notion.site",
    "domain:canva.com",
    "domain:figma.com",
    "domain:miro.com",
    "domain:trello.com",
    "domain:atlassian.com",
    "domain:atlassian.net",
    "domain:slack.com",
    "domain:zoom.us",
    "domain:airtable.com",
    "domain:linear.app",
    "domain:proton.me",
    "domain:protonmail.com",
    "domain:bitwarden.com",
    "domain:1password.com",
    "domain:github.com",
    "domain:githubusercontent.com",
    "domain:githubassets.com",
    "domain:gitlab.com",
    "domain:docker.com",
    "domain:docker.io",
    "domain:jetbrains.com",
    "domain:jetbrains.ai",
    "domain:vercel.com",
    "domain:adobe.com",
    "domain:autodesk.com",
    "domain:intel.com",
    "domain:amd.com",
    "domain:dell.com",
    "domain:speedtest.net",
    "domain:ooklaserver.net",
    "domain:fast.com",
    "domain:archive.org",
    "domain:bbc.com",
    "domain:dw.com",
    "domain:euronews.com",
    "domain:meduza.io",
    "domain:rutracker.org",
    "domain:nnmclub.to",
    "domain:flibusta.is",
    "domain:lostfilm.tv",
];

/// Build production Android `xray-rust` TUN configuration (v1.4 Browser-First Architecture):
/// 1) Zero-latency in-core `FakeIP` (`198.19.0.0/16`, TTL 60s) on `198.18.0.1:53` — answers Android
///    system & browser DNS `A` in 0.05 ms and `AAAA`/`HTTPS`/`SVCB` with instant empty `NOERROR`,
///    forwarding exact domain names to VLESS/Hysteria2/Trojan/VMess/SS/Opera/MASQUE (zero DNS leaks!).
/// 2) Split direct `tcp+local://77.88.8.8` DNS for curated Russian banks/Gosuslugi/marketplaces +
///    in-tunnel HTTP/2 DoH (`1.1.1.1`/`8.8.8.8`/`9.9.9.9` or domain DoH for Opera) for WireGuard/Freedom.
/// 3) `tun-in` TLS/HTTP/QUIC sniffing (zero overhead on mapped FakeIPs; recovers SNI/Host on stale
///    cached `198.19.x.y` sockets across reconnects).
/// 4) Instant rejection of Android Private DNS probe (`198.18.0.1:853`), IPv6 (`::/0`), and browser
///    HTTP/3 QUIC (`udp:443,853`) so Chrome/Yandex/Brave/Firefox/Opera negotiate multiplexed TLS 1.3
///    HTTP/2 over TCP in <1 ms on 100% of sites (Google, YouTube, ChatGPT, Instagram, Discord, 2ip.ru).
/// 5) Consistent same-region hot-standby pool (`vpn_0` + up to 2 compatible backups, 20s observatory),
///    always ranking full-stack TCP/QUIC tunnels above HTTP-only Opera proxies unless explicitly pinned.
/// Browser DoH / DoT encrypted DNS resolvers — ALWAYS routed cleanly through the VPN tunnel
/// BEFORE `CURATED_RU_DIRECT_DOMAINS` so Chrome, Yandex Browser (`common.dot.dns.yandex.net`),
/// Brave, Firefox, Opera, Edge, and AdGuard Private DNS NEVER leak to ISP DPI or receive
/// RKN-poisoned/sinkhole IPs, and NEVER hit `DNS_PROBE_FINISHED_BAD_SECURE_CONFIG`!
pub const BROWSER_DOH_DOT_DOMAINS: &[&str] = &[
    "domain:dns.yandex.ru",
    "domain:dns.yandex.net",
    "domain:dot.dns.yandex.net",
    "domain:dns.google",
    "domain:dns.google.com",
    "domain:cloudflare-dns.com",
    "domain:one.one.one.one",
    "domain:dns.quad9.net",
    "domain:dns.adguard-dns.com",
    "domain:dns.adguard.com",
    "domain:adguard-dns.io",
    "domain:nextdns.io",
    "domain:dns.nextdns.io",
    "domain:dns.comss.one",
    "domain:xbox-dns.ru",
    "domain:dns.malw.link",
    "domain:doh.opendns.com",
    "domain:doh.cleanbrowsing.org",
    "domain:dns.mullvad.net",
    "domain:freedns.controld.com",
    "domain:controld.com",
    "domain:dns.sb",
    "domain:doh.sb",
    "domain:mozilla.cloudflare-dns.com",
    "domain:security.cloudflare-dns.com",
    "domain:family.adguard-dns.com",
    "domain:unfiltered.adguard-dns.com",
    "domain:dns.alidns.com",
];

pub const BROWSER_DOH_DOT_IPS: &[&str] = &[
    "1.1.1.1",
    "1.0.0.1",
    "8.8.8.8",
    "8.8.4.4",
    "9.9.9.9",
    "9.9.9.11",
    "149.112.112.112",
    "149.112.112.11",
    "94.140.14.14",
    "94.140.15.15",
    "94.140.14.140",
    "94.140.14.141",
    "208.67.222.222",
    "208.67.220.220",
    "76.76.2.0",
    "76.76.10.0",
    "185.228.168.9",
    "185.222.222.222",
    "77.88.8.8",
    "77.88.8.1",
    "77.88.8.2",
    "77.88.8.3",
    "77.88.8.7",
    "77.88.8.88",
];

/// YouTube video, API & thumbnail domains split-routed to a verified 0%-monetized YouTube server
/// (`yt_noad`: `AL`, `MD`, or EU VPS with `GL=RU`) when «YouTube без рекламы» is enabled!
pub const YOUTUBE_SPLIT_DOMAINS: &[&str] = &[
    "domain:youtube.com",
    "domain:youtu.be",
    "domain:googlevideo.com",
    "domain:youtubei.googleapis.com",
    "domain:ytimg.com",
    "domain:youtube-nocookie.com",
    "domain:youtubekids.com",
    "domain:yt.be",
];

/// Zero-overhead surgical ad & ad-injection blocklist (YouTube ad servers + Google DoubleClick/IMA
/// + Yandex Direct/AdFox + popunder/banner networks). Explicitly NEVER blocks `googlevideo.com`,
/// `ytimg.com`, `youtubei.googleapis.com`, `ggpht.com`, `gstatic.com`, logins, CAPTCHAs, or CDNs!
pub const CURATED_AD_DOMAINS: &[&str] = &[
    // YouTube & Google ad-serving / IMA SDK / DoubleClick
    "domain:doubleclick.net",
    "domain:googlesyndication.com",
    "domain:googleadservices.com",
    "domain:adservice.google.com",
    "domain:adservice.google.ru",
    "domain:adservice.google.de",
    "domain:2mdn.net",
    "domain:ads.youtube.com",
    "domain:imasdk.googleapis.com",
    "domain:admob.com",
    "domain:app-measurement.com",
    // Российские рекламные сети (Яндекс.Директ, AdFox, VK/myTarget, тизеры)
    "domain:an.yandex.ru",
    "domain:yandexadexchange.net",
    "domain:adsdk.yandex.ru",
    "domain:adfox.ru",
    "domain:ad.mail.ru",
    "domain:r.mradx.net",
    "domain:target.my.com",
    "domain:adriver.ru",
    "domain:betweendigital.com",
    "domain:buzzoola.com",
    "domain:smi2.ru",
    "domain:directadvert.ru",
    "domain:marketgid.com",
    "domain:mgid.com",
    "domain:relap.io",
    "domain:adhigh.net",
    "domain:hybrid.ai",
    "domain:otm-r.com",
    // Глобальные баннерные и popunder-сети (экономия трафика, ОЗУ и батареи в браузере)
    "domain:criteo.com",
    "domain:criteo.net",
    "domain:taboola.com",
    "domain:outbrain.com",
    "domain:adnxs.com",
    "domain:rubiconproject.com",
    "domain:pubmatic.com",
    "domain:openx.net",
    "domain:casalemedia.com",
    "domain:adsrvr.org",
    "domain:moatads.com",
    "domain:doubleverify.com",
    "domain:unityads.unity3d.com",
    "domain:applovin.com",
    "domain:vungle.com",
    "domain:ironsrc.com",
    "domain:chartboost.com",
    "domain:inmobi.com",
    "domain:popads.net",
    "domain:popcash.net",
    "domain:propellerads.com",
    "domain:adsterra.com",
    "domain:exoclick.com",
    "domain:trafficjunky.net",
    "domain:juicyads.com",
    // Доп. фильтр навязчивой рекламы, push-спама, трекеров и веб-майнеров (v1.7, 0 МБ доп. ОЗУ)
    "domain:clickadu.com",
    "domain:hilltopads.net",
    "domain:adcash.com",
    "domain:trafficstars.com",
    "domain:richads.com",
    "domain:evadav.com",
    "domain:galaksion.com",
    "domain:bidvertiser.com",
    "domain:revcontent.com",
    "domain:teads.tv",
    "domain:smartadserver.com",
    "domain:indexexchange.com",
    "domain:sharethrough.com",
    "domain:3lift.com",
    "domain:media.net",
    "domain:amazon-adsystem.com",
    "domain:ads.tiktok.com",
    "domain:analytics.tiktok.com",
    "domain:business-api.tiktok.com",
    "domain:ads-twitter.com",
    "domain:ads.linkedin.com",
    "domain:scorecardresearch.com",
    "domain:quantserve.com",
    "domain:hotjar.com",
    "domain:mouseflow.com",
    "domain:luckyorange.com",
    "domain:appsflyer.com",
    "domain:adjust.com",
    "domain:appmetrica.yandex.ru",
    "domain:appmetrica.yandex.net",
    "domain:top-fwz1.mail.ru",
    "domain:coinhive.com",
    "domain:coin-hive.com",
    "domain:cryptoloot.pro",
    "domain:webminepool.com",
];

/// User-defined per-site routing rules configured in Settings («Свои правила сайтов»):
/// force specific domains through VPN, direct (bypass VPN), or block (anti-ad / parental).
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct CustomDomainRules {
    #[serde(default)]
    pub vpn: Vec<String>,
    #[serde(default)]
    pub direct: Vec<String>,
    #[serde(default)]
    pub block: Vec<String>,
}

impl CustomDomainRules {
    pub fn from_json_str(raw: &str) -> Self {
        let t = raw.trim();
        if t.is_empty() || t == "{}" {
            return Self::default();
        }
        let parsed: Self = serde_json::from_str(t).unwrap_or_default();
        Self {
            vpn: sanitize_custom_domain_list(&parsed.vpn),
            direct: sanitize_custom_domain_list(&parsed.direct),
            block: sanitize_custom_domain_list(&parsed.block),
        }
    }
}

fn sanitize_custom_domain_list(items: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for raw in items.iter().take(200) {
        let mut s = raw.trim().to_ascii_lowercase();
        let mut prefix = "domain:";
        if let Some(rest) = s.strip_prefix("https://").or_else(|| s.strip_prefix("http://")) {
            s = rest.to_string();
        }
        if let Some(rest) = s.strip_prefix("full:") {
            prefix = "full:";
            s = rest.to_string();
        } else if let Some(rest) = s.strip_prefix("domain:") {
            s = rest.to_string();
        }
        if let Some(rest) = s.strip_prefix("*.") {
            s = rest.to_string();
        }
        if let Some((host, _)) = s.split_once(['/', '?', '#', ':']) {
            s = host.to_string();
        }
        let trimmed = s.trim_matches('*').trim_matches('.');
        let s = if prefix == "full:" {
            trimmed
        } else {
            trimmed.strip_prefix("www.").unwrap_or(trimmed)
        };
        if s.len() >= 3
            && s.len() <= 128
            && s.contains('.')
            && s != "localhost"
            && !s.ends_with(".localhost")
            && !s.ends_with(".local")
            && s.parse::<std::net::IpAddr>().is_err()
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
            && !s.starts_with('-')
            && !s.ends_with('-')
            && !s.contains("..")
        {
            let rule = format!("{prefix}{s}");
            if !out.contains(&rule) {
                out.push(rule);
            }
        }
    }
    out
}

/// True if two host strings belong to the same physical host OR the same IPv4 `/24` subnet —
/// ensuring Primary (`vpn_0`) and Hot-Standby (`vpn_1`) never share a single datacenter rack or
/// TSPU `/24` block!
pub fn hosts_share_failure_domain(a: &str, b: &str) -> bool {
    if a.eq_ignore_ascii_case(b) {
        return true;
    }
    if let (Ok(ip_a), Ok(ip_b)) = (a.parse::<std::net::Ipv4Addr>(), b.parse::<std::net::Ipv4Addr>())
    {
        let oa = ip_a.octets();
        let ob = ip_b.octets();
        return oa[0] == ob[0] && oa[1] == ob[1] && oa[2] == ob[2];
    }
    false
}

/// Canonical v1.7 Hot-Standby priority comparator:
/// - **Tier 0 (HIGHEST PRIORITY):** Exact same country as the active Primary server (`primary.exit_country`)!
///   Zero country jump on failover — sessions, tokens, games, and streams stay seamless!
/// - **Tier 1 (NEXT HIGHEST PRIORITY):** Germany (`🇩🇪 DE`) and USA (`🇺🇸 US`) backbone reserves!
/// - **Tier 2:** Top low-latency foreign Tier-1 exits (`NL`, `FI`, `SE`, `GB`, `FR`, `CH`, `AT`, `CA`).
/// - **Tier 3:** Any other verified foreign exit (NEVER `"RU"`!).
/// - **Tier 4:** Local Cloudflare WARP fallback (`"CF"`).
/// Within each country tier, prioritizes: `/24` subnet independence -> recent-failure cleanliness ->
/// custom subscription tier -> transport diversity (TCP standby behind QUIC/UDP primary) ->
/// stability streak (`ok_streak`) + low RTT + high throughput!
pub fn standby_priority_key(
    n: &VerifiedVpnNode,
    primary: &VerifiedVpnNode,
    now_unix: u64,
) -> (u8, u8, u8, u8, u8, i32) {
    let p_cc = primary.exit_country.trim().to_ascii_uppercase();
    let n_cc = n.exit_country.trim().to_ascii_uppercase();
    let same_primary_country =
        p_cc.len() == 2 && !matches!(p_cc.as_str(), "RU" | "CF") && n_cc == p_cc;
    let country_tier = if same_primary_country {
        0u8 // #1 Absolute highest priority: same country as current Primary!
    } else if matches!(n_cc.as_str(), "DE" | "US") {
        1u8 // #2 Priority reserve tier: Germany (DE) & USA (US)!
    } else if matches!(
        n_cc.as_str(),
        "NL" | "FI" | "SE" | "GB" | "FR" | "CH" | "AT" | "CA"
    ) {
        2u8
    } else if n_cc == "CF" {
        4u8
    } else {
        3u8
    };

    let same_domain_penalty = if hosts_share_failure_domain(&n.host, &primary.host) {
        1u8
    } else {
        0u8
    };
    let recent_fail_penalty = if n.fail_count > 0 {
        n.fail_count.min(3) as u8
    } else if n.last_fail_unix > 0 && now_unix.saturating_sub(n.last_fail_unix) < 1200 {
        1u8
    } else {
        0u8
    };
    let custom_rank = if n.source_tier == 0 { 0u8 } else { 1u8 };

    // Anti-drop transport diversity: if Primary uses QUIC/UDP (Hysteria2/WG/MASQUE) and carrier
    // throttles UDP mid-session, prefer a TCP/Reality/XHTTP standby so failover is 100% immune!
    let primary_is_udp = matches!(primary.protocol.as_str(), "hysteria2" | "wireguard" | "masque")
        || primary.via_warp;
    let cand_is_udp =
        matches!(n.protocol.as_str(), "hysteria2" | "wireguard" | "masque") || n.via_warp;
    let transport_div = if primary_is_udp && cand_is_udp { 1u8 } else { 0u8 };

    let rtt = if n.rtt_ms == 0 { 450i32 } else { n.rtt_ms as i32 };
    let streak_bonus = (n.ok_streak.min(12) as i32) * 8;
    let speed_bonus = (n.kbps.min(3000) / 20) as i32;
    let de_tiebreak = if n_cc == "DE" { -18 } else if n_cc == "US" { -10 } else { 0 };
    let perf_score = rtt - streak_bonus - speed_bonus + de_tiebreak;

    (
        country_tier,
        same_domain_penalty,
        recent_fail_penalty,
        custom_rank,
        transport_div,
        perf_score,
    )
}

pub fn build_production_tun_config(
    nodes: &[VerifiedVpnNode],
    pinned_node_id: Option<&str>,
    bypass_ru_domains: bool,
    fragment_tls: bool,
    local_socks_port: u16,
    warp_acc: Option<&WarpAccountCache>,
) -> Result<(String, VerifiedVpnNode, usize), String> {
    build_production_tun_config_full(
        nodes,
        pinned_node_id,
        false,
        bypass_ru_domains,
        fragment_tls,
        true,
        local_socks_port,
        warp_acc,
    )
    .map(|(cfg, primary, backups, _yt_mode)| (cfg, primary, backups))
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
    build_production_tun_config_full(
        nodes,
        pinned_node_id,
        whitelist_mode,
        bypass_ru_domains,
        fragment_tls,
        true,
        local_socks_port,
        warp_acc,
    )
    .map(|(cfg, primary, backups, _yt_mode)| (cfg, primary, backups))
}

/// VeloxVPN v1.5.0 Production TUN Config Builder:
/// - Pure single-primary outbound (`vpn_0`) so browsers NEVER experience mid-page IP flapping or
///   flaky backup subresource hangs (instant watchdog failover handles dead servers cleanly).
/// - Full compatibility with ALL Android browsers (Chrome, Yandex, Opera, Brave, Firefox, Edge,
///   Samsung, Infinix XOS/Phoenix, WebView) — whether using OS DNS (`198.18.0.1` FakeIP), browser
///   Secure DNS (DoH to Google/Cloudflare/Yandex/AdGuard/Comss), or Android Private DNS (DoT).
/// - Zero-RAM **Ad-Free YouTube (`adblock = true`)**:
///   1) Automatic YouTube geo-split (`yt_noad`) through a verified 0%-monetized exit (`AL`, `MD`,
///      or fast European VPS with `GL=RU`) with `observatory` + `fallbackTag: "vpn_0"` safety net
///      -> 0% pre-roll, 0% mid-roll, 0% Shorts & 0% YouTube Music ads even when connected to US/DE!
///   2) Surgical domain blocking (`CURATED_AD_DOMAINS`) + DNS `NXDOMAIN` for DoubleClick, IMA SDK,
///      Google Ads, Yandex.Direct/AdFox & popunders with ZERO breakage on real websites or streams!
/// Strict country/mode membership check used by the Dual-Channel (`vpn_0` + `vpn_1`) engine
/// and failover watchdog:
/// - When the user selects a specific 2-letter country (e.g. `"DE"` Germany, `"US"` USA, `"NL"`,
///   `"FI"`, `"GB"`, `"FR"`, `"SE"`, `"PL"`, `"CH"`, `"TR"`, `"JP"`, `"SG"`, `"CA"`, `"AL"`, `"MD"`),
///   BOTH primary (`vpn_0`), hot-standby (`vpn_1`), and all failovers stay **100% strictly** in that country!
/// - When `"AUTO"` is selected, picks #1 best overall as primary + #2 best distinct-host across all
///   healthy countries as instant 0-ms hot-standby!
pub fn node_matches_strict_region(n: &VerifiedVpnNode, selected_region: &str, whitelist_mode: bool) -> bool {
    // NEVER match a domestic Russian (`RU`) exit — VPN replaces Russia with a foreign IP!
    if n.exit_country.eq_ignore_ascii_case("RU") {
        return false;
    }
    let reg = selected_region.trim().to_ascii_uppercase();
    if reg == "RU" {
        return false;
    }
    if whitelist_mode || reg == "WL" {
        return n.whitelist_friendly && !n.via_warp && n.exit_country != "CF";
    }
    match reg.as_str() {
        "" | "AUTO" => n.exit_country != "CF",
        "YT" => n.yt_ad_free && n.exit_country != "CF",
        "WARP" => n.via_warp || n.protocol.starts_with("warp-"),
        "EU" => matches!(
            n.exit_country.as_str(),
            "DE" | "NL" | "FI" | "GB" | "FR" | "SE" | "PL" | "CH" | "AT" | "CZ" | "IT" | "ES"
                | "PT" | "EE" | "LV" | "LT" | "DK" | "NO" | "IE" | "BE" | "LU" | "HU" | "RO"
                | "BG" | "AL" | "MD"
        ),
        code if code.len() == 2 => n.exit_country.eq_ignore_ascii_case(code),
        _ => true,
    }
}

/// Complete v1.7.0 Anti-Drop Dual-Channel TUN config build output.
#[derive(Debug, Clone)]
pub struct ProductionTunPlan {
    pub config_json: String,
    pub primary: VerifiedVpnNode,
    /// Instant 0-ms hot-standby (`vpn_1`) mounted under `vpn_main.fallbackTag` when `dual_channel` is active.
    /// Strictly prioritized: `#1 Same country as primary` -> `#2 Germany (DE) / USA (US)` -> `#3 Other foreign`.
    pub standby: Option<VerifiedVpnNode>,
    /// `"same_country"`, `"de_us"`, `"foreign"`, or `"none"`.
    pub standby_tier: String,
    /// Total verified standby candidates available in the active region scope.
    pub standby_pool_count: usize,
    pub yt_mode_desc: String,
    pub dual_channel_active: bool,
}

#[allow(clippy::too_many_arguments)]
pub fn build_production_tun_config_full(
    nodes: &[VerifiedVpnNode],
    pinned_node_id: Option<&str>,
    whitelist_mode: bool,
    bypass_ru_domains: bool,
    fragment_tls: bool,
    adblock: bool,
    local_socks_port: u16,
    warp_acc: Option<&WarpAccountCache>,
) -> Result<(String, VerifiedVpnNode, usize, String), String> {
    let plan = build_production_tun_config_v16(
        nodes,
        pinned_node_id,
        "AUTO",
        whitelist_mode,
        bypass_ru_domains,
        fragment_tls,
        adblock,
        true,
        false,
        local_socks_port,
        None,
        warp_acc,
    )?;
    Ok((
        plan.config_json,
        plan.primary,
        plan.standby_pool_count,
        plan.yt_mode_desc,
    ))
}

/// VeloxVPN v1.6.0 Production TUN Config Builder (Surpass-Happ Architecture):
/// 1) **True Dual-Channel Zero-Drop Failover (`vpn_0` + `vpn_1` via `vpn_main`)**:
///    - `selector: ["vpn_0"]`, `strategy: "random"`, `fallbackTag: "vpn_1"`:
///      100% locked single exit IP (`vpn_0`) during normal browsing (zero IP flapping!) +
///      **0.00 ms in-core switch** to pre-verified `vpn_1` the instant `vpn_0` drops — never tears down `tun0`!
///    - Strict country enforcement: choosing `"DE"` restricts `vpn_0`, `vpn_1`, and every failover
///      strictly to Germany (`DE`); choosing `"AUTO"` picks best #1 + best distinct-host #2 across regions!
/// 2) **Zero-Idle Radio-Tail Battery Design**:
///    - Observatory uses tiny zero-TLS `http://cp.cloudflare.com/generate_204` every `90s` (or `180s`
///      in screen-off idle mode) — 4x–7x fewer LTE modem wakeups with zero latency loss!
/// 3) **Per-Session RFC 1929 Authenticated Loopback SOCKS5** (`127.0.0.1:10808`):
///    - Blocks untrusted apps on the phone from piggybacking on our loopback proxy port!
/// 4) **Speed-Gated 0%-Ad YouTube Split (`yt_pool`)**:
///    - Prefers custom subscription 0%-ad nodes first; only splits onto verified high-speed (`>= 1400 kbps`,
///      `<= 950 ms`) `AL`/`MD`/`GL=RU` exits with instant `fallbackTag` so 1080p60/4K NEVER buffers!
#[allow(clippy::too_many_arguments)]
pub fn build_production_tun_config_v16(
    nodes: &[VerifiedVpnNode],
    pinned_node_id: Option<&str>,
    selected_region: &str,
    whitelist_mode: bool,
    bypass_ru_domains: bool,
    fragment_tls: bool,
    adblock: bool,
    dual_channel: bool,
    idle_power_save: bool,
    local_socks_port: u16,
    local_socks_auth: Option<(&str, &str)>,
    warp_acc: Option<&WarpAccountCache>,
) -> Result<ProductionTunPlan, String> {
    build_production_tun_config_v17(
        nodes,
        pinned_node_id,
        selected_region,
        whitelist_mode,
        bypass_ru_domains,
        fragment_tls,
        adblock,
        dual_channel,
        idle_power_save,
        local_socks_port,
        local_socks_auth,
        warp_acc,
        None,
    )
}

/// VeloxVPN v1.7.0 Anti-Drop Production TUN Config Builder:
/// 1) **Zero Russia Exits (`exit_country != "RU"`)** across Primary, Standby, Failover & YT split.
/// 2) **Smart Dual-Channel Reserve Priority**:
///    - Tier 0 (Maximum Priority): **Same country as active Primary (`vpn_0`)** on distinct `/24` host!
///    - Tier 1 (Next Highest): **Germany (`🇩🇪 DE`) & USA (`🇺🇸 US`)** backbone reserves!
///    - Tier 2: Other fast foreign exits (strict country lock preserved on explicit country selection!).
/// 3) **Anti-Drop Socket Keepalives & RFC 5482 `tcpUserTimeout`**: defeats 45s mobile carrier CGNAT
///    drops & 15-minute blackhole stalls on open sockets while sending 0 packets when idle!
/// 4) **250+ Built-in Service Rules + Custom Per-Site Rules (`VPN` / `Direct` / `Block`)**.
#[allow(clippy::too_many_arguments)]
pub fn build_production_tun_config_v17(
    nodes: &[VerifiedVpnNode],
    pinned_node_id: Option<&str>,
    selected_region: &str,
    whitelist_mode: bool,
    bypass_ru_domains: bool,
    fragment_tls: bool,
    adblock: bool,
    dual_channel: bool,
    idle_power_save: bool,
    local_socks_port: u16,
    local_socks_auth: Option<(&str, &str)>,
    warp_acc: Option<&WarpAccountCache>,
    custom_rules: Option<&CustomDomainRules>,
) -> Result<ProductionTunPlan, String> {
    let can_warp_chain = warp_acc.is_some_and(|w| w.has_masque());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let raw_reg = selected_region.trim().to_ascii_uppercase();
    let reg_up = if raw_reg == "RU" {
        "DE".to_string()
    } else {
        raw_reg
    };
    let is_strict_country = reg_up.len() == 2 && !matches!(reg_up.as_str(), "EU" | "WL" | "YT");
    let is_strict_mode = matches!(reg_up.as_str(), "WL" | "YT" | "WARP" | "EU") || whitelist_mode;

    let mut candidates: Vec<&VerifiedVpnNode> = nodes
        .iter()
        .filter(|n| {
            // NEVER select a domestic Russian (`RU`) exit server!
            if n.exit_country.eq_ignore_ascii_case("RU") {
                return false;
            }
            let is_pinned = pinned_node_id.is_some_and(|id| id == n.id);
            if n.via_warp && !can_warp_chain {
                return false;
            }
            if !is_pinned
                && n.protocol == "opera"
                && n.verified_unix > 0
                && now.saturating_sub(n.verified_unix) > 45 * 60
            {
                return false;
            }
            true
        })
        .collect();
    if candidates.is_empty() {
        return Err("Нет проверенных зарубежных узлов для запуска туннеля".into());
    }

    // Strict country enforcement: when the user selected a specific country (e.g. Germany "DE")
    // and did NOT explicitly pin a specific server row, NEVER leak to a different country!
    if pinned_node_id.is_none() && is_strict_country {
        candidates.retain(|n| node_matches_strict_region(n, &reg_up, false));
        if candidates.is_empty() {
            return Err(format!(
                "Нет проверенных рабочих серверов в стране {reg_up} — нажмите «Обновить» для поиска новых"
            ));
        }
    } else if pinned_node_id.is_none() && is_strict_mode {
        let matching_cnt = candidates
            .iter()
            .filter(|n| node_matches_strict_region(n, &reg_up, whitelist_mode))
            .count();
        if matching_cnt > 0 {
            candidates.retain(|n| node_matches_strict_region(n, &reg_up, whitelist_mode));
        } else if matches!(reg_up.as_str(), "WL" | "YT" | "EU") || whitelist_mode {
            return Err(format!(
                "Нет проверенных рабочих серверов для режима {reg_up} — нажмите «Обновить»"
            ));
        }
    }

    // Rank Primary preserving caller's custom-tier + DE/US + stability + RTT order
    candidates.sort_by_key(|n| {
        let is_pinned = pinned_node_id.is_some_and(|id| id == n.id);
        let is_http_only_proxy = if matches!(n.protocol.as_str(), "opera" | "http") {
            1u8
        } else {
            0u8
        };
        let is_local_cf = if n.source_tier >= 4 || n.exit_country == "CF" {
            1u8
        } else {
            0u8
        };
        let recent_fail = if !is_pinned
            && n.fail_count == 0
            && n.last_fail_unix > 0
            && now.saturating_sub(n.last_fail_unix) < 900
        {
            1u8
        } else {
            0u8
        };
        (
            if is_pinned { 0u8 } else { 1u8 },
            if n.device_verified { 0u8 } else { 1u8 },
            is_http_only_proxy,
            is_local_cf,
            n.fail_count,
            recent_fail,
        )
    });

    let chosen_primary = (*candidates[0]).clone();

    // Hot-Standby (`vpn_1`) pool & v1.7 Priority Hierarchy:
    // - Specific selected country (e.g. `DE`, `US`, `FI`): strictly restricted to that country!
    // - `AUTO` / `WL` / `YT` / `EU` / `WARP`: sorted by `standby_priority_key`:
    //     Tier 0 (HIGHEST): Exact same country as `chosen_primary.exit_country`!
    //     Tier 1 (NEXT):    Germany (`🇩🇪 DE`) & USA (`🇺🇸 US`) priority reserves!
    //     Tier 2+:          Other verified foreign exits (NEVER `"RU"`!)
    let mut standby_eligible: Vec<&VerifiedVpnNode> = nodes
        .iter()
        .filter(|n| {
            n.id != chosen_primary.id
                && !n.exit_country.eq_ignore_ascii_case("RU")
                && (!n.via_warp || can_warp_chain)
                && n.device_verified
                && n.fail_count < 2
                && !matches!(n.protocol.as_str(), "opera" | "http")
                && node_matches_strict_region(n, &reg_up, whitelist_mode)
        })
        .collect();
    standby_eligible.sort_by_key(|n| standby_priority_key(n, &chosen_primary, now));
    let standby_count = standby_eligible.len();

    let chosen_standby: Option<VerifiedVpnNode> = if dual_channel
        && !matches!(chosen_primary.protocol.as_str(), "opera" | "http")
    {
        standby_eligible.first().copied().cloned()
    } else {
        None
    };

    let standby_tier = match &chosen_standby {
        Some(sb)
            if !chosen_primary.exit_country.is_empty()
                && sb.exit_country.eq_ignore_ascii_case(&chosen_primary.exit_country) =>
        {
            "same_country".to_string()
        }
        Some(sb) if matches!(sb.exit_country.as_str(), "DE" | "US") => "de_us".to_string(),
        Some(_) => "foreign".to_string(),
        None => "none".to_string(),
    };

    let primary_tag = "vpn_0";
    let standby_tag = "vpn_1";
    let main_balancer_tag = "vpn_main";
    let has_dual = chosen_standby.is_some();
    let primary_is_http = matches!(chosen_primary.protocol.as_str(), "opera" | "http");
    let primary_supports_udp = node_supports_native_udp(&chosen_primary);
    let dual_supports_udp = primary_supports_udp
        && chosen_standby
            .as_ref()
            .is_some_and(node_supports_native_udp);

    // Speed-gated 0%-ad YouTube split outbound (`yt_noad`):
    // 1) Custom subscription 0%-ad nodes rank #0 (maximum bandwidth!)
    // 2) Free `yt_noad` nodes MUST have >= 1400 kbps & <= 950 ms RTT so 1080p60/4K streams never buffer!
    let yt_split_node: Option<&VerifiedVpnNode> = if !adblock || chosen_primary.yt_ad_free {
        None
    } else {
        nodes
            .iter()
            .filter(|n| {
                n.id != chosen_primary.id
                    && n.yt_ad_free
                    && n.device_verified
                    && n.fail_count == 0
                    && !matches!(n.exit_country.as_str(), "RU" | "CF")
                    && !matches!(n.protocol.as_str(), "opera" | "http")
                    && (!n.via_warp || can_warp_chain)
                    && (!whitelist_mode || (n.whitelist_friendly && !n.via_warp))
                    // Cold-TLS 38 KiB probe kbps floor: drops slow/throttled (<220 kbps or >1450 ms)
                    // community exits so 1080p60/4K YouTube never buffers, while keeping fast AL/MD/GL=RU exits!
                    && (n.source_tier == 0 || n.kbps == 0 || n.kbps >= 220)
                    && (n.rtt_ms == 0 || n.rtt_ms <= 1450)
            })
            .min_by_key(|n| {
                let tier_pri = if n.source_tier == 0 { 0u8 } else { 1u8 };
                let warp_pri = if n.via_warp { 1u8 } else { 0u8 };
                // Strong throughput bonus + low RTT so fastest 0%-Ad server ALWAYS wins!
                let speed_bonus = (n.kbps.min(8_000) / 4) as i32;
                let rtt = if n.rtt_ms == 0 { 500i32 } else { n.rtt_ms as i32 };
                (tier_pri, warp_pri, rtt - speed_bonus)
            })
    };

    let needs_warp_carrier = chosen_primary.via_warp
        || chosen_standby.as_ref().is_some_and(|n| n.via_warp)
        || yt_split_node.is_some_and(|n| n.via_warp);

    let mut inbounds = vec![json!({
        "tag": "tun-in",
        "protocol": "tun",
        "settings": {},
        "sniffing": {
            "enabled": true,
            "destOverride": ["http", "tls", "quic"]
        }
    })];
    if local_socks_port > 0 {
        let socks_settings = match local_socks_auth.filter(|(u, p)| !u.is_empty() && !p.is_empty())
        {
            Some((u, p)) => json!({
                "auth": "password",
                "accounts": [{ "user": u, "pass": p }],
                "udp": true
            }),
            None => json!({
                "auth": "noauth",
                "udp": true
            }),
        };
        // Note: NEVER enable `sniffing` on `local-socks`! Clients pass domain names via SOCKS5
        // ATYP=0x03, and xray-rust v0.10.0 `socks.rs:881` omits `outbound_stream.flush()` after
        // `write_all(&initial_payload)`, stalling buffered TLS/XHTTP/gRPC/WS handshakes!
        inbounds.push(json!({
            "tag": "local-socks",
            "listen": "127.0.0.1",
            "port": local_socks_port,
            "protocol": "socks",
            "settings": socks_settings
        }));
    }

    let prepare_outbound = |n: &VerifiedVpnNode, tag: &str| -> Value {
        let mut ob = n.outbound_json.clone();
        if let Some(obj) = ob.as_object_mut() {
            obj.insert("tag".into(), json!(tag));
            let proto = obj.get("protocol").and_then(|v| v.as_str()).unwrap_or("");
            if proto == "wireguard" {
                if let Some(st) = obj.get_mut("settings").and_then(|v| v.as_object_mut()) {
                    st.entry("mtu").or_insert_with(|| json!(1280));
                }
            }
            // Radio-tail battery optimization: 25s keepalive vs default 10s (2.5x fewer wakeups!)
            if let Some(ms) = obj
                .get_mut("streamSettings")
                .and_then(|v| v.as_object_mut())
                .and_then(|s| s.get_mut("masqueSettings"))
                .and_then(|v| v.as_object_mut())
            {
                ms.entry("xmux")
                    .or_insert_with(|| json!({ "hKeepAlivePeriod": 25 }));
            }
            if !n.via_warp {
                if let Some(ss) = obj.get_mut("streamSettings").and_then(|v| v.as_object_mut()) {
                    let net = ss
                        .get("network")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let sec = ss.get("security").and_then(|v| v.as_str()).unwrap_or("");
                    let is_h3 = ss
                        .get("tlsSettings")
                        .and_then(|v| v.get("alpn"))
                        .and_then(|v| v.as_array())
                        .is_some_and(|a| a.len() == 1 && a[0].as_str() == Some("h3"));
                    let is_tcp_carrier =
                        matches!(net.as_str(), "tcp" | "ws" | "httpupgrade" | "grpc" | "xhttp")
                            && !is_h3;
                    if is_tcp_carrier && matches!(sec, "tls" | "reality") {
                        if !fragment_tls {
                            ss.remove("finalmask");
                        } else if sec == "tls" || n.fragment_enabled {
                            ss.entry("finalmask").or_insert_with(tcp_fragment_mask);
                        }
                    }
                    // Anti-drop keepalives on active connections (0 packets when 0 sockets open!):
                    // - TCP: `tcpKeepAliveIdle=28s` beats 45s mobile carrier CGNAT drops; RFC 5482
                    //   `tcpUserTimeout=15000ms` kills blackholed sockets in 15s instead of 15 min!
                    // - WS / gRPC / XHTTP: lightweight HTTP/2 & WS PING frames keep multiplexed pipes hot!
                    let has_dialer_proxy = ss
                        .get("sockopt")
                        .and_then(|v| v.get("dialerProxy"))
                        .and_then(|v| v.as_str())
                        .is_some_and(|s| !s.is_empty());
                    if is_tcp_carrier && !has_dialer_proxy {
                        let ka_idle = if idle_power_save { 55 } else { 28 };
                        let ka_intvl = if idle_power_save { 30 } else { 15 };
                        let user_to = if idle_power_save { 18000 } else { 15000 };
                        let sock = ss
                            .entry("sockopt")
                            .or_insert_with(|| json!({}));
                        if let Some(so) = sock.as_object_mut() {
                            so.entry("tcpKeepAliveIdle").or_insert_with(|| json!(ka_idle));
                            so.entry("tcpKeepAliveInterval").or_insert_with(|| json!(ka_intvl));
                            so.entry("tcpUserTimeout").or_insert_with(|| json!(user_to));
                        }
                    }
                    if net == "ws" {
                        if let Some(ws) = ss.get_mut("wsSettings").and_then(|v| v.as_object_mut()) {
                            let hb = if idle_power_save { 45 } else { 25 };
                            ws.entry("heartbeatPeriod").or_insert_with(|| json!(hb));
                        }
                    } else if net == "grpc" {
                        if let Some(gr) = ss.get_mut("grpcSettings").and_then(|v| v.as_object_mut()) {
                            gr.entry("idle_timeout").or_insert_with(|| json!(60));
                            gr.entry("health_check_timeout").or_insert_with(|| json!(15));
                        }
                    } else if net == "xhttp" {
                        if let Some(xh) = ss.get_mut("xhttpSettings").and_then(|v| v.as_object_mut()) {
                            if let Some(xmux) = xh
                                .get_mut("extra")
                                .and_then(|v| v.as_object_mut())
                                .and_then(|e| e.get_mut("xmux"))
                                .and_then(|v| v.as_object_mut())
                            {
                                xmux.entry("hKeepAlivePeriod").or_insert_with(|| json!(25));
                            }
                        }
                    }
                }
            }
        }
        ob
    };

    let mut outbounds = vec![prepare_outbound(&chosen_primary, primary_tag)];
    let mut rules = Vec::new();
    let mut balancers = Vec::new();
    let mut obs_selectors: Vec<Value> = Vec::new();

    if let Some(ref sb) = chosen_standby {
        outbounds.push(prepare_outbound(sb, standby_tag));
        // True Dual-Channel Hot-Standby Balancer:
        // - Normal operation: `vpn_0` is `Unknown`/`Healthy` -> 100.0% traffic locked to `vpn_0` (0 IP flap!)
        // - Fault on `vpn_0`: switches in 0.00 ms to pre-verified `vpn_1` without dropping Android TUN!
        balancers.push(json!({
            "tag": main_balancer_tag,
            "selector": [primary_tag],
            "strategy": {
                "type": "random"
            },
            "fallbackTag": standby_tag
        }));
        obs_selectors.push(json!(primary_tag));
        obs_selectors.push(json!(standby_tag));
    }

    let yt_mode_desc = if !adblock {
        "off".to_string()
    } else if chosen_primary.yt_ad_free {
        let gl = if chosen_primary.yt_country.is_empty() {
            chosen_primary.exit_country.as_str()
        } else {
            chosen_primary.yt_country.as_str()
        };
        format!("primary-0ads(GL={gl})+adblock")
    } else if let Some(yt_node) = yt_split_node {
        outbounds.push(prepare_outbound(yt_node, "yt_noad"));
        balancers.push(json!({
            "tag": "yt_pool",
            "selector": ["yt_noad"],
            "strategy": {
                "type": "random"
            },
            "fallbackTag": primary_tag
        }));
        obs_selectors.push(json!("yt_noad"));
        let gl = if yt_node.yt_country.is_empty() {
            yt_node.exit_country.as_str()
        } else {
            yt_node.yt_country.as_str()
        };
        format!("split-0ads({}/GL={gl})+adblock", yt_node.exit_country)
    } else {
        "domain-adblock".to_string()
    };

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
                rules.push(hop_rule);
                balancers.push(hop_bal);
                obs_selectors.push(json!("warp_hop_"));
                mounted_warp_carrier = true;
            }
        }
    }

    // Direct outbound: prefer IPv4 dialing via the modern socket-option location
    // (legacy `settings.domainStrategy` is deprecated in xray-rust v0.10.0).
    outbounds.push(json!({
        "tag": "direct",
        "protocol": "freedom",
        "settings": {},
        "streamSettings": {
            "sockopt": {
                "domainStrategy": "UseIPv4"
            }
        }
    }));
    outbounds.push(json!({
        "tag": "block",
        "protocol": "blackhole",
        "settings": {}
    }));

    // Helper: route to `balancerTag: "vpn_main"` when Dual-Channel is active, else `outboundTag: "vpn_0"`
    let attach_main_target = |mut r: Map<String, Value>| -> Value {
        if has_dual {
            r.insert("balancerTag".into(), json!(main_balancer_tag));
        } else {
            r.insert("outboundTag".into(), json!(primary_tag));
        }
        Value::Object(r)
    };

    // Rule #1: Reject Android opportunistic Private DNS probe (`198.18.0.1:853`) -> instant FakeIP!
    rules.push(json!({
        "type": "field",
        "ip": ["198.18.0.0/24"],
        "port": "853",
        "outboundTag": "block"
    }));

    // Rule #2: Exact LAN / RFC1918 / loopback / link-local / CGNAT direct (never 198.19.0.0/16 FakeIP!)
    rules.push(json!({
        "type": "field",
        "ip": [
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "100.64.0.0/10"
        ],
        "outboundTag": "direct"
    }));

    let empty_custom = CustomDomainRules::default();
    let cr = custom_rules.unwrap_or(&empty_custom);

    // Rule #2b: User-defined custom per-site rules (highest priority over presets!)
    if !cr.block.is_empty() {
        rules.push(json!({
            "type": "field",
            "domain": cr.block,
            "outboundTag": "block"
        }));
    }
    if !cr.direct.is_empty() {
        rules.push(json!({
            "type": "field",
            "domain": cr.direct,
            "outboundTag": "direct"
        }));
    }
    if !cr.vpn.is_empty() {
        let mut r_cv = Map::new();
        r_cv.insert("type".into(), json!("field"));
        r_cv.insert("network".into(), json!("tcp"));
        r_cv.insert("domain".into(), json!(cr.vpn));
        rules.push(attach_main_target(r_cv));
    }

    // Rule #3: Surgical zero-RAM Ad, Tracker, Push-Spam & Miner Blocker
    if adblock {
        rules.push(json!({
            "type": "field",
            "domain": CURATED_AD_DOMAINS,
            "outboundTag": "block"
        }));
    }

    // Rule #4: Reject browser QUIC (`udp:443`) & DoQ (`udp:853`); keep Discord/TG/WA/games UDP open!
    let block_udp_ports = if primary_supports_udp || mounted_warp_carrier {
        "443,853"
    } else {
        "443,853,3478,5349,19302-19309"
    };
    rules.push(json!({
        "type": "field",
        "network": "udp",
        "port": block_udp_ports,
        "outboundTag": "block"
    }));

    // Rule #5: Browser DoH / DoT DNS strictly via VPN (with dual-channel failover!) before RU direct
    if primary_is_http {
        rules.push(json!({
            "type": "field",
            "inboundTag": ["tun-in", "local-socks"],
            "network": "tcp",
            "domain": BROWSER_DOH_DOT_DOMAINS,
            "outboundTag": "block"
        }));
        rules.push(json!({
            "type": "field",
            "inboundTag": ["tun-in", "local-socks"],
            "ip": BROWSER_DOH_DOT_IPS,
            "port": "53,443,853",
            "outboundTag": "block"
        }));
    } else {
        let mut r_dom = Map::new();
        r_dom.insert("type".into(), json!("field"));
        r_dom.insert("inboundTag".into(), json!(["tun-in", "local-socks"]));
        r_dom.insert("network".into(), json!("tcp"));
        r_dom.insert("domain".into(), json!(BROWSER_DOH_DOT_DOMAINS));
        rules.push(attach_main_target(r_dom));

        let mut r_ip = Map::new();
        r_ip.insert("type".into(), json!("field"));
        r_ip.insert("inboundTag".into(), json!(["tun-in", "local-socks"]));
        r_ip.insert("ip".into(), json!(BROWSER_DOH_DOT_IPS));
        r_ip.insert("port".into(), json!("53,443,853"));
        rules.push(attach_main_target(r_ip));
    }

    // Rule #6: Speed-gated 0%-Ad YouTube geo-split (`yt_pool` with instant `fallbackTag: "vpn_0"`)
    if yt_split_node.is_some() {
        rules.push(json!({
            "type": "field",
            "network": "tcp",
            "domain": YOUTUBE_SPLIT_DOMAINS,
            "balancerTag": "yt_pool"
        }));
    }

    // Rule #6b: Guaranteed-via-VPN services (135+ AI, Discord, Social, Streaming, Games, Dev/Design)
    // placed strictly BEFORE domestic RU bypass so geo-blocked services never leak directly!
    {
        let mut r_svc = Map::new();
        r_svc.insert("type".into(), json!("field"));
        r_svc.insert("network".into(), json!("tcp"));
        r_svc.insert("domain".into(), json!(GUARANTEED_VPN_SERVICE_DOMAINS));
        rules.push(attach_main_target(r_svc));
    }

    // Rule #7: Curated domestic Russian banks, SBP, Gosuslugi, delivery, marketplaces & portals direct
    if bypass_ru_domains {
        rules.push(json!({
            "type": "field",
            "domain": CURATED_RU_DIRECT_DOMAINS,
            "outboundTag": "direct"
        }));
    }

    // Rule #8: Non-443 UDP (Discord voice, TG/WA calls, games, NTP) — dual-channel protected when both support UDP!
    if dual_supports_udp {
        let mut r_udp = Map::new();
        r_udp.insert("type".into(), json!("field"));
        r_udp.insert("network".into(), json!("udp"));
        rules.push(attach_main_target(r_udp));
    } else {
        let udp_out = if primary_supports_udp {
            primary_tag
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
    }

    // Rule #9: All remaining browser & app TCP (+ in-core encrypted DoH DNS) -> Dual-Channel `vpn_main`!
    let mut r_tcp = Map::new();
    r_tcp.insert("type".into(), json!("field"));
    r_tcp.insert("network".into(), json!("tcp"));
    rules.push(attach_main_target(r_tcp));

    let mut dns_servers: Vec<Value> = Vec::with_capacity(5);
    if bypass_ru_domains || !cr.direct.is_empty() {
        let mut direct_dns_domains: Vec<String> = Vec::new();
        if bypass_ru_domains {
            direct_dns_domains.extend(CURATED_RU_DIRECT_DOMAINS.iter().map(|s| (*s).to_string()));
        }
        for d in &cr.direct {
            if !direct_dns_domains.contains(d) {
                direct_dns_domains.push(d.clone());
            }
        }
        // Exclude any domain explicitly placed in `cr.vpn` so user's Force-VPN always wins!
        if !cr.vpn.is_empty() {
            direct_dns_domains.retain(|d| !cr.vpn.contains(d));
        }
        if !direct_dns_domains.is_empty() {
            dns_servers.push(json!({
                "address": "https+local://common.dot.dns.yandex.net/dns-query",
                "domains": direct_dns_domains
            }));
            dns_servers.push(json!({
                "address": "tcp+local://77.88.8.8",
                "domains": direct_dns_domains
            }));
        }
    }
    if primary_is_http {
        dns_servers.push(json!("https://cloudflare-dns.com/dns-query"));
    } else {
        dns_servers.push(json!("https://1.1.1.1/dns-query"));
        dns_servers.push(json!("https://8.8.8.8/dns-query"));
        dns_servers.push(json!("https://9.9.9.9/dns-query"));
    }

    let mut dns_obj = Map::new();
    dns_obj.insert("queryStrategy".into(), json!("UseIPv4"));
    dns_obj.insert(
        "fakeIp".into(),
        json!({
            "enabled": true,
            "ipv4Pool": "198.19.0.0/16",
            "poolSize": 65534,
            "ttl": 45
        }),
    );
    if adblock || !cr.block.is_empty() {
        let mut hosts_map = Map::new();
        if adblock {
            for ad_dom in CURATED_AD_DOMAINS {
                hosts_map.insert((*ad_dom).to_string(), json!("#3"));
            }
        }
        for b_dom in &cr.block {
            hosts_map.insert(b_dom.clone(), json!("#3"));
        }
        dns_obj.insert("hosts".into(), Value::Object(hosts_map));
    }
    dns_obj.insert("servers".into(), Value::Array(dns_servers));

    let mut root = Map::new();
    root.insert("dns".into(), Value::Object(dns_obj));
    root.insert("inbounds".into(), Value::Array(inbounds));
    root.insert("outbounds".into(), Value::Array(outbounds));

    let mut routing = Map::new();
    routing.insert("domainStrategy".into(), json!("AsIs"));
    routing.insert("rules".into(), Value::Array(rules));
    if !balancers.is_empty() {
        routing.insert("balancers".into(), Value::Array(balancers));
    }
    if !obs_selectors.is_empty() {
        // Radio-tail-friendly interval (90s active / 180s screen-off idle -> 3.6x-7.2x fewer LTE/5G
        // modem wakeups than 25s, while staying on TCP:443 so port-80-blocking exits never false-fail!)
        let interval = if idle_power_save { "180s" } else { "90s" };
        root.insert(
            "observatory".into(),
            json!({
                "subjectSelector": obs_selectors,
                "probeURL": "https://www.gstatic.com/generate_204",
                "probeInterval": interval,
                "enableConcurrency": false
            }),
        );
    }
    root.insert("routing".into(), Value::Object(routing));

    Ok(ProductionTunPlan {
        config_json: Value::Object(root).to_string(),
        primary: chosen_primary,
        standby: chosen_standby,
        standby_tier,
        standby_pool_count: standby_count,
        yt_mode_desc,
        dual_channel_active: has_dual,
    })
}
