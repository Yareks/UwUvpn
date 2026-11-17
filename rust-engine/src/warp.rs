//! Anonymous zero-cost Cloudflare WARP provisioner (Tier-3 fallback):
//! - Registers a WireGuard (X25519) free account via official Cloudflare Consumer WARP API
//! - Registers a second separate MASQUE (ECDSA P-256) free account (HTTP/3 QUIC & HTTP/2 TCP CONNECT-IP,
//!   which looks like ordinary HTTPS/HTTP3 traffic and passes strict UDP/WireGuard DPI filters!)
//! - Uses DoH + TLS ClientHello fragmentation + fallback Cloudflare anycast IPs to bypass SNI throttling.

use crate::net_util::{http_request_once, resolve_host_resilient, HttpRequestOptions};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use p256::ecdsa::SigningKey as P256SigningKey;
use p256::pkcs8::{EncodePrivateKey, EncodePublicKey};
use rand::rngs::OsRng;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519Secret};

const CF_API_BASE: &str = "https://api.cloudflareclient.com/v0a4005";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WarpAccountCache {
    // WireGuard account
    pub wg_device_id: String,
    pub wg_token: String,
    pub wg_private_key_b64: String,
    pub wg_peer_public_key_b64: String,
    pub wg_ipv4: String,
    pub wg_ipv6: String,
    pub wg_reserved: [u8; 3],
    pub wg_endpoint_host: String,

    // MASQUE (CONNECT-IP over H3/H2) account
    pub masque_device_id: String,
    pub masque_token: String,
    pub masque_private_key_pkcs8_b64: String,
    pub masque_peer_public_key_b64: String,
    pub masque_ipv4: String,
    pub masque_ipv6: String,
    pub masque_endpoint_ip: String,

    pub created_unix: u64,
}

impl WarpAccountCache {
    pub fn has_wg(&self) -> bool {
        !self.wg_private_key_b64.is_empty()
            && !self.wg_peer_public_key_b64.is_empty()
            && !self.wg_ipv4.is_empty()
    }

    pub fn has_masque(&self) -> bool {
        !self.masque_private_key_pkcs8_b64.is_empty()
            && !self.masque_peer_public_key_b64.is_empty()
            && !self.masque_ipv4.is_empty()
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(1_763_000_000)
}

/// Format current UTC timestamp in ISO-8601 RFC3339 format accepted by Cloudflare WARP `/reg`.
fn iso8601_utc_now() -> String {
    let secs = unix_now();
    let days = (secs / 86400) as i64;
    let sod = secs % 86400;
    let hh = sod / 3600;
    let mm = (sod % 3600) / 60;
    let ss = sod % 60;
    // Howard Hinnant civil-from-days algorithm
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}.000Z")
}

fn decode_client_id_reserved(client_id_b64: &str) -> [u8; 3] {
    if let Ok(bytes) = B64.decode(client_id_b64.trim()) {
        if bytes.len() >= 3 {
            return [bytes[0], bytes[1], bytes[2]];
        }
    }
    [0, 0, 0]
}

fn cf_headers(token: Option<&str>) -> Vec<(String, String)> {
    let mut h = vec![
        ("User-Agent".to_string(), "1.1.1.1/6.81".to_string()),
        ("CF-Client-Version".to_string(), "a-6.81-2410012252.0".to_string()),
        ("Content-Type".to_string(), "application/json; charset=UTF-8".to_string()),
        ("Accept".to_string(), "application/json".to_string()),
    ];
    if let Some(t) = token {
        h.push(("Authorization".to_string(), format!("Bearer {t}")));
    }
    h
}

async fn cf_api_call(
    method: &str,
    path: &str,
    json_body: &serde_json::Value,
    token: Option<&str>,
    socks5_proxy: Option<SocketAddr>,
) -> Result<serde_json::Value, String> {
    let url = format!("{CF_API_BASE}{path}");
    let body = serde_json::to_vec(json_body).map_err(|e| e.to_string())?;

    // Candidate IPs: DoH-resolved api.cloudflareclient.com + fallback Cloudflare API IPs
    let mut candidate_ips: Vec<Option<IpAddr>> = Vec::new();
    if socks5_proxy.is_some() {
        candidate_ips.push(None);
    } else {
        if let Ok(ips) = resolve_host_resilient("api.cloudflareclient.com").await {
            for ip in ips.into_iter().filter(|i| i.is_ipv4()).take(2) {
                candidate_ips.push(Some(ip));
            }
        }
        candidate_ips.push(Some(IpAddr::V4(Ipv4Addr::new(188, 114, 97, 3))));
        candidate_ips.push(Some(IpAddr::V4(Ipv4Addr::new(162, 159, 192, 1))));
    }

    let mut last_err = String::from("cf api unreachable");
    for fixed_ip in candidate_ips {
        let opts = HttpRequestOptions {
            method: method.to_string(),
            headers: cf_headers(token),
            body: Some(body.clone()),
            timeout: Duration::from_secs(9),
            max_bytes: 128 * 1024,
            fragment_tls: true,
            socks5_proxy,
            sni_override: None,
            insecure_masked_sni: false,
            fixed_ip,
        };
        match http_request_once(&url, &opts).await {
            Ok(resp) if resp.status == 200 => {
                let v: serde_json::Value =
                    serde_json::from_slice(&resp.body).map_err(|e| e.to_string())?;
                // Some API versions wrap under `result`, v0a* returns object directly
                let data = v.get("result").cloned().unwrap_or(v);
                return Ok(data);
            }
            Ok(resp) => {
                last_err = format!(
                    "CF API HTTP {}: {}",
                    resp.status,
                    resp.text().chars().take(160).collect::<String>()
                );
            }
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

async fn register_wg_raw(
    pubkey_b64: &str,
    socks5_proxy: Option<SocketAddr>,
) -> Result<serde_json::Value, String> {
    let mut serial = [0u8; 8];
    rand::thread_rng().fill(&mut serial);
    let payload = serde_json::json!({
        "key": pubkey_b64,
        "install_id": "",
        "fcm_token": "",
        "tos": iso8601_utc_now(),
        "model": "Pixel 7",
        "serial_number": hex::encode(serial),
        "os_version": "12",
        "key_type": "curve25519",
        "tunnel_type": "wireguard",
        "locale": "en_US"
    });
    cf_api_call("POST", "/reg", &payload, None, socks5_proxy).await
}

/// Register/ensure both WireGuard and MASQUE free Cloudflare WARP credentials.
pub async fn provision_warp_account(
    existing: Option<&WarpAccountCache>,
    force_new: bool,
    socks5_proxy: Option<SocketAddr>,
) -> Result<WarpAccountCache, String> {
    let mut acc = if force_new {
        WarpAccountCache::default()
    } else {
        existing.cloned().unwrap_or_default()
    };

    // 1. WireGuard X25519 WARP credentials
    if !acc.has_wg() {
        let priv_key = X25519Secret::random_from_rng(OsRng);
        let pub_key = X25519PublicKey::from(&priv_key);
        let priv_b64 = B64.encode(priv_key.to_bytes());
        let pub_b64 = B64.encode(pub_key.as_bytes());

        let reg = register_wg_raw(&pub_b64, socks5_proxy).await?;
        let id = reg
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let token = reg
            .get("token")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let peer_pub = reg
            .pointer("/config/peers/0/public_key")
            .and_then(|v| v.as_str())
            .unwrap_or("bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=")
            .to_string();
        let v4 = reg
            .pointer("/config/interface/addresses/v4")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "WARP WG missing interface v4".to_string())?
            .to_string();
        let v6 = reg
            .pointer("/config/interface/addresses/v6")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let client_id = reg
            .pointer("/config/client_id")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let ep_host = reg
            .pointer("/config/peers/0/endpoint/v4")
            .and_then(|v| v.as_str())
            .and_then(|s| s.split(':').next())
            .unwrap_or("162.159.192.1")
            .to_string();

        acc.wg_device_id = id;
        acc.wg_token = token;
        acc.wg_private_key_b64 = priv_b64;
        acc.wg_peer_public_key_b64 = peer_pub;
        acc.wg_ipv4 = v4;
        acc.wg_ipv6 = v6;
        acc.wg_reserved = decode_client_id_reserved(client_id);
        acc.wg_endpoint_host = ep_host;
        acc.created_unix = unix_now();
    }

    // 2. MASQUE (ECDSA P-256 over HTTP/3 QUIC & HTTP/2 TCP) enrollment
    if !acc.has_masque() {
        let dummy_wg = X25519Secret::random_from_rng(OsRng);
        let dummy_pub = B64.encode(X25519PublicKey::from(&dummy_wg).as_bytes());
        if let Ok(base_reg) = register_wg_raw(&dummy_pub, socks5_proxy).await {
            let dev_id = base_reg
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let dev_tok = base_reg
                .get("token")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();

            if !dev_id.is_empty() && !dev_tok.is_empty() {
                let signing_key = P256SigningKey::random(&mut OsRng);
                let verify_key = *signing_key.verifying_key();
                if let (Ok(priv_der), Ok(pub_der)) = (
                    signing_key.to_pkcs8_der(),
                    verify_key.to_public_key_der(),
                ) {
                    let priv_b64 = B64.encode(priv_der.as_bytes());
                    let pub_b64 = B64.encode(pub_der.as_bytes());
                    let patch_body = serde_json::json!({
                        "key": pub_b64,
                        "key_type": "secp256r1",
                        "tunnel_type": "masque",
                        "name": "Android"
                    });
                    if let Ok(mreg) = cf_api_call(
                        "PATCH",
                        &format!("/reg/{dev_id}"),
                        &patch_body,
                        Some(&dev_tok),
                        socks5_proxy,
                    )
                    .await
                    {
                        let peer_pub = mreg
                            .pointer("/config/peers/0/public_key")
                            .and_then(|v| v.as_str())
                            .unwrap_or_default()
                            .to_string();
                        let v4 = mreg
                            .pointer("/config/interface/addresses/v4")
                            .and_then(|v| v.as_str())
                            .unwrap_or_default()
                            .to_string();
                        let v6 = mreg
                            .pointer("/config/interface/addresses/v6")
                            .and_then(|v| v.as_str())
                            .unwrap_or_default()
                            .to_string();
                        let ep_v4 = mreg
                            .pointer("/config/peers/0/endpoint/v4")
                            .and_then(|v| v.as_str())
                            .and_then(|s| s.split(':').next())
                            .unwrap_or("162.159.198.2")
                            .to_string();

                        if !peer_pub.is_empty() && !v4.is_empty() {
                            acc.masque_device_id = dev_id;
                            acc.masque_token = dev_tok;
                            acc.masque_private_key_pkcs8_b64 = priv_b64;
                            acc.masque_peer_public_key_b64 = peer_pub;
                            acc.masque_ipv4 = v4;
                            acc.masque_ipv6 = v6;
                            acc.masque_endpoint_ip = ep_v4;
                        }
                    }
                }
            }
        }
    }

    Ok(acc)
}

/// Curated diverse Cloudflare WARP WireGuard `(ip, port)` endpoints across independent anycast prefixes
/// and alternate ports (500, 1701, 2408, 4500, 854) that frequently bypass port-based UDP filters.
pub fn warp_wg_candidate_endpoints() -> Vec<(String, u16)> {
    vec![
        ("162.159.192.1".into(), 2408),
        ("162.159.193.10".into(), 500),
        ("162.159.195.1".into(), 1701),
        ("188.114.96.3".into(), 2408),
        ("188.114.97.7".into(), 4500),
        ("188.114.98.224".into(), 854),
        ("188.114.99.224".into(), 500),
    ]
}

/// Cloudflare WARP MASQUE CONNECT-IP endpoints (port 443 across both .198.x and .199.x anycast pools).
pub fn warp_masque_candidate_endpoints(primary: &str) -> Vec<(String, u16)> {
    let mut v = Vec::new();
    if !primary.is_empty() {
        v.push((primary.to_string(), 443));
    }
    for ip in ["162.159.198.2", "162.159.199.2", "162.159.198.1", "162.159.199.1"] {
        if !v.iter().any(|(existing, _)| existing == ip) {
            v.push((ip.to_string(), 443));
        }
    }
    v
}
