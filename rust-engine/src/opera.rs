//! Clean-room Opera SurfEasy HTTPS proxy provisioner (Tier-2 zero-cost US & EU fallback).
//! Registers an anonymous ephemeral device over DoH + masked SNI, implements RFC 2617 HTTP Digest
//! Authentication (MD5 / MD5-sess / SHA-256), manages session cookies, and discovers fresh
//! authenticated TLS HTTPS CONNECT endpoints in `AM` (USA) and `EU` (Europe/Germany).

use crate::net_util::{http_request_once, resolve_host_resilient, HttpRequestOptions, HttpResponse};
use md5::{Digest as _, Md5};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::Sha256;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const SE_API_HOST: &str = "api2.sec-tunnel.com";
const SE_API_USER: &str = "se0316";
const SE_API_SECRET: &str = "SILrMEPBmJuhomxWkfm3JalqHX2Eheg1YhlEZiMh8II";
const SE_CLIENT_TYPE: &str = "se0316";
const SE_CLIENT_VERSION: &str = "Stable 114.0.5282.21";
const SE_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 OPR/114.0.0.0";
const PROXY_SUFFIX: &str = "sec-tunnel.com";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperaEndpoint {
    pub ip: String,
    pub port: u16,
    pub region: String,       // "US" or "DE" (EU)
    pub opera_geo: String,    // "am" or "eu"
    pub country_code: String, // reported ISO code from API
    pub sni_verify: String,   // e.g. "am0.sec-tunnel.com" or "eu0.sec-tunnel.com"
    pub proxy_user: String,
    pub proxy_pass: String,
    pub expires_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OperaSessionCache {
    pub subscriber_email: String,
    pub subscriber_password: String,
    pub device_hash: String,
    pub assigned_device_id: String,
    pub assigned_device_id_hash: String,
    pub device_password: String,
    pub endpoints: Vec<OperaEndpoint>,
    pub refreshed_unix: u64,
}

impl OperaSessionCache {
    pub fn is_fresh(&self) -> bool {
        let now = unix_now();
        let has_us = self.endpoints.iter().any(|e| e.region == "US");
        let has_eu = self.endpoints.iter().any(|e| matches!(e.region.as_str(), "NL" | "DE"));
        // SurfEasy device passwords expire every ~60m; refresh every 35m so active & cached
        // relays never hit HTTP 407 Proxy Authentication Required!
        has_us
            && has_eu
            && !self.assigned_device_id_hash.is_empty()
            && !self.device_password.is_empty()
            && now.saturating_sub(self.refreshed_unix) < 35 * 60
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn random_hex_upper(nbytes: usize) -> String {
    let mut rng = rand::thread_rng();
    let mut b = vec![0u8; nbytes];
    rng.fill(&mut b[..]);
    hex::encode_upper(b)
}

fn random_hex_lower(nbytes: usize) -> String {
    let mut rng = rand::thread_rng();
    let mut b = vec![0u8; nbytes];
    rng.fill(&mut b[..]);
    hex::encode(b)
}

fn sha1_hex_upper(input: &str) -> String {
    let mut h = Sha1::new();
    h.update(input.as_bytes());
    hex::encode_upper(h.finalize())
}

fn md5_hex(input: &str) -> String {
    let mut h = Md5::new();
    h.update(input.as_bytes());
    hex::encode(h.finalize())
}

/// Parse `WWW-Authenticate: Digest realm="...", nonce="...", qop="auth", opaque="..."`.
fn parse_digest_challenge(hdr: &str) -> Option<HashMap<String, String>> {
    let rest = hdr.trim().strip_prefix("Digest ")?.trim();
    let mut map = HashMap::new();
    let bytes = rest.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b',') {
            i += 1;
        }
        let k_start = i;
        while i < bytes.len() && bytes[i] != b'=' && bytes[i] != b',' {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] != b'=' {
            break;
        }
        let key = String::from_utf8_lossy(&bytes[k_start..i])
            .trim()
            .to_ascii_lowercase();
        i += 1; // skip '='
        let val = if i < bytes.len() && bytes[i] == b'"' {
            i += 1;
            let mut raw = Vec::new();
            while i < bytes.len() && bytes[i] != b'"' {
                if bytes[i] == b'\\' && i + 1 < bytes.len() {
                    i += 1;
                }
                raw.push(bytes[i]);
                i += 1;
            }
            if i < bytes.len() {
                i += 1; // closing '"'
            }
            String::from_utf8_lossy(&raw).into_owned()
        } else {
            let v_start = i;
            while i < bytes.len() && bytes[i] != b',' {
                i += 1;
            }
            String::from_utf8_lossy(&bytes[v_start..i]).trim().to_string()
        };
        map.insert(key, val);
    }
    if map.contains_key("realm") && map.contains_key("nonce") {
        Some(map)
    } else {
        None
    }
}

fn sha256_hex(input: &str) -> String {
    let mut h = Sha256::new();
    h.update(input.as_bytes());
    hex::encode(h.finalize())
}

fn build_digest_header(
    challenge: &HashMap<String, String>,
    username: &str,
    password: &str,
    method: &str,
    uri: &str,
) -> String {
    let realm = challenge.get("realm").map(|s| s.as_str()).unwrap_or("");
    let nonce = challenge.get("nonce").map(|s| s.as_str()).unwrap_or("");
    let algorithm = challenge
        .get("algorithm")
        .map(|s| s.as_str())
        .unwrap_or("MD5");
    let cnonce = random_hex_lower(8);
    let nc = "00000001";

    let upper_alg = algorithm.to_ascii_uppercase();
    let hash_fn: fn(&str) -> String = if upper_alg.starts_with("SHA-256") {
        sha256_hex
    } else {
        md5_hex
    };

    let mut ha1 = hash_fn(&format!("{username}:{realm}:{password}"));
    if upper_alg.ends_with("-SESS") {
        ha1 = hash_fn(&format!("{ha1}:{nonce}:{cnonce}"));
    }
    let ha2 = hash_fn(&format!("{method}:{uri}"));

    let qop_opt = challenge.get("qop").and_then(|q| {
        q.split(',')
            .map(|s| s.trim())
            .find(|s| s.eq_ignore_ascii_case("auth"))
    });

    let response = if let Some(qop) = qop_opt {
        hash_fn(&format!("{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}"))
    } else {
        hash_fn(&format!("{ha1}:{nonce}:{ha2}"))
    };

    let mut out = format!(
        "Digest username=\"{username}\", realm=\"{realm}\", nonce=\"{nonce}\", uri=\"{uri}\", response=\"{response}\""
    );
    if let Some(alg) = challenge.get("algorithm") {
        out.push_str(&format!(", algorithm={alg}"));
    }
    if let Some(opaque) = challenge.get("opaque") {
        out.push_str(&format!(", opaque=\"{opaque}\""));
    }
    if let Some(qop) = qop_opt {
        out.push_str(&format!(", qop={qop}, nc={nc}, cnonce=\"{cnonce}\""));
    }
    out
}

fn collect_cookies(resp: &HttpResponse, jar: &mut HashMap<String, String>) {
    for (k, v) in &resp.headers {
        if k.eq_ignore_ascii_case("set-cookie") {
            if let Some(pair) = v.split(';').next() {
                if let Some((ck, cv)) = pair.split_once('=') {
                    jar.insert(ck.trim().to_string(), cv.trim().to_string());
                }
            }
        }
    }
}

fn cookie_header(jar: &HashMap<String, String>) -> Option<String> {
    if jar.is_empty() {
        return None;
    }
    let joined: Vec<String> = jar.iter().map(|(k, v)| format!("{k}={v}")).collect();
    Some(joined.join("; "))
}

async fn se_rpc(
    path: &str,
    params: &[(&str, &str)],
    cookies: &mut HashMap<String, String>,
    api_ip: Option<std::net::IpAddr>,
    socks5_proxy: Option<SocketAddr>,
) -> Result<serde_json::Value, String> {
    let url = format!("https://{SE_API_HOST}{path}");
    let body_str: String = {
        let mut ser = url::form_urlencoded::Serializer::new(String::new());
        for (k, v) in params {
            ser.append_pair(k, v);
        }
        ser.finish()
    };
    let body_bytes = body_str.into_bytes();

    let make_headers = |auth: Option<String>, jar: &HashMap<String, String>| {
        let mut h = vec![
            ("SE-Client-Version".to_string(), SE_CLIENT_VERSION.to_string()),
            ("SE-Operating-System".to_string(), "Windows".to_string()),
            ("User-Agent".to_string(), SE_USER_AGENT.to_string()),
            (
                "Content-Type".to_string(),
                "application/x-www-form-urlencoded".to_string(),
            ),
            ("Accept".to_string(), "application/json".to_string()),
        ];
        if let Some(c) = cookie_header(jar) {
            h.push(("Cookie".to_string(), c));
        }
        if let Some(a) = auth {
            h.push(("Authorization".to_string(), a));
        }
        h
    };

    // Use neutral SNI camouflage (example.com) + TLS fragmentation just like opera-proxy -fake-SNI
    let base_opts = HttpRequestOptions {
        method: "POST".to_string(),
        headers: make_headers(None, cookies),
        body: Some(body_bytes.clone()),
        timeout: Duration::from_secs(9),
        max_bytes: 128 * 1024,
        fragment_tls: true,
        socks5_proxy,
        sni_override: Some("www.microsoft.com".to_string()),
        insecure_masked_sni: true,
        fixed_ip: api_ip,
    };

    let mut resp = http_request_once(&url, &base_opts).await?;
    collect_cookies(&resp, cookies);

    if resp.status == 401 {
        let www = resp
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("www-authenticate"))
            .map(|(_, v)| v.clone())
            .ok_or_else(|| "401 without WWW-Authenticate".to_string())?;
        let chal =
            parse_digest_challenge(&www).ok_or_else(|| "invalid Digest challenge".to_string())?;
        let auth_hdr = build_digest_header(&chal, SE_API_USER, SE_API_SECRET, "POST", path);
        let auth_opts = HttpRequestOptions {
            headers: make_headers(Some(auth_hdr), cookies),
            ..base_opts
        };
        resp = http_request_once(&url, &auth_opts).await?;
        collect_cookies(&resp, cookies);
    }

    if resp.status != 200 {
        return Err(format!("SurfEasy {path} HTTP {}", resp.status));
    }

    let val: serde_json::Value =
        serde_json::from_slice(&resp.body).map_err(|e| format!("SurfEasy json: {e}"))?;

    // Check return_code == {"0": "..."}
    if let Some(rc) = val.get("return_code").and_then(|v| v.as_object()) {
        if !rc.contains_key("0") {
            return Err(format!("SurfEasy {path} api error: {rc:?}"));
        }
    }
    Ok(val)
}

/// Provision or refresh fresh free Opera HTTPS proxies in USA (`AM`) and Europe (`EU`).
pub async fn provision_opera_endpoints(
    existing: Option<&OperaSessionCache>,
    socks5_proxy: Option<SocketAddr>,
) -> Result<OperaSessionCache, String> {
    let api_ip = if socks5_proxy.is_none() {
        resolve_host_resilient(SE_API_HOST)
            .await
            .ok()
            .and_then(|v| v.into_iter().find(|ip| ip.is_ipv4()))
    } else {
        None
    };

    let mut cookies = HashMap::new();
    let mut cache = existing.cloned().unwrap_or_default();

    // Try re-login if we already have an account; otherwise register a fresh anonymous one
    let mut logged_in = false;
    if !cache.subscriber_email.is_empty()
        && !cache.subscriber_password.is_empty()
        && !cache.assigned_device_id.is_empty()
    {
        if se_rpc(
            "/v4/subscriber_login",
            &[
                ("login", &cache.subscriber_email),
                ("password", &cache.subscriber_password),
                ("client_type", SE_CLIENT_TYPE),
            ],
            &mut cookies,
            api_ip,
            socks5_proxy,
        )
        .await
        .is_ok()
        {
            if let Ok(pw_res) = se_rpc(
                "/v4/device_generate_password",
                &[("device_id", &cache.assigned_device_id)],
                &mut cookies,
                api_ip,
                socks5_proxy,
            )
            .await
            {
                if let Some(pw) = pw_res
                    .pointer("/data/device_password")
                    .and_then(|v| v.as_str())
                {
                    cache.device_password = pw.to_string();
                    logged_in = true;
                }
            }
        }
    }

    if !logged_in {
        cookies.clear();
        let email = format!("{}@{}.best.vpn", random_hex_lower(16), SE_CLIENT_TYPE);
        let password = sha1_hex_upper(&email);
        let device_hash = random_hex_upper(20);

        se_rpc(
            "/v4/register_subscriber",
            &[("email", &email), ("password", &password)],
            &mut cookies,
            api_ip,
            socks5_proxy,
        )
        .await?;

        let dev_res = se_rpc(
            "/v4/register_device",
            &[
                ("client_type", SE_CLIENT_TYPE),
                ("device_hash", &device_hash),
                ("device_name", "Opera-Browser-Client"),
            ],
            &mut cookies,
            api_ip,
            socks5_proxy,
        )
        .await?;

        let assigned_id = dev_res
            .pointer("/data/device_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "missing device_id".to_string())?
            .to_string();
        let device_pw = dev_res
            .pointer("/data/device_password")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "missing device_password".to_string())?
            .to_string();
        let assigned_hash = sha1_hex_upper(&assigned_id);

        cache.subscriber_email = email;
        cache.subscriber_password = password;
        cache.device_hash = device_hash;
        cache.assigned_device_id = assigned_id;
        cache.assigned_device_id_hash = assigned_hash;
        cache.device_password = device_pw;
    }

    let now = unix_now();
    let expires = now + 45 * 60;
    let mut endpoints = Vec::new();

    // Discover AM (USA), EU (Europe/NL/DE), and AS (Asia/Singapore) official 10 Gbps relays
    for (opera_geo, region_label) in [("AM", "US"), ("EU", "NL"), ("AS", "SG")] {
        let req_geo = format!("\"{opera_geo}\",,");
        let mut disc_opt = None;
        for _ in 0..2 {
            if let Ok(d) = se_rpc(
                "/v4/discover",
                &[
                    ("serial_no", &cache.assigned_device_id_hash),
                    ("requested_geo", &req_geo),
                ],
                &mut cookies,
                api_ip,
                socks5_proxy,
            )
            .await
            {
                disc_opt = Some(d);
                break;
            }
        }
        if let Some(disc) = disc_opt {
            if let Some(ips) = disc.pointer("/data/ips").and_then(|v| v.as_array()) {
                for entry in ips.iter().take(3) {
                    let Some(ip) = entry.get("ip").and_then(|v| v.as_str()) else {
                        continue;
                    };
                    let port = entry
                        .get("ports")
                        .and_then(|v| v.as_array())
                        .and_then(|arr| arr.iter().find_map(|p| p.as_u64()))
                        .unwrap_or(443) as u16;
                    let cc = entry
                        .pointer("/geo/country_code")
                        .and_then(|v| v.as_str())
                        .unwrap_or(region_label)
                        .to_ascii_uppercase();
                    let geo_lower = opera_geo.to_ascii_lowercase();
                    endpoints.push(OperaEndpoint {
                        ip: ip.to_string(),
                        port,
                        region: region_label.to_string(),
                        opera_geo: geo_lower.clone(),
                        country_code: cc,
                        sni_verify: format!("{geo_lower}0.{PROXY_SUFFIX}"),
                        proxy_user: cache.assigned_device_id_hash.clone(),
                        proxy_pass: cache.device_password.clone(),
                        expires_unix: expires,
                    });
                }
            }
        }
    }

    if endpoints.is_empty() {
        return Err("SurfEasy returned 0 endpoints".to_string());
    }

    cache.endpoints = endpoints;
    cache.refreshed_unix = now;
    Ok(cache)
}
