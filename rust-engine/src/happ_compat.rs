//! Complete zero-server, offline Happ 4.11+ / Incy 4.0+ / v2rayTun / Remnawave / Marzban / 3x-ui
//! subscription compatibility layer for VeloxVPN v1.6.0:
//!
//! - Offline client-side decryption of `happ://crypt/`, `happ://crypt2/`, `happ://crypt3/`,
//!   `happ://crypt4/` (RSA-4096), and `happ://crypt5/` (hybrid RSA + ChaCha20-Poly1305)
//! - Extraction of encrypted links wrapped inside HTTPS portal redirectors
//!   (e.g. `https://portal.example/open?url=happ%3A%2F%2Fcrypt5%2F...` or `/happ://crypt4/...`)
//! - Offline AES-256-GCM decryption of `incy://crypt1/...`
//! - Unwrapping of `happ://add/...`, `v2raytun://import/...`, `v2raytun://crypt/...` (Base64),
//!   `v2rayng://`, `hiddify://import/...`, `streisand://import/...`, `clash://install-config`,
//!   `flclash://`, `sing-box://import-remote-profile`, `velox://add/...`, and `ssconf://`
//! - Offline AES-128-GCM subscription body decryption (built-in Happ key tables)
//! - Full metadata extraction: `profile-title` (`base64:` & UTF-8 & fragment), structured
//!   `subscription-userinfo` (`upload`, `download`, `total`, `expire`), `announce`, `support-url`,
//!   `profile-web-page-url` / renewal link, `profile-update-interval`, and HWID device-limit status
//! - Optional privacy-first Happ `X-HWID` + wire-order `Happ/Android` request header builder
//! - Ready-made Xray JSON & JSON-array outbound support in addition to standard share URIs.

use base64::engine::general_purpose::{
    STANDARD as B64, STANDARD_NO_PAD as B64_NP, URL_SAFE as B64_URL, URL_SAFE_NO_PAD as B64_URL_NP,
};
use base64::Engine;
use happ_sub::deeplink::{parse_deeplink, Deeplink};
use happ_sub::happ_request::{self, ClientOs, DeviceInfo, Identity};
use happ_sub::incy_crypt;
use happ_sub::url_crypt;
use happ_sub::{BodyEncryption, Input, Limits, MergeMode, Payload, StoredState};
use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};
use url::Url;

/// User-controlled optional HWID identity (OFF by default for maximum privacy; can be toggled ON
/// for paid Happ/Remnawave/3x-ui subscriptions that enforce per-device `X-HWID` limits).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HwidIdentityConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub hwid: String,
    #[serde(default)]
    pub os_version: String,
    #[serde(default)]
    pub device_model: String,
    #[serde(default)]
    pub locale: String,
}

/// Result of unwrapping / decrypting any user-supplied or deep-linked subscription URL.
#[derive(Debug, Clone)]
pub struct UnwrappedSubscription {
    /// Full decrypted URL (may carry `#title?meta=val` fragment for `happ_sub::parse`).
    pub full_url: String,
    /// Network fetch URL (without `#fragment`, matching Happ's exact HTTP behavior).
    pub fetch_url: String,
    /// Non-empty when link was encrypted (e.g. `"crypt5"`, `"crypt4"`, `"crypt3"`, `"incy1"`).
    pub encrypted_kind: String,
    /// Optional provider/display title carried inside the link or fragment.
    pub hint_title: String,
    /// Whether the link originated from a Happ/Incy scheme (prefer `Happ/Android` UA first).
    pub prefer_happ_ua: bool,
}

/// Structured subscription metadata & extracted payload from HTTP headers + body.
#[derive(Debug, Clone, Default)]
pub struct ParsedSubscriptionEnvelope {
    pub title: String,
    pub userinfo_summary: String,
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub total_bytes: u64,
    pub expire_unix: u64,
    pub announce: String,
    pub support_url: String,
    pub web_page_url: String,
    pub update_interval_hours: u32,
    pub body_encrypted: bool,
    pub encrypted_label: String,
    /// `""`, `"limit_reached"`, or `"hwid_required"`
    pub hwid_status: String,
    /// Extracted share-link lines (if `Payload::Links`).
    pub share_links: Vec<String>,
    /// Extracted raw Xray JSON documents (if `Payload::XrayJson` or `Payload::JsonArray`).
    pub xray_json_configs: Vec<serde_json::Value>,
    /// True if subscription returned only a sing-box JSON profile.
    pub sing_box_only: bool,
}

/// Strip `#fragment` from a stored subscription URL to produce the exact HTTP wire fetch URL.
pub fn fetch_url_without_fragment(full_url: &str) -> String {
    full_url.split('#').next().unwrap_or(full_url).trim().to_string()
}

/// Extract an embedded `happ://crypt...` or `incy://crypt1/...` or `happ://add/...` hidden inside
/// an HTTPS redirect wrapper such as `https://sub.example/open/happ%3A%2F%2Fcrypt5%2F...` or
/// `https://sub.example/?link=happ://crypt4/...`.
fn extract_embedded_special_uri(input: &str) -> Option<String> {
    let trimmed = input.trim();
    if !(trimmed.starts_with("https://") || trimmed.starts_with("http://")) {
        return None;
    }
    // Check raw string after scheme (`https://` = 8 chars)
    let tail = &trimmed[7..];
    for needle in [
        "happ://crypt",
        "happ://add/",
        "incy://crypt1/",
        "v2raytun://import/",
        "v2raytun://crypt/",
    ] {
        if let Some(pos) = tail.to_ascii_lowercase().find(needle) {
            let candidate = tail[pos..].trim();
            if !candidate.is_empty() {
                return Some(candidate.to_string());
            }
        }
    }
    // Check percent-decoded query/path (e.g. `happ%3A%2F%2Fcrypt5%2F...`)
    let decoded = percent_decode_str(tail).decode_utf8_lossy();
    let dec_low = decoded.to_ascii_lowercase();
    for needle in [
        "happ://crypt",
        "happ://add/",
        "incy://crypt1/",
        "v2raytun://import/",
        "v2raytun://crypt/",
    ] {
        if let Some(pos) = dec_low.find(needle) {
            let sub = decoded[pos..].trim();
            // Stop at `&` only when wrapping query had extra tracking params outside the payload
            let clean = sub.split_whitespace().next().unwrap_or(sub);
            if !clean.is_empty() {
                return Some(clean.to_string());
            }
        }
    }
    None
}

fn try_decode_b64_utf8(s: &str) -> Option<String> {
    let clean: String = s.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    if clean.len() < 8 {
        return None;
    }
    for bytes_res in [
        B64.decode(&clean),
        B64_NP.decode(&clean),
        B64_URL.decode(&clean),
        B64_URL_NP.decode(&clean),
    ] {
        if let Ok(bytes) = bytes_res {
            if let Ok(txt) = String::from_utf8(bytes) {
                let t = txt.trim().to_string();
                if !t.is_empty() {
                    return Some(t);
                }
            }
        }
    }
    None
}

fn finalize_http_url(
    raw_url: &str,
    encrypted_kind: &str,
    hint_title: &str,
    prefer_happ_ua: bool,
) -> Result<UnwrappedSubscription, String> {
    let normalized = if let Some(rest) = raw_url.trim().strip_prefix("ssconf://") {
        format!("https://{rest}")
    } else {
        raw_url.trim().to_string()
    };
    let parsed = Url::parse(&normalized)
        .map_err(|_| "Расшифрованная ссылка имеет неверный формат URL".to_string())?;
    if !matches!(parsed.scheme(), "https" | "http") {
        return Err(format!("Неподдерживаемая схема подписки: {}", parsed.scheme()));
    }
    let host = parsed.host_str().unwrap_or("");
    if host.is_empty() || !host.contains('.') {
        return Err("В ссылке подписки отсутствует корректный домен".to_string());
    }
    // Extract optional human title from `#title` or `#title?k=v` fragment
    let mut title = hint_title.trim().to_string();
    if title.is_empty() {
        if let Ok(fmeta) = happ_sub::meta::parse_fragment(&normalized, &Limits::default()) {
            if let Some(t) = fmeta.profile_title() {
                title = t.trim().to_string();
            }
        }
        if title.is_empty() {
            if let Some(frag) = parsed.fragment() {
                let raw_name = frag.split('?').next().unwrap_or(frag);
                let dec = percent_decode_str(raw_name).decode_utf8_lossy();
                let clean = dec.trim();
                if !clean.is_empty() && clean.len() <= 64 && !clean.contains('=') {
                    title = clean.to_string();
                }
            }
        }
    }
    let fetch_url = happ_sub::meta::fetch_url(&normalized).trim().to_string();
    Ok(UnwrappedSubscription {
        full_url: normalized,
        fetch_url,
        encrypted_kind: encrypted_kind.to_string(),
        hint_title: title,
        prefer_happ_ua,
    })
}

/// Check whether a raw single-line input is a decrypted/encrypted subscription link or action.
/// - Returns `Some(Ok(UnwrappedSubscription))` when it unwraps/decrypts to an `http(s)://` URL.
/// - Returns `Some(Err(ru_error))` when it IS a recognized encrypted link (`happ://crypt*`,
///   `incy://crypt1/*`, `v2raytun://crypt/*`) whose ciphertext is corrupted/invalid.
/// - Returns `None` when the input is NOT a subscription URL (e.g. a raw `vless://` or `tg://` key).
pub fn unwrap_or_decrypt_subscription(raw: &str) -> Option<Result<UnwrappedSubscription, String>> {
    let mut s = raw.trim().to_string();
    if s.is_empty() || s.contains('\n') {
        return None;
    }

    // Step 0: Check for encrypted/client deeplinks wrapped inside an `https://` portal URL
    if let Some(embedded) = extract_embedded_special_uri(&s) {
        s = embedded;
    }

    let low = s.to_ascii_lowercase();

    // Step 1: Offline `happ://` deeplink & `happ://crypt/` .. `happ://crypt5/` RSA/ChaCha20 decryption!
    if low.starts_with("happ://") {
        // Explicit `happ://crypt*` fast path via built-in RSA-4096 + crypt5 keyring
        if low.starts_with("happ://crypt") {
            let ver_tag = if low.starts_with("happ://crypt5/") {
                "crypt5"
            } else if low.starts_with("happ://crypt4/") {
                "crypt4"
            } else if low.starts_with("happ://crypt3/") {
                "crypt3"
            } else if low.starts_with("happ://crypt2/") {
                "crypt2"
            } else {
                "crypt"
            };
            let keyring = url_crypt::builtin_keyring();
            return match url_crypt::decrypt_url(&s, keyring) {
                Ok(plain) => {
                    let p = plain.trim();
                    if p.starts_with("https://")
                        || p.starts_with("http://")
                        || p.starts_with("ssconf://")
                    {
                        Some(finalize_http_url(p, ver_tag, "", true))
                    } else if p.to_ascii_lowercase().starts_with("happ://") {
                        // Nested `happ://add/https://...` inside a crypt envelope
                        unwrap_or_decrypt_subscription(p).map(|r| {
                            r.map(|mut u| {
                                if u.encrypted_kind.is_empty() {
                                    u.encrypted_kind = ver_tag.to_string();
                                }
                                u.prefer_happ_ua = true;
                                u
                            })
                        })
                    } else {
                        Some(Err(
                            "Расшифрованная ссылка happ://crypt не содержит адрес подписки"
                                .to_string(),
                        ))
                    }
                }
                Err(e) => Some(Err(format!(
                    "Не удалось расшифровать ссылку {ver_tag}: повреждённые данные ({e})"
                ))),
            };
        }

        // Standard `happ://add/<url>` & structured deeplinks
        if let Ok(dl) = parse_deeplink(&s) {
            match dl {
                Deeplink::Add(inner) => {
                    let dec = percent_decode_str(inner.trim()).decode_utf8_lossy();
                    let cand = if inner.trim().starts_with("http") {
                        inner.trim().to_string()
                    } else {
                        dec.trim().to_string()
                    };
                    if cand.to_ascii_lowercase().starts_with("happ://crypt") {
                        return unwrap_or_decrypt_subscription(&cand);
                    }
                    return Some(finalize_http_url(&cand, "", "", true));
                }
                Deeplink::Crypt { version, .. } => {
                    let keyring = url_crypt::builtin_keyring();
                    let tag = if version <= 1 {
                        "crypt".to_string()
                    } else {
                        format!("crypt{version}")
                    };
                    return Some(
                        url_crypt::decrypt_url(&s, keyring)
                            .map_err(|e| format!("Ошибка расшифровки happ://{tag}: {e}"))
                            .and_then(|plain| finalize_http_url(&plain, &tag, "", true)),
                    );
                }
                _ => {}
            }
        }
        // Query-style fallback `happ://install-config?url=...`
        if let Ok(u) = Url::parse(&s) {
            for (k, v) in u.query_pairs() {
                if matches!(k.as_ref(), "url" | "sub" | "config") && !v.is_empty() {
                    return Some(finalize_http_url(v.trim(), "", "", true));
                }
            }
        }
        return Some(Err("Неподдерживаемая команда ссылки happ://".to_string()));
    }

    // Step 2: Offline `incy://crypt1/...` AES-256-GCM decryption!
    if incy_crypt::is_incy_link(&s) || low.starts_with("incy://") {
        if incy_crypt::is_incy_link(&s) {
            let key = incy_crypt::builtin_key();
            return Some(
                incy_crypt::decrypt_link(&s, key)
                    .map_err(|e| format!("Ошибка расшифровки incy://crypt1: {e}"))
                    .and_then(|link| {
                        finalize_http_url(
                            &link.url,
                            "incy1",
                            link.name.as_deref().unwrap_or(""),
                            true,
                        )
                    }),
            );
        }
        if let Some(rest) = s.strip_prefix("incy://add/") {
            let dec = percent_decode_str(rest.trim()).decode_utf8_lossy();
            return Some(finalize_http_url(dec.trim(), "", "", true));
        }
    }

    // Step 3: `v2raytun://`, `hiddify://`, `streisand://`, `velox://`, `v2rayng://`, `clash://`, `sing-box://`
    if let Some(rest) = s
        .strip_prefix("v2raytun://crypt/")
        .or_else(|| s.strip_prefix("v2raytun://import-base64/"))
    {
        if let Some(plain) = try_decode_b64_utf8(rest) {
            if plain.starts_with("https://") || plain.starts_with("http://") {
                return Some(finalize_http_url(&plain, "v2raytun", "", false));
            }
        }
        // Try Happ keyring fallback (several panels cross-label RSA payloads)
        let as_happ4 = format!("happ://crypt4/{}", rest.trim());
        if let Ok(plain) = url_crypt::decrypt_url(&as_happ4, url_crypt::builtin_keyring()) {
            return Some(finalize_http_url(&plain, "v2raytun", "", true));
        }
        let as_happ3 = format!("happ://crypt3/{}", rest.trim());
        if let Ok(plain) = url_crypt::decrypt_url(&as_happ3, url_crypt::builtin_keyring()) {
            return Some(finalize_http_url(&plain, "v2raytun", "", true));
        }
        return Some(Err(
            "Ссылка v2raytun://crypt использует закрытый ключ — используйте happ://crypt или https://"
                .to_string(),
        ));
    }

    for prefix in [
        "v2raytun://import/",
        "hiddify://import/",
        "streisand://import/",
        "velox://add/",
        "velox://import/",
        "uwuvpn://add/",
        "uwuvpn://import/",
    ] {
        if low.starts_with(prefix) {
            let raw_tail = s[prefix.len()..].trim();
            if raw_tail.starts_with("https://") || raw_tail.starts_with("http://") {
                return Some(finalize_http_url(raw_tail, "", "", false));
            }
            let dec = percent_decode_str(raw_tail).decode_utf8_lossy();
            if dec.starts_with("https://") || dec.starts_with("http://") {
                return Some(finalize_http_url(dec.trim(), "", "", false));
            }
            if let Some(b64) = try_decode_b64_utf8(raw_tail) {
                if b64.starts_with("https://") || b64.starts_with("http://") {
                    return Some(finalize_http_url(&b64, "", "", false));
                }
            }
        }
    }

    if low.starts_with("clash://")
        || low.starts_with("flclash://")
        || low.starts_with("koala-clash://")
        || low.starts_with("sing-box://")
        || low.starts_with("v2rayng://")
        || low.starts_with("karing://")
        || low.starts_with("velox://")
    {
        if let Ok(u) = Url::parse(&s) {
            let mut name_hint = String::new();
            let mut found_url = None;
            for (k, v) in u.query_pairs() {
                if matches!(k.as_ref(), "name" | "title" | "remarks") && !v.is_empty() {
                    name_hint = v.into_owned();
                } else if matches!(k.as_ref(), "url" | "config" | "sub")
                    && (v.starts_with("https://") || v.starts_with("http://"))
                {
                    found_url = Some(v.into_owned());
                }
            }
            if let Some(target) = found_url {
                return Some(finalize_http_url(&target, "", &name_hint, false));
            }
        }
    }

    // Step 4: Direct `https://`, `http://`, or `ssconf://` (skip Telegram proxy links `t.me/proxy`)
    if (low.starts_with("https://") || low.starts_with("http://") || low.starts_with("ssconf://"))
        && !low.starts_with("https://t.me/proxy")
        && !low.starts_with("https://t.me/socks")
        && !low.starts_with("http://t.me/proxy")
    {
        return finalize_http_url(&s, "", "", false).ok().map(Ok);
    }

    None
}

/// Also decrypt raw single-line `happ://crypt*` that resolves directly to share links
/// (`vless://...\nhy2://...`) instead of a subscription URL!
pub fn try_decrypt_inline_happ_keys(raw: &str) -> Option<String> {
    let s = raw.trim();
    if !s.to_ascii_lowercase().starts_with("happ://crypt") {
        return None;
    }
    let plain = url_crypt::decrypt_url(s, url_crypt::builtin_keyring()).ok()?;
    let pt = plain.trim();
    if pt.contains("://")
        && !pt.starts_with("https://")
        && !pt.starts_with("http://")
        && !pt.to_ascii_lowercase().starts_with("happ://")
    {
        Some(pt.to_string())
    } else {
        None
    }
}

/// Build authentic wire-order `Happ/<ver>/Android` subscription request headers.
/// Only attaches `X-HWID` & device metadata when `hwid_cfg.enabled && !hwid_cfg.hwid.is_empty()`.
pub fn build_happ_headers(hwid_cfg: &HwidIdentityConfig, unix_secs: u64) -> Vec<(String, String)> {
    let use_hwid = hwid_cfg.enabled && !hwid_cfg.hwid.trim().is_empty();
    let identity = Identity {
        hwid: if use_hwid {
            Some(hwid_cfg.hwid.trim().to_string())
        } else {
            None
        },
        device: DeviceInfo {
            os: ClientOs::Android,
            os_version: if hwid_cfg.os_version.is_empty() {
                "14".to_string()
            } else {
                hwid_cfg.os_version.clone()
            },
            model: if hwid_cfg.device_model.is_empty() {
                "Android".to_string()
            } else {
                hwid_cfg.device_model.clone()
            },
            locale: if hwid_cfg.locale.is_empty() {
                "ru-RU".to_string()
            } else {
                hwid_cfg.locale.clone()
            },
        },
        send_hwid_override: Some(use_hwid),
        ..Identity::default()
    };
    let profile = happ_request::build(&identity, None, unix_secs, |_| false);
    profile
        .headers
        .into_iter()
        .filter(|(k, _)| !k.eq_ignore_ascii_case("connection"))
        .collect()
}

/// Format structured `upload/download/total/expire` into a crisp Russian badge line.
pub fn format_userinfo_ru(upload: u64, download: u64, total: u64, expire_unix: u64, now: u64) -> String {
    let used = upload.saturating_add(download);
    let mut parts = Vec::with_capacity(2);
    if total > 0 {
        let used_gb = used as f64 / 1_073_741_824.0;
        let tot_gb = total as f64 / 1_073_741_824.0;
        if tot_gb >= 9_000.0 {
            parts.push(format!("{used_gb:.1} ГБ · ∞"));
        } else {
            parts.push(format!("{used_gb:.1} / {tot_gb:.0} ГБ"));
        }
    } else if used > 0 {
        let used_gb = used as f64 / 1_073_741_824.0;
        parts.push(format!("{used_gb:.1} ГБ"));
    }
    if expire_unix > 1_600_000_000 {
        if expire_unix <= now {
            parts.push("истекла".to_string());
        } else {
            let days_left = (expire_unix - now) / 86_400;
            if days_left == 0 {
                let hrs = ((expire_unix - now) / 3_600).max(1);
                parts.push(format!("ещё {hrs} ч"));
            } else if days_left <= 3650 {
                parts.push(format!("ещё {days_left} дн."));
            } else {
                parts.push("бессрочно".to_string());
            }
        }
    }
    parts.join(" · ")
}

/// Parse an HTTP subscription response using `happ_sub` (AES-128-GCM body decryption, base64/plain
/// metadata headers, URL fragment directives, `Payload::Links` / `XrayJson` / `JsonArray`, and
/// explicit HWID limit detection).
pub fn parse_subscription_envelope(
    full_url: &str,
    headers: &[(String, String)],
    body: &[u8],
    was_body_encrypted: bool,
    url_encrypted_kind: &str,
    now_unix: u64,
) -> ParsedSubscriptionEnvelope {
    let mut out = ParsedSubscriptionEnvelope {
        encrypted_label: url_encrypted_kind.to_string(),
        ..Default::default()
    };

    // Inspect vendor-specific HWID limit & Content-Disposition fallback headers
    let mut content_disp_name = String::new();
    for (k, v) in headers {
        let kl = k.to_ascii_lowercase();
        let vt = v.trim();
        if kl == "x-hwid-limit" || kl == "x-hwid-max-devices-reached" {
            if vt.eq_ignore_ascii_case("true") {
                out.hwid_status = "limit_reached".to_string();
            } else if let Ok(n) = vt.parse::<u32>() {
                if n > 0 && out.hwid_status.is_empty() {
                    out.hwid_status = format!("лимит {n} устр.");
                }
            }
        } else if kl == "x-hwid-not-supported" && vt.eq_ignore_ascii_case("true") {
            out.hwid_status = "hwid_required".to_string();
        } else if kl == "content-disposition" && content_disp_name.is_empty() {
            if let Some(idx) = vt.find("filename*=UTF-8''") {
                let raw_fn = vt[idx + 17..].split(';').next().unwrap_or("").trim();
                let dec = percent_decode_str(raw_fn).decode_utf8_lossy();
                content_disp_name = dec.trim_matches('"').trim().to_string();
            } else if let Some(idx) = vt.find("filename=") {
                let raw_fn = vt[idx + 9..].split(';').next().unwrap_or("").trim();
                content_disp_name = raw_fn.trim_matches('"').trim().to_string();
            }
        }
    }

    let input = Input {
        url: full_url,
        headers,
        body,
        stored: if was_body_encrypted {
            Some(StoredState {
                encrypted: true,
                meta: None,
                merge: MergeMode::Full,
            })
        } else {
            None
        },
        limits: None,
    };

    if let Ok(parsed) = happ_sub::parse(&input) {
        if parsed.body_encryption != BodyEncryption::None {
            out.body_encrypted = true;
            if out.encrypted_label.is_empty() {
                out.encrypted_label = "aes-gcm".to_string();
            } else if !out.encrypted_label.contains("aes") {
                out.encrypted_label = format!("{}+aes", out.encrypted_label);
            }
        }

        let m = &parsed.meta;
        if let Some(t) = m.profile_title() {
            let clean = t.trim();
            if !clean.is_empty() {
                out.title = clean.chars().take(64).collect();
            }
        }
        if let Some(ui) = m.user_info() {
            out.upload_bytes = ui.upload;
            out.download_bytes = ui.download;
            out.total_bytes = ui.total;
            out.expire_unix = ui.expire;
            out.userinfo_summary = format_userinfo_ru(
                out.upload_bytes,
                out.download_bytes,
                out.total_bytes,
                out.expire_unix,
                now_unix,
            );
        }
        if let Some(ann) = m.announce().or_else(|| m.sub_info_text()) {
            let clean = ann.replace("\\n", "\n").trim().to_string();
            if !clean.is_empty() {
                out.announce = clean.chars().take(280).collect();
            }
        }
        if let Some(sup) = m.support_url() {
            let s = sup.trim();
            if s.starts_with("https://") || s.starts_with("tg://") {
                out.support_url = s.chars().take(240).collect();
            }
        }
        if let Some(web) = m
            .profile_web_page_url()
            .or_else(|| m.sub_expire_button_link())
            .or_else(|| m.sub_info_button_link())
        {
            let w = web.trim();
            if w.starts_with("https://") || w.starts_with("tg://") {
                out.web_page_url = w.chars().take(240).collect();
            }
        }
        if let Some(hrs) = m.profile_update_interval() {
            out.update_interval_hours = hrs.clamp(1, 730);
        }

        match parsed.payload {
            Payload::Links(links) => {
                out.share_links = links;
            }
            Payload::XrayJson(doc) => {
                out.xray_json_configs.push(doc);
            }
            Payload::JsonArray(items) => {
                out.xray_json_configs = items;
            }
            Payload::SingBoxJson(_) => {
                out.sing_box_only = true;
            }
        }
    } else {
        // Fallback header parse when body is a custom TG proxy list or non-Happ response
        if let Ok(m) = happ_sub::meta::parse_headers(headers, &Limits::default()) {
            if let Some(t) = m.profile_title() {
                out.title = t.trim().chars().take(64).collect();
            }
            if let Some(ui) = m.user_info() {
                out.upload_bytes = ui.upload;
                out.download_bytes = ui.download;
                out.total_bytes = ui.total;
                out.expire_unix = ui.expire;
                out.userinfo_summary = format_userinfo_ru(
                    out.upload_bytes,
                    out.download_bytes,
                    out.total_bytes,
                    out.expire_unix,
                    now_unix,
                );
            }
            if let Some(sup) = m.support_url() {
                if sup.trim().starts_with("https://") || sup.trim().starts_with("tg://") {
                    out.support_url = sup.trim().chars().take(240).collect();
                }
            }
            if let Some(web) = m.profile_web_page_url() {
                if web.trim().starts_with("https://") || web.trim().starts_with("tg://") {
                    out.web_page_url = web.trim().chars().take(240).collect();
                }
            }
            if let Some(ann) = m.announce() {
                out.announce = ann.replace("\\n", "\n").trim().chars().take(280).collect();
            }
        }
    }

    if out.title.is_empty() && !content_disp_name.is_empty() {
        out.title = content_disp_name.chars().take(64).collect();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xray_config::{
        build_production_tun_config_v16, node_matches_strict_region,
        parse_share_uri_to_candidate, parse_xray_json_config_to_candidates,
    };

    #[test]
    fn test_deeplink_unwrapping_all_clients() {
        for link in [
            "happ://add/https://panel.example.com/sub/abc123#MySub",
            "v2raytun://import/https://panel.example.com/sub/abc123",
            "hiddify://import/https://panel.example.com/sub/abc123#VIP",
            "clash://install-config?url=https%3A%2F%2Fpanel.example.com%2Fsub%2Fabc123&name=Test",
            "sing-box://import-remote-profile?url=https%3A%2F%2Fpanel.example.com%2Fsub%2Fabc123",
            "ssconf://panel.example.com/sub/abc123#Outline",
            "velox://add/https://panel.example.com/sub/abc123",
        ] {
            let unw = unwrap_or_decrypt_subscription(link)
                .unwrap_or_else(|| panic!("expected Some for {link}"))
                .unwrap_or_else(|e| panic!("unwrap failed for {link}: {e}"));
            assert_eq!(unw.fetch_url, "https://panel.example.com/sub/abc123", "link={link}");
        }
        assert!(matches!(
            unwrap_or_decrypt_subscription("happ://crypt5/not_valid_rsa_blob"),
            Some(Err(_))
        ));
        assert!(matches!(
            unwrap_or_decrypt_subscription("incy://crypt1/not_valid_rsa_blob"),
            Some(Err(_))
        ));
    }

    #[test]
    fn test_hwid_headers_and_happ_metadata() {
        let off = HwidIdentityConfig::default();
        let h_off = build_happ_headers(&off, 1_763_000_000);
        assert!(h_off
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("user-agent") && v.contains("Happ/")));
        assert!(!h_off.iter().any(|(k, _)| k.eq_ignore_ascii_case("x-hwid")));

        let on = HwidIdentityConfig {
            enabled: true,
            hwid: "0123456789abcdef0123".into(),
            os_version: "12".into(),
            device_model: "Infinix X669D".into(),
            locale: "ru-RU".into(),
        };
        let h_on = build_happ_headers(&on, 1_763_000_000);
        assert!(h_on
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("x-hwid") && v == "0123456789abcdef0123"));
        assert!(h_on
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("x-device-model") && v == "Infinix X669D"));

        let hdrs = vec![
            ("profile-title".into(), "base64:VGVzdCBQcm9maWxl".into()),
            (
                "subscription-userinfo".into(),
                "upload=1073741824; download=2147483648; total=10737418240; expire=1900000000"
                    .into(),
            ),
            ("profile-update-interval".into(), "12".into()),
            ("support-url".into(), "https://t.me/support_example".into()),
            ("announce".into(), "base64:V2VsY29tZSE=".into()),
        ];
        let body = b"vless://11111111-1111-1111-1111-111111111111@198.51.100.10:443?security=reality&sni=www.microsoft.com&pbk=m0R_t5s8x2A1b3C4d5E6f7G8h9I0j1K2l3M4n5O6p7Q&fp=chrome#DE-1\n";
        let env = parse_subscription_envelope(
            "https://panel.example.com/s/tok",
            &hdrs,
            body,
            false,
            "crypt5",
            1_763_000_000,
        );
        assert_eq!(env.title, "Test Profile");
        assert_eq!(env.update_interval_hours, 12);
        assert_eq!(env.total_bytes, 10_737_418_240);
        assert_eq!(env.upload_bytes + env.download_bytes, 3_221_225_472);
        assert_eq!(env.support_url, "https://t.me/support_example");
        assert_eq!(env.announce, "Welcome!");
        assert_eq!(env.share_links.len(), 1);
    }

    #[test]
    fn test_v16_protocol_extensions_and_xray_json_import() {
        let pin = "a".repeat(64);
        let uri = format!(
            "vless://11111111-1111-1111-1111-111111111111@91.215.43.20:443?encryption=none&security=tls&sni=cdn.example.com&type=ws&path=%2Fws%3Fed%3D2048&pcs={pin}&vcn=cdn.example.com#WS-ED"
        );
        let c = parse_share_uri_to_candidate(&uri, "AUTO", 0, true).expect("ws+ed+pcs should parse");
        let s = c.outbound_json.to_string();
        assert!(s.contains("/ws?ed=2048"), "missing ?ed=2048: {s}");
        assert!(s.contains(&pin), "missing pinnedPeerCertSha256: {s}");
        assert!(s.contains("verifyPeerCertByName"), "missing vcn: {s}");
        assert!(!s.contains("allowInsecure"), "must never emit allowInsecure: {s}");

        let xh_uri = "vless://11111111-1111-1111-1111-111111111111@91.215.43.21:443?security=reality&flow=xtls-rprx-vision&sni=vk.com&pbk=m0R_t5s8x2A1b3C4d5E6f7G8h9I0j1K2l3M4n5O6p7Q&pqv=mlDsaVerifyKey123&type=xhttp&mode=packet-up&path=%2Fapi&extra=%7B%22noGRPCHeader%22%3Atrue%7D#XHTTP-PQ";
        let xh = parse_share_uri_to_candidate(xh_uri, "AUTO", 0, false).expect("xhttp+pqv+extra");
        let xs = xh.outbound_json.to_string();
        assert!(xs.contains("mldsa65Verify"), "missing pqv: {xs}");
        assert!(xs.contains("xtls-rprx-vision"), "missing xhttp vision: {xs}");
        assert!(xs.contains("noGRPCHeader"), "missing xhttp extra: {xs}");

        let raw_json = serde_json::json!({
            "remarks": "🇩🇪 Frankfurt Custom JSON",
            "outbounds": [
                {
                    "tag": "proxy",
                    "protocol": "vless",
                    "settings": {
                        "vnext": [{
                            "address": "91.215.43.55",
                            "port": 443,
                            "users": [{"id": "22222222-2222-2222-2222-222222222222", "encryption": "none", "flow": "xtls-rprx-vision"}]
                        }]
                    },
                    "streamSettings": {
                        "network": "tcp",
                        "security": "reality",
                        "realitySettings": {
                            "serverName": "www.microsoft.com",
                            "publicKey": "m0R_t5s8x2A1b3C4d5E6f7G8h9I0j1K2l3M4n5O6p7Q",
                            "shortId": "01ab",
                            "fingerprint": "chrome"
                        }
                    }
                },
                {"tag": "direct", "protocol": "freedom"}
            ]
        });
        let imported = parse_xray_json_config_to_candidates(&raw_json, "Custom", "DE", 0);
        assert_eq!(imported.len(), 1);
        assert_eq!(imported[0].host, "91.215.43.55");
    }

    #[test]
    fn test_dual_channel_failover_and_strict_country_scoping() {
        let mk = |ip: &str, cc: &str, name: &str, rtt: u32| {
            let uri = format!(
                "vless://11111111-1111-1111-1111-111111111111@{ip}:443?security=reality&sni=www.microsoft.com&pbk=m0R_t5s8x2A1b3C4d5E6f7G8h9I0j1K2l3M4n5O6p7Q&fp=chrome#{name}"
            );
            let c = parse_share_uri_to_candidate(&uri, cc, 1, false).unwrap();
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            crate::sources::VerifiedVpnNode {
                id: c.id,
                name: name.into(),
                display_protocol: "VLESS Reality".into(),
                protocol: c.protocol,
                host: c.host,
                port: c.port,
                sni: c.sni,
                exit_country: cc.into(),
                exit_colo: "FRA".into(),
                exit_ip: ip.into(),
                rtt_ms: rtt,
                kbps: 2500,
                passed_32kb: true,
                whitelist_friendly: false,
                fragment_enabled: false,
                via_warp: false,
                device_verified: true,
                yt_ad_free: false,
                yt_country: cc.into(),
                source_tier: 1,
                verified_unix: now,
                fail_count: 0,
                ok_streak: 2,
                last_fail_unix: 0,
                raw_uri: c.raw_uri,
                outbound_json: c.outbound_json,
            }
        };
        let de1 = mk("91.215.43.1", "DE", "DE-1", 55);
        let de2 = mk("91.215.43.2", "DE", "DE-2", 68);
        let fi1 = mk("91.215.43.3", "FI", "FI-1", 32);
        let us1 = mk("91.215.43.4", "US", "US-1", 110);
        let all = vec![fi1.clone(), de1.clone(), de2.clone(), us1.clone()];

        // Strict country lock: DE must ONLY match DE, never faster FI or US!
        assert!(node_matches_strict_region(&de1, "DE", false));
        assert!(node_matches_strict_region(&de2, "DE", false));
        assert!(!node_matches_strict_region(&fi1, "DE", false));
        assert!(!node_matches_strict_region(&us1, "DE", false));
        assert!(node_matches_strict_region(&fi1, "AUTO", false));
        assert!(node_matches_strict_region(&us1, "AUTO", false));

        // 1) Strict DE mode with mixed [FI, DE1, DE2, US] pool:
        //    primary MUST be DE1, hot-standby MUST be DE2, and FI/US must NOT leak into vpn_main!
        let plan_de = build_production_tun_config_v16(
            &all,
            None,
            "DE",
            false,
            true,
            true,
            true,
            true,
            false,
            10808,
            Some(("vlx_user", "vlx_secret_pass")),
            None,
        )
        .expect("DE dual-channel plan");
        assert_eq!(plan_de.primary.exit_country, "DE");
        assert_eq!(plan_de.primary.id, de1.id);
        assert!(plan_de.dual_channel_active);
        let st_de = plan_de.standby.as_ref().expect("DE standby must exist");
        assert_eq!(st_de.exit_country, "DE");
        assert_eq!(st_de.id, de2.id);

        let cfg: serde_json::Value = serde_json::from_str(&plan_de.config_json).unwrap();
        let bals = cfg["routing"]["balancers"].as_array().unwrap();
        let main_bal = bals.iter().find(|b| b["tag"] == "vpn_main").unwrap();
        assert_eq!(main_bal["selector"][0], "vpn_0");
        assert_eq!(main_bal["fallbackTag"], "vpn_1");
        assert_eq!(main_bal["strategy"]["type"], "random");
        assert_eq!(cfg["observatory"]["probeInterval"], "90s");
        let socks_in = cfg["inbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|i| i["tag"] == "local-socks")
            .unwrap();
        assert_eq!(socks_in["settings"]["auth"], "password");
        assert_eq!(socks_in["settings"]["accounts"][0]["user"], "vlx_user");

        // 2) Single DE node with [FI, DE1, US] pool: primary=DE1, standby=None (NEVER leaks FI/US!)
        let plan_single_de = build_production_tun_config_v16(
            &[fi1.clone(), de1.clone(), us1.clone()],
            None,
            "DE",
            false,
            true,
            true,
            true,
            true,
            false,
            10808,
            None,
            None,
        )
        .expect("single DE plan");
        assert_eq!(plan_single_de.primary.exit_country, "DE");
        assert!(
            plan_single_de.standby.is_none(),
            "single DE node must NOT leak foreign standby!"
        );

        // 3) AUTO mode: picks best global primary (FI-1) + best distinct global standby (DE-1),
        //    and idle_power_save=true switches observatory to 180s!
        let plan_auto = build_production_tun_config_v16(
            &all,
            None,
            "AUTO",
            false,
            true,
            true,
            true,
            true,
            true,
            10808,
            Some(("u", "p")),
            None,
        )
        .expect("AUTO dual-channel plan");
        assert_eq!(plan_auto.primary.id, fi1.id);
        assert_eq!(plan_auto.standby.as_ref().unwrap().id, de1.id);
        let ci: serde_json::Value = serde_json::from_str(&plan_auto.config_json).unwrap();
        assert_eq!(ci["observatory"]["probeInterval"], "180s");
    }

    #[test]
    fn test_diag_secret_redaction() {
        let s1 = crate::diag::redact_url_for_log("https://admin.example.site/s/SuperSecretToken123");
        let s2 = crate::diag::redact_url_for_log("happ://crypt5/ABCDEF1234567890");
        assert!(!s1.contains("SuperSecretToken123"), "leaked sub token: {s1}");
        assert!(s1.contains("admin.example.site"), "should keep host: {s1}");
        assert!(!s2.contains("ABCDEF1234567890"), "leaked crypt5: {s2}");
    }

    #[test]
    fn test_v17_zero_ru_and_standby_priority_same_country_then_de_us() {
        use crate::sources::is_pure_russia_exit_remark;
        use crate::store::{filter_nodes_for_region, normalize_region};
        use crate::xray_config::{
            build_production_tun_config_v17, parse_share_uri_to_candidate, CustomDomainRules,
        };

        assert_eq!(normalize_region("RU"), "DE");
        assert_eq!(normalize_region("PT"), "PT");
        assert_eq!(normalize_region("HU"), "HU");
        assert!(is_pure_russia_exit_remark("🇷🇺 Россия #1"));
        assert!(is_pure_russia_exit_remark("Moscow VDS"));
        assert!(!is_pure_russia_exit_remark("🇷🇺 WL -> 🇩🇪 Germany"));
        assert!(!is_pure_russia_exit_remark("🇩🇪 Frankfurt Reality"));
        assert!(!is_pure_russia_exit_remark("🇺🇸 USA New York"));

        let mk = |ip: &str, cc: &str, name: &str, rtt: u32, yt_free: bool| {
            let uri = format!(
                "vless://11111111-1111-1111-1111-111111111111@{ip}:443?security=reality&sni=www.microsoft.com&pbk=m0R_t5s8x2A1b3C4d5E6f7G8h9I0j1K2l3M4n5O6p7Q&fp=chrome#{name}"
            );
            let c = parse_share_uri_to_candidate(&uri, cc, 1, false).unwrap();
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            crate::sources::VerifiedVpnNode {
                id: c.id,
                name: name.into(),
                display_protocol: "VLESS Reality".into(),
                protocol: c.protocol,
                host: c.host,
                port: c.port,
                sni: c.sni,
                exit_country: cc.into(),
                exit_colo: "FRA".into(),
                exit_ip: ip.into(),
                rtt_ms: rtt,
                kbps: 4500,
                passed_32kb: true,
                whitelist_friendly: false,
                fragment_enabled: false,
                via_warp: false,
                device_verified: true,
                yt_ad_free: yt_free,
                yt_country: if yt_free { "RU".into() } else { cc.into() },
                source_tier: 1,
                verified_unix: now,
                fail_count: 0,
                ok_streak: 3,
                last_fail_unix: 0,
                raw_uri: c.raw_uri,
                outbound_json: c.outbound_json,
            }
        };

        let ru_bad = mk("185.10.10.1", "RU", "RU-MustDrop", 10, true);
        let nl_pri = mk("185.20.20.1", "NL", "NL-Primary", 45, false);
        let nl_same_subnet = mk("185.20.20.99", "NL", "NL-Same24", 46, false);
        let nl_distinct = mk("94.142.241.10", "NL", "NL-Distinct", 130, false);
        let se_fast = mk("193.138.218.5", "SE", "SE-UltraFast", 22, false);
        let de_res = mk("88.198.10.20", "DE", "DE-Reserve", 95, false);
        let us_res = mk("64.225.80.30", "US", "US-Reserve", 155, false);

        // Zero-RU check: filter & planner must completely eliminate RU nodes (including yt_pool!)
        let filtered = filter_nodes_for_region(
            &[
                ru_bad.clone(),
                nl_pri.clone(),
                nl_same_subnet.clone(),
                nl_distinct.clone(),
                se_fast.clone(),
                de_res.clone(),
                us_res.clone(),
            ],
            "AUTO",
            false,
        );
        assert!(
            filtered.iter().all(|n| n.exit_country != "RU"),
            "RU node leaked into filtered pool!"
        );
        // AUTO mode boosts DE/US ahead of non-DE/US nodes!
        assert!(
            matches!(filtered[0].exit_country.as_str(), "DE" | "US"),
            "DE/US should rank #1 in AUTO mode, got {}",
            filtered[0].exit_country
        );

        // Case A: Pinned NL primary with distinct NL + same-/24 NL + faster SE + DE + US
        // -> #1 standby MUST be `nl_distinct` (same_country AND distinct /24 subnet)!
        let pool_a = vec![
            ru_bad.clone(),
            nl_pri.clone(),
            nl_same_subnet.clone(),
            nl_distinct.clone(),
            se_fast.clone(),
            de_res.clone(),
            us_res.clone(),
        ];
        let plan_a = build_production_tun_config_v17(
            &pool_a,
            Some(&nl_pri.id),
            "AUTO",
            false,
            true,
            true,
            true,
            true,
            false,
            10808,
            Some(("u", "p")),
            None,
            None,
        )
        .expect("plan A");
        assert_eq!(plan_a.primary.id, nl_pri.id);
        let sb_a = plan_a.standby.expect("standby A");
        assert_eq!(
            sb_a.id, nl_distinct.id,
            "Expected distinct same-country NL standby, got {} ({})",
            sb_a.name, sb_a.exit_country
        );
        assert_eq!(plan_a.standby_tier, "same_country");
        assert!(!plan_a.config_json.contains("185.10.10.1"), "RU IP leaked into Xray JSON!");

        // Case B: Pinned NL primary with NO second NL, plus fast SE (22ms) + DE (95ms) + US (155ms)
        // -> #2 standby priority MUST pick DE (priority country DE/US) over 22ms SE!
        let pool_b = vec![ru_bad.clone(), nl_pri.clone(), se_fast.clone(), de_res.clone(), us_res.clone()];
        let plan_b = build_production_tun_config_v17(
            &pool_b,
            Some(&nl_pri.id),
            "AUTO",
            false,
            true,
            true,
            true,
            true,
            false,
            10808,
            Some(("u", "p")),
            None,
            None,
        )
        .expect("plan B");
        let sb_b = plan_b.standby.expect("standby B");
        assert_eq!(sb_b.id, de_res.id);
        assert_eq!(plan_b.standby_tier, "de_us");

        // Case C: Pinned NL primary with NO NL, NO DE, plus fast SE (22ms) + US (155ms)
        // -> #2 standby priority MUST pick US over 22ms SE!
        let pool_c = vec![nl_pri.clone(), se_fast.clone(), us_res.clone()];
        let plan_c = build_production_tun_config_v17(
            &pool_c,
            Some(&nl_pri.id),
            "AUTO",
            false,
            true,
            true,
            true,
            true,
            false,
            10808,
            Some(("u", "p")),
            None,
            None,
        )
        .expect("plan C");
        assert_eq!(plan_c.standby.unwrap().id, us_res.id);
        assert_eq!(plan_c.standby_tier, "de_us");

        // Case D: Pinned DE primary with DE-2 + US -> picks DE-2 (`same_country`) before US!
        let de_2 = mk("116.203.50.60", "DE", "DE-Second", 110, false);
        let plan_d = build_production_tun_config_v17(
            &[de_res.clone(), us_res.clone(), de_2.clone(), se_fast.clone()],
            Some(&de_res.id),
            "AUTO",
            false,
            true,
            true,
            true,
            true,
            false,
            10808,
            Some(("u", "p")),
            None,
            None,
        )
        .expect("plan D");
        assert_eq!(plan_d.standby.unwrap().id, de_2.id);
        assert_eq!(plan_d.standby_tier, "same_country");

        // Case E: Custom domain rules + TCP anti-drop keepalives + DNS <= 8 invariant
        let rules = CustomDomainRules::from_json_str(
            r#"{"vpn":["https://MyService.Example.com/api","*.ai-lab.org"],"direct":["mybank.local.ru","localhost"],"block":["full:tracker.bad.example"]}"#,
        );
        assert_eq!(rules.vpn.len(), 2);
        assert_eq!(rules.direct.len(), 1); // localhost rejected safely
        assert_eq!(rules.block.len(), 1);
        let plan_e = build_production_tun_config_v17(
            &[de_res.clone(), us_res.clone()],
            None,
            "AUTO",
            false,
            true,
            true,
            true,
            true,
            false,
            10808,
            Some(("u", "p")),
            None,
            Some(&rules),
        )
        .expect("plan E");
        let cfg: serde_json::Value = serde_json::from_str(&plan_e.config_json).unwrap();
        let dns_servers = cfg["dns"]["servers"].as_array().unwrap();
        assert!(dns_servers.len() <= 8, "dns.servers exceeded 8: {}", dns_servers.len());
        let vpn0 = cfg["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["tag"] == "vpn_0")
            .unwrap();
        assert_eq!(vpn0["streamSettings"]["sockopt"]["tcpKeepAliveIdle"], 28);
        assert_eq!(vpn0["streamSettings"]["sockopt"]["tcpKeepAliveInterval"], 15);
        assert_eq!(vpn0["streamSettings"]["sockopt"]["tcpUserTimeout"], 15000);
        let rstr = serde_json::to_string(&cfg["routing"]["rules"]).unwrap();
        assert!(rstr.contains("domain:myservice.example.com"));
        assert!(rstr.contains("domain:ai-lab.org"));
        assert!(rstr.contains("domain:mybank.local.ru"));
        assert!(rstr.contains("full:tracker.bad.example"));
        assert!(rstr.contains("domain:cursor.com"));
        assert!(rstr.contains("domain:claude.ai"));
        assert!(rstr.contains("domain:rutracker.org"));
    }
}

