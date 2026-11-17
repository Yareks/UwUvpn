//! Dynamic subscription sources, Base64/plain decoder, URI parser, deduplicator, and priority scorer.

use crate::diag::{diag_info, diag_ok, diag_warn};
use crate::net_util::{fetch_subscription_smart, fetch_text_resilient, fetch_text_resilient_tagged};
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::Instant;
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubSource {
    pub name: String,
    pub url: String,
    pub kind: String,        // "vpn" or "tg"
    pub region_hint: String, // "US", "DE", "AUTO", "WHITELIST", "TG", "TG_SOCKS"
    pub enabled: bool,
    pub builtin: bool,
    /// Optional human-readable expiry / quota parsed from `subscription-userinfo`.
    #[serde(default)]
    pub userinfo: String,
    /// Number of valid unique keys/proxies parsed on last sync.
    #[serde(default)]
    pub cached_count: u32,
    /// Unix timestamp of last successful sync.
    #[serde(default)]
    pub last_sync_unix: u64,
    /// Short SHA-256 content hash for smart incremental delta sync (skip redundant re-installs).
    #[serde(default)]
    pub content_hash: String,
    /// Cached normalized URIs for user's custom subscriptions (`!builtin`), capped to 120 items.
    #[serde(default)]
    pub cached_uris: Vec<String>,
}

fn builtin_src(name: &str, url: &str, kind: &str, region_hint: &str) -> SubSource {
    SubSource {
        name: name.into(),
        url: url.into(),
        kind: kind.into(),
        region_hint: region_hint.into(),
        enabled: true,
        builtin: true,
        userinfo: String::new(),
        cached_count: 0,
        last_sync_unix: 0,
        content_hash: String::new(),
        cached_uris: Vec::new(),
    }
}

/// 38 live-verified, actively auto-updated free sources (every GitHub URL includes Gcore/jsDelivr/Codeberg
/// CDN failover): 7 dedicated Russian Mobile Whitelist (Минцифры SNI + VK/Yandex/CDN CIDR), 16 US/DE/Global
/// Reality/XHTTP/SS2022/Trojan/Hysteria2 feeds, and 15 Russia-verified Telegram MTProto FakeTLS & SOCKS5 feeds.
pub fn default_sources() -> Vec<SubSource> {
    vec![
        // --- VPN: Белые списки РФ (Минцифры SNI + VK Cloud / Yandex Cloud / CDNvideo CIDR) ---
        builtin_src(
            "БС РФ · Auto-Checked (Минцифры SNI)",
            "https://raw.githubusercontent.com/u23jd9/russia-whitelist-vpn/main/whitelist_raw.txt",
            "vpn",
            "WHITELIST",
        ),
        builtin_src(
            "БС РФ · CIDR VK/Yandex/CDN (Проверенные)",
            "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/WHITE-CIDR-RU-checked.txt",
            "vpn",
            "WHITELIST",
        ),
        builtin_src(
            "БС РФ · Моб. ТОП-150 (Auto 1h)",
            "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
            "vpn",
            "WHITELIST",
        ),
        builtin_src(
            "БС РФ · CIDR Полный пул",
            "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/WHITE-CIDR-RU-all.txt",
            "vpn",
            "WHITELIST",
        ),
        builtin_src(
            "БС РФ · Zieng2 XHTTP & Reality",
            "https://raw.githubusercontent.com/zieng2/wl/main/vless_universal.txt",
            "vpn",
            "WHITELIST",
        ),
        builtin_src(
            "БС РФ · Zieng2 Lite Моб.",
            "https://raw.githubusercontent.com/zieng2/wl/main/vless_lite.txt",
            "vpn",
            "WHITELIST",
        ),
        builtin_src(
            "РФ Моб. · VLESS Reality 150",
            "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS_mobile.txt",
            "vpn",
            "WHITELIST",
        ),
        // --- VPN: Germany (DE) Dedicated ---
        builtin_src(
            "0xRadikal · Germany (Auto 15m)",
            "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/Countries/Germany.txt",
            "vpn",
            "DE",
        ),
        builtin_src(
            "SoliSpirit · Germany DE Pool",
            "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Countries/Germany.txt",
            "vpn",
            "DE",
        ),
        builtin_src(
            "Argh94 · Germany VLESS/Reality",
            "https://raw.githubusercontent.com/Argh94/V2RayAutoConfig/main/configs/Germany.txt",
            "vpn",
            "DE",
        ),
        // --- VPN: United States (US) Dedicated ---
        builtin_src(
            "0xRadikal · United States (Auto 15m)",
            "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/Countries/United_States.txt",
            "vpn",
            "US",
        ),
        builtin_src(
            "SoliSpirit · United States US Pool",
            "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Countries/United_States.txt",
            "vpn",
            "US",
        ),
        builtin_src(
            "Argh94 · USA VLESS/Reality",
            "https://raw.githubusercontent.com/Argh94/V2RayAutoConfig/main/configs/USA.txt",
            "vpn",
            "US",
        ),
        // --- VPN: Multi-Region SS2022 / Trojan / Reality / XHTTP / Hysteria2 (Direct + MASQUE-Chain) ---
        builtin_src(
            "0xRadikal · SS2022 & AEAD (Auto 15m)",
            "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/protocols/shadowsocks.txt",
            "vpn",
            "AUTO",
        ),
        builtin_src(
            "SoliSpirit · SS2022 & AEAD (US/DE)",
            "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Protocols/ss.txt",
            "vpn",
            "AUTO",
        ),
        builtin_src(
            "Barry-Far · SS2022 & AEAD (DE/US)",
            "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Splitted-By-Protocol/ss.txt",
            "vpn",
            "AUTO",
        ),
        builtin_src(
            "0xRadikal · Trojan TLS (Auto 15m)",
            "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/protocols/trojan.txt",
            "vpn",
            "AUTO",
        ),
        builtin_src(
            "SoliSpirit · Trojan TLS (US/DE)",
            "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Protocols/trojan.txt",
            "vpn",
            "AUTO",
        ),
        builtin_src(
            "РФ · SS2022/Trojan/Hy2 Проверенные",
            "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_SS+All_RUS.txt",
            "vpn",
            "AUTO",
        ),
        builtin_src(
            "РФ · VLESS Reality Пул",
            "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS.txt",
            "vpn",
            "AUTO",
        ),
        builtin_src(
            "Barry-Far · VLESS XHTTP & Reality",
            "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Splitted-By-Protocol/vless.txt",
            "vpn",
            "AUTO",
        ),
        builtin_src(
            "Pure REALITY Curated Feed",
            "https://raw.githubusercontent.com/Mosifree/-FREE2CONFIG/main/Reality",
            "vpn",
            "AUTO",
        ),
        builtin_src(
            "0xRadikal · Hysteria2 QUIC (Auto 15m)",
            "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/protocols/hysteria2.txt",
            "vpn",
            "AUTO",
        ),
        builtin_src(
            "Argh94 · Hysteria2 QUIC Pool",
            "https://raw.githubusercontent.com/Argh94/V2RayAutoConfig/main/configs/Hysteria2.txt",
            "vpn",
            "AUTO",
        ),
        builtin_src(
            "0xRadikal · Top-100 Verified",
            "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/top100.txt",
            "vpn",
            "AUTO",
        ),
        // --- Telegram: Russia-Checked & DC-Verified MTProto Fake-TLS (ee), Secure (dd) & SOCKS5 (Calls) ---
        builtin_src(
            "ВнеСписка · TG Проверено из РФ (15м)",
            "https://vnespiska.win/api/proxies-ru.json",
            "tg",
            "TG",
        ),
        builtin_src(
            "TG РФ VPS · Проверено из России (2ч)",
            "https://raw.githubusercontent.com/Chumbayoumba/free-telegram-proxy-russia-2026/main/proxy-list.txt",
            "tg",
            "TG",
        ),
        builtin_src(
            "MTProto Pro · Fake-TLS 443 для РФ",
            "https://zakky8.github.io/mtproto-proxy-pro/censorship_resistant.txt",
            "tg",
            "TG",
        ),
        builtin_src(
            "TG Fake-TLS (ee) · Авто 15м",
            "https://raw.githubusercontent.com/0xRadikal/Free-Telegram-Proxy/main/faketls/tg.txt",
            "tg",
            "TG",
        ),
        builtin_src(
            "TG Fast Top-25% · Авто 15м",
            "https://raw.githubusercontent.com/0xRadikal/Free-Telegram-Proxy/main/fast/tg.txt",
            "tg",
            "TG",
        ),
        builtin_src(
            "TG Stable 90%+ Uptime · Авто 15м",
            "https://raw.githubusercontent.com/0xRadikal/Free-Telegram-Proxy/main/stable/tg.txt",
            "tg",
            "TG",
        ),
        builtin_src(
            "TG Финляндия · Низкий пинг РФ",
            "https://raw.githubusercontent.com/0xRadikal/Free-Telegram-Proxy/main/countries/FI.txt",
            "tg",
            "TG",
        ),
        builtin_src(
            "TG Нидерланды · Прямой DC2",
            "https://raw.githubusercontent.com/0xRadikal/Free-Telegram-Proxy/main/countries/NL.txt",
            "tg",
            "TG",
        ),
        builtin_src(
            "TG Германия · Авто 15м",
            "https://raw.githubusercontent.com/0xRadikal/Free-Telegram-Proxy/main/countries/DE.txt",
            "tg",
            "TG",
        ),
        builtin_src(
            "TG Top-100 DC-Checked (15м)",
            "https://raw.githubusercontent.com/0xRadikal/Free-Telegram-Proxy/main/top100.txt",
            "tg",
            "TG",
        ),
        builtin_src(
            "TG Secure (dd) · Авто 15м",
            "https://raw.githubusercontent.com/0xRadikal/Free-Telegram-Proxy/main/secure/tg.txt",
            "tg",
            "TG",
        ),
        builtin_src(
            "SoliSpirit · MTProto Verified",
            "https://raw.githubusercontent.com/SoliSpirit/mtproto/master/all_proxies.txt",
            "tg",
            "TG",
        ),
        builtin_src(
            "TGMTProxy · Обновление каждый час",
            "https://raw.githubusercontent.com/tgmtproxy/telegram-mtproto-proxy-list/main/proxies.txt",
            "tg",
            "TG",
        ),
        builtin_src(
            "Monosans SOCKS5 (TG + Звонки)",
            "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
            "tg",
            "TG_SOCKS",
        ),
        builtin_src(
            "0xRadikal SOCKS5 (TG + Звонки)",
            "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/protocols/socks.txt",
            "tg",
            "TG_SOCKS",
        ),
        builtin_src(
            "TheSpeedX SOCKS5 (TG + Звонки)",
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
            "tg",
            "TG_SOCKS",
        ),
    ]
}

/// Exact Tier-A 2026 Russian Минцифры mobile-internet carrier white-list domains
/// (МТС, МегаФон, Билайн, Т2, Ростелеком regional whitelist allowlists).
const RU_WHITELIST_SNI_KEYWORDS: &[&str] = &[
    "yandex",
    "ya.ru",
    "yastatic",
    "kinopoisk",
    "dzen.ru",
    "vk.com",
    "vk.ru",
    "userapi",
    "vkuser",
    "vkcloud",
    "mycdn.me",
    "ok.ru",
    "okcdn.ru",
    "mail.ru",
    "imgsmail",
    "max.ru",
    "oneme.ru",
    "ozon.ru",
    "ozone.ru",
    "ozonusercontent",
    "wb.ru",
    "wildberries",
    "wbbasket",
    "gosuslugi",
    "gu-st.ru",
    "mos.ru",
    "nalog.ru",
    "sber",
    "tbank.ru",
    "tinkoff",
    "alfabank",
    "vtb.ru",
    "nspk.ru",
    "mirpay",
    "rzd.ru",
    "pochta.ru",
    "rutube",
    "rtbcdn",
    "avito",
    "kaspersky",
    "drweb",
    "2gis",
    "1c.ru",
    "rostelecom",
    "rt.ru",
    "mts.ru",
    "megafon",
    "beeline",
    "t2.ru",
    "tele2.ru",
    "selectel",
    "selcdn",
    "timeweb",
    "reg.ru",
    "edgecenter",
    "cdnvideo",
    "qrator",
    "ddos-guard",
    "hh.ru",
    "rbc.ru",
    "ria.ru",
    "lenta.ru",
    "kp.ru",
    "pikabu.ru",
    "gismeteo",
];

/// Domains blocked or actively throttled/16KB-capped by Russian RKN/TSPU — NEVER pick as outer SNI!
const RF_BLOCKED_SNI_KEYWORDS: &[&str] = &[
    "cloudflare.com",
    "cloudflare-dns.com",
    "cloudflareinsights.com",
    "workers.dev",
    "pages.dev",
    "discord.com",
    "discord.gg",
    "discordapp.com",
    "discord.media",
    "youtube.com",
    "googlevideo.com",
    "ytimg.com",
    "youtu.be",
    "instagram.com",
    "cdninstagram.com",
    "facebook.com",
    "fbcdn.net",
    "twitter.com",
    "twimg.com",
    "t.co",
    "proton.me",
    "protonvpn.com",
    "protonmail.com",
    "torproject.org",
    "rutracker.org",
    "medium.com",
    "patreon.com",
    "linkedin.com",
    "quora.com",
    "canva.com",
    "chatgpt.com",
    "openai.com",
    "ntc.party",
    "amnezia.org",
];

/// Proven globally clean corporate/CDN SNIs that pass RF TSPU cleanly.
const RF_CLEAN_SNI_KEYWORDS: &[&str] = &[
    "microsoft.com",
    "windowsupdate.com",
    "live.com",
    "office.com",
    "apple.com",
    "icloud.com",
    "mzstatic.com",
    "cdn-apple.com",
    "samsung.com",
    "amd.com",
    "nvidia.com",
    "intel.com",
    "yahoo.com",
    "dl.google.com",
    "addons.mozilla.org",
    "mozilla.org",
    "github.com",
    "aws.amazon.com",
    "oracle.com",
    "cisco.com",
    "hp.com",
    "lenovo.com",
    "logitech.com",
    "lovelive-anime.jp",
    "tradingview.com",
    "steamcommunity.com",
    "steampowered.com",
    "worldoftanks.com",
    "worldoftanks.eu",
    "wargaming.net",
    "akamai",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnCandidate {
    pub id: String,
    pub raw_uri: String,
    pub name: String,
    pub protocol: String,   // "vless", "hysteria2", "trojan", "shadowsocks", "vmess", "opera", "warp-masque", "warp-wg"
    pub transport: String,  // "tcp", "xhttp", "grpc", "ws", "httpupgrade", "quic", "masque-h3", "masque-h2", "wg", "https"
    pub security: String,   // "reality", "tls", "quic", "wg", "none"
    pub sni: String,
    pub host: String,
    pub port: u16,
    pub region_hint: String, // "US", "DE", "OTHER"
    pub whitelist_friendly: bool,
    #[serde(default)]
    pub fragment_enabled: bool,
    /// TRUE when dialed through Cloudflare WARP MASQUE (`dialerProxy: "warp_bridge"`) to bypass
    /// Russian ISP TSPU & RKN IP blocks while exiting in genuine USA (`US`) or Germany (`DE`)!
    #[serde(default)]
    pub via_warp: bool,
    pub priority_score: i32,
    pub outbound_json: serde_json::Value,
    pub source_tier: u8, // 0=User, 1=VLESS/Hy2/Trojan/SS, 2=Opera, 3=WARP foreign, 4=WARP local anti-TSPU
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedVpnNode {
    pub id: String,
    pub name: String,
    pub display_protocol: String, // e.g. "Opera HTTPS + MASQUE", "Trojan TLS + MASQUE", "VLESS Reality"
    pub protocol: String,
    pub host: String,
    pub port: u16,
    pub sni: String,
    pub exit_country: String, // REAL verified ISO-2 (e.g. "US", "DE", "NL", or "CF" for WARP local)
    pub exit_colo: String,    // Edge colo (e.g. "FRA", "IAD", "AMS")
    pub exit_ip: String,      // REAL exit IP
    pub rtt_ms: u32,          // Real full-tunnel HTTPS RTT
    pub kbps: u32,            // Measured throughput during ≥32KB anti-16KB verification
    pub passed_32kb: bool,    // Passed anti-16KB TSPU freeze test
    pub whitelist_friendly: bool,
    #[serde(default)]
    pub fragment_enabled: bool,
    /// TRUE when tunneled over Cloudflare WARP MASQUE 1st hop -> genuine US/DE 2nd hop!
    #[serde(default)]
    pub via_warp: bool,
    /// TRUE when verified LIVE on this Android device/ISP; FALSE for bundled `bootstrap_seed.json`!
    #[serde(default)]
    pub device_verified: bool,
    pub source_tier: u8,
    pub raw_uri: String,
    pub outbound_json: serde_json::Value,
    pub verified_unix: u64,
    pub fail_count: u32,
}

/// Try decoding a whole subscription body if it is Base64-encoded; otherwise return as-is.
pub fn decode_subscription_body(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.contains("://") || trimmed.contains('\n') && trimmed.lines().any(|l| l.contains("://") || l.starts_with('#')) {
        return trimmed.to_string();
    }
    let compact: String = trimmed.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    if compact.len() >= 24 {
        for engine in [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD] {
            if let Ok(bytes) = engine.decode(&compact) {
                if let Ok(s) = String::from_utf8(bytes) {
                    if s.contains("://") {
                        return s;
                    }
                }
            }
        }
    }
    trimmed.to_string()
}

pub fn decode_b64_flexible(s: &str) -> Option<Vec<u8>> {
    let clean: String = s.trim().chars().filter(|c| !c.is_ascii_whitespace()).collect();
    let unpadded = clean.trim_end_matches('=');
    STANDARD
        .decode(&clean)
        .or_else(|_| URL_SAFE.decode(&clean))
        .or_else(|_| STANDARD_NO_PAD.decode(unpadded))
        .or_else(|_| URL_SAFE_NO_PAD.decode(unpadded))
        .ok()
}

/// Short content fingerprint for incremental delta sync (no wasted re-installs when unchanged).
pub fn content_hash_short(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    hex::encode(&h.finalize()[..8])
}

/// Unwrap VPN client subscription deep-links (`happ://add/...`, `v2raytun://import/...`,
/// `v2rayng://install-config?url=...`, `hiddify://import/...`, `streisand://import/...`,
/// `sing-box://import-remote-profile?url=...`, `clash://install-config?url=...`, `ssconf://...`)
/// into a clean fetchable `https://` or `http://` URL.
pub fn unwrap_subscription_url(raw: &str) -> Option<String> {
    let t = raw.trim();
    if t.starts_with("https://") || t.starts_with("http://") {
        // Ignore Telegram proxy share links — handled as TG proxies
        if t.starts_with("https://t.me/proxy") || t.starts_with("https://t.me/socks") {
            return None;
        }
        return Some(t.to_string());
    }
    if let Some(rest) = t.strip_prefix("ssconf://") {
        return Some(format!("https://{rest}"));
    }
    for prefix in [
        "happ://add/",
        "v2raytun://import/",
        "v2raytun://import-sub?url=",
        "hiddify://import/",
        "streisand://import/",
        "flclash://install-config?url=",
    ] {
        if let Some(rest) = t.strip_prefix(prefix) {
            let cut = rest.split('#').next().unwrap_or(rest).trim();
            let dec = percent_decode_str(cut).decode_utf8_lossy().trim().to_string();
            if dec.starts_with("https://") || dec.starts_with("http://") {
                return Some(dec);
            }
        }
    }
    if let Ok(u) = Url::parse(t) {
        if matches!(
            u.scheme(),
            "v2rayng" | "clash" | "sing-box" | "hiddify" | "v2raytun" | "happ" | "nekobox" | "karing"
        ) {
            for (k, v) in u.query_pairs() {
                if k.eq_ignore_ascii_case("url") || k.eq_ignore_ascii_case("sub") {
                    let sv = v.trim().to_string();
                    if sv.starts_with("https://") || sv.starts_with("http://") {
                        return Some(sv);
                    }
                }
            }
        }
    }
    None
}

/// Extract clean share URIs from any decoded subscription payload (Base64 list, plain text,
/// Remnawave/Marzban/3x-ui/Happ/Shuka lists, or embedded links). Skips dummy banner placeholders!
pub fn extract_vpn_uris_from_subscription(raw_body: &str, max_items: usize) -> Vec<String> {
    let decoded = decode_subscription_body(raw_body);
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for line in decoded.lines() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') || l.starts_with("//") {
            continue;
        }
        if !(l.starts_with("vless://")
            || l.starts_with("vmess://")
            || l.starts_with("trojan://")
            || l.starts_with("ss://")
            || l.starts_with("hy2://")
            || l.starts_with("hysteria2://"))
        {
            continue;
        }
        if is_dummy_banner_uri(l) {
            continue;
        }
        // Verify URI parses into a valid strict Xray outbound
        if crate::xray_config::parse_share_uri_to_candidate(l, "AUTO", 0, false).is_some()
            && seen.insert(l.to_string())
        {
            out.push(l.to_string());
            if out.len() >= max_items {
                break;
            }
        }
    }
    out
}

/// Detect non-functional info/expiry banner lines commonly injected at the top of subscriptions
/// (e.g. `vless://00000000-0000-0000-0000-000000000000@app.deprecated:443?...#ОСТАЛОСЬ ДНЕЙ`).
pub fn is_dummy_banner_uri(uri: &str) -> bool {
    let low = uri.to_ascii_lowercase();
    low.contains("00000000-0000-0000-0000-000000000000")
        || low.contains("@app.deprecated")
        || low.contains("@127.0.0.1")
        || low.contains("@0.0.0.0")
        || low.contains("@localhost")
        || low.contains("@1.1.1.1:")
        || low.contains("@8.8.8.8:")
}

/// Exact Tier-A 2026 Минцифры RF mobile carrier whitelist SNI match.
pub fn is_tier_a_whitelist_sni(sni: &str) -> bool {
    let low = sni.trim().to_ascii_lowercase();
    !low.is_empty() && RU_WHITELIST_SNI_KEYWORDS.iter().any(|kw| low.contains(kw))
}

pub fn is_whitelist_sni(sni: &str) -> bool {
    let low = sni.trim().to_ascii_lowercase();
    low.ends_with(".ru")
        || low.ends_with(".su")
        || low.ends_with(".xn--p1ai")
        || is_tier_a_whitelist_sni(&low)
}

/// Detect explicit Russian mobile-whitelist / whitelisted-CIDR tags in server remark/name
/// (e.g. `🇩🇪 Белые списки`, `🇫🇮 Белые списки`, `[*CIDR] VK`, `[*CIDR] YA`, `[Apex (БС)]`).
pub fn is_whitelist_remark(remark: &str) -> bool {
    let low = remark.to_lowercase();
    low.contains("белые списки")
        || low.contains("белый список")
        || low.contains("обход бс")
        || low.contains("(бс)")
        || low.contains("[бс]")
        || low.contains("[*cidr]")
        || low.contains("[cidr]")
        || low.contains("whitelist")
        || low.contains("white list")
        || low.contains("wl-рф")
}

/// Returns true if `sni` is known to be blocked, RST-injected, or 16KB-capped by RF RKN/TSPU.
pub fn is_rf_blocked_sni(sni: &str) -> bool {
    let low = sni.trim().to_ascii_lowercase();
    if low.is_empty() {
        return false;
    }
    if low == "x.com" || low.ends_with(".x.com") {
        return true;
    }
    RF_BLOCKED_SNI_KEYWORDS.iter().any(|kw| low.contains(kw))
}

pub fn is_rf_clean_sni(sni: &str) -> bool {
    let low = sni.to_ascii_lowercase();
    RF_CLEAN_SNI_KEYWORDS.iter().any(|kw| low.contains(kw))
}

pub fn detect_region_hint(remark: &str, host: &str, source_hint: &str) -> String {
    if source_hint == "US" || source_hint == "DE" {
        return source_hint.to_string();
    }
    let r = remark.to_lowercase();
    let h = host.to_lowercase();
    if remark.contains("🇺🇸")
        || r.contains("united states")
        || r.contains("america")
        || r.contains("сша")
        || r.contains(" usa")
        || r.starts_with("us ")
        || r.starts_with("us-")
        || r.starts_with("us_")
        || r.contains("[us]")
        || r.contains("(us)")
        || r.contains("ashburn")
        || r.contains("dallas")
        || r.contains("new york")
        || r.contains("los angeles")
        || r.contains("virginia")
        || r.contains("chicago")
        || r.contains("seattle")
        || r.contains("miami")
        || r.contains("silicon")
        || r.contains("atlanta")
        || h.contains(".us.")
        || h.starts_with("us.")
        || h.starts_with("us-")
        || h.starts_with("us1")
        || h.starts_with("us2")
    {
        return "US".to_string();
    }
    if remark.contains("🇩🇪")
        || r.contains("germany")
        || r.contains("deutschland")
        || r.contains("frankfurt")
        || r.contains("falkenstein")
        || r.contains("nuremberg")
        || r.contains("hetzner")
        || r.contains("герман")
        || r.starts_with("de ")
        || r.starts_with("de-")
        || r.starts_with("de_")
        || r.contains("[de]")
        || r.contains("(de)")
        || h.contains(".de.")
        || h.contains("fra")
    {
        return "DE".to_string();
    }
    "OTHER".to_string()
}

/// Clean remark label for display in UI.
pub fn clean_remark(raw_frag: &str, fallback: &str) -> String {
    let decoded = percent_decode_str(raw_frag).decode_utf8_lossy().into_owned();
    let cleaned: String = decoded
        .chars()
        .filter(|c| !c.is_control())
        .take(48)
        .collect::<String>()
        .trim()
        .to_string();
    if cleaned.is_empty() {
        fallback.to_string()
    } else {
        cleaned
    }
}

/// Check if an IP/host is obviously bogus (loopback, private, documentation, wildcard).
pub fn is_valid_public_host(host: &str, port: u16) -> bool {
    if port == 0 || host.is_empty() || host.len() > 253 {
        return false;
    }
    let h = host.trim_matches(|c| c == '[' || c == ']');
    if h.contains(char::is_whitespace)
        || h == "localhost"
        || h.eq_ignore_ascii_case("app.deprecated")
        || h.ends_with(".local")
        || h.ends_with(".example")
        || h.ends_with(".deprecated")
        || h.ends_with(".invalid")
    {
        return false;
    }
    if let Ok(ip) = h.parse::<std::net::IpAddr>() {
        return match ip {
            std::net::IpAddr::V4(v4) => {
                let o = v4.octets();
                !v4.is_private()
                    && !v4.is_loopback()
                    && !v4.is_link_local()
                    && !v4.is_broadcast()
                    && !v4.is_unspecified()
                    && !v4.is_documentation()
                    && o[0] != 0
                    && o[0] < 224
                    && !(o[0] == 100 && (64..=127).contains(&o[1]))
                    && !(o[0] == 198 && (o[1] == 18 || o[1] == 19))
            }
            std::net::IpAddr::V6(v6) => {
                // Prefer IPv4 on Android mobile networks unless well-formed global unicast
                !v6.is_loopback() && !v6.is_unspecified() && (v6.segments()[0] & 0xe000) == 0x2000
            }
        };
    }
    h.contains('.')
}

/// Fetch all relevant VPN subscriptions concurrently, decode, parse into validated `VpnCandidate`s,
/// deduplicate, and rank for `target_region` ("US", "DE", or "AUTO") and `whitelist_mode`.
pub async fn fetch_vpn_candidates(
    sources: &[SubSource],
    target_region: &str,
    whitelist_mode: bool,
    fragment_tls: bool,
    socks5_proxy: Option<SocketAddr>,
    blacklist: &HashSet<String>,
) -> Vec<VpnCandidate> {
    let selected: Vec<SubSource> = sources
        .iter()
        .filter(|s| {
            if !s.enabled || s.kind != "vpn" {
                return false;
            }
            if !s.builtin {
                return true; // Always fetch user's own subscriptions first!
            }
            if whitelist_mode {
                // In Белые списки РФ mode, load ALL 7 dedicated RF Whitelist/CIDR feeds + target region
                return matches!(s.region_hint.as_str(), "WHITELIST")
                    || s.region_hint == target_region
                    || s.url.contains("shadowsocks.txt")
                    || s.url.contains("BLACK_SS+All_RUS");
            }
            match target_region {
                "US" => matches!(s.region_hint.as_str(), "US" | "AUTO" | "WHITELIST"),
                "DE" => matches!(s.region_hint.as_str(), "DE" | "AUTO" | "WHITELIST"),
                _ => true,
            }
        })
        .cloned()
        .collect();

    let total_sources = selected.len();
    let mut handles = Vec::new();
    for src in selected {
        handles.push(tokio::spawn(async move {
            let t0 = Instant::now();
            // Custom user subscriptions MUST use VPN-client User-Agent (`v2rayNG/1.9.30` / `Happ`)
            // so Remnawave/Shuka/Marzban/3x-ui/Happ return Base64 keys instead of HTML portals!
            let res: Result<(String, String), String> = if !src.builtin {
                match fetch_subscription_smart(&src.url, socks5_proxy, 768 * 1024).await {
                    Ok(sub) => Ok((sub.body, sub.via_tag)),
                    Err(_e) if !src.cached_uris.is_empty() => {
                        Ok((src.cached_uris.join("\n"), "cache".to_string()))
                    }
                    Err(e) => Err(e),
                }
            } else {
                // Limit each public feed to 640 KiB so mobile LTE completes all feeds in ~2.2s
                fetch_text_resilient_tagged(&src.url, socks5_proxy, 640 * 1024)
                    .await
                    .map(|(b, tag)| (b, tag.to_string()))
            };
            (src, res, t0.elapsed().as_millis() as u32)
        }));
    }

    let mut seen_ep = HashSet::new();
    let mut candidates = Vec::new();
    let mut ok_feeds = 0usize;
    let mut fail_feeds = 0usize;
    let mut skipped_blocked_sni = 0usize;
    let mut reality_idx = 0usize;

    for h in handles {
        let Ok((src, res, elapsed_ms)) = h.await else {
            fail_feeds += 1;
            continue;
        };
        let (body, mirror) = match res {
            Ok(v) => {
                ok_feeds += 1;
                v
            }
            Err(err) => {
                fail_feeds += 1;
                diag_warn(
                    "SRC",
                    format!("{} -> ошибка ({elapsed_ms}мс): {err}", src.name),
                );
                continue;
            }
        };

        let decoded = decode_subscription_body(&body);
        let tier = if src.builtin { 1 } else { 0 };
        // Cap parsed lines per huge feed so one 3,000-line file doesn't drown curated feeds
        let mut per_src = 0usize;
        for line in decoded.lines() {
            let l = line.trim();
            if l.is_empty() || l.starts_with('#') || l.starts_with("//") || is_dummy_banner_uri(l) {
                continue;
            }
            if per_src >= 520 {
                break;
            }
            // Alternate fragment_tls on REALITY servers (keeps Tier-0 user subscription Reality
            // pure uTLS Vision by default for maximum speed & compatibility!)
            let is_reality_line = l.contains("security=reality");
            let use_frag = if !fragment_tls {
                false
            } else if tier == 0 && is_reality_line {
                false
            } else if is_reality_line {
                reality_idx += 1;
                reality_idx % 2 == 0
            } else {
                true
            };

            if let Some(mut cand) = crate::xray_config::parse_share_uri_to_candidate(
                l,
                &src.region_hint,
                tier,
                use_frag,
            ) {
                // Skip IPv6-only hosts (often unavailable on RF LTE)
                if cand.host.contains(':') {
                    continue;
                }
                // Filter out RKN/TSPU-blocked outer SNIs (e.g. www.cloudflare.com, discord.com, youtube.com)
                if tier != 0 && is_rf_blocked_sni(&cand.sni) {
                    skipped_blocked_sni += 1;
                    continue;
                }

                // Mark Russian Whitelist / Whitelisted-CIDR candidates (VK Cloud / Yandex Cloud / CDNvideo / Минцифры SNI)
                let is_wl_feed = src.region_hint == "WHITELIST";
                let is_wl_tag = is_whitelist_remark(&cand.name);
                let is_tier_a_wl = is_tier_a_whitelist_sni(&cand.sni);
                if (is_wl_feed || is_wl_tag) && !is_rf_blocked_sni(&cand.sni) {
                    cand.whitelist_friendly = true;
                }

                let ep_key = format!("{}:{}", cand.host.to_ascii_lowercase(), cand.port);
                if tier != 0 && blacklist.contains(&ep_key) {
                    continue;
                }
                // Deduplicate by endpoint+transport (allow distinct custom sub items)
                let dedup_key = if tier == 0 {
                    format!(
                        "custom:{}:{}:{}:{}:{}",
                        cand.host.to_ascii_lowercase(),
                        cand.port,
                        cand.protocol,
                        cand.transport,
                        cand.sni.to_ascii_lowercase()
                    )
                } else {
                    format!(
                        "{}:{}:{}:{}",
                        cand.host.to_ascii_lowercase(),
                        cand.port,
                        cand.protocol,
                        cand.transport
                    )
                };
                if !seen_ep.insert(dedup_key) {
                    continue;
                }

                // Boost RF-resilient transports & clean SNIs
                if cand.transport == "xhttp" {
                    cand.priority_score += 40; // XHTTP split-HTTP excels against RF TSPU & WL
                } else if cand.protocol == "hysteria2" {
                    cand.priority_score += 28;
                } else if cand.transport == "grpc" && cand.security == "reality" {
                    cand.priority_score += 24;
                }
                if is_rf_clean_sni(&cand.sni) {
                    cand.priority_score += 22;
                }
                if is_tier_a_wl {
                    cand.priority_score += 48; // Минцифры SNI (yandex.ru, vk.com, wb.ru, rutube.ru, tbank.ru)
                } else if cand.whitelist_friendly {
                    cand.priority_score += 32;
                }
                if cand.port == 443 || cand.port == 8443 || cand.port == 2053 {
                    cand.priority_score += 12;
                }

                // Adjust score for user's target region & mobile whitelist preference
                match target_region {
                    "US" if cand.region_hint == "US" => cand.priority_score += 80,
                    "US" if cand.region_hint == "DE" => cand.priority_score -= 20,
                    "DE" if cand.region_hint == "DE" => cand.priority_score += 80,
                    "DE" if cand.region_hint == "US" => cand.priority_score -= 20,
                    _ => {
                        if cand.region_hint == "DE" || cand.region_hint == "US" {
                            cand.priority_score += 55;
                        }
                    }
                }
                if whitelist_mode {
                    if is_tier_a_wl {
                        cand.priority_score += 210; // #1: Exact Минцифры SNI (yandex/vk/rutube/wb/tbank/ozon/sber)
                    } else if src.url.contains("WHITE-CIDR-RU-checked")
                        || src.url.contains("russia-whitelist-vpn")
                        || is_wl_tag
                    {
                        cand.priority_score += 185; // #2: Verified VK/Yandex/CDN CIDR bridge & explicit БС tag
                    } else if cand.whitelist_friendly {
                        cand.priority_score += 145; // #3: .ru SNI & RF Mobile Whitelist feeds
                    } else {
                        cand.priority_score -= 60;
                    }
                    if cand.transport == "xhttp" || cand.transport == "grpc" {
                        cand.priority_score += 35;
                    }
                    if cand.security == "reality" {
                        cand.priority_score += 45;
                    }
                }
                if cand.source_tier == 0 {
                    cand.priority_score += 280; // User's own subscriptions & keys ALWAYS rank #0!
                }

                candidates.push(cand);
                per_src += 1;
            }
        }

        if per_src > 0 {
            diag_ok(
                "SRC",
                format!(
                    "{} [{mirror}, {elapsed_ms}мс] -> +{per_src} узлов",
                    src.name
                ),
            );
        }
    }

    let xhttp_n = candidates.iter().filter(|c| c.transport == "xhttp").count();
    let real_n = candidates.iter().filter(|c| c.security == "reality").count();
    let hy2_n = candidates.iter().filter(|c| c.protocol == "hysteria2").count();
    let tr_n = candidates.iter().filter(|c| c.protocol == "trojan").count();
    let ss_n = candidates.iter().filter(|c| c.protocol == "shadowsocks").count();
    let wl_n = candidates.iter().filter(|c| c.whitelist_friendly).count();
    diag_info(
        "SRC",
        format!(
            "Источники: {ok_feeds}/{total_sources} OK (сбой: {fail_feeds}) · уникальных: {} (Reality:{real_n}, XHTTP:{xhttp_n}, Hy2:{hy2_n}, Trojan:{tr_n}, SS:{ss_n}, WL-РФ:{wl_n}, отсеяно SNI:{skipped_blocked_sni})",
            candidates.len()
        ),
    );

    candidates.sort_by(|a, b| b.priority_score.cmp(&a.priority_score));
    candidates
}

/// Optional remote manifest JSON structure for dynamic over-the-air source updates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteManifest {
    pub version: u32,
    #[serde(default)]
    pub sources: Vec<SubSource>,
    #[serde(default)]
    pub extra_vless: Vec<String>,
    #[serde(default)]
    pub extra_tg: Vec<String>,
}

pub async fn fetch_remote_manifest(
    manifest_url: &str,
    socks5_proxy: Option<SocketAddr>,
) -> Result<RemoteManifest, String> {
    let u = Url::parse(manifest_url).map_err(|e| e.to_string())?;
    if u.scheme() != "https" {
        return Err("manifest must use https://".to_string());
    }
    let body = fetch_text_resilient(manifest_url, socks5_proxy, 256 * 1024).await?;
    serde_json::from_str::<RemoteManifest>(&body).map_err(|e| format!("manifest json: {e}"))
}
