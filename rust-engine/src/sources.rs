//! Dynamic subscription sources, Base64/plain decoder, URI parser, deduplicator, and priority scorer.

use crate::diag::{diag_info, diag_ok, diag_warn};
use crate::net_util::{fetch_text_resilient, fetch_text_resilient_tagged};
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::Instant;
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
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
    /// Structured quota & Happ/Remnawave/Marzban subscription metadata (v1.6.0).
    #[serde(default)]
    pub upload_bytes: u64,
    #[serde(default)]
    pub download_bytes: u64,
    #[serde(default)]
    pub total_bytes: u64,
    #[serde(default)]
    pub expire_unix: u64,
    #[serde(default)]
    pub update_interval_hours: u32,
    #[serde(default)]
    pub announce: String,
    #[serde(default)]
    pub support_url: String,
    #[serde(default)]
    pub web_page_url: String,
    #[serde(default)]
    pub hwid_status: String,
    /// `"crypt"`, `"crypt2"`, `"crypt3"`, `"crypt4"`, `"crypt5"`, `"incy-crypt1"`, or `""`.
    #[serde(default)]
    pub encrypted_kind: String,
    /// True if server delivered an AES-128-GCM body-encrypted Happ payload (`Encrypt-Tag`).
    #[serde(default)]
    pub body_encrypted: bool,
    #[serde(default)]
    pub prefer_happ_ua: bool,
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
    /// Cached raw Xray JSON outbounds for JSON-format Happ/Remnawave subscriptions, capped to 64 items.
    #[serde(default)]
    pub cached_json_outbounds: Vec<serde_json::Value>,
}

fn builtin_src(name: &str, url: &str, kind: &str, region_hint: &str) -> SubSource {
    SubSource {
        name: name.into(),
        url: url.into(),
        kind: kind.into(),
        region_hint: region_hint.into(),
        enabled: true,
        builtin: true,
        ..Default::default()
    }
}

/// 96 live-verified, actively auto-updated free sources (every GitHub URL includes Gcore/jsDelivr/Codeberg
/// CDN failover): 79 VPN feeds (including 7 dedicated Russian Mobile Whitelist — Минцифры SNI + VK/Yandex/CDN
/// CIDR — plus US/DE/Global Reality/XHTTP/SS2022/Trojan/Hysteria2/VLESS feeds) and 17 Telegram MTProto/SOCKS5 feeds.
pub fn default_sources() -> Vec<SubSource> {
    vec![
        // --- VPN: Белые списки РФ (Минцифры SNI + VK Cloud / Yandex Cloud / CDNvideo CIDR) ---
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
        builtin_src(
            "Peasoft · NoMoreWalls (DE/US/EU Reality+Hy2)",
            "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list_raw.txt",
            "vpn",
            "DE",
        ),
        builtin_src(
            "MatinGhanbari · Filtered VLESS/Reality (DE/US)",
            "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/vless.txt",
            "vpn",
            "DE",
        ),
        builtin_src(
            "MatinGhanbari · Filtered Hysteria2 (DE/US)",
            "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/hysteria2.txt",
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
        builtin_src(
            "Roosterkid · OpenProxyList (US/DE VLESS)",
            "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt",
            "vpn",
            "US",
        ),
        builtin_src(
            "Kwinshadow · VLESS Verified (DE/US/EU)",
            "https://raw.githubusercontent.com/Kwinshadow/TelegramV2rayCollector/main/sublinks/vless.txt",
            "vpn",
            "US",
        ),
        builtin_src(
            "Danialsamadi · VLESS Reality Pool (DE/US)",
            "https://raw.githubusercontent.com/Danialsamadi/v2go/main/Splitted-By-Protocol/vless.txt",
            "vpn",
            "DE",
        ),
        // --- VPN: Extra European & Ad-Free YouTube Countries (NL, FI, GB, FR, SE, CH, AT, CZ, IT, ES, CA, MD) ---
        builtin_src(
            "Argh94 · Netherlands NL Pool",
            "https://raw.githubusercontent.com/Argh94/V2RayAutoConfig/main/configs/Netherlands.txt",
            "vpn",
            "NL",
        ),
        builtin_src(
            "Argh94 · Finland FI Pool",
            "https://raw.githubusercontent.com/Argh94/V2RayAutoConfig/main/configs/Finland.txt",
            "vpn",
            "FI",
        ),
        builtin_src(
            "Argh94 · United Kingdom GB Pool",
            "https://raw.githubusercontent.com/Argh94/V2RayAutoConfig/main/configs/UK.txt",
            "vpn",
            "GB",
        ),
        builtin_src(
            "Argh94 · Sweden SE Pool",
            "https://raw.githubusercontent.com/Argh94/V2RayAutoConfig/main/configs/Sweden.txt",
            "vpn",
            "SE",
        ),
        builtin_src(
            "Argh94 · Switzerland CH Pool",
            "https://raw.githubusercontent.com/Argh94/V2RayAutoConfig/main/configs/Switzerland.txt",
            "vpn",
            "CH",
        ),
        builtin_src(
            "Argh94 · Austria AT Pool",
            "https://raw.githubusercontent.com/Argh94/V2RayAutoConfig/main/configs/Austria.txt",
            "vpn",
            "AT",
        ),
        builtin_src(
            "SoliSpirit · Czechia CZ Pool",
            "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Countries/Czechia.txt",
            "vpn",
            "CZ",
        ),
        builtin_src(
            "SoliSpirit · Italy IT Pool",
            "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Countries/Italy.txt",
            "vpn",
            "IT",
        ),
        builtin_src(
            "SoliSpirit · Spain ES Pool",
            "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Countries/Spain.txt",
            "vpn",
            "ES",
        ),
        builtin_src(
            "SoliSpirit · Moldova MD (YT 0% Ads)",
            "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Countries/Moldova.txt",
            "vpn",
            "MD",
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
        // --- Multi-Protocol Curated Pools (Hysteria2 QUIC, VLESS Reality/XHTTP/WS/gRPC, Trojan, VMess, SS2022, SOCKS5) ---
        builtin_src(
            "MatinGhanbari · Hysteria2 QUIC",
            "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/hysteria2.txt",
            "vpn",
            "HY2",
        ),
        builtin_src(
            "MatinGhanbari · VLESS Filtered",
            "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/vless.txt",
            "vpn",
            "AUTO",
        ),
        builtin_src(
            "MatinGhanbari · Trojan TLS",
            "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/trojan.txt",
            "vpn",
            "AUTO",
        ),
        builtin_src(
            "MatinGhanbari · Shadowsocks AEAD/2022",
            "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/ss.txt",
            "vpn",
            "AUTO",
        ),
        builtin_src(
            "NoMoreWalls · VLESS + Hy2 + Trojan + VMess",
            "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list_raw.txt",
            "vpn",
            "MULTI",
        ),
        builtin_src(
            "Ermaozi · Multi-Protocol (Hy2 + Reality + VMess)",
            "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
            "vpn",
            "MULTI",
        ),
        builtin_src(
            "OpenProxyList · Verified VLESS/Trojan/SS",
            "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt",
            "vpn",
            "MULTI",
        ),
        builtin_src(
            "Barry-Far · VMess TLS Pool",
            "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Splitted-By-Protocol/vmess.txt",
            "vpn",
            "MULTI",
        ),
        builtin_src(
            "Pawdroid · Curated Free Nodes",
            "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
            "vpn",
            "MULTI",
        ),
        // --- Нидерланды (NL · Амстердам AMS — топ скорость и YouTube 4K) ---
        builtin_src(
            "Argh94 · Нидерланды (AMS)",
            "https://raw.githubusercontent.com/Argh94/V2RayAutoConfig/main/configs/Netherlands.txt",
            "vpn",
            "NL",
        ),
        builtin_src(
            "SoliSpirit · Нидерланды",
            "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Countries/Netherlands.txt",
            "vpn",
            "NL",
        ),
        // --- Финляндия (FI · Хельсинки HEL — минимальный пинг 15–35 мс!) ---
        builtin_src(
            "0xRadikal · Финляндия (HEL)",
            "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/Countries/Finland.txt",
            "vpn",
            "FI",
        ),
        builtin_src(
            "SoliSpirit · Финляндия",
            "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Countries/Finland.txt",
            "vpn",
            "FI",
        ),
        builtin_src(
            "Argh94 · Финляндия",
            "https://raw.githubusercontent.com/Argh94/V2RayAutoConfig/main/configs/Finland.txt",
            "vpn",
            "FI",
        ),
        // --- Великобритания (GB · Лондон LHR) ---
        builtin_src(
            "0xRadikal · Великобритания (LHR)",
            "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/Countries/United_Kingdom.txt",
            "vpn",
            "GB",
        ),
        builtin_src(
            "SoliSpirit · Великобритания",
            "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Countries/United_Kingdom.txt",
            "vpn",
            "GB",
        ),
        builtin_src(
            "Argh94 · Великобритания",
            "https://raw.githubusercontent.com/Argh94/V2RayAutoConfig/main/configs/UK.txt",
            "vpn",
            "GB",
        ),
        // --- Франция (FR · Париж CDG) ---
        builtin_src(
            "0xRadikal · Франция (CDG)",
            "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/Countries/France.txt",
            "vpn",
            "FR",
        ),
        builtin_src(
            "SoliSpirit · Франция",
            "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Countries/France.txt",
            "vpn",
            "FR",
        ),
        // --- Швеция (SE · Стокгольм ARN — низкий пинг!) ---
        builtin_src(
            "0xRadikal · Швеция (ARN)",
            "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/Countries/Sweden.txt",
            "vpn",
            "SE",
        ),
        builtin_src(
            "SoliSpirit · Швеция",
            "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Countries/Sweden.txt",
            "vpn",
            "SE",
        ),
        // --- Польша (PL · Варшава WAW) ---
        builtin_src(
            "0xRadikal · Польша (WAW)",
            "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/Countries/Poland.txt",
            "vpn",
            "PL",
        ),
        builtin_src(
            "SoliSpirit · Польша",
            "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Countries/Poland.txt",
            "vpn",
            "PL",
        ),
        // --- Швейцария (CH · Цюрих ZRH) и Австрия (AT · Вена VIE) ---
        builtin_src(
            "0xRadikal · Швейцария (ZRH)",
            "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/Countries/Switzerland.txt",
            "vpn",
            "CH",
        ),
        builtin_src(
            "SoliSpirit · Швейцария",
            "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Countries/Switzerland.txt",
            "vpn",
            "CH",
        ),
        builtin_src(
            "0xRadikal · Австрия (VIE)",
            "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/Countries/Austria.txt",
            "vpn",
            "CH",
        ),
        // --- Турция (TR · Стамбул IST — игры, подписки, сервисы) ---
        builtin_src(
            "0xRadikal · Турция (IST)",
            "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/Countries/Turkey.txt",
            "vpn",
            "TR",
        ),
        builtin_src(
            "Argh94 · Турция (Hy2 + VLESS)",
            "https://raw.githubusercontent.com/Argh94/V2RayAutoConfig/main/configs/Turkey.txt",
            "vpn",
            "TR",
        ),
        // --- Япония (JP · Токио NRT) и Сингапур (SG · SIN) ---
        builtin_src(
            "0xRadikal · Япония (NRT)",
            "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/Countries/Japan.txt",
            "vpn",
            "JP",
        ),
        builtin_src(
            "SoliSpirit · Япония",
            "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Countries/Japan.txt",
            "vpn",
            "JP",
        ),
        builtin_src(
            "0xRadikal · Сингапур (SIN)",
            "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/Countries/Singapore.txt",
            "vpn",
            "SG",
        ),
        builtin_src(
            "SoliSpirit · Сингапур",
            "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Countries/Singapore.txt",
            "vpn",
            "SG",
        ),
        // --- Канада (CA · Торонто/Монреаль YYZ) ---
        builtin_src(
            "0xRadikal · Канада (YYZ)",
            "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/Countries/Canada.txt",
            "vpn",
            "CA",
        ),
        builtin_src(
            "SoliSpirit · Канада",
            "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Countries/Canada.txt",
            "vpn",
            "CA",
        ),
        // --- YouTube без рекламы (0% прероллов/мидроллов: Албания AL, Молдова MD, Армения AM, EU GL=RU) ---
        builtin_src(
            "YT No-Ads · Албания (0% рекламы)",
            "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Countries/Albania.txt",
            "vpn",
            "YT",
        ),
        builtin_src(
            "YT No-Ads · Молдова (0% рекламы)",
            "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Countries/Moldova.txt",
            "vpn",
            "YT",
        ),
        builtin_src(
            "YT No-Ads · Армения (0% рекламы)",
            "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Countries/Armenia.txt",
            "vpn",
            "YT",
        ),
        builtin_src(
            "YT No-Ads · Казахстан & СНГ",
            "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Countries/Kazakhstan.txt",
            "vpn",
            "YT",
        ),
        builtin_src(
            "YT No-Ads · Беларусь & EU",
            "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Countries/Belarus.txt",
            "vpn",
            "YT",
        ),
        builtin_src(
            "YT No-Ads · Люксембург & EU",
            "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Countries/Luxembourg.txt",
            "vpn",
            "YT",
        ),
        builtin_src(
            "YT No-Ads · Kobabi Fast EU (GL=RU/MD)",
            "https://raw.githubusercontent.com/liketolivefree/kobabi/main/sub.txt",
            "vpn",
            "YT",
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
            "ALIILAPRO · MTProto Fake-TLS Pool",
            "https://raw.githubusercontent.com/ALIILAPRO/MTProtoProxy/main/mtproto.txt",
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
    /// TRUE when Google's own YouTube geo (`sw.js_data`) returns a 0%-monetized country (`AL`, `MD`,
    /// `RU` on foreign VPS, `MC`, `AD`, `AM`, `BY`, `MN`, `MM`, `UZ`, `KG`, `TJ`, `TM`) on a fast
    /// non-RU exit — guarantees 0% pre-roll/mid-roll/Shorts/Music ads in official YouTube app & web!
    #[serde(default)]
    pub yt_ad_free: bool,
    /// Exact ISO-2 country code detected by Google YouTube (`sw.js_data`), e.g. `"AL"`, `"MD"`, `"RU"`.
    #[serde(default)]
    pub yt_country: String,
    pub source_tier: u8,
    pub raw_uri: String,
    pub outbound_json: serde_json::Value,
    pub verified_unix: u64,
    pub fail_count: u32,
    /// Consecutive successful tunnel sessions & health checks (capped at 20) — rewards stable,
    /// zero-drop servers over erratic ones!
    #[serde(default)]
    pub ok_streak: u16,
    /// Unix timestamp of the most recent failure — prevents bouncing right back onto a flapping host!
    #[serde(default)]
    pub last_fail_unix: u64,
}

/// Returns `true` when a server remark explicitly declares a domestic Russian exit (`🇷🇺 Россия`,
/// `🇷🇺 Москва`, `🇷🇺 СПб`, `Russia Moscow`) WITHOUT naming any foreign destination country or
/// whitelist relay bridge. Domestic Russian exits defeat the purpose of a VPN (we are replacing a
/// Russian IP!), whereas RU-entry -> DE/US/NL/FI relay bridges are kept and verified by real exit GeoIP!
pub fn is_pure_russia_exit_remark(name: &str) -> bool {
    let t = name.trim();
    if t.is_empty() {
        return false;
    }
    let low = t.to_lowercase();
    let mentions_foreign = [
        "🇩🇪", "🇺🇸", "🇳🇱", "🇫🇮", "🇬🇧", "🇫🇷", "🇸🇪", "🇳🇴", "🇩🇰", "🇨🇭", "🇦🇹", "🇵🇱", "🇨🇿",
        "🇮🇹", "🇪🇸", "🇵🇹", "🇪🇪", "🇱🇻", "🇱🇹", "🇮🇪", "🇧🇪", "🇱🇺", "🇦🇱", "🇲🇩", "🇹🇷", "🇯🇵",
        "🇸🇬", "🇨🇦", "🇰🇷", "🇭🇰", "🇰🇿", "🇦🇪", "🇦🇲", "🇭🇺", "🇷🇴", "🇧🇬",
        "герман", "germany", "frankfurt", "франкфурт", "сша", "usa", "united states",
        "нидерланд", "netherlands", "amsterdam", "амстердам", "финлянд", "finland", "helsinki",
        "британ", "london", "франц", "france", "paris", "швец", "sweden", "польш", "poland",
        "швейцар", "switzerland", "австри", "austria", "турци", "turkey", "япони", "japan",
        "сингапур", "singapore", "канад", "canada", "албан", "albania", "молдов", "moldova",
        "казах", "чехи", "итал", "испан", "латви", "эстон", "литв",
    ]
    .iter()
    .any(|kw| t.contains(kw) || low.contains(kw));
    if mentions_foreign {
        return false;
    }
    // Keep genuine mobile whitelist bridges ("обход бс", "whitelist", "белые списки", "relay")
    // so the live SOCKS prober checks their REAL exit country (keeps DE/US/NL/FI, drops RU!).
    let is_wl_bridge = [
        "бс", "белые списк", "белый спис", "whitelist", "white-list", "обход", "relay", "мост",
        "bridge", "cascade", "каскад",
    ]
    .iter()
    .any(|kw| low.contains(kw));
    if is_wl_bridge {
        return false;
    }
    [
        "🇷🇺",
        "россия",
        "россии",
        "russia",
        "moscow",
        "москва",
        "санкт-петербург",
        "петербург",
        "spb ",
        " spb",
        "novosibirsk",
        "новосибирск",
        "ekaterinburg",
        "екатеринбург",
    ]
    .iter()
    .any(|kw| t.contains(kw) || low.contains(kw))
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

/// Unwrap & offline-decrypt any VPN client subscription URL or encrypted deep-link:
/// `happ://crypt/...` .. `happ://crypt5/...`, `https://.../happ://crypt5/...`, `incy://crypt1/...`,
/// `happ://add/...`, `v2raytun://import/...`, `v2rayng://...`, `hiddify://import/...`,
/// `streisand://import/...`, `sing-box://import-remote-profile?url=...`, `clash://...`, `ssconf://...`.
pub fn unwrap_subscription_url(raw: &str) -> Option<String> {
    if let Some(Ok(unw)) = crate::happ_compat::unwrap_or_decrypt_subscription(raw) {
        return Some(unw.full_url);
    }
    None
}

/// Convert a standard WireGuard / AmneziaWG INI configuration (`[Interface]` + `[Peer]`) into a
/// canonical `wireguard://` share URI so users can paste raw `.conf` files directly!
pub fn convert_wg_conf_to_uri(text: &str) -> Option<String> {
    if !text.contains("[Interface]") || !text.contains("[Peer]") {
        return None;
    }
    let mut priv_key = String::new();
    let mut pub_key = String::new();
    let mut psk = String::new();
    let mut address = String::new();
    let mut endpoint = String::new();
    let mut mtu = String::new();
    let mut section = "";

    for raw_line in text.lines() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = if line.eq_ignore_ascii_case("[interface]") {
                "iface"
            } else if line.eq_ignore_ascii_case("[peer]") {
                "peer"
            } else {
                ""
            };
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let key = k.trim().to_ascii_lowercase();
        let val = v.trim();
        match (section, key.as_str()) {
            ("iface", "privatekey") => priv_key = val.to_string(),
            ("iface", "address") => address = val.replace(' ', ""),
            ("iface", "mtu") => mtu = val.to_string(),
            ("peer", "publickey") => pub_key = val.to_string(),
            ("peer", "presharedkey") => psk = val.to_string(),
            ("peer", "endpoint") => endpoint = val.to_string(),
            _ => {}
        }
    }
    if priv_key.is_empty() || pub_key.is_empty() || endpoint.is_empty() {
        return None;
    }
    let enc_priv: String = url::form_urlencoded::byte_serialize(priv_key.as_bytes()).collect();
    let mut ser = url::form_urlencoded::Serializer::new(String::new());
    ser.append_pair("publickey", &pub_key);
    if !address.is_empty() {
        ser.append_pair("address", &address);
    }
    if !psk.is_empty() {
        ser.append_pair("presharedkey", &psk);
    }
    if !mtu.is_empty() {
        ser.append_pair("mtu", &mtu);
    }
    let q = ser.finish();
    Some(format!("wireguard://{enc_priv}@{endpoint}?{q}#WireGuard"))
}

/// Extract clean share URIs from any decoded subscription payload (Base64 list, plain text,
/// Remnawave/Marzban/3x-ui/Happ/Shuka lists, WireGuard `.conf`, SOCKS5/HTTPS proxies).
pub fn extract_vpn_uris_from_subscription(raw_body: &str, max_items: usize) -> Vec<String> {
    let decoded = decode_subscription_body(raw_body);
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    if let Some(wg_uri) = convert_wg_conf_to_uri(&decoded) {
        if crate::xray_config::parse_share_uri_to_candidate(&wg_uri, "AUTO", 0, false).is_some()
            && seen.insert(wg_uri.clone())
        {
            out.push(wg_uri);
        }
    }
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
            || l.starts_with("hysteria2://")
            || l.starts_with("wireguard://")
            || l.starts_with("wg://")
            || l.starts_with("socks5://")
            || l.starts_with("socks://")
            || (l.starts_with("https://") && l.contains('@')))
        {
            continue;
        }
        if is_dummy_banner_uri(l) {
            continue;
        }
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
    if matches!(
        source_hint,
        "US" | "DE" | "NL" | "FI" | "GB" | "FR" | "SE" | "PL" | "CH" | "AT" | "TR" | "JP" | "SG" | "CA"
    ) {
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
        || r.contains("герман")
        || r.starts_with("de ")
        || r.starts_with("de-")
        || r.starts_with("de_")
        || r.contains("[de]")
        || r.contains("(de)")
        || h.contains(".de.")
        || h.starts_with("de.")
        || h.starts_with("de-")
    {
        return "DE".to_string();
    }
    for (flag, kws, cc) in [
        ("🇳🇱", &["netherlands", "amsterdam", "нидерланд", "голланди", "[nl]", "(nl)"][..], "NL"),
        ("🇫🇮", &["finland", "helsinki", "финлянд", "[fi]", "(fi)"][..], "FI"),
        ("🇬🇧", &["united kingdom", "london", "britain", "британи", "англи", "[gb]", "[uk]", "(uk)"][..], "GB"),
        ("🇫🇷", &["france", "paris", "франц", "[fr]", "(fr)"][..], "FR"),
        ("🇸🇪", &["sweden", "stockholm", "швеци", "[se]", "(se)"][..], "SE"),
        ("🇵🇱", &["poland", "warsaw", "польш", "[pl]", "(pl)"][..], "PL"),
        ("🇨🇭", &["switzerland", "zurich", "швейцар", "[ch]", "(ch)"][..], "CH"),
        ("🇦🇹", &["austria", "vienna", "австри", "[at]", "(at)"][..], "AT"),
        ("🇹🇷", &["turkey", "türkiye", "istanbul", "турци", "стамбул", "[tr]", "(tr)"][..], "TR"),
        ("🇯🇵", &["japan", "tokyo", "osaka", "япони", "[jp]", "(jp)"][..], "JP"),
        ("🇸🇬", &["singapore", "сингапур", "[sg]", "(sg)"][..], "SG"),
        ("🇨🇦", &["canada", "toronto", "montreal", "канад", "[ca]", "(ca)"][..], "CA"),
        ("🇰🇷", &["korea", "seoul", "коре", "[kr]", "(kr)"][..], "KR"),
        ("🇪🇪", &["estonia", "tallinn", "эстони", "[ee]"][..], "EE"),
        ("🇱🇻", &["latvia", "riga", "латви", "[lv]"][..], "LV"),
        ("🇨🇿", &["czech", "prague", "чехи", "[cz]"][..], "CZ"),
        ("🇮🇹", &["italy", "milan", "итали", "[it]"][..], "IT"),
        ("🇪🇸", &["spain", "madrid", "испани", "[es]"][..], "ES"),
        ("🇦🇱", &["albania", "tirana", "албани", "[al]", "(al)"][..], "AL"),
        ("🇲🇩", &["moldova", "chisinau", "молдов", "молдави", "[md]", "(md)"][..], "MD"),
        ("🇦🇲", &["armenia", "yerevan", "армени", "[am]", "(am)"][..], "AM"),
        ("🇱🇺", &["luxembourg", "люксембург", "[lu]", "(lu)"][..], "LU"),
        ("🇰🇿", &["kazakhstan", "almaty", "astana", "казахстан", "[kz]"][..], "KZ"),
        ("🇧🇾", &["belarus", "minsk", "беларус", "[by]"][..], "BY"),
        ("🇲🇨", &["monaco", "монако", "[mc]"][..], "MC"),
        ("🇳🇴", &["norway", "oslo", "норвег", "[no]"][..], "NO"),
        ("🇰🇿", &["kazakhstan", "almaty", "казахстан", "[kz]"][..], "KZ"),
    ] {
        if remark.contains(flag) || kws.iter().any(|kw| r.contains(kw)) {
            return cc.to_string();
        }
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
    let mut selected: Vec<SubSource> = Vec::new();
    // 1) Always fetch 100% of the user's own custom subscriptions first!
    for s in sources {
        if s.enabled && s.kind == "vpn" && !s.builtin {
            selected.push(s.clone());
        }
    }
    // 2) Smart selective feed router: picks the exact relevant country + protocol feeds (<= 20 per
    //    sweep) so RAM stays minimal while covering 14+ countries and all anti-DPI protocols!
    let want_wl = whitelist_mode || target_region == "WL";
    let builtins: Vec<&SubSource> = sources
        .iter()
        .filter(|s| s.enabled && s.kind == "vpn" && s.builtin)
        .filter(|s| {
            if want_wl {
                return s.region_hint == "WHITELIST"
                    || s.url.contains("shadowsocks.txt")
                    || s.url.contains("BLACK_SS+All_RUS");
            }
            match target_region {
                "US" => matches!(s.region_hint.as_str(), "US" | "CA" | "HY2" | "MULTI" | "AUTO"),
                "DE" => matches!(s.region_hint.as_str(), "DE" | "NL" | "HY2" | "MULTI" | "AUTO"),
                "NL" => matches!(s.region_hint.as_str(), "NL" | "DE" | "HY2" | "MULTI"),
                "FI" => matches!(s.region_hint.as_str(), "FI" | "SE" | "HY2" | "MULTI" | "WHITELIST"),
                "GB" => matches!(s.region_hint.as_str(), "GB" | "NL" | "HY2" | "MULTI"),
                "FR" => matches!(s.region_hint.as_str(), "FR" | "CH" | "NL" | "HY2" | "MULTI"),
                "SE" => matches!(s.region_hint.as_str(), "SE" | "FI" | "HY2" | "MULTI"),
                "PL" => matches!(s.region_hint.as_str(), "PL" | "DE" | "FI" | "HY2" | "MULTI"),
                "CH" => matches!(s.region_hint.as_str(), "CH" | "AT" | "DE" | "HY2" | "MULTI"),
                "TR" => matches!(s.region_hint.as_str(), "TR" | "HY2" | "MULTI" | "AUTO"),
                "JP" => matches!(s.region_hint.as_str(), "JP" | "SG" | "HY2" | "MULTI"),
                "SG" => matches!(s.region_hint.as_str(), "SG" | "JP" | "HY2" | "MULTI"),
                "CA" => matches!(s.region_hint.as_str(), "CA" | "US" | "HY2" | "MULTI"),
                "YT" | "AL" | "MD" => matches!(
                    s.region_hint.as_str(),
                    "YT" | "NL" | "FI" | "DE" | "SE" | "PL" | "WHITELIST"
                ),
                "EU" => matches!(
                    s.region_hint.as_str(),
                    "DE" | "NL" | "FI" | "GB" | "FR" | "SE" | "PL" | "CH" | "YT" | "HY2" | "MULTI"
                ),
                "WARP" => matches!(s.region_hint.as_str(), "DE" | "NL" | "FI" | "US" | "HY2"),
                // AUTO: balanced global diversity across FI, NL, DE, US, SE, GB, FR, PL, TR, SG, JP,
                // Ad-Free YouTube (AL/MD/EU-GL=RU), Russian Whitelist, Hy2, Reality, XHTTP, Trojan, VMess, SS2022!
                _ => {
                    s.region_hint == "HY2"
                        || s.region_hint == "MULTI"
                        || s.region_hint == "WHITELIST"
                        || s.region_hint == "YT"
                        || s.url.contains("0xRadikal/Free-v2ray-Configs/main/Countries/")
                        || s.url.contains("Argh94/V2RayAutoConfig/main/configs/Netherlands")
                        || s.url.contains("Argh94/V2RayAutoConfig/main/configs/Germany")
                        || s.url.contains("Argh94/V2RayAutoConfig/main/configs/USA")
                        || s.url.contains("Argh94/V2RayAutoConfig/main/configs/Hysteria2")
                        || s.url.contains("MatinGhanbari")
                        || s.url.contains("shadowsocks.txt")
                        || s.url.contains("top100.txt")
                        || s.url.contains("Splitted-By-Protocol/trojan")
                }
            }
        })
        .take(28)
        .collect();
    selected.extend(builtins.into_iter().cloned());

    let total_sources = selected.len();
    // Bounded 8-way feed download semaphore (prevents 28-socket TLS/DoH burst & cuts peak RAM by 60%!)
    let feed_sem = std::sync::Arc::new(tokio::sync::Semaphore::new(8));
    let mut handles = Vec::with_capacity(total_sources);
    for src in selected {
        let sem_f = feed_sem.clone();
        handles.push(tokio::spawn(async move {
            let _permit = sem_f.acquire_owned().await.ok();
            let t0 = Instant::now();
            // Custom user subscriptions use Happ 4.11.2 / v2rayNG / SFA + AES-128-GCM body decrypt + gzip!
            let res: Result<(String, Vec<serde_json::Value>, String), String> = if !src.builtin {
                let fetch_u = crate::happ_compat::fetch_url_without_fragment(&src.url);
                let hwid_def = crate::happ_compat::HwidIdentityConfig::default();
                match crate::net_util::fetch_subscription_smart_ex(
                    &src.url,
                    &fetch_u,
                    &src.encrypted_kind,
                    src.body_encrypted,
                    src.prefer_happ_ua,
                    &hwid_def,
                    socks5_proxy,
                    768 * 1024,
                )
                .await
                {
                    Ok(sub) => Ok((sub.body, sub.envelope.xray_json_configs, sub.via_tag)),
                    Err(_e)
                        if !src.cached_uris.is_empty() || !src.cached_json_outbounds.is_empty() =>
                    {
                        Ok((
                            src.cached_uris.join("\n"),
                            src.cached_json_outbounds.clone(),
                            "cache".to_string(),
                        ))
                    }
                    Err(e) => Err(e),
                }
            } else {
                // Limit each public feed to 576 KiB with transparent gzip + ETag 304 cache!
                fetch_text_resilient_tagged(&src.url, socks5_proxy, 576 * 1024)
                    .await
                    .map(|(b, tag)| (b, Vec::new(), tag.to_string()))
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
        let (body, json_cfgs, mirror) = match res {
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

        let tier = if src.builtin { 1 } else { 0 };
        let mut per_src = 0usize;
        let mut raw_line_budget = 0usize;

        // Import any raw Xray JSON outbounds from Happ / Remnawave JSON subscriptions
        if tier == 0 && !json_cfgs.is_empty() {
            for jcfg in &json_cfgs {
                for mut jcand in crate::xray_config::parse_xray_json_config_to_candidates(
                    jcfg,
                    &src.name,
                    &src.region_hint,
                    0,
                ) {
                    jcand.priority_score += 280;
                    let dkey = format!("custom-json:{}", jcand.id);
                    if seen_ep.insert(dkey) {
                        candidates.push(jcand);
                        per_src += 1;
                    }
                }
            }
        }

        let decoded = decode_subscription_body(&body);
        for line in decoded.lines() {
            let l = line.trim();
            if l.is_empty() || l.starts_with('#') || l.starts_with("//") || is_dummy_banner_uri(l) {
                continue;
            }
            raw_line_budget += 1;
            // Bound BOTH raw parsed lines (prevents CPU spikes on 5,000-line junk files) AND accepted nodes!
            if per_src >= 420 || (tier != 0 && raw_line_budget >= 1100) {
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

                // Never include pure domestic Russian exit servers in VPN pool (we are replacing a
                // Russian IP!); genuine RU-entry whitelist relays exiting abroad are kept & verified!
                if !cand.whitelist_friendly && is_pure_russia_exit_remark(&cand.name) {
                    continue;
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
                    "AUTO" | "WL" | "WARP" => {
                        if matches!(
                            cand.region_hint.as_str(),
                            "FI" | "NL" | "DE" | "SE" | "US" | "GB" | "FR" | "PL" | "CH" | "TR" | "SG" | "JP" | "CA"
                        ) {
                            cand.priority_score += 55;
                        }
                    }
                    "EU" => {
                        if matches!(
                            cand.region_hint.as_str(),
                            "FI" | "NL" | "DE" | "SE" | "GB" | "FR" | "PL" | "CH" | "AT"
                        ) {
                            cand.priority_score += 80;
                        }
                    }
                    exact_cc => {
                        if cand.region_hint == exact_cc {
                            cand.priority_score += 95;
                        } else if cand.region_hint != "OTHER" {
                            cand.priority_score -= 15;
                        }
                    }
                }
                if want_wl {
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
