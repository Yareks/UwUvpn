//! Persistent atomic state manager & high-level engine coordinator (v1.1 — RF TSPU hardened).

use crate::diag::{
    clear_diag_logs, diag_err, diag_info, diag_log, diag_ok, diag_warn, fmt_endpoint,
    read_diag_logs, set_log_dir, write_file_atomic_locked, PROBE_PROGRESS,
};
use crate::happ_compat::{
    fetch_url_without_fragment, unwrap_or_decrypt_subscription, HwidIdentityConfig,
};
use crate::net_util::{
    fetch_subscription_smart_ex, prune_network_caches, set_local_socks_auth,
};
use crate::opera::{provision_opera_endpoints, OperaSessionCache};
use crate::sources::{
    content_hash_short, default_sources, extract_vpn_uris_from_subscription,
    fetch_remote_manifest, fetch_vpn_candidates, is_dummy_banner_uri, is_pure_russia_exit_remark,
    is_rf_blocked_sni, is_whitelist_remark, SubSource, VerifiedVpnNode, VpnCandidate,
};
use crate::tg_bridge::{probe_tg_ws_direct, start_tg_bridge, TgLocalBridge};
use crate::tg_checker::{
    fetch_and_verify_tg_proxies_delta, parse_single_tg_token, parse_tg_proxies_from_text,
    verify_tg_candidate_strict, TgCheckProgress, VerifiedTgProxy,
};
use crate::vpn_probe::{
    check_active_tunnel_health, check_services_live, fast_verify_seed_nodes, region_match_rank,
    revalidate_cached_nodes_via_socks, tcp_prefilter_candidates_ex, verify_batch_via_socks,
    TunnelHealthResult,
};
use crate::warp::{provision_warp_account, WarpAccountCache};
use crate::xray_config::{
    build_batch_probe_config, build_production_tun_config_v17, candidate_to_warp_chain,
    node_matches_strict_region, opera_endpoints_to_candidates,
    opera_endpoints_to_warp_chain_candidates, parse_share_uri_to_candidate,
    parse_xray_json_config_to_candidates, warp_account_to_candidates, CustomDomainRules,
};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::runtime::{Builder, Runtime};

/// Ultra-lean Tokio runtime: 1 worker in the long-lived `:vpn` service process (minimum idle threads
/// & RAM — `xray-rust` handles packet I/O on its own worker), 2 workers in UI/CLI for parallel feeds.
pub static TOKIO_RT: Lazy<Runtime> = Lazy::new(|| {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let is_vpn_proc = fs::read_to_string("/proc/self/cmdline")
        .map(|s| s.split('\0').next().unwrap_or("").ends_with(":vpn"))
        .unwrap_or(false);
    let workers = if is_vpn_proc { 1 } else { 2 };
    let max_blocking = if is_vpn_proc { 2 } else { 3 };
    Builder::new_multi_thread()
        .worker_threads(workers)
        .max_blocking_threads(max_blocking)
        .thread_name("velox-io")
        .thread_stack_size(384 * 1024)
        .enable_all()
        .build()
        .expect("tokio runtime init")
});

/// Poison-recovering read/write lock helpers — never panic inside JNI even after a caught unwind!
fn read_data(lock: &RwLock<PersistedData>) -> std::sync::RwLockReadGuard<'_, PersistedData> {
    lock.read().unwrap_or_else(|e| e.into_inner())
}
fn write_data(lock: &RwLock<PersistedData>) -> std::sync::RwLockWriteGuard<'_, PersistedData> {
    lock.write().unwrap_or_else(|e| e.into_inner())
}

fn file_stamp(path: &std::path::Path) -> (u128, u64) {
    let Ok(md) = fs::metadata(path) else {
        return (0, 0);
    };
    let mtime_ns = md
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    (mtime_ns, md.len())
}

pub static ENGINE: Lazy<EngineController> = Lazy::new(EngineController::new);

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PersistedData {
    pub version: u32,
    pub sources: Vec<SubSource>,
    pub custom_vpn_uris: Vec<String>,
    pub custom_tg_links: Vec<String>,
    pub manifest_url: String,
    pub vpn_nodes: Vec<VerifiedVpnNode>,
    pub tg_proxies: Vec<VerifiedTgProxy>,
    pub warp: WarpAccountCache,
    pub opera: OperaSessionCache,
    /// Map of `host:port` -> unix timestamp when failure was recorded (90m TTL).
    pub blacklist: HashMap<String, u64>,
    pub last_vpn_refresh_unix: u64,
    pub last_tg_refresh_unix: u64,
    /// Optional opt-in Happ-compatible HWID & device identity settings (OFF by default for privacy!).
    #[serde(default)]
    pub hwid_config: HwidIdentityConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BootstrapSeed {
    #[serde(default)]
    pub vpn_nodes: Vec<VerifiedVpnNode>,
    #[serde(default)]
    pub tg_proxies: Vec<VerifiedTgProxy>,
}

pub struct EngineController {
    pub data_dir: RwLock<Option<PathBuf>>,
    pub data: RwLock<PersistedData>,
    /// Last loaded `(mtime_ns, len)` of `velox_state.json` — skips redundant 150 KB JSON re-parse in 0.01 ms!
    pub last_state_stamp: Mutex<(u128, u64)>,
    pub pending_batches: Mutex<HashMap<String, Vec<VpnCandidate>>>,
    pub pending_seed_batches: Mutex<HashMap<String, Vec<VerifiedVpnNode>>>,
    pub tg_progress: Arc<TgCheckProgress>,
    pub tg_bridge: Arc<TgLocalBridge>,
    pub logged_startup: AtomicBool,
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn socks_opt(port: u16) -> Option<SocketAddr> {
    if port > 0 {
        Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port))
    } else {
        None
    }
}

pub fn normalize_region(target_region: &str) -> &'static str {
    match target_region.trim().to_ascii_uppercase().as_str() {
        "YT" | "NOADS" | "ADFREE" => "YT",
        "DE" => "DE",
        "US" => "US",
        "NL" => "NL",
        "FI" => "FI",
        "GB" | "UK" => "GB",
        "FR" => "FR",
        "SE" => "SE",
        "PL" => "PL",
        "CH" => "CH",
        "AT" => "AT",
        "CZ" => "CZ",
        "IT" => "IT",
        "ES" => "ES",
        "PT" => "PT",
        "HU" => "HU",
        "AL" => "AL",
        "MD" => "MD",
        "TR" => "TR",
        "KZ" => "KZ",
        "JP" => "JP",
        "SG" => "SG",
        "CA" => "CA",
        "EU" => "EU",
        "WL" => "WL",
        "WARP" => "WARP",
        // Domestic Russia is never a VPN target — redirect cleanly to priority Germany (DE)
        "RU" => "DE",
        _ => "AUTO",
    }
}

impl Default for EngineController {
    fn default() -> Self {
        Self::new()
    }
}

impl EngineController {
    pub fn new() -> Self {
        let init = PersistedData {
            version: 8,
            sources: default_sources(),
            ..Default::default()
        };
        Self {
            data_dir: RwLock::new(None),
            data: RwLock::new(init),
            last_state_stamp: Mutex::new((0, 0)),
            pending_batches: Mutex::new(HashMap::new()),
            pending_seed_batches: Mutex::new(HashMap::new()),
            tg_progress: Arc::new(TgCheckProgress::default()),
            tg_bridge: Arc::new(TgLocalBridge::default()),
            logged_startup: AtomicBool::new(false),
        }
    }

    pub fn init(&self, dir_path: &str, seed_json: &str) -> String {
        let path = PathBuf::from(dir_path);
        let _ = fs::create_dir_all(&path);
        set_log_dir(path.clone());
        if let Ok(mut d) = self.data_dir.write() {
            *d = Some(path.clone());
        }

        let state_file = path.join("velox_state.json");
        let is_reload = seed_json.trim().is_empty() && state_file.exists();
        let disk_stamp = file_stamp(&state_file);

        // O(1) zero-allocation cross-process reload fast path: if `velox_state.json` `(mtime_ns, len)`
        // hasn't changed since our last read/save, return cached counts in ~5 microseconds!
        if is_reload && disk_stamp.1 > 0 {
            let unchanged = self
                .last_state_stamp
                .lock()
                .ok()
                .is_some_and(|st| *st == disk_stamp);
            if unchanged {
                let g = read_data(&self.data);
                let vpn_cnt = g.vpn_nodes.len();
                let dev_cnt = g.vpn_nodes.iter().filter(|n| n.device_verified).count();
                let tg_cnt = g.tg_proxies.len();
                return json!({
                    "ok": true,
                    "cached": true,
                    "vpnCount": vpn_cnt,
                    "deviceVerifiedCount": dev_cnt,
                    "tgCount": tg_cnt
                })
                .to_string();
            }
        }

        let mut loaded = if let Ok(bytes) = fs::read(&state_file) {
            serde_json::from_slice::<PersistedData>(&bytes).unwrap_or_default()
        } else {
            PersistedData::default()
        };

        // Seamless upgrade migration (v1..v7 -> v8 / VeloxVPN v1.7.0):
        // - Remove ALL domestic Russian (`RU`) exit nodes (we replace Russia with foreign IPs!)
        // - Strip confusing `[RU]` labels from foreign 0%-ad YouTube servers
        // - Reset false failover `fail_count` from pre-v1.7, preserve WARP, custom subs, HWID & live pool
        let now_mig = unix_now();
        let mut mutated = false;
        if loaded.version < 8 {
            let prev_ver = loaded.version;
            loaded.version = 8;
            loaded.vpn_nodes.retain(|n| {
                let drop_opera = matches!(n.protocol.as_str(), "opera" | "http")
                    && (prev_ver < 6
                        || (n.verified_unix > 0
                            && now_mig.saturating_sub(n.verified_unix) > 45 * 60));
                let drop_ru = n.exit_country.eq_ignore_ascii_case("RU")
                    || (!n.whitelist_friendly && is_pure_russia_exit_remark(&n.name));
                !drop_opera && !drop_ru && (n.source_tier == 0 || !is_rf_blocked_sni(&n.sni))
            });
            for n in &mut loaded.vpn_nodes {
                if n.via_warp {
                    n.whitelist_friendly = false;
                }
                if n.name.contains(" [RU]") {
                    n.name = n.name.replace(" [RU]", "");
                }
                if n.device_verified || n.source_tier == 0 {
                    n.fail_count = 0;
                    n.last_fail_unix = 0;
                }
                if n.device_verified && n.ok_streak == 0 {
                    n.ok_streak = 1;
                }
                if !n.via_warp && is_whitelist_remark(&n.name) && !is_rf_blocked_sni(&n.sni) {
                    n.whitelist_friendly = true;
                }
                if matches!(n.exit_country.as_str(), "AL" | "MD" | "MC" | "AD")
                    && !matches!(n.protocol.as_str(), "opera" | "http")
                {
                    n.yt_ad_free = true;
                    if n.yt_country.is_empty() {
                        n.yt_country = n.exit_country.clone();
                    }
                }
            }
            let valid_builtins: HashSet<String> =
                default_sources().into_iter().map(|s| s.url).collect();
            loaded
                .sources
                .retain(|s| !s.builtin || valid_builtins.contains(&s.url));
            loaded.blacklist.clear();
            if prev_ver > 0 {
                diag_info(
                    "SYS",
                    format!(
                        "Обновление v1.7 (Анти-разрыв + Резерв Страна/DE/US + 0% RU + 250+ сервисов): живых VPN={}, подписок={}",
                        loaded.vpn_nodes.iter().filter(|n| n.device_verified).count(),
                        loaded.sources.iter().filter(|s| !s.builtin).count()
                    ),
                );
            }
            mutated = true;
        }

        // Ensure all built-in sources exist while preserving user custom subs at the very top!
        for def in default_sources() {
            if !loaded.sources.iter().any(|s| s.url == def.url) {
                loaded.sources.push(def);
                mutated = true;
            }
        }

        // Prune expired blacklist entries (> 90 min old) and expired Opera relays (> 45 min old)
        let now = unix_now();
        let bl_before = loaded.blacklist.len();
        loaded
            .blacklist
            .retain(|_, ts| now.saturating_sub(*ts) < 5400);
        let vpn_before = loaded.vpn_nodes.len();
        loaded.vpn_nodes.retain(|n| {
            !n.exit_country.eq_ignore_ascii_case("RU")
                && !(n.protocol == "opera"
                    && n.verified_unix > 0
                    && now.saturating_sub(n.verified_unix) > 45 * 60)
        });
        // Gently recover custom subscription nodes whose temporary failure happened > 30 min ago
        for n in &mut loaded.vpn_nodes {
            if n.source_tier == 0
                && n.fail_count > 0
                && n.last_fail_unix > 0
                && now.saturating_sub(n.last_fail_unix) > 1800
            {
                n.fail_count = 0;
                mutated = true;
            }
        }
        if loaded.blacklist.len() != bl_before || loaded.vpn_nodes.len() != vpn_before {
            mutated = true;
        }

        // Seed initial LKG pool on very first install (always marked `device_verified = false`, 0% RU!)
        if !seed_json.trim().is_empty() && loaded.vpn_nodes.is_empty() && loaded.tg_proxies.is_empty()
        {
            if let Ok(seed) = serde_json::from_str::<BootstrapSeed>(seed_json) {
                if !seed.vpn_nodes.is_empty() {
                    loaded.vpn_nodes = seed
                        .vpn_nodes
                        .into_iter()
                        .filter(|n| {
                            !n.exit_country.eq_ignore_ascii_case("RU")
                                && !is_rf_blocked_sni(&n.sni)
                        })
                        .map(|mut n| {
                            if n.name.contains(" [RU]") {
                                n.name = n.name.replace(" [RU]", "");
                            }
                            n.device_verified = false;
                            n.fail_count = 0;
                            n
                        })
                        .collect();
                }
                if !seed.tg_proxies.is_empty() {
                    loaded.tg_proxies = seed.tg_proxies;
                }
                diag_info(
                    "SYS",
                    format!(
                        "Стартовый пакет загружен: {} VPN-узлов, {} TG-прокси",
                        loaded.vpn_nodes.len(),
                        loaded.tg_proxies.len()
                    ),
                );
                mutated = true;
            }
        }

        self.tg_bridge.update_pool(&loaded.tg_proxies);
        let vpn_cnt = loaded.vpn_nodes.len();
        let dev_verified_cnt = loaded.vpn_nodes.iter().filter(|n| n.device_verified).count();
        let tg_cnt = loaded.tg_proxies.len();

        {
            let mut g = write_data(&self.data);
            *g = loaded;
        }
        if mutated || !is_reload {
            self.save();
        } else if let Ok(mut st) = self.last_state_stamp.lock() {
            *st = disk_stamp;
        }

        // Log engine initialization ONLY once per process creation (never spam on cross-process reloads!)
        if !self.logged_startup.swap(true, Ordering::Relaxed) && !is_reload {
            diag_info(
                "SYS",
                format!(
                    "Velox Engine v1.7 готов (VPN: {vpn_cnt} [живых: {dev_verified_cnt}], TG: {tg_cnt}, 2× Резерв Страна/DE/US, 0% RU, 250+ сервисов)"
                ),
            );
        }

        json!({
            "ok": true,
            "vpnCount": vpn_cnt,
            "deviceVerifiedCount": dev_verified_cnt,
            "tgCount": tg_cnt
        })
        .to_string()
    }

    /// Cross-process atomic `flock` + PID-unique temp file write (eliminates UI <-> `:vpn` races!).
    pub fn save(&self) {
        let Some(dir) = self.data_dir.read().ok().and_then(|g| g.clone()) else {
            return;
        };
        let Ok(bytes) = serde_json::to_vec(&*read_data(&self.data)) else {
            return;
        };
        let dst = dir.join("velox_state.json");
        if write_file_atomic_locked(&dst, &bytes) {
            if let Ok(mut st) = self.last_state_stamp.lock() {
                *st = file_stamp(&dst);
            }
        }
    }

    /// Release all transient probe batches, DNS/ETag HTTP caches, and excess Vec capacity
    /// once the tunnel is connected or Android signals `onTrimMemory()` — zero feature loss!
    pub fn trim_runtime_memory(&self, aggressive: bool) {
        if let Ok(mut m) = self.pending_batches.lock() {
            m.clear();
            m.shrink_to_fit();
        }
        if let Ok(mut m) = self.pending_seed_batches.lock() {
            m.clear();
            m.shrink_to_fit();
        }
        prune_network_caches(aggressive);
        if aggressive {
            let mut g = write_data(&self.data);
            g.vpn_nodes.shrink_to_fit();
            g.tg_proxies.shrink_to_fit();
            g.sources.shrink_to_fit();
            g.blacklist.shrink_to_fit();
        }
    }

    /// Configure opt-in Happ-compatible `X-HWID` & device headers (used on HWID-locked paid subs).
    pub fn configure_hwid(
        &self,
        enabled: bool,
        hwid: &str,
        device_os: &str,
        ver_os: &str,
        device_model: &str,
        app_locale: &str,
    ) -> String {
        {
            let mut g = write_data(&self.data);
            let _ = device_os;
            g.hwid_config = HwidIdentityConfig {
                enabled,
                hwid: hwid.trim().chars().take(128).collect(),
                os_version: ver_os.trim().chars().take(32).collect(),
                device_model: device_model.trim().chars().take(64).collect(),
                locale: if app_locale.trim().is_empty() {
                    "ru-RU".into()
                } else {
                    app_locale.trim().chars().take(16).collect()
                },
            };
        }
        self.save();
        json!({ "ok": true, "enabled": enabled }).to_string()
    }

    /// Register ephemeral per-session RFC 1929 SOCKS5 auth credentials for `127.0.0.1:local_socks_port`.
    pub fn register_local_socks_auth(&self, port: u16, user: &str, pass: &str) {
        set_local_socks_auth(port, user, pass);
    }

    /// Build a fast parallel probe config for unverified bundled seed nodes so initial cold-start
    /// tests 14 seed servers in ~3.8s concurrently instead of stalling on serial 7s timeouts!
    pub fn prepare_seed_quick_probe(
        &self,
        target_region: &str,
        whitelist_mode: bool,
        base_port: u16,
        max_count: usize,
    ) -> String {
        let region = normalize_region(target_region);
        let cap = max_count.clamp(4, 18);
        let seeds: Vec<VerifiedVpnNode> = {
            let g = read_data(&self.data);
            let mut list: Vec<VerifiedVpnNode> = g
                .vpn_nodes
                .iter()
                .filter(|n| !n.device_verified && n.fail_count < 2 && !is_rf_blocked_sni(&n.sni))
                .cloned()
                .collect();
            list.sort_by_key(|n| {
                let wl = if whitelist_mode && n.whitelist_friendly {
                    0u8
                } else {
                    1u8
                };
                (wl, region_match_rank(&n.exit_country, region), n.rtt_ms)
            });
            list.truncate(cap);
            list
        };

        if seeds.is_empty() {
            return json!({ "ok": false, "empty": true }).to_string();
        }

        let mut inbounds = Vec::with_capacity(seeds.len());
        let mut outbounds = Vec::with_capacity(seeds.len() + 1);
        let mut rules = Vec::with_capacity(seeds.len());
        for (idx, n) in seeds.iter().enumerate() {
            let port = base_port + idx as u16;
            let in_tag = format!("sin_{idx}");
            let out_tag = format!("sp_{idx}");
            inbounds.push(json!({
                "tag": in_tag,
                "listen": "127.0.0.1",
                "port": port,
                "protocol": "socks",
                "settings": { "auth": "noauth", "udp": false }
            }));
            let mut ob = n.outbound_json.clone();
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
        outbounds.push(json!({ "tag": "direct", "protocol": "freedom", "settings": {} }));
        let cfg = json!({
            "log": { "loglevel": "none" },
            "inbounds": inbounds,
            "outbounds": outbounds,
            "routing": { "domainStrategy": "AsIs", "rules": rules }
        })
        .to_string();

        let count = seeds.len();
        let batch_id = format!("seed_{}", unix_now());
        diag_info(
            "PROBE",
            format!("Запуск параллельного экспресс-теста {count} стартовых узлов (регион: {region})"),
        );

        if let Ok(mut m) = self.pending_seed_batches.lock() {
            m.clear();
            m.insert(batch_id.clone(), seeds);
        }

        json!({
            "ok": true,
            "batchId": batch_id,
            "basePort": base_port,
            "count": count,
            "probeConfigJson": cfg
        })
        .to_string()
    }

    pub fn finalize_seed_quick_probe(
        &self,
        batch_id: &str,
        base_port: u16,
        target_region: &str,
    ) -> String {
        let region = normalize_region(target_region);
        let seeds = self
            .pending_seed_batches
            .lock()
            .ok()
            .and_then(|mut m| m.remove(batch_id))
            .unwrap_or_default();
        if seeds.is_empty() {
            PROBE_PROGRESS.finish();
            return json!({ "ok": false, "aliveCount": 0 }).to_string();
        }

        let (live_nodes, dead_ids) =
            TOKIO_RT.block_on(fast_verify_seed_nodes(&seeds, base_port, region));
        let dead_set: HashSet<String> = dead_ids.into_iter().collect();
        let live_ids: HashSet<String> = live_nodes.iter().map(|n| n.id.clone()).collect();
        let alive_cnt = live_nodes.len();

        {
            let now = unix_now();
            let mut g = write_data(&self.data);
            // Remove dead tested seeds immediately so they NEVER delay connection again!
            let dead_eps: Vec<String> = g
                .vpn_nodes
                .iter()
                .filter(|n| dead_set.contains(&n.id) && n.source_tier == 1)
                .map(|n| format!("{}:{}", n.host.to_ascii_lowercase(), n.port))
                .collect();
            for ep in dead_eps {
                g.blacklist.insert(ep, now);
            }
            g.vpn_nodes
                .retain(|n| !dead_set.contains(&n.id) && !live_ids.contains(&n.id));
            let mut updated = live_nodes;
            // If at least one seed passed on user's ISP, keep other untested seeds strictly behind it
            updated.extend(g.vpn_nodes.drain(..));
            updated.sort_by_key(|n| (!n.device_verified, n.fail_count, n.rtt_ms));
            g.vpn_nodes = updated;
            if alive_cnt > 0 {
                g.last_vpn_refresh_unix = now;
            }
        }
        self.save();
        PROBE_PROGRESS.finish();

        json!({
            "ok": alive_cnt > 0,
            "aliveCount": alive_cnt
        })
        .to_string()
    }

    /// Fetch Tier 0/1/2/3 VPN candidates, pre-filter via async TCP + clean DoH IP pinning, and
    /// build a batch SOCKS5 `xray-rust` JSON config for parallel full-tunnel verification.
    pub fn prepare_vpn_probe_batch(
        &self,
        target_region: &str,
        whitelist_mode: bool,
        fragment_tls: bool,
        base_port: u16,
        max_batch: usize,
        active_socks_port: u16,
    ) -> String {
        let region = normalize_region(target_region);
        let eff_wl = whitelist_mode || region == "WL";
        let max_batch = max_batch.clamp(12, 54);
        let proxy = socks_opt(active_socks_port);

        let (sources, custom_uris, existing_opera, existing_warp, bl_set, skip_live_eps, manifest_url) = {
            let g = read_data(&self.data);
            let now = unix_now();
            let bl: HashSet<String> = g
                .blacklist
                .iter()
                .filter(|(_, ts)| now.saturating_sub(**ts) < 5400)
                .map(|(k, _)| k.clone())
                .collect();
            // Smart Incremental Delta Sync: never waste slots re-installing servers verified in last 35 min!
            let skip_live: HashSet<String> = g
                .vpn_nodes
                .iter()
                .filter(|n| {
                    n.device_verified
                        && n.fail_count == 0
                        && now.saturating_sub(n.verified_unix) < 2100
                })
                .map(|n| format!("{}:{}", n.host.to_ascii_lowercase(), n.port))
                .collect();
            (
                g.sources.clone(),
                g.custom_vpn_uris.clone(),
                g.opera.clone(),
                g.warp.clone(),
                bl,
                skip_live,
                g.manifest_url.clone(),
            )
        };

        PROBE_PROGRESS.set_stage(
            1,
            5,
            10,
            14,
            0,
            0,
            0,
            if whitelist_mode {
                "Загрузка серверов «Белые списки РФ» (SNI + CIDR)…".to_string()
            } else {
                format!("Умная загрузка списков {region} + MASQUE-Chain…")
            },
        );
        diag_info(
            "VPN",
            format!(
                "Умное обновление: регион={region}, БС={whitelist_mode}, frag={fragment_tls}, пакет={max_batch}, живых_сохр={}, ЧС={}",
                skip_live_eps.len(),
                bl_set.len()
            ),
        );

        let bl_chain = bl_set.clone();
        let skip_chain_live = skip_live_eps.clone();
        let t_start = Instant::now();
        let (selected, dead_eps, new_opera, new_warp, extra_manifest) = TOKIO_RT.block_on(async {
            let manifest_fut = async {
                if manifest_url.starts_with("https://") {
                    fetch_remote_manifest(&manifest_url, proxy).await.ok()
                } else {
                    None
                }
            };

            // Tier-0 (user subs) + Tier-1 (53 curated feeds: 15 countries + RF WL + Reality + XHTTP + Hy2 + Trojan + VMess + SS2022 + WG)
            let tier1_fut = fetch_vpn_candidates(
                &sources,
                region,
                eff_wl,
                fragment_tls,
                proxy,
                &bl_set,
            );

            // Tier-2: Free official Opera SurfEasy HTTPS proxies across US, EU (NL) & Asia (SG)
            let opera_fut = async {
                if eff_wl {
                    return None;
                }
                if existing_opera.is_fresh() {
                    Some(existing_opera.clone())
                } else {
                    match tokio::time::timeout(
                        std::time::Duration::from_millis(3400),
                        provision_opera_endpoints(Some(&existing_opera), proxy),
                    )
                    .await
                    {
                        Ok(Ok(op)) => {
                            diag_ok(
                                "OPERA",
                                format!("Получено {} релеев Opera US/EU/Asia", op.endpoints.len()),
                            );
                            Some(op)
                        }
                        _ => None,
                    }
                }
            };

            // Tier-3: Free official Cloudflare WARP (MASQUE H3/H2 + WireGuard with UDP noise)
            let warp_fut = async {
                if existing_warp.has_wg() && existing_warp.has_masque() {
                    Some(existing_warp.clone())
                } else {
                    let t_wp = Instant::now();
                    match tokio::time::timeout(
                        std::time::Duration::from_millis(4800),
                        provision_warp_account(Some(&existing_warp), false, proxy),
                    )
                    .await
                    {
                        Ok(Ok(wp)) => {
                            diag_ok(
                                "WARP",
                                format!(
                                    "Аккаунт WARP готов за {}мс (MASQUE:{})",
                                    t_wp.elapsed().as_millis(),
                                    wp.has_masque()
                                ),
                            );
                            Some(wp)
                        }
                        Ok(Err(e)) => {
                            diag_warn("WARP", format!("WARP API недоступен: {e}"));
                            None
                        }
                        Err(_) => {
                            diag_warn("WARP", "WARP API таймаут (4.8с) — идём через прямые узлы");
                            None
                        }
                    }
                }
            };

            let (manifest_opt, mut all_cands, opera_opt, warp_opt) =
                tokio::join!(manifest_fut, tier1_fut, opera_fut, warp_fut);

            // Collect individual custom keys (user subscriptions are already in all_cands with source_tier == 0!)
            let mut custom_cands = Vec::new();
            for u in &custom_uris {
                if is_dummy_banner_uri(u) {
                    continue;
                }
                let is_real = u.contains("security=reality");
                if let Some(c) =
                    parse_share_uri_to_candidate(u, "AUTO", 0, fragment_tls && !is_real)
                {
                    let ep = format!("{}:{}", c.host.to_ascii_lowercase(), c.port);
                    if !skip_live_eps.contains(&ep) {
                        custom_cands.push(c);
                    }
                }
            }
            if let Some(m) = &manifest_opt {
                for u in &m.extra_vless {
                    if let Some(c) = parse_share_uri_to_candidate(u, "AUTO", 1, fragment_tls) {
                        custom_cands.push(c);
                    }
                }
            }

            let has_masque = warp_opt.as_ref().map(|w| w.has_masque()).unwrap_or(false);

            // Opera+MASQUE 3-continent slots (US / EU-NL / Asia-SG — deduplicated 1 per region)
            let opera_chain_cands: Vec<VpnCandidate> = if has_masque && !eff_wl {
                opera_opt
                    .as_ref()
                    .map(|op| {
                        let all_op = opera_endpoints_to_warp_chain_candidates(&op.endpoints, region);
                        let cap = if region == "WARP" { 3usize } else { 2usize };
                        let mut seen_reg = HashSet::new();
                        let mut picked = Vec::new();
                        for c in &all_op {
                            if seen_reg.insert(c.region_hint.clone()) {
                                picked.push(c.clone());
                                if picked.len() >= cap {
                                    break;
                                }
                            }
                        }
                        picked
                    })
                    .unwrap_or_default()
            } else {
                Vec::new()
            };

            // Chain custom TLS/SS/Trojan/VMess/SOCKS5 keys over MASQUE as extra fallback
            let mut custom_chain_cands = Vec::new();
            if has_masque && !eff_wl {
                for cc in custom_cands
                    .iter()
                    .chain(all_cands.iter().filter(|c| c.source_tier == 0))
                    .take(6)
                {
                    if let Some(wc) = candidate_to_warp_chain(cc) {
                        custom_chain_cands.push(wc);
                        if custom_chain_cands.len() >= 2 {
                            break;
                        }
                    }
                }
            }

            // Echelon B: Multi-country 2-hop `MASQUE-Chain` (SS2022, Trojan, VLESS-TLS, VMess, SOCKS5)
            // Unlocks RKN IP-blocked servers across FI, NL, DE, US, GB, FR, SE, PL, CH, TR, JP, SG, CA!
            let mut tier1_chain_cands: Vec<VpnCandidate> = Vec::new();
            if has_masque && !eff_wl {
                let mut chain_seen_hosts = HashSet::new();
                let mut per_region_cnt: HashMap<String, usize> = HashMap::new();
                let chain_cap: usize = if region == "WARP" { 16 } else { 15 };

                let mut chain_pool: Vec<&VpnCandidate> = all_cands
                    .iter()
                    .filter(|c| {
                        let h_low = c.host.to_ascii_lowercase();
                        let ep = format!("{}:{}", h_low, c.port);
                        let wkey = format!("wchain:{ep}");
                        !bl_chain.contains(&wkey) && !skip_chain_live.contains(&ep)
                    })
                    .collect();
                chain_pool.sort_by_key(|c| {
                    let exact_reg = match region {
                        "AUTO" | "WARP" => 0u8,
                        "EU" => {
                            if matches!(
                                c.region_hint.as_str(),
                                "FI" | "NL" | "DE" | "SE" | "GB" | "FR" | "PL" | "CH" | "AT"
                            ) {
                                0u8
                            } else {
                                1u8
                            }
                        }
                        target => if c.region_hint == target { 0u8 } else { 1u8 },
                    };
                    let proto_prio = match (c.protocol.as_str(), c.security.as_str()) {
                        ("shadowsocks", "ss2022") => 0u8,
                        ("trojan", "tls") => 1u8,
                        ("vless", "tls") => 2u8,
                        ("shadowsocks", _) => 3u8,
                        ("vmess", "tls") => 4u8,
                        ("socks", _) => 5u8,
                        _ => 6u8,
                    };
                    let net_prio = match c.transport.as_str() {
                        "tcp" => 0u8,
                        "httpupgrade" | "ws" => 1u8,
                        "grpc" => 2u8,
                        _ => 3u8,
                    };
                    let port_prio = if matches!(c.port, 443 | 8443 | 2053) { 0u8 } else { 1u8 };
                    (exact_reg, proto_prio, net_prio, port_prio)
                });

                for c in chain_pool {
                    if tier1_chain_cands.len() >= chain_cap {
                        break;
                    }
                    let h_low = c.host.to_ascii_lowercase();
                    if (h_low.starts_with("104.16.")
                        || h_low.starts_with("104.17.")
                        || h_low.starts_with("104.18.")
                        || h_low.starts_with("104.21.")
                        || h_low.starts_with("172.67.")
                        || h_low.starts_with("162.159."))
                        && c.transport == "tcp"
                    {
                        continue;
                    }
                    let rc = per_region_cnt.get(&c.region_hint).copied().unwrap_or(0);
                    let max_for_reg = match region {
                        "AUTO" | "EU" | "WARP" => {
                            // Spread slots across many countries (2-3 each -> NL, FI, DE, US, GB, FR, SE, PL, TR, SG, JP!)
                            if c.region_hint == "OTHER" { 1 } else { 3 }
                        }
                        target => {
                            if c.region_hint == target { 10 } else { 2 }
                        }
                    };
                    if rc >= max_for_reg {
                        continue;
                    }
                    let host_key = format!("{}:{}", h_low, c.port);
                    if !chain_seen_hosts.insert(host_key) {
                        continue;
                    }
                    if let Some(wc) = candidate_to_warp_chain(c) {
                        *per_region_cnt.entry(c.region_hint.clone()).or_insert(0) += 1;
                        tier1_chain_cands.push(wc);
                    }
                }
            }

            // Direct Opera HTTPS+TLS+Fragment relay
            let tier2_direct = if eff_wl {
                Vec::new()
            } else {
                opera_opt
                    .as_ref()
                    .map(|op| {
                        let mut v =
                            opera_endpoints_to_candidates(&op.endpoints, region, fragment_tls);
                        v.truncate(1);
                        v
                    })
                    .unwrap_or_default()
            };

            // Direct Cloudflare WARP suite: MASQUE H3, MASQUE H3+Noise, MASQUE H2+Frag, WARP AWG+Noise!
            let tier3_cands = if eff_wl {
                Vec::new()
            } else {
                warp_opt
                    .as_ref()
                    .map(|wp| {
                        let all_wp = warp_account_to_candidates(wp, fragment_tls);
                        if region == "WARP" {
                            // Showcase full WARP variety: H3 :443, H3+Noise, H3 :8443, H2 :443, H2 :8443, AWG :2408, AWG :500
                            let mut picked: Vec<VpnCandidate> = all_wp.iter().take(6).cloned().collect();
                            for w in all_wp.iter().filter(|c| c.protocol == "warp-wg").take(2) {
                                picked.push(w.clone());
                            }
                            picked
                        } else {
                            // Always include H3 QUIC, H3+Noise, H2 TCP+Frag, and 1 WARP AWG Noise!
                            let mut picked: Vec<VpnCandidate> = all_wp.iter().take(3).cloned().collect();
                            if let Some(wg) = all_wp.iter().find(|c| c.protocol == "warp-wg") {
                                picked.push(wg.clone());
                            }
                            picked
                        }
                    })
                    .unwrap_or_default()
            };

            let eff_max = max_batch.max(46).min(54);
            let reserved = custom_cands.len().min(6)
                + custom_chain_cands.len().min(2)
                + opera_chain_cands.len()
                + tier1_chain_cands.len()
                + tier2_direct.len()
                + tier3_cands.len();
            let tier1_direct_cap = eff_max
                .saturating_sub(reserved)
                .max(if eff_wl { 34 } else { 24 });
            let tcp_scan_cap = if eff_wl { 300 } else { 260 };

            // Echelon C: Direct 1-hop multi-protocol & multi-country harvest (Reality, XHTTP, Hy2, Trojan, VMess, SS2022, WG, WL-РФ)!
            let (mut alive_tier1, dead) = tcp_prefilter_candidates_ex(
                all_cands.drain(..).collect(),
                tcp_scan_cap,
                tier1_direct_cap,
                eff_wl,
                &skip_live_eps,
            )
            .await;

            let mut combined = Vec::with_capacity(eff_max);
            combined.extend(custom_cands.into_iter().take(6));
            if eff_wl {
                combined.append(&mut alive_tier1);
            } else if region == "WARP" {
                combined.extend(tier3_cands);
                combined.extend(tier1_chain_cands);
                combined.extend(opera_chain_cands);
                combined.append(&mut alive_tier1);
            } else {
                combined.append(&mut alive_tier1);
                combined.extend(custom_chain_cands.into_iter().take(2));
                combined.extend(tier1_chain_cands);
                combined.extend(tier3_cands);
                combined.extend(opera_chain_cands);
                combined.extend(tier2_direct);
            }
            combined.truncate(eff_max);

            (combined, dead, opera_opt, warp_opt, manifest_opt)
        });

        // Persist refreshed Opera / WARP credentials, manifest sources, and dead IPs
        {
            let now = unix_now();
            let mut g = write_data(&self.data);
            if let Some(op) = new_opera {
                g.opera = op;
            }
            if let Some(wp) = new_warp {
                g.warp = wp;
            }
            if let Some(m) = extra_manifest {
                for s in m.sources {
                    if !g.sources.iter().any(|ex| ex.url == s.url) && s.url.starts_with("https://")
                    {
                        g.sources.push(s);
                    }
                }
                for tg in m.extra_tg {
                    if !g.custom_tg_links.contains(&tg) {
                        g.custom_tg_links.push(tg);
                    }
                }
            }
            for ep in dead_eps {
                g.blacklist.insert(ep, now);
            }
            if g.blacklist.len() > 2500 {
                g.blacklist.clear();
            }
        }
        self.save();

        if selected.is_empty() {
            PROBE_PROGRESS.finish();
            diag_err(
                "VPN",
                "0 доступных кандидатов после загрузки и TCP-отбора (проверьте интернет или прокси/DNS)",
            );
            return json!({
                "ok": false,
                "error": "Не найдено доступных серверов. Проверьте интернет или откройте Журнал."
            })
            .to_string();
        }

        let warp_snapshot = { read_data(&self.data).warp.clone() };
        let probe_config = build_batch_probe_config(
            &selected,
            base_port,
            Some(&warp_snapshot),
            fragment_tls,
        );
        let batch_id = format!("b_{}", unix_now());
        let count = selected.len();

        let chain_cnt = selected.iter().filter(|c| c.via_warp).count();
        let opera_cnt = selected.iter().filter(|c| c.source_tier == 2).count();
        let warp_cnt = selected.iter().filter(|c| c.source_tier == 3).count();
        let xhttp_cnt = selected.iter().filter(|c| c.transport == "xhttp").count();
        let hy2_cnt = selected.iter().filter(|c| c.protocol == "hysteria2").count();
        let wl_cnt = selected.iter().filter(|c| c.whitelist_friendly).count();
        let real_nofrag = selected
            .iter()
            .filter(|c| c.security == "reality" && !c.fragment_enabled)
            .count();
        let real_frag = selected
            .iter()
            .filter(|c| c.security == "reality" && c.fragment_enabled)
            .count();

        diag_info(
            "PROBE",
            format!(
                "Пакет {count} узлов: MASQUE-Chain:{chain_cnt}, Opera:{opera_cnt}, WARP:{warp_cnt}, Reality:{real_nofrag}+{real_frag}f, XHTTP:{xhttp_cnt}, Hy2:{hy2_cnt}, WL:{wl_cnt}"
            ),
        );

        PROBE_PROGRESS.set_stage(
            3,
            5,
            40,
            13,
            0,
            count as u32,
            0,
            format!("Запуск Rust-ядра для {count} кандидатов…"),
        );

        diag_info(
            "VPN",
            format!(
                "Пакет готов за {}мс: {count} шт. (Reality:{real_nofrag}+{real_frag}frag, XHTTP:{xhttp_cnt}, Hy2:{hy2_cnt}, WL:{wl_cnt}, Opera:{opera_cnt}, WARP:{warp_cnt})",
                t_start.elapsed().as_millis()
            ),
        );

        if let Ok(mut pb) = self.pending_batches.lock() {
            pb.clear();
            pb.insert(batch_id.clone(), selected);
        }

        json!({
            "ok": true,
            "batchId": batch_id,
            "basePort": base_port,
            "count": count,
            "probeConfigJson": probe_config
        })
        .to_string()
    }

    /// Run full-tunnel HTTPS (`gstatic` 204 + 38 KiB anti-16KB + GeoIP/colo) verification across
    /// the running batch `xray-rust` SOCKS5 ports and promote live device-verified nodes to #0!
    pub fn finalize_vpn_probe_batch(
        &self,
        batch_id: &str,
        base_port: u16,
        target_region: &str,
    ) -> String {
        let region = normalize_region(target_region);
        let cands = self
            .pending_batches
            .lock()
            .ok()
            .and_then(|mut m| m.remove(batch_id))
            .unwrap_or_default();

        if cands.is_empty() {
            PROBE_PROGRESS.finish();
            return json!({ "ok": false, "error": "Пустой пакет проверки" }).to_string();
        }

        let total_tested = cands.len();
        let (verified, failed_eps) =
            TOKIO_RT.block_on(verify_batch_via_socks(&cands, base_port, region));

        let now = unix_now();
        let new_cnt = verified.len();
        let final_nodes = {
            let mut g = write_data(&self.data);
            for ep in failed_eps {
                g.blacklist.insert(ep, now);
            }
            if !verified.is_empty() {
                // CRITICAL FIX: ONLY merge with previously DEVICE-VERIFIED live nodes (age < 6h)!
                // Unverified datacenter `bootstrap_seed.json` nodes are dropped immediately so they
                // can NEVER outrank a server verified live on the user's own RF ISP!
                let new_ids: HashSet<String> = verified.iter().map(|n| n.id.clone()).collect();
                let mut merged = verified.clone();
                for old in &g.vpn_nodes {
                    let max_age = if old.protocol == "opera" {
                        45 * 60
                    } else {
                        10 * 3600
                    };
                    if old.device_verified
                        && !new_ids.contains(&old.id)
                        && old.fail_count < 2
                        && now.saturating_sub(old.verified_unix) < max_age
                    {
                        merged.push(old.clone());
                    }
                }
                merged.sort_by_key(|n| {
                    let http_pen = if matches!(n.protocol.as_str(), "opera" | "http") {
                        1u8
                    } else {
                        0u8
                    };
                    (
                        !n.device_verified,
                        n.fail_count,
                        if n.source_tier == 0 { 0u8 } else { 1u8 },
                        if n.source_tier >= 4 { 1u8 } else { 0u8 },
                        region_match_rank(&n.exit_country, region),
                        http_pen,
                        n.rtt_ms,
                    )
                });
                // Preserve up to 120 live verified nodes across 15+ countries & all protocols!
                merged.truncate(120);
                g.vpn_nodes = merged;
                g.last_vpn_refresh_unix = now;
            } else {
                // Prune degraded entries even if batch added 0 new ones
                g.vpn_nodes.retain(|n| n.fail_count < 2);
            }
            g.vpn_nodes.clone()
        };
        self.save();
        PROBE_PROGRESS.finish();

        if new_cnt > 0 {
            let top = &verified[0];
            diag_ok(
                "VPN",
                format!(
                    "Пул обновлён: {new_cnt}/{total_tested} живых! Лучший: {} [{}] ({}мс, {} Кбит/с)",
                    top.name, top.display_protocol, top.rtt_ms, top.kbps
                ),
            );
        } else {
            let kept_live = final_nodes
                .iter()
                .filter(|n| n.device_verified && n.fail_count < 2)
                .count();
            diag_err(
                "VPN",
                format!(
                    "Глубокая проверка: 0/{total_tested} прошли все этапы (ранее живых в кэше: {kept_live})"
                ),
            );
        }

        let live_filtered: Vec<VerifiedVpnNode> = filter_nodes_for_region(&final_nodes, region, false)
            .into_iter()
            .filter(|n| n.device_verified && n.fail_count < 3)
            .collect();

        json!({
            "ok": true,
            "testedCount": total_tested,
            "newlyVerified": new_cnt,
            "liveAvailable": live_filtered.len(),
            "nodes": live_filtered,
            "allNodes": final_nodes
        })
        .to_string()
    }

    /// Build production Android `xray-rust` TUN configuration for the chosen region / pinned node.
    pub fn build_tun_config(
        &self,
        target_region: &str,
        pinned_node_id: &str,
        whitelist_mode: bool,
        bypass_ru: bool,
        fragment_tls: bool,
        local_socks_port: u16,
    ) -> String {
        self.build_tun_config_ex(
            target_region,
            pinned_node_id,
            whitelist_mode,
            bypass_ru,
            fragment_tls,
            true,
            local_socks_port,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn build_tun_config_ex(
        &self,
        target_region: &str,
        pinned_node_id: &str,
        whitelist_mode: bool,
        bypass_ru: bool,
        fragment_tls: bool,
        adblock: bool,
        local_socks_port: u16,
    ) -> String {
        self.build_tun_config_v16(
            target_region,
            pinned_node_id,
            whitelist_mode,
            bypass_ru,
            fragment_tls,
            adblock,
            true,
            false,
            local_socks_port,
            "",
            "",
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn build_tun_config_v16(
        &self,
        target_region: &str,
        pinned_node_id: &str,
        whitelist_mode: bool,
        bypass_ru: bool,
        fragment_tls: bool,
        adblock: bool,
        dual_channel: bool,
        idle_power_save: bool,
        local_socks_port: u16,
        socks_user: &str,
        socks_pass: &str,
    ) -> String {
        self.build_tun_config_v17(
            target_region,
            pinned_node_id,
            whitelist_mode,
            bypass_ru,
            fragment_tls,
            adblock,
            dual_channel,
            idle_power_save,
            local_socks_port,
            socks_user,
            socks_pass,
            "",
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn build_tun_config_v17(
        &self,
        target_region: &str,
        pinned_node_id: &str,
        whitelist_mode: bool,
        bypass_ru: bool,
        fragment_tls: bool,
        adblock: bool,
        dual_channel: bool,
        idle_power_save: bool,
        local_socks_port: u16,
        socks_user: &str,
        socks_pass: &str,
        custom_rules_json: &str,
    ) -> String {
        let region = normalize_region(target_region);
        let pinned_opt = if pinned_node_id.trim().is_empty() {
            None
        } else {
            Some(pinned_node_id.trim())
        };

        // Register ephemeral local SOCKS5 password so internal probes & TG bridge authenticate cleanly
        if local_socks_port > 0 {
            set_local_socks_auth(local_socks_port, socks_user, socks_pass);
        }

        let (all_nodes, warp_snapshot, last_refresh) = {
            let g = read_data(&self.data);
            (
                g.vpn_nodes.clone(),
                g.warp.clone(),
                g.last_vpn_refresh_unix,
            )
        };
        let any_device_verified = all_nodes.iter().any(|n| {
            n.device_verified && n.fail_count < 3 && !n.exit_country.eq_ignore_ascii_case("RU")
        });
        let any_foreign_verified = all_nodes.iter().any(|n| {
            n.device_verified
                && n.fail_count < 3
                && !matches!(n.exit_country.as_str(), "CF" | "RU" | "ru")
                && (n.source_tier == 0 || n.source_tier <= 3)
        });

        if pinned_opt.is_none() && !any_device_verified {
            let has_untested_seeds = all_nodes
                .iter()
                .any(|n| !n.device_verified && n.fail_count < 2 && !n.via_warp);
            return json!({
                "ok": false,
                "needsSeedProbe": has_untested_seeds,
                "needsRefresh": true,
                "error": "Проверка серверов для вашей сети…"
            })
            .to_string();
        }

        let now = unix_now();
        if pinned_opt.is_none() && !any_foreign_verified && now.saturating_sub(last_refresh) > 90 {
            return json!({
                "ok": false,
                "needsSeedProbe": false,
                "needsRefresh": true,
                "error": "Подбор зарубежных серверов через MASQUE…"
            })
            .to_string();
        }

        let eff_wl = whitelist_mode || region == "WL";
        let is_strict_country = region.len() == 2 && !matches!(region, "EU" | "WL" | "YT");

        let live_only: Vec<VerifiedVpnNode> = all_nodes
            .into_iter()
            .filter(|n| {
                // Zero-RU guarantee: never mount a domestic Russian exit server!
                if n.exit_country.eq_ignore_ascii_case("RU") {
                    return false;
                }
                let is_pin = pinned_opt == Some(n.id.as_str());
                let stale_op = !is_pin
                    && n.protocol == "opera"
                    && n.verified_unix > 0
                    && now.saturating_sub(n.verified_unix) > 45 * 60;
                !stale_op && n.fail_count < 3 && (is_pin || n.device_verified)
            })
            .collect();

        // Count strictly matching healthy nodes for the chosen region/country
        let strict_matches: Vec<VerifiedVpnNode> = live_only
            .iter()
            .filter(|n| n.device_verified && node_matches_strict_region(n, region, eff_wl))
            .cloned()
            .collect();
        let strict_match_cnt = strict_matches.len();

        // STRICT COUNTRY GUARANTEE: When the user selected a specific country (e.g. Germany `DE`,
        // USA `US`, Finland `FI`, Netherlands `NL`, etc.) or `WL`/`YT`, NEVER silently connect to
        // a different country! Immediately ask `VeloxVpnService` to probe servers of THAT country!
        if pinned_opt.is_none() && strict_match_cnt == 0 {
            if eff_wl {
                return json!({
                    "ok": false,
                    "needsSeedProbe": false,
                    "needsRefresh": true,
                    "needsWhitelistRefresh": true,
                    "strictRegion": region,
                    "error": "Подбор рабочих серверов «Белые списки РФ» (SNI + CIDR)…"
                })
                .to_string();
            }
            if is_strict_country || matches!(region, "YT" | "EU") {
                return json!({
                    "ok": false,
                    "needsSeedProbe": false,
                    "needsRefresh": true,
                    "strictRegion": region,
                    "error": format!("Подбор рабочих серверов {region}…")
                })
                .to_string();
            }
        }

        // Build ordered pool: strictly same-country for specific countries, best overall for AUTO
        let mut pool = if let Some(pid) = pinned_opt {
            let mut v: Vec<VerifiedVpnNode> =
                live_only.iter().filter(|n| n.id == pid).cloned().collect();
            let rest = if is_strict_country || eff_wl || matches!(region, "YT" | "EU") {
                filter_nodes_for_region(&strict_matches, region, eff_wl)
            } else {
                filter_nodes_for_region(&live_only, region, eff_wl)
            };
            for n in rest {
                if n.id != pid {
                    v.push(n);
                }
            }
            v
        } else if is_strict_country || eff_wl || matches!(region, "YT" | "EU") {
            filter_nodes_for_region(&strict_matches, region, eff_wl)
        } else {
            filter_nodes_for_region(&live_only, region, eff_wl)
        };

        // Fallback to any live node ONLY in AUTO/WARP mode (NEVER on a specific selected country!)
        if pool.is_empty() && !is_strict_country && !eff_wl {
            pool = live_only.clone();
            pool.sort_by_key(|n| {
                (
                    !n.device_verified,
                    n.fail_count,
                    if n.source_tier == 0 { 0u8 } else { 1u8 },
                    if n.source_tier >= 4 { 1u8 } else { 0u8 },
                    region_match_rank(&n.exit_country, region),
                    n.rtt_ms,
                )
            });
        }

        if pool.is_empty() {
            return json!({
                "ok": false,
                "needsSeedProbe": false,
                "needsRefresh": true,
                "strictRegion": region,
                "error": format!("Серверы {region} исчерпаны — запускаю поиск новых…")
            })
            .to_string();
        }

        // Append healthy `yt_ad_free` servers at tail for YouTube 0%-ad domain split ONLY
        // (`build_production_tun_config_v16` strictly filters primary & standby by `region`!)
        if adblock {
            for yn in &live_only {
                if yn.yt_ad_free && yn.device_verified && !pool.iter().any(|p| p.id == yn.id) {
                    pool.push(yn.clone());
                }
            }
        }

        let auth_opt = if !socks_user.is_empty() && !socks_pass.is_empty() {
            Some((socks_user, socks_pass))
        } else {
            None
        };
        let custom_rules = CustomDomainRules::from_json_str(custom_rules_json);

        // Include full verified foreign pool so `standby_priority_key` always finds #1 same-country
        // and #2 Germany/USA reserves even if `filter_nodes_for_region` truncated!
        for vn in &live_only {
            if vn.device_verified
                && !vn.exit_country.eq_ignore_ascii_case("RU")
                && !pool.iter().any(|p| p.id == vn.id)
                && (!is_strict_country || node_matches_strict_region(vn, region, eff_wl))
            {
                pool.push(vn.clone());
            }
        }

        match build_production_tun_config_v17(
            &pool,
            pinned_opt,
            region,
            eff_wl,
            bypass_ru,
            fragment_tls,
            adblock,
            dual_channel,
            idle_power_save,
            local_socks_port,
            auth_opt,
            Some(&warp_snapshot),
            Some(&custom_rules),
        ) {
            Ok(plan) => {
                let primary = plan.primary;
                let standby = plan.standby;
                let standby_tier = plan.standby_tier;
                let age_sec = now.saturating_sub(primary.verified_unix);
                let freshly_verified =
                    primary.device_verified && age_sec <= 900 && primary.fail_count == 0;
                // Replenish quietly if we lack a standby OR if standby isn't yet same-country or DE/US!
                let needs_standby_replenish = dual_channel
                    && (standby.is_none()
                        || (standby_tier == "foreign" && now.saturating_sub(last_refresh) > 300))
                    && now.saturating_sub(last_refresh) > 45;
                let tier_lbl = match standby_tier.as_str() {
                    "same_country" => "та же страна",
                    "de_us" => "приоритет DE/US",
                    "foreign" => "зарубеж.",
                    _ => "поиск",
                };
                let sb_desc = match &standby {
                    Some(sb) => format!(
                        "{} [{} · {} · {}мс]",
                        sb.name, sb.exit_country, tier_lbl, sb.rtt_ms
                    ),
                    None => "поиск резерва".to_string(),
                };
                diag_info(
                    "VPN",
                    format!(
                        "Старт TUN [{}] -> #1 {} [{}] ({}, {}мс) | #2 резерв 0мс: {} | yt={}",
                        region,
                        primary.name,
                        primary.display_protocol,
                        primary.exit_country,
                        primary.rtt_ms,
                        if dual_channel { sb_desc.as_str() } else { "выкл" },
                        plan.yt_mode_desc
                    ),
                );
                let sb_json = standby
                    .as_ref()
                    .map(compact_node_json)
                    .unwrap_or(serde_json::Value::Null);
                let pri_json = compact_node_json(&primary);
                json!({
                    "ok": true,
                    "configJson": plan.config_json,
                    "activeNode": pri_json,
                    "primary": pri_json,
                    "standbyNode": sb_json,
                    "standbyTier": standby_tier,
                    "dualChannelActive": plan.dual_channel_active,
                    "needsStandbyReplenish": needs_standby_replenish,
                    "firstTag": "vpn_0",
                    "viaWarp": primary.via_warp,
                    "ytMode": plan.yt_mode_desc,
                    "whitelistActive": eff_wl && primary.whitelist_friendly,
                    "freshlyVerified": freshly_verified,
                    "primaryVerified": primary.device_verified,
                    "needsRegionRefresh": false,
                    "backupCount": plan.standby_pool_count
                })
                .to_string()
            }
            Err(e) => {
                diag_err("VPN", format!("Ошибка сборки TUN-конфига: {e}"));
                json!({
                    "ok": false,
                    "needsRefresh": true,
                    "strictRegion": region,
                    "error": e
                })
                .to_string()
            }
        }
    }

    /// Mark a node as failed/degraded with full diagnostic context and return remaining live count
    /// strictly scoped to `target_region` (so selecting Germany counts ONLY live Germany standbys!).
    pub fn report_node_failure(
        &self,
        node_id: &str,
        target_region: &str,
        reason: &str,
    ) -> String {
        let region = normalize_region(target_region);
        let eff_wl = region == "WL";
        let now = unix_now();
        let (node_desc, remaining_live) = {
            let mut g = write_data(&self.data);
            let mut bad_ep = None;
            let mut desc = node_id.to_string();
            let instant_evict = reason.contains("startupProbe")
                || reason.contains("ручная смена")
                || reason.contains("РФ (RU)");
            for n in &mut g.vpn_nodes {
                if n.id == node_id {
                    n.fail_count = if instant_evict {
                        3
                    } else {
                        n.fail_count.saturating_add(1).min(3)
                    };
                    n.ok_streak = 0;
                    n.last_fail_unix = now;
                    if reason.contains("РФ (RU)") {
                        n.exit_country = "RU".into();
                    }
                    desc = format!(
                        "{} [{}] {} sni={} (сбой #{})",
                        n.name,
                        n.display_protocol,
                        fmt_endpoint(&n.host, n.port),
                        if n.sni.is_empty() { "-" } else { &n.sni },
                        n.fail_count
                    );
                    if n.fail_count >= 2 && n.source_tier == 1 {
                        let ep = if n.via_warp {
                            format!("wchain:{}:{}", n.host.to_ascii_lowercase(), n.port)
                        } else {
                            format!("{}:{}", n.host.to_ascii_lowercase(), n.port)
                        };
                        bad_ep = Some(ep);
                    }
                }
            }
            if let Some(ep) = bad_ep {
                g.blacklist.insert(ep, now);
            }
            // Drop dead free nodes & ALL domestic RU nodes; keep foreign Tier-0 sub nodes recoverable
            g.vpn_nodes.retain(|n| {
                !n.exit_country.eq_ignore_ascii_case("RU")
                    && (n.source_tier == 0 || n.fail_count < 3)
            });
            let rem = g
                .vpn_nodes
                .iter()
                .filter(|n| {
                    n.device_verified
                        && n.fail_count < 2
                        && node_matches_strict_region(n, region, eff_wl)
                })
                .count();
            (desc, rem)
        };
        self.save();

        let reason_suffix = if reason.trim().is_empty() {
            String::new()
        } else {
            format!(" — {}", reason.trim())
        };
        diag_warn(
            "VPN",
            format!("Сбой узла: {node_desc}{reason_suffix} · резерв [{region}]: {remaining_live}"),
        );

        json!({
            "ok": true,
            "remainingLive": remaining_live,
            "healthyRemaining": remaining_live,
            "needsStandbyReplenish": remaining_live < 2,
            "needsRefresh": remaining_live == 0
        })
        .to_string()
    }

    /// Reward a node that verified clean in live tunnel operation — boosts its stability streak
    /// (`ok_streak`) and clears transient failures so rock-solid servers stay locked in!
    pub fn record_node_success(&self, node_id: &str, rtt_ms: u32) -> String {
        let mut changed = false;
        {
            let mut g = write_data(&self.data);
            for n in &mut g.vpn_nodes {
                if n.id == node_id {
                    let prev_streak = n.ok_streak;
                    n.ok_streak = n.ok_streak.saturating_add(1).min(20);
                    n.fail_count = 0;
                    n.last_fail_unix = 0;
                    n.device_verified = true;
                    n.verified_unix = unix_now();
                    if rtt_ms > 0 && rtt_ms < 4000 {
                        n.rtt_ms = if n.rtt_ms > 0 {
                            // Exponential moving average reduces RTT jitter spikes
                            (n.rtt_ms * 2 + rtt_ms) / 3
                        } else {
                            rtt_ms
                        };
                    }
                    // Write to disk only on meaningful streak steps (minimizes flash I/O!)
                    changed = prev_streak < 3 || n.ok_streak % 4 == 0;
                    break;
                }
            }
        }
        if changed {
            self.save();
        }
        "{\"ok\":true}".to_string()
    }

    /// On-demand 12-service live reachability, anti-RU IP & YouTube 0%-ad check (v1.7.0).
    pub fn check_services(&self, local_socks_port: u16) -> String {
        let val = TOKIO_RT.block_on(check_services_live(local_socks_port));
        let passed = val.get("passed").and_then(|v| v.as_u64()).unwrap_or(0);
        let total = val.get("total").and_then(|v| v.as_u64()).unwrap_or(12);
        let cc = val.get("exitCountry").and_then(|v| v.as_str()).unwrap_or("-");
        let ms = val.get("elapsedMs").and_then(|v| v.as_u64()).unwrap_or(0);
        diag_info(
            "SVC",
            format!(
                "Проверка сервисов ({}): {passed}/{total} доступны · IP={cc} · {ms}мс",
                if local_socks_port > 0 { "через VPN" } else { "напрямую" }
            ),
        );
        val.to_string()
    }

    /// Export a clean shareable URI for a saved VPN node (for 1-tap Copy/Share in server list).
    pub fn export_node_uri(&self, node_id: &str) -> String {
        let g = read_data(&self.data);
        if let Some(n) = g.vpn_nodes.iter().find(|n| n.id == node_id) {
            let uri = n.raw_uri.trim();
            if !uri.is_empty() && !uri.starts_with("warp-") && !uri.starts_with("opera:") {
                return json!({
                    "ok": true,
                    "uri": uri,
                    "name": n.name
                })
                .to_string();
            }
        }
        json!({
            "ok": false,
            "error": "Этот встроенный узел создаётся динамически и не экспортируется в виде ссылки"
        })
        .to_string()
    }

    /// Live tunnel check for background Watchdog (runs on ultra-slim 1-thread `:vpn` runtime).
    pub fn check_tunnel_health(&self, local_socks_port: u16) -> String {
        let res: TunnelHealthResult =
            TOKIO_RT.block_on(check_active_tunnel_health(local_socks_port));
        if !res.alive {
            diag_warn(
                "WATCHDOG",
                format!("Проверка туннеля 127.0.0.1:{local_socks_port} не прошла: {}", res.error),
            );
        }
        serde_json::to_string(&res).unwrap_or_else(|_| "{\"alive\":false}".into())
    }

    /// Consolidated single-pass post-TUN HTML + DoH + GeoIP verifier (authed `127.0.0.1:10808`).
    pub fn verify_tunnel_web(&self, local_socks_port: u16, is_opera: bool) -> String {
        TOKIO_RT
            .block_on(crate::vpn_probe::verify_tunnel_web_and_geo(
                local_socks_port,
                is_opera,
            ))
            .to_string()
    }

    /// Fetch & strictly verify Telegram proxies against real Telegram DC2 (`req_pq_multi -> resPQ`)
    /// requiring response time `<= max_rtt_ms` (default 1400 ms).
    pub fn refresh_tg_proxies(&self, max_rtt_ms: u32, active_socks_port: u16) -> String {
        let limit_ms = max_rtt_ms.clamp(300, 1400);
        let proxy = socks_opt(active_socks_port);
        let (sources, custom_tg, existing_tg) = {
            let g = read_data(&self.data);
            (
                g.sources.clone(),
                g.custom_tg_links.clone(),
                g.tg_proxies.clone(),
            )
        };

        diag_info(
            "TG",
            format!(
                "Умное обновление TG-прокси (MTProto resPQ к DC2 ≤{limit_ms}мс, в кэше:{}, источников:{})",
                existing_tg.len(),
                sources.iter().filter(|s| s.enabled && s.kind == "tg").count()
            ),
        );

        let t0 = Instant::now();
        let prog = self.tg_progress.clone();
        let ((verified, kept_cnt, added_cnt, removed_cnt), ws_res) = TOKIO_RT.block_on(async {
            tokio::join!(
                fetch_and_verify_tg_proxies_delta(
                    &sources,
                    &custom_tg,
                    &existing_tg,
                    limit_ms,
                    proxy,
                    Some(prog)
                ),
                probe_tg_ws_direct(limit_ms)
            )
        });

        match ws_res {
            Ok(ms) => {
                self.tg_bridge.ws_rtt_ms.store(ms, Ordering::Relaxed);
                self.tg_bridge.ws_available.store(true, Ordering::Relaxed);
                diag_ok("BRIDGE", format!("Прямой WebSocket TG-WS (kws2:443) доступен: {ms}мс"));
            }
            Err(e) => {
                self.tg_bridge.ws_available.store(false, Ordering::Relaxed);
                diag_warn("BRIDGE", format!("Прямой TG-WS (kws2) недоступен: {e} -> используем пул"));
            }
        }

        let final_list = {
            let mut g = write_data(&self.data);
            if !verified.is_empty() {
                g.tg_proxies = verified.clone();
                g.last_tg_refresh_unix = unix_now();
            } else {
                g.tg_proxies.retain(|p| p.rtt_ms <= limit_ms);
            }
            g.tg_proxies.clone()
        };

        self.tg_bridge.update_pool(&final_list);
        self.save();

        let checked = self.tg_progress.checked.load(Ordering::Relaxed);
        let best_ms = final_list.first().map(|p| p.rtt_ms).unwrap_or(0);
        let ftls_cnt = final_list.iter().filter(|p| p.kind == "faketls").count();
        let socks_cnt = final_list.iter().filter(|p| p.kind == "socks5").count();
        if !verified.is_empty() {
            diag_ok(
                "TG",
                format!(
                    "Готово за {}мс: {}/{checked} живых ≤{limit_ms}мс (+{added_cnt} новых, ={kept_cnt} сохр., -{removed_cnt} убрано · FakeTLS:{ftls_cnt}, SOCKS5:{socks_cnt}, лучший:{best_ms}мс)",
                    t0.elapsed().as_millis(),
                    final_list.len()
                ),
            );
        } else {
            diag_warn(
                "TG",
                format!(
                    "Свежие TG-прокси не ответили за {limit_ms}мс (проверено:{checked}, в кэше:{})",
                    final_list.len()
                ),
            );
        }

        json!({
            "ok": true,
            "count": final_list.len(),
            "keptAlive": kept_cnt,
            "newlyAdded": added_cnt,
            "removedDead": removed_cnt,
            "maxRttMs": limit_ms,
            "wsAvailable": self.tg_bridge.ws_available.load(Ordering::Relaxed),
            "wsRttMs": self.tg_bridge.ws_rtt_ms.load(Ordering::Relaxed),
            "proxies": final_list
        })
        .to_string()
    }

    pub fn start_local_tg_bridge(&self, port: u16, max_rtt_ms: u32) -> String {
        let limit_ms = max_rtt_ms.clamp(300, 1400);
        let proxies = { read_data(&self.data).tg_proxies.clone() };
        let socks_cnt = proxies.iter().filter(|p| p.kind == "socks5").count();
        self.tg_bridge.update_pool(&proxies);
        let bridge = self.tg_bridge.clone();
        match TOKIO_RT.block_on(start_tg_bridge(bridge, port, limit_ms)) {
            Ok(bound) => {
                let ws_ok = self.tg_bridge.ws_available.load(Ordering::Relaxed);
                let ws_ms = self.tg_bridge.ws_rtt_ms.load(Ordering::Relaxed);
                diag_ok(
                    "BRIDGE",
                    format!(
                        "TG-WS-Bridge запущен на 127.0.0.1:{bound} (TG-WS: {}, SOCKS5 резерв: {socks_cnt})",
                        if ws_ok {
                            format!("OK {ws_ms}мс")
                        } else {
                            "авто-резерв".into()
                        }
                    ),
                );
                json!({
                    "ok": true,
                    "port": bound,
                    "tgLink": format!("tg://socks?server=127.0.0.1&port={bound}"),
                    "tmeLink": format!("https://t.me/socks?server=127.0.0.1&port={bound}")
                })
                .to_string()
            }
            Err(e) => {
                diag_err("BRIDGE", format!("Ошибка старта TG-WS-Bridge (порт {port}): {e}"));
                json!({ "ok": false, "error": e }).to_string()
            }
        }
    }

    pub fn stop_local_tg_bridge(&self) -> String {
        let was_running = self.tg_bridge.running.load(Ordering::Relaxed);
        self.tg_bridge.stop();
        if was_running {
            diag_info("BRIDGE", "TG-WS-Bridge остановлен");
        }
        json!({ "ok": true }).to_string()
    }

    pub fn get_tg_status(&self) -> String {
        let b = &self.tg_bridge;
        let p = &self.tg_progress;
        let port = b.port.load(Ordering::Relaxed);
        json!({
            "total": p.total.load(Ordering::Relaxed),
            "checked": p.checked.load(Ordering::Relaxed),
            "alive": p.alive.load(Ordering::Relaxed),
            "bridgeRunning": b.running.load(Ordering::Relaxed),
            "bridgePort": port,
            "bridgeLink": format!("tg://socks?server=127.0.0.1&port={port}"),
            "bridgeSessions": b.active_sessions.load(Ordering::Relaxed),
            "bridgeBytes": b.relayed_bytes.load(Ordering::Relaxed),
            "wsAvailable": b.ws_available.load(Ordering::Relaxed),
            "wsRttMs": b.ws_rtt_ms.load(Ordering::Relaxed)
        })
        .to_string()
    }

    pub fn get_probe_progress(&self) -> String {
        PROBE_PROGRESS.to_json()
    }

    pub fn append_diag_log(&self, level: &str, tag: &str, message: &str) {
        diag_log(level, tag, message);
    }

    pub fn read_diag_logs_json(&self, max_lines: usize) -> String {
        let lines = read_diag_logs(max_lines);
        json!({ "logs": lines }).to_string()
    }

    pub fn clear_diag_logs_json(&self) -> String {
        clear_diag_logs();
        json!({ "ok": true, "logs": read_diag_logs(50) }).to_string()
    }

    /// Smart universal import with REAL immediate fetch, parsing, incremental diff, and validation!
    /// Accepts:
    /// - Any VPN/TG subscription URL: `https://...`, `http://...`, `ssconf://...` (Remnawave,
    ///   Marzban, Happ, 3x-ui, PasarGuard, Hiddify, V2Board, GitHub, Codeberg)
    /// - Any app deep-link: `happ://add/...`, `v2raytun://import/...`, `v2rayng://...`, `hiddify://...`,
    ///   `streisand://...`, `sing-box://import-remote-profile?url=...`, `clash://install-config?url=...`
    /// - Single OR multi-line VPN keys: `vless://`, `vmess://`, `hy2://`, `hysteria2://`, `trojan://`, `ss://`
    /// - Telegram proxy links: `tg://proxy`, `https://t.me/proxy`, `tg://socks`, `socks5://`
    /// Universal v1.6.0 import engine — supports EVERYTHING Happ, Incy, v2RayTun, Hiddify,
    /// v2rayNG, sing-box, Clash & Streisand support:
    /// - Offline RSA/AES decryption of `happ://crypt/...`, `crypt2`, `crypt3`, `crypt4`, `crypt5`!
    /// - HTTPS-wrapped crypto redirects (`https://go.example.com/happ://crypt5/...`) & `incy://crypt1/...`!
    /// - Happ AES-128-GCM body-encrypted responses (`Encrypt-Tag`), Xray JSON & JSON Array payloads!
    /// - Multi-client deep-links (`happ://add/`, `v2raytun://`, `hiddify://`, `v2rayng://`, `sing-box://`, `clash://`, `streisand://`, `ssconf://`)!
    /// - Single/multi-line VPN keys (`vless://` incl. PQ `mlkem768x25519plus` & `pcs`/`pqv`/`extra`, `vmess://`, `hy2://`, `trojan://`, `ss://`, `wireguard://`, `.conf`, `socks5://`, `https://user:pass@`)!
    /// - Raw Xray JSON outbound configs (`{"outbounds":[...]}`)!
    /// - Telegram proxies (`tg://proxy`, `https://t.me/proxy`, `tg://socks`, `socks5://`)!
    pub fn add_custom_item(&self, raw_input: &str, kind_hint: &str, max_tg_rtt_ms: u32) -> String {
        let input = raw_input.trim();
        if input.is_empty() {
            return json!({ "ok": false, "error": "Пустая строка" }).to_string();
        }

        // 1. Single-line subscription URL, `happ://crypt..crypt5`, `incy://crypt1`, or client deep-link
        let single_line = input.lines().filter(|l| !l.trim().is_empty()).count() == 1;
        if single_line {
            // Check single-node deep-links first (e.g. `happ://import/vless://...`, `v2raytun://import/vless://...`)
            for inline_pfx in ["happ://import/", "v2raytun://import/", "velox://import/"] {
                if let Some(rest) = input.strip_prefix(inline_pfx) {
                    let dec = percent_encoding::percent_decode_str(rest)
                        .decode_utf8_lossy()
                        .trim()
                        .to_string();
                    if dec.starts_with("vless://")
                        || dec.starts_with("vmess://")
                        || dec.starts_with("trojan://")
                        || dec.starts_with("ss://")
                        || dec.starts_with("hy2://")
                        || dec.starts_with("hysteria2://")
                        || dec.starts_with("wireguard://")
                    {
                        return self.add_custom_item(&dec, kind_hint, max_tg_rtt_ms);
                    }
                }
            }

            match unwrap_or_decrypt_subscription(input) {
                Some(Ok(unw)) => {
                    if kind_hint == "manifest" && unw.fetch_url.starts_with("https://") {
                        {
                            let mut g = write_data(&self.data);
                            g.manifest_url = unw.fetch_url;
                        }
                        self.save();
                        return json!({
                            "ok": true,
                            "type": "manifest",
                            "message": "Манифест сохранён"
                        })
                        .to_string();
                    }
                    if !unw.encrypted_kind.is_empty() {
                        diag_ok(
                            "HAPP",
                            format!(
                                "Расшифрована ссылка happ://{} офлайн (без передачи на сторонние серверы)",
                                unw.encrypted_kind
                            ),
                        );
                    }
                    return self.fetch_and_upsert_subscription_ex(
                        &unw.full_url,
                        &unw.fetch_url,
                        &unw.hint_title,
                        &unw.encrypted_kind,
                        unw.prefer_happ_ua,
                        kind_hint,
                        max_tg_rtt_ms,
                        crate::net_util::active_local_socks_port(),
                    );
                }
                Some(Err(err_msg)) => {
                    diag_warn("HAPP", format!("Ошибка расшифровки ссылки: {err_msg}"));
                    return json!({
                        "ok": false,
                        "error": err_msg
                    })
                    .to_string();
                }
                None => {}
            }
        }

        // 2. Telegram proxy link -> verify immediately against real Telegram DC2!
        if input.starts_with("tg://")
            || input.starts_with("https://t.me/proxy")
            || input.starts_with("https://t.me/socks")
            || input.starts_with("socks5://")
            || kind_hint == "tg_proxy"
        {
            let Some(cand) = parse_single_tg_token(input, true) else {
                return json!({ "ok": false, "error": "Неверный формат ссылки прокси Telegram" })
                    .to_string();
            };
            let limit = max_tg_rtt_ms.clamp(300, 1400);
            match TOKIO_RT.block_on(verify_tg_candidate_strict(&cand, limit)) {
                Ok(verified) => {
                    let rtt = verified.rtt_ms;
                    {
                        let mut g = write_data(&self.data);
                        if !g.custom_tg_links.contains(&cand.tg_link) {
                            g.custom_tg_links.push(cand.tg_link.clone());
                        }
                        g.tg_proxies.retain(|p| p.id != verified.id);
                        g.tg_proxies.insert(0, verified.clone());
                        self.tg_bridge.update_pool(&g.tg_proxies);
                    }
                    self.save();
                    diag_ok(
                        "TG",
                        format!(
                            "Импортирован и проверен TG-прокси {}:{} ({}) -> {rtt}мс",
                            verified.host, verified.port, verified.kind_label
                        ),
                    );
                    return json!({
                        "ok": true,
                        "type": "tg_proxy",
                        "message": format!("Прокси работает! Отклик DC Telegram: {rtt} мс"),
                        "proxy": verified
                    })
                    .to_string();
                }
                Err(e) => {
                    diag_warn("TG", format!("Импорт TG-прокси отклонён: {e}"));
                    return json!({
                        "ok": false,
                        "error": format!("Прокси не прошёл проверку DC Telegram (≤{limit} мс): {e}")
                    })
                    .to_string();
                }
            }
        }

        // 3. Single OR multi-line OR raw-Base64 VPN keys (`vless://`, `vmess://`, `hy2://`, `trojan://`, `ss://`)
        let parsed_uris = extract_vpn_uris_from_subscription(input, 80);
        if !parsed_uris.is_empty() {
            let mut added = 0usize;
            let mut first_name = String::new();
            {
                let mut g = write_data(&self.data);
                for uri in parsed_uris.iter().rev() {
                    if first_name.is_empty() {
                        if let Some(c) = parse_share_uri_to_candidate(uri, "AUTO", 0, false) {
                            first_name = c.name;
                        }
                    }
                    if !g.custom_vpn_uris.iter().any(|u| u == uri) {
                        g.custom_vpn_uris.insert(0, uri.clone());
                        added += 1;
                    }
                }
                g.custom_vpn_uris.truncate(120);
            }
            self.save();
            let total = parsed_uris.len();
            let msg = if total == 1 {
                format!("Ключ «{first_name}» добавлен — проверяю соединение…")
            } else {
                format!("Импортировано {total} VPN-ключей (новых: {added}) — проверяю рабочие…")
            };
            diag_ok("VPN", format!("Импорт VPN-ключей: всего={total}, новых={added}"));
            return json!({
                "ok": true,
                "type": "vpn_key",
                "needsCustomProbe": true,
                "importedCount": total,
                "message": msg
            })
            .to_string();
        }

        // 4. Raw Xray-core JSON config (`{"outbounds":[...]}` or array of Xray configs)
        if input.starts_with('{') || input.starts_with('[') {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(input) {
                let items: Vec<&serde_json::Value> = match &val {
                    serde_json::Value::Array(arr) => arr.iter().collect(),
                    obj => vec![obj],
                };
                let mut staged_nodes = Vec::new();
                for item in items {
                    for c in parse_xray_json_config_to_candidates(item, "Xray JSON", "AUTO", 0) {
                        if !c.whitelist_friendly && is_pure_russia_exit_remark(&c.name) {
                            continue;
                        }
                        let proto_lbl = crate::xray_config::human_protocol_label(&c);
                        let guess_cc = detect_country_from_name(&c.name, &c.region_hint);
                        staged_nodes.push(VerifiedVpnNode {
                            id: c.id,
                            name: c.name,
                            display_protocol: proto_lbl,
                            protocol: c.protocol,
                            host: c.host,
                            port: c.port,
                            sni: c.sni,
                            exit_country: guess_cc.clone(),
                            exit_colo: String::new(),
                            exit_ip: String::new(),
                            rtt_ms: 0,
                            kbps: 0,
                            passed_32kb: false,
                            whitelist_friendly: c.whitelist_friendly,
                            fragment_enabled: c.fragment_enabled,
                            via_warp: false,
                            device_verified: false,
                            yt_ad_free: matches!(guess_cc.as_str(), "AL" | "MD" | "MC" | "AD"),
                            yt_country: String::new(),
                            source_tier: 0,
                            raw_uri: c.raw_uri,
                            outbound_json: c.outbound_json,
                            verified_unix: 0,
                            fail_count: 0,
                            ok_streak: 0,
                            last_fail_unix: 0,
                        });
                    }
                }
                if !staged_nodes.is_empty() {
                    let total = staged_nodes.len();
                    let first_name = staged_nodes[0].name.clone();
                    {
                        let mut g = write_data(&self.data);
                        let ids: HashSet<String> = staged_nodes.iter().map(|n| n.id.clone()).collect();
                        g.vpn_nodes.retain(|n| !ids.contains(&n.id));
                        staged_nodes.append(&mut g.vpn_nodes);
                        staged_nodes.truncate(128);
                        g.vpn_nodes = staged_nodes;
                    }
                    self.save();
                    diag_ok("VPN", format!("Импортирован Xray JSON: {total} серверов"));
                    return json!({
                        "ok": true,
                        "type": "vpn_key",
                        "needsCustomProbe": true,
                        "importedCount": total,
                        "message": if total == 1 {
                            format!("Xray JSON «{first_name}» добавлен — проверяю соединение…")
                        } else {
                            format!("Импортировано {total} серверов из Xray JSON — проверяю…")
                        }
                    })
                    .to_string();
                }
            }
        }

        json!({
            "ok": false,
            "error": "Поддерживаются https:// подписки, happ://crypt1–5, happ://add, incy://crypt1, v2raytun://, hiddify://, vless://, vmess://, hy2://, trojan://, ss://, wireguard:// (.conf), Xray JSON и tg://proxy"
        })
        .to_string()
    }

    pub fn fetch_and_upsert_subscription(
        &self,
        sub_url: &str,
        kind_hint: &str,
        max_tg_rtt_ms: u32,
        active_socks_port: u16,
    ) -> String {
        let fetch_url = fetch_url_without_fragment(sub_url);
        let (enc_kind, body_enc, pref_happ) = {
            let g = read_data(&self.data);
            g.sources
                .iter()
                .find(|s| s.url == sub_url)
                .map(|s| (s.encrypted_kind.clone(), s.body_encrypted, s.prefer_happ_ua))
                .unwrap_or_default()
        };
        self.fetch_and_upsert_subscription_ex(
            sub_url,
            &fetch_url,
            "",
            &enc_kind,
            pref_happ || body_enc,
            kind_hint,
            max_tg_rtt_ms,
            active_socks_port,
        )
    }

    /// Full Happ 4.11+ / Remnawave / Marzban / 3x-ui / Shuka subscription importer:
    /// - Offline `happ://crypt..crypt5` + AES-128-GCM body decryption + Xray JSON + share URIs
    /// - Opt-in `X-HWID` device binding + clear limit diagnostics
    /// - Rich metadata (`upload/download/total_bytes`, `expire_unix`, `announce`, `support_url`, `web_page_url`, `update_interval_hours`)
    /// - Retains cached working servers on temporary 4xx/5xx/network errors (zero disruption!)
    #[allow(clippy::too_many_arguments)]
    pub fn fetch_and_upsert_subscription_ex(
        &self,
        sub_url: &str,
        fetch_url: &str,
        name_hint: &str,
        encrypted_kind: &str,
        prefer_happ_ua: bool,
        kind_hint: &str,
        max_tg_rtt_ms: u32,
        active_socks_port: u16,
    ) -> String {
        let host_label = url::Url::parse(fetch_url)
            .ok()
            .and_then(|u| u.host_str().map(|s| s.to_string()))
            .unwrap_or_else(|| "Подписка".into());
        let proxy = socks_opt(active_socks_port);
        let (hwid_cfg, prev_body_enc, prev_cached_cnt) = {
            let g = read_data(&self.data);
            let ex = g.sources.iter().find(|s| s.url == sub_url);
            (
                g.hwid_config.clone(),
                ex.is_some_and(|s| s.body_encrypted),
                ex.map(|s| s.cached_count).unwrap_or(0),
            )
        };

        diag_info("SRC", format!("Загрузка подписки: {host_label}"));
        let fetched = match TOKIO_RT.block_on(fetch_subscription_smart_ex(
            sub_url,
            fetch_url,
            encrypted_kind,
            prev_body_enc,
            prefer_happ_ua,
            &hwid_cfg,
            proxy,
            1536 * 1024,
        )) {
            Ok(f) => f,
            Err(e) => {
                // Retain previously cached servers intact on 4xx/5xx/network error!
                let retain_note = if prev_cached_cnt > 0 {
                    format!(" (сохранено {prev_cached_cnt} ранее загруженных серверов)")
                } else {
                    String::new()
                };
                diag_err("SRC", format!("Ошибка загрузки подписки {host_label}: {e}{retain_note}"));
                return json!({
                    "ok": false,
                    "retainedCount": prev_cached_cnt,
                    "error": format!("Не удалось обновить подписку ({host_label}): {e}{retain_note}")
                })
                .to_string();
            }
        };

        let env = &fetched.envelope;
        let vpn_uris = extract_vpn_uris_from_subscription(&fetched.body, 140);
        let mut json_cands: Vec<VpnCandidate> = Vec::new();
        for jcfg in env.xray_json_configs.iter().take(64) {
            json_cands.extend(parse_xray_json_config_to_candidates(
                jcfg,
                &host_label,
                "AUTO",
                0,
            ));
        }
        let cached_json_obs: Vec<serde_json::Value> = json_cands
            .iter()
            .take(64)
            .map(|c| {
                let mut m = c.outbound_json.clone();
                if let Some(o) = m.as_object_mut() {
                    o.insert("remarks".into(), json!(c.name));
                }
                m
            })
            .collect();

        let title = if !fetched.profile_title.is_empty() {
            fetched.profile_title.clone()
        } else if !name_hint.trim().is_empty() {
            name_hint.trim().chars().take(48).collect()
        } else if !encrypted_kind.is_empty() {
            format!("Happ · {host_label}")
        } else {
            format!("Подписка · {host_label}")
        };
        let new_hash = content_hash_short(&format!("{}:{}", fetched.body, cached_json_obs.len()));
        let now = unix_now();

        // Case A: Subscription contains valid VPN servers (share URIs and/or Xray JSON outbounds)!
        if (!vpn_uris.is_empty() || !json_cands.is_empty()) && kind_hint != "tg" {
            let count = vpn_uris.len() + json_cands.len();
            let added_cnt: usize;
            let removed_cnt: usize;
            let mut unchanged = false;

            {
                let mut g = write_data(&self.data);
                let prev_uris: HashSet<String> = g
                    .sources
                    .iter()
                    .find(|s| s.url == sub_url)
                    .map(|s| s.cached_uris.iter().cloned().collect())
                    .unwrap_or_default();
                let mut all_next_raws: HashSet<String> = vpn_uris.iter().cloned().collect();
                for jc in &json_cands {
                    all_next_raws.insert(jc.raw_uri.clone());
                }

                let removed_uris: HashSet<String> =
                    prev_uris.difference(&all_next_raws).cloned().collect();
                removed_cnt = removed_uris.len();
                added_cnt = all_next_raws.difference(&prev_uris).count();
                if !removed_uris.is_empty() {
                    g.vpn_nodes
                        .retain(|n| !(n.source_tier == 0 && removed_uris.contains(&n.raw_uri)));
                }
                // Reset fail_count on re-synced custom nodes so temporarily flaky paid nodes recover cleanly
                for n in &mut g.vpn_nodes {
                    if n.source_tier == 0 && all_next_raws.contains(&n.raw_uri) {
                        n.fail_count = 0;
                    }
                }
                let has_present_nodes = g
                    .vpn_nodes
                    .iter()
                    .any(|n| n.source_tier == 0 && all_next_raws.contains(&n.raw_uri));

                let hwid_badge = match env.hwid_status.as_str() {
                    "limit_reached" => "лимит исчерпан".to_string(),
                    "hwid_required" => "требуется HWID".to_string(),
                    other => other.to_string(),
                };
                let effective_url = if encrypted_kind.is_empty()
                    && fetched.migrated_url.starts_with("https://")
                    && fetched.migrated_url != sub_url
                {
                    diag_info("SRC", "Панель обновила адрес подписки (заголовок new-url)");
                    fetched.migrated_url.clone()
                } else {
                    sub_url.to_string()
                };
                let meta_src = SubSource {
                    name: title.clone(),
                    url: effective_url,
                    kind: "vpn".into(),
                    region_hint: "AUTO".into(),
                    enabled: true,
                    builtin: false,
                    userinfo: fetched.userinfo.clone(),
                    upload_bytes: env.upload_bytes,
                    download_bytes: env.download_bytes,
                    total_bytes: env.total_bytes,
                    expire_unix: env.expire_unix,
                    update_interval_hours: env.update_interval_hours,
                    announce: env.announce.clone(),
                    support_url: env.support_url.clone(),
                    web_page_url: env.web_page_url.clone(),
                    hwid_status: hwid_badge,
                    encrypted_kind: encrypted_kind.to_string(),
                    body_encrypted: env.body_encrypted,
                    prefer_happ_ua: prefer_happ_ua
                        || env.body_encrypted
                        || !encrypted_kind.is_empty()
                        || fetched.via_tag.starts_with("Happ"),
                    cached_count: count as u32,
                    last_sync_unix: now,
                    content_hash: new_hash.clone(),
                    cached_uris: vpn_uris.clone(),
                    cached_json_outbounds: cached_json_obs,
                };

                if let Some(existing) = g.sources.iter_mut().find(|s| s.url == sub_url) {
                    unchanged = existing.content_hash == new_hash
                        && existing.cached_count > 0
                        && has_present_nodes;
                    *existing = meta_src;
                } else {
                    g.sources.insert(0, meta_src);
                }

                let existing_raws: HashSet<String> =
                    g.vpn_nodes.iter().map(|n| n.raw_uri.clone()).collect();
                let mut staged = Vec::new();
                let uri_cands = vpn_uris.iter().filter_map(|uri| {
                    if existing_raws.contains(uri) {
                        return None;
                    }
                    let is_real = uri.contains("security=reality");
                    parse_share_uri_to_candidate(uri, "AUTO", 0, !is_real)
                });
                let extra_json_cands = json_cands
                    .iter()
                    .filter(|c| !existing_raws.contains(&c.raw_uri))
                    .cloned();
                let mut skipped_ru_cnt = 0usize;
                for c in uri_cands.chain(extra_json_cands) {
                    // Automatically skip domestic Russian (`🇷🇺 Россия`) exits in subscriptions
                    // (while preserving genuine foreign-exit mobile whitelist relay bridges!)
                    if !c.whitelist_friendly && is_pure_russia_exit_remark(&c.name) {
                        skipped_ru_cnt += 1;
                        continue;
                    }
                    let proto_lbl = crate::xray_config::human_protocol_label(&c);
                    let guess_cc = detect_country_from_name(&c.name, &c.region_hint);
                    let guess_yt_free = matches!(guess_cc.as_str(), "AL" | "MD" | "MC" | "AD");
                    staged.push(VerifiedVpnNode {
                        id: c.id,
                        name: c.name,
                        display_protocol: proto_lbl,
                        protocol: c.protocol,
                        host: c.host,
                        port: c.port,
                        sni: c.sni,
                        exit_country: guess_cc,
                        exit_colo: String::new(),
                        exit_ip: String::new(),
                        rtt_ms: 0,
                        kbps: 0,
                        passed_32kb: false,
                        whitelist_friendly: c.whitelist_friendly,
                        fragment_enabled: c.fragment_enabled,
                        via_warp: false,
                        device_verified: false,
                        yt_ad_free: guess_yt_free,
                        yt_country: String::new(),
                        source_tier: 0,
                        raw_uri: c.raw_uri,
                        outbound_json: c.outbound_json,
                        verified_unix: 0,
                        fail_count: 0,
                        ok_streak: 0,
                        last_fail_unix: 0,
                    });
                }
                if skipped_ru_cnt > 0 {
                    diag_info(
                        "SRC",
                        format!("Подписка «{title}»: пропущено {skipped_ru_cnt} узлов РФ (оставлены только зарубежные)"),
                    );
                }
                if !staged.is_empty() {
                    staged.append(&mut g.vpn_nodes);
                    staged.truncate(140);
                    g.vpn_nodes = staged;
                }
            }
            self.save();

            let wl_cnt = vpn_uris
                .iter()
                .filter_map(|u| parse_share_uri_to_candidate(u, "AUTO", 0, false))
                .filter(|c| c.whitelist_friendly)
                .count()
                + json_cands.iter().filter(|c| c.whitelist_friendly).count();
            let info_sfx = if fetched.userinfo.is_empty() {
                String::new()
            } else {
                format!(" ({})", fetched.userinfo)
            };
            let crypt_badge = if !encrypted_kind.is_empty() && env.body_encrypted {
                format!(" [happ://{encrypted_kind}+AES]")
            } else if !encrypted_kind.is_empty() {
                format!(" [happ://{encrypted_kind}]")
            } else if env.body_encrypted {
                " [Happ AES]".to_string()
            } else {
                String::new()
            };
            diag_ok(
                "SRC",
                format!(
                    "Подписка «{title}»{crypt_badge} [{via}]: {count} серверов (БС-РФ:{wl_cnt}, +{added_cnt}/-{removed_cnt}){info_sfx}",
                    via = fetched.via_tag
                ),
            );
            let msg = if unchanged {
                format!("«{title}»{crypt_badge}: актуальна ({count} серверов)")
            } else {
                format!("«{title}»{crypt_badge}: загружено {count} серверов{info_sfx} — проверяю…")
            };
            return json!({
                "ok": true,
                "type": "subscription",
                "subName": title,
                "userinfo": fetched.userinfo,
                "encryptedKind": encrypted_kind,
                "bodyEncrypted": env.body_encrypted,
                "announce": env.announce,
                "supportUrl": env.support_url,
                "webPageUrl": env.web_page_url,
                "importedCount": count,
                "whitelistCount": wl_cnt,
                "addedCount": added_cnt,
                "removedCount": removed_cnt,
                "unchanged": unchanged,
                "needsCustomProbe": !unchanged,
                "message": msg
            })
            .to_string();
        }

        // Case B: Telegram proxy subscription
        let tg_cands = parse_tg_proxies_from_text(&fetched.body, kind_hint == "tg_socks");
        if !tg_cands.is_empty() {
            let total_tg = tg_cands.len();
            {
                let mut g = write_data(&self.data);
                if let Some(ex) = g.sources.iter_mut().find(|s| s.url == sub_url) {
                    ex.name = title.clone();
                    ex.kind = "tg".into();
                    ex.enabled = true;
                    ex.cached_count = total_tg as u32;
                    ex.last_sync_unix = now;
                    ex.content_hash = new_hash;
                } else {
                    g.sources.insert(
                        0,
                        SubSource {
                            name: title.clone(),
                            url: sub_url.to_string(),
                            kind: "tg".into(),
                            region_hint: "TG".into(),
                            enabled: true,
                            builtin: false,
                            userinfo: fetched.userinfo.clone(),
                            cached_count: total_tg as u32,
                            last_sync_unix: now,
                            content_hash: new_hash,
                            ..Default::default()
                        },
                    );
                }
            }
            self.save();
            let _ = self.refresh_tg_proxies(max_tg_rtt_ms, active_socks_port);
            diag_ok(
                "SRC",
                format!("Добавлена TG-подписка «{title}»: {total_tg} прокси"),
            );
            return json!({
                "ok": true,
                "type": "tg_subscription",
                "subName": title,
                "importedCount": total_tg,
                "message": format!("TG-подписка «{title}» загружена ({total_tg} прокси) и проверена!")
            })
            .to_string();
        }

        let hint = if env.sing_box_only && vpn_uris.is_empty() && json_cands.is_empty() {
            "Подписка вернула конфиг только для sing-box — отключите фильтр клиента в панели или включите формат Xray/Happ"
        } else {
            "возможно, подписка истекла или заблокирована"
        };
        diag_warn(
            "SRC",
            format!(
                "В подписке {host_label} не найдено ключей ({} Б, via {}, {hint})",
                fetched.raw_bytes.len(),
                fetched.via_tag
            ),
        );
        json!({
            "ok": false,
            "error": format!("По ссылке {host_label} не найдено активных серверов ({hint})")
        })
        .to_string()
    }

    /// Build a fast dedicated Xray probe batch for all user custom subscriptions (URIs + Xray JSON) & keys!
    pub fn prepare_custom_sub_probe(&self, base_port: u16, fragment_tls: bool) -> String {
        let (uris, json_obs, staged_json_nodes, warp_acc) = {
            let g = read_data(&self.data);
            let mut list: Vec<String> = Vec::new();
            let mut jobs: Vec<serde_json::Value> = Vec::new();
            let mut seen = HashSet::new();
            for s in g.sources.iter().filter(|s| !s.builtin && s.enabled && s.kind == "vpn") {
                for u in &s.cached_uris {
                    if seen.insert(u.clone()) {
                        list.push(u.clone());
                    }
                }
                for j in &s.cached_json_outbounds {
                    jobs.push(j.clone());
                }
            }
            for u in &g.custom_vpn_uris {
                if seen.insert(u.clone()) {
                    list.push(u.clone());
                }
            }
            let standalone_json: Vec<VerifiedVpnNode> = g
                .vpn_nodes
                .iter()
                .filter(|n| n.source_tier == 0 && n.raw_uri.starts_with("xray-json://"))
                .cloned()
                .collect();
            (list, jobs, standalone_json, g.warp.clone())
        };

        let mut raw_cands: Vec<VpnCandidate> = uris
            .into_iter()
            .filter(|u| !is_dummy_banner_uri(u))
            .filter_map(|u| {
                let is_real = u.contains("security=reality");
                parse_share_uri_to_candidate(&u, "AUTO", 0, fragment_tls && !is_real)
            })
            .collect();
        for job in &json_obs {
            raw_cands.extend(parse_xray_json_config_to_candidates(job, "Happ JSON", "AUTO", 0));
        }
        for sn in staged_json_nodes {
            if !raw_cands.iter().any(|c| c.id == sn.id) {
                raw_cands.push(VpnCandidate {
                    id: sn.id,
                    raw_uri: sn.raw_uri,
                    name: sn.name,
                    protocol: sn.protocol,
                    transport: "tcp".into(),
                    security: "tls".into(),
                    sni: sn.sni,
                    host: sn.host,
                    port: sn.port,
                    region_hint: sn.exit_country,
                    whitelist_friendly: sn.whitelist_friendly,
                    fragment_enabled: sn.fragment_enabled,
                    via_warp: false,
                    priority_score: 180,
                    outbound_json: sn.outbound_json,
                    source_tier: 0,
                });
            }
        }
        raw_cands.truncate(40);

        if raw_cands.is_empty() {
            return json!({ "ok": false, "empty": true }).to_string();
        }

        PROBE_PROGRESS.set_stage(
            1,
            3,
            20,
            6,
            0,
            raw_cands.len() as u32,
            0,
            format!("Проверка {} серверов вашей подписки…", raw_cands.len()),
        );

        let (selected, _) = TOKIO_RT.block_on(tcp_prefilter_candidates_ex(
            raw_cands,
            36,
            28,
            false,
            &HashSet::new(),
        ));

        if selected.is_empty() {
            PROBE_PROGRESS.finish();
            diag_warn("SRC", "Ни один сервер из подписки не ответил по TCP в текущей сети");
            return json!({
                "ok": false,
                "error": "Серверы подписки не ответили по TCP (возможно, недоступны у вашего оператора)"
            })
            .to_string();
        }

        let cfg = build_batch_probe_config(&selected, base_port, Some(&warp_acc), fragment_tls);
        let batch_id = format!("csub_{}", unix_now());
        let count = selected.len();
        if let Ok(mut pb) = self.pending_batches.lock() {
            pb.insert(batch_id.clone(), selected);
        }

        json!({
            "ok": true,
            "batchId": batch_id,
            "basePort": base_port,
            "count": count,
            "probeConfigJson": cfg
        })
        .to_string()
    }

    /// Remove a user-added custom subscription and its associated servers cleanly.
    pub fn remove_source(&self, url: &str) -> String {
        let mut removed_name = String::new();
        {
            let mut g = write_data(&self.data);
            let mut drop_uris = HashSet::new();
            g.sources.retain(|s| {
                if !s.builtin && s.url == url {
                    removed_name = s.name.clone();
                    for u in &s.cached_uris {
                        drop_uris.insert(u.clone());
                    }
                    false
                } else {
                    true
                }
            });
            if !drop_uris.is_empty() {
                g.vpn_nodes
                    .retain(|n| !(n.source_tier == 0 && drop_uris.contains(&n.raw_uri)));
            }
        }
        self.save();
        if !removed_name.is_empty() {
            diag_info("SRC", format!("Удалена подписка «{removed_name}»"));
        }
        json!({ "ok": !removed_name.is_empty(), "name": removed_name }).to_string()
    }

    /// Step 1 of Smart Incremental Startup Sync: build lightweight parallel probe for existing
    /// cached live VPN nodes (and sync any custom subscription deltas!) so still-working nodes
    /// stay untouched and broken old nodes get evicted automatically without full reinstall!
    pub fn prepare_delta_revalidate_batch(&self, base_port: u16, fragment_tls: bool) -> String {
        // Respect subscription server's `profile-update-interval` header (default 2h if unset)
        // instead of hammering the panel every 20m — saves battery & avoids rate-limits!
        let stale_custom_urls: Vec<String> = {
            let g = read_data(&self.data);
            let now = unix_now();
            g.sources
                .iter()
                .filter(|s| {
                    if s.builtin || !s.enabled || s.kind != "vpn" {
                        return false;
                    }
                    let interval_sec = if s.update_interval_hours > 0 {
                        (s.update_interval_hours as u64).clamp(1, 72) * 3600
                    } else {
                        7200
                    };
                    (s.cached_uris.is_empty() && s.cached_json_outbounds.is_empty())
                        || now.saturating_sub(s.last_sync_unix) >= interval_sec
                })
                .map(|s| s.url.clone())
                .collect()
        };
        for u in stale_custom_urls {
            let _ = self.fetch_and_upsert_subscription(&u, "vpn", 1400, 0);
        }

        let (to_check, warp_acc) = {
            let g = read_data(&self.data);
            let now = unix_now();
            let can_chain = g.warp.has_masque();
            // Only re-check device-verified nodes older than 12 min (newer ones are already fresh!)
            let nodes: Vec<VerifiedVpnNode> = g
                .vpn_nodes
                .iter()
                .filter(|n| {
                    n.device_verified
                        && n.fail_count < 3
                        && (!n.via_warp || can_chain)
                        && now.saturating_sub(n.verified_unix) > 720
                })
                .take(28)
                .cloned()
                .collect();
            (nodes, g.warp.clone())
        };

        if to_check.is_empty() {
            let (live_total, live_us, live_de, live_wl, unverified_custom) = self.pool_health_counts();
            let needs_top_up =
                live_total < 6 || live_us == 0 || live_de == 0 || live_wl == 0 || unverified_custom > 0;
            return json!({
                "ok": false,
                "empty": true,
                "liveTotal": live_total,
                "liveWl": live_wl,
                "unverifiedCustom": unverified_custom,
                "needsTopUp": needs_top_up
            })
            .to_string();
        }

        // Convert cached VerifiedVpnNode outbounds into a lightweight batch config
        let pseudo_cands: Vec<VpnCandidate> = to_check
            .iter()
            .map(|n| VpnCandidate {
                id: n.id.clone(),
                raw_uri: n.raw_uri.clone(),
                name: n.name.clone(),
                protocol: n.protocol.clone(),
                transport: "tcp".into(),
                security: "tls".into(),
                sni: n.sni.clone(),
                host: n.host.clone(),
                port: n.port,
                region_hint: n.exit_country.clone(),
                whitelist_friendly: n.whitelist_friendly,
                fragment_enabled: n.fragment_enabled,
                via_warp: n.via_warp,
                priority_score: 100,
                outbound_json: n.outbound_json.clone(),
                source_tier: n.source_tier,
            })
            .collect();

        let cfg = build_batch_probe_config(&pseudo_cands, base_port, Some(&warp_acc), fragment_tls);
        let batch_id = format!("delta_{}", unix_now());
        let count = to_check.len();
        if let Ok(mut ps) = self.pending_seed_batches.lock() {
            ps.insert(batch_id.clone(), to_check);
        }

        json!({
            "ok": true,
            "batchId": batch_id,
            "basePort": base_port,
            "count": count,
            "probeConfigJson": cfg
        })
        .to_string()
    }

    /// Finalize Step 1 of Smart Incremental Sync: keep working cached nodes, evict dead ones!
    pub fn finalize_delta_revalidate_batch(&self, batch_id: &str, base_port: u16) -> String {
        let checked = self
            .pending_seed_batches
            .lock()
            .ok()
            .and_then(|mut m| m.remove(batch_id))
            .unwrap_or_default();

        if checked.is_empty() {
            PROBE_PROGRESS.finish();
            return json!({ "ok": false, "empty": true }).to_string();
        }

        let (kept_alive, dead_ids, dead_bl) =
            TOKIO_RT.block_on(revalidate_cached_nodes_via_socks(&checked, base_port));
        let kept_cnt = kept_alive.len();
        let removed_cnt = dead_ids.len();
        let dead_set: HashSet<String> = dead_ids.into_iter().collect();
        let alive_map: HashMap<String, VerifiedVpnNode> =
            kept_alive.into_iter().map(|n| (n.id.clone(), n)).collect();

        {
            let now = unix_now();
            let mut g = write_data(&self.data);
            for bl in dead_bl {
                g.blacklist.insert(bl, now);
            }
            // Drop broken old nodes, update fresh RTT/timestamp on working ones in-place!
            g.vpn_nodes.retain(|n| !dead_set.contains(&n.id));
            for n in &mut g.vpn_nodes {
                if let Some(updated) = alive_map.get(&n.id) {
                    *n = updated.clone();
                }
            }
            if kept_cnt >= 6 {
                g.last_vpn_refresh_unix = now;
            }
        }
        self.save();
        PROBE_PROGRESS.finish();

        let (live_total, live_us, live_de, live_wl, unverified_custom) = self.pool_health_counts();
        let needs_top_up =
            live_total < 6 || live_us == 0 || live_de == 0 || live_wl == 0 || unverified_custom > 0;

        json!({
            "ok": true,
            "keptAlive": kept_cnt,
            "removedDead": removed_cnt,
            "liveTotal": live_total,
            "liveWl": live_wl,
            "unverifiedCustom": unverified_custom,
            "needsTopUp": needs_top_up
        })
        .to_string()
    }

    fn pool_health_counts(&self) -> (usize, usize, usize, usize, usize) {
        let g = read_data(&self.data);
        let live: Vec<&VerifiedVpnNode> = g
            .vpn_nodes
            .iter()
            .filter(|n| n.device_verified && n.fail_count < 2)
            .collect();
        let total = live.iter().filter(|n| n.source_tier <= 3).count();
        let us = live.iter().filter(|n| n.exit_country == "US").count();
        let de = live
            .iter()
            .filter(|n| region_match_rank(&n.exit_country, "DE") <= 1)
            .count();
        let wl = live.iter().filter(|n| n.whitelist_friendly).count();
        let unv_custom = g
            .vpn_nodes
            .iter()
            .filter(|n| n.source_tier == 0 && !n.device_verified && n.fail_count < 2)
            .count();
        (total, us, de, wl, unv_custom)
    }

    pub fn toggle_source(&self, url: &str, enabled: bool) -> String {
        let mut toggled_name = String::new();
        {
            let mut g = write_data(&self.data);
            for s in &mut g.sources {
                if s.url == url {
                    s.enabled = enabled;
                    toggled_name = s.name.clone();
                }
            }
        }
        self.save();
        if !toggled_name.is_empty() {
            diag_info(
                "SRC",
                format!(
                    "Источник «{toggled_name}»: {}",
                    if enabled { "включён" } else { "выключен" }
                ),
            );
        }
        json!({ "ok": true }).to_string()
    }

    pub fn regenerate_warp(&self, active_socks_port: u16) -> String {
        let proxy = socks_opt(active_socks_port);
        diag_info("WARP", "Перевыпуск бесплатных ключей Cloudflare WARP + MASQUE…");
        match TOKIO_RT.block_on(provision_warp_account(None, true, proxy)) {
            Ok(acc) => {
                let has_m = acc.has_masque();
                let v4 = acc.wg_ipv4.clone();
                {
                    let mut g = write_data(&self.data);
                    g.warp = acc;
                }
                self.save();
                diag_ok(
                    "WARP",
                    format!("WARP перевыпущен: IP={v4}, MASQUE_H3_H2={has_m}"),
                );
                json!({
                    "ok": true,
                    "ipv4": v4,
                    "hasMasque": has_m
                })
                .to_string()
            }
            Err(e) => {
                diag_err("WARP", format!("Ошибка регистрации WARP: {e}"));
                json!({ "ok": false, "error": e }).to_string()
            }
        }
    }

    pub fn get_state_snapshot(&self, target_region: &str, whitelist_mode: bool) -> String {
        self.get_state_snapshot_ex(target_region, whitelist_mode, false)
    }

    /// Ultra-compact JNI state snapshot (v1.6.0):
    /// - Strips large `outbound_json`, `raw_uri`, `cached_uris` & `cached_json_outbounds` from UI DTOs
    ///   (12x smaller JNI JSON: ~20 KB vs ~260 KB — slashes UI heap churn & GC pauses to near zero!)
    /// - Only reads diagnostic log lines from disk when `include_logs == true` (Logs tab open)!
    /// - Computes live `suggestedStandby` preview for Dual-Channel card right in Rust!
    pub fn get_state_snapshot_ex(
        &self,
        target_region: &str,
        whitelist_mode: bool,
        include_logs: bool,
    ) -> String {
        let g = read_data(&self.data);
        let b = &self.tg_bridge;
        let norm_reg = normalize_region(target_region);
        let eff_wl = whitelist_mode || norm_reg == "WL";
        let region_nodes = filter_nodes_for_region(&g.vpn_nodes, norm_reg, eff_wl);
        let logs = if include_logs {
            read_diag_logs(240)
        } else {
            Vec::new()
        };
        let dev_verified_cnt = g.vpn_nodes.iter().filter(|n| n.device_verified && n.fail_count < 3).count();
        let wl_verified_cnt = g
            .vpn_nodes
            .iter()
            .filter(|n| n.device_verified && n.whitelist_friendly && !n.via_warp && n.fail_count < 3)
            .count();
        let yt_adfree_cnt = g
            .vpn_nodes
            .iter()
            .filter(|n| n.yt_ad_free && n.fail_count < 3)
            .count();
        let yt_adfree_live_cnt = g
            .vpn_nodes
            .iter()
            .filter(|n| n.yt_ad_free && n.device_verified && n.fail_count < 3)
            .count();
        let custom_sub_cnt = g.sources.iter().filter(|s| !s.builtin).count();

        let compact_region: Vec<serde_json::Value> =
            region_nodes.iter().map(compact_node_json).collect();
        let compact_all: Vec<serde_json::Value> =
            g.vpn_nodes.iter().map(compact_node_json).collect();
        let compact_sources: Vec<serde_json::Value> =
            g.sources.iter().map(compact_source_json).collect();

        json!({
            "vpnNodes": compact_region,
            "allVpnNodes": compact_all,
            "deviceVerifiedCount": dev_verified_cnt,
            "whitelistVerifiedCount": wl_verified_cnt,
            "ytAdFreeCount": yt_adfree_cnt,
            "ytAdFreeLiveCount": yt_adfree_live_cnt,
            "customSubCount": custom_sub_cnt,
            "tgProxies": g.tg_proxies,
            "sources": compact_sources,
            "customVpnCount": g.custom_vpn_uris.len(),
            "manifestUrl": g.manifest_url,
            "hwidEnabled": g.hwid_config.enabled,
            "hwidValue": g.hwid_config.hwid,
            "hasWarpWg": g.warp.has_wg(),
            "hasWarpMasque": g.warp.has_masque(),
            "warpIpv4": g.warp.wg_ipv4,
            "operaCount": g.opera.endpoints.len(),
            "lastVpnRefreshUnix": g.last_vpn_refresh_unix,
            "lastTgRefreshUnix": g.last_tg_refresh_unix,
            "bridgeRunning": b.running.load(Ordering::Relaxed),
            "bridgePort": b.port.load(Ordering::Relaxed),
            "bridgeLink": format!("tg://socks?server=127.0.0.1&port={}", b.port.load(Ordering::Relaxed)),
            "wsAvailable": b.ws_available.load(Ordering::Relaxed),
            "wsRttMs": b.ws_rtt_ms.load(Ordering::Relaxed),
            "logs": logs
        })
        .to_string()
    }
}

/// Strip heavy internal `outbound_json` & `raw_uri` before crossing JNI to Kotlin UI (12x less RAM!).
fn compact_node_json(n: &VerifiedVpnNode) -> serde_json::Value {
    json!({
        "id": n.id,
        "name": n.name,
        "display_protocol": n.display_protocol,
        "protocol": n.protocol,
        "host": n.host,
        "port": n.port,
        "sni": n.sni,
        "exit_country": n.exit_country,
        "exit_colo": n.exit_colo,
        "exit_ip": n.exit_ip,
        "rtt_ms": n.rtt_ms,
        "kbps": n.kbps,
        "passed_32kb": n.passed_32kb,
        "whitelist_friendly": n.whitelist_friendly,
        "fragment_enabled": n.fragment_enabled,
        "via_warp": n.via_warp,
        "device_verified": n.device_verified,
        "yt_ad_free": n.yt_ad_free,
        "yt_country": n.yt_country,
        "source_tier": n.source_tier,
        "verified_unix": n.verified_unix,
        "fail_count": n.fail_count
    })
}

/// Compact UI DTO for `SubSource` (includes full Happ/Remnawave quota, expiry, announce, support & crypt meta,
/// omits raw `cached_uris` & `cached_json_outbounds` arrays to save ~90 KB per UI snapshot!).
fn compact_source_json(s: &SubSource) -> serde_json::Value {
    json!({
        "name": s.name,
        "url": s.url,
        "kind": s.kind,
        "region_hint": s.region_hint,
        "enabled": s.enabled,
        "builtin": s.builtin,
        "userinfo": s.userinfo,
        "upload_bytes": s.upload_bytes,
        "download_bytes": s.download_bytes,
        "total_bytes": s.total_bytes,
        "expire_unix": s.expire_unix,
        "update_interval_hours": s.update_interval_hours,
        "announce": s.announce,
        "support_url": s.support_url,
        "web_page_url": s.web_page_url,
        "hwid_status": s.hwid_status,
        "encrypted_kind": s.encrypted_kind,
        "body_encrypted": s.body_encrypted,
        "cached_count": s.cached_count,
        "last_sync_unix": s.last_sync_unix
    })
}

fn detect_country_from_name(name: &str, hint: &str) -> String {
    if hint.len() == 2 && !matches!(hint, "CF" | "RU") {
        return hint.to_string();
    }
    let low = name.to_lowercase();
    for (flag_or_kw, cc) in [
        ("🇩🇪", "DE"),
        ("герман", "DE"),
        ("🇺🇸", "US"),
        ("сша", "US"),
        ("🇫🇮", "FI"),
        ("финлянд", "FI"),
        ("🇳🇱", "NL"),
        ("нидерланд", "NL"),
        ("🇬🇧", "GB"),
        ("британ", "GB"),
        ("англи", "GB"),
        ("🇫🇷", "FR"),
        ("франц", "FR"),
        ("🇸🇪", "SE"),
        ("швеци", "SE"),
        ("🇵🇱", "PL"),
        ("польш", "PL"),
        ("🇨🇭", "CH"),
        ("швейцар", "CH"),
        ("🇦🇹", "AT"),
        ("австри", "AT"),
        ("🇹🇷", "TR"),
        ("турци", "TR"),
        ("стамбул", "TR"),
        ("🇯🇵", "JP"),
        ("япони", "JP"),
        ("🇸🇬", "SG"),
        ("сингапур", "SG"),
        ("🇨🇦", "CA"),
        ("канад", "CA"),
        ("🇰🇷", "KR"),
        ("коре", "KR"),
        ("🇰🇿", "KZ"),
        ("казах", "KZ"),
        ("🇮🇹", "IT"),
        ("итал", "IT"),
        ("🇪🇸", "ES"),
        ("испан", "ES"),
        ("🇭🇺", "HU"),
        ("венгр", "HU"),
        ("🇪🇪", "EE"),
        ("🇱🇻", "LV"),
        ("🇨🇿", "CZ"),
        ("🇳🇴", "NO"),
        ("🇦🇱", "AL"),
        ("албан", "AL"),
        ("🇲🇩", "MD"),
        ("молдов", "MD"),
        ("🇦🇲", "AM"),
        ("армен", "AM"),
        ("🇱🇺", "LU"),
        ("🇲🇨", "MC"),
        ("🇧🇾", "BY"),
    ] {
        if name.contains(flag_or_kw) || low.contains(flag_or_kw) {
            return cc.to_string();
        }
    }
    "DE".to_string()
}

pub fn filter_nodes_for_region(
    raw_nodes: &[VerifiedVpnNode],
    target_region: &str,
    whitelist_mode: bool,
) -> Vec<VerifiedVpnNode> {
    let reg = normalize_region(target_region);
    let eff_wl = whitelist_mode || reg == "WL";
    // Never include domestic Russian (`RU`) exit nodes in VPN pool!
    let clean_nodes: Vec<VerifiedVpnNode> = raw_nodes
        .iter()
        .filter(|n| !n.exit_country.eq_ignore_ascii_case("RU"))
        .cloned()
        .collect();
    let nodes = clean_nodes.as_slice();

    let mut exact: Vec<VerifiedVpnNode> = if eff_wl {
        let wl_only: Vec<VerifiedVpnNode> = nodes
            .iter()
            .filter(|n| n.whitelist_friendly && !n.via_warp)
            .cloned()
            .collect();
        if wl_only.iter().any(|n| n.device_verified && n.fail_count < 3) {
            wl_only
        } else {
            nodes.to_vec()
        }
    } else if reg == "YT" {
        let yt_only: Vec<VerifiedVpnNode> = nodes
            .iter()
            .filter(|n| n.yt_ad_free && !matches!(n.exit_country.as_str(), "RU" | "CF"))
            .cloned()
            .collect();
        if !yt_only.is_empty() {
            yt_only
        } else {
            nodes.to_vec()
        }
    } else if reg == "WARP" {
        let wp_only: Vec<VerifiedVpnNode> = nodes
            .iter()
            .filter(|n| n.via_warp || n.protocol.starts_with("warp"))
            .cloned()
            .collect();
        if !wp_only.is_empty() {
            wp_only
        } else {
            nodes.to_vec()
        }
    } else if reg == "AUTO" {
        nodes.to_vec()
    } else {
        let mut v: Vec<VerifiedVpnNode> = nodes
            .iter()
            .filter(|n| region_match_rank(&n.exit_country, reg) == 0)
            .cloned()
            .collect();
        let live_exact = v
            .iter()
            .filter(|n| {
                n.device_verified
                    && n.fail_count == 0
                    && region_match_rank(&n.exit_country, reg) == 0
            })
            .count();
        if live_exact < 2 {
            for n in nodes {
                if !v.iter().any(|e| e.id == n.id) {
                    v.push(n.clone());
                }
            }
        }
        v
    };

    // Rank strictly:
    // - Full-stack protocols (VLESS Reality/XHTTP, Hy2, Trojan, SS2022, VMess, WG, WARP) rank above
    //   HTTP-only Opera relays so every browser & app gets full bare-IP + domain TCP/UDP support!
    exact.sort_by_key(|n| {
        let is_custom = n.source_tier == 0;
        let reg_rank = region_match_rank(&n.exit_country, reg);
        let cf_penalty = if reg != "WARP" && (n.source_tier >= 4 || n.exit_country == "CF") {
            1u8
        } else {
            0u8
        };
        let http_penalty = if matches!(n.protocol.as_str(), "opera" | "http") {
            1u8
        } else {
            0u8
        };
        let wl_rank = if n.whitelist_friendly && !n.via_warp {
            0u8
        } else if n.via_warp {
            1u8
        } else {
            2u8
        };
        let eff_rtt = if n.rtt_ms == 0 {
            9_999
        } else {
            // Reward proven stability (`ok_streak`) so rock-solid nodes stay preferred
            n.rtt_ms.saturating_sub((n.ok_streak.min(8) as u32) * 12)
        };
        let ver_rank = if n.device_verified {
            0u8
        } else if is_custom {
            1u8
        } else {
            2u8
        };
        let cust_rank = if is_custom { 0u8 } else { 1u8 };
        if eff_wl {
            (
                ver_rank,
                n.fail_count,
                wl_rank,
                http_penalty,
                cf_penalty,
                cust_rank,
                reg_rank,
                eff_rtt,
            )
        } else if reg == "YT" {
            let yt_rank = if n.yt_ad_free { 0u8 } else { 1u8 };
            let via_pen = if n.via_warp { 1u8 } else { 0u8 };
            (
                ver_rank,
                n.fail_count,
                yt_rank,
                http_penalty,
                cf_penalty,
                via_pen,
                cust_rank,
                eff_rtt,
            )
        } else if reg == "WARP" {
            let wp_direct = if n.protocol.starts_with("warp") { 0u8 } else { 1u8 };
            (
                ver_rank,
                n.fail_count,
                http_penalty,
                reg_rank,
                wp_direct,
                cust_rank,
                wl_rank,
                eff_rtt,
            )
        } else {
            let region_or_custom = if is_custom && (reg == "AUTO" || reg_rank == 0) {
                0u8
            } else if reg_rank == 0 {
                0u8
            } else {
                reg_rank.saturating_add(1)
            };
            (
                ver_rank,
                n.fail_count,
                cf_penalty,
                region_or_custom,
                http_penalty,
                cust_rank,
                wl_rank,
                eff_rtt,
            )
        }
    });

    exact
}
