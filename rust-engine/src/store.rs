//! Persistent atomic state manager & high-level engine coordinator (v1.1 — RF TSPU hardened).

use crate::diag::{
    clear_diag_logs, diag_err, diag_info, diag_log, diag_ok, diag_warn, fmt_endpoint,
    read_diag_logs, set_log_dir, PROBE_PROGRESS,
};
use crate::net_util::fetch_subscription_smart;
use crate::opera::{provision_opera_endpoints, OperaSessionCache};
use crate::sources::{
    content_hash_short, default_sources, extract_vpn_uris_from_subscription,
    fetch_remote_manifest, fetch_vpn_candidates, is_dummy_banner_uri, is_rf_blocked_sni,
    is_whitelist_remark, unwrap_subscription_url, SubSource, VerifiedVpnNode, VpnCandidate,
};
use crate::tg_bridge::{probe_tg_ws_direct, start_tg_bridge, TgLocalBridge};
use crate::tg_checker::{
    fetch_and_verify_tg_proxies_delta, parse_single_tg_token, parse_tg_proxies_from_text,
    verify_tg_candidate_strict, TgCheckProgress, VerifiedTgProxy,
};
use crate::vpn_probe::{
    check_active_tunnel_health, fast_verify_seed_nodes, region_match_rank,
    revalidate_cached_nodes_via_socks, tcp_prefilter_candidates_ex, verify_batch_via_socks,
    TunnelHealthResult,
};
use crate::warp::{provision_warp_account, WarpAccountCache};
use crate::xray_config::{
    build_batch_probe_config, build_production_tun_config_ex, candidate_to_warp_chain,
    opera_endpoints_to_candidates, opera_endpoints_to_warp_chain_candidates,
    parse_share_uri_to_candidate, warp_account_to_candidates,
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

/// Bounded 2-worker Tokio runtime: minimal background thread & RAM footprint on Android.
pub static TOKIO_RT: Lazy<Runtime> = Lazy::new(|| {
    let _ = rustls::crypto::ring::default_provider().install_default();
    Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(4)
        .thread_name("velox-io")
        .thread_stack_size(512 * 1024)
        .enable_all()
        .build()
        .expect("tokio runtime init")
});

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

fn normalize_region(target_region: &str) -> &'static str {
    match target_region.to_ascii_uppercase().as_str() {
        "US" => "US",
        "DE" => "DE",
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
            version: 4,
            sources: default_sources(),
            ..Default::default()
        };
        Self {
            data_dir: RwLock::new(None),
            data: RwLock::new(init),
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
        let mut loaded = if let Ok(bytes) = fs::read(&state_file) {
            serde_json::from_slice::<PersistedData>(&bytes).unwrap_or_default()
        } else {
            PersistedData::default()
        };

        // Seamless upgrade migration (v1/v2/v3 -> v4 / VeloxVPN v1.3.0):
        // - Preserve Cloudflare WARP MASQUE credentials, user custom subscriptions & live nodes
        // - Reset transient fail_count from v1.2 startup probe race
        // - Retire superseded/dead builtin feed URLs while merging all 38 new 2026 RF-WL/US/DE/TG feeds
        let mut mutated = false;
        if loaded.version < 4 {
            let prev_ver = loaded.version;
            loaded.version = 4;
            loaded
                .vpn_nodes
                .retain(|n| n.source_tier == 0 || !is_rf_blocked_sni(&n.sni));
            for n in &mut loaded.vpn_nodes {
                if n.device_verified {
                    n.fail_count = 0;
                }
                if is_whitelist_remark(&n.name) && !is_rf_blocked_sni(&n.sni) {
                    n.whitelist_friendly = true;
                }
            }
            // Replace outdated builtin TG/VPN URLs while keeping 100% of user's `!s.builtin` sources!
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
                        "Обновление v1.3 (БС РФ + Smart Sync + Подписки): WARP={}, живых VPN={}, своих подписок={}",
                        loaded.warp.has_masque(),
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

        // Prune expired blacklist entries (> 90 min old)
        let now = unix_now();
        let bl_before = loaded.blacklist.len();
        loaded
            .blacklist
            .retain(|_, ts| now.saturating_sub(*ts) < 5400);
        if loaded.blacklist.len() != bl_before {
            mutated = true;
        }

        // Seed initial LKG pool on very first install (always marked `device_verified = false`)
        if !seed_json.trim().is_empty() && loaded.vpn_nodes.is_empty() && loaded.tg_proxies.is_empty()
        {
            if let Ok(seed) = serde_json::from_str::<BootstrapSeed>(seed_json) {
                if !seed.vpn_nodes.is_empty() {
                    loaded.vpn_nodes = seed
                        .vpn_nodes
                        .into_iter()
                        .filter(|n| !is_rf_blocked_sni(&n.sni))
                        .map(|mut n| {
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

        if let Ok(mut g) = self.data.write() {
            *g = loaded;
        }
        if mutated || !is_reload {
            self.save();
        }

        // Log engine initialization ONLY once per process creation (never spam on cross-process reloads!)
        if !self.logged_startup.swap(true, Ordering::Relaxed) && !is_reload {
            diag_info(
                "SYS",
                format!(
                    "Velox Engine v1.3 готов (VPN: {vpn_cnt} [живых: {dev_verified_cnt}], TG: {tg_cnt}, БС-РФ + SmartSync)"
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

    pub fn save(&self) {
        let Some(dir) = self.data_dir.read().ok().and_then(|g| g.clone()) else {
            return;
        };
        let Ok(snapshot) = self.data.read().map(|g| serde_json::to_vec(&*g)) else {
            return;
        };
        let Ok(bytes) = snapshot else {
            return;
        };
        let tmp = dir.join("velox_state.json.tmp");
        let dst = dir.join("velox_state.json");
        if fs::write(&tmp, &bytes).is_ok() {
            let _ = fs::rename(&tmp, &dst);
        }
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
            let g = self.data.read().unwrap();
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
            let mut g = self.data.write().unwrap();
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
        let max_batch = max_batch.clamp(12, 46);
        let proxy = socks_opt(active_socks_port);

        let (sources, custom_uris, existing_opera, existing_warp, bl_set, skip_live_eps, manifest_url) = {
            let g = self.data.read().unwrap();
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

            // Tier-0 (user subs) + Tier-1 (25 auto-updated RF Whitelist, US, DE, SS2022, Trojan, Reality, XHTTP, Hy2 feeds)
            let tier1_fut = fetch_vpn_candidates(
                &sources,
                region,
                whitelist_mode,
                fragment_tls,
                proxy,
                &bl_set,
            );

            // Tier-2: Free official Opera SurfEasy HTTPS proxies (strictly time-boxed to 3.2s so slow API NEVER delays connect!)
            let opera_fut = async {
                if whitelist_mode {
                    return None;
                }
                if existing_opera.is_fresh() {
                    Some(existing_opera.clone())
                } else {
                    match tokio::time::timeout(
                        std::time::Duration::from_millis(3200),
                        provision_opera_endpoints(Some(&existing_opera), proxy),
                    )
                    .await
                    {
                        Ok(Ok(op)) => {
                            diag_ok("OPERA", format!("Получено {} релеев Opera US/EU", op.endpoints.len()));
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

            // Trim Opera+MASQUE to 2 best slots (fast check, never hogs the batch!)
            let opera_chain_cands: Vec<VpnCandidate> = if has_masque && !whitelist_mode {
                opera_opt
                    .as_ref()
                    .map(|op| {
                        let mut v = opera_endpoints_to_warp_chain_candidates(&op.endpoints, region);
                        v.truncate(2);
                        v
                    })
                    .unwrap_or_default()
            } else {
                Vec::new()
            };

            // Chain custom TLS/SS/Trojan/VMess keys over MASQUE as extra fallback
            let mut custom_chain_cands = Vec::new();
            if has_masque {
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

            // Echelon B: High-yield USA (US) & Germany (DE) SS2022/AEAD, Trojan-TLS, VLESS-TLS 2-hop over MASQUE!
            // In normal mode: 15 slots across BOTH US & DE so switching US <-> DE is ALWAYS instant (0.1s)!
            // In whitelist_mode: 6 backup slots so 34+ slots go straight to genuine Russian Whitelist SNI & CIDR!
            let mut tier1_chain_cands: Vec<VpnCandidate> = Vec::new();
            if has_masque {
                let mut chain_seen_hosts = HashSet::new();
                let (chain_cap, want_de, want_us, want_other) = if whitelist_mode {
                    (6usize, 3usize, 3usize, 0usize)
                } else {
                    match region {
                        "DE" => (15usize, 9usize, 5usize, 1usize),
                        "US" => (15usize, 5usize, 9usize, 1usize),
                        _ => (15usize, 7usize, 7usize, 1usize),
                    }
                };
                let mut got_de = 0usize;
                let mut got_us = 0usize;
                let mut got_other = 0usize;

                let mut chain_pool: Vec<&VpnCandidate> = all_cands
                    .iter()
                    .filter(|c| {
                        let h_low = c.host.to_ascii_lowercase();
                        let ep = format!("{}:{}" , h_low, c.port);
                        let wkey = format!("wchain:{ep}");
                        !bl_chain.contains(&wkey) && !skip_chain_live.contains(&ep)
                    })
                    .collect();
                chain_pool.sort_by_key(|c| {
                    let proto_prio = match (c.protocol.as_str(), c.security.as_str()) {
                        ("shadowsocks", "ss2022") => 0u8,
                        ("shadowsocks", _) => 1u8,
                        ("trojan", "tls") => 2u8,
                        ("vless", "tls") => 3u8,
                        ("vmess", "tls") => 4u8,
                        _ => 5u8,
                    };
                    let net_prio = match c.transport.as_str() {
                        "tcp" => 0u8,
                        "ws" | "httpupgrade" => 1u8,
                        "grpc" => 2u8,
                        _ => 3u8,
                    };
                    let port_prio = if c.port == 443 || c.port == 8443 { 0u8 } else { 1u8 };
                    (proto_prio, net_prio, port_prio)
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
                    let slot_ok = match c.region_hint.as_str() {
                        "DE" if got_de < want_de => true,
                        "US" if got_us < want_us => true,
                        "EU" if got_de < want_de => true,
                        _ if got_other < want_other && tier1_chain_cands.len() >= 8 => true,
                        _ => false,
                    };
                    if !slot_ok {
                        continue;
                    }
                    let host_key = format!("{}:{}", h_low, c.port);
                    if !chain_seen_hosts.insert(host_key) {
                        continue;
                    }
                    if let Some(wc) = candidate_to_warp_chain(c) {
                        match c.region_hint.as_str() {
                            "DE" | "EU" => got_de += 1,
                            "US" => got_us += 1,
                            _ => got_other += 1,
                        }
                        tier1_chain_cands.push(wc);
                    }
                }
            }

            // Direct Opera relay (1 slot on non-whitelist Wi-Fi)
            let tier2_direct = if whitelist_mode {
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

            // Direct Cloudflare WARP MASQUE (2 clean slots: primary H3 + primary H2+frag; skips dead .198.1 H2!)
            let tier3_cands = if whitelist_mode {
                Vec::new()
            } else {
                warp_opt
                    .as_ref()
                    .map(|wp| {
                        let mut v = warp_account_to_candidates(wp, fragment_tls);
                        v.truncate(2);
                        v
                    })
                    .unwrap_or_default()
            };

            let eff_max = max_batch.max(42).min(46);
            let reserved = custom_cands.len().min(6)
                + custom_chain_cands.len().min(2)
                + opera_chain_cands.len()
                + tier1_chain_cands.len()
                + tier2_direct.len()
                + tier3_cands.len();
            let tier1_direct_cap = eff_max
                .saturating_sub(reserved)
                .max(if whitelist_mode { 30 } else { 18 });
            let tcp_scan_cap = if whitelist_mode { 280 } else { 220 };

            // Echelon C: Direct Russian Whitelist (Минцифры SNI + VK/Yandex/CDN CIDR) + Custom Subs + Reality/XHTTP/Hy2!
            let (mut alive_tier1, dead) = tcp_prefilter_candidates_ex(
                all_cands.drain(..).collect(),
                tcp_scan_cap,
                tier1_direct_cap,
                whitelist_mode,
                &skip_live_eps,
            )
            .await;

            let mut combined = Vec::with_capacity(eff_max);
            combined.extend(custom_cands.into_iter().take(6));
            // In Белые списки РФ mode, put direct RF-whitelist & custom nodes FIRST!
            if whitelist_mode {
                combined.append(&mut alive_tier1);
                combined.extend(custom_chain_cands.into_iter().take(2));
                combined.extend(tier1_chain_cands);
            } else {
                combined.extend(custom_chain_cands.into_iter().take(2));
                combined.extend(tier1_chain_cands);
                combined.append(&mut alive_tier1);
                combined.extend(opera_chain_cands);
                combined.extend(tier3_cands);
                combined.extend(tier2_direct);
            }
            combined.truncate(eff_max);

            (combined, dead, opera_opt, warp_opt, manifest_opt)
        });

        // Persist refreshed Opera / WARP credentials, manifest sources, and dead IPs
        {
            let now = unix_now();
            let mut g = self.data.write().unwrap();
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

        let warp_snapshot = { self.data.read().unwrap().warp.clone() };
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
            let mut g = self.data.write().unwrap();
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
                    if old.device_verified
                        && !new_ids.contains(&old.id)
                        && old.fail_count < 2
                        && now.saturating_sub(old.verified_unix) < 6 * 3600
                    {
                        merged.push(old.clone());
                    }
                }
                merged.sort_by_key(|n| {
                    (
                        !n.device_verified,
                        n.fail_count,
                        if n.source_tier == 0 { 0u8 } else { 1u8 },
                        if n.source_tier >= 4 { 1u8 } else { 0u8 },
                        region_match_rank(&n.exit_country, region),
                        n.rtt_ms,
                    )
                });
                // Preserve up to 52 live verified nodes across Custom Subs + WL-РФ + US + DE + EU!
                merged.truncate(52);
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
        let region = normalize_region(target_region);
        let pinned_opt = if pinned_node_id.trim().is_empty() {
            None
        } else {
            Some(pinned_node_id.trim())
        };

        let (all_nodes, warp_snapshot, last_refresh) = {
            let g = self.data.read().unwrap();
            (
                g.vpn_nodes.clone(),
                g.warp.clone(),
                g.last_vpn_refresh_unix,
            )
        };
        let any_device_verified = all_nodes
            .iter()
            .any(|n| n.device_verified && n.fail_count < 3);
        let any_foreign_verified = all_nodes
            .iter()
            .any(|n| n.device_verified && n.fail_count < 3 && n.source_tier <= 3 && n.exit_country != "CF");

        // If user hasn't explicitly pinned a node and NO node has been verified on THIS device/ISP
        // yet, signal VeloxVpnService to run parallel seed probe + live MASQUE-Chain refresh!
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
        // If only Tier-4 CF WARP was cached and >90s passed, re-probe for real US/DE MASQUE-Chain first
        if pinned_opt.is_none() && !any_foreign_verified && now.saturating_sub(last_refresh) > 90 {
            return json!({
                "ok": false,
                "needsSeedProbe": false,
                "needsRefresh": true,
                "error": "Подбор зарубежных серверов US/DE через MASQUE…"
            })
            .to_string();
        }

        let live_only: Vec<VerifiedVpnNode> = if pinned_opt.is_some() {
            all_nodes.into_iter().filter(|n| n.fail_count < 3).collect()
        } else {
            all_nodes
                .into_iter()
                .filter(|n| n.device_verified && n.fail_count < 3)
                .collect()
        };

        // Check «Белые списки РФ» requirement FIRST: when whitelist_mode is ON and user didn't pin
        // a node, require real verified RF-whitelist (Минцифры SNI / VK-Yandex-CDN CIDR) servers!
        let live_wl_count = live_only
            .iter()
            .filter(|n| n.whitelist_friendly && n.fail_count < 2)
            .count();
        if pinned_opt.is_none()
            && whitelist_mode
            && live_wl_count == 0
            && now.saturating_sub(last_refresh) > 20
        {
            return json!({
                "ok": false,
                "needsSeedProbe": false,
                "needsRefresh": true,
                "needsWhitelistRefresh": true,
                "error": "Подбор рабочих серверов «Белые списки РФ» (SNI + CIDR)…"
            })
            .to_string();
        }

        // Check if user switched to a specific region (US or DE) that currently has 0 matching live nodes
        let has_region_match = match region {
            "US" => live_only.iter().any(|n| n.exit_country == "US"),
            "DE" => live_only
                .iter()
                .any(|n| region_match_rank(&n.exit_country, "DE") <= 1),
            _ => any_foreign_verified,
        };
        let needs_region_refresh = pinned_opt.is_none()
            && !whitelist_mode
            && !has_region_match
            && now.saturating_sub(last_refresh) > 45;

        let mut pool = if let Some(pid) = pinned_opt {
            let mut v: Vec<VerifiedVpnNode> =
                live_only.iter().filter(|n| n.id == pid).cloned().collect();
            for n in filter_nodes_for_region(&live_only, region, whitelist_mode) {
                if n.id != pid {
                    v.push(n);
                }
            }
            v
        } else {
            filter_nodes_for_region(&live_only, region, whitelist_mode)
        };

        // Fallback to any live device-verified healthy node so user is never left stranded
        if pool.is_empty() {
            pool = live_only;
            pool.sort_by_key(|n| {
                (
                    !n.device_verified,
                    n.fail_count,
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
                "error": "Живые узлы исчерпаны — запускаю обновление пула"
            })
            .to_string();
        }

        match build_production_tun_config_ex(
            &pool,
            pinned_opt,
            whitelist_mode,
            bypass_ru,
            fragment_tls,
            local_socks_port,
            Some(&warp_snapshot),
        ) {
            Ok((cfg_json, primary, backup_count)) => {
                let age_sec = now.saturating_sub(primary.verified_unix);
                // Any node verified on THIS device within the last 15 minutes connects in 0.1s
                // without a redundant blocking startup probe (live watchdog monitors seamlessly)!
                let freshly_verified =
                    primary.device_verified && age_sec <= 900 && primary.fail_count == 0;
                diag_info(
                    "VPN",
                    format!(
                        "Старт TUN -> {} [{}] {} chain={} wl={} sni={} frag={} exit={} rtt={}мс (свежесть:{}с, резерв:{})",
                        primary.name,
                        primary.display_protocol,
                        fmt_endpoint(&primary.host, primary.port),
                        if primary.via_warp { "MASQUE" } else { "direct" },
                        if primary.whitelist_friendly { "да" } else { "нет" },
                        if primary.sni.is_empty() { "-" } else { &primary.sni },
                        if primary.fragment_enabled { "on" } else { "off" },
                        primary.exit_country,
                        primary.rtt_ms,
                        age_sec,
                        backup_count
                    ),
                );
                json!({
                    "ok": true,
                    "configJson": cfg_json,
                    "activeNode": primary,
                    "primary": primary,
                    "firstTag": "vpn_0",
                    "viaWarp": primary.via_warp,
                    "whitelistActive": whitelist_mode && primary.whitelist_friendly,
                    "freshlyVerified": freshly_verified,
                    "primaryVerified": primary.device_verified,
                    "needsRegionRefresh": needs_region_refresh || (whitelist_mode && live_wl_count == 0),
                    "backupCount": backup_count
                })
                .to_string()
            }
            Err(e) => {
                diag_err("VPN", format!("Ошибка сборки TUN-конфига: {e}"));
                json!({ "ok": false, "error": e }).to_string()
            }
        }
    }

    /// Mark a node as failed/degraded with full diagnostic context and return remaining live count.
    pub fn report_node_failure(
        &self,
        node_id: &str,
        target_region: &str,
        reason: &str,
    ) -> String {
        let now = unix_now();
        let (node_desc, remaining_live) = {
            let mut g = self.data.write().unwrap();
            let mut bad_ep = None;
            let mut desc = node_id.to_string();
            let instant_evict = reason.contains("startupProbe") || reason.contains("ручная смена");
            for n in &mut g.vpn_nodes {
                if n.id == node_id {
                    // Never waste the user's time retrying a node whose TUN startupProbe just died!
                    n.fail_count = if instant_evict {
                        3
                    } else {
                        n.fail_count.saturating_add(1)
                    };
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
            g.vpn_nodes.retain(|n| n.fail_count < 3);
            let rem = g
                .vpn_nodes
                .iter()
                .filter(|n| n.device_verified && n.fail_count == 0)
                .count();
            let _ = target_region;
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
            format!("Сбой узла: {node_desc}{reason_suffix} · живых в резерве: {remaining_live}"),
        );

        json!({
            "ok": true,
            "healthyRemaining": remaining_live,
            "needsRefresh": remaining_live == 0
        })
        .to_string()
    }

    /// Live tunnel check for background Watchdog.
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

    /// Fetch & strictly verify Telegram proxies against real Telegram DC2 (`req_pq_multi -> resPQ`)
    /// requiring response time `<= max_rtt_ms` (default 1400 ms).
    pub fn refresh_tg_proxies(&self, max_rtt_ms: u32, active_socks_port: u16) -> String {
        let limit_ms = max_rtt_ms.clamp(300, 1400);
        let proxy = socks_opt(active_socks_port);
        let (sources, custom_tg, existing_tg) = {
            let g = self.data.read().unwrap();
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
            let mut g = self.data.write().unwrap();
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
        let proxies = { self.data.read().unwrap().tg_proxies.clone() };
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
    pub fn add_custom_item(&self, raw_input: &str, kind_hint: &str, max_tg_rtt_ms: u32) -> String {
        let input = raw_input.trim();
        if input.is_empty() {
            return json!({ "ok": false, "error": "Пустая строка" }).to_string();
        }

        // Reject hardware-locked encrypted Happ blobs with a clear actionable explanation
        if input.starts_with("happ://crypt") {
            return json!({
                "ok": false,
                "error": "Ссылка happ://crypt зашифрована под один клиент — вставьте обычную https:// ссылку подписки"
            })
            .to_string();
        }

        // 1. Subscription URL or client deep-link (`https://...`, `happ://add/...`, `v2raytun://...`)
        let single_line = input.lines().filter(|l| !l.trim().is_empty()).count() == 1;
        if single_line {
            if let Some(sub_url) = unwrap_subscription_url(input) {
                if kind_hint == "manifest" && sub_url.starts_with("https://") {
                    {
                        let mut g = self.data.write().unwrap();
                        g.manifest_url = sub_url;
                    }
                    self.save();
                    return json!({
                        "ok": true,
                        "type": "manifest",
                        "message": "Манифест сохранён"
                    })
                    .to_string();
                }
                return self.fetch_and_upsert_subscription(&sub_url, kind_hint, max_tg_rtt_ms, 0);
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
                        let mut g = self.data.write().unwrap();
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
                let mut g = self.data.write().unwrap();
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

        json!({
            "ok": false,
            "error": "Поддерживаются https:// подписки, happ://, v2raytun://, vless://, vmess://, hy2://, trojan://, ss://, tg://proxy и socks5://"
        })
        .to_string()
    }

    /// Download, decode, validate, and incrementally merge a user subscription URL.
    /// Uses `v2rayNG/1.9.30` / `Happ` / `SFA` User-Agents + redirect & portal unwrapping
    /// so Remnawave/Marzban/3x-ui/Happ panels return real server URIs & profile metadata.
    pub fn fetch_and_upsert_subscription(
        &self,
        sub_url: &str,
        kind_hint: &str,
        max_tg_rtt_ms: u32,
        active_socks_port: u16,
    ) -> String {
        let host_label = url::Url::parse(sub_url)
            .ok()
            .and_then(|u| u.host_str().map(|s| s.to_string()))
            .unwrap_or_else(|| "Подписка".into());
        let proxy = socks_opt(active_socks_port);

        diag_info("SRC", format!("Загрузка подписки: {sub_url}"));
        let fetched = match TOKIO_RT.block_on(fetch_subscription_smart(sub_url, proxy, 1024 * 1024))
        {
            Ok(f) => f,
            Err(e) => {
                diag_err("SRC", format!("Ошибка загрузки подписки {host_label}: {e}"));
                return json!({
                    "ok": false,
                    "error": format!("Не удалось скачать подписку ({host_label}): {e}")
                })
                .to_string();
            }
        };

        let vpn_uris = extract_vpn_uris_from_subscription(&fetched.body, 120);
        let title = if !fetched.profile_title.is_empty() {
            fetched.profile_title.clone()
        } else {
            format!("Подписка · {host_label}")
        };
        let new_hash = content_hash_short(&fetched.body);
        let now = unix_now();

        // Case A: Subscription contains valid VPN servers (VLESS Reality/XHTTP, Hy2, Trojan, SS, VMess)!
        if !vpn_uris.is_empty() && kind_hint != "tg" {
            let count = vpn_uris.len();
            let added_cnt: usize;
            let removed_cnt: usize;
            let mut unchanged = false;

            // Create immediate visible entries for new custom servers + prune deleted old ones!
            {
                let mut g = self.data.write().unwrap();
                let prev_uris: HashSet<String> = g
                    .sources
                    .iter()
                    .find(|s| s.url == sub_url)
                    .map(|s| s.cached_uris.iter().cloned().collect())
                    .unwrap_or_default();
                let next_set: HashSet<String> = vpn_uris.iter().cloned().collect();

                // Incremental delta diff: remove nodes deleted from subscription, keep working unchanged ones!
                let removed_uris: HashSet<String> =
                    prev_uris.difference(&next_set).cloned().collect();
                removed_cnt = removed_uris.len();
                added_cnt = next_set.difference(&prev_uris).count();
                if !removed_uris.is_empty() {
                    g.vpn_nodes
                        .retain(|n| !(n.source_tier == 0 && removed_uris.contains(&n.raw_uri)));
                }
                let has_present_nodes = g
                    .vpn_nodes
                    .iter()
                    .any(|n| n.source_tier == 0 && next_set.contains(&n.raw_uri));

                if let Some(existing) = g.sources.iter_mut().find(|s| s.url == sub_url) {
                    unchanged = existing.content_hash == new_hash
                        && !existing.cached_uris.is_empty()
                        && has_present_nodes;
                    existing.name = title.clone();
                    existing.kind = "vpn".into();
                    existing.enabled = true;
                    existing.builtin = false;
                    existing.userinfo = fetched.userinfo.clone();
                    existing.cached_count = count as u32;
                    existing.last_sync_unix = now;
                    existing.content_hash = new_hash;
                    existing.cached_uris = vpn_uris.clone();
                } else {
                    g.sources.insert(
                        0,
                        SubSource {
                            name: title.clone(),
                            url: sub_url.to_string(),
                            kind: "vpn".into(),
                            region_hint: "AUTO".into(),
                            enabled: true,
                            builtin: false,
                            userinfo: fetched.userinfo.clone(),
                            cached_count: count as u32,
                            last_sync_unix: now,
                            content_hash: new_hash,
                            cached_uris: vpn_uris.clone(),
                        },
                    );
                }

                // Immediately register any un-probed subscription nodes into vpn_nodes so the user
                // sees EVERY server from their subscription right away even before probe finishes!
                let existing_raws: HashSet<String> =
                    g.vpn_nodes.iter().map(|n| n.raw_uri.clone()).collect();
                let mut staged = Vec::new();
                for uri in &vpn_uris {
                    if existing_raws.contains(uri) {
                        continue;
                    }
                    let is_real = uri.contains("security=reality");
                    if let Some(c) = parse_share_uri_to_candidate(uri, "AUTO", 0, !is_real) {
                        let proto_lbl = crate::xray_config::human_protocol_label(&c);
                        let guess_cc = detect_country_from_name(&c.name, &c.region_hint);
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
                            source_tier: 0,
                            raw_uri: c.raw_uri,
                            outbound_json: c.outbound_json,
                            verified_unix: 0,
                            fail_count: 0,
                        });
                    }
                }
                if !staged.is_empty() {
                    staged.append(&mut g.vpn_nodes);
                    staged.truncate(64);
                    g.vpn_nodes = staged;
                }
            }
            self.save();

            let wl_cnt = vpn_uris
                .iter()
                .filter_map(|u| parse_share_uri_to_candidate(u, "AUTO", 0, false))
                .filter(|c| c.whitelist_friendly)
                .count();
            let info_sfx = if fetched.userinfo.is_empty() {
                String::new()
            } else {
                format!(" ({})", fetched.userinfo)
            };
            diag_ok(
                "SRC",
                format!(
                    "Подписка «{title}» [{via}]: {count} серверов (БС-РФ:{wl_cnt}, +{added_cnt}/-{removed_cnt}){info_sfx}",
                    via = fetched.via_tag
                ),
            );
            let msg = if unchanged {
                format!("«{title}»: актуальна ({count} серверов, без изменений)")
            } else {
                format!("«{title}»: загружено {count} серверов{info_sfx} — проверяю рабочие…")
            };
            return json!({
                "ok": true,
                "type": "subscription",
                "subName": title,
                "userinfo": fetched.userinfo,
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

        // Case B: Subscription contains Telegram proxy links (`tg://proxy`, `t.me/proxy`, `socks5`)
        let tg_cands = parse_tg_proxies_from_text(&fetched.body, kind_hint == "tg_socks");
        if !tg_cands.is_empty() {
            let total_tg = tg_cands.len();
            {
                let mut g = self.data.write().unwrap();
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
                            cached_uris: Vec::new(),
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

        diag_warn(
            "SRC",
            format!(
                "В подписке {host_label} не найдено поддерживаемых ключей (размер {} Б, via {})",
                fetched.body.len(),
                fetched.via_tag
            ),
        );
        json!({
            "ok": false,
            "error": format!("По ссылке {host_label} не найдено активных ключей VPN или прокси (возможно, подписка истекла)")
        })
        .to_string()
    }

    /// Build a fast dedicated Xray probe batch for all user custom subscriptions & custom keys
    /// so imported subscriptions verify in ~4–5 seconds.
    pub fn prepare_custom_sub_probe(&self, base_port: u16, fragment_tls: bool) -> String {
        let (uris, warp_acc) = {
            let g = self.data.read().unwrap();
            let mut list: Vec<String> = Vec::new();
            let mut seen = HashSet::new();
            for s in g.sources.iter().filter(|s| !s.builtin && s.enabled && s.kind == "vpn") {
                // If an older custom subscription had 0 cached_uris (migrated from v1.2!), save URL for fetch
                for u in &s.cached_uris {
                    if seen.insert(u.clone()) {
                        list.push(u.clone());
                    }
                }
            }
            for u in &g.custom_vpn_uris {
                if seen.insert(u.clone()) {
                    list.push(u.clone());
                }
            }
            (list, g.warp.clone())
        };

        if uris.is_empty() {
            return json!({ "ok": false, "empty": true }).to_string();
        }

        let raw_cands: Vec<VpnCandidate> = uris
            .into_iter()
            .filter(|u| !is_dummy_banner_uri(u))
            .filter_map(|u| {
                let is_real = u.contains("security=reality");
                parse_share_uri_to_candidate(&u, "AUTO", 0, fragment_tls && !is_real)
            })
            .take(36)
            .collect();

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
            let mut g = self.data.write().unwrap();
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
        // First incrementally refresh any user custom subscriptions older than 20 minutes
        let stale_custom_urls: Vec<String> = {
            let g = self.data.read().unwrap();
            let now = unix_now();
            g.sources
                .iter()
                .filter(|s| {
                    !s.builtin
                        && s.enabled
                        && s.kind == "vpn"
                        && (s.cached_uris.is_empty() || now.saturating_sub(s.last_sync_unix) > 1200)
                })
                .map(|s| s.url.clone())
                .collect()
        };
        for u in stale_custom_urls {
            let _ = self.fetch_and_upsert_subscription(&u, "vpn", 1400, 0);
        }

        let (to_check, warp_acc) = {
            let g = self.data.read().unwrap();
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
            let mut g = self.data.write().unwrap();
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
        let g = self.data.read().unwrap();
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
            let mut g = self.data.write().unwrap();
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
                    let mut g = self.data.write().unwrap();
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
        let g = self.data.read().unwrap();
        let b = &self.tg_bridge;
        let region_nodes = filter_nodes_for_region(&g.vpn_nodes, target_region, whitelist_mode);
        let logs = read_diag_logs(260);
        let dev_verified_cnt = g.vpn_nodes.iter().filter(|n| n.device_verified).count();
        let wl_verified_cnt = g
            .vpn_nodes
            .iter()
            .filter(|n| n.device_verified && n.whitelist_friendly && n.fail_count < 3)
            .count();
        let custom_sub_cnt = g.sources.iter().filter(|s| !s.builtin).count();

        json!({
            "vpnNodes": region_nodes,
            "allVpnNodes": g.vpn_nodes,
            "deviceVerifiedCount": dev_verified_cnt,
            "whitelistVerifiedCount": wl_verified_cnt,
            "customSubCount": custom_sub_cnt,
            "tgProxies": g.tg_proxies,
            "sources": g.sources,
            "customVpnCount": g.custom_vpn_uris.len(),
            "manifestUrl": g.manifest_url,
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

fn detect_country_from_name(name: &str, hint: &str) -> String {
    if hint == "US" || hint == "DE" {
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
        ("🇫🇷", "FR"),
        ("франц", "FR"),
        ("🇮🇹", "IT"),
        ("итал", "IT"),
        ("🇭🇺", "HU"),
        ("венгр", "HU"),
        ("🇦🇹", "AT"),
        ("🇨🇭", "CH"),
        ("🇸🇪", "SE"),
        ("🇬🇧", "GB"),
        ("🇵🇱", "PL"),
        ("🇪🇪", "EE"),
        ("🇱🇻", "LV"),
        ("🇨🇿", "CZ"),
        ("🇷🇺", "RU"),
        ("росси", "RU"),
    ] {
        if name.contains(flag_or_kw) || low.contains(flag_or_kw) {
            return cc.to_string();
        }
    }
    "DE".to_string()
}

pub fn filter_nodes_for_region(
    nodes: &[VerifiedVpnNode],
    target_region: &str,
    whitelist_mode: bool,
) -> Vec<VerifiedVpnNode> {
    let reg = normalize_region(target_region);

    // ALWAYS include user's own custom subscription servers (`source_tier == 0`) and, when
    // `whitelist_mode` is ON, ALL genuine Russian Whitelist (`whitelist_friendly`) servers
    // across all clean exits (DE, FI, NL, US, PL, AT, FR)!
    let mut exact: Vec<VerifiedVpnNode> = if whitelist_mode {
        let wl_only: Vec<VerifiedVpnNode> = nodes
            .iter()
            .filter(|n| n.whitelist_friendly)
            .cloned()
            .collect();
        if wl_only.iter().any(|n| n.device_verified && n.fail_count < 3) {
            wl_only
        } else {
            nodes.to_vec()
        }
    } else {
        let mut v: Vec<VerifiedVpnNode> = nodes
            .iter()
            .filter(|n| n.source_tier == 0 || region_match_rank(&n.exit_country, reg) == 0)
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
        if live_exact < 3 {
            for n in nodes {
                if !v.iter().any(|e| e.id == n.id) {
                    v.push(n.clone());
                }
            }
        }
        v
    };

    // Rank strictly:
    // - In `whitelist_mode`: genuine `n.whitelist_friendly` (Минцифры SNI / VK-Yandex-CDN CIDR) ALWAYS #0!
    // - In normal mode: exact target region + user custom subscription (`source_tier == 0`) first, lowest RTT!
    exact.sort_by_key(|n| {
        let is_custom = n.source_tier == 0;
        let reg_rank = region_match_rank(&n.exit_country, reg);
        let cf_penalty = if n.source_tier >= 4 || n.exit_country == "CF" {
            1u8
        } else {
            0u8
        };
        // CRITICAL FIX: ONLY genuine `whitelist_friendly` gets rank 0 in «Белые списки РФ» mode!
        let wl_rank = if n.whitelist_friendly {
            0u8
        } else if n.via_warp {
            1u8
        } else {
            2u8
        };
        let eff_rtt = if n.rtt_ms == 0 { 9_999 } else { n.rtt_ms };
        let ver_rank = if n.device_verified {
            0u8
        } else if is_custom {
            1u8
        } else {
            2u8
        };
        let cust_rank = if is_custom { 0u8 } else { 1u8 };
        if whitelist_mode {
            (
                ver_rank,
                n.fail_count,
                wl_rank,
                cf_penalty,
                cust_rank,
                reg_rank,
                eff_rtt,
            )
        } else {
            let region_or_custom = if is_custom && (reg == "AUTO" || reg_rank == 0) {
                0u8
            } else if reg_rank == 0 {
                0u8
            } else if is_custom {
                1u8
            } else {
                reg_rank.saturating_add(1)
            };
            (
                ver_rank,
                n.fail_count,
                cf_penalty,
                region_or_custom,
                cust_rank,
                wl_rank,
                eff_rtt,
            )
        }
    });

    exact
}
