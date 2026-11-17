//! Real end-to-end live verification suite linking `libxray_ffi.so` (v0.10.0) on Linux x86_64.
//! Tests every protocol echelon — INCLUDING v1.2 2-Hop `MASQUE-Chain` (Opera US/EU + MASQUE and
//! German/US Trojan/VLESS-TLS/SS2022/VMess + MASQUE) — verifies real US + DE VPN tunnels
//! (>=32 KB + WebPKI + GeoIP), validates every production Android TUN JSON permutation,
//! verifies real Telegram DC2 `resPQ` <= 1400 ms proxies, tests the local `TG-WS` bridge,
//! and exports a freshly verified sanitized `bootstrap_seed.json`.

use std::collections::HashSet;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::time::Duration;
use velox_engine::net_util::fetch_subscription_smart;
use velox_engine::opera::provision_opera_endpoints;
use velox_engine::sources::{
    default_sources, extract_vpn_uris_from_subscription, fetch_vpn_candidates,
    unwrap_subscription_url, VerifiedVpnNode, VpnCandidate,
};
use velox_engine::store::BootstrapSeed;
use velox_engine::tg_bridge::{probe_tg_ws_direct, start_tg_bridge, TgLocalBridge};
use velox_engine::tg_checker::{
    fetch_and_verify_tg_proxies_delta, parse_single_tg_token, verify_tg_candidate_strict,
};
use velox_engine::vpn_probe::{
    check_active_tunnel_health, revalidate_cached_nodes_via_socks, tcp_prefilter_candidates,
    verify_batch_via_socks,
};
use velox_engine::warp::{provision_warp_account, WarpAccountCache};
use velox_engine::xray_config::{
    build_batch_probe_config, build_production_tun_config, build_production_tun_config_ex,
    candidate_to_warp_chain, opera_endpoints_to_candidates,
    opera_endpoints_to_warp_chain_candidates, parse_share_uri_to_candidate,
    warp_account_to_candidates,
};

#[repr(C)]
struct XrayCoreHandle {
    _priv: [u8; 0],
}
#[repr(C)]
struct XrayError {
    _priv: [u8; 0],
}

#[cfg(target_os = "linux")]
#[link(name = "xray_ffi")]
extern "C" {
    fn xray_core_new(error: *mut *mut XrayError) -> *mut XrayCoreHandle;
    fn xray_core_load_config_json(
        handle: *mut XrayCoreHandle,
        json: *const c_char,
        error: *mut *mut XrayError,
    ) -> c_int;
    fn xray_core_start(handle: *mut XrayCoreHandle, error: *mut *mut XrayError) -> c_int;
    fn xray_core_stop(handle: *mut XrayCoreHandle, error: *mut *mut XrayError) -> c_int;
    fn xray_core_free(handle: *mut XrayCoreHandle);
    fn xray_error_message(error: *const XrayError) -> *const c_char;
    fn xray_error_free(error: *mut XrayError);
}

#[cfg(target_os = "linux")]
struct LiveXray {
    h: *mut XrayCoreHandle,
    started: bool,
}

#[cfg(target_os = "linux")]
unsafe impl Send for LiveXray {}

#[cfg(target_os = "linux")]
impl LiveXray {
    fn take_err(err: *mut XrayError) -> String {
        if err.is_null() {
            return "unknown xray error".into();
        }
        unsafe {
            let p = xray_error_message(err);
            let s = if p.is_null() {
                "null xray error".into()
            } else {
                CStr::from_ptr(p).to_string_lossy().into_owned()
            };
            xray_error_free(err);
            s
        }
    }

    fn validate_only(json: &str) -> Result<(), String> {
        let c = CString::new(json).map_err(|e| e.to_string())?;
        unsafe {
            let mut err: *mut XrayError = std::ptr::null_mut();
            let h = xray_core_new(&mut err);
            if h.is_null() {
                return Err(Self::take_err(err));
            }
            let rc = xray_core_load_config_json(h, c.as_ptr(), &mut err);
            xray_core_free(h);
            if rc != 0 {
                return Err(Self::take_err(err));
            }
            Ok(())
        }
    }

    fn start_json(json: &str) -> Result<Self, String> {
        let c = CString::new(json).map_err(|e| e.to_string())?;
        unsafe {
            let mut err: *mut XrayError = std::ptr::null_mut();
            let h = xray_core_new(&mut err);
            if h.is_null() {
                return Err(Self::take_err(err));
            }
            if xray_core_load_config_json(h, c.as_ptr(), &mut err) != 0 {
                let msg = Self::take_err(err);
                xray_core_free(h);
                return Err(format!("load_config: {msg}"));
            }
            if xray_core_start(h, &mut err) != 0 {
                let msg = Self::take_err(err);
                xray_core_free(h);
                return Err(format!("start: {msg}"));
            }
            Ok(Self { h, started: true })
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for LiveXray {
    fn drop(&mut self) {
        unsafe {
            if self.started && !self.h.is_null() {
                let mut err: *mut XrayError = std::ptr::null_mut();
                let _ = xray_core_stop(self.h, &mut err);
                if !err.is_null() {
                    xray_error_free(err);
                }
            }
            if !self.h.is_null() {
                xray_core_free(self.h);
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn filter_schema_valid(
    cands: Vec<VpnCandidate>,
    warp: Option<&WarpAccountCache>,
    label: &str,
) -> Vec<VpnCandidate> {
    let mut good = Vec::new();
    let mut bad = 0usize;
    for c in cands {
        let single_cfg = build_batch_probe_config(std::slice::from_ref(&c), 31000, warp, true);
        match LiveXray::validate_only(&single_cfg) {
            Ok(()) => good.push(c),
            Err(e) => {
                bad += 1;
                if bad <= 8 {
                    println!(
                        "  [SCHEMA-WARN:{label}] {} ({}/{}/sec={}/warp={}) rejected: {e}",
                        c.name, c.protocol, c.transport, c.security, c.via_warp
                    );
                }
            }
        }
    }
    println!(
        "  [SCHEMA:{label}] valid={}/{} (rejected={bad})",
        good.len(),
        good.len() + bad
    );
    good
}

#[cfg(target_os = "linux")]
async fn run_batch_test(
    cands: &[VpnCandidate],
    base_port: u16,
    region: &str,
    warp: Option<&WarpAccountCache>,
    label: &str,
) -> Vec<VerifiedVpnNode> {
    if cands.is_empty() {
        return Vec::new();
    }
    let cfg = build_batch_probe_config(cands, base_port, warp, true);
    let _core = match LiveXray::start_json(&cfg) {
        Ok(c) => c,
        Err(e) => {
            println!("  [ERR:{label}] failed to start batch: {e}");
            return Vec::new();
        }
    };
    tokio::time::sleep(Duration::from_millis(250)).await;
    let (ok, _bad) = verify_batch_via_socks(cands, base_port, region).await;
    for n in &ok {
        println!(
            "  [OK:{label}] {} | {} | host={}:{} | exit={} (colo={}) | rtt={}ms | speed={}kbps | warp={} | sni={}",
            n.name, n.display_protocol, n.host, n.port, n.exit_country, n.exit_colo, n.rtt_ms, n.kbps, n.via_warp, n.sni
        );
    }
    if let Some(first_idx) = cands
        .iter()
        .position(|c| ok.first().map(|n| n.id == c.id).unwrap_or(false))
    {
        let h = check_active_tunnel_health(base_port + first_idx as u16).await;
        println!(
            "  [WATCHDOG:{label}] alive={} rtt={}ms loc={} colo={}",
            h.alive, h.rtt_ms, h.exit_country, h.exit_colo
        );
    }
    ok
}

#[cfg(not(target_os = "linux"))]
fn main() {}

#[cfg(target_os = "linux")]
fn main() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let seed_out = std::env::args().nth(1);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async move {
        println!("=== 1. Provisioning Free Official Cloudflare WARP (MASQUE H3/H2 + WG) ===");
        let warp_acc = match provision_warp_account(None, false, None).await {
            Ok(acc) => {
                println!(
                    "  Provisioned WARP! wg={} (ip={}) masque={}",
                    acc.has_wg(),
                    acc.wg_ipv4,
                    acc.has_masque(),
                );
                Some(acc)
            }
            Err(e) => {
                println!("  [ERR:warp] {e}");
                None
            }
        };
        let mut warp_verified = Vec::new();
        if let Some(ref acc) = warp_acc {
            let wp_cands =
                filter_schema_valid(warp_account_to_candidates(acc, true), Some(acc), "warp");
            warp_verified = run_batch_test(&wp_cands, 23100, "AUTO", Some(acc), "warp").await;
        }

        println!("\n=== 2. Testing v1.2 KILLER FEATURE: Official Opera US + EU over WARP MASQUE-Chain! ===");
        let mut opera_chain_verified = Vec::new();
        let mut opera_direct_verified = Vec::new();
        match provision_opera_endpoints(None, None).await {
            Ok(sess) => {
                let cnt_us = sess.endpoints.iter().filter(|e| e.region == "US").count();
                let cnt_de = sess.endpoints.iter().filter(|e| e.region == "DE").count();
                println!(
                    "  Provisioned {} Opera endpoints! (US={cnt_us}, DE/EU={cnt_de})",
                    sess.endpoints.len()
                );
                for ep in &sess.endpoints {
                    println!("    region={} ip={}:{} sni={}", ep.region, ep.ip, ep.port, ep.sni_verify);
                }
                if let Some(ref acc) = warp_acc {
                    let op_chain = filter_schema_valid(
                        opera_endpoints_to_warp_chain_candidates(&sess.endpoints, "AUTO"),
                        Some(acc),
                        "opera+masque",
                    );
                    assert!(!op_chain.is_empty(), "opera+masque must pass xray-rust schema!");
                    opera_chain_verified =
                        run_batch_test(&op_chain, 23200, "AUTO", Some(acc), "opera+masque").await;
                    assert!(
                        !opera_chain_verified.is_empty(),
                        "2-hop Opera+MASQUE MUST succeed end-to-end!"
                    );
                }
                let op_direct = filter_schema_valid(
                    opera_endpoints_to_candidates(&sess.endpoints, "AUTO", true),
                    None,
                    "opera-direct",
                );
                opera_direct_verified =
                    run_batch_test(&op_direct, 23260, "AUTO", None, "opera-direct").await;
            }
            Err(e) => println!("  [ERR:opera] {e}"),
        }

        println!("\n=== 3. Testing v1.2 2-Hop DE & US Trojan/VLESS-TLS/SS2022/VMess over WARP MASQUE-Chain! ===");
        let sources = default_sources();
        let bl = HashSet::new();
        let de_raw = fetch_vpn_candidates(&sources, "DE", false, true, None, &bl).await;
        let us_raw = fetch_vpn_candidates(&sources, "US", false, true, None, &bl).await;
        println!(
            "  Fetched {} DE-sorted & {} US-sorted Tier-1 candidates",
            de_raw.len(),
            us_raw.len()
        );

        let mut tier1_chain_verified = Vec::new();
        if let Some(ref acc) = warp_acc {
            let mut chain_cands = Vec::new();
            let mut seen = HashSet::new();
            let mut de_ch = 0usize;
            for c in de_raw
                .iter()
                .filter(|c| c.region_hint == "DE" || c.region_hint == "AUTO")
            {
                if de_ch >= 14 {
                    break;
                }
                let h = c.host.to_ascii_lowercase();
                if (h.starts_with("104.") || h.starts_with("172.67.") || h.starts_with("162.159."))
                    && c.transport == "tcp"
                {
                    continue;
                }
                if let Some(wc) = candidate_to_warp_chain(c) {
                    if seen.insert(format!("{}:{}", h, c.port)) {
                        chain_cands.push(wc);
                        de_ch += 1;
                    }
                }
            }
            for c in us_raw.iter().filter(|c| c.region_hint == "US") {
                if chain_cands.len() >= 26 {
                    break;
                }
                let h = c.host.to_ascii_lowercase();
                if (h.starts_with("104.") || h.starts_with("172.67.") || h.starts_with("162.159."))
                    && c.transport == "tcp"
                {
                    continue;
                }
                if let Some(wc) = candidate_to_warp_chain(c) {
                    if seen.insert(format!("{}:{}", h, c.port)) {
                        chain_cands.push(wc);
                    }
                }
            }
            let chain_valid = filter_schema_valid(chain_cands, Some(acc), "tier1+masque");
            tier1_chain_verified =
                run_batch_test(&chain_valid, 23350, "DE", Some(acc), "tier1+masque").await;
        }

        println!("\n=== 4. Testing Direct Single-Hop US & DE VLESS/REALITY/XHTTP/Hy2 + Gaming/RU-WL SNIs ===");
        // Explicitly prioritize proven RF-friendly gaming & whitelist SNIs alongside top US/DE nodes
        let mut us_pick: Vec<VpnCandidate> = us_raw
            .iter()
            .filter(|c| {
                c.host == "87.120.252.67"
                    || c.sni.contains("worldoftanks")
                    || c.sni.contains("steampowered")
                    || c.sni.contains("wargaming")
            })
            .take(24)
            .cloned()
            .collect();
        for c in us_raw.into_iter().take(150) {
            if !us_pick.iter().any(|x| x.id == c.id) {
                us_pick.push(c);
            }
        }
        let us_valid = filter_schema_valid(us_pick, None, "tier1-us");
        let (us_tcp, _) = tcp_prefilter_candidates(us_valid, 150, 32).await;
        let us_verified = run_batch_test(&us_tcp, 23500, "US", None, "tier1-us").await;

        let de_valid = filter_schema_valid(de_raw.into_iter().take(150).collect(), None, "tier1-de");
        let (de_tcp, _) = tcp_prefilter_candidates(de_valid, 140, 32).await;
        let de_verified = run_batch_test(&de_tcp, 23650, "DE", None, "tier1-de").await;

        let wl_raw = fetch_vpn_candidates(&sources, "AUTO", true, true, None, &bl).await;
        let wl_only: Vec<VpnCandidate> = wl_raw
            .into_iter()
            .filter(|c| {
                c.whitelist_friendly
                    || c.sni.contains("worldoftanks")
                    || c.sni.contains("steampowered")
            })
            .take(80)
            .collect();
        let wl_valid = filter_schema_valid(wl_only, None, "tier1-wl");
        let (wl_tcp, _) = tcp_prefilter_candidates(wl_valid, 80, 22).await;
        let wl_verified = run_batch_test(&wl_tcp, 23800, "AUTO", None, "tier1-wl").await;

        println!("\n=== 5. Validating ALL Production Android TUN Config Permutations (1-Hop + 2-Hop MASQUE-Chain + CF Fallback) ===");
        let mut all_verified = Vec::new();
        all_verified.extend(opera_chain_verified.iter().cloned());
        all_verified.extend(tier1_chain_verified.iter().cloned());
        all_verified.extend(us_verified.iter().cloned());
        all_verified.extend(de_verified.iter().cloned());
        all_verified.extend(opera_direct_verified.iter().cloned());
        all_verified.extend(warp_verified.iter().cloned());

        // Synthetic Tier-4 CF fallback test to guarantee CF never mixes into US/DE auto_pool AND works standalone
        if let Some(mut cf_node) = warp_verified.first().cloned() {
            cf_node.id = "warp_cf_test".into();
            cf_node.exit_country = "CF".into();
            cf_node.exit_colo = "DME".into();
            cf_node.source_tier = 4;

            let mut mixed_with_cf = all_verified.clone();
            mixed_with_cf.insert(0, cf_node.clone());
            let (m_json, m_primary, _) =
                build_production_tun_config(&mixed_with_cf, None, true, true, 10808, warp_acc.as_ref())
                    .expect("mixed+cf tun");
            assert_ne!(
                m_primary.exit_country, "CF",
                "CF Tier-4 node MUST NEVER become primary when US/DE nodes exist!"
            );
            LiveXray::validate_only(&m_json).expect("mixed+cf schema valid");
            println!(
                "  [OK:TUN-CF-GUARD] CF excluded from auto_pool; primary={} ({})",
                m_primary.name, m_primary.display_protocol
            );

            let (cf_json, cf_primary, _) = build_production_tun_config(
                std::slice::from_ref(&cf_node),
                None,
                true,
                true,
                10808,
                warp_acc.as_ref(),
            )
            .expect("cf-only tun");
            assert_eq!(cf_primary.exit_country, "CF");
            LiveXray::validate_only(&cf_json).expect("cf-only schema valid");
            println!("  [OK:TUN-CF-SOLO] Emergency CF fallback valid ({} bytes)", cf_json.len());
        }

        // Pure 2-hop MASQUE-Chain production TUN config
        if !opera_chain_verified.is_empty() {
            let mut pure_chain = opera_chain_verified.clone();
            pure_chain.extend(tier1_chain_verified.iter().cloned());
            let (ch_json, ch_primary, ch_bk) =
                build_production_tun_config(&pure_chain, None, true, true, 10808, warp_acc.as_ref())
                    .expect("pure masque-chain tun");
            LiveXray::validate_only(&ch_json).expect("pure masque-chain schema valid");
            println!(
                "  [OK:TUN-PURE-MASQUE-CHAIN] primary={} [{}] exit={} backups={ch_bk} ({} bytes)",
                ch_primary.name, ch_primary.display_protocol, ch_primary.exit_country, ch_json.len()
            );
        }

        // Mixed 2-hop + direct + pinned permutations
        for (bypass_ru, frag, pinned) in [
            (true, true, None),
            (false, true, None),
            (true, false, Some(all_verified[0].id.as_str())),
        ] {
            let (tun_json, prim, bk) = build_production_tun_config(
                &all_verified,
                pinned,
                bypass_ru,
                frag,
                10808,
                warp_acc.as_ref(),
            )
            .expect("tun json build");
            LiveXray::validate_only(&tun_json).expect("mixed tun schema valid");
            println!(
                "  [OK:TUN-MIXED] bypass_ru={bypass_ru} frag={frag} pinned={} primary={} [{}] bk={bk} ({} bytes)",
                pinned.is_some(),
                prim.name,
                prim.display_protocol,
                tun_json.len()
            );
        }

        println!("\n=== 6. Testing Telegram Proxies (16 Feeds + Incremental Delta Sync <= 1400 ms) ===");
        let (tg_verified, tg_kept, tg_added, tg_removed) =
            fetch_and_verify_tg_proxies_delta(&sources, &[], &[], 1400, None, None).await;
        let cnt_ee = tg_verified.iter().filter(|p| p.kind == "faketls").count();
        let cnt_dd = tg_verified.iter().filter(|p| p.kind == "dd").count();
        let cnt_cl = tg_verified.iter().filter(|p| p.kind == "classic").count();
        let cnt_s5 = tg_verified.iter().filter(|p| p.kind == "socks5").count();
        println!(
            "  Verified {} REAL Telegram proxies <= 1400 ms! (+{tg_added}/={tg_kept}/-{tg_removed} · FakeTLS ee={cnt_ee}, Secure dd={cnt_dd}, Classic={cnt_cl}, SOCKS5={cnt_s5})",
            tg_verified.len()
        );

        println!("\n=== 7. Testing Direct TG-WS + Local 127.0.0.1:10809 Bridge ===");
        if let Ok(ms) = probe_tg_ws_direct(1400).await {
            println!("  [OK:TG-WS] Direct WebSocket resPQ verified in {ms} ms!");
        }
        let bridge = std::sync::Arc::new(TgLocalBridge::default());
        bridge.update_pool(&tg_verified);
        let port = start_tg_bridge(bridge.clone(), 10809, 1400)
            .await
            .expect("start tg bridge");
        let local_cand =
            parse_single_tg_token(&format!("tg://socks?server=127.0.0.1&port={port}"), true)
                .unwrap();
        match verify_tg_candidate_strict(&local_cand, 1400).await {
            Ok(v) => println!(
                "  [OK:TG-BRIDGE] End-to-end SOCKS5(127.0.0.1:{port}) -> DC2 resPQ in {} ms!",
                v.rtt_ms
            ),
            Err(e) => println!("  [ERR:TG-BRIDGE] {e}"),
        }
        bridge.stop();

        let exact_us = all_verified.iter().filter(|n| n.exit_country == "US").count();
        let exact_de = all_verified.iter().filter(|n| n.exit_country == "DE").count();
        let chain_us = opera_chain_verified
            .iter()
            .chain(tier1_chain_verified.iter())
            .filter(|n| n.exit_country == "US")
            .count();
        let chain_de_eu = opera_chain_verified
            .iter()
            .chain(tier1_chain_verified.iter())
            .filter(|n| matches!(n.exit_country.as_str(), "DE" | "NL" | "SE" | "AT" | "CH" | "FI" | "FR" | "PL"))
            .count();
        println!(
            "\n=== SUMMARY: total_vpn={} (exact_US={exact_us}, exact_DE={exact_de}, WL_RF={}, MASQUE-Chain_US={chain_us}, MASQUE-Chain_DE_EU={chain_de_eu}, opera_chain={}, tier1_chain={}) | tg_proxies_(<=1400ms)={} ===",
            all_verified.len(),
            wl_verified.len(),
            opera_chain_verified.len(),
            tier1_chain_verified.len(),
            tg_verified.len()
        );

        // === 8. v1.3 LIVE TEST: Optional Custom Subscription Import (VELOX_TEST_SUB_URL)
        //        + Deep-Link Unwrap + Strict Russian Whitelist TUN + Incremental Delta Sync ===
        println!("\n=== 8. v1.3 LIVE TEST: Custom Subscription + Strict WL-RF TUN + Delta Sync ===");
        let demo_sub = "https://sub.example.com/s/demo-profile";
        assert_eq!(
            unwrap_subscription_url(&format!("happ://add/{demo_sub}")).as_deref(),
            Some(demo_sub)
        );
        assert_eq!(
            unwrap_subscription_url(&format!("v2raytun://import/{demo_sub}")).as_deref(),
            Some(demo_sub)
        );
        if let Ok(test_sub_url) = std::env::var("VELOX_TEST_SUB_URL") {
            match fetch_subscription_smart(&test_sub_url, None, 1024 * 1024).await {
                Ok(fetched) => {
                    let sub_uris = extract_vpn_uris_from_subscription(&fetched.body, 100);
                    println!(
                        "  [SUB-OK] title='{}' userinfo='{}' via={} uris={} (dummy banners filtered)",
                        fetched.profile_title, fetched.userinfo, fetched.via_tag, sub_uris.len()
                    );
                    assert!(
                        !sub_uris.is_empty(),
                        "Custom subscription must extract >0 real URIs"
                    );
                    assert!(
                        !sub_uris
                            .iter()
                            .any(|u| u.contains("app.deprecated") || u.contains("00000000-0000")),
                        "Dummy banners must be filtered out"
                    );
                    let sub_cands: Vec<VpnCandidate> = sub_uris
                        .iter()
                        .filter_map(|u| {
                            parse_share_uri_to_candidate(u, "AUTO", 0, !u.contains("security=reality"))
                        })
                        .collect();
                    let valid_sub = filter_schema_valid(sub_cands, warp_acc.as_ref(), "custom_sub");
                    let wl_sub_cnt = valid_sub.iter().filter(|c| c.whitelist_friendly).count();
                    println!(
                        "  [SUB-PARSED] {}/{} schema-valid in xray-rust v0.10.0, WL-RF={wl_sub_cnt}",
                        valid_sub.len(),
                        sub_uris.len()
                    );
                    let sub_live =
                        run_batch_test(&valid_sub, 25500, "AUTO", warp_acc.as_ref(), "custom_sub")
                            .await;
                    println!(
                        "  [SUB-LIVE] {}/{} subscription servers LIVE!",
                        sub_live.len(),
                        valid_sub.len()
                    );
                    if !sub_live.is_empty() {
                        let (wl_tun, wl_prim, cnt) = build_production_tun_config_ex(
                            &sub_live,
                            None,
                            true,
                            true,
                            true,
                            10808,
                            warp_acc.as_ref(),
                        )
                        .expect("strict wl tun build");
                        LiveXray::validate_only(&wl_tun)
                            .expect("Strict WL-RF production TUN JSON must validate");
                        println!(
                            "  [WL-TUN-OK] Strict whitelist_mode=true TUN validated! primary={} (wl={}) backups={cnt}",
                            wl_prim.name, wl_prim.whitelist_friendly
                        );

                        // Test Smart Incremental Delta Revalidation (live + simulated dead node)
                        let mut delta_sample: Vec<VerifiedVpnNode> =
                            sub_live.iter().take(2).cloned().collect();
                        let mut fake_dead = delta_sample[0].clone();
                        fake_dead.id = "dead_old_node".into();
                        fake_dead.host = "192.0.2.1".into();
                        fake_dead.outbound_json["settings"]["vnext"][0]["address"] =
                            serde_json::json!("192.0.2.1");
                        delta_sample.push(fake_dead);
                        let pseudo: Vec<VpnCandidate> = delta_sample
                            .iter()
                            .map(|n| VpnCandidate {
                                id: n.id.clone(),
                                raw_uri: n.raw_uri.clone(),
                                name: n.name.clone(),
                                protocol: n.protocol.clone(),
                                transport: "tcp".into(),
                                security: "reality".into(),
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
                        let dcfg =
                            build_batch_probe_config(&pseudo, 25800, warp_acc.as_ref(), true);
                        let _dcore = LiveXray::start_json(&dcfg).expect("start delta core");
                        tokio::time::sleep(Duration::from_millis(200)).await;
                        let (kept, dead_ids, _) =
                            revalidate_cached_nodes_via_socks(&delta_sample, 25800).await;
                        println!(
                            "  [DELTA-SYNC-OK] kept_alive={} removed_dead={} (dead_ids={:?})",
                            kept.len(),
                            dead_ids.len(),
                            dead_ids
                        );
                        assert!(dead_ids.contains(&"dead_old_node".to_string()));
                    }
                }
                Err(e) => println!("  [SUB-ERR] {e}"),
            }
        } else {
            println!("  [SUB-SKIP] Set VELOX_TEST_SUB_URL=https://... to live-test a custom subscription");
        }

        // Also validate strict whitelist_mode=true TUN on free public Russian Whitelist nodes!
        if !wl_verified.is_empty() {
            let (wl_free_tun, wl_prim, cnt) = build_production_tun_config_ex(
                &wl_verified,
                None,
                true,
                true,
                true,
                10808,
                warp_acc.as_ref(),
            )
            .expect("free wl tun build");
            LiveXray::validate_only(&wl_free_tun)
                .expect("Free WL-RF production TUN JSON must validate!");
            println!(
                "  [FREE-WL-TUN-OK] Validated strict free Russian Whitelist TUN (primary={} sni={} backups={cnt})!",
                wl_prim.name, wl_prim.sni
            );
        }

        // Export sanitized FREE-ONLY public direct bootstrap seed (`source_tier==1`, `via_warp=false`, ZERO user sub keys!)
        if let Some(out_path) = seed_out {
            let mut seen_id = HashSet::new();
            let mut seed_vpn: Vec<VerifiedVpnNode> = Vec::new();
            let all_public: Vec<VerifiedVpnNode> = wl_verified
                .into_iter()
                .chain(de_verified.into_iter())
                .chain(us_verified.into_iter())
                .filter(|n| n.source_tier == 1 && !n.via_warp)
                .collect();

            // 1. Genuine Russian Whitelist (Минцифры SNI + CIDR VK/Yandex/CDN) + XHTTP + Hy2 (up to 14!)
            for n in &all_public {
                if seed_vpn.len() >= 14 {
                    break;
                }
                let is_rf_gem = n.whitelist_friendly
                    || n.host == "87.120.252.67"
                    || n.sni.contains("yandex.ru")
                    || n.sni.contains("vk.com")
                    || n.sni.contains("wb.ru")
                    || n.sni.contains("tbank.ru")
                    || n.sni.contains("ozon.ru")
                    || n.sni.contains("rutube.ru")
                    || n.sni.contains("gosuslugi.ru")
                    || n.protocol == "hysteria2"
                    || n.display_protocol.contains("XHTTP")
                    || n.display_protocol.contains("gRPC");
                if is_rf_gem && n.rtt_ms <= 3600 && seen_id.insert(n.id.clone()) {
                    seed_vpn.push(n.clone());
                }
            }
            // 2. Clean DE / FI / NL / AT / SE servers
            for n in &all_public {
                if seed_vpn.len() >= 22 {
                    break;
                }
                if matches!(n.exit_country.as_str(), "DE" | "FI" | "NL" | "EE" | "SE" | "AT" | "CH")
                    && n.rtt_ms <= 3200
                    && seen_id.insert(n.id.clone())
                {
                    seed_vpn.push(n.clone());
                }
            }
            // 3. Clean US VLESS Reality / Hy2 servers
            for n in &all_public {
                if seed_vpn.len() >= 30 {
                    break;
                }
                if n.exit_country == "US" && n.rtt_ms <= 1600 && seen_id.insert(n.id.clone()) {
                    seed_vpn.push(n.clone());
                }
            }
            for n in &mut seed_vpn {
                n.device_verified = false;
                n.fail_count = 0;
            }
            // Put Russian Whitelist (Минцифры SNI / CIDR) first so quickVerifySeed hits in <2s!
            seed_vpn.sort_by_key(|n| {
                let top = if n.whitelist_friendly { 0u8 } else { 1u8 };
                (top, n.rtt_ms)
            });

            let mut seen_tg = HashSet::new();
            let mut seed_tg = Vec::new();
            for p in tg_verified.iter().filter(|p| p.kind == "faketls").take(20) {
                if seen_tg.insert(p.id.clone()) {
                    seed_tg.push(p.clone());
                }
            }
            for p in tg_verified.iter().filter(|p| p.kind == "socks5").take(5) {
                if seen_tg.insert(p.id.clone()) {
                    seed_tg.push(p.clone());
                }
            }
            for p in tg_verified.iter().filter(|p| p.kind == "dd").take(7) {
                if seen_tg.insert(p.id.clone()) {
                    seed_tg.push(p.clone());
                }
            }
            seed_tg.truncate(32);

            let seed = BootstrapSeed {
                vpn_nodes: seed_vpn,
                tg_proxies: seed_tg,
            };
            let json = serde_json::to_string(&seed).unwrap();
            if let Some(parent) = std::path::Path::new(&out_path).parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            std::fs::write(&out_path, &json).expect("write seed");
            println!(
                "  Saved v1.3 bootstrap seed to {out_path} ({} VPN nodes [WL={}], {} TG proxies, {} bytes)",
                seed.vpn_nodes.len(),
                seed.vpn_nodes.iter().filter(|n| n.whitelist_friendly).count(),
                seed.tg_proxies.len(),
                json.len()
            );
        }
    });
}
