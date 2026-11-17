//! Android JNI bridge (`app.velox.vpn.core.VeloxNative`) with panic guards so native errors
//! can never crash the Android UI or `:vpn` process.

use crate::store::ENGINE;
use jni::objects::{JClass, JString};
use jni::sys::{jboolean, jint, jstring};
use jni::JNIEnv;
use std::panic::{catch_unwind, AssertUnwindSafe};

fn jstr_in(env: &mut JNIEnv, s: &JString) -> String {
    if s.is_null() {
        return String::new();
    }
    env.get_string(s)
        .map(|js| js.into())
        .unwrap_or_default()
}

fn jstr_out(env: &mut JNIEnv, s: String) -> jstring {
    env.new_string(s)
        .map(|js| js.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

fn guarded<F: FnOnce(&mut JNIEnv) -> String>(env: &mut JNIEnv, f: F) -> jstring {
    let res = catch_unwind(AssertUnwindSafe(|| f(env)))
        .unwrap_or_else(|_| "{\"ok\":false,\"error\":\"internal rust panic\"}".to_string());
    jstr_out(env, res)
}

#[no_mangle]
pub extern "system" fn Java_app_velox_vpn_core_VeloxNative_init(
    mut env: JNIEnv,
    _class: JClass,
    data_dir: JString,
    seed_json: JString,
) -> jstring {
    guarded(&mut env, |e| {
        let dir = jstr_in(e, &data_dir);
        let seed = jstr_in(e, &seed_json);
        ENGINE.init(&dir, &seed)
    })
}

#[no_mangle]
pub extern "system" fn Java_app_velox_vpn_core_VeloxNative_getStateSnapshot(
    mut env: JNIEnv,
    _class: JClass,
    target_region: JString,
    whitelist_mode: jboolean,
) -> jstring {
    guarded(&mut env, |e| {
        let reg = jstr_in(e, &target_region);
        ENGINE.get_state_snapshot(&reg, whitelist_mode != 0)
    })
}

#[no_mangle]
pub extern "system" fn Java_app_velox_vpn_core_VeloxNative_prepareSeedQuickProbe(
    mut env: JNIEnv,
    _class: JClass,
    target_region: JString,
    whitelist_mode: jboolean,
    base_port: jint,
    max_count: jint,
) -> jstring {
    guarded(&mut env, |e| {
        let reg = jstr_in(e, &target_region);
        ENGINE.prepare_seed_quick_probe(
            &reg,
            whitelist_mode != 0,
            base_port.clamp(1025, 65000) as u16,
            max_count.clamp(4, 18) as usize,
        )
    })
}

#[no_mangle]
pub extern "system" fn Java_app_velox_vpn_core_VeloxNative_finalizeSeedQuickProbe(
    mut env: JNIEnv,
    _class: JClass,
    batch_id: JString,
    base_port: jint,
    target_region: JString,
) -> jstring {
    guarded(&mut env, |e| {
        let bid = jstr_in(e, &batch_id);
        let reg = jstr_in(e, &target_region);
        ENGINE.finalize_seed_quick_probe(&bid, base_port.clamp(1025, 65000) as u16, &reg)
    })
}

#[no_mangle]
pub extern "system" fn Java_app_velox_vpn_core_VeloxNative_prepareVpnProbeBatch(
    mut env: JNIEnv,
    _class: JClass,
    target_region: JString,
    whitelist_mode: jboolean,
    fragment_tls: jboolean,
    base_port: jint,
    max_batch: jint,
    active_socks_port: jint,
) -> jstring {
    guarded(&mut env, |e| {
        let reg = jstr_in(e, &target_region);
        ENGINE.prepare_vpn_probe_batch(
            &reg,
            whitelist_mode != 0,
            fragment_tls != 0,
            base_port.clamp(1025, 65000) as u16,
            max_batch.clamp(8, 46) as usize,
            active_socks_port.clamp(0, 65535) as u16,
        )
    })
}

#[no_mangle]
pub extern "system" fn Java_app_velox_vpn_core_VeloxNative_finalizeVpnProbeBatch(
    mut env: JNIEnv,
    _class: JClass,
    batch_id: JString,
    base_port: jint,
    target_region: JString,
) -> jstring {
    guarded(&mut env, |e| {
        let bid = jstr_in(e, &batch_id);
        let reg = jstr_in(e, &target_region);
        ENGINE.finalize_vpn_probe_batch(&bid, base_port.clamp(1025, 65000) as u16, &reg)
    })
}

#[no_mangle]
pub extern "system" fn Java_app_velox_vpn_core_VeloxNative_getProbeProgress(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    guarded(&mut env, |_| ENGINE.get_probe_progress())
}

#[no_mangle]
pub extern "system" fn Java_app_velox_vpn_core_VeloxNative_buildTunConfig(
    mut env: JNIEnv,
    _class: JClass,
    target_region: JString,
    pinned_node_id: JString,
    whitelist_mode: jboolean,
    bypass_ru: jboolean,
    fragment_tls: jboolean,
    local_socks_port: jint,
) -> jstring {
    guarded(&mut env, |e| {
        let reg = jstr_in(e, &target_region);
        let pid = jstr_in(e, &pinned_node_id);
        ENGINE.build_tun_config(
            &reg,
            &pid,
            whitelist_mode != 0,
            bypass_ru != 0,
            fragment_tls != 0,
            local_socks_port.clamp(0, 65535) as u16,
        )
    })
}

#[no_mangle]
pub extern "system" fn Java_app_velox_vpn_core_VeloxNative_reportNodeFailure(
    mut env: JNIEnv,
    _class: JClass,
    node_id: JString,
    target_region: JString,
    reason: JString,
) -> jstring {
    guarded(&mut env, |e| {
        let nid = jstr_in(e, &node_id);
        let reg = jstr_in(e, &target_region);
        let rsn = jstr_in(e, &reason);
        ENGINE.report_node_failure(&nid, &reg, &rsn)
    })
}

#[no_mangle]
pub extern "system" fn Java_app_velox_vpn_core_VeloxNative_checkTunnelHealth(
    mut env: JNIEnv,
    _class: JClass,
    local_socks_port: jint,
) -> jstring {
    guarded(&mut env, |_| {
        ENGINE.check_tunnel_health(local_socks_port.clamp(1025, 65535) as u16)
    })
}

#[no_mangle]
pub extern "system" fn Java_app_velox_vpn_core_VeloxNative_refreshTgProxies(
    mut env: JNIEnv,
    _class: JClass,
    max_rtt_ms: jint,
    active_socks_port: jint,
) -> jstring {
    guarded(&mut env, |_| {
        ENGINE.refresh_tg_proxies(
            max_rtt_ms.clamp(300, 1400) as u32,
            active_socks_port.clamp(0, 65535) as u16,
        )
    })
}

#[no_mangle]
pub extern "system" fn Java_app_velox_vpn_core_VeloxNative_startTgBridge(
    mut env: JNIEnv,
    _class: JClass,
    port: jint,
    max_rtt_ms: jint,
) -> jstring {
    guarded(&mut env, |_| {
        ENGINE.start_local_tg_bridge(
            port.clamp(1025, 65535) as u16,
            max_rtt_ms.clamp(300, 1400) as u32,
        )
    })
}

#[no_mangle]
pub extern "system" fn Java_app_velox_vpn_core_VeloxNative_stopTgBridge(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    guarded(&mut env, |_| ENGINE.stop_local_tg_bridge())
}

#[no_mangle]
pub extern "system" fn Java_app_velox_vpn_core_VeloxNative_getTgStatus(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    guarded(&mut env, |_| ENGINE.get_tg_status())
}

#[no_mangle]
pub extern "system" fn Java_app_velox_vpn_core_VeloxNative_appendDiagLog(
    mut env: JNIEnv,
    _class: JClass,
    level: JString,
    tag: JString,
    message: JString,
) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let lvl = jstr_in(&mut env, &level);
        let tg = jstr_in(&mut env, &tag);
        let msg = jstr_in(&mut env, &message);
        ENGINE.append_diag_log(&lvl, &tg, &msg);
    }));
}

#[no_mangle]
pub extern "system" fn Java_app_velox_vpn_core_VeloxNative_readDiagLogs(
    mut env: JNIEnv,
    _class: JClass,
    max_lines: jint,
) -> jstring {
    guarded(&mut env, |_| {
        ENGINE.read_diag_logs_json(max_lines.clamp(20, 600) as usize)
    })
}

#[no_mangle]
pub extern "system" fn Java_app_velox_vpn_core_VeloxNative_clearDiagLogs(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    guarded(&mut env, |_| ENGINE.clear_diag_logs_json())
}

#[no_mangle]
pub extern "system" fn Java_app_velox_vpn_core_VeloxNative_addCustomItem(
    mut env: JNIEnv,
    _class: JClass,
    raw_input: JString,
    kind_hint: JString,
    max_tg_rtt_ms: jint,
) -> jstring {
    guarded(&mut env, |e| {
        let inp = jstr_in(e, &raw_input);
        let hint = jstr_in(e, &kind_hint);
        ENGINE.add_custom_item(&inp, &hint, max_tg_rtt_ms.clamp(300, 1400) as u32)
    })
}

#[no_mangle]
pub extern "system" fn Java_app_velox_vpn_core_VeloxNative_toggleSource(
    mut env: JNIEnv,
    _class: JClass,
    url: JString,
    enabled: jboolean,
) -> jstring {
    guarded(&mut env, |e| {
        let u = jstr_in(e, &url);
        ENGINE.toggle_source(&u, enabled != 0)
    })
}

#[no_mangle]
pub extern "system" fn Java_app_velox_vpn_core_VeloxNative_regenerateWarp(
    mut env: JNIEnv,
    _class: JClass,
    active_socks_port: jint,
) -> jstring {
    guarded(&mut env, |_| {
        ENGINE.regenerate_warp(active_socks_port.clamp(0, 65535) as u16)
    })
}

#[no_mangle]
pub extern "system" fn Java_app_velox_vpn_core_VeloxNative_prepareCustomSubProbe(
    mut env: JNIEnv,
    _class: JClass,
    base_port: jint,
    fragment_tls: jboolean,
) -> jstring {
    guarded(&mut env, |_| {
        ENGINE.prepare_custom_sub_probe(
            base_port.clamp(1025, 65000) as u16,
            fragment_tls != 0,
        )
    })
}

#[no_mangle]
pub extern "system" fn Java_app_velox_vpn_core_VeloxNative_prepareDeltaRevalidateBatch(
    mut env: JNIEnv,
    _class: JClass,
    base_port: jint,
    fragment_tls: jboolean,
) -> jstring {
    guarded(&mut env, |_| {
        ENGINE.prepare_delta_revalidate_batch(
            base_port.clamp(1025, 65000) as u16,
            fragment_tls != 0,
        )
    })
}

#[no_mangle]
pub extern "system" fn Java_app_velox_vpn_core_VeloxNative_finalizeDeltaRevalidateBatch(
    mut env: JNIEnv,
    _class: JClass,
    batch_id: JString,
    base_port: jint,
) -> jstring {
    guarded(&mut env, |e| {
        let bid = jstr_in(e, &batch_id);
        ENGINE.finalize_delta_revalidate_batch(&bid, base_port.clamp(1025, 65000) as u16)
    })
}

#[no_mangle]
pub extern "system" fn Java_app_velox_vpn_core_VeloxNative_syncSubscription(
    mut env: JNIEnv,
    _class: JClass,
    url: JString,
    max_tg_rtt_ms: jint,
    active_socks_port: jint,
) -> jstring {
    guarded(&mut env, |e| {
        let u = jstr_in(e, &url);
        ENGINE.fetch_and_upsert_subscription(
            &u,
            "auto",
            max_tg_rtt_ms.clamp(300, 1400) as u32,
            active_socks_port.clamp(0, 65535) as u16,
        )
    })
}

#[no_mangle]
pub extern "system" fn Java_app_velox_vpn_core_VeloxNative_removeSource(
    mut env: JNIEnv,
    _class: JClass,
    url: JString,
) -> jstring {
    guarded(&mut env, |e| {
        let u = jstr_in(e, &url);
        ENGINE.remove_source(&u)
    })
}
