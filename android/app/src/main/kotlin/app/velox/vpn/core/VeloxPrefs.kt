package app.velox.vpn.core

import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.RandomAccessFile

/**
 * Advisory-locked (`FileLock`) atomic cross-process settings and VPN runtime state store,
 * shared cleanly between the Compose UI process, the `:vpn` tunnel process, and `VeloxTileService`.
 */
object VeloxPrefs {

    const val ACTION_VPN_RUNTIME = "app.velox.vpn.action.VPN_RUNTIME"
    const val ACTION_ENGINE_UPDATED = "app.velox.vpn.action.ENGINE_UPDATED"
    const val ACTION_TG_BRIDGE_CHANGED = "app.velox.vpn.action.TG_BRIDGE_CHANGED"
    const val EXTRA_TOAST_MESSAGE = "toast_msg"

    /** v1.7.2: runtime JSON is shipped inside the broadcast so the UI never touches disk. */
    const val EXTRA_RUNTIME_JSON = "runtime_json"

    /** v1.7.5: прогресс/финал подбора серверов из изолированного процесса `:probe`. */
    const val ACTION_PROBE_PROGRESS = "app.velox.vpn.action.PROBE_PROGRESS"
    const val ACTION_PROBE_FINISHED = "app.velox.vpn.action.PROBE_FINISHED"

    const val LOCAL_VPN_SOCKS_PORT = 10808
    const val LOCAL_TG_BRIDGE_PORT = 10809
    const val BATCH_PROBE_BASE_PORT = 24200
    const val SEED_PROBE_BASE_PORT = 24320

    private fun settingsFile(ctx: Context) = File(ctx.applicationContext.filesDir, "velox_settings.json")
    private fun runtimeFile(ctx: Context) = File(ctx.applicationContext.filesDir, "vpn_runtime.json")
    private fun socksAuthFile(ctx: Context) = File(ctx.applicationContext.filesDir, "socks_session.json")
    private fun lockFile(ctx: Context, name: String) = File(ctx.applicationContext.filesDir, "$name.lock")

    /** Save ephemeral per-session CSPRNG SOCKS5 credentials (mode-private `filesDir` — readable only by our UID). */
    fun saveSessionSocksAuth(ctx: Context, port: Int, user: String, pass: String) {
        val o = JSONObject().apply {
            put("port", port)
            put("user", user)
            put("pass", pass)
        }
        writeAtomicLocked(lockFile(ctx, "socks"), socksAuthFile(ctx), o.toString())
        runCatching {
            val f = socksAuthFile(ctx)
            f.setReadable(false, false)
            f.setReadable(true, true)
            f.setWritable(false, false)
            f.setWritable(true, true)
        }
    }

    fun clearSessionSocksAuth(ctx: Context) {
        runCatching { socksAuthFile(ctx).delete() }
    }

    /**
     * When `:vpn` is actively `CONNECTED`, loads the current per-session CSPRNG SOCKS5 credentials
     * into this process's `VeloxNative` and returns `LOCAL_VPN_SOCKS_PORT` (10808); otherwise returns `0`.
     * Enables authenticated `check-url-via-proxy` subscription updates, TG refreshes, and WARP key rotation!
     */
    fun resolveActiveLocalSocksPort(ctx: Context): Int {
        if (loadRuntime(ctx).phase != VpnPhase.CONNECTED) {
            runCatching { VeloxNative.setLocalSocksAuth(0, "", "") }
            return 0
        }
        val f = socksAuthFile(ctx)
        if (!f.exists()) return 0
        return runCatching {
            val o = JSONObject(f.readText(Charsets.UTF_8))
            val p = o.optInt("port", LOCAL_VPN_SOCKS_PORT)
            val u = o.optString("user", "")
            val pw = o.optString("pass", "")
            if (p > 0 && u.isNotEmpty() && pw.isNotEmpty()) {
                VeloxNative.setLocalSocksAuth(p, u, pw)
                p
            } else {
                0
            }
        }.getOrDefault(0)
    }

    @Synchronized
    fun loadSettings(ctx: Context): AppSettings {
        val f = settingsFile(ctx)
        if (!f.exists()) return AppSettings()
        return runCatching {
            val o = JSONObject(f.readText(Charsets.UTF_8))
            AppSettings(
                region = o.optString("region", "AUTO").ifBlank { "AUTO" },
                pinnedNodeId = o.optString("pinnedNodeId", ""),
                dualChannel = o.optBoolean("dualChannel", true),
                sendHwid = o.optBoolean("sendHwid", false),
                whitelistMode = o.optBoolean("whitelistMode", false),
                bypassRu = o.optBoolean("bypassRu", true),
                fragmentTls = o.optBoolean("fragmentTls", true),
                adblockYoutube = o.optBoolean("adblockYoutube", true),
                autoHeal = o.optBoolean("autoHeal", true),
                profileMode = RuntimeProfileMode.from(o.optString("profileMode", "mobile")),
                tgMaxRttMs = o.optInt("tgMaxRttMs", 1400).coerceIn(300, 1400),
                excludedPackages = o.optJSONArray("excludedPackages").mapStrings().toSet(),
                rulesVpn = o.optString("rulesVpn", ""),
                rulesDirect = o.optString("rulesDirect", ""),
                rulesBlock = o.optString("rulesBlock", ""),
            )
        }.getOrDefault(AppSettings())
    }

    @Synchronized
    fun saveSettings(ctx: Context, s: AppSettings) {
        val o = JSONObject().apply {
            put("region", s.region)
            put("pinnedNodeId", s.pinnedNodeId)
            put("dualChannel", s.dualChannel)
            put("sendHwid", s.sendHwid)
            put("whitelistMode", s.whitelistMode)
            put("bypassRu", s.bypassRu)
            put("fragmentTls", s.fragmentTls)
            put("adblockYoutube", s.adblockYoutube)
            put("autoHeal", s.autoHeal)
            put("profileMode", s.profileMode.code)
            put("tgMaxRttMs", s.tgMaxRttMs.coerceIn(300, 1400))
            put("rulesVpn", s.rulesVpn)
            put("rulesDirect", s.rulesDirect)
            put("rulesBlock", s.rulesBlock)
            val arr = JSONArray()
            s.excludedPackages.forEach { arr.put(it) }
            put("excludedPackages", arr)
        }
        writeAtomicLocked(lockFile(ctx, "settings"), settingsFile(ctx), o.toString())
    }

    @Synchronized
    fun updateSettings(ctx: Context, transform: (AppSettings) -> AppSettings): AppSettings {
        return withCrossProcessLock(lockFile(ctx, "settings")) {
            val current = loadSettings(ctx)
            val updated = transform(current)
            val o = JSONObject().apply {
                put("region", updated.region)
                put("pinnedNodeId", updated.pinnedNodeId)
                put("dualChannel", updated.dualChannel)
                put("sendHwid", updated.sendHwid)
                put("whitelistMode", updated.whitelistMode)
                put("bypassRu", updated.bypassRu)
                put("fragmentTls", updated.fragmentTls)
                put("adblockYoutube", updated.adblockYoutube)
                put("autoHeal", updated.autoHeal)
                put("profileMode", updated.profileMode.code)
                put("tgMaxRttMs", updated.tgMaxRttMs.coerceIn(300, 1400))
                put("rulesVpn", updated.rulesVpn)
                put("rulesDirect", updated.rulesDirect)
                put("rulesBlock", updated.rulesBlock)
                val arr = JSONArray()
                updated.excludedPackages.forEach { arr.put(it) }
                put("excludedPackages", arr)
            }
            writeAtomicUnlocked(settingsFile(ctx), o.toString())
            updated
        }
    }

    fun loadRuntime(ctx: Context): VpnRuntimeState {
        val f = runtimeFile(ctx)
        if (!f.exists()) return VpnRuntimeState()
        val state = runCatching {
            VpnRuntimeState.fromJson(JSONObject(f.readText(Charsets.UTF_8)))
        }.getOrDefault(VpnRuntimeState())

        val ageMs = if (state.updatedAtMs > 0L) {
            (System.currentTimeMillis() - state.updatedAtMs).coerceAtLeast(0L)
        } else {
            Long.MAX_VALUE
        }

        // Instant real OS VPN check: if file claims CONNECTED (>4s old) while Android has zero active
        // TRANSPORT_VPN interface (e.g. :vpn was killed by OEM task killer or reboot), clear immediately!
        if (state.phase == VpnPhase.CONNECTED && ageMs > 4_000L && !isSystemVpnTransportUp(ctx)) {
            return VpnRuntimeState()
        }
        // Transient FETCHING/CONNECTING without updates for >90s means the service died mid-connect
        if ((state.phase == VpnPhase.FETCHING || state.phase == VpnPhase.CONNECTING) && ageMs > 90_000L) {
            return VpnRuntimeState()
        }
        // HEALING can stay silent while waiting for elevator/subway network, cap at 6h if orphaned
        if (state.phase == VpnPhase.HEALING && ageMs > 6 * 3600 * 1000L) {
            return VpnRuntimeState()
        }
        return state
    }

    @Suppress("DEPRECATION")
    private fun isSystemVpnTransportUp(ctx: Context): Boolean = runCatching {
        val cm = ctx.getSystemService(ConnectivityManager::class.java) ?: return@runCatching true
        cm.allNetworks.any { net ->
            cm.getNetworkCapabilities(net)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
        }
    }.getOrDefault(true)

    @Synchronized
    fun publishRuntime(ctx: Context, state: VpnRuntimeState, broadcast: Boolean = true) {
        val stamped = state.copy(updatedAtMs = System.currentTimeMillis())
        val json = stamped.toJson().toString()
        writeAtomicLocked(lockFile(ctx, "runtime"), runtimeFile(ctx), json)
        if (broadcast) {
            val intent = Intent(ACTION_VPN_RUNTIME).setPackage(ctx.packageName)
            // Payload is ~1 KB — Android delivers it asynchronously; the UI parses it in memory
            // instead of re-reading + re-parsing `vpn_runtime.json` from flash on the main thread.
            intent.putExtra(EXTRA_RUNTIME_JSON, json)
            runCatching { ctx.sendBroadcast(intent) }
        }
    }

    fun notifyEngineUpdated(ctx: Context, toastMessage: String? = null) {
        val intent = Intent(ACTION_ENGINE_UPDATED).setPackage(ctx.packageName)
        if (!toastMessage.isNullOrBlank()) {
            intent.putExtra(EXTRA_TOAST_MESSAGE, toastMessage)
        }
        runCatching { ctx.sendBroadcast(intent) }
    }

    fun notifyTgBridgeChanged(ctx: Context) {
        val intent = Intent(ACTION_TG_BRIDGE_CHANGED).setPackage(ctx.packageName)
        runCatching { ctx.sendBroadcast(intent) }
    }

    /**
     * Cross-process advisory lock around `block`.
     *
     * v1.7.2 fix: раньше исключение ВНУТРИ `block` перехватывалось и `block` выполнялся повторно,
     * уже без блокировки (двойная запись/двойное чтение). Теперь различаем «не удалось взять
     * блокировку» (тогда — однократный проход без неё) и «упало внутри блока» (пробрасываем как есть).
     */
    private inline fun <T> withCrossProcessLock(lockTarget: File, block: () -> T): T {
        var raf: RandomAccessFile? = null
        var lock: java.nio.channels.FileLock? = null
        try {
            lockTarget.parentFile?.mkdirs()
            raf = RandomAccessFile(lockTarget, "rw")
            lock = raf.channel.lock()
        } catch (_: Throwable) {
            // ФС без поддержки блокировок — работаем без межпроцессного лока (запись атомарна через rename)
            runCatching { lock?.release() }
            runCatching { raf?.close() }
            return block()
        }
        return try {
            block()
        } finally {
            runCatching { lock?.release() }
            runCatching { raf?.close() }
        }
    }

    private fun writeAtomicLocked(lockTarget: File, target: File, content: String) {
        withCrossProcessLock(lockTarget) {
            writeAtomicUnlocked(target, content)
        }
    }

    private fun writeAtomicUnlocked(target: File, content: String) {
        runCatching {
            target.parentFile?.mkdirs()
            val tmp = File(
                target.parentFile,
                "${target.name}.${android.os.Process.myPid()}.tmp"
            )
            tmp.writeText(content, Charsets.UTF_8)
            if (!tmp.renameTo(target)) {
                target.writeText(content, Charsets.UTF_8)
                tmp.delete()
            }
        }
    }
}
