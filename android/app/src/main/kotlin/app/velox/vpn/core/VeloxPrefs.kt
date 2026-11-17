package app.velox.vpn.core

import android.content.Context
import android.content.Intent
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * Atomic cross-process settings and VPN runtime state store (shared safely between
 * the main Compose UI process, the dedicated `:vpn` tunnel process, and `VeloxTileService`).
 */
object VeloxPrefs {

    const val ACTION_VPN_RUNTIME = "app.velox.vpn.action.VPN_RUNTIME"
    const val ACTION_ENGINE_UPDATED = "app.velox.vpn.action.ENGINE_UPDATED"
    const val ACTION_TG_BRIDGE_CHANGED = "app.velox.vpn.action.TG_BRIDGE_CHANGED"
    const val EXTRA_TOAST_MESSAGE = "toast_msg"

    const val LOCAL_VPN_SOCKS_PORT = 10808
    const val LOCAL_TG_BRIDGE_PORT = 10809
    const val BATCH_PROBE_BASE_PORT = 24200
    const val SEED_PROBE_BASE_PORT = 24320

    private fun settingsFile(ctx: Context) = File(ctx.applicationContext.filesDir, "velox_settings.json")
    private fun runtimeFile(ctx: Context) = File(ctx.applicationContext.filesDir, "vpn_runtime.json")

    @Synchronized
    fun loadSettings(ctx: Context): AppSettings {
        val f = settingsFile(ctx)
        if (!f.exists()) return AppSettings()
        return runCatching {
            val o = JSONObject(f.readText(Charsets.UTF_8))
            AppSettings(
                region = o.optString("region", "US").ifBlank { "US" },
                pinnedNodeId = o.optString("pinnedNodeId", ""),
                whitelistMode = o.optBoolean("whitelistMode", false),
                bypassRu = o.optBoolean("bypassRu", true),
                fragmentTls = o.optBoolean("fragmentTls", true),
                autoHeal = o.optBoolean("autoHeal", true),
                profileMode = RuntimeProfileMode.from(o.optString("profileMode", "mobile")),
                tgMaxRttMs = o.optInt("tgMaxRttMs", 1400).coerceIn(300, 1400),
                excludedPackages = o.optJSONArray("excludedPackages").mapStrings().toSet(),
            )
        }.getOrDefault(AppSettings())
    }

    @Synchronized
    fun saveSettings(ctx: Context, s: AppSettings) {
        val o = JSONObject().apply {
            put("region", s.region)
            put("pinnedNodeId", s.pinnedNodeId)
            put("whitelistMode", s.whitelistMode)
            put("bypassRu", s.bypassRu)
            put("fragmentTls", s.fragmentTls)
            put("autoHeal", s.autoHeal)
            put("profileMode", s.profileMode.code)
            put("tgMaxRttMs", s.tgMaxRttMs.coerceIn(300, 1400))
            val arr = JSONArray()
            s.excludedPackages.forEach { arr.put(it) }
            put("excludedPackages", arr)
        }
        writeAtomic(settingsFile(ctx), o.toString())
    }

    fun updateSettings(ctx: Context, transform: (AppSettings) -> AppSettings): AppSettings {
        val current = loadSettings(ctx)
        val updated = transform(current)
        saveSettings(ctx, updated)
        return updated
    }

    fun loadRuntime(ctx: Context): VpnRuntimeState {
        val f = runtimeFile(ctx)
        if (!f.exists()) return VpnRuntimeState()
        val state = runCatching {
            VpnRuntimeState.fromJson(JSONObject(f.readText(Charsets.UTF_8)))
        }.getOrDefault(VpnRuntimeState())

        // If :vpn process was killed long ago without clean shutdown, sanitize stale status
        if (state.isActiveOrBusy && state.updatedAtMs > 0L) {
            val ageMs = System.currentTimeMillis() - state.updatedAtMs
            if (ageMs > 15 * 60 * 1000L) {
                return VpnRuntimeState()
            }
        }
        return state
    }

    @Synchronized
    fun publishRuntime(ctx: Context, state: VpnRuntimeState, broadcast: Boolean = true) {
        val stamped = state.copy(updatedAtMs = System.currentTimeMillis())
        writeAtomic(runtimeFile(ctx), stamped.toJson().toString())
        if (broadcast) {
            val intent = Intent(ACTION_VPN_RUNTIME).setPackage(ctx.packageName)
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

    private fun writeAtomic(target: File, content: String) {
        runCatching {
            target.parentFile?.mkdirs()
            val tmp = File(target.parentFile, "${target.name}.tmp")
            tmp.writeText(content, Charsets.UTF_8)
            if (!tmp.renameTo(target)) {
                target.writeText(content, Charsets.UTF_8)
                tmp.delete()
            }
        }
    }
}
