package app.velox.vpn.core

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import java.io.File
import java.util.concurrent.atomic.AtomicBoolean

/**
 * JNI interface to our pure-Rust `libvelox_engine.so` anti-DPI coordinator,
 * cross-process ring-buffer diagnostic logger, multi-echelon US/DE provisioner,
 * live ETA/progress tracker, and authentic Telegram DC proxy verifier.
 */
object VeloxNative {

    private val loaded = AtomicBoolean(false)
    private val initialized = AtomicBoolean(false)

    private fun ensureLibrary() {
        if (loaded.compareAndSet(false, true)) {
            System.loadLibrary("velox_engine")
        }
    }

    @Synchronized
    fun ensureInitialized(context: Context) {
        ensureLibrary()
        if (initialized.compareAndSet(false, true)) {
            val dir = File(context.applicationContext.filesDir, "engine").apply { mkdirs() }
            val stateExists = File(dir, "velox_state.json").exists()
            val seed = if (!stateExists) {
                runCatching {
                    context.applicationContext.assets
                        .open("bootstrap_seed.json")
                        .bufferedReader(Charsets.UTF_8)
                        .use { it.readText() }
                }.getOrDefault("")
            } else {
                ""
            }
            init(dir.absolutePath, seed)
        }
    }

    /** Re-sync persisted `velox_state.json` across main and `:vpn` processes (<0.3 ms, silent). */
    @Synchronized
    fun reloadFromDisk(context: Context) {
        ensureInitialized(context)
        val dir = File(context.applicationContext.filesDir, "engine").apply { mkdirs() }
        init(dir.absolutePath, "")
    }

    fun logInfo(context: Context, tag: String, msg: String) {
        runCatching {
            ensureInitialized(context)
            appendDiagLog("INFO", tag, msg)
        }
    }

    fun logOk(context: Context, tag: String, msg: String) {
        runCatching {
            ensureInitialized(context)
            appendDiagLog("OK", tag, msg)
        }
    }

    fun logWarn(context: Context, tag: String, msg: String) {
        runCatching {
            ensureInitialized(context)
            appendDiagLog("WARN", tag, msg)
        }
    }

    fun logErr(context: Context, tag: String, msg: String) {
        runCatching {
            ensureInitialized(context)
            appendDiagLog("ERR", tag, msg)
        }
    }

    /** Concise, privacy-safe active network summary for connection diagnostics. */
    fun describeActiveNetwork(context: Context): String = runCatching {
        val cm = context.getSystemService(ConnectivityManager::class.java)
            ?: return@runCatching "нет ConnectivityManager"
        val net = cm.activeNetwork ?: return@runCatching "НЕТ АКТИВНОЙ СЕТИ"
        val caps = cm.getNetworkCapabilities(net) ?: return@runCatching "нет capabilities"
        val transport = when {
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "Wi-Fi"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "Моб. сеть (LTE/5G)"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "Ethernet"
            else -> "Другая"
        }
        val valid = if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) "интернет=OK" else "интернет=не_подтв"
        val lp = cm.getLinkProperties(net)
        val hasV6 = lp?.linkAddresses?.any { it.address.hostAddress?.contains(':') == true } == true
        val dnsCnt = lp?.dnsServers?.size ?: 0
        val privDns = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && lp?.isPrivateDnsActive == true) {
            " DoT=${lp.privateDnsServerName ?: "auto"}"
        } else ""
        "$transport ($valid, DNS:$dnsCnt, IPv6:${if (hasV6) "да" else "нет"}$privDns, SDK ${Build.VERSION.SDK_INT})"
    }.getOrDefault("сеть=неизв")

    @JvmStatic
    external fun init(dataDir: String, seedJson: String): String

    @JvmStatic
    external fun getStateSnapshot(targetRegion: String, whitelistMode: Boolean): String

    @JvmStatic
    external fun prepareSeedQuickProbe(
        targetRegion: String,
        whitelistMode: Boolean,
        basePort: Int,
        maxCount: Int,
    ): String

    @JvmStatic
    external fun finalizeSeedQuickProbe(
        batchId: String,
        basePort: Int,
        targetRegion: String,
    ): String

    @JvmStatic
    external fun prepareVpnProbeBatch(
        targetRegion: String,
        whitelistMode: Boolean,
        fragmentTls: Boolean,
        basePort: Int,
        maxBatch: Int,
        activeSocksPort: Int,
    ): String

    @JvmStatic
    external fun finalizeVpnProbeBatch(
        batchId: String,
        basePort: Int,
        targetRegion: String,
    ): String

    @JvmStatic
    external fun getProbeProgress(): String

    @JvmStatic
    external fun buildTunConfig(
        targetRegion: String,
        pinnedNodeId: String,
        whitelistMode: Boolean,
        bypassRu: Boolean,
        fragmentTls: Boolean,
        localSocksPort: Int,
    ): String

    @JvmStatic
    external fun reportNodeFailure(nodeId: String, targetRegion: String, reason: String): String

    @JvmStatic
    external fun checkTunnelHealth(localSocksPort: Int): String

    @JvmStatic
    external fun refreshTgProxies(maxRttMs: Int, activeSocksPort: Int): String

    @JvmStatic
    external fun startTgBridge(port: Int, maxRttMs: Int): String

    @JvmStatic
    external fun stopTgBridge(): String

    @JvmStatic
    external fun getTgStatus(): String

    @JvmStatic
    external fun appendDiagLog(level: String, tag: String, message: String)

    @JvmStatic
    external fun readDiagLogs(maxLines: Int): String

    @JvmStatic
    external fun clearDiagLogs(): String

    @JvmStatic
    external fun addCustomItem(
        rawInput: String,
        kindHint: String,
        maxTgRttMs: Int,
    ): String

    @JvmStatic
    external fun toggleSource(url: String, enabled: Boolean): String

    @JvmStatic
    external fun regenerateWarp(activeSocksPort: Int): String

    @JvmStatic
    external fun prepareCustomSubProbe(basePort: Int, fragmentTls: Boolean): String

    @JvmStatic
    external fun prepareDeltaRevalidateBatch(basePort: Int, fragmentTls: Boolean): String

    @JvmStatic
    external fun finalizeDeltaRevalidateBatch(batchId: String, basePort: Int): String

    @JvmStatic
    external fun syncSubscription(url: String, maxTgRttMs: Int, activeSocksPort: Int): String

    @JvmStatic
    external fun removeSource(url: String): String
}
