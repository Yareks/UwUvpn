package app.velox.vpn.core

import android.annotation.SuppressLint
import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.provider.Settings
import java.io.File
import java.security.MessageDigest
import java.util.Locale
import java.util.concurrent.atomic.AtomicBoolean

/**
 * JNI interface to our pure-Rust `libvelox_engine.so` v1.6.0 anti-DPI coordinator:
 * - Dual-channel Primary + Hot-Standby zero-drop failover with strict country lock
 * - Full offline Happ `crypt`..`crypt5`, `incy://crypt1/`, AES-GCM body & HWID support
 * - Per-session CSPRNG-authenticated local SOCKS5 bridge & secret-redacted diagnostic logs
 * - Multi-echelon US/DE/WL-RF/0%-Ad-YouTube provisioner and DC-verified Telegram proxy engine.
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
            val app = context.applicationContext
            val dir = File(app.filesDir, "engine").apply { mkdirs() }
            val stateExists = File(dir, "velox_state.json").exists()
            val seed = if (!stateExists) {
                runCatching {
                    app.assets
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

    /** Re-sync persisted `velox_state.json` across main and `:vpn` processes (0 B read if mtime unchanged!). */
    @Synchronized
    fun reloadFromDisk(context: Context) {
        ensureInitialized(context)
        val dir = File(context.applicationContext.filesDir, "engine").apply { mkdirs() }
        init(dir.absolutePath, "")
    }

    /** Free transient DNS/HTTP/feed caches in Rust without touching active tunnel or saved nodes. */
    fun trimMemoryIfLoaded() {
        if (initialized.get()) {
            runCatching { trimMemory() }
        }
    }

    /**
     * Configure opt-in Happ-compatible `X-HWID` + device headers using a privacy-safe
     * one-way SHA-256 hash of app-scoped `ANDROID_ID` (zero telephony/IMEI permissions).
     */
    @SuppressLint("HardwareIds")
    fun syncHwidConfig(context: Context, enabled: Boolean): String = runCatching {
        ensureInitialized(context)
        val rawId = runCatching {
            Settings.Secure.getString(context.contentResolver, Settings.Secure.ANDROID_ID)
        }.getOrNull().orEmpty().ifBlank { "velox-anon-device" }
        val digest = MessageDigest.getInstance("SHA-256")
            .digest("velox-hwid-v1:$rawId:${Build.MODEL}".toByteArray(Charsets.UTF_8))
        val hwidHex = buildString(20) {
            for (i in 0 until 10) append(String.format("%02x", digest[i].toInt() and 0xff))
        }
        val model = "${Build.MANUFACTURER} ${Build.MODEL}".trim().take(48)
        val osVer = Build.VERSION.RELEASE.orEmpty().ifBlank { Build.VERSION.SDK_INT.toString() }
        val locale = Locale.getDefault().toLanguageTag().ifBlank { "ru-RU" }
        configureHwid(enabled, hwidHex, "Android", osVer, model, locale)
    }.getOrDefault("{}")

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

    /**
     * Strict physical upstream network check (`NET_CAPABILITY_NOT_VPN` + `NET_CAPABILITY_INTERNET`) —
     * never fooled by our own active `tun0` interface during elevator/subway/airplane transitions!
     */
    @Suppress("DEPRECATION")
    fun hasPhysicalInternet(context: Context): Boolean = runCatching {
        val cm = context.getSystemService(ConnectivityManager::class.java) ?: return@runCatching true
        val active = cm.activeNetwork
        if (active != null) {
            val caps = cm.getNetworkCapabilities(active)
            if (caps != null &&
                caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) &&
                caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            ) {
                return@runCatching true
            }
        }
        cm.allNetworks.any { net ->
            val caps = cm.getNetworkCapabilities(net) ?: return@any false
            caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) &&
                caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) ||
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) ||
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) ||
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_BLUETOOTH))
        }
    }.getOrDefault(true)

    /** Concise, privacy-safe physical upstream network summary for connection diagnostics. */
    @Suppress("DEPRECATION")
    fun describeActiveNetwork(context: Context): String = runCatching {
        val cm = context.getSystemService(ConnectivityManager::class.java)
            ?: return@runCatching "нет ConnectivityManager"
        val net = cm.allNetworks.firstOrNull { n ->
            val c = cm.getNetworkCapabilities(n) ?: return@firstOrNull false
            c.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) &&
                c.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                (c.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) ||
                    c.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) ||
                    c.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET))
        } ?: cm.activeNetwork?.takeIf { n ->
            cm.getNetworkCapabilities(n)?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) == true
        } ?: return@runCatching "НЕТ ФИЗИЧЕСКОЙ СЕТИ"

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
    external fun getStateSnapshotEx(
        targetRegion: String,
        whitelistMode: Boolean,
        includeLogs: Boolean,
    ): String

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
        adblock: Boolean,
        localSocksPort: Int,
        dualChannel: Boolean,
        idlePowerSave: Boolean,
        socksUser: String,
        socksPass: String,
    ): String

    @JvmStatic
    external fun configureHwid(
        enabled: Boolean,
        hwid: String,
        deviceOs: String,
        verOs: String,
        deviceModel: String,
        appLocale: String,
    ): String

    @JvmStatic
    external fun setLocalSocksAuth(port: Int, user: String, pass: String)

    @JvmStatic
    external fun verifyTunnelWeb(localSocksPort: Int, isOpera: Boolean): String

    @JvmStatic
    external fun trimMemory()

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
