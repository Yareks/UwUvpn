package app.velox.vpn.service

import android.app.Notification
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import app.velox.vpn.R
import app.velox.vpn.VeloxApp
import app.velox.vpn.core.VeloxNative
import app.velox.vpn.core.VeloxPrefs
import app.velox.vpn.ui.MainActivity
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.json.JSONObject

/**
 * Lightweight standalone foreground service hosting our pure-Rust auto-healing local
 * Telegram proxy (`127.0.0.1:10809`): direct `TG-WS` (`wss://kws1..5.web.telegram.org/apiws`)
 * with TLS ClientHello fragmentation + automatic failover across verified ≤1400 ms SOCKS5 proxies.
 */
class TgBridgeService : Service() {

    companion object {
        const val ACTION_START = "app.velox.vpn.tg.START"
        const val ACTION_STOP = "app.velox.vpn.tg.STOP"

        fun start(context: Context) {
            val i = Intent(context, TgBridgeService::class.java).setAction(ACTION_START)
            try {
                ContextCompat.startForegroundService(context, i)
            } catch (_: Throwable) {
                runCatching { context.startService(i) }
            }
        }

        fun stop(context: Context) {
            val i = Intent(context, TgBridgeService::class.java).setAction(ACTION_STOP)
            runCatching { context.startService(i) }
        }
    }

    private val crashHandler = CoroutineExceptionHandler { _, e ->
        runCatching { VeloxNative.logErr(this, "TG", "Сбой фоновой задачи прокси (сервис продолжает работу): ${e.message}") }
    }
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO + crashHandler)
    private var keeperJob: Job? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        VeloxNative.ensureInitialized(this)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            shutdownBridge()
            return START_NOT_STICKY
        }

        val notif = buildNotif(
            "Умный прокси Telegram активен",
            "127.0.0.1:${VeloxPrefs.LOCAL_TG_BRIDGE_PORT} · TG-WS + авто-резерв (≤1400 мс)"
        )
        runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                startForeground(
                    VeloxApp.NOTIF_ID_TG,
                    notif,
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
                )
            } else {
                startForeground(VeloxApp.NOTIF_ID_TG, notif)
            }
        }

        if (keeperJob?.isActive != true) {
            keeperJob = scope.launch {
                val settings = VeloxPrefs.loadSettings(this@TgBridgeService)
                val raw = VeloxNative.startTgBridge(
                    port = VeloxPrefs.LOCAL_TG_BRIDGE_PORT,
                    maxRttMs = settings.tgMaxRttMs,
                )
                val res = runCatching { JSONObject(raw) }.getOrNull()
                if (res?.optBoolean("ok", false) != true) {
                    shutdownBridge()
                    return@launch
                }
                val boundPort = res.optInt("port", VeloxPrefs.LOCAL_TG_BRIDGE_PORT)
                updateNotif(
                    "Умный прокси Telegram · 127.0.0.1:$boundPort",
                    "TG-WS (WebSocket 443) + авто-резерв ≤${settings.tgMaxRttMs} мс"
                )
                VeloxPrefs.notifyTgBridgeChanged(this@TgBridgeService)

                // Battery-smart maintenance: check every 45 min, skip heavy sweeps while screen is off
                // (Doze-friendly!) if we already hold >=8 verified proxies, and skip if offline.
                while (isActive) {
                    delay(45 * 60 * 1000L)
                    if (!VeloxNative.hasPhysicalInternet(this@TgBridgeService)) continue
                    val pm = getSystemService(android.os.PowerManager::class.java)
                    val screenOn = pm?.isInteractive != false
                    val st = runCatching { JSONObject(VeloxNative.getTgStatus()) }.getOrNull()
                    val aliveCnt = st?.optInt("alive", 0) ?: 0
                    if (!screenOn && aliveCnt >= 8) continue
                    val cur = VeloxPrefs.loadSettings(this@TgBridgeService)
                    val socks = VeloxPrefs.resolveActiveLocalSocksPort(this@TgBridgeService)
                    runCatching { VeloxNative.refreshTgProxies(cur.tgMaxRttMs, socks) }
                    VeloxNative.trimMemoryIfLoaded()
                    VeloxPrefs.notifyTgBridgeChanged(this@TgBridgeService)
                }
            }
        }
        return START_STICKY
    }

    private fun shutdownBridge() {
        keeperJob?.cancel()
        runCatching { VeloxNative.stopTgBridge() }
        VeloxPrefs.notifyTgBridgeChanged(this)
        runCatching { stopForeground(STOP_FOREGROUND_REMOVE) }
        stopSelf()
    }

    override fun onDestroy() {
        runCatching { VeloxNative.stopTgBridge() }
        scope.cancel()
        super.onDestroy()
    }

    private fun updateNotif(title: String, text: String) {
        val nm = getSystemService(NotificationManager::class.java) ?: return
        runCatching { nm.notify(VeloxApp.NOTIF_ID_TG, buildNotif(title, text)) }
    }

    private fun buildNotif(title: String, text: String): Notification {
        val openPi = PendingIntent.getActivity(
            this,
            20,
            Intent(this, MainActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val stopPi = PendingIntent.getService(
            this,
            21,
            Intent(this, TgBridgeService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val b = NotificationCompat.Builder(this, VeloxApp.CHANNEL_TG_BRIDGE)
            .setSmallIcon(R.drawable.ic_qs_shield)
            .setContentTitle(title)
            .setContentText(text)
            .setContentIntent(openPi)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setSilent(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .addAction(0, "Выключить", stopPi)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            b.setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
        }
        return b.build()
    }
}
