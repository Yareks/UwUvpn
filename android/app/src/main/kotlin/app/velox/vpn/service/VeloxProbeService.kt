package app.velox.vpn.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import app.velox.vpn.R
import app.velox.vpn.core.AppSettings
import app.velox.vpn.core.LiveProgressUpdate
import app.velox.vpn.core.VeloxNative
import app.velox.vpn.core.VeloxPrefs
import app.velox.vpn.core.VpnBatchProber
import app.velox.vpn.core.regionTitleRu
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import org.json.JSONObject

/**
 * v1.7.5 — подбор и проверка серверов в ОТДЕЛЬНОМ процессе (`:probe`).
 *
 * Зачем: проверка узлов поднимает собственное ядро Xray и дергает десятки тысяч строк парсеров
 * внутри процесса. Любой сбой в этой цепочке (нативное падение, OOM, ошибка на служебном потоке)
 * закрывал приложение целиком — пользователь видел «краш при обновлении/загрузке серверов».
 * Теперь эта работа живёт в изолированном процессе: если он упадёт, UI останется на экране и
 * покажет ошибку, а данные (общий `velox_state.json`) не пострадают.
 */
class VeloxProbeService : Service() {

    companion object {
        const val ACTION_RUN = "app.velox.vpn.probe.RUN"
        const val ACTION_STOP = "app.velox.vpn.probe.STOP"
        const val CHANNEL_ID = "velox_probe"
        const val NOTIF_ID = 1003
        const val EXTRA_MODE = "mode"
        const val MODE_REFRESH = "refresh"
        const val MODE_DISCOVER = "discover"
        const val MODE_CUSTOM = "custom"
        const val MODE_SUB_SYNC = "sub_sync"
        const val MODE_IMPORT = "import"

        /** Доп. параметры для режимов «обновить подписку» / «импорт ссылки». */
        const val EXTRA_URL = "url"
        const val EXTRA_KIND = "kind"

        /** UI-хуки: прогресс и завершение приходят широковещательно (процессы разные!). */
        fun run(context: Context, mode: String, url: String = "", kind: String = "auto") {
            val i = Intent(context, VeloxProbeService::class.java)
                .setAction(ACTION_RUN)
                .putExtra(EXTRA_MODE, mode)
                .putExtra(EXTRA_URL, url)
                .putExtra(EXTRA_KIND, kind)
            try {
                ContextCompat.startForegroundService(context, i)
            } catch (_: Throwable) {
                runCatching { context.startService(i) }
            }
        }

        fun stop(context: Context) {
            runCatching {
                context.startService(
                    Intent(context, VeloxProbeService::class.java).setAction(ACTION_STOP)
                )
            }
        }

        /** Последний результат (JSON) — его читает UI для показа сводки. */
        fun lastResult(ctx: Context): JSONObject? = runCatching {
            val f = java.io.File(ctx.applicationContext.filesDir, "probe_result.json")
            if (!f.exists()) null else JSONObject(f.readText())
        }.getOrNull()
    }

    private val crashHandler = CoroutineExceptionHandler { _, e ->
        runCatching { VeloxNative.logErr(this, "PROBE", "Ошибка процесса проверки: ${VpnBatchProber.formatThrowable(e)}") }
        finishWith(ok = false, message = "Сбой проверки: ${e.message?.take(120) ?: "неизвестно"}")
    }
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO + crashHandler)
    private var job: Job? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        runCatching { VeloxNative.ensureInitialized(this) }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            job?.cancel()
            stopSelf()
            return START_NOT_STICKY
        }
        val mode = intent?.getStringExtra(EXTRA_MODE) ?: MODE_REFRESH
        val url = intent?.getStringExtra(EXTRA_URL).orEmpty()
        val kind = intent?.getStringExtra(EXTRA_KIND) ?: "auto"
        val title = when (mode) {
            MODE_DISCOVER -> "Поиск новых серверов…"
            MODE_SUB_SYNC -> "Обновление подписки…"
            MODE_IMPORT -> "Загрузка подписки / ключа…"
            else -> "Проверка серверов…"
        }
        promoteForeground(title)
        if (job?.isActive != true) {
            job = scope.launch { runProbe(mode, url, kind) }
        }
        return START_STICKY
    }

    private suspend fun runProbe(mode: String, url: String = "", kind: String = "auto") {
        val settings = VeloxPrefs.loadSettings(this)
        val progress: (LiveProgressUpdate) -> Unit = { upd ->
            runCatching {
                val b = Intent(VeloxPrefs.ACTION_PROBE_PROGRESS).setPackage(packageName)
                b.putExtra("stageIndex", upd.stageIndex)
                b.putExtra("stageTotal", upd.stageTotal)
                b.putExtra("percent", upd.percent)
                b.putExtra("etaSeconds", upd.etaSeconds)
                b.putExtra("statusLine", upd.statusLine)
                b.putExtra("detailLine", upd.detailLine)
                sendBroadcast(b)
                if (upd.percent % 20 < 3) updateText("${upd.statusLine} ${upd.percent}%")
            }
        }
        runCatching { VeloxNative.logInfo(this, "PROBE", "Процесс проверки запущен (mode=$mode): ${regionTitleRu(settings.region)}") }

        // v1.7.6: обновление/импорт подписки — самая тяжёлая операция после проверки узлов
        // (расшифровка Happ crypt0..crypt5, разбор Remnawave/Marzban/3x-ui). Раньше это шло в
        // процессе приложения и его падение выглядело как «краш при обновлении подписки».
        if (mode == MODE_SUB_SYNC || mode == MODE_IMPORT) {
            val activeSocks = VeloxPrefs.resolveActiveLocalSocksPort(this)
            val raw = runCatching {
                VeloxNative.reloadFromDisk(this)
                VeloxNative.syncHwidConfig(this, settings.sendHwid)
                if (mode == MODE_SUB_SYNC) {
                    VeloxNative.syncSubscription(url, settings.tgMaxRttMs, activeSocks)
                } else {
                    VeloxNative.addCustomItem(url, kind, settings.tgMaxRttMs)
                }
            }.getOrElse { e -> """{"ok":false,"error":"${VpnBatchProber.formatThrowable(e).take(180)}"}""" }

            val obj = runCatching { JSONObject(raw) }.getOrDefault(JSONObject())
            VeloxNative.trimMemoryIfLoaded()
            // Результат целиком (включая subName/importedCount/needsCustomProbe) — для UI
            runCatching { java.io.File(filesDir, "probe_result.json").writeText(obj.toString()) }
            val ok = obj.optBoolean("ok", false)
            finishWith(ok, if (ok) obj.optString("message", "Готово") else obj.optString("error", "Не удалось"))
            return
        }

        val result = when (mode) {
            MODE_DISCOVER -> runCatching { VpnBatchProber.discoverMoreConnectionsBlocking(this, settings, progress) }
            MODE_CUSTOM -> runCatching {
                VpnBatchProber.verifyCustomSubBlocking(
                    context = this,
                    settings = settings,
                    vpnService = null,
                    onProgress = progress,
                )
            }
            else -> runCatching {
                VpnBatchProber.refreshPoolBlocking(
                    context = this,
                    settings = settings,
                    vpnService = null,
                    maxBatch = 44,
                    shouldAbort = null,
                    onProgress = progress,
                )
            }
        }

        VeloxNative.trimMemoryIfLoaded()
        val payload = JSONObject().apply {
            val ok = result.getOrNull()
            put("mode", mode)
            put("ok", ok?.ok ?: false)
            put("newlyVerified", ok?.newlyVerified ?: 0)
            put("testedCount", ok?.testedCount ?: 0)
            put("liveAvailable", ok?.liveAvailable ?: 0)
            put("error", ok?.error ?: VpnBatchProber.formatThrowable(result.exceptionOrNull()).take(160))
        }
        runCatching {
            java.io.File(filesDir, "probe_result.json").writeText(payload.toString())
        }
        finishWith(payload.optBoolean("ok", false), payload.optString("error", ""))
    }

    private fun finishWith(ok: Boolean, message: String) {
        runCatching {
            val b = Intent(VeloxPrefs.ACTION_PROBE_FINISHED).setPackage(packageName)
            b.putExtra("ok", ok)
            b.putExtra("message", message)
            sendBroadcast(b)
        }
        runCatching { VeloxPrefs.notifyEngineUpdated(this, null) }
        runCatching { stopForegroundCompat() }
        stopSelf()
    }

    private fun ensureChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val nm = getSystemService(NotificationManager::class.java) ?: return
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL_ID, "Подбор серверов", NotificationManager.IMPORTANCE_LOW).apply {
                setShowBadge(false)
                setSound(null, null)
                enableVibration(false)
            }
        )
    }

    private fun notifyBuilder(text: String): Notification {
        ensureChannel()
        val open = android.app.PendingIntent.getActivity(
            this,
            0,
            Intent(this, app.velox.vpn.ui.MainActivity::class.java),
            android.app.PendingIntent.FLAG_UPDATE_CURRENT or android.app.PendingIntent.FLAG_IMMUTABLE
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_qs_shield)
            .setContentTitle("VeloxVPN · серверы")
            .setContentText(text)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setContentIntent(open)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }

    private fun promoteForeground(text: String) {
        val n = notifyBuilder(text)
        runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                startForeground(NOTIF_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
            } else {
                startForeground(NOTIF_ID, n)
            }
        }
    }

    private fun updateText(text: String) {
        runCatching {
            getSystemService(NotificationManager::class.java)?.notify(NOTIF_ID, notifyBuilder(text))
        }
    }

    private fun stopForegroundCompat() {
        runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                stopForeground(STOP_FOREGROUND_REMOVE)
            } else {
                @Suppress("DEPRECATION")
                stopForeground(true)
            }
        }
    }

    override fun onDestroy() {
        job?.cancel()
        scope.cancel()
        super.onDestroy()
    }
}
