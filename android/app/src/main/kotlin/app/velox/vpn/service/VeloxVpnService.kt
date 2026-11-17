package app.velox.vpn.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
import android.os.ParcelFileDescriptor
import android.service.quicksettings.TileService
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import app.velox.vpn.R
import app.velox.vpn.core.AppSettings
import app.velox.vpn.core.RuBypassPackages
import app.velox.vpn.core.RuntimeProfileMode
import app.velox.vpn.core.VeloxNative
import app.velox.vpn.core.VeloxPrefs
import app.velox.vpn.core.VpnBatchProber
import app.velox.vpn.core.VpnPhase
import app.velox.vpn.core.VpnRuntimeState
import app.velox.vpn.core.countryFlag
import app.velox.vpn.core.formatBytesRu
import app.velox.vpn.core.formatEtaRu
import app.velox.vpn.core.regionTitleRu
import app.velox.vpn.ui.MainActivity
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import org.json.JSONObject
import org.xrayrust.mobile.XrayNetworkRebindResult
import org.xrayrust.mobile.XrayStartupProbeOptions
import org.xrayrust.mobile.XrayTunBackend
import org.xrayrust.mobile.XrayTunRuntimeProfile
import org.xrayrust.mobile.XrayVpnService
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

/**
 * Isolated `:vpn` Foreground Service powered by pure-Rust `xray-rust` v0.10.0.
 *
 * - Real-time connection progress (`0..100%`) + approximate remaining time (`etaSeconds`)
 * - 2-stage smart connect: ~3.8s seed quick-probe -> multi-echelon live refresh (feeds + Opera fake-SNI + WARP)
 * - `https://www.gstatic.com/generate_204` startupProbe (never rejected by Cloudflare bot rules)
 * - Bounded, deterministic failover (never loops blindly) + comprehensive Russian diagnostic logging
 * - Ultra-low footprint: idle ~6–14 MB RAM, zero wake-locks, Android 7.0–16 (incl. Android 12 API 31/32).
 */
class VeloxVpnService : XrayVpnService() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var connectJob: Job? = null
    private var monitorJob: Job? = null
    private var poolRefreshJob: Job? = null

    private val sessionSeq = AtomicInteger(0)
    private val pendingStartResult = AtomicReference<CompletableDeferred<Result<Unit>>?>(null)

    @Volatile
    private var activeTunSettings: AppSettings = AppSettings()

    @Volatile
    private var currentState: VpnRuntimeState = VpnRuntimeState()

    @Volatile
    private var lastNetworkHandle: Long = 0L

    private var netCallbackRegistered = false
    private var lastNotifUpdateMs: Long = 0L

    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            val handle = network.networkHandle
            val prev = lastNetworkHandle
            lastNetworkHandle = handle
            if (prev != 0L && prev != handle) {
                val st = currentState
                val netDesc = VeloxNative.describeActiveNetwork(this@VeloxVpnService)
                if (st.phase == VpnPhase.CONNECTED) {
                    VeloxNative.logInfo(this@VeloxVpnService, "NET", "Смена сети -> $netDesc, проверка туннеля…")
                    scope.launch {
                        delay(1400L)
                        if (currentState.phase == VpnPhase.CONNECTED) {
                            verifyTunnelOrHeal(reason = "Смена сети")
                        }
                    }
                } else if (st.phase == VpnPhase.HEALING) {
                    VeloxNative.logInfo(this@VeloxVpnService, "NET", "Сеть восстановлена ($netDesc) — переподключение")
                    launchConnectFlow(forceRefresh = false, autoHealing = true)
                }
            }
        }
    }

    override fun onCreate() {
        super.onCreate()
        ensureNotificationChannel()
        VeloxNative.ensureInitialized(this)
        registerNetWatcher()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action ?: ACTION_CONNECT
        when (action) {
            ACTION_DISCONNECT -> {
                VeloxNative.logInfo(this, "VPN", "Остановка по запросу пользователя")
                shutdownTunnel(userInitiated = true, message = "Отключено · готов к работе")
                return START_NOT_STICKY
            }
            ACTION_ROTATE -> {
                promoteForeground(
                    buildStatusNotification(
                        title = "VeloxVPN · Смена сервера…",
                        subtitle = "Переключение на следующий проверенный узел (${formatEtaRu(5)})",
                        ongoing = true,
                        progressPct = 35,
                    )
                )
                rotateActiveNode()
                return START_STICKY
            }
            ACTION_REFRESH_POOL -> {
                refreshPoolInBackground()
                return START_STICKY
            }
            else -> {
                // Covers ACTION_CONNECT, Android Always-On VPN ("android.net.VpnService"), and restart
                val forceRefresh = intent?.getBooleanExtra(EXTRA_FORCE_REFRESH, false) == true
                val region = VeloxPrefs.loadSettings(this).region
                promoteForeground(
                    buildStatusNotification(
                        title = "VeloxVPN · Подключение (${regionTitleRu(region)})",
                        subtitle = "Подготовка анти-DPI ядра · ${formatEtaRu(8)}",
                        ongoing = true,
                        progressPct = 8,
                    )
                )
                launchConnectFlow(forceRefresh = forceRefresh, autoHealing = false)
                return START_STICKY
            }
        }
    }

    override fun onRevoke() {
        VeloxNative.logWarn(this, "VPN", "Разрешение VPN отозвано системой Android")
        shutdownTunnel(userInitiated = true, message = "Туннель отключён системой")
        super.onRevoke()
    }

    override fun onDestroy() {
        unregisterNetWatcher()
        sessionSeq.incrementAndGet()
        monitorJob?.cancel()
        connectJob?.cancel()
        poolRefreshJob?.cancel()
        safeStopCoreAndTun()
        scope.cancel()
        super.onDestroy()
    }

    private fun launchConnectFlow(forceRefresh: Boolean, autoHealing: Boolean) {
        val mySeq = sessionSeq.incrementAndGet()
        connectJob?.cancel()
        monitorJob?.cancel()

        connectJob = scope.launch {
            val startedMs = System.currentTimeMillis()
            val settings = VeloxPrefs.loadSettings(this@VeloxVpnService)
            val regionLabel = regionTitleRu(settings.region)
            val isAborted: () -> Boolean = { !isActive || sessionSeq.get() != mySeq }

            try {
                VeloxNative.reloadFromDisk(this@VeloxVpnService)
                val netDesc = VeloxNative.describeActiveNetwork(this@VeloxVpnService)
                VeloxNative.logInfo(
                    this@VeloxVpnService,
                    "VPN",
                    "=== Подключение: $regionLabel | БС=${if (settings.whitelistMode) "ВКЛ" else "выкл"} | " +
                        "Фрагм=${if (settings.fragmentTls) "ВКЛ" else "выкл"} | ОбходРФ=${if (settings.bypassRu) "ВКЛ" else "выкл"} | $netDesc ==="
                )

                // Fast connectivity sanity check before spending seconds probing
                if (!hasActiveNetwork()) {
                    VeloxNative.logErr(this@VeloxVpnService, "NET", "Нет активного подключения к интернету (Wi-Fi/LTE выключены)")
                    finishWithError(
                        "Нет подключения к интернету — включите Wi-Fi или мобильную сеть",
                        keepWaitingForNetwork = autoHealing,
                    )
                    return@launch
                }

                // Tear down any existing tunnel before probing direct ISP reachability
                safeStopCoreAndTun()
                if (isAborted()) return@launch

                // Decide whether we already have device-verified live nodes matching this region / БС РФ
                var buildRes = JSONObject(buildTunJson(settings))
                val hasVerified = buildRes.optBoolean("ok", false) &&
                    buildRes.optBoolean("primaryVerified", false)
                val needsRegionRefresh = buildRes.optBoolean("needsRegionRefresh", false)
                val needsWhitelistRefresh = buildRes.optBoolean("needsWhitelistRefresh", false)
                val needsSeedProbe = buildRes.optBoolean("needsSeedProbe", false)

                var didFullLiveRefresh = false

                if (forceRefresh ||
                    (hasVerified && (needsRegionRefresh || needsWhitelistRefresh) && !autoHealing)
                ) {
                    if (needsWhitelistRefresh && !forceRefresh) {
                        VeloxNative.logInfo(
                            this@VeloxVpnService,
                            "VPN",
                            "Режим «Белые списки РФ»: в кэше 0 проверенных БС-узлов -> подбираю серверы Минцифры SNI + CIDR РФ"
                        )
                    } else if (needsRegionRefresh && !forceRefresh) {
                        VeloxNative.logInfo(
                            this@VeloxVpnService,
                            "VPN",
                            "Для региона $regionLabel нет готовых узлов в кэше -> подбираю свежие серверы $regionLabel"
                        )
                    }
                    didFullLiveRefresh = true
                    val ok = runLiveRefreshWithUi(
                        settings = settings,
                        startedMs = startedMs,
                        maxBatch = 44,
                        isAborted = isAborted,
                    )
                    if (isAborted()) return@launch
                    if (!ok && !settings.whitelistMode) {
                        runEmergencyWhitelistPass(settings, startedMs, isAborted)
                        if (isAborted()) return@launch
                    }
                    buildRes = JSONObject(buildTunJson(settings))
                } else if (!hasVerified) {
                    var seedAlive = 0
                    if (needsSeedProbe) {
                        // Step 1: Lightning ~3.8s parallel seed verification on user's actual ISP!
                        emitProgress(
                            phase = if (autoHealing) VpnPhase.HEALING else VpnPhase.FETCHING,
                            startedMs = startedMs,
                            stageIdx = 1,
                            stageTotal = 3,
                            percent = 14,
                            etaSec = 6,
                            statusLine = "Экспресс-проверка серверов $regionLabel…",
                            detailLine = "Тест встроенного пула (Reality / XHTTP / Hy2)",
                        )
                        seedAlive = VpnBatchProber.quickVerifySeedBlocking(
                            context = this@VeloxVpnService,
                            settings = settings,
                            vpnService = null,
                            shouldAbort = isAborted,
                            onProgress = { upd ->
                                if (!isAborted()) {
                                    emitProgress(
                                        phase = if (autoHealing) VpnPhase.HEALING else VpnPhase.FETCHING,
                                        startedMs = startedMs,
                                        stageIdx = upd.stageIndex,
                                        stageTotal = upd.stageTotal,
                                        percent = upd.percent,
                                        etaSec = upd.etaSeconds,
                                        statusLine = upd.statusLine,
                                        detailLine = upd.detailLine,
                                    )
                                }
                            },
                        )
                        if (isAborted()) return@launch
                    }

                    if (seedAlive > 0) {
                        VeloxNative.logOk(
                            this@VeloxVpnService,
                            "VPN",
                            "Экспресс-проверка нашла $seedAlive рабочих узлов — мгновенный запуск!"
                        )
                        buildRes = JSONObject(buildTunJson(settings))
                        notifyEngineUpdated(null)
                    } else {
                        // Step 2: Multi-echelon live provisioning v1.3 (Белые списки РФ SNI+CIDR + MASQUE-Chain US/DE + Подписки + 25 фидов)
                        VeloxNative.logInfo(
                            this@VeloxVpnService,
                            "VPN",
                            if (settings.whitelistMode) {
                                "Автоподбор v1.3 «Белые списки РФ» (Минцифры SNI + CIDR VK/Yandex/CDN + подписки)"
                            } else {
                                "Быстрый автоподбор v1.3 (MASQUE-Chain US/DE + БС РФ + подписки + 25 фидов)"
                            }
                        )
                        didFullLiveRefresh = true
                        val ok = runLiveRefreshWithUi(
                            settings = settings,
                            startedMs = startedMs,
                            maxBatch = 44,
                            isAborted = isAborted,
                        )
                        if (isAborted()) return@launch
                        if (!ok && !settings.whitelistMode) {
                            runEmergencyWhitelistPass(settings, startedMs, isAborted)
                            if (isAborted()) return@launch
                        }
                        buildRes = JSONObject(buildTunJson(settings))
                    }
                }

                // Step 3: Establish real Android TUN tunnel (max 4 verified candidates + 1 live refresh if cached nodes expired)
                var attempt = 0
                val maxTunAttempts = 4
                var lastTunError = ""

                while (attempt < maxTunAttempts && !isAborted()) {
                    val wlStarved = settings.whitelistMode &&
                        buildRes.optBoolean("needsWhitelistRefresh", false) &&
                        !didFullLiveRefresh
                    val ready = !wlStarved &&
                        buildRes.optBoolean("ok", false) &&
                        (buildRes.optBoolean("primaryVerified", false) || settings.pinnedNodeId.isNotBlank())

                    if (!ready) {
                        if (!didFullLiveRefresh) {
                            didFullLiveRefresh = true
                            VeloxNative.logInfo(
                                this@VeloxVpnService,
                                "VPN",
                                if (settings.whitelistMode) {
                                    "Сохранённые БС-серверы устарели -> подбираю свежие серверы «Белые списки РФ»"
                                } else {
                                    "Сохранённые серверы устарели -> подбираю свежие узлы $regionLabel"
                                }
                            )
                            val ok = runLiveRefreshWithUi(
                                settings = settings,
                                startedMs = startedMs,
                                maxBatch = 44,
                                isAborted = isAborted,
                            )
                            if (isAborted()) return@launch
                            if (!ok && !settings.whitelistMode) {
                                runEmergencyWhitelistPass(settings, startedMs, isAborted)
                                if (isAborted()) return@launch
                            }
                            buildRes = JSONObject(buildTunJson(settings))
                            if (!buildRes.optBoolean("ok", false) || !buildRes.optBoolean("primaryVerified", false)) {
                                break
                            }
                        } else {
                            break
                        }
                    }

                    attempt++
                    val configJson = buildRes.getString("configJson")
                    val primary = buildRes.optJSONObject("primary")
                        ?: buildRes.getJSONObject("activeNode")
                    val firstTag = buildRes.optString("firstTag", "vpn_0").ifBlank { "vpn_0" }
                    val freshlyVerified = buildRes.optBoolean("freshlyVerified", false)
                    val viaWarp = buildRes.optBoolean("viaWarp", primary.optBoolean("via_warp", false))
                    val nodeId = primary.optString("id")
                    val nodeName = primary.optString("name", regionLabel)
                    val proto = primary.optString("display_protocol", "VLESS")
                    val host = primary.optString("host")
                    val port = primary.optInt("port", 443)
                    val sni = primary.optString("sni")
                    val exitCountry = primary.optString("exit_country", settings.region)
                    val exitColo = primary.optString("exit_colo", "")
                    val exitIp = primary.optString("exit_ip", "")
                    var initRtt = primary.optInt("rtt_ms", 0)
                    val backupCnt = buildRes.optInt("backupCount", 0)

                    // Skip duplicate in-core startupProbe when node was verified recently (<=15m)
                    // or when using a 2-hop MASQUE-Chain (which we verify end-to-end via local_socks!).
                    // Use fast HTTP 204 (inside encrypted VLESS/Trojan/Hy2/SS tunnel) to avoid nested TLS delay.
                    val startupProbe = if (freshlyVerified || viaWarp) {
                        null
                    } else {
                        XrayStartupProbeOptions(
                            "http://cp.cloudflare.com/generate_204",
                            5500L,
                            firstTag,
                        )
                    }

                    emitProgress(
                        phase = if (autoHealing) VpnPhase.HEALING else VpnPhase.CONNECTING,
                        startedMs = startedMs,
                        stageIdx = 5,
                        stageTotal = 5,
                        percent = 93,
                        etaSec = if (freshlyVerified) 2 else 4,
                        statusLine = "Запуск туннеля: $nodeName ($proto)…",
                        detailLine = if (viaWarp) {
                            "Двуххоповый канал MASQUE-Chain -> $exitCountry (попытка $attempt/$maxTunAttempts)"
                        } else {
                            "Открытие защищённого TUN-интерфейса (попытка $attempt/$maxTunAttempts)"
                        },
                    )
                    VeloxNative.logInfo(
                        this@VeloxVpnService,
                        "TUN",
                        "Старт #$attempt: $nodeName [$proto] $host:$port chain=${if (viaWarp) "MASQUE" else "direct"} sni=${sni.ifBlank { "-" }} свежий=$freshlyVerified резерв=$backupCnt"
                    )

                    safeStopCoreAndTun()
                    activeTunSettings = settings
                    val tStart = System.currentTimeMillis()
                    val waiter = CompletableDeferred<Result<Unit>>()
                    pendingStartResult.set(waiter)

                    val invoked = runCatching {
                        startXrayTunnel(
                            configJson,
                            XrayTunBackend.FileDescriptor,
                            mapRuntimeProfile(settings.profileMode),
                            startupProbe,
                            1400,
                        )
                    }

                    var startAttempt: Result<Unit> = if (invoked.isFailure) {
                        pendingStartResult.compareAndSet(waiter, null)
                        Result.failure(invoked.exceptionOrNull() ?: IllegalStateException("startXrayTunnel failed"))
                    } else {
                        withTimeoutOrNull(16_000L) { waiter.await() }
                            ?: run {
                                pendingStartResult.compareAndSet(waiter, null)
                                Result.failure(IllegalStateException("Таймаут запуска TUN (16с)"))
                            }
                    }

                    // For older cached (>15 min) 2-hop MASQUE-Chain nodes, allow QUIC MASQUE carrier
                    // to establish cleanly (1.3s > RETRY_INTERVAL 1s) before verifying reachability!
                    if (startAttempt.isSuccess && viaWarp && !freshlyVerified && !isAborted()) {
                        delay(1300L)
                        var hObj = probeLocalSocksOnce()
                        if (!hObj.first && !isAborted()) {
                            // Respect Xray MASQUE 1s retryInterval & H3->H2+frag failover
                            delay(1250L)
                            hObj = probeLocalSocksOnce()
                        }
                        if (hObj.first) {
                            if (hObj.second > 0) initRtt = hObj.second
                        } else {
                            startAttempt = Result.failure(
                                IllegalStateException("Кэш MASQUE-Chain устарел: ${hObj.third}")
                            )
                        }
                    }

                    if (startAttempt.isSuccess) {
                        val totalMs = System.currentTimeMillis() - startedMs
                        val tunMs = System.currentTimeMillis() - tStart
                        val wlActive = buildRes.optBoolean(
                            "whitelistActive",
                            settings.whitelistMode && primary.optBoolean("whitelist_friendly", false)
                        )
                        val fallbackNote = when {
                            wlActive -> " · Белые списки РФ"
                            exitCountry.equals("CF", ignoreCase = true) ->
                                " · анти-ТСПУ (нажмите ↻ для US/DE)"
                            !settings.region.equals("AUTO", ignoreCase = true) &&
                                exitCountry.isNotBlank() &&
                                !exitCountry.equals(settings.region, ignoreCase = true) ->
                                " · выход $exitCountry"
                            else -> ""
                        }

                        VeloxNative.logOk(
                            this@VeloxVpnService,
                            "VPN",
                            "ПОДКЛЮЧЕНО за ${String.format("%.1f", totalMs / 1000.0)}с (TUN ${tunMs}мс): " +
                                "$nodeName [$proto] exit=$exitIp ($exitCountry/$exitColo) rtt=${initRtt}мс резерв=$backupCnt"
                        )

                        val connectedState = VpnRuntimeState(
                            phase = VpnPhase.CONNECTED,
                            statusLine = buildString {
                                append("$proto$fallbackNote")
                                if (backupCnt > 0) append(" · резерв: $backupCnt")
                                if (settings.bypassRu) append(" · РФ напрямую")
                            },
                            activeNodeId = nodeId,
                            activeNodeName = nodeName,
                            activeProtocol = proto,
                            exitCountry = exitCountry,
                            exitColo = exitColo,
                            exitIp = exitIp,
                            rttMs = initRtt,
                            backupCount = backupCnt,
                            connectedSinceMs = System.currentTimeMillis(),
                            progressPercent = 100,
                            etaSeconds = 0,
                        )
                        publishState(connectedState)
                        updateConnectedNotification(connectedState)
                        startLiveMonitorLoop(settings, mySeq)
                        return@launch
                    }

                    // TUN startupProbe failed — log exact reason, demote node, clear pin if pinned
                    val errText = VpnBatchProber.formatThrowable(startAttempt.exceptionOrNull())
                    lastTunError = errText
                    safeStopCoreAndTun()
                    VeloxNative.reportNodeFailure(nodeId, settings.region, "TUN startupProbe: $errText")
                    if (settings.pinnedNodeId == nodeId) {
                        VeloxPrefs.updateSettings(this@VeloxVpnService) { it.copy(pinnedNodeId = "") }
                    }
                    buildRes = JSONObject(buildTunJson(VeloxPrefs.loadSettings(this@VeloxVpnService)))
                }

                if (isAborted()) return@launch

                val finalMsg = if (lastTunError.isNotBlank()) {
                    "Не удалось поднять туннель — откройте Журнал или включите «Белые списки РФ»"
                } else {
                    "Не найдено рабочих узлов $regionLabel — попробуйте «Авто», «Белые списки РФ» или свой ключ"
                }
                VeloxNative.logErr(this@VeloxVpnService, "VPN", "Подключение завершено без успеха: $finalMsg")
                finishWithError(finalMsg, keepWaitingForNetwork = false)
            } catch (_: CancellationException) {
                // Superseded by stop / region switch / newer connect request
            } catch (t: Throwable) {
                val err = VpnBatchProber.formatThrowable(t)
                VeloxNative.logErr(this@VeloxVpnService, "VPN", "Непредвиденная ошибка сервиса: $err")
                finishWithError("Ошибка VPN: ${err.take(110)}", keepWaitingForNetwork = false)
            }
        }
    }

    private fun runLiveRefreshWithUi(
        settings: AppSettings,
        startedMs: Long,
        maxBatch: Int,
        isAborted: () -> Boolean,
    ): Boolean {
        val outcome = VpnBatchProber.refreshPoolBlocking(
            context = this,
            settings = settings,
            vpnService = null,
            maxBatch = maxBatch,
            shouldAbort = isAborted,
            onProgress = { upd ->
                if (!isAborted()) {
                    emitProgress(
                        phase = VpnPhase.FETCHING,
                        startedMs = startedMs,
                        stageIdx = upd.stageIndex,
                        stageTotal = upd.stageTotal,
                        percent = upd.percent,
                        etaSec = upd.etaSeconds,
                        statusLine = upd.statusLine,
                        detailLine = upd.detailLine,
                    )
                }
            }
        )
        notifyEngineUpdated(null)
        return outcome.ok
    }

    /**
     * Automatic single emergency pass prioritizing Russian mobile whitelist SNIs + AUTO region
     * when a user's carrier blocks every standard US/DE endpoint.
     */
    private fun runEmergencyWhitelistPass(
        settings: AppSettings,
        startedMs: Long,
        isAborted: () -> Boolean,
    ): Boolean {
        if (!hasActiveNetwork() || isAborted()) return false
        VeloxNative.logWarn(
            this,
            "VPN",
            "Обычные узлы ${regionTitleRu(settings.region)} заблокированы -> экстренный поиск (Белые списки РФ + Opera + WARP)"
        )
        emitProgress(
            phase = VpnPhase.FETCHING,
            startedMs = startedMs,
            stageIdx = 2,
            stageTotal = 5,
            percent = 24,
            etaSec = 16,
            statusLine = "Резервный обход ТСПУ (Белые списки + WARP)…",
            detailLine = "Тест устойчивых SNI и альтернативных протоколов",
        )
        val emergencySettings = settings.copy(whitelistMode = true, fragmentTls = true)
        val outcome = VpnBatchProber.refreshPoolBlocking(
            context = this,
            settings = emergencySettings,
            vpnService = null,
            maxBatch = 38,
            shouldAbort = isAborted,
            onProgress = { upd ->
                if (!isAborted()) {
                    emitProgress(
                        phase = VpnPhase.FETCHING,
                        startedMs = startedMs,
                        stageIdx = upd.stageIndex,
                        stageTotal = upd.stageTotal,
                        percent = upd.percent,
                        etaSec = upd.etaSeconds,
                        statusLine = "Резервный обход ТСПУ…",
                        detailLine = upd.detailLine,
                    )
                }
            }
        )
        notifyEngineUpdated(null)
        return outcome.ok
    }

    private fun finishWithError(message: String, keepWaitingForNetwork: Boolean) {
        safeStopCoreAndTun()
        if (keepWaitingForNetwork) {
            publishState(
                VpnRuntimeState(
                    phase = VpnPhase.HEALING,
                    statusLine = "Ожидание появления сети (Wi-Fi / LTE)…",
                )
            )
            updateForegroundText(
                title = "VeloxVPN · Ожидание сети",
                subtitle = "Автоподключение при появлении интернета",
                progressPct = -1,
            )
        } else {
            publishState(
                VpnRuntimeState(
                    phase = VpnPhase.ERROR,
                    statusLine = message,
                )
            )
            stopForegroundCompat()
            stopSelf()
        }
    }

    private fun rotateActiveNode() {
        val cur = currentState
        val settings = VeloxPrefs.loadSettings(this)
        if (cur.activeNodeId.isNotBlank()) {
            VeloxNative.reloadFromDisk(this)
            VeloxNative.reportNodeFailure(cur.activeNodeId, settings.region, "ручная смена узла")
            VeloxPrefs.updateSettings(this) { it.copy(pinnedNodeId = "") }
            notifyEngineUpdated(null)
        }
        launchConnectFlow(forceRefresh = false, autoHealing = false)
    }

    private fun refreshPoolInBackground() {
        if (poolRefreshJob?.isActive == true) return
        poolRefreshJob = scope.launch {
            val settings = VeloxPrefs.loadSettings(this@VeloxVpnService)
            val outcome = VpnBatchProber.refreshPoolBlocking(
                context = this@VeloxVpnService,
                settings = settings,
                vpnService = this@VeloxVpnService, // protects all probe sockets outside active TUN!
                maxBatch = 38,
                onProgress = null,
            )
            val msg = if (outcome.ok) {
                "Обновлено: ${outcome.newlyVerified} проверенных серверов (${regionTitleRu(settings.region)})"
            } else {
                outcome.error.ifBlank { "Новых серверов не найдено" }
            }
            notifyEngineUpdated(msg)
        }
    }

    /**
     * Ultra-lean live monitor loop:
     * - Every 1 s: zero-allocation traffic counter read (zero radio wakeups).
     * - Every 28 s: silent probe via `127.0.0.1:10808` to detect mid-session DPI drops.
     */
    private fun startLiveMonitorLoop(initialSettings: AppSettings, mySeq: Int) {
        monitorJob?.cancel()
        monitorJob = scope.launch {
            var tick = 0
            var consecutiveHealthFailures = 0

            // Refresh live RTT + exit IP 7.5s after connecting (after QUIC/observatory settles cleanly)
            delay(7500L)
            if (isActive && sessionSeq.get() == mySeq && currentState.phase == VpnPhase.CONNECTED) {
                runSilentHealthUpdate()
            }

            while (isActive && sessionSeq.get() == mySeq && currentState.phase == VpnPhase.CONNECTED) {
                delay(1000L)
                tick++

                val snap = runCatching { xrayVpnRuntimeSnapshot() }.getOrNull()
                if (snap != null && !snap.running) {
                    VeloxNative.logWarn(this@VeloxVpnService, "TUN", "Ядро Xray остановилось — перезапуск")
                    if (VeloxPrefs.loadSettings(this@VeloxVpnService).autoHeal) {
                        launchConnectFlow(forceRefresh = false, autoHealing = true)
                    } else {
                        shutdownTunnel(userInitiated = false, message = "Соединение прервано")
                    }
                    return@launch
                }

                if (snap != null) {
                    val ts = snap.tunStats
                    val updated = currentState.copy(
                        uplinkBytes = ts?.uplinkBytes ?: currentState.uplinkBytes,
                        downlinkBytes = ts?.downlinkBytes ?: currentState.downlinkBytes,
                        activeConnections = snap.activeConnections,
                    )
                    publishState(updated, silentIfSmall = (tick % 2 == 1))
                    if (tick % 6 == 0) {
                        updateConnectedNotification(updated)
                    }
                }

                if (tick % 28 == 0) {
                    val healthy = runSilentHealthUpdate()
                    if (healthy) {
                        consecutiveHealthFailures = 0
                    } else {
                        consecutiveHealthFailures++
                        val curSettings = VeloxPrefs.loadSettings(this@VeloxVpnService)
                        VeloxNative.logWarn(
                            this@VeloxVpnService,
                            "HEAL",
                            "Нет ответа через туннель ($consecutiveHealthFailures/2) на ${currentState.activeNodeName}"
                        )
                        if (curSettings.autoHeal && consecutiveHealthFailures >= 3) {
                            if (!hasActiveNetwork()) {
                                finishWithError("Ожидание сети", keepWaitingForNetwork = true)
                                return@launch
                            }
                            verifyTunnelOrHeal(reason = "Потеря связи с узлом (блокировка/обрыв)")
                            return@launch
                        }
                    }
                }
            }
        }
    }

    private fun probeLocalSocksOnce(): Triple<Boolean, Int, String> {
        val raw = runCatching {
            VeloxNative.checkTunnelHealth(VeloxPrefs.LOCAL_VPN_SOCKS_PORT)
        }.getOrDefault("{}")
        val obj = runCatching { JSONObject(raw) }.getOrNull()
            ?: return Triple(false, 0, "json error")
        val alive = obj.optBoolean("alive", obj.optBoolean("ok", false))
        val rtt = obj.optInt("rtt_ms", obj.optInt("rttMs", 0))
        val err = obj.optString("error", "")
        return Triple(alive, rtt, err)
    }

    private fun runSilentHealthUpdate(): Boolean {
        val raw = runCatching {
            VeloxNative.checkTunnelHealth(VeloxPrefs.LOCAL_VPN_SOCKS_PORT)
        }.getOrDefault("{}")
        val obj = runCatching { JSONObject(raw) }.getOrNull() ?: return false
        val alive = obj.optBoolean("alive", obj.optBoolean("ok", false))
        if (!alive) return false

        val rtt = obj.optInt("rtt_ms", obj.optInt("rttMs", currentState.rttMs))
        val ip = obj.optString("exit_ip", obj.optString("ip", "")).ifBlank { currentState.exitIp }
        val loc = obj.optString("exit_country", obj.optString("loc", "")).ifBlank { currentState.exitCountry }
        val colo = obj.optString("exit_colo", obj.optString("colo", "")).ifBlank { currentState.exitColo }

        val updated = currentState.copy(
            rttMs = if (rtt > 0) rtt else currentState.rttMs,
            exitIp = ip,
            exitCountry = loc,
            exitColo = colo,
        )
        publishState(updated)
        return true
    }

    private fun verifyTunnelOrHeal(reason: String) {
        if (runSilentHealthUpdate()) {
            VeloxNative.logOk(this, "HEAL", "Туннель стабилен (${currentState.rttMs} мс, ${currentState.exitIp})")
            return
        }
        val badId = currentState.activeNodeId
        val settings = VeloxPrefs.loadSettings(this)
        if (badId.isNotBlank()) {
            VeloxNative.reloadFromDisk(this)
            VeloxNative.reportNodeFailure(badId, settings.region, reason)
            if (settings.pinnedNodeId == badId) {
                VeloxPrefs.updateSettings(this) { it.copy(pinnedNodeId = "") }
            }
        }
        launchConnectFlow(forceRefresh = false, autoHealing = true)
    }

    override fun onXrayTunnelStarted() {
        pendingStartResult.getAndSet(null)?.complete(Result.success(Unit))
    }

    override fun onXrayTunnelStartFailed(error: Throwable) {
        pendingStartResult.getAndSet(null)?.complete(Result.failure(error))
    }

    override fun onXrayTunnelStartCancelled() {
        pendingStartResult.getAndSet(null)?.complete(
            Result.failure(CancellationException("Запуск туннеля отменён"))
        )
    }

    override fun onXrayTunnelFatalError(error: Throwable) {
        val err = VpnBatchProber.formatThrowable(error)
        VeloxNative.logErr(this, "TUN", "Критическая ошибка туннеля: $err")
        if (currentState.phase == VpnPhase.CONNECTED) {
            if (VeloxPrefs.loadSettings(this).autoHeal) {
                launchConnectFlow(forceRefresh = false, autoHealing = true)
            } else {
                shutdownTunnel(userInitiated = false, message = "Ошибка туннеля: ${err.take(90)}")
            }
        }
    }

    override fun onXrayNetworkRebind(result: XrayNetworkRebindResult) {
        VeloxNative.logInfo(
            this,
            "NET",
            "Мгновенный ребинд сокетов (QUIC/WG) после смены сети (gen=${result.sessionGeneration})"
        )
    }

    override fun onXrayNetworkChangeError(error: Exception) {
        VeloxNative.logWarn(this, "NET", "Ошибка смены сети Xray: ${VpnBatchProber.formatThrowable(error)}")
    }

    override fun buildTunnel(): Builder {
        val settings = activeTunSettings
        val builder = Builder()
            .setSession("VeloxVPN")
            .setMtu(1400)
            .addAddress("10.255.0.1", 30)
            .addRoute("0.0.0.0", 0)
            .addDnsServer("8.8.8.8")
            .addDnsServer("1.1.1.1")
            .setBlocking(false)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            builder.setMetered(false)
        }

        // Prevent routing loops by always excluding our own package
        runCatching { builder.addDisallowedApplication(packageName) }

        // User-selected split-tunnel bypass apps
        for (pkg in settings.excludedPackages) {
            if (pkg.isNotBlank() && pkg != packageName) {
                runCatching { builder.addDisallowedApplication(pkg) }
            }
        }

        // Auto-bypass Russian banks, Mir Pay, SBP, Gosuslugi, marketplaces & taxi
        if (settings.bypassRu) {
            for (pkg in RuBypassPackages.DEFAULT) {
                runCatching { builder.addDisallowedApplication(pkg) }
            }
        }

        val configurePi = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        builder.setConfigureIntent(configurePi)
        return builder
    }

    private fun buildTunJson(settings: AppSettings): String {
        return VeloxNative.buildTunConfig(
            targetRegion = settings.region,
            pinnedNodeId = settings.pinnedNodeId,
            whitelistMode = settings.whitelistMode,
            bypassRu = settings.bypassRu,
            fragmentTls = settings.fragmentTls,
            localSocksPort = VeloxPrefs.LOCAL_VPN_SOCKS_PORT,
        )
    }

    private fun mapRuntimeProfile(mode: RuntimeProfileMode): XrayTunRuntimeProfile = when (mode) {
        RuntimeProfileMode.LOW_MEMORY -> XrayTunRuntimeProfile.LowMemory
        RuntimeProfileMode.MOBILE -> XrayTunRuntimeProfile.Mobile
        RuntimeProfileMode.TURBO -> XrayTunRuntimeProfile.MobilePlus
    }

    private fun emitProgress(
        phase: VpnPhase,
        startedMs: Long,
        stageIdx: Int,
        stageTotal: Int,
        percent: Int,
        etaSec: Int,
        statusLine: String,
        detailLine: String,
    ) {
        val clampedPct = percent.coerceIn(4, 98)
        val st = VpnRuntimeState(
            phase = phase,
            statusLine = statusLine,
            connectingSinceMs = startedMs,
            progressPercent = clampedPct,
            etaSeconds = etaSec.coerceAtLeast(1),
            stageIndex = stageIdx,
            stageTotal = stageTotal,
            stageDetail = detailLine,
        )
        publishState(st)
        val now = System.currentTimeMillis()
        if (now - lastNotifUpdateMs >= 900L) {
            lastNotifUpdateMs = now
            updateForegroundText(
                title = "VeloxVPN · $statusLine",
                subtitle = "Осталось ${formatEtaRu(etaSec)} · ${detailLine.ifBlank { "$clampedPct%" }}",
                progressPct = clampedPct,
            )
        }
    }

    private fun safeStopCoreAndTun() {
        pendingStartResult.getAndSet(null)?.cancel()
        runCatching { stopXrayTunnel() }
    }

    private fun shutdownTunnel(userInitiated: Boolean, message: String) {
        sessionSeq.incrementAndGet()
        monitorJob?.cancel()
        connectJob?.cancel()
        safeStopCoreAndTun()
        publishState(
            VpnRuntimeState(
                phase = if (userInitiated) VpnPhase.DISCONNECTED else VpnPhase.ERROR,
                statusLine = message,
            )
        )
        stopForegroundCompat()
        stopSelf()
    }

    private fun hasActiveNetwork(): Boolean = runCatching {
        val cm = getSystemService(ConnectivityManager::class.java) ?: return@runCatching true
        val net = cm.activeNetwork ?: return@runCatching false
        val caps = cm.getNetworkCapabilities(net) ?: return@runCatching false
        caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
    }.getOrDefault(true)

    private fun publishState(state: VpnRuntimeState, silentIfSmall: Boolean = false) {
        val stamped = state.copy(updatedAtMs = System.currentTimeMillis())
        currentState = stamped
        VeloxPrefs.publishRuntime(this, stamped, broadcast = !silentIfSmall)
        if (!silentIfSmall) {
            requestTileRefresh()
        }
    }

    private fun notifyEngineUpdated(toastMessage: String?) {
        val intent = Intent(VeloxPrefs.ACTION_ENGINE_UPDATED).setPackage(packageName)
        if (!toastMessage.isNullOrBlank()) {
            intent.putExtra(VeloxPrefs.EXTRA_TOAST_MESSAGE, toastMessage)
        }
        sendBroadcast(intent)
    }

    private fun requestTileRefresh() {
        runCatching {
            TileService.requestListeningState(
                this,
                android.content.ComponentName(this, VeloxTileService::class.java)
            )
        }
    }

    private fun registerNetWatcher() {
        if (netCallbackRegistered) return
        runCatching {
            val cm = getSystemService(ConnectivityManager::class.java) ?: return
            val req = NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                .build()
            cm.registerNetworkCallback(req, networkCallback)
            netCallbackRegistered = true
        }
    }

    private fun unregisterNetWatcher() {
        if (!netCallbackRegistered) return
        runCatching {
            val cm = getSystemService(ConnectivityManager::class.java)
            cm?.unregisterNetworkCallback(networkCallback)
        }
        netCallbackRegistered = false
    }

    // -------------------------------------------------------------------------
    // Android 7.0 – 16 (incl. Android 12 API 31/32) Foreground Notifications
    // -------------------------------------------------------------------------

    private fun ensureNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val nm = getSystemService(NotificationManager::class.java) ?: return
            val channel = NotificationChannel(
                CHANNEL_ID,
                getString(R.string.notif_channel_vpn),
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = getString(R.string.notif_channel_vpn_desc)
                setShowBadge(false)
                enableVibration(false)
                setSound(null, null)
            }
            nm.createNotificationChannel(channel)
        }
    }

    private fun promoteForeground(notification: Notification) {
        runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                startForeground(
                    NOTIF_ID,
                    notification,
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
                )
            } else {
                startForeground(NOTIF_ID, notification)
            }
        }
    }

    private fun stopForegroundCompat() {
        runCatching {
            stopForeground(STOP_FOREGROUND_REMOVE)
        }
    }

    private fun updateForegroundText(title: String, subtitle: String, progressPct: Int = -1) {
        val nm = getSystemService(NotificationManager::class.java) ?: return
        runCatching {
            nm.notify(NOTIF_ID, buildStatusNotification(title, subtitle, ongoing = true, progressPct = progressPct))
        }
    }

    private fun updateConnectedNotification(state: VpnRuntimeState) {
        val nm = getSystemService(NotificationManager::class.java) ?: return
        val flag = countryFlag(state.exitCountry)
        val rttPart = if (state.rttMs > 0) " · ${state.rttMs} мс" else ""
        val title = "$flag ${state.activeNodeName.ifBlank { "Подключено" }}$rttPart"
        val sub = "${state.activeProtocol} · ↓ ${formatBytesRu(state.downlinkBytes)}  ↑ ${formatBytesRu(state.uplinkBytes)}"
        runCatching {
            nm.notify(
                NOTIF_ID,
                buildStatusNotification(title, sub, ongoing = true, showRotate = true, progressPct = -1)
            )
        }
    }

    private fun buildStatusNotification(
        title: String,
        subtitle: String,
        ongoing: Boolean,
        showRotate: Boolean = false,
        progressPct: Int = -1,
    ): Notification {
        val openAppPi = PendingIntent.getActivity(
            this,
            10,
            Intent(this, MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
            },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val stopPi = PendingIntent.getService(
            this,
            11,
            Intent(this, VeloxVpnService::class.java).setAction(ACTION_DISCONNECT),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val builder = NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_qs_shield)
            .setContentTitle(title)
            .setContentText(subtitle)
            .setContentIntent(openAppPi)
            .setOngoing(ongoing)
            .setOnlyAlertOnce(true)
            .setSilent(true)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)

        if (progressPct in 0..99) {
            builder.setProgress(100, progressPct, false)
        }

        if (showRotate) {
            val rotatePi = PendingIntent.getService(
                this,
                12,
                Intent(this, VeloxVpnService::class.java).setAction(ACTION_ROTATE),
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
            builder.addAction(0, getString(R.string.action_switch_node), rotatePi)
            builder.addAction(0, getString(R.string.action_disconnect), stopPi)
        } else {
            builder.addAction(0, "Отмена", stopPi)
        }

        return builder.build()
    }

    companion object {
        const val ACTION_CONNECT = "app.velox.vpn.action.CONNECT"
        const val ACTION_DISCONNECT = "app.velox.vpn.action.DISCONNECT"
        const val ACTION_ROTATE = "app.velox.vpn.action.ROTATE"
        const val ACTION_REFRESH_POOL = "app.velox.vpn.action.REFRESH_POOL"
        const val EXTRA_FORCE_REFRESH = "force_refresh"

        private const val CHANNEL_ID = "velox_vpn_tunnel"
        private const val NOTIF_ID = 1001

        fun startConnect(context: Context, forceRefresh: Boolean = false) {
            val app = context.applicationContext
            val intent = Intent(app, VeloxVpnService::class.java)
                .setAction(ACTION_CONNECT)
                .putExtra(EXTRA_FORCE_REFRESH, forceRefresh)
            ContextCompat.startForegroundService(app, intent)
        }

        fun requestStop(context: Context) {
            val app = context.applicationContext
            runCatching {
                app.startService(
                    Intent(app, VeloxVpnService::class.java).setAction(ACTION_DISCONNECT)
                )
            }
        }

        fun requestRotate(context: Context) {
            val app = context.applicationContext
            ContextCompat.startForegroundService(
                app,
                Intent(app, VeloxVpnService::class.java).setAction(ACTION_ROTATE)
            )
        }

        fun requestRefreshPool(context: Context) {
            val app = context.applicationContext
            runCatching {
                app.startService(
                    Intent(app, VeloxVpnService::class.java).setAction(ACTION_REFRESH_POOL)
                )
            }
        }
    }
}
