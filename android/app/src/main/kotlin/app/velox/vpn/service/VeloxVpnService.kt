package app.velox.vpn.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
import android.os.PowerManager
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
import kotlinx.coroutines.withContext
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
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlin.math.abs

/**
 * Isolated `:vpn` Foreground Service v1.6.0 powered by pure-Rust `xray-rust` v0.10.0 + `velox-engine`:
 *
 * - **Dual-Channel Zero-Drop Failover**: mounts Primary (`vpn_0`) + pre-verified Hot-Standby (`vpn_1`)
 *   simultaneously inside `vpn_main`, detects silent DPI stalls in <=3 s with zero extra radio traffic,
 *   promotes `vpn_1 -> vpn_0` via atomic hot-swap (~40 ms), mounts `vpn_2 -> vpn_1`, and replenishes
 *   standby nodes in the background — strictly scoped to the chosen country (or global on `AUTO`).
 * - **Zero-Idle Doze Battery Mode**: 0 wakeups/min, 0 disk writes, 0 notification/Tile IPC, and 0 active
 *   network probes while screen is OFF; delta-gated stats & traffic-aware probe skipping while screen is ON.
 * - **Lossless Offline Recovery**: strict `NET_CAPABILITY_NOT_VPN` monitoring never blacklists good nodes
 *   or clears `pinnedNodeId` in elevators/subways/airplane mode, and reconnects instantly on network return.
 * - **Hardened Loopback Security**: per-session 128-bit CSPRNG credentials on `127.0.0.1:10808`.
 */
class VeloxVpnService : XrayVpnService() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var connectJob: Job? = null
    private var monitorJob: Job? = null
    private var poolRefreshJob: Job? = null

    // -----------------------------------------------------------------------------------------
    // v1.7.1 ANTI-DROP / ANTI-FLAP GUARD
    // Whitelist («белые списки РФ») и часть подписочных узлов сознательно блокируют внешние
    // «эталонные» адреса (gstatic / example.com / 1.1.1.1), при этом сам туннель полностью жив.
    // Раньше HTTP-проба через SOCKS возвращала «умер» -> мы каждые ~1.5–3 минуты переключали
    // рабочий сервер (для пользователя это выглядело как регулярный разрыв). Теперь:
    //   1) L1-проба SOCKS5 CONNECT: туннель считается живым, если ядро принимает соединение;
    //   2) эскалация только после нескольких независимых подтверждений;
    //   3) демпфирование флапа — не более 3 автопереключений за 6 минут, затем пауза 3 минуты.
    // -----------------------------------------------------------------------------------------
    private val autoPromoteStamps = ArrayDeque<Long>()
    @Volatile
    private var resilientUntilMs: Long = 0L
    @Volatile
    private var lastL1OkAtMs: Long = 0L
    @Volatile
    private var l1RescueLogAtMs: Long = 0L

    /** Активный узел помечен как «белые списки РФ» (эталонные сайты у него закрыты по дизайну). */
    @Volatile
    private var activeIsWhitelist: Boolean = false

    // v1.7.2: отдельная «полоса» проверок живости. Ни один блокирующий JNI-HTTP-замер больше не
    // выполняется внутри 1-секундного цикла монитора (раньше он мог заморозить статистику и
    // детектор замирания на 15–21 с), а параллельные проверки схлопываются в одну (single-flight).
    private val probeBusy = AtomicBoolean(false)
    @Volatile
    private var probeFailures: Int = 0
    @Volatile
    private var lastProbeAtMs: Long = 0L

    /** Пользователь сменил страну/настройки, но готового плана не было — применим после подбора. */
    @Volatile
    private var pendingHotSwap: Boolean = false

    private val flapLock = Any()

    /** True — можно выполнять автоматическое переключение по результатам пробы. */
    private fun canAutoPromote(reason: String): Boolean {
        val now = System.currentTimeMillis()
        synchronized(flapLock) {
            while (autoPromoteStamps.isNotEmpty() && now - autoPromoteStamps.first() > 360_000L) {
                autoPromoteStamps.removeFirst()
            }
        }
        if (now < resilientUntilMs) {
            VeloxNative.logInfo(
                this,
                "ANTI-FLAP",
                "«$reason»: узел помечен сомнительным, но удержание стабильности ещё ${(resilientUntilMs - now) / 1000}с — оставляем текущий сервер подключённым"
            )
            return false
        }
        if (synchronized(flapLock) { autoPromoteStamps.size } >= 3) {
            resilientUntilMs = now + 180_000L
            synchronized(flapLock) { autoPromoteStamps.clear() }
            VeloxNative.logWarn(
                this,
                "ANTI-FLAP",
                "Слишком частые переключения (3 за 6 мин) — пауза 3 мин: держим текущий узел, чтобы не рвать соединения"
            )
            return false
        }
        return true
    }

    private fun noteAutoPromote() {
        synchronized(flapLock) { autoPromoteStamps.addLast(System.currentTimeMillis()) }
    }

    /**
     * L1-проба живости туннеля: «сырой» SOCKS5 (RFC 1928 + RFC 1929) CONNECT к внешнему адресу
     * через локальный вход `127.0.0.1:10808`. Успешный CONNECT = ядро диспетчеризует трафик,
     * даже если SNI-фильтр «белого списка» режет последующий TLS к gstatic/example.com.
     */
    private fun l1TunnelAlive(timeoutMs: Int = 2200): Boolean {
        val port = VeloxPrefs.LOCAL_VPN_SOCKS_PORT
        val targets = arrayOf("www.gstatic.com" to 443, "1.1.1.1" to 443, "cp.cloudflare.com" to 443)
        for ((host, tport) in targets) {
            val ok = runCatching {
                java.net.Socket().use { s ->
                    s.tcpNoDelay = true
                    s.soTimeout = timeoutMs
                    s.connect(java.net.InetSocketAddress("127.0.0.1", port), timeoutMs)
                    val out = s.getOutputStream()
                    val inp = s.getInputStream()

                    // --- RFC 1928 greeting: VER=5, NMETHODS=2, [NO-AUTH, USER/PASS] ---
                    out.write(byteArrayOf(0x05, 0x02, 0x00, 0x02))
                    out.flush()
                    if (inp.read() != 0x05) return@use false
                    val method = inp.read()
                    if (method == 0x02) {
                        // --- RFC 1929 username/password ---
                        val u = sessionSocksUser.toByteArray(Charsets.UTF_8)
                        val p = sessionSocksPass.toByteArray(Charsets.UTF_8)
                        val auth = ByteArray(3 + u.size + p.size)
                        auth[0] = 0x01
                        auth[1] = u.size.toByte()
                        u.copyInto(auth, 2)
                        auth[2 + u.size] = p.size.toByte()
                        p.copyInto(auth, 3 + u.size)
                        out.write(auth)
                        out.flush()
                        if (inp.read() != 0x01 || inp.read() != 0x00) return@use false
                    } else if (method != 0x00) {
                        return@use false
                    }

                    // --- CONNECT domain:port ---
                    val hb = host.toByteArray(Charsets.UTF_8)
                    val req = ByteArray(5 + hb.size + 2)
                    req[0] = 0x05; req[1] = 0x01; req[2] = 0x00; req[3] = 0x03
                    req[4] = hb.size.toByte()
                    hb.copyInto(req, 5)
                    req[5 + hb.size] = ((tport shr 8) and 0xFF).toByte()
                    req[6 + hb.size] = (tport and 0xFF).toByte()
                    out.write(req)
                    out.flush()
                    if (inp.read() != 0x05) return@use false
                    // REP = 0x00 (succeeded) — маршрут построен, туннель функционален
                    inp.read() == 0x00
                }
            }.getOrDefault(false)
            if (ok) {
                lastL1OkAtMs = System.currentTimeMillis()
                return true
            }
        }
        return false
    }

    private var networkChangeJob: Job? = null

    private val sessionSeq = AtomicInteger(0)
    private val failoverInFlight = AtomicBoolean(false)
    private val pendingStartResult = AtomicReference<CompletableDeferred<Result<Unit>>?>(null)
    private val screenWakeSignal = AtomicReference(CompletableDeferred<Unit>())

    // Per-session CSPRNG credentials authenticating local SOCKS5 inbound `127.0.0.1:10808`
    private val sessionSocksUser: String by lazy { "vlx_" + randomHex(6) }
    private val sessionSocksPass: String by lazy { randomHex(16) }

    @Volatile
    private var activeTunSettings: AppSettings = AppSettings()

    @Volatile
    private var currentState: VpnRuntimeState = VpnRuntimeState()

    @Volatile
    private var isScreenInteractive: Boolean = true

    @Volatile
    private var screenOffSinceMs: Long = 0L

    @Volatile
    private var waitingForPhysicalNet: Boolean = false

    @Volatile
    private var sessionFailoverCount: Int = 0

    @Volatile
    private var lastNetworkHandle: Long = 0L

    private var netCallbackRegistered = false
    private var screenReceiverRegistered = false

    // Delta-gating state to eliminate wasted disk I/O, NotificationManager & TileService IPC
    private var lastNotifUpdateMs: Long = 0L
    private var lastNotifBytes: Long = -1L
    private var lastNotifNodeKey: String = ""
    private var lastDiskPublishMs: Long = 0L
    private var lastDiskBytes: Long = -1L
    private var lastTileSignature: String = ""
    private var lastProgressEmitMs: Long = 0L
    private var lastProgressLabel: String = ""

    private val screenStateReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            when (intent?.action) {
                Intent.ACTION_SCREEN_OFF -> {
                    isScreenInteractive = false
                    screenOffSinceMs = System.currentTimeMillis()
                    screenWakeSignal.set(CompletableDeferred())
                    VeloxNative.trimMemoryIfLoaded()
                }
                Intent.ACTION_SCREEN_ON, Intent.ACTION_USER_PRESENT -> {
                    val wasOff = !isScreenInteractive
                    val sleptMs = if (screenOffSinceMs > 0L) {
                        System.currentTimeMillis() - screenOffSinceMs
                    } else 0L
                    isScreenInteractive = true
                    screenOffSinceMs = 0L
                    screenWakeSignal.get().complete(Unit)

                    // After prolonged sleep (>=60s), verify tunnel once on wake & heal seamlessly if NAT expired
                    if (wasOff && sleptMs >= 60_000L && currentState.phase == VpnPhase.CONNECTED) {
                        scope.launch {
                            delay(350L)
                            if (currentState.phase == VpnPhase.CONNECTED && hasUnderlyingNetwork()) {
                                verifyTunnelOrPromoteStandby(reason = "Пробуждение экрана после сна")
                            }
                        }
                    } else if (wasOff && waitingForPhysicalNet && hasUnderlyingNetwork()) {
                        waitingForPhysicalNet = false
                        launchConnectFlow(forceRefresh = false, autoHealing = true)
                    }
                }
            }
        }
    }

    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            val handle = network.networkHandle
            val prev = lastNetworkHandle
            lastNetworkHandle = handle

            if (waitingForPhysicalNet) {
                waitingForPhysicalNet = false
                val netDesc = VeloxNative.describeActiveNetwork(this@VeloxVpnService)
                VeloxNative.logOk(this@VeloxVpnService, "NET", "Сеть вернулась ($netDesc) — мгновенное восстановление!")
                networkChangeJob?.cancel()
                networkChangeJob = scope.launch {
                    delay(250L)
                    if (currentState.phase == VpnPhase.CONNECTED) {
                        verifyTunnelOrPromoteStandby(reason = "Возврат физической сети")
                    } else {
                        launchConnectFlow(forceRefresh = false, autoHealing = true)
                    }
                }
                return
            }

            if (prev != 0L && prev != handle) {
                val st = currentState
                val netDesc = VeloxNative.describeActiveNetwork(this@VeloxVpnService)
                if (st.phase == VpnPhase.CONNECTED) {
                    VeloxNative.logInfo(this@VeloxVpnService, "NET", "Переключение сети -> $netDesc, проверка канала…")
                    networkChangeJob?.cancel()
                    networkChangeJob = scope.launch {
                        delay(900L)
                        if (currentState.phase == VpnPhase.CONNECTED && hasUnderlyingNetwork()) {
                            verifyTunnelOrPromoteStandby(reason = "Смена сети Wi-Fi/LTE")
                        }
                    }
                } else if (st.phase == VpnPhase.HEALING) {
                    VeloxNative.logInfo(this@VeloxVpnService, "NET", "Сеть активна ($netDesc) — переподключение")
                    launchConnectFlow(forceRefresh = false, autoHealing = true)
                }
            }
        }

        override fun onLost(network: Network) {
            networkChangeJob?.cancel()
            networkChangeJob = scope.launch {
                // Brief 450 ms grace so Wi-Fi -> LTE handover doesn't flicker offline banner
                delay(450L)
                if (!hasUnderlyingNetwork() &&
                    (currentState.phase == VpnPhase.CONNECTED || currentState.phase == VpnPhase.HEALING)
                ) {
                    enterSilentOfflineWait()
                }
            }
        }
    }

    override fun onCreate() {
        super.onCreate()
        ensureNotificationChannel()
        VeloxNative.ensureInitialized(this)
        VeloxNative.setLocalSocksAuth(VeloxPrefs.LOCAL_VPN_SOCKS_PORT, sessionSocksUser, sessionSocksPass)
        VeloxPrefs.saveSessionSocksAuth(this, VeloxPrefs.LOCAL_VPN_SOCKS_PORT, sessionSocksUser, sessionSocksPass)
        val settings = VeloxPrefs.loadSettings(this)
        VeloxNative.syncHwidConfig(this, settings.sendHwid)
        val pm = getSystemService(PowerManager::class.java)
        isScreenInteractive = pm?.isInteractive != false
        if (!isScreenInteractive) {
            screenOffSinceMs = System.currentTimeMillis()
        }
        registerScreenWatcher()
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
                        subtitle = "Бесшовное переключение на резервный узел",
                        ongoing = true,
                        progressPct = 45,
                    )
                )
                rotateActiveNode()
                return START_STICKY
            }
            ACTION_HOT_RELOAD -> {
                if (currentState.phase == VpnPhase.CONNECTED) {
                    hotReloadActiveTunnel(reason = "Обновление настроек")
                } else if (currentState.isActiveOrBusy) {
                    launchConnectFlow(forceRefresh = false, autoHealing = false)
                }
                return START_STICKY
            }
            ACTION_REFRESH_POOL -> {
                refreshPoolInBackground(silentStandbyMount = false)
                return START_STICKY
            }
            else -> {
                // Covers ACTION_CONNECT, Android Always-On VPN ("android.net.VpnService"), and restart
                val forceRefresh = intent?.getBooleanExtra(EXTRA_FORCE_REFRESH, false) == true
                val settings = VeloxPrefs.loadSettings(this)
                sessionFailoverCount = 0
                waitingForPhysicalNet = false
                promoteForeground(
                    buildStatusNotification(
                        title = "VeloxVPN · Подключение (${regionTitleRu(settings.region)})",
                        subtitle = "Подготовка анти-DPI ядра · ${formatEtaRu(6)}",
                        ongoing = true,
                        progressPct = 10,
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
        unregisterScreenWatcher()
        unregisterNetWatcher()
        sessionSeq.incrementAndGet()
        networkChangeJob?.cancel()
        monitorJob?.cancel()
        connectJob?.cancel()
        poolRefreshJob?.cancel()
        VeloxPrefs.clearSessionSocksAuth(this)
        safeStopCoreAndTun()
        scope.cancel()
        super.onDestroy()
    }

    private fun launchConnectFlow(forceRefresh: Boolean, autoHealing: Boolean) {
        val mySeq = sessionSeq.incrementAndGet()
        if (!autoHealing) {
            // Ручной коннект = новый отсчёт: снимаем окно удержания и историю автопереключений
            synchronized(flapLock) { autoPromoteStamps.clear() }
            resilientUntilMs = 0L
            activeIsWhitelist = false
            pendingHotSwap = false
        }
        probeFailures = 0
        connectJob?.cancel()
        monitorJob?.cancel()

        connectJob = scope.launch {
            val startedMs = System.currentTimeMillis()
            val settings = VeloxPrefs.loadSettings(this@VeloxVpnService)
            val regionLabel = regionTitleRu(settings.region)
            val isAborted: () -> Boolean = { !isActive || sessionSeq.get() != mySeq }

            try {
                VeloxNative.reloadFromDisk(this@VeloxVpnService)
                VeloxNative.setLocalSocksAuth(
                    VeloxPrefs.LOCAL_VPN_SOCKS_PORT,
                    sessionSocksUser,
                    sessionSocksPass
                )
                VeloxNative.syncHwidConfig(this@VeloxVpnService, settings.sendHwid)

                val netDesc = VeloxNative.describeActiveNetwork(this@VeloxVpnService)
                VeloxNative.logInfo(
                    this@VeloxVpnService,
                    "VPN",
                    "=== Старт v1.7.2: $regionLabel | 2×Резерв=${if (settings.dualChannel) "ВКЛ" else "выкл"} | " +
                        "БС=${if (settings.whitelistMode) "ВКЛ" else "выкл"} | YT0%=${if (settings.adblockYoutube) "ВКЛ" else "выкл"} | " +
                        "Фрагм=${if (settings.fragmentTls) "ВКЛ" else "выкл"} | $netDesc ==="
                )

                // Strict physical internet check — never blacklist good servers when offline!
                if (!hasUnderlyingNetwork()) {
                    VeloxNative.logWarn(this@VeloxVpnService, "NET", "Физическая сеть (Wi-Fi/LTE) недоступна — ожидание")
                    finishWithError(
                        "Нет подключения к интернету — включите Wi-Fi или мобильную сеть",
                        keepWaitingForNetwork = autoHealing,
                    )
                    return@launch
                }

                // Check cached strictly-scoped verified pool FIRST (allows atomic hot-swap when switching nodes!)
                var buildRes = JSONObject(buildTunJson(settings, idlePowerSave = !isScreenInteractive))
                val hasVerified = buildRes.optBoolean("ok", false) &&
                    buildRes.optBoolean("primaryVerified", false)
                val needsRegionRefresh = buildRes.optBoolean("needsRegionRefresh", false)
                val needsWhitelistRefresh = buildRes.optBoolean("needsWhitelistRefresh", false)
                val needsSeedProbe = buildRes.optBoolean("needsSeedProbe", false)

                var didFullLiveRefresh = false

                if (forceRefresh ||
                    (hasVerified && (needsRegionRefresh || needsWhitelistRefresh) && !autoHealing)
                ) {
                    prepareForRefresh()
                    if (isAborted()) return@launch
                    didFullLiveRefresh = true
                    val ok = runLiveRefreshWithUi(
                        settings = settings,
                        startedMs = startedMs,
                        maxBatch = 44,
                        isAborted = isAborted,
                    )
                    if (isAborted()) return@launch
                    if (!ok && canFallbackToWhitelistPass(settings)) {
                        runEmergencyWhitelistPass(settings, startedMs, isAborted)
                        if (isAborted()) return@launch
                    }
                    buildRes = JSONObject(buildTunJson(settings, idlePowerSave = !isScreenInteractive))
                } else if (!hasVerified) {
                    prepareForRefresh()
                    if (isAborted()) return@launch
                    var seedAlive = 0
                    if (needsSeedProbe) {
                        emitProgress(
                            phase = if (autoHealing) VpnPhase.HEALING else VpnPhase.FETCHING,
                            startedMs = startedMs,
                            stageIdx = 1,
                            stageTotal = 3,
                            percent = 14,
                            etaSec = 5,
                            statusLine = "Экспресс-проверка серверов $regionLabel…",
                            detailLine = "Тест основного и резервного канала (Reality / XHTTP / Hy2)",
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
                            "Экспресс-проверка нашла $seedAlive живых узлов ($regionLabel) — мгновенный старт!"
                        )
                        buildRes = JSONObject(buildTunJson(settings, idlePowerSave = !isScreenInteractive))
                        notifyEngineUpdated(null)
                    } else {
                        didFullLiveRefresh = true
                        val ok = runLiveRefreshWithUi(
                            settings = settings,
                            startedMs = startedMs,
                            maxBatch = 44,
                            isAborted = isAborted,
                        )
                        if (isAborted()) return@launch
                        if (!ok && canFallbackToWhitelistPass(settings)) {
                            runEmergencyWhitelistPass(settings, startedMs, isAborted)
                            if (isAborted()) return@launch
                        }
                        buildRes = JSONObject(buildTunJson(settings, idlePowerSave = !isScreenInteractive))
                    }
                }

                // Step 3: Establish Android TUN tunnel (atomic replace if already running -> zero drop!)
                var attempt = 0
                val maxTunAttempts = 4
                var lastTunError = ""

                while (attempt < maxTunAttempts && !isAborted()) {
                    val curSettings = VeloxPrefs.loadSettings(this@VeloxVpnService)
                    val wlStarved = curSettings.whitelistMode &&
                        buildRes.optBoolean("needsWhitelistRefresh", false) &&
                        !didFullLiveRefresh
                    val ready = !wlStarved &&
                        buildRes.optBoolean("ok", false) &&
                        (buildRes.optBoolean("primaryVerified", false) || curSettings.pinnedNodeId.isNotBlank())

                    if (!ready) {
                        if (!didFullLiveRefresh && hasUnderlyingNetwork()) {
                            prepareForRefresh()
                            didFullLiveRefresh = true
                            val ok = runLiveRefreshWithUi(
                                settings = curSettings,
                                startedMs = startedMs,
                                maxBatch = 44,
                                isAborted = isAborted,
                            )
                            if (isAborted()) return@launch
                            if (!ok && canFallbackToWhitelistPass(curSettings)) {
                                runEmergencyWhitelistPass(curSettings, startedMs, isAborted)
                                if (isAborted()) return@launch
                            }
                            buildRes = JSONObject(buildTunJson(curSettings, idlePowerSave = !isScreenInteractive))
                            if (!buildRes.optBoolean("ok", false) || !buildRes.optBoolean("primaryVerified", false)) {
                                break
                            }
                        } else {
                            break
                        }
                    }

                    attempt++
                    val startedState = startTunSessionFromPlan(
                        buildRes = buildRes,
                        settings = curSettings,
                        startedMs = startedMs,
                        attempt = attempt,
                        maxAttempts = maxTunAttempts,
                        autoHealing = autoHealing,
                        preserveSinceMs = 0L,
                        isAborted = isAborted,
                    )

                    if (startedState.isSuccess) {
                        val connectedState = startedState.getOrThrow()
                        waitingForPhysicalNet = false
                        publishState(connectedState, force = true)
                        updateConnectedNotification(connectedState, force = true)
                        // Release bootstrap HTTP/DNS/feed buffers from :vpn heap immediately!
                        VeloxNative.trimMemoryIfLoaded()

                        // If Dual-Channel is ON and we only had 1 verified node in this country,
                        // quietly fetch & mount a 2nd hot-standby in the background with ZERO drop!
                        if (curSettings.dualChannel &&
                            buildRes.optBoolean("needsStandbyReplenish", false) &&
                            hasUnderlyingNetwork()
                        ) {
                            refreshPoolInBackground(silentStandbyMount = true)
                        }

                        startLiveMonitorLoop(mySeq)
                        return@launch
                    }

                    val errText = VpnBatchProber.formatThrowable(startedState.exceptionOrNull())
                    lastTunError = errText
                    safeStopCoreAndTun()

                    // Never penalize nodes or drop user's pinned server if physical internet vanished!
                    if (!hasUnderlyingNetwork()) {
                        finishWithError("Ожидание сети", keepWaitingForNetwork = true)
                        return@launch
                    }

                    val failedId = (buildRes.optJSONObject("primary") ?: buildRes.optJSONObject("activeNode"))
                        ?.optString("id").orEmpty()
                    if (failedId.isNotBlank()) {
                        VeloxNative.reportNodeFailure(failedId, curSettings.region, "TUN старт: $errText")
                        if (curSettings.pinnedNodeId == failedId) {
                            VeloxPrefs.updateSettings(this@VeloxVpnService) { it.copy(pinnedNodeId = "") }
                        }
                    }
                    buildRes = JSONObject(
                        buildTunJson(
                            VeloxPrefs.loadSettings(this@VeloxVpnService),
                            idlePowerSave = !isScreenInteractive
                        )
                    )
                }

                if (isAborted()) return@launch

                if (!hasUnderlyingNetwork()) {
                    finishWithError("Ожидание сети", keepWaitingForNetwork = true)
                    return@launch
                }

                val isSpecificCountry = settings.region.length == 2 &&
                    !settings.region.equals("WL", true) &&
                    !settings.region.equals("YT", true) &&
                    !settings.region.equals("EU", true)
                val finalMsg = when {
                    isSpecificCountry ->
                        "В регионе «$regionLabel» сейчас нет доступных узлов — нажмите ↻ или выберите «Авто»"
                    lastTunError.isNotBlank() ->
                        "Не удалось поднять туннель — включите «Белые списки РФ» или откройте Журнал"
                    else ->
                        "Не найдено рабочих узлов $regionLabel — попробуйте «Авто», «Белые списки РФ» или подписку"
                }
                VeloxNative.logErr(this@VeloxVpnService, "VPN", "Подключение завершено без успеха: $finalMsg")
                finishWithError(finalMsg, keepWaitingForNetwork = false)
            } catch (_: CancellationException) {
                // Superseded by newer action
            } catch (t: Throwable) {
                val err = VpnBatchProber.formatThrowable(t)
                VeloxNative.logErr(this@VeloxVpnService, "VPN", "Непредвиденная ошибка сервиса: $err")
                finishWithError("Ошибка VPN: ${err.take(110)}", keepWaitingForNetwork = false)
            }
        }
    }

    private suspend fun startTunSessionFromPlan(
        buildRes: JSONObject,
        settings: AppSettings,
        startedMs: Long,
        attempt: Int,
        maxAttempts: Int,
        autoHealing: Boolean,
        preserveSinceMs: Long,
        isAborted: () -> Boolean,
    ): Result<VpnRuntimeState> {
        val regionLabel = regionTitleRu(settings.region)
        val configJson = buildRes.getString("configJson")
        val primary = buildRes.optJSONObject("primary") ?: buildRes.getJSONObject("activeNode")
        val standby = buildRes.optJSONObject("standbyNode")
        val dualActive = buildRes.optBoolean("dualChannelActive", standby != null)
        val firstTag = buildRes.optString("firstTag", "vpn_0").ifBlank { "vpn_0" }
        val freshlyVerified = buildRes.optBoolean("freshlyVerified", false)
        val viaWarp = buildRes.optBoolean("viaWarp", primary.optBoolean("via_warp", false))

        val nodeId = primary.optString("id")
        val nodeName = primary.optString("name", regionLabel)
        val proto = primary.optString("display_protocol", "VLESS")
        val exitCountry = primary.optString("exit_country", settings.region)
        val exitColo = primary.optString("exit_colo", "")
        val exitIp = primary.optString("exit_ip", "")
        var initRtt = primary.optInt("rtt_ms", 0)
        val backupCnt = buildRes.optInt("backupCount", 0)

        val sbId = standby?.optString("id").orEmpty()
        val sbName = standby?.optString("name").orEmpty()
        val sbProto = standby?.optString("display_protocol").orEmpty()
        val sbCountry = standby?.optString("exit_country").orEmpty()
        val sbRtt = standby?.optInt("rtt_ms", 0) ?: 0

        val startupProbe = if (freshlyVerified || viaWarp || preserveSinceMs > 0L) {
            null
        } else {
            XrayStartupProbeOptions(
                // HTTPS :443 only — HTTP :80 is dropped by many exits/DPI and caused false fails
                "https://cp.cloudflare.com/generate_204",
                5000L,
                firstTag,
            )
        }

        if (preserveSinceMs == 0L) {
            emitProgress(
                phase = if (autoHealing) VpnPhase.HEALING else VpnPhase.CONNECTING,
                startedMs = startedMs,
                stageIdx = 5,
                stageTotal = 5,
                percent = 94,
                etaSec = if (freshlyVerified) 1 else 3,
                statusLine = "Запуск: $nodeName ($proto)…",
                detailLine = when {
                    dualActive && sbName.isNotBlank() ->
                        "2× канал: резерв $sbName (${countryFlag(sbCountry)}) готов"
                    viaWarp ->
                        "Двуххоповый канал MASQUE-Chain -> $exitCountry ($attempt/$maxAttempts)"
                    else ->
                        "Открытие защищённого TUN-интерфейса ($attempt/$maxAttempts)"
                },
            )
        }

        activeTunSettings = settings
        probeFailures = 0
        val tStart = System.currentTimeMillis()
        val waiter = CompletableDeferred<Result<Unit>>()
        pendingStartResult.set(waiter)

        // Atomic session swap: XrayVpnService replaces any existing core without dropping VPN consent!
        val invoked = runCatching {
            startXrayTunnel(
                configJson,
                XrayTunBackend.FileDescriptor,
                mapRuntimeProfile(settings.profileMode),
                startupProbe,
                1360, // Safe MTU 1360 (MSS 1320) across LTE/5G/PPPoE + VLESS/XHTTP/Hy2/MASQUE
            )
        }

        var startAttempt: Result<Unit> = if (invoked.isFailure) {
            pendingStartResult.compareAndSet(waiter, null)
            Result.failure(invoked.exceptionOrNull() ?: IllegalStateException("startXrayTunnel failed"))
        } else {
            withTimeoutOrNull(15_000L) { waiter.await() } ?: run {
                pendingStartResult.compareAndSet(waiter, null)
                Result.failure(IllegalStateException("Таймаут запуска TUN (15с)"))
            }
        }

        // Verify stale (>15 min) 2-hop MASQUE-Chain nodes respecting 1.15s QUIC spacing
        if (startAttempt.isSuccess && viaWarp && !freshlyVerified && preserveSinceMs == 0L && !isAborted()) {
            delay(1250L)
            var hObj = probeLocalSocksOnce()
            if (!hObj.first && !isAborted()) {
                delay(1200L)
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

        if (startAttempt.isFailure) {
            return Result.failure(startAttempt.exceptionOrNull() ?: IllegalStateException("TUN fail"))
        }

        val tunMs = System.currentTimeMillis() - tStart
        val totalMs = System.currentTimeMillis() - startedMs
        val wlActive = buildRes.optBoolean(
            "whitelistActive",
            settings.whitelistMode && primary.optBoolean("whitelist_friendly", false)
        )
        // v1.7.1: запоминаем тип активного узла — от него зависит стратегия проверки живости
        activeIsWhitelist = wlActive
        val ytMode = buildRes.optString("ytMode", "")
        val ytZeroAds = settings.adblockYoutube && ytMode.contains("0ads")

        if (preserveSinceMs == 0L) {
            VeloxNative.logOk(
                this,
                "VPN",
                "ПОДКЛЮЧЕНО за ${String.format("%.1f", totalMs / 1000.0)}с (TUN ${tunMs}мс): " +
                    "$nodeName [$proto] exit=$exitIp ($exitCountry/$exitColo) " +
                    "2×=${if (dualActive) "$sbName($sbCountry)" else "ожид"} yt=$ytMode rtt=${initRtt}мс"
            )
        }

        val standbyTier = buildRes.optString("standbyTier", "")
        val status = buildString {
            append(proto)
            if (dualActive) {
                append(
                    when (standbyTier) {
                        "same_country" -> " · 2× та же страна"
                        "de_us" -> " · 2× резерв DE/US"
                        "foreign" -> " · 2× зарубеж."
                        else -> " · 2× резерв"
                    }
                )
            }
            if (wlActive) append(" · БС РФ")
            if (ytZeroAds) {
                append(" · YT 0%")
            } else if (settings.adblockYoutube) {
                append(" · Антирекл.")
            }
            if (settings.bypassRu) append(" · РФ напрямую")
        }

        val prev = currentState
        return Result.success(
            VpnRuntimeState(
                phase = VpnPhase.CONNECTED,
                statusLine = status,
                activeNodeId = nodeId,
                activeNodeName = nodeName,
                activeProtocol = proto,
                exitCountry = exitCountry,
                exitColo = exitColo,
                exitIp = exitIp,
                rttMs = initRtt,
                backupCount = backupCnt,
                dualChannelActive = dualActive,
                standbyNodeId = sbId,
                standbyNodeName = sbName,
                standbyProtocol = sbProto,
                standbyCountry = sbCountry,
                standbyRttMs = sbRtt,
                failoverCount = sessionFailoverCount,
                connectedSinceMs = if (preserveSinceMs > 0L) preserveSinceMs else System.currentTimeMillis(),
                progressPercent = 100,
                etaSeconds = 0,
                uplinkBytes = if (preserveSinceMs > 0L) prev.uplinkBytes else 0L,
                downlinkBytes = if (preserveSinceMs > 0L) prev.downlinkBytes else 0L,
                activeConnections = if (preserveSinceMs > 0L) prev.activeConnections else 0,
            )
        )
    }

    /**
     * Seamless Dual-Channel Promotion (~40 ms atomic swap, zero drop):
     * 1) Demotes failed primary `vpn_0` in strictly scoped region pool.
     * 2) Pre-verified Hot-Standby `vpn_1` promotes to Primary `vpn_0`, and next best server `vpn_2`
     *    (strictly same country if country selected; best global if `AUTO`) mounts as new `vpn_1`!
     * 3) If pool has <2 live servers left in that country, triggers silent background replenishment
     *    via protected sockets and hot-mounts the new `vpn_1` automatically once verified!
     */
    private suspend fun promoteHotStandbySeamlessly(reason: String, probeDriven: Boolean = false): Boolean {
        // v1.7.1: автопереключение по «мягким» признакам (HTTP-проба/замирание) не должно
        // превращаться в карусель серверов — только после подтверждений и вне окна удержания.
        if (probeDriven && !canAutoPromote(reason)) return false
        if (!hasUnderlyingNetwork()) {
            enterSilentOfflineWait()
            return true
        }
        if (!failoverInFlight.compareAndSet(false, true)) return false
        try {
            val prev = currentState
            val badId = prev.activeNodeId
            val settings = VeloxPrefs.loadSettings(this)
            VeloxNative.reloadFromDisk(this)
            VeloxNative.setLocalSocksAuth(
                VeloxPrefs.LOCAL_VPN_SOCKS_PORT,
                sessionSocksUser,
                sessionSocksPass
            )

            var needsReplenish = false
            if (badId.isNotBlank()) {
                val rep = runCatching {
                    JSONObject(VeloxNative.reportNodeFailure(badId, settings.region, reason))
                }.getOrDefault(JSONObject())
                needsReplenish = rep.optBoolean("needsStandbyReplenish", false) ||
                    rep.optInt("remainingLive", 0) < 2
                if (settings.pinnedNodeId == badId) {
                    VeloxPrefs.updateSettings(this) { it.copy(pinnedNodeId = "") }
                }
            }

            val freshSettings = VeloxPrefs.loadSettings(this)
            val buildRes = JSONObject(buildTunJson(freshSettings, idlePowerSave = !isScreenInteractive))
            if (!buildRes.optBoolean("ok", false) || !buildRes.optBoolean("primaryVerified", false)) {
                VeloxNative.logWarn(
                    this,
                    "DUAL",
                    "В пуле ${regionTitleRu(freshSettings.region)} закончились готовые резервы — запуск подбора…"
                )
                notifyEngineUpdated(null)
                launchConnectFlow(forceRefresh = false, autoHealing = true)
                return false
            }

            sessionFailoverCount++
            val since = prev.connectedSinceMs.takeIf { it > 0L } ?: System.currentTimeMillis()
            val swapped = startTunSessionFromPlan(
                buildRes = buildRes,
                settings = freshSettings,
                startedMs = System.currentTimeMillis(),
                attempt = 1,
                maxAttempts = 1,
                autoHealing = true,
                preserveSinceMs = since,
                isAborted = { false },
            )

            if (swapped.isSuccess) {
                val next = swapped.getOrThrow()
                if (probeDriven) noteAutoPromote()
                VeloxNative.logOk(
                    this,
                    "DUAL",
                    "Бесшовный переход #$sessionFailoverCount ($reason) -> #1 ${next.activeNodeName} (${next.exitCountry}) | " +
                        "#2 резерв: ${next.standbyNodeName.ifBlank { "подбор в фоне…" }}"
                )
                publishState(next, force = true)
                if (isScreenInteractive) {
                    updateConnectedNotification(next, force = true)
                }
                notifyEngineUpdated(null)
                VeloxNative.trimMemoryIfLoaded()

                if (freshSettings.dualChannel &&
                    (needsReplenish || buildRes.optBoolean("needsStandbyReplenish", false)) &&
                    hasUnderlyingNetwork()
                ) {
                    refreshPoolInBackground(silentStandbyMount = true)
                }
                return true
            }

            launchConnectFlow(forceRefresh = false, autoHealing = true)
            return false
        } finally {
            failoverInFlight.set(false)
        }
    }

    /** Atomic live config hot-swap when user toggles settings or when a fresh `vpn_1` standby arrives. */
    private fun hotReloadActiveTunnel(reason: String) {
        scope.launch {
            if (currentState.phase != VpnPhase.CONNECTED) return@launch
            if (!failoverInFlight.compareAndSet(false, true)) return@launch
            try {
                val settings = VeloxPrefs.loadSettings(this@VeloxVpnService)
                VeloxNative.reloadFromDisk(this@VeloxVpnService)
                VeloxNative.setLocalSocksAuth(
                    VeloxPrefs.LOCAL_VPN_SOCKS_PORT,
                    sessionSocksUser,
                    sessionSocksPass
                )
                VeloxNative.syncHwidConfig(this@VeloxVpnService, settings.sendHwid)
                val buildRes = JSONObject(buildTunJson(settings, idlePowerSave = !isScreenInteractive))
                val planReady = buildRes.optBoolean("ok", false) &&
                    (buildRes.optBoolean("primaryVerified", false) || settings.pinnedNodeId.isNotBlank())
                if (!planReady) {
                    // v1.7.2: для новой страны/настроек ещё нет проверенного узла. Раньше здесь
                    // просто ничего не происходило (пользователь ждал «в никуда»). Теперь текущий
                    // туннель продолжает работать, а пул дозаполняется в фоне и применяется сам.
                    pendingHotSwap = true
                    VeloxNative.logInfo(
                        this@VeloxVpnService,
                        "SWAP",
                        "Готового плана для ${regionTitleRu(settings.region)} нет — соединение сохранено, подбираю узлы в фоне…"
                    )
                    notifyEngineUpdated("Подбираю узлы для ${regionTitleRu(settings.region)} без разрыва соединения")
                    // Если подбор уже идёт, его завершение само применит отложенный план
                    // (`applyPendingHotSwapIfReady` в хвосте refreshPoolInBackground). Здесь лишь
                    // страхуем редкую гонку «подбор завершился ровно в этот момент» — без удержания
                    // failover-флага и без ожидания длинной операции.
                    if (poolRefreshJob?.isActive != true) {
                        refreshPoolInBackground(silentStandbyMount = false)
                    } else {
                        scope.launch {
                            delay(9000L)
                            if (pendingHotSwap && poolRefreshJob?.isActive != true) {
                                if (!applyPendingHotSwapIfReady()) {
                                    refreshPoolInBackground(silentStandbyMount = false)
                                }
                            }
                        }
                    }
                    return@launch
                }
                val since = currentState.connectedSinceMs.takeIf { it > 0L } ?: System.currentTimeMillis()
                val res = startTunSessionFromPlan(
                    buildRes = buildRes,
                    settings = settings,
                    startedMs = System.currentTimeMillis(),
                    attempt = 1,
                    maxAttempts = 1,
                    autoHealing = false,
                    preserveSinceMs = since,
                    isAborted = { false },
                )
                res.onSuccess { st ->
                    VeloxNative.logInfo(
                        this@VeloxVpnService,
                        "TUN",
                        "Горячее обновление без разрыва ($reason): #1 ${st.activeNodeName} | #2 ${st.standbyNodeName.ifBlank { "-" }}"
                    )
                    publishState(st, force = true)
                    if (isScreenInteractive) {
                        updateConnectedNotification(st, force = true)
                    }
                    VeloxNative.trimMemoryIfLoaded()
                }
            } finally {
                failoverInFlight.set(false)
            }
        }
    }

    private fun enterSilentOfflineWait() {
        if (waitingForPhysicalNet) return
        waitingForPhysicalNet = true
        VeloxNative.logInfo(
            this,
            "NET",
            "Физическая сеть пропала (лифт/метро/авиарежим) — тихое ожидание, узлы и выбор сохранены"
        )
        val st = currentState.copy(
            statusLine = "Ожидание сети (Wi-Fi / LTE)… · без сброса узла",
        )
        publishState(st, force = true)
        if (isScreenInteractive) {
            updateForegroundText(
                title = "VeloxVPN · Ожидание сети",
                subtitle = "Мгновенно восстановится при появлении Wi-Fi / LTE",
                progressPct = -1,
            )
        }
    }

    /** Only fallback to global whitelist search on AUTO/WL — NEVER violate a chosen country! */
    private fun canFallbackToWhitelistPass(settings: AppSettings): Boolean {
        if (settings.whitelistMode) return false
        val r = settings.region.uppercase()
        return r == "AUTO"
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

    private fun runEmergencyWhitelistPass(
        settings: AppSettings,
        startedMs: Long,
        isAborted: () -> Boolean,
    ): Boolean {
        if (!hasUnderlyingNetwork() || isAborted()) return false
        VeloxNative.logWarn(
            this,
            "VPN",
            "Стандартные узлы заблокированы -> экстренный поиск (Белые списки РФ + WARP MASQUE)"
        )
        emitProgress(
            phase = VpnPhase.FETCHING,
            startedMs = startedMs,
            stageIdx = 2,
            stageTotal = 5,
            percent = 24,
            etaSec = 14,
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
            waitingForPhysicalNet = true
            publishState(
                VpnRuntimeState(
                    phase = VpnPhase.HEALING,
                    statusLine = "Ожидание появления сети (Wi-Fi / LTE)…",
                ),
                force = true,
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
                ),
                force = true,
            )
            stopForegroundCompat()
            stopSelf()
        }
    }

    private fun rotateActiveNode() {
        if (currentState.phase == VpnPhase.CONNECTED) {
            scope.launch {
                promoteHotStandbySeamlessly(reason = "ручная смена узла")
            }
            return
        }
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

    /** Применяет отложенный план (смена страны/настроек) атомарной заменой ядра без разрыва. */
    private suspend fun applyPendingHotSwapIfReady(): Boolean {
        if (!pendingHotSwap || currentState.phase != VpnPhase.CONNECTED) return false
        val latest = VeloxPrefs.loadSettings(this)
        val plan = runCatching {
            JSONObject(buildTunJson(latest, idlePowerSave = !isScreenInteractive))
        }.getOrNull()
        val planOk = plan?.optBoolean("ok", false) == true &&
            (plan.optBoolean("primaryVerified", false) || latest.pinnedNodeId.isNotBlank())
        if (!planOk) return false
        pendingHotSwap = false
        hotReloadActiveTunnel(reason = "применение новых настроек после подбора")
        return true
    }

    private fun refreshPoolInBackground(silentStandbyMount: Boolean) {
        if (poolRefreshJob?.isActive == true) return
        poolRefreshJob = scope.launch {
            if (!hasUnderlyingNetwork()) {
                if (!silentStandbyMount) notifyEngineUpdated("Нет подключения к интернету")
                return@launch
            }
            val settings = VeloxPrefs.loadSettings(this@VeloxVpnService)
            if (silentStandbyMount) {
                VeloxNative.logInfo(
                    this@VeloxVpnService,
                    "DUAL",
                    "Фоновая подготовка резервного сервера (${regionTitleRu(settings.region)}) без разрыва VPN…"
                )
            }
            val outcome = VpnBatchProber.refreshPoolBlocking(
                context = this@VeloxVpnService,
                settings = settings,
                vpnService = this@VeloxVpnService, // protects all probe sockets outside active TUN!
                maxBatch = if (silentStandbyMount) 28 else 38,
                onProgress = null,
            )
            VeloxNative.trimMemoryIfLoaded()

            // v1.7.2: если пользователь менял страну/настройки, пока шёл подбор — применяем план
            // бесшовно, как только он готов.
            applyPendingHotSwapIfReady()

            if (silentStandbyMount) {
                notifyEngineUpdated(null)
                val reloadNeeded = outcome.ok &&
                    currentState.phase == VpnPhase.CONNECTED &&
                    !currentState.dualChannelActive &&
                    VeloxPrefs.loadSettings(this@VeloxVpnService).dualChannel
                if (reloadNeeded) {
                    hotReloadActiveTunnel(reason = "подключён горячий резерв")
                }
            } else {
                val msg = if (outcome.ok) {
                    "Обновлено: +${outcome.newlyVerified} серверов (${regionTitleRu(settings.region)})"
                } else {
                    outcome.error.ifBlank { "Новых серверов не найдено" }
                }
                notifyEngineUpdated(msg)
                val reloadNeeded = outcome.ok &&
                    currentState.phase == VpnPhase.CONNECTED &&
                    !currentState.dualChannelActive &&
                    VeloxPrefs.loadSettings(this@VeloxVpnService).dualChannel
                if (reloadNeeded) {
                    hotReloadActiveTunnel(reason = "подключён горячий резерв")
                }
            }
        }
    }

    /**
     * Zero-Idle Battery + Passive 3-Second Stall-Detecting Monitor Loop (v1.6.0):
     * - Screen OFF: blocks on `screenWakeSignal` with **0 wakeups/min**, 0 disk I/O, 0 probes!
     * - Screen ON: reads zero-cost in-memory `tunStats`; detects DPI freeze (`up >= 1.4 KB` with
     *   `down == 0 B` for 3 s) -> instantly promotes hot-standby `vpn_1` + mounts `vpn_2`!
     * - Skips periodic probe whenever real downlink traffic flowed in last 30 s (0 radio tail waste!).
     */
    private fun startLiveMonitorLoop(mySeq: Int) {
        monitorJob?.cancel()
        monitorJob = scope.launch {
            var activeTick = 0
            var stallSeconds = 0
            var stallAccumUp = 0L
            var prevUp = currentState.uplinkBytes
            var prevDown = currentState.downlinkBytes
            var lastDownlinkAtMs = System.currentTimeMillis()

            // v1.7.2: единичная пост-проверка идёт В ОТДЕЛЬНОЙ корутине, чтобы даже худший
            // сценарий (узел с фильтрацией SNI + 15-секундные таймауты) не замораживал тики монитора.
            scope.launch {
                delay(1800L)
                if (isActive && sessionSeq.get() == mySeq &&
                    currentState.phase == VpnPhase.CONNECTED &&
                    !waitingForPhysicalNet && hasUnderlyingNetwork()
                ) {
                    verifyRealAndroidBrowserTunPath()
                    lastDownlinkAtMs = System.currentTimeMillis()
                }
            }

            while (isActive && sessionSeq.get() == mySeq && currentState.phase == VpnPhase.CONNECTED) {
                // ZERO-IDLE DOZE MODE: sleep completely while screen is off (0 CPU/radio/IPC wakeups!)
                if (!isScreenInteractive) {
                    val sig = screenWakeSignal.get()
                    sig.await()
                    // Re-baseline counters smoothly on wake so accumulated sleep bytes don't trigger stall
                    val wakeSnap = runCatching { xrayVpnRuntimeSnapshot() }.getOrNull()
                    if (wakeSnap != null) {
                        prevUp = wakeSnap.tunStats?.uplinkBytes ?: prevUp
                        prevDown = wakeSnap.tunStats?.downlinkBytes ?: prevDown
                        stallSeconds = 0
                        stallAccumUp = 0L
                        val updated = currentState.copy(
                            uplinkBytes = prevUp,
                            downlinkBytes = prevDown,
                            activeConnections = wakeSnap.activeConnections,
                        )
                        publishState(updated, force = true)
                        updateConnectedNotification(updated, force = false)
                    }
                    continue
                }

                delay(1000L)
                if (!isScreenInteractive) continue
                activeTick++

                val snap = runCatching { xrayVpnRuntimeSnapshot() }.getOrNull()
                if (snap != null && !snap.running && !failoverInFlight.get()) {
                    VeloxNative.logWarn(this@VeloxVpnService, "TUN", "Сессия Xray завершилась — авто-восстановление")
                    if (VeloxPrefs.loadSettings(this@VeloxVpnService).autoHeal) {
                        promoteHotStandbySeamlessly(reason = "перезапуск ядра")
                    } else {
                        shutdownTunnel(userInitiated = false, message = "Соединение прервано")
                    }
                    continue
                }

                if (snap != null) {
                    val curUp = snap.tunStats?.uplinkBytes ?: currentState.uplinkBytes
                    val curDown = snap.tunStats?.downlinkBytes ?: currentState.downlinkBytes
                    val dUp = (curUp - prevUp).coerceAtLeast(0L)
                    val dDown = (curDown - prevDown).coerceAtLeast(0L)
                    prevUp = curUp
                    prevDown = curDown

                    val now = System.currentTimeMillis()
                    if (dDown > 0L) {
                        lastDownlinkAtMs = now
                        stallSeconds = 0
                        stallAccumUp = 0L
                        probeFailures = 0
                    } else if (snap.activeConnections > 0 && dUp > 0L && !waitingForPhysicalNet) {
                        stallSeconds++
                        stallAccumUp += dUp
                    } else if (snap.activeConnections == 0) {
                        stallSeconds = 0
                        stallAccumUp = 0L
                    }

                    val updated = currentState.copy(
                        uplinkBytes = curUp,
                        downlinkBytes = curDown,
                        activeConnections = snap.activeConnections,
                    )
                    publishState(updated, force = false)
                    updateConnectedNotification(updated, force = false)

                    // PASSIVE STALL DETECTOR (zero extra packets until real user traffic freezes!):
                    // User apps sent >=1.4 KB across >=3 s and received 0 B back -> check & promote vpn_1!
                    if (stallSeconds >= 4 && stallAccumUp >= 1400L && !failoverInFlight.get()) {
                        stallSeconds = 0
                        stallAccumUp = 0L
                        val curSettings = VeloxPrefs.loadSettings(this@VeloxVpnService)
                        if (curSettings.autoHeal) {
                            if (!hasUnderlyingNetwork()) {
                                enterSilentOfflineWait()
                            } else {
                                // Трафик замер, но L1 может быть жив (узел режет часть адресов) —
                                // поэтому здесь принудительно идёт и тяжёлый замер. Монитор при этом
                                // продолжает тикать: проверка вынесена в отдельную полосу.
                                launchProbeCheck(
                                    reason = "замирание канала (0 Б ответа)",
                                    forceHeavy = true,
                                    minFailures = 2,
                                )
                                lastDownlinkAtMs = System.currentTimeMillis()
                            }
                        }
                    }

                    // RADIO-FRIENDLY WATCHDOG: only every 90 s, ONLY if active connections exist AND
                    // no real downlink arrived in the last 30 s (0 wasted LTE/5G tail energy!).
                    // v1.7.2: дешёвая L1-проба каждые 60 с вместо тяжёлого HTTP каждые 90 с.
                    // L1 = один SOCKS5 CONNECT через локальный вход (миллисекунды, без TLS и без
                    // лишних радиотайлов), поэтому проверок можно делать больше при меньшем расходе.
                    if (activeTick % 60 == 0 &&
                        !waitingForPhysicalNet &&
                        now - lastProbeAtMs >= 45_000L &&
                        !failoverInFlight.get()
                    ) {
                        if (!hasUnderlyingNetwork()) {
                            enterSilentOfflineWait()
                        } else {
                            launchProbeCheck(reason = "плановый сторож")
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

    /**
     * Тяжёлая проверка через сам туннель (HTML + DoH + GeoIP). Блокирующий JNI-вызов: суммарно
     * до ~15 с в худшем случае, поэтому запускается ТОЛЬКО с отдельной полосы проверок и только
     * когда дешёвая L1-проба уже показала проблему (или пользовательский трафик замер).
     */
    private suspend fun runHeavyHealthCheck(): Pair<Boolean, String> =
        withContext(Dispatchers.IO) {
            val obj = runCatching {
                JSONObject(VeloxNative.checkTunnelHealth(VeloxPrefs.LOCAL_VPN_SOCKS_PORT))
            }.getOrNull() ?: return@withContext false to "json error"

            val alive = obj.optBoolean("alive", obj.optBoolean("ok", false))
            if (!alive) {
                val err = obj.optString("error", "").ifBlank { "нет ответа" }
                // «Спасение» по L1 имеет смысл только для узлов, которым разрешено закрывать
                // посторонние сайты (белые списки). Для обычного узла отказ HTTP = реальная проблема.
                val rescueAllowed = activeIsWhitelist ||
                    VeloxPrefs.loadSettings(this@VeloxVpnService).whitelistMode
                if (!rescueAllowed) return@withContext false to err
                return@withContext detectWhitelistRescue(err)
            }

            val rtt = obj.optInt("rtt_ms", obj.optInt("rttMs", 0))
            val ip = obj.optString("exit_ip", obj.optString("ip", ""))
            val loc = obj.optString("exit_country", obj.optString("loc", ""))
            val colo = obj.optString("exit_colo", obj.optString("colo", ""))
            if (currentState.phase == VpnPhase.CONNECTED) {
                publishState(
                    currentState.copy(
                        rttMs = if (rtt in 1..4000) rtt else currentState.rttMs,
                        exitIp = ip.ifBlank { currentState.exitIp },
                        exitCountry = loc.ifBlank { currentState.exitCountry },
                        exitColo = colo.ifBlank { currentState.exitColo },
                    ),
                    force = true,
                )
            }
            true to "HTTP $rtt мс"
        }

    /**
     * Эталонный HTTP-адрес может быть закрыт самим узлом («белые списки», подписки с фильтрацией
     * SNI). Если ядро при этом принимает SOCKS5 CONNECT — туннель рабочий, переключаться нельзя.
     */
    private suspend fun detectWhitelistRescue(err: String): Pair<Boolean, String> {
        val l1 = withContext(Dispatchers.IO) { l1TunnelAlive() }
        if (!l1) return false to err
        val now = System.currentTimeMillis()
        if (now - l1RescueLogAtMs > 120_000L) {
            l1RescueLogAtMs = now
            VeloxNative.logInfo(
                this,
                "HEAL",
                "Узел ${currentState.activeNodeName} не отвечает на эталонный HTTP-запрос ($err), " +
                    "но L1-туннель жив — оставляем соединение, переключение не требуется"
            )
        }
        return true to "L1"
    }

    /**
     * Единая точка проверок живости. Работает на отдельной корутине, никогда не блокирует
     * 1-секундный монитор; параллельные вызовы схлопываются (single-flight).
     *
     * @param forceHeavy принудительно использовать тяжёлую HTTP-проверку (детектор замирания)
     */
    private fun launchProbeCheck(
        reason: String,
        forceHeavy: Boolean = false,
        allowPromote: Boolean = true,
        minFailures: Int = 3,
    ) {
        if (!probeBusy.compareAndSet(false, true)) return
        val probeSeq = sessionSeq.get()
        scope.launch {
            try {
                if (!hasUnderlyingNetwork()) {
                    probeFailures = 0
                    return@launch
                }
                lastProbeAtMs = System.currentTimeMillis()

                // Уровень 1 — дешёвая L1-проба SOCKS5 CONNECT (миллисекунды, без TLS).
                // Если ядро не принимает CONNECT, туннель мёртв — тяжёлый HTTP-замер ничего
                // не добавит (он идёт через тот же вход), поэтому экономим до 15 с.
                val l1 = withContext(Dispatchers.IO) { l1TunnelAlive() }
                var alive = l1
                var detail = if (l1) "L1 OK" else "L1 нет ответа"

                // Уровень 2 — тяжёлый HTTP-замер: только если L1 жив, но пользовательский трафик
                // реально замер (узел «принимает», но не пропускает).
                if (l1 && forceHeavy) {
                    val heavy = runHeavyHealthCheck()
                    alive = heavy.first
                    detail = "L1 OK · ${heavy.second}"
                }

                if (alive) {
                    probeFailures = 0
                } else {
                    probeFailures++
                    VeloxNative.logWarn(
                        this@VeloxVpnService,
                        "HEAL",
                        "Проверка «$reason» не прошла ($detail), подряд: $probeFailures/$minFailures"
                    )
                    // v1.7.2: результат «старой» сессии не должен управлять новой (гонка при
                    // переподключении/смене страны) — сверяем поколение сессии перед действием.
                    if (allowPromote && probeFailures >= minFailures &&
                        sessionSeq.get() == probeSeq &&
                        currentState.phase == VpnPhase.CONNECTED &&
                        VeloxPrefs.loadSettings(this@VeloxVpnService).autoHeal
                    ) {
                        probeFailures = 0
                        promoteHotStandbySeamlessly(
                            reason = "узел не отвечает ($reason)",
                            probeDriven = true,
                        )
                    }
                }
            } finally {
                probeBusy.set(false)
            }
        }
    }

    private suspend fun verifyTunnelOrPromoteStandby(reason: String) {
        if (!hasUnderlyingNetwork()) {
            enterSilentOfflineWait()
            return
        }
        launchProbeCheck(reason = reason)
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
                scope.launch { promoteHotStandbySeamlessly(reason = "сбой сессии: ${err.take(60)}") }
            } else {
                shutdownTunnel(userInitiated = false, message = "Ошибка туннеля: ${err.take(90)}")
            }
        }
    }

    override fun onXrayNetworkRebind(result: XrayNetworkRebindResult) {
        VeloxNative.logInfo(
            this,
            "NET",
            "Мгновенный ребинд сокетов (QUIC/WG) при смене сети (gen=${result.sessionGeneration})"
        )
    }

    override fun onXrayNetworkChangeError(error: Exception) {
        VeloxNative.logWarn(this, "NET", "Ошибка смены сети Xray: ${VpnBatchProber.formatThrowable(error)}")
    }

    /**
     * Single-pass post-connect browser HTML + bare-IPv4 DoH + GeoIP check over authenticated
     * `127.0.0.1:10808`. If the server blocks general websites, seamlessly promotes `vpn_1`!
     */
    private suspend fun verifyRealAndroidBrowserTunPath() {
        runCatching {
            val cm = getSystemService(ConnectivityManager::class.java) ?: return@runCatching
            @Suppress("DEPRECATION")
            val vpnNet = cm.allNetworks.firstOrNull { net ->
                cm.getNetworkCapabilities(net)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
            }
            if (vpnNet != null) {
                val lp = cm.getLinkProperties(vpnNet)
                if (lp != null) {
                    val dnsList = lp.dnsServers.joinToString(",") { it.hostAddress ?: "?" }
                    val mtuVal = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) lp.mtu else 1360
                    val pDnsHost = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                        lp.privateDnsServerName.orEmpty()
                    } else ""
                    if (pDnsHost.isNotBlank()) {
                        VeloxNative.logInfo(this, "DNS", "Частный DNS Android ($pDnsHost) через IPv4 VPN · MTU=$mtuVal")
                    } else {
                        VeloxNative.logOk(this, "DNS", "IPv4 TUN DNS [$dnsList] FakeIP+DoH · MTU=$mtuVal")
                    }
                }
            }
        }

        val isOpera = currentState.activeProtocol.contains("Opera", ignoreCase = true)

        // v1.7.1: узел «Белых списков РФ» по определению не открывает example.com/wikipedia/1.1.1.1 —
        // проверяем только L1-живость. Иначе каждый коннект к WL-узлу вызывал бы ложное
        // «сайты недоступны» и мгновенный переход (для пользователя — обрыв).
        if (activeIsWhitelist) {
            val l1 = withContext(Dispatchers.IO) { l1TunnelAlive() }
            if (l1) {
                val curId = currentState.activeNodeId
                if (curId.isNotBlank()) runCatching { VeloxNative.recordNodeSuccess(curId, currentState.rttMs) }
                VeloxNative.logOk(
                    this,
                    "WEB",
                    "Узел «Белые списки»: L1-туннель живой — эталонные сайты у таких узлов закрыты по дизайну, соединение оставляем"
                )
            } else {
                VeloxNative.logWarn(
                    this,
                    "WEB",
                    "Узел «Белые списки» не отвечает даже на L1 — переключение на резерв"
                )
                promoteHotStandbySeamlessly(reason = "WL-узел не отвечает (L1)", probeDriven = true)
            }
            return
        }

        val res = runCatching {
            JSONObject(VeloxNative.verifyTunnelWeb(VeloxPrefs.LOCAL_VPN_SOCKS_PORT, isOpera))
        }.getOrDefault(JSONObject())

        val host = res.optString("host", "example.com")
        val webCode = res.optInt("webCode", -1)
        val dohCode = res.optInt("dohCode", -1)
        val rtt = res.optInt("rttMs", 0)
        val loc = res.optString("exitCountry", "").ifBlank { currentState.exitCountry }
        val colo = res.optString("exitColo", "").ifBlank { currentState.exitColo }
        val ip = res.optString("exitIp", "").ifBlank { currentState.exitIp }
        val ruExit = res.optBoolean("ruExit", false)
        // Браузерный HTML-ответ — главный критерий; DoH-плечо (1.1.1.1) лишь вспомогательное.
        val ok = res.optBoolean("ok", false) ||
            (webCode in 200..399 && !ruExit)

        if (ok) {
            VeloxNative.logOk(
                this,
                "WEB",
                "Веб + DoH ОК: $host HTTP $webCode + DoH HTTP $dohCode (${rtt} мс, $ip $loc)"
            )
            // Reward rock-solid nodes: bumps stability streak & smoothing RTT (reduces flapping)
            val curId = currentState.activeNodeId
            if (curId.isNotBlank()) {
                runCatching { VeloxNative.recordNodeSuccess(curId, rtt) }
            }
            if (currentState.phase == VpnPhase.CONNECTED) {
                publishState(
                    currentState.copy(
                        rttMs = if (rtt in 1..4000) rtt else currentState.rttMs,
                        exitCountry = loc,
                        exitColo = colo,
                        exitIp = ip,
                    ),
                    force = true,
                )
            }
        } else if (hasUnderlyingNetwork() && VeloxPrefs.loadSettings(this).autoHeal) {
            // v1.7.1: один неудачный замер — ещё не повод рвать соединение. Сначала проверяем,
            // жив ли туннель на L1, затем один контрольный замер через 6 с. Переключаем только при
            // повторном подтверждении (и только вне окна удержания стабильности).
            VeloxNative.logWarn(
                this,
                "WEB",
                "Сайты не открылись ($host=$webCode, DoH=$dohCode) — контрольная проверка через 6 с…"
            )
            if (ruExit) {
                promoteHotStandbySeamlessly(reason = "выход в РФ (RU)", probeDriven = true)
                return
            }
            val l1 = withContext(Dispatchers.IO) { l1TunnelAlive() }
            if (l1) {
                delay(6000L)
                if (currentState.phase != VpnPhase.CONNECTED) return
                val retry = runCatching {
                    JSONObject(VeloxNative.verifyTunnelWeb(VeloxPrefs.LOCAL_VPN_SOCKS_PORT, isOpera))
                }.getOrDefault(JSONObject())
                val retryWeb = retry.optInt("webCode", -1)
                val retryOk = retry.optBoolean("ok", false) ||
                    (retryWeb in 200..399 && !retry.optBoolean("ruExit", false))
                if (retryOk) {
                    val curId = currentState.activeNodeId
                    val r2 = retry.optInt("rttMs", 0)
                    if (curId.isNotBlank()) runCatching { VeloxNative.recordNodeSuccess(curId, r2) }
                    VeloxNative.logOk(
                        this,
                        "WEB",
                        "Повторная проверка успешна ($host HTTP $retryWeb) — узел стабилен, соединение сохранено"
                    )
                    return
                }
                VeloxNative.logWarn(
                    this,
                    "WEB",
                    "Узел устойчиво ограничивает сайты ($host HTTP $retryWeb) — бесшовный переход на резерв"
                )
                promoteHotStandbySeamlessly(reason = "сайты недоступны ($retryWeb/$dohCode)", probeDriven = true)
            } else {
                VeloxNative.logWarn(this, "WEB", "L1-туннель не отвечает — бесшовный переход на резерв")
                promoteHotStandbySeamlessly(reason = "сайты недоступны + L1 молчит", probeDriven = true)
            }
        }
    }

    override fun networkChangeRebindEnabled(): Boolean = true

    override fun buildTunnel(): Builder {
        val settings = activeTunSettings
        // Pure IPv4 `/30` TUN (`10.7.0.1/30` + `0.0.0.0/0`), NO IPv6 address/route, NO `allowFamily`:
        // Android `netd` installs leak-proof `ip -6 rule unreachable` (instant `ENETUNREACH`),
        // eliminating Happy Eyeballs stalls across Chrome/Yandex/Brave/Firefox/Discord; `198.18.0.1`
        // is sole DNS (FakeIP + encrypted DoH inside tunnel) with MTU 1360.
        val builder = Builder()
            .setSession("VeloxVPN")
            .addAddress("10.7.0.1", 30)
            .addRoute("0.0.0.0", 0)
            .setBlocking(false)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            builder.setMetered(false)
        }

        runCatching { builder.addDisallowedApplication(packageName) }

        for (pkg in settings.excludedPackages) {
            if (pkg.isNotBlank() && pkg != packageName) {
                runCatching { builder.addDisallowedApplication(pkg) }
            }
        }

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

    private fun buildTunJson(settings: AppSettings, idlePowerSave: Boolean): String {
        return VeloxNative.buildTunConfig(
            targetRegion = settings.region,
            pinnedNodeId = settings.pinnedNodeId,
            whitelistMode = settings.whitelistMode,
            bypassRu = settings.bypassRu,
            fragmentTls = settings.fragmentTls,
            adblock = settings.adblockYoutube,
            localSocksPort = VeloxPrefs.LOCAL_VPN_SOCKS_PORT,
            dualChannel = settings.dualChannel,
            idlePowerSave = idlePowerSave,
            socksUser = sessionSocksUser,
            socksPass = sessionSocksPass,
            customRulesJson = settings.customRulesJson(),
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
        // v1.7.2: одинаковые шаги прогресса не переписывают диск/шторку чаще 2 раз в секунду.
        val emitNow = System.currentTimeMillis()
        val label = "$stageIdx|$clampedPct|$statusLine"
        if (label == lastProgressLabel && emitNow - lastProgressEmitMs < 500L) return
        lastProgressLabel = label
        lastProgressEmitMs = emitNow
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
        publishState(st, force = true)
        val now = System.currentTimeMillis()
        if (isScreenInteractive && now - lastNotifUpdateMs >= 1000L) {
            lastNotifUpdateMs = now
            updateForegroundText(
                title = "VeloxVPN · $statusLine",
                subtitle = "Осталось ${formatEtaRu(etaSec)} · ${detailLine.ifBlank { "$clampedPct%" }}",
                progressPct = clampedPct,
            )
        }
    }

    /**
     * v1.7.2: раньше любой путь «нужно обновить пул» начинался с `safeStopCoreAndTun()` — то есть
     * на время подбора серверов (десятки секунд) у пользователя был МЁРТВЫЙ интернет. Теперь при
     * живом туннеле ядро НЕ останавливается: подбор идёт параллельно (наши сокеты вне TUN), а
     * замена происходит атомарно в `startXrayTunnel` уже после проверки нового узла.
     */
    private fun prepareForRefresh() {
        if (currentState.phase == VpnPhase.CONNECTED) {
            VeloxNative.logInfo(
                this,
                "SWAP",
                "Обновление пула без разрыва: текущий туннель остаётся активным до атомарной замены"
            )
        } else {
            safeStopCoreAndTun()
        }
    }

    private fun safeStopCoreAndTun() {
        pendingStartResult.getAndSet(null)?.cancel()
        runCatching { stopXrayTunnel() }
    }

    private fun shutdownTunnel(userInitiated: Boolean, message: String) {
        waitingForPhysicalNet = false
        sessionSeq.incrementAndGet()
        networkChangeJob?.cancel()
        monitorJob?.cancel()
        connectJob?.cancel()
        poolRefreshJob?.cancel()
        safeStopCoreAndTun()
        publishState(
            VpnRuntimeState(
                phase = if (userInitiated) VpnPhase.DISCONNECTED else VpnPhase.ERROR,
                statusLine = message,
            ),
            force = true,
        )
        stopForegroundCompat()
        stopSelf()
    }

    /** Strict physical upstream network check — never tricked by our own `tun0`! */
    private fun hasUnderlyingNetwork(): Boolean = VeloxNative.hasPhysicalInternet(this)

    /**
     * Delta-gated runtime state publisher:
     * - Zero disk writes & zero broadcasts when idle (bytes unchanged)!
     * - Calls `TileService.requestListeningState` ONLY when tile text actually changed!
     */
    private fun publishState(state: VpnRuntimeState, force: Boolean = false) {
        val now = System.currentTimeMillis()
        val prev = currentState
        val totalBytes = state.uplinkBytes + state.downlinkBytes
        val bytesDelta = abs(totalBytes - lastDiskBytes)
        val structuralChange = force ||
            state.phase != prev.phase ||
            state.activeNodeId != prev.activeNodeId ||
            state.standbyNodeId != prev.standbyNodeId ||
            state.dualChannelActive != prev.dualChannelActive ||
            state.statusLine != prev.statusLine ||
            abs(state.rttMs - prev.rttMs) >= 8

        val stamped = state.copy(updatedAtMs = now)
        currentState = stamped

        // v1.7.2: UI получает состояние в самом broadcast, поэтому диск нужен лишь как снимок
        // «на случай смерти процесса» — пишем реже (меньше износ flash и лишних wakeup'ов).
        val shouldWrite = structuralChange ||
            (bytesDelta >= 16_384L && now - lastDiskPublishMs >= 3000L) ||
            (state.activeConnections != prev.activeConnections && now - lastDiskPublishMs >= 6000L)

        if (shouldWrite) {
            lastDiskPublishMs = now
            lastDiskBytes = totalBytes
            val shouldBroadcast = isScreenInteractive || structuralChange
            VeloxPrefs.publishRuntime(this, stamped, broadcast = shouldBroadcast)
        }

        // Delta-gate Quick Settings Tile IPC (saves ~30 system binds/min!)
        val tileSig = "${state.phase}|${state.exitCountry}|${state.dualChannelActive}|${state.rttMs / 15}|${state.progressPercent / 10}"
        if (tileSig != lastTileSignature && (isScreenInteractive || state.phase != prev.phase)) {
            lastTileSignature = tileSig
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
                ComponentName(this, VeloxTileService::class.java)
            )
        }
    }

    private fun registerScreenWatcher() {
        if (screenReceiverRegistered) return
        runCatching {
            val f = IntentFilter().apply {
                addAction(Intent.ACTION_SCREEN_OFF)
                addAction(Intent.ACTION_SCREEN_ON)
                addAction(Intent.ACTION_USER_PRESENT)
            }
            ContextCompat.registerReceiver(this, screenStateReceiver, f, ContextCompat.RECEIVER_NOT_EXPORTED)
            screenReceiverRegistered = true
        }
    }

    private fun unregisterScreenWatcher() {
        if (!screenReceiverRegistered) return
        runCatching { unregisterReceiver(screenStateReceiver) }
        screenReceiverRegistered = false
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
            getSystemService(ConnectivityManager::class.java)?.unregisterNetworkCallback(networkCallback)
        }
        netCallbackRegistered = false
    }

    // -------------------------------------------------------------------------
    // Delta-gated Foreground Notifications (Android 7.0 – 16, incl. Android 12)
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
                startForeground(NOTIF_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
            } else {
                startForeground(NOTIF_ID, notification)
            }
        }
    }

    private fun stopForegroundCompat() {
        runCatching { stopForeground(STOP_FOREGROUND_REMOVE) }
    }

    private fun updateForegroundText(title: String, subtitle: String, progressPct: Int = -1) {
        val nm = getSystemService(NotificationManager::class.java) ?: return
        runCatching {
            nm.notify(NOTIF_ID, buildStatusNotification(title, subtitle, ongoing = true, progressPct = progressPct))
        }
    }

    private fun updateConnectedNotification(state: VpnRuntimeState, force: Boolean) {
        if (!isScreenInteractive && !force) return
        val now = System.currentTimeMillis()
        val total = state.uplinkBytes + state.downlinkBytes
        val nodeKey = "${state.activeNodeId}|${state.standbyNodeId}|${state.dualChannelActive}"
        if (!force && nodeKey == lastNotifNodeKey &&
            (now - lastNotifUpdateMs < 15_000L || abs(total - lastNotifBytes) < 65_536L)
        ) {
            return
        }
        lastNotifUpdateMs = now
        lastNotifBytes = total
        lastNotifNodeKey = nodeKey

        val nm = getSystemService(NotificationManager::class.java) ?: return
        val flag = countryFlag(state.exitCountry)
        val rttPart = if (state.rttMs > 0) " · ${state.rttMs} мс" else ""
        val dualTag = if (state.dualChannelActive) " · 2×" else ""
        val title = "$flag ${state.activeNodeName.ifBlank { "Подключено" }}$rttPart$dualTag"
        val sub = buildString {
            append("↓ ${formatBytesRu(state.downlinkBytes)}  ↑ ${formatBytesRu(state.uplinkBytes)}")
            if (state.dualChannelActive && state.standbyNodeName.isNotBlank()) {
                append(" · Резерв: ${countryFlag(state.standbyCountry)} ${state.standbyNodeName.take(18)}")
            } else {
                append(" · ${state.activeProtocol}")
            }
        }
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

    private fun randomHex(byteCount: Int): String {
        val buf = ByteArray(byteCount)
        SecureRandom().nextBytes(buf)
        return buildString(byteCount * 2) {
            for (b in buf) append(String.format("%02x", b.toInt() and 0xff))
        }
    }

    companion object {
        const val ACTION_CONNECT = "app.velox.vpn.action.CONNECT"
        const val ACTION_DISCONNECT = "app.velox.vpn.action.DISCONNECT"
        const val ACTION_ROTATE = "app.velox.vpn.action.ROTATE"
        const val ACTION_HOT_RELOAD = "app.velox.vpn.action.HOT_RELOAD"
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
                app.startService(Intent(app, VeloxVpnService::class.java).setAction(ACTION_DISCONNECT))
            }
        }

        fun requestRotate(context: Context) {
            val app = context.applicationContext
            ContextCompat.startForegroundService(
                app,
                Intent(app, VeloxVpnService::class.java).setAction(ACTION_ROTATE)
            )
        }

        fun requestHotReload(context: Context) {
            val app = context.applicationContext
            runCatching {
                app.startService(Intent(app, VeloxVpnService::class.java).setAction(ACTION_HOT_RELOAD))
            }
        }

        fun requestRefreshPool(context: Context) {
            val app = context.applicationContext
            runCatching {
                app.startService(Intent(app, VeloxVpnService::class.java).setAction(ACTION_REFRESH_POOL))
            }
        }
    }
}
