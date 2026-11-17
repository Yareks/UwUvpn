package app.velox.vpn.ui

import android.Manifest
import android.annotation.SuppressLint
import android.content.BroadcastReceiver
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.graphics.Color
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.PowerManager
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.material3.SnackbarHostState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import app.velox.vpn.core.AppSettings
import app.velox.vpn.core.EngineSnapshot
import app.velox.vpn.core.InstalledAppInfo
import app.velox.vpn.core.LiveProgressUpdate
import app.velox.vpn.core.ServicesCheckResult
import app.velox.vpn.core.TgBridgeStatus
import app.velox.vpn.core.VeloxNative
import app.velox.vpn.core.VeloxPrefs
import app.velox.vpn.core.VpnBatchProber
import app.velox.vpn.core.VpnNode
import app.velox.vpn.core.VpnPhase
import app.velox.vpn.core.VpnRuntimeState
import app.velox.vpn.core.regionTitleRu
import app.velox.vpn.service.TgBridgeService
import app.velox.vpn.service.VeloxVpnService
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject

class MainActivity : ComponentActivity() {

    private var settingsState by mutableStateOf(AppSettings())
    private var runtimeState by mutableStateOf(VpnRuntimeState())
    private var engineSnapshot by mutableStateOf(EngineSnapshot())
    private var tgStatusState by mutableStateOf(TgBridgeStatus())
    private var bgSyncJob: Job? = null
    @Volatile
    private var abortBgSync: Boolean = false
    private var isRefreshingVpn by mutableStateOf(false)
    private var vpnRefreshDelegated = false
    private var manualRefreshProgress by mutableStateOf<LiveProgressUpdate?>(null)
    private var isRefreshingTg by mutableStateOf(false)
    private var isBusyWarp by mutableStateOf(false)
    private var isBusyImport by mutableStateOf(false)
    private var batteryIgnored by mutableStateOf(true)
    private var servicesResult by mutableStateOf(ServicesCheckResult())
    private var isCheckingServices by mutableStateOf(false)
    private var pendingForceRefresh = false
    private var lastHandledDeepLink: String = ""

    private val snackbarHost = SnackbarHostState()
    private var receiverRegistered = false

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        val force = pendingForceRefresh
        pendingForceRefresh = false
        if (result.resultCode == RESULT_OK || VpnService.prepare(this) == null) {
            requestNotifPermissionIfNeeded()
            VeloxVpnService.startConnect(this, forceRefresh = force)
        } else {
            VeloxNative.logWarn(this, "VPN", "Пользователь отклонил системное разрешение VPN")
            showSnack("Разрешение VPN отклонено — без него туннель не запустится")
        }
    }

    private val notifPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { /* Notification permission optional; VPN tunnel works either way */ }

    private val stateReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            when (intent?.action) {
                VeloxPrefs.ACTION_VPN_RUNTIME -> {
                    // v1.7.2: состояние приезжает внутри broadcast — без чтения файла с диска
                    // на главном потоке (раньше это был I/O на каждый тик при активной загрузке).
                    val payload = intent.getStringExtra(VeloxPrefs.EXTRA_RUNTIME_JSON)
                    val next = if (!payload.isNullOrBlank()) {
                        runCatching { VpnRuntimeState.fromJson(JSONObject(payload)) }
                            .getOrElse { VeloxPrefs.loadRuntime(this@MainActivity) }
                    } else {
                        VeloxPrefs.loadRuntime(this@MainActivity)
                    }
                    runtimeState = next
                    if (!next.isActiveOrBusy && vpnRefreshDelegated) {
                        vpnRefreshDelegated = false
                        isRefreshingVpn = false
                        manualRefreshProgress = null
                    }
                }
                VeloxPrefs.ACTION_ENGINE_UPDATED -> {
                    val msg = intent.getStringExtra(VeloxPrefs.EXTRA_TOAST_MESSAGE)
                    vpnRefreshDelegated = false
                    isRefreshingVpn = false
                    manualRefreshProgress = null
                    refreshEngineSnapshotAsync(reloadDisk = true)
                    settingsState = VeloxPrefs.loadSettings(this@MainActivity)
                    if (!msg.isNullOrBlank()) showSnack(msg)
                }
                VeloxPrefs.ACTION_TG_BRIDGE_CHANGED -> {
                    refreshTgStatusAsync()
                }
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge(
            statusBarStyle = SystemBarStyle.dark(Color.TRANSPARENT),
            navigationBarStyle = SystemBarStyle.dark(0xFF101722.toInt()),
        )
        super.onCreate(savedInstanceState)

        settingsState = VeloxPrefs.loadSettings(this)
        runtimeState = VeloxPrefs.loadRuntime(this)
        updateBatteryFlag()
        registerBusReceiver()
        refreshEngineSnapshotAsync(reloadDisk = false, syncHwid = true)

        val consumedDeepLink = handleIncomingDeepLink(intent)
        if (!consumedDeepLink) {
            triggerStartupSmartDeltaSync()
        }

        setContent {
            VeloxTheme {
                VeloxRootScreen(
                    settings = settingsState,
                    runtime = runtimeState,
                    snapshot = engineSnapshot,
                    tgStatus = tgStatusState,
                    isRefreshingVpn = isRefreshingVpn,
                    manualProgress = manualRefreshProgress,
                    isRefreshingTg = isRefreshingTg,
                    isBusyWarp = isBusyWarp,
                    isBusyImport = isBusyImport,
                    batteryIgnored = batteryIgnored,
                    servicesResult = servicesResult,
                    isCheckingServices = isCheckingServices,
                    onCheckServices = ::handleCheckServices,
                    snackbarHostState = snackbarHost,
                    onToggleVpn = ::handleToggleVpn,
                    onRetryFreshVpn = { startVpnWithConsent(forceRefresh = true) },
                    onSelectRegion = ::handleSelectRegion,
                    onSelectNode = ::handleSelectNode,
                    onRotateNode = { VeloxVpnService.requestRotate(this) },
                    onRefreshVpn = ::handleRefreshVpn,
                    onDiscoverMoreVpn = ::handleDiscoverMoreVpn,
                    onUpdateSettings = ::handleUpdateSettings,
                    onRefreshTg = ::handleRefreshTgProxies,
                    onTgTabOpened = ::maybeLazySyncTgProxies,
                    onToggleTgBridge = ::handleToggleTgBridge,
                    onOpenTgLink = ::openTelegramProxyLink,
                    onOpenExternalUrl = ::openExternalUrlSafe,
                    onCopyText = ::copyToClipboard,
                    onShareText = ::sharePlainText,
                    onImportItem = ::handleImportCustom,
                    onReadClipboard = ::readClipboardText,
                    onToggleSource = ::handleToggleSource,
                    onSyncSource = ::handleSyncSource,
                    onRemoveSource = ::handleRemoveSource,
                    onRegenerateWarp = ::handleRegenerateWarp,
                    onRequestIgnoreBattery = ::requestIgnoreBatteryOpt,
                    onLoadInstalledApps = ::loadInstalledAppsAsync,
                    onLoadDiagLogs = ::loadDiagLogsBlocking,
                    onClearDiagLogs = ::handleClearDiagLogs,
                    onFormatDiagExport = ::formatFullDiagExport,
                )
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleIncomingDeepLink(intent)
    }

    override fun onResume() {
        super.onResume()
        settingsState = VeloxPrefs.loadSettings(this)
        val rt = VeloxPrefs.loadRuntime(this)
        runtimeState = rt
        // Auto-reconcile spinner if a background refresh completed while Activity was paused
        if (isRefreshingVpn && !VpnBatchProber.isRunning() && !rt.isActiveOrBusy) {
            vpnRefreshDelegated = false
            isRefreshingVpn = false
            manualRefreshProgress = null
        }
        updateBatteryFlag()
        refreshEngineSnapshotAsync(reloadDisk = true)
    }

    override fun onDestroy() {
        if (receiverRegistered) {
            runCatching { unregisterReceiver(stateReceiver) }
            receiverRegistered = false
        }
        super.onDestroy()
    }

    /**
     * 1-tap Deep-Link import for `happ://crypt`..`crypt5`, `incy://crypt1/`, `happ://add/`,
     * `v2raytun://`, `v2rayng://`, `hiddify://`, `streisand://`, `clash://`, `flclash://`,
     * `sing-box://`, `ssconf://`, `velox://`, and direct proxy URIs (`vless://`, `hy2://`, etc.).
     */
    private fun handleIncomingDeepLink(intent: Intent?): Boolean {
        if (intent?.action != Intent.ACTION_VIEW) return false
        val rawUri = intent.dataString?.trim().orEmpty()
        if (rawUri.isBlank() || rawUri == lastHandledDeepLink) return false
        lastHandledDeepLink = rawUri
        intent.data = null
        handleImportCustom(rawUri, "auto")
        return true
    }

    private fun registerBusReceiver() {
        if (receiverRegistered) return
        val filter = IntentFilter().apply {
            addAction(VeloxPrefs.ACTION_VPN_RUNTIME)
            addAction(VeloxPrefs.ACTION_ENGINE_UPDATED)
            addAction(VeloxPrefs.ACTION_TG_BRIDGE_CHANGED)
        }
        ContextCompat.registerReceiver(
            this,
            stateReceiver,
            filter,
            ContextCompat.RECEIVER_NOT_EXPORTED,
        )
        receiverRegistered = true
    }

    private fun cancelBgSyncForUserAction() {
        abortBgSync = true
        bgSyncJob?.cancel()
        bgSyncJob = null
    }

    /** Emit progress cleanly to Compose state (throttled to <=4 Hz to avoid coroutine allocation churn). */
    private fun makeUiProgressCallback(): (LiveProgressUpdate) -> Unit {
        var lastPostMs = 0L
        var lastPct = -1
        return { upd ->
            val now = System.currentTimeMillis()
            if (now - lastPostMs >= 260L || upd.percent != lastPct) {
                lastPostMs = now
                lastPct = upd.percent
                runOnUiThread {
                    if (!isDestroyed) manualRefreshProgress = upd
                }
            }
        }
    }

    /**
     * Battery-smart First-Launch Preload & Incremental Delta Sync (v1.6.0):
     * - Respects verified cached VPN pool for 45 min (0 s instant launch when fresh!).
     * - Defers heavy Telegram proxy sweeps to the Telegram tab unless pool is empty or >3 h old.
     * - Incremental: preserves working servers, prunes dead ones, tops up new ones; yields immediately on Connect!
     */
    private fun triggerStartupSmartDeltaSync() {
        bgSyncJob?.cancel()
        abortBgSync = false
        bgSyncJob = lifecycleScope.launch(Dispatchers.IO) {
            delay(550L)
            if (abortBgSync || runtimeState.isActiveOrBusy) return@launch
            if (!VeloxNative.hasPhysicalInternet(this@MainActivity)) return@launch

            val cur = settingsState
            val snap0 = loadSnapshotBlocking(cur.region, reloadDisk = false)
            withContext(Dispatchers.Main) { engineSnapshot = snap0 }

            val nowSec = System.currentTimeMillis() / 1000L
            val vpnAge = nowSec - snap0.lastVpnRefreshUnix
            val needVpn = snap0.deviceVerifiedCount < 4 || vpnAge > 2700L

            if (needVpn && !isRefreshingVpn && !abortBgSync && !runtimeState.isActiveOrBusy) {
                withContext(Dispatchers.Main) {
                    isRefreshingVpn = true
                    manualRefreshProgress = LiveProgressUpdate(
                        stageIndex = 1,
                        stageTotal = 5,
                        percent = 8,
                        etaSeconds = if (snap0.deviceVerifiedCount == 0) 11 else 5,
                        statusLine = if (snap0.deviceVerifiedCount == 0) {
                            "Автоподготовка основного и резервного серверов…"
                        } else {
                            "Умная сверка серверов…"
                        },
                        detailLine = "Рабочие сохраняем, нерабочие заменяем новыми",
                    )
                }
                val progressCb = makeUiProgressCallback()
                val res = runCatching {
                    VpnBatchProber.smartDeltaSyncBlocking(
                        context = this@MainActivity,
                        settings = settingsState,
                        shouldAbort = { abortBgSync || runtimeState.isActiveOrBusy },
                        onProgress = { upd -> if (!abortBgSync) progressCb(upd) },
                    )
                }.getOrNull()
                VeloxNative.trimMemoryIfLoaded()
                val snap = loadSnapshotBlocking(settingsState.region, reloadDisk = false)
                withContext(Dispatchers.Main) {
                    engineSnapshot = snap
                    if (!vpnRefreshDelegated) {
                        isRefreshingVpn = false
                        manualRefreshProgress = null
                    }
                    if (!abortBgSync && res != null && res.ok &&
                        (res.newlyVerified > 0 || res.removedDead > 0)
                    ) {
                        val parts = buildList {
                            if (res.newlyVerified > 0) add("+${res.newlyVerified} новых")
                            if (res.keptAlive > 0) add("${res.keptAlive} в строю")
                            if (res.removedDead > 0) add("-${res.removedDead} убрано")
                        }
                        showSnack("Пул 2× готов (${parts.joinToString(", ")}) — мгновенный старт!")
                    }
                }
            }

            // Only refresh Telegram proxies in background on startup if pool is genuinely empty/stale (>3h)
            val tgAge = (System.currentTimeMillis() / 1000L) - snap0.lastTgRefreshUnix
            if (!abortBgSync && !isRefreshingTg && (snap0.tgProxies.size < 4 || tgAge > 10_800L)) {
                maybeLazySyncTgProxies()
            }
        }
    }

    /** Lazy Telegram proxy refresh triggered when user opens the Telegram tab and cache is >45m old. */
    private fun maybeLazySyncTgProxies() {
        if (isRefreshingTg) return
        val nowSec = System.currentTimeMillis() / 1000L
        val tgAge = nowSec - engineSnapshot.lastTgRefreshUnix
        if (engineSnapshot.tgProxies.size >= 8 && tgAge < 2700L) return
        if (!VeloxNative.hasPhysicalInternet(this)) return

        lifecycleScope.launch(Dispatchers.IO) {
            if (isRefreshingTg) return@launch
            withContext(Dispatchers.Main) { isRefreshingTg = true }
            try {
                VeloxNative.ensureInitialized(this@MainActivity)
                val maxMs = settingsState.tgMaxRttMs
                val activeSocks = VeloxPrefs.resolveActiveLocalSocksPort(this@MainActivity)
                VeloxNative.refreshTgProxies(maxMs, activeSocks)
                VeloxNative.trimMemoryIfLoaded()
                val snap = loadSnapshotBlocking(settingsState.region, reloadDisk = false)
                val st = TgBridgeStatus.fromJsonStr(VeloxNative.getTgStatus())
                withContext(Dispatchers.Main) {
                    engineSnapshot = snap
                    tgStatusState = st
                }
            } catch (_: Throwable) {
            } finally {
                withContext(Dispatchers.Main) { isRefreshingTg = false }
            }
        }
    }

    private fun handleToggleVpn() {
        cancelBgSyncForUserAction()
        if (runtimeState.isActiveOrBusy) {
            VeloxVpnService.requestStop(this)
        } else {
            startVpnWithConsent(forceRefresh = false)
        }
    }

    private fun startVpnWithConsent(forceRefresh: Boolean = false) {
        cancelBgSyncForUserAction()
        if (!vpnRefreshDelegated) {
            isRefreshingVpn = false
            manualRefreshProgress = null
        }
        val prep = runCatching { VpnService.prepare(this) }.getOrNull()
        if (prep != null) {
            pendingForceRefresh = forceRefresh
            vpnPermissionLauncher.launch(prep)
        } else {
            requestNotifPermissionIfNeeded()
            VeloxVpnService.startConnect(this, forceRefresh = forceRefresh)
        }
    }

    private fun handleSelectRegion(newRegion: String) {
        if (settingsState.region.equals(newRegion, ignoreCase = true) && settingsState.pinnedNodeId.isEmpty()) {
            return
        }
        val wasWlRegion = settingsState.region.equals("WL", ignoreCase = true)
        val isWlRegion = newRegion.equals("WL", ignoreCase = true)
        settingsState = VeloxPrefs.updateSettings(this) {
            it.copy(
                region = newRegion,
                pinnedNodeId = "",
                whitelistMode = when {
                    isWlRegion -> true
                    wasWlRegion -> false
                    else -> it.whitelistMode
                }
            )
        }
        refreshEngineSnapshotAsync(reloadDisk = false)
        if (runtimeState.isActiveOrBusy) {
            if (runtimeState.phase == VpnPhase.CONNECTED) {
                // v1.7.2: смена страны при живом туннеле — бесшовный горячий свап (0 разрыва).
                // Если для новой страны ещё нет проверенных узлов, сервис сам дозаполнит пул в фоне
                // и переключится, не убивая текущее соединение.
                VeloxVpnService.requestHotReload(this)
            } else {
                VeloxVpnService.startConnect(this, forceRefresh = false)
            }
        }
    }

    private fun handleSelectNode(node: VpnNode) {
        val unpin = settingsState.pinnedNodeId == node.id
        settingsState = VeloxPrefs.updateSettings(this) {
            it.copy(pinnedNodeId = if (unpin) "" else node.id)
        }
        if (unpin) {
            showSnack("Включён авто-выбор основного и резервного узла")
            if (runtimeState.phase == VpnPhase.CONNECTED) {
                VeloxVpnService.requestHotReload(this)
            }
        } else {
            startVpnWithConsent(forceRefresh = false)
        }
    }

    private fun handleUpdateSettings(
        transform: (AppSettings) -> AppSettings,
        reconnectIfActive: Boolean,
    ) {
        val prev = settingsState
        val next = VeloxPrefs.updateSettings(this, transform)
        settingsState = next

        if (prev.sendHwid != next.sendHwid) {
            lifecycleScope.launch(Dispatchers.IO) {
                VeloxNative.syncHwidConfig(this@MainActivity, next.sendHwid)
                val snap = loadSnapshotBlocking(next.region, reloadDisk = false)
                withContext(Dispatchers.Main) {
                    engineSnapshot = snap
                    showSnack(
                        if (next.sendHwid) "Заголовки Happ X-HWID включены для подписок"
                        else "Передача X-HWID отключена (приватный режим)"
                    )
                }
            }
        }

        if (prev.whitelistMode != next.whitelistMode) {
            refreshEngineSnapshotAsync(reloadDisk = false)
        }

        if (reconnectIfActive && runtimeState.isActiveOrBusy) {
            cancelBgSyncForUserAction()
            if (runtimeState.phase == VpnPhase.CONNECTED && prev.whitelistMode == next.whitelistMode) {
                // Seamless ~40 ms atomic hot-swap — zero drop on YouTube/DualChannel/Split/Fragment toggles!
                VeloxVpnService.requestHotReload(this)
            } else {
                VeloxVpnService.startConnect(this, forceRefresh = false)
            }
        }
    }

    private fun handleRefreshVpn() {
        cancelBgSyncForUserAction()
        if (isRefreshingVpn && vpnRefreshDelegated) return
        isRefreshingVpn = true
        val regLabel = regionTitleRu(settingsState.region)
        manualRefreshProgress = LiveProgressUpdate(
            stageIndex = 1,
            stageTotal = 5,
            percent = 10,
            etaSeconds = 12,
            statusLine = if (settingsState.whitelistMode) {
                "Умное обновление «Белые списки РФ»…"
            } else {
                "Умное обновление серверов $regLabel…"
            },
            detailLine = "Reality · XHTTP · Hysteria2 · Trojan · SS2022 · WG · WARP MASQUE",
        )

        if (runtimeState.isActiveOrBusy) {
            vpnRefreshDelegated = true
            VeloxVpnService.requestRefreshPool(this)
            return
        }

        val progressCb = makeUiProgressCallback()
        lifecycleScope.launch(Dispatchers.IO) {
            var waited = 0
            while (VpnBatchProber.isRunning() && waited < 10) {
                delay(200L)
                waited++
            }
            val curSettings = settingsState
            val res = VpnBatchProber.refreshPoolBlocking(
                context = this@MainActivity,
                settings = curSettings,
                vpnService = null,
                maxBatch = 44,
                onProgress = progressCb,
            )
            VeloxNative.trimMemoryIfLoaded()
            val snap = loadSnapshotBlocking(curSettings.region, reloadDisk = false)
            withContext(Dispatchers.Main) {
                engineSnapshot = snap
                isRefreshingVpn = false
                manualRefreshProgress = null
                if (res.ok) {
                    showSnack(
                        "Обновлено: +${res.newlyVerified} свежих · всего ${snap.deviceVerifiedCount} живых (БС-РФ: ${snap.whitelistVerifiedCount})"
                    )
                } else {
                    showSnack(res.error.ifBlank { "Не удалось найти узлы — попробуйте «Авто», «Белые списки РФ» или подписку" })
                }
            }
        }
    }

    private fun handleDiscoverMoreVpn() {
        cancelBgSyncForUserAction()
        if (isRefreshingVpn) return
        if (runtimeState.isActiveOrBusy) {
            isRefreshingVpn = true
            vpnRefreshDelegated = true
            manualRefreshProgress = LiveProgressUpdate(
                stageIndex = 1,
                stageTotal = 3,
                percent = 14,
                etaSeconds = 13,
                statusLine = "Поиск дополнительных серверов в фоне…",
                detailLine = "Без разрыва текущего VPN-туннеля",
            )
            VeloxVpnService.requestRefreshPool(this)
            return
        }
        isRefreshingVpn = true
        manualRefreshProgress = LiveProgressUpdate(
            stageIndex = 1,
            stageTotal = 3,
            percent = 6,
            etaSeconds = 26,
            statusLine = "Мульти-поиск серверов (15 стран + 12 протоколов)…",
            detailLine = "Reality · XHTTP · Hysteria2 · WARP MASQUE · БС-РФ",
        )
        val progressCb = makeUiProgressCallback()
        lifecycleScope.launch(Dispatchers.IO) {
            var waited = 0
            while (VpnBatchProber.isRunning() && waited < 12) {
                delay(200L)
                waited++
            }
            val curSettings = settingsState
            val res = VpnBatchProber.discoverMoreConnectionsBlocking(
                context = this@MainActivity,
                settings = curSettings,
                onProgress = progressCb,
            )
            VeloxNative.trimMemoryIfLoaded()
            val snap = loadSnapshotBlocking(settingsState.region, reloadDisk = false)
            withContext(Dispatchers.Main) {
                engineSnapshot = snap
                isRefreshingVpn = false
                manualRefreshProgress = null
                if (res.ok) {
                    val countries = snap.allVpnNodes.map { it.exitCountry }.filter { it.isNotBlank() }.distinct().size
                    showSnack(
                        "Найдено +${res.newlyVerified} новых · в пуле ${snap.allVpnNodes.size} подключений ($countries стран)!"
                    )
                } else {
                    showSnack(res.error.ifBlank { "Новых серверов не найдено" })
                }
            }
        }
    }

    private fun handleRefreshTgProxies() {
        if (isRefreshingTg) return
        isRefreshingTg = true
        val maxMs = settingsState.tgMaxRttMs

        val poller = lifecycleScope.launch(Dispatchers.IO) {
            while (isActive) {
                val st = TgBridgeStatus.fromJsonStr(VeloxNative.getTgStatus())
                withContext(Dispatchers.Main) { tgStatusState = st }
                delay(320L)
            }
        }

        lifecycleScope.launch(Dispatchers.IO) {
            VeloxNative.ensureInitialized(this@MainActivity)
            VeloxNative.logInfo(this@MainActivity, "TG", "Запуск проверки прокси Telegram (порог ≤${maxMs}мс)")
            val activeSocks = VeloxPrefs.resolveActiveLocalSocksPort(this@MainActivity)
            val raw = runCatching { VeloxNative.refreshTgProxies(maxMs, activeSocks) }.getOrDefault("{}")
            poller.cancel()
            VeloxNative.trimMemoryIfLoaded()
            val rawObj = runCatching { JSONObject(raw) }.getOrNull()
            val count = rawObj?.optInt("count", 0) ?: 0
            val added = rawObj?.optInt("newlyAdded", 0) ?: 0
            val removed = rawObj?.optInt("removedDead", 0) ?: 0
            val snap = loadSnapshotBlocking(settingsState.region, reloadDisk = false)
            val st = TgBridgeStatus.fromJsonStr(VeloxNative.getTgStatus())
            withContext(Dispatchers.Main) {
                engineSnapshot = snap
                tgStatusState = st
                isRefreshingTg = false
                if (count > 0) {
                    val best = snap.tgProxies.firstOrNull()?.rttMs ?: 0
                    val delta = buildString {
                        if (added > 0) append(", +$added новых")
                        if (removed > 0) append(", -$removed убрано")
                    }
                    showSnack("Живых TG-прокси: $count ≤$maxMs мс (лучший $best мс$delta)")
                } else {
                    showSnack("Не найдено прокси ≤$maxMs мс — подключите VPN или включите TG-WS")
                }
            }
        }
    }

    private fun handleToggleTgBridge(enable: Boolean) {
        if (enable) {
            requestNotifPermissionIfNeeded()
            VeloxNative.logInfo(this, "TG", "Запуск локального умного прокси 127.0.0.1:10809 (TG-WS + пул)")
            TgBridgeService.start(this)
            showSnack("Умный прокси запущен — нажмите «Включить в Telegram»")
        } else {
            VeloxNative.logInfo(this, "TG", "Остановка локального прокси Telegram")
            TgBridgeService.stop(this)
            showSnack("Умный прокси Telegram остановлен")
        }
        lifecycleScope.launch {
            delay(400L)
            refreshTgStatusAsync()
        }
    }

    private fun handleImportCustom(raw: String, kindHint: String) {
        if (raw.isBlank() || isBusyImport) return
        cancelBgSyncForUserAction()
        isBusyImport = true
        val lower = raw.trim().lowercase()
        showSnack(
            when {
                lower.startsWith("happ://crypt") || lower.startsWith("incy://crypt") ->
                    "Расшифровываю Happ-подписку и загружаю серверы…"
                lower.startsWith("happ://") || lower.startsWith("v2raytun://") ||
                    lower.startsWith("hiddify://") || lower.startsWith("clash://") ->
                    "Импортирую подписку по быстрой ссылке…"
                else -> "Загружаю и разбираю подписку / ключ…"
            }
        )
        val progressCb = makeUiProgressCallback()
        lifecycleScope.launch(Dispatchers.IO) {
            VeloxNative.reloadFromDisk(this@MainActivity)
            VeloxNative.syncHwidConfig(this@MainActivity, settingsState.sendHwid)
            // Load active authenticated 127.0.0.1:10808 creds if VPN is CONNECTED so blocked panel URLs import seamlessly
            val _activeSocks = VeloxPrefs.resolveActiveLocalSocksPort(this@MainActivity)
            val resRaw = runCatching {
                VeloxNative.addCustomItem(raw, kindHint, settingsState.tgMaxRttMs)
            }.getOrElse { e -> """{"ok":false,"error":"${e.message}"}""" }
            val obj = runCatching { JSONObject(resRaw) }.getOrDefault(JSONObject())
            val ok = obj.optBoolean("ok", false)
            val msg = if (ok) {
                obj.optString("message", "Успешно импортировано")
            } else {
                obj.optString("error", "Ошибка импорта")
            }
            val subName = obj.optString("subName", "")
            val importedCount = obj.optInt("importedCount", 0)
            val needsProbe = ok && obj.optBoolean("needsCustomProbe", false)
            val snap = loadSnapshotBlocking(settingsState.region, reloadDisk = false)
            withContext(Dispatchers.Main) {
                isBusyImport = false
                engineSnapshot = snap
                showSnack(msg)
            }

            if (needsProbe && !runtimeState.isActiveOrBusy) {
                var waited = 0
                while (VpnBatchProber.isRunning() && waited < 12) {
                    delay(250L)
                    waited++
                }
                withContext(Dispatchers.Main) {
                    isRefreshingVpn = true
                    manualRefreshProgress = LiveProgressUpdate(
                        stageIndex = 1,
                        stageTotal = 3,
                        percent = 20,
                        etaSeconds = 5,
                        statusLine = if (subName.isNotBlank()) {
                            "Проверка «$subName» ($importedCount серв.)…"
                        } else {
                            "Проверка импортированных серверов…"
                        },
                        detailLine = "Замер отклика, скорости, YT 0% и Белых списков РФ",
                    )
                }
                val probeRes = runCatching {
                    VpnBatchProber.verifyCustomSubBlocking(
                        context = this@MainActivity,
                        settings = settingsState,
                        onProgress = progressCb,
                    )
                }.getOrNull()
                VeloxNative.trimMemoryIfLoaded()
                val snap2 = loadSnapshotBlocking(settingsState.region, reloadDisk = false)
                withContext(Dispatchers.Main) {
                    engineSnapshot = snap2
                    isRefreshingVpn = false
                    manualRefreshProgress = null
                    val title = if (subName.isNotBlank()) "«$subName»" else "Подписка"
                    if (probeRes != null && probeRes.newlyVerified > 0) {
                        showSnack("$title: ${probeRes.newlyVerified} из $importedCount серверов онлайн и готовы!")
                    } else if (importedCount > 0) {
                        showSnack("$title добавлена ($importedCount серверов в списке)")
                    }
                }
            }
        }
    }

    private fun handleSyncSource(url: String) {
        if (url.isBlank() || isBusyImport) return
        cancelBgSyncForUserAction()
        isBusyImport = true
        showSnack("Обновляю подписку…")
        lifecycleScope.launch(Dispatchers.IO) {
            VeloxNative.reloadFromDisk(this@MainActivity)
            VeloxNative.syncHwidConfig(this@MainActivity, settingsState.sendHwid)
            val activeSocks = VeloxPrefs.resolveActiveLocalSocksPort(this@MainActivity)
            val resRaw = runCatching {
                VeloxNative.syncSubscription(url, settingsState.tgMaxRttMs, activeSocks)
            }.getOrElse { e -> """{"ok":false,"error":"${e.message}"}""" }
            val obj = runCatching { JSONObject(resRaw) }.getOrDefault(JSONObject())
            val ok = obj.optBoolean("ok", false)
            val msg = if (ok) {
                obj.optString("message", "Подписка обновлена")
            } else {
                obj.optString("error", "Не удалось обновить подписку")
            }
            val subName = obj.optString("subName", "Подписка")
            val importedCount = obj.optInt("importedCount", 0)
            val needsProbe = ok && obj.optBoolean("needsCustomProbe", false)
            val snap = loadSnapshotBlocking(settingsState.region, reloadDisk = false)
            withContext(Dispatchers.Main) {
                isBusyImport = false
                engineSnapshot = snap
                showSnack(msg)
            }
            if (needsProbe && !runtimeState.isActiveOrBusy) {
                withContext(Dispatchers.Main) { isRefreshingVpn = true }
                val res = runCatching {
                    VpnBatchProber.verifyCustomSubBlocking(this@MainActivity, settingsState)
                }.getOrNull()
                VeloxNative.trimMemoryIfLoaded()
                val snap2 = loadSnapshotBlocking(settingsState.region, reloadDisk = false)
                withContext(Dispatchers.Main) {
                    engineSnapshot = snap2
                    isRefreshingVpn = false
                    manualRefreshProgress = null
                    if (res != null && res.newlyVerified > 0) {
                        showSnack("«$subName»: ${res.newlyVerified}/$importedCount серверов онлайн!")
                    }
                }
            }
        }
    }

    private fun handleRemoveSource(url: String) {
        lifecycleScope.launch(Dispatchers.IO) {
            VeloxNative.reloadFromDisk(this@MainActivity)
            val raw = runCatching { VeloxNative.removeSource(url) }.getOrDefault("{}")
            val name = runCatching { JSONObject(raw).optString("name", "Подписка") }
                .getOrDefault("Подписка")
            val snap = loadSnapshotBlocking(settingsState.region, reloadDisk = false)
            withContext(Dispatchers.Main) {
                engineSnapshot = snap
                showSnack("Удалена подписка «$name»")
            }
        }
    }

    private fun handleToggleSource(url: String, enabled: Boolean) {
        lifecycleScope.launch(Dispatchers.IO) {
            VeloxNative.reloadFromDisk(this@MainActivity)
            VeloxNative.toggleSource(url, enabled)
            val snap = loadSnapshotBlocking(settingsState.region, reloadDisk = false)
            withContext(Dispatchers.Main) {
                engineSnapshot = snap
            }
        }
    }

    private fun handleRegenerateWarp() {
        if (isBusyWarp) return
        isBusyWarp = true
        lifecycleScope.launch(Dispatchers.IO) {
            VeloxNative.reloadFromDisk(this@MainActivity)
            val activeSocks = VeloxPrefs.resolveActiveLocalSocksPort(this@MainActivity)
            val raw = VeloxNative.regenerateWarp(activeSocks)
            val obj = runCatching { JSONObject(raw) }.getOrDefault(JSONObject())
            val ok = obj.optBoolean("ok", false)
            val snap = loadSnapshotBlocking(settingsState.region, reloadDisk = false)
            withContext(Dispatchers.Main) {
                isBusyWarp = false
                engineSnapshot = snap
                if (ok) {
                    val m = if (obj.optBoolean("hasMasque")) "MASQUE H3/H2 + AWG" else "WireGuard AWG"
                    showSnack("Ключи Cloudflare WARP обновлены ($m)")
                } else {
                    showSnack(obj.optString("error", "Не удалось связаться с API WARP"))
                }
            }
        }
    }

    private fun loadDiagLogsBlocking(): List<String> = runCatching {
        VeloxNative.ensureInitialized(this)
        val raw = VeloxNative.readDiagLogs(300).trim()
        val arr = if (raw.startsWith("[")) {
            JSONArray(raw)
        } else {
            JSONObject(raw).optJSONArray("logs") ?: JSONArray()
        }
        val out = ArrayList<String>(arr.length())
        for (i in 0 until arr.length()) {
            val s = arr.optString(i)
            if (s.isNotBlank()) out.add(s)
        }
        out
    }.getOrDefault(emptyList())

    private fun handleClearDiagLogs(onCleared: (List<String>) -> Unit) {
        lifecycleScope.launch(Dispatchers.IO) {
            VeloxNative.ensureInitialized(this@MainActivity)
            VeloxNative.clearDiagLogs()
            val fresh = loadDiagLogsBlocking()
            val snap = loadSnapshotBlocking(settingsState.region, reloadDisk = false)
            withContext(Dispatchers.Main) {
                engineSnapshot = snap
                onCleared(fresh)
                showSnack("Журнал очищен")
            }
        }
    }

    private fun formatFullDiagExport(lines: List<String>): String {
        val s = settingsState
        val r = runtimeState
        val abis = Build.SUPPORTED_ABIS.joinToString(",")
        val header = buildString {
            appendLine("=== VeloxVPN 1.6.0 Diagnostic Log ===")
            appendLine("Устройство: ${Build.MANUFACTURER} ${Build.MODEL} | Android ${Build.VERSION.RELEASE} (SDK ${Build.VERSION.SDK_INT}) | ABI: $abis")
            appendLine("Сеть: ${VeloxNative.describeActiveNetwork(this@MainActivity)}")
            appendLine(
                "Настройки: region=${s.region} dual2x=${s.dualChannel} hwid=${s.sendHwid} WL=${s.whitelistMode} " +
                    "frag=${s.fragmentTls} bypassRU=${s.bypassRu} autoHeal=${s.autoHeal} profile=${s.profileMode.code} excluded=${s.excludedPackages.size}"
            )
            appendLine(
                "Состояние: phase=${r.phase} #1=${r.activeNodeName.ifBlank { "-" }} #2=${r.standbyNodeName.ifBlank { "-" }} " +
                    "failovers=${r.failoverCount} verified=${engineSnapshot.deviceVerifiedCount}/${engineSnapshot.allVpnNodes.size} " +
                    "warp=${engineSnapshot.hasWarpWg}/${engineSnapshot.hasWarpMasque} tg=${engineSnapshot.tgProxies.size}"
            )
            appendLine("-------------------------------------")
        }
        return header + lines.joinToString("\n")
    }

    private fun openExternalUrlSafe(url: String) {
        val clean = url.trim()
        if (!clean.startsWith("https://") && !clean.startsWith("tg://")) return
        val ok = runCatching {
            startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(clean)).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            true
        }.getOrDefault(false)
        if (!ok) {
            copyToClipboard(clean, "Ссылка скопирована в буфер обмена")
        }
    }

    private fun openTelegramProxyLink(tgUri: String, fallbackHttps: String) {
        val openedTg = runCatching {
            startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(tgUri)).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            true
        }.getOrDefault(false)

        if (!openedTg) {
            val openedWeb = runCatching {
                startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(fallbackHttps)).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                true
            }.getOrDefault(false)

            if (!openedWeb) {
                copyToClipboard(tgUri, "Telegram не найден — ссылка прокси скопирована в буфер")
            }
        }
    }

    private fun copyToClipboard(text: String, message: String) {
        val cm = getSystemService(ClipboardManager::class.java)
        cm?.setPrimaryClip(ClipData.newPlainText("VeloxVPN", text))
        showSnack(message)
    }

    private fun readClipboardText(): String {
        val cm = getSystemService(ClipboardManager::class.java) ?: return ""
        val item = cm.primaryClip?.getItemAt(0) ?: return ""
        return item.coerceToText(this)?.toString()?.trim().orEmpty()
    }

    private fun sharePlainText(text: String) {
        runCatching {
            val send = Intent(Intent.ACTION_SEND).apply {
                type = "text/plain"
                putExtra(Intent.EXTRA_TEXT, text)
            }
            startActivity(Intent.createChooser(send, "Поделиться"))
        }
    }

    @SuppressLint("BatteryLife")
    private fun requestIgnoreBatteryOpt() {
        runCatching {
            val intent = Intent(
                Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS,
                Uri.parse("package:$packageName")
            )
            startActivity(intent)
        }.onFailure {
            runCatching {
                startActivity(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS))
            }
        }
    }

    /**
     * On-demand live 12-service reachability check (AI, Discord, social, streaming, games, work).
     * Runs through the authenticated loopback SOCKS5 when VPN is active, otherwise directly over
     * the carrier network so users can see exactly what is blocked without a VPN. 0% idle cost.
     */
    private fun handleCheckServices() {
        if (isCheckingServices) return
        isCheckingServices = true
        val rt = VeloxPrefs.loadRuntime(this)
        val port = VeloxPrefs.resolveActiveLocalSocksPort(this)
        lifecycleScope.launch(Dispatchers.IO) {
            val raw = runCatching { VeloxNative.checkServices(port) }.getOrDefault("{}")
            val parsed = ServicesCheckResult.fromJsonStr(raw)
            withContext(Dispatchers.Main) {
                servicesResult = parsed
                isCheckingServices = false
                if (parsed.services.isNotEmpty()) {
                    val viaVpn = if (parsed.viaVpn) "через VPN" else "напрямую"
                    showSnack(
                        "Сервисы $viaVpn: ${parsed.passed}/${parsed.services.size} доступны" +
                            if (parsed.exitCountry.isNotBlank()) " · IP ${parsed.exitCountry}" else ""
                    )
                } else if (parsed.error.isNotBlank()) {
                    showSnack("Ошибка проверки: ${parsed.error}")
                }
            }
            // Refresh runtime state so exit-IP drift / forced RU substitution is visible immediately
            if (rt.phase == VpnPhase.CONNECTED) {
                withContext(Dispatchers.Main) {
                    runtimeState = VeloxPrefs.loadRuntime(this@MainActivity)
                }
            }
        }
    }

    private fun updateBatteryFlag() {
        val pm = getSystemService(PowerManager::class.java)
        batteryIgnored = pm?.isIgnoringBatteryOptimizations(packageName) == true
    }

    private fun requestNotifPermissionIfNeeded() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED
            ) {
                runCatching { notifPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS) }
            }
        }
    }

    private fun loadInstalledAppsAsync(onLoaded: (List<InstalledAppInfo>) -> Unit) {
        lifecycleScope.launch(Dispatchers.IO) {
            val pm = packageManager
            @Suppress("DEPRECATION")
            val pkgs = runCatching {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    pm.getInstalledApplications(PackageManager.ApplicationInfoFlags.of(0))
                } else {
                    pm.getInstalledApplications(0)
                }
            }.getOrDefault(emptyList())

            val result = pkgs.asSequence()
                .filter { info ->
                    info.packageName != packageName && (
                        (info.flags and ApplicationInfo.FLAG_SYSTEM) == 0 ||
                            pm.getLaunchIntentForPackage(info.packageName) != null
                        )
                }
                .map { info ->
                    val label = runCatching { pm.getApplicationLabel(info).toString().trim() }
                        .getOrDefault(info.packageName)
                        .ifBlank { info.packageName }
                    InstalledAppInfo(packageName = info.packageName, label = label)
                }
                .distinctBy { it.packageName }
                .sortedBy { it.label.lowercase() }
                .toList()

            withContext(Dispatchers.Main) {
                onLoaded(result)
            }
        }
    }

    private fun refreshEngineSnapshotAsync(reloadDisk: Boolean, syncHwid: Boolean = false) {
        lifecycleScope.launch(Dispatchers.IO) {
            val cur = settingsState
            if (syncHwid) {
                VeloxNative.syncHwidConfig(this@MainActivity, cur.sendHwid)
            }
            val snap = loadSnapshotBlocking(cur.region, reloadDisk)
            val tg = TgBridgeStatus.fromJsonStr(VeloxNative.getTgStatus())
            withContext(Dispatchers.Main) {
                engineSnapshot = snap
                tgStatusState = tg
            }
        }
    }

    private fun refreshTgStatusAsync() {
        lifecycleScope.launch(Dispatchers.IO) {
            VeloxNative.ensureInitialized(this@MainActivity)
            val tg = TgBridgeStatus.fromJsonStr(VeloxNative.getTgStatus())
            withContext(Dispatchers.Main) {
                tgStatusState = tg
            }
        }
    }

    /** Compact JNI snapshot: omits `outbound_json`, `raw_uri`, and log ring unless logs sheet is opened! */
    private fun loadSnapshotBlocking(region: String, reloadDisk: Boolean): EngineSnapshot {
        if (reloadDisk) {
            VeloxNative.reloadFromDisk(this)
        } else {
            VeloxNative.ensureInitialized(this)
        }
        return EngineSnapshot.parse(
            VeloxNative.getStateSnapshotEx(region, settingsState.whitelistMode, false)
        )
    }

    private fun showSnack(msg: String) {
        lifecycleScope.launch {
            snackbarHost.currentSnackbarData?.dismiss()
            snackbarHost.showSnackbar(msg)
        }
    }
}
