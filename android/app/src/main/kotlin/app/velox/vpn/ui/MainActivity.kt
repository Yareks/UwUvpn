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
import app.velox.vpn.core.TgBridgeStatus
import app.velox.vpn.core.VeloxNative
import app.velox.vpn.core.VeloxPrefs
import app.velox.vpn.core.VpnBatchProber
import app.velox.vpn.core.VpnNode
import app.velox.vpn.core.VpnRuntimeState
import app.velox.vpn.core.regionTitleRu
import app.velox.vpn.service.TgBridgeService
import app.velox.vpn.service.VeloxVpnService
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.async
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
    private var pendingForceRefresh = false

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
                    val next = VeloxPrefs.loadRuntime(this@MainActivity)
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
        refreshEngineSnapshotAsync(reloadDisk = false)
        triggerStartupSmartDeltaSync()

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
                    snackbarHostState = snackbarHost,
                    onToggleVpn = ::handleToggleVpn,
                    onRetryFreshVpn = { startVpnWithConsent(forceRefresh = true) },
                    onSelectRegion = ::handleSelectRegion,
                    onSelectNode = ::handleSelectNode,
                    onRotateNode = { VeloxVpnService.requestRotate(this) },
                    onRefreshVpn = ::handleRefreshVpn,
                    onUpdateSettings = ::handleUpdateSettings,
                    onRefreshTg = ::handleRefreshTgProxies,
                    onToggleTgBridge = ::handleToggleTgBridge,
                    onOpenTgLink = ::openTelegramProxyLink,
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

    override fun onResume() {
        super.onResume()
        settingsState = VeloxPrefs.loadSettings(this)
        runtimeState = VeloxPrefs.loadRuntime(this)
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

    /**
     * Smart First-Launch Preload & Incremental Delta Sync (v1.3):
     * - Automatically loads & verifies real live VPN servers (US/DE/Белые списки РФ) + TG proxies
     *   in background on launch so pressing «ПОДКЛЮЧИТЬ» connects in ~0.1s!
     * - Incremental: keeps every still-working entry untouched (no redundant reinstall!), drops
     *   dead old entries, and adds fresh verified entries. Yields immediately if user taps Connect!
     */
    private fun triggerStartupSmartDeltaSync() {
        bgSyncJob?.cancel()
        abortBgSync = false
        bgSyncJob = lifecycleScope.launch(Dispatchers.IO) {
            delay(500L)
            if (abortBgSync || runtimeState.isActiveOrBusy) return@launch

            val cur = settingsState
            val snap0 = loadSnapshotBlocking(cur.region, reloadDisk = false)
            withContext(Dispatchers.Main) { engineSnapshot = snap0 }

            val nowSec = System.currentTimeMillis() / 1000L
            val tgAge = nowSec - snap0.lastTgRefreshUnix
            val vpnAge = nowSec - snap0.lastVpnRefreshUnix
            val needTg = snap0.tgProxies.size < 5 || tgAge > 900L
            val needVpn = snap0.deviceVerifiedCount < 5 ||
                snap0.whitelistVerifiedCount == 0 ||
                vpnAge > 900L

            val tgDeferred = if (needTg && !isRefreshingTg) {
                async(Dispatchers.IO) {
                    withContext(Dispatchers.Main) { isRefreshingTg = true }
                    try {
                        VeloxNative.refreshTgProxies(cur.tgMaxRttMs, 0)
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
            } else {
                null
            }

            if (needVpn && !isRefreshingVpn && !abortBgSync && !runtimeState.isActiveOrBusy) {
                withContext(Dispatchers.Main) {
                    isRefreshingVpn = true
                    manualRefreshProgress = LiveProgressUpdate(
                        stageIndex = 1,
                        stageTotal = 5,
                        percent = 8,
                        etaSeconds = if (snap0.deviceVerifiedCount == 0) 12 else 6,
                        statusLine = if (snap0.deviceVerifiedCount == 0) {
                            "Автоподготовка рабочих серверов…"
                        } else {
                            "Умная сверка серверов…"
                        },
                        detailLine = "Рабочие сохраняем, нерабочие заменяем новыми",
                    )
                }
                val res = runCatching {
                    VpnBatchProber.smartDeltaSyncBlocking(
                        context = this@MainActivity,
                        settings = settingsState,
                        shouldAbort = { abortBgSync || runtimeState.isActiveOrBusy },
                        onProgress = { upd ->
                            if (!abortBgSync) {
                                lifecycleScope.launch(Dispatchers.Main) {
                                    manualRefreshProgress = upd
                                }
                            }
                        },
                    )
                }.getOrNull()
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
                            if (res.keptAlive > 0) add("${res.keptAlive} актуальных")
                            if (res.removedDead > 0) add("-${res.removedDead} убрано")
                        }
                        showSnack("Пул готов (${parts.joinToString(", ")}) — мгновенное подключение!")
                    }
                }
            }

            tgDeferred?.await()
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
        settingsState = VeloxPrefs.updateSettings(this) {
            it.copy(region = newRegion, pinnedNodeId = "")
        }
        refreshEngineSnapshotAsync(reloadDisk = false)
        if (runtimeState.isActiveOrBusy) {
            VeloxVpnService.startConnect(this, forceRefresh = false)
        }
    }

    private fun handleSelectNode(node: VpnNode) {
        val unpin = settingsState.pinnedNodeId == node.id
        settingsState = VeloxPrefs.updateSettings(this) {
            it.copy(pinnedNodeId = if (unpin) "" else node.id)
        }
        if (unpin) {
            showSnack("Включён автоматический выбор лучшего узла")
        } else {
            startVpnWithConsent(forceRefresh = false)
        }
    }

    private fun handleUpdateSettings(
        transform: (AppSettings) -> AppSettings,
        reconnectIfActive: Boolean,
    ) {
        val prevWl = settingsState.whitelistMode
        settingsState = VeloxPrefs.updateSettings(this, transform)
        if (prevWl != settingsState.whitelistMode) {
            // Immediately refresh visible server ranking for «Белые списки РФ»!
            refreshEngineSnapshotAsync(reloadDisk = false)
        }
        if (reconnectIfActive && runtimeState.isActiveOrBusy) {
            cancelBgSyncForUserAction()
            VeloxVpnService.startConnect(this, forceRefresh = false)
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
            etaSeconds = 13,
            statusLine = if (settingsState.whitelistMode) {
                "Умное обновление «Белые списки РФ»…"
            } else {
                "Умное обновление серверов $regLabel…"
            },
            detailLine = "Рабочие сохраняем + добавляем свежие US/DE/БС-РФ (25 фидов)",
        )

        if (runtimeState.isActiveOrBusy) {
            vpnRefreshDelegated = true
            VeloxVpnService.requestRefreshPool(this)
            return
        }

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
                onProgress = { upd ->
                    lifecycleScope.launch(Dispatchers.Main) {
                        manualRefreshProgress = upd
                    }
                }
            )
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
                    showSnack(res.error.ifBlank { "Не удалось найти узлы — включите «Белые списки РФ» или добавьте подписку" })
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
                delay(250L)
            }
        }

        lifecycleScope.launch(Dispatchers.IO) {
            VeloxNative.ensureInitialized(this@MainActivity)
            VeloxNative.logInfo(this@MainActivity, "TG", "Запуск проверки прокси Telegram (порог ≤${maxMs}мс)")
            val raw = runCatching { VeloxNative.refreshTgProxies(maxMs, 0) }.getOrDefault("{}")
            poller.cancel()
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
            delay(350L)
            refreshTgStatusAsync()
        }
    }

    private fun handleImportCustom(raw: String, kindHint: String) {
        if (raw.isBlank() || isBusyImport) return
        cancelBgSyncForUserAction()
        isBusyImport = true
        showSnack("Загружаю и разбираю подписку / ключ…")
        lifecycleScope.launch(Dispatchers.IO) {
            VeloxNative.reloadFromDisk(this@MainActivity)
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

            // Immediately run real Xray verification on imported subscription/keys so live RTT &
            // speed appear right in the server list and user can tap any server to connect in 0.1s!
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
                        etaSeconds = 6,
                        statusLine = if (subName.isNotBlank()) {
                            "Проверка «$subName» ($importedCount серв.)…"
                        } else {
                            "Проверка импортированных серверов…"
                        },
                        detailLine = "Замер отклика, скорости и Белых списков РФ",
                    )
                }
                val probeRes = runCatching {
                    VpnBatchProber.verifyCustomSubBlocking(
                        context = this@MainActivity,
                        settings = settingsState,
                        onProgress = { upd ->
                            lifecycleScope.launch(Dispatchers.Main) {
                                manualRefreshProgress = upd
                            }
                        },
                    )
                }.getOrNull()
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
            val socks = if (runtimeState.phase == app.velox.vpn.core.VpnPhase.CONNECTED) {
                VeloxPrefs.LOCAL_VPN_SOCKS_PORT
            } else {
                0
            }
            val resRaw = runCatching {
                VeloxNative.syncSubscription(url, settingsState.tgMaxRttMs, socks)
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
            val raw = VeloxNative.regenerateWarp(0)
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
            appendLine("=== VeloxVPN 1.2.0 Diagnostic Log ===")
            appendLine("Устройство: ${Build.MANUFACTURER} ${Build.MODEL} | Android ${Build.VERSION.RELEASE} (SDK ${Build.VERSION.SDK_INT}) | ABI: $abis")
            appendLine("Сеть: ${VeloxNative.describeActiveNetwork(this@MainActivity)}")
            appendLine(
                "Настройки: region=${s.region} WL=${s.whitelistMode} frag=${s.fragmentTls} " +
                    "bypassRU=${s.bypassRu} autoHeal=${s.autoHeal} profile=${s.profileMode.code} excluded=${s.excludedPackages.size}"
            )
            appendLine(
                "Состояние: phase=${r.phase} node=${r.activeNodeName.ifBlank { "-" }} " +
                    "verified=${engineSnapshot.deviceVerifiedCount}/${engineSnapshot.allVpnNodes.size} " +
                    "opera=${engineSnapshot.operaCount} warp=${engineSnapshot.hasWarpWg}/${engineSnapshot.hasWarpMasque} tg=${engineSnapshot.tgProxies.size}"
            )
            appendLine("-------------------------------------")
        }
        return header + lines.joinToString("\n")
    }

    private fun openTelegramProxyLink(tgUri: String, fallbackHttps: String) {
        val openedTg = runCatching {
            val intent = Intent(Intent.ACTION_VIEW, Uri.parse(tgUri))
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            startActivity(intent)
            true
        }.getOrDefault(false)

        if (!openedTg) {
            val openedWeb = runCatching {
                val intent = Intent(Intent.ACTION_VIEW, Uri.parse(fallbackHttps))
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                startActivity(intent)
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

    private fun refreshEngineSnapshotAsync(reloadDisk: Boolean) {
        lifecycleScope.launch(Dispatchers.IO) {
            val reg = settingsState.region
            val snap = loadSnapshotBlocking(reg, reloadDisk)
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

    private fun loadSnapshotBlocking(region: String, reloadDisk: Boolean): EngineSnapshot {
        if (reloadDisk) {
            VeloxNative.reloadFromDisk(this)
        } else {
            VeloxNative.ensureInitialized(this)
        }
        return EngineSnapshot.parse(
            VeloxNative.getStateSnapshot(region, settingsState.whitelistMode)
        )
    }

    private fun showSnack(msg: String) {
        lifecycleScope.launch {
            snackbarHost.currentSnackbarData?.dismiss()
            snackbarHost.showSnackbar(msg)
        }
    }
}
