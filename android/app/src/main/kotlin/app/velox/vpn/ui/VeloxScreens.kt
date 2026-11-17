package app.velox.vpn.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Slider
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import app.velox.vpn.core.AppIconCache
import app.velox.vpn.core.AppSettings
import app.velox.vpn.core.EngineSnapshot
import app.velox.vpn.core.InstalledAppInfo
import app.velox.vpn.core.LiveProgressUpdate
import app.velox.vpn.core.RuntimeProfileMode
import app.velox.vpn.core.SELECTABLE_REGIONS
import app.velox.vpn.core.ServicesCheckResult
import app.velox.vpn.core.SubSourceItem
import app.velox.vpn.core.TgBridgeStatus
import app.velox.vpn.core.TgProxy
import app.velox.vpn.core.VpnNode
import app.velox.vpn.core.VpnPhase
import app.velox.vpn.core.VpnProtoFilter
import app.velox.vpn.core.VpnRuntimeState
import app.velox.vpn.core.VpnSortMode
import app.velox.vpn.core.countryFlag
import app.velox.vpn.core.formatBytesRu
import app.velox.vpn.core.formatDuration
import app.velox.vpn.core.formatEtaRu
import app.velox.vpn.core.regionTitleRu
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext

@Composable
fun VeloxRootScreen(
    settings: AppSettings,
    runtime: VpnRuntimeState,
    snapshot: EngineSnapshot,
    tgStatus: TgBridgeStatus,
    isRefreshingVpn: Boolean,
    manualProgress: LiveProgressUpdate?,
    isRefreshingTg: Boolean,
    isBusyWarp: Boolean,
    isBusyImport: Boolean,
    batteryIgnored: Boolean,
    servicesResult: ServicesCheckResult,
    isCheckingServices: Boolean,
    onCheckServices: () -> Unit,
    snackbarHostState: SnackbarHostState,
    onToggleVpn: () -> Unit,
    onRetryFreshVpn: () -> Unit,
    onSelectRegion: (String) -> Unit,
    onSelectNode: (VpnNode) -> Unit,
    onRotateNode: () -> Unit,
    onRefreshVpn: () -> Unit,
    onDiscoverMoreVpn: () -> Unit,
    onUpdateSettings: ((AppSettings) -> AppSettings, Boolean) -> Unit,
    onRefreshTg: () -> Unit,
    onTgTabOpened: () -> Unit,
    onToggleTgBridge: (Boolean) -> Unit,
    onOpenTgLink: (String, String) -> Unit,
    onOpenExternalUrl: (String) -> Unit,
    onCopyText: (String, String) -> Unit,
    onShareText: (String) -> Unit,
    onImportItem: (String, String) -> Unit,
    onReadClipboard: () -> String,
    onToggleSource: (String, Boolean) -> Unit,
    onSyncSource: (String) -> Unit,
    onRemoveSource: (String) -> Unit,
    onRegenerateWarp: () -> Unit,
    onRequestIgnoreBattery: () -> Unit,
    onLoadInstalledApps: (onLoaded: (List<InstalledAppInfo>) -> Unit) -> Unit,
    onLoadDiagLogs: () -> List<String>,
    onClearDiagLogs: (onCleared: (List<String>) -> Unit) -> Unit,
    onFormatDiagExport: (List<String>) -> String,
) {
    var tab by rememberSaveable { mutableIntStateOf(0) }
    var showImportDialog by remember { mutableStateOf(false) }
    var importKindHint by remember { mutableStateOf("auto") }
    var showAppsDialog by remember { mutableStateOf(false) }
    var showLogsDialog by remember { mutableStateOf(false) }
    var installedApps by remember { mutableStateOf<List<InstalledAppInfo>?>(null) }

    Scaffold(
        containerColor = BgObsidian,
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            VeloxTopBar(
                phase = runtime.phase,
                tgBridgeOn = tgStatus.bridgeRunning,
                onOpenLogs = { showLogsDialog = true },
                onOpenAdd = {
                    importKindHint = if (tab == 1) "tg_proxy" else "auto"
                    showImportDialog = true
                }
            )
        },
        bottomBar = {
            VeloxBottomBar(
                selectedTab = tab,
                vpnActive = runtime.phase == VpnPhase.CONNECTED,
                tgCount = snapshot.tgProxies.size,
                onSelect = { idx ->
                    tab = idx
                    if (idx == 2) onTgTabOpened()
                }
            )
        }
    ) { innerPadding ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
        ) {
            when (tab) {
                0 -> VpnTabContent(
                    settings = settings,
                    runtime = runtime,
                    nodes = snapshot.vpnNodes,
                    allNodes = snapshot.allVpnNodes.ifEmpty { snapshot.vpnNodes },
                    customSubs = remember(snapshot.sources) { snapshot.sources.filter { !it.builtin } },
                    verifiedCount = snapshot.deviceVerifiedCount,
                    whitelistVerifiedCount = snapshot.whitelistVerifiedCount,
                    ytAdFreeCount = snapshot.ytAdFreeCount,
                    ytAdFreeLiveCount = snapshot.ytAdFreeLiveCount,
                    isRefreshing = isRefreshingVpn,
                    isBusyImport = isBusyImport,
                    manualProgress = manualProgress,
                    onToggleVpn = onToggleVpn,
                    onRetryFreshVpn = onRetryFreshVpn,
                    onSelectRegion = onSelectRegion,
                    onSelectNode = onSelectNode,
                    onRotateNode = onRotateNode,
                    onRefreshVpn = onRefreshVpn,
                    onDiscoverMoreVpn = onDiscoverMoreVpn,
                    onOpenLogs = { showLogsDialog = true },
                    onOpenImportSub = {
                        importKindHint = "vpn"
                        showImportDialog = true
                    },
                    onSyncSource = onSyncSource,
                    onRemoveSource = onRemoveSource,
                    onOpenExternalUrl = onOpenExternalUrl,
                    onUpdateSettings = onUpdateSettings,
                )

                1 -> ServicesTabContent(
                    result = servicesResult,
                    isChecking = isCheckingServices,
                    vpnConnected = runtime.phase == VpnPhase.CONNECTED,
                    runtime = runtime,
                    onCheck = onCheckServices,
                )

                2 -> TelegramTabContent(
                    settings = settings,
                    proxies = snapshot.tgProxies,
                    tgStatus = tgStatus,
                    isRefreshing = isRefreshingTg,
                    onRefreshTg = onRefreshTg,
                    onToggleBridge = onToggleTgBridge,
                    onOpenTgLink = onOpenTgLink,
                    onCopy = onCopyText,
                    onShare = onShareText,
                    onOpenAddProxy = {
                        importKindHint = "tg_proxy"
                        showImportDialog = true
                    }
                )

                3 -> SettingsTabContent(
                    settings = settings,
                    snapshot = snapshot,
                    isBusyWarp = isBusyWarp,
                    isBusyImport = isBusyImport,
                    batteryIgnored = batteryIgnored,
                    onUpdateSettings = onUpdateSettings,
                    onOpenImport = { hint ->
                        importKindHint = hint
                        showImportDialog = true
                    },
                    onToggleSource = onToggleSource,
                    onSyncSource = onSyncSource,
                    onRemoveSource = onRemoveSource,
                    onOpenExternalUrl = onOpenExternalUrl,
                    onRegenerateWarp = onRegenerateWarp,
                    onRequestIgnoreBattery = onRequestIgnoreBattery,
                    onOpenSplitApps = {
                        showAppsDialog = true
                        if (installedApps == null) {
                            onLoadInstalledApps { list -> installedApps = list }
                        }
                    },
                    onOpenLogsDialog = { showLogsDialog = true },
                    onCopy = onCopyText,
                    onFormatDiagExport = onFormatDiagExport,
                    onClearLogs = { onClearDiagLogs {} },
                )
            }
        }
    }

    if (showLogsDialog) {
        DiagnosticLogDialog(
            initialLogs = snapshot.logs,
            onLoadLogs = onLoadDiagLogs,
            onClearLogs = onClearDiagLogs,
            onCopy = { lines ->
                onCopyText(onFormatDiagExport(lines), "Журнал (${lines.size} строк) скопирован")
            },
            onShare = { lines ->
                onShareText(onFormatDiagExport(lines))
            },
            onDismiss = { showLogsDialog = false },
        )
    }

    if (showImportDialog) {
        UniversalImportDialog(
            initialHint = importKindHint,
            onDismiss = { showImportDialog = false },
            onPasteClipboard = onReadClipboard,
            onSubmit = { text, hint ->
                showImportDialog = false
                onImportItem(text, hint)
            }
        )
    }

    if (showAppsDialog) {
        AppSplitTunnelDialog(
            apps = installedApps,
            excluded = settings.excludedPackages,
            onTogglePkg = { pkg, checked ->
                onUpdateSettings({ cur ->
                    val next = cur.excludedPackages.toMutableSet()
                    if (checked) next.add(pkg) else next.remove(pkg)
                    cur.copy(excludedPackages = next)
                }, true)
            },
            onDismiss = { showAppsDialog = false }
        )
    }
}

@Composable
internal fun VeloxTopBar(
    phase: VpnPhase,
    tgBridgeOn: Boolean,
    onOpenLogs: () -> Unit,
    onOpenAdd: () -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(BgObsidian)
            .statusBarsPadding()
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            VeloxShieldGlyph(
                modifier = Modifier.size(26.dp),
                color = if (phase == VpnPhase.CONNECTED) EmeraldPrimary else CyanAccent
            )
            Spacer(Modifier.width(9.dp))
            Column {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        text = "VeloxVPN",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold,
                        color = TextHigh,
                    )
                    Spacer(Modifier.width(6.dp))
                    BadgePill(
                        text = "1.4",
                        bg = SurfaceElevated,
                        fg = EmeraldPrimary,
                    )
                    if (tgBridgeOn) {
                        Spacer(Modifier.width(5.dp))
                        BadgePill(
                            text = "TG-WS",
                            bg = CyanDim,
                            fg = CyanAccent,
                        )
                    }
                }
                Text(
                    text = "YouTube 0% рекл. · Все сайты · Telegram",
                    style = MaterialTheme.typography.labelSmall,
                    color = TextLow,
                )
            }
        }

        Row(
            horizontalArrangement = Arrangement.spacedBy(6.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Surface(
                shape = RoundedCornerShape(10.dp),
                color = if (phase == VpnPhase.ERROR) CoralError.copy(alpha = 0.16f) else SurfaceCard,
                border = BorderStroke(
                    1.dp,
                    if (phase == VpnPhase.ERROR) CoralError.copy(alpha = 0.55f) else SurfaceStroke
                ),
                modifier = Modifier.clickable(onClick = onOpenLogs)
            ) {
                Text(
                    text = "Логи",
                    style = MaterialTheme.typography.labelMedium,
                    color = if (phase == VpnPhase.ERROR) CoralError else TextMedium,
                    modifier = Modifier.padding(horizontal = 10.dp, vertical = 7.dp),
                )
            }
            Surface(
                shape = RoundedCornerShape(10.dp),
                color = SurfaceElevated,
                border = BorderStroke(1.dp, SurfaceStroke),
                modifier = Modifier.clickable(onClick = onOpenAdd)
            ) {
                Text(
                    text = "+ Импорт",
                    style = MaterialTheme.typography.labelMedium,
                    color = TextHigh,
                    modifier = Modifier.padding(horizontal = 10.dp, vertical = 7.dp),
                )
            }
        }
    }
}

@Composable
internal fun VeloxBottomBar(
    selectedTab: Int,
    vpnActive: Boolean,
    tgCount: Int,
    onSelect: (Int) -> Unit,
) {
    Column(modifier = Modifier.navigationBarsPadding()) {
        HorizontalDivider(color = SurfaceStroke.copy(alpha = 0.6f), thickness = 0.7.dp)
        NavigationBar(
            containerColor = SurfaceCard,
            tonalElevation = 0.dp,
            modifier = Modifier.height(64.dp),
        ) {
            val itemColors = NavigationBarItemDefaults.colors(
                selectedIconColor = EmeraldPrimary,
                selectedTextColor = EmeraldPrimary,
                indicatorColor = EmeraldDim,
                unselectedIconColor = TextMedium,
                unselectedTextColor = TextMedium,
            )

            NavigationBarItem(
                selected = selectedTab == 0,
                onClick = { onSelect(0) },
                colors = itemColors,
                icon = {
                    NavVectorIcon(kind = 0, active = selectedTab == 0 || vpnActive)
                },
                label = { Text("VPN", style = MaterialTheme.typography.labelMedium) }
            )

            NavigationBarItem(
                selected = selectedTab == 1,
                onClick = { onSelect(1) },
                colors = itemColors,
                icon = {
                    NavVectorIcon(kind = 3, active = selectedTab == 1)
                },
                label = { Text("Сервисы", style = MaterialTheme.typography.labelMedium) }
            )

            NavigationBarItem(
                selected = selectedTab == 2,
                onClick = { onSelect(2) },
                colors = itemColors,
                icon = {
                    NavVectorIcon(kind = 1, active = selectedTab == 2)
                },
                label = {
                    Text(
                        text = if (tgCount > 0) "TG ($tgCount)" else "Telegram",
                        style = MaterialTheme.typography.labelMedium,
                        maxLines = 1,
                    )
                }
            )

            NavigationBarItem(
                selected = selectedTab == 3,
                onClick = { onSelect(3) },
                colors = itemColors,
                icon = {
                    NavVectorIcon(kind = 2, active = selectedTab == 3)
                },
                label = { Text("Настройки", style = MaterialTheme.typography.labelMedium) }
            )
        }
    }
}

// ============================================================================
// TAB 1: VPN (US + DE + AUTO, Self-Healing Multi-Echelon Rust Tunnel)
// ============================================================================

@Composable
internal fun VpnTabContent(
    settings: AppSettings,
    runtime: VpnRuntimeState,
    nodes: List<VpnNode>,
    allNodes: List<VpnNode>,
    customSubs: List<SubSourceItem>,
    verifiedCount: Int,
    whitelistVerifiedCount: Int,
    ytAdFreeCount: Int,
    ytAdFreeLiveCount: Int,
    isRefreshing: Boolean,
    isBusyImport: Boolean,
    manualProgress: LiveProgressUpdate?,
    onToggleVpn: () -> Unit,
    onRetryFreshVpn: () -> Unit,
    onSelectRegion: (String) -> Unit,
    onSelectNode: (VpnNode) -> Unit,
    onRotateNode: () -> Unit,
    onRefreshVpn: () -> Unit,
    onDiscoverMoreVpn: () -> Unit,
    onOpenLogs: () -> Unit,
    onOpenImportSub: () -> Unit,
    onSyncSource: (String) -> Unit,
    onRemoveSource: (String) -> Unit,
    onOpenExternalUrl: (String) -> Unit,
    onUpdateSettings: ((AppSettings) -> AppSettings, Boolean) -> Unit,
) {
    var protoFilterName by rememberSaveable { mutableStateOf(VpnProtoFilter.ALL.name) }
    var sortModeName by rememberSaveable { mutableStateOf(VpnSortMode.SMART.name) }
    val protoFilter = VpnProtoFilter.entries.firstOrNull { it.name == protoFilterName } ?: VpnProtoFilter.ALL
    val sortMode = VpnSortMode.entries.firstOrNull { it.name == sortModeName } ?: VpnSortMode.SMART

    // Reset filter to ALL if selected protocol category has 0 matches after a region switch
    val availableFilters = remember(nodes) {
        VpnProtoFilter.entries.filter { f ->
            f == VpnProtoFilter.ALL || nodes.any { f.matches(it) }
        }
    }
    val effectiveFilter = if (protoFilter in availableFilters) protoFilter else VpnProtoFilter.ALL

    val displayedNodes = remember(nodes, effectiveFilter, sortMode) {
        val base = nodes.filter { effectiveFilter.matches(it) }
        when (sortMode) {
            VpnSortMode.SMART -> base
            VpnSortMode.PING -> base.sortedBy { if (it.rttMs > 0) it.rttMs else 99_999 }
            VpnSortMode.SPEED -> base.sortedByDescending { it.kbps }
            VpnSortMode.COUNTRY -> base.sortedWith(
                compareBy<VpnNode>({ it.exitCountry.ifBlank { "ZZ" } }, { if (it.rttMs > 0) it.rttMs else 99_999 })
            )
        }
    }

    // Lifecycle-gated ETA ticker: ticks ONLY during CONNECTING/FETCHING/HEALING and ONLY when visible!
    // Connected uptime uses isolated leaf `LiveSessionTimerCell` -> 0 parent recompositions/sec!
    val isUiStarted = rememberIsLifecycleStarted()
    val needEtaTicker = isUiStarted && (
        (runtime.isActiveOrBusy && runtime.phase != VpnPhase.CONNECTED) ||
            (!runtime.isActiveOrBusy && isRefreshing)
        )
    var nowMs by remember { mutableLongStateOf(System.currentTimeMillis()) }
    LaunchedEffect(needEtaTicker) {
        while (needEtaTicker) {
            nowMs = System.currentTimeMillis()
            delay(1000L)
        }
    }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(horizontal = 16.dp, vertical = 8.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        // 1. Multi-country & mode selector (16 countries/modes with live server counts)
        item {
            RegionSelectorBar(
                selected = settings.region,
                allNodes = allNodes,
                onSelect = onSelectRegion,
            )
        }

        // 2. Hero Connect Card (with live progress bar + approximate remaining time)
        item {
            VpnHeroCard(
                runtime = runtime,
                nowMs = nowMs,
                dualChannelEnabled = settings.dualChannel,
                isRefreshing = isRefreshing,
                manualProgress = manualProgress,
                selectedRegion = settings.region,
                onToggle = onToggleVpn,
                onRetryFresh = onRetryFreshVpn,
                onRotate = onRotateNode,
                onRefresh = onRefreshVpn,
                onOpenLogs = onOpenLogs,
            )
        }

        // 3. Fast YouTube No-Ads + RF anti-block quick toggles
        item {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                QuickModeTile(
                    modifier = Modifier.fillMaxWidth(),
                    title = "🛡️ Двойной канал 2× (основной + резерв)",
                    subtitle = when {
                        !settings.dualChannel ->
                            "Выкл · нажмите для мгновенного резерва без потери связи"
                        runtime.phase == VpnPhase.CONNECTED && runtime.dualChannelActive && runtime.standbyNodeName.isNotBlank() ->
                            "Вкл · резерв ${countryFlag(runtime.standbyCountry)} ${runtime.standbyNodeName} (0 мс обрыва)"
                        settings.region.equals("AUTO", ignoreCase = true) ->
                            "Вкл · авто-выбор лучшего основного и резервного сервера"
                        else ->
                            "Вкл · основной и резервный строго в «${regionTitleRu(settings.region)}»"
                    },
                    enabled = settings.dualChannel,
                    accent = CyanAccent,
                    onClick = {
                        onUpdateSettings({ it.copy(dualChannel = !it.dualChannel) }, true)
                    }
                )
                QuickModeTile(
                    modifier = Modifier.fillMaxWidth(),
                    title = "📺 YouTube и сайты без рекламы",
                    subtitle = when {
                        !settings.adblockYoutube ->
                            "Выкл · нажмите для 0% рекламы в YouTube и браузере"
                        ytAdFreeLiveCount > 0 ->
                            "Вкл · 0% видеорекламы YouTube ($ytAdFreeLiveCount серв.) + антибаннер сайтов"
                        ytAdFreeCount > 0 ->
                            "Вкл · $ytAdFreeCount серв. YouTube без рекламы (AL/MD/EU) + антибаннер"
                        else ->
                            "Вкл · авто-маршрут YouTube 0% рекламы + блокировка DoubleClick/Директ"
                    },
                    enabled = settings.adblockYoutube,
                    accent = EmeraldPrimary,
                    onClick = {
                        onUpdateSettings({ it.copy(adblockYoutube = !it.adblockYoutube) }, true)
                    }
                )
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(10.dp),
                ) {
                    QuickModeTile(
                        modifier = Modifier.weight(1f),
                        title = "Белые списки РФ",
                        subtitle = when {
                            settings.whitelistMode && whitelistVerifiedCount > 0 ->
                                "Вкл · БС-РФ: $whitelistVerifiedCount живых"
                            settings.whitelistMode ->
                                "Вкл · Минцифры SNI/CIDR"
                            whitelistVerifiedCount > 0 ->
                                "Готово БС: $whitelistVerifiedCount · LTE/МТС/Т2"
                            else -> "При блоке LTE/МТС/Т2"
                        },
                        enabled = settings.whitelistMode,
                        accent = CyanAccent,
                        onClick = {
                            onUpdateSettings(
                                { it.copy(whitelistMode = !it.whitelistMode, pinnedNodeId = "") },
                                true
                            )
                        }
                    )
                    QuickModeTile(
                        modifier = Modifier.weight(1f),
                        title = "Банки и РФ напрямую",
                        subtitle = if (settings.bypassRu) "Сбер, Т-Банк, Госусл." else "Весь трафик в VPN",
                        enabled = settings.bypassRu,
                        accent = EmeraldPrimary,
                        onClick = {
                            onUpdateSettings({ it.copy(bypassRu = !it.bypassRu) }, true)
                        }
                    )
                }
            }
        }

        // 3b. User's Imported Subscriptions Card (always visible once added)
        if (customSubs.isNotEmpty() || isBusyImport) {
            item {
                Surface(
                    shape = RoundedCornerShape(15.dp),
                    color = SurfaceCard,
                    border = BorderStroke(1.dp, CyanAccent.copy(alpha = 0.45f)),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Column(modifier = Modifier.padding(horizontal = 13.dp, vertical = 10.dp)) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Text(
                                text = if (isBusyImport) {
                                    "Загрузка подписки…"
                                } else {
                                    "Мои подписки (${customSubs.size})"
                                },
                                style = MaterialTheme.typography.titleSmall,
                                color = CyanAccent,
                            )
                            TextButton(
                                onClick = onOpenImportSub,
                                enabled = !isBusyImport,
                                contentPadding = PaddingValues(horizontal = 8.dp, vertical = 2.dp),
                            ) {
                                Text("+ Ещё", style = MaterialTheme.typography.labelMedium, color = EmeraldPrimary)
                            }
                        }
                        if (isBusyImport) {
                            Spacer(Modifier.height(4.dp))
                            LinearProgressIndicator(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .height(4.dp)
                                    .clip(RoundedCornerShape(2.dp)),
                                color = CyanAccent,
                                trackColor = SurfaceElevated,
                            )
                        }
                        customSubs.forEach { sub ->
                            Spacer(Modifier.height(6.dp))
                            HappSubscriptionCard(
                                sub = sub,
                                busy = isBusyImport,
                                onSync = { onSyncSource(sub.url) },
                                onRemove = { onRemoveSource(sub.url) },
                                onOpenUrl = onOpenExternalUrl,
                            )
                        }
                    }
                }
            }
        }

        // 4. Verified Server Pool Header
        item {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 4.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    val liveInList = nodes.count { it.deviceVerified }
                    val countryCnt = remember(allNodes) {
                        allNodes.map { it.exitCountry }.filter { it.isNotBlank() }.distinct().size
                    }
                    Text(
                        text = if (liveInList > 0) {
                            "Подключения: ${displayedNodes.size} ($liveInList пров. · $countryCnt стран)"
                        } else {
                            "Пул подключений: ${displayedNodes.size} ($countryCnt стран)"
                        },
                        style = MaterialTheme.typography.titleSmall,
                        color = TextHigh,
                    )
                    Text(
                        text = if (settings.pinnedNodeId.isEmpty()) {
                            "${regionTitleRu(settings.region)} · автовыбор + горячий резерв"
                        } else {
                            "Узел закреплён · нажмите ещё раз для автовыбора"
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = TextLow,
                    )
                }
                Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                    TextButton(
                        onClick = onDiscoverMoreVpn,
                        enabled = !isRefreshing,
                        contentPadding = PaddingValues(horizontal = 8.dp, vertical = 4.dp),
                    ) {
                        Text(
                            text = "＋ Ещё",
                            style = MaterialTheme.typography.labelMedium,
                            color = CyanAccent,
                        )
                    }
                    TextButton(
                        onClick = onRefreshVpn,
                        enabled = !isRefreshing,
                        contentPadding = PaddingValues(horizontal = 8.dp, vertical = 4.dp),
                    ) {
                        Text(
                            text = if (isRefreshing) "Поиск…" else "↻ Обновить",
                            style = MaterialTheme.typography.labelMedium,
                            color = EmeraldPrimary,
                        )
                    }
                }
            }
        }

        // Protocol filter chips + 1-tap sort switcher
        if (nodes.isNotEmpty()) {
            item {
                LazyRow(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    item {
                        Surface(
                            shape = RoundedCornerShape(9.dp),
                            color = SurfaceElevated,
                            border = BorderStroke(1.dp, CyanAccent.copy(alpha = 0.45f)),
                            modifier = Modifier.clickable {
                                val list = VpnSortMode.entries
                                val next = list[(list.indexOf(sortMode) + 1) % list.size]
                                sortModeName = next.name
                            }
                        ) {
                            Text(
                                text = sortMode.label,
                                style = MaterialTheme.typography.labelSmall,
                                color = CyanAccent,
                                modifier = Modifier.padding(horizontal = 9.dp, vertical = 6.dp),
                            )
                        }
                    }
                    items(availableFilters, key = { it.name }) { flt ->
                        val active = flt == effectiveFilter
                        val cnt = if (flt == VpnProtoFilter.ALL) nodes.size else nodes.count { flt.matches(it) }
                        Surface(
                            shape = RoundedCornerShape(9.dp),
                            color = if (active) EmeraldDim else SurfaceCard,
                            border = BorderStroke(
                                1.dp,
                                if (active) EmeraldPrimary.copy(alpha = 0.7f) else SurfaceStroke
                            ),
                            modifier = Modifier.clickable { protoFilterName = flt.name }
                        ) {
                            Text(
                                text = "${flt.label} ($cnt)",
                                style = MaterialTheme.typography.labelSmall,
                                color = if (active) EmeraldPrimary else TextMedium,
                                modifier = Modifier.padding(horizontal = 9.dp, vertical = 6.dp),
                            )
                        }
                    }
                }
            }
        }

        if (displayedNodes.isEmpty()) {
            item {
                Surface(
                    shape = RoundedCornerShape(16.dp),
                    color = SurfaceCard,
                    border = BorderStroke(1.dp, SurfaceStroke),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Column(
                        modifier = Modifier.padding(20.dp),
                        horizontalAlignment = Alignment.CenterHorizontally,
                    ) {
                        Text(
                            text = "Нет узлов ${regionTitleRu(settings.region)} в кэше — нажмите «↻ Обновить» или «＋ Ещё»",
                            style = MaterialTheme.typography.titleSmall,
                            color = TextHigh,
                            textAlign = TextAlign.Center,
                        )
                        Spacer(Modifier.height(6.dp))
                        Text(
                            text = "Движок проверит 76 источников: VLESS Reality, XHTTP, gRPC, WS, Hysteria 2, Trojan, VMess, Shadowsocks 2022, WireGuard, YouTube 0% рекламы (AL/MD/EU) и Cloudflare WARP MASQUE.",
                            style = MaterialTheme.typography.bodySmall,
                            color = TextMedium,
                            textAlign = TextAlign.Center,
                        )
                        Spacer(Modifier.height(10.dp))
                        OutlinedButton(
                            onClick = onRefreshVpn,
                            enabled = !isRefreshing,
                            border = BorderStroke(1.dp, EmeraldPrimary.copy(alpha = 0.65f)),
                        ) {
                            Text(
                                text = "Найти серверы ${countryFlag(settings.region)} ${regionTitleRu(settings.region)}",
                                color = EmeraldPrimary,
                            )
                        }
                    }
                }
            }
        } else {
            items(displayedNodes, key = { it.id }) { node ->
                val isCurrent = runtime.phase == VpnPhase.CONNECTED && runtime.activeNodeId == node.id
                val isPinned = settings.pinnedNodeId == node.id
                VpnNodeCard(
                    node = node,
                    isCurrent = isCurrent,
                    isPinned = isPinned,
                    onClick = { onSelectNode(node) }
                )
            }
        }

        item { Spacer(Modifier.height(8.dp)) }
    }
}

@Composable
internal fun RegionSelectorBar(
    selected: String,
    allNodes: List<VpnNode>,
    onSelect: (String) -> Unit,
) {
    val countByCode = remember(allNodes) {
        val m = HashMap<String, Int>()
        m["AUTO"] = allNodes.size
        m["YT"] = allNodes.count { it.ytAdFree }
        m["WL"] = allNodes.count { it.whitelistFriendly && !it.viaWarp }
        m["WARP"] = allNodes.count {
            it.viaWarp || it.protocol == "masque" || it.displayProtocol.startsWith("WARP", ignoreCase = true)
        }
        for (n in allNodes) {
            val cc = n.exitCountry.uppercase()
            if (cc.length == 2) {
                m[cc] = (m[cc] ?: 0) + 1
            }
        }
        m
    }
    LazyRow(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(6.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        items(SELECTABLE_REGIONS, key = { it.code }) { opt ->
            val active = selected.equals(opt.code, ignoreCase = true)
            val cnt = countByCode[opt.code] ?: 0
            Surface(
                shape = RoundedCornerShape(12.dp),
                color = if (active) EmeraldDim else SurfaceCard,
                border = BorderStroke(
                    width = 1.dp,
                    color = if (active) EmeraldPrimary.copy(alpha = 0.75f) else SurfaceStroke,
                ),
                modifier = Modifier.clickable { onSelect(opt.code) },
            ) {
                Row(
                    modifier = Modifier.padding(horizontal = 11.dp, vertical = 8.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(5.dp),
                ) {
                    Text(
                        text = "${opt.flag} ${opt.shortLabel}",
                        style = MaterialTheme.typography.labelLarge,
                        fontWeight = if (active) FontWeight.SemiBold else FontWeight.Normal,
                        color = if (active) EmeraldPrimary else TextHigh,
                        maxLines = 1,
                    )
                    if (cnt > 0) {
                        Text(
                            text = "$cnt",
                            style = MaterialTheme.typography.labelSmall,
                            color = if (active) EmeraldPrimary else CyanAccent,
                        )
                    }
                }
            }
        }
    }
}

@Composable
internal fun VpnHeroCard(
    runtime: VpnRuntimeState,
    nowMs: Long,
    dualChannelEnabled: Boolean,
    isRefreshing: Boolean,
    manualProgress: LiveProgressUpdate?,
    selectedRegion: String,
    onToggle: () -> Unit,
    onRetryFresh: () -> Unit,
    onRotate: () -> Unit,
    onRefresh: () -> Unit,
    onOpenLogs: () -> Unit,
) {
    val connected = runtime.phase == VpnPhase.CONNECTED
    val busy = runtime.phase == VpnPhase.CONNECTING ||
        runtime.phase == VpnPhase.FETCHING ||
        runtime.phase == VpnPhase.HEALING

    val ringColor = when (runtime.phase) {
        VpnPhase.CONNECTED -> EmeraldPrimary
        VpnPhase.CONNECTING, VpnPhase.FETCHING, VpnPhase.HEALING -> AmberWarn
        VpnPhase.ERROR -> CoralError
        VpnPhase.DISCONNECTED -> CyanAccent.copy(alpha = 0.7f)
    }

    val cardBrush = Brush.verticalGradient(
        colors = when {
            connected -> listOf(Color(0xFF0E2622), SurfaceCard)
            busy -> listOf(Color(0xFF231D12), SurfaceCard)
            runtime.phase == VpnPhase.ERROR -> listOf(Color(0xFF261216), SurfaceCard)
            else -> listOf(Color(0xFF121C2B), SurfaceCard)
        }
    )

    // Smooth real-time progress + ticking remaining seconds (never freezes between poll intervals)
    val rawPct = when {
        busy && runtime.progressPercent > 0 -> runtime.progressPercent
        !connected && isRefreshing && manualProgress != null -> manualProgress.percent
        busy -> 12
        else -> 0
    }.coerceIn(0, 99)

    val displayEtaSec = when {
        busy && runtime.etaSeconds > 0 -> {
            val sinceUpdate = if (runtime.updatedAtMs > 0L) {
                ((nowMs - runtime.updatedAtMs).coerceAtLeast(0L) / 1000L).toInt()
            } else 0
            (runtime.etaSeconds - sinceUpdate).coerceAtLeast(1)
        }
        !connected && isRefreshing && manualProgress != null -> manualProgress.etaSeconds.coerceAtLeast(1)
        busy -> 8
        else -> 0
    }

    val displayDetail = when {
        busy -> runtime.stageDetail
        !connected && isRefreshing && manualProgress != null -> manualProgress.detailLine
        else -> ""
    }

    val displayStep = when {
        busy && runtime.stageTotal > 0 -> "Шаг ${runtime.stageIndex.coerceAtLeast(1)}/${runtime.stageTotal}"
        !connected && isRefreshing && manualProgress != null && manualProgress.stageTotal > 0 ->
            "Шаг ${manualProgress.stageIndex.coerceAtLeast(1)}/${manualProgress.stageTotal}"
        else -> ""
    }

    Box(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(22.dp))
            .background(cardBrush)
            .border(
                width = 1.dp,
                color = when {
                    connected -> EmeraldPrimary.copy(alpha = 0.42f)
                    busy -> AmberWarn.copy(alpha = 0.38f)
                    runtime.phase == VpnPhase.ERROR -> CoralError.copy(alpha = 0.42f)
                    else -> SurfaceStroke
                },
                shape = RoundedCornerShape(22.dp)
            )
            .padding(horizontal = 18.dp, vertical = 20.dp)
    ) {
        Column(
            modifier = Modifier.fillMaxWidth(),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            // Tactile Power Button with live radial progress ring while connecting
            Box(
                modifier = Modifier
                    .size(128.dp)
                    .clip(CircleShape)
                    .background(ringColor.copy(alpha = 0.10f))
                    .border(2.5.dp, ringColor.copy(alpha = if (busy) 0.35f else 1f), CircleShape)
                    .clickable(onClick = onToggle),
                contentAlignment = Alignment.Center,
            ) {
                if (busy) {
                    CircularProgressIndicator(
                        progress = { (rawPct / 100f).coerceIn(0.06f, 0.98f) },
                        color = AmberWarn,
                        trackColor = Color.Transparent,
                        strokeWidth = 3.5.dp,
                        modifier = Modifier.size(126.dp),
                    )
                }
                Box(
                    modifier = Modifier
                        .size(100.dp)
                        .clip(CircleShape)
                        .background(
                            if (connected) EmeraldPrimary.copy(alpha = 0.18f)
                            else SurfaceElevated
                        ),
                    contentAlignment = Alignment.Center,
                ) {
                    if (busy) {
                        Column(horizontalAlignment = Alignment.CenterHorizontally) {
                            Text(
                                text = "$rawPct%",
                                style = MaterialTheme.typography.titleMedium,
                                fontWeight = FontWeight.Bold,
                                color = AmberWarn,
                            )
                            Text(
                                text = "Стоп",
                                style = MaterialTheme.typography.labelSmall,
                                color = TextLow,
                            )
                        }
                    } else {
                        PowerGlyph(
                            modifier = Modifier.size(44.dp),
                            color = if (connected) EmeraldPrimary else TextHigh,
                        )
                    }
                }
            }

            Spacer(Modifier.height(14.dp))

            // Headline state
            val headline = when (runtime.phase) {
                VpnPhase.CONNECTED -> {
                    val flag = countryFlag(runtime.exitCountry.ifBlank { selectedRegion })
                    "$flag ${runtime.activeNodeName.ifBlank { "Подключено" }}"
                }
                VpnPhase.CONNECTING -> "Подключение…"
                VpnPhase.FETCHING -> "Подбор рабочего сервера…"
                VpnPhase.HEALING -> "Автовосстановление…"
                VpnPhase.ERROR -> "Не удалось подключиться"
                VpnPhase.DISCONNECTED -> if (isRefreshing) "Обновление серверов…" else "Нажмите для подключения"
            }

            Text(
                text = headline,
                style = MaterialTheme.typography.headlineSmall,
                color = when {
                    connected -> EmeraldPrimary
                    runtime.phase == VpnPhase.ERROR -> CoralError
                    else -> TextHigh
                },
                textAlign = TextAlign.Center,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )

            Spacer(Modifier.height(4.dp))

            val subLine = when {
                !connected && isRefreshing && manualProgress != null -> manualProgress.statusLine
                else -> runtime.statusLine
            }
            Text(
                text = subLine,
                style = MaterialTheme.typography.bodySmall,
                color = if (runtime.phase == VpnPhase.ERROR) CoralError.copy(alpha = 0.92f) else TextMedium,
                textAlign = TextAlign.Center,
                maxLines = 2,
            )

            // Live connection/probing progress card with approximate remaining time (ETA)
            if (busy || (!connected && isRefreshing)) {
                Spacer(Modifier.height(14.dp))
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(12.dp))
                        .background(BgObsidian.copy(alpha = 0.62f))
                        .border(1.dp, SurfaceStroke, RoundedCornerShape(12.dp))
                        .padding(horizontal = 12.dp, vertical = 10.dp),
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text(
                            text = buildString {
                                if (displayStep.isNotBlank()) append("$displayStep · ")
                                append("$rawPct%")
                            },
                            style = MaterialTheme.typography.labelMedium,
                            fontWeight = FontWeight.SemiBold,
                            color = TextHigh,
                        )
                        BadgePill(
                            text = "Осталось ${formatEtaRu(displayEtaSec)}",
                            bg = if (busy) AmberWarn.copy(alpha = 0.16f) else EmeraldDim,
                            fg = if (busy) AmberWarn else EmeraldPrimary,
                        )
                    }
                    Spacer(Modifier.height(7.dp))
                    LinearProgressIndicator(
                        progress = { (rawPct / 100f).coerceIn(0.05f, 0.99f) },
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(6.dp)
                            .clip(RoundedCornerShape(3.dp)),
                        color = if (busy) AmberWarn else EmeraldPrimary,
                        trackColor = SurfaceElevated,
                    )
                    if (displayDetail.isNotBlank()) {
                        Spacer(Modifier.height(6.dp))
                        Text(
                            text = displayDetail,
                            style = MaterialTheme.typography.labelSmall,
                            color = TextLow,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
                }

                if (busy) {
                    Spacer(Modifier.height(10.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        OutlinedButton(
                            onClick = onToggle,
                            modifier = Modifier.weight(1f),
                            shape = RoundedCornerShape(11.dp),
                            border = BorderStroke(1.dp, SurfaceStroke),
                            contentPadding = PaddingValues(vertical = 8.dp),
                        ) {
                            Text("Отменить", style = MaterialTheme.typography.labelMedium, color = TextHigh)
                        }
                        OutlinedButton(
                            onClick = onOpenLogs,
                            modifier = Modifier.weight(1f),
                            shape = RoundedCornerShape(11.dp),
                            border = BorderStroke(1.dp, SurfaceStroke),
                            contentPadding = PaddingValues(vertical = 8.dp),
                        ) {
                            Text("Журнал вживую", style = MaterialTheme.typography.labelMedium, color = CyanAccent)
                        }
                    }
                }
            } else if (runtime.phase == VpnPhase.ERROR) {
                Spacer(Modifier.height(12.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    OutlinedButton(
                        onClick = onRetryFresh,
                        modifier = Modifier.weight(1f),
                        shape = RoundedCornerShape(11.dp),
                        border = BorderStroke(1.dp, EmeraldPrimary.copy(alpha = 0.5f)),
                        contentPadding = PaddingValues(vertical = 9.dp),
                    ) {
                        Text("Свежий подбор", style = MaterialTheme.typography.labelMedium, color = EmeraldPrimary)
                    }
                    OutlinedButton(
                        onClick = onOpenLogs,
                        modifier = Modifier.weight(1f),
                        shape = RoundedCornerShape(11.dp),
                        border = BorderStroke(1.dp, CoralError.copy(alpha = 0.5f)),
                        contentPadding = PaddingValues(vertical = 9.dp),
                    ) {
                        Text("Открыть логи", style = MaterialTheme.typography.labelMedium, color = CoralError)
                    }
                }
            } else if (connected) {
                Spacer(Modifier.height(14.dp))
                // Zero-recomposition leaf uptime timer + Ping | Downlink | Uplink
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(12.dp))
                        .background(BgObsidian.copy(alpha = 0.55f))
                        .padding(vertical = 10.dp, horizontal = 8.dp),
                    horizontalArrangement = Arrangement.SpaceEvenly,
                ) {
                    LiveSessionTimerCell(connectedSinceMs = runtime.connectedSinceMs)
                    MetricCell(
                        "Отклик",
                        if (runtime.rttMs > 0) "${runtime.rttMs} мс" else "—",
                        rttColor(runtime.rttMs)
                    )
                    MetricCell("↓ Приём", formatBytesRu(runtime.downlinkBytes), CyanAccent)
                    MetricCell("↑ Отдача", formatBytesRu(runtime.uplinkBytes), EmeraldPrimary)
                }

                if (dualChannelEnabled) {
                    Spacer(Modifier.height(8.dp))
                    DualChannelLiveStrip(
                        runtime = runtime,
                        dualEnabled = dualChannelEnabled,
                        selectedRegion = selectedRegion,
                    )
                }

                if (runtime.exitIp.isNotBlank() || runtime.backupCount > 0) {
                    Spacer(Modifier.height(7.dp))
                    Text(
                        text = buildString {
                            if (runtime.exitIp.isNotBlank()) {
                                append("IP: ${runtime.exitIp}")
                            }
                            if (runtime.exitColo.isNotBlank()) {
                                append(" (${runtime.exitColo})")
                            }
                            if (runtime.backupCount > 0) {
                                append(" · В пуле региона: +${runtime.backupCount}")
                            }
                        },
                        style = MaterialTheme.typography.labelSmall,
                        color = TextLow,
                    )
                }

                Spacer(Modifier.height(12.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    OutlinedButton(
                        onClick = onRotate,
                        modifier = Modifier.weight(1f),
                        shape = RoundedCornerShape(11.dp),
                        border = BorderStroke(1.dp, SurfaceStroke),
                        contentPadding = PaddingValues(vertical = 9.dp),
                    ) {
                        Text("Сменить узел", style = MaterialTheme.typography.labelMedium, color = TextHigh)
                    }
                    OutlinedButton(
                        onClick = onRefresh,
                        enabled = !isRefreshing,
                        modifier = Modifier.weight(1f),
                        shape = RoundedCornerShape(11.dp),
                        border = BorderStroke(1.dp, SurfaceStroke),
                        contentPadding = PaddingValues(vertical = 9.dp),
                    ) {
                        Text(
                            if (isRefreshing) "Обновление…" else "Свежие конфиги",
                            style = MaterialTheme.typography.labelMedium,
                            color = CyanAccent
                        )
                    }
                }
            }
        }
    }
}

@Composable
internal fun MetricCell(label: String, value: String, valueColor: Color) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(
            text = value,
            style = MaterialTheme.typography.labelMedium,
            fontWeight = FontWeight.Bold,
            color = valueColor,
        )
        Text(
            text = label,
            style = MaterialTheme.typography.labelSmall,
            color = TextLow,
        )
    }
}

@Composable
internal fun QuickModeTile(
    modifier: Modifier,
    title: String,
    subtitle: String,
    enabled: Boolean,
    accent: Color,
    onClick: () -> Unit,
) {
    Surface(
        modifier = modifier.clickable(onClick = onClick),
        shape = RoundedCornerShape(14.dp),
        color = if (enabled) accent.copy(alpha = 0.11f) else SurfaceCard,
        border = BorderStroke(
            1.dp,
            if (enabled) accent.copy(alpha = 0.55f) else SurfaceStroke
        ),
    ) {
        Column(modifier = Modifier.padding(horizontal = 12.dp, vertical = 10.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Box(
                    modifier = Modifier
                        .size(8.dp)
                        .clip(CircleShape)
                        .background(if (enabled) accent else TextLow)
                )
                Text(
                    text = if (enabled) "ВКЛ" else "ВЫКЛ",
                    style = MaterialTheme.typography.labelSmall,
                    fontWeight = FontWeight.Bold,
                    color = if (enabled) accent else TextLow,
                )
            }
            Spacer(Modifier.height(5.dp))
            Text(
                text = title,
                style = MaterialTheme.typography.labelMedium,
                fontWeight = FontWeight.SemiBold,
                color = TextHigh,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                text = subtitle,
                style = MaterialTheme.typography.labelSmall,
                color = TextMedium,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
    }
}

@Composable
internal fun VpnNodeCard(
    node: VpnNode,
    isCurrent: Boolean,
    isPinned: Boolean,
    onClick: () -> Unit,
) {
    val borderCol = when {
        isCurrent -> EmeraldPrimary.copy(alpha = 0.7f)
        isPinned -> CyanAccent.copy(alpha = 0.6f)
        else -> SurfaceStroke
    }
    Surface(
        shape = RoundedCornerShape(14.dp),
        color = if (isCurrent) Color(0xFF0E2320) else SurfaceCard,
        border = BorderStroke(1.dp, borderCol),
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 14.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Row(
                modifier = Modifier.weight(1f),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    text = countryFlag(node.exitCountry),
                    fontSize = 22.sp,
                )
                Spacer(Modifier.width(11.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            text = node.name,
                            style = MaterialTheme.typography.titleSmall,
                            color = TextHigh,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                        if (isCurrent) {
                            Spacer(Modifier.width(6.dp))
                            BadgePill("АКТИВЕН", EmeraldDim, EmeraldPrimary)
                        } else if (isPinned) {
                            Spacer(Modifier.width(6.dp))
                            BadgePill("ВЫБРАН", CyanDim, CyanAccent)
                        }
                    }
                    Spacer(Modifier.height(3.dp))
                    Row(
                        horizontalArrangement = Arrangement.spacedBy(6.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        BadgePill(node.displayProtocol, SurfaceElevated, CyanAccent)
                        if (node.sourceTier == 0) {
                            BadgePill("★ Подписка", CyanDim, CyanAccent)
                        }
                        if (node.deviceVerified) {
                            BadgePill("✓ Живой", EmeraldDim, EmeraldPrimary)
                        }
                        if (node.ytAdFree) {
                            BadgePill("📺 YT 0%", EmeraldDim, EmeraldPrimary)
                        }
                        if (node.whitelistFriendly) {
                            BadgePill("БС-РФ", EmeraldDim, EmeraldPrimary)
                        } else if (node.viaWarp) {
                            BadgePill("2-Hop", EmeraldDim, EmeraldPrimary)
                        }
                        if (node.sni.isNotBlank() && node.sourceTier <= 1) {
                            Text(
                                text = node.sni,
                                style = MaterialTheme.typography.labelSmall,
                                color = TextLow,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                        }
                    }
                }
            }

            Spacer(Modifier.width(8.dp))
            Column(horizontalAlignment = Alignment.End) {
                Text(
                    text = if (node.rttMs > 0) "${node.rttMs} мс" else "Готов",
                    style = MaterialTheme.typography.titleSmall,
                    color = if (node.rttMs > 0) rttColor(node.rttMs) else CyanAccent,
                )
                if (node.kbps > 0) {
                    val mbps = node.kbps / 1000.0
                    Text(
                        text = if (mbps >= 1.0) String.format("%.1f Мбит", mbps) else "${node.kbps} Кбит",
                        style = MaterialTheme.typography.labelSmall,
                        color = TextLow,
                    )
                }
            }
        }
    }
}

