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
import app.velox.vpn.core.SubSourceItem
import app.velox.vpn.core.TgBridgeStatus
import app.velox.vpn.core.TgProxy
import app.velox.vpn.core.VpnNode
import app.velox.vpn.core.VpnPhase
import app.velox.vpn.core.VpnRuntimeState
import app.velox.vpn.core.countryFlag
import app.velox.vpn.core.formatBytesRu
import app.velox.vpn.core.formatDuration
import app.velox.vpn.core.formatEtaRu
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
    snackbarHostState: SnackbarHostState,
    onToggleVpn: () -> Unit,
    onRetryFreshVpn: () -> Unit,
    onSelectRegion: (String) -> Unit,
    onSelectNode: (VpnNode) -> Unit,
    onRotateNode: () -> Unit,
    onRefreshVpn: () -> Unit,
    onUpdateSettings: ((AppSettings) -> AppSettings, Boolean) -> Unit,
    onRefreshTg: () -> Unit,
    onToggleTgBridge: (Boolean) -> Unit,
    onOpenTgLink: (String, String) -> Unit,
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
                onSelect = { tab = it }
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
                    customSubs = remember(snapshot.sources) { snapshot.sources.filter { !it.builtin } },
                    verifiedCount = snapshot.deviceVerifiedCount,
                    whitelistVerifiedCount = snapshot.whitelistVerifiedCount,
                    isRefreshing = isRefreshingVpn,
                    isBusyImport = isBusyImport,
                    manualProgress = manualProgress,
                    onToggleVpn = onToggleVpn,
                    onRetryFreshVpn = onRetryFreshVpn,
                    onSelectRegion = onSelectRegion,
                    onSelectNode = onSelectNode,
                    onRotateNode = onRotateNode,
                    onRefreshVpn = onRefreshVpn,
                    onOpenLogs = { showLogsDialog = true },
                    onOpenImportSub = {
                        importKindHint = "vpn"
                        showImportDialog = true
                    },
                    onSyncSource = onSyncSource,
                    onRemoveSource = onRemoveSource,
                    onUpdateSettings = onUpdateSettings,
                )

                1 -> TelegramTabContent(
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

                2 -> SettingsTabContent(
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
private fun VeloxTopBar(
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
                        text = "1.2",
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
                    text = "США · Германия · Прокси Telegram",
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
private fun VeloxBottomBar(
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
                    NavVectorIcon(kind = 1, active = selectedTab == 1)
                },
                label = {
                    Text(
                        text = if (tgCount > 0) "Telegram ($tgCount)" else "Telegram",
                        style = MaterialTheme.typography.labelMedium,
                        maxLines = 1,
                    )
                }
            )

            NavigationBarItem(
                selected = selectedTab == 2,
                onClick = { onSelect(2) },
                colors = itemColors,
                icon = {
                    NavVectorIcon(kind = 2, active = selectedTab == 2)
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
private fun VpnTabContent(
    settings: AppSettings,
    runtime: VpnRuntimeState,
    nodes: List<VpnNode>,
    customSubs: List<SubSourceItem>,
    verifiedCount: Int,
    whitelistVerifiedCount: Int,
    isRefreshing: Boolean,
    isBusyImport: Boolean,
    manualProgress: LiveProgressUpdate?,
    onToggleVpn: () -> Unit,
    onRetryFreshVpn: () -> Unit,
    onSelectRegion: (String) -> Unit,
    onSelectNode: (VpnNode) -> Unit,
    onRotateNode: () -> Unit,
    onRefreshVpn: () -> Unit,
    onOpenLogs: () -> Unit,
    onOpenImportSub: () -> Unit,
    onSyncSource: (String) -> Unit,
    onRemoveSource: (String) -> Unit,
    onUpdateSettings: ((AppSettings) -> AppSettings, Boolean) -> Unit,
) {
    // Tick once per second while actively connected OR connecting/probing (for smooth ETA countdown)
    var nowMs by remember { mutableLongStateOf(System.currentTimeMillis()) }
    LaunchedEffect(runtime.phase, runtime.connectedSinceMs, isRefreshing) {
        while (runtime.isActiveOrBusy || isRefreshing) {
            nowMs = System.currentTimeMillis()
            delay(1000L)
        }
    }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(horizontal = 16.dp, vertical = 8.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        // 1. Country selector: USA / Germany / Auto
        item {
            RegionSelectorBar(
                selected = settings.region,
                onSelect = onSelectRegion,
            )
        }

        // 2. Hero Connect Card (with live progress bar + approximate remaining time)
        item {
            VpnHeroCard(
                runtime = runtime,
                nowMs = nowMs,
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

        // 3. Fast RF anti-block quick toggles
        item {
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
                            CustomSubCompactRow(
                                sub = sub,
                                busy = isBusyImport,
                                onSync = { onSyncSource(sub.url) },
                                onRemove = { onRemoveSource(sub.url) },
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
                Column {
                    val liveInList = nodes.count { it.deviceVerified }
                    Text(
                        text = if (liveInList > 0) {
                            "Рабочие серверы ($liveInList пров. · всего ${nodes.size})"
                        } else {
                            "Стартовый пул (${nodes.size}) · проверится при старте"
                        },
                        style = MaterialTheme.typography.titleSmall,
                        color = TextHigh,
                    )
                    Text(
                        text = if (settings.pinnedNodeId.isEmpty()) {
                            "Автовыбор лучшего + горячий резерв"
                        } else {
                            "Узел закреплён · нажмите ещё раз для автовыбора"
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = TextLow,
                    )
                }
                TextButton(
                    onClick = onRefreshVpn,
                    enabled = !isRefreshing,
                    contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp),
                ) {
                    Text(
                        text = if (isRefreshing) "Проверка…" else "↻ Обновить",
                        style = MaterialTheme.typography.labelMedium,
                        color = EmeraldPrimary,
                    )
                }
            }
        }

        if (nodes.isEmpty()) {
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
                            text = "Нажмите кнопку подключения или «↻ Обновить»",
                            style = MaterialTheme.typography.titleSmall,
                            color = TextHigh,
                            textAlign = TextAlign.Center,
                        )
                        Spacer(Modifier.height(4.dp))
                        Text(
                            text = "Движок автоматически подгрузит и проверит бесплатные узлы США и Германии (VLESS Reality, XHTTP, Hysteria2, Opera, WARP MASQUE).",
                            style = MaterialTheme.typography.bodySmall,
                            color = TextMedium,
                            textAlign = TextAlign.Center,
                        )
                    }
                }
            }
        } else {
            items(nodes, key = { it.id }) { node ->
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
private fun RegionSelectorBar(
    selected: String,
    onSelect: (String) -> Unit,
) {
    val options = listOf(
        "US" to "🇺🇸 США",
        "DE" to "🇩🇪 Германия",
        "AUTO" to "⚡ Авто",
    )
    Surface(
        shape = RoundedCornerShape(14.dp),
        color = SurfaceCard,
        border = BorderStroke(1.dp, SurfaceStroke),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(4.dp),
            horizontalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            for ((code, label) in options) {
                val active = selected.equals(code, ignoreCase = true)
                Box(
                    modifier = Modifier
                        .weight(1f)
                        .clip(RoundedCornerShape(10.dp))
                        .background(if (active) EmeraldDim else Color.Transparent)
                        .border(
                            width = if (active) 1.dp else 0.dp,
                            color = if (active) EmeraldPrimary.copy(alpha = 0.65f) else Color.Transparent,
                            shape = RoundedCornerShape(10.dp)
                        )
                        .clickable { onSelect(code) }
                        .padding(vertical = 10.dp),
                    contentAlignment = Alignment.Center,
                ) {
                    Text(
                        text = label,
                        style = MaterialTheme.typography.titleSmall,
                        color = if (active) EmeraldPrimary else TextMedium,
                        maxLines = 1,
                    )
                }
            }
        }
    }
}

@Composable
private fun VpnHeroCard(
    runtime: VpnRuntimeState,
    nowMs: Long,
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
                // Live telemetry strip: Timer | Ping | Downlink | Uplink
                val elapsed = if (runtime.connectedSinceMs > 0L) {
                    (nowMs - runtime.connectedSinceMs).coerceAtLeast(0L)
                } else 0L

                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(12.dp))
                        .background(BgObsidian.copy(alpha = 0.55f))
                        .padding(vertical = 10.dp, horizontal = 8.dp),
                    horizontalArrangement = Arrangement.SpaceEvenly,
                ) {
                    MetricCell("Время", formatDuration(elapsed), TextHigh)
                    MetricCell(
                        "Отклик",
                        if (runtime.rttMs > 0) "${runtime.rttMs} мс" else "—",
                        rttColor(runtime.rttMs)
                    )
                    MetricCell("↓ Приём", formatBytesRu(runtime.downlinkBytes), CyanAccent)
                    MetricCell("↑ Отдача", formatBytesRu(runtime.uplinkBytes), EmeraldPrimary)
                }

                if (runtime.exitIp.isNotBlank() || runtime.backupCount > 0) {
                    Spacer(Modifier.height(8.dp))
                    Text(
                        text = buildString {
                            if (runtime.exitIp.isNotBlank()) {
                                append("IP: ${runtime.exitIp}")
                            }
                            if (runtime.exitColo.isNotBlank()) {
                                append(" (${runtime.exitColo})")
                            }
                            if (runtime.backupCount > 0) {
                                append(" · Горячий резерв: ${runtime.backupCount}")
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
private fun MetricCell(label: String, value: String, valueColor: Color) {
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
private fun QuickModeTile(
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
private fun VpnNodeCard(
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

// ============================================================================
// TAB 2: TELEGRAM PROXIES (Authentic DC resPQ <= 1400 ms + Local TG-WS Bridge)
// ============================================================================

@Composable
private fun TelegramTabContent(
    settings: AppSettings,
    proxies: List<TgProxy>,
    tgStatus: TgBridgeStatus,
    isRefreshing: Boolean,
    onRefreshTg: () -> Unit,
    onToggleBridge: (Boolean) -> Unit,
    onOpenTgLink: (String, String) -> Unit,
    onCopy: (String, String) -> Unit,
    onShare: (String) -> Unit,
    onOpenAddProxy: () -> Unit,
) {
    var filter by rememberSaveable { mutableStateOf("all") }

    val filtered = remember(proxies, filter, settings.tgMaxRttMs) {
        proxies.filter { p ->
            p.rttMs <= settings.tgMaxRttMs && when (filter) {
                "faketls" -> p.kind == "faketls"
                "mtproto" -> p.kind == "dd" || p.kind == "classic"
                "socks5" -> p.kind == "socks5"
                else -> true
            }
        }
    }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(horizontal = 16.dp, vertical = 8.dp),
        verticalArrangement = Arrangement.spacedBy(11.dp),
    ) {
        // 1. Smart Auto-Failover Local Proxy + TG-WS Bridge Card
        item {
            TgSmartBridgeCard(
                status = tgStatus,
                maxRttMs = settings.tgMaxRttMs,
                onToggle = onToggleBridge,
                onConnectTelegram = {
                    val port = tgStatus.bridgePort.takeIf { it > 0 } ?: 10809
                    onOpenTgLink(
                        "tg://socks?server=127.0.0.1&port=$port",
                        "https://t.me/socks?server=127.0.0.1&port=$port"
                    )
                },
                onCopy = {
                    val port = tgStatus.bridgePort.takeIf { it > 0 } ?: 10809
                    onCopy("tg://socks?server=127.0.0.1&port=$port", "Ссылка локального прокси скопирована")
                }
            )
        }

        // 2. Live Fetch & Authentic Telegram DC Verification Card
        item {
            Surface(
                shape = RoundedCornerShape(16.dp),
                color = SurfaceCard,
                border = BorderStroke(1.dp, SurfaceStroke),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Column(modifier = Modifier.padding(14.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = "Реальная проверка DC Telegram",
                                style = MaterialTheme.typography.titleSmall,
                                color = TextHigh,
                            )
                            Text(
                                text = "MTProto resPQ к серверам Telegram · строго ≤ ${settings.tgMaxRttMs} мс",
                                style = MaterialTheme.typography.bodySmall,
                                color = TextMedium,
                            )
                        }
                    }

                    if (isRefreshing) {
                        Spacer(Modifier.height(10.dp))
                        val progress = if (tgStatus.total > 0) {
                            (tgStatus.checked.toFloat() / tgStatus.total.toFloat()).coerceIn(0f, 1f)
                        } else 0f
                        if (tgStatus.total > 0) {
                            LinearProgressIndicator(
                                progress = { progress },
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .height(5.dp)
                                    .clip(RoundedCornerShape(3.dp)),
                                color = EmeraldPrimary,
                                trackColor = SurfaceElevated,
                            )
                            Spacer(Modifier.height(6.dp))
                            val remItems = (tgStatus.total - tgStatus.checked).coerceAtLeast(0)
                            val tgEtaSec = ((remItems * 12) / tgStatus.total.coerceAtLeast(1)).coerceAtLeast(1)
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                            ) {
                                Text(
                                    text = "Проверено: ${tgStatus.checked}/${tgStatus.total} · Рабочих: ${tgStatus.alive}",
                                    style = MaterialTheme.typography.labelSmall,
                                    color = EmeraldPrimary,
                                )
                                Text(
                                    text = "Осталось ${formatEtaRu(tgEtaSec)}",
                                    style = MaterialTheme.typography.labelSmall,
                                    color = CyanAccent,
                                )
                            }
                        } else {
                            LinearProgressIndicator(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .height(5.dp)
                                    .clip(RoundedCornerShape(3.dp)),
                                color = EmeraldPrimary,
                                trackColor = SurfaceElevated,
                            )
                            Spacer(Modifier.height(6.dp))
                            Text(
                                text = "Загрузка списков Fake-TLS / MTProto / SOCKS5 · осталось ≈ 12 сек",
                                style = MaterialTheme.typography.labelSmall,
                                color = CyanAccent,
                            )
                        }
                    }

                    Spacer(Modifier.height(11.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        Button(
                            onClick = onRefreshTg,
                            enabled = !isRefreshing,
                            modifier = Modifier.weight(1f),
                            shape = RoundedCornerShape(11.dp),
                            colors = ButtonDefaults.buttonColors(
                                containerColor = EmeraldPrimary,
                                contentColor = Color(0xFF002116),
                            ),
                            contentPadding = PaddingValues(vertical = 11.dp),
                        ) {
                            Text(
                                text = if (isRefreshing) "Идёт проверка DC…" else "Найти и проверить прокси",
                                style = MaterialTheme.typography.titleSmall,
                            )
                        }
                        OutlinedButton(
                            onClick = onOpenAddProxy,
                            shape = RoundedCornerShape(11.dp),
                            border = BorderStroke(1.dp, SurfaceStroke),
                            contentPadding = PaddingValues(horizontal = 14.dp, vertical = 11.dp),
                        ) {
                            Text("Свой", style = MaterialTheme.typography.labelMedium, color = TextHigh)
                        }
                    }
                }
            }
        }

        // 3. Protocol Filter Chips
        item {
            val faketlsCnt = proxies.count { it.kind == "faketls" && it.rttMs <= settings.tgMaxRttMs }
            val mtpCnt = proxies.count { (it.kind == "dd" || it.kind == "classic") && it.rttMs <= settings.tgMaxRttMs }
            val s5Cnt = proxies.count { it.kind == "socks5" && it.rttMs <= settings.tgMaxRttMs }
            val chips = listOf(
                "all" to "Все (${proxies.count { it.rttMs <= settings.tgMaxRttMs }})",
                "faketls" to "Fake-TLS ($faketlsCnt)",
                "mtproto" to "MTProto ($mtpCnt)",
                "socks5" to "SOCKS5 · Звонки ($s5Cnt)",
            )
            LazyRow(horizontalArrangement = Arrangement.spacedBy(7.dp)) {
                items(chips) { (key, label) ->
                    val sel = filter == key
                    FilterChip(
                        selected = sel,
                        onClick = { filter = key },
                        label = { Text(label, style = MaterialTheme.typography.labelMedium) },
                        colors = FilterChipDefaults.filterChipColors(
                            selectedContainerColor = EmeraldDim,
                            selectedLabelColor = EmeraldPrimary,
                            containerColor = SurfaceCard,
                            labelColor = TextMedium,
                        ),
                        border = FilterChipDefaults.filterChipBorder(
                            enabled = true,
                            selected = sel,
                            borderColor = SurfaceStroke,
                            selectedBorderColor = EmeraldPrimary.copy(alpha = 0.6f),
                        )
                    )
                }
            }
        }

        // 4. Verified <= 1400 ms Proxy List
        if (filtered.isEmpty()) {
            item {
                Surface(
                    shape = RoundedCornerShape(14.dp),
                    color = SurfaceCard,
                    border = BorderStroke(1.dp, SurfaceStroke),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(
                        text = "В этой категории пока нет прокси — нажмите «Найти и проверить прокси».",
                        style = MaterialTheme.typography.bodySmall,
                        color = TextMedium,
                        modifier = Modifier.padding(18.dp),
                        textAlign = TextAlign.Center,
                    )
                }
            }
        } else {
            items(filtered, key = { it.id }) { proxy ->
                TgProxyCard(
                    proxy = proxy,
                    onConnect = { onOpenTgLink(proxy.tgLink, proxy.tmeLink) },
                    onCopy = { onCopy(proxy.tgLink, "Прокси скопирован (${proxy.rttMs} мс)") },
                    onShare = { onShare(proxy.tmeLink) },
                )
            }
        }

        item { Spacer(Modifier.height(8.dp)) }
    }
}

@Composable
private fun TgSmartBridgeCard(
    status: TgBridgeStatus,
    maxRttMs: Int,
    onToggle: (Boolean) -> Unit,
    onConnectTelegram: () -> Unit,
    onCopy: () -> Unit,
) {
    val active = status.bridgeRunning
    Surface(
        shape = RoundedCornerShape(18.dp),
        color = if (active) Color(0xFF0D2230) else SurfaceCard,
        border = BorderStroke(
            1.dp,
            if (active) CyanAccent.copy(alpha = 0.65f) else SurfaceStroke
        ),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(modifier = Modifier.padding(15.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            text = "Умный авто-прокси + TG-WS",
                            style = MaterialTheme.typography.titleMedium,
                            color = TextHigh,
                        )
                    }
                    Spacer(Modifier.height(2.dp))
                    Text(
                        text = if (active) {
                            buildString {
                                append("Активен на 127.0.0.1:${status.bridgePort}")
                                if (status.wsAvailable && status.wsRttMs > 0) {
                                    append(" · TG-WS: ${status.wsRttMs} мс")
                                }
                                if (status.bridgeBytes > 0L) {
                                    append(" · ${formatBytesRu(status.bridgeBytes)}")
                                }
                            }
                        } else {
                            "Работает без VPN · прямой WebSocket 443 к Telegram + автосмена прокси ≤$maxRttMs мс"
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = if (active) CyanAccent else TextMedium,
                    )
                }
                Spacer(Modifier.width(8.dp))
                Switch(
                    checked = active,
                    onCheckedChange = onToggle,
                    colors = SwitchDefaults.colors(
                        checkedThumbColor = BgObsidian,
                        checkedTrackColor = CyanAccent,
                    )
                )
            }

            if (active) {
                Spacer(Modifier.height(11.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Button(
                        onClick = onConnectTelegram,
                        modifier = Modifier.weight(1f),
                        shape = RoundedCornerShape(10.dp),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = CyanAccent,
                            contentColor = Color(0xFF001F2A),
                        ),
                        contentPadding = PaddingValues(vertical = 9.dp),
                    ) {
                        Text("Включить в Telegram", style = MaterialTheme.typography.titleSmall)
                    }
                    OutlinedButton(
                        onClick = onCopy,
                        shape = RoundedCornerShape(10.dp),
                        border = BorderStroke(1.dp, SurfaceStroke),
                        contentPadding = PaddingValues(horizontal = 12.dp, vertical = 9.dp),
                    ) {
                        Text("Копир.", style = MaterialTheme.typography.labelMedium, color = TextHigh)
                    }
                }
            }
        }
    }
}

@Composable
private fun TgProxyCard(
    proxy: TgProxy,
    onConnect: () -> Unit,
    onCopy: () -> Unit,
    onShare: () -> Unit,
) {
    Surface(
        shape = RoundedCornerShape(14.dp),
        color = SurfaceCard,
        border = BorderStroke(1.dp, SurfaceStroke),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(modifier = Modifier.padding(horizontal = 14.dp, vertical = 12.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Row(
                    modifier = Modifier.weight(1f),
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    val (badgeBg, badgeFg) = when (proxy.kind) {
                        "faketls" -> EmeraldDim to EmeraldPrimary
                        "socks5" -> CyanDim to CyanAccent
                        else -> SurfaceElevated to TextHigh
                    }
                    BadgePill(proxy.kindLabel, badgeBg, badgeFg)
                    if (proxy.supportsCalls) {
                        BadgePill("Звонки", CyanDim, CyanAccent)
                    }
                    if (proxy.sniDomain.isNotBlank()) {
                        Text(
                            text = "SNI: ${proxy.sniDomain}",
                            style = MaterialTheme.typography.labelSmall,
                            color = TextMedium,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
                }

                Spacer(Modifier.width(8.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        text = "${proxy.rttMs} мс",
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Bold,
                        color = rttColor(proxy.rttMs),
                    )
                    if (proxy.jitterMs > 0) {
                        Text(
                            text = " ±${proxy.jitterMs}",
                            style = MaterialTheme.typography.labelSmall,
                            color = TextLow,
                        )
                    }
                }
            }

            Spacer(Modifier.height(5.dp))
            Text(
                text = "${proxy.host}:${proxy.port} · DC${proxy.verifiedDc} проверен",
                style = MaterialTheme.typography.labelSmall,
                color = TextLow,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )

            Spacer(Modifier.height(9.dp))
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Button(
                    onClick = onConnect,
                    modifier = Modifier.weight(1f),
                    shape = RoundedCornerShape(10.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = EmeraldDim,
                        contentColor = EmeraldPrimary,
                    ),
                    border = BorderStroke(1.dp, EmeraldPrimary.copy(alpha = 0.45f)),
                    contentPadding = PaddingValues(vertical = 8.dp),
                ) {
                    Text("Подключить в Telegram", style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.SemiBold)
                }
                OutlinedButton(
                    onClick = onCopy,
                    shape = RoundedCornerShape(10.dp),
                    border = BorderStroke(1.dp, SurfaceStroke),
                    contentPadding = PaddingValues(horizontal = 11.dp, vertical = 8.dp),
                ) {
                    Text("Копир.", style = MaterialTheme.typography.labelSmall, color = TextHigh)
                }
                OutlinedButton(
                    onClick = onShare,
                    shape = RoundedCornerShape(10.dp),
                    border = BorderStroke(1.dp, SurfaceStroke),
                    contentPadding = PaddingValues(horizontal = 11.dp, vertical = 8.dp),
                ) {
                    Text("↗", style = MaterialTheme.typography.labelMedium, color = TextHigh)
                }
            }
        }
    }
}

// ============================================================================
// TAB 3: SETTINGS (Anti-DPI, RAM Profile, Split Tunnel, WARP/Opera, Sources, Logs)
// ============================================================================

@Composable
private fun SettingsTabContent(
    settings: AppSettings,
    snapshot: EngineSnapshot,
    isBusyWarp: Boolean,
    isBusyImport: Boolean,
    batteryIgnored: Boolean,
    onUpdateSettings: ((AppSettings) -> AppSettings, Boolean) -> Unit,
    onOpenImport: (String) -> Unit,
    onToggleSource: (String, Boolean) -> Unit,
    onSyncSource: (String) -> Unit,
    onRemoveSource: (String) -> Unit,
    onRegenerateWarp: () -> Unit,
    onRequestIgnoreBattery: () -> Unit,
    onOpenSplitApps: () -> Unit,
    onOpenLogsDialog: () -> Unit,
    onCopy: (String, String) -> Unit,
    onFormatDiagExport: (List<String>) -> String,
    onClearLogs: () -> Unit,
) {
    var showSources by rememberSaveable { mutableStateOf(false) }
    var showLogs by rememberSaveable { mutableStateOf(false) }
    var rttSlider by remember(settings.tgMaxRttMs) {
        mutableFloatStateOf(settings.tgMaxRttMs.toFloat())
    }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(horizontal = 16.dp, vertical = 8.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        // 1. Performance & Memory Profile
        item {
            SettingsCard(title = "Производительность и расход ОЗУ") {
                for (mode in RuntimeProfileMode.entries) {
                    val selected = settings.profileMode == mode
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(10.dp))
                            .background(if (selected) EmeraldDim.copy(alpha = 0.65f) else Color.Transparent)
                            .clickable {
                                onUpdateSettings({ it.copy(profileMode = mode) }, true)
                            }
                            .padding(horizontal = 10.dp, vertical = 9.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween,
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = mode.title,
                                style = MaterialTheme.typography.titleSmall,
                                color = if (selected) EmeraldPrimary else TextHigh,
                            )
                            Text(
                                text = mode.subtitle,
                                style = MaterialTheme.typography.bodySmall,
                                color = TextMedium,
                            )
                        }
                        if (selected) {
                            BadgePill("ВЫБРАНО", EmeraldDim, EmeraldPrimary)
                        }
                    }
                }

                if (!batteryIgnored) {
                    Spacer(Modifier.height(8.dp))
                    OutlinedButton(
                        onClick = onRequestIgnoreBattery,
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(10.dp),
                        border = BorderStroke(1.dp, AmberWarn.copy(alpha = 0.5f)),
                    ) {
                        Text(
                            text = "Отключить экономию батареи для стабильного фона",
                            style = MaterialTheme.typography.labelMedium,
                            color = AmberWarn,
                        )
                    }
                }
            }
        }

        // 2. Anti-DPI (TSPU) & Auto-Healing
        item {
            SettingsCard(title = "Обход блокировок ТСПУ и автозащита") {
                SettingSwitchRow(
                    title = "Фрагментация TLS ClientHello",
                    subtitle = "Дробит SNI-пакет (finalmask) против DPI провайдеров",
                    checked = settings.fragmentTls,
                    onCheckedChange = { v -> onUpdateSettings({ it.copy(fragmentTls = v) }, true) }
                )
                HorizontalDivider(color = SurfaceStroke.copy(alpha = 0.5f))
                SettingSwitchRow(
                    title = "Режим белых списков РФ",
                    subtitle = "Приоритет российских SNI при ограничениях мобильного интернета",
                    checked = settings.whitelistMode,
                    onCheckedChange = { v ->
                        onUpdateSettings({ it.copy(whitelistMode = v, pinnedNodeId = "") }, true)
                    }
                )
                HorizontalDivider(color = SurfaceStroke.copy(alpha = 0.5f))
                SettingSwitchRow(
                    title = "Автовосстановление и смена узла",
                    subtitle = "Проверяет туннель (включая блок 16 КБ) и сам подгружает рабочие узлы",
                    checked = settings.autoHeal,
                    onCheckedChange = { v -> onUpdateSettings({ it.copy(autoHeal = v) }, false) }
                )
            }
        }

        // 3. Split Tunneling
        item {
            SettingsCard(title = "Раздельное туннелирование") {
                SettingSwitchRow(
                    title = "Банки, Госуслуги и РФ без VPN",
                    subtitle = "Сбер, Т-Банк, ВТБ, Альфа, Мир Pay, Госуслуги, Ozon, WB, Яндекс, домены .ru/.рф",
                    checked = settings.bypassRu,
                    onCheckedChange = { v -> onUpdateSettings({ it.copy(bypassRu = v) }, true) }
                )
                Spacer(Modifier.height(8.dp))
                OutlinedButton(
                    onClick = onOpenSplitApps,
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(10.dp),
                    border = BorderStroke(1.dp, SurfaceStroke),
                ) {
                    val cnt = settings.excludedPackages.size
                    Text(
                        text = if (cnt > 0) "Исключённые приложения: $cnt (изменить)" else "Выбрать приложения без VPN",
                        style = MaterialTheme.typography.labelMedium,
                        color = TextHigh,
                    )
                }
            }
        }

        // 4. Telegram RTT Threshold
        item {
            SettingsCard(title = "Фильтр отклика прокси Telegram") {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                    Text(
                        text = "Макс. время ответа DC Telegram",
                        style = MaterialTheme.typography.bodyMedium,
                        color = TextHigh,
                    )
                    Text(
                        text = "≤ ${rttSlider.toInt()} мс",
                        style = MaterialTheme.typography.titleSmall,
                        color = EmeraldPrimary,
                    )
                }
                Slider(
                    value = rttSlider,
                    onValueChange = { rttSlider = (it / 50f).toInt() * 50f },
                    onValueChangeFinished = {
                        onUpdateSettings({ it.copy(tgMaxRttMs = rttSlider.toInt().coerceIn(400, 1400)) }, false)
                    },
                    valueRange = 400f..1400f,
                )
                Text(
                    text = "Все медленные и фейковые прокси выше порога (максимум 1400 мс) отбрасываются автоматически.",
                    style = MaterialTheme.typography.labelSmall,
                    color = TextLow,
                )
            }
        }

        // 5. Built-in Free Echelons (WARP MASQUE/AWG + Opera US/EU)
        item {
            SettingsCard(title = "Встроенные бесплатные эшелоны (без аккаунта)") {
                Text(
                    text = buildString {
                        append("• Эшелон 1: VLESS Reality / XHTTP / Hysteria2 (США и Германия)\n")
                        append("• Эшелон 2: Opera HTTPS TLS US/EU (активных: ${snapshot.operaCount})\n")
                        append("• Эшелон 3: Cloudflare WARP ")
                        if (snapshot.hasWarpWg || snapshot.hasWarpMasque) {
                            append("готов (${snapshot.warpIpv4}, MASQUE H3/H2 + AWG Noise)")
                        } else {
                            append("(выпускается автоматически при обновлении)")
                        }
                    },
                    style = MaterialTheme.typography.bodySmall,
                    color = TextMedium,
                )
                Spacer(Modifier.height(10.dp))
                OutlinedButton(
                    onClick = onRegenerateWarp,
                    enabled = !isBusyWarp,
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(10.dp),
                    border = BorderStroke(1.dp, SurfaceStroke),
                ) {
                    Text(
                        text = if (isBusyWarp) "Регистрация WARP + MASQUE…" else "Перевыпустить ключи WARP + MASQUE",
                        style = MaterialTheme.typography.labelMedium,
                        color = CyanAccent,
                    )
                }
            }
        }

        // 6. Auto-Update Sources & Custom Subscriptions
        item {
            val customSubs = remember(snapshot.sources) { snapshot.sources.filter { !it.builtin } }
            val builtinSubs = remember(snapshot.sources) { snapshot.sources.filter { it.builtin } }
            SettingsCard(
                title = "Мои подписки и источники (${snapshot.sources.count { it.enabled }}/${snapshot.sources.size})"
            ) {
                Text(
                    text = "Умное дельта-обновление: рабочие серверы и прокси сохраняются, нерабочие удаляются, новые догружаются автоматически.",
                    style = MaterialTheme.typography.labelSmall,
                    color = TextMedium,
                )
                Spacer(Modifier.height(8.dp))
                if (customSubs.isNotEmpty()) {
                    customSubs.forEach { sub ->
                        CustomSubCompactRow(
                            sub = sub,
                            busy = isBusyImport,
                            onSync = { onSyncSource(sub.url) },
                            onRemove = { onRemoveSource(sub.url) },
                        )
                        Spacer(Modifier.height(6.dp))
                    }
                }
                if (snapshot.customVpnCount > 0) {
                    Text(
                        text = "Отдельных VPN-ключей: ${snapshot.customVpnCount}",
                        style = MaterialTheme.typography.bodySmall,
                        color = EmeraldPrimary,
                    )
                    Spacer(Modifier.height(6.dp))
                }
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Button(
                        onClick = { onOpenImport("auto") },
                        enabled = !isBusyImport,
                        modifier = Modifier.weight(1f),
                        shape = RoundedCornerShape(10.dp),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = EmeraldDim,
                            contentColor = EmeraldPrimary,
                        ),
                    ) {
                        Text(
                            if (isBusyImport) "Загрузка…" else "+ Подписка / ключ",
                            style = MaterialTheme.typography.labelMedium
                        )
                    }
                    OutlinedButton(
                        onClick = { showSources = !showSources },
                        shape = RoundedCornerShape(10.dp),
                        border = BorderStroke(1.dp, SurfaceStroke),
                    ) {
                        Text(
                            if (showSources) "Скрыть" else "Фиды (${builtinSubs.size})",
                            style = MaterialTheme.typography.labelMedium,
                            color = TextHigh
                        )
                    }
                }

                if (showSources) {
                    Spacer(Modifier.height(8.dp))
                    builtinSubs.forEach { src ->
                        SourceRow(src = src, onToggle = { en -> onToggleSource(src.url, en) })
                    }
                }
            }
        }

        // 7. Rust Engine Diagnostic Log & About
        item {
            SettingsCard(title = "Подробные логи и о приложении") {
                Text(
                    text = "VeloxVPN 1.3.0 · Ядро xray-rust 0.10.0 + velox-engine (100% Rust)\n" +
                        "Белые списки РФ (Минцифры SNI + CIDR) · MASQUE-Chain US/DE · 41 источник · Подписки\n" +
                        "Умное дельта-обновление · Android 7.0–16 · Без рекламы и аккаунтов",
                    style = MaterialTheme.typography.bodySmall,
                    color = TextMedium,
                )
                Spacer(Modifier.height(10.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(7.dp),
                ) {
                    Button(
                        onClick = onOpenLogsDialog,
                        modifier = Modifier.weight(1f),
                        shape = RoundedCornerShape(10.dp),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = SurfaceElevated,
                            contentColor = EmeraldPrimary,
                        ),
                        border = BorderStroke(1.dp, EmeraldPrimary.copy(alpha = 0.45f)),
                        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 9.dp),
                    ) {
                        Text(
                            "Журнал (${snapshot.logs.size})",
                            style = MaterialTheme.typography.labelMedium,
                            maxLines = 1,
                        )
                    }
                    OutlinedButton(
                        onClick = {
                            onCopy(
                                onFormatDiagExport(snapshot.logs),
                                "Подробный лог (${snapshot.logs.size} строк) скопирован"
                            )
                        },
                        shape = RoundedCornerShape(10.dp),
                        border = BorderStroke(1.dp, SurfaceStroke),
                        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 9.dp),
                    ) {
                        Text("Копировать", style = MaterialTheme.typography.labelMedium, color = CyanAccent)
                    }
                    if (snapshot.logs.size > 1) {
                        OutlinedButton(
                            onClick = onClearLogs,
                            shape = RoundedCornerShape(10.dp),
                            border = BorderStroke(1.dp, SurfaceStroke),
                            contentPadding = PaddingValues(horizontal = 10.dp, vertical = 9.dp),
                        ) {
                            Text("Очистить", style = MaterialTheme.typography.labelMedium, color = TextLow)
                        }
                    }
                }
                if (snapshot.logs.isNotEmpty()) {
                    Spacer(Modifier.height(8.dp))
                    TextButton(
                        onClick = { showLogs = !showLogs },
                        contentPadding = PaddingValues(horizontal = 4.dp, vertical = 2.dp),
                    ) {
                        Text(
                            if (showLogs) "▴ Скрыть последние записи" else "▾ Показать последние 20 записей здесь",
                            style = MaterialTheme.typography.labelSmall,
                            color = TextMedium,
                        )
                    }
                }
                if (showLogs && snapshot.logs.isNotEmpty()) {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(10.dp))
                            .background(BgObsidian)
                            .border(1.dp, SurfaceStroke, RoundedCornerShape(10.dp))
                            .padding(10.dp)
                    ) {
                        Column(verticalArrangement = Arrangement.spacedBy(3.dp)) {
                            snapshot.logs.takeLast(20).forEach { line ->
                                Text(
                                    text = line,
                                    fontFamily = FontFamily.Monospace,
                                    fontSize = 10.5.sp,
                                    lineHeight = 14.sp,
                                    color = diagLineColor(line),
                                )
                            }
                        }
                    }
                }
            }
        }

        item { Spacer(Modifier.height(8.dp)) }
    }
}

@Composable
private fun SettingsCard(
    title: String,
    content: @Composable () -> Unit,
) {
    Surface(
        shape = RoundedCornerShape(16.dp),
        color = SurfaceCard,
        border = BorderStroke(1.dp, SurfaceStroke),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(modifier = Modifier.padding(15.dp)) {
            Text(
                text = title,
                style = MaterialTheme.typography.titleSmall,
                color = EmeraldPrimary,
            )
            Spacer(Modifier.height(10.dp))
            content()
        }
    }
}

@Composable
private fun SettingSwitchRow(
    title: String,
    subtitle: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onCheckedChange(!checked) }
            .padding(vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.titleSmall, color = TextHigh)
            Text(subtitle, style = MaterialTheme.typography.bodySmall, color = TextMedium)
        }
        Spacer(Modifier.width(10.dp))
        Switch(
            checked = checked,
            onCheckedChange = onCheckedChange,
            colors = SwitchDefaults.colors(
                checkedThumbColor = BgObsidian,
                checkedTrackColor = EmeraldPrimary,
            )
        )
    }
}

@Composable
private fun CustomSubCompactRow(
    sub: SubSourceItem,
    busy: Boolean,
    onSync: () -> Unit,
    onRemove: () -> Unit,
) {
    Surface(
        shape = RoundedCornerShape(10.dp),
        color = SurfaceElevated,
        border = BorderStroke(1.dp, SurfaceStroke),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 10.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = sub.name,
                    style = MaterialTheme.typography.titleSmall,
                    color = TextHigh,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                val meta = buildString {
                    if (sub.cachedCount > 0) {
                        append(if (sub.kind == "tg") "${sub.cachedCount} прокси" else "${sub.cachedCount} серверов")
                    } else {
                        append("Нажмите ↻ для загрузки")
                    }
                    if (sub.userinfo.isNotBlank()) {
                        append(" · ${sub.userinfo}")
                    }
                }
                Text(
                    text = meta,
                    style = MaterialTheme.typography.labelSmall,
                    color = EmeraldPrimary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            Row(horizontalArrangement = Arrangement.spacedBy(2.dp)) {
                TextButton(
                    onClick = onSync,
                    enabled = !busy,
                    contentPadding = PaddingValues(horizontal = 8.dp, vertical = 4.dp),
                ) {
                    Text("↻", style = MaterialTheme.typography.titleSmall, color = CyanAccent)
                }
                TextButton(
                    onClick = onRemove,
                    enabled = !busy,
                    contentPadding = PaddingValues(horizontal = 8.dp, vertical = 4.dp),
                ) {
                    Text("✕", style = MaterialTheme.typography.labelMedium, color = CoralError)
                }
            }
        }
    }
}

@Composable
private fun SourceRow(src: SubSourceItem, onToggle: (Boolean) -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 5.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                BadgePill(
                    text = if (src.kind == "tg") "TG" else src.regionHint,
                    bg = SurfaceElevated,
                    fg = if (src.kind == "tg") CyanAccent else EmeraldPrimary,
                )
                Spacer(Modifier.width(6.dp))
                Text(
                    text = src.name,
                    style = MaterialTheme.typography.labelMedium,
                    color = TextHigh,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }
        Switch(
            checked = src.enabled,
            onCheckedChange = onToggle,
        )
    }
}

// ============================================================================
// DIALOGS (Universal Key/Proxy/Subscription Import + Per-App Split Tunneling)
// ============================================================================

@Composable
private fun UniversalImportDialog(
    initialHint: String,
    onDismiss: () -> Unit,
    onPasteClipboard: () -> String,
    onSubmit: (String, String) -> Unit,
) {
    var input by remember { mutableStateOf("") }
    var subKind by remember { mutableStateOf(if (initialHint == "tg_proxy") "tg" else "vpn") }

    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = SurfaceCard,
        title = {
            Text("Добавить подписку, ключ или прокси", style = MaterialTheme.typography.titleMedium, color = TextHigh)
        },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    text = "Поддерживаются любые https:// подписки (Remnawave, Marzban, Happ, 3x-ui, Hiddify и др.), happ://, v2raytun://, vless://, vmess://, hy2://, trojan://, ss://, tg://proxy и socks5://.",
                    style = MaterialTheme.typography.bodySmall,
                    color = TextMedium,
                )
                OutlinedTextField(
                    value = input,
                    onValueChange = { input = it },
                    placeholder = {
                        Text(
                            "https://.../s/... или happ://... или vless://... или tg://proxy?...",
                            style = MaterialTheme.typography.bodySmall
                        )
                    },
                    modifier = Modifier.fillMaxWidth(),
                    maxLines = 4,
                )
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    TextButton(onClick = {
                        val clip = onPasteClipboard()
                        if (clip.isNotBlank()) input = clip
                    }) {
                        Text("Вставить из буфера", color = CyanAccent)
                    }
                    if ((input.trim().startsWith("https://") || input.trim().startsWith("http://")) &&
                        !input.contains("t.me/")
                    ) {
                        TextButton(onClick = { subKind = if (subKind == "vpn") "tg" else "vpn" }) {
                            Text(
                                text = if (subKind == "vpn") "Авто / VPN" else "Тип: TG",
                                color = EmeraldPrimary
                            )
                        }
                    }
                }
            }
        },
        confirmButton = {
            Button(
                onClick = { onSubmit(input.trim(), subKind) },
                enabled = input.isNotBlank(),
                colors = ButtonDefaults.buttonColors(
                    containerColor = EmeraldPrimary,
                    contentColor = Color(0xFF002116),
                )
            ) {
                Text("Добавить")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Отмена", color = TextMedium)
            }
        }
    )
}

@Composable
private fun DiagnosticLogDialog(
    initialLogs: List<String>,
    onLoadLogs: () -> List<String>,
    onClearLogs: (onCleared: (List<String>) -> Unit) -> Unit,
    onCopy: (List<String>) -> Unit,
    onShare: (List<String>) -> Unit,
    onDismiss: () -> Unit,
) {
    var logs by remember { mutableStateOf(initialLogs) }
    var filter by remember { mutableStateOf("all") }

    // Live cross-process tail every 1.2s ONLY while dialog is open (zero cost otherwise)
    LaunchedEffect(Unit) {
        while (true) {
            val fresh = withContext(Dispatchers.IO) { onLoadLogs() }
            if (fresh != logs) {
                logs = fresh
            }
            delay(1200L)
        }
    }

    val filtered = remember(logs, filter) {
        val src = when (filter) {
            "err" -> logs.filter { "[ERR]" in it || "[WARN]" in it }
            "vpn" -> logs.filter {
                "[VPN]" in it || "[TUN]" in it || "[XRAY]" in it || "[HEAL]" in it || "[NET]" in it
            }
            "probe" -> logs.filter {
                "[PROBE]" in it || "[FEED]" in it || "[SRC]" in it || "[SYNC]" in it ||
                    "[OPERA]" in it || "[WARP]" in it || "[DOH]" in it
            }
            "tg" -> logs.filter { "[TG]" in it }
            else -> logs
        }
        src.asReversed() // newest events right at the top for instant visibility!
    }

    val filterOptions = listOf(
        "all" to "Все (${logs.size})",
        "err" to "Ошибки/Пред.",
        "vpn" to "VPN/TUN",
        "probe" to "Пробы/Сеть",
        "tg" to "Telegram",
    )

    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = SurfaceCard,
        title = {
            Column {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        text = "Журнал диагностики",
                        style = MaterialTheme.typography.titleMedium,
                        color = TextHigh,
                    )
                    BadgePill("LIVE", EmeraldDim, EmeraldPrimary)
                }
                Text(
                    text = "Новые события сверху · обновляется в реальном времени",
                    style = MaterialTheme.typography.labelSmall,
                    color = TextLow,
                )
            }
        },
        text = {
            Column {
                LazyRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    items(filterOptions) { (key, title) ->
                        FilterChip(
                            selected = filter == key,
                            onClick = { filter = key },
                            label = { Text(title, style = MaterialTheme.typography.labelSmall) },
                            colors = FilterChipDefaults.filterChipColors(
                                selectedContainerColor = EmeraldDim,
                                selectedLabelColor = EmeraldPrimary,
                                containerColor = SurfaceElevated,
                                labelColor = TextMedium,
                            ),
                        )
                    }
                }
                Spacer(Modifier.height(8.dp))

                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(320.dp)
                        .clip(RoundedCornerShape(10.dp))
                        .background(BgObsidian)
                        .border(1.dp, SurfaceStroke, RoundedCornerShape(10.dp))
                        .padding(horizontal = 9.dp, vertical = 8.dp)
                ) {
                    if (filtered.isEmpty()) {
                        Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                            Text(
                                text = "Записей в выбранной категории пока нет",
                                style = MaterialTheme.typography.bodySmall,
                                color = TextLow,
                                textAlign = TextAlign.Center,
                            )
                        }
                    } else {
                        LazyColumn(
                            modifier = Modifier.fillMaxSize(),
                            verticalArrangement = Arrangement.spacedBy(4.dp),
                        ) {
                            items(filtered.size) { idx ->
                                val line = filtered[idx]
                                Text(
                                    text = line,
                                    fontFamily = FontFamily.Monospace,
                                    fontSize = 10.5.sp,
                                    lineHeight = 14.sp,
                                    color = diagLineColor(line),
                                )
                            }
                        }
                    }
                }

                Spacer(Modifier.height(8.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    OutlinedButton(
                        onClick = { onCopy(logs) },
                        modifier = Modifier.weight(1f),
                        shape = RoundedCornerShape(9.dp),
                        border = BorderStroke(1.dp, SurfaceStroke),
                        contentPadding = PaddingValues(vertical = 7.dp),
                    ) {
                        Text("Копировать", style = MaterialTheme.typography.labelSmall, color = CyanAccent)
                    }
                    OutlinedButton(
                        onClick = { onShare(logs) },
                        modifier = Modifier.weight(1f),
                        shape = RoundedCornerShape(9.dp),
                        border = BorderStroke(1.dp, SurfaceStroke),
                        contentPadding = PaddingValues(vertical = 7.dp),
                    ) {
                        Text("Поделиться", style = MaterialTheme.typography.labelSmall, color = TextHigh)
                    }
                    OutlinedButton(
                        onClick = { onClearLogs { fresh -> logs = fresh } },
                        shape = RoundedCornerShape(9.dp),
                        border = BorderStroke(1.dp, SurfaceStroke),
                        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 7.dp),
                    ) {
                        Text("Сброс", style = MaterialTheme.typography.labelSmall, color = TextLow)
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) {
                Text("Закрыть", color = EmeraldPrimary)
            }
        }
    )
}

private fun diagLineColor(line: String): Color = when {
    "[ERR]" in line -> CoralError
    "[WARN]" in line -> AmberWarn
    "[OK]" in line -> EmeraldPrimary
    else -> TextMedium
}

@Composable
private fun AppSplitTunnelDialog(
    apps: List<InstalledAppInfo>?,
    excluded: Set<String>,
    onTogglePkg: (String, Boolean) -> Unit,
    onDismiss: () -> Unit,
) {
    var query by remember { mutableStateOf("") }
    var onlySelected by remember { mutableStateOf(false) }

    val filtered = remember(apps, query, excluded, onlySelected) {
        apps?.filter { app ->
            (!onlySelected || app.packageName in excluded) && (
                query.isBlank() ||
                    app.label.contains(query, ignoreCase = true) ||
                    app.packageName.contains(query, ignoreCase = true)
                )
        }?.sortedWith(
            compareByDescending<InstalledAppInfo> { it.packageName in excluded }
                .thenBy { it.label.lowercase() }
        )
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = SurfaceCard,
        title = {
            Column {
                Text(
                    text = "Приложения без VPN",
                    style = MaterialTheme.typography.titleMedium,
                    color = TextHigh,
                )
                Text(
                    text = "Выбрано: ${excluded.size} · идут напрямую мимо туннеля",
                    style = MaterialTheme.typography.labelSmall,
                    color = TextLow,
                )
            }
        },
        text = {
            Column {
                OutlinedTextField(
                    value = query,
                    onValueChange = { query = it },
                    placeholder = { Text("Поиск по названию или пакету…", style = MaterialTheme.typography.bodySmall) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                if (apps != null) {
                    Spacer(Modifier.height(6.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        FilterChip(
                            selected = !onlySelected,
                            onClick = { onlySelected = false },
                            label = { Text("Все (${apps.size})", style = MaterialTheme.typography.labelSmall) },
                            colors = FilterChipDefaults.filterChipColors(
                                selectedContainerColor = EmeraldDim,
                                selectedLabelColor = EmeraldPrimary,
                                containerColor = SurfaceElevated,
                                labelColor = TextMedium,
                            ),
                        )
                        FilterChip(
                            selected = onlySelected,
                            onClick = { onlySelected = true },
                            label = { Text("Выбранные (${excluded.size})", style = MaterialTheme.typography.labelSmall) },
                            colors = FilterChipDefaults.filterChipColors(
                                selectedContainerColor = EmeraldDim,
                                selectedLabelColor = EmeraldPrimary,
                                containerColor = SurfaceElevated,
                                labelColor = TextMedium,
                            ),
                        )
                    }
                }
                Spacer(Modifier.height(6.dp))
                if (filtered == null) {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(160.dp),
                        contentAlignment = Alignment.Center,
                    ) {
                        Column(horizontalAlignment = Alignment.CenterHorizontally) {
                            CircularProgressIndicator(color = EmeraldPrimary, modifier = Modifier.size(30.dp))
                            Spacer(Modifier.height(8.dp))
                            Text(
                                text = "Загрузка списка приложений…",
                                style = MaterialTheme.typography.labelSmall,
                                color = TextLow,
                            )
                        }
                    }
                } else if (filtered.isEmpty()) {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(110.dp),
                        contentAlignment = Alignment.Center,
                    ) {
                        Text(
                            text = if (onlySelected) "Пока не выбрано ни одного приложения" else "Ничего не найдено",
                            style = MaterialTheme.typography.bodySmall,
                            color = TextLow,
                        )
                    }
                } else {
                    LazyColumn(
                        modifier = Modifier.heightIn(max = 350.dp),
                        verticalArrangement = Arrangement.spacedBy(2.dp),
                    ) {
                        items(filtered, key = { it.packageName }) { app ->
                            val isEx = app.packageName in excluded
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clip(RoundedCornerShape(10.dp))
                                    .background(if (isEx) EmeraldDim.copy(alpha = 0.35f) else Color.Transparent)
                                    .clickable { onTogglePkg(app.packageName, !isEx) }
                                    .padding(horizontal = 4.dp, vertical = 6.dp),
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                InstalledAppIconBox(
                                    packageName = app.packageName,
                                    label = app.label,
                                )
                                Spacer(Modifier.width(10.dp))
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        text = app.label,
                                        style = MaterialTheme.typography.bodyMedium,
                                        fontWeight = if (isEx) FontWeight.SemiBold else FontWeight.Normal,
                                        color = TextHigh,
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis,
                                    )
                                    Text(
                                        text = app.packageName,
                                        style = MaterialTheme.typography.labelSmall,
                                        color = TextLow,
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis,
                                    )
                                }
                                Checkbox(
                                    checked = isEx,
                                    onCheckedChange = { onTogglePkg(app.packageName, it) }
                                )
                            }
                        }
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) {
                Text("Готово", color = EmeraldPrimary)
            }
        }
    )
}

@Composable
private fun InstalledAppIconBox(
    packageName: String,
    label: String,
) {
    val context = LocalContext.current
    var iconBitmap by remember(packageName) {
        mutableStateOf<ImageBitmap?>(AppIconCache.getCached(packageName))
    }

    LaunchedEffect(packageName) {
        if (iconBitmap == null) {
            iconBitmap = AppIconCache.load(context, packageName)
        }
    }

    val bmp = iconBitmap
    if (bmp != null) {
        Image(
            bitmap = bmp,
            contentDescription = label,
            contentScale = ContentScale.Crop,
            modifier = Modifier
                .size(38.dp)
                .clip(RoundedCornerShape(10.dp)),
        )
    } else {
        // Clean monogram placeholder for the few milliseconds before async decode completes
        Box(
            modifier = Modifier
                .size(38.dp)
                .clip(RoundedCornerShape(10.dp))
                .background(SurfaceElevated)
                .border(1.dp, SurfaceStroke, RoundedCornerShape(10.dp)),
            contentAlignment = Alignment.Center,
        ) {
            Text(
                text = label.firstOrNull()?.uppercase() ?: "•",
                style = MaterialTheme.typography.titleSmall,
                color = CyanAccent,
            )
        }
    }
}

// ============================================================================
// ZERO-BLOAT VECTOR GLYPHS & HELPERS (0 KB icon-pack overhead!)
// ============================================================================

@Composable
private fun BadgePill(text: String, bg: Color, fg: Color) {
    Box(
        modifier = Modifier
            .clip(RoundedCornerShape(5.dp))
            .background(bg)
            .padding(horizontal = 6.dp, vertical = 2.dp)
    ) {
        Text(
            text = text,
            style = MaterialTheme.typography.labelSmall,
            fontWeight = FontWeight.SemiBold,
            color = fg,
            maxLines = 1,
        )
    }
}

private fun rttColor(ms: Int): Color = when {
    ms <= 0 -> TextMedium
    ms <= 550 -> EmeraldPrimary
    ms <= 950 -> CyanAccent
    ms <= 1400 -> AmberWarn
    else -> CoralError
}

@Composable
private fun PowerGlyph(modifier: Modifier, color: Color) {
    Canvas(modifier = modifier) {
        val sw = size.minDimension * 0.085f
        val pad = sw * 1.4f
        drawArc(
            color = color,
            startAngle = -52f,
            sweepAngle = 284f,
            useCenter = false,
            topLeft = Offset(pad, pad),
            size = Size(size.width - pad * 2, size.height - pad * 2),
            style = Stroke(width = sw, cap = StrokeCap.Round),
        )
        drawLine(
            color = color,
            start = Offset(size.width / 2f, size.height * 0.08f),
            end = Offset(size.width / 2f, size.height * 0.48f),
            strokeWidth = sw,
            cap = StrokeCap.Round,
        )
    }
}

@Composable
private fun VeloxShieldGlyph(modifier: Modifier, color: Color) {
    Canvas(modifier = modifier) {
        val w = size.width
        val h = size.height
        val p = Path().apply {
            moveTo(w * 0.5f, h * 0.08f)
            lineTo(w * 0.88f, h * 0.24f)
            lineTo(w * 0.88f, h * 0.53f)
            cubicTo(w * 0.88f, h * 0.76f, w * 0.70f, h * 0.88f, w * 0.5f, h * 0.95f)
            cubicTo(w * 0.30f, h * 0.88f, w * 0.12f, h * 0.76f, w * 0.12f, h * 0.53f)
            lineTo(w * 0.12f, h * 0.24f)
            close()
        }
        drawPath(p, color = color, style = Stroke(width = w * 0.09f, cap = StrokeCap.Round))
        drawLine(
            color = color,
            start = Offset(w * 0.35f, h * 0.40f),
            end = Offset(w * 0.50f, h * 0.68f),
            strokeWidth = w * 0.09f,
            cap = StrokeCap.Round,
        )
        drawLine(
            color = color,
            start = Offset(w * 0.50f, h * 0.68f),
            end = Offset(w * 0.67f, h * 0.35f),
            strokeWidth = w * 0.09f,
            cap = StrokeCap.Round,
        )
    }
}

@Composable
private fun NavVectorIcon(kind: Int, active: Boolean) {
    val c = if (active) EmeraldPrimary else TextMedium
    Canvas(modifier = Modifier.size(21.dp)) {
        val w = size.width
        val h = size.height
        val sw = w * 0.095f
        when (kind) {
            0 -> {
                // Shield
                val p = Path().apply {
                    moveTo(w * 0.5f, h * 0.10f)
                    lineTo(w * 0.86f, h * 0.25f)
                    lineTo(w * 0.86f, h * 0.54f)
                    cubicTo(w * 0.86f, h * 0.76f, w * 0.68f, h * 0.88f, w * 0.5f, h * 0.94f)
                    cubicTo(w * 0.32f, h * 0.88f, w * 0.14f, h * 0.76f, w * 0.14f, h * 0.54f)
                    lineTo(w * 0.14f, h * 0.25f)
                    close()
                }
                drawPath(p, color = c, style = Stroke(width = sw))
            }
            1 -> {
                // Telegram paper-plane glyph
                val p = Path().apply {
                    moveTo(w * 0.10f, h * 0.52f)
                    lineTo(w * 0.90f, h * 0.16f)
                    lineTo(w * 0.72f, h * 0.86f)
                    lineTo(w * 0.45f, h * 0.64f)
                    close()
                }
                drawPath(p, color = c, style = Stroke(width = sw, cap = StrokeCap.Round))
            }
            else -> {
                // Sliders / tuning glyph
                drawLine(c, Offset(w * 0.14f, h * 0.28f), Offset(w * 0.86f, h * 0.28f), sw, StrokeCap.Round)
                drawCircle(c, radius = w * 0.11f, center = Offset(w * 0.36f, h * 0.28f))
                drawLine(c, Offset(w * 0.14f, h * 0.72f), Offset(w * 0.86f, h * 0.72f), sw, StrokeCap.Round)
                drawCircle(c, radius = w * 0.11f, center = Offset(w * 0.66f, h * 0.72f))
            }
        }
    }
}
