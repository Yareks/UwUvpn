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


// ============================================================================
// TAB 3: SETTINGS (Anti-DPI, RAM Profile, Split Tunnel, WARP/Opera, Sources, Logs)
// ============================================================================

@Composable
internal fun SettingsTabContent(
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
    onOpenExternalUrl: (String) -> Unit,
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
    var showRules by rememberSaveable { mutableStateOf(false) }
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

        // 2. Dual-Channel Zero-Drop, YouTube Ad-Free, Anti-DPI (TSPU) & Auto-Healing
        item {
            SettingsCard(title = "Двойной канал 2×, YouTube 0% и обход ТСПУ") {
                SettingSwitchRow(
                    title = "Двойной канал (основной + горячий резерв)",
                    subtitle = "Держит наготове 2-й проверенный узел (в выбранной стране или лучший на «Авто») — мгновенный переход без обрыва и авто-замена резерва",
                    checked = settings.dualChannel,
                    onCheckedChange = { v -> onUpdateSettings({ it.copy(dualChannel = v) }, true) }
                )
                HorizontalDivider(color = SurfaceStroke.copy(alpha = 0.5f))
                SettingSwitchRow(
                    title = "YouTube и сайты без рекламы (0 МБ ОЗУ)",
                    subtitle = "Авто-выход YouTube через регионы без монетизации (0% прероллов/Shorts/Music) + блок рекламных доменов",
                    checked = settings.adblockYoutube,
                    onCheckedChange = { v -> onUpdateSettings({ it.copy(adblockYoutube = v) }, true) }
                )
                HorizontalDivider(color = SurfaceStroke.copy(alpha = 0.5f))
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
                    text = "Полная офлайн-поддержка Happ (happ://crypt…crypt5, AES-GCM, incy://), Remnawave, Marzban, 3x-ui, Xray JSON и дельта-обновление.",
                    style = MaterialTheme.typography.labelSmall,
                    color = TextMedium,
                )
                Spacer(Modifier.height(6.dp))
                SettingSwitchRow(
                    title = "Заголовки Happ X-HWID (для подписок с лимитом устройств)",
                    subtitle = if (settings.sendHwid && snapshot.hwidShort.isNotBlank()) {
                        "Вкл · анонимный хэш ID ${snapshot.hwidShort}… + модель устройства"
                    } else {
                        "Выкл · включите, если ваша Happ/Remnawave подписка требует привязку HWID"
                    },
                    checked = settings.sendHwid,
                    onCheckedChange = { v -> onUpdateSettings({ it.copy(sendHwid = v) }, false) }
                )
                HorizontalDivider(color = SurfaceStroke.copy(alpha = 0.5f))
                Spacer(Modifier.height(8.dp))
                if (customSubs.isNotEmpty()) {
                    customSubs.forEach { sub ->
                        HappSubscriptionCard(
                            sub = sub,
                            busy = isBusyImport,
                            onSync = { onSyncSource(sub.url) },
                            onRemove = { onRemoveSource(sub.url) },
                            onOpenUrl = onOpenExternalUrl,
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

        // 6b. v1.7.0 Custom per-site routing rules (Force VPN / Direct / Block)
        item {
            SettingsCard(title = "Свои правила сайтов (VPN / напрямую / блок)") {
                Text(
                    text = "Принудительно направьте любые сайты через VPN, оставьте их напрямую " +
                        "(без VPN) или заблокируйте. Правила применяются мгновенно и главнее " +
                        "встроенных списков.",
                    style = MaterialTheme.typography.bodySmall,
                    color = TextMedium,
                )
                Spacer(Modifier.height(8.dp))
                val vpnCnt = settings.rulesVpn.split(',', ' ', '\n').count { it.isNotBlank() }
                val dirCnt = settings.rulesDirect.split(',', ' ', '\n').count { it.isNotBlank() }
                val blkCnt = settings.rulesBlock.split(',', ' ', '\n').count { it.isNotBlank() }
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(7.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    BadgePill("VPN: $vpnCnt", EmeraldDim, EmeraldPrimary)
                    BadgePill("Напрямую: $dirCnt", CyanDim, CyanAccent)
                    BadgePill("Блок: $blkCnt", AmberWarn.copy(alpha = 0.2f), AmberWarn)
                    Spacer(Modifier.weight(1f))
                    OutlinedButton(
                        onClick = { showRules = true },
                        shape = RoundedCornerShape(10.dp),
                        border = BorderStroke(1.dp, SurfaceStroke),
                        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 8.dp),
                    ) {
                        Text("Изменить", style = MaterialTheme.typography.labelMedium, color = EmeraldPrimary)
                    }
                }
            }
        }

        // 7. Rust Engine Diagnostic Log & About
        item {
            SettingsCard(title = "Подробные логи и о приложении") {
                Text(
                    text = "VeloxVPN 1.7.0 · Ядро xray-rust 0.10.0 + velox-engine (100% Rust)\n" +
                        "Двойной канал 2× (0 мс обрыва) · резерв: та же страна → Германия/США · 0% серверов РФ\n" +
                        "KeepAlive 28с + tcpUserTimeout 15с (анти-разрыв) · 250+ сервисов · 12 проверок · YouTube 0%\n" +
                        "22+ страны · Reality (PQ) / XHTTP / Hysteria 2 / Trojan / VMess / SS2022 / WG / WARP MASQUE · Android 7.0–16",
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

    if (showRules) {
        SiteRulesDialog(
            initialVpn = settings.rulesVpn,
            initialDirect = settings.rulesDirect,
            initialBlock = settings.rulesBlock,
            onSave = { v, d, b ->
                showRules = false
                onUpdateSettings({ it.copy(rulesVpn = v, rulesDirect = d, rulesBlock = b) }, true)
            },
            onDismiss = { showRules = false },
        )
    }
}

@Composable
private fun SiteRulesDialog(
    initialVpn: String,
    initialDirect: String,
    initialBlock: String,
    onSave: (String, String, String) -> Unit,
    onDismiss: () -> Unit,
) {
    var v by remember(initialVpn) { mutableStateOf(initialVpn) }
    var d by remember(initialDirect) { mutableStateOf(initialDirect) }
    var b by remember(initialBlock) { mutableStateOf(initialBlock) }
    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = SurfaceCard,
        title = {
            Text(
                "Свои правила сайтов",
                style = MaterialTheme.typography.titleMedium,
                color = TextHigh,
            )
        },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    "Домены через запятую или с новой строки, например: openai.com, *.example.org",
                    style = MaterialTheme.typography.bodySmall,
                    color = TextMedium,
                )
                OutlinedTextField(
                    value = v,
                    onValueChange = { v = it },
                    label = { Text("Всегда через VPN") },
                    modifier = Modifier.fillMaxWidth(),
                    maxLines = 3,
                    textStyle = MaterialTheme.typography.bodySmall,
                )
                OutlinedTextField(
                    value = d,
                    onValueChange = { d = it },
                    label = { Text("Всегда напрямую (без VPN)") },
                    modifier = Modifier.fillMaxWidth(),
                    maxLines = 3,
                    textStyle = MaterialTheme.typography.bodySmall,
                )
                OutlinedTextField(
                    value = b,
                    onValueChange = { b = it },
                    label = { Text("Блокировать (реклама/телеметрия)") },
                    modifier = Modifier.fillMaxWidth(),
                    maxLines = 3,
                    textStyle = MaterialTheme.typography.bodySmall,
                )
            }
        },
        confirmButton = {
            TextButton(onClick = { onSave(v, d, b) }) {
                Text("Сохранить и применить", color = EmeraldPrimary)
            }
        },
        dismissButton = {
            TextButton(onClick = {
                v = ""
                d = ""
                b = ""
                onSave("", "", "")
            }) {
                Text("Очистить", color = TextMedium)
            }
        },
    )
}

@Composable
internal fun SettingsCard(
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
internal fun SettingSwitchRow(
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
internal fun SourceRow(src: SubSourceItem, onToggle: (Boolean) -> Unit) {
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

