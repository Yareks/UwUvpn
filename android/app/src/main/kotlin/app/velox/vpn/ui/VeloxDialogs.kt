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
// DIALOGS (Universal Key/Proxy/Subscription Import + Per-App Split Tunneling)
// ============================================================================

@Composable
internal fun UniversalImportDialog(
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
                    text = "Поддерживаются зашифрованные ссылки Happ (happ://crypt…crypt5, AES-GCM тела, HWID), incy://crypt1/, v2raytun://, hiddify://, clash://, sing-box://, ssconf://, любые https:// подписки (Remnawave, Marzban, 3x-ui, Xray JSON), vless:// (Reality PQ/XHTTP/WS ?ed/gRPC/pcs), hy2://, trojan://, vmess://, ss://, wireguard:///.conf и tg://proxy.",
                    style = MaterialTheme.typography.bodySmall,
                    color = TextMedium,
                )
                OutlinedTextField(
                    value = input,
                    onValueChange = { input = it },
                    placeholder = {
                        Text(
                            "happ://crypt5/... · https://.../s/... · vless:// · hy2:// · wg · tg://",
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
internal fun DiagnosticLogDialog(
    initialLogs: List<String>,
    onLoadLogs: () -> List<String>,
    onClearLogs: (onCleared: (List<String>) -> Unit) -> Unit,
    onCopy: (List<String>) -> Unit,
    onShare: (List<String>) -> Unit,
    onDismiss: () -> Unit,
) {
    var logs by remember { mutableStateOf(initialLogs) }
    var filter by remember { mutableStateOf("all") }

    // Lifecycle-gated live cross-process tail (pauses cleanly on screen-off / app background!)
    val isVisible = rememberIsLifecycleStarted()
    LaunchedEffect(isVisible) {
        while (isVisible) {
            val fresh = withContext(Dispatchers.IO) { onLoadLogs() }
            if (fresh != logs) {
                logs = fresh
            }
            delay(1300L)
        }
    }

    val filtered = remember(logs, filter) {
        val src = when (filter) {
            "err" -> logs.filter { "[ERR]" in it || "[WARN]" in it }
            "vpn" -> logs.filter {
                "[VPN]" in it || "[DUAL]" in it || "[TUN]" in it || "[XRAY]" in it ||
                    "[HEAL]" in it || "[NET]" in it || "[WEB]" in it || "[DNS]" in it
            }
            "probe" -> logs.filter {
                "[PROBE]" in it || "[FEED]" in it || "[SRC]" in it || "[SYNC]" in it ||
                    "[HAPP]" in it || "[OPERA]" in it || "[WARP]" in it || "[DOH]" in it
            }
            "tg" -> logs.filter { "[TG]" in it }
            else -> logs
        }
        src.asReversed()
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
                    items(filterOptions, key = { it.first }) { (key, title) ->
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
                            items(filtered.size, key = { idx -> idx }) { idx ->
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

internal fun diagLineColor(line: String): Color = when {
    "[ERR]" in line -> CoralError
    "[WARN]" in line -> AmberWarn
    "[OK]" in line -> EmeraldPrimary
    else -> TextMedium
}

@Composable
internal fun AppSplitTunnelDialog(
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
internal fun InstalledAppIconBox(
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
internal fun BadgePill(text: String, bg: Color, fg: Color) {
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

internal fun rttColor(ms: Int): Color = when {
    ms <= 0 -> TextMedium
    ms <= 550 -> EmeraldPrimary
    ms <= 950 -> CyanAccent
    ms <= 1400 -> AmberWarn
    else -> CoralError
}

@Composable
internal fun PowerGlyph(modifier: Modifier, color: Color) {
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
internal fun VeloxShieldGlyph(modifier: Modifier, color: Color) {
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
internal fun NavVectorIcon(kind: Int, active: Boolean) {
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
            3 -> {
                // Globe glyph (services reachability)
                drawCircle(c, radius = w * 0.34f, center = Offset(w * 0.5f, h * 0.5f), style = Stroke(width = sw))
                drawLine(c, Offset(w * 0.16f, h * 0.5f), Offset(w * 0.84f, h * 0.5f), sw, StrokeCap.Round)
                drawOval(
                    color = c,
                    topLeft = Offset(w * 0.32f, h * 0.16f),
                    size = Size(w * 0.36f, h * 0.68f),
                    style = Stroke(width = sw * 0.8f),
                )
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
