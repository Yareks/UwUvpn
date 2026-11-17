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
// TAB 2: TELEGRAM PROXIES (Authentic DC resPQ <= 1400 ms + Local TG-WS Bridge)
// ============================================================================

@Composable
internal fun TelegramTabContent(
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
                items(chips, key = { it.first }) { (key, label) ->
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
internal fun TgSmartBridgeCard(
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
internal fun TgProxyCard(
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

