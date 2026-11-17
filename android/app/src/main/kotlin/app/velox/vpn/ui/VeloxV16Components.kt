package app.velox.vpn.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import app.velox.vpn.core.SubSourceItem
import app.velox.vpn.core.VpnRuntimeState
import app.velox.vpn.core.countryFlag
import app.velox.vpn.core.formatBytesRu
import app.velox.vpn.core.formatDuration
import app.velox.vpn.core.regionTitleRu
import kotlinx.coroutines.delay

/**
 * Observes `Lifecycle.State.STARTED` so 1 Hz timers and log tails stop completely (0% CPU)
 * the instant the user turns off the screen or switches to another app.
 */
@Composable
fun rememberIsLifecycleStarted(): Boolean {
    val owner = LocalLifecycleOwner.current
    var started by remember(owner) {
        mutableStateOf(owner.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED))
    }
    DisposableEffect(owner) {
        val obs = LifecycleEventObserver { _, _ ->
            started = owner.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)
        }
        owner.lifecycle.addObserver(obs)
        onDispose { owner.lifecycle.removeObserver(obs) }
    }
    return started
}

/**
 * Isolated leaf uptime timer — ticks ONLY when visible and recomposes ONLY this single `Text`,
 * keeping `VpnHeroCard` and `VpnTabContent` at 0 recompositions/sec while connected.
 */
@Composable
fun LiveSessionTimerCell(connectedSinceMs: Long) {
    val visible = rememberIsLifecycleStarted()
    var nowMs by remember(connectedSinceMs) { mutableLongStateOf(System.currentTimeMillis()) }
    LaunchedEffect(connectedSinceMs, visible) {
        while (visible && connectedSinceMs > 0L) {
            nowMs = System.currentTimeMillis()
            delay(1000L)
        }
    }
    val elapsed = if (connectedSinceMs > 0L) (nowMs - connectedSinceMs).coerceAtLeast(0L) else 0L
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(text = "Время", style = MaterialTheme.typography.labelSmall, color = TextLow)
        Spacer(Modifier.height(2.dp))
        Text(
            text = formatDuration(elapsed),
            style = MaterialTheme.typography.labelLarge,
            fontWeight = FontWeight.SemiBold,
            color = TextHigh,
        )
    }
}

/**
 * Compact Dual-Channel Primary (`#1`) + Hot-Standby (`#2`) live strip shown inside `VpnHeroCard`
 * when connected, displaying strict-country standby readiness and zero-drop failover count.
 */
@Composable
fun DualChannelLiveStrip(
    runtime: VpnRuntimeState,
    dualEnabled: Boolean,
    selectedRegion: String,
) {
    if (!dualEnabled) return
    val hasStandby = runtime.dualChannelActive && runtime.standbyNodeName.isNotBlank()
    val stripBorder = if (hasStandby) {
        EmeraldPrimary.copy(alpha = 0.35f)
    } else {
        CyanAccent.copy(alpha = 0.28f)
    }

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(10.dp))
            .background(BgObsidian.copy(alpha = 0.52f))
            .border(1.dp, stripBorder, RoundedCornerShape(10.dp))
            .padding(horizontal = 10.dp, vertical = 7.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            val title = if (hasStandby) {
                val flag = countryFlag(runtime.standbyCountry)
                val rtt = if (runtime.standbyRttMs > 0) " · ${runtime.standbyRttMs} мс" else ""
                "🛡️ Горячий резерв: $flag ${runtime.standbyNodeName}$rtt"
            } else {
                val scopeLabel = if (selectedRegion.equals("AUTO", ignoreCase = true)) {
                    "авто-подбор резерва"
                } else {
                    "подбор резерва (${regionTitleRu(selectedRegion)})"
                }
                "🛡️ 2× канал активен · $scopeLabel"
            }
            Text(
                text = title,
                style = MaterialTheme.typography.labelSmall,
                color = if (hasStandby) EmeraldPrimary else CyanAccent,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            if (runtime.failoverCount > 0) {
                Text(
                    text = "Бесшовных переключений без разрыва: ${runtime.failoverCount}",
                    style = MaterialTheme.typography.labelSmall,
                    color = TextMedium,
                )
            }
        }
        Spacer(Modifier.width(6.dp))
        Box(
            modifier = Modifier
                .clip(RoundedCornerShape(6.dp))
                .background(if (hasStandby) EmeraldDim else SurfaceElevated)
                .padding(horizontal = 6.dp, vertical = 2.dp)
        ) {
            Text(
                text = if (hasStandby) "0 МС" else "ПОИСК",
                style = MaterialTheme.typography.labelSmall,
                fontWeight = FontWeight.Bold,
                color = if (hasStandby) EmeraldPrimary else CyanAccent,
            )
        }
    }
}

/**
 * Rich Happ 4.11+ / Remnawave / Marzban / 3x-ui subscription card:
 * - Encryption badge (`CRYPT5`, `AES-GCM`, `INCY`) + HWID device limit status
 * - Visual traffic quota progress bar + remaining days + auto-update interval
 * - Provider announcement text + 1-tap Support (`tg://` / `https://`) & Cabinet buttons
 */
@Composable
fun HappSubscriptionCard(
    sub: SubSourceItem,
    busy: Boolean,
    onSync: () -> Unit,
    onRemove: () -> Unit,
    onOpenUrl: (String) -> Unit,
) {
    Surface(
        shape = RoundedCornerShape(12.dp),
        color = SurfaceElevated,
        border = BorderStroke(1.dp, SurfaceStroke),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 11.dp, vertical = 9.dp),
            verticalArrangement = Arrangement.spacedBy(5.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(5.dp),
                    ) {
                        Text(
                            text = sub.name,
                            style = MaterialTheme.typography.titleSmall,
                            color = TextHigh,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                            modifier = Modifier.weight(1f, fill = false),
                        )
                        if (sub.encryptedKind.isNotBlank() || sub.bodyEncrypted) {
                            val tag = when {
                                sub.encryptedKind.isNotBlank() -> sub.encryptedKind.uppercase()
                                else -> "AES"
                            }
                            SmallSubTag(text = "🔒 $tag", bg = EmeraldDim, fg = EmeraldPrimary)
                        }
                        if (sub.updateIntervalHours > 0) {
                            SmallSubTag(
                                text = "${sub.updateIntervalHours}ч",
                                bg = BgObsidian.copy(alpha = 0.6f),
                                fg = TextMedium,
                            )
                        }
                    }

                    val meta = buildString {
                        if (sub.cachedCount > 0) {
                            append(if (sub.kind == "tg") "${sub.cachedCount} прокси" else "${sub.cachedCount} серверов")
                        } else {
                            append("Нажмите ↻ для обновления")
                        }
                        if (sub.userinfo.isNotBlank()) {
                            append(" · ${sub.userinfo}")
                        } else if (sub.totalBytes == 0L && sub.expireUnix > 0L) {
                            val nowSec = System.currentTimeMillis() / 1000L
                            val days = ((sub.expireUnix - nowSec) / 86_400L)
                            append(if (days >= 0) " · ∞ трафик · ещё ${days} дн." else " · истекла")
                        }
                    }
                    Text(
                        text = meta,
                        style = MaterialTheme.typography.labelSmall,
                        color = EmeraldPrimary,
                        maxLines = 2,
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

            // Traffic quota progress bar (when provider reports finite totalBytes > 0)
            if (sub.totalBytes > 0L) {
                val ratio = (sub.usedBytes.toDouble() / sub.totalBytes.toDouble())
                    .toFloat()
                    .coerceIn(0f, 1f)
                val barColor = when {
                    ratio >= 0.90f -> CoralError
                    ratio >= 0.72f -> AmberWarn
                    else -> EmeraldPrimary
                }
                LinearProgressIndicator(
                    progress = { ratio },
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(4.dp)
                        .clip(RoundedCornerShape(2.dp)),
                    color = barColor,
                    trackColor = BgObsidian.copy(alpha = 0.65f),
                )
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                    Text(
                        text = "${formatBytesRu(sub.usedBytes)} из ${formatBytesRu(sub.totalBytes)}",
                        style = MaterialTheme.typography.labelSmall,
                        color = TextLow,
                    )
                    Text(
                        text = "${(ratio * 100).toInt()}%",
                        style = MaterialTheme.typography.labelSmall,
                        color = barColor,
                    )
                }
            }

            if (sub.hwidStatus.isNotBlank()) {
                Text(
                    text = "HWID: ${sub.hwidStatus}",
                    style = MaterialTheme.typography.labelSmall,
                    color = AmberWarn,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }

            if (sub.announce.isNotBlank()) {
                Text(
                    text = "📢 ${sub.announce}",
                    style = MaterialTheme.typography.labelSmall,
                    color = TextMedium,
                    maxLines = 3,
                    overflow = TextOverflow.Ellipsis,
                )
            }

            if (sub.supportUrl.isNotBlank() || sub.webPageUrl.isNotBlank()) {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    if (sub.webPageUrl.isNotBlank()) {
                        TextButton(
                            onClick = { onOpenUrl(sub.webPageUrl) },
                            contentPadding = PaddingValues(horizontal = 6.dp, vertical = 2.dp),
                        ) {
                            Text("🌐 Кабинет / Продлить", style = MaterialTheme.typography.labelSmall, color = CyanAccent)
                        }
                    }
                    if (sub.supportUrl.isNotBlank()) {
                        TextButton(
                            onClick = { onOpenUrl(sub.supportUrl) },
                            contentPadding = PaddingValues(horizontal = 6.dp, vertical = 2.dp),
                        ) {
                            Text("💬 Поддержка", style = MaterialTheme.typography.labelSmall, color = EmeraldPrimary)
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun SmallSubTag(text: String, bg: Color, fg: Color) {
    Box(
        modifier = Modifier
            .clip(RoundedCornerShape(5.dp))
            .background(bg)
            .padding(horizontal = 5.dp, vertical = 1.dp)
    ) {
        Text(
            text = text,
            style = MaterialTheme.typography.labelSmall,
            fontWeight = FontWeight.SemiBold,
            color = fg,
        )
    }
}
