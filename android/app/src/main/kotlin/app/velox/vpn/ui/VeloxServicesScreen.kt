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
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import app.velox.vpn.core.ServiceCheckItem
import app.velox.vpn.core.ServicesCheckResult
import app.velox.vpn.core.countryFlag
import app.velox.vpn.core.regionTitleRu

/**
 * v1.7.0 «Доступ к сервисам» tab — on-demand real live check of 12 service groups through the
 * active VPN tunnel (0% idle background cost: probe runs only when the user taps the button).
 *
 * Groups: Зарубежный IP (anti-RU) · Шифрованный DNS · YouTube/Shorts/Music · Discord ·
 * ChatGPT/Sora · Gemini/Claude/Grok · Instagram/Threads/X · Spotify/SoundCloud ·
 * Twitch/Netflix · Steam/Roblox/Brawl · GitHub/Notion/Figma/Canva · Telegram.
 */
@Composable
internal fun ServicesTabContent(
    result: ServicesCheckResult,
    isChecking: Boolean,
    vpnConnected: Boolean,
    runtime: app.velox.vpn.core.VpnRuntimeState,
    onCheck: () -> Unit,
) {
    val passed = if (result.services.isEmpty()) 0 else result.services.count { it.ok }
    val total = if (result.services.isEmpty()) result.total else result.services.size

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(horizontal = 16.dp, vertical = 10.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        item {
            Surface(
                shape = RoundedCornerShape(14.dp),
                color = SurfaceCard,
                border = BorderStroke(1.dp, SurfaceStroke),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Column(modifier = Modifier.padding(14.dp)) {
                    Text(
                        text = "🌍 Доступ к сервисам",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold,
                        color = TextHigh,
                    )
                    Spacer(Modifier.height(4.dp))
                    Text(
                        text = if (vpnConnected) {
                            "Проверка реального доступа через активный VPN: зарубежный IP, шифрованный DNS, " +
                                "ИИ, соцсети, видео, игры и работа. Запускается только по нажатию — 0% фоновой нагрузки."
                        } else {
                            "VPN выключен — проверка покажет, какие сервисы доступны напрямую с вашего оператора, " +
                                "а какие блокируются без VPN."
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = TextMedium,
                    )
                    Spacer(Modifier.height(10.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(10.dp),
                    ) {
                        Button(
                            onClick = onCheck,
                            enabled = !isChecking,
                            shape = RoundedCornerShape(10.dp),
                            colors = ButtonDefaults.buttonColors(
                                containerColor = EmeraldDim,
                                contentColor = EmeraldPrimary,
                            ),
                            modifier = Modifier.weight(1f),
                        ) {
                            if (isChecking) {
                                CircularProgressIndicator(
                                    modifier = Modifier.size(15.dp),
                                    strokeWidth = 2.dp,
                                    color = EmeraldPrimary,
                                )
                                Spacer(Modifier.width(8.dp))
                                Text("Проверяем 12 сервисов…", style = MaterialTheme.typography.labelLarge)
                            } else {
                                Text(
                                    text = if (result.services.isEmpty()) "Проверить все сервисы" else "Проверить снова",
                                    style = MaterialTheme.typography.labelLarge,
                                )
                            }
                        }
                        if (result.services.isNotEmpty()) {
                            BadgePill(
                                text = "$passed / $total",
                                bg = if (passed >= total - 1) EmeraldDim else AmberWarn.copy(alpha = 0.2f),
                                fg = if (passed >= total - 1) EmeraldPrimary else AmberWarn,
                            )
                        }
                    }
                    if (isChecking) {
                        Spacer(Modifier.height(8.dp))
                        LinearProgressIndicator(
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(3.dp)
                                .clip(RoundedCornerShape(2.dp)),
                            color = EmeraldPrimary,
                            trackColor = SurfaceStroke,
                        )
                    }
                    if (result.error.isNotBlank()) {
                        Spacer(Modifier.height(6.dp))
                        Text(
                            text = "Ошибка: ${result.error}",
                            style = MaterialTheme.typography.labelSmall,
                            color = AmberWarn,
                        )
                    }
                }
            }
        }

        if (result.services.isNotEmpty()) {
            item {
                Surface(
                    shape = RoundedCornerShape(12.dp),
                    color = SurfaceElevated,
                    border = BorderStroke(1.dp, SurfaceStroke),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 12.dp, vertical = 9.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween,
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            val cc = result.exitCountry
                            Text(
                                text = if (cc.isNotBlank()) {
                                    "${countryFlag(cc)} ${regionTitleRu(cc)} · ${result.exitIp}"
                                } else {
                                    "IP: ${result.exitIp.ifBlank { "-" }}"
                                },
                                style = MaterialTheme.typography.labelMedium,
                                color = TextHigh,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                            Text(
                                text = buildString {
                                    append(if (result.viaVpn) "через VPN" else "напрямую")
                                    if (result.elapsedMs > 0) append(" · ${result.elapsedMs} мс")
                                    if (result.ytAdFree) append(" · YouTube 0% рекламы")
                                },
                                style = MaterialTheme.typography.labelSmall,
                                color = TextMedium,
                            )
                        }
                        val runtimeCc = runtime.exitCountry
                        if (runtimeCc.isNotBlank() && result.exitCountry.isNotBlank() &&
                            !runtimeCc.equals(result.exitCountry, ignoreCase = true)
                        ) {
                            BadgePill("≠ ${regionTitleRu(runtimeCc)}", AmberWarn.copy(alpha = 0.2f), AmberWarn)
                        }
                    }
                }
            }

            items(result.services, key = { it.id }) { svc ->
                ServiceRowItem(svc)
            }

            item {
                Spacer(Modifier.height(4.dp))
                Text(
                    text = "Зелёный — сервис реально отвечает (TLS-сессия установлена). Красный — заблокирован " +
                        "оператором, геоблок (451) или недоступен через текущий сервер: смените страну или включите VPN.",
                    style = MaterialTheme.typography.labelSmall,
                    color = TextLow,
                )
            }
        } else if (!isChecking) {
            item {
                Surface(
                    shape = RoundedCornerShape(12.dp),
                    color = SurfaceElevated,
                    border = BorderStroke(1.dp, SurfaceStroke),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Column(modifier = Modifier.padding(13.dp)) {
                        Text(
                            text = "Что проверяется:",
                            style = MaterialTheme.typography.labelLarge,
                            color = TextHigh,
                        )
                        Spacer(Modifier.height(6.dp))
                        for (line in listOf(
                            "🛡️ Зарубежный IP (не РФ) и шифрованный DNS без утечек",
                            "📺 YouTube, Shorts и Music — включая режим 0% рекламы",
                            "💬 Discord (чат и голос) · Telegram (медиа и звонки)",
                            "🤖 ChatGPT/Sora · Gemini/Claude/Grok",
                            "📸 Instagram/Threads/X · Spotify/SoundCloud",
                            "🎮 Twitch/Netflix · Steam/Roblox/Brawl Stars",
                            "💼 GitHub/Notion/Figma/Canva",
                        )) {
                            Text(
                                text = line,
                                style = MaterialTheme.typography.bodySmall,
                                color = TextMedium,
                                modifier = Modifier.padding(vertical = 1.5.dp),
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun ServiceRowItem(svc: ServiceCheckItem) {
    val okColor = if (svc.ok) EmeraldPrimary else Color(0xFFFF6B81)
    val okBg = if (svc.ok) EmeraldDim else Color(0xFF2A1119)
    Surface(
        shape = RoundedCornerShape(11.dp),
        color = SurfaceElevated,
        border = BorderStroke(1.dp, SurfaceStroke),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 9.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Box(
                modifier = Modifier
                    .size(26.dp)
                    .clip(RoundedCornerShape(8.dp))
                    .background(okBg)
                    .border(1.dp, okColor.copy(alpha = 0.45f), RoundedCornerShape(8.dp)),
                contentAlignment = Alignment.Center,
            ) {
                Text(
                    text = if (svc.ok) "✓" else "✕",
                    style = MaterialTheme.typography.labelLarge,
                    fontWeight = FontWeight.Bold,
                    color = okColor,
                )
            }
            Spacer(Modifier.width(10.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = svc.name,
                    style = MaterialTheme.typography.labelLarge,
                    color = TextHigh,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    text = buildString {
                        if (svc.category.isNotBlank()) append(svc.category)
                        if (svc.rttMs > 0) {
                            if (isNotEmpty()) append(" · ")
                            append(svc.rttMs)
                            append(" мс")
                        }
                        if (svc.detail.isNotBlank()) {
                            if (isNotEmpty()) append(" · ")
                            append(svc.detail)
                        }
                    },
                    style = MaterialTheme.typography.labelSmall,
                    color = if (svc.ok) TextMedium else okColor.copy(alpha = 0.9f),
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }
    }
}
