package app.velox.vpn.service

import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import app.velox.vpn.core.VeloxPrefs
import app.velox.vpn.core.VpnPhase
import app.velox.vpn.core.regionTitleRu
import app.velox.vpn.ui.MainActivity

/**
 * Zero-native-RAM 1-tap Quick Settings Tile (Android 7–16, optimized for Android 12 pill tiles).
 * Reads only the tiny locked JSON snapshot — never loads `libvelox_engine.so` on system tile polls.
 */
class VeloxTileService : TileService() {

    override fun onStartListening() {
        super.onStartListening()
        // v1.7.4: тайл живёт в основном процессе — его сбой закрывал всё приложение.
        runCatching { syncTile() }
    }

    override fun onClick() {
        super.onClick()
        runCatching { handleClick() }
    }

    private fun handleClick() {
        val rt = VeloxPrefs.loadRuntime(this)
        if (rt.isActiveOrBusy) {
            VeloxVpnService.requestStop(this)
        } else if (VpnService.prepare(this) != null) {
            val openIntent = Intent(this, MainActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                val pi = PendingIntent.getActivity(
                    this,
                    30,
                    openIntent,
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
                )
                startActivityAndCollapse(pi)
            } else {
                @Suppress("DEPRECATION")
                startActivityAndCollapse(openIntent)
            }
        } else {
            VeloxVpnService.startConnect(this)
        }
        runCatching { syncTile() }
    }

    private fun syncTile() {
        val tile = qsTile ?: return
        val rt = VeloxPrefs.loadRuntime(this)
        val settings = VeloxPrefs.loadSettings(this)

        tile.label = "VeloxVPN"
        tile.state = if (rt.isActiveOrBusy) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            tile.subtitle = when (rt.phase) {
                VpnPhase.CONNECTED -> {
                    val country = rt.exitCountry.ifBlank { settings.region }
                    val dual = if (rt.dualChannelActive) " · 2×" else ""
                    val rtt = if (rt.rttMs > 0) " · ${rt.rttMs} мс" else ""
                    "${regionTitleRu(country)}$rtt$dual"
                }
                VpnPhase.CONNECTING, VpnPhase.FETCHING, VpnPhase.HEALING -> {
                    if (rt.etaSeconds > 0) "${rt.progressPercent}% · ≈${rt.etaSeconds}с" else "Ожидание…"
                }
                else -> regionTitleRu(settings.region)
            }
        }
        runCatching { tile.updateTile() }
    }
}
