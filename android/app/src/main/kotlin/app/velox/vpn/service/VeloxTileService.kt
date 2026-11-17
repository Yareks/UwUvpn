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
 * 1-tap Quick Settings Tile — works smoothly across Android 7–16 including
 * Android 12 (API 31/32) large two-line pill tiles and Android 14+ PendingIntent requirement.
 */
class VeloxTileService : TileService() {

    override fun onStartListening() {
        super.onStartListening()
        syncTile()
    }

    override fun onClick() {
        super.onClick()
        val rt = VeloxPrefs.loadRuntime(this)
        if (rt.isActiveOrBusy) {
            VeloxVpnService.requestStop(this)
        } else if (VpnService.prepare(this) != null) {
            // First-ever launch: open MainActivity to grant one-time system VPN consent
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
        syncTile()
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
                    "${regionTitleRu(country)} · ${rt.rttMs} мс"
                }
                VpnPhase.CONNECTING, VpnPhase.FETCHING, VpnPhase.HEALING -> {
                    if (rt.etaSeconds > 0) "${rt.progressPercent}% · ≈${rt.etaSeconds}с" else "Подключение…"
                }
                else -> regionTitleRu(settings.region)
            }
        }
        runCatching { tile.updateTile() }
    }
}
