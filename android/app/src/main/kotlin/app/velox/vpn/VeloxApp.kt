package app.velox.vpn

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.os.Build
import app.velox.vpn.core.VeloxNative

class VeloxApp : Application() {

    companion object {
        const val CHANNEL_VPN = "velox_vpn_tunnel"
        const val CHANNEL_TG_BRIDGE = "velox_tg_bridge"
        const val NOTIF_ID_VPN = 1001
        const val NOTIF_ID_TG = 1002
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannels()
        // Lightweight background init so first frame draws in <16 ms
        Thread {
            runCatching { VeloxNative.ensureInitialized(this) }
        }.apply {
            name = "velox-boot"
            isDaemon = true
            start()
        }
    }

    private fun createNotificationChannels() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val nm = getSystemService(NotificationManager::class.java) ?: return

        val vpnChannel = NotificationChannel(
            CHANNEL_VPN,
            "VPN-туннель VeloxVPN",
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = "Тихий статус активного VPN-подключения и быстрые кнопки управления"
            setShowBadge(false)
            enableLights(false)
            enableVibration(false)
        }

        val tgChannel = NotificationChannel(
            CHANNEL_TG_BRIDGE,
            "Умный прокси Telegram",
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = "Локальный авто-прокси и TG-WS мост для Telegram (127.0.0.1:10809)"
            setShowBadge(false)
            enableLights(false)
            enableVibration(false)
        }

        nm.createNotificationChannels(listOf(vpnChannel, tgChannel))
    }
}
