package app.velox.vpn

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.ComponentCallbacks2
import android.os.Build
import app.velox.vpn.core.AppIconCache
import app.velox.vpn.core.CrashGuard
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
        // v1.7.3: перехватчик фатальных сбоев ставится ПЕРВЫМ — он пишет стектрейс в файл,
        // чтобы любой краш (в т.ч. при запуске) можно было увидеть и починить.
        CrashGuard.install(this)
        // Zero eager native-library or thread-pool load here: Quick Settings Tile binds stay
        // <1 MB pure Kotlin, while MainActivity & :vpn initialize Rust lazily off the UI thread.
        createNotificationChannels()
    }

    @Suppress("DEPRECATION")
    override fun onTrimMemory(level: Int) {
        super.onTrimMemory(level)
        if (level >= ComponentCallbacks2.TRIM_MEMORY_UI_HIDDEN) {
            AppIconCache.clear()
            VeloxNative.trimMemoryIfLoaded()
        } else if (level >= ComponentCallbacks2.TRIM_MEMORY_RUNNING_LOW) {
            AppIconCache.trimHalf()
            VeloxNative.trimMemoryIfLoaded()
        }
    }

    override fun onLowMemory() {
        super.onLowMemory()
        AppIconCache.clear()
        VeloxNative.trimMemoryIfLoaded()
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
            setSound(null, null)
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
            setSound(null, null)
        }

        nm.createNotificationChannels(listOf(vpnChannel, tgChannel))
    }
}
