package app.velox.vpn.core

import android.content.Context
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.drawable.BitmapDrawable
import android.util.LruCache
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Ultra-lightweight bounded LRU app-icon cache for the per-app Split Tunneling sheet.
 * Renders BitmapDrawable, AdaptiveIconDrawable (Android 8–16 incl. Android 12), and vector
 * icons sharply at 84x84 px (~28 KB each, max 64 entries <= ~1.7 MB, auto-evicted on UI hide).
 */
object AppIconCache {

    private const val ICON_PX = 84
    private const val MAX_ENTRIES = 64
    private val cache = LruCache<String, ImageBitmap>(MAX_ENTRIES)

    fun getCached(packageName: String): ImageBitmap? = synchronized(cache) {
        cache.get(packageName)
    }

    fun clear() = synchronized(cache) {
        cache.evictAll()
    }

    fun trimHalf() = synchronized(cache) {
        cache.trimToSize(MAX_ENTRIES / 2)
    }

    suspend fun load(context: Context, packageName: String): ImageBitmap? {
        getCached(packageName)?.let { return it }
        return withContext(Dispatchers.IO) {
            getCached(packageName)?.let { return@withContext it }
            val loaded = runCatching {
                val drawable = context.applicationContext.packageManager.getApplicationIcon(packageName)
                val bmp = if (drawable is BitmapDrawable && drawable.bitmap != null && !drawable.bitmap.isRecycled) {
                    val src = drawable.bitmap
                    if (src.width in 48..ICON_PX && src.height in 48..ICON_PX && src.config != null) {
                        src
                    } else {
                        Bitmap.createScaledBitmap(src, ICON_PX, ICON_PX, true)
                    }
                } else {
                    val out = Bitmap.createBitmap(ICON_PX, ICON_PX, Bitmap.Config.ARGB_8888)
                    val canvas = Canvas(out)
                    drawable.setBounds(0, 0, ICON_PX, ICON_PX)
                    drawable.draw(canvas)
                    out
                }
                bmp.asImageBitmap()
            }.getOrNull()

            if (loaded != null) {
                synchronized(cache) {
                    cache.put(packageName, loaded)
                }
            }
            loaded
        }
    }
}
