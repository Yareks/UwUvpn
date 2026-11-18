package app.velox.vpn.core

import android.content.Context
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * v1.7.4 — минимальный «чёрный ящик» запуска.
 *
 * Пишет по одной короткой строке на каждый значимый шаг холодного старта в
 * `filesDir/startup_trace.log` (без нативного ядра, без корутин, без аллокаций в горячем пути).
 * Хвост этого файла автоматически попадает в отчёт [CrashGuard], поэтому при сбое видно
 * ПОСЛЕДНИЙ выполненный шаг — даже если журнал приложения недоступен.
 */
object StartupTrace {

    private const val FILE_NAME = "startup_trace.log"
    private const val MAX_BYTES = 48_000L
    private const val MAX_STEPS = 200

    private val fmt = SimpleDateFormat("HH:mm:ss.SSS", Locale.US)

    @Volatile
    private var steps = 0

    fun mark(ctx: Context, step: String) {
        val line = "${fmt.format(Date())}  $step"
        runCatching {
            val f = File(ctx.applicationContext.filesDir, FILE_NAME)
            if (f.length() > MAX_BYTES || steps > MAX_STEPS) {
                f.delete()
                steps = 0
            }
            f.appendText(line + "\n")
            steps++
        }
    }

    /** Последние `maxLines` строк трассы (для отчёта о сбое). */
    fun tail(ctx: Context, maxLines: Int = 40): String = runCatching {
        val f = File(ctx.applicationContext.filesDir, FILE_NAME)
        if (!f.exists()) return ""
        f.readLines().takeLast(maxLines).joinToString("\n")
    }.getOrDefault("")

    fun clear(ctx: Context) {
        runCatching { File(ctx.applicationContext.filesDir, FILE_NAME).delete() }
        steps = 0
    }
}
