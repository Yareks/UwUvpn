package app.velox.vpn.core

import android.content.Context
import android.os.Build
import app.velox.vpn.BuildConfig
import java.io.File
import java.io.PrintWriter
import java.io.StringWriter
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * v1.7.3 — самодиагностика сбоев.
 *
 * Ставит глобальный `UncaughtExceptionHandler`, который ДО передачи управления системному
 * обработчику пишет компактный отчёт (версия, устройство, поток, полный стектрейс) в
 * `filesDir/crash_report.txt`. Отчёт:
 *  - не зависит от нативного ядра (чистый Kotlin + файловый I/O), поэтому переживает падение
 *    при загрузке `.so` или в JNI;
 *  - ограничен по размеру и хранит только последние три записи;
 *  - читается на следующем запуске: попадает в основной журнал и включает «безопасный режим»
 *    (пропуск тяжёлой инициализации), чтобы приложение гарантированно открывалось.
 */
object CrashGuard {

    private const val FILE_NAME = "crash_report.txt"
    private const val MAX_CHARS = 16_000
    private const val KEEP_ENTRIES = 3

    @Volatile
    private var installed = false

    /** Метка времени последнего зафиксированного сбоя (0 — сбоев не было). */
    @Volatile
    var lastCrashAtMs: Long = 0L
        private set

    fun install(app: Context) {
        if (installed) return
        installed = true
        val previous = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, error ->
            runCatching { writeReport(app.applicationContext, thread, error) }
            if (previous != null) {
                previous.uncaughtException(thread, error)
            } else {
                android.os.Process.killProcess(android.os.Process.myPid())
                kotlin.system.exitProcess(10)
            }
        }
    }

    private fun crashFile(ctx: Context) = File(ctx.filesDir, FILE_NAME)

    private fun writeReport(ctx: Context, thread: Thread, error: Throwable) {
        lastCrashAtMs = System.currentTimeMillis()
        val stack = StringWriter().also { sw ->
            PrintWriter(sw).use { error.printStackTrace(it) }
        }.toString()

        val stamp = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date())
        val entry = buildString {
            append("=== CRASH ").append(stamp).append(" ===\n")
            append("app=").append(BuildConfig.VERSION_NAME)
                .append(" (").append(BuildConfig.VERSION_CODE).append(")\n")
            append("device=").append(Build.MANUFACTURER).append(' ').append(Build.MODEL)
                .append(" · Android ").append(Build.VERSION.RELEASE)
                .append(" (SDK ").append(Build.VERSION.SDK_INT).append(")\n")
            append("thread=").append(thread.name).append(" · abi=")
                .append(Build.SUPPORTED_ABIS.firstOrNull().orEmpty()).append("\n")
            append(stack.take(MAX_CHARS)).append("\n\n")
        }

        val f = crashFile(ctx)
        val old = runCatching { if (f.exists()) f.readText() else "" }.getOrDefault("")
        val merged = (entry + old).take(MAX_CHARS * KEEP_ENTRIES)
        runCatching { f.writeText(merged) }
    }

    /** Читает (и удаляет) отчёт о прошлом сбое. Возвращает текст или пустую строку. */
    fun consumeReport(ctx: Context): String {
        val f = crashFile(ctx)
        if (!f.exists()) return ""
        val text = runCatching { f.readText() }.getOrDefault("")
        runCatching { f.delete() }
        return text
    }

    /** Дописывает строку в собственный (неродной) журнал сбоев — работает без libvelox_engine. */
    fun appendPlainLog(ctx: Context, line: String) {
        runCatching {
            val f = File(ctx.filesDir, "startup_trace.log")
            if (f.length() > 64_000) f.writeText("")
            f.appendText(line + "\n")
        }
    }
}
