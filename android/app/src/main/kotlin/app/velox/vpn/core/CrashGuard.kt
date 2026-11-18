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
        Thread.setDefaultUncaughtExceptionHandler { thread, error ->
            // v1.7.6: падение ВСПОМОГАТЕЛЬНОГО процесса (`:probe` — проверка серверов/подписка)
            // не должно блокировать приложение «безопасным режимом»: UI жив и полностью рабочий.
            // Пишем отдельный журнал PROBE_CRASH и просто перезапускаем такой процесс при
            // следующей операции.
            if (isAuxiliaryProcess()) {
                runCatching { writeAuxiliaryReport(app.applicationContext, thread, error) }
                runCatching { android.os.Process.killProcess(android.os.Process.myPid()) }
                kotlin.system.exitProcess(11)
                return@setDefaultUncaughtExceptionHandler
            }
            runCatching { writeReport(app.applicationContext, thread, error) }
            // v1.7.5: НЕ вызываем прежний обработчик. Android по умолчанию показывает диалог
            // только для Java-крашей и молча завершает процесс при нативном падении (SIGSEGV/
            // SIGABRT в .so). Теперь отчёт уже записан на диск, поэтому процесс завершаем сами —
            // при следующем запуске приложение покажет причину и уйдёт в безопасный режим.
            runCatching { android.os.Process.killProcess(android.os.Process.myPid()) }
            kotlin.system.exitProcess(10)
        }
    }

    private fun crashFile(ctx: Context) = File(ctx.filesDir, FILE_NAME)

    private fun isAuxiliaryProcess(): Boolean = runCatching {
        val name = if (Build.VERSION.SDK_INT >= 28) {
            android.app.Application.getProcessName()
        } else {
            File("/proc/self/cmdline").readText().trim('\u0000', '\n')
        }.orEmpty()
        name.endsWith(":probe")
    }.getOrDefault(false)

    /** Краткий отчёт о сбое вспомогательного процесса — попадает в журнал как PROBE_CRASH. */
    private fun writeAuxiliaryReport(ctx: Context, thread: Thread, error: Throwable) {
        runCatching {
            val stack = StringWriter().also { sw ->
                PrintWriter(sw).use { error.printStackTrace(it) }
            }.toString()
            val stamp = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date())
            val f = File(ctx.filesDir, "probe_crash.log")
            if (f.length() > 24_000) f.writeText("")
            f.appendText("=== PROBE_CRASH $stamp ===\n")
            f.appendText("thread=${thread.name}\n")
            f.appendText(stack.take(6000) + "\n\n")
        }
    }

    /** Читает (и очищает) журнал сбоев вспомогательного процесса. */
    fun consumeAuxReport(ctx: Context): String = runCatching {
        val f = File(ctx.filesDir, "probe_crash.log")
        if (!f.exists()) "" else f.readText().also { f.delete() }
    }.getOrDefault("")

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
            append(stack.take(MAX_CHARS)).append("\n")
            val tail = runCatching { StartupTrace.tail(ctx, 40) }.getOrDefault("")
            if (tail.isNotBlank()) {
                append("--- последние шаги запуска ---\n").append(tail).append("\n")
            }
            append("\n")
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
