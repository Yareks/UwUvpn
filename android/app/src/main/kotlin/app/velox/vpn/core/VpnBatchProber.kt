package app.velox.vpn.core

import android.content.Context
import android.net.VpnService
import org.json.JSONArray
import org.json.JSONObject
import org.xrayrust.mobile.XrayCore
import org.xrayrust.mobile.XrayTunRuntimeProfile
import java.util.concurrent.atomic.AtomicBoolean

data class BatchRefreshOutcome(
    val ok: Boolean,
    val testedCount: Int = 0,
    val newlyVerified: Int = 0,
    val liveAvailable: Int = 0,
    val keptAlive: Int = 0,
    val removedDead: Int = 0,
    val error: String = "",
)

data class LiveProgressUpdate(
    val stageIndex: Int,
    val stageTotal: Int,
    val percent: Int,
    val etaSeconds: Int,
    val statusLine: String,
    val detailLine: String,
)

/**
 * End-to-end multi-echelon VPN pool fetcher & verifier with real-time progress + ETA reporting:
 * 1) `quickVerifySeedBlocking`: ~3.8s parallel check of up to 14 clean bundled seed nodes on cold start.
 * 2) `refreshPoolBlocking`: parallel fetch of 12 auto-updated feeds + free Opera SurfEasy (decoy SNI +
 *    WebPKI cert verification) + free Cloudflare WARP (MASQUE H3/H2 + WireGuard+Noise), TCP prefilter
 *    with anti-spoof DoH IP pinning, and full-tunnel `gstatic` 204 + 38 KiB anti-16KB + GeoIP checks!
 */
object VpnBatchProber {

    private val running = AtomicBoolean(false)

    fun isRunning(): Boolean = running.get()

    /**
     * Lightning-fast (~3.8s) parallel probe of bundled seed nodes on the user's real ISP/network.
     * Returns number of live verified nodes (`0` means skip straight to full live refresh!).
     */
    fun quickVerifySeedBlocking(
        context: Context,
        settings: AppSettings,
        vpnService: VpnService? = null,
        shouldAbort: (() -> Boolean)? = null,
        onProgress: ((LiveProgressUpdate) -> Unit)? = null,
    ): Int {
        if (shouldAbort?.invoke() == true) return 0
        if (!running.compareAndSet(false, true)) return 0
        try {
            VeloxNative.reloadFromDisk(context)
            val basePort = VeloxPrefs.SEED_PROBE_BASE_PORT
            val prepRaw = VeloxNative.prepareSeedQuickProbe(
                targetRegion = settings.region,
                whitelistMode = settings.whitelistMode,
                basePort = basePort,
                maxCount = 14,
            )
            val prep = JSONObject(prepRaw)
            if (!prep.optBoolean("ok", false)) return 0

            val batchId = prep.getString("batchId")
            val count = prep.optInt("count", 0)
            val cfg = prep.getString("probeConfigJson")

            onProgress?.invoke(
                LiveProgressUpdate(
                    stageIndex = 1,
                    stageTotal = 3,
                    percent = 18,
                    etaSeconds = 5,
                    statusLine = "Экспресс-проверка $count встроенных узлов…",
                    detailLine = "Параллельный тест TLS + анти-16КБ для вашей сети",
                )
            )

            var probeCore: XrayCore? = null
            val pollerStop = AtomicBoolean(false)
            val poller = startProgressPoller(
                stopFlag = pollerStop,
                statusLine = "Экспресс-проверка серверов ${regionTitleRu(settings.region)}…",
                onProgress = onProgress,
            )
            try {
                if (shouldAbort?.invoke() == true) return 0
                probeCore = startProbeCoreWithSanitizer(context, cfg, vpnService, "SEED")
                Thread.sleep(160L)
                if (shouldAbort?.invoke() == true) return 0

                val fin = JSONObject(
                    VeloxNative.finalizeSeedQuickProbe(
                        batchId = batchId,
                        basePort = basePort,
                        targetRegion = settings.region,
                    )
                )
                return fin.optInt("aliveCount", 0)
            } catch (t: Throwable) {
                VeloxNative.logWarn(
                    context,
                    "PROBE",
                    "Экспресс-тест стартового пула прерван: ${formatThrowable(t)}"
                )
                return 0
            } finally {
                pollerStop.set(true)
                runCatching { poller?.interrupt() }
                runCatching { probeCore?.stop() }
                runCatching { probeCore?.close() }
            }
        } finally {
            running.set(false)
        }
    }

    fun refreshPoolBlocking(
        context: Context,
        settings: AppSettings,
        vpnService: VpnService? = null,
        maxBatch: Int = 42,
        shouldAbort: (() -> Boolean)? = null,
        onProgress: ((LiveProgressUpdate) -> Unit)? = null,
    ): BatchRefreshOutcome {
        if (!running.compareAndSet(false, true)) {
            return BatchRefreshOutcome(ok = false, error = "Проверка уже выполняется")
        }
        val t0 = System.currentTimeMillis()
        val pollerStop = AtomicBoolean(false)
        var poller: Thread? = null
        try {
            VeloxNative.reloadFromDisk(context)
            onProgress?.invoke(
                LiveProgressUpdate(
                    stageIndex = 1,
                    stageTotal = 5,
                    percent = 10,
                    etaSeconds = 13,
                    statusLine = if (settings.whitelistMode) {
                        "Подбор серверов «Белые списки РФ»…"
                    } else {
                        "Быстрый подбор серверов ${regionTitleRu(settings.region)}…"
                    },
                    detailLine = if (settings.whitelistMode) {
                        "Минцифры SNI + CIDR VK/Yandex/CDN + подписки (7 БС-фидов)"
                    } else {
                        "MASQUE-Chain (US/DE) + БС РФ + Reality/XHTTP/Hy2 (25 фидов)"
                    },
                )
            )

            poller = startProgressPoller(
                stopFlag = pollerStop,
                statusLine = "Подбор рабочих узлов ${regionTitleRu(settings.region)}…",
                onProgress = onProgress,
            )

            val basePort = VeloxPrefs.BATCH_PROBE_BASE_PORT
            val prepRaw = VeloxNative.prepareVpnProbeBatch(
                targetRegion = settings.region,
                whitelistMode = settings.whitelistMode,
                fragmentTls = settings.fragmentTls,
                basePort = basePort,
                maxBatch = maxBatch,
                activeSocksPort = 0,
            )
            if (shouldAbort?.invoke() == true) {
                return BatchRefreshOutcome(ok = false, error = "Отменено пользователем")
            }

            val prep = JSONObject(prepRaw)
            if (!prep.optBoolean("ok", false)) {
                val err = prep.optString("error", "Не удалось получить список серверов")
                return BatchRefreshOutcome(ok = false, error = err)
            }

            val batchId = prep.getString("batchId")
            val count = prep.optInt("count", 0)
            val rawConfig = prep.getString("probeConfigJson")

            onProgress?.invoke(
                LiveProgressUpdate(
                    stageIndex = 3,
                    stageTotal = 5,
                    percent = 42,
                    etaSeconds = 12,
                    statusLine = "Запуск проверки $count туннелей…",
                    detailLine = "MASQUE-Chain US/DE · Opera · Reality · XHTTP · Hy2",
                )
            )

            var probeCore: XrayCore? = null
            try {
                val tCore = System.currentTimeMillis()
                probeCore = startProbeCoreWithSanitizer(context, rawConfig, vpnService, "BATCH")
                VeloxNative.logInfo(
                    context,
                    "XRAY",
                    "Проверочное ядро запущено за ${System.currentTimeMillis() - tCore}мс ($count портов, base=$basePort)"
                )
                Thread.sleep(200L)

                if (shouldAbort?.invoke() == true) {
                    return BatchRefreshOutcome(ok = false, error = "Отменено пользователем")
                }

                val finRaw = VeloxNative.finalizeVpnProbeBatch(
                    batchId = batchId,
                    basePort = basePort,
                    targetRegion = settings.region,
                )
                val fin = JSONObject(finRaw)
                if (!fin.optBoolean("ok", false)) {
                    val err = fin.optString("error", "Ошибка глубокой проверки узлов")
                    VeloxNative.logErr(context, "PROBE", err)
                    return BatchRefreshOutcome(ok = false, error = err)
                }

                val tested = fin.optInt("testedCount", count)
                val newCnt = fin.optInt("newlyVerified", 0)
                val liveAvail = fin.optInt("liveAvailable", newCnt)
                val totalSec = ((System.currentTimeMillis() - t0) / 1000L).coerceAtLeast(1L)

                // CRITICAL: only report ok=true when we have genuine DEVICE-VERIFIED live nodes!
                val success = newCnt > 0 || liveAvail > 0
                if (!success) {
                    VeloxNative.logErr(
                        context,
                        "VPN",
                        "За ${totalSec}с ни один из $tested серверов не прошёл полную проверку в текущей сети"
                    )
                }
                return BatchRefreshOutcome(
                    ok = success,
                    testedCount = tested,
                    newlyVerified = newCnt,
                    liveAvailable = liveAvail,
                    error = if (!success) {
                        "0 из $tested узлов прошли ТСПУ — включите «Белые списки РФ» или откройте Журнал"
                    } else {
                        ""
                    }
                )
            } finally {
                runCatching { probeCore?.stop() }
                runCatching { probeCore?.close() }
            }
        } catch (t: Throwable) {
            val detail = formatThrowable(t)
            VeloxNative.logErr(context, "XRAY", "Сбой пакетной проверки: $detail")
            return BatchRefreshOutcome(
                ok = false,
                error = "Сбой проверки: ${detail.take(110)}"
            )
        } finally {
            pollerStop.set(true)
            runCatching { poller?.interrupt() }
            running.set(false)
        }
    }

    /**
     * Fast (~4–6s) dedicated Xray verification of user-imported subscriptions & keys
     * (Remnawave, Marzban, Happ, 3x-ui, Hiddify, V2Board, `happ://`, `v2raytun://`).
     */
    fun verifyCustomSubBlocking(
        context: Context,
        settings: AppSettings,
        vpnService: VpnService? = null,
        onProgress: ((LiveProgressUpdate) -> Unit)? = null,
    ): BatchRefreshOutcome {
        if (!running.compareAndSet(false, true)) {
            return BatchRefreshOutcome(ok = false, error = "Подождите окончания текущей проверки")
        }
        val pollerStop = AtomicBoolean(false)
        var poller: Thread? = null
        try {
            VeloxNative.reloadFromDisk(context)
            val basePort = VeloxPrefs.BATCH_PROBE_BASE_PORT
            onProgress?.invoke(
                LiveProgressUpdate(
                    stageIndex = 1,
                    stageTotal = 3,
                    percent = 18,
                    etaSeconds = 6,
                    statusLine = "Проверка серверов вашей подписки…",
                    detailLine = "Тест TLS / Reality / XHTTP / Белые списки",
                )
            )
            poller = startProgressPoller(
                stopFlag = pollerStop,
                statusLine = "Проверка вашей подписки…",
                onProgress = onProgress,
            )
            val prep = JSONObject(VeloxNative.prepareCustomSubProbe(basePort, settings.fragmentTls))
            if (!prep.optBoolean("ok", false)) {
                return BatchRefreshOutcome(
                    ok = false,
                    error = prep.optString("error", "Нет новых серверов для проверки"),
                )
            }
            val batchId = prep.getString("batchId")
            val count = prep.optInt("count", 0)
            val rawConfig = prep.getString("probeConfigJson")

            var probeCore: XrayCore? = null
            try {
                probeCore = startProbeCoreWithSanitizer(context, rawConfig, vpnService, "CSUB")
                Thread.sleep(150L)
                val fin = JSONObject(
                    VeloxNative.finalizeVpnProbeBatch(batchId, basePort, settings.region)
                )
                val newCnt = fin.optInt("newlyVerified", 0)
                return BatchRefreshOutcome(
                    ok = newCnt > 0,
                    testedCount = count,
                    newlyVerified = newCnt,
                    liveAvailable = fin.optInt("liveAvailable", newCnt),
                    error = if (newCnt == 0) {
                        "Подписка сохранена ($count серв.), но 0 ответили в текущей сети"
                    } else {
                        ""
                    },
                )
            } finally {
                runCatching { probeCore?.stop() }
                runCatching { probeCore?.close() }
            }
        } catch (t: Throwable) {
            return BatchRefreshOutcome(ok = false, error = formatThrowable(t).take(110))
        } finally {
            pollerStop.set(true)
            runCatching { poller?.interrupt() }
            running.set(false)
        }
    }

    /**
     * Smart Incremental Startup / Background Delta Sync:
     * 1) Quickly re-validates existing cached live servers (~2.5s): keeps still-working servers
     *    untouched (ZERO wasted reinstall!), deletes dead/broken old servers immediately.
     * 2) ONLY if pool needs top-up (first launch, <6 live servers, missing US/DE/WL, or new
     *    subscription servers), fetches & merges fresh working US + DE + WL-РФ servers!
     */
    fun smartDeltaSyncBlocking(
        context: Context,
        settings: AppSettings,
        shouldAbort: (() -> Boolean)? = null,
        onProgress: ((LiveProgressUpdate) -> Unit)? = null,
    ): BatchRefreshOutcome {
        if (shouldAbort?.invoke() == true) return BatchRefreshOutcome(ok = false)
        var kept = 0
        var removed = 0
        var needsTopUp = true
        var liveTotal = 0

        if (running.compareAndSet(false, true)) {
            var probeCore: XrayCore? = null
            try {
                VeloxNative.reloadFromDisk(context)
                val basePort = VeloxPrefs.SEED_PROBE_BASE_PORT
                val prep = JSONObject(
                    VeloxNative.prepareDeltaRevalidateBatch(basePort, settings.fragmentTls)
                )
                if (prep.optBoolean("ok", false) && shouldAbort?.invoke() != true) {
                    val count = prep.optInt("count", 0)
                    val batchId = prep.getString("batchId")
                    val rawCfg = prep.getString("probeConfigJson")
                    onProgress?.invoke(
                        LiveProgressUpdate(
                            stageIndex = 1,
                            stageTotal = 2,
                            percent = 25,
                            etaSeconds = 4,
                            statusLine = "Сверка $count сохранённых серверов…",
                            detailLine = "Рабочие оставляем, нерабочие убираем",
                        )
                    )
                    probeCore = startProbeCoreWithSanitizer(context, rawCfg, null, "DELTA")
                    Thread.sleep(150L)
                    if (shouldAbort?.invoke() != true) {
                        val fin = JSONObject(
                            VeloxNative.finalizeDeltaRevalidateBatch(batchId, basePort)
                        )
                        kept = fin.optInt("keptAlive", 0)
                        removed = fin.optInt("removedDead", 0)
                        liveTotal = fin.optInt("liveTotal", kept)
                        needsTopUp = fin.optBoolean("needsTopUp", liveTotal < 6)
                    }
                } else {
                    liveTotal = prep.optInt("liveTotal", 0)
                    kept = liveTotal
                    needsTopUp = prep.optBoolean("needsTopUp", liveTotal < 6)
                }
            } catch (_: Throwable) {
                needsTopUp = true
            } finally {
                runCatching { probeCore?.stop() }
                runCatching { probeCore?.close() }
                running.set(false)
            }
        } else {
            return BatchRefreshOutcome(ok = false, error = "busy")
        }

        if (shouldAbort?.invoke() == true) {
            return BatchRefreshOutcome(ok = kept > 0, keptAlive = kept, removedDead = removed)
        }

        if (!needsTopUp) {
            VeloxNative.logOk(
                context,
                "SYNC",
                "Пул актуален (живых: $liveTotal, убрано нерабочих: $removed) — переустановка не требуется"
            )
            return BatchRefreshOutcome(
                ok = true,
                newlyVerified = 0,
                liveAvailable = liveTotal,
                keptAlive = kept,
                removedDead = removed,
            )
        }

        // Top up pool with fresh verified US + DE + WL-РФ + Custom Sub nodes (skipping already-live ones!)
        val topUp = refreshPoolBlocking(
            context = context,
            settings = settings,
            vpnService = null,
            maxBatch = 44,
            shouldAbort = shouldAbort,
            onProgress = onProgress,
        )
        return topUp.copy(keptAlive = kept, removedDead = removed)
    }

    private fun startProgressPoller(
        stopFlag: AtomicBoolean,
        statusLine: String,
        onProgress: ((LiveProgressUpdate) -> Unit)?,
    ): Thread? {
        if (onProgress == null) return null
        return Thread({
            var lastEmitPct = -1
            var lastEmitDone = -1
            var lastEmitEta = -1
            val startedMs = System.currentTimeMillis()
            while (!stopFlag.get() && !Thread.currentThread().isInterrupted) {
                try {
                    Thread.sleep(380L)
                } catch (_: InterruptedException) {
                    break
                }
                if (stopFlag.get()) break
                val raw = runCatching { VeloxNative.getProbeProgress() }.getOrNull() ?: continue
                val snap = ProbeProgressSnapshot.fromJsonStr(raw)
                if (!snap.active) continue

                // Smooth live second-by-second countdown calibrated to v1.3 fast connect (~8-13s)
                val computedEta = if (snap.stageIdx <= 2) {
                    val elapsedSec = ((System.currentTimeMillis() - startedMs) / 1000L).toInt()
                    (14 - elapsedSec).coerceAtLeast(6)
                } else {
                    snap.etaSec.coerceAtLeast(1)
                }

                if (snap.percent != lastEmitPct || snap.done != lastEmitDone || computedEta != lastEmitEta) {
                    lastEmitPct = snap.percent
                    lastEmitDone = snap.done
                    lastEmitEta = computedEta
                    runCatching {
                        onProgress(
                            LiveProgressUpdate(
                                stageIndex = snap.stageIdx,
                                stageTotal = snap.stageTotal,
                                percent = snap.percent,
                                etaSeconds = computedEta,
                                statusLine = statusLine,
                                detailLine = snap.detail,
                            )
                        )
                    }
                }
            }
        }, "velox-eta").apply {
            isDaemon = true
            start()
        }
    }

    /**
     * Starts the temporary probe `XrayCore`. If any single community URI in the batch carries an
     * unsupported parameter, logs the exact error, strips only that outbound, and starts the rest.
     */
    private fun startProbeCoreWithSanitizer(
        context: Context,
        configJson: String,
        vpnService: VpnService?,
        label: String,
    ): XrayCore {
        val direct = runCatching {
            XrayCore.create(
                configJson = configJson,
                vpnService = vpnService,
                tunRuntimeProfile = XrayTunRuntimeProfile.LowMemory,
            )
        }
        if (direct.isSuccess) {
            val core = direct.getOrThrow()
            core.start()
            return core
        }

        val firstErr = formatThrowable(direct.exceptionOrNull())
        VeloxNative.logWarn(context, "XRAY", "[$label] Санитайзер конфига: $firstErr")

        val root = JSONObject(configJson)
        val inbounds = root.getJSONArray("inbounds")
        val outbounds = root.getJSONArray("outbounds")
        val routingObj = root.getJSONObject("routing")
        val rules = routingObj.getJSONArray("rules")
        val balancers = routingObj.optJSONArray("balancers")
        val observatory = root.optJSONObject("observatory")

        // Separate shared infrastructure (MASQUE-Chain carrier + direct freedom) from candidate slots
        val sharedIn = JSONArray()
        val candIn = ArrayList<JSONObject>()
        for (i in 0 until inbounds.length()) {
            val o = inbounds.getJSONObject(i)
            val tag = o.optString("tag")
            if (tag.startsWith("warp_hop")) sharedIn.put(o) else candIn.add(o)
        }

        val sharedOut = JSONArray()
        val outByTag = HashMap<String, JSONObject>()
        for (i in 0 until outbounds.length()) {
            val o = outbounds.getJSONObject(i)
            val tag = o.optString("tag")
            if (tag == "direct" || tag == "warp_bridge" || tag.startsWith("warp_hop")) {
                sharedOut.put(o)
            } else {
                outByTag[tag] = o
            }
        }

        val sharedRules = JSONArray()
        val ruleByInTag = HashMap<String, JSONObject>()
        for (i in 0 until rules.length()) {
            val r = rules.getJSONObject(i)
            val firstIn = r.optJSONArray("inboundTag")?.optString(0).orEmpty()
            if (firstIn.startsWith("warp_hop")) {
                sharedRules.put(r)
            } else if (firstIn.isNotEmpty()) {
                ruleByInTag[firstIn] = r
            }
        }

        val goodIn = JSONArray()
        val goodOut = JSONArray()
        val goodRules = JSONArray()
        for (i in 0 until sharedIn.length()) goodIn.put(sharedIn.getJSONObject(i))
        for (i in 0 until sharedRules.length()) goodRules.put(sharedRules.getJSONObject(i))
        var stripped = 0

        for (inb in candIn) {
            val inTag = inb.optString("tag")
            val rule = ruleByInTag[inTag] ?: continue
            val outTag = rule.optString("outboundTag")
            val outb = outByTag[outTag] ?: continue

            val testIn = JSONArray()
            for (k in 0 until sharedIn.length()) testIn.put(sharedIn.getJSONObject(k))
            testIn.put(inb)

            val testOut = JSONArray()
            for (k in 0 until sharedOut.length()) testOut.put(sharedOut.getJSONObject(k))
            testOut.put(outb)

            val testRules = JSONArray()
            for (k in 0 until sharedRules.length()) testRules.put(sharedRules.getJSONObject(k))
            testRules.put(rule)

            val testRouting = JSONObject()
                .put("domainStrategy", "AsIs")
                .put("rules", testRules)
            if (balancers != null && balancers.length() > 0) {
                testRouting.put("balancers", balancers)
            }

            val single = JSONObject().apply {
                put("log", JSONObject().put("loglevel", "none"))
                put("inbounds", testIn)
                put("outbounds", testOut)
                put("routing", testRouting)
                if (observatory != null) put("observatory", observatory)
            }
            val valid = runCatching {
                XrayCore.create(
                    configJson = single.toString(),
                    vpnService = vpnService,
                    tunRuntimeProfile = XrayTunRuntimeProfile.LowMemory,
                ).close()
            }.isSuccess
            if (valid) {
                goodIn.put(inb)
                goodOut.put(outb)
                goodRules.put(rule)
            } else {
                stripped++
            }
        }
        if (stripped > 0) {
            VeloxNative.logWarn(
                context,
                "XRAY",
                "[$label] Исключено несовместимых URI: $stripped, оставлено: ${goodOut.length()}"
            )
        }
        for (i in 0 until sharedOut.length()) goodOut.put(sharedOut.getJSONObject(i))

        val cleanRouting = JSONObject()
            .put("domainStrategy", "AsIs")
            .put("rules", goodRules)
        if (balancers != null && balancers.length() > 0) {
            cleanRouting.put("balancers", balancers)
        }

        val cleaned = JSONObject().apply {
            put("log", JSONObject().put("loglevel", "none"))
            put("inbounds", goodIn)
            put("outbounds", goodOut)
            put("routing", cleanRouting)
            if (observatory != null) put("observatory", observatory)
        }
        val core = XrayCore.create(
            configJson = cleaned.toString(),
            vpnService = vpnService,
            tunRuntimeProfile = XrayTunRuntimeProfile.LowMemory,
        )
        core.start()
        return core
    }

    fun formatThrowable(t: Throwable?): String {
        if (t == null) return "неизвестная ошибка"
        val primary = "${t.javaClass.simpleName}: ${t.message.orEmpty()}".trim()
        val cause = t.cause?.let { c ->
            if (c !== t && !c.message.isNullOrBlank() && c.message != t.message) {
                " [cause: ${c.javaClass.simpleName}: ${c.message}]"
            } else ""
        }.orEmpty()
        return (primary + cause).take(300)
    }
}
