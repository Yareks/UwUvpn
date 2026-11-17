package app.velox.vpn.core

import org.json.JSONArray
import org.json.JSONObject

enum class VpnPhase {
    DISCONNECTED,
    FETCHING,
    CONNECTING,
    CONNECTED,
    HEALING,
    ERROR;

    companion object {
        fun from(raw: String): VpnPhase =
            entries.firstOrNull { it.name == raw } ?: DISCONNECTED
    }
}

enum class RuntimeProfileMode(val code: String, val title: String, val subtitle: String) {
    LOW_MEMORY("low", "Эко (мин. ОЗУ)", "Минимум ОЗУ (~6–10 МБ) и заряда батареи"),
    MOBILE("mobile", "Баланс (реком.)", "Оптимальная скорость и низкая нагрузка"),
    TURBO("turbo", "Макс. скорость", "Увеличенные буферы для 4K-видео и загрузок");

    companion object {
        fun from(code: String): RuntimeProfileMode =
            entries.firstOrNull { it.code == code } ?: MOBILE
    }
}

data class AppSettings(
    val region: String = "US",                // "US", "DE", "AUTO"
    val pinnedNodeId: String = "",
    val whitelistMode: Boolean = false,       // Mobile LTE/5G RU whitelist SNI priority
    val bypassRu: Boolean = true,             // Direct routing for RU banks, Gosuslugi, marketplaces
    val fragmentTls: Boolean = true,          // TCP TLS ClientHello anti-TSPU record splitting
    val autoHeal: Boolean = true,             // Automatic failover & dead-node replacement
    val profileMode: RuntimeProfileMode = RuntimeProfileMode.MOBILE,
    val tgMaxRttMs: Int = 1400,               // Strict Telegram DC resPQ ceiling (300..1400 ms)
    val excludedPackages: Set<String> = emptySet(),
)

data class VpnRuntimeState(
    val phase: VpnPhase = VpnPhase.DISCONNECTED,
    val statusLine: String = "Отключено · готов к работе",
    val activeNodeId: String = "",
    val activeNodeName: String = "",
    val activeProtocol: String = "",
    val exitCountry: String = "",
    val exitColo: String = "",
    val exitIp: String = "",
    val rttMs: Int = 0,
    val backupCount: Int = 0,
    val connectedSinceMs: Long = 0L,
    val connectingSinceMs: Long = 0L,
    val progressPercent: Int = 0,
    val etaSeconds: Int = 0,
    val stageIndex: Int = 0,
    val stageTotal: Int = 0,
    val stageDetail: String = "",
    val uplinkBytes: Long = 0L,
    val downlinkBytes: Long = 0L,
    val activeConnections: Int = 0,
    val updatedAtMs: Long = 0L,
) {
    val isActiveOrBusy: Boolean
        get() = phase == VpnPhase.CONNECTED ||
            phase == VpnPhase.CONNECTING ||
            phase == VpnPhase.FETCHING ||
            phase == VpnPhase.HEALING

    fun toJson(): JSONObject = JSONObject().apply {
        put("phase", phase.name)
        put("statusLine", statusLine)
        put("activeNodeId", activeNodeId)
        put("activeNodeName", activeNodeName)
        put("activeProtocol", activeProtocol)
        put("exitCountry", exitCountry)
        put("exitColo", exitColo)
        put("exitIp", exitIp)
        put("rttMs", rttMs)
        put("backupCount", backupCount)
        put("connectedSinceMs", connectedSinceMs)
        put("connectingSinceMs", connectingSinceMs)
        put("progressPercent", progressPercent)
        put("etaSeconds", etaSeconds)
        put("stageIndex", stageIndex)
        put("stageTotal", stageTotal)
        put("stageDetail", stageDetail)
        put("uplinkBytes", uplinkBytes)
        put("downlinkBytes", downlinkBytes)
        put("activeConnections", activeConnections)
        put("updatedAtMs", updatedAtMs)
    }

    companion object {
        fun fromJson(o: JSONObject): VpnRuntimeState = VpnRuntimeState(
            phase = VpnPhase.from(o.optString("phase", "DISCONNECTED")),
            statusLine = o.optString("statusLine", "Отключено"),
            activeNodeId = o.optString("activeNodeId", ""),
            activeNodeName = o.optString("activeNodeName", ""),
            activeProtocol = o.optString("activeProtocol", ""),
            exitCountry = o.optString("exitCountry", ""),
            exitColo = o.optString("exitColo", ""),
            exitIp = o.optString("exitIp", ""),
            rttMs = o.optInt("rttMs", 0),
            backupCount = o.optInt("backupCount", 0),
            connectedSinceMs = o.optLong("connectedSinceMs", 0L),
            connectingSinceMs = o.optLong("connectingSinceMs", 0L),
            progressPercent = o.optInt("progressPercent", 0),
            etaSeconds = o.optInt("etaSeconds", 0),
            stageIndex = o.optInt("stageIndex", 0),
            stageTotal = o.optInt("stageTotal", 0),
            stageDetail = o.optString("stageDetail", ""),
            uplinkBytes = o.optLong("uplinkBytes", 0L),
            downlinkBytes = o.optLong("downlinkBytes", 0L),
            activeConnections = o.optInt("activeConnections", 0),
            updatedAtMs = o.optLong("updatedAtMs", 0L),
        )
    }
}

data class ProbeProgressSnapshot(
    val active: Boolean = false,
    val stageIdx: Int = 0,
    val stageTotal: Int = 0,
    val percent: Int = 0,
    val etaSec: Int = 0,
    val done: Int = 0,
    val total: Int = 0,
    val alive: Int = 0,
    val detail: String = "",
) {
    companion object {
        fun fromJsonStr(raw: String): ProbeProgressSnapshot = runCatching {
            val o = JSONObject(raw)
            ProbeProgressSnapshot(
                active = o.optBoolean("active", false),
                stageIdx = o.optInt("stageIdx", 0),
                stageTotal = o.optInt("stageTotal", 0),
                percent = o.optInt("percent", 0),
                etaSec = o.optInt("etaSec", 0),
                done = o.optInt("done", 0),
                total = o.optInt("total", 0),
                alive = o.optInt("alive", 0),
                detail = o.optString("detail", ""),
            )
        }.getOrDefault(ProbeProgressSnapshot())
    }
}

data class VpnNode(
    val id: String,
    val name: String,
    val displayProtocol: String,
    val protocol: String,
    val host: String,
    val port: Int,
    val sni: String,
    val exitCountry: String,
    val exitColo: String,
    val exitIp: String,
    val rttMs: Int,
    val kbps: Int,
    val whitelistFriendly: Boolean,
    val fragmentEnabled: Boolean,
    val viaWarp: Boolean,
    val deviceVerified: Boolean,
    val sourceTier: Int,
    val failCount: Int,
) {
    companion object {
        fun fromJson(o: JSONObject): VpnNode = VpnNode(
            id = o.optString("id"),
            name = o.optString("name", "Узел VPN"),
            displayProtocol = o.optString("display_protocol", o.optString("protocol", "VLESS")),
            protocol = o.optString("protocol"),
            host = o.optString("host"),
            port = o.optInt("port", 443),
            sni = o.optString("sni"),
            exitCountry = o.optString("exit_country"),
            exitColo = o.optString("exit_colo"),
            exitIp = o.optString("exit_ip"),
            rttMs = o.optInt("rtt_ms", 0),
            kbps = o.optInt("kbps", 0),
            whitelistFriendly = o.optBoolean("whitelist_friendly", false),
            fragmentEnabled = o.optBoolean("fragment_enabled", false),
            viaWarp = o.optBoolean("via_warp", false),
            deviceVerified = o.optBoolean("device_verified", false),
            sourceTier = o.optInt("source_tier", 1),
            failCount = o.optInt("fail_count", 0),
        )
    }
}

data class TgProxy(
    val id: String,
    val kind: String,        // "faketls", "dd", "classic", "socks5"
    val kindLabel: String,
    val host: String,
    val port: Int,
    val sniDomain: String,
    val rttMs: Int,
    val jitterMs: Int,
    val verifiedDc: Int,
    val supportsCalls: Boolean,
    val tgLink: String,
    val tmeLink: String,
    val verifiedUnix: Long,
) {
    companion object {
        fun fromJson(o: JSONObject): TgProxy = TgProxy(
            id = o.optString("id"),
            kind = o.optString("kind"),
            kindLabel = o.optString("kind_label", "MTProto"),
            host = o.optString("host"),
            port = o.optInt("port", 443),
            sniDomain = o.optString("sni_domain"),
            rttMs = o.optInt("rtt_ms", 0),
            jitterMs = o.optInt("jitter_ms", 0),
            verifiedDc = o.optInt("verified_dc", 2),
            supportsCalls = o.optBoolean("supports_calls", false),
            tgLink = o.optString("tg_link"),
            tmeLink = o.optString("tme_link"),
            verifiedUnix = o.optLong("verified_unix", 0L),
        )
    }
}

data class SubSourceItem(
    val name: String,
    val url: String,
    val kind: String,
    val regionHint: String,
    val enabled: Boolean,
    val builtin: Boolean,
    val userinfo: String = "",
    val cachedCount: Int = 0,
    val lastSyncUnix: Long = 0L,
) {
    companion object {
        fun fromJson(o: JSONObject): SubSourceItem = SubSourceItem(
            name = o.optString("name"),
            url = o.optString("url"),
            kind = o.optString("kind", "vpn"),
            regionHint = o.optString("region_hint", "AUTO"),
            enabled = o.optBoolean("enabled", true),
            builtin = o.optBoolean("builtin", true),
            userinfo = o.optString("userinfo", ""),
            cachedCount = o.optInt("cached_count", 0),
            lastSyncUnix = o.optLong("last_sync_unix", 0L),
        )
    }
}

data class TgBridgeStatus(
    val total: Int = 0,
    val checked: Int = 0,
    val alive: Int = 0,
    val bridgeRunning: Boolean = false,
    val bridgePort: Int = 10809,
    val bridgeLink: String = "tg://socks?server=127.0.0.1&port=10809",
    val bridgeSessions: Long = 0L,
    val bridgeBytes: Long = 0L,
    val wsAvailable: Boolean = false,
    val wsRttMs: Int = 0,
) {
    companion object {
        fun fromJsonStr(raw: String): TgBridgeStatus = runCatching {
            val o = JSONObject(raw)
            TgBridgeStatus(
                total = o.optInt("total", 0),
                checked = o.optInt("checked", 0),
                alive = o.optInt("alive", 0),
                bridgeRunning = o.optBoolean("bridgeRunning", false),
                bridgePort = o.optInt("bridgePort", 10809),
                bridgeLink = o.optString("bridgeLink", "tg://socks?server=127.0.0.1&port=10809"),
                bridgeSessions = o.optLong("bridgeSessions", 0L),
                bridgeBytes = o.optLong("bridgeBytes", 0L),
                wsAvailable = o.optBoolean("wsAvailable", false),
                wsRttMs = o.optInt("wsRttMs", 0),
            )
        }.getOrDefault(TgBridgeStatus())
    }
}

data class EngineSnapshot(
    val vpnNodes: List<VpnNode> = emptyList(),
    val allVpnNodes: List<VpnNode> = emptyList(),
    val tgProxies: List<TgProxy> = emptyList(),
    val sources: List<SubSourceItem> = emptyList(),
    val customVpnCount: Int = 0,
    val customSubCount: Int = 0,
    val deviceVerifiedCount: Int = 0,
    val whitelistVerifiedCount: Int = 0,
    val manifestUrl: String = "",
    val hasWarpWg: Boolean = false,
    val hasWarpMasque: Boolean = false,
    val warpIpv4: String = "",
    val operaCount: Int = 0,
    val lastVpnRefreshUnix: Long = 0L,
    val lastTgRefreshUnix: Long = 0L,
    val bridgeRunning: Boolean = false,
    val bridgePort: Int = 10809,
    val bridgeLink: String = "tg://socks?server=127.0.0.1&port=10809",
    val wsAvailable: Boolean = false,
    val wsRttMs: Int = 0,
    val logs: List<String> = emptyList(),
) {
    companion object {
        fun parse(raw: String): EngineSnapshot = runCatching {
            val o = JSONObject(raw)
            EngineSnapshot(
                vpnNodes = o.optJSONArray("vpnNodes").mapObjects(VpnNode::fromJson),
                allVpnNodes = o.optJSONArray("allVpnNodes").mapObjects(VpnNode::fromJson),
                tgProxies = o.optJSONArray("tgProxies").mapObjects(TgProxy::fromJson),
                sources = o.optJSONArray("sources").mapObjects(SubSourceItem::fromJson),
                customVpnCount = o.optInt("customVpnCount", 0),
                customSubCount = o.optInt("customSubCount", 0),
                deviceVerifiedCount = o.optInt("deviceVerifiedCount", 0),
                whitelistVerifiedCount = o.optInt("whitelistVerifiedCount", 0),
                manifestUrl = o.optString("manifestUrl", ""),
                hasWarpWg = o.optBoolean("hasWarpWg", false),
                hasWarpMasque = o.optBoolean("hasWarpMasque", false),
                warpIpv4 = o.optString("warpIpv4", ""),
                operaCount = o.optInt("operaCount", 0),
                lastVpnRefreshUnix = o.optLong("lastVpnRefreshUnix", 0L),
                lastTgRefreshUnix = o.optLong("lastTgRefreshUnix", 0L),
                bridgeRunning = o.optBoolean("bridgeRunning", false),
                bridgePort = o.optInt("bridgePort", 10809),
                bridgeLink = o.optString("bridgeLink", "tg://socks?server=127.0.0.1&port=10809"),
                wsAvailable = o.optBoolean("wsAvailable", false),
                wsRttMs = o.optInt("wsRttMs", 0),
                logs = o.optJSONArray("logs").mapStrings(),
            )
        }.getOrDefault(EngineSnapshot())
    }
}

data class InstalledAppInfo(
    val packageName: String,
    val label: String,
)

/**
 * Built-in Russian banking, government, payment, taxi, and marketplace apps automatically
 * bypassed when "Обход для банков и сервисов РФ" is enabled so they never trigger fraud blocks.
 */
object RuBypassPackages {
    val DEFAULT: Set<String> = setOf(
        // Banking & Mir / SBP payments
        "ru.sberbankmobile",
        "com.idamob.tinkoff.android",
        "ru.tbank.android",
        "ru.vtb24.mobilebanking.android",
        "ru.alfabank.mobile.android",
        "ru.raiffeisennews",
        "ru.gazprombank.android.mobilebank.app",
        "ru.sovcombank.halva.v1",
        "ru.rosbank.android",
        "logo.com.mbanking",
        "ru.pochtabank",
        "ru.rshb.dbo",
        "ru.yoomoney.android",
        "ru.nspk.mirpay",
        "ru.nspk.sbpay",
        // Gosuslugi, FNS, Mos.ru
        "ru.rostel",
        "ru.gosuslugi.pos",
        "ru.fns.lkfl",
        "ru.mos.app",
        "ru.emias.app",
        // Marketplaces, delivery, taxi, navigation, domestic messengers
        "ru.ozon.app.android",
        "com.wildberries.ru",
        "com.avito.android",
        "ru.yandex.taxi",
        "ru.yandex.yandexmaps",
        "ru.yandex.yandexnavi",
        "ru.beru.android",
        "com.vkontakte.android",
        "ru.ok.android",
        "ru.oneme.app",
        "ru.mts.mymts",
        "ru.megafon.mlk",
        "ru.beeline.services",
        "ru.tele2.mytele2",
        "ru.russianpost.client",
        "ru.rzd.pass",
    )
}

inline fun <T> JSONArray?.mapObjects(transform: (JSONObject) -> T): List<T> {
    if (this == null) return emptyList()
    val out = ArrayList<T>(length())
    for (i in 0 until length()) {
        val obj = optJSONObject(i) ?: continue
        out.add(transform(obj))
    }
    return out
}

fun JSONArray?.mapStrings(): List<String> {
    if (this == null) return emptyList()
    val out = ArrayList<String>(length())
    for (i in 0 until length()) {
        val s = optString(i)
        if (s.isNotEmpty()) out.add(s)
    }
    return out
}

fun countryFlag(code: String): String = when (code.uppercase()) {
    "US" -> "🇺🇸"
    "DE" -> "🇩🇪"
    "NL" -> "🇳🇱"
    "FI" -> "🇫🇮"
    "SE" -> "🇸🇪"
    "AT" -> "🇦🇹"
    "CH" -> "🇨🇭"
    "FR" -> "🇫🇷"
    "GB" -> "🇬🇧"
    "CA" -> "🇨🇦"
    "EE" -> "🇪🇪"
    "ES" -> "🇪🇸"
    "PL" -> "🇵🇱"
    "CZ" -> "🇨🇿"
    "LV" -> "🇱🇻"
    "LT" -> "🇱🇹"
    "IT" -> "🇮🇹"
    "HU" -> "🇭🇺"
    "RU" -> "🇷🇺"
    "BE" -> "🇧🇪"
    "NO" -> "🇳🇴"
    "DK" -> "🇩🇰"
    "CF" -> "☁️"
    "AUTO" -> "⚡"
    else -> "🌐"
}

fun formatEtaRu(seconds: Int): String {
    if (seconds <= 0) return "почти готово"
    if (seconds <= 2) return "≈ 1–2 сек"
    if (seconds < 60) return "≈ $seconds сек"
    val m = seconds / 60
    val s = seconds % 60
    return if (s == 0) "≈ $m мин" else String.format("≈ %d мин %02d сек", m, s)
}

fun regionTitleRu(code: String): String = when (code.uppercase()) {
    "US" -> "США"
    "DE" -> "Германия"
    "AUTO" -> "Авто (US/DE)"
    else -> code
}

fun formatBytesRu(bytes: Long): String {
    if (bytes < 1024L) return "$bytes Б"
    val kb = bytes / 1024.0
    if (kb < 1024.0) return String.format("%.1f КБ", kb)
    val mb = kb / 1024.0
    if (mb < 1024.0) return String.format("%.1f МБ", mb)
    val gb = mb / 1024.0
    return String.format("%.2f ГБ", gb)
}

fun formatDuration(elapsedMs: Long): String {
    val totalSec = (elapsedMs / 1000L).coerceAtLeast(0L)
    val h = totalSec / 3600L
    val m = (totalSec % 3600L) / 60L
    val s = totalSec % 60L
    return String.format("%02d:%02d:%02d", h, m, s)
}
