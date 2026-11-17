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
    val region: String = "AUTO",              // AUTO, YT, WL, WARP, US, DE, NL, FI, GB, FR, SE, PL, CH, TR, JP, SG, CA, EU
    val pinnedNodeId: String = "",
    val dualChannel: Boolean = true,          // Dual-Channel Primary + Hot-Standby zero-drop failover (strictly region-scoped!)
    val sendHwid: Boolean = false,            // Opt-in Happ-compatible X-HWID device header for HWID-locked subscriptions
    val whitelistMode: Boolean = false,       // Mobile LTE/5G RU whitelist SNI priority
    val bypassRu: Boolean = true,             // Direct routing for RU banks, Gosuslugi, marketplaces
    val fragmentTls: Boolean = true,          // TCP TLS ClientHello anti-TSPU record splitting
    val adblockYoutube: Boolean = true,       // 0%-ad YouTube geo-split (AL/MD/GL=RU) + zero-RAM domain adblock
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
    val dualChannelActive: Boolean = false,
    val standbyNodeId: String = "",
    val standbyNodeName: String = "",
    val standbyProtocol: String = "",
    val standbyCountry: String = "",
    val standbyRttMs: Int = 0,
    val failoverCount: Int = 0,
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
        put("dualChannelActive", dualChannelActive)
        put("standbyNodeId", standbyNodeId)
        put("standbyNodeName", standbyNodeName)
        put("standbyProtocol", standbyProtocol)
        put("standbyCountry", standbyCountry)
        put("standbyRttMs", standbyRttMs)
        put("failoverCount", failoverCount)
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
            dualChannelActive = o.optBoolean("dualChannelActive", false),
            standbyNodeId = o.optString("standbyNodeId", ""),
            standbyNodeName = o.optString("standbyNodeName", ""),
            standbyProtocol = o.optString("standbyProtocol", ""),
            standbyCountry = o.optString("standbyCountry", ""),
            standbyRttMs = o.optInt("standbyRttMs", 0),
            failoverCount = o.optInt("failoverCount", 0),
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
    val ytAdFree: Boolean,
    val ytCountry: String,
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
            ytAdFree = o.optBoolean("yt_ad_free", false),
            ytCountry = o.optString("yt_country", ""),
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
    val encryptedKind: String = "",
    val bodyEncrypted: Boolean = false,
    val uploadBytes: Long = 0L,
    val downloadBytes: Long = 0L,
    val totalBytes: Long = 0L,
    val expireUnix: Long = 0L,
    val updateIntervalHours: Int = 0,
    val supportUrl: String = "",
    val webPageUrl: String = "",
    val announce: String = "",
    val hwidStatus: String = "",
) {
    val usedBytes: Long get() = (uploadBytes.coerceAtLeast(0L) + downloadBytes.coerceAtLeast(0L))

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
            encryptedKind = o.optString("encrypted_kind", ""),
            bodyEncrypted = o.optBoolean("body_encrypted", false),
            uploadBytes = o.optLong("upload_bytes", 0L),
            downloadBytes = o.optLong("download_bytes", 0L),
            totalBytes = o.optLong("total_bytes", 0L),
            expireUnix = o.optLong("expire_unix", 0L),
            updateIntervalHours = o.optInt("update_interval_hours", 0),
            supportUrl = o.optString("support_url", ""),
            webPageUrl = o.optString("web_page_url", ""),
            announce = o.optString("announce", ""),
            hwidStatus = o.optString("hwid_status", ""),
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
    val ytAdFreeCount: Int = 0,
    val ytAdFreeLiveCount: Int = 0,
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
    val hwidEnabled: Boolean = false,
    val hwidShort: String = "",
    val logs: List<String> = emptyList(),
) {
    companion object {
        fun parse(raw: String): EngineSnapshot = runCatching {
            val o = JSONObject(raw)
            val allNodes = o.optJSONArray("allVpnNodes").mapObjects(VpnNode::fromJson)
            val primaryNodes = o.optJSONArray("vpnNodes")?.mapObjects(VpnNode::fromJson) ?: allNodes
            EngineSnapshot(
                vpnNodes = primaryNodes,
                allVpnNodes = allNodes.ifEmpty { primaryNodes },
                tgProxies = o.optJSONArray("tgProxies").mapObjects(TgProxy::fromJson),
                sources = o.optJSONArray("sources").mapObjects(SubSourceItem::fromJson),
                customVpnCount = o.optInt("customVpnCount", 0),
                customSubCount = o.optInt("customSubCount", 0),
                deviceVerifiedCount = o.optInt("deviceVerifiedCount", 0),
                whitelistVerifiedCount = o.optInt("whitelistVerifiedCount", 0),
                ytAdFreeCount = o.optInt("ytAdFreeCount", 0),
                ytAdFreeLiveCount = o.optInt("ytAdFreeLiveCount", 0),
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
                hwidEnabled = o.optBoolean("hwidEnabled", false),
                hwidShort = o.optString("hwidValue", "").take(12),
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

data class RegionOption(
    val code: String,
    val flag: String,
    val shortLabel: String,
    val fullLabel: String,
)

val SELECTABLE_REGIONS: List<RegionOption> = listOf(
    RegionOption("AUTO", "⚡", "Авто", "Авто (лучший)"),
    RegionOption("YT", "📺", "YT без рекл.", "YouTube без рекламы (0%)"),
    RegionOption("WL", "🛡️", "БС РФ", "Белые списки РФ"),
    RegionOption("FI", "🇫🇮", "Финляндия", "Финляндия"),
    RegionOption("NL", "🇳🇱", "Нидерланды", "Нидерланды"),
    RegionOption("DE", "🇩🇪", "Германия", "Германия"),
    RegionOption("US", "🇺🇸", "США", "США"),
    RegionOption("GB", "🇬🇧", "Британия", "Великобритания"),
    RegionOption("FR", "🇫🇷", "Франция", "Франция"),
    RegionOption("SE", "🇸🇪", "Швеция", "Швеция"),
    RegionOption("PL", "🇵🇱", "Польша", "Польша"),
    RegionOption("CH", "🇨🇭", "Швейцария", "Швейцария"),
    RegionOption("TR", "🇹🇷", "Турция", "Турция"),
    RegionOption("JP", "🇯🇵", "Япония", "Япония"),
    RegionOption("SG", "🇸🇬", "Сингапур", "Сингапур"),
    RegionOption("CA", "🇨🇦", "Канада", "Канада"),
    RegionOption("WARP", "☁️", "WARP / MASQUE", "Cloudflare WARP / MASQUE"),
)

enum class VpnProtoFilter(val label: String) {
    ALL("Все"),
    YT_NOADS("📺 YT 0%"),
    REALITY("Reality"),
    XHTTP("XHTTP"),
    HY2("Hysteria 2"),
    GRPC_WS("gRPC / WS"),
    WARP("WARP / MASQUE"),
    CHAIN("2-Hop Chain"),
    OPERA("Opera"),
    WL("БС РФ"),
    OTHER("Trojan / SS / WG"),
    CUSTOM("Мои");

    fun matches(n: VpnNode): Boolean {
        val dp = n.displayProtocol.lowercase()
        val p = n.protocol.lowercase()
        return when (this) {
            ALL -> true
            YT_NOADS -> n.ytAdFree
            REALITY -> dp.contains("reality") && !dp.contains("xhttp") && !n.viaWarp
            XHTTP -> dp.contains("xhttp")
            HY2 -> p == "hysteria" || dp.contains("hysteria")
            GRPC_WS -> dp.contains("grpc") || dp.contains("ws") || dp.contains("httpupgrade")
            WARP -> dp.startsWith("warp") || p == "masque"
            CHAIN -> n.viaWarp
            OPERA -> dp.contains("opera")
            WL -> n.whitelistFriendly && !n.viaWarp
            OTHER -> p in setOf("trojan", "shadowsocks", "vmess", "wireguard", "socks", "http") &&
                !dp.contains("opera") && !dp.startsWith("warp")
            CUSTOM -> n.sourceTier == 0
        }
    }
}

enum class VpnSortMode(val label: String) {
    SMART("★ Умный"),
    PING("⚡ Пинг"),
    SPEED("🚀 Скорость"),
    COUNTRY("🌍 Страна"),
}

fun countryFlag(code: String): String = when (code.uppercase()) {
    "US" -> "🇺🇸"
    "DE" -> "🇩🇪"
    "NL" -> "🇳🇱"
    "FI" -> "🇫🇮"
    "SE" -> "🇸🇪"
    "NO" -> "🇳🇴"
    "DK" -> "🇩🇰"
    "IS" -> "🇮🇸"
    "AT" -> "🇦🇹"
    "CH" -> "🇨🇭"
    "FR" -> "🇫🇷"
    "GB", "UK" -> "🇬🇧"
    "IE" -> "🇮🇪"
    "CA" -> "🇨🇦"
    "EE" -> "🇪🇪"
    "LV" -> "🇱🇻"
    "LT" -> "🇱🇹"
    "ES" -> "🇪🇸"
    "PT" -> "🇵🇹"
    "PL" -> "🇵🇱"
    "CZ" -> "🇨🇿"
    "SK" -> "🇸🇰"
    "IT" -> "🇮🇹"
    "HU" -> "🇭🇺"
    "RO" -> "🇷🇴"
    "BG" -> "🇧🇬"
    "MD" -> "🇲🇩"
    "AL" -> "🇦🇱"
    "AM" -> "🇦🇲"
    "MC" -> "🇲🇨"
    "AD" -> "🇦🇩"
    "BY" -> "🇧🇾"
    "UZ" -> "🇺🇿"
    "KG" -> "🇰🇬"
    "MN" -> "🇲🇳"
    "BE" -> "🇧🇪"
    "LU" -> "🇱🇺"
    "TR" -> "🇹🇷"
    "JP" -> "🇯🇵"
    "SG" -> "🇸🇬"
    "KR" -> "🇰🇷"
    "HK" -> "🇭🇰"
    "TW" -> "🇹🇼"
    "IN" -> "🇮🇳"
    "AE" -> "🇦🇪"
    "IL" -> "🇮🇱"
    "KZ" -> "🇰🇿"
    "AU" -> "🇦🇺"
    "BR" -> "🇧🇷"
    "RU" -> "🇷🇺"
    "EU" -> "🇪🇺"
    "YT" -> "📺"
    "WL" -> "🛡️"
    "WARP", "CF" -> "☁️"
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
    "AUTO" -> "Авто (все страны)"
    "YT" -> "YouTube без рекламы"
    "WL" -> "Белые списки РФ"
    "AL" -> "Албания"
    "AM" -> "Армения"
    "LU" -> "Люксембург"
    "MC" -> "Монако"
    "BY" -> "Беларусь"
    "WARP" -> "WARP / MASQUE"
    "EU" -> "Европа"
    "US" -> "США"
    "DE" -> "Германия"
    "NL" -> "Нидерланды"
    "FI" -> "Финляндия"
    "GB", "UK" -> "Великобритания"
    "FR" -> "Франция"
    "SE" -> "Швеция"
    "NO" -> "Норвегия"
    "PL" -> "Польша"
    "CH" -> "Швейцария"
    "AT" -> "Австрия"
    "TR" -> "Турция"
    "JP" -> "Япония"
    "SG" -> "Сингапур"
    "CA" -> "Канада"
    "KR" -> "Корея"
    "HK" -> "Гонконг"
    "ES" -> "Испания"
    "IT" -> "Италия"
    "CZ" -> "Чехия"
    "HU" -> "Венгрия"
    "EE" -> "Эстония"
    "LV" -> "Латвия"
    "KZ" -> "Казахстан"
    "AE" -> "ОАЭ"
    "MD" -> "Молдова"
    "RU" -> "Россия"
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
