package app.velox.vpn.core

import org.json.JSONArray
import org.json.JSONObject

/**
 * v1.7.7 — совместимость с Xray-core v26.10.21+ (ядро `xray-rust-mobile 0.10.0`).
 *
 * Новое ядро стало строгим: вместо игнорирования устаревших/некорректных полей оно
 * **отвергает весь конфиг**, и туннель не поднимается. Из журнала:
 *
 * ```
 * XrayCoreException: reality fingerprint `ios` has no X25519MLKEM768 key share, which REALITY
 * servers from Xray-core v26.10.21 require
 * freedom domainStrategy is deprecated; its value was migrated to `streamSettings.sockopt.domainStrategy`
 * fakeIp poolSize exceeds the 65534 usable addresses in ipv4Pool
 * ```
 *
 * Проверочное ядро при этом рапортовало «14/14 живых» — потому что проверка делает TLS-хендшейк,
 * а не валидацию конфига. Отсюда «серверы есть, подключения нет».
 *
 * Этот санитайзер приводирует (нормализует) любой конфиг из нативного ядра к тому, что новое
 * ядро гарантированно принимает. Это страховка на всех путях — туннель, проверка, WARP-цепочка, —
 * даже если генератор ядра когда-нибудь снова добавит устаревшее поле.
 */
object XrayConfigSanitizer {

    /** Подписи, которые ОБЯЗАНЫ содержать X25519MLKEM768. Остальные новое ядро отвергает. */
    private val TLS_SAFE_FINGERPRINTS = setOf("chrome", "firefox", "safari", "random")

    /**
     * Возвращает безопасный конфиг. При любой проблеме разбора возвращает исходную строку —
     * санитайзер никогда не должен быть причиной отказа подключения.
     */
    fun sanitize(configJson: String): String = runCatching {
        if (!configJson.trimStart().startsWith("{")) return configJson
        val root = JSONObject(configJson)

        fixFingerprints(root)
        fixFreedomDomainStrategy(root)
        fixFakeIp(root)

        root.toString()
    }.getOrDefault(configJson)

    // ------------------------------------------------------------------ fingerprints

    private fun fixFingerprints(node: Any?) {
        when (node) {
            is JSONObject -> {
                // 1) "fingerprint": "ios" -> "chrome" в любом месте конфига
                if (node.has("fingerprint")) {
                    val fp = node.optString("fingerprint").trim().lowercase()
                    if (fp.isNotEmpty() && fp !in TLS_SAFE_FINGERPRINTS) {
                        node.put("fingerprint", "chrome")
                    }
                }
                // 2) новое ядро принимает только {chrome, firefox, safari, random}; устаревшее
                //    `randomized` тоже убираем, оставляя валидное значение.
                if (node.has("fingerprint")) {
                    val fp = node.optString("fingerprint").trim().lowercase()
                    if (fp == "randomized") node.put("fingerprint", "random")
                }
                val keys = node.keys()
                val collect = ArrayList<String>()
                while (keys.hasNext()) collect.add(keys.next())
                for (k in collect) fixFingerprints(node.opt(k))
            }
            is JSONArray -> for (i in 0 until node.length()) fixFingerprints(node.opt(i))
        }
    }

    // ------------------------------------------------------------------ freedom outbound

    /**
     * `freedom` больше не принимает `settings.domainStrategy` — только `streamSettings.sockopt`.
     * Также убираем пустой `streamSettings` (ядро ругается на пустой объект).
     */
    private fun fixFreedomDomainStrategy(root: JSONObject) {
        val outbounds = root.optJSONArray("outbounds") ?: return
        for (i in 0 until outbounds.length()) {
            val ob = outbounds.optJSONObject(i) ?: continue
            if (!ob.optString("protocol").equals("freedom", ignoreCase = true)) continue

            val settings = ob.optJSONObject("settings")
            val legacy = settings?.optString("domainStrategy").orEmpty()
            if (settings != null && settings.has("domainStrategy")) settings.remove("domainStrategy")

            val stream = ob.optJSONObject("streamSettings")
            if (legacy.isNotBlank()) {
                val target = stream ?: JSONObject().also { ob.put("streamSettings", it) }
                val sockopt = target.optJSONObject("sockopt")
                    ?: JSONObject().also { target.put("sockopt", it) }
                // UseIPv4 — то, что нам нужно (мобильные сети без рабочего IPv6)
                val normalized = when (legacy.trim().lowercase()) {
                    "useipv6" -> "UseIPv6"
                    "useip" -> "UseIP"
                    "asis" -> "AsIs"
                    else -> "UseIPv4"
                }
                if (!sockopt.has("domainStrategy")) sockopt.put("domainStrategy", normalized)
            }
            // пустой streamSettings без ключей — лишний повод для валидатора ругаться
            val st = ob.optJSONObject("streamSettings")
            if (st != null && st.length() == 0) ob.remove("streamSettings")
        }
    }

    // ------------------------------------------------------------------ fakeIp

    /**
     * `fakeIp.poolSize` должен быть СТРОГО меньше числа пригодных адресов пула:
     * `198.19.0.0/16` = 65534. Ядро отвергает даже равенство. Держим половину — с запасом.
     */
    private fun fixFakeIp(root: JSONObject) {
        val dns = root.optJSONObject("dns") ?: return
        val fake = dns.optJSONObject("fakeIp") ?: return
        val pool = fake.optString("ipv4Pool", "198.19.0.0/16")
        val usable = usableAddresses(pool)
        val wanted = fake.optInt("poolSize", 0)
        val safe = (usable * 3 / 4).coerceAtLeast(1024)
        if (wanted <= 0 || wanted >= usable) fake.put("poolSize", safe)
    }

    /** Пригодные адреса в IPv4 CIDR: 2^(32-prefix) - 2 (сеть и broadcast). */
    private fun usableAddresses(cidr: String): Int = runCatching {
        val prefix = cidr.substringAfter("/").toInt()
        val hosts = if (prefix >= 31) 0 else (1 shl (32 - prefix)) - 2
        hosts.coerceIn(2, 65534)
    }.getOrDefault(65534)
}
