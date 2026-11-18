# UwUvpn (VeloxVPN)

<p align="center">
  <b>Сверхлёгкий и быстрый VPN + Telegram-прокси клиент для Android на 100% Rust-ядре</b><br/>
  Без регистрации · Без рекламы и телеметрии · Минимальная нагрузка на ОЗУ и батарею · Android 7.0–16
</p>

<p align="center">
  <a href="https://github.com/Yareks/UwUvpn/releases/latest"><b>Скачать готовый APK (Releases)</b></a> ·
  <a href="#возможности">Возможности</a> ·
  <a href="#архитектура">Архитектура</a> ·
  <a href="#сборка-из-исходников">Сборка из исходников</a> ·
  <a href="#english-summary">English</a>
</p>

---

## Возможности

- **v1.7.6: обновление подписки и подключение ВПН** — `syncSubscription`/`addCustomItem` (Happ crypt, Remnawave, Marzban) вынесены в изолированный процесс `:probe`; у каждого процесса (UI / `:probe` / `:vpn`) теперь **свои диапазоны портов** (конфликт портов был причиной «ВПН не подключается»); межпроцессный маркер `vpn_connecting.marker` даёт подключению приоритет и мгновенно сворачивает проверку; падения `:probe` больше не включают «безопасный режим», а пишутся как `PROBE_CRASH`.
- **v1.7.5: устранён краш при загрузке/обновлении серверов** — подбор узлов вынесен в **отдельный процесс `:probe`** (падение нативного ядра больше не закрывает приложение, при отказе OEM — авто-переезд в процесс туннеля `:vpn`); колбэки прогресса изолированы; проверочные `.so` в APK больше не сжимаются deflate (прямой `mmap` вместо рискованной распаковки 20-МБ библиотеки); отчёт о сбое пишется и для нативных падений.
- **v1.7.4: исправлен краш «главный экран и сразу закрылось»** — все фоновые задачи UI идут через `launchGuarded` (ошибка логируется, процесс жив), чтение состояния из ядра защищено от `null` (раньше `NPE` в корутине `lifecycleScope` убивал приложение), тайл быстрых настроек изолирован, R8/обфускация отключены, а шаги холодного старта пишутся в `startup_trace.log` и попадают в отчёт о сбое.
- **v1.7.3: самодиагностика сбоев и защита от падений** — глобальный обработчик пишет стектрейс любого краша в `crash_report.txt` (чистый Kotlin, переживает падение JNI/`.so`/Compose), следующий запуск открывается в **безопасном режиме** (без тяжёлой инициализации) и показывает отчёт в журнале; у корутин сервисов появился `CoroutineExceptionHandler`, а `onCreate`/`onStartCommand` больше не могут уронить процесс; при «ядро не вернуло план» приложение штатно уходит на подбор узлов вместо `JSONObject(null)`; проверочные сокеты при живом туннеле принудительно идут мимо TUN.
- **v1.7.2: аудит и «идеализация» горячего пути** — блокирующие проверки живости вынесены в отдельную полосу (`single-flight`), поэтому 1-секундный монитор больше не замирает на 15–21 с; смена страны и настроек при живом туннеле выполняется **атомарной заменой ядра без разрыва** (подбор узлов идёт параллельно, интернет не пропадает); `currentState` стал `@Volatile`; исправлено двойное исполнение критической секции в межпроцессном локалке; UI получает состояние **внутри broadcast** (без чтения файла с диска на главном потоке); запись снимка состояния на flash стала в 4 раза реже.
- **v1.7.1: лечение «обрывов через пару минут» (анти-флап)** — сторожевой контур больше не принимает «эталонные» адреса (`gstatic` / `example.com` / `1.1.1.1`) за единственный критерий жизни узла. Добавлена **L1-проба SOCKS5 CONNECT**: если ядро принимает соединение, туннель считается живым, даже когда сам узел закрывает посторонние сайты (типично для узлов «Белых списков РФ» и подписок с фильтрацией SNI). Автопереключение требует **3 подтверждений подряд** и ограничено **демпфером флапа** (не более 3 переключений за 6 минут, далее пауза 3 минуты), поэтому рабочий сервер больше не меняется «сам по себе» и не рвёт уже открытые соединения.
- **v1.7.0: анти-разрыв + приоритетный резерв + 0% серверов РФ** — горячий резерв `#2` теперь сначала берётся **из той же страны**, что и активный сервер `#1` (никакого прыжка страны при сбое), затем **Германия (DE) / США (US)**; серверы с выходом в РФ полностью исключены; TCP `tcpKeepAlive 28с` + RFC 5482 `tcpUserTimeout 15с` + heartbeat для WS/gRPC/XHTTP против CGNAT-обрывов; вкладка **«Сервисы»** с одиночной проверкой 12 групп сервисов (ИИ, Discord, соцсети, видео, игры, работа) и **свои правила сайтов** (через VPN / напрямую / блок).
- **100% Rust сетевой стек (`xray-rust` 0.10.0 + `velox-engine` 1.7.0)** — нативный туннель с потреблением ~4–8 МБ ОЗУ в простое, отдельным процессом `:vpn` (1-поточный рантайм, энергосбережение при выключенном экране и в авиарежиме, `90s`/`180s` radio-tail friendly observatory), чистым `IPv4 TUN` без утечек IPv6, `FakeIP DNS (198.19.0.0/16)`, аутентификацией RFC 1929 на локальном SOCKS5 (`127.0.0.1:10808`), прозрачной маршрутизацией браузерных `DoH/DoT` (Chrome, Яндекс Браузер, Opera, Brave, Firefox, AdGuard, WebView) и Discord, профилями `LowMemory` / `Mobile` / `MobilePlus` и выравниванием ELF-сегментов `16 КБ` (`arm64-v8a` и `armeabi-v7a`, Android 7.0–16, включая Android 12).
- **Двухканальный режим `2×` (Primary + горячий резерв Hot-Standby без обрыва `tun0`):**
  - Одновременно держит основной канал `vpn_0` (100% трафика, без «прыжков» IP) и заранее проверенный резерв `vpn_1` с мгновенным переключением в ядре (`fallbackTag`), пассивным детектором зависания (3 с), автопродвижением `#2 → #1` и автопополнением нового `#2` в фоне.
  - Строгая изоляция по стране: в режиме `Авто` выбирает лучший основной + лучший резерв на другом хосте, а при выборе конкретной страны (например, `🇩🇪 Германия`) основной, резервный и все автопереключения строго ограничены этой страной.
- **Полная офлайн-совместимость с Happ 4.11+ / Incy / Remnawave / Marzban / 3x-ui:**
  - Офлайн-расшифровка `happ://crypt`, `crypt2`, `crypt3`, `crypt4`, `crypt5`, `incy://crypt1/` и AES-128-GCM зашифрованных тел подписок (`Encrypt-Tag`), импорт сырых JSON-конфигов Xray, поддержка 19 схем deep-link (`happ://`, `incy://`, `v2raytun://`, `hiddify://`, `clash://`, `flclash://`, `sing-box://`, `v2rayng://`, `streisand://`, `karing://`, `velox://`, `uwuvpn://` и др.).
  - Опциональная анонимная привязка `X-HWID` (SHA-256) + заголовки устройства в точном wire-order `Happ`, чтение `profile-title` (`base64:`), квот трафика, срока действия, `profile-update-interval`, объявлений (`announce`), кнопок поддержки/кабинета, `new-url` и статуса лимита HWID + автоматическое редактирование секретов/токенов в журнале.
- **Расширения анти-DPI протоколов 2026:** поддержка `pcs`/`pinSHA256` (`pinnedPeerCertSha256`), `vcn` (`verifyPeerCertByName`), WebSocket 0-RTT Early Data (`?ed=2048`), `XHTTP` + `xtls-rprx-vision` + полного JSON `extra` (`xmux`, `downloadSettings`, `xPaddingBytes`), постквантового REALITY `pqv` (`mldsa65Verify`) и VLESS `encryption` (`mlkem768x25519plus`), gzip/deflate и `ETag`/`304 Not Modified` кэширования фидов.
- **YouTube и сайты без рекламы (0 МБ доп. ОЗУ, со скоростным фильтром):**
  - Автоматическое определение быстрых серверов с 0% монетизации YouTube (`youtube.com/sw.js_data`: Албания, Молдова и европейские VPS с YouTube GeoIP `RU`) и сплит-маршрутизация `yt_pool` со скоростным порогом и мгновенным фоллбэком на `vpn_0` (без буферизации 1080p60/4K).
  - Встроенный доменный антибаннер (`NXDOMAIN` + фильтрация в туннеле: DoubleClick, Google Ads/IMA, Яндекс.Директ/AdFox, myTarget, popunder-сети) без поломки сайтов и видеопотоков.
- **16+ стран и многоэшелонный бесплатный пул без аккаунтов (96 автообновляемых источников: 79 VPN + 17 Telegram, до 120 проверенных подключений в пуле):**
  - **Страны и режимы в 1 тап:** Авто, YouTube без рекламы (0%), Белые списки РФ, Финляндия, Нидерланды, Германия, США, Великобритания, Франция, Швеция, Польша, Швейцария, Турция, Япония, Сингапур, Канада и Cloudflare WARP / MASQUE + фильтрация по протоколам и сортировка по пингу/скорости/стране.
  - **Эшелон 1 — Прямые анти-DPI протоколы:** `VLESS + REALITY` (`Vision`, `XHTTP`, `gRPC`, `WS`, `HTTPUpgrade` с uTLS `chrome`, `firefox`, `safari`, `ios`, `edge`, `qq`), `Hysteria 2` (QUIC + Salamander + port hopping), `Trojan`, `VMess AEAD`, `Shadowsocks 2022` / `SS AEAD`, `WireGuard` (+ AmneziaWG Noise), `SOCKS5` (+ TLS) и `HTTPS CONNECT` + фрагментация TLS ClientHello (`finalmask.tcp`).
  - **Эшелон 2 — Двуххоповый `MASQUE-Chain` (США / ЕС / Азия):** автоматическая маршрутизация зарубежных узлов (`SS2022`, `Trojan`, `VLESS`, `VMess`, `Opera US/NL/SG`) поверх HTTP/3 QUIC и HTTP/2 TCP туннеля Cloudflare WARP MASQUE.
  - **Эшелон 3 — Opera HTTPS TLS (США / Нидерланды / Сингапур) & Cloudflare WARP (`MASQUE H3`, `MASQUE H3 + Noise`, `MASQUE H2 + Frag`, `AWG Noise`, порты `:443/:8443/:500`):** автоматический выпуск бесплатных ключей на устройстве без регистрации.
- **Режим «Белые списки РФ»:** строгий приоритет и изоляция серверов с SNI из белых списков мобильных операторов и релейных мостов в российских облачных подсетях (с выходом в Европу и США), включая зеркала источников на Codeberg.
- **Полноценный импорт своих подписок и ключей:**
  - Поддержка любых `https://` подписок (Remnawave, Marzban, Happ, 3x-ui, PasarGuard, Hiddify, V2Board и др.) с клиентскими `User-Agent`, распаковкой Base64, чтением `profile-title` и `subscription-userinfo`, фильтрацией служебных заглушек и мгновенной проверкой пинга/скорости.
  - Поддержка deep-link ссылок (`happ://add/...`, `v2raytun://import/...`, `v2rayng://...`, `hiddify://...`, `sing-box://...`, `clash://...`, `ssconf://...`), а также одиночной и многострочной вставки `vless://`, `vmess://`, `hy2://`, `trojan://`, `ss://`, `tg://proxy`, `socks5://`.
- **Настоящая проверка прокси Telegram (строго ≤ 1400 мс) + локальный мост `TG-WS`:**
  - Честный криптографический handshake `Fake-TLS (ee)` / `MTProto obfuscated2 (dd)` / `SOCKS5` с отправкой реального `req_pq_multi` и проверкой 128-битного nonce в `resPQ` от DC Telegram.
  - Встроенный локальный умный прокси `127.0.0.1:10809` с автопереключением между прямым `WebSocket (TG-WS)` и пулом проверенных прокси.
- **Умное инкрементальное (дельта) обновление и автоподготовка:**
  - При запуске в фоне сверяются сохранённые узлы и прокси: рабочие остаются без переустановки, переставшие отвечать сразу удаляются, новые рабочие догружаются параллельно (включая проверку прокачки ≥ 38 КБ против обрыва соединения на 16 КБ и определение реальной страны выхода).
- **Раздельное туннелирование и обход для банков/сервисов РФ:**
  - Встроенный прямой маршрут для российских банков, СБП/Mir Pay, Госуслуг, маркетплейсов и такси + поштучный выбор любых установленных приложений с иконками («Приложения без VPN»).
- **Живой прогресс с оценкой оставшегося времени (ETA), плитка быстрых настроек (Quick Settings) и подробный сквозной журнал диагностики (`UI` + `:vpn`).**

---

## Архитектура

```text
UwUvpn/
├── rust-engine/                 # Нативный движок velox-engine v1.7.0 (100% Rust, fat LTO, JNI cdylib)
│   ├── src/
│   │   ├── happ_compat.rs       # Офлайн-дешифратор happ://crypt..crypt5, incy://crypt1/, AES-GCM, HWID, deep-link
│   │   ├── net_util.rs          # Анти-спуфинг DoH + TTL-кэш, ETag/304, gzip/deflate, SSRF-guard, SOCKS5 auth
│   │   ├── sources.rs           # Курируемые источники VPN/БС-РФ/TG, парсинг подписок, Xray JSON и метаданных
│   │   ├── xray_config.rs       # Генератор конфигов Xray (Dual-Channel 2×, yt_pool 0% Ads, pcs/pqv/?ed/xhttp)
│   │   ├── vpn_probe.rs         # Потоковый TCP + SOCKS5 пробер (204, GeoIP, sw.js_data YT, 38 КБ, verifyTunnelWeb)
│   │   ├── warp.rs              # Авторегистрация Cloudflare WARP (WireGuard + MASQUE ECDSA P-256)
│   │   ├── opera.rs             # Авторегистрация Opera SurfEasy HTTPS TLS (US / EU)
│   │   ├── tg_checker.rs        # Реальная проверка MTProto Fake-TLS (ee) / dd / SOCKS5 через resPQ к DC2
│   │   ├── tg_bridge.rs         # Локальный отказоустойчивый SOCKS5 + TG-WS WebSocket мост
│   │   ├── store.rs             # Хранилище v7 с flock, строгий фильтр стран, дельта-синк, компактный UI-снапшот
│   │   ├── diag.rs              # Кольцевой кросс-процессный журнал диагностики с авто-маскировкой секретов
│   │   ├── jni_bridge.rs        # Безопасный JNI-мост для Android (panic-guarded, 1-поточный рантайм :vpn)
│   │   └── bin/live_verify.rs   # Интеграционный E2E-стенд проверки на реальном libxray_ffi.so
│   └── Cargo.toml
├── android/                     # Нативное Android-приложение (Kotlin + Jetpack Compose Material 3)
│   └── app/src/main/
│       ├── kotlin/app/velox/vpn/
│       │   ├── core/            # JNI-обёртка, пакетный пробер, модели, кэш иконок, FileLock-настройки
│       │   ├── service/         # VeloxVpnService (:vpn, 2× failover, screen-off), TgBridgeService (:vpn), QS Tile
│       │   └── ui/              # Модульные экраны VPN, 2×-панель, Telegram, подписки/HWID, сплит-туннель, журнал
│       └── assets/
│           └── bootstrap_seed.json
├── patches/                     # Патч к xray-rust v0.10.0 для X.509 v1 REALITY (sing-box / БС-мосты)
├── scripts/build-android.sh     # Воспроизводимая сборка libxray_ffi.so + libvelox_engine.so + release APK
├── ci/github-actions-build.yml  # Готовый шаблон GitHub Actions для автосборки APK
└── LICENSE                      # Mozilla Public License 2.0 (MPL-2.0)
```

---

## Установка готового APK

1. Скачайте последний `VeloxVPN-v1.7.6.apk` в разделе [**Releases**](https://github.com/Yareks/UwUvpn/releases/latest).
2. Установите APK на Android 7.0–16 (`arm64-v8a` или `armeabi-v7a`, полностью совместим с обновлением поверх v1.3.0–v1.5.0).
3. Откройте приложение — рабочие серверы и прокси Telegram подгрузятся автоматически; выберите регион (`🇺🇸 США`, `🇩🇪 Германия`, `⚡ Авто` и др.), режим **`2×` (Основной + резерв)**, включите при необходимости **«Белые списки РФ»** или добавьте свою подписку (`https://`, `happ://crypt*`, `incy://crypt1/`, `v2raytun://` и др.) через кнопку **`+`**.

---

## Сборка из исходников

### Требования
- **JDK 17** (Temurin / OpenJDK)
- **Android SDK** (`platforms;android-35`, `build-tools;35.0.0`, `build-tools;34.0.0`) и **Android NDK `27.2.12479018`** (r27c)
- **Rust** (`rustup`, таргеты `aarch64-linux-android` и `armv7-linux-androideabi`), **`cargo-ndk`**, `cmake`, `ninja`
- **Gradle 8.10+**

### Сборка одной командой

```bash
export ANDROID_HOME=/path/to/android-sdk
export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/27.2.12479018"

# Опционально — подпись собственным релизным ключом (иначе используется debug-подпись):
# export VELOX_KS_FILE=/path/to/release.jks
# export VELOX_KS_PASS="your-store-password"
# export VELOX_KEY_ALIAS="velox"
# export VELOX_KEY_PASS="your-key-password"

chmod +x scripts/build-android.sh
./scripts/build-android.sh
```

Скрипт автоматически скачивает исходники [`aimalygin/xray-rust` v0.10.0](https://github.com/aimalygin/xray-rust), применяет патч `patches/xray-rust-0.10.0-reality-x509v1.patch` (поддержка X.509 v1 сертификатов REALITY с полной проверкой HMAC-SHA512 и RFC 8446 TLS 1.3 `CertificateVerify`), собирает `libxray_ffi.so` и `libvelox_engine.so` с выравниванием `16 КБ` для `arm64-v8a` и `armeabi-v7a`, затем компилирует и минифицирует (R8) релизный APK.

---

## English Summary

**UwUvpn (VeloxVPN v1.7.0)** is an ultra-lightweight, zero-registration, zero-telemetry Android VPN and Telegram proxy client built on a 100% Rust networking stack ([`xray-rust`](https://github.com/aimalygin/xray-rust) v0.10.0 + `velox-engine` v1.7.0) with a native Jetpack Compose Material 3 UI.

- **Dual-Channel `2×` Hot-Standby & Strict Country Lock:** Keeps a verified standby channel (`vpn_1`) ready behind `vpn_0` for zero-drop failover without tearing down `tun0`, promotes/replenishes automatically, and strictly locks primary, standby, and retries to the selected country.
- **Full Offline Happ 4.11+ / Incy Subscription Support:** Decrypts `happ://crypt`..`crypt5`, `incy://crypt1/`, and AES-128-GCM subscription bodies on-device, handles 19 deep-link schemes, supports optional `X-HWID` + wire-order device headers, traffic/expiry/announce/support metadata, and raw Xray JSON imports.
- **Protocols & Ad-Free YouTube Split:** VLESS (REALITY Vision / `pqv` / `encryption` / XHTTP + Vision + `extra` / gRPC / WS `?ed` / HTTPUpgrade), Hysteria2, Trojan, VMess AEAD, Shadowsocks 2022/AEAD, `pcs`/`vcn` cert pinning, 2-hop `MASQUE-Chain` over Cloudflare WARP, WireGuard Noise, Opera HTTPS TLS, TLS ClientHello fragmentation, RF whitelist routing, speed-gated 0%-ad YouTube `yt_pool`, and 52-domain in-tunnel ad blocking.
- **Zero-Idle Battery & Security Hardening:** Screen-off/offline power saving (`90s`/`180s` HTTPS observatory), single-worker `:vpn` runtime, RFC 1929 CSPRNG-authenticated loopback SOCKS5, IPv4/IPv6 SSRF redirect guards, and automatic secret redaction in diagnostic logs.
- **Authentic Telegram Verifier & Local Bridge:** Verifies Fake-TLS (`ee`), MTProto (`dd`), and SOCKS5 proxies against real Telegram DCs (`req_pq_multi` → `resPQ` ≤ 1400 ms) and exposes a local auto-failover `TG-WS` + pool proxy on `127.0.0.1:10809`.

---

## Лицензия / License

Проект распространяется под открытой лицензией **[Mozilla Public License 2.0 (MPL-2.0)](LICENSE)**.  
Использует открытое Rust-ядро [`aimalygin/xray-rust`](https://github.com/aimalygin/xray-rust) (MPL-2.0) и открытую библиотеку совместимости подписок [`loss-and-quick/happ-sub`](https://github.com/loss-and-quick/happ-sub) (MIT OR Apache-2.0).
