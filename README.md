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

- **100% Rust сетевой стек (`xray-rust` 0.10.0 + `velox-engine`)** — нативный туннель с потреблением ~4–8 МБ ОЗУ в простое, отдельным процессом `:vpn`, поддержкой профилей `Mobile` / `MobilePlus` и выравниванием ELF-сегментов `16 КБ` (`arm64-v8a` и `armeabi-v7a`, Android 7.0–16, включая Android 12).
- **Многоэшелонный бесплатный пул без аккаунтов (41 автообновляемый источник):**
  - **Эшелон 1 — Прямые анти-DPI протоколы:** `VLESS + REALITY` (`Vision`, `XHTTP`, `gRPC`, `WS`, `HTTPUpgrade` с нативными uTLS-профилями `chrome`, `firefox`, `safari`, `ios`, `edge`, `qq`), `Hysteria2` (QUIC + Salamander), `Trojan`, `VMess AEAD`, `Shadowsocks 2022` и классический `SS AEAD` + фрагментация TLS ClientHello (`finalmask.tcp`).
  - **Эшелон 2 — Двуххоповый `MASQUE-Chain` (США / Германия / ЕС):** автоматическая маршрутизация зарубежных узлов (`SS2022`, `Trojan`, `VLESS`, `VMess`, `Opera US/EU`) поверх HTTP/3 QUIC и HTTP/2 TCP туннеля Cloudflare WARP MASQUE.
  - **Эшелон 3 — Opera HTTPS TLS & Cloudflare WARP (MASQUE H3/H2 + WireGuard Noise):** автоматический выпуск бесплатных ключей на устройстве без регистрации.
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
├── rust-engine/                 # Нативный движок velox-engine (100% Rust, JNI cdylib)
│   ├── src/
│   │   ├── net_util.rs          # Анти-спуфинг DoH, фрагментация TLS, умный загрузчик подписок и зеркал
│   │   ├── sources.rs           # 41 источник VPN/БС-РФ/TG, парсинг подписок и deep-link ссылок
│   │   ├── xray_config.rs       # Генератор и валидатор конфигураций Xray (1-Hop, 2-Hop MASQUE-Chain, БС РФ)
│   │   ├── vpn_probe.rs         # Потоковый TCP + SOCKS5 пробер (204, GeoIP, анти-16КБ 38 КБ, дельта-сверка)
│   │   ├── warp.rs              # Авторегистрация Cloudflare WARP (WireGuard + MASQUE ECDSA P-256)
│   │   ├── opera.rs             # Авторегистрация Opera SurfEasy HTTPS TLS (US / EU)
│   │   ├── tg_checker.rs        # Реальная проверка MTProto Fake-TLS (ee) / dd / SOCKS5 через resPQ к DC2
│   │   ├── tg_bridge.rs         # Локальный отказоустойчивый SOCKS5 + TG-WS WebSocket мост
│   │   ├── store.rs             # Атомарное хранилище, миграции, дельта-синхронизация и ротация пула
│   │   ├── diag.rs              # Кольцевой кросс-процессный журнал диагностики
│   │   ├── jni_bridge.rs        # Безопасный JNI-мост для Android (panic-guarded)
│   │   └── bin/live_verify.rs   # Интеграционный E2E-стенд проверки на реальном libxray_ffi.so
│   └── Cargo.toml
├── android/                     # Нативное Android-приложение (Kotlin + Jetpack Compose Material 3)
│   └── app/src/main/
│       ├── kotlin/app/velox/vpn/
│       │   ├── core/            # JNI-обёртка, пакетный пробер, модели, кэш иконок, настройки
│       │   ├── service/         # VeloxVpnService (:vpn), TgBridgeService, Quick Settings Tile
│       │   └── ui/              # Главный экран VPN, Telegram-прокси, подписки, сплит-туннель, журнал
│       └── assets/
│           └── bootstrap_seed.json
├── patches/                     # Патч к xray-rust v0.10.0 для X.509 v1 REALITY (sing-box / БС-мосты)
├── scripts/build-android.sh     # Воспроизводимая сборка libxray_ffi.so + libvelox_engine.so + release APK
├── ci/github-actions-build.yml  # Готовый шаблон GitHub Actions для автосборки APK
└── LICENSE                      # Mozilla Public License 2.0 (MPL-2.0)
```

---

## Установка готового APK

1. Скачайте последний `VeloxVPN-v1.3.0.apk` в разделе [**Releases**](https://github.com/Yareks/UwUvpn/releases/latest).
2. Установите APK на Android 7.0–16 (`arm64-v8a` или `armeabi-v7a`).
3. Откройте приложение — рабочие серверы и прокси Telegram подгрузятся автоматически; выберите регион (`🇺🇸 США`, `🇩🇪 Германия`, `⚡ Авто`), включите при необходимости **«Белые списки РФ»** или добавьте свою подписку через кнопку **`+`**.

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

**UwUvpn (VeloxVPN)** is an ultra-lightweight, zero-registration, zero-telemetry Android VPN and Telegram proxy client built on a 100% Rust networking stack ([`xray-rust`](https://github.com/aimalygin/xray-rust) v0.10.0 + `velox-engine`) with a minimal native Jetpack Compose Material 3 UI.

- **Protocols:** VLESS (REALITY Vision / XHTTP / gRPC / WS / HTTPUpgrade with full uTLS profiles), Hysteria2, Trojan, VMess AEAD, Shadowsocks 2022/AEAD, 2-hop `MASQUE-Chain` over Cloudflare WARP (HTTP/3 QUIC & HTTP/2 TCP), WireGuard Noise, Opera HTTPS TLS, TLS ClientHello fragmentation, and mobile whitelist (SNI/CIDR) routing.
- **Smart Incremental Sync:** Keeps verified working VPN nodes and Telegram proxies in place, evicts dead endpoints, and tops up from 41 curated sources + user-imported subscription URLs (`https://`, `happ://`, `v2raytun://`, etc.).
- **Authentic Telegram Verifier & Local Bridge:** Verifies Fake-TLS (`ee`), MTProto (`dd`), and SOCKS5 proxies against real Telegram DCs (`req_pq_multi` → `resPQ` ≤ 1400 ms) and exposes a local auto-failover `TG-WS` + pool proxy on `127.0.0.1:10809`.

---

## Лицензия / License

Проект распространяется под открытой лицензией **[Mozilla Public License 2.0 (MPL-2.0)](LICENSE)**.  
Использует открытое Rust-ядро [`aimalygin/xray-rust`](https://github.com/aimalygin/xray-rust) (MPL-2.0).
