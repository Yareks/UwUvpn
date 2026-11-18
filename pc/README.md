# VeloxVPN для Windows

Отдельное приложение для ПК на том же семействе ядер, что Android-версия.

## Сборка

```bash
# 1) приложение (нужен Go 1.22+)
cd pc
GOOS=windows GOARCH=amd64 go build -trimpath \
  -ldflags "-s -w -H windowsgui" -o VeloxVPN.exe ./cmd/velox-pc

# 2) ядро (mihomo)
git clone --depth 1 --branch v1.19.34 https://github.com/MetaCubeX/mihomo.git
cd mihomo
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -tags with_gvisor -trimpath \
  -ldflags "-s -w" -o ../mihomo.exe .
```

`VeloxVPN.exe` и `mihomo.exe` должны лежать в одной папке.

## Структура

| Путь | Назначение |
|---|---|
| `cmd/velox-pc/main.go` | точка входа, режимы GUI/CLI, подбор узлов |
| `internal/convert` | разбор share-ссылок (vless/vmess/trojan/ss/hy2) → YAML mihomo |
| `internal/core` | сборка конфига (TUN, DNS, правила), клиент API ядра |
| `internal/sources` | 25 фидов, base64-подписки, дедупликация |
| `internal/tunnel` | запуск/остановка ядра, журнал |
| `internal/ui` | нативное окно Win32 + трей (без внешних зависимостей) |

## Тесты

```bash
cd pc && go test ./...
```

Покрыто: Reality (с ключом и без), XHTTP, gRPC, WS, Trojan, Shadowsocks AEAD/2022,
Hysteria2, VMess, нормализация TLS-отпечатков под Xray v26.

## Что проверено вживую

- валидатор ядра принимает собранный конфиг (`is successful`);
- 25/25 источников, 28 022 узла, 63/63 узла живы в замере задержек;
- реальный туннель: смена внешнего IP + HTTP 204, скорость до 9,5 МБ/с.
