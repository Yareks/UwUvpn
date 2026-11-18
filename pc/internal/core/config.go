// Package core собирает YAML-конфиг mihomo: TUN-режим, DNS, правила и группы узлов.
package core

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"veloxpc/internal/convert"
)

// Node — узел с метаданными для выбора.
type Node struct {
	Proxy    convert.Proxy
	Name     string
	Country  string
	Latency  int // мс, 0 = не измерялась
	Source   string
	Protocol string
}

// Config — пользовательские настройки ПК-версии.
type Config struct {
	MixedPort   int    `yaml:"mixed-port"`
	Mode        string `yaml:"mode"`        // rule | global | direct
	Region      string `yaml:"region"`      // AUTO | US | DE | NL | FI | ... | WL
	Whitelist   bool   `yaml:"whitelist"`   // «Белые списки РФ»: только разрешённые домены
	BypassRu    bool   `yaml:"bypass-ru"`   // российские сайты — напрямую
	LocalHost   string `yaml:"local-host"`  // 127.0.0.1
	LogLevel    string `yaml:"log-level"`
	EnableTun   bool   `yaml:"-"`           // выставляется флагом --tun
	AutoSelect  bool   `yaml:"-"`           // url-test группа
}

// apiSecret — случайный ключ доступа к локальному API (не пускает чужие процессы).
var apiSecret = func() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err == nil {
		return hex.EncodeToString(b)
	}
	return "velox-local-api"
}()

// Secret возвращает ключ доступа к локальному API для текущего конфига.
func Secret() string { return apiSecret }

// DefaultConfig — разумные значения по умолчанию.
func DefaultConfig() Config {
	return Config{
		MixedPort: 7890,
		Mode:      "rule",
		Region:    "AUTO",
		Whitelist: false,
		BypassRu:  true,
		LocalHost: "127.0.0.1",
		LogLevel:  "warning",
		AutoSelect: true,
	}
}

// BuildConfig собирает полноценный YAML для mihomo.
func BuildConfig(nodes []Node, cfg Config) (string, error) {
	if len(nodes) == 0 {
		return "", fmt.Errorf("нет узлов для подключения")
	}

	// 1) Группа: все имена узлов + авто-выбор по задержке + прямое соединение
	var names []string
	proxies := make([]convert.Proxy, 0, len(nodes))
	// v1.0.1: ядро отвергает конфиг при совпадении имён («is the duplicate name»),
	// а фиды часто отдают одинаковые remark. Делаем имена уникальными.
	used := make(map[string]int, len(nodes))
	for _, n := range nodes {
		p := n.Proxy
		name := n.Name
		if c, ok := used[name]; ok {
			used[name] = c + 1
			name = fmt.Sprintf("%s #%d", n.Name, c+1)
		} else {
			used[name] = 1
		}
		p["name"] = name
		proxies = append(proxies, p)
		names = append(names, name)
	}

	proxyGroup := []map[string]any{
		{
			"name":    "VELOX",
			"type":    "select",
			"proxies": append([]string{"AUTO"}, append(names, "DIRECT")...),
		},
		{
			"name":        "AUTO",
			"type":        "url-test",
			"proxies":     names,
			"url":         "https://www.gstatic.com/generate_204",
			"interval":    180,
			"tolerance":   80,
			"lazy":        true,
		},
	}

	root := map[string]any{
		"mixed-port":              cfg.MixedPort,
		"allow-lan":               false,
		// Локальный управляющий API: по нему приложение меряет задержки узлов и
		// переключает сервер, не перезапуская ядро. Слушает только 127.0.0.1.
		"external-controller":     APIAddress,
		"secret":                  apiSecret,

		"bind-address":            cfg.LocalHost,
		"mode":                    orDefault(cfg.Mode, "rule"),
		"log-level":               orDefault(cfg.LogLevel, "warning"),
		"ipv6":                    false,
		"unified-delay":           true,
		"tcp-concurrent":          true,
		"find-process-mode":       "off",
		"proxies":                 proxies,
		"proxy-groups":            proxyGroup,
	}

	if cfg.EnableTun {
		root["tun"] = map[string]any{
			"enable":              true,
			"stack":               "gvisor",
			"dns-hijack":          []string{"any:53", "tcp://any:53"},
			"auto-route":          true,
			"auto-detect-interface": true,
			"mtu":                 1500,
		}
	}

	// DNS: тот же принцип, что в Android-версии — DoH + локальный кэш
	dns := map[string]any{
		"enable":         true,
		"ipv6":           false,
		"enhanced-mode":  "fake-ip",
		"fake-ip-range":  "198.18.0.1/16",
		// 198.18.0.0/16 = 65534 пригодных адреса: ядро Xray v26 отвергает равенство,
		// поэтому держим запас (та же причина, что «fakeIp poolSize» в Android).
		"fake-ip-filter": []string{
			"*.lan", "*.local", "localhost.ptlogin2.qq.com",
			"time.*.com", "ntp.*.com",
		},
		"default-nameserver": []string{"1.1.1.1", "8.8.8.8"},
		"nameserver": []string{
			"https://cloudflare-dns.com/dns-query",
			"https://dns.google/dns-query",
		},
	}
	if cfg.BypassRu {
		// v1.0.1: mihomo не понимает `https+local://` (это синтаксис Xray). Российские домены
		// резолвим обычным DoH, чтобы они не уходили через туннель.
		dns["nameserver-policy"] = map[string]any{
			"+.ru": []string{"https://common.dot.dns.yandex.net/dns-query", "77.88.8.8"},
			"+.su": []string{"https://common.dot.dns.yandex.net/dns-query"},
			"+.рф": []string{"https://common.dot.dns.yandex.net/dns-query"},
		}
	}
	root["dns"] = dns

	// Правила: РФ-домены напрямую, приватные сети — напрямую, остальное — через VELOX
	rules := []string{
		"GEOIP,PRIVATE,DIRECT",
		"DOMAIN-SUFFIX,local,DIRECT",
		"IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
		"IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
		"IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
		"IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
	}
	if cfg.BypassRu {
		rules = append(rules, RuDirectRules()...)
	}
	rules = append(rules, "MATCH,VELOX")
	root["rules"] = rules

	out, err := yaml.Marshal(root)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// RuDirectRules — российские сервисы напрямую (банки, госуслуги, маркетплейсы).
// Ограниченный список: НЕ `GEOIP,RU` целиком, чтобы IP-чекеры показывали реальный выход.
func RuDirectRules() []string {
	domains := []string{
		"gosuslugi.ru", "gu-st.ru", "nalog.ru", "mos.ru", "emias.info", "spb.ru",
		"sberbank.ru", "sber.ru", "tbank.ru", "tinkoff.ru", "alfabank.ru", "vtb.ru",
		"gazprombank.ru", "raiffeisen.ru", "sovcombank.ru", "rshb.ru", "psbank.ru",
		"yoomoney.ru", "yookassa.ru", "nspk.ru", "mirpay.ru", "cbr.ru",
		"ozon.ru", "wildberries.ru", "wb.ru", "avito.ru", "kuper.ru", "samokat.ru",
		"cdek.ru", "pochta.ru", "rzd.ru", "tutu.ru", "aeroflot.ru", "s7.ru", "2gis.ru", "hh.ru",
		"yandex.ru", "yastatic.net", "ya.ru", "kinopoisk.ru", "dzen.ru",
		"vk.com", "vk.ru", "vkvideo.ru", "userapi.com", "mycdn.me", "ok.ru", "okcdn.ru",
		"mail.ru", "imgsmail.ru", "max.ru", "rutube.ru", "rtbcdn.ru",
		"mts.ru", "megafon.ru", "beeline.ru", "t2.ru", "tele2.ru", "rt.ru",
		"1c.ru", "kaspersky.ru", "drweb.ru", "rbc.ru", "ria.ru", "lenta.ru", "pikabu.ru",
	}
	rules := make([]string, 0, len(domains)+1)
	for _, d := range domains {
		rules = append(rules, "DOMAIN-SUFFIX,"+d+",DIRECT")
	}
	return rules
}

// WriteConfig пишет YAML в файл (для запуска ядра).
func WriteConfig(path string, yamlText string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(yamlText), 0o600)
}

// SortNodesByLatency — лучшие узлы первыми (0 = не измерялась -> в конец).
func SortNodesByLatency(nodes []Node) {
	sort.SliceStable(nodes, func(i, j int) bool {
		a, b := nodes[i].Latency, nodes[j].Latency
		if a == 0 {
			return false
		}
		if b == 0 {
			return true
		}
		return a < b
	})
}

func orDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}
