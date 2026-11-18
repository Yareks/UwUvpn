// VeloxVPN для Windows — единый .exe с нативным окном, треем и ядром mihomo рядом.
//
// Режимы:
//   velox-pc.exe            — обычный запуск: окно + подключение через локальный SOCKS/HTTP
//   velox-pc.exe --tun      — включить TUN (весь трафик компьютера) сразу при старте
//   velox-pc.exe --cli      — без окна: поднять прокси и печатать статус в консоль
//   velox-pc.exe --region=DE --wl   — конкретная страна / «Белые списки РФ»
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"veloxpc/internal/convert"
	"veloxpc/internal/core"
	"veloxpc/internal/sources"
	"veloxpc/internal/tunnel"
	"veloxpc/internal/ui"
)

type app struct {
	mu        sync.Mutex
	cfg       core.Config
	nodes     []core.Node
	engine    *tunnel.Engine
	api       *core.APIClient
	connected bool
	busy      bool
	detail    string
	win       *ui.Window
	tun       bool
}

func main() {
	region := flag.String("region", "AUTO", "страна: AUTO, US, DE, NL, FI, GB, SE, PL, CH, TR, JP или WL (белые списки)")
	wl := flag.Bool("wl", false, "«Белые списки РФ» (только разрешённые домены)")
	tun := flag.Bool("tun", false, "включить TUN-режим (весь трафик компьютера)")
	cli := flag.Bool("cli", false, "без GUI: поднять прокси и печатать статус")
	port := flag.Int("port", 7890, "локальный порт (SOCKS5 + HTTP)")
	limit := flag.Int("limit", 220, "максимум узлов после отбора")
	flag.Parse()

	a := &app{cfg: core.DefaultConfig()}
	a.cfg.Region = strings.ToUpper(*region)
	a.cfg.Whitelist = *wl
	a.cfg.MixedPort = *port
	if *wl {
		a.cfg.Region = "WL"
	}
	a.tun = *tun
	a.cfg.EnableTun = *tun

	// Простой контекст «пока приложение живо» + корректная остановка по Ctrl+C
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigs
		a.shutdown()
		cancel()
		os.Exit(0)
	}()

	if *cli {
		a.runCLI(ctx, *limit)
		return
	}

	a.win = &ui.Window{}
	actions := ui.Actions{
		OnConnect:   a.toggleConnect,
		OnRefresh:   func() { go a.loadAndConnect(ctx, *limit, false) },
		OnToggleTun: a.toggleTun,
		OnQuit:      a.shutdown,
		Status:      a.status,
	}
	if err := ui.Run("VeloxVPN", actions); err != nil {
		fmt.Fprintln(os.Stderr, "GUI недоступен:", err)
		a.runCLI(ctx, *limit)
	}
	a.shutdown()
}

func (a *app) status() (string, string, bool, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	state := "не подключено"
	if a.busy {
		state = "подготовка…"
	} else if a.connected {
		state = "подключено"
	}
	detail := a.detail
	if detail == "" {
		detail = fmt.Sprintf("Регион: %s · порт %d · узлов: %d", a.cfg.Region, a.cfg.MixedPort, len(a.nodes))
	}
	return state, detail, a.connected, a.cfg.EnableTun
}

func (a *app) setDetail(s string) {
	a.mu.Lock()
	a.detail = s
	a.mu.Unlock()
	if a.win != nil {
		a.win.SetDetail(s)
	}
	if a.win != nil {
		a.win.SetTrayTip("VeloxVPN — " + s)
	}
}

func (a *app) toggleTun() {
	a.mu.Lock()
	a.cfg.EnableTun = !a.cfg.EnableTun
	wasConnected := a.connected
	a.mu.Unlock()
	if wasConnected {
		// перезапуск с новым режимом, чтобы TUN применился
		a.stopEngine()
		go a.loadAndConnect(context.Background(), 220, true)
	} else {
		a.setDetail("Режим TUN переключён — он применится при подключении")
	}
}

func (a *app) toggleConnect() {
	a.mu.Lock()
	connected := a.connected
	a.mu.Unlock()
	if connected {
		a.stopEngine()
		a.setDetail("Отключено")
		return
	}
	a.loadAndConnect(context.Background(), 220, true)
}

// loadAndConnect скачивает узлы, собирает конфиг и запускает ядро.
func (a *app) loadAndConnect(ctx context.Context, limit int, connect bool) {
	a.mu.Lock()
	if a.busy {
		a.mu.Unlock()
		return
	}
	a.busy = true
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		a.busy = false
		a.mu.Unlock()
	}()

	a.setDetail("Загружаю списки серверов…")
	proxies, summary, err := sources.FetchAll(ctx, sources.Feeds(), 0)
	if err != nil {
		a.setDetail("Не удалось загрузить серверы: " + err.Error())
		return
	}

	okFeeds, total := 0, 0
	for _, r := range summary {
		if r.Err == "" && r.Count > 0 {
			okFeeds++
			total += r.Count
		}
	}
	a.setDetail(fmt.Sprintf("Источники: %d/%d OK · найдено %d узлов", okFeeds, len(summary), total))

	nodes := pickNodes(proxies, a.cfg, limit)
	if len(nodes) == 0 {
		a.setDetail("В выбранном регионе не нашлось подходящих узлов — попробуйте AUTO")
		return
	}

	a.mu.Lock()
	a.nodes = nodes
	a.mu.Unlock()
	a.setDetail(fmt.Sprintf("Отобрано %d узлов (%s) — запускаю ядро…", len(nodes), regionLabel(a.cfg.Region)))

	yamlText, err := core.BuildConfig(nodes, a.cfg)
	if err != nil {
		a.setDetail("Ошибка конфига: " + err.Error())
		return
	}

	a.stopEngine()
	engine, err := tunnel.Start(ctx, yamlText)
	if err != nil {
		a.setDetail("Ядро не запустилось: " + err.Error())
		return
	}
	a.mu.Lock()
	a.engine = engine
	mode := "SOCKS5/HTTP"
	if a.cfg.EnableTun {
		mode = "TUN (весь компьютер)"
	}
	a.mu.Unlock()

	// v1.0.1: «ядро запустилось» ≠ «трафик идёт». Меряем задержки, выбираем лучший узел
	// и проверяем реальный выход в интернет — как в Android-версии после фикса 1.7.8.
	api := core.NewAPI(core.APIPort, core.Secret())
	a.mu.Lock()
	a.api = api
	a.mu.Unlock()

	ctx2, cancel2 := context.WithTimeout(ctx, 45*time.Second)
	defer cancel2()

	bestName, bestMs := "", 0
	if delays, err := api.DelayGroup(ctx2, "VELOX", "", 5000); err == nil {
		for _, d := range delays {
			// служебные элементы группы пропускаем
			if d.Name == "DIRECT" || d.Name == "AUTO" {
				continue
			}
			bestName, bestMs = d.Name, d.Ms
			break
		}
	}
	if bestName != "" {
		_ = api.SelectNode(ctx2, "VELOX", bestName)
		a.setDetail(fmt.Sprintf("Лучший узел: %s (%d мс) — проверяю трафик…", bestName, bestMs))
	}

	exitIP, verr := core.VerifyTraffic(ctx2, a.cfg.MixedPort, 12*time.Second)
	if verr != nil {
		a.setDetail("Туннель поднят, но трафик не проходит: " + verr.Error())
		a.mu.Lock()
		a.connected = false
		a.mu.Unlock()
		return
	}

	a.mu.Lock()
	a.connected = connect
	a.mu.Unlock()
	a.setDetail(fmt.Sprintf("Подключено · %s (%d мс) · выход %s · %s · порт %d",
		firstNonEmpty(bestName, nodes[0].Name), bestMs, exitIP, mode, a.cfg.MixedPort))
}

// pickNodes фильтрует по региону/белым спискам и ограничивает количество.
func pickNodes(proxies []convert.Proxy, cfg core.Config, limit int) []core.Node {
	seen := map[string]bool{}
	var out []core.Node
	for _, p := range proxies {
		name := fmt.Sprint(p["name"])
		proto := fmt.Sprint(p["type"])
		country := guessCountry(name)

		if cfg.Whitelist && !isWhitelistFriendly(name) {
			continue
		}
		if cfg.Region != "" && cfg.Region != "AUTO" && cfg.Region != "WL" && len(cfg.Region) == 2 {
			if country != cfg.Region {
				continue
			}
		}
		// XHTTP/gRPC/Reality — приоритетные (лучше проходят ТСПУ)
		key := name + "|" + fmt.Sprint(p["server"])
		if seen[key] {
			continue
		}
		seen[key] = true

		out = append(out, core.Node{
			Proxy:    p,
			Name:     name,
			Country:  country,
			Protocol: proto,
		})
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	// стабильный порядок: сначала Reality/XHTTP, затем остальные
	var pref, rest []core.Node
	for _, n := range out {
		if _, ok := n.Proxy["reality-opts"]; ok {
			pref = append(pref, n)
			continue
		}
		if n.Proxy["network"] == "xhttp" {
			pref = append(pref, n)
			continue
		}
		rest = append(rest, n)
	}
	return append(pref, rest...)
}

func isWhitelistFriendly(name string) bool {
	l := strings.ToLower(name)
	for _, kw := range []string{"белые списки", "белый список", "(бс)", "[бс]", "whitelist", "white list", "wl"} {
		if strings.Contains(l, kw) {
			return true
		}
	}
	return false
}

var countryHints = []struct {
	code string
	keys []string
}{
	{"US", []string{"🇺🇸", "сша", "united states", "usa", "america", "ashburn", "new york", "dallas", "seattle", "miami", "virginia", "chicago", "los angeles"}},
	{"DE", []string{"🇩🇪", "герман", "germany", "frankfurt", "fra", "berlin"}},
	{"NL", []string{"🇳🇱", "нидерланд", "netherlands", "amsterdam", "ams", "holland"}},
	{"FI", []string{"🇫🇮", "финлянд", "finland", "helsinki", "hel"}},
	{"GB", []string{"🇬🇧", "великобрита", "britain", "united kingdom", "london", "england"}},
	{"SE", []string{"🇸🇪", "швец", "sweden", "stockholm"}},
	{"PL", []string{"🇵🇱", "польш", "poland", "warsaw"}},
	{"CH", []string{"🇨🇭", "швейцар", "switzerland", "zurich"}},
	{"FR", []string{"🇫🇷", "франц", "france", "paris"}},
	{"TR", []string{"🇹🇷", "турц", "turkey", "istanbul"}},
	{"JP", []string{"🇯🇵", "япон", "japan", "tokyo"}},
	{"SG", []string{"🇸🇬", "сингапур", "singapore"}},
	{"CA", []string{"🇨🇦", "канад", "canada", "toronto"}},
}

func guessCountry(name string) string {
	l := strings.ToLower(name)
	for _, h := range countryHints {
		for _, k := range h.keys {
			if strings.Contains(l, k) {
				return h.code
			}
		}
	}
	return ""
}

func regionLabel(r string) string {
	switch r {
	case "AUTO":
		return "Авто (все страны)"
	case "WL":
		return "Белые списки РФ"
	}
	return r
}

func (a *app) stopEngine() {
	a.mu.Lock()
	e := a.engine
	a.engine = nil
	a.connected = false
	a.mu.Unlock()
	if e != nil {
		_ = e.Stop()
	}
}

func (a *app) shutdown() {
	a.stopEngine()
}

// runCLI — режим без окна: печатает статус раз в секунду (удобно для проверки и скриптов).
func (a *app) runCLI(ctx context.Context, limit int) {
	fmt.Printf("VeloxVPN ПК · регион=%s · белые списки=%v · TUN=%v\n", a.cfg.Region, a.cfg.Whitelist, a.cfg.EnableTun)
	a.loadAndConnect(ctx, limit, true)
	for {
		select {
		case <-ctx.Done():
			a.shutdown()
			return
		case <-time.After(time.Second):
			st, detail, _, _ := a.status()
			fmt.Printf("[%s] %s · %s\n", time.Now().Format("15:04:05"), st, detail)
		}
	}
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}
