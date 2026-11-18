// Package sources загружает публичные фиды и превращает их в узлы.
package sources

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"veloxpc/internal/convert"
)

// Feed — источник конфигов.
type Feed struct {
	Name    string
	URL     string
	Country string // подсказка страны, "" = определять по имени
}

// Feeds — те же 25 фидов, что использует Android-версия (проверены в бою).
func Feeds() []Feed {
	return []Feed{
		{"БС РФ · Моб. ТОП-150", "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/Vless-Reality-White-Lists-Rus-Mobile.txt", "WL"},
		{"РФ Моб. · VLESS Reality 150", "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS_mobile.txt", "RU"},
		{"0xRadikal · Germany", "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/Countries/Germany.txt", "DE"},
		{"Argh94 · Germany", "https://raw.githubusercontent.com/Argh94/V2RayAutoConfig/main/configs/Germany.txt", "DE"},
		{"MatinGhanbari · VLESS", "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/vless.txt", ""},
		{"MatinGhanbari · Hysteria2", "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/hysteria2.txt", ""},
		{"0xRadikal · United States", "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/Countries/United_States.txt", "US"},
		{"SoliSpirit · United States", "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Countries/United_States.txt", "US"},
		{"Argh94 · USA", "https://raw.githubusercontent.com/Argh94/V2RayAutoConfig/main/configs/USA.txt", "US"},
		{"Argh94 · Netherlands", "https://raw.githubusercontent.com/Argh94/V2RayAutoConfig/main/configs/Netherlands.txt", "NL"},
		{"Argh94 · Finland", "https://raw.githubusercontent.com/Argh94/V2RayAutoConfig/main/configs/Finland.txt", "FI"},
		{"Argh94 · UK", "https://raw.githubusercontent.com/Argh94/V2RayAutoConfig/main/configs/UK.txt", "GB"},
		{"Argh94 · Sweden", "https://raw.githubusercontent.com/Argh94/V2RayAutoConfig/main/configs/Sweden.txt", "SE"},
		{"Argh94 · Switzerland", "https://raw.githubusercontent.com/Argh94/V2RayAutoConfig/main/configs/Switzerland.txt", "CH"},
		{"0xRadikal · Top-100", "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/protocols/shadowsocks.txt", ""},
		{"SoliSpirit · SS", "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Protocols/ss.txt", ""},
		{"Barry-Far · SS", "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Splitted-By-Protocol/ss.txt", ""},
		{"0xRadikal · Trojan", "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/protocols/trojan.txt", ""},
		{"Barry-Far · Trojan", "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Splitted-By-Protocol/trojan.txt", ""},
		{"Barry-Far · VMess", "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Splitted-By-Protocol/vmess.txt", ""},
		{"Barry-Far · VLESS", "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Splitted-By-Protocol/vless.txt", ""},
		{"roosterkid · V2RAY", "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt", ""},
		{"Kwinshadow · VLESS", "https://raw.githubusercontent.com/Kwinshadow/TelegramV2rayCollector/main/sublinks/vless.txt", ""},
		{"Danialsamadi · vless", "https://raw.githubusercontent.com/Danialsamadi/v2go/main/Splitted-By-Protocol/vless.txt", ""},
		{"peasoft · NoMoreWalls", "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list_raw.txt", ""},
	}
}

// Result — итог загрузки одного фида.
type Result struct {
	Feed   string
	Count  int
	Err    string
	Millis int64
}

var client = &http.Client{Timeout: 12 * time.Second}

// FetchAll параллельно скачивает фиды и возвращает уникальные узлы.
func FetchAll(ctx context.Context, feeds []Feed, limit int) ([]convert.Proxy, []Result, error) {
	type job struct {
		f   Feed
		out []convert.Proxy
		res Result
	}
	results := make([]job, len(feeds))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 14) // не душим сеть

	for i, f := range feeds {
		wg.Add(1)
		go func(i int, f Feed) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			t0 := time.Now()
			proxies, err := fetchOne(ctx, f)
			results[i] = job{
				f:   f,
				out: proxies,
				res: Result{
					Feed:   f.Name,
					Count:  len(proxies),
					Millis: time.Since(t0).Milliseconds(),
					Err:    errString(err),
				},
			}
		}(i, f)
	}
	wg.Wait()

	seen := map[string]bool{}
	var all []convert.Proxy
	var summary []Result
	for _, r := range results {
		summary = append(summary, r.res)
		for _, p := range r.out {
			key := fmt.Sprintf("%v|%v|%v", p["type"], p["server"], p["port"])
			if seen[key] {
				continue
			}
			seen[key] = true
			all = append(all, p)
			if limit > 0 && len(all) >= limit {
				break
			}
		}
	}
	if len(all) == 0 {
		return nil, summary, fmt.Errorf("ни один источник не вернул узлов")
	}
	return all, summary, nil
}

func fetchOne(ctx context.Context, f Feed) ([]convert.Proxy, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "VeloxPC/1.0 (mihomo)")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("http %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 12<<20))
	if err != nil {
		return nil, err
	}
	return ParseBody(string(body)), nil
}

var uriLine = regexp.MustCompile(`(?i)(vless|vmess|trojan|ss|hy2|hysteria2)://[^\s"'<>]+`)

// ParseBody вытаскивает все share-ссылки из текста фида.
func ParseBody(text string) []convert.Proxy {
	text = maybeBase64Decode(text)
	var out []convert.Proxy
	for _, m := range uriLine.FindAllString(text, -1) {
		link := strings.TrimSpace(strings.TrimRight(m, "\\"))
		if isDummy(link) {
			continue
		}
		if p, err := convert.ParseLink(link); err == nil {
			out = append(out, p)
		}
	}
	return out
}

// maybeBase64Decode — многие подписки отдаются целиком в base64.
func maybeBase64Decode(s string) string {
	trimmed := strings.TrimSpace(s)
	if strings.Contains(trimmed, "://") {
		return s
	}
	clean := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, trimmed)
	if d, err := base64.StdEncoding.DecodeString(pad(clean)); err == nil {
		return string(d)
	}
	if d, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(clean, "=")); err == nil {
		return string(d)
	}
	return s
}

func pad(s string) string {
	if m := len(s) % 4; m != 0 {
		return s + strings.Repeat("=", 4-m)
	}
	return s
}

func isDummy(link string) bool {
	l := strings.ToLower(link)
	return strings.Contains(l, "00000000-0000-0000-0000-000000000000") ||
		strings.Contains(l, "@app.deprecated") ||
		strings.Contains(l, "@127.0.0.1") ||
		strings.Contains(l, "@0.0.0.0") ||
		strings.Contains(l, "@localhost")
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
