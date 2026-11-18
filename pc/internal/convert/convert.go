// Package convert превращает share-ссылки (vless/vmess/trojan/ss/hy2) в YAML-прокси для mihomo.
//
// v1.0 (ПК-версия). Поддерживает Reality, XHTTP, gRPC, WS, H2, TCP;
// отпечатки TLS всегда переводятся в безопасные для Xray v26+ (chrome/firefox/safari/random).
package convert

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// Proxy — один узел в формате mihomo (карта для YAML).
type Proxy map[string]any

// tlsSafeFingerprint — та же логика, что в Android: ядро Xray v26+ требует
// X25519MLKEM768 в ClientHello, а подписи ios/edge/qq её не содержат.
func tlsSafeFingerprint(fp string) string {
	switch strings.ToLower(strings.TrimSpace(fp)) {
	case "firefox":
		return "firefox"
	case "safari":
		return "safari"
	case "random", "randomized":
		return "random"
	case "chrome", "":
		return "chrome"
	default:
		return "chrome"
	}
}

func safeName(name string) string {
	n := strings.TrimSpace(strings.ReplaceAll(name, "\n", " "))
	if n == "" {
		return "node"
	}
	// mihomo не любит спецсимволы в именах прокси — оставляем печатные
	n = strings.ReplaceAll(n, "\"", "'")
	return n
}

// ParseLink возвращает прокси mihomo или ошибку, если ссылка не поддерживается.
func ParseLink(link string) (Proxy, error) {
	l := strings.TrimSpace(link)
	switch {
	case strings.HasPrefix(l, "vless://"):
		return parseVLESS(l)
	case strings.HasPrefix(l, "vmess://"):
		return parseVMess(l)
	case strings.HasPrefix(l, "trojan://"):
		return parseTrojan(l)
	case strings.HasPrefix(l, "ss://"):
		return parseSS(l)
	case strings.HasPrefix(l, "hy2://"), strings.HasPrefix(l, "hysteria2://"):
		return parseHysteria2(l)
	}
	return nil, fmt.Errorf("unsupported scheme")
}

func splitName(u *url.URL, fallback string) (string, string) {
	name := u.Fragment
	if name == "" {
		name = fallback
	}
	decoded, err := url.QueryUnescape(name)
	if err == nil && decoded != "" {
		name = decoded
	}
	return safeName(name), u.Hostname()
}

// applyTransport переносит network/ws/grpc/xhttp-параметры в прокси mihomo.
func applyTransport(p Proxy, q url.Values) {
	network := strings.ToLower(q.Get("type"))
	if network == "" {
		network = strings.ToLower(q.Get("network"))
	}

	// XHTTP: mihomo поддерживает с 2.11.28 (network: xhttp + xhttp-opts)
	switch network {
	case "ws", "websocket":
		p["network"] = "ws"
		opts := map[string]any{}
		if path := q.Get("path"); path != "" {
			opts["path"] = path
		}
		if host := q.Get("host"); host != "" {
			opts["headers"] = map[string]any{"Host": host}
		}
		if len(opts) > 0 {
			p["ws-opts"] = opts
		}
	case "grpc":
		p["network"] = "grpc"
		opts := map[string]any{}
		if sn := q.Get("serviceName"); sn != "" {
			opts["grpc-service-name"] = sn
		}
		if len(opts) > 0 {
			p["grpc-opts"] = opts
		}
	case "h2", "http":
		p["network"] = "h2"
		opts := map[string]any{}
		if path := q.Get("path"); path != "" {
			opts["path"] = path
		}
		if host := q.Get("host"); host != "" {
			opts["host"] = []string{host}
		}
		if len(opts) > 0 {
			p["h2-opts"] = opts
		}
	case "xhttp", "splithttp":
		p["network"] = "xhttp"
		opts := map[string]any{}
		if path := q.Get("path"); path != "" {
			opts["path"] = path
		}
		if host := q.Get("host"); host != "" {
			opts["host"] = host
		}
		mode := q.Get("mode")
		if mode == "" {
			mode = "auto"
		}
		opts["mode"] = mode
		p["xhttp-opts"] = opts
	}

	// uTLS-отпечаток: mihomo называет его client-fingerprint
	if fp := q.Get("fp"); fp != "" {
		p["client-fingerprint"] = tlsSafeFingerprint(fp)
	} else if q.Get("security") == "reality" || strings.EqualFold(q.Get("security"), "tls") {
		p["client-fingerprint"] = "chrome"
	}
}

func parseVLESS(raw string) (Proxy, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User == nil {
		return nil, fmt.Errorf("bad vless url")
	}
	q := u.Query()
	name, host := splitName(u, "vless")
	port, err := strconv.Atoi(u.Port())
	if err != nil || port <= 0 {
		return nil, fmt.Errorf("bad port")
	}

	p := Proxy{
		"name":   name,
		"type":   "vless",
		"server": host,
		"port":   port,
		"uuid":   u.User.Username(),
		"udp":    true,
	}
	if flow := q.Get("flow"); flow != "" {
		p["flow"] = flow
	}

	security := strings.ToLower(q.Get("security"))
	if security == "reality" {
		// v1.0.1: ядро отвергает конфиг, если у reality-opts не задан public-key
		// («reality-opts has unset fields: public-key»). Такой узел всё равно нерабочий.
		pbk := strings.TrimSpace(q.Get("pbk"))
		if pbk == "" {
			return nil, fmt.Errorf("reality без public-key")
		}
		p["tls"] = true
		ro := map[string]any{"public-key": pbk}
		if sid := q.Get("sid"); sid != "" {
			ro["short-id"] = sid
		}
		p["reality-opts"] = ro
		if sni := q.Get("sni"); sni != "" {
			p["servername"] = sni
		}
	} else if security == "tls" {
		p["tls"] = true
		if sni := q.Get("sni"); sni != "" {
			p["servername"] = sni
		}
		if alpn := q.Get("alpn"); alpn != "" {
			p["alpn"] = strings.Split(alpn, ",")
		}
	} else if sni := q.Get("sni"); sni != "" {
		// некоторые панели отдают sni без security=tls — не теряем его
		p["tls"] = true
		p["servername"] = sni
	}

	applyTransport(p, q)
	return p, nil
}

func parseVMess(raw string) (Proxy, error) {
	b64 := strings.TrimPrefix(raw, "vmess://")
	if i := strings.IndexByte(b64, '#'); i >= 0 {
		b64 = b64[:i]
	}
	body := b64
	if d, err := base64.StdEncoding.DecodeString(padBase64(b64)); err == nil {
		body = string(d)
	} else if d, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(b64, "=")); err == nil {
		body = string(d)
	} else {
		return nil, fmt.Errorf("bad vmess base64")
	}

	var v struct {
		PS   string `json:"ps"`
		Add  string `json:"add"`
		Port any    `json:"port"`
		ID   string `json:"id"`
		Aid  any    `json:"aid"`
		Scy  string `json:"scy"`
		Net  string `json:"net"`
		Host string `json:"host"`
		Path string `json:"path"`
		TLS  string `json:"tls"`
		SNI  string `json:"sni"`
		FP   string `json:"fp"`
		Alpn string `json:"alpn"`
	}
	if err := json.Unmarshal([]byte(body), &v); err != nil || v.Add == "" || v.ID == "" {
		return nil, fmt.Errorf("bad vmess json")
	}

	p := Proxy{
		"name":   safeName(v.PS),
		"type":   "vmess",
		"server": v.Add,
		"port":   toInt(v.Port),
		"uuid":   v.ID,
		"alterId": toInt(v.Aid),
		"cipher": "auto",
		"udp":    true,
	}
	if v.Scy != "" && v.Scy != "auto" {
		p["cipher"] = v.Scy
	}
	if strings.EqualFold(v.TLS, "tls") || strings.EqualFold(v.TLS, "reality") {
		p["tls"] = true
		sni := v.SNI
		if sni == "" {
			sni = v.Host
		}
		if sni != "" {
			p["servername"] = sni
		}
		p["client-fingerprint"] = tlsSafeFingerprint(v.FP)
	}
	q := url.Values{}
	q.Set("type", v.Net)
	q.Set("host", v.Host)
	q.Set("path", v.Path)
	applyTransport(p, q)
	return p, nil
}

func parseTrojan(raw string) (Proxy, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User == nil {
		return nil, fmt.Errorf("bad trojan url")
	}
	q := u.Query()
	name, host := splitName(u, "trojan")
	p := Proxy{
		"name":     name,
		"type":     "trojan",
		"server":   host,
		"port":     toInt(u.Port()),
		"password": u.User.Username(),
		"udp":      true,
	}
	if sni := q.Get("sni"); sni != "" {
		p["servername"] = sni
	}
	p["tls"] = true
	if fp := q.Get("fp"); fp != "" {
		p["client-fingerprint"] = tlsSafeFingerprint(fp)
	}
	applyTransport(p, q)
	return p, nil
}

func parseSS(raw string) (Proxy, error) {
	// ss://base64(method:pass)@host:port#name  |  ss://base64(method:pass@host:port)#name
	body := strings.TrimPrefix(raw, "ss://")
	name := ""
	if i := strings.IndexByte(body, '#'); i >= 0 {
		if n, err := url.QueryUnescape(body[i+1:]); err == nil {
			name = n
		} else {
			name = body[i+1:]
		}
		body = body[:i]
	}
	if i := strings.IndexByte(body, '?'); i >= 0 {
		body = body[:i]
	}

	var method, pass, hostport string
	if at := strings.LastIndexByte(body, '@'); at >= 0 {
		credPart := body[:at]
		hostport = body[at+1:]
		if d, err := base64.StdEncoding.DecodeString(padBase64(credPart)); err == nil {
			credPart = string(d)
		} else if d, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(credPart, "=")); err == nil {
			credPart = string(d)
		}
		parts := strings.SplitN(credPart, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("bad ss credentials")
		}
		method, pass = parts[0], parts[1]
	} else {
		if d, err := base64.StdEncoding.DecodeString(padBase64(body)); err == nil {
			body = string(d)
		}
		parts := strings.SplitN(body, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("bad ss url")
		}
		method = parts[0]
		rest := parts[1]
		i := strings.LastIndexByte(rest, '@')
		if i < 0 {
			return nil, fmt.Errorf("bad ss host")
		}
		pass = rest[:i]
		hostport = rest[i+1:]
	}

	h, portStr, err := splitHostPort(hostport)
	if err != nil {
		return nil, err
	}
	if name == "" {
		name = "ss " + h
	}
	return Proxy{
		"name":     safeName(name),
		"type":     "ss",
		"server":   h,
		"port":     toInt(portStr),
		"cipher":   method,
		"password": pass,
		"udp":      true,
	}, nil
}

func parseHysteria2(raw string) (Proxy, error) {
	u, err := url.Parse(strings.Replace(raw, "hy2://", "hysteria2://", 1))
	if err != nil || u.Host == "" || u.User == nil {
		return nil, fmt.Errorf("bad hy2 url")
	}
	q := u.Query()
	name, host := splitName(u, "hy2")
	p := Proxy{
		"name":     name,
		"type":     "hysteria2",
		"server":   host,
		"port":     toInt(u.Port()),
		"password": u.User.Username(),
	}
	if sni := q.Get("sni"); sni != "" {
		p["sni"] = sni
	}
	if sn := q.Get("insecure"); sn == "1" || sn == "true" {
		p["skip-cert-verify"] = true
	}
	return p, nil
}

// ------------------------------------------------------------------ helpers

func padBase64(s string) string {
	s = strings.TrimSpace(s)
	if m := len(s) % 4; m != 0 {
		s += strings.Repeat("=", 4-m)
	}
	return s
}

func toInt(v any) int {
	switch t := v.(type) {
	case int:
		return t
	case float64:
		return int(t)
	case string:
		n, _ := strconv.Atoi(strings.TrimSpace(t))
		return n
	case json.Number:
		n, _ := t.Int64()
		return int(n)
	}
	return 0
}

func splitHostPort(hp string) (string, string, error) {
	i := strings.LastIndexByte(hp, ':')
	if i <= 0 {
		return "", "", fmt.Errorf("bad host:port")
	}
	return hp[:i], hp[i+1:], nil
}
