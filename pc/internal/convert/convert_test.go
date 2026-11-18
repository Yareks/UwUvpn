package convert

import (
	"encoding/base64"
	"testing"
)

func base64Std(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// Реальные форматы, которые встречаются в фидах и в подписках пользователя.
func TestParseVLESSRealityXHTTP(t *testing.T) {
	link := "vless://11111111-2222-3333-4444-555555555555@191.217.206.147:6443" +
		"?encryption=none&security=reality&sni=nl.krabvpn.pro&fp=ios&pbk=m0R_t5s8x2A1b3C4d5E6f7G8h9I0j1K2l3M4n5O6p7Q&sid=ab12" +
		"&type=xhttp&mode=packet-up&path=%2Fapi&host=nl.krabvpn.pro#NL%20WL%20XHTTP"
	p, err := ParseLink(link)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p["type"] != "vless" || p["server"] != "191.217.206.147" || p["port"] != 6443 {
		t.Fatalf("bad base fields: %v", p)
	}
	if p["network"] != "xhttp" {
		t.Fatalf("xhttp transport lost: %v", p["network"])
	}
	// КРИТИЧНО: fp=ios должен стать chrome, иначе Xray v26 отвергает конфиг
	if p["client-fingerprint"] != "chrome" {
		t.Fatalf("fingerprint not normalized: %v", p["client-fingerprint"])
	}
	ro, ok := p["reality-opts"].(map[string]any)
	if !ok || ro["public-key"] == "" || ro["short-id"] != "ab12" {
		t.Fatalf("reality opts broken: %v", p["reality-opts"])
	}
	if p["name"] != "NL WL XHTTP" {
		t.Fatalf("name not decoded: %q", p["name"])
	}
}

func TestParseVLESSgRPCReality(t *testing.T) {
	link := "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@162.35.101.177:443" +
		"?security=reality&sni=0592efg.us8.h1clayd.click&fp=edge&pbk=ABCdef1234567890abcdef1234567890abcdef123456&sid=&type=grpc&serviceName=grpcsvc#US%20gRPC"
	p, err := ParseLink(link)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p["network"] != "grpc" {
		t.Fatalf("grpc lost: %v", p)
	}
	if p["client-fingerprint"] != "chrome" {
		t.Fatalf("edge must normalize to chrome: %v", p["client-fingerprint"])
	}
}

func TestParseTrojan(t *testing.T) {
	p, err := ParseLink("trojan://secretpass@example.com:443?sni=example.com&type=ws&path=%2Fws&fp=safari#Trojan%20WS")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p["type"] != "trojan" || p["password"] != "secretpass" || p["tls"] != true {
		t.Fatalf("bad trojan: %v", p)
	}
	if p["client-fingerprint"] != "safari" {
		t.Fatalf("safari must be preserved: %v", p["client-fingerprint"])
	}
}

func TestParseSSLegacy(t *testing.T) {
	// ss://base64(method:password)@host:port#name
	p, err := ParseLink("ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@1.2.3.4:8388#SS%20node")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p["cipher"] != "aes-256-gcm" || p["password"] != "password" || p["server"] != "1.2.3.4" {
		t.Fatalf("bad ss: %v", p)
	}
}

func TestParseSS2022(t *testing.T) {
	p, err := ParseLink("ss://2022-blake3-aes-128-gcm:YWJjZGVmZ2hpamtsbW5vcA==@5.6.7.8:443#SS2022")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p["cipher"] != "2022-blake3-aes-128-gcm" {
		t.Fatalf("bad ss2022 cipher: %v", p["cipher"])
	}
}

func TestParseHysteria2(t *testing.T) {
	p, err := ParseLink("hy2://mypass@9.9.9.9:8443?sni=example.org&insecure=1#HY2")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p["type"] != "hysteria2" || p["password"] != "mypass" || p["skip-cert-verify"] != true {
		t.Fatalf("bad hy2: %v", p)
	}
}

func TestParseVMess(t *testing.T) {
	// {"v":"2","ps":"VM TEST","add":"7.7.7.7","port":"443","id":"uuid-x","aid":"0","net":"ws","path":"/vm","tls":"tls","sni":"vm.example.com","fp":"qq"}
	b64 := "eyJ2IjoiMiIsInBzIjoiVk0gVEVTVCIsImFkZCI6IjcuNy43LjciLCJwb3J0IjoiNDQzIiwiaWQiOiJ1dWlkLXgiLCJhaWQiOiIwIiwibmV0Ijoid3MiLCJwYXRoIjoiL3ZtIiwidGxzIjoidGxzIiwic25pIjoidm0uZXhhbXBsZS5jb20iLCJmcCI6InFcIn0="
	_ = b64
	link := "vmess://" + b64encoded()
	p, err := ParseLink(link)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p["type"] != "vmess" || p["server"] != "7.7.7.7" || p["network"] != "ws" {
		t.Fatalf("bad vmess: %v", p)
	}
	if p["client-fingerprint"] != "chrome" {
		t.Fatalf("qq fingerprint must normalize: %v", p["client-fingerprint"])
	}
}

func TestUnsupported(t *testing.T) {
	if _, err := ParseLink("https://example.com/sub"); err == nil {
		t.Fatal("http link must not parse as node")
	}
	if _, err := ParseLink("vless://broken"); err == nil {
		t.Fatal("broken vless must fail")
	}
}

// b64encoded — валидный base64 JSON для теста VMess.
func b64encoded() string {
	raw := `{"v":"2","ps":"VM TEST","add":"7.7.7.7","port":"443","id":"uuid-x","aid":"0","net":"ws","path":"/vm","tls":"tls","sni":"vm.example.com","fp":"qq"}`
	return base64Std(raw)
}

// Узел Reality без public-key нерабочий — ядро отвергает такой конфиг целиком.
func TestRealityWithoutPubkeyRejected(t *testing.T) {
	link := "vless://uuid@1.2.3.4:443?security=reality&sni=x.com&type=tcp#broken"
	if _, err := ParseLink(link); err == nil {
		t.Fatal("reality without pbk must be rejected")
	}
}
