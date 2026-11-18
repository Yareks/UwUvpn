// Package core: клиент локального API ядра mihomo.
// Через него приложение меряет задержки узлов, выбирает лучший и проверяет,
// что трафик реально проходит (а не только «ядро запустилось»).
package core

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"time"
)

// APIClient — обёртка над REST API mihomo (только 127.0.0.1).
type APIClient struct {
	Base   string
	Secret string
	http   *http.Client
}

// NewAPI создаёт клиент к локальному API.
func NewAPI(port int, secret string) *APIClient {
	return &APIClient{
		Base:   fmt.Sprintf("http://127.0.0.1:%d", port),
		Secret: secret,
		http:   &http.Client{Timeout: 12 * time.Second},
	}
}

// APIPort — порт управляющего API (тот же, что в конфиге).
const APIPort = 9090

// APIAddress — адрес API, который приложение записывает в конфиг.
const APIAddress = "127.0.0.1:9090"

func (c *APIClient) do(ctx context.Context, method, path string, body any) ([]byte, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.Base+path, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Secret)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("api %d: %s", resp.StatusCode, string(data))
	}
	return data, nil
}

// DelayGroup измеряет задержки всех узлов группы и возвращает отсортированный список.
func (c *APIClient) DelayGroup(ctx context.Context, group, testURL string, timeoutMs int) ([]Delay, error) {
	if testURL == "" {
		testURL = "https://www.gstatic.com/generate_204"
	}
	path := fmt.Sprintf("/group/%s/delay?url=%s&timeout=%d",
		url.PathEscape(group), url.QueryEscape(testURL), timeoutMs)
	raw, err := c.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	out := make([]Delay, 0, len(m))
	for name, v := range m {
		n, ok := v.(float64)
		if !ok || n <= 0 {
			continue
		}
		out = append(out, Delay{Name: name, Ms: int(n)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Ms < out[j].Ms })
	return out, nil
}

// Delay — задержка узла.
type Delay struct {
	Name string
	Ms   int
}

// SelectNode переключает группу на конкретный узел.
func (c *APIClient) SelectNode(ctx context.Context, group, node string) error {
	_, err := c.do(ctx, http.MethodPut, "/proxies/"+url.PathEscape(group),
		map[string]string{"name": node})
	return err
}

// CurrentNode возвращает активный узел группы.
func (c *APIClient) CurrentNode(ctx context.Context, group string) (string, error) {
	raw, err := c.do(ctx, http.MethodGet, "/proxies/"+url.PathEscape(group), nil)
	if err != nil {
		return "", err
	}
	var m struct {
		Now string `json:"now"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return "", err
	}
	return m.Now, nil
}

// Relay — тестовый SOCKS-запрос через локальный порт (проверка реального трафика).
type Relay struct {
	Port int
}

// VerifyTraffic проверяет, что через туннель реально идут данные.
// Возвращает внешний IP (если удалось узнать) и ошибку.
func VerifyTraffic(ctx context.Context, proxyPort int, timeout time.Duration) (string, error) {
	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", proxyPort))
	tr := &http.Transport{
		Proxy:               http.ProxyURL(proxyURL),
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: timeout,
	}
	cl := &http.Client{Transport: tr, Timeout: timeout}
	defer tr.CloseIdleConnections()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.ipify.org", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "VeloxPC/1.0")
	resp, err := cl.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("http %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64))
	if err != nil {
		return "", err
	}
	ip := string(bytes.TrimSpace(b))
	if ip == "" {
		return "", fmt.Errorf("пустой ответ")
	}
	return ip, nil
}
