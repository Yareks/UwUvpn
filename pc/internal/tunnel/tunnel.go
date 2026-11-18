// Package tunnel запускает ядро mihomo рядом с приложением и управляет его жизненным циклом.
package tunnel

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Engine — запущенное ядро.
type Engine struct {
	cmd      *exec.Cmd
	confPath string
	logLines *ringLog
	mu       sync.Mutex
	stopped  bool
}

type ringLog struct {
	mu    sync.Mutex
	lines []string
	max   int
}

func newRing(max int) *ringLog { return &ringLog{max: max} }

func (r *ringLog) add(s string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lines = append(r.lines, s)
	if len(r.lines) > r.max {
		r.lines = r.lines[len(r.lines)-r.max:]
	}
}

// Tail возвращает последние строки журнала ядра.
func (r *ringLog) Tail(n int) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if n > len(r.lines) {
		n = len(r.lines)
	}
	out := make([]string, n)
	copy(out, r.lines[len(r.lines)-n:])
	return out
}

// EnginePath возвращает путь к ядру mihomo (рядом с исполняемым файлом).
func EnginePath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	dir := filepath.Dir(exe)
	name := "mihomo"
	if runtime.GOOS == "windows" {
		name = "mihomo.exe"
	}
	p := filepath.Join(dir, name)
	if _, err := os.Stat(p); err != nil {
		return "", fmt.Errorf("ядро не найдено: %s (положите mihomo рядом с приложением)", p)
	}
	return p, nil
}

// Start запускает ядро с готовым YAML-конфигом.
func Start(ctx context.Context, yamlText string) (*Engine, error) {
	engine, err := EnginePath()
	if err != nil {
		return nil, err
	}
	dir, err := os.UserCacheDir()
	if err != nil {
		dir = os.TempDir()
	}
	confDir := filepath.Join(dir, "VeloxVPN")
	if err := os.MkdirAll(confDir, 0o755); err != nil {
		return nil, err
	}
	confPath := filepath.Join(confDir, "config.yaml")
	if err := os.WriteFile(confPath, []byte(yamlText), 0o600); err != nil {
		return nil, err
	}

	cmd := exec.Command(engine, "-d", confDir, "-f", confPath)
	cmd.Env = append(os.Environ(), "SAFE_PATHS="+confDir)
	hideWindow(cmd)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	e := &Engine{cmd: cmd, confPath: confPath, logLines: newRing(400)}
	scan := func(sc *bufio.Scanner) {
		for sc.Scan() {
			e.logLines.add(sc.Text())
		}
	}
	go scan(bufio.NewScanner(stdout))
	go scan(bufio.NewScanner(stderr))

	// ждём, пока ядро займёт порт или упадёт
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if cmd.ProcessState != nil {
			break
		}
		if e.LogContains("start initial configuration") || e.LogContains("Mixed") ||
			e.LogContains("listening") || e.LogContains("TUN") {
			break
		}
		select {
		case <-ctx.Done():
			_ = e.Stop()
			return nil, ctx.Err()
		case <-time.After(120 * time.Millisecond):
		}
	}
	if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
		return nil, fmt.Errorf("ядро завершилось при старте: %s", strings.Join(e.tailOr(6), " | "))
	}
	go func() { _ = cmd.Wait() }()
	return e, nil
}

// LogContains — есть ли подстрока в журнале ядра.
func (e *Engine) LogContains(sub string) bool {
	for _, l := range e.logLines.Tail(200) {
		if strings.Contains(l, sub) {
			return true
		}
	}
	return false
}

// Tail — последние строки журнала.
func (e *Engine) Tail(n int) []string { return e.logLines.Tail(n) }

func (e *Engine) tailOr(n int) []string { return e.logLines.Tail(n) }

// Stop корректно останавливает ядро (важно: TUN-адаптер освобождается).
func (e *Engine) Stop() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.stopped || e.cmd == nil || e.cmd.Process == nil {
		return nil
	}
	e.stopped = true
	_ = e.cmd.Process.Kill()
	_, _ = e.cmd.Process.Wait()
	return nil
}

// ConfPath — путь к активному конфигу (для отладки).
func (e *Engine) ConfPath() string { return e.confPath }
