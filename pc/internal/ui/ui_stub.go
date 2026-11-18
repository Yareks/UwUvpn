//go:build !windows

package ui

import "fmt"

// Actions — тот же контракт для не-Windows сборок (для проверки компиляции).
type Actions struct {
	OnConnect   func()
	OnRefresh   func()
	OnToggleTun func()
	OnQuit      func()
	Status      func() (state string, detail string, connected bool, tun bool)
}

// Window — заглушка.
type Window struct{}

func Run(title string, a Actions) error {
	return fmt.Errorf("GUI доступен только в Windows-сборке")
}

func (w *Window) SetDetail(text string) {}
func (w *Window) SetTrayTip(text string) {}
