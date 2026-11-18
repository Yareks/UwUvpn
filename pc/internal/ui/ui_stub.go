//go:build !windows

package ui

import "fmt"

// ServerRow — строка списка серверов.
type ServerRow struct {
	Name    string
	Country string
	Ms      int
	Active  bool
}

// View — состояние для отрисовки.
type View struct {
	State   string
	Sub     string
	ExitIP  string
	Region  string
	Tun     bool
	Busy    bool
	Servers []ServerRow
	Log     []string
	Step    int
}

// Actions — контракт окна.
type Actions struct {
	OnConnect   func()
	OnRefresh   func()
	OnToggleTun func()
	OnQuit      func()
	OnPick      func(name string)
	OnUiReady   func(w *Window)
	View        func() View
}

// Window — заглушка для не-Windows сборок.
type Window struct{}

func Run(title string, a Actions) error { return fmt.Errorf("GUI только для Windows") }
func (w *Window) SetView(v View)        {}
func (w *Window) SetDetail(text string) {}
func (w *Window) SetTrayTip(text string) {}
