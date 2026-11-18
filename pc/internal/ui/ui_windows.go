//go:build windows

// Package ui — нативное окно Windows (Win32 через syscall). Без внешних зависимостей:
// один .exe, никаких установщиков и WebView.
package ui

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

var (
	user32   = syscall.NewLazyDLL("user32.dll")
	gdi32    = syscall.NewLazyDLL("gdi32.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	shell32  = syscall.NewLazyDLL("shell32.dll")

	pRegisterClassExW = user32.NewProc("RegisterClassExW")
	pCreateWindowExW  = user32.NewProc("CreateWindowExW")
	pDefWindowProcW   = user32.NewProc("DefWindowProcW")
	pGetMessageW      = user32.NewProc("GetMessageW")
	pDispatchMessageW = user32.NewProc("DispatchMessageW")
	pTranslateMessage = user32.NewProc("TranslateMessage")
	pPostQuitMessage  = user32.NewProc("PostQuitMessage")
	pDestroyWindow    = user32.NewProc("DestroyWindow")
	pShowWindow       = user32.NewProc("ShowWindow")
	pUpdateWindow     = user32.NewProc("UpdateWindow")
	pSendMessageW     = user32.NewProc("SendMessageW")
	pSetWindowTextW   = user32.NewProc("SetWindowTextW")
	pCreateSolidBrush = gdi32.NewProc("CreateSolidBrush")
	pSetBkMode        = gdi32.NewProc("SetBkMode")
	pGetStockObject   = gdi32.NewProc("GetStockObject")
	pShellNotifyIcon  = shell32.NewProc("Shell_NotifyIconW")
	pLoadImageW       = user32.NewProc("LoadImageW")
	pGetModuleHandleW = kernel32.NewProc("GetModuleHandleW")
	pSetTimer         = user32.NewProc("SetTimer")
	pKillTimer        = user32.NewProc("KillTimer")
	pInvalidateRect   = user32.NewProc("InvalidateRect")
	pAppendMenuW      = user32.NewProc("AppendMenuW")
	pCreatePopupMenu  = user32.NewProc("CreatePopupMenu")
	pTrackPopupMenu   = user32.NewProc("TrackPopupMenu")
	pSetForegroundW   = user32.NewProc("SetForegroundWindow")
	pGetCursorPos     = user32.NewProc("GetCursorPos")
)

const (
	wsOverlappedWindow = 0x00CF0000
	wsVisible          = 0x10000000
	wsChild            = 0x40000000
	wsBorder           = 0x00800000
	wsTabStop           = 0x00010000
	esAutoHScroll      = 0x0001
	esMultiline        = 0x0004
	esReadOnly         = 0x0800
	bsPushButton       = 0x00000000
	bsGroupbox         = 0x00000007
	cwUseDefault       = 0x80000000
	swShow             = 5
	wmCreate           = 0x0001
	wmDestroy          = 0x0002
	wmSize             = 0x0005
	wmClose            = 0x0010
	wmPaint            = 0x000F
	wmTimer            = 0x0113
	wmCommand          = 0x0111
	wmApp              = 0x8000
	wmTray             = wmApp + 1
	wmLButtonUp        = 0x0202
	wmLButtonDblClk    = 0x0203
	wmRButtonUp        = 0x0205
	nimAdd             = 0
	nimModify          = 1
	nimDelete          = 2
	nifMessage         = 0x1
	nifIcon            = 0x2
	nifTip             = 0x4
	transparent        = 1
	colorWindow        = 5
	tpmLeftAlign       = 0
	tpmBottomAlign     = 0x20
	tpmRightButton     = 0x0002
	tpmReturnCmd       = 0x0100
	imageIcon          = 1
	lrLoadFromFile     = 0x00000010
	idConnect          = 1001
	idRefresh          = 1002
	idTun              = 1003
	idExit             = 1004
	idHide             = 1005
	idShow             = 1006
	timerRefresh       = 1
)

type wndClassExW struct {
	Size       uint32
	Style      uint32
	WndProc    uintptr
	ClsExtra   int32
	WndExtra   int32
	Instance   syscall.Handle
	Icon       syscall.Handle
	Cursor     syscall.Handle
	Background syscall.Handle
	MenuName   *uint16
	ClassName  *uint16
	IconSm     syscall.Handle
}

type point struct{ X, Y int32 }

type msgStruct struct {
	Hwnd    syscall.Handle
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      point
}

type notifyIconData struct {
	Size      uint32
	Wnd       syscall.Handle
	ID        uint32
	Flags     uint32
	Callback  uint32
	Icon      syscall.Handle
	Tip       [128]uint16
	State     uint32
	StateMask uint32
	Info      [256]uint16
	Version   uint32
	InfoTitle [64]uint16
	InfoFlags uint32
}

type rect struct{ Left, Top, Right, Bottom int32 }

// Actions — то, что окно умеет вызывать в приложении.
type Actions struct {
	OnConnect    func() // включить/выключить туннель
	OnRefresh    func() // найти/обновить серверы
	OnToggleTun  func()
	OnQuit       func()
	Status       func() (state string, detail string, connected bool, tun bool)
}

// Window — главное окно.
type Window struct {
	hwnd      syscall.Handle
	hStatus   syscall.Handle
	hDetail   syscall.Handle
	hConnect  syscall.Handle
	hRefresh  syscall.Handle
	hTun      syscall.Handle
	actions   Actions
	mu        sync.Mutex
	visible   bool
	logBuf    []string
}

var (
	gWin     *Window
	wndProcCb = syscall.NewCallback(wndProc)
)

func utf16(s string) *uint16 {
	p, err := syscall.UTF16PtrFromString(s)
	if err != nil {
		return nil
	}
	return p
}

func fillTip(dst *[128]uint16, s string) {
	u, _ := syscall.UTF16FromString(s)
	copy(dst[:], u)
}

// Run создаёт окно и входит в цикл сообщений (блокирующий вызов).
func Run(title string, a Actions) error {
	gWin = &Window{actions: a, visible: true}

	hInst, _, _ := pGetModuleHandleW.Call(0)
	className := utf16("VeloxVPNPC")
	iconPath := utf16(selfIconPath())

	var wc wndClassExW
	wc.Size = uint32(unsafe.Sizeof(wc))
	wc.WndProc = wndProcCb
	wc.Instance = syscall.Handle(hInst)
	wc.ClassName = className
	wc.Background = syscall.Handle(colorWindow + 1)
	if iconPath != nil {
		if hIcon, _, _ := pLoadImageW.Call(0, uintptr(unsafe.Pointer(iconPath)), imageIcon, 0, 0, lrLoadFromFile); hIcon != 0 {
			wc.Icon = syscall.Handle(hIcon)
			wc.IconSm = syscall.Handle(hIcon)
		}
	}
	if r, _, _ := pRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc))); r == 0 {
		return fmt.Errorf("RegisterClassExW failed")
	}

	hwnd, _, _ := pCreateWindowExW.Call(
		0, uintptr(unsafe.Pointer(className)), uintptr(unsafe.Pointer(utf16(title))),
		wsOverlappedWindow|wsVisible,
		cwUseDefault, cwUseDefault, 560, 460,
		0, 0, hInst, 0,
	)
	if hwnd == 0 {
		return fmt.Errorf("CreateWindowExW failed")
	}
	gWin.hwnd = syscall.Handle(hwnd)
	gWin.logBuf = append(gWin.logBuf, "Готово. Нажмите «Подключить».")

	pShowWindow.Call(hwnd, swShow)
	pUpdateWindow.Call(hwnd)
	pSetTimer.Call(hwnd, timerRefresh, 500, 0)

	var m msgStruct
	for {
		r, _, _ := pGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			break
		}
		pTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		pDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}
	return nil
}

func selfIconPath() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	i := strings.LastIndexAny(exe, `\/`)
	if i < 0 {
		return "velox.ico"
	}
	return exe[:i+1] + "velox.ico"
}

func wndProc(hwnd syscall.Handle, msg uint32, wParam, lParam uintptr) uintptr {
	switch msg {
	case wmCreate:
		gWin.createControls(hwnd)
		gWin.addTrayIcon()
		return 0

	case wmTimer:
		gWin.refreshLabels()
		return 0

	case wmCommand:
		switch int(wParam & 0xffff) {
		case idConnect:
			if gWin.actions.OnConnect != nil {
				go gWin.actions.OnConnect()
			}
		case idRefresh:
			if gWin.actions.OnRefresh != nil {
				go gWin.actions.OnRefresh()
			}
		case idTun:
			if gWin.actions.OnToggleTun != nil {
				go gWin.actions.OnToggleTun()
			}
		case idHide:
			pShowWindow.Call(uintptr(hwnd), 0)
			gWin.mu.Lock()
			gWin.visible = false
			gWin.mu.Unlock()
		case idShow:
			pShowWindow.Call(uintptr(hwnd), swShow)
			pSetForegroundW.Call(uintptr(hwnd))
			gWin.mu.Lock()
			gWin.visible = true
			gWin.mu.Unlock()
		case idExit:
			if gWin.actions.OnQuit != nil {
				gWin.actions.OnQuit()
			}
			pDestroyWindow.Call(uintptr(hwnd))
		}
		return 0

	case wmTray:
		switch int(lParam & 0xffff) {
		case wmLButtonDblClk:
			pShowWindow.Call(uintptr(hwnd), swShow)
			pSetForegroundW.Call(uintptr(hwnd))
		case wmRButtonUp:
			gWin.showTrayMenu(hwnd)
		}
		return 0

	case wmClose:
		// Крестик сворачивает в трей, туннель продолжает работать
		pShowWindow.Call(uintptr(hwnd), 0)
		gWin.mu.Lock()
		gWin.visible = false
		gWin.mu.Unlock()
		return 0

	case wmDestroy:
		gWin.removeTrayIcon()
		pKillTimer.Call(uintptr(hwnd), timerRefresh)
		pPostQuitMessage.Call(0)
		return 0
	}
	r, _, _ := pDefWindowProcW.Call(uintptr(hwnd), uintptr(msg), wParam, lParam)
	return r
}

func (w *Window) createControls(hwnd syscall.Handle) {
	hInst, _, _ := pGetModuleHandleW.Call(0)
	mk := func(class, text string, style uintptr, x, y, cx, cy int32, id int) syscall.Handle {
		h, _, _ := pCreateWindowExW.Call(
			0, uintptr(unsafe.Pointer(utf16(class))), uintptr(unsafe.Pointer(utf16(text))),
			style, uintptr(x), uintptr(y), uintptr(cx), uintptr(cy),
			uintptr(hwnd), uintptr(id), hInst, 0,
		)
		return syscall.Handle(h)
	}

	w.hStatus = mk("STATIC", "VELOX VPN · не подключено", wsChild|wsVisible, 24, 20, 500, 26, 0)
	w.hDetail = mk("STATIC", "Нажмите «Найти серверы», затем «Подключить»", wsChild|wsVisible, 24, 50, 500, 40, 0)

	w.hConnect = mk("BUTTON", "Подключить", wsChild|wsVisible|wsTabStop|bsPushButton, 24, 100, 240, 44, idConnect)
	w.hRefresh = mk("BUTTON", "Найти серверы", wsChild|wsVisible|wsTabStop|bsPushButton, 276, 100, 240, 44, idRefresh)
	w.hTun = mk("BUTTON", "Режим TUN: выкл", wsChild|wsVisible|wsTabStop|bsPushButton, 24, 156, 492, 36, idTun)

	mk("STATIC", "VeloxVPN для Windows · ядро mihomo · VLESS/Reality/XHTTP · Белые списки РФ",
		wsChild|wsVisible, 24, 384, 500, 20, 0)
}

func (w *Window) addTrayIcon() {
	var nid notifyIconData
	nid.Size = uint32(unsafe.Sizeof(nid))
	nid.Wnd = w.hwnd
	nid.ID = 1
	nid.Flags = nifIcon | nifTip | nifMessage
	nid.Callback = wmTray
	if p := utf16(selfIconPath()); p != nil {
		if h, _, _ := pLoadImageW.Call(0, uintptr(unsafe.Pointer(p)), imageIcon, 0, 0, lrLoadFromFile); h != 0 {
			nid.Icon = syscall.Handle(h)
		}
	}
	fillTip(&nid.Tip, "VeloxVPN — не подключено")
	pShellNotifyIcon.Call(nimAdd, uintptr(unsafe.Pointer(&nid)))
}

func (w *Window) removeTrayIcon() {
	var nid notifyIconData
	nid.Size = uint32(unsafe.Sizeof(nid))
	nid.Wnd = w.hwnd
	pShellNotifyIcon.Call(nimDelete, uintptr(unsafe.Pointer(&nid)))
}

func (w *Window) showTrayMenu(hwnd syscall.Handle) {
	menu, _, _ := pCreatePopupMenu.Call()
	pAppendMenuW.Call(menu, 0, idShow, uintptr(unsafe.Pointer(utf16("Открыть VeloxVPN"))))
	pAppendMenuW.Call(menu, 0, idConnect, uintptr(unsafe.Pointer(utf16("Подключить / Отключить"))))
	pAppendMenuW.Call(menu, 0, idExit, uintptr(unsafe.Pointer(utf16("Выход"))))
	var pt point
	pGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	pSetForegroundW.Call(uintptr(hwnd))
	pTrackPopupMenu.Call(menu, tpmLeftAlign|tpmBottomAlign|tpmRightButton|tpmReturnCmd,
		uintptr(pt.X), uintptr(pt.Y), 0, uintptr(hwnd), 0)
}

// refreshLabels обновляет статус из приложения (вызывается по таймеру).
func (w *Window) refreshLabels() {
	if w.actions.Status == nil {
		return
	}
	state, detail, connected, tun := w.actions.Status()
	if w.hStatus != 0 {
		pSetWindowTextW.Call(uintptr(w.hStatus), uintptr(unsafe.Pointer(utf16("VELOX VPN · "+state))))
	}
	if w.hDetail != 0 {
		pSetWindowTextW.Call(uintptr(w.hDetail), uintptr(unsafe.Pointer(utf16(detail))))
	}
	if w.hConnect != 0 {
		label := "Подключить"
		if connected {
			label = "Отключить"
		}
		pSetWindowTextW.Call(uintptr(w.hConnect), uintptr(unsafe.Pointer(utf16(label))))
	}
	if w.hTun != 0 {
		label := "Режим TUN: выкл"
		if tun {
			label = "Режим TUN: вкл (весь компьютер)"
		}
		pSetWindowTextW.Call(uintptr(w.hTun), uintptr(unsafe.Pointer(utf16(label))))
	}
}

// SetDetail — обновить текст из другого потока.
func (w *Window) SetDetail(text string) {
	w.mu.Lock()
	w.logBuf = append(w.logBuf, text)
	if len(w.logBuf) > 40 {
		w.logBuf = w.logBuf[len(w.logBuf)-40:]
	}
	w.mu.Unlock()
	if w.hDetail != 0 {
		pSetWindowTextW.Call(uintptr(w.hDetail), uintptr(unsafe.Pointer(utf16(text))))
	}
}

// SetTrayTip — подсказка в трее.
func (w *Window) SetTrayTip(text string) {
	var nid notifyIconData
	nid.Size = uint32(unsafe.Sizeof(nid))
	nid.Wnd = w.hwnd
	nid.ID = 1
	nid.Flags = nifTip
	fillTip(&nid.Tip, text)
	pShellNotifyIcon.Call(nimModify, uintptr(unsafe.Pointer(&nid)))
}
