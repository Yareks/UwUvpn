//go:build windows

// Package ui — собственный отрисованный интерфейс (Win32 GDI), без системных кнопок.
//
// v1.0.2: предыдущее окно использовало стандартные серые контролы Windows — отсюда «некрасиво».
// Теперь всё рисуется вручную: тёмная тема, скруглённые карточки, большая кнопка питания,
// список серверов с задержками, живой индикатор и журнал операций. Один .exe, без зависимостей.
package ui

import (
	"fmt"
	"math"
	"strings"
	"sync"
	"syscall"
	"time"
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
	pCreateSolidBrush = gdi32.NewProc("CreateSolidBrush")
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
	pBeginPaint       = user32.NewProc("BeginPaint")
	pEndPaint         = user32.NewProc("EndPaint")
	pGetClientRect    = user32.NewProc("GetClientRect")
	pSetCapture       = user32.NewProc("SetCapture")
	pReleaseCapture   = user32.NewProc("ReleaseCapture")
	pLoadCursorW      = user32.NewProc("LoadCursorW")

	pCreateFontW      = gdi32.NewProc("CreateFontW")
	pCreatePen        = gdi32.NewProc("CreatePen")
	pRectangle        = gdi32.NewProc("Rectangle")
	pEllipse          = gdi32.NewProc("Ellipse")
	pRoundRect        = gdi32.NewProc("RoundRect")
	pTextOutW         = user32.NewProc("TextOutW")
	pSetTextColor     = gdi32.NewProc("SetTextColor")
	pSetBkMode        = gdi32.NewProc("SetBkMode")
	pSelectObject     = gdi32.NewProc("SelectObject")
	pDeleteObject     = gdi32.NewProc("DeleteObject")
	pCreateCompatDC   = gdi32.NewProc("CreateCompatibleDC")
	pCreateCompatBmp  = gdi32.NewProc("CreateCompatibleBitmap")
	pBitBlt           = gdi32.NewProc("BitBlt")
	pDeleteDC         = gdi32.NewProc("DeleteDC")
	pFillRect         = user32.NewProc("FillRect")
)

const (
	wsOverlappedWindow = 0x00CF0000
	wsVisible          = 0x10000000
	wsMinimizeBox      = 0x00020000
	wsMaximizeBox      = 0x00010000
	wsThickFrame       = 0x00040000
	wsSysMenu          = 0x00080000
	cwUseDefault       = 0x80000000
	swShow             = 5
	wmCreate           = 0x0001
	wmDestroy          = 0x0002
	wmPaint            = 0x000F
	wmClose            = 0x0010
	wmTimer            = 0x0113
	wmCommand          = 0x0111
	wmApp              = 0x8000
	wmTray             = wmApp + 1
	wmLButtonUp        = 0x0202
	wmLButtonDblClk    = 0x0203
	wmRButtonUp        = 0x0205
	wmMouseMove        = 0x0200
	nimAdd             = 0
	nimModify          = 1
	nimDelete          = 2
	nifMessage         = 0x1
	nifIcon            = 0x2
	nifTip             = 0x4
	imageIcon          = 1
	lrLoadFromFile     = 0x00000010
	idExit             = 1004
	idHide             = 1005
	idShow             = 1006
	timerTick          = 1
	colorWindowClass   = 5
	dtLeft             = 0x00000000
	dtCenter           = 0x00000001
	dtVCenter          = 0x00000004
	dtSingleLine       = 0x00000020
	dtRight            = 0x00000002
	srccopy            = 0x00CC0020
	psSolid            = 0
	transparent        = 1
)

var (
	colBg      = rgb(0x0E, 0x11, 0x18)
	colCard    = rgb(0x17, 0x1C, 0x26)
	colCard2   = rgb(0x1E, 0x24, 0x31)
	colText    = rgb(0xEC, 0xF1, 0xF8)
	colSub     = rgb(0x8C, 0x97, 0xA8)
	colAccent  = rgb(0x3B, 0x82, 0xF6)
	colOk      = rgb(0x2E, 0xC4, 0x8A)
	colWarn    = rgb(0xF2, 0xB0, 0x2E)
	colErr     = rgb(0xE5, 0x4D, 0x4D)
	colRing    = rgb(0x22, 0x2A, 0x38)
)

func rgb(r, g, b byte) uint32 {
	return uint32(r) | uint32(g)<<8 | uint32(b)<<16
}

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
type rect struct{ Left, Top, Right, Bottom int32 }

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

type paintStruct struct {
	Hdc         syscall.Handle
	Erase       int32
	RcPaint     rect
	Restore     int32
	IncUpdate   int32
	Reserved    [32]byte
}

// ServerRow — строка списка серверов для отрисовки.
type ServerRow struct {
	Name    string
	Country string
	Ms      int
	Active  bool
}

// View — всё, что окно рисует. Приложение заполняет через SetView.
type View struct {
	State   string // «не подключено» / «подключение…» / «подключено»
	Sub     string // вторая строка статуса
	ExitIP  string
	Region  string
	Tun     bool
	Busy    bool
	Servers []ServerRow
	Log     []string
	Step    int // 0..4 текущий шаг загрузки
}

// Actions — то, что окно вызывает в приложении.
type Actions struct {
	OnConnect   func()
	OnRefresh   func()
	OnToggleTun func()
	OnQuit      func()
	OnPick      func(name string)
	OnUiReady   func(w *Window)
	View        func() View
}

// Window — главное окно.
type Window struct {
	hwnd     syscall.Handle
	actions  Actions
	mu       sync.Mutex
	view     View
	visible  bool
	hoverBtn int // 0 = нет, 1 = кнопка питания, 2 = обновить, 3 = TUN
	pressBtn int
	rowAt    []struct {
		top, bottom int32
		name        string
	}
	fontTitle syscall.Handle
	fontBig   syscall.Handle
	fontBody  syscall.Handle
	fontSmall syscall.Handle
	fontMono  syscall.Handle
}

var (
	gWin      *Window
	wndProcCb  = syscall.NewCallback(wndProc)
	cursorHand = syscall.Handle(0)
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

// Run создаёт окно и входит в цикл сообщений.
func Run(title string, a Actions) error {
	gWin = &Window{actions: a, visible: true}
	gWin.view = View{State: "не подключено", Sub: "Нажмите «Найти серверы»"}

	hInst, _, _ := pGetModuleHandleW.Call(0)
	className := utf16("VeloxVPNPC2")
	iconPath := utf16(selfIconPath())

	var wc wndClassExW
	wc.Size = uint32(unsafe.Sizeof(wc))
	wc.WndProc = wndProcCb
	wc.Instance = syscall.Handle(hInst)
	wc.ClassName = className
	wc.Background = syscall.Handle(colorWindowClass + 1)
	if iconPath != nil {
		if hIcon, _, _ := pLoadImageW.Call(0, uintptr(unsafe.Pointer(iconPath)), imageIcon, 0, 0, lrLoadFromFile); hIcon != 0 {
			wc.Icon = syscall.Handle(hIcon)
			wc.IconSm = syscall.Handle(hIcon)
		}
	}
	if c, _, _ := pLoadCursorW.Call(0, 32512); c != 0 { // IDC_ARROW
		wc.Cursor = syscall.Handle(c)
	}
	if r, _, _ := pRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc))); r == 0 {
		return fmt.Errorf("RegisterClassExW failed")
	}
	if c, _, _ := pLoadCursorW.Call(0, 32649); c != 0 { // IDC_HAND
		cursorHand = syscall.Handle(c)
	}

	hwnd, _, _ := pCreateWindowExW.Call(
		0, uintptr(unsafe.Pointer(className)), uintptr(unsafe.Pointer(utf16(title))),
		wsOverlappedWindow|wsVisible,
		cwUseDefault, cwUseDefault, 620, 720,
		0, 0, hInst, 0,
	)
	if hwnd == 0 {
		return fmt.Errorf("CreateWindowExW failed")
	}
	gWin.hwnd = syscall.Handle(hwnd)
	gWin.createFonts()

	pShowWindow.Call(hwnd, swShow)
	pUpdateWindow.Call(hwnd)
	pSetTimer.Call(hwnd, timerTick, 250, 0)

	if a.OnUiReady != nil {
		a.OnUiReady(gWin)
	}

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
	exe := ownPath()
	i := strings.LastIndexAny(exe, `\/`)
	if i < 0 {
		return "velox.ico"
	}
	return exe[:i+1] + "velox.ico"
}

func (w *Window) createFonts() {
	mk := func(height int32, weight int32, face string) syscall.Handle {
		h, _, _ := pCreateFontW.Call(
			uintptr(height), 0, 0, 0, uintptr(weight),
			0, 0, 0, 204, 5, 0, 4, 0, uintptr(unsafe.Pointer(utf16(face))),
		)
		return syscall.Handle(h)
	}
	w.fontTitle = mk(-22, 700, "Segoe UI")
	w.fontBig = mk(-27, 700, "Segoe UI")
	w.fontBody = mk(-15, 400, "Segoe UI")
	w.fontSmall = mk(-13, 400, "Segoe UI")
	w.fontMono = mk(-13, 400, "Consolas")
}

// SetView заменяет содержимое окна.
func (w *Window) SetView(v View) {
	w.mu.Lock()
	w.view = v
	w.mu.Unlock()
	if w.hwnd != 0 {
		pInvalidateRect.Call(uintptr(w.hwnd), 0, 0)
	}
}

// SetDetail — совместимость: просто обновляет подпись.
func (w *Window) SetDetail(text string) {
	w.mu.Lock()
	w.view.Sub = text
	w.mu.Unlock()
	if w.hwnd != 0 {
		pInvalidateRect.Call(uintptr(w.hwnd), 0, 0)
	}
}

// SetTrayTip — подсказка в трее.
func (w *Window) SetTrayTip(text string) {
	var nid notifyIconData
	nid.Size = uint32(unsafe.Sizeof(nid))
	nid.ID = 1
	nid.Wnd = w.hwnd
	nid.Flags = nifTip
	fillTip(&nid.Tip, text)
	pShellNotifyIcon.Call(nimModify, uintptr(unsafe.Pointer(&nid)))
}

// ------------------------------------------------------------------ drawing

func wndProc(hwnd syscall.Handle, msg uint32, wParam, lParam uintptr) uintptr {
	switch msg {
	case wmCreate:
		gWin.hwnd = hwnd
		gWin.addTrayIcon()
		return 0

	case wmTimer:
		if gWin.actions.View != nil {
			gWin.SetView(gWin.actions.View())
		}
		return 0

	case wmPaint:
		gWin.paint(hwnd)
		return 0

	case wmMouseMove:
		x, y := int32(lParam&0xffff), int32((lParam>>16)&0xffff)
		gWin.hoverBtn = gWin.hitTest(x, y)
		if gWin.hoverBtn != 0 || gWin.overRow(y) {
			pSetCursorW.Call(uintptr(cursorHand))
			return 1 // TRUE: курсор уже установлен
		}
		pSetCursorW.Call(uintptr(32512)) // IDC_ARROW
		return 0

	case wmLButtonUp:
		x, y := int32(lParam&0xffff), int32((lParam>>16)&0xffff)
		gWin.click(x, y)
		return 0

	case wmCommand:
		switch int(wParam & 0xffff) {
		case idHide:
			pShowWindow.Call(uintptr(hwnd), 0)
		case idShow:
			pShowWindow.Call(uintptr(hwnd), swShow)
			pSetForegroundW.Call(uintptr(hwnd))
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
		pShowWindow.Call(uintptr(hwnd), 0) // сворачиваем в трей, туннель живёт
		return 0

	case wmDestroy:
		gWin.removeTrayIcon()
		pKillTimer.Call(uintptr(hwnd), timerTick)
		pPostQuitMessage.Call(0)
		return 0
	}
	r, _, _ := pDefWindowProcW.Call(uintptr(hwnd), uintptr(msg), wParam, lParam)
	return r
}

var pSetCursorW = user32.NewProc("SetCursor")

// hitTest возвращает 1 (кнопка питания), 2 (обновить), 3 (TUN) или 0.
func (w *Window) hitTest(x, y int32) int {
	cx, cy := int32(310), int32(180)
	if d := dist(x, y, cx, cy); d <= 60 {
		return 1
	}
	if x >= 40 && x <= 300 && y >= 352 && y <= 396 {
		return 2 // «Обновить»
	}
	if x >= 320 && x <= 580 && y >= 352 && y <= 396 {
		return 3 // TUN
	}
	w.mu.Lock()
	rows := w.rowAt
	w.mu.Unlock()
	for _, r := range rows {
		if y >= r.top && y <= r.bottom && w.actions.OnPick != nil {
			return 0 // строку обрабатываем в click
		}
	}
	return 0
}

// overRow — находится ли Y над строкой сервера (для курсора-руки).
func (w *Window) overRow(y int32) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, r := range w.rowAt {
		if y >= r.top && y <= r.bottom {
			return true
		}
	}
	return false
}

func dist(x1, y1, x2, y2 int32) float64 {
	dx, dy := float64(x1-x2), float64(y1-y2)
	return math.Sqrt(dx*dx + dy*dy)
}

func (w *Window) click(x, y int32) {
	switch w.hitTest(x, y) {
	case 1:
		if w.actions.OnConnect != nil {
			go w.actions.OnConnect()
		}
		return
	case 2:
		if w.actions.OnRefresh != nil {
			go w.actions.OnRefresh()
		}
		return
	case 3:
		if w.actions.OnToggleTun != nil {
			go w.actions.OnToggleTun()
		}
		return
	}
	// клик по строке сервера -> выбор узла
	w.mu.Lock()
	rows := w.rowAt
	w.mu.Unlock()
	for _, r := range rows {
		if y >= r.top && y <= r.bottom && w.actions.OnPick != nil {
			go w.actions.OnPick(r.name)
			return
		}
	}
}

func (w *Window) paint(hwnd syscall.Handle) {
	var ps paintStruct
	hdc, _, _ := pBeginPaint.Call(uintptr(hwnd), uintptr(unsafe.Pointer(&ps)))
	defer pEndPaint.Call(uintptr(hwnd), uintptr(unsafe.Pointer(&ps)))

	var rc rect
	pGetClientRect.Call(uintptr(hwnd), uintptr(unsafe.Pointer(&rc)))
	W, H := rc.Right, rc.Bottom

	// двойная буферизация, чтобы не мигало при перерисовке
	memDC, _, _ := pCreateCompatDC.Call(uintptr(hdc))
	bmp, _, _ := pCreateCompatBmp.Call(uintptr(hdc), uintptr(W), uintptr(H))
	old, _, _ := pSelectObject.Call(memDC, bmp)
	defer func() {
		pSelectObject.Call(memDC, old)
		pDeleteObject.Call(bmp)
		pDeleteDC.Call(memDC)
	}()
	dc := memDC

	w.mu.Lock()
	v := w.view
	w.mu.Unlock()

	// фон
	fill(dc, 0, 0, W, H, colBg)

	// заголовок
	text(dc, w.fontTitle, "VeloxVPN", 32, 26, colText)
	text(dc, w.fontSmall, "Windows · VLESS/Reality/XHTTP", 34, 56, colSub)
	badge := "не подключено"
	badgeCol := colSub
	if v.Busy {
		badge, badgeCol = "работаю…", colWarn
	} else if strings.HasPrefix(v.State, "подключено") {
		badge, badgeCol = "защищено", colOk
	}
	text(dc, w.fontSmall, badge, W-150, 34, badgeCol)

	// карточка статуса
	card(dc, 32, 84, W-32, 332, colCard)

	// кнопка питания (круг + иконка)
	cx, cy := int32(310), int32(180)
	ringCol := colRing
	iconCol := colSub
	if strings.HasPrefix(v.State, "подключено") {
		ringCol, iconCol = colOk, colOk
	} else if v.Busy {
		ringCol, iconCol = colWarn, colWarn
	}
	thickRing(dc, cx, cy, 50, 6, ringCol)
	// «питание»: дуга + вертикальная черта
	arc(dc, cx, cy, 33, iconCol)
	fill(dc, cx-2, cy-37, cx+3, cy-3, iconCol)

	// крупный статус
	headline := "Не подключено"
	if v.Busy {
		headline = "Подготовка…"
	} else if strings.HasPrefix(v.State, "подключено") {
		headline = "Защищено"
	}
	textCenter(dc, w.fontBig, headline, 32, W-32, 244, colText)
	caption := "нажмите «Обновить»"
	if v.Busy {
		caption = "проверяю серверы…"
	} else if strings.HasPrefix(v.State, "подключено") {
		if v.ExitIP != "" {
			caption = "выход " + v.ExitIP
		} else {
			caption = "трафик идёт через VPN"
		}
	}
	textCenter(dc, w.fontSmall, caption, 32, W-32, 296, colSub)

	// ряд кнопок: «Обновить» + переключатель TUN
	btn(dc, 40, 352, 300, 396, "Найти серверы", colAccent, colText, w.fontBody)
	tunCol := colCard2
	tunText := "TUN: выкл · прокси 127.0.0.1"
	if v.Tun {
		tunCol = colOk
		tunText = "TUN: включён (весь ПК)"
	}
	btn(dc, 320, 352, 580, 396, tunText, tunCol, colText, w.fontSmall)

	// подпись состояния под кнопками
	if v.Sub != "" {
		text(dc, w.fontSmall, clip(v.Sub, 88), 40, 414, colSub)
	}

	// список серверов
	y := int32(452)
	text(dc, w.fontSmall, "СЕРВЕРЫ", 40, y, colSub)
	y += 22
	w.rowAt = w.rowAt[:0]
	shown := 0
	for _, s := range v.Servers {
		if shown >= 6 || y+30 > H-40 {
			break
		}
		rowCol := colCard
		nameCol := colText
		if s.Active {
			rowCol = colCard2
			nameCol = colOk
		}
		card(dc, 32, y, W-32, y+30, rowCol)
		text(dc, w.fontSmall, clip(s.Name, 44), 44, y+8, nameCol)
		ms := "—"
		msCol := colSub
		if s.Ms > 0 {
			ms = fmt.Sprintf("%d мс", s.Ms)
			switch {
			case s.Ms < 100:
				msCol = colOk
			case s.Ms < 250:
				msCol = colWarn
			default:
				msCol = colErr
			}
		}
		text(dc, w.fontSmall, ms, W-120, y+8, msCol)
		w.rowAt = append(w.rowAt, struct {
			top, bottom int32
			name        string
		}{y, y + 30, s.Name})
		y += 36
		shown++
	}
	if shown == 0 {
		text(dc, w.fontSmall, "Список пуст — нажмите «Найти серверы»", 44, y+6, colSub)
	}

	// нижняя строка журнала
	if len(v.Log) > 0 {
		last := v.Log[len(v.Log)-1]
		text(dc, w.fontSmall, clip(last, 84), 40, H-28, colSub)
	}

	pBitBlt.Call(uintptr(hdc), 0, 0, uintptr(W), uintptr(H), dc, 0, 0, srccopy)
}

// ------------------------------------------------------------------ primitives

func fill(dc uintptr, x1, y1, x2, y2 int32, color uint32) {
	br, _, _ := pCreateSolidBrush.Call(uintptr(color))
	r := rect{x1, y1, x2, y2}
	pFillRect.Call(uintptr(dc), uintptr(unsafe.Pointer(&r)), br)
	pDeleteObject.Call(br)
}

func card(dc uintptr, x1, y1, x2, y2 int32, color uint32) {
	br, _, _ := pCreateSolidBrush.Call(uintptr(color))
	pen, _, _ := pCreatePen.Call(psSolid, 1, uintptr(color))
	ob, _, _ := pSelectObject.Call(dc, br)
	op, _, _ := pSelectObject.Call(dc, pen)
	pRoundRect.Call(dc, uintptr(x1), uintptr(y1), uintptr(x2), uintptr(y2), 16, 16)
	pSelectObject.Call(dc, ob)
	pSelectObject.Call(dc, op)
	pDeleteObject.Call(br)
	pDeleteObject.Call(pen)
}

func btn(dc uintptr, x1, y1, x2, y2 int32, label string, bg, fg uint32, font syscall.Handle) {
	br, _, _ := pCreateSolidBrush.Call(uintptr(bg))
	pen, _, _ := pCreatePen.Call(psSolid, 1, uintptr(bg))
	ob, _, _ := pSelectObject.Call(dc, br)
	op, _, _ := pSelectObject.Call(dc, pen)
	pRoundRect.Call(dc, uintptr(x1), uintptr(y1), uintptr(x2), uintptr(y2), 14, 14)
	pSelectObject.Call(dc, ob)
	pSelectObject.Call(dc, op)
	pDeleteObject.Call(br)
	pDeleteObject.Call(pen)
	textCenter(dc, font, label, x1, x2, (y1+y2)/2-9, fg)
}

func thickRing(dc uintptr, cx, cy, r, w int32, color uint32) {
	for i := int32(0); i < w; i++ {
		pen, _, _ := pCreatePen.Call(psSolid, 1, uintptr(color))
		ob, _, _ := pSelectObject.Call(dc, pen)
		nullBr, _, _ := pGetStockObject.Call(5) // NULL_BRUSH
		obr, _, _ := pSelectObject.Call(dc, nullBr)
		rr := r - i
		pEllipse.Call(dc, uintptr(cx-rr), uintptr(cy-rr), uintptr(cx+rr), uintptr(cy+rr))
		pSelectObject.Call(dc, ob)
		pSelectObject.Call(dc, obr)
		pDeleteObject.Call(pen)
	}
}

// arc рисует дугу «питания» (разрыв сверху) множеством точек.
func arc(dc uintptr, cx, cy, r int32, color uint32) {
	pen, _, _ := pCreatePen.Call(psSolid, 5, uintptr(color))
	ob, _, _ := pSelectObject.Call(dc, pen)
	defer func() {
		pSelectObject.Call(dc, ob)
		pDeleteObject.Call(pen)
	}()
	prevX, prevY := int32(0), int32(0)
	first := true
	for deg := -60.0; deg <= 240.0; deg += 4 {
		a := deg * math.Pi / 180
		x := cx + int32(float64(r)*math.Cos(a))
		y := cy + int32(float64(r)*math.Sin(a))
		if !first {
			pMoveTo.Call(dc, uintptr(prevX), uintptr(prevY))
			pLineTo.Call(dc, uintptr(x), uintptr(y))
		}
		prevX, prevY = x, y
		first = false
	}
}

var (
	pMoveTo = gdi32.NewProc("MoveToEx")
	pLineTo = gdi32.NewProc("LineTo")
)

func text(dc uintptr, font syscall.Handle, s string, x, y int32, color uint32) {
	if s == "" {
		return
	}
	o, _, _ := pSelectObject.Call(dc, uintptr(font))
	pSetTextColor.Call(dc, uintptr(color))
	pSetBkMode.Call(dc, transparent)
	pTextOutW.Call(dc, uintptr(x), uintptr(y), uintptr(unsafe.Pointer(utf16(s))), uintptr(len([]rune(s))))
	pSelectObject.Call(dc, o)
}

func textCenter(dc uintptr, font syscall.Handle, s string, x1, x2, y int32, color uint32) {
	w := textWidth(dc, font, s)
	text(dc, font, s, (x1+x2)/2-w/2, y, color)
}

func textWidth(dc uintptr, font syscall.Handle, s string) int32 {
	if s == "" {
		return 0
	}
	o, _, _ := pSelectObject.Call(dc, uintptr(font))
	var r rect
	pGetTextExtent.Call(dc, uintptr(unsafe.Pointer(utf16(s))), uintptr(len([]rune(s))),
		uintptr(unsafe.Pointer(&r.Right)), uintptr(unsafe.Pointer(&r.Bottom)))
	pSelectObject.Call(dc, o)
	return r.Right
}

var pGetTextExtent = gdi32.NewProc("GetTextExtentPoint32W")

func clip(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max-1]) + "…"
}

// ------------------------------------------------------------------ tray

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
	nid.ID = 1
	pShellNotifyIcon.Call(nimDelete, uintptr(unsafe.Pointer(&nid)))
}

func (w *Window) showTrayMenu(hwnd syscall.Handle) {
	menu, _, _ := pCreatePopupMenu.Call()
	pAppendMenuW.Call(menu, 0, idShow, uintptr(unsafe.Pointer(utf16("Открыть VeloxVPN"))))
	pAppendMenuW.Call(menu, 0, 1001, uintptr(unsafe.Pointer(utf16("Подключить / Отключить"))))
	pAppendMenuW.Call(menu, 0, idExit, uintptr(unsafe.Pointer(utf16("Выход"))))
	var pt point
	pGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	pSetForegroundW.Call(uintptr(hwnd))
	pTrackPopupMenu.Call(menu, 0x0002|0x0100|0x0020, uintptr(pt.X), uintptr(pt.Y), 0, uintptr(hwnd), 0)
}

var _ = time.Second
