//go:build windows

package ui

import (
	"os"
	"syscall"
	"unsafe"
)

var pGetModuleFileNameW = syscall.NewLazyDLL("kernel32.dll").NewProc("GetModuleFileNameW")

// ownPath возвращает путь к текущему .exe без обрезки длинных путей.
func ownPath() string {
	if exe, err := os.Executable(); err == nil {
		return exe
	}
	buf := make([]uint16, 4096)
	n, _, _ := pGetModuleFileNameW.Call(0, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if n == 0 {
		return ""
	}
	return syscall.UTF16ToString(buf[:n])
}
