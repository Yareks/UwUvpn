//go:build windows

package tunnel

import (
	"os/exec"
	"syscall"
)

// hideWindow не даёт ядру мигать консольным окном поверх приложения.
func hideWindow(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
}
