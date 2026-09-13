//go:build windows

// terminal_windows.go - Detect streams attached to a Windows console

package cli

import (
	"os"
	"syscall"
)

// GetConsoleMode rejects non-console character devices such as NUL
func isTerminal(file *os.File) bool {
	var mode uint32
	return syscall.GetConsoleMode(syscall.Handle(file.Fd()), &mode) == nil
}
