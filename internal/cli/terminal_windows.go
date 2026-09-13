//go:build windows

package cli

import (
	"os"
	"syscall"
)

// isTerminal succeeds only for handles attached to a Windows console. In
// particular, NUL is a character device but GetConsoleMode rejects its handle.
func isTerminal(file *os.File) bool {
	var mode uint32
	return syscall.GetConsoleMode(syscall.Handle(file.Fd()), &mode) == nil
}
