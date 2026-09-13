//go:build linux

// terminal_linux.go - Detect interactive terminals on Linux

package cli

import (
	"os"
	"syscall"
	"unsafe"
)

// isTerminal asks the kernel for terminal attributes without consuming input
// filesystem metadata alone cannot distinguish terminals from /dev/null
// non-terminal character devices reject TCGETS and fail closed
func isTerminal(file *os.File) bool {
	var attributes syscall.Termios
	_, _, errno := syscall.Syscall6(
		syscall.SYS_IOCTL,
		file.Fd(),
		uintptr(syscall.TCGETS),
		uintptr(unsafe.Pointer(&attributes)),
		0,
		0,
		0,
	)
	return errno == 0
}
