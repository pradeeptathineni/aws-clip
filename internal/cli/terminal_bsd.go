//go:build darwin || dragonfly || freebsd || netbsd || openbsd

// terminal_bsd.go - Detect interactive terminals on BSD-family systems

package cli

import (
	"os"
	"syscall"
	"unsafe"
)

// TIOCGETA distinguishes terminals from other character devices without consuming input
func isTerminal(file *os.File) bool {
	var attributes syscall.Termios
	_, _, errno := syscall.Syscall6(
		syscall.SYS_IOCTL,
		file.Fd(),
		uintptr(syscall.TIOCGETA),
		uintptr(unsafe.Pointer(&attributes)),
		0,
		0,
		0,
	)
	return errno == 0
}
