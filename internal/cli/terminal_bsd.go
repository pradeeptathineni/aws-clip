//go:build darwin || dragonfly || freebsd || netbsd || openbsd

package cli

import (
	"os"
	"syscall"
	"unsafe"
)

// BSD-family systems expose terminal attributes through TIOCGETA. A successful
// ioctl distinguishes a real terminal from other character devices without
// reading from or otherwise disturbing the stream.
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
