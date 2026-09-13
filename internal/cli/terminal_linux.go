//go:build linux

package cli

import (
	"os"
	"syscall"
	"unsafe"
)

// isTerminal asks the kernel for terminal attributes instead of relying on
// filesystem metadata. Devices such as /dev/null are character devices too,
// but reject TCGETS and must therefore be treated as non-interactive streams.
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
