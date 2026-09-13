//go:build !linux && !darwin && !dragonfly && !freebsd && !netbsd && !openbsd && !windows

// terminal_unsupported.go - Disable interactive mode on unsupported platforms

package cli

import "os"

// Fail closed rather than let a pager or prompt block automation
func isTerminal(_ *os.File) bool {
	return false
}
