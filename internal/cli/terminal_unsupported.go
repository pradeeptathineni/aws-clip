//go:build !linux && !darwin && !dragonfly && !freebsd && !netbsd && !openbsd && !windows

// terminal_unsupported.go - Disable interactive mode on unsupported platforms

package cli

import "os"

// isTerminal fails closed on platforms without an implemented console probe
// Disabling interactive AWS features is safer than allowing a pager or prompt
// to block automation based only on ambiguous character-device metadata
func isTerminal(_ *os.File) bool {
	return false
}
