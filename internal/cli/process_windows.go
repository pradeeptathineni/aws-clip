//go:build windows

// process_windows.go - Preserve Windows interrupts and child exit statuses

package cli

import (
	"os"
	"os/exec"
)

// forwardedSignals limits forwarding to the portable console interrupt
func forwardedSignals() []os.Signal {
	return []os.Signal{os.Interrupt}
}

// processExitCode returns the native Windows child status when available
// negative codes indicate an unavailable status and fail as a wrapper error
func processExitCode(exitError *exec.ExitError) int {
	code := exitError.ExitCode()
	if code < 0 {
		return exitCannotRun
	}
	return code
}
