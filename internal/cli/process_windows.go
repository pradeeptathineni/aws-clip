//go:build windows

// process_windows.go - Preserve Windows interrupts and child exit statuses

package cli

import (
	"os"
	"os/exec"
)

func forwardedSignals() []os.Signal {
	return []os.Signal{os.Interrupt}
}

func processExitCode(exitError *exec.ExitError) int {
	code := exitError.ExitCode()
	// Negative codes indicate that no native child status is available
	if code < 0 {
		return exitCannotRun
	}
	return code
}
