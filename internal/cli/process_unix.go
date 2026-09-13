//go:build !windows

// process_unix.go - Preserve Unix signals and native child exit statuses

package cli

import (
	"os"
	"os/exec"
	"syscall"
)

// Leave unlisted signals under wrapper ownership
func forwardedSignals() []os.Signal {
	return []os.Signal{syscall.SIGHUP, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM}
}

func processExitCode(exitError *exec.ExitError) int {
	if status, ok := exitError.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		// Preserve the conventional shell status for signal termination
		return 128 + int(status.Signal())
	}
	return exitError.ExitCode()
}
