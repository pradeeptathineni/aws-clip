//go:build !windows

// process_unix.go - Preserve Unix signals and native child exit statuses

package cli

import (
	"os"
	"os/exec"
	"syscall"
)

// forwardedSignals lists termination signals that should reach the AWS child
// excludes signals whose default handling should remain owned by the wrapper
func forwardedSignals() []os.Signal {
	return []os.Signal{syscall.SIGHUP, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM}
}

// processExitCode translates exec errors into conventional shell statuses
// exitError must describe a child that started and subsequently failed
func processExitCode(exitError *exec.ExitError) int {
	if status, ok := exitError.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		// Shells conventionally expose signal termination as 128 + signal
		// the same representation makes wrapper automation indistinguishable
		// from invoking AWS CLI directly for the supported forwarded signals
		return 128 + int(status.Signal())
	}
	return exitError.ExitCode()
}
