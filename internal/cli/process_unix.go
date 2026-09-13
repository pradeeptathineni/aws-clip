//go:build !windows

package cli

import (
	"os"
	"os/exec"
	"syscall"
)

func forwardedSignals() []os.Signal {
	return []os.Signal{syscall.SIGHUP, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM}
}

func processExitCode(exitError *exec.ExitError) int {
	if status, ok := exitError.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		// Shells conventionally expose signal termination as 128 + signal. Using
		// the same representation makes wrapper automation indistinguishable
		// from invoking AWS CLI directly for the supported forwarded signals.
		return 128 + int(status.Signal())
	}
	return exitError.ExitCode()
}
