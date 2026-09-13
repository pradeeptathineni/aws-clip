//go:build windows

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
	if code < 0 {
		return exitCannotRun
	}
	return code
}
