// process.go - Run AWS CLI commands with native streams, signals, and statuses
package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
)

// runAWS starts exactly one AWS operation process after version validation.
// User-facing streams are attached directly, preserving binary data, terminal
// behavior, and AWS diagnostic formatting. Internal probes may supply bounded
// writers or nil for an operating-system null device.
func runAWS(path string, arguments, environ []string, stdin io.Reader, stdout, stderr io.Writer) int {
	command := exec.Command(path, arguments...)
	command.Env = environ
	command.Stdin = stdin
	// A nil os/exec stream is connected directly to the null device. Presence
	// checks use that path so configured credential values never pass through
	// aws-clip memory.
	if stdout != nil {
		command.Stdout = stdout
	}
	if stderr != nil {
		command.Stderr = stderr
	}

	forwarded := make(chan os.Signal, 1)
	signal.Notify(forwarded, forwardedSignals()...)
	if err := command.Start(); err != nil {
		signal.Stop(forwarded)
		if stderr != nil {
			fmt.Fprintln(stderr, "aws-clip: AWS CLI could not be started")
		}
		return exitCannotRun
	}

	stopped := make(chan struct{})
	go func() {
		for {
			select {
			case received := <-forwarded:
				// Signal errors usually mean the child has already exited. Wait owns
				// the authoritative status, so there is nothing useful to report.
				_ = command.Process.Signal(received)
			case <-stopped:
				return
			}
		}
	}()

	err := command.Wait()
	close(stopped)
	signal.Stop(forwarded)
	if err == nil {
		return exitOK
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		return processExitCode(exitError)
	}
	if stderr != nil {
		fmt.Fprintln(stderr, "aws-clip: AWS CLI process wait failed")
	}
	return exitCannotRun
}
