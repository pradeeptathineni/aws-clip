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

// runAWS starts exactly one previously validated AWS CLI process
// arguments remain literal with no intermediate shell interpretation
// environ replaces the child environment and streams preserve binary data
// nil output streams use the operating-system null device for secret-safe probes
// returns the native child status or exitCannotRun for wrapper process failures
func runAWS(path string, arguments, environ []string, stdin io.Reader, stdout, stderr io.Writer) int {
	command := exec.Command(path, arguments...)
	command.Env = environ
	command.Stdin = stdin
	// A nil os/exec stream is connected directly to the null device
	// checks use that path so configured credential values never pass through
	// aws-clip memory
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
				// Signal errors usually mean the child has already exited
				// Wait owns the authoritative status so there is nothing useful to report
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
