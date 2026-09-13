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

// Arguments stay literal, streams preserve binary data, and nil output goes to
// the null device for secret-safe probes; wrapper failures return exitCannotRun
func runAWS(path string, arguments, environ []string, stdin io.Reader, stdout, stderr io.Writer) int {
	command := exec.Command(path, arguments...)
	command.Env = environ
	command.Stdin = stdin
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
				// Wait owns the authoritative status if the child has already exited
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
