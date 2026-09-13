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
// Streams are attached directly rather than copied through scanners or buffers,
// preserving binary data, terminal behavior, and AWS diagnostic formatting.
func runAWS(path string, arguments, environ []string, stdin io.Reader, stdout, stderr io.Writer) int {
	command := exec.Command(path, arguments...)
	command.Env = environ
	command.Stdin = stdin
	command.Stdout = stdout
	command.Stderr = stderr

	forwarded := make(chan os.Signal, 1)
	signal.Notify(forwarded, forwardedSignals()...)
	if err := command.Start(); err != nil {
		signal.Stop(forwarded)
		fmt.Fprintln(stderr, "aws-clip: AWS CLI could not be started")
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
	fmt.Fprintln(stderr, "aws-clip: AWS CLI process wait failed")
	return exitCannotRun
}
