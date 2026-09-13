// Package cli implements aws-clip's command-line boundary and process runner.
// AWS service behavior deliberately remains in the installed AWS CLI v2; this
// package only resolves configuration, applies explicit execution controls, and
// preserves the child process contract.
package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const (
	exitOK           = 0
	exitUsage        = 2
	exitCannotRun    = 126
	exitNotFound     = 127
	versionOutputMax = 64 * 1024
)

var awsVersionPattern = regexp.MustCompile(`(?:^|[[:space:]])(aws-cli/([0-9]+)(?:\.[0-9A-Za-z_-]+)*)`)

// runtime contains the operating-system boundaries used by the application.
// Keeping these values together makes configuration and TTY behavior testable
// without changing how production child processes inherit their streams.
type runtime struct {
	stdin         io.Reader
	stdout        io.Writer
	stderr        io.Writer
	environ       []string
	interactive   bool
	userConfigDir func() (string, error)
}

// Main runs one aws-clip command and returns the status that the entry point
// should expose to its caller. AWS exit statuses are returned unchanged.
func Main(args []string, stdin *os.File, stdout, stderr *os.File) int {
	return run(args, runtime{
		stdin:         stdin,
		stdout:        stdout,
		stderr:        stderr,
		environ:       os.Environ(),
		interactive:   isTerminal(stdin) && isTerminal(stdout) && isTerminal(stderr),
		userConfigDir: os.UserConfigDir,
	})
}

func run(args []string, rt runtime) int {
	request, err := parseArguments(args)
	if err != nil {
		fmt.Fprintf(rt.stderr, "aws-clip: %v\n\n%s", err, usageText)
		return exitUsage
	}
	if request.help {
		io.WriteString(rt.stdout, usageText)
		return exitOK
	}

	loaded, err := resolveSettings(request.flags, rt.environ, rt.userConfigDir)
	if err != nil {
		fmt.Fprintf(rt.stderr, "aws-clip: configuration error: %v\n", err)
		return exitUsage
	}

	path, err := resolveAWSBinary(loaded.Settings.AWSBinary)
	if err != nil {
		fmt.Fprintf(rt.stderr, "aws-clip: %v\n", err)
		return exitNotFound
	}

	childEnvironment := effectiveEnvironment(rt.environ, loaded.Settings, rt.interactive)
	info, err := inspectAWSVersion(path, childEnvironment)
	if err != nil {
		fmt.Fprintf(rt.stderr, "aws-clip: %v\n", err)
		if errors.Is(err, errAWSV1) || errors.Is(err, errUnverifiedVersion) {
			return exitCannotRun
		}
		return exitCannotRun
	}

	switch request.command {
	case "doctor":
		writeDoctor(rt.stdout, info, loaded, rt.interactive)
		return exitOK
	case "exec":
		awsArguments := effectiveArguments(request.awsArguments, loaded.Settings)
		return runAWS(path, awsArguments, childEnvironment, rt.stdin, rt.stdout, rt.stderr)
	default:
		// parseArguments owns command validation. Keep this guard so a future
		// parser change fails closed instead of accidentally executing AWS.
		fmt.Fprintln(rt.stderr, "aws-clip: internal command validation error")
		return exitUsage
	}
}

type request struct {
	command      string
	flags        overrides
	awsArguments []string
	help         bool
}

func parseArguments(args []string) (request, error) {
	var result request
	for index := 0; index < len(args); index++ {
		argument := args[index]

		if argument == "--help" || argument == "-h" || argument == "help" {
			result.help = true
			return result, nil
		}
		if argument == "exec" || argument == "doctor" {
			if result.command != "" {
				return request{}, errors.New("exactly one command is required")
			}
			result.command = argument
			continue
		}
		if argument == "--" {
			if result.command != "exec" {
				return request{}, errors.New("the -- separator is valid only after exec")
			}
			result.awsArguments = append([]string(nil), args[index+1:]...)
			if len(result.awsArguments) == 0 {
				return request{}, errors.New("exec requires at least one AWS argument after --")
			}
			return result, nil
		}
		if strings.HasPrefix(argument, "-") {
			name, inlineValue, hasInlineValue := strings.Cut(argument, "=")
			if !recognizedOption(name) {
				return request{}, errors.New("unknown wrapper option")
			}
			value := inlineValue
			if !hasInlineValue {
				index++
				if index >= len(args) {
					return request{}, fmt.Errorf("%s requires a value", name)
				}
				value = args[index]
			}
			if err := setOption(&result.flags, name, value); err != nil {
				return request{}, err
			}
			continue
		}
		if result.command == "" {
			return request{}, errors.New("expected exec or doctor")
		}
		return request{}, errors.New("wrapper options must precede the -- separator")
	}

	if result.command == "" {
		return request{}, errors.New("expected exec or doctor")
	}
	if result.command == "exec" {
		return request{}, errors.New("exec requires the -- separator")
	}
	return result, nil
}

func recognizedOption(name string) bool {
	switch name {
	case "--config", "--aws-binary", "--profile", "--region", "--retry-mode", "--max-attempts", "--connect-timeout", "--read-timeout":
		return true
	default:
		return false
	}
}

func setOption(target *overrides, name, value string) error {
	valueCopy := value
	switch name {
	case "--config":
		target.ConfigPath = &valueCopy
	case "--aws-binary":
		target.AWSBinary = &valueCopy
	case "--profile":
		target.Profile = &valueCopy
	case "--region":
		target.Region = &valueCopy
	case "--retry-mode":
		target.RetryMode = &valueCopy
	case "--max-attempts":
		parsed, err := parseFlagInteger(name, value)
		if err != nil {
			return err
		}
		target.MaxAttempts = &parsed
	case "--connect-timeout":
		parsed, err := parseFlagInteger(name, value)
		if err != nil {
			return err
		}
		target.ConnectTimeout = &parsed
	case "--read-timeout":
		parsed, err := parseFlagInteger(name, value)
		if err != nil {
			return err
		}
		target.ReadTimeout = &parsed
	}
	return nil
}

func parseFlagInteger(name, value string) (int, error) {
	parsed, err := strconv.Atoi(value)
	if err != nil {
		// Avoid reflecting a possibly sensitive argument value into diagnostics.
		return 0, fmt.Errorf("%s requires an integer", name)
	}
	return parsed, nil
}

type awsInfo struct {
	path    string
	version string
}

var (
	errAWSV1             = errors.New("AWS CLI v1 is not supported")
	errUnverifiedVersion = errors.New("AWS CLI version could not be verified")
)

func resolveAWSBinary(configured string) (string, error) {
	path, err := exec.LookPath(configured)
	if err != nil {
		return "", fmt.Errorf("AWS CLI executable not found; install AWS CLI v2 or set --aws-binary, AWS_CLIP_AWS_BINARY, or aws_binary in the configuration file")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return path, nil
	}
	return absolute, nil
}

func inspectAWSVersion(path string, environ []string) (awsInfo, error) {
	var output bytes.Buffer
	command := exec.Command(path, "--version")
	command.Env = environ
	command.Stdout = io.MultiWriter(&limitedWriter{writer: &output, remaining: versionOutputMax})
	command.Stderr = io.MultiWriter(&limitedWriter{writer: &output, remaining: versionOutputMax})
	if err := command.Run(); err != nil {
		return awsInfo{}, fmt.Errorf("AWS CLI version check failed; confirm the configured executable can run: %w", err)
	}

	match := awsVersionPattern.FindSubmatch(output.Bytes())
	if match == nil {
		return awsInfo{}, fmt.Errorf("%w; expected output beginning with aws-cli/2", errUnverifiedVersion)
	}
	if string(match[2]) != "2" {
		return awsInfo{}, fmt.Errorf("%w; install AWS CLI v2 and update the configured binary", errAWSV1)
	}
	return awsInfo{path: path, version: string(match[1])}, nil
}

// limitedWriter accepts every byte while retaining only a bounded prefix. The
// version subprocess therefore cannot grow wrapper memory without limit, and it
// cannot block because a diagnostic exceeded the retained capacity.
type limitedWriter struct {
	writer    io.Writer
	remaining int
}

func (writer *limitedWriter) Write(data []byte) (int, error) {
	originalLength := len(data)
	if writer.remaining > 0 {
		toWrite := data
		if len(toWrite) > writer.remaining {
			toWrite = toWrite[:writer.remaining]
		}
		written, err := writer.writer.Write(toWrite)
		writer.remaining -= written
		if err != nil {
			return written, err
		}
	}
	return originalLength, nil
}

func effectiveEnvironment(base []string, settings Settings, interactive bool) []string {
	// Wrapper-only variables are not meaningful to AWS CLI and are removed from
	// its environment. Existing AWS credential-provider variables are preserved
	// verbatim and credential resolution remains entirely AWS CLI's concern.
	environment := make([]string, 0, len(base)+6)
	for _, entry := range base {
		key, _, found := strings.Cut(entry, "=")
		if found && strings.HasPrefix(key, "AWS_CLIP_") {
			continue
		}
		environment = append(environment, entry)
	}

	if settings.Profile != nil {
		environment = setEnvironment(environment, "AWS_PROFILE", *settings.Profile)
	}
	if settings.Region != nil {
		environment = setEnvironment(environment, "AWS_REGION", *settings.Region)
	}
	if settings.RetryMode != nil {
		environment = setEnvironment(environment, "AWS_RETRY_MODE", *settings.RetryMode)
	}
	if settings.MaxAttempts != nil {
		environment = setEnvironment(environment, "AWS_MAX_ATTEMPTS", strconv.Itoa(*settings.MaxAttempts))
	}
	if !interactive {
		environment = setEnvironment(environment, "AWS_PAGER", "")
		environment = setEnvironment(environment, "AWS_CLI_AUTO_PROMPT", "off")
	}
	return environment
}

func setEnvironment(environ []string, name, value string) []string {
	result := make([]string, 0, len(environ)+1)
	for _, entry := range environ {
		key, _, found := strings.Cut(entry, "=")
		if found && strings.EqualFold(key, name) {
			continue
		}
		result = append(result, entry)
	}
	return append(result, name+"="+value)
}

func effectiveArguments(original []string, settings Settings) []string {
	arguments := make([]string, 0, len(original)+4)
	if settings.ConnectTimeout != nil {
		arguments = append(arguments, "--cli-connect-timeout", strconv.Itoa(*settings.ConnectTimeout))
	}
	if settings.ReadTimeout != nil {
		arguments = append(arguments, "--cli-read-timeout", strconv.Itoa(*settings.ReadTimeout))
	}
	return append(arguments, original...)
}

func writeDoctor(output io.Writer, info awsInfo, loaded loadedSettings, interactive bool) {
	mode := "non-interactive"
	if interactive {
		mode = "interactive"
	}
	configState := "not found (optional)"
	if loaded.ConfigRead {
		configState = "loaded"
	}

	fmt.Fprintln(output, "status: ok")
	fmt.Fprintf(output, "aws_binary: %s\n", info.path)
	fmt.Fprintf(output, "aws_version: %s\n", info.version)
	fmt.Fprintf(output, "config_file: %s (%s)\n", loaded.ConfigPath, configState)
	fmt.Fprintf(output, "profile: %s\n", displayOptionalString(loaded.Settings.Profile))
	fmt.Fprintf(output, "region: %s\n", displayOptionalString(loaded.Settings.Region))
	fmt.Fprintf(output, "retry_mode: %s\n", displayOptionalString(loaded.Settings.RetryMode))
	fmt.Fprintf(output, "max_attempts: %s\n", displayOptionalInt(loaded.Settings.MaxAttempts))
	fmt.Fprintf(output, "connect_timeout_seconds: %s\n", displayOptionalInt(loaded.Settings.ConnectTimeout))
	fmt.Fprintf(output, "read_timeout_seconds: %s\n", displayOptionalInt(loaded.Settings.ReadTimeout))
	fmt.Fprintf(output, "stream_mode: %s\n", mode)
}

func displayOptionalString(value *string) string {
	if value == nil {
		return "aws-cli default"
	}
	return *value
}

func displayOptionalInt(value *int) string {
	if value == nil {
		return "aws-cli default"
	}
	return strconv.Itoa(*value)
}

func isTerminal(file *os.File) bool {
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

const usageText = `Usage:
  aws-clip [wrapper options] exec [wrapper options] -- <aws arguments...>
  aws-clip [wrapper options] doctor

Wrapper options:
  --config PATH             Override the user configuration file
  --aws-binary PATH         Select the AWS CLI v2 executable
  --profile NAME            Set the AWS CLI profile
  --region REGION           Set the AWS Region
  --retry-mode MODE         Set legacy, standard, or adaptive retries
  --max-attempts NUMBER     Set total AWS request attempts
  --connect-timeout SECONDS Set the socket connection timeout (0 disables)
  --read-timeout SECONDS    Set the socket read timeout (0 disables)

The -- separator is mandatory for exec. Every argument after it belongs to
AWS CLI and is passed without shell parsing.
`
