// cli.go - Parse commands and coordinate AWS CLI-backed operations
// Package cli implements aws-clip's profile lifecycle, identity guards,
// workflows, command-line, and process boundaries. AWS service and credential
// behavior deliberately remain in the installed AWS CLI v2.
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
	exitPolicy       = 3
	exitCannotRun    = 126
	exitNotFound     = 127
	versionOutputMax = 64 * 1024
)

var awsVersionPattern = regexp.MustCompile(`^(aws-cli/([0-9]+)(?:\.[0-9A-Za-z_-]+)+)(?:[[:space:]]|$)`)

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
		fmt.Fprintf(rt.stderr, "aws-clip: %s\n\n%s", printableLine(err.Error()), usageText)
		return exitUsage
	}
	if request.help {
		io.WriteString(rt.stdout, usageText)
		return exitOK
	}

	loaded, err := resolveSettings(request.flags, rt.environ, rt.userConfigDir)
	if err != nil {
		fmt.Fprintf(rt.stderr, "aws-clip: configuration error: %s\n", printableLine(err.Error()))
		return exitUsage
	}
	if requiresExplicitProfile(request.command) && loaded.Settings.Profile == nil {
		fmt.Fprintln(rt.stderr, "aws-clip: an explicit profile is required; use --profile, AWS_CLIP_PROFILE, or profile in the configuration file")
		return exitUsage
	}
	if request.command == "plan" || request.command == "run" {
		candidate, err := readWorkflow(request.workflowPath, loaded.Settings.WorkflowPolicy.MaxSteps)
		if err != nil {
			fmt.Fprintf(rt.stderr, "aws-clip: workflow error: %s\n", printableLine(err.Error()))
			return exitUsage
		}
		plan := buildWorkflowPlan(candidate, loaded.Settings)
		if request.command == "plan" {
			if request.format == "json" {
				if err := writeWorkflowPlanJSON(rt.stdout, plan); err != nil {
					fmt.Fprintln(rt.stderr, "aws-clip: could not write workflow plan")
					return exitCannotRun
				}
			} else {
				writeWorkflowPlanText(rt.stdout, plan)
			}
			if !plan.Allowed {
				return exitPolicy
			}
			return exitOK
		}
		if !plan.Allowed {
			writeWorkflowPlanText(rt.stderr, plan)
			fmt.Fprintln(rt.stderr, "aws-clip: workflow blocked; update workflow_policy only after reviewing the denied operations")
			return exitPolicy
		}
		if request.approval != candidate.Name {
			fmt.Fprintf(rt.stderr, "aws-clip: run requires --approve %q to match the workflow name\n", printableLine(candidate.Name))
			return exitUsage
		}

		path, err := resolveAWSBinary(loaded.Settings.AWSBinary)
		if err != nil {
			fmt.Fprintf(rt.stderr, "aws-clip: %s\n", printableLine(err.Error()))
			return exitNotFound
		}
		childEnvironment := effectiveEnvironment(rt.environ, loaded.Settings, rt.interactive)
		if _, err := inspectAWSVersion(path, childEnvironment); err != nil {
			fmt.Fprintf(rt.stderr, "aws-clip: %s\n", printableLine(err.Error()))
			return exitCannotRun
		}
		commands := make([]executionOperation, 0, len(candidate.Steps))
		for _, step := range candidate.Steps {
			commands = append(commands, classifyExecutionCommand(step.Command))
		}
		if _, status := prepareProfileExecution(path, loaded.Settings, childEnvironment, rt, commands, request.approvalAccount); status != exitOK {
			return status
		}
		return runWorkflow(path, candidate, loaded.Settings, childEnvironment, rt)
	}

	path, err := resolveAWSBinary(loaded.Settings.AWSBinary)
	if err != nil {
		fmt.Fprintf(rt.stderr, "aws-clip: %s\n", printableLine(err.Error()))
		return exitNotFound
	}

	childEnvironment := effectiveEnvironment(rt.environ, loaded.Settings, rt.interactive)
	info, err := inspectAWSVersion(path, childEnvironment)
	if err != nil {
		fmt.Fprintf(rt.stderr, "aws-clip: %s\n", printableLine(err.Error()))
		if errors.Is(err, errAWSV1) || errors.Is(err, errUnverifiedVersion) {
			return exitCannotRun
		}
		return exitCannotRun
	}

	switch request.command {
	case "profiles":
		return runProfiles(path, loaded.Settings, childEnvironment, request.format, rt)
	case "login":
		return runLogin(path, loaded.Settings, childEnvironment, rt)
	case "logout":
		return runLogout(path, loaded.Settings, childEnvironment, request.approval, rt)
	case "context":
		return runContext(path, loaded.Settings, childEnvironment, request.format, rt)
	case "doctor":
		return runDoctor(path, info, loaded, childEnvironment, rt)
	case "exec":
		return runProfileExec(path, request.awsArguments, loaded.Settings, childEnvironment, request.approvalAccount, rt)
	default:
		// parseArguments owns command validation. Keep this guard so a future
		// parser change fails closed instead of accidentally executing AWS.
		fmt.Fprintln(rt.stderr, "aws-clip: internal command validation error")
		return exitUsage
	}
}

// requiresExplicitProfile identifies commands whose value depends on proving
// one named profile's identity. Discovery, planning, and an unscoped doctor
// remain useful before an operator has selected a profile.
func requiresExplicitProfile(command string) bool {
	switch command {
	case "login", "logout", "context", "exec", "run":
		return true
	default:
		return false
	}
}

type request struct {
	command            string
	flags              overrides
	awsArguments       []string
	workflowPath       string
	approval           string
	format             string
	approvalAccount    string
	approvalSet        bool
	approvalAccountSet bool
	formatSet          bool
	help               bool
}

func parseArguments(args []string) (request, error) {
	var result request
	for index := 0; index < len(args); index++ {
		argument := args[index]

		if argument == "--help" || argument == "-h" || (argument == "help" && result.command == "") {
			result.help = true
			return result, nil
		}
		if isCommand(argument) {
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
			if result.approvalSet || result.formatSet {
				return request{}, errors.New("--approve and --format are not valid with exec")
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
			switch name {
			case "--approve":
				result.approval = value
				result.approvalSet = true
			case "--format":
				result.format = value
				result.formatSet = true
			case "--approve-account":
				result.approvalAccount = value
				result.approvalAccountSet = true
			default:
				if err := setOption(&result.flags, name, value); err != nil {
					return request{}, err
				}
			}
			continue
		}
		if result.command == "" {
			return request{}, errors.New("expected profiles, login, logout, context, exec, doctor, plan, or run")
		}
		if result.command == "plan" || result.command == "run" {
			if result.workflowPath != "" {
				return request{}, errors.New("plan and run accept exactly one workflow file")
			}
			result.workflowPath = argument
			continue
		}
		return request{}, errors.New("wrapper options must precede the -- separator")
	}

	if result.command == "" {
		return request{}, errors.New("expected profiles, login, logout, context, exec, doctor, plan, or run")
	}
	if result.command == "exec" {
		return request{}, errors.New("exec requires the -- separator")
	}
	if (result.command == "plan" || result.command == "run") && result.workflowPath == "" {
		return request{}, fmt.Errorf("%s requires a workflow file", result.command)
	}
	if result.workflowPath != "" && !isPrintableSingleLine(result.workflowPath) {
		return request{}, errors.New("workflow file path must be printable and single-line")
	}
	if result.command != "run" && result.command != "logout" && result.approvalSet {
		return request{}, errors.New("--approve is valid only with run or logout")
	}
	if result.command != "run" && result.command != "exec" && result.approvalAccountSet {
		return request{}, errors.New("--approve-account is valid only with exec or run")
	}
	if result.command == "plan" || result.command == "profiles" || result.command == "context" {
		if !result.formatSet {
			result.format = "text"
		}
		if result.format != "text" && result.format != "json" {
			return request{}, errors.New("--format must be text or json")
		}
	} else if result.formatSet {
		return request{}, errors.New("--format is valid only with plan, profiles, or context")
	}
	return result, nil
}

// isCommand centralizes public command recognition so parsing and usage errors
// cannot drift as the profile/session surface evolves.
func isCommand(value string) bool {
	switch value {
	case "profiles", "login", "logout", "context", "exec", "doctor", "plan", "run":
		return true
	default:
		return false
	}
}

func recognizedOption(name string) bool {
	switch name {
	case "--config", "--aws-binary", "--profile", "--region", "--retry-mode", "--max-attempts", "--connect-timeout", "--read-timeout", "--approve", "--approve-account", "--format":
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
	captured := &limitedWriter{writer: &output, remaining: versionOutputMax}
	command := exec.Command(path, "--version")
	command.Env = environ
	// Use the same comparable writer for both streams. os/exec then serializes
	// calls to Write, avoiding a data race in bytes.Buffer while retaining one
	// combined bound for unexpectedly noisy or misconfigured executables.
	command.Stdout = captured
	command.Stderr = captured
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

	fmt.Fprintln(output, "aws_cli: ok")
	fmt.Fprintf(output, "aws_binary: %s\n", printableLine(info.path))
	fmt.Fprintf(output, "aws_version: %s\n", printableLine(info.version))
	fmt.Fprintf(output, "config_file: %s (%s)\n", printableLine(loaded.ConfigPath), configState)
	fmt.Fprintf(output, "profile: %s\n", printableLine(displayOptionalString(loaded.Settings.Profile)))
	fmt.Fprintf(output, "region: %s\n", printableLine(displayOptionalString(loaded.Settings.Region)))
	fmt.Fprintf(output, "retry_mode: %s\n", printableLine(displayOptionalString(loaded.Settings.RetryMode)))
	fmt.Fprintf(output, "max_attempts: %s\n", displayOptionalInt(loaded.Settings.MaxAttempts))
	fmt.Fprintf(output, "connect_timeout_seconds: %s\n", displayOptionalInt(loaded.Settings.ConnectTimeout))
	fmt.Fprintf(output, "read_timeout_seconds: %s\n", displayOptionalInt(loaded.Settings.ReadTimeout))
	fmt.Fprintf(output, "workflow_policy: read-oriented default; %d allow rules; %d deny rules; max %d steps\n",
		len(loaded.Settings.WorkflowPolicy.Allow), len(loaded.Settings.WorkflowPolicy.Deny), loaded.Settings.WorkflowPolicy.MaxSteps)
	fmt.Fprintf(output, "protected_profiles: %d\n", len(loaded.Settings.ProtectedProfiles))
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

// printableLine keeps diagnostic records structurally trustworthy even when a
// path obtained from the operating system contains bytes that configuration
// validation never saw (for example, an unusual current working directory).
// Valid configured values are already printable and remain unchanged.
func printableLine(value string) string {
	if isPrintableSingleLine(value) {
		return value
	}
	quoted := strconv.QuoteToGraphic(value)
	return quoted[1 : len(quoted)-1]
}

const usageText = `Usage:
  aws-clip [wrapper options] profiles [--format text|json]
  aws-clip [wrapper options] login
  aws-clip [wrapper options] logout [--approve all-sso-sessions]
  aws-clip [wrapper options] context [--format text|json]
  aws-clip [wrapper options] exec [--approve-account ID] -- <aws arguments...>
  aws-clip [wrapper options] doctor
  aws-clip [wrapper options] plan [--format text|json] <workflow.json>
  aws-clip [wrapper options] run --approve NAME [--approve-account ID] <workflow.json>

Wrapper options:
  --config PATH             Override the user configuration file
  --aws-binary PATH         Select the AWS CLI v2 executable
  --profile NAME            Set the AWS CLI profile
  --region REGION           Set the AWS Region
  --retry-mode MODE         Set legacy, standard, or adaptive retries
  --max-attempts NUMBER     Set total AWS request attempts
  --connect-timeout SECONDS Set the socket connection timeout (0 disables)
  --read-timeout SECONDS    Set the socket read timeout (0 disables)

Output and workflow options:
  --format text|json         Select text or stable JSON output
  --approve NAME             Confirm the exact workflow name for run

Safety options:
  --approve-account ID       Confirm the verified account for guarded execution
  --approve all-sso-sessions Confirm the global effect of AWS SSO logout

Profiles, login, logout, context, exec, and doctor delegate configuration,
authentication, credentials, and service calls to AWS CLI v2. Exec requires an
explicit profile, verifies its STS identity, and applies account guards. Plan
and run retain policy-controlled sequences for operations that need review,
named approval, fail-fast behavior, and step visibility. The -- separator is
mandatory for exec, and every following value remains a literal AWS argument.
`
