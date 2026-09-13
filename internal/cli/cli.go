// cli.go - Parse commands and coordinate AWS CLI-backed operations

// Package cli implements profile, session, workflow, and process controls.
// AWS service and credential behavior remains in the installed AWS CLI v2.
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

// Wrapper-owned failures use distinct statuses; AWS failures preserve native statuses
const (
	exitOK           = 0
	exitUsage        = 2
	exitPolicy       = 3
	exitConfirmation = 4
	exitIdentity     = 5
	exitCannotRun    = 126
	exitNotFound     = 127
	versionOutputMax = 64 * 1024
)

// Anchoring prevents unrelated executables from passing with embedded version text
var awsVersionPattern = regexp.MustCompile(`^(aws-cli/([0-9]+)(?:\.[0-9A-Za-z_-]+)+)(?:[[:space:]]|$)`)

// runtime isolates process boundaries without changing production stream inheritance
type runtime struct {
	stdin         io.Reader
	stdout        io.Writer
	stderr        io.Writer
	environ       []string
	interactive   bool
	stdinTerminal bool
	userConfigDir func() (string, error)
}

// Main runs one aws-clip command using args without the executable name.
// It attaches the supplied streams to child AWS CLI operations and returns wrapper
// statuses for local failures or the native AWS CLI status for child failures.
func Main(args []string, stdin *os.File, stdout, stderr *os.File) int {
	return run(args, runtime{
		stdin:         stdin,
		stdout:        stdout,
		stderr:        stderr,
		environ:       os.Environ(),
		interactive:   isTerminal(stdin) && isTerminal(stdout) && isTerminal(stderr),
		stdinTerminal: isTerminal(stdin),
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
		// Planning remains local and useful even when AWS CLI is unavailable
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
		// Workflow approval precedes AWS access; account approval awaits STS identity
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
		// One risky step guards the whole sequence before any operation starts
		if _, status := prepareProfileExecution(path, loaded.Settings, childEnvironment, rt, commands, request.approvalAccount); status != exitOK {
			return status
		}
		return runWorkflow(path, candidate, loaded.Settings, childEnvironment, rt)
	}
	if request.command == "exec" {
		if err := validateWorkflowCommand("exec", request.awsArguments); err != nil {
			fmt.Fprintf(rt.stderr, "aws-clip: %s\n", err)
			return exitUsage
		}
		path, err := resolveAWSBinary(loaded.Settings.AWSBinary)
		if err != nil {
			fmt.Fprintf(rt.stderr, "aws-clip: %s\n", printableLine(err.Error()))
			return exitNotFound
		}
		childEnvironment := effectiveEnvironment(rt.environ, loaded.Settings, rt.interactive)
		if request.preview {
			return writeExecutionPreview(path, request.awsArguments, loaded.Settings, childEnvironment, request.approvalAccount, request.yes, rt)
		}
		if _, err := inspectAWSVersion(path, childEnvironment); err != nil {
			fmt.Fprintf(rt.stderr, "aws-clip: %s\n", printableLine(err.Error()))
			return exitCannotRun
		}
		return runProfileExec(path, request.awsArguments, loaded.Settings, childEnvironment, request.approvalAccount, request.yes, rt)
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
	default:
		// Fail closed if parser and dispatch recognition ever diverge
		fmt.Fprintln(rt.stderr, "aws-clip: internal command validation error")
		return exitUsage
	}
}

// Discovery, planning, and unscoped diagnostics remain useful before account selection
func requiresExplicitProfile(command string) bool {
	switch command {
	case "login", "logout", "context", "exec", "run":
		return true
	default:
		return false
	}
}

// Set markers distinguish omitted options from explicitly empty values
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
	yes                bool
	preview            bool
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
			// Stop parsing at the trust boundary; every remaining value is literal AWS input
			result.awsArguments = append([]string(nil), args[index+1:]...)
			if len(result.awsArguments) == 0 {
				return request{}, errors.New("exec requires at least one AWS argument after --")
			}
			return result, nil
		}
		if strings.HasPrefix(argument, "-") {
			// Reject unknown options before they can shift the remaining parse
			name, inlineValue, hasInlineValue := strings.Cut(argument, "=")
			if !recognizedOption(name) {
				return request{}, errors.New("unknown wrapper option")
			}
			if name == "--yes" || name == "--preview" {
				if hasInlineValue {
					return request{}, fmt.Errorf("%s does not accept a value", name)
				}
				if name == "--yes" {
					result.yes = true
				} else {
					result.preview = true
				}
				continue
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
	if result.command != "exec" && (result.yes || result.preview) {
		return request{}, errors.New("--yes and --preview are valid only with exec")
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
	case "--config", "--aws-binary", "--profile", "--region", "--retry-mode", "--max-attempts", "--connect-timeout", "--read-timeout", "--approve", "--approve-account", "--format", "--yes", "--preview":
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
		// Avoid reflecting a possibly sensitive argument value into diagnostics
		return 0, fmt.Errorf("%s requires an integer", name)
	}
	return parsed, nil
}

// awsInfo excludes raw executable output from doctor diagnostics
type awsInfo struct {
	path    string
	version string
}

var (
	errAWSV1             = errors.New("AWS CLI v1 is not supported")
	errUnverifiedVersion = errors.New("AWS CLI version could not be verified")
)

// A relative resolved path is returned only when absolute conversion fails
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

// Accept only a leading AWS CLI v2 token from bounded combined output
func inspectAWSVersion(path string, environ []string) (awsInfo, error) {
	var output bytes.Buffer
	captured := &limitedWriter{writer: &output, remaining: versionOutputMax}
	command := exec.Command(path, "--version")
	command.Env = environ
	// One comparable writer lets os/exec serialize stdout and stderr writes safely
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

// limitedWriter discards overflow while reporting it consumed to bound memory without blocking
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

// Strip wrapper controls while preserving AWS credential-provider variables verbatim
func effectiveEnvironment(base []string, settings Settings, interactive bool) []string {
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

// Case-insensitive replacement matches Windows environment lookup semantics
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

// Omit unset timeouts so AWS CLI retains authority for its defaults
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

// Escape OS-derived values to preserve one diagnostic fact per line
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
	fmt.Fprintf(output, "command_policy: %d allow rules; %d deny rules; %d profile, %d region, and %d account constraints\n",
		len(loaded.Settings.CommandPolicy.Allow), len(loaded.Settings.CommandPolicy.Deny), len(loaded.Settings.CommandPolicy.AllowedProfiles),
		len(loaded.Settings.CommandPolicy.AllowedRegions), len(loaded.Settings.CommandPolicy.AllowedAccountIDs))
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

// Preserve record boundaries for OS-derived values outside configuration validation
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
  aws-clip [wrapper options] exec [--preview] [--yes] [--approve-account ID] -- <aws arguments...>
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
  --preview                  Explain a redacted exec decision without running AWS CLI
  --yes                      Approve a mutating, unknown, or sensitive exec command
  --approve-account ID       Bind guarded execution to the verified account
  --approve all-sso-sessions Confirm the global effect of AWS SSO logout

Profiles, login, logout, context, exec, and doctor delegate configuration,
authentication, credentials, and service calls to AWS CLI v2. Exec requires an
explicit profile, classifies the command, applies configured target policy,
and confirms mutating or unknown operations. Account-constrained execution
also verifies STS identity. Plan and run retain policy-controlled sequences for
operations that need named approval, fail-fast behavior, and step visibility.
The -- separator is mandatory for exec, and every following value remains a
literal AWS argument.
`
