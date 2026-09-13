// config.go - Resolve aws-clip settings and validate local safety policy

package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Local configuration name under the platform user configuration directory
const configFileName = "config.json"

// Conservative workflow size used when policy does not set a lower or higher bound
const defaultMaxWorkflowSteps = 20

// WorkflowPolicy defines the local guardrails applied to declarative
// workflows
// Read-oriented AWS operations are allowed by default
// Allow adds deliberate exceptions and Deny adds organization-specific blocks
// Deny always wins when more than one rule matches
type WorkflowPolicy struct {
	// Allow names non-read operations permitted after all stronger guards pass
	Allow []string
	// Deny names operations that remain blocked even when another rule allows
	Deny []string
	// MaxSteps bounds workflow process count and review size
	MaxSteps int
}

// workflowPolicyFile preserves omission within the nested JSON policy object
type workflowPolicyFile struct {
	Allow    []string `json:"allow"`
	Deny     []string `json:"deny"`
	MaxSteps *int     `json:"max_steps"`
}

// Settings is the fully resolved wrapper configuration
// Optional AWS settings
// remain pointers so an absent value can be distinguished from an explicit
// zero timeout
// aws-clip defers to AWS CLI unless an operator supplies a wrapper setting
type Settings struct {
	// AWSBinary selects the AWS CLI v2 executable
	AWSBinary string
	// Profile is the explicit AWS profile used by lifecycle and execution commands
	Profile *string
	// Region overrides AWS profile and ambient Region selection when present
	Region *string
	// RetryMode delegates retry strategy to AWS CLI
	RetryMode *string
	// MaxAttempts delegates total request-attempt count to AWS CLI
	MaxAttempts *int
	// ConnectTimeout sets the AWS CLI socket connection timeout in seconds
	ConnectTimeout *int
	// ReadTimeout sets the AWS CLI socket read timeout in seconds
	ReadTimeout *int
	// WorkflowPolicy contains file-owned controls for reviewed sequences
	WorkflowPolicy WorkflowPolicy
	// ProtectedProfiles binds high-risk profile names to their expected AWS accounts
	// configuration-file-only to prevent ambient or one-off guard weakening
	ProtectedProfiles map[string]string
}

// fileSettings mirrors the public JSON schema
// Pointer fields preserve whether a key was omitted
// allows environment variables and flags to override only
// values that actually exist in a lower-precedence layer
type fileSettings struct {
	AWSBinary         *string             `json:"aws_binary"`
	Profile           *string             `json:"profile"`
	Region            *string             `json:"region"`
	RetryMode         *string             `json:"retry_mode"`
	MaxAttempts       *int                `json:"max_attempts"`
	ConnectTimeout    *int                `json:"connect_timeout_seconds"`
	ReadTimeout       *int                `json:"read_timeout_seconds"`
	WorkflowPolicy    *workflowPolicyFile `json:"workflow_policy"`
	ProtectedProfiles map[string]string   `json:"protected_profiles"`
}

// overrides contains values explicitly supplied as wrapper command flags
// ConfigPath is handled separately because it selects the file from which the
// rest of the settings are loaded
type overrides struct {
	fileSettings
	ConfigPath *string
}

// loadedSettings pairs resolved values with configuration discovery diagnostics
type loadedSettings struct {
	Settings   Settings
	ConfigPath string
	ConfigRead bool
}

// resolveSettings applies defaults, file, environment, and flags in ascending precedence
// configDir remains injectable so discovery failures and platform paths are testable
func resolveSettings(flagValues overrides, environ []string, configDir func() (string, error)) (loadedSettings, error) {
	path, explicit, err := resolveConfigPath(flagValues.ConfigPath, environ, configDir)
	if err != nil {
		return loadedSettings{}, err
	}

	result := loadedSettings{
		Settings: Settings{
			AWSBinary:      "aws",
			WorkflowPolicy: WorkflowPolicy{MaxSteps: defaultMaxWorkflowSteps},
		},
		ConfigPath: path,
	}

	// Apply independent layers in documented ascending precedence
	// policy and protected-profile settings exist only in the file layer
	fromFile, read, err := readConfig(path, explicit)
	if err != nil {
		return loadedSettings{}, err
	}
	result.ConfigRead = read
	applyLayer(&result.Settings, fromFile)

	fromEnvironment, err := environmentSettings(environ)
	if err != nil {
		return loadedSettings{}, err
	}
	applyLayer(&result.Settings, fromEnvironment)
	applyLayer(&result.Settings, flagValues.fileSettings)

	if err := validateSettings(result.Settings); err != nil {
		return loadedSettings{}, err
	}
	return result, nil
}

// resolveConfigPath selects flag, environment, then platform-default location
// explicit reports whether a missing file is an error rather than an optional default
func resolveConfigPath(flagPath *string, environ []string, configDir func() (string, error)) (path string, explicit bool, err error) {
	if flagPath != nil {
		if strings.TrimSpace(*flagPath) == "" {
			return "", true, errors.New("--config requires a non-empty path")
		}
		if !isPrintableSingleLine(*flagPath) {
			return "", true, errors.New("--config requires a printable single-line path")
		}
		return *flagPath, true, nil
	}
	if value, ok := lookupEnvironment(environ, "AWS_CLIP_CONFIG_FILE"); ok {
		if strings.TrimSpace(value) == "" {
			return "", true, errors.New("AWS_CLIP_CONFIG_FILE requires a non-empty path")
		}
		if !isPrintableSingleLine(value) {
			return "", true, errors.New("AWS_CLIP_CONFIG_FILE requires a printable single-line path")
		}
		return value, true, nil
	}

	dir, err := configDir()
	if err != nil {
		return "", false, fmt.Errorf("determine user configuration directory: %w", err)
	}
	path = filepath.Join(dir, "aws-clip", configFileName)
	if !isPrintableSingleLine(path) {
		return "", false, errors.New("user configuration path must be printable and single-line")
	}
	return path, false, nil
}

// readConfig decodes exactly one strict JSON object from path
// missing default files are optional while explicitly selected files are required
func readConfig(path string, required bool) (fileSettings, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && !required {
			return fileSettings{}, false, nil
		}
		return fileSettings{}, false, fmt.Errorf("read configuration file %q: %w", path, err)
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	// Strict decoding prevents misspelled safety controls from appearing effective
	decoder.DisallowUnknownFields()
	var settings fileSettings
	if err := decoder.Decode(&settings); err != nil {
		return fileSettings{}, false, fmt.Errorf("parse configuration file %q: %w", path, err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return fileSettings{}, false, fmt.Errorf("parse configuration file %q: expected one JSON object", path)
	}
	return settings, true, nil
}

// environmentSettings maps only AWS_CLIP variables into a precedence layer
// numeric parse errors identify the setting without echoing its value
func environmentSettings(environ []string) (fileSettings, error) {
	var settings fileSettings
	setStringFromEnvironment(environ, "AWS_CLIP_AWS_BINARY", &settings.AWSBinary)
	setStringFromEnvironment(environ, "AWS_CLIP_PROFILE", &settings.Profile)
	setStringFromEnvironment(environ, "AWS_CLIP_REGION", &settings.Region)
	setStringFromEnvironment(environ, "AWS_CLIP_RETRY_MODE", &settings.RetryMode)

	var err error
	if settings.MaxAttempts, err = intFromEnvironment(environ, "AWS_CLIP_MAX_ATTEMPTS"); err != nil {
		return fileSettings{}, err
	}
	if settings.ConnectTimeout, err = intFromEnvironment(environ, "AWS_CLIP_CONNECT_TIMEOUT"); err != nil {
		return fileSettings{}, err
	}
	if settings.ReadTimeout, err = intFromEnvironment(environ, "AWS_CLIP_READ_TIMEOUT"); err != nil {
		return fileSettings{}, err
	}
	return settings, nil
}

// setStringFromEnvironment preserves the distinction between unset and empty
func setStringFromEnvironment(environ []string, name string, target **string) {
	if value, ok := lookupEnvironment(environ, name); ok {
		valueCopy := value
		*target = &valueCopy
	}
}

// intFromEnvironment parses an optional integer without exposing invalid input
func intFromEnvironment(environ []string, name string) (*int, error) {
	value, ok := lookupEnvironment(environ, name)
	if !ok {
		return nil, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		// Configuration errors name the setting but deliberately omit its value
		// Arguments and environment values can contain sensitive operator data
		return nil, fmt.Errorf("%s must be an integer", name)
	}
	return &parsed, nil
}

// lookupEnvironment returns the last exact-name entry to match process semantics
// exact matching preserves case-sensitive AWS variable behavior on supported shells
func lookupEnvironment(environ []string, name string) (string, bool) {
	for i := len(environ) - 1; i >= 0; i-- {
		key, value, found := strings.Cut(environ[i], "=")
		if found && key == name {
			return value, true
		}
	}
	return "", false
}

// applyLayer copies present values over target without aliasing mutable slices or maps
// workflow policy and protected profiles remain file-owned because later layers omit them
func applyLayer(target *Settings, layer fileSettings) {
	if layer.AWSBinary != nil {
		target.AWSBinary = *layer.AWSBinary
	}
	if layer.Profile != nil {
		target.Profile = cloneString(layer.Profile)
	}
	if layer.Region != nil {
		target.Region = cloneString(layer.Region)
	}
	if layer.RetryMode != nil {
		target.RetryMode = cloneString(layer.RetryMode)
	}
	if layer.MaxAttempts != nil {
		target.MaxAttempts = cloneInt(layer.MaxAttempts)
	}
	if layer.ConnectTimeout != nil {
		target.ConnectTimeout = cloneInt(layer.ConnectTimeout)
	}
	if layer.ReadTimeout != nil {
		target.ReadTimeout = cloneInt(layer.ReadTimeout)
	}
	if layer.WorkflowPolicy != nil {
		// Replacing the complete policy avoids accidental merging across layers
		target.WorkflowPolicy = WorkflowPolicy{
			Allow:    append([]string(nil), layer.WorkflowPolicy.Allow...),
			Deny:     append([]string(nil), layer.WorkflowPolicy.Deny...),
			MaxSteps: defaultMaxWorkflowSteps,
		}
		if layer.WorkflowPolicy.MaxSteps != nil {
			target.WorkflowPolicy.MaxSteps = *layer.WorkflowPolicy.MaxSteps
		}
	}
	if layer.ProtectedProfiles != nil {
		// Copy account bindings so callers cannot mutate decoded configuration indirectly
		target.ProtectedProfiles = make(map[string]string, len(layer.ProtectedProfiles))
		for profile, accountID := range layer.ProtectedProfiles {
			target.ProtectedProfiles[profile] = accountID
		}
	}
}

// cloneString returns an independently owned optional value
func cloneString(value *string) *string {
	copy := *value
	return &copy
}

// cloneInt returns an independently owned optional value
func cloneInt(value *int) *int {
	copy := *value
	return &copy
}

// validateSettings enforces bounds and diagnostic-safe text after all layers merge
// validates the final effective state so overridden invalid lower values do not leak
func validateSettings(settings Settings) error {
	if strings.TrimSpace(settings.AWSBinary) == "" {
		return errors.New("AWS binary path must not be empty")
	}
	if !isPrintableSingleLine(settings.AWSBinary) {
		return errors.New("AWS binary path must be printable and single-line")
	}
	if settings.Profile != nil && strings.TrimSpace(*settings.Profile) == "" {
		return errors.New("profile must not be empty")
	}
	if settings.Profile != nil && !isPrintableSingleLine(*settings.Profile) {
		return errors.New("profile must be printable and single-line")
	}
	if settings.Region != nil && strings.TrimSpace(*settings.Region) == "" {
		return errors.New("region must not be empty")
	}
	if settings.Region != nil && !isPrintableSingleLine(*settings.Region) {
		return errors.New("region must be printable and single-line")
	}
	if settings.RetryMode != nil {
		switch *settings.RetryMode {
		case "legacy", "standard", "adaptive":
		default:
			return errors.New("retry mode must be legacy, standard, or adaptive")
		}
	}
	if settings.MaxAttempts != nil && *settings.MaxAttempts < 1 {
		return errors.New("maximum attempts must be at least 1")
	}
	if settings.ConnectTimeout != nil && *settings.ConnectTimeout < 0 {
		return errors.New("connection timeout must be 0 or greater")
	}
	if settings.ReadTimeout != nil && *settings.ReadTimeout < 0 {
		return errors.New("read timeout must be 0 or greater")
	}
	if settings.WorkflowPolicy.MaxSteps < 1 || settings.WorkflowPolicy.MaxSteps > 100 {
		return errors.New("workflow policy max_steps must be between 1 and 100")
	}
	if len(settings.WorkflowPolicy.Allow) > 100 || len(settings.WorkflowPolicy.Deny) > 100 {
		return errors.New("workflow policy supports at most 100 allow and 100 deny rules")
	}
	for _, rule := range append(append([]string(nil), settings.WorkflowPolicy.Allow...), settings.WorkflowPolicy.Deny...) {
		if err := validatePolicyRule(rule); err != nil {
			return err
		}
	}
	for profile, accountID := range settings.ProtectedProfiles {
		if strings.TrimSpace(profile) == "" || !isPrintableSingleLine(profile) {
			return errors.New("protected profile names must be non-empty, printable, and single-line")
		}
		if !isAWSAccountID(accountID) {
			return fmt.Errorf("protected profile %q must use a 12-digit AWS account ID", profile)
		}
	}
	return nil
}

// isAWSAccountID validates the fixed-width decimal identifier returned by AWS
// STS and used by account guards
// rejects ARNs, aliases, and malformed account-bound approval tokens
func isAWSAccountID(value string) bool {
	if len(value) != 12 {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

// isPrintableSingleLine defines the text accepted for values that may appear in
// diagnostics
// Besides ASCII control characters, unicode.IsPrint excludes line
// and paragraph separators, formatting controls, and other runes that can alter
// terminal presentation
// Invalid UTF-8 is rejected so output stays portable
func isPrintableSingleLine(value string) bool {
	if !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if !unicode.IsPrint(character) {
			return false
		}
	}
	return true
}
