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

const configFileName = "config.json"

// Keep default workflow reviews and subprocess counts practical
const defaultMaxWorkflowSteps = 20

// WorkflowPolicy controls which declarative workflow operations may run.
// Read-oriented operations are allowed by default, Deny overrides Allow, and
// stronger account guards still apply.
type WorkflowPolicy struct {
	// Allow lists non-read operations permitted after stronger guards pass.
	Allow []string
	// Deny lists operations blocked even when an allow rule matches.
	Deny []string
	// MaxSteps limits workflow process count and review size.
	MaxSteps int
}

// CommandPolicy limits direct exec targets independently of confirmation.
// Deny rules take precedence, and each non-empty allowlist must match.
type CommandPolicy struct {
	// Allow restricts execution to matching service-operation identities when set.
	Allow []string
	// Deny blocks matching service-operation identities even when Allow matches.
	Deny []string
	// AllowedProfiles restricts selected profile names by exact match.
	AllowedProfiles []string
	// AllowedRegions restricts resolved Regions by exact match.
	AllowedRegions []string
	// AllowedAccountIDs restricts the live STS account by exact match.
	AllowedAccountIDs []string
}

type workflowPolicyFile struct {
	Allow    []string `json:"allow"`
	Deny     []string `json:"deny"`
	MaxSteps *int     `json:"max_steps"`
}

type commandPolicyFile struct {
	Allow             []string `json:"allow"`
	Deny              []string `json:"deny"`
	AllowedProfiles   []string `json:"allowed_profiles"`
	AllowedRegions    []string `json:"allowed_regions"`
	AllowedAccountIDs []string `json:"allowed_account_ids"`
}

// Settings contains the fully resolved wrapper configuration.
// Nil optional AWS settings delegate the corresponding default to AWS CLI.
type Settings struct {
	// AWSBinary selects the AWS CLI v2 executable.
	AWSBinary string
	// Profile selects the AWS profile used by lifecycle and execution commands.
	Profile *string
	// Region overrides AWS profile and ambient Region selection when present.
	Region *string
	// RetryMode selects the AWS CLI retry strategy.
	RetryMode *string
	// MaxAttempts sets the total AWS CLI request-attempt count.
	MaxAttempts *int
	// ConnectTimeout sets the AWS CLI socket connection timeout in seconds.
	ConnectTimeout *int
	// ReadTimeout sets the AWS CLI socket read timeout in seconds.
	ReadTimeout *int
	// WorkflowPolicy controls reviewed command sequences.
	WorkflowPolicy WorkflowPolicy
	// CommandPolicy constrains direct exec targets before confirmation.
	CommandPolicy CommandPolicy
	// ProtectedProfiles binds high-risk profile names to expected AWS accounts.
	// It is file-only so ambient or one-off settings cannot weaken the guard.
	ProtectedProfiles map[string]string
}

// Pointer fields preserve omission through precedence resolution
type fileSettings struct {
	AWSBinary         *string             `json:"aws_binary"`
	Profile           *string             `json:"profile"`
	Region            *string             `json:"region"`
	RetryMode         *string             `json:"retry_mode"`
	MaxAttempts       *int                `json:"max_attempts"`
	ConnectTimeout    *int                `json:"connect_timeout_seconds"`
	ReadTimeout       *int                `json:"read_timeout_seconds"`
	WorkflowPolicy    *workflowPolicyFile `json:"workflow_policy"`
	CommandPolicy     *commandPolicyFile  `json:"command_policy"`
	ProtectedProfiles map[string]string   `json:"protected_profiles"`
}

// ConfigPath selects the file before its remaining overrides can be resolved
type overrides struct {
	fileSettings
	ConfigPath *string
}

type loadedSettings struct {
	Settings   Settings
	ConfigPath string
	ConfigRead bool
}

// Apply defaults, file, environment, and flags in ascending precedence
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

	// Policy and account bindings are file-only; later layers cannot weaken them
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

// An explicitly selected missing file is an error; the platform default is optional
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

// Default files are optional; explicit files and unknown JSON fields fail
func readConfig(path string, required bool) (fileSettings, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && !required {
			return fileSettings{}, false, nil
		}
		return fileSettings{}, false, fmt.Errorf("read configuration file %q: %w", path, err)
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
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

func setStringFromEnvironment(environ []string, name string, target **string) {
	if value, ok := lookupEnvironment(environ, name); ok {
		valueCopy := value
		*target = &valueCopy
	}
}

func intFromEnvironment(environ []string, name string) (*int, error) {
	value, ok := lookupEnvironment(environ, name)
	if !ok {
		return nil, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		// Name only the setting because environment values may contain sensitive data
		return nil, fmt.Errorf("%s must be an integer", name)
	}
	return &parsed, nil
}

// Last exact-name entry matches process semantics and preserves case sensitivity
func lookupEnvironment(environ []string, name string) (string, bool) {
	for i := len(environ) - 1; i >= 0; i-- {
		key, value, found := strings.Cut(environ[i], "=")
		if found && key == name {
			return value, true
		}
	}
	return "", false
}

// Copy mutable values so callers cannot mutate decoded configuration indirectly
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
		// Replace the complete policy rather than merge independent layers
		target.WorkflowPolicy = WorkflowPolicy{
			Allow:    append([]string(nil), layer.WorkflowPolicy.Allow...),
			Deny:     append([]string(nil), layer.WorkflowPolicy.Deny...),
			MaxSteps: defaultMaxWorkflowSteps,
		}
		if layer.WorkflowPolicy.MaxSteps != nil {
			target.WorkflowPolicy.MaxSteps = *layer.WorkflowPolicy.MaxSteps
		}
	}
	if layer.CommandPolicy != nil {
		target.CommandPolicy = CommandPolicy{
			Allow:             append([]string(nil), layer.CommandPolicy.Allow...),
			Deny:              append([]string(nil), layer.CommandPolicy.Deny...),
			AllowedProfiles:   append([]string(nil), layer.CommandPolicy.AllowedProfiles...),
			AllowedRegions:    append([]string(nil), layer.CommandPolicy.AllowedRegions...),
			AllowedAccountIDs: append([]string(nil), layer.CommandPolicy.AllowedAccountIDs...),
		}
	}
	if layer.ProtectedProfiles != nil {
		target.ProtectedProfiles = make(map[string]string, len(layer.ProtectedProfiles))
		for profile, accountID := range layer.ProtectedProfiles {
			target.ProtectedProfiles[profile] = accountID
		}
	}
}

func cloneString(value *string) *string {
	copy := *value
	return &copy
}

func cloneInt(value *int) *int {
	copy := *value
	return &copy
}

// Validate only the effective state so overridden lower values cannot fail resolution
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
	if len(settings.CommandPolicy.Allow) > 100 || len(settings.CommandPolicy.Deny) > 100 {
		return errors.New("command policy supports at most 100 allow and 100 deny rules")
	}
	for _, rule := range append(append([]string(nil), settings.CommandPolicy.Allow...), settings.CommandPolicy.Deny...) {
		if err := validatePolicyRule(rule); err != nil {
			return err
		}
	}
	if len(settings.CommandPolicy.AllowedProfiles) > 100 || len(settings.CommandPolicy.AllowedRegions) > 100 || len(settings.CommandPolicy.AllowedAccountIDs) > 100 {
		return errors.New("command policy supports at most 100 allowed profiles, regions, and account IDs")
	}
	for _, profile := range settings.CommandPolicy.AllowedProfiles {
		if strings.TrimSpace(profile) == "" || !isPrintableSingleLine(profile) {
			return errors.New("command policy allowed profiles must be non-empty, printable, and single-line")
		}
	}
	for _, region := range settings.CommandPolicy.AllowedRegions {
		if strings.TrimSpace(region) == "" || !isPrintableSingleLine(region) {
			return errors.New("command policy allowed regions must be non-empty, printable, and single-line")
		}
	}
	for _, accountID := range settings.CommandPolicy.AllowedAccountIDs {
		if !isAWSAccountID(accountID) {
			return errors.New("command policy allowed account IDs must be 12 digits")
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

// Reject invalid UTF-8 and non-printing Unicode to keep diagnostics portable
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
