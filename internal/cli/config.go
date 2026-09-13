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
)

const configFileName = "config.json"

// Settings is the fully resolved wrapper configuration. Optional AWS settings
// remain pointers so an absent value can be distinguished from an explicit
// zero timeout. This distinction is important: aws-clip must defer to AWS CLI
// configuration unless an operator deliberately supplies a wrapper setting.
type Settings struct {
	AWSBinary      string
	Profile        *string
	Region         *string
	RetryMode      *string
	MaxAttempts    *int
	ConnectTimeout *int
	ReadTimeout    *int
}

// fileSettings mirrors the public JSON schema. Pointer fields preserve whether
// a key was omitted, allowing environment variables and flags to override only
// values that actually exist in a lower-precedence layer.
type fileSettings struct {
	AWSBinary      *string `json:"aws_binary"`
	Profile        *string `json:"profile"`
	Region         *string `json:"region"`
	RetryMode      *string `json:"retry_mode"`
	MaxAttempts    *int    `json:"max_attempts"`
	ConnectTimeout *int    `json:"connect_timeout_seconds"`
	ReadTimeout    *int    `json:"read_timeout_seconds"`
}

// overrides contains values explicitly supplied as wrapper command flags.
// ConfigPath is handled separately because it selects the file from which the
// rest of the settings are loaded.
type overrides struct {
	fileSettings
	ConfigPath *string
}

type loadedSettings struct {
	Settings   Settings
	ConfigPath string
	ConfigRead bool
}

func resolveSettings(flagValues overrides, environ []string, configDir func() (string, error)) (loadedSettings, error) {
	path, explicit, err := resolveConfigPath(flagValues.ConfigPath, environ, configDir)
	if err != nil {
		return loadedSettings{}, err
	}

	result := loadedSettings{
		Settings:   Settings{AWSBinary: "aws"},
		ConfigPath: path,
	}

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

func resolveConfigPath(flagPath *string, environ []string, configDir func() (string, error)) (path string, explicit bool, err error) {
	if flagPath != nil {
		if strings.TrimSpace(*flagPath) == "" {
			return "", true, errors.New("--config requires a non-empty path")
		}
		return *flagPath, true, nil
	}
	if value, ok := lookupEnvironment(environ, "AWS_CLIP_CONFIG_FILE"); ok {
		if strings.TrimSpace(value) == "" {
			return "", true, errors.New("AWS_CLIP_CONFIG_FILE requires a non-empty path")
		}
		return value, true, nil
	}

	dir, err := configDir()
	if err != nil {
		return "", false, fmt.Errorf("determine user configuration directory: %w", err)
	}
	return filepath.Join(dir, "aws-clip", configFileName), false, nil
}

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
		// Configuration errors name the setting but deliberately omit its value.
		// Arguments and environment values can contain sensitive operator data.
		return nil, fmt.Errorf("%s must be an integer", name)
	}
	return &parsed, nil
}

func lookupEnvironment(environ []string, name string) (string, bool) {
	for i := len(environ) - 1; i >= 0; i-- {
		key, value, found := strings.Cut(environ[i], "=")
		if found && key == name {
			return value, true
		}
	}
	return "", false
}

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
}

func cloneString(value *string) *string {
	copy := *value
	return &copy
}

func cloneInt(value *int) *int {
	copy := *value
	return &copy
}

func validateSettings(settings Settings) error {
	if strings.TrimSpace(settings.AWSBinary) == "" {
		return errors.New("AWS binary path must not be empty")
	}
	if settings.Profile != nil && strings.TrimSpace(*settings.Profile) == "" {
		return errors.New("profile must not be empty")
	}
	if settings.Region != nil && strings.TrimSpace(*settings.Region) == "" {
		return errors.New("region must not be empty")
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
	return nil
}
