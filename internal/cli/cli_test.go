package cli

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	gostdruntime "runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestMain also serves as a hermetic AWS CLI v2 and wrapper process. The tests
// execute this binary through filesystem aliases, which exercises real argv,
// streams, environment, signals, and exit statuses without requiring AWS or
// making a network request.
func TestMain(m *testing.M) {
	name := strings.TrimSuffix(filepath.Base(os.Args[0]), ".exe")
	switch name {
	case "fake-aws":
		fakeAWS()
		return
	case "fake-wrapper":
		os.Exit(Main(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
	}
	os.Exit(m.Run())
}

type observedEnvironment struct {
	Set   bool   `json:"set"`
	Value string `json:"value,omitempty"`
}

type observation struct {
	Arguments   []string                       `json:"arguments"`
	Environment map[string]observedEnvironment `json:"environment"`
}

func fakeAWS() {
	arguments := os.Args[1:]
	appendCallLog(arguments)
	if len(arguments) == 1 && arguments[0] == "--version" {
		version := os.Getenv("FAKE_AWS_VERSION")
		if version == "" {
			version = "aws-cli/2.17.0 Python/3.12.0 test/1.0"
		}
		fmt.Fprintln(os.Stdout, version)
		return
	}

	if path := os.Getenv("FAKE_OBSERVATION_PATH"); path != "" {
		environment := make(map[string]observedEnvironment)
		for _, name := range []string{
			"AWS_PAGER",
			"AWS_CLI_AUTO_PROMPT",
			"AWS_PROFILE",
			"AWS_REGION",
			"AWS_RETRY_MODE",
			"AWS_MAX_ATTEMPTS",
			"AWS_ACCESS_KEY_ID",
			"AWS_SECRET_ACCESS_KEY",
		} {
			value, set := os.LookupEnv(name)
			environment[name] = observedEnvironment{Set: set, Value: value}
		}
		data, err := json.Marshal(observation{Arguments: arguments, Environment: environment})
		if err != nil || os.WriteFile(path, data, 0o600) != nil {
			os.Exit(120)
		}
	}

	switch os.Getenv("FAKE_MODE") {
	case "binary-streams":
		_, _ = io.Copy(os.Stdout, os.Stdin)
		_, _ = os.Stdout.Write([]byte{0x00, 0x01, '\n', 0xff})
		_, _ = os.Stderr.Write([]byte{0xfe, '\r', '\n', 0x00})
	case "wait-for-signal":
		fmt.Fprintln(os.Stdout, "ready")
		for {
			time.Sleep(time.Hour)
		}
	default:
		_, _ = io.WriteString(os.Stdout, os.Getenv("FAKE_STDOUT"))
		_, _ = io.WriteString(os.Stderr, os.Getenv("FAKE_STDERR"))
	}

	if value := os.Getenv("FAKE_EXIT_CODE"); value != "" {
		code, err := strconv.Atoi(value)
		if err != nil {
			os.Exit(121)
		}
		os.Exit(code)
	}
}

func appendCallLog(arguments []string) {
	path := os.Getenv("FAKE_CALL_LOG")
	if path == "" {
		return
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		os.Exit(122)
	}
	defer file.Close()
	data, err := json.Marshal(arguments)
	if err != nil {
		os.Exit(123)
	}
	_, _ = file.Write(append(data, '\n'))
}

func TestExecPassesArgumentsLiterallyAndReturnsAWSStatus(t *testing.T) {
	fake := makeProcessAlias(t, "fake-aws")
	observationPath := filepath.Join(t.TempDir(), "observation.json")
	callLog := filepath.Join(t.TempDir(), "calls.jsonl")
	sentinel := filepath.Join(t.TempDir(), "must-not-exist")
	arguments := []string{
		"s3api", "put-object",
		"--key", "space value",
		"; touch " + sentinel,
		"$(touch " + sentinel + ")",
		"*",
		`single'and"double`,
	}
	rt, stdout, stderr := testRuntime(t, false, nil,
		"FAKE_OBSERVATION_PATH="+observationPath,
		"FAKE_CALL_LOG="+callLog,
		"FAKE_STDOUT=aws output\n",
		"FAKE_STDERR=aws diagnostic\n",
		"FAKE_EXIT_CODE=37",
	)

	status := run(append([]string{"--aws-binary", fake, "exec", "--"}, arguments...), rt)
	if status != 37 {
		t.Fatalf("status = %d, want 37; stderr = %q", status, stderr.String())
	}
	if stdout.String() != "aws output\n" || stderr.String() != "aws diagnostic\n" {
		t.Fatalf("streams changed: stdout %q, stderr %q", stdout.String(), stderr.String())
	}
	if _, err := os.Stat(sentinel); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("metacharacter argument was evaluated by a shell")
	}

	observed := readObservation(t, observationPath)
	if !reflect.DeepEqual(observed.Arguments, arguments) {
		t.Fatalf("arguments = %#v, want %#v", observed.Arguments, arguments)
	}
	if calls := readCallLog(t, callLog); !reflect.DeepEqual(calls, [][]string{{"--version"}, arguments}) {
		t.Fatalf("process calls = %#v, want one version check and one AWS operation", calls)
	}
}

func TestExecPreservesBinaryStdinStdoutAndStderr(t *testing.T) {
	fake := makeProcessAlias(t, "fake-aws")
	input := []byte{0x00, 'i', 'n', '\n', 0xff}
	rt, stdout, stderr := testRuntime(t, false, bytes.NewReader(input), "FAKE_MODE=binary-streams")

	status := run([]string{"--aws-binary", fake, "exec", "--", "service", "operation"}, rt)
	if status != 0 {
		t.Fatalf("status = %d, want 0; stderr = %q", status, stderr.Bytes())
	}
	wantStdout := append(append([]byte(nil), input...), 0x00, 0x01, '\n', 0xff)
	if !bytes.Equal(stdout.Bytes(), wantStdout) {
		t.Fatalf("stdout bytes = %v, want %v", stdout.Bytes(), wantStdout)
	}
	if want := []byte{0xfe, '\r', '\n', 0x00}; !bytes.Equal(stderr.Bytes(), want) {
		t.Fatalf("stderr bytes = %v, want %v", stderr.Bytes(), want)
	}
}

func TestNonTTYDisablesPagerAndAutoPromptWithoutAddingOutput(t *testing.T) {
	fake := makeProcessAlias(t, "fake-aws")
	observationPath := filepath.Join(t.TempDir(), "observation.json")
	rt, stdout, stderr := testRuntime(t, false, nil,
		"AWS_PAGER=less --RAW-CONTROL-CHARS",
		"AWS_CLI_AUTO_PROMPT=on-partial",
		"FAKE_OBSERVATION_PATH="+observationPath,
		"FAKE_STDOUT=only child output\n",
	)

	status := run([]string{"--aws-binary", fake, "exec", "--", "sts", "get-caller-identity"}, rt)
	if status != 0 || stderr.Len() != 0 {
		t.Fatalf("status = %d, stderr = %q", status, stderr.String())
	}
	if stdout.String() != "only child output\n" {
		t.Fatalf("stdout = %q", stdout.String())
	}
	observed := readObservation(t, observationPath)
	assertEnvironment(t, observed, "AWS_PAGER", true, "")
	assertEnvironment(t, observed, "AWS_CLI_AUTO_PROMPT", true, "off")
}

func TestProcessWithNullStreamsDisablesPagerAndAutoPrompt(t *testing.T) {
	wrapper := makeProcessAlias(t, "fake-wrapper")
	fake := makeProcessAlias(t, "fake-aws")
	configPath := writeConfig(t, `{}`)
	observationPath := filepath.Join(t.TempDir(), "observation.json")

	null, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer null.Close()

	command := exec.Command(wrapper,
		"--config", configPath,
		"--aws-binary", fake,
		"exec", "--", "sts", "get-caller-identity",
	)
	command.Env = append(baseEnvironment(),
		"AWS_PAGER=operator-pager",
		"AWS_CLI_AUTO_PROMPT=on",
		"FAKE_OBSERVATION_PATH="+observationPath,
	)
	command.Stdin = null
	command.Stdout = null
	command.Stderr = null
	if err := command.Run(); err != nil {
		t.Fatalf("wrapper with null streams failed: %v", err)
	}

	observed := readObservation(t, observationPath)
	assertEnvironment(t, observed, "AWS_PAGER", true, "")
	assertEnvironment(t, observed, "AWS_CLI_AUTO_PROMPT", true, "off")
}

func TestTTYLeavesPagerAndAutoPromptUntouched(t *testing.T) {
	fake := makeProcessAlias(t, "fake-aws")
	observationPath := filepath.Join(t.TempDir(), "observation.json")
	rt, _, stderr := testRuntime(t, true, nil,
		"AWS_PAGER=operator-pager",
		"AWS_CLI_AUTO_PROMPT=on",
		"FAKE_OBSERVATION_PATH="+observationPath,
	)

	status := run([]string{"--aws-binary", fake, "exec", "--", "ec2", "describe-regions"}, rt)
	if status != 0 {
		t.Fatalf("status = %d, stderr = %q", status, stderr.String())
	}
	observed := readObservation(t, observationPath)
	assertEnvironment(t, observed, "AWS_PAGER", true, "operator-pager")
	assertEnvironment(t, observed, "AWS_CLI_AUTO_PROMPT", true, "on")
}

func TestConfigurationPrecedenceAndAWSDeferral(t *testing.T) {
	fake := makeProcessAlias(t, "fake-aws")
	tests := []struct {
		name             string
		configBinary     string
		environment      []string
		flags            []string
		wantProfile      observedEnvironment
		wantRegion       observedEnvironment
		wantRetry        observedEnvironment
		wantAttempts     observedEnvironment
		wantArgumentLead []string
	}{
		{
			name:             "config file supplies values",
			configBinary:     fake,
			wantProfile:      observedEnvironment{Set: true, Value: "file-profile"},
			wantRegion:       observedEnvironment{Set: true, Value: "file-region"},
			wantRetry:        observedEnvironment{Set: true, Value: "legacy"},
			wantAttempts:     observedEnvironment{Set: true, Value: "3"},
			wantArgumentLead: []string{"--cli-connect-timeout", "11", "--cli-read-timeout", "12"},
		},
		{
			name:         "environment overrides config file",
			configBinary: filepath.Join(t.TempDir(), "wrong-aws"),
			environment: []string{
				"AWS_CLIP_AWS_BINARY=" + fake,
				"AWS_CLIP_PROFILE=environment-profile",
				"AWS_CLIP_REGION=environment-region",
				"AWS_CLIP_RETRY_MODE=standard",
				"AWS_CLIP_MAX_ATTEMPTS=4",
				"AWS_CLIP_CONNECT_TIMEOUT=21",
				"AWS_CLIP_READ_TIMEOUT=22",
			},
			wantProfile:      observedEnvironment{Set: true, Value: "environment-profile"},
			wantRegion:       observedEnvironment{Set: true, Value: "environment-region"},
			wantRetry:        observedEnvironment{Set: true, Value: "standard"},
			wantAttempts:     observedEnvironment{Set: true, Value: "4"},
			wantArgumentLead: []string{"--cli-connect-timeout", "21", "--cli-read-timeout", "22"},
		},
		{
			name:         "flags override environment",
			configBinary: filepath.Join(t.TempDir(), "wrong-aws"),
			environment: []string{
				"AWS_CLIP_AWS_BINARY=" + filepath.Join(t.TempDir(), "also-wrong-aws"),
				"AWS_CLIP_PROFILE=environment-profile",
				"AWS_CLIP_REGION=environment-region",
				"AWS_CLIP_RETRY_MODE=legacy",
				"AWS_CLIP_MAX_ATTEMPTS=5",
				"AWS_CLIP_CONNECT_TIMEOUT=31",
				"AWS_CLIP_READ_TIMEOUT=32",
			},
			flags: []string{
				"--aws-binary", fake,
				"--profile", "flag-profile",
				"--region", "flag-region",
				"--retry-mode", "adaptive",
				"--max-attempts", "6",
				"--connect-timeout", "41",
				"--read-timeout", "42",
			},
			wantProfile:      observedEnvironment{Set: true, Value: "flag-profile"},
			wantRegion:       observedEnvironment{Set: true, Value: "flag-region"},
			wantRetry:        observedEnvironment{Set: true, Value: "adaptive"},
			wantAttempts:     observedEnvironment{Set: true, Value: "6"},
			wantArgumentLead: []string{"--cli-connect-timeout", "41", "--cli-read-timeout", "42"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			configPath := writeConfig(t, fmt.Sprintf(`{
  "aws_binary": %q,
  "profile": "file-profile",
  "region": "file-region",
  "retry_mode": "legacy",
  "max_attempts": 3,
  "connect_timeout_seconds": 11,
  "read_timeout_seconds": 12
}`, test.configBinary))
			observationPath := filepath.Join(t.TempDir(), "observation.json")
			extraEnvironment := append([]string{
				"AWS_CLIP_CONFIG_FILE=" + configPath,
				"FAKE_OBSERVATION_PATH=" + observationPath,
			}, test.environment...)
			rt, _, stderr := testRuntime(t, false, nil, extraEnvironment...)
			arguments := append([]string(nil), test.flags...)
			arguments = append(arguments, "exec", "--", "sts", "get-caller-identity")

			if status := run(arguments, rt); status != 0 {
				t.Fatalf("status = %d; stderr = %q", status, stderr.String())
			}
			observed := readObservation(t, observationPath)
			assertEnvironment(t, observed, "AWS_PROFILE", test.wantProfile.Set, test.wantProfile.Value)
			assertEnvironment(t, observed, "AWS_REGION", test.wantRegion.Set, test.wantRegion.Value)
			assertEnvironment(t, observed, "AWS_RETRY_MODE", test.wantRetry.Set, test.wantRetry.Value)
			assertEnvironment(t, observed, "AWS_MAX_ATTEMPTS", test.wantAttempts.Set, test.wantAttempts.Value)
			wantArguments := append(append([]string(nil), test.wantArgumentLead...), "sts", "get-caller-identity")
			if !reflect.DeepEqual(observed.Arguments, wantArguments) {
				t.Fatalf("arguments = %#v, want %#v", observed.Arguments, wantArguments)
			}
		})
	}

	t.Run("unset values defer to AWS CLI", func(t *testing.T) {
		configPath := writeConfig(t, `{}`)
		observationPath := filepath.Join(t.TempDir(), "observation.json")
		rt, _, stderr := testRuntime(t, false, nil,
			"AWS_CLIP_CONFIG_FILE="+configPath,
			"FAKE_OBSERVATION_PATH="+observationPath,
		)
		if status := run([]string{"--aws-binary", fake, "exec", "--", "sts", "get-caller-identity"}, rt); status != 0 {
			t.Fatalf("status = %d; stderr = %q", status, stderr.String())
		}
		observed := readObservation(t, observationPath)
		for _, name := range []string{"AWS_PROFILE", "AWS_REGION", "AWS_RETRY_MODE", "AWS_MAX_ATTEMPTS"} {
			assertEnvironment(t, observed, name, false, "")
		}
		if want := []string{"sts", "get-caller-identity"}; !reflect.DeepEqual(observed.Arguments, want) {
			t.Fatalf("arguments = %#v, want %#v", observed.Arguments, want)
		}
	})
}

func TestDoctorChecksLocallyAndDoesNotExposeCredentials(t *testing.T) {
	fake := makeProcessAlias(t, "fake-aws")
	callLog := filepath.Join(t.TempDir(), "calls.jsonl")
	secret := "credential-value-that-must-not-appear"
	rt, stdout, stderr := testRuntime(t, false, nil,
		"FAKE_CALL_LOG="+callLog,
		"AWS_ACCESS_KEY_ID=access-key-that-must-not-appear",
		"AWS_SECRET_ACCESS_KEY="+secret,
	)

	status := run([]string{"--aws-binary", fake, "--profile", "operations", "--region", "us-east-1", "doctor"}, rt)
	if status != 0 || stderr.Len() != 0 {
		t.Fatalf("status = %d, stderr = %q", status, stderr.String())
	}
	if !strings.Contains(stdout.String(), "aws_version: aws-cli/2.17.0") ||
		!strings.Contains(stdout.String(), "profile: operations") ||
		!strings.Contains(stdout.String(), "region: us-east-1") {
		t.Fatalf("doctor output lacks effective context: %q", stdout.String())
	}
	if strings.Contains(stdout.String(), secret) || strings.Contains(stderr.String(), secret) || strings.Contains(stdout.String(), "access-key-that-must-not-appear") {
		t.Fatalf("doctor exposed credential material")
	}
	calls := readCallLog(t, callLog)
	if want := [][]string{{"--version"}}; !reflect.DeepEqual(calls, want) {
		t.Fatalf("doctor calls = %#v, want only a version check", calls)
	}
}

func TestConfiguredControlCharactersCannotInjectDiagnostics(t *testing.T) {
	fake := makeProcessAlias(t, "fake-aws")
	tests := []struct {
		name        string
		arguments   []string
		environment []string
		wantError   string
	}{
		{
			name:      "profile flag",
			arguments: []string{"--aws-binary", fake, "--profile", "operations\nstatus: forged", "doctor"},
			wantError: "profile must be printable and single-line",
		},
		{
			name:        "region environment",
			arguments:   []string{"--aws-binary", fake, "doctor"},
			environment: []string{"AWS_CLIP_REGION=us-east-1\x1b[2Jstatus: forged"},
			wantError:   "region must be printable and single-line",
		},
		{
			name:        "binary environment",
			arguments:   []string{"doctor"},
			environment: []string{"AWS_CLIP_AWS_BINARY=" + fake + "\rstatus: forged"},
			wantError:   "AWS binary path must be printable and single-line",
		},
		{
			name:        "configuration path environment",
			arguments:   []string{"doctor"},
			environment: []string{"AWS_CLIP_CONFIG_FILE=missing\nstatus: forged"},
			wantError:   "AWS_CLIP_CONFIG_FILE requires a printable single-line path",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rt, stdout, stderr := testRuntime(t, false, nil, test.environment...)
			status := run(test.arguments, rt)
			if status != exitUsage || stdout.Len() != 0 || !strings.Contains(stderr.String(), test.wantError) {
				t.Fatalf("status = %d, stdout = %q, stderr = %q", status, stdout.String(), stderr.String())
			}
			if strings.Contains(stderr.String(), "forged") || strings.Count(stderr.String(), "\n") != 1 {
				t.Fatalf("diagnostic included configured control text: %q", stderr.String())
			}
		})
	}
}

func TestDoctorEscapesUnsafeOSDerivedValues(t *testing.T) {
	var output bytes.Buffer
	writeDoctor(&output, awsInfo{
		path:    "/working\ndirectory/aws",
		version: "aws-cli/2.17.0",
	}, loadedSettings{
		Settings:   Settings{AWSBinary: "aws"},
		ConfigPath: "/config\x1b[2J/file",
	}, false)

	if strings.Contains(output.String(), "/working\ndirectory") || strings.Contains(output.String(), "\x1b") {
		t.Fatalf("doctor emitted raw control characters: %q", output.String())
	}
	if !strings.Contains(output.String(), `aws_binary: /working\ndirectory/aws`) ||
		!strings.Contains(output.String(), `config_file: /config\x1b[2J/file`) {
		t.Fatalf("doctor did not escape unsafe values: %q", output.String())
	}
}

func TestMissingAndV1AWSAreRejectedBeforeExecution(t *testing.T) {
	t.Run("missing binary", func(t *testing.T) {
		rt, stdout, stderr := testRuntime(t, false, nil)
		missing := filepath.Join(t.TempDir(), "missing-aws")
		status := run([]string{"--aws-binary", missing, "doctor"}, rt)
		if status != exitNotFound || stdout.Len() != 0 || !strings.Contains(stderr.String(), "install AWS CLI v2") {
			t.Fatalf("status = %d, stdout = %q, stderr = %q", status, stdout.String(), stderr.String())
		}
	})

	t.Run("v1 binary", func(t *testing.T) {
		fake := makeProcessAlias(t, "fake-aws")
		observationPath := filepath.Join(t.TempDir(), "operation.json")
		rt, stdout, stderr := testRuntime(t, false, nil,
			"FAKE_AWS_VERSION=aws-cli/1.32.0 Python/3.11.0 test/1.0",
			"FAKE_OBSERVATION_PATH="+observationPath,
		)
		status := run([]string{"--aws-binary", fake, "exec", "--", "sts", "get-caller-identity"}, rt)
		if status != exitCannotRun || stdout.Len() != 0 || !strings.Contains(stderr.String(), "AWS CLI v1") || !strings.Contains(stderr.String(), "install AWS CLI v2") {
			t.Fatalf("status = %d, stdout = %q, stderr = %q", status, stdout.String(), stderr.String())
		}
		if _, err := os.Stat(observationPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("AWS operation ran after v1 rejection")
		}
	})

	t.Run("version token does not begin output", func(t *testing.T) {
		fake := makeProcessAlias(t, "fake-aws")
		observationPath := filepath.Join(t.TempDir(), "operation.json")
		rt, stdout, stderr := testRuntime(t, false, nil,
			"FAKE_AWS_VERSION=unexpected prefix aws-cli/2.17.0 Python/3.12.0",
			"FAKE_OBSERVATION_PATH="+observationPath,
		)
		status := run([]string{"--aws-binary", fake, "exec", "--", "sts", "get-caller-identity"}, rt)
		if status != exitCannotRun || stdout.Len() != 0 || !strings.Contains(stderr.String(), "version could not be verified") {
			t.Fatalf("status = %d, stdout = %q, stderr = %q", status, stdout.String(), stderr.String())
		}
		if _, err := os.Stat(observationPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("AWS operation ran after malformed version output")
		}
	})
}

func TestExecForwardsInterruptAndReportsSignalStatus(t *testing.T) {
	if gostdruntime.GOOS == "windows" {
		t.Skip("Windows interrupt delivery does not use POSIX exit status 130")
	}
	wrapper := makeProcessAlias(t, "fake-wrapper")
	fake := makeProcessAlias(t, "fake-aws")
	configPath := writeConfig(t, `{}`)
	command := exec.Command(wrapper,
		"--config", configPath,
		"--aws-binary", fake,
		"exec", "--", "sts", "get-caller-identity",
	)
	command.Env = append(baseEnvironment(), "FAKE_MODE=wait-for-signal")
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}

	ready := make(chan string, 1)
	go func() {
		line, _ := bufio.NewReader(stdout).ReadString('\n')
		ready <- line
	}()
	select {
	case line := <-ready:
		if line != "ready\n" {
			_ = command.Process.Kill()
			t.Fatalf("unexpected readiness output %q; stderr = %q", line, stderr.String())
		}
	case <-time.After(5 * time.Second):
		_ = command.Process.Kill()
		t.Fatal("timed out waiting for child process")
	}

	if err := command.Process.Signal(os.Interrupt); err != nil {
		_ = command.Process.Kill()
		t.Fatal(err)
	}
	waited := make(chan error, 1)
	go func() { waited <- command.Wait() }()
	select {
	case err := <-waited:
		var exitError *exec.ExitError
		if !errors.As(err, &exitError) || exitError.ExitCode() != 130 {
			t.Fatalf("interrupt result = %v, want exit status 130; stderr = %q", err, stderr.String())
		}
	case <-time.After(5 * time.Second):
		_ = command.Process.Kill()
		t.Fatal("wrapper did not terminate after interrupt")
	}
}

func TestExecRequiresExplicitSeparator(t *testing.T) {
	rt, stdout, stderr := testRuntime(t, false, nil)
	status := run([]string{"exec", "sts", "get-caller-identity"}, rt)
	if status != exitUsage || stdout.Len() != 0 || !strings.Contains(stderr.String(), "-- separator") {
		t.Fatalf("status = %d, stdout = %q, stderr = %q", status, stdout.String(), stderr.String())
	}
}

func testRuntime(t *testing.T, interactive bool, stdin io.Reader, additionalEnvironment ...string) (runtime, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	if stdin == nil {
		stdin = bytes.NewReader(nil)
	}
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	configRoot := t.TempDir()
	environment := append(baseEnvironment(), additionalEnvironment...)
	return runtime{
		stdin:       stdin,
		stdout:      stdout,
		stderr:      stderr,
		environ:     environment,
		interactive: interactive,
		userConfigDir: func() (string, error) {
			return configRoot, nil
		},
	}, stdout, stderr
}

func baseEnvironment() []string {
	// Keep only process-launch essentials. In particular, omit host AWS settings
	// so tests for unset wrapper values cannot depend on a developer's machine.
	environment := []string{"PATH=" + os.Getenv("PATH")}
	for _, name := range []string{"TMPDIR", "TEMP", "TMP", "SYSTEMROOT"} {
		if value, ok := os.LookupEnv(name); ok {
			environment = append(environment, name+"="+value)
		}
	}
	return environment
}

func makeProcessAlias(t *testing.T, name string) string {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if gostdruntime.GOOS == "windows" {
		name += ".exe"
	}
	directory := filepath.Join(t.TempDir(), "path with spaces & metacharacters")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(directory, name)
	if err := os.Symlink(executable, target); err == nil {
		return target
	}

	// Some environments prohibit symlinks. Copying the already-built test
	// executable retains the same hermetic helper behavior.
	source, err := os.Open(executable)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	destination, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(destination, source); err != nil {
		_ = destination.Close()
		t.Fatal(err)
	}
	if err := destination.Close(); err != nil {
		t.Fatal(err)
	}
	return target
}

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), configFileName)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func readObservation(t *testing.T, path string) observation {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var observed observation
	if err := json.Unmarshal(data, &observed); err != nil {
		t.Fatal(err)
	}
	return observed
}

func assertEnvironment(t *testing.T, observed observation, name string, wantSet bool, wantValue string) {
	t.Helper()
	value := observed.Environment[name]
	if value.Set != wantSet || value.Value != wantValue {
		t.Fatalf("%s = %#v, want set=%t value=%q", name, value, wantSet, wantValue)
	}
}

func readCallLog(t *testing.T, path string) [][]string {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var calls [][]string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var call []string
		if err := json.Unmarshal(scanner.Bytes(), &call); err != nil {
			t.Fatal(err)
		}
		calls = append(calls, call)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return calls
}
