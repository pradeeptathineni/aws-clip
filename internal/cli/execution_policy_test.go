// execution_policy_test.go - Verify direct command classification and safety gates

package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestReadOnlyExecSkipsConfirmationAndIdentityPreflight(t *testing.T) {
	fake := makeProcessAlias(t, "fake-aws")
	callLog := filepath.Join(t.TempDir(), "calls.jsonl")
	command := []string{"ec2", "describe-instances", "--output", "json"}
	rt, _, stderr := testRuntime(t, false, nil, "FAKE_CALL_LOG="+callLog)

	status := run(append([]string{"--aws-binary", fake, "--profile", "development", "--region", "us-east-1", "exec", "--"}, command...), rt)

	if status != exitOK || !strings.Contains(stderr.String(), "classification=read-only") {
		t.Fatalf("status = %d, stderr = %q", status, stderr.String())
	}
	if calls := readCallLog(t, callLog); !reflect.DeepEqual(calls, [][]string{{"--version"}, command}) {
		t.Fatalf("calls = %#v, want version and target only", calls)
	}
}

func TestExecRefusesKnownAndUnknownChangesWithoutConfirmation(t *testing.T) {
	fake := makeProcessAlias(t, "fake-aws")
	tests := []struct {
		name           string
		command        []string
		classification string
	}{
		{"known mutation", []string{"ec2", "terminate-instances", "--instance-ids", "i-example"}, "classification=mutating"},
		{"unknown operation", []string{"example", "future-operation", "--token", "hidden"}, "classification=unknown; treated as mutating"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			callLog := filepath.Join(t.TempDir(), "calls.jsonl")
			rt, stdout, stderr := testRuntime(t, false, nil, "FAKE_CALL_LOG="+callLog)
			status := run(append([]string{"--aws-binary", fake, "--profile", "development", "--region", "us-east-1", "exec", "--"}, test.command...), rt)

			if status != exitConfirmation || stdout.Len() != 0 || !strings.Contains(stderr.String(), test.classification) || !strings.Contains(stderr.String(), "--yes") {
				t.Fatalf("status = %d, stdout = %q, stderr = %q", status, stdout.String(), stderr.String())
			}
			if containsCall(readCallLog(t, callLog), test.command) {
				t.Fatal("unconfirmed target command ran")
			}
		})
	}
}

func TestExecRejectsMalformedCommandBeforeAWSInspection(t *testing.T) {
	fake := makeProcessAlias(t, "fake-aws")
	callLog := filepath.Join(t.TempDir(), "calls.jsonl")
	rt, stdout, stderr := testRuntime(t, false, nil, "FAKE_CALL_LOG="+callLog)

	status := run([]string{"--aws-binary", fake, "--profile", "development", "exec", "--", "EC2", "describe-instances"}, rt)

	if status != exitUsage || stdout.Len() != 0 || !strings.Contains(stderr.String(), "lowercase AWS service and operation") {
		t.Fatalf("status = %d, stdout = %q, stderr = %q", status, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(callLog); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("AWS CLI ran for malformed input: %v", err)
	}
}

func TestCommandPolicyDenyOverridesAllowAndYes(t *testing.T) {
	fake := makeProcessAlias(t, "fake-aws")
	configPath := writeConfig(t, `{
  "command_policy": {
    "allow": ["ec2:*"],
    "deny": ["ec2:terminate-*"],
    "allowed_profiles": ["operations"],
    "allowed_regions": ["us-east-1"]
  }
}`)
	callLog := filepath.Join(t.TempDir(), "calls.jsonl")
	command := []string{"ec2", "terminate-instances", "--instance-ids", "i-example"}
	rt, stdout, stderr := testRuntime(t, false, nil, "FAKE_CALL_LOG="+callLog)

	status := run(append([]string{"--config", configPath, "--aws-binary", fake, "--profile", "operations", "--region", "us-east-1", "exec", "--yes", "--"}, command...), rt)

	if status != exitPolicy || stdout.Len() != 0 || !strings.Contains(stderr.String(), "matched configured deny rule") {
		t.Fatalf("status = %d, stdout = %q, stderr = %q", status, stdout.String(), stderr.String())
	}
	if containsCall(readCallLog(t, callLog), command) {
		t.Fatal("denied target command ran")
	}
}

func TestCommandPolicyAllowlistsFailClosed(t *testing.T) {
	fake := makeProcessAlias(t, "fake-aws")
	command := []string{"ec2", "describe-regions"}
	tests := []struct {
		name      string
		config    string
		profile   string
		region    string
		wantError string
	}{
		{
			"command",
			`{"command_policy":{"allow":["s3api:list-*"]}}`,
			"operations",
			"us-east-1",
			"allow rule",
		},
		{
			"profile",
			`{"command_policy":{"allowed_profiles":["production"]}}`,
			"development",
			"us-east-1",
			"allowed_profiles",
		},
		{
			"Region",
			`{"command_policy":{"allowed_regions":["us-west-2"]}}`,
			"operations",
			"us-east-1",
			"allowed_regions",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			configPath := writeConfig(t, test.config)
			callLog := filepath.Join(t.TempDir(), "calls.jsonl")
			rt, stdout, stderr := testRuntime(t, false, nil, "FAKE_CALL_LOG="+callLog)
			status := run(append([]string{"--config", configPath, "--aws-binary", fake, "--profile", test.profile, "--region", test.region, "exec", "--"}, command...), rt)

			if status != exitPolicy || stdout.Len() != 0 || !strings.Contains(stderr.String(), test.wantError) {
				t.Fatalf("status = %d, stdout = %q, stderr = %q", status, stdout.String(), stderr.String())
			}
			if containsCall(readCallLog(t, callLog), command) {
				t.Fatal("target outside an allowlist ran")
			}
		})
	}
}

func TestInteractiveExecRequiresAffirmativeConfirmation(t *testing.T) {
	fake := makeProcessAlias(t, "fake-aws")
	command := []string{"secretsmanager", "put-secret-value", "--secret-id", "example", "--secret-string", "must-not-appear"}

	t.Run("cancelled", func(t *testing.T) {
		callLog := filepath.Join(t.TempDir(), "calls.jsonl")
		rt, stdout, stderr := testRuntime(t, true, strings.NewReader("no\n"), "FAKE_CALL_LOG="+callLog)
		status := run(append([]string{"--aws-binary", fake, "--profile", "development", "--region", "us-east-1", "exec", "--"}, command...), rt)
		if status != exitConfirmation || stdout.Len() != 0 || !strings.Contains(stderr.String(), "confirmation cancelled") {
			t.Fatalf("status = %d, stdout = %q, stderr = %q", status, stdout.String(), stderr.String())
		}
		if strings.Contains(stderr.String(), "must-not-appear") || containsCall(readCallLog(t, callLog), command) {
			t.Fatal("confirmation exposed a value or ran the target")
		}
	})

	t.Run("approved", func(t *testing.T) {
		input := []byte("yes\npayload")
		rt, stdout, stderr := testRuntime(t, true, bytes.NewReader(input), "FAKE_MODE=binary-streams")
		status := run(append([]string{"--aws-binary", fake, "--profile", "development", "--region", "us-east-1", "exec", "--"}, command...), rt)
		if status != exitOK {
			t.Fatalf("status = %d, stderr = %q", status, stderr.String())
		}
		wantPrefix := []byte("payload")
		if !bytes.HasPrefix(stdout.Bytes(), wantPrefix) {
			t.Fatalf("confirmation consumed child stdin: stdout = %v", stdout.Bytes())
		}
	})
}

func TestExecPreviewIsOfflineAndRedactsValues(t *testing.T) {
	fake := makeProcessAlias(t, "fake-aws")
	callLog := filepath.Join(t.TempDir(), "calls.jsonl")
	secret := "value-that-must-not-appear"
	rt, stdout, stderr := testRuntime(t, false, nil, "FAKE_CALL_LOG="+callLog)

	status := run([]string{
		"--aws-binary", fake,
		"--profile", "operations",
		"--region", "us-east-1",
		"exec", "--preview", "--",
		"secretsmanager", "put-secret-value",
		"--secret-id=example", "--secret-string", secret,
	}, rt)

	if status != exitOK || stderr.Len() != 0 {
		t.Fatalf("status = %d, stderr = %q", status, stderr.String())
	}
	for _, expected := range []string{"aws_binary:", "command: secretsmanager:put-secret-value", "classification: mutating", "profile: operations", "region: us-east-1", "options: --secret-id, --secret-string", "policy: allow", "confirmation: required"} {
		if !strings.Contains(stdout.String(), expected) {
			t.Fatalf("preview missing %q: %q", expected, stdout.String())
		}
	}
	if strings.Contains(stdout.String(), secret) || strings.Contains(stdout.String(), "example") {
		t.Fatalf("preview exposed an argument value: %q", stdout.String())
	}
	if _, err := os.Stat(callLog); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("preview invoked AWS CLI: %v", err)
	}
}

func TestCommandPolicyAccountAllowlistGuardsTarget(t *testing.T) {
	fake := makeProcessAlias(t, "fake-aws")
	command := []string{"ec2", "describe-regions"}

	t.Run("identity mismatch", func(t *testing.T) {
		configPath := writeConfig(t, `{"command_policy":{"allowed_account_ids":["210987654321"]}}`)
		callLog := filepath.Join(t.TempDir(), "calls.jsonl")
		rt, stdout, stderr := testRuntime(t, false, nil, "FAKE_CALL_LOG="+callLog)
		status := run(append([]string{"--config", configPath, "--aws-binary", fake, "--profile", "operations", "--region", "us-east-1", "exec", "--"}, command...), rt)
		if status != exitIdentity || stdout.Len() != 0 || !strings.Contains(stderr.String(), "identity mismatch") {
			t.Fatalf("status = %d, stdout = %q, stderr = %q", status, stdout.String(), stderr.String())
		}
		if containsCall(readCallLog(t, callLog), command) {
			t.Fatal("target ran after account mismatch")
		}
	})

	t.Run("preflight failure preserves AWS status", func(t *testing.T) {
		configPath := writeConfig(t, `{"command_policy":{"allowed_account_ids":["123456789012"]}}`)
		callLog := filepath.Join(t.TempDir(), "calls.jsonl")
		rt, stdout, stderr := testRuntime(t, false, nil,
			"FAKE_CALL_LOG="+callLog,
			"FAKE_IDENTITY_EXIT_CODE=41",
			"FAKE_IDENTITY_STDERR=identity diagnostic\n",
		)
		status := run(append([]string{"--config", configPath, "--aws-binary", fake, "--profile", "operations", "--region", "us-east-1", "exec", "--"}, command...), rt)
		if status != 41 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "identity diagnostic") || !strings.Contains(stderr.String(), "account preflight failed") {
			t.Fatalf("status = %d, stdout = %q, stderr = %q", status, stdout.String(), stderr.String())
		}
		if containsCall(readCallLog(t, callLog), command) {
			t.Fatal("target ran after preflight failure")
		}
	})

	t.Run("matching identity permits read", func(t *testing.T) {
		configPath := writeConfig(t, `{"command_policy":{"allowed_account_ids":["123456789012"]}}`)
		callLog := filepath.Join(t.TempDir(), "calls.jsonl")
		rt, _, stderr := testRuntime(t, false, nil, "FAKE_CALL_LOG="+callLog)
		status := run(append([]string{"--config", configPath, "--aws-binary", fake, "--profile", "operations", "--region", "us-east-1", "exec", "--"}, command...), rt)
		if status != exitOK {
			t.Fatalf("status = %d, stderr = %q", status, stderr.String())
		}
		want := [][]string{{"--version"}, fakeIdentityArguments(), command}
		if calls := readCallLog(t, callLog); !reflect.DeepEqual(calls, want) {
			t.Fatalf("calls = %#v, want identity preflight before target", calls)
		}
	})
}

func TestCommandPolicyConfigurationValidation(t *testing.T) {
	tests := []struct {
		name      string
		config    string
		wantError string
	}{
		{"invalid rule", `{"command_policy":{"deny":["EC2:*"]}}`, "lowercase letters"},
		{"invalid account", `{"command_policy":{"allowed_account_ids":["1234"]}}`, "12 digits"},
		{"unknown field", `{"command_policy":{"allowed_roles":["Admin"]}}`, "unknown field"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			configPath := writeConfig(t, test.config)
			rt, stdout, stderr := testRuntime(t, false, bytes.NewReader(nil))
			status := run([]string{"--config", configPath, "doctor"}, rt)
			if status != exitUsage || stdout.Len() != 0 || !strings.Contains(stderr.String(), test.wantError) {
				t.Fatalf("status = %d, stdout = %q, stderr = %q", status, stdout.String(), stderr.String())
			}
		})
	}
}
