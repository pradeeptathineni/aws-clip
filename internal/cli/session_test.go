// session_test.go - Verify profile discovery, authentication, context, and guards
package cli

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestProfilesExposeSafeConfigurationMetadata(t *testing.T) {
	fake := makeProcessAlias(t, "fake-aws")
	configPath := writeConfig(t, `{"profile":"prod","protected_profiles":{"prod":"210987654321"}}`)
	profileConfig := `{
  "dev": {
    "region": "us-west-2",
    "sso_session": "company",
    "sso_account_id": "123456789012",
    "sso_role_name": "Developer"
  },
  "prod": {
    "region": "us-east-1",
    "login_session": "local-session",
    "aws_access_key_id": "must-not-appear"
  }
}`
	rt, stdout, stderr := testRuntime(t, false, nil,
		"FAKE_PROFILES=dev\nprod\n",
		"FAKE_CONFIG_JSON="+profileConfig,
	)

	status := run([]string{"--config", configPath, "--aws-binary", fake, "profiles", "--format", "json"}, rt)
	if status != exitOK || stderr.Len() != 0 {
		t.Fatalf("status = %d, stderr = %q", status, stderr.String())
	}
	var document profilesDocument
	if err := json.Unmarshal(stdout.Bytes(), &document); err != nil {
		t.Fatalf("profiles output is not JSON: %v; output = %q", err, stdout.String())
	}
	if document.SchemaVersion != 1 || len(document.Profiles) != 2 {
		t.Fatalf("profiles = %#v", document)
	}
	if document.Profiles[0].Authentication != "IAM Identity Center" || document.Profiles[0].ConfiguredRole == nil || *document.Profiles[0].ConfiguredRole != "Developer" {
		t.Fatalf("dev profile = %#v", document.Profiles[0])
	}
	if !document.Profiles[1].Selected || !document.Profiles[1].Protected || document.Profiles[1].ExpectedAccount == nil || *document.Profiles[1].ExpectedAccount != "210987654321" {
		t.Fatalf("prod profile = %#v", document.Profiles[1])
	}
	if strings.Contains(stdout.String(), "must-not-appear") || strings.Contains(stdout.String(), "local-session") {
		t.Fatalf("profile output exposed credential or session configuration: %q", stdout.String())
	}
}

func TestLoginUsesSourceProfileAuthenticationAndVerifiesIdentity(t *testing.T) {
	fake := makeProcessAlias(t, "fake-aws")
	callLog := filepath.Join(t.TempDir(), "calls.jsonl")
	failureMarker := filepath.Join(t.TempDir(), "identity-failed")
	profileConfig := `{
  "application": {
    "role_arn": "arn:aws:iam::123456789012:role/Application",
    "source_profile": "identity"
  },
  "identity": {
    "sso_session": "company"
  }
}`
	rt, stdout, stderr := testRuntime(t, false, nil,
		"FAKE_PROFILES=application\nidentity\n",
		"FAKE_CONFIG_JSON="+profileConfig,
		"FAKE_CALL_LOG="+callLog,
		"FAKE_IDENTITY_FAIL_ONCE="+failureMarker,
	)

	status := run([]string{"--aws-binary", fake, "--profile", "application", "login"}, rt)
	if status != exitOK {
		t.Fatalf("status = %d, stdout = %q, stderr = %q", status, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "assume role via IAM Identity Center") || !strings.Contains(stdout.String(), "new session established") {
		t.Fatalf("login summary = %q", stdout.String())
	}
	calls := readCallLog(t, callLog)
	if !containsCall(calls, []string{"sso", "login", "--profile", "identity"}) {
		t.Fatalf("calls = %#v, want source-profile SSO login", calls)
	}
	identityCalls := 0
	for _, call := range calls {
		if reflect.DeepEqual(call, fakeIdentityArguments()) {
			identityCalls++
		}
	}
	if identityCalls != 2 {
		t.Fatalf("identity calls = %d, want failed probe and successful verification; calls = %#v", identityCalls, calls)
	}
}

func TestLoginBootstrapsAndLogsOutLocalSession(t *testing.T) {
	fake := makeProcessAlias(t, "fake-aws")

	t.Run("bootstrap", func(t *testing.T) {
		callLog := filepath.Join(t.TempDir(), "calls.jsonl")
		failureMarker := filepath.Join(t.TempDir(), "identity-failed")
		rt, stdout, stderr := testRuntime(t, false, nil,
			"FAKE_PROFILES=local\n",
			"FAKE_CALL_LOG="+callLog,
			"FAKE_IDENTITY_FAIL_ONCE="+failureMarker,
		)
		status := run([]string{"--aws-binary", fake, "--profile", "local", "login"}, rt)
		if status != exitOK || !strings.Contains(stdout.String(), "method: AWS local login") {
			t.Fatalf("status = %d, stdout = %q, stderr = %q", status, stdout.String(), stderr.String())
		}
		calls := readCallLog(t, callLog)
		if !containsCall(calls, []string{"login", "help"}) || !containsCall(calls, []string{"login", "--profile", "local"}) {
			t.Fatalf("calls = %#v, want local-login capability check and login", calls)
		}
	})

	t.Run("logout", func(t *testing.T) {
		callLog := filepath.Join(t.TempDir(), "calls.jsonl")
		rt, stdout, stderr := testRuntime(t, false, nil,
			`FAKE_CONFIG_JSON={"local":{"login_session":"session"}}`,
			"FAKE_CALL_LOG="+callLog,
		)
		status := run([]string{"--aws-binary", fake, "--profile", "local", "logout"}, rt)
		if status != exitOK || stderr.Len() != 0 || !strings.Contains(stdout.String(), "profile local") {
			t.Fatalf("status = %d, stdout = %q, stderr = %q", status, stdout.String(), stderr.String())
		}
		if !containsCall(readCallLog(t, callLog), []string{"logout", "--profile", "local"}) {
			t.Fatal("local logout did not run")
		}
	})
}

func TestSSOLogoutRequiresGlobalEffectAcknowledgement(t *testing.T) {
	fake := makeProcessAlias(t, "fake-aws")
	profileConfig := `{"operations":{"sso_session":"company"}}`

	t.Run("blocked without acknowledgement", func(t *testing.T) {
		callLog := filepath.Join(t.TempDir(), "calls.jsonl")
		rt, stdout, stderr := testRuntime(t, false, nil,
			"FAKE_CONFIG_JSON="+profileConfig,
			"FAKE_CALL_LOG="+callLog,
		)
		status := run([]string{"--aws-binary", fake, "--profile", "operations", "logout"}, rt)
		if status != exitUsage || stdout.Len() != 0 || !strings.Contains(stderr.String(), "clears all cached SSO sessions") {
			t.Fatalf("status = %d, stdout = %q, stderr = %q", status, stdout.String(), stderr.String())
		}
		if containsCall(readCallLog(t, callLog), []string{"sso", "logout"}) {
			t.Fatal("SSO logout ran without acknowledgement")
		}
	})

	t.Run("approved global logout", func(t *testing.T) {
		callLog := filepath.Join(t.TempDir(), "calls.jsonl")
		rt, stdout, stderr := testRuntime(t, false, nil,
			"FAKE_CONFIG_JSON="+profileConfig,
			"FAKE_CALL_LOG="+callLog,
		)
		status := run([]string{"--aws-binary", fake, "--profile", "operations", "logout", "--approve", approveAllSSOSessions}, rt)
		if status != exitOK || stderr.Len() != 0 || !strings.Contains(stdout.String(), "sessions cleared") {
			t.Fatalf("status = %d, stdout = %q, stderr = %q", status, stdout.String(), stderr.String())
		}
		if !containsCall(readCallLog(t, callLog), []string{"sso", "logout"}) {
			t.Fatal("approved SSO logout did not run")
		}
	})
}

func TestContextVerifiesProtectedAccountAndReturnsStableJSON(t *testing.T) {
	fake := makeProcessAlias(t, "fake-aws")
	configPath := writeConfig(t, `{"profile":"prod","protected_profiles":{"prod":"123456789012"}}`)
	profileConfig := `{"prod":{"region":"us-east-1","sso_session":"company","sso_role_name":"Administrator"}}`
	rt, stdout, stderr := testRuntime(t, false, nil, "FAKE_CONFIG_JSON="+profileConfig)

	status := run([]string{"--config", configPath, "--aws-binary", fake, "context", "--format", "json"}, rt)
	if status != exitOK || stderr.Len() != 0 {
		t.Fatalf("status = %d, stderr = %q", status, stderr.String())
	}
	var context contextDocument
	if err := json.Unmarshal(stdout.Bytes(), &context); err != nil {
		t.Fatalf("context output is not JSON: %v; output = %q", err, stdout.String())
	}
	if context.SchemaVersion != 1 || context.Profile != "prod" || context.AccountID != "123456789012" ||
		context.Role == nil || *context.Role != "Operator" || context.Region == nil || *context.Region != "us-east-1" ||
		context.CredentialSource != "IAM Identity Center" || !context.Protected {
		t.Fatalf("context = %#v", context)
	}
}

func TestExecRequiresIdentityBoundApprovalForDestructiveOperations(t *testing.T) {
	fake := makeProcessAlias(t, "fake-aws")
	command := []string{"ec2", "terminate-instances", "--instance-ids", "i-example"}

	t.Run("preview blocks before operation", func(t *testing.T) {
		callLog := filepath.Join(t.TempDir(), "calls.jsonl")
		rt, stdout, stderr := testRuntime(t, false, nil, "FAKE_CALL_LOG="+callLog)
		arguments := append([]string{"--aws-binary", fake, "--profile", "operations", "exec", "--"}, command...)
		status := run(arguments, rt)
		if status != exitPolicy || stdout.Len() != 0 || !strings.Contains(stderr.String(), "--approve-account 123456789012") {
			t.Fatalf("status = %d, stdout = %q, stderr = %q", status, stdout.String(), stderr.String())
		}
		want := [][]string{{"--version"}, fakeIdentityArguments(), fakeProfileRegionArguments("operations")}
		if calls := readCallLog(t, callLog); !reflect.DeepEqual(calls, want) {
			t.Fatalf("calls = %#v, want identity preflight only", calls)
		}
	})

	t.Run("matching account approval permits operation", func(t *testing.T) {
		callLog := filepath.Join(t.TempDir(), "calls.jsonl")
		rt, _, stderr := testRuntime(t, false, nil, "FAKE_CALL_LOG="+callLog)
		arguments := []string{"--aws-binary", fake, "--profile", "operations", "exec", "--approve-account", "123456789012", "--"}
		arguments = append(arguments, command...)
		status := run(arguments, rt)
		if status != exitOK {
			t.Fatalf("status = %d, stderr = %q", status, stderr.String())
		}
		if !containsCall(readCallLog(t, callLog), command) {
			t.Fatal("approved destructive operation did not run")
		}
	})
}

func TestExecBlocksProfileOverridesAndCredentialEnvironment(t *testing.T) {
	fake := makeProcessAlias(t, "fake-aws")

	t.Run("missing explicit profile", func(t *testing.T) {
		callLog := filepath.Join(t.TempDir(), "calls.jsonl")
		rt, stdout, stderr := testRuntime(t, false, nil, "FAKE_CALL_LOG="+callLog)
		status := run([]string{"--aws-binary", fake, "exec", "--", "ec2", "describe-regions"}, rt)
		if status != exitUsage || stdout.Len() != 0 || !strings.Contains(stderr.String(), "explicit profile is required") {
			t.Fatalf("status = %d, stdout = %q, stderr = %q", status, stdout.String(), stderr.String())
		}
		if _, err := os.Stat(callLog); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("AWS CLI ran without an explicit profile: %v", err)
		}
	})

	t.Run("AWS profile argument", func(t *testing.T) {
		rt, stdout, stderr := testRuntime(t, false, nil)
		status := run([]string{"--aws-binary", fake, "--profile", "operations", "exec", "--", "ec2", "describe-regions", "--profile", "other"}, rt)
		if status != exitUsage || stdout.Len() != 0 || !strings.Contains(stderr.String(), "invalidate the verified profile context") {
			t.Fatalf("status = %d, stdout = %q, stderr = %q", status, stdout.String(), stderr.String())
		}
	})

	t.Run("ambient access key", func(t *testing.T) {
		callLog := filepath.Join(t.TempDir(), "calls.jsonl")
		secret := "must-not-appear"
		rt, stdout, stderr := testRuntime(t, false, nil,
			"FAKE_CALL_LOG="+callLog,
			"AWS_ACCESS_KEY_ID="+secret,
			"AWS_SECRET_ACCESS_KEY="+secret,
		)
		status := run([]string{"--aws-binary", fake, "--profile", "operations", "exec", "--", "ec2", "describe-regions"}, rt)
		if status != exitPolicy || stdout.Len() != 0 || !strings.Contains(stderr.String(), "AWS_ACCESS_KEY_ID") || strings.Contains(stderr.String(), secret) {
			t.Fatalf("status = %d, stdout = %q, stderr = %q", status, stdout.String(), stderr.String())
		}
		if calls := readCallLog(t, callLog); !reflect.DeepEqual(calls, [][]string{{"--version"}}) {
			t.Fatalf("calls = %#v, want no identity or operation request", calls)
		}
	})
}

func TestProtectedProfileRejectsAccountMismatch(t *testing.T) {
	fake := makeProcessAlias(t, "fake-aws")
	configPath := writeConfig(t, `{"profile":"prod","protected_profiles":{"prod":"210987654321"}}`)
	callLog := filepath.Join(t.TempDir(), "calls.jsonl")
	rt, stdout, stderr := testRuntime(t, false, nil, "FAKE_CALL_LOG="+callLog)

	status := run([]string{"--config", configPath, "--aws-binary", fake, "exec", "--", "ec2", "describe-regions"}, rt)
	if status != exitPolicy || stdout.Len() != 0 || !strings.Contains(stderr.String(), "account mismatch") {
		t.Fatalf("status = %d, stdout = %q, stderr = %q", status, stdout.String(), stderr.String())
	}
	if calls := readCallLog(t, callLog); !reflect.DeepEqual(calls, [][]string{{"--version"}, fakeIdentityArguments()}) {
		t.Fatalf("calls = %#v, want no service operation", calls)
	}
}

func TestProtectedProfileRequiresAccountApprovalForChanges(t *testing.T) {
	fake := makeProcessAlias(t, "fake-aws")
	configPath := writeConfig(t, `{"profile":"prod","protected_profiles":{"prod":"123456789012"}}`)
	callLog := filepath.Join(t.TempDir(), "calls.jsonl")
	rt, stdout, stderr := testRuntime(t, false, nil, "FAKE_CALL_LOG="+callLog)
	command := []string{"s3api", "put-object", "--bucket", "example", "--key", "release"}

	arguments := append([]string{"--config", configPath, "--aws-binary", fake, "exec", "--"}, command...)
	status := run(arguments, rt)
	if status != exitPolicy || stdout.Len() != 0 || !strings.Contains(stderr.String(), "change on protected profile") {
		t.Fatalf("status = %d, stdout = %q, stderr = %q", status, stdout.String(), stderr.String())
	}
	if containsCall(readCallLog(t, callLog), command) {
		t.Fatal("protected-profile change ran without account approval")
	}
}

func TestPotentiallyCostlyOperationRequiresAccountApproval(t *testing.T) {
	fake := makeProcessAlias(t, "fake-aws")
	callLog := filepath.Join(t.TempDir(), "calls.jsonl")
	rt, stdout, stderr := testRuntime(t, false, nil, "FAKE_CALL_LOG="+callLog)
	command := []string{"ec2", "run-instances", "--image-id", "ami-example"}

	arguments := append([]string{"--aws-binary", fake, "--profile", "development", "exec", "--"}, command...)
	status := run(arguments, rt)
	if status != exitPolicy || stdout.Len() != 0 || !strings.Contains(stderr.String(), "potentially costly operation") {
		t.Fatalf("status = %d, stdout = %q, stderr = %q", status, stdout.String(), stderr.String())
	}
	if containsCall(readCallLog(t, callLog), command) {
		t.Fatal("potentially costly operation ran without account approval")
	}
}

func TestProtectedProfileConfigurationIsValidated(t *testing.T) {
	tests := []struct {
		name   string
		config string
	}{
		{"empty profile", `{"protected_profiles":{"":"123456789012"}}`},
		{"invalid account", `{"protected_profiles":{"prod":"1234"}}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			configPath := writeConfig(t, test.config)
			rt, stdout, stderr := testRuntime(t, false, nil)
			status := run([]string{"--config", configPath, "doctor"}, rt)
			if status != exitUsage || stdout.Len() != 0 || !strings.Contains(stderr.String(), "protected profile") {
				t.Fatalf("status = %d, stdout = %q, stderr = %q", status, stdout.String(), stderr.String())
			}
		})
	}
}

func containsCall(calls [][]string, wanted []string) bool {
	for _, call := range calls {
		if reflect.DeepEqual(call, wanted) {
			return true
		}
	}
	return false
}
