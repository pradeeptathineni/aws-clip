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

func TestPlanValidatesAndEvaluatesPolicyWithoutAWS(t *testing.T) {
	workflowPath := writeWorkflow(t, `{
  "schema_version": 1,
  "name": "inventory",
  "description": "Review the active identity and compute fleet",
  "steps": [
    {
      "name": "identity",
      "description": "Confirm the caller before reading resources",
      "command": ["sts", "get-caller-identity"]
    },
    {
      "name": "instances",
      "command": ["ec2", "describe-instances", "--output", "json"]
    }
  ]
}`)
	rt, stdout, stderr := testRuntime(t, false, nil)

	status := run([]string{
		"--aws-binary", filepath.Join(t.TempDir(), "missing-aws"),
		"--profile", "operations",
		"--region", "us-east-1",
		"--retry-mode", "standard",
		"--max-attempts", "4",
		"plan", "--format", "json", workflowPath,
	}, rt)
	if status != exitOK || stderr.Len() != 0 {
		t.Fatalf("status = %d, stderr = %q", status, stderr.String())
	}
	var plan workflowPlan
	if err := json.Unmarshal(stdout.Bytes(), &plan); err != nil {
		t.Fatalf("plan is not valid JSON: %v; output = %q", err, stdout.String())
	}
	if !plan.Allowed || plan.Name != "inventory" || len(plan.Steps) != 2 {
		t.Fatalf("plan = %#v", plan)
	}
	if plan.Context.Profile == nil || *plan.Context.Profile != "operations" ||
		plan.Context.Region == nil || *plan.Context.Region != "us-east-1" ||
		plan.Context.RetryMode == nil || *plan.Context.RetryMode != "standard" ||
		plan.Context.MaxAttempts == nil || *plan.Context.MaxAttempts != 4 {
		t.Fatalf("plan context = %#v", plan.Context)
	}
	if plan.Context.ConnectTimeoutSeconds != nil || plan.Context.ReadTimeoutSeconds != nil {
		t.Fatalf("unset context settings must remain null: %#v", plan.Context)
	}
	if plan.Steps[1].Command != "ec2:describe-instances" || plan.Steps[1].AdditionalArguments != 2 || plan.Steps[1].Decision != "allow" {
		t.Fatalf("second step = %#v", plan.Steps[1])
	}
	if strings.Contains(stdout.String(), "--output") {
		t.Fatalf("plan exposed command argument values: %q", stdout.String())
	}
}

func TestWorkflowPolicyRequiresExplicitWriteAllowanceAndDenyWins(t *testing.T) {
	workflowPath := writeWorkflow(t, `{
  "schema_version": 1,
  "name": "release",
  "steps": [{"name": "deploy", "command": ["cloudformation", "deploy", "--stack-name", "example"]}]
}`)

	t.Run("write blocked by default", func(t *testing.T) {
		rt, stdout, stderr := testRuntime(t, false, nil)
		status := run([]string{"plan", workflowPath}, rt)
		if status != exitPolicy || stderr.Len() != 0 || !strings.Contains(stdout.String(), "[deny] cloudformation:deploy") {
			t.Fatalf("status = %d, stdout = %q, stderr = %q", status, stdout.String(), stderr.String())
		}
	})

	t.Run("configured allow", func(t *testing.T) {
		configPath := writeConfig(t, `{"workflow_policy":{"allow":["cloudformation:deploy"]}}`)
		rt, stdout, stderr := testRuntime(t, false, nil)
		status := run([]string{"--config", configPath, "plan", workflowPath}, rt)
		if status != exitOK || stderr.Len() != 0 || !strings.Contains(stdout.String(), "matched configured allow rule") {
			t.Fatalf("status = %d, stdout = %q, stderr = %q", status, stdout.String(), stderr.String())
		}
	})

	t.Run("deny overrides allow", func(t *testing.T) {
		configPath := writeConfig(t, `{
  "workflow_policy": {
    "allow": ["cloudformation:*"],
    "deny": ["*:deploy"]
  }
}`)
		rt, stdout, stderr := testRuntime(t, false, nil)
		status := run([]string{"--config", configPath, "plan", workflowPath}, rt)
		if status != exitPolicy || stderr.Len() != 0 || !strings.Contains(stdout.String(), "matched configured deny rule") {
			t.Fatalf("status = %d, stdout = %q, stderr = %q", status, stdout.String(), stderr.String())
		}
	})
}

func TestRunRequiresNamedApprovalAndExecutesAllowedStepsInOrder(t *testing.T) {
	fake := makeProcessAlias(t, "fake-aws")
	callLog := filepath.Join(t.TempDir(), "calls.jsonl")
	workflowPath := writeWorkflow(t, `{
  "schema_version": 1,
  "name": "release",
  "steps": [
    {"name": "inventory", "command": ["ec2", "describe-instances"]},
    {"name": "deploy", "command": ["cloudformation", "deploy", "--stack-name", "example"]}
  ]
}`)
	configPath := writeConfig(t, `{"workflow_policy":{"allow":["cloudformation:deploy"]}}`)

	t.Run("approval must match", func(t *testing.T) {
		rt, stdout, stderr := testRuntime(t, false, nil, "FAKE_CALL_LOG="+callLog)
		status := run([]string{"--config", configPath, "--aws-binary", fake, "run", "--approve", "different", workflowPath}, rt)
		if status != exitUsage || stdout.Len() != 0 || !strings.Contains(stderr.String(), `--approve "release"`) {
			t.Fatalf("status = %d, stdout = %q, stderr = %q", status, stdout.String(), stderr.String())
		}
		if _, err := os.Stat(callLog); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("AWS CLI was inspected or run before approval")
		}
	})

	t.Run("approved steps run sequentially", func(t *testing.T) {
		approvedLog := filepath.Join(t.TempDir(), "calls.jsonl")
		rt, stdout, stderr := testRuntime(t, false, nil,
			"FAKE_CALL_LOG="+approvedLog,
			"FAKE_STDOUT=step output\n",
		)
		status := run([]string{"--config", configPath, "--aws-binary", fake, "run", workflowPath, "--approve", "release"}, rt)
		if status != exitOK {
			t.Fatalf("status = %d, stderr = %q", status, stderr.String())
		}
		wantCalls := [][]string{
			{"--version"},
			{"ec2", "describe-instances"},
			{"cloudformation", "deploy", "--stack-name", "example"},
		}
		if calls := readCallLog(t, approvedLog); !reflect.DeepEqual(calls, wantCalls) {
			t.Fatalf("calls = %#v, want %#v", calls, wantCalls)
		}
		if stdout.String() != "step output\nstep output\n" {
			t.Fatalf("AWS stdout changed: %q", stdout.String())
		}
		for _, expected := range []string{"step 1/2 \"inventory\": succeeded", "step 2/2 \"deploy\": succeeded", "workflow \"release\": succeeded"} {
			if !strings.Contains(stderr.String(), expected) {
				t.Fatalf("execution visibility missing %q: %q", expected, stderr.String())
			}
		}
	})
}

func TestRunStopsAfterFirstAWSFailureAndReturnsItsStatus(t *testing.T) {
	fake := makeProcessAlias(t, "fake-aws")
	callLog := filepath.Join(t.TempDir(), "calls.jsonl")
	workflowPath := writeWorkflow(t, `{
  "schema_version": 1,
  "name": "inspect",
  "steps": [
    {"name": "first", "command": ["sts", "get-caller-identity"]},
    {"name": "second", "command": ["ec2", "describe-regions"]}
  ]
}`)
	rt, _, stderr := testRuntime(t, false, nil,
		"FAKE_CALL_LOG="+callLog,
		"FAKE_EXIT_CODE=47",
	)

	status := run([]string{"--aws-binary", fake, "run", workflowPath, "--approve", "inspect"}, rt)
	if status != 47 || !strings.Contains(stderr.String(), "remaining steps skipped") {
		t.Fatalf("status = %d, stderr = %q", status, stderr.String())
	}
	wantCalls := [][]string{{"--version"}, {"sts", "get-caller-identity"}}
	if calls := readCallLog(t, callLog); !reflect.DeepEqual(calls, wantCalls) {
		t.Fatalf("calls = %#v, want %#v", calls, wantCalls)
	}
}

func TestWorkflowValidationRejectsAmbiguousDefinitions(t *testing.T) {
	tests := []struct {
		name      string
		workflow  string
		wantError string
	}{
		{
			name:      "unknown field",
			workflow:  `{"schema_version":1,"name":"inspect","unexpected":true,"steps":[{"name":"one","command":["sts","get-caller-identity"]}]}`,
			wantError: "unknown field",
		},
		{
			name:      "duplicate step name",
			workflow:  `{"schema_version":1,"name":"inspect","steps":[{"name":"same","command":["sts","get-caller-identity"]},{"name":"same","command":["ec2","describe-regions"]}]}`,
			wantError: "must be unique",
		},
		{
			name:      "global option obscures command identity",
			workflow:  `{"schema_version":1,"name":"inspect","steps":[{"name":"one","command":["--profile","prod","sts","get-caller-identity"]}]}`,
			wantError: "must begin with a lowercase AWS service and operation",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			workflowPath := writeWorkflow(t, test.workflow)
			rt, stdout, stderr := testRuntime(t, false, nil)
			status := run([]string{"plan", workflowPath}, rt)
			if status != exitUsage || stdout.Len() != 0 || !strings.Contains(stderr.String(), test.wantError) {
				t.Fatalf("status = %d, stdout = %q, stderr = %q", status, stdout.String(), stderr.String())
			}
		})
	}
}

func TestWorkflowPolicyConfigurationRejectsInvalidRulesAndLimits(t *testing.T) {
	workflowPath := writeWorkflow(t, `{
  "schema_version": 1,
  "name": "inspect",
  "steps": [{"name": "identity", "command": ["sts", "get-caller-identity"]}]
}`)
	tests := []struct {
		name      string
		config    string
		wantError string
	}{
		{"zero step limit", `{"workflow_policy":{"max_steps":0}}`, "between 1 and 100"},
		{"invalid rule", `{"workflow_policy":{"allow":["CloudFormation:deploy"]}}`, "lowercase letters"},
		{"unknown policy key", `{"workflow_policy":{"approval":"always"}}`, "unknown field"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			configPath := writeConfig(t, test.config)
			rt, stdout, stderr := testRuntime(t, false, nil)
			status := run([]string{"--config", configPath, "plan", workflowPath}, rt)
			if status != exitUsage || stdout.Len() != 0 || !strings.Contains(stderr.String(), test.wantError) {
				t.Fatalf("status = %d, stdout = %q, stderr = %q", status, stdout.String(), stderr.String())
			}
		})
	}
}

func TestWildcardMatchUsesOnlyAsteriskSemantics(t *testing.T) {
	tests := []struct {
		pattern string
		value   string
		want    bool
	}{
		{"cloudformation:*", "cloudformation:deploy", true},
		{"*:delete-*", "s3api:delete-bucket", true},
		{"ec2:*instances", "ec2:terminate-instances", true},
		{"ec2:describe-*", "rds:describe-db-instances", false},
		{"ec2:create-*", "ec2:create", false},
	}
	for _, test := range tests {
		if got := wildcardMatch(test.pattern, test.value); got != test.want {
			t.Errorf("wildcardMatch(%q, %q) = %t, want %t", test.pattern, test.value, got, test.want)
		}
	}
}

func TestSensitiveOutputOperationsRequireExplicitAllowance(t *testing.T) {
	command := "secretsmanager:batch-get-secret-value"
	if allowed, reason := evaluateWorkflowCommand(command, WorkflowPolicy{}); allowed || !strings.Contains(reason, "sensitive-output") {
		t.Fatalf("default decision = allowed %t, reason %q", allowed, reason)
	}
	policy := WorkflowPolicy{Allow: []string{"secretsmanager:batch-get-secret-value"}}
	if allowed, reason := evaluateWorkflowCommand(command, policy); !allowed || reason != "matched configured allow rule" {
		t.Fatalf("configured decision = allowed %t, reason %q", allowed, reason)
	}
}

func writeWorkflow(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "workflow.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
