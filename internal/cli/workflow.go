package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	workflowFileMaxBytes = 1024 * 1024
	workflowNameMaxBytes = 80
	stepNameMaxBytes     = 80
	descriptionMaxBytes  = 240
	stepArgumentMaxCount = 256
	stepArgumentMaxBytes = 64 * 1024
)

// workflow is the versioned, reusable unit executed by aws-clip. Commands are
// arrays rather than shell strings so spaces and metacharacters keep their
// literal meaning and a workflow cannot acquire an accidental shell boundary.
type workflow struct {
	SchemaVersion int            `json:"schema_version"`
	Name          string         `json:"name"`
	Description   string         `json:"description,omitempty"`
	Steps         []workflowStep `json:"steps"`
}

type workflowStep struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Command     []string `json:"command"`
}

// workflowPlan is the stable JSON representation produced by `plan --format
// json`. It intentionally excludes command argument values: those values can
// contain secrets or large request documents, while the service, operation,
// descriptions, and policy decisions provide a useful review boundary.
type workflowPlan struct {
	SchemaVersion int                `json:"schema_version"`
	Name          string             `json:"name"`
	Description   string             `json:"description,omitempty"`
	Context       workflowContext    `json:"context"`
	Steps         []workflowPlanStep `json:"steps"`
	Allowed       bool               `json:"allowed"`
}

type workflowContext struct {
	Profile               *string `json:"profile"`
	Region                *string `json:"region"`
	RetryMode             *string `json:"retry_mode"`
	MaxAttempts           *int    `json:"max_attempts"`
	ConnectTimeoutSeconds *int    `json:"connect_timeout_seconds"`
	ReadTimeoutSeconds    *int    `json:"read_timeout_seconds"`
}

type workflowPlanStep struct {
	Index               int    `json:"index"`
	Name                string `json:"name"`
	Description         string `json:"description,omitempty"`
	Command             string `json:"command"`
	AdditionalArguments int    `json:"additional_arguments"`
	Decision            string `json:"decision"`
	Reason              string `json:"reason"`
}

func readWorkflow(path string, maxSteps int) (workflow, error) {
	file, err := os.Open(path)
	if err != nil {
		return workflow{}, fmt.Errorf("read workflow file %q: %w", path, err)
	}
	defer file.Close()

	// The extra byte distinguishes an exactly-full valid file from an oversized
	// input without loading an unbounded local file into memory.
	data, err := io.ReadAll(io.LimitReader(file, workflowFileMaxBytes+1))
	if err != nil {
		return workflow{}, fmt.Errorf("read workflow file %q: %w", path, err)
	}
	if len(data) > workflowFileMaxBytes {
		return workflow{}, errors.New("workflow file exceeds the 1 MiB limit")
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var result workflow
	if err := decoder.Decode(&result); err != nil {
		return workflow{}, fmt.Errorf("parse workflow file %q: %w", path, err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return workflow{}, fmt.Errorf("parse workflow file %q: expected one JSON object", path)
	}
	if err := validateWorkflow(result, maxSteps); err != nil {
		return workflow{}, err
	}
	return result, nil
}

func validateWorkflow(candidate workflow, maxSteps int) error {
	if candidate.SchemaVersion != 1 {
		return errors.New("workflow schema_version must be 1")
	}
	if err := validateWorkflowText("workflow name", candidate.Name, true, workflowNameMaxBytes); err != nil {
		return err
	}
	if err := validateWorkflowText("workflow description", candidate.Description, false, descriptionMaxBytes); err != nil {
		return err
	}
	if len(candidate.Steps) == 0 {
		return errors.New("workflow requires at least one step")
	}
	if len(candidate.Steps) > maxSteps {
		return fmt.Errorf("workflow has %d steps; policy permits at most %d", len(candidate.Steps), maxSteps)
	}

	seenNames := make(map[string]struct{}, len(candidate.Steps))
	for index, step := range candidate.Steps {
		label := fmt.Sprintf("workflow step %d", index+1)
		if err := validateWorkflowText(label+" name", step.Name, true, stepNameMaxBytes); err != nil {
			return err
		}
		if _, exists := seenNames[step.Name]; exists {
			return fmt.Errorf("workflow step names must be unique; %q is repeated", step.Name)
		}
		seenNames[step.Name] = struct{}{}
		if err := validateWorkflowText(label+" description", step.Description, false, descriptionMaxBytes); err != nil {
			return err
		}
		if err := validateWorkflowCommand(label, step.Command); err != nil {
			return err
		}
	}
	return nil
}

func validateWorkflowText(field, value string, required bool, maxBytes int) error {
	if required && strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s must not be empty", field)
	}
	if value != "" && !isPrintableSingleLine(value) {
		return fmt.Errorf("%s must be printable and single-line", field)
	}
	if len(value) > maxBytes {
		return fmt.Errorf("%s exceeds the %d-byte limit", field, maxBytes)
	}
	return nil
}

func validateWorkflowCommand(label string, command []string) error {
	if len(command) < 2 {
		return fmt.Errorf("%s command requires an AWS service and operation", label)
	}
	if len(command) > stepArgumentMaxCount {
		return fmt.Errorf("%s command exceeds the %d-argument limit", label, stepArgumentMaxCount)
	}
	totalBytes := 0
	for _, argument := range command {
		if !isPrintableSingleLine(argument) {
			return fmt.Errorf("%s command arguments must be printable and single-line", label)
		}
		totalBytes += len(argument)
	}
	if totalBytes > stepArgumentMaxBytes {
		return fmt.Errorf("%s command exceeds the %d-byte argument limit", label, stepArgumentMaxBytes)
	}
	if !isAWSCommandToken(command[0]) || !isAWSCommandToken(command[1]) {
		return fmt.Errorf("%s command must begin with a lowercase AWS service and operation", label)
	}
	return nil
}

func isAWSCommandToken(value string) bool {
	if value == "" {
		return false
	}
	if !isLowercaseLetterOrDigit(value[0]) || !isLowercaseLetterOrDigit(value[len(value)-1]) {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
			return false
		}
	}
	return true
}

func isLowercaseLetterOrDigit(character byte) bool {
	return (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9')
}

func buildWorkflowPlan(candidate workflow, settings Settings) workflowPlan {
	result := workflowPlan{
		SchemaVersion: 1,
		Name:          candidate.Name,
		Description:   candidate.Description,
		Context: workflowContext{
			Profile:               cloneOptionalString(settings.Profile),
			Region:                cloneOptionalString(settings.Region),
			RetryMode:             cloneOptionalString(settings.RetryMode),
			MaxAttempts:           cloneOptionalInt(settings.MaxAttempts),
			ConnectTimeoutSeconds: cloneOptionalInt(settings.ConnectTimeout),
			ReadTimeoutSeconds:    cloneOptionalInt(settings.ReadTimeout),
		},
		Steps:   make([]workflowPlanStep, 0, len(candidate.Steps)),
		Allowed: true,
	}
	for index, step := range candidate.Steps {
		command := step.Command[0] + ":" + step.Command[1]
		allowed, reason := evaluateWorkflowCommand(command, settings.WorkflowPolicy)
		decision := "allow"
		if !allowed {
			decision = "deny"
			result.Allowed = false
		}
		result.Steps = append(result.Steps, workflowPlanStep{
			Index:               index + 1,
			Name:                step.Name,
			Description:         step.Description,
			Command:             command,
			AdditionalArguments: len(step.Command) - 2,
			Decision:            decision,
			Reason:              reason,
		})
	}
	return result
}

func cloneOptionalString(value *string) *string {
	if value == nil {
		return nil
	}
	return cloneString(value)
}

func cloneOptionalInt(value *int) *int {
	if value == nil {
		return nil
	}
	return cloneInt(value)
}

func evaluateWorkflowCommand(command string, policy WorkflowPolicy) (bool, string) {
	for _, rule := range policy.Deny {
		if wildcardMatch(rule, command) {
			return false, "matched configured deny rule"
		}
	}
	_, operation, _ := strings.Cut(command, ":")
	if isReadOperation(operation) && !isSensitiveOutputOperation(command) {
		return true, "read-oriented operation"
	}
	for _, rule := range policy.Allow {
		if wildcardMatch(rule, command) {
			return true, "matched configured allow rule"
		}
	}
	if isSensitiveOutputOperation(command) {
		return false, "sensitive-output operation requires an explicit allow rule"
	}
	return false, "operation is not read-oriented or explicitly allowed"
}

func isSensitiveOutputOperation(command string) bool {
	for _, pattern := range []string{
		"codeartifact:get-authorization-token",
		"cognito-identity:get-credentials-for-identity",
		"cognito-identity:get-open-id-token*",
		"ecr:get-authorization-token",
		"ecr:get-login-password",
		"eks:get-token",
		"secretsmanager:*get-secret-value",
		"secretsmanager:get-random-password",
		"sso:get-role-credentials",
		"ssm:get-parameter*",
		"sts:get-federation-token",
		"sts:get-session-token",
	} {
		if wildcardMatch(pattern, command) {
			return true
		}
	}
	return false
}

func isReadOperation(operation string) bool {
	for _, exact := range []string{"describe", "get", "head", "list", "lookup", "ls", "scan", "search", "select", "tail", "validate", "wait"} {
		if operation == exact {
			return true
		}
	}
	for _, prefix := range []string{"batch-get-", "describe-", "get-", "head-", "list-", "lookup-", "search-", "validate-"} {
		if strings.HasPrefix(operation, prefix) {
			return true
		}
	}
	return false
}

func validatePolicyRule(rule string) error {
	service, operation, found := strings.Cut(rule, ":")
	if !found || strings.Contains(operation, ":") || service == "" || operation == "" {
		return errors.New("workflow policy rules must use service:operation patterns")
	}
	for _, part := range []string{service, operation} {
		for _, character := range part {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' && character != '*' {
				return errors.New("workflow policy rules may contain lowercase letters, digits, hyphens, and * wildcards")
			}
		}
	}
	return nil
}

// wildcardMatch implements only the documented '*' wildcard. A purpose-built
// matcher keeps policy behavior identical across operating systems and avoids
// accepting character classes or path separators with surprising semantics.
func wildcardMatch(pattern, value string) bool {
	patternIndex, valueIndex := 0, 0
	starIndex, starValueIndex := -1, 0
	for valueIndex < len(value) {
		if patternIndex < len(pattern) && pattern[patternIndex] == value[valueIndex] {
			patternIndex++
			valueIndex++
			continue
		}
		if patternIndex < len(pattern) && pattern[patternIndex] == '*' {
			starIndex = patternIndex
			patternIndex++
			starValueIndex = valueIndex
			continue
		}
		if starIndex >= 0 {
			patternIndex = starIndex + 1
			starValueIndex++
			valueIndex = starValueIndex
			continue
		}
		return false
	}
	for patternIndex < len(pattern) && pattern[patternIndex] == '*' {
		patternIndex++
	}
	return patternIndex == len(pattern)
}

func writeWorkflowPlanText(output io.Writer, plan workflowPlan) {
	fmt.Fprintf(output, "Workflow: %s\n", plan.Name)
	if plan.Description != "" {
		fmt.Fprintf(output, "Purpose: %s\n", plan.Description)
	}
	fmt.Fprintf(output, "Context: profile=%s region=%s\n",
		displayOptionalString(plan.Context.Profile), displayOptionalString(plan.Context.Region))
	fmt.Fprintf(output, "Execution: retry_mode=%s max_attempts=%s connect_timeout_seconds=%s read_timeout_seconds=%s\n",
		displayOptionalString(plan.Context.RetryMode), displayOptionalInt(plan.Context.MaxAttempts),
		displayOptionalInt(plan.Context.ConnectTimeoutSeconds), displayOptionalInt(plan.Context.ReadTimeoutSeconds))
	fmt.Fprintln(output, "Steps:")
	for _, step := range plan.Steps {
		fmt.Fprintf(output, "  %d. %s [%s] %s", step.Index, step.Name, step.Decision, step.Command)
		if step.Description != "" {
			fmt.Fprintf(output, " - %s", step.Description)
		}
		fmt.Fprintf(output, " (%s)\n", step.Reason)
	}
	if plan.Allowed {
		fmt.Fprintln(output, "Decision: allowed by workflow policy")
		return
	}
	fmt.Fprintln(output, "Decision: blocked by workflow policy")
}

func writeWorkflowPlanJSON(output io.Writer, plan workflowPlan) error {
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(plan)
}

func runWorkflow(awsPath string, candidate workflow, settings Settings, environ []string, rt runtime) int {
	fmt.Fprintf(rt.stderr, "aws-clip: workflow %q: starting %d steps\n", candidate.Name, len(candidate.Steps))
	fmt.Fprintf(rt.stderr, "aws-clip: context: profile=%s region=%s\n",
		printableLine(displayOptionalString(settings.Profile)), printableLine(displayOptionalString(settings.Region)))
	for index, step := range candidate.Steps {
		command := step.Command[0] + ":" + step.Command[1]
		fmt.Fprintf(rt.stderr, "aws-clip: step %d/%d %q (%s): started\n", index+1, len(candidate.Steps), step.Name, command)
		status := runAWS(awsPath, effectiveArguments(step.Command, settings), environ, rt.stdin, rt.stdout, rt.stderr)
		if status != exitOK {
			fmt.Fprintf(rt.stderr, "aws-clip: step %d/%d %q: failed with status %d; remaining steps skipped\n", index+1, len(candidate.Steps), step.Name, status)
			return status
		}
		fmt.Fprintf(rt.stderr, "aws-clip: step %d/%d %q: succeeded\n", index+1, len(candidate.Steps), step.Name)
	}
	fmt.Fprintf(rt.stderr, "aws-clip: workflow %q: succeeded\n", candidate.Name)
	return exitOK
}
