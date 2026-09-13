// execution_policy.go - Explain and enforce direct AWS command policy

package cli

import (
	"fmt"
	"io"
	"strings"
)

type commandPolicyDecision struct {
	Allowed bool
	Reason  string
}

// Preview uses only resolved wrapper and ambient settings; profile configuration
// remains unresolved because no AWS CLI process may start
func writeExecutionPreview(path string, arguments []string, settings Settings, environ []string, approvalAccount string, yes bool, rt runtime) int {
	profile, err := selectedProfile(settings)
	if err != nil {
		fmt.Fprintf(rt.stderr, "aws-clip: %s\n", err)
		return exitUsage
	}
	operation := classifyExecutionCommand(arguments)
	region := localEffectiveRegion(settings, environ)
	decision := evaluateCommandPolicy(operation.Command, profile, region, settings.CommandPolicy)
	accountPreflight := len(settings.CommandPolicy.AllowedAccountIDs) > 0 || approvalAccount != ""
	if _, protected := settings.ProtectedProfiles[profile]; protected {
		accountPreflight = true
	}

	fmt.Fprintln(rt.stdout, "AWS command preview")
	fmt.Fprintf(rt.stdout, "  aws_binary: %s\n", printableLine(path))
	fmt.Fprintf(rt.stdout, "  command: %s\n", operation.Command)
	fmt.Fprintf(rt.stdout, "  classification: %s\n", executionClassification(operation))
	fmt.Fprintf(rt.stdout, "  profile: %s\n", profile)
	fmt.Fprintf(rt.stdout, "  region: %s\n", previewRegion(region))
	fmt.Fprintf(rt.stdout, "  options: %s\n", strings.Join(redactedOptionNames(arguments[2:]), ", "))
	if !decision.Allowed {
		fmt.Fprintln(rt.stdout, "  policy: deny")
		fmt.Fprintf(rt.stdout, "  reason: %s\n", decision.Reason)
		return exitPolicy
	}
	if accountPreflight {
		fmt.Fprintln(rt.stdout, "  policy: allow pending account preflight")
	} else {
		fmt.Fprintln(rt.stdout, "  policy: allow")
	}
	fmt.Fprintf(rt.stdout, "  reason: %s\n", decision.Reason)
	fmt.Fprintf(rt.stdout, "  account_preflight: %s\n", requiredLabel(accountPreflight))
	requiresConfirmation := operation.Changing || operation.Sensitive
	confirmation := requiredLabel(requiresConfirmation)
	if requiresConfirmation && yes {
		confirmation = "approved by --yes"
	}
	fmt.Fprintf(rt.stdout, "  confirmation: %s\n", confirmation)
	return exitOK
}

func evaluateCommandPolicy(command, profile string, region *string, policy CommandPolicy) commandPolicyDecision {
	for _, rule := range policy.Deny {
		if wildcardMatch(rule, command) {
			return commandPolicyDecision{Reason: "matched configured deny rule " + rule}
		}
	}
	if len(policy.Allow) > 0 && !matchesAnyPolicyRule(policy.Allow, command) {
		return commandPolicyDecision{Reason: "command did not match a configured allow rule"}
	}
	if len(policy.AllowedProfiles) > 0 && !containsString(policy.AllowedProfiles, profile) {
		return commandPolicyDecision{Reason: "profile is not in allowed_profiles"}
	}
	if len(policy.AllowedRegions) > 0 {
		if region == nil {
			return commandPolicyDecision{Reason: "Region is unresolved; select --region to satisfy allowed_regions"}
		}
		if !containsString(policy.AllowedRegions, *region) {
			return commandPolicyDecision{Reason: "Region is not in allowed_regions"}
		}
	}
	reason := "default command policy"
	if len(policy.Allow) > 0 {
		reason = "matched a configured allow rule"
	}
	return commandPolicyDecision{Allowed: true, Reason: reason}
}

func matchesAnyPolicyRule(rules []string, command string) bool {
	for _, rule := range rules {
		if wildcardMatch(rule, command) {
			return true
		}
	}
	return false
}

func localEffectiveRegion(settings Settings, environ []string) *string {
	if settings.Region != nil {
		return cloneString(settings.Region)
	}
	for _, name := range []string{"AWS_REGION", "AWS_DEFAULT_REGION"} {
		if value, ok := lookupEnvironment(environ, name); ok && value != "" && isPrintableSingleLine(value) {
			return stringPointer(value)
		}
	}
	return nil
}

func previewRegion(region *string) string {
	if region == nil {
		return "<AWS profile default; not resolved during preview>"
	}
	return *region
}

func requiredLabel(required bool) string {
	if required {
		return "required"
	}
	return "not required"
}

// Return only syntactically recognizable option names in first-seen order
func redactedOptionNames(arguments []string) []string {
	seen := make(map[string]bool)
	var names []string
	for _, argument := range arguments {
		name, _, _ := strings.Cut(argument, "=")
		if !isSafeOptionName(name) || seen[name] {
			continue
		}
		seen[name] = true
		names = append(names, name)
	}
	if len(names) == 0 {
		return []string{"<none>"}
	}
	return names
}

func isSafeOptionName(value string) bool {
	if len(value) < 3 || !strings.HasPrefix(value, "--") {
		return false
	}
	for _, character := range value[2:] {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
			return false
		}
	}
	return true
}

func executionClassification(operation executionOperation) string {
	if operation.Sensitive {
		return operation.Classification + "; sensitive output"
	}
	return operation.Classification
}

// runProfileExec evaluates static policy before identity checks and confirmation
// Only account constraints, protected profiles, or an explicit account approval
// require STS; target argument values never enter wrapper diagnostics
func runProfileExec(path string, arguments []string, settings Settings, environ []string, approvalAccount string, yes bool, rt runtime) int {
	profile, err := selectedProfile(settings)
	if err != nil {
		fmt.Fprintf(rt.stderr, "aws-clip: %s\n", err)
		return exitUsage
	}
	if status := rejectCredentialEnvironment(environ, rt.stderr); status != exitOK {
		return status
	}

	operation := classifyExecutionCommand(arguments)
	region := effectiveRegion(path, settings, environ, profile)
	decision := evaluateCommandPolicy(operation.Command, profile, region, settings.CommandPolicy)
	if !decision.Allowed {
		writeExecutionTarget(rt.stderr, profile, region, operation, nil, "deny")
		fmt.Fprintf(rt.stderr, "aws-clip: policy denied execution: %s\n", decision.Reason)
		return exitPolicy
	}

	expectedAccount, protected := settings.ProtectedProfiles[profile]
	needsIdentity := len(settings.CommandPolicy.AllowedAccountIDs) > 0 || protected || approvalAccount != ""
	var identity *identityRecord
	if needsIdentity {
		observed, status := readIdentity(path, settings, environ, rt.stderr)
		if status != exitOK {
			fmt.Fprintf(rt.stderr, "aws-clip: account preflight failed for profile %q\n", profile)
			return status
		}
		identity = &observed
		if len(settings.CommandPolicy.AllowedAccountIDs) > 0 && !containsString(settings.CommandPolicy.AllowedAccountIDs, observed.Account) {
			fmt.Fprintf(rt.stderr, "aws-clip: identity mismatch: account %s is not in allowed_account_ids\n", observed.Account)
			return exitIdentity
		}
		if protected && observed.Account != expectedAccount {
			fmt.Fprintf(rt.stderr, "aws-clip: identity mismatch for protected profile %q: expected %s, current %s\n", profile, expectedAccount, observed.Account)
			return exitIdentity
		}
		if approvalAccount != "" && approvalAccount != observed.Account {
			fmt.Fprintf(rt.stderr, "aws-clip: identity mismatch: --approve-account does not match current account %s\n", observed.Account)
			return exitIdentity
		}
	}

	writeExecutionTarget(rt.stderr, profile, region, operation, identity, "allow")
	requiresConfirmation := operation.Changing || operation.Sensitive
	if requiresConfirmation && !yes {
		if !rt.stdinTerminal {
			fmt.Fprintln(rt.stderr, "aws-clip: confirmation refused: mutating, unknown, and sensitive-output commands require --yes when stdin is non-interactive")
			return exitConfirmation
		}
		fmt.Fprint(rt.stderr, "aws-clip: execute this command? [y/N] ")
		if !readConfirmation(rt.stdin) {
			fmt.Fprintln(rt.stderr, "aws-clip: confirmation cancelled")
			return exitConfirmation
		}
	}
	return runAWS(path, effectiveArguments(arguments, settings), environ, rt.stdin, rt.stdout, rt.stderr)
}

func writeExecutionTarget(output io.Writer, profile string, region *string, operation executionOperation, identity *identityRecord, policy string) {
	fmt.Fprintf(output, "aws-clip: target profile=%s region=%s operation=%s classification=%s policy=%s",
		profile, displayOptionalString(region), operation.Command, executionClassification(operation), policy)
	if identity != nil {
		fmt.Fprintf(output, " account=%s principal=%s", identity.Account, identity.ARN)
	}
	fmt.Fprintln(output)
}

// Read one byte at a time so confirmation cannot consume input intended for AWS CLI
func readConfirmation(input io.Reader) bool {
	var answer strings.Builder
	buffer := []byte{0}
	for answer.Len() <= 16 {
		count, err := input.Read(buffer)
		if count == 1 {
			if buffer[0] == '\n' {
				break
			}
			answer.WriteByte(buffer[0])
		}
		if err != nil {
			break
		}
		if count == 0 {
			return false
		}
	}
	value := strings.ToLower(strings.TrimSpace(answer.String()))
	return value == "y" || value == "yes"
}
