// session.go - Discover AWS profiles and enforce identity-bound session operations

package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

// Shared output bound for AWS CLI metadata and identity subprocesses
const sessionOutputMaxBytes = 1024 * 1024

// Literal acknowledgement for AWS CLI's account-wide SSO cache clearing
const approveAllSSOSessions = "all-sso-sessions"

// profileRecord is the stable machine representation returned by profiles
// It contains configuration metadata only and deliberately excludes start
// URLs, credential-process commands, access key IDs, and credential values
type profileRecord struct {
	Name              string  `json:"name"`
	Selected          bool    `json:"selected"`
	Region            *string `json:"region"`
	Authentication    string  `json:"authentication"`
	SourceProfile     *string `json:"source_profile,omitempty"`
	RoleARN           *string `json:"role_arn,omitempty"`
	ConfiguredAccount *string `json:"configured_account_id,omitempty"`
	ConfiguredRole    *string `json:"configured_role,omitempty"`
	Protected         bool    `json:"protected"`
	ExpectedAccount   *string `json:"expected_account_id,omitempty"`

	// SessionKind and LoginProfile guide login and logout without entering JSON
	// Role profiles inherit source authentication while execution stays on the selected role
	SessionKind  string `json:"-"`
	LoginProfile string `json:"-"`
}

// profilesDocument is the versioned machine envelope for ordered profile records
type profilesDocument struct {
	SchemaVersion int             `json:"schema_version"`
	Profiles      []profileRecord `json:"profiles"`
}

// identityRecord is the non-secret context returned by STS
// UserID supports session diagnosis but never serves as an approval token
// account ID remains the stable guard boundary
type identityRecord struct {
	Account string `json:"Account"`
	ARN     string `json:"Arn"`
	UserID  string `json:"UserId"`
}

// contextDocument is the versioned machine view of observed identity and local policy
type contextDocument struct {
	SchemaVersion     int     `json:"schema_version"`
	Profile           string  `json:"profile"`
	AccountID         string  `json:"account_id"`
	PrincipalARN      string  `json:"principal_arn"`
	UserID            string  `json:"user_id"`
	Role              *string `json:"role,omitempty"`
	Region            *string `json:"region"`
	CredentialSource  string  `json:"credential_source"`
	SourceProfile     *string `json:"source_profile,omitempty"`
	Protected         bool    `json:"protected"`
	ExpectedAccountID *string `json:"expected_account_id,omitempty"`
}

// executionOperation captures policy facts needed before an AWS command starts
// Classification records normalized command identity and guard decisions only
// argument values never enter preview or policy diagnostics
type executionOperation struct {
	Command     string
	Changing    bool
	Destructive bool
	Costly      bool
	Sensitive   bool
}

// boundedOutput retains a fixed prefix while continuing to accept writes
// AWS subprocesses therefore cannot block on a full pipe or grow wrapper
// memory without limit when a local metadata command behaves unexpectedly
type boundedOutput struct {
	buffer   bytes.Buffer
	limit    int
	exceeded bool
}

// Write stores up to limit bytes while reporting the full input as consumed
// exceeded remains sticky once any byte falls outside the retained prefix
func (output *boundedOutput) Write(data []byte) (int, error) {
	originalLength := len(data)
	remaining := output.limit - output.buffer.Len()
	if remaining <= 0 {
		output.exceeded = output.exceeded || originalLength > 0
		return originalLength, nil
	}
	toWrite := data
	if len(toWrite) > remaining {
		toWrite = toWrite[:remaining]
		output.exceeded = true
	}
	_, err := output.buffer.Write(toWrite)
	if err != nil {
		return 0, err
	}
	return originalLength, nil
}

// Bytes returns the retained prefix for structured decoding
func (output *boundedOutput) Bytes() []byte {
	return output.buffer.Bytes()
}

// String returns the retained prefix for line-oriented metadata parsing
func (output *boundedOutput) String() string {
	return output.buffer.String()
}

// selectedProfile requires an aws-clip-resolved profile for lifecycle and
// guarded execution commands
// Explicit wrapper context prevents fallback to an AWS CLI default in another account
func selectedProfile(settings Settings) (string, error) {
	if settings.Profile == nil {
		return "", errors.New("an explicit profile is required; use --profile, AWS_CLIP_PROFILE, or profile in the configuration file")
	}
	return *settings.Profile, nil
}

// runProfiles discovers names through AWS CLI and enriches each one with safe
// configuration metadata
// AWS CLI remains authoritative for paths, merged sections, and platform behavior
func runProfiles(path string, settings Settings, environ []string, format string, rt runtime) int {
	names, status := listProfileNames(path, environ, rt.stderr)
	if status != exitOK {
		return status
	}
	records := make([]profileRecord, 0, len(names))
	for _, name := range names {
		record := inspectProfile(path, environ, settings, name, map[string]bool{})
		records = append(records, record)
	}

	document := profilesDocument{SchemaVersion: 1, Profiles: records}
	if format == "json" {
		encoder := json.NewEncoder(rt.stdout)
		encoder.SetEscapeHTML(false)
		if err := encoder.Encode(document); err != nil {
			fmt.Fprintln(rt.stderr, "aws-clip: could not write profile output")
			return exitCannotRun
		}
		return exitOK
	}

	fmt.Fprintf(rt.stdout, "AWS profiles (%d)\n", len(records))
	if len(records) == 0 {
		fmt.Fprintln(rt.stdout, "  none configured")
		fmt.Fprintln(rt.stdout, "Next: aws configure sso --profile <name>")
		return exitOK
	}
	for _, record := range records {
		marker := " "
		if record.Selected {
			marker = "*"
		}
		fmt.Fprintf(rt.stdout, "%s %s: region=%s auth=%s", marker, record.Name, displayOptionalString(record.Region), record.Authentication)
		if record.ConfiguredAccount != nil {
			fmt.Fprintf(rt.stdout, " account=%s", *record.ConfiguredAccount)
		}
		if record.ConfiguredRole != nil {
			fmt.Fprintf(rt.stdout, " role=%s", *record.ConfiguredRole)
		}
		if record.Protected {
			fmt.Fprintf(rt.stdout, " protected=%s", *record.ExpectedAccount)
		}
		fmt.Fprintln(rt.stdout)
	}
	return exitOK
}

// listProfileNames uses the installed AWS CLI instead of parsing shared files
// preserves AWS file selection, merging, ordering, and profile-name behavior
// rejects oversized or structurally unsafe output before displaying any name
func listProfileNames(path string, environ []string, stderr io.Writer) ([]string, int) {
	output := &boundedOutput{limit: sessionOutputMaxBytes}
	status := runAWS(path, []string{"configure", "list-profiles"}, inspectionEnvironment(environ), strings.NewReader(""), output, stderr)
	if status != exitOK {
		return nil, status
	}
	if output.exceeded {
		fmt.Fprintln(stderr, "aws-clip: profile list exceeded the 1 MiB output limit")
		return nil, exitCannotRun
	}

	seen := make(map[string]bool)
	var names []string
	for _, line := range strings.Split(strings.ReplaceAll(output.String(), "\r\n", "\n"), "\n") {
		if line == "" || seen[line] {
			continue
		}
		if !isPrintableSingleLine(line) {
			fmt.Fprintln(stderr, "aws-clip: AWS CLI returned an invalid profile name")
			return nil, exitCannotRun
		}
		seen[line] = true
		names = append(names, line)
	}
	return names, exitOK
}

// inspectProfile classifies a profile from non-secret AWS configuration keys
// Presence-only checks discard values for fields that can hold credentials or
// executable command text
// Source-profile recursion uses cycle detection and a fixed depth bound
func inspectProfile(path string, environ []string, settings Settings, profile string, visiting map[string]bool) profileRecord {
	record := profileRecord{
		Name:           profile,
		Selected:       settings.Profile != nil && *settings.Profile == profile,
		Authentication: "unconfigured credential source",
		SessionKind:    "login-fallback",
		LoginProfile:   profile,
	}
	if len(visiting) >= 64 {
		record.Authentication = "assume role via source chain exceeding 64 profiles"
		return record
	}
	if account, protected := settings.ProtectedProfiles[profile]; protected {
		record.Protected = true
		record.ExpectedAccount = stringPointer(account)
	}
	record.Region = safeConfigValue(path, environ, profile, "region")
	record.RoleARN = safeConfigValue(path, environ, profile, "role_arn")
	record.SourceProfile = safeConfigValue(path, environ, profile, "source_profile")
	record.ConfiguredAccount = safeConfigValue(path, environ, profile, "sso_account_id")
	record.ConfiguredRole = safeConfigValue(path, environ, profile, "sso_role_name")

	if record.RoleARN != nil {
		// Role profiles inherit authentication lifecycle from their source
		// execution identity still resolves through the originally selected profile
		if hasConfigValue(path, environ, profile, "web_identity_token_file") {
			record.Authentication = "web identity role"
			return record
		}
		if record.SourceProfile != nil {
			if visiting[profile] {
				record.Authentication = "assume role via cyclic source profile"
				return record
			}
			visiting[profile] = true
			source := inspectProfile(path, environ, settings, *record.SourceProfile, visiting)
			delete(visiting, profile)
			record.Authentication = "assume role via " + source.Authentication
			record.SessionKind = source.SessionKind
			record.LoginProfile = source.LoginProfile
			return record
		}
		if source := safeConfigValue(path, environ, profile, "credential_source"); source != nil {
			record.Authentication = "assume role via credential source " + *source
			return record
		}
		record.Authentication = "assume role"
		return record
	}
	if hasConfigValue(path, environ, profile, "sso_session") || hasConfigValue(path, environ, profile, "sso_start_url") {
		record.Authentication = "IAM Identity Center"
		record.SessionKind = "sso"
		return record
	}
	if hasConfigValue(path, environ, profile, "login_session") {
		record.Authentication = "AWS local login"
		record.SessionKind = "login"
		return record
	}
	if hasConfigValue(path, environ, profile, "credential_process") {
		// Presence-only probes deliberately discard executable command text
		record.Authentication = "credential process"
		return record
	}
	if hasConfigValue(path, environ, profile, "aws_access_key_id") {
		record.Authentication = "static access keys"
		return record
	}
	return record
}

// safeConfigValue reads one non-secret profile field through AWS CLI
// suppresses command failures, oversized output, and unsafe display text as absent
func safeConfigValue(path string, environ []string, profile, key string) *string {
	output := &boundedOutput{limit: sessionOutputMaxBytes}
	status := runAWS(path, []string{"configure", "get", key, "--profile", profile}, inspectionEnvironment(environ), strings.NewReader(""), output, io.Discard)
	if status != exitOK || output.exceeded {
		return nil
	}
	value := strings.TrimSuffix(strings.TrimSuffix(output.String(), "\n"), "\r")
	if value == "" || !isPrintableSingleLine(value) {
		return nil
	}
	return stringPointer(value)
}

// hasConfigValue checks presence without capturing a potentially secret value
func hasConfigValue(path string, environ []string, profile, key string) bool {
	return runAWS(path, []string{"configure", "get", key, "--profile", profile}, inspectionEnvironment(environ), strings.NewReader(""), nil, io.Discard) == exitOK
}

// stringPointer returns independent storage for optional machine fields
func stringPointer(value string) *string {
	copy := value
	return &copy
}

// runContext resolves the active identity before showing it, making the
// profile/account/role relationship an observed fact rather than a guess from
// local configuration
// JSON output remains a versioned automation contract
func runContext(path string, settings Settings, environ []string, format string, rt runtime) int {
	profile, err := selectedProfile(settings)
	if err != nil {
		fmt.Fprintf(rt.stderr, "aws-clip: %s\n", err)
		return exitUsage
	}
	if status := rejectCredentialEnvironment(environ, rt.stderr); status != exitOK {
		return status
	}
	record := inspectProfile(path, environ, settings, profile, map[string]bool{})
	identity, status := readIdentity(path, settings, environ, rt.stderr)
	if status != exitOK {
		fmt.Fprintf(rt.stderr, "aws-clip: authentication failed for profile %q; run aws-clip --profile %s login\n", profile, profile)
		return status
	}
	if status := verifyExpectedAccount(record, identity, rt.stderr); status != exitOK {
		return status
	}
	context := buildContext(path, settings, environ, record, identity)
	return writeContext(context, format, rt)
}

// buildContext combines validated STS identity with safe local profile metadata
func buildContext(path string, settings Settings, environ []string, profile profileRecord, identity identityRecord) contextDocument {
	return contextDocument{
		SchemaVersion:     1,
		Profile:           profile.Name,
		AccountID:         identity.Account,
		PrincipalARN:      identity.ARN,
		UserID:            identity.UserID,
		Role:              principalRole(identity.ARN),
		Region:            effectiveRegion(path, settings, environ, profile.Name),
		CredentialSource:  profile.Authentication,
		SourceProfile:     profile.SourceProfile,
		Protected:         profile.Protected,
		ExpectedAccountID: profile.ExpectedAccount,
	}
}

// writeContext renders either the stable JSON contract or concise operator text
func writeContext(context contextDocument, format string, rt runtime) int {
	if format == "json" {
		encoder := json.NewEncoder(rt.stdout)
		encoder.SetEscapeHTML(false)
		if err := encoder.Encode(context); err != nil {
			fmt.Fprintln(rt.stderr, "aws-clip: could not write context output")
			return exitCannotRun
		}
		return exitOK
	}
	fmt.Fprintln(rt.stdout, "AWS context")
	fmt.Fprintf(rt.stdout, "  profile: %s\n", context.Profile)
	fmt.Fprintf(rt.stdout, "  account: %s\n", context.AccountID)
	fmt.Fprintf(rt.stdout, "  principal: %s\n", context.PrincipalARN)
	if context.Role != nil {
		fmt.Fprintf(rt.stdout, "  role: %s\n", *context.Role)
	}
	fmt.Fprintf(rt.stdout, "  region: %s\n", displayOptionalString(context.Region))
	fmt.Fprintf(rt.stdout, "  credential source: %s\n", context.CredentialSource)
	if context.SourceProfile != nil {
		fmt.Fprintf(rt.stdout, "  source profile: %s\n", *context.SourceProfile)
	}
	guard := "standard"
	if context.Protected {
		guard = "protected; expected account " + *context.ExpectedAccountID
	}
	fmt.Fprintf(rt.stdout, "  guard: %s\n", guard)
	return exitOK
}

// readIdentity makes one bounded STS request using the effective AWS CLI
// environment
// AWS diagnostics and status remain intact on failure
// successful JSON is validated before use in safety decisions
func readIdentity(path string, settings Settings, environ []string, stderr io.Writer) (identityRecord, int) {
	output := &boundedOutput{limit: sessionOutputMaxBytes}
	arguments := effectiveArguments([]string{
		"sts", "get-caller-identity",
		"--output", "json",
		"--query", "{Account:Account,Arn:Arn,UserId:UserId}",
	}, settings)
	status := runAWS(path, arguments, inspectionEnvironment(environ), strings.NewReader(""), output, stderr)
	if status != exitOK {
		return identityRecord{}, status
	}
	if output.exceeded {
		fmt.Fprintln(stderr, "aws-clip: STS identity output exceeded the 1 MiB limit")
		return identityRecord{}, exitCannotRun
	}
	var identity identityRecord
	if err := json.Unmarshal(output.Bytes(), &identity); err != nil || !isAWSAccountID(identity.Account) ||
		identity.ARN == "" || identity.UserID == "" || !isPrintableSingleLine(identity.ARN) || !isPrintableSingleLine(identity.UserID) {
		fmt.Fprintln(stderr, "aws-clip: AWS CLI returned an invalid STS identity response")
		return identityRecord{}, exitCannotRun
	}
	return identity, exitOK
}

// principalRole derives a human label from role, assumed-role, or user ARN resources
// returns nil for unrecognized principals rather than guessing from arbitrary ARN text
func principalRole(arn string) *string {
	resource := arn
	if separator := strings.Index(resource, ":"); separator >= 0 {
		parts := strings.SplitN(resource, ":", 6)
		if len(parts) == 6 {
			resource = parts[5]
		}
	}
	segments := strings.Split(resource, "/")
	if len(segments) < 2 {
		return nil
	}
	if segments[0] == "assumed-role" || segments[0] == "role" || segments[0] == "user" {
		return stringPointer(segments[1])
	}
	return nil
}

// effectiveRegion applies wrapper, AWS environment, then profile precedence
// ignores unsafe ambient values so terminal records remain structurally sound
func effectiveRegion(path string, settings Settings, environ []string, profile string) *string {
	if settings.Region != nil {
		return cloneString(settings.Region)
	}
	for _, name := range []string{"AWS_REGION", "AWS_DEFAULT_REGION"} {
		if value, ok := lookupEnvironment(environ, name); ok && value != "" && isPrintableSingleLine(value) {
			return stringPointer(value)
		}
	}
	return safeConfigValue(path, environ, profile, "region")
}

// runLogin reuses a valid session or invokes profile-appropriate authentication
// External and static providers remain responsible for refreshing their credentials
func runLogin(path string, settings Settings, environ []string, rt runtime) int {
	profile, err := selectedProfile(settings)
	if err != nil {
		fmt.Fprintf(rt.stderr, "aws-clip: %s\n", err)
		return exitUsage
	}
	if status := rejectCredentialEnvironment(environ, rt.stderr); status != exitOK {
		return status
	}
	names, status := listProfileNames(path, environ, rt.stderr)
	if status != exitOK {
		return status
	}
	if !containsString(names, profile) {
		fmt.Fprintf(rt.stderr, "aws-clip: profile %q is not configured\n", profile)
		fmt.Fprintf(rt.stderr, "Next: aws configure sso --profile %s, aws configure --profile %s, or configure AWS local login\n", profile, profile)
		return exitUsage
	}
	record := inspectProfile(path, environ, settings, profile, map[string]bool{})
	// A silent STS probe makes repeated login idempotent without hiding final failures
	if identity, probeStatus := readIdentity(path, settings, environ, io.Discard); probeStatus == exitOK {
		if guardStatus := verifyExpectedAccount(record, identity, rt.stderr); guardStatus != exitOK {
			return guardStatus
		}
		writeLoginResult(rt.stdout, record, identity, "existing credentials reused")
		return exitOK
	}

	switch record.SessionKind {
	case "sso":
		status = runAWS(path, effectiveArguments([]string{"sso", "login", "--profile", record.LoginProfile}, settings), environ, rt.stdin, rt.stdout, rt.stderr)
	case "login", "login-fallback":
		// Capability detection gives older AWS CLI v2 installations an actionable error
		if support := runAWS(path, []string{"login", "help"}, inspectionEnvironment(environ), strings.NewReader(""), io.Discard, io.Discard); support != exitOK {
			fmt.Fprintln(rt.stderr, "aws-clip: installed AWS CLI v2 does not support local login; upgrade AWS CLI v2")
			return exitCannotRun
		}
		status = runAWS(path, effectiveArguments([]string{"login", "--profile", record.LoginProfile}, settings), environ, rt.stdin, rt.stdout, rt.stderr)
		if record.SessionKind == "login-fallback" {
			record.Authentication = "AWS local login"
		}
	default:
		fmt.Fprintf(rt.stderr, "aws-clip: profile %q uses %s, which has no AWS CLI login action\n", profile, record.Authentication)
		fmt.Fprintln(rt.stderr, "Next: refresh the configured credential provider, then run aws-clip context")
		// Repeat the silent reuse probe with attached diagnostics so provider
		// failures retain AWS CLI's actionable detail and native exit status
		identity, providerStatus := readIdentity(path, settings, environ, rt.stderr)
		if providerStatus == exitOK {
			if guardStatus := verifyExpectedAccount(record, identity, rt.stderr); guardStatus != exitOK {
				return guardStatus
			}
			writeLoginResult(rt.stdout, record, identity, "credentials became available")
		}
		return providerStatus
	}
	if status != exitOK {
		return status
	}
	identity, status := readIdentity(path, settings, environ, rt.stderr)
	if status != exitOK {
		fmt.Fprintf(rt.stderr, "aws-clip: authentication completed but profile %q still cannot resolve an identity\n", profile)
		return status
	}
	if guardStatus := verifyExpectedAccount(record, identity, rt.stderr); guardStatus != exitOK {
		return guardStatus
	}
	writeLoginResult(rt.stdout, record, identity, "new session established")
	return exitOK
}

// writeLoginResult reports only non-secret authentication and identity facts
func writeLoginResult(output io.Writer, profile profileRecord, identity identityRecord, session string) {
	fmt.Fprintln(output, "AWS login")
	fmt.Fprintf(output, "  profile: %s\n", profile.Name)
	fmt.Fprintf(output, "  method: %s\n", profile.Authentication)
	fmt.Fprintf(output, "  session: %s\n", session)
	fmt.Fprintf(output, "  account: %s\n", identity.Account)
	fmt.Fprintf(output, "  principal: %s\n", identity.ARN)
}

// runLogout distinguishes profile-scoped local logout from AWS SSO's global
// cache operation
// SSO logout requires a literal acknowledgement because AWS CLI clears every
// cached SSO session rather than only the selected profile
func runLogout(path string, settings Settings, environ []string, approval string, rt runtime) int {
	profile, err := selectedProfile(settings)
	if err != nil {
		fmt.Fprintf(rt.stderr, "aws-clip: %s\n", err)
		return exitUsage
	}
	record := inspectProfile(path, environ, settings, profile, map[string]bool{})
	switch record.SessionKind {
	case "sso":
		if approval != approveAllSSOSessions {
			fmt.Fprintf(rt.stderr, "aws-clip: IAM Identity Center logout clears all cached SSO sessions; rerun with --approve %s\n", approveAllSSOSessions)
			return exitUsage
		}
		status := runAWS(path, effectiveArguments([]string{"sso", "logout"}, settings), environ, rt.stdin, rt.stdout, rt.stderr)
		if status == exitOK {
			fmt.Fprintln(rt.stdout, "AWS SSO sessions cleared")
		}
		return status
	case "login":
		status := runAWS(path, effectiveArguments([]string{"logout", "--profile", record.LoginProfile}, settings), environ, rt.stdin, rt.stdout, rt.stderr)
		if status == exitOK {
			fmt.Fprintf(rt.stdout, "AWS local login session cleared for profile %s\n", record.LoginProfile)
		}
		return status
	default:
		fmt.Fprintf(rt.stderr, "aws-clip: profile %q uses %s, which has no AWS CLI logout action\n", profile, record.Authentication)
		return exitUsage
	}
}

// runProfileExec adds an identity preflight and account-bound controls to one
// literal AWS command
// Operators without these guard needs can use AWS CLI directly
// aws-clip intentionally has no unguarded passthrough mode
func runProfileExec(path string, arguments []string, settings Settings, environ []string, approvalAccount string, rt runtime) int {
	if err := validateWorkflowCommand("exec", arguments); err != nil {
		fmt.Fprintf(rt.stderr, "aws-clip: %s\n", err)
		return exitUsage
	}
	operation := classifyExecutionCommand(arguments)
	if _, status := prepareProfileExecution(path, settings, environ, rt, []executionOperation{operation}, approvalAccount); status != exitOK {
		return status
	}
	return runAWS(path, effectiveArguments(arguments, settings), environ, rt.stdin, rt.stdout, rt.stderr)
}

// prepareProfileExecution is the shared preflight for exec and workflow run
// It verifies the effective account before evaluating account-bound approval,
// ensuring a misleading profile name alone can never satisfy a guard
// returns validated identity only when all operations satisfy current guards
func prepareProfileExecution(path string, settings Settings, environ []string, rt runtime, operations []executionOperation, approvalAccount string) (identityRecord, int) {
	profile, err := selectedProfile(settings)
	if err != nil {
		fmt.Fprintf(rt.stderr, "aws-clip: %s\n", err)
		return identityRecord{}, exitUsage
	}
	if status := rejectCredentialEnvironment(environ, rt.stderr); status != exitOK {
		return identityRecord{}, status
	}
	identity, status := readIdentity(path, settings, environ, rt.stderr)
	if status != exitOK {
		fmt.Fprintf(rt.stderr, "aws-clip: cannot verify profile %q; run aws-clip --profile %s login\n", profile, profile)
		return identityRecord{}, status
	}
	expected, protected := settings.ProtectedProfiles[profile]
	// Account mismatch always wins and cannot be overridden by an approval token
	if protected && identity.Account != expected {
		fmt.Fprintf(rt.stderr, "aws-clip: account mismatch for protected profile %q: expected %s, current %s\n", profile, expected, identity.Account)
		return identityRecord{}, exitPolicy
	}

	reasons := make(map[string]bool)
	for _, operation := range operations {
		if operation.Destructive {
			reasons["destructive operation"] = true
		}
		if operation.Costly {
			reasons["potentially costly operation"] = true
		}
		if operation.Sensitive {
			reasons["sensitive-output operation"] = true
		}
		if protected && operation.Changing {
			reasons["change on protected profile"] = true
		}
	}
	operationSummary := fmt.Sprintf("%d workflow operations", len(operations))
	if len(operations) == 1 {
		operationSummary = operations[0].Command
	}
	fmt.Fprintf(rt.stderr, "aws-clip: context profile=%s account=%s principal=%s region=%s operation=%s\n",
		profile, identity.Account, identity.ARN, displayOptionalString(effectiveRegion(path, settings, environ, profile)), operationSummary)
	if len(reasons) > 0 && approvalAccount != identity.Account {
		// Stable reason ordering keeps previews readable and machine-testable
		ordered := make([]string, 0, len(reasons))
		for reason := range reasons {
			ordered = append(ordered, reason)
		}
		sort.Strings(ordered)
		fmt.Fprintf(rt.stderr, "aws-clip: blocked: %s; rerun with --approve-account %s after reviewing this context\n", strings.Join(ordered, ", "), identity.Account)
		return identityRecord{}, exitPolicy
	}
	return identity, exitOK
}

// classifyExecutionCommand derives conservative guard facts from service and operation
// arguments must already contain validated service and operation tokens
// S3 high-level transfers need explicit handling because their names lack API verbs
func classifyExecutionCommand(arguments []string) executionOperation {
	command := arguments[0] + ":" + arguments[1]
	operation := executionOperation{
		Command:   command,
		Changing:  !isReadOperation(arguments[1]),
		Sensitive: isSensitiveOutputOperation(command),
	}
	for _, prefix := range []string{"cancel-", "close-", "delete-", "deregister-", "detach-", "disable-", "disassociate-", "purge-", "remove-", "revoke-", "stop-", "terminate-"} {
		if strings.HasPrefix(arguments[1], prefix) {
			operation.Destructive = true
		}
	}
	for _, prefix := range []string{"create-", "launch-", "purchase-", "run-", "scale-", "start-"} {
		if strings.HasPrefix(arguments[1], prefix) {
			operation.Costly = true
		}
	}
	if command == "cloudformation:deploy" || command == "cloudformation:update-stack" || command == "ecs:update-service" {
		operation.Costly = true
	}
	// High-level S3 commands use short verbs outside normal AWS API naming
	if arguments[0] == "s3" {
		switch arguments[1] {
		case "cp", "mv", "sync":
			operation.Costly = true
		case "rb", "rm":
			operation.Destructive = true
		}
		if arguments[1] == "sync" && containsString(arguments[2:], "--delete") {
			operation.Destructive = true
		}
	}
	return operation
}

// contextOverrideArgument finds AWS global options that could bypass verified context
// accepts both separate and equals-value forms while returning only the safe option name
func contextOverrideArgument(arguments []string) string {
	for _, argument := range arguments {
		name, _, _ := strings.Cut(argument, "=")
		switch name {
		case "--profile", "--region", "--endpoint-url", "--no-sign-request":
			return name
		}
	}
	return ""
}

// credentialEnvironmentNames reports override variable names without reading values aloud
// stable ordering keeps diagnostics predictable and suitable for assertions
func credentialEnvironmentNames(environ []string) []string {
	var names []string
	for _, name := range []string{
		"AWS_ACCESS_KEY_ID",
		"AWS_SECRET_ACCESS_KEY",
		"AWS_SESSION_TOKEN",
		"AWS_SECURITY_TOKEN",
		"AWS_WEB_IDENTITY_TOKEN_FILE",
		"AWS_ROLE_ARN",
		"AWS_CONTAINER_CREDENTIALS_FULL_URI",
		"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
	} {
		if value, ok := lookupEnvironment(environ, name); ok && value != "" {
			names = append(names, name)
		}
	}
	return names
}

// inspectionEnvironment prevents internal configuration and STS probes from
// opening a pager or waiting for an AWS CLI auto-prompt
// User-requested login, logout, and service operations retain interactive settings
func inspectionEnvironment(environ []string) []string {
	result := setEnvironment(environ, "AWS_PAGER", "")
	return setEnvironment(result, "AWS_CLI_AUTO_PROMPT", "off")
}

// rejectCredentialEnvironment protects profile isolation from ambient provider overrides
// diagnostics expose variable names only and never credential values
func rejectCredentialEnvironment(environ []string, stderr io.Writer) int {
	names := credentialEnvironmentNames(environ)
	if len(names) == 0 {
		return exitOK
	}
	fmt.Fprintf(stderr, "aws-clip: credential environment could override the selected profile: %s\n", strings.Join(names, ", "))
	fmt.Fprintln(stderr, "aws-clip: clear these variables for profile isolation, or invoke aws directly when environment credentials are intentional")
	return exitPolicy
}

// verifyExpectedAccount binds a protected profile name to observed STS identity
func verifyExpectedAccount(profile profileRecord, identity identityRecord, stderr io.Writer) int {
	if !profile.Protected || *profile.ExpectedAccount == identity.Account {
		return exitOK
	}
	fmt.Fprintf(stderr, "aws-clip: account mismatch for protected profile %q: expected %s, current %s\n", profile.Name, *profile.ExpectedAccount, identity.Account)
	return exitPolicy
}

// containsString performs exact case-sensitive membership checks
func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

// runDoctor combines local installation/config checks with an optional live
// identity probe when a profile is selected
// Failures include the next useful action and preserve AWS status after STS calls
func runDoctor(path string, info awsInfo, loaded loadedSettings, environ []string, rt runtime) int {
	writeDoctor(rt.stdout, info, loaded, rt.interactive)
	names, status := listProfileNames(path, environ, rt.stderr)
	if status != exitOK {
		fmt.Fprintln(rt.stdout, "profile_discovery: failed")
		return status
	}
	fmt.Fprintf(rt.stdout, "configured_profiles: %d\n", len(names))
	credentialNames := credentialEnvironmentNames(environ)
	if len(credentialNames) == 0 {
		fmt.Fprintln(rt.stdout, "credential_environment: clear")
	} else {
		fmt.Fprintf(rt.stdout, "credential_environment: present (%s)\n", strings.Join(credentialNames, ", "))
	}
	if loaded.Settings.Profile == nil {
		fmt.Fprintln(rt.stdout, "profile_check: skipped")
		fmt.Fprintln(rt.stdout, "next: select a profile with --profile or run aws-clip profiles")
		return exitOK
	}
	profile := *loaded.Settings.Profile
	if !containsString(names, profile) {
		fmt.Fprintf(rt.stdout, "profile_check: failed (profile %s is not configured)\n", profile)
		fmt.Fprintf(rt.stdout, "next: configure it with aws configure sso --profile %s or aws configure --profile %s\n", profile, profile)
		return exitUsage
	}
	if len(credentialNames) > 0 {
		fmt.Fprintln(rt.stdout, "profile_check: blocked (credential environment can override the selected profile)")
		fmt.Fprintln(rt.stdout, "next: clear the listed variables, then rerun doctor")
		return exitPolicy
	}
	record := inspectProfile(path, environ, loaded.Settings, profile, map[string]bool{})
	fmt.Fprintf(rt.stdout, "credential_source: %s\n", record.Authentication)
	fmt.Fprintf(rt.stdout, "effective_region: %s\n", displayOptionalString(effectiveRegion(path, loaded.Settings, environ, profile)))
	identity, status := readIdentity(path, loaded.Settings, environ, rt.stderr)
	if status != exitOK {
		fmt.Fprintln(rt.stdout, "authentication: failed")
		fmt.Fprintf(rt.stdout, "next: aws-clip --profile %s login\n", profile)
		return status
	}
	if status := verifyExpectedAccount(record, identity, rt.stderr); status != exitOK {
		fmt.Fprintln(rt.stdout, "account_guard: failed")
		return status
	}
	fmt.Fprintln(rt.stdout, "authentication: ok")
	fmt.Fprintf(rt.stdout, "account: %s\n", identity.Account)
	fmt.Fprintf(rt.stdout, "principal: %s\n", identity.ARN)
	if record.Protected {
		fmt.Fprintf(rt.stdout, "account_guard: ok (protected account %s)\n", *record.ExpectedAccount)
	} else {
		fmt.Fprintln(rt.stdout, "account_guard: standard")
	}
	return exitOK
}
