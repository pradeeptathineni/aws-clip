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

// Bound AWS-owned metadata and identity output before parsing
const sessionOutputMaxBytes = 1024 * 1024

const approveAllSSOSessions = "all-sso-sessions"

// Machine output omits SSO URLs, credential commands, access key IDs, and credentials
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

	// Role profiles inherit source authentication while execution stays on the selected role
	SessionKind  string `json:"-"`
	LoginProfile string `json:"-"`
}

type profilesDocument struct {
	SchemaVersion int             `json:"schema_version"`
	Profiles      []profileRecord `json:"profiles"`
}

// Account is the only approval boundary; UserID remains diagnostic context
type identityRecord struct {
	Account string `json:"Account"`
	ARN     string `json:"Arn"`
	UserID  string `json:"UserId"`
}

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

// Classification contains normalized command identity and guard facts, never argument values
type executionOperation struct {
	Command        string
	Classification string
	Changing       bool
	Destructive    bool
	Costly         bool
	Sensitive      bool
}

// boundedOutput discards overflow while reporting it consumed to bound memory without blocking
type boundedOutput struct {
	buffer   bytes.Buffer
	limit    int
	exceeded bool
}

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

func (output *boundedOutput) Bytes() []byte {
	return output.buffer.Bytes()
}

func (output *boundedOutput) String() string {
	return output.buffer.String()
}

// Explicit wrapper selection prevents fallback to another account's AWS default
func selectedProfile(settings Settings) (string, error) {
	if settings.Profile == nil {
		return "", errors.New("an explicit profile is required; use --profile, AWS_CLIP_PROFILE, or profile in the configuration file")
	}
	return *settings.Profile, nil
}

// Delegate profile paths, merging, ordering, and platform behavior to AWS CLI
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

// Reject unsafe or oversized AWS output before exposing any profile name
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

// Read only non-secret fields; presence probes discard credentials and command text
// Source chains use cycle detection and a fixed depth bound
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
		// Authentication follows the source while identity stays on the selected role
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
		record.Authentication = "credential process"
		return record
	}
	if hasConfigValue(path, environ, profile, "aws_access_key_id") {
		record.Authentication = "static access keys"
		return record
	}
	return record
}

// Treat failed, oversized, or unsafe non-secret metadata as absent
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

// Send values directly to the null device because configuration may contain secrets
func hasConfigValue(path string, environ []string, profile, key string) bool {
	return runAWS(path, []string{"configure", "get", key, "--profile", profile}, inspectionEnvironment(environ), strings.NewReader(""), nil, io.Discard) == exitOK
}

func stringPointer(value string) *string {
	copy := value
	return &copy
}

// Resolve account and role through STS rather than infer them from local configuration
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

// Preserve AWS diagnostics and status on failure; validate bounded JSON before safety decisions
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

// Return nil rather than guess from an unrecognized principal ARN
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

// Ignore unsafe ambient values so output records remain structurally sound
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
		// Repeat with attached diagnostics so provider failures retain AWS detail and status
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

// Limit login output to non-secret authentication and identity facts
func writeLoginResult(output io.Writer, profile profileRecord, identity identityRecord, session string) {
	fmt.Fprintln(output, "AWS login")
	fmt.Fprintf(output, "  profile: %s\n", profile.Name)
	fmt.Fprintf(output, "  method: %s\n", profile.Authentication)
	fmt.Fprintf(output, "  session: %s\n", session)
	fmt.Fprintf(output, "  account: %s\n", identity.Account)
	fmt.Fprintf(output, "  principal: %s\n", identity.ARN)
}

// Require literal approval because AWS SSO logout clears every cached SSO session
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

// Verify STS identity before account approval so a profile name cannot satisfy a guard
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
		return identityRecord{}, exitIdentity
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

// Arguments must contain validated tokens; high-level S3 verbs need explicit handling
func classifyExecutionCommand(arguments []string) executionOperation {
	command := arguments[0] + ":" + arguments[1]
	operation := executionOperation{
		Command:        command,
		Classification: "unknown; treated as mutating",
		Changing:       true,
		Sensitive:      isSensitiveOutputOperation(command),
	}
	if isReadOperation(arguments[1]) {
		operation.Classification = "read-only"
		operation.Changing = false
	} else if isKnownMutatingOperation(arguments[0], arguments[1]) {
		operation.Classification = "mutating"
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

func isKnownMutatingOperation(service, operation string) bool {
	for _, prefix := range []string{
		"add-", "associate-", "attach-", "authorize-", "cancel-", "close-", "create-", "delete-", "deregister-", "detach-",
		"disable-", "disassociate-", "enable-", "launch-", "modify-", "move-", "put-", "purchase-", "reboot-", "register-",
		"remove-", "restore-", "revoke-", "run-", "scale-", "set-", "start-", "stop-", "tag-", "terminate-", "untag-", "update-", "upload-",
	} {
		if strings.HasPrefix(operation, prefix) {
			return true
		}
	}
	if service == "s3" {
		switch operation {
		case "cp", "mv", "rb", "rm", "sync":
			return true
		}
	}
	return service == "cloudformation" && operation == "deploy"
}

// Return only the option name so diagnostics never echo supplied values
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

// Preserve stable diagnostic order without reading credential values
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

// Disable prompts only for internal probes; user-requested operations remain interactive
func inspectionEnvironment(environ []string) []string {
	result := setEnvironment(environ, "AWS_PAGER", "")
	return setEnvironment(result, "AWS_CLI_AUTO_PROMPT", "off")
}

// Reject ambient credential overrides while exposing variable names only
func rejectCredentialEnvironment(environ []string, stderr io.Writer) int {
	names := credentialEnvironmentNames(environ)
	if len(names) == 0 {
		return exitOK
	}
	fmt.Fprintf(stderr, "aws-clip: credential environment could override the selected profile: %s\n", strings.Join(names, ", "))
	fmt.Fprintln(stderr, "aws-clip: clear these variables for profile isolation, or invoke aws directly when environment credentials are intentional")
	return exitPolicy
}

func verifyExpectedAccount(profile profileRecord, identity identityRecord, stderr io.Writer) int {
	if !profile.Protected || *profile.ExpectedAccount == identity.Account {
		return exitOK
	}
	fmt.Fprintf(stderr, "aws-clip: account mismatch for protected profile %q: expected %s, current %s\n", profile.Name, *profile.ExpectedAccount, identity.Account)
	return exitIdentity
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

// Probe identity only when selected; preserve native STS status on failure
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
