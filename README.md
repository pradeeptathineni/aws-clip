# AWS CLI Plus

AWS CLI Plus (`aws-clip`) makes multi-profile AWS CLI work safer and easier to
understand. It discovers the profiles already known to AWS CLI v2, follows each
profile's authentication path, verifies the active account and principal, and
puts account-bound guards in front of risky commands.

It does not replace AWS CLI. AWS CLI v2 remains responsible for configuration,
credentials, IAM Identity Center, local login, service coverage, retries,
requests, and output formatting. Use `aws` directly for ordinary one-off work.
Use `aws-clip` when profile isolation, identity visibility, production account
checks, or explicit approval materially reduces operational risk.

## Install

Requirements:

- AWS CLI v2 on `PATH`, or its executable path configured explicitly
- Go 1.22 or newer when building from source

```sh
make build
./bin/aws-clip doctor
```

Or install into the active Go binary directory:

```sh
go install ./cmd/aws-clip
aws-clip doctor
```

## Start with a profile

List the profiles AWS CLI has already merged from its normal configuration:

```sh
aws-clip profiles
aws-clip profiles --format json
```

The text view shows Region, authentication path, configured SSO account and
role when available, selection, and protection status. It never prints access
key IDs, credential-process commands, SSO start URLs, login-session names, or
credential values. The JSON response has `schema_version: 1` and an ordered
`profiles` array; an unavailable Region is `null`.

`aws-clip` does not create profiles. Use AWS CLI's own configuration commands,
then select a profile explicitly:

```sh
aws configure sso --profile development
aws-clip --profile development login
aws-clip --profile development context
```

Profile selection can also come from `AWS_CLIP_PROFILE` or the user
configuration file. Lifecycle and guarded execution commands do not fall back
to AWS CLI's default profile.

## Login and logout

`login` first asks STS whether the selected profile already resolves valid
credentials. A valid session is reused. Otherwise it follows safe AWS profile
metadata, including `source_profile` chains:

- IAM Identity Center profiles run `aws sso login` for the owning profile
- AWS local login profiles run `aws login` for the owning profile
- role profiles use the login path of their source profile
- configured profiles with no declared provider can bootstrap AWS local login
  after an identity probe fails and the installed AWS CLI supports it
- static keys, credential processes, web identity, instance/container roles,
  and the default provider chain remain the owning provider's responsibility

After authentication, `aws-clip` verifies STS identity again and reports the
account and principal. It never exports or stores session credentials.

```sh
aws-clip --profile production login
```

Local-login logout is scoped to its login profile:

```sh
aws-clip --profile development logout
```

AWS CLI's SSO logout clears every cached SSO session, not only the selected
profile. `aws-clip` makes that wider effect explicit:

```sh
aws-clip --profile development logout --approve all-sso-sessions
```

Profiles backed by external or static providers have no AWS CLI login/logout
action; the diagnostic names the provider that must be refreshed.

## Verify the active context

`context` calls `aws sts get-caller-identity` through the selected AWS CLI
profile and reports only non-secret operational context:

```sh
aws-clip --profile production --region us-east-1 context
aws-clip --profile production context --format json
```

The result includes profile, observed account ID, principal ARN, user ID,
derived role or user name, effective Region, configured credential source,
source profile, and account-guard state. JSON output is a stable
`schema_version: 1` contract. The observed STS account, rather than the profile
name, is the value used for safety decisions.

Region precedence is wrapper flag, `AWS_CLIP_REGION`, user configuration,
`AWS_REGION`, `AWS_DEFAULT_REGION`, then the selected AWS profile. Unset retry
and timeout settings continue to defer to AWS CLI.

## Guarded command execution

`exec` is intentionally more restrictive than `aws --profile`. It requires an
explicit profile, rejects context-changing AWS arguments, verifies STS identity,
shows the verified profile/account/principal/Region on stderr, applies account
guards, then passes literal arguments and standard streams to AWS CLI:

```sh
aws-clip --profile development exec -- ec2 describe-instances --output json
```

The `--` separator is mandatory. Values after it are never run through a shell.
Use wrapper `--profile` and `--region`; `--profile`, `--region`,
`--endpoint-url`, and `--no-sign-request` after the separator are rejected
because they would invalidate the verified context.

Destructive and potentially costly operations require approval using the
account returned by the preflight. Credential-, token-, or secret-returning
operations receive the same guard. The blocked preview prints the exact account
approval needed:

```sh
aws-clip --profile development exec -- ec2 terminate-instances --instance-ids i-example
aws-clip --profile development exec --approve-account 123456789012 -- \
  ec2 terminate-instances --instance-ids i-example
```

Destructive recognition covers common operation prefixes such as `delete-`,
`terminate-`, `remove-`, `disable-`, `stop-`, and `revoke-`, plus `s3 rm`,
`s3 rb`, and `s3 sync --delete`. Potential-cost recognition covers common
`create-`, `launch-`, `purchase-`, `run-`, `scale-`, and `start-` operations,
S3 copy/move/sync, plus common deployment commands. These are conservative
name-based checks, not
replacements for IAM, service control policies, budgets, backups, or change
management.

### Protect production profiles

Bind a high-risk profile to its expected 12-digit account in the configuration
file:

```json
{
  "profile": "production",
  "region": "us-east-1",
  "protected_profiles": {
    "production": "123456789012"
  }
}
```

Every live context or execution check fails if `production` resolves to a
different account. On the expected account, every non-read operation requires
`--approve-account 123456789012`; read-oriented commands do not. Protection is
configuration-file-only, so an environment variable or one-off flag cannot
weaken it.

For isolation, `context`, `login`, guarded `exec`, and workflow execution block
credential environment variables such as `AWS_ACCESS_KEY_ID`,
`AWS_SESSION_TOKEN`, web-identity settings, and container credential endpoints.
Their names are reported, never their values. Clear them when a profile should
be authoritative. If environment credentials are intentional, use AWS CLI
directly.

## Doctor diagnostics

```sh
aws-clip doctor
aws-clip --profile production doctor
```

`doctor` verifies AWS CLI v2, resolves the local aws-clip configuration, lists
configured AWS profiles, and checks for credential environment conflicts. With
an explicit profile it also reports the authentication path and effective
Region, calls STS to verify the current identity, and validates any protected
account binding. Failed checks include the next useful command. AWS diagnostic
text and exit status remain available when a subprocess fails.

## Advanced reviewed workflows

A Makefile or script is usually the simpler choice for plain repeatability.
Keep an aws-clip workflow only when its strict schema, policy review, named
approval, identity preflight, account guard, literal argument handling,
fail-fast execution, and per-step visibility provide useful controls.

A workflow is a versioned JSON file containing named AWS CLI steps:

```json
{
  "schema_version": 1,
  "name": "release-check",
  "description": "Confirm identity and inspect the deployed stack",
  "steps": [
    {
      "name": "identity",
      "command": ["sts", "get-caller-identity"]
    },
    {
      "name": "stack",
      "command": [
        "cloudformation",
        "describe-stacks",
        "--stack-name",
        "application",
        "--output",
        "json"
      ]
    }
  ]
}
```

Previewing is local and does not run AWS CLI or call AWS:

```sh
aws-clip --profile production plan release-check.json
aws-clip --profile production plan --format json release-check.json
```

The plan shows effective context, protected account configuration, whether an
account approval will be required, each `service:operation`, and its policy
decision. Argument values are omitted because they may contain sensitive
request data. JSON plans are a `schema_version: 1` contract with ordered steps.

Run only after reviewing the file and plan:

```sh
aws-clip --profile production run --approve release-check release-check.json
```

Every run requires the exact workflow name. Runs also require an explicit
profile and a live STS identity preflight. A destructive or sensitive-output
step requires `--approve-account`; any change on a protected profile does too.
All policy and approvals are checked before the first workflow step. Steps run
in order, stop on the first failure, retain AWS output and diagnostics, and
return the failing AWS status unchanged. AWS CLI remains responsible for
request retries.

### Workflow policy

Read-oriented operations such as `describe-*`, `get-*`, `head-*`, `list-*`,
`lookup-*`, `search-*`, and `validate-*` are allowed by default. Known
credential-, token-, and secret-returning operations are blocked even when the
name looks read-only. All other operations need a narrow allow rule. Deny rules
always win:

```json
{
  "workflow_policy": {
    "allow": [
      "cloudformation:deploy",
      "s3api:put-object"
    ],
    "deny": [
      "*:delete-*",
      "ec2:terminate-*"
    ],
    "max_steps": 20
  }
}
```

Rules use lowercase `service:operation` with `*` as the only wildcard. Policy
supports at most 100 allow and 100 deny rules. `max_steps` must be from 1 to
100 and defaults to 20. Workflow files are limited to 1 MiB, commands to 256
arguments and 64 KiB of argument data, and names/descriptions to printable
single-line text. Unknown JSON fields and trailing data are rejected.

## Configuration

The default file is `aws-clip/config.json` below the platform user
configuration directory:

- Linux and other Unix systems: `$XDG_CONFIG_HOME`, or `$HOME/.config`
- macOS: `$HOME/Library/Application Support`
- Windows: `%AppData%`

Select another file with `--config PATH` or `AWS_CLIP_CONFIG_FILE`. An optional
default file may be absent; an explicitly selected file must exist. Unknown
keys and trailing JSON are errors.

Runtime precedence, highest first, is wrapper flag, `AWS_CLIP_*` environment,
user configuration, then wrapper default:

| Wrapper flag | Environment variable | JSON key | Effect |
| --- | --- | --- | --- |
| `--aws-binary PATH` | `AWS_CLIP_AWS_BINARY` | `aws_binary` | AWS CLI v2 executable; default `aws` |
| `--profile NAME` | `AWS_CLIP_PROFILE` | `profile` | Select AWS profile |
| `--region REGION` | `AWS_CLIP_REGION` | `region` | Set `AWS_REGION` for AWS CLI |
| `--retry-mode MODE` | `AWS_CLIP_RETRY_MODE` | `retry_mode` | `legacy`, `standard`, or `adaptive` |
| `--max-attempts NUMBER` | `AWS_CLIP_MAX_ATTEMPTS` | `max_attempts` | Set total AWS request attempts |
| `--connect-timeout SECONDS` | `AWS_CLIP_CONNECT_TIMEOUT` | `connect_timeout_seconds` | Set AWS socket connection timeout; `0` disables |
| `--read-timeout SECONDS` | `AWS_CLIP_READ_TIMEOUT` | `read_timeout_seconds` | Set AWS socket read timeout; `0` disables |

`protected_profiles` and `workflow_policy` are file-only safety settings.
Automation should pin and protect the selected configuration file.

When any standard stream is not a terminal, `aws-clip` sets `AWS_PAGER` to an
empty value and `AWS_CLI_AUTO_PROMPT=off` so automation cannot block on a pager
or prompt. Interactive runs leave both settings unchanged.

## Safety and limitations

- `aws-clip` never retains, writes, prints, exports, or caches credential values
- AWS command stdout and stderr remain AWS-owned and can contain sensitive
  service data; protect them as you would direct AWS CLI output
- Profile and workflow classification uses safe configuration metadata and
  operation names; IAM and AWS Organizations remain authoritative
- Guarded commands require network access to STS before the service operation
- Identity preflight and the service command are separate AWS CLI processes;
  an external credential provider can change between them
- Intentionally environment-backed credentials are outside profile isolation
- There is no interactive profile selector, browser-console launcher, or
  credential exporter
- Workflows are sequential; there are no variables, conditionals, output
  chaining, concurrency, rollback, or remote orchestration
- Multi-step workflow stdout is the concatenation of each AWS command's output;
  use `exec` for one stable machine-readable service response

## Exit statuses

| Status | Meaning |
| --- | --- |
| `0` | Requested check or operation succeeded |
| AWS CLI status | An AWS CLI command started and failed; its status is unchanged |
| `2` | Invalid syntax, configuration, profile, workflow, or acknowledgement |
| `3` | Identity isolation, account guard, or workflow policy blocked execution |
| `126` | AWS CLI could not be validated or started, or returned invalid local data |
| `127` | AWS CLI executable was not found |

## Development

```sh
make check
```

The check target verifies formatting, runs static analysis, and executes a
hermetic process-level suite. Tests use a local fake executable and do not
contact AWS.
