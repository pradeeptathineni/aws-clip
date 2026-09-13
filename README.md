# AWS CLI Plus

AWS CLI Plus (`aws-clip`) turns an installed AWS CLI v2 into previewable,
policy-controlled operational workflows. It is for work that should be
repeatable and reviewable: inventory checks, release sequences, verification,
and explicitly approved changes.

It does not replace the AWS CLI. AWS CLI v2 still provides service coverage,
credential resolution, request handling, retries, and output formatting.
`aws-clip` adds a small local layer for reusable sequences, policy decisions,
approval, fail-fast execution, and step-by-step visibility.

Use `aws-clip` when a sequence should be checked and run the same way more than
once. Use `aws` directly for ordinary exploration and one-off commands. The
`aws-clip exec` command is a low-level compatibility escape hatch; it is useful
when wrapper configuration is needed, but it intentionally bypasses workflow
policy and approval.

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

`doctor` performs a local `aws --version` check, rejects AWS CLI v1, and shows
the effective non-secret context and workflow policy summary. It does not call
an AWS API or inspect account identity.

## Create, preview, and run a workflow

A workflow is a versioned JSON file containing named AWS CLI steps. Command
arguments are arrays, so they are passed literally without a shell:

```json
{
  "schema_version": 1,
  "name": "release-check",
  "description": "Confirm identity and inspect the deployed stack",
  "steps": [
    {
      "name": "identity",
      "description": "Confirm which caller will perform later work",
      "command": ["sts", "get-caller-identity"]
    },
    {
      "name": "stack",
      "description": "Read the current application stack",
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

The schema is strict: unknown fields and trailing JSON are rejected. Names and
descriptions must be printable single-line text; step names must be unique; and
each command must begin with a lowercase service and operation. Files are
limited to 1 MiB, each step to 256 arguments and 64 KiB of argument data, and
the policy controls the maximum number of steps. Use AWS `file://` or `fileb://`
parameters for larger request documents.

Preview it first. Planning reads configuration and the workflow, evaluates
policy, and makes no AWS CLI or AWS API call:

```sh
aws-clip --profile production --region us-east-1 plan release-check.json
```

The preview shows the effective profile, Region, retry and timeout settings,
step descriptions, `service:operation` identifiers, and each policy decision.
It deliberately does not print argument values, which may contain sensitive
request data. For a stable machine-readable preview, use:

```sh
aws-clip plan --format json release-check.json
```

The JSON contract contains `schema_version`, workflow identity, effective
`context`, and the overall `allowed` result. Each ordered step contains
`index`, `name`, optional `description`, `command`, `additional_arguments`,
`decision`, and `reason`. Unset context settings are `null`, optional
descriptions are omitted, and argument values are never part of this output.

After reviewing the plan, run it by typing the exact workflow name:

```sh
aws-clip --profile production --region us-east-1 \
  run release-check.json --approve release-check
```

`run` validates the complete workflow and policy before it checks AWS CLI v2 or
starts a step. It then executes steps in file order, writes lifecycle messages
to stderr, leaves AWS stdout and stderr attached, and stops at the first failed
step. The failing AWS CLI status is returned unchanged. There is no implicit
retry around a step; AWS CLI retry configuration remains authoritative.

Every workflow run requires named approval, including read-only workflows.
This makes an unattended run deliberate as well: the caller must include the
reviewed workflow name in its invocation.

## Workflow policy

By default, workflows allow operations whose AWS CLI operation begins with a
read-oriented name such as `describe-`, `get-`, `head-`, `list-`, `lookup-`,
`search-`, or `validate-`, plus common read commands including `ls`, `scan`,
`select`, `tail`, and `wait`. Known credential-, token-, and secret-returning
operations require an explicit allow rule even when their name looks read-only.
Other operations are also blocked until configuration allows them. This
conservative name-based rule is a local safeguard, not a substitute for IAM
authorization or AWS Organizations controls.

Add narrowly scoped exceptions and local blocks in the user configuration:

```json
{
  "profile": "operations",
  "region": "us-east-1",
  "retry_mode": "standard",
  "max_attempts": 3,
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

Rules match the lowercase `service:operation` at the beginning of each step.
`*` is the only wildcard and can match any number of characters. A deny match
always wins over the read-oriented default and configured allow rules. Policy
supports at most 100 allow and 100 deny rules, and `max_steps` must be from 1
through 100. When omitted, the workflow limit is 20 steps.

Changing operations therefore require two separate decisions: a persistent
allow rule and the exact `--approve` value for a run. Destructive operations
can also be denied broadly even if another allow pattern would match.

## Configuration and precedence

The default configuration file is `aws-clip/config.json` beneath the platform
user configuration directory:

- Linux and other Unix systems: `$XDG_CONFIG_HOME`, or `$HOME/.config`
- macOS: `$HOME/Library/Application Support`
- Windows: `%AppData%`

Select another file with `--config PATH` or `AWS_CLIP_CONFIG_FILE`. The optional
default file may be absent; an explicitly selected file must exist. JSON keys
are strict, and unknown keys or trailing data are errors.

Runtime settings use this precedence, from highest to lowest:

1. Wrapper flags
2. `AWS_CLIP_*` environment variables
3. The user configuration file
4. Wrapper defaults

| Wrapper flag | Environment variable | JSON key | Effect |
| --- | --- | --- | --- |
| `--aws-binary PATH` | `AWS_CLIP_AWS_BINARY` | `aws_binary` | AWS CLI v2 executable; default `aws` |
| `--profile NAME` | `AWS_CLIP_PROFILE` | `profile` | Sets `AWS_PROFILE` for AWS CLI |
| `--region REGION` | `AWS_CLIP_REGION` | `region` | Sets `AWS_REGION` for AWS CLI |
| `--retry-mode MODE` | `AWS_CLIP_RETRY_MODE` | `retry_mode` | Sets `AWS_RETRY_MODE`: `legacy`, `standard`, or `adaptive` |
| `--max-attempts NUMBER` | `AWS_CLIP_MAX_ATTEMPTS` | `max_attempts` | Sets `AWS_MAX_ATTEMPTS`; the initial request counts |
| `--connect-timeout SECONDS` | `AWS_CLIP_CONNECT_TIMEOUT` | `connect_timeout_seconds` | Adds AWS `--cli-connect-timeout`; `0` disables it |
| `--read-timeout SECONDS` | `AWS_CLIP_READ_TIMEOUT` | `read_timeout_seconds` | Adds AWS `--cli-read-timeout`; `0` disables it |

Workflow policy is configuration-file-only so an ambient environment variable
or ad hoc flag cannot weaken it. `--config` still selects the complete policy,
so automation should pin and protect the intended configuration file.

Unset runtime settings are omitted, allowing AWS CLI command-line,
environment, profile, and built-in precedence to work normally. Text and path
settings that may appear in diagnostics must be printable and single-line.

## Safety and credential boundary

`aws-clip` does not inspect or persist credential values, and it never copies
AWS command argument values into plans or its own diagnostics. Existing AWS
credential environment variables, shared configuration, IAM roles, IAM
Identity Center sessions, credential processes, and other AWS providers pass
to AWS CLI unchanged. Profile and Region selection affect AWS CLI in the normal
way; a plan does not prove an account identity or permission set.

Do not put credentials or secret literals in workflow files. AWS CLI output is
not captured or rewritten and can itself contain sensitive service data, so
protect workflow output as you would direct `aws` output. Workflow descriptions
and names are shown in plans and execution messages.

When any standard stream is not a terminal, `aws-clip` sets `AWS_PAGER` to an
empty value and `AWS_CLI_AUTO_PROMPT=off`. This prevents a pager or prompt from
blocking automation. Interactive runs leave both settings untouched.

## Raw compatibility execution

`exec` applies the same resolved profile, Region, retry, timeout, AWS CLI v2,
stream, and exit-status behavior to one arbitrary AWS command:

```sh
aws-clip --profile production exec -- ec2 describe-instances --output json
aws-clip exec -- s3 cp "release notes.txt" "s3://example/releases/release notes.txt"
```

The `--` separator is mandatory. Everything after it is a distinct AWS CLI
argument and is never evaluated or re-tokenized by a shell. `exec` does not
apply workflow policy, named approval, sequencing, or plan output. Prefer
direct `aws` when these wrapper settings add no value; prefer `plan` and `run`
when safeguards and repeatability matter.

## Exit statuses

| Status | Meaning |
| --- | --- |
| `0` | Local check, plan, or all workflow steps succeeded |
| AWS CLI status | An `exec` operation or workflow step started and failed; its status is unchanged |
| `2` | Invalid syntax, configuration, approval, or workflow file |
| `3` | Workflow policy blocked one or more steps |
| `126` | AWS CLI exists but cannot be validated or started, or plan output failed |
| `127` | AWS CLI executable was not found |

AWS diagnostics are not hidden or reformatted. For composable AWS output,
choose an AWS machine format explicitly, such as `--output json`, and remember
that a multi-step run writes each step's output to the same stdout stream.

## Current limitations

- Workflows are sequential JSON files. They do not provide variables,
  conditionals, concurrency, output chaining, rollback, or remote orchestration.
- Policy identifies the first two command entries as `service:operation`; AWS
  global options cannot precede them in a workflow step.
- The read-oriented default is based on operation names. IAM and organization
  policy remain the authoritative security boundary.
- Plan output omits argument values. Review the protected workflow file itself
  when target-level detail is required.
- `exec` is an explicit policy bypass and should not be used as the primary
  interface for controlled automation.

## Troubleshooting

- **Workflow blocked**: inspect `plan`, then narrow the operation or add the
  smallest justified allow rule. Check deny rules first because they win.
- **Approval rejected**: pass `--approve` followed by the exact workflow
  `name`; values are case-sensitive.
- **AWS CLI executable not found**: install AWS CLI v2, add it to `PATH`, or
  configure `--aws-binary`/`AWS_CLIP_AWS_BINARY`.
- **AWS CLI v1 is not supported**: upgrade to v2 and check the selected binary.
- **Authentication or service failure**: use `doctor` for non-secret context,
  then use AWS CLI's normal diagnostic and credential facilities.

## Development

```sh
make check
```

The check target verifies formatting, runs static analysis, and executes a
hermetic process-level suite. Tests use a local fake executable and do not
contact AWS.
