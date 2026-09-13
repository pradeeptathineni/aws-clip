# AWS CLI Plus

`aws-clip` is a transparent execution wrapper for an installed AWS CLI v2. It
keeps AWS service coverage, credentials, request serialization, output formats,
and retries in the official CLI while adding an explicit wrapper boundary,
predictable configuration, safer non-interactive behavior, and local
diagnostics.

## Requirements and installation

- AWS CLI v2 available on `PATH`, or its executable path configured explicitly
- Go 1.22 or newer to build from source

Build the executable locally:

```sh
make build
./bin/aws-clip doctor
```

Or install it into the active Go binary directory:

```sh
go install ./cmd/aws-clip
aws-clip doctor
```

The wrapper checks the configured executable using `aws --version` and rejects
AWS CLI v1. Version inspection is local and does not make an AWS API request.

## Passing through AWS commands

Use `exec --` to separate wrapper options from AWS arguments:

```sh
aws-clip exec -- sts get-caller-identity
aws-clip --profile production --region us-east-1 exec -- ec2 describe-instances --output json
aws-clip exec -- s3 cp "release notes.txt" "s3://example-bucket/releases/release notes.txt"
```

The separator is mandatory. Every value after it is passed as a distinct
argument without shell evaluation, interpolation, or re-tokenization. Quote
values for your shell exactly as you would when invoking `aws` directly.

Before each operation, `aws-clip` runs a captured `--version` check. It then
starts exactly one AWS operation process. In normal use, the child inherits
stdin, stdout, and stderr directly, and its exit status is returned unchanged.
Common termination signals are forwarded; on POSIX systems a signal-terminated
child is reported using the conventional `128 + signal` status.

When any standard stream is not a terminal, the wrapper sets `AWS_PAGER` to an
empty value and `AWS_CLI_AUTO_PROMPT=off`. This prevents a pager or interactive
prompt from blocking automation. The wrapper itself writes nothing to stdout
during `exec`, so stdout remains exclusively AWS CLI output. Interactive runs
leave both AWS settings untouched.

## Configuration

Configuration precedence is deterministic, from highest to lowest:

1. Wrapper command flags before `--`
2. `AWS_CLIP_*` environment variables
3. The user configuration file
4. Wrapper defaults

Only the AWS executable has a wrapper default (`aws`). Every other unset value
is omitted so the AWS CLI can apply its normal command-line, environment,
profile, and built-in behavior.

| Wrapper flag | Environment variable | JSON key | Effect |
| --- | --- | --- | --- |
| `--aws-binary PATH` | `AWS_CLIP_AWS_BINARY` | `aws_binary` | AWS CLI v2 executable; defaults to `aws` |
| `--profile NAME` | `AWS_CLIP_PROFILE` | `profile` | Sets `AWS_PROFILE` for the child |
| `--region REGION` | `AWS_CLIP_REGION` | `region` | Sets `AWS_REGION` for the child |
| `--retry-mode MODE` | `AWS_CLIP_RETRY_MODE` | `retry_mode` | Sets `AWS_RETRY_MODE`; accepts `legacy`, `standard`, or `adaptive` |
| `--max-attempts NUMBER` | `AWS_CLIP_MAX_ATTEMPTS` | `max_attempts` | Sets `AWS_MAX_ATTEMPTS`; the initial request counts as an attempt |
| `--connect-timeout SECONDS` | `AWS_CLIP_CONNECT_TIMEOUT` | `connect_timeout_seconds` | Prepends the AWS global `--cli-connect-timeout` option; `0` disables it |
| `--read-timeout SECONDS` | `AWS_CLIP_READ_TIMEOUT` | `read_timeout_seconds` | Prepends the AWS global `--cli-read-timeout` option; `0` disables it |

The default file is `aws-clip/config.json` beneath the platform user
configuration directory:

- Linux and other Unix systems: `$XDG_CONFIG_HOME`, or `$HOME/.config`
- macOS: `$HOME/Library/Application Support`
- Windows: `%AppData%`

Select another file with `--config PATH` or `AWS_CLIP_CONFIG_FILE`. Unlike the
optional default file, an explicitly selected file must exist and be valid.
Unknown JSON keys and trailing data are rejected to catch configuration errors.

Example configuration:

```json
{
  "aws_binary": "/usr/local/bin/aws",
  "profile": "operations",
  "region": "us-east-1",
  "retry_mode": "standard",
  "max_attempts": 3,
  "connect_timeout_seconds": 10,
  "read_timeout_seconds": 60
}
```

These settings contain no credentials. Existing AWS credential environment
variables, shared files, IAM roles, IAM Identity Center sessions, and other AWS
providers pass through unchanged. `aws-clip` does not read or persist credential
values.

## Doctor

Run a local readiness check with:

```sh
aws-clip doctor
```

`doctor` reports the resolved executable, parsed AWS CLI version, configuration
file state, effective non-secret wrapper settings, and stream mode. It does not
call STS or any other AWS API, inspect account identity, or print credential
values. Missing executables, AWS CLI v1, and unrecognized version output produce
an actionable error and a nonzero status.

## Exit statuses

| Status | Meaning |
| --- | --- |
| AWS CLI status | The operation started; its status is returned unchanged |
| `2` | Invalid wrapper syntax or configuration |
| `126` | The configured executable exists but cannot be validated or started |
| `127` | The AWS CLI executable could not be found |

AWS diagnostics are not reformatted or hidden. For automation, choose an AWS
machine-readable format explicitly, for example `--output json`; the wrapper
does not silently change output format or query behavior.

## Troubleshooting

- **`AWS CLI executable not found`**: install AWS CLI v2, add it to `PATH`, or
  use `--aws-binary`/`AWS_CLIP_AWS_BINARY`.
- **`AWS CLI v1 is not supported`**: upgrade to v2 and ensure the selected path
  is the v2 installation.
- **Version check failed**: run the configured executable with `--version` and
  confirm it exits successfully with standard `aws-cli/2...` version output.
- **Configuration error**: validate that the file is one JSON object, contains
  only documented keys, uses integer timeout/attempt values, and uses a listed
  retry mode.
- **Unexpected AWS result or authentication failure**: run `aws-clip doctor` to
  confirm non-secret context, then use the AWS CLI's normal configuration and
  diagnostic facilities. The wrapper deliberately leaves credential resolution
  and service errors to AWS CLI.

## Development

```sh
make check
```

The check target verifies formatting, runs static analysis, and executes the
hermetic process-level test suite. Tests use a local fake executable and do not
contact AWS.
