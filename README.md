# ddash

Lightweight process sandboxing for macOS. One command, zero setup.

```bash
ddash run -- ./script.sh
```

The script runs with **no network access**, **no access to your secrets**, and **can only write to the current directory**. Everything else is denied at the kernel level.

## Why?

macOS ships with a powerful process sandboxing engine, but using it requires writing Scheme-based policy files by hand. Nobody does this. ddash makes it a one-liner.

## Install

```bash
brew tap marklechner/tap && brew install ddash
```

Or from source (requires Go):

```bash
go install github.com/marklechner/ddash@latest
```

## Quick start

```bash
# Run anything sandboxed — network blocked, writes to cwd only, secrets scrubbed
ddash run -- python script.py

# Allow network when you need it
ddash run --allow-net -- npm install

# Full read-only — nothing gets written anywhere
ddash run --deny-write -- ./suspicious-binary

# Pass env vars through when the command needs credentials
ddash run --allow-net --pass-env -- ./deploy.sh

# Not sure what a script needs? Trace it first
ddash trace -- python train.py

# Set up a per-project policy interactively
ddash sandbox init -i
```

## Practical examples

### Sandbox an AI coding agent

Let an agent read and modify your project, but prevent it from accessing your SSH keys, cloud credentials, or phoning home:

```json
{
  "name": "coding-agent",
  "allow_net": [],
  "allow_read": ["."],
  "allow_write": ["."]
}
```

```bash
ddash run -- aider --model claude-3.5-sonnet
```

The agent can read and edit code in the current directory. It cannot reach the internet, read `~/.ssh`, `~/.aws`, or `~/.config`, or write outside the project.

### Sandbox a build system

Allow `make` to build your project and write to a build dir, but block network access so the build can't exfiltrate source code or secrets:

```json
{
  "name": "secure-build",
  "allow_net": [],
  "allow_read": [".", "/opt/homebrew"],
  "allow_write": [".", "./build", "/tmp"]
}
```

```bash
ddash run -- make -j8
```

### Install packages with network, but no filesystem escape

Let npm/pip download packages but only write to the project directory:

```json
{
  "name": "package-install",
  "allow_net": ["*"],
  "allow_read": ["."],
  "allow_write": ["."]
}
```

```bash
ddash run -- npm install
ddash run -- pip install -r requirements.txt --target ./vendor
```

### Run untrusted scripts read-only

Inspect a downloaded script without letting it modify anything:

```bash
ddash run --deny-write -- bash setup.sh --dry-run
```

No config file needed — the `--deny-write` flag creates a fully read-only sandbox on the fly.

### Data analysis with controlled output

Let a data pipeline read input files and write results, but block network access to prevent data exfiltration:

```json
{
  "name": "data-pipeline",
  "allow_net": [],
  "allow_read": [".", "./data", "/datasets"],
  "allow_write": ["./output"]
}
```

```bash
ddash run -- python pipeline.py --input ./data --output ./output
```

### Audit a third-party CLI tool

Not sure what a binary does? Trace it first, then sandbox it:

```bash
# Step 1: See what it tries to access
ddash trace -- ./vendor-tool export --format csv

# Step 2: Review the suggested policy, save it
# Step 3: Run sandboxed
ddash run -- ./vendor-tool export --format csv
```

## Discover what a program needs (`trace`)

Run any command in trace mode — ddash monitors what it accesses and suggests a minimal policy:

```bash
ddash trace -- python train.py
```

```
Tracing python train.py...

Access summary:
  Network:    5 outbound connections (api.openai.com, pypi.org, ...)
  File reads: 142 (system: 98, project: 44)
  File writes: 3 (/tmp/cache.db, ./output.csv, ./model.pt)

Suggested .ddash.json:
  allow_net:   ["api.openai.com"]
  allow_read:  ["."]
  allow_write: [".", "/tmp"]

Save this config? [Y/n]
```

## Interactive policy setup

```bash
ddash sandbox init -i
```

Walks you through building a `.ddash.json` step by step:

```
Project name [my-project]:
Allow network access? [y/N]: y
  Allow all hosts or specific ones? [all/specific]: specific
  Hosts (comma-separated): api.example.com, cdn.example.com
Allow writes outside current directory? [y/N]: n
```

## Configuration reference

A `.ddash.json` file defines a persistent sandbox policy per project. When present, `ddash run` applies it automatically.

| Field | Description |
|-------|-------------|
| `allow_net` | `[]` = deny all network. `["*"]` = allow all. Or list specific hosts. |
| `allow_read` | Filesystem read paths beyond system defaults. |
| `allow_write` | Filesystem write paths. `[]` = fully read-only. |

## Default security policy

| Resource | Default | Override |
|----------|---------|---------|
| Network | **Denied** | `--allow-net` or config |
| Filesystem reads | System paths + cwd | Config |
| Filesystem writes | cwd + `/tmp` | `--deny-write` for none |
| Environment variables | **Sensitive vars scrubbed** | `--pass-env` to allow all |
| Process execution | Allowed | — |

System paths (`/bin`, `/usr`, `/System`, `/Library`, `/opt/homebrew`) are always readable so programs can find interpreters and shared libraries.

### Environment scrubbing

By default, ddash strips environment variables that match known secret patterns before passing them to the sandboxed process. This prevents credential leakage even if a script reads `os.environ`.

Scrubbed patterns include:
- Cloud credentials: `AWS_*`, `AZURE_*`, `GCP_*`, `GOOGLE_*`
- API tokens: `GITHUB_TOKEN`, `GH_TOKEN`, `GITLAB_*`, `NPM_TOKEN`, `OPENAI_API*`, `ANTHROPIC_API*`, `HF_TOKEN`
- Infrastructure: `DATABASE_URL`, `REDIS_URL`, `DOCKER_*`, `SENTRY_*`, `DATADOG_*`
- Any variable containing `_SECRET`, `_TOKEN`, `_KEY`, `_PASSWORD`, `_CREDENTIAL`, or `_AUTH`

Use `--pass-env` when the sandboxed command legitimately needs credentials (e.g., an API client with network access).

## What ddash protects against (tested)

Every release is verified against these attack scenarios:

| Attack | Result |
|--------|--------|
| Script reads `~/.ssh/` private keys | **Blocked** — `Operation not permitted` |
| Script reads `~/.aws/credentials` | **Blocked** — path outside sandbox |
| Script opens outbound network connection | **Blocked** — DNS and TCP denied |
| Script writes to home directory (`~/`) | **Blocked** — write restricted to cwd |
| Script writes to arbitrary path (`/etc`, `/var`) | **Blocked** — write restricted to cwd |
| Subprocess tries to escape sandbox (e.g., `cat ~/.ssh/id_ed25519`) | **Blocked** — child processes inherit sandbox |
| Shell redirect escape (`sh -c 'echo x > ~/file'`) | **Blocked** — sandbox is kernel-level, applies to all children |
| Script reads `GITHUB_TOKEN` from environment | **Scrubbed** — variable removed before exec |
| Script reads `AWS_SECRET_ACCESS_KEY` from env | **Scrubbed** — variable removed before exec |
| `--deny-write` bypass via `/tmp` | **Blocked** — deny-write blocks all paths including `/tmp` |

## How it works

ddash generates macOS [Sandbox Profiles](https://reverse.put.as/wp-content/uploads/2011/09/Apple-Sandbox-Guide-v1.0.pdf) (SBPL) and runs commands through `sandbox-exec`. This is the same kernel-level sandboxing used by Safari, Mail, and other system apps. It operates at the syscall level — near-zero overhead, no containers, no filesystem layers.

Use `ddash run --profile -- <cmd>` to inspect the exact profile that will be applied.

## All commands

```
ddash run [flags] -- <cmd>     Run a command in a sandbox
ddash trace -- <cmd>           Trace access and suggest policy
ddash sandbox init [-i]        Create config (interactive with -i)
ddash sandbox list             Show current config
ddash sandbox status           Check sandbox status
ddash version                  Print version
```

### Flags for `ddash run`

| Flag | Description |
|------|-------------|
| `--allow-net` | Allow network access |
| `--deny-write` | Deny all filesystem writes |
| `--pass-env` | Pass all environment variables (skip scrubbing) |
| `--profile` | Print the sandbox profile without running |

## Requirements

- macOS (uses the built-in `sandbox-exec` facility)

## License

MIT
