# ddash

Lightweight process sandboxing for macOS. One command, zero setup.

```bash
ddash run -- ./script.sh
```

The script runs with **no network access**, **no access to your secrets**, and **can only write to the current directory**. Enforced at the kernel level via macOS sandbox-exec — the same mechanism used by Safari, Chrome, and other system apps.

## Why ddash instead of Docker?

Docker runs **Linux containers**. If you download a macOS-native binary (a Mach-O arm64 executable), a Homebrew package, a Swift CLI, or a `.command` file — Docker can't run it. VMs are heavy and slow. ddash runs macOS-native software with constraints, instantly.

The other case: you want to use **your actual local environment** but constrain it. `npm install` needs your local Node version. `pip install` needs your venv. An AI agent needs your actual project files. Docker requires volume mounts, image building, environment mirroring. ddash just works — same toolchain, same files, but the process can't reach beyond what you allow.

**Use ddash when:**
- You need to run a **macOS-native binary** you don't fully trust
- You want to use your **local toolchain** (Node, Python, Go) but restrict what it can access
- You need **instant startup** — no image pull, no container build, zero overhead
- You're a security person triaging a downloaded tool on your Mac

**Use Docker when:**
- You need **full process isolation** (separate PID namespace, network namespace)
- You need a **reproducible environment** (clean slate every time)
- You're running **Linux software** or **server workloads**
- You need to isolate **inter-process communication** (Mach IPC — see limitations)

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

# Set up a per-project policy interactively
ddash sandbox init -i
```

## Real-world scenarios

### Security triage: downloaded binary from the internet

You find a tool on GitHub. It's a compiled macOS binary. You want to run it but don't know what it does.

```bash
# Run it read-only, no network — see what happens
ddash run --deny-write -- ./sketchy-tool --help

# If it needs to write output, allow cwd only
ddash run -- ./sketchy-tool export --output results.csv

# If it needs network, allow it but block filesystem escape
ddash run --allow-net -- ./recon-tool scan target.com
```

In Docker, this binary **wouldn't run at all** (wrong platform). In a VM, you'd need minutes of setup. With ddash, it takes one command and the binary runs natively on your Mac with constraints.

### Supply chain risk: npm/pip install

Package managers execute arbitrary code during install (postinstall scripts, setup.py). A compromised package could read your SSH keys and send them to an attacker.

```bash
# Network allowed (needs to download), but can only write to project dir
# Env scrubbed so postinstall scripts can't read GITHUB_TOKEN, AWS keys, etc.
ddash run --allow-net -- npm install
```

The install works normally. But if a malicious postinstall script tries to `cat ~/.ssh/id_ed25519` or `curl` your env vars somewhere — blocked.

### AI coding agents

Let an agent modify your project without giving it the keys to everything:

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

The agent reads and edits code in the current directory. It cannot reach the internet, read `~/.ssh`, `~/.aws`, `~/.config`, or write outside the project. Env vars like `OPENAI_API_KEY` are scrubbed unless you pass `--pass-env`.

### Sandboxed build systems

Allow `make` to build but block network exfiltration of source code:

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

### Vendor CLI evaluation

Security team evaluating a new SaaS vendor's CLI tool before approving it:

```bash
# Step 1: Run it read-only, no network — see what it tries to access
ddash run --deny-write -- ./vendor-cli --help

# Step 2: Run with controlled access
ddash run -- ./vendor-cli export --format csv

# Step 3: If satisfied, create a permanent policy
ddash sandbox init -i
```

### Data pipeline with controlled output

Read data, write results, no network — prevents data exfiltration:

```json
{
  "name": "data-pipeline",
  "allow_net": [],
  "allow_read": [".", "./data"],
  "allow_write": ["./output"]
}
```

```bash
ddash run -- python pipeline.py --input ./data --output ./output
```

## What ddash protects against (tested)

Every release is verified against these attack scenarios with [integration tests](cmd/security_test.go):

| Attack | Result |
|--------|--------|
| Script reads `~/.ssh/` private keys | **Blocked** — `Operation not permitted` |
| Script reads `~/.aws/credentials` | **Blocked** — path outside sandbox |
| Script opens outbound network connection | **Blocked** — DNS and TCP denied |
| Script writes to home directory (`~/`) | **Blocked** — write restricted to cwd |
| Script writes to arbitrary path (`/etc`, `/var`) | **Blocked** — write restricted to cwd |
| Subprocess tries to escape (e.g., `cat ~/.ssh/id_ed25519`) | **Blocked** — child processes inherit sandbox |
| Shell redirect escape (`sh -c 'echo x > ~/file'`) | **Blocked** — kernel-level, applies to all children |
| Script reads `GITHUB_TOKEN` from environment | **Scrubbed** — removed before exec |
| Script reads `AWS_SECRET_ACCESS_KEY` from env | **Scrubbed** — removed before exec |
| `--deny-write` bypass via `/tmp` | **Blocked** — deny-write blocks all paths |

## Known limitations

ddash is a practical security tool, not a security boundary against a sophisticated attacker. Be aware of what it does and doesn't do.

**Mach IPC is open.** The sandbox allows `mach-lookup`, which means sandboxed processes can communicate with system services (clipboard/pasteboard, potentially Keychain). Restricting this breaks most programs, so it's allowed by default. A determined attacker could use Mach IPC for cross-process communication.

**File metadata is visible.** Sandboxed processes can see that files *exist* everywhere on disk (`file-read-metadata` is allowed), they just can't read contents outside allowed paths. A process can enumerate filenames in `~/.ssh/` even though it can't read the keys.

**Process enumeration is possible.** Sandboxed processes can list running processes and PIDs (`process-info*` is allowed). This leaks information about what's running on the machine.

**Env scrubbing is pattern-based.** ddash strips known patterns (`AWS_*`, `*_TOKEN`, `*_SECRET`, etc.) but won't catch secrets in non-standard variable names like `MY_DB=postgres://user:pass@host`. Use `--deny-write --deny-net` (no network + no writes) as the strongest defense against exfiltration regardless of env vars.

**`ddash trace` is experimental.** Trace mode runs commands permissively and tries to log access patterns, but sandbox-exec trace output goes to syslog rather than being directly capturable. The suggested policies are best-effort, not comprehensive. Verify them manually.

**Not a container.** ddash is syscall-level access control, not process isolation. There's no separate PID namespace, no filesystem layering, no network namespace. The sandboxed process runs as your user on your machine — it just can't do everything your user can.

**Detection is possible.** A sandboxed process can detect it's running under sandbox-exec and could behave differently (appear benign when sandboxed, act malicious when not).

## How it works

ddash generates macOS [Sandbox Profiles](https://reverse.put.as/wp-content/uploads/2011/09/Apple-Sandbox-Guide-v1.0.pdf) (SBPL) and runs commands through `sandbox-exec`. This is the same kernel-level Mandatory Access Control used by Safari, Chrome, Mail, and other macOS apps. Enforcement happens in the XNU kernel at the syscall level — there is no userspace bypass. Near-zero overhead, no containers, no filesystem layers.

Use `ddash run --profile -- <cmd>` to inspect the exact profile that will be applied.

## Configuration

### Interactive setup

```bash
ddash sandbox init -i
```

```
Project name [my-project]:
Allow network access? [y/N]: y
  Allow all hosts or specific ones? [all/specific]: specific
  Hosts (comma-separated): api.example.com, cdn.example.com
Allow writes outside current directory? [y/N]: n
```

### Config reference

A `.ddash.json` defines a per-project sandbox policy. When present, `ddash run` applies it automatically.

| Field | Description |
|-------|-------------|
| `allow_net` | `[]` = deny all. `["*"]` = allow all. Or list specific hosts. |
| `allow_read` | Filesystem read paths beyond system defaults. |
| `allow_write` | Filesystem write paths. `[]` = fully read-only. |

### Default policy

| Resource | Default | Override |
|----------|---------|---------|
| Network | **Denied** | `--allow-net` or config |
| Filesystem reads | System paths + cwd | Config |
| Filesystem writes | cwd + `/tmp` | `--deny-write` for none |
| Environment variables | **Sensitive vars scrubbed** | `--pass-env` to allow all |
| Process execution | Allowed | — |

### Environment scrubbing

By default, ddash strips env vars matching known secret patterns before exec. Scrubbed patterns:

- Cloud: `AWS_*`, `AZURE_*`, `GCP_*`, `GOOGLE_*`
- Tokens: `GITHUB_TOKEN`, `GH_TOKEN`, `GITLAB_*`, `NPM_TOKEN`, `OPENAI_API*`, `ANTHROPIC_API*`, `HF_TOKEN`
- Infra: `DATABASE_URL`, `REDIS_URL`, `DOCKER_*`, `SENTRY_*`, `DATADOG_*`
- Any variable containing `_SECRET`, `_TOKEN`, `_KEY`, `_PASSWORD`, `_CREDENTIAL`, or `_AUTH`

## All commands

```
ddash run [flags] -- <cmd>     Run a command in a sandbox
ddash trace -- <cmd>           Trace access and suggest policy (experimental)
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
