# ddash

One command to sandbox anything on macOS. No Docker. No VMs. No dependencies.

```bash
ddash run -- ./untrusted-script.sh
```

That's it. The script runs with **no network access** and **can only write to the current directory**. Everything else is denied by default.

## Why?

macOS has a powerful built-in sandboxing engine that almost nobody uses because it requires writing Scheme-based policy files by hand. ddash generates these profiles for you and makes sandboxing as simple as prefixing a command.

**Use cases:**
- Run downloaded scripts without worrying what they do
- Execute build tools without letting them phone home
- Test CLI tools in a restricted environment
- Prevent rogue processes from reading your SSH keys or browser data
- Audit what filesystem/network access a program actually needs

## Install

```bash
brew install ddash
```

Or from source:

```bash
go install github.com/marklechner/ddash@latest
```

## Usage

### Sandbox a command (default: no network, writes restricted to cwd)

```bash
ddash run -- python script.py
ddash run -- node build.js
ddash run -- ./configure && make
```

### Allow network access

```bash
ddash run --allow-net -- npm install
ddash run --allow-net -- curl https://api.example.com
```

### Read-only mode (deny all writes)

```bash
ddash run --deny-write -- ./suspicious-binary
ddash run --deny-write -- python analyze.py
```

### Inspect the generated sandbox profile

```bash
ddash run --profile -- python script.py
```

This prints the raw macOS sandbox profile (SBPL) that would be applied — useful for auditing or customizing.

## Per-project configuration

Create a `.ddash.json` to define a persistent sandbox policy for a project:

```bash
ddash sandbox init
```

```json
{
  "name": "my-project",
  "isolation": "process",
  "allow_net": [],
  "allow_read": ["."],
  "allow_write": ["."]
}
```

| Field | Description |
|-------|-------------|
| `allow_net` | Network rules. `[]` = no network. `["*"]` = allow all. |
| `allow_read` | Filesystem read paths beyond system defaults. |
| `allow_write` | Filesystem write paths. `[]` = fully read-only. |

## Default security policy

| Resource | Default | Flag to override |
|----------|---------|-----------------|
| Network | **Denied** | `--allow-net` |
| Filesystem reads | System paths + cwd | Via `.ddash.json` |
| Filesystem writes | cwd + `/tmp` | `--deny-write` for none |
| Process execution | Allowed | — |

System paths (`/bin`, `/usr`, `/System`, `/Library`, `/opt/homebrew`) are always readable so sandboxed programs can find their interpreters and libraries.

## How it works

ddash generates a macOS [Sandbox Profile](https://reverse.put.as/wp-content/uploads/2011/09/Apple-Sandbox-Guide-v1.0.pdf) (SBPL) and executes your command through `sandbox-exec`. This is the same kernel-level sandboxing mechanism used by Safari, Mail, and other macOS system apps. It operates at the syscall level — there's no container overhead, no filesystem layering, and no virtualization.

## Commands

```
ddash run [flags] -- <command>    Run a command in a sandbox
ddash sandbox init                Create .ddash.json config
ddash sandbox list                Show current config
ddash sandbox status              Check sandbox status
ddash version                     Print version
```

## Requirements

- macOS (uses the built-in `sandbox-exec` facility)

## License

MIT
