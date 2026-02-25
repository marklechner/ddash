# ddash

AI sandbox orchestration CLI. Create, manage, and enforce isolation policies for AI agent workloads.

## Install

```bash
brew install ddash
```

Or build from source:

```bash
go install github.com/marklechner/ddash@latest
```

## Usage

```bash
# Initialize a sandbox config in the current directory
ddash sandbox init

# List configured sandboxes
ddash sandbox list

# Check sandbox status
ddash sandbox status

# Print version
ddash version
```

## What is ddash?

ddash provides lightweight sandboxing for AI agents and LLM-powered tools. It enforces isolation policies — network access, filesystem permissions, process boundaries — so AI workloads run within well-defined security boundaries.

## License

MIT
