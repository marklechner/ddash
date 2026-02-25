package cmd

import (
	"fmt"
	"os"
)

var Version = "0.1.0"

const usage = `ddash - Lightweight process sandboxing for macOS

One command to sandbox anything. Zero setup, zero overhead.
Blocks network, restricts filesystem, scrubs secrets from env.
Uses the native macOS sandbox engine (sandbox-exec) at the kernel level.

Usage:
  ddash run [flags] -- <command>    Run a command in a sandbox
  ddash trace -- <command>          Trace access and suggest policy
  ddash sandbox <subcommand>        Manage sandbox configuration
  ddash version                     Print version

Examples:
  ddash run -- ./untrusted.sh             No network, env scrubbed, writes to cwd
  ddash run --allow-net -- npm install     Allow network access
  ddash run --deny-write -- ./binary       Full read-only mode
  ddash run --pass-env -- ./needs-creds    Pass env vars through
  ddash trace -- python train.py           Trace access, suggest policy
  ddash sandbox init -i                    Interactive config setup

Flags:
  -h, --help      Show help
  -v, --version   Print version`

func Execute() error {
	if len(os.Args) < 2 {
		fmt.Println(usage)
		return nil
	}

	switch os.Args[1] {
	case "run":
		return runCmd()
	case "trace":
		return traceCmd()
	case "version", "-v", "--version":
		fmt.Printf("ddash version %s\n", Version)
	case "sandbox":
		return sandboxCmd()
	case "help", "-h", "--help":
		fmt.Println(usage)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", os.Args[1])
		fmt.Println(usage)
		return fmt.Errorf("unknown command: %s", os.Args[1])
	}
	return nil
}
