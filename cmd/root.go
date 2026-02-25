package cmd

import (
	"fmt"
	"os"
)

var Version = "0.1.0"

const usage = `ddash - Sandbox any command on macOS

One command to sandbox anything. No Docker. No VMs. No dependencies.
Uses the built-in macOS sandbox engine (sandbox-exec) at the kernel level.

Usage:
  ddash run [flags] -- <command>    Run a command in a sandbox
  ddash sandbox <subcommand>        Manage sandbox configuration
  ddash version                     Print version

Examples:
  ddash run -- ./untrusted.sh           No network, writes to cwd only
  ddash run --allow-net -- npm install   Allow network access
  ddash run --deny-write -- python x.py  Full read-only mode
  ddash run --profile -- node app.js     Print sandbox profile

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
