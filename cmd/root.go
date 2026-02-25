package cmd

import (
	"fmt"
	"os"
)

var Version = "0.1.0"

const usage = `ddash - AI sandbox orchestration CLI

Usage:
  ddash <command> [flags]

Commands:
  version     Print the ddash version
  sandbox     Manage AI sandboxes
  help        Show this help message

Flags:
  -h, --help      Show help
  -v, --version   Print version

Use "ddash <command> --help" for more information about a command.`

func Execute() error {
	if len(os.Args) < 2 {
		fmt.Println(usage)
		return nil
	}

	switch os.Args[1] {
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
