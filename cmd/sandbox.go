package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const sandboxUsage = `Manage AI sandboxes

Usage:
  ddash sandbox <command> [flags]

Commands:
  init        Initialize a new sandbox configuration
  list        List configured sandboxes
  status      Show sandbox status

Flags:
  -h, --help  Show help`

// SandboxConfig represents a sandbox configuration file.
type SandboxConfig struct {
	Name      string   `json:"name"`
	Version   string   `json:"version"`
	CreatedAt string   `json:"created_at"`
	Isolation string   `json:"isolation"`
	AllowNet  []string `json:"allow_net"`
	AllowRead []string `json:"allow_read"`
}

func sandboxCmd() error {
	if len(os.Args) < 3 {
		fmt.Println(sandboxUsage)
		return nil
	}

	switch os.Args[2] {
	case "init":
		return sandboxInit()
	case "list":
		return sandboxList()
	case "status":
		return sandboxStatus()
	case "help", "-h", "--help":
		fmt.Println(sandboxUsage)
	default:
		fmt.Fprintf(os.Stderr, "Unknown sandbox command: %s\n\n", os.Args[2])
		fmt.Println(sandboxUsage)
		return fmt.Errorf("unknown sandbox command: %s", os.Args[2])
	}
	return nil
}

func configPath() string {
	return filepath.Join(".", ".ddash.json")
}

func sandboxInit() error {
	path := configPath()
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("sandbox config already exists at %s", path)
	}

	cfg := SandboxConfig{
		Name:      filepath.Base(mustGetwd()),
		Version:   Version,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
		Isolation: "process",
		AllowNet:  []string{},
		AllowRead: []string{"."},
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(path, append(data, '\n'), 0644); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	fmt.Printf("Initialized sandbox config at %s\n", path)
	return nil
}

func sandboxList() error {
	path := configPath()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("No sandbox configured. Run 'ddash sandbox init' to create one.")
			return nil
		}
		return fmt.Errorf("failed to read config: %w", err)
	}

	var cfg SandboxConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("failed to parse config: %w", err)
	}

	fmt.Printf("%-12s %s\n", "Name:", cfg.Name)
	fmt.Printf("%-12s %s\n", "Isolation:", cfg.Isolation)
	fmt.Printf("%-12s %s\n", "Created:", cfg.CreatedAt)
	return nil
}

func sandboxStatus() error {
	path := configPath()
	if _, err := os.Stat(path); os.IsNotExist(err) {
		fmt.Println("No sandbox configured.")
		return nil
	}
	fmt.Println("Sandbox: configured (inactive)")
	return nil
}

func mustGetwd() string {
	dir, err := os.Getwd()
	if err != nil {
		return "ddash"
	}
	return dir
}
