package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const sandboxUsage = `Manage sandbox configuration

Create and inspect .ddash.json config files that define per-project
sandbox policies. When present, 'ddash run' applies these policies
automatically.

Usage:
  ddash sandbox <command> [flags]

Commands:
  init        Create a .ddash.json (use -i for interactive setup)
  list        Show current sandbox configuration
  status      Check if a sandbox config exists

Flags:
  -h, --help  Show help`

// SandboxConfig represents a sandbox configuration file.
type SandboxConfig struct {
	Name      string   `json:"name"`
	Version   string   `json:"version"`
	CreatedAt string   `json:"created_at"`
	Isolation string   `json:"isolation"`
	AllowNet   []string `json:"allow_net"`
	AllowRead  []string `json:"allow_read"`
	AllowWrite []string `json:"allow_write"`
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

const initUsage = `Create a sandbox configuration file

Usage:
  ddash sandbox init [flags]

Creates a .ddash.json in the current directory that defines the sandbox
policy for this project. When present, 'ddash run' enforces it automatically.

Without flags, creates a sensible default (no network, read/write to cwd).
With -i, walks you through each policy decision interactively.

Generated config:
  {
    "allow_net":   []        # No network (use ["*"] for all, or list hosts)
    "allow_read":  ["."]     # Read current directory (system paths always allowed)
    "allow_write": ["."]     # Write current directory only
  }

Flags:
  -i, --interactive   Walk through policy setup step by step
  -h, --help          Show help

Examples:
  ddash sandbox init           Create default restrictive config
  ddash sandbox init -i        Interactive setup with prompts`

func sandboxInit() error {
	interactive := false
	for _, arg := range os.Args[3:] {
		switch arg {
		case "-i", "--interactive":
			interactive = true
		case "-h", "--help":
			fmt.Println(initUsage)
			return nil
		}
	}

	path := configPath()
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("sandbox config already exists at %s (delete it first or edit manually)", path)
	}

	var cfg SandboxConfig

	if interactive {
		cfg = interactiveInit()
	} else {
		cfg = SandboxConfig{
			Name:       filepath.Base(mustGetwd()),
			Version:    Version,
			CreatedAt:  time.Now().UTC().Format(time.RFC3339),
			Isolation:  "process",
			AllowNet:   []string{},
			AllowRead:  []string{"."},
			AllowWrite: []string{"."},
		}
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

func interactiveInit() SandboxConfig {
	reader := bufio.NewReader(os.Stdin)

	defaultName := filepath.Base(mustGetwd())
	fmt.Printf("Project name [%s]: ", defaultName)
	name := readLine(reader)
	if name == "" {
		name = defaultName
	}

	// Network
	fmt.Print("Allow network access? [y/N]: ")
	allowNet := []string{}
	if yesNo(reader) {
		fmt.Print("  Allow all hosts or specific ones? [all/specific]: ")
		answer := strings.ToLower(readLine(reader))
		if answer == "specific" {
			fmt.Print("  Hosts (comma-separated): ")
			hostsStr := readLine(reader)
			for _, h := range strings.Split(hostsStr, ",") {
				h = strings.TrimSpace(h)
				if h != "" {
					allowNet = append(allowNet, h)
				}
			}
		} else {
			allowNet = []string{"*"}
		}
	}

	// Write access
	allowWrite := []string{"."}
	fmt.Print("Allow writes outside current directory? [y/N]: ")
	if yesNo(reader) {
		fmt.Print("  Additional write paths (comma-separated): ")
		pathsStr := readLine(reader)
		for _, p := range strings.Split(pathsStr, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				allowWrite = append(allowWrite, p)
			}
		}
	}

	// Read access
	allowRead := []string{"."}
	fmt.Print("Allow reads outside current directory and system paths? [y/N]: ")
	if yesNo(reader) {
		fmt.Print("  Additional read paths (comma-separated): ")
		pathsStr := readLine(reader)
		for _, p := range strings.Split(pathsStr, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				allowRead = append(allowRead, p)
			}
		}
	}

	return SandboxConfig{
		Name:       name,
		Version:    Version,
		CreatedAt:  time.Now().UTC().Format(time.RFC3339),
		Isolation:  "process",
		AllowNet:   allowNet,
		AllowRead:  allowRead,
		AllowWrite: allowWrite,
	}
}

func readLine(reader *bufio.Reader) string {
	line, _ := reader.ReadString('\n')
	return strings.TrimSpace(line)
}

func yesNo(reader *bufio.Reader) bool {
	answer := strings.ToLower(readLine(reader))
	return answer == "y" || answer == "yes"
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
	if len(cfg.AllowNet) == 0 {
		fmt.Printf("%-12s %s\n", "Network:", "denied")
	} else {
		fmt.Printf("%-12s %v\n", "Network:", cfg.AllowNet)
	}
	fmt.Printf("%-12s %v\n", "Read:", cfg.AllowRead)
	fmt.Printf("%-12s %v\n", "Write:", cfg.AllowWrite)
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
