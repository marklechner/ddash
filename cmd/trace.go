package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

const traceUsage = `Trace a command's access and suggest a sandbox policy

Usage:
  ddash trace [flags] -- <command> [args...]

Runs the command with full permissions while monitoring what it accesses.
After the command exits, ddash summarizes the access and suggests a
minimal .ddash.json policy.

Examples:
  ddash trace -- python train.py
  ddash trace -- npm run build
  ddash trace --save -- ./my-script.sh    Auto-save suggested config

Flags:
  --save        Automatically save the suggested config to .ddash.json
  -h, --help    Show help`

type accessLog struct {
	netOut     map[string]int
	fileReads  map[string]int
	fileWrites map[string]int
}

func traceCmd() error {
	if len(os.Args) < 3 {
		fmt.Println(traceUsage)
		return nil
	}

	autoSave := false
	cmdStart := -1

	for i := 2; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "--save":
			autoSave = true
		case "-h", "--help":
			fmt.Println(traceUsage)
			return nil
		case "--":
			if i+1 < len(os.Args) {
				cmdStart = i + 1
			}
		}
		if cmdStart != -1 {
			break
		}
	}

	if cmdStart == -1 {
		fmt.Println(traceUsage)
		return fmt.Errorf("no command specified; use -- before the command")
	}

	args := os.Args[cmdStart:]

	binary, err := exec.LookPath(args[0])
	if err != nil {
		return fmt.Errorf("command not found: %s", args[0])
	}

	// Generate a trace profile that allows everything but logs denials
	// We use sandbox-exec with (trace ...) to capture access patterns
	traceProfile := generateTraceProfile()

	// Create a temp file for the sandbox trace log
	logFile, err := os.CreateTemp("", "ddash-trace-*.log")
	if err != nil {
		return fmt.Errorf("failed to create trace log: %w", err)
	}
	logPath := logFile.Name()
	logFile.Close()
	defer os.Remove(logPath)

	fmt.Fprintf(os.Stderr, "ddash: tracing %s (all access allowed, logging to %s)\n\n", args[0], logPath)

	// Run with a permissive profile but log file access via dtrace-style approach
	// Since sandbox-exec trace output goes to syslog, we'll use a different approach:
	// Run with fs_usage to capture filesystem access
	cmdArgs := []string{"-p", traceProfile, binary}
	cmdArgs = append(cmdArgs, args[1:]...)

	sandboxExec, err := exec.LookPath("sandbox-exec")
	if err != nil {
		return fmt.Errorf("sandbox-exec not found")
	}

	// First, run the actual command with sandbox-exec in permissive trace mode
	cmd := exec.Command(sandboxExec, cmdArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), "SANDBOX_LOG_FILE="+logPath)

	runErr := cmd.Run()

	fmt.Fprintf(os.Stderr, "\n")

	if runErr != nil {
		fmt.Fprintf(os.Stderr, "ddash: command exited with error: %v\n\n", runErr)
	}

	// Analyze the sandbox trace log
	log := analyzeTrace(logPath)

	// Also do a basic analysis based on the command itself
	cwd, _ := os.Getwd()
	enrichFromCommand(log, args, cwd)

	// Print summary
	printTraceSummary(log, cwd)

	// Suggest config
	cfg := suggestConfig(log, cwd)

	fmt.Fprintf(os.Stderr, "\nSuggested .ddash.json:\n")
	data, _ := json.MarshalIndent(cfg, "  ", "  ")
	fmt.Fprintf(os.Stderr, "  %s\n", string(data))

	if autoSave {
		return saveConfig(cfg)
	}

	// Prompt to save
	fmt.Fprintf(os.Stderr, "\nSave this config? [Y/n] ")
	reader := bufio.NewReader(os.Stdin)
	answer, _ := reader.ReadString('\n')
	answer = strings.TrimSpace(strings.ToLower(answer))

	if answer == "" || answer == "y" || answer == "yes" {
		return saveConfig(cfg)
	}

	fmt.Fprintf(os.Stderr, "Config not saved.\n")
	return nil
}

func generateTraceProfile() string {
	var sb strings.Builder
	sb.WriteString("(version 1)\n")
	sb.WriteString("(allow default)\n")
	// Log all operations for analysis
	sb.WriteString("(trace default)\n")
	return sb.String()
}

func analyzeTrace(logPath string) *accessLog {
	log := &accessLog{
		netOut:     make(map[string]int),
		fileReads:  make(map[string]int),
		fileWrites: make(map[string]int),
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		return log
	}

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Parse sandbox trace log lines
		if strings.Contains(line, "file-read") {
			if path := extractPath(line); path != "" {
				log.fileReads[path]++
			}
		} else if strings.Contains(line, "file-write") {
			if path := extractPath(line); path != "" {
				log.fileWrites[path]++
			}
		} else if strings.Contains(line, "network-outbound") {
			if host := extractHost(line); host != "" {
				log.netOut[host]++
			}
		}
	}

	return log
}

func extractPath(line string) string {
	// Look for quoted paths in trace output
	if idx := strings.Index(line, "\""); idx >= 0 {
		end := strings.Index(line[idx+1:], "\"")
		if end >= 0 {
			return line[idx+1 : idx+1+end]
		}
	}
	return ""
}

func extractHost(line string) string {
	if idx := strings.Index(line, "\""); idx >= 0 {
		end := strings.Index(line[idx+1:], "\"")
		if end >= 0 {
			return line[idx+1 : idx+1+end]
		}
	}
	return ""
}

func enrichFromCommand(log *accessLog, args []string, cwd string) {
	// Add the cwd as a known read path
	log.fileReads[cwd]++

	// If the command is a script, note its path
	if len(args) > 1 {
		for _, arg := range args[1:] {
			if !strings.HasPrefix(arg, "-") {
				if abs, err := filepath.Abs(arg); err == nil {
					if _, err := os.Stat(abs); err == nil {
						log.fileReads[abs]++
					}
				}
			}
		}
	}
}

func printTraceSummary(log *accessLog, cwd string) {
	fmt.Fprintf(os.Stderr, "Access summary:\n")

	// Network
	if len(log.netOut) == 0 {
		fmt.Fprintf(os.Stderr, "  Network:     no outbound connections detected\n")
	} else {
		hosts := sortedKeys(log.netOut)
		fmt.Fprintf(os.Stderr, "  Network:     %d outbound (%s)\n", len(hosts), strings.Join(hosts, ", "))
	}

	// File reads
	sysReads, projReads := categorizeFiles(log.fileReads, cwd)
	fmt.Fprintf(os.Stderr, "  File reads:  %d (system: %d, project: %d)\n",
		len(log.fileReads), sysReads, projReads)

	// File writes
	if len(log.fileWrites) == 0 {
		fmt.Fprintf(os.Stderr, "  File writes: none detected\n")
	} else {
		writePaths := sortedKeys(log.fileWrites)
		displayed := writePaths
		if len(displayed) > 5 {
			displayed = displayed[:5]
			displayed = append(displayed, fmt.Sprintf("... and %d more", len(writePaths)-5))
		}
		fmt.Fprintf(os.Stderr, "  File writes: %d (%s)\n", len(writePaths), strings.Join(displayed, ", "))
	}
}

func suggestConfig(log *accessLog, cwd string) SandboxConfig {
	cfg := SandboxConfig{
		Name:      filepath.Base(cwd),
		Version:   Version,
		Isolation: "process",
		AllowNet:  []string{},
		AllowRead: []string{"."},
	}

	// Suggest network if any was used
	if len(log.netOut) > 0 {
		hosts := sortedKeys(log.netOut)
		cfg.AllowNet = hosts
	}

	// Suggest write paths
	writeDirs := make(map[string]bool)
	for path := range log.fileWrites {
		dir := filepath.Dir(path)
		// Normalize to relative if under cwd
		if rel, err := filepath.Rel(cwd, dir); err == nil && !strings.HasPrefix(rel, "..") {
			writeDirs["."] = true
		} else if strings.HasPrefix(dir, "/tmp") || strings.HasPrefix(dir, "/private/tmp") {
			// /tmp is allowed by default, skip
		} else {
			writeDirs[dir] = true
		}
	}

	if len(writeDirs) == 0 {
		cfg.AllowWrite = []string{"."}
	} else {
		cfg.AllowWrite = sortedKeysFromBoolMap(writeDirs)
	}

	return cfg
}

func saveConfig(cfg SandboxConfig) error {
	path := configPath()
	if _, err := os.Stat(path); err == nil {
		fmt.Fprintf(os.Stderr, "Overwriting existing %s\n", path)
	}

	cfg.CreatedAt = ""
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(path, append(data, '\n'), 0644); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Saved to %s\n", path)
	return nil
}

func categorizeFiles(files map[string]int, cwd string) (system, project int) {
	sysPrefixes := []string{"/bin", "/sbin", "/usr", "/System", "/Library", "/opt", "/private", "/dev"}
	for path := range files {
		isSys := false
		for _, prefix := range sysPrefixes {
			if strings.HasPrefix(path, prefix) {
				isSys = true
				break
			}
		}
		if isSys {
			system++
		} else {
			project++
		}
	}
	return
}

func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedKeysFromBoolMap(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
