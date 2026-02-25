package cmd

import (
	"encoding/json"
	"os"
	"testing"
)

func TestSandboxInitCreatesConfig(t *testing.T) {
	origDir, _ := os.Getwd()
	tmpDir, _ := os.MkdirTemp("", "ddash-test-*")
	defer os.RemoveAll(tmpDir)
	os.Chdir(tmpDir)
	defer os.Chdir(origDir)

	// Simulate: ddash sandbox init
	origArgs := os.Args
	os.Args = []string{"ddash", "sandbox", "init"}
	defer func() { os.Args = origArgs }()

	err := sandboxInit()
	if err != nil {
		t.Fatalf("sandboxInit failed: %v", err)
	}

	// Verify file exists
	data, err := os.ReadFile(".ddash.json")
	if err != nil {
		t.Fatalf("config file not created: %v", err)
	}

	// Verify valid JSON
	var cfg SandboxConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("config is not valid JSON: %v", err)
	}

	// Verify defaults
	if cfg.Version != Version {
		t.Errorf("expected version %s, got %s", Version, cfg.Version)
	}
	if len(cfg.AllowNet) != 0 {
		t.Errorf("expected empty allow_net, got %v", cfg.AllowNet)
	}
	if len(cfg.AllowRead) != 1 || cfg.AllowRead[0] != "." {
		t.Errorf("expected allow_read=[.], got %v", cfg.AllowRead)
	}
	if len(cfg.AllowWrite) != 1 || cfg.AllowWrite[0] != "." {
		t.Errorf("expected allow_write=[.], got %v", cfg.AllowWrite)
	}
	if cfg.CreatedAt == "" {
		t.Error("expected created_at to be set")
	}
}

func TestSandboxInitRefusesOverwrite(t *testing.T) {
	origDir, _ := os.Getwd()
	tmpDir, _ := os.MkdirTemp("", "ddash-test-*")
	defer os.RemoveAll(tmpDir)
	os.Chdir(tmpDir)
	defer os.Chdir(origDir)

	// Create existing config
	os.WriteFile(".ddash.json", []byte(`{}`), 0644)

	origArgs := os.Args
	os.Args = []string{"ddash", "sandbox", "init"}
	defer func() { os.Args = origArgs }()

	err := sandboxInit()
	if err == nil {
		t.Error("expected error when config already exists")
	}
}

func TestSandboxInitHelp(t *testing.T) {
	origArgs := os.Args
	os.Args = []string{"ddash", "sandbox", "init", "--help"}
	defer func() { os.Args = origArgs }()

	// Should not error
	err := sandboxInit()
	if err != nil {
		t.Errorf("--help should not return error, got: %v", err)
	}
}

func TestSandboxList(t *testing.T) {
	origDir, _ := os.Getwd()
	tmpDir, _ := os.MkdirTemp("", "ddash-test-*")
	defer os.RemoveAll(tmpDir)
	os.Chdir(tmpDir)
	defer os.Chdir(origDir)

	// No config — should not error
	err := sandboxList()
	if err != nil {
		t.Errorf("sandboxList with no config should not error, got: %v", err)
	}

	// With config
	cfg := SandboxConfig{
		Name:       "test",
		Version:    Version,
		Isolation:  "process",
		AllowNet:   []string{"api.example.com"},
		AllowRead:  []string{"."},
		AllowWrite: []string{".", "./output"},
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	os.WriteFile(".ddash.json", data, 0644)

	err = sandboxList()
	if err != nil {
		t.Errorf("sandboxList with config should not error, got: %v", err)
	}
}

func TestSandboxStatus(t *testing.T) {
	origDir, _ := os.Getwd()
	tmpDir, _ := os.MkdirTemp("", "ddash-test-*")
	defer os.RemoveAll(tmpDir)
	os.Chdir(tmpDir)
	defer os.Chdir(origDir)

	// No config
	err := sandboxStatus()
	if err != nil {
		t.Errorf("status with no config should not error, got: %v", err)
	}

	// With config
	os.WriteFile(".ddash.json", []byte(`{}`), 0644)
	err = sandboxStatus()
	if err != nil {
		t.Errorf("status with config should not error, got: %v", err)
	}
}

func TestConfigPath(t *testing.T) {
	path := configPath()
	if path != ".ddash.json" {
		t.Errorf("expected .ddash.json, got %s", path)
	}
}
