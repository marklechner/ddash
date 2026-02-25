package cmd

import (
	"os"
	"strings"
	"testing"
)

func TestIsSensitive(t *testing.T) {
	sensitive := []string{
		"AWS_SECRET_ACCESS_KEY",
		"AWS_SESSION_TOKEN",
		"GITHUB_TOKEN",
		"GH_TOKEN",
		"GITLAB_TOKEN",
		"NPM_TOKEN",
		"OPENAI_API_KEY",
		"ANTHROPIC_API_KEY",
		"DATABASE_URL",
		"REDIS_URL",
		"DOCKER_PASSWORD",
		"SENTRY_DSN",
		"DATADOG_API_KEY",
		"STRIPE_SECRET_KEY",
		"MY_APP_SECRET",
		"DB_PASSWORD",
		"SSH_AUTH_SOCK",
		"HF_TOKEN",
		"SLACK_TOKEN",
		"AZURE_CLIENT_SECRET",
		"GCP_SERVICE_ACCOUNT_KEY",
		"GOOGLE_APPLICATION_CREDENTIALS",
	}

	for _, name := range sensitive {
		if !isSensitive(name) {
			t.Errorf("expected %q to be sensitive, but it was not", name)
		}
	}
}

func TestIsSensitiveAllowsSafeVars(t *testing.T) {
	safe := []string{
		"HOME",
		"PATH",
		"USER",
		"SHELL",
		"TERM",
		"LANG",
		"PWD",
		"EDITOR",
		"GOPATH",
		"GOROOT",
		"PYTHONPATH",
		"NODE_ENV",
		"MY_APP_NAME",
		"LOG_LEVEL",
		"PORT",
	}

	for _, name := range safe {
		if isSensitive(name) {
			t.Errorf("expected %q to be safe, but it was marked sensitive", name)
		}
	}
}

func TestScrubEnv(t *testing.T) {
	// Set some test env vars
	os.Setenv("DDASH_TEST_SAFE", "safe_value")
	os.Setenv("DDASH_TEST_SECRET_KEY", "should_be_scrubbed")
	os.Setenv("DDASH_TEST_TOKEN", "should_be_scrubbed")
	defer os.Unsetenv("DDASH_TEST_SAFE")
	defer os.Unsetenv("DDASH_TEST_SECRET_KEY")
	defer os.Unsetenv("DDASH_TEST_TOKEN")

	env := scrubEnv()

	foundSafe := false
	for _, e := range env {
		if strings.HasPrefix(e, "DDASH_TEST_SAFE=") {
			foundSafe = true
		}
		if strings.HasPrefix(e, "DDASH_TEST_SECRET_KEY=") {
			t.Error("DDASH_TEST_SECRET_KEY should have been scrubbed")
		}
		if strings.HasPrefix(e, "DDASH_TEST_TOKEN=") {
			t.Error("DDASH_TEST_TOKEN should have been scrubbed")
		}
	}

	if !foundSafe {
		t.Error("DDASH_TEST_SAFE should have been kept")
	}
}

func TestGenerateProfileDefaults(t *testing.T) {
	cfg := SandboxConfig{
		AllowNet:   []string{},
		AllowRead:  []string{"."},
		AllowWrite: []string{"."},
	}

	profile := generateProfile(cfg, false, false)

	// Must have deny default
	if !strings.Contains(profile, "(deny default)") {
		t.Error("profile missing (deny default)")
	}

	// Must deny network by default
	if strings.Contains(profile, "(allow network*)") {
		t.Error("profile should not allow network by default")
	}

	// Must allow process execution
	if !strings.Contains(profile, "(allow process-exec)") {
		t.Error("profile missing process-exec")
	}

	// Must allow file reads to system paths
	for _, path := range []string{"/bin", "/usr", "/System", "/Library"} {
		if !strings.Contains(profile, path) {
			t.Errorf("profile missing read access to %s", path)
		}
	}

	// Must allow writes to /private/tmp
	if !strings.Contains(profile, "(allow file-write* (subpath \"/private/tmp\"))") {
		t.Error("profile missing write access to /private/tmp")
	}
}

func TestGenerateProfileAllowNet(t *testing.T) {
	cfg := SandboxConfig{
		AllowNet:   []string{"*"},
		AllowRead:  []string{"."},
		AllowWrite: []string{"."},
	}

	profile := generateProfile(cfg, false, false)

	if !strings.Contains(profile, "(allow network*)") {
		t.Error("profile should allow network when configured")
	}
}

func TestGenerateProfileDenyWrite(t *testing.T) {
	cfg := SandboxConfig{
		AllowNet:   []string{},
		AllowRead:  []string{"."},
		AllowWrite: []string{},
	}

	profile := generateProfile(cfg, true, false)

	// Should NOT have /private/tmp write access
	if strings.Contains(profile, "(allow file-write* (subpath \"/private/tmp\"))") {
		t.Error("deny-write profile should not allow writes to /tmp")
	}

	// Should only allow /dev/null
	if !strings.Contains(profile, "/dev/null") {
		t.Error("deny-write profile should allow /dev/null")
	}
}

func TestLoadRunConfigDefaults(t *testing.T) {
	// Ensure no config file exists
	origDir, _ := os.Getwd()
	tmpDir, _ := os.MkdirTemp("", "ddash-test-*")
	defer os.RemoveAll(tmpDir)
	os.Chdir(tmpDir)
	defer os.Chdir(origDir)

	cfg := loadRunConfig()

	if len(cfg.AllowNet) != 0 {
		t.Errorf("expected empty AllowNet, got %v", cfg.AllowNet)
	}
	if len(cfg.AllowRead) != 1 || cfg.AllowRead[0] != "." {
		t.Errorf("expected AllowRead=[.], got %v", cfg.AllowRead)
	}
	if len(cfg.AllowWrite) != 1 || cfg.AllowWrite[0] != "." {
		t.Errorf("expected AllowWrite=[.], got %v", cfg.AllowWrite)
	}
}

func TestLoadRunConfigFromFile(t *testing.T) {
	origDir, _ := os.Getwd()
	tmpDir, _ := os.MkdirTemp("", "ddash-test-*")
	defer os.RemoveAll(tmpDir)
	os.Chdir(tmpDir)
	defer os.Chdir(origDir)

	config := `{"name":"test","allow_net":["*"],"allow_read":[".","./data"],"allow_write":["./output"]}`
	os.WriteFile(".ddash.json", []byte(config), 0644)

	cfg := loadRunConfig()

	if len(cfg.AllowNet) != 1 || cfg.AllowNet[0] != "*" {
		t.Errorf("expected AllowNet=[*], got %v", cfg.AllowNet)
	}
	if len(cfg.AllowRead) != 2 {
		t.Errorf("expected 2 AllowRead entries, got %v", cfg.AllowRead)
	}
	if len(cfg.AllowWrite) != 1 || cfg.AllowWrite[0] != "./output" {
		t.Errorf("expected AllowWrite=[./output], got %v", cfg.AllowWrite)
	}
}

func TestNetworkStatus(t *testing.T) {
	if networkStatus("(allow network*)") != "allowed" {
		t.Error("should detect allowed network")
	}
	if networkStatus("(deny default)") != "denied" {
		t.Error("should detect denied network")
	}
}

func TestWriteStatus(t *testing.T) {
	// Only /dev/null — restricted
	if writeStatus("(allow file-write* (subpath \"/dev/null\"))") != "restricted" {
		t.Error("should detect restricted writes")
	}

	// Multiple write paths — allowed
	profile := `(allow file-write* (subpath "/private/tmp"))
(allow file-write* (subpath "/dev"))
(allow file-write* (subpath "/Users/mark/project"))`
	if writeStatus(profile) != "allowed" {
		t.Error("should detect allowed writes")
	}
}

func TestResolvePath(t *testing.T) {
	cwd := "/Users/mark/project"

	tests := []struct {
		input    string
		expected string
	}{
		{".", "/Users/mark/project"},
		{"/tmp", "/tmp"},
		{"./output", "/Users/mark/project/./output"},
		{"data", "/Users/mark/project/data"},
	}

	for _, tt := range tests {
		result := resolvePath(tt.input, cwd)
		if result != tt.expected {
			t.Errorf("resolvePath(%q, %q) = %q, want %q", tt.input, cwd, result, tt.expected)
		}
	}
}
