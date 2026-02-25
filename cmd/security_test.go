package cmd

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// These tests require a built ddash binary. Run: go build -o ddash . && go test ./... -v
// They exercise the actual sandbox-exec enforcement at the kernel level.

func ddashBinary(t *testing.T) string {
	t.Helper()
	// Build a fresh binary for integration tests
	binary := t.TempDir() + "/ddash"
	build := exec.Command("go", "build", "-o", binary, "..")
	build.Dir = "."
	out, err := build.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to build ddash: %v\n%s", err, out)
	}
	return binary
}

func TestSecurityNetworkBlocked(t *testing.T) {
	binary := ddashBinary(t)

	cmd := exec.Command(binary, "run", "--", "python3", "-c",
		"import urllib.request; urllib.request.urlopen('https://example.com', timeout=3); print('FAIL')")
	out, err := cmd.CombinedOutput()
	output := string(out)

	// Command should fail (network blocked)
	if err == nil && strings.Contains(output, "FAIL") {
		t.Error("network access should be blocked but python reached the internet")
	}
}

func TestSecuritySSHBlocked(t *testing.T) {
	binary := ddashBinary(t)

	home, _ := os.UserHomeDir()
	sshDir := home + "/.ssh"
	if _, err := os.Stat(sshDir); os.IsNotExist(err) {
		t.Skip("no ~/.ssh directory to test against")
	}

	cmd := exec.Command(binary, "run", "--", "python3", "-c",
		"import os; os.listdir(os.path.expanduser('~/.ssh')); print('FAIL')")
	out, _ := cmd.CombinedOutput()
	output := string(out)

	if strings.Contains(output, "FAIL") {
		t.Error("~/.ssh should be blocked but was readable")
	}
	if !strings.Contains(output, "Operation not permitted") {
		t.Errorf("expected 'Operation not permitted' error, got: %s", output)
	}
}

func TestSecurityHomeWriteBlocked(t *testing.T) {
	binary := ddashBinary(t)

	cmd := exec.Command(binary, "run", "--", "python3", "-c",
		"import os; open(os.path.expanduser('~/ddash_test_evil'), 'w').write('x'); print('FAIL')")
	out, _ := cmd.CombinedOutput()
	output := string(out)

	if strings.Contains(output, "FAIL") {
		t.Error("writing to ~ should be blocked")
	}

	// Clean up just in case
	home, _ := os.UserHomeDir()
	os.Remove(home + "/ddash_test_evil")
}

func TestSecurityDenyWriteBlocksTmp(t *testing.T) {
	binary := ddashBinary(t)

	cmd := exec.Command(binary, "run", "--deny-write", "--", "python3", "-c",
		"open('/tmp/ddash_test_evil', 'w').write('x'); print('FAIL')")
	out, _ := cmd.CombinedOutput()
	output := string(out)

	if strings.Contains(output, "FAIL") {
		t.Error("--deny-write should block writes to /tmp")
	}

	os.Remove("/tmp/ddash_test_evil")
}

func TestSecuritySubprocessInheritsSandbox(t *testing.T) {
	binary := ddashBinary(t)

	home, _ := os.UserHomeDir()
	sshKey := home + "/.ssh/id_ed25519"
	if _, err := os.Stat(sshKey); os.IsNotExist(err) {
		sshKey = home + "/.ssh/id_rsa"
		if _, err := os.Stat(sshKey); os.IsNotExist(err) {
			t.Skip("no SSH key to test against")
		}
	}

	cmd := exec.Command(binary, "run", "--", "cat", sshKey)
	out, err := cmd.CombinedOutput()
	output := string(out)

	if err == nil && !strings.Contains(output, "Operation not permitted") {
		t.Errorf("subprocess cat should not be able to read SSH key, got: %s", output)
	}
}

func TestSecurityEnvScrubbed(t *testing.T) {
	binary := ddashBinary(t)

	cmd := exec.Command(binary, "run", "--", "python3", "-c",
		"import os; v=os.environ.get('TEST_SECRET_KEY','SCRUBBED'); print(v)")
	cmd.Env = append(os.Environ(), "TEST_SECRET_KEY=supersecret")
	out, _ := cmd.CombinedOutput()
	output := string(out)

	if strings.Contains(output, "supersecret") {
		t.Error("TEST_SECRET_KEY should be scrubbed from env")
	}
	if !strings.Contains(output, "SCRUBBED") {
		t.Errorf("expected SCRUBBED, got: %s", output)
	}
}

func TestSecurityEnvPassthrough(t *testing.T) {
	binary := ddashBinary(t)

	cmd := exec.Command(binary, "run", "--pass-env", "--", "python3", "-c",
		"import os; print(os.environ.get('TEST_SECRET_KEY','MISSING'))")
	cmd.Env = append(os.Environ(), "TEST_SECRET_KEY=supersecret")
	out, _ := cmd.CombinedOutput()
	output := string(out)

	if !strings.Contains(output, "supersecret") {
		t.Errorf("--pass-env should pass TEST_SECRET_KEY through, got: %s", output)
	}
}

func TestSecurityStdinPiping(t *testing.T) {
	binary := ddashBinary(t)

	cmd := exec.Command(binary, "run", "--", "cat")
	cmd.Stdin = strings.NewReader("piped input works\n")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("stdin pipe failed: %v\n%s", err, out)
	}

	output := string(out)
	if !strings.Contains(output, "piped input works") {
		t.Errorf("expected piped input in output, got: %s", output)
	}
}

func TestSecurityExitCodeForwarded(t *testing.T) {
	binary := ddashBinary(t)

	cmd := exec.Command(binary, "run", "--", "python3", "-c", "import sys; sys.exit(42)")
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected non-zero exit")
	}
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("expected ExitError, got %T", err)
	}
	if exitErr.ExitCode() != 42 {
		t.Errorf("expected exit code 42, got %d", exitErr.ExitCode())
	}
}
