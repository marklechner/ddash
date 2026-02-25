package cmd

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

func TestProxyStartsAndListens(t *testing.T) {
	p, err := NewProxy(nil, "test")
	if err != nil {
		t.Fatalf("NewProxy failed: %v", err)
	}
	defer p.Shutdown()
	p.Start()

	addr := p.Addr()
	if addr == "" {
		t.Fatal("proxy addr is empty")
	}

	// Verify we can connect to it
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("cannot connect to proxy at %s: %v", addr, err)
	}
	conn.Close()
}

func TestProxyCachedAllow(t *testing.T) {
	// Start a backend HTTP server
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("backend-ok"))
	}))
	defer backend.Close()

	// Extract host from backend URL
	backendURL, _ := url.Parse(backend.URL)
	host := backendURL.Host

	// Start proxy with this host pre-allowed
	domains := map[string]string{stripPort(host): "allow"}
	p, err := NewProxy(domains, "test")
	if err != nil {
		t.Fatalf("NewProxy failed: %v", err)
	}
	defer p.Shutdown()
	p.Start()

	// Make HTTP request through proxy
	proxyURL, _ := url.Parse("http://" + p.Addr())
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   5 * time.Second,
	}

	resp, err := client.Get(backend.URL)
	if err != nil {
		t.Fatalf("request through proxy failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "backend-ok" {
		t.Errorf("expected 'backend-ok', got %q", string(body))
	}
}

func TestProxyCachedDeny(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("should-not-reach"))
	}))
	defer backend.Close()

	backendURL, _ := url.Parse(backend.URL)
	host := backendURL.Host

	domains := map[string]string{stripPort(host): "deny"}
	p, err := NewProxy(domains, "test")
	if err != nil {
		t.Fatalf("NewProxy failed: %v", err)
	}
	defer p.Shutdown()
	p.Start()

	proxyURL, _ := url.Parse("http://" + p.Addr())
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   5 * time.Second,
	}

	resp, err := client.Get(backend.URL)
	if err != nil {
		t.Fatalf("request through proxy failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden, got %d", resp.StatusCode)
	}
}

func TestProxyCachedAlwaysAllows(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	backendURL, _ := url.Parse(backend.URL)
	host := backendURL.Host

	// "always" should be treated as allowed
	domains := map[string]string{stripPort(host): "always"}
	p, err := NewProxy(domains, "test")
	if err != nil {
		t.Fatalf("NewProxy failed: %v", err)
	}
	defer p.Shutdown()
	p.Start()

	proxyURL, _ := url.Parse("http://" + p.Addr())
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   5 * time.Second,
	}

	resp, err := client.Get(backend.URL)
	if err != nil {
		t.Fatalf("request through proxy failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "ok" {
		t.Errorf("expected 'ok', got %q", string(body))
	}
}

func TestProxyCachedNeverDenies(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("should-not-reach"))
	}))
	defer backend.Close()

	backendURL, _ := url.Parse(backend.URL)
	host := backendURL.Host

	// "never" should be treated as denied
	domains := map[string]string{stripPort(host): "never"}
	p, err := NewProxy(domains, "test")
	if err != nil {
		t.Fatalf("NewProxy failed: %v", err)
	}
	defer p.Shutdown()
	p.Start()

	proxyURL, _ := url.Parse("http://" + p.Addr())
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   5 * time.Second,
	}

	resp, err := client.Get(backend.URL)
	if err != nil {
		t.Fatalf("request through proxy failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden, got %d", resp.StatusCode)
	}
}

func TestProxyUnknownDomainPrompt(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("reached"))
	}))
	defer backend.Close()

	backendURL, _ := url.Parse(backend.URL)
	host := backendURL.Host

	// No pre-cached domain — proxy will try /dev/tty and fail, defaulting to deny
	p, err := NewProxy(nil, "test")
	if err != nil {
		t.Fatalf("NewProxy failed: %v", err)
	}
	defer p.Shutdown()
	p.Start()

	// Mock the tty with a pipe that provides "a\n" (allow)
	pr, pw, err := createMockTTY()
	if err != nil {
		t.Fatalf("failed to create mock tty: %v", err)
	}
	defer pr.Close()
	defer pw.Close()

	p.mu.Lock()
	p.tty = pw // Write end as tty — but we need read+write
	p.mu.Unlock()

	// Instead of mocking /dev/tty (which is hard), test that unknown domains
	// with no tty get denied by default
	p.mu.Lock()
	p.tty = nil // Force tty to be nil so it tries /dev/tty
	p.mu.Unlock()

	// For this test, pre-set a mock tty using a pipe
	mockR, mockW, _ := createPipePair()
	defer mockR.Close()
	defer mockW.Close()

	// Write "a\n" to mock input
	go func() {
		fmt.Fprint(mockW, "a\n")
	}()

	p.mu.Lock()
	p.tty = mockR
	p.mu.Unlock()

	proxyURL, _ := url.Parse("http://" + p.Addr())
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   5 * time.Second,
	}

	resp, err := client.Get(backend.URL)
	if err != nil {
		t.Fatalf("request through proxy failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "reached" {
		t.Errorf("expected 'reached' after allowing, got %q (status %d)", string(body), resp.StatusCode)
	}

	// Verify the domain was cached as "allow"
	domains := p.Domains()
	domain := stripPort(host)
	if domains[domain] != "allow" {
		t.Errorf("expected domain %q to be cached as 'allow', got %q", domain, domains[domain])
	}
}

func TestProxyAlwaysDecisionSaved(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	backendURL, _ := url.Parse(backend.URL)
	host := backendURL.Host

	p, err := NewProxy(nil, "test")
	if err != nil {
		t.Fatalf("NewProxy failed: %v", err)
	}
	defer p.Shutdown()
	p.Start()

	// Mock tty with "l\n" (always)
	mockR, mockW, _ := createPipePair()
	defer mockR.Close()
	defer mockW.Close()

	go func() {
		fmt.Fprint(mockW, "l\n")
	}()

	p.mu.Lock()
	p.tty = mockR
	p.mu.Unlock()

	proxyURL, _ := url.Parse("http://" + p.Addr())
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   5 * time.Second,
	}

	resp, err := client.Get(backend.URL)
	if err != nil {
		t.Fatalf("request through proxy failed: %v", err)
	}
	resp.Body.Close()

	// Verify the domain was cached as "always"
	domains := p.Domains()
	domain := stripPort(host)
	if domains[domain] != "always" {
		t.Errorf("expected domain %q to be cached as 'always', got %q", domain, domains[domain])
	}
}

func TestProxyNeverDecisionSaved(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("should-not-reach"))
	}))
	defer backend.Close()

	backendURL, _ := url.Parse(backend.URL)
	host := backendURL.Host

	p, err := NewProxy(nil, "test")
	if err != nil {
		t.Fatalf("NewProxy failed: %v", err)
	}
	defer p.Shutdown()
	p.Start()

	// Mock tty with "n\n" (never)
	mockR, mockW, _ := createPipePair()
	defer mockR.Close()
	defer mockW.Close()

	go func() {
		fmt.Fprint(mockW, "n\n")
	}()

	p.mu.Lock()
	p.tty = mockR
	p.mu.Unlock()

	proxyURL, _ := url.Parse("http://" + p.Addr())
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   5 * time.Second,
	}

	resp, err := client.Get(backend.URL)
	if err != nil {
		t.Fatalf("request through proxy failed: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for 'never' decision, got %d", resp.StatusCode)
	}

	// Verify the domain was cached as "never"
	domains := p.Domains()
	domain := stripPort(host)
	if domains[domain] != "never" {
		t.Errorf("expected domain %q to be cached as 'never', got %q", domain, domains[domain])
	}
}

func TestProxyCONNECTAllow(t *testing.T) {
	// Start a TLS backend
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("tls-ok"))
	}))
	defer backend.Close()

	backendURL, _ := url.Parse(backend.URL)
	host := backendURL.Host

	domains := map[string]string{stripPort(host): "allow"}
	p, err := NewProxy(domains, "test")
	if err != nil {
		t.Fatalf("NewProxy failed: %v", err)
	}
	defer p.Shutdown()
	p.Start()

	proxyURL, _ := url.Parse("http://" + p.Addr())
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get(backend.URL)
	if err != nil {
		t.Fatalf("CONNECT request through proxy failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "tls-ok" {
		t.Errorf("expected 'tls-ok', got %q", string(body))
	}
}

func TestProxyCONNECTDeny(t *testing.T) {
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("should-not-reach"))
	}))
	defer backend.Close()

	backendURL, _ := url.Parse(backend.URL)
	host := backendURL.Host

	domains := map[string]string{stripPort(host): "deny"}
	p, err := NewProxy(domains, "test")
	if err != nil {
		t.Fatalf("NewProxy failed: %v", err)
	}
	defer p.Shutdown()
	p.Start()

	proxyURL, _ := url.Parse("http://" + p.Addr())
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		Timeout: 5 * time.Second,
	}

	_, err = client.Get(backend.URL)
	if err == nil {
		t.Error("expected error for denied CONNECT, got success")
	}
	// The error should indicate the proxy rejected the connection
	if err != nil && !strings.Contains(err.Error(), "403") && !strings.Contains(err.Error(), "Forbidden") {
		// Connection reset or refused is also acceptable — proxy blocked it
		t.Logf("CONNECT denied with error (expected): %v", err)
	}
}

func TestProxyDomainsReturnsCopy(t *testing.T) {
	domains := map[string]string{"example.com": "allow"}
	p, err := NewProxy(domains, "test")
	if err != nil {
		t.Fatalf("NewProxy failed: %v", err)
	}
	defer p.Shutdown()

	got := p.Domains()
	got["evil.com"] = "allow" // Mutate the copy

	// Original should be unchanged
	original := p.Domains()
	if _, ok := original["evil.com"]; ok {
		t.Error("Domains() should return a copy, not a reference")
	}
}

func TestStripPort(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"example.com:443", "example.com"},
		{"example.com:80", "example.com"},
		{"127.0.0.1:8080", "127.0.0.1"},
		{"example.com", "example.com"},
		{"[::1]:443", "::1"},
	}

	for _, tt := range tests {
		got := stripPort(tt.input)
		if got != tt.expected {
			t.Errorf("stripPort(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestIsAllowed(t *testing.T) {
	if !isAllowed("allow") {
		t.Error("'allow' should be allowed")
	}
	if !isAllowed("always") {
		t.Error("'always' should be allowed")
	}
	if isAllowed("deny") {
		t.Error("'deny' should not be allowed")
	}
	if isAllowed("never") {
		t.Error("'never' should not be allowed")
	}
	if isAllowed("") {
		t.Error("empty string should not be allowed")
	}
}

func TestGenerateProfileProxyMode(t *testing.T) {
	cfg := SandboxConfig{
		AllowNet:   []string{},
		AllowRead:  []string{"."},
		AllowWrite: []string{"."},
	}

	profile := generateProfile(cfg, false, true)

	if !strings.Contains(profile, "Interactive proxy mode") {
		t.Error("proxy mode profile should contain proxy mode comment")
	}
	if !strings.Contains(profile, `(allow network* (remote ip "localhost:*"))`) {
		t.Error("proxy mode profile should only allow localhost network")
	}
	if strings.Contains(profile, "(allow network*)") && !strings.Contains(profile, "remote ip") {
		t.Error("proxy mode should NOT have unrestricted network access")
	}
}

// createMockTTY creates a pipe pair that can simulate /dev/tty for testing.
func createMockTTY() (r *os.File, w *os.File, err error) {
	return os.Pipe()
}

// createPipePair creates an os.Pipe pair for mocking tty input.
func createPipePair() (r *os.File, w *os.File, err error) {
	return os.Pipe()
}
