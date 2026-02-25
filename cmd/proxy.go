package cmd

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
)

// NetworkProxy is a local HTTP/CONNECT proxy that prompts the user
// before allowing connections to new domains. It reads input from
// /dev/tty so it doesn't conflict with the sandboxed process's stdin.
type NetworkProxy struct {
	listener net.Listener
	server   *http.Server
	domains  map[string]string // domain -> "allow" or "deny"
	mu       sync.Mutex
	tty      *os.File // /dev/tty for interactive prompts
	cmdName  string   // command name for prompt display
}

// NewProxy creates a proxy listening on 127.0.0.1:0 (random port).
// domains is a pre-populated map of domain decisions from .ddash.json.
// cmdName is used in the interactive prompt (e.g. "npm install").
func NewProxy(domains map[string]string, cmdName string) (*NetworkProxy, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("failed to start proxy listener: %w", err)
	}

	p := &NetworkProxy{
		listener: ln,
		domains:  make(map[string]string),
		cmdName:  cmdName,
	}

	// Copy pre-cached domains
	for k, v := range domains {
		p.domains[k] = v
	}

	p.server = &http.Server{Handler: p}

	return p, nil
}

// Start begins serving proxy connections in a background goroutine.
func (p *NetworkProxy) Start() {
	go p.server.Serve(p.listener)
}

// Addr returns the proxy's listen address as "127.0.0.1:PORT".
func (p *NetworkProxy) Addr() string {
	return p.listener.Addr().String()
}

// Domains returns a copy of the current domain decisions map.
func (p *NetworkProxy) Domains() map[string]string {
	p.mu.Lock()
	defer p.mu.Unlock()
	result := make(map[string]string, len(p.domains))
	for k, v := range p.domains {
		result[k] = v
	}
	return result
}

// Shutdown closes the proxy listener and server.
func (p *NetworkProxy) Shutdown() {
	if p.tty != nil {
		p.tty.Close()
	}
	p.server.Close()
	p.listener.Close()
}

// ServeHTTP dispatches CONNECT (HTTPS) vs regular HTTP requests.
func (p *NetworkProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleCONNECT(w, r)
	} else {
		p.handleHTTP(w, r)
	}
}

// handleCONNECT handles HTTPS proxy requests (CONNECT method).
func (p *NetworkProxy) handleCONNECT(w http.ResponseWriter, r *http.Request) {
	domain := stripPort(r.Host)

	decision := p.checkDomain(domain)
	if !isAllowed(decision) {
		http.Error(w, "ddash: connection blocked", http.StatusForbidden)
		return
	}

	// Dial the target
	targetConn, err := net.Dial("tcp", r.Host)
	if err != nil {
		http.Error(w, fmt.Sprintf("ddash: failed to connect to %s: %v", r.Host, err), http.StatusBadGateway)
		return
	}

	// Hijack the client connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		targetConn.Close()
		http.Error(w, "ddash: hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		targetConn.Close()
		http.Error(w, fmt.Sprintf("ddash: hijack failed: %v", err), http.StatusInternalServerError)
		return
	}

	// Send 200 Connection Established
	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// Bidirectional tunnel
	go func() {
		io.Copy(targetConn, clientConn)
		targetConn.Close()
	}()
	go func() {
		io.Copy(clientConn, targetConn)
		clientConn.Close()
	}()
}

// handleHTTP handles plain HTTP proxy requests (non-CONNECT).
func (p *NetworkProxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	domain := stripPort(r.Host)

	decision := p.checkDomain(domain)
	if !isAllowed(decision) {
		http.Error(w, "ddash: connection blocked", http.StatusForbidden)
		return
	}

	// Forward the request
	outReq, err := http.NewRequest(r.Method, r.URL.String(), r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("ddash: bad request: %v", err), http.StatusBadRequest)
		return
	}
	outReq.Header = r.Header.Clone()

	resp, err := http.DefaultTransport.RoundTrip(outReq)
	if err != nil {
		http.Error(w, fmt.Sprintf("ddash: upstream error: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy response headers and body
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// checkDomain returns "allow" or "deny" for a domain, prompting the user
// interactively if the domain hasn't been seen before.
func (p *NetworkProxy) checkDomain(domain string) string {
	p.mu.Lock()
	defer p.mu.Unlock()

	if decision, ok := p.domains[domain]; ok {
		return decision
	}

	// New domain — prompt
	decision := p.promptUser(domain)
	p.domains[domain] = decision
	return decision
}

// promptUser opens /dev/tty and asks the user about a domain.
// Returns "allow" or "deny".
func (p *NetworkProxy) promptUser(domain string) string {
	if p.tty == nil {
		tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
		if err != nil {
			// Can't open tty — deny by default
			fmt.Fprintf(os.Stderr, "ddash: can't open /dev/tty, denying %s\n", domain)
			return "deny"
		}
		p.tty = tty
	}

	fmt.Fprintf(p.tty, "\nddash: %s wants to connect to %s\n", p.cmdName, domain)
	fmt.Fprintf(p.tty, "       [a]llow  [d]eny  a[l]ways  [n]ever: ")

	reader := bufio.NewReader(p.tty)
	line, _ := reader.ReadString('\n')
	line = strings.TrimSpace(strings.ToLower(line))

	switch line {
	case "a", "allow":
		return "allow"
	case "d", "deny":
		return "deny"
	case "l", "always":
		return "always"
	case "n", "never":
		return "never"
	default:
		// Unknown input — treat as deny for safety
		fmt.Fprintf(p.tty, "       (unknown input %q, denying)\n", line)
		return "deny"
	}
}

// stripPort removes :port from a host:port string.
func stripPort(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

// isAllowed returns true if a decision means the connection should proceed.
func isAllowed(decision string) bool {
	return decision == "allow" || decision == "always"
}
