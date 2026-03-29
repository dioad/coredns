package forward

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/plugin/pkg/proxy"
)

// --- helpers ---

// The following helpers stub HostnameTarget's DNS resolution by injecting a
// custom lookup function (lookupFn) instead of using net.LookupHost directly.

// testLookup is a stubbed net.LookupHost that returns controlled results.
type testLookup struct {
	mu      sync.Mutex
	results []string
	err     error
}

func (l *testLookup) lookup(_ string) ([]string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.results, l.err
}

func (l *testLookup) set(ips []string, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.results = ips
	l.err = err
}

// makeTestTarget builds a HostnameTarget with a custom lookup function instead
// of net.LookupHost, allowing unit tests to control DNS resolution.
func makeTestTarget(hostname string, lookupFn func(string) ([]string, error)) *HostnameTarget {
	ht := newHostnameTarget("forward-test", hostname, "53", "dns", "")
	ht.expire = 10 * time.Second
	ht.opts = proxy.Options{HCRecursionDesired: true, HCDomain: "."}
	// Override the lookup function.
	ht.lookupFn = lookupFn
	return ht
}

// --- tests ---

func TestHostnameTargetResolve(t *testing.T) {
	stub := &testLookup{results: []string{"1.2.3.4", "1.2.3.5"}}
	ht := makeTestTarget("dns.example.com", stub.lookup)

	if err := ht.resolve(); err != nil {
		t.Fatalf("unexpected resolve error: %v", err)
	}

	proxies := ht.Proxies()
	if len(proxies) != 2 {
		t.Fatalf("expected 2 proxies, got %d", len(proxies))
	}
}

func TestHostnameTargetProxyLifecycle(t *testing.T) {
	stub := &testLookup{results: []string{"1.2.3.4", "1.2.3.5"}}
	ht := makeTestTarget("dns.example.com", stub.lookup)

	// Initial resolve: 2 IPs.
	if err := ht.resolve(); err != nil {
		t.Fatalf("initial resolve: %v", err)
	}
	if got := len(ht.Proxies()); got != 2 {
		t.Fatalf("after initial resolve: expected 2 proxies, got %d", got)
	}

	// Simulate IP change: one removed, one added.
	stub.set([]string{"1.2.3.5", "1.2.3.6"}, nil)
	if err := ht.resolve(); err != nil {
		t.Fatalf("second resolve: %v", err)
	}
	proxies := ht.Proxies()
	if len(proxies) != 2 {
		t.Fatalf("after re-resolve: expected 2 proxies, got %d", len(proxies))
	}

	addrs := make(map[string]bool)
	for _, p := range proxies {
		addrs[p.Addr()] = true
	}
	if addrs["1.2.3.4:53"] {
		t.Error("expected 1.2.3.4 to have been removed")
	}
	if !addrs["1.2.3.5:53"] {
		t.Error("expected 1.2.3.5 to be present")
	}
	if !addrs["1.2.3.6:53"] {
		t.Error("expected 1.2.3.6 to be present")
	}
}

func TestHostnameTargetResolveFailureKeepsProxies(t *testing.T) {
	stub := &testLookup{results: []string{"1.2.3.4"}}
	ht := makeTestTarget("dns.example.com", stub.lookup)

	if err := ht.resolve(); err != nil {
		t.Fatalf("initial resolve: %v", err)
	}
	if got := len(ht.Proxies()); got != 1 {
		t.Fatalf("expected 1 proxy, got %d", got)
	}

	// Simulate DNS failure.
	stub.set(nil, &net.DNSError{Err: "connection refused", Name: "dns.example.com"})
	if err := ht.resolve(); err == nil {
		t.Fatal("expected error on DNS failure, got nil")
	}

	// Proxies should be unchanged.
	if got := len(ht.Proxies()); got != 1 {
		t.Fatalf("after failed re-resolve: expected 1 proxy, got %d (proxies should be kept)", got)
	}
}

func TestHostnameTargetProxiesConcurrency(t *testing.T) {
	stub := &testLookup{results: []string{"1.2.3.4"}}
	ht := makeTestTarget("dns.example.com", stub.lookup)
	if err := ht.resolve(); err != nil {
		t.Fatalf("resolve: %v", err)
	}

	var wg sync.WaitGroup
	for range 50 {
		wg.Go(func() {
			_ = ht.Proxies()
		})
	}
	wg.Wait()
}

// TestSetupHostnameTarget verifies that a hostname-based upstream is parsed
// without error and recorded in hostnameTargets (not proxies).
func TestSetupHostnameTarget(t *testing.T) {
	c := caddy.NewTestController("dns", "forward . dns.example.com")
	fs, err := parseForward(c)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	f := fs[0]
	if len(f.proxies) != 0 {
		t.Errorf("expected 0 static proxies, got %d", len(f.proxies))
	}
	if len(f.hostnameTargets) != 1 {
		t.Fatalf("expected 1 hostname target, got %d", len(f.hostnameTargets))
	}
	ht := f.hostnameTargets[0]
	if ht.hostname != "dns.example.com" {
		t.Errorf("expected hostname dns.example.com, got %q", ht.hostname)
	}
	if ht.port != "53" {
		t.Errorf("expected port 53, got %q", ht.port)
	}
}

// TestSetupHostnameTargetWithPort verifies that a hostname with an explicit
// port is parsed correctly.
func TestSetupHostnameTargetWithPort(t *testing.T) {
	c := caddy.NewTestController("dns", "forward . dns.example.com:5353")
	fs, err := parseForward(c)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	f := fs[0]
	if len(f.hostnameTargets) != 1 {
		t.Fatalf("expected 1 hostname target, got %d", len(f.hostnameTargets))
	}
	if f.hostnameTargets[0].port != "5353" {
		t.Errorf("expected port 5353, got %q", f.hostnameTargets[0].port)
	}
}

// TestSetupResolveUpstream verifies that the resolve_upstream directive is
// parsed and stored correctly.
func TestSetupResolveUpstream(t *testing.T) {
	c := caddy.NewTestController("dns", "forward . dns.example.com {\nresolve_upstream 8.8.8.8:53\n}\n")
	fs, err := parseForward(c)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	f := fs[0]
	if f.resolveUpstream != "8.8.8.8:53" {
		t.Errorf("expected resolveUpstream 8.8.8.8:53, got %q", f.resolveUpstream)
	}
	if len(f.hostnameTargets) != 1 {
		t.Fatalf("expected 1 hostname target, got %d", len(f.hostnameTargets))
	}
	if f.hostnameTargets[0].resolverAddr != "8.8.8.8:53" {
		t.Errorf("expected resolverAddr 8.8.8.8:53, got %q", f.hostnameTargets[0].resolverAddr)
	}
}

// TestSetupResolveUpstreamInvalid verifies that an invalid resolve_upstream
// value is rejected at parse time.
func TestSetupResolveUpstreamInvalid(t *testing.T) {
	c := caddy.NewTestController("dns", "forward . dns.example.com {\nresolve_upstream not-an-ip\n}\n")
	_, err := parseForward(c)
	if err == nil {
		t.Fatal("expected parse error for invalid resolve_upstream, got nil")
	}
}

// TestSetupMixedTargets verifies that a mix of IP and hostname targets is
// accepted, with each type stored in the appropriate field.
func TestSetupMixedTargets(t *testing.T) {
	c := caddy.NewTestController("dns", "forward . 8.8.8.8 dns.example.com")
	fs, err := parseForward(c)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	f := fs[0]
	if len(f.proxies) != 1 {
		t.Errorf("expected 1 static proxy, got %d", len(f.proxies))
	}
	if len(f.hostnameTargets) != 1 {
		t.Errorf("expected 1 hostname target, got %d", len(f.hostnameTargets))
	}
}

// TestSplitToTargets verifies the IP vs. hostname classification logic.
func TestSplitToTargets(t *testing.T) {
	tests := []struct {
		input             []string
		wantIPCount       int
		wantHostnameCount int
		wantErr           bool
	}{
		{[]string{"8.8.8.8"}, 1, 0, false},
		{[]string{"8.8.8.8:53"}, 1, 0, false},
		{[]string{"[::1]:53"}, 1, 0, false},
		{[]string{"dns.example.com"}, 0, 1, false},
		{[]string{"dns.example.com:5353"}, 0, 1, false},
		{[]string{"tls://dns.example.com"}, 0, 1, false},
		{[]string{"8.8.8.8", "dns.example.com"}, 1, 1, false},
		{[]string{"/dev/null"}, 1, 0, false},                  // file path → IP path (error propagated by parse.HostPortOrFile)
		{[]string{"dns.example.com:bad:extra"}, 0, 0, true},   // malformed host:port → error
		{[]string{"dns://"}, 0, 0, true},                      // empty address → error
		{[]string{"host%zone.example.com"}, 0, 0, true},       // '%' in hostname → error
		{[]string{"dns://host%zone.example.com"}, 0, 0, true}, // '%' in hostname with scheme → error
	}

	for _, tc := range tests {
		ipTargets, hostnames, err := splitToTargets(tc.input)
		if tc.wantErr && err == nil {
			t.Errorf("input %v: expected error, got nil", tc.input)
		}
		if !tc.wantErr && err != nil {
			t.Errorf("input %v: unexpected error: %v", tc.input, err)
		}
		if len(ipTargets) != tc.wantIPCount {
			t.Errorf("input %v: expected %d IP targets, got %d", tc.input, tc.wantIPCount, len(ipTargets))
		}
		if len(hostnames) != tc.wantHostnameCount {
			t.Errorf("input %v: expected %d hostname targets, got %d", tc.input, tc.wantHostnameCount, len(hostnames))
		}
	}
}
