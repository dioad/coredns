package forward

import (
	"context"
	"testing"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/pkg/fall"
	"github.com/coredns/coredns/plugin/test"

	"github.com/miekg/dns"
)

// nextWriter is a plugin.Handler that records whether it was called and writes
// a fixed response, used to verify that fallthrough reaches the next plugin.
type nextWriter struct {
	called bool
	rcode  int
}

func (n *nextWriter) ServeDNS(_ context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	n.called = true
	m := new(dns.Msg)
	m.SetRcode(r, n.rcode)
	w.WriteMsg(m)
	return n.rcode, nil
}

func (n *nextWriter) Name() string { return "nextwriter" }

// newTestForward creates a Forward pointing at the given server address,
// starts its proxies, and returns it.  The caller must call f.OnShutdown().
func newTestForward(t *testing.T, addr string) *Forward {
	t.Helper()
	c := caddy.NewTestController("dns", "forward . "+addr)
	fs, err := parseForward(c)
	if err != nil {
		t.Fatalf("parseForward: %v", err)
	}
	f := fs[0]
	if err := f.OnStartup(); err != nil {
		t.Fatalf("OnStartup: %v", err)
	}
	return f
}

// TestFallthroughOnNXDOMAIN verifies that when the upstream returns NXDOMAIN
// and fallthrough is configured (with no zone restriction), the next plugin in
// the chain is called instead of the NXDOMAIN being returned to the client.
func TestFallthroughOnNXDOMAIN(t *testing.T) {
	s := dnstest.NewServer(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeNameError) // NXDOMAIN
		w.WriteMsg(m)
	})
	defer s.Close()

	f := newTestForward(t, s.Addr)
	defer f.OnShutdown()

	next := &nextWriter{rcode: dns.RcodeSuccess}
	f.Next = next
	f.fall = fall.Root // fallthrough for all zones

	m := new(dns.Msg)
	m.SetQuestion("nxdomain.example.org.", dns.TypeA)
	rec := dnstest.NewRecorder(&test.ResponseWriter{})

	if _, err := f.ServeDNS(context.TODO(), rec, m); err != nil {
		t.Fatalf("ServeDNS returned error: %v", err)
	}
	if !next.called {
		t.Error("expected next plugin to be called on NXDOMAIN with fallthrough, but it was not")
	}
}

// TestNoFallthroughWithoutOption verifies that when fallthrough is NOT
// configured, an NXDOMAIN from the upstream is returned directly to the client
// and the next plugin is never called.
func TestNoFallthroughWithoutOption(t *testing.T) {
	s := dnstest.NewServer(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeNameError)
		w.WriteMsg(m)
	})
	defer s.Close()

	f := newTestForward(t, s.Addr)
	defer f.OnShutdown()

	next := &nextWriter{rcode: dns.RcodeSuccess}
	f.Next = next
	// f.fall is zero value — Through() always returns false

	m := new(dns.Msg)
	m.SetQuestion("nxdomain.example.org.", dns.TypeA)
	rec := dnstest.NewRecorder(&test.ResponseWriter{})

	if _, err := f.ServeDNS(context.TODO(), rec, m); err != nil {
		t.Fatalf("ServeDNS returned error: %v", err)
	}
	if next.called {
		t.Error("expected next plugin NOT to be called without fallthrough, but it was")
	}
	if rec.Msg == nil || rec.Msg.Rcode != dns.RcodeNameError {
		t.Errorf("expected NXDOMAIN response to be written; got rcode %v", rec.Msg)
	}
}

// TestNoFallthroughOnSuccess verifies that a successful upstream response is
// returned directly to the client even when fallthrough is configured — the
// next plugin must not be called when the upstream answers.
func TestNoFallthroughOnSuccess(t *testing.T) {
	s := dnstest.NewServer(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer, test.A("example.org. IN A 1.2.3.4"))
		w.WriteMsg(m)
	})
	defer s.Close()

	f := newTestForward(t, s.Addr)
	defer f.OnShutdown()

	next := &nextWriter{rcode: dns.RcodeSuccess}
	f.Next = next
	f.fall = fall.Root

	m := new(dns.Msg)
	m.SetQuestion("example.org.", dns.TypeA)
	rec := dnstest.NewRecorder(&test.ResponseWriter{})

	if _, err := f.ServeDNS(context.TODO(), rec, m); err != nil {
		t.Fatalf("ServeDNS returned error: %v", err)
	}
	if next.called {
		t.Error("expected next plugin NOT to be called when upstream returns a valid answer")
	}
	if rec.Msg == nil || len(rec.Msg.Answer) == 0 {
		t.Error("expected answer section in response")
	}
}

// TestFallthroughZoneMatch verifies that fallthrough scoped to a specific zone
// (e.g. "example.org.") triggers for queries in that zone.
func TestFallthroughZoneMatch(t *testing.T) {
	s := dnstest.NewServer(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeNameError)
		w.WriteMsg(m)
	})
	defer s.Close()

	f := newTestForward(t, s.Addr)
	defer f.OnShutdown()

	next := &nextWriter{rcode: dns.RcodeSuccess}
	f.Next = next

	var fa fall.F
	fa.SetZonesFromArgs([]string{"example.org."})
	f.fall = fa

	m := new(dns.Msg)
	m.SetQuestion("sub.example.org.", dns.TypeA)
	rec := dnstest.NewRecorder(&test.ResponseWriter{})

	if _, err := f.ServeDNS(context.TODO(), rec, m); err != nil {
		t.Fatalf("ServeDNS returned error: %v", err)
	}
	if !next.called {
		t.Error("expected next plugin to be called when NXDOMAIN falls through for a matching zone")
	}
}

// TestFallthroughZoneNoMatch verifies that fallthrough scoped to a specific
// zone does NOT trigger for queries outside that zone — NXDOMAIN is returned
// directly.
func TestFallthroughZoneNoMatch(t *testing.T) {
	s := dnstest.NewServer(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeNameError)
		w.WriteMsg(m)
	})
	defer s.Close()

	f := newTestForward(t, s.Addr)
	defer f.OnShutdown()

	next := &nextWriter{rcode: dns.RcodeSuccess}
	f.Next = next

	var fa fall.F
	fa.SetZonesFromArgs([]string{"example.org."}) // only example.org
	f.fall = fa

	m := new(dns.Msg)
	m.SetQuestion("other.example.com.", dns.TypeA) // different zone
	rec := dnstest.NewRecorder(&test.ResponseWriter{})

	if _, err := f.ServeDNS(context.TODO(), rec, m); err != nil {
		t.Fatalf("ServeDNS returned error: %v", err)
	}
	if next.called {
		t.Error("expected next plugin NOT to be called when query zone does not match fallthrough zone")
	}
	if rec.Msg == nil || rec.Msg.Rcode != dns.RcodeNameError {
		t.Errorf("expected NXDOMAIN to be written directly; got rcode %v", rec.Msg)
	}
}

// TestFallthroughConfigParsed verifies that the 'fallthrough' directive in the
// Corefile is parsed and stored correctly on the Forward struct.
func TestFallthroughConfigParsed(t *testing.T) {
	tests := []struct {
		input         string
		expectedZones []string
	}{
		{
			"forward . 127.0.0.1 {\nfallthrough\n}\n",
			[]string{"."},
		},
		{
			"forward . 127.0.0.1 {\nfallthrough example.org\n}\n",
			[]string{"example.org."},
		},
		{
			"forward . 127.0.0.1 {\nfallthrough example.org example.com\n}\n",
			[]string{"example.org.", "example.com."},
		},
	}

	for _, tc := range tests {
		c := caddy.NewTestController("dns", tc.input)
		fs, err := parseForward(c)
		if err != nil {
			t.Fatalf("parseForward(%q): %v", tc.input, err)
		}
		f := fs[0]
		got := f.fall.Zones
		if len(got) != len(tc.expectedZones) {
			t.Errorf("input %q: expected zones %v, got %v", tc.input, tc.expectedZones, got)
			continue
		}
		for i, z := range tc.expectedZones {
			if got[i] != z {
				t.Errorf("input %q zone[%d]: expected %q, got %q", tc.input, i, z, got[i])
			}
		}
	}
}
