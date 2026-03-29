package forward

import (
	"context"
	"crypto/tls"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coredns/coredns/plugin/pkg/proxy"

	"github.com/miekg/dns"
)

// HostnameTarget holds a hostname-based upstream target and manages a dynamic
// set of Proxy objects, one per resolved IP address. It re-resolves the
// hostname at a configured interval and updates the proxy set accordingly.
type HostnameTarget struct {
	mu sync.RWMutex

	hostname     string
	port         string
	transport    string
	proxyName    string
	resolverAddr string // optional: e.g. "8.8.8.8:53". Empty means use net.LookupHost.

	// options forwarded to each created proxy
	tlsConfig    *tls.Config
	expire       time.Duration
	maxIdleConns int
	opts         proxy.Options
	hcInterval   time.Duration // re-resolution and health-check interval

	proxies map[string]*proxy.Proxy // keyed by "ip:port"

	// cachedProxies holds a pre-sorted []*proxy.Proxy snapshot updated atomically
	// by resolve() so that Proxies() is allocation-free and lock-free on the read path.
	cachedProxies atomic.Value // stores []*proxy.Proxy

	// ctx/cancel are used to abort in-flight DNS lookups when Stop() is called.
	ctx    context.Context
	cancel context.CancelFunc

	stop     chan struct{}
	stopOnce sync.Once
	stopped  atomic.Bool
	wg       sync.WaitGroup

	lookupFn func(string) ([]string, error) // injectable for testing; nil → default
}

// newHostnameTarget creates a HostnameTarget. resolverAddr may be empty to use
// the system resolver.
func newHostnameTarget(proxyName, hostname, port, trans string, resolverAddr string) *HostnameTarget {
	ctx, cancel := context.WithCancel(context.Background())
	return &HostnameTarget{
		hostname:     hostname,
		port:         port,
		transport:    trans,
		proxyName:    proxyName,
		resolverAddr: resolverAddr,
		proxies:      make(map[string]*proxy.Proxy),
		stop:         make(chan struct{}),
		ctx:          ctx,
		cancel:       cancel,
	}
}

// start performs the initial resolution and launches a goroutine that
// re-resolves the hostname at the given interval.
func (h *HostnameTarget) start(hcInterval time.Duration) {
	h.hcInterval = hcInterval
	if err := h.resolve(); err != nil {
		log.Warningf("hostname target %s: initial resolution failed: %v", h.hostname, err)
	}

	if hcInterval <= 0 {
		// health_check 0 disables periodic re-resolution.
		return
	}
	h.wg.Go(func() {
		ticker := time.NewTicker(hcInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if h.stopped.Load() {
					return
				}
				if err := h.resolve(); err != nil {
					log.Warningf("hostname target %s: re-resolution failed, keeping existing proxies: %v", h.hostname, err)
				}
			case <-h.stop:
				return
			}
		}
	})
}

// Stop signals the re-resolution goroutine, waits for it to exit, and closes
// all managed proxies. It is safe to call Stop more than once.
func (h *HostnameTarget) Stop() {
	h.stopOnce.Do(func() {
		h.stopped.Store(true)
		h.cancel() // abort any in-flight DNS lookups
		close(h.stop)
	})
	h.wg.Wait()
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, p := range h.proxies {
		p.Stop()
	}
}

// Proxies returns the current proxy snapshot. The slice is pre-sorted by
// address (for deterministic policy ordering) and is updated atomically on
// each successful resolution, so reads are allocation-free and lock-free.
func (h *HostnameTarget) Proxies() []*proxy.Proxy {
	if v := h.cachedProxies.Load(); v != nil {
		return v.([]*proxy.Proxy)
	}
	return nil
}

// resolve looks up the hostname and reconciles the proxy set.
func (h *HostnameTarget) resolve() error {
	// Don't resolve if already stopped.
	if h.stopped.Load() {
		return nil
	}

	ips, err := h.lookupIPs()
	if err != nil {
		return err
	}

	// Build the desired set of addr strings.
	desired := make(map[string]struct{}, len(ips))
	for _, ip := range ips {
		desired[net.JoinHostPort(ip, h.port)] = struct{}{}
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	// Check again under lock to prevent a race between the stopped check
	// above and proxy creation below.
	if h.stopped.Load() {
		return nil
	}

	// Stop and remove proxies whose IPs are no longer present.
	for addr, p := range h.proxies {
		if _, ok := desired[addr]; !ok {
			p.Stop()
			delete(h.proxies, addr)
			log.Infof("hostname target %s: removed proxy %s", h.hostname, addr)
		}
	}

	// Start proxies for newly resolved IPs.
	for addr := range desired {
		if _, exists := h.proxies[addr]; exists {
			continue
		}
		p := h.newProxy(addr)
		h.proxies[addr] = p
		log.Infof("hostname target %s: added proxy %s", h.hostname, addr)
	}

	// Build and atomically cache a sorted proxy snapshot for Proxies().
	out := make([]*proxy.Proxy, 0, len(h.proxies))
	for _, p := range h.proxies {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Addr() < out[j].Addr()
	})
	h.cachedProxies.Store(out)

	return nil
}

// newProxy creates, configures, and starts a proxy for the given address.
// When h.hcInterval is zero or negative (health-check disabled), p.Start
// still receives the zero/negative value, matching the behaviour of
// statically-configured proxies (see Forward.SetProxy).
func (h *HostnameTarget) newProxy(addr string) *proxy.Proxy {
	p := proxy.NewProxy(h.proxyName, addr, h.transport)
	if h.tlsConfig != nil {
		p.SetTLSConfig(h.tlsConfig)
	}
	p.SetExpire(h.expire)
	p.SetMaxIdleConns(h.maxIdleConns)
	p.GetHealthchecker().SetRecursionDesired(h.opts.HCRecursionDesired)
	p.GetHealthchecker().SetDomain(h.opts.HCDomain)
	if h.opts.ForceTCP && h.tlsConfig == nil {
		p.GetHealthchecker().SetTCPTransport()
	}
	p.Start(h.hcInterval)
	return p
}

// lookupIPs resolves h.hostname to a list of IP address strings using either
// a custom DNS server (if h.resolverAddr is set), the injected lookupFn (for
// testing), or the system resolver.
func (h *HostnameTarget) lookupIPs() ([]string, error) {
	if h.lookupFn != nil {
		return h.lookupFn(h.hostname)
	}
	if h.resolverAddr != "" {
		return h.lookupIPsViaDNS()
	}
	return net.DefaultResolver.LookupHost(h.ctx, h.hostname)
}

// lookupIPsViaDNS resolves the hostname by sending A and AAAA queries to
// h.resolverAddr using the miekg/dns client.
func (h *HostnameTarget) lookupIPsViaDNS() ([]string, error) {
	client := &dns.Client{Timeout: 5 * time.Second}

	var ips []string
	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn(h.hostname), qtype)
		msg.RecursionDesired = true

		resp, _, err := client.ExchangeContext(h.ctx, msg, h.resolverAddr)
		if err != nil {
			// Non-fatal: one record type failing is acceptable (e.g. no AAAA).
			log.Debugf("hostname target %s: DNS query (type %d) to %s failed: %v", h.hostname, qtype, h.resolverAddr, err)
			continue
		}
		for _, rr := range resp.Answer {
			switch v := rr.(type) {
			case *dns.A:
				ips = append(ips, v.A.String())
			case *dns.AAAA:
				ips = append(ips, v.AAAA.String())
			}
		}
	}

	if len(ips) == 0 {
		return nil, &net.DNSError{Err: "no records found", Name: h.hostname}
	}
	return ips, nil
}
