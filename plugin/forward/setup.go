package forward

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/dnstap"
	"github.com/coredns/coredns/plugin/pkg/fall"
	"github.com/coredns/coredns/plugin/pkg/parse"
	"github.com/coredns/coredns/plugin/pkg/proxy"
	pkgtls "github.com/coredns/coredns/plugin/pkg/tls"
	"github.com/coredns/coredns/plugin/pkg/transport"

	"github.com/miekg/dns"
)

func init() {
	plugin.Register("forward", setup)
}

func setup(c *caddy.Controller) error {
	fs, err := parseForward(c)
	if err != nil {
		return plugin.Error("forward", err)
	}
	for i := range fs {
		f := fs[i]
		// At parse time, hostname targets have no resolved proxies yet; count
		// each declared hostname target as 1 for the purpose of the max check.
		declaredLen := len(f.proxies) + len(f.hostnameTargets)
		if declaredLen > max {
			return plugin.Error("forward", fmt.Errorf("more than %d TOs configured: %d", max, declaredLen))
		}

		if i == len(fs)-1 {
			// last forward: point next to next plugin
			dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
				f.Next = next
				return f
			})
		} else {
			// middle forward: point next to next forward
			nextForward := fs[i+1]
			dnsserver.GetConfig(c).AddPlugin(func(plugin.Handler) plugin.Handler {
				f.Next = nextForward
				return f
			})
		}

		c.OnStartup(func() error {
			return f.OnStartup()
		})
		c.OnStartup(func() error {
			if taph := dnsserver.GetConfig(c).Handler("dnstap"); taph != nil {
				f.SetTapPlugin(taph.(*dnstap.Dnstap))
			}
			return nil
		})

		c.OnShutdown(func() error {
			return f.OnShutdown()
		})
	}

	return nil
}

// OnStartup starts a goroutines for all proxies.
func (f *Forward) OnStartup() (err error) {
	for _, p := range f.proxies {
		p.Start(f.hcInterval)
	}
	for _, ht := range f.hostnameTargets {
		ht.start(f.hcInterval)
	}
	return nil
}

// OnShutdown stops all configured proxies.
func (f *Forward) OnShutdown() error {
	for _, p := range f.proxies {
		p.Stop()
	}
	for _, ht := range f.hostnameTargets {
		ht.Stop()
	}
	return nil
}

func parseForward(c *caddy.Controller) ([]*Forward, error) {
	var fs = []*Forward{}
	for c.Next() {
		f, err := parseStanza(c)
		if err != nil {
			return nil, err
		}
		fs = append(fs, f)
	}
	return fs, nil
}

// Splits the zone, preserving any port that comes after the zone
func splitZone(host string) (newHost string, zone string) {
	trans, host, found := strings.Cut(host, "://")
	if !found {
		host, trans = trans, ""
	}
	newHost = host
	if strings.Contains(host, "%") {
		lastPercent := strings.LastIndex(host, "%")
		newHost = host[:lastPercent]
		if strings.HasPrefix(newHost, "[") {
			newHost = newHost + "]"
		}
		zone = host[lastPercent+1:]
		if strings.Contains(zone, ":") {
			lastColon := strings.LastIndex(zone, ":")
			newHost += zone[lastColon:]
			zone = zone[:lastColon]
			zone = strings.TrimSuffix(zone, "]")
		}
	}
	if trans != "" {
		newHost = trans + "://" + newHost
	}
	return
}

func parseStanza(c *caddy.Controller) (*Forward, error) {
	f := New()

	if !c.Args(&f.from) {
		return f, c.ArgErr()
	}
	origFrom := f.from
	zones := plugin.Host(f.from).NormalizeExact()
	if len(zones) == 0 {
		return f, fmt.Errorf("unable to normalize '%s'", f.from)
	}
	f.from = zones[0] // there can only be one here, won't work with non-octet reverse

	if len(zones) > 1 {
		log.Warningf("Unsupported CIDR notation: '%s' expands to multiple zones. Using only '%s'.", origFrom, f.from)
	}

	to := c.RemainingArgs()
	if len(to) == 0 {
		return f, c.ArgErr()
	}

	// Separate IP/file targets from hostname targets before block parsing,
	// so we can validate them early without needing TLS config yet.
	ipTo, hostnameEntries, err := splitToTargets(to)
	if err != nil {
		return f, err
	}

	var toHosts []string
	if len(ipTo) > 0 {
		toHosts, err = parse.HostPortOrFile(ipTo...)
		if err != nil {
			return f, err
		}
	}

	for c.NextBlock() {
		if err := parseBlock(c, f); err != nil {
			return f, err
		}
	}

	tlsServerNames := make([]string, len(toHosts))
	perServerNameProxyCount := make(map[string]int)
	transports := make([]string, len(toHosts))
	allowedTrans := map[string]bool{"dns": true, "tls": true}
	for i, hostWithZone := range toHosts {
		host, serverName := splitZone(hostWithZone)
		trans, h := parse.Transport(host)

		if !allowedTrans[trans] {
			return f, fmt.Errorf("'%s' is not supported as a destination protocol in forward: %s", trans, host)
		}
		if trans == transport.TLS && serverName != "" {
			if f.tlsServerName != "" {
				return f, fmt.Errorf("both forward ('%s') and proxy level ('%s') TLS servernames are set for upstream proxy '%s'", f.tlsServerName, serverName, host)
			}

			tlsServerNames[i] = serverName
			perServerNameProxyCount[serverName]++
		}
		p := proxy.NewProxy("forward", h, trans)
		f.proxies = append(f.proxies, p)
		transports[i] = trans
	}

	perServerNameTlsConfig := make(map[string]*tls.Config)
	if f.tlsServerName != "" {
		f.tlsConfig.ServerName = f.tlsServerName
	} else {
		for serverName, proxyCount := range perServerNameProxyCount {
			tlsConfig := f.tlsConfig.Clone()
			tlsConfig.ServerName = serverName
			tlsConfig.ClientSessionCache = tls.NewLRUClientSessionCache(proxyCount)
			perServerNameTlsConfig[serverName] = tlsConfig
		}
	}

	// Initialize ClientSessionCache in tls.Config. This may speed up a TLS handshake
	// in upcoming connections to the same TLS server.
	f.tlsConfig.ClientSessionCache = tls.NewLRUClientSessionCache(len(f.proxies))

	for i := range f.proxies {
		// Only set this for proxies that need it.
		if transports[i] == transport.TLS {
			if tlsConfig, ok := perServerNameTlsConfig[tlsServerNames[i]]; ok {
				f.proxies[i].SetTLSConfig(tlsConfig)
			} else {
				f.proxies[i].SetTLSConfig(f.tlsConfig)
			}
		}
		f.proxies[i].SetExpire(f.expire)
		f.proxies[i].SetMaxIdleConns(f.maxIdleConns)
		f.proxies[i].GetHealthchecker().SetRecursionDesired(f.opts.HCRecursionDesired)
		// when TLS is used, checks are set to tcp-tls
		if f.opts.ForceTCP && transports[i] != transport.TLS {
			f.proxies[i].GetHealthchecker().SetTCPTransport()
		}
		f.proxies[i].GetHealthchecker().SetDomain(f.opts.HCDomain)
	}

	// Build HostnameTarget objects for hostname-based upstreams. TLS config and
	// proxy options are now available after block parsing.
	for _, he := range hostnameEntries {
		if !allowedTrans[he.trans] {
			return f, fmt.Errorf("'%s' is not supported as a destination protocol in forward: %s", he.trans, he.hostname)
		}
		ht := newHostnameTarget("forward", he.hostname, he.port, he.trans, f.resolveUpstream)
		ht.expire = f.expire
		ht.maxIdleConns = f.maxIdleConns
		ht.opts = f.opts
		if he.trans == transport.TLS {
			tlsCfg := f.tlsConfig.Clone()
			if f.tlsServerName != "" {
				tlsCfg.ServerName = f.tlsServerName
			}
			ht.tlsConfig = tlsCfg
		}
		f.hostnameTargets = append(f.hostnameTargets, ht)
	}

	return f, nil
}

func parseBlock(c *caddy.Controller, f *Forward) error {
	config := dnsserver.GetConfig(c)

	switch c.Val() {
	case "except":
		ignore := c.RemainingArgs()
		if len(ignore) == 0 {
			return c.ArgErr()
		}
		for i := range ignore {
			f.ignored = append(f.ignored, plugin.Host(ignore[i]).NormalizeExact()...)
		}
	case "max_fails":
		if !c.NextArg() {
			return c.ArgErr()
		}
		n, err := strconv.ParseUint(c.Val(), 10, 32)
		if err != nil {
			return err
		}
		f.maxfails = uint32(n)
	case "max_connect_attempts":
		if !c.NextArg() {
			return c.ArgErr()
		}
		n, err := strconv.ParseUint(c.Val(), 10, 32)
		if err != nil {
			return err
		}
		f.maxConnectAttempts = uint32(n)
	case "health_check":
		if !c.NextArg() {
			return c.ArgErr()
		}
		dur, err := time.ParseDuration(c.Val())
		if err != nil {
			return err
		}
		if dur < 0 {
			return fmt.Errorf("health_check can't be negative: %d", dur)
		}
		f.hcInterval = dur
		f.opts.HCDomain = "."

		for c.NextArg() {
			switch hcOpts := c.Val(); hcOpts {
			case "no_rec":
				f.opts.HCRecursionDesired = false
			case "domain":
				if !c.NextArg() {
					return c.ArgErr()
				}
				hcDomain := c.Val()
				if _, ok := dns.IsDomainName(hcDomain); !ok {
					return fmt.Errorf("health_check: invalid domain name %s", hcDomain)
				}
				f.opts.HCDomain = plugin.Name(hcDomain).Normalize()
			default:
				return fmt.Errorf("health_check: unknown option %s", hcOpts)
			}
		}

	case "force_tcp":
		if c.NextArg() {
			return c.ArgErr()
		}
		f.opts.ForceTCP = true
	case "prefer_udp":
		if c.NextArg() {
			return c.ArgErr()
		}
		f.opts.PreferUDP = true
	case "tls":
		args := c.RemainingArgs()
		if len(args) > 3 {
			return c.ArgErr()
		}

		for i := range args {
			if !filepath.IsAbs(args[i]) && config.Root != "" {
				args[i] = filepath.Join(config.Root, args[i])
			}
		}
		tlsConfig, err := pkgtls.NewTLSConfigFromArgs(args...)
		if err != nil {
			return err
		}
		f.tlsConfig = tlsConfig
	case "tls_servername":
		if !c.NextArg() {
			return c.ArgErr()
		}
		f.tlsServerName = c.Val()
	case "expire":
		if !c.NextArg() {
			return c.ArgErr()
		}
		dur, err := time.ParseDuration(c.Val())
		if err != nil {
			return err
		}
		if dur < 0 {
			return fmt.Errorf("expire can't be negative: %s", dur)
		}
		f.expire = dur
	case "max_idle_conns":
		if !c.NextArg() {
			return c.ArgErr()
		}
		n, err := strconv.Atoi(c.Val())
		if err != nil {
			return err
		}
		if n < 0 {
			return fmt.Errorf("max_idle_conns can't be negative: %d", n)
		}
		f.maxIdleConns = n
	case "policy":
		if !c.NextArg() {
			return c.ArgErr()
		}
		switch x := c.Val(); x {
		case "random":
			f.p = &random{}
		case "round_robin":
			f.p = &roundRobin{}
		case "sequential":
			f.p = &sequential{}
		default:
			return c.Errf("unknown policy '%s'", x)
		}
	case "max_concurrent":
		if !c.NextArg() {
			return c.ArgErr()
		}
		n, err := strconv.Atoi(c.Val())
		if err != nil {
			return err
		}
		if n < 0 {
			return fmt.Errorf("max_concurrent can't be negative: %d", n)
		}
		f.ErrLimitExceeded = errors.New("concurrent queries exceeded maximum " + c.Val())
		f.maxConcurrent = int64(n)
	case "next":
		args := c.RemainingArgs()
		if len(args) == 0 {
			return c.ArgErr()
		}

		for _, rcode := range args {
			var rc int
			var ok bool

			if rc, ok = dns.StringToRcode[strings.ToUpper(rcode)]; !ok {
				return fmt.Errorf("%s is not a valid rcode", rcode)
			}

			f.nextAlternateRcodes = append(f.nextAlternateRcodes, rc)
		}
	case "fallthrough":
		var fall fall.F
		fall.SetZonesFromArgs(c.RemainingArgs())
		f.fall = fall
	case "failfast_all_unhealthy_upstreams":
		args := c.RemainingArgs()
		if len(args) != 0 {
			return c.ArgErr()
		}
		f.failfastUnhealthyUpstreams = true
	case "failover":
		args := c.RemainingArgs()
		if len(args) == 0 {
			return c.ArgErr()
		}
		toRcode := dns.StringToRcode

		for _, rcode := range args {
			rc, ok := toRcode[strings.ToUpper(rcode)]
			if !ok {
				return fmt.Errorf("%s is not a valid rcode", rcode)
			}
			if rc == dns.RcodeSuccess {
				return fmt.Errorf("NoError cannot be used in failover")
			}

			f.failoverRcodes = append(f.failoverRcodes, rc)
		}
	case "resolve_upstream":
		if !c.NextArg() {
			return c.ArgErr()
		}
		resolverAddr := c.Val()
		// Validate and normalize: must be host:port with an IP host, applying default port if needed.
		normalizedAddr, err := parse.HostPort(resolverAddr, "53")
		if err != nil {
			return fmt.Errorf("resolve_upstream: %v", err)
		}
		f.resolveUpstream = normalizedAddr
	default:
		return c.Errf("unknown property '%s'", c.Val())
	}

	return nil
}

const max = 15 // Maximum number of upstreams.

// hostnameEntry holds the parsed components of a hostname-based upstream target.
type hostnameEntry struct {
	hostname string
	port     string
	trans    string
}

// splitToTargets classifies each entry in to as either an IP/file target or a
// hostname target. IP/file targets are returned as-is for parse.HostPortOrFile;
// hostname targets are returned as hostnameEntry values for HostnameTarget.
func splitToTargets(to []string) (ipTargets []string, hostnames []hostnameEntry, err error) {
	for _, t := range to {
		trans, addr := parse.Transport(t)

		// Strip zone ID for IP classification purposes.
		host, port, splitErr := net.SplitHostPort(addr)
		if splitErr != nil {
			// Distinguish a bare host (no port) from a malformed host:port.
			// If the trimmed address (brackets and zone ID stripped) contains
			// a colon but is not a valid IP, the input is malformed (e.g.
			// "dns.example.com:bad:extra"). Bare IPv6 addresses and IPv6 with
			// zone IDs are valid and accepted with no port.
			trimmed := strings.Trim(addr, "[]")
			if idx := strings.LastIndex(trimmed, "%"); idx != -1 {
				trimmed = trimmed[:idx]
			}
			if strings.Contains(trimmed, ":") && net.ParseIP(trimmed) == nil {
				return nil, nil, fmt.Errorf("invalid upstream address %q: %v", addr, splitErr)
			}
			// No port — treat the whole addr as host.
			host = strings.Trim(addr, "[]")
			port = ""
		}
		// Strip any zone suffix (e.g. %eth0) before ParseIP.
		hostNoZone := host
		if idx := strings.LastIndex(host, "%"); idx != -1 {
			hostNoZone = host[:idx]
		}

		if net.ParseIP(hostNoZone) != nil {
			// Definitely an IP address: keep in the existing path.
			ipTargets = append(ipTargets, t)
			continue
		}

		// Not an IP. Check if it looks like a file path (absolute/relative
		// prefix) or if a file with that name actually exists on disk.
		// File paths are routed through parse.HostPortOrFile which handles
		// resolv.conf-style files and returns proper errors.
		if looksLikeFilePath(host) || fileExists(host) {
			ipTargets = append(ipTargets, t)
			continue
		}

		// Treat as a DNS hostname.
		if port == "" {
			switch trans {
			case transport.TLS:
				port = transport.TLSPort
			default:
				port = transport.Port
			}
		}
		hostnames = append(hostnames, hostnameEntry{hostname: host, port: port, trans: trans})
	}
	return ipTargets, hostnames, nil
}

// looksLikeFilePath returns true when s is an absolute or relative path,
// indicating it should be treated as a resolv.conf-style file rather than a
// DNS hostname.
func looksLikeFilePath(s string) bool {
	return strings.HasPrefix(s, "/") ||
		strings.HasPrefix(s, "./") ||
		strings.HasPrefix(s, "../")
}

// fileExists returns true if a file exists at the given path. It is used to
// distinguish relative-path file references (e.g. "resolv.conf") from DNS
// hostnames that happen to contain dots.
func fileExists(s string) bool {
	// Only consider bare names or paths without a scheme (e.g. "dns://").
	// Inputs that look like they contain a URI scheme are treated as hostnames.
	if strings.Contains(s, "://") {
		return false
	}
	_, err := os.Stat(s)
	return err == nil
}
