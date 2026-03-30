package proxy

import (
	"crypto/tls"
	"sort"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// a persistConn hold the dns.Conn and the last used time.
type persistConn struct {
	c    *dns.Conn
	used time.Time
}

// Transport hold the persistent cache.
type Transport struct {
	avgDialTime  int64                          // kind of average time of dial time
	conns        [typeTotalCount][]*persistConn // Buckets for udp, tcp and tcp-tls.
	expire       time.Duration                  // After this duration a connection is expired.
	maxIdleConns int                            // Max idle connections per transport type; 0 means unlimited.
	addr         string
	tlsConfig    *tls.Config
	proxyName    string

	mu       sync.Mutex
	stop     chan struct{}
	stopOnce sync.Once
}

func newTransport(proxyName, addr string) *Transport {
	t := &Transport{
		avgDialTime: int64(maxDialTimeout / 2),
		conns:       [typeTotalCount][]*persistConn{},
		expire:      defaultExpire,
		addr:        addr,
		stop:        make(chan struct{}),
		proxyName:   proxyName,
	}
	return t
}

// connManager manages the persistent connection cache for UDP and TCP.
func (t *Transport) connManager() {
	ticker := time.NewTicker(defaultExpire)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			t.cleanup(false)
		case <-t.stop:
			t.cleanup(true)
			return
		}
	}
}

// closeConns closes connections.
func closeConns(conns []*persistConn) {
	for _, pc := range conns {
		pc.c.Close()
	}
}

// cleanup removes connections from cache.
func (t *Transport) cleanup(all bool) {
	var toClose []*persistConn

	t.mu.Lock()
	staleTime := time.Now().Add(-t.expire)
	for transtype, stack := range t.conns {
		if len(stack) == 0 {
			continue
		}
		if all {
			t.conns[transtype] = nil
			toClose = append(toClose, stack...)
			continue
		}
		if stack[0].used.After(staleTime) {
			continue
		}

		// connections in stack are sorted by "used"
		good := sort.Search(len(stack), func(i int) bool {
			return stack[i].used.After(staleTime)
		})
		t.conns[transtype] = stack[good:]
		toClose = append(toClose, stack[:good]...)
	}
	t.mu.Unlock()

	// Close connections after releasing lock
	closeConns(toClose)
}

// Yield returns the connection to transport for reuse.
func (t *Transport) Yield(pc *persistConn) {
	pc.used = time.Now()

	t.mu.Lock()

	// Re-check under lock: Stop() closes t.stop before connManager runs
	// cleanup(true), so this select and the append below are atomic with
	// respect to the cleanup. Without this, a Yield that passed a pre-lock
	// stop check could still append after cleanup, leaving an open conn with
	// no manager to ever close it.
	select {
	case <-t.stop:
		t.mu.Unlock()
		pc.c.Close()
		return
	default:
	}

	transtype := t.transportTypeFromConn(pc)

	if t.maxIdleConns > 0 && len(t.conns[transtype]) >= t.maxIdleConns {
		t.mu.Unlock()
		pc.c.Close()
		return
	}

	t.conns[transtype] = append(t.conns[transtype], pc)
	t.mu.Unlock()
}

// Start starts the transport's connection manager.
func (t *Transport) Start() { go t.connManager() }

// Stop stops the transport's connection manager and releases cached
// connections. It is safe to call multiple times.
func (t *Transport) Stop() {
	t.stopOnce.Do(func() {
		close(t.stop)
		// Ensure cached connections are cleaned up even if connManager is
		// not running or never observes the stop signal.
		go t.cleanup(true)
	})
}

// SetExpire sets the connection expire time in transport.
func (t *Transport) SetExpire(expire time.Duration) { t.expire = expire }

// SetMaxIdleConns sets the maximum idle connections per transport type.
// A value of 0 means unlimited (default).
func (t *Transport) SetMaxIdleConns(n int) { t.maxIdleConns = n }

// SetTLSConfig sets the TLS config in transport.
func (t *Transport) SetTLSConfig(cfg *tls.Config) { t.tlsConfig = cfg }

// GetTLSConfig returns the TLS config in transport.
func (t *Transport) GetTLSConfig() *tls.Config { return t.tlsConfig }

const (
	defaultExpire  = 10 * time.Second
	minDialTimeout = 1 * time.Second
	maxDialTimeout = 30 * time.Second
)
