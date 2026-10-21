package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// upstream is one host:port of a backend. Objects are reused across reloads
// while their dial settings are unchanged.
type upstream struct {
	addr    string
	key     string
	tlsConf *tls.Config // nil for plaintext; owns a TLS session cache

	udpAddr   atomic.Pointer[net.UDPAddr] // resolved at pool build (and reload) for udp backends
	lastReply atomic.Int64                // unix nanos of the last reply any session had from this upstream

	active  atomic.Int64 // open connections through this upstream
	dialOK  atomic.Uint64
	dialErr atomic.Uint64

	mu           sync.Mutex
	activeDown   bool // set by active health checks
	okStreak     int
	failStreak   int
	passiveFails int
	passiveUntil time.Time // passive "down" window after repeated dial failures
	lastErr      string
	lastErrAt    time.Time
	lastCheck    time.Time
	reportedUp   bool // last state written to the log
}

func (u *upstream) healthyLocked(now time.Time) bool {
	return !u.activeDown && !now.Before(u.passiveUntil)
}

func (u *upstream) isHealthy(now time.Time) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.healthyLocked(now)
}

// noteLocked reports whether the health state changed since it was last logged.
func (u *upstream) noteLocked(now time.Time) (changed, up bool) {
	up = u.healthyLocked(now)
	if up != u.reportedUp {
		u.reportedUp = up
		return true, up
	}
	return false, up
}

type upstreamSnapshot struct {
	Addr      string    `json:"addr"`
	Healthy   bool      `json:"healthy"`
	Active    int64     `json:"active"`
	DialOK    uint64    `json:"dials_ok"`
	DialErr   uint64    `json:"dial_errors"`
	LastErr   string    `json:"last_error,omitempty"`
	LastErrAt time.Time `json:"last_error_at,omitempty"`
	LastCheck time.Time `json:"last_check,omitempty"`
}

func (u *upstream) snapshot(now time.Time) upstreamSnapshot {
	u.mu.Lock()
	defer u.mu.Unlock()
	return upstreamSnapshot{
		Addr: u.addr, Healthy: u.healthyLocked(now), Active: u.active.Load(),
		DialOK: u.dialOK.Load(), DialErr: u.dialErr.Load(),
		LastErr: u.lastErr, LastErrAt: u.lastErrAt, LastCheck: u.lastCheck,
	}
}

// pool holds the upstreams of one backend. A path backend's pool holds its
// one server (pinned); only a udp pool holds several and chooses between them.
type pool struct {
	backend  string
	ups      []*upstream
	pinned   bool
	lb       string
	rr       atomic.Uint64
	connect  time.Duration
	ka       keepAlive
	fall     int
	cooldown time.Duration
	log      *slog.Logger
}

// udpFall makes one hard failure (ECONNREFUSED or a reply timeout, both
// unambiguous for UDP) rotate the upstream, instead of the active-check
// default that never runs for datagrams.
func udpFall(b Backend) int {
	if b.isUDP() {
		return 1
	}
	return b.HealthCheck.Fall
}

func upstreamKey(b Backend, addr string) string {
	return fmt.Sprintf("%s|tls=%v|host=%s|insecure=%v", addr, b.useTLS(), b.Host, b.Insecure)
}

func newPool(b Backend, to *Timeouts, prev *pool, log *slog.Logger) *pool {
	p := &pool{
		backend:  b.Name,
		pinned:   b.isPathRouted(),
		lb:       b.LB,
		connect:  to.UpstreamConnect.D(),
		ka:       newKeepAlive(to),
		fall:     udpFall(b),
		cooldown: max(b.HealthCheck.Interval.D(), 5*time.Second),
		log:      log,
	}
	addrs := b.Upstreams
	if p.pinned && len(addrs) > 1 {
		addrs = addrs[:1] // config validation already keeps one; never dial another server
	}
	for _, addr := range addrs {
		key := upstreamKey(b, addr)
		var u *upstream
		if prev != nil {
			for _, pu := range prev.ups {
				if pu.key == key {
					u = pu
					break
				}
			}
		}
		if u == nil {
			u = &upstream{addr: addr, key: key, reportedUp: true}
			if b.useTLS() {
				u.tlsConf = &tls.Config{
					ServerName:         normHost(b.Host),
					InsecureSkipVerify: b.Insecure, //nolint:gosec // operator opt-in per backend
					MinVersion:         tls.VersionTLS12,
					NextProtos:         []string{"http/1.1"},
					ClientSessionCache: tls.NewLRUClientSessionCache(64),
				}
			}
		}
		if b.isUDP() {
			// Resolve here, off the datagram hot path, and re-resolve on every
			// reload (the pool is rebuilt). A name that does not resolve leaves
			// the address unset and dialUDP skips the upstream.
			if ua, err := net.ResolveUDPAddr("udp", addr); err == nil {
				u.udpAddr.Store(ua)
			} else {
				log.Warn("udp upstream does not resolve", "backend", b.Name, "upstream", addr, "err", errString(err))
			}
		}
		p.ups = append(p.ups, u)
	}
	return p
}

// order returns the upstreams of a udp pool to try for a new session: by
// policy, healthy ones first, the rest after them. Unhealthy upstreams stay in
// the list (fail-open): trying a possibly-down upstream beats refusing the
// client outright. Path backends never choose: see dial.
func (p *pool) order(now time.Time) []*upstream {
	n := len(p.ups)
	cands := make([]*upstream, 0, n)
	if p.lb == "first" || n == 1 {
		cands = append(cands, p.ups...)
	} else {
		start := int(p.rr.Add(1) % uint64(n))
		for i := 0; i < n; i++ {
			cands = append(cands, p.ups[(start+i)%n])
		}
		if p.lb == "least_conn" {
			load := make(map[*upstream]int64, n)
			for _, u := range cands {
				load[u] = u.active.Load()
			}
			sort.SliceStable(cands, func(i, j int) bool { return load[cands[i]] < load[cands[j]] })
		}
	}
	out := make([]*upstream, 0, n)
	var down []*upstream
	for _, u := range cands {
		if u.isHealthy(now) {
			out = append(out, u)
		} else {
			down = append(down, u)
		}
	}
	return append(out, down...)
}

// dial connects a client of a path backend (tunnels and HTTP requests) to its
// one server, and to nothing else: if the server does not answer, the client
// gets the error (a 502) and retries; there is no failover to another server.
// The server is dialed even while it is marked down, so service resumes the
// moment it is back. (udp sessions dial through dialUDP.)
func (p *pool) dial(ctx context.Context) (net.Conn, *upstream, error) {
	if len(p.ups) == 0 {
		return nil, nil, errors.New("backend has no upstreams")
	}
	if !p.pinned {
		return nil, nil, errors.New("not a path backend") // unreachable: udp never dials here
	}
	u := p.ups[0]
	c, err := p.dialOne(ctx, u)
	if err != nil {
		if ctx.Err() != nil { // the client went away; not the server's fault
			return nil, nil, ctx.Err()
		}
		u.dialErr.Add(1)
		p.onFailure(u, err)
		return nil, nil, fmt.Errorf("server %s: %s", u.addr, errString(err))
	}
	u.dialOK.Add(1)
	p.onSuccess(u)
	u.active.Add(1)
	return &upstreamConn{Conn: c, u: u}, u, nil
}

func (p *pool) dialOne(ctx context.Context, u *upstream) (net.Conn, error) {
	d := net.Dialer{Timeout: p.connect, KeepAlive: -1} // keepAlive.apply is the single source of truth
	c, err := d.DialContext(ctx, "tcp", u.addr)
	if err != nil {
		return nil, err
	}
	p.ka.apply(c) // the same dead-peer detection as on the client side
	if u.tlsConf == nil {
		return c, nil
	}
	tc := tls.Client(c, u.tlsConf)
	hctx, cancel := context.WithTimeout(ctx, p.connect)
	defer cancel()
	if err := tc.HandshakeContext(hctx); err != nil {
		c.Close()
		return nil, fmt.Errorf("tls handshake: %w", err)
	}
	return tc, nil
}

func (p *pool) onFailure(u *upstream, err error) {
	now := time.Now()
	u.mu.Lock()
	u.lastErr, u.lastErrAt = errString(err), now
	u.passiveFails++
	if u.passiveFails >= p.fall {
		u.passiveFails = 0
		u.passiveUntil = now.Add(p.cooldown)
	}
	changed, up := u.noteLocked(now)
	u.mu.Unlock()
	if changed {
		p.logState(u, up, "consecutive dial failures: "+errString(err))
	}
}

func (p *pool) onSuccess(u *upstream) {
	now := time.Now()
	u.mu.Lock()
	u.passiveFails = 0
	u.passiveUntil = time.Time{}
	changed, up := u.noteLocked(now)
	u.mu.Unlock()
	if changed {
		p.logState(u, up, "dial succeeded")
	}
}

func (p *pool) logState(u *upstream, up bool, why string) {
	if up {
		p.log.Info("upstream UP", "backend", p.backend, "upstream", u.addr, "reason", why)
	} else {
		p.log.Warn("upstream DOWN", "backend", p.backend, "upstream", u.addr, "reason", why)
	}
}

// upstreamConn keeps the per-upstream connection count accurate however the
// connection ends (tunnel close, HTTP keep-alive expiry, errors).
type upstreamConn struct {
	net.Conn
	u    *upstream
	once sync.Once
}

func (c *upstreamConn) Close() error {
	c.once.Do(func() { c.u.active.Add(-1) })
	return c.Conn.Close()
}

// CloseWrite half-closes: a TLS close_notify, or a TCP FIN for plaintext.
func (c *upstreamConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}
