package main

import (
	"bufio"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const proxyHeaderTimeout = 5 * time.Second

var errLimited = errors.New("connection refused by per-IP limits")

// edgeListener wraps the raw TCP listener. Accept only does O(1) work (the
// global cap); anything that may block — reading a PROXY header, per-IP
// admission — happens lazily on the connection's own goroutine, so one slow
// or hostile peer can never stall the accept loop for everyone else.
type edgeListener struct {
	net.Listener
	s      *Server
	active atomic.Int64
}

func (l *edgeListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		st := l.s.state.Load()
		st.keepAlive.apply(c)
		l.s.stats.global.accepted.Add(1)
		if st.maxConns > 0 && l.active.Load() >= st.maxConns {
			l.s.stats.global.rejGlobal.Add(1)
			c.Close()
			continue
		}
		l.active.Add(1)
		return &edgeConn{Conn: c, l: l}, nil
	}
}

// edgeConn resolves the real client address (PROXY protocol, trusted sources
// only) and applies per-IP admission on first use.
type edgeConn struct {
	net.Conn
	l *edgeListener

	initOnce sync.Once
	initErr  error
	r        io.Reader // bufio.Reader if a PROXY header was parsed
	remote   net.Addr

	mu      sync.Mutex
	closed  bool
	ipKey   string
	tracked bool
}

func (c *edgeConn) init() {
	c.initOnce.Do(func() {
		c.remote = c.Conn.RemoteAddr()
		s := c.l.s
		st := s.state.Load()
		if st.cfg.ProxyProtocol && prefixesContain(st.trusted, addrIP(c.remote)) {
			// net/http calls RemoteAddr before it arms the TLS handshake
			// deadline, so bound the header read ourselves.
			_ = c.Conn.SetReadDeadline(time.Now().Add(proxyHeaderTimeout))
			br := bufio.NewReaderSize(c.Conn, 256)
			addr, err := readProxyHeader(br)
			_ = c.Conn.SetReadDeadline(time.Time{})
			if err != nil {
				s.stats.global.proxyErrs.Add(1)
				c.initErr = err
				return
			}
			c.r = br
			if addr != nil {
				c.remote = addr
			}
		}
		ip := addrIP(c.remote)
		if !ip.IsValid() || prefixesContain(st.exempt, ip) {
			return
		}
		key := limiterKey(ip)
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.closed {
			c.initErr = net.ErrClosed
			return
		}
		ok, tracked, reason := s.limiter.admit(key, time.Now())
		if !ok {
			s.stats.global.reject(reason)
			c.initErr = errLimited
			return
		}
		c.ipKey, c.tracked = key, tracked
	})
}

func (c *edgeConn) Read(p []byte) (int, error) {
	c.init()
	if c.initErr != nil {
		return 0, c.initErr
	}
	if c.r != nil {
		return c.r.Read(p)
	}
	return c.Conn.Read(p)
}

func (c *edgeConn) RemoteAddr() net.Addr {
	c.init()
	return c.remote
}

func (c *edgeConn) Close() error {
	c.mu.Lock()
	if !c.closed {
		c.closed = true
		if c.tracked {
			c.l.s.limiter.release(c.ipKey)
		}
		c.l.active.Add(-1)
	}
	c.mu.Unlock()
	return c.Conn.Close()
}
