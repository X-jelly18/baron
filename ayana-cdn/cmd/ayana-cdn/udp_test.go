package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"testing"
	"time"
)

// startUDPEcho runs a UDP echo server for a udp backend to relay to.
func startUDPEcho(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 64<<10)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], addr)
		}
	}()
	return pc.LocalAddr().String()
}

func udpBackend(name, listen string, ups ...string) Backend {
	return Backend{Name: name, Upstreams: ups, Proto: "udp", Listen: listen}
}

// udpFlow is a client socket to the edge's udp listener; each socket is a
// distinct flow (source port), so it maps to its own session.
func udpFlow(t *testing.T, edgeAddr string) *net.UDPConn {
	t.Helper()
	raddr, err := net.ResolveUDPAddr("udp", edgeAddr)
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func udpRoundTrip(t *testing.T, c *net.UDPConn, msg string) string {
	t.Helper()
	if _, err := c.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 64<<10)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("read reply to %q: %v", msg, err)
	}
	return string(buf[:n])
}

func TestUDPRelayMultipleFlowsOneAddress(t *testing.T) {
	t.Parallel()
	cfg := newEdgeConfig(t, udpBackend("game", "127.0.0.1:0", startUDPEcho(t)))
	e := startEdge(t, cfg)
	addr := e.s.UDPAddr("game").String()

	// Several flows from one address (distinct source ports): each is its own
	// session and must echo its own payload back, not another flow's.
	const flows = 6
	conns := make([]*net.UDPConn, flows)
	for i := range conns {
		conns[i] = udpFlow(t, addr)
	}
	for round := 0; round < 3; round++ {
		for i, c := range conns {
			want := fmt.Sprintf("flow-%d-round-%d", i, round)
			if got := udpRoundTrip(t, c, want); got != want {
				t.Fatalf("flow %d round %d: got %q", i, round, got)
			}
		}
	}
	eventually(t, "six sessions counted", func() bool {
		var st statusDoc
		if err := json.Unmarshal([]byte(e.adminGet(t, "/status")), &st); err != nil {
			return false
		}
		return st.Connections.UDPSessions == flows
	})
	m := e.adminGet(t, "/metrics")
	if !strings.Contains(m, `ayana_cdn_udp_sessions_active `) ||
		!strings.Contains(m, `ayana_cdn_udp_packets_total{backend="game",direction="up"} `) {
		t.Fatalf("udp metrics missing:\n%s", m)
	}
}

func TestUDPSessionIdleTimeout(t *testing.T) {
	t.Parallel()
	cfg := newEdgeConfig(t, udpBackend("g", "127.0.0.1:0", startUDPEcho(t)))
	cfg.Timeouts = &Timeouts{UDPIdle: Duration(300 * time.Millisecond)}
	e := startEdge(t, cfg)
	c := udpFlow(t, e.s.UDPAddr("g").String())
	if got := udpRoundTrip(t, c, "hi"); got != "hi" {
		t.Fatalf("got %q", got)
	}
	eventually(t, "session opened", func() bool {
		var st statusDoc
		_ = json.Unmarshal([]byte(e.adminGet(t, "/status")), &st)
		return st.Connections.UDPSessions == 1
	})
	eventually(t, "idle session closed", func() bool {
		var st statusDoc
		_ = json.Unmarshal([]byte(e.adminGet(t, "/status")), &st)
		return st.Connections.UDPSessions == 0
	})
	if !strings.Contains(e.logs.String(), "reason=idle_timeout") {
		t.Fatalf("no idle_timeout log:\n%s", e.logs.String())
	}
}

func TestUDPUpstreamUnreachable(t *testing.T) {
	t.Parallel()
	// A closed UDP port: the connected socket gets ECONNREFUSED from the ICMP
	// reply, so the session ends and the drop is not silent.
	dead := refusedUDPAddr(t)
	cfg := newEdgeConfig(t, udpBackend("g", "127.0.0.1:0", dead))
	cfg.Timeouts = &Timeouts{UDPIdle: Duration(5 * time.Second)}
	e := startEdge(t, cfg)
	c := udpFlow(t, e.s.UDPAddr("g").String())
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	eventually(t, "session torn down after ICMP unreachable", func() bool {
		var st statusDoc
		_ = json.Unmarshal([]byte(e.adminGet(t, "/status")), &st)
		return st.Connections.UDPSessions == 0
	})
	eventually(t, "upstream_unreachable logged", func() bool {
		return strings.Contains(e.logs.String(), "reason=upstream_unreachable")
	})
}

func TestUDPGlobalSessionCap(t *testing.T) {
	t.Parallel()
	cfg := newEdgeConfig(t, udpBackend("g", "127.0.0.1:0", startUDPEcho(t)))
	cfg.Limits = &Limits{MaxUDPSessions: 1}
	e := startEdge(t, cfg)
	addr := e.s.UDPAddr("g").String()
	c1 := udpFlow(t, addr)
	if got := udpRoundTrip(t, c1, "one"); got != "one" {
		t.Fatalf("first flow: %q", got)
	}
	c2 := udpFlow(t, addr)
	if _, err := c2.Write([]byte("two")); err != nil {
		t.Fatal(err)
	}
	_ = c2.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
	buf := make([]byte, 64<<10)
	if _, err := c2.Read(buf); err == nil {
		t.Fatal("second flow should have been dropped by the session cap")
	}
	eventually(t, "cap drop counted", func() bool {
		return strings.Contains(e.adminGet(t, "/metrics"), `ayana_cdn_udp_dropped_total{backend="g",reason="global_cap"} 1`)
	})
}

func TestUDPBackendMaxConns(t *testing.T) {
	t.Parallel()
	b := udpBackend("g", "127.0.0.1:0", startUDPEcho(t))
	b.MaxConns = 1
	cfg := newEdgeConfig(t, b)
	e := startEdge(t, cfg)
	addr := e.s.UDPAddr("g").String()
	c1 := udpFlow(t, addr)
	if got := udpRoundTrip(t, c1, "x"); got != "x" {
		t.Fatalf("first: %q", got)
	}
	c2 := udpFlow(t, addr)
	_, _ = c2.Write([]byte("y"))
	_ = c2.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
	buf := make([]byte, 1024)
	if _, err := c2.Read(buf); err == nil {
		t.Fatal("second session should hit the backend cap")
	}
	eventually(t, "backend cap drop counted", func() bool {
		return strings.Contains(e.adminGet(t, "/metrics"), `ayana_cdn_udp_dropped_total{backend="g",reason="backend_cap"} 1`)
	})
}

func TestUDPReloadKeepsSessions(t *testing.T) {
	t.Parallel()
	cfg := newEdgeConfig(t, udpBackend("g", "127.0.0.1:0", startUDPEcho(t)))
	cfg.Timeouts = &Timeouts{UDPIdle: Duration(30 * time.Second)}
	e := startEdge(t, cfg)
	addr := e.s.UDPAddr("g").String()
	c := udpFlow(t, addr)
	if got := udpRoundTrip(t, c, "before"); got != "before" {
		t.Fatalf("before reload: %q", got)
	}
	// A reload that changes an unrelated setting must not touch the socket or
	// the live session.
	ncfg := newEdgeConfig(t, udpBackend("g", cfg.Backends[0].Listen, cfg.Backends[0].Upstreams[0]))
	ncfg.Listen = cfg.Listen
	ncfg.AdminListen = cfg.AdminListen
	ncfg.TLS = cfg.TLS
	ncfg.Timeouts = &Timeouts{UDPIdle: Duration(45 * time.Second)}
	// keep the same random listen port for the udp backend
	ncfg.Backends[0].Listen = e.s.UDPAddr("g").String()
	e.rewrite(ncfg)
	if got := udpRoundTrip(t, c, "after"); got != "after" {
		t.Fatalf("after reload: %q", got)
	}
}

func TestUDPShutdownClosesSessions(t *testing.T) {
	t.Parallel()
	cfg := newEdgeConfig(t, udpBackend("g", "127.0.0.1:0", startUDPEcho(t)))
	cfg.Timeouts = &Timeouts{UDPIdle: Duration(30 * time.Second)}
	e := startEdge(t, cfg)
	c := udpFlow(t, e.s.UDPAddr("g").String())
	if got := udpRoundTrip(t, c, "hi"); got != "hi" {
		t.Fatalf("got %q", got)
	}
	e.stop()
	if !strings.Contains(e.logs.String(), "reason=shutdown") {
		t.Fatalf("session not closed on shutdown:\n%s", e.logs.String())
	}
}

// refusedUDPAddr returns the address of a UDP socket that has been closed, so
// datagrams to it draw an ICMP port-unreachable.
func refusedUDPAddr(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	pc.Close()
	return addr
}

// startUDPBlackhole reads datagrams and never replies: a silently dead upstream.
func startUDPBlackhole(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 64<<10)
		for {
			if _, _, err := pc.ReadFrom(buf); err != nil {
				return
			}
		}
	}()
	return pc.LocalAddr().String()
}

func TestUDPSilentUpstreamClosed(t *testing.T) {
	t.Parallel()
	cfg := newEdgeConfig(t, udpBackend("g", "127.0.0.1:0", startUDPBlackhole(t)))
	cfg.Timeouts = &Timeouts{UDPIdle: Duration(10 * time.Second), UDPReply: Duration(300 * time.Millisecond)}
	e := startEdge(t, cfg)
	c := udpFlow(t, e.s.UDPAddr("g").String())
	if _, err := c.Write([]byte("anyone there")); err != nil {
		t.Fatal(err)
	}
	eventually(t, "silent upstream session reclaimed", func() bool {
		var st statusDoc
		_ = json.Unmarshal([]byte(e.adminGet(t, "/status")), &st)
		return st.Connections.UDPSessions == 0
	})
	if !strings.Contains(e.logs.String(), "reason=upstream_silent") {
		t.Fatalf("no upstream_silent log:\n%s", e.logs.String())
	}
}

func TestUDPOversizeDatagramDropped(t *testing.T) {
	t.Parallel()
	cfg := newEdgeConfig(t, udpBackend("g", "127.0.0.1:0", startUDPEcho(t)))
	cfg.Limits = &Limits{MaxUDPPacket: 1000}
	e := startEdge(t, cfg)
	c := udpFlow(t, e.s.UDPAddr("g").String())
	// A datagram over the cap must be dropped, not truncated and relayed.
	if _, err := c.Write(make([]byte, 1500)); err != nil {
		t.Fatal(err)
	}
	eventually(t, "oversize drop counted", func() bool {
		return strings.Contains(e.adminGet(t, "/metrics"), `ayana_cdn_udp_dropped_total{backend="g",reason="oversize"} 1`)
	})
	// A datagram within the cap still works.
	if got := udpRoundTrip(t, c, "small"); got != "small" {
		t.Fatalf("within-cap datagram: %q", got)
	}
}

func TestUDPHashLoadBalancingIsSticky(t *testing.T) {
	t.Parallel()
	// pickUDP must return a stable, client-dependent order so a re-created
	// session lands on the same upstream (stateful UDP protocols need this).
	b := udpBackend("g", ":0", "10.0.0.1:1", "10.0.0.2:2", "10.0.0.3:3")
	b.LB = "hash"
	eff, err := newEdgeConfig(t, b).Effective()
	if err != nil {
		t.Fatal(err)
	}
	p := newPool(eff.Backends[0], eff.Timeouts, nil, quietLog())
	a := netip.MustParseAddr("203.0.113.7")
	first := p.pickUDP(a)[0].addr
	for i := 0; i < 5; i++ {
		if got := p.pickUDP(a)[0].addr; got != first {
			t.Fatalf("hash not stable for one client: %q then %q", first, got)
		}
	}
	// Different clients should not all pick the same upstream.
	seen := map[string]bool{}
	for _, s := range []string{"203.0.113.1", "203.0.113.2", "203.0.113.3", "198.51.100.9", "192.0.2.5"} {
		seen[p.pickUDP(netip.MustParseAddr(s))[0].addr] = true
	}
	if len(seen) < 2 {
		t.Fatalf("hash sent every client to one upstream: %v", seen)
	}
}

func TestUDPLimiterKeyUnmapsV4(t *testing.T) {
	t.Parallel()
	// On a dual-stack listener an IPv4 client can arrive as ::ffff:a.b.c.d;
	// the read loop unmaps before keying the limiter, so two IPv4 clients must
	// not collapse into one ::/64 bucket.
	a := netip.MustParseAddr("::ffff:203.0.113.7").Unmap()
	b := netip.MustParseAddr("::ffff:198.51.100.9").Unmap()
	if limiterKey(a) == limiterKey(b) {
		t.Fatalf("v4-mapped clients share a limiter key: %q", limiterKey(a))
	}
	if limiterKey(a) != "203.0.113.7" {
		t.Fatalf("unmapped v4 key = %q", limiterKey(a))
	}
}

func TestUDPReloadAddsAndRemovesBackend(t *testing.T) {
	t.Parallel()
	// Start with no udp backend, add one on reload, use it, then remove it.
	base := newEdgeConfig(t, wsBackend("echo", startEcho(t, echoOpts{})))
	base.Timeouts = &Timeouts{UDPIdle: Duration(30 * time.Second)}
	e := startEdge(t, base)

	udpListen := freeUDPPort(t)
	withUDP := newEdgeConfig(t, wsBackend("echo", startEcho(t, echoOpts{})), udpBackend("g", udpListen, startUDPEcho(t)))
	withUDP.Listen, withUDP.AdminListen, withUDP.TLS = base.Listen, base.AdminListen, base.TLS
	withUDP.Timeouts = &Timeouts{UDPIdle: Duration(30 * time.Second)}
	e.rewrite(withUDP)

	c := udpFlow(t, udpListen)
	if got := udpRoundTrip(t, c, "hello-udp"); got != "hello-udp" {
		t.Fatalf("after reload-add: %q", got)
	}

	// Remove the udp backend on another reload; its socket should stop.
	e.rewrite(base)
	eventually(t, "udp listener stopped after reload-remove", func() bool {
		pc, err := net.ListenPacket("udp", udpListen)
		if err != nil {
			return false // still held by the edge
		}
		pc.Close()
		return true
	})
}

func TestUDPPerIPSessionCap(t *testing.T) {
	t.Parallel()
	cfg := newEdgeConfig(t, udpBackend("g", "127.0.0.1:0", startUDPEcho(t)))
	cfg.Limits = &Limits{MaxUDPSessionsPerIP: 1, Exempt: []string{"192.0.2.0/24"}} // one session per client address; loopback not exempt
	e := startEdge(t, cfg)
	addr := e.s.UDPAddr("g").String()
	c1 := udpFlow(t, addr)
	if got := udpRoundTrip(t, c1, "one"); got != "one" {
		t.Fatalf("first: %q", got)
	}
	c2 := udpFlow(t, addr) // same 127.0.0.1 address, new port
	_, _ = c2.Write([]byte("two"))
	_ = c2.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
	buf := make([]byte, 64)
	if _, err := c2.Read(buf); err == nil {
		t.Fatal("second session from the same address should hit max_udp_sessions_per_ip")
	}
	eventually(t, "per-ip drop counted", func() bool {
		return strings.Contains(e.adminGet(t, "/metrics"), `ayana_cdn_udp_dropped_total{backend="g",reason="ip_conns"} 1`)
	})
}

func TestUDPErrorClassifier(t *testing.T) {
	t.Parallel()
	fatal := []error{syscall.ECONNREFUSED, syscall.EHOSTUNREACH, syscall.ENETUNREACH, syscall.EACCES, syscall.EPERM}
	for _, e := range fatal {
		if !isUnreachable(e) {
			t.Errorf("%v should be fatal (unreachable)", e)
		}
		if isTransient(e) {
			t.Errorf("%v should not be transient", e)
		}
	}
	transient := []error{syscall.EMSGSIZE, syscall.EAGAIN, syscall.EINTR, syscall.ENOBUFS}
	for _, e := range transient {
		if !isTransient(e) {
			t.Errorf("%v should be transient", e)
		}
	}
	if isUnreachable(syscall.EMSGSIZE) {
		t.Error("EMSGSIZE must not end a session")
	}
	for _, e := range []error{syscall.EADDRNOTAVAIL, syscall.EMFILE, syscall.ENFILE, syscall.ENOBUFS} {
		if !isLocalExhaustion(e) {
			t.Errorf("%v should be local exhaustion", e)
		}
	}
	if isLocalExhaustion(syscall.ECONNREFUSED) {
		t.Error("ECONNREFUSED is an upstream failure, not local exhaustion")
	}
}

func TestUDPRepliedSessionSurvivesQuietGap(t *testing.T) {
	t.Parallel()
	// A session that replied, went quiet longer than udp_reply but shorter
	// than udp_idle, then sends again must NOT be torn down as upstream_silent:
	// the reply window is measured from the first unanswered send, not the
	// last reply. (Regression for the lastDown-based baseline bug.)
	cfg := newEdgeConfig(t, udpBackend("g", "127.0.0.1:0", startUDPEcho(t)))
	cfg.Timeouts = &Timeouts{UDPReply: Duration(300 * time.Millisecond), UDPIdle: Duration(10 * time.Second)}
	e := startEdge(t, cfg)
	c := udpFlow(t, e.s.UDPAddr("g").String())
	if got := udpRoundTrip(t, c, "first"); got != "first" {
		t.Fatalf("first: %q", got)
	}
	time.Sleep(600 * time.Millisecond) // longer than udp_reply, shorter than udp_idle
	if got := udpRoundTrip(t, c, "second"); got != "second" {
		t.Fatalf("session was wrongly torn down across a quiet gap: %q", got)
	}
	var st statusDoc
	_ = json.Unmarshal([]byte(e.adminGet(t, "/status")), &st)
	if st.Connections.UDPSessions != 1 {
		t.Fatalf("expected the one session to survive, have %d", st.Connections.UDPSessions)
	}
	if strings.Contains(e.logs.String(), "reason=upstream_silent") {
		t.Fatalf("a healthy session was closed as upstream_silent:\n%s", e.logs.String())
	}
}

func TestUDPUnrepliedFIFO(t *testing.T) {
	t.Parallel()
	// The spoof-flood defence keeps unreplied sessions in a per-listener FIFO
	// and evicts the oldest first. Exercise the FIFO mechanics directly.
	var l udpListener
	s1, s2, s3 := &udpSession{}, &udpSession{}, &udpSession{}
	l.addUnreplied(s1)
	l.addUnreplied(s2)
	l.addUnreplied(s3)
	if l.unreplied.Load() != 3 {
		t.Fatalf("unreplied count = %d, want 3", l.unreplied.Load())
	}
	if l.oldestUnreplied() != s1 {
		t.Fatal("oldest should be the first added (s1)")
	}
	// Releasing s1 (it replied) advances the front to s2.
	l.releaseUnreplied(s1)
	if l.unreplied.Load() != 2 || l.oldestUnreplied() != s2 {
		t.Fatalf("after releasing s1: count=%d front=%p (want s2 %p)", l.unreplied.Load(), l.oldestUnreplied(), s2)
	}
	// A double release is a no-op (closeOnce/CAS guard).
	l.releaseUnreplied(s1)
	if l.unreplied.Load() != 2 {
		t.Fatalf("double release changed the count: %d", l.unreplied.Load())
	}
	// Releasing a middle element keeps ordering intact.
	l.releaseUnreplied(s2)
	if l.oldestUnreplied() != s3 || l.unreplied.Load() != 1 {
		t.Fatalf("after releasing s2: front=%p count=%d", l.oldestUnreplied(), l.unreplied.Load())
	}
	l.releaseUnreplied(s3)
	if l.oldestUnreplied() != nil || l.unreplied.Load() != 0 {
		t.Fatalf("empty FIFO: front=%p count=%d", l.oldestUnreplied(), l.unreplied.Load())
	}
}
