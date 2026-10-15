package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// startUDPAsymmetric is a udp backend that answers each datagram with `mult`
// times as many bytes — the shape of a request/reply amplifier (DNS, NTP).
func startUDPAsymmetric(t *testing.T, mult int) string {
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
			_, _ = pc.WriteTo(bytes.Repeat([]byte("A"), n*mult), addr)
		}
	}()
	return pc.LocalAddr().String()
}

func udpReadMaybe(c *net.UDPConn, d time.Duration) (string, bool) {
	_ = c.SetReadDeadline(time.Now().Add(d))
	buf := make([]byte, 64<<10)
	n, err := c.Read(buf)
	if err != nil {
		return "", false
	}
	return string(buf[:n]), true
}

// TestUDPAsymmetricReplyDeliveredByDefault guards the regression the audit
// caught: with anti-amplification off by default, a large reply to a small
// request (DNS-style) must be delivered, not withheld.
func TestUDPAsymmetricReplyDeliveredByDefault(t *testing.T) {
	t.Parallel()
	e := startEdge(t, newEdgeConfig(t, udpBackend("dns", "127.0.0.1:0", startUDPAsymmetric(t, 10))))
	c := udpFlow(t, e.s.UDPAddr("dns").String())
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	got, ok := udpReadMaybe(c, 3*time.Second)
	if !ok || len(got) != 40 {
		t.Fatalf("asymmetric reply not delivered by default: ok=%v len=%d", ok, len(got))
	}
}

// TestUDPAmplificationWithholdsThenRecovers checks the opt-in anti-amplification
// limit: the first over-budget reply to an unverified source is withheld, the
// session is NOT reaped as silent, and once the client proves itself (a second
// datagram) the reply flows.
func TestUDPAmplificationWithholdsThenRecovers(t *testing.T) {
	t.Parallel()
	cfg := newEdgeConfig(t, udpBackend("amp", "127.0.0.1:0", startUDPAsymmetric(t, 10)))
	cfg.Limits = &Limits{UDPAmplification: 3} // 10x reply > 3x request -> withheld while unverified
	e := startEdge(t, cfg)
	c := udpFlow(t, e.s.UDPAddr("amp").String())

	if _, err := c.Write([]byte("query")); err != nil {
		t.Fatal(err)
	}
	if _, ok := udpReadMaybe(c, 700*time.Millisecond); ok {
		t.Fatal("first over-budget reply to an unverified source should be withheld")
	}
	// Second datagram on the same flow proves return-routability; now replies flow.
	if _, err := c.Write([]byte("query")); err != nil {
		t.Fatal(err)
	}
	if _, ok := udpReadMaybe(c, 3*time.Second); !ok {
		t.Fatal("after the client's second datagram the reply should be delivered")
	}
	// The session must still be alive (the withheld reply counts as upstream liveness).
	eventually(t, "amplified drop counted, session alive", func() bool {
		var st statusDoc
		if err := json.Unmarshal([]byte(e.adminGet(t, "/status")), &st); err != nil {
			return false
		}
		return st.Connections.UDPSessions >= 1 && st.Connections.UDPDropped["amplified"] >= 1
	})
}

// TestShardedIPLimiter covers the rewritten per-IP limiter: the concurrency
// cap, release, the rate bucket, and that distinct keys do not interfere
// across shards.
func TestShardedIPLimiter(t *testing.T) {
	t.Parallel()
	l := newIPLimiter()
	l.configureRaw(0, 1, 3) // rate off, concurrency cap 3
	now := time.Now()
	for i := 0; i < 3; i++ {
		if ok, tracked, _ := l.admit("k", now); !ok || !tracked {
			t.Fatalf("admit %d should pass", i)
		}
	}
	if ok, _, reason := l.admit("k", now); ok || reason != "ip_conns" {
		t.Fatalf("4th concurrent should be refused by ip_conns, got ok=%v reason=%q", ok, reason)
	}
	l.release("k")
	if ok, _, _ := l.admit("k", now); !ok {
		t.Fatal("after release one slot should free up")
	}
	// A different key is unaffected (independent of shard placement).
	if ok, _, _ := l.admit("other", now); !ok {
		t.Fatal("a different key must have its own budget")
	}

	// Rate bucket: burst 2, 1/s. Two pass immediately, the third is limited.
	r := newIPLimiter()
	r.configureRaw(1, 2, 0)
	t0 := time.Now()
	if ok, _, _ := r.admit("x", t0); !ok {
		t.Fatal("burst 1")
	}
	if ok, _, _ := r.admit("x", t0); !ok {
		t.Fatal("burst 2")
	}
	if ok, _, reason := r.admit("x", t0); ok || reason != "ip_rate" {
		t.Fatalf("3rd within the same instant should be ip_rate, got ok=%v reason=%q", ok, reason)
	}
	// After ~1s a token refills.
	if ok, _, _ := r.admit("x", t0.Add(1100*time.Millisecond)); !ok {
		t.Fatal("a token should refill after ~1s")
	}

	// Sweep removes idle, refilled entries but keeps ones with live conns.
	s := newIPLimiter()
	s.configureRaw(0, 1, 5)
	s.admit("live", now) // conns=1, not swept
	s.admit("idle", now) //nolint - conns incremented
	s.release("idle")    // conns=0, rate off -> refilled -> swept
	if got := s.sweep(now); got != 1 {
		t.Fatalf("sweep should drop exactly the idle entry, dropped %d", got)
	}
	if s.size() != 1 {
		t.Fatalf("one live entry should remain, size=%d", s.size())
	}
}

// TestTunnelRequestBodyFramed is the request-smuggling regression: a body on
// the tunnel path must be forwarded with an explicit Content-Length (or
// chunked), never as bare bytes the backend would parse as a second request.
func TestTunnelRequestBodyFramed(t *testing.T) {
	t.Parallel()
	addr, heads := startCapture(t)
	e := startEdge(t, newEdgeConfig(t, wsBackend("cap", addr)))
	c := e.dial(t)
	body := "SMUGGLED"
	req := "POST /cap/x HTTP/1.1\r\nHost: cdn.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Content-Length: 8\r\n\r\n" + body
	if _, err := io.WriteString(c, req); err != nil {
		t.Fatal(err)
	}
	select {
	case head := <-heads:
		if !strings.Contains(head, "Content-Length: 8") {
			t.Fatalf("backend request head has no Content-Length; body would be smuggled:\n%s", head)
		}
		if strings.Contains(head, body) {
			t.Fatalf("request body leaked into the head:\n%s", head)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("backend never received the request head")
	}
}

// TestTunnelStripsClientForwardingHeaders confirms a client cannot spoof its
// address or the forwarded prefix to the backend on the tunnel path.
func TestTunnelStripsClientForwardingHeaders(t *testing.T) {
	t.Parallel()
	addr, heads := startCapture(t)
	e := startEdge(t, newEdgeConfig(t, wsBackend("cap", addr)))
	c := e.dial(t)
	_, _ = io.WriteString(c, upgradeReq("/cap/",
		"X-Forwarded-For: 9.9.9.9", "X-Forwarded-Prefix: /evil", "X-Real-Ip: 9.9.9.9"))
	select {
	case head := <-heads:
		if strings.Contains(head, "9.9.9.9") {
			t.Fatalf("client X-Forwarded-For/X-Real-Ip not stripped:\n%s", head)
		}
		if strings.Contains(head, "/evil") {
			t.Fatalf("client X-Forwarded-Prefix not stripped:\n%s", head)
		}
		if !strings.Contains(head, "X-Forwarded-Prefix: /cap") {
			t.Fatalf("edge did not set its own X-Forwarded-Prefix:\n%s", head)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("backend never received the request head")
	}
}

// startSlowStream answers an upgrade with a 101 and then streams `chunks`
// 6-byte frames `gap` apart, to test that a half-closed tunnel is not
// truncated while data is still flowing.
func startSlowStream(t *testing.T, chunks int, gap time.Duration) string {
	t.Helper()
	ln := listenLocal(t)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				br := bufio.NewReader(conn)
				if _, err := readHead(br, 64<<10); err != nil {
					return
				}
				_, _ = io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
				for i := 0; i < chunks; i++ {
					if _, err := io.WriteString(conn, "DATA00"); err != nil {
						return
					}
					time.Sleep(gap)
				}
			}()
		}
	}()
	return ln.Addr().String()
}

// TestRelayHalfCloseDoesNotTruncate is the half-close regression (#1): once the
// client half-closes its write side, a still-streaming download from the
// backend must keep flowing (linger is an idle bound), not be cut off a fixed
// half_close after the half-close.
func TestRelayHalfCloseDoesNotTruncate(t *testing.T) {
	t.Parallel()
	const chunks = 8
	const gap = 120 * time.Millisecond
	cfg := newEdgeConfig(t, wsBackend("stream", startSlowStream(t, chunks, gap)))
	cfg.Timeouts = &Timeouts{HalfClose: Duration(200 * time.Millisecond)} // << chunks*gap (~960ms)
	e := startEdge(t, cfg)
	c := e.dial(t)
	if _, err := io.WriteString(c, upgradeReq("/stream/")); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(c)
	if code, head := readStatus(t, br); code != 101 {
		t.Fatalf("status %d: %s", code, head)
	}
	// Half-close the client's write side; the backend keeps streaming.
	if err := c.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	got, err := io.ReadAll(br)
	if err != nil {
		t.Fatalf("read stream: %v (got %d bytes)", err, len(got))
	}
	if want := chunks * len("DATA00"); len(got) != want {
		t.Fatalf("download truncated by the half-close linger: got %d bytes, want %d (%q)", len(got), want, got)
	}
}

// TestHostTrafficCounted is the per-domain live-traffic feature: a request to a
// configured cdn_host shows up in the status host_traffic.
func TestHostTrafficCounted(t *testing.T) {
	t.Parallel()
	e := startEdge(t, newEdgeConfig(t, wsBackend("echo", startEcho(t, echoOpts{}))))
	c := e.dial(t)
	if _, err := io.WriteString(c, upgradeReq("/echo/")); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(c)
	if code, _ := readStatus(t, br); code != 101 {
		t.Fatalf("status %d", code)
	}
	if _, err := io.WriteString(c, "ping!!"); err != nil {
		t.Fatal(err)
	}
	if got := readN(t, br, 6); got != "ping!!" {
		t.Fatalf("echo: %q", got)
	}
	_ = c.CloseWrite()

	eventually(t, "cdn.example host traffic recorded", func() bool {
		for _, h := range e.s.buildStatus().HostTraffic {
			if h.Host == "cdn.example" && h.Requests >= 1 && (h.BytesUp > 0 || h.BytesDown > 0) {
				return true
			}
		}
		return false
	})
}
