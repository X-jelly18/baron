package main

import (
	"context"
	"flag"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func quietLog() *slog.Logger { return slog.New(slog.DiscardHandler) }

// refusedAddr returns an address on which nothing listens.
func refusedAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

func acceptingAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(io.Discard, c); c.Close() }()
		}
	}()
	return ln.Addr().String()
}

func testBackend(lb string, ups ...string) Backend {
	b := Backend{Name: "b", Upstreams: ups, Proto: "ws", LB: lb}
	b.applyDefaults()
	b.HealthCheck.Fall = 2
	return b
}

// udpTestBackend is a udp pool: the only kind that holds several upstreams
// and chooses between them.
func udpTestBackend(lb string, ups ...string) Backend {
	b := Backend{Name: "u", Upstreams: ups, Proto: "udp", Listen: "127.0.0.1:0", LB: lb}
	b.applyDefaults()
	return b
}

// countingAddr is acceptingAddr that counts the connections it accepts.
func countingAddr(t *testing.T) (string, *atomic.Int64) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var n atomic.Int64
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			n.Add(1)
			go func() { _, _ = io.Copy(io.Discard, c); c.Close() }()
		}
	}()
	return ln.Addr().String(), &n
}

var testTimeouts = &Timeouts{UpstreamConnect: Duration(2 * time.Second)}

// A path backend connects to its one server whatever lb an older config
// still names: the pool holds only the first server and every dial goes there,
// however loaded or unhealthy it looks.
func TestPathPoolPinsFirstServer(t *testing.T) {
	first, n1 := countingAddr(t)
	second, n2 := countingAddr(t)
	for _, lb := range []string{"", "path", "first", "round_robin", "least_conn"} {
		b := testBackend(lb, first, second)
		if b.LB != "path" {
			t.Fatalf("lb %q: effective lb = %q, want path", lb, b.LB)
		}
		p := newPool(b, testTimeouts, nil, quietLog())
		if len(p.ups) != 1 || p.ups[0].addr != first {
			t.Fatalf("lb %q: pool holds %d upstreams, want only %s", lb, len(p.ups), first)
		}
		p.ups[0].active.Store(50)                         // busy...
		p.ups[0].passiveUntil = time.Now().Add(time.Hour) // ...and marked down
		for i := 0; i < 5; i++ {
			c, u, err := p.dial(context.Background())
			if err != nil || u.addr != first {
				t.Fatalf("lb %q dial %d: %v %v", lb, i, u, err)
			}
			c.Close()
		}
	}
	eventually(t, "25 connections to the first server", func() bool { return n1.Load() == 25 })
	if n2.Load() != 0 {
		t.Fatalf("the second server was dialed %d times; a path must never reach it", n2.Load())
	}
}

// No failover: when the path's server is down the client gets the error and
// no other server is tried. The server stays the one dialed, even marked down.
func TestPathPoolNoFailover(t *testing.T) {
	dead := refusedAddr(t)
	live, accepted := countingAddr(t)
	p := newPool(testBackend("first", dead, live), testTimeouts, nil, quietLog())
	for i := 0; i < 3; i++ {
		_, _, err := p.dial(context.Background())
		if err == nil || !strings.Contains(err.Error(), "server "+dead) {
			t.Fatalf("dial %d: got %v, want the error of %s", i, err, dead)
		}
	}
	if p.ups[0].isHealthy(time.Now()) {
		t.Fatal("after `fall` consecutive dial failures the server must be marked down")
	}
	if p.ups[0].dialErr.Load() != 3 {
		t.Fatalf("a down server must still be dialed (fail-open): dial errors = %d", p.ups[0].dialErr.Load())
	}
	time.Sleep(50 * time.Millisecond)
	if accepted.Load() != 0 {
		t.Fatalf("failover reached %s %d times", live, accepted.Load())
	}
}

func TestPoolActiveCount(t *testing.T) {
	live := acceptingAddr(t)
	p := newPool(testBackend("", live), testTimeouts, nil, quietLog())
	for i := 0; i < 2; i++ {
		c, u, err := p.dial(context.Background())
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		if u.active.Load() != 1 {
			t.Fatalf("active count = %d", u.active.Load())
		}
		c.Close()
		c.Close() // double close must not double count
		if u.active.Load() != 0 {
			t.Fatalf("active count after close = %d", u.active.Load())
		}
	}
	if p.ups[0].dialOK.Load() != 2 || !p.ups[0].isHealthy(time.Now()) {
		t.Fatalf("dial counters: ok=%d", p.ups[0].dialOK.Load())
	}
}

// udp pools keep choosing between their upstreams (pickUDP uses order).
func TestUDPPoolOrdering(t *testing.T) {
	b := udpTestBackend("first", "10.0.0.1:1", "10.0.0.2:1", "10.0.0.3:1")
	p := newPool(b, testTimeouts, nil, quietLog())
	if len(p.ups) != 3 {
		t.Fatalf("a udp pool must keep every upstream, got %d", len(p.ups))
	}
	for i := 0; i < 3; i++ {
		if o := p.order(time.Now()); o[0].addr != "10.0.0.1:1" {
			t.Fatal("first policy must always start with the first upstream")
		}
	}
	b = udpTestBackend("round_robin", "10.0.0.1:1", "10.0.0.2:1", "10.0.0.3:1")
	p = newPool(b, testTimeouts, nil, quietLog())
	seen := map[string]int{}
	for i := 0; i < 30; i++ {
		seen[p.order(time.Now())[0].addr]++
	}
	if len(seen) != 3 || seen["10.0.0.1:1"] != 10 {
		t.Fatalf("round robin distribution: %v", seen)
	}
	b = udpTestBackend("least_conn", "10.0.0.1:1", "10.0.0.2:1")
	p = newPool(b, testTimeouts, nil, quietLog())
	p.ups[0].active.Store(5)
	for i := 0; i < 4; i++ {
		if o := p.order(time.Now()); o[0].addr != "10.0.0.2:1" {
			t.Fatal("least_conn must prefer the idle upstream")
		}
	}
	// Unhealthy upstreams go last but are kept (fail-open).
	p.ups[1].activeDown = true
	o := p.order(time.Now())
	if len(o) != 2 || o[0].addr != "10.0.0.1:1" || o[1].addr != "10.0.0.2:1" {
		t.Fatalf("unhealthy upstream must move to the end, got %v, %v", o[0].addr, o[1].addr)
	}
}

func TestPoolReuseAcrossReload(t *testing.T) {
	p1 := newPool(testBackend("", "10.0.0.1:1"), testTimeouts, nil, quietLog())
	p1.ups[0].active.Store(7)
	p2 := newPool(testBackend("", "10.0.0.1:1"), testTimeouts, p1, quietLog())
	if p2.ups[0] != p1.ups[0] || p2.ups[0].active.Load() != 7 {
		t.Fatal("an unchanged server must be carried over with its state")
	}
	if p3 := newPool(testBackend("", "10.0.0.9:1"), testTimeouts, p1, quietLog()); p3.ups[0] == p1.ups[0] {
		t.Fatal("a new server address must get a fresh upstream")
	}
	b4 := testBackend("", "10.0.0.1:1")
	b4.Host = "other.example"
	if p4 := newPool(b4, testTimeouts, p1, quietLog()); p4.ups[0] == p1.ups[0] {
		t.Fatal("a changed Host must create a fresh upstream (new TLS settings)")
	}
}

func TestParseInterspersed(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	host := fs.String("host", "", "")
	cfg := fs.String("config", "", "")
	pos, err := parseInterspersed(fs, []string{"native11", "h:443", "--host", "x", "-config", "c.json"})
	if err != nil || len(pos) != 2 || pos[0] != "native11" || pos[1] != "h:443" || *host != "x" || *cfg != "c.json" {
		t.Fatalf("pos=%v host=%q cfg=%q err=%v", pos, *host, *cfg, err)
	}
	fs2 := flag.NewFlagSet("t", flag.ContinueOnError)
	fs2.String("host", "", "")
	pos, _ = parseInterspersed(fs2, []string{"a", "--", "-notaflag"})
	if len(pos) != 2 || pos[1] != "-notaflag" {
		t.Fatalf("after -- everything is positional: %v", pos)
	}
}

// The exact command from the v1 README, which v1 rejected.
func TestBackendCommandsV1Syntax(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	data, _ := os.ReadFile("testdata/v1-config.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout, _ = os.Open(os.DevNull)
	defer func() { os.Stdout = stdout }()

	if err := cmdBackend([]string{"add", "native11", "native11.example.com:443", "--host", "native11.example.com", "-config", path, "-no-reload"}); err != nil {
		t.Fatalf("v1-documented syntax: %v", err)
	}
	if err := cmdBackend([]string{"add", "native11", "x.example.com:443", "-config", path, "-no-reload"}); err == nil {
		t.Fatal("duplicate add accepted")
	}
	if err := cmdBackend([]string{"set", "native11", "-proto", "ws", "-config", path, "-no-reload"}); err != nil {
		t.Fatalf("set proto: %v", err)
	}
	if err := cmdBackend([]string{"set", "native11", "-lb", "bogus", "-config", path, "-no-reload"}); err == nil {
		t.Fatal("invalid value saved")
	}
	if err := cmdBackend([]string{"disable", "native2", "-config", path, "-no-reload"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdBackend([]string{"rm", "native3", "-config", path, "-no-reload"}); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	n11 := findBackend(cfg, "native11")
	if n11 == nil || n11.Proto != "ws" || n11.useTLS() || n11.Host != "native11.example.com" {
		t.Fatalf("native11 = %+v", n11)
	}
	if !findBackend(cfg, "native2").Disabled || findBackend(cfg, "native3") != nil || len(cfg.Backends) != 10 {
		t.Fatal("disable/rm not applied")
	}
}

// New input from the CLI never puts several servers on one path, while an
// older config that already does keeps loading and stays editable.
func TestBackendCommandsOneServerPerPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	raw := &Config{CDNHosts: []string{"cdn.example.com"}, TLS: TLSConfig{Mode: "acme", Email: "a@example.com"},
		Backends: []Backend{{Name: "legacy", Upstreams: []string{"a.example.com:443", "b.example.com:443"}, LB: "least_conn"}}}
	if err := saveRaw(path, raw); err != nil {
		t.Fatal(err)
	}
	stdout, stderr := os.Stdout, os.Stderr
	os.Stdout, _ = os.Open(os.DevNull)
	os.Stderr, _ = os.Open(os.DevNull)
	defer func() { os.Stdout, os.Stderr = stdout, stderr }()
	run := func(args ...string) error {
		return cmdBackend(append(args, "-config", path, "-no-reload"))
	}
	refused := func(want string, args ...string) {
		t.Helper()
		before, _ := os.ReadFile(path)
		err := run(args...)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%v: got %v, want an error containing %q", args, err, want)
		}
		if after, _ := os.ReadFile(path); string(after) != string(before) {
			t.Fatalf("%v: a refused change modified the file", args)
		}
	}
	rawBackend := func(name string) *Backend {
		t.Helper()
		r, err := loadRaw(path)
		if err != nil {
			t.Fatal(err)
		}
		return findBackend(r, name)
	}

	refused("its own path", "add", "pool", "10.0.0.1:80,10.0.0.2:80", "-proto", "ws")
	refused("applies only to udp", "add", "p1", "10.0.0.1:80", "-lb", "least_conn")
	if err := run("add", "p1", "10.0.0.1:80", "-lb", "path"); err != nil {
		t.Fatal(err)
	}
	if b := rawBackend("p1"); b.LB != "" {
		t.Fatalf("lb %q written for a path backend; its one server needs no policy", b.LB)
	}
	if err := run("add", "dns", "10.0.0.1:53,10.0.0.2:53", "-proto", "udp", "-listen", "127.0.0.1:5353", "-lb", "round_robin"); err != nil {
		t.Fatalf("a udp backend may list several upstreams: %v", err)
	}
	refused("its own path", "set", "dns", "-proto", "ws")

	// The older backend stays editable without touching its servers...
	if err := run("set", "legacy", "-host", "h.example.com"); err != nil {
		t.Fatalf("editing an older multi-server path must still work: %v", err)
	}
	if b := rawBackend("legacy"); len(b.Upstreams) != 2 || b.Host != "h.example.com" {
		t.Fatalf("legacy = %+v", b)
	}
	// ...but new servers are one per path, and fixing it drops the old policy.
	refused("its own path", "set", "legacy", "-upstreams", "a.example.com:443,c.example.com:443")
	if err := run("set", "legacy", "-upstreams", "a.example.com:443"); err != nil {
		t.Fatal(err)
	}
	if b := rawBackend("legacy"); len(b.Upstreams) != 1 || b.LB != "" {
		t.Fatalf("legacy after the fix = %+v", b)
	}
}

// The installer gates an upgrade on `check -no-dial`: a config with several
// servers on one path must pass it, with a warning.
func TestCheckWarnsAboutIgnoredServers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	raw := &Config{CDNHosts: []string{"cdn.example.com"}, TLS: TLSConfig{Mode: "acme", Email: "a@example.com"},
		Backends: []Backend{{Name: "legacy", Upstreams: []string{"a.example.com:443", "b.example.com:443"}, LB: "first"}}}
	if err := saveRaw(path, raw); err != nil {
		t.Fatal(err)
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = w
	err = cmdCheck([]string{"-no-dial", "-config", path})
	os.Stdout = stdout
	w.Close()
	out, _ := io.ReadAll(r)
	if err != nil {
		t.Fatalf("check must pass (the upgrade gate): %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "connects to one server only: using a.example.com:443, ignoring b.example.com:443") {
		t.Fatalf("no warning in:\n%s", out)
	}
}
