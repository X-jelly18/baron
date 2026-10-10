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

var testTimeouts = &Timeouts{UpstreamConnect: Duration(2 * time.Second)}

func TestPoolOrdering(t *testing.T) {
	b := testBackend("first", "10.0.0.1:1", "10.0.0.2:1", "10.0.0.3:1")
	p := newPool(b, testTimeouts, nil, quietLog())
	for i := 0; i < 3; i++ {
		if o := p.order(time.Now()); o[0].addr != "10.0.0.1:1" {
			t.Fatal("first policy must always start with the first upstream")
		}
	}
	b = testBackend("round_robin", "10.0.0.1:1", "10.0.0.2:1", "10.0.0.3:1")
	p = newPool(b, testTimeouts, nil, quietLog())
	seen := map[string]int{}
	for i := 0; i < 30; i++ {
		seen[p.order(time.Now())[0].addr]++
	}
	if len(seen) != 3 || seen["10.0.0.1:1"] != 10 {
		t.Fatalf("round robin distribution: %v", seen)
	}
	b = testBackend("least_conn", "10.0.0.1:1", "10.0.0.2:1")
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

func TestPoolFailoverAndPassiveHealth(t *testing.T) {
	dead, live := refusedAddr(t), acceptingAddr(t)
	b := testBackend("first", dead, live)
	p := newPool(b, testTimeouts, nil, quietLog())
	for i := 0; i < 2; i++ {
		c, u, err := p.dial(context.Background())
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		if u.addr != live {
			t.Fatalf("dial %d went to %s", i, u.addr)
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
	if p.ups[0].isHealthy(time.Now()) {
		t.Fatal("after `fall` consecutive dial failures the upstream must be marked down")
	}
	if p.ups[0].dialErr.Load() != 2 || p.ups[1].dialOK.Load() != 2 {
		t.Fatalf("dial counters: err=%d ok=%d", p.ups[0].dialErr.Load(), p.ups[1].dialOK.Load())
	}
	// Now the live one is tried first: no more wasted attempts on the dead one.
	if _, u, err := p.dial(context.Background()); err != nil || u.addr != live || p.ups[0].dialErr.Load() != 2 {
		t.Fatalf("down upstream should be skipped while others are healthy (err=%v)", err)
	}
}

func TestPoolAllDown(t *testing.T) {
	b := testBackend("first", refusedAddr(t), refusedAddr(t))
	p := newPool(b, testTimeouts, nil, quietLog())
	_, _, err := p.dial(context.Background())
	if err == nil || !strings.Contains(err.Error(), "all upstreams failed") {
		t.Fatalf("got %v", err)
	}
}

func TestPoolReuseAcrossReload(t *testing.T) {
	b := testBackend("first", "10.0.0.1:1", "10.0.0.2:1")
	p1 := newPool(b, testTimeouts, nil, quietLog())
	p1.ups[0].active.Store(7)
	b2 := testBackend("first", "10.0.0.1:1", "10.0.0.9:1")
	p2 := newPool(b2, testTimeouts, p1, quietLog())
	if p2.ups[0] != p1.ups[0] || p2.ups[0].active.Load() != 7 {
		t.Fatal("unchanged upstream must be carried over with its state")
	}
	b3 := testBackend("first", "10.0.0.1:1")
	b3.Host = "other.example"
	if p3 := newPool(b3, testTimeouts, p1, quietLog()); p3.ups[0] == p1.ups[0] {
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
