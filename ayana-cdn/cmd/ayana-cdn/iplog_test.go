package main

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestIPLogRecordCountEvict(t *testing.T) {
	t.Parallel()
	l := newIPLog(3)
	now := time.Now()
	if !l.record("a", now) {
		t.Fatal("first sighting should report fresh=true")
	}
	l.record("b", now)
	l.record("c", now) // table full: [a, b, c]
	if l.record("a", now.Add(time.Second)) {
		t.Fatal("repeat sighting should report fresh=false")
	}
	// Touching "a" moves it to the back -> [b, c, a]; the next new IP evicts the
	// least-recently-touched, which is now "b".
	l.record("d", now.Add(2*time.Second))
	rows, total, overflow := l.snapshot(10)
	if total != 3 || overflow != 1 {
		t.Fatalf("total=%d overflow=%d, want 3 and 1", total, overflow)
	}
	seen := map[string]uint64{}
	for _, r := range rows {
		seen[r.IP] = r.Count
	}
	if _, ok := seen["b"]; ok {
		t.Fatal(`"b" should have been evicted as least-recently-touched`)
	}
	if seen["a"] != 2 {
		t.Fatalf(`"a" count = %d, want 2`, seen["a"])
	}
	if _, ok := seen["d"]; !ok {
		t.Fatal(`"d" should be present`)
	}
}

func TestIPLogSnapshotOrderedByHits(t *testing.T) {
	t.Parallel()
	l := newIPLog(100)
	now := time.Now()
	for i := 0; i < 5; i++ {
		l.record("a", now)
	}
	for i := 0; i < 2; i++ {
		l.record("b", now)
	}
	l.record("c", now)
	rows, _, _ := l.snapshot(2)
	if len(rows) != 2 || rows[0].IP != "a" || rows[1].IP != "b" {
		t.Fatalf("top-2 by hits should be a,b; got %+v", rows)
	}
}

func TestGeoResolver(t *testing.T) {
	t.Parallel()
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true, "country": "Testland", "city": "Testville", "country_code": "TL",
		})
	}))
	defer srv.Close()

	g := newGeoResolver()
	g.configure(&GeoConfig{Enabled: true, URL: srv.URL + "/{ip}", RatePerMin: 60000, CacheSize: 100, CacheTTL: Duration(time.Hour)})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go g.run(ctx)

	g.enqueue("8.8.8.8")
	deadline := time.Now().Add(3 * time.Second)
	var info geoInfo
	var ok bool
	for time.Now().Before(deadline) {
		if info, ok = g.lookup("8.8.8.8"); ok {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !ok || info.country != "Testland" || info.cc != "TL" {
		t.Fatalf("public IP should resolve to Testland/TL, got %+v ok=%v", info, ok)
	}

	// Private and CGNAT (carrier-NAT) addresses are never sent to the provider;
	// they are marked locally.
	for _, ip := range []string{"10.1.2.3", "100.64.37.9"} {
		g.enqueue(ip)
		if info, ok := g.lookup(ip); !ok || info.country != "private" {
			t.Fatalf("%s should be marked private without a lookup, got %+v ok=%v", ip, info, ok)
		}
	}
	if hits != 1 {
		t.Fatalf("exactly one outbound lookup expected (public only), got %d", hits)
	}

	// When disabled, nothing is enqueued or resolved.
	g2 := newGeoResolver()
	g2.configure(&GeoConfig{Enabled: false, URL: srv.URL + "/{ip}"})
	go g2.run(ctx)
	g2.enqueue("1.2.3.4")
	time.Sleep(100 * time.Millisecond)
	if _, ok := g2.lookup("1.2.3.4"); ok {
		t.Fatal("disabled resolver must not resolve anything")
	}
}

// TestPanelIPLogEndpoint drives a real tunnel through the edge and checks the
// client IP shows up in the panel's per-backend IP log.
func TestPanelIPLogEndpoint(t *testing.T) {
	e := panelEdge(t, false, wsBackend("echo", startEcho(t, echoOpts{})))
	// open a tunnel so the edge records our client IP for backend "echo"
	tc := e.dial(t)
	if _, err := io.WriteString(tc, upgradeReq("/echo/")); err != nil {
		t.Fatal(err)
	}
	if code, _ := readStatus(t, bufio.NewReader(tc)); code != 101 {
		t.Fatalf("tunnel status %d", code)
	}

	c := panelClient(t, e)
	login(t, c, testPanelUser, testPanelPass).Body.Close()
	eventually(t, "client IP recorded for backend echo", func() bool {
		resp, err := c.Get(panelURL("/api/iplog") + "?backend=echo")
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return false
		}
		var doc struct {
			TotalIPs int        `json:"total_ips"`
			IPs      []ipLogRow `json:"ips"`
		}
		if json.NewDecoder(resp.Body).Decode(&doc) != nil {
			return false
		}
		for _, r := range doc.IPs {
			if r.IP == "127.0.0.1" && r.Count >= 1 {
				return true
			}
		}
		return false
	})

	// Unknown backend -> 404.
	resp, err := c.Get(panelURL("/api/iplog") + "?backend=" + url.QueryEscape("nope"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown backend iplog: want 404, got %d", resp.StatusCode)
	}
}
