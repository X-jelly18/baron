package main

import (
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

func eqU(t *testing.T, got []uint64, want ...uint64) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("length: got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("at %d: got %v want %v", i, got, want)
		}
	}
}

// setBytes sets a backend's cumulative counters, creating it if needed.
func setBytes(reg *statsRegistry, name string, up, down uint64) {
	b := reg.backend(name)
	b.bytesUp.Store(up)
	b.bytesDown.Store(down)
}

func TestSeriesDeltaAndTotal(t *testing.T) {
	reg := newStatsRegistry()
	st := newSeriesStore(2*time.Second, 4)

	setBytes(reg, "x", 0, 0)
	reg.host("h").bytesUp.Store(0)
	st.sample(reg) // prime -> delta 0

	setBytes(reg, "x", 100, 50)
	reg.host("h").bytesUp.Store(100)
	st.sample(reg) // delta 100 / 50

	setBytes(reg, "x", 130, 60)
	reg.host("h").bytesUp.Store(100) // host unchanged this tick
	st.sample(reg)                   // delta 30 / 10 (host 0)

	snap := st.snapshot()
	if snap.IntervalMS != 2000 {
		t.Fatalf("interval_ms: %d", snap.IntervalMS)
	}
	if snap.Points != 3 {
		t.Fatalf("points: %d", snap.Points)
	}
	eqU(t, snap.Backends["x"].Up, 0, 100, 30)
	eqU(t, snap.Backends["x"].Down, 0, 50, 10)
	eqU(t, snap.Total.Up, 0, 100, 30) // total = sum over backends
	eqU(t, snap.Hosts["h"].Up, 0, 100, 0)
}

func TestSeriesRingWrap(t *testing.T) {
	reg := newStatsRegistry()
	st := newSeriesStore(time.Second, 3)
	setBytes(reg, "x", 0, 0)
	st.sample(reg) // prime
	cum := uint64(0)
	for _, v := range []uint64{10, 20, 30, 40} {
		cum += v
		setBytes(reg, "x", cum, 0)
		st.sample(reg)
	}
	snap := st.snapshot()
	if snap.Points != 3 {
		t.Fatalf("points after wrap: %d (want 3)", snap.Points)
	}
	// Oldest two deltas (prime 0, then 10) have rolled off; newest three remain.
	eqU(t, snap.Backends["x"].Up, 20, 30, 40)
}

func TestSeriesCounterReset(t *testing.T) {
	reg := newStatsRegistry()
	st := newSeriesStore(time.Second, 4)
	setBytes(reg, "x", 1000, 0)
	st.sample(reg) // prime at 1000
	setBytes(reg, "x", 500, 0)
	st.sample(reg) // counter went backwards -> delta 0, not a huge wrap
	snap := st.snapshot()
	up := snap.Backends["x"].Up
	if up[len(up)-1] != 0 {
		t.Fatalf("reset should yield delta 0, got %v", up)
	}
}

func TestSeriesNewKeyMidway(t *testing.T) {
	reg := newStatsRegistry()
	st := newSeriesStore(time.Second, 4)
	setBytes(reg, "a", 0, 0)
	st.sample(reg) // tick0: a=0
	setBytes(reg, "a", 10, 0)
	st.sample(reg) // tick1: a +10
	setBytes(reg, "a", 20, 0)
	setBytes(reg, "b", 0, 0) // b appears now
	st.sample(reg)           // tick2: a +10, b baseline (0)
	setBytes(reg, "a", 20, 0)
	setBytes(reg, "b", 5, 0)
	st.sample(reg) // tick3: a +0, b +5

	snap := st.snapshot()
	if snap.Points != 4 {
		t.Fatalf("points: %d", snap.Points)
	}
	eqU(t, snap.Backends["a"].Up, 0, 10, 10, 0)
	eqU(t, snap.Backends["b"].Up, 0, 0, 0, 5) // leading zeros before b existed
}

func TestSeriesEmptySnapshot(t *testing.T) {
	st := newSeriesStore(2*time.Second, 8)
	snap := st.snapshot()
	if snap.Points != 0 || len(snap.Total.Up) != 0 {
		t.Fatalf("fresh store should be empty, got points=%d", snap.Points)
	}
}

func TestSeriesMaxKeysBackstop(t *testing.T) {
	reg := newStatsRegistry()
	st := newSeriesStore(time.Second, 2)
	for i := 0; i < seriesMaxKeys+50; i++ {
		setBytes(reg, "b"+itoa(i), uint64(i), 0)
	}
	st.sample(reg)
	snap := st.snapshot()
	if len(snap.Backends) > seriesMaxKeys {
		t.Fatalf("key count %d exceeds backstop %d", len(snap.Backends), seriesMaxKeys)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	return string(b[p:])
}

// Endpoint: /api/series needs auth and returns the series document.
func TestPanelSeriesEndpoint(t *testing.T) {
	e := panelEdge(t, false)
	c := panelClient(t, e)

	resp, err := c.Get(panelURL("/api/series"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("series without auth: want 401, got %d", resp.StatusCode)
	}

	login(t, c, testPanelUser, testPanelPass).Body.Close()
	resp, err = c.Get(panelURL("/api/series"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("series with session: want 200, got %d", resp.StatusCode)
	}
	var doc seriesDoc
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("series json: %v", err)
	}
	if doc.IntervalMS != seriesInterval.Milliseconds() {
		t.Fatalf("interval_ms: got %d want %d", doc.IntervalMS, seriesInterval.Milliseconds())
	}
	if doc.Backends == nil || doc.Hosts == nil {
		t.Fatal("series doc should always include backends/hosts maps")
	}
}

func TestSeriesSinceIncremental(t *testing.T) {
	reg := newStatsRegistry()
	st := newSeriesStore(time.Second, 8)
	cum := uint64(0)
	setBytes(reg, "x", 0, 0)
	st.sample(reg) // tick -> 1
	for _, v := range []uint64{10, 20, 30, 40} {
		cum += v
		setBytes(reg, "x", cum, 0)
		st.sample(reg) // ticks -> 2..5
	}
	full := st.snapshot()
	if !full.Full || full.Tick != 5 || full.Points != 5 || full.Epoch == "" || full.Cap != 8 {
		t.Fatalf("full snapshot: %+v", full)
	}
	inc := st.snapshotSince(3, full.Epoch)
	if inc.Full || inc.Points != 2 || inc.Tick != 5 {
		t.Fatalf("incremental: full=%v points=%d tick=%d", inc.Full, inc.Points, inc.Tick)
	}
	eqU(t, inc.Backends["x"].Up, 30, 40)
	eqU(t, inc.Total.Up, 30, 40)

	none := st.snapshotSince(5, full.Epoch) // nothing new since the last poll
	if none.Full || none.Points != 0 || len(none.Backends["x"].Up) != 0 {
		t.Fatalf("no-new: %+v", none)
	}
	if _, ok := none.Backends["x"]; !ok {
		t.Fatal("an incremental response must still list every key")
	}
}

func TestSeriesSinceFallsBackToFull(t *testing.T) {
	reg := newStatsRegistry()
	st := newSeriesStore(time.Second, 4)
	setBytes(reg, "x", 0, 0)
	for i := 0; i < 10; i++ { // tick 10, window holds 4
		setBytes(reg, "x", uint64(i*100), 0)
		st.sample(reg)
	}
	ep := st.snapshot().Epoch
	cases := map[string]seriesDoc{
		"new client (no epoch)":     st.snapshotSince(0, ""),
		"process restarted (epoch)": st.snapshotSince(9, "some-other-process"),
		"since ahead of tick":       st.snapshotSince(50, ep),
		"fell behind the window":    st.snapshotSince(2, ep),
	}
	for name, d := range cases {
		if !d.Full || d.Points != 4 {
			t.Errorf("%s: want full window of 4, got full=%v points=%d", name, d.Full, d.Points)
		}
	}
	if d := st.snapshotSince(6, ep); d.Full || d.Points != 4 { // exactly one window behind: still incremental
		t.Errorf("since=tick-cap: want incremental 4 points, got full=%v points=%d", d.Full, d.Points)
	}
}

func TestAcceptsGzip(t *testing.T) {
	for hdr, want := range map[string]bool{
		"":                     false,
		"gzip":                 true,
		"gzip, deflate, br":    true,
		"br;q=1.0, gzip;q=0.8": true,
		"GZIP":                 true,
		"gzip;q=0":             false,
		"gzip; q=0.0":          false,
		"deflate, br":          false,
		"x-gzip":               false,
	} {
		r, _ := http.NewRequest("GET", "/", nil)
		if hdr != "" {
			r.Header.Set("Accept-Encoding", hdr)
		}
		if got := acceptsGzip(r); got != want {
			t.Errorf("Accept-Encoding %q: got %v want %v", hdr, got, want)
		}
	}
}

// The panel API is gzip-compressed for browsers that accept it, and the series
// endpoint honours since/epoch.
func TestPanelGzipAndIncrementalSeries(t *testing.T) {
	e := panelEdge(t, false)
	c := panelClient(t, e)
	login(t, c, testPanelUser, testPanelPass).Body.Close()

	get := func(path string, gz bool) (*http.Response, []byte) {
		t.Helper()
		req, _ := http.NewRequest("GET", panelURL(path), nil)
		if gz {
			req.Header.Set("Accept-Encoding", "gzip") // set by hand: the transport then leaves the body compressed
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var rd io.Reader = resp.Body
		if resp.Header.Get("Content-Encoding") == "gzip" {
			zr, err := gzip.NewReader(resp.Body)
			if err != nil {
				t.Fatalf("%s: bad gzip: %v", path, err)
			}
			rd = zr
		}
		body, _ := io.ReadAll(rd)
		return resp, body
	}

	resp, body := get("/api/status", true)
	if resp.Header.Get("Content-Encoding") != "gzip" || !strings.Contains(resp.Header.Get("Vary"), "Accept-Encoding") {
		t.Fatalf("status not gzipped: CE=%q Vary=%q", resp.Header.Get("Content-Encoding"), resp.Header.Get("Vary"))
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil || doc["version"] != version {
		t.Fatalf("gzipped status does not decode: %v", err)
	}
	if resp, _ := get("/api/status", false); resp.Header.Get("Content-Encoding") != "" {
		t.Fatal("a client without Accept-Encoding: gzip must get an uncompressed body")
	}

	_, body = get("/api/series", true)
	var first seriesDoc
	if err := json.Unmarshal(body, &first); err != nil || !first.Full || first.Epoch == "" {
		t.Fatalf("first series poll should be the full window with an epoch: %v %+v", err, first)
	}
	_, body = get("/api/series?since="+strconv.FormatUint(first.Tick, 10)+"&epoch="+url.QueryEscape(first.Epoch), true)
	var next seriesDoc
	if err := json.Unmarshal(body, &next); err != nil || next.Full {
		t.Fatalf("follow-up poll should be incremental: %v %+v", err, next)
	}
	if uint64(next.Points) != next.Tick-first.Tick {
		t.Fatalf("incremental points %d != tick delta %d", next.Points, next.Tick-first.Tick)
	}
}
