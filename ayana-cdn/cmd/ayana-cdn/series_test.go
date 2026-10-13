package main

import (
	"encoding/json"
	"net/http"
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
