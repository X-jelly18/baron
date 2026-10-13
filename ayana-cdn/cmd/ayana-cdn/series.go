package main

import (
	"context"
	"sync"
	"time"
)

// Per-backend / per-domain throughput history for the panel's live graphs.
//
// A background sampler reads the cumulative byte counters at a fixed cadence
// and stores the delta for each interval in a small ring buffer, so the panel
// can draw the last few minutes of throughput the moment it loads — not only
// what has accrued since the tab was opened. Everything here is per-process:
// the counters reset when the service (re)starts, exactly like every other
// stat in this edge.
//
// Memory is bounded: one ring per backend and per domain bucket (both are
// already bounded sets — backends by config, hosts by configured + "other"),
// each holding seriesCap samples of two uint64s, plus a hard cap on the number
// of distinct keys as a backstop.

const (
	seriesInterval = 2 * time.Second // sampling cadence
	seriesCap      = 90              // samples kept per key (90 * 2s = 3 min window)
	seriesMaxKeys  = 512             // backstop against unbounded key growth
)

// bytePair is a cumulative (or per-interval) up/down byte reading.
type bytePair struct{ up, down uint64 }

// ring is a fixed-size circular buffer of per-interval byte deltas for one key.
// All rings in a store advance in lockstep at the same index each tick, so a
// snapshot across keys is aligned in time. Slots for ticks before a key first
// appeared stay zero, which reads correctly as "no traffic yet".
type ring struct {
	up, down         []uint64
	lastUp, lastDown uint64 // last cumulative reading, for delta computation
	haveLast         bool
}

func newRing(n int) *ring { return &ring{up: make([]uint64, n), down: make([]uint64, n)} }

// write records the per-interval delta at idx from a new cumulative reading.
// The first reading only seeds the baseline (delta 0) so startup does not show
// one giant spike; a counter that went backwards (a reset we somehow observed)
// also yields 0 rather than a huge wrapped value.
func (rg *ring) write(idx int, curUp, curDown uint64) {
	if !rg.haveLast {
		rg.lastUp, rg.lastDown, rg.haveLast = curUp, curDown, true
		rg.up[idx], rg.down[idx] = 0, 0
		return
	}
	du, dd := uint64(0), uint64(0)
	if curUp >= rg.lastUp {
		du = curUp - rg.lastUp
	}
	if curDown >= rg.lastDown {
		dd = curDown - rg.lastDown
	}
	rg.up[idx], rg.down[idx] = du, dd
	rg.lastUp, rg.lastDown = curUp, curDown
}

type seriesStore struct {
	interval time.Duration
	cap      int

	mu       sync.Mutex
	tick     uint64 // number of samples taken; also the next write position via %cap
	total    *ring
	backends map[string]*ring
	hosts    map[string]*ring
}

func newSeriesStore(interval time.Duration, capn int) *seriesStore {
	return &seriesStore{
		interval: interval, cap: capn,
		total:    newRing(capn),
		backends: map[string]*ring{},
		hosts:    map[string]*ring{},
	}
}

// sample takes one reading of the current cumulative counters and advances the
// ring by one interval. Called from the sampler goroutine.
func (st *seriesStore) sample(reg *statsRegistry) {
	bb := reg.backendBytes()
	hb := reg.hostBytes()

	st.mu.Lock()
	defer st.mu.Unlock()
	idx := int(st.tick % uint64(st.cap))

	var tu, td uint64
	for _, v := range bb {
		tu += v.up
		td += v.down
	}
	st.total.write(idx, tu, td)
	writeGroup(st.backends, idx, bb, st.cap)
	writeGroup(st.hosts, idx, hb, st.cap)
	st.tick++
}

// writeGroup writes this tick's delta at idx for every known key, creating
// rings for keys seen for the first time and writing 0 for keys that reported
// nothing this tick (so all rings stay time-aligned).
func writeGroup(m map[string]*ring, idx int, cur map[string]bytePair, capn int) {
	for k, rg := range m {
		if c, ok := cur[k]; ok {
			rg.write(idx, c.up, c.down)
		} else {
			rg.up[idx], rg.down[idx] = 0, 0
		}
	}
	for k, c := range cur {
		if _, ok := m[k]; ok {
			continue
		}
		if len(m) >= seriesMaxKeys {
			continue
		}
		rg := newRing(capn)
		rg.write(idx, c.up, c.down) // seeds baseline, writes 0
		m[k] = rg
	}
}

func (s *Server) runSeries(ctx context.Context) {
	s.series.sample(s.stats) // prime the baseline immediately
	t := time.NewTicker(s.series.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.series.sample(s.stats)
		}
	}
}

// ---- snapshot (JSON for the panel) -----------------------------------------

type seriesPair struct {
	Up   []uint64 `json:"up"`
	Down []uint64 `json:"down"`
}

type seriesDoc struct {
	IntervalMS int64                 `json:"interval_ms"`
	Points     int                   `json:"points"`
	Total      seriesPair            `json:"total"`
	Backends   map[string]seriesPair `json:"backends"`
	Hosts      map[string]seriesPair `json:"hosts"`
}

// snapshot returns the recorded history oldest-first for every key.
func (st *seriesStore) snapshot() seriesDoc {
	st.mu.Lock()
	defer st.mu.Unlock()
	valid := int(min(st.tick, uint64(st.cap)))
	order := func(rg *ring) seriesPair {
		up := make([]uint64, valid)
		down := make([]uint64, valid)
		for i := 0; i < valid; i++ {
			j := int((st.tick - uint64(valid) + uint64(i)) % uint64(st.cap))
			up[i], down[i] = rg.up[j], rg.down[j]
		}
		return seriesPair{Up: up, Down: down}
	}
	doc := seriesDoc{
		IntervalMS: st.interval.Milliseconds(),
		Points:     valid,
		Total:      order(st.total),
		Backends:   make(map[string]seriesPair, len(st.backends)),
		Hosts:      make(map[string]seriesPair, len(st.hosts)),
	}
	for k, rg := range st.backends {
		doc.Backends[k] = order(rg)
	}
	for k, rg := range st.hosts {
		doc.Hosts[k] = order(rg)
	}
	return doc
}
