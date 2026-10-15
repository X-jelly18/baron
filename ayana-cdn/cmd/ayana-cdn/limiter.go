package main

import (
	"hash/maphash"
	"sync"
	"sync/atomic"
	"time"
)

// ipLimiter enforces, per client IP (IPv6: per /64), a token-bucket rate for
// new connections and an optional cap on concurrent connections.
//
// It is sharded: the tracking table is split across limiterShards independent
// (mutex, map) pairs chosen by a hash of the key. This keeps lock hold times
// and the per-sweep scan to ~1/N of the whole, so a high connect rate from
// many addresses cannot serialize every admission behind one mutex or stall
// them all during a sweep. The rate/burst/cap settings are read lock-free from
// an atomic pointer, so the hot path never contends on configuration.
//
// Each shard is also size-bounded: once a shard is full it is swept on the
// spot, and if it is still full the new address is admitted untracked rather
// than either growing without bound or turning legitimate clients away.
//
// Defaults are deliberately generous: mobile carriers put many subscribers
// behind one address (CGNAT), and a tunnel edge must not punish them for it.
const (
	limiterShards      = 16
	limiterMaxPerShard = 1 << 16 // ~1M tracked keys total before untracked admission
)

type limiterCfg struct {
	rate    float64 // tokens per second; <= 0 disables rate limiting
	burst   float64
	maxConn int // <= 0 disables the concurrency cap
}

type ipShard struct {
	mu sync.Mutex
	m  map[string]*ipEntry
}

type ipLimiter struct {
	cfg    atomic.Pointer[limiterCfg]
	seed   maphash.Seed
	shards [limiterShards]ipShard
}

type ipEntry struct {
	conns  int
	tokens float64
	last   time.Time
}

func newIPLimiter() *ipLimiter {
	l := &ipLimiter{seed: maphash.MakeSeed()}
	l.cfg.Store(&limiterCfg{})
	for i := range l.shards {
		l.shards[i].m = make(map[string]*ipEntry)
	}
	return l
}

func (l *ipLimiter) configure(lim *Limits) {
	l.configureRaw(lim.ConnRatePerIP, lim.ConnBurstPerIP, lim.MaxConnsPerIP)
}

// configureRaw sets the token-bucket rate/burst and concurrency cap, so the
// same limiter type serves both TCP connections and UDP sessions.
func (l *ipLimiter) configureRaw(rate float64, burst, maxConn int) {
	l.cfg.Store(&limiterCfg{rate: rate, burst: float64(burst), maxConn: maxConn})
}

func (l *ipLimiter) shard(key string) *ipShard {
	return &l.shards[maphash.String(l.seed, key)&(limiterShards-1)]
}

// admit decides whether a new connection from key may proceed. tracked reports
// whether release must be called for it when it closes.
func (l *ipLimiter) admit(key string, now time.Time) (ok, tracked bool, reason string) {
	c := l.cfg.Load()
	if c.rate <= 0 && c.maxConn <= 0 {
		return true, false, ""
	}
	sh := l.shard(key)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	e := sh.m[key]
	if e == nil {
		if len(sh.m) >= limiterMaxPerShard {
			sweepShardLocked(sh, c, now)
			if len(sh.m) >= limiterMaxPerShard {
				// The shard is saturated with active entries; admit without
				// tracking rather than deny a legitimate client. The global
				// max_conns cap still bounds total connections.
				return true, false, ""
			}
		}
		e = &ipEntry{tokens: c.burst, last: now}
		sh.m[key] = e
	}
	if c.rate > 0 {
		e.tokens = min(c.burst, e.tokens+now.Sub(e.last).Seconds()*c.rate)
		e.last = now
		if e.tokens < 1 {
			return false, false, "ip_rate"
		}
	}
	if c.maxConn > 0 && e.conns >= c.maxConn {
		return false, false, "ip_conns"
	}
	if c.rate > 0 {
		e.tokens--
	}
	e.conns++
	return true, true, ""
}

func (l *ipLimiter) release(key string) {
	sh := l.shard(key)
	sh.mu.Lock()
	if e := sh.m[key]; e != nil && e.conns > 0 {
		e.conns--
	}
	sh.mu.Unlock()
}

// sweep drops idle entries (no connections, bucket refilled) to bound memory.
// It locks one shard at a time, so it never blocks the whole limiter at once.
func (l *ipLimiter) sweep(now time.Time) int {
	c := l.cfg.Load()
	n := 0
	for i := range l.shards {
		sh := &l.shards[i]
		sh.mu.Lock()
		n += sweepShardLocked(sh, c, now)
		sh.mu.Unlock()
	}
	return n
}

// sweepShardLocked removes idle, fully-refilled entries from one shard; the
// caller holds sh.mu.
func sweepShardLocked(sh *ipShard, c *limiterCfg, now time.Time) int {
	n := 0
	for k, e := range sh.m {
		refilled := c.rate <= 0 || e.tokens+now.Sub(e.last).Seconds()*c.rate >= c.burst
		if e.conns == 0 && refilled {
			delete(sh.m, k)
			n++
		}
	}
	return n
}

func (l *ipLimiter) size() int {
	n := 0
	for i := range l.shards {
		sh := &l.shards[i]
		sh.mu.Lock()
		n += len(sh.m)
		sh.mu.Unlock()
	}
	return n
}
