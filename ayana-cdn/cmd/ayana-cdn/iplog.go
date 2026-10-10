package main

import (
	"container/list"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Per-backend client-IP log + optional geolocation.
//
// ipLog records, for one backend, how many times each client IP has connected,
// with first/last-seen times. It is an LRU bounded to maxIPLogPerBackend
// entries, so a churn of distinct addresses cannot grow it without bound; the
// number of addresses dropped to stay within the bound is counted as overflow.
// The log is in-memory only (it is not persisted) and lives on backendStats,
// so it survives reloads like the other per-backend counters.
//
// Geolocation is resolved out of band by geoResolver: the hot path only ever
// enqueues an IP, and a single rate-limited worker looks it up against a
// configurable HTTP endpoint and caches the result. It is OFF by default —
// nothing is sent anywhere unless the operator sets geo.enabled — so the IP
// counter works offline and the edge makes no third-party calls unless asked.

const maxIPLogPerBackend = 2048

type ipHit struct {
	ip    string
	count uint64
	first time.Time
	last  time.Time
}

type ipLog struct {
	mu       sync.Mutex
	m        map[string]*list.Element // ip -> element holding *ipHit
	lru      list.List                // most-recently-seen at the back
	max      int
	overflow uint64
}

func newIPLog(max int) *ipLog {
	return &ipLog{m: make(map[string]*list.Element), max: max}
}

// record counts one connection from ip. It returns true the first time an IP
// is seen (so the caller can trigger a geo lookup once, not on every hit).
func (l *ipLog) record(ip string, now time.Time) (fresh bool) {
	if ip == "" {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if el := l.m[ip]; el != nil {
		e := el.Value.(*ipHit)
		e.count++
		e.last = now
		l.lru.MoveToBack(el)
		return false
	}
	if len(l.m) >= l.max {
		if front := l.lru.Front(); front != nil {
			l.lru.Remove(front)
			delete(l.m, front.Value.(*ipHit).ip)
			l.overflow++
		}
	}
	l.m[ip] = l.lru.PushBack(&ipHit{ip: ip, count: 1, first: now, last: now})
	return true
}

type ipLogRow struct {
	IP      string    `json:"ip"`
	Count   uint64    `json:"count"`
	First   time.Time `json:"first"`
	Last    time.Time `json:"last"`
	Country string    `json:"country,omitempty"`
	City    string    `json:"city,omitempty"`
	CC      string    `json:"cc,omitempty"`
}

// snapshot returns the top-N IPs by hit count, plus the total distinct count
// and the overflow (addresses evicted to stay within the bound).
func (l *ipLog) snapshot(limit int) (rows []ipLogRow, total int, overflow uint64) {
	l.mu.Lock()
	rows = make([]ipLogRow, 0, len(l.m))
	for _, el := range l.m {
		e := el.Value.(*ipHit)
		rows = append(rows, ipLogRow{IP: e.ip, Count: e.count, First: e.first, Last: e.last})
	}
	total, overflow = len(l.m), l.overflow
	l.mu.Unlock()
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Count != rows[j].Count {
			return rows[i].Count > rows[j].Count
		}
		return rows[i].Last.After(rows[j].Last)
	})
	if limit > 0 && len(rows) > limit {
		rows = rows[:limit]
	}
	return rows, total, overflow
}

// ---- geolocation ------------------------------------------------------------

type geoInfo struct {
	country string
	city    string
	cc      string
	at      time.Time
}

// geoResolver looks up IP locations against a configurable HTTP endpoint and
// caches them. All state changes go through its mutex; the hot path only calls
// enqueue (cheap, deduplicated). It is reconfigured live on reload.
type geoResolver struct {
	mu      sync.Mutex
	cache   map[string]*list.Element // ip -> element holding geoCacheEntry
	lru     list.List
	pending map[string]bool
	cfg     atomic.Pointer[geoRuntime]
	queue   chan string
	client  *http.Client
	last    time.Time // last outbound lookup, for rate limiting (guarded by mu)
}

type geoCacheEntry struct {
	ip   string
	info geoInfo
}

type geoRuntime struct {
	enabled  bool
	url      string // template containing {ip}
	minGap   time.Duration
	maxCache int
	ttl      time.Duration
}

func newGeoResolver() *geoResolver {
	g := &geoResolver{
		cache:   make(map[string]*list.Element),
		pending: make(map[string]bool),
		queue:   make(chan string, 512),
		client:  &http.Client{Timeout: 6 * time.Second},
	}
	g.cfg.Store(&geoRuntime{})
	return g
}

func (g *geoResolver) configure(c *GeoConfig) {
	rt := &geoRuntime{}
	if c != nil {
		rt.enabled = c.Enabled
		rt.url = c.URL
		rt.maxCache = c.CacheSize
		rt.ttl = c.CacheTTL.D()
		if c.RatePerMin > 0 {
			rt.minGap = time.Minute / time.Duration(c.RatePerMin)
		}
	}
	g.cfg.Store(rt)
}

func (g *geoResolver) enabled() bool { return g.cfg.Load().enabled }

// lookup returns a cached location for ip, if present and not expired.
func (g *geoResolver) lookup(ip string) (geoInfo, bool) {
	rt := g.cfg.Load()
	g.mu.Lock()
	defer g.mu.Unlock()
	el := g.cache[ip]
	if el == nil {
		return geoInfo{}, false
	}
	info := el.Value.(*geoCacheEntry).info
	if rt.ttl > 0 && !info.at.IsZero() && time.Since(info.at) > rt.ttl {
		return info, false // stale: still return it, but report miss so it is refreshed
	}
	g.lru.MoveToBack(el)
	return info, true
}

// enqueue schedules a lookup for ip if geolocation is on, the address is
// public, and it is not already cached-fresh or in flight. Safe to call often.
func (g *geoResolver) enqueue(ip string) {
	rt := g.cfg.Load()
	if !rt.enabled || ip == "" {
		return
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return
	}
	if isPrivateAddr(addr) {
		g.store(ip, geoInfo{country: "private", at: time.Now()}, rt)
		return
	}
	if _, ok := g.lookup(ip); ok {
		return
	}
	g.mu.Lock()
	if g.pending[ip] {
		g.mu.Unlock()
		return
	}
	g.pending[ip] = true
	g.mu.Unlock()
	select {
	case g.queue <- ip:
	default: // queue full: drop, clear pending so a later attempt can retry
		g.mu.Lock()
		delete(g.pending, ip)
		g.mu.Unlock()
	}
}

// run starts the single resolver worker; it exits when ctx is cancelled.
func (g *geoResolver) run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case ip := <-g.queue:
			g.resolve(ctx, ip)
		}
	}
}

func (g *geoResolver) resolve(ctx context.Context, ip string) {
	defer func() {
		g.mu.Lock()
		delete(g.pending, ip)
		g.mu.Unlock()
	}()
	rt := g.cfg.Load()
	if !rt.enabled || rt.url == "" {
		return
	}
	// Rate-limit outbound lookups.
	g.mu.Lock()
	wait := time.Duration(0)
	if rt.minGap > 0 && !g.last.IsZero() {
		if since := time.Since(g.last); since < rt.minGap {
			wait = rt.minGap - since
		}
	}
	g.mu.Unlock()
	if wait > 0 {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
	g.mu.Lock()
	g.last = time.Now()
	g.mu.Unlock()

	info, ok := g.fetch(ctx, rt.url, ip)
	if !ok {
		return
	}
	info.at = time.Now()
	g.store(ip, info, rt)
}

// fetch performs one HTTP geo lookup. It reads the common fields used by the
// popular free providers (ipwho.is, ip-api.com): country, city, and a country
// code under country_code or countryCode. Any JSON object with those keys works.
func (g *geoResolver) fetch(ctx context.Context, urlTmpl, ip string) (geoInfo, bool) {
	cctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, strings.ReplaceAll(urlTmpl, "{ip}", ip), nil)
	if err != nil {
		return geoInfo{}, false
	}
	req.Header.Set("User-Agent", "ayana-cdn/"+version)
	resp, err := g.client.Do(req)
	if err != nil {
		return geoInfo{}, false
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil || resp.StatusCode != http.StatusOK {
		return geoInfo{}, false
	}
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return geoInfo{}, false
	}
	// Providers signal failure differently; treat an explicit failure as a miss.
	if v, ok := m["success"].(bool); ok && !v {
		return geoInfo{}, false
	}
	if v, ok := m["status"].(string); ok && v != "" && v != "success" {
		return geoInfo{}, false
	}
	str := func(keys ...string) string {
		for _, k := range keys {
			if s, ok := m[k].(string); ok && s != "" {
				return s
			}
		}
		return ""
	}
	info := geoInfo{country: str("country"), city: str("city"), cc: str("country_code", "countryCode", "cc")}
	if info.country == "" && info.cc == "" && info.city == "" {
		return geoInfo{}, false
	}
	return info, true
}

func (g *geoResolver) store(ip string, info geoInfo, rt *geoRuntime) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if el := g.cache[ip]; el != nil {
		el.Value.(*geoCacheEntry).info = info
		g.lru.MoveToBack(el)
		return
	}
	maxc := rt.maxCache
	if maxc <= 0 {
		maxc = 50000
	}
	for len(g.cache) >= maxc {
		front := g.lru.Front()
		if front == nil {
			break
		}
		g.lru.Remove(front)
		delete(g.cache, front.Value.(*geoCacheEntry).ip)
	}
	g.cache[ip] = g.lru.PushBack(&geoCacheEntry{ip: ip, info: info})
}

// reservedPrefixes are non-global IPv4 ranges netip has no predicate for but
// that are never a globally-routable client and must not be sent to a geo
// service: CGNAT (shared carrier-NAT subscriber space) above all, plus
// benchmarking/protocol/documentation/reserved blocks.
var reservedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),   // RFC 6598 carrier-grade NAT
	netip.MustParsePrefix("198.18.0.0/15"),   // RFC 2544 benchmarking
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // TEST-NET-1 (documentation)
	netip.MustParsePrefix("198.51.100.0/24"), // TEST-NET-2
	netip.MustParsePrefix("203.0.113.0/24"),  // TEST-NET-3
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved
}

// isPrivateAddr reports addresses that must never be sent to a geo service:
// anything not a globally-routable client address.
func isPrivateAddr(a netip.Addr) bool {
	if !a.IsValid() || a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() ||
		a.IsLinkLocalMulticast() || a.IsUnspecified() || a.IsMulticast() {
		return true
	}
	u := a.Unmap()
	for _, p := range reservedPrefixes {
		if p.Contains(u) {
			return true
		}
	}
	return false
}
