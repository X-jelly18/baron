package main

import (
	"bufio"
	"io"
	"math"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type globalStats struct {
	accepted    atomic.Uint64
	rejGlobal   atomic.Uint64
	rejRate     atomic.Uint64
	rejPerIP    atomic.Uint64
	proxyErrs   atomic.Uint64
	sniFallback atomic.Uint64
	sniRejected atomic.Uint64
	reloadOK    atomic.Uint64
	reloadErr   atomic.Uint64
	unrouted    atomic.Uint64
	misdirected atomic.Uint64
}

func (g *globalStats) reject(reason string) {
	switch reason {
	case "ip_rate":
		g.rejRate.Add(1)
	case "ip_conns":
		g.rejPerIP.Add(1)
	}
}

type backendStats struct {
	ips           *ipLog // per-backend client-IP hit counter
	tunnelsActive atomic.Int64
	tunnelsTotal  atomic.Uint64
	tunnelsFailed atomic.Uint64 // edge-generated 502/504: backend unreachable or bad response
	rejectedCap   atomic.Uint64
	status        [6]atomic.Uint64 // by class 1..5; [0] = raw (no HTTP status)
	bytesUp       atomic.Uint64
	bytesDown     atomic.Uint64
	packetsUp     atomic.Uint64 // udp only
	packetsDown   atomic.Uint64
}

var statusClasses = [6]string{"raw", "1xx", "2xx", "3xx", "4xx", "5xx"}

func (b *backendStats) observeStatus(code int) {
	c := code / 100
	if c < 1 || c > 5 {
		c = 0
	}
	b.status[c].Add(1)
}

// hostStats is live traffic for one CDN hostname (the Host the client
// connected to), so the panel can show per-domain activity. Cardinality is
// bounded: a Host that is not a configured cdn_host is bucketed as "other".
type hostStats struct {
	requests  atomic.Uint64
	active    atomic.Int64
	bytesUp   atomic.Uint64
	bytesDown atomic.Uint64
}

// statsRegistry keeps counters by backend name and by host, so they survive reloads.
type statsRegistry struct {
	global   globalStats
	udp      udpStats
	mu       sync.Mutex
	backends map[string]*backendStats
	hosts    map[string]*hostStats
}

func newStatsRegistry() *statsRegistry {
	return &statsRegistry{backends: map[string]*backendStats{}, hosts: map[string]*hostStats{}}
}

func (r *statsRegistry) backend(name string) *backendStats {
	r.mu.Lock()
	defer r.mu.Unlock()
	b := r.backends[name]
	if b == nil {
		b = &backendStats{ips: newIPLog(maxIPLogPerBackend)}
		r.backends[name] = b
	}
	return b
}

func (r *statsRegistry) host(name string) *hostStats {
	r.mu.Lock()
	defer r.mu.Unlock()
	h := r.hosts[name]
	if h == nil {
		h = &hostStats{}
		r.hosts[name] = h
	}
	return h
}

// hostSnapshot returns a copy of the per-host counters for status/metrics.
func (r *statsRegistry) hostSnapshot() map[string]*hostStats {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string]*hostStats, len(r.hosts))
	for k, v := range r.hosts {
		out[k] = v
	}
	return out
}

// backendBytes returns the cumulative up/down byte totals per backend, for the
// throughput sampler (series.go).
func (r *statsRegistry) backendBytes() map[string]bytePair {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string]bytePair, len(r.backends))
	for k, b := range r.backends {
		out[k] = bytePair{up: b.bytesUp.Load(), down: b.bytesDown.Load()}
	}
	return out
}

// hostBytes returns the cumulative up/down byte totals per host bucket.
func (r *statsRegistry) hostBytes() map[string]bytePair {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string]bytePair, len(r.hosts))
	for k, h := range r.hosts {
		out[k] = bytePair{up: h.bytesUp.Load(), down: h.bytesDown.Load()}
	}
	return out
}

// ---- Prometheus text format ------------------------------------------------------

type prom struct{ w *bufio.Writer }

func (p prom) head(name, typ, help string) {
	p.w.WriteString("# HELP " + name + " " + help + "\n# TYPE " + name + " " + typ + "\n")
}

func (p prom) val(name string, v float64, labels ...string) {
	p.w.WriteString(name)
	if len(labels) > 0 {
		p.w.WriteByte('{')
		for i := 0; i+1 < len(labels); i += 2 {
			if i > 0 {
				p.w.WriteByte(',')
			}
			p.w.WriteString(labels[i] + `="` + labelEscaper.Replace(labels[i+1]) + `"`)
		}
		p.w.WriteByte('}')
	}
	p.w.WriteString(" " + formatSample(v) + "\n")
}

// formatSample prints integral values as plain integers ('g' formatting
// would turn 18998193 into 1.8998193e+07).
func formatSample(v float64) string {
	if v == math.Trunc(v) && math.Abs(v) < 1e15 {
		return strconv.FormatInt(int64(v), 10)
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}

var labelEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

func (s *Server) writeMetrics(w io.Writer) {
	bw := bufio.NewWriter(w)
	defer bw.Flush()
	p := prom{bw}
	st := s.state.Load()
	g := &s.stats.global
	now := time.Now()

	p.head("ayana_cdn_build_info", "gauge", "Build information.")
	p.val("ayana_cdn_build_info", 1, "version", version, "go", runtime.Version())
	p.head("ayana_cdn_start_time_seconds", "gauge", "Process start time, unix seconds.")
	p.val("ayana_cdn_start_time_seconds", float64(s.startTime.Unix()))
	p.head("ayana_cdn_draining", "gauge", "1 while this process drains after a restart or stop.")
	p.val("ayana_cdn_draining", b2f(s.draining.Load()))
	p.head("ayana_cdn_config_generation", "gauge", "Increments with every config load.")
	p.val("ayana_cdn_config_generation", float64(st.gen))
	p.head("ayana_cdn_config_reloads_total", "counter", "Config reloads by result.")
	p.val("ayana_cdn_config_reloads_total", float64(g.reloadOK.Load()), "result", "ok")
	p.val("ayana_cdn_config_reloads_total", float64(g.reloadErr.Load()), "result", "error")

	p.head("ayana_cdn_connections_active", "gauge", "Open client connections.")
	p.val("ayana_cdn_connections_active", float64(s.activeConns()))
	p.head("ayana_cdn_connections_max", "gauge", "Global client connection cap (0 = none).")
	p.val("ayana_cdn_connections_max", float64(st.maxConns))
	p.head("ayana_cdn_connections_accepted_total", "counter", "Client connections accepted by the kernel.")
	p.val("ayana_cdn_connections_accepted_total", float64(g.accepted.Load()))
	p.head("ayana_cdn_connections_rejected_total", "counter", "Client connections refused by limits.")
	p.val("ayana_cdn_connections_rejected_total", float64(g.rejGlobal.Load()), "reason", "global_cap")
	p.val("ayana_cdn_connections_rejected_total", float64(g.rejRate.Load()), "reason", "ip_rate")
	p.val("ayana_cdn_connections_rejected_total", float64(g.rejPerIP.Load()), "reason", "ip_conns")
	p.head("ayana_cdn_proxy_protocol_errors_total", "counter", "Malformed PROXY protocol headers.")
	p.val("ayana_cdn_proxy_protocol_errors_total", float64(g.proxyErrs.Load()))
	p.head("ayana_cdn_tls_sni_fallback_total", "counter", "Handshakes with a missing or unknown SNI served the primary certificate.")
	p.val("ayana_cdn_tls_sni_fallback_total", float64(g.sniFallback.Load()))
	p.head("ayana_cdn_tls_sni_rejected_total", "counter", "Handshakes refused by strict_sni.")
	p.val("ayana_cdn_tls_sni_rejected_total", float64(g.sniRejected.Load()))
	p.head("ayana_cdn_requests_unrouted_total", "counter", "Requests matching no backend (404).")
	p.val("ayana_cdn_requests_unrouted_total", float64(g.unrouted.Load()))
	p.head("ayana_cdn_requests_misdirected_total", "counter", "Requests refused by strict_host (421).")
	p.val("ayana_cdn_requests_misdirected_total", float64(g.misdirected.Load()))
	p.head("ayana_cdn_limiter_entries", "gauge", "Client addresses tracked by the per-IP limiter.")
	p.val("ayana_cdn_limiter_entries", float64(s.limiter.size()))
	p.head("ayana_cdn_udp_sessions_active", "gauge", "Open UDP sessions (one per client address and port).")
	p.val("ayana_cdn_udp_sessions_active", float64(s.stats.udp.active.Load()))
	p.head("ayana_cdn_udp_sessions_max", "gauge", "Global UDP session cap (0 = none).")
	p.val("ayana_cdn_udp_sessions_max", float64(st.maxUDP))
	p.head("ayana_cdn_udp_dropped_total", "counter", "Datagrams dropped instead of relayed, by backend and reason.")
	for _, l := range s.udpListeners() {
		for i, name := range udpDropNames {
			p.val("ayana_cdn_udp_dropped_total", float64(l.drops[i].Load()), "backend", l.name, "reason", name)
		}
	}

	list := make([]*backendRT, 0, len(st.routes.byName))
	for _, b := range st.cfg.Backends {
		list = append(list, st.routes.byName[b.Name])
	}
	p.head("ayana_cdn_tunnels_active", "gauge", "Tunnel requests in progress (udp: open sessions).")
	for _, b := range list {
		p.val("ayana_cdn_tunnels_active", float64(b.stats.tunnelsActive.Load()), "backend", b.cfg.Name)
	}
	p.head("ayana_cdn_tunnels_total", "counter", "Tunnels established (udp: sessions opened).")
	for _, b := range list {
		p.val("ayana_cdn_tunnels_total", float64(b.stats.tunnelsTotal.Load()), "backend", b.cfg.Name)
	}
	p.head("ayana_cdn_backend_failures_total", "counter", "Edge-generated 502/504: backend unreachable or bad response.")
	for _, b := range list {
		p.val("ayana_cdn_backend_failures_total", float64(b.stats.tunnelsFailed.Load()), "backend", b.cfg.Name)
	}
	p.head("ayana_cdn_backend_capacity_rejections_total", "counter", "Requests refused by a backend's max_conns.")
	for _, b := range list {
		p.val("ayana_cdn_backend_capacity_rejections_total", float64(b.stats.rejectedCap.Load()), "backend", b.cfg.Name)
	}
	p.head("ayana_cdn_responses_total", "counter", "Responses by status class (raw = relay without an HTTP status).")
	for _, b := range list {
		for c := range statusClasses {
			p.val("ayana_cdn_responses_total", float64(b.stats.status[c].Load()), "backend", b.cfg.Name, "class", statusClasses[c])
		}
	}
	p.head("ayana_cdn_bytes_total", "counter", "Payload bytes relayed (up = client to backend).")
	for _, b := range list {
		p.val("ayana_cdn_bytes_total", float64(b.stats.bytesUp.Load()), "backend", b.cfg.Name, "direction", "up")
		p.val("ayana_cdn_bytes_total", float64(b.stats.bytesDown.Load()), "backend", b.cfg.Name, "direction", "down")
	}
	p.head("ayana_cdn_udp_packets_total", "counter", "Datagrams relayed (up = client to backend).")
	for _, b := range list {
		if b.udp {
			p.val("ayana_cdn_udp_packets_total", float64(b.stats.packetsUp.Load()), "backend", b.cfg.Name, "direction", "up")
			p.val("ayana_cdn_udp_packets_total", float64(b.stats.packetsDown.Load()), "backend", b.cfg.Name, "direction", "down")
		}
	}
	p.head("ayana_cdn_upstream_up", "gauge", "Upstream health (1 = eligible).")
	for _, b := range list {
		for _, u := range b.pool.ups {
			p.val("ayana_cdn_upstream_up", b2f(u.isHealthy(now)), "backend", b.cfg.Name, "upstream", u.addr)
		}
	}
	p.head("ayana_cdn_upstream_connections", "gauge", "Open connections per upstream.")
	for _, b := range list {
		for _, u := range b.pool.ups {
			p.val("ayana_cdn_upstream_connections", float64(u.active.Load()), "backend", b.cfg.Name, "upstream", u.addr)
		}
	}
	p.head("ayana_cdn_upstream_dials_total", "counter", "Upstream connection attempts by result.")
	for _, b := range list {
		for _, u := range b.pool.ups {
			p.val("ayana_cdn_upstream_dials_total", float64(u.dialOK.Load()), "backend", b.cfg.Name, "upstream", u.addr, "result", "ok")
			p.val("ayana_cdn_upstream_dials_total", float64(u.dialErr.Load()), "backend", b.cfg.Name, "upstream", u.addr, "result", "error")
		}
	}
	hsnap := s.stats.hostSnapshot()
	p.head("ayana_cdn_host_requests_total", "counter", "Requests received per CDN host (Host header).")
	for name, h := range hsnap {
		p.val("ayana_cdn_host_requests_total", float64(h.requests.Load()), "host", name)
	}
	p.head("ayana_cdn_host_active", "gauge", "Active client connections per CDN host.")
	for name, h := range hsnap {
		p.val("ayana_cdn_host_active", float64(h.active.Load()), "host", name)
	}
	p.head("ayana_cdn_host_bytes_total", "counter", "Payload bytes relayed per CDN host (up = client to backend).")
	for name, h := range hsnap {
		p.val("ayana_cdn_host_bytes_total", float64(h.bytesUp.Load()), "host", name, "direction", "up")
		p.val("ayana_cdn_host_bytes_total", float64(h.bytesDown.Load()), "host", name, "direction", "down")
	}

	p.head("ayana_cdn_cert_expiry_timestamp_seconds", "gauge", "Expiry of the certificate being served, unix seconds.")
	for _, c := range s.certs.list() {
		p.val("ayana_cdn_cert_expiry_timestamp_seconds", float64(c.NotAfter.Unix()), "host", c.Host)
	}

	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	p.head("ayana_cdn_goroutines", "gauge", "Goroutines.")
	p.val("ayana_cdn_goroutines", float64(runtime.NumGoroutine()))
	p.head("ayana_cdn_heap_inuse_bytes", "gauge", "Go heap in use.")
	p.val("ayana_cdn_heap_inuse_bytes", float64(ms.HeapInuse))
	p.head("ayana_cdn_stack_inuse_bytes", "gauge", "Goroutine stacks in use (about two goroutines per tunnel).")
	p.val("ayana_cdn_stack_inuse_bytes", float64(ms.StackInuse))
	p.head("ayana_cdn_memory_sys_bytes", "gauge", "Memory obtained from the OS by the Go runtime.")
	p.val("ayana_cdn_memory_sys_bytes", float64(ms.Sys))
	p.head("ayana_cdn_open_fds", "gauge", "Open file descriptors.")
	p.val("ayana_cdn_open_fds", float64(countOpenFDs()))
	p.head("ayana_cdn_max_fds", "gauge", "File descriptor limit.")
	p.val("ayana_cdn_max_fds", float64(nofileLimit()))
}

func countOpenFDs() int {
	f, err := os.Open("/proc/self/fd")
	if err != nil {
		return -1
	}
	defer f.Close()
	names, err := f.Readdirnames(-1)
	if err != nil {
		return -1
	}
	return len(names) - 1 // minus the descriptor used to read the directory
}

// ---- status document -------------------------------------------------------------

type statusDoc struct {
	Version       string          `json:"version"`
	Go            string          `json:"go"`
	PID           int             `json:"pid"`
	Started       time.Time       `json:"started"`
	UptimeSeconds int64           `json:"uptime_seconds"`
	Draining      bool            `json:"draining"`
	Generation    uint64          `json:"config_generation"`
	ConfigPath    string          `json:"config_path"`
	Listen        string          `json:"listen"`
	Hosts         []string        `json:"cdn_hosts"`
	TLSMode       string          `json:"tls_mode"`
	Connections   connStatus      `json:"connections"`
	TunnelsActive int             `json:"tunnels_active"`
	Certificates  []certInfo      `json:"certificates"`
	HostTraffic   []hostStatus    `json:"host_traffic"`
	Backends      []backendStatus `json:"backends"`
	Runtime       runtimeStatus   `json:"runtime"`
}

type hostStatus struct {
	Host      string `json:"host"`
	Requests  uint64 `json:"requests"`
	Active    int64  `json:"active"`
	BytesUp   uint64 `json:"bytes_up"`
	BytesDown uint64 `json:"bytes_down"`
}

type connStatus struct {
	Active         int64             `json:"active"`
	Max            int64             `json:"max"`
	Accepted       uint64            `json:"accepted"`
	RejectedGlobal uint64            `json:"rejected_global_cap"`
	RejectedRate   uint64            `json:"rejected_ip_rate"`
	RejectedPerIP  uint64            `json:"rejected_ip_conns"`
	SNIFallback    uint64            `json:"sni_fallback"`
	ProxyErrors    uint64            `json:"proxy_protocol_errors"`
	UDPSessions    int64             `json:"udp_sessions"`
	UDPMax         int64             `json:"udp_sessions_max"`
	UDPDropped     map[string]uint64 `json:"udp_dropped,omitempty"`
}

type backendStatus struct {
	Name          string             `json:"name"`
	Path          string             `json:"path"`
	Listen        string             `json:"listen,omitempty"` // udp backends: their own socket
	Proto         string             `json:"proto"`
	Relay         string             `json:"relay"`
	Host          string             `json:"host,omitempty"` // Host header / SNI sent to the backend
	Strip         bool               `json:"strip"`          // strip /<name> from the path
	Insecure      bool               `json:"insecure"`       // backend cert not verified
	LB            string             `json:"lb"`             // "path" (one server per path), or the udp policy
	Disabled      bool               `json:"disabled"`
	TunnelsActive int64              `json:"tunnels_active"`
	TunnelsTotal  uint64             `json:"tunnels_total"`
	Failures      uint64             `json:"failures"`
	CapRejections uint64             `json:"capacity_rejections"`
	BytesUp       uint64             `json:"bytes_up"`
	BytesDown     uint64             `json:"bytes_down"`
	PacketsUp     uint64             `json:"packets_up,omitempty"`
	PacketsDown   uint64             `json:"packets_down,omitempty"`
	Responses     map[string]uint64  `json:"responses"`
	Upstreams     []upstreamSnapshot `json:"upstreams"`
	// Servers after the first that an older config lists on a path; never dialed.
	IgnoredUpstreams []string `json:"ignored_upstreams,omitempty"`
}

type runtimeStatus struct {
	Goroutines    int    `json:"goroutines"`
	HeapInuse     uint64 `json:"heap_inuse_bytes"`
	StackInuse    uint64 `json:"stack_inuse_bytes"`
	Sys           uint64 `json:"sys_bytes"`
	OpenFDs       int    `json:"open_fds"`
	MaxFDs        uint64 `json:"max_fds"`
	TCPCongestion string `json:"tcp_congestion,omitempty"` // kernel default, e.g. "bbr"
	DefaultQdisc  string `json:"default_qdisc,omitempty"`  // e.g. "fq"
	BBRAvailable  bool   `json:"bbr_available"`
	NetAdvice     string `json:"net_advice,omitempty"` // set when BBR is not in force
}

func (s *Server) buildStatus() statusDoc {
	st := s.state.Load()
	g := &s.stats.global
	now := time.Now()
	d := statusDoc{
		Version: version, Go: runtime.Version(), PID: os.Getpid(),
		Started: s.startTime, UptimeSeconds: int64(now.Sub(s.startTime).Seconds()),
		Draining: s.draining.Load(), Generation: st.gen, ConfigPath: s.cfgPath,
		Listen: st.cfg.Listen, Hosts: st.cfg.CDNHosts, TLSMode: st.cfg.TLS.Mode,
		Connections: connStatus{
			Active: s.activeConns(), Max: st.maxConns, Accepted: g.accepted.Load(),
			RejectedGlobal: g.rejGlobal.Load(), RejectedRate: g.rejRate.Load(), RejectedPerIP: g.rejPerIP.Load(),
			SNIFallback: g.sniFallback.Load(), ProxyErrors: g.proxyErrs.Load(),
			UDPSessions: s.stats.udp.active.Load(), UDPMax: st.maxUDP, UDPDropped: map[string]uint64{},
		},
		TunnelsActive: s.tunnels.count(),
		Certificates:  s.certs.list(),
	}
	// Per-host (per-domain) live traffic. Configured hosts first in config
	// order, then any "other" bucket, so the panel can show every domain even
	// before it has seen traffic.
	hsnap := s.stats.hostSnapshot()
	seenHost := map[string]bool{}
	addHost := func(name string) {
		if seenHost[name] {
			return
		}
		seenHost[name] = true
		h := hsnap[name]
		if h == nil {
			h = &hostStats{}
		}
		d.HostTraffic = append(d.HostTraffic, hostStatus{Host: name, Requests: h.requests.Load(), Active: h.active.Load(),
			BytesUp: h.bytesUp.Load(), BytesDown: h.bytesDown.Load()})
	}
	for _, name := range st.cfg.CDNHosts {
		addHost(name)
	}
	if _, ok := hsnap["other"]; ok {
		addHost("other")
	}
	for _, l := range s.udpListeners() {
		for i, name := range udpDropNames {
			if v := l.drops[i].Load(); v > 0 {
				d.Connections.UDPDropped[name] += v
			}
		}
	}
	for _, b := range st.routes.byName {
		bs := backendStatus{
			Name: b.cfg.Name, Path: b.prefix + "/", Proto: b.cfg.Proto, Relay: b.cfg.Relay, Disabled: b.cfg.Disabled,
			Host: b.cfg.Host, Strip: b.cfg.strip(), Insecure: b.cfg.Insecure, LB: b.cfg.LB,
			TunnelsActive: b.stats.tunnelsActive.Load(), TunnelsTotal: b.stats.tunnelsTotal.Load(),
			Failures: b.stats.tunnelsFailed.Load(), CapRejections: b.stats.rejectedCap.Load(),
			BytesUp: b.stats.bytesUp.Load(), BytesDown: b.stats.bytesDown.Load(),
			Responses:        map[string]uint64{},
			IgnoredUpstreams: b.cfg.ignoredUpstreams,
		}
		if b.udp {
			bs.Path, bs.Listen = "", b.cfg.Listen
			bs.PacketsUp, bs.PacketsDown = b.stats.packetsUp.Load(), b.stats.packetsDown.Load()
		}
		for c := range statusClasses {
			if v := b.stats.status[c].Load(); v > 0 {
				bs.Responses[statusClasses[c]] = v
			}
		}
		for _, u := range b.pool.ups {
			bs.Upstreams = append(bs.Upstreams, u.snapshot(now))
		}
		d.Backends = append(d.Backends, bs)
	}
	// Keep config order for display (the route table is sorted by prefix length).
	order := map[string]int{}
	for i, b := range st.cfg.Backends {
		order[b.Name] = i
	}
	sortBackends(d.Backends, order)
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	nt := readNetTuning("/")
	d.Runtime = runtimeStatus{Goroutines: runtime.NumGoroutine(), HeapInuse: ms.HeapInuse, StackInuse: ms.StackInuse, Sys: ms.Sys,
		OpenFDs: countOpenFDs(), MaxFDs: nofileLimit(),
		TCPCongestion: nt.congestion, DefaultQdisc: nt.qdisc, BBRAvailable: nt.bbrAvailable(), NetAdvice: nt.advice()}
	return d
}

func sortBackends(list []backendStatus, order map[string]int) {
	for i := 1; i < len(list); i++ {
		for j := i; j > 0 && order[list[j].Name] < order[list[j-1].Name]; j-- {
			list[j], list[j-1] = list[j-1], list[j]
		}
	}
}
