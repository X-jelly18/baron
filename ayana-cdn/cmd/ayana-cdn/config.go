package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	defaultMaxUDPPacket = 8192  // covers every tunnel protocol that avoids IP fragmentation
	maxUDPDatagram      = 65507 // the largest IPv4 UDP payload

	defaultConfigPath  = "/etc/ayana-cdn/config.json"
	defaultListen      = ":443"
	defaultAdminListen = "127.0.0.1:9180"
	defaultACMECache   = "/var/lib/ayana-cdn/acme"
	reservedHealthPath = "/healthz"
)

// Duration is a time.Duration that is written to JSON as "30s"-style strings.
// Plain numbers are accepted on input and read as seconds.
type Duration time.Duration

// D returns the value as a time.Duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(time.Duration(d).String()) }

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		v, err := time.ParseDuration(strings.TrimSpace(s))
		if err != nil {
			return fmt.Errorf("invalid duration %q (use values like \"30s\", \"5m\", \"4h\")", s)
		}
		*d = Duration(v)
		return nil
	}
	var n float64
	if err := json.Unmarshal(b, &n); err == nil {
		*d = Duration(n * float64(time.Second))
		return nil
	}
	return fmt.Errorf("invalid duration %s (use a string like \"30s\")", string(b))
}

// Config is the whole edge configuration.
//
// A config exists in two forms. The raw form is exactly what the operator wrote;
// the CLI edits and saves it without injecting defaults, so the file stays
// readable. The effective form (Effective) is a validated copy with every
// default filled in, and is what the server runs on.
type Config struct {
	Listen               string   `json:"listen"`
	CDNHost              string   `json:"cdn_host,omitempty"` // v1 form; merged into cdn_hosts
	CDNHosts             []string `json:"cdn_hosts,omitempty"`
	ProxyProtocol        bool     `json:"proxy_protocol"`
	ProxyProtocolTrusted []string `json:"proxy_protocol_trusted,omitempty"`
	EnableHTTP2          bool     `json:"enable_http2"`
	StrictSNI            bool     `json:"strict_sni,omitempty"`
	StrictHost           bool     `json:"strict_host,omitempty"`
	RedirectListen       string   `json:"redirect_listen,omitempty"`
	AdminListen          string   `json:"admin_listen,omitempty"`
	AdminPprof           bool     `json:"admin_pprof,omitempty"`
	AdminUser            string   `json:"admin_user,omitempty"`          // optional HTTP Basic user for the admin endpoint
	AdminPasswordHash    string   `json:"admin_password_hash,omitempty"` // bcrypt hash; when set (with admin_user) the admin endpoint requires Basic auth

	TLS      TLSConfig    `json:"tls"`
	Limits   *Limits      `json:"limits,omitempty"`
	Timeouts *Timeouts    `json:"timeouts,omitempty"`
	Log      *LogConfig   `json:"log,omitempty"`
	Geo      *GeoConfig   `json:"geo,omitempty"`
	Panel    *PanelConfig `json:"panel,omitempty"`
	Backends []Backend    `json:"backends"`

	warnings []string // produced by validate; never serialized
}

// TLSConfig controls the client-facing certificate.
type TLSConfig struct {
	Mode       string `json:"mode"`                  // acme | files
	Email      string `json:"email,omitempty"`       // acme account contact
	CacheDir   string `json:"cache_dir,omitempty"`   // acme certificate cache
	CertFile   string `json:"cert_file,omitempty"`   // files mode: full chain
	KeyFile    string `json:"key_file,omitempty"`    // files mode: private key
	MinVersion string `json:"min_version,omitempty"` // 1.0 | 1.1 | 1.2 | 1.3
}

// Limits protect the edge. For numeric fields, 0 (or absent) means "use the
// default" and -1 means "off".
type Limits struct {
	MaxConns            int      `json:"max_conns,omitempty"`               // global concurrent client connections; default derived from the file-descriptor limit
	MaxConnsPerIP       int      `json:"max_conns_per_ip,omitempty"`        // concurrent connections per client IP (IPv6: per /64); default off, -1 = off, positive = cap
	ConnRatePerIP       float64  `json:"conn_rate_per_ip,omitempty"`        // new connections per second per IP; default off, -1 = off, positive = rate
	ConnBurstPerIP      int      `json:"conn_burst_per_ip,omitempty"`       // bucket size for the rate above; default 300
	Exempt              []string `json:"exempt,omitempty"`                  // CIDRs never subject to per-IP limits; default loopback
	MaxHeaderBytes      int      `json:"max_header_bytes,omitempty"`        // request header size limit; default 32768
	MaxUDPSessions      int      `json:"max_udp_sessions,omitempty"`        // global concurrent UDP sessions; default derived from the fd limit and port range
	MaxUDPPacket        int      `json:"max_udp_packet,omitempty"`          // largest datagram relayed, bytes; default 8192
	UDPRatePerIP        float64  `json:"udp_rate_per_ip,omitempty"`         // new UDP sessions per second per client IP; default off
	UDPBurstPerIP       int      `json:"udp_burst_per_ip,omitempty"`        // bucket size for udp_rate_per_ip; default 1000
	MaxUDPSessionsPerIP int      `json:"max_udp_sessions_per_ip,omitempty"` // concurrent UDP sessions per client IP; default 4096, -1 = off
	UDPAmplification    int      `json:"udp_amplification,omitempty"`       // max bytes reflected to an unverified UDP source per byte it sent (QUIC-style anti-amplification); 0/-1 = off (default), positive = on with that factor
}

// Timeouts, all written as duration strings.
type Timeouts struct {
	ReadHeader      Duration `json:"read_header,omitempty"`      // client request headers, also the TLS handshake budget
	HTTPIdle        Duration `json:"http_idle,omitempty"`        // idle keep-alive between client requests
	UpstreamConnect Duration `json:"upstream_connect,omitempty"` // per upstream attempt (TCP + TLS)
	UpstreamHeader  Duration `json:"upstream_header,omitempty"`  // backend must answer within this
	RequestBody     Duration `json:"request_body,omitempty"`     // bound on reading a client request body (slow-body / R-U-Dead-Yet); 0 = off
	TunnelIdle      Duration `json:"tunnel_idle,omitempty"`      // close tunnels with no traffic either way; 0 = never
	UDPIdle         Duration `json:"udp_idle,omitempty"`         // close UDP sessions with no datagrams either way; default 60s
	UDPReply        Duration `json:"udp_reply,omitempty"`        // close a UDP session whose upstream never answers within this; default 15s, -1 = off
	WriteStall      Duration `json:"write_stall,omitempty"`      // close a tunnel whose peer stops reading for this long
	HalfClose       Duration `json:"half_close,omitempty"`       // linger after one side of a tunnel closes
	ClientKeepAlive Duration `json:"client_keepalive,omitempty"` // silence before TCP keepalive probes start, client and backend sockets
	DeadPeer        Duration `json:"dead_peer,omitempty"`        // a peer that stays silent this long past client_keepalive is dropped
	ShutdownGrace   Duration `json:"shutdown_grace,omitempty"`   // in-flight HTTP requests on stop
	Drain           Duration `json:"drain,omitempty"`            // how long the old process keeps tunnels after `restart`
}

// LogConfig controls logging.
type LogConfig struct {
	Level  string `json:"level,omitempty"`  // debug | info | warn | error
	Format string `json:"format,omitempty"` // text | json
	Access *bool  `json:"access,omitempty"` // one line per tunnel/request; default true
	IPLog  *bool  `json:"ip_log,omitempty"` // per-backend client-IP hit counter (in-memory, bounded); default true
}

// GeoConfig controls optional IP geolocation for the per-backend IP log. It is
// off by default: nothing is sent anywhere unless Enabled is set. When on, the
// edge resolves each logged public IP once against URL (a template containing
// {ip}) and caches the result. Sending client IPs to a third-party service has
// privacy implications — point URL at a provider you trust or a self-hosted one.
type GeoConfig struct {
	Enabled    bool     `json:"enabled"`
	URL        string   `json:"url,omitempty"`          // template with {ip}, e.g. "https://ipwho.is/{ip}"
	RatePerMin int      `json:"rate_per_min,omitempty"` // max outbound lookups per minute; default 20
	CacheSize  int      `json:"cache_size,omitempty"`   // max cached IPs; default 50000
	CacheTTL   Duration `json:"cache_ttl,omitempty"`    // how long a location is reused; default 720h
}

// PanelConfig controls the authenticated web panel. The panel is served on
// the public TLS listener at a secret path prefix (so it is reachable over
// https without exposing the loopback admin endpoint) and is guarded by a
// username and a bcrypt-hashed password. Configure it with `ayana-cdn panel`
// rather than by hand; the password is never stored in clear text.
type PanelConfig struct {
	Enabled      bool     `json:"enabled"`                 // serve the panel
	Path         string   `json:"path,omitempty"`          // secret URL prefix, e.g. "/__ayana_x8Kq..."; keep it unguessable
	Username     string   `json:"username,omitempty"`      // login name
	PasswordHash string   `json:"password_hash,omitempty"` // bcrypt hash of the password ($2a/$2b/$2y)
	SessionKey   string   `json:"session_key,omitempty"`   // base64 >=32 bytes signing key; empty = random per start (restart logs everyone out)
	SessionTTL   Duration `json:"session_ttl,omitempty"`   // how long a login stays valid; default 12h
	AllowControl bool     `json:"allow_control,omitempty"` // permit state-changing actions (reload, enable/disable backend); default read-only
	AllowedCIDRs []string `json:"allowed_cidrs,omitempty"` // optional source-IP allowlist (defense in depth); empty = any address
}

// Backend is one origin. Clients reach it at https://<cdn host>/<name>/...
type Backend struct {
	Name        string       `json:"name"`
	Upstream    string       `json:"upstream,omitempty"`  // v1 form; merged into upstreams
	Upstreams   []string     `json:"upstreams,omitempty"` // path backends use exactly one server; udp may list several
	Listen      string       `json:"listen,omitempty"`    // udp: the address this backend receives datagrams on
	Host        string       `json:"host,omitempty"`
	Proto       string       `json:"proto,omitempty"`
	TLS         *bool        `json:"tls,omitempty"`
	Strip       *bool        `json:"strip,omitempty"`
	Insecure    bool         `json:"insecure,omitempty"`
	Disabled    bool         `json:"disabled,omitempty"`
	LB          string       `json:"lb,omitempty"` // "path" (path backends: their one server); udp: hash | least_conn | round_robin | first
	Relay       string       `json:"relay,omitempty"`
	MaxConns    int          `json:"max_conns,omitempty"`
	IdleTimeout Duration     `json:"idle_timeout,omitempty"`
	HealthCheck *HealthCheck `json:"health_check,omitempty"`

	// ignoredUpstreams holds the servers after the first of a path backend in
	// an older config. Only the effective copy sets it; it is never saved.
	ignoredUpstreams []string
}

// HealthCheck configures active probing of every upstream of a backend.
type HealthCheck struct {
	Type     string   `json:"type,omitempty"` // tcp | tls | http | ws | off
	Path     string   `json:"path,omitempty"`
	Interval Duration `json:"interval,omitempty"`
	Timeout  Duration `json:"timeout,omitempty"`
	Fall     int      `json:"fall,omitempty"`
	Rise     int      `json:"rise,omitempty"`
	Expect   int      `json:"expect,omitempty"`
}

func (b *Backend) useTLS() bool   { return b.TLS != nil && *b.TLS }
func (b *Backend) strip() bool    { return b.Strip == nil || *b.Strip }
func (b *Backend) isTunnel() bool { return b.Proto == "ws" || b.Proto == "wss" }
func (b *Backend) isUDP() bool    { return b.Proto == "udp" }

// isPathRouted reports a backend reached by its path (every proto but udp).
// Such a backend connects to exactly one server: no balancing, no failover.
func (b *Backend) isPathRouted() bool { return !b.isUDP() }

// normProto is the proto as applyDefaults stores it.
func normProto(p string) string {
	p = strings.ToLower(strings.TrimSpace(p))
	if p == "" {
		return "wss"
	}
	return p
}

// mergeUpstreams joins the v1 "upstream" and the "upstreams" list, trimmed
// and without duplicates, in order: the first entry is the server a path uses.
func mergeUpstreams(single string, list []string) []string {
	var ups []string
	seen := map[string]bool{}
	for _, u := range append([]string{single}, list...) {
		u = strings.TrimSpace(u)
		if u != "" && !seen[u] {
			seen[u] = true
			ups = append(ups, u)
		}
	}
	return ups
}

// errSeveralServers is how new input (the panel, `backend add/set`, `routes
// import`) is told that a path takes one server. A config that already lists
// several still loads (only the first is used, with a warning), so an upgrade
// never stops a running edge.
func errSeveralServers(name string, ups []string) error {
	alt := name + "-2"
	return fmt.Errorf("path /%s/ connects to exactly one server, but %d were given (%s): "+
		"give each server its own path (for example keep %s on /%s/ and add %s as /%s/)",
		name, len(ups), strings.Join(ups, ", "), ups[0], name, ups[1], alt)
}

// checkOneServer refuses new input that puts several servers on a path
// backend. It reads a raw backend and does not modify it.
func checkOneServer(b *Backend) error {
	if normProto(b.Proto) == "udp" {
		return nil
	}
	if ups := mergeUpstreams(b.Upstream, b.Upstreams); len(ups) > 1 {
		return errSeveralServers(strings.TrimSpace(b.Name), ups)
	}
	return nil
}

// ---- loading -----------------------------------------------------------------

func loadRaw(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	return parseRaw(data, path)
}

func parseRaw(data []byte, name string) (*Config, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var c Config
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", name, describeJSONError(data, err))
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("parse %s: unexpected data after the closing brace", name)
	}
	return &c, nil
}

// LoadConfig reads, validates and returns the effective config.
func LoadConfig(path string) (*Config, error) {
	raw, err := loadRaw(path)
	if err != nil {
		return nil, err
	}
	return raw.Effective()
}

// Effective returns a validated deep copy with all defaults applied. The
// receiver is not modified.
func (c *Config) Effective() (*Config, error) {
	data, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	var e Config
	if err := json.Unmarshal(data, &e); err != nil {
		return nil, err
	}
	e.applyDefaults()
	if err := e.validate(); err != nil {
		return nil, err
	}
	return &e, nil
}

func describeJSONError(data []byte, err error) error {
	var se *json.SyntaxError
	var te *json.UnmarshalTypeError
	switch {
	case errors.As(err, &se):
		line, col := lineCol(data, se.Offset)
		return fmt.Errorf("line %d, column %d: %v", line, col, se)
	case errors.As(err, &te):
		line, col := lineCol(data, te.Offset)
		return fmt.Errorf("line %d, column %d: field %q expects %s, got JSON %s", line, col, te.Field, te.Type, te.Value)
	}
	return err
}

func lineCol(data []byte, off int64) (int, int) {
	if off > int64(len(data)) {
		off = int64(len(data))
	}
	line, col := 1, 1
	for _, ch := range data[:off] {
		if ch == '\n' {
			line, col = line+1, 1
		} else {
			col++
		}
	}
	return line, col
}

// ---- defaults ----------------------------------------------------------------

func setDur(d *Duration, def time.Duration) {
	if *d == 0 {
		*d = Duration(def)
	}
}

func (c *Config) applyDefaults() {
	if c.Listen == "" {
		c.Listen = defaultListen
	}
	var hosts []string
	seen := map[string]bool{}
	for _, h := range append([]string{c.CDNHost}, c.CDNHosts...) {
		h = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
		if h != "" && !seen[h] {
			seen[h] = true
			hosts = append(hosts, h)
		}
	}
	c.CDNHost, c.CDNHosts = "", hosts
	if len(c.ProxyProtocolTrusted) == 0 {
		c.ProxyProtocolTrusted = []string{"127.0.0.0/8", "::1/128"}
	}
	if c.AdminListen == "" {
		c.AdminListen = defaultAdminListen
	}
	if c.TLS.Mode == "" {
		c.TLS.Mode = "acme"
	}
	if c.TLS.CacheDir == "" {
		c.TLS.CacheDir = defaultACMECache
	}
	if c.TLS.MinVersion == "" {
		c.TLS.MinVersion = "1.2"
	}

	if c.Limits == nil {
		c.Limits = &Limits{}
	}
	l := c.Limits
	if l.ConnRatePerIP == 0 {
		l.ConnRatePerIP = -1 // off by default: no per-IP new-connection rate limit
	}
	if l.ConnBurstPerIP == 0 {
		l.ConnBurstPerIP = 300 // only used when a positive conn_rate_per_ip is set
	}
	if l.MaxConnsPerIP == 0 {
		l.MaxConnsPerIP = -1 // off by default: no per-IP concurrent-connection cap
	}
	if len(l.Exempt) == 0 {
		l.Exempt = []string{"127.0.0.0/8", "::1/128"}
	}
	if l.MaxHeaderBytes == 0 {
		l.MaxHeaderBytes = 32 << 10
	}
	if l.MaxUDPPacket == 0 {
		l.MaxUDPPacket = defaultMaxUDPPacket
	}
	if l.UDPBurstPerIP == 0 {
		l.UDPBurstPerIP = 1000
	}
	if l.MaxUDPSessionsPerIP == 0 {
		l.MaxUDPSessionsPerIP = -1 // off by default: no per-IP concurrent UDP-session cap
	}
	// UDPAmplification defaults to off (0): a byte-ratio cap necessarily breaks
	// legitimate high-ratio request/reply protocols (DNS answers, etc.), so it
	// is opt-in. Spoofed-source reflection is bounded by default through the
	// client-proof unreplied FIFO + eviction and the per-IP/global session
	// caps; set a positive factor to additionally cap reflected bytes.

	if c.Timeouts == nil {
		c.Timeouts = &Timeouts{}
	}
	t := c.Timeouts
	setDur(&t.ReadHeader, 10*time.Second)
	setDur(&t.HTTPIdle, 75*time.Second)
	setDur(&t.UpstreamConnect, 5*time.Second)
	setDur(&t.UpstreamHeader, 15*time.Second)
	if t.RequestBody == 0 {
		t.RequestBody = Duration(60 * time.Second) // -1 turns it off for legitimate long uploads
	}
	setDur(&t.UDPIdle, 60*time.Second)
	if t.UDPReply == 0 {
		t.UDPReply = Duration(15 * time.Second)
	}
	setDur(&t.WriteStall, 2*time.Minute)
	setDur(&t.HalfClose, 30*time.Second)
	setDur(&t.ClientKeepAlive, 30*time.Second)
	setDur(&t.DeadPeer, 30*time.Second)
	setDur(&t.ShutdownGrace, 5*time.Second)
	setDur(&t.Drain, 4*time.Hour)
	// TunnelIdle stays 0 (off) unless set: tunnel users expect sessions to live.

	if c.Log == nil {
		c.Log = &LogConfig{}
	}
	if c.Log.Level == "" {
		c.Log.Level = "info"
	}
	if c.Log.Format == "" {
		c.Log.Format = "text"
	}
	if c.Log.Access == nil {
		c.Log.Access = ptr(true)
	}
	if c.Log.IPLog == nil {
		c.Log.IPLog = ptr(true) // the per-backend IP counter is in-memory and bounded; on by default
	}
	if c.Geo == nil {
		c.Geo = &GeoConfig{}
	}
	g := c.Geo
	if g.URL == "" {
		g.URL = "https://ipwho.is/{ip}"
	}
	if g.RatePerMin == 0 {
		g.RatePerMin = 20
	}
	if g.CacheSize == 0 {
		g.CacheSize = 50000
	}
	if g.CacheTTL == 0 {
		g.CacheTTL = Duration(720 * time.Hour)
	}
	if c.Panel != nil {
		c.Panel.applyDefaults()
	}
	for i := range c.Backends {
		c.Backends[i].applyDefaults()
	}
}

func (p *PanelConfig) applyDefaults() {
	p.Path = strings.TrimSpace(p.Path)
	if p.Path != "" {
		p.Path = "/" + strings.Trim(p.Path, "/") // normalize to a single leading slash, no trailing slash
	}
	p.Username = strings.TrimSpace(p.Username)
	p.PasswordHash = strings.TrimSpace(p.PasswordHash)
	p.SessionKey = strings.TrimSpace(p.SessionKey)
	if p.SessionTTL == 0 {
		p.SessionTTL = Duration(12 * time.Hour)
	}
}

func (b *Backend) applyDefaults() {
	b.Name = strings.TrimSpace(b.Name)
	ups := mergeUpstreams(b.Upstream, b.Upstreams)
	b.Upstream, b.Upstreams = "", ups
	b.Proto = normProto(b.Proto)
	b.Listen = strings.TrimSpace(b.Listen)
	if b.TLS == nil {
		b.TLS = ptr(b.Proto == "wss" || b.Proto == "https" || b.Proto == "sse")
	}
	if b.Strip == nil {
		b.Strip = ptr(true)
	}
	if b.isUDP() {
		if b.LB == "" {
			b.LB = "hash" // keep every flow of one client on the same upstream (stateful UDP)
		}
	} else {
		switch b.LB {
		case "", "least_conn", "round_robin", "first":
			// A path connects to its one server. The balancing policies of
			// older versions are still accepted in a config file and mean the
			// same thing now.
			b.LB = "path"
		}
	}
	if b.Relay == "" {
		b.Relay = "upgrade"
	}
	if b.Host == "" && len(ups) > 0 {
		if h, _, err := net.SplitHostPort(ups[0]); err == nil {
			b.Host = h
		}
	}
	if b.HealthCheck == nil {
		b.HealthCheck = &HealthCheck{}
	}
	hc := b.HealthCheck
	hc.Type = strings.ToLower(hc.Type)
	if hc.Type == "" {
		switch {
		case b.isUDP():
			hc.Type = "off" // datagrams cannot be probed; sessions report unreachable upstreams themselves
		case *b.TLS:
			hc.Type = "tls"
		default:
			hc.Type = "tcp"
		}
	}
	if hc.Path == "" {
		hc.Path = "/"
	}
	setDur(&hc.Interval, 10*time.Second)
	if hc.Timeout == 0 {
		// Default the timeout, but never longer than the interval, so a user
		// who sets a sub-3s interval (and no explicit timeout) is not rejected
		// by validate(). An explicitly oversized timeout is still an error.
		hc.Timeout = min(Duration(3*time.Second), hc.Interval)
	}
	if hc.Fall == 0 {
		hc.Fall = 3
	}
	if hc.Rise == 0 {
		hc.Rise = 2
	}
}

// ---- validation --------------------------------------------------------------

func (c *Config) validate() error {
	var warn []string
	if err := checkHostPort(c.Listen, true); err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	if c.AdminListen != "off" {
		if err := checkHostPort(c.AdminListen, true); err != nil {
			return fmt.Errorf("admin_listen: %w (use \"off\" to disable)", err)
		}
		authed := c.AdminUser != "" && c.AdminPasswordHash != ""
		if (c.AdminUser != "") != (c.AdminPasswordHash != "") {
			return errors.New("admin_user and admin_password_hash must both be set (or both empty); set them with: ayana-cdn admin passwd")
		}
		if c.AdminPasswordHash != "" && !looksLikeBcrypt(c.AdminPasswordHash) {
			return errors.New("admin_password_hash is not a bcrypt hash; set it with: ayana-cdn admin passwd")
		}
		if !isLoopbackAddr(c.AdminListen) && !authed {
			warn = append(warn, fmt.Sprintf("admin_listen %q is not a loopback address and has no authentication; set admin_user/admin_password_hash (ayana-cdn admin passwd) or keep it on loopback", c.AdminListen))
			if c.AdminPprof {
				warn = append(warn, "admin_pprof exposes Go profiling (heap/cpu/cmdline) on a non-loopback address with no authentication; this is a remote info-leak and DoS vector — add admin auth or disable admin_pprof")
			}
		}
	}
	if c.RedirectListen != "" {
		if err := checkHostPort(c.RedirectListen, true); err != nil {
			return fmt.Errorf("redirect_listen: %w", err)
		}
	}
	for _, h := range c.CDNHosts {
		if !looksLikeHostname(h) {
			return fmt.Errorf("cdn_hosts: %q is not a valid hostname", h)
		}
	}
	switch c.TLS.Mode {
	case "acme":
		if len(c.CDNHosts) == 0 {
			return errors.New(`tls.mode "acme" needs at least one entry in cdn_hosts (certificates are issued for them)`)
		}
		if c.TLS.Email == "" {
			warn = append(warn, "tls.email is empty; Let's Encrypt accepts that, but you lose the account contact")
		}
	case "files":
		if c.TLS.CertFile == "" || c.TLS.KeyFile == "" {
			return errors.New(`tls.mode "files" needs tls.cert_file and tls.key_file`)
		}
	default:
		return fmt.Errorf(`tls.mode must be "acme" or "files", not %q`, c.TLS.Mode)
	}
	if _, ok := tlsVersions[c.TLS.MinVersion]; !ok {
		return fmt.Errorf("tls.min_version must be 1.0, 1.1, 1.2 or 1.3, not %q", c.TLS.MinVersion)
	}
	if (c.StrictSNI || c.StrictHost) && len(c.CDNHosts) == 0 {
		return errors.New("strict_sni and strict_host need cdn_hosts to compare against")
	}
	if _, err := parsePrefixes(c.ProxyProtocolTrusted); err != nil {
		return fmt.Errorf("proxy_protocol_trusted: %w", err)
	}

	l := c.Limits
	switch {
	case l.MaxConns < -1:
		return errors.New("limits.max_conns must be -1 (off), 0 (auto) or positive")
	case l.MaxConnsPerIP < -1:
		return errors.New("limits.max_conns_per_ip must be -1 (off), 0 (default off) or positive")
	case l.ConnRatePerIP < 0 && l.ConnRatePerIP != -1:
		return errors.New("limits.conn_rate_per_ip must be -1 (off) or positive")
	case l.ConnBurstPerIP < 1:
		return errors.New("limits.conn_burst_per_ip must be at least 1")
	case l.MaxHeaderBytes < 4096 || l.MaxHeaderBytes > 1<<20:
		return errors.New("limits.max_header_bytes must be between 4096 and 1048576")
	case l.MaxUDPSessions < -1:
		return errors.New("limits.max_udp_sessions must be -1 (off), 0 (auto) or positive")
	case l.MaxUDPPacket < 576 || l.MaxUDPPacket > maxUDPDatagram:
		return fmt.Errorf("limits.max_udp_packet must be between 576 and %d", maxUDPDatagram)
	case l.UDPRatePerIP < 0 && l.UDPRatePerIP != -1:
		return errors.New("limits.udp_rate_per_ip must be -1 (off), 0 (off) or positive")
	case l.UDPBurstPerIP < 1:
		return errors.New("limits.udp_burst_per_ip must be at least 1")
	case l.MaxUDPSessionsPerIP < -1:
		return errors.New("limits.max_udp_sessions_per_ip must be -1 (off), 0 (default) or positive")
	case l.UDPAmplification < -1:
		return errors.New("limits.udp_amplification must be -1 (off), 0 (default) or positive")
	}
	if _, err := parsePrefixes(l.Exempt); err != nil {
		return fmt.Errorf("limits.exempt: %w", err)
	}

	t := c.Timeouts
	for name, d := range map[string]Duration{
		"read_header": t.ReadHeader, "http_idle": t.HTTPIdle, "upstream_connect": t.UpstreamConnect,
		"upstream_header": t.UpstreamHeader, "tunnel_idle": t.TunnelIdle, "udp_idle": t.UDPIdle, "write_stall": t.WriteStall,
		"dead_peer":  t.DeadPeer,
		"half_close": t.HalfClose, "client_keepalive": t.ClientKeepAlive,
		"shutdown_grace": t.ShutdownGrace, "drain": t.Drain,
	} {
		if d < 0 {
			return fmt.Errorf("timeouts.%s must not be negative", name)
		}
	}
	if t.UDPIdle == 0 {
		return errors.New("timeouts.udp_idle must be positive: a datagram session has no other way to end")
	}
	if t.UDPReply < 0 && t.UDPReply != Duration(-time.Second) {
		return errors.New("timeouts.udp_reply must be -1 (off) or positive")
	}
	if t.RequestBody < 0 && t.RequestBody != Duration(-time.Second) {
		return errors.New("timeouts.request_body must be -1 (off) or positive")
	}

	if _, err := parseLevel(c.Log.Level); err != nil {
		return fmt.Errorf("log.level: %w", err)
	}
	if c.Log.Format != "text" && c.Log.Format != "json" {
		return fmt.Errorf(`log.format must be "text" or "json", not %q`, c.Log.Format)
	}

	if c.Geo.Enabled {
		if !strings.Contains(c.Geo.URL, "{ip}") {
			return errors.New(`geo.url must contain the "{ip}" placeholder, e.g. "https://ipwho.is/{ip}"`)
		}
		if !strings.HasPrefix(c.Geo.URL, "http://") && !strings.HasPrefix(c.Geo.URL, "https://") {
			return errors.New("geo.url must start with http:// or https://")
		}
		if c.Geo.RatePerMin < 1 {
			return errors.New("geo.rate_per_min must be at least 1")
		}
		if c.Geo.CacheSize < 1 {
			return errors.New("geo.cache_size must be at least 1")
		}
		warn = append(warn, fmt.Sprintf("geo.enabled sends client IPs to %s for location lookup; disable it or point geo.url at a provider you trust", c.Geo.URL))
	}

	panelWarn, err := c.validatePanel()
	if err != nil {
		return err
	}
	warn = append(warn, panelWarn...)

	names := map[string]bool{}
	udpListen := map[string]string{}
	for i := range c.Backends {
		b := &c.Backends[i]
		label := fmt.Sprintf("backend %q", b.Name)
		if b.Name == "" {
			label = fmt.Sprintf("backend #%d", i+1)
		}
		if err := b.validate(); err != nil {
			return fmt.Errorf("%s: %w", label, err)
		}
		if names[b.Name] {
			return fmt.Errorf("%s: duplicate name", label)
		}
		names[b.Name] = true
		if b.isUDP() {
			if other, dup := udpListen[b.Listen]; dup {
				return fmt.Errorf("%s: listen %q is already used by backend %q", label, b.Listen, other)
			}
			udpListen[b.Listen] = b.Name
		}
		if b.isPathRouted() && len(b.Upstreams) > 1 {
			// An older config may list several servers on one path. It still
			// loads, so an upgrade never takes the edge down, but only the
			// first server is used: a path never reaches another server.
			b.ignoredUpstreams = append([]string(nil), b.Upstreams[1:]...)
			b.Upstreams = b.Upstreams[:1]
			warn = append(warn, fmt.Sprintf("%s: path /%s/ connects to one server only: using %s, ignoring %s. "+
				"Give each server its own path (edit this one to keep a single server, then add the others as new paths)",
				label, b.Name, b.Upstreams[0], strings.Join(b.ignoredUpstreams, ", ")))
		}
		if b.Insecure {
			warn = append(warn, fmt.Sprintf("%s: insecure=true, the backend certificate is not verified", label))
		}
		if hc := b.HealthCheck.Type; hc != "off" && (b.isTunnel() || b.Relay == "always") {
			warn = append(warn, fmt.Sprintf("%s: %s health checks repeatedly connect to the backend; if it forwards to sshd, "+
				"OpenSSH 9.8+ PerSourcePenalties may block this edge's address — use health_check.type \"off\" or a dedicated "+
				"health endpoint, and exempt the edge's source address", label, hc))
		}
	}
	if len(c.Backends) == 0 {
		warn = append(warn, "no backends configured; every request will get 404")
	}
	c.warnings = warn
	return nil
}

func (b *Backend) validate() error {
	if !isValidName(b.Name) {
		return errors.New("name must be 1-64 characters from A-Z a-z 0-9 _ -")
	}
	if "/"+b.Name == reservedHealthPath {
		return errors.New(`name "healthz" is reserved for the edge's own health endpoint`)
	}
	switch b.Proto {
	case "wss", "ws", "https", "http", "sse", "udp":
	default:
		return fmt.Errorf("proto must be wss, ws, https, http, sse or udp, not %q", b.Proto)
	}
	tls := *b.TLS
	if b.isUDP() {
		if b.Listen == "" {
			return errors.New(`proto "udp" needs "listen" (the host:port that receives the datagrams; UDP has no path to route on)`)
		}
		if err := checkHostPort(b.Listen, true); err != nil {
			return fmt.Errorf("listen: %w", err)
		}
		if tls {
			return errors.New(`proto "udp" cannot use TLS to the backend`)
		}
		if b.Insecure {
			return errors.New(`"insecure" does not apply to a udp backend`)
		}
		if b.Relay != "upgrade" {
			return errors.New(`"relay" does not apply to a udp backend`)
		}
		if b.HealthCheck.Type != "off" {
			return fmt.Errorf(`health_check.type must be "off" for a udp backend (datagrams cannot be probed), not %q`, b.HealthCheck.Type)
		}
	} else if b.Listen != "" {
		return fmt.Errorf(`"listen" only applies to udp backends (proto %q backends are reached by path)`, b.Proto)
	}
	if (b.Proto == "wss" || b.Proto == "https") && !tls {
		return fmt.Errorf(`proto %q means TLS to the backend; use "%s" for plaintext`, b.Proto, strings.TrimSuffix(b.Proto, "s"))
	}
	if (b.Proto == "ws" || b.Proto == "http") && tls {
		return fmt.Errorf(`proto %q is plaintext; use "%ss" for TLS to the backend`, b.Proto, b.Proto)
	}
	if len(b.Upstreams) == 0 {
		return errors.New("needs at least one upstream (host:port)")
	}
	for _, u := range b.Upstreams {
		if err := checkHostPort(u, false); err != nil {
			return fmt.Errorf("upstream %q: %w", u, err)
		}
	}
	if strings.ContainsAny(b.Host, " /\t\r\n") {
		return fmt.Errorf("host %q is not a valid hostname", b.Host)
	}
	switch {
	case b.isUDP():
		switch b.LB {
		case "hash", "least_conn", "round_robin", "first":
		case "path":
			return errors.New(`lb "path" applies to path backends; a udp backend uses hash, least_conn, round_robin or first`)
		default:
			return fmt.Errorf("lb must be hash, least_conn, round_robin or first, not %q", b.LB)
		}
	case b.LB == "path":
	case b.LB == "hash":
		return errors.New(`lb "hash" applies only to udp backends; a path connects to its one server (lb "path")`)
	default:
		return fmt.Errorf(`lb must be "path" (a path connects to its one server), not %q`, b.LB)
	}
	switch b.Relay {
	case "upgrade":
	case "always":
		if !b.isTunnel() {
			return errors.New(`relay "always" only applies to ws/wss backends`)
		}
	default:
		return fmt.Errorf(`relay must be "upgrade" or "always", not %q`, b.Relay)
	}
	if b.MaxConns < 0 {
		return errors.New("max_conns must be 0 (unlimited) or positive")
	}
	if b.IdleTimeout < 0 {
		return errors.New("idle_timeout must not be negative")
	}
	hc := b.HealthCheck
	switch hc.Type {
	case "tcp", "http", "ws", "off":
	case "tls":
		if !tls {
			return errors.New(`health_check.type "tls" needs a TLS backend; use "tcp"`)
		}
	default:
		return fmt.Errorf("health_check.type must be tcp, tls, http, ws or off, not %q", hc.Type)
	}
	switch {
	case !strings.HasPrefix(hc.Path, "/"):
		return errors.New(`health_check.path must start with "/"`)
	case hc.Interval.D() < time.Second:
		return errors.New("health_check.interval must be at least 1s")
	case hc.Timeout.D() <= 0 || hc.Timeout > hc.Interval:
		return errors.New("health_check.timeout must be positive and not longer than the interval")
	case hc.Fall < 1 || hc.Rise < 1:
		return errors.New("health_check.fall and rise must be at least 1")
	case hc.Expect != 0 && (hc.Expect < 100 || hc.Expect > 599):
		return errors.New("health_check.expect must be an HTTP status code")
	}
	return nil
}

// checkHostPort validates host:port. Listen addresses (listen=true) may omit
// the host and may use port 0 (any free port); upstreams need both.
func checkHostPort(addr string, listen bool) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("%q is not host:port", addr)
	}
	if host == "" && !listen {
		return fmt.Errorf("%q has no host", addr)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 0 || n > 65535 || (n == 0 && !listen) {
		return fmt.Errorf("%q has an invalid port", addr)
	}
	return nil
}

func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func isValidName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

func looksLikeHostname(s string) bool {
	if s == "" || len(s) > 253 || !strings.Contains(s, ".") {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

// isValidPanelPath restricts the secret panel prefix to unambiguous, safe URL
// path characters so it can never need percent-decoding to match and cannot
// collide with query or fragment syntax.
func isValidPanelPath(s string) bool {
	if !strings.HasPrefix(s, "/") {
		return false
	}
	for _, r := range s[1:] {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' ||
			r == '_' || r == '-' || r == '.' || r == '~' || r == '/') {
			return false
		}
	}
	return true
}

// validatePanel checks the web panel configuration and returns any warnings.
// Full checks apply only when the panel is enabled; a stored-but-disabled
// panel is left alone so it can be completed incrementally.
func (c *Config) validatePanel() ([]string, error) {
	p := c.Panel
	if p == nil || !p.Enabled {
		return nil, nil
	}
	var warn []string
	if p.Path == "" {
		return nil, errors.New(`panel.path is required when the panel is enabled (set it with: ayana-cdn panel enable)`)
	}
	if !isValidPanelPath(p.Path) {
		return nil, fmt.Errorf("panel.path %q must start with / and use only letters, digits and _-.~/ ", p.Path)
	}
	if p.Path == "/" || hasPathPrefix(p.Path, reservedHealthPath) || hasPathPrefix(reservedHealthPath, p.Path) {
		return nil, fmt.Errorf("panel.path %q conflicts with a reserved path", p.Path)
	}
	// A short path is easy to guess; the whole point is secrecy.
	if seg := strings.Trim(p.Path, "/"); len(seg) < 6 {
		warn = append(warn, fmt.Sprintf("panel.path %q is short and easy to guess; use a long random prefix (ayana-cdn panel path)", p.Path))
	}
	if p.Username == "" {
		return nil, errors.New("panel.username is required when the panel is enabled")
	}
	if len(p.Username) > 64 || strings.ContainsAny(p.Username, "\x00\r\n") {
		return nil, errors.New("panel.username must be at most 64 characters and contain no control characters")
	}
	if p.PasswordHash == "" {
		return nil, errors.New(`panel.password_hash is required when the panel is enabled (set it with: ayana-cdn panel passwd)`)
	}
	if !looksLikeBcrypt(p.PasswordHash) {
		return nil, errors.New("panel.password_hash is not a bcrypt hash; set it with: ayana-cdn panel passwd")
	}
	if p.SessionKey != "" {
		key, err := base64.StdEncoding.DecodeString(p.SessionKey)
		if err != nil || len(key) < 32 {
			return nil, errors.New("panel.session_key must be base64 encoding at least 32 bytes (leave it empty to generate a random key each start)")
		}
	} else {
		warn = append(warn, "panel.session_key is empty; a random key is generated at each start, so a restart logs every panel user out (set one with: ayana-cdn panel enable)")
	}
	if p.SessionTTL <= 0 {
		return nil, errors.New("panel.session_ttl must be positive")
	}
	if _, err := parsePrefixes(p.AllowedCIDRs); err != nil {
		return nil, fmt.Errorf("panel.allowed_cidrs: %w", err)
	}
	for _, b := range c.Backends {
		prefix := "/" + strings.TrimSpace(b.Name)
		if prefix == "/" {
			continue
		}
		if hasPathPrefix(p.Path, prefix) || hasPathPrefix(prefix, p.Path) {
			warn = append(warn, fmt.Sprintf("panel.path %q overlaps backend %q (%s/); the panel is matched first, so that backend would be unreachable", p.Path, b.Name, prefix))
		}
	}
	return warn, nil
}

// looksLikeBcrypt reports whether s has a bcrypt hash's shape ($2a/$2b/$2y,
// cost, 53 trailing characters). The real check is bcrypt's own at login.
func looksLikeBcrypt(s string) bool {
	if len(s) != 60 {
		return false
	}
	if !(strings.HasPrefix(s, "$2a$") || strings.HasPrefix(s, "$2b$") || strings.HasPrefix(s, "$2y$")) {
		return false
	}
	return s[6] == '$'
}

// ---- saving (CLI) -----------------------------------------------------------------

// withConfigLock serializes CLI edits of the same config file.
func withConfigLock(path string, fn func() error) error {
	lockPath := path + ".lock"
	lf, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("lock config: %w", err)
	}
	// CLI operations are often run as root while the service/panel runs as the
	// dedicated service user. If root creates the lock, align its ownership
	// with the config file so the panel can open it on later requests.
	if fi, statErr := os.Stat(path); statErr == nil {
		if st, ok := fi.Sys().(*syscall.Stat_t); ok && os.Geteuid() == 0 {
			if err := os.Chown(lockPath, int(st.Uid), int(st.Gid)); err != nil {
				lf.Close()
				return fmt.Errorf("set config lock ownership: %w", err)
			}
			if err := os.Chmod(lockPath, 0o600); err != nil {
				lf.Close()
				return fmt.Errorf("set config lock permissions: %w", err)
			}
		}
	}
	defer lf.Close()
	if err := syscall.Flock(int(lf.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("lock config: %w", err)
	}
	defer syscall.Flock(int(lf.Fd()), syscall.LOCK_UN) //nolint:errcheck
	return fn()
}

// saveRaw writes the raw config atomically, keeping the previous file as .bak.
func saveRaw(path string, c *Config) error {
	out, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	out = append(out, '\n')
	mode := os.FileMode(0o644)
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm()
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(out); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if old, err := os.ReadFile(path); err == nil {
		if err := os.WriteFile(path+".bak", old, mode); err != nil {
			slog.Warn("could not write config backup", "err", err)
		}
	}
	return os.Rename(tmp, path)
}
