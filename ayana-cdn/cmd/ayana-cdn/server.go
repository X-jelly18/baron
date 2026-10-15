package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "2.7.0"

const defaultPIDFile = "/run/ayana-cdn/pid"

// state is an immutable snapshot of everything derived from one config load.
// Handlers load it once per request, so a reload never changes the rules in
// the middle of a request or tunnel.
type state struct {
	cfg          *Config
	gen          uint64
	routes       *routeTable
	hosts        map[string]bool
	primary      string
	trusted      []netip.Prefix
	exempt       []netip.Prefix
	keepAlive    keepAlive
	maxConns     int64
	maxUDP       int64
	maxUnreplied int64
	access       bool
	ipLogOn      bool
	tlsConf      *tls.Config
}

// Server is the edge.
type Server struct {
	cfgPath string
	log     *slog.Logger
	fixed   *Config // the config the process started with (listener-bound settings)
	tlsMode string  // certificate source chosen at startup: "acme" or "files"

	state      atomic.Pointer[state]
	gen        atomic.Uint64
	stats      *statsRegistry
	tunnels    *tunnelRegistry
	limiter    *ipLimiter
	udpLimiter *ipLimiter
	certs      *certTracker
	panel      *panelAuth
	geo        *geoResolver
	series     *seriesStore

	acme     *autocert.Manager
	acmeSrc  certSource
	fileCert atomic.Pointer[tls.Certificate]

	startTime time.Time
	pidFile   string

	draining    atomic.Bool
	handoffBusy atomic.Bool
	handedOff   chan struct{}
	ready       chan struct{}

	// lifecycleMu serializes config/listener-mutating transitions: a reload
	// (which reconciles UDP sockets) must never run while a handoff is
	// snapshotting and duplicating those same sockets. Reload try-locks and
	// refuses if a handoff holds it; Handoff holds it for its whole body.
	lifecycleMu sync.Mutex

	lnMu      sync.Mutex // guards listeners (appended at startup and on udp reload)
	listeners []namedListener
	inherited []string
	pubLn     *edgeListener
	udpMu     sync.Mutex // guards udp
	udp       []*udpListener
	httpSrv   *http.Server
	adminSrv  *http.Server
	redirSrv  *http.Server
}

var errDraining = errors.New("process is draining")

// NewServer loads and validates the config and prepares certificates. It
// binds nothing; Run does.
func NewServer(cfgPath string, log *slog.Logger) (*Server, error) {
	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		return nil, err
	}
	if log == nil {
		log = newLogger(os.Stderr, cfg.Log.Format)
	}
	s := &Server{
		cfgPath: cfgPath, log: log, fixed: cfg, tlsMode: cfg.TLS.Mode,
		stats: newStatsRegistry(), tunnels: newTunnelRegistry(), limiter: newIPLimiter(), udpLimiter: newIPLimiter(),
		certs: newCertTracker(log), startTime: time.Now(), pidFile: defaultPIDFile,
		series:    newSeriesStore(seriesInterval, seriesCap),
		handedOff: make(chan struct{}), ready: make(chan struct{}),
	}
	switch cfg.TLS.Mode {
	case "acme":
		if err := os.MkdirAll(cfg.TLS.CacheDir, 0o700); err != nil {
			return nil, fmt.Errorf("tls.cache_dir: %w", err)
		}
		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			Email:      cfg.TLS.Email,
			Cache:      loggingCache{Cache: autocert.DirCache(cfg.TLS.CacheDir), log: log},
			HostPolicy: s.hostPolicy,
		}
		s.acme, s.acmeSrc = m, m
	case "files":
		if err := s.loadFileCert(cfg.TLS.CertFile, cfg.TLS.KeyFile); err != nil {
			return nil, err
		}
	}
	s.geo = newGeoResolver()
	s.applyRuntime(cfg)
	if s.panel, err = newPanelAuth(cfg); err != nil {
		return nil, err
	}
	s.state.Store(s.buildState(cfg, nil))
	for _, w := range cfg.warnings {
		log.Warn("config warning", "detail", w)
	}
	return s, nil
}

func (s *Server) applyRuntime(cfg *Config) {
	if lv, err := parseLevel(cfg.Log.Level); err == nil {
		logLevel.Set(lv)
	}
	s.limiter.configure(cfg.Limits)
	s.udpLimiter.configureRaw(cfg.Limits.UDPRatePerIP, cfg.Limits.UDPBurstPerIP, cfg.Limits.MaxUDPSessionsPerIP)
	if s.geo != nil {
		s.geo.configure(cfg.Geo)
	}
}

func (s *Server) buildState(cfg *Config, old *state) *state {
	st := &state{
		cfg:       cfg,
		hosts:     make(map[string]bool, len(cfg.CDNHosts)),
		keepAlive: newKeepAlive(cfg.Timeouts),
		access:    *cfg.Log.Access,
		ipLogOn:   cfg.Log.IPLog == nil || *cfg.Log.IPLog,
		maxConns:  effectiveMaxConns(cfg.Limits.MaxConns),
		maxUDP:    effectiveMaxUDPSessions(cfg.Limits.MaxUDPSessions),
	}
	st.maxUnreplied = maxUnreplied(st.maxUDP)
	for _, h := range cfg.CDNHosts {
		st.hosts[h] = true
	}
	if len(cfg.CDNHosts) > 0 {
		st.primary = cfg.CDNHosts[0]
	}
	st.trusted, _ = parsePrefixes(cfg.ProxyProtocolTrusted) // validated already
	st.exempt, _ = parsePrefixes(cfg.Limits.Exempt)
	var oldRoutes *routeTable
	if old != nil {
		oldRoutes = old.routes
	}
	st.routes = s.buildRoutes(cfg, oldRoutes)
	st.tlsConf = s.buildTLS(cfg, st)
	st.gen = s.gen.Add(1)
	return st
}

// effectiveMaxConns: explicit value, -1 = unlimited, 0 = derived from the
// file-descriptor limit (each tunnel needs two descriptors).
func effectiveMaxConns(v int) int64 {
	switch {
	case v > 0:
		return int64(v)
	case v < 0:
		return 0
	}
	lim := nofileLimit()
	if lim > 1<<30 {
		lim = 1 << 30
	}
	return max(int64(lim)/2-256, 256)
}

// Run binds the listeners, serves until ctx is canceled (graceful stop) or a
// handoff completes (drain), and returns.
func (s *Server) Run(ctx context.Context) error {
	st := s.state.Load()
	cfg := st.cfg
	inh, err := parseInherit(os.Getenv(envInherit))
	if err != nil {
		return err
	}
	defer closeInherited(inh)

	pub, err := s.listenTCP("public", cfg.Listen, inh)
	if err != nil {
		return err
	}
	s.pubLn = &edgeListener{Listener: pub, s: s}
	tlsLn := tls.NewListener(s.pubLn, &tls.Config{GetConfigForClient: s.getConfigForClient})
	s.httpSrv = &http.Server{
		Handler:                      s,
		ReadHeaderTimeout:            cfg.Timeouts.ReadHeader.D(), // also bounds the TLS handshake
		IdleTimeout:                  cfg.Timeouts.HTTPIdle.D(),
		MaxHeaderBytes:               cfg.Limits.MaxHeaderBytes,
		ErrorLog:                     httpErrorLog(s.log, "edge"),
		DisableGeneralOptionsHandler: true,
		// No ReadTimeout/WriteTimeout: tunnels are long-lived by design.
	}
	var adminLn, redirLn net.Listener
	if cfg.AdminListen != "off" {
		if adminLn, err = s.listenTCP("admin", cfg.AdminListen, inh); err != nil {
			s.closeListeners()
			return err
		}
		s.adminSrv = &http.Server{Handler: s.adminHandler(cfg), ReadHeaderTimeout: 5 * time.Second,
			ErrorLog: httpErrorLog(s.log, "admin")}
	}
	if cfg.RedirectListen != "" {
		if redirLn, err = s.listenTCP("redirect", cfg.RedirectListen, inh); err != nil {
			s.closeListeners()
			return err
		}
		s.redirSrv = &http.Server{Handler: s.redirectHandler(), ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout: 30 * time.Second, ErrorLog: httpErrorLog(s.log, "redirect")}
	}
	if err := s.startUDP(cfg, inh); err != nil {
		s.stopUDP("startup failed")
		s.closeListeners()
		return err
	}

	errCh := make(chan error, 3)
	serve := func(name string, srv *http.Server, ln net.Listener) {
		go func() {
			err := srv.Serve(ln)
			if errors.Is(err, http.ErrServerClosed) {
				err = nil
			} else if err != nil {
				err = fmt.Errorf("%s listener: %w", name, err)
			}
			errCh <- err
		}()
	}
	serve("public", s.httpSrv, tlsLn)
	if s.adminSrv != nil {
		serve("admin", s.adminSrv, adminLn)
	}
	if s.redirSrv != nil {
		serve("redirect", s.redirSrv, redirLn)
	}
	go s.sweepLoop(ctx)
	go s.geo.run(ctx)
	go s.runSeries(ctx)
	s.writePIDFile()
	if err := s.signalReady(); err != nil {
		s.log.Warn("could not signal readiness", "err", err)
	}
	close(s.ready)
	s.log.Info("ayana-cdn serving", "version", version, "listen", pub.Addr().String(), "hosts", cfg.CDNHosts,
		"tls", s.tlsMode, "backends", len(cfg.Backends), "max_conns", st.maxConns, "udp_listeners", len(s.udpListeners()),
		"dead_peer_after", st.keepAlive.deadAfter().String(),
		"admin", cfg.AdminListen, "inherited", strings.Join(s.inherited, ","))
	if s.tlsMode == "acme" {
		go s.warmUp(ctx, cfg.CDNHosts, dialableAddr(pub.Addr()))
	}

	select {
	case <-ctx.Done():
		return s.shutdown()
	case err := <-errCh:
		if err == nil {
			err = errors.New("a listener stopped unexpectedly")
		}
		s.log.Error("serving failed", "err", err)
		_ = s.shutdown()
		return err
	case <-s.handedOff:
		return s.drain(ctx)
	}
}

// Ready is closed once the listeners are serving.
func (s *Server) Ready() <-chan struct{} { return s.ready }

// PublicAddr is the bound address of the public listener (after Ready).
func (s *Server) PublicAddr() net.Addr { return s.listenerAddr("public") }

// AdminAddr is the bound address of the admin listener, if any (after Ready).
func (s *Server) AdminAddr() net.Addr { return s.listenerAddr("admin") }

// UDPAddr is the bound address of a udp backend's listener (after Ready).
func (s *Server) UDPAddr(backend string) net.Addr { return s.listenerAddr(udpListenerName(backend)) }

func (s *Server) listenerAddr(name string) net.Addr {
	s.lnMu.Lock()
	defer s.lnMu.Unlock()
	for _, l := range s.listeners {
		if l.name == name {
			return l.bound
		}
	}
	return nil
}

func (s *Server) closeListeners() {
	s.lnMu.Lock()
	ls := append([]namedListener(nil), s.listeners...)
	s.lnMu.Unlock()
	for _, l := range ls {
		l.ln.Close()
	}
}

// dropListener removes a listener entry by name (a udp socket stopped on
// reload), so a later handoff does not try to pass its closed descriptor on.
func (s *Server) dropListener(name string) {
	s.lnMu.Lock()
	kept := s.listeners[:0:0]
	for _, l := range s.listeners {
		if l.name != name {
			kept = append(kept, l)
		}
	}
	s.listeners = kept
	s.lnMu.Unlock()
}

func (s *Server) activeConns() int64 {
	if s.pubLn == nil {
		return 0
	}
	return s.pubLn.active.Load()
}

// ServeHTTP dispatches client requests.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	st := s.state.Load()
	// The web panel owns its secret prefix and is matched before any backend
	// route and before strict_host, so it stays reachable and no backend can
	// shadow it. Its own auth, not the host policy, protects it.
	if prefix := panelPrefix(st); prefix != "" && hasPathPrefix(r.URL.Path, prefix) {
		s.servePanel(w, r, st)
		return
	}
	if r.URL.Path == reservedHealthPath {
		if s.draining.Load() {
			http.Error(w, "draining", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "ok\n")
		return
	}
	if st.cfg.StrictHost && !st.hosts[normHost(r.Host)] {
		s.stats.global.misdirected.Add(1)
		http.Error(w, "misdirected request", http.StatusMisdirectedRequest)
		return
	}
	brt := st.routes.match(r.URL.Path)
	if brt == nil {
		s.stats.global.unrouted.Add(1)
		s.log.Debug("unrouted request", "client", clientIP(r), "method", r.Method, "path", truncate(r.URL.Path, 200))
		http.NotFound(w, r)
		return
	}
	hs := s.stats.host(hostBucket(r, st))
	hs.requests.Add(1)
	if st.ipLogOn {
		if brt.stats.ips.record(clientIP(r), time.Now()) {
			s.geo.enqueue(clientIP(r))
		}
	}
	if brt.cfg.Disabled {
		s.respondError(w, r, brt, st, http.StatusServiceUnavailable, "backend disabled", nil, time.Now())
		return
	}
	if brt.tunnelOnly || r.Header.Get("Upgrade") != "" {
		s.serveTunnel(w, r, brt, st, hs)
		return
	}
	s.serveHTTPProxy(w, r, brt, st, hs)
}

// hostBucket maps a request to its per-host traffic bucket: the configured
// cdn_host it hit, or "other" for anything else (so a flood of random Host
// headers cannot grow the host-stats map without bound).
func hostBucket(r *http.Request, st *state) string {
	h := normHost(r.Host)
	if st.hosts[h] {
		return h
	}
	return "other"
}

// Reload re-reads the config (SIGHUP). A config that fails validation is
// rejected as a whole and the running config stays in effect.
func (s *Server) Reload() error {
	if s.draining.Load() {
		return errDraining
	}
	// Never reconcile sockets while a handoff is duplicating them (or while
	// another reload runs). TryLock keeps the signal loop responsive: a reload
	// that collides with a restart is refused, not blocked.
	if !s.lifecycleMu.TryLock() {
		return errors.New("a restart or another reload is in progress; config not reloaded")
	}
	defer s.lifecycleMu.Unlock()
	cfg, err := LoadConfig(s.cfgPath)
	if err == nil && s.tlsMode == "files" && cfg.TLS.Mode == "files" {
		err = s.loadFileCert(cfg.TLS.CertFile, cfg.TLS.KeyFile)
	}
	if err != nil {
		s.stats.global.reloadErr.Add(1)
		s.log.Error("reload rejected; the running config stays in effect", "err", err)
		return err
	}
	for _, name := range restartOnlyChanges(s.fixed, cfg) {
		s.log.Warn("setting changed but only applies after a restart", "setting", name,
			"apply_with", "ayana-cdn restart (no downtime)")
	}
	old := s.state.Load()
	s.applyRuntime(cfg)
	st := s.buildState(cfg, old)
	s.state.Store(st)
	s.reconcileUDP(old.cfg, cfg, map[string]inheritSpec{})
	old.routes.stop()
	s.stats.global.reloadOK.Add(1)
	s.log.Info("config reloaded", "generation", st.gen, "backends", len(cfg.Backends), "hosts", cfg.CDNHosts)
	for _, w := range cfg.warnings {
		s.log.Warn("config warning", "detail", w)
	}
	return nil
}

// restartOnlyChanges lists settings bound at startup that a reload cannot change.
func restartOnlyChanges(old, cur *Config) []string {
	var out []string
	check := func(name string, changed bool) {
		if changed {
			out = append(out, name)
		}
	}
	check("listen", old.Listen != cur.Listen)
	check("admin_listen", old.AdminListen != cur.AdminListen)
	check("admin_pprof", old.AdminPprof != cur.AdminPprof)
	check("panel.session_key", panelSessionKey(old) != panelSessionKey(cur))
	check("redirect_listen", old.RedirectListen != cur.RedirectListen)
	check("tls.mode", old.TLS.Mode != cur.TLS.Mode)
	check("tls.email", old.TLS.Email != cur.TLS.Email)
	check("tls.cache_dir", old.TLS.CacheDir != cur.TLS.CacheDir)
	check("log.format", old.Log.Format != cur.Log.Format)
	check("timeouts.read_header", old.Timeouts.ReadHeader != cur.Timeouts.ReadHeader)
	check("timeouts.http_idle", old.Timeouts.HTTPIdle != cur.Timeouts.HTTPIdle)
	check("limits.max_header_bytes", old.Limits.MaxHeaderBytes != cur.Limits.MaxHeaderBytes)
	return out
}

// udpListenSet maps each udp backend to its listen address: the sockets a
// process binds at startup.
func udpListenSet(c *Config) map[string]string {
	out := map[string]string{}
	for _, b := range c.Backends {
		if b.isUDP() {
			out[b.Name] = b.Listen
		}
	}
	return out
}

// shutdown is a stop (SIGTERM): tunnels are closed right away — there is
// nothing to gain by waiting for them — and in-flight HTTP requests get
// timeouts.shutdown_grace to finish.
func (s *Server) shutdown() error {
	s.draining.Store(true)
	_, _ = sdNotify("STOPPING=1")
	if n := s.tunnels.shutdown("shutdown"); n > 0 {
		s.log.Info("closing tunnels", "count", n)
	}
	if n := s.stopUDP("shutdown"); n > 0 {
		s.log.Info("closing udp sessions", "count", n)
	}
	grace := s.state.Load().cfg.Timeouts.ShutdownGrace.D()
	ctx, cancel := context.WithTimeout(context.Background(), grace)
	defer cancel()
	var wg sync.WaitGroup
	for _, srv := range []*http.Server{s.httpSrv, s.adminSrv, s.redirSrv} {
		if srv == nil {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := srv.Shutdown(ctx); err != nil {
				_ = srv.Close()
			}
		}()
	}
	wg.Wait()
	wctx, wcancel := context.WithTimeout(context.Background(), 3*time.Second)
	s.tunnels.waitEmpty(wctx)
	wcancel()
	s.state.Load().routes.stop()
	s.removePIDFile()
	s.log.Info("stopped")
	return nil
}

// redirectHandler answers plain HTTP: ACME http-01 challenges when in acme
// mode, a 308 to https for everything else.
func (s *Server) redirectHandler() http.Handler {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		st := s.state.Load()
		host := normHost(r.Host)
		if !st.hosts[host] {
			host = st.primary
		}
		if host == "" {
			http.NotFound(w, r)
			return
		}
		http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), http.StatusPermanentRedirect)
	})
	if s.acme != nil {
		return s.acme.HTTPHandler(h)
	}
	return h
}

func (s *Server) sweepLoop(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			s.limiter.sweep(now)
			s.udpLimiter.sweep(now)
			s.panel.throttle.sweep(now)
		}
	}
}

func (s *Server) writePIDFile() {
	if s.pidFile == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(s.pidFile), 0o755); err != nil {
		s.log.Debug("pid file not written", "err", err)
		return
	}
	tmp := s.pidFile + ".tmp"
	if err := os.WriteFile(tmp, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o644); err != nil {
		s.log.Debug("pid file not written", "err", err)
		return
	}
	_ = os.Rename(tmp, s.pidFile)
}

// removePIDFile removes the pid file only if it still names this process
// (after a handoff it names the new one).
func (s *Server) removePIDFile() {
	if s.pidFile == "" {
		return
	}
	if b, err := os.ReadFile(s.pidFile); err == nil && strings.TrimSpace(string(b)) == strconv.Itoa(os.Getpid()) {
		_ = os.Remove(s.pidFile)
	}
}
