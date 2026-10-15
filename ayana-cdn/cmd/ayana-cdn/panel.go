package main

import (
	"compress/gzip"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// The web panel is an authenticated, HTTPS-only admin dashboard served on the
// public TLS listener at a secret path prefix (panel.path). It is matched in
// ServeHTTP before the route table, so no backend can shadow it. Everything
// below the prefix requires a signed session cookie that is handed out only
// after a username + bcrypt-password login; state-changing actions
// additionally require panel.allow_control and a CSRF token.

const (
	panelCookie     = "ayana_panel" // session cookie name; scoped to the panel path
	panelLoginDelay = 350 * time.Millisecond
	panelMaxBody    = 64 << 10
)

// panelAuth holds the process-wide panel secrets and the login throttle. The
// per-request policy (path, username, password hash, ttl, allow_control,
// allowlist) is read live from the config snapshot, so a reload changes it
// without a restart. The signing key is fixed at startup: an empty
// panel.session_key means a random key each start (restart logs everyone out),
// which is why session_key is a restart-only change.
type panelAuth struct {
	key       []byte
	ephemeral bool // key was randomly generated, not from config
	throttle  *loginThrottle
}

func newPanelAuth(cfg *Config) (*panelAuth, error) {
	a := &panelAuth{throttle: newLoginThrottle()}
	if cfg.Panel != nil && cfg.Panel.SessionKey != "" {
		key, err := base64.StdEncoding.DecodeString(cfg.Panel.SessionKey)
		if err != nil || len(key) < 32 {
			return nil, errBadSessionKey
		}
		a.key = key
		return a, nil
	}
	a.key = make([]byte, 32)
	if _, err := rand.Read(a.key); err != nil {
		return nil, err
	}
	a.ephemeral = true
	return a, nil
}

var errBadSessionKey = errPanel("panel.session_key must be base64 of at least 32 bytes")

type errPanel string

func (e errPanel) Error() string { return string(e) }

// panelPrefix is the normalized secret prefix, or "" when the panel is off.
func panelPrefix(st *state) string {
	if st.cfg.Panel == nil || !st.cfg.Panel.Enabled {
		return ""
	}
	return st.cfg.Panel.Path
}

func panelSessionKey(c *Config) string {
	if c.Panel == nil {
		return ""
	}
	return c.Panel.SessionKey
}

// servePanel handles a request already known to fall under the panel prefix.
func (s *Server) servePanel(w http.ResponseWriter, r *http.Request, st *state) {
	p := st.cfg.Panel
	// HTTPS only. ServeHTTP is mounted solely on the TLS listener, so this is
	// belt-and-braces; a plaintext request must never see the login form.
	if r.TLS == nil {
		http.NotFound(w, r)
		return
	}
	// Optional source-IP allowlist. A blocked address gets the same 404 an
	// unknown path would, so the panel's existence is not confirmed.
	if len(p.AllowedCIDRs) > 0 {
		prefixes, _ := parsePrefixes(p.AllowedCIDRs) // validated at load
		if !prefixesContain(prefixes, panelClientAddr(r)) {
			http.NotFound(w, r)
			return
		}
	}

	rel := r.URL.Path[len(p.Path):]
	if rel == "" {
		rel = "/"
	}

	nonce := randToken(16)
	setPanelHeaders(w, nonce)

	switch rel {
	case "/login":
		s.panelLogin(w, r, st, nonce)
	case "/logout":
		s.panelLogout(w, r, st)
	case "/api/status":
		s.panelStatus(w, r, st)
	case "/api/series":
		s.panelSeries(w, r, st)
	case "/api/iplog":
		s.panelIPLog(w, r, st)
	case "/api/reload":
		s.panelReload(w, r, st)
	case "/api/backend":
		s.panelBackend(w, r, st)
	case "/api/host":
		s.panelHost(w, r, st)
	case "/":
		s.panelDashboard(w, r, st, nonce)
	default:
		http.NotFound(w, r)
	}
}

// ---- request helpers --------------------------------------------------------

func panelClientAddr(r *http.Request) netip.Addr {
	ip, err := netip.ParseAddr(clientIP(r))
	if err != nil {
		return netip.Addr{}
	}
	return ip.Unmap()
}

func panelClientKey(r *http.Request) string {
	if ip := panelClientAddr(r); ip.IsValid() {
		return limiterKey(ip)
	}
	return clientIP(r)
}

// authed reports the logged-in user and the session nonce (for CSRF), or ok=false.
func (s *Server) authed(r *http.Request, st *state) (user, nonce string, ok bool) {
	c, err := r.Cookie(panelCookie)
	if err != nil {
		return "", "", false
	}
	user, nonce, ok = verifySession(s.panel.key, c.Value)
	if !ok {
		return "", "", false
	}
	// The session is only valid for the currently configured user. Changing
	// panel.username (via reload) invalidates outstanding sessions.
	if subtle.ConstantTimeCompare([]byte(user), []byte(st.cfg.Panel.Username)) != 1 {
		return "", "", false
	}
	return user, nonce, true
}

func setPanelHeaders(w http.ResponseWriter, nonce string) {
	h := w.Header()
	h.Set("Content-Security-Policy",
		"default-src 'none'; style-src 'nonce-"+nonce+"'; script-src 'nonce-"+nonce+"'; "+
			"connect-src 'self'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store, max-age=0")
	h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
}

// ---- login / logout ---------------------------------------------------------

func (s *Server) panelLogin(w http.ResponseWriter, r *http.Request, st *state, nonce string) {
	p := st.cfg.Panel
	switch r.Method {
	case http.MethodGet:
		if _, _, ok := s.authed(r, st); ok {
			http.Redirect(w, r, p.Path+"/", http.StatusSeeOther)
			return
		}
		writePanelLogin(w, nonce, "")
	case http.MethodPost:
		key := panelClientKey(r)
		if wait, locked := s.panel.throttle.locked(key, time.Now()); locked {
			s.log.Warn("panel login throttled", "client", clientIP(r), "retry_after", wait.Round(time.Second).String())
			w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
			w.WriteHeader(http.StatusTooManyRequests)
			writePanelLoginBody(w, nonce, "Too many attempts. Try again later.")
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		user := r.PostFormValue("username")
		pass := r.PostFormValue("password")
		if s.panelCheckCredentials(p, user, pass) {
			s.panel.throttle.reset(key)
			value, exp := newSession(s.panel.key, p.Username, p.SessionTTL.D())
			http.SetCookie(w, &http.Cookie{
				Name: panelCookie, Value: value, Path: p.Path,
				Expires: exp, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
			})
			s.log.Info("panel login", "user", p.Username, "client", clientIP(r))
			http.Redirect(w, r, p.Path+"/", http.StatusSeeOther)
			return
		}
		s.panel.throttle.fail(key, time.Now())
		s.log.Warn("panel login failed", "client", clientIP(r))
		time.Sleep(panelLoginDelay) // blunt timing/brute-force
		w.WriteHeader(http.StatusUnauthorized)
		writePanelLoginBody(w, nonce, "Invalid credentials.")
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// panelCheckCredentials verifies the username and password in roughly constant
// time: bcrypt runs whether or not the username matches, so a wrong username
// is not distinguishable from a wrong password by timing.
func (s *Server) panelCheckCredentials(p *PanelConfig, user, pass string) bool {
	userOK := subtle.ConstantTimeCompare([]byte(user), []byte(p.Username)) == 1
	passOK := bcrypt.CompareHashAndPassword([]byte(p.PasswordHash), []byte(pass)) == nil
	return userOK && passOK
}

func (s *Server) panelLogout(w http.ResponseWriter, r *http.Request, st *state) {
	p := st.cfg.Panel
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Logout changes state (drops the session), so it needs a valid session + CSRF.
	_, nonce, ok := s.authed(r, st)
	if ok && !s.checkCSRF(r, nonce) {
		http.Error(w, "bad csrf token", http.StatusForbidden)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: panelCookie, Value: "", Path: p.Path,
		MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
	http.Redirect(w, r, p.Path+"/login", http.StatusSeeOther)
}

// ---- dashboard + API --------------------------------------------------------

func (s *Server) panelDashboard(w http.ResponseWriter, r *http.Request, st *state, nonce string) {
	p := st.cfg.Panel
	user, snonce, ok := s.authed(r, st)
	if !ok {
		http.Redirect(w, r, p.Path+"/login", http.StatusSeeOther)
		return
	}
	writePanelDashboard(w, nonce, dashData{
		Base:    p.Path,
		User:    user,
		CSRF:    s.csrfToken(snonce),
		Control: p.AllowControl,
	})
}

func (s *Server) panelStatus(w http.ResponseWriter, r *http.Request, st *state) {
	if _, _, ok := s.authed(r, st); !ok {
		writeJSONError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	writePanelJSON(w, r, http.StatusOK, s.buildStatus(), true)
}

// panelSeries returns the recent per-backend / per-domain / total throughput
// history for the panel's live graphs. Read-only (no allow_control needed);
// authentication required.
func (s *Server) panelSeries(w http.ResponseWriter, r *http.Request, st *state) {
	if _, _, ok := s.authed(r, st); !ok {
		writeJSONError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	q := r.URL.Query()
	since, _ := strconv.ParseUint(q.Get("since"), 10, 64)
	writePanelJSON(w, r, http.StatusOK, s.series.snapshotSince(since, q.Get("epoch")), false)
}

// panelIPLog returns the per-backend client-IP hit log, joined with any cached
// geolocation. Read-only (no allow_control needed); authentication required.
func (s *Server) panelIPLog(w http.ResponseWriter, r *http.Request, st *state) {
	if _, _, ok := s.authed(r, st); !ok {
		writeJSONError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	name := strings.TrimSpace(r.URL.Query().Get("backend"))
	brt := st.routes.byName[name]
	if brt == nil {
		writeJSONError(w, http.StatusNotFound, "no such backend")
		return
	}
	rows, total, overflow := brt.stats.ips.snapshot(200)
	for i := range rows {
		s.geo.enqueue(rows[i].IP) // lazily fill/refresh geo for what we display
		if info, ok := s.geo.lookup(rows[i].IP); ok {
			rows[i].Country, rows[i].City, rows[i].CC = info.country, info.city, info.cc
		}
	}
	writePanelJSON(w, r, http.StatusOK, map[string]any{
		"backend": name, "geo_enabled": s.geo.enabled(),
		"total_ips": total, "overflow": overflow, "ips": rows,
	}, false)
}

func (s *Server) panelReload(w http.ResponseWriter, r *http.Request, st *state) {
	user, nonce, ok := s.authed(r, st)
	if !ok {
		writeJSONError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "use POST")
		return
	}
	if !st.cfg.Panel.AllowControl {
		writeJSONError(w, http.StatusForbidden, "control actions are disabled (panel.allow_control is false)")
		return
	}
	if !s.checkCSRF(r, nonce) {
		writeJSONError(w, http.StatusForbidden, "bad csrf token")
		return
	}
	s.log.Info("panel reload requested", "user", user, "client", clientIP(r))
	if err := s.Reload(); err != nil {
		writeJSONError(w, http.StatusBadRequest, "reload rejected: "+errString(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "configuration reloaded"})
}

// controlPreamble checks auth, method, allow_control and CSRF for a
// state-changing panel action, returning the form values on success.
func (s *Server) controlPreamble(w http.ResponseWriter, r *http.Request, st *state) (user string, ok bool) {
	u, nonce, authed := s.authed(r, st)
	if !authed {
		writeJSONError(w, http.StatusUnauthorized, "not authenticated")
		return "", false
	}
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "use POST")
		return "", false
	}
	if !st.cfg.Panel.AllowControl {
		writeJSONError(w, http.StatusForbidden, "control actions are disabled; enable them with: ayana-cdn panel enable -control")
		return "", false
	}
	if !s.checkCSRF(r, nonce) {
		writeJSONError(w, http.StatusForbidden, "bad csrf token")
		return "", false
	}
	if err := r.ParseForm(); err != nil {
		writeJSONError(w, http.StatusBadRequest, "bad request")
		return "", false
	}
	return u, true
}

func (s *Server) panelBackend(w http.ResponseWriter, r *http.Request, st *state) {
	user, ok := s.controlPreamble(w, r, st)
	if !ok {
		return
	}
	name := strings.TrimSpace(r.PostFormValue("name"))
	action := r.PostFormValue("action")
	s.log.Info("panel backend edit", "user", user, "backend", name, "action", action, "client", clientIP(r))
	msg, err := s.applyBackendEdit(action, name, r)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, errString(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": msg})
}

// applyBackendEdit persists a backend add/update/remove/enable/disable to the
// config file (same lock + whole-config validation the CLI uses) and applies
// it live with a reload.
func (s *Server) applyBackendEdit(action, name string, r *http.Request) (string, error) {
	if !isValidName(name) {
		return "", errPanel("backend name must be 1-64 chars of A-Z a-z 0-9 _ -")
	}
	var msg string
	err := s.panelEditConfig(func(c *Config) error {
		switch action {
		case "enable", "disable":
			b := findBackend(c, name)
			if b == nil {
				return errPanel("no backend named " + strconv.Quote(name))
			}
			b.Disabled = action == "disable"
			msg = action + "d backend " + name
		case "remove":
			for i := range c.Backends {
				if c.Backends[i].Name == name {
					c.Backends = append(c.Backends[:i], c.Backends[i+1:]...)
					msg = "removed backend " + name
					return nil
				}
			}
			return errPanel("no backend named " + strconv.Quote(name))
		case "add":
			if findBackend(c, name) != nil {
				return errPanel("backend " + strconv.Quote(name) + " already exists")
			}
			nb, err := backendFromForm(name, r)
			if err != nil {
				return err
			}
			c.Backends = append(c.Backends, nb)
			msg = "added backend " + name
		case "update":
			b := findBackend(c, name)
			if b == nil {
				return errPanel("no backend named " + strconv.Quote(name))
			}
			nb, err := backendFromForm(name, r)
			if err != nil {
				return err
			}
			// Keep what the form does not carry: the enabled state, the caps,
			// and (while the proto is unchanged) the TLS and health-check
			// settings, which a proto change would otherwise contradict.
			nb.Disabled, nb.MaxConns, nb.IdleTimeout = b.Disabled, b.MaxConns, b.IdleTimeout
			if normProto(nb.Proto) == normProto(b.Proto) {
				nb.TLS, nb.HealthCheck = b.TLS, b.HealthCheck
			}
			*b = nb
			msg = "updated backend " + name
		default:
			return errPanel("action must be add, update, remove, enable or disable")
		}
		return nil
	})
	return msg, err
}

// backendFromForm builds a backend from the panel's add/update form. It
// refuses several servers on a path (a path connects to exactly one); every
// other check is the whole-config validation by Effective() in
// panelEditConfig. A path backend gets no lb (its one server is the policy),
// whatever an older panel page still posts.
func backendFromForm(name string, r *http.Request) (Backend, error) {
	b := Backend{
		Name:      name,
		Upstreams: splitList(r.PostFormValue("upstreams")),
		Proto:     strings.ToLower(strings.TrimSpace(r.PostFormValue("proto"))),
		Host:      strings.TrimSpace(r.PostFormValue("host")),
		Listen:    strings.TrimSpace(r.PostFormValue("listen")),
		LB:        strings.TrimSpace(r.PostFormValue("lb")),
		Relay:     strings.TrimSpace(r.PostFormValue("relay")),
		Insecure:  r.PostFormValue("insecure") == "true",
	}
	// strip defaults to true unless explicitly "false".
	b.Strip = ptr(r.PostFormValue("strip") != "false")
	if normProto(b.Proto) != "udp" {
		b.LB = ""
		if err := checkOneServer(&b); err != nil {
			return Backend{}, errPanel(err.Error())
		}
	}
	return b, nil
}

func (s *Server) panelHost(w http.ResponseWriter, r *http.Request, st *state) {
	user, ok := s.controlPreamble(w, r, st)
	if !ok {
		return
	}
	host := normHost(r.PostFormValue("host"))
	action := r.PostFormValue("action")
	if host == "" {
		writeJSONError(w, http.StatusBadRequest, "host is required")
		return
	}
	s.log.Info("panel host edit", "user", user, "host", host, "action", action, "client", clientIP(r))
	var msg string
	err := s.panelEditConfig(func(c *Config) error {
		// Normalize the stored list the way applyDefaults does, then act.
		cur := map[string]bool{}
		for _, h := range append([]string{c.CDNHost}, c.CDNHosts...) {
			if h = normHost(h); h != "" {
				cur[h] = true
			}
		}
		switch action {
		case "add":
			if cur[host] {
				return errPanel("host " + strconv.Quote(host) + " is already configured")
			}
			// Rebuild from the normalized union so a config still using the v1
			// singular cdn_host is migrated, not dropped (loadRaw does not merge
			// it; only Effective's throwaway copy does).
			var all []string
			for _, h := range append([]string{c.CDNHost}, c.CDNHosts...) {
				if n := normHost(h); n != "" {
					all = append(all, n)
				}
			}
			c.CDNHost, c.CDNHosts = "", append(all, host)
			msg = "added domain " + host
		case "remove":
			if !cur[host] {
				return errPanel("host " + strconv.Quote(host) + " is not configured")
			}
			var kept []string
			for _, h := range append([]string{c.CDNHost}, c.CDNHosts...) {
				if normHost(h) != host && strings.TrimSpace(h) != "" {
					kept = append(kept, h)
				}
			}
			c.CDNHost, c.CDNHosts = "", kept
			msg = "removed domain " + host
		default:
			return errPanel("action must be add or remove")
		}
		return nil
	})
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, errString(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": msg})
}

// panelEditConfig applies mutate to the raw config file under the CLI's lock,
// validates the whole config, saves it atomically and reloads live. A write
// failure (e.g. a read-only /etc under the sandbox) surfaces as the error.
func (s *Server) panelEditConfig(mutate func(*Config) error) error {
	err := withConfigLock(s.cfgPath, func() error {
		raw, err := loadRaw(s.cfgPath)
		if err != nil {
			return err
		}
		if err := mutate(raw); err != nil {
			return err
		}
		if _, err := raw.Effective(); err != nil {
			return errPanel("change rejected: " + errString(err))
		}
		return saveRaw(s.cfgPath, raw)
	})
	if err != nil {
		return err
	}
	return s.Reload()
}

// ---- sessions + CSRF --------------------------------------------------------

var b64 = base64.RawURLEncoding

// newSession returns a signed cookie value binding user until the TTL expires.
// Layout: nonce "." expiryUnix "." base64url(user) "." base64url(hmac).
func newSession(key []byte, user string, ttl time.Duration) (value string, expiry time.Time) {
	expiry = time.Now().Add(ttl)
	nonce := randToken(16)
	exp := strconv.FormatInt(expiry.Unix(), 10)
	mac := sessionMAC(key, user, nonce, exp)
	return nonce + "." + exp + "." + b64.EncodeToString([]byte(user)) + "." + mac, expiry
}

func verifySession(key []byte, value string) (user, nonce string, ok bool) {
	parts := strings.Split(value, ".")
	if len(parts) != 4 {
		return "", "", false
	}
	nonce, exp, userB64, mac := parts[0], parts[1], parts[2], parts[3]
	ub, err := b64.DecodeString(userB64)
	if err != nil {
		return "", "", false
	}
	user = string(ub)
	want := sessionMAC(key, user, nonce, exp)
	if subtle.ConstantTimeCompare([]byte(mac), []byte(want)) != 1 {
		return "", "", false
	}
	n, err := strconv.ParseInt(exp, 10, 64)
	if err != nil || time.Now().Unix() >= n {
		return "", "", false
	}
	return user, nonce, true
}

func sessionMAC(key []byte, user, nonce, exp string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(user))
	m.Write([]byte{0})
	m.Write([]byte(nonce))
	m.Write([]byte{0})
	m.Write([]byte(exp))
	return b64.EncodeToString(m.Sum(nil))
}

// csrfToken is derived from the session nonce, so it is stable for the life of
// a session and cannot be forged without the signing key.
func (s *Server) csrfToken(nonce string) string {
	m := hmac.New(sha256.New, s.panel.key)
	m.Write([]byte("csrf"))
	m.Write([]byte{0})
	m.Write([]byte(nonce))
	return hex.EncodeToString(m.Sum(nil))
}

func (s *Server) checkCSRF(r *http.Request, nonce string) bool {
	want := s.csrfToken(nonce)
	got := r.Header.Get("X-CSRF-Token")
	if got == "" {
		got = r.PostFormValue("csrf")
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func randToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// rand.Read never fails on Linux; if it somehow does, a non-constant
		// fallback would be worse than refusing, so panic to fail closed.
		panic("ayana-cdn: crypto/rand unavailable: " + err.Error())
	}
	return b64.EncodeToString(b)
}

// ---- JSON helpers -----------------------------------------------------------

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeJSONError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{"ok": false, "error": msg})
}

// writePanelJSON writes a panel API response, gzip-compressed when the browser
// accepts it. The panel polls every couple of seconds, often over mobile data;
// status and IP-log JSON shrink 10-20x. Compression is safe here: these bodies
// carry no secrets (the session lives in an HttpOnly cookie and the CSRF token
// only in the dashboard HTML), so there is nothing for a BREACH-style length
// oracle to recover.
func writePanelJSON(w http.ResponseWriter, r *http.Request, code int, v any, indent bool) {
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Add("Vary", "Accept-Encoding")
	var out io.Writer = w
	var zw *gzip.Writer
	if acceptsGzip(r) {
		h.Set("Content-Encoding", "gzip")
		zw = gzipWriters.Get().(*gzip.Writer)
		zw.Reset(w)
		out = zw
	}
	w.WriteHeader(code)
	enc := json.NewEncoder(out)
	if indent {
		enc.SetIndent("", "  ")
	}
	_ = enc.Encode(v)
	if zw != nil {
		_ = zw.Close()
		zw.Reset(io.Discard) // drop the reference to the response writer before pooling
		gzipWriters.Put(zw)
	}
}

// BestSpeed: these are small JSON bodies; the CPU-cheapest level already gets
// most of the size win.
var gzipWriters = sync.Pool{New: func() any {
	zw, _ := gzip.NewWriterLevel(io.Discard, gzip.BestSpeed)
	return zw
}}

// acceptsGzip reports whether Accept-Encoding lists gzip without q=0.
func acceptsGzip(r *http.Request) bool {
	for _, part := range strings.Split(r.Header.Get("Accept-Encoding"), ",") {
		enc, params, _ := strings.Cut(part, ";")
		if !strings.EqualFold(strings.TrimSpace(enc), "gzip") {
			continue
		}
		for _, p := range strings.Split(params, ";") {
			if k, v, ok := strings.Cut(strings.TrimSpace(p), "="); ok && strings.EqualFold(k, "q") {
				if q, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil && q <= 0 {
					return false
				}
			}
		}
		return true
	}
	return false
}

// ---- login throttle ---------------------------------------------------------

// loginThrottle locks out an IP (grouped like the connection limiter) after
// repeated failed logins, with exponential backoff. It is memory-bounded by a
// sweep of stale entries.
type loginThrottle struct {
	mu sync.Mutex
	m  map[string]*attemptRec
}

type attemptRec struct {
	fails int
	until time.Time
	last  time.Time
}

const (
	loginFailGrace = 5                // failures allowed before lockouts begin
	loginBaseLock  = 5 * time.Second  // first lockout
	loginMaxLock   = 15 * time.Minute // cap
)

func newLoginThrottle() *loginThrottle { return &loginThrottle{m: map[string]*attemptRec{}} }

func (t *loginThrottle) locked(key string, now time.Time) (time.Duration, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	e := t.m[key]
	if e == nil || now.After(e.until) {
		return 0, false
	}
	return e.until.Sub(now), true
}

func (t *loginThrottle) fail(key string, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	e := t.m[key]
	if e == nil {
		e = &attemptRec{}
		t.m[key] = e
	}
	e.fails++
	e.last = now
	if e.fails > loginFailGrace {
		shift := e.fails - loginFailGrace - 1
		if shift > 12 {
			shift = 12
		}
		lock := loginBaseLock << shift
		if lock > loginMaxLock || lock <= 0 {
			lock = loginMaxLock
		}
		e.until = now.Add(lock)
	}
}

func (t *loginThrottle) reset(key string) {
	t.mu.Lock()
	delete(t.m, key)
	t.mu.Unlock()
}

// sweep drops entries that are no longer locked and have been idle a while.
func (t *loginThrottle) sweep(now time.Time) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := 0
	for k, e := range t.m {
		if now.After(e.until) && now.Sub(e.last) > time.Hour {
			delete(t.m, k)
			n++
		}
	}
	return n
}

func (t *loginThrottle) size() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.m)
}
