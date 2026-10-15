package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	testPanelPath = "/__ayana_testprefix"
	testPanelUser = "admin"
	testPanelPass = "correct horse battery staple"
)

func testPanelHash(t *testing.T) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(testPanelPass), bcrypt.MinCost) // MinCost: fast tests
	if err != nil {
		t.Fatal(err)
	}
	return string(h)
}

func panelEdge(t *testing.T, control bool, backends ...Backend) *edge {
	t.Helper()
	cfg := newEdgeConfig(t, backends...)
	cfg.Panel = &PanelConfig{
		Enabled:      true,
		Path:         testPanelPath,
		Username:     testPanelUser,
		PasswordHash: testPanelHash(t),
		SessionKey:   base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")),
		AllowControl: control,
	}
	return startEdge(t, cfg)
}

// panelClient returns an HTTP client whose TLS transport always dials the edge
// (ignoring the hostname in the URL) and that keeps cookies but does not follow
// redirects, so tests can inspect them.
func panelClient(t *testing.T, e *edge) *http.Client {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	tr := &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialTLS(e.addr, "cdn.example")
		},
	}
	return &http.Client{
		Transport:     tr,
		Jar:           jar,
		Timeout:       10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func panelURL(path string) string { return "https://cdn.example" + testPanelPath + path }

func login(t *testing.T, c *http.Client, user, pass string) *http.Response {
	t.Helper()
	form := url.Values{"username": {user}, "password": {pass}}
	resp, err := c.PostForm(panelURL("/login"), form)
	if err != nil {
		t.Fatalf("login post: %v", err)
	}
	return resp
}

// csrfFor extracts the session nonce from the client's cookie and derives the
// matching CSRF token the way the server does.
func csrfFor(t *testing.T, e *edge, c *http.Client) string {
	t.Helper()
	u, _ := url.Parse(panelURL("/"))
	for _, ck := range c.Jar.Cookies(u) {
		if ck.Name == panelCookie {
			nonce := strings.SplitN(ck.Value, ".", 2)[0]
			return e.s.csrfToken(nonce)
		}
	}
	t.Fatal("no session cookie found")
	return ""
}

func TestPanelRequiresAuth(t *testing.T) {
	e := panelEdge(t, false)
	c := panelClient(t, e)

	resp, err := c.Get(panelURL("/"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("dashboard without auth: want 303 redirect, got %d", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); !strings.HasSuffix(loc, "/login") {
		t.Fatalf("redirect should point at login, got %q", loc)
	}

	resp, err = c.Get(panelURL("/api/status"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status API without auth: want 401, got %d", resp.StatusCode)
	}
}

func TestPanelLoginFlow(t *testing.T) {
	e := panelEdge(t, false)
	c := panelClient(t, e)

	// Wrong password is rejected and sets no cookie.
	resp := login(t, c, testPanelUser, "wrong")
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad login: want 401, got %d", resp.StatusCode)
	}
	u, _ := url.Parse(panelURL("/"))
	if len(c.Jar.Cookies(u)) != 0 {
		t.Fatal("a failed login must not set a session cookie")
	}

	// Correct credentials set a Secure, HttpOnly, path-scoped cookie.
	resp = login(t, c, testPanelUser, testPanelPass)
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("good login: want 303, got %d", resp.StatusCode)
	}
	var sess *http.Cookie
	for _, ck := range resp.Cookies() {
		if ck.Name == panelCookie {
			sess = ck
		}
	}
	if sess == nil {
		t.Fatal("no session cookie set on login")
	}
	if !sess.HttpOnly || !sess.Secure || sess.SameSite != http.SameSiteStrictMode || sess.Path != testPanelPath {
		t.Fatalf("session cookie flags: HttpOnly=%v Secure=%v SameSite=%v Path=%q", sess.HttpOnly, sess.Secure, sess.SameSite, sess.Path)
	}

	// The session now authorizes the status API.
	resp, err := c.Get(panelURL("/api/status"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status with session: want 200, got %d", resp.StatusCode)
	}
	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("status json: %v", err)
	}
	if doc["version"] != version {
		t.Fatalf("status body missing version: %v", doc["version"])
	}
}

func TestPanelCSRFProtectsActions(t *testing.T) {
	e := panelEdge(t, true)
	c := panelClient(t, e)
	login(t, c, testPanelUser, testPanelPass).Body.Close()

	// Without a CSRF token the action is refused even with a valid session.
	resp, err := c.PostForm(panelURL("/api/reload"), url.Values{})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("reload without csrf: want 403, got %d", resp.StatusCode)
	}

	// With the right token it succeeds.
	req, _ := http.NewRequest(http.MethodPost, panelURL("/api/reload"), nil)
	req.Header.Set("X-CSRF-Token", csrfFor(t, e, c))
	resp, err = c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("reload with csrf: want 200, got %d", resp.StatusCode)
	}
}

func TestPanelControlDisabledByDefault(t *testing.T) {
	e := panelEdge(t, false) // allow_control = false
	c := panelClient(t, e)
	login(t, c, testPanelUser, testPanelPass).Body.Close()

	req, _ := http.NewRequest(http.MethodPost, panelURL("/api/reload"), nil)
	req.Header.Set("X-CSRF-Token", csrfFor(t, e, c))
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("control action when allow_control=false: want 403, got %d", resp.StatusCode)
	}
}

func TestPanelBackendToggle(t *testing.T) {
	e := panelEdge(t, true, wsBackend("n1", "127.0.0.1:9"))
	c := panelClient(t, e)
	login(t, c, testPanelUser, testPanelPass).Body.Close()

	form := url.Values{"name": {"n1"}, "action": {"disable"}, "csrf": {csrfFor(t, e, c)}}
	resp, err := c.PostForm(panelURL("/api/backend"), form)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("disable backend: want 200, got %d", resp.StatusCode)
	}
	// The change is persisted and applied: status reports it disabled.
	resp, err = c.Get(panelURL("/api/status"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var doc statusDoc
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, b := range doc.Backends {
		if b.Name == "n1" {
			found = true
			if !b.Disabled {
				t.Fatal("backend n1 should be disabled after toggle")
			}
		}
	}
	if !found {
		t.Fatal("backend n1 missing from status")
	}
}

func TestPanelSecurityHeaders(t *testing.T) {
	e := panelEdge(t, false)
	c := panelClient(t, e)
	resp, err := c.Get(panelURL("/login"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	h := resp.Header
	if !strings.Contains(h.Get("Content-Security-Policy"), "default-src 'none'") {
		t.Fatalf("missing/weak CSP: %q", h.Get("Content-Security-Policy"))
	}
	if h.Get("X-Frame-Options") != "DENY" {
		t.Fatalf("X-Frame-Options: %q", h.Get("X-Frame-Options"))
	}
	if h.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("X-Content-Type-Options: %q", h.Get("X-Content-Type-Options"))
	}
	if !strings.Contains(h.Get("Cache-Control"), "no-store") {
		t.Fatalf("Cache-Control: %q", h.Get("Cache-Control"))
	}
}

func TestPanelPathBoundaryAndSecrecy(t *testing.T) {
	// A ws backend plus the panel. The panel prefix must be matched exactly on
	// the path boundary; a look-alike path must fall through to routing (404),
	// never reveal the login page.
	e := panelEdge(t, false, wsBackend("n1", "127.0.0.1:9"))
	c := panelClient(t, e)

	resp, err := c.Get("https://cdn.example" + testPanelPath + "extra") // no "/" boundary
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("look-alike path should 404, got %d", resp.StatusCode)
	}

	// /healthz is still the edge's own health endpoint, not shadowed.
	resp, err = c.Get("https://cdn.example/healthz")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/healthz: want 200, got %d", resp.StatusCode)
	}
}

func TestPanelDisabledPathFallsThrough(t *testing.T) {
	cfg := newEdgeConfig(t)
	cfg.Panel = &PanelConfig{ // present but disabled
		Enabled:      false,
		Path:         testPanelPath,
		Username:     testPanelUser,
		PasswordHash: testPanelHash(t),
	}
	e := startEdge(t, cfg)
	c := panelClient(t, e)
	resp, err := c.Get(panelURL("/login"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("disabled panel path should 404, got %d", resp.StatusCode)
	}
}

func TestPanelLoginThrottle(t *testing.T) {
	e := panelEdge(t, false)
	c := panelClient(t, e)
	var got429 bool
	for i := 0; i < loginFailGrace+3; i++ {
		resp := login(t, c, testPanelUser, "wrong")
		resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests {
			got429 = true
			break
		}
	}
	if !got429 {
		t.Fatal("repeated failed logins should eventually be throttled (429)")
	}
	// Even a correct password is refused while locked out.
	resp := login(t, c, testPanelUser, testPanelPass)
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("correct login while locked out: want 429, got %d", resp.StatusCode)
	}
}

// postCtl posts a control action with the session's CSRF token and returns the
// decoded JSON result.
func postCtl(t *testing.T, e *edge, c *http.Client, path string, form url.Values) (int, map[string]any) {
	t.Helper()
	form.Set("csrf", csrfFor(t, e, c))
	resp, err := c.PostForm(panelURL(path), form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var j map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&j)
	return resp.StatusCode, j
}

func statusDocOf(t *testing.T, c *http.Client) statusDoc {
	t.Helper()
	resp, err := c.Get(panelURL("/api/status"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var d statusDoc
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestPanelDomainManagement(t *testing.T) {
	e := panelEdge(t, true)
	c := panelClient(t, e)
	login(t, c, testPanelUser, testPanelPass).Body.Close()

	code, j := postCtl(t, e, c, "/api/host", url.Values{"action": {"add"}, "host": {"extra.example.com"}})
	if code != http.StatusOK || j["ok"] != true {
		t.Fatalf("add domain: %d %v", code, j)
	}
	if !contains(statusDocOf(t, c).Hosts, "extra.example.com") {
		t.Fatal("new domain not in cdn_hosts after add")
	}
	// Remove it again.
	code, j = postCtl(t, e, c, "/api/host", url.Values{"action": {"remove"}, "host": {"extra.example.com"}})
	if code != http.StatusOK || j["ok"] != true {
		t.Fatalf("remove domain: %d %v", code, j)
	}
	if contains(statusDocOf(t, c).Hosts, "extra.example.com") {
		t.Fatal("domain still present after remove")
	}
}

func TestPanelBackendManagement(t *testing.T) {
	e := panelEdge(t, true)
	c := panelClient(t, e)
	login(t, c, testPanelUser, testPanelPass).Body.Close()

	// Add a local (loopback) HTTP backend — the "support my 127 service" case.
	code, j := postCtl(t, e, c, "/api/backend", url.Values{
		"action": {"add"}, "name": {"local"}, "proto": {"http"},
		"upstreams": {"127.0.0.1:8080"}, "strip": {"true"},
	})
	if code != http.StatusOK || j["ok"] != true {
		t.Fatalf("add backend: %d %v", code, j)
	}
	findLocal := func() *backendStatus {
		for _, b := range statusDocOf(t, c).Backends {
			if b.Name == "local" {
				return &b
			}
		}
		return nil
	}
	b := findLocal()
	if b == nil || b.Proto != "http" {
		t.Fatalf("backend not added as http: %+v", b)
	}
	// Update it (switch upstream) and confirm the change applied live.
	code, j = postCtl(t, e, c, "/api/backend", url.Values{
		"action": {"update"}, "name": {"local"}, "proto": {"http"},
		"upstreams": {"127.0.0.1:9090"}, "strip": {"false"},
	})
	if code != http.StatusOK || j["ok"] != true {
		t.Fatalf("update backend: %d %v", code, j)
	}
	if b = findLocal(); b == nil || b.Strip {
		t.Fatalf("update did not apply (strip still true): %+v", b)
	}
	// Remove it.
	code, _ = postCtl(t, e, c, "/api/backend", url.Values{"action": {"remove"}, "name": {"local"}})
	if code != http.StatusOK {
		t.Fatalf("remove backend: %d", code)
	}
	if findLocal() != nil {
		t.Fatal("backend still present after remove")
	}
}

func TestPanelAddBackendRejectsBadConfig(t *testing.T) {
	e := panelEdge(t, true)
	c := panelClient(t, e)
	login(t, c, testPanelUser, testPanelPass).Body.Close()
	// http proto with tls-implying nothing but no upstreams -> whole-config validation rejects it.
	code, j := postCtl(t, e, c, "/api/backend", url.Values{
		"action": {"add"}, "name": {"bad"}, "proto": {"http"}, "upstreams": {""},
	})
	if code == http.StatusOK || j["ok"] == true {
		t.Fatalf("expected rejection of a backend with no upstreams, got %d %v", code, j)
	}
}

func TestPanelControlHostBlockedWithoutControl(t *testing.T) {
	e := panelEdge(t, false) // allow_control = false
	c := panelClient(t, e)
	login(t, c, testPanelUser, testPanelPass).Body.Close()
	code, _ := postCtl(t, e, c, "/api/host", url.Values{"action": {"add"}, "host": {"x.example.com"}})
	if code != http.StatusForbidden {
		t.Fatalf("host add without allow_control: want 403, got %d", code)
	}
}

// ---- unit tests (no server) -------------------------------------------------

func TestSessionRoundTrip(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	value, exp := newSession(key, "alice", time.Hour)
	if !exp.After(time.Now()) {
		t.Fatal("expiry should be in the future")
	}
	user, nonce, ok := verifySession(key, value)
	if !ok || user != "alice" || nonce == "" {
		t.Fatalf("verify failed: ok=%v user=%q", ok, user)
	}
	// Tamper with the MAC.
	if _, _, ok := verifySession(key, value+"x"); ok {
		t.Fatal("tampered cookie must not verify")
	}
	// Different key must not verify.
	if _, _, ok := verifySession([]byte("ffffffffffffffffffffffffffffffff"), value); ok {
		t.Fatal("cookie signed with another key must not verify")
	}
	// Expired session.
	expired, _ := newSession(key, "alice", -time.Minute)
	if _, _, ok := verifySession(key, expired); ok {
		t.Fatal("expired cookie must not verify")
	}
}

func TestLoginThrottleBackoff(t *testing.T) {
	th := newLoginThrottle()
	now := time.Now()
	if _, locked := th.locked("k", now); locked {
		t.Fatal("fresh key must not be locked")
	}
	for i := 0; i <= loginFailGrace; i++ {
		th.fail("k", now)
	}
	if _, locked := th.locked("k", now); !locked {
		t.Fatal("key should be locked after exceeding the grace count")
	}
	th.reset("k")
	if _, locked := th.locked("k", now); locked {
		t.Fatal("reset should clear the lock")
	}
}

func TestPanelConfigValidation(t *testing.T) {
	good := func() *PanelConfig {
		return &PanelConfig{
			Enabled:      true,
			Path:         "/__ayana_abcdef",
			Username:     "admin",
			PasswordHash: "$2a$10$abcdefghijklmnopqrstuuWmSPjf1aAbcdefghijklmnopqrstuvw", // shape only
			SessionKey:   base64.StdEncoding.EncodeToString(make([]byte, 32)),
		}
	}
	base := func(p *PanelConfig) *Config {
		return &Config{
			Listen: ":443", CDNHosts: []string{"cdn.example.com"},
			TLS: TLSConfig{Mode: "acme", Email: "a@b.com"}, Panel: p,
			Backends: []Backend{{Name: "n1", Upstream: "n1.example.com:443"}},
		}
	}
	if _, err := base(good()).Effective(); err != nil {
		t.Fatalf("valid panel config rejected: %v", err)
	}

	cases := map[string]func(*PanelConfig){
		"missing path":      func(p *PanelConfig) { p.Path = "" },
		"reserved path":     func(p *PanelConfig) { p.Path = "/healthz" },
		"bad path chars":    func(p *PanelConfig) { p.Path = "/has space" },
		"missing user":      func(p *PanelConfig) { p.Username = "" },
		"missing hash":      func(p *PanelConfig) { p.PasswordHash = "" },
		"non-bcrypt hash":   func(p *PanelConfig) { p.PasswordHash = "plaintext" },
		"short session key": func(p *PanelConfig) { p.SessionKey = base64.StdEncoding.EncodeToString(make([]byte, 8)) },
	}
	for name, mut := range cases {
		p := good()
		mut(p)
		if _, err := base(p).Effective(); err == nil {
			t.Fatalf("%s: expected validation error, got none", name)
		}
	}

	// A disabled panel with holes must not fail validation.
	p := &PanelConfig{Enabled: false, Path: "", Username: ""}
	if _, err := base(p).Effective(); err != nil {
		t.Fatalf("disabled panel should not be validated strictly: %v", err)
	}
}

func TestIsValidPanelPath(t *testing.T) {
	ok := []string{"/__ayana_abc", "/panel/x", "/a.b-c_d~e"}
	bad := []string{"panel", "/has space", "/q?x", "/a#b", "/pct%2f"}
	for _, s := range ok {
		if !isValidPanelPath(s) {
			t.Errorf("%q should be valid", s)
		}
	}
	for _, s := range bad {
		if isValidPanelPath(s) {
			t.Errorf("%q should be invalid", s)
		}
	}
}

// The panel refuses several servers on one path, and an older config that
// already lists them shows the ignored ones and stays editable.
func TestPanelOneServerPerPath(t *testing.T) {
	legacy := wsBackend("legacy", "127.0.0.1:9", "127.0.0.1:10")
	legacy.MaxConns, legacy.IdleTimeout = 5000, Duration(5*time.Minute)
	legacy.TLS, legacy.HealthCheck = ptr(false), &HealthCheck{Type: "off"}
	e := panelEdge(t, true, legacy)
	c := panelClient(t, e)
	login(t, c, testPanelUser, testPanelPass).Body.Close()
	backend := func(name string) *backendStatus {
		for _, b := range statusDocOf(t, c).Backends {
			if b.Name == name {
				return &b
			}
		}
		return nil
	}
	if b := backend("legacy"); b == nil || len(b.Upstreams) != 1 || len(b.IgnoredUpstreams) != 1 || b.IgnoredUpstreams[0] != "127.0.0.1:10" {
		t.Fatalf("legacy backend status: %+v", b)
	}
	post := func(v url.Values) (int, map[string]any) { return postCtl(t, e, c, "/api/backend", v) }

	code, j := post(url.Values{"action": {"add"}, "name": {"two"}, "proto": {"wss"}, "upstreams": {"127.0.0.1:1, 127.0.0.1:2"}})
	if code == http.StatusOK || !strings.Contains(fmt.Sprint(j["error"]), "its own path") || backend("two") != nil {
		t.Fatalf("two servers on one path: %d %v", code, j)
	}
	code, j = post(url.Values{"action": {"add"}, "name": {"dup"}, "proto": {"wss"}, "upstreams": {"127.0.0.1:1, 127.0.0.1:1"}, "lb": {"least_conn"}})
	if code != http.StatusOK {
		t.Fatalf("the same server twice is one server: %d %v", code, j)
	}
	if b := backend("dup"); b == nil || b.LB != "path" {
		t.Fatalf("dup: %+v", b)
	}
	code, j = post(url.Values{"action": {"add"}, "name": {"dns"}, "proto": {"udp"}, "listen": {"127.0.0.1:0"},
		"upstreams": {"127.0.0.1:53, 127.0.0.2:53"}, "lb": {"hash"}})
	if code != http.StatusOK {
		t.Fatalf("a udp backend may list several upstreams: %d %v", code, j)
	}

	// Unrelated changes still work on the older config.
	if code, j = post(url.Values{"action": {"disable"}, "name": {"legacy"}}); code != http.StatusOK {
		t.Fatalf("disable legacy: %d %v", code, j)
	}
	if code, j = postCtl(t, e, c, "/api/host", url.Values{"action": {"add"}, "host": {"two.example.com"}}); code != http.StatusOK {
		t.Fatalf("domain add on an older config: %d %v", code, j)
	}
	raw, err := loadRaw(e.path)
	if err != nil {
		t.Fatal(err)
	}
	if b := findBackend(raw, "legacy"); len(b.Upstreams) != 2 {
		t.Fatalf("an unrelated save dropped the file's servers: %+v", b)
	}
	if b := findBackend(raw, "dup"); b.LB != "" {
		t.Fatalf("lb %q saved for a path backend", b.LB)
	}

	// Saving the older backend as it is (both servers) is refused; one is fine.
	code, j = post(url.Values{"action": {"update"}, "name": {"legacy"}, "proto": {"ws"}, "upstreams": {"127.0.0.1:9, 127.0.0.1:10"}})
	if code == http.StatusOK || !strings.Contains(fmt.Sprint(j["error"]), "its own path") {
		t.Fatalf("update with two servers: %d %v", code, j)
	}
	code, j = post(url.Values{"action": {"update"}, "name": {"legacy"}, "proto": {"ws"}, "upstreams": {"127.0.0.1:9"}, "lb": {"least_conn"}})
	if code != http.StatusOK {
		t.Fatalf("update with one server: %d %v", code, j)
	}
	if b := backend("legacy"); b == nil || len(b.IgnoredUpstreams) != 0 || !b.Disabled {
		t.Fatalf("legacy after the fix: %+v", b)
	}
	// The edit keeps what the form does not carry.
	raw, err = loadRaw(e.path)
	if err != nil {
		t.Fatal(err)
	}
	if b := findBackend(raw, "legacy"); b.MaxConns != 5000 || b.IdleTimeout.D() != 5*time.Minute ||
		b.TLS == nil || *b.TLS || b.HealthCheck == nil || b.HealthCheck.Type != "off" || b.LB != "" {
		t.Fatalf("the panel edit dropped settings: %+v", b)
	}
}
