package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func TestV1ConfigLoadsUnchanged(t *testing.T) {
	cfg, err := LoadConfig("testdata/v1-config.json")
	if err != nil {
		t.Fatalf("v1 config must load: %v", err)
	}
	if got := cfg.CDNHosts; len(got) != 1 || got[0] != "cdn.example.com" {
		t.Fatalf("cdn_host not merged into cdn_hosts: %v", got)
	}
	if len(cfg.Backends) != 10 {
		t.Fatalf("want 10 backends, got %d", len(cfg.Backends))
	}
	b := cfg.Backends[9]
	if b.Name != "native10" || len(b.Upstreams) != 1 || b.Upstreams[0] != "native10.example.com:443" || b.Upstream != "" {
		t.Fatalf("upstream not merged: %+v", b)
	}
	if !b.useTLS() || !b.strip() || b.Proto != "wss" || b.Relay != "upgrade" || b.LB != "path" {
		t.Fatalf("unexpected backend defaults: %+v", b)
	}
	if b.HealthCheck.Type != "tls" || b.HealthCheck.Interval.D() != 10*time.Second {
		t.Fatalf("health check defaults: %+v", b.HealthCheck)
	}
	if cfg.AdminListen != defaultAdminListen || cfg.Timeouts.Drain.D() != 4*time.Hour {
		t.Fatalf("global defaults missing: admin=%q drain=%v", cfg.AdminListen, cfg.Timeouts.Drain)
	}
	// Rate limiting and per-IP caps are off by default.
	if cfg.Limits.ConnRatePerIP != -1 || cfg.Limits.MaxConnsPerIP != -1 || cfg.Limits.MaxUDPSessionsPerIP != -1 {
		t.Fatalf("per-IP limits should default to off (-1): rate=%v conns=%d udp=%d",
			cfg.Limits.ConnRatePerIP, cfg.Limits.MaxConnsPerIP, cfg.Limits.MaxUDPSessionsPerIP)
	}
	if cfg.TLS.MinVersion != "1.2" || !*cfg.Log.Access {
		t.Fatalf("tls/log defaults: %+v %+v", cfg.TLS, cfg.Log)
	}
}

func TestEffectiveDoesNotModifyRaw(t *testing.T) {
	raw, err := loadRaw("testdata/v1-config.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Effective(); err != nil {
		t.Fatal(err)
	}
	if raw.CDNHost != "cdn.example.com" || raw.Timeouts != nil || raw.Backends[0].Upstream == "" || raw.Backends[0].HealthCheck != nil {
		t.Fatal("Effective must work on a copy; the raw config was modified")
	}
}

func baseRaw() *Config {
	return &Config{
		Listen:   ":443",
		CDNHosts: []string{"cdn.example.com"},
		TLS:      TLSConfig{Mode: "acme", Email: "a@example.com"},
		Backends: []Backend{{Name: "n1", Upstream: "n1.example.com:443"}},
	}
}

func TestValidation(t *testing.T) {
	cases := []struct {
		name string
		mod  func(c *Config)
		want string // substring of the error; "" = valid
	}{
		{"valid", func(c *Config) {}, ""},
		{"listen port 0 allowed", func(c *Config) { c.Listen = "127.0.0.1:0" }, ""},
		{"bad listen", func(c *Config) { c.Listen = "443" }, "listen"},
		{"acme without hosts", func(c *Config) { c.CDNHosts = nil }, "cdn_hosts"},
		{"bad host", func(c *Config) { c.CDNHosts = []string{"no_dots"} }, "not a valid hostname"},
		{"files without cert", func(c *Config) { c.TLS = TLSConfig{Mode: "files"} }, "cert_file"},
		{"bad tls mode", func(c *Config) { c.TLS.Mode = "self" }, "tls.mode"},
		{"bad min version", func(c *Config) { c.TLS.MinVersion = "1.4" }, "min_version"},
		{"strict sni no hosts", func(c *Config) {
			c.TLS = TLSConfig{Mode: "files", CertFile: "a", KeyFile: "b"}
			c.CDNHosts = nil
			c.StrictSNI = true
		}, "strict_sni"},
		{"bad trusted cidr", func(c *Config) { c.ProxyProtocolTrusted = []string{"10.0.0.0/33"} }, "proxy_protocol_trusted"},
		{"negative timeout", func(c *Config) { c.Timeouts = &Timeouts{Drain: Duration(-time.Second)} }, "timeouts.drain"},
		{"bad log level", func(c *Config) { c.Log = &LogConfig{Level: "loud"} }, "log.level"},
		{"small header limit", func(c *Config) { c.Limits = &Limits{MaxHeaderBytes: 100} }, "max_header_bytes"},
		{"bad rate", func(c *Config) { c.Limits = &Limits{ConnRatePerIP: -5} }, "conn_rate_per_ip"},
		{"bad name", func(c *Config) { c.Backends[0].Name = "a/b" }, "name must be"},
		{"reserved name", func(c *Config) { c.Backends[0].Name = "healthz" }, "reserved"},
		{"duplicate", func(c *Config) { c.Backends = append(c.Backends, c.Backends[0]) }, "duplicate"},
		{"no upstream", func(c *Config) { c.Backends[0].Upstream = "" }, "at least one upstream"},
		{"upstream no port", func(c *Config) { c.Backends[0].Upstream = "n1.example.com" }, "host:port"},
		{"upstream port 0", func(c *Config) { c.Backends[0].Upstream = "n1.example.com:0" }, "invalid port"},
		{"wss with tls false", func(c *Config) { c.Backends[0].TLS = ptr(false) }, `use "ws" for plaintext`},
		{"ws with tls true", func(c *Config) { c.Backends[0].Proto = "ws"; c.Backends[0].TLS = ptr(true) }, `use "wss"`},
		{"bad proto", func(c *Config) { c.Backends[0].Proto = "quic" }, "proto must be"},
		{"bad lb", func(c *Config) { c.Backends[0].LB = "random" }, "lb must be"},
		{"lb path", func(c *Config) { c.Backends[0].LB = "path" }, ""},
		{"older lb least_conn still loads", func(c *Config) { c.Backends[0].LB = "least_conn" }, ""},
		{"older lb round_robin still loads", func(c *Config) { c.Backends[0].LB = "round_robin" }, ""},
		{"older lb first still loads", func(c *Config) { c.Backends[0].LB = "first" }, ""},
		{"several servers on a path still load", func(c *Config) { c.Backends[0].Upstreams = []string{"n1b.example.com:443"} }, ""},
		{"hash on a path", func(c *Config) { c.Backends[0].LB = "hash" }, "applies only to udp"},
		{"path on udp", func(c *Config) {
			c.Backends[0].Proto = "udp"
			c.Backends[0].TLS = ptr(false)
			c.Backends[0].Listen = ":36712"
			c.Backends[0].LB = "path"
		}, "applies to path backends"},
		{"udp with several upstreams", func(c *Config) {
			c.Backends[0].Proto = "udp"
			c.Backends[0].TLS = ptr(false)
			c.Backends[0].Listen = ":36712"
			c.Backends[0].Upstreams = []string{"n1b.example.com:443"}
			c.Backends[0].LB = "round_robin"
		}, ""},
		{"relay always on http", func(c *Config) { c.Backends[0].Proto = "https"; c.Backends[0].Relay = "always" }, "only applies to ws/wss"},
		{"tls check on plaintext", func(c *Config) {
			c.Backends[0].Proto = "ws"
			c.Backends[0].HealthCheck = &HealthCheck{Type: "tls"}
		}, `needs a TLS backend`},
		{"check timeout > interval", func(c *Config) {
			c.Backends[0].HealthCheck = &HealthCheck{Interval: Duration(2 * time.Second), Timeout: Duration(5 * time.Second)}
		}, "timeout must be"},
		{"check path", func(c *Config) { c.Backends[0].HealthCheck = &HealthCheck{Path: "health"} }, "path must start"},
		{"udp needs listen", func(c *Config) { c.Backends[0].Proto = "udp"; c.Backends[0].TLS = ptr(false) }, `needs "listen"`},
		{"udp valid", func(c *Config) {
			c.Backends[0].Proto = "udp"
			c.Backends[0].TLS = ptr(false)
			c.Backends[0].Listen = ":36712"
		}, ""},
		{"udp bad listen", func(c *Config) {
			c.Backends[0].Proto = "udp"
			c.Backends[0].TLS = ptr(false)
			c.Backends[0].Listen = "nope"
		}, "listen"},
		{"udp with tls", func(c *Config) {
			c.Backends[0].Proto = "udp"
			c.Backends[0].TLS = ptr(true)
			c.Backends[0].Listen = ":36712"
		}, "cannot use TLS"},
		{"udp relay always", func(c *Config) {
			c.Backends[0].Proto = "udp"
			c.Backends[0].TLS = ptr(false)
			c.Backends[0].Listen = ":36712"
			c.Backends[0].Relay = "always"
		}, `"relay" does not apply`},
		{"udp health check", func(c *Config) {
			c.Backends[0].Proto = "udp"
			c.Backends[0].TLS = ptr(false)
			c.Backends[0].Listen = ":36712"
			c.Backends[0].HealthCheck = &HealthCheck{Type: "tcp"}
		}, `must be "off" for a udp backend`},
		{"listen on non-udp", func(c *Config) { c.Backends[0].Listen = ":36712" }, "only applies to udp"},
		{"duplicate udp listen", func(c *Config) {
			c.Backends[0].Proto = "udp"
			c.Backends[0].TLS = ptr(false)
			c.Backends[0].Listen = ":36712"
			b2 := c.Backends[0]
			b2.Name = "g2"
			c.Backends = append(c.Backends, b2)
		}, "already used by backend"},
		{"udp_idle zero rejected", func(c *Config) { c.Timeouts = &Timeouts{UDPIdle: Duration(-1)} }, "udp_idle"},
		{"udp_reply off accepted", func(c *Config) { c.Timeouts = &Timeouts{UDPReply: Duration(-time.Second)} }, ""},
		{"udp_reply bad negative", func(c *Config) { c.Timeouts = &Timeouts{UDPReply: Duration(-5 * time.Second)} }, "udp_reply"},
		{"bad max_udp_sessions", func(c *Config) { c.Limits = &Limits{MaxUDPSessions: -5} }, "max_udp_sessions"},
		{"bad max_udp_packet", func(c *Config) { c.Limits = &Limits{MaxUDPPacket: 10} }, "max_udp_packet"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := baseRaw()
			tc.mod(c)
			_, err := c.Effective()
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tc.want != "" && err == nil:
				t.Fatalf("expected an error containing %q", tc.want)
			case tc.want != "" && !strings.Contains(err.Error(), tc.want):
				t.Fatalf("error %q does not contain %q", err, tc.want)
			}
		})
	}
}

func TestWarnings(t *testing.T) {
	c := baseRaw()
	c.TLS.Email = ""
	c.AdminListen = "0.0.0.0:9180"
	c.Backends[0].Insecure = true
	e, err := c.Effective()
	if err != nil {
		t.Fatal(err)
	}
	all := strings.Join(e.warnings, "\n")
	for _, want := range []string{"tls.email", "not a loopback", "insecure"} {
		if !strings.Contains(all, want) {
			t.Errorf("missing warning about %q in:\n%s", want, all)
		}
	}
}

// A path connects to one server. An older config that lists several on one
// path still loads (upgrade safety), with only the first server in the
// effective config, a warning, and the file itself left as it was.
func TestPathBackendKeepsOneServer(t *testing.T) {
	c := baseRaw()
	c.Backends[0].Upstream = ""
	c.Backends[0].Upstreams = []string{"a.example.com:443", " b.example.com:443", "a.example.com:443", "c.example.com:443"}
	c.Backends[0].LB = "first"
	c.Backends = append(c.Backends, Backend{Name: "dns", Proto: "udp", Listen: ":5353",
		Upstreams: []string{"10.0.0.1:53", "10.0.0.2:53"}, LB: "round_robin"})
	e, err := c.Effective()
	if err != nil {
		t.Fatalf("an older config with several servers on a path must still load: %v", err)
	}
	b := e.Backends[0]
	if len(b.Upstreams) != 1 || b.Upstreams[0] != "a.example.com:443" || b.LB != "path" {
		t.Fatalf("effective path backend: upstreams %v, lb %q", b.Upstreams, b.LB)
	}
	if strings.Join(b.ignoredUpstreams, ",") != "b.example.com:443,c.example.com:443" {
		t.Fatalf("ignored servers: %v", b.ignoredUpstreams)
	}
	all := strings.Join(e.warnings, "\n")
	if !strings.Contains(all, `backend "n1": path /n1/ connects to one server only: using a.example.com:443, ignoring b.example.com:443, c.example.com:443`) {
		t.Fatalf("missing warning:\n%s", all)
	}
	if u := e.Backends[1]; len(u.Upstreams) != 2 || u.LB != "round_robin" || len(u.ignoredUpstreams) != 0 || strings.Contains(all, `"dns"`) {
		t.Fatalf("a udp backend keeps every upstream and its policy: %+v\n%s", u, all)
	}
	if len(c.Backends[0].Upstreams) != 4 || c.Backends[0].LB != "first" {
		t.Fatal("Effective must not change the raw config (the file keeps what it lists)")
	}
}

func TestCheckOneServer(t *testing.T) {
	for _, tc := range []struct {
		b    Backend
		want string
	}{
		{Backend{Name: "a", Upstream: "x:1"}, ""},
		{Backend{Name: "a", Upstreams: []string{"x:1", " x:1 "}}, ""}, // the same server twice counts once
		{Backend{Name: "a", Upstreams: []string{"x:1", "y:1"}}, "give each server its own path"},
		{Backend{Name: "a", Upstream: "x:1", Upstreams: []string{"y:1"}, Proto: "HTTP"}, "connects to exactly one server, but 2"},
		{Backend{Name: "a", Upstreams: []string{"x:1", "y:1"}, Proto: " udp "}, ""},
	} {
		err := checkOneServer(&tc.b)
		if (tc.want == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), tc.want)) {
			t.Errorf("%+v: got %v, want %q", tc.b, err, tc.want)
		}
	}
}

// Every shipped example and the default config load, and none of them puts
// several servers on one path.
func TestShippedExamplesLoad(t *testing.T) {
	files, _ := filepath.Glob("../../config/examples/*.json")
	files = append(files, "../../config/config.json")
	if len(files) < 2 {
		t.Skip("config files not found")
	}
	for _, f := range files {
		raw, err := loadRaw(f)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if raw.Panel != nil && strings.Contains(raw.Panel.PasswordHash, "REPLACE") {
			h, _ := bcrypt.GenerateFromPassword([]byte("x"), bcrypt.MinCost)
			raw.Panel.PasswordHash = string(h) // the example's placeholders until `panel passwd`
			raw.Panel.SessionKey = ""
		}
		e, err := raw.Effective()
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		for _, b := range e.Backends {
			if len(b.ignoredUpstreams) > 0 {
				t.Errorf("%s: backend %q lists several servers on one path", f, b.Name)
			}
		}
	}
}

func TestDurationJSON(t *testing.T) {
	var v struct{ D Duration }
	for in, want := range map[string]time.Duration{`"1m30s"`: 90 * time.Second, `45`: 45 * time.Second, `"0s"`: 0, `1.5`: 1500 * time.Millisecond} {
		if err := json.Unmarshal([]byte(`{"D":`+in+`}`), &v); err != nil || v.D.D() != want {
			t.Errorf("%s: got %v err %v, want %v", in, v.D.D(), err, want)
		}
	}
	if err := json.Unmarshal([]byte(`{"D":"soon"}`), &v); err == nil {
		t.Error("invalid duration accepted")
	}
	out, _ := json.Marshal(struct{ D Duration }{Duration(4 * time.Hour)})
	if string(out) != `{"D":"4h0m0s"}` {
		t.Errorf("marshal: %s", out)
	}
}

func TestJSONErrorsAreLocated(t *testing.T) {
	_, err := parseRaw([]byte("{\n  \"listen\": \":443\",\n  \"backends\": [\n    {\"name\": \"a\",}\n  ]\n}"), "x.json")
	if err == nil || !strings.Contains(err.Error(), "line 4") {
		t.Fatalf("syntax error should report line 4, got %v", err)
	}
	_, err = parseRaw([]byte(`{"listen": ":443", "backendz": []}`), "x.json")
	if err == nil || !strings.Contains(err.Error(), "backendz") {
		t.Fatalf("unknown field should be named, got %v", err)
	}
	_, err = parseRaw([]byte(`{"listen": 443}`), "x.json")
	if err == nil || !strings.Contains(err.Error(), "line 1") {
		t.Fatalf("type error should be located, got %v", err)
	}
	_, err = parseRaw([]byte(`{"listen": ":443"} {"x":1}`), "x.json")
	if err == nil {
		t.Fatal("trailing data accepted")
	}
}

func TestSaveRawKeepsFileMinimal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	data, _ := os.ReadFile("testdata/v1-config.json")
	if err := os.WriteFile(path, data, 0o640); err != nil {
		t.Fatal(err)
	}
	raw, err := loadRaw(path)
	if err != nil {
		t.Fatal(err)
	}
	raw.Backends = append(raw.Backends, Backend{Name: "extra", Upstream: "x.example.com:443"})
	if err := saveRaw(path, raw); err != nil {
		t.Fatal(err)
	}
	out, _ := os.ReadFile(path)
	for _, unwanted := range []string{"timeouts", "health_check", `"lb"`, "limits", "admin_listen"} {
		if strings.Contains(string(out), unwanted) {
			t.Errorf("saved file contains injected default %q", unwanted)
		}
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o640 {
		t.Errorf("file mode changed to %v", fi.Mode().Perm())
	}
	if _, err := os.Stat(path + ".bak"); err != nil {
		t.Errorf("no backup written: %v", err)
	}
	if _, err := LoadConfig(path); err != nil {
		t.Fatalf("saved config does not load: %v", err)
	}
}

// A config edit made as root (the CLI) leaves the file to the owner of the
// config directory (the service user), so a 0640 config stays readable by
// the service and its panel.
func TestSaveRawAsRootKeepsServiceOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	dir := filepath.Join(t.TempDir(), "etc")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	const uid, gid = 4242, 4343
	if err := os.Chown(dir, uid, gid); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.json")
	data, _ := os.ReadFile("testdata/v1-config.json")
	if err := os.WriteFile(path, data, 0o640); err != nil { // root-owned, like after an older CLI edit
		t.Fatal(err)
	}
	raw, err := loadRaw(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := saveRaw(path, raw); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{path, path + ".bak"} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		st := fi.Sys().(*syscall.Stat_t)
		if st.Uid != uid || st.Gid != gid || fi.Mode().Perm() != 0o640 {
			t.Errorf("%s: owner %d:%d mode %v, want %d:%d 0640", filepath.Base(p), st.Uid, st.Gid, fi.Mode().Perm(), uid, gid)
		}
	}
}
