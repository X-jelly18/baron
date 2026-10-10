package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseRoutes(t *testing.T) {
	src := `{
	  "/plain": "http://south.example",
	  "/tls":   "https://ses.example:8443",
	  "/pool":  ["http://10.0.0.5", "http://south2.example"],
	  "/obj":   {"targets": ["http://1.2.3.4"], "host": "name.example", "insecure": true},
	  "/v6":    "ws://[2001:db8::1]:8080/"
	}`
	got, err := parseRoutes([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	want := []Backend{
		{Name: "obj", Upstream: "1.2.3.4:80", Host: "name.example", Proto: "ws", Strip: ptr(false), Insecure: true},
		{Name: "plain", Upstream: "south.example:80", Proto: "ws", Strip: ptr(false)},
		{Name: "pool", Upstreams: []string{"10.0.0.5:80", "south2.example:80"}, Proto: "ws", Strip: ptr(false), LB: "first"},
		{Name: "tls", Upstream: "ses.example:8443", Proto: "wss", Strip: ptr(false)},
		{Name: "v6", Upstream: "[2001:db8::1]:8080", Proto: "ws", Strip: ptr(false)},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d backends, want %d", len(got), len(want))
	}
	for i := range want {
		if !reflect.DeepEqual(got[i], want[i]) {
			t.Errorf("route %d:\n got  %+v\n want %+v", i, got[i], want[i])
		}
	}
	// The result must be a valid config with the reference semantics.
	cfg := &Config{CDNHosts: []string{"cdn.example"}, TLS: TLSConfig{Mode: "acme"}, Backends: got}
	eff, err := cfg.Effective()
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range eff.Backends {
		if b.strip() {
			t.Errorf("%s: the path must be forwarded unchanged", b.Name)
		}
	}
	if eff.Backends[1].Host != "south.example" || eff.Backends[0].Host != "name.example" {
		t.Errorf("Host must default to the target hostname unless given: %+v", eff.Backends)
	}
}

func TestParseRoutesErrors(t *testing.T) {
	cases := map[string]string{
		`{"/a/b": "http://x"}`:                       "nested",
		`{"a": "http://x"}`:                          `start with "/"`,
		`{"/a": "ftp://x"}`:                          "scheme",
		`{"/a": "http://x/path"}`:                    "path in the target",
		`{"/a": "http://x?q=1"}`:                     "path in the target",
		`{"/a": ["http://x", "https://y"]}`:          "plain or all TLS",
		`{"/a": {"targets": []}}`:                    "no target",
		`{"/a": {"target": "http://x", "extra": 1}}`: "unknown field",
		`{"/a": 42}`:                                 "must be a URL",
		`{"/a": "http://"}`:                          "expected scheme://host",
		`{"/healthz": "http://x"}`:                   "", // parses; validation rejects the reserved name later
		`[]`:                                         "routes file",
		`{"/a": "http://x"} {}`:                      "unexpected data",
	}
	for src, want := range cases {
		_, err := parseRoutes([]byte(src))
		if want == "" {
			if err != nil {
				t.Errorf("%s: unexpected error %v", src, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want an error containing %q", src, err, want)
		}
	}
}

func TestRoutesImportMergeAndReplace(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	data, _ := os.ReadFile("testdata/v1-config.json")
	if err := os.WriteFile(cfgPath, data, 0o644); err != nil {
		t.Fatal(err)
	}
	routes := filepath.Join(dir, "routes.json")
	if err := os.WriteFile(routes, []byte(`{"/s1": "http://192.0.2.73", "/native1": "https://new.example"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout, _ = os.Open(os.DevNull)
	defer func() { os.Stdout = stdout }()

	if err := cmdRoutes([]string{"import", routes, "-config", cfgPath, "-no-reload"}); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Backends) != 11 { // 10 v1 backends, native1 replaced, s1 added
		t.Fatalf("merge: %d backends", len(cfg.Backends))
	}
	n1 := findBackend(cfg, "native1")
	if n1 == nil || n1.Upstreams[0] != "new.example:443" || n1.Proto != "wss" || n1.strip() {
		t.Fatalf("native1 not updated from the file: %+v", n1)
	}
	if s1 := findBackend(cfg, "s1"); s1 == nil || s1.Upstreams[0] != "192.0.2.73:80" || s1.useTLS() {
		t.Fatalf("s1: %+v", s1)
	}

	if err := cmdRoutes([]string{"import", routes, "-replace", "-config", cfgPath, "-no-reload"}); err != nil {
		t.Fatal(err)
	}
	if cfg, err = LoadConfig(cfgPath); err != nil || len(cfg.Backends) != 2 {
		t.Fatalf("replace: %d backends, %v", len(cfg.Backends), err)
	}

	bad := filepath.Join(dir, "bad.json")
	os.WriteFile(bad, []byte(`{"/healthz": "http://x"}`), 0o644) //nolint:errcheck
	if err := cmdRoutes([]string{"import", bad, "-replace", "-config", cfgPath, "-no-reload"}); err == nil {
		t.Fatal("a reserved name must be rejected before saving")
	}
	if cfg, _ = LoadConfig(cfgPath); len(cfg.Backends) != 2 {
		t.Fatal("a rejected import must not modify the config")
	}
}

// The shipped routes.json and config/config.json must describe the same backends.
func TestShippedRoutesMatchShippedConfig(t *testing.T) {
	routes, err := os.ReadFile("../../routes.json")
	if err != nil {
		t.Skip("package root not available")
	}
	fromRoutes, err := parseRoutes(routes)
	if err != nil {
		t.Fatal(err)
	}
	shipped, err := LoadConfig("../../config/config.json")
	if err != nil {
		t.Fatal(err)
	}
	cfg := &Config{CDNHosts: shipped.CDNHosts, TLS: TLSConfig{Mode: "acme"}, Backends: fromRoutes}
	eff, err := cfg.Effective()
	if err != nil {
		t.Fatal(err)
	}
	type key struct {
		name, host, proto, lb string
		ups                   string
		tls, strip, insecure  bool
	}
	summarize := func(bs []Backend) []key {
		var out []key
		for _, b := range bs {
			out = append(out, key{b.Name, b.Host, b.Proto, b.LB, strings.Join(b.Upstreams, ","), b.useTLS(), b.strip(), b.Insecure})
		}
		return out
	}
	if a, b := summarize(eff.Backends), summarize(shipped.Backends); !reflect.DeepEqual(a, b) {
		t.Fatalf("routes.json and config/config.json disagree:\n routes: %+v\n config: %+v", a, b)
	}
}
