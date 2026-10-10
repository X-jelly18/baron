package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---- the three v1 data-path bugs ---------------------------------------------------------

func TestEarlyDataSameTLSRecord(t *testing.T) {
	t.Parallel()
	e := startEdge(t, newEdgeConfig(t, wsBackend("echo", startEcho(t, echoOpts{}))))
	c := e.dial(t)
	// Request and SSH banner in ONE write, so one TLS record: v1 dropped the banner.
	if _, err := io.WriteString(c, upgradeReq("/echo/")+"SSH-2.0-client\r\n"); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(c)
	if code, head := readStatus(t, br); code != 101 {
		t.Fatalf("status %d: %s", code, head)
	}
	if got := readN(t, br, 16); got != "SSH-2.0-client\r\n" {
		t.Fatalf("early data corrupted: %q", got)
	}
}

func TestEarlyDataSeparateWrite(t *testing.T) {
	t.Parallel()
	e := startEdge(t, newEdgeConfig(t, wsBackend("echo", startEcho(t, echoOpts{}))))
	for i := 0; i < 20; i++ { // v1 lost the first byte ("SH-2.0-client") in this pattern
		c := e.dial(t)
		if _, err := io.WriteString(c, upgradeReq("/echo/")); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(c, "SSH-2.0-client\r\n"); err != nil {
			t.Fatal(err)
		}
		br := bufio.NewReader(c)
		if code, _ := readStatus(t, br); code != 101 {
			t.Fatalf("status %d", code)
		}
		if got := readN(t, br, 16); got != "SSH-2.0-client\r\n" {
			t.Fatalf("attempt %d: early data corrupted: %q", i, got)
		}
		c.Close()
	}
}

func TestPythonStyle101WithoutUpgradeHeader(t *testing.T) {
	t.Parallel()
	e := startEdge(t, newEdgeConfig(t, wsBackend("py", startEcho(t, echoOpts{noUpgradeHeader: true}))))
	c := e.dial(t)
	io.WriteString(c, upgradeReq("/py/")) //nolint:errcheck
	br := bufio.NewReader(c)
	code, head := readStatus(t, br)
	if code != 101 {
		t.Fatalf("v1 answered 502 here; got %d: %s", code, head)
	}
	if strings.Contains(strings.ToLower(head), "upgrade:") {
		t.Fatalf("the backend's head must be forwarded verbatim, got %q", head)
	}
	io.WriteString(c, "ping\n") //nolint:errcheck
	if got := readN(t, br, 5); got != "ping\n" {
		t.Fatalf("echo: %q", got)
	}
}

func TestBackendBannerRightAfter101(t *testing.T) {
	t.Parallel()
	e := startEdge(t, newEdgeConfig(t, wsBackend("ssh", startEcho(t, echoOpts{banner: "SSH-2.0-backend"}))))
	c := e.dial(t)
	io.WriteString(c, upgradeReq("/ssh/")+"SSH-2.0-client\r\n") //nolint:errcheck
	br := bufio.NewReader(c)
	if code, _ := readStatus(t, br); code != 101 {
		t.Fatalf("status %d", code)
	}
	if got := readN(t, br, 17+16); got != "SSH-2.0-backend\r\nSSH-2.0-client\r\n" {
		t.Fatalf("got %q", got)
	}
}

// ---- relay modes and response handling -------------------------------------------------------

func TestRelayAlways200ThenRaw(t *testing.T) {
	t.Parallel()
	b := wsBackend("raw", startEcho(t, echoOpts{status: 200}))
	b.Relay = "always"
	e := startEdge(t, newEdgeConfig(t, b))
	c := e.dial(t)
	io.WriteString(c, upgradeReq("/raw/")+"payload-1\n") //nolint:errcheck
	br := bufio.NewReader(c)
	if code, _ := readStatus(t, br); code != 200 {
		t.Fatalf("status %d", code)
	}
	if got := readN(t, br, 10); got != "payload-1\n" {
		t.Fatalf("got %q", got)
	}
	io.WriteString(c, "payload-2\n") //nolint:errcheck
	if got := readN(t, br, 10); got != "payload-2\n" {
		t.Fatalf("got %q", got)
	}
}

func TestRelayAlwaysNonHTTPBackend(t *testing.T) {
	t.Parallel()
	b := wsBackend("raw", startScripted(t, "RAW-HELLO\n", true))
	b.Relay = "always"
	e := startEdge(t, newEdgeConfig(t, b))
	c := e.dial(t)
	io.WriteString(c, upgradeReq("/raw/")) //nolint:errcheck
	br := bufio.NewReader(c)
	if got := readN(t, br, 10); got != "RAW-HELLO\n" {
		t.Fatalf("got %q", got)
	}
	io.WriteString(c, "x\n") //nolint:errcheck
	if got := readN(t, br, 2); got != "x\n" {
		t.Fatalf("got %q", got)
	}
}

func TestNonHTTPBackendInUpgradeModeIs502(t *testing.T) {
	t.Parallel()
	e := startEdge(t, newEdgeConfig(t, wsBackend("raw", startScripted(t, "RAW-HELLO\n", false))))
	c := e.dial(t)
	io.WriteString(c, upgradeReq("/raw/")) //nolint:errcheck
	if code, _ := readStatus(t, bufio.NewReader(c)); code != 502 {
		t.Fatalf("status %d", code)
	}
	eventually(t, "a log line suggesting relay always", func() bool { return strings.Contains(e.logs.String(), `\"relay\": \"always\"`) })
}

func TestNon101ResponseForwardedAndKeepAlive(t *testing.T) {
	t.Parallel()
	resp := "HTTP/1.1 403 Forbidden\r\nContent-Length: 9\r\nX-Test: yes\r\nConnection: keep-alive\r\n\r\nforbidden"
	e := startEdge(t, newEdgeConfig(t, wsBackend("deny", startScripted(t, resp, false))))
	c := e.dial(t)
	br := bufio.NewReader(c)
	for i := 0; i < 2; i++ { // the client connection stays usable
		io.WriteString(c, "GET /deny/x HTTP/1.1\r\nHost: cdn.example\r\n\r\n") //nolint:errcheck
		r, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		body, _ := io.ReadAll(r.Body)
		r.Body.Close()
		if r.StatusCode != 403 || string(body) != "forbidden" || r.Header.Get("X-Test") != "yes" {
			t.Fatalf("request %d: %d %q %v", i, r.StatusCode, body, r.Header)
		}
	}
}

func TestUpstreamHeaderTimeoutIs504(t *testing.T) {
	t.Parallel()
	cfg := newEdgeConfig(t, wsBackend("slow", startSilent(t)))
	cfg.Timeouts = &Timeouts{UpstreamHeader: Duration(300 * time.Millisecond)}
	e := startEdge(t, cfg)
	c := e.dial(t)
	io.WriteString(c, upgradeReq("/slow/")) //nolint:errcheck
	if code, _ := readStatus(t, bufio.NewReader(c)); code != 504 {
		t.Fatalf("status %d", code)
	}
}

func TestForwardingHeadersAndPathStrip(t *testing.T) {
	t.Parallel()
	addr, heads := startCapture(t)
	e := startEdge(t, newEdgeConfig(t, wsBackend("cap", addr)))
	c := e.dial(t)
	io.WriteString(c, upgradeReq("/cap/ws%2Fx?ed=2048", "X-Forwarded-For: 6.6.6.6", "X-Real-IP: 6.6.6.6", "X-Custom: keep")) //nolint:errcheck
	if code, _ := readStatus(t, bufio.NewReader(c)); code != 101 {
		t.Fatalf("status %d", code)
	}
	head := <-heads
	for _, want := range []string{
		"GET /ws%2Fx?ed=2048 HTTP/1.1\r\n", "Host: cap.internal\r\n", "X-Forwarded-For: 127.0.0.1\r\n",
		"X-Real-Ip: 127.0.0.1\r\n", "X-Forwarded-Proto: https\r\n", "X-Forwarded-Host: cdn.example\r\n",
		"X-Forwarded-Prefix: /cap\r\n", "X-Custom: keep\r\n", "Sec-Websocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
		"Upgrade: websocket\r\n",
	} {
		if !strings.Contains(head, want) {
			t.Errorf("backend request lacks %q:\n%s", want, head)
		}
	}
	if strings.Contains(head, "6.6.6.6") {
		t.Errorf("spoofed forwarding header reached the backend:\n%s", head)
	}
}

// ---- upstreams, failover, capacity ----------------------------------------------------------

func TestFailoverToSecondUpstream(t *testing.T) {
	t.Parallel()
	b := wsBackend("ha", refusedAddr(t), startEcho(t, echoOpts{}))
	b.LB = "first"
	e := startEdge(t, newEdgeConfig(t, b))
	for i := 0; i < 3; i++ {
		c := e.dial(t)
		io.WriteString(c, upgradeReq("/ha/")+"hi\n") //nolint:errcheck
		br := bufio.NewReader(c)
		if code, _ := readStatus(t, br); code != 101 {
			t.Fatalf("status %d", code)
		}
		if got := readN(t, br, 3); got != "hi\n" {
			t.Fatalf("got %q", got)
		}
		c.Close()
	}
	var st statusDoc
	if err := json.Unmarshal([]byte(e.adminGet(t, "/status")), &st); err != nil {
		t.Fatal(err)
	}
	ups := st.Backends[0].Upstreams
	if ups[0].Healthy || ups[0].DialErr == 0 || ups[1].DialOK != 3 {
		t.Fatalf("upstream state: %+v", ups)
	}
}

func TestBackendMaxConns(t *testing.T) {
	t.Parallel()
	b := wsBackend("one", startEcho(t, echoOpts{}))
	b.MaxConns = 1
	e := startEdge(t, newEdgeConfig(t, b))
	c1 := e.dial(t)
	io.WriteString(c1, upgradeReq("/one/")) //nolint:errcheck
	if code, _ := readStatus(t, bufio.NewReader(c1)); code != 101 {
		t.Fatalf("first: %d", code)
	}
	c2 := e.dial(t)
	io.WriteString(c2, upgradeReq("/one/")) //nolint:errcheck
	if code, _ := readStatus(t, bufio.NewReader(c2)); code != 503 {
		t.Fatalf("second while the first is open: %d", code)
	}
	c1.Close()
	eventually(t, "a free slot after closing the first tunnel", func() bool {
		c, err := e.dialSNI(t, "cdn.example")
		if err != nil {
			return false
		}
		defer c.Close()
		io.WriteString(c, upgradeReq("/one/")) //nolint:errcheck
		head, err := readHead(bufio.NewReader(c), 4096)
		code, _ := parseStatusCode(head)
		return err == nil && code == 101
	})
}

// ---- TLS: SNI fallback, strict mode, ALPN ----------------------------------------------------

func TestSNIFallback(t *testing.T) {
	t.Parallel()
	e := startEdge(t, newEdgeConfig(t, wsBackend("echo", startEcho(t, echoOpts{}))))
	for _, sni := range []string{"bug.host.example", ""} { // bug-host SNI, and no SNI at all
		c, err := e.dialSNI(t, sni)
		if err != nil {
			t.Fatalf("SNI %q: handshake failed: %v", sni, err)
		}
		io.WriteString(c, upgradeReq("/echo/")+"ok\n") //nolint:errcheck
		br := bufio.NewReader(c)
		if code, _ := readStatus(t, br); code != 101 || readN(t, br, 3) != "ok\n" {
			t.Fatalf("SNI %q: tunnel failed", sni)
		}
	}
	if m := e.adminGet(t, "/metrics"); !strings.Contains(m, "ayana_cdn_tls_sni_fallback_total 2") {
		t.Fatal("fallback handshakes not counted")
	}
}

func TestStrictSNI(t *testing.T) {
	t.Parallel()
	cfg := newEdgeConfig(t, wsBackend("echo", startEcho(t, echoOpts{})))
	cfg.StrictSNI = true
	e := startEdge(t, cfg)
	if _, err := e.dialSNI(t, "bug.host.example"); err == nil {
		t.Fatal("strict_sni must refuse unknown names")
	}
	if _, err := e.dialSNI(t, "cdn.example"); err != nil {
		t.Fatalf("known name refused: %v", err)
	}
}

func TestHTTP2OffByDefault(t *testing.T) {
	t.Parallel()
	e := startEdge(t, newEdgeConfig(t))
	raw, err := net.Dial("tcp", e.addr)
	if err != nil {
		t.Fatal(err)
	}
	c := tls.Client(raw, &tls.Config{ServerName: "cdn.example", InsecureSkipVerify: true, NextProtos: []string{"h2", "http/1.1"}})
	defer c.Close()
	if err := c.Handshake(); err != nil {
		t.Fatal(err)
	}
	if p := c.ConnectionState().NegotiatedProtocol; p != "http/1.1" {
		t.Fatalf("negotiated %q; tunnel clients that offer h2 must still get HTTP/1.1", p)
	}
}

// ---- tunnel lifecycle --------------------------------------------------------------------------

func TestHalfClosePropagates(t *testing.T) {
	t.Parallel()
	e := startEdge(t, newEdgeConfig(t, wsBackend("echo", startEcho(t, echoOpts{}))))
	c := e.dial(t)
	io.WriteString(c, upgradeReq("/echo/")+"last words\n") //nolint:errcheck
	br := bufio.NewReader(c)
	if code, _ := readStatus(t, br); code != 101 {
		t.Fatalf("status %d", code)
	}
	if err := c.CloseWrite(); err != nil { // we are done sending, but still reading
		t.Fatal(err)
	}
	rest, err := io.ReadAll(br)
	if err != nil {
		t.Fatalf("read to EOF: %v", err)
	}
	if string(rest) != "last words\n" {
		t.Fatalf("data after half-close: %q", rest)
	}
	eventually(t, "tunnel logged as client_closed", func() bool { return strings.Contains(e.logs.String(), "reason=client_closed") })
}

func TestTunnelIdleTimeout(t *testing.T) {
	t.Parallel()
	cfg := newEdgeConfig(t, wsBackend("echo", startEcho(t, echoOpts{})))
	cfg.Timeouts = &Timeouts{TunnelIdle: Duration(300 * time.Millisecond)}
	e := startEdge(t, cfg)
	c := e.dial(t)
	io.WriteString(c, upgradeReq("/echo/")) //nolint:errcheck
	br := bufio.NewReader(c)
	if code, _ := readStatus(t, br); code != 101 {
		t.Fatalf("status %d", code)
	}
	for i := 0; i < 4; i++ { // activity keeps it alive
		time.Sleep(150 * time.Millisecond)
		io.WriteString(c, "k\n") //nolint:errcheck
		if readN(t, br, 2) != "k\n" {
			t.Fatal("echo")
		}
	}
	start := time.Now()
	if _, err := br.ReadByte(); err == nil {
		t.Fatal("expected the idle tunnel to be closed")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("idle close took %v", d)
	}
	eventually(t, "idle_timeout logged", func() bool { return strings.Contains(e.logs.String(), "reason=idle_timeout") })
}

func TestReloadKeepsOpenTunnels(t *testing.T) {
	t.Parallel()
	echoA, echoB := startEcho(t, echoOpts{}), startEcho(t, echoOpts{})
	cfg := newEdgeConfig(t, wsBackend("a", echoA))
	e := startEdge(t, cfg)
	c := e.dial(t)
	io.WriteString(c, upgradeReq("/a/")) //nolint:errcheck
	br := bufio.NewReader(c)
	if code, _ := readStatus(t, br); code != 101 {
		t.Fatalf("status %d", code)
	}
	cfg.Backends = []Backend{wsBackend("b", echoB)} // remove a, add b
	e.rewrite(cfg)
	io.WriteString(c, "still here\n") //nolint:errcheck
	if got := readN(t, br, 11); got != "still here\n" {
		t.Fatalf("open tunnel broken by reload: %q", got)
	}
	for path, want := range map[string]int{"/a/": 404, "/b/": 101} {
		c2 := e.dial(t)
		io.WriteString(c2, upgradeReq(path)) //nolint:errcheck
		if code, _ := readStatus(t, bufio.NewReader(c2)); code != want {
			t.Fatalf("%s after reload: %d, want %d", path, code, want)
		}
	}
	bad := *cfg
	bad.Backends = []Backend{{Name: "x/y", Upstream: "h:1"}}
	if err := saveRaw(e.path, &bad); err != nil {
		t.Fatal(err)
	}
	if err := e.s.Reload(); err == nil {
		t.Fatal("invalid config must be rejected")
	}
	c3 := e.dial(t)
	io.WriteString(c3, upgradeReq("/b/")) //nolint:errcheck
	if code, _ := readStatus(t, bufio.NewReader(c3)); code != 101 {
		t.Fatal("a rejected reload must leave the running config in place")
	}
}

func TestShutdownClosesTunnelsPromptly(t *testing.T) {
	t.Parallel()
	e := startEdge(t, newEdgeConfig(t, wsBackend("echo", startEcho(t, echoOpts{}))))
	c := e.dial(t)
	io.WriteString(c, upgradeReq("/echo/")) //nolint:errcheck
	br := bufio.NewReader(c)
	if code, _ := readStatus(t, br); code != 101 {
		t.Fatalf("status %d", code)
	}
	start := time.Now()
	e.stop()
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("stop took %v with an open tunnel", d)
	}
	if _, err := br.ReadByte(); err == nil {
		t.Fatal("tunnel still open after stop")
	}
}

// ---- data integrity through the adaptive relay -------------------------------------------------

func TestRelayIntegrityBulkAndInteractive(t *testing.T) {
	t.Parallel()
	e := startEdge(t, newEdgeConfig(t, wsBackend("echo", startEcho(t, echoOpts{}))))
	c := e.dial(t)
	_ = c.SetDeadline(time.Now().Add(60 * time.Second))
	io.WriteString(c, upgradeReq("/echo/")) //nolint:errcheck
	br := bufio.NewReader(c)
	if code, _ := readStatus(t, br); code != 101 {
		t.Fatalf("status %d", code)
	}
	// Alternate bulk bursts (32 KiB buffers) with tiny writes (back to 4 KiB).
	var plan [][]byte
	total := 0
	for i := 0; i < 6; i++ {
		bulk := make([]byte, 3<<20+i*7919)
		_, _ = rand.Read(bulk)
		plan = append(plan, bulk)
		total += len(bulk)
		for j := 0; j < 50; j++ {
			small := []byte(fmt.Sprintf("interactive %d/%d\n", i, j))
			plan = append(plan, small)
			total += len(small)
		}
	}
	sent := sha256.New()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for _, p := range plan {
			sent.Write(p)
			if _, err := c.Write(p); err != nil {
				t.Errorf("write: %v", err)
				return
			}
		}
	}()
	recv := sha256.New()
	if n, err := io.CopyN(recv, br, int64(total)); err != nil {
		t.Fatalf("read %d of %d bytes: %v", n, total, err)
	}
	wg.Wait()
	if fmt.Sprintf("%x", sent.Sum(nil)) != fmt.Sprintf("%x", recv.Sum(nil)) {
		t.Fatal("data corrupted in transit")
	}
	eventually(t, "bytes counted in metrics", func() bool {
		return strings.Contains(e.adminGet(t, "/metrics"), fmt.Sprintf(`ayana_cdn_bytes_total{backend="echo",direction="down"} %d`, total))
	})
}

// ---- HTTP backends --------------------------------------------------------------------------------

func TestHTTPBackendProxyAndStreaming(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseFn := func() { releaseOnce.Do(func() { close(release) }) }
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/events" {
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprint(w, "data: first\n\n")
			w.(http.Flusher).Flush()
			<-release // the client must see the first event before we continue
			fmt.Fprint(w, "data: second\n\n")
			return
		}
		fmt.Fprintf(w, "uri=%s host=%s xff=%s prefix=%s real=%s",
			r.URL.RequestURI(), r.Host, r.Header.Get("X-Forwarded-For"), r.Header.Get("X-Forwarded-Prefix"), r.Header.Get("X-Real-Ip"))
	}))
	defer origin.Close()
	defer releaseFn() // runs first: never leave the handler blocked, or Close would hang
	b := Backend{Name: "web", Upstream: strings.TrimPrefix(origin.URL, "http://"), Proto: "http", Host: "web.internal"}
	e := startEdge(t, newEdgeConfig(t, b))

	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "cdn.example"},
	}}
	base := "https://" + e.addr
	resp, err := client.Get(base + "/web/a%2Fb/page?q=1")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	want := "uri=/a%2Fb/page?q=1 host=web.internal xff=127.0.0.1 prefix=/web real=127.0.0.1"
	if string(body) != want {
		t.Fatalf("got  %s\nwant %s", body, want)
	}

	resp, err = client.Get(base + "/web/events")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	br := bufio.NewReader(resp.Body)
	line, err := br.ReadString('\n')
	if err != nil || line != "data: first\n" {
		t.Fatalf("first event not streamed: %q %v", line, err)
	}
	releaseFn()
	rest, _ := io.ReadAll(br)
	if !strings.Contains(string(rest), "data: second") {
		t.Fatalf("second event: %q", rest)
	}
}

func TestUpgradeToHTTPBackendUsesTunnelPath(t *testing.T) {
	t.Parallel()
	b := Backend{Name: "mixed", Upstream: startEcho(t, echoOpts{}), Proto: "http", Host: "mixed.internal"}
	e := startEdge(t, newEdgeConfig(t, b))
	c := e.dial(t)
	io.WriteString(c, upgradeReq("/mixed/")+"early\n") //nolint:errcheck
	br := bufio.NewReader(c)
	if code, _ := readStatus(t, br); code != 101 {
		t.Fatalf("status %d", code)
	}
	if got := readN(t, br, 6); got != "early\n" {
		t.Fatalf("got %q", got)
	}
}

// ---- edge behaviors ----------------------------------------------------------------------------------

func TestHealthzStrictHostUnroutedDisabled(t *testing.T) {
	t.Parallel()
	off := wsBackend("off", startEcho(t, echoOpts{}))
	off.Disabled = true
	cfg := newEdgeConfig(t, wsBackend("echo", startEcho(t, echoOpts{})), off)
	cfg.StrictHost = true
	e := startEdge(t, cfg)
	cases := []struct {
		req  string
		want int
	}{
		{"GET /healthz HTTP/1.1\r\nHost: cdn.example\r\n\r\n", 200},
		{"GET /nothing/ HTTP/1.1\r\nHost: cdn.example\r\n\r\n", 404},
		{"GET /off/ HTTP/1.1\r\nHost: cdn.example\r\n\r\n", 503},
		{"GET /echo/ HTTP/1.1\r\nHost: evil.example\r\n\r\n", 421},
	}
	for _, tc := range cases {
		c := e.dial(t)
		io.WriteString(c, tc.req) //nolint:errcheck
		if code, _ := readStatus(t, bufio.NewReader(c)); code != tc.want {
			t.Errorf("%q: %d, want %d", strings.SplitN(tc.req, "\r\n", 2)[0], code, tc.want)
		}
	}
}

func TestProxyProtocolFromTrustedFrontDoor(t *testing.T) {
	t.Parallel()
	addr, heads := startCapture(t)
	cfg := newEdgeConfig(t, wsBackend("cap", addr))
	cfg.ProxyProtocol = true
	e := startEdge(t, cfg)
	for _, header := range []string{"PROXY TCP4 203.0.113.9 127.0.0.1 5555 443\r\n", ""} {
		raw, err := net.Dial("tcp", e.addr)
		if err != nil {
			t.Fatal(err)
		}
		io.WriteString(raw, header) //nolint:errcheck
		c := tls.Client(raw, &tls.Config{ServerName: "cdn.example", InsecureSkipVerify: true})
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		io.WriteString(c, upgradeReq("/cap/")) //nolint:errcheck
		if code, _ := readStatus(t, bufio.NewReader(c)); code != 101 {
			t.Fatalf("status %d", code)
		}
		want := "X-Forwarded-For: 203.0.113.9\r\n"
		if header == "" {
			want = "X-Forwarded-For: 127.0.0.1\r\n" // trusted source without a header: plain connection
		}
		if head := <-heads; !strings.Contains(head, want) {
			t.Fatalf("want %q in:\n%s", want, head)
		}
		c.Close()
	}
}

func TestPerIPConnectionRate(t *testing.T) {
	t.Parallel()
	cfg := newEdgeConfig(t)
	cfg.Limits = &Limits{ConnRatePerIP: 1, ConnBurstPerIP: 2, Exempt: []string{"192.0.2.0/24"}} // loopback not exempt
	e := startEdge(t, cfg)
	var ok, refused int
	for i := 0; i < 4; i++ {
		if c, err := e.dialSNI(t, "cdn.example"); err == nil {
			ok++
			c.Close()
		} else {
			refused++
		}
	}
	if ok != 2 || refused != 2 {
		t.Fatalf("burst of 2: ok=%d refused=%d", ok, refused)
	}
	if m := e.adminGet(t, "/metrics"); !strings.Contains(m, `ayana_cdn_connections_rejected_total{reason="ip_rate"} 2`) {
		t.Fatal("rate rejections not counted")
	}
}

func TestMetricsAndStatus(t *testing.T) {
	t.Parallel()
	e := startEdge(t, newEdgeConfig(t, wsBackend("echo", startEcho(t, echoOpts{}))))
	c := e.dial(t)
	io.WriteString(c, upgradeReq("/echo/")+"12345\n") //nolint:errcheck
	br := bufio.NewReader(c)
	readStatus(t, br)
	readN(t, br, 6)
	c.Close()
	eventually(t, "tunnel counted", func() bool {
		m := e.adminGet(t, "/metrics")
		return strings.Contains(m, `ayana_cdn_tunnels_total{backend="echo"} 1`) &&
			strings.Contains(m, `ayana_cdn_responses_total{backend="echo",class="1xx"} 1`) &&
			strings.Contains(m, `ayana_cdn_upstream_up{backend="echo",upstream="`)
	})
	var st statusDoc
	if err := json.Unmarshal([]byte(e.adminGet(t, "/status")), &st); err != nil {
		t.Fatal(err)
	}
	if st.Version != version || len(st.Backends) != 1 || st.Backends[0].TunnelsTotal != 1 || st.Backends[0].BytesUp != 6 {
		t.Fatalf("status: %+v", st)
	}
	if len(st.Certificates) != 1 || st.Certificates[0].Host != "cdn.example" {
		t.Fatalf("certificates: %+v", st.Certificates)
	}
	var sb strings.Builder
	renderStatus(&sb, &st)
	if !strings.Contains(sb.String(), "echo") || !strings.Contains(sb.String(), "certificate cdn.example") {
		t.Fatalf("rendered status:\n%s", sb.String())
	}
}
