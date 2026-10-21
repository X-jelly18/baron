package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestRouteBoundaries(t *testing.T) {
	rt := &routeTable{}
	for _, name := range []string{"native1", "native10", "web"} {
		rt.list = append(rt.list, &backendRT{cfg: Backend{Name: name}, prefix: "/" + name})
	}
	// buildRoutes sorts longest first; the boundary rule must work regardless.
	cases := map[string]string{
		"/native1": "native1", "/native1/": "native1", "/native1/x/y": "native1",
		"/native10": "native10", "/native10/": "native10", "/native10/abc": "native10",
		"/native100": "", "/native1x": "", "/": "", "/web/index.html": "web", "/webx": "",
	}
	for path, want := range cases {
		got := ""
		if b := rt.match(path); b != nil {
			got = b.cfg.Name
		}
		if got != want {
			t.Errorf("match(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestBackendRequestURI(t *testing.T) {
	cases := []struct {
		target string
		strip  bool
		want   string
	}{
		{"/native1/", true, "/"},
		{"/native1", true, "/"},
		{"/native1/ws?ed=2048", true, "/ws?ed=2048"},
		{"/native1/a%2Fb/c", true, "/a%2Fb/c"}, // encoded slash survives
		{"/native%31/x", true, "/x"},           // encoded prefix still strips
		{"/native1/sp%20ace", true, "/sp%20ace"},
		{"/native1/x?", true, "/x?"}, // ForceQuery kept
		{"/native1/x", false, "/native1/x"},
		{"/native1/a%2Fb", false, "/native1/a%2Fb"},
	}
	for _, tc := range cases {
		u, err := url.ParseRequestURI(tc.target)
		if err != nil {
			t.Fatal(err)
		}
		if got := backendRequestURI(u, "/native1", tc.strip); got != tc.want {
			t.Errorf("backendRequestURI(%q, strip=%v) = %q, want %q", tc.target, tc.strip, got, tc.want)
		}
	}
}

func TestSetBackendPath(t *testing.T) {
	in, _ := url.ParseRequestURI("/web/a%2Fb/c")
	out := *in
	setBackendPath(&out, in, "/web", true)
	if out.EscapedPath() != "/a%2Fb/c" || out.Path != "/a/b/c" {
		t.Fatalf("got path=%q escaped=%q", out.Path, out.EscapedPath())
	}
}

func TestLimiter(t *testing.T) {
	l := newIPLimiter()
	l.configure(&Limits{ConnRatePerIP: 10, ConnBurstPerIP: 3, MaxConnsPerIP: 0})
	now := time.Unix(1000, 0)
	for i := 0; i < 3; i++ {
		if ok, _, _ := l.admit("a", now); !ok {
			t.Fatalf("burst connection %d refused", i)
		}
	}
	if ok, _, reason := l.admit("a", now); ok || reason != "ip_rate" {
		t.Fatalf("4th connection within the burst window must be refused by rate, got ok=%v reason=%q", ok, reason)
	}
	if ok, _, _ := l.admit("b", now); !ok {
		t.Fatal("another IP must be unaffected")
	}
	if ok, _, _ := l.admit("a", now.Add(150*time.Millisecond)); !ok {
		t.Fatal("bucket must refill at 10/s")
	}

	l2 := newIPLimiter()
	l2.configure(&Limits{ConnRatePerIP: -1, ConnBurstPerIP: 1, MaxConnsPerIP: 2})
	for i := 0; i < 2; i++ {
		if ok, tracked, _ := l2.admit("c", now); !ok || !tracked {
			t.Fatal("under the per-IP cap")
		}
	}
	if ok, _, reason := l2.admit("c", now); ok || reason != "ip_conns" {
		t.Fatalf("over the per-IP cap: ok=%v reason=%q", ok, reason)
	}
	l2.release("c")
	if ok, _, _ := l2.admit("c", now); !ok {
		t.Fatal("a slot must free up after release")
	}
	l2.release("c")
	l2.release("c")
	if n := l2.sweep(now); n != 1 || l2.size() != 0 {
		t.Fatalf("sweep removed %d, %d left", n, l2.size())
	}

	off := newIPLimiter()
	off.configure(&Limits{ConnRatePerIP: -1, ConnBurstPerIP: 1, MaxConnsPerIP: 0})
	if ok, tracked, _ := off.admit("d", now); !ok || tracked || off.size() != 0 {
		t.Fatal("disabled limiter must admit without tracking")
	}
}

func TestLimiterKeyIPv6Slash64(t *testing.T) {
	a := limiterKey(netip.MustParseAddr("2001:db8:1:2:aaaa::1"))
	b := limiterKey(netip.MustParseAddr("2001:db8:1:2:bbbb::9"))
	c := limiterKey(netip.MustParseAddr("2001:db8:1:3::1"))
	if a != b || a == c {
		t.Fatalf("IPv6 must group by /64: %s %s %s", a, b, c)
	}
	if k := limiterKey(netip.MustParseAddr("192.0.2.7")); k != "192.0.2.7" {
		t.Fatalf("IPv4 key: %s", k)
	}
}

func proxyV2(fam byte, cmd byte, src []byte, sport uint16) []byte {
	var body []byte
	switch fam {
	case 0x11:
		body = append(append(append([]byte{}, src...), 10, 0, 0, 1), 0, 0, 0, 0)
		binary.BigEndian.PutUint16(body[8:], sport)
		binary.BigEndian.PutUint16(body[10:], 443)
	case 0x21:
		body = append(append([]byte{}, src...), make([]byte, 16+4)...)
		binary.BigEndian.PutUint16(body[32:], sport)
	}
	h := append([]byte{}, proxyV2Sig...)
	h = append(h, 0x20|cmd, fam, 0, 0)
	binary.BigEndian.PutUint16(h[14:], uint16(len(body)))
	return append(h, body...)
}

func TestProxyProtocol(t *testing.T) {
	cases := []struct {
		name    string
		in      []byte
		want    string // "" = no address
		wantErr bool
	}{
		{"v1 tcp4", []byte("PROXY TCP4 203.0.113.9 10.0.0.1 51234 443\r\n"), "203.0.113.9:51234", false},
		{"v1 tcp6", []byte("PROXY TCP6 2001:db8::5 2001:db8::1 40000 443\r\n"), "[2001:db8::5]:40000", false},
		{"v1 unknown", []byte("PROXY UNKNOWN\r\n"), "", false},
		{"v1 malformed", []byte("PROXY TCP4 nonsense\r\n"), "", true},
		{"v2 tcp4", proxyV2(0x11, 1, []byte{198, 51, 100, 7}, 6000), "198.51.100.7:6000", false},
		{"v2 tcp6", proxyV2(0x21, 1, net.ParseIP("2001:db8::77").To16(), 7000), "[2001:db8::77]:7000", false},
		{"v2 local", proxyV2(0x11, 0, []byte{1, 2, 3, 4}, 1), "", false},
		{"no header", []byte{0x16, 0x03, 0x01}, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := []byte("\x16\x03\x01TLS-HELLO")
			br := bufio.NewReaderSize(bytes.NewReader(append(append([]byte{}, tc.in...), payload...)), 256)
			addr, err := readProxyHeader(br)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got := ""
			if addr != nil {
				got = addr.String()
			}
			if got != tc.want {
				t.Fatalf("addr = %q, want %q", got, tc.want)
			}
			rest, _ := io.ReadAll(br)
			wantRest := payload
			if tc.name == "no header" {
				wantRest = append(append([]byte{}, tc.in...), payload...)
			}
			if !bytes.Equal(rest, wantRest) {
				t.Fatalf("stream after the header = %q, want %q", rest, wantRest)
			}
		})
	}
}

func TestReadHeadKeepsFollowingBytes(t *testing.T) {
	stream := "\r\nHTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\nSSH-2.0-banner\r\n"
	br := bufio.NewReaderSize(strings.NewReader(stream), 4096)
	head, err := readHead(br, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(head), "HTTP/1.1 101") || !strings.HasSuffix(string(head), "\r\n\r\n") {
		t.Fatalf("head = %q", head)
	}
	rest, _ := io.ReadAll(br)
	if string(rest) != "SSH-2.0-banner\r\n" {
		t.Fatalf("bytes after the head = %q", rest)
	}
	if _, err := readHead(bufio.NewReader(strings.NewReader("HTTP/1.1 200 OK\nX: y\n\n")), 1024); err != nil {
		t.Fatalf("bare LF line endings must be accepted: %v", err)
	}
	if _, err := readHead(bufio.NewReader(strings.NewReader("HTTP/1.1 200 OK\r\n"+strings.Repeat("X: y\r\n", 100)+"\r\n")), 256); err != errHeadTooLarge {
		t.Fatalf("oversized head: %v", err)
	}
}

func TestParseStatusCode(t *testing.T) {
	good := map[string]int{
		"HTTP/1.1 101 Switching Protocols\r\n": 101,
		"HTTP/1.0 200 OK\r\n":                  200,
		"HTTP/1.1 101 <b>custom</b>\r\n":       101,
		"HTTP/1.1 101\r\n":                     101,
	}
	for in, want := range good {
		if got, err := parseStatusCode([]byte(in)); err != nil || got != want {
			t.Errorf("%q: got %d, %v", in, got, err)
		}
	}
	for _, in := range []string{"SSH-2.0-OpenSSH\r\n", "HTTP/1.1 abc\r\n", "HTTP/1.1\r\n"} {
		if _, err := parseStatusCode([]byte(in)); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

func TestParseSize(t *testing.T) {
	good := map[string]int64{"": 0, "512": 512, "64KiB": 64 << 10, "64KB": 64 << 10, "256MiB": 256 << 20, "1G": 1 << 30, "2GiB": 2 << 30}
	for in, want := range good {
		if got, err := parseSize(in); err != nil || got != want {
			t.Errorf("parseSize(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"12XB", "MiB", "-5"} {
		if _, err := parseSize(in); err == nil {
			t.Errorf("parseSize(%q) accepted", in)
		}
	}
}
