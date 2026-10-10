package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func writeTestCert(t *testing.T, dir string, hosts ...string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: hosts[0]},
		DNSNames:     hosts,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(48 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

// newEdgeConfig returns a raw config for an in-process edge on random ports.
func newEdgeConfig(t *testing.T, backends ...Backend) *Config {
	t.Helper()
	cert, key := writeTestCert(t, t.TempDir(), "cdn.example")
	return &Config{
		Listen:      "127.0.0.1:0",
		AdminListen: "127.0.0.1:0",
		CDNHosts:    []string{"cdn.example"},
		TLS:         TLSConfig{Mode: "files", CertFile: cert, KeyFile: key},
		Log:         &LogConfig{Level: "debug"},
		Backends:    backends,
	}
}

type edge struct {
	t        *testing.T
	s        *Server
	path     string
	addr     string
	admin    string
	logs     *syncBuffer
	cancel   context.CancelFunc
	done     chan error
	stopOnce sync.Once
}

func startEdge(t *testing.T, cfg *Config) *edge {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := saveRaw(path, cfg); err != nil {
		t.Fatal(err)
	}
	logs := &syncBuffer{}
	s, err := NewServer(path, newLogger(logs, "text"))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	s.pidFile = ""
	ctx, cancel := context.WithCancel(context.Background())
	e := &edge{t: t, s: s, path: path, logs: logs, cancel: cancel, done: make(chan error, 1)}
	go func() { e.done <- s.Run(ctx) }()
	select {
	case <-s.Ready():
	case err := <-e.done:
		t.Fatalf("edge failed to start: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("edge did not start")
	}
	e.addr = s.PublicAddr().String()
	if a := s.AdminAddr(); a != nil {
		e.admin = a.String()
	}
	t.Cleanup(func() {
		e.stop()
		if t.Failed() {
			t.Logf("edge log:\n%s", logs.String())
		}
	})
	return e
}

func (e *edge) stop() {
	e.stopOnce.Do(func() {
		e.cancel()
		select {
		case <-e.done:
		case <-time.After(15 * time.Second):
			e.t.Error("edge did not stop within 15s")
		}
	})
}

// rewrite saves a new raw config and reloads the edge.
func (e *edge) rewrite(cfg *Config) {
	e.t.Helper()
	if err := saveRaw(e.path, cfg); err != nil {
		e.t.Fatal(err)
	}
	if err := e.s.Reload(); err != nil {
		e.t.Fatalf("reload: %v", err)
	}
}

func dialTLS(addr, sni string) (*tls.Conn, error) {
	d := &net.Dialer{Timeout: 5 * time.Second}
	raw, err := d.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	c := tls.Client(raw, &tls.Config{ServerName: sni, InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}})
	_ = c.SetDeadline(time.Now().Add(20 * time.Second))
	if err := c.Handshake(); err != nil {
		raw.Close()
		return nil, err
	}
	return c, nil
}

func (e *edge) dialSNI(t *testing.T, sni string) (*tls.Conn, error) {
	c, err := dialTLS(e.addr, sni)
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { c.Close() })
	return c, nil
}

func (e *edge) dial(t *testing.T) *tls.Conn {
	t.Helper()
	c, err := e.dialSNI(t, "cdn.example")
	if err != nil {
		t.Fatalf("dial edge: %v", err)
	}
	return c
}

func (e *edge) adminGet(t *testing.T, path string) string {
	t.Helper()
	resp, err := adminClient.Get("http://" + e.admin + path)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

// eventually polls cond until it holds or 5s pass.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("timed out waiting for: %s", what)
}

func upgradeReq(path string, extra ...string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "GET %s HTTP/1.1\r\nHost: cdn.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n", path)
	for _, h := range extra {
		b.WriteString(h + "\r\n")
	}
	b.WriteString("\r\n")
	return b.String()
}

func readStatus(t *testing.T, br *bufio.Reader) (int, string) {
	t.Helper()
	head, err := readHead(br, 64<<10)
	if err != nil {
		t.Fatalf("read response head: %v", err)
	}
	code, err := parseStatusCode(head)
	if err != nil {
		t.Fatalf("parse status: %v (head %q)", err, head)
	}
	return code, string(head)
}

func readN(t *testing.T, r io.Reader, n int) string {
	t.Helper()
	buf := make([]byte, n)
	if got, err := io.ReadFull(r, buf); err != nil {
		t.Fatalf("read %d bytes: %v (got %q)", n, err, buf[:got])
	}
	return string(buf)
}

// ---- backends -----------------------------------------------------------------------

func listenLocal(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln
}

func startEcho(t *testing.T, o echoOpts) string {
	ln := listenLocal(t)
	if o.status == 0 {
		o.status = http.StatusSwitchingProtocols
	}
	go serveEcho(ln, o) //nolint:errcheck
	return ln.Addr().String()
}

// startCapture answers every request with a 101 and an echo, and reports the
// request head it received.
func startCapture(t *testing.T) (string, <-chan string) {
	ln := listenLocal(t)
	heads := make(chan string, 16)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				br := bufio.NewReader(c)
				head, err := readHead(br, 64<<10)
				if err != nil {
					return
				}
				heads <- string(head)
				_, _ = io.WriteString(c, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
				_, _ = io.Copy(c, br)
			}()
		}
	}()
	return ln.Addr().String(), heads
}

// startScripted answers each request with fn's bytes, then echoes if echo is set.
func startScripted(t *testing.T, resp string, echo bool) string {
	ln := listenLocal(t)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				br := bufio.NewReader(c)
				if _, err := readHead(br, 64<<10); err != nil {
					return
				}
				_, _ = io.WriteString(c, resp)
				if echo {
					_, _ = io.Copy(c, br)
				}
			}()
		}
	}()
	return ln.Addr().String()
}

// startSilent accepts connections and never answers.
func startSilent(t *testing.T) string {
	ln := listenLocal(t)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(io.Discard, c); c.Close() }()
		}
	}()
	return ln.Addr().String()
}

func wsBackend(name string, ups ...string) Backend {
	return Backend{Name: name, Upstreams: ups, Proto: "ws", Host: name + ".internal"}
}
