package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

var tlsVersions = map[string]uint16{
	"1.0": tls.VersionTLS10, "1.1": tls.VersionTLS11, "1.2": tls.VersionTLS12, "1.3": tls.VersionTLS13,
}

// certSource is satisfied by *autocert.Manager (and by a stub in tests).
type certSource interface {
	GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error)
}

// alpn: HTTP/1.1 always; h2 only when enabled. Some tunnel clients advertise
// h2 but then speak HTTP/1.1, which is why h2 is off by default.
func alpn(http2, acmeMode bool) []string {
	var p []string
	if http2 {
		p = append(p, "h2")
	}
	p = append(p, "http/1.1")
	if acmeMode {
		p = append(p, acme.ALPNProto)
	}
	return p
}

// buildTLS returns the per-state TLS config handed out via GetConfigForClient,
// which lets SIGHUP change hosts, ALPN and minimum version without a restart.
// Session ticket keys stay with the listener's base config, so resumption
// survives reloads.
func (s *Server) buildTLS(cfg *Config, st *state) *tls.Config {
	return &tls.Config{
		MinVersion:     tlsVersions[cfg.TLS.MinVersion],
		NextProtos:     alpn(cfg.EnableHTTP2, s.tlsMode == "acme"),
		GetCertificate: s.certFunc(cfg, st),
	}
}

func (s *Server) getConfigForClient(*tls.ClientHelloInfo) (*tls.Config, error) {
	return s.state.Load().tlsConf, nil
}

func isACMEChallenge(hello *tls.ClientHelloInfo) bool {
	return len(hello.SupportedProtos) == 1 && hello.SupportedProtos[0] == acme.ALPNProto
}

// certFunc selects the certificate for a handshake.
//
// SNI fallback (default): a client that sends no SNI, or an SNI that is not
// one of cdn_hosts, still completes the handshake with the primary host's
// certificate. Tunnel clients rely on this: they put a "bug host" in the SNI
// or connect by IP with no SNI at all, and a strict server would simply fail
// the handshake. strict_sni restores the strict behavior.
func (s *Server) certFunc(cfg *Config, st *state) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	strict, hosts, primary := cfg.StrictSNI, st.hosts, st.primary
	g := &s.stats.global
	// The certificate source is fixed at startup: a reload that edits
	// tls.mode only takes effect after a restart.
	switch s.tlsMode {
	case "acme":
		src := s.acmeSrc
		return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if isACMEChallenge(hello) {
				return src.GetCertificate(hello)
			}
			name := normHost(hello.ServerName)
			if !hosts[name] {
				if strict {
					g.sniRejected.Add(1)
					return nil, fmt.Errorf("unknown server name %q (strict_sni)", hello.ServerName)
				}
				g.sniFallback.Add(1)
				h := *hello
				h.ServerName = primary
				hello, name = &h, primary
			}
			cert, err := src.GetCertificate(hello)
			if err == nil {
				s.certs.observe(name, cert)
			}
			return cert, err
		}
	default: // files
		return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if len(hosts) > 0 && !hosts[normHost(hello.ServerName)] {
				if strict {
					g.sniRejected.Add(1)
					return nil, fmt.Errorf("unknown server name %q (strict_sni)", hello.ServerName)
				}
				g.sniFallback.Add(1)
			}
			c := s.fileCert.Load()
			if c == nil {
				return nil, errors.New("no certificate loaded")
			}
			key := primary
			if key == "" {
				key = "(cert_file)"
			}
			s.certs.observe(key, c)
			return c, nil
		}
	}
}

func (s *Server) loadFileCert(certFile, keyFile string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("load tls.cert_file/key_file: %w", err)
	}
	if cert.Leaf == nil && len(cert.Certificate) > 0 {
		if leaf, err := x509.ParseCertificate(cert.Certificate[0]); err == nil {
			cert.Leaf = leaf
		}
	}
	s.fileCert.Store(&cert)
	return nil
}

// hostPolicy is consulted by autocert before any issuance; it reads the live
// host set so cdn_hosts edits apply on SIGHUP.
func (s *Server) hostPolicy(_ context.Context, host string) error {
	if s.state.Load().hosts[strings.ToLower(host)] {
		return nil
	}
	return fmt.Errorf("host %q is not in cdn_hosts", host)
}

// ---- certificate tracking ------------------------------------------------------

type certInfo struct {
	Host     string    `json:"host"`
	NotAfter time.Time `json:"expires"`
	Issuer   string    `json:"issuer"`
}

// certTracker remembers which certificate is served per host, for metrics and
// status, and logs whenever it changes (first issuance, renewal).
type certTracker struct {
	log *slog.Logger
	mu  sync.Mutex
	m   map[string]certInfo
}

func newCertTracker(log *slog.Logger) *certTracker {
	return &certTracker{log: log, m: map[string]certInfo{}}
}

func (t *certTracker) observe(host string, c *tls.Certificate) {
	if c == nil || c.Leaf == nil {
		return
	}
	leaf := c.Leaf
	t.mu.Lock()
	old, ok := t.m[host]
	changed := !ok || !old.NotAfter.Equal(leaf.NotAfter)
	if changed {
		t.m[host] = certInfo{Host: host, NotAfter: leaf.NotAfter, Issuer: leaf.Issuer.CommonName}
	}
	t.mu.Unlock()
	if changed {
		t.log.Info("certificate in use", "host", host, "expires", leaf.NotAfter.UTC().Format(time.RFC3339),
			"issuer", leaf.Issuer.CommonName)
	}
}

func (t *certTracker) list() []certInfo {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]certInfo, 0, len(t.m))
	for _, v := range t.m {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	return out
}

// loggingCache records when autocert stores a new certificate.
type loggingCache struct {
	autocert.Cache
	log *slog.Logger
}

func (c loggingCache) Put(ctx context.Context, key string, data []byte) error {
	err := c.Cache.Put(ctx, key, data)
	if (!strings.Contains(key, "+") || strings.HasSuffix(key, "+rsa")) && err == nil {
		c.log.Info("acme: certificate stored (issued or renewed)", "key", key)
	}
	return err
}

// ---- warm-up ---------------------------------------------------------------------

// warmUp triggers certificate issuance right after startup by handshaking
// with our own listener. The first real client no longer waits for ACME, and
// problems (DNS not pointing here, port 443 unreachable) show up in the log
// immediately. Retries are sparse to stay far from Let's Encrypt's
// failed-validation limits.
func (s *Server) warmUp(ctx context.Context, hosts []string, addr string) {
	for _, h := range hosts {
		go func() {
			for i, wait := range []time.Duration{0, 10 * time.Minute, 30 * time.Minute} {
				select {
				case <-ctx.Done():
					return
				case <-time.After(wait):
				}
				err := warmOne(ctx, h, addr)
				if err == nil {
					return
				}
				s.log.Warn("certificate not ready yet", "host", h, "attempt", i+1, "err", errString(err),
					"hint", "the host's DNS must point at this server and port 443 must be reachable from the internet; the ACME error is logged just above")
			}
		}()
	}
}

func warmOne(ctx context.Context, host, addr string) error {
	cctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	d := tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 10 * time.Second},
		Config:    &tls.Config{ServerName: host, InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}}, //nolint:gosec // only triggers issuance
	}
	c, err := d.DialContext(cctx, "tcp", addr)
	if err != nil {
		return err
	}
	return c.Close()
}

// dialableAddr turns a listen address into one we can dial locally.
func dialableAddr(a net.Addr) string {
	host, port, err := net.SplitHostPort(a.String())
	if err != nil {
		return a.String()
	}
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		host = "127.0.0.1" // ":443" and "[::]:443" are dual-stack
	}
	return net.JoinHostPort(host, port)
}
