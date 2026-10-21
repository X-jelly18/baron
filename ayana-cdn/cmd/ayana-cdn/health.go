package main

import (
	"bufio"
	"context"
	crand "crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"strings"
	"time"
)

// startHealthChecks launches one checker per upstream. They stop when ctx
// (owned by the route table) is canceled on the next reload.
func (p *pool) startHealthChecks(ctx context.Context, b Backend) {
	hc := *b.HealthCheck
	if hc.Type == "off" {
		return
	}
	for _, u := range p.ups {
		go p.healthLoop(ctx, u, b, hc)
	}
}

func (p *pool) healthLoop(ctx context.Context, u *upstream, b Backend, hc HealthCheck) {
	// Spread the first checks so ten backends don't all probe at once.
	first := time.Duration(rand.Int64N(int64(min(hc.Interval.D(), 2*time.Second))))
	t := time.NewTimer(first)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		err := probeUpstream(ctx, u.addr, u.tlsConf, b, hc)
		if ctx.Err() != nil {
			return // superseded by a reload mid-check; don't record a spurious failure
		}
		p.onCheck(u, hc, err)
		t.Reset(hc.Interval.D())
	}
}

func (p *pool) onCheck(u *upstream, hc HealthCheck, err error) {
	now := time.Now()
	u.mu.Lock()
	u.lastCheck = now
	if err == nil {
		u.okStreak++
		u.failStreak = 0
		if u.activeDown && u.okStreak >= hc.Rise {
			u.activeDown = false
			u.passiveUntil = time.Time{}
		}
	} else {
		u.failStreak++
		u.okStreak = 0
		u.lastErr, u.lastErrAt = errString(err), now
		if !u.activeDown && u.failStreak >= hc.Fall {
			u.activeDown = true
		}
	}
	changed, up := u.noteLocked(now)
	u.mu.Unlock()
	if changed {
		why := fmt.Sprintf("%d consecutive %s checks passed", hc.Rise, hc.Type)
		if !up {
			why = fmt.Sprintf("%d consecutive %s checks failed: %s", hc.Fall, hc.Type, errString(err))
		}
		p.logState(u, up, why)
	}
}

// probeUpstream performs one health check. It is also used by `ayana-cdn check`.
func probeUpstream(ctx context.Context, addr string, tlsConf *tls.Config, b Backend, hc HealthCheck) error {
	cctx, cancel := context.WithTimeout(ctx, hc.Timeout.D())
	defer cancel()
	var d net.Dialer
	raw, err := d.DialContext(cctx, "tcp", addr)
	if err != nil {
		return err
	}
	defer raw.Close()
	if hc.Type == "tcp" {
		return nil
	}
	conn := raw
	if tlsConf != nil {
		tc := tls.Client(raw, tlsConf)
		if err := tc.HandshakeContext(cctx); err != nil {
			return fmt.Errorf("tls handshake: %w", err)
		}
		conn = tc
		if hc.Type == "tls" {
			return nil
		}
	}
	if dl, ok := cctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	var req strings.Builder
	fmt.Fprintf(&req, "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: ayana-cdn-health/%s\r\n", hc.Path, b.Host, version)
	if hc.Type == "ws" {
		key := make([]byte, 16)
		_, _ = crand.Read(key)
		fmt.Fprintf(&req, "Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: %s\r\n",
			base64.StdEncoding.EncodeToString(key))
	} else {
		req.WriteString("Connection: close\r\n")
	}
	req.WriteString("\r\n")
	if _, err := io.WriteString(conn, req.String()); err != nil {
		return fmt.Errorf("write request: %w", err)
	}
	head, err := readHead(bufio.NewReaderSize(conn, 4096), 16<<10)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	code, err := parseStatusCode(head)
	if err != nil {
		return err
	}
	switch {
	case hc.Expect != 0 && code != hc.Expect:
		return fmt.Errorf("status %d, expected %d", code, hc.Expect)
	case hc.Expect == 0 && hc.Type == "ws" && code != 101:
		return fmt.Errorf("status %d, expected 101", code)
	case hc.Expect == 0 && hc.Type == "http" && code >= 500:
		return fmt.Errorf("status %d", code)
	}
	return nil
}
