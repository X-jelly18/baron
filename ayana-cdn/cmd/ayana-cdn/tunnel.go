package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/textproto"
	"strconv"
	"strings"
	"time"
)

const maxResponseHead = 64 << 10

// serveTunnel handles every request to a ws/wss backend, and upgrade requests
// to the other backend types.
//
// Why not httputil.ReverseProxy: its upgrade handling (a) copies from the raw
// connection and silently drops client bytes that net/http had already
// buffered — tunnel clients that send their payload without waiting for the
// 101 lost data, even the first byte of the SSH banner — and (b) rejects any
// 101 without "Upgrade:"/"Connection: Upgrade" headers, which many tunnel
// backends omit. Here the backend's response head is read raw and forwarded
// verbatim, every buffered byte is passed on in both directions, and any 101
// switches the connection to a raw relay.
func (s *Server) serveTunnel(w http.ResponseWriter, r *http.Request, brt *backendRT, st *state, hs *hostStats) {
	b := &brt.cfg
	bs := brt.stats
	to := st.cfg.Timeouts
	always := brt.tunnelOnly && b.Relay == "always"
	start := time.Now()

	// Tunnels (and any request carrying a body here) need HTTP/1.1: an HTTP/2
	// body has no Content-Length/Transfer-Encoding to restate, so it could not
	// be framed to the backend and would be silently dropped. Reject instead.
	if r.ProtoMajor != 1 && (always || r.Header.Get("Upgrade") != "" || r.ContentLength != 0 || len(r.TransferEncoding) > 0) {
		s.respondError(w, r, brt, st, http.StatusHTTPVersionNotSupported, "tunnels need HTTP/1.1", nil, start)
		return
	}
	n := bs.tunnelsActive.Add(1)
	handedOff := false // once true, the relay goroutine owns bconn and the active count
	defer func() {
		if !handedOff {
			bs.tunnelsActive.Add(-1)
		}
	}()
	if b.MaxConns > 0 && n > int64(b.MaxConns) {
		bs.rejectedCap.Add(1)
		s.respondError(w, r, brt, st, http.StatusServiceUnavailable, "backend at capacity", nil, start)
		return
	}

	bconn, up, err := brt.pool.dial(r.Context())
	if err != nil {
		if r.Context().Err() != nil {
			return // client gave up while we were dialing
		}
		bs.tunnelsFailed.Add(1)
		s.respondError(w, r, brt, st, http.StatusBadGateway, "bad gateway", err, start)
		return
	}
	defer func() {
		if !handedOff {
			bconn.Close()
		}
	}()
	// While the tunnel is being set up, a client disconnect aborts backend I/O.
	stop := context.AfterFunc(r.Context(), func() { _ = bconn.SetDeadline(time.Now()) })
	defer stop()
	_ = bconn.SetDeadline(time.Now().Add(to.UpstreamHeader.D()))

	if _, err := bconn.Write(buildRequestHead(r, b, brt.prefix, clientIP(r))); err != nil {
		bs.tunnelsFailed.Add(1)
		s.respondError(w, r, brt, st, http.StatusBadGateway, "bad gateway", fmt.Errorf("write request: %w", err), start)
		return
	}

	if always {
		// Raw from the first byte: whatever the backend answers — a 101, a
		// "200 then raw" payload, or no HTTP at all — goes to the client as is.
		cconn, early, err := takeOver(w)
		if err != nil {
			s.log.Error("hijack failed", "backend", b.Name, "err", err)
			return
		}
		stop()
		if len(early) > 0 {
			if _, err := bconn.Write(early); err != nil {
				cconn.Close()
				return
			}
		}
		_ = bconn.SetDeadline(time.Time{})
		handedOff = true
		go s.runTunnel(brt, st, hs, clientIP(r), cconn, bconn, up, 0, int64(len(early)), 0, true, start)
		return
	}

	if hasBody(r) {
		// Bound a slow/stalled client body (R-U-Dead-Yet) as an idle window,
		// then clear it before any hijack so the relay's own deadlines apply.
		clearBody := guardBody(w, r, to.RequestBody.D())
		err := copyRequestBody(bconn, r)
		clearBody()
		if err != nil {
			bs.tunnelsFailed.Add(1)
			s.respondError(w, r, brt, st, http.StatusBadGateway, "bad gateway", fmt.Errorf("send request body: %w", err), start)
			return
		}
	}

	br := bufio.NewReaderSize(bconn, 4096)
	head, code, err := readResponseHead(br)
	if err != nil {
		if r.Context().Err() != nil {
			return
		}
		bs.tunnelsFailed.Add(1)
		status := http.StatusBadGateway
		if isTimeout(err) {
			status = http.StatusGatewayTimeout
		}
		if errors.Is(err, errNotHTTP) {
			err = errors.New(`backend did not answer with HTTP; for raw backends set "relay": "always"`)
		}
		s.respondError(w, r, brt, st, status, http.StatusText(status), fmt.Errorf("read response: %w", err), start)
		return
	}

	if code != http.StatusSwitchingProtocols {
		s.forwardResponse(w, r, brt, st, hs, head, br, start)
		return
	}

	cconn, early, err := takeOver(w)
	if err != nil {
		s.log.Error("hijack failed", "backend", b.Name, "err", err)
		return
	}
	stop()
	// The backend's 101 exactly as sent, plus anything it sent right after
	// (an SSH server banner often arrives in the same segment).
	out := head
	if n := br.Buffered(); n > 0 {
		extra, _ := br.Peek(n)
		out = append(out, extra...)
	}
	_ = cconn.SetWriteDeadline(time.Now().Add(to.UpstreamHeader.D()))
	if _, err := cconn.Write(out); err != nil {
		cconn.Close()
		return
	}
	_ = cconn.SetWriteDeadline(time.Time{})
	// Bytes the client sent without waiting for the 101 (early data).
	if len(early) > 0 {
		if _, err := bconn.Write(early); err != nil {
			cconn.Close()
			return
		}
	}
	_ = bconn.SetDeadline(time.Time{})
	handedOff = true
	// The relay runs on its own goroutines and the handler returns, so net/http
	// releases this connection's request, buffers and handshake-sized stack.
	// That roughly halves the memory an idle tunnel costs.
	go s.runTunnel(brt, st, hs, clientIP(r), cconn, bconn, up, http.StatusSwitchingProtocols,
		int64(len(early)), int64(len(out)-len(head)), false, start)
}

// takeOver hijacks the client connection and returns the bytes net/http had
// already read past the request head.
func takeOver(w http.ResponseWriter) (net.Conn, []byte, error) {
	conn, brw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return nil, nil, err
	}
	var early []byte
	if n := brw.Reader.Buffered(); n > 0 {
		early, _ = brw.Reader.Peek(n)
	}
	return conn, early, nil
}

// runTunnel relays an established tunnel until it ends. It must not hold on to
// the *http.Request or anything else from the handler.
func (s *Server) runTunnel(brt *backendRT, st *state, hs *hostStats, client string, cconn, bconn net.Conn, up *upstream,
	status int, upPre, downPre int64, sniff bool, start time.Time) {
	b := &brt.cfg
	bs := brt.stats
	defer bs.tunnelsActive.Add(-1)
	hs.active.Add(1)
	defer hs.active.Add(-1)
	to := st.cfg.Timeouts
	idle := to.TunnelIdle.D()
	if b.IdleTimeout > 0 {
		idle = b.IdleTimeout.D()
	}
	t := &tunnel{
		backend: b.Name, upstream: up.addr, client: client, start: start, status: status,
		cconn: cconn, sconn: bconn, idle: idle, stall: to.WriteStall.D(),
	}
	bs.tunnelsTotal.Add(1)
	bs.bytesUp.Add(uint64(upPre))
	bs.bytesDown.Add(uint64(downPre))
	s.tunnels.add(t)
	defer s.tunnels.remove(t)
	reason, upN, downN := t.relay(to.HalfClose.D(), &bs.bytesUp, &bs.bytesDown, sniff)
	hs.bytesUp.Add(uint64(upPre + upN))
	hs.bytesDown.Add(uint64(downPre + downN))
	bs.observeStatus(t.status)
	if st.access {
		s.log.Info("tunnel", "backend", b.Name, "client", t.client, "upstream", t.upstream, "status", t.status,
			"up", upPre+upN, "down", downPre+downN, "duration", time.Since(start).Round(time.Millisecond).String(),
			"reason", reason)
	}
}

// buildRequestHead writes the request head sent to the backend. Client
// headers pass through unchanged (tunnel payloads often depend on odd ones)
// except for hop-by-hop framing and the forwarding headers, which the edge
// sets itself: a client cannot spoof its address to the backend.
func buildRequestHead(r *http.Request, b *Backend, prefix, client string) []byte {
	var buf bytes.Buffer
	proto := r.Proto
	if r.ProtoMajor != 1 {
		proto = "HTTP/1.1"
	}
	fmt.Fprintf(&buf, "%s %s %s\r\nHost: %s\r\n", r.Method, backendRequestURI(r.URL, prefix, b.strip()), proto, b.Host)
	h := r.Header.Clone()
	for _, k := range []string{"Keep-Alive", "Proxy-Connection", "Te", "Trailer", "Transfer-Encoding",
		"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Forwarded-Prefix", "X-Real-Ip"} {
		h.Del(k)
	}
	h.Set("X-Forwarded-For", client)
	h.Set("X-Real-Ip", client)
	h.Set("X-Forwarded-Proto", "https")
	if r.Host != "" {
		h.Set("X-Forwarded-Host", r.Host)
	}
	if b.strip() {
		h.Set("X-Forwarded-Prefix", prefix)
	}
	// Frame the body explicitly. net/http parsed the client's framing into
	// r.TransferEncoding / r.ContentLength and stripped the headers, so if we
	// forward body bytes without re-stating one of them the backend reads an
	// empty body and parses the bytes as a second, smuggled request (CL.0
	// desync). copyRequestBody chunk-frames the TransferEncoding case; a
	// fixed-length body needs its Content-Length restated here.
	if len(r.TransferEncoding) > 0 {
		h.Set("Transfer-Encoding", strings.Join(r.TransferEncoding, ", "))
	} else if r.ContentLength > 0 {
		h.Set("Content-Length", strconv.FormatInt(r.ContentLength, 10))
	}
	_ = h.Write(&buf)
	buf.WriteString("\r\n")
	return buf.Bytes()
}

func hasBody(r *http.Request) bool { return len(r.TransferEncoding) > 0 || r.ContentLength > 0 }

// bodyDeadline bounds a request body by INACTIVITY: it re-arms the connection
// read deadline before every Read, so a body that keeps making progress —
// however large or slow — is never cut, while a trickle or a stall is caught
// after d of silence. A single absolute deadline would instead sever a
// legitimate large upload once it exceeded d regardless of throughput.
type bodyDeadline struct {
	rc  *http.ResponseController
	d   time.Duration
	src io.ReadCloser
}

func (b *bodyDeadline) Read(p []byte) (int, error) {
	_ = b.rc.SetReadDeadline(time.Now().Add(b.d))
	return b.src.Read(p)
}

func (b *bodyDeadline) Close() error { return b.src.Close() }

// guardBody wraps r.Body with an idle deadline when one is configured and the
// request has a body; it returns a cleanup that clears the deadline.
func guardBody(w http.ResponseWriter, r *http.Request, d time.Duration) func() {
	if d <= 0 || !hasBody(r) {
		return func() {}
	}
	rc := http.NewResponseController(w)
	r.Body = &bodyDeadline{rc: rc, d: d, src: r.Body}
	return func() { _ = rc.SetReadDeadline(time.Time{}) }
}

func copyRequestBody(dst io.Writer, r *http.Request) error {
	if len(r.TransferEncoding) > 0 {
		cw := httputil.NewChunkedWriter(dst)
		if _, err := io.Copy(cw, r.Body); err != nil {
			return err
		}
		if err := cw.Close(); err != nil {
			return err
		}
		_, err := io.WriteString(dst, "\r\n")
		return err
	}
	_, err := io.CopyN(dst, r.Body, r.ContentLength)
	return err
}

// readResponseHead reads the backend's response head, skipping interim 1xx
// responses other than 101.
func readResponseHead(br *bufio.Reader) ([]byte, int, error) {
	for i := 0; i < 8; i++ {
		// Fail fast on a backend that does not speak HTTP (an SSH banner, a raw
		// payload) instead of waiting for a head that will never arrive.
		if p, err := br.Peek(5); err == nil && p[0] != '\r' && p[0] != '\n' && string(p) != "HTTP/" {
			return nil, 0, errNotHTTP
		}
		head, err := readHead(br, maxResponseHead)
		if err != nil {
			return nil, 0, err
		}
		code, err := parseStatusCode(head)
		if err != nil {
			return nil, 0, err
		}
		if code >= 100 && code < 200 && code != http.StatusSwitchingProtocols {
			continue
		}
		return head, code, nil
	}
	return nil, 0, errors.New("too many interim responses")
}

var hopHeaders = []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade"}

func removeHopHeaders(h http.Header) {
	for _, f := range h["Connection"] {
		for _, name := range strings.Split(f, ",") {
			if name = textproto.TrimString(name); name != "" {
				h.Del(name)
			}
		}
	}
	for _, k := range hopHeaders {
		h.Del(k)
	}
}

// forwardResponse relays an ordinary (non-101) backend response through
// net/http; the backend connection is closed afterwards by the caller.
func (s *Server) forwardResponse(w http.ResponseWriter, r *http.Request, brt *backendRT, st *state, hs *hostStats,
	head []byte, br *bufio.Reader, start time.Time) {
	resp, err := http.ReadResponse(bufio.NewReader(io.MultiReader(bytes.NewReader(head), br)), r)
	if err != nil {
		brt.stats.tunnelsFailed.Add(1)
		s.respondError(w, r, brt, st, http.StatusBadGateway, "bad gateway", fmt.Errorf("parse response: %w", err), start)
		return
	}
	defer resp.Body.Close()
	dst := w.Header()
	for k, vv := range resp.Header {
		dst[k] = append([]string(nil), vv...)
	}
	removeHopHeaders(dst)
	w.WriteHeader(resp.StatusCode)
	n, _ := copyFlushing(w, resp.Body, resp.ContentLength < 0)
	brt.stats.observeStatus(resp.StatusCode)
	brt.stats.bytesDown.Add(uint64(n))
	hs.bytesDown.Add(uint64(n))
	if st.access {
		s.log.Info("http", "backend", brt.cfg.Name, "client", clientIP(r), "method", r.Method,
			"path", truncate(r.URL.Path, 200), "status", resp.StatusCode, "bytes", n,
			"duration", time.Since(start).Round(time.Millisecond).String())
	}
}

// copyFlushing copies a response body, flushing after each chunk for
// streams of unknown length (SSE, long-polling).
func copyFlushing(w http.ResponseWriter, body io.Reader, flush bool) (int64, error) {
	rc := http.NewResponseController(w)
	bp := bigBufs.Get().(*[]byte) // reuse the relay's 32 KiB pool instead of allocating per response
	defer bigBufs.Put(bp)
	buf := *bp
	var total int64
	for {
		n, err := body.Read(buf)
		if n > 0 {
			wn, werr := w.Write(buf[:n])
			total += int64(wn)
			if werr != nil {
				return total, werr
			}
			if flush {
				_ = rc.Flush()
			}
		}
		if err == io.EOF {
			return total, nil
		}
		if err != nil {
			return total, err
		}
	}
}

// respondError sends an edge-generated error response and logs it.
func (s *Server) respondError(w http.ResponseWriter, r *http.Request, brt *backendRT, st *state,
	code int, msg string, cause error, start time.Time) {
	http.Error(w, msg, code)
	name := ""
	if brt != nil {
		brt.stats.observeStatus(code)
		name = brt.cfg.Name
	}
	if st.access || (cause != nil && code >= 500) {
		attrs := []any{"backend", name, "client", clientIP(r), "method", r.Method,
			"path", truncate(r.URL.Path, 200), "status", code,
			"duration", time.Since(start).Round(time.Millisecond).String()}
		if cause != nil {
			attrs = append(attrs, "err", errString(cause))
		}
		s.log.Info("http", attrs...)
	}
}
