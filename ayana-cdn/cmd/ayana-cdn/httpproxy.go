package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httputil"
	"time"
)

// newHTTPProxy builds the handler for ordinary (non-upgrade) requests to
// http/https/sse backends. Connections come from the backend's pool, so
// failover and health checks apply here too; keep-alive connections are
// reused through the Transport.
func (s *Server) newHTTPProxy(brt *backendRT, cfg *Config) http.Handler {
	b := brt.cfg
	scheme := "http"
	if b.useTLS() {
		scheme = "https"
	}
	p := brt.pool
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		c, _, err := p.dial(ctx)
		return c, err
	}
	tr := &http.Transport{
		Proxy:                 nil,
		MaxIdleConns:          512,
		MaxIdleConnsPerHost:   128,
		IdleConnTimeout:       60 * time.Second,
		ResponseHeaderTimeout: cfg.Timeouts.UpstreamHeader.D(),
		ExpectContinueTimeout: time.Second,
		WriteBufferSize:       64 << 10, // fewer syscalls on bulk HTTP backends
		ReadBufferSize:        64 << 10,
		ForceAttemptHTTP2:     false, // the pool hands over plain conns; HTTP/1.1 keep-alive is reused
	}
	if b.useTLS() {
		tr.DialTLSContext = dial // the pool performs the TLS handshake
	} else {
		tr.DialContext = dial
	}
	prefix, strip, host := brt.prefix, b.strip(), b.Host
	return &httputil.ReverseProxy{
		Transport:     tr,
		FlushInterval: -1, // stream immediately: SSE, long-polling
		ErrorLog:      httpErrorLog(s.log, "proxy"),
		Rewrite: func(pr *httputil.ProxyRequest) {
			// Rewrite mode has already removed client-supplied forwarding
			// headers; set trustworthy ones.
			pr.SetXForwarded()
			pr.Out.Header.Set("X-Real-Ip", clientIP(pr.In))
			pr.Out.URL.Scheme = scheme
			pr.Out.URL.Host = b.Name + ".upstream" // connection-pool key; the pool picks the address
			pr.Out.Host = host
			setBackendPath(pr.Out.URL, pr.In.URL, prefix, strip)
			// ReverseProxy's Rewrite mode strips client X-Forwarded-For/Host/Proto
			// but not X-Forwarded-Prefix, so drop any client-supplied one before
			// we (maybe) set our own, matching the tunnel path.
			pr.Out.Header.Del("X-Forwarded-Prefix")
			if strip {
				pr.Out.Header.Set("X-Forwarded-Prefix", prefix)
			}
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if r.Context().Err() != nil {
				return // client went away
			}
			brt.stats.tunnelsFailed.Add(1)
			s.log.Warn("backend request failed", "backend", b.Name, "client", clientIP(r), "err", errString(err))
			w.WriteHeader(http.StatusBadGateway)
		},
	}
}

func (s *Server) serveHTTPProxy(w http.ResponseWriter, r *http.Request, brt *backendRT, st *state, hs *hostStats) {
	start := time.Now()
	b := &brt.cfg
	hs.active.Add(1)
	defer hs.active.Add(-1)
	// Enforce the backend's max_conns here too: it was previously honoured only
	// on the tunnel path, so a plain http/https/sse backend's cap was silently
	// ignored and a burst went straight to a fragile origin.
	n := brt.stats.tunnelsActive.Add(1)
	defer brt.stats.tunnelsActive.Add(-1)
	if b.MaxConns > 0 && n > int64(b.MaxConns) {
		brt.stats.rejectedCap.Add(1)
		s.respondError(w, r, brt, st, http.StatusServiceUnavailable, "backend at capacity", nil, start)
		return
	}
	// Bound a slow/stalled request body (R-U-Dead-Yet) as an idle window on the
	// body read; GET/SSE requests have no body so this never arms, and it never
	// touches a streaming response.
	defer guardBody(w, r, st.cfg.Timeouts.RequestBody.D())()
	rec := &statusRecorder{ResponseWriter: w}
	brt.proxy.ServeHTTP(rec, r)
	code := rec.code
	if code == 0 {
		code = http.StatusOK
	}
	brt.stats.observeStatus(code)
	brt.stats.bytesDown.Add(uint64(rec.bytes))
	hs.bytesDown.Add(uint64(rec.bytes))
	if r.ContentLength > 0 {
		brt.stats.bytesUp.Add(uint64(r.ContentLength))
		hs.bytesUp.Add(uint64(r.ContentLength))
	}
	if st.access {
		s.log.Info("http", "backend", brt.cfg.Name, "client", clientIP(r), "method", r.Method,
			"path", truncate(r.URL.Path, 200), "status", code, "bytes", rec.bytes,
			"duration", time.Since(start).Round(time.Millisecond).String())
	}
}

// statusRecorder captures the status and size of a response. Unwrap keeps
// http.ResponseController (flushing) working through it.
type statusRecorder struct {
	http.ResponseWriter
	code  int
	bytes int64
}

func (r *statusRecorder) WriteHeader(code int) {
	if r.code == 0 && code >= 200 { // 1xx interim responses are not the final status
		r.code = code
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(p []byte) (int, error) {
	if r.code == 0 {
		r.code = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(p)
	r.bytes += int64(n)
	return n, err
}

func (r *statusRecorder) Flush() { _ = http.NewResponseController(r.ResponseWriter).Flush() }

func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }
