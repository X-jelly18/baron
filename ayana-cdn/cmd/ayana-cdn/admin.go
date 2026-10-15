package main

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/pprof"

	"golang.org/x/crypto/bcrypt"
)

// adminHandler serves the local admin endpoints (status, metrics, health, and
// optionally pprof). It is loopback-only by default (admin_listen). When
// admin_user/admin_password_hash are set it additionally requires HTTP Basic
// auth on everything except /healthz, so it can be reached remotely or shared
// on a host without leaking status, upstream addresses or pprof to anyone who
// can open the port. Keep it on loopback or authenticated; never both-off on a
// public address.
func (s *Server) adminHandler(cfg *Config) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		s.writeMetrics(w)
	})
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(s.buildStatus())
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		if s.draining.Load() {
			http.Error(w, "draining", http.StatusServiceUnavailable)
			return
		}
		fmt.Fprintln(w, "ok")
	})
	if cfg.AdminPprof {
		mux.HandleFunc("/debug/pprof/", pprof.Index)
		mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	}
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "ayana-cdn admin: /metrics /status /healthz")
	})
	if cfg.AdminUser != "" && cfg.AdminPasswordHash != "" {
		return adminBasicAuth(cfg.AdminUser, cfg.AdminPasswordHash, mux)
	}
	return mux
}

// adminBasicAuth guards everything but /healthz with HTTP Basic auth. The
// username is compared in constant time and bcrypt runs whether or not it
// matched, so a wrong username is not distinguishable from a wrong password.
func adminBasicAuth(user, hash string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		u, p, ok := r.BasicAuth()
		userOK := subtle.ConstantTimeCompare([]byte(u), []byte(user)) == 1
		passOK := bcrypt.CompareHashAndPassword([]byte(hash), []byte(p)) == nil
		if !ok || !userOK || !passOK {
			w.Header().Set("WWW-Authenticate", `Basic realm="ayana-cdn admin", charset="UTF-8"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
