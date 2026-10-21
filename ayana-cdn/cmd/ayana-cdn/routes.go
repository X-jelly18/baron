package main

import (
	"context"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// backendRT is the runtime form of one configured backend.
type backendRT struct {
	cfg        Backend
	prefix     string // "/native1"
	pool       *pool
	proxy      http.Handler // plain HTTP requests to http/https/sse backends
	stats      *backendStats
	tunnelOnly bool // ws/wss: every request goes through the tunnel path
	udp        bool // reached on its own socket (udp.go), never by path
}

// routeTable is an immutable snapshot, swapped atomically on reload. Requests
// in flight keep the table they started with, so a reload never cuts a tunnel.
type routeTable struct {
	list   []*backendRT // longest prefix first
	byName map[string]*backendRT
	cancel context.CancelFunc // stops this table's health checkers
}

// match returns the backend owning path. The boundary rule (exact match, or
// the next character is '/') keeps /native1 from swallowing /native10.
func (rt *routeTable) match(path string) *backendRT {
	for _, b := range rt.list {
		if hasPathPrefix(path, b.prefix) {
			return b
		}
	}
	return nil
}

func hasPathPrefix(path, prefix string) bool {
	return path == prefix ||
		(len(path) > len(prefix) && path[len(prefix)] == '/' && strings.HasPrefix(path, prefix))
}

func (rt *routeTable) stop() {
	if rt != nil && rt.cancel != nil {
		rt.cancel()
	}
}

// buildRoutes creates the runtime table. Upstream objects of unchanged
// backends are carried over from the previous table so connection counts,
// health state and TLS session caches survive a reload.
func (s *Server) buildRoutes(cfg *Config, old *routeTable) *routeTable {
	ctx, cancel := context.WithCancel(context.Background())
	rt := &routeTable{byName: make(map[string]*backendRT, len(cfg.Backends)), cancel: cancel}
	for _, b := range cfg.Backends {
		var prev *pool
		if old != nil {
			if ob := old.byName[b.Name]; ob != nil {
				prev = ob.pool
			}
		}
		brt := &backendRT{
			cfg:        b,
			prefix:     "/" + b.Name,
			stats:      s.stats.backend(b.Name),
			tunnelOnly: b.isTunnel(),
			udp:        b.isUDP(),
		}
		brt.pool = newPool(b, cfg.Timeouts, prev, s.log)
		if !brt.tunnelOnly && !brt.udp {
			brt.proxy = s.newHTTPProxy(brt, cfg)
		}
		if !b.Disabled {
			brt.pool.startHealthChecks(ctx, b)
		}
		if !brt.udp {
			rt.list = append(rt.list, brt)
		}
		rt.byName[b.Name] = brt
	}
	sort.SliceStable(rt.list, func(i, j int) bool { return len(rt.list[i].prefix) > len(rt.list[j].prefix) })
	return rt
}

// stripPrefix removes prefix from a decoded path; the caller has already
// confirmed the boundary.
func stripPrefix(p, prefix string) string {
	rest := strings.TrimPrefix(p, prefix)
	if rest == "" || rest[0] != '/' {
		rest = "/" + rest
	}
	return rest
}

// cutEscapedPrefix strips prefix from an escaped path, respecting the boundary.
func cutEscapedPrefix(esc, prefix string) (string, bool) {
	if esc == prefix {
		return "/", true
	}
	if strings.HasPrefix(esc, prefix+"/") {
		return esc[len(prefix):], true
	}
	return "", false
}

// backendRequestURI is the origin-form request target sent to a backend. The
// original percent-encoding is kept, so an encoded "%2F" stays encoded.
func backendRequestURI(u *url.URL, prefix string, strip bool) string {
	path := u.EscapedPath()
	if strip {
		if rest, ok := cutEscapedPrefix(path, prefix); ok {
			path = rest
		} else { // the client percent-encoded part of the prefix itself
			path = (&url.URL{Path: stripPrefix(u.Path, prefix)}).EscapedPath()
		}
	}
	if path == "" {
		path = "/"
	}
	if u.RawQuery != "" || u.ForceQuery {
		return path + "?" + u.RawQuery
	}
	return path
}

// setBackendPath applies the same rewrite to a ReverseProxy outbound URL.
func setBackendPath(out, in *url.URL, prefix string, strip bool) {
	if !strip {
		return
	}
	out.Path = stripPrefix(in.Path, prefix)
	out.RawPath = ""
	if rest, ok := cutEscapedPrefix(in.EscapedPath(), prefix); ok && rest != out.Path {
		out.RawPath = rest // net/url uses it only if it is a valid encoding of Path
	}
}
