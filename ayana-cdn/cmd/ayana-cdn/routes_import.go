package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"sort"
	"strings"
)

// routes.json is the format of the small Express/http-proxy relays used on
// Cloud Run: a JSON object mapping a path prefix to a target URL. The import
// keeps those semantics: the path is forwarded unchanged and the Host header
// becomes the target's hostname (http-proxy's changeOrigin).

const routesUsage = `usage: ayana-cdn routes import FILE [-replace] [-no-reload] [-config FILE]

FILE is a routes.json: a JSON object mapping a path prefix to where it goes.
  "/s1": "http://host"                                plain WebSocket backend (port 80)
  "/s2": "https://host:8443"                          TLS backend
  "/s3": {"target": "http://1.2.3.4", "host": "name.example", "insecure": true}
A path connects to exactly one target: no load balancing, no failover. To use
several servers, give each its own path ("/s3": "http://a", "/s4": "http://b").
The path is forwarded unchanged and the Host header is the target's hostname
unless "host" is given. Without -replace, backends that are not in FILE are kept.`

type routeSpec struct {
	Target   string   `json:"target"`
	Targets  []string `json:"targets"`
	Host     string   `json:"host"`
	Insecure bool     `json:"insecure"`
}

// parseRoutes converts a routes.json document into backends, sorted by name.
func parseRoutes(data []byte) ([]Backend, error) {
	raw, err := decodeRouteObject(data)
	if err != nil {
		return nil, err
	}
	var out []Backend
	for path, val := range raw {
		b, err := parseRoute(path, val)
		if err != nil {
			return nil, fmt.Errorf("route %q: %w", path, err)
		}
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// decodeRouteObject reads the top-level routes object token by token so a
// duplicate path (a copy-paste mistake) is reported instead of being silently
// collapsed to the last value, which Go's map decoder would do.
func decodeRouteObject(data []byte) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("routes file: %w", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, errors.New("routes file: expected a JSON object mapping paths to targets")
	}
	out := map[string]json.RawMessage{}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("routes file: %w", err)
		}
		key := keyTok.(string)
		if _, dup := out[key]; dup {
			return nil, fmt.Errorf("routes file: path %q is listed more than once", key)
		}
		var val json.RawMessage
		if err := dec.Decode(&val); err != nil {
			return nil, fmt.Errorf("routes file: path %q: %w", key, err)
		}
		out[key] = val
	}
	if _, err := dec.Token(); err != nil { // consume the closing '}'
		return nil, fmt.Errorf("routes file: %w", err)
	}
	if _, err := dec.Token(); err == nil {
		return nil, errors.New("routes file: unexpected data after the JSON object")
	}
	return out, nil
}

func parseRoute(path string, val json.RawMessage) (Backend, error) {
	name := strings.Trim(path, "/")
	if !strings.HasPrefix(path, "/") || name == "" {
		return Backend{}, errors.New(`the path must start with "/"`)
	}
	if strings.Contains(name, "/") {
		return Backend{}, errors.New("nested paths are not supported; routes are matched on the first path segment")
	}
	var spec routeSpec
	switch trimmed := bytes.TrimSpace(val); {
	case len(trimmed) == 0:
		return Backend{}, errors.New("empty value")
	case trimmed[0] == '"':
		if err := json.Unmarshal(trimmed, &spec.Target); err != nil {
			return Backend{}, err
		}
	case trimmed[0] == '[':
		if err := json.Unmarshal(trimmed, &spec.Targets); err != nil {
			return Backend{}, err
		}
	case trimmed[0] == '{':
		dec := json.NewDecoder(bytes.NewReader(trimmed))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&spec); err != nil {
			return Backend{}, err
		}
	default:
		return Backend{}, errors.New("the value must be a URL, a list of URLs, or an object")
	}
	targets := spec.Targets
	if spec.Target != "" {
		targets = append([]string{spec.Target}, targets...)
	}
	if len(targets) == 0 {
		return Backend{}, errors.New("no target URL")
	}
	// A list (or "targets") with one URL is still accepted: older setup.sh
	// runs wrote routes that way. Two URLs for the same server count once.
	var first string
	var useTLS bool
	seen := map[string]bool{}
	var distinct []string
	for _, t := range targets {
		addr, tls, err := parseTarget(t)
		if err != nil {
			return Backend{}, err
		}
		if !seen[addr+fmt.Sprint(tls)] {
			seen[addr+fmt.Sprint(tls)] = true
			distinct = append(distinct, t)
			if len(distinct) == 1 {
				first, useTLS = addr, tls
			}
		}
	}
	if len(distinct) > 1 {
		return Backend{}, fmt.Errorf("lists %d targets (%s), but a path connects to exactly one server: "+
			"give each server its own path, e.g. %q: %q, %q: %q",
			len(distinct), strings.Join(distinct, ", "), "/"+name, distinct[0], "/"+name+"-2", distinct[1])
	}
	b := Backend{Name: name, Upstream: first, Proto: "ws", Host: spec.Host, Strip: ptr(false), Insecure: spec.Insecure}
	if useTLS {
		b.Proto = "wss"
	}
	return b, nil
}

// parseTarget turns "http://host[:port]" into host:port and whether it is TLS.
func parseTarget(t string) (string, bool, error) {
	u, err := url.Parse(t)
	if err != nil {
		return "", false, fmt.Errorf("target %q: %w", t, err)
	}
	var useTLS bool
	switch strings.ToLower(u.Scheme) {
	case "http", "ws":
	case "https", "wss":
		useTLS = true
	default:
		return "", false, fmt.Errorf("target %q: the scheme must be http, https, ws or wss", t)
	}
	if u.Hostname() == "" || u.User != nil {
		return "", false, fmt.Errorf("target %q: expected scheme://host[:port]", t)
	}
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return "", false, fmt.Errorf("target %q: a path in the target is not supported; the client's path is forwarded unchanged", t)
	}
	port := u.Port()
	if port == "" {
		port = "80"
		if useTLS {
			port = "443"
		}
	}
	return net.JoinHostPort(u.Hostname(), port), useTLS, nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func cmdRoutes(args []string) error {
	if len(args) == 0 || args[0] != "import" {
		return errors.New(routesUsage)
	}
	fs := flag.NewFlagSet("routes import", flag.ContinueOnError)
	cfgPath := fs.String("config", defaultConfigPath, "config file")
	replace := fs.Bool("replace", false, "drop backends that are not in FILE")
	noReload := fs.Bool("no-reload", false, "edit the file only; do not signal the running edge")
	pos, err := parseInterspersed(fs, args[1:])
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New(routesUsage)
	}
	data, err := os.ReadFile(pos[0])
	if err != nil {
		return err
	}
	backends, err := parseRoutes(data)
	if err != nil {
		return err
	}
	if len(backends) == 0 {
		return errors.New("the routes file has no routes")
	}
	return editConfig(*cfgPath, *noReload, func(c *Config) (string, error) {
		imported := make(map[string]bool, len(backends))
		for _, b := range backends {
			imported[b.Name] = true
		}
		// A routes.json describes only ws/wss backends. If an imported path
		// collides with an existing UDP backend of the same name, replacing it
		// would silently delete a working UDP listener, so refuse with a clear
		// message instead (rename the route or remove the udp backend first).
		var udpClash []string
		for _, old := range c.Backends {
			if old.isUDP() && imported[old.Name] {
				udpClash = append(udpClash, old.Name)
			}
		}
		if len(udpClash) > 0 {
			return "", fmt.Errorf("route name(s) collide with existing udp backend(s): %s; rename the route(s) or remove the udp backend(s) first",
				strings.Join(udpClash, ", "))
		}
		var others []string
		var kept []Backend
		for _, old := range c.Backends {
			if !imported[old.Name] {
				others = append(others, old.Name)
				kept = append(kept, old)
			}
		}
		var msg strings.Builder
		fmt.Fprintf(&msg, "imported %d route(s) from %s:\n", len(backends), pos[0])
		for _, b := range backends {
			fmt.Fprintf(&msg, "  /%-12s -> %s (%s)\n", b.Name, b.Upstream, b.Proto)
		}
		if *replace {
			// A routes.json can only describe ws/wss backends. UDP backends
			// have no representation here, so -replace keeps them rather than
			// silently deleting a working listener.
			var udpKept []string
			result := backends
			for _, old := range c.Backends {
				if old.isUDP() && !imported[old.Name] {
					result = append(result, old)
					udpKept = append(udpKept, old.Name)
				}
			}
			c.Backends = result
			var droppedNames []string
			for _, name := range others {
				if !contains(udpKept, name) {
					droppedNames = append(droppedNames, name)
				}
			}
			if len(droppedNames) > 0 {
				fmt.Fprintf(&msg, "dropped %d backend(s) not in the file: %s\n", len(droppedNames), strings.Join(droppedNames, ", "))
			}
			if len(udpKept) > 0 {
				fmt.Fprintf(&msg, "kept %d udp backend(s) (not expressible in routes.json): %s", len(udpKept), strings.Join(udpKept, ", "))
			}
		} else {
			c.Backends = append(backends, kept...)
			if len(others) > 0 {
				fmt.Fprintf(&msg, "kept %d other backend(s): %s (use -replace to drop them)", len(others), strings.Join(others, ", "))
			}
		}
		return strings.TrimRight(msg.String(), "\n"), nil
	})
}
