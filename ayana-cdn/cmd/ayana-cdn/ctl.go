package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"
)

// ---- flag helpers ------------------------------------------------------------------

// parseInterspersed allows flags before, between and after positional
// arguments; Go's flag package alone stops at the first positional one.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if used := len(args) - len(rest); used > 0 && args[used-1] == "--" {
			return append(pos, rest...), nil
		}
		if len(rest) == 0 {
			return pos, nil
		}
		pos = append(pos, rest[0])
		args = rest[1:]
	}
}

// Optional flag values remember whether they were given, so `backend set`
// only touches the fields the operator named.
type optString struct {
	v   string
	set bool
}

func (o *optString) String() string {
	if o == nil {
		return ""
	}
	return o.v
}
func (o *optString) Set(s string) error { o.v, o.set = s, true; return nil }

type optBool struct{ v, set bool }

func (o *optBool) String() string {
	if o == nil {
		return "false"
	}
	return strconv.FormatBool(o.v)
}
func (o *optBool) IsBoolFlag() bool { return true }
func (o *optBool) Set(s string) error {
	b, err := strconv.ParseBool(s)
	if err != nil {
		return err
	}
	o.v, o.set = b, true
	return nil
}

type optInt struct {
	v   int
	set bool
}

func (o *optInt) String() string {
	if o == nil {
		return "0"
	}
	return strconv.Itoa(o.v)
}
func (o *optInt) Set(s string) error {
	n, err := strconv.Atoi(s)
	if err != nil {
		return err
	}
	o.v, o.set = n, true
	return nil
}

type optDur struct {
	v   time.Duration
	set bool
}

func (o *optDur) String() string {
	if o == nil {
		return "0s"
	}
	return o.v.String()
}
func (o *optDur) Set(s string) error {
	d, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	o.v, o.set = d, true
	return nil
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// ---- backend commands ---------------------------------------------------------------

const backendUsage = `usage:
  ayana-cdn backend ls [-json]
  ayana-cdn backend add <name> <host:port>[,<host:port>...] [flags]
  ayana-cdn backend add <name> <host:port> -proto udp -listen :PORT   (a UDP backend on its own port)
  ayana-cdn backend set <name> [flags]
  ayana-cdn backend rm <name>
  ayana-cdn backend enable|disable <name>
flags for add/set (any order, before or after the arguments):
  -host NAME           Host header and TLS SNI sent to the backend
  -proto P             wss (default) | ws | https | http | sse | udp
  -listen ADDR         udp only: the address that receives the datagrams, e.g. :36712
  -tls[=false]         TLS to the backend (default follows -proto)
  -strip[=false]       remove /<name> from the path (default true)
  -insecure            do not verify the backend certificate
  -lb POLICY           least_conn (default) | round_robin | first
  -relay MODE          upgrade (default) | always (ws/wss: raw relay from the first byte)
  -max-conns N         cap concurrent tunnels or udp sessions (0 = no cap)
  -idle-timeout DUR    close idle tunnels or udp sessions after DUR
  -check TYPE          health check: tcp | tls | http | ws | off
  -check-path PATH     -check-interval DUR     -check-expect STATUS
  -upstreams LIST      (set only) replace the upstream list
  -disabled[=false]    -no-reload    -config FILE`

type backendFlags struct {
	upstreams, host, proto, listen, lb, relay, check, checkPath optString
	tlsF, strip, insecure, disabled                             optBool
	maxConns, checkExpect                                       optInt
	idle, checkInterval, checkTimeout                           optDur
	noReload                                                    bool
}

func (f *backendFlags) register(fs *flag.FlagSet, withUpstreams bool) {
	if withUpstreams {
		fs.Var(&f.upstreams, "upstreams", "replace the upstream list (comma-separated host:port)")
	}
	fs.Var(&f.host, "host", "Host header and TLS SNI sent to the backend")
	fs.Var(&f.proto, "proto", "wss | ws | https | http | sse | udp")
	fs.Var(&f.listen, "listen", "udp only: address that receives the datagrams")
	fs.Var(&f.tlsF, "tls", "TLS to the backend (default follows proto)")
	fs.Var(&f.strip, "strip", "strip /<name> from the path")
	fs.Var(&f.insecure, "insecure", "do not verify the backend certificate")
	fs.Var(&f.disabled, "disabled", "answer 503 instead of proxying")
	fs.Var(&f.lb, "lb", "least_conn | round_robin | first")
	fs.Var(&f.relay, "relay", "upgrade | always")
	fs.Var(&f.maxConns, "max-conns", "cap concurrent tunnels (0 = no cap)")
	fs.Var(&f.idle, "idle-timeout", "close idle tunnels after this long")
	fs.Var(&f.check, "check", "health check: tcp | tls | http | ws | off")
	fs.Var(&f.checkPath, "check-path", "path for http/ws health checks")
	fs.Var(&f.checkInterval, "check-interval", "health check interval")
	fs.Var(&f.checkTimeout, "check-timeout", "health check timeout (<= interval)")
	fs.Var(&f.checkExpect, "check-expect", "expected status for http/ws health checks")
	fs.BoolVar(&f.noReload, "no-reload", false, "edit the file only; do not signal the running edge")
}

func (f *backendFlags) apply(b *Backend) {
	if f.upstreams.set {
		b.Upstream, b.Upstreams = "", splitList(f.upstreams.v)
	}
	if f.host.set {
		b.Host = f.host.v
	}
	if f.listen.set {
		b.Listen = f.listen.v
	}
	if f.proto.set {
		b.Proto = strings.ToLower(f.proto.v)
		if !f.tlsF.set {
			b.TLS = nil // follow the new proto instead of a stale explicit value
		}
	}
	if f.tlsF.set {
		b.TLS = ptr(f.tlsF.v)
	}
	if f.strip.set {
		b.Strip = ptr(f.strip.v)
	}
	if f.insecure.set {
		b.Insecure = f.insecure.v
	}
	if f.disabled.set {
		b.Disabled = f.disabled.v
	}
	if f.lb.set {
		b.LB = f.lb.v
	}
	if f.relay.set {
		b.Relay = f.relay.v
	}
	if f.maxConns.set {
		b.MaxConns = f.maxConns.v
	}
	if f.idle.set {
		b.IdleTimeout = Duration(f.idle.v)
	}
	if f.check.set || f.checkPath.set || f.checkInterval.set || f.checkTimeout.set || f.checkExpect.set {
		if b.HealthCheck == nil {
			b.HealthCheck = &HealthCheck{}
		}
		if f.check.set {
			b.HealthCheck.Type = f.check.v
		}
		if f.checkPath.set {
			b.HealthCheck.Path = f.checkPath.v
		}
		if f.checkInterval.set {
			b.HealthCheck.Interval = Duration(f.checkInterval.v)
		}
		if f.checkTimeout.set {
			b.HealthCheck.Timeout = Duration(f.checkTimeout.v)
		}
		if f.checkExpect.set {
			b.HealthCheck.Expect = f.checkExpect.v
		}
	}
}

func cmdBackend(args []string) error {
	if len(args) == 0 {
		return errors.New(backendUsage)
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "ls", "list":
		return backendList(rest)
	case "add":
		return backendAdd(rest)
	case "set", "edit":
		return backendSet(rest)
	case "rm", "remove", "delete":
		return backendRemove(rest)
	case "enable", "disable":
		return backendToggle(sub, rest)
	}
	return fmt.Errorf("unknown backend command %q\n%s", sub, backendUsage)
}

// editConfig applies fn to the raw config under a lock, validates the result
// and saves it atomically; nothing is written if validation fails.
func editConfig(path string, noReload bool, fn func(*Config) (string, error)) error {
	var msg string
	err := withConfigLock(path, func() error {
		raw, err := loadRaw(path)
		if err != nil {
			return err
		}
		m, err := fn(raw)
		if err != nil {
			return err
		}
		eff, err := raw.Effective()
		if err != nil {
			return fmt.Errorf("change rejected, config not modified: %w", err)
		}
		for _, w := range eff.warnings {
			fmt.Fprintln(os.Stderr, "warning:", w)
		}
		if err := saveRaw(path, raw); err != nil {
			return err
		}
		msg = m
		return nil
	})
	if err != nil {
		return err
	}
	fmt.Println(msg)
	if !noReload {
		fmt.Println(signalReload(defaultPIDFile))
	}
	return nil
}

func findBackend(c *Config, name string) *Backend {
	for i := range c.Backends {
		if c.Backends[i].Name == name {
			return &c.Backends[i]
		}
	}
	return nil
}

func backendAdd(args []string) error {
	fs := flag.NewFlagSet("backend add", flag.ContinueOnError)
	cfgPath := fs.String("config", defaultConfigPath, "config file")
	var f backendFlags
	f.register(fs, false)
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 2 {
		return errors.New("usage: ayana-cdn backend add <name> <host:port>[,<host:port>...] [flags]")
	}
	name, ups := pos[0], splitList(pos[1])
	return editConfig(*cfgPath, f.noReload, func(c *Config) (string, error) {
		if findBackend(c, name) != nil {
			return "", fmt.Errorf("backend %q already exists (change it with: ayana-cdn backend set %s ...)", name, name)
		}
		b := Backend{Name: name}
		if len(ups) == 1 {
			b.Upstream = ups[0]
		} else {
			b.Upstreams = ups
		}
		f.apply(&b)
		c.Backends = append(c.Backends, b)
		if strings.EqualFold(b.Proto, "udp") {
			return fmt.Sprintf("added udp backend %q -> %s (listening on %s; needs `ayana-cdn restart` to bind the socket)",
				name, strings.Join(ups, ", "), b.Listen), nil
		}
		return fmt.Sprintf("added backend %q -> %s (clients use path /%s/)", name, strings.Join(ups, ", "), name), nil
	})
}

func backendSet(args []string) error {
	fs := flag.NewFlagSet("backend set", flag.ContinueOnError)
	cfgPath := fs.String("config", defaultConfigPath, "config file")
	var f backendFlags
	f.register(fs, true)
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: ayana-cdn backend set <name> [flags]")
	}
	changes := 0
	fs.Visit(func(fl *flag.Flag) {
		if fl.Name != "config" && fl.Name != "no-reload" {
			changes++
		}
	})
	if changes == 0 {
		return errors.New("nothing to change; see: ayana-cdn backend (for the flag list)")
	}
	return editConfig(*cfgPath, f.noReload, func(c *Config) (string, error) {
		b := findBackend(c, pos[0])
		if b == nil {
			return "", fmt.Errorf("no backend named %q", pos[0])
		}
		f.apply(b)
		return fmt.Sprintf("updated backend %q", pos[0]), nil
	})
}

func backendRemove(args []string) error {
	fs := flag.NewFlagSet("backend rm", flag.ContinueOnError)
	cfgPath := fs.String("config", defaultConfigPath, "config file")
	noReload := fs.Bool("no-reload", false, "edit the file only")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: ayana-cdn backend rm <name>")
	}
	return editConfig(*cfgPath, *noReload, func(c *Config) (string, error) {
		for i := range c.Backends {
			if c.Backends[i].Name == pos[0] {
				c.Backends = append(c.Backends[:i], c.Backends[i+1:]...)
				return fmt.Sprintf("removed backend %q (open tunnels to it keep running until they close)", pos[0]), nil
			}
		}
		return "", fmt.Errorf("no backend named %q", pos[0])
	})
}

func backendToggle(sub string, args []string) error {
	fs := flag.NewFlagSet("backend "+sub, flag.ContinueOnError)
	cfgPath := fs.String("config", defaultConfigPath, "config file")
	noReload := fs.Bool("no-reload", false, "edit the file only")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("usage: ayana-cdn backend %s <name>", sub)
	}
	return editConfig(*cfgPath, *noReload, func(c *Config) (string, error) {
		b := findBackend(c, pos[0])
		if b == nil {
			return "", fmt.Errorf("no backend named %q", pos[0])
		}
		b.Disabled = sub == "disable"
		return fmt.Sprintf("%sd backend %q", sub, pos[0]), nil
	})
}

func backendList(args []string) error {
	fs := flag.NewFlagSet("backend ls", flag.ContinueOnError)
	cfgPath := fs.String("config", defaultConfigPath, "config file")
	asJSON := fs.Bool("json", false, "print the effective backend list as JSON")
	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}
	cfg, err := LoadConfig(*cfgPath)
	if err != nil {
		return err
	}
	if *asJSON {
		out, _ := json.MarshalIndent(cfg.Backends, "", "  ")
		fmt.Println(string(out))
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tPATH\tPROTO\tUPSTREAMS\tHOST\tNOTES")
	for _, b := range cfg.Backends {
		var notes []string
		if b.Disabled {
			notes = append(notes, "DISABLED")
		}
		if b.Insecure {
			notes = append(notes, "insecure")
		}
		if b.Relay == "always" {
			notes = append(notes, "relay=always")
		}
		if !b.strip() {
			notes = append(notes, "strip=false")
		}
		if len(b.Upstreams) > 1 {
			notes = append(notes, "lb="+b.LB)
		}
		if b.MaxConns > 0 {
			notes = append(notes, fmt.Sprintf("max_conns=%d", b.MaxConns))
		}
		notes = append(notes, "check="+b.HealthCheck.Type)
		path, host := "/"+b.Name+"/", b.Host
		if b.isUDP() {
			path, host = "udp "+b.Listen, ""
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", b.Name, path, b.Proto, strings.Join(b.Upstreams, ","), host, strings.Join(notes, " "))
	}
	return tw.Flush()
}

// ---- process control ------------------------------------------------------------------

func processAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

// runningPID finds the serving process: systemd's MainPID first, then the pid file.
func runningPID(pidFile string) (int, string) {
	if _, err := exec.LookPath("systemctl"); err == nil {
		out, err := exec.Command("systemctl", "show", "--property=MainPID", "--value", "ayana-cdn.service").Output()
		if err == nil {
			if pid, _ := strconv.Atoi(strings.TrimSpace(string(out))); pid > 0 && processAlive(pid) {
				return pid, "systemd"
			}
		}
	}
	if b, err := os.ReadFile(pidFile); err == nil {
		if pid, _ := strconv.Atoi(strings.TrimSpace(string(b))); pid > 0 && processAlive(pid) {
			return pid, "pid file"
		}
	}
	return 0, ""
}

func signalReload(pidFile string) string {
	pid, how := runningPID(pidFile)
	if pid == 0 {
		return "the edge is not running; the change applies when it starts"
	}
	if err := syscall.Kill(pid, syscall.SIGHUP); err != nil {
		return fmt.Sprintf("could not signal pid %d: %v (run: systemctl reload ayana-cdn)", pid, err)
	}
	return fmt.Sprintf("reload signal sent to pid %d (%s); verify with: ayana-cdn status", pid, how)
}

var adminClient = &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil}}

func adminURL(addr, path string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "http://" + addr + path
	}
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port) + path
}

func fetchStatus(addr string) (*statusDoc, []byte, error) {
	resp, err := adminClient.Get(adminURL(addr, "/status"))
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var doc statusDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, nil, fmt.Errorf("unexpected /status answer: %w", err)
	}
	return &doc, raw, nil
}

func cmdReload(args []string) error {
	fs := flag.NewFlagSet("reload", flag.ContinueOnError)
	cfgPath := fs.String("config", defaultConfigPath, "config file")
	pidFile := fs.String("pidfile", defaultPIDFile, "pid file used when systemd is not available")
	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}
	cfg, err := LoadConfig(*cfgPath)
	if err != nil {
		return fmt.Errorf("not reloading, the config is invalid: %w", err)
	}
	for _, w := range cfg.warnings {
		fmt.Fprintln(os.Stderr, "warning:", w)
	}
	pid, how := runningPID(*pidFile)
	if pid == 0 {
		return errors.New("ayana-cdn is not running")
	}
	var before uint64
	if cfg.AdminListen != "off" {
		if d, _, err := fetchStatus(cfg.AdminListen); err == nil && d.PID == pid {
			before = d.Generation
		}
	}
	if err := syscall.Kill(pid, syscall.SIGHUP); err != nil {
		return fmt.Errorf("signal pid %d: %w", pid, err)
	}
	if before == 0 {
		fmt.Printf("reload signal sent to pid %d (%s)\n", pid, how)
		return nil
	}
	for i := 0; i < 30; i++ {
		time.Sleep(100 * time.Millisecond)
		if d, _, err := fetchStatus(cfg.AdminListen); err == nil && d.Generation > before {
			fmt.Printf("reloaded: pid %d, config generation %d -> %d, %d backends\n", pid, before, d.Generation, len(d.Backends))
			return nil
		}
	}
	return errors.New("the edge did not apply the config; see: journalctl -u ayana-cdn -n 30")
}

func cmdRestart(args []string) error {
	fs := flag.NewFlagSet("restart", flag.ContinueOnError)
	cfgPath := fs.String("config", defaultConfigPath, "config file")
	pidFile := fs.String("pidfile", defaultPIDFile, "pid file used when systemd is not available")
	timeout := fs.Duration("timeout", 90*time.Second, "how long to wait for the new process")
	force := fs.Bool("force", false, "send the signal even if the running process cannot be verified as v2")
	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}
	cfg, err := LoadConfig(*cfgPath)
	if err != nil {
		return fmt.Errorf("not restarting, the config is invalid (the new process would refuse to start): %w", err)
	}
	pid, how := runningPID(*pidFile)
	if pid == 0 {
		return errors.New("ayana-cdn is not running; start it with: systemctl start ayana-cdn")
	}
	// SIGUSR2 is only understood by v2; it would terminate a v1 process.
	if !*force {
		if cfg.AdminListen == "off" {
			return errors.New("cannot verify the running version (admin_listen is off); rerun with -force if it is v2")
		}
		d, _, err := fetchStatus(cfg.AdminListen)
		if err != nil || d.PID != pid {
			return fmt.Errorf("the running process (pid %d) does not answer on the admin endpoint, so it is probably v1, "+
				"which cannot hand over its connections. Do a one-time `systemctl restart ayana-cdn`; restarts after that are zero-downtime", pid)
		}
		if d.Draining {
			return errors.New("the running process is already draining; wait a moment and retry")
		}
	}
	if err := syscall.Kill(pid, syscall.SIGUSR2); err != nil {
		return fmt.Errorf("signal pid %d: %w", pid, err)
	}
	fmt.Printf("restart requested (pid %d via %s); waiting for the new process...\n", pid, how)
	deadline := time.Now().Add(*timeout)
	for time.Now().Before(deadline) {
		time.Sleep(250 * time.Millisecond)
		if np, _ := runningPID(*pidFile); np != 0 && np != pid {
			fmt.Printf("restarted with zero downtime: pid %d -> %d; the old process drains its tunnels (up to %s)\n",
				pid, np, cfg.Timeouts.Drain.D())
			return nil
		}
	}
	return errors.New("no handoff happened; the old process is still serving. See: journalctl -u ayana-cdn -n 50")
}

// ---- status -----------------------------------------------------------------------------

func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	cfgPath := fs.String("config", defaultConfigPath, "config file (to find admin_listen)")
	admin := fs.String("admin", "", "admin address (default: admin_listen from the config)")
	asJSON := fs.Bool("json", false, "print the raw JSON status")
	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}
	addr := *admin
	if addr == "" {
		cfg, err := LoadConfig(*cfgPath)
		if err != nil {
			return err
		}
		if cfg.AdminListen == "off" {
			return errors.New(`the admin endpoint is disabled (admin_listen is "off")`)
		}
		addr = cfg.AdminListen
	}
	doc, raw, err := fetchStatus(addr)
	if err != nil {
		return fmt.Errorf("no answer from the edge's admin endpoint %s: %w (is it running? systemctl status ayana-cdn)", addr, err)
	}
	if *asJSON {
		_, err := os.Stdout.Write(raw)
		return err
	}
	renderStatus(os.Stdout, doc)
	return nil
}

func fmtUptime(sec int64) string {
	d := time.Duration(sec) * time.Second
	if d >= 24*time.Hour {
		return fmt.Sprintf("%dd%dh", d/(24*time.Hour), (d%(24*time.Hour))/time.Hour)
	}
	return d.String()
}

func renderStatus(w io.Writer, d *statusDoc) {
	mode := "serving"
	if d.Draining {
		mode = "DRAINING"
	}
	fmt.Fprintf(w, "ayana-cdn %s (%s)  pid %d  %s  up %s  config generation %d\n",
		d.Version, d.Go, d.PID, mode, fmtUptime(d.UptimeSeconds), d.Generation)
	fmt.Fprintf(w, "listen %s  hosts %s  tls %s\n", d.Listen, strings.Join(d.Hosts, ","), d.TLSMode)
	c := d.Connections
	maxS := "unlimited"
	if c.Max > 0 {
		maxS = strconv.FormatInt(c.Max, 10)
	}
	fmt.Fprintf(w, "connections %d open (cap %s), %d accepted; refused %d by cap, %d by ip rate, %d by ip conns; sni fallback %d\n",
		c.Active, maxS, c.Accepted, c.RejectedGlobal, c.RejectedRate, c.RejectedPerIP, c.SNIFallback)
	fmt.Fprintf(w, "tunnels %d open\n", d.TunnelsActive)
	if c.UDPSessions > 0 || c.UDPMax > 0 || len(c.UDPDropped) > 0 {
		udpMax := "unlimited"
		if c.UDPMax > 0 {
			udpMax = strconv.FormatInt(c.UDPMax, 10)
		}
		var dropped []string
		for _, k := range []string{"no_backend", "disabled", "global_cap", "ip_rate", "ip_conns", "backend_cap", "dial_error", "port_exhausted", "oversize", "write_error", "amplified"} {
			if v := c.UDPDropped[k]; v > 0 {
				dropped = append(dropped, fmt.Sprintf("%d %s", v, k))
			}
		}
		line := fmt.Sprintf("udp sessions %d open (cap %s)", c.UDPSessions, udpMax)
		if len(dropped) > 0 {
			line += "; dropped " + strings.Join(dropped, ", ")
		}
		fmt.Fprintln(w, line)
	}
	for _, ci := range d.Certificates {
		fmt.Fprintf(w, "certificate %s expires %s (%.0f days), issuer %s\n", ci.Host,
			ci.NotAfter.Format("2006-01-02"), time.Until(ci.NotAfter).Hours()/24, ci.Issuer)
	}
	fmt.Fprintln(w)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "BACKEND\tPATH\tPROTO\tOPEN\tTOTAL\tFAILED\tUP\tDOWN\tUPSTREAMS")
	for _, b := range d.Backends {
		ups := make([]string, 0, len(b.Upstreams))
		for _, u := range b.Upstreams {
			h := "up"
			if !u.Healthy {
				h = "DOWN"
			}
			ups = append(ups, fmt.Sprintf("%s %s/%d", u.Addr, h, u.Active))
		}
		name := b.Name
		if b.Disabled {
			name += " (disabled)"
		}
		path := b.Path
		if b.Listen != "" {
			path = "udp " + b.Listen
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%d\t%d\t%s\t%s\t%s\n", name, path, b.Proto, b.TunnelsActive,
			b.TunnelsTotal, b.Failures, humanBytes(b.BytesUp), humanBytes(b.BytesDown), strings.Join(ups, ", "))
	}
	tw.Flush()
	for _, b := range d.Backends {
		for _, u := range b.Upstreams {
			if !u.Healthy && u.LastErr != "" {
				fmt.Fprintf(w, "  %s %s last error: %s\n", b.Name, u.Addr, u.LastErr)
			}
		}
	}
	r := d.Runtime
	fmt.Fprintf(w, "\nruntime: %d goroutines, heap %s, stacks %s, sys %s, fds %d of %d\n",
		r.Goroutines, humanBytes(r.HeapInuse), humanBytes(r.StackInuse), humanBytes(r.Sys), r.OpenFDs, r.MaxFDs)
}

// ---- config ------------------------------------------------------------------------------

func cmdConfig(args []string) error {
	if len(args) == 0 || args[0] != "show" {
		return errors.New("usage: ayana-cdn config show [-raw] [-config FILE]")
	}
	fs := flag.NewFlagSet("config show", flag.ContinueOnError)
	cfgPath := fs.String("config", defaultConfigPath, "config file")
	raw := fs.Bool("raw", false, "print the file as written instead of the effective config")
	if _, err := parseInterspersed(fs, args[1:]); err != nil {
		return err
	}
	c, err := loadRaw(*cfgPath)
	if err != nil {
		return err
	}
	if !*raw {
		if c, err = c.Effective(); err != nil {
			return err
		}
	}
	out, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(out))
	return nil
}

// ---- check ------------------------------------------------------------------------------

func udpBackendCount(c *Config) int {
	n := 0
	for _, b := range c.Backends {
		if b.isUDP() {
			n++
		}
	}
	return n
}

func cmdCheck(args []string) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	cfgPath := fs.String("config", defaultConfigPath, "config file")
	noDial := fs.Bool("no-dial", false, "validate only; do not contact the upstreams")
	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}
	raw, err := loadRaw(*cfgPath)
	if err != nil {
		return err
	}
	cfg, err := raw.Effective()
	if err != nil {
		return fmt.Errorf("config invalid: %w", err)
	}
	fmt.Printf("config OK: %s\n", *cfgPath)
	fmt.Printf("  listen %s, hosts %s, tls %s, admin %s, %d backends\n",
		cfg.Listen, strings.Join(cfg.CDNHosts, ","), cfg.TLS.Mode, cfg.AdminListen, len(cfg.Backends))
	if d := newKeepAlive(cfg.Timeouts).deadAfter(); d > 0 {
		fmt.Printf("  dead peers dropped after ~%s of silence (client_keepalive %s + dead_peer %s)\n",
			d.Round(time.Second), cfg.Timeouts.ClientKeepAlive.D(), cfg.Timeouts.DeadPeer.D())
	}
	if udp := udpBackendCount(cfg); udp > 0 {
		fmt.Printf("  %d udp backend(s); global session cap %d, udp_idle %s, udp_reply %s\n",
			udp, effectiveMaxUDPSessions(cfg.Limits.MaxUDPSessions), cfg.Timeouts.UDPIdle.D(), cfg.Timeouts.UDPReply.D())
	}
	for _, w := range cfg.warnings {
		fmt.Printf("  warning: %s\n", w)
	}
	checkCertificates(cfg)
	if *noDial {
		return nil
	}
	failures := 0
	for _, b := range cfg.Backends {
		if b.Disabled {
			fmt.Printf("  skip %-14s disabled\n", b.Name)
			continue
		}
		p := newPool(b, cfg.Timeouts, nil, slog.New(slog.DiscardHandler))
		if b.isUDP() {
			// Datagrams cannot be probed without knowing the protocol; the
			// most `check` can do is make sure every address resolves.
			for _, u := range p.ups {
				if addr, err := net.ResolveUDPAddr("udp", u.addr); err != nil {
					failures++
					fmt.Printf("  FAIL %-14s %-34s udp: %s\n", b.Name, u.addr, errString(err))
				} else {
					fmt.Printf("  ok   %-14s %-34s udp -> %s (listening on %s; datagrams are not probed)\n", b.Name, u.addr, addr, b.Listen)
				}
			}
			continue
		}
		hc := *b.HealthCheck
		if hc.Type == "off" {
			hc.Type = "tcp"
			if b.useTLS() {
				hc.Type = "tls"
			}
		}
		for _, u := range p.ups {
			t0 := time.Now()
			err := probeUpstream(context.Background(), u.addr, u.tlsConf, b, hc)
			if err != nil {
				failures++
				fmt.Printf("  FAIL %-14s %-34s %s check: %s\n", b.Name, u.addr, hc.Type, errString(err))
				continue
			}
			fmt.Printf("  ok   %-14s %-34s %s check %s\n", b.Name, u.addr, hc.Type, fmtDur(time.Since(t0)))
		}
	}
	if failures > 0 {
		return fmt.Errorf("%d upstream check(s) failed", failures)
	}
	return nil
}

func checkCertificates(cfg *Config) {
	describe := func(label string, leaf *x509.Certificate) {
		days := time.Until(leaf.NotAfter).Hours() / 24
		fmt.Printf("  certificate %s: %s, expires %s (%.0f days), issuer %s\n", label,
			strings.Join(leaf.DNSNames, ","), leaf.NotAfter.Format("2006-01-02"), days, leaf.Issuer.CommonName)
	}
	switch cfg.TLS.Mode {
	case "files":
		pair, err := tls.LoadX509KeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile)
		if err != nil {
			fmt.Printf("  certificate: ERROR %v\n", err)
			return
		}
		leaf, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			fmt.Printf("  certificate: ERROR %v\n", err)
			return
		}
		describe(filepath.Base(cfg.TLS.CertFile), leaf)
		for _, h := range cfg.CDNHosts {
			if leaf.VerifyHostname(h) != nil {
				fmt.Printf("  warning: the certificate does not cover %s\n", h)
			}
		}
	case "acme":
		for _, h := range cfg.CDNHosts {
			data, err := os.ReadFile(filepath.Join(cfg.TLS.CacheDir, h))
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					fmt.Printf("  certificate %s: not issued yet (it is requested when the edge starts)\n", h)
				} else {
					fmt.Printf("  certificate %s: cannot read the cache: %v\n", h, err)
				}
				continue
			}
			var leaf *x509.Certificate
			for rest := data; ; {
				var blk *pem.Block
				if blk, rest = pem.Decode(rest); blk == nil {
					break
				}
				if blk.Type == "CERTIFICATE" {
					if leaf, err = x509.ParseCertificate(blk.Bytes); err == nil {
						break
					}
				}
			}
			if leaf == nil {
				fmt.Printf("  certificate %s: cache entry unreadable\n", h)
				continue
			}
			describe(h, leaf)
		}
	}
}
