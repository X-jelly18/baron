package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/crypto/bcrypt"
)

const panelUsage = `usage:
  ayana-cdn panel enable [-user NAME] [-path /PREFIX] [-control] [-allow CIDR,CIDR] [-ttl DUR] [password flags]
  ayana-cdn panel passwd [-user NAME] [password flags]     change the login (and optionally the username)
  ayana-cdn panel path                                     generate a new secret URL prefix
  ayana-cdn panel disable                                  stop serving the panel (settings are kept)
  ayana-cdn panel show                                     print the panel URL and settings (never the password)
  ayana-cdn panel hash [password flags]                    print a bcrypt hash for manual config editing

password flags (for enable / passwd / hash):
  -password STRING     the password on the command line (visible in ps/history; prefer the alternatives)
  -password-stdin      read the password as one line from standard input (echo 'secret' | ayana-cdn panel passwd -password-stdin)
  (otherwise you are prompted twice, without echo)

The panel is served over HTTPS on the normal :443 listener at the secret
prefix, guarded by the username and password. Keep the prefix unguessable;
turn on -control only if you want the panel to reload the config and
enable/disable backends (that requires the service to be able to write the
config file).`

func cmdPanel(args []string) error {
	if len(args) == 0 {
		return errors.New(panelUsage)
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "enable":
		return panelEnable(rest)
	case "passwd", "password":
		return panelPasswd(rest)
	case "path":
		return panelNewPath(rest)
	case "disable":
		return panelDisable(rest)
	case "show", "status":
		return panelShow(rest)
	case "hash":
		return panelHash(rest)
	}
	return fmt.Errorf("unknown panel command %q\n%s", sub, panelUsage)
}

type passwordFlags struct {
	password  string
	passStdin bool
}

func (pf *passwordFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&pf.password, "password", "", "password on the command line (prefer -password-stdin or the prompt)")
	fs.BoolVar(&pf.passStdin, "password-stdin", false, "read the password from standard input")
}

// resolve returns the password from the flag, stdin, the AYANA_PANEL_PASSWORD
// env var, or an interactive no-echo prompt (asked twice when confirm is set).
func (pf *passwordFlags) resolve(confirm bool) (string, error) {
	if pf.password != "" {
		return pf.password, nil
	}
	if v := os.Getenv("AYANA_PANEL_PASSWORD"); v != "" {
		return v, nil
	}
	r := bufio.NewReader(os.Stdin)
	if pf.passStdin {
		line, err := r.ReadString('\n')
		if err != nil && line == "" {
			return "", err
		}
		return strings.TrimRight(line, "\r\n"), nil
	}
	p1, err := promptNoEcho(r, "Panel password: ")
	if err != nil {
		return "", err
	}
	if p1 == "" {
		return "", errors.New("password must not be empty")
	}
	if confirm {
		p2, err := promptNoEcho(r, "Confirm password: ")
		if err != nil {
			return "", err
		}
		if p1 != p2 {
			return "", errors.New("passwords do not match")
		}
	}
	return p1, nil
}

func hashPassword(pw string) (string, error) {
	if len(pw) > 72 {
		// bcrypt silently ignores everything past 72 bytes; refuse rather than
		// hash a password that is not fully used.
		return "", errors.New("password must be at most 72 bytes")
	}
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(h), nil
}

func warnWeak(pw string) {
	if len(pw) < 10 {
		fmt.Fprintln(os.Stderr, "warning: that password is short; a long random passphrase is strongly recommended for an internet-facing panel")
	}
}

func panelEnable(args []string) error {
	fs := flag.NewFlagSet("panel enable", flag.ContinueOnError)
	cfgPath := fs.String("config", defaultConfigPath, "config file")
	user := fs.String("user", "", "login username")
	path := fs.String("path", "", "secret URL prefix (generated if omitted)")
	control := fs.Bool("control", false, "allow reload and enable/disable backend actions from the panel")
	allow := fs.String("allow", "", "comma-separated source-IP allowlist (CIDRs); empty allows any address")
	ttl := fs.Duration("ttl", 0, "session lifetime (default 12h)")
	noReload := fs.Bool("no-reload", false, "edit the file only; do not signal the running edge")
	var pf passwordFlags
	pf.register(fs)
	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}
	set := flagSet(fs)

	return editConfig(*cfgPath, *noReload, func(c *Config) (string, error) {
		if c.Panel == nil {
			c.Panel = &PanelConfig{}
		}
		p := c.Panel
		if set["user"] {
			p.Username = strings.TrimSpace(*user)
		}
		if p.Username == "" {
			return "", errors.New("no username yet; pass -user NAME")
		}
		if set["path"] {
			p.Path = *path
		}
		if strings.Trim(p.Path, "/") == "" {
			p.Path = newSecretPath()
		}
		if p.SessionKey == "" {
			k, err := newSessionKey()
			if err != nil {
				return "", err
			}
			p.SessionKey = k
		}
		if set["control"] {
			p.AllowControl = *control
		}
		if set["allow"] {
			p.AllowedCIDRs = splitList(*allow)
		}
		if set["ttl"] {
			p.SessionTTL = Duration(*ttl)
		}
		// A password is required to enable; reuse the stored one only if it exists.
		if set["password"] || pf.passStdin || os.Getenv("AYANA_PANEL_PASSWORD") != "" || p.PasswordHash == "" {
			pw, err := pf.resolve(true)
			if err != nil {
				return "", err
			}
			warnWeak(pw)
			h, err := hashPassword(pw)
			if err != nil {
				return "", err
			}
			p.PasswordHash = h
		}
		p.Enabled = true
		return panelEnabledMessage(c), nil
	})
}

func panelPasswd(args []string) error {
	fs := flag.NewFlagSet("panel passwd", flag.ContinueOnError)
	cfgPath := fs.String("config", defaultConfigPath, "config file")
	user := fs.String("user", "", "also change the username")
	noReload := fs.Bool("no-reload", false, "edit the file only; do not signal the running edge")
	var pf passwordFlags
	pf.register(fs)
	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}
	set := flagSet(fs)
	return editConfig(*cfgPath, *noReload, func(c *Config) (string, error) {
		if c.Panel == nil {
			return "", errors.New("the panel is not configured; run: ayana-cdn panel enable")
		}
		if set["user"] {
			c.Panel.Username = strings.TrimSpace(*user)
		}
		pw, err := pf.resolve(true)
		if err != nil {
			return "", err
		}
		warnWeak(pw)
		h, err := hashPassword(pw)
		if err != nil {
			return "", err
		}
		c.Panel.PasswordHash = h
		return "panel password updated", nil
	})
}

func panelNewPath(args []string) error {
	fs := flag.NewFlagSet("panel path", flag.ContinueOnError)
	cfgPath := fs.String("config", defaultConfigPath, "config file")
	noReload := fs.Bool("no-reload", false, "edit the file only; do not signal the running edge")
	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}
	return editConfig(*cfgPath, *noReload, func(c *Config) (string, error) {
		if c.Panel == nil {
			return "", errors.New("the panel is not configured; run: ayana-cdn panel enable")
		}
		c.Panel.Path = newSecretPath()
		return "new panel path: " + c.Panel.Path + "  (old bookmarks stop working)", nil
	})
}

func panelDisable(args []string) error {
	fs := flag.NewFlagSet("panel disable", flag.ContinueOnError)
	cfgPath := fs.String("config", defaultConfigPath, "config file")
	noReload := fs.Bool("no-reload", false, "edit the file only; do not signal the running edge")
	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}
	return editConfig(*cfgPath, *noReload, func(c *Config) (string, error) {
		if c.Panel == nil || !c.Panel.Enabled {
			return "", errors.New("the panel is already disabled")
		}
		c.Panel.Enabled = false
		return "panel disabled (settings kept; re-enable with: ayana-cdn panel enable)", nil
	})
}

func panelShow(args []string) error {
	fs := flag.NewFlagSet("panel show", flag.ContinueOnError)
	cfgPath := fs.String("config", defaultConfigPath, "config file")
	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}
	cfg, err := LoadConfig(*cfgPath)
	if err != nil {
		return err
	}
	p := cfg.Panel
	if p == nil {
		fmt.Println("panel: not configured (enable it with: ayana-cdn panel enable)")
		return nil
	}
	state := "disabled"
	if p.Enabled {
		state = "enabled"
	}
	fmt.Printf("panel:        %s\n", state)
	fmt.Printf("username:     %s\n", p.Username)
	fmt.Printf("path:         %s\n", p.Path)
	if len(cfg.CDNHosts) > 0 && p.Path != "" {
		fmt.Printf("url:          https://%s%s/\n", cfg.CDNHosts[0], p.Path)
	}
	fmt.Printf("control:      %v\n", p.AllowControl)
	fmt.Printf("session_ttl:  %s\n", p.SessionTTL.D())
	keyState := "random each start (restart logs everyone out)"
	if p.SessionKey != "" {
		keyState = "set (sessions survive restart)"
	}
	fmt.Printf("session_key:  %s\n", keyState)
	if len(p.AllowedCIDRs) > 0 {
		fmt.Printf("allowed_cidrs: %s\n", strings.Join(p.AllowedCIDRs, ", "))
	}
	return nil
}

func panelHash(args []string) error {
	fs := flag.NewFlagSet("panel hash", flag.ContinueOnError)
	var pf passwordFlags
	pf.register(fs)
	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}
	pw, err := pf.resolve(true)
	if err != nil {
		return err
	}
	warnWeak(pw)
	h, err := hashPassword(pw)
	if err != nil {
		return err
	}
	fmt.Println(h)
	return nil
}

// panelEnabledMessage summarises what was turned on, with the URL if a host is known.
func panelEnabledMessage(c *Config) string {
	var b strings.Builder
	fmt.Fprintf(&b, "panel enabled for user %q at %s", c.Panel.Username, c.Panel.Path)
	if len(c.CDNHosts) > 0 {
		fmt.Fprintf(&b, "\n  url: https://%s%s/", c.CDNHosts[0], c.Panel.Path)
	}
	if c.Panel.AllowControl {
		b.WriteString("\n  control actions are ON (reload, manage domains and backends/paths from the browser)")
	} else {
		b.WriteString("\n  read-only dashboard (enable management with: ayana-cdn panel enable -control)")
	}
	return b.String()
}

// ---- admin endpoint auth ----------------------------------------------------

const adminAuthUsage = `usage:
  ayana-cdn admin passwd [-user NAME] [password flags]   set HTTP Basic auth on the admin endpoint
  ayana-cdn admin disable-auth                           remove admin auth (loopback-only again)

The admin endpoint (admin_listen, default 127.0.0.1:9180) serves /status,
/metrics and /healthz. It is loopback-only by default; set a username and
password here to require HTTP Basic auth, which is what lets you bind it to a
reachable address safely. Same password flags as "ayana-cdn panel".`

func cmdAdmin(args []string) error {
	if len(args) == 0 {
		return errors.New(adminAuthUsage)
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "passwd", "password":
		return adminPasswd(rest)
	case "disable-auth", "disable":
		return adminDisableAuth(rest)
	}
	return fmt.Errorf("unknown admin command %q\n%s", sub, adminAuthUsage)
}

func adminPasswd(args []string) error {
	fs := flag.NewFlagSet("admin passwd", flag.ContinueOnError)
	cfgPath := fs.String("config", defaultConfigPath, "config file")
	user := fs.String("user", "admin", "admin username")
	noReload := fs.Bool("no-reload", false, "edit the file only; do not signal the running edge")
	var pf passwordFlags
	pf.register(fs)
	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}
	return editConfig(*cfgPath, *noReload, func(c *Config) (string, error) {
		c.AdminUser = strings.TrimSpace(*user)
		if c.AdminUser == "" {
			return "", errors.New("admin username must not be empty")
		}
		pw, err := pf.resolve(true)
		if err != nil {
			return "", err
		}
		warnWeak(pw)
		h, err := hashPassword(pw)
		if err != nil {
			return "", err
		}
		c.AdminPasswordHash = h
		return fmt.Sprintf("admin endpoint now requires HTTP Basic auth for user %q (admin_listen %s)", c.AdminUser, nonEmpty(c.AdminListen, defaultAdminListen)), nil
	})
}

func adminDisableAuth(args []string) error {
	fs := flag.NewFlagSet("admin disable-auth", flag.ContinueOnError)
	cfgPath := fs.String("config", defaultConfigPath, "config file")
	noReload := fs.Bool("no-reload", false, "edit the file only; do not signal the running edge")
	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}
	return editConfig(*cfgPath, *noReload, func(c *Config) (string, error) {
		if c.AdminUser == "" && c.AdminPasswordHash == "" {
			return "", errors.New("admin auth is not set")
		}
		c.AdminUser, c.AdminPasswordHash = "", ""
		return "admin auth removed; keep admin_listen on loopback", nil
	})
}

func nonEmpty(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// ---- geolocation for the IP log ---------------------------------------------

const geoUsage = `usage:
  ayana-cdn geo on [-url URL] [-rate N]   enable IP geolocation for the per-backend IP log
  ayana-cdn geo off                       disable it (the IP counter keeps working)
  ayana-cdn geo show                      print the current geolocation settings

The per-backend IP log (counts per client IP) is always on unless you set
log.ip_log=false. Geolocation is separate and off by default: turning it on
makes the edge resolve each logged public IP once against URL (a template with
{ip}, default https://ipwho.is/{ip}) and cache it. Sending client IPs to a
third party has privacy implications — point -url at a provider you trust.`

func cmdGeo(args []string) error {
	if len(args) == 0 {
		return errors.New(geoUsage)
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "on", "enable":
		return geoSet(rest, true)
	case "off", "disable":
		return geoSet(rest, false)
	case "show", "status":
		return geoShow(rest)
	}
	return fmt.Errorf("unknown geo command %q\n%s", sub, geoUsage)
}

func geoSet(args []string, on bool) error {
	fs := flag.NewFlagSet("geo", flag.ContinueOnError)
	cfgPath := fs.String("config", defaultConfigPath, "config file")
	url := fs.String("url", "", "geolocation URL template containing {ip}")
	rate := fs.Int("rate", 0, "max outbound lookups per minute")
	noReload := fs.Bool("no-reload", false, "edit the file only; do not signal the running edge")
	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}
	set := flagSet(fs)
	return editConfig(*cfgPath, *noReload, func(c *Config) (string, error) {
		if c.Geo == nil {
			c.Geo = &GeoConfig{}
		}
		c.Geo.Enabled = on
		if set["url"] {
			c.Geo.URL = strings.TrimSpace(*url)
		}
		if set["rate"] {
			c.Geo.RatePerMin = *rate
		}
		if on {
			return "IP geolocation enabled (resolving via " + nonEmpty(c.Geo.URL, "the default provider") + ")", nil
		}
		return "IP geolocation disabled (the per-backend IP counter keeps working)", nil
	})
}

func geoShow(args []string) error {
	fs := flag.NewFlagSet("geo show", flag.ContinueOnError)
	cfgPath := fs.String("config", defaultConfigPath, "config file")
	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}
	cfg, err := LoadConfig(*cfgPath)
	if err != nil {
		return err
	}
	ipLogOn := cfg.Log.IPLog == nil || *cfg.Log.IPLog
	fmt.Printf("ip_log:       %v\n", ipLogOn)
	fmt.Printf("geo.enabled:  %v\n", cfg.Geo.Enabled)
	fmt.Printf("geo.url:      %s\n", cfg.Geo.URL)
	fmt.Printf("geo.rate:     %d/min\n", cfg.Geo.RatePerMin)
	fmt.Printf("geo.cache:    %d entries, ttl %s\n", cfg.Geo.CacheSize, cfg.Geo.CacheTTL.D())
	return nil
}

// ---- small helpers ----------------------------------------------------------

// flagSet reports which flags were actually provided on the command line.
func flagSet(fs *flag.FlagSet) map[string]bool {
	m := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { m[f.Name] = true })
	return m
}

func newSecretPath() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return "/__ayana_" + base64.RawURLEncoding.EncodeToString(b)
}

func newSessionKey() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// promptNoEcho reads one line from r with terminal echo disabled. If stdin is
// not a terminal (TCGETS fails), it reads the line normally. Linux-only, like
// the rest of the program; uses the standard library's termios directly to
// keep the dependency set unchanged.
func promptNoEcho(r *bufio.Reader, prompt string) (string, error) {
	fd := int(os.Stdin.Fd())
	var old syscall.Termios
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.TCGETS, uintptr(unsafe.Pointer(&old)))
	fmt.Fprint(os.Stderr, prompt)
	if errno != 0 { // not a terminal (piped/redirected): read without toggling echo
		line, err := r.ReadString('\n')
		return strings.TrimRight(line, "\r\n"), err
	}
	noecho := old
	noecho.Lflag &^= syscall.ECHO
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.TCSETS, uintptr(unsafe.Pointer(&noecho))); errno != 0 {
		line, err := r.ReadString('\n')
		return strings.TrimRight(line, "\r\n"), err
	}
	defer func() {
		_, _, _ = syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.TCSETS, uintptr(unsafe.Pointer(&old)))
		fmt.Fprintln(os.Stderr)
	}()
	line, err := r.ReadString('\n')
	return strings.TrimRight(line, "\r\n"), err
}
