// Command ayana-cdn is a TLS edge that fronts WebSocket/SSH tunnel backends
// and ordinary HTTP backends by path: https://<cdn host>/<backend>/...
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"
)

const usageText = `ayana-cdn %s - TLS edge for WebSocket tunnels and HTTP backends

usage:
  ayana-cdn serve    [-config FILE]            run the edge (systemd runs this)
  ayana-cdn status   [-json]                   live connections, tunnels, upstream health, certificates
  ayana-cdn check    [-no-dial]                validate the config and probe every upstream
  ayana-cdn reload                             apply config changes without dropping anything
  ayana-cdn restart                            zero-downtime restart (also picks up a new binary)
  ayana-cdn config show [-raw]                 print the config with all defaults filled in
  ayana-cdn backend ls|add|set|rm|enable|disable ...
  ayana-cdn panel enable|passwd|path|disable|show|hash ...  authenticated web panel on a secret path
  ayana-cdn admin passwd|disable-auth ...      HTTP Basic auth for the admin endpoint
  ayana-cdn geo on|off|show ...                IP geolocation for the per-backend IP log
  ayana-cdn routes import FILE [-replace]      apply a routes.json (path -> target URL)
  ayana-cdn bench    -url wss://HOST/PATH [-c N -rate R -hold D -sni S -early DATA -ping D -bulk SIZE]
  ayana-cdn echo-backend [-listen ADDR] [-no-upgrade-header] [-banner LINE] [-status 101|200]
  ayana-cdn version

Every command accepts -config FILE (default %s).
Signals: HUP reloads, USR2 restarts without downtime, TERM/INT stop.
`

func usage() {
	fmt.Fprintf(os.Stderr, usageText, version, defaultConfigPath)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "serve", "run":
		err = cmdServe(args)
	case "status":
		err = cmdStatus(args)
	case "check", "validate":
		err = cmdCheck(args)
	case "reload":
		err = cmdReload(args)
	case "restart":
		err = cmdRestart(args)
	case "config":
		err = cmdConfig(args)
	case "backend", "backends":
		err = cmdBackend(args)
	case "panel":
		err = cmdPanel(args)
	case "admin":
		err = cmdAdmin(args)
	case "geo":
		err = cmdGeo(args)
	case "routes", "route":
		err = cmdRoutes(args)
	case "bench":
		err = cmdBench(args)
	case "echo-backend":
		err = cmdEchoBackend(args)
	case "version", "-version", "--version":
		fmt.Printf("ayana-cdn %s (%s, %s/%s)\n", version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
	case "help", "-h", "-help", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "ayana-cdn: unknown command %q\n\n", cmd)
		usage()
		os.Exit(2)
	}
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		fmt.Fprintln(os.Stderr, "ayana-cdn:", err)
		os.Exit(1)
	}
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	cfgPath := fs.String("config", defaultConfigPath, "config file")
	pidFile := fs.String("pidfile", defaultPIDFile, `pid file ("" disables it)`)
	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}
	s, err := NewServer(*cfgPath, nil)
	if err != nil {
		return err
	}
	s.pidFile = *pidFile

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigs := make(chan os.Signal, 8)
	signal.Notify(sigs, syscall.SIGHUP, syscall.SIGUSR2, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		for sig := range sigs {
			switch sig {
			case syscall.SIGHUP:
				_ = s.Reload() // logs its own outcome
			case syscall.SIGUSR2:
				go func() {
					if err := s.Handoff(); err != nil && !errors.Is(err, errDraining) {
						s.log.Error("restart failed; this process keeps serving", "err", err)
					}
				}()
			default:
				s.log.Info("stopping", "signal", sig.String())
				cancel()
			}
		}
	}()
	return s.Run(ctx)
}
