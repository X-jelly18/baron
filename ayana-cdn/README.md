# ayana-cdn 2.0

A small, self-hosted TLS edge for your VPS. Clients connect to **one hostname on
port 443** (`https://cdn.example.com`) and the path picks the backend:
`/native1/` goes to `native1.example.com:443`, `/native2/` to native2,
and so on. WebSocket/SSH tunnel backends are relayed byte for byte; ordinary
HTTP backends are proxied. Certificates come from Let's Encrypt automatically.

It is one static Go binary with no runtime dependencies. The installer builds it
on your server with the current Go release.

    client ──TLS──▶ cdn.example.com:443 (ayana-cdn) ──/native1/──▶ native1.example.com:443
                                                          ──/native2/──▶ native2.example.com:443
                                                          ──/panel/────▶ 127.0.0.1:8080 (plain HTTP app)

## What changed in v2

v1 worked for the simple case and lost data in the cases tunnel clients
actually produce. Every row below was reproduced with an independent Python
harness (a real backend, real TLS, raw bytes) against the v1 binary, then
against v2 with **the v1 config file unchanged**:

| Case | v1 | v2 |
|---|---|---|
| Client sends its first bytes (SSH banner) in the same TLS record as the upgrade request | bytes silently dropped | delivered |
| Client sends its first bytes right after the request, in a separate write | first byte lost (`SH-2.0-...`) | delivered |
| Backend answers `101` without an `Upgrade:` header (most Python tunnel proxies) | `502` | works |
| Backend sends a banner immediately after its `101` | works | works |
| `ayana-cdn backend add native11 host:443 --host x` (the v1 README's own example) | usage error | works |

Beyond the fixes, v2 adds what a production edge needs:

- **Zero-downtime restart and upgrade** (`ayana-cdn restart`): the new process
  inherits the listening sockets, the old one drains its tunnels. Verified with
  6,000 connections opened at 500/s across a restart: zero failures.
- **Live reload** (`ayana-cdn reload`, SIGHUP) that never drops an open tunnel,
  with the config validated as a whole before it is applied.
- **Several upstreams per backend** with failover, least-connections or
  round-robin balancing, and active health checks (tcp / tls / http / ws).
- **Raw relay mode** (`"relay": "always"`) for backends that answer `200` and
  then go raw, or that do not speak HTTP at all.
- **Plain HTTP backends** on the same hostname (`"proto": "http"`), including
  streaming (SSE) responses.
- **UDP relay** (`"proto": "udp"`) on its own port for WireGuard, QUIC-based
  tunnels, DNS and game traffic: per-flow sessions from one address, sticky
  `hash` load-balancing, and dead-session detection (idle, ICMP-unreachable,
  and reply-timeout for black-holed upstreams).
- **Protection**: per-IP connection rate and concurrency limits (separate
  budgets for TCP connections and UDP sessions), a global cap derived from the
  file-descriptor limit, idle and write-stall timeouts, request size limits,
  and faster dead-peer detection with TCP keepalive + `TCP_USER_TIMEOUT`.
- **Observability**: `ayana-cdn status`, Prometheus metrics, JSON status,
  structured logs with one line per tunnel (bytes each way, duration, why it
  ended), certificate expiry in the status output.
- **Tools**: `check` validates the config and probes every upstream, `bench`
  load-tests tunnels with SNI control and early data, `echo-backend` is a test
  backend that can imitate Python-style proxies, `routes import` applies a
  Cloud Run-style `routes.json`.
- **Less memory per tunnel**: about 35 KiB resident per idle TLS tunnel
  against 57 KiB in v1 (2,000 open tunnels, same machine), with adaptive
  4 KiB / 32 KiB relay buffers.
- **Hardened service unit**: runs unprivileged with `CAP_NET_BIND_SERVICE`,
  systemd sandboxing, `Type=notify`, `GOMEMLIMIT` at 75% of RAM.

Evidence shipped with the package: 53 Go tests (`make test`), including
in-process integration tests with real TLS and backends and an end-to-end
restart test with real processes and signals; the suite passes repeatedly
under the race detector. See `docs/ARCHITECTURE.md` for the v1 root causes.

## Requirements

- Linux (Debian/Ubuntu tested; any systemd distribution should work).
- Root for the installer. It creates the `ayana-cdn` system user.
- Outbound HTTPS to `go.dev`/`dl.google.com` (Go toolchain), `proxy.golang.org`
  and `sum.golang.org` (one dependency, verified against the checksum
  database). No prebuilt binaries and no vendored code are shipped: the
  binary is built on your server, reproducibly, from the sources in this
  package.
- The CDN hostname's DNS must point at the server before starting, so
  Let's Encrypt can validate it (TLS-ALPN on port 443, no port 80 needed).

## Quick start

```sh
unzip ayana-cdn.zip && cd ayana-cdn
sudo ./setup.sh          # install or upgrade, apply routes.json, probe upstreams, show status
```

`setup.sh` asks for the domain (and the ACME email), runs the installer (add
`--test` to run the test suite first), then asks for the routes one at a
time: the path clients use, the target (`http://IP-or-host[:port]`,
`https://…` for TLS, several separated by commas for failover), and optionally
the Host header to send. It shows the routes it
is about to apply, validates them with the same code that applies them,
probes every upstream, and prints the client payload for each route. The
entered routes are saved to `/etc/ayana-cdn/routes.json`; rerunning
`setup.sh` shows the current routes and keeps them if you leave the first
path empty. The domain you enter becomes the primary one; domains already
configured (e.g. added from the panel) are kept. `--routes FILE` applies a
file without prompting. To upgrade without changing anything, use
`sudo ./setup.sh --keep-config`: it asks nothing and keeps the domains, the
email and the routes as they are.

The routes file uses the same format as the Cloud Run `http-proxy` relay it
replaces, path prefix to target, with the same semantics: the path is
forwarded unchanged and the Host header becomes the target's hostname. The
package's `routes.json` is an example:

```json
{
  "/maibhhhh": "http://south.example.com",
  "/s1": { "targets": ["http://192.0.2.73", "http://south2.example.com"], "host": "south2.example.com" },
  "/s2": "http://ses.example.com",
  "/p6CAaNg": "https://ses.example.com"
}
```

A route with several targets tries them in order (the first is the origin
reached directly, the rest are failover). A routes file can be applied at any
time with `sudo ayana-cdn routes import FILE -replace`; `config/config.json`
holds the same example routes in the full config format. Individual backends
can also be managed from the shell:

```sh
sudo ayana-cdn backend add ssh 127.0.0.1:2222 -proto ws -relay always   # raw SSH-over-WS proxy
sudo ayana-cdn backend set s1 -upstreams 192.0.2.73:80
sudo ayana-cdn backend ls
```

Each edit is validated before it is saved and applied live; the previous file
is kept as `config.json.bak`.

### Upgrading from v1

Run the same installer over the existing installation. Your config file is
kept (v1 configs load unchanged), the new build validates it before anything
is replaced, and the service is restarted once with `systemctl restart`, the
only restart that makes clients reconnect. Every later upgrade or config change
that needs a restart goes through `ayana-cdn restart` with no downtime.

Two v1 quirks to know about: v1's front door sent PROXY protocol headers to
your other tunnel service, which most tunnel servers reject; the v2
`deploy/frontdoor.conf` fixes that. And v1's installer pinned an end-of-life Go
release into `/usr/local/go`; v2 uses a private toolchain under
`/opt/ayana-cdn` and never touches `/usr/local/go`.

## Everyday commands

| Command | What it does |
|---|---|
| `ayana-cdn status [-json]` | Live view: connections, tunnels per backend with bytes, upstream health, certificate expiry, memory. |
| `ayana-cdn check [-no-dial]` | Validate the config, show the certificate, probe every upstream (exit code 1 if any fails). |
| `ayana-cdn reload` | Apply config changes without dropping anything. Rejected configs leave the running one in place. |
| `ayana-cdn restart` | Replace the running process (new binary, or a listen/TLS-mode change) without dropping connections. |
| `ayana-cdn backend ls / add / set / rm / enable / disable` | Edit backends safely from the shell. `ayana-cdn backend` prints all flags. |
| `ayana-cdn panel enable / passwd / path / disable / show` | Set up the authenticated web panel on a secret HTTPS path. |
| `ayana-cdn routes import routes.json [-replace]` | Apply a routes.json (path prefix → target URL) as backends; `-replace` drops backends not in the file. |
| `ayana-cdn config show [-raw]` | The effective config with every default filled in (or the file as written). |
| `ayana-cdn bench -url wss://cdn.example/native1/ -c 500 -rate 100 -hold 30s` | Open real tunnels through the edge and report connect/TLS/upgrade latency percentiles. |
| `ayana-cdn echo-backend -listen 127.0.0.1:9000 [-no-upgrade-header]` | A tunnel-style test backend that echoes everything. |
| `journalctl -u ayana-cdn -f` | Logs: one line per tunnel and request, plus health and certificate events. |

Signals: `HUP` reloads, `USR2` restarts without downtime, `TERM` stops.

## Web panel

An authenticated dashboard served over HTTPS on the normal `:443` listener at a
**secret path**, so you can watch the edge from a browser without exposing the
loopback admin endpoint:

```sh
sudo ayana-cdn panel enable -user admin   # prompts for a password, generates the secret path + session key
sudo ayana-cdn panel show                 # prints the https URL to open
```

Open `https://<cdn host>/<secret path>/` and sign in with the username and
password. The panel shows **live throughput graphs** — a hero upload/download
area chart over the last few minutes, per-domain sparklines, and a card per
backend with its **total usage** (cumulative up/down), **live rate** (Mbps),
a sparkline, and a full per-backend chart with upstream health and
response-class counts under *Details*. It also shows connections, tunnels,
certificate expiry, runtime stats, and a **Client IPs** view per backend (which
addresses connected, how many times, and — with geolocation on — where from),
refreshing every couple of seconds. The history is kept server-side (a small
bounded ring buffer), so the graphs are populated the moment you open the panel.
With `-control` it also lets you
**manage domains and paths from the browser**: add/remove `cdn_hosts`, and
add/edit/remove/enable/disable backends — including a local service on this VPS
(`proto: http`, upstream `127.0.0.1:PORT`), reachable at `/<name>/`. Changes are
written to the config and applied live.

The secret path is the first layer; the login is the second. The session cookie
is `HttpOnly`/`Secure`/`SameSite=Strict` and scoped to the panel path, actions
are CSRF-protected, failed logins are rate-limited per IP, and every page
carries a strict CSP. See `docs/CONFIG.md` (`panel`) and `docs/OPERATIONS.md`.

A UDP backend listens on its own port (UDP has no path to route on):

```sh
sudo ayana-cdn backend add wg 10.0.0.2:51820 -proto udp -listen :51820   # WireGuard/QUIC/DNS over UDP
```

Datagrams from one client address are relayed as independent sessions, dead
sessions are reclaimed (idle, ICMP-unreachable, or no reply within
`udp_reply`), and `lb: hash` keeps a client on the same upstream. See
`docs/CONFIG.md` and `config/examples/udp.json`.

## Client settings

For HTTP Injector-style clients, point them at the CDN host and use the
backend's path:

- Server / SNI: `cdn.example.com` (a bug host in the SNI also works; the
  edge serves its certificate regardless, unless `strict_sni` is set).
- Payload: `GET /native1/ HTTP/1.1[crlf]Host: cdn.example.com[crlf]Upgrade: websocket[crlf][crlf]`
- The rest of the path after `/native1` is passed to the backend
  (`/native1/ws?x=1` arrives as `/ws?x=1`); `"strip": false` keeps it whole.

The edge forwards `X-Forwarded-For`, `X-Real-IP`, `X-Forwarded-Proto`,
`X-Forwarded-Host` and `X-Forwarded-Prefix`, and drops any of those the client
sent itself.

## Documentation

- `docs/CONFIG.md`: every setting, its default and what it does.
- `docs/OPERATIONS.md`: reload vs restart, certificates, monitoring, capacity,
  troubleshooting, security and the optional nginx front door.
- `docs/ARCHITECTURE.md`: how the data path, reload and restart work, and
  what was wrong in v1.
- `CHANGELOG.md`.

## Package contents

    setup.sh               one command: install/upgrade, prompt for the routes, check, status
    routes.json            example routes file, in the Cloud Run relay's format
    cmd/ayana-cdn/         the program and its tests (testdata/v1-config.json is v1's shipped config)
    config/config.json     the same routes as a full config; config/examples/ for failover, raw
                           tunnels, HTTP backends, certificate files, and the nginx front door
    deploy/install.sh      install or upgrade; --test, --no-sysctl, --no-start, --go-root DIR
    deploy/uninstall.sh    remove (keeps config and certificates unless --purge)
    deploy/ayana-cdn.service, sysctl-99-ayana-cdn.conf, frontdoor.conf, ayana-cdn.bash-completion
    Makefile               build / test / race / vet for development
