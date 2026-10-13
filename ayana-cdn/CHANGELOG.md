# Changelog

## 2.6.0

### Added

- **Redesigned web panel with live throughput graphs.** The dashboard has a new
  look (design-token theming, dark and light, mobile-friendly) and a hero
  **throughput area chart** of upload/download over the last few minutes, with a
  hover readout. Each **domain** row carries a sparkline; each **backend** is now
  a card showing its **total usage** (cumulative up/down bytes), **live rate**
  (Mbps up/down), a live sparkline, and — on *Details* — a full per-backend
  throughput chart alongside upstream health and response-class counts.
- **Server-side throughput history.** A lightweight sampler records per-backend,
  per-domain and total throughput into a bounded in-memory ring buffer (2 s
  cadence, ~3 min window), so the graphs show real history the moment the panel
  loads instead of only what has accrued since the tab opened. Exposed to the
  panel via the authenticated `GET <panel>/api/series` endpoint. Memory is
  bounded (one small ring per backend/domain, plus a hard key cap); everything is
  per-process and resets on restart, like every other counter here. No new
  configuration and no new dependencies.

## 2.5.1

### Changed

- **Per-IP rate and connection limits are now off by default.** `conn_rate_per_ip`,
  `max_conns_per_ip` and `max_udp_sessions_per_ip` all default to off (`-1`) —
  this edge fronts tunnel clients that legitimately open many connections, often
  from one carrier-NAT address, so it should not throttle them out of the box.
  Set any of them to a positive value to turn that limiter on. The global
  connection cap (`max_conns`) stays on as an auto, fd-derived **backstop** (so
  the process can't run itself out of file descriptors); set `max_conns: -1` to
  remove even that. No features change — the panel, IP log, geolocation and Mbps
  display are all unaffected.

## 2.5.0

### Added

- **Per-backend client-IP log.** Each backend now keeps an in-memory, bounded
  (top ~2048, least-recently-seen evicted) counter of client IPs with hit count
  and first/last-seen times, across tunnel, HTTP and UDP backends. On by default
  (`log.ip_log`, in-memory only — turn off with `log.ip_log: false`). Surfaced
  in the panel's new **Client IPs** section (pick a backend, see the top talkers)
  and via the authenticated `GET <panel>/api/iplog?backend=NAME` endpoint.
- **Optional IP geolocation** (`geo` config, `ayana-cdn geo on|off|show`). When
  enabled, each logged *public* IP is resolved once against a configurable URL
  template (default `https://ipwho.is/{ip}`; any provider returning
  `country`/`city`/`country_code` works, e.g. `http://ip-api.com/json/{ip}`) by a
  single rate-limited worker and cached (LRU, TTL). **Off by default** — the edge
  sends nothing anywhere unless you turn it on, private/loopback addresses are
  never sent out, and enabling it prints a privacy warning. The panel shows the
  location next to each IP. Still no new Go dependencies (plain `net/http`).

Both features are additive and change nothing about existing routing, tunnels or
config; the IP counter costs an O(1) map/LRU update per connection and geo never
touches the data path (lookups run out of band).

### Changed

- The panel's live per-domain and per-backend throughput now reads in **Mbps**
  (decimal megabits/second, the usual network unit) instead of bytes/second;
  cumulative totals stay in bytes (KiB/MiB/GiB).

## 2.4.0

### Panel

- **Manage domains and paths from the browser.** With `panel.allow_control`,
  the web panel now adds/removes `cdn_hosts` (domains) and
  adds/edits/removes/enables/disables backends and paths, including a local
  service on this VPS (`proto: http`, upstream `127.0.0.1:PORT`) reachable at
  `/<name>/`. Every change is written to the config under the same lock and
  whole-config validation the CLI uses, then applied live (a new domain gets a
  certificate on first use; a new UDP backend binds on the reload). New
  authenticated endpoints `POST <path>/api/host` and the extended
  `POST <path>/api/backend`, both CSRF-protected.
- **Live per-domain and per-backend traffic.** The dashboard shows requests,
  active connections and a live up/down byte rate for each domain and each
  backend, refreshing every few seconds. New per-host counters are exported in
  `/status` (`host_traffic`) and as `ayana_cdn_host_requests_total`,
  `ayana_cdn_host_active` and `ayana_cdn_host_bytes_total{host,direction}`.
- The shipped systemd unit now sets `ReadWritePaths=/etc/ayana-cdn` so
  panel-driven config edits work out of the box; remove the line to keep the
  config read-only to the service.

### Security / correctness fixes (from an independent audit)

- **Half-close no longer truncates a live transfer.** A tunnel whose two
  directions did not both finish within `half_close` of each other could be cut
  off mid-stream, because the linger was a single absolute deadline on both
  connections. It is now an *idle* bound on the surviving direction: an active
  transfer is never cut, a silent half-open one is still reaped after `half_close`.
- **Request-smuggling fix on the tunnel path.** A fixed-length request body is
  now forwarded with an explicit `Content-Length`; previously body bytes went
  out with no framing, which a backend could parse as a second, smuggled request.
- **Admin endpoint can require auth.** `admin_user`/`admin_password_hash`
  (bcrypt, `ayana-cdn admin passwd`) add HTTP Basic auth to everything but
  `/healthz`, so it is safe to reach remotely; the off-loopback warning is now
  specific about pprof exposure.
- **Reload no longer races a zero-downtime restart.** A `lifecycleMu` excludes
  a config reload (which reconciles UDP sockets) from the handoff that is
  duplicating those sockets; a colliding reload is refused, not corrupted.
- **Fairer UDP spoof defence.** A session now leaves the unreplied set only
  when the *client* keeps sending, not on the upstream's first reply, so a
  single spoofed datagram can no longer buy an eviction-immune, full-lifetime
  reflecting session; and the unreplied-eviction FIFO is per-listener, so a
  flood on one UDP backend can no longer evict sessions on another. An opt-in
  QUIC-style anti-amplification byte cap (`limits.udp_amplification`, off by
  default) can additionally bound reflected bytes to unverified sources.
- **Per-backend `max_conns` is now enforced for http/https/sse backends** (it
  was honoured only on the tunnel path).
- **Slow-body guard** (`timeouts.request_body`, default 60s) bounds a trickled
  or stalled request body on both the tunnel and proxy paths as an *idle*
  window (re-armed on each read, so a large upload that keeps progressing is
  never cut), without affecting streaming responses.
- **A sane `max_conns_per_ip` default (512)** so one source (a /64) cannot
  quietly pin the global connection cap.
- Client `X-Forwarded-Prefix` is now stripped on the proxy path for
  `strip:false` backends (it was already stripped on the tunnel path).
- `routes import` reports duplicate route paths instead of silently keeping the
  last, and refuses a route name that collides with an existing UDP backend
  instead of deleting that listener.
- The default health-check timeout no longer rejects a sub-3s interval, and a
  new `-check-timeout` flag sets it explicitly.
- The broadened health-check warning covers any active check on a raw/tunnel
  backend (OpenSSH `PerSourcePenalties`), not only `ws`.
- The shipped `config/config.json` is reconciled with `routes.json` so
  `make test` passes on a fresh unzip.

### Performance

- The HTTP-backend transport uses larger idle pools and 64 KiB read/write
  buffers; the SSE/response copy reuses the relay's buffer pool instead of
  allocating per response. (The edge was already tuned: BBR + fq, buffer
  autotuning, `tcp_notsent_lowat`, tuned keepalive/`TCP_USER_TIMEOUT`,
  `GOMEMLIMIT`, and adaptive 4 KiB/32 KiB relay buffers.)

## 2.3.0

### Added

- **Authenticated web panel** (`panel` config section, `ayana-cdn panel`
  commands): an HTTPS dashboard served on the public `:443` listener at a
  **secret path prefix**, guarded by a username and a bcrypt-hashed password.
  It is matched before any backend route and before `strict_host`, so no
  backend can shadow it and it stays reachable; its own auth protects it. The
  dashboard shows live connections, tunnels per backend with bytes, upstream
  health, certificate expiry and runtime stats, auto-refreshing from a JSON
  `api/status` endpoint. Read-only by default; `panel enable -control` adds
  reload and enable/disable-backend actions (the latter writes the config file,
  so it needs `ReadWritePaths=/etc/ayana-cdn` on the sandboxed unit).
  Security: bcrypt with a constant-time username check, a signed
  `HttpOnly`/`Secure`/`SameSite=Strict` session cookie scoped to the panel path
  (never sent to a backend), CSRF tokens on all state-changing actions, per-IP
  login lockout with exponential backoff, a strict nonce-based
  `Content-Security-Policy` with `X-Frame-Options: DENY` and `no-store`, an
  optional `panel.allowed_cidrs` source allowlist, and HTTPS-only serving. Set
  up with `ayana-cdn panel enable -user NAME` (prompts for the password without
  echo, generates a random secret path and signing key); `panel passwd`,
  `panel path`, `panel disable`, `panel show` and `panel hash` manage it. The
  only new import is `golang.org/x/crypto/bcrypt`, already part of the one
  existing dependency. See `docs/CONFIG.md` (`panel`) and `config/examples/panel.json`.

## 2.2.0

### Added

- **UDP backends** (`"proto": "udp"`, `"listen": ":port"`): a datagram relay
  alongside the TCP edge, for WireGuard, QUIC-based tunnels, DNS and game
  traffic. Each client address/port is an independent session with its own
  connected upstream socket, so many flows from one address are handled
  side by side. Sessions are reclaimed when idle (`timeouts.udp_idle`), when
  the upstream is ICMP-unreachable, or when it stays silent past
  `timeouts.udp_reply` (catching a black-holed or wrong upstream that no ICMP
  error reveals). `lb: "hash"` (the udp default) keeps every flow of one client
  on the same upstream so stateful servers and QUIC migrations keep working.
  UDP has its own per-IP budget (`limits.udp_rate_per_ip`, `udp_burst_per_ip`,
  `max_udp_sessions_per_ip`) and a global `limits.max_udp_sessions`; a
  spoofed-source flood is bounded by a separate unreplied-session cap with
  oldest-first eviction. `ayana-cdn backend add NAME HOST:PORT -proto udp
  -listen :PORT`, `echo-backend -udp ADDR`, per-backend UDP metrics and a
  `msg=udp` access line. UDP listeners are managed on reload and inherited
  across a zero-downtime restart (sessions are re-established in the new
  process).
- **Faster dead-peer detection** (`timeouts.dead_peer`, default 30s): TCP
  keepalive is tuned (probes after `client_keepalive`, dropped after
  `dead_peer` more) and `TCP_USER_TIMEOUT` is set to
  `client_keepalive + dead_peer` on client and upstream sockets, so a peer that
  vanishes without a FIN — a phone off network, a rebooted backend — is dropped
  in about a minute instead of Linux's multi-minute default, and unacknowledged
  data is bounded the same way. Such a close logs `client_dead`/`backend_dead`.

### Changed

- Dead-peer detection changes the behaviour of existing configs on upgrade: a
  silent, half-open TCP tunnel is now closed after `client_keepalive +
  dead_peer` (60s by default) rather than after the kernel's own keepalive
  schedule. `write_stall` still bounds a peer that is alive but not reading, and
  `TCP_USER_TIMEOUT` is never raised above it needlessly. Set `dead_peer` higher
  to loosen this.


## 2.1.0

- `ayana-cdn routes import FILE [-replace]`: apply a routes.json in the Cloud
  Run `http-proxy` relay's format (path prefix → target URL, path forwarded
  unchanged, Host rewritten to the target), with lists of targets for
  failover and an object form for an explicit Host.
- `setup.sh`: one command that installs or upgrades, prompts for the routes
  (path, target, optional Host; validated before anything is saved; kept in
  `/etc/ayana-cdn/routes.json`), probes every upstream and prints the client
  payload per route. `--routes FILE` and `--keep-config` for unattended runs.
- The package's `routes.json` and `config/config.json` carry the same example
  routes (a test keeps the two in agreement).

## 2.0.0

A rewrite of the data path and the operations around it. v1 config files load
unchanged; v1 installations upgrade with one `systemctl restart`.

### Fixed (v1 data loss, reproduced with an independent harness)

- Early data sent by the client in the same TLS record as the upgrade request
  was silently dropped; early data sent a moment later lost its first byte.
  Tunnels are no longer proxied through `httputil.ReverseProxy`; the bytes
  already buffered by `net/http` are forwarded.
- Backends answering `101` without an `Upgrade:` header (Python tunnel
  proxies) got a `502`; any `101` now switches to relay mode.
- `ayana-cdn backend add NAME HOST:PORT --host X`, the README's own example,
  failed with a usage error; flags may now appear anywhere.
- Connections with no SNI or a bug-host SNI were refused in ACME mode; they
  now receive the primary host's certificate (`strict_sni` restores the old
  behaviour on purpose).
- PROXY protocol headers were parsed inside `Accept`, so one slow peer stalled
  every accept.
- The nginx front door forwarded PROXY protocol headers to the other tunnel
  service, which most tunnel servers reject.
- The installer pinned an end-of-life Go release into `/usr/local/go` and
  built with a two-year-old `x/crypto`.

### Added

- Zero-downtime restart and upgrade: `ayana-cdn restart` / `SIGUSR2`, with
  socket inheritance, systemd `MAINPID` handoff and a drain that keeps existing
  tunnels alive (`timeouts.drain`).
- Several upstreams per backend, `least_conn` / `round_robin` / `first`,
  failover within the connect budget, passive and active health checks.
- `relay: always` for raw backends (200-then-raw, non-HTTP).
- Plain HTTP backends (`proto: http`/`https`/`sse`) with streaming.
- Per-IP connection rate and concurrency limits, a global cap derived from the
  descriptor limit, idle and write-stall timeouts, header size limit,
  per-backend `max_conns`, `disabled` backends, `strict_host`.
- Admin endpoint: `/status` (JSON), `/metrics` (Prometheus), `/healthz`,
  optional pprof. `ayana-cdn status` renders it.
- `ayana-cdn check` (validation, certificate info, upstream probes),
  `config show`, `backend set/enable/disable`, `bench`, `echo-backend`.
- Structured logs with one line per tunnel: bytes each way, duration, reason.
- PROXY protocol v2 alongside v1; trusted-source list.
- `redirect_listen` for http-01 challenges and http→https redirects.
- Config: unknown keys rejected with line numbers, defaults and validation for
  every setting, durations as strings, warnings for risky settings.
- Adaptive relay buffers (4 KiB / 32 KiB): about 35 KiB resident per idle
  tunnel against 57 KiB in v1.
- Installer: latest Go release verified by checksum into a private directory,
  config validated with the new build before anything is replaced, atomic
  binary replacement, `GOMEMLIMIT` drop-in at 75% of RAM, preflight checks
  for the port, DNS and clock, `--test`, `--no-sysctl`, `--no-start`,
  `--go-root`; `uninstall.sh`; bash completion.
- Hardened systemd unit (`Type=notify`, unprivileged, sandboxed,
  `LimitNOFILE=1048576`); kernel tuning with `tcp_notsent_lowat`.
- 49 tests, including in-process integration tests and an end-to-end restart
  test; the suite passes under the race detector.

### Changed

- `cdn_host` became `cdn_hosts` (a list); the old key still works.
- `upstream` became `upstreams` (a list); the old key still works.
- Default `admin_listen` is `127.0.0.1:9180`; set `"off"` to disable.
- The sysctl file is `99-ayana-cdn.conf`; v1's `99-cdn.conf` is removed by
  the installer.
- Minimum Go version to build: 1.26.

## 1.0.0

Initial release: stdlib `ReverseProxy` edge with autocert, SIGHUP reload,
PROXY protocol v1, installer, systemd unit, sysctl tuning, nginx front door.
