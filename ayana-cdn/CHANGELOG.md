# Changelog

## 2.7.3

### Fixed

- **The panel could lose permission to change the config** ("permission
  denied" when adding a path or domain, or on reload) after any `ayana-cdn`
  command run as root (`backend add/set`, `panel enable`, `routes import`, a
  setup run). Such a command rewrote `config.json` owned by root, so a config
  with mode 640 became unreadable to the service user that the edge and its
  panel run as, and its lock file could be left root-only too; the next
  restart would have failed. Files root writes in `/etc/ayana-cdn` now belong
  to the owner of that directory (the service user), and a broken install is
  repaired by the next such command, or right away with:
  `sudo chown -R ayana-cdn:ayana-cdn /etc/ayana-cdn && sudo systemctl restart ayana-cdn`.

## 2.7.2

### Fixed

- **Restoring onto a VPS where the edge already runs** stops it first, and the
  install starts it again. Before, systemd's sandbox kept the running edge on
  the moved-aside directories, so after the zero-downtime restart the restored
  config and certificates were read-only to it: panel saves and certificate
  renewals failed until a reboot.
- **A restore can be undone and cannot half-finish.** The archive is checked
  and unpacked into a scratch directory before anything moves, so a broken or
  truncated file, or a full disk, changes nothing. If the install then fails,
  the VPS's previous settings are put back (and an edge that was running is
  started again). The restored files belong to the service user at once.
- A restore refuses archives with entries for `/`, `/etc` or `/var` themselves
  (tar would have changed their permissions), as well as links and anything
  outside ayana-cdn's two directories.
- `--restore` combined with `--routes` or `--backup` (and `--backup` with
  `--keep-config`) is refused instead of silently doing something else.
- A backup never overwrites another: the one it replaces is kept with its date
  in the name (the five newest), so a backup copied to `/root` from the old VPS
  survives a later setup run. `--backup DIR` saves `DIR/ayana-cdn-backup.tar.gz`,
  a path inside the backed-up directories is refused, the temporary file is
  created safely, and linked certificate files are stored as plain files.
- `uninstall.sh --purge` also deletes the copies a restore leaves behind.

## 2.7.1

### Added

- **Move the settings to a new VPS.** Every `setup.sh` run now saves the
  config (domains, paths and servers, panel login and secret path), the routes
  file and the ACME account and certificates to
  `/root/ayana-cdn-backup.tar.gz` (mode 600; the previous one is kept as
  `ayana-cdn-backup.prev.tar.gz`). `sudo ./setup.sh --backup [FILE]` saves it
  at any time without installing. On the new VPS,
  `sudo ./setup.sh --restore FILE` puts the settings in place, moves anything
  already there to `*.before-restore-*`, installs with the settings kept (like
  `--keep-config`), and lists what is left to do: the DNS of each domain,
  services on the VPS itself that a path reaches, and servers that only accept
  the old address. The restored certificates serve at once, without a new
  Let's Encrypt order. A restore accepts only regular files of ayana-cdn's own
  two directories, so a wrong or tampered archive is refused before anything
  is touched; a plain `tar` of `/etc/ayana-cdn` and `/var/lib/ayana-cdn`
  restores the same way.

## 2.7.0

### Changed

- **Path-based routing: each path connects only to its own server.** A path
  (backend) used to balance between the servers it listed (`least_conn` by
  default) and fail over to the next one when a server did not answer. Now a
  path connects to exactly one server and to nothing else: no load balancing,
  no failover. If that server is down, the client gets `502` and retries; it is
  never sent to another server. Health checks still run and show each server's
  state in `status`, the panel and the metrics, but never route anywhere. For
  several servers, give each its own path. UDP backends, which are reached by
  port rather than by path, keep their upstream lists and `lb` policies.
- **Upgrading is safe.** A config that lists several servers on one path still
  loads (an upgrade never stops the edge): the path uses its first server, and
  a warning names the ignored ones in the log, `ayana-cdn check`, `backend ls`
  and on the path's card in the panel. The file itself is left as it is.
  Tunnels opened to another server before the upgrade keep running until they
  close; Prometheus series for the ignored servers disappear.
- **New input takes one server per path.** The panel, `ayana-cdn backend
  add/set` and `ayana-cdn routes import` refuse several servers on one path
  ("give each server its own path"); the panel's form has a single Server
  field and shows LB only for udp. `setup.sh` takes one target per path; when
  it reapplies a saved routes file that still lists several, it keeps the
  running routes and says so instead of stopping the upgrade.
- `lb` for a path backend is `path` (the default). The `least_conn`,
  `round_robin` and `first` of older configs are accepted and mean the same;
  `ayana-cdn backend set NAME -lb ...` refuses them, and `hash` stays udp-only.
- `config/examples/failover.json` is now `per-path.json` (one server per path).

### Fixed

- **Editing a backend in the panel keeps the settings the form does not
  show.** Saving the Edit form used to drop `max_conns`, `idle_timeout` and,
  while the proto stays the same, an explicit `tls` and the `health_check`.
- **The panel's Edit button opens the backend as it is now**, not as it was
  when its card was drawn, so a second edit no longer reverts the first.
- `ayana-cdn backend set NAME -lb path` writes nothing (a path has no policy
  to choose), so the file stays readable by the previous version.
- `TestUDPSilentUpstreamClosed` could pass its wait before the session existed
  and then miss the log line under a loaded test run; it now waits for the
  close itself.

## 2.6.3

### Fixed

- **Upgrading no longer drops the domains you added in the panel.**
  `sudo ./setup.sh --keep-config` still asked for a domain and then replaced
  `cdn_hosts` with that single domain, so every domain added from the web
  panel's Domains section was silently removed on upgrade. With
  `--keep-config` on an existing install, setup.sh now asks nothing and leaves
  the domains and the ACME email as they are (set `AYANA_CDN_DOMAIN` to add one
  anyway).
- **Entering a domain in setup.sh adds it instead of replacing the others.**
  The domain you type becomes the primary (first) entry of `cdn_hosts`; domains
  already configured are kept after it, and the installer lists them so you can
  remove any you no longer use from the panel. A legacy `cdn_host` entry is
  folded in, and re-entering an existing domain just moves it to the front.
- `AYANA_CDN_DOMAIN` given in upper case is accepted (lower-cased), as typed
  input already was.

## 2.6.2

### Changed

- **The panel downloads ~30-40x less per refresh.** Each 2 s poll used to
  re-download the full 3-minute graph history for every backend, the whole
  status document and the client-IP log — about 66 KB per poll at 20 backends
  and 225 KB at 100, i.e. a continuous 32-110 KB/s on a phone, enough to make
  the dashboard lag on a weak mobile link. Now:
  - `GET <panel>/api/series?since=<tick>&epoch=<id>` returns only the samples
    taken since the last poll (one point per series); the whole window is sent
    only on first load, after a restart, or after a gap longer than the window.
  - Panel API responses are gzip-compressed when the browser accepts it
    (status shrinks ~10x). The bodies carry no secrets, so this is BREACH-safe.
  - The client-IP log refreshes every 10 s (or at once when you pick another
    backend) instead of every 2 s.
  - Polling pauses while the tab is hidden (including a tab opened in the
    background) and resumes with an immediate refresh. Polls never overlap,
    and each is bounded by a 10 s timeout, so a request stuck on a dead
    connection cannot freeze the dashboard. A slow IP-log reply for a backend
    you just switched away from can no longer overwrite the one now selected.
  Result: ~2.1 KB per poll at 20 backends (1 KB/s), ~5.5 KB at 100 (2.7 KB/s).

### Added

- **TCP congestion-control check.** The panel's Runtime section and
  `ayana-cdn check` now show the kernel's TCP congestion control and default
  qdisc, and warn (with the fix) when BBR is not actually in force — the
  installer asks for BBR, but some hosts (containers, images that reset sysctl
  at boot) silently keep cubic, which costs a lot of throughput to clients on
  lossy mobile links. Also exposed in the status JSON as
  `runtime.tcp_congestion`, `default_qdisc`, `bbr_available`, `net_advice`.

## 2.6.1

### Added

- **`docs/PERFORMANCE.md`** documenting the throughput design and an honest
  comparison to sing-box / Hiddify (what applies to a TLS edge and what does
  not — splice, mux and TCP Brutal), plus how to measure.
- **`BenchmarkPipeThroughput`** — a relay copy-loop throughput benchmark
  (`go test -bench`). It confirms the current 32 KiB burst buffer is optimal
  (~1.45 GB/s/core on loopback; larger buffers are measurably slower here), so
  no buffer change was made.

### Changed

- **Panel stays smooth with many backends.** The dashboard no longer tears down
  and rebuilds every domain row and backend card (with its SVG charts) on each
  2 s refresh. Rows and cards are now built once and only their changing values
  and sparklines are updated in place — sparkline SVG paths are created once and
  only their geometry is redrawn. A full refresh with ~100 backends dropped from
  ~32 ms to ~12–17 ms per tick (roughly 2–3× less work; far more on a phone),
  so live updates no longer stutter when you run a lot of backends. Open add/edit
  forms and expanded backend details are preserved across refreshes. No
  functional or visual change.

  Note: the edge itself was already fast here — install-time validation, startup,
  config reload and the zero-downtime restart are all well under a tenth of a
  second even at 100 backends; the cost was purely in the browser-side panel
  re-render, which this addresses.

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
