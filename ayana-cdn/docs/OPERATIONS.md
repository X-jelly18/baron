# Operations

## The service

| | |
|---|---|
| Unit | `ayana-cdn.service` (`Type=notify`, unprivileged user `ayana-cdn`, sandboxed) |
| Binary | `/usr/local/bin/ayana-cdn` (built by `deploy/install.sh` from `/opt/ayana-cdn/src` with the toolchain in `/opt/ayana-cdn/go`) |
| Config | `/etc/ayana-cdn/config.json` (+ `.bak` written by the `backend` commands; `config.json.example` is the package default) |
| State | `/var/lib/ayana-cdn/acme/` certificates and the ACME account key |
| Runtime | `/run/ayana-cdn/pid` |
| Admin | `http://127.0.0.1:9180/` (`/status`, `/metrics`, `/healthz`) |
| Logs | `journalctl -u ayana-cdn -f` |
| Memory limit | `/etc/systemd/system/ayana-cdn.service.d/10-memory.conf`, `GOMEMLIMIT` at 75% of RAM; edit it and remove the "managed" line to keep your own value |

`systemctl status ayana-cdn` shows `Main PID`; after a zero-downtime restart it
is the new process. `ayana-cdn status` is the operator's view: connections,
tunnels per backend with bytes and failures, upstream health, certificate
expiry, memory and file descriptors.

## Three ways to apply a change

| | What it does | Open tunnels | New connections |
|---|---|---|---|
| `ayana-cdn reload` (`systemctl reload`, `HUP`) | Re-reads the config. Backends, limits, timeouts, log level, certificate files. Rejected if invalid: the old config stays. | untouched | untouched |
| `ayana-cdn restart` (`USR2`) | Starts a new process on the same sockets, then the old one drains. Needed for a new binary and for `listen`, `admin_listen`, `redirect_listen`, `tls.mode/email/cache_dir`, `timeouts.read_header/http_idle`, `log.format`, `limits.max_header_bytes`. | keep running in the old process until they end (up to `timeouts.drain`); **UDP sessions are re-created in the new process** (a new upstream source port; invisible to roaming/QUIC clients, a reconnect for source-keyed upstreams) | served by the new process immediately; none are refused or dropped |
| `systemctl restart` | Stops the process (`TERM`) and starts a new one. | closed at once; clients reconnect | refused for about a second |

`reload` logs a warning naming any changed setting that needs a restart.
`restart` refuses to act on a broken config, on a process that does not answer
as v2 (v1 would die from the signal; use `systemctl restart` once), and while
a previous restart is still handing over. If the new process fails to start,
the old one keeps serving and the failure is in the journal.

During a drain both processes run. `ayana-cdn status` talks to the new one;
the old one has stopped accepting, logs `restart: handed over; this process
now drains` and exits on its own when its last tunnel closes (`drain
complete`). A drain that runs into `timeouts.drain`
closes the remaining tunnels with reason `drain_timeout`.

## Certificates

**ACME (default).** The CDN hostnames must resolve to this server and port 443
must be reachable from the internet; Let's Encrypt validates over TLS-ALPN-01
on 443, so port 80 is not required. The edge requests each certificate when it
starts (retrying after 10 and 30 minutes on failure, then on client
handshakes) and renews 30 days before expiry. Problems appear in the journal as
`acme: …` lines; `ayana-cdn check` shows the certificate or "not issued yet".
Behind the nginx front door this still works: nginx routes the validation
connection by SNI to the edge like any other. If you prefer http-01, set
`"redirect_listen": ":80"`; the same listener redirects plain HTTP to https.

If you add a hostname to `cdn_hosts`, reload; it is issued on the first
handshake for it (the warm-up only runs at start).

**Files.** For certificates managed elsewhere (certbot, a wildcard):

```json
"tls": { "mode": "files", "cert_file": "/etc/ayana-cdn/tls/fullchain.pem", "key_file": "/etc/ayana-cdn/tls/privkey.pem" }
```

The service user must be able to read them. The simplest robust setup is a
certbot deploy hook that copies the files and reloads:

```sh
# /etc/letsencrypt/renewal-hooks/deploy/ayana-cdn.sh
#!/bin/sh
install -d -m 0750 -o root -g ayana-cdn /etc/ayana-cdn/tls
install -m 0640 -o root -g ayana-cdn "$RENEWED_LINEAGE/fullchain.pem" /etc/ayana-cdn/tls/fullchain.pem
install -m 0640 -o root -g ayana-cdn "$RENEWED_LINEAGE/privkey.pem"   /etc/ayana-cdn/tls/privkey.pem
ayana-cdn reload
```

A reload re-reads the files; a certificate that fails to load is rejected and
the previous one stays in use.

## Monitoring

`ayana-cdn status -json` and `curl -s 127.0.0.1:9180/status` return the same
document; `/metrics` is Prometheus text. Metrics worth alerting on:

| Metric | Alert when |
|---|---|
| `ayana_cdn_upstream_up{backend,upstream}` | `0` for longer than a check interval or two |
| `ayana_cdn_cert_expiry_timestamp_seconds{host}` | less than 14 days away (renewal is failing) |
| `ayana_cdn_connections_rejected_total{reason}` | rising: `global` means the connection cap, `ip_rate`/`ip_conns` a client or a proxy in front hitting the per-IP limits |
| `ayana_cdn_backend_failures_total{backend}` | rising: upstream dials or 5xx answers |
| `ayana_cdn_connections_active` vs `ayana_cdn_connections_max` | approaching the cap |
| `ayana_cdn_open_fds` vs `ayana_cdn_max_fds` | approaching the limit |
| `ayana_cdn_draining` | `1` for longer than a restart should take |
| `ayana_cdn_udp_sessions_active` vs `ayana_cdn_udp_sessions_max` | approaching the UDP session cap (the ephemeral port range is the real ceiling) |
| `ayana_cdn_udp_dropped_total{backend,reason}` | rising: `port_exhausted` means the local port range is full; `ip_rate`/`ip_conns` a client or flood hitting the UDP per-IP limits; `dial_error` an unresolved or unreachable upstream |

Per-backend counters: `tunnels_active`, `tunnels_total`, `bytes_total{direction=up|down}`,
`responses_total{class}`, `backend_capacity_rejections_total`,
`upstream_connections`, `upstream_dials_total{result}`. Global:
`tls_sni_fallback_total` (clients using a bug host as SNI),
`tls_sni_rejected_total` (strict mode), `requests_unrouted_total` (404),
`requests_misdirected_total` (421), `config_reloads_total{result}`.

Each finished tunnel logs one line:

    msg=tunnel backend=native1 client=203.0.113.9 upstream=native1.example.com:443 status=101 up=8421 down=190330 duration=1h2m3s reason=client_closed

`reason` is who ended it: `client_closed` / `backend_closed` (clean),
`client_stalled` / `backend_stalled` (`write_stall` expired: the peer stopped
reading), `client_dead` / `backend_dead` (TCP keepalive or `TCP_USER_TIMEOUT`
gave up: the peer vanished without closing), `idle_timeout`, `client_error: …`
/ `backend_error: …` (the underlying error, e.g. a reset), `shutdown`,
`drain_timeout`. UDP sessions log `msg=udp … packets_up=… packets_down=…
reason=…` where the reason is `idle_timeout`, `upstream_unreachable`,
`upstream_silent`, `evicted_unreplied`, `backend_removed`, `shutdown` or
`restart`. Proxied HTTP requests log `msg=http … status=… duration=…`, and
failures include `err=`.

`/healthz` on the public listener answers `200 ok` while serving and `503`
while draining, for an external load balancer.

## Capacity

Each tunnel is one client connection plus one backend connection: two file
descriptors, two goroutines and, measured with 2,000 idle TLS tunnels, about
35 KiB of resident memory (most of it the TLS session buffers). The unit sets
`LimitNOFILE=1048576`, which makes the automatic `limits.max_conns` 524,032.
Memory, not descriptors, is the practical limit: 50,000 idle tunnels need
about 1.7 GiB; busy tunnels use up to 64 KiB more each while moving bulk
data. Throughput through one tunnel was 343 MB/s each way on a single shared
vCPU in testing; the edge is not the bottleneck on typical VPS links.

Outbound connections to a backend use one local port each, so
`net.ipv4.ip_local_port_range` (set to 10000–65535 by the sysctl file) bounds
the tunnels to one `host:port` at about 55,000. Spread very large deployments
over several backend addresses or ports.

A UDP session is one connected socket, so it also holds one local port and one
descriptor; the practical ceiling for all UDP sessions of one edge is the width
of `net.ipv4.ip_local_port_range` (about 55,000 with the shipped sysctl). The
automatic `limits.max_udp_sessions` is the smaller of that and the
descriptor-derived figure, and the effective value is logged as `max_sessions`
on each `udp listening` line at start. Raise the port range, or spread udp
upstreams over more addresses, to go higher. Connection tracking, if the firewall
uses it, needs one entry per connection on both sides; the sysctl file raises
`nf_conntrack_max` to 262,144 when the module is loaded.

The kernel tuning in `deploy/sysctl-99-ayana-cdn.conf` (BBR, larger buffer
ceilings, `tcp_notsent_lowat`, bigger accept backlogs) is installed unless
`--no-sysctl` is given; containers that forbid sysctl writes get a warning and
run with the kernel defaults.

## Troubleshooting

| Symptom | Likely cause | What to do |
|---|---|---|
| `502`, log `all upstreams failed: … connection refused` | backend down or wrong `upstreams` | `ayana-cdn check` probes every upstream and prints the error |
| `502`, log `backend did not answer with HTTP` | raw backend (SSH straight on the socket, stunnel) | `"relay": "always"` |
| `504` | backend accepted but did not answer within `timeouts.upstream_header` | check the backend; raise the timeout |
| `404` | path does not match a backend name; `/native1x` is not `/native1` | `ayana-cdn backend ls`; debug log shows the path |
| `421` | `strict_host` and the client sent another `Host:` | fix the client payload or disable `strict_host` |
| `503` | backend disabled, or its `max_conns` reached | `ayana-cdn status` shows which |
| TLS handshake failures in the debug log | `strict_sni` with a bug-host SNI, or `min_version` above what the client supports | check `tls_sni_rejected_total`; relax the setting |
| clients refused in bursts, `rejected_total{reason="ip_rate"}` | many clients behind one NAT, or a proxy in front | raise `conn_rate_per_ip`/`conn_burst_per_ip`, or add the proxy to `limits.exempt` and use PROXY protocol so limits apply per real client |
| `ayana-cdn restart` says the process does not answer as v2 | v1 is running | `systemctl restart ayana-cdn` once |
| `acme: …` errors | DNS not pointing here, port 443 not reachable, clock wrong | `ayana-cdn check`, `timedatectl`, firewall; the edge retries on its own |
| log `udp backend not listening` | its `listen` port is taken (on `:53`, usually systemd-resolved) | free the port (`ss -ulnp`; for resolved set `DNSStubListener=no` in `/etc/systemd/resolved.conf` and restart it), then `ayana-cdn reload`. The rest of the edge kept serving |
| UDP client gets no replies | wrong upstream, or the edge answers from another IP on a multi-homed host | `ayana-cdn status` shows the session and `upstream_silent`/`dial_error`; bind the backend's `listen` to the address clients use |
| `ayana_cdn_udp_dropped_total{reason="upstream_silent"}` rising | the upstream is up but not answering (wrong port, black hole) | check the upstream; `udp_reply` bounds how long a silent session lingers |
| `reload rejected` in the journal | invalid config | `ayana-cdn check -no-dial` shows the line and reason; the running config is unaffected |
| old process still around long after a restart | tunnels still open (expected) | it exits when they end or after `timeouts.drain`; `kill -TERM <old pid>` closes them now |

Set `"log": {"level": "debug"}` and reload for handshake and routing detail;
`admin_pprof: true` (restart) exposes CPU and heap profiles at
`127.0.0.1:9180/debug/pprof/`.

## Security

- The service runs as the `ayana-cdn` user with only `CAP_NET_BIND_SERVICE`,
  under `ProtectSystem=strict`, `PrivateDevices`, `MemoryDenyWriteExecute` and
  the other restrictions in the unit. It can write only to `/var/lib/ayana-cdn`
  and `/run/ayana-cdn`.
- The admin endpoint is unauthenticated: keep `admin_listen` on loopback
  (the installer warns otherwise) and use SSH port forwarding to reach it. For
  a browser dashboard you can reach remotely, use the **web panel** below
  instead of exposing the admin port.
- PROXY protocol headers are accepted only from `proxy_protocol_trusted`, so
  clients cannot forge their address; forwarding headers sent by clients are
  replaced.
- `"insecure": true` on a backend disables certificate verification for that
  backend only and is logged at startup. Prefer a real certificate on the
  backend or a private CA.
- Per-IP rate and connection limits are **off by default** (this edge fronts
  tunnel clients that legitimately open many connections, often behind one
  carrier NAT). The global connection cap stays on as an auto fd-derived
  backstop (so the process can't exhaust file descriptors), and the header size
  limit is 32 KiB. Turn per-IP limits on by setting `limits.conn_rate_per_ip`
  / `max_conns_per_ip` to positive values if you need to throttle a source.
- Optional hardening: adding `SystemCallFilter=@system-service` to the unit
  works with Go on current kernels, but a filtered syscall kills the process
  with `SIGSYS` on kernels where the runtime uses something outside the set.
  Add it, restart, and watch the journal for a day before relying on it.

## The web panel

An authenticated dashboard on the public `:443` listener at a secret path, so
you can watch connections, tunnels, upstream health and certificates from a
browser without opening the admin port. Set it up with:

```sh
sudo ayana-cdn panel enable -user admin      # prompts for a password (no echo),
                                             # generates a secret path + session key
sudo ayana-cdn panel show                    # prints the full https URL to open
```

- Open the printed URL (`https://<cdn host>/<secret path>/`) and sign in.
- `panel passwd` changes the password; `panel path` rotates the secret prefix;
  `panel disable` turns it off (settings are kept).
- The dashboard shows **live per-domain and per-backend traffic** (requests,
  active connections, up/down rate), upstream health and certificate expiry,
  refreshing every few seconds.
- It is read-only by default. `ayana-cdn panel enable -control` turns on the
  management actions: **reload the config**, **add/remove domains**
  (`cdn_hosts`), and **add/edit/remove/enable/disable backends and paths** —
  including a local service on this box (`proto: http`, upstream
  `127.0.0.1:PORT`), reachable at `/<name>/`. Every change is written to
  `/etc/ayana-cdn/config.json` and applied live (a new domain gets a Let's
  Encrypt certificate on first use; a new UDP backend binds its socket on the
  reload). For those writes to work the service (which runs as the `ayana-cdn`
  user) needs `/etc/ayana-cdn` both reachable and owned by it: the shipped unit
  grants `ReadWritePaths=/etc/ayana-cdn` and the installer `chown`s the config
  directory to the service user. If you see a permission error adding a backend
  from the panel, run `sudo chown -R ayana-cdn:ayana-cdn /etc/ayana-cdn` and
  `sudo systemctl daemon-reload && sudo systemctl restart ayana-cdn` (a full
  restart, so the unit's `ReadWritePaths` takes effect — `ayana-cdn restart`
  does not reload the unit). Remove the `ReadWritePaths` line to keep the panel
  read-only at the filesystem level. The CLI (`ayana-cdn backend/panel …`) runs
  as your shell user and never needs any of this.
- Defenses: bcrypt-hashed password, constant-time check, signed `HttpOnly`
  `Secure` `SameSite=Strict` cookie scoped to the panel path (so it never leaks
  to a backend), CSRF tokens on actions, per-IP login lockout with backoff, a
  strict nonce CSP, and an optional `panel.allowed_cidrs` source allowlist.
  Leave `panel.session_key` set (enable writes one) so a restart does not log
  everyone out; clear it to force logout on restart.

## The nginx front door (optional)

Only if another service on this VPS must keep receiving connections on 443.
`deploy/frontdoor.conf` routes by SNI without decrypting: the CDN hostname to
the edge (which listens on `127.0.0.1:8443` with `proxy_protocol: true`, see
`config/examples/frontdoor.json`), everything else to your existing tunnel
service. It passes the real client address to the edge with PROXY protocol and
strips that header again before your other service, which usually does not
understand it. The comments in the file walk through the four steps.

## Without systemd

`ayana-cdn serve -config FILE [-pidfile FILE]` runs in the foreground and
writes its pid file (default `/run/ayana-cdn/pid`); `reload` and `restart`
find the process through it. Readiness and stop notifications are simply
skipped when `NOTIFY_SOCKET` is not set.

## Uninstall

`sudo ./deploy/uninstall.sh` removes the service, binary, toolchain and
kernel tuning and keeps `/etc/ayana-cdn` and `/var/lib/ayana-cdn`; add
`--purge` to delete those and the service user too.
