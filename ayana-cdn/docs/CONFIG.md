# Configuration reference

The config is one JSON file, `/etc/ayana-cdn/config.json`. Unknown keys are
rejected with the line number, so typos cannot silently do nothing. Durations
are strings like `"30s"`, `"5m"`, `"4h"` (a bare number means seconds).

`ayana-cdn config show` prints the effective config with every default filled
in; `ayana-cdn check` validates it and probes the upstreams. `ayana-cdn backend
…` edits the file for you and writes only what you set, so the file stays as
short as the one you wrote.

Everything applies with `ayana-cdn reload` except the settings marked
**restart**, which are bound when the process starts and are picked up by
`ayana-cdn restart` (no downtime).

## Top level

| Key | Default | Meaning |
|---|---|---|
| `listen` | `":443"` | Public address. **restart** |
| `cdn_hosts` | required in acme mode | Hostnames clients connect to. The first one is the primary: its certificate is served to clients that send no SNI or an unknown one (bug hosts). v1's `cdn_host` (a single string) is still accepted and merged. |
| `strict_sni` | `false` | Refuse TLS handshakes whose SNI is not one of `cdn_hosts`. Off by default because tunnel clients often send a bug host as SNI. |
| `strict_host` | `false` | Answer `421` to requests whose `Host:` header is not one of `cdn_hosts`. |
| `enable_http2` | `false` | Offer `h2` in ALPN. Leave off for tunnel clients: WebSocket upgrades need HTTP/1.1, and clients that negotiate h2 could not tunnel. |
| `proxy_protocol` | `false` | Accept a PROXY protocol v1 or v2 header (from nginx `proxy_protocol on`, a load balancer) to learn the real client address. |
| `proxy_protocol_trusted` | `["127.0.0.0/8","::1/128"]` | Only these sources may send the header; everyone else's is refused so nobody can spoof their address. |
| `redirect_listen` | off | Plain-HTTP listener, e.g. `":80"`: answers ACME http-01 challenges (acme mode) and redirects everything else to `https://`. **restart** |
| `admin_listen` | `"127.0.0.1:9180"` | Local endpoint for `status`, `/metrics`, `/status`, `/healthz`. `"off"` disables it (then `ayana-cdn status` and `restart` cannot verify the process). Keep it on loopback, or set `admin_user`/`admin_password_hash` to bind it elsewhere safely. **restart** |
| `admin_pprof` | `false` | Also serve Go's `/debug/pprof/` on the admin endpoint. Never expose it unauthenticated off loopback. **restart** |
| `admin_user`, `admin_password_hash` | empty | Optional HTTP Basic auth for the admin endpoint (bcrypt hash; set both with `ayana-cdn admin passwd`). When set, everything but `/healthz` requires the credential, compared in constant time. This is what lets you bind `admin_listen` to a reachable address. |

## `tls`

| Key | Default | Meaning |
|---|---|---|
| `mode` | `"acme"` | `acme`: Let's Encrypt via TLS-ALPN-01 on port 443 (or http-01 if `redirect_listen` is `:80`). `files`: use `cert_file`/`key_file`. **restart** |
| `email` | | Account contact for Let's Encrypt expiry notices. Recommended. **restart** |
| `cache_dir` | `"/var/lib/ayana-cdn/acme"` | Where issued certificates and the account key are stored. Must stay under `/var/lib/ayana-cdn` for the sandboxed service. **restart** |
| `cert_file`, `key_file` | | files mode: full chain and private key (PEM). Re-read on every `reload`, so certbot deploy hooks can just run `ayana-cdn reload`. |
| `min_version` | `"1.2"` | Lowest TLS version accepted: `1.0`, `1.1`, `1.2`, `1.3`. |

Certificates are requested when the edge starts (and retried after 10 and 30
minutes if that fails), then renewed automatically about 30 days before
expiry. `ayana-cdn status` and `check` show the expiry date.

## `limits`

| Key | Default | Meaning |
|---|---|---|
| `max_conns` | `0` = auto | Global cap on open client connections. Auto derives it from the process's file-descriptor limit (each tunnel needs two): with the unit's `LimitNOFILE=1048576` that is 524,032. `-1` disables the cap. Connections over the cap are closed at accept. |
| `max_conns_per_ip` | `0` = off | Concurrent connections per client address (IPv6 counted per /64). Off by default (no per-IP cap); set a positive number to cap one source — useful if a single /64 starts pinning resources. |
| `conn_rate_per_ip` | `0` = off | New connections per second per client address, as a token bucket. Off by default; set a positive number (e.g. `50`) to rate-limit new connections per source. |
| `conn_burst_per_ip` | `300` | Bucket size: how many connections one address may open at once before the rate applies. |
| `exempt` | `["127.0.0.0/8","::1/128"]` | CIDRs never subject to the per-IP limits (your own monitoring, a front door without PROXY protocol). |
| `max_header_bytes` | `32768` | Request header size limit, 4096 to 1048576. **restart** |
| `max_udp_sessions` | `0` = auto | Global cap on concurrent UDP sessions (one per client address/port). Auto is derived from the file-descriptor limit and the ephemeral port range, whichever is smaller, because every session takes one local port. `-1` disables the cap. |
| `max_udp_packet` | `8192` | Largest datagram relayed, in bytes, 576 to 65507. Bigger datagrams are dropped and counted as `oversize`. 8192 covers the tunnel protocols that avoid IP fragmentation. |
| `udp_rate_per_ip` | `0` = off | New UDP sessions per second per client address, a token bucket independent of the TCP `conn_rate_per_ip`. Off by default so a legitimate burst (a game or DNS client opening many flows) is not throttled; set it if you see spoofed-source floods. |
| `udp_burst_per_ip` | `1000` | Bucket size for `udp_rate_per_ip`. |
| `max_udp_sessions_per_ip` | `0` = off | Concurrent UDP sessions per client address (IPv6 per /64). Off by default; set a positive number to cap one source. Separate from `max_conns_per_ip` so UDP and TCP do not compete for one budget. |
| `udp_amplification` | `0` = off | Opt-in anti-amplification (QUIC's 3× rule): set a positive factor and, until a UDP source proves return-routability (it sends a second datagram), the edge reflects at most that many bytes per byte the source sent, withholding the rest (counted as `amplified`). Off by default because a byte-ratio cap necessarily withholds the first reply of a legitimate high-ratio request/reply protocol (a DNS answer, say) until the client retransmits. Spoofed-source reflection is already bounded without it — a single-datagram source never gains an eviction-immune, full-lifetime session (it leaves the unreplied set only once the *client* keeps sending), and the per-IP/global session caps apply — so enable this only for a backend deliberately exposed to untrusted one-shot clients, alongside BCP38 ingress filtering. |

Refused connections are counted in `ayana_cdn_connections_rejected_total` by
reason (`global`, `ip_rate`, `ip_conns`) and shown by `ayana-cdn status`.
UDP sessions have their own per-IP budget (`udp_rate_per_ip`,
`udp_burst_per_ip`, `max_udp_sessions_per_ip`), so many flows from one address
are allowed without competing with TCP tunnel connects; UDP admission refusals
are counted in `ayana_cdn_udp_dropped_total{backend,reason}`, not in
`connections_rejected_total`. The same `exempt` list applies to both.

## `timeouts`

| Key | Default | Meaning |
|---|---|---|
| `read_header` | `"10s"` | Time a client has to complete the TLS handshake and send its request headers. **restart** |
| `http_idle` | `"75s"` | Idle keep-alive time between requests on a plain HTTP connection (tunnels are not affected). **restart** |
| `upstream_connect` | `"5s"` | Connect budget (TCP + TLS) to a path's server; past it the client gets `502` (no other server is tried). |
| `upstream_header` | `"15s"` | The backend must answer the request head within this, else the client gets `504`. |
| `request_body` | `"60s"` | Bound on reading a client request *body* (a slow-body / R-U-Dead-Yet hold of a goroutine and an upstream connection). Applies only to requests that carry a body, so GET and SSE subscribers are unaffected, and it never touches a streaming *response*. `-1` turns it off for legitimately slow large uploads. |
| `tunnel_idle` | `0` = never | Close a tunnel that has carried no bytes in either direction for this long. Most SSH clients keep tunnels alive themselves; set this only if you see leaks. |
| `udp_idle` | `"60s"` | Close a UDP session that has carried no datagram either way for this long. A datagram flow has no close, so this reclaims vanished clients. Overridden per backend by `idle_timeout`. |
| `udp_reply` | `"15s"` | Close a UDP session whose upstream never answers, even while the client keeps sending: it catches a black-holed or wrong upstream that no ICMP error reveals, and rotates the upstream. `-1` turns it off for one-way protocols (syslog, some telemetry). |
| `write_stall` | `"2m"` | Close a tunnel whose receiving side has stopped reading (a client that vanished without closing). |
| `half_close` | `"30s"` | After one side closes, how long the other direction may keep sending. |
| `client_keepalive` | `"30s"` | How long a TCP connection may be silent before the kernel starts keepalive probes, on both client and upstream sockets. `0` uses the default (30s); it is not an off switch. |
| `dead_peer` | `"30s"` | How much longer a peer that answers no probe survives: it is dropped `client_keepalive + dead_peer` after its last sign of life (60s by default, against roughly 2.5 minutes with the kernel defaults before). This also arms `TCP_USER_TIMEOUT`, so data left unacknowledged that long ends the connection too, rather than after Linux's ~15-minute retransmission limit. `0` keeps the kernel's own probe schedule. Applies to client and upstream sockets. |
| `shutdown_grace` | `"5s"` | On `systemctl stop`, how long in-flight HTTP requests get to finish (tunnels are closed at once). |
| `drain` | `"4h"` | After `ayana-cdn restart`, how long the old process keeps serving its existing tunnels before closing the rest. |

`write_stall` still bounds a peer that is alive but has stopped reading (its
socket keeps answering keepalive probes): `TCP_USER_TIMEOUT` is never set below
`write_stall`, so `dead_peer` shortens detection of a *dead* peer without
cutting a merely slow one early. A tunnel closed by keepalive/user-timeout logs
`reason=client_dead`/`backend_dead`; one closed by `write_stall` logs
`client_stalled`/`backend_stalled`.

## `log`

| Key | Default | Meaning |
|---|---|---|
| `level` | `"info"` | `debug`, `info`, `warn`, `error`. `debug` adds handshake failures, unrouted requests and health-check details. |
| `format` | `"text"` | `text` or `json`. Under systemd the timestamp is omitted (the journal has it). **restart** |
| `access` | `true` | One line per finished tunnel (`msg=tunnel`) and proxied request (`msg=http`). Set `false` on very busy edges. |
| `ip_log` | `true` | Keep a per-backend counter of client IPs (hits, first/last seen), shown in the panel's **Client IPs** section. In-memory only, bounded to the top ~2048 addresses per backend (least-recently-seen evicted), so it is cheap and never grows without bound. Set `false` to turn it off. |

## `geo`

Optional IP **geolocation** for the per-backend IP log. **Off by default** — the
edge sends nothing anywhere unless you turn it on (`ayana-cdn geo on`). When on,
each logged *public* IP is resolved once against `url` and cached; private and
loopback addresses are never sent out. Sending client IPs to a third-party
service has privacy implications: point `url` at a provider you trust or a
self-hosted one.

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `false` | Resolve locations for logged IPs. Off = the IP log still works, locations are blank. |
| `url` | `"https://ipwho.is/{ip}"` | Lookup URL template; `{ip}` is replaced with the address. Any provider returning JSON with `country`/`city`/`country_code` (or `countryCode`) works — e.g. `http://ip-api.com/json/{ip}`. |
| `rate_per_min` | `20` | Cap on outbound lookups per minute (one shared worker), to respect free-tier limits. |
| `cache_size` | `50000` | Max cached IP→location entries (LRU). |
| `cache_ttl` | `"720h"` | How long a cached location is reused before it is refreshed. |

Toggle it with `ayana-cdn geo on [-url URL] [-rate N]` / `ayana-cdn geo off`, or
`ayana-cdn geo show` to see the current settings.

## `panel`

An authenticated web dashboard served over HTTPS on the public `:443` listener
at a **secret path prefix**, so you can watch the edge from a browser without
exposing the loopback admin endpoint. It is matched before any backend route
(no backend can shadow it) and before `strict_host`, and is guarded by a
username and a bcrypt-hashed password. Configure it with `ayana-cdn panel`,
not by hand — the password is never stored in clear text.

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `false` | Serve the panel. When off, the prefix 404s like any unknown path. |
| `path` | required when enabled | The secret URL prefix, e.g. `/__ayana_x8Kq3f…`. Must start with `/` and use only `A–Z a–z 0–9 _ - . ~ /`. Keep it long and random: secrecy of the path is the first layer, auth is the second. Generate one with `ayana-cdn panel path`. |
| `username` | required when enabled | Login name. Compared in constant time. |
| `password_hash` | required when enabled | bcrypt hash of the password (`$2a$`/`$2b$`/`$2y$`). Set it with `ayana-cdn panel passwd`; never put a plaintext password here. |
| `session_key` | random each start | base64 of ≥32 bytes used to sign the session cookie. Empty means a fresh random key at every start, so a restart logs all panel users out. Set one (`panel enable` does) to keep sessions across restarts. **restart** |
| `session_ttl` | `"12h"` | How long a login stays valid before the cookie expires. |
| `allow_control` | `false` | Allow state-changing actions from the panel: reload the config, add/remove **domains** (`cdn_hosts`), add/edit/remove/enable/disable **backends and paths** (including local `127.0.0.1` HTTP services), all persisted to the config file and applied live. Off = a read-only dashboard. Turning it on requires the service user to be able to write the config file — the shipped unit allows this via `ReadWritePaths=/etc/ayana-cdn`; remove that line to forbid it. |
| `allowed_cidrs` | `[]` = any | Optional source-IP allowlist (CIDRs). A request from any other address gets a plain 404, so the panel's existence is not even confirmed. Defense in depth on top of the password. |

The session cookie is `HttpOnly`, `Secure`, `SameSite=Strict` and scoped to the
panel path (so it is never sent to a backend). State-changing actions also
require a CSRF token. Repeated failed logins are locked out per source address
with exponential backoff. Every response carries a strict `Content-Security-Policy`,
`X-Frame-Options: DENY` and `no-store`. Because the panel lives on the TLS
listener it is reachable only over HTTPS.

The dashboard shows **live per-domain traffic** (requests, active connections
and a live up/down rate for each `cdn_host`) and **live per-backend traffic**
(open tunnels, totals and rate), refreshing every few seconds. With
`allow_control` on it also has inline forms to add a domain and to add or edit a
backend/path — pick `proto: http` with upstream `127.0.0.1:PORT` to expose a
local service on this VPS at `/<name>/`. A **Client IPs** section (see `log.ip_log`
and `geo` above) shows, per backend, which client addresses connected, how many
times, and — when geolocation is on — where from.

## `backends[]`

| Key | Default | Meaning |
|---|---|---|
| `name` | required | Path prefix: clients use `/<name>/…`. Letters, digits, `_`, `-`; `healthz` is reserved. Matching is exact on path segments: `/native1` never matches `/native10`. |
| `upstreams` | required | The server: `"upstream": "host:port"` (or a one-entry `upstreams` list). **A path connects to exactly one server**: no load balancing, no failover; if it is down the client gets `502` and retries. For several servers, give each its own path. Only `udp` backends may list several (`["host:port", …]`). A config from an older version with several servers on one path still loads, but only the first is used and a warning names the others (log, `ayana-cdn check`, panel); the panel, `backend add/set` and `routes import` refuse several. |
| `host` | first upstream's hostname | `Host:` header and TLS SNI sent to the backend. |
| `proto` | `"wss"` | What the backend speaks. `wss`/`ws`: tunnel backend (every request is relayed after the upgrade), over TLS or plain. `https`/`http`: HTTP backend, proxied; upgrade requests are still tunnelled. `sse` is `https` with a name that says what it is for (all proxied responses stream). `udp`: a datagram relay on its own port (see `listen`). |
| `listen` | (udp only) | For `proto: "udp"`, the `host:port` this backend receives datagrams on, e.g. `":51820"`. UDP carries no path, so a udp backend owns a port instead of a `/name/` prefix. Required for udp, rejected otherwise. **restart** (bound when the process starts; `ayana-cdn restart` picks up a new one). Use `[::]:port` for a dual-stack socket. |
| `tls` | follows `proto` | Override TLS to the backend. Contradicting `proto` (`wss` with `tls:false`) is rejected: use `ws`. |
| `strip` | `true` | Remove `/<name>` before forwarding. `false` sends the full path. Encoded characters are preserved either way. |
| `insecure` | `false` | Skip verification of the backend's certificate (self-signed backends). Logged as a warning. |
| `disabled` | `false` | Answer `503` instead of proxying; open tunnels are unaffected. `ayana-cdn backend disable NAME`. |
| `lb` | `path` (path backends), `hash` (udp) | `path`: the path's one server, nothing else. The `least_conn`, `round_robin` and `first` of older versions are still accepted in a path backend's config and mean `path`. udp backends choose between their upstreams: `hash` (a client's address always picks the same upstream, so a re-created session or a client's QUIC migration keeps talking to the same stateful server), `least_conn`, `round_robin` or `first`; unhealthy upstreams go last and are still tried if all others fail. |
| `relay` | `"upgrade"` | `upgrade`: relay after any `101`; other responses are forwarded as HTTP and the client connection stays usable. `always`: relay from the first byte, for backends that answer `200` then go raw, or that do not speak HTTP at all. `ws`/`wss` only. |
| `max_conns` | `0` = no cap | Concurrent tunnels for this backend; over it, clients get `503`. |
| `idle_timeout` | global `tunnel_idle` (udp: `udp_idle`) | Per-backend idle timeout for tunnels or UDP sessions. |
| `health_check` | see below | Active check of the path's server: it feeds the up/down state in `status` and the panel and the `upstream_up` metric, and never sends a client anywhere else. For udp backends this must be `off`: datagrams cannot be probed. A udp upstream is marked down by a hard ICMP error or by `udp_reply` elapsing with no answer, and back up by its first reply. |

### `backends[].health_check`

| Key | Default | Meaning |
|---|---|---|
| `type` | `tls` for TLS backends, `tcp` otherwise | `tcp`: connect. `tls`: connect and handshake (`insecure` respected). `http`: `GET path`, healthy unless 5xx. `ws`: upgrade request, expects `101`. `off`: only passive detection (consecutive dial failures mark the upstream down for a while). |
| `path` | `"/"` | For `http` and `ws`. |
| `interval` | `"10s"` | |
| `timeout` | `"3s"` | Must not exceed the interval. |
| `fall` | `3` | Consecutive failures before the upstream is marked down. |
| `rise` | `2` | Consecutive successes before it is marked up again. |
| `expect` | | Exact status to require for `http`/`ws` instead of the defaults above. |

A path's server is tried on each request even while it is marked down
(fail-open), so a health checker that is wrong cannot take a working backend
offline; if the server really is down, the client gets `502` and retries. No
other server is ever tried.

## routes.json

`ayana-cdn routes import FILE [-replace]` turns a routes file in the format of
the Cloud Run `http-proxy` relay into backends with the same behaviour: the
path is forwarded unchanged (`strip: false`) and the Host header is the
target's hostname (`changeOrigin`). Each key is a path prefix (one segment);
each value is one of:

| Value | Result |
|---|---|
| `"http://host[:port]"` | plain `ws` backend, port 80 unless given |
| `"https://host[:port]"` | `wss` backend, port 443 unless given |
| `{"target": "http://a", "host": "name", "insecure": true}` | the same, plus an explicit Host header and no certificate check |

A path has exactly one target. A one-entry list (`["http://a"]`, or
`"targets": [...]` as older `setup.sh` runs wrote it) is still accepted; two
or more different targets on one path are refused: give each server its own
path (`"/s1": "http://a", "/s1-2": "http://b"`).

Without `-replace`, backends whose names are not in the file are kept. The
import is validated before it is saved, and the running edge is reloaded.
`setup.sh` builds such a file from the routes you type in and keeps it at
`/etc/ayana-cdn/routes.json`.

## UDP backends

A `proto: "udp"` backend relays datagrams instead of a byte stream. Because UDP
carries no path, it does not sit under `/<name>/`: it listens on its own
`host:port` (`listen`) and every datagram there is relayed to an upstream.

```json
{ "name": "wg", "proto": "udp", "listen": ":51820", "upstream": "10.0.0.2:51820", "idle_timeout": "3m" }
```

- **Sessions.** A datagram from a new client address+port opens a session: one
  socket connected to the chosen upstream plus a reply path back. Many flows
  from one client are many sessions, so several apps behind one address each
  get their own upstream socket. A session ends when it is idle (`udp_idle`),
  when its upstream is unreachable (ICMP) or silent (`udp_reply`), on shutdown,
  or on a restart (see below).
- **Dead upstreams.** A closed port (ICMP unreachable) ends a session at once.
  A black-holed upstream — powered off, firewalled `DROP`, wrong port on a host
  that filters ICMP — is caught by `udp_reply`: if the client keeps sending and
  nothing comes back within it, the session is closed and the upstream is
  rotated. The upstream is marked down only when it has answered no session at
  all, so one client with a bad key cannot take it down for everyone.
- **Load balancing.** `lb` defaults to `hash` for udp: a client's address
  always maps to the same upstream, so a re-created session or a client's QUIC
  migration keeps talking to the same stateful server. Use `least_conn`/
  `round_robin`/`first` only for stateless request-reply upstreams (DNS).
- **Listen address.** `:port` binds IPv4; `[::]:port` binds dual-stack. On a
  host with more than one address (a floating or secondary IP), bind `listen`
  to the specific address clients reach, so replies leave from it.
- **Applying changes.** Adding, moving or removing a udp backend takes effect
  on `ayana-cdn reload`, like a tunnel backend; the socket is bound or closed
  then. `ayana-cdn restart` re-creates every session in the new process (the
  upstream sees a new source port), which is invisible to roaming protocols
  such as WireGuard and to QUIC, but forces a reconnect for upstreams that key
  state strictly by source address.
- **Health checks** must be `off` for udp (datagrams cannot be probed);
  `ayana-cdn check` resolves each udp upstream and reports the listen address
  but does not send traffic.

`config/examples/udp.json` is a complete example (WireGuard, a DNS pool, and a
tunnel side by side).

## Examples

`config/examples/` has complete files for: one server per path
(`per-path.json`), raw SSH/stunnel backends (`raw-tunnels.json`), plain HTTP
apps next to the tunnels (`http-backends.json`), certificate files instead of
ACME (`files-tls.json`), and running behind the nginx front door
(`frontdoor.json`).

Minimal v2 file:

```json
{
  "cdn_hosts": ["cdn.example.com"],
  "tls": { "mode": "acme", "email": "admin@example.com" },
  "backends": [
    { "name": "native1", "upstream": "native1.example.com:443" }
  ]
}
```
