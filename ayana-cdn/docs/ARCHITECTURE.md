# Architecture

ayana-cdn is a single Go process. This document explains how a connection
moves through it, how configuration changes and restarts work, what was wrong
in v1, and the standard-library behaviours that shaped the design. Source
files are named where they matter.

## Process model

`serve` builds a `Server` (`server.go`) from the config, binds the public,
admin and optional redirect listeners, and runs one `net/http` server on each.
Everything derived from the config lives in an immutable `state` snapshot
(routes, hosts, TLS config, limits); handlers load the current snapshot once
per request, so a reload never changes the rules under a request in flight.

Signals: `HUP` → `Reload`, `USR2` → `Handoff`, `TERM`/`INT` → graceful stop.

Dead-peer detection (`keepalive.go`) applies to every client and upstream TCP
socket: keepalive probes start after `client_keepalive` of silence and
`TCP_USER_TIMEOUT` is set to `client_keepalive + dead_peer`, so a peer that
vanishes without a FIN, or data left unacknowledged that long, ends the
connection in about a minute with the defaults instead of Linux's multi-minute
retransmission limit. A connection cut this way logs `client_dead`/
`backend_dead`; `write_stall` still governs a peer that is alive but has
stopped reading.
Under systemd the unit is `Type=notify`: the process sends `READY=1` when the
listeners serve, `MAINPID=` during a handoff, `STOPPING=1` on stop.

## The data path of a tunnel

`listener.go` wraps the accepted TCP connection. On first use it applies the
global connection cap, reads a PROXY protocol header if the source is trusted
(`proxyproto.go`), and applies the per-IP token bucket and concurrency limit
(`limiter.go`). Rejections are counted by reason and cost no TLS work.

TLS (`tlsconf.go`) uses `GetConfigForClient` so the current snapshot's TLS
config (min version, ALPN) applies per handshake. The certificate source is
fixed when the process starts: ACME (`autocert`, cached under
`/var/lib/ayana-cdn/acme`) or files. Unknown or missing SNI gets the primary
host's certificate unless `strict_sni` is set, because tunnel clients often
send a bug host as SNI.

Routing (`routes.go`) matches the longest backend name that is a whole path
segment, so `/native1` never captures `/native10`. Encoded characters in the
path survive the prefix strip (`backendRequestURI`).

For `ws`/`wss` backends every request is a tunnel (`tunnel.go`):

1. The client connection is hijacked from `net/http` together with its
   buffered reader. **Any bytes the client sent after the request head are in
   that buffer**; they are forwarded to the backend right after the request.
2. The request head is rewritten (backend `Host`, forwarding headers, stripped
   path) and written to a connection to the path's one server (`upstream.go`).
3. The backend's response head is read raw (`httphead.go`). Any status `101`
   switches to relay mode, whatever headers it carries. Bytes that arrived
   together with the head (a banner) are forwarded after it. A non-`101`
   response is forwarded as a normal HTTP response and the client connection
   stays usable. If the first bytes are not `HTTP/`, the client gets a `502`
   that says to use `relay: always`.
4. `relay.go` copies in both directions with pooled buffers that start at
   4 KiB and switch to 32 KiB while a direction is moving bulk data, then
   fall back. It propagates half-close (a `CloseWrite` on one side becomes a
   TLS close-notify or TCP FIN on the other), enforces the write-stall and
   idle timeouts, counts bytes per direction, and records why the tunnel
   ended. Tunnels are registered in a registry so reloads, stops and drains
   can reason about them; `net/http` does not track hijacked connections.

`relay: always` skips step 3 and relays from the first byte. HTTP backends go
through `httpproxy.go`, a `ReverseProxy` that dials the same server,
flushes every chunk (so SSE works) and records the status class; upgrade
requests to an HTTP backend still take the tunnel path.

Routing is by path, and a path connects to exactly one server: its pool holds
that server only, and a dial goes there or fails with a `502` (no load
balancing, no failover to another server). The pool tracks active connections
and dial results and marks the server down after consecutive dial failures;
`health.go` runs the active checks. Health only feeds `status`, the panel and
the metrics: the server is dialed even while marked down, so service resumes
the moment it is back. Only a udp pool holds several upstreams and chooses
between them. A pool survives reloads: an unchanged server keeps its state.

## The data path of a UDP session

A `proto: "udp"` backend (`udp.go`) binds its own socket (`listen`) instead of
a path. One goroutine reads the socket; the read loop never blocks, so it does
no name resolution (udp upstreams are resolved to `net.UDPAddr` when the pool
is built, and again on reload) and its send to the upstream is a non-blocking
raw write that drops on a full buffer rather than parking every session.

A datagram from a new client address+port opens a *session*: a socket
connected to the chosen upstream (`lb: hash` by default, so a client's address
always maps to the same upstream), plus one goroutine reading replies and
writing them back to the client. The session is keyed by the client's unmapped
`AddrPort`, so an IPv4 client on a dual-stack socket shares the per-IP budget
correctly rather than collapsing into one IPv6 /64.

Liveness is reply-based, because a datagram flow has no close and Linux only
delivers *hard* ICMP errors asynchronously on a connected UDP socket: a
port-unreachable ends the session at once, but a powered-off host or a `DROP`
rule produces nothing. A sweeper closes a session that has sent to its upstream
and heard nothing back within `udp_reply`, and rotates the upstream only when
it has answered no session at all in that window. `IP_PMTUDISC_DONT` is set so
an ICMP "fragmentation needed" does not turn into a one-shot `EMSGSIZE` that
would kill a tunnel; only a hard unreachable ends a session, while `EMSGSIZE`,
`EAGAIN` and the like lose a single datagram. A per-IP session cap and a FIFO
of never-replied sessions (evicted oldest-first) keep a spoofed-source flood
from filling the table.

## Reload

`Reload` loads and validates the whole file, then builds a new snapshot,
reusing upstream state for unchanged backends, and swaps it atomically. Old
health checkers are stopped. Open tunnels hold references to their own
connections and are unaffected. An invalid file is rejected in full and
counted; settings that are bound at startup produce a warning naming them.
UDP listeners are reconciled on reload: a socket whose `(name, listen)` pair
is unchanged keeps serving its sessions, an added or moved one is bound, and a
removed one is closed (its sessions end with reason `backend_removed`). The
listeners slice is guarded so this cannot race a concurrent handoff.

`ayana-cdn backend …` edits the raw file under a lock, validates the result,
writes it atomically with a `.bak`, and sends `HUP`.

## Zero-downtime restart (`handoff.go`)

1. The old process starts the binary on disk (`os.Executable()`, so an
   upgraded file is picked up) with the listening sockets as inherited file
   descriptors and a pipe for readiness. Nothing changes for clients: the
   kernel keeps queueing connections on the same sockets.
2. The new process adopts a socket if its configured address is unchanged,
   binds a new one otherwise, starts serving, and writes `ready` to the pipe.
   If it fails before that (bad config, crash), the old process logs the
   reason, restores its pid file and keeps serving.
3. The old process sends `MAINPID=` to systemd, closes its listeners, disables
   keep-alives so idle connections close and busy ones close after their
   response, and waits until every client connection it still holds is gone,
   up to `timeouts.drain`. Tunnels still being set up are counted too, because
   the wait is on the listener's own connection counter, not on `net/http`.

UDP sockets are inherited the same way (adopted with `net.FilePacketConn` on
the duplicated descriptor). The old process pauses its UDP read loops the
moment the child starts, so datagrams queue in the kernel until the new process
reads them, and closes its UDP sessions once the handover succeeds; each
client's next datagram opens a fresh session in the new process. Datagrams are
not lost across the switch, but a session's upstream sees a new source port.

Two standard-library behaviours forced the exact shape of step 3; both were
found by the end-to-end restart test (`restart_test.go`), which runs real
processes and signals with clients connecting continuously:

- `http.Server.Shutdown` must not be used for a drain. Once it has begun,
  `net/http` reads the first request of any connection it has not served yet
  and then closes the connection without answering. Under load, one to three
  of every 2,000 connections accepted in the last milliseconds before the
  handover were cut this way. Closing the listener directly and disabling
  keep-alives finishes those requests instead.
- Sockets must not be passed with `TCPListener.File()`. `os/exec` obtains the
  descriptor with `File.Fd()`, which switches a socket obtained that way into
  blocking mode, and `O_NONBLOCK` lives on the open file description shared by
  both processes. The old process's accept loop then blocks inside the kernel
  and its listener `Close` waits for that call, which stalled connections for
  the 5 seconds `net/http` allows a connection without a request. The edge
  duplicates the descriptor with `fcntl(F_DUPFD_CLOEXEC)` through
  `SyscallConn`, which leaves the flag alone.

A stop (`TERM`) is different from a drain: tunnels are closed immediately
(there is no point waiting for them) and in-flight HTTP requests get
`timeouts.shutdown_grace`.

## Why v1 lost data

v1 proxied tunnels with `net/http/httputil.ReverseProxy`. Its upgrade path
hijacks the client connection and then copies between the raw connections,
ignoring the bytes `net/http` had already read into its buffered reader.
Whether those bytes existed depended on timing: a client that sent its SSH
banner in the same TLS record as the request lost all of it; one that sent it
a moment later usually lost the first byte, because `net/http` starts a
one-byte background read on idle connections. It also required the backend's
`101` to carry an `Upgrade:` header matching the request, which the Python
tunnel proxies common in this setup do not send, so those backends got a
`502`. v2 does not use `ReverseProxy` for tunnels at all (see the data path
above), and the three regressions are pinned by `TestEarlyDataSameTLSRecord`,
`TestEarlyDataSeparateWrite` and `TestPythonStyle101WithoutUpgradeHeader`.

Other v1 problems fixed in passing: PROXY protocol headers were parsed inside
`Accept`, so one slow or malicious peer stalled all accepts (now parsed lazily
per connection); clients that sent no SNI or a bug-host SNI were refused by
the ACME certificate lookup (now they get the primary host's certificate);
a stop did not shut down gracefully; the CLI's own documented
`backend add … --host` form was rejected by Go's flag parsing
(`parseInterspersed` fixes that); the memory limit was hard-coded instead of
derived from the machine; the installer pinned an end-of-life Go release,
replaced `/usr/local/go`, and shipped a two-year-old `x/crypto`.

## What is deliberately not here

- No `splice(2)`: TLS terminates in user space, so every byte is decrypted
  and re-sent anyway; the adaptive buffers keep the copy cheap and memory low.
- No HTTP/2 by default: WebSocket upgrades over HTTP/1.1 are what the clients
  speak, and a client negotiating h2 could not tunnel.
- No built-in caching or static file serving: put a real HTTP server behind an
  `http` backend.
- No prebuilt binaries: the installer fetches the current Go release with its
  published checksum and builds from this source, with the one dependency
  verified against the Go checksum database.

## Tests

`go test ./cmd/ayana-cdn` runs 120 tests in about five seconds. Unit tests
cover config loading and validation (including v1's shipped config, verbatim
in `testdata/`), routing, URI rewriting, the limiter, PROXY protocol v1/v2,
head parsing, one server per path, udp upstream ordering, and the CLI.
Integration tests start a full edge in-process with a generated certificate
and real TCP backends, and drive it with raw client bytes: early data,
Python-style `101`, banners, relay modes, forwarded headers, path pinning,
capacity, SNI fallback, half-close, idle timeout, reload, stop, a 19 MB
integrity run through the adaptive relay, HTTP proxying with streaming, PROXY
protocol, per-IP limits and metrics. `TestZeroDowntimeRestart` re-executes the
test binary as the edge, becomes a child subreaper like systemd, fakes the
notify socket, and checks a failed restart, a successful one, the surviving
tunnel, the old process's exit and the new one's stop while four clients
connect continuously. The whole suite passes repeatedly under `-race`.
