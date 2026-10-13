# Performance

ayana-cdn is a TLS edge that terminates client TLS and relays raw bytes to
backends. Its throughput ceiling in practice is the network and TLS, not the
process: the relay copy loop sustains **~1.4 GB/s per core** on loopback
(`go test -bench BenchmarkPipeThroughput`), which is far above any real link.

This note records the design choices that keep it fast, and how they compare to
sing-box / Hiddify (a common point of reference for "fast proxy").

## What makes it fast

**Kernel network tuning (`deploy/sysctl-99-ayana-cdn.conf`).** This is the same
class of tuning a well-configured Hiddify server uses, applied automatically by
the installer:

- `net.ipv4.tcp_congestion_control = bbr` + `net.core.default_qdisc = fq` — BBR
  is the mainstream high-throughput congestion control; `fq` pairs with it for
  pacing.
- 32 MiB socket buffer ceilings (`rmem_max`/`wmem_max`) and auto-tuned
  `tcp_rmem`/`tcp_wmem`, so a single high-bandwidth-delay-product flow can fill
  the pipe.
- `tcp_slow_start_after_idle = 0` (don't re-enter slow start on an idle tunnel),
  `tcp_mtu_probing = 1`, `tcp_notsent_lowat`, larger SYN backlog, `tcp_tw_reuse`.

**Relay copy loop (`relay.go`).**

- **Pooled, adaptive buffers.** Each direction starts on a 4 KiB buffer and
  borrows a pooled 32 KiB buffer only while data arrives in bursts, returning it
  when traffic turns interactive. Idle tunnels hold 8 KiB instead of the 64 KiB
  two `io.Copy` loops would pin for the life of a connection — so a box can hold
  far more concurrent tunnels in the same memory.
- **One goroutine per tunnel, not two.** The backend→client direction runs on
  the calling goroutine; only the client→backend direction gets its own. Half
  the goroutines and stacks of a naive `io.Copy` pair.
- **32 KiB is the measured sweet spot.** Larger copy buffers *reduce* throughput
  here (≈1,450 MB/s at 32 KiB vs ≈1,080 MB/s at 64 KiB vs ≈840 MB/s at 128 KiB
  on the bench), because the working set stops fitting the CPU cache and the
  socket windows are already large. sing-box grows its buffer after 512 KB of
  sustained transfer; for this edge that change is a regression, so we don't.
- **Precise liveness without extra cost:** per-read idle/linger deadlines and a
  write-stall guard, armed only when configured, so dead peers are reaped
  without a timer per tunnel.

**TCP keepalive (`keepalive.go`)** detects dead peers quickly; `TCP_NODELAY` is
on by default (Go), so interactive tunnels (e.g. SSH-over-WebSocket) are not
delayed by Nagle.

## How this compares to sing-box / Hiddify

sing-box is a proxy *platform* (many protocols, multiplexing, a client and a
server side). The parts that make it fast and that **also apply to a TLS edge**
are already present here: pooled buffers + byte counting, BBR, big socket
buffers, keepalive, `TCP_NODELAY`. The parts that **don't** apply:

- **`splice()` / zero-copy.** sing-box can move bytes kernel-to-kernel for a
  *direct* (unprocessed) connection. ayana-cdn terminates the client's TLS (the
  bytes are decrypted in userspace — there is nothing to splice) and counts
  every byte to drive the panel's live-traffic graphs, so a userspace copy is
  required by design. The copy loop is cheap enough (~1.4 GB/s/core) that this
  is not a throughput limit.
- **Multiplexing (mux/h2mux/smux).** A protocol feature between a sing-box
  client and server. ayana-cdn is a path-routing edge, not an endpoint of such a
  protocol, so there is no session to multiplex.
- **TCP Brutal.** An aggressive congestion control that sends at a fixed,
  *negotiated* rate regardless of loss — great on very lossy links, but it needs
  a kernel module (`tcp_brutal`) **and** a per-connection target rate carried by
  sing-box's own protocol. Without that rate it misbehaves, so it is not a clean
  drop-in for a generic edge. BBR (already enabled) is the right default here.
  An operator who still wants Brutal can install the module and set it globally
  with `sysctl net.ipv4.tcp_congestion_control=brutal`, accepting its caveats.

## Measuring

- **Copy-loop throughput (this repo):** `go test -bench BenchmarkPipeThroughput ./cmd/ayana-cdn/`
- **End-to-end on your server:** the built-in load tool measures TCP/TLS/upgrade
  handshake latency, round-trip times, and bulk throughput against a running
  edge: `ayana-cdn bench -help`. Run it from a client box against your edge for
  numbers that include the real network and TLS.
- **Live throughput:** the web panel's graphs show per-domain and per-backend
  Mbps in real time.
