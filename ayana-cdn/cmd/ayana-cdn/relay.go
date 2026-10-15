package main

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Adaptive buffering. Every tunnel starts on a 4 KiB buffer per direction and
// borrows a pooled 32 KiB buffer only while data arrives in bursts, returning
// it as soon as traffic turns interactive again. Idle tunnels — most of them,
// most of the time — therefore hold 8 KiB of copy buffers instead of the
// 64 KiB that two io.Copy loops keep pinned for the life of a connection.
const (
	smallBufSize = 4 << 10
	bigBufSize   = 32 << 10
)

var (
	smallBufs = sync.Pool{New: func() any { b := make([]byte, smallBufSize); return &b }}
	bigBufs   = sync.Pool{New: func() any { b := make([]byte, bigBufSize); return &b }}
)

type tunnel struct {
	backend  string
	upstream string
	client   string
	start    time.Time
	status   int // 101, or sniffed from the backend in relay "always" mode
	cconn    net.Conn
	sconn    net.Conn
	idle     time.Duration // 0 = no idle timeout
	stall    time.Duration // 0 = no write-stall guard
	linger   time.Duration // half-close: how long the surviving direction may stay idle after one side closes

	last      atomic.Int64 // unix nanos of last traffic; maintained only when idle > 0
	sniffed   atomic.Int32
	firstEnd  atomic.Int32 // 1: client->backend finished first, 2: backend->client first
	lingering atomic.Bool  // one side has half-closed; the surviving pipe now bounds its reads by linger as an idle window
	closeOnce sync.Once
	forced    atomic.Pointer[string]
}

// closeWith closes both sides. The first caller's reason wins; the relay
// itself closes with "" once both directions are done.
func (t *tunnel) closeWith(reason string) {
	t.closeOnce.Do(func() {
		t.forced.Store(&reason)
		_ = t.cconn.Close()
		_ = t.sconn.Close()
	})
}

type dirResult struct {
	n        int64
	readErr  error
	writeErr error
}

// relay copies both directions until both are finished and returns the close
// reason and byte counts (client->backend, backend->client). The backend->client
// direction runs on the calling goroutine, so a tunnel costs one extra
// goroutine instead of the two a plain io.Copy pair would need.
func (t *tunnel) relay(halfClose time.Duration, upCtr, downCtr *atomic.Uint64, sniff bool) (string, int64, int64) {
	t.linger = halfClose
	var stopIdle func()
	if t.idle > 0 {
		t.last.Store(time.Now().UnixNano())
		stopIdle = t.watchIdle()
	}
	upCh := make(chan dirResult, 1)
	go func() {
		r := t.pipe(t.sconn, t.cconn, upCtr, false)
		t.endDir(1, t.sconn, halfClose)
		upCh <- r
	}()
	down := t.pipe(t.cconn, t.sconn, downCtr, sniff)
	t.endDir(2, t.cconn, halfClose)
	up := <-upCh
	if stopIdle != nil {
		stopIdle()
	}
	t.closeWith("")
	if code := t.sniffed.Load(); code != 0 {
		t.status = int(code)
	}
	return t.reason(up, down), up.n, down.n
}

// endDir runs when one direction finishes. The first to finish propagates the
// half-close (TLS close_notify / TCP FIN) to its destination and arms the
// linger window on the surviving direction.
//
// The surviving direction reads from the same conn this one wrote to (dst):
// client->backend writes the backend conn, which backend->client reads, and
// vice versa. We set that read a linger deadline and flip t.lingering so the
// surviving pipe refreshes the deadline on every read. linger is therefore an
// IDLE bound, not a hard cap: an actively progressing transfer is never cut
// (the old code set one absolute deadline on both conns, which truncated any
// transfer still running linger after the first half-close), while a genuinely
// silent half-open connection is still reaped after linger.
func (t *tunnel) endDir(dir int32, dst net.Conn, linger time.Duration) {
	if !t.firstEnd.CompareAndSwap(0, dir) {
		return
	}
	if cw, ok := dst.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
	t.lingering.Store(true)
	_ = dst.SetReadDeadline(time.Now().Add(linger))
}

func (t *tunnel) pipe(dst, src net.Conn, ctr *atomic.Uint64, sniff bool) (r dirResult) {
	sp := smallBufs.Get().(*[]byte)
	defer smallBufs.Put(sp)
	small := *sp
	var bp *[]byte
	defer func() {
		if bp != nil {
			bigBufs.Put(bp)
		}
	}()
	buf := small
	for {
		// Once the peer half-closed, this surviving direction is bounded by an
		// IDLE window: the deadline is armed right before the read, so only
		// time spent waiting for data counts — a slow write to the far side
		// (bounded separately by write_stall) never eats into it, and a
		// transfer that keeps delivering, however slowly, is never truncated.
		if t.linger > 0 && t.lingering.Load() {
			_ = src.SetReadDeadline(time.Now().Add(t.linger))
		}
		n, rerr := src.Read(buf)
		if n > 0 {
			if t.idle > 0 {
				t.last.Store(time.Now().UnixNano())
			}
			if sniff && r.n == 0 {
				if code := sniffStatus(buf[:n]); code != 0 {
					t.sniffed.Store(int32(code))
				}
			}
			if t.stall > 0 {
				_ = dst.SetWriteDeadline(time.Now().Add(t.stall))
			}
			wn, werr := dst.Write(buf[:n])
			r.n += int64(wn)
			ctr.Add(uint64(wn))
			if werr != nil {
				r.writeErr = werr
				return r
			}
			if bp == nil && n == len(small) {
				bp = bigBufs.Get().(*[]byte)
				buf = *bp
			} else if bp != nil && n < len(small) {
				bigBufs.Put(bp)
				bp, buf = nil, small
			}
		}
		if rerr != nil {
			if !errors.Is(rerr, io.EOF) {
				r.readErr = rerr
			}
			return r
		}
	}
}

func (t *tunnel) watchIdle() (stop func()) {
	var (
		mu      sync.Mutex
		stopped bool
		timer   *time.Timer
	)
	check := func() {
		mu.Lock()
		defer mu.Unlock()
		if stopped {
			return
		}
		idleFor := time.Since(time.Unix(0, t.last.Load()))
		if idleFor >= t.idle {
			t.closeWith("idle_timeout")
			return
		}
		timer.Reset(t.idle - idleFor)
	}
	mu.Lock()
	timer = time.AfterFunc(t.idle, check)
	mu.Unlock()
	return func() {
		mu.Lock()
		stopped = true
		timer.Stop()
		mu.Unlock()
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func (t *tunnel) reason(up, down dirResult) string {
	if p := t.forced.Load(); p != nil && *p != "" {
		return *p
	}
	classify := func(side string, err error) string {
		if errors.Is(err, syscall.ETIMEDOUT) {
			return side + "_dead" // the kernel gave up: keepalive probes or unacked data timed out
		}
		if isTimeout(err) {
			return side + "_stalled"
		}
		return side + "_error: " + errString(err)
	}
	switch t.firstEnd.Load() {
	case 1:
		switch {
		case up.readErr != nil:
			return classify("client", up.readErr)
		case up.writeErr != nil:
			return classify("backend", up.writeErr)
		}
		return "client_closed"
	case 2:
		switch {
		case down.readErr != nil:
			return classify("backend", down.readErr)
		case down.writeErr != nil:
			return classify("client", down.writeErr)
		}
		return "backend_closed"
	}
	return "closed"
}

// ---- registry ------------------------------------------------------------------

// tunnelRegistry tracks live tunnels. net/http's Shutdown does not know about
// hijacked connections, so draining and shutdown go through this instead.
type tunnelRegistry struct {
	mu      sync.Mutex
	m       map[*tunnel]struct{}
	closing string // set by shutdown: tunnels registering afterwards are closed at once
}

func newTunnelRegistry() *tunnelRegistry { return &tunnelRegistry{m: map[*tunnel]struct{}{}} }

func (r *tunnelRegistry) add(t *tunnel) {
	r.mu.Lock()
	r.m[t] = struct{}{}
	reason := r.closing
	r.mu.Unlock()
	if reason != "" {
		t.closeWith(reason)
	}
}

// shutdown closes every tunnel and any that finish setting up afterwards.
func (r *tunnelRegistry) shutdown(reason string) int {
	r.mu.Lock()
	r.closing = reason
	r.mu.Unlock()
	return r.closeAll(reason)
}

func (r *tunnelRegistry) remove(t *tunnel) {
	r.mu.Lock()
	delete(r.m, t)
	r.mu.Unlock()
}

func (r *tunnelRegistry) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.m)
}

func (r *tunnelRegistry) closeAll(reason string) int {
	r.mu.Lock()
	list := make([]*tunnel, 0, len(r.m))
	for t := range r.m {
		list = append(list, t)
	}
	r.mu.Unlock()
	for _, t := range list {
		t.closeWith(reason)
	}
	return len(list)
}

// waitEmpty blocks until no tunnels remain or ctx ends; it reports whether
// the registry emptied.
func (r *tunnelRegistry) waitEmpty(ctx context.Context) bool {
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for r.count() > 0 {
		select {
		case <-ctx.Done():
			return r.count() == 0
		case <-tick.C:
		}
	}
	return true
}
