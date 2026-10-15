package main

import (
	"net"
	"syscall"
	"time"
)

// tcpUserTimeout is Linux's TCP_USER_TIMEOUT socket option (milliseconds).
// Package syscall does not define it.
const tcpUserTimeout = 18

// keepAlive is how a TCP connection finds out that its peer is gone without
// either side sending anything: a phone that lost its signal, a NAT that
// dropped the mapping, a backend host that was powered off. TCP alone never
// notices an idle dead peer, and Linux's default probing (9 probes 75 s
// apart after 2 h idle) takes about 11 minutes even with a shorter idle
// time. Both sides of every tunnel get the same settings.
type keepAlive struct {
	idle        time.Duration // silence before the first probe; 0 = probing off
	interval    time.Duration // between probes; 0 = kernel default
	count       int           // unanswered probes before the connection is dropped; 0 = kernel default
	userTimeout time.Duration // TCP_USER_TIMEOUT; 0 = kernel default
}

// newKeepAlive derives the probing schedule from the timeouts: the peer is
// probed after client_keepalive of silence and dropped once it has stayed
// silent for dead_peer more, and data that stays unacknowledged for
// client_keepalive+dead_peer ends the connection too, instead of Linux's
// 15-minute retransmission timeout.
func newKeepAlive(t *Timeouts) keepAlive {
	ka := keepAlive{idle: t.ClientKeepAlive.D()}
	if ka.idle <= 0 {
		return keepAlive{}
	}
	dead := t.DeadPeer.D()
	if dead <= 0 {
		return ka // probing on, kernel default schedule (Go: 15s interval, 9 probes)
	}
	ka.count = 3
	ka.interval = max(dead/time.Duration(ka.count), time.Second)
	// A non-zero TCP_USER_TIMEOUT overrides the keepalive probe count in the
	// kernel, so it must equal the dead-peer budget: raising it to write_stall
	// would silently make dead-peer detection take that much longer. It also
	// bounds a peer that keeps ACKing zero-window probes (a stalled reader),
	// so with the defaults a non-reading peer is dropped at client_keepalive+
	// dead_peer (60s), earlier than write_stall (2m) would; that is intended.
	ka.userTimeout = ka.idle + dead
	return ka
}

// deadAfter is how long a silent peer survives: idle time plus the probes.
func (ka keepAlive) deadAfter() time.Duration {
	// Only report a figure when we set the probe schedule ourselves (dead_peer
	// > 0). With dead_peer 0 the kernel's own schedule applies, which we do not
	// read, so reporting a made-up number would mislead.
	if ka.idle <= 0 || ka.count == 0 {
		return 0
	}
	return ka.idle + ka.interval*time.Duration(ka.count)
}

// apply configures the connection. Errors are ignored on purpose: a kernel
// that refuses an option leaves the connection with its defaults, which is
// still a working tunnel.
func (ka keepAlive) apply(c net.Conn) {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return
	}
	if ka.idle <= 0 {
		_ = tc.SetKeepAlive(false) // the only way to turn it off on an inherited socket
		return
	}
	cfg := net.KeepAliveConfig{Enable: true, Idle: ka.idle, Interval: -1, Count: -1} // -1: keep the kernel default
	if ka.count > 0 {
		cfg.Interval, cfg.Count = ka.interval, ka.count
	}
	_ = tc.SetKeepAliveConfig(cfg)
	if ka.userTimeout > 0 {
		if rc, err := tc.SyscallConn(); err == nil {
			_ = rc.Control(func(fd uintptr) {
				_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, tcpUserTimeout, int(ka.userTimeout/time.Millisecond))
			})
		}
	}
}
