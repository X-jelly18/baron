package main

import (
	"net"
	"syscall"
	"testing"
	"time"
)

func sockoptInt(t *testing.T, c *net.TCPConn, opt int) int {
	t.Helper()
	rc, err := c.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var v int
	var gerr error
	if err := rc.Control(func(fd uintptr) { v, gerr = syscall.GetsockoptInt(int(fd), syscall.IPPROTO_TCP, opt) }); err != nil {
		t.Fatal(err)
	}
	if gerr != nil {
		t.Fatal(gerr)
	}
	return v
}

func TestKeepAliveSchedule(t *testing.T) {
	t.Parallel()
	ka := newKeepAlive(&Timeouts{ClientKeepAlive: Duration(30 * time.Second), DeadPeer: Duration(30 * time.Second)})
	if ka.idle != 30*time.Second || ka.interval != 10*time.Second || ka.count != 3 || ka.userTimeout != 60*time.Second {
		t.Fatalf("schedule: %+v", ka)
	}
	if ka.deadAfter() != 60*time.Second {
		t.Fatalf("deadAfter %s", ka.deadAfter())
	}
	// dead_peer off: probing on with Go's default schedule (15s x 9), no user timeout.
	ka = newKeepAlive(&Timeouts{ClientKeepAlive: Duration(30 * time.Second)})
	if ka.idle != 30*time.Second || ka.count != 0 || ka.userTimeout != 0 {
		t.Fatalf("kernel-default schedule: %+v", ka)
	}
	// With dead_peer off the kernel's own probe schedule applies, which we do
	// not read, so deadAfter reports 0 (unknown) rather than a made-up number.
	if ka.deadAfter() != 0 {
		t.Fatalf("kernel-default deadAfter should be 0 (unknown), got %s", ka.deadAfter())
	}
	// user timeout equals the dead-peer budget (a non-zero TCP_USER_TIMEOUT
	// overrides the kernel probe count, so it must not be lengthened to
	// write_stall or detection would silently take that long).
	ka = newKeepAlive(&Timeouts{ClientKeepAlive: Duration(30 * time.Second), DeadPeer: Duration(15 * time.Second), WriteStall: Duration(2 * time.Minute)})
	if ka.userTimeout != 45*time.Second {
		t.Fatalf("userTimeout should be idle+dead=45s, got %s", ka.userTimeout)
	}
	// keepalive off entirely.
	if ka := newKeepAlive(&Timeouts{DeadPeer: Duration(time.Second)}); ka != (keepAlive{}) {
		t.Fatalf("off: %+v", ka)
	}
	// a very short dead_peer never probes faster than once a second
	if ka := newKeepAlive(&Timeouts{ClientKeepAlive: Duration(time.Second), DeadPeer: Duration(time.Second)}); ka.interval != time.Second {
		t.Fatalf("interval floor: %+v", ka)
	}
}

func TestKeepAliveAppliedToSockets(t *testing.T) {
	t.Parallel()
	ln := listenLocal(t)
	go func() {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err == nil {
			time.Sleep(time.Second)
			c.Close()
		}
	}()
	c, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ka := newKeepAlive(&Timeouts{ClientKeepAlive: Duration(20 * time.Second), DeadPeer: Duration(15 * time.Second)})
	ka.apply(c)
	tc := c.(*net.TCPConn)
	if got := sockoptInt(t, tc, syscall.TCP_KEEPIDLE); got != 20 {
		t.Errorf("TCP_KEEPIDLE %d", got)
	}
	if got := sockoptInt(t, tc, syscall.TCP_KEEPINTVL); got != 5 {
		t.Errorf("TCP_KEEPINTVL %d", got)
	}
	if got := sockoptInt(t, tc, syscall.TCP_KEEPCNT); got != 3 {
		t.Errorf("TCP_KEEPCNT %d", got)
	}
	if got := sockoptInt(t, tc, tcpUserTimeout); got != 35000 {
		t.Errorf("TCP_USER_TIMEOUT %d ms", got)
	}
	rc, _ := tc.SyscallConn()
	var on int
	_ = rc.Control(func(fd uintptr) { on, _ = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_KEEPALIVE) })
	if on != 1 {
		t.Errorf("SO_KEEPALIVE %d", on)
	}
}
