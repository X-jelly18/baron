package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Zero-downtime restart (SIGUSR2, `ayana-cdn restart`):
//
//  1. The running process starts a new copy of the binary on disk, passing its
//     listening sockets as inherited file descriptors. The kernel keeps
//     queueing new connections on them the whole time: nothing is refused.
//  2. The new process loads the config, starts serving on the inherited
//     sockets and writes "ready" to a pipe.
//  3. The old process tells systemd the new main PID, stops accepting, and
//     drains: every connection it already has (in-flight requests, tunnels)
//     is served to completion, bounded by timeouts.drain.
//
// If the new process fails at any point before step 3 (bad config, crash),
// the old one simply keeps serving and logs why.
//
// Two details matter for not losing a single connection (both found by the
// restart test under load):
//   - The sockets are duplicated with fcntl(F_DUPFD_CLOEXEC), never with
//     TCPListener.File(): exec calls File.Fd(), which switches such a file to
//     blocking mode, and O_NONBLOCK is shared by every process holding the
//     socket. accept() would then block inside the kernel, and Close would
//     wait for it.
//   - The drain does not use http.Server.Shutdown: once Shutdown has begun,
//     net/http reads the first request of a connection it has not served yet
//     and drops it, which cuts connections accepted just before the handoff.

const (
	envInherit          = "AYANA_CDN_INHERIT"
	envReadyFD          = "AYANA_CDN_READY_FD"
	handoffReadyTimeout = 60 * time.Second
)

// listenSocket is what TCP listeners and UDP sockets have in common for a
// handoff: both can be duplicated through SyscallConn and closed.
type listenSocket interface {
	SyscallConn() (syscall.RawConn, error)
	Close() error
}

type namedListener struct {
	name  string
	addr  string // the configured address the socket was bound for
	bound net.Addr
	ln    listenSocket
}

type inheritSpec struct {
	fd   int
	addr string
}

// parseInherit reads "public=3@:443,admin=4@127.0.0.1:9180".
func parseInherit(v string) (map[string]inheritSpec, error) {
	out := map[string]inheritSpec{}
	if v == "" {
		return out, nil
	}
	for _, item := range strings.Split(v, ",") {
		name, rest, ok1 := strings.Cut(item, "=")
		fdStr, addr, ok2 := strings.Cut(rest, "@")
		fd, err := strconv.Atoi(fdStr)
		if !ok1 || !ok2 || err != nil || fd < 3 {
			return nil, fmt.Errorf("malformed %s entry %q", envInherit, item)
		}
		out[name] = inheritSpec{fd: fd, addr: addr}
	}
	return out, nil
}

func closeInherited(inh map[string]inheritSpec) {
	for name, spec := range inh {
		_ = os.NewFile(uintptr(spec.fd), name).Close()
		delete(inh, name)
	}
}

// listenTCP binds addr, or adopts the inherited socket for this listener if
// the configured address is unchanged.
func (s *Server) listenTCP(name, addr string, inh map[string]inheritSpec) (*net.TCPListener, error) {
	if spec, ok := inh[name]; ok {
		delete(inh, name)
		f := os.NewFile(uintptr(spec.fd), name+"-listener")
		if spec.addr == addr {
			ln, err := net.FileListener(f)
			f.Close()
			if err != nil {
				return nil, fmt.Errorf("adopt inherited %s listener: %w", name, err)
			}
			tl, ok := ln.(*net.TCPListener)
			if !ok {
				ln.Close()
				return nil, fmt.Errorf("inherited %s listener is not TCP", name)
			}
			s.appendListener(namedListener{name: name, addr: addr, bound: tl.Addr(), ln: tl})
			s.inherited = append(s.inherited, name)
			return tl, nil
		}
		f.Close()
		s.log.Info("listen address changed; binding a new socket", "listener", name, "old", spec.addr, "new", addr)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen %s on %s: %w", name, addr, err)
	}
	tl := ln.(*net.TCPListener)
	s.appendListener(namedListener{name: name, addr: addr, bound: tl.Addr(), ln: tl})
	return tl, nil
}

// appendListener records a bound socket under the listeners lock, so a udp
// reconcile on reload cannot race a concurrent handoff snapshot.
func (s *Server) appendListener(nl namedListener) {
	s.lnMu.Lock()
	s.listeners = append(s.listeners, nl)
	s.lnMu.Unlock()
}

// listenUDP is listenTCP for a udp backend's socket. The socket gets a large
// receive buffer: it absorbs bursts, and during a restart it holds the
// datagrams that arrive between the old process going quiet and the new one
// reading (the kernel caps the request at net.core.rmem_max).
func (s *Server) listenUDP(name, addr string, inh map[string]inheritSpec) (*net.UDPConn, error) {
	var pc *net.UDPConn
	if spec, ok := inh[name]; ok {
		delete(inh, name)
		f := os.NewFile(uintptr(spec.fd), name+"-listener")
		if spec.addr == addr {
			c, err := net.FilePacketConn(f)
			f.Close()
			if err != nil {
				return nil, fmt.Errorf("adopt inherited %s socket: %w", name, err)
			}
			uc, ok := c.(*net.UDPConn)
			if !ok {
				c.Close()
				return nil, fmt.Errorf("inherited %s socket is not UDP", name)
			}
			pc = uc
			s.inherited = append(s.inherited, name)
		} else {
			f.Close()
			s.log.Info("listen address changed; binding a new socket", "listener", name, "old", spec.addr, "new", addr)
		}
	}
	if pc == nil {
		c, err := net.ListenPacket("udp", addr)
		if err != nil {
			return nil, fmt.Errorf("listen %s on udp %s: %w", name, addr, err)
		}
		pc = c.(*net.UDPConn)
	}
	_ = pc.SetReadBuffer(udpSocketBuffer)
	_ = pc.SetWriteBuffer(udpSocketBuffer)
	s.appendListener(namedListener{name: name, addr: addr, bound: pc.LocalAddr(), ln: pc})
	return pc, nil
}

const udpSocketBuffer = 4 << 20

// signalReady tells whoever started us that we are serving: the parent
// process during a handoff, systemd otherwise.
func (s *Server) signalReady() error {
	if v := os.Getenv(envReadyFD); v != "" {
		os.Unsetenv(envReadyFD)
		os.Unsetenv(envInherit)
		fd, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("bad %s: %w", envReadyFD, err)
		}
		f := os.NewFile(uintptr(fd), "ready-pipe")
		defer f.Close()
		_, err = f.WriteString("ready\n")
		return err
	}
	_, err := sdNotify("READY=1")
	return err
}

// dupListener duplicates a listening socket for a child process without
// touching its O_NONBLOCK flag (see the package comment above). os.NewFile
// keeps a non-blocking descriptor non-blocking when exec calls Fd().
func dupListener(ln listenSocket, name string) (*os.File, error) {
	rc, err := ln.SyscallConn()
	if err != nil {
		return nil, err
	}
	nfd, derr := -1, error(nil)
	if err := rc.Control(func(fd uintptr) {
		r, _, errno := syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_DUPFD_CLOEXEC, 0)
		if errno != 0 {
			derr = errno
			return
		}
		nfd = int(r)
	}); err != nil {
		return nil, err
	}
	if derr != nil {
		return nil, derr
	}
	return os.NewFile(uintptr(nfd), name), nil
}

func envWithout(env []string, keys ...string) []string {
	out := env[:0:0]
next:
	for _, kv := range env {
		for _, k := range keys {
			if strings.HasPrefix(kv, k+"=") {
				continue next
			}
		}
		out = append(out, kv)
	}
	return out
}

// Handoff starts a new process on the current listeners and, once it is
// ready, puts this process into drain mode. It is safe to call repeatedly;
// concurrent or late calls are refused.
func (s *Server) Handoff() error {
	// Receiving from ready orders this goroutine after Run's listener setup
	// (the race detector caught a SIGUSR2-during-startup data race here).
	select {
	case <-s.ready:
	default:
		return errors.New("still starting up; retry the restart in a moment")
	}
	if s.draining.Load() {
		return errDraining
	}
	if !s.handoffBusy.CompareAndSwap(false, true) {
		return errors.New("a restart is already in progress")
	}
	// Exclude a concurrent reload for the whole handoff: reconcileUDP must not
	// close or open a socket while we are snapshotting and duplicating them.
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	success := false
	defer func() {
		if !success {
			s.handoffBusy.Store(false)
			s.writePIDFile() // the new process may have claimed the pid file before failing
		}
	}()

	bin, err := os.Executable() // after an upgrade this is the new binary
	if err != nil {
		return fmt.Errorf("locate executable: %w", err)
	}
	var files []*os.File
	defer func() {
		for _, f := range files {
			f.Close()
		}
	}()
	s.lnMu.Lock()
	lsnap := append([]namedListener(nil), s.listeners...)
	s.lnMu.Unlock()
	var specs []string
	for i, nl := range lsnap {
		f, err := dupListener(nl.ln, nl.name+"-listener")
		if err != nil {
			return fmt.Errorf("duplicate %s listener: %w", nl.name, err)
		}
		files = append(files, f)
		specs = append(specs, fmt.Sprintf("%s=%d@%s", nl.name, 3+i, nl.addr))
	}
	pr, pw, err := os.Pipe()
	if err != nil {
		return err
	}
	defer pr.Close()

	cmd := exec.Command(bin, os.Args[1:]...)
	cmd.Env = append(envWithout(os.Environ(), envInherit, envReadyFD),
		envInherit+"="+strings.Join(specs, ","),
		envReadyFD+"="+strconv.Itoa(3+len(files)))
	cmd.ExtraFiles = append(append([]*os.File(nil), files...), pw)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	// From here on only the new process reads the UDP sockets; datagrams wait
	// in the kernel until it does. If it never gets ready, reading resumes.
	s.pauseUDP()
	defer func() {
		if !success {
			s.resumeUDP()
		}
	}()
	if err := cmd.Start(); err != nil {
		pw.Close()
		return fmt.Errorf("start new process: %w", err)
	}
	pw.Close()
	pid := cmd.Process.Pid
	s.log.Info("restart: new process started; waiting until it is ready", "pid", pid, "binary", bin)

	readyCh := make(chan error, 1)
	go func() {
		buf := make([]byte, 16)
		n, _ := pr.Read(buf)
		if n > 0 && strings.HasPrefix(string(buf[:n]), "ready") {
			readyCh <- nil
			return
		}
		readyCh <- errors.New("new process exited before it was ready (its log lines above say why)")
	}()
	select {
	case err := <-readyCh:
		if err != nil {
			go cmd.Wait() //nolint:errcheck // reap
			return err
		}
	case <-time.After(handoffReadyTimeout):
		_ = cmd.Process.Kill()
		go cmd.Wait() //nolint:errcheck
		return fmt.Errorf("new process not ready after %s; killed it", handoffReadyTimeout)
	}
	go cmd.Wait() //nolint:errcheck // reap it should it exit while we drain

	if sent, err := sdNotify("MAINPID=" + strconv.Itoa(pid)); err != nil {
		s.log.Warn("could not hand the main PID to systemd", "err", err)
	} else if sent {
		s.log.Debug("systemd main PID updated", "pid", pid)
	}
	success = true
	s.log.Info("restart: handed over; this process now drains", "new_pid", pid,
		"tunnels", s.tunnels.count(), "udp_sessions", s.udpSessions(),
		"drain_timeout", s.state.Load().cfg.Timeouts.Drain.D().String())
	close(s.handedOff)
	return nil
}

// drain runs in the old process after a handoff. The new process accepts on
// the shared sockets now; this one stops accepting and serves everything it
// already has to completion: in-flight requests (their connections close after
// the response, keep-alives are off), connections still sending their first
// request, and tunnels. Only timeouts.drain (or SIGTERM) cuts it short.
func (s *Server) drain(ctx context.Context) error {
	s.draining.Store(true)
	timeout := s.state.Load().cfg.Timeouts.Drain.D()
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// UDP sessions cannot move: the new process reads the sockets now, and
	// each client's next datagram opens a fresh session there.
	if n := s.stopUDP("restart"); n > 0 {
		s.log.Info("restart: udp sessions closed; clients continue in the new process", "count", n)
	}
	s.closeListeners()
	servers := []*http.Server{s.httpSrv, s.adminSrv, s.redirSrv}
	for _, srv := range servers {
		if srv != nil {
			srv.SetKeepAlivesEnabled(false) // closes idle keep-alive connections now
		}
	}

	// Every client connection counts until it is closed: requests, tunnels,
	// and tunnels still being set up (already hijacked from net/http but not
	// yet registered), so nothing is cut in between.
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for s.activeConns() > 0 && dctx.Err() == nil {
		select {
		case <-tick.C:
		case <-dctx.Done():
		}
	}
	if n := s.activeConns(); n > 0 {
		reason := "drain_timeout"
		if ctx.Err() != nil {
			reason = "shutdown"
		}
		t := s.tunnels.shutdown(reason)
		s.log.Info("drain ended; closing remaining connections", "connections", n, "tunnels", t, "reason", reason)
	}
	for _, srv := range servers {
		if srv != nil {
			_ = srv.Close()
		}
	}
	wctx, wcancel := context.WithTimeout(context.Background(), 3*time.Second)
	s.tunnels.waitEmpty(wctx) // let closed tunnels finish logging
	wcancel()
	s.state.Load().routes.stop()
	s.log.Info("drain complete; old process exiting")
	return nil
}
