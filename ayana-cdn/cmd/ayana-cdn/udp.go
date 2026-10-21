package main

import (
	"container/list"
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// UDP backends.
//
// A datagram carries no path, so a udp backend does not live under /<name>/:
// it owns a listen address of its own ("listen": ":36712"), and every
// datagram that arrives there is relayed to one of its upstreams. The
// "connection" TCP gives for free is rebuilt here as a session: the client's
// address and port map to one socket connected to the chosen upstream, so the
// upstream sees one source port per client flow and its replies find their way
// back. Several flows from one client address are several sessions, each with
// its own upstream socket, and each draws on the UDP per-IP budget.
//
// A session ends when:
//   - it is idle: no datagram either way for timeouts.udp_idle;
//   - the upstream is unreachable: an ICMP port/host/net-unreachable surfaces
//     as ECONNREFUSED/EHOSTUNREACH/ENETUNREACH on the connected socket;
//   - the upstream is silent: the client keeps sending but nothing comes back
//     within timeouts.udp_reply (a black-holed or wrong upstream that a hard
//     ICMP error never reveals);
//   - the edge shuts down, or restarts (the new process takes over the socket
//     and the client's next datagram opens a fresh session there).

const udpSweepInterval = 500 * time.Millisecond

type udpStats struct {
	active atomic.Int64
}

// Why a datagram was dropped instead of relayed.
const (
	udpDropNoBackend     = iota // the listener's backend is gone or no longer udp (after a reload)
	udpDropDisabled             // backend disabled
	udpDropGlobalCap            // limits.max_udp_sessions
	udpDropIPRate               // limits.udp_rate_per_ip
	udpDropIPConns              // limits.max_udp_sessions_per_ip
	udpDropBackendCap           // the backend's max_conns
	udpDropDialError            // no upstream could be dialed
	udpDropPortExhausted        // the edge ran out of local ports/descriptors (see docs/OPERATIONS.md capacity)
	udpDropOversize             // datagram larger than limits.max_udp_packet
	udpDropWriteError           // the socket refused the datagram (full buffer, PMTU, transient)
	udpDropAmplified            // reply withheld from an unverified source by the anti-amplification limit
	udpDropReasons
)

var udpDropNames = [udpDropReasons]string{"no_backend", "disabled", "global_cap", "ip_rate", "ip_conns",
	"backend_cap", "dial_error", "port_exhausted", "oversize", "write_error", "amplified"}

// isLocalExhaustion reports the dial errors that mean the edge itself ran out
// of local ports or descriptors, not that the upstream is down.
func isLocalExhaustion(err error) bool {
	return errors.Is(err, syscall.EADDRNOTAVAIL) || errors.Is(err, syscall.EAGAIN) ||
		errors.Is(err, syscall.EMFILE) || errors.Is(err, syscall.ENFILE) || errors.Is(err, syscall.ENOBUFS)
}

// udpListener is one udp backend's socket. It outlives reloads: the backend is
// looked up by name in the current state for every new session, so upstreams,
// limits and timeouts follow the config while the socket stays put.
type udpListener struct {
	s    *Server
	name string
	addr string // configured listen address
	pc   *net.UDPConn
	v6   bool

	drops [udpDropReasons]atomic.Uint64 // per-backend, exported with a backend label

	// Unreplied-session FIFO, per listener so a spoof flood on one backend
	// cannot evict legitimate mid-handshake sessions on another (the counter
	// and queue used to be global). Oldest first, for O(1) eviction.
	fifoMu    sync.Mutex
	unrepFIFO list.List
	unreplied atomic.Int64

	mu       sync.Mutex
	sessions map[netip.AddrPort]*udpSession
	closing  string // set once; sessions registering afterwards are closed at once

	paused   atomic.Bool
	resumeCh chan struct{}
	stopCh   chan struct{}
	stopOnce sync.Once
	done     chan struct{} // closed when the read loop has exited
}

func (l *udpListener) drop(reason int) { l.drops[reason].Add(1) }

func newUDPListener(s *Server, name, addr string, pc *net.UDPConn) *udpListener {
	l := &udpListener{
		s: s, name: name, addr: addr, pc: pc,
		sessions: make(map[netip.AddrPort]*udpSession),
		resumeCh: make(chan struct{}, 1),
		stopCh:   make(chan struct{}),
		done:     make(chan struct{}),
	}
	if rc, err := pc.SyscallConn(); err == nil {
		l.v6 = socketDomain(rc) == syscall.AF_INET6
		disablePMTU(rc, l.v6)
	}
	return l
}

func (l *udpListener) start() {
	go l.serve()
	go l.sweep()
}

// serve is the read loop: one goroutine per listener, one datagram at a time.
// It never blocks — no name resolution (upstreams are resolved at config load)
// and no blocking write (the upstream send is non-blocking).
func (l *udpListener) serve() {
	defer close(l.done)
	buf := make([]byte, maxUDPDatagram+1) // largest possible datagram; the cap below is read live so a reload applies
	for {
		n, _, flags, from, err := l.pc.ReadMsgUDPAddrPort(buf, nil)
		if err != nil {
			select {
			case <-l.stopCh:
				return
			default:
			}
			if l.paused.Load() {
				select {
				case <-l.resumeCh:
				case <-l.stopCh:
					return
				}
				continue
			}
			if isTimeout(err) {
				continue // a leftover deadline from a pause that was resumed
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			l.s.log.Warn("udp read failed", "backend", l.name, "err", errString(err))
			time.Sleep(10 * time.Millisecond) // do not spin on a persistent error
			continue
		}
		if flags&syscall.MSG_TRUNC != 0 || n > l.s.state.Load().cfg.Limits.MaxUDPPacket {
			l.drop(udpDropOversize)
			continue
		}
		client := netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		l.mu.Lock()
		sess := l.sessions[client]
		l.mu.Unlock()
		if sess == nil {
			if sess = l.open(client); sess == nil {
				continue
			}
		}
		if sess.fromClient(buf[:n]) { // the session died under us: rebuild it and resend once
			l.remove(sess)
			if sess = l.open(client); sess != nil {
				sess.fromClient(buf[:n])
			}
		}
	}
}

// open admits and sets up a session for a new client flow, or returns nil and
// counts the reason when the datagram must be dropped.
func (l *udpListener) open(client netip.AddrPort) *udpSession {
	s := l.s
	st := s.state.Load()
	brt := st.routes.byName[l.name]
	if brt == nil || !brt.udp {
		l.drop(udpDropNoBackend)
		return nil
	}
	b := &brt.cfg
	bs := brt.stats
	if b.Disabled {
		l.drop(udpDropDisabled)
		return nil
	}
	// A flood of spoofed sources would otherwise fill the table with sessions
	// that never reply. Cap those per listener and evict the oldest unreplied
	// one (O(1)) so a real client — on this or any other backend — is not
	// turned away by noise.
	if st.maxUnreplied > 0 && l.unreplied.Load() >= st.maxUnreplied {
		l.evictOldestUnreplied()
	}
	if st.maxUDP > 0 {
		if n := s.stats.udp.active.Add(1); n > st.maxUDP {
			s.stats.udp.active.Add(-1)
			l.drop(udpDropGlobalCap)
			return nil
		}
	} else {
		s.stats.udp.active.Add(1)
	}
	// From here a failure must roll back udp.active.
	now := time.Now()
	ip := client.Addr()
	var ipKey string
	tracked := false
	if !prefixesContain(st.exempt, ip) {
		ipKey = limiterKey(ip)
		ok, tr, reason := s.udpLimiter.admit(ipKey, now)
		if !ok {
			s.stats.udp.active.Add(-1)
			if reason == "ip_rate" {
				l.drop(udpDropIPRate)
			} else {
				l.drop(udpDropIPConns)
			}
			return nil
		}
		tracked = tr
	}
	rollback := func() {
		s.stats.udp.active.Add(-1)
		if tracked {
			s.udpLimiter.release(ipKey)
		}
	}
	if n := bs.tunnelsActive.Add(1); b.MaxConns > 0 && n > int64(b.MaxConns) {
		bs.tunnelsActive.Add(-1)
		bs.rejectedCap.Add(1)
		l.drop(udpDropBackendCap)
		rollback()
		return nil
	}
	uc, up, err := brt.pool.dialUDP(ip)
	if err != nil {
		bs.tunnelsActive.Add(-1)
		bs.tunnelsFailed.Add(1)
		if isLocalExhaustion(err) {
			l.drop(udpDropPortExhausted)
		} else {
			l.drop(udpDropDialError)
		}
		rollback()
		s.log.Warn("udp session failed", "backend", b.Name, "client", client.String(), "err", errString(err))
		return nil
	}
	idle := st.cfg.Timeouts.UDPIdle.D()
	if b.IdleTimeout > 0 {
		idle = b.IdleTimeout.D()
	}
	sess := &udpSession{
		l: l, key: client, backend: b.Name, pool: brt.pool, up: up, uc: uc, bs: bs,
		start: now, idle: idle, reply: st.cfg.Timeouts.UDPReply.D(), maxPacket: st.cfg.Limits.MaxUDPPacket,
		ampFactor: st.cfg.Limits.UDPAmplification,
		ipKey:     ipKey, tracked: tracked, access: st.access,
	}
	sess.last.Store(now.UnixNano())
	sess.pendingSince.Store(now.UnixNano()) // the first datagram is unanswered until the upstream replies
	l.mu.Lock()
	closing := l.closing
	if closing == "" {
		l.sessions[client] = sess
	}
	l.mu.Unlock()
	if closing != "" {
		bs.tunnelsActive.Add(-1)
		up.active.Add(-1)
		_ = uc.Close()
		rollback()
		return nil
	}
	l.addUnreplied(sess)
	bs.tunnelsTotal.Add(1)
	if st.ipLogOn {
		ipStr := client.Addr().String()
		if bs.ips.record(ipStr, now) {
			s.geo.enqueue(ipStr)
		}
	}
	s.log.Debug("udp session opened", "backend", b.Name, "client", client.String(), "upstream", up.addr)
	go sess.fromUpstream()
	return sess
}

func (l *udpListener) remove(sess *udpSession) {
	l.mu.Lock()
	if l.sessions[sess.key] == sess {
		delete(l.sessions, sess.key)
	}
	l.mu.Unlock()
}

func (l *udpListener) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.sessions)
}

// sweep closes idle sessions and sessions whose upstream has gone silent. A
// datagram flow has no FIN, so this is how a vanished client or a black-holed
// upstream is reclaimed.
func (l *udpListener) sweep() {
	t := time.NewTicker(udpSweepInterval)
	defer t.Stop()
	for {
		select {
		case <-l.stopCh:
			return
		case now := <-t.C:
			type victim struct {
				s      *udpSession
				reason string
			}
			var victims []victim
			l.mu.Lock()
			for _, sess := range l.sessions {
				pending := sess.pendingSince.Load()
				switch {
				case sess.reply > 0 && pending != 0 && now.Sub(time.Unix(0, pending)) >= sess.reply:
					// A send has gone unanswered for udp_reply: a black-holed or
					// wrong upstream. A reply resets pending, so a client that
					// resumes after an idle gap is given a fresh window.
					victims = append(victims, victim{sess, "upstream_silent"})
				case now.Sub(time.Unix(0, sess.last.Load())) >= sess.idle:
					victims = append(victims, victim{sess, "idle_timeout"})
				}
			}
			l.mu.Unlock()
			for _, v := range victims {
				if v.reason == "upstream_silent" {
					// Only rotate the upstream if it has answered no session at
					// all lately: one client with a bad key must not take a
					// healthy upstream down for everyone.
					if now.Sub(time.Unix(0, v.s.up.lastReply.Load())) >= v.s.reply {
						v.s.pool.onFailure(v.s.up, errors.New("no reply within udp_reply"))
					}
				}
				v.s.close(v.reason)
			}
		}
	}
}

// pause stops reading from the socket without closing it: datagrams queue in
// the kernel until resume, or until another process holding the same socket
// reads them (a restart). The old process is silent from the moment the new
// one starts, so a flow is never split between the two.
func (l *udpListener) pause() {
	if l.paused.CompareAndSwap(false, true) {
		_ = l.pc.SetReadDeadline(time.Now())
	}
}

func (l *udpListener) resume() {
	if l.paused.CompareAndSwap(true, false) {
		_ = l.pc.SetReadDeadline(time.Time{})
		select {
		case l.resumeCh <- struct{}{}:
		default:
		}
	}
}

// stop ends the read loop and every session, then closes the socket. It
// reports how many sessions it closed.
func (l *udpListener) stop(reason string) int {
	l.mu.Lock()
	if l.closing == "" {
		l.closing = reason
	}
	sessList := make([]*udpSession, 0, len(l.sessions))
	for _, sess := range l.sessions {
		sessList = append(sessList, sess)
	}
	l.mu.Unlock()
	l.stopOnce.Do(func() {
		close(l.stopCh)
		_ = l.pc.SetReadDeadline(time.Now()) // wake the read loop
		l.resume()                           // in case a handoff left it paused
	})
	<-l.done
	for _, sess := range sessList {
		sess.close(reason)
	}
	_ = l.pc.Close()
	return len(sessList)
}

// ---- sessions --------------------------------------------------------------------

type udpSession struct {
	l         *udpListener
	key       netip.AddrPort // client address, the map key
	backend   string
	pool      *pool
	up        *upstream
	uc        *net.UDPConn // connected to the upstream: ICMP errors arrive here
	bs        *backendStats
	start     time.Time
	idle      time.Duration
	reply     time.Duration // 0 = reply-based liveness disabled
	maxPacket int
	ampFactor int // max bytes reflected per byte sent, until verified; <=0 = off
	ipKey     string
	tracked   bool
	access    bool

	last         atomic.Int64 // unix nanos of the last datagram either way (idle timer)
	pendingSince atomic.Int64 // unix nanos of the oldest send still unanswered by the upstream; 0 = none outstanding
	pktUp        atomic.Uint64
	pktDown      atomic.Uint64
	bytesUp      atomic.Uint64
	bytesDown    atomic.Uint64
	replied      atomic.Bool // the upstream has answered at least once
	unrelDone    atomic.Bool // the unreplied FIFO/counter has been released for this session
	fifoElem     *list.Element
	closeOnce    sync.Once
}

// fromClient relays one datagram to the upstream. It runs on the listener's
// read loop, so the send is non-blocking. It returns true when the session has
// already been torn down and the caller should rebuild it.
func (s *udpSession) fromClient(b []byte) (dead bool) {
	now := time.Now()
	s.last.Store(now.UnixNano())
	s.pendingSince.CompareAndSwap(0, now.UnixNano()) // start the reply window at the first unanswered send
	// Count bytes received from the client BEFORE forwarding: the
	// anti-amplification budget is based on what this (possibly spoofed) source
	// sent us, and the upstream's reply can race ahead of a post-send
	// increment, which would wrongly withhold a legitimate first answer.
	s.pktUp.Add(1)
	s.bytesUp.Add(uint64(len(b)))
	err := writeConnected(s.uc, b)
	switch {
	case err == nil:
		s.bs.bytesUp.Add(uint64(len(b)))
		s.bs.packetsUp.Add(1)
		s.maybePromote() // a client that keeps sending earns its way out of the unreplied FIFO
		return false
	case errors.Is(err, net.ErrClosed):
		return true // closed by the sweeper or the downstream goroutine
	case isUnreachable(err):
		s.pool.onFailure(s.up, err)
		s.close("upstream_unreachable")
		return false
	default:
		// EMSGSIZE (PMTU), EAGAIN (full buffer), ENOBUFS: drop this datagram,
		// keep the session; UDP is lossy by contract.
		s.l.drop(udpDropWriteError)
		return false
	}
}

// fromUpstream relays the upstream's datagrams back to the client. One
// goroutine per session, blocked in Read most of the time.
func (s *udpSession) fromUpstream() {
	buf := make([]byte, s.maxPacket+1)
	for {
		n, _, flags, _, err := s.uc.ReadMsgUDP(buf, nil)
		if err != nil {
			switch {
			case errors.Is(err, net.ErrClosed):
				return
			case isUnreachable(err):
				s.pool.onFailure(s.up, err)
				s.close("upstream_unreachable")
				return
			case isTransient(err):
				continue // EMSGSIZE / EINTR / EAGAIN: the datagram is lost, the session is not
			default:
				s.close("upstream_error: " + errString(err))
				return
			}
		}
		if flags&syscall.MSG_TRUNC != 0 || n > s.maxPacket {
			s.l.drop(udpDropOversize)
			continue
		}
		nowN := time.Now().UnixNano()
		s.up.lastReply.Store(nowN)
		if s.replied.CompareAndSwap(false, true) {
			s.pool.onSuccess(s.up) // the first answer is the proof this upstream is up
		}
		// Anti-amplification (QUIC's 3x rule): until the source has proven it
		// is really there (it kept sending), never reflect more than ampFactor
		// times the bytes it sent. This bounds how much a spoofed source can be
		// made to receive. Verified flows (pktUp >= udpVerifyPackets) are not
		// limited. A reply over the budget is dropped, the session kept.
		if s.ampFactor > 0 && s.pktUp.Load() < udpVerifyPackets &&
			s.bytesDown.Load()+uint64(n) > uint64(s.ampFactor)*s.bytesUp.Load() {
			// The upstream answered, so record liveness (clear the pending
			// window, refresh idle) before withholding the over-budget reply:
			// otherwise the silent-upstream sweeper would reap a session that
			// is actually healthy. The session stays unpromoted and evictable;
			// a retransmit on it reaches pktUp>=2 and the reply then flows.
			s.last.Store(nowN)
			s.pendingSince.Store(0)
			s.l.drop(udpDropAmplified)
			continue
		}
		s.last.Store(nowN)
		s.pendingSince.Store(0) // the upstream answered; nothing outstanding until the next send
		if _, err := s.l.pc.WriteToUDPAddrPort(buf[:n], s.key); err != nil {
			s.l.drop(udpDropWriteError)
			continue
		}
		s.pktDown.Add(1)
		s.bytesDown.Add(uint64(n))
		s.bs.bytesDown.Add(uint64(n))
		s.bs.packetsDown.Add(1)
		s.maybePromote()
	}
}

// close ends the session once; the first caller's reason is logged.
func (s *udpSession) close(reason string) {
	s.closeOnce.Do(func() {
		s.l.remove(s)    // drop the map entry first, so a racing datagram rebuilds cleanly
		_ = s.uc.Close() // ends fromUpstream
		s.up.active.Add(-1)
		s.bs.tunnelsActive.Add(-1)
		s.l.s.stats.udp.active.Add(-1)
		s.l.releaseUnreplied(s)
		if s.tracked {
			s.l.s.udpLimiter.release(s.ipKey)
		}
		if s.replied.Load() {
			s.bs.observeStatus(0) // raw: a session that carried an answer
		}
		if s.access {
			s.l.s.log.Info("udp", "backend", s.backend, "client", s.key.String(), "upstream", s.up.addr,
				"up", s.bytesUp.Load(), "down", s.bytesDown.Load(),
				"packets_up", s.pktUp.Load(), "packets_down", s.pktDown.Load(),
				"duration", time.Since(s.start).Round(time.Millisecond).String(), "reason", reason)
		}
	})
}

// ---- unreplied FIFO (spoof-flood defence) -----------------------------------------

// udpVerifyPackets is how many datagrams a source must send before it is
// treated as return-routable: it leaves the unreplied FIFO and the
// anti-amplification limit stops applying. This is a cost-raising heuristic,
// not cryptographic proof (a blind spoofer can still send two datagrams), so a
// publicly reachable udp backend should also sit behind BCP38 ingress
// filtering; see docs/OPERATIONS.md.
const udpVerifyPackets = 2

// maybePromote removes a session from the unreplied FIFO once the upstream has
// answered AND the client has proven it keeps sending. Basing this on the
// client (not just the upstream's first reply) is what stops a single spoofed
// datagram from buying an eviction-immune, full-lifetime reflecting session.
func (s *udpSession) maybePromote() {
	if s.replied.Load() && s.pktUp.Load() >= udpVerifyPackets {
		s.l.releaseUnreplied(s)
	}
}

func (l *udpListener) addUnreplied(s *udpSession) {
	l.fifoMu.Lock()
	s.fifoElem = l.unrepFIFO.PushBack(s)
	l.fifoMu.Unlock()
	l.unreplied.Add(1)
}

func (l *udpListener) releaseUnreplied(s *udpSession) {
	if !s.unrelDone.CompareAndSwap(false, true) {
		return
	}
	l.fifoMu.Lock()
	if s.fifoElem != nil {
		l.unrepFIFO.Remove(s.fifoElem)
		s.fifoElem = nil
	}
	l.fifoMu.Unlock()
	l.unreplied.Add(-1)
}

// oldestUnreplied returns the session at the front of the unreplied FIFO, or
// nil when it is empty.
func (l *udpListener) oldestUnreplied() *udpSession {
	l.fifoMu.Lock()
	defer l.fifoMu.Unlock()
	if front := l.unrepFIFO.Front(); front != nil {
		return front.Value.(*udpSession)
	}
	return nil
}

func (l *udpListener) evictOldestUnreplied() {
	if victim := l.oldestUnreplied(); victim != nil {
		victim.close("evicted_unreplied")
	}
}

// isUnreachable reports the hard ICMP errors that mean the upstream is not
// there: they end the session at once.
func isUnreachable(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM)
}

// isTransient reports errors that lose one datagram but not the session.
func isTransient(err error) bool {
	return errors.Is(err, syscall.EMSGSIZE) || errors.Is(err, syscall.EAGAIN) ||
		errors.Is(err, syscall.EINTR) || errors.Is(err, syscall.ENOBUFS)
}

// ---- pool -----------------------------------------------------------------------------

// dialUDP connects a socket to an upstream, healthy ones first. Connecting a
// UDP socket sends nothing, so success here only means the address is usable;
// the session marks the upstream up on its first answer and down when the
// kernel reports it unreachable or it stays silent.
func (p *pool) dialUDP(client netip.Addr) (*net.UDPConn, *upstream, error) {
	if len(p.ups) == 0 {
		return nil, nil, errors.New("backend has no upstreams")
	}
	var errs []string
	var portErr error
	for _, u := range p.pickUDP(client) {
		ua := u.udpAddr.Load()
		if ua == nil {
			errs = append(errs, u.addr+": unresolved")
			continue
		}
		c, err := net.DialUDP("udp", nil, ua)
		if err != nil {
			if isLocalExhaustion(err) {
				portErr = err // running out of local ports/fds is the edge's problem, not the upstream's
			} else {
				u.dialErr.Add(1)
				p.onFailure(u, err)
			}
			errs = append(errs, u.addr+": "+errString(err))
			continue
		}
		if rc, e := c.SyscallConn(); e == nil {
			disablePMTU(rc, ua.IP.To4() == nil)
		}
		u.dialOK.Add(1)
		u.active.Add(1)
		return c, u, nil
	}
	if portErr != nil {
		return nil, nil, portErr
	}
	return nil, nil, fmt.Errorf("all upstreams failed: %s", strings.Join(errs, "; "))
}

// pickUDP orders the upstreams for a new session. "hash" keeps every flow of
// one client on the same upstream (so a re-created session and a client's QUIC
// migration keep talking to the same stateful server); the others reuse the
// TCP ordering.
func (p *pool) pickUDP(client netip.Addr) []*upstream {
	now := time.Now()
	if p.lb != "hash" || len(p.ups) == 1 {
		return p.order(now)
	}
	type scored struct {
		u     *upstream
		up    bool
		score uint64
	}
	xs := make([]scored, len(p.ups))
	for i, u := range p.ups {
		h := fnv.New64a()
		_, _ = h.Write(client.AsSlice())
		_, _ = h.Write([]byte(u.addr))
		xs[i] = scored{u, u.isHealthy(now), h.Sum64()}
	}
	sort.SliceStable(xs, func(i, j int) bool {
		if xs[i].up != xs[j].up {
			return xs[i].up // healthy upstreams first
		}
		return xs[i].score > xs[j].score
	})
	out := make([]*upstream, len(xs))
	for i := range xs {
		out[i] = xs[i].u
	}
	return out
}

// ---- server integration ------------------------------------------------------------

// startUDP binds (or adopts) the socket of every udp backend in the startup
// config and starts serving them. A bind failure is logged and skipped, never
// fatal: a taken UDP port must not stop the edge from serving TCP.
func (s *Server) startUDP(cfg *Config, inh map[string]inheritSpec) error {
	inh0 := inheritedNames(inh)
	for _, b := range cfg.Backends {
		if !b.isUDP() {
			continue
		}
		pc, err := s.listenUDP(udpListenerName(b.Name), b.Listen, inh)
		if err != nil {
			s.log.Error("udp backend not listening; the rest of the edge keeps serving",
				"backend", b.Name, "listen", b.Listen, "err", errString(err))
			continue
		}
		l := newUDPListener(s, b.Name, b.Listen, pc)
		s.udpMu.Lock()
		s.udp = append(s.udp, l)
		s.udpMu.Unlock()
		s.logUDPListen(b.Name, pc, inh0[udpListenerName(b.Name)])
		l.start()
	}
	return nil
}

func (s *Server) logUDPListen(name string, pc *net.UDPConn, inherited bool) {
	got := socketRcvBuf(pc)
	s.log.Info("udp listening", "backend", name, "listen", pc.LocalAddr().String(),
		"rcvbuf", got, "inherited", inherited, "max_sessions", s.state.Load().maxUDP)
	if got > 0 && got < udpSocketBuffer {
		s.log.Warn("udp receive buffer smaller than requested; raise net.core.rmem_max to absorb bursts",
			"backend", name, "have", got, "want", udpSocketBuffer)
	}
}

// socketRcvBuf reports the effective SO_RCVBUF (the kernel stores twice the set
// value; halve it for a comparable number).
func socketRcvBuf(pc *net.UDPConn) int {
	rc, err := pc.SyscallConn()
	if err != nil {
		return 0
	}
	var v int
	_ = rc.Control(func(fd uintptr) {
		if n, err := syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF); err == nil {
			v = n / 2
		}
	})
	return v
}

func udpListenerName(backend string) string { return "udp-" + backend }

func inheritedNames(inh map[string]inheritSpec) map[string]bool {
	out := make(map[string]bool, len(inh))
	for name := range inh {
		out[name] = true
	}
	return out
}

func (s *Server) pauseUDP() {
	for _, l := range s.udpListeners() {
		l.pause()
	}
}

func (s *Server) resumeUDP() {
	for _, l := range s.udpListeners() {
		l.resume()
	}
}

// stopUDP ends every UDP listener and session; it reports the sessions closed.
func (s *Server) stopUDP(reason string) int {
	s.udpMu.Lock()
	ls := s.udp
	s.udp = nil
	s.udpMu.Unlock()
	n := 0
	for _, l := range ls {
		n += l.stop(reason)
	}
	return n
}

func (s *Server) udpSessions() int {
	n := 0
	for _, l := range s.udpListeners() {
		n += l.count()
	}
	return n
}

// udpListeners returns a snapshot for metrics, status and lifecycle calls.
func (s *Server) udpListeners() []*udpListener {
	s.udpMu.Lock()
	defer s.udpMu.Unlock()
	return append([]*udpListener(nil), s.udp...)
}

// reconcileUDP starts listeners for udp backends added or moved since the last
// config and stops those removed or moved, so `backend add/rm` and `routes
// import` for udp backends take effect on reload as they do for tunnels.
// Sockets whose (name, listen) pair is unchanged keep serving.
func (s *Server) reconcileUDP(old, cur *Config, inh map[string]inheritSpec) {
	want := udpListenSet(cur)
	have := udpListenSet(old)
	for name, addr := range have {
		if want[name] != addr {
			s.stopOneUDP(name)
		}
	}
	inh0 := inheritedNames(inh)
	for _, b := range cur.Backends {
		if !b.isUDP() || have[b.Name] == b.Listen {
			continue // unchanged: leave the running socket alone
		}
		pc, err := s.listenUDP(udpListenerName(b.Name), b.Listen, inh)
		if err != nil {
			s.log.Error("udp backend not listening after reload; the edge keeps serving",
				"backend", b.Name, "listen", b.Listen, "err", errString(err))
			continue
		}
		l := newUDPListener(s, b.Name, b.Listen, pc)
		s.udpMu.Lock()
		s.udp = append(s.udp, l)
		s.udpMu.Unlock()
		s.logUDPListen(b.Name, pc, inh0[udpListenerName(b.Name)])
		l.start()
	}
}

// stopOneUDP stops and removes the listener for one backend.
func (s *Server) stopOneUDP(name string) {
	s.udpMu.Lock()
	var target *udpListener
	kept := make([]*udpListener, 0, len(s.udp))
	for _, l := range s.udp {
		if l.name == name {
			target = l
		} else {
			kept = append(kept, l)
		}
	}
	s.udp = kept
	s.udpMu.Unlock()
	if target != nil {
		n := target.stop("backend_removed")
		s.dropListener(udpListenerName(name))
		s.log.Info("udp backend stopped", "backend", name, "sessions_closed", n)
	}
}

// effectiveMaxUDPSessions: explicit value, -1 = unlimited, 0 = derived from the
// file-descriptor limit and the ephemeral port range (each session needs one of
// each; the TCP side keeps its own share of the descriptors).
func effectiveMaxUDPSessions(v int) int64 {
	switch {
	case v > 0:
		return int64(v)
	case v < 0:
		return 0
	}
	lim := nofileLimit()
	if lim > 1<<30 {
		lim = 1 << 30
	}
	byFD := int64(lim)/4 - 256
	if ports := int64(ephemeralPortRange()) - 1024; ports > 0 && ports < byFD {
		byFD = ports // a connected UDP socket takes a local port, so this is the real ceiling
	}
	return max(byFD, 256)
}

// maxUnreplied bounds the sessions that have never had a reply, so a spoofed
// flood cannot exhaust the table; it is a quarter of the session cap.
func maxUnreplied(maxUDP int64) int64 {
	if maxUDP <= 0 {
		return 0 // unlimited sessions: do not cap the unreplied ones either
	}
	return max(maxUDP/4, 256)
}
