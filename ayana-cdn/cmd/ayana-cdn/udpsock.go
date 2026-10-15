package main

import (
	"net"
	"syscall"
)

// Socket plumbing for the UDP data path, kept apart from the relay logic.
//
// Path-MTU discovery is the one kernel behaviour that has to be turned off. A
// connected UDP socket defaults to IP_PMTUDISC_WANT, so an ICMP "fragmentation
// needed" turns the next send into a one-shot EMSGSIZE. WireGuard, QUIC and
// other tunnels routinely send packets larger than a 1400-byte overlay path,
// so this would tear a session down whenever the path MTU dropped. The edge
// relays opaque datagrams and must not do PMTU discovery of its own; a too-big
// datagram is dropped by the network as any UDP datagram may be.
//
// Reply source address on a multi-homed host is handled by binding the
// backend's "listen" to the specific address clients use, not with per-packet
// IP_PKTINFO: on the wildcard socket the kernel picks the source by route,
// which is only wrong when the edge answers on an address other than the one
// it received on. See docs/CONFIG.md (backends[].listen).

// Linux socket options that package syscall does not expose by name.
const (
	sockIPMTUDiscover   = 10 // IP_MTU_DISCOVER
	sockIPv6MTUDiscover = 23 // IPV6_MTU_DISCOVER
	sockPMTUDiscDont    = 0  // IP_PMTUDISC_DONT / IPV6_PMTUDISC_DONT
)

// socketDomain reports the address family of a socket (AF_INET or AF_INET6).
func socketDomain(rc syscall.RawConn) int {
	dom := syscall.AF_INET
	_ = rc.Control(func(fd uintptr) {
		if d, err := syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_DOMAIN); err == nil {
			dom = d
		}
	})
	return dom
}

// disablePMTU turns off path-MTU discovery so a large datagram is never
// refused with EMSGSIZE. Errors are ignored: a kernel that lacks the option
// leaves the default, which only risks the rare EMSGSIZE the relay tolerates.
func disablePMTU(rc syscall.RawConn, v6 bool) {
	_ = rc.Control(func(fd uintptr) {
		if v6 {
			_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, sockIPv6MTUDiscover, sockPMTUDiscDont)
		} else {
			_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, sockIPMTUDiscover, sockPMTUDiscDont)
		}
	})
}

// writeConnected sends on a connected UDP socket without blocking the caller:
// the socket is non-blocking, so a full send buffer returns EAGAIN and the
// datagram is dropped instead of parking the shared read loop.
func writeConnected(uc *net.UDPConn, b []byte) error {
	rc, err := uc.SyscallConn()
	if err != nil {
		return err
	}
	var werr error
	cerr := rc.Write(func(fd uintptr) bool {
		_, werr = syscall.Write(int(fd), b)
		return true // one attempt, never wait for writability
	})
	if cerr != nil {
		return cerr
	}
	return werr
}
