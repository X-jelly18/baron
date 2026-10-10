package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

var proxyV2Sig = []byte("\r\n\r\n\x00\r\nQUIT\n")

var errProxyHeader = errors.New("malformed PROXY protocol header")

// readProxyHeader consumes a PROXY protocol v1 or v2 header if one is present
// and returns the client address it carries. It returns (nil, nil) when the
// stream has no header (a direct connection from a trusted address) or the
// header does not describe a TCP client (LOCAL, UNKNOWN, UDP, UNIX).
//
// nginx `proxy_protocol on;` sends v1; HAProxy `send-proxy-v2` sends v2.
func readProxyHeader(br *bufio.Reader) (net.Addr, error) {
	first, err := br.Peek(1)
	if err != nil {
		return nil, err
	}
	switch first[0] {
	case 'P':
		return readProxyV1(br)
	case '\r':
		return readProxyV2(br)
	}
	return nil, nil
}

func readProxyV1(br *bufio.Reader) (net.Addr, error) {
	sig, err := br.Peek(6)
	if err != nil || string(sig) != "PROXY " {
		return nil, nil // not a header; let the TLS layer reject the bytes
	}
	line, err := br.ReadSlice('\n')
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errProxyHeader, err)
	}
	if len(line) > 107 { // maximum v1 header length per the spec
		return nil, fmt.Errorf("%w: v1 header too long", errProxyHeader)
	}
	f := strings.Split(strings.TrimRight(string(line), "\r\n"), " ")
	if len(f) < 2 {
		return nil, errProxyHeader
	}
	switch f[1] {
	case "UNKNOWN":
		return nil, nil
	case "TCP4", "TCP6":
		if len(f) != 6 {
			return nil, fmt.Errorf("%w: v1 needs 6 fields", errProxyHeader)
		}
		ip, err := netip.ParseAddr(f[2])
		if err != nil {
			return nil, fmt.Errorf("%w: bad source address", errProxyHeader)
		}
		port, err := strconv.ParseUint(f[4], 10, 16)
		if err != nil {
			return nil, fmt.Errorf("%w: bad source port", errProxyHeader)
		}
		return net.TCPAddrFromAddrPort(netip.AddrPortFrom(ip.Unmap(), uint16(port))), nil
	}
	return nil, fmt.Errorf("%w: unknown protocol %q", errProxyHeader, f[1])
}

func readProxyV2(br *bufio.Reader) (net.Addr, error) {
	hdr, err := br.Peek(16)
	if err != nil || !bytes.Equal(hdr[:12], proxyV2Sig) {
		return nil, nil
	}
	verCmd, fam := hdr[12], hdr[13]
	n := int(binary.BigEndian.Uint16(hdr[14:16]))
	if verCmd>>4 != 2 {
		return nil, fmt.Errorf("%w: v2 version %d", errProxyHeader, verCmd>>4)
	}
	if n > 4096 {
		return nil, fmt.Errorf("%w: v2 header too long", errProxyHeader)
	}
	buf := make([]byte, 16+n)
	if _, err := io.ReadFull(br, buf); err != nil {
		return nil, fmt.Errorf("%w: %v", errProxyHeader, err)
	}
	switch verCmd & 0x0f {
	case 0x0: // LOCAL: the proxy's own connection (health check); keep the real peer
		return nil, nil
	case 0x1: // PROXY
	default:
		return nil, fmt.Errorf("%w: v2 command %d", errProxyHeader, verCmd&0x0f)
	}
	body := buf[16:]
	switch fam {
	case 0x11: // TCP over IPv4: src(4) dst(4) sport(2) dport(2)
		if len(body) < 12 {
			return nil, fmt.Errorf("%w: short v2 IPv4 block", errProxyHeader)
		}
		ip := netip.AddrFrom4([4]byte(body[0:4]))
		return net.TCPAddrFromAddrPort(netip.AddrPortFrom(ip, binary.BigEndian.Uint16(body[8:10]))), nil
	case 0x21: // TCP over IPv6: src(16) dst(16) sport(2) dport(2)
		if len(body) < 36 {
			return nil, fmt.Errorf("%w: short v2 IPv6 block", errProxyHeader)
		}
		ip := netip.AddrFrom16([16]byte(body[0:16])).Unmap()
		return net.TCPAddrFromAddrPort(netip.AddrPortFrom(ip, binary.BigEndian.Uint16(body[32:34]))), nil
	}
	return nil, nil // UNSPEC, UDP or UNIX: no usable TCP client address
}
