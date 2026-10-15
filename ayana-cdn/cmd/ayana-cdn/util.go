package main

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"syscall"
)

func ptr[T any](v T) *T { return &v }

// normHost lowercases a Host header or SNI value and drops any port and trailing dot.
func normHost(h string) string {
	h = strings.TrimSpace(h)
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	return strings.TrimSuffix(strings.ToLower(h), ".")
}

// addrIP extracts the IP from a net.Addr (IPv4-mapped IPv6 is unmapped).
func addrIP(a net.Addr) netip.Addr {
	if a == nil {
		return netip.Addr{}
	}
	if t, ok := a.(*net.TCPAddr); ok {
		ip, _ := netip.AddrFromSlice(t.IP)
		return ip.Unmap()
	}
	if ap, err := netip.ParseAddrPort(a.String()); err == nil {
		return ap.Addr().Unmap()
	}
	return netip.Addr{}
}

// limiterKey groups IPv6 clients by /64: a single subscriber usually owns a
// whole /64, so per-address limits would be trivial to evade.
func limiterKey(ip netip.Addr) string {
	if ip.Is4() {
		return ip.String()
	}
	p, err := ip.Prefix(64)
	if err != nil {
		return ip.String()
	}
	return p.String()
}

// parsePrefixes accepts CIDRs and bare IPs.
func parsePrefixes(list []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(list))
	for _, s := range list {
		s = strings.TrimSpace(s)
		if strings.Contains(s, "/") {
			p, err := netip.ParsePrefix(s)
			if err != nil {
				return nil, fmt.Errorf("%q is not a valid CIDR", s)
			}
			out = append(out, p.Masked())
			continue
		}
		ip, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("%q is not a valid IP or CIDR", s)
		}
		ip = ip.Unmap()
		out = append(out, netip.PrefixFrom(ip, ip.BitLen()))
	}
	return out, nil
}

func prefixesContain(ps []netip.Prefix, ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	ip = ip.Unmap()
	for _, p := range ps {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// clientIP is the host part of r.RemoteAddr, which already reflects PROXY
// protocol information when a trusted front door supplied it.
func clientIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := uint64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// errString flattens an error for logs and status output.
func errString(err error) string {
	if err == nil {
		return ""
	}
	return strings.ReplaceAll(err.Error(), "\n", " ")
}

// ephemeralPortRange returns the width of net.ipv4.ip_local_port_range: the
// number of local ports available for outbound (and connected-UDP) sockets,
// which is the true ceiling on concurrent UDP sessions. It falls back to the
// usual kernel default when the file cannot be read.
func ephemeralPortRange() int {
	b, err := os.ReadFile("/proc/sys/net/ipv4/ip_local_port_range")
	if err != nil {
		return 60999 - 32768 + 1
	}
	f := strings.Fields(string(b))
	if len(f) != 2 {
		return 60999 - 32768 + 1
	}
	lo, err1 := strconv.Atoi(f[0])
	hi, err2 := strconv.Atoi(f[1])
	if err1 != nil || err2 != nil || hi <= lo {
		return 60999 - 32768 + 1
	}
	return hi - lo + 1
}

// nofileLimit returns the current soft RLIMIT_NOFILE (Go raises it to the
// hard limit at startup on Linux).
func nofileLimit() uint64 {
	var rl syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rl); err != nil {
		return 1024
	}
	return rl.Cur
}
