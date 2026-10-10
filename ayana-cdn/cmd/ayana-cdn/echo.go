package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"time"
)

// echoOpts describes how the test backend behaves.
type echoOpts struct {
	noUpgradeHeader bool   // answer "101" without Upgrade/Connection headers (Python-proxy style)
	banner          string // sent right after the response head, in the same write
	status          int    // status for tunnel requests: 101, or 200 for "200 then raw" backends
	raw             bool   // treat every request as a tunnel
	logf            func(format string, args ...any)
}

func cmdEchoBackend(args []string) error {
	fs := flag.NewFlagSet("echo-backend", flag.ContinueOnError)
	listen := fs.String("listen", "127.0.0.1:9000", "listen address")
	noUp := fs.Bool("no-upgrade-header", false, "answer 101 without Upgrade/Connection headers, like many Python tunnel proxies")
	banner := fs.String("banner", "", "line sent right after the 101, e.g. SSH-2.0-test")
	status := fs.Int("status", 101, "status for tunnel requests (101, or 200 for 200-then-raw backends)")
	raw := fs.Bool("raw", false, "treat every request as a tunnel, even without an Upgrade header")
	cert := fs.String("tls-cert", "", "serve TLS with this certificate (full chain)")
	key := fs.String("tls-key", "", "private key for -tls-cert")
	udp := fs.String("udp", "", "also echo UDP datagrams on this address, e.g. 127.0.0.1:9001 (for udp backends)")
	quiet := fs.Bool("quiet", false, "do not log each connection")
	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	if *udp != "" {
		pc, err := net.ListenPacket("udp", *udp)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "udp echo on %s: every datagram is sent back to its sender\n", pc.LocalAddr())
		go serveEchoUDP(pc) //nolint:errcheck
	}
	scheme := "ws"
	if *cert != "" {
		c, err := tls.LoadX509KeyPair(*cert, *key)
		if err != nil {
			return err
		}
		ln = tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{c}, NextProtos: []string{"http/1.1"}})
		scheme = "wss"
	}
	o := echoOpts{noUpgradeHeader: *noUp, banner: *banner, status: *status, raw: *raw}
	if !*quiet {
		o.logf = log.New(os.Stderr, "", log.Ltime).Printf
	}
	fmt.Fprintf(os.Stderr, "echo backend on %s (%s): tunnel requests get %d and an echo, plain requests get 200 \"ok\"\n",
		ln.Addr(), scheme, *status)
	return serveEcho(ln, o)
}

// serveEchoUDP sends every datagram back to its sender, so a udp backend can
// be tested end to end through the edge.
func serveEchoUDP(pc net.PacketConn) error {
	buf := make([]byte, 64<<10)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return err
		}
		if _, err := pc.WriteTo(buf[:n], addr); err != nil {
			return err
		}
	}
}

func serveEcho(ln net.Listener, o echoOpts) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go handleEcho(c, o)
	}
}

func handleEcho(c net.Conn, o echoOpts) {
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(30 * time.Second))
	br := bufio.NewReaderSize(c, 4096)
	head, err := readHead(br, 64<<10)
	if err != nil {
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	line, _, _ := bytes.Cut(head, []byte("\n"))
	line = bytes.TrimSpace(line)
	if !o.raw && !bytes.Contains(bytes.ToLower(head), []byte("\nupgrade:")) {
		_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 3\r\nConnection: close\r\n\r\nok\n")
		if o.logf != nil {
			o.logf("%s plain %q", c.RemoteAddr(), line)
		}
		return
	}
	var resp bytes.Buffer
	fmt.Fprintf(&resp, "HTTP/1.1 %d %s\r\n", o.status, http.StatusText(o.status))
	if o.status == http.StatusSwitchingProtocols && !o.noUpgradeHeader {
		resp.WriteString("Upgrade: websocket\r\nConnection: Upgrade\r\n")
	}
	resp.WriteString("\r\n")
	if o.banner != "" {
		resp.WriteString(o.banner + "\r\n")
	}
	if n := br.Buffered(); n > 0 { // early data that arrived with the request head
		b, _ := br.Peek(n)
		resp.Write(b)
		_, _ = br.Discard(n)
	}
	if _, err := c.Write(resp.Bytes()); err != nil {
		return
	}
	start := time.Now()
	var total int64
	buf := make([]byte, 32<<10)
	for {
		n, err := br.Read(buf)
		if n > 0 {
			if _, werr := c.Write(buf[:n]); werr != nil {
				break
			}
			total += int64(n)
		}
		if err != nil {
			break
		}
	}
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite() // pass the client's half-close back
	}
	if o.logf != nil {
		o.logf("%s tunnel %q: echoed %d bytes in %s", c.RemoteAddr(), line, total, time.Since(start).Round(time.Millisecond))
	}
}
