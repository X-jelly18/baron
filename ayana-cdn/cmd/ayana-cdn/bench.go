package main

import (
	"bufio"
	crand "crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"text/tabwriter"
	"time"
)

type benchResult struct {
	tcp, tls, upgrade  time.Duration
	rtts               []time.Duration
	bulkStart, bulkEnd time.Time
	bulkBytes          int64
	err                string
}

func cmdBench(args []string) error {
	fs := flag.NewFlagSet("bench", flag.ContinueOnError)
	target := fs.String("url", "", "tunnel URL: wss://host/path (also ws://, https://, http://)")
	connect := fs.String("connect", "", "dial this host:port instead of the URL's (Host header and SNI still come from the URL)")
	sni := fs.String("sni", "", `TLS SNI to send instead of the URL host ("-" sends none)`)
	conns := fs.Int("c", 100, "number of tunnels to open")
	rate := fs.Float64("rate", 100, "new tunnels per second (0 = all at once)")
	hold := fs.Duration("hold", 10*time.Second, "keep each tunnel open this long")
	ping := fs.Duration("ping", 0, "send a line this often and time the echo (needs an echo backend)")
	early := fs.String("early", "", "bytes to send right after the request, without waiting for the 101 (\\r\\n escapes allowed)")
	insecure := fs.Bool("insecure", true, "do not verify the edge's certificate")
	timeout := fs.Duration("timeout", 10*time.Second, "setup timeout per tunnel")
	expect := fs.Int("expect", 101, "status that counts as success")
	bulk := fs.String("bulk", "", "push this much data through each tunnel and read it back, e.g. 256MiB (needs an echo backend)")
	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}
	if *target == "" {
		return errors.New("bench needs -url, e.g. -url wss://cdn.example.com/native1/")
	}
	u, err := url.Parse(*target)
	if err != nil {
		return fmt.Errorf("bad -url: %w", err)
	}
	useTLS := u.Scheme == "wss" || u.Scheme == "https"
	if !useTLS && u.Scheme != "ws" && u.Scheme != "http" {
		return errors.New("-url scheme must be wss, ws, https or http")
	}
	addr := u.Host
	if u.Port() == "" {
		port := "80"
		if useTLS {
			port = "443"
		}
		addr = net.JoinHostPort(u.Hostname(), port)
	}
	if *connect != "" {
		addr = *connect
	}
	serverName := u.Hostname()
	switch *sni {
	case "":
	case "-":
		serverName = ""
	default:
		serverName = *sni
	}
	bulkBytes, err := parseSize(*bulk)
	if err != nil {
		return fmt.Errorf("bad -bulk: %w", err)
	}
	path := u.RequestURI()
	earlyData := strings.NewReplacer(`\r`, "\r", `\n`, "\n").Replace(*early)

	var (
		mu       sync.Mutex
		results  []benchResult
		wg       sync.WaitGroup
		open     atomic.Int64
		peak     atomic.Int64
		interval time.Duration
	)
	if *rate > 0 {
		interval = time.Duration(float64(time.Second) / *rate)
	}
	fmt.Printf("bench %s via %s: %d tunnels, %.0f/s, hold %s\n", *target, addr, *conns, *rate, *hold)
	start := time.Now()
	for i := 0; i < *conns; i++ {
		if interval > 0 {
			time.Sleep(time.Until(start.Add(time.Duration(i) * interval)))
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := benchOne(benchSpec{
				addr: addr, useTLS: useTLS, serverName: serverName, insecure: *insecure, host: u.Host,
				path: path, early: earlyData, timeout: *timeout, hold: *hold, ping: *ping, expect: *expect,
				bulk: bulkBytes,
			}, &open, &peak)
			mu.Lock()
			results = append(results, r)
			mu.Unlock()
		}()
	}
	wg.Wait()
	printBench(os.Stdout, results, peak.Load(), time.Since(start))
	for _, r := range results {
		if r.err != "" {
			return errors.New("some tunnels failed")
		}
	}
	return nil
}

type benchSpec struct {
	addr, serverName, host, path, early string
	useTLS, insecure                    bool
	timeout, hold, ping                 time.Duration
	expect                              int
	bulk                                int64
}

func benchOne(sp benchSpec, open, peak *atomic.Int64) (r benchResult) {
	t0 := time.Now()
	c, err := net.DialTimeout("tcp", sp.addr, sp.timeout)
	if err != nil {
		r.err = "connect: " + errString(err)
		return r
	}
	defer c.Close()
	r.tcp = time.Since(t0)
	_ = c.SetDeadline(time.Now().Add(sp.timeout))
	conn := c
	if sp.useTLS {
		t1 := time.Now()
		tc := tls.Client(c, &tls.Config{ServerName: sp.serverName, InsecureSkipVerify: sp.insecure, //nolint:gosec // test tool
			NextProtos: []string{"http/1.1"}})
		if err := tc.Handshake(); err != nil {
			r.err = "tls: " + errString(err)
			return r
		}
		r.tls = time.Since(t1)
		conn = tc
	}
	key := make([]byte, 16)
	_, _ = crand.Read(key)
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\nUser-Agent: ayana-cdn-bench/%s\r\n\r\n",
		sp.path, sp.host, base64.StdEncoding.EncodeToString(key), version)
	t2 := time.Now()
	if _, err := io.WriteString(conn, req+sp.early); err != nil {
		r.err = "write: " + errString(err)
		return r
	}
	br := bufio.NewReaderSize(conn, 4096)
	head, err := readHead(br, 64<<10)
	if err != nil {
		r.err = "response: " + errString(err)
		return r
	}
	code, err := parseStatusCode(head)
	if err != nil || code != sp.expect {
		r.err = fmt.Sprintf("status %d", code)
		return r
	}
	r.upgrade = time.Since(t2)
	_ = conn.SetDeadline(time.Time{})
	n := open.Add(1)
	defer open.Add(-1)
	for p := peak.Load(); n > p && !peak.CompareAndSwap(p, n); p = peak.Load() {
	}
	if sp.bulk > 0 {
		return benchBulk(conn, br, sp.bulk, r)
	}
	if sp.ping <= 0 {
		time.Sleep(sp.hold)
		return r
	}
	end := time.Now().Add(sp.hold)
	for seq := 0; time.Now().Before(end); seq++ {
		msg := fmt.Sprintf("ping %d\n", seq)
		ts := time.Now()
		_ = conn.SetDeadline(ts.Add(sp.timeout))
		if _, err := io.WriteString(conn, msg); err != nil {
			r.err = "ping write: " + errString(err)
			return r
		}
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				r.err = "ping read: " + errString(err)
				return r
			}
			if strings.HasSuffix(line, msg) { // echoed early data may precede the first ping
				break
			}
		}
		r.rtts = append(r.rtts, time.Since(ts))
		time.Sleep(time.Until(ts.Add(sp.ping)))
	}
	return r
}

// benchBulk writes n bytes into the tunnel while reading n bytes back.
func benchBulk(conn net.Conn, br *bufio.Reader, n int64, r benchResult) benchResult {
	_ = conn.SetDeadline(time.Now().Add(30 * time.Minute))
	r.bulkStart = time.Now()
	werr := make(chan error, 1)
	go func() {
		chunk := make([]byte, 64<<10)
		for i := range chunk {
			chunk[i] = byte(i*7 + 13)
		}
		for left := n; left > 0; {
			k := min(int64(len(chunk)), left)
			if _, err := conn.Write(chunk[:k]); err != nil {
				werr <- err
				return
			}
			left -= k
		}
		werr <- nil
	}()
	if _, err := io.CopyN(io.Discard, br, n); err != nil {
		r.err = "bulk read: " + errString(err)
		return r
	}
	if err := <-werr; err != nil {
		r.err = "bulk write: " + errString(err)
		return r
	}
	r.bulkEnd, r.bulkBytes = time.Now(), n
	return r
}

// parseSize reads sizes like 512, 64KiB, 256MiB, 1GiB (also KB/MB/GB as powers of 1024).
func parseSize(v string) (int64, error) {
	if v == "" {
		return 0, nil
	}
	num := strings.TrimRight(v, "KMGiBkmgb")
	mult := int64(1)
	switch strings.ToUpper(strings.TrimSuffix(strings.TrimSuffix(v[len(num):], "B"), "b")) {
	case "":
	case "K", "KI":
		mult = 1 << 10
	case "M", "MI":
		mult = 1 << 20
	case "G", "GI":
		mult = 1 << 30
	default:
		return 0, fmt.Errorf("unknown unit in %q", v)
	}
	n, err := strconv.ParseInt(num, 10, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("%q is not a size", v)
	}
	return n * mult, nil
}

func pct(d []time.Duration, q float64) time.Duration {
	if len(d) == 0 {
		return 0
	}
	return d[int(q*float64(len(d)-1))]
}

func printBench(out io.Writer, results []benchResult, peak int64, elapsed time.Duration) {
	var tcp, tlsD, up, rtt []time.Duration
	errs := map[string]int{}
	ok := 0
	for _, r := range results {
		if r.err != "" {
			errs[r.err]++
			continue
		}
		ok++
		tcp = append(tcp, r.tcp)
		up = append(up, r.upgrade)
		if r.tls > 0 {
			tlsD = append(tlsD, r.tls)
		}
		rtt = append(rtt, r.rtts...)
	}
	fmt.Fprintf(out, "  succeeded %d/%d, peak open %d, elapsed %s\n", ok, len(results), peak, elapsed.Round(time.Millisecond))
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "  phase\tp50\tp90\tp99\tmax\t")
	for _, row := range []struct {
		name string
		d    []time.Duration
	}{{"tcp connect", tcp}, {"tls handshake", tlsD}, {"upgrade (to 101)", up}, {"echo rtt", rtt}} {
		if len(row.d) == 0 {
			continue
		}
		sort.Slice(row.d, func(i, j int) bool { return row.d[i] < row.d[j] })
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\t\n", row.name, fmtDur(pct(row.d, .5)), fmtDur(pct(row.d, .9)),
			fmtDur(pct(row.d, .99)), fmtDur(row.d[len(row.d)-1]))
	}
	tw.Flush()
	var first, last time.Time
	var total int64
	var rates []float64
	for _, r := range results {
		if r.err != "" || r.bulkBytes == 0 {
			continue
		}
		if first.IsZero() || r.bulkStart.Before(first) {
			first = r.bulkStart
		}
		if r.bulkEnd.After(last) {
			last = r.bulkEnd
		}
		total += r.bulkBytes
		rates = append(rates, float64(r.bulkBytes)/r.bulkEnd.Sub(r.bulkStart).Seconds()/(1<<20))
	}
	if len(rates) > 0 {
		sort.Float64s(rates)
		fmt.Fprintf(out, "  bulk: %s each way per tunnel; per tunnel %.0f MiB/s (min %.0f, max %.0f); all tunnels %.0f MiB/s each way\n",
			humanBytes(uint64(total/int64(len(rates)))), rates[len(rates)/2], rates[0], rates[len(rates)-1],
			float64(total)/last.Sub(first).Seconds()/(1<<20))
	}
	if len(errs) > 0 {
		type kv struct {
			k string
			v int
		}
		var list []kv
		for k, v := range errs {
			list = append(list, kv{k, v})
		}
		sort.Slice(list, func(i, j int) bool { return list[i].v > list[j].v })
		fmt.Fprintln(out, "  failures:")
		for i, e := range list {
			if i == 8 {
				fmt.Fprintf(out, "    ... %d more kinds\n", len(list)-8)
				break
			}
			fmt.Fprintf(out, "    %6d  %s\n", e.v, e.k)
		}
	}
}

func fmtDur(d time.Duration) string {
	switch {
	case d < time.Millisecond:
		return fmt.Sprintf("%.2fms", float64(d)/float64(time.Millisecond))
	case d < time.Second:
		return fmt.Sprintf("%.1fms", float64(d)/float64(time.Millisecond))
	}
	return d.Round(time.Millisecond).String()
}
