package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// TestMain lets the test binary act as the ayana-cdn binary, so the restart
// test can run real processes (and the handoff can re-execute "itself").
func TestMain(m *testing.M) {
	if os.Getenv("AYANA_CDN_TEST_MAIN") == "1" {
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// notifySocket imitates systemd's NOTIFY_SOCKET and records messages.
type notifySocket struct {
	path string
	conn *net.UnixConn
	mu   sync.Mutex
	msgs []string
}

func newNotifySocket(t *testing.T) *notifySocket {
	path := filepath.Join(t.TempDir(), "notify.sock")
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	n := &notifySocket{path: path, conn: conn}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buf := make([]byte, 4096)
		for {
			k, err := conn.Read(buf)
			if err != nil {
				return
			}
			n.mu.Lock()
			n.msgs = append(n.msgs, string(buf[:k]))
			n.mu.Unlock()
		}
	}()
	return n
}

func (n *notifySocket) find(prefix string) (string, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, m := range n.msgs {
		if strings.HasPrefix(m, prefix) {
			return m, true
		}
	}
	return "", false
}

type fileLog string

func (f fileLog) String() string { b, _ := os.ReadFile(string(f)); return string(b) }

func freePort(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

func freeUDPPort(t *testing.T) string {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	return pc.LocalAddr().String()
}

// udpEchoServer runs a UDP echo the edge relays to during the restart test.
func udpEchoServer(t *testing.T) string {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 64<<10)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], addr)
		}
	}()
	return pc.LocalAddr().String()
}

// udpProbe sends one datagram through the edge and waits for the echo,
// retrying briefly so a packet lost exactly at the handover does not fail it.
func udpProbe(c *net.UDPConn, msg string) error {
	buf := make([]byte, 1024)
	var lastErr error
	for i := 0; i < 5; i++ {
		if _, err := c.Write([]byte(msg)); err != nil {
			return err
		}
		_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, err := c.Read(buf)
		if err == nil && string(buf[:n]) == msg {
			return nil
		}
		lastErr = err
	}
	return fmt.Errorf("no echo for %q: %v", msg, lastErr)
}

// tunnelOnce opens a tunnel, checks the echo, and closes it.
func tunnelOnce(addr string) error {
	c, err := dialTLS(addr, "cdn.example")
	if err != nil {
		return err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(c, upgradeReq("/echo/")+"probe\n"); err != nil {
		return err
	}
	br := bufio.NewReader(c)
	head, err := readHead(br, 64<<10)
	if err != nil {
		return err
	}
	if code, _ := parseStatusCode(head); code != 101 {
		return fmt.Errorf("status %d", code)
	}
	buf := make([]byte, 6)
	if _, err := io.ReadFull(br, buf); err != nil || string(buf) != "probe\n" {
		return fmt.Errorf("echo %q: %v", buf, err)
	}
	return nil
}

func TestZeroDowntimeRestart(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns processes")
	}
	// Become a child subreaper like systemd, so the new process is reparented
	// to us when the old one exits and we can reap it.
	const prSetChildSubreaper = 36
	if _, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, prSetChildSubreaper, 1, 0); errno != 0 {
		t.Skipf("prctl(PR_SET_CHILD_SUBREAPER): %v", errno)
	}
	dir := t.TempDir()
	cert, key := writeTestCert(t, dir, "cdn.example")
	pub, admin, udpListen := freePort(t), freePort(t), freeUDPPort(t)
	cfgPath, pidFile := filepath.Join(dir, "config.json"), filepath.Join(dir, "pid")
	cfg := &Config{
		Listen: pub, AdminListen: admin, CDNHosts: []string{"cdn.example"},
		TLS:      TLSConfig{Mode: "files", CertFile: cert, KeyFile: key},
		Timeouts: &Timeouts{Drain: Duration(time.Minute), UDPIdle: Duration(time.Minute)},
		Backends: []Backend{wsBackend("echo", startEcho(t, echoOpts{})), udpBackend("game", udpListen, udpEchoServer(t))},
	}
	if err := saveRaw(cfgPath, cfg); err != nil {
		t.Fatal(err)
	}
	notify := newNotifySocket(t)
	// Log to a file, not a pipe: the new process inherits the old one's
	// stdout/stderr, and exec.Cmd.Wait would wait for EOF on a pipe until
	// the new process exited too.
	logFile, err := os.Create(filepath.Join(dir, "edge.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()
	logs := fileLog(logFile.Name())
	a := exec.Command(os.Args[0], "serve", "-config", cfgPath, "-pidfile", pidFile)
	a.Env = append(os.Environ(), "AYANA_CDN_TEST_MAIN=1", "NOTIFY_SOCKET="+notify.path)
	a.Stdout, a.Stderr = logFile, logFile
	if err := a.Start(); err != nil {
		t.Fatal(err)
	}
	aDone := make(chan error, 1)
	go func() { aDone <- a.Wait() }()
	t.Cleanup(func() {
		_ = a.Process.Kill()
		if t.Failed() {
			t.Logf("process log:\n%s", logs.String())
		}
	})
	eventually(t, "READY=1 from the first process", func() bool { _, ok := notify.find("READY=1"); return ok })

	// A long-lived tunnel opened before the restart.
	e := &edge{addr: pub}
	old := e.dial(t)
	io.WriteString(old, upgradeReq("/echo/")) //nolint:errcheck
	oldBR := bufio.NewReader(old)
	if code, _ := readStatus(t, oldBR); code != 101 {
		t.Fatalf("status %d", code)
	}

	// A UDP flow opened before the restart must keep working across it (the
	// session is remade in the new process on the client's next datagram).
	udpAddr, err := net.ResolveUDPAddr("udp", udpListen)
	if err != nil {
		t.Fatal(err)
	}
	udpConn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer udpConn.Close()
	if err := udpProbe(udpConn, "udp-before"); err != nil {
		t.Fatalf("udp before restart: %v", err)
	}

	// Clients connect continuously through everything below.
	var okCount, failCount atomic.Int64
	var firstErr atomic.Pointer[string]
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if err := tunnelOnce(pub); err != nil {
					failCount.Add(1)
					s := err.Error()
					firstErr.CompareAndSwap(nil, &s)
				} else {
					okCount.Add(1)
				}
			}
		}()
	}

	// 1. A restart with a broken config must leave the old process serving.
	bad := *cfg
	bad.Backends = []Backend{{Name: "bad name", Upstream: "x:1"}}
	if err := saveRaw(cfgPath, &bad); err != nil {
		t.Fatal(err)
	}
	if err := a.Process.Signal(syscall.SIGUSR2); err != nil {
		t.Fatal(err)
	}
	eventually(t, "failed restart reported", func() bool {
		return strings.Contains(logs.String(), "restart failed; this process keeps serving")
	})
	if b, _ := os.ReadFile(pidFile); strings.TrimSpace(string(b)) != strconv.Itoa(a.Process.Pid) {
		t.Fatalf("pid file after a failed restart: %q", b)
	}

	// 2. A real restart.
	if err := saveRaw(cfgPath, cfg); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	if err := a.Process.Signal(syscall.SIGUSR2); err != nil {
		t.Fatal(err)
	}
	var newPID int
	eventually(t, "MAINPID handed to systemd", func() bool {
		m, ok := notify.find("MAINPID=")
		if ok {
			newPID, _ = strconv.Atoi(strings.TrimPrefix(m, "MAINPID="))
		}
		return ok
	})
	if newPID <= 0 || newPID == a.Process.Pid {
		t.Fatalf("new main pid %d (old %d)", newPID, a.Process.Pid)
	}
	eventually(t, "pid file names the new process", func() bool {
		b, _ := os.ReadFile(pidFile)
		return strings.TrimSpace(string(b)) == strconv.Itoa(newPID)
	})
	eventually(t, "admin endpoint served by the new process", func() bool {
		d, _, err := fetchStatus(admin)
		return err == nil && d.PID == newPID
	})
	time.Sleep(300 * time.Millisecond) // keep clients connecting across the switch

	// The UDP flow is served by the new process now.
	if err := udpProbe(udpConn, "udp-after"); err != nil {
		t.Fatalf("udp after restart: %v", err)
	}

	// 3. The tunnel from before the restart still works (old process, draining).
	io.WriteString(old, "still alive\n") //nolint:errcheck
	if got := readN(t, oldBR, 12); got != "still alive\n" {
		t.Fatalf("pre-restart tunnel: %q", got)
	}
	select {
	case err := <-aDone:
		t.Fatalf("old process exited while it still had a tunnel: %v", err)
	default:
	}

	// 4. Closing that tunnel lets the old process finish draining and exit cleanly.
	old.Close()
	select {
	case err := <-aDone:
		if err != nil {
			t.Fatalf("old process exit: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("old process did not exit after its last tunnel closed")
	}

	close(stop)
	wg.Wait()
	if n := failCount.Load(); n != 0 {
		t.Fatalf("%d of %d client connections failed during the restarts; first error: %s", n, n+okCount.Load(), *firstErr.Load())
	}
	if okCount.Load() < 50 {
		t.Fatalf("only %d connections made; the test did not exercise the restart", okCount.Load())
	}
	t.Logf("%d tunnels opened across a failed and a successful restart, 0 failures", okCount.Load())

	// 5. Stop the new process (we are its subreaper now).
	if err := syscall.Kill(newPID, syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	var ws syscall.WaitStatus
	done := make(chan error, 1)
	go func() { _, err := syscall.Wait4(newPID, &ws, 0, nil); done <- err }()
	select {
	case err := <-done:
		if err != nil || ws.ExitStatus() != 0 {
			t.Fatalf("new process exit: err=%v status=%d", err, ws.ExitStatus())
		}
	case <-time.After(10 * time.Second):
		_ = syscall.Kill(newPID, syscall.SIGKILL)
		t.Fatal("new process did not stop")
	}
	if _, ok := notify.find("STOPPING=1"); !ok {
		t.Error("no STOPPING=1 notification")
	}
	if _, err := os.Stat(pidFile); !os.IsNotExist(err) {
		t.Errorf("pid file left behind: %v", err)
	}
}
