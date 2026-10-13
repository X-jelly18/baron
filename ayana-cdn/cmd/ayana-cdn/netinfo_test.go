package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeSys(t *testing.T, root, rel, val string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(val+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestNetTuning(t *testing.T) {
	ok := t.TempDir()
	writeSys(t, ok, "proc/sys/net/ipv4/tcp_congestion_control", "bbr")
	writeSys(t, ok, "proc/sys/net/core/default_qdisc", "fq")
	writeSys(t, ok, "proc/sys/net/ipv4/tcp_available_congestion_control", "reno cubic bbr")
	n := readNetTuning(ok)
	if !n.bbr() || n.qdisc != "fq" || !n.bbrAvailable() || n.advice() != "" {
		t.Fatalf("bbr host: %+v advice=%q", n, n.advice())
	}

	loadable := t.TempDir()
	writeSys(t, loadable, "proc/sys/net/ipv4/tcp_congestion_control", "cubic")
	writeSys(t, loadable, "proc/sys/net/ipv4/tcp_available_congestion_control", "reno cubic bbr")
	if a := readNetTuning(loadable).advice(); !strings.Contains(a, "cubic") || strings.Contains(a, "modprobe") {
		t.Fatalf("cubic with bbr loaded: advice %q", a)
	}

	missing := t.TempDir()
	writeSys(t, missing, "proc/sys/net/ipv4/tcp_congestion_control", "cubic")
	writeSys(t, missing, "proc/sys/net/ipv4/tcp_available_congestion_control", "reno cubic")
	if a := readNetTuning(missing).advice(); !strings.Contains(a, "modprobe tcp_bbr") {
		t.Fatalf("cubic without bbr module: advice %q", a)
	}

	if n := readNetTuning(t.TempDir()); n.congestion != "" || n.advice() != "" {
		t.Fatalf("unreadable settings must stay quiet: %+v", n)
	}
}
