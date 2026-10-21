package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// netTuning is the kernel's TCP congestion control and default qdisc — the two
// settings that matter most for tunnel throughput to clients on lossy mobile
// links. The installer asks for BBR + fq (deploy/sysctl-99-ayana-cdn.conf), but
// on some hosts (containers, images that reset sysctl at boot) that never takes
// effect, silently leaving the default (usually cubic). This reads what is
// actually in force so the panel and `ayana-cdn check` can say so.
type netTuning struct {
	congestion string   // net.ipv4.tcp_congestion_control
	qdisc      string   // net.core.default_qdisc
	available  []string // net.ipv4.tcp_available_congestion_control (loaded algorithms)
}

// readNetTuning reads the settings under root ("/" in production; a temp dir
// in tests). Unreadable files leave the field empty.
func readNetTuning(root string) netTuning {
	rd := func(p string) string {
		b, err := os.ReadFile(filepath.Join(root, p))
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(b))
	}
	return netTuning{
		congestion: rd("proc/sys/net/ipv4/tcp_congestion_control"),
		qdisc:      rd("proc/sys/net/core/default_qdisc"),
		available:  strings.Fields(rd("proc/sys/net/ipv4/tcp_available_congestion_control")),
	}
}

func (n netTuning) bbr() bool          { return n.congestion == "bbr" }
func (n netTuning) bbrAvailable() bool { return slices.Contains(n.available, "bbr") }

// advice is a one-line fix when BBR is not in force, or "" when it is (or the
// settings could not be read at all).
func (n netTuning) advice() string {
	if n.congestion == "" || n.bbr() {
		return ""
	}
	if !n.bbrAvailable() {
		return "TCP congestion control is " + n.congestion + ", not bbr, and the bbr module is not loaded: " +
			"run `modprobe tcp_bbr && sysctl -w net.ipv4.tcp_congestion_control=bbr net.core.default_qdisc=fq` " +
			"(or re-run the installer); on a container VPS the host may not allow it"
	}
	return "TCP congestion control is " + n.congestion + ", not bbr: run " +
		"`sysctl -w net.ipv4.tcp_congestion_control=bbr net.core.default_qdisc=fq` (or re-run the installer)"
}
