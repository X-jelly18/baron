package main

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// BenchmarkPipeThroughput measures the throughput of the relay copy loop over real loopback TCP (so syscall cost is
// real, not an in-memory net.Pipe). Measures pipe(dst,src): src is fed a large
// stream as fast as possible; dst discards. Reported as MB/s.
func benchPipeThroughput(b *testing.B) {
	// src side: pipe reads from srcRead; a writer floods srcWrite.
	srcWrite, srcRead := tcpPair(b)
	// dst side: pipe writes to dstWrite; a reader drains dstRead.
	dstWrite, dstRead := tcpPair(b)

	var stop atomic.Bool
	var wg sync.WaitGroup
	wg.Add(2)
	chunk := make([]byte, 256<<10)
	go func() {
		defer wg.Done()
		for !stop.Load() {
			if _, err := srcWrite.Write(chunk); err != nil {
				return
			}
		}
	}()
	go func() { defer wg.Done(); _, _ = io.Copy(io.Discard, dstRead) }()

	t := &tunnel{cconn: srcRead, sconn: dstWrite}
	var ctr atomic.Uint64

	b.ResetTimer()
	done := make(chan struct{})
	go func() { t.pipe(dstWrite, srcRead, &ctr, false); close(done) }()
	time.Sleep(2 * time.Second)
	b.StopTimer()

	moved := ctr.Load()
	stop.Store(true)
	_ = srcWrite.Close()
	_ = srcRead.Close()
	_ = dstWrite.Close()
	_ = dstRead.Close()
	<-done
	wg.Wait()
	mbps := float64(moved) / (1024 * 1024) / 2.0
	b.ReportMetric(mbps, "MB/s")
}

func BenchmarkPipeThroughput(b *testing.B) { benchPipeThroughput(b) }

func tcpPair(b *testing.B) (client, server net.Conn) {
	b.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer ln.Close()
	ch := make(chan net.Conn, 1)
	go func() { c, _ := ln.Accept(); ch <- c }()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		b.Fatal(err)
	}
	s := <-ch
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetWriteBuffer(1 << 20)
		_ = tc.SetReadBuffer(1 << 20)
	}
	return c, s
}
