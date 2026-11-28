// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

func now() int64 { return time.Now().UnixMilli() }

// onFatal is run by fatalf before the process exits: the server role sets it to end the product process it started (never an orphan).
var onFatal func()

func fatalf(f string, a ...any) {
	fmt.Fprintf(os.Stderr, "queries: "+f+"\n", a...)
	if onFatal != nil {
		onFatal()
	}
	os.Exit(1)
}

func must(err error, what string) {
	if err != nil {
		fatalf("%s: %v", what, err)
	}
}

// tlsClient trusts the private CA at caPath (the product's own certificate); verification is never disabled.
func tlsClient(caPath string, timeout time.Duration) *http.Client {
	pem, err := os.ReadFile(caPath)
	must(err, "read CA")
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		fatalf("CA %s holds no certificate", caPath)
	}
	return &http.Client{Timeout: timeout, Transport: &http.Transport{
		TLSClientConfig:     &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13},
		MaxIdleConnsPerHost: 256, MaxConnsPerHost: 0, IdleConnTimeout: 90 * time.Second, ForceAttemptHTTP2: false,
	}}
}

func readPlan(path string) Plan {
	raw, err := os.ReadFile(path)
	must(err, "read plan")
	var p Plan
	must(json.Unmarshal(raw, &p), "parse plan")
	return p
}

// gzCSV writes a gzip-compressed CSV file line by line, safe for concurrent writers.
type gzCSV struct {
	mu sync.Mutex
	f  *os.File
	zw *gzip.Writer
	bw *bufio.Writer
}

func newGzCSV(path, header string) *gzCSV {
	f, err := os.Create(path)
	must(err, "create "+path)
	zw := gzip.NewWriter(f)
	w := &gzCSV{f: f, zw: zw, bw: bufio.NewWriterSize(zw, 1<<20)}
	w.bw.WriteString(header + "\n")
	return w
}

func (w *gzCSV) Line(s string) {
	w.mu.Lock()
	w.bw.WriteString(s)
	w.bw.WriteByte('\n')
	w.mu.Unlock()
}

// Flush pushes every line written so far through the buffer and the compressor to the file, so an operator can zcat it mid-run (the
// gzip trailer is missing until Close, which readers tolerate).
func (w *gzCSV) Flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.bw.Flush()
	w.zw.Flush()
}

func (w *gzCSV) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.bw.Flush()
	w.zw.Close()
	w.f.Close()
}

// defaultIface is the interface of the default route (/proc/net/route), "" when there is none.
func defaultIface() string {
	raw, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return ""
	}
	for _, l := range strings.Split(string(raw), "\n")[1:] {
		f := strings.Fields(l)
		if len(f) > 2 && f[1] == "00000000" {
			return f[0]
		}
	}
	return ""
}

// netCounters reads the receive and transmit byte counters of iface from /proc/net/dev.
func netCounters(iface string) (rx, tx uint64, ok bool) {
	raw, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return 0, 0, false
	}
	for _, l := range strings.Split(string(raw), "\n") {
		name, rest, found := strings.Cut(l, ":")
		if !found || strings.TrimSpace(name) != iface {
			continue
		}
		f := strings.Fields(rest)
		if len(f) < 9 {
			return 0, 0, false
		}
		rx, _ = strconv.ParseUint(f[0], 10, 64)
		tx, _ = strconv.ParseUint(f[8], 10, 64)
		return rx, tx, true
	}
	return 0, 0, false
}

// startNetMon appends one line {"t_ms","iface","rx_bytes","tx_bytes"} to path every period until ctx ends: the link use of this host
// (the lab links are rate-limited; the validator turns the counters into Mbit/s).
func startNetMon(ctx context.Context, path string, every time.Duration) {
	iface := defaultIface()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	must(err, "net series file")
	go func() {
		defer f.Close()
		tick := time.NewTicker(every)
		defer tick.Stop()
		for {
			if rx, tx, ok := netCounters(iface); ok {
				fmt.Fprintf(f, "{\"t_ms\":%d,\"iface\":%q,\"rx_bytes\":%d,\"tx_bytes\":%d}\n", now(), iface, rx, tx)
			}
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			}
		}
	}()
}

// percentile is the nearest-rank percentile of a sorted slice (p in (0,1]), with the single-host harness's tolerance for float rounding.
func percentile(sorted []int64, p float64) int64 {
	if len(sorted) == 0 {
		return 0
	}
	rank := int(p*float64(len(sorted)) + 0.999999999)
	rank = min(max(rank, 1), len(sorted))
	return sorted[rank-1]
}
