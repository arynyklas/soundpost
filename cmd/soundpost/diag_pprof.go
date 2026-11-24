// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

//go:build soundpost_diag

package main

import (
	"encoding/json"
	"net/http"
	_ "net/http/pprof" // registers the profile handlers on the default mux
	"os"
	"runtime"
	"time"

	"github.com/arynyklas/soundpost/internal/diagstat"
)

// A diagnostic build (-tags soundpost_diag) serves the Go profiles (CPU, heap, goroutine and, with SOUNDPOST_DIAG_BLOCK set, block and
// mutex) on the loopback address SOUNDPOST_DIAG_PPROF names, and the counters of the components that registered
// with internal/diagstat, with the runtime's heap and GC figures, at /debug/soundpost. The shipped
// binaries are built without the tag and carry none of this: the overhead and capacity investigations
// build with it to take live profiles and per-window counters.
func init() {
	addr := os.Getenv("SOUNDPOST_DIAG_PPROF")
	if addr == "" {
		return
	}
	if os.Getenv("SOUNDPOST_DIAG_BLOCK") != "" { // the block and mutex profiles cost the requests a few percent: only when asked for
		runtime.SetBlockProfileRate(10_000) // one blocking event per 10 µs of blocked time on average
		runtime.SetMutexProfileFraction(5)
	}
	http.HandleFunc("/debug/soundpost", func(w http.ResponseWriter, _ *http.Request) {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		pauses := make([]uint64, 0, 8)
		for i := uint32(0); i < 8 && i < m.NumGC; i++ { // the newest eight pauses, newest first
			pauses = append(pauses, m.PauseNs[(m.NumGC+255-i)%256])
		}
		out := diagstat.Snapshot()
		out["at_unix_ns"] = time.Now().UnixNano()
		out["runtime"] = map[string]any{
			"heap_alloc": m.HeapAlloc, "heap_inuse": m.HeapInuse, "heap_sys": m.HeapSys, "heap_objects": m.HeapObjects,
			"next_gc": m.NextGC, "num_gc": m.NumGC, "pause_total_ns": m.PauseTotalNs, "newest_pauses_ns": pauses,
			"gc_cpu_fraction": m.GCCPUFraction, "goroutines": runtime.NumGoroutine(), "total_alloc": m.TotalAlloc, "mallocs": m.Mallocs,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
	go func() { _ = http.ListenAndServe(addr, nil) }()
}
