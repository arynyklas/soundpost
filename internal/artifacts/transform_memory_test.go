// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package artifacts

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"io"
	"runtime"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func memMap(total int) []byte {
	unit, _ := json.Marshal("function f(a, b) {\n\treturn a < b && \"x\" > '<y>' ? a : b; // \u00e9\u4e16\n}\n")
	piece := unit[1 : len(unit)-1]
	head := `{"version":3,"file":"app.js","sources":["src/app.ts"],"names":["a","b"],"mappings":"AAAA,CAAC","sourcesContent":["`
	tail := `"]}`
	n := (total - len(head) - len(tail)) / len(piece)
	return []byte(head + strings.Repeat(string(piece), n) + tail)
}

// peakOf runs fn and returns the cumulative allocation and the peak live heap
// above the starting heap. A tight GC percent makes HeapAlloc track live data.
func peakOf(fn func()) (total, peak uint64) {
	defer debug.SetGCPercent(debug.SetGCPercent(5))
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	var hi atomic.Uint64
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		var ms runtime.MemStats
		for {
			runtime.ReadMemStats(&ms)
			if ms.HeapAlloc > hi.Load() {
				hi.Store(ms.HeapAlloc)
			}
			select {
			case <-stop:
				return
			case <-time.After(time.Millisecond):
			}
		}
	}()
	fn()
	close(stop)
	<-done
	runtime.ReadMemStats(&after)
	if hi.Load() < before.HeapAlloc {
		return after.TotalAlloc - before.TotalAlloc, 0
	}
	return after.TotalAlloc - before.TotalAlloc, hi.Load() - before.HeapAlloc
}

// TestUploadFrontEndMemory measures what Put itself does with a body: buffer
// it (hashing), then decode and split it. The storage/replica layer that
// receives the outputs afterwards is deliberately outside this measurement.
// The caller owns the input slice, so it is not part of the delta; the stage's
// own copies are.
func TestUploadFrontEndMemory(t *testing.T) {
	raw := memMap(16 << 20)
	in := uint64(len(raw))
	var pub, priv []byte
	var err error
	total, peak := peakOf(func() {
		// Same buffering Put performs before transformMap.
		buf := bytes.NewBuffer(make([]byte, 0, len(raw)+1))
		h := sha256.New()
		if _, err = io.Copy(io.MultiWriter(buf, h), bytes.NewReader(raw)); err != nil {
			return
		}
		b := buf.Bytes()
		buf = nil
		pub, priv, err = transformMap(b, true)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("FRONTEND-MEM input=%d total_alloc=%d (%.1fx) peak_live=%d (%.1fx) public=%d private=%d", in, total, float64(total)/float64(in), peak, float64(peak)/float64(in), len(pub), len(priv))
	// Peak live heap is sampled and GC-timing dependent, so it is reported
	// above, not asserted. Cumulative allocation is deterministic.
	if !raceEnabled && total > 12*in {
		t.Fatalf("cumulative allocation %.2fx input exceeds 12x", float64(total)/float64(in))
	}
}
