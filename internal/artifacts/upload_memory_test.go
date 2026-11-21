// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package artifacts_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"io"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// bigSourceMap builds a v3 map of roughly total bytes whose bulk is
// sourcesContent (newlines, quotes, HTML-sensitive runes), like a real bundler.
func bigSourceMap(total int) []byte {
	unit, _ := json.Marshal("function f(a, b) {\n\treturn a < b && \"x\" > '<y>' ? a : b; // \u00e9\u4e16\n}\n")
	piece := unit[1 : len(unit)-1]
	head := `{"version":3,"file":"app.js","sources":["src/app.ts"],"names":["a","b"],"mappings":"AAAA,CAAC","sourcesContent":["`
	tail := `"]}`
	n := (total - len(head) - len(tail)) / len(piece)
	return []byte(head + strings.Repeat(string(piece), n) + tail)
}

func sha(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

// TestUploadMemoryIsBoundedByInput is the I-2 reproduction: one 16 MiB upload
// with sourcesContent must not hold many multiples of its size.
func TestUploadMemoryIsBoundedByInput(t *testing.T) {
	f := newArtifactFixture(t)
	raw := bigSourceMap(16 << 20)
	m := f.manifest(raw)
	m.SourceContent = true
	scope := f.scope(t, auth.Permission("artifacts.write"))
	// A tight GC percent makes HeapAlloc track live data instead of the
	// default 2x pacing headroom, so the sampled peak is retained heap.
	defer debug.SetGCPercent(debug.SetGCPercent(5))
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	var peak atomic.Uint64
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		var ms runtime.MemStats
		for {
			runtime.ReadMemStats(&ms)
			if ms.HeapAlloc > peak.Load() {
				peak.Store(ms.HeapAlloc)
			}
			select {
			case <-stop:
				return
			case <-time.After(2 * time.Millisecond):
			}
		}
	}()
	if _, err := f.app.Artifacts.Put(context.Background(), scope, m, bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	close(stop)
	<-done
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	total := after.TotalAlloc - before.TotalAlloc
	peakDelta := peak.Load() - before.HeapAlloc
	in := uint64(len(raw))
	t.Logf("UPLOAD-MEM input=%d total_alloc=%d (%.1fx) peak_heap_delta=%d (%.1fx)", in, total, float64(total)/float64(in), peakDelta, float64(peakDelta)/float64(in))
	// Regression guard only: the end-to-end peak and cumulative allocation are
	// dominated by the storage/replica layer that receives the fragments (see
	// docs/artifacts and TestUploadFrontEndMemory for what Put itself does), so
	// the cumulative figure is reported, not asserted.
	if peakDelta > 6*in {
		t.Fatalf("peak heap %.1fx input exceeds 6x", float64(peakDelta)/float64(in))
	}
}

// slowReader blocks its first Read until released, so a Put stays in flight.
type slowReader struct {
	r       io.Reader
	entered *atomic.Int32
	gate    <-chan struct{}
	once    sync.Once
}

func (s *slowReader) Read(p []byte) (int, error) {
	s.once.Do(func() { s.entered.Add(1); <-s.gate })
	return s.r.Read(p)
}

// TestUploadsInFlightBytesAreBounded: N parallel max-size uploads must not all
// be admitted; the excess is refused with a retryable quota fault.
func TestUploadsInFlightBytesAreBounded(t *testing.T) {
	f := newArtifactFixture(t)
	const n = 8
	raw := bigSourceMap(model.ArtifactBundleLimit - 1024)
	var entered atomic.Int32
	gate := make(chan struct{})
	errs := make(chan error, n)
	var wg sync.WaitGroup
	for i := range n {
		m := f.manifest(raw)
		m.DebugID = fmt.Sprintf("debug-%d", i)
		scope := f.scope(t, auth.Permission("artifacts.write"))
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := f.app.Artifacts.Put(context.Background(), scope, m, &slowReader{r: bytes.NewReader(raw), entered: &entered, gate: gate})
			errs <- err
		}()
	}
	time.Sleep(1500 * time.Millisecond)
	admitted := int64(entered.Load())
	inflight := admitted * int64(len(raw))
	close(gate)
	wg.Wait()
	close(errs)
	if inflight > 128<<20 {
		t.Fatalf("%d concurrent uploads admitted = %d in-flight declared bytes (> 128 MiB)", admitted, inflight)
	}
	refused := 0
	for err := range errs {
		var fault *model.Fault
		if errors.As(err, &fault) && fault.Code == model.Quota {
			if !fault.Retryable {
				t.Fatal("quota refusal must be retryable")
			}
			refused++
		}
	}
	if refused == 0 {
		t.Fatal("no upload was refused")
	}
}

// failReader fails the test if the body is touched.
type failReader struct{ t *testing.T }

func (r failReader) Read([]byte) (int, error) {
	r.t.Helper()
	r.t.Error("body read although declared size exceeds policy MaxBytes")
	return 0, io.EOF
}

// TestUploadRejectsOverPolicyMaxBytesBeforeBuffering: the policy MaxBytes the
// path already fetches must be consulted before any byte is read.
func TestUploadRejectsOverPolicyMaxBytesBeforeBuffering(t *testing.T) {
	f := newArtifactFixture(t)
	ctx := context.Background()
	raw := bigSourceMap(4096)
	m := f.manifest(raw)
	if err := f.app.Control.Update(ctx, func(st *model.ControlState) error {
		s := st.Sources[f.source.String()]
		s.Policy.MaxBytes = model.Uint64(1024)
		st.Sources[f.source.String()] = s
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	_, err := f.app.Artifacts.Put(ctx, f.scope(t, auth.Permission("artifacts.write")), m, failReader{t})
	var fault *model.Fault
	if !errors.As(err, &fault) || fault.Code != model.TooLarge {
		t.Fatalf("want TooLarge, got %v", err)
	}
}

// TestUploadOutputGolden pins public/private bytes for a fixed input; the
// digests were captured from the pre-change implementation.
func TestUploadOutputGolden(t *testing.T) {
	f := newArtifactFixture(t)
	ctx := context.Background()
	raw := []byte(`{"version":3,"file":"x.js","x_google_ignoreList":[0],"sourceRoot":"r/","sources":["a.ts","b<&>.ts"],"names":["n\u00e9","\u4e16"],"mappings":"AAAA;AACA,CAAC","sourcesContent":["line1\n<b>&\"q\"\u2028 \u00e9","\u0000 null next"],"x_secret":{"sourcesContent":["leak"]}}`)
	raw = append(raw[:len(raw):len(raw)], '\n')
	m := f.manifest(raw)
	m.SourceContent = true
	got, err := f.app.Artifacts.Put(ctx, f.scope(t, auth.Permission("artifacts.write")), m, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	read := f.scope(t, auth.Permission("artifacts.read"))
	pr, err := f.app.Artifacts.Get(ctx, read, got.ID)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := io.ReadAll(pr)
	pr.Close()
	sr, err := f.app.Artifacts.GetSources(ctx, read, got.ID)
	if err != nil {
		t.Fatal(err)
	}
	priv, _ := io.ReadAll(sr)
	sr.Close()
	t.Logf("GOLDEN public=%s private=%s\npub=%s\npriv=%s", sha(pub), sha(priv), pub, priv)
	if sha(pub) != goldenPublic || sha(priv) != goldenPrivate {
		t.Fatalf("output bytes changed: public=%s private=%s", sha(pub), sha(priv))
	}
	if got.Map.Hash != model.HashCanonical(pub) {
		t.Fatal("receipt hash not over public bytes")
	}
}

const goldenPublic, goldenPrivate = "3aac7c9a935867b77b6059b51a161b2c220ad2a670263e1c80e227c301cb3e7c", "424805e3bd46f6e6f8f768cd6607a0e3eb6012c4a3bb38b84a8e33e222ff875e"

// TestUploadOutputGoldenSections pins the sectioned (index map) split.
func TestUploadOutputGoldenSections(t *testing.T) {
	f := newArtifactFixture(t)
	ctx := context.Background()
	raw := []byte(`{"version":3,"sections":[{"offset":{"line":0,"column":0},"map":{"version":3,"sources":["a.ts"],"names":[],"mappings":"AAAA","sourcesContent":["<A>"],"x_ext":1}},{"offset":{"line":5,"column":2},"map":{"version":3,"sources":["b.ts"],"sourceRoot":"r/","names":["q"],"mappings":"AAAAA","sourcesContent":[null]}}]}`)
	m := f.manifest(raw)
	m.SourceContent = true
	got, err := f.app.Artifacts.Put(ctx, f.scope(t, auth.Permission("artifacts.write")), m, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	read := f.scope(t, auth.Permission("artifacts.read"))
	pr, err := f.app.Artifacts.Get(ctx, read, got.ID)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := io.ReadAll(pr)
	pr.Close()
	sr, err := f.app.Artifacts.GetSources(ctx, read, got.ID)
	if err != nil {
		t.Fatal(err)
	}
	priv, _ := io.ReadAll(sr)
	sr.Close()
	t.Logf("GOLDEN public=%s private=%s\npub=%s\npriv=%s", sha(pub), sha(priv), pub, priv)
	if sha(pub) != goldenSectionsPublic || sha(priv) != goldenSectionsPrivate {
		t.Fatalf("output bytes changed: public=%s private=%s", sha(pub), sha(priv))
	}
}

const goldenSectionsPublic, goldenSectionsPrivate = "f0ebab7ed576566b543b9be60025ee27be345dfab950c04c524ee26302bd5a5f", "9721cf16ce7d842607282a8926b1f1c9db5b68c8aa78fdb978829985d2a1fbfd"
