// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/exports"
	"github.com/arynyklas/soundpost/internal/model"
	"io"
	"math"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// busyProject is a project with one span source, a reader, and a real-wired
// export service (the application's own retention-backed delete generations and
// cache over the real engine), so a test can ingest while an export runs.
type busyProject struct {
	e       *isoEnv
	org     model.ID
	project model.ID
	source  sourceFixture
	reader  person
	scope   auth.Scope
	exports *exports.Service
	deletes *countedDeletes
}

// countedDeletes records every generation the export service observed.
type countedDeletes struct {
	base   auth.DeleteGenerations
	mu     sync.Mutex
	values []uint64
	errs   atomic.Int64
}

func (c *countedDeletes) DeleteGeneration(ctx context.Context, org model.ID, projects []model.ID) (uint64, error) {
	v, err := c.base.DeleteGeneration(ctx, org, projects)
	if err != nil {
		c.errs.Add(1)
		return v, err
	}
	c.mu.Lock()
	if n := len(c.values); n == 0 || c.values[n-1] != v {
		c.values = append(c.values, v)
	}
	c.mu.Unlock()
	return v, nil
}
func (c *countedDeletes) distinct() []uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]uint64(nil), c.values...)
}

func newBusyProject(t *testing.T) *busyProject {
	t.Helper()
	e := newIsoEnv(t)
	b := &busyProject{e: e}
	b.project = model.NewID()
	b.org = e.org("busy org", b.project)
	b.reader = e.user(b.org, "busy-reader@example.test")
	e.grant(b.org, b.reader, b.project, true, auth.Read)
	ids := sharedIDs{model.NewID(), model.NewID(), model.NewID()}
	policy := model.SourcePolicy{Revision: 1, Enabled: true, Class: "structured", Kinds: []model.Kind{model.SpanKind}, Operations: []string{"operation"}, RetentionDays: map[model.Kind]uint32{model.SpanKind: 7}, MaxBytes: 8 << 20, MaxSeries: 100}
	source := model.NewID()
	b.source = e.onboard(b.org, b.project, source, ids, policy, auth.SourcePolicyConfig{ProjectID: b.project, Enabled: true})
	// The application's own wiring: the retention-backed generations and the
	// application's cache, in front of the real storage engine.
	b.deletes = &countedDeletes{base: e.app.Retention}
	var err error
	if b.exports, err = exports.New(e.app.Auth, e.app.Cache, b.deletes, e.app.Storage); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.exports.Close)
	if b.scope, err = e.scope(b.reader, b.org, b.project, auth.Read); err != nil {
		t.Fatal(err)
	}
	return b
}

// spans ingests n spans in one batch, over the real HTTP ingest route.
func (b *busyProject) spans(t testing.TB, n int) error {
	e := b.e
	clock := model.TraceClock{Wall: 1, Mono: 1, Domain: model.ClockDomain{Host: model.NewID(), Boot: model.NewID(), Runtime: model.NewID()}}
	end := clock
	end.Mono = 2
	trace := model.NewID() // one owner per batch: every record of a batch must route to the same slot
	records := make([]model.Record, n)
	for i := range records {
		var span model.SpanID
		id := model.NewID()
		copy(span[:], id[:8])
		records[i] = model.Record{ID: model.NewID(), Kind: model.SpanKind, ObservedAt: model.UnixNano(e.tick.Add(1)), Resource: e.resource(b.source), Payload: model.Payload{Span: &model.Span{Trace: trace, ID: span, Kind: "internal", Operation: "operation", Start: clock, End: &end, Status: "ok", SampleProbability: model.FloatBits(0x3ff0000000000000), SampleDecision: "keep"}}}
	}
	batch := model.Batch{Version: 1, Project: b.project, Source: b.source.ID, Producer: model.NewID(), ID: model.NewID(), PolicyRevision: 1, Records: records}
	var err error
	if batch.RouteSlot, err = model.OwnerSlot(b.org, b.project, b.source.ID, batch.Producer, records[0]); err != nil {
		return err
	}
	raw, _ := json.Marshal(batch)
	req, _ := http.NewRequest("POST", e.server.URL+"/ingest/v1/batches", bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+b.source.Credential)
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Logf("ingest status %d %s", resp.StatusCode, body)
		return io.ErrUnexpectedEOF
	}
	return nil
}

func (b *busyProject) request() exports.Request {
	return exports.Request{Project: b.project, Signal: model.SpanKind, Start: 0, End: model.Int64(math.MaxInt64)}
}

// await polls the operation until it leaves "running" and reports how many
// distinct progress values it observed (a proxy for pages released).
func (b *busyProject) await(t testing.TB, id model.ID, limit time.Duration) (exports.Operation, int) {
	t.Helper()
	deadline := time.Now().Add(limit)
	seen := map[model.Uint64]bool{}
	for time.Now().Before(deadline) {
		op, err := b.exports.Status(b.e.ctx, b.scope, id)
		if err != nil {
			t.Fatal("status", err)
		}
		seen[op.Progress] = true
		if op.Phase != "running" {
			return op, len(seen)
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("export still running after", limit)
	return exports.Operation{}, 0
}

// A legitimate export of a busy project must keep running while that project
// ingests and the retention worker passes run: nothing the reader's
// authorization depends on (credential, grants, organization policy epoch,
// delete generation) moves, so every export of several in a row completes.
// This is the negative half of open item #1: it pins what ingest does NOT move.
func TestExportSurvivesConcurrentIngest(t *testing.T) {
	b := newBusyProject(t)
	for range 15 { // 1500 spans, about 1.6 MB of export: far below exports.MaxBytes even after the ingest below
		if err := b.spans(t, 100); err != nil {
			t.Fatal(err)
		}
	}
	epoch0, generation0 := b.scope.PolicyEpoch(), uint64(0)
	if g, err := b.e.app.Retention.DeleteGeneration(b.e.ctx, b.org, []model.ID{b.project}); err != nil {
		t.Fatal(err)
	} else {
		generation0 = g
	}
	stop := make(chan struct{})
	var ingested, passes atomic.Int64
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ingested.Load() < 3500 {
				select {
				case <-stop:
					return
				default:
				}
				time.Sleep(5 * time.Millisecond)
				if err := b.spans(t, 20); err != nil {
					return
				}
				ingested.Add(20)
			}
		}()
	}
	wg.Add(1)
	go func() { // the retention worker's passes (every minute in production), here back to back
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			case <-time.After(20 * time.Millisecond):
			}
			_ = b.e.app.Retention.RunOnce(b.e.ctx)
			passes.Add(1)
		}
	}()
	for round := 1; round <= 2; round++ {
		started := time.Now()
		grant, err := b.exports.Create(b.e.ctx, b.scope, b.request())
		if err != nil {
			t.Fatal(err)
		}
		// Budget per round: 90 s. Measured on an idle 8-CPU VM the round takes 1.2-2.1 s; with -race
		// 36-50 s idle, 60-79 s under 16 busy loops, and past 90 s when the package's other parallel
		// -race tests also compete (wave 24 failure): the race detector's CPU cost, not the export,
		// which completes with delete-read-errors=0. Under -race the budget is four times larger.
		budget := 90 * time.Second
		if raceEnabled {
			budget *= 4
		}
		op, steps := b.await(t, grant.Operation.ID, budget)
		t.Logf("round %d: phase=%s reason=%q progress=%d chunks=%d progress-steps=%d elapsed=%s ingested-so-far=%d worker-passes=%d delete-generations-seen=%v delete-read-errors=%d", round, op.Phase, op.SafeReason, op.Progress, op.Chunks, steps, time.Since(started).Round(time.Millisecond), ingested.Load(), passes.Load(), b.deletes.distinct(), b.deletes.errs.Load())
		if op.Phase != "complete" || op.SafeReason != "" {
			close(stop)
			wg.Wait()
			t.Fatalf("round %d: a legitimate export on a busy project ended %s/%q (progress %d)", round, op.Phase, op.SafeReason, op.Progress)
		}
	}
	close(stop)
	wg.Wait()
	if ingested.Load() == 0 || passes.Load() == 0 {
		t.Fatalf("no concurrent load happened (ingested %d, worker passes %d): the test proved nothing", ingested.Load(), passes.Load())
	}
	fresh, err := b.e.scope(b.reader, b.org, b.project, auth.Read)
	if err != nil {
		t.Fatal(err)
	}
	generation1, err := b.e.app.Retention.DeleteGeneration(b.e.ctx, b.org, []model.ID{b.project})
	if err != nil {
		t.Fatal(err)
	}
	if fresh.PolicyEpoch() != epoch0 || generation1 != generation0 {
		t.Fatalf("ingest moved what an export revalidates: policy epoch %d -> %d, delete generation %d -> %d", epoch0, fresh.PolicyEpoch(), generation0, generation1)
	}
}
