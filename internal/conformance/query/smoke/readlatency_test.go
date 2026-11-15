// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package smoke

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query"
)

// The node-loss drill reads its data back with two instant queries per member,
// last_over_time(m[30m]) and count_over_time(m[30m]), over a few hundred batches
// that each carry one sample of their own series. Before 11.18 such a read took
// 17-24 s per query on three voters (up to 75 s in the drill, over its 30 s
// timeout) because every released page paid several quorum rounds per data group,
// one group at a time, and every page held one batch.
const (
	readBackBatches = 300
	readBackBound   = 5 * time.Second
	// raceSlowdown scales the bound for a race-detector binary. The bound is a
	// regression ceiling of this harness, not a product guarantee: the sequential
	// per-page fences it guards against took 17-24 s per query without the race
	// detector, far above 4 x 5 s once the detector's slowdown is added.
	raceSlowdown   = 4
	readBackMetric = "drill_writes"
)

// readBackRig is a three-voter installation holding readBackBatches
// single-sample batches in one project, one series per batch (the drill shape).
type readBackRig struct {
	env    *Env
	reader *Person
}

func newReadBackRig(ctx context.Context, dir string, batches int) (rig *readBackRig, err error) {
	defer recoverFailure(&err)
	env, err := NewEnv(ctx, Distributed, dir)
	check(err)
	opened := false
	defer func() {
		if !opened {
			env.Close()
		}
	}()
	env.AddProject("project-a")
	reader := env.AddPerson("reader")
	env.Grant("reader", "project-a", true, "telemetry.read")
	values := make([]string, batches)
	for i := range values {
		values[i] = model.NewID().String()
	}
	source := env.AddSource(SourceSpec{Name: "drill", Project: "project-a", Kinds: []model.Kind{model.Metric}, Labels: map[string][]string{"batch": values}})
	// One writer rotating over the three voters: a batch is acknowledged by
	// whichever voter it is posted to.
	now := time.Now().UnixNano()
	for i := range batches {
		node := uint64(i%3) + 1
		rec := env.MetricRecord(source, readBackMetric, map[string]string{"batch": values[i]}, now+int64(i)*1000, FloatBitsOf(float64(i)+0.25), nil)
		code, body, batch := sendBatchRetrying(env, node, source, rec)
		checkf(code == 200, "node %d did not acknowledge: %d %s", node, code, trim(body))
		var receipt model.Receipt
		check(json.Unmarshal(body, &receipt))
		checkf(receipt.BatchID == batch.ID, "receipt names a different batch")
	}
	opened = true
	return &readBackRig{env: env, reader: reader}, nil
}

// readBack runs the drill's two read-back queries on node and returns how long
// each took and how many series each returned.
func (r *readBackRig) readBack(node uint64) (last, count time.Duration, lastSeries, countSeries int, err error) {
	defer recoverFailure(&err)
	at := time.Now().Add(time.Minute).UnixNano()
	run := func(expression string) (time.Duration, int) {
		started := time.Now()
		a := r.env.ask(node, r.reader, r.env.QueryBody("promql", promProfile, expression, at, "project-a"))
		took := time.Since(started)
		checkf(a.code == 200, "node %d %s answered %d: %s", node, expression, a.code, trim(a.raw))
		pr := a.res.Projects[0]
		checkf(pr.Failure == nil && pr.Completeness == query.CompletenessComplete && pr.Value != nil, "node %d %s is not complete", node, expression)
		return took, len(pr.Value.Vector)
	}
	last, lastSeries = run("last_over_time(" + readBackMetric + "[30m])")
	count, countSeries = run("count_over_time(" + readBackMetric + "[30m])")
	return
}

// TestDistributedReadBackOfManyBatchesIsFast pins the drill read-back latency:
// the two queries over readBackBatches one-sample batches return every series
// on every voter well inside readBackBound. The bound is a ceiling for a loaded
// CI machine; it sits far below what the sequential per-page fences cost.
func TestDistributedReadBackOfManyBatchesIsFast(t *testing.T) {
	if testing.Short() {
		t.Skip("starts three voters and ingests 300 batches")
	}
	rig, err := newReadBackRig(context.Background(), t.TempDir(), readBackBatches)
	if err != nil {
		t.Fatal(err)
	}
	defer rig.env.Close()
	bound := readBackBound
	if raceEnabled {
		bound *= raceSlowdown
	}
	for round := range 2 { // the second round is the warm one
		for _, node := range []uint64{1, 2, 3} {
			last, count, ls, cs, err := rig.readBack(node)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("round %d node %d: last_over_time %v (%d series), count_over_time %v (%d series)", round, node, last.Round(time.Millisecond), ls, count.Round(time.Millisecond), cs)
			if ls != readBackBatches || cs != readBackBatches {
				t.Errorf("node %d read back %d / %d series, want %d", node, ls, cs, readBackBatches)
			}
			if last > bound || count > bound {
				t.Errorf("node %d: reading %d batches took %v / %v, bound %v", node, readBackBatches, last, count, bound)
			}
		}
	}
}

// BenchmarkDistributedReadBack reports the drill read-back on a follower and on
// the leader of the three voters.
func BenchmarkDistributedReadBack(b *testing.B) {
	rig, err := newReadBackRig(context.Background(), b.TempDir(), readBackBatches)
	if err != nil {
		b.Fatal(err)
	}
	defer rig.env.Close()
	for _, node := range []uint64{1, 2} {
		b.Run(fmt.Sprintf("node%d", node), func(b *testing.B) {
			var last, count time.Duration
			for range b.N {
				l, c, _, _, err := rig.readBack(node)
				if err != nil {
					b.Fatal(err)
				}
				last += l
				count += c
			}
			b.ReportMetric(float64(last.Milliseconds())/float64(b.N), "ms/last_over_time")
			b.ReportMetric(float64(count.Milliseconds())/float64(b.N), "ms/count_over_time")
		})
	}
}

// sendBatchRetrying posts one batch and, while a voter answers with a retryable
// refusal (a leadership or application-order race), posts the very same batch
// again, as the drill's writer does: the batch id makes the retry idempotent.
func sendBatchRetrying(e *Env, node uint64, s *Source, records ...model.Record) (int, []byte, model.Batch) {
	project := e.Projects[s.Project]
	batch := model.Batch{Version: 1, Project: project, Source: s.ID, Producer: model.NewID(), ID: model.NewID(), PolicyRevision: 1, Records: records}
	var err error
	batch.RouteSlot, err = model.OwnerSlot(e.org, project, s.ID, batch.Producer, records[0])
	check(err)
	raw, err := json.Marshal(batch)
	check(err)
	var code int
	var body []byte
	for attempt := range 100 {
		base, client := e.endpoint((node-1+uint64(attempt))%3 + 1)
		req, _ := http.NewRequest("POST", base+"/ingest/v1/batches", bytes.NewReader(raw))
		req.Header.Set("Authorization", "Bearer "+s.Credential)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		check(err)
		body, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		code = resp.StatusCode
		if code != http.StatusServiceUnavailable {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	return code, body, batch
}
