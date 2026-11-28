// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"fmt"
	"math/rand/v2"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

// gateWindow is what one window of acks wrote: apply.db pages and page nodes (the random writes) by the commits that carried the acks
// and by the merges those commits made due, and the bytes the other files of the engine (journal, payload log) grew.
type gateWindow struct {
	acks                    int
	byIndex                 map[string]float64 // per ack, 4 KiB pages the merges of each index wrote
	bodies                  map[string]float64 // per ack, bytes of keys and values the commits wrote to the runs of each index
	commitPages, mergePages float64            // per ack, 4 KiB pages of apply.db (the meta page of each commit counted for the commits)
	commitNodes, mergeNodes float64            // per ack, bolt page nodes written (a node of several contiguous pages is one)
	files                   float64            // per ack, bytes the journal and the payload log grew
	runs                    int                // ready runs of the three indexes at the end of the window
	batchBytes              float64            // mean canonical size of a batch
	commitTime, mergeTime   time.Duration      // per ack, the time of the commits and of the merges
}

func (w gateWindow) pages() float64 { return w.commitPages + w.mergePages }
func (w gateWindow) nodes() float64 { return w.commitNodes + w.mergeNodes }

// gateRequest is what every batch of a gate history shares: the scope of the source, its resource and the hash of its policy (the
// authentication of a credential is far costlier than the batch built on it).
type gateRequest struct {
	store      *control.Store
	scope      auth.Scope
	desc       model.SourceDescriptor
	res        model.Resource
	policyHash string
}

func newGateRequest(a *auth.Service, store *control.Store, c auth.SourceCredential, d model.SourceDescriptor) (*gateRequest, error) {
	scope, e := a.SourceScope(context.Background(), c, false)
	if e != nil {
		return nil, e
	}
	src, e := a.SourceAuthority(context.Background(), c, true)
	if e != nil {
		return nil, e
	}
	policyBytes, err := model.CanonicalJSON(src.Policy)
	if err != nil {
		return nil, err
	}
	res := model.Resource{Service: src.Policy.Resources.Services[0], Environment: src.Policy.Resources.Environments[0], Build: src.Policy.Resources.Builds[0], Instance: src.Policy.Resources.Instances[0]}
	return &gateRequest{store: store, scope: scope, desc: d, res: res, policyHash: model.HashCanonical(policyBytes).String()}, nil
}

// batch is ackPagesBatch for a request of several records, one series each: the records of a gate request that one source routes to
// the same owner. It reports its failure instead of stopping the test, so that batches can be prepared by several goroutines (the
// reservation of a batch is a commit of the control store, which dominates the time of a test that prepares thousands).
func (g *gateRequest) batch(at model.UnixNano, names []string) (model.NormalizedBatch, error) {
	var zero model.NormalizedBatch
	d := g.desc
	records := make([]model.Record, len(names))
	for i, name := range names {
		records[i] = model.Record{ID: model.NewID(), Kind: model.Metric, ObservedAt: at, Resource: g.res, Payload: model.Payload{Metric: &model.MetricPoint{Name: name, Labels: model.Labels{}, SampleKind: "float", Value: ptrBits(0x3ff0000000000000), Type: "counter", Unit: "1"}}}
	}
	b := model.Batch{Version: 1, Project: d.Project, Source: d.Source, Producer: model.NewID(), ID: model.NewID(), PolicyRevision: 1, Records: records}
	slot, _ := model.OwnerSlot(d.Org, b.Project, b.Source, b.Producer, b.Records[0])
	b.RouteSlot = slot
	raw, err := model.CanonicalJSON(b)
	if err != nil {
		return zero, err
	}
	n := model.NormalizedBatch{Batch: b, Org: d.Org, Hash: model.HashCanonical(raw), Canonical: raw, PolicyEpoch: model.Uint64(g.scope.PolicyEpoch()), PolicyHash: g.policyHash, AdmissionAt: 10, Deadlines: []model.SignalDeadline{{Kind: model.Metric, RetainUntil: 100}}}
	n.Reservation, err = g.store.ReserveAdmission(context.Background(), g.scope, n)
	if err != nil {
		return zero, err
	}
	return n, nil
}

// gateHistory prepares the batches of a history of the shape of the single-host gate: recordsPerBatch records (~4) of one slot, one
// series each, drawn from a pool, so that every record adds its postings, its time key and its rows. The observation time increases
// with the index of the batch, like a clock. A reservation of the control store costs more the more reservations it holds that no
// append has consumed (the fixture's books are one document), so a history is prepared a window at a time, each window appended
// before the next is reserved.
type gateHistory struct {
	t       *testing.T
	req     *gateRequest
	bySlot  map[uint16][]string
	order   []uint16
	rng     *rand.Rand
	records int
	made    int
}

func newGateHistory(t *testing.T, store *control.Store, service *auth.Service, cred auth.SourceCredential, desc model.SourceDescriptor, recordsPerBatch int) *gateHistory {
	t.Helper()
	const universe = 900 // the series quota of the fixture is 1000
	h := &gateHistory{t: t, bySlot: map[uint16][]string{}, rng: rand.New(rand.NewPCG(13, 13)), records: recordsPerBatch}
	for i := range universe {
		name := fmt.Sprintf("gate_series_%d", i)
		slot := ackPagesSlotOf(t, desc, name)
		h.bySlot[slot] = append(h.bySlot[slot], name)
	}
	for slot, names := range h.bySlot {
		if len(names) >= recordsPerBatch {
			h.order = append(h.order, slot)
		}
	}
	sort.Slice(h.order, func(i, j int) bool { return h.order[i] < h.order[j] })
	if len(h.order) < 2 {
		t.Fatalf("the %d series route to %d slots with %d series: a commit needs two slots", universe, len(h.order), recordsPerBatch)
	}
	var err error
	if h.req, err = newGateRequest(service, store, cred, desc); err != nil {
		t.Fatal(err)
	}
	return h
}

// next prepares the next n batches of the history.
func (h *gateHistory) next(n int) []preparedAppend {
	h.t.Helper()
	picks := make([][]string, n)
	for i := range picks {
		names := h.bySlot[h.order[(h.made+i)%len(h.order)]]
		for _, j := range h.rng.Perm(len(names))[:h.records] {
			picks[i] = append(picks[i], names[j])
		}
	}
	batches := make([]preparedAppend, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	todo := make(chan int)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range todo {
				batches[i].scope = h.req.scope
				batches[i].batch, errs[i] = h.req.batch(model.UnixNano(1+h.made+i), picks[i])
			}
		}()
	}
	for i := range n {
		todo <- i
	}
	close(todo)
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			h.t.Fatalf("preparing batch %d: %v", h.made+i, err)
		}
	}
	h.made += n
	return batches
}

// readyRuns is the number of ready runs of the three indexes.
func readyRuns(t *testing.T, e *Engine) (runs int) {
	t.Helper()
	err := e.db.View(func(tx *bolt.Tx) error {
		reg := tx.Bucket([]byte(runsRegistry))
		if reg == nil {
			return nil
		}
		for _, name := range []string{"scan_time", "scan_postings", rowsIndex} {
			rs, err := listIndexRuns(reg, name)
			if err != nil {
				return err
			}
			for _, r := range rs {
				if r.meta.State == indexRunReady {
					runs++
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return runs
}

// level0Bytes is the keys and values (the bytes of the registry metas) of the ready runs of level 0 of each index: what the commits
// wrote that no merge has taken yet.
func level0Bytes(t *testing.T, e *Engine) map[string]int64 {
	t.Helper()
	out := map[string]int64{}
	err := e.db.View(func(tx *bolt.Tx) error {
		reg := tx.Bucket([]byte(runsRegistry))
		if reg == nil {
			return nil
		}
		for _, name := range []string{"scan_time", "scan_postings", rowsIndex} {
			rs, err := listIndexRuns(reg, name)
			if err != nil {
				return err
			}
			for _, r := range rs {
				if r.meta.State == indexRunReady && r.meta.Level == 0 {
					out[name] += r.meta.Bytes
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// measureGateWindow appends the batches width to a commit, runs the merges those commits made due and returns what the window wrote.
func measureGateWindow(t *testing.T, e *Engine, dir string, batches []preparedAppend, width int) gateWindow {
	t.Helper()
	e.stopIndexMerger()
	before := e.db.Stats()
	beforeFiles := dirBytesBesidesApplyDB(t, dir)
	body0 := level0Bytes(t, e)
	begin := time.Now()
	commits, applies := appendInCommits(t, e, batches, width)
	if applies != uint64(len(batches)) {
		t.Fatalf("%d appends made %d applies", len(batches), applies)
	}
	committed := time.Since(begin)
	body1 := level0Bytes(t, e)
	mid := e.db.Stats()
	n := float64(len(batches))
	byIndex, bodies := map[string]float64{}, map[string]float64{}
	begin = time.Now()
	for _, name := range []string{"scan_time", "scan_postings", rowsIndex} {
		bodies[name] = float64(body1[name]-body0[name]) / n
		b := e.db.Stats()
		if cancelled, err := e.mergeIndexRunsOf(name, nil); cancelled || err != nil {
			t.Fatalf("merging the runs of %s the commits made due: cancelled=%v %v", name, cancelled, err)
		}
		a := e.db.Stats()
		d := a.Sub(&b)
		byIndex[name] = float64(d.TxStats.GetPageAlloc()) / 4096 / n
	}
	if cancelled, err := e.mergeIndexRuns(nil); cancelled || err != nil { // what the passes above leave (the blocks of final runs)
		t.Fatalf("merging the runs the commits made due: cancelled=%v %v", cancelled, err)
	}
	merged := time.Since(begin)
	after := e.db.Stats()
	c, m := mid.Sub(&before), after.Sub(&mid)
	var canon int
	for _, b := range batches {
		canon += len(b.batch.Canonical)
	}
	return gateWindow{
		byIndex:     byIndex,
		bodies:      bodies,
		acks:        len(batches),
		commitPages: (float64(c.TxStats.GetPageAlloc()) + float64(4096*commits)) / 4096 / n,
		mergePages:  float64(m.TxStats.GetPageAlloc()) / 4096 / n,
		commitNodes: float64(c.TxStats.GetWrite()) / n,
		mergeNodes:  float64(m.TxStats.GetWrite()) / n,
		files:       float64(dirBytesBesidesApplyDB(t, dir)-beforeFiles) / n,
		runs:        readyRuns(t, e),
		batchBytes:  float64(canon) / n,
		commitTime:  committed / time.Duration(len(batches)),
		mergeTime:   merged / time.Duration(len(batches)),
	}
}

func (w gateWindow) bodyBytes() float64 {
	var sum float64
	for _, b := range w.bodies {
		sum += b
	}
	return sum
}

func (w gateWindow) String() string {
	return fmt.Sprintf("%.1f pages (%.1f commit + %.1f merge: time %.1f postings %.1f rows %.1f), %.1f nodes (%.1f + %.1f), %.0f B of index bodies and rows (time %.0f postings %.0f rows %.0f), %.0f file bytes, %d runs, %v commit + %v merge per ack",
		w.pages(), w.commitPages, w.mergePages, w.byIndex["scan_time"], w.byIndex["scan_postings"], w.byIndex[rowsIndex], w.nodes(), w.commitNodes, w.mergeNodes,
		w.bodyBytes(), w.bodies["scan_time"], w.bodies["scan_postings"], w.bodies[rowsIndex], w.files, w.runs, w.commitTime, w.mergeTime)
}

// TestGateWriteVolumePerAckIncludingMergesIsBoundedAndIndependentOfHistory is the red test of D83 for the index-run merges (L2w20Admission28).
// The single-host gate (64 data groups at 2,000 records/s, ~585 requests/s, a request of ~4 records, about 9 acknowledged requests a
// second and two to a commit in each group) wrote 18.8 M pages to the apply.db files in 900 s, 9.79 M (52 %) of them in scan_runs, because
// every commit adds one tiny run to each of the three indexes (about 17 KB of keys and values) and the background merges rewrote a key
// once per level, with 8 runs to a level: four to five times before a run reached the size at which it is final (64 MiB: no run does in
// the first hour, at 50 KB/s of index bodies a group). The older measurement (TestWrittenBytesPerAck...) used a batch of 653 bytes and a
// window of 240 acks; this one is the gate's: batches of four records (1.9 KB canonical, 8.7 KB of index bodies and rows), two to a
// commit, a history of 2,048 acks (18 MB of bodies, 1,024 commits) in windows of 512.
//
// What an acknowledged request writes to apply.db, merges included, is bounded by the structure and does not grow with the history:
//
//   - a commit adds ~15 pages for its three runs (their buckets, their registry entries and the meta page: measured 9 pages an ack) and
//     the rest of what the engine writes for it;
//   - the merges of the first 4,096 commits rewrite a key once (indexRunFanouts: 64 runs to each of the first two levels): at most the
//     pages of the bodies the window wrote, 1.2 times for the registry and the bucket of the output, measured 0.6 (the blocks are prefix
//     compressed) and 3.9 to 8.5 (4 levels, 4 to 5 once the history is 4,096 commits) before the change;
//   - the pages of a commit grow a little with the runs the registry holds (at most 3 x 63 of a level), so the last window may exceed
//     the first by 15 %: 11.7 against 10.5 pages measured.
//
// The measurement merges, after each window, what the merger would have (it wakes every 200 ms and a commit comes every ~250 ms), so
// that a window pays for the merges its own commits made due, and counts the pages bolt allocated (4 KiB, in nodes of several
// contiguous pages) separately for the commits and for the merges.
func TestGateWriteVolumePerAckIncludingMergesIsBoundedAndIndependentOfHistory(t *testing.T) {
	const total, window, width, records = 2048, 512, 2, 4
	store, service, cred, desc := fixture(t)
	dir := t.TempDir()
	e := openPayloadEngine(t, dir, store, service)
	if err := store.BindAdmissionOwner(e); err != nil {
		t.Fatal(err)
	}
	e.stopIndexMerger()
	h := newGateHistory(t, store, service, cred, desc, records)
	var windows []gateWindow
	for from := 0; from < total; from += window {
		begin := time.Now()
		batches := h.next(window)
		prepared := time.Since(begin)
		w := measureGateWindow(t, e, dir, batches, width)
		windows = append(windows, w)
		t.Logf("acks %5d-%5d (batch %.0f B, prepared in %v): %s", from, from+window, w.batchBytes, prepared, w)
	}
	for i, w := range windows {
		name := fmt.Sprintf("window %d (acks %d-%d)", i, i*window, (i+1)*window)
		if limit := gateMergePagesPerBodyPage * w.bodyBytes() / 4096; w.mergePages > limit {
			t.Errorf("%s: the merges wrote %.2f pages an ack for %.0f bytes of index bodies and rows (%.2f pages): more than %.1f times what the commits wrote, a key is rewritten more than once", name, w.mergePages, w.bodyBytes(), w.bodyBytes()/4096, gateMergePagesPerBodyPage)
		}
		if w.mergeNodes > gateMergeNodesPerAck {
			t.Errorf("%s: the merges wrote %.2f page nodes an ack, bound %.1f", name, w.mergeNodes, gateMergeNodesPerAck)
		}
		if w.pages() > gatePagesPerAck {
			t.Errorf("%s: apply.db is written %.1f pages an ack (%.1f by the commits, %.1f by the merges), bound %d", name, w.pages(), w.commitPages, w.mergePages, gatePagesPerAck)
		}
		if want := 3 * (63 + 63 + 7); w.runs > want {
			t.Errorf("%s: %d ready runs, the levels hold at most %d", name, w.runs, want)
		}
	}
	first, last := windows[0], windows[len(windows)-1]
	if last.pages() > first.pages()*gateHistoryDrift {
		t.Errorf("the pages written per ack grew with the history: %.1f for the first %d acks, %.1f for the last %d (limit %.2fx)", first.pages(), window, last.pages(), window, gateHistoryDrift)
	}
	if last.mergePages > first.mergePages*gateHistoryDrift+0.1 {
		t.Errorf("the pages the merges write per ack grew with the history: %.2f for the first %d acks, %.2f for the last %d", first.mergePages, window, last.mergePages, window)
	}
}

const (
	// gateMergePagesPerBodyPage is the pages the merges of a window may write per page of index bodies and rows its commits wrote: one
	// level of merges (a key is rewritten once until 4,096 commits), 1.2 for the buckets and the registry of the outputs.
	gateMergePagesPerBodyPage = 1.2
	// gateMergeNodesPerAck is the page nodes (random writes) the merges write an ack: a merge writes its output as a few contiguous nodes
	// (a block of 32 or 128 KiB is one), measured 0.2 against 1.8 to 2.2 with 8 runs to a level.
	gateMergeNodesPerAck = 0.6
	// gatePagesPerAck bounds the pages apply.db is written an ack, commits and merges: measured 10.5 to 11.7.
	gatePagesPerAck = 13
	// gateHistoryDrift is how much more the last window may write than the first.
	gateHistoryDrift = 1.15
)
