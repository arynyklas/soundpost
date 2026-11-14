// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"io"
	"sort"
	"sync"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/policy"
)

// toctouView is a DeletionView whose answer changes after a chosen number of
// calls: that is a Begin committing between a page's predicate fetch and the
// moment that page is certified for release. The test arms it right before
// Next, so call numbers are relative to that Next.
type toctouView struct {
	mu      sync.Mutex
	preds   []model.DeletePredicate
	next    []model.DeletePredicate
	calls   int
	flipAt  int
	flipped bool
}

func (v *toctouView) arm(after int, next ...model.DeletePredicate) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.calls, v.flipAt, v.next, v.flipped = 0, after, next, false
}
func (v *toctouView) didFlip() bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.flipped
}
func (v *toctouView) ActiveDeletions(_ context.Context, org model.ID, _ []model.ID) ([]model.DeletePredicate, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	var out []model.DeletePredicate
	for _, p := range v.preds {
		if p.Org == org {
			out = append(out, p)
		}
	}
	v.calls++
	if v.flipAt > 0 && v.calls == v.flipAt {
		v.preds, v.flipped = v.next, true
	}
	return out, nil
}

// pageFetchCalls is the number of DeletionView calls a Next makes up to and
// including the per-partition predicate fetch of a scan (entry authorize, loop
// authorize, readDeletions) and of a live Next with a queued event (first
// iteration authorize, second iteration authorize, readDeletions).
const pageFetchCalls = 3

type toctouEnv struct {
	engine *Engine
	view   *toctouView
	scope  auth.Scope
	d      model.SourceDescriptor
	commit func() // appends the page; run by the helper unless deferred
}

// appendRowsWithProducer commits rows as ONE batch (one stored page); all rows
// must share an owner slot computed against producer.
func appendRowsWithProducer(t *testing.T, e *Engine, store *control.Store, a *auth.Service, c auth.SourceCredential, d model.SourceDescriptor, producer model.ID, rows []model.Record) {
	t.Helper()
	ctx := context.Background()
	source, err := a.SourceAuthority(ctx, c, true)
	if err != nil {
		t.Fatal(err)
	}
	service, err := policy.New(a, nil)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := service.ResolveSource(ctx, c, d.Project, d.Source, source.Policy.Revision)
	if err != nil {
		t.Fatal(err)
	}
	input := typedInput(t, d, source.Policy.Revision, rows[0])
	input.Producer = producer
	input.Records = nil
	for _, row := range rows {
		var owned model.Record
		if err := model.StrictJSON(mustJSON(t, row), &owned); err != nil {
			t.Fatal(err)
		}
		input.Records = append(input.Records, owned)
	}
	if input.RouteSlot, err = model.OwnerSlot(d.Org, d.Project, d.Source, producer, input.Records[0]); err != nil {
		t.Fatal(err)
	}
	batch, err := policy.Normalize(grant, input)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	scope, err := grant.Scope()
	if err != nil {
		t.Fatal(err)
	}
	if batch.Reservation, err = store.ReserveAdmission(ctx, scope, batch); err != nil {
		t.Fatal(err)
	}
	if _, err = e.Append(ctx, scope, batch); err != nil {
		t.Fatalf("append: %v", err)
	}
}

func toctouResource(t *testing.T, a *auth.Service, c auth.SourceCredential) model.Resource {
	t.Helper()
	source, err := a.SourceAuthority(context.Background(), c, true)
	if err != nil {
		t.Fatal(err)
	}
	return model.Resource{Service: source.Policy.Resources.Services[0], Environment: source.Policy.Resources.Environments[0], Build: source.Policy.Resources.Builds[0], Instance: source.Policy.Resources.Instances[0]}
}

// metricPage stores (or, with deferCommit, prepares) one page of metric rows
// at the given times.
func metricPage(t *testing.T, deferCommit bool, times ...model.UnixNano) (*toctouEnv, []model.ID) {
	t.Helper()
	store, a, c, d := typedFixture(t)
	engine := openDeleteEngine(t, t.TempDir(), a, store)
	view := &toctouView{}
	if err := engine.BindDeletions(view); err != nil {
		t.Fatal(err)
	}
	base := typedRows(toctouResource(t, a, c))[0]
	var rows []model.Record
	var ids []model.ID
	for _, at := range times {
		row := base
		row.ID = model.NewID()
		row.ObservedAt = at
		rows = append(rows, row)
		ids = append(ids, row.ID)
	}
	producer := model.NewID()
	env := &toctouEnv{engine: engine, view: view, scope: scanScope(t, store, a, d), d: d}
	env.commit = func() { appendRowsWithProducer(t, engine, store, a, c, d, producer, rows) }
	if !deferCommit {
		env.commit()
	}
	return env, ids
}

// replayPage prepares one page holding two chunks of one replay root and one
// chunk of another replay in the same owner slot.
func replayPage(t *testing.T, deferCommit bool) (env *toctouEnv, root model.ID, covered, kept []model.ID) {
	t.Helper()
	store, a, c, d := typedFixture(t)
	engine := openDeleteEngine(t, t.TempDir(), a, store)
	view := &toctouView{}
	if err := engine.BindDeletions(view); err != nil {
		t.Fatal(err)
	}
	template := typedRows(toctouResource(t, a, c))[9]
	root = template.Payload.Replay.Replay
	producer := model.NewID()
	slotOf := func(r model.Record) uint16 {
		s, err := model.OwnerSlot(d.Org, d.Project, d.Source, producer, r)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	chunk := func(replay model.ID, seq model.Uint64, wall model.UnixNano) model.Record {
		row := template
		row.ID = model.NewID()
		body := *template.Payload.Replay
		body.Replay = replay
		body.Sequence = seq
		body.Clock.Wall = wall
		row.Payload = model.Payload{Replay: &body}
		return row
	}
	first := chunk(root, 1, 10)
	other := model.NewID()
	// An owner slot is a hash of the replay id: find a second replay that lands
	// in the same slot so the stored page is shared by covered and kept rows.
	for slotOf(chunk(other, 1, 20)) != slotOf(first) {
		other = model.NewID()
	}
	second := chunk(other, 1, 20)
	third := chunk(root, 2, 30)
	env = &toctouEnv{engine: engine, view: view, scope: scanScope(t, store, a, d), d: d}
	env.commit = func() {
		appendRowsWithProducer(t, engine, store, a, c, d, producer, []model.Record{first, second, third})
	}
	if !deferCommit {
		env.commit()
	}
	return env, root, []model.ID{first.ID, third.ID}, []model.ID{second.ID}
}

func toctouSorted(ids []model.ID) []model.ID {
	out := append([]model.ID(nil), ids...)
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}
func sameIDs(a, b []model.ID) bool {
	a, b = toctouSorted(a), toctouSorted(b)
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// drainScan reads a whole scan, arming the view before the first Next.
func drainScan(t *testing.T, env *toctouEnv, req ScanRequest, next ...model.DeletePredicate) []model.ID {
	t.Helper()
	req.Projects, req.End = []model.ID{env.d.Project}, 1000
	it, err := env.engine.Scan(context.Background(), env.scope, req)
	if err != nil {
		t.Fatal(err)
	}
	defer it.Close()
	env.view.arm(pageFetchCalls, next...)
	var got []model.ID
	for {
		page, err := it.Next(context.Background())
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, page.IDs...)
	}
	if !env.view.didFlip() {
		t.Fatal("the deletion view never changed during the read: the test did not exercise the window")
	}
	return got
}

// A historical_range deletion whose Begin lands after the page's predicates
// were fetched but before the page is released must not release covered rows;
// rows outside [start,end) on the same page still are.
func TestScanToctouRangeDeletionCommittingMidPageHidesCoveredRows(t *testing.T) {
	env, ids := metricPage(t, false, 2, 3, 4, 5, 6)
	got := drainScan(t, env, ScanRequest{Signal: model.Metric}, rangeDelete(env.d, []model.Kind{model.Metric}, 3, 5))
	want := []model.ID{ids[0], ids[3], ids[4]} // t=2 (before start), t=5 (end is exclusive), t=6
	if !sameIDs(got, want) {
		t.Fatalf("released %d rows %v, want only the uncovered %v", len(got), got, want)
	}
}

// Same window for an entity deletion of a replay root.
func TestScanToctouEntityDeletionCommittingMidPageHidesCoveredRows(t *testing.T) {
	env, root, _, kept := replayPage(t, false)
	entity := model.DeletePredicate{Operation: model.NewID(), Org: env.d.Org, Mode: model.DeleteEntity, Projects: []model.ID{env.d.Project}, Signals: []model.Kind{model.Replay}, Entities: []model.ID{root}, Generation: 1}
	got := drainScan(t, env, ScanRequest{Signal: model.Replay}, entity)
	if !sameIDs(got, kept) {
		t.Fatalf("released %v under an entity deletion that began mid-page, want only %v", got, kept)
	}
}

// A narrow projection that does not decode the payload still has to honor an
// entity deletion that began after the payload-column decision was made.
func TestScanToctouEntityDeletionWithPayloadlessProjection(t *testing.T) {
	env, root, _, kept := replayPage(t, false)
	entity := model.DeletePredicate{Operation: model.NewID(), Org: env.d.Org, Mode: model.DeleteEntity, Projects: []model.ID{env.d.Project}, Signals: []model.Kind{model.Replay}, Entities: []model.ID{root}, Generation: 1}
	got := drainScan(t, env, ScanRequest{Signal: model.Replay, Projection: []Field{FieldObservedTime}}, entity)
	if !sameIDs(got, kept) {
		t.Fatalf("released %v, want only %v", got, kept)
	}
}
