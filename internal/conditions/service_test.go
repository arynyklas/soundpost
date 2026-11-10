// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package conditions_test

import (
	"context"
	"encoding/json"
	"math/rand/v2"
	"path/filepath"
	"reflect"
	"sync"
	"testing"

	"soundpost/internal/auth"
	"soundpost/internal/conditions"
	"soundpost/internal/control"
	"soundpost/internal/model"
	"soundpost/internal/replica"
	"soundpost/internal/rules"
)

type sfx struct {
	*node
	svc   *conditions.Service
	clock *fixedClock
}

func newSfx(t *testing.T) *sfx {
	t.Helper()
	n := newNode(t)
	clock := &fixedClock{}
	clock.set(1000)
	return &sfx{node: n, svc: n.service(clock, nil), clock: clock}
}

func (f *sfx) apply(e model.ConditionEvent) (conditions.State, error) {
	return f.svc.Apply(f.ctx, f.scope(auth.OrgAdmin), e)
}

func (f *sfx) mustApply(e model.ConditionEvent) conditions.State {
	f.t.Helper()
	s, err := f.apply(e)
	if err != nil {
		f.t.Fatalf("apply %s seq=%d: %v", e.Status, e.Sequence, err)
	}
	return s
}

// A committed transition is applied once: an old, duplicate or conflicting event
// has no effect on the committed state, the audit or the control revision.
func TestConditionServiceOrderingAndNoDuplicateEffect(t *testing.T) {
	f := newSfx(t)
	first := f.mustApply(event(epoch2, 10, 100, "firing"))
	if first.Phase != conditions.PhaseFiring || first.Version != 1 || first.Arrived != 1000*sec || !first.Notify || first.Rule != nil {
		t.Fatalf("first: %+v", first)
	}
	recs := f.conditionRecords()
	if len(recs) != 1 || recs[0].Org != f.org || recs[0].Project != f.project || recs[0].ID != cond || recs[0].Version != 1 || recs[0].Fence == nil {
		t.Fatalf("committed record: %+v", recs)
	}
	revision := f.revision()
	f.clock.set(2000)
	for name, e := range map[string]model.ConditionEvent{"older": event(epoch2, 9, 90, "recovered"), "duplicate": event(epoch2, 10, 100, "firing")} {
		got, err := f.apply(e)
		if err != nil || !reflect.DeepEqual(got, first) {
			t.Fatalf("%s: %+v %v", name, got, err)
		}
	}
	if f.revision() != revision || f.audits("conditions.firing") != 1 {
		t.Fatalf("an old or duplicate event committed: revision %d -> %d, %d audits", revision, f.revision(), f.audits("conditions.firing"))
	}
	if _, err := f.apply(event(epoch2, 10, 100, "recovered")); code(err) != model.Conflict || detail(err) != conditions.DetailEventConflict {
		t.Fatalf("conflicting replay: %v", err)
	}
	if f.revision() != revision {
		t.Fatal("a rejected conflicting replay committed")
	}
	// A newer sequence applies, with its own arrival time.
	next := f.mustApply(event(epoch2, 11, 110, "recovered"))
	if !next.Recovered() || next.Version != 2 || next.Arrived != 2000*sec || f.audits("conditions.recovered") != 1 {
		t.Fatalf("recovery: %+v", next)
	}
	got, found, err := f.svc.Get(f.ctx, f.scope(auth.Read), cond)
	if err != nil || !found || !reflect.DeepEqual(got, next) {
		t.Fatalf("get: %+v %v %v", got, found, err)
	}
	if _, found, err = f.svc.Get(f.ctx, f.scope(auth.Read), model.ID{0xc9}); err != nil || found {
		t.Fatalf("get of a missing condition: %v %v", found, err)
	}
}

// Concurrent deliveries of the same events, in any interleaving, converge on the
// state the newest sequence defines, with no error and no lost update.
func TestConditionServiceConcurrentEventsConverge(t *testing.T) {
	f := newSfx(t)
	statuses := []string{"pending", "firing", "unknown", "firing", "recovering", "firing", "unknown", "firing", "recovering", "recovered", "firing", "recovered"}
	var events []model.ConditionEvent
	for i, s := range statuses {
		e := event(epoch1, uint64(i+1), int64(100+i), s)
		events = append(events, e, e) // every event is delivered twice
	}
	rand.New(rand.NewPCG(7, 7)).Shuffle(len(events), func(i, j int) { events[i], events[j] = events[j], events[i] })
	var wg sync.WaitGroup
	errs := make(chan error, len(events))
	for _, e := range events {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := f.apply(e); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent apply: %v", err)
	}
	s, found, err := f.svc.Get(f.ctx, f.scope(auth.Read), cond)
	if err != nil || !found {
		t.Fatal(found, err)
	}
	if s.Sequence != 12 || !s.Recovered() || s.EventAt != 111 {
		t.Fatalf("concurrent delivery ended in %+v", s)
	}
	// Each accepted sequence was applied at most once: the history has no repeats.
	seen := map[model.Uint64]bool{}
	for _, ref := range s.Recent {
		if seen[ref.Sequence] {
			t.Fatalf("sequence %d applied twice", ref.Sequence)
		}
		seen[ref.Sequence] = true
	}
}

// Two independent stores see the same events, one in order and one with early,
// late and duplicated retries interleaved: their committed states are equal.
func TestConditionServiceDeterministicUnderReorderedRetries(t *testing.T) {
	events := []model.ConditionEvent{
		event(epoch1, 1, 100, "pending"), event(epoch1, 2, 110, "firing"), event(epoch1, 3, 120, "unknown"), event(epoch1, 4, 130, "firing"), event(epoch1, 5, 140, "recovered"),
	}
	run := func(order []int) conditions.State {
		f := newSfx(t)
		for _, i := range order {
			if _, err := f.apply(events[i]); err != nil {
				t.Fatalf("event %d: %v", i, err)
			}
		}
		s, _, err := f.svc.Get(f.ctx, f.scope(auth.Read), cond)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	ordered := run([]int{0, 1, 2, 3, 4})
	retried := run([]int{0, 1, 0, 2, 1, 3, 2, 0, 4, 3, 4, 1})
	if !reflect.DeepEqual(ordered, retried) || !ordered.Recovered() {
		t.Fatalf("state depends on retry order:\n%s\n%s", mustJSON(t, ordered), mustJSON(t, retried))
	}
	// A reordered delivery loses the events that arrive after a newer one and
	// still ends at the newest.
	reordered := run([]int{0, 1, 4, 3, 2})
	if reordered.Sequence != 5 || !reordered.Recovered() {
		t.Fatalf("reordered: %+v", reordered)
	}
}

// Condition state survives a control snapshot import and a restart of the whole
// node, and a restarted service still treats a committed event as done.
func TestConditionServiceSurvivesRestartAndSnapshotImport(t *testing.T) {
	f := newSfx(t)
	f.mustApply(event(epoch1, 1, 100, "pending"))
	f.mustApply(event(epoch1, 2, 110, "firing"))
	last := f.mustApply(event(epoch1, 3, 120, "unknown"))
	if last.Phase != conditions.PhaseFiring || last.Freshness != conditions.FreshnessUnknown {
		t.Fatalf("before: %+v", last)
	}
	books := func(st model.ControlState) map[string]json.RawMessage { return st.ConditionBooks }
	var before map[string]json.RawMessage
	if err := f.app.Control.View(f.ctx, func(st model.ControlState) error { before = books(st); return nil }); err != nil {
		t.Fatal(err)
	}
	seed, _, err := f.app.Control.ReplicationSeed()
	if err != nil {
		t.Fatal(err)
	}
	imported, err := control.OpenSeed(filepath.Join(t.TempDir(), "imported"), seed)
	if err != nil {
		t.Fatal(err)
	}
	var restored map[string]json.RawMessage
	if err = imported.View(f.ctx, func(st model.ControlState) error { restored = books(st); return nil }); err != nil {
		t.Fatal(err)
	}
	imported.Close()
	if len(before) != 1 || !reflect.DeepEqual(before, restored) {
		t.Fatalf("snapshot import changed the condition state:\n%v\n%v", before, restored)
	}

	f.restart()
	f.svc = f.node.service(f.clock, nil)
	got, found, err := f.svc.Get(f.ctx, f.scope(auth.Read), cond)
	if err != nil || !found || !reflect.DeepEqual(got, last) {
		t.Fatalf("after restart: %+v %v %v", got, found, err)
	}
	revision := f.revision()
	for _, e := range []model.ConditionEvent{event(epoch1, 3, 120, "unknown"), event(epoch1, 2, 110, "firing")} {
		if again, err := f.apply(e); err != nil || !reflect.DeepEqual(again, last) {
			t.Fatalf("replay after restart: %+v %v", again, err)
		}
	}
	if f.revision() != revision {
		t.Fatal("a committed event committed again after a restart")
	}
	if next := f.mustApply(event(epoch1, 4, 130, "recovered")); !next.Recovered() || next.Version != last.Version+1 {
		t.Fatalf("the next event after a restart: %+v", next)
	}
}

type fakeFencer struct {
	group    *replica.Group
	token    *replica.FenceToken // overrides the group's lease when set
	validate error               // returned by ValidateFence when set
	skip     bool                // ValidateFence passes: leadership was lost just after it
}

func (f *fakeFencer) Fence(ctx context.Context) (replica.FenceToken, error) {
	if f.token != nil {
		return *f.token, nil
	}
	return f.group.Fence(ctx)
}

func (f *fakeFencer) ValidateFence(ctx context.Context, token replica.FenceToken) error {
	if f.validate != nil {
		return f.validate
	}
	if f.skip {
		return nil
	}
	return f.group.ValidateFence(ctx, token)
}

func (f *sfx) serviceWith(fencer conditions.Fencer) *conditions.Service {
	f.t.Helper()
	svc, err := conditions.New(f.app.Control, fencer, rules.NewOutboxStore(f.app.Control), f.clock)
	if err != nil {
		f.t.Fatal(err)
	}
	return svc
}

// A condition is applied only under a live lease: a leader that is no longer one
// is refused before anything commits, and one that raced past its own check is
// refused by control because a newer lease already wrote the condition.
func TestConditionServiceFence(t *testing.T) {
	f := newSfx(t)
	group := f.app.Control.ReplicaGroup()
	scope := f.scope(auth.OrgAdmin)

	deposed := f.serviceWith(&fakeFencer{group: group, validate: replica.ErrStale})
	revision := f.revision()
	if _, err := deposed.Apply(f.ctx, scope, event(epoch1, 1, 100, "firing")); code(err) != model.Stale {
		t.Fatalf("a deposed leader applied a condition: %v", err)
	}
	if f.revision() != revision || len(f.conditionRecords()) != 0 {
		t.Fatal("a fenced-out apply committed")
	}

	// A newer lease writes the condition ...
	newer := f.lease()
	newer.Term += 5
	if _, err := f.serviceWith(&fakeFencer{group: group, token: &newer, skip: true}).Apply(f.ctx, scope, event(epoch1, 1, 100, "firing")); err != nil {
		t.Fatalf("newer lease: %v", err)
	}
	// ... and the older leader, which passed its own check just before losing
	// leadership, is stale at the control state machine.
	older := f.lease()
	racing := f.serviceWith(&fakeFencer{group: group, token: &older, skip: true})
	revision = f.revision()
	if _, err := racing.Apply(f.ctx, scope, event(epoch1, 2, 110, "recovered")); code(err) != model.Stale || detail(err) != control.ConditionLeaseStale {
		t.Fatalf("a leader that lost leadership between the check and the commit: %v", err)
	}
	if f.revision() != revision {
		t.Fatal("a stale-lease apply committed")
	}
	s, _, _ := f.svc.Get(f.ctx, f.scope(auth.Read), cond)
	if s.Phase != conditions.PhaseFiring || s.Sequence != 1 {
		t.Fatalf("a stale leader changed the condition: %+v", s)
	}
}

func TestConditionServiceScopeAndValidation(t *testing.T) {
	f := newSfx(t)
	revision := f.revision()
	if _, err := f.svc.Apply(f.ctx, f.scope(auth.Read), event(epoch1, 1, 100, "firing")); code(err) != model.Forbidden {
		t.Fatalf("a read-only scope applied a condition: %v", err)
	}
	// The worker scope names exactly one project: an org-wide scope does not.
	if _, err := f.svc.Apply(f.ctx, f.orgScope(), event(epoch1, 1, 100, "firing")); code(err) != model.Invalid {
		t.Fatalf("an org-wide scope applied a condition: %v", err)
	}
	// Nor does a scope that names two projects: it would be a guess which one.
	other := model.NewID()
	f.command("create_project", auth.AdminPayload{ID: other, Name: "other"})
	two, err := f.app.Auth.Authorize(f.ctx, f.actor, f.org, []model.ID{f.project, other}, auth.OrgAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.svc.Apply(f.ctx, two, event(epoch1, 1, 100, "firing")); code(err) != model.Invalid {
		t.Fatalf("a two-project scope applied a condition: %v", err)
	}
	revision = f.revision() // the second project's creation is the only change since
	bad := event(epoch1, 1, 100, "firing")
	bad.Status = "paging"
	if _, err := f.apply(bad); code(err) != model.Invalid {
		t.Fatalf("an invalid event: %v", err)
	}
	if f.revision() != revision || len(f.conditionRecords()) != 0 {
		t.Fatal("a rejected event left state")
	}
	if _, err := conditions.New(nil, nil, nil, nil); code(err) != model.Invalid {
		t.Fatalf("a service without dependencies: %v", err)
	}
}

func TestConditionServiceListsInIDOrder(t *testing.T) {
	f := newSfx(t)
	for _, seed := range []byte{0xc5, 0xc3, 0xc4} {
		e := event(epoch1, 1, 100, "firing")
		e.Condition = model.ID{seed}
		f.mustApply(e)
	}
	got, err := f.svc.List(f.ctx, f.scope(auth.Read))
	if err != nil || len(got) != 3 || got[0].Condition[0] != 0xc3 || got[1].Condition[0] != 0xc4 || got[2].Condition[0] != 0xc5 {
		t.Fatalf("list: %+v %v", got, err)
	}
}
