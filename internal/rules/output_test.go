// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package rules

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
)

// memOutbox is an in-memory Outbox that applies the same transition table
// control does, so the worker is exercised against its contract, not a mock of
// its own behavior. The real control machine is covered by the recovery tests.
type memOutbox struct {
	items   []control.RuleOutput
	settled []control.RuleOutputApply
	leases  []replica.FenceToken
	failOn  string
}

func (m *memOutbox) Pending(_ context.Context, _ auth.Scope, limit int) ([]control.RuleOutput, error) {
	var out []control.RuleOutput
	for _, i := range m.items {
		if i.Kind == control.RuleOutputRecording && (i.Phase == control.RulePhasePending || i.Phase == control.RulePhaseAdmitted) {
			out = append(out, i)
		}
	}
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *memOutbox) Settle(_ context.Context, _ auth.Scope, lease replica.FenceToken, item control.RuleOutput, update control.RuleOutputApply) (control.Result, error) {
	if m.failOn == update.To {
		return control.Result{}, errors.New("control unavailable")
	}
	m.settled = append(m.settled, update)
	m.leases = append(m.leases, lease)
	for i := range m.items {
		if m.items[i].ID == item.ID {
			m.items[i].Phase = update.To
			m.items[i].Receipt, m.items[i].Hash, m.items[i].Reason = update.Receipt, update.Hash, update.Reason
		}
	}
	return control.Result{}, nil
}

func (m *memOutbox) phase(id model.ID) string {
	for _, i := range m.items {
		if i.ID == id {
			return i.Phase
		}
	}
	return ""
}

func intentItem(t *testing.T, seed byte, at int64) control.RuleOutput {
	t.Helper()
	v := model.FloatBits(math.Float64bits(float64(seed)))
	batch := model.Batch{Version: 1, Project: model.ID{2}, Source: model.ID{0xa1}, Producer: model.ID{0xa2}, ID: model.ID{seed}, PolicyRevision: 1, RouteSlot: 3, Records: []model.Record{{
		ID: model.ID{seed, 1}, Kind: model.Metric, ObservedAt: model.UnixNano(at) * sec, Resource: producer().Resource,
		Payload: model.Payload{Metric: &model.MetricPoint{Name: "m", Labels: model.Labels{}, SampleKind: "float", Value: &v, Unit: "1", Type: "gauge"}},
	}}}
	raw, err := model.CanonicalJSON(RecordingIntent{ID: batch.ID, Slot: 3, Batch: batch, Inputs: []model.Cursor{{Group: model.ID{9}, Index: 1}}})
	if err != nil {
		t.Fatal(err)
	}
	return control.RuleOutput{ID: batch.ID, Project: model.ID{2}, Rule: model.ID{1}, At: model.UnixNano(at) * sec, Kind: control.RuleOutputRecording, Phase: control.RulePhasePending, Payload: raw}
}

type scriptedAdmitter struct {
	admit  func(call int, b model.Batch) (model.Receipt, error)
	lookup func(b model.Batch) (model.Receipt, bool, error)
	calls  int
	looked int
}

func (s *scriptedAdmitter) Admit(_ context.Context, b model.Batch) (model.Receipt, error) {
	s.calls++
	return s.admit(s.calls, b)
}
func (s *scriptedAdmitter) LookupReceipt(_ context.Context, b model.Batch) (model.Receipt, bool, error) {
	s.looked++
	if s.lookup == nil {
		return model.Receipt{}, false, nil
	}
	return s.lookup(b)
}

func okReceipt(b model.Batch) model.Receipt {
	return model.Receipt{Version: 1, BatchID: b.ID, Hash: model.Hash{1}, Cursor: model.Cursor{Group: model.ID{7}, Index: model.Uint64(b.ID[0])}}
}

func newWorker(t *testing.T, adm *scriptedAdmitter, outbox *memOutbox, fence Fencer) *OutputWorker {
	t.Helper()
	w, err := NewOutputWorker(adm, outbox, adm, fence)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func TestOutputWorkerRequiresEveryDependency(t *testing.T) {
	adm := &scriptedAdmitter{}
	outbox := &memOutbox{}
	for name, build := range map[string]func() (*OutputWorker, error){
		"no admitter": func() (*OutputWorker, error) { return NewOutputWorker(nil, outbox, adm, fakeFence{}) },
		"no outbox":   func() (*OutputWorker, error) { return NewOutputWorker(adm, nil, adm, fakeFence{}) },
		"no lookup":   func() (*OutputWorker, error) { return NewOutputWorker(adm, outbox, nil, fakeFence{}) },
		"no fencer":   func() (*OutputWorker, error) { return NewOutputWorker(adm, outbox, adm, nil) },
	} {
		if w, err := build(); err == nil || w != nil || code(err) != model.Invalid {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// Flush releases in order, up to the limit, and reports every output by ID and
// every admitted cursor.
func TestFlushFinalizesInOrderUpToLimit(t *testing.T) {
	outbox := &memOutbox{items: []control.RuleOutput{intentItem(t, 1, 60), intentItem(t, 2, 120), intentItem(t, 3, 180)}}
	adm := &scriptedAdmitter{admit: func(_ int, b model.Batch) (model.Receipt, error) { return okReceipt(b), nil }}
	w := newWorker(t, adm, outbox, fakeFence{})
	report, err := w.Flush(context.Background(), auth.Scope{}, testLease, 2)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(report.Finalized, []model.ID{{1}, {2}}) || !reflect.DeepEqual(report.Admitted, []model.Cursor{{Group: model.ID{7}, Index: 1}, {Group: model.ID{7}, Index: 2}}) || len(report.Retried)+len(report.Suppressed) != 0 {
		t.Fatalf("report %+v", report)
	}
	if outbox.phase(model.ID{3}) != control.RulePhasePending || adm.calls != 2 {
		t.Fatalf("limit exceeded: %d admissions", adm.calls)
	}
	// Admitted, then finalized, each under the caller's lease.
	var steps []string
	for _, u := range outbox.settled {
		steps = append(steps, u.To)
	}
	if !reflect.DeepEqual(steps, []string{"admitted", "finalized", "admitted", "finalized"}) {
		t.Fatalf("settle order %v", steps)
	}
	for _, l := range outbox.leases {
		if l != testLease {
			t.Fatalf("a settle carried another lease: %+v", l)
		}
	}
	if _, err = w.Flush(context.Background(), auth.Scope{}, testLease, 0); code(err) != model.Invalid {
		t.Fatalf("zero limit: %v", err)
	}
	if _, err = w.Flush(context.Background(), auth.Scope{}, replica.FenceToken{}, 1); code(err) != model.Invalid {
		t.Fatalf("zero lease: %v", err)
	}
}

// A deposed leader releases nothing: the fence is validated before any output is
// read, and again before every admission.
func TestFlushIsFenced(t *testing.T) {
	outbox := &memOutbox{items: []control.RuleOutput{intentItem(t, 1, 60), intentItem(t, 2, 120)}}
	adm := &scriptedAdmitter{admit: func(_ int, b model.Batch) (model.Receipt, error) { return okReceipt(b), nil }}
	if _, err := newWorker(t, adm, outbox, fakeFence{err: replica.ErrStale}).Flush(context.Background(), auth.Scope{}, testLease, 5); code(err) != model.Stale || adm.calls != 0 || len(outbox.settled) != 0 {
		t.Fatalf("deposed leader released effects: %v (%d admissions)", err, adm.calls)
	}
	// Leadership lost midway: the first admission happens, the second must not.
	flip := &flippingFence{okFor: 2}
	report, err := newWorker(t, adm, outbox, flip).Flush(context.Background(), auth.Scope{}, testLease, 5)
	if code(err) != model.Stale || adm.calls != 1 || len(report.Finalized) != 1 {
		t.Fatalf("mid-flush loss of leadership: %v calls=%d report=%+v", err, adm.calls, report)
	}
}

type flippingFence struct {
	okFor int
	calls int
}

func (f *flippingFence) ValidateFence(context.Context, replica.FenceToken) error {
	f.calls++
	if f.calls > f.okFor {
		return replica.ErrStale
	}
	return nil
}

// Obsolete intents (a deletion or retirement covers their origin) are suppressed
// before release and never admitted.
func TestFlushSuppressesObsoleteIntents(t *testing.T) {
	gone := intentItem(t, 1, 60)
	gone.Obsolete = true
	live := intentItem(t, 2, 120)
	outbox := &memOutbox{items: []control.RuleOutput{gone, live}}
	adm := &scriptedAdmitter{admit: func(_ int, b model.Batch) (model.Receipt, error) { return okReceipt(b), nil }}
	report, err := newWorker(t, adm, outbox, fakeFence{}).Flush(context.Background(), auth.Scope{}, testLease, 5)
	if err != nil || !reflect.DeepEqual(report.Suppressed, []model.ID{{1}}) || !reflect.DeepEqual(report.Finalized, []model.ID{{2}}) || adm.calls != 1 {
		t.Fatalf("report %+v err %v admissions %d", report, err, adm.calls)
	}
	if outbox.phase(model.ID{1}) != control.RulePhaseSuppress || outbox.items[0].Reason != "obsolete_origin" || outbox.items[0].Receipt != nil {
		t.Fatalf("obsolete intent: %+v", outbox.items[0])
	}
}

// Admission can fail for ever (the source is gone, its policy moved, the batch is
// invalid) or only for now. The first retires the intent with a visible reason,
// the second leaves it to be retried.
func TestFlushClassifiesAdmissionFailures(t *testing.T) {
	for _, c := range []struct {
		err       error
		suppress  bool
		reason    string
		lookedUp  bool
		finalized bool
	}{
		{err: model.Fail(model.Forbidden), suppress: true, reason: "admission_forbidden"},
		{err: model.Fail(model.NotFound), suppress: true, reason: "admission_not_found"},
		{err: model.Fail(model.Stale), lookedUp: true}, // a policy revision bump: refreshable, never a reason to give up
		{err: model.Fail(model.Invalid), suppress: true, reason: "admission_invalid"},
		{err: model.Fail(model.Conflict), suppress: true, reason: "admission_conflict"},
		{err: model.Fail(model.Unavailable), lookedUp: true},
		{err: model.Fail(model.Timeout), lookedUp: true},
		{err: model.Fail(model.Quota), lookedUp: true},
		{err: model.Fail(model.Unauthenticated), lookedUp: true},
		{err: errors.New("connection reset"), lookedUp: true},
	} {
		outbox := &memOutbox{items: []control.RuleOutput{intentItem(t, 1, 60)}}
		adm := &scriptedAdmitter{admit: func(int, model.Batch) (model.Receipt, error) { return model.Receipt{}, c.err }}
		report, err := newWorker(t, adm, outbox, fakeFence{}).Flush(context.Background(), auth.Scope{}, testLease, 5)
		if err != nil {
			t.Fatalf("%v: %v", c.err, err)
		}
		if c.suppress {
			if len(report.Suppressed) != 1 || outbox.items[0].Reason != c.reason || adm.looked != 0 {
				t.Errorf("%v: %+v reason=%q lookups=%d", c.err, report, outbox.items[0].Reason, adm.looked)
			}
			continue
		}
		if len(report.Retried) != 1 || len(report.Finalized)+len(report.Suppressed) != 0 || outbox.phase(model.ID{1}) != control.RulePhasePending || adm.looked != 1 {
			t.Errorf("%v: %+v phase=%s lookups=%d", c.err, report, outbox.phase(model.ID{1}), adm.looked)
		}
	}
}

// After an ambiguous admission C03's receipt lookup decides: found means admitted
// (never admitted twice), and a receipt that names another batch is corruption.
func TestFlushUsesReceiptLookupAfterAmbiguousAdmission(t *testing.T) {
	outbox := &memOutbox{items: []control.RuleOutput{intentItem(t, 1, 60)}}
	adm := &scriptedAdmitter{
		admit:  func(int, model.Batch) (model.Receipt, error) { return model.Receipt{}, model.Fail(model.Timeout) },
		lookup: func(b model.Batch) (model.Receipt, bool, error) { return okReceipt(b), true, nil },
	}
	report, err := newWorker(t, adm, outbox, fakeFence{}).Flush(context.Background(), auth.Scope{}, testLease, 5)
	if err != nil || len(report.Finalized) != 1 || adm.calls != 1 || adm.looked != 1 {
		t.Fatalf("%+v %v calls=%d lookups=%d", report, err, adm.calls, adm.looked)
	}
	// A lookup that itself fails leaves the output for the next flush.
	outbox = &memOutbox{items: []control.RuleOutput{intentItem(t, 1, 60)}}
	adm = &scriptedAdmitter{
		admit: func(int, model.Batch) (model.Receipt, error) { return model.Receipt{}, model.Fail(model.Timeout) },
		lookup: func(model.Batch) (model.Receipt, bool, error) {
			return model.Receipt{}, false, model.Fail(model.Unavailable)
		},
	}
	if report, err = newWorker(t, adm, outbox, fakeFence{}).Flush(context.Background(), auth.Scope{}, testLease, 5); err != nil || len(report.Retried) != 1 || outbox.phase(model.ID{1}) != control.RulePhasePending {
		t.Fatalf("failed lookup: %+v %v", report, err)
	}
	// A receipt for another batch is never recorded.
	outbox = &memOutbox{items: []control.RuleOutput{intentItem(t, 1, 60)}}
	adm = &scriptedAdmitter{admit: func(_ int, b model.Batch) (model.Receipt, error) {
		r := okReceipt(b)
		r.BatchID = model.ID{9}
		return r, nil
	}}
	if _, err = newWorker(t, adm, outbox, fakeFence{}).Flush(context.Background(), auth.Scope{}, testLease, 5); code(err) != model.Corrupt || len(outbox.settled) != 0 {
		t.Fatalf("a receipt for another batch: %v", err)
	}
}

// A control failure ends the flush at once: whatever was already released stays
// reported, the rest is untouched, and the intent is retried from where it was.
func TestFlushStopsOnControlFailureAndResumes(t *testing.T) {
	outbox := &memOutbox{items: []control.RuleOutput{intentItem(t, 1, 60), intentItem(t, 2, 120)}, failOn: control.RulePhaseFinalized}
	adm := &scriptedAdmitter{admit: func(_ int, b model.Batch) (model.Receipt, error) { return okReceipt(b), nil }}
	w := newWorker(t, adm, outbox, fakeFence{})
	if report, err := w.Flush(context.Background(), auth.Scope{}, testLease, 5); err == nil || len(report.Finalized) != 0 || adm.calls != 1 {
		t.Fatalf("%+v %v calls=%d", report, err, adm.calls)
	}
	if outbox.phase(model.ID{1}) != control.RulePhaseAdmitted || outbox.phase(model.ID{2}) != control.RulePhasePending {
		t.Fatalf("phases %s %s", outbox.phase(model.ID{1}), outbox.phase(model.ID{2}))
	}
	outbox.failOn = ""
	report, err := w.Flush(context.Background(), auth.Scope{}, testLease, 5)
	if err != nil || len(report.Finalized) != 2 || adm.calls != 2 {
		t.Fatalf("resume: %+v %v calls=%d", report, err, adm.calls)
	}
}

// Condition outputs belong to the incident side; the worker neither admits nor
// finalizes them, and a corrupt payload is an error, not a silent skip.
func TestFlushLeavesConditionsAndRejectsCorruptPayload(t *testing.T) {
	cond := control.RuleOutput{ID: model.ID{8}, Kind: control.RuleOutputCondition, Phase: control.RulePhasePending, Payload: json.RawMessage(`{}`)}
	outbox := &memOutbox{items: []control.RuleOutput{cond}}
	adm := &scriptedAdmitter{admit: func(int, model.Batch) (model.Receipt, error) { return model.Receipt{}, errors.New("unreachable") }}
	if report, err := newWorker(t, adm, outbox, fakeFence{}).Flush(context.Background(), auth.Scope{}, testLease, 5); err != nil || adm.calls != 0 || len(report.Finalized) != 0 || outbox.phase(model.ID{8}) != control.RulePhasePending {
		t.Fatalf("condition output touched: %+v %v", report, err)
	}
	bad := intentItem(t, 1, 60)
	bad.Payload = json.RawMessage(`{"id":"zz"}`)
	outbox = &memOutbox{items: []control.RuleOutput{bad}}
	if _, err := newWorker(t, adm, outbox, fakeFence{}).Flush(context.Background(), auth.Scope{}, testLease, 5); code(err) != model.Corrupt || adm.calls != 0 {
		t.Fatalf("corrupt payload: %v", err)
	}
	// An intent whose payload names another output is not this output.
	swapped := intentItem(t, 1, 60)
	swapped.ID = model.ID{2}
	outbox = &memOutbox{items: []control.RuleOutput{swapped}}
	if _, err := newWorker(t, adm, outbox, fakeFence{}).Flush(context.Background(), auth.Scope{}, testLease, 5); code(err) != model.Corrupt || adm.calls != 0 {
		t.Fatalf("mismatched payload identity: %v", err)
	}
}
