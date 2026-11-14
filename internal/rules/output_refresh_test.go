// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package rules

import (
	"context"
	"errors"
	"math"
	"reflect"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

// batchItem is a pending recording output whose batch carries n series.
func batchItem(t *testing.T, seed byte, at int64, n int) control.RuleOutput {
	t.Helper()
	item := intentItem(t, seed, at)
	var intent RecordingIntent
	if err := model.StrictJSON(item.Payload, &intent); err != nil {
		t.Fatal(err)
	}
	first := intent.Batch.Records[0]
	intent.Batch.Records = nil
	for i := range n {
		r := first
		r.ID = model.ID{seed, byte(i)}
		v := model.FloatBits(math.Float64bits(float64(i)))
		point := *first.Payload.Metric
		point.Labels, point.Value = model.Labels{{Name: "series", Value: string(rune('a' + i))}}, &v
		r.Payload = model.Payload{Metric: &point}
		intent.Batch.Records = append(intent.Batch.Records, r)
	}
	raw, err := model.CanonicalJSON(intent)
	if err != nil {
		t.Fatal(err)
	}
	item.Payload = raw
	return item
}

func refresher(source, producerID model.ID, revision *model.Revision) ProducerResolver {
	return func(context.Context) (ProducerIdentity, error) {
		return ProducerIdentity{Source: source, Producer: producerID, PolicyRevision: *revision, Resource: producer().Resource}, nil
	}
}

// A routine source-policy revision bump between commit and flush must not
// suppress the pending recording for good: the worker re-resolves the producer
// and admits the same batch (same identity, same samples) at the current
// revision.
func TestFlushRefreshesTheProducerAfterAPolicyRevisionBump(t *testing.T) {
	current := model.Revision(2)
	build := func(options ...OutputOption) (*OutputWorker, *memOutbox, *scriptedAdmitter, *[]model.Batch) {
		outbox := &memOutbox{items: []control.RuleOutput{intentItem(t, 1, 60)}}
		var stored []model.Batch
		adm := &scriptedAdmitter{admit: func(_ int, b model.Batch) (model.Receipt, error) {
			if b.PolicyRevision != current {
				return model.Receipt{}, model.Fail(model.Stale)
			}
			stored = append(stored, b)
			return okReceipt(b), nil
		}}
		return newWorkerWith(t, adm, outbox, options...), outbox, adm, &stored
	}
	same := intentItem(t, 1, 60)
	var original RecordingIntent
	if err := model.StrictJSON(same.Payload, &original); err != nil {
		t.Fatal(err)
	}

	t.Run("refreshed", func(t *testing.T) {
		w, outbox, _, stored := build(WithProducerRefresh(refresher(model.ID{0xa1}, model.ID{0xa2}, &current)))
		report, err := w.Flush(context.Background(), auth.Scope{}, testLease, 5)
		if err != nil || !reflect.DeepEqual(report.Finalized, []model.ID{{1}}) || len(report.Suppressed)+len(report.Retried) != 0 {
			t.Fatalf("report %+v err %v", report, err)
		}
		if len(*stored) != 1 || (*stored)[0].PolicyRevision != 2 || (*stored)[0].ID != original.Batch.ID || !reflect.DeepEqual((*stored)[0].Records, original.Batch.Records) {
			t.Fatalf("admitted batch: %+v", *stored)
		}
		if outbox.phase(model.ID{1}) != control.RulePhaseFinalized {
			t.Fatalf("phase %s", outbox.phase(model.ID{1}))
		}
	})
	t.Run("no refresher: pending, visible, retried", func(t *testing.T) {
		w, outbox, _, stored := build()
		report, err := w.Flush(context.Background(), auth.Scope{}, testLease, 5)
		if err != nil || len(report.Retried) != 1 || len(report.Suppressed) != 0 || len(*stored) != 0 || outbox.phase(model.ID{1}) != control.RulePhasePending {
			t.Fatalf("report %+v err %v phase %s", report, err, outbox.phase(model.ID{1}))
		}
	})
	t.Run("refresh finds the same revision", func(t *testing.T) {
		old := model.Revision(1)
		w, outbox, _, _ := build(WithProducerRefresh(refresher(model.ID{0xa1}, model.ID{0xa2}, &old)))
		report, err := w.Flush(context.Background(), auth.Scope{}, testLease, 5)
		if err != nil || len(report.Retried) != 1 || outbox.phase(model.ID{1}) != control.RulePhasePending {
			t.Fatalf("report %+v err %v", report, err)
		}
	})
	t.Run("a refreshed producer that moved sources cannot adopt the batch", func(t *testing.T) {
		w, outbox, _, stored := build(WithProducerRefresh(refresher(model.ID{0xb1}, model.ID{0xa2}, &current)))
		report, err := w.Flush(context.Background(), auth.Scope{}, testLease, 5)
		if err != nil || len(report.Suppressed) != 1 || len(*stored) != 0 || outbox.items[0].Reason != "admission_producer_changed" {
			t.Fatalf("report %+v err %v reason %q", report, err, outbox.items[0].Reason)
		}
	})
	t.Run("a refreshed producer identity that changed cannot adopt the batch", func(t *testing.T) {
		w, outbox, _, stored := build(WithProducerRefresh(refresher(model.ID{0xa1}, model.ID{0xb2}, &current)))
		report, err := w.Flush(context.Background(), auth.Scope{}, testLease, 5)
		if err != nil || len(report.Suppressed) != 1 || len(*stored) != 0 || outbox.items[0].Reason != "admission_producer_changed" {
			t.Fatalf("report %+v err %v reason %q", report, err, outbox.items[0].Reason)
		}
	})
	t.Run("refresh failure retries", func(t *testing.T) {
		w, outbox, _, _ := build(WithProducerRefresh(func(context.Context) (ProducerIdentity, error) {
			return ProducerIdentity{}, errors.New("control unavailable")
		}))
		report, err := w.Flush(context.Background(), auth.Scope{}, testLease, 5)
		if err != nil || len(report.Retried) != 1 || outbox.phase(model.ID{1}) != control.RulePhasePending {
			t.Fatalf("report %+v err %v", report, err)
		}
	})
}

// If the batch was in fact admitted before the bump (the response was lost), the
// receipt lookup decides, and nothing is admitted again at the new revision.
func TestFlushPrefersTheReceiptOfTheOriginalBatchOverARefresh(t *testing.T) {
	outbox := &memOutbox{items: []control.RuleOutput{intentItem(t, 1, 60)}}
	adm := &scriptedAdmitter{
		admit:  func(int, model.Batch) (model.Receipt, error) { return model.Receipt{}, model.Fail(model.Stale) },
		lookup: func(b model.Batch) (model.Receipt, bool, error) { return okReceipt(b), true, nil },
	}
	current := model.Revision(2)
	w := newWorkerWith(t, adm, outbox, WithProducerRefresh(refresher(model.ID{0xa1}, model.ID{0xa2}, &current)))
	report, err := w.Flush(context.Background(), auth.Scope{}, testLease, 5)
	if err != nil || len(report.Finalized) != 1 || adm.calls != 1 {
		t.Fatalf("report %+v err %v admissions %d", report, err, adm.calls)
	}
}

func newWorkerWith(t *testing.T, adm *scriptedAdmitter, outbox *memOutbox, options ...OutputOption) *OutputWorker {
	t.Helper()
	w, err := NewOutputWorker(adm, outbox, adm, fakeFence{}, options...)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

// A derived series that collides with an already-ingested sample is refused by
// admission for its whole batch. Only the colliding series is dropped, and it is
// reported; every other series of the slot is still admitted.
func TestFlushDropsOnlyTheCollidingSeries(t *testing.T) {
	collide := model.ID{1, 2}
	stored := map[model.ID]model.Batch{}
	admit := func(_ int, b model.Batch) (model.Receipt, error) {
		for _, r := range b.Records {
			if r.ID == collide {
				return model.Receipt{}, model.Fail(model.Conflict)
			}
		}
		stored[b.ID] = b
		return okReceipt(b), nil
	}
	item := batchItem(t, 1, 60, 4)
	outbox := &memOutbox{items: []control.RuleOutput{item}}
	adm := &scriptedAdmitter{admit: admit}
	report, err := newWorker(t, adm, outbox, fakeFence{}).Flush(context.Background(), auth.Scope{}, testLease, 5)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(report.Finalized, []model.ID{{1}}) || len(report.Suppressed)+len(report.Retried) != 0 {
		t.Fatalf("report %+v", report)
	}
	if !reflect.DeepEqual(report.Dropped, []DroppedRecord{{Output: item.ID, Record: collide, Reason: ReasonSeriesConflict}}) {
		t.Fatalf("dropped %+v", report.Dropped)
	}
	var records []model.ID
	for _, b := range stored {
		for _, r := range b.Records {
			records = append(records, r.ID)
		}
	}
	if len(records) != 3 || len(stored) != 3 {
		t.Fatalf("stored %v in %d batches, want the 3 non-colliding series", records, len(stored))
	}
	if outbox.phase(item.ID) != control.RulePhaseFinalized || outbox.items[0].Receipt == nil || outbox.items[0].Reason != "series_conflict:1" {
		t.Fatalf("output after the split: %+v", outbox.items[0])
	}

	// A flush after a transient failure while splitting changes nothing durable
	// twice: the split admissions have stable identities.
	stored = map[model.ID]model.Batch{}
	outbox = &memOutbox{items: []control.RuleOutput{item}}
	failing := true
	adm = &scriptedAdmitter{admit: func(n int, b model.Batch) (model.Receipt, error) {
		if failing && len(b.Records) == 1 && b.Records[0].ID == (model.ID{1, 3}) {
			return model.Receipt{}, model.Fail(model.Unavailable)
		}
		return admit(n, b)
	}}
	w := newWorker(t, adm, outbox, fakeFence{})
	if report, err = w.Flush(context.Background(), auth.Scope{}, testLease, 5); err != nil || len(report.Retried) != 1 || outbox.phase(item.ID) != control.RulePhasePending {
		t.Fatalf("transient failure while splitting: %+v %v", report, err)
	}
	failing = false
	if report, err = w.Flush(context.Background(), auth.Scope{}, testLease, 5); err != nil || len(report.Finalized) != 1 || len(stored) != 3 {
		t.Fatalf("retry: %+v %v stored=%d", report, err, len(stored))
	}
}

// When every series collides nothing is admitted and the output is suppressed
// with the closed reason, each dropped series reported.
func TestFlushSuppressesAnOutputWhoseEverySeriesCollides(t *testing.T) {
	item := batchItem(t, 1, 60, 2)
	outbox := &memOutbox{items: []control.RuleOutput{item}}
	adm := &scriptedAdmitter{admit: func(int, model.Batch) (model.Receipt, error) { return model.Receipt{}, model.Fail(model.Conflict) }}
	report, err := newWorker(t, adm, outbox, fakeFence{}).Flush(context.Background(), auth.Scope{}, testLease, 5)
	if err != nil || len(report.Suppressed) != 1 || len(report.Finalized) != 0 || len(report.Dropped) != 2 || outbox.items[0].Reason != "admission_conflict" {
		t.Fatalf("report %+v err %v reason %q", report, err, outbox.items[0].Reason)
	}
}
