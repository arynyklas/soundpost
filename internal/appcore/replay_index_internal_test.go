// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"soundpost/internal/auth"
	"soundpost/internal/model"
)

// The decorator is proved here against doubles that record every call; the real
// engine, control store and Raft are exercised in replay_index_test.go.

type appendDouble struct {
	log      *[]string
	receipt  model.Receipt
	err      error
	appends  int
	lookups  int
	lastSeen model.NormalizedBatch
}

func (d *appendDouble) Append(_ context.Context, _ auth.Scope, b model.NormalizedBatch) (model.Receipt, error) {
	d.appends++
	d.lastSeen = b
	*d.log = append(*d.log, "append")
	return d.receipt, d.err
}

func (d *appendDouble) LookupReceipt(context.Context, auth.Scope, model.ReceiptRequest) (model.Receipt, error) {
	d.lookups++
	return d.receipt, d.err
}

type indexDouble struct {
	log      *[]string
	checkErr func(model.ReplayChunk) error
	recErr   func(model.ReplayChunk) error
	checked  []model.ReplayChunk
	recorded []model.ReplayChunk
	retains  []model.UnixNano
}

func (d *indexDouble) CheckIndex(_ context.Context, _ auth.Scope, _ model.ID, c model.ReplayChunk) error {
	d.checked = append(d.checked, c)
	*d.log = append(*d.log, "check")
	if d.checkErr != nil {
		return d.checkErr(c)
	}
	return nil
}

func (d *indexDouble) RecordScope(_ context.Context, _ auth.Scope, _ model.ID, c model.ReplayChunk, retain model.UnixNano) error {
	d.recorded = append(d.recorded, c)
	d.retains = append(d.retains, retain)
	*d.log = append(*d.log, "record")
	if d.recErr != nil {
		return d.recErr(c)
	}
	return nil
}

type decorated struct {
	app   *appendDouble
	index *indexDouble
	wrap  *replayIndexingAppender
	log   *[]string
	now   time.Time
}

const replayDeadline = model.UnixNano(1_900_000_000_000_000_000)

func newDecorated(t *testing.T) *decorated {
	t.Helper()
	log := &[]string{}
	d := &decorated{log: log, now: time.Unix(0, 1_800_000_000_000_000_000)}
	d.app = &appendDouble{log: log, receipt: model.Receipt{Version: 1, BatchID: model.NewID(), Cursor: model.Cursor{Index: 7},
		SignalDeadlines: []model.SignalDeadline{{Kind: model.Log, RetainUntil: replayDeadline + 5}, {Kind: model.Replay, RetainUntil: replayDeadline}}}}
	d.index = &indexDouble{log: log}
	w, err := NewReplayIndexingAppender(d.app, d.index)
	if err != nil {
		t.Fatal(err)
	}
	d.wrap = w.(*replayIndexingAppender)
	d.wrap.now = func() time.Time { return d.now }
	return d
}

func faultOf(err error) model.Code {
	var f *model.Fault
	if errors.As(err, &f) {
		return f.Code
	}
	return ""
}

func replayChunk(replay, session model.ID, sequence, checkpoint uint64) model.ReplayChunk {
	return model.ReplayChunk{Replay: replay, Session: session, Recorder: "1", Sequence: model.Uint64(sequence), CheckpointSequence: model.Uint64(checkpoint), PolicyRevision: 1,
		Clock: model.TraceClock{Wall: 1, Mono: 1, Domain: model.ClockDomain{Host: model.ID{1}, Boot: model.ID{2}, Runtime: model.ID{3}}}}
}

func replayRecord(c model.ReplayChunk) model.Record {
	return model.Record{ID: model.NewID(), Kind: model.Replay, Payload: model.Payload{Replay: &c}}
}

func batchOf(records ...model.Record) model.NormalizedBatch {
	return model.NormalizedBatch{Batch: model.Batch{Version: 1, Project: model.NewID(), ID: model.NewID(), Records: records}}
}

func logs(d *decorated) string { return strings.Join(*d.log, ",") }

// A batch with no replay record costs the index nothing: it is not read, not
// recorded, and the batch and receipt are the inner appender's own.
func TestReplayIndexingAppenderPassesBatchesWithoutReplayRecordsThroughUntouched(t *testing.T) {
	d := newDecorated(t)
	b := batchOf(model.Record{ID: model.NewID(), Kind: model.Log}, model.Record{ID: model.NewID(), Kind: model.Metric})
	got, err := d.wrap.Append(context.Background(), auth.Scope{}, b)
	if err != nil || got.BatchID != d.app.receipt.BatchID || got.Cursor != d.app.receipt.Cursor {
		t.Fatalf("receipt %+v err %v", got, err)
	}
	if len(d.index.checked) != 0 || len(d.index.recorded) != 0 || logs(d) != "append" {
		t.Fatalf("a batch without a replay record touched the index: %s", logs(d))
	}
	if d.app.lastSeen.ID != b.ID || len(d.app.lastSeen.Records) != 2 {
		t.Fatal("the inner appender did not get the batch as it was")
	}
	// An error of the inner appender is returned as it is, unindexed.
	d.app.err = model.Fail(model.Quota)
	if _, err = d.wrap.Append(context.Background(), auth.Scope{}, b); faultOf(err) != model.Quota || len(d.index.checked) != 0 {
		t.Fatalf("err %v", err)
	}
}

// A replay record with no chunk never reaches storage (the ingest gate refuses
// it first; the decorator does not trust that).
func TestReplayIndexingAppenderRefusesAReplayRecordWithoutAChunk(t *testing.T) {
	d := newDecorated(t)
	_, err := d.wrap.Append(context.Background(), auth.Scope{}, batchOf(model.Record{ID: model.NewID(), Kind: model.Replay}))
	if faultOf(err) != model.Invalid || d.app.appends != 0 || len(d.index.checked) != 0 {
		t.Fatalf("err %v log %s", err, logs(d))
	}
}

// The index is consulted before the append and written after it: a chunk the
// index would refuse is never stored, and the index never learns of a chunk the
// append did not store.
func TestReplayIndexingAppenderChecksBeforeAndRecordsAfterTheAppend(t *testing.T) {
	d := newDecorated(t)
	c := replayChunk(model.NewID(), model.NewID(), 1, 1)
	got, err := d.wrap.Append(context.Background(), auth.Scope{}, batchOf(replayRecord(c)))
	if err != nil || got.Cursor.Index != 7 {
		t.Fatalf("%+v %v", got, err)
	}
	if logs(d) != "check,append,record" {
		t.Fatalf("order %s", logs(d))
	}
	if len(d.index.retains) != 1 || d.index.retains[0] != replayDeadline {
		t.Fatalf("recorded deadline %v, want the receipt's replay deadline %d (not another signal's)", d.index.retains, replayDeadline)
	}

	// The append is refused (quota): the index is checked but never written.
	d2 := newDecorated(t)
	d2.app.err = model.Fail(model.Quota)
	if _, err = d2.wrap.Append(context.Background(), auth.Scope{}, batchOf(replayRecord(c))); faultOf(err) != model.Quota || logs(d2) != "check,append" {
		t.Fatalf("err %v order %s", err, logs(d2))
	}
}

// What the index refuses is refused before the append, as the index's own typed
// fault, and nothing is stored.
func TestReplayIndexingAppenderRefusesAConflictingChunkBeforeStoringIt(t *testing.T) {
	for _, code := range []model.Code{model.Conflict, model.TooLarge, model.Unavailable} {
		d := newDecorated(t)
		d.index.checkErr = func(model.ReplayChunk) error { return model.Fail(code) }
		_, err := d.wrap.Append(context.Background(), auth.Scope{}, batchOf(replayRecord(replayChunk(model.NewID(), model.NewID(), 1, 1))))
		if faultOf(err) != code || d.app.appends != 0 || len(d.index.recorded) != 0 {
			t.Fatalf("%s: err %v log %s", code, err, logs(d))
		}
	}
}

// The original receipt of a retried batch is indexed like a fresh one, whatever
// it says about itself: the retry of a batch whose index step was lost is the
// repair, and the index step is idempotent.
func TestReplayIndexingAppenderRecordsTheReceiptOfARetriedBatchToo(t *testing.T) {
	for _, historical := range []bool{false, true} {
		d := newDecorated(t)
		d.app.receipt.Historical = historical
		c := replayChunk(model.NewID(), model.NewID(), 1, 1)
		b := batchOf(replayRecord(c))
		for attempt := 1; attempt <= 2; attempt++ {
			got, err := d.wrap.Append(context.Background(), auth.Scope{}, b)
			if err != nil || got.Historical != historical || got.Cursor.Index != 7 {
				t.Fatalf("historical=%v attempt %d: %+v %v", historical, attempt, got, err)
			}
			if len(d.index.recorded) != attempt {
				t.Fatalf("historical=%v: %d records after %d attempts", historical, len(d.index.recorded), attempt)
			}
		}
	}
}

// A failed index step is never an acknowledgement: the receipt is dropped and the
// sender gets a bare typed fault, so it retries (or, for a conflict, stops).
func TestReplayIndexingAppenderNeverAcknowledgesAFailedIndexStep(t *testing.T) {
	const canary = "CANARYINDEXe6b1a07d3c5f"
	for name, c := range map[string]struct {
		err  error
		want model.Code
	}{
		"unavailable":          {model.Fail(model.Unavailable), model.Unavailable},
		"corrupt index":        {model.Fail(model.Corrupt), model.Corrupt},
		"race lost to a pin":   {model.Fail(model.Conflict), model.Conflict},
		"driver error":         {errors.New("raft proposal failed " + canary), model.Unavailable},
		"fault with a detail":  {&model.Fault{Code: model.Unavailable, SafeDetail: canary}, model.Unavailable},
		"wrapped typed fault":  {errors.Join(errors.New(canary), model.Fail(model.Timeout)), model.Timeout},
		"deadline of the call": {context.DeadlineExceeded, model.Unavailable},
	} {
		d := newDecorated(t)
		d.index.recErr = func(model.ReplayChunk) error { return c.err }
		got, err := d.wrap.Append(context.Background(), auth.Scope{}, batchOf(replayRecord(replayChunk(model.NewID(), model.NewID(), 1, 1))))
		if err == nil || got.BatchID != (model.ID{}) || got.Cursor != (model.Cursor{}) {
			t.Fatalf("%s: a failed index step was acknowledged: %+v %v", name, got, err)
		}
		if faultOf(err) != c.want {
			t.Fatalf("%s: code %q, want %q", name, faultOf(err), c.want)
		}
		if strings.Contains(err.Error(), canary) {
			t.Fatalf("%s: the error carries index text: %v", name, err)
		}
		if d.app.appends != 1 {
			t.Fatalf("%s: %d appends", name, d.app.appends)
		}
	}
}

// A batch that contradicts itself is refused before any of it is stored; the same
// checkpoint twice in one batch is asked of the index once.
func TestReplayIndexingAppenderRefusesABatchThatContradictsItself(t *testing.T) {
	replay, session := model.NewID(), model.NewID()
	cp := replayChunk(replay, session, 5, 5)
	forged := cp
	forged.Events = []model.MaskedEvent{{At: 1, Kind: "pointer"}}
	foreign := replayChunk(replay, model.NewID(), 6, 5)
	for name, records := range map[string][]model.Record{
		"two different checkpoints at one sequence": {replayRecord(cp), replayRecord(forged)},
		"two sessions for one replay root":          {replayRecord(cp), replayRecord(foreign)},
		"a foreign session first":                   {replayRecord(foreign), replayRecord(cp)},
	} {
		d := newDecorated(t)
		_, err := d.wrap.Append(context.Background(), auth.Scope{}, batchOf(records...))
		if faultOf(err) != model.Conflict || d.app.appends != 0 || len(d.index.checked) != 0 {
			t.Fatalf("%s: err %v log %s", name, err, logs(d))
		}
	}
	d := newDecorated(t)
	if _, err := d.wrap.Append(context.Background(), auth.Scope{}, batchOf(replayRecord(cp), replayRecord(cp))); err != nil {
		t.Fatal(err)
	}
	if len(d.index.checked) != 1 || len(d.index.recorded) != 1 {
		t.Fatalf("the same checkpoint twice was asked %d times and recorded %d times", len(d.index.checked), len(d.index.recorded))
	}
}

// The index is asked for the first chunk of each replay (the root session) and
// for every checkpoint, in batch order, and only for replay records of a mixed
// batch.
func TestReplayIndexingAppenderAsksTheIndexOnlyWhatItCanAnswerDifferently(t *testing.T) {
	a, b := model.NewID(), model.NewID()
	sa, sb := model.NewID(), model.NewID()
	d := newDecorated(t)
	batch := batchOf(
		model.Record{ID: model.NewID(), Kind: model.Log},
		replayRecord(replayChunk(a, sa, 1, 1)),
		replayRecord(replayChunk(a, sa, 2, 1)),
		replayRecord(replayChunk(b, sb, 9, 1)),
		model.Record{ID: model.NewID(), Kind: model.Metric},
		replayRecord(replayChunk(a, sa, 3, 1)),
		replayRecord(replayChunk(a, sa, 4, 4)),
		replayRecord(replayChunk(b, sb, 10, 1)),
	)
	if _, err := d.wrap.Append(context.Background(), auth.Scope{}, batch); err != nil {
		t.Fatal(err)
	}
	want := []struct {
		replay   model.ID
		sequence model.Uint64
	}{{a, 1}, {b, 9}, {a, 4}}
	for _, got := range [][]model.ReplayChunk{d.index.checked, d.index.recorded} {
		if len(got) != len(want) {
			t.Fatalf("index saw %d chunks, want %d", len(got), len(want))
		}
		for i, w := range want {
			if got[i].Replay != w.replay || got[i].Sequence != w.sequence {
				t.Fatalf("index chunk %d is replay %s sequence %d, want %s %d", i, got[i].Replay, got[i].Sequence, w.replay, w.sequence)
			}
		}
	}
	if logs(d) != "check,check,check,append,record,record,record" {
		t.Fatalf("order %s", logs(d))
	}
}

// A receipt whose replay deadline has passed protects and indexes nothing: the
// retried batch gets its original receipt. A receipt of a replay batch with no
// replay deadline is not trusted.
func TestReplayIndexingAppenderHandlesAnExpiredOrMissingDeadline(t *testing.T) {
	d := newDecorated(t)
	d.now = time.Unix(0, int64(replayDeadline)+1)
	got, err := d.wrap.Append(context.Background(), auth.Scope{}, batchOf(replayRecord(replayChunk(model.NewID(), model.NewID(), 1, 1))))
	if err != nil || got.Cursor.Index != 7 || len(d.index.recorded) != 0 {
		t.Fatalf("expired: %+v %v recorded %d", got, err, len(d.index.recorded))
	}
	for name, deadlines := range map[string][]model.SignalDeadline{
		"no deadline at all":     nil,
		"only another signal's":  {{Kind: model.Log, RetainUntil: replayDeadline}},
		"a zero replay deadline": {{Kind: model.Replay}},
	} {
		d = newDecorated(t)
		d.app.receipt.SignalDeadlines = deadlines
		got, err = d.wrap.Append(context.Background(), auth.Scope{}, batchOf(replayRecord(replayChunk(model.NewID(), model.NewID(), 1, 1))))
		if faultOf(err) != model.Corrupt || got.BatchID != (model.ID{}) || got.Cursor != (model.Cursor{}) || len(d.index.recorded) != 0 {
			t.Fatalf("%s: %+v %v", name, got, err)
		}
	}
}

// The receipt lookup is the inner appender's own: a historical receipt carries no
// chunk, so there is nothing for the index to record (see docs/protocol/replay-v1.md).
func TestReplayIndexingAppenderLeavesReceiptLookupToTheInnerAppender(t *testing.T) {
	d := newDecorated(t)
	got, err := d.wrap.LookupReceipt(context.Background(), auth.Scope{}, model.ReceiptRequest{})
	if err != nil || got.BatchID != d.app.receipt.BatchID || d.app.lookups != 1 || len(d.index.checked)+len(d.index.recorded) != 0 {
		t.Fatalf("%+v %v", got, err)
	}
}

func TestNewReplayIndexingAppenderNeedsBothParts(t *testing.T) {
	log := &[]string{}
	if _, err := NewReplayIndexingAppender(nil, &indexDouble{log: log}); faultOf(err) != model.Invalid {
		t.Fatal("nil inner accepted")
	}
	if _, err := NewReplayIndexingAppender(&appendDouble{log: log}, nil); faultOf(err) != model.Invalid {
		t.Fatal("nil index accepted")
	}
}
