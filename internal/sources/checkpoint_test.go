// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package sources

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"soundpost/internal/model"
)

// The durable checkpoint advances only with the receipts of the pending range.
// A lost acknowledgement or a restart neither skips records nor produces a
// second logical admission.
func TestSourceCheckpointAfterACK(t *testing.T) {
	ctx := context.Background()
	file := filepath.Join(t.TempDir(), "app.log")
	appendLines(t, file,
		"service started unit alpha",
		"request status 503",
		"password reset for carol", // unknown: must never be exported
		"service started unit beta",
	)
	p := baseFilePolicy(t, file)
	store, dir := mustStore(t)
	server := newRecorder()
	server.loseAck = true // the batch is stored, the receipt never arrives
	pump := newPump(t, p, store, server)

	if _, err := pump.Cycle(ctx); err == nil {
		t.Fatal("cycle with a lost acknowledgement reported success")
	}
	cp, err := store.Load("app")
	if err != nil {
		t.Fatal(err)
	}
	if cp.Position.Offset != 0 || cp.Admitted != 0 || len(cp.Counters) != 0 {
		t.Fatalf("checkpoint advanced without a receipt: %+v", cp)
	}
	if cp.Pending == nil || cp.Pending.Records != 3 || cp.Pending.Scanned != 4 {
		t.Fatalf("pending intent was not durably recorded before submission: %+v", cp.Pending)
	}
	intent := *cp.Pending

	// Process restart: a new store and a new pump over the same state
	// directory. Two more records arrive while the agent was down.
	appendLines(t, file, "request status 200", "service started unit alpha")
	store2, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	server.loseAck = false
	pump2 := newPump(t, p, store2, server)
	res, err := pump2.Cycle(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.Admitted != 3 {
		t.Fatalf("retry admitted %d records, want the 3 of the pending range", res.Admitted)
	}
	cp, err = store2.Load("app")
	if err != nil {
		t.Fatal(err)
	}
	if cp.Pending != nil || cp.Admitted != 3 || cp.Counters[DropUnknownTemplate] != 1 {
		t.Fatalf("after the receipt: %+v", cp)
	}
	// the retry presented the very same batch: no second logical admission
	want := []string{"service started unit alpha", "request status 503", "service started unit beta"}
	if got := server.lines(); !reflect.DeepEqual(got, want) {
		t.Fatalf("admitted lines after retry %q, want %q", got, want)
	}
	for id, n := range server.ids() {
		if n != 1 {
			t.Fatalf("record %s admitted %d times", id, n)
		}
	}
	if len(server.batches) != 1 || server.batches[0].ID != BatchID(intent.Group, PartLogs) {
		t.Fatalf("retry used a different batch than the recorded intent")
	}

	// the records written while down are read next, not skipped
	if _, err = pump2.Cycle(ctx); err != nil {
		t.Fatal(err)
	}
	want = append(want, "request status 200", "service started unit alpha")
	if got := server.lines(); !reflect.DeepEqual(got, want) {
		t.Fatalf("admitted lines %q, want %q", got, want)
	}
	cp, _ = store2.Load("app")
	if cp.Admitted != 5 {
		t.Fatalf("admitted total %d, want 5", cp.Admitted)
	}
	// nothing new: no batch, no change
	calls := server.calls
	if res, err = pump2.Cycle(ctx); err != nil || res.Batches != 0 || server.calls != calls {
		t.Fatalf("idle cycle submitted data: %+v %v", res, err)
	}
}

func TestSourceCheckpointRefusesWithoutMatchingReceipt(t *testing.T) {
	ctx := context.Background()
	file := filepath.Join(t.TempDir(), "app.log")
	appendLines(t, file, "service started unit alpha", "request status 200")
	p := baseFilePolicy(t, file)
	store, _ := mustStore(t)

	recs, next, err := Read(ctx, p, Checkpoint{Version: 1, Source: "app"})
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("read %d records", len(recs))
	}
	if next.Position != (Position{}) {
		t.Fatalf("Read advanced the committed position: %+v", next.Position)
	}
	if next.Pending == nil || next.Pending.To.Offset == 0 {
		t.Fatalf("Read did not describe the range: %+v", next.Pending)
	}
	// Prepare may record the intent but never move the position
	moved := next
	moved.Position = next.Pending.To
	if err := store.Prepare(moved); err == nil {
		t.Fatal("Prepare advanced the position")
	}
	if err := store.Prepare(next); err != nil {
		t.Fatal(err)
	}
	for name, receipts := range map[string][]model.Receipt{
		"none":         nil,
		"other":        {{Version: 1, BatchID: model.ID{9}, Cursor: model.Cursor{Group: model.ID{1}, Index: 1}}},
		"empty cursor": {{Version: 1, BatchID: BatchID(next.Pending.Group, PartLogs)}},
		"extra receipt": {
			{Version: 1, BatchID: BatchID(next.Pending.Group, PartLogs), Cursor: model.Cursor{Group: model.ID{1}, Index: 4}},
			{Version: 1, BatchID: model.ID{9}, Cursor: model.Cursor{Group: model.ID{1}, Index: 5}},
		},
		"duplicate receipt": {
			{Version: 1, BatchID: BatchID(next.Pending.Group, PartLogs), Cursor: model.Cursor{Group: model.ID{1}, Index: 4}},
			{Version: 1, BatchID: BatchID(next.Pending.Group, PartLogs), Cursor: model.Cursor{Group: model.ID{1}, Index: 4}},
		},
	} {
		if _, err := store.Commit("app", receipts...); err == nil {
			t.Fatalf("%s: committed without the matching receipt", name)
		}
		cp, _ := store.Load("app")
		if cp.Position != (Position{}) || cp.Admitted != 0 || cp.Pending == nil {
			t.Fatalf("%s: state moved: %+v", name, cp)
		}
	}
	// the matching receipt commits
	rc := model.Receipt{Version: 1, BatchID: BatchID(next.Pending.Group, PartLogs), Cursor: model.Cursor{Group: model.ID{1}, Index: 4}}
	cp, err := store.Commit("app", rc)
	if err != nil {
		t.Fatal(err)
	}
	if cp.Position != next.Pending.To || cp.Admitted != 2 || cp.Pending != nil {
		t.Fatalf("commit result %+v", cp)
	}
	// a second commit of the same receipt has nothing pending
	if _, err := store.Commit("app", rc); err == nil {
		t.Fatal("double commit accepted")
	}
}

// A corrupt checkpoint is an error. Resetting it would silently skip records.
func TestSourceCheckpointCorruptIsError(t *testing.T) {
	store, dir := mustStore(t)
	file := filepath.Join(t.TempDir(), "app.log")
	appendLines(t, file, "service started unit alpha")
	pump := newPump(t, baseFilePolicy(t, file), store, newRecorder())
	if _, err := pump.Cycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "app.checkpoint.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(string) string{
		"flipped offset": func(s string) string { return strings.Replace(s, `"offset":27`, `"offset":1`, 1) },
		"truncated":      func(s string) string { return s[:len(s)/2] },
	} {
		mutated := mutate(string(raw))
		if mutated == string(raw) {
			t.Fatalf("%s: mutation did not change the file", name)
		}
		if err := os.WriteFile(path, []byte(mutated), 0600); err != nil {
			t.Fatal(err)
		}
		_, err := store.Load("app")
		se, ok := AsError(err)
		if !ok || se.Reason != ReasonCheckpointCorrup {
			t.Fatalf("%s: got %v, want checkpoint_corrupt", name, err)
		}
	}
}

// The same lost-acknowledgement drill against a real node: real source grant,
// real C03 receipt ledger and real C05 storage.
func TestSourceCheckpointAfterACKRealIngest(t *testing.T) {
	ctx := context.Background()
	res := testResource()
	node := newRealNode(t, res, testTemplates(t), map[string][]string{"source": {"app"}})
	file := filepath.Join(t.TempDir(), "app.log")
	appendLines(t, file, "service started unit alpha", "request status 503", "service started unit beta")
	p := baseFilePolicy(t, file)
	p.Resource = res
	store, dir := mustStore(t)

	lost := &loseAckOnce{inner: node}
	pump := &Pump{Policy: p, Store: store, ID: node.identity(), Submit: lost}
	if _, err := pump.Cycle(ctx); err == nil {
		t.Fatal("lost acknowledgement reported as success")
	}
	if got := node.storedLines(); len(got) != 3 {
		t.Fatalf("the batch was admitted before the acknowledgement was lost: stored %q", got)
	}
	cp, _ := store.Load("app")
	if cp.Position.Offset != 0 || cp.Pending == nil {
		t.Fatalf("checkpoint moved without a receipt: %+v", cp)
	}
	store2, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	pump2 := &Pump{Policy: p, Store: store2, ID: node.identity(), Submit: node}
	if _, err := pump2.Cycle(ctx); err != nil {
		t.Fatal(err)
	}
	got := node.storedLines()
	want := []string{"service started unit alpha", "request status 503", "service started unit beta"}
	if !reflect.DeepEqual(sortedCopy(got), sortedCopy(want)) {
		t.Fatalf("stored lines after the retry %q, want exactly %q (no skip, no duplicate)", got, want)
	}
}

type loseAckOnce struct {
	inner Submitter
	done  bool
}

func (l *loseAckOnce) Admit(ctx context.Context, b model.Batch) (model.Receipt, error) {
	r, err := l.inner.Admit(ctx, b)
	if err == nil && !l.done {
		l.done = true
		return model.Receipt{}, model.Fail(model.Unavailable)
	}
	return r, err
}

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
