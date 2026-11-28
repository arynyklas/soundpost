// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"math"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

func (x *eraseEnv) errorRecord(at model.UnixNano) model.Record {
	return model.Record{ID: model.NewID(), Kind: model.ErrorKind, ObservedAt: at, Resource: x.res, Payload: model.Payload{Error: &model.ErrorOccurrence{
		Occurrence: model.NewID(), Class: "TypeError", Mechanism: "manual", Build: x.res.Build, Frames: []model.Frame{}}}}
}

// appendError admits one batch of one error record whose evidence is retained until the instant.
func (x *eraseEnv) appendError(until model.UnixNano) (model.Record, model.Receipt) {
	x.t.Helper()
	rec := x.errorRecord(5)
	_, r, _ := x.appendRecords(model.NewID(), []model.SignalDeadline{{Kind: model.ErrorKind, RetainUntil: until}}, rec)
	return rec, r
}

func (x *eraseEnv) expiring(horizon model.UnixNano) map[model.Cursor]model.UnixNano {
	x.t.Helper()
	list, err := x.e.ExpiringErrorEvidence(context.Background(), horizon)
	if err != nil {
		x.t.Fatal(err)
	}
	out := map[model.Cursor]model.UnixNano{}
	for _, entry := range list {
		out[entry.Cursor] = entry.Deadline
	}
	if len(out) != len(list) {
		x.t.Fatalf("%d entries for %d cursors", len(list), len(out))
	}
	return out
}

func (x *eraseEnv) expiryRead() uint64 {
	x.e.expiry.mu.Lock()
	defer x.e.expiry.mu.Unlock()
	return x.e.expiry.scanned
}

// The journal-expiry plan, every 15 minutes, read every command of the history (the whole payload log at the single-host gate: 174,773
// reads in a 12 s window at 1,300 s, and 70 % of the log left in the page cache of the scope). A command is read once: the next plan reads
// the commands appended since, and the error evidence it found is kept. An erasure, which rewrites commands, starts the reading again.
func TestExpiringErrorEvidenceReadsEachCommandOnce(t *testing.T) {
	holdBackgroundVerification(t)
	x := newEraseEnv(t)
	x.adoptPayload()
	cursors := map[model.Cursor]model.UnixNano{}
	var first model.Record
	for i := range 4 {
		rec, r := x.appendError(model.UnixNano(100 + i))
		if i == 0 {
			first = rec
		}
		cursors[r.Cursor] = model.UnixNano(100 + i)
		x.appendMixed("plan", bothDeadlines)
	}
	same := func(label string, got, want map[model.Cursor]model.UnixNano) {
		t.Helper()
		if len(got) != len(want) {
			t.Fatalf("%s: %d entries, want %d (%v, %v)", label, len(got), len(want), got, want)
		}
		for c, d := range want {
			if got[c] != d {
				t.Fatalf("%s: cursor %v has deadline %d, want %d", label, c, got[c], d)
			}
		}
	}
	same("first plan", x.expiring(math.MaxInt64), cursors)
	read := x.expiryRead()
	if read < 8 {
		t.Fatalf("the first plan read %d commands of 8", read)
	}
	same("second plan", x.expiring(math.MaxInt64), cursors)
	if got := x.expiryRead(); got != read {
		t.Fatalf("the second plan read %d commands again", got-read)
	}
	soon := map[model.Cursor]model.UnixNano{}
	for c, d := range cursors {
		if d <= 101 {
			soon[c] = d
		}
	}
	same("horizon", x.expiring(101), soon)
	if got := x.expiryRead(); got != read {
		t.Fatalf("a plan with another horizon read %d commands again", got-read)
	}
	_, r := x.appendError(200)
	cursors[r.Cursor] = 200
	x.appendMixed("plan", bothDeadlines)
	same("plan after two appends", x.expiring(math.MaxInt64), cursors)
	if got := x.expiryRead(); got != read+2 {
		t.Fatalf("the plan after two appended commands read %d commands", got-read)
	}
	read = x.expiryRead()
	guard := func(context.Context, EraseCandidate) (bool, error) { return true, nil }
	sel := eraseSelector{
		record: func(_, _ model.ID, r model.Record, _ model.Receipt) (bool, model.UnixNano) {
			return r.ID == first.ID, 0
		},
		blob: func(model.BlobManifest) (bool, model.UnixNano) { return false, 0 },
	}
	if _, err := x.e.erase(context.Background(), sel, guard); err != nil {
		t.Fatal(err)
	}
	for c, d := range cursors {
		if d == 100 {
			delete(cursors, c)
		}
	}
	same("plan after an erasure", x.expiring(math.MaxInt64), cursors)
	if got := x.expiryRead(); got <= read {
		t.Fatal("the plan after an erasure trusted what it had read before the commands were rewritten")
	}
}

// A plan is made every 15 minutes, and the commands it would read then are older than the keep window of the payload log: one random
// disk read each (two million at the single-host gate). The background loop reads the commands a minute after their append, from the
// page cache, so the plan finds nothing new. It extends a cache that stands and never rebuilds one an erasure invalidated (a rebuild
// reads every command; a loop that did it for every erasure would repeat it).
func TestExpiryCacheIsKeptUpWithoutAPlan(t *testing.T) {
	holdBackgroundVerification(t)
	old := expiryRefresh
	expiryRefresh = 10 * time.Millisecond
	t.Cleanup(func() { expiryRefresh = old })
	x := newEraseEnv(t)
	x.adoptPayload()
	first, _ := x.appendError(100)
	x.appendMixed("plan", bothDeadlines)
	x.expiring(math.MaxInt64) // the first plan builds the cache
	read := x.expiryRead()
	_, r := x.appendError(200)
	x.appendMixed("plan", bothDeadlines)
	for deadline := time.Now().Add(10 * time.Second); x.expiryRead() < read+2; {
		if time.Now().After(deadline) {
			t.Fatalf("the loop read %d of the 2 commands appended since the plan", x.expiryRead()-read)
		}
		time.Sleep(5 * time.Millisecond)
	}
	read = x.expiryRead()
	if got := x.expiring(math.MaxInt64); got[r.Cursor] != 200 || len(got) != 2 {
		t.Fatalf("plan after the loop: %v", got)
	}
	if got := x.expiryRead(); got != read {
		t.Fatalf("the plan read %d commands the loop had read", got-read)
	}
	guard := func(context.Context, EraseCandidate) (bool, error) { return true, nil }
	sel := eraseSelector{
		record: func(_, _ model.ID, rec model.Record, _ model.Receipt) (bool, model.UnixNano) {
			return rec.ID == first.ID, 0
		},
		blob: func(model.BlobManifest) (bool, model.UnixNano) { return false, 0 },
	}
	if _, err := x.e.erase(context.Background(), sel, guard); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * expiryRefresh) // twenty rounds of the loop
	if got := x.expiryRead(); got != read {
		t.Fatalf("the loop read %d commands after an erasure invalidated the cache: a rebuild is the plan's", got-read)
	}
	if got := x.expiring(math.MaxInt64); len(got) != 1 || got[r.Cursor] != 200 {
		t.Fatalf("plan after the erasure: %v", got)
	}
}
