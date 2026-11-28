// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore_test

import (
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/ingest"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/policy"
	"github.com/arynyklas/soundpost/internal/replays"
)

// productionIngest is the production composition (closed-format gate, indexing
// appender over the real replay service) over a given control store, with no
// counting double hiding the replay service from the appender.
func (r *indexRig) productionIngest(store replays.ReferenceStore) {
	r.t.Helper()
	service, err := replays.New(r.app.Storage, r.app.Auth, store)
	if err != nil {
		r.t.Fatal(err)
	}
	appender, err := appcore.NewReplayIndexingAppender(r.app.Storage, service)
	if err != nil {
		r.t.Fatal(err)
	}
	p, err := policy.New(r.app.Auth, nil)
	if err != nil {
		r.t.Fatal(err)
	}
	svc, err := ingest.New(r.app.Auth, p, r.app.Control, appender)
	if err != nil {
		r.t.Fatal(err)
	}
	svc.SetReplayGate(replays.ValidateChunk)
	r.override = svc
}

// refused admits a batch that intake must refuse as a typed Conflict, and checks
// that it left nothing behind: no stored row, no charged byte or reservation.
func (r *indexRig) refused(what string, replay model.ID, rows int, chunks ...model.ReplayChunk) {
	r.t.Helper()
	bytes, reservations := r.quota()
	if _, err := r.admit(r.replayBatch(chunks...)); codeOf(err) != model.Conflict {
		r.t.Fatalf("%s: %v, want a typed conflict", what, err)
	}
	if got := r.storedRows(replay); got != rows {
		r.t.Fatalf("%s: %d rows stored, want %d", what, got, rows)
	}
	if b, n := r.quota(); b != bytes || n != reservations {
		r.t.Fatalf("%s left a charge: %d bytes in %d reservations, was %d in %d", what, b, n, bytes, reservations)
	}
}

// A refused forged batch leaves no charged reservation: intake refuses it before
// ReserveAdmission (ingest.Preflighter), not after it.
func TestRefusedReplayBatchLeavesNoReservation(t *testing.T) {
	rig := newIndexRig(t)
	rec := newReplayRecorder()
	cp, d2 := rec.cp(), rec.delta()
	for _, c := range []model.ReplayChunk{cp, d2} {
		if _, err := rig.admit(rig.replayBatch(c)); err != nil {
			t.Fatal(err)
		}
	}
	rig.refused("a different chunk at the recorded checkpoint", rec.replay, 2, forged(cp))
	rig.refused("a different delta at a stored sequence", rec.replay, 2, forged(d2))
	other := newReplayRecorder()
	other.cp()
	rig.refused("a delta that would root a replay", other.replay, 0, other.delta())
	if got := rig.reads(rec.replay); got != "checkpoint1 delta2" {
		t.Fatalf("the reader sees %q", got)
	}
}

// A replay is rooted by a checkpoint, never by a delta: the delta that arrives
// first is refused and creates neither a row nor an index group, and a batch that
// starts with a delta but carries the replay's checkpoint roots it normally.
func TestADeltaCannotRootAReplay(t *testing.T) {
	rig := newIndexRig(t)
	rec := newReplayRecorder()
	cp, d2 := rec.cp(), rec.delta()
	rig.refused("a delta first", rec.replay, 0, d2)
	if group, pin := rig.indexOf(rec.replay); group != nil || pin.RetainUntil != 0 {
		t.Fatal("a refused delta created an index group")
	}
	if _, err := rig.admit(rig.replayBatch(cp)); err != nil {
		t.Fatal(err)
	}
	if _, err := rig.admit(rig.replayBatch(d2)); err != nil {
		t.Fatalf("the delta after its checkpoint: %v", err)
	}
	if got := rig.reads(rec.replay); got != "checkpoint1 delta2" {
		t.Fatalf("the reader sees %q", got)
	}

	// [delta, checkpoint] of a replay not seen before: the checkpoint roots it.
	late := newReplayRecorder()
	late.cp()
	d2late, cp3 := late.delta(), late.cp()
	if _, err := rig.admit(rig.replayBatch(d2late, cp3)); err != nil {
		t.Fatalf("a batch whose checkpoint follows its first delta: %v", err)
	}
	group, _ := rig.indexOf(late.replay)
	if group == nil || group.Session != late.session || len(group.Checkpoints) != 1 || group.Checkpoints[0].Sequence != 3 {
		t.Fatalf("index of the late-rooted replay: %+v", group)
	}
	if got := rig.reads(late.replay); got != "gap1-2 checkpoint3" {
		t.Fatalf("the reader sees %q", got)
	}
}

// The chain is checked at intake against the chunks already STORED: a different
// chunk at a stored sequence and a delta whose previous or checkpoint hash
// contradicts the stored chunks are refused before the append; a late or missing
// predecessor is not (it is a read-time gap), and a byte-identical retry is not.
func TestStoredChunkChainIsCheckedAtIntake(t *testing.T) {
	rig := newIndexRig(t)
	rec := newReplayRecorder()
	cp, d2, d3 := rec.cp(), rec.delta(), rec.delta()
	for _, c := range []model.ReplayChunk{cp, d2} {
		if _, err := rig.admit(rig.replayBatch(c)); err != nil {
			t.Fatal(err)
		}
	}
	rig.refused("a different delta at stored sequence 2", rec.replay, 2, forged(d2))

	badPrev := d3
	badPrev.Previous = model.Hash{9}
	rig.refused("a delta whose previous hash is not the stored predecessor", rec.replay, 2, badPrev)
	badCheckpoint := d3
	badCheckpoint.Checkpoint = model.Hash{9}
	rig.refused("a delta naming a different checkpoint than the stored one", rec.replay, 2, badCheckpoint)
	// The contradiction is also found between two chunks of one batch.
	rig.refused("a batch whose delta contradicts its own predecessor", rec.replay, 2, d3, forged(d3))
	followsForged := forged(d2)
	rig.refused("a batch that forges the stored sequence 2 and continues from it", rec.replay, 2, followsForged, d3)

	// The identical chunk again (a retry under a new batch id) is accepted.
	if _, err := rig.admit(rig.replayBatch(d2)); err != nil {
		t.Fatalf("a byte-identical retry of a stored delta: %v", err)
	}
	if _, err := rig.admit(rig.replayBatch(d3)); err != nil {
		t.Fatalf("the genuine next delta: %v", err)
	}
	// A delta whose predecessor is not stored yet is staged, not refused.
	rec.delta() // sequence 4 never arrives
	d5 := rec.delta()
	if _, err := rig.admit(rig.replayBatch(d5)); err != nil {
		t.Fatalf("a delta whose predecessor is missing: %v", err)
	}
	if got := rig.reads(rec.replay); got != "checkpoint1 delta2 delta3 gap4-5" {
		t.Fatalf("the reader sees %q", got)
	}
}

// The first STORED chunk pins the root session, not the first chunk the index
// recorded. After a crash between the append and the index step the replay is
// stored but unindexed; a checkpoint under another session must not be able to
// root the index and take the replay over.
func TestStoredRootSessionPinsTheReplayBeforeTheIndexKnowsIt(t *testing.T) {
	rig := newIndexRig(t)
	store := &flakyStore{ReferenceStore: rig.app.Control}
	rig.productionIngest(store)
	rec := newReplayRecorder()
	cp := rec.cp()
	store.down.Store(true)
	if _, err := rig.admit(rig.replayBatch(cp)); codeOf(err) != model.Unavailable {
		t.Fatalf("fixture: the index step must fail after the append: %v", err)
	}
	store.down.Store(false)
	if rows := rig.storedRows(rec.replay); rows != 1 {
		t.Fatalf("fixture: %d rows stored", rows)
	}
	if group, _ := rig.indexOf(rec.replay); group != nil {
		t.Fatal("fixture: the index must be empty")
	}
	// A checkpoint at a sequence nothing is stored at, under another session: only the
	// stored root session can refuse it (the index is empty and would root the replay).
	foreign := newReplayRecorder()
	foreign.replay = rec.replay
	foreign.cp()
	usurper := foreign.cp()
	rig.refused("a checkpoint of a foreign session over a stored, unindexed root", rec.replay, 1, usurper)
	if group, _ := rig.indexOf(rec.replay); group != nil {
		t.Fatal("the refused checkpoint rooted the index")
	}
	// The genuine sender's retry repairs the index with the stored root.
	if _, err := rig.admit(rig.replayBatch(cp)); err != nil {
		t.Fatalf("the genuine retry: %v", err)
	}
	if group, _ := rig.indexOf(rec.replay); group == nil || group.Session != rec.session {
		t.Fatalf("index after the genuine retry: %+v", group)
	}
}

func vmHWM() int {
	raw, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if rest, ok := strings.CutPrefix(line, "VmHWM:"); ok {
			n, _ := strconv.Atoi(strings.Fields(rest)[0])
			return n
		}
	}
	return 0
}

// TestReplayAdmissionPeakMemoryReport is a measurement, not an assertion: set
// SOUNDPOST_REPLAY_MEASURE_CHUNKS to the number of ~100 KiB replay chunks in each
// batch and run the test alone in its own process; it admits 4 such batches
// through the production composition (gate, preflight, stored check, quota, append,
// index) and logs the process peak RSS before and after. docs/artifacts/source-maps.md
// "Sizing" uses it for the replay path.
func TestReplayAdmissionPeakMemoryReport(t *testing.T) {
	chunks, _ := strconv.Atoi(os.Getenv("SOUNDPOST_REPLAY_MEASURE_CHUNKS"))
	if chunks == 0 {
		t.Skip("measurement only: set SOUNDPOST_REPLAY_MEASURE_CHUNKS")
	}
	rig := newIndexRig(t)
	events := make([]model.MaskedEvent, 1900)
	for i := range events {
		events[i] = model.MaskedEvent{At: model.MonoNano(i), Kind: "pointer", Node: 1, X: int32(i), Y: 7}
	}
	before, bytes := vmHWM(), 0
	for b := 0; b < 4; b++ {
		rec := newReplayRecorder()
		batch := make([]model.ReplayChunk, chunks)
		for i := range batch {
			c := rec.next(i == 0)
			c.Events = events
			h, err := replays.ChunkHash(c)
			if err != nil {
				t.Fatal(err)
			}
			rec.prev = h
			if i == 0 {
				rec.cpHash = h
			}
			batch[i] = c
		}
		sealed := rig.replayBatch(batch...)
		if _, err := rig.admit(sealed); err != nil {
			t.Fatalf("batch %d: %v", b, err)
		}
		for _, r := range sealed.Records {
			raw, _ := model.CanonicalJSON(r)
			bytes += len(raw)
		}
	}
	after := vmHWM()
	t.Logf("REPLAY-RSS 4 batches of %d chunks (%d bytes of records in total, %d per batch): VmHWM before=%d kB after=%d kB delta=%d kB", chunks, bytes, bytes/4, before, after, after-before)
}
