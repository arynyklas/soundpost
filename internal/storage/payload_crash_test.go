// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// crashExpect is what every disk of a crash point must give back.
type crashExpect struct {
	metrics, logs []model.ID // acknowledged kept records: they must read back
	gone          []string   // canaries of erasures that returned: no copy of them may be on the disk
}

func (c crashExpect) clone() crashExpect {
	return crashExpect{append([]model.ID(nil), c.metrics...), append([]model.ID(nil), c.logs...), append([]string(nil), c.gone...)}
}

// expectAt is the expectation at crash point item: what the earlier generations acknowledged, and what this run did up to it.
func (r *crashRecorder) expectAt(item int, carry crashExpect) crashExpect {
	out := carry.clone()
	for i := 0; i <= item && i < len(r.items); i++ {
		if m := r.items[i].mark; m >= 0 {
			mk := r.marks[m]
			switch mk.kind {
			case "ack":
				out.metrics = append(out.metrics, mk.metrics...)
				out.logs = append(out.logs, mk.logs...)
			case "erased":
				out.gone = append(out.gone, mk.canary...)
			}
		}
	}
	return out
}

// finalPoint is the disk the end of the recording leaves under one mode.
func (r *crashRecorder) finalPoint(mode string) crashPoint {
	r.mu.Lock()
	defer r.mu.Unlock()
	it := r.items[len(r.items)-1]
	sim, dir := r.simulate(it.nev)
	for mi, m := range crashModes {
		if m.name != mode {
			continue
		}
		rng := rand.New(rand.NewPCG(7, uint64(mi)+1))
		files := map[string][]byte{}
		for n, f := range sim {
			if data, ok := m.image(f, rng); ok {
				files[n] = data
			}
		}
		return crashPoint{item: len(r.items) - 1, desc: "end of the run", snap: it.gen, mode: m.name, files: files, dir: dir}
	}
	panic("no crash mode " + mode)
}

// crashRun is one recorded generation of the engine and what it takes to rebuild the disk of any of its crash points.
type crashRun struct {
	x     *eraseEnv // the fixture (authority, source, reader): the engine under test is opened on the image of a crash point
	rec   *crashRecorder
	raft  map[string][]byte
	carry crashExpect
}

// ackKept notes the acknowledgement of an append whose kept records must survive from here on.
func (r *crashRecorder) ackKept(desc string, e erased) {
	r.note(desc, crashMark{kind: "ack", metrics: []model.ID{e.keepM.ID}, logs: []model.ID{e.keepL.ID}})
}

const (
	crashCanary2 = "CANARYsecond5a7c13e9d02b84"
	crashOther2  = "OTHERCANARYsecond9c41d7e03a"
	crashOther3  = "OTHERCANARYthird62e8f1a5b7c0"
)

// recordFirstGeneration runs ingest, apply, the move of the blocks to the log, an erasure and its scrub on a fresh engine whose log runs on
// the recorder, and stops the engine where it stands.
func recordFirstGeneration(t *testing.T) *crashRun {
	t.Helper()
	rec := newCrashRecorder()
	payloadFSHook = rec.hook
	x := newEraseEnv(t)
	payloadFSHook = nil
	if err := x.e.adoptRunsLayout(); err != nil {
		t.Fatal(err)
	}
	if err := x.e.adoptPayloadLayout(); err != nil {
		t.Fatal(err)
	}
	x.e.stopIndexMerger()
	rec.start(x.e.db)
	ctx := context.Background()

	rec.ackKept("ack sibling 1", x.appendMixed(otherCanary, bothDeadlines))
	rec.ackKept("ack victim 1", x.appendMixed(eraseCanary, bothDeadlines))
	rec.ackKept("ack sibling 2", x.appendMixed(crashOther2, bothDeadlines))
	if _, err := x.e.mergeIndexRuns(nil); err != nil { // the merges write the blocks of their final output to the log
		t.Fatal(err)
	}
	rec.note("runs merged", crashMark{})
	finalRunBytes = 1 // every ready run is final now: its blocks move to the log
	if _, err := x.e.externalizeRuns(nil); err != nil {
		t.Fatal(err)
	}
	t.Logf("first generation: blocks of the final runs: %+v", countInline(t, x.e))
	rec.note("blocks of the runs moved to the log", crashMark{})
	if _, err := x.e.EraseDeleted(ctx, []model.DeletePredicate{x.rangePredicate(0, 10, model.Metric)}, nil); err != nil {
		t.Fatal(err)
	}
	rec.note("erasure of victim 1 returned", crashMark{kind: "erased", canary: []string{eraseCanary}})
	if _, err := x.e.scrubPayload(ctx, scrubConfig{attempts: 1}.withDefaults()); err != nil {
		t.Fatal(err)
	}
	rec.ackKept("ack victim 2", x.appendMixed(crashCanary2, bothDeadlines))
	rec.ackKept("ack sibling 3", x.appendMixed(crashOther3, bothDeadlines))

	rec.stop(x.e.db)
	if err := x.e.Close(); err != nil {
		t.Fatal(err)
	}
	raft, err := readTree(filepath.Join(x.dir, "raft"))
	if err != nil {
		t.Fatal(err)
	}
	return &crashRun{x: x, rec: rec, raft: raft}
}

// recordSecondGeneration opens the engine on the disk a power cut at the end of the first generation leaves (the log holds a span the
// crash left, so the erasure pass sweeps it) and runs the erasure of the second victim, appends and the scrub.
func recordSecondGeneration(t *testing.T, first *crashRun) *crashRun {
	t.Helper()
	base := first.rec.finalPoint("unsynced-lost")
	dst := t.TempDir()
	if err := first.rec.writeImage(dst, base, first.raft); err != nil {
		t.Fatal(err)
	}
	rec := newCrashRecorder()
	for name, data := range base.files {
		rec.load(name, data)
	}
	if base.dir {
		rec.dirOK = true
		rec.events = append(rec.events, crashEvent{kind: "mkdir"})
	}
	payloadFSHook = rec.hook
	y := *first.x
	y.dir, y.e = dst, nil
	y.reopen()
	payloadFSHook = nil
	if !y.e.payloadDebt.Load() {
		t.Fatal("the log was reopened after a power cut and holds no span to sweep: the fixture does not reach the sweep")
	}
	y.e.stopIndexMerger()
	rec.start(y.e.db)
	ctx := context.Background()

	if _, err := y.e.EraseDeleted(ctx, []model.DeletePredicate{y.rangePredicate(0, 10, model.Metric)}, nil); err != nil {
		t.Fatal(err)
	}
	rec.note("erasure of victim 2 (and the sweep) returned", crashMark{kind: "erased", canary: []string{eraseCanary, crashCanary2}})
	rec.ackKept("ack sibling 4", y.appendMixed(crashOther3+"b", bothDeadlines))
	if _, err := y.e.scrubPayload(ctx, scrubConfig{attempts: 1}.withDefaults()); err != nil {
		t.Fatal(err)
	}

	rec.stop(y.e.db)
	if err := y.e.Close(); err != nil {
		t.Fatal(err)
	}
	raft, err := readTree(filepath.Join(dst, "raft"))
	if err != nil {
		t.Fatal(err)
	}
	return &crashRun{x: &y, rec: rec, raft: raft, carry: first.rec.expectAt(len(first.rec.items)-1, first.carry)}
}

// mustRead waits until every id is returned by a scan of the kind (the engine replays the journal of its groups behind the open), and
// fails when one is still missing: an acknowledged record that is not there.
func (x *eraseEnv) mustRead(kind model.Kind, want []model.ID, why string) {
	x.t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		got := map[model.ID]bool{}
		for _, id := range x.ids(kind) {
			got[id] = true
		}
		var missing []model.ID
		for _, id := range want {
			if !got[id] {
				missing = append(missing, id)
			}
		}
		if len(missing) == 0 {
			return
		}
		if time.Now().After(deadline) {
			x.t.Fatalf("%s: %d of %d acknowledged %v records are not returned by a scan: %v", why, len(missing), len(want), kind, missing)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// checkDisk is what the engine opened on the disk of a crash point must give: every reference of the file reads, every acknowledged
// record is returned, and no erased canary is anywhere in the file or in the log.
func (x *eraseEnv) checkDisk(exp crashExpect, why string) {
	x.t.Helper()
	everyLiveRecordReads(x.t, x.e)
	x.mustRead(model.Metric, exp.metrics, why)
	x.mustRead(model.Log, exp.logs, why)
	for _, canary := range exp.gone {
		if hits := rawHits(x.t, x.e, canary); len(hits) != 0 {
			x.t.Fatalf("%s: erased bytes (%s) are still present in %v", why, canary[:8], hits)
		}
	}
}

// verify opens the engine on the disk of a crash point and judges it, then runs the erasure pass again (the one that sweeps the span the
// crash left) and judges it again: the privacy sweep must neither leave an erased byte nor take a record that is not erased.
func (c *crashRun) verify(t *testing.T, p crashPoint, exp crashExpect) {
	dst := t.TempDir()
	if err := c.rec.writeImage(dst, p, c.raft); err != nil {
		t.Fatal(err)
	}
	y := *c.x
	y.t, y.dir, y.e = t, dst, nil
	y.reopen()
	defer func() { _ = y.e.Close() }()
	y.e.stopIndexMerger()
	y.checkDisk(exp, "after the power cut")
	// The erasure pass that follows a crash sweeps the span the crash left (it runs only when an erasure is owed, which depends on where
	// the crash was): the sweep itself is run here, and must keep every record a reference names and zero the rest.
	if err := y.e.sweepPayloadOrphans(context.Background()); err != nil {
		t.Fatalf("sweep after the power cut: %v", err)
	}
	y.checkDisk(exp, "after the sweep that follows the power cut")
	if _, err := y.e.EraseDeleted(context.Background(), []model.DeletePredicate{y.rangePredicate(0, 10, model.Metric)}, nil); err != nil {
		t.Fatalf("erasure pass after the power cut: %v", err)
	}
	after := exp.clone()
	after.gone = append(after.gone, eraseCanary, crashCanary2)
	y.checkDisk(after, "after the erasure pass that follows the power cut")
	y.integrity()
}

// TestPayloadLogSurvivesPowerLossAtEveryCrashPoint is the crash test of D89 (ack ordering) and D90 (the sweep of records no reference
// names): the engine ingests, applies, moves the blocks of its runs to the log, erases and scrubs on a file system that loses what no
// fsync covered, and a power cut is tried at EVERY position of that run (every write, fsync, directory fsync, create and commit of
// apply.db), under every way the disk may treat what was not synced (lost, kept as zeros, torn, reordered, the entry of a created
// file lost). After each, the engine opens, every reference of apply.db reads, every acknowledged record is returned with its
// exact bytes, no erased canary is on the disk; and the erasure pass that follows a crash (it sweeps the span the crash left)
// leaves both true. A second generation starts from the disk a power cut at the end of the first leaves, so that the sweep runs over
// a log whose mark never moved, as it did on the voter that lost power.
func TestPayloadLogSurvivesPowerLossAtEveryCrashPoint(t *testing.T) {
	withoutPayloadToggle(t)
	oldFinal, oldFanouts := finalRunBytes, indexRunFanouts
	finalRunBytes, indexRunFanouts = 16<<10, [...]int{2, 2, 2} // small runs merge; a merged run of 16 KiB or more is final, its blocks go to the log
	defer func() { finalRunBytes, indexRunFanouts = oldFinal, oldFanouts }()
	limit := 0
	if v := os.Getenv("PAYLOAD_CRASH_LIMIT"); v != "" {
		limit, _ = strconv.Atoi(v)
	}

	verifyAll := func(gen int, run *crashRun) {
		points := run.rec.points()
		t.Logf("generation %d: %d positions, %d distinct disks, %d commits, %d operations on the log", gen, len(run.rec.items), len(points), len(run.rec.snaps)-1, len(run.rec.events))
		step := 1
		if limit > 0 && len(points) > limit {
			step = (len(points) + limit - 1) / limit
		}
		for i := 0; i < len(points); i += step {
			p := points[i]
			t.Run(fmt.Sprintf("gen%d/%04d %s [%s, apply.db after %d commits]", gen, i, p.desc, p.mode, p.snap), func(t *testing.T) {
				run.verify(t, p, run.rec.expectAt(p.item, run.carry))
			})
		}
	}
	first := recordFirstGeneration(t)
	verifyAll(1, first)
	second := recordSecondGeneration(t, first)
	verifyAll(2, second)
}
