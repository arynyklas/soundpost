// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// dirFileSizes is the size of every regular file under dir but apply.db, by path relative to dir: the replica journals, the payload
// log, the snapshots. Those files are append-only between cuts, so their growth over a window is what the window wrote to them (the
// test stays below the cadence of a cut).
func dirFileSizes(t *testing.T, dir string) map[string]int64 {
	t.Helper()
	sizes := map[string]int64{}
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Base(p) == "apply.db" {
			return err
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		sizes[filepath.ToSlash(rel)] = fi.Size()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return sizes
}

// dirBytesBesidesApplyDB is the sum of dirFileSizes.
func dirBytesBesidesApplyDB(t *testing.T, dir string) int64 {
	t.Helper()
	var n int64
	for _, size := range dirFileSizes(t, dir) {
		n += size
	}
	return n
}

// writtenBytesPerAck appends the batches width to a commit (appendInCommits), runs the merges the commits made due, and returns the
// bytes written per ack to apply.db (every page bolt allocated for the commits and the merges, and one meta page per commit) and to
// the other files of the engine, with the mean canonical size of a batch.
func writtenBytesPerAck(t *testing.T, e *Engine, dir string, batches []preparedAppend, width int) (bolt, files, batch float64) {
	t.Helper()
	e.stopIndexMerger()
	beforeDB := e.db.Stats()
	beforeFiles := dirFileSizes(t, dir)
	commits, applies := appendInCommits(t, e, batches, width)
	if applies != uint64(len(batches)) {
		t.Fatalf("%d appends made %d applies", len(batches), applies)
	}
	if cancelled, err := e.mergeIndexRuns(nil); cancelled || err != nil {
		t.Fatalf("merging the runs the commits made due: cancelled=%v %v", cancelled, err)
	}
	afterDB := e.db.Stats()
	d := afterDB.Sub(&beforeDB)
	var canon int
	for _, b := range batches {
		canon += len(b.batch.Canonical)
	}
	n := float64(len(batches))
	pages := float64(d.TxStats.GetPageAlloc()) + float64(4096*commits) // and the meta page of each commit of the acks (the merge transactions' own are not counted)
	var grown int64
	classes := map[string]int64{}
	for name, size := range dirFileSizes(t, dir) {
		if delta := size - beforeFiles[name]; delta > 0 {
			class := name
			switch {
			case filepath.Base(name) == "ready.wal":
				class = "journals"
			case filepath.Ext(name) == ".spl":
				class = "payload log"
			}
			classes[class] += delta
			grown += delta
		}
	}
	var perClass []string
	for class, delta := range classes {
		perClass = append(perClass, fmt.Sprintf("%s %.0f", class, float64(delta)/n))
	}
	sort.Strings(perClass)
	t.Logf("files grew per ack by: %s", strings.Join(perClass, ", "))
	return pages / n, float64(grown) / n, float64(canon) / n
}

// TestWrittenBytesPerAckAreBoundedAndIndependentOfFreePages is the red test of the write amplification of D91 (the server wrote 245 GB
// in 900 s at 570 requests/s, ~21x the 11.4 GB it kept). What an acknowledged request writes is bounded per file class, whatever
// part of apply.db is free, in the layout a file has before the payload log (every value inline in apply.db) and in the layout a
// contracted installation adopts (the log holds the command, the rows and the page; D89):
//
//   - the journal and the payload log take the bytes of the batch (B: its canonical bytes) once per copy the layout writes into them,
//     plus what an append adds around the copies: the command envelope and the canonical bytes beside the batch's JSON in it, the
//     receipt and cursors, the 4/3 of the base64 an entry is written in, the membership each journal record names, the commit-only
//     record of a hard state, a 16-byte frame per journal record and a 12-byte header per log record. Inline, the journal alone takes
//     the batch (one copy: its entry); with the log, the journal takes the entry and the log takes the command, the stored rows and
//     the hot page (four copies). A batch of 650 bytes measured 4,415 bytes in the journal (a 4,172-byte record, a 211-byte
//     commit-only record, two frames) and, with the log, 2,794 in it (command 2,056, rows 414, page 288, three headers): 7,209 bytes,
//     of which 4 x B = 2,600 and 4,609 around the copies. The constant around them is 5 KiB in both layouts (the journal alone:
//     3,765 around its one copy), so the bound is copies x B + 5 KiB. The first form of this test bounded the files at 2 x B + 5 KiB
//     from 4.4 KB measured for a batch of 653 bytes (apply.db measured 18.8 and 27.4 KB per ack beside it): that was the inline
//     layout, which the test happened to be in because it stopped the merger, which adopts the payload layout about a second after
//     a start, before it had; it was in the other layout when the scheduler let the merger run first, and failed with 7.2 KB. The
//     test adopts the layout it measures itself now;
//   - apply.db takes the dirty pages of the commit shared by its acks (the trees of the ~15 buckets it writes, 20 to 26 pages, ~100 KB
//     for a commit of 12 acks: 8.7 KiB per ack) and what the merges rewrite of the runs it adds (a key is rewritten once per level;
//     the later window pays for a level more than the earlier): inline measured 18.8 and 27.4 KB per ack, with the log 7.5 and 10.8
//     (the command, the rows and the page are in the log), so the bound is 32 KiB per ack and the later window may exceed the
//     earlier by 60 %. The freelist of a file that holds 96 MB of free pages written by every commit adds 196 KB per commit, 16 KB
//     per ack, and the same appends measured 40.3 and 47.3 KB per ack before D91.
//
// The window at the start and the one at the end of the history are measured on a file that holds 96 MB of free pages (the file the
// gate leaves).
func TestWrittenBytesPerAckAreBoundedAndIndependentOfFreePages(t *testing.T) {
	for _, layout := range []struct {
		name    string
		payload bool
		copies  float64 // copies of the batch the layout writes into the journal and the log
	}{{"inline values", false, 1}, {"payload log", true, 4}} {
		t.Run(layout.name, func(t *testing.T) { writtenBytesPerAckBounded(t, layout.payload, layout.copies) })
	}
}

func writtenBytesPerAckBounded(t *testing.T, payload bool, copies float64) {
	withoutPayloadToggle(t) // the layout is the case's, not the merger's or the environment's
	store, service, cred, desc := fixture(t)
	dir := t.TempDir()
	e, err := openTestEngine(t, dir, service, store)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.BindAdmissionOwner(e); err != nil {
		t.Fatal(err)
	}
	e.stopIndexMerger()
	if payload {
		if err = e.adoptRunsLayout(); err == nil {
			err = e.adoptPayloadLayout()
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if e.payloadOn.Load() != payload {
		t.Fatalf("payload layout %v, the case measures %v", e.payloadOn.Load(), payload)
	}
	inflateFreePages(t, e, 96)
	const total, window, width, universe = 1200, 240, 12, 900
	bySlot := map[uint16][]string{}
	for i := range universe {
		name := fmt.Sprintf("write_volume_series_%d", i)
		slot := ackPagesSlotOf(t, desc, name)
		bySlot[slot] = append(bySlot[slot], name)
	}
	slots := make([]uint16, 0, len(bySlot))
	for slot := range bySlot {
		slots = append(slots, slot)
	}
	sort.Slice(slots, func(i, j int) bool { return slots[i] < slots[j] })
	if len(slots) < width {
		t.Fatalf("the %d series route to %d slots, a commit needs %d", universe, len(slots), width)
	}
	rng := rand.New(rand.NewPCG(11, 11))
	batches := make([]preparedAppend, total)
	for i := range batches {
		names := bySlot[slots[i%len(slots)]]
		batches[i].scope, batches[i].batch = ackPagesBatch(t, store, service, cred, desc, model.UnixNano(1+i), []string{names[rng.IntN(len(names))]})
	}
	eDB, eFiles, eB := writtenBytesPerAck(t, e, dir, batches[:window], width)
	writtenBytesPerAck(t, e, dir, batches[window:total-window], width)
	lDB, lFiles, lB := writtenBytesPerAck(t, e, dir, batches[total-window:], width)
	t.Logf("per ack (batch %.0f / %.0f bytes canonical): apply.db %.0f then %.0f bytes, journal and payload log %.0f then %.0f bytes", eB, lB, eDB, lDB, eFiles, lFiles)
	for _, w := range []struct {
		name  string
		db    float64
		files float64
		b     float64
	}{{"first", eDB, eFiles, eB}, {"last", lDB, lFiles, lB}} {
		if w.files > copies*w.b+5<<10 {
			t.Errorf("%s window: the journal and the payload log grow %.0f bytes per ack of a batch of %.0f bytes (bound %.0f x batch + 5 KiB)", w.name, w.files, w.b, copies)
		}
		if w.db > 32<<10 {
			t.Errorf("%s window: apply.db is written %.0f bytes per ack (bound %d)", w.name, w.db, 32<<10)
		}
	}
	if lDB > eDB*1.6+4096 {
		t.Errorf("the bytes written to apply.db per ack grew with the history: %.0f then %.0f", eDB, lDB)
	}
}
