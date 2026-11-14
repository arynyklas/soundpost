// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"github.com/arynyklas/soundpost/internal/model"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
)

var base64Run = regexp.MustCompile(`[A-Za-z0-9+/_-]{16,}={0,2}`)

// deepContains looks for needle in data and in everything that decodes out of it: journals and
// snapshots wrap commands in base64 inside JSON inside base64, so a plain search proves nothing.
func deepContains(data, needle []byte, depth int) bool {
	if bytes.Contains(data, needle) {
		return true
	}
	if depth == 0 {
		return false
	}
	for _, run := range base64Run.FindAll(data, -1) {
		for skip := range 4 {
			if skip >= len(run) {
				break
			}
			for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
				text := bytes.TrimRight(run[skip:], "=")
				if len(text)%4 == 1 {
					text = text[:len(text)-1]
				}
				if decoded, err := enc.DecodeString(string(text)); err == nil && deepContains(decoded, needle, depth-1) {
					return true
				}
			}
		}
	}
	return false
}

// raftHits lists the files under the engine's Raft directory (journals and snapshots, pinned
// segment copies included) that hold the canary in any nesting of encodings.
func (x *eraseEnv) raftHits(canary string) []string {
	x.t.Helper()
	var hits []string
	root := filepath.Join(x.dir, "raft")
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		raw, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		if deepContains(raw, []byte(canary), 5) {
			rel, _ := filepath.Rel(root, p)
			hits = append(hits, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		x.t.Fatal(err)
	}
	sort.Strings(hits)
	return hits
}

func (x *eraseEnv) cut() {
	x.t.Helper()
	if _, err := x.e.CreateSnapshots(context.Background()); err != nil {
		x.t.Fatal(err)
	}
}

// pinnedCopyHits are the hits in the snapshots' pinned copies of segments and manifests (files/):
// copies that exist only because a snapshot pins the engine's files, as opposed to the journal and
// the snapshot envelopes.
func pinnedCopyHits(hits []string) []string {
	var out []string
	for _, h := range hits {
		if base := filepath.Base(h); base != "ready.wal" && base != "envelope.json" {
			out = append(out, h)
		}
	}
	return out
}

// snapshotStateHits lists the snapshots whose machine state (what the storage engine itself
// supplies, as opposed to the replication layer's cache) carries the canary.
func (x *eraseEnv) snapshotStateHits(canary string) []string {
	x.t.Helper()
	var out []string
	matches, err := filepath.Glob(filepath.Join(x.dir, "raft", "slot-*", "snapshots", "snap-*", "envelope.json"))
	if err != nil {
		x.t.Fatal(err)
	}
	for _, m := range matches {
		raw, err := os.ReadFile(m)
		if err != nil {
			x.t.Fatal(err)
		}
		var envelope struct {
			State json.RawMessage `json:"state"`
		}
		if err = json.Unmarshal(raw, &envelope); err != nil {
			x.t.Fatal(err)
		}
		if deepContains(envelope.State, []byte(canary), 5) {
			out = append(out, m)
		}
	}
	return out
}

// The store keeps the selected snapshot AND the newest previous one. After a deletion the
// previous one is the routine snapshot from before it, with its pinned copy of every segment and
// its full command history. Physical erasure has to drop it once a verified post-erasure snapshot
// is selected; what may remain is only the replication layer's own cache.
func TestErasedBytesAreNotRetainedByASupersededSnapshot(t *testing.T) {
	x := newCheckpointEnv(t)
	ctx := context.Background()
	first := x.appendMixed(eraseCanary, bothDeadlines)
	second := x.appendMixed(otherCanary, bothDeadlines)
	x.coldCanary(eraseCanary)
	x.cut() // the routine hourly snapshot, before anyone asked for a deletion
	routine := x.raftHits(eraseCanary)
	if len(pinnedCopyHits(routine)) == 0 {
		t.Fatalf("fixture invalid: the pre-deletion snapshot does not hold the canary outside the replication cache (%v)", routine)
	}
	pred := x.rangePredicate(0, 10, model.Metric)
	barrierAll(t, x.e, pred) // the saga's fence: every group's applied index moves past the routine cut
	if report, err := x.e.EraseDeleted(ctx, []model.DeletePredicate{pred}, nil); err != nil || report.Records < 2 {
		t.Fatalf("erase %+v %v", report, err)
	}
	x.cut() // the post-erasure cut is a new snapshot; the routine one is now the retained "previous"
	if kept := pinnedCopyHits(x.raftHits(eraseCanary)); len(kept) == 0 {
		t.Fatal("fixture invalid: the routine snapshot is not retained as the previous one, so there is nothing to drop")
	}
	dropped, err := x.e.DropSupersededSnapshots(ctx)
	if err != nil || dropped == 0 {
		t.Fatalf("dropped %d (%v)", dropped, err)
	}
	for _, c := range []string{eraseCanary, otherCanary} {
		if after := x.raftHits(c); len(after) != 0 {
			t.Fatalf("a journal or snapshot file still holds erased bytes: %v (routine %v)", after, routine)
		}
		if after := x.snapshotStateHits(c); len(after) != 0 {
			t.Fatalf("a snapshot's machine state still carries erased bytes: %v", after)
		}
	}
	// The surviving snapshot is the post-erasure one: selected and verifiable, and truncating the
	// journal against it works.
	for slot, group := range x.e.ReplicaGroups() {
		if _, err := group.Snapshots().Verify(); err != nil {
			t.Fatalf("slot %d: the selected snapshot no longer verifies: %v", slot, err)
		}
	}
	if err := x.e.CompactJournals(ctx); err != nil {
		t.Fatal(err)
	}
	if got, want := x.ids(model.Metric), sortedIDs(first.keepM, second.keepM); !reflect.DeepEqual(got, want) {
		t.Fatalf("rows %v want %v", got, want)
	}
	if again, err := x.e.DropSupersededSnapshots(ctx); err != nil || again != 0 {
		t.Fatalf("a second call found %d superseded snapshots (%v)", again, err)
	}
}

// newCheckpointEnv is an erase fixture whose engine accepts delete barriers the way a control
// store with a committed deletion would, so a test can run the barrier -> erase -> cut sequence.
func newCheckpointEnv(t *testing.T) *eraseEnv {
	t.Helper()
	store, a, c, d := typedFixture(t)
	x := &eraseEnv{t: t, store: store, a: a, cred: c, d: d, dir: t.TempDir()}
	x.e = openDeleteEngine(t, x.dir, a, store)
	src, err := a.SourceAuthority(context.Background(), c, true)
	if err != nil {
		t.Fatal(err)
	}
	r := src.Policy.Resources
	x.res = model.Resource{Service: r.Services[0], Environment: r.Environments[0], Build: r.Builds[0], Instance: r.Instances[0]}
	x.read = scanScope(t, store, a, d)
	return x
}

// A snapshot cut at an applied index the group already has is a no-op: the retained snapshot "is
// already this state". When a cut was taken between a deletion's barrier and its erasure (a
// backup run, a held deletion) it is therefore frozen with the deleted bytes, and so is the
// journal compacted against it. The erasure checkpoint advances every group's applied index
// after the erasure, so the next cut is a new snapshot and the journal is re-anchored on it.
func TestErasureCheckpointMakesSnapshotAndJournalFreshAtAnUnchangedIndex(t *testing.T) {
	x := newCheckpointEnv(t)
	ctx := context.Background()
	hit := x.appendMixed(eraseCanary, bothDeadlines)
	pred := x.rangePredicate(0, 10, model.Metric)
	barrierAll(t, x.e, pred) // the saga's fence: every slot's applied index moves on
	x.coldCanary(eraseCanary)
	x.cut() // a cut between the barrier and the erasure
	if report, err := x.e.EraseDeleted(ctx, []model.DeletePredicate{pred}, nil); err != nil || report.Records < 1 {
		t.Fatalf("erase %+v %v", report, err)
	}
	x.cut()
	if err := x.e.CompactJournals(ctx); err != nil {
		t.Fatal(err)
	}
	if len(x.raftHits(eraseCanary))+len(x.snapshotStateHits(eraseCanary)) == 0 {
		t.Fatal("fixture invalid: a cut at an unchanged index should be frozen with the erased bytes")
	}
	// The frozen cut is what the engine reports, measured against where the erasure happened.
	if got := x.e.ResidualStores(); strings.Join(got, ",") != ResidualRaftJournal+","+ResidualRaftSnapshots {
		t.Fatalf("residual stores while the journal and snapshot are frozen at the erasure index: %v", got)
	}
	if err := x.e.CheckpointErasure(ctx, pred); err != nil {
		t.Fatal(err)
	}
	x.cut()
	if _, err := x.e.DropSupersededSnapshots(ctx); err != nil {
		t.Fatal(err)
	}
	if err := x.e.CompactJournals(ctx); err != nil {
		t.Fatal(err)
	}
	if left := x.raftHits(eraseCanary); len(left) != 0 {
		t.Fatalf("a journal or snapshot file still holds the erased bytes after the checkpoint: %v", left)
	}
	if left := x.snapshotStateHits(eraseCanary); len(left) != 0 {
		t.Fatalf("a snapshot's machine state still carries the erased bytes after the checkpoint: %v", left)
	}
	// Nothing is declared as residual any more, and the declaration is measured: it is empty
	// because no copy exists, not because it stopped looking.
	if got := x.e.ResidualStores(); len(got) != 0 {
		t.Fatalf("residual stores after a complete physical cleanup: %v", got)
	}
	if got, want := x.ids(model.Metric), sortedIDs(hit.keepM); !reflect.DeepEqual(got, want) {
		t.Fatalf("rows %v want %v", got, want)
	}
	// An ACKed batch still answers, the barrier is still one per slot, and a restart works.
	if _, err := x.e.Append(ctx, hit.scope, hit.batch); err != nil {
		t.Fatalf("ACKed batch no longer answerable: %v", err)
	}
	barriers, err := x.e.DeleteBarriers(ctx)
	if err != nil || len(barriers) != 64 {
		t.Fatalf("%d barriers (%v): the checkpoint must not add tombstones", len(barriers), err)
	}
	if err := x.e.CheckpointErasure(ctx, x.rangePredicate(0, 10, model.Metric)); err == nil {
		t.Fatal("a checkpoint for an operation that never had a barrier was accepted")
	}
}
