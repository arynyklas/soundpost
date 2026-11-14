// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
	bolt "go.etcd.io/bbolt"
)

// reopenDelete restarts an engine that accepts delete barriers (a crash and restart).
func (x *eraseEnv) reopenDelete() {
	x.t.Helper()
	if err := x.e.Close(); err != nil {
		x.t.Fatal(err)
	}
	x.e = openDeleteEngineRestored(x.t, x.dir, x.a, x.store)
}

// maintain is the worker's physical sequence after an erasure: checkpoint, cut, drop what the cut
// supersedes, truncate the journal onto the cut.
func (x *eraseEnv) maintain(pred model.DeletePredicate) {
	x.t.Helper()
	ctx := context.Background()
	if err := x.e.CheckpointErasure(ctx, pred); err != nil {
		x.t.Fatal(err)
	}
	x.cut()
	if _, err := x.e.DropSupersededSnapshots(ctx); err != nil {
		x.t.Fatal(err)
	}
	if err := x.e.CompactJournals(ctx); err != nil {
		x.t.Fatal(err)
	}
}

func inHits(hits []string, base string) bool {
	for _, h := range hits {
		if filepath.Base(h) == base {
			return true
		}
	}
	return false
}

// requireReceipt proves an ACKed batch still answers its retry with the original receipt, byte for
// byte.
func (x *eraseEnv) requireReceipt(label string, hit erased) {
	x.t.Helper()
	retry, err := x.e.Append(context.Background(), hit.scope, hit.batch)
	if err != nil {
		x.t.Fatalf("%s: the ACKed batch no longer answers its retry: %v", label, err)
	}
	if got, want := string(mustJSON(x.t, retry)), string(mustJSON(x.t, hit.receipt)); got != want {
		x.t.Fatalf("%s: the retry returned a different receipt:\n got  %s\n want %s", label, got, want)
	}
}

// requireNoCopy asserts that no file the node keeps for replication, snapshots or the apply
// database holds any of the canaries, in any nesting of encodings.
func (x *eraseEnv) requireNoCopy(label string, canaries ...string) {
	x.t.Helper()
	for _, c := range canaries {
		if hits := x.raftHits(c); len(hits) != 0 {
			x.t.Fatalf("%s: %s survives in the replication layer: %v", label, c, hits)
		}
		if hits := x.snapshotStateHits(c); len(hits) != 0 {
			x.t.Fatalf("%s: %s survives in a snapshot's machine state: %v", label, c, hits)
		}
		if hits := rawHits(x.t, x.e, c); len(hits) != 0 {
			x.t.Fatalf("%s: %s survives in the apply database or a segment: %v", label, c, hits)
		}
	}
}

// After a physical deletion the deleted record's original bytes must exist nowhere on the node:
// not in the stored command, not in the replication layer's retry table or journal, not in a
// snapshot. What the replication layer cannot rewrite in place (a snapshot sealed at an older
// cut) is reported until the maintenance sequence replaces it, and nothing is reported after.
func TestEraseRemovesTheDeletedBytesFromTheReplicationLayerAndKeepsTheReceipt(t *testing.T) {
	x := newCheckpointEnv(t)
	ctx := context.Background()
	hit := x.appendMixed(eraseCanary, bothDeadlines)
	other := x.appendMixed(otherCanary, bothDeadlines)
	x.coldCanary(eraseCanary)
	x.cut() // the routine snapshot, sealed before anyone asked for a deletion
	pred := x.rangePredicate(0, 10, model.Metric)
	barrierAll(t, x.e, pred)
	for _, c := range []string{eraseCanary, otherCanary} {
		hits := x.raftHits(c)
		if !inHits(hits, "ready.wal") || !inHits(hits, "envelope.json") {
			t.Fatalf("fixture invalid: %s is not in the journal and the snapshot envelope before the erasure: %v", c, hits)
		}
	}
	if report, err := x.e.EraseDeleted(ctx, []model.DeletePredicate{pred}, nil); err != nil || report.Records < 2 {
		t.Fatalf("erase %+v %v", report, err)
	}
	// The journal is rewritten by the erasure itself; the snapshot sealed before it is not.
	for _, c := range []string{eraseCanary, otherCanary} {
		hits := x.raftHits(c)
		if inHits(hits, "ready.wal") {
			t.Fatalf("the journal still holds %s right after the erasure: %v", c, hits)
		}
		if !inHits(hits, "envelope.json") {
			t.Fatalf("fixture invalid: the routine snapshot cannot have been rewritten in place: %v", hits)
		}
	}
	if got := x.e.ResidualStores(); strings.Join(got, ",") != ResidualRaftJournal+","+ResidualRaftSnapshots {
		t.Fatalf("residual stores before the maintenance sequence: %v", got)
	}
	x.maintain(pred)
	x.requireNoCopy("after the maintenance sequence", eraseCanary, otherCanary)
	if got := x.e.ResidualStores(); len(got) != 0 {
		t.Fatalf("residual stores after the maintenance sequence: %v", got)
	}
	if got, want := x.ids(model.Metric), sortedIDs(hit.keepM, other.keepM); !reflect.DeepEqual(got, want) {
		t.Fatalf("rows %v want %v", got, want)
	}
	x.requireReceipt("after the maintenance sequence", hit)
	x.requireReceipt("after the maintenance sequence", other)
	x.integrity()

	x.reopenDelete()
	x.requireNoCopy("after a restart", eraseCanary, otherCanary)
	if got := x.e.ResidualStores(); len(got) != 0 {
		t.Fatalf("residual stores after a restart: %v", got)
	}
	x.requireReceipt("after a restart", hit)
	if got, want := x.ids(model.Metric), sortedIDs(hit.keepM, other.keepM); !reflect.DeepEqual(got, want) {
		t.Fatalf("rows after a restart %v want %v", got, want)
	}
}

// Kill the process at every step of the redaction that follows an erasure. The erasing
// transaction is already durable; whatever the replication layer was not yet told is re-derived
// from the stored redacted commands when the engine opens, and the worker's next pass finishes.
func TestEraseRedactionCrashPointsConverge(t *testing.T) {
	hooks := []string{"redact_replica", replica.HookRedactBegin, replica.HookRedactWrite, replica.HookRedactSync, replica.HookRedactSwitch, replica.HookRedactRenamed, replica.HookRedactMemory}
	for _, hook := range hooks {
		t.Run(hook, func(t *testing.T) {
			x := newCheckpointEnv(t)
			ctx := context.Background()
			hit := x.appendMixed(eraseCanary, bothDeadlines)
			x.coldCanary(eraseCanary)
			x.cut()
			pred := x.rangePredicate(0, 10, model.Metric)
			barrierAll(t, x.e, pred)
			fired := false
			x.e.fault = func(at string) error {
				if at == hook && !fired {
					fired = true
					return errors.New("crash at " + at)
				}
				return nil
			}
			if _, err := x.e.EraseDeleted(ctx, []model.DeletePredicate{pred}, nil); err == nil || !fired {
				t.Fatalf("hook %s never interrupted the erasure (%v)", hook, err)
			}
			x.reopenDelete() // the stored redacted command is durable; the open re-derives the rest
			if _, err := x.e.EraseDeleted(ctx, []model.DeletePredicate{pred}, nil); err != nil {
				t.Fatalf("the worker's next pass after a crash at %s: %v", hook, err)
			}
			x.maintain(pred)
			x.requireNoCopy("after a crash at "+hook, eraseCanary)
			if got := x.e.ResidualStores(); len(got) != 0 {
				t.Fatalf("residual stores after a crash at %s and a full pass: %v", hook, got)
			}
			x.requireReceipt("after a crash at "+hook, hit)
			if got, want := x.ids(model.Metric), sortedIDs(hit.keepM); !reflect.DeepEqual(got, want) {
				t.Fatalf("rows %v want %v", got, want)
			}
			x.integrity()
		})
	}
}

// A snapshot cut while a redaction is still owed must not carry the retry table of the command the
// machine already redacted: the cut itself finishes the redaction first.
func TestSnapshotCutFinishesAnOwedRedactionFirst(t *testing.T) {
	x := newCheckpointEnv(t)
	ctx := context.Background()
	hit := x.appendMixed(eraseCanary, bothDeadlines)
	pred := x.rangePredicate(0, 10, model.Metric)
	barrierAll(t, x.e, pred)
	fired := false
	x.e.fault = func(at string) error { // the erasing transaction commits, the replica is not told
		if at == "redact_replica" && !fired {
			fired = true
			return errors.New("redaction interrupted")
		}
		return nil
	}
	if _, err := x.e.EraseDeleted(ctx, []model.DeletePredicate{pred}, nil); err == nil || !fired {
		t.Fatalf("the erasure was not interrupted before the replica was told: %v", err)
	}
	if got := x.e.ResidualStores(); !contains(got, ResidualRaftCompletedEntries) {
		t.Fatalf("an owed redaction is not reported as a residual store: %v", got)
	}
	x.cut()
	x.maintain(pred)
	x.requireNoCopy("after a cut that finished the owed redaction", eraseCanary)
	x.requireReceipt("after the cut", hit)
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// Expiry erases through the same pass, so it redacts the replication layer too.
func TestExpireRedactsTheReplicationLayer(t *testing.T) {
	x := newCheckpointEnv(t)
	ctx := context.Background()
	hit := x.appendMixed(eraseCanary, bothDeadlines)
	if hits := x.raftHits(eraseCanary); !inHits(hits, "ready.wal") {
		t.Fatalf("fixture invalid: %v", hits)
	}
	if report, err := x.e.EraseExpired(ctx, metricDeadline, nil); err != nil || report.Records == 0 {
		t.Fatalf("expire %+v %v", report, err)
	}
	if hits := x.raftHits(eraseCanary); inHits(hits, "ready.wal") {
		t.Fatalf("the journal still holds an expired record: %v", hits)
	}
	x.cut()
	if err := x.e.CompactJournals(ctx); err != nil {
		t.Fatal(err)
	}
	x.requireNoCopy("after expiry", eraseCanary)
	x.requireReceipt("after expiry", hit)
}

// A batch erased in two rounds is redacted twice, the second time to a narrower command; the
// second erasure leaves no copy of what the first had kept.
func TestEraseInTwoRoundsRedactsTheNarrowerCommand(t *testing.T) {
	x := newCheckpointEnv(t)
	ctx := context.Background()
	hit := x.appendMixed(eraseCanary, bothDeadlines)
	keptName := hit.keepM.Payload.Metric.Name
	first := x.rangePredicate(0, 10, model.Metric)
	barrierAll(t, x.e, first)
	if _, err := x.e.EraseDeleted(ctx, []model.DeletePredicate{first}, nil); err != nil {
		t.Fatal(err)
	}
	x.maintain(first)
	x.requireNoCopy("after the first round", eraseCanary)
	if hits := x.raftHits(keptName); !inHits(hits, "envelope.json") {
		t.Fatalf("fixture invalid: the record the first round keeps must still be in the retry table and the snapshot: %v", hits)
	}
	second := x.rangePredicate(40, 60, model.Metric)
	barrierAll(t, x.e, second)
	if _, err := x.e.EraseDeleted(ctx, []model.DeletePredicate{second}, nil); err != nil {
		t.Fatal(err)
	}
	x.maintain(second)
	x.requireNoCopy("after the second round", eraseCanary, keptName)
	x.requireReceipt("after two rounds", hit)
	if got := x.e.ResidualStores(); len(got) != 0 {
		t.Fatalf("residual stores after two rounds: %v", got)
	}
}

// A backup that dies between BeginBackup and Seal/Abort leaves a durable pin in every group. The
// engine lists them so a backup driver can reap them, and nothing else can: the pins are reloaded
// on every start and every truncation archives into them.
func TestCrashedBackupPinsAreListedAndDroppedByTheEngine(t *testing.T) {
	store, service, _, _ := fixture(t)
	dir := t.TempDir()
	engine, err := openTestEngine(t, dir, service, store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = engine.BeginBackup(context.Background(), controlCut(t, engine, store)); err != nil {
		t.Fatal(err)
	}
	if err = engine.Close(); err != nil { // the process dies: no Seal, no Abort
		t.Fatal(err)
	}
	pinFilesOnDisk := func() int {
		matches, gerr := filepath.Glob(filepath.Join(dir, "raft", "slot-*", "pins", "*.pin"))
		if gerr != nil {
			t.Fatal(gerr)
		}
		return len(matches)
	}
	if n := pinFilesOnDisk(); n != 64 {
		t.Fatalf("fixture invalid: %d pin archives after the crash", n)
	}
	re, err := openTestEngine(t, dir, service, store)
	if err != nil {
		t.Fatal(err)
	}
	pins, err := re.JournalPins()
	if err != nil || len(pins) != 64 {
		t.Fatalf("%d pins listed after the crash (%v)", len(pins), err)
	}
	groups := map[string]bool{}
	for _, p := range pins {
		if !p.Orphaned || !p.Expires.After(p.Created) || p.ID == "" {
			t.Fatalf("a pin left by a dead process must be listed as orphaned with a lease: %+v", p)
		}
		groups[p.Group] = true
	}
	if len(groups) != 64 {
		t.Fatalf("pins span %d groups, want 64", len(groups))
	}
	for _, p := range pins {
		if err = re.DropJournalPin(p.ID); err != nil {
			t.Fatal(err)
		}
	}
	if left, lerr := re.JournalPins(); lerr != nil || len(left) != 0 {
		t.Fatalf("pins left after the reaper dropped them: %d %v", len(left), lerr)
	}
	if n := pinFilesOnDisk(); n != 0 {
		t.Fatalf("%d pin archives left on disk", n)
	}
	if err = re.DropJournalPin(pins[0].ID); err != nil {
		t.Fatalf("dropping a dropped pin must be a no-op for a reaper that retries: %v", err)
	}
	if err = re.DropJournalPin("not-a-pin"); faultCode(err) != model.Invalid {
		t.Fatalf("malformed pin ID: %v", err)
	}
}

// An erasure at exactly the index of the last cut, with the journal already compacted onto that
// cut: no retained journal entry is at or before the stamped floor, but the journal still begins
// with the sealed snapshot record, and the snapshot directory exists, both cut before the
// erasure. Both are reported until a later cut replaces them.
func TestErasureAtTheLastCutIndexReportsTheSealedJournalHead(t *testing.T) {
	x := newCheckpointEnv(t)
	ctx := context.Background()
	hit := x.appendMixed(eraseCanary, bothDeadlines)
	pred := x.rangePredicate(0, 10, model.Metric)
	barrierAll(t, x.e, pred)
	x.cut() // the cut index is the applied index of every group; the journal begins at it
	if err := x.e.CompactJournals(ctx); err != nil {
		t.Fatal(err)
	}
	if report, err := x.e.EraseDeleted(ctx, []model.DeletePredicate{pred}, nil); err != nil || report.Records < 1 {
		t.Fatalf("erase %+v %v", report, err)
	}
	slot := hit.batch.RouteSlot
	var floor uint64
	if err := x.e.db.View(func(tx *bolt.Tx) error {
		floor = getUint(tx.Bucket([]byte("replica_data")), metaKey(slot, redactFloorKey))
		return nil
	}); err != nil || floor == 0 {
		t.Fatalf("floor %d (%v)", floor, err)
	}
	group := x.e.ReplicaGroups()[slot]
	if first, _ := group.JournalRange(); first <= floor {
		t.Fatalf("fixture invalid: the journal retains entries at or before the floor (first %d floor %d)", first, floor)
	}
	if !inHits(x.raftHits(eraseCanary), "ready.wal") {
		t.Fatal("fixture invalid: the sealed journal head no longer carries the payload")
	}
	residue, err := group.Residue(floor)
	if err != nil || strings.Join(residue, ",") != ResidualRaftJournal+","+ResidualRaftSnapshots {
		t.Fatalf("Residue(%d) = %v (%v): the sealed head at the cut is not reported", floor, residue, err)
	}
	if got := x.e.ResidualStores(); strings.Join(got, ",") != ResidualRaftJournal+","+ResidualRaftSnapshots {
		t.Fatalf("residual stores: %v", got)
	}
	x.maintain(pred)
	x.requireNoCopy("after the maintenance sequence", eraseCanary)
	if got := x.e.ResidualStores(); len(got) != 0 {
		t.Fatalf("residual stores after the maintenance sequence: %v", got)
	}
}

// Artifact bytes are the largest payload class the replication layer holds: every fragment is a
// replicated command. Erasing an artifact root redacts them from the retry table, the journal,
// the pin archives and every snapshot the same way a deleted record is.
func TestEraseOfAnArtifactRootRedactsTheReplicationLayer(t *testing.T) {
	const canary = "artifact-byte"
	c, a, scope, m, raw := blobFixture(t)
	ctx := context.Background()
	x := &eraseEnv{t: t, store: c, a: a, dir: t.TempDir()}
	x.e = openDeleteEngine(t, x.dir, a, c)
	receipt, err := x.e.WriteBlob(ctx, scope, m, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	x.cut() // the routine snapshot, sealed before anyone asked for a deletion
	hits := x.raftHits(canary)
	if !inHits(hits, "ready.wal") || !inHits(hits, "envelope.json") {
		t.Fatalf("fixture invalid: the fragments are not in the journal and the snapshot envelope: %v", hits)
	}
	pred := model.DeletePredicate{Operation: model.NewID(), Org: m.Org, Mode: model.DeleteRetireProject, Projects: []model.ID{m.Project}, Generation: 1}
	barrierAll(t, x.e, pred)
	if report, err := x.e.EraseDeleted(ctx, []model.DeletePredicate{pred}, nil); err != nil || report.Blobs != 1 {
		t.Fatalf("erase %+v %v", report, err)
	}
	if hits = x.raftHits(canary); inHits(hits, "ready.wal") {
		t.Fatalf("the journal still holds the erased fragments right after the erasure: %v", hits)
	}
	if got := x.e.ResidualStores(); strings.Join(got, ",") != ResidualRaftJournal+","+ResidualRaftSnapshots {
		t.Fatalf("residual stores before the maintenance sequence: %v", got)
	}
	x.maintain(pred)
	x.requireNoCopy("after the maintenance sequence", canary)
	if got := x.e.ResidualStores(); len(got) != 0 {
		t.Fatalf("residual stores after the maintenance sequence: %v", got)
	}
	x.reopenDelete()
	x.requireNoCopy("after a restart", canary)
	if err := x.e.VerifyBlob(ctx, receipt); err == nil {
		t.Fatal("an erased artifact still verifies")
	}
}

// The redaction set is found by the JSON text prefix of the stored command (isRedactedCommand,
// redactionOf, batchCommandPrefix). Both redaction kinds, produced by the real erase pass and
// marshalled again by the real wire encoder, must stay recognizable by every prefix reader: an
// encoder change that moves or adds a leading field would silently drop erased commands out of
// the reconcile.
func TestRedactedCommandsStayRecognizedAfterTheWireEncoder(t *testing.T) {
	op := model.NewID()
	original := model.HashCanonical([]byte("the original command"))
	artifact, err := json.Marshal(walEntry{Type: "artifact_redacted", Redaction: &redaction{Original: original, Erased: 2, Operations: []model.ID{op}}})
	if err != nil {
		t.Fatal(err)
	}
	if !isRedactedCommand(artifact) || bytes.HasPrefix(artifact, batchCommandPrefix) {
		t.Fatalf("artifact_redacted is misclassified: %.60s", artifact)
	}
	if got := redactionOf(artifact); got == nil || got.Original != original || got.Erased != 2 || len(got.Operations) != 1 || got.Operations[0] != op {
		t.Fatalf("artifact_redacted: redactionOf = %+v", got)
	}

	x := newCheckpointEnv(t)
	hit := x.appendMixed(eraseCanary, bothDeadlines)
	ordinary := x.command(hit.batch, hit.receipt)
	if !bytes.HasPrefix(ordinary, batchCommandPrefix) || isRedactedCommand(ordinary) || redactionOf(ordinary) != nil {
		t.Fatalf("an ordinary batch is misclassified: %.60s", ordinary)
	}
	pred := x.rangePredicate(0, 10, model.Metric)
	barrierAll(t, x.e, pred)
	if report, err := x.e.EraseDeleted(context.Background(), []model.DeletePredicate{pred}, nil); err != nil || report.Records != 1 {
		t.Fatalf("erase %+v %v", report, err)
	}
	stored := x.command(hit.batch, hit.receipt)
	var decoded walEntry
	if err = json.Unmarshal(stored, &decoded); err != nil {
		t.Fatal(err)
	}
	reencoded, err := json.Marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reencoded, stored) {
		t.Fatalf("the wire encoder does not round-trip a redacted batch:\n stored  %.120s\n encoded %.120s", stored, reencoded)
	}
	for _, raw := range [][]byte{stored, reencoded} {
		if !isRedactedCommand(raw) || !bytes.HasPrefix(raw, batchCommandPrefix) {
			t.Fatalf("batch_redacted is not recognized after the wire encoder: %.60s", raw)
		}
		got := redactionOf(raw)
		if got == nil || got.Erased != 1 || got.Original != model.HashCanonical(ordinary) {
			t.Fatalf("batch_redacted: redactionOf = %+v", got)
		}
	}
	if !sameCommand(stored, ordinary) || !sameCommand(reencoded, ordinary) {
		t.Fatal("the redacted command is not recognized as the redaction of the original")
	}
}
