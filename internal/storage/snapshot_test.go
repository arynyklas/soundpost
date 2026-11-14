// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
	bolt "go.etcd.io/bbolt"
)

func snapshotStream(t *testing.T, s replica.Snapshot) []byte {
	t.Helper()
	var b bytes.Buffer
	if _, err := s.WriteTo(&b); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// openRestoredEngine builds an engine on an empty directory that adopts
// identity, lets install place snapshots under the raft directory, and only then
// opens replication, exactly as a restore or a replaced node does.
func openRestoredEngine(t *testing.T, dir string, validator Revalidator, authority *control.Store, identity model.ID, install func(e *Engine, raft string) error) (*Engine, error) {
	t.Helper()
	engine, err := Open(dir, validator)
	if err != nil {
		return nil, err
	}
	if err = engine.InstallReplicationIdentity(identity); err != nil {
		engine.Close()
		return nil, err
	}
	raftDirectory := filepath.Join(dir, "raft")
	if install != nil {
		if err = install(engine, raftDirectory); err != nil {
			engine.Close()
			return nil, err
		}
	}
	return enableSolo(t, engine, raftDirectory, authority)
}

func enableSolo(t *testing.T, engine *Engine, raftDirectory string, authority *control.Store) (*Engine, error) {
	t.Helper()
	transport := replica.NewLoopback()
	groups, err := engine.EnableReplication(replica.Config{ID: 1, Directory: raftDirectory, Transport: transport, Members: replica.Members{Revision: 1, Nodes: []replica.Member{{ID: 1, Address: "https://single.invalid", NodeIdentity: "single", FailureDomain: "local-disk"}}}}, nil, authority)
	if err != nil {
		engine.Close()
		transport.Close()
		return nil, err
	}
	for _, group := range groups {
		if err = transport.Register(group); err == nil {
			err = group.Campaign()
		}
		if err != nil {
			engine.Close()
			transport.Close()
			return nil, err
		}
	}
	t.Cleanup(func() { engine.Close(); transport.Close() })
	return engine, nil
}

func installEngineSnapshot(t *testing.T, snapshot EngineSnapshot) func(e *Engine, raft string) error {
	return func(e *Engine, raftDirectory string) error {
		for slot, s := range snapshot.Slots {
			store, err := replica.OpenSnapshotStore(SlotDirectory(raftDirectory, uint16(slot)), s.Manifest.Group, nil)
			if err != nil {
				return err
			}
			if err = store.InstallSnapshot(context.Background(), s.Manifest, bytes.NewReader(snapshotStream(t, s))); err != nil {
				return err
			}
		}
		return nil
	}
}

func onceAt(name string, occurrence int) func(string) error {
	var mu sync.Mutex
	seen := 0
	return func(at string) error {
		if at != name {
			return nil
		}
		mu.Lock()
		defer mu.Unlock()
		seen++
		if seen == occurrence {
			return errors.New("injected crash at " + name)
		}
		return nil
	}
}

func storedBatch(t *testing.T, e *Engine, b model.NormalizedBatch) (batch, receipt []byte) {
	t.Helper()
	key := batchKey(b.Org, b.Project, b.Source, b.Producer, b.RouteSlot, b.ID)
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.db.View(func(tx *bolt.Tx) error {
		batch = bytes.Clone(tx.Bucket([]byte("batches")).Get(key))
		receipt = bytes.Clone(tx.Bucket([]byte("receipts")).Get(key))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return batch, receipt
}

// Snapshots taken while ingest, flush and compaction run must resolve every
// ACKed receipt to the exact original data, both after a restart on the same
// disk and when installed into a replacement engine with the committed suffix.
func TestSnapshotConcurrentAppendCompactionAndRetry(t *testing.T) {
	store, service, credential, descriptor := fixture(t)
	dir := t.TempDir()
	engine, err := openTestEngine(t, dir, service, store)
	if err != nil {
		t.Fatal(err)
	}
	scope, first := normalized(t, store, service, credential, descriptor)
	batches := []model.NormalizedBatch{first}
	for range 17 {
		_, b := normalized(t, store, service, credential, descriptor)
		batches = append(batches, b)
	}
	acked := map[model.ID]model.Receipt{}
	var ackMu sync.Mutex
	appendBatch := func(b model.NormalizedBatch) error {
		r, err := engine.Append(context.Background(), scope, b)
		if err != nil {
			return err
		}
		ackMu.Lock()
		acked[b.ID] = r
		ackMu.Unlock()
		return nil
	}
	for _, b := range batches[:6] {
		if err = appendBatch(b); err != nil {
			t.Fatal(err)
		}
	}
	if err = engine.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	failures := make(chan error, 8)
	stop := make(chan struct{})
	wg.Add(3)
	go func() { // ingest keeps going throughout
		defer wg.Done()
		for _, b := range batches[6:] {
			if err := appendBatch(b); err != nil {
				failures <- fmt.Errorf("append: %w", err)
				return
			}
		}
	}()
	go func() { // flush and compaction rewrite and retire segments
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if err := engine.Flush(context.Background()); err != nil {
				failures <- fmt.Errorf("flush: %w", err)
				return
			}
			if err := engine.Compact(context.Background()); err != nil {
				failures <- fmt.Errorf("compact: %w", err)
				return
			}
			time.Sleep(time.Millisecond)
		}
	}()
	var cuts []EngineSnapshot
	go func() { // snapshot + truncation while all of that happens
		defer wg.Done()
		defer close(stop)
		for range 2 {
			cut, err := engine.CreateSnapshots(context.Background())
			if err != nil {
				failures <- fmt.Errorf("snapshot: %w", err)
				return
			}
			cuts = append(cuts, cut)
			if err = engine.CompactJournals(context.Background()); err != nil {
				failures <- fmt.Errorf("truncate: %w", err)
				return
			}
		}
	}()
	wg.Wait()
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
	if len(acked) != len(batches) {
		t.Fatalf("acknowledged %d of %d", len(acked), len(batches))
	}
	// The segment transfer set inside the snapshot matches the manifest it was
	// pinned with, even though compaction retired segments during the copy.
	for _, cut := range cuts {
		seg := cut.Slots[0]
		in, err := seg.File("files/storage-manifest.json")
		if err != nil {
			continue // no segments yet at this cut
		}
		raw, _ := io.ReadAll(in)
		in.Close()
		var manifest Manifest
		if json.Unmarshal(raw, &manifest) != nil {
			t.Fatal("pinned storage manifest unreadable")
		}
		for i, s := range manifest.Segments {
			f, err := seg.File(fmt.Sprintf("files/segment-%06d.sps", i))
			if err != nil {
				t.Fatalf("segment %d of the pinned manifest missing from the snapshot", i)
			}
			h := newFileHash()
			io.Copy(h, f)
			f.Close()
			var got model.Hash
			copy(got[:], h.Sum(nil))
			if got != s.Checksum {
				t.Fatalf("segment %d does not match the pinned manifest checksum", i)
			}
		}
	}
	final, err := engine.CreateSnapshots(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err = engine.CompactJournals(context.Background()); err != nil {
		t.Fatal(err)
	}
	engine.mu.Lock()
	leaked := len(engine.snap.pinned) + len(engine.snap.retired)
	engine.mu.Unlock()
	if leaked != 0 {
		t.Fatalf("snapshot copy left %d pinned/retired files behind", leaked)
	}
	truncated := 0
	for _, group := range engine.repl.groups {
		if first, _ := group.JournalRange(); first > 2 {
			truncated++
		}
	}
	if truncated == 0 {
		t.Fatal("no journal was truncated")
	}
	want := map[model.ID][2][]byte{}
	for _, b := range batches {
		batch, receipt := storedBatch(t, engine, b)
		if len(batch) == 0 || len(receipt) == 0 {
			t.Fatal("ACK without exact stored data")
		}
		want[b.ID] = [2][]byte{batch, receipt}
	}
	check := func(t *testing.T, e *Engine, label string) {
		t.Helper()
		for _, b := range batches {
			original := acked[b.ID]
			retry, err := e.Append(context.Background(), scope, b)
			if err != nil {
				t.Fatalf("%s: retry of an ACKed batch failed: %v", label, err)
			}
			if !bytes.Equal(mustJSON(t, retry), mustJSON(t, original)) {
				t.Fatalf("%s: idempotent retry changed the original receipt", label)
			}
			batch, receipt := storedBatch(t, e, b)
			if !bytes.Equal(batch, want[b.ID][0]) || !bytes.Equal(receipt, want[b.ID][1]) {
				t.Fatalf("%s: stored data differs for an ACKed receipt", label)
			}
		}
	}
	identity := engine.identity
	if err = engine.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := openTestEngine(t, dir, service, store)
	if err != nil {
		t.Fatal(err)
	}
	check(t, restarted, "restart from truncated journal")
	replaced, err := openRestoredEngine(t, t.TempDir(), service, store, identity, installEngineSnapshot(t, final))
	if err != nil {
		t.Fatal(err)
	}
	check(t, replaced, "replacement installed from snapshot")
}

// A compaction that retires segments after the snapshot pinned them but before
// the copy finished must not remove them from under the copy: the snapshot
// holds the pinned manifest's exact bytes and the files are reclaimed on release.
func TestSnapshotPinsSegmentsRetiredDuringCopy(t *testing.T) {
	store, service, credential, descriptor := fixture(t)
	engine, err := openTestEngine(t, t.TempDir(), service, store)
	if err != nil {
		t.Fatal(err)
	}
	scope, first := normalized(t, store, service, credential, descriptor)
	if _, err = engine.Append(context.Background(), scope, first); err != nil {
		t.Fatal(err)
	}
	if err = engine.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	engine.mu.Lock()
	before := append([]SegmentManifest(nil), engine.catalog.Manifest.Segments...)
	engine.mu.Unlock()
	if len(before) == 0 {
		t.Fatal("fixture produced no cold segment")
	}
	var once sync.Once
	var compactErr error
	engine.fault = func(at string) error {
		if at == replica.HookSnapshotFileWrite {
			once.Do(func() {
				_, extra := normalized(t, store, service, credential, descriptor)
				if _, compactErr = engine.Append(context.Background(), scope, extra); compactErr == nil {
					if compactErr = engine.Flush(context.Background()); compactErr == nil {
						compactErr = engine.Compact(context.Background())
					}
				}
			})
		}
		return nil
	}
	cut, err := engine.CreateSnapshots(context.Background())
	engine.fault = nil
	if compactErr != nil {
		t.Fatal(compactErr)
	}
	if err != nil {
		t.Fatalf("snapshot failed when a pinned segment was retired mid-copy: %v", err)
	}
	in, err := cut.Slots[0].File("files/storage-manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(in)
	in.Close()
	var pinned Manifest
	if json.Unmarshal(raw, &pinned) != nil || len(pinned.Segments) != len(before) {
		t.Fatal("snapshot did not keep the manifest it pinned")
	}
	for i, s := range pinned.Segments {
		f, err := cut.Slots[0].File(fmt.Sprintf("files/segment-%06d.sps", i))
		if err != nil {
			t.Fatal(err)
		}
		h := newFileHash()
		io.Copy(h, f)
		f.Close()
		var got model.Hash
		copy(got[:], h.Sum(nil))
		if got != s.Checksum {
			t.Fatalf("segment %d changed during the copy", i)
		}
	}
	engine.mu.Lock()
	leaked := len(engine.snap.pinned) + len(engine.snap.retired)
	engine.mu.Unlock()
	if leaked != 0 {
		t.Fatalf("%d pinned/retired files leaked after release", leaked)
	}
	for _, s := range before {
		path, err := segmentPath(engine.dir, s.File)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("retired segment %s was not reclaimed after the pin was released", s.File)
		}
	}
}

// Every tombstone-class command is carried in the snapshot ledger and survives
// installation; a snapshot stripped of its ledger never becomes ready.
func TestSnapshotCarriesDeletionLedgerAndRejectsStrippedOne(t *testing.T) {
	store, service, credential, descriptor := fixture(t)
	engine, err := openTestEngine(t, t.TempDir(), service, store)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.BindAdmissionOwner(engine); err != nil {
		t.Fatal(err)
	}
	scope, kept := normalized(t, store, service, credential, descriptor)
	if _, err = engine.Append(context.Background(), scope, kept); err != nil {
		t.Fatal(err)
	}
	_, cancelled := normalized(t, store, service, credential, descriptor)
	proof, err := engine.Cancel(context.Background(), scope, cancelled.Reservation)
	if err != nil {
		t.Fatal(err)
	}
	if err = service.BindSourceBarrier(engine); err != nil {
		t.Fatal(err)
	}
	session, err := service.Login(context.Background(), "owner@example.test", "a long test password 2026", "")
	if err != nil {
		t.Fatal(err)
	}
	actor, err := service.Authenticate(context.Background(), session.Token)
	if err != nil {
		t.Fatal(err)
	}
	src, err := service.SourceAuthority(context.Background(), credential, true)
	if err != nil {
		t.Fatal(err)
	}
	next := src.Policy
	next.Revision++
	next.Enabled = false
	operation, err := service.ChangeSourcePolicy(context.Background(), actor, auth.SourcePolicyChange{CommandID: model.NewID(), Source: descriptor.Source, ExpectedRevision: src.Policy.Revision, Policy: next, Reason: "restrict capture"})
	if err != nil || operation.Phase != "fencing" {
		t.Fatalf("closing operation: %v", err)
	}
	if err = service.DrainSourceFences(context.Background()); err != nil {
		t.Fatal(err)
	}
	cut, err := engine.CreateSnapshots(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	fences, cancels := 0, 0
	for _, slot := range cut.Slots {
		in, _ := slot.File("ledger.json")
		var ledger replica.Ledger
		raw, _ := io.ReadAll(in)
		in.Close()
		if json.Unmarshal(raw, &ledger) != nil || ledger.Entries == nil {
			t.Fatal("slot snapshot has no ledger")
		}
		for _, e := range ledger.Entries {
			switch e.Kind {
			case "fence":
				fences++
			case "cancel":
				cancels++
			}
		}
	}
	if fences != 64 || cancels != 1 {
		t.Fatalf("ledger lost tombstones: %d fences, %d cancels", fences, cancels)
	}
	replacement, err := openRestoredEngine(t, t.TempDir(), service, store, engine.identity, installEngineSnapshot(t, cut))
	if err != nil {
		t.Fatal(err)
	}
	if err = replacement.VerifyCancellation(context.Background(), proof); err != nil {
		t.Fatalf("cancellation fence lost across installation: %v", err)
	}
	replacement.mu.Lock()
	var restoredFences int
	_ = replacement.db.View(func(tx *bolt.Tx) error { restoredFences = tx.Bucket([]byte("fences")).Stats().KeyN; return nil })
	replacement.mu.Unlock()
	if restoredFences != 64 {
		t.Fatalf("source tombstones lost across installation: %d", restoredFences)
	}
	if _, err = replacement.Append(context.Background(), scope, cancelled); err == nil {
		t.Fatal("cancelled reservation consumable after installation")
	}
	// Strip the ledger from slot 3's snapshot, re-seal nothing: the receiver refuses.
	stripped := cut.Slots[3].Manifest
	stripped.Files = nil
	for _, f := range cut.Slots[3].Manifest.Files {
		if f.Name != "ledger.json" {
			stripped.Files = append(stripped.Files, f)
		}
	}
	target, err := replica.OpenSnapshotStore(t.TempDir(), stripped.Group, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = target.InstallSnapshot(context.Background(), stripped, bytes.NewReader(nil)); !errors.Is(err, replica.ErrNoLedger) && !errors.Is(err, replica.ErrCorrupt) {
		t.Fatalf("ledger-less snapshot accepted: %v", err)
	}
	if _, ok := target.Current(); ok {
		t.Fatal("ledger-less snapshot became ready")
	}
}

// Kill the engine at each durability boundary of snapshot creation and journal
// truncation. No ACK is lost, an unacknowledged write is retried, not duplicated,
// and the original receipts are returned unchanged.
func TestSnapshotCrashPointsKeepAckedReceipts(t *testing.T) {
	type point struct {
		hook       string
		occurrence int
	}
	var points []point
	for _, h := range []string{replica.HookSnapshotCut, replica.HookSnapshotPin, replica.HookSnapshotFileWrite, replica.HookSnapshotFileSync, replica.HookSnapshotManifestWrite, replica.HookSnapshotDirSync, replica.HookSnapshotSwitch, replica.HookSnapshotRenamed, replica.HookSnapshotCurrentWrite, replica.HookSnapshotCurrentSwitch, replica.HookSnapshotPublished, replica.HookCompactBegin, replica.HookCompactWrite, replica.HookCompactSync, replica.HookCompactSwitch, replica.HookCompactRenamed, replica.HookCompactMemory} {
		points = append(points, point{h, 1})
	}
	representative := map[string]bool{replica.HookSnapshotPin: true, replica.HookSnapshotFileWrite: true, replica.HookSnapshotRenamed: true, replica.HookSnapshotCurrentSwitch: true, replica.HookSnapshotPublished: true, replica.HookCompactWrite: true, replica.HookCompactRenamed: true, replica.HookCompactMemory: true}
	points = append(points, point{replica.HookSnapshotRenamed, 64}, point{replica.HookCompactRenamed, 64})
	store, service, credential, descriptor := fixture(t)
	scope, _ := normalized(t, store, service, credential, descriptor)
	for _, p := range points {
		t.Run(fmt.Sprintf("%s#%d", p.hook, p.occurrence), func(t *testing.T) {
			// Every hook is exercised on a single group in internal/replica; against
			// the real 64-group engine -short keeps one hook per durability boundary.
			if testing.Short() && (p.occurrence > 1 || !representative[p.hook]) {
				t.Skip("full hook matrix runs without -short")
			}
			dir := t.TempDir()
			engine, err := openTestEngine(t, dir, service, store)
			if err != nil {
				t.Fatal(err)
			}
			acked := map[model.ID]model.Receipt{}
			// Batches are single-use in control (one reservation each); a fresh pool
			// member per case keeps every case's ACK set independent.
			var batches []model.NormalizedBatch
			for range 3 {
				_, b := normalized(t, store, service, credential, descriptor)
				batches = append(batches, b)
			}
			_, next := normalized(t, store, service, credential, descriptor)
			for _, b := range batches {
				r, err := engine.Append(context.Background(), scope, b)
				if err != nil {
					t.Fatal(err)
				}
				acked[b.ID] = r
			}
			engine.fault = onceAt(p.hook, p.occurrence)
			_, err = engine.CreateSnapshots(context.Background())
			if err == nil {
				err = engine.CompactJournals(context.Background())
			}
			if err == nil {
				t.Fatalf("hook %s#%d never fired", p.hook, p.occurrence)
			}
			if err = engine.Close(); err != nil {
				t.Fatal(err)
			}
			restarted, err := openTestEngine(t, dir, service, store)
			if err != nil {
				t.Fatalf("restart after crash at %s: %v", p.hook, err)
			}
			for _, b := range batches {
				retry, err := restarted.Append(context.Background(), scope, b)
				if err != nil || !bytes.Equal(mustJSON(t, retry), mustJSON(t, acked[b.ID])) {
					t.Fatalf("ACKed receipt lost or changed after crash at %s: %v", p.hook, err)
				}
				if batch, receipt := storedBatch(t, restarted, b); len(batch) == 0 || len(receipt) == 0 {
					t.Fatal("ACKed data missing")
				}
			}
			// Work continues: a new snapshot/truncation succeeds and a new write is acknowledged once.
			if cut, err := restarted.CreateSnapshots(context.Background()); err != nil || len(cut.Slots) != 64 {
				t.Fatalf("snapshot after crash at %s: %v", p.hook, err)
			}
			if err = restarted.CompactJournals(context.Background()); err != nil {
				t.Fatalf("truncation after crash at %s: %v", p.hook, err)
			}
			if _, err = restarted.Append(context.Background(), scope, next); err != nil {
				t.Fatalf("write after crash at %s: %v", p.hook, err)
			}
		})
	}
}

func controlCut(t *testing.T, e *Engine, store *control.Store) ControlCut {
	t.Helper()
	cut := ControlCut{Reservations: map[string]model.AdmissionReservation{}}
	if err := store.View(context.Background(), func(st control.State) error {
		cut.Revision = st.Revision
		for id, r := range st.Reservations {
			cut.Reservations[id] = r
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for slot, group := range e.repl.groups {
		cut.Processed = append(cut.Processed, model.Cursor{Group: e.group(uint16(slot)), Index: group.Status().ApplicationCursor.Index})
	}
	return cut
}

// Evidence appended after the control highwater H must stay replayable even
// when the journal is reclaimed before the data cut D is sealed; without the pin
// the seal fails instead of silently skipping it.
func TestBackupCutPinsPostCheckpointEvidence(t *testing.T) {
	store, service, credential, descriptor := fixture(t)
	scope, first := normalized(t, store, service, credential, descriptor)
	engine, err := openTestEngine(t, t.TempDir(), service, store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = engine.Append(context.Background(), scope, first); err != nil {
		t.Fatal(err)
	}
	cut := controlCut(t, engine, store)
	post := []model.NormalizedBatch{}
	for range 7 {
		_, b := normalized(t, store, service, credential, descriptor)
		post = append(post, b)
	}
	perSlot := map[uint16]uint64{}
	run := func(batches []model.NormalizedBatch) {
		t.Helper()
		for _, b := range batches {
			if _, err := engine.Append(context.Background(), scope, b); err != nil {
				t.Fatal(err)
			}
			perSlot[b.RouteSlot]++
		}
	}
	reclaim := func() {
		t.Helper() // the live processor/retention reclaiming journal: snapshot + truncate
		if _, err := engine.CreateSnapshots(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := engine.CompactJournals(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("a pin taken at H survives reclamation and the seal proves replay", func(t *testing.T) {
		backup, err := engine.BeginBackup(context.Background(), cut)
		if err != nil {
			t.Fatal(err)
		}
		run(post[:4])
		reclaim()
		run(post[4:])
		reclaim()
		for slot, n := range perSlot {
			// The journal is truncated past the evidence in every slot that has any.
			if first, _ := engine.repl.groups[slot].JournalRange(); first <= 2 || n == 0 {
				t.Fatalf("slot %d journal not truncated (%d)", slot, first)
			}
		}
		sealed, err := backup.Seal(context.Background(), nil)
		if err != nil {
			t.Fatalf("seal failed despite the pin: %v", err)
		}
		var replayed uint64
		groups := map[model.ID]bool{}
		for _, in := range sealed.Bundle.Replay.Intervals {
			groups[in.Group] = true
			if in.Mode != "replay" {
				t.Fatalf("unexpected %s interval", in.Mode)
			}
			replayed += uint64(in.Count)
		}
		if len(groups) != 64 || replayed != uint64(len(post)) {
			t.Fatalf("certificate covers %d groups and %d post-H commands, want 64 and %d", len(groups), replayed, len(post))
		}
		for slot, n := range perSlot {
			var count uint64
			for _, in := range sealed.Bundle.Replay.Intervals {
				if in.Group == engine.group(slot) {
					count += uint64(in.Count)
					if uint64(in.After) < uint64(cut.Processed[slot].Index) {
						t.Fatal("interval starts before H")
					}
				}
			}
			if count != n {
				t.Fatalf("slot %d: %d replayed, want %d", slot, count, n)
			}
		}
		tampered := sealed.Bundle
		tampered.Replay.Intervals = append([]ReplayInterval(nil), tampered.Replay.Intervals...)
		for i := range tampered.Replay.Intervals {
			if tampered.Replay.Intervals[i].Count > 0 {
				tampered.Replay.Intervals[i].Digest[0] ^= 1
				break
			}
		}
		tampered.Replay.Digest = tampered.Replay.seal() // only the snapshot cross-check can catch it now
		if err = verifyReplayAgainstSnapshots(tampered, sealed.Snapshots); err == nil {
			t.Fatal("altered replay digest verified against the snapshot bytes")
		}
	})
	t.Run("without a pin the reclaimed evidence fails the seal; only an exact declared gap explains it", func(t *testing.T) {
		store2, service2, credential2, descriptor2 := fixture(t)
		scope2, base := normalized(t, store2, service2, credential2, descriptor2)
		e2, err := openTestEngine(t, t.TempDir(), service2, store2)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = e2.Append(context.Background(), scope2, base); err != nil {
			t.Fatal(err)
		}
		late := controlCut(t, e2, store2)
		counts := map[uint16]uint64{}
		for range 5 {
			_, b := normalized(t, store2, service2, credential2, descriptor2)
			if _, err = e2.Append(context.Background(), scope2, b); err != nil {
				t.Fatal(err)
			}
			counts[b.RouteSlot]++
		}
		if _, err = e2.CreateSnapshots(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err = e2.CompactJournals(context.Background()); err != nil {
			t.Fatal(err)
		}
		backup, err := e2.BeginBackup(context.Background(), late) // too late: nothing pinned the evidence
		if err != nil {
			t.Fatal(err)
		}
		if _, err = backup.Seal(context.Background(), nil); err == nil {
			t.Fatal("seal succeeded although post-H evidence was reclaimed and no gap was declared")
		}
		var gaps []DeclaredGap
		for slot, n := range counts {
			h := uint64(late.Processed[slot].Index)
			gaps = append(gaps, DeclaredGap{Group: e2.group(slot), After: model.Uint64(h), Through: model.Uint64(h + n), Reason: "retention expired before backup"})
		}
		wrong := append([]DeclaredGap(nil), gaps...)
		wrong[0].Through++ // a gap that does not match the hole is not an explanation
		if _, err = backup.Seal(context.Background(), wrong); err == nil {
			t.Fatal("inexact gap accepted")
		}
		sealed, err := backup.Seal(context.Background(), gaps)
		if err != nil {
			t.Fatalf("exact declared gaps rejected: %v", err)
		}
		var gapCount uint64
		for _, in := range sealed.Bundle.Replay.Intervals {
			if in.Mode == "gap" {
				gapCount += uint64(in.Count)
				if in.Reason == "" {
					t.Fatal("gap without reason")
				}
			}
		}
		if gapCount != 5 {
			t.Fatalf("gap intervals cover %d commands, want 5", gapCount)
		}
	})
	t.Run("a missing group or a deletion fails or restarts the backup", func(t *testing.T) {
		partial := cut
		partial.Processed = cut.Processed[:63]
		if _, err := engine.BeginBackup(context.Background(), partial); err == nil {
			t.Fatal("backup began with a missing group")
		}
		ahead := cut
		ahead.Processed = append([]model.Cursor(nil), cut.Processed...)
		ahead.Processed[0].Index += 1 << 20
		if _, err := engine.BeginBackup(context.Background(), ahead); err == nil {
			t.Fatal("backup began with a highwater beyond the data")
		}
		backup, err := engine.BeginBackup(context.Background(), cut)
		if err != nil {
			t.Fatal(err)
		}
		backup.NoteDeletion() // privacy deletion of a pinned target
		if _, err = backup.Seal(context.Background(), nil); err == nil {
			t.Fatal("sealed a backup after deletion of pinned evidence")
		}
	})
}

// A reservation created after the control cut C and consumed before D must be
// reconstructed as exactly one charge before the restored engine admits anything.
func TestRestoreRebuildsPostControlCutQuota(t *testing.T) {
	store, service, credential, descriptor := fixture(t)
	engine, err := openTestEngine(t, t.TempDir(), service, store)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.BindAdmissionOwner(engine); err != nil {
		t.Fatal(err)
	}
	scope, consumedBeforeC := normalized(t, store, service, credential, descriptor)
	if _, err = engine.Append(context.Background(), scope, consumedBeforeC); err != nil {
		t.Fatal(err)
	}
	if err = store.ReconcileAdmissions(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, pending := normalized(t, store, service, credential, descriptor)         // reserved, never used
	_, refundedBeforeC := normalized(t, store, service, credential, descriptor) // cancelled before C
	proof, err := engine.Cancel(context.Background(), scope, refundedBeforeC.Reservation)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.CancelAdmission(context.Background(), scope, proof); err != nil {
		t.Fatal(err)
	}
	_, refundedAfterC := normalized(t, store, service, credential, descriptor) // reserved at C, cancelled after
	_, consumedAfterC := normalized(t, store, service, credential, descriptor) // reserved at C, used after
	cut := controlCut(t, engine, store)
	backup, err := engine.BeginBackup(context.Background(), cut)
	if err != nil {
		t.Fatal(err)
	}
	// After C: a reservation that control did not know at C is created and consumed.
	scopeLate, createdAfterC := normalized(t, store, service, credential, descriptor)
	if _, err = engine.Append(context.Background(), scopeLate, createdAfterC); err != nil {
		t.Fatal(err)
	}
	if _, ok := cut.Reservations[createdAfterC.Reservation.ID.String()]; ok {
		t.Fatal("fixture: post-C reservation was visible at C")
	}
	receiptAfterC, err := engine.Append(context.Background(), scopeLate, createdAfterC)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = engine.Append(context.Background(), scope, consumedAfterC); err != nil {
		t.Fatal(err)
	}
	proof, err = engine.Cancel(context.Background(), scope, refundedAfterC.Reservation)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.CancelAdmission(context.Background(), scope, proof); err != nil {
		t.Fatal(err)
	}
	if err = store.ReconcileAdmissions(context.Background()); err != nil {
		t.Fatal(err)
	}
	var truth map[string]model.QuotaState
	if err = store.View(context.Background(), func(st control.State) error {
		truth = map[string]model.QuotaState{}
		for k, v := range st.Quotas {
			series := map[string]uint64{}
			for s, n := range v.Series {
				series[s] = n
			}
			v.Series = series
			truth[k] = v
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	sealed, err := backup.Seal(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ReconcileQuota(sealed.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	has := func(ids []model.ID, id model.ID) bool {
		for _, x := range ids {
			if x == id {
				return true
			}
		}
		return false
	}
	if !has(cert.AddedAfterCut, createdAfterC.Reservation.ID) || has(cert.AddedAfterCut, consumedAfterC.Reservation.ID) || has(cert.AddedAfterCut, consumedBeforeC.Reservation.ID) {
		t.Fatal("only the reservation unknown at C may be reconstructed")
	}
	if !has(cert.Refunded, refundedAfterC.Reservation.ID) || !has(cert.Refunded, refundedBeforeC.Reservation.ID) || !has(cert.Pending, pending.Reservation.ID) {
		t.Fatal("cancellation fences and pending intents not reconciled")
	}
	if len(cert.Consumed) != 3 {
		t.Fatalf("%d consumed reservations, want 3", len(cert.Consumed))
	}
	// Applying the certificate to the control state captured at C yields exactly
	// the charges live control holds now: one per consumed reservation.
	atC := map[string]model.QuotaState{}
	for k, v := range truth {
		atC[k] = model.QuotaState{MaxBytes: v.MaxBytes, MaxSeries: v.MaxSeries, Configured: v.Configured, Series: map[string]uint64{}}
	}
	rebuilt := cert.Apply(atC)
	if len(rebuilt) != len(truth) {
		t.Fatalf("certificate touched %d keys, control has %d", len(rebuilt), len(truth))
	}
	for key, want := range truth {
		got := rebuilt[key]
		if got.Bytes != want.Bytes || got.MaxBytes != want.MaxBytes || len(got.Series) != len(want.Series) {
			t.Fatalf("%s: rebuilt bytes=%d series=%d, control bytes=%d series=%d", key, got.Bytes, len(got.Series), want.Bytes, len(want.Series))
		}
		for s, n := range want.Series {
			if got.Series[s] != n {
				t.Fatalf("%s: series refcount %d, want %d (a charge was doubled or dropped)", key, got.Series[s], n)
			}
		}
	}
	// Restore into a clean engine: intake stays closed until the certificate is committed.
	restored, err := openRestoredEngine(t, t.TempDir(), service, store, sealed.Bundle.Identity, func(e *Engine, raft string) error {
		return e.InstallBackup(context.Background(), raft, sealed.Bundle, func(slot uint16) (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(snapshotStream(t, sealed.Snapshots[slot]))), nil
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = restored.RestoreReady(); err == nil {
		t.Fatal("restored engine ready before quota reconciliation")
	}
	_, probe := normalized(t, store, service, credential, descriptor)
	if _, err = restored.Append(context.Background(), scope, probe); err == nil {
		t.Fatal("restored engine admitted before quota reconciliation")
	}
	if _, err = restored.Append(context.Background(), scopeLate, createdAfterC); err == nil {
		t.Fatal("restored engine served receipts before quota reconciliation")
	}
	forged := cert
	forged.Backup[0] ^= 1
	forged.Digest = forged.seal()
	if err = restored.CommitQuotaReconciliation(context.Background(), forged); err == nil {
		t.Fatal("certificate for a different backup accepted")
	}
	wrongSeries := cert
	wrongSeries.SeriesDigest = map[string]model.Hash{}
	for k := range cert.SeriesDigest {
		wrongSeries.SeriesDigest[k] = model.HashCanonical([]byte("not the restored index"))
	}
	wrongSeries.Digest = wrongSeries.seal()
	if err = restored.CommitQuotaReconciliation(context.Background(), wrongSeries); err == nil {
		t.Fatal("certificate disagreeing with the restored project index accepted")
	}
	if restored.RestoreReady() == nil {
		t.Fatal("failed reconciliation opened intake")
	}
	restored.fault = onceAt("quota_certificate_persisted", 1)
	if err = restored.CommitQuotaReconciliation(context.Background(), cert); err == nil {
		t.Fatal("hook did not interrupt the commit")
	}
	restored.fault = nil
	if restored.RestoreReady() == nil {
		t.Fatal("intake opened although the commit was interrupted")
	}
	restored.Close()
	again, err := openRestoredEngine(t, restored.dir, service, store, sealed.Bundle.Identity, nil)
	if err != nil {
		t.Fatal(err)
	}
	if again.RestoreReady() == nil {
		t.Fatal("interrupted reconciliation forgot to keep intake closed across restart")
	}
	if err = again.CommitQuotaReconciliation(context.Background(), cert); err != nil {
		t.Fatal(err)
	}
	if again.RestoreReady() == nil {
		t.Fatal("restored engine ready before its deletion ledger was applied")
	}
	if err = again.ApplyDeletionLedger(context.Background(), replica.Ledger{Version: 1}, nil); err != nil {
		t.Fatal(err)
	}
	if err = again.RestoreReady(); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(again.dir, quotaCertFile)); err != nil {
		t.Fatal("certificate not persisted")
	}
	retry, err := again.Append(context.Background(), scopeLate, createdAfterC)
	if err != nil || !bytes.Equal(mustJSON(t, retry), mustJSON(t, receiptAfterC)) {
		t.Fatalf("restored engine changed the original receipt: %v", err)
	}
	if _, err = again.Append(context.Background(), scope, probe); err != nil {
		t.Fatalf("restored engine refuses new intake after reconciliation: %v", err)
	}
	// Missing proof is a failed installation, not a partial one.
	for name, dropped := range map[string]model.ID{"control consumed it but D has no proof": consumedBeforeC.Reservation.ID, "consumed after C but proof absent": createdAfterC.Reservation.ID} {
		broken := sealed.Bundle
		broken.Quota.Consumed = nil
		for _, c := range sealed.Bundle.Quota.Consumed {
			if c.ID != dropped {
				broken.Quota.Consumed = append(broken.Quota.Consumed, c)
			}
		}
		broken.Quota.Digest = broken.Quota.seal()
		broken.Digest = broken.seal()
		_, err = openRestoredEngine(t, t.TempDir(), service, store, sealed.Bundle.Identity, func(e *Engine, raft string) error {
			return e.InstallBackup(context.Background(), raft, broken, func(slot uint16) (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(snapshotStream(t, sealed.Snapshots[slot]))), nil
			})
		})
		if err == nil {
			t.Fatalf("bundle with missing proof installed (%s)", name)
		}
	}
}
