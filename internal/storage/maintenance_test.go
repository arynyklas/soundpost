// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/model"
)

// ackLog records the receipts a client actually obtained.
type ackLog struct {
	mu       sync.Mutex
	batches  []model.NormalizedBatch
	receipts map[model.ID]model.Receipt
}

func (l *ackLog) add(b model.NormalizedBatch, r model.Receipt) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.receipts == nil {
		l.receipts = map[model.ID]model.Receipt{}
	}
	l.batches = append(l.batches, b)
	l.receipts[b.ID] = r
}
func (l *ackLog) perSlot() map[uint16]uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := map[uint16]uint64{}
	for _, b := range l.batches {
		out[b.RouteSlot]++
	}
	return out
}
func (l *ackLog) snapshot() ([]model.NormalizedBatch, map[model.ID]model.Receipt) {
	l.mu.Lock()
	defer l.mu.Unlock()
	receipts := map[model.ID]model.Receipt{}
	for id, r := range l.receipts {
		receipts[id] = r
	}
	return append([]model.NormalizedBatch(nil), l.batches...), receipts
}

type maintenanceFixture struct {
	t          *testing.T
	v          *voters
	store      *control.Store
	service    *auth.Service
	descriptor model.SourceDescriptor
	scope      auth.Scope
	pool       []model.NormalizedBatch
	acks       *ackLog
}

// distinctBatch builds a normalized, reserved batch whose single row is unique
// by series and time, so every batch produces its own page: batches of one
// series and one timestamp deduplicate into a single row and would leave the
// maintenance paths nothing to move. The series name varies, so batches route
// to several slots.
func distinctBatch(t *testing.T, store *control.Store, a *auth.Service, c auth.SourceCredential, d model.SourceDescriptor, i int) (auth.Scope, model.NormalizedBatch) {
	t.Helper()
	scope, err := a.SourceScope(context.Background(), c, false)
	if err != nil {
		t.Fatal(err)
	}
	src, err := a.SourceAuthority(context.Background(), c, true)
	if err != nil {
		t.Fatal(err)
	}
	b := model.Batch{Version: 1, Project: d.Project, Source: d.Source, Producer: model.NewID(), ID: model.NewID(), PolicyRevision: 1, Records: []model.Record{{ID: model.NewID(), Kind: model.Metric, ObservedAt: model.UnixNano(i + 1), Resource: model.Resource{Service: src.Policy.Resources.Services[0], Environment: src.Policy.Resources.Environments[0], Build: src.Policy.Resources.Builds[0], Instance: src.Policy.Resources.Instances[0]}, Payload: model.Payload{Metric: &model.MetricPoint{Name: fmt.Sprintf("requests_%d", i%9), Labels: model.Labels{}, SampleKind: "float", Value: ptrBits(0x3ff0000000000000), Type: "counter", Unit: "1"}}}}}
	slot, err := model.OwnerSlot(d.Org, b.Project, b.Source, b.Producer, b.Records[0])
	if err != nil {
		t.Fatal(err)
	}
	b.RouteSlot = slot
	raw := mustJSON(t, b)
	n := model.NormalizedBatch{Batch: b, Org: d.Org, Hash: model.HashCanonical(raw), Canonical: raw, PolicyEpoch: model.Uint64(scope.PolicyEpoch()), PolicyHash: model.HashCanonical(mustJSON(t, src.Policy)).String(), AdmissionAt: 10, Deadlines: []model.SignalDeadline{{Kind: model.Metric, RetainUntil: 1 << 40}}}
	if n.Reservation, err = store.ReserveAdmission(context.Background(), scope, n); err != nil {
		t.Fatal(err)
	}
	return scope, n
}

func newMaintenanceFixture(t *testing.T, batches int) *maintenanceFixture {
	t.Helper()
	store, service, credential, descriptor := fixture(t)
	f := &maintenanceFixture{t: t, store: store, service: service, descriptor: descriptor, acks: &ackLog{}}
	f.v = openVoters(t, service, store)
	for i := range batches {
		scope, b := distinctBatch(t, store, service, credential, descriptor, i)
		f.scope, f.pool = scope, append(f.pool, b)
	}
	return f
}

// take hands out the next n unused batches.
func (f *maintenanceFixture) take(n int) []model.NormalizedBatch {
	f.t.Helper()
	if n > len(f.pool) {
		f.t.Fatal("fixture batch pool exhausted")
	}
	out := f.pool[:n]
	f.pool = f.pool[n:]
	return out
}

// ack appends each batch through its leader; any batch that cannot be ACKed
// fails the test because the cluster has a quorum throughout.
func (f *maintenanceFixture) ack(batches []model.NormalizedBatch) {
	f.t.Helper()
	for _, b := range batches {
		receipt, err := f.v.append(f.scope, b)
		if err != nil {
			f.t.Fatalf("append: %v", err)
		}
		f.acks.add(b, receipt)
	}
}

// verify requires every voter to hold every ACKed batch and receipt byte for
// byte, to read exactly the ACKed rows through the public scan path, and every
// retry to return the original receipt. It then reopens each disk from scratch.
func (f *maintenanceFixture) verify() {
	f.t.Helper()
	t := f.t
	f.v.converge(t, f.acks.perSlot())
	batches, receipts := f.acks.snapshot()
	var cursors []model.Cursor
	for _, b := range batches {
		cursors = append(cursors, receipts[b.ID].Cursor)
	}
	read := scanScope(t, f.store, f.service, f.descriptor)
	reference := map[model.ID][2][]byte{}
	for _, b := range batches {
		batch, receipt := storedBatch(t, f.v.engines[1], b)
		var stored model.Receipt
		if len(batch) == 0 || json.Unmarshal(receipt, &stored) != nil || !bytes.Equal(mustJSON(t, stored), mustJSON(t, receipts[b.ID])) {
			t.Fatalf("batch %s: the ACKed receipt is not what node 1 stored", b.ID)
		}
		reference[b.ID] = [2][]byte{batch, receipt}
	}
	for node := uint64(1); node <= 3; node++ {
		engine := f.v.engines[node]
		for _, b := range batches {
			batch, receipt := storedBatch(t, engine, b)
			if !bytes.Equal(batch, reference[b.ID][0]) || !bytes.Equal(receipt, reference[b.ID][1]) {
				t.Fatalf("node %d lost or changed ACKed batch %s", node, b.ID)
			}
		}
		rows := collectPages(t, engine, read, ScanRequest{Projects: []model.ID{f.descriptor.Project}, Signal: model.Metric, Start: 0, End: 1000, Fence: ReadFence{Min: cursors}})
		if len(rows) != len(batches) {
			t.Fatalf("node %d scans %d rows after maintenance, %d were ACKed", node, len(rows), len(batches))
		}
	}
	for _, b := range batches {
		retry, err := f.v.append(f.scope, b)
		if err != nil || !bytes.Equal(mustJSON(t, retry), mustJSON(t, receipts[b.ID])) {
			t.Fatalf("retry of ACKed batch %s did not return the original receipt (%v)", b.ID, err)
		}
	}
	live := map[uint64]Manifest{}
	for node := uint64(1); node <= 3; node++ {
		live[node] = f.v.manifest(node)
	}
	for node := uint64(1); node <= 3; node++ {
		if err := f.v.engines[node].Close(); err != nil {
			t.Fatal(err)
		}
	}
	for node := uint64(1); node <= 3; node++ {
		reopened, err := Open(f.v.dirs[node], f.service)
		if err != nil {
			t.Fatalf("node %d: the manifest, segments or indexes it published do not verify on reopen: %v", node, err)
		}
		if got := reopened.catalog.Manifest; got.Revision != live[node].Revision || len(got.Segments) != len(live[node].Segments) {
			t.Fatalf("node %d reopened at manifest revision %d with %d segments, was %d with %d", node, got.Revision, len(got.Segments), live[node].Revision, len(live[node].Segments))
		}
		reopened.Close()
	}
}

func truncatedJournals(v *voters, node uint64) int {
	count := 0
	for _, group := range v.groups[node] {
		if first, _ := group.JournalRange(); first > 2 {
			count++
		}
	}
	return count
}

// A manifest publication is local to the node. A voter that leads none of the
// groups must still flush hot pages, rewrite segments, cut verified snapshot
// coverage and truncate its own journals, including while leadership moves and
// appends continue. The previous implementation required the caller to be Raft
// leader of all 65 groups at once, so no follower and no node without
// all-group leadership could ever do any of this.
func TestFollowerMaintainsItsLocalLayoutWhileLeadershipMoves(t *testing.T) {
	f := newMaintenanceFixture(t, 110)
	f.v.lead(t, func(int) uint64 { return 1 })
	f.ack(f.take(20))
	f.v.converge(t, f.acks.perSlot())

	background, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	for _, node := range []uint64{2, 3} {
		engine := f.v.engines[node]
		led := 0
		for _, group := range f.v.groups[node] {
			if group.Status().Leader == node {
				led++
			}
		}
		if led == 64 {
			t.Fatalf("node %d leads every group, so this does not exercise a node without all-group leadership", node)
		}
		if err := engine.Flush(background); err != nil {
			t.Fatalf("follower %d could not flush its own hot pages: %v", node, err)
		}
		m := f.v.manifest(node)
		if m.Revision != 1 || len(m.Segments) == 0 {
			t.Fatalf("follower %d manifest after flush: revision %d, %d segments", node, m.Revision, len(m.Segments))
		}
		want := f.acks.perSlot()
		for slot, mark := range m.Applied {
			if uint64(mark.Index) != want[uint16(slot)] {
				t.Fatalf("follower %d manifest records slot %d applied %d, rows cover %d", node, slot, mark.Index, want[uint16(slot)])
			}
		}
	}

	// Compaction, a verified snapshot of every group and journal truncation on a
	// follower; the next publication records the snapshot coverage.
	follower := f.v.engines[2]
	if err := follower.Compact(background); err != nil {
		t.Fatalf("follower compaction: %v", err)
	}
	cut, err := follower.CreateSnapshots(background)
	if err != nil {
		t.Fatalf("follower snapshot: %v", err)
	}
	if err = follower.CompactJournals(background); err != nil {
		t.Fatalf("follower journal truncation: %v", err)
	}
	if truncatedJournals(f.v, 2) == 0 {
		t.Fatal("follower journals were not truncated")
	}
	f.ack(f.take(6))
	f.v.converge(t, f.acks.perSlot())
	if err = follower.Flush(background); err != nil {
		t.Fatalf("follower flush after its snapshot: %v", err)
	}
	m := f.v.manifest(2)
	if len(m.SnapshotCoverage) != 64 {
		t.Fatalf("follower manifest records %d snapshot coverage cursors", len(m.SnapshotCoverage))
	}
	for slot, covered := range m.SnapshotCoverage {
		if covered != cut.Slots[slot].Manifest.Cursor {
			t.Fatalf("slot %d coverage %v does not match the verified snapshot cut %v", slot, covered, cut.Slots[slot].Manifest.Cursor)
		}
	}

	// Nobody leads everything, leadership keeps moving, appends continue, and
	// every node keeps maintaining its own layout.
	f.v.lead(t, func(slot int) uint64 { return uint64(1 + slot%3) })
	failures := make(chan error, 16)
	stop := make(chan struct{})
	var mover, appender, maintainers sync.WaitGroup
	mover.Add(1)
	go func() {
		defer mover.Done()
		for round := 1; ; round++ {
			select {
			case <-stop:
				return
			case <-time.After(150 * time.Millisecond):
			}
			for slot := range 64 {
				if slot%4 != round%4 {
					continue
				}
				for node := uint64(1); node <= 3; node++ {
					if f.v.groups[node][slot].Status().Leader == node {
						ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
						_ = f.v.groups[node][slot].TransferLeadership(ctx, uint64(1+(slot+round)%3))
						cancel()
					}
				}
			}
		}
	}()
	appender.Add(1)
	go func() {
		defer appender.Done()
		for _, b := range f.take(60) {
			receipt, err := f.v.append(f.scope, b)
			if err != nil {
				failures <- fmt.Errorf("append during maintenance: %w", err)
				return
			}
			f.acks.add(b, receipt)
			time.Sleep(5 * time.Millisecond)
		}
	}()
	for node := uint64(1); node <= 3; node++ {
		maintainers.Add(1)
		go func() {
			defer maintainers.Done()
			for round := range 2 {
				if err := f.v.maintain(node); err != nil {
					failures <- fmt.Errorf("node %d maintenance round %d: %w", node, round, err)
					return
				}
			}
		}()
	}
	maintainers.Wait()
	appender.Wait()
	close(stop)
	mover.Wait()
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
	for node := uint64(1); node <= 3; node++ {
		if truncatedJournals(f.v, node) == 0 {
			t.Fatalf("node %d truncated no journal", node)
		}
	}
	f.verify()
}

// Publication, snapshot installation from another node and journal truncation
// all touch the same engine. A voter that is cut off while the others truncate
// their journals past it must be repaired from a snapshot while it flushes,
// compacts and truncates its own journals, without losing or changing a single
// ACKed receipt.
func TestPublicationRacesSnapshotInstallAndJournalTruncation(t *testing.T) {
	f := newMaintenanceFixture(t, 90)
	f.v.lead(t, func(int) uint64 { return 1 })
	f.ack(f.take(10))
	f.v.converge(t, f.acks.perSlot())
	var lastBefore [64]uint64
	for slot, group := range f.v.groups[3] {
		_, lastBefore[slot] = group.JournalRange()
	}

	f.v.mesh.partition(3, true)
	f.ack(f.take(30))
	for _, node := range []uint64{1, 2} {
		if err := f.v.maintain(node); err != nil {
			t.Fatalf("node %d maintenance while node 3 was away: %v", node, err)
		}
	}
	f.ack(f.take(6))

	failures := make(chan error, 16)
	var appender, maintainers sync.WaitGroup
	appender.Add(1)
	go func() {
		defer appender.Done()
		for _, b := range f.take(30) {
			receipt, err := f.v.append(f.scope, b)
			if err != nil {
				failures <- fmt.Errorf("append during repair: %w", err)
				return
			}
			f.acks.add(b, receipt)
			time.Sleep(5 * time.Millisecond)
		}
	}()
	for node := uint64(1); node <= 3; node++ {
		maintainers.Add(1)
		go func() {
			defer maintainers.Done()
			for round := range 2 {
				if err := f.v.maintain(node); err != nil {
					failures <- fmt.Errorf("node %d maintenance round %d: %w", node, round, err)
					return
				}
			}
		}()
	}
	time.Sleep(100 * time.Millisecond)
	f.v.mesh.partition(3, false)
	maintainers.Wait()
	appender.Wait()
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
	f.v.converge(t, f.acks.perSlot())
	installed := 0
	for slot, group := range f.v.groups[3] {
		if first, _ := group.JournalRange(); first > lastBefore[slot]+1 {
			installed++
		}
	}
	if installed == 0 {
		t.Fatal("node 3 was never repaired from a snapshot, so no installation raced its publications")
	}
	f.verify()
}

// A flush writes and verifies the pages it moves. It must not read every cold
// page the store already holds again: publication cost follows the data being
// published, not the whole store, because the engine mutex is held throughout.
func TestFlushOnlyReadsThePagesItPublishes(t *testing.T) {
	store, service, credential, descriptor := fixture(t)
	engine, err := openTestEngine(t, t.TempDir(), service, store)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	flushOne := func(i int) uint64 {
		t.Helper()
		scope, b := distinctBatch(t, store, service, credential, descriptor, i)
		if _, err := engine.Append(ctx, scope, b); err != nil {
			t.Fatal(err)
		}
		before := engine.Stats().PagesRead
		if err := engine.Flush(ctx); err != nil {
			t.Fatal(err)
		}
		return engine.Stats().PagesRead - before
	}
	base := flushOne(0) // an empty store: only the new page is read back
	for i := 1; i <= 8; i++ {
		if reads := flushOne(i); reads != base {
			t.Fatalf("flush %d read %d pages with %d already published; a lone flush reads %d", i, reads, i, base)
		}
	}
	if got := len(engine.catalog.Manifest.Segments); got != 9 {
		t.Fatalf("expected one segment per flush, found %d", got)
	}
}

// The incremental check must keep verifying what it publishes: a segment whose
// pages do not read back correctly is never made authoritative, and the hot
// copies stay readable.
func TestPublicationRejectsANewSegmentThatDoesNotReadBack(t *testing.T) {
	store, service, credential, descriptor := fixture(t)
	engine, err := openTestEngine(t, t.TempDir(), service, store)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	scope, b := distinctBatch(t, store, service, credential, descriptor, 0)
	if _, err = engine.Append(ctx, scope, b); err != nil {
		t.Fatal(err)
	}
	engine.fault = func(at string) error {
		if at != "segment_sync" {
			return nil
		}
		// Damage the freshly written page bytes before the file is hashed.
		return filepath.WalkDir(filepath.Join(engine.dir, "segments"), func(path string, entry fs.DirEntry, err error) error {
			if err != nil || entry.IsDir() || filepath.Ext(path) != ".sps" {
				return err
			}
			f, err := os.OpenFile(path, os.O_RDWR, 0)
			if err != nil {
				return err
			}
			defer f.Close()
			info, err := f.Stat()
			if err != nil {
				return err
			}
			var last [1]byte
			if _, err = f.ReadAt(last[:], info.Size()-1); err != nil {
				return err
			}
			last[0] ^= 0xff
			_, err = f.WriteAt(last[:], info.Size()-1)
			return err
		})
	}
	err = engine.Flush(ctx)
	engine.fault = nil
	var fault *model.Fault
	if !errors.As(err, &fault) || fault.Code != model.Corrupt {
		t.Fatalf("a segment that does not read back was published: %v", err)
	}
	if revision := engine.catalog.Manifest.Revision; revision != 0 || len(engine.catalog.Manifest.Segments) != 0 {
		t.Fatalf("manifest moved to revision %d with %d segments despite the failed verification", revision, len(engine.catalog.Manifest.Segments))
	}
	read := scanScope(t, store, service, descriptor)
	if rows := collectPages(t, engine, read, ScanRequest{Projects: []model.ID{descriptor.Project}, Signal: model.Metric, End: 1000}); len(rows) != 1 {
		t.Fatalf("the hot copy stopped being authoritative: %d rows", len(rows))
	}
	if err = engine.Flush(ctx); err != nil {
		t.Fatalf("the engine did not recover after the rejected publication: %v", err)
	}
}

// Carrying published segments forward still requires every one of them to be
// present at the size it was published with.
func TestPublicationRejectsAResizedPublishedSegment(t *testing.T) {
	store, service, credential, descriptor := fixture(t)
	engine, err := openTestEngine(t, t.TempDir(), service, store)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for i := range 2 {
		scope, b := distinctBatch(t, store, service, credential, descriptor, i)
		if _, err = engine.Append(ctx, scope, b); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			if err = engine.Flush(ctx); err != nil {
				t.Fatal(err)
			}
		}
	}
	path, err := segmentPath(engine.dir, engine.catalog.Manifest.Segments[0].File)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Truncate(path, info.Size()-1); err != nil {
		t.Fatal(err)
	}
	err = engine.Flush(ctx)
	var fault *model.Fault
	if !errors.As(err, &fault) || fault.Code != model.Corrupt {
		t.Fatalf("a published segment with a changed size was carried forward: %v", err)
	}
}
