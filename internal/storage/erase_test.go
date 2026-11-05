// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	bolt "go.etcd.io/bbolt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/model"
	"soundpost/internal/policy"
	"soundpost/internal/replica"
	"testing"
)

const (
	eraseCanary = "CANARY9d41e7b2c0a85f3d1e"
	otherCanary = "OTHERCANARY7f3a91c4de0b2"
	longCanary  = "LONGLIVED5c8a2e0f7b1d349"
	// Metric deadline 100 / log deadline 1000 let EraseExpired distinguish kinds of one batch.
	metricDeadline = model.UnixNano(100)
	logDeadline    = model.UnixNano(1000)
)

type eraseEnv struct {
	t     *testing.T
	store *control.Store
	a     *auth.Service
	cred  auth.SourceCredential
	d     model.SourceDescriptor
	dir   string
	e     *Engine
	read  auth.Scope
	res   model.Resource
}

func newEraseEnv(t *testing.T) *eraseEnv {
	t.Helper()
	store, a, c, d := typedFixture(t)
	x := &eraseEnv{t: t, store: store, a: a, cred: c, d: d, dir: t.TempDir()}
	x.reopen()
	src, err := a.SourceAuthority(context.Background(), c, true)
	if err != nil {
		t.Fatal(err)
	}
	r := src.Policy.Resources
	x.res = model.Resource{Service: r.Services[0], Environment: r.Environments[0], Build: r.Builds[0], Instance: r.Instances[0]}
	x.read = scanScope(t, store, a, d)
	return x
}

// reopen (re)opens the engine on the same directory, as a restart does.
func (x *eraseEnv) reopen() {
	x.t.Helper()
	if x.e != nil {
		if err := x.e.Close(); err != nil {
			x.t.Fatal(err)
		}
	}
	e, err := openTestEngine(x.t, x.dir, x.a, x.store)
	if err != nil {
		x.t.Fatal(err)
	}
	x.e = e
}
func (x *eraseEnv) metric(name string, at model.UnixNano) model.Record {
	return model.Record{ID: model.NewID(), Kind: model.Metric, ObservedAt: at, Resource: x.res, Payload: model.Payload{Metric: &model.MetricPoint{Name: name, Labels: model.Labels{{Name: "zone", Value: "a"}}, SampleKind: "float", Value: ptrBits(0x3ff0000000000000), Unit: "1", Type: "gauge"}}}
}
func (x *eraseEnv) log() model.Record {
	var safe model.Scalar
	_ = json.Unmarshal([]byte(`9007199254740993`), &safe)
	return model.Record{ID: model.NewID(), Kind: model.Log, ObservedAt: 50, Resource: x.res, Payload: model.Payload{Log: &model.LogRecord{Severity: "error", TemplateID: "failed", TemplateRevision: 1, Fields: map[string]model.Scalar{"count": safe}, Line: "same safe line", StreamLabels: model.Labels{{Name: "stream", Value: "test"}}, Metadata: map[string]model.Scalar{"count": safe}, SourceClass: "structured"}}}
}

type erased struct {
	batch   model.NormalizedBatch
	receipt model.Receipt
	scope   auth.Scope
	secret  model.Record // observed 5, carries the canary in its series name
	keepM   model.Record // observed 50, same batch
	keepL   model.Record // same batch, different kind
}

// appendMixed admits one batch of a canary metric (t=5), a kept metric (t=50) and a kept log
// line. A batch is slot-atomic, so metric names are searched until both metrics route to the
// slot the (fixed-label) log routes to.
func (x *eraseEnv) appendMixed(canary string, deadlines []model.SignalDeadline) erased {
	x.t.Helper()
	producer := model.NewID()
	keepL := x.log()
	want, err := model.OwnerSlot(x.d.Org, x.d.Project, x.d.Source, producer, keepL)
	if err != nil {
		x.t.Fatal(err)
	}
	find := func(prefix string, at model.UnixNano) model.Record {
		for salt := range 1 << 16 {
			r := x.metric(fmt.Sprintf("%s_%d", prefix, salt), at)
			if s, err := model.OwnerSlot(x.d.Org, x.d.Project, x.d.Source, producer, r); err == nil && s == want {
				return r
			}
		}
		x.t.Fatal("no metric name routes to the log slot")
		return model.Record{}
	}
	// A distinct kept series per batch: an equal (series, time) in a second batch is a duplicate
	// the engine deliberately does not store.
	secret, keepM := find("secret"+canary, 5), find("kept"+model.NewID().String()[:12], 50)
	b, r, scope := x.appendRecords(producer, deadlines, secret, keepM, keepL)
	return erased{batch: b, receipt: r, scope: scope, secret: secret, keepM: keepM, keepL: keepL}
}
func (x *eraseEnv) appendRecords(producer model.ID, deadlines []model.SignalDeadline, recs ...model.Record) (model.NormalizedBatch, model.Receipt, auth.Scope) {
	x.t.Helper()
	ctx := context.Background()
	src, err := x.a.SourceAuthority(ctx, x.cred, true)
	if err != nil {
		x.t.Fatal(err)
	}
	service, err := policy.New(x.a, nil)
	if err != nil {
		x.t.Fatal(err)
	}
	grant, err := service.ResolveSource(ctx, x.cred, x.d.Project, x.d.Source, src.Policy.Revision)
	if err != nil {
		x.t.Fatal(err)
	}
	b := model.Batch{Version: 1, Project: x.d.Project, Source: x.d.Source, Producer: producer, ID: model.NewID(), PolicyRevision: src.Policy.Revision, Records: recs}
	b.RouteSlot, err = model.OwnerSlot(x.d.Org, b.Project, b.Source, b.Producer, recs[0])
	if err != nil {
		x.t.Fatal(err)
	}
	n, err := policy.Normalize(grant, b)
	if err != nil {
		x.t.Fatal("normalize: ", err)
	}
	n.Deadlines = deadlines // deadlines are not part of the canonical bytes or the reservation binding
	scope, err := grant.Scope()
	if err != nil {
		x.t.Fatal(err)
	}
	if n.Reservation, err = x.store.ReserveAdmission(ctx, scope, n); err != nil {
		x.t.Fatal("reserve: ", err)
	}
	r, err := x.e.Append(ctx, scope, n)
	if err != nil {
		x.t.Fatal("append: ", err)
	}
	return n, r, scope
}

var bothDeadlines = []model.SignalDeadline{{Kind: model.Metric, RetainUntil: metricDeadline}, {Kind: model.Log, RetainUntil: logDeadline}}

func (x *eraseEnv) rangePredicate(start, end model.UnixNano, kinds ...model.Kind) model.DeletePredicate {
	return model.DeletePredicate{Operation: model.NewID(), Org: x.d.Org, Mode: model.DeleteHistoricalRange, Projects: []model.ID{x.d.Project}, Signals: kinds, Start: start, End: end, Generation: 1}
}
func (x *eraseEnv) ids(kind model.Kind) []model.ID {
	x.t.Helper()
	var out []model.ID
	for _, r := range collectPages(x.t, x.e, x.read, ScanRequest{Projects: []model.ID{x.d.Project}, Signal: kind, Start: 0, End: 1 << 40}) {
		out = append(out, r.ID)
	}
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i][:], out[j][:]) < 0 })
	return out
}
func sortedIDs(rs ...model.Record) []model.ID {
	out := make([]model.ID, len(rs))
	for i, r := range rs {
		out[i] = r.ID
	}
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i][:], out[j][:]) < 0 })
	return out
}

// rawHits lists where canary bytes live in the apply database (keys and values of every bucket,
// nested included) and in the segment files. bbolt free pages are not scanned here: they are
// not reachable through any bucket and cannot be scrubbed by an erasure pass.
func canaryForms(canary string) [][]byte {
	forms := [][]byte{[]byte(canary)}
	// Batch commands carry the canonical input as base64: look for the three alignments of the
	// canary's interior (drop the first and last 4-character groups, which mix in neighbours).
	for offset := range 3 {
		enc := base64.StdEncoding.EncodeToString(append(make([]byte, offset), canary...))
		forms = append(forms, []byte(enc[4:len(enc)-4]))
	}
	return forms
}
func containsAny(haystack []byte, forms [][]byte) bool {
	for _, f := range forms {
		if bytes.Contains(haystack, f) {
			return true
		}
	}
	return false
}
func rawHits(t *testing.T, e *Engine, canary string) []string {
	t.Helper()
	var hits []string
	forms := canaryForms(canary)
	var walk func(path string, b *bolt.Bucket)
	walk = func(path string, b *bolt.Bucket) {
		_ = b.ForEach(func(k, v []byte) error {
			if v == nil {
				walk(path+"/"+string(k), b.Bucket(k))
			} else if containsAny(k, forms) || containsAny(v, forms) {
				hits = append(hits, path)
			}
			return nil
		})
	}
	if err := e.db.View(func(tx *bolt.Tx) error {
		return tx.ForEach(func(name []byte, b *bolt.Bucket) error { walk(string(name), b); return nil })
	}); err != nil {
		t.Fatal(err)
	}
	_ = filepath.WalkDir(filepath.Join(e.dir, "segments"), func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if raw, rerr := os.ReadFile(p); rerr == nil && containsAny(raw, forms) {
				hits = append(hits, "segment:"+filepath.Base(p))
			}
		}
		return nil
	})
	return hits
}
func hasHit(hits []string, prefix string) bool {
	for _, h := range hits {
		if len(h) >= len(prefix) && h[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}
func (x *eraseEnv) integrity() {
	x.t.Helper()
	if err := x.e.db.View(validateIndexIntegrity); err != nil {
		x.t.Fatalf("scan_integrity digests/row counts invalid after erase: %v", err)
	}
}
func (x *eraseEnv) command(b model.NormalizedBatch, r model.Receipt) []byte {
	x.t.Helper()
	var raw []byte
	_ = x.e.db.View(func(tx *bolt.Tx) error {
		raw = bytes.Clone(tx.Bucket([]byte("replica_commands")).Get(commandKey(b.RouteSlot, uint64(r.Cursor.Index))))
		return nil
	})
	if raw == nil {
		x.t.Fatal("command missing")
	}
	return raw
}
func (x *eraseEnv) coldCanary(c string) {
	x.t.Helper()
	ctx := context.Background()
	if err := x.e.Flush(ctx); err != nil {
		x.t.Fatal(err)
	}
	if err := x.e.Compact(ctx); err != nil {
		x.t.Fatal(err)
	}
	_ = c
}

// A deletion that only hides rows leaves their bytes in the command history, the batch, the
// metric and the scan pages. Physical erasure must remove every reachable copy.
func TestDeleteEraseRemovesBytesAndKeepsSiblings(t *testing.T) {
	x := newEraseEnv(t)
	hit := x.appendMixed(eraseCanary, bothDeadlines)
	other := x.appendMixed(otherCanary, bothDeadlines)
	x.coldCanary(eraseCanary)
	before := rawHits(t, x.e, eraseCanary)
	for _, want := range []string{"replica_commands", "batches", "metrics", "segment:"} {
		if !hasHit(before, want) {
			t.Fatalf("fixture invalid: canary not stored in %s (hits %v)", want, before)
		}
	}
	original := x.command(hit.batch, hit.receipt)

	report, err := x.e.EraseDeleted(context.Background(), []model.DeletePredicate{x.rangePredicate(0, 10, model.Metric)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if report.Batches < 2 || report.Records < 2 || report.Held != 0 || report.Pages == 0 || report.SegmentsRewritten == 0 {
		t.Fatalf("report %+v", report)
	}
	if hits := rawHits(t, x.e, eraseCanary); len(hits) != 0 {
		t.Fatalf("erased bytes still present in %v", hits)
	}
	if hits := rawHits(t, x.e, otherCanary); len(hits) != 0 {
		t.Fatalf("second erased batch bytes still present in %v", hits)
	}
	if got, want := x.ids(model.Metric), sortedIDs(hit.keepM, other.keepM); !reflect.DeepEqual(got, want) {
		t.Fatalf("metric scan after erase %v want only kept siblings %v (hit keep %s, other keep %s, hit secret %s, other secret %s)", got, want, hit.keepM.ID, other.keepM.ID, hit.secret.ID, other.secret.ID)
	}
	if got, want := x.ids(model.Log), sortedIDs(hit.keepL, other.keepL); !reflect.DeepEqual(got, want) {
		t.Fatalf("log of a batch with an erased metric lost: %v want %v", got, want)
	}
	x.integrity()
	var redacted walEntry
	if err = json.Unmarshal(x.command(hit.batch, hit.receipt), &redacted); err != nil {
		t.Fatal(err)
	}
	var kept model.Batch
	if redacted.Type != "batch_redacted" || redacted.Redaction == nil || redacted.Redaction.Original != sha256.Sum256(original) || redacted.Redaction.Erased != 1 || len(redacted.Batch.Records) != 2 || redacted.Receipt == nil || redacted.Receipt.Cursor != hit.receipt.Cursor || redacted.Batch.Hash != hit.batch.Hash || model.StrictJSON(redacted.Batch.Canonical, &kept) != nil || len(kept.Records) != 2 {
		t.Fatalf("redacted command wrong: %+v", redacted.Redaction)
	}
	retry, err := x.e.Append(context.Background(), hit.scope, hit.batch)
	if err != nil || !bytes.Equal(mustJSON(t, retry), mustJSON(t, hit.receipt)) {
		t.Fatalf("retry after erase did not return the original receipt: %v", err)
	}
	again, err := x.e.EraseDeleted(context.Background(), []model.DeletePredicate{x.rangePredicate(0, 10, model.Metric)}, nil)
	if err != nil || again != (EraseReport{}) {
		t.Fatalf("rerun not a no-op: %+v %v", again, err)
	}
	x.reopen()
	if got, want := x.ids(model.Metric), sortedIDs(hit.keepM, other.keepM); !reflect.DeepEqual(got, want) {
		t.Fatalf("restart changed rows: %v", got)
	}
	x.integrity()
}

// Selectivity: another project, a signal outside the predicate or a time outside [Start,End)
// must keep its bytes.
func TestDeleteEraseIgnoresNonMatchingPredicates(t *testing.T) {
	x := newEraseEnv(t)
	hit := x.appendMixed(eraseCanary, bothDeadlines)
	preds := []model.DeletePredicate{
		{Operation: model.NewID(), Org: x.d.Org, Mode: model.DeleteHistoricalRange, Projects: []model.ID{model.NewID()}, Signals: []model.Kind{model.Metric}, Start: 0, End: 1 << 40, Generation: 1},
		x.rangePredicate(0, 10, model.Log),
		x.rangePredicate(6, 49, model.Metric),
	}
	report, err := x.e.EraseDeleted(context.Background(), preds, nil)
	if err != nil || report != (EraseReport{}) {
		t.Fatalf("non-matching predicates erased something: %+v %v", report, err)
	}
	if !hasHit(rawHits(t, x.e, eraseCanary), "replica_commands") {
		t.Fatal("bytes removed by a predicate that does not cover them")
	}
	if got := x.ids(model.Metric); len(got) != 2 {
		t.Fatalf("rows %v (%v)", got, hit.secret.ID)
	}
}

// Holds, reference counting and the evidence gate veto erasure through the guard; a vetoed
// record stays physically present and is reported, an erroring guard fails closed.
func TestDeleteGuardVetoKeepsBytesAndReportsHeld(t *testing.T) {
	x := newEraseEnv(t)
	hit := x.appendMixed(eraseCanary, bothDeadlines)
	var seen []EraseCandidate
	report, err := x.e.EraseDeleted(context.Background(), []model.DeletePredicate{x.rangePredicate(0, 10, model.Metric)}, func(_ context.Context, c EraseCandidate) (bool, error) {
		seen = append(seen, c)
		return false, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Held != 1 || report.Records != 0 || report.Batches != 0 {
		t.Fatalf("report %+v", report)
	}
	if len(seen) != 1 || seen[0].Record == nil || seen[0].Record.ID != hit.secret.ID || seen[0].Blob != nil || seen[0].Kind != model.Metric || seen[0].Org != x.d.Org || seen[0].Project != x.d.Project || seen[0].Slot != hit.batch.RouteSlot || seen[0].Cursor != hit.receipt.Cursor || seen[0].Deadline != 0 {
		t.Fatalf("candidate %+v", seen)
	}
	if !hasHit(rawHits(t, x.e, eraseCanary), "replica_commands") || !hasHit(rawHits(t, x.e, eraseCanary), "batches") {
		t.Fatal("vetoed record bytes were removed")
	}
	_, err = x.e.EraseDeleted(context.Background(), []model.DeletePredicate{x.rangePredicate(0, 10, model.Metric)}, func(context.Context, EraseCandidate) (bool, error) {
		return true, errors.New("evidence gate unavailable")
	})
	if err == nil || !hasHit(rawHits(t, x.e, eraseCanary), "replica_commands") {
		t.Fatalf("guard error did not fail closed: %v", err)
	}
	// Released: the same call now erases.
	if report, err = x.e.EraseDeleted(context.Background(), []model.DeletePredicate{x.rangePredicate(0, 10, model.Metric)}, nil); err != nil || report.Records != 1 {
		t.Fatalf("%+v %v", report, err)
	}
}

// Receipt deadlines are exact: deadline == now erases, now-1 does not, and kinds with a later
// deadline in the same batch (and later batches) are untouched.
func TestExpireHonorsReceiptDeadlinesExactly(t *testing.T) {
	x := newEraseEnv(t)
	short := x.appendMixed(eraseCanary, bothDeadlines)
	long := x.appendMixed(longCanary, []model.SignalDeadline{{Kind: model.Metric, RetainUntil: 500}, {Kind: model.Log, RetainUntil: logDeadline}})
	// Nothing was flushed: the canary also sits in a hot page inside scan_pages.
	if !hasHit(rawHits(t, x.e, eraseCanary), "scan_pages") {
		t.Fatal("fixture invalid: canary not in a hot page")
	}
	var seen []EraseCandidate
	guard := func(_ context.Context, c EraseCandidate) (bool, error) { seen = append(seen, c); return true, nil }
	report, err := x.e.EraseExpired(context.Background(), metricDeadline-1, guard)
	if err != nil || report != (EraseReport{}) || len(seen) != 0 {
		t.Fatalf("erased before the deadline: %+v %v %v", report, err, seen)
	}
	report, err = x.e.EraseExpired(context.Background(), metricDeadline, guard)
	if err != nil {
		t.Fatal(err)
	}
	if report.Batches != 1 || report.Records != 2 || report.Held != 0 {
		t.Fatalf("report %+v", report)
	}
	for _, c := range seen {
		if c.Deadline != metricDeadline || c.Kind != model.Metric || c.Record == nil {
			t.Fatalf("candidate %+v", c)
		}
	}
	if hits := rawHits(t, x.e, eraseCanary); len(hits) != 0 {
		t.Fatalf("expired bytes present in %v (hot pages included)", hits)
	}
	if !hasHit(rawHits(t, x.e, longCanary), "replica_commands") {
		t.Fatal("unexpired batch was erased")
	}
	if got, want := x.ids(model.Log), sortedIDs(short.keepL, long.keepL); !reflect.DeepEqual(got, want) {
		t.Fatalf("log with a later deadline in the same batch was erased: %v", got)
	}
	if got, want := x.ids(model.Metric), sortedIDs(long.secret, long.keepM); !reflect.DeepEqual(got, want) {
		t.Fatalf("metrics %v want %v", got, want)
	}
	// The stored receipt (deadlines, dedup window) is still the original.
	if retry, err := x.e.Append(context.Background(), short.scope, short.batch); err != nil || !bytes.Equal(mustJSON(t, retry), mustJSON(t, short.receipt)) {
		t.Fatalf("receipt changed by expiry: %v", err)
	}
	x.integrity()
	if again, err := x.e.EraseExpired(context.Background(), metricDeadline, nil); err != nil || again != (EraseReport{}) {
		t.Fatalf("rerun %+v %v", again, err)
	}
	// Later the log kind of the same batch expires on its own receipt deadline.
	if report, err = x.e.EraseExpired(context.Background(), logDeadline, nil); err != nil || report.Records < 2 {
		t.Fatalf("%+v %v", report, err)
	}
}

func dumpBuckets(t *testing.T, e *Engine, names ...string) map[string]map[string]string {
	t.Helper()
	out := map[string]map[string]string{}
	if err := e.db.View(func(tx *bolt.Tx) error {
		for _, n := range names {
			b := tx.Bucket([]byte(n))
			if b == nil {
				t.Fatalf("bucket %s", n)
			}
			m := map[string]string{}
			_ = b.ForEach(func(k, v []byte) error { m[string(k)] = string(v); return nil })
			out[n] = m
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

var derivedBuckets = []string{"batches", "receipts", "consumed", "metrics", "jobs", "scan_pages", "scan_time", "scan_postings", "scan_commits", "scan_integrity"}

// Restore / snapshot install replays the stored history through applyTx. A history containing a
// redaction must rebuild exactly the state the erasing node holds.
func TestDeleteRedactedHistoryReplaysToIdenticalState(t *testing.T) {
	x := newEraseEnv(t)
	hit := x.appendMixed(eraseCanary, bothDeadlines)
	x.appendMixed(otherCanary, bothDeadlines)
	if _, err := x.e.EraseDeleted(context.Background(), []model.DeletePredicate{x.rangePredicate(0, 10, model.Metric)}, nil); err != nil {
		t.Fatal(err)
	}
	want := dumpBuckets(t, x.e, derivedBuckets...)
	// Every slot that holds history is replayed, in slot order, from its own snapshot.
	type replay struct {
		m        *slotMachine
		snapshot []byte
		physical uint64
	}
	var replays []replay
	for s := range uint16(64) {
		x.e.mu.Lock()
		active := x.e.indexes[s] != 0
		x.e.mu.Unlock()
		if !active {
			continue
		}
		m := &slotMachine{engine: x.e, slot: s}
		snapshot, err := m.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		replays = append(replays, replay{m: m, snapshot: snapshot})
	}
	if len(replays) == 0 {
		t.Fatal("no slot has history")
	}
	_ = hit
	// Wipe every derived row and the applied cursors, as an empty replica has.
	if err := x.e.db.Update(func(tx *bolt.Tx) error {
		for i := range replays {
			replays[i].physical = getUint(tx.Bucket([]byte("replica_data")), metaKey(replays[i].m.slot, "physical"))
			if err := tx.Bucket([]byte("cursors")).Delete(slotKey(replays[i].m.slot)); err != nil {
				return err
			}
		}
		for _, n := range derivedBuckets {
			b := tx.Bucket([]byte(n))
			var keys [][]byte
			_ = b.ForEach(func(k, _ []byte) error { keys = append(keys, bytes.Clone(k)); return nil })
			for _, k := range keys {
				if err := b.Delete(k); err != nil {
					return err
				}
			}
		}
		for _, n := range []string{"scan_time", "scan_postings"} {
			if err := tx.Bucket([]byte("scan_integrity")).Put([]byte(n), digestBytes(IndexDigest{})); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, r := range replays {
		x.e.mu.Lock()
		x.e.indexes[r.m.slot] = 0
		x.e.mu.Unlock()
		if err := r.m.Restore(r.snapshot, r.physical); err != nil {
			t.Fatalf("replaying redacted history of slot %d: %v", r.m.slot, err)
		}
	}
	got := dumpBuckets(t, x.e, derivedBuckets...)
	for _, n := range derivedBuckets {
		if !reflect.DeepEqual(got[n], want[n]) {
			t.Fatalf("bucket %s differs after replaying the redacted history: %d rows want %d", n, len(got[n]), len(want[n]))
		}
	}
	x.integrity()
	if hits := rawHits(t, x.e, eraseCanary); len(hits) != 0 {
		t.Fatalf("replay resurrected erased bytes in %v", hits)
	}
}

// A snapshot taken before the erasure and one taken after it describe the same history:
// whichever side holds the redaction, VerifySnapshot accepts; real divergence is still Corrupt.
func TestDeleteVerifySnapshotAcceptsEitherSideRedacted(t *testing.T) {
	x := newEraseEnv(t)
	hit := x.appendMixed(eraseCanary, bothDeadlines)
	m := &slotMachine{engine: x.e, slot: hit.batch.RouteSlot}
	pre, err := m.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = x.e.EraseDeleted(context.Background(), []model.DeletePredicate{x.rangePredicate(0, 10, model.Metric)}, nil); err != nil {
		t.Fatal(err)
	}
	post, err := m.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if err = m.VerifySnapshot(pre); err != nil {
		t.Fatalf("pre-erasure snapshot refused by a node holding the redaction: %v", err)
	}
	if err = m.VerifySnapshot(post); err != nil {
		t.Fatalf("redacted snapshot refused: %v", err)
	}
	var snap slotSnapshot
	if err = json.Unmarshal(pre, &snap); err != nil {
		t.Fatal(err)
	}
	var forged walEntry
	if err = json.Unmarshal(snap.Entries[len(snap.Entries)-1], &forged); err != nil {
		t.Fatal(err)
	}
	forged.Batch.AdmissionAt++ // a different command, not the original of the redaction
	if snap.Entries[len(snap.Entries)-1], err = json.Marshal(forged); err != nil {
		t.Fatal(err)
	}
	tampered, _ := json.Marshal(snap)
	if err = m.VerifySnapshot(tampered); err == nil {
		t.Fatal("a command that is not the original of the redaction was accepted")
	}
	// Backup replay digests are computed on the journal form; the redacted form must agree.
	var originalEntry, redactedEntry walEntry
	var preSnap, postSnap slotSnapshot
	_ = json.Unmarshal(pre, &preSnap)
	_ = json.Unmarshal(post, &postSnap)
	last := len(preSnap.Entries) - 1
	_ = json.Unmarshal(preSnap.Entries[last], &originalEntry)
	_ = json.Unmarshal(postSnap.Entries[last], &redactedEntry)
	a, _ := evidenceDigest(originalEntry)
	b, _ := evidenceDigest(redactedEntry)
	if a != b {
		t.Fatal("evidence digest of a redacted command differs from the journal original")
	}
}

// The journal re-delivers the original entry (leader relocation, restart replay). It must be
// recognised as the redacted command, while a different command at that index is corruption.
func TestDeleteApplyAcceptsOriginalJournalEntryForRedactedCommand(t *testing.T) {
	x := newEraseEnv(t)
	hit := x.appendMixed(eraseCanary, bothDeadlines)
	original := x.command(hit.batch, hit.receipt)
	if _, err := x.e.EraseDeleted(context.Background(), []model.DeletePredicate{x.rangePredicate(0, 10, model.Metric)}, nil); err != nil {
		t.Fatal(err)
	}
	m := &slotMachine{engine: x.e, slot: hit.batch.RouteSlot}
	var physical uint64
	_ = x.e.db.View(func(tx *bolt.Tx) error {
		physical = getUint(tx.Bucket([]byte("replica_data")), metaKey(m.slot, "logical:"+fmt.Sprint(uint64(hit.receipt.Cursor.Index))))
		return nil
	})
	if physical == 0 {
		t.Fatal("no physical index for the command")
	}
	deliver := func(payload []byte) error {
		return m.Apply(replica.CommittedEntry{Group: x.e.group(m.slot), Term: 1, Index: physical, ApplicationCursor: hit.receipt.Cursor, Entry: replica.Entry{ID: model.NewID(), Kind: replica.Data, Payload: payload, ApplicationIndex: uint64(hit.receipt.Cursor.Index)}})
	}
	if err := deliver(original); err != nil {
		t.Fatalf("original journal entry rejected for a redacted command: %v", err)
	}
	var forged walEntry
	_ = json.Unmarshal(original, &forged)
	forged.Batch.AdmissionAt++
	raw, _ := json.Marshal(forged)
	if err := deliver(raw); err == nil {
		t.Fatal("a different command was accepted at a redacted index")
	}
}

// Every bolt transaction leaves a consistent engine; a crash anywhere in a pass reopens cleanly
// and a rerun completes the erasure.
func TestDeleteCrashHooksReopenCleanlyAndRerunCompletes(t *testing.T) {
	for _, hook := range []string{"erase_batch", "erase_redacted", "erase_compact"} {
		t.Run(hook, func(t *testing.T) {
			x := newEraseEnv(t)
			hit := x.appendMixed(eraseCanary, bothDeadlines)
			x.coldCanary(eraseCanary)
			x.e.fault = func(at string) error {
				if at == hook {
					return errors.New("crash at " + at)
				}
				return nil
			}
			preds := []model.DeletePredicate{x.rangePredicate(0, 10, model.Metric)}
			if _, err := x.e.EraseDeleted(context.Background(), preds, nil); err == nil {
				t.Fatalf("hook %s never fired", hook)
			}
			x.reopen()
			x.integrity()
			cold := hasHit(rawHits(t, x.e, eraseCanary), "segment:")
			if hook != "erase_compact" && !hasHit(rawHits(t, x.e, eraseCanary), "replica_commands") {
				t.Fatal("aborted transaction left a partial erasure")
			}
			if hook == "erase_compact" && (hasHit(rawHits(t, x.e, eraseCanary), "replica_commands") || !cold) {
				t.Fatalf("metadata pass not durable before compaction (cold segment hit %v)", cold)
			}
			report, err := x.e.EraseDeleted(context.Background(), preds, nil)
			if err != nil {
				t.Fatal(err)
			}
			if hook == "erase_compact" && (report.Batches != 0 || report.SegmentsRewritten == 0) {
				t.Fatalf("rerun after a crash before compaction did not rewrite the stale segment: %+v", report)
			}
			if hits := rawHits(t, x.e, eraseCanary); len(hits) != 0 {
				t.Fatalf("rerun left bytes in %v", hits)
			}
			if got, want := x.ids(model.Metric), sortedIDs(hit.keepM); !reflect.DeepEqual(got, want) {
				t.Fatalf("rows %v want %v", got, want)
			}
			x.integrity()
		})
	}
}

// Artifact roots covered by a predicate lose their fragments, root and fragment commands.
func TestDeleteErasesArtifactRootAndFragmentCommands(t *testing.T) {
	c, a, scope, m, raw := blobFixture(t)
	ctx := context.Background()
	e, err := openTestEngine(t, t.TempDir(), a, c)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := e.WriteBlob(ctx, scope, m, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	counts := func() [3]uint64 {
		var n [3]uint64
		_ = e.db.View(func(tx *bolt.Tx) error {
			v := tx.Bucket([]byte("meta")).Get([]byte("artifact_counts"))
			for i := range n {
				n[i] = binary.BigEndian.Uint64(v[i*8:])
			}
			return nil
		})
		return n
	}
	fragmentCommands := func() (plain int, redacted int) {
		_ = e.db.View(func(tx *bolt.Tx) error {
			return tx.Bucket([]byte("replica_commands")).ForEach(func(_, v []byte) error {
				var entry walEntry
				if json.Unmarshal(v, &entry) == nil {
					switch entry.Type {
					case "artifact_fragment":
						if entry.Artifact != nil && len(entry.Artifact.Bytes) > 0 {
							plain++
						}
					case "artifact_redacted":
						if entry.Artifact == nil && entry.Redaction != nil && entry.Redaction.Erased == 1 {
							redacted++
						}
					}
				}
				return nil
			})
		})
		return
	}
	if p, _ := fragmentCommands(); p != 2 || counts() != [3]uint64{1, 2, 0} {
		t.Fatalf("fixture: %d fragment commands, counts %v", p, counts())
	}
	pred := model.DeletePredicate{Operation: model.NewID(), Org: m.Org, Mode: model.DeleteRetireProject, Projects: []model.ID{m.Project}, Generation: 1}
	var seen []EraseCandidate
	report, err := e.EraseDeleted(ctx, []model.DeletePredicate{pred}, func(_ context.Context, cand EraseCandidate) (bool, error) {
		seen = append(seen, cand)
		return false, nil
	})
	if err != nil || report.Held != 1 || report.Blobs != 0 || len(seen) != 1 || seen[0].Blob == nil || seen[0].Record != nil || seen[0].Blob.Root != m.Root {
		t.Fatalf("held artifact: %+v %v %+v", report, err, seen)
	}
	if p, _ := fragmentCommands(); p != 2 || counts() != [3]uint64{1, 2, 0} {
		t.Fatal("vetoed artifact was erased")
	}
	if report, err = e.EraseDeleted(ctx, []model.DeletePredicate{pred}, nil); err != nil || report.Blobs != 1 {
		t.Fatalf("%+v %v", report, err)
	}
	if p, r := fragmentCommands(); p != 0 || r != 2 || counts() != [3]uint64{0, 0, 0} {
		t.Fatalf("after erase: %d plain %d redacted counts %v", p, r, counts())
	}
	if hits := rawHits(t, e, "artifact-byte"); len(hits) != 0 {
		t.Fatalf("artifact bytes remain in %v", hits)
	}
	if err = e.VerifyBlob(ctx, receipt); err == nil {
		t.Fatal("erased artifact still verifies")
	}
	if again, err := e.EraseDeleted(ctx, []model.DeletePredicate{pred}, nil); err != nil || again != (EraseReport{}) {
		t.Fatalf("rerun %+v %v", again, err)
	}
}
