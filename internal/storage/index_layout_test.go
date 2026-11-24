// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

// logicalBucket is what the tests use of a bucket that holds entries of a logical bucket: a plain bolt bucket,
// or a run bucket (blocks, not one bolt entry per key) seen as one.
type logicalBucket interface {
	Get(key []byte) []byte
	Put(key, value []byte) error
	Delete(key []byte) error
	ForEach(fn func(k, v []byte) error) error
}

// runBucket is a run bucket in the block format seen as a bucket. The key a ForEach callback gets is valid
// until the callback returns.
type runBucket struct{ b *bolt.Bucket }

func (r runBucket) Get(key []byte) []byte { return blockRun{r.b}.Get(key) }

func (r runBucket) Delete(key []byte) error {
	_, err := blockRun{r.b}.Delete(key)
	return err
}

func (r runBucket) ForEach(fn func(k, v []byte) error) error {
	c := blockRun{r.b}.Cursor().(*blockCursor)
	for k, v := c.First(); k != nil; k, v = c.Next() {
		if err := fn(k, v); err != nil {
			return err
		}
	}
	return c.Err()
}

// Put replaces the value of a key the run holds (a test damages entries, it does not add them).
func (r runBucket) Put(key, value []byte) error {
	rd := new(blockReader)
	boltKey, _, found, err := blockRun{r.b}.locate(rd, key)
	if err != nil {
		return err
	}
	if !found || !bytes.Equal(rd.key, key) {
		return errors.New("runBucket.Put: the run does not hold the key")
	}
	blk := rd.blk
	var bb blockBuilder
	bb.start(len(blk.raw) + len(value))
	for rd.reset(blk, 0); rd.next(); {
		v := rd.val
		if bytes.Equal(rd.key, key) {
			v = value
		}
		bb.add(rd.key, v)
	}
	return r.b.Put(bytes.Clone(boltKey), bb.finish()) // the last key, which the block is filed under, is the same
}

// logicalBuckets returns the buckets that hold the entries of the logical bucket name: the bucket
// itself (when it exists) and, in the runs layout, the run buckets of a query index (scan_time, scan_postings)
// or the run buckets of the row store that hold the rows of the table (batches, receipts, metrics, scan_pages,
// scan_commits).
func logicalBuckets(tx *bolt.Tx, name string) []logicalBucket {
	var out []logicalBucket
	if b := tx.Bucket([]byte(name)); b != nil {
		out = append(out, b)
	}
	if tx.Bucket([]byte(runsRegistry)) == nil {
		return out
	}
	if name == "scan_time" || name == "scan_postings" {
		_ = tx.ForEach(func(n []byte, b *bolt.Bucket) error {
			if strings.HasPrefix(string(n), name+".r") {
				out = append(out, runBucket{b})
			}
			return nil
		})
		return out
	}
	for _, tbl := range rowTables {
		if tbl.bucket != name {
			continue
		}
		// A run that a merge is still building holds copies of rows of the runs it merges: not a bucket of the table.
		entries, err := listIndexRuns(tx.Bucket([]byte(runsRegistry)), rowsIndex)
		if err != nil {
			continue
		}
		for i := len(entries) - 1; i >= 0; i-- {
			if b := tx.Bucket(indexRunBucketName(rowsIndex, entries[i].id)); b != nil && entries[i].meta.State == indexRunReady {
				out = append(out, tagRunBucket{b, tbl.tag})
			}
		}
	}
	return out
}

// tagRunBucket is the range of one table of a run of the row store seen as a bucket: the keys are the keys of
// the table.
type tagRunBucket struct {
	b   *bolt.Bucket
	tag byte
}

func (r tagRunBucket) tagged(key []byte) []byte { return append([]byte{r.tag}, key...) }

func (r tagRunBucket) Get(key []byte) []byte { return runBucket{r.b}.Get(r.tagged(key)) }

func (r tagRunBucket) Delete(key []byte) error { return runBucket{r.b}.Delete(r.tagged(key)) }

func (r tagRunBucket) Put(key, value []byte) error { return runBucket{r.b}.Put(r.tagged(key), value) }

func (r tagRunBucket) ForEach(fn func(k, v []byte) error) error {
	return runBucket{r.b}.ForEach(func(k, v []byte) error {
		if len(k) == 0 || k[0] != r.tag {
			return nil
		}
		return fn(k[1:], v)
	})
}

// logicalGet is the value of key in the logical bucket name (nil when no bucket of it holds the key).
func logicalGet(tx *bolt.Tx, name string, key []byte) []byte {
	if b := bucketHolding(tx, name, key); b != nil {
		return storedTx(tx, b.Get(key)) // a payload reference stands for its bytes
	}
	return nil
}

// logicalCount is the number of entries of the logical bucket name.
func logicalCount(t *testing.T, tx *bolt.Tx, name string) int {
	t.Helper()
	n := 0
	if err := forEachLogical(tx, name, func(_, _ []byte) error { n++; return nil }); err != nil {
		t.Fatal(err)
	}
	return n
}

// deleteLogical removes key from whichever bucket of the logical bucket name holds it.
func deleteLogical(tx *bolt.Tx, name string, key []byte) error {
	b := bucketHolding(tx, name, key)
	if b == nil {
		return errors.New("no bucket of " + name + " holds the key")
	}
	return b.Delete(key)
}

// forEachLogical visits every entry of the logical bucket name.
func forEachLogical(tx *bolt.Tx, name string, fn func(k, v []byte) error) error {
	for _, b := range logicalBuckets(tx, name) {
		if err := b.ForEach(func(k, v []byte) error { return fn(k, storedTx(tx, v)) }); err != nil {
			return err
		}
	}
	return nil
}

// bucketHolding returns the bucket of the logical bucket name that holds key.
func bucketHolding(tx *bolt.Tx, name string, key []byte) logicalBucket {
	for _, b := range logicalBuckets(tx, name) {
		if b.Get(key) != nil {
			return b
		}
	}
	return nil
}

var errStopEach = errors.New("stop")

// firstLogical returns the bucket and the key of the first entry of the logical bucket name.
func firstLogical(tx *bolt.Tx, name string) (logicalBucket, []byte) {
	for _, b := range logicalBuckets(tx, name) {
		var first []byte
		_ = b.ForEach(func(k, _ []byte) error { first = bytes.Clone(k); return errStopEach })
		if first != nil {
			return b, first
		}
	}
	return nil, nil
}

// emptyLogical deletes every entry of the logical bucket name.
func emptyLogical(tx *bolt.Tx, name string) error {
	for _, b := range logicalBuckets(tx, name) {
		var keys [][]byte
		_ = b.ForEach(func(k, _ []byte) error { keys = append(keys, bytes.Clone(k)); return nil })
		for _, k := range keys {
			if err := b.Delete(k); err != nil {
				return err
			}
		}
	}
	return nil
}

// dropRunsLayout turns the database of tx into the image a release that predates the runs layout
// wrote: no registry and no run buckets (the caller removes the marker and the index buckets).
func dropRunsLayout(t *testing.T, tx *bolt.Tx) {
	t.Helper()
	var names [][]byte
	var rowRuns []*bolt.Bucket
	_ = tx.ForEach(func(n []byte, b *bolt.Bucket) error {
		s := string(n)
		if s == runsRegistry || strings.HasPrefix(s, "scan_time.r") || strings.HasPrefix(s, "scan_postings.r") {
			names = append(names, bytes.Clone(n))
		}
		if strings.HasPrefix(s, rowsIndex+".r") {
			names = append(names, bytes.Clone(n))
			rowRuns = append(rowRuns, b)
		}
		return nil
	})
	// Such a release kept the batches, the receipts and the metric samples in their buckets: the rows of the
	// row store go back where they were. The pages and the commit records are derived state that the
	// callers drop with the index buckets.
	for _, b := range rowRuns {
		for _, tbl := range []rowTable{tblBatches, tblReceipts, tblMetrics} {
			err := tagRunBucket{b, tbl.tag}.ForEach(func(k, v []byte) error { return tx.Bucket([]byte(tbl.bucket)).Put(bytes.Clone(k), bytes.Clone(v)) })
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, n := range names {
		if err := tx.DeleteBucket(n); err != nil {
			t.Fatal(err)
		}
	}
}

func scanLayoutMarker(t *testing.T, e *Engine) (marker byte, registry bool) {
	t.Helper()
	if err := e.db.View(func(tx *bolt.Tx) error {
		m := tx.Bucket([]byte("meta")).Get([]byte("scan_index_version"))
		if len(m) != 1 {
			t.Fatalf("scan_index_version %v", m)
		}
		marker, registry = m[0], tx.Bucket([]byte(runsRegistry)) != nil
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return
}

// appendLayoutBatches appends n batches of distinct series and returns the receipts.
func appendLayoutBatches(t *testing.T, e *Engine, fx layoutFixture, n int) []model.Cursor {
	t.Helper()
	var marks []model.Cursor
	for i := range n {
		scope, b := settleBatch(t, fx.store, fx.service, fx.cred, fx.desc, model.NewID(), 1, fmt.Sprintf("layout_%d_%s", i, model.NewID()))
		r, err := e.Append(context.Background(), scope, b)
		if err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
		marks = append(marks, r.Cursor)
	}
	return marks
}

type layoutFixture struct {
	store   *control.Store
	service *auth.Service
	cred    auth.SourceCredential
	desc    model.SourceDescriptor
}

func scanAllRows(t *testing.T, e *Engine, fx layoutFixture, marks []model.Cursor) int {
	t.Helper()
	read := scanScope(t, fx.store, fx.service, fx.desc)
	return len(collectPages(t, e, read, ScanRequest{Projects: []model.ID{fx.desc.Project}, Signal: model.Metric, End: 2, Fence: ReadFence{Min: marks}}))
}

func layoutEntries(t *testing.T, e *Engine, name string) (base, runs int) {
	t.Helper()
	if err := e.db.View(func(tx *bolt.Tx) error {
		for i, b := range logicalBuckets(tx, name) {
			n := 0
			_ = b.ForEach(func(_, _ []byte) error { n++; return nil })
			if i == 0 {
				base += n
			} else {
				runs += n
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return
}

// A database of a contracted installation (one this release bootstrapped) is in the runs layout as soon
// as replication is enabled: the index keys of an append are a run, and a query, the reopen and the
// integrity validation see the same rows as in the single-bucket layout.
func TestFreshDatabaseOfAContractedInstallationIsInTheRunsLayout(t *testing.T) {
	withoutPayloadToggle(t)
	store, service, cred, desc := fixture(t)
	fx := layoutFixture{store, service, cred, desc}
	dir := t.TempDir()
	e, err := openTestEngine(t, dir, service, store)
	if err != nil {
		t.Fatal(err)
	}
	if marker, registry := scanLayoutMarker(t, e); marker != scanIndexRows || !registry || !e.runsLayout.Load() {
		t.Fatalf("a fresh database has scan_index_version %d, registry %v, runsLayout %v", marker, registry, e.runsLayout.Load())
	}
	marks := appendLayoutBatches(t, e, fx, 12)
	if got := scanAllRows(t, e, fx, marks); got != 12 {
		t.Fatalf("a query returns %d rows, want 12", got)
	}
	for _, name := range []string{"scan_time", "scan_postings", "batches", "receipts", "metrics", "scan_pages", "scan_commits"} {
		if base, runs := layoutEntries(t, e, name); base != 0 || runs == 0 {
			t.Fatalf("%s: %d entries in the base bucket and %d in runs, want everything in runs", name, base, runs)
		}
	}
	if err = e.Close(); err != nil {
		t.Fatal(err)
	}
	e, err = openTestEngine(t, dir, service, store)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if !e.runsLayout.Load() {
		t.Fatal("a database in the runs layout opened as the single-bucket layout")
	}
	if got := scanAllRows(t, e, fx, marks); got != 12 {
		t.Fatalf("after the reopen a query returns %d rows, want 12", got)
	}
}

// A database the previous release wrote (version 1, no registry) stays in its layout whatever this
// release appends to it: the previous release can read it back.
func TestSingleBucketDatabaseStaysInItsLayout(t *testing.T) {
	withoutPayloadToggle(t)
	expandedInstallation(t)
	store, service, cred, desc := fixture(t)
	fx := layoutFixture{store, service, cred, desc}
	dir := t.TempDir()
	e, err := openTestEngine(t, dir, service, store)
	if err != nil {
		t.Fatal(err)
	}
	if err = e.Close(); err != nil {
		t.Fatal(err)
	}
	// The image of a previous release: an empty index, no registry, version 1.
	editDB(t, dir, func(tx *bolt.Tx) error {
		dropRunsLayout(t, tx)
		return tx.Bucket([]byte("meta")).Put([]byte("scan_index_version"), []byte{scanIndexClassic})
	})
	e, err = openTestEngine(t, dir, service, store)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if marker, registry := scanLayoutMarker(t, e); marker != scanIndexClassic || registry || e.runsLayout.Load() {
		t.Fatalf("a version 1 database became version %d, registry %v, runsLayout %v", marker, registry, e.runsLayout.Load())
	}
	marks := appendLayoutBatches(t, e, fx, 8)
	if got := scanAllRows(t, e, fx, marks); got != 8 {
		t.Fatalf("a query returns %d rows, want 8", got)
	}
	if base, runs := layoutEntries(t, e, "scan_postings"); base == 0 || runs != 0 {
		t.Fatalf("scan_postings: %d entries in the base bucket and %d in runs, want a single bucket", base, runs)
	}
}

// The merger folds runs without changing what a query, the digests or the reopen see.
func TestRunsMergeWithoutChangingTheIndex(t *testing.T) {
	store, service, cred, desc := fixture(t)
	fx := layoutFixture{store, service, cred, desc}
	dir := t.TempDir()
	e, err := openTestEngine(t, dir, service, store)
	if err != nil {
		t.Fatal(err)
	}
	marks := appendLayoutBatches(t, e, fx, 40)
	var before int
	for _, name := range []string{"scan_time", "scan_postings"} {
		_, n := layoutEntries(t, e, name)
		before += n
		for {
			did, err := compactIndexRuns(e.db.DB, name, compactOptions{Fanout: 4})
			if err != nil {
				t.Fatal(err)
			}
			if !did {
				break
			}
		}
	}
	var after int
	for _, name := range []string{"scan_time", "scan_postings"} {
		_, n := layoutEntries(t, e, name)
		after += n
	}
	if before != after {
		t.Fatalf("the merge changed the entry count: %d before, %d after", before, after)
	}
	if err = e.db.View(validateIndexIntegrity); err != nil {
		t.Fatalf("integrity after the merge: %v", err)
	}
	if got := scanAllRows(t, e, fx, marks); got != 40 {
		t.Fatalf("after the merge a query returns %d rows, want 40", got)
	}
	if err = e.Close(); err != nil {
		t.Fatal(err)
	}
	e, err = openTestEngine(t, dir, service, store)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if got := scanAllRows(t, e, fx, marks); got != 40 {
		t.Fatalf("after the reopen a query returns %d rows, want 40", got)
	}
}

// expandedInstallation plays an installation the previous release bootstrapped and that nobody has
// contracted: the engine must keep the layout the previous release reads.
func expandedInstallation(t *testing.T) {
	t.Helper()
	old := layoutContracted
	layoutContracted = func(context.Context, ReplicatedAuthority) (bool, error) { return false, nil }
	t.Cleanup(func() { layoutContracted = old })
}

// The runs layout follows the installation: a file of an expanded installation stays single-bucket
// across appends and a restart (the previous release can read it), contraction moves it to the runs
// layout without rewriting the rows it holds, and a restart after that opens the runs layout.
func TestRunsLayoutIsAdoptedWhenTheInstallationIsContracted(t *testing.T) {
	withoutPayloadToggle(t)
	store, service, cred, desc := fixture(t)
	fx := layoutFixture{store, service, cred, desc}
	var contracted atomic.Bool
	old := layoutContracted
	layoutContracted = func(context.Context, ReplicatedAuthority) (bool, error) { return contracted.Load(), nil }
	t.Cleanup(func() { layoutContracted = old })
	dir := t.TempDir()
	e, err := openTestEngine(t, dir, service, store)
	if err != nil {
		t.Fatal(err)
	}
	marks := appendLayoutBatches(t, e, fx, 6)
	time.Sleep(1500 * time.Millisecond) // the watcher asks about every second: still expanded
	if marker, registry := scanLayoutMarker(t, e); marker != scanIndexClassic || registry || e.runsLayout.Load() {
		t.Fatalf("an expanded installation moved to version %d, registry %v", marker, registry)
	}
	if err = e.Close(); err != nil {
		t.Fatal(err)
	}
	e, err = openTestEngine(t, dir, service, store)
	if err != nil {
		t.Fatal(err)
	}
	if marker, registry := scanLayoutMarker(t, e); marker != scanIndexClassic || registry {
		t.Fatalf("a restart moved an expanded installation to version %d, registry %v", marker, registry)
	}
	contracted.Store(true)
	deadline := time.Now().Add(10 * time.Second)
	for !e.runsLayout.Load() {
		if time.Now().After(deadline) {
			t.Fatal("the installation was contracted and the engine did not adopt the runs layout within 10 s")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if marker, registry := scanLayoutMarker(t, e); marker != scanIndexRows || !registry {
		t.Fatalf("after contraction: version %d, registry %v", marker, registry)
	}
	more := appendLayoutBatches(t, e, fx, 6)
	if got := scanAllRows(t, e, fx, append(append([]model.Cursor{}, marks...), more...)); got != 12 {
		t.Fatalf("after adoption a query returns %d rows, want the 6 of the single-bucket layout and the 6 of runs", got)
	}
	if base, runs := layoutEntries(t, e, "scan_postings"); base == 0 || runs == 0 {
		t.Fatalf("scan_postings: %d entries in the base bucket and %d in runs, want both", base, runs)
	}
	if err = e.Close(); err != nil {
		t.Fatal(err)
	}
	e, err = openTestEngine(t, dir, service, store)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if !e.runsLayout.Load() {
		t.Fatal("a contracted installation reopened in the single-bucket layout")
	}
	if got := scanAllRows(t, e, fx, append(append([]model.Cursor{}, marks...), more...)); got != 12 {
		t.Fatalf("after the restart a query returns %d rows, want 12", got)
	}
}
