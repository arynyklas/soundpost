// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

// bucketSizes returns the key bytes, value bytes and key count of every top-level bucket.
func bucketSizes(t *testing.T, e *Engine) map[string][3]int64 {
	t.Helper()
	out := map[string][3]int64{}
	if err := e.db.View(func(tx *bolt.Tx) error {
		return tx.ForEach(func(name []byte, b *bolt.Bucket) error {
			var s [3]int64
			var walk func(b *bolt.Bucket)
			walk = func(b *bolt.Bucket) {
				c := b.Cursor()
				for k, v := c.First(); k != nil; k, v = c.Next() {
					if v == nil {
						if sub := b.Bucket(k); sub != nil {
							walk(sub)
						}
						continue
					}
					s[0] += int64(len(k))
					s[1] += int64(len(v))
					s[2]++
				}
			}
			walk(b)
			out[string(name)] = s
			return nil
		})
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

// An append writes what it adds, not what the store already holds: the bytes bolt writes for one
// acknowledged append (dirty pages, 4 KiB each) must stay small and must not grow with the
// history. The live 2,000 records/s run wrote ~500 KB per acked request, ~67 dirty pages of
// apply.db per append, and one bolt writer saturated at ~300 appends/s (L2w20Admission4).
func TestAppendWriteSetIsBoundedAndIndependentOfHistory(t *testing.T) {
	store, service, cred, desc := fixture(t)
	e, err := openTestEngine(t, t.TempDir(), service, store)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.BindAdmissionOwner(e); err != nil {
		t.Fatal(err)
	}
	const total, window = 600, 100
	batches := make([]preparedAppend, total+1) // the last is the lone commit whose buckets the bound counts
	for i := range batches {
		batches[i].scope, batches[i].batch = settleBatch(t, store, service, cred, desc, model.NewID(), 1, fmt.Sprintf("series_%d", i))
	}
	// One serial append is one commit (appendInCommits with a width of 1); a window pays for the merges its
	// commits make due (pageNodesPerAck).
	pageWrites := func(from, to int) float64 { return pageNodesPerAck(t, e, batches[from:to], 1) }
	early := pageWrites(0, window)
	mid := pageWrites(window, total-window)
	sizesBefore := bucketSizes(t, e)
	late := pageWrites(total-window, total)
	sizesAfter := bucketSizes(t, e)
	names := make([]string, 0, len(sizesAfter))
	for n := range sizesAfter {
		names = append(names, n)
	}
	sort.Strings(names)
	var added int64
	for _, n := range names {
		a, b := sizesAfter[n], sizesBefore[n]
		added += (a[0] - b[0]) + (a[1] - b[1])
		t.Logf("bucket %-22s per append: +%6.1f keys, +%8.1f key bytes, +%8.1f value bytes", n, float64(a[2]-b[2])/window, float64(a[0]-b[0])/window, float64(a[1]-b[1])/window)
	}
	t.Logf("bolt page writes per append: first %d: %.1f, middle: %.1f, last %d: %.1f; logical bytes added per append %.0f", window, early, mid, window, late, float64(added)/window)
	// One serial append is one bolt commit and dirties at most one root-to-leaf path in each bucket it
	// writes (D83: the bound is structural). Its pages are therefore the sum of the depths of the trees it
	// writes, plus a constant for the meta and freelist pages, splits and overflow pages (20, as before the
	// block-run layout). The buckets it writes are not guessed: the contents of every bucket are
	// fingerprinted before and after one more lone commit at the history of the test, and every bucket
	// that differs is written, including the ones that only get a row overwritten (cursor, metric, consumed
	// rows) and the new run buckets of the commit's index runs (a run bucket is written once, at depth 1 or 2:
	// its blocks are overflow nodes of that one leaf). A tree gets one level deeper per ~20-100x more rows
	// (batches, receipts: 167 byte keys; replica_commands: 2 KB values, one per leaf), which is the whole of
	// the growth of a serial append with the history; a bucket rewritten whole on each append would grow by
	// orders more. What the writer pays in production is the group commit, where the appends of one commit
	// share the paths: TestAppendWriteSetUnderGroupCommit.
	//
	// Derivation at this test's history (600 appends, block-run layout; numbers as measured by this test, bucket
	// depths from bolt's Bucket.Stats): the lone commit writes 9 buckets: consumed (3 levels),
	// replica_commands (3), replica_data (2), scan_runs (2, the run registry), cursors (1), scan_integrity (1)
	// and the three run buckets it creates, scan_time.r*, scan_postings.r* and scan_rows.r* (1 each: a run of one
	// append is one leaf, and a block over an inline bucket is one overflow node) = 15 levels. The bound is
	// 15 + 20 = 35 pages. The same lone commit writes 21 pages, and the window of 100 serial commits with the
	// merges they make due 26 to 30.5 pages each: the margin is the constant, the same as before the
	// block-run layout. An earlier version of this test counted only the buckets that grew (8 levels, bound
	// 28) and left out the buckets whose rows are overwritten and the run buckets, which the layout
	// writes on every commit; the structural bound counts every bucket the commit writes.
	before := bucketFingerprints(t, e)
	loneBefore := e.db.Stats()
	if commits, applies := appendInCommits(t, e, batches[total:], 1); commits != 1 || applies != 1 {
		t.Fatalf("the lone append made %d commits of %d applies", commits, applies)
	}
	loneAfter := e.db.Stats()
	loneDelta := loneAfter.Sub(&loneBefore)
	lone := loneDelta.TxStats.GetWrite()
	after := bucketFingerprints(t, e)
	depths := bucketDepths(t, e)
	var written []string
	var paths int
	for n, fp := range after {
		if old, ok := before[n]; !ok || old != fp {
			written = append(written, n)
			paths += depths[n]
		}
	}
	sort.Strings(written)
	st := e.db.Stats()
	t.Logf("freelist at history %d: %d free pages, %d pending, %d bytes in the file's freelist", total, st.FreePageN, st.PendingPageN, st.FreelistInuse)
	t.Logf("tree depth per bucket at history %d: %v", total, depths)
	t.Logf("the lone commit at history %d wrote %d pages and writes %d buckets %v with depths summing to %d", total, lone, len(written), written, paths)
	const overhead = 20 // meta and freelist pages, splits, overflow pages, the index runs and the background merge
	if late > float64(paths+overhead) {
		t.Fatalf("an append at history %d writes %.1f pages (%.0f KB) of apply.db, more than one path through each of the %d buckets it writes (%d levels) and %d: some bucket is rewritten whole", total, late, late*4, len(written), paths, overhead)
	}
	if lone > int64(paths+overhead) {
		t.Fatalf("a lone commit at history %d writes %d pages of apply.db, more than one path through each of the %d buckets it writes (%d levels) and %d", total, lone, len(written), paths, overhead)
	}
	if late > early+14 {
		t.Fatalf("pages written per append grew with the history beyond the depth of the trees: %.1f for the first %d appends, %.1f for the last %d", early, window, late, window)
	}
}

// bucketFingerprints returns a digest of the contents of every top-level bucket: keys, values and nested
// buckets, so two digests differ exactly when something in the bucket was written in between.
func bucketFingerprints(t *testing.T, e *Engine) map[string][32]byte {
	t.Helper()
	out := map[string][32]byte{}
	if err := e.db.View(func(tx *bolt.Tx) error {
		return tx.ForEach(func(name []byte, b *bolt.Bucket) error {
			h := sha256.New()
			var walk func(b *bolt.Bucket)
			walk = func(b *bolt.Bucket) {
				c := b.Cursor()
				for k, v := c.First(); k != nil; k, v = c.Next() {
					fmt.Fprintf(h, "%d:%d:", len(k), len(v))
					h.Write(k)
					if v == nil {
						h.Write([]byte{0})
						if sub := b.Bucket(k); sub != nil {
							walk(sub)
						}
						continue
					}
					h.Write(v)
				}
			}
			walk(b)
			var sum [32]byte
			copy(sum[:], h.Sum(nil))
			out[string(name)] = sum
			return nil
		})
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

// bucketDepths returns the B+tree depth of every top-level bucket (nested buckets count with their parent's maximum).
func bucketDepths(t *testing.T, e *Engine) map[string]int {
	t.Helper()
	out := map[string]int{}
	if err := e.db.View(func(tx *bolt.Tx) error {
		return tx.ForEach(func(name []byte, b *bolt.Bucket) error {
			out[string(name)] = b.Stats().Depth
			return nil
		})
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

// Under group commit (many appends in a commit, as in production) the appends of one bolt commit share
// the dirty pages of every bucket, and the index keys of all of them are one run. The old layout wrote
// ~67 pages per append under the live load (L2w20Admission4); the pages written per acknowledged append
// now stay below 20.
//
// What an append may cost is bounded per bucket, not by a flat allowance (D83, amendment): an append
// dirties at most one root-to-leaf path in each bucket it writes, however the other appends of its commit
// fall, so its share of a commit is at most the sum of the depths of those trees. The keys of a commit
// (batch ids, record ids) are random, so once a tree has more leaves than a commit has appends the appends
// stop sharing leaves and the cost per append rises from the shared upper levels to the whole path, one
// level deeper per ~20-100x more rows: that is the growth between a short history and a long one, and it
// is not a regression; a bucket rewritten whole per append, or a path per index row, would be far over it.
func TestAppendWriteSetUnderGroupCommit(t *testing.T) {
	store, service, cred, desc := fixture(t)
	e, err := openTestEngine(t, t.TempDir(), service, store)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.BindAdmissionOwner(e); err != nil {
		t.Fatal(err)
	}
	e.stopIndexMerger() // pageNodesPerAck runs its pass itself
	// A commit is 64 appends, one to each slot (appendInCommits), and a phase is 3 commits: how many appends
	// meet in one commit is the schedule's to decide, and the page nodes per append are a function of it
	// (TestAckPageNodesAreBoundedAndIndependentOfHistory).
	const width, groups, phaseLen = 64, 9, 3 * 64
	const total = width * groups
	bySlot := make([][]string, width)
	for i, full := 0, 0; full < width; i++ {
		if i == 1<<16 {
			t.Fatalf("no %d series for every one of the %d slots among the first %d names", groups, width, i)
		}
		name := fmt.Sprintf("series_%d", i)
		slot := ackPagesSlotOf(t, desc, name)
		if len(bySlot[slot]) < groups {
			bySlot[slot] = append(bySlot[slot], name)
			if len(bySlot[slot]) == groups {
				full++
			}
		}
	}
	batches := make([]preparedAppend, total)
	for i := range batches {
		batches[i].scope, batches[i].batch = settleBatch(t, store, service, cred, desc, model.NewID(), 1, bySlot[i%width][i/width])
	}
	phase := func(from, to int) float64 { return pageNodesPerAck(t, e, batches[from:to], width) }
	first := phase(0, phaseLen)
	phase(phaseLen, 2*phaseLen)
	sizesBefore := bucketSizes(t, e)
	last := phase(2*phaseLen, total)
	sizesAfter := bucketSizes(t, e)
	grown := map[string]bool{}
	for n, a := range sizesAfter {
		if a[2] > sizesBefore[n][2] && !strings.Contains(n, ".r") {
			grown[n] = true
		}
	}
	depths := bucketDepths(t, e)
	var paths int
	for n := range grown {
		paths += depths[n]
	}
	t.Logf("%d in a commit: %.1f bolt pages written per append for the first %d appends, %.1f for the last %d; the %d buckets an append writes have depths summing to %d (%v)", width, first, phaseLen, last, phaseLen, len(grown), paths, depths)
	if last > 20 {
		t.Fatalf("an append under group commit writes %.1f pages of apply.db, want at most 20", last)
	}
	// An append dirties at most one path through each bucket it writes, and the commit's own meta and
	// freelist pages are shared by its 64 appends: the bound is the sum of the depths of the trees.
	if last > float64(paths) {
		t.Fatalf("an append under group commit writes %.1f pages of apply.db at history %d, more than one path through each of the %d buckets it writes (%d levels): some bucket is rewritten whole or per index row", last, total, len(grown), paths)
	}
}
