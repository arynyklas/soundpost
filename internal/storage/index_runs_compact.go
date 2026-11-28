// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

// indexMergeStats counts the merges of the index runs of every database file of the process (what a diagnostic build reports,
// diag_stats_on.go): the chunk transactions (and the time they held the writer, the longest of them), and the merges that ended
// by the level of their output, with their inputs' bytes and their wall time. Four atomics per chunk of about 30 ms.
var indexMergeStats struct {
	chunks, chunkNS, maxChunkNS atomic.Int64
	merges, mergeNS, inBytes    [4]atomic.Int64
}

const (
	indexRunDefaultChunk      = 2 << 20
	indexRunDefaultMaxRunByte = 64 << 20
)

// indexRunFanouts is how many runs of level 0, 1, 2 ... merge into one run of the next level (compactOptions.Fanout zero); the last
// entry holds for every level above. A key is rewritten once per level it climbs (index_runs.go, Write amplification), and a level
// costs the readers its runs: at the single-host gate (D83) a commit makes one tiny run per index (about 13 KB of rows, postings and
// time keys at ~2 acks per commit), so with 8 runs per level a key was rewritten four to five times before its run reached
// MaxRunBytes (9.8 M of the 18.8 M pages apply.db wrote in a 900 s run were these rewrites), and with 64 runs for each of the first
// two levels it is rewritten twice until 4,096 commits (~17 min at the gate), whatever the size of the commits: a run holds at most
// 63 + 63 + 7 runs of an index before it is merged, a few hundred runs for the three, which the merged cursor (a heap) and the one
// bolt seek per run of a Get or a Seek take without notice.
var indexRunFanouts = [...]int{64, 64, 8}

// indexRunFanoutAt is the number of runs of the level that merge into one run of the next level.
func indexRunFanoutAt(level int) int {
	return indexRunFanouts[min(max(level, 0), len(indexRunFanouts)-1)]
}

// compactOptions tunes compactIndexRuns. Zero values mean the defaults.
type compactOptions struct {
	// Fanout is the number of runs of one level that merge into one run of the next level, at every level (at least 2). Zero
	// means indexRunFanouts.
	Fanout int
	// MaxChunkBytes bounds the output of one write transaction (default 2 MiB), about 30 ms of work. It also
	// bounds the size of the blocks the merge writes (they are never larger than a chunk).
	MaxChunkBytes int
	// MaxRunBytes is the size (Bytes of the registry meta: the keys and values) from which a run is never
	// merged again (default 64 MiB). It bounds how often a key is rewritten by merges whatever the history.
	MaxRunBytes int64
	// Cancel, when closed, stops the compaction before its next chunk transaction: compactIndexRuns returns
	// (false, nil) and leaves the unfinished output as a building run for removeBuildingRuns. nil never cancels.
	Cancel <-chan struct{}
	// Payload, when set, receives the blocks of the output of a merge whose inputs add up to MaxRunBytes or more: that output is a
	// final run, which no merge rewrites again, so its blocks are appended to the payload log and the run keeps one reference
	// per block (paylog.go). nil stores every block in the run.
	Payload *payloadLog
	// Update, when set, runs the write transactions of the merge in place of db.Update: the engine passes its own, which a test
	// observes (trackedDB.updateHook) to see every commit of apply.db.
	Update func(fn func(*bolt.Tx) error) error
}

// indexRunsChunkHook, when set (tests), is called after every chunk transaction of a merge that is not its last,
// with no transaction open.
var indexRunsChunkHook func()

// indexRunCompactLocks serializes the compactions of one index of one database file: a second compactor would
// drop the building run of the first as leftovers. Keys are db path + "\x00" + index name.
var indexRunCompactLocks sync.Map

func indexRunCancelled(c <-chan struct{}) bool {
	select {
	case <-c:
		return true
	default:
		return false
	}
}

// planIndexMerge is planIndexMergeAt with the same fanout at every level.
func planIndexMerge(runs []indexRunEntry, fanout int, maxBytes int64) (building bool, inputs []indexRunEntry) {
	return planIndexMergeAt(runs, func(int) int { return fanout }, maxBytes)
}

// planIndexMergeAt picks the next merge: the oldest fanoutAt(level) ready runs of the lowest level that has at least that many of
// them, not counting the runs that reached maxBytes (they are final). building reports whether the registry holds an unfinished
// (building) run.
func planIndexMergeAt(runs []indexRunEntry, fanoutAt func(level int) int, maxBytes int64) (building bool, inputs []indexRunEntry) {
	byLevel := map[int][]indexRunEntry{}
	for _, r := range runs {
		if r.meta.State == indexRunBuilding {
			building = true
			continue
		}
		if r.meta.Bytes >= maxBytes {
			continue
		}
		byLevel[r.meta.Level] = append(byLevel[r.meta.Level], r)
	}
	best := -1
	for level, rs := range byLevel {
		if len(rs) >= fanoutAt(level) && (best < 0 || level < best) {
			best = level
		}
	}
	if best >= 0 {
		inputs = byLevel[best][:fanoutAt(best)] // listIndexRuns is in ascending id order: the oldest first
	}
	return building, inputs
}

// indexMerge is one merge in progress: the output run is built over several write transactions.
type indexMerge struct {
	name    string
	inputs  []indexRunEntry // oldest first
	level   int             // level of the output run
	block   int             // size at which an output block is closed
	id      uint64          // id of the output run, allocated by the first chunk
	started bool
	resume  []byte // the smallest key above the last one written; nil before the first chunk
	count   int64
	size    int64
	bloom   *bloomBuilder // of the keys written so far, for an index that keeps blooms
	log     *payloadLog   // the blocks of the output go to the payload log (the output is a final run)
}

// chunk appends about budget bytes of the merged inputs, as whole blocks, to the output run in tx. The chunk
// that reaches the end of the inputs flips the output to ready and drops the inputs (registry entries and
// buckets) in the same transaction, and reports done.
func (m *indexMerge) chunk(tx *bolt.Tx, budget int) (done bool, err error) {
	if done, err = m.chunkTo(tx, budget); err == nil && m.log != nil {
		err = m.log.sync() // a reference that reaches disk names bytes that reached disk: before the commit of this transaction
	}
	return done, err
}

func (m *indexMerge) chunkTo(tx *bolt.Tx, budget int) (done bool, err error) {
	reg := tx.Bucket([]byte(runsRegistry))
	if reg == nil {
		return false, model.Fail(model.Corrupt)
	}
	var out *bolt.Bucket
	if !m.started {
		m.id = nextIndexRunID(reg, m.name)
		if out, err = tx.CreateBucket(indexRunBucketName(m.name, m.id)); err != nil {
			return false, err
		}
		building := indexRunMeta{State: indexRunBuilding, Level: m.level}
		if err = reg.Put(indexRunRegKey(m.name, m.id), indexRunMetaJSON(building)); err != nil {
			return false, err
		}
		m.started = true
		if indexKeepsBlooms(m.name) {
			var keys int64
			for _, in := range m.inputs {
				keys += in.meta.Count
			}
			m.bloom = newBloomBuilder(keys)
		}
	} else if out = tx.Bucket(indexRunBucketName(m.name, m.id)); out == nil {
		return false, model.Fail(model.Corrupt)
	}

	srcs := make([]indexSource, 0, len(m.inputs))
	for i := len(m.inputs) - 1; i >= 0; i-- { // newest first: it wins a (corrupt) duplicate key
		b := tx.Bucket(indexRunBucketName(m.name, m.inputs[i].id))
		if b == nil {
			return false, model.Fail(model.Corrupt)
		}
		srcs = append(srcs, blockRun{b})
	}
	cur := newIndexCursor(srcs)
	var k, v []byte
	if m.resume == nil {
		k, v = cur.First()
	} else {
		k, v = cur.Seek(m.resume)
	}
	ap := newBlockAppender(out, m.block, m.block+4096)
	ap.log = m.log
	for k != nil {
		closed, err := ap.add(k, v)
		if err != nil {
			return false, err
		}
		if m.bloom != nil {
			m.bloom.add(k)
		}
		m.count++
		m.size += int64(len(k) + len(v))
		if closed && ap.written >= budget && cur.more() {
			if err = cur.Err(); err != nil { // a damaged input block is not copied
				return false, err
			}
			m.resume = append(append(m.resume[:0], k...), 0)
			return false, nil
		}
		k, v = cur.Next()
	}
	if err = cur.Err(); err != nil {
		return false, err
	}
	if err = ap.flush(); err != nil {
		return false, err
	}

	if m.bloom != nil {
		if err = reg.Put(indexRunBloomKey(m.name, m.id), m.bloom.bytes()); err != nil {
			return false, err
		}
	}
	ready := indexRunMeta{State: indexRunReady, Level: m.level, Count: m.count, Bytes: m.size}
	if err = reg.Put(indexRunRegKey(m.name, m.id), indexRunMetaJSON(ready)); err != nil {
		return false, err
	}
	for _, in := range m.inputs {
		if err = dropIndexRun(tx, reg, m.name, in.id); err != nil {
			return false, err
		}
	}
	return true, nil
}

// compactIndexRuns does one merge of the index name, or nothing, and reports whether it merged. Each run has a
// level (0 for writeIndexRun); when at least Fanout ready runs share a level, the oldest Fanout of the lowest
// such level merge into one run of the next level. A run of MaxRunBytes or more is final: it is not merged
// again, which bounds the write amplification of a key (index_runs.go). Keys never repeat across runs, so the
// order of the inputs only decides the winner of a corrupt duplicate.
//
// It runs in its own transactions on db, never inside a caller's: the output is built as a "building" run
// (invisible to readers) over write transactions of about MaxChunkBytes each, and the last one flips it to
// ready and removes the inputs atomically. Readers in flight keep their snapshot. Deletes through an indexSet
// that run in between (the engine's) reach the building run too, so a key deleted after it was copied stays
// deleted. An unfinished building run (crash, error, Cancel) is dropped by the next call or by removeBuildingRuns.
func compactIndexRuns(db *bolt.DB, name string, opt compactOptions) (did bool, err error) {
	fanoutAt := indexRunFanoutAt
	switch {
	case opt.Fanout == 0:
	case opt.Fanout < 2:
		return false, model.Fail(model.Invalid)
	default:
		fanoutAt = func(int) int { return opt.Fanout }
	}
	if opt.MaxChunkBytes <= 0 {
		opt.MaxChunkBytes = indexRunDefaultChunk
	}
	switch {
	case opt.MaxRunBytes == 0:
		opt.MaxRunBytes = indexRunDefaultMaxRunByte
	case opt.MaxRunBytes < 0:
		return false, model.Fail(model.Invalid)
	}
	update := db.Update
	if opt.Update != nil {
		update = opt.Update
	}
	mu, _ := indexRunCompactLocks.LoadOrStore(db.Path()+"\x00"+name, &sync.Mutex{})
	mu.(*sync.Mutex).Lock()
	defer mu.(*sync.Mutex).Unlock()
	if indexRunCancelled(opt.Cancel) {
		return false, nil
	}

	var building bool
	var inputs []indexRunEntry
	err = db.View(func(tx *bolt.Tx) error {
		reg := tx.Bucket([]byte(runsRegistry))
		if reg == nil {
			return nil
		}
		runs, err := listIndexRuns(reg, name)
		if err != nil {
			return err
		}
		building, inputs = planIndexMergeAt(runs, fanoutAt, opt.MaxRunBytes)
		return nil
	})
	if err != nil {
		return false, err
	}
	if building {
		err = update(func(tx *bolt.Tx) error {
			_, err := removeBuildingRuns(tx, name)
			return err
		})
		if err != nil {
			return false, err
		}
	}
	if len(inputs) == 0 {
		return false, nil
	}

	m := &indexMerge{name: name, inputs: inputs, level: inputs[0].meta.Level + 1, block: min(runBlockBytes(name), opt.MaxChunkBytes)}
	var sum int64
	for _, in := range inputs {
		sum += in.meta.Bytes
	}
	if opt.Payload != nil && sum >= opt.MaxRunBytes {
		m.log = opt.Payload
	}
	began := time.Now()
	for {
		if indexRunCancelled(opt.Cancel) {
			return false, nil
		}
		var done bool
		chunkAt := time.Now()
		err = update(func(tx *bolt.Tx) error {
			var err error
			done, err = m.chunk(tx, opt.MaxChunkBytes)
			return err
		})
		took := time.Since(chunkAt).Nanoseconds()
		indexMergeStats.chunks.Add(1)
		indexMergeStats.chunkNS.Add(took)
		for old := indexMergeStats.maxChunkNS.Load(); took > old && !indexMergeStats.maxChunkNS.CompareAndSwap(old, took); old = indexMergeStats.maxChunkNS.Load() {
		}
		if err != nil {
			return false, err
		}
		if done {
			lv := min(m.level, len(indexMergeStats.merges)-1)
			indexMergeStats.merges[lv].Add(1)
			indexMergeStats.mergeNS[lv].Add(time.Since(began).Nanoseconds())
			indexMergeStats.inBytes[lv].Add(sum)
			return true, nil
		}
		if indexRunsChunkHook != nil {
			indexRunsChunkHook()
		}
	}
}
