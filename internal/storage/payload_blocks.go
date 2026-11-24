// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	bolt "go.etcd.io/bbolt"
)

// Stage 2 of the owned payload log (decision D89): what an append leaves in bolt after the background merges is bounded and
// independent of the history.
//
// Stage 1 (paylog.go) moved the three payloads of an append (the command, the stored records, the hot page) into the log. What
// stayed was the per-record index bodies of the query indexes and the row store: about 1.4 KB per record of scan_postings,
// scan_time and scan_rows, in runs that the background merges rewrite level by level. A run that reaches finalRunBytes is never
// merged again (index_runs_compact.go), so its blocks are written once more, into the log: the run keeps its bolt keys (the last
// key of every block, which the cursors and the seeks need) and one 21-byte reference per block, and a block is read from the log
// by its reference (blockRun.blockOf). The runs below finalRunBytes (the newest few minutes of the history, at most
// fanout runs per level) stay in bolt, where the merges rewrite them cheaply.
//
// What bolt then holds per acknowledged batch, whatever the history behind it, is the pointer of its command (replica_commands: the
// key and one reference), the key of its logical index (replica_data) and the registry and block pointers of its runs, which
// are one 21-byte reference and one key per 32 KiB (rows) or 128 KiB (query indexes) of its bytes. TestStoredBytesPerBatchAfterMerges states the
// bound and its derivation.
//
// An installation that already holds inline values (a file the stage-1 build or the rows layout wrote) migrates them in the
// background once it has adopted the layout (migrateInlinePayload): the commands, the rows of the legacy buckets and the blocks of the final
// runs move to the log, resumably, a chunk of about payloadChunkBytes a transaction, and both forms are read until the last
// one is gone.

// finalRunBytes is the size from which a run is final (compactOptions.MaxRunBytes); a variable of the tests.
var finalRunBytes int64 = indexRunDefaultMaxRunByte

// payloadChunkBytes bounds the bytes one migration transaction moves.
const payloadChunkBytes = 2 << 20

// moved is one value a chunk moved out of bolt: the value it read and what the bucket holds after it.
type moved struct {
	key, old, val []byte
}

// moveChunk moves the values of the bucket name, from the key resume (nil: the first), to the payload log: convert returns the
// value that stands for old after its bytes are appended to the log (nil to leave the value in place). The log is synced before the
// transaction that stores the new values starts, and a value that changed in between is left as it is (its record is owed a
// zeroing). next is the key to continue from, done is true at the end of the bucket.
func (e *Engine) moveChunk(name []byte, resume []byte, convert func(old []byte) ([]byte, error)) (next []byte, did int, done bool, err error) {
	// A chunk reads a value, logs its bytes and replaces the value: an erasure that rewrote the value in between would leave a record
	// holding the erased bytes after its scrub has run. Erasure holds cutMu exclusively, so a chunk is never concurrent with one.
	e.cutMu.RLock()
	defer e.cutMu.RUnlock()
	var items []moved
	var size int
	err = e.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(name)
		if b == nil {
			done = true
			return nil
		}
		c := b.Cursor()
		var k, v []byte
		if resume == nil {
			k, v = c.First()
		} else {
			k, v = c.Seek(resume)
		}
		for ; k != nil; k, v = c.Next() {
			if isPayloadRef(v) {
				continue
			}
			if size >= payloadChunkBytes {
				next = bytes.Clone(k)
				return nil
			}
			items = append(items, moved{key: bytes.Clone(k), old: bytes.Clone(v)})
			size += len(v)
		}
		done = true
		return nil
	})
	if err != nil {
		return nil, 0, false, unavailableDB(err)
	}
	for i := range items {
		if items[i].val, err = convert(items[i].old); err != nil {
			return nil, 0, false, err
		}
	}
	if err = e.payload.sync(); err != nil {
		return nil, 0, false, err
	}
	if err = e.trip("payload_migrate"); err != nil { // the records are durable, no value names them yet
		return nil, 0, false, err
	}
	err = e.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(name)
		for i := range items {
			it := &items[i]
			if it.val == nil {
				continue
			}
			if b != nil && bytes.Equal(b.Get(it.key), it.old) {
				if err := b.Put(it.key, it.val); err != nil {
					return err
				}
				did++
				continue
			}
			if err := owePayloadScrub(tx, refOf(it.val)); err != nil { // the value changed since it was read: the record is dead
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, 0, false, unavailableDB(err)
	}
	return next, did, done, nil
}

// refOf is the payload reference a moved value holds: the value itself, or the reference inside a page row.
func refOf(v []byte) []byte {
	if isPayloadRef(v) {
		return v
	}
	if p, err := parsePageRef(v); err == nil {
		return p.Log
	}
	return nil
}

// externalizeRuns moves the blocks of the final runs of the three indexes to the log, one chunk of one run at a time, and reports
// whether stop closed first. A run whose blocks all moved is remembered for the life of the engine.
func (e *Engine) externalizeRuns(stop <-chan struct{}) (cancelled bool, first error) {
	for _, name := range []string{"scan_time", "scan_postings", rowsIndex} {
		var final []indexRunEntry
		if err := e.db.View(func(tx *bolt.Tx) error {
			reg := tx.Bucket([]byte(runsRegistry))
			if reg == nil {
				return nil
			}
			runs, err := listIndexRuns(reg, name)
			if err != nil {
				return err
			}
			for _, r := range runs {
				if r.meta.State == indexRunReady && r.meta.Bytes >= finalRunBytes {
					if _, done := e.externalized.Load(string(indexRunBucketName(name, r.id))); !done {
						final = append(final, r)
					}
				}
			}
			return nil
		}); err != nil {
			if first == nil {
				first = unavailableDB(err)
			}
			continue
		}
		for _, r := range final {
			bucket := indexRunBucketName(name, r.id)
			var resume []byte
			for {
				select {
				case <-stop:
					return true, first
				default:
				}
				next, _, done, err := e.moveChunk(bucket, resume, e.logBlock)
				if err != nil {
					if first == nil {
						first = err
					}
					break
				}
				if done {
					e.externalized.Store(string(bucket), struct{}{})
					break
				}
				resume = next
			}
		}
	}
	return false, first
}

// logBlock appends a block to the log and returns its reference.
func (e *Engine) logBlock(block []byte) ([]byte, error) { return e.payload.append(block) }

// inlineSource is a bucket whose inline values migrate to the log: its name, and how a value becomes a reference.
type inlineSource struct {
	bucket  string
	convert func(e *Engine, old []byte) ([]byte, error)
}

// convertWhole moves a value of payloadMinBytes or more as it is. A redacted command stays in its row: it is the authority every
// reconciliation reads back by its JSON prefix (redactedCommands), and one moved to the log would be a reference no reconciliation finds.
func convertWhole(e *Engine, old []byte) ([]byte, error) {
	if len(old) < payloadMinBytes || isRedactedCommand(old) {
		return nil, nil
	}
	return e.payload.append(old)
}

// convertHotPage moves the bytes of a hot page out of its row (the row keeps the reference in Log).
func convertHotPage(e *Engine, old []byte) ([]byte, error) {
	p, err := parsePageRef(old)
	if err != nil || len(p.Hot) == 0 || p.Segment != "" {
		return nil, nil
	}
	ref, err := e.payload.append(p.Hot)
	if err != nil {
		return nil, err
	}
	p.Hot, p.Log = nil, ref
	return pageRefBytes(p)
}

// inlineSources are the buckets that hold payload inline in a file the stage-1 build or the rows layout wrote: the stored commands,
// and the legacy buckets of the row store (a row of the runs is in a block, which moves with its run).
var inlineSources = []inlineSource{
	{"replica_commands", convertWhole},
	{tblBatches.bucket, convertWhole},
	{tblPages.bucket, convertHotPage},
}

const (
	payloadMigrateBucket = "payload_migrate"
	migrateDonePrefix    = "done:"
	migrateResumePrefix  = "resume:"
)

// migrateInlinePayload moves one chunk of every inline source to the log, and reports whether stop closed first. A source that has
// no inline value left is marked done in the file and never read again. The progress is in the file (payload_migrate): a restart
// continues where the pass stopped.
func (e *Engine) migrateInlinePayload(stop <-chan struct{}) (cancelled bool, first error) {
	for _, src := range inlineSources {
		select {
		case <-stop:
			return true, first
		default:
		}
		var done bool
		var resume []byte
		if err := e.db.View(func(tx *bolt.Tx) error {
			if b := tx.Bucket([]byte(payloadMigrateBucket)); b != nil {
				done = b.Get([]byte(migrateDonePrefix+src.bucket)) != nil
				resume = bytes.Clone(b.Get([]byte(migrateResumePrefix + src.bucket)))
			}
			return nil
		}); err != nil {
			if first == nil {
				first = unavailableDB(err)
			}
			continue
		}
		if done {
			continue
		}
		next, _, end, err := e.moveChunk([]byte(src.bucket), resume, func(old []byte) ([]byte, error) { return src.convert(e, old) })
		if err != nil {
			if first == nil {
				first = err
			}
			continue
		}
		if err = e.db.Update(func(tx *bolt.Tx) error {
			b, err := tx.CreateBucketIfNotExists([]byte(payloadMigrateBucket))
			if err != nil {
				return err
			}
			if end {
				if err = b.Delete([]byte(migrateResumePrefix + src.bucket)); err != nil {
					return err
				}
				return b.Put([]byte(migrateDonePrefix+src.bucket), []byte{1})
			}
			return b.Put([]byte(migrateResumePrefix+src.bucket), next)
		}); err != nil && first == nil {
			first = unavailableDB(err)
		}
	}
	return false, first
}

// payloadMigrationDone reports whether every inline source has been moved (tests, diagnostics).
func (e *Engine) payloadMigrationDone() bool {
	done := true
	_ = e.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(payloadMigrateBucket))
		for _, src := range inlineSources {
			if b == nil || b.Get([]byte(migrateDonePrefix+src.bucket)) == nil {
				done = false
			}
		}
		return nil
	})
	return done
}
