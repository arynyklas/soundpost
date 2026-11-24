// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
	"hash"
	"hash/crc32"
)

// Entry CRCs detect damaged keys/values. This independently persisted counted
// SHA-256 multiset root also detects missing entries, not just malformed entries.
type IndexDigest struct {
	Count    model.Uint64 `json:"count"`
	Checksum model.Hash   `json:"checksum"`
}
type indexWriter struct {
	bucket, meta *bolt.Bucket
	name         string
	state        IndexDigest
	hasher       hash.Hash
	scratch      model.Hash
	// In the runs layout (a scan_runs bucket exists) puts are collected and written as one sorted
	// run: by the accumulator of the bolt commit the writer runs in, or by finish when there is none.
	tx      *bolt.Tx
	runs    bool
	set     *indexSet
	acc     *indexAccumulator
	pending []indexPair
	seen    map[string]struct{}
}

func digestBytes(state IndexDigest) []byte {
	b := make([]byte, 52)
	copy(b, "SPI1")
	binary.BigEndian.PutUint16(b[4:6], 1)
	binary.BigEndian.PutUint64(b[8:16], uint64(state.Count))
	copy(b[16:48], state.Checksum[:])
	binary.BigEndian.PutUint32(b[48:], crc32.Checksum(b[:48], pageCRC))
	return b
}
func parseDigest(b []byte) (IndexDigest, error) {
	var state IndexDigest
	if len(b) != 52 || !bytes.Equal(b[:4], []byte("SPI1")) || binary.BigEndian.Uint16(b[4:6]) != 1 || b[6] != 0 || b[7] != 0 || crc32.Checksum(b[:48], pageCRC) != binary.BigEndian.Uint32(b[48:]) {
		return state, model.Fail(model.Corrupt)
	}
	state.Count = model.Uint64(binary.BigEndian.Uint64(b[8:16]))
	copy(state.Checksum[:], b[16:48])
	return state, nil
}
func newIndexWriter(tx *bolt.Tx, name string) (*indexWriter, error) {
	bucket, meta := tx.Bucket([]byte(name)), tx.Bucket([]byte("scan_integrity"))
	if bucket == nil || meta == nil {
		return nil, model.Fail(model.Corrupt)
	}
	state, err := parseDigest(meta.Get([]byte(name)))
	if err != nil {
		return nil, err
	}
	w := &indexWriter{bucket: bucket, meta: meta, name: name, state: state, hasher: sha256.New(), tx: tx}
	if tx.Bucket([]byte(runsRegistry)) != nil {
		w.runs = true
		w.acc = accumulatorOf(tx)
		w.seen = map[string]struct{}{}
	}
	return w, nil
}
func entryDigest(h hash.Hash, key, value []byte, scratch *model.Hash) model.Hash {
	h.Reset()
	_, _ = h.Write(key)
	_, _ = h.Write(value)
	_ = h.Sum(scratch[:0])
	return *scratch
}
func xorDigest(dst *model.Hash, value model.Hash) {
	for i := range dst {
		dst[i] ^= value[i]
	}
}

// putBuilt puts the entries of one append that buildBatchIndex derived (distinct keys, their digest
// computed outside the transaction). In the runs layout they join the run of the commit with the digest
// added at once; in the single-bucket layout each entry goes through put.
func (w *indexWriter) putBuilt(pairs []indexPair, d digestDelta) error {
	if !w.runs {
		for _, p := range pairs {
			if err := w.put(p.Key, p.Value); err != nil {
				return err
			}
		}
		return nil
	}
	if uint64(w.state.Count) > ^uint64(0)-d.count {
		return model.Fail(model.Unavailable)
	}
	w.state.Count += model.Uint64(d.count)
	xorDigest(&w.state.Checksum, d.xor)
	w.pending = append(w.pending, pairs...)
	return nil
}
func (w *indexWriter) put(key, value []byte) error {
	if w.runs {
		// The keys of an append carry its cursor, so a key is new; one record can name the same
		// term twice, which is one entry (both puts carry the same value).
		if _, dup := w.seen[string(key)]; dup {
			return nil
		}
		w.seen[string(key)] = struct{}{}
		if uint64(w.state.Count) == ^uint64(0) {
			return model.Fail(model.Unavailable)
		}
		w.state.Count++
		xorDigest(&w.state.Checksum, entryDigest(w.hasher, key, value, &w.scratch))
		w.pending = append(w.pending, indexPair{Key: key, Value: value})
		return nil
	}
	if old := w.bucket.Get(key); old != nil {
		if !validIndexValue(key, old) {
			return model.Fail(model.Corrupt)
		}
		xorDigest(&w.state.Checksum, entryDigest(w.hasher, key, old, &w.scratch))
	} else {
		if uint64(w.state.Count) == ^uint64(0) {
			return model.Fail(model.Unavailable)
		}
		w.state.Count++
	}
	xorDigest(&w.state.Checksum, entryDigest(w.hasher, key, value, &w.scratch))
	return w.bucket.Put(key, value)
}

// delete removes one entry and keeps the counted multiset root exact; a missing or damaged
// entry is corruption (the caller derived the key from rows that must be indexed).
func (w *indexWriter) delete(key []byte) error {
	if w.runs {
		set, err := w.openSet()
		if err != nil {
			return err
		}
		old := set.Get(key)
		if old == nil || !validIndexValue(key, old) || w.state.Count == 0 {
			return model.Fail(model.Corrupt)
		}
		xorDigest(&w.state.Checksum, entryDigest(w.hasher, key, old, &w.scratch))
		w.state.Count--
		if _, err := set.Delete(key); err != nil {
			return err
		}
		return nil
	}
	old := w.bucket.Get(key)
	if old == nil || !validIndexValue(key, old) || w.state.Count == 0 {
		return model.Fail(model.Corrupt)
	}
	xorDigest(&w.state.Checksum, entryDigest(w.hasher, key, old, &w.scratch))
	w.state.Count--
	return w.bucket.Delete(key)
}

// openSet opens the union of the base bucket and the runs of the index (once: a put never needs it).
func (w *indexWriter) openSet() (*indexSet, error) {
	if w.set == nil {
		set, err := openIndexSet(w.tx, w.name)
		if err != nil {
			return nil, err
		}
		w.set = set
	}
	return w.set, nil
}
func (w *indexWriter) finish() error {
	if w.runs && len(w.pending) > 0 {
		if w.acc != nil {
			w.acc.add(w.name, w.pending)
		} else if err := writeIndexRun(w.tx, w.name, w.pending); err != nil {
			return err
		}
		w.pending = nil
	}
	return w.meta.Put([]byte(w.name), digestBytes(w.state))
}
func initializeIndexIntegrity(tx *bolt.Tx) error {
	meta := tx.Bucket([]byte("scan_integrity"))
	if meta == nil {
		return model.Fail(model.Corrupt)
	}
	for _, name := range []string{"scan_time", "scan_postings"} {
		bucket := tx.Bucket([]byte(name))
		if bucket == nil || bucket.Stats().KeyN != 0 {
			return model.Fail(model.Corrupt)
		}
		if err := meta.Put([]byte(name), digestBytes(IndexDigest{})); err != nil {
			return err
		}
	}
	return nil
}

// validateIndexIntegrity is validateIndexIntegrityPolled for a caller that is not stopped (the start, the tests).
func validateIndexIntegrity(tx *bolt.Tx) error { return validateIndexIntegrityPolled(tx, nil) }

// validateIndexIntegrityPolled re-derives the counted digest of both query indexes and the row count of the pages from every entry;
// a poll that reports cancellation stops it (the background full pass, which Close waits for).
func validateIndexIntegrityPolled(tx *bolt.Tx, poll *cancelPoll) error {
	var timeCount uint64
	for _, name := range []string{"scan_time", "scan_postings"} {
		writer, err := newIndexWriter(tx, name)
		if err != nil {
			return err
		}
		var actual IndexDigest
		scan := writer.bucket.ForEach
		if writer.runs {
			set, err := writer.openSet()
			if err != nil {
				return err
			}
			scan = set.ForEach
		}
		err = scan(func(key, value []byte) error {
			if err := poll.tick(); err != nil {
				return err
			}
			if !validIndexValue(key, value) || uint64(actual.Count) == ^uint64(0) {
				return model.Fail(model.Corrupt)
			}
			actual.Count++
			xorDigest(&actual.Checksum, entryDigest(writer.hasher, key, value, &writer.scratch))
			return nil
		})
		if err != nil {
			return err
		}
		if actual != writer.state {
			return model.Fail(model.Corrupt)
		}
		if name == "scan_time" {
			timeCount = uint64(actual.Count)
		}
	}
	var rows uint64
	if err := tableForEach(tx, tblPages, func(_, value []byte) error {
		if err := poll.tick(); err != nil {
			return err
		}
		ref, err := parsePageRef(value)
		if err != nil || ^uint64(0)-rows < uint64(ref.Count) {
			return model.Fail(model.Corrupt)
		}
		rows += uint64(ref.Count)
		return nil
	}); err != nil {
		return err
	}
	if rows != timeCount {
		return model.Fail(model.Corrupt)
	}
	return nil
}
