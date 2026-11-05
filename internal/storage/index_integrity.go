// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	bolt "go.etcd.io/bbolt"
	"hash"
	"hash/crc32"
	"soundpost/internal/model"
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
	return &indexWriter{bucket: bucket, meta: meta, name: name, state: state, hasher: sha256.New()}, nil
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
func (w *indexWriter) put(key, value []byte) error {
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
	old := w.bucket.Get(key)
	if old == nil || !validIndexValue(key, old) || w.state.Count == 0 {
		return model.Fail(model.Corrupt)
	}
	xorDigest(&w.state.Checksum, entryDigest(w.hasher, key, old, &w.scratch))
	w.state.Count--
	return w.bucket.Delete(key)
}
func (w *indexWriter) finish() error { return w.meta.Put([]byte(w.name), digestBytes(w.state)) }
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
func validateIndexIntegrity(tx *bolt.Tx) error {
	var timeCount uint64
	for _, name := range []string{"scan_time", "scan_postings"} {
		writer, err := newIndexWriter(tx, name)
		if err != nil {
			return err
		}
		var actual IndexDigest
		err = writer.bucket.ForEach(func(key, value []byte) error {
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
	pages := tx.Bucket([]byte("scan_pages"))
	if pages == nil {
		return model.Fail(model.Corrupt)
	}
	if err := pages.ForEach(func(_, value []byte) error {
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
