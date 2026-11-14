// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
	"io"
	"os"
	"path/filepath"
)

// migrateIndexes reads only the already-applied WAL prefix. The frozen recovery
// owner still validates/truncates the tail and applies genuinely unapplied work.
// Reading the original normalized envelope preserves its exact capture-policy
// revision; current source policy is never substituted for historical metadata.
func (e *Engine) migrateIndexes(tx *bolt.Tx) error {
	batches := tx.Bucket([]byte("batches"))
	indexed := 0
	for slot := range uint16(64) {
		cursor := tx.Bucket([]byte("cursors")).Get(slotKey(slot))
		if cursor == nil {
			continue
		}
		if len(cursor) != 8 {
			return model.Fail(model.Corrupt)
		}
		applied := binary.BigEndian.Uint64(cursor)
		if applied == 0 {
			continue
		}
		f, err := os.Open(filepath.Join(e.dir, walName(slot)))
		if err != nil {
			return model.Fail(model.Corrupt)
		}
		err = func() error {
			defer f.Close()
			for index := uint64(1); ; index++ {
				var header [walHeader]byte
				if _, err := io.ReadFull(f, header[:]); err != nil {
					return model.Fail(model.Corrupt)
				}
				if !bytes.Equal(header[:4], []byte("SPW1")) || binary.BigEndian.Uint16(header[4:6]) != 1 || binary.BigEndian.Uint16(header[6:8]) != slot || binary.BigEndian.Uint64(header[16:24]) != 1 || binary.BigEndian.Uint64(header[24:32]) != index || headerChecksum(header[:]) != binary.BigEndian.Uint32(header[32:36]) || !bytes.Equal(header[36:], make([]byte, 4)) {
					return model.Fail(model.Corrupt)
				}
				size := binary.BigEndian.Uint32(header[8:12])
				if size == 0 || size > 8<<20 {
					return model.Fail(model.Corrupt)
				}
				payload := make([]byte, int(size))
				if _, err := io.ReadFull(f, payload); err != nil || checksum(header[:], payload) != binary.BigEndian.Uint32(header[12:16]) {
					return model.Fail(model.Corrupt)
				}
				var entry walEntry
				if json.Unmarshal(payload, &entry) != nil {
					return model.Fail(model.Corrupt)
				}
				if entry.Type == "batch" {
					if entry.Batch == nil || entry.Receipt == nil {
						return model.Fail(model.Corrupt)
					}
					b, r := entry.Batch, entry.Receipt
					if b.RouteSlot != slot || b.PolicyRevision == 0 || r.Cursor.Group != e.group(slot) || uint64(r.Cursor.Index) != index {
						return model.Fail(model.Corrupt)
					}
					key := batchKey(b.Org, b.Project, b.Source, b.Producer, b.RouteSlot, b.ID)
					if raw := batches.Get(key); raw != nil {
						var rows []model.Record
						if json.Unmarshal(raw, &rows) != nil {
							return model.Fail(model.Corrupt)
						}
						if err := e.indexAppliedRows(tx, *b, *r, rows); err != nil {
							return err
						}
						indexed++
					}
				}
				if index == applied {
					break
				}
			}
			return nil
		}()
		if err != nil {
			return err
		}
	}
	if indexed != batches.Stats().KeyN {
		return model.Fail(model.Corrupt)
	}
	return nil
}
