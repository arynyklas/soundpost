// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import bolt "go.etcd.io/bbolt"
import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"soundpost/internal/model"
)

const walHeader = 40

func checksum(header, payload []byte) uint32 {
	h := crc32.New(crc32.MakeTable(crc32.Castagnoli))
	h.Write(header[:12])
	h.Write(header[16:])
	h.Write(payload)
	return h.Sum32()
}
func headerChecksum(h []byte) uint32 {
	x := crc32.New(crc32.MakeTable(crc32.Castagnoli))
	x.Write(h[:12])
	x.Write(h[16:32])
	x.Write(h[36:40])
	return x.Sum32()
}
func (e *Engine) recover() error {
	for slot := range uint16(64) {
		path := filepath.Join(e.dir, walName(slot))
		f, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND, 0600)
		if err == nil {
			e.files[slot] = f
		}
		var previouslyApplied uint64
		if readErr := e.db.View(func(tx *bolt.Tx) error {
			raw := tx.Bucket([]byte("cursors")).Get(slotKey(slot))
			if raw != nil {
				if len(raw) != 8 {
					return model.Fail(model.Corrupt)
				}
				previouslyApplied = binary.BigEndian.Uint64(raw)
			}
			return nil
		}); readErr != nil {
			return readErr
		}
		replicated, legacy, cutErr := e.replicatedLegacyCut(slot)
		if cutErr != nil {
			return cutErr
		}
		walApplied := previouslyApplied
		if replicated {
			walApplied = legacy
			e.indexes[slot] = previouslyApplied
		}
		if os.IsNotExist(err) {
			if walApplied != 0 {
				return model.Fail(model.Corrupt)
			}
			continue
		}
		if err != nil {
			return err
		}
		var offset int64
		var index uint64
		for {
			var h [walHeader]byte
			n, err := io.ReadFull(f, h[:])
			if err == io.EOF {
				break
			}
			if err == io.ErrUnexpectedEOF {
				if n == 0 {
					break
				}
				if err = f.Truncate(offset); err != nil {
					return err
				}
				if err = f.Sync(); err != nil {
					return err
				}
				break
			}
			if err != nil {
				return err
			}
			if !bytes.Equal(h[:4], []byte("SPW1")) || binary.BigEndian.Uint16(h[4:6]) != 1 || binary.BigEndian.Uint16(h[6:8]) != slot || binary.BigEndian.Uint64(h[16:24]) != 1 || binary.BigEndian.Uint64(h[24:32]) != index+1 || headerChecksum(h[:]) != binary.BigEndian.Uint32(h[32:36]) || !bytes.Equal(h[36:], make([]byte, 4)) {
				return model.Fail(model.Corrupt)
			}
			length := binary.BigEndian.Uint32(h[8:12])
			if length == 0 || length > 8<<20 {
				return model.Fail(model.Corrupt)
			}
			payload := make([]byte, int(length))
			_, err = io.ReadFull(f, payload)
			if err == io.ErrUnexpectedEOF || err == io.EOF {
				if err = f.Truncate(offset); err != nil {
					return err
				}
				if err = f.Sync(); err != nil {
					return err
				}
				break
			}
			if err != nil {
				return err
			}
			if checksum(h[:], payload) != binary.BigEndian.Uint32(h[12:16]) {
				return model.Fail(model.Corrupt)
			}
			var entry walEntry
			if json.Unmarshal(payload, &entry) != nil {
				return model.Fail(model.Corrupt)
			}
			index++
			if replicated && index > legacy {
				return model.Fail(model.Corrupt)
			}
			if index > previouslyApplied {
				if err = e.apply(slot, index, entry); err != nil {
					return model.Fail(model.Corrupt)
				}
			}
			offset += walHeader + int64(length)
		}
		if replicated {
			if index != legacy {
				return model.Fail(model.Corrupt)
			}
			e.indexes[slot] = previouslyApplied
		} else {
			e.indexes[slot] = index
		}
		var applied uint64
		if err = e.db.View(func(tx *bolt.Tx) error {
			v := tx.Bucket([]byte("cursors")).Get(slotKey(slot))
			if len(v) == 8 {
				applied = binary.BigEndian.Uint64(v)
			}
			return nil
		}); err != nil {
			return err
		}
		if applied != e.indexes[slot] {
			return model.Fail(model.Corrupt)
		}
	}
	return nil
}
