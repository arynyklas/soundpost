// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"encoding/binary"
	"encoding/json"
	"github.com/arynyklas/soundpost/internal/durablefs"
	"github.com/arynyklas/soundpost/internal/model"
	"io"
	"os"
	"path/filepath"
)

// This is an image generator, not an ACK-producing proposer. The Engine must be
// closed and the directory must be a test-owned synthetic predecessor image.
func writeLegacyTestEntry(dir string, slot uint16, index uint64, entry walEntry) error {
	if slot >= 64 || index == 0 {
		return model.Fail(model.Invalid)
	}
	if _, err := legacyHistory(dir, slot, index-1); err != nil {
		return err
	}
	payload, err := json.Marshal(entry)
	if err != nil || len(payload) == 0 || len(payload) > 8<<20 {
		return model.Fail(model.Invalid)
	}
	path := filepath.Join(dir, walName(slot))
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	var header [walHeader]byte
	copy(header[:4], "SPW1")
	binary.BigEndian.PutUint16(header[4:6], 1)
	binary.BigEndian.PutUint16(header[6:8], slot)
	binary.BigEndian.PutUint32(header[8:12], uint32(len(payload)))
	binary.BigEndian.PutUint64(header[16:24], 1)
	binary.BigEndian.PutUint64(header[24:32], index)
	binary.BigEndian.PutUint32(header[32:36], headerChecksum(header[:]))
	binary.BigEndian.PutUint32(header[12:16], checksum(header[:], payload))
	for _, raw := range [][]byte{header[:], payload} {
		n, e := file.Write(raw)
		if e != nil {
			file.Close()
			return e
		}
		if n != len(raw) {
			file.Close()
			return io.ErrShortWrite
		}
	}
	if err = file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	return durablefs.SyncDir(dir)
}
