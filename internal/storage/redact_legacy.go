// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"

	bolt "go.etcd.io/bbolt"
	"soundpost/internal/durablefs"
	"soundpost/internal/model"
	"soundpost/internal/replica"
)

// Legacy WAL redaction crash hooks, in the order redactLegacyWAL reaches them.
const (
	HookLegacyWALBegin   = "legacy_wal_begin"   // stale entries found, nothing written
	HookLegacyWALWrite   = "legacy_wal_write"   // temp file created, nothing copied
	HookLegacyWALSync    = "legacy_wal_sync"    // temp file complete, not yet durable
	HookLegacyWALSwitch  = "legacy_wal_switch"  // temp file durable, not yet renamed
	HookLegacyWALRenamed = "legacy_wal_renamed" // renamed, directory not yet synced
)

// ResidualLegacyWAL: a pre-replication data/slot-NN.wal still holds the original payload of a
// command that has since been erased (it differs from the redacted command stored for the same
// index). It is reported until redactLegacyWAL has replaced those entries.
const ResidualLegacyWAL = "storage_legacy_wal"

const legacyWALTemp = ".redact"

// A node upgraded from the pre-replication layout holds its whole history twice: initializeReplicaNamespace
// imports data/slot-NN.wal into replica_commands, and the file stays on disk because the 01.03
// reader (recover) validates it on every open and a node that never replicates reads its state
// from it. After the import the file is no longer an authority (recover only checks it, and
// applies nothing from the imported prefix), so the erasure pass redacts it exactly as it
// redacts the Raft journal:
//
//   - the stored redacted command (replica_commands) is the durable authority;
//   - the file is streamed into slot-NN.wal.redact, each entry whose stored command is a
//     redaction replaced by that command's bytes (new length, header and payload checksums),
//     every other entry copied byte for byte;
//   - the temp file is fsynced, closed and atomically renamed over the WAL, then the directory
//     is synced.
//
// A crash leaves the complete old or the complete new WAL (rename is atomic and the new file is
// durable before it), plus at worst a temp file that holds no erased byte (every stale entry is
// substituted while it is copied) and is removed by the next pass. The old WAL is never trusted
// to be clean: the stored redacted commands are re-derived on every open and every erase pass,
// and the pass fails (so physical cleanup is not recorded) until the file is rewritten.
//
// The rewritten file is still a valid legacy WAL: same entry count, same indexes, every entry
// decodes as a walEntry (a batch_redacted/artifact_redacted command decodes), so recover accepts
// it. Only entries that were redacted change; an index above the imported prefix never exists
// in this file.
func (e *Engine) redactLegacyWAL(slot uint16, redacted []replica.Redaction) error {
	legacy, err := e.legacyCount(slot)
	if err != nil || legacy == 0 {
		return err
	}
	want := legacyRedactions(redacted, legacy)
	if len(want) == 0 {
		return nil
	}
	path := filepath.Join(e.dir, walName(slot))
	temp := path + legacyWALTemp
	epoch := e.redact.epoch[slot].Load()
	if err = os.Remove(temp); err != nil && !os.IsNotExist(err) {
		return err
	}
	stale, err := legacyWALDiffers(path, slot, legacy, want)
	if err != nil {
		return err
	}
	if !stale {
		e.redact.legacyClean[slot].Store(epoch + 1)
		return nil
	}
	if err = e.trip(HookLegacyWALBegin); err != nil {
		return err
	}
	if err = e.writeLegacyWALTemp(path, temp, slot, legacy, want); err != nil {
		return err
	}
	if err = e.trip(HookLegacyWALSwitch); err != nil {
		return err
	}
	// Nothing reads the handle recover left open (this engine never appends to the legacy WAL);
	// it is released so the rename also works where an open file cannot be replaced.
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return model.Fail(model.Unavailable)
	}
	f := e.files[slot]
	e.files[slot] = nil
	e.mu.Unlock()
	if f != nil {
		_ = f.Close()
	}
	if err = os.Rename(temp, path); err != nil {
		return err
	}
	if err = e.trip(HookLegacyWALRenamed); err != nil {
		return err
	}
	if err = durablefs.SyncDir(e.dir); err != nil {
		return err
	}
	e.redact.legacyClean[slot].Store(epoch + 1)
	return nil
}

func (e *Engine) writeLegacyWALTemp(path, temp string, slot uint16, legacy uint64, want map[uint64][]byte) error {
	out, err := os.OpenFile(temp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	fail := func(err error) error { _ = out.Close(); return err }
	if err = e.trip(HookLegacyWALWrite); err != nil {
		return fail(err)
	}
	w := bufio.NewWriterSize(out, 1<<20)
	err = scanLegacyWAL(path, slot, legacy, func(index uint64, header [walHeader]byte, payload []byte) error {
		if replacement, ok := want[index]; ok && !bytes.Equal(replacement, payload) {
			if len(replacement) > 8<<20 {
				return model.Fail(model.Invalid) // the 01.03 reader refuses a longer entry
			}
			header, payload = resealWALRecord(header, replacement), replacement
		}
		if _, err := w.Write(header[:]); err != nil {
			return err
		}
		_, err := w.Write(payload)
		return err
	})
	if err != nil {
		return fail(err)
	}
	if err = w.Flush(); err != nil {
		return fail(err)
	}
	if err = e.trip(HookLegacyWALSync); err != nil {
		return fail(err)
	}
	if err = out.Sync(); err != nil {
		return fail(err)
	}
	return out.Close()
}

// resealWALRecord returns the header of a record whose payload was replaced: the new length, then
// the header checksum, then the checksum that covers both and the payload (the writer's order).
func resealWALRecord(header [walHeader]byte, payload []byte) [walHeader]byte {
	binary.BigEndian.PutUint32(header[8:12], uint32(len(payload)))
	binary.BigEndian.PutUint32(header[32:36], headerChecksum(header[:]))
	binary.BigEndian.PutUint32(header[12:16], checksum(header[:], payload))
	return header
}

// legacyRedactions keeps the redactions that name an entry of the imported prefix.
func legacyRedactions(redacted []replica.Redaction, legacy uint64) map[uint64][]byte {
	want := map[uint64][]byte{}
	for _, r := range redacted {
		if r.ApplicationIndex <= legacy {
			want[r.ApplicationIndex] = r.Replacement
		}
	}
	return want
}

func (e *Engine) legacyCount(slot uint16) (uint64, error) {
	var legacy uint64
	err := e.db.View(func(tx *bolt.Tx) error {
		if meta := tx.Bucket([]byte("replica_data")); meta != nil {
			legacy = getUint(meta, metaKey(slot, "legacy"))
		}
		return nil
	})
	return legacy, err
}

// legacyWALStale reports whether the slot's legacy WAL still holds the original of a command
// that has been redacted since. An unreadable WAL is an error, not a "no".
func (e *Engine) legacyWALStale(slot uint16, legacy uint64) (bool, error) {
	epoch := e.redact.epoch[slot].Load()
	if e.redact.legacyClean[slot].Load() == epoch+1 {
		return false, nil
	}
	redacted, err := e.redactedCommands(slot)
	if err != nil {
		return false, err
	}
	stale := false
	if want := legacyRedactions(redacted, legacy); len(want) != 0 {
		if stale, err = legacyWALDiffers(filepath.Join(e.dir, walName(slot)), slot, legacy, want); err != nil {
			return false, err
		}
	}
	if !stale {
		e.redact.legacyClean[slot].Store(epoch + 1)
	}
	return stale, nil
}

var errLegacyStop = errors.New("stop")

// legacyWALDiffers reports whether any entry named in want holds other bytes than its redaction.
func legacyWALDiffers(path string, slot uint16, legacy uint64, want map[uint64][]byte) (bool, error) {
	differs := false
	err := scanLegacyWAL(path, slot, legacy, func(index uint64, _ [walHeader]byte, payload []byte) error {
		if replacement, ok := want[index]; ok && !bytes.Equal(replacement, payload) {
			differs = true
			return errLegacyStop
		}
		return nil
	})
	if errors.Is(err, errLegacyStop) {
		err = nil
	}
	return differs, err
}

// scanLegacyWAL streams the legacy WAL record by record with the checks recover applies to the
// imported prefix: frame, slot, index chain, both checksums and size bounds, and exactly legacy
// records (recover truncated any torn tail when the engine opened).
func scanLegacyWAL(path string, slot uint16, legacy uint64, visit func(index uint64, header [walHeader]byte, payload []byte) error) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 1<<20)
	for index := uint64(1); index <= legacy; index++ {
		var h [walHeader]byte
		if _, err = io.ReadFull(r, h[:]); err != nil {
			return model.Fail(model.Corrupt)
		}
		if !bytes.Equal(h[:4], []byte("SPW1")) || binary.BigEndian.Uint16(h[4:6]) != 1 || binary.BigEndian.Uint16(h[6:8]) != slot || binary.BigEndian.Uint64(h[16:24]) != 1 || binary.BigEndian.Uint64(h[24:32]) != index || headerChecksum(h[:]) != binary.BigEndian.Uint32(h[32:36]) || !bytes.Equal(h[36:], make([]byte, 4)) {
			return model.Fail(model.Corrupt)
		}
		size := binary.BigEndian.Uint32(h[8:12])
		if size == 0 || size > 8<<20 {
			return model.Fail(model.Corrupt)
		}
		payload := make([]byte, size)
		if _, err = io.ReadFull(r, payload); err != nil || checksum(h[:], payload) != binary.BigEndian.Uint32(h[12:16]) {
			return model.Fail(model.Corrupt)
		}
		if err = visit(index, h, payload); err != nil {
			return err
		}
	}
	if _, err = r.ReadByte(); err != io.EOF {
		return model.Fail(model.Corrupt)
	}
	return nil
}
