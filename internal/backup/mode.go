// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package backup

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// maxFirstRecord bounds the first journal record read by IsDistributedDirectory (the
// replica journal's own per-record limit).
const maxFirstRecord = 256 << 20

// journalMode is what the first record of one replica journal says about the node that
// wrote it.
type journalMode int

const (
	// journalUnknown: no journal, an empty one, or a first record that is not readable as one.
	journalUnknown journalMode = iota
	journalSingle
	journalDistributed
)

// IsDistributedDirectory reports whether a data directory was written by a node of a
// replicated (distributed) installation. Backup, restore and activation implement the
// single-voter layout only (docs/operations/backup-restore.md, Limits); opening a
// distributed node's directory as a single node fails deep inside the replica journal
// with an untyped error, so callers ask first and refuse with a typed message.
//
// The answer comes from the first record of a replica journal, which carries the creating
// node's identity and the membership it was created with. A single-node installation is
// always member 1 of a one-member group; a distributed node is a member of a group of at
// least three. The control group's journal (raft/control/ready.wal) decides when it can be
// read. When it is absent or unreadable (deleted, or torn at its first record) the data
// groups' journals (raft/data/slot-N/ready.wal) are asked in its place: every group of a
// node is created with the same identity and membership, so one slot journal that names a
// distributed node classifies the directory.
//
// Snapshot files are deliberately not a marker: a single-voter root restored from a cluster
// backup holds snapshots cut in that cluster (their membership is the source's), and no
// journal yet, until it is first opened. A directory whose journals are all gone, with only
// snapshots left, is therefore not classified either way; the ordinary open path reports
// its own condition.
func IsDistributedDirectory(dir string) (bool, error) {
	mode, err := firstRecordMode(filepath.Join(dir, "raft", "control", "ready.wal"))
	if err != nil || mode != journalUnknown {
		return mode == journalDistributed, err
	}
	slots, err := os.ReadDir(filepath.Join(dir, "raft", "data"))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	for _, slot := range slots {
		if !slot.IsDir() || !strings.HasPrefix(slot.Name(), "slot-") {
			continue
		}
		mode, err = firstRecordMode(filepath.Join(dir, "raft", "data", slot.Name(), "ready.wal"))
		if err != nil {
			return false, err
		}
		if mode == journalDistributed {
			return true, nil
		}
	}
	return false, nil
}

// firstRecordMode classifies one replica journal by its first record. A journal that does
// not exist, or whose first record cannot be read as one, is journalUnknown; any other
// failure to open it is returned.
func firstRecordMode(path string) (journalMode, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return journalUnknown, nil
	}
	if err != nil {
		return journalUnknown, err
	}
	defer f.Close()
	var header [16]byte
	if _, err = io.ReadFull(f, header[:]); err != nil {
		return journalUnknown, nil
	}
	length := binary.BigEndian.Uint32(header[4:8])
	if string(header[:4]) != "SPR1" || length == 0 || length > maxFirstRecord {
		return journalUnknown, nil
	}
	raw := make([]byte, length)
	if _, err = io.ReadFull(f, raw); err != nil {
		return journalUnknown, nil
	}
	var record struct {
		Node    string `json:"node"`
		Members struct {
			Nodes []json.RawMessage `json:"nodes"`
		} `json:"members"`
	}
	if json.Unmarshal(raw, &record) != nil || (record.Node == "" && len(record.Members.Nodes) == 0) {
		return journalUnknown, nil
	}
	if len(record.Members.Nodes) > 1 || (record.Node != "" && record.Node != "1") {
		return journalDistributed, nil
	}
	return journalSingle, nil
}
