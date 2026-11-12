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
)

// maxFirstRecord bounds the first control-group journal record read by
// IsDistributedDirectory (the replica journal's own per-record limit).
const maxFirstRecord = 256 << 20

// IsDistributedDirectory reports whether a data directory was written by a node of a
// replicated (distributed) installation. Backup, restore and activation implement the
// single-voter layout only (docs/operations/backup-restore.md, Limits); opening a
// distributed node's directory as a single node fails deep inside the replica journal
// with an untyped error, so callers ask first and refuse with a typed message.
//
// The answer comes from the first record of the control group's journal
// (raft/control/ready.wal), which carries the creating node's identity and the
// membership it was created with. A single-node installation is always member 1 of a
// one-member group; a distributed node is a member of a group of at least three. A
// directory with no journal, or one whose first record cannot be read as that record,
// is not classified as distributed: the ordinary open path reports its own condition.
func IsDistributedDirectory(dir string) (bool, error) {
	f, err := os.Open(filepath.Join(dir, "raft", "control", "ready.wal"))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer f.Close()
	var header [16]byte
	if _, err = io.ReadFull(f, header[:]); err != nil {
		return false, nil
	}
	length := binary.BigEndian.Uint32(header[4:8])
	if string(header[:4]) != "SPR1" || length == 0 || length > maxFirstRecord {
		return false, nil
	}
	raw := make([]byte, length)
	if _, err = io.ReadFull(f, raw); err != nil {
		return false, nil
	}
	var record struct {
		Node    string `json:"node"`
		Members struct {
			Nodes []json.RawMessage `json:"nodes"`
		} `json:"members"`
	}
	if json.Unmarshal(raw, &record) != nil {
		return false, nil
	}
	return len(record.Members.Nodes) > 1 || (record.Node != "" && record.Node != "1"), nil
}
