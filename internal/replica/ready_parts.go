// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"sync/atomic"

	raft "go.etcd.io/raft/v3"
	"google.golang.org/protobuf/proto"
)

// A snapshot larger than one journal record (D86, condition 3).
//
// A journal record is bounded (defaultMaxReadyBytes), and a snapshot used to travel in one: the record that
// seeds a journal, the head of a compacted journal and the snapshot a lagging voter installs. The control
// state grows with the admissions that are not settled yet (141 MB at 115,000 acknowledged requests, and
// it reaches the bound once base64 has been applied twice to it), so the whole snapshot of a group whose
// state is that large did not fit: the first compaction failed the bound and stopped the node, and a peer,
// a new member or a backup restore could not be given the state at all.
//
// A snapshot that does not fit one record is therefore written as a chain of records: part records, each
// carrying one slice of the snapshot's protobuf encoding (readyRecord.SnapshotPart), then the record that
// would have carried the snapshot, with SnapshotParts naming how many part records precede it and the hard
// state and entries it always carried. The reader joins the chain and installs the snapshot as if it had
// been one record. A chain whose last record never reached the disk is a record that was never
// acknowledged (the writer syncs once, after the last record): the journal is cut back to where the chain
// began, as for a torn record.
//
// A snapshot that fits one record is written exactly as before, so a journal that the previous release can
// read stays one it can read; a snapshot beyond the bound is the one the previous release could not have
// written or read at all.

// defaultMaxReadyBytes is the bound on one journal record (and on one message of the peer transport).
const defaultMaxReadyBytes = 256 << 20

var readyLimit atomic.Int64

func init() { readyLimit.Store(defaultMaxReadyBytes) }

// maxReady is the bound on one journal record.
func maxReady() int { return int(readyLimit.Load()) }

// SetRecordLimitForTest sets the bound on one journal record (and on one peer message) and returns the
// function that puts the previous one back. A test that needs a snapshot larger than a record lowers the
// bound instead of building hundreds of megabytes of state. Test only.
func SetRecordLimitForTest(n int) (restore func()) {
	previous := readyLimit.Swap(int64(n))
	return func() { readyLimit.Store(previous) }
}

// snapshotPartBytes is how many bytes of a snapshot one part record carries: a quarter of the bound, so
// that the base64 text of a part is a third of it.
func snapshotPartBytes() int { return max(1, maxReady()/4) }

// recordNeed is the length of the record text of rd (the bytes appendRecord writes); head is the text of
// the record's leading members. scratch is the size of the largest protobuf encoding appendRecord builds.
func (w *readyWAL) recordNeed(rd raft.Ready) (head []byte, need, scratch int, err error) {
	if head, err = json.Marshal(readyHead{Group: w.group, Node: w.node, Members: cloneMembers(w.members)}); err != nil {
		return nil, 0, 0, ErrInvalid
	}
	// The record is sized once: the head, then the base64 of every part and its separators.
	const separators = len(`,"hard":"",`) + len(`"snapshot":"",`) + len(`"entries":[]}`)
	need = len(head) + separators
	size := func(m proto.Message) int {
		n := proto.Size(m)
		scratch = max(scratch, n)
		return base64.StdEncoding.EncodedLen(n)
	}
	if rd.HardState != nil {
		need += size(rd.HardState)
	}
	if rd.Snapshot != nil {
		need += size(rd.Snapshot)
	}
	for _, ent := range rd.Entries {
		need += size(ent) + len(`"",`)
	}
	return head, need, scratch, nil
}

// needsParts reports whether the record of rd carries a snapshot that cannot be written in one record.
func (w *readyWAL) needsParts(rd raft.Ready) bool {
	if rd.Snapshot == nil {
		return false
	}
	_, need, _, err := w.recordNeed(rd)
	return err == nil && need > maxReady()
}

// persistParts writes the snapshot of rd as a chain of records (see above), then its hard state and
// entries, and syncs once.
func (w *readyWAL) persistParts(rd raft.Ready) error {
	snapshot, err := proto.Marshal(rd.Snapshot)
	if err != nil {
		return err
	}
	r := readyRecord{Group: w.group, Node: w.node, Members: cloneMembers(w.members), Snapshot: snapshot}
	if rd.HardState != nil {
		if r.Hard, err = proto.Marshal(rd.HardState); err != nil {
			return err
		}
	}
	for _, ent := range rd.Entries {
		raw, err := proto.Marshal(ent)
		if err != nil {
			return err
		}
		r.Entries = append(r.Entries, raw)
	}
	err = splitReady(r, func(frame readyRecord) error {
		raw, err := json.Marshal(frame)
		if err != nil || len(raw) > maxReady() {
			return ErrInvalid
		}
		return w.writeFrame(raw)
	})
	if err != nil {
		return err
	}
	return w.syncFrames()
}

// splitReady calls emit with the records that carry r when its snapshot does not fit one record: a part
// record for each slice of the snapshot, then r without the snapshot and with SnapshotParts.
func splitReady(r readyRecord, emit func(readyRecord) error) error {
	snapshot := r.Snapshot
	r.Snapshot = nil
	part := readyRecord{Group: r.Group, Node: r.Node, Members: r.Members}
	step, parts := snapshotPartBytes(), 0
	for off := 0; off < len(snapshot); off += step {
		part.SnapshotPart = snapshot[off:min(off+step, len(snapshot))]
		if err := emit(part); err != nil {
			return err
		}
		parts++
	}
	r.SnapshotParts = uint64(parts)
	return emit(r)
}

// readyTooLarge reports whether the record text of r (its snapshot as text, and the rest of it) is beyond
// the bound: the case that is written as a chain.
func readyTooLarge(r readyRecord) bool {
	if len(r.Snapshot) == 0 {
		return false
	}
	rest := r
	rest.Snapshot = nil
	raw, err := json.Marshal(rest)
	return err == nil && len(raw)+len(`,"snapshot":""`)+base64.StdEncoding.EncodedLen(len(r.Snapshot)) > maxReady()
}

// writeReadyRecord writes r to out as the record it is, or as the chain that carries it when its snapshot
// does not fit one record.
func writeReadyRecord(out io.Writer, r readyRecord) error {
	if !readyTooLarge(r) {
		raw, err := encodeReady(r)
		if err != nil {
			return err
		}
		return writeFull(out, raw)
	}
	return splitReady(r, func(frame readyRecord) error {
		raw, err := encodeReady(frame)
		if err != nil {
			return err
		}
		return writeFull(out, raw)
	})
}
