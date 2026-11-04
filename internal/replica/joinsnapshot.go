// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"encoding/json"
	"sort"

	raft "go.etcd.io/raft/v3"
	pb "go.etcd.io/raft/v3/raftpb"
	"google.golang.org/protobuf/proto"
)

// snapshotSource is the raft.Storage of every group. It is the journal's
// MemoryStorage except for the snapshot offered to a peer that needs one.
//
// etcd raft refuses to restore a snapshot whose ConfState does not contain the
// recipient. The stored snapshot is cut by CreateSnapshot and anchors a
// truncated journal, so its ConfState predates any member added afterwards: a
// fresh learner (a replacement voter under a new id) added after a truncation
// could never be repaired, it ignored every snapshot forever. For such a
// recipient the leader offers a snapshot cut at the applied index with the
// current configuration instead. That snapshot is only ever sent; it is never
// stored in MemoryStorage or the journal, so truncation keeps anchoring on the
// verified snapshot directory.
type snapshotSource struct {
	*raft.MemoryStorage
	g *Group
}

// Snapshot is called only from RawNode methods, which the Group invokes with
// g.mu held.
func (s snapshotSource) Snapshot() (*pb.Snapshot, error) {
	stored, err := s.MemoryStorage.Snapshot()
	if err != nil {
		return stored, err
	}
	g := s.g
	if confCovers(stored.GetMetadata().GetConfState(), g.conf) {
		if g.sendSnap != nil && g.sendSnap.GetMetadata().GetIndex() <= stored.GetMetadata().GetIndex() {
			g.sendSnap = nil
		}
		return stored, nil
	}
	return g.membershipSnapshotLocked(stored)
}

// confCovers reports whether every member of the current configuration appears
// in the snapshot's configuration.
func confCovers(snapshot, current *pb.ConfState) bool {
	if current == nil {
		return true
	}
	have := map[uint64]bool{}
	for _, set := range [][]uint64{snapshot.GetVoters(), snapshot.GetLearners(), snapshot.GetVotersOutgoing(), snapshot.GetLearnersNext()} {
		for _, id := range set {
			have[id] = true
		}
	}
	for _, set := range [][]uint64{current.GetVoters(), current.GetLearners(), current.GetVotersOutgoing(), current.GetLearnersNext()} {
		for _, id := range set {
			if !have[id] {
				return false
			}
		}
	}
	return true
}

// membershipSnapshotLocked cuts the sendable snapshot at the applied index with
// the current configuration, reusing the previous one while it is still current
// and not older than the stored snapshot the retained journal is anchored on.
// The machine state and the applied index are consistent because both change
// only under g.mu. A failure is reported as temporarily unavailable so raft
// retries on its next round instead of panicking.
func (g *Group) membershipSnapshotLocked(stored *pb.Snapshot) (*pb.Snapshot, error) {
	if cached := g.sendSnap; cached != nil && cached.GetMetadata().GetIndex() >= stored.GetMetadata().GetIndex() && confCovers(cached.GetMetadata().GetConfState(), g.conf) {
		return cached, nil
	}
	if g.failed || g.closed || g.applied == 0 || g.applied < stored.GetMetadata().GetIndex() {
		return nil, raft.ErrSnapshotTemporarilyUnavailable
	}
	index := g.applied
	term, err := g.memory.Term(index)
	if err != nil {
		return nil, raft.ErrSnapshotTemporarilyUnavailable
	}
	state, err := g.machine.Snapshot()
	if err != nil {
		return nil, raft.ErrSnapshotTemporarilyUnavailable
	}
	envelope := snapshotEnvelope{Application: g.application, State: state, Members: cloneMembers(g.members), Retiring: append([]Member(nil), g.retiring...)}
	for _, c := range g.completed {
		envelope.Completed = append(envelope.Completed, c)
	}
	sort.Slice(envelope.Completed, func(i, j int) bool { return envelope.Completed[i].Index < envelope.Completed[j].Index })
	raw, err := json.Marshal(envelope)
	if err != nil {
		return nil, raft.ErrSnapshotTemporarilyUnavailable
	}
	g.sendSnap = &pb.Snapshot{Data: raw, Metadata: &pb.SnapshotMetadata{Index: new(index), Term: new(term), ConfState: proto.Clone(g.conf).(*pb.ConfState)}}
	return g.sendSnap, nil
}
