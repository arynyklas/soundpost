// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"context"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	pb "go.etcd.io/raft/v3/raftpb"
)

// The running group tolerates a snapshot at exactly the index of the one it holds (as the open
// path does) and nothing else: an older or newer one is still a different state.
func TestSameIndexSnapshotIsRecognisedExactly(t *testing.T) {
	s := openSolo(t, t.TempDir(), model.NewID(), nil)
	s.propose(Barrier, "a")
	s.propose(Barrier, "b")
	cursor := model.Cursor{Group: s.id, Index: model.Uint64(s.group.Status().ApplicationCursor.Index)}
	if _, err := s.group.CreateSnapshot(context.Background(), cursor); err != nil {
		t.Fatal(err)
	}
	if _, err := s.group.CompactJournal(context.Background()); err != nil {
		t.Fatal(err)
	}
	held, err := s.group.memory.Snapshot()
	if err != nil || held.GetMetadata().GetIndex() == 0 {
		t.Fatalf("no in-memory snapshot: %v", err)
	}
	at := func(i uint64) *pb.Snapshot { return &pb.Snapshot{Metadata: &pb.SnapshotMetadata{Index: &i}} }
	index := held.GetMetadata().GetIndex()
	if !s.group.sameIndexSnapshot(at(index)) || s.group.sameIndexSnapshot(at(index-1)) || s.group.sameIndexSnapshot(at(index+1)) {
		t.Fatalf("same-index recognition wrong around %d", index)
	}
}
