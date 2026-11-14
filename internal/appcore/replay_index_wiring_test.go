// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore_test

import (
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replays"
	"github.com/arynyklas/soundpost/internal/storage"
)

// The production wiring: a node opened the way a served process is opened admits a
// checkpoint-and-delta chain through ingest, and the control state then holds the
// immutable checkpoint index and the retention group of the replay. Without the
// post-admission index step the chunks are stored but the index stays empty, so
// the reader has no pinned hash to settle competing chunks and the retention
// group never exists.
func TestAdmittedReplayChunksPopulateTheCheckpointIndex(t *testing.T) {
	rig := newIndexRig(t)
	rec := newReplayRecorder()
	chain := []model.ReplayChunk{rec.cp(), rec.delta(), rec.delta(), rec.cp()}
	var last model.UnixNano
	for _, c := range chain {
		receipt, err := rig.admit(rig.replayBatch(c))
		if err != nil {
			t.Fatalf("chunk %d: %v", c.Sequence, err)
		}
		for _, d := range receipt.SignalDeadlines {
			if d.Kind == model.Replay {
				last = d.RetainUntil
			}
		}
	}
	if rows := rig.storedRows(rec.replay); rows != len(chain) {
		t.Fatalf("%d rows stored, want %d", rows, len(chain))
	}

	group, pin := rig.indexOf(rec.replay)
	if group == nil {
		t.Fatal("the checkpoint index of an admitted replay is empty: admission never recorded its chunks")
	}
	if group.Session != rec.session || len(group.Checkpoints) != 2 || group.Checkpoints[0].Sequence != 1 || group.Checkpoints[1].Sequence != 4 {
		t.Fatalf("index %+v, want session %s and checkpoints at 1 and 4", group, rec.session)
	}
	for i, c := range []model.ReplayChunk{chain[0], chain[3]} {
		if want, err := replays.ChunkHash(c); err != nil || group.Checkpoints[i].Hash != want {
			t.Fatalf("checkpoint %d is not pinned to the stored chunk's hash (%v)", i, err)
		}
	}

	// The retention group: its deadline follows the newest chunk (to within the
	// coalescing slack) and answers for every chunk of the replay.
	if pin.RetainUntil == 0 || last-pin.RetainUntil > model.UnixNano(time.Minute) || pin.RetainUntil > last {
		t.Fatalf("group deadline %d, newest chunk deadline %d", pin.RetainUntil, last)
	}
	service, err := appcore.NewReplayService(rig.app.Storage, rig.app.Auth, rig.app.Control)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range chain {
		c := c
		ref, err := service.LatestReference(rig.ctx, storage.EraseCandidate{Org: rig.org, Project: rig.project, Kind: model.Replay, Record: &model.Record{Kind: model.Replay, Payload: model.Payload{Replay: &c}}})
		if err != nil || ref != pin.RetainUntil {
			t.Fatalf("chunk %d is retained until %d (%v), want the group deadline %d", c.Sequence, ref, err, pin.RetainUntil)
		}
	}
	if got := rig.reads(rec.replay); got != "checkpoint1 delta2 delta3 checkpoint4" {
		t.Fatalf("the reader sees %q", got)
	}
}
