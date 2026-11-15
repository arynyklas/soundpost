// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replays

import (
	"context"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"math"
	"slices"
)

// systemAuthorizer is implemented by *auth.Service: the runner's own read scope
// for one project. Intake holds a source scope, which cannot read records, so
// the stored-chunk check reads under the runner's scope and only ever for the
// replay IDs and project of the batch being admitted.
type systemAuthorizer interface {
	AuthorizeSystem(ctx context.Context, org model.ID, projects []model.ID, action auth.Permission) (auth.Scope, error)
}

// maxStoredPerSequence bounds the distinct chunks remembered per sequence while
// the stored rows of a replay are scanned.
const maxStoredPerSequence = maxAlternates + 1

// storedReplay is what a scan of one replay's stored rows keeps: the distinct
// chunk hashes per sequence and the sessions that stored chunks claim.
type storedReplay struct {
	hashes   map[uint64][]model.Hash
	sessions []model.ID
}

func (r *storedReplay) add(seq uint64, h model.Hash, session model.ID) {
	if !slices.Contains(r.sessions, session) && len(r.sessions) < maxStoredPerSequence {
		r.sessions = append(r.sessions, session)
	}
	if hs := r.hashes[seq]; !slices.Contains(hs, h) && len(hs) < maxStoredPerSequence {
		r.hashes[seq] = append(hs, h)
	}
}

// CheckStored is the stateful half of the intake check of a batch: the chunks of
// the batch are verified against the chunks already STORED for the same replays
// (not only against the checkpoint index), before anything of the batch is
// appended. It refuses, as a Conflict and without writing anything:
//
//   - two different chunks at one sequence, inside the batch or between the batch
//     and a stored chunk (a retry of the identical chunk is not a conflict);
//   - a chunk whose session differs from the session of a stored chunk of the
//     replay (the first stored chunk pins the root session, not the first one
//     the index recorded);
//   - a delta whose previous-hash differs from the hash of the chunk already
//     stored (or present earlier in the batch) at the preceding sequence, and a
//     delta whose checkpoint hash differs from the stored/batch checkpoint it
//     names. A recorder-declared gap delta states a deliberate break and is
//     exempt from the previous-hash rule only.
//
// A delta whose predecessor is not stored yet is accepted: a missing or late
// chunk is a read-time gap (docs/protocol/replay-v1.md), never an intake refusal.
// Nothing here is authority; the reader still proves the chain from verified
// checkpoints.
func (s *Service) CheckStored(ctx context.Context, scope auth.Scope, project model.ID, chunks []model.ReplayChunk) error {
	if len(chunks) == 0 {
		return nil
	}
	if !scope.AllowsProject(project) {
		return model.Fail(model.Forbidden)
	}
	if err := s.authorizer.Revalidate(ctx, scope); err != nil {
		return err
	}
	runner, ok := s.authorizer.(systemAuthorizer)
	if !ok {
		return model.Fail(model.Unavailable)
	}
	byReplay := map[model.ID][]*model.ReplayChunk{}
	var order []model.ID
	for i := range chunks {
		c := &chunks[i]
		if _, seen := byReplay[c.Replay]; !seen {
			order = append(order, c.Replay)
		}
		byReplay[c.Replay] = append(byReplay[c.Replay], c)
	}
	var read auth.Scope
	for _, id := range order {
		batch := byReplay[id]
		inBatch, err := batchHashes(batch)
		if err != nil {
			return err
		}
		if read.OrgID() == (model.ID{}) {
			if read, err = runner.AuthorizeSystem(ctx, scope.OrgID(), []model.ID{project}, auth.Read); err != nil {
				return err
			}
		}
		stored := storedReplay{hashes: map[uint64][]model.Hash{}}
		err = s.scan(ctx, read, id, math.MinInt64, math.MaxInt64, func(p model.ID, c *model.ReplayChunk) error {
			if p != project {
				return nil
			}
			m, ok := metaOf(c)
			if !ok || m.invalid {
				return nil
			}
			stored.add(m.seq, m.hash, c.Session)
			return nil
		})
		if err != nil {
			return err
		}
		if err = checkAgainstStored(batch, inBatch, &stored); err != nil {
			return err
		}
	}
	return nil
}

// batchHashes is the chunk hash by sequence of one replay's chunks in a batch; two
// different chunks at one sequence contradict the batch.
func batchHashes(batch []*model.ReplayChunk) (map[uint64]model.Hash, error) {
	out := make(map[uint64]model.Hash, len(batch))
	for _, c := range batch {
		h, err := ChunkHash(*c)
		if err != nil {
			return nil, err
		}
		if seen, dup := out[uint64(c.Sequence)]; dup && seen != h {
			return nil, model.Fail(model.Conflict)
		}
		out[uint64(c.Sequence)] = h
	}
	return out, nil
}

func checkAgainstStored(batch []*model.ReplayChunk, inBatch map[uint64]model.Hash, stored *storedReplay) error {
	known := func(seq uint64) []model.Hash {
		hs := stored.hashes[seq]
		if h, ok := inBatch[seq]; ok && !slices.Contains(hs, h) {
			hs = append(slices.Clone(hs), h)
		}
		return hs
	}
	for _, c := range batch {
		for _, session := range stored.sessions {
			if session != c.Session {
				return model.Fail(model.Conflict)
			}
		}
		seq := uint64(c.Sequence)
		h := inBatch[seq]
		if hs := stored.hashes[seq]; len(hs) > 0 && !slices.Contains(hs, h) {
			return model.Fail(model.Conflict)
		}
		if c.CheckpointSequence == c.Sequence {
			continue
		}
		if cp := uint64(c.CheckpointSequence); cp >= 1 && cp < seq {
			if hs := known(cp); len(hs) > 0 && !slices.Contains(hs, c.Checkpoint) {
				return model.Fail(model.Conflict)
			}
		}
		if seq > 1 && !c.Gap {
			if hs := known(seq - 1); len(hs) > 0 && !slices.Contains(hs, c.Previous) {
				return model.Fail(model.Conflict)
			}
		}
	}
	return nil
}
