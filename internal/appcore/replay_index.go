// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore

import (
	"context"
	"errors"
	"soundpost/internal/auth"
	"soundpost/internal/ingest"
	"soundpost/internal/model"
	"soundpost/internal/replays"
	"time"
)

// ReplayIndex is the index step of replay admission: *replays.Service.
type ReplayIndex interface {
	CheckIndex(ctx context.Context, scope auth.Scope, project model.ID, chunk model.ReplayChunk) error
	RecordScope(ctx context.Context, scope auth.Scope, project model.ID, chunk model.ReplayChunk, retainUntil model.UnixNano) error
}

var _ ReplayIndex = (*replays.Service)(nil)

// replayIndexingAppender is the post-admission half of replay intake (the
// closed-format gate is the pre-admission half, see ingest.SetReplayGate). It
// wraps the durable appender so that no replay chunk is acknowledged before the
// immutable checkpoint index and the retention group know it:
//
//   - before the append, every checkpoint is checked against the index, so a
//     chunk that conflicts with a recorded checkpoint (a different chunk at a
//     recorded checkpoint sequence, a foreign session for the replay root) is
//     refused as a Conflict and never stored;
//   - after the append, the receipt's replay deadline is recorded for the
//     batch's chunks. This runs for a fresh receipt and for the original receipt
//     of a retried batch alike, and Record is idempotent, so a crash between the
//     append and the record is repaired by the sender's retry of the same batch.
//     A record failure is returned as an error and the receipt is dropped: the
//     sender is not acknowledged and retries.
//
// A batch with no replay record passes straight through, unread. The decorator
// holds chunks only to hand them to the index; it logs nothing and every error it
// returns is a bare typed fault.
type replayIndexingAppender struct {
	inner ingest.Appender
	index ReplayIndex
	now   func() time.Time
}

// NewReplayIndexingAppender decorates the durable appender of ingest.
func NewReplayIndexingAppender(inner ingest.Appender, index ReplayIndex) (ingest.Appender, error) {
	if inner == nil || index == nil {
		return nil, model.Fail(model.Invalid)
	}
	return &replayIndexingAppender{inner: inner, index: index, now: time.Now}, nil
}

func (a *replayIndexingAppender) Append(ctx context.Context, scope auth.Scope, b model.NormalizedBatch) (model.Receipt, error) {
	var chunks []*model.ReplayChunk
	for i := range b.Records {
		if r := &b.Records[i]; r.Kind == model.Replay {
			if r.Payload.Replay == nil {
				return model.Receipt{}, model.Fail(model.Invalid)
			}
			chunks = append(chunks, r.Payload.Replay)
		}
	}
	if len(chunks) == 0 {
		return a.inner.Append(ctx, scope, b)
	}
	indexed, err := indexedChunks(chunks)
	if err != nil {
		return model.Receipt{}, err
	}
	for _, c := range indexed {
		if err = a.index.CheckIndex(ctx, scope, b.Project, *c); err != nil {
			return model.Receipt{}, indexFault(err)
		}
	}
	receipt, err := a.inner.Append(ctx, scope, b)
	if err != nil {
		return model.Receipt{}, err
	}
	retain := model.UnixNano(0)
	for _, d := range receipt.SignalDeadlines {
		if d.Kind == model.Replay {
			retain = d.RetainUntil
		}
	}
	if retain == 0 {
		// The receipt of a batch with a replay record must carry its replay deadline.
		return model.Receipt{}, model.Fail(model.Corrupt)
	}
	if int64(retain) <= a.now().UnixNano() {
		// A retried batch whose replay deadline has passed: its chunks are due for
		// erasure and there is nothing left to protect or to index.
		return receipt, nil
	}
	for _, c := range indexed {
		if err = a.index.RecordScope(ctx, scope, b.Project, *c, retain); err != nil {
			return model.Receipt{}, indexFault(err)
		}
	}
	return receipt, nil
}

func (a *replayIndexingAppender) LookupReceipt(ctx context.Context, scope auth.Scope, q model.ReceiptRequest) (model.Receipt, error) {
	return a.inner.LookupReceipt(ctx, scope, q)
}

// indexFault reduces an index error to its bare code, so nothing but a typed
// fault, never chunk content or a driver message, reaches the sender or a log. An
// error that is not a typed fault is an unavailable index: retryable.
func indexFault(err error) error {
	var f *model.Fault
	if errors.As(err, &f) {
		return model.Fail(f.Code)
	}
	return model.Fail(model.Unavailable)
}

type checkpointKey struct {
	replay   model.ID
	sequence uint64
}

// indexedChunks selects what the index must see and refuses what cannot be
// stored together. The first chunk of each replay fixes the batch's root session
// and every checkpoint is a pinned hash; a later delta of the same replay adds
// nothing the index can answer differently (every chunk of a batch shares one
// deadline). A batch that contradicts itself (two sessions for one replay, two
// different chunks at one checkpoint sequence) is a Conflict before any chunk
// of it is stored.
func indexedChunks(chunks []*model.ReplayChunk) ([]*model.ReplayChunk, error) {
	sessions := make(map[model.ID]model.ID, len(chunks))
	checkpoints := map[checkpointKey]*model.ReplayChunk{}
	out := make([]*model.ReplayChunk, 0, len(chunks))
	for _, c := range chunks {
		session, known := sessions[c.Replay]
		if known && session != c.Session {
			return nil, model.Fail(model.Conflict)
		}
		sessions[c.Replay] = c.Session
		isCheckpoint := c.CheckpointSequence == c.Sequence
		if isCheckpoint {
			key := checkpointKey{c.Replay, uint64(c.Sequence)}
			if first, dup := checkpoints[key]; dup {
				a, errA := replays.ChunkHash(*first)
				b, errB := replays.ChunkHash(*c)
				if errA != nil || errB != nil {
					return nil, model.Fail(model.Invalid)
				}
				if a != b {
					return nil, model.Fail(model.Conflict)
				}
				continue
			}
			checkpoints[key] = c
		}
		if !known || isCheckpoint {
			out = append(out, c)
		}
	}
	return out, nil
}
