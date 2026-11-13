// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"

	bolt "go.etcd.io/bbolt"
	"soundpost/internal/auth"
	"soundpost/internal/model"
)

// ReceiptReplayChunks returns the replay chunks of the stored batch a receipt answers for, read
// back from the durable command the receipt's cursor names. It is what lets a receipt lookup pin
// the checkpoints of a batch whose acknowledgement was lost between the append and the index step.
// The caller has just obtained receipt from LookupReceipt with the same scope and request; the
// batch must be that request's (org, project, source, producer, slot, id, hash). A batch whose
// bytes were erased or redacted yields no chunks: there is nothing left to pin.
func (e *Engine) ReceiptReplayChunks(ctx context.Context, scope auth.Scope, r model.ReceiptRequest, receipt model.Receipt) ([]model.ReplayChunk, error) {
	projects := scope.ProjectIDs()
	if len(projects) != 1 || r.RouteSlot >= 64 {
		return nil, model.Fail(model.Forbidden)
	}
	if err := ctx.Err(); err != nil {
		return nil, model.Fail(model.Cancelled)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.failed {
		return nil, model.Fail(model.Unavailable)
	}
	var chunks []model.ReplayChunk
	err := e.db.View(func(tx *bolt.Tx) error {
		commands := tx.Bucket([]byte("replica_commands"))
		if commands == nil {
			return model.Fail(model.Corrupt)
		}
		raw := commands.Get(commandKey(r.RouteSlot, uint64(receipt.Cursor.Index)))
		if raw == nil {
			return nil
		}
		entry, err := decodeWAL(raw)
		if err != nil {
			return model.Fail(model.Corrupt)
		}
		b := entry.Batch
		if b == nil || b.Org != scope.OrgID() || b.Project != projects[0] || b.Source != r.Source || b.Producer != r.Producer || b.RouteSlot != r.RouteSlot || b.ID != r.BatchID || b.Hash != r.OriginalHash {
			return nil
		}
		for i := range b.Records {
			if rec := &b.Records[i]; rec.Kind == model.Replay && rec.Payload.Replay != nil {
				chunks = append(chunks, *rec.Payload.Replay)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return chunks, nil
}
