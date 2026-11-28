// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
	"strconv"
)

func metricKey(b model.NormalizedBatch, r model.Record) []byte {
	k, _ := model.OwnerKey(r)
	h := model.HashCanonical(k)
	return []byte(b.Org.String() + ":" + b.Project.String() + ":" + strconv.Itoa(int(b.RouteSlot)) + ":" + stringHash(h) + ":" + strconv.FormatInt(int64(r.ObservedAt), 10))
}
func stringHash(h model.Hash) string { b, _ := h.MarshalJSON(); return string(b) }
func validateMetrics(tx *bolt.Tx, b model.NormalizedBatch) error {
	return validateMetricsWith(tx, b, nil)
}

// validateMetricsWith is validateMetrics with the canonical keys and values of the samples taken from prep
// when the caller derived them already.
func validateMetricsWith(tx *bolt.Tx, b model.NormalizedBatch, prep *batchPrep) error {
	var rows *rowStore
	seen := map[string][]byte{}
	for i, r := range b.Records {
		if r.Kind != model.Metric {
			continue
		}
		var key, value []byte
		if prep != nil {
			key, value = prep.metricKeys[i], prep.metricVals[i]
		} else {
			var err error
			key = metricKey(b, r)
			if value, err = model.CanonicalJSON(r.Payload.Metric); err != nil {
				return model.Fail(model.Invalid)
			}
		}
		if rows == nil {
			var err error
			if rows, err = rowsOf(tx); err != nil {
				return err
			}
		}
		old := rows.Get(tblMetrics, key)
		if prior, ok := seen[string(key)]; ok {
			old = prior
		}
		if old != nil && !bytes.Equal(old, value) {
			return model.Fail(model.Conflict)
		}
		seen[string(key)] = value
	}
	return nil
}
func (e *Engine) apply(slot uint16, index uint64, entry walEntry) error {
	return e.db.Update(func(tx *bolt.Tx) error {
		return withIndexRun(tx, func() error { return e.applyTx(tx, slot, index, entry) })
	})
}
func (e *Engine) applyTx(tx *bolt.Tx, slot uint16, index uint64, entry walEntry) error {
	return e.applyTxPrepared(tx, slot, index, entry, nil)
}

// applyTxPrepared is applyTx for a batch whose derived bytes the caller built before the transaction
// (prepareBatch); prep is nil for any other caller and for an entry that is not a batch.
func (e *Engine) applyTxPrepared(tx *bolt.Tx, slot uint16, index uint64, entry walEntry, prep *batchPrep) error {
	cursors := tx.Bucket([]byte("cursors"))
	previous := cursors.Get(slotKey(slot))
	var applied uint64
	if len(previous) == 8 {
		applied = binary.BigEndian.Uint64(previous)
	}
	if index <= applied {
		return nil
	}
	if index != applied+1 {
		return model.Fail(model.Corrupt)
	}
	if entry.Type != "batch" && entry.Type != "rejected" {
		// The entry may read or delete index entries of the appends before it in this commit.
		if err := flushIndexRun(tx); err != nil {
			return err
		}
	}
	switch entry.Type {
	case "rejected":
		if entry.Rejection == nil || entry.Batch != nil || entry.Receipt != nil || entry.Cancel != nil || entry.Fence != nil || entry.Artifact != nil || entry.ArtifactGC != nil {
			return model.Fail(model.Corrupt)
		}
		rejections, err := tx.CreateBucketIfNotExists([]byte("replica_data"))
		if err != nil {
			return err
		}
		if err = rejections.Put(metaKey(slot, "rejected:"+entry.Rejection.String()), []byte{1}); err != nil {
			return err
		}
	case "batch":
		if entry.Batch == nil || entry.Receipt == nil {
			return model.Fail(model.Corrupt)
		}
		b := *entry.Batch
		r := *entry.Receipt
		if b.RouteSlot != slot || uint64(r.Cursor.Index) != index || r.Cursor.Group != e.group(slot) || r.Hash != b.Hash || r.BatchID != b.ID || model.HashCanonical(b.Canonical) != b.Hash {
			return model.Fail(model.Corrupt)
		}
		rows, err := rowsOf(tx)
		if err != nil {
			return err
		}
		if prep == nil {
			prep = prepareBatch(b, r)
		}
		if err := validateOrderedWith(tx, b, prep); err != nil {
			return err
		}
		e.noteApplied(b.Org, b.Project, b.Records, nil)
		if tx.Bucket([]byte("cancelled")).Get([]byte(b.Reservation.ID.String())) != nil {
			return model.Fail(model.Corrupt)
		}
		key := batchKey(b.Org, b.Project, b.Source, b.Producer, slot, b.ID)
		if rows.Get(tblReceipts, key) != nil {
			return model.Fail(model.Corrupt)
		}
		records := make([]model.Record, 0, len(b.Records))
		for i, record := range b.Records {
			if record.Kind == model.Metric {
				var k, v []byte
				if prep != nil {
					k = prep.metricKeys[i]
				} else {
					k = metricKey(b, record)
				}
				if rows.Get(tblMetrics, k) != nil {
					continue
				}
				if prep != nil {
					v = prep.metricVals[i]
				} else {
					var err error
					if v, err = model.CanonicalJSON(record.Payload.Metric); err != nil {
						return err
					}
				}
				if err := rows.Insert(tblMetrics, k, v); err != nil {
					return err
				}
			}
			if record.Kind == model.JobAttempt {
				if err := putJob(tx, b, record.Payload.Job); err != nil {
					return err
				}
			}
			records = append(records, record)
		}
		// The derived bytes describe the batch with every record stored; a record the store held already
		// is skipped and the rest is derived again from the records that remain.
		whole := prep != nil && len(records) == len(b.Records)
		if prep != nil && !whole {
			if err = prep.oweUnusedPayload(tx); err != nil { // the bytes externalize logged for a batch applied in another shape are dead
				return err
			}
		}
		var raw []byte
		if whole && prep.batchesRef != nil {
			raw = prep.batchesRef
		} else if whole {
			raw = prep.batches
		} else if raw, err = json.Marshal(records); err != nil {
			return err
		}
		if err = rows.Insert(tblBatches, key, raw); err != nil {
			return err
		}
		if whole {
			err = putBuiltIndex(tx, prep.index, r.Cursor)
		} else {
			err = e.indexAppliedRows(tx, b, r, records)
		}
		if err != nil {
			return err
		}
		if err = e.trip("receipt_write"); err != nil {
			return err
		}
		if prep != nil {
			raw = prep.receipt
		} else if raw, err = json.Marshal(r); err != nil {
			return err
		}
		if err = rows.Insert(tblReceipts, key, raw); err != nil {
			return err
		}
		consumed := b.Reservation
		if prep != nil {
			raw = prep.consumed
		} else {
			consumed.State = "consumed"
			consumed.Cursor = &r.Cursor
			if raw, err = json.Marshal(consumed); err != nil {
				return err
			}
		}
		if err = putConsumed(rows, consumed.ID, raw); err != nil {
			return err
		}
	case "cancel":
		if entry.Cancel == nil {
			return model.Fail(model.Corrupt)
		}
		c := entry.Cancel
		if uint64(c.Fence.Index) != index || c.Fence.Group != e.group(slot) {
			return model.Fail(model.Corrupt)
		}
		raw, err := json.Marshal(c)
		if err != nil {
			return err
		}
		if err = tx.Bucket([]byte("cancelled")).Put([]byte(c.ReservationID.String()), raw); err != nil {
			return err
		}
		if entry.CommitSet != nil {
			proof, err := json.Marshal(entry.CommitSet)
			if err != nil {
				return err
			}
			meta, err := tx.CreateBucketIfNotExists([]byte("replica_data"))
			if err != nil {
				return err
			}
			if err = meta.Put(metaKey(slot, "cancel-proof:"+c.ReservationID.String()), proof); err != nil {
				return err
			}
		}
	case "fence":
		if entry.Fence == nil {
			return model.Fail(model.Corrupt)
		}
		raw, err := json.Marshal(entry.Fence)
		if err != nil {
			return err
		}
		if err = tx.Bucket([]byte("fences")).Put([]byte(entry.Fence.Source.String()+":"+strconv.Itoa(int(slot))), raw); err != nil {
			return err
		}
	case "delete_barrier":
		if err := e.applyDeleteBarrier(tx, slot, index, entry); err != nil {
			return err
		}
	case "erase_ack":
		if err := applyEraseAckTx(tx, slot, entry); err != nil {
			return err
		}
	case "erase_unack":
		if err := applyEraseUnackTx(tx, slot, entry); err != nil {
			return err
		}
	case "erase_notice":
		if err := applyEraseNoticeTx(tx, slot, index, entry); err != nil {
			return err
		}
	case "artifact_fragment":
		if entry.Artifact == nil || entry.Batch != nil || entry.Receipt != nil || entry.Cancel != nil || entry.Fence != nil || entry.ArtifactGC != nil {
			return model.Fail(model.Corrupt)
		}
		e.noteApplied(entry.Artifact.Manifest.Org, entry.Artifact.Manifest.Project, nil, &entry.Artifact.Manifest)
		if err := e.applyBlobFragment(tx, slot, index, *entry.Artifact); err != nil {
			return err
		}
	case "artifact_gc":
		if entry.ArtifactGC == nil || entry.Artifact != nil || entry.Batch != nil || entry.Receipt != nil || entry.Cancel != nil || entry.Fence != nil {
			return model.Fail(model.Corrupt)
		}
		if err := e.applyBlobGC(tx, slot, index, *entry.ArtifactGC); err != nil {
			return err
		}
	case "batch_redacted":
		if err := e.applyBatchRedactedTx(tx, slot, index, entry); err != nil {
			return err
		}
	case "artifact_redacted":
		// The erased fragment replays to nothing: there is no root or bytes to rebuild.
		if entry.Redaction == nil || entry.Artifact != nil || entry.Batch != nil || entry.Receipt != nil {
			return model.Fail(model.Corrupt)
		}
	default:
		return model.Fail(model.Corrupt)
	}
	if err := e.trip("applied_cursor"); err != nil {
		return err
	}
	var cursor [8]byte
	binary.BigEndian.PutUint64(cursor[:], index)
	return cursors.Put(slotKey(slot), cursor[:])
}
func (e *Engine) LookupReceipt(ctx context.Context, scope auth.Scope, r model.ReceiptRequest) (model.Receipt, error) {
	authorizedProjects := scope.ProjectIDs()
	if len(authorizedProjects) != 1 {
		return model.Receipt{}, model.Fail(model.Forbidden)
	}
	if err := scope.RevalidateSource(ctx, authorizedProjects[0], r.Source, false); err != nil {
		return model.Receipt{}, err
	}
	if err := e.replicaBeforeWrite(ctx, r.RouteSlot); err != nil {
		return model.Receipt{}, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.failed {
		return model.Receipt{}, model.Fail(model.Unavailable)
	}
	projects := scope.ProjectIDs()
	if len(projects) != 1 || r.RouteSlot >= 64 {
		return model.Receipt{}, model.Fail(model.Forbidden)
	}
	if err := e.validator.Revalidate(ctx, scope); err != nil {
		return model.Receipt{}, err
	}
	if err := scope.RevalidateSource(ctx, projects[0], r.Source, false); err != nil {
		return model.Receipt{}, err
	}
	var out model.Receipt
	err := e.db.View(func(tx *bolt.Tx) error {
		raw, rerr := tableGet(tx, tblReceipts, batchKey(scope.OrgID(), projects[0], r.Source, r.Producer, r.RouteSlot, r.BatchID))
		if rerr != nil {
			return rerr
		}
		if raw == nil {
			return model.Fail(model.NotFound)
		}
		if json.Unmarshal(raw, &out) != nil {
			return model.Fail(model.Corrupt)
		}
		if out.Hash != r.OriginalHash {
			return model.Fail(model.Conflict)
		}
		return nil
	})
	if err != nil {
		return model.Receipt{}, err
	}
	if err = scope.RevalidateSource(ctx, projects[0], r.Source, false); err != nil {
		return model.Receipt{}, err
	}
	out.Historical = true
	return out, nil
}
