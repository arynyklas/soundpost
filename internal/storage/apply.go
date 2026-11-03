// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	bolt "go.etcd.io/bbolt"
	"soundpost/internal/auth"
	"soundpost/internal/model"
	"strconv"
)

func metricKey(b model.NormalizedBatch, r model.Record) []byte {
	k, _ := model.OwnerKey(r)
	h := model.HashCanonical(k)
	return []byte(b.Org.String() + ":" + b.Project.String() + ":" + strconv.Itoa(int(b.RouteSlot)) + ":" + stringHash(h) + ":" + strconv.FormatInt(int64(r.ObservedAt), 10))
}
func stringHash(h model.Hash) string { b, _ := h.MarshalJSON(); return string(b) }
func validateMetrics(tx *bolt.Tx, b model.NormalizedBatch) error {
	seen := map[string][]byte{}
	for _, r := range b.Records {
		if r.Kind != model.Metric {
			continue
		}
		key := metricKey(b, r)
		value, err := model.CanonicalJSON(r.Payload.Metric)
		if err != nil {
			return model.Fail(model.Invalid)
		}
		old := tx.Bucket([]byte("metrics")).Get(key)
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
		switch entry.Type {
		case "batch":
			if entry.Batch == nil || entry.Receipt == nil {
				return model.Fail(model.Corrupt)
			}
			b := *entry.Batch
			r := *entry.Receipt
			if b.RouteSlot != slot || r.Cursor.Index != index || r.Cursor.Group != e.group(slot) || r.Hash != b.Hash || r.BatchID != b.ID || model.HashCanonical(b.Canonical) != b.Hash {
				return model.Fail(model.Corrupt)
			}
			if err := validateOrdered(tx, b); err != nil {
				return err
			}
			if tx.Bucket([]byte("cancelled")).Get([]byte(b.Reservation.ID.String())) != nil {
				return model.Fail(model.Corrupt)
			}
			key := batchKey(b.Org, b.Project, b.Source, b.Producer, slot, b.ID)
			if tx.Bucket([]byte("receipts")).Get(key) != nil {
				return model.Fail(model.Corrupt)
			}
			records := make([]model.Record, 0, len(b.Records))
			for _, record := range b.Records {
				if record.Kind == model.Metric {
					k := metricKey(b, record)
					bucket := tx.Bucket([]byte("metrics"))
					if bucket.Get(k) != nil {
						continue
					}
					v, err := model.CanonicalJSON(record.Payload.Metric)
					if err != nil {
						return err
					}
					if err = bucket.Put(k, v); err != nil {
						return err
					}
				}
				if record.Kind == model.JobAttempt {
					raw, err := json.Marshal(record.Payload.Job)
					if err != nil {
						return err
					}
					if err = tx.Bucket([]byte("jobs")).Put(jobKey(b, record.Payload.Job), raw); err != nil {
						return err
					}
				}
				records = append(records, record)
			}
			raw, err := json.Marshal(records)
			if err != nil {
				return err
			}
			if err = tx.Bucket([]byte("batches")).Put(key, raw); err != nil {
				return err
			}
			if err = e.trip("receipt_write"); err != nil {
				return err
			}
			raw, err = json.Marshal(r)
			if err != nil {
				return err
			}
			if err = tx.Bucket([]byte("receipts")).Put(key, raw); err != nil {
				return err
			}
			consumed := b.Reservation
			consumed.State = "consumed"
			consumed.Cursor = &r.Cursor
			raw, err = json.Marshal(consumed)
			if err != nil {
				return err
			}
			if err = tx.Bucket([]byte("consumed")).Put([]byte(consumed.ID.String()), raw); err != nil {
				return err
			}
		case "cancel":
			if entry.Cancel == nil {
				return model.Fail(model.Corrupt)
			}
			c := entry.Cancel
			if c.Fence.Index != index || c.Fence.Group != e.group(slot) {
				return model.Fail(model.Corrupt)
			}
			raw, err := json.Marshal(c)
			if err != nil {
				return err
			}
			if err = tx.Bucket([]byte("cancelled")).Put([]byte(c.ReservationID.String()), raw); err != nil {
				return err
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
		default:
			return model.Fail(model.Corrupt)
		}
		if err := e.trip("applied_cursor"); err != nil {
			return err
		}
		var cursor [8]byte
		binary.BigEndian.PutUint64(cursor[:], index)
		return cursors.Put(slotKey(slot), cursor[:])
	})
}
func (e *Engine) LookupReceipt(ctx context.Context, scope auth.Scope, r model.ReceiptRequest) (model.Receipt, error) {
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
		raw := tx.Bucket([]byte("receipts")).Get(batchKey(scope.OrgID(), projects[0], r.Source, r.Producer, r.RouteSlot, r.BatchID))
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
