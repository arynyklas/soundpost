// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"encoding/json"
	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
	"strconv"
)

func jobKey(b model.NormalizedBatch, j *model.JobAttemptEvent) []byte {
	return []byte(b.Org.String() + ":" + b.Project.String() + ":" + j.Attempt.String())
}
func validateJobs(tx *bolt.Tx, b model.NormalizedBatch) error {
	seen := map[string]model.JobAttemptEvent{}
	for _, record := range b.Records {
		if record.Kind != model.JobAttempt {
			continue
		}
		next := record.Payload.Job
		key := jobKey(b, next)
		previous, exists := seen[string(key)]
		if !exists {
			if raw := tx.Bucket([]byte("jobs")).Get(key); raw != nil {
				if json.Unmarshal(raw, &previous) != nil {
					return model.Fail(model.Corrupt)
				}
				exists = true
			}
		}
		if exists {
			old, _ := model.CanonicalJSON(previous)
			value, _ := model.CanonicalJSON(next)
			if previous.Job != next.Job || previous.Run != next.Run || previous.Ordinal != next.Ordinal || previous.Epoch != next.Epoch {
				return model.Fail(model.Conflict)
			}
			// A re-sent older "started" of an attempt that has moved on (even to a
			// terminal event) is a late duplicate, not a conflict: the sender never
			// saw the ack. The reducer is the authority on duplicate/ordering and
			// the stored marker keeps the newest event (see putJob). An older
			// terminal event, or any different event at the same sequence, is.
			late := next.Sequence < previous.Sequence && next.State == "started"
			if !late {
				if previous.State != "started" && !bytes.Equal(old, value) {
					return model.Fail(model.Conflict)
				}
				if next.Sequence < previous.Sequence || next.Sequence == previous.Sequence && !bytes.Equal(old, value) {
					return model.Fail(model.Conflict)
				}
			}
			if late {
				continue
			}
		}
		seen[string(key)] = *next
	}
	return nil
}
func validateFence(tx *bolt.Tx, b model.NormalizedBatch) error {
	raw := tx.Bucket([]byte("fences")).Get([]byte(b.Source.String() + ":" + strconv.Itoa(int(b.RouteSlot))))
	if raw == nil {
		return nil
	}
	var f model.SourceFence
	if json.Unmarshal(raw, &f) != nil {
		return model.Fail(model.Corrupt)
	}
	if b.PolicyEpoch < f.Epoch {
		return model.Fail(model.Stale)
	}
	return nil
}
func validateOrdered(tx *bolt.Tx, b model.NormalizedBatch) error {
	if e := validateFence(tx, b); e != nil {
		return e
	}
	if e := validateTombstoneBatch(tx, b); e != nil {
		return e
	}
	if e := validateMetrics(tx, b); e != nil {
		return e
	}
	return validateJobs(tx, b)
}

// putJob stores the newest event of an attempt: a late older event (accepted as a
// duplicate by validateJobs) never regresses the marker.
func putJob(tx *bolt.Tx, b model.NormalizedBatch, j *model.JobAttemptEvent) error {
	bucket := tx.Bucket([]byte("jobs"))
	key := jobKey(b, j)
	if raw := bucket.Get(key); raw != nil {
		var previous model.JobAttemptEvent
		if json.Unmarshal(raw, &previous) == nil && previous.Epoch == j.Epoch && j.Sequence < previous.Sequence {
			return nil
		}
	}
	raw, err := json.Marshal(j)
	if err != nil {
		return err
	}
	return bucket.Put(key, raw)
}
