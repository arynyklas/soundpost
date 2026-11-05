// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"encoding/json"
	bolt "go.etcd.io/bbolt"
	"soundpost/internal/model"
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
			if previous.State != "started" && !bytes.Equal(old, value) {
				return model.Fail(model.Conflict)
			}
			if previous.Job != next.Job || previous.Run != next.Run || previous.Ordinal != next.Ordinal || previous.Epoch != next.Epoch || next.Sequence < previous.Sequence {
				return model.Fail(model.Conflict)
			}
			if next.Sequence == previous.Sequence && !bytes.Equal(old, value) {
				return model.Fail(model.Conflict)
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
