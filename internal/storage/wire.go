// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"encoding/json"
	"soundpost/internal/model"
)

// The canonical input is stored once. Encoding both Batch and its canonical
// bytes would exceed the WAL budget for an otherwise valid 4-MiB batch.
type durableBatch struct {
	Org         model.ID                   `json:"org"`
	Hash        model.Hash                 `json:"hash"`
	Canonical   []byte                     `json:"canonical"`
	PolicyEpoch uint64                     `json:"policy_epoch,string"`
	PolicyHash  string                     `json:"policy_hash"`
	AdmissionAt model.UnixNano             `json:"admission_at_ns"`
	Deadlines   []model.SignalDeadline     `json:"deadlines"`
	Reservation model.AdmissionReservation `json:"reservation"`
}
type durableEntry struct {
	Type    string                   `json:"type"`
	Batch   *durableBatch            `json:"batch,omitempty"`
	Receipt *model.Receipt           `json:"receipt,omitempty"`
	Cancel  *model.CancelReservation `json:"cancel,omitempty"`
	Fence   *model.SourceFence       `json:"fence,omitempty"`
}

func (entry walEntry) MarshalJSON() ([]byte, error) {
	wire := durableEntry{Type: entry.Type, Receipt: entry.Receipt, Cancel: entry.Cancel, Fence: entry.Fence}
	if b := entry.Batch; b != nil {
		wire.Batch = &durableBatch{Org: b.Org, Hash: b.Hash, Canonical: b.Canonical, PolicyEpoch: b.PolicyEpoch, PolicyHash: b.PolicyHash, AdmissionAt: b.AdmissionAt, Deadlines: b.Deadlines, Reservation: b.Reservation}
	}
	return json.Marshal(wire)
}
func (entry *walEntry) UnmarshalJSON(raw []byte) error {
	var wire durableEntry
	if model.StrictJSON(raw, &wire) != nil {
		return model.Fail(model.Corrupt)
	}
	out := walEntry{Type: wire.Type, Receipt: wire.Receipt, Cancel: wire.Cancel, Fence: wire.Fence}
	if b := wire.Batch; b != nil {
		if len(b.Canonical) > 4<<20 || model.HashCanonical(b.Canonical) != b.Hash {
			return model.Fail(model.Corrupt)
		}
		var input model.Batch
		if model.StrictJSON(b.Canonical, &input) != nil {
			return model.Fail(model.Corrupt)
		}
		out.Batch = &model.NormalizedBatch{Batch: input, Org: b.Org, Hash: b.Hash, Canonical: b.Canonical, PolicyEpoch: b.PolicyEpoch, PolicyHash: b.PolicyHash, AdmissionAt: b.AdmissionAt, Deadlines: b.Deadlines, Reservation: b.Reservation, Series: b.Reservation.Series}
	}
	*entry = out
	return nil
}
