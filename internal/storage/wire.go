// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"encoding/json"
	"soundpost/internal/model"
	"soundpost/internal/replica"
)

// The canonical input is stored once. Encoding both Batch and its canonical
// bytes would exceed the WAL budget for an otherwise valid 4-MiB batch.
type durableBatch struct {
	Org         model.ID                   `json:"org"`
	Hash        model.Hash                 `json:"hash"`
	Canonical   []byte                     `json:"canonical"`
	PolicyEpoch model.Uint64               `json:"policy_epoch"`
	PolicyHash  string                     `json:"policy_hash"`
	AdmissionAt model.UnixNano             `json:"admission_at_ns"`
	Deadlines   []model.SignalDeadline     `json:"deadlines"`
	Reservation model.AdmissionReservation `json:"reservation"`
}
type durableEntry struct {
	Type       string                   `json:"type"`
	Batch      *durableBatch            `json:"batch,omitempty"`
	Receipt    *model.Receipt           `json:"receipt,omitempty"`
	Cancel     *model.CancelReservation `json:"cancel,omitempty"`
	Fence      *model.SourceFence       `json:"fence,omitempty"`
	Artifact   *model.ArtifactFragment  `json:"artifact,omitempty"`
	ArtifactGC *model.ArtifactGC        `json:"artifact_gc,omitempty"`
	Rejection  *model.ID                `json:"rejection,omitempty"`
	// DeleteBarrier is the data-slot tombstone (Type "delete_barrier").
	DeleteBarrier *model.DeleteBarrier        `json:"delete_barrier,omitempty"`
	CommitSet     *replica.CommitSetWatermark `json:"commit_set,omitempty"`
	EraseAck      *eraseAck                   `json:"erase_ack,omitempty"`
	Redaction     *redaction                  `json:"redaction,omitempty"`
}

func (entry walEntry) MarshalJSON() ([]byte, error) { return encodeWAL(entry) }

// encodeWAL is json.Marshal(entry) without the second validate-and-copy pass that json.Marshal
// makes over the output of MarshalJSON; the bytes are the same.
func encodeWAL(entry walEntry) ([]byte, error) {
	wire := durableEntry{Type: entry.Type, Receipt: entry.Receipt, Cancel: entry.Cancel, Fence: entry.Fence, Artifact: entry.Artifact, ArtifactGC: entry.ArtifactGC, Rejection: entry.Rejection, CommitSet: entry.CommitSet, DeleteBarrier: entry.DeleteBarrier, EraseAck: entry.EraseAck, Redaction: entry.Redaction}
	if b := entry.Batch; b != nil {
		wire.Batch = &durableBatch{Org: b.Org, Hash: b.Hash, Canonical: b.Canonical, PolicyEpoch: b.PolicyEpoch, PolicyHash: b.PolicyHash, AdmissionAt: b.AdmissionAt, Deadlines: b.Deadlines, Reservation: b.Reservation}
	}
	return json.Marshal(wire)
}

// decodeWAL is json.Unmarshal(raw, &entry) without the outer pass that only re-validates and
// copies raw before handing it to UnmarshalJSON, which validates strictly itself.
func decodeWAL(raw []byte) (walEntry, error) {
	var entry walEntry
	err := entry.UnmarshalJSON(raw)
	return entry, err
}
func (entry *walEntry) UnmarshalJSON(raw []byte) error {
	var wire durableEntry
	if model.StrictJSON(raw, &wire) != nil {
		return model.Fail(model.Corrupt)
	}
	if wire.Type == "batch_redacted" || wire.Type == "artifact_redacted" {
		return entry.unmarshalRedacted(wire)
	}
	if wire.Redaction != nil {
		return model.Fail(model.Corrupt)
	}
	arms := 0
	for _, present := range []bool{wire.Batch != nil, wire.Cancel != nil, wire.Fence != nil, wire.Artifact != nil, wire.ArtifactGC != nil, wire.Rejection != nil, wire.DeleteBarrier != nil, wire.EraseAck != nil} {
		if present {
			arms++
		}
	}
	if arms != 1 || (wire.Type == "batch") != (wire.Batch != nil) || (wire.Type == "batch") != (wire.Receipt != nil) || (wire.Type == "cancel") != (wire.Cancel != nil) || (wire.Type == "fence") != (wire.Fence != nil) {
		return model.Fail(model.Corrupt)
	}
	if wire.CommitSet != nil && (wire.Type != "cancel" || wire.Cancel == nil || wire.CommitSet.Reservation != wire.Cancel.ReservationID || wire.CommitSet.Group != wire.Cancel.OwnerGroup) {
		return model.Fail(model.Corrupt)
	}
	if (wire.Type == "delete_barrier") != (wire.DeleteBarrier != nil) || (wire.Type == "erase_ack") != (wire.EraseAck != nil) {
		return model.Fail(model.Corrupt)
	}
	if (wire.Type == "rejected") != (wire.Rejection != nil) || wire.Rejection != nil && (wire.Batch != nil || wire.Receipt != nil || wire.Cancel != nil || wire.Fence != nil || wire.Artifact != nil || wire.ArtifactGC != nil) {
		return model.Fail(model.Corrupt)
	}
	if (wire.Type == "artifact_fragment") != (wire.Artifact != nil) || (wire.Type == "artifact_gc") != (wire.ArtifactGC != nil) || wire.Artifact != nil && (wire.Batch != nil || wire.Receipt != nil || wire.Cancel != nil || wire.Fence != nil || wire.ArtifactGC != nil) || wire.ArtifactGC != nil && (wire.Batch != nil || wire.Receipt != nil || wire.Cancel != nil || wire.Fence != nil || wire.Artifact != nil) {
		return model.Fail(model.Corrupt)
	}
	out := walEntry{Type: wire.Type, Receipt: wire.Receipt, Cancel: wire.Cancel, Fence: wire.Fence, Artifact: wire.Artifact, ArtifactGC: wire.ArtifactGC, Rejection: wire.Rejection, CommitSet: wire.CommitSet, DeleteBarrier: wire.DeleteBarrier, EraseAck: wire.EraseAck}
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
