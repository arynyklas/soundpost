// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"encoding/base64"
	"encoding/json"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
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
	EraseUnack    *eraseUnack                 `json:"erase_unack,omitempty"`
	EraseNotice   *eraseNotice                `json:"erase_notice,omitempty"`
	Proposer      *replica.Proposer           `json:"proposer,omitempty"`
	Redaction     *redaction                  `json:"redaction,omitempty"`
}

func (entry walEntry) MarshalJSON() ([]byte, error) { return encodeWAL(entry) }

// fragmentHead and fragmentTail are the members of a model.ArtifactFragment that json.Marshal
// writes before and after its bytes, with the tags of ArtifactFragment.
// TestFragmentHeadAndTailCoverArtifactFragment keeps them in step.
type fragmentHead struct {
	Manifest    model.BlobManifest             `json:"manifest"`
	Reservation model.ArtifactQuotaReservation `json:"reservation"`
	Ordinal     uint32                         `json:"ordinal"`
}
type fragmentTail struct {
	Hash   model.Hash   `json:"hash"`
	Cursor model.Cursor `json:"cursor"`
}

// encodeWAL is json.Marshal(entry) without the second validate-and-copy pass that json.Marshal
// makes over the output of MarshalJSON; the bytes are the same.
func encodeWAL(entry walEntry) ([]byte, error) {
	if raw, ok, err := encodeFragmentJSON(entry); ok || err != nil {
		return raw, err
	}
	wire := durableEntry{Type: entry.Type, Receipt: entry.Receipt, Cancel: entry.Cancel, Fence: entry.Fence, Artifact: entry.Artifact, ArtifactGC: entry.ArtifactGC, Rejection: entry.Rejection, CommitSet: entry.CommitSet, DeleteBarrier: entry.DeleteBarrier, EraseAck: entry.EraseAck, EraseUnack: entry.EraseUnack, EraseNotice: entry.EraseNotice, Proposer: entry.Proposer, Redaction: entry.Redaction}
	if b := entry.Batch; b != nil {
		wire.Batch = &durableBatch{Org: b.Org, Hash: b.Hash, Canonical: b.Canonical, PolicyEpoch: b.PolicyEpoch, PolicyHash: b.PolicyHash, AdmissionAt: b.AdmissionAt, Deadlines: b.Deadlines, Reservation: b.Reservation}
	}
	return json.Marshal(wire)
}

// encodeFragmentJSON writes an artifact fragment entry in the bytes encodeWAL's generic path
// gives it, assembled once at its exact size: the generic path grows the encoder's buffer for the
// base64 of the fragment and returns a copy of it, about three times the fragment's size more
// than the text itself. ok is false for any other entry, which the caller encodes generically.
func encodeFragmentJSON(entry walEntry) (raw []byte, ok bool, err error) {
	f := entry.Artifact
	if f == nil || entry.Type != "artifact_fragment" || entry.Batch != nil || entry.Receipt != nil || entry.Cancel != nil || entry.Fence != nil || entry.ArtifactGC != nil || entry.Rejection != nil || entry.CommitSet != nil || entry.DeleteBarrier != nil || entry.EraseAck != nil || entry.EraseUnack != nil || entry.EraseNotice != nil || entry.Proposer != nil || entry.Redaction != nil {
		return nil, false, nil
	}
	head, err := json.Marshal(fragmentHead{Manifest: f.Manifest, Reservation: f.Reservation, Ordinal: f.Ordinal})
	if err != nil {
		return nil, true, err
	}
	tail, err := json.Marshal(fragmentTail{Hash: f.Hash, Cursor: f.Cursor})
	if err != nil {
		return nil, true, err
	}
	// head is {"manifest":..,"reservation":..,"ordinal":..}; tail is {"hash":..,"cursor":..}.
	const open, bytesKey, end = `{"type":"artifact_fragment","artifact":`, `,"bytes":`, `}`
	size := len(open) + len(head) - 1 + len(bytesKey) + len(tail) + len(end)
	if f.Bytes == nil {
		size += len("null")
	} else {
		size += base64.StdEncoding.EncodedLen(len(f.Bytes)) + 2
	}
	out := make([]byte, 0, size)
	out = append(out, open...)
	out = append(out, head[:len(head)-1]...)
	out = append(out, bytesKey...)
	if f.Bytes == nil {
		out = append(out, "null"...)
	} else {
		out = append(out, '"')
		out = base64.StdEncoding.AppendEncode(out, f.Bytes)
		out = append(out, '"')
	}
	out = append(out, ',')
	out = append(out, tail[1:]...)
	return append(out, end...), true, nil
}

// decodeWAL reads a replicated command in either wire form: the binary fragment envelope
// (envelope.go) or the JSON text every other command, and every command a build that predates
// the envelope wrote, has. The JSON path is decodeWALJSON, which is also exactly what such a
// build runs on every payload.
func decodeWAL(raw []byte) (walEntry, error) {
	if isEnvelope(raw) {
		return decodeFragmentEnvelope(raw)
	}
	return decodeWALJSON(raw)
}

// decodeWALJSON is json.Unmarshal(raw, &entry) without the outer pass that only re-validates and
// copies raw before handing it to UnmarshalJSON, which validates strictly itself.
func decodeWALJSON(raw []byte) (walEntry, error) {
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
	for _, present := range []bool{wire.Batch != nil, wire.Cancel != nil, wire.Fence != nil, wire.Artifact != nil, wire.ArtifactGC != nil, wire.Rejection != nil, wire.DeleteBarrier != nil, wire.EraseAck != nil, wire.EraseUnack != nil, wire.EraseNotice != nil} {
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
	if (wire.Type == "delete_barrier") != (wire.DeleteBarrier != nil) || (wire.Type == "erase_ack") != (wire.EraseAck != nil) || (wire.Type == "erase_unack") != (wire.EraseUnack != nil) || (wire.Type == "erase_notice") != (wire.EraseNotice != nil) {
		return model.Fail(model.Corrupt)
	}
	if wire.Proposer != nil && wire.Type != "erase_ack" && wire.Type != "erase_unack" && wire.Type != "erase_notice" {
		return model.Fail(model.Corrupt)
	}
	if (wire.Type == "rejected") != (wire.Rejection != nil) || wire.Rejection != nil && (wire.Batch != nil || wire.Receipt != nil || wire.Cancel != nil || wire.Fence != nil || wire.Artifact != nil || wire.ArtifactGC != nil) {
		return model.Fail(model.Corrupt)
	}
	if (wire.Type == "artifact_fragment") != (wire.Artifact != nil) || (wire.Type == "artifact_gc") != (wire.ArtifactGC != nil) || wire.Artifact != nil && (wire.Batch != nil || wire.Receipt != nil || wire.Cancel != nil || wire.Fence != nil || wire.ArtifactGC != nil) || wire.ArtifactGC != nil && (wire.Batch != nil || wire.Receipt != nil || wire.Cancel != nil || wire.Fence != nil || wire.Artifact != nil) {
		return model.Fail(model.Corrupt)
	}
	out := walEntry{Type: wire.Type, Receipt: wire.Receipt, Cancel: wire.Cancel, Fence: wire.Fence, Artifact: wire.Artifact, ArtifactGC: wire.ArtifactGC, Rejection: wire.Rejection, CommitSet: wire.CommitSet, DeleteBarrier: wire.DeleteBarrier, EraseAck: wire.EraseAck, EraseUnack: wire.EraseUnack, EraseNotice: wire.EraseNotice, Proposer: wire.Proposer}
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
