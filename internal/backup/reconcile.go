// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package backup

import (
	"encoding/json"
	"slices"

	"soundpost/internal/model"
	"soundpost/internal/replica"
	"soundpost/internal/storage"
)

// reservationKey mirrors the control store's idempotency key of an admission
// (org:project:source:producer:slot:batch, slot as two lowercase hex digits). A
// restored reservation without it would let a client retry of an ACKed batch be
// reserved and charged a second time; restore_test.go proves the keys agree by
// retrying a batch admitted after the control cut.
func reservationKey(r model.AdmissionReservation) string {
	const digits = "0123456789abcdef"
	return r.Org.String() + ":" + r.Project.String() + ":" + r.Source.String() + ":" + r.Producer.String() + ":" + string([]byte{digits[r.Slot>>4], digits[r.Slot&15]}) + ":" + r.Batch.String()
}

// applyQuotaReconciliation writes the verified C12 QuotaReconciliation into the
// control state restored at the cut C, so that before intake opens control holds
// exactly one charge per reservation the sealed data D consumed:
//
//   - a reservation D proves consumed becomes consumed with its cursor, whether
//     control knew it at C (reserved or consumed) or not;
//   - a reservation created after C and consumed before D is rebuilt whole (the
//     full record comes from the batch inside the sealed snapshot) together with
//     its idempotency key;
//   - a reservation a committed cancellation fence in D proves unused is
//     cancelled (and not charged);
//   - a reservation neither consumed nor fenced is a pending intent: left
//     reserved and charged.
//
// The per-key charges are exactly cert.Apply's. Applying twice is a no-op.
func applyQuotaReconciliation(st *model.ControlState, cert storage.QuotaReconciliation, created map[model.ID]model.AdmissionReservation, evidence []storage.ReservationEvidence) error {
	if st == nil || cert.Version != 1 {
		return model.Fail(model.Invalid)
	}
	byID := make(map[model.ID]storage.ReservationEvidence, len(evidence))
	for _, e := range evidence {
		byID[e.ID] = e
	}
	if st.Reservations == nil {
		st.Reservations = map[string]model.AdmissionReservation{}
	}
	if st.AdmissionKeys == nil {
		st.AdmissionKeys = map[string]string{}
	}
	added := map[model.ID]bool{}
	for _, id := range cert.AddedAfterCut {
		added[id] = true
	}
	for _, id := range cert.Consumed {
		ev, ok := byID[id]
		if !ok {
			return model.Fail(model.Corrupt)
		}
		cursor := ev.Cursor
		r, known := st.Reservations[id.String()]
		if !known {
			if !added[id] {
				return model.Fail(model.Corrupt) // control must know every reservation not created after C
			}
			if r, ok = created[id]; !ok {
				return model.Fail(model.Unavailable) // cannot rebuild the single charge: fail closed
			}
			if r.ID != id || r.Org != ev.Org || r.Project != ev.Project || r.Source != ev.Source || r.Hash != ev.Hash || r.Bytes != ev.Bytes || !slices.Equal(r.Series, ev.Series) || r.Slot >= 64 {
				return model.Fail(model.Corrupt)
			}
			if old, exists := st.AdmissionKeys[reservationKey(r)]; exists && old != id.String() {
				return model.Fail(model.Conflict)
			}
		}
		if r.State == "cancelled" || r.Hash != ev.Hash || r.Bytes != ev.Bytes || (r.Cursor != nil && *r.Cursor != cursor) {
			return model.Fail(model.Conflict)
		}
		r.State, r.Cursor = "consumed", &cursor
		st.Reservations[id.String()] = r
		st.AdmissionKeys[reservationKey(r)] = id.String()
	}
	for _, id := range cert.Refunded {
		r, known := st.Reservations[id.String()]
		if !known {
			return model.Fail(model.Corrupt)
		}
		if r.State == "consumed" {
			return model.Fail(model.Conflict)
		}
		r.State = "cancelled"
		st.Reservations[id.String()] = r
	}
	for _, id := range cert.Pending {
		if r, known := st.Reservations[id.String()]; !known || r.State == "cancelled" || r.State == "consumed" && r.Cursor == nil {
			return model.Fail(model.Corrupt)
		}
	}
	st.Quotas = cert.Apply(st.Quotas)
	return nil
}

// verifyGaps re-verifies, at restore, every gap of the replay certificate
// against the committed control facts at the manifest's control cut. The backup
// driver only ever declares gaps that were committed RecordEvidenceGap facts, but
// a bundle is not trusted for that: every "gap" interval must be named by an
// attestation, every attestation must name a fact present in the control state at
// the cut (same group, exact interval, reason and digest, verified at the cut's
// revision), and nothing may be left over on either side. A widened, shifted,
// duplicated or unbacked gap is rejected.
func verifyGaps(m BackupManifest, intervals []storage.ReplayInterval, st model.ControlState) error {
	var gaps []storage.ReplayInterval
	for _, in := range intervals {
		if in.Mode == "gap" {
			gaps = append(gaps, in)
		}
	}
	if len(gaps) != len(m.Gaps) {
		return model.Fail(model.Corrupt)
	}
	used := make([]bool, len(gaps))
	facts := map[model.ID]bool{}
	for _, a := range m.Gaps {
		if facts[a.Fact] || a.ControlRevision != m.Control.Revision || a.ControlRevision > st.Revision {
			return model.Fail(model.Corrupt)
		}
		facts[a.Fact] = true
		fact, ok := st.EvidenceGaps[a.Fact.String()]
		if !ok || fact.ID != a.Fact || fact.Group != a.Group || fact.After != a.After || fact.Through != a.Through || fact.Reason != a.Reason || GapDigest(fact) != a.Digest {
			return model.Fail(model.Corrupt)
		}
		matched := false
		for i, in := range gaps {
			if !used[i] && in.Group == a.Group && in.After == a.After && in.Through == a.Through && in.Reason == a.Reason && uint64(in.Count) == uint64(in.Through)-uint64(in.After) {
				used[i], matched = true, true
				break
			}
		}
		if !matched {
			return model.Fail(model.Corrupt)
		}
	}
	return nil
}

// slotReservations extracts, from the machine state inside an installed slot
// snapshot, the full admission reservation of every batch it holds. The sealed
// QuotaEvidence carries only what quota needs; the idempotency key of a batch
// admitted after the control cut needs the producer, batch and slot too.
func slotReservations(snapshot replica.Snapshot) (map[model.ID]model.AdmissionReservation, error) {
	state, err := snapshot.MachineState()
	if err != nil {
		return nil, model.Fail(model.Corrupt)
	}
	var machine struct {
		Entries []json.RawMessage `json:"entries"`
	}
	if json.Unmarshal(state, &machine) != nil {
		return nil, model.Fail(model.Corrupt)
	}
	out := map[model.ID]model.AdmissionReservation{}
	for _, raw := range machine.Entries {
		var entry struct {
			Type  string `json:"type"`
			Batch *struct {
				Reservation model.AdmissionReservation `json:"reservation"`
			} `json:"batch"`
		}
		if json.Unmarshal(raw, &entry) != nil {
			return nil, model.Fail(model.Corrupt)
		}
		if entry.Type == "batch" && entry.Batch != nil {
			out[entry.Batch.Reservation.ID] = entry.Batch.Reservation
		}
	}
	return out, nil
}
