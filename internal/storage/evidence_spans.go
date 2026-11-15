// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"encoding/json"
	"sort"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
)

// Per-window consumption evidence (bundle version 2). See window.go for the windows themselves.

type winKey struct {
	group model.ID
	n     uint64
}

// controlView groups the reservations the control cut holds as consumed by the window their
// consumption cursor falls into. A reservation whose group has no window is left out: nothing in
// the data proves it.
func controlView(cut map[string]model.AdmissionReservation, spans map[model.ID]uint64) map[winKey][]ReservationEvidence {
	view := map[winKey][]ReservationEvidence{}
	for _, r := range cut {
		if r.State != "consumed" || r.Cursor == nil || r.Cursor.Index == 0 {
			continue
		}
		span := spans[r.Cursor.Group]
		if span == 0 {
			continue
		}
		k := winKey{r.Cursor.Group, (uint64(r.Cursor.Index) - 1) / span}
		view[k] = append(view[k], ReservationEvidence{ID: r.ID, Org: r.Org, Project: r.Project, Source: r.Source, Hash: r.Hash, Bytes: r.Bytes, Series: append([]string(nil), r.Series...), Cursor: *r.Cursor})
	}
	return view
}

// quotaEvidenceFor derives the consumption evidence of a set of 64 slot snapshots: version 2 when
// they are compact, version 1 (the whole history read from the envelopes) otherwise. With
// fromCommands the windows are re-derived from the command files themselves (restore); without it
// the window table the cut wrote is trusted (the cut has just derived it, and the replay check
// reads the tail windows' commands).
func quotaEvidenceFor(slots []replica.Snapshot, cut map[string]model.AdmissionReservation, fromCommands bool) (QuotaEvidence, error) {
	compact := 0
	for _, s := range slots {
		if _, ok, err := compactState(s); err != nil {
			return QuotaEvidence{}, err
		} else if ok {
			compact++
		}
	}
	switch compact {
	case 0:
		return quotaEvidence(slots)
	case len(slots):
		return quotaEvidenceWindowed(slots, cut, fromCommands)
	}
	return QuotaEvidence{}, model.Fail(model.Corrupt)
}

func quotaEvidenceWindowed(slots []replica.Snapshot, cut map[string]model.AdmissionReservation, fromCommands bool) (QuotaEvidence, error) {
	states := make([]slotSnapshotV2, len(slots))
	spans := map[model.ID]uint64{}
	for i, s := range slots {
		st, _, err := compactState(s)
		if err != nil {
			return QuotaEvidence{}, err
		}
		states[i] = st
		spans[s.Manifest.Group] = uint64(st.Span)
	}
	view := controlView(cut, spans)
	out := QuotaEvidence{Version: 2, Consumed: []ReservationEvidence{}, Cancelled: []CancellationEvidence{}}
	for i, s := range slots {
		group := s.Manifest.Group
		for _, w := range states[i].Windows {
			if fromCommands {
				b, err := newWindowBuilder(w.N, w.First, nil)
				if err != nil {
					return QuotaEvidence{}, err
				}
				if err = readWindowFile(s, w, func(_ uint64, raw []byte) error { return b.add(raw) }); err != nil {
					return QuotaEvidence{}, err
				}
				rec, _, err := b.finish()
				if err != nil || rec.windowRef != w {
					return QuotaEvidence{}, model.Fail(model.Corrupt)
				}
			}
			list := view[winKey{group, w.N}]
			detail := w.Redacted != 0 || chargeDigest(list) != w.Charge
			out.Windows = append(out.Windows, WindowEvidence{Group: group, N: w.N, First: w.First, Count: w.Count, Span: uint64(states[i].Span), Batches: w.Batches, Redacted: w.Redacted, Charge: w.Charge, Identity: w.Identity, Detail: detail})
			if !detail && w.Cancels == 0 {
				continue
			}
			sc, err := readSidecar(s, w)
			if err != nil {
				return QuotaEvidence{}, err
			}
			if detail {
				if chargeDigest(sc.Consumed) != w.Charge {
					return QuotaEvidence{}, model.Fail(model.Corrupt)
				}
				out.Consumed = append(out.Consumed, sc.Consumed...)
			}
			out.Cancelled = append(out.Cancelled, sc.Cancelled...)
		}
	}
	sort.Slice(out.Consumed, func(i, j int) bool { return bytes.Compare(out.Consumed[i].ID[:], out.Consumed[j].ID[:]) < 0 })
	sort.Slice(out.Cancelled, func(i, j int) bool { return bytes.Compare(out.Cancelled[i].ID[:], out.Cancelled[j].ID[:]) < 0 })
	out.Digest = out.seal()
	return out, nil
}

// resolve returns every consumed reservation the evidence proves. Version 1 lists them. In version
// 2 a Detail window's reservations are listed and every other window's are the ones the control
// cut holds as consumed in it, which the window's charge digest must equal exactly: a digest that
// does not match is corruption, never a reason to trust the cut's side of it.
func (q QuotaEvidence) resolve(cut map[string]model.AdmissionReservation) ([]ReservationEvidence, error) {
	if q.Version == 1 {
		return q.Consumed, nil
	}
	if q.Version != 2 {
		return nil, model.Fail(model.Corrupt)
	}
	spans := map[model.ID]uint64{}
	next := map[model.ID]uint64{}
	wins := make(map[winKey]WindowEvidence, len(q.Windows))
	for _, w := range q.Windows {
		if w.Span == 0 || w.Count == 0 || w.Count > w.Span || w.First != w.N*w.Span+1 || w.N != next[w.Group] || spans[w.Group] != 0 && spans[w.Group] != w.Span {
			return nil, model.Fail(model.Corrupt)
		}
		spans[w.Group], next[w.Group] = w.Span, w.N+1
		wins[winKey{w.Group, w.N}] = w
	}
	byWindow := map[winKey][]ReservationEvidence{}
	for _, c := range q.Consumed {
		span := spans[c.Cursor.Group]
		if span == 0 || c.Cursor.Index == 0 {
			return nil, model.Fail(model.Corrupt)
		}
		k := winKey{c.Cursor.Group, (uint64(c.Cursor.Index) - 1) / span}
		if w, ok := wins[k]; !ok || !w.Detail {
			return nil, model.Fail(model.Corrupt)
		}
		byWindow[k] = append(byWindow[k], c)
	}
	view := controlView(cut, spans)
	out := append([]ReservationEvidence(nil), q.Consumed...)
	for k, w := range wins {
		if w.Detail {
			if chargeDigest(byWindow[k]) != w.Charge {
				return nil, model.Fail(model.Corrupt)
			}
			continue
		}
		if chargeDigest(view[k]) != w.Charge {
			return nil, model.Fail(model.Corrupt)
		}
		out = append(out, view[k]...)
	}
	return out, nil
}

// ConsumedEvidence is every consumed reservation the bundle's evidence proves, in the form
// ReconcileQuota and the control-state reconciliation work from.
func (b BackupBundle) ConsumedEvidence() ([]ReservationEvidence, error) {
	return b.Quota.resolve(b.Cut.Reservations)
}

// evidenceDigests returns, for a slot snapshot in either form, the replay digest of every
// command above after (index -> digest) and the number of commands the snapshot holds. For a
// compact snapshot only the windows that reach above after are read, one command at a time.
func evidenceDigests(snapshot replica.Snapshot, after uint64) (map[uint64]model.Hash, uint64, error) {
	st, compact, err := compactState(snapshot)
	if err != nil {
		return nil, 0, err
	}
	digests := map[uint64]model.Hash{}
	if !compact {
		entries, err := slotEntries(snapshot)
		if err != nil {
			return nil, 0, err
		}
		for i, e := range entries {
			if uint64(i+1) <= after {
				continue
			}
			if digests[uint64(i+1)], err = evidenceDigest(e.entry); err != nil {
				return nil, 0, model.Fail(model.Corrupt)
			}
		}
		return digests, uint64(len(entries)), nil
	}
	for _, w := range st.Windows {
		if w.First+w.Count-1 <= after {
			continue
		}
		err := readWindowFile(snapshot, w, func(index uint64, raw []byte) error {
			if index <= after {
				return nil
			}
			var entry walEntry
			if json.Unmarshal(raw, &entry) != nil {
				return model.Fail(model.Corrupt)
			}
			d, err := evidenceDigest(entry)
			if err != nil {
				return model.Fail(model.Corrupt)
			}
			digests[index] = d
			return nil
		})
		if err != nil {
			return nil, 0, err
		}
	}
	return digests, uint64(st.Application), nil
}

// BatchReservations returns the full admission reservation of every batch a slot snapshot holds
// (either form). For a compact snapshot only is, when given, selects the windows to read by
// number: the reservations of batches admitted after the control cut are always in a Detail
// window.
func BatchReservations(snapshot replica.Snapshot, only func(n uint64) bool) (map[model.ID]model.AdmissionReservation, error) {
	out := map[model.ID]model.AdmissionReservation{}
	take := func(raw []byte) error {
		var entry walEntry
		if json.Unmarshal(raw, &entry) != nil {
			return model.Fail(model.Corrupt)
		}
		if entry.Type == "batch" && entry.Batch != nil {
			out[entry.Batch.Reservation.ID] = entry.Batch.Reservation
		}
		return nil
	}
	st, compact, err := compactState(snapshot)
	if err != nil {
		return nil, err
	}
	if !compact {
		entries, err := slotEntries(snapshot)
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if err = take(e.raw); err != nil {
				return nil, err
			}
		}
		return out, nil
	}
	for _, w := range st.Windows {
		if only != nil && !only(w.N) || w.Batches == 0 {
			continue
		}
		if err = readWindowFile(snapshot, w, func(_ uint64, raw []byte) error { return take(raw) }); err != nil {
			return nil, err
		}
	}
	return out, nil
}
