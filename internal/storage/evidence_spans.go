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
func quotaEvidenceFor(slots []replica.Snapshot, cut ControlCut, fromCommands bool) (QuotaEvidence, error) {
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

func quotaEvidenceWindowed(slots []replica.Snapshot, cut ControlCut, fromCommands bool) (QuotaEvidence, error) {
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
	view := controlView(cut.Reservations, spans)
	settled := cut.Settlement
	// A settled window's reservations are no longer rows of the control cut: the window's own
	// charge digest must equal the digest control settled it with, and, when the windows are
	// re-derived from the command files (restore), what the sidecars of every settled window
	// charge must add up to exactly the charge control folded (QuotaEvidence cannot list them,
	// that is the point of settling).
	var sums map[string]model.SettledCharge
	if fromCommands && settled != nil {
		sums = map[string]model.SettledCharge{}
	}
	seen := map[string]bool{}
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
			key := model.SettledKey(group, w.N)
			sw, isSettled := settled.Lookup(key)
			var detail bool
			if isSettled {
				if sw.Span != uint64(states[i].Span) || sw.Charge != w.Charge || sw.Count != w.Batches {
					return QuotaEvidence{}, model.Fail(model.Corrupt)
				}
				seen[key] = true
				detail = w.Redacted != 0
			} else {
				detail = w.Redacted != 0 || chargeDigest(view[winKey{group, w.N}]) != w.Charge
			}
			out.Windows = append(out.Windows, WindowEvidence{Group: group, N: w.N, First: w.First, Count: w.Count, Span: uint64(states[i].Span), Batches: w.Batches, Redacted: w.Redacted, Charge: w.Charge, Identity: w.Identity, Detail: detail})
			needSidecar := detail || w.Cancels != 0 || isSettled && sums != nil
			if !needSidecar {
				continue
			}
			sc, err := readSidecar(s, w)
			if err != nil {
				return QuotaEvidence{}, err
			}
			if detail || isSettled && sums != nil {
				if chargeDigest(sc.Consumed) != w.Charge {
					return QuotaEvidence{}, model.Fail(model.Corrupt)
				}
			}
			if isSettled && sums != nil {
				addCharges(sums, sc.Consumed)
			}
			if detail {
				out.Consumed = append(out.Consumed, sc.Consumed...)
			}
			out.Cancelled = append(out.Cancelled, sc.Cancelled...)
		}
	}
	if settled != nil {
		for key := range settled.Windows {
			if !seen[key] {
				return QuotaEvidence{}, model.Fail(model.Corrupt) // a settled window the data does not hold
			}
		}
		if sums != nil && !equalSettledCharges(sums, settled.Charges) {
			return QuotaEvidence{}, model.Fail(model.Corrupt) // control folded another charge than the data windows carry
		}
	}
	sort.Slice(out.Consumed, func(i, j int) bool { return bytes.Compare(out.Consumed[i].ID[:], out.Consumed[j].ID[:]) < 0 })
	sort.Slice(out.Cancelled, func(i, j int) bool { return bytes.Compare(out.Cancelled[i].ID[:], out.Cancelled[j].ID[:]) < 0 })
	out.Digest = out.seal()
	return out, nil
}

// addCharges adds what the consumed reservations charge on every quota key they touch.
func addCharges(sums map[string]model.SettledCharge, consumed []ReservationEvidence) {
	for _, c := range consumed {
		for _, key := range quotaKeys(c.Org, c.Project, c.Source) {
			s := sums[key]
			if s.Series == nil {
				s.Series = map[string]uint64{}
			}
			s.Bytes += c.Bytes
			for _, id := range c.Series {
				s.Series[id]++
			}
			sums[key] = s
		}
	}
}

// equalSettledCharges reports whether two charge tables are identical (an absent key and a key
// with no bytes and no series are different tables: both sides are built from reservations).
func equalSettledCharges(a, b map[string]model.SettledCharge) bool {
	if len(a) != len(b) {
		return false
	}
	for key, x := range a {
		y, ok := b[key]
		if !ok || x.Bytes != y.Bytes || len(x.Series) != len(y.Series) {
			return false
		}
		for id, n := range x.Series {
			if y.Series[id] != n {
				return false
			}
		}
	}
	return true
}

// resolve returns every consumed reservation the evidence proves. Version 1 lists them. In version
// 2 a Detail window's reservations are listed and every other window's are the ones the control
// cut holds as consumed in it, which the window's charge digest must equal exactly: a digest that
// does not match is corruption, never a reason to trust the cut's side of it. A window control
// settled holds no rows in the cut: its charge digest must equal the digest control settled it
// with, and it contributes the reservations of its Detail listing only (a window redacted since).
func (q QuotaEvidence) resolve(cut ControlCut) ([]ReservationEvidence, error) {
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
	if cut.Settlement != nil {
		for key, sw := range cut.Settlement.Windows {
			w, ok := wins[winKey{sw.Group, sw.N}]
			if !ok || key != model.SettledKey(sw.Group, sw.N) || sw.Span != w.Span || sw.Charge != w.Charge || sw.Count != w.Batches {
				return nil, model.Fail(model.Corrupt)
			}
		}
	}
	view := controlView(cut.Reservations, spans)
	out := append([]ReservationEvidence(nil), q.Consumed...)
	for k, w := range wins {
		if w.Detail {
			if chargeDigest(byWindow[k]) != w.Charge {
				return nil, model.Fail(model.Corrupt)
			}
			continue
		}
		if _, settled := cut.Settlement.Lookup(model.SettledKey(k.group, k.n)); settled {
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
// ReconcileQuota and the control-state reconciliation work from. The reservations of a settled
// window are not among them unless the window is a Detail window (see resolve): their charge is
// the cut's Settlement.Charges.
func (b BackupBundle) ConsumedEvidence() ([]ReservationEvidence, error) {
	return b.Quota.resolve(b.Cut)
}

// evidenceDigests returns, for a slot snapshot in either form, the replay digest of every
// command above after (index -> digest) and the number of commands the snapshot holds. For a
// compact snapshot only the windows that reach above after are read, one command at a time.
func evidenceDigests(snapshot replica.Snapshot, after uint64) (map[uint64]model.Hash, uint64, error) {
	digests, _, total, err := evidenceDigestsAndRejections(snapshot, after)
	return digests, total, err
}

// evidenceDigestsAndRejections is evidenceDigests that also names, for every command above after
// that the machine rejected at apply and stored as a `rejected` stub, the id of the replicated entry
// it rejected (index -> entry id). The stub is not the command it stands for, so the journal form of
// that command has another digest: the seal asks which indexes these are (replayIntervals).
func evidenceDigestsAndRejections(snapshot replica.Snapshot, after uint64) (map[uint64]model.Hash, map[uint64]model.ID, uint64, error) {
	st, compact, err := compactState(snapshot)
	if err != nil {
		return nil, nil, 0, err
	}
	digests, rejected := map[uint64]model.Hash{}, map[uint64]model.ID{}
	take := func(index uint64, entry walEntry) error {
		d, err := evidenceDigest(entry)
		if err != nil {
			return model.Fail(model.Corrupt)
		}
		digests[index] = d
		if entry.Type == "rejected" && entry.Rejection != nil {
			rejected[index] = *entry.Rejection
		}
		return nil
	}
	if !compact {
		entries, err := slotEntries(snapshot)
		if err != nil {
			return nil, nil, 0, err
		}
		for i, e := range entries {
			if uint64(i+1) <= after {
				continue
			}
			if err = take(uint64(i+1), e.entry); err != nil {
				return nil, nil, 0, err
			}
		}
		return digests, rejected, uint64(len(entries)), nil
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
			return take(index, entry)
		})
		if err != nil {
			return nil, nil, 0, err
		}
	}
	return digests, rejected, uint64(st.Application), nil
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

// settledMatchesEvidence reports whether a version 1 evidence (every consumed reservation listed)
// holds exactly the reservations control settled: per settled window the digest and the count, and
// over all of them the folded charge.
func settledMatchesEvidence(s *model.Settlement, evidence []ReservationEvidence) bool {
	byWindow := map[string][]ReservationEvidence{}
	var all []ReservationEvidence
	for _, c := range evidence {
		if w, ok := s.Window(c.Cursor); ok {
			key := model.SettledKey(w.Group, w.N)
			byWindow[key] = append(byWindow[key], c)
			all = append(all, c)
		}
	}
	for key, w := range s.Windows {
		list := byWindow[key]
		if uint64(len(list)) != w.Count || chargeDigest(list) != w.Charge {
			return false
		}
	}
	sums := map[string]model.SettledCharge{}
	addCharges(sums, all)
	return equalSettledCharges(sums, s.Charges)
}
