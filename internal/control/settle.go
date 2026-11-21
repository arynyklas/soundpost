// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"context"
	"errors"
	"sort"

	"github.com/arynyklas/soundpost/internal/model"
)

// Settlement of consumed admission reservations (01.07-W1 residue, lane 1 wave 7).
//
// A consumed reservation is never refunded and the data holds the batch that consumed it with
// its whole reservation, yet control kept every one of them as a row (the reservation, its
// AdmissionKeys entry and its series list) for as long as the installation lives. The rows are
// part of the state each control command re-reads and re-proposes, of every control snapshot and
// of the control cut a backup seals, so they made all three grow with the number of batches ever
// admitted. SettleAdmissions bounds them: when the storage engine offers a sealed data window
// (model.SettleCandidate: the digest of the reservations its batches consumed) and the
// reservations control holds for that window digest to exactly the same value, control drops
// those rows and keeps one model.SettledWindow (the digest and the count) plus, folded into
// Settlement.Charges, the charge the rows put on each quota key. Nothing a quota decision reads
// changes (Quotas is not touched), and a backup proves the folded charge against the data
// windows themselves (storage.ReconcileQuota, InstallBackup).
//
// What settling gives up: the row that answered a retry of the batch. A retry of a settled
// batch finds no AdmissionKeys entry, so ReserveAdmission asks the installed owner whether the
// batch is in the data (receipt for the same key and hash) and answers it as already consumed
// (settledRetry), which is the answer the row gave; the data's own duplicate check then returns
// the stored receipt. A window that carries a redacted batch is never offered, and cancelled
// reservations keep their rows (they are bounded by the cancellations the data holds fences for).

// settleWindowsPerCommand bounds the windows one SettleAdmissions command settles, so a pass over
// a large backlog is several small proposals, not one.
const settleWindowsPerCommand = 256

// SettleReport is what one SettleAdmissions call settled.
type SettleReport struct {
	Windows      int // windows whose rows were replaced by a settled window
	Reservations int // consumed reservation rows dropped
}

func (r SettleReport) none() bool { return r == SettleReport{} }

type settledWindowPlan struct {
	candidate model.SettleCandidate
	rows      []model.AdmissionReservation
}

// planSettlement decides, without changing st, which candidate windows can be settled now: the
// window is not settled yet, its span matches the group's, control holds exactly the consumed
// reservations whose charge digest the candidate carries, and every one of them is still
// reachable through its AdmissionKeys entry.
func planSettlement(st *State, candidates []model.SettleCandidate) []settledWindowPlan {
	spans := map[string]uint64{}
	if st.Settlement != nil {
		for group, span := range st.Settlement.Spans {
			spans[group] = span
		}
	}
	wanted := map[string]model.SettleCandidate{}
	groupSpan := map[model.ID]uint64{}
	for _, c := range candidates {
		if c.Span == 0 || c.Batches == 0 || c.Batches > c.Span {
			continue
		}
		if known := spans[c.Group.String()]; known != 0 && known != c.Span {
			continue
		}
		if span, ok := groupSpan[c.Group]; ok && span != c.Span {
			continue
		}
		key := model.SettledKey(c.Group, c.N)
		if st.Settlement != nil {
			if _, done := st.Settlement.Windows[key]; done {
				continue
			}
		}
		groupSpan[c.Group] = c.Span
		wanted[key] = c
	}
	if len(wanted) == 0 {
		return nil
	}
	rows := map[string][]model.AdmissionReservation{}
	for _, r := range st.Reservations {
		if r.State != "consumed" || r.Cursor == nil || r.Cursor.Index == 0 {
			continue
		}
		span := groupSpan[r.Cursor.Group]
		if span == 0 {
			continue
		}
		key := model.SettledKey(r.Cursor.Group, (uint64(r.Cursor.Index)-1)/span)
		if _, ok := wanted[key]; ok {
			rows[key] = append(rows[key], r)
		}
	}
	keys := make([]string, 0, len(wanted))
	for key := range wanted {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var out []settledWindowPlan
	for _, key := range keys {
		c, held := wanted[key], rows[key]
		if uint64(len(held)) != c.Batches {
			continue
		}
		items := make([]model.ChargeItem, len(held))
		reachable := true
		for i, r := range held {
			items[i] = model.ChargeOf(r)
			if st.AdmissionKeys[reservationKey(r)] != r.ID.String() {
				reachable = false
			}
		}
		if !reachable || model.ChargeDigest(items) != c.Charge {
			continue
		}
		out = append(out, settledWindowPlan{candidate: c, rows: held})
		if len(out) == settleWindowsPerCommand {
			break
		}
	}
	return out
}

// applySettlement drops the planned rows from st and folds their charge into Settlement.
func applySettlement(st *State, plan []settledWindowPlan) SettleReport {
	var rep SettleReport
	if len(plan) == 0 {
		return rep
	}
	if st.Settlement == nil {
		st.Settlement = &model.Settlement{}
	}
	s := st.Settlement
	if s.Spans == nil {
		s.Spans = map[string]uint64{}
	}
	if s.Windows == nil {
		s.Windows = map[string]model.SettledWindow{}
	}
	if s.Charges == nil {
		s.Charges = map[string]model.SettledCharge{}
	}
	for _, w := range plan {
		c := w.candidate
		s.Spans[c.Group.String()] = c.Span
		s.Windows[model.SettledKey(c.Group, c.N)] = model.SettledWindow{Group: c.Group, N: c.N, Span: c.Span, Count: uint64(len(w.rows)), Charge: c.Charge}
		for _, r := range w.rows {
			for _, key := range quotaKeys(r) {
				charge := s.Charges[key]
				if charge.Series == nil {
					charge.Series = map[string]uint64{}
				}
				charge.Bytes += r.Bytes
				for _, id := range r.Series {
					charge.Series[id]++
				}
				s.Charges[key] = charge
			}
			delete(st.Reservations, r.ID.String())
			delete(st.AdmissionKeys, reservationKey(r))
			rep.Reservations++
		}
		rep.Windows++
	}
	return rep
}

// SettleAdmissions settles the offered windows control can prove equal to its own rows (see the
// file comment). It reads first and commits nothing when no window is settleable, so an idle
// installation pays one linearizable read. The commit leaves AuthorityRevision alone
// (writerSettleAdmissions): it moves consumed bookkeeping between two representations and
// changes no quota, grant or policy.
func (s *Store) SettleAdmissions(ctx context.Context, candidates []model.SettleCandidate) (SettleReport, error) {
	if len(candidates) == 0 {
		return SettleReport{}, nil
	}
	var plan []settledWindowPlan
	if err := s.View(ctx, func(st State) error { plan = planSettlement(&st, candidates); return nil }); err != nil {
		return SettleReport{}, err
	}
	if len(plan) == 0 {
		return SettleReport{}, nil
	}
	var out SettleReport
	err := s.updateAs(ctx, writerSettleAdmissions, func(st *State) error {
		out = applySettlement(st, planSettlement(st, candidates))
		if out.none() {
			return errNothingToSettle // another voter's pass settled them first: commit nothing
		}
		return nil
	})
	if errors.Is(err, errNothingToSettle) {
		return SettleReport{}, nil
	}
	return out, err
}

// admittedBatches is implemented by the installed owner (the storage engine): it answers whether
// the data holds the batch a reservation names, with the receipt it stored. ReserveAdmission asks
// it for a batch control has no AdmissionKeys entry for once windows were settled.
type admittedBatches interface {
	AdmittedBatch(context.Context, model.AdmissionReservation) (model.Receipt, bool, error)
}

// errNeedsAdmittedLookup aborts a ReserveAdmission update that found no row for its key in a
// state that has settled windows: the retry may be one of a settled batch, which only the owner's
// receipts can tell. The caller asks the owner and runs the update again.
var errNeedsAdmittedLookup = errors.New("control: settled windows, owner lookup needed")
