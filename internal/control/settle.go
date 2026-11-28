// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"sync/atomic"

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

// Settling in parts. A window settles only once the data seals it, 4096 commands per group, and at
// 64 groups and a few hundred acknowledged batches a second that is minutes in which every admitted batch
// stays a row of the control state: the rows pile up to a quarter of a million and each control command
// pays for them. So a window is also settled while it is open, a part (a few dozen commands) at a time,
// by exactly the proof a whole window gets: the data states the digest of the reservations a part consumed
// (model.SettlePart), control holds exactly those rows, and drops them. A window settled in parts is an
// incomplete model.SettledWindow (Part and Parts, no digest of its own) that costs one record per window
// the group has open; when the data seals the window it offers it whole with the digest of every part,
// control checks the parts it settled against them, settles the parts it still holds the rows of and
// replaces the record with the complete one. The persisted span of a group (Spans) is the span of its
// windows and is not touched: windows settled whole by an earlier release stay valid beside the parts
// of the windows that follow them.

// settleWindowsPerCommand bounds the windows one SettleAdmissions command settles (or advances), so a pass
// over a large backlog is several small proposals, not one.
const settleWindowsPerCommand = 256

// settleRowsPerCommand bounds the reservations one settle command drops. The command is applied under the lock
// every control writer shares and rewrites the charge rows (a row per quota key and series) of each reservation it
// drops, so its cost grows with the rows it carries: three thousand rows in one command held the control group
// for most of a second and the acknowledgements queued behind it (L2w20Admission18). 256 rows were still a
// round of 80 ms beside the acknowledgements' rounds of 8 ms; a pass settles a backlog with commands of a few
// milliseconds, which ride in the rounds of the acknowledgements. A window settled whole is one unit (its rows
// prove one digest) and is taken alone when it exceeds the bound; such windows predate settling in parts.
const settleRowsPerCommand = 64

// SettleReport is what one SettleAdmissions call settled.
type SettleReport struct {
	Windows      int // windows whose rows were replaced by a complete settled window
	Parts        int // parts of windows (open, or sealed and not yet complete) whose rows were dropped
	Reservations int // consumed reservation rows dropped
}

func (r SettleReport) none() bool { return r == SettleReport{} }

type settledWindowPlan struct {
	key       string
	candidate model.SettleCandidate
	rows      []model.AdmissionReservation
	record    model.SettledWindow // what the window is after the plan
	parts     int                 // parts whose rows the plan drops (0 for a window settled whole)
	added     []model.SettledPart // the parts the plan adds to the record (none for a window settled whole)
}

// settleCandidateValid refuses a candidate whose own fields contradict each other: it is the data's
// statement, and one that cannot be true is not acted on.
func settleCandidateValid(c model.SettleCandidate) bool {
	if c.Span == 0 {
		return false
	}
	if c.Part != 0 {
		if c.Part >= c.Span || c.Span%c.Part != 0 {
			return false
		}
		var sum uint64
		for i, p := range c.Parts {
			if uint64(p.J) >= c.Span/c.Part || i > 0 && p.J <= c.Parts[i-1].J || p.Batches == 0 || p.Batches > c.Part {
				return false
			}
			sum += p.Batches
		}
		if c.Open {
			return len(c.Parts) != 0
		}
		if len(c.Parts) != 0 && sum != c.Batches {
			return false
		}
	} else if c.Open || len(c.Parts) != 0 {
		return false
	}
	return c.Open || c.Batches != 0 && c.Batches <= c.Span
}

// settleRows is the consumed reservation rows of the windows a settlement wants, by settled window key.
type settleRows map[string][]model.AdmissionReservation

// planSettlement decides, without changing the books, which candidates can be settled now. A window that
// is not settled yet, whose span matches the group's, is settled whole when control holds exactly the
// consumed reservations whose charge digest the candidate carries and every one of them is still
// reachable through its AdmissionKeys entry. A window that is open or already settled in parts is settled
// part by part: each part whose rows control holds exactly as the data's digest of it states is dropped,
// every part control settled before must be the one the data states, and a sealed window with every part
// settled becomes a complete record.
//
// It plans on the rows given in reuse, or on the rows it reads when reuse is nil: finding the rows of a window
// means reading the whole reservation table, which a pass does once (SettleAdmissions) and counts in scanned.
// It returns the rows it read, for the commands of the pass.
func planSettlement(books admissionBooks, candidates []model.SettleCandidate, reuse settleRows, scanned *atomic.Uint64) ([]settledWindowPlan, settleRows, error) {
	type want struct {
		c        model.SettleCandidate
		existing model.SettledWindow
		partial  bool
	}
	wanted := map[string]*want{}
	groupSpan := map[model.ID]uint64{}
	for _, c := range candidates {
		if !settleCandidateValid(c) {
			continue
		}
		if known := books.span(c.Group.String()); known != 0 && known != c.Span {
			continue
		}
		if span, ok := groupSpan[c.Group]; ok && span != c.Span {
			continue
		}
		key := model.SettledKey(c.Group, c.N)
		existing, found, err := books.window(key)
		if err != nil {
			return nil, nil, err
		}
		if found && existing.Complete() {
			continue
		}
		if found && (existing.Span != c.Span || existing.Part != c.Part) || (c.Open || found) && c.Part == 0 {
			continue
		}
		groupSpan[c.Group] = c.Span
		wanted[key] = &want{c: c, existing: existing, partial: found}
	}
	if len(wanted) == 0 {
		return nil, nil, nil
	}
	rows := reuse
	if rows == nil {
		rows = settleRows{}
		if err := books.eachReservation(func(r model.AdmissionReservation) bool {
			scanned.Add(1)
			if r.State != "consumed" || r.Cursor == nil || r.Cursor.Index == 0 {
				return true
			}
			span := groupSpan[r.Cursor.Group]
			if span == 0 {
				return true
			}
			key := model.SettledKey(r.Cursor.Group, (uint64(r.Cursor.Index)-1)/span)
			if _, ok := wanted[key]; ok {
				rows[key] = append(rows[key], r)
			}
			return true
		}); err != nil {
			return nil, nil, err
		}
	}
	// proves reports whether control holds exactly the rows a digest states, every one reachable.
	proves := func(held []model.AdmissionReservation, batches uint64, charge model.Hash) bool {
		if uint64(len(held)) != batches {
			return false
		}
		items := make([]model.ChargeItem, len(held))
		for i, r := range held {
			items[i] = model.ChargeOf(r)
			if id, _ := books.keyed(reservationKey(r)); id != r.ID.String() {
				return false
			}
		}
		return model.ChargeDigest(items) == charge
	}
	keys := make([]string, 0, len(wanted))
	for key := range wanted {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var out []settledWindowPlan
	planned := 0 // reservations the plan drops
	for _, key := range keys {
		w := wanted[key]
		c, held := w.c, rows[key]
		if !c.Open && !w.partial {
			if len(out) != 0 && planned+len(held) > settleRowsPerCommand {
				continue // a window settled whole is taken alone when it exceeds the bound: a smaller one may still fit
			}
			if !proves(held, c.Batches, c.Charge) {
				continue
			}
			out = append(out, settledWindowPlan{key: key, candidate: c, rows: held, record: model.SettledWindow{Group: c.Group, N: c.N, Span: c.Span, Count: uint64(len(held)), Charge: c.Charge}})
			planned += len(held)
		} else if plan, ok := planParts(key, c, w.existing, w.partial, held, settleRowsPerCommand-planned, proves); ok {
			out = append(out, plan)
			planned += len(plan.rows)
		} else {
			continue
		}
		if len(out) == settleWindowsPerCommand || planned >= settleRowsPerCommand {
			break
		}
	}
	return out, rows, nil
}

// planParts plans the parts of one window that is open or settled in parts already (see planSettlement).
func planParts(key string, c model.SettleCandidate, existing model.SettledWindow, partial bool, held []model.AdmissionReservation, budget int, proves func([]model.AdmissionReservation, uint64, model.Hash) bool) (settledWindowPlan, bool) {
	record := model.SettledWindow{Group: c.Group, N: c.N, Span: c.Span, Part: c.Part}
	if partial {
		record.Count = existing.Count
		record.Parts = append([]model.SettledPart(nil), existing.Parts...)
	}
	// Every part settled before must be the data's, and a sealed window must not have lost a part the
	// record holds: anything else is a window the data does not describe the way control settled it.
	stated := map[uint32]model.SettlePart{}
	for _, p := range c.Parts {
		stated[p.J] = p
	}
	for _, p := range existing.Parts {
		if s, ok := stated[p.J]; ok && (s.Batches != p.Count || s.Charge != p.Charge) || !ok && !c.Open {
			return settledWindowPlan{}, false
		}
	}
	byPart := map[uint32][]model.AdmissionReservation{}
	for _, r := range held {
		j := model.PartOf(uint64(r.Cursor.Index), c.Span, c.Part)
		byPart[j] = append(byPart[j], r)
	}
	plan := settledWindowPlan{key: key, candidate: c}
	proven := true
	for _, p := range c.Parts {
		if _, done := existing.Settled(p.J); done {
			continue
		}
		rows := byPart[p.J]
		if plan.parts != 0 && len(plan.rows)+len(rows) > budget {
			proven = false // the parts left are settled by a later command
			break
		}
		if !proves(rows, p.Batches, p.Charge) {
			proven = false
			continue
		}
		record.Parts = append(record.Parts, model.SettledPart{J: p.J, Count: uint64(len(rows)), Charge: p.Charge})
		plan.added = append(plan.added, model.SettledPart{J: p.J, Count: uint64(len(rows)), Charge: p.Charge})
		record.Count += uint64(len(rows))
		plan.rows = append(plan.rows, rows...)
		plan.parts++
	}
	sort.Slice(record.Parts, func(i, j int) bool { return record.Parts[i].J < record.Parts[j].J })
	if !c.Open && proven {
		// Every part the data states is settled: the window is complete, with the digest of the data's own.
		if record.Count != c.Batches {
			return settledWindowPlan{}, false
		}
		record = model.SettledWindow{Group: c.Group, N: c.N, Span: c.Span, Count: c.Batches, Charge: c.Charge}
	} else if plan.parts == 0 {
		return settledWindowPlan{}, false
	}
	plan.record = record
	return plan, true
}

// settleDeriver is the books of a round whose group applies the stl op: a settlement is handed over as it is planned, and the
// books answer whether the voters derive its charge (the round then writes the rows' deletes and the window, not the charge).
type settleDeriver interface {
	deriveSettlement(w settledWindowPlan) bool
}

// applySettlement drops the planned rows, folds their charge into the settlement and stores the records.
func applySettlement(books admissionBooks, plan []settledWindowPlan) SettleReport {
	var rep SettleReport
	for _, w := range plan {
		c := w.candidate
		books.setSpan(c.Group.String(), c.Span)
		books.putWindow(w.key, w.record)
		if d, ok := books.(settleDeriver); ok && d.deriveSettlement(w) {
			// The voters derive the charge from the rows they hold (compact_settle.go): the round neither reads nor writes a
			// series record for it. The rows and their keys are gone for the transitions that follow in the round.
			for _, r := range w.rows {
				books.delReservation(r.ID.String())
				books.delKey(reservationKey(r))
				rep.Reservations++
			}
		} else {
			for _, r := range w.rows {
				for _, tier := range quotaKeys(r) {
					books.setCharge(tier, books.charge(tier)+uint64(r.Bytes))
					for _, id := range r.Series {
						books.setChargeSeries(tier, id, books.chargeSeries(tier, id)+1)
					}
				}
				books.delReservation(r.ID.String())
				books.delKey(reservationKey(r))
				rep.Reservations++
			}
		}
		rep.Parts += w.parts
		if w.record.Complete() {
			rep.Windows++
		}
	}
	return rep
}

// SettledWindows returns the settled window records stored under keys (model.SettledKey), those that
// exist. The storage engine asks it which windows it still has to offer.
func (s *Store) SettledWindows(ctx context.Context, keys []string) (map[string]model.SettledWindow, error) {
	out := make(map[string]model.SettledWindow, len(keys))
	err := s.viewBooks(ctx, func(books admissionBooks) error {
		for _, key := range keys {
			w, ok, err := books.window(key)
			if err != nil {
				return err
			}
			if ok {
				out[key] = w
			}
		}
		return nil
	})
	return out, err
}

// settleRowsHeld reports whether control still holds every row the plan drops exactly as the plan read it: a
// command of a pass plans on the rows the pass read once, and drops them only while they are the rows control holds.
func settleRowsHeld(books admissionBooks, plan []settledWindowPlan) (bool, error) {
	for _, w := range plan {
		for _, r := range w.rows {
			live, ok, err := books.reservation(r.ID.String())
			if err != nil {
				return false, err
			}
			if !ok || !reflect.DeepEqual(live, r) {
				return false, nil
			}
		}
	}
	return true, nil
}

// SettleAdmissions settles the offered windows control can prove equal to its own rows (see the
// file comment). It reads first and commits nothing when no window is settleable, so an idle
// installation pays one linearizable read. The reservation table is read once, here, outside the lock the
// control writers share, and the call settles what it found with commands of at most settleRowsPerCommand
// rows each: a command looks up the rows it drops (the books may have moved since the read, and a row that
// is not as the pass read it ends the pass: the next one reads again) and never scans the table, so what a
// command costs the writers that wait is a function of its rows and not of the rows control holds. The
// commit leaves AuthorityRevision alone (writerSettleAdmissions): it moves consumed bookkeeping between
// two representations and changes no quota, grant or policy.
func (s *Store) SettleAdmissions(ctx context.Context, candidates []model.SettleCandidate) (SettleReport, error) {
	if len(candidates) == 0 {
		return SettleReport{}, nil
	}
	if rep, handled, err := s.settleAtLeader(ctx, candidates); handled {
		return rep, err
	}
	var plan []settledWindowPlan
	var rows settleRows
	if err := s.viewBooks(ctx, func(books admissionBooks) (err error) {
		plan, rows, err = planSettlement(books, candidates, nil, &s.settleScanRows)
		return
	}); err != nil {
		return SettleReport{}, err
	}
	var total SettleReport
	for len(plan) != 0 {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		var out SettleReport
		err := s.admissionUpdate(ctx, writerSettleAdmissions, func(_ *State, books admissionBooks) error {
			again, _, err := planSettlement(books, candidates, rows, &s.settleScanRows)
			if err != nil {
				return err
			}
			if held, err := settleRowsHeld(books, again); err != nil {
				return err
			} else if !held {
				return errNothingToSettle // the books moved since the pass read them: the next pass reads again
			}
			if out = applySettlement(books, again); out.none() {
				return errNothingToSettle // another voter's pass settled them first, or nothing is left: commit nothing
			}
			return nil
		})
		if errors.Is(err, errNothingToSettle) {
			break
		}
		if err != nil {
			return total, err
		}
		total.Windows += out.Windows
		total.Parts += out.Parts
		total.Reservations += out.Reservations
	}
	return total, nil
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
