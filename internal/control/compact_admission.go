// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"encoding/json"

	"github.com/arynyklas/soundpost/internal/model"
)

// The compact admission ops (D104).
//
// An admission round (admission_group.go) proposes the records its transitions changed, one op for each. Measured at 5,000
// records/s (50 projects, 2,000 series each) the round was the ceiling of the cluster: 481 transitions, 1.84 MB, 3.8 KB per
// transition. What a batch writes is a few facts that the records spell out again and again: its reservation row names the
// series of the batch, and the same series are then written one op each under each of the three quota tiers (an op is
// ["Quotas", tier, "series", id] with the tier key of a hundred bytes and the series id of ninety-seven, around 270 bytes for
// the number one), the row's key is a function of the row, and finalizing the reservation writes the whole row again with the
// receipt's cursor added.
//
// Two ops say the same in what they carry and nothing more, both addressed [Reservations, id]:
//
//	rsv  the reservation row, and for each of its three quota tiers (quotaKeys, in that order) the count of each of its series
//	     once the round is applied, in the order of the row's Series. A voter writes the row, the key reservationKey(row) that
//	     names it, and the counts (a series new to the tier is counted in the tier's head), exactly the records the plain ops
//	     [Reservations, id], [AdmissionKeys, key] and [Quotas, tier, series, id] write: the counts are absolute (the value the
//	     round leaves), as the plain ops' are, so an op never depends on the order or the number of the ops around it.
//	fin  the cursor of the receipt: the reservation the voter holds under id becomes "consumed" at that cursor.
//
// A voter that does not know them stops applying the command, so they are proposed only once every member declared the protocol
// that knows them (storage.compactAdmissionProtocol, Store.SetCompactAdmissionGate) and the installation keeps its books in the
// ledger, which is where an admission round runs at all. Anywhere an op does not say exactly what the plain ops would (the row
// of the round was changed again after the reservation, a count the round does not leave, a key that names another row) the round
// writes the plain ops for it: the compact ops are an encoding of what a transition wrote, never a different decision
// (TestCompactAdmissionOpsLeaveTheLedgerThePlainOpsLeave pins that).
//
// An erasure pass that rewrites a retained command (redactPatch) reads the records of the command, so it is given the plain
// ops of a reservation (expandCompact); the cursor of a fin is a position in the data, not a record the pass erases.

// reserveOp is the value of an rsv op.
type reserveOp struct {
	Row    model.AdmissionReservation `json:"r"`
	Counts [3][]uint64                `json:"n"`
}

// compactCover is what the compact ops of a round write, so that the plain ops for the same records are left out.
type compactCover struct {
	keys   map[string]bool // admission keys
	series map[string]bool // seriesKey(tier, id)
}

// CompactAdmissionOps is how many rsv and fin ops the admission rounds of this store proposed.
func (s *Store) CompactAdmissionOps() (reserves, finalizes uint64) {
	return s.compactReserves.Load(), s.compactFinalizes.Load()
}

// CompactSettleOps is how many stl ops the rounds of this store proposed.
func (s *Store) CompactSettleOps() uint64 { return s.compactSettles.Load() }

// CompactRecordOps is how many rec ops (record_delta.go) the rounds of this store proposed.
func (s *Store) CompactRecordOps() uint64 { return s.compactRecords.Load() }

// noteCompact counts the compact ops of a round's patch.
func (s *Store) noteCompact(ops []patchOp) {
	var rsv, fin, stl, rec uint64
	for _, op := range ops {
		switch op.Op {
		case opReserve:
			rsv++
		case opFinalize:
			fin++
		case opSettle:
			stl++
		case opRecord:
			rec++
		}
	}
	s.compactReserves.Add(rsv)
	s.compactFinalizes.Add(fin)
	s.compactSettles.Add(stl)
	s.compactRecords.Add(rec)
}

// compactReservation is the compact op for the reservation row id that the round holds as r, when it says exactly what the plain
// ops for r would (ok); the records it implies are noted in cover. had says that the ledger holds old under id.
func (b *ledgerBooks) compactReservation(id string, old model.AdmissionReservation, had bool, r model.AdmissionReservation, cover *compactCover) (op patchOp, ok bool) {
	path := []string{"Reservations", id}
	if had {
		settled := old
		settled.State, settled.Cursor = "consumed", r.Cursor
		if r.State != "consumed" || r.Cursor == nil || old.Cursor != nil || !sameValue(settled, r) {
			return patchOp{}, false
		}
		return patchOp{Op: opFinalize, Path: path, Value: mustJSON(*r.Cursor)}, true
	}
	key := reservationKey(r)
	if k := b.keys[key]; k == nil || *k != id {
		return patchOp{}, false
	}
	var q reserveOp
	q.Row = r
	for i, tier := range quotaKeys(r) {
		q.Counts[i] = make([]uint64, len(r.Series))
		for j, series := range r.Series {
			n := b.sers[string(seriesKey(tier, series))]
			if n == 0 {
				return patchOp{}, false // a count the round does not leave (the series was released again, or never charged)
			}
			q.Counts[i][j] = n
		}
	}
	for _, tier := range quotaKeys(r) {
		for _, series := range r.Series {
			cover.series[string(seriesKey(tier, series))] = true
		}
	}
	cover.keys[key] = true
	return patchOp{Op: opReserve, Path: path, Value: mustJSON(q)}, true
}

// expandCompact is ops with every rsv op written as the plain ops it stands for; ops is returned as it is when it holds none.
// (The fin op needs the row the ledger holds and is kept.)
func expandCompact(ops []patchOp) ([]patchOp, error) {
	found := false
	for _, op := range ops {
		if op.Op == opReserve {
			found = true
			break
		}
	}
	if !found {
		return ops, nil
	}
	out := make([]patchOp, 0, len(ops)+8)
	for _, op := range ops {
		if op.Op != opReserve {
			out = append(out, op)
			continue
		}
		var q reserveOp
		if err := decodeValue(op.Value, &q); err != nil {
			return nil, err
		}
		if err := q.check(op.Path); err != nil {
			return nil, err
		}
		out = append(out,
			patchOp{Op: opSet, Path: []string{"Reservations", op.Path[1]}, Value: mustJSON(q.Row)},
			patchOp{Op: opSet, Path: []string{"AdmissionKeys", reservationKey(q.Row)}, Value: mustJSON(q.Row.ID.String())})
		for i, tier := range quotaKeys(q.Row) {
			for j, series := range q.Row.Series {
				out = append(out, patchOp{Op: opSet, Path: []string{"Quotas", tier, "series", series}, Value: mustJSON(q.Counts[i][j])})
			}
		}
	}
	sortOps(out)
	return out, nil
}

// check is whether the op at path says what a proposer writes: the row's own id, and a count for each series of each tier.
func (q reserveOp) check(path []string) error {
	if len(path) != 2 || path[0] != "Reservations" || path[1] != q.Row.ID.String() {
		return model.Fail(model.Corrupt)
	}
	for i := range q.Counts {
		if len(q.Counts[i]) != len(q.Row.Series) {
			return model.Fail(model.Corrupt)
		}
		for _, n := range q.Counts[i] {
			if n == 0 {
				return model.Fail(model.Corrupt)
			}
		}
	}
	return nil
}

// reserve applies an rsv op.
func (a *opApplier) reserve(op patchOp) error {
	var q reserveOp
	if err := decodeValue(op.Value, &q); err != nil {
		return err
	}
	if err := q.check(op.Path); err != nil {
		return err
	}
	raw, err := json.Marshal(q.Row)
	if err != nil {
		return model.Fail(model.Corrupt)
	}
	id := q.Row.ID.String()
	if err = a.l.put(tableReservations, []byte(id), raw); err != nil {
		return err
	}
	if err = a.l.put(tableKeys, []byte(reservationKey(q.Row)), []byte(id)); err != nil {
		return err
	}
	for i, tier := range quotaKeys(q.Row) {
		for j, series := range q.Row.Series {
			if err = a.setSeriesCount(tier, series, q.Counts[i][j]); err != nil {
				return err
			}
		}
	}
	return nil
}

// finalize applies a fin op. A reservation the voter does not hold is left alone: a voter that replays a command an erasure pass
// rewrote reaches it with the row the pass dropped (the same records a plain write would find it without), and the reservation
// it settles is erased with it.
func (a *opApplier) finalize(op patchOp) error {
	var c model.Cursor
	if err := decodeValue(op.Value, &c); err != nil {
		return err
	}
	if len(op.Path) != 2 || op.Path[0] != "Reservations" {
		return model.Fail(model.Corrupt)
	}
	r, ok, err := a.l.reservation(op.Path[1])
	if err != nil || !ok {
		return err
	}
	r.State, r.Cursor = "consumed", &c
	raw, err := json.Marshal(r)
	if err != nil {
		return model.Fail(model.Corrupt)
	}
	return a.l.put(tableReservations, []byte(op.Path[1]), raw)
}

// setSeriesCount writes the count n (not zero) of a series under a quota tier, and counts the series in the tier's head when the
// tier did not hold it.
func (a *opApplier) setSeriesCount(tier, id string, n uint64) error {
	hs, err := a.head(tier)
	if err != nil {
		return err
	}
	hs.exists = true
	key := seriesKey(tier, id)
	had := a.l.t[tableSeries].Get(key) != nil
	if err = a.l.put(tableSeries, key, u64(n)); err != nil {
		return err
	}
	if !had {
		hs.h.Series++
	}
	return nil
}

// verifyReserve is verifyOp of an rsv op: the ledger holds the row, its key and the counts.
func (l *ledgerTx) verifyReserve(op patchOp) error {
	bad := model.Fail(model.Corrupt)
	var q reserveOp
	if err := decodeValue(op.Value, &q); err != nil {
		return err
	}
	if err := q.check(op.Path); err != nil {
		return err
	}
	stored, ok, err := l.reservation(op.Path[1])
	if err != nil {
		return err
	}
	if !ok || !sameValue(stored, q.Row) {
		return bad
	}
	if id, ok := l.keyed(reservationKey(q.Row)); !ok || id != op.Path[1] {
		return bad
	}
	for i, tier := range quotaKeys(q.Row) {
		for j, series := range q.Row.Series {
			if l.series(tier, series) != q.Counts[i][j] {
				return bad
			}
		}
	}
	return nil
}

// verifyFinalize is verifyOp of a fin op: the ledger holds the reservation consumed at the cursor.
func (l *ledgerTx) verifyFinalize(op patchOp) error {
	var c model.Cursor
	if err := decodeValue(op.Value, &c); err != nil {
		return err
	}
	if len(op.Path) != 2 || op.Path[0] != "Reservations" {
		return model.Fail(model.Corrupt)
	}
	r, ok, err := l.reservation(op.Path[1])
	if err != nil {
		return err
	}
	if !ok || r.State != "consumed" || r.Cursor == nil || *r.Cursor != c {
		return model.Fail(model.Corrupt)
	}
	return nil
}
