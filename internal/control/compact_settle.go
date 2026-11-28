// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"encoding/json"
	"sort"

	"github.com/arynyklas/soundpost/internal/model"
)

// The derived settlement op (D104, with the compact admission ops of compact_admission.go; ControlLane round 3).
//
// A settlement command (settle.go) drops the consumed reservations of sealed data windows or of parts of open ones, keeps one
// SettledWindow record for each window and folds the charge of the rows into the settlement: for each of the three quota tiers
// of a row, one count for each of its series. Spelled out as records that is, for a command of 64 rows of 12 series, the count of
// every (tier, series) pair, each series id of ninety-seven bytes written once: 73-84 KB measured at 5,000 records/s, about half
// of the leader's rounds and 33 % (minute 1) to 62 % (minute 20) of its time, judged under the lock (2,300 series records read and
// written) and replicated to every voter. Every voter holds the rows. The command therefore says which rows it settles and how
// the windows end up, and each voter derives the rest from the rows it holds:
//
//	stl  for each window the command touches, in window-key order: the window (group, number, span), the parts the command adds
//	     (a window settled in parts) or none (a window settled whole), the digest the record ends with (whole windows and windows
//	     the command completes) and the ids of the reservations it drops, in the order the proposer judged them.
//
// A voter reads each row (it must be consumed, in the window the entry names, reachable through its admission key), finds that
// the rows prove what the entry states (the digest of all the rows of a window settled whole; for each added part its count and the
// digest of the rows that fall into the part; every row in some added part), writes the window record the entry leaves (the
// parts added to the ones the record holds: a record grows by what a command adds, not by a rewrite of its part list), the
// window's span, the tier charges (bytes, and one more reference for every series of every row) and drops the rows and their
// keys. These are the records the plain ops write (the equivalence test TestSettleOpLeavesTheLedgerThePlainOpsLeave pins it over
// random rounds, windows settled whole and in parts, honest and false statements of the data); a count, a window or a row the
// rows do not prove is refused (Corrupt) before anything is written. The proposer no longer reads or writes a series record to
// build the command, and the bytes are a function of the rows and the parts added.
//
// Like rsv, fin and rec it is proposed only once every member declared the protocol that knows it (Store.SetCompactAdmissionGate)
// and the installation keeps its books in the ledger. An erasure pass does not read it: it carries ids and digests, and
// the rows it names are not records a pass rewrites.

// maxSettleOpRows bounds the rows of one stl op (a command settles settleRowsPerCommand rows, a window settled whole is one unit).
const maxSettleOpRows = 1 << 16

// settleOp is the value of an stl op.
type settleOp struct {
	Windows []settleWindow `json:"w"`
}

// settleWindow is one window of an stl op.
type settleWindow struct {
	Group model.ID `json:"g"`
	N     uint64   `json:"n"`
	Span  uint64   `json:"s"`
	// Part is the number of commands of a part when the command settles parts of the window (Parts lists the ones it adds), zero
	// when it settles the window whole.
	Part  uint64              `json:"p,omitempty"`
	Parts []model.SettledPart `json:"a,omitempty"`
	// Charge is the digest the record ends with: the digest of Rows for a window settled whole, the data window's own for a
	// window the command completes. It is unset for a window that stays incomplete.
	Charge *model.Hash `json:"c,omitempty"`
	Rows   []string    `json:"r"`
}

// check is whether the op says what a proposer writes: windows in key order, each with rows (named once in the whole op), parts of
// a window cut into parts in order, and the digest that a window settled whole must carry.
func (q settleOp) check(path []string) error {
	bad := model.Fail(model.Corrupt)
	if len(path) != 2 || path[0] != "settlement" || path[1] != "stl" || len(q.Windows) == 0 || len(q.Windows) > settleWindowsPerCommand {
		return bad
	}
	seen := map[string]bool{}
	last := ""
	for _, w := range q.Windows {
		key := model.SettledKey(w.Group, w.N)
		if w.Group == (model.ID{}) || w.Span == 0 || len(w.Rows) == 0 && (w.Part == 0 || len(w.Parts) != 0) || key < last {
			return bad
		}
		last = key
		if w.Part == 0 {
			if len(w.Parts) != 0 || w.Charge == nil {
				return bad
			}
		} else {
			if w.Part >= w.Span || w.Span%w.Part != 0 || len(w.Parts) == 0 && w.Charge == nil {
				return bad
			}
			for i, p := range w.Parts {
				if uint64(p.J) >= w.Span/w.Part || i > 0 && p.J <= w.Parts[i-1].J || p.Count == 0 || p.Count > w.Part {
					return bad
				}
			}
		}
		for _, id := range w.Rows {
			if id == "" || seen[id] {
				return bad
			}
			seen[id] = true
		}
		if len(seen) > maxSettleOpRows {
			return bad
		}
	}
	return nil
}

func chargeItems(rows []model.AdmissionReservation) []model.ChargeItem {
	items := make([]model.ChargeItem, len(rows))
	for i, r := range rows {
		items[i] = model.ChargeOf(r)
	}
	return items
}

// record is the window record the entry leaves when it is applied to the record the voter holds (found) and the rows it names,
// or Corrupt when the rows do not prove what the entry states.
func (w settleWindow) record(existing model.SettledWindow, found bool, rows []model.AdmissionReservation) (model.SettledWindow, error) {
	bad := model.Fail(model.Corrupt)
	if w.Part == 0 {
		if found || model.ChargeDigest(chargeItems(rows)) != *w.Charge {
			return model.SettledWindow{}, bad
		}
		return model.SettledWindow{Group: w.Group, N: w.N, Span: w.Span, Count: uint64(len(rows)), Charge: *w.Charge}, nil
	}
	if !found && len(w.Parts) == 0 {
		return model.SettledWindow{}, bad
	}
	record := model.SettledWindow{Group: w.Group, N: w.N, Span: w.Span, Part: w.Part}
	if found {
		if existing.Complete() || existing.Span != w.Span || existing.Part != w.Part {
			return model.SettledWindow{}, bad
		}
		record.Count = existing.Count
		record.Parts = append([]model.SettledPart(nil), existing.Parts...)
	}
	byPart := map[uint32][]model.AdmissionReservation{}
	for _, r := range rows {
		j := model.PartOf(uint64(r.Cursor.Index), w.Span, w.Part)
		byPart[j] = append(byPart[j], r)
	}
	settled := 0
	for _, p := range w.Parts {
		in := byPart[p.J]
		if _, done := record.Settled(p.J); done || uint64(len(in)) != p.Count || model.ChargeDigest(chargeItems(in)) != p.Charge {
			return model.SettledWindow{}, bad
		}
		record.Parts = append(record.Parts, p)
		record.Count += p.Count
		settled += len(in)
	}
	if settled != len(rows) {
		return model.SettledWindow{}, bad
	}
	sort.Slice(record.Parts, func(i, j int) bool { return record.Parts[i].J < record.Parts[j].J })
	if w.Charge != nil {
		if record.Count == 0 || record.Count > w.Span {
			return model.SettledWindow{}, bad
		}
		record = model.SettledWindow{Group: w.Group, N: w.N, Span: w.Span, Count: record.Count, Charge: *w.Charge}
	}
	return record, nil
}

// settleOps is the stl op of the settlement plans of a round (none when there are none), the windows in key order and the plans
// of one window in the order they were judged.
func settleOps(plans []settledWindowPlan) []patchOp {
	if len(plans) == 0 {
		return nil
	}
	q := settleOp{Windows: make([]settleWindow, 0, len(plans))}
	for _, p := range plans {
		c := p.candidate
		w := settleWindow{Group: c.Group, N: c.N, Span: c.Span, Rows: make([]string, len(p.rows))}
		if len(p.added) != 0 || len(p.rows) == 0 { // a window the command completes may add no part: its parts were all settled before
			w.Part, w.Parts = c.Part, p.added
		}
		if p.record.Complete() {
			charge := p.record.Charge
			w.Charge = &charge
		}
		for i, r := range p.rows {
			w.Rows[i] = r.ID.String()
		}
		q.Windows = append(q.Windows, w)
	}
	sort.SliceStable(q.Windows, func(i, j int) bool {
		return model.SettledKey(q.Windows[i].Group, q.Windows[i].N) < model.SettledKey(q.Windows[j].Group, q.Windows[j].N)
	})
	return []patchOp{{Op: opSettle, Path: []string{"settlement", "stl"}, Value: mustJSON(q)}}
}

// settleRows reads the rows an entry names: each is consumed, in the window of the entry and reachable through its admission key.
func (l *ledgerTx) settleRows(w settleWindow) ([]model.AdmissionReservation, error) {
	rows := make([]model.AdmissionReservation, len(w.Rows))
	for i, id := range w.Rows {
		r, ok, err := l.reservation(id)
		if err != nil {
			return nil, err
		}
		if !ok || r.ID.String() != id || r.State != "consumed" || r.Cursor == nil || r.Cursor.Index == 0 || r.Cursor.Group != w.Group || (uint64(r.Cursor.Index)-1)/w.Span != w.N {
			return nil, model.Fail(model.Corrupt)
		}
		if keyed, ok := l.keyed(reservationKey(r)); !ok || keyed != id {
			return nil, model.Fail(model.Corrupt)
		}
		rows[i] = r
	}
	return rows, nil
}

// settle applies an stl op: nothing is written unless every window of it is proved by the rows the voter holds.
func (a *opApplier) settle(op patchOp) error {
	var q settleOp
	if err := decodeValue(op.Value, &q); err != nil {
		return err
	}
	if err := q.check(op.Path); err != nil {
		return err
	}
	l := a.l
	type tierFold struct {
		bytes  uint64
		series map[string]uint64
	}
	folds := map[string]*tierFold{}
	records := map[string]model.SettledWindow{} // what the entries before this one left (a window may be taken by two commands of a round)
	for _, w := range q.Windows {
		rows, err := l.settleRows(w)
		if err != nil {
			return err
		}
		key := model.SettledKey(w.Group, w.N)
		existing, found := records[key]
		if !found {
			if existing, found, err = l.window(key); err != nil {
				return err
			}
		}
		record, err := w.record(existing, found, rows)
		if err != nil {
			return err
		}
		if known := l.span(w.Group.String()); known != 0 && known != w.Span {
			return model.Fail(model.Corrupt)
		}
		raw, err := json.Marshal(record)
		if err != nil {
			return model.Fail(model.Corrupt)
		}
		if err = l.put(tableWindows, []byte(key), raw); err != nil {
			return err
		}
		records[key] = record
		if err = l.put(tableSpans, []byte(w.Group.String()), u64(w.Span)); err != nil {
			return err
		}
		for _, r := range rows {
			for _, tier := range quotaKeys(r) {
				f := folds[tier]
				if f == nil {
					f = &tierFold{series: map[string]uint64{}}
					folds[tier] = f
				}
				f.bytes += uint64(r.Bytes)
				for _, id := range r.Series {
					f.series[id]++
				}
			}
			if _, err = l.del(tableReservations, []byte(r.ID.String())); err != nil {
				return err
			}
			if _, err = l.del(tableKeys, []byte(reservationKey(r))); err != nil {
				return err
			}
		}
	}
	tiers := make([]string, 0, len(folds))
	for tier := range folds {
		tiers = append(tiers, tier)
	}
	sort.Strings(tiers)
	for _, tier := range tiers {
		f := folds[tier]
		old, _ := l.charge(tier)
		if err := l.put(tableCharges, []byte(tier), u64(old+f.bytes)); err != nil {
			return err
		}
		for id, n := range f.series {
			if err := l.put(tableChargeSeries, seriesKey(tier, id), u64(l.chargeSeries(tier, id)+n)); err != nil {
				return err
			}
		}
	}
	return nil
}

// verifySettle is verifyOp of an stl op: the ledger holds the windows the op leaves and none of the rows it drops. The counts it
// folded cannot be told from the ledger after the fact (they are sums over rows that are gone); a voter that applied the op
// proved them against the rows before it wrote anything.
func (l *ledgerTx) verifySettle(op patchOp) error {
	var q settleOp
	if err := decodeValue(op.Value, &q); err != nil {
		return err
	}
	if err := q.check(op.Path); err != nil {
		return err
	}
	bad := model.Fail(model.Corrupt)
	for _, w := range q.Windows {
		held, ok, err := l.window(model.SettledKey(w.Group, w.N))
		if err != nil {
			return err
		}
		if !ok || held.Span != w.Span || l.span(w.Group.String()) != w.Span {
			return bad
		}
		if w.Charge != nil && (!held.Complete() || held.Charge != *w.Charge) {
			return bad
		}
		if w.Charge == nil {
			if held.Complete() {
				return bad
			}
			for _, p := range w.Parts {
				if got, ok := held.Settled(p.J); !ok || got != p {
					return bad
				}
			}
		}
		for _, id := range w.Rows {
			_, ok, err := l.reservation(id)
			if err != nil {
				return err
			}
			if ok {
				return bad
			}
		}
	}
	return nil
}

// deriveSettlement is settleDeriver: the root books of a round that proposes compact ops hand the settlement to the voters.
func (b *ledgerBooks) deriveSettlement(w settledWindowPlan) bool {
	root := b
	for root.up != nil {
		root = root.up
	}
	if !root.compact {
		return false
	}
	b.settled = append(b.settled, w)
	return true
}

// settleCover is what the stl op of a round writes, so that the plain ops for the same records are left out.
type settleCover struct {
	res, keys, wins, spans map[string]bool
}

func (b *ledgerBooks) settledCover() settleCover {
	c := settleCover{res: map[string]bool{}, keys: map[string]bool{}, wins: map[string]bool{}, spans: map[string]bool{}}
	for _, w := range b.settled {
		c.wins[w.key] = true
		c.spans[w.candidate.Group.String()] = true
		for _, r := range w.rows {
			c.res[r.ID.String()] = true
			c.keys[reservationKey(r)] = true
		}
	}
	return c
}
