// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"errors"
	"sort"

	"github.com/arynyklas/soundpost/internal/model"
)

// admissionBooks is what the admission transitions (reserve, finalize, cancel, reconcile, settle)
// read and write: the reservation rows, their keys, the quota records and the settlement. One
// implementation sits over a State (a transition that runs on the whole state: a replacement, a
// store whose group has a member without the ledger), the other over the ledger records of one bolt
// transaction (ledgerBooks), which collects what the transition wrote as the patch ops that carry it.
// The transitions are written once, against this interface, so that the two cannot decide differently.
type admissionBooks interface {
	reservation(id string) (model.AdmissionReservation, bool, error)
	putReservation(r model.AdmissionReservation)
	delReservation(id string)
	keyed(key string) (string, bool)
	putKey(key, id string)
	delKey(key string)
	// eachReservation calls fn for every reservation row of the committed state, until fn says stop.
	eachReservation(fn func(model.AdmissionReservation) bool) error
	// eachOpen calls fn for every reservation of the committed state that is still reserved, until fn says stop:
	// the ledger answers from its index (admission_open.go) and returns errOpenIndexStale when the file's index
	// does not belong to its ledger.
	eachOpen(fn func(model.AdmissionReservation) bool) error

	head(tier string) (quotaHead, error)
	putHead(tier string, h quotaHead)
	series(tier, id string) uint64
	setSeries(tier, id string, n uint64)

	span(group string) uint64
	setSpan(group string, span uint64)
	window(key string) (model.SettledWindow, bool, error)
	putWindow(key string, w model.SettledWindow)
	hasWindows() bool
	charge(tier string) uint64
	setCharge(tier string, bytes uint64)
	chargeSeries(tier, id string) uint64
	setChargeSeries(tier, id string, n uint64)
}

// windowOf is the settled window record the cursor falls into; settled reports whether the cursor's
// reservation is settled by it: the window is settled whole or the part of it the cursor falls into is
// (model.Settlement.Covers).
func windowOf(b admissionBooks, c model.Cursor) (w model.SettledWindow, settled bool, err error) {
	if c.Index == 0 {
		return model.SettledWindow{}, false, nil
	}
	span := b.span(c.Group.String())
	if span == 0 {
		return model.SettledWindow{}, false, nil
	}
	w, ok, err := b.window(model.SettledKey(c.Group, (uint64(c.Index)-1)/span))
	if err != nil || !ok {
		return w, false, err
	}
	return w, w.Covers(c.Index), nil
}

// stateBooks is admissionBooks over the members of a State.
type stateBooks struct{ st *State }

func (b stateBooks) reservation(id string) (model.AdmissionReservation, bool, error) {
	r, ok := b.st.Reservations[id]
	return r, ok, nil
}

func (b stateBooks) putReservation(r model.AdmissionReservation) {
	if b.st.Reservations == nil {
		b.st.Reservations = map[string]model.AdmissionReservation{}
	}
	b.st.Reservations[r.ID.String()] = r
}

func (b stateBooks) delReservation(id string) { delete(b.st.Reservations, id) }

func (b stateBooks) keyed(key string) (string, bool) {
	id, ok := b.st.AdmissionKeys[key]
	return id, ok
}

func (b stateBooks) putKey(key, id string) {
	if b.st.AdmissionKeys == nil {
		b.st.AdmissionKeys = map[string]string{}
	}
	b.st.AdmissionKeys[key] = id
}

func (b stateBooks) delKey(key string) { delete(b.st.AdmissionKeys, key) }

func (b stateBooks) eachReservation(fn func(model.AdmissionReservation) bool) error {
	for _, r := range b.st.Reservations {
		if !fn(r) {
			return nil
		}
	}
	return nil
}

func (b stateBooks) eachOpen(fn func(model.AdmissionReservation) bool) error {
	for _, r := range b.st.Reservations {
		if r.State == "reserved" && !fn(r) {
			return nil
		}
	}
	return nil
}

func (b stateBooks) head(tier string) (quotaHead, error) {
	q := b.st.Quotas[tier]
	return quotaHead{Bytes: q.Bytes, MaxBytes: q.MaxBytes, MaxSeries: q.MaxSeries, Configured: q.Configured, Series: uint64(len(q.Series))}, nil
}

func (b stateBooks) putHead(tier string, h quotaHead) {
	if b.st.Quotas == nil {
		b.st.Quotas = map[string]model.QuotaState{}
	}
	q := b.st.Quotas[tier]
	q.Bytes, q.MaxBytes, q.MaxSeries, q.Configured = h.Bytes, h.MaxBytes, h.MaxSeries, h.Configured
	if q.Series == nil {
		q.Series = map[string]uint64{}
	}
	b.st.Quotas[tier] = q
}

func (b stateBooks) series(tier, id string) uint64 { return b.st.Quotas[tier].Series[id] }

func (b stateBooks) setSeries(tier, id string, n uint64) {
	if b.st.Quotas == nil {
		b.st.Quotas = map[string]model.QuotaState{}
	}
	q := b.st.Quotas[tier]
	if q.Series == nil {
		q.Series = map[string]uint64{}
	}
	if n == 0 {
		delete(q.Series, id)
	} else {
		q.Series[id] = n
	}
	b.st.Quotas[tier] = q
}

func (b stateBooks) settlement() *model.Settlement {
	if b.st.Settlement == nil {
		b.st.Settlement = &model.Settlement{}
	}
	return b.st.Settlement
}

func (b stateBooks) span(group string) uint64 {
	if b.st.Settlement == nil {
		return 0
	}
	return b.st.Settlement.Spans[group]
}

func (b stateBooks) setSpan(group string, span uint64) {
	s := b.settlement()
	if s.Spans == nil {
		s.Spans = map[string]uint64{}
	}
	s.Spans[group] = span
}

func (b stateBooks) window(key string) (model.SettledWindow, bool, error) {
	w, ok := b.st.Settlement.Lookup(key)
	return w, ok, nil
}

func (b stateBooks) putWindow(key string, w model.SettledWindow) {
	s := b.settlement()
	if s.Windows == nil {
		s.Windows = map[string]model.SettledWindow{}
	}
	s.Windows[key] = w
}

func (b stateBooks) hasWindows() bool {
	return b.st.Settlement != nil && len(b.st.Settlement.Windows) != 0
}

func (b stateBooks) charge(tier string) uint64 {
	if b.st.Settlement == nil {
		return 0
	}
	return uint64(b.st.Settlement.Charges[tier].Bytes)
}

func (b stateBooks) setCharge(tier string, bytes uint64) {
	s := b.settlement()
	if s.Charges == nil {
		s.Charges = map[string]model.SettledCharge{}
	}
	c := s.Charges[tier]
	c.Bytes = model.Uint64(bytes)
	if c.Series == nil {
		c.Series = map[string]uint64{}
	}
	s.Charges[tier] = c
}

func (b stateBooks) chargeSeries(tier, id string) uint64 {
	if b.st.Settlement == nil {
		return 0
	}
	return b.st.Settlement.Charges[tier].Series[id]
}

func (b stateBooks) setChargeSeries(tier, id string, n uint64) {
	s := b.settlement()
	if s.Charges == nil {
		s.Charges = map[string]model.SettledCharge{}
	}
	c := s.Charges[tier]
	if c.Series == nil {
		c.Series = map[string]uint64{}
	}
	if n == 0 {
		delete(c.Series, id)
	} else {
		c.Series[id] = n
	}
	s.Charges[tier] = c
}

// ledgerBooks is admissionBooks over the ledger of one bolt transaction. Reads see what the
// transition wrote before them; nothing is written to the ledger: ops() is what the transition
// changed, as the patch ops that a proposal carries and every voter applies.
//
// The books of one transition of a group commit (admission_group.go) are a child of the books of the
// round: a read that the child did not write is answered from the round (what the transitions that came
// before it in the round wrote), then from the ledger; the child's writes reach the round only when
// the transition succeeds (merge), so a transition that is refused half way leaves nothing behind.
type ledgerBooks struct {
	l  *ledgerTx
	up *ledgerBooks // the round this is one transition of; nil for the round itself

	res    map[string]*model.AdmissionReservation // nil: deleted
	keys   map[string]*string
	heads  map[string]*headEdit
	sers   map[string]uint64 // quota key NUL series -> count (0: deleted)
	spans  map[string]uint64
	wins   map[string]model.SettledWindow
	chg    map[string]uint64
	chgSer map[string]uint64
}

// headEdit is a quota head a transition read, and what it is now.
type headEdit struct {
	orig       quotaHead
	origExists bool
	cur        quotaHead
	written    bool
}

func newLedgerBooks(l *ledgerTx) *ledgerBooks {
	return &ledgerBooks{l: l, res: map[string]*model.AdmissionReservation{}, keys: map[string]*string{}, heads: map[string]*headEdit{}, sers: map[string]uint64{}, spans: map[string]uint64{}, wins: map[string]model.SettledWindow{}, chg: map[string]uint64{}, chgSer: map[string]uint64{}}
}

// child is the books of one transition of the round b: it reads what b holds, and writes only to itself
// until b.merge takes its writes.
func (b *ledgerBooks) child() *ledgerBooks {
	c := newLedgerBooks(b.l)
	c.up = b
	return c
}

// merge makes the writes of the child c the writes of b (the transition of c succeeded).
func (b *ledgerBooks) merge(c *ledgerBooks) {
	for k, v := range c.res {
		b.res[k] = v
	}
	for k, v := range c.keys {
		b.keys[k] = v
	}
	for k, v := range c.heads {
		b.heads[k] = v
	}
	for k, v := range c.sers {
		b.sers[k] = v
	}
	for k, v := range c.spans {
		b.spans[k] = v
	}
	for k, v := range c.wins {
		b.wins[k] = v
	}
	for k, v := range c.chg {
		b.chg[k] = v
	}
	for k, v := range c.chgSer {
		b.chgSer[k] = v
	}
}

func (b *ledgerBooks) reservation(id string) (model.AdmissionReservation, bool, error) {
	if r, ok := b.res[id]; ok {
		if r == nil {
			return model.AdmissionReservation{}, false, nil
		}
		return *r, true, nil
	}
	if b.up != nil {
		return b.up.reservation(id)
	}
	return b.l.reservation(id)
}

func (b *ledgerBooks) putReservation(r model.AdmissionReservation) {
	b.res[r.ID.String()] = &r
}

func (b *ledgerBooks) delReservation(id string) { b.res[id] = nil }

func (b *ledgerBooks) keyed(key string) (string, bool) {
	if id, ok := b.keys[key]; ok {
		if id == nil {
			return "", false
		}
		return *id, true
	}
	if b.up != nil {
		return b.up.keyed(key)
	}
	return b.l.keyed(key)
}

func (b *ledgerBooks) putKey(key, id string) { b.keys[key] = &id }

func (b *ledgerBooks) delKey(key string) { b.keys[key] = nil }

// errOpenIndexStale reports that the file's index of open reservations does not belong to its ledger (a build
// without the index changed the ledger): the caller rebuilds it (ensureOpenIndex) and reads again.
var errOpenIndexStale = errors.New("control: the index of open reservations is stale")

func (b *ledgerBooks) eachOpen(fn func(model.AdmissionReservation) bool) error {
	if b.l.open == nil || !openIndexCurrent(b.l.ctrl) {
		return errOpenIndexStale
	}
	return b.l.eachOpen(fn)
}

func (b *ledgerBooks) eachReservation(fn func(model.AdmissionReservation) bool) error {
	c := b.l.t[tableReservations].Cursor()
	for k, v := c.First(); k != nil; k, v = c.Next() {
		var r model.AdmissionReservation
		if err := decodeValue(v, &r); err != nil {
			return err
		}
		if !fn(r) {
			return nil
		}
	}
	return nil
}

func (b *ledgerBooks) edit(tier string) (*headEdit, error) {
	if h, ok := b.heads[tier]; ok {
		return h, nil
	}
	if b.up != nil {
		u, err := b.up.edit(tier)
		if err != nil {
			return nil, err
		}
		h := *u // the round's head as this transition starts from it
		b.heads[tier] = &h
		return &h, nil
	}
	orig, exists, err := b.l.head(tier)
	if err != nil {
		return nil, err
	}
	h := &headEdit{orig: orig, origExists: exists, cur: orig}
	b.heads[tier] = h
	return h, nil
}

func (b *ledgerBooks) head(tier string) (quotaHead, error) {
	h, err := b.edit(tier)
	if err != nil {
		return quotaHead{}, err
	}
	return h.cur, nil
}

func (b *ledgerBooks) putHead(tier string, h quotaHead) {
	e, err := b.edit(tier)
	if err != nil {
		// A head that cannot be read cannot have been read by the caller either: head returned the error.
		e = &headEdit{}
		b.heads[tier] = e
	}
	e.cur.Bytes, e.cur.MaxBytes, e.cur.MaxSeries, e.cur.Configured = h.Bytes, h.MaxBytes, h.MaxSeries, h.Configured
	e.written = true
}

func (b *ledgerBooks) series(tier, id string) uint64 {
	if n, ok := b.sers[string(seriesKey(tier, id))]; ok {
		return n
	}
	if b.up != nil {
		return b.up.series(tier, id)
	}
	return b.l.series(tier, id)
}

func (b *ledgerBooks) setSeries(tier, id string, n uint64) {
	old := b.series(tier, id)
	b.sers[string(seriesKey(tier, id))] = n
	e, _ := b.edit(tier)
	if e == nil {
		return
	}
	switch {
	case old == 0 && n != 0:
		e.cur.Series++
	case old != 0 && n == 0:
		e.cur.Series--
	}
	e.written = true
}

func (b *ledgerBooks) span(group string) uint64 {
	if s, ok := b.spans[group]; ok {
		return s
	}
	if b.up != nil {
		return b.up.span(group)
	}
	return b.l.span(group)
}

func (b *ledgerBooks) setSpan(group string, span uint64) { b.spans[group] = span }

func (b *ledgerBooks) window(key string) (model.SettledWindow, bool, error) {
	if w, ok := b.wins[key]; ok {
		return w, true, nil
	}
	if b.up != nil {
		return b.up.window(key)
	}
	return b.l.window(key)
}

func (b *ledgerBooks) putWindow(key string, w model.SettledWindow) { b.wins[key] = w }

func (b *ledgerBooks) hasWindows() bool {
	return len(b.wins) != 0 || b.up != nil && b.up.hasWindows() || b.l.hasWindows()
}

func (b *ledgerBooks) charge(tier string) uint64 {
	if v, ok := b.chg[tier]; ok {
		return v
	}
	if b.up != nil {
		return b.up.charge(tier)
	}
	v, _ := b.l.charge(tier)
	return v
}

func (b *ledgerBooks) setCharge(tier string, bytes uint64) { b.chg[tier] = bytes }

func (b *ledgerBooks) chargeSeries(tier, id string) uint64 {
	if n, ok := b.chgSer[string(seriesKey(tier, id))]; ok {
		return n
	}
	if b.up != nil {
		return b.up.chargeSeries(tier, id)
	}
	return b.l.chargeSeries(tier, id)
}

func (b *ledgerBooks) setChargeSeries(tier, id string, n uint64) {
	b.chgSer[string(seriesKey(tier, id))] = n
}

// ops is what the transition wrote, as patch ops in path order. A series record is written only
// when it differs from the ledger's, a head field only when it does.
func (b *ledgerBooks) ops() []patchOp {
	var ops []patchOp
	set := func(path []string, v any) { ops = append(ops, patchOp{Op: opSet, Path: path, Value: mustJSON(v)}) }
	del := func(path []string) { ops = append(ops, patchOp{Op: opDelete, Path: path}) }
	for id, r := range b.res {
		switch {
		case r == nil:
			if _, ok, _ := b.l.reservation(id); ok {
				del([]string{"Reservations", id})
			}
		default:
			if old, ok, _ := b.l.reservation(id); !ok || !sameValue(old, *r) {
				set([]string{"Reservations", id}, *r)
			}
		}
	}
	for key, id := range b.keys {
		old, ok := b.l.keyed(key)
		switch {
		case id == nil:
			if ok {
				del([]string{"AdmissionKeys", key})
			}
		case !ok || old != *id:
			set([]string{"AdmissionKeys", key}, *id)
		}
	}
	for tier, h := range b.heads {
		if !h.written {
			continue
		}
		p := func(field string) []string { return []string{"Quotas", tier, field} }
		if !h.origExists || h.cur.Bytes != h.orig.Bytes {
			set(p("bytes"), h.cur.Bytes)
		}
		if !h.origExists || h.cur.MaxBytes != h.orig.MaxBytes {
			set(p("max_bytes"), h.cur.MaxBytes)
		}
		if !h.origExists || h.cur.MaxSeries != h.orig.MaxSeries {
			set(p("max_series"), h.cur.MaxSeries)
		}
		if !h.origExists || h.cur.Configured != h.orig.Configured {
			set(p("configured"), h.cur.Configured)
		}
	}
	for key, n := range b.sers {
		tier, id := splitSeriesKey(key)
		old := b.l.series(tier, id)
		switch {
		case n == 0 && old != 0:
			del([]string{"Quotas", tier, "series", id})
		case n != 0 && n != old:
			set([]string{"Quotas", tier, "series", id}, n)
		}
	}
	for group, span := range b.spans {
		if b.l.span(group) != span {
			set([]string{"settlement", "spans", group}, span)
		}
	}
	for key, w := range b.wins {
		if old, ok, _ := b.l.window(key); !ok || !old.Equal(w) {
			set([]string{"settlement", "windows", key}, w)
		}
	}
	for tier, v := range b.chg {
		if old, ok := b.l.charge(tier); !ok || old != v {
			set([]string{"settlement", "charges", tier, "bytes"}, model.Uint64(v))
		}
	}
	for key, n := range b.chgSer {
		tier, id := splitSeriesKey(key)
		old := b.l.chargeSeries(tier, id)
		switch {
		case n == 0 && old != 0:
			del([]string{"settlement", "charges", tier, "series", id})
		case n != 0 && n != old:
			set([]string{"settlement", "charges", tier, "series", id}, n)
		}
	}
	sort.Slice(ops, func(i, j int) bool { return pathLess(ops[i].Path, ops[j].Path) })
	return ops
}
