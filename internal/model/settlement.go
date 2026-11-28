// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package model

import (
	"encoding/json"
	"sort"
	"strconv"
)

// Settlement is what control keeps of consumed admission reservations after it dropped their
// rows (internal/control/settle.go).
//
// A consumed reservation is permanent: its charge is never refunded, and the data holds the
// batch that consumed it together with the whole reservation. Control therefore keeps a row for
// it only while it needs the row (the retry answer of ReserveAdmission, the finalize and the
// reconciliation against the owner's outcomes) and, once the data window holding the batch is
// sealed, replaces the rows of that window by one SettledWindow (the digest of exactly the
// reservations it held, as the data window states it) and adds their charge to Charges. The
// charge of a settled reservation is thus still exact on every quota key, and a backup proves
// it against the data windows themselves (internal/storage/evidence_spans.go) instead of
// carrying one row per reservation.
type Settlement struct {
	// Spans is the window size of each data group that has settled windows (group ID -> commands
	// per window); one group never changes it.
	Spans map[string]uint64 `json:"spans"`
	// Windows is keyed by SettledKey(group, n).
	Windows map[string]SettledWindow `json:"windows"`
	// Charges is the charge of every settled reservation on each quota key it touched: the bytes
	// and, per series, the number of settled reservations that reference it (the refcount the
	// quota objects keep).
	Charges map[string]SettledCharge `json:"charges"`
}

// SettledWindow is one data-group window whose consumed reservations control no longer holds, or, when
// Part is set, one whose reservations it holds no longer in part.
//
// A window is settled whole when the data seals it. Waiting for that leaves up to a window of commands
// per group (4096 of 64 groups) as consumed rows in control, however fast the load makes them, so a
// window is also settled in parts while it is still open: a part is Part consecutive commands of the
// window, and the data states the digest of the reservations each part consumed exactly as it states the
// window's. A window settled in parts is an incomplete record (Part and Parts set, Charge unset) that the
// sealed window replaces with the complete one once every part that carries batches is settled.
type SettledWindow struct {
	Group ID     `json:"group"`
	N     uint64 `json:"n,string"`
	Span  uint64 `json:"span,string"`
	// Count is the number of reservations the window (or, in an incomplete record, its settled parts)
	// settled.
	Count uint64 `json:"count,string"`
	// Charge is ChargeDigest of those reservations; the data window's own charge digest equals it. It is
	// unset in an incomplete record.
	Charge Hash `json:"charge"`
	// Part is the number of commands of a part; zero for a complete window.
	Part uint64 `json:"part,string,omitempty"`
	// Parts are the settled parts of an incomplete window, by part number.
	Parts []SettledPart `json:"parts,omitempty"`
}

// SettledPart is one settled part of a window: its number inside the window, the reservations it
// settled and their charge digest (the data part's own digest equals it).
type SettledPart struct {
	J      uint32 `json:"j"`
	Count  uint64 `json:"count,string"`
	Charge Hash   `json:"charge"`
}

// SettledCharge is the charge settled reservations put on one quota key.
type SettledCharge struct {
	Bytes  Uint64            `json:"bytes"`
	Series map[string]uint64 `json:"series"`
}

// SettlePart is one part of a data window as the data states it: the batches the part consumed and their
// charge digest. Parts that carry no batch are not listed.
type SettlePart struct {
	J       uint32 `json:"j"`
	Batches uint64 `json:"batches,string"`
	Charge  Hash   `json:"charge"`
}

// SettleCandidate is a data window a storage engine offers for settlement: the window it holds, how many
// batches (consumed reservations) it carries and their charge digest. Windows that carry a redacted batch
// are never offered.
//
// A window the data has sealed is offered whole (Batches and Charge are its totals) and, when the data
// derived the parts of it, with them (Part, Parts). A window that is still open is offered with the parts
// of it that are complete (Open; Batches and Charge unset): control may settle those and nothing else.
type SettleCandidate struct {
	Group   ID           `json:"group"`
	N       uint64       `json:"n,string"`
	Span    uint64       `json:"span,string"`
	Batches uint64       `json:"batches,string"`
	Charge  Hash         `json:"charge"`
	Part    uint64       `json:"part,string,omitempty"`
	Parts   []SettlePart `json:"parts,omitempty"`
	Open    bool         `json:"open,omitempty"`
}

// Complete reports whether the record settles the whole window.
func (w SettledWindow) Complete() bool { return w.Part == 0 }

// PartOf is the number of the part of its window that the command at index falls into, for windows of span
// commands cut into parts of part commands; part is zero for a window that has none.
func PartOf(index, span, part uint64) uint32 {
	if part == 0 || span == 0 || index == 0 {
		return 0
	}
	return uint32(((index - 1) % span) / part)
}

// Settled returns the settled part with number j of an incomplete window.
func (w SettledWindow) Settled(j uint32) (SettledPart, bool) {
	for _, p := range w.Parts {
		if p.J == j {
			return p, true
		}
	}
	return SettledPart{}, false
}

// Lookup returns the settled window stored under key (SettledKey), if there is one.
func (s *Settlement) Lookup(key string) (SettledWindow, bool) {
	if s == nil {
		return SettledWindow{}, false
	}
	w, ok := s.Windows[key]
	return w, ok
}

// SettledKey is the key of a settled window in Settlement.Windows.
func SettledKey(group ID, n uint64) string { return group.String() + ":" + strconv.FormatUint(n, 10) }

// Window returns the settled window record the cursor falls into, if there is one. An incomplete record
// (Part set) is returned although the cursor's own part may not be settled: Covers answers that.
func (s *Settlement) Window(c Cursor) (SettledWindow, bool) {
	if s == nil || c.Index == 0 {
		return SettledWindow{}, false
	}
	span := s.Spans[c.Group.String()]
	if span == 0 {
		return SettledWindow{}, false
	}
	w, ok := s.Windows[SettledKey(c.Group, (uint64(c.Index)-1)/span)]
	return w, ok
}

// Covers reports whether the reservation consumed at the cursor is settled: its window is settled whole or
// the part of it the cursor falls into is.
func (s *Settlement) Covers(c Cursor) bool {
	w, ok := s.Window(c)
	return ok && w.Covers(c.Index)
}

// Covers reports whether the command at index is settled by the record: the window is complete or the
// part it falls into is settled.
func (w SettledWindow) Covers(index Uint64) bool {
	if w.Complete() {
		return true
	}
	_, ok := w.Settled(PartOf(uint64(index), w.Span, w.Part))
	return ok
}

// SortedWindows lists the settled windows by group, then window number.
func (s *Settlement) SortedWindows() []SettledWindow {
	if s == nil {
		return nil
	}
	out := make([]SettledWindow, 0, len(s.Windows))
	for _, w := range s.Windows {
		out = append(out, w)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Group != out[j].Group {
			return out[i].Group.String() < out[j].Group.String()
		}
		return out[i].N < out[j].N
	})
	return out
}

// ChargeItem is what one consumed reservation charges, in the form ChargeDigest hashes.
type ChargeItem struct {
	ID      ID
	Org     ID
	Project ID
	Source  ID
	Hash    Hash
	Bytes   Uint64
	Series  []string
	Cursor  Cursor
}

// ChargeOf is the ChargeItem of a consumed reservation.
func ChargeOf(r AdmissionReservation) ChargeItem {
	item := ChargeItem{ID: r.ID, Org: r.Org, Project: r.Project, Source: r.Source, Hash: r.Hash, Bytes: r.Bytes, Series: append([]string{}, r.Series...)}
	if r.Cursor != nil {
		item.Cursor = *r.Cursor
	}
	return item
}

// ChargeDigest is the digest of what a set of consumed reservations charges, in cursor order. A
// data window's charge digest and the digest of the reservations control holds for it agree
// exactly when control holds every one of them with the same charge.
func ChargeDigest(items []ChargeItem) Hash {
	type tuple struct {
		ID      ID       `json:"id"`
		Org     ID       `json:"org"`
		Project ID       `json:"project"`
		Source  ID       `json:"source"`
		Hash    Hash     `json:"hash"`
		Bytes   Uint64   `json:"bytes"`
		Series  []string `json:"series"`
		Cursor  Cursor   `json:"cursor"`
	}
	tuples := make([]tuple, len(items))
	for i, it := range items {
		series := it.Series
		if series == nil {
			series = []string{}
		}
		tuples[i] = tuple{it.ID, it.Org, it.Project, it.Source, it.Hash, it.Bytes, series, it.Cursor}
	}
	sort.SliceStable(tuples, func(i, j int) bool { return tuples[i].Cursor.Index < tuples[j].Cursor.Index })
	raw, _ := json.Marshal(tuples)
	return HashCanonical(raw)
}

// Check refuses a settlement whose tables contradict each other.
func (s *Settlement) Check() error {
	if s == nil {
		return nil
	}
	for group, span := range s.Spans {
		if span == 0 || group == "" {
			return Fail(Corrupt)
		}
	}
	for key, w := range s.Windows {
		if key != SettledKey(w.Group, w.N) || w.Span == 0 || w.Count == 0 || w.Count > w.Span || s.Spans[w.Group.String()] != w.Span {
			return Fail(Corrupt)
		}
		if err := w.checkParts(); err != nil {
			return err
		}
	}
	return nil
}

// checkParts refuses an incomplete record whose parts contradict it: a complete window carries none, an
// incomplete one carries distinct parts of a window that is cut into parts, in order, each holding at most
// a part's commands, summing to the record's count, and it has no window digest yet.
func (w SettledWindow) checkParts() error {
	if w.Complete() {
		if len(w.Parts) != 0 {
			return Fail(Corrupt)
		}
		return nil
	}
	if w.Part >= w.Span || w.Span%w.Part != 0 || len(w.Parts) == 0 || w.Charge != (Hash{}) {
		return Fail(Corrupt)
	}
	var sum uint64
	for i, p := range w.Parts {
		if uint64(p.J) >= w.Span/w.Part || i > 0 && p.J <= w.Parts[i-1].J || p.Count == 0 || p.Count > w.Part {
			return Fail(Corrupt)
		}
		sum += p.Count
	}
	if sum != w.Count {
		return Fail(Corrupt)
	}
	return nil
}

// Equal reports whether two records are the same record.
func (w SettledWindow) Equal(o SettledWindow) bool {
	if w.Group != o.Group || w.N != o.N || w.Span != o.Span || w.Count != o.Count || w.Charge != o.Charge || w.Part != o.Part || len(w.Parts) != len(o.Parts) {
		return false
	}
	for i := range w.Parts {
		if w.Parts[i] != o.Parts[i] {
			return false
		}
	}
	return true
}
