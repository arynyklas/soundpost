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

// SettledWindow is one data-group window whose consumed reservations control no longer holds.
type SettledWindow struct {
	Group ID     `json:"group"`
	N     uint64 `json:"n,string"`
	Span  uint64 `json:"span,string"`
	// Count is the number of reservations the window settled.
	Count uint64 `json:"count,string"`
	// Charge is ChargeDigest of those reservations; the data window's own charge digest equals it.
	Charge Hash `json:"charge"`
}

// SettledCharge is the charge settled reservations put on one quota key.
type SettledCharge struct {
	Bytes  Uint64            `json:"bytes"`
	Series map[string]uint64 `json:"series"`
}

// SettleCandidate is a sealed data window a storage engine offers for settlement: the window it
// holds, how many batches (consumed reservations) it carries and their charge digest. Windows
// that carry a redacted batch are never offered.
type SettleCandidate struct {
	Group   ID     `json:"group"`
	N       uint64 `json:"n,string"`
	Span    uint64 `json:"span,string"`
	Batches uint64 `json:"batches,string"`
	Charge  Hash   `json:"charge"`
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

// Window returns the settled window the cursor falls into, if there is one.
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
	}
	return nil
}
