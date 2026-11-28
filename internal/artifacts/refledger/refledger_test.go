// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package refledger

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

func code(err error) model.Code {
	var f *model.Fault
	if errors.As(err, &f) {
		return f.Code
	}
	return ""
}

func cursor(n uint64) model.Cursor {
	var g model.ID
	g[0], g[15] = 1, byte(n)
	return model.Cursor{Group: g, Index: model.Uint64(n)}
}

type fx struct {
	t       *testing.T
	project model.ID
	org     model.ControlOrg
}

// newFx is an organization whose indexes are contracted (the sharded layout alone); newExpandedFx is one
// the operator has not contracted yet (D70), which keeps the previous release's whole-project index too.
func newFx(t *testing.T) *fx {
	return &fx{t: t, project: model.NewID(), org: model.ControlOrg{Settings: map[string]json.RawMessage{model.IndexesContractedKey: json.RawMessage(`true`)}}}
}

func newExpandedFx(t *testing.T) *fx {
	return &fx{t: t, project: model.NewID(), org: model.ControlOrg{Settings: map[string]json.RawMessage{}}}
}

func (f *fx) ledger(entries ...Entry) *Ledger {
	return &Ledger{Project: f.project, Root: model.NewID(), Seq: 1, Entries: entries}
}

// ledgerIn is a ledger whose root falls in the same index shard as like's: the anchor of a shard
// covers the roots of that shard only.
func (f *fx) ledgerIn(like *Ledger, entries ...Entry) *Ledger {
	l := f.ledger(entries...)
	l.Root[0] = like.Root[0]
	return l
}

func (f *fx) store(ls ...*Ledger) {
	f.t.Helper()
	if err := Store(&f.org, f.project, ls...); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fx) load(l *Ledger) (*Ledger, error) { return Load(f.org.Settings, f.project, l.Root) }

// index rewrites the stored index shard of root with fn, leaving its anchor untouched.
func (f *fx) index(root model.ID, fn func(map[string]IndexEntry)) {
	f.t.Helper()
	var idx map[string]IndexEntry
	if err := json.Unmarshal(f.org.Settings[ShardIndexKey(f.project, root)], &idx); err != nil {
		f.t.Fatal(err)
	}
	fn(idx)
	raw, err := json.Marshal(idx)
	if err != nil {
		f.t.Fatal(err)
	}
	f.org.Settings[ShardIndexKey(f.project, root)] = raw
}

// A ledger together with its own index entry is removed (the shard is rewritten without it):
// the ledger and the index agree that the root never had a ledger, and only the anchor over the
// shard tells that an entry is missing. Every root of that shard then fails closed.
func TestAnchorDetectsRemovedLedgerWithItsIndexEntry(t *testing.T) {
	f := newFx(t)
	a := f.ledger(Entry{Kind: KindError, Cursor: cursor(1), RetainUntil: 100})
	b := f.ledgerIn(a, Entry{Kind: KindBuild, Cursor: cursor(2), RetainUntil: 200})
	f.store(a, b)
	for _, l := range []*Ledger{a, b} {
		if got, err := f.load(l); err != nil || got == nil {
			t.Fatalf("setup: %v", err)
		}
	}
	delete(f.org.Settings, LedgerKey(f.project, a.Root))
	f.index(a.Root, func(idx map[string]IndexEntry) { delete(idx, a.Root.String()) })
	for name, l := range map[string]*Ledger{"the removed root": a, "its sibling": b} {
		if got, err := f.load(l); code(err) != model.Corrupt {
			t.Errorf("%s: loaded %v, %v after the ledger and its index entry were removed", name, got, err)
		}
	}
}

// The whole shard index removed while the ledgers and the anchor stay.
func TestAnchorDetectsRemovedIndex(t *testing.T) {
	f := newFx(t)
	a := f.ledger(Entry{Kind: KindError, Cursor: cursor(1), RetainUntil: 100})
	f.store(a)
	delete(f.org.Settings, ShardIndexKey(f.project, a.Root))
	if got, err := f.load(a); code(err) != model.Corrupt {
		t.Fatalf("loaded %v, %v with the index removed", got, err)
	}
	// A root with no ledger at all is the same shard state: fail closed for every root of it.
	unknown := f.ledgerIn(a)
	if got, err := f.load(unknown); code(err) != model.Corrupt {
		t.Fatalf("an unknown root loaded %v, %v under an anchor without an index", got, err)
	}
}

// An entry added to the index by hand (no ledger behind it, anchor not updated) is detected too.
func TestAnchorDetectsAnIndexEntryAddedByHand(t *testing.T) {
	f := newFx(t)
	a := f.ledger(Entry{Kind: KindError, Cursor: cursor(1), RetainUntil: 100})
	f.store(a)
	f.index(a.Root, func(idx map[string]IndexEntry) { idx[f.ledgerIn(a).Root.String()] = IndexEntry{Seq: 1} })
	if got, err := f.load(a); code(err) != model.Corrupt {
		t.Fatalf("loaded %v, %v with a foreign index entry", got, err)
	}
}

// A shard written before anchors existed (ledgers and index, no anchor) still loads; the next
// write anchors it, after which the same removals are detected.
func TestProjectWithoutAnchorLoadsAndIsAnchoredByTheNextWrite(t *testing.T) {
	f := newFx(t)
	a := f.ledger(Entry{Kind: KindError, Cursor: cursor(1), RetainUntil: 100})
	b := f.ledgerIn(a, Entry{Kind: KindBuild, Cursor: cursor(2), RetainUntil: 200})
	f.store(a, b)
	delete(f.org.Settings, ShardAnchorKey(f.project, a.Root))
	if got, err := f.load(a); err != nil || got == nil {
		t.Fatalf("an unanchored project does not load: %v", err)
	}
	c := f.ledgerIn(a, Entry{Kind: KindProfile, Cursor: cursor(3), RetainUntil: 300})
	f.store(c)
	if _, ok := f.org.Settings[ShardAnchorKey(f.project, a.Root)]; !ok {
		t.Fatal("the write did not anchor the shard")
	}
	delete(f.org.Settings, LedgerKey(f.project, b.Root))
	f.index(b.Root, func(idx map[string]IndexEntry) { delete(idx, b.Root.String()) })
	if _, err := f.load(a); code(err) != model.Corrupt {
		t.Fatalf("removal after anchoring was not detected: %v", err)
	}
}

// A write over a tampered index is refused: a later honest write must not paper over it.
func TestStoreRefusesToRewriteATamperedIndex(t *testing.T) {
	f := newFx(t)
	a := f.ledger(Entry{Kind: KindError, Cursor: cursor(1), RetainUntil: 100})
	f.store(a)
	f.index(a.Root, func(idx map[string]IndexEntry) { idx[f.ledgerIn(a).Root.String()] = IndexEntry{Seq: 1} })
	if err := Store(&f.org, f.project, f.ledgerIn(a, Entry{Kind: KindError, Cursor: cursor(5), RetainUntil: 1})); code(err) != model.Corrupt {
		t.Fatalf("a write over a tampered index: %v", err)
	}
}

func TestEffectiveRetention(t *testing.T) {
	f := newFx(t)
	root := model.NewID()
	manifest := func(until model.UnixNano) model.BlobManifest {
		return model.BlobManifest{Org: model.NewID(), Project: f.project, Root: root, RetainUntil: until}
	}
	state := func(m model.BlobManifest, l *Ledger) model.ControlState {
		o := model.ControlOrg{Settings: map[string]json.RawMessage{}}
		if l != nil {
			l.Project, l.Root = f.project, root
			if err := Store(&o, f.project, l); err != nil {
				t.Fatal(err)
			}
		}
		return model.ControlState{Orgs: map[string]model.ControlOrg{m.Org.String(): o}}
	}
	for _, tc := range []struct {
		name    string
		upload  model.UnixNano
		ledger  *Ledger
		until   model.UnixNano
		retired bool
	}{
		{"no ledger: the upload's own deadline", 100, nil, 100, false},
		{"a later reference extends", 100, &Ledger{Entries: []Entry{{Kind: KindError, Cursor: cursor(1), RetainUntil: 500}}}, 500, false},
		{"an earlier reference does not shorten", 100, &Ledger{Entries: []Entry{{Kind: KindError, Cursor: cursor(1), RetainUntil: 50}}}, 100, false},
		{"the latest of several", 100, &Ledger{Entries: []Entry{{Kind: KindError, Cursor: cursor(1), RetainUntil: 300}, {Kind: KindBuild, Cursor: cursor(2), RetainUntil: 700}, {Kind: KindIssue, Cursor: model.Cursor{Group: model.NewID()}, RetainUntil: 400}}}, 700, false},
		{"a released reference does not hold", 100, &Ledger{Entries: []Entry{{Kind: KindError, Cursor: cursor(1), RetainUntil: 900, Released: true}}}, 100, false},
		{"folded references keep the floor", 100, &Ledger{Floor: 800}, 800, false},
		{"the GC fence", 100, &Ledger{Retired: true, Entries: []Entry{{Kind: KindError, Cursor: cursor(1), RetainUntil: 900}}}, 0, true},
		{"no deadline at all", 0, nil, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := manifest(tc.upload)
			until, retired, err := EffectiveRetention(state(m, tc.ledger), m)
			if err != nil || until != tc.until || retired != tc.retired {
				t.Fatalf("got (%d, retired %v, %v), want (%d, retired %v)", until, retired, err, tc.until, tc.retired)
			}
		})
	}
	t.Run("a ledger that does not verify is an error", func(t *testing.T) {
		m := manifest(100)
		st := state(m, &Ledger{Entries: []Entry{{Kind: KindError, Cursor: cursor(1), RetainUntil: 500}}})
		o := st.Orgs[m.Org.String()]
		o.Settings[LedgerKey(f.project, root)] = json.RawMessage(`{"Version":1}`)
		if _, _, err := EffectiveRetention(st, m); code(err) != model.Corrupt {
			t.Fatalf("a garbage ledger answered %v", err)
		}
	})
}

// An issue hold has no origin cursor index and is dropped, never marked released: a stored
// ledger that says otherwise is not one the lifecycle wrote.
func TestIssueEntriesFollowTheirOwnRules(t *testing.T) {
	issue := model.NewID()
	for _, tc := range []struct {
		name  string
		entry Entry
		ok    bool
	}{
		{"hold of an issue", Entry{Kind: KindIssue, Cursor: model.Cursor{Group: issue}, RetainUntil: 5}, true},
		{"hold with a cursor index", Entry{Kind: KindIssue, Cursor: model.Cursor{Group: issue, Index: 1}, RetainUntil: 5}, false},
		{"hold of no issue", Entry{Kind: KindIssue, RetainUntil: 5}, false},
		{"released hold", Entry{Kind: KindIssue, Cursor: model.Cursor{Group: issue}, RetainUntil: 5, Released: true}, false},
		{"error with no index", Entry{Kind: KindError, Cursor: model.Cursor{Group: issue}, RetainUntil: 5}, false},
		{"unknown kind", Entry{Kind: "url", Cursor: cursor(1), RetainUntil: 5}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFx(t)
			l := f.ledger(tc.entry)
			// An entry with no issue cannot even be sealed (a zero ID does not encode).
			err := Store(&f.org, f.project, l)
			if err == nil {
				_, err = f.load(l)
			}
			if tc.ok != (err == nil) {
				t.Fatalf("ok=%v but Load answered %v", tc.ok, err)
			}
		})
	}
}

// A full ledger folds the live issue holds with the earliest deadlines into the floor: room is
// made, and the map is retained at least as long as before (a fold only lengthens retention).
func TestMakeRoomFoldsIssueHoldsWithoutShorteningRetention(t *testing.T) {
	var l Ledger
	var latest model.UnixNano
	for i := range MaxEntries {
		until := model.UnixNano(1000 + 10*i)
		latest = max(latest, until)
		l.Entries = append(l.Entries, Entry{Kind: KindIssue, Cursor: model.Cursor{Group: model.NewID()}, RetainUntil: until})
	}
	before := l.Latest()
	if !l.MakeRoom(500) {
		t.Fatal("a ledger of live issue holds could not make room")
	}
	if len(l.Entries) >= MaxEntries {
		t.Fatalf("no room made: %d entries", len(l.Entries))
	}
	if l.Latest() < before || l.Latest() != latest {
		t.Fatalf("retention changed from %d to %d by folding", before, l.Latest())
	}
	if l.Floor == 0 {
		t.Fatal("the folded holds left no floor")
	}
	// Non-issue entries are never folded: a ledger full of them has no room.
	var full Ledger
	for i := range MaxEntries {
		full.Entries = append(full.Entries, Entry{Kind: KindError, Cursor: cursor(uint64(i + 1)), RetainUntil: 1000})
	}
	if full.MakeRoom(500) {
		t.Fatal("a ledger full of live references made room")
	}
}

func TestHolderRoundTripAndLimits(t *testing.T) {
	f := newFx(t)
	issue := model.NewID()
	h := Holder{Roots: []model.ID{model.NewID(), model.NewID()}, Until: 77, Held: true}
	if err := PutHolder(&f.org, f.project, issue, h); err != nil {
		t.Fatal(err)
	}
	got, err := LoadHolder(f.org.Settings, f.project, issue)
	if err != nil || got == nil || got.Until != 77 || !got.Held || len(got.Roots) != 2 || got.Roots[0] != h.Roots[0] {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	if none, err := LoadHolder(f.org.Settings, f.project, model.NewID()); err != nil || none != nil {
		t.Fatalf("a missing holder: %v %v", none, err)
	}
	seen := 0
	EachHolder(f.org.Settings, f.project, func(i model.ID, h *Holder, err error) {
		if i != issue || err != nil || h == nil {
			t.Errorf("each: %s %v %v", i, h, err)
		}
		seen++
	})
	if seen != 1 {
		t.Fatalf("EachHolder visited %d holders", seen)
	}
	// Another project's holders are not visited.
	EachHolder(f.org.Settings, model.NewID(), func(model.ID, *Holder, error) { t.Error("visited a foreign project's holder") })
	tooMany := Holder{Until: 1}
	for range MaxHolderRoots + 1 {
		tooMany.Roots = append(tooMany.Roots, model.NewID())
	}
	if err = PutHolder(&f.org, f.project, issue, tooMany); err != nil {
		t.Fatal(err)
	}
	if _, err = LoadHolder(f.org.Settings, f.project, issue); code(err) != model.Corrupt {
		t.Fatalf("an oversized holder loaded: %v", err)
	}
	DeleteHolder(&f.org, f.project, issue)
	if none, _ := LoadHolder(f.org.Settings, f.project, issue); none != nil {
		t.Fatal("DeleteHolder left the holder")
	}
}
