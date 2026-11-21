// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package refledger

import (
	"bytes"
	"encoding/json"
	"maps"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// previousRelease is the ledger index of release 5475ef6, verbatim in behavior: one whole-project index and its
// anchor under artifact_refs_index:<project> and artifact_refs_index:anchor:<project>, nothing else read.
type previousRelease struct{}

func (previousRelease) loadIndex(settings map[string]json.RawMessage, project model.ID) (map[string]IndexEntry, error) {
	raw, hasIndex := settings[LegacyIndexKey(project)]
	rawAnchor, hasAnchor := settings[LegacyAnchorKey(project)]
	switch {
	case !hasIndex && !hasAnchor:
		return map[string]IndexEntry{}, nil
	case !hasIndex:
		return nil, model.Fail(model.Corrupt)
	}
	var idx map[string]IndexEntry
	if model.StrictJSON(raw, &idx) != nil || idx == nil {
		return nil, model.Fail(model.Corrupt)
	}
	if hasAnchor {
		var a anchor
		if model.StrictJSON(rawAnchor, &a) != nil || a.Version != Version || a.Roots != len(idx) || a.Index != model.HashCanonical(raw) {
			return nil, model.Fail(model.Corrupt)
		}
	}
	return idx, nil
}

func (p previousRelease) load(settings map[string]json.RawMessage, project, root model.ID) (*Ledger, error) {
	idx, err := p.loadIndex(settings, project)
	if err != nil {
		return nil, err
	}
	ie, indexed := idx[root.String()]
	raw, stored := settings[LedgerKey(project, root)]
	if !stored && !indexed {
		return nil, nil
	}
	if stored != indexed {
		return nil, model.Fail(model.Corrupt)
	}
	var l Ledger
	if model.StrictJSON(raw, &l) != nil || l.Version != Version || l.Project != project || l.Root != root || len(l.Entries) > MaxEntries || l.Head != l.digest() || l.Seq != ie.Seq || l.Head != ie.Head {
		return nil, model.Fail(model.Corrupt)
	}
	return &l, nil
}

func (p previousRelease) store(settings map[string]json.RawMessage, project model.ID, l *Ledger) error {
	idx, err := p.loadIndex(settings, project)
	if err != nil {
		return err
	}
	l.Version = Version
	l.Head = l.digest()
	raw, _ := json.Marshal(l)
	settings[LedgerKey(project, l.Root)] = raw
	idx[l.Root.String()] = IndexEntry{Seq: l.Seq, Head: l.Head}
	rawIndex, _ := json.Marshal(idx)
	rawAnchor, _ := json.Marshal(anchor{Version: Version, Roots: len(idx), Index: model.HashCanonical(rawIndex)})
	settings[LegacyIndexKey(project)] = rawIndex
	settings[LegacyAnchorKey(project)] = rawAnchor
	return nil
}

// bothRead requires every ledger to load, and to be the same, in the previous release and in this one.
func (f *fx) bothRead(ledgers ...*Ledger) {
	f.t.Helper()
	for _, l := range ledgers {
		old, oerr := previousRelease{}.load(f.org.Settings, f.project, l.Root)
		now, nerr := f.load(l)
		if oerr != nil || nerr != nil || old == nil || now == nil || old.Head != now.Head || old.Seq != now.Seq {
			f.t.Fatalf("root %s: previous release %v (%v), this release %v (%v)", l.Root, old, oerr, now, nerr)
		}
	}
}

// Before the contraction a write keeps the whole-project index of the previous release current, so a voter
// rolled back to that release reads every ledger (D70).
func TestExpandedWritesStayReadableByThePreviousRelease(t *testing.T) {
	f := newExpandedFx(t)
	var all []*Ledger
	for round := range 3 {
		var batch []*Ledger
		for i := range 25 {
			batch = append(batch, f.ledger(Entry{Kind: KindError, Cursor: cursor(uint64(round*25 + i + 1)), RetainUntil: 100}))
		}
		f.store(batch...)
		all = append(all, batch...)
		f.bothRead(all...)
	}
	// An update of an existing ledger (Seq 2) is read at its new Seq by both.
	again := &Ledger{Project: f.project, Root: all[3].Root, Seq: 2, Entries: []Entry{{Kind: KindBuild, Cursor: cursor(200), RetainUntil: 900}}}
	f.store(again)
	f.bothRead(all...)
	if got, _ := f.load(again); got == nil || got.Seq != 2 {
		t.Fatalf("update not read: %+v", got)
	}
}

// The previous release may write after a rollback: its ledger and its whole-project index are all it knows.
// This release then reads that ledger (the shard is behind) and its next write brings the shard up to date.
func TestExpandedLoadFollowsAWriteOfThePreviousRelease(t *testing.T) {
	f := newExpandedFx(t)
	a, b := f.ledger(Entry{Kind: KindError, Cursor: cursor(1), RetainUntil: 100}), f.ledger(Entry{Kind: KindError, Cursor: cursor(2), RetainUntil: 100})
	f.store(a, b)
	// The previous release updates a and creates c, writing nothing but its own layout.
	a2 := &Ledger{Project: f.project, Root: a.Root, Seq: 2, Entries: []Entry{{Kind: KindProfile, Cursor: cursor(3), RetainUntil: 700}}}
	c := f.ledger(Entry{Kind: KindBuild, Cursor: cursor(4), RetainUntil: 300})
	for _, l := range []*Ledger{a2, c} {
		if err := (previousRelease{}).store(f.org.Settings, f.project, l); err != nil {
			t.Fatal(err)
		}
	}
	f.bothRead(a2, c, b)
	// A write of this release on top keeps everyone consistent, whatever the shard state was.
	d := f.ledger(Entry{Kind: KindError, Cursor: cursor(5), RetainUntil: 100})
	f.store(d)
	f.bothRead(a2, b, c, d)
	// A ledger this release wrote is read by the previous release at its latest Seq too.
	b2 := &Ledger{Project: f.project, Root: b.Root, Seq: 2, Entries: []Entry{{Kind: KindProfile, Cursor: cursor(6), RetainUntil: 800}}}
	f.store(b2)
	f.bothRead(a2, b2, c, d)
}

// A tampered whole-project index is refused by the expanded write, not papered over.
func TestExpandedWriteRefusesATamperedWholeProjectIndex(t *testing.T) {
	f := newExpandedFx(t)
	a := f.ledger(Entry{Kind: KindError, Cursor: cursor(1), RetainUntil: 100})
	f.store(a)
	f.org.Settings[LegacyIndexKey(f.project)] = json.RawMessage(`{}`)
	if err := Store(&f.org, f.project, f.ledger(Entry{Kind: KindError, Cursor: cursor(2), RetainUntil: 1})); code(err) != model.Corrupt {
		t.Fatalf("a write over a tampered whole-project index: %v", err)
	}
}

// Contract removes the previous release's values, keeps every ledger readable (including what the previous
// release wrote last), marks the organization, and is idempotent. Afterwards a write touches one ledger and
// one shard whatever the size of the project.
func TestContractDropsThePerProjectIndexAndMakesWritesBounded(t *testing.T) {
	const n = 3000
	f := newExpandedFx(t)
	var all []*Ledger
	for i := range n {
		l := f.ledger(Entry{Kind: KindError, Cursor: cursor(uint64(i%200 + 1)), RetainUntil: 100})
		l.Retired = true
		all = append(all, l)
	}
	f.store(all...)
	late := &Ledger{Project: f.project, Root: all[7].Root, Seq: 2, Retired: true, Entries: []Entry{{Kind: KindBuild, Cursor: cursor(9), RetainUntil: 500}}}
	if err := (previousRelease{}).store(f.org.Settings, f.project, late); err != nil {
		t.Fatal(err)
	}
	changed, err := Contract(&f.org)
	if err != nil || !changed {
		t.Fatalf("contract: %v %v", changed, err)
	}
	if _, ok := f.org.Settings[LegacyIndexKey(f.project)]; ok {
		t.Fatal("the whole-project index survived the contraction")
	}
	if _, ok := f.org.Settings[LegacyAnchorKey(f.project)]; ok {
		t.Fatal("the whole-project anchor survived the contraction")
	}
	if !f.org.IndexesContracted() {
		t.Fatal("the organization is not marked contracted")
	}
	for _, l := range all {
		got, err := f.load(l)
		if err != nil || got == nil {
			t.Fatalf("after the contraction: %v %v", got, err)
		}
		if l.Root == late.Root && got.Seq != 2 {
			t.Fatalf("the ledger the previous release wrote last was lost: Seq %d", got.Seq)
		}
	}
	if changed, err := Contract(&f.org); err != nil || changed {
		t.Fatalf("a second contraction: %v %v", changed, err)
	}
	before := map[string]json.RawMessage{}
	for k, v := range f.org.Settings {
		before[k] = bytes.Clone(v)
	}
	f.store(f.ledger(Entry{Kind: KindError, Cursor: cursor(1), RetainUntil: 100}))
	changedBytes := 0
	for k, v := range f.org.Settings {
		if !bytes.Equal(before[k], v) {
			changedBytes += len(k) + len(v)
		}
	}
	if changedBytes > 24<<10 {
		t.Fatalf("one ledger write changed %d bytes of Settings after the contraction in a project of %d ledgers; want one ledger and one shard", changedBytes, n)
	}
	for k := range f.org.Settings {
		if k == LegacyIndexKey(f.project) || k == LegacyAnchorKey(f.project) {
			t.Fatalf("a write after the contraction wrote %s", k)
		}
	}
}

// A contraction over a whole-project index that does not verify changes nothing.
func TestContractRefusesATamperedWholeProjectIndex(t *testing.T) {
	f := newExpandedFx(t)
	f.store(f.ledger(Entry{Kind: KindError, Cursor: cursor(1), RetainUntil: 100}))
	f.org.Settings[LegacyIndexKey(f.project)] = json.RawMessage(`{}`)
	snapshot := maps.Clone(f.org.Settings)
	if _, err := Contract(&f.org); code(err) != model.Corrupt {
		t.Fatalf("contract over a tampered index: %v", err)
	}
	if len(snapshot) != len(f.org.Settings) || f.org.IndexesContracted() {
		t.Fatal("a refused contraction changed the organization")
	}
}

// A crash cannot leave a torn state (one control transition carries the ledger, the whole-project index and the
// shards), but a state that holds only some of the keys of a write must still be read consistently by this
// release: the whole-project index and the ledger are the authority before the contraction, the shards follow.
func TestExpandedReadsAreConsistentForAnySubsetOfTheShardKeys(t *testing.T) {
	f := newExpandedFx(t)
	var ls []*Ledger
	for i := range 10 {
		ls = append(ls, f.ledger(Entry{Kind: KindError, Cursor: cursor(uint64(i + 1)), RetainUntil: 100}))
	}
	f.store(ls...)
	l := &Ledger{Project: f.project, Root: ls[0].Root, Seq: 2, Entries: []Entry{{Kind: KindBuild, Cursor: cursor(50), RetainUntil: 400}}}
	next := &fx{t: t, project: f.project, org: model.ControlOrg{Settings: maps.Clone(f.org.Settings)}}
	next.store(l)
	// A shard is never written without its anchor (they are one write) and the previous release writes neither:
	// a shard whose anchor disagrees is an edit and stays corrupt in the expanded phase too.
	shard, anchorKey := ShardIndexKey(f.project, l.Root), ShardAnchorKey(f.project, l.Root)
	for _, keep := range [][]string{{}, {shard, anchorKey}} {
		torn := &fx{t: t, project: f.project, org: model.ControlOrg{Settings: maps.Clone(f.org.Settings)}}
		torn.org.Settings[LedgerKey(f.project, l.Root)] = next.org.Settings[LedgerKey(f.project, l.Root)]
		torn.org.Settings[LegacyIndexKey(f.project)] = next.org.Settings[LegacyIndexKey(f.project)]
		torn.org.Settings[LegacyAnchorKey(f.project)] = next.org.Settings[LegacyAnchorKey(f.project)]
		for _, k := range keep {
			torn.org.Settings[k] = next.org.Settings[k]
		}
		torn.bothRead(append([]*Ledger{l}, ls[1:]...)...)
	}
}

// A shard edited by hand is corrupt in the expanded phase as it is once contracted: the previous release never
// writes shards, so a shard that disagrees with its own anchor is not a rollback artifact.
func TestExpandedShardEditedByHandIsCorrupt(t *testing.T) {
	f := newExpandedFx(t)
	a := f.ledger(Entry{Kind: KindError, Cursor: cursor(1), RetainUntil: 100})
	f.store(a)
	f.index(a.Root, func(idx map[string]IndexEntry) { idx[model.NewID().String()] = IndexEntry{Seq: 1} })
	if got, err := f.load(a); code(err) != model.Corrupt {
		t.Fatalf("an edited shard was read: %v %v", got, err)
	}
}
