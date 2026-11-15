// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

// Package refledger is the durable state of artifact references. It is a leaf
// (model only) so that the control and auth packages, which cannot import
// internal/artifacts, can read the same verified state the lifecycle writes.
//
// Every key lives in an organization's Settings map, under the model.ArtifactLedgerKeyPrefix or
// model.ArtifactLedgerIndexKeyPrefix family, so a write of nothing but these keys does not move
// the control AuthorityRevision (control.Store.UpdateArtifactReferences):
//
//	artifact_refs:<project>:<root>                 the ledger of one artifact root (authoritative)
//	artifact_refs_index:<project>                  root -> (Seq, Head) of every ledger of the project
//	artifact_refs_index:anchor:<project>           (count, digest) of the stored index bytes
//	artifact_refs_index:holder:<project>:<issue>   the roots an issue holds (advisory, see Holder)
//
// A ledger carries a digest over itself (Head); the index pins (Seq, Head) of each ledger, so an
// edited, removed or rolled-back ledger is Corrupt; the anchor pins the index bytes, so a ledger
// together with its index entry cannot be removed unseen either.
package refledger

import (
	"encoding/json"
	"slices"

	"github.com/arynyklas/soundpost/internal/model"
)

// The kinds of retained usage that keep a map. The set is closed.
const (
	KindError   = "error"
	KindProfile = "profile"
	KindBuild   = "build"
	// KindIssue is an open issue that groups occurrences naming the map. It is identified
	// by the issue alone (cursor group = issue ID, index 0), is never tombstoned (an issue that
	// reopens holds the map again) and is dropped, not marked, when the issue stops being open.
	KindIssue = "issue"
)

const (
	LedgerPrefix = model.ArtifactLedgerKeyPrefix
	IndexPrefix  = model.ArtifactLedgerIndexKeyPrefix
	anchorPrefix = model.ArtifactLedgerIndexKeyPrefix + "anchor:"
	holderPrefix = model.ArtifactLedgerIndexKeyPrefix + "holder:"

	// Version is the ledger format.
	Version = 1
	// MaxEntries bounds one ledger.
	MaxEntries = 1024
	// MaxHolderRoots bounds the maps one issue holds.
	MaxHolderRoots = 32
)

// ValidOrigin reports whether kind and cursor name a retained usage in canonical form.
func ValidOrigin(kind string, c model.Cursor) bool {
	switch kind {
	case KindError, KindProfile, KindBuild:
		return c.Group != (model.ID{}) && c.Index != 0
	case KindIssue:
		return c.Group != (model.ID{}) && c.Index == 0
	}
	return false
}

// Entry is one retained usage.
type Entry struct {
	Kind        string         `json:"kind"`
	Cursor      model.Cursor   `json:"cursor"`
	RetainUntil model.UnixNano `json:"retain_until_ns"`
	Released    bool           `json:"released,omitempty"`
}

// Ledger is the complete reference state of one artifact root. Head is a digest over
// everything else.
type Ledger struct {
	Version int            `json:"Version"`
	Project model.ID       `json:"Project"`
	Root    model.ID       `json:"Root"`
	Seq     uint64         `json:"Seq"`
	Retired bool           `json:"Retired"`
	Floor   model.UnixNano `json:"Floor"` // latest deadline of entries compacted away
	Entries []Entry        `json:"Entries"`
	Head    model.Hash     `json:"Head"`
}

// IndexEntry pins one ledger.
type IndexEntry struct {
	Seq  uint64     `json:"Seq"`
	Head model.Hash `json:"Head"`
}

type anchor struct {
	Version int        `json:"Version"`
	Roots   int        `json:"Roots"`
	Index   model.Hash `json:"Index"`
}

func (l Ledger) digest() model.Hash {
	l.Head = model.Hash{}
	raw, err := model.CanonicalJSON(l)
	if err != nil {
		return model.Hash{}
	}
	return model.HashCanonical(raw)
}

// Latest is the latest deadline any unreleased entry still holds (zero for a nil ledger).
func (l *Ledger) Latest() model.UnixNano {
	if l == nil {
		return 0
	}
	out := l.Floor
	for _, e := range l.Entries {
		if !e.Released && e.RetainUntil > out {
			out = e.RetainUntil
		}
	}
	return out
}

// Compact folds expired entries into Floor. Released tombstones stay: they are what keeps a
// released occurrence from being revived.
func (l *Ledger) Compact(now model.UnixNano) {
	kept := l.Entries[:0]
	for _, e := range l.Entries {
		if !e.Released && e.RetainUntil <= now {
			l.Floor = max(l.Floor, e.RetainUntil)
			continue
		}
		kept = append(kept, e)
	}
	l.Entries = kept
}

// MakeRoom reports whether one more entry fits, after folding what can be folded: expired
// entries first, then (still full) the quarter of live issue holds with the earliest deadlines.
// A folded hold keeps retaining the map until Floor but can no longer be released early: the
// fold only ever lengthens retention, never shortens it.
func (l *Ledger) MakeRoom(now model.UnixNano) bool {
	if len(l.Entries) < MaxEntries {
		return true
	}
	l.Compact(now)
	if len(l.Entries) < MaxEntries {
		return true
	}
	var holds []int
	for i, e := range l.Entries {
		if e.Kind == KindIssue && !e.Released {
			holds = append(holds, i)
		}
	}
	if len(holds) == 0 {
		return false
	}
	slices.SortStableFunc(holds, func(a, b int) int {
		switch {
		case l.Entries[a].RetainUntil < l.Entries[b].RetainUntil:
			return -1
		case l.Entries[a].RetainUntil > l.Entries[b].RetainUntil:
			return 1
		}
		return 0
	})
	folded := make(map[int]bool, MaxEntries/4)
	for _, i := range holds[:min(len(holds), MaxEntries/4)] {
		l.Floor = max(l.Floor, l.Entries[i].RetainUntil)
		folded[i] = true
	}
	kept := l.Entries[:0]
	for i, e := range l.Entries {
		if !folded[i] {
			kept = append(kept, e)
		}
	}
	l.Entries = kept
	return len(l.Entries) < MaxEntries
}

// LedgerKey, IndexKey and AnchorKey are the Settings keys of a project's state.
func LedgerKey(project, root model.ID) string {
	return LedgerPrefix + project.String() + ":" + root.String()
}
func IndexKey(project model.ID) string  { return IndexPrefix + project.String() }
func AnchorKey(project model.ID) string { return anchorPrefix + project.String() }

// loadIndex returns the project's index and, when one is stored, verifies it against its anchor.
// An anchor with no index, or an index that is not the one the anchor pinned, is Corrupt (an
// entry, or the whole index, was removed or rewritten without its ledger writer). An index with
// no anchor is a project written before anchors existed: it is accepted and the next write
// anchors it.
func loadIndex(settings map[string]json.RawMessage, project model.ID) (map[string]IndexEntry, error) {
	raw, hasIndex := settings[IndexKey(project)]
	rawAnchor, hasAnchor := settings[AnchorKey(project)]
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

// Load returns the verified ledger, nil when the root has none, and Corrupt for any disagreement
// between the ledger, the index and the anchor.
func Load(settings map[string]json.RawMessage, project, root model.ID) (*Ledger, error) {
	idx, err := loadIndex(settings, project)
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
	for _, e := range l.Entries {
		if !ValidOrigin(e.Kind, e.Cursor) || e.Kind == KindIssue && e.Released {
			return nil, model.Fail(model.Corrupt)
		}
	}
	return &l, nil
}

// Store seals the ledgers and writes them with the project's index entries and anchor, in the
// organization's Settings. The index is verified before it is rewritten, so a tampered index is
// never papered over by a later write. Every ledger must belong to project.
func Store(o *model.ControlOrg, project model.ID, ledgers ...*Ledger) error {
	if len(ledgers) == 0 {
		return nil
	}
	if o.Settings == nil {
		o.Settings = map[string]json.RawMessage{}
	}
	idx, err := loadIndex(o.Settings, project)
	if err != nil {
		return err
	}
	for _, l := range ledgers {
		if l.Project != project {
			return model.Fail(model.Invalid)
		}
		l.Version = Version
		l.Head = l.digest()
		raw, err := json.Marshal(l)
		if err != nil {
			return model.Fail(model.Corrupt)
		}
		o.Settings[LedgerKey(project, l.Root)] = raw
		idx[l.Root.String()] = IndexEntry{Seq: l.Seq, Head: l.Head}
	}
	rawIndex, err := json.Marshal(idx)
	if err != nil {
		return model.Fail(model.Corrupt)
	}
	rawAnchor, err := json.Marshal(anchor{Version: Version, Roots: len(idx), Index: model.HashCanonical(rawIndex)})
	if err != nil {
		return model.Fail(model.Corrupt)
	}
	o.Settings[IndexKey(project)] = rawIndex
	o.Settings[AnchorKey(project)] = rawAnchor
	return nil
}

// EffectiveRetention is the deadline until which the artifact root of m is retained: the later of
// the upload's own deadline and every unreleased reference (zero: no deadline). retired reports
// the GC fence. A ledger that does not verify is an error: nothing can be said about the root.
func EffectiveRetention(st model.ControlState, m model.BlobManifest) (until model.UnixNano, retired bool, err error) {
	led, err := Load(st.Orgs[m.Org.String()].Settings, m.Project, m.Root)
	if err != nil {
		return 0, false, err
	}
	if led != nil && led.Retired {
		return 0, true, nil
	}
	if m.RetainUntil == 0 {
		return 0, false, nil
	}
	return max(m.RetainUntil, led.Latest()), false, nil
}

// Holder is what one issue holds: the artifact roots its occurrences name and the latest
// deadline any of them can still need. It is an index over the ledgers' issue entries so that
// releasing an issue does not scan every ledger of the project. It is advisory: a ledger
// entry is authoritative, and a holder that is missing or lost only means the entries lapse at
// their own deadline instead of when the issue stops being open (never earlier).
type Holder struct {
	Roots []model.ID     `json:"roots"`
	Until model.UnixNano `json:"until_ns"`
	// Held is whether the ledgers carry the issue's entries right now. A holder of an issue
	// that is not open keeps its roots with Held false, so a reopening takes the holds again.
	Held bool `json:"held"`
}

// HolderPrefix is the Settings key prefix of every holder of one project.
func HolderPrefix(project model.ID) string { return holderPrefix + project.String() + ":" }

// HolderKey is the Settings key of one issue's holder.
func HolderKey(project, issue model.ID) string { return HolderPrefix(project) + issue.String() }

// LoadHolder returns the issue's holder, nil when it has none. A holder that does not parse is
// Corrupt; the caller decides whether an advisory record may simply be dropped.
func LoadHolder(settings map[string]json.RawMessage, project, issue model.ID) (*Holder, error) {
	raw, ok := settings[HolderKey(project, issue)]
	if !ok {
		return nil, nil
	}
	return decodeHolder(raw)
}

func decodeHolder(raw json.RawMessage) (*Holder, error) {
	var h Holder
	if model.StrictJSON(raw, &h) != nil || len(h.Roots) == 0 || len(h.Roots) > MaxHolderRoots {
		return nil, model.Fail(model.Corrupt)
	}
	for _, r := range h.Roots {
		if r == (model.ID{}) {
			return nil, model.Fail(model.Corrupt)
		}
	}
	return &h, nil
}

// PutHolder writes the issue's holder.
func PutHolder(o *model.ControlOrg, project, issue model.ID, h Holder) error {
	raw, err := json.Marshal(h)
	if err != nil {
		return model.Fail(model.Corrupt)
	}
	if o.Settings == nil {
		o.Settings = map[string]json.RawMessage{}
	}
	o.Settings[HolderKey(project, issue)] = raw
	return nil
}

// DeleteHolder removes the issue's holder.
func DeleteHolder(o *model.ControlOrg, project, issue model.ID) {
	delete(o.Settings, HolderKey(project, issue))
}

// EachHolder calls fn for every holder key of the project, in unspecified order. A key whose
// suffix is not an issue ID is reported with a zero issue so the caller can drop it.
func EachHolder(settings map[string]json.RawMessage, project model.ID, fn func(issue model.ID, h *Holder, err error)) {
	prefix := HolderPrefix(project)
	for key, raw := range settings {
		if len(key) <= len(prefix) || key[:len(prefix)] != prefix {
			continue
		}
		issue, perr := model.ParseID(key[len(prefix):])
		if perr != nil {
			fn(model.ID{}, nil, model.Fail(model.Corrupt))
			continue
		}
		h, err := decodeHolder(raw)
		fn(issue, h, err)
	}
}
