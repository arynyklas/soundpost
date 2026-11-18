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
//	artifact_refs:<project>:<root>                      the ledger of one artifact root (authoritative)
//	artifact_refs_index:shard:<project>:<xx>            root -> (Seq, Head) of the ledgers of one shard
//	artifact_refs_index:shardanchor:<project>:<xx>      (count, digest) of the stored shard bytes
//	artifact_refs_index:holder:<project>:<issue>        the roots an issue holds (advisory, see Holder)
//
// <xx> is the first byte of the root ID in hex: a project's index is 256 shards, so reading or
// writing one ledger parses, hashes and rewrites about 1/256 of the project's index, not all of
// it (a project that ever fenced tens of thousands of maps paid a whole-index cost per artifact
// read and a whole-index rewrite per ledger write before). Two earlier key families are read
// and migrated by the first write of the project:
//
//	artifact_refs_index:<project>                  the whole index in one value (legacy)
//	artifact_refs_index:anchor:<project>           its (count, digest) (legacy)
//
// A ledger carries a digest over itself (Head); the shard index pins (Seq, Head) of each ledger,
// so an edited, removed or rolled-back ledger is Corrupt; the shard anchor pins the shard bytes,
// so a ledger together with its index entry cannot be removed unseen either (every root of that
// shard then fails closed).
//
// Two phases (D70). Until the operator runs `soundpost upgrade contract-indexes` for the
// organization (model.IndexesContractedKey) a write also keeps the whole-project index and its
// anchor current, the layout the previous release reads, so a voter can be rolled back at any
// time; reads use the shards and fall back to the whole-project index for a ledger the previous
// release wrote. Contract rebuilds the shards from it, deletes it, and from then on a write
// touches one ledger and one shard.
package refledger

import (
	"encoding/hex"
	"encoding/json"
	"maps"
	"slices"
	"strings"

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
	LedgerPrefix       = model.ArtifactLedgerKeyPrefix
	IndexPrefix        = model.ArtifactLedgerIndexKeyPrefix
	legacyAnchorPrefix = model.ArtifactLedgerIndexKeyPrefix + "anchor:"
	holderPrefix       = model.ArtifactLedgerIndexKeyPrefix + "holder:"
	shardPrefix        = model.ArtifactLedgerIndexKeyPrefix + "shard:"
	shardAnchorPrefix  = model.ArtifactLedgerIndexKeyPrefix + "shardanchor:"

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

// LedgerKey is the Settings key of one ledger.
func LedgerKey(project, root model.ID) string {
	return LedgerPrefix + project.String() + ":" + root.String()
}

// ShardIndexKey and ShardAnchorKey are the Settings keys of the index shard (and its anchor)
// that holds root: the shard is the first byte of the root ID.
func ShardIndexKey(project, root model.ID) string { return shardKey(shardPrefix, project, root[0]) }
func ShardAnchorKey(project, root model.ID) string {
	return shardKey(shardAnchorPrefix, project, root[0])
}
func shardKey(prefix string, project model.ID, shard byte) string {
	return prefix + project.String() + ":" + hex.EncodeToString([]byte{shard})
}

// LegacyIndexKey and LegacyAnchorKey are the keys of the whole-project index that earlier
// builds wrote. They are read while present and removed by the first Store of the project.
func LegacyIndexKey(project model.ID) string  { return IndexPrefix + project.String() }
func LegacyAnchorKey(project model.ID) string { return legacyAnchorPrefix + project.String() }

// verifyIndex decodes one stored index value and checks it against its anchor. An anchor with no
// index, or an index that is not the one the anchor pinned, is Corrupt (an entry, or the whole
// index, was removed or rewritten without its ledger writer). An index with no anchor is a
// project written before anchors existed: it is accepted and the next write anchors it.
func verifyIndex(raw, rawAnchor json.RawMessage, hasIndex, hasAnchor bool) (map[string]IndexEntry, error) {
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

// loadLegacy returns the whole-project index of an earlier build; legacy reports that one is
// stored (an index or an anchor under the legacy keys).
func loadLegacy(settings map[string]json.RawMessage, project model.ID) (idx map[string]IndexEntry, legacy bool, err error) {
	raw, hasIndex := settings[LegacyIndexKey(project)]
	rawAnchor, hasAnchor := settings[LegacyAnchorKey(project)]
	if !hasIndex && !hasAnchor {
		return nil, false, nil
	}
	idx, err = verifyIndex(raw, rawAnchor, hasIndex, hasAnchor)
	return idx, true, err
}

// loadShard returns the verified index shard that holds root. A project that still carries the
// legacy whole-project index answers from it until its first write.
func loadShard(settings map[string]json.RawMessage, project, root model.ID) (map[string]IndexEntry, error) {
	if idx, legacy, err := loadLegacy(settings, project); legacy {
		return idx, err
	}
	raw, hasIndex := settings[ShardIndexKey(project, root)]
	rawAnchor, hasAnchor := settings[ShardAnchorKey(project, root)]
	return verifyIndex(raw, rawAnchor, hasIndex, hasAnchor)
}

// Load returns the verified ledger, nil when the root has none, and Corrupt for any disagreement
// between the ledger, the index and its anchor.
//
// Until the operator contracts the organization's indexes (model.IndexesContractedKey, D70) the
// whole-project index of the previous release is kept current beside the shards, and the previous
// release (or a rolled-back voter) may write ledgers that only that index knows. The shard answers
// first, as one small value; a shard that does not agree with the ledger (the previous release
// wrote it, or the project predates the shards) is checked against the whole-project index, which
// is verified against its own anchor, so such a ledger loads exactly as the previous release loads
// it and the next write of the project brings the shard up to date.
func Load(settings map[string]json.RawMessage, project, root model.ID) (*Ledger, error) {
	if _, contracted := settings[model.IndexesContractedKey]; contracted {
		idx, err := loadShard(settings, project, root)
		if err != nil {
			return nil, err
		}
		return verifyLedger(settings, project, root, idx)
	}
	shardRaw, hasIndex := settings[ShardIndexKey(project, root)]
	shardAnchor, hasAnchor := settings[ShardAnchorKey(project, root)]
	idx, err := verifyIndex(shardRaw, shardAnchor, hasIndex, hasAnchor)
	if err != nil {
		// The previous release never writes a shard: one that does not match its own anchor was edited.
		return nil, err
	}
	l, err := verifyLedger(settings, project, root, idx)
	if err == nil {
		return l, nil
	}
	whole, legacy, lerr := loadLegacy(settings, project)
	if !legacy || lerr != nil {
		return nil, err
	}
	return verifyLedger(settings, project, root, whole)
}

// verifyLedger checks the stored ledger of root against its entry in idx.
func verifyLedger(settings map[string]json.RawMessage, project, root model.ID, idx map[string]IndexEntry) (*Ledger, error) {
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

// indexFromShards merges the verified shards of a project: the index of a project that has no
// whole-project index (empty when it has no shard either).
func indexFromShards(settings map[string]json.RawMessage, project model.ID) (map[string]IndexEntry, error) {
	all := map[string]IndexEntry{}
	for b := range 256 {
		raw, hasIndex := settings[shardKey(shardPrefix, project, byte(b))]
		rawAnchor, hasAnchor := settings[shardKey(shardAnchorPrefix, project, byte(b))]
		if !hasIndex && !hasAnchor {
			continue
		}
		idx, err := verifyIndex(raw, rawAnchor, hasIndex, hasAnchor)
		if err != nil {
			return nil, err
		}
		maps.Copy(all, idx)
	}
	return all, nil
}

// putIndex writes one index value with its anchor.
func putIndex(settings map[string]json.RawMessage, indexKey, anchorKey string, idx map[string]IndexEntry) error {
	rawIndex, err := json.Marshal(idx)
	if err != nil {
		return model.Fail(model.Corrupt)
	}
	rawAnchor, err := json.Marshal(anchor{Version: Version, Roots: len(idx), Index: model.HashCanonical(rawIndex)})
	if err != nil {
		return model.Fail(model.Corrupt)
	}
	settings[indexKey] = rawIndex
	settings[anchorKey] = rawAnchor
	return nil
}

// partition splits an index by the first byte of its roots.
func partition(idx map[string]IndexEntry, only map[byte]bool) (map[byte]map[string]IndexEntry, error) {
	out := map[byte]map[string]IndexEntry{}
	for b := range only {
		out[b] = map[string]IndexEntry{}
	}
	for key, e := range idx {
		id, err := model.ParseID(key)
		if err != nil {
			return nil, model.Fail(model.Corrupt)
		}
		if only != nil && !only[id[0]] {
			continue
		}
		if out[id[0]] == nil {
			out[id[0]] = map[string]IndexEntry{}
		}
		out[id[0]][key] = e
	}
	return out, nil
}

// Store seals the ledgers and writes them with the index entries and anchors of the shards they
// fall in, in the organization's Settings. Every ledger must belong to project.
//
// Contracted organization (model.IndexesContractedKey): each shard is verified before it is
// rewritten, so a tampered index is never papered over by a later write, and only the ledgers and
// the shards they fall in are written, whatever the size of the project. A project that still
// carries the whole-project index is verified once, split into shards and has the legacy keys
// removed, in this same write.
//
// Before the contraction (D70) the whole-project index and its anchor, the only layout the
// previous release reads, are verified, updated and written as well, which costs what a write
// cost on the previous release, and the shards the write touches are rebuilt from it.
func Store(o *model.ControlOrg, project model.ID, ledgers ...*Ledger) error {
	if len(ledgers) == 0 {
		return nil
	}
	if o.Settings == nil {
		o.Settings = map[string]json.RawMessage{}
	}
	if !o.IndexesContracted() {
		return storeExpanded(o, project, ledgers)
	}
	shards := map[byte]map[string]IndexEntry{}
	old, legacy, err := loadLegacy(o.Settings, project)
	if err != nil {
		return err
	}
	for key, e := range old {
		id, err := model.ParseID(key)
		if err != nil {
			return model.Fail(model.Corrupt)
		}
		if shards[id[0]] == nil {
			shards[id[0]] = map[string]IndexEntry{}
		}
		shards[id[0]][key] = e
	}
	for _, l := range ledgers {
		if l.Project != project {
			return model.Fail(model.Invalid)
		}
		if shards[l.Root[0]] != nil || legacy {
			continue
		}
		idx, err := loadShard(o.Settings, project, l.Root)
		if err != nil {
			return err
		}
		shards[l.Root[0]] = idx
	}
	for _, l := range ledgers {
		l.Version = Version
		l.Head = l.digest()
		raw, err := json.Marshal(l)
		if err != nil {
			return model.Fail(model.Corrupt)
		}
		o.Settings[LedgerKey(project, l.Root)] = raw
		if shards[l.Root[0]] == nil {
			shards[l.Root[0]] = map[string]IndexEntry{}
		}
		shards[l.Root[0]][l.Root.String()] = IndexEntry{Seq: l.Seq, Head: l.Head}
	}
	for shard, idx := range shards {
		if err := putIndex(o.Settings, shardKey(shardPrefix, project, shard), shardKey(shardAnchorPrefix, project, shard), idx); err != nil {
			return err
		}
	}
	delete(o.Settings, LegacyIndexKey(project))
	delete(o.Settings, LegacyAnchorKey(project))
	return nil
}

func storeExpanded(o *model.ControlOrg, project model.ID, ledgers []*Ledger) error {
	idx, legacy, err := loadLegacy(o.Settings, project)
	if err != nil {
		return err
	}
	if !legacy {
		if idx, err = indexFromShards(o.Settings, project); err != nil {
			return err
		}
	}
	touched := map[byte]bool{}
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
		touched[l.Root[0]] = true
	}
	if err := putIndex(o.Settings, LegacyIndexKey(project), LegacyAnchorKey(project), idx); err != nil {
		return err
	}
	shards, err := partition(idx, touched)
	if err != nil {
		return err
	}
	for shard, part := range shards {
		if err := putIndex(o.Settings, shardKey(shardPrefix, project, shard), shardKey(shardAnchorPrefix, project, shard), part); err != nil {
			return err
		}
	}
	return nil
}

// Contract drops the whole-project indexes of every project of the organization (D70): the shards
// of each project are rebuilt from its verified whole-project index (the one the previous release
// reads, which a rolled-back voter may have written last), the legacy keys are removed, and the
// organization is marked contracted so no write keeps them. A whole-project index that does not
// verify is Corrupt and nothing is changed. It reports whether anything changed.
func Contract(o *model.ControlOrg) (bool, error) {
	if o.Settings == nil {
		o.Settings = map[string]json.RawMessage{}
	}
	changed := false
	projects := map[model.ID]bool{}
	for key := range o.Settings {
		rest, ok := strings.CutPrefix(key, IndexPrefix)
		if !ok {
			continue
		}
		rest = strings.TrimPrefix(rest, "anchor:")
		if id, err := model.ParseID(rest); err == nil {
			projects[id] = true
		}
	}
	next := maps.Clone(o.Settings)
	for project := range projects {
		idx, legacy, err := loadLegacy(o.Settings, project)
		if err != nil {
			return false, err
		}
		if !legacy {
			continue
		}
		for b := range 256 {
			delete(next, shardKey(shardPrefix, project, byte(b)))
			delete(next, shardKey(shardAnchorPrefix, project, byte(b)))
		}
		parts, err := partition(idx, nil)
		if err != nil {
			return false, err
		}
		for shard, part := range parts {
			if err := putIndex(next, shardKey(shardPrefix, project, shard), shardKey(shardAnchorPrefix, project, shard), part); err != nil {
				return false, err
			}
		}
		delete(next, LegacyIndexKey(project))
		delete(next, LegacyAnchorKey(project))
		changed = true
	}
	if _, ok := next[model.IndexesContractedKey]; !ok {
		next[model.IndexesContractedKey] = json.RawMessage(`true`)
		changed = true
	}
	o.Settings = next
	return changed, nil
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
