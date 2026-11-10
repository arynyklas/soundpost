// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package artifacts

import (
	"context"
	"encoding/json"
	"slices"
	"soundpost/internal/auth"
	"soundpost/internal/model"
	"time"
)

// ReferenceKind names the retained usage that keeps a map: an error occurrence,
// a profile, or a build record. The set is closed: a reference never carries a
// URL or any other user-supplied string.
type ReferenceKind string

const (
	ReferenceError   ReferenceKind = "error"
	ReferenceProfile ReferenceKind = "profile"
	ReferenceBuild   ReferenceKind = "build"
)

const (
	// DefaultMapRetention is how long a reference with no explicit deadline
	// retains its map.
	DefaultMapRetention = 90 * 24 * time.Hour
	// MaxReferenceRetention bounds how far one reference can pin a map.
	MaxReferenceRetention = 10 * 365 * 24 * time.Hour
	maxLedgerEntries      = 1024
	ledgerVersion         = 1
	ledgerPrefix          = "artifact_refs:"
	indexPrefix           = "artifact_refs_index:"
)

// OriginCursor is the durable position of the retained record that uses the map
// (the batch cursor of the error occurrence or profile; the control cursor of a
// build record).
type OriginCursor struct {
	Kind   ReferenceKind
	Cursor model.Cursor
}

func (o OriginCursor) valid() bool {
	switch o.Kind {
	case ReferenceError, ReferenceProfile, ReferenceBuild:
	default:
		return false
	}
	return o.Cursor.Group != (model.ID{}) && o.Cursor.Index != 0
}

// StateStore is the replicated control state the reference ledgers live in
// (*control.Store).
type StateStore interface {
	View(context.Context, func(model.ControlState) error) error
	Update(context.Context, func(*model.ControlState) error) error
}

// SnapshotPins reports whether any local snapshot, journal or replica state
// still needs the artifact root. An unknown answer is an error, never "no".
type SnapshotPins interface {
	Pinned(ctx context.Context, org, project, root model.ID) (bool, error)
}

// OriginVerifier, when configured, proves that the retained record exists, uses
// the artifact's build, and reports when that record itself expires. A reference
// never outlives the record that caused it.
type OriginVerifier interface {
	VerifyOrigin(ctx context.Context, scope auth.Scope, root ArtifactID, o OriginCursor) (model.UnixNano, error)
}

// LifecycleConfig wires a Lifecycle. State, Deletes and Pins are required.
type LifecycleConfig struct {
	State      StateStore
	Deletes    auth.DeleteGenerations // the retention service
	Pins       SnapshotPins
	Origins    OriginVerifier // optional
	Now        func() time.Time
	CacheBytes int // visibility-bound fragment cache budget; 0 disables
}

// Lifecycle owns artifact references, retention decisions and the read fences.
// It installs the read gate on the Service it is built over, so the common Get
// path, ReadAuthorized and ReadSourcesAuthorized all apply the same fences.
type Lifecycle struct {
	service *Service
	cfg     LifecycleConfig
	gate    *readGate
}

func NewLifecycle(s *Service, cfg LifecycleConfig) (*Lifecycle, error) {
	if s == nil || cfg.State == nil || cfg.Deletes == nil || cfg.Pins == nil || cfg.CacheBytes < 0 {
		return nil, model.Fail(model.Invalid)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	l := &Lifecycle{service: s, cfg: cfg}
	l.gate = &readGate{deletes: cfg.Deletes, state: cfg.State, cache: newFragmentCache(cfg.CacheBytes)}
	s.gate.Store(l.gate)
	return l, nil
}

type refEntry struct {
	Kind        ReferenceKind  `json:"kind"`
	Cursor      model.Cursor   `json:"cursor"`
	RetainUntil model.UnixNano `json:"retain_until_ns"`
	Released    bool           `json:"released,omitempty"`
}

// refLedger is the complete reference state of one artifact root. Head is a
// digest over everything else, and the project index pins (Seq, Head), so an
// edited, removed or rolled-back ledger is detected on load.
type refLedger struct {
	Version int            `json:"Version"`
	Project model.ID       `json:"Project"`
	Root    model.ID       `json:"Root"`
	Seq     uint64         `json:"Seq"`
	Retired bool           `json:"Retired"`
	Floor   model.UnixNano `json:"Floor"` // latest deadline of entries compacted away
	Entries []refEntry     `json:"Entries"`
	Head    model.Hash     `json:"Head"`
}
type refIndexEntry struct {
	Seq  uint64     `json:"Seq"`
	Head model.Hash `json:"Head"`
}

func (l refLedger) digest() model.Hash {
	l.Head = model.Hash{}
	raw, err := model.CanonicalJSON(l)
	if err != nil {
		return model.Hash{}
	}
	return model.HashCanonical(raw)
}

// latest is the latest deadline any unreleased reference still holds.
func (l *refLedger) latest() model.UnixNano {
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

func ledgerKey(project, root model.ID) string {
	return ledgerPrefix + project.String() + ":" + root.String()
}
func indexKey(project model.ID) string { return indexPrefix + project.String() }

func readIndex(settings map[string]json.RawMessage, project model.ID) (map[string]refIndexEntry, error) {
	raw, ok := settings[indexKey(project)]
	if !ok {
		return map[string]refIndexEntry{}, nil
	}
	var idx map[string]refIndexEntry
	if model.StrictJSON(raw, &idx) != nil || idx == nil {
		return nil, model.Fail(model.Corrupt)
	}
	return idx, nil
}

// loadLedger returns the verified ledger, nil when the artifact has none, and
// Corrupt for any disagreement between the ledger and the index.
func loadLedger(settings map[string]json.RawMessage, project, root model.ID) (*refLedger, error) {
	idx, err := readIndex(settings, project)
	if err != nil {
		return nil, err
	}
	ie, indexed := idx[root.String()]
	raw, stored := settings[ledgerKey(project, root)]
	if !stored && !indexed {
		return nil, nil
	}
	if stored != indexed {
		return nil, model.Fail(model.Corrupt)
	}
	var l refLedger
	if model.StrictJSON(raw, &l) != nil || l.Version != ledgerVersion || l.Project != project || l.Root != root || len(l.Entries) > maxLedgerEntries || l.Head != l.digest() || l.Seq != ie.Seq || l.Head != ie.Head {
		return nil, model.Fail(model.Corrupt)
	}
	for _, e := range l.Entries {
		if !(OriginCursor{Kind: e.Kind, Cursor: e.Cursor}).valid() {
			return nil, model.Fail(model.Corrupt)
		}
	}
	return &l, nil
}

// storeLedger seals and writes the ledger and its index entry together.
func storeLedger(o *model.ControlOrg, l *refLedger) error {
	l.Version = ledgerVersion
	l.Head = l.digest()
	raw, err := json.Marshal(l)
	if err != nil {
		return model.Fail(model.Corrupt)
	}
	idx, err := readIndex(o.Settings, l.Project)
	if err != nil {
		return err
	}
	idx[l.Root.String()] = refIndexEntry{Seq: l.Seq, Head: l.Head}
	rawIdx, err := json.Marshal(idx)
	if err != nil {
		return model.Fail(model.Corrupt)
	}
	o.Settings[ledgerKey(l.Project, l.Root)] = raw
	o.Settings[indexKey(l.Project)] = rawIdx
	return nil
}

func deletionCovers(st model.ControlState, m model.BlobManifest) bool {
	for _, op := range st.Deletions {
		if op.Phase != model.DeletePhaseHeld && op.Predicate.CoversBlob(m) {
			return true
		}
	}
	return false
}

// mutation is run inside one replicated control transaction, over the verified
// ledger. It returns whether the ledger changed.
type mutation func(m model.ArtifactManifest, l *refLedger, now model.UnixNano) (bool, error)

// apply runs fn over the verified ledger of one published artifact inside a
// single control transaction: authorize (when non-nil) sees the intent, a
// deleted artifact is NotFound, a corrupt ledger fails the transaction, and a
// changed ledger is sealed together with its index entry (and, when bump is set,
// the org delete generation advances: readable bytes are about to go).
func (l *Lifecycle) apply(ctx context.Context, org, project model.ID, id ArtifactID, bump bool, authorize func(model.ControlState, model.ArtifactReferenceIntent) error, fn mutation) error {
	return l.cfg.State.Update(ctx, func(st *model.ControlState) error {
		intent, ok := st.ArtifactIntents[org.String()+":"+project.String()+":"+id.String()]
		if !ok || intent.State != "published" {
			return model.Fail(model.NotFound)
		}
		if authorize != nil {
			if err := authorize(*st, intent); err != nil {
				return err
			}
		}
		if deletionCovers(*st, intent.Map.Manifest) {
			return model.Fail(model.NotFound)
		}
		o, ok := st.Orgs[org.String()]
		if !ok {
			return model.Fail(model.NotFound)
		}
		if o.Settings == nil {
			o.Settings = map[string]json.RawMessage{}
		}
		ledger, err := loadLedger(o.Settings, project, id)
		if err != nil {
			return err
		}
		if ledger == nil {
			ledger = &refLedger{Project: project, Root: id}
		}
		changed, err := fn(intent.Manifest, ledger, model.UnixNano(l.cfg.Now().UnixNano()))
		if err != nil || !changed {
			return err
		}
		ledger.Seq++
		if err = storeLedger(&o, ledger); err != nil {
			return err
		}
		if bump {
			if st.DeleteGenerations == nil {
				st.DeleteGenerations = map[string]uint64{}
			}
			st.DeleteGenerations[org.String()]++
		}
		st.Orgs[org.String()] = o
		return nil
	})
}

// mutate authorizes artifacts.write over the artifact's exact org/project (the
// same scope check as cleanup: current grant, no elevation, no live source
// admission needed) and applies fn.
func (l *Lifecycle) mutate(ctx context.Context, scope auth.Scope, id ArtifactID, fn mutation) error {
	if scope.Permission() != auth.ArtifactWrite || len(scope.ProjectIDs()) != 1 {
		return model.Fail(model.NotFound)
	}
	return l.apply(ctx, scope.OrgID(), scope.ProjectIDs()[0], id, false, func(st model.ControlState, in model.ArtifactReferenceIntent) error {
		return scope.ValidateArtifactCleanup(st, in.Map.Manifest)
	}, fn)
}

// Reference records that a retained error/profile/build usage needs the map
// until retainUntil (zero: DefaultMapRetention from now). The origin is a typed
// cursor, never a user string. Idempotent: a repeat never shortens, the same
// origin may extend, a released origin or a GC-fenced map is a Conflict.
func (l *Lifecycle) Reference(ctx context.Context, scope auth.Scope, id ArtifactID, origin OriginCursor, retainUntil model.UnixNano) error {
	if !origin.valid() {
		return model.Fail(model.Invalid)
	}
	now := l.cfg.Now()
	if retainUntil == 0 {
		retainUntil = model.UnixNano(now.Add(DefaultMapRetention).UnixNano())
	}
	if int64(retainUntil) <= now.UnixNano() || int64(retainUntil) > now.Add(MaxReferenceRetention).UnixNano() {
		return model.Fail(model.Invalid)
	}
	if l.cfg.Origins != nil {
		expires, err := l.cfg.Origins.VerifyOrigin(ctx, scope, id, origin)
		if err != nil {
			return err
		}
		if expires <= 0 {
			return model.Fail(model.NotFound)
		}
		retainUntil = min(retainUntil, expires)
		if int64(retainUntil) <= now.UnixNano() {
			return model.Fail(model.Invalid)
		}
	}
	return l.mutate(ctx, scope, id, func(_ model.ArtifactManifest, led *refLedger, _ model.UnixNano) (bool, error) {
		if led.Retired {
			return false, model.Fail(model.Conflict) // the GC fence was taken first
		}
		i := slices.IndexFunc(led.Entries, func(e refEntry) bool { return e.Kind == origin.Kind && e.Cursor == origin.Cursor })
		if i >= 0 {
			e := &led.Entries[i]
			if e.Released {
				return false, model.Fail(model.Conflict)
			}
			if retainUntil <= e.RetainUntil {
				return false, nil
			}
			e.RetainUntil = retainUntil
			return true, nil
		}
		if len(led.Entries) >= maxLedgerEntries {
			led.compact(model.UnixNano(now.UnixNano()))
			if len(led.Entries) >= maxLedgerEntries {
				return false, model.Fail(model.TooLarge)
			}
		}
		led.Entries = append(led.Entries, refEntry{Kind: origin.Kind, Cursor: origin.Cursor, RetainUntil: retainUntil})
		return true, nil
	})
}

// compact folds expired entries into Floor. Released tombstones stay: they are
// what keeps a released occurrence from being revived.
func (l *refLedger) compact(now model.UnixNano) {
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

// Unreference releases one origin (its record expired or was deleted). Fenced by
// expectedSeq when non-zero: a ledger that moved since the caller read it is a
// Conflict. Releasing an origin never seen records a tombstone so a late
// Reference of it cannot revive it. Releasing after the GC fence is a no-op.
func (l *Lifecycle) Unreference(ctx context.Context, scope auth.Scope, id ArtifactID, origin OriginCursor, expectedSeq uint64) error {
	if !origin.valid() {
		return model.Fail(model.Invalid)
	}
	return l.mutate(ctx, scope, id, func(_ model.ArtifactManifest, led *refLedger, _ model.UnixNano) (bool, error) {
		if expectedSeq != 0 && led.Seq != expectedSeq {
			return false, model.Fail(model.Conflict)
		}
		if led.Retired {
			return false, nil
		}
		i := slices.IndexFunc(led.Entries, func(e refEntry) bool { return e.Kind == origin.Kind && e.Cursor == origin.Cursor })
		switch {
		case i >= 0 && led.Entries[i].Released:
			return false, nil
		case i >= 0:
			led.Entries[i].Released = true
		default:
			if len(led.Entries) >= maxLedgerEntries {
				return false, model.Fail(model.TooLarge)
			}
			led.Entries = append(led.Entries, refEntry{Kind: origin.Kind, Cursor: origin.Cursor, Released: true})
		}
		return true, nil
	})
}

// settingsOf is an org's settings (where ledgers live) in a read-only snapshot.
func settingsOf(st model.ControlState, org model.ID) map[string]json.RawMessage {
	return st.Orgs[org.String()].Settings
}
