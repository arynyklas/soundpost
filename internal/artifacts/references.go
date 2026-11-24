// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package artifacts

import (
	"context"
	"encoding/json"
	"github.com/arynyklas/soundpost/internal/artifacts/refledger"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/storage"
	"slices"
	"time"
)

// ReferenceKind names the retained usage that keeps a map: an error occurrence,
// a profile, a build record, or (written only by HoldMaps) an open issue. The
// set is closed: a reference never carries a URL or any other user-supplied
// string.
type ReferenceKind string

const (
	ReferenceError   ReferenceKind = refledger.KindError
	ReferenceProfile ReferenceKind = refledger.KindProfile
	ReferenceBuild   ReferenceKind = refledger.KindBuild
	// ReferenceIssue is the hold of an open issue that groups occurrences naming the map
	// (holds.go). It is identified by the issue alone, is dropped when the issue stops being
	// open and may be taken again when it reopens; Reference and Unreference refuse it.
	ReferenceIssue ReferenceKind = refledger.KindIssue
)

// The artifact intent's state. "retired" is written in the same control transition
// that sets the reference ledger's Retired flag (the GC fence); control, which must
// not import this package, reads the literal (internal/control/artifacts.go).
const (
	intentPublished = "published"
	intentRetired   = "retired"
)

const (
	// DefaultMapRetention is how long a reference with no explicit deadline
	// retains its map when the lifecycle has no retention policy to ask
	// (LifecycleConfig.DefaultRetention).
	DefaultMapRetention = 90 * 24 * time.Hour
	// MaxReferenceRetention bounds how far one reference can pin a map.
	MaxReferenceRetention = 10 * 365 * 24 * time.Hour
)

// OriginCursor is the durable position of the retained record that uses the map
// (the batch cursor of the error occurrence or profile; the control cursor of a
// build record).
type OriginCursor struct {
	Kind   ReferenceKind
	Cursor model.Cursor
}

func (o OriginCursor) valid() bool {
	return o.Kind != ReferenceIssue && refledger.ValidOrigin(string(o.Kind), o.Cursor)
}

// StateStore is the replicated control state the reference ledgers live in
// (*control.Store).
type StateStore interface {
	View(context.Context, func(model.ControlState) error) error
	Update(context.Context, func(*model.ControlState) error) error
}

// ledgerUpdater is implemented by *control.Store: an update that does not move the control
// AuthorityRevision when it wrote nothing but ledger entries. Reference, Unreference and the
// profile holds use it; the GC fence (bump set) keeps the always-bumping Update. A StateStore
// without it falls back to Update. Its state carries no job or issue book: an evaluation that
// reads an issue uses issueHoldUpdater.
type ledgerUpdater interface {
	UpdateArtifactReferences(context.Context, func(*model.ControlState) error) error
}

// issueHoldUpdater is implemented by *control.Store: ledgerUpdater for the holds of the issue
// producer, whose decision reads the workflow of an issue. The state it gives fn carries the job
// and issue books and the grouping issues; the one UpdateArtifactReferences gives does not, and an
// evaluation over it finds every issue unknown. A StateStore without it falls back to Update, which
// carries all of it. A *control.Store is both; the two are separate interfaces so that neither
// can be taken for the other.
type issueHoldUpdater interface {
	UpdateIssueHolds(context.Context, func(*model.ControlState) error) error
}

// coreViewer is implemented by *control.Store: the committed state without the admission books, the job and issue
// books and the grouping issues, shared by every reader and not to be changed (ViewCore). The reads of the
// lifecycle that look at none of those use it, so that what a pass costs does not depend on how many batches were
// admitted before it; a StateStore without it is read through View.
type coreViewer interface {
	ViewCore(context.Context, func(model.ControlState) error) error
}

// projectIssueViewer is implemented by *control.Store: the shared decode of the state, with the grouping issues of
// one project added (ViewProjectIssues). The issue holds read the workflow of the issues of the project they hold for
// and nothing else of the issue books.
type projectIssueViewer interface {
	ViewProjectIssues(ctx context.Context, org, project model.ID, fn func(model.ControlState) error) error
}

// view reads the committed state for fn, which only reads it: the shared decode when the store has one (with the grouping
// issues of the project when fn looks at an issue: they are not part of the core decode), a decode of its own otherwise.
func (l *Lifecycle) view(ctx context.Context, issues bool, org, project model.ID, fn func(model.ControlState) error) error {
	if issues {
		if v, ok := l.cfg.State.(projectIssueViewer); ok {
			return v.ViewProjectIssues(ctx, org, project, fn)
		}
	} else if v, ok := l.cfg.State.(coreViewer); ok {
		return v.ViewCore(ctx, fn)
	}
	return l.cfg.State.View(ctx, fn)
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
	// DefaultRetention is how long a Reference with no explicit deadline retains the
	// map in one project at an instant: the audited organization and project retention
	// for source maps (retention.Resolve ArtifactDays), so an override is honoured. Nil
	// means DefaultMapRetention.
	DefaultRetention func(ctx context.Context, org, project model.ID, at model.UnixNano) (time.Duration, error)
}

// Lifecycle owns artifact references, retention decisions and the read fences.
// It installs the read gate on the Service it is built over, so the common Get
// path, ReadAuthorized and ReadSourcesAuthorized all apply the same fences.
//
// The retention decision of a read is D-new C07 (owner decision, backlog item
// 10.09-W2): a map is readable until its EFFECTIVE retention, the later of the
// upload's own deadline and every unreleased reference (EffectiveRetention), and
// not until the upload's stored deadline alone. The check itself runs where every
// reader meets it, auth.Scope.ValidateArtifactState, over the same verified ledger
// (internal/artifacts/refledger); Lifecycle adds the organization delete
// generation and the visibility-bound cache on top.
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
	l.gate = &readGate{deletes: cfg.Deletes, cache: newFragmentCache(cfg.CacheBytes)}
	s.gate.Store(l.gate)
	return l, nil
}

// Now is the lifecycle's clock: the instant every deadline it records, extends or
// expires is measured on.
func (l *Lifecycle) Now() time.Time { return l.cfg.Now() }

func deletionCovers(st model.ControlState, m model.BlobManifest) bool {
	for _, op := range st.Deletions {
		if op.Phase != model.DeletePhaseHeld && op.Predicate.CoversBlob(m) {
			return true
		}
	}
	return false
}

// plan is what one ledger operation changes, computed read-only over a control state.
type plan struct {
	project    model.ID
	ledgers    []*refledger.Ledger           // sealed on write; Seq already advanced
	putHolders map[model.ID]refledger.Holder // issue -> holder to store
	delHolders []model.ID                    // issues whose holder is removed
	retire     []string                      // artifact intent keys flipped to retired
}

func (p plan) empty() bool {
	return len(p.ledgers) == 0 && len(p.putHolders) == 0 && len(p.delHolders) == 0 && len(p.retire) == 0
}

// write applies the plan to the state a control transaction is changing. When bump is set the
// org delete generation advances if a ledger changed: readable bytes are about to go.
func (p plan) write(st *model.ControlState, org model.ID, bump bool) error {
	o, ok := st.Orgs[org.String()]
	if !ok {
		return model.Fail(model.NotFound)
	}
	if err := refledger.Store(&o, p.project, p.ledgers...); err != nil {
		return err
	}
	for issue, h := range p.putHolders {
		if err := refledger.PutHolder(&o, p.project, issue, h); err != nil {
			return err
		}
	}
	for _, issue := range p.delHolders {
		refledger.DeleteHolder(&o, p.project, issue)
	}
	st.Orgs[org.String()] = o
	if bump && len(p.ledgers) > 0 {
		if st.DeleteGenerations == nil {
			st.DeleteGenerations = map[string]uint64{}
		}
		st.DeleteGenerations[org.String()]++
	}
	for _, key := range p.retire {
		intent := st.ArtifactIntents[key]
		intent.State = intentRetired
		st.ArtifactIntents[key] = intent
	}
	return nil
}

// run evaluates an operation over the committed state first and commits only when it has
// something to change: a call that changes nothing (a repeated Reference, a release of
// nothing) is a read, not a replicated control transaction. The evaluation is repeated
// inside the transaction, over the state it really changes. The instant is fixed per call,
// so both evaluations decide on the same time.
func (l *Lifecycle) run(ctx context.Context, org model.ID, bump bool, evaluate func(model.ControlState, model.UnixNano) (plan, error)) error {
	return l.runUsing(ctx, org, model.ID{}, bump, false, evaluate)
}

// runIssues is run for an evaluation that reads the workflow of an issue (HoldIssues,
// SettleIssues): the transaction it commits in must be given the grouping issues, which the
// plain ledger writer's state does not carry (issueHoldUpdater).
func (l *Lifecycle) runIssues(ctx context.Context, scope auth.Scope, evaluate func(model.ControlState, model.UnixNano) (plan, error)) error {
	var project model.ID // a scope over any other than one project is refused by the evaluation
	if ids := scope.ProjectIDs(); len(ids) == 1 {
		project = ids[0]
	}
	return l.runUsing(ctx, scope.OrgID(), project, false, true, evaluate)
}

func (l *Lifecycle) runUsing(ctx context.Context, org, project model.ID, bump, issues bool, evaluate func(model.ControlState, model.UnixNano) (plan, error)) error {
	now := model.UnixNano(l.cfg.Now().UnixNano())
	pending := false
	if err := l.view(ctx, issues, org, project, func(st model.ControlState) error {
		p, err := evaluate(st, now)
		pending = !p.empty()
		return err
	}); err != nil || !pending {
		return err
	}
	update := l.cfg.State.Update
	if !bump {
		if issues {
			if u, ok := l.cfg.State.(issueHoldUpdater); ok {
				update = u.UpdateIssueHolds // issue holds: ledger bookkeeping decided by the issue book, not authority
			}
		} else if u, ok := l.cfg.State.(ledgerUpdater); ok {
			update = u.UpdateArtifactReferences // Reference / Unreference / profile holds: ledger bookkeeping, not authority
		}
	}
	return update(ctx, func(st *model.ControlState) error {
		p, err := evaluate(*st, now)
		if err != nil || p.empty() {
			return err
		}
		return p.write(st, org, bump)
	})
}

// mutation is run over the verified ledger of one published artifact. It returns whether the
// ledger changed.
type mutation func(m model.ArtifactManifest, l *refledger.Ledger, now model.UnixNano) (bool, error)

// one evaluates fn over the verified ledger of one artifact: authorize (when non-nil) sees the
// intent, a deleted artifact is NotFound, a corrupt ledger fails the evaluation, and a changed
// ledger is part of the plan. The GC fence and the intent move together, in one control
// transition: control (which cannot read the ledger) sees "retired" and no longer requires the
// root's bytes, and the fence is durable before retention erases them. A crash after the fence
// leaves a retired intent over present bytes (an orphan the next pass erases), never a
// published intent over missing bytes. A ledger fenced by an earlier build over a
// still-published intent is healed here too.
func one(org, project model.ID, id ArtifactID, authorize func(model.ControlState, model.ArtifactReferenceIntent) error, fn mutation) func(model.ControlState, model.UnixNano) (plan, error) {
	return func(st model.ControlState, now model.UnixNano) (plan, error) {
		key := org.String() + ":" + project.String() + ":" + id.String()
		intent, ok := st.ArtifactIntents[key]
		if !ok || intent.State != intentPublished && intent.State != intentRetired {
			return plan{}, model.Fail(model.NotFound)
		}
		if authorize != nil {
			if err := authorize(st, intent); err != nil {
				return plan{}, err
			}
		}
		if deletionCovers(st, intent.Map.Manifest) {
			return plan{}, model.Fail(model.NotFound)
		}
		o, ok := st.Orgs[org.String()]
		if !ok {
			return plan{}, model.Fail(model.NotFound)
		}
		ledger, err := refledger.Load(o.Settings, project, id)
		if err != nil {
			return plan{}, err
		}
		if ledger == nil {
			ledger = &refledger.Ledger{Project: project, Root: id}
		}
		if intent.State == intentRetired && !ledger.Retired {
			// The fence writes the ledger and the intent in one transition: a retired intent
			// over a ledger that is missing or not fenced means the ledger was removed or
			// rolled back (not detectable by the digest and the index alone).
			return plan{}, model.Fail(model.Corrupt)
		}
		changed, err := fn(intent.Manifest, ledger, now)
		if err != nil {
			return plan{}, err
		}
		p := plan{project: project}
		if changed {
			ledger.Seq++
			p.ledgers = []*refledger.Ledger{ledger}
		}
		if ledger.Retired && intent.State == intentPublished {
			p.retire = []string{key}
		}
		return p, nil
	}
}

// mutate authorizes artifacts.write over the artifact's exact org/project (the
// same scope check as cleanup: current grant, no elevation, no live source
// admission needed) and applies fn.
func (l *Lifecycle) mutate(ctx context.Context, scope auth.Scope, id ArtifactID, fn mutation) error {
	if scope.Permission() != auth.ArtifactWrite || len(scope.ProjectIDs()) != 1 {
		return model.Fail(model.NotFound)
	}
	org, project := scope.OrgID(), scope.ProjectIDs()[0]
	return l.run(ctx, org, false, one(org, project, id, func(st model.ControlState, in model.ArtifactReferenceIntent) error {
		return scope.ValidateArtifactCleanup(st, in.Map.Manifest)
	}, fn))
}

// defaultRetention is how long a Reference without a deadline retains the map of one project.
func (l *Lifecycle) defaultRetention(ctx context.Context, scope auth.Scope, now time.Time) (time.Duration, error) {
	if l.cfg.DefaultRetention == nil {
		return DefaultMapRetention, nil
	}
	if scope.Permission() != auth.ArtifactWrite || len(scope.ProjectIDs()) != 1 {
		return 0, model.Fail(model.NotFound)
	}
	d, err := l.cfg.DefaultRetention(ctx, scope.OrgID(), scope.ProjectIDs()[0], model.UnixNano(now.UnixNano()))
	if err != nil {
		return 0, err
	}
	return d, nil
}

// Reference records that a retained error/profile/build usage needs the map
// until retainUntil (zero: the audited source-map retention of the project from
// now, DefaultMapRetention without a policy). The origin is a typed cursor, never
// a user string. Idempotent: a repeat never shortens, the same origin may extend,
// a released origin or a GC-fenced map is a Conflict, and so is a map whose
// retention (its own deadline and every other reference) has already elapsed: an
// expired map is gone for its readers (C07) and a late reference cannot revive it,
// whether or not retention has fenced it yet.
func (l *Lifecycle) Reference(ctx context.Context, scope auth.Scope, id ArtifactID, origin OriginCursor, retainUntil model.UnixNano) error {
	if !origin.valid() {
		return model.Fail(model.Invalid)
	}
	now := l.cfg.Now()
	if retainUntil == 0 {
		d, err := l.defaultRetention(ctx, scope, now)
		if err != nil {
			return err
		}
		retainUntil = model.UnixNano(now.Add(d).UnixNano())
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
	return l.mutate(ctx, scope, id, func(m model.ArtifactManifest, led *refledger.Ledger, at model.UnixNano) (bool, error) {
		if led.Retired {
			return false, model.Fail(model.Conflict) // the GC fence was taken first
		}
		if max(m.RetainUntil, led.Latest()) <= at {
			return false, model.Fail(model.Conflict) // retention elapsed: expired, not yet fenced, and not revivable
		}
		i := slices.IndexFunc(led.Entries, func(e refledger.Entry) bool { return e.Kind == string(origin.Kind) && e.Cursor == origin.Cursor })
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
		if len(led.Entries) >= refledger.MaxEntries {
			led.Compact(at)
			if len(led.Entries) >= refledger.MaxEntries {
				return false, model.Fail(model.TooLarge)
			}
		}
		led.Entries = append(led.Entries, refledger.Entry{Kind: string(origin.Kind), Cursor: origin.Cursor, RetainUntil: retainUntil})
		return true, nil
	})
}

// Unreference releases one origin (its record expired or was deleted). Fenced by
// expectedSeq when non-zero: a ledger that moved since the caller read it is a
// Conflict. Releasing an origin never seen records a tombstone so a late
// Reference of it cannot revive it. Releasing after the GC fence is a no-op.
func (l *Lifecycle) Unreference(ctx context.Context, scope auth.Scope, id ArtifactID, origin OriginCursor, expectedSeq uint64) error {
	if !origin.valid() {
		return model.Fail(model.Invalid)
	}
	return l.mutate(ctx, scope, id, func(_ model.ArtifactManifest, led *refledger.Ledger, _ model.UnixNano) (bool, error) {
		if expectedSeq != 0 && led.Seq != expectedSeq {
			return false, model.Fail(model.Conflict)
		}
		if led.Retired {
			return false, nil
		}
		i := slices.IndexFunc(led.Entries, func(e refledger.Entry) bool { return e.Kind == string(origin.Kind) && e.Cursor == origin.Cursor })
		switch {
		case i >= 0 && led.Entries[i].Released:
			return false, nil
		case i >= 0:
			led.Entries[i].Released = true
		default:
			if len(led.Entries) >= refledger.MaxEntries {
				return false, model.Fail(model.TooLarge)
			}
			led.Entries = append(led.Entries, refledger.Entry{Kind: string(origin.Kind), Cursor: origin.Cursor, Released: true})
		}
		return true, nil
	})
}

// settingsOf is an org's settings (where ledgers live) in a read-only snapshot.
func settingsOf(st model.ControlState, org model.ID) map[string]json.RawMessage {
	return st.Orgs[org.String()].Settings
}

// ReconcileRetired is the restore-activation reconciliation of artifact retirement. A restore
// from a backup older than a retirement brings back the published intent and the unfenced ledger
// of a map that the installation had already retired: its bytes are present again and nothing
// records that it was gone. A retirement is only ever taken after the map's effective retention
// (the upload's deadline and every unreleased reference) elapsed, and time does not go back, so
// every published map whose retention is over now is retired again here, through the same fenced
// decision retention takes (LatestReference: deletion precedence, snapshot pins, the verified
// ledger), instead of staying readable until the next expiry pass reaches it. A map that is still
// retained, or held by a pin, is left to the pass. A ledger that does not verify fails the
// reconciliation closed. It returns how many maps it retired; it is idempotent.
func (l *Lifecycle) ReconcileRetired(ctx context.Context) (int, error) {
	now := model.UnixNano(l.cfg.Now().UnixNano())
	var due []model.BlobManifest
	if err := l.view(ctx, false, model.ID{}, model.ID{}, func(st model.ControlState) error {
		for _, intent := range st.ArtifactIntents {
			if intent.State != intentPublished || deletionCovers(st, intent.Map.Manifest) {
				continue
			}
			m := intent.Map.Manifest
			led, err := refledger.Load(settingsOf(st, m.Org), m.Project, m.Root)
			if err != nil {
				return err
			}
			if max(m.RetainUntil, led.Latest()) <= now {
				due = append(due, m)
			}
		}
		return nil
	}); err != nil {
		return 0, err
	}
	retired := 0
	for _, m := range due {
		if err := ctx.Err(); err != nil {
			return retired, model.Fail(model.Cancelled)
		}
		latest, err := l.LatestReference(ctx, storage.EraseCandidate{Org: m.Org, Project: m.Project, Blob: &m})
		if err != nil {
			return retired, err
		}
		if latest == 0 {
			retired++
		}
	}
	return retired, nil
}
