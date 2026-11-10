// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package notify

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"

	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/model"
)

// This file is the notification ownership cutover (plan 06 task 09). Soundpost
// becomes the normal-notification owner of a project through six phases, one
// owner at a time:
//
//	shadow -> quiescing_old -> barrier_verified -> new_active
//	new_active -> rollback_quiescing -> old_active -> quiescing_old ...
//
// The old owner is an external system this product cannot observe or stop. The
// authorized adoption flow disables it and hands this package audited evidence;
// the product RECORDS and VERIFIES its own authorization and barrier state, in
// committed control state, and never pretends that a cross-product atomic
// transaction exists. Nothing here sends, imports or deletes legacy history.
//
// The state machine, the barrier verification and the claim, enqueue and
// pre-send fences live in control (cutover.go, delivery_outbox.go): they must
// apply atomically with the deliveries they fence. This package is the scoped
// facade (AdvanceCutover), the replay and error contract, the shadow decision
// evaluator and the parity comparison against a legacy decision stream.

// CutoverPhase is the closed set of ownership phases of one project.
type CutoverPhase string

// The phases.
const (
	CutoverShadow            CutoverPhase = control.CutoverShadow
	CutoverQuiescingOld      CutoverPhase = control.CutoverQuiescingOld
	CutoverBarrierVerified   CutoverPhase = control.CutoverBarrierVerified
	CutoverNewActive         CutoverPhase = control.CutoverNewActive
	CutoverRollbackQuiescing CutoverPhase = control.CutoverRollbackQuiescing
	CutoverOldActive         CutoverPhase = control.CutoverOldActive
)

// Valid reports whether the phase is one of the six.
func (p CutoverPhase) Valid() bool {
	switch p {
	case CutoverShadow, CutoverQuiescingOld, CutoverBarrierVerified, CutoverNewActive, CutoverRollbackQuiescing, CutoverOldActive:
		return true
	}
	return false
}

// ModeFor is the policy delivery mode every notification subject of the
// project must be in while the cutover is in the phase: only the new owner's
// active phase delivers; every other phase decides without sending.
func ModeFor(p CutoverPhase) DeliveryMode {
	if p == CutoverNewActive {
		return ModeActive
	}
	return ModeShadow
}

// ActiveOwners are the normal-notification owners active in a phase: never
// more than one.
func ActiveOwners(p CutoverPhase, oldOwner, newOwner model.ID) []model.ID {
	return control.CutoverActiveOwners(string(p), oldOwner, newOwner)
}

// The evidence shapes are control's closed DTOs: the committed record carries
// exactly what the operator flow supplied.
type (
	// FrontierEntry is one source, the source policy version and the data
	// journal cursor the old owner had processed through.
	FrontierEntry = control.CutoverFrontier
	// BarrierEvidence is the verified barrier evidence of one transition.
	BarrierEvidence = control.CutoverEvidence
	// BarrierAccounting is the pending/unknown delivery accounting.
	BarrierAccounting = control.CutoverAccounting
	// OwnerEvidence is the external owner's observed state.
	OwnerEvidence = control.CutoverOwnerEvidence
	// Authorization is the explicit operator authorization.
	Authorization = control.CutoverAuthorization
	// RollbackRoute is the route back to the old owner.
	RollbackRoute = control.CutoverRoute
	// ObserverProof is the independent observer proof.
	ObserverProof = control.CutoverObserver
	// CutoverFacts are the product-side facts a barrier is verified against.
	CutoverFacts = control.CutoverFacts
)

// CutoverCommand is one requested transition. ID is the C05 command ID: it
// makes a retry a replay. ExpectedRevision is the cutover revision the operator
// saw (zero before the first command). Evidence is required exactly for
// barrier_verified, new_active and old_active.
type CutoverCommand struct {
	ID               model.ID
	ExpectedRevision model.Revision
	Frontier         []FrontierEntry
	OldOwner         model.ID
	NewOwner         model.ID
	Phase            CutoverPhase
	Reason           string
	Evidence         *BarrierEvidence
}

// CutoverEntry is one step of the sanitized timeline: identities, phases,
// revisions and digests only, never the operator's text or the evidence
// payload.
type CutoverEntry struct {
	Command        model.ID
	Principal      model.ID
	From, To       CutoverPhase
	Revision       model.Revision
	Epoch          uint64
	At             model.UnixNano
	EvidenceDigest *model.Hash
}

// CutoverState is the committed ownership state of one project.
type CutoverState struct {
	Project   model.ID
	Cutover   model.ID
	Revision  model.Revision
	Phase     CutoverPhase
	OldOwner  model.ID
	NewOwner  model.ID
	Epoch     uint64
	EnteredAt model.UnixNano
	// ActiveOwners is empty or exactly one owner.
	ActiveOwners []model.ID
	Frontier     []FrontierEntry
	// RestoreAck is the disaster-restore generation the cutover acknowledged.
	RestoreAck *model.ID
	// Replayed says the state is the original result of an earlier identical
	// command, not the current state.
	Replayed bool
	Timeline []CutoverEntry
}

// CutoverStore is the control surface the cutover needs (*control.Store).
type CutoverStore interface {
	TransactCutover(ctx context.Context, scope auth.Scope, command model.ID, t control.CutoverTransition) (control.CutoverRecord, error)
	Cutover(ctx context.Context, scope auth.Scope, project model.ID) (control.CutoverRecord, bool, error)
	CutoverFacts(ctx context.Context, scope auth.Scope, project model.ID, at model.UnixNano) (control.CutoverFacts, error)
}

// CutoverService advances and reads the ownership cutover of a project.
type CutoverService struct {
	store CutoverStore
	clock Clock
}

// NewCutoverService builds the service; every dependency is required.
func NewCutoverService(store CutoverStore, clock Clock) (*CutoverService, error) {
	if store == nil || clock == nil {
		return nil, model.Fail(model.Invalid)
	}
	return &CutoverService{store: store, clock: clock}, nil
}

// CutoverConflictError is a stale expected revision: the cutover is at Current.
type CutoverConflictError struct{ Current model.Revision }

func (e *CutoverConflictError) Error() string {
	return "conflict: " + control.CutoverRevisionConflict
}

// Unwrap returns the shared conflict fault.
func (e *CutoverConflictError) Unwrap() error {
	f := model.Fail(model.Conflict)
	f.SafeDetail = control.CutoverRevisionConflict
	return f
}

// BarrierError is a failed barrier: Checks are the closed codes of every check
// that did not hold.
type BarrierError struct{ Checks []string }

func (e *BarrierError) Error() string {
	return "conflict: " + control.CutoverBarrierFailed + " checks=" + strings.Join(e.Checks, ",")
}

// Unwrap returns the shared conflict fault.
func (e *BarrierError) Unwrap() error {
	f := model.Fail(model.Conflict)
	f.SafeDetail = control.CutoverBarrierFailed
	return f
}

// CutoverCurrent extracts the current revision of a stale-revision refusal.
func CutoverCurrent(err error) (model.Revision, bool) {
	var c *CutoverConflictError
	if errors.As(err, &c) {
		return c.Current, true
	}
	return 0, false
}

func cutoverProject(scope auth.Scope) (model.ID, error) {
	projects := scope.ProjectIDs()
	if len(projects) != 1 || projects[0] == (model.ID{}) {
		return model.ID{}, model.Fail(model.Invalid)
	}
	return projects[0], nil
}

func stateOf(rec control.CutoverRecord) CutoverState {
	out := CutoverState{Project: rec.Project, Cutover: rec.ID, Revision: rec.Revision, Phase: CutoverPhase(rec.Phase), OldOwner: rec.Old, NewOwner: rec.New,
		Epoch: uint64(rec.Epoch), EnteredAt: rec.EnteredAt, ActiveOwners: rec.ActiveOwners(), Frontier: append([]FrontierEntry(nil), rec.Frontier...), RestoreAck: rec.RestoreAck}
	for _, s := range rec.Steps {
		out.Timeline = append(out.Timeline, CutoverEntry{Command: s.Command, Principal: s.Principal, From: CutoverPhase(s.From), To: CutoverPhase(s.To), Revision: s.Revision,
			Epoch: uint64(s.Epoch), At: s.At, EvidenceDigest: s.Evidence})
	}
	return out
}

// stateAtStep is the original result of the step that committed command: the
// state as it stood right after it.
func stateAtStep(rec control.CutoverRecord, command model.ID) (CutoverState, bool) {
	for i, s := range rec.Steps {
		if s.Command != command {
			continue
		}
		out := stateOf(rec)
		out.Revision, out.Phase, out.Epoch, out.EnteredAt = s.Revision, CutoverPhase(s.To), uint64(s.Epoch), s.At
		out.ActiveOwners = ActiveOwners(out.Phase, rec.Old, rec.New)
		out.Timeline = out.Timeline[:i+1]
		return out, true
	}
	return CutoverState{}, false
}

func mapCutoverError(err error) error {
	var f *model.Fault
	if !errors.As(err, &f) {
		return err
	}
	switch {
	case strings.HasPrefix(f.SafeDetail, control.CutoverRevisionConflict+" current="):
		if cur, ok := control.CutoverVersionOf(err); ok {
			return &CutoverConflictError{Current: cur}
		}
	case strings.HasPrefix(f.SafeDetail, control.CutoverBarrierFailed+" checks="):
		return &BarrierError{Checks: strings.Split(strings.TrimPrefix(f.SafeDetail, control.CutoverBarrierFailed+" checks="), ",")}
	}
	return err
}

// AdvanceCutover commits one ownership transition of the scope's project.
//
// The scope is an organization administrator scope naming exactly one project.
// A stale ExpectedRevision is a *CutoverConflictError carrying the current
// revision. A command ID that already committed returns the original result
// (Replayed) when the content is the same and is a conflict when it differs:
// the retry of a lost response is harmless, and a reused ID never silently
// stands for another request. A transition into barrier_verified, new_active or
// old_active is verified against the evidence and the committed state inside the
// same transaction that commits it; a failed barrier is a *BarrierError listing
// every failed check.
func (s *CutoverService) AdvanceCutover(ctx context.Context, scope auth.Scope, command CutoverCommand) (CutoverState, error) {
	project, err := cutoverProject(scope)
	if err != nil {
		return CutoverState{}, err
	}
	if command.ID == (model.ID{}) || !command.Phase.Valid() {
		return CutoverState{}, model.Fail(model.Invalid)
	}
	t := control.CutoverTransition{Project: project, ExpectedRevision: command.ExpectedRevision, Old: command.OldOwner, New: command.NewOwner, Phase: string(command.Phase),
		At: s.clock.Now(), Reason: command.Reason, Frontier: command.Frontier, Evidence: command.Evidence}
	rec, found, err := s.store.Cutover(ctx, scope, project)
	if err != nil {
		return CutoverState{}, err
	}
	if found {
		for _, step := range rec.Steps {
			if step.Command != command.ID {
				continue
			}
			if step.Digest != t.Digest() {
				return CutoverState{}, refuse(model.Conflict, ReasonCutoverReused)
			}
			out, _ := stateAtStep(rec, command.ID)
			out.Replayed = true
			return out, nil
		}
	}
	rec, err = s.store.TransactCutover(ctx, scope, command.ID, t)
	if err != nil {
		return CutoverState{}, mapCutoverError(err)
	}
	if out, ok := stateAtStep(rec, command.ID); ok {
		return out, nil
	}
	out := stateOf(rec)
	out.Replayed = true
	return out, nil
}

// Cutover reads the committed ownership state of the scope's project.
func (s *CutoverService) Cutover(ctx context.Context, scope auth.Scope) (CutoverState, bool, error) {
	project, err := cutoverProject(scope)
	if err != nil {
		return CutoverState{}, false, err
	}
	rec, found, err := s.store.Cutover(ctx, scope, project)
	if err != nil || !found {
		return CutoverState{}, false, err
	}
	return stateOf(rec), true, nil
}

// Facts reads the facts a barrier is verified against at the injected clock's
// instant: the delivery accounting and the committed source checkpoints the
// operator flow attests to.
func (s *CutoverService) Facts(ctx context.Context, scope auth.Scope) (CutoverFacts, error) {
	project, err := cutoverProject(scope)
	if err != nil {
		return CutoverFacts{}, err
	}
	return s.store.CutoverFacts(ctx, scope, project, s.clock.Now())
}

// The closed reasons of the cutover facade's own refusals.
const (
	// ReasonCutoverReused: the command ID already committed with other content.
	ReasonCutoverReused Reason = "cutover_command_reused"
)

// ShadowDecision is one decision a shadow evaluation produced, at delivery
// granularity: one entry per intended recipient (or one for the shared queue).
type ShadowDecision struct {
	Entity         Entity
	Kind           Kind
	ImpactRevision uint64
	Ordinal        uint64
	// Recipient is nil for the shared queue and for a missing destination.
	Recipient *model.ID
	// SourceVersion is the version of the source evidence the decision was made
	// at: the incident version, the condition sequence or the cursor index.
	SourceVersion uint64
	// DedupID is the stable idempotency ID of the decision.
	DedupID model.ID
	// Suppression is why the decision would not be delivered if the product were
	// the active owner; empty means it would be delivered.
	Suppression Code
	Route       Route
}

// LegacyDecision is one decision of the old owner in the same vocabulary. The
// adoption flow normalizes the legacy output into it; the product never
// imports legacy history.
type LegacyDecision struct {
	Entity         Entity
	Kind           Kind
	ImpactRevision uint64
	Ordinal        uint64
	Recipient      *model.ID
	SourceVersion  uint64
	// DedupID is the old owner's own dedup identifier.
	DedupID     string
	Suppression Code
}

// ParityMismatch is one difference between the shadow and the legacy decisions.
type ParityMismatch struct {
	Entity         Entity
	Kind           Kind
	ImpactRevision uint64
	Ordinal        uint64
	Recipient      *model.ID
	// Field is the closed name of what differs: source_version, suppression,
	// recipients, dedup, only_shadow or only_legacy.
	Field string
}

// ParityReport is the comparison of a shadow decision set with a legacy one.
type ParityReport struct {
	Compared   int
	Mismatches []ParityMismatch
}

// Equal reports that every decision matched on every compared field.
func (r ParityReport) Equal() bool { return len(r.Mismatches) == 0 }

// ShadowEvaluator replays policy events through Decide on an in-memory twin
// state held in active mode: it produces the decisions the product would take
// as the owner and never stores, claims or sends anything. The twin follows its
// own canonical-owner revision (a caller that feeds the same events the stored,
// shadow-mode state sees need not track it) and stays active whatever mode an
// owner_cutover event asks for.
type ShadowEvaluator struct {
	state PolicyState
	last  uint64
}

// NewShadowEvaluator starts the twin of one notification subject.
func NewShadowEvaluator(org, project, policy model.ID, subject Entity) (*ShadowEvaluator, error) {
	s, err := NewState(org, project, policy, subject)
	if err != nil {
		return nil, err
	}
	return &ShadowEvaluator{state: s}, nil
}

// sourceVersionOf is the version of the source evidence an event carries: the
// incident version, the condition sequence or the source cursor's index.
func sourceVersionOf(ev PolicyEvent) (uint64, bool) {
	switch {
	case ev.Incident != nil:
		return uint64(ev.Incident.Version), true
	case ev.Condition != nil:
		return ev.Condition.Seq, true
	case ev.Issue != nil && ev.Cursor != nil:
		return uint64(ev.Cursor.Index), true
	}
	return 0, false
}

// Apply decides one event on the twin. A refused event decides nothing and
// leaves the twin as it was. Decisions made by a timer or a human action carry
// the source version of the evidence last applied.
func (e *ShadowEvaluator) Apply(ev PolicyEvent, at model.UnixNano) ([]ShadowDecision, error) {
	ev.OwnerRevision = e.state.OwnerRevision
	if ev.Cutover != nil {
		c := *ev.Cutover
		c.Mode = ModeActive
		ev.Cutover = &c
	}
	next, intents, err := Decide(e.state, ev, at)
	if err != nil {
		return nil, err
	}
	e.state = next
	if v, ok := sourceVersionOf(ev); ok {
		e.last = v
	}
	out := make([]ShadowDecision, 0, len(intents))
	for _, in := range intents {
		d := ShadowDecision{Entity: in.Key.Entity, Kind: in.Key.Kind, ImpactRevision: in.Key.ImpactRevision, Ordinal: in.Key.Ordinal, Recipient: in.Key.Recipient,
			SourceVersion: e.last, DedupID: in.ID, Route: in.Route}
		if in.Disposition != DispositionDeliver {
			d.Suppression = in.Code
		}
		out = append(out, d)
	}
	return out, nil
}

// logicalKey identifies a notification independent of its recipients; a
// decision key adds the recipient.
type logicalKey struct {
	Entity         Entity
	Kind           Kind
	ImpactRevision uint64
	Ordinal        uint64
}

type decisionKey struct {
	logicalKey
	recipient    model.ID
	hasRecipient bool
}

func decisionKeyOf(l logicalKey, r *model.ID) decisionKey {
	k := decisionKey{logicalKey: l}
	if r != nil {
		k.recipient, k.hasRecipient = *r, true
	}
	return k
}

func (k decisionKey) recipientID() *model.ID {
	if !k.hasRecipient {
		return nil
	}
	r := k.recipient
	return &r
}

func (l logicalKey) less(o logicalKey) bool {
	switch {
	case l.Entity.Kind != o.Entity.Kind:
		return l.Entity.Kind < o.Entity.Kind
	case l.Entity.ID != o.Entity.ID:
		return l.Entity.ID.String() < o.Entity.ID.String()
	case l.Kind != o.Kind:
		return l.Kind < o.Kind
	case l.ImpactRevision != o.ImpactRevision:
		return l.ImpactRevision < o.ImpactRevision
	}
	return l.Ordinal < o.Ordinal
}

// CompareParity compares the shadow decisions with the legacy decisions,
// decision by decision. A notification is identified by its entity, kind, impact
// revision and ordinal; for the ones both sides took it compares the intended
// recipients as sets, and for every recipient both reached the source version and
// the suppression. The legacy side is first collapsed by its own dedup ID (a
// legacy replay that carries the same dedup ID is one decision), and a dedup ID
// that stands for two different decisions, or two decisions that were never
// deduplicated against each other, are mismatches on their own. The result does not
// depend on the order of either stream.
func CompareParity(shadow []ShadowDecision, legacy []LegacyDecision) ParityReport {
	var report ParityReport
	add := func(l logicalKey, r *model.ID, field string) {
		report.Mismatches = append(report.Mismatches, ParityMismatch{Entity: l.Entity, Kind: l.Kind, ImpactRevision: l.ImpactRevision, Ordinal: l.Ordinal, Recipient: r, Field: field})
	}
	type side struct {
		source      uint64
		suppression Code
	}
	shadowBy := map[decisionKey]side{}
	dedupOfShadow := map[model.ID]decisionKey{}
	for _, d := range shadow {
		k := decisionKeyOf(logicalKey{d.Entity, d.Kind, d.ImpactRevision, d.Ordinal}, d.Recipient)
		if prev, ok := dedupOfShadow[d.DedupID]; ok && prev != k {
			add(k.logicalKey, k.recipientID(), "dedup")
			continue
		}
		dedupOfShadow[d.DedupID] = k
		if _, ok := shadowBy[k]; !ok {
			shadowBy[k] = side{d.SourceVersion, d.Suppression}
		}
	}
	legacyBy := map[decisionKey]side{}
	dedupOfLegacy := map[string]decisionKey{}
	for _, d := range legacy {
		k := decisionKeyOf(logicalKey{d.Entity, d.Kind, d.ImpactRevision, d.Ordinal}, d.Recipient)
		if prev, ok := dedupOfLegacy[d.DedupID]; ok {
			if prev != k {
				add(k.logicalKey, k.recipientID(), "dedup")
			}
			continue // the same dedup ID again: one decision
		}
		dedupOfLegacy[d.DedupID] = k
		if _, ok := legacyBy[k]; ok {
			add(k.logicalKey, k.recipientID(), "dedup") // the same decision under two dedup IDs
			continue
		}
		legacyBy[k] = side{d.SourceVersion, d.Suppression}
	}
	recipients := func(by map[decisionKey]side) map[logicalKey]map[decisionKey]bool {
		out := map[logicalKey]map[decisionKey]bool{}
		for k := range by {
			if out[k.logicalKey] == nil {
				out[k.logicalKey] = map[decisionKey]bool{}
			}
			out[k.logicalKey][k] = true
		}
		return out
	}
	sr, lr := recipients(shadowBy), recipients(legacyBy)
	logical := make([]logicalKey, 0, len(sr))
	seen := map[logicalKey]bool{}
	for l := range sr {
		logical, seen[l] = append(logical, l), true
	}
	for l := range lr {
		if !seen[l] {
			logical = append(logical, l)
		}
	}
	sort.Slice(logical, func(i, j int) bool { return logical[i].less(logical[j]) })
	for _, l := range logical {
		s, ok1 := sr[l]
		g, ok2 := lr[l]
		switch {
		case !ok2:
			add(l, nil, "only_shadow")
			continue
		case !ok1:
			add(l, nil, "only_legacy")
			continue
		}
		same := len(s) == len(g)
		for k := range s {
			if !g[k] {
				same = false
			}
		}
		if !same {
			add(l, nil, "recipients")
		}
		keys := make([]decisionKey, 0, len(s))
		for k := range s {
			if g[k] {
				keys = append(keys, k)
			}
		}
		sort.Slice(keys, func(i, j int) bool {
			if keys[i].hasRecipient != keys[j].hasRecipient {
				return !keys[i].hasRecipient
			}
			return keys[i].recipient.String() < keys[j].recipient.String()
		})
		for _, k := range keys {
			report.Compared++
			a, b := shadowBy[k], legacyBy[k]
			if a.source != b.source {
				add(l, k.recipientID(), "source_version")
			}
			if a.suppression != b.suppression {
				add(l, k.recipientID(), "suppression")
			}
		}
	}
	sort.SliceStable(report.Mismatches, func(i, j int) bool {
		a, b := report.Mismatches[i], report.Mismatches[j]
		la, lb := logicalKey{a.Entity, a.Kind, a.ImpactRevision, a.Ordinal}, logicalKey{b.Entity, b.Kind, b.ImpactRevision, b.Ordinal}
		if la != lb {
			return la.less(lb)
		}
		return a.Field < b.Field
	})
	return report
}

// ManifestDigest identifies a frontier manifest; the barrier evidence is bound
// to the manifest of the command that carries it.
func ManifestDigest(f []FrontierEntry) model.Hash { return control.CutoverManifestDigest(f) }

// maxOwnerRetries bounds how often one claim is re-read after a cutover moved
// between its read and its commit.
const maxOwnerRetries = 3

func faultDetail(err error) (model.Code, string) {
	var f *model.Fault
	if errors.As(err, &f) {
		return f.Code, f.SafeDetail
	}
	return "", ""
}

// SyncModes brings every policy state of the scope's project to the delivery
// mode the cutover phase requires (ModeFor), with one idempotent owner_cutover
// event per state whose command ID derives from the cutover, its revision and
// the subject: a retry, a second worker or a restart decides nothing twice. It
// returns how many states it changed. A state that moved under it (a decision
// advanced its owner revision first) is left for the next call.
func (o *Outbox) SyncModes(ctx context.Context, scope auth.Scope, lease FenceToken, phase CutoverPhase, cutover model.ID, revision model.Revision, at model.UnixNano) (int, error) {
	project, err := o.project(scope)
	if err != nil {
		return 0, err
	}
	if err = validLease(lease); err != nil || !phase.Valid() || cutover == (model.ID{}) || revision == 0 || at <= 0 {
		return 0, model.Fail(model.Invalid)
	}
	recs, err := o.store.PolicyRecords(ctx, scope, project)
	if err != nil {
		return 0, err
	}
	want := ModeFor(phase)
	changed := 0
	for _, rec := range recs {
		var ps PolicyState
		if err = json.Unmarshal(rec.State, &ps); err != nil {
			return changed, model.Fail(model.Corrupt)
		}
		if ps.Mode == want {
			continue
		}
		command := commandID([]byte("cutover-sync"), orgBytes(scope), project[:], cutover[:], u64(uint64(revision)), []byte(rec.Subject), rec.Policy[:])
		owner := ps.Owner
		ev := PolicyEvent{Kind: EventCutover, Command: command, Org: scope.OrgID(), Project: project, Policy: ps.Policy, PolicyRef: PolicyRef{Revision: ps.PolicyRevision},
			OwnerRevision: ps.OwnerRevision, Entity: &owner, Cutover: &OwnerCutover{Command: command, To: owner, Mode: want}}
		sub, err := o.Submit(ctx, scope, lease, ps.Subject, ev, at)
		if reason, ok := ReasonOf(err); ok && reason == ReasonOwnerRevision {
			continue
		}
		if err != nil {
			return changed, err
		}
		if !sub.Unchanged {
			changed++
		}
	}
	return changed, nil
}
