// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"slices"
	"sort"
	"strconv"
	"strings"

	"soundpost/internal/auth"
	"soundpost/internal/model"
)

// Cutover phases. They are the closed set of notification ownership states of
// one project. Exactly one normal-notification owner is active in shadow,
// quiescing_old, new_active and old_active; none is active in barrier_verified
// and rollback_quiescing (see CutoverActiveOwners).
const (
	CutoverShadow            = "shadow"
	CutoverQuiescingOld      = "quiescing_old"
	CutoverBarrierVerified   = "barrier_verified"
	CutoverNewActive         = "new_active"
	CutoverRollbackQuiescing = "rollback_quiescing"
	CutoverOldActive         = "old_active"
)

// CutoverFrontier is one entry of the source/version frontier manifest: the
// source, the source policy revision the frontier was taken at and the data
// journal cursor the old owner had processed through.
type CutoverFrontier struct {
	Source  model.ID       `json:"source"`
	Version model.Revision `json:"version"`
	Cursor  model.Cursor   `json:"cursor"`
}

// CutoverAccounting is the delivery accounting the operator attests and this
// product verifies against its own committed deliveries.
type CutoverAccounting struct {
	Pending       uint32     `json:"pending"`
	Claimed       uint32     `json:"claimed"`
	Unknown       uint32     `json:"unknown"`
	UnknownDigest model.Hash `json:"unknown_digest"`
	Reviewed      bool       `json:"reviewed"`
}

// CutoverOwnerEvidence is the external owner's own state as the operator flow
// observed it. The product records it and checks its shape, binding and age; it
// cannot observe the external system.
type CutoverOwnerEvidence struct {
	Owner           model.ID       `json:"owner"`
	Method          string         `json:"method"`
	ObservedAt      model.UnixNano `json:"observed_at_ns"`
	Ref             model.Hash     `json:"ref"`
	Pending         uint32         `json:"pending"`
	Unknown         uint32         `json:"unknown"`
	UnknownReviewed bool           `json:"unknown_reviewed"`
}

// CutoverAuthorization is the explicit authorization of the operator: the
// principal must be the scope's own and the window is bounded.
type CutoverAuthorization struct {
	Principal    model.ID       `json:"principal"`
	Ref          model.Hash     `json:"ref"`
	AuthorizedAt model.UnixNano `json:"authorized_at_ns"`
	ExpiresAt    model.UnixNano `json:"expires_at_ns"`
}

// CutoverRoute is the rollback route: the owner it returns to and the digest of
// the audited runbook step.
type CutoverRoute struct {
	Owner model.ID   `json:"owner"`
	Ref   model.Hash `json:"ref"`
}

// CutoverObserver is the independent observer proof: who observes, the failure
// domain the operator asserts for the observer and for this product, and when
// the observer last proved itself armed. The product checks that the two
// asserted domains differ; it cannot verify them.
type CutoverObserver struct {
	Observer      model.ID       `json:"observer"`
	Domain        model.ID       `json:"domain"`
	ProductDomain model.ID       `json:"product_domain"`
	ObservedAt    model.UnixNano `json:"observed_at_ns"`
	Ref           model.Hash     `json:"ref"`
}

// CutoverEvidence is the barrier evidence of one transition.
type CutoverEvidence struct {
	Cutover           model.ID              `json:"cutover"`
	ForRevision       model.Revision        `json:"for_revision"`
	ManifestDigest    model.Hash            `json:"manifest_digest"`
	Accounting        CutoverAccounting     `json:"accounting"`
	Owner             *CutoverOwnerEvidence `json:"owner,omitempty"`
	Authorization     *CutoverAuthorization `json:"authorization,omitempty"`
	Route             *CutoverRoute         `json:"route,omitempty"`
	Observer          *CutoverObserver      `json:"observer,omitempty"`
	RestoreGeneration *model.ID             `json:"restore_generation,omitempty"`
}

// CutoverTransition is the closed payload of the cutover operation of
// KindClaimDelivery: one requested phase with the command's frontier manifest,
// reason and barrier evidence. At is the deterministic command time.
type CutoverTransition struct {
	Project          model.ID          `json:"project"`
	ExpectedRevision model.Revision    `json:"expected_revision"`
	Old              model.ID          `json:"old"`
	New              model.ID          `json:"new"`
	Phase            string            `json:"phase"`
	At               model.UnixNano    `json:"at_ns"`
	Reason           string            `json:"reason"`
	Frontier         []CutoverFrontier `json:"frontier"`
	Evidence         *CutoverEvidence  `json:"evidence,omitempty"`
}

// Digest identifies the command's content, the time excluded: a retry of the
// same command at another instant is the same command.
func (t CutoverTransition) Digest() model.Hash {
	t.At = 0
	t.Frontier = sortedFrontier(t.Frontier)
	raw, _ := json.Marshal(t)
	h := sha256.New()
	h.Write([]byte("soundpost.control.cutover.command.v1\x00"))
	h.Write(raw)
	var out model.Hash
	copy(out[:], h.Sum(nil))
	return out
}

// CutoverStep is one committed transition.
type CutoverStep struct {
	Command   model.ID        `json:"command"`
	Principal model.ID        `json:"principal"`
	Digest    model.Hash      `json:"digest"`
	From      string          `json:"from"`
	To        string          `json:"to"`
	Revision  model.Revision  `json:"revision"`
	Epoch     model.Uint64    `json:"epoch"`
	At        model.UnixNano  `json:"at_ns"`
	Evidence  *model.Hash     `json:"evidence_digest,omitempty"`
	Reason    string          `json:"reason,omitempty"`
	Payload   json.RawMessage `json:"evidence,omitempty"`
}

// CutoverRecord is everything control holds for one project's cutover.
type CutoverRecord struct {
	Org          model.ID          `json:"org"`
	Project      model.ID          `json:"project"`
	ID           model.ID          `json:"id"`
	Old          model.ID          `json:"old"`
	New          model.ID          `json:"new"`
	Revision     model.Revision    `json:"revision"`
	Phase        string            `json:"phase"`
	Epoch        model.Uint64      `json:"epoch"`
	EnteredAt    model.UnixNano    `json:"entered_at_ns"`
	QuiesceStart model.UnixNano    `json:"quiesce_start_ns,omitempty"`
	Frontier     []CutoverFrontier `json:"frontier"`
	RestoreAck   *model.ID         `json:"restore_ack,omitempty"`
	Steps        []CutoverStep     `json:"steps"`
	Erased       *model.ID         `json:"erased,omitempty"`
}

// CutoverFacts are the product-side facts a barrier is verified against.
type CutoverFacts struct {
	Pending       uint32
	Claimed       uint32
	Lapsed        uint32
	Unknown       uint32
	UnknownDigest model.Hash
	Checkpoints   []model.Cursor
	// Restore is the generation of a committed disaster-restore quarantine that
	// the cutover has not acknowledged yet.
	Restore *model.ID
}

// The SafeDetails of the cutover refusals.
const (
	CutoverRevisionConflict  = "cutover_revision_conflict"
	CutoverTransitionInvalid = "cutover_transition_invalid"
	CutoverBarrierFailed     = "cutover_barrier_failed"
	CutoverIdentityConflict  = "cutover_identity_conflict"
)

func cutoverKey(org, project model.ID) string { return org.String() + ":" + project.String() }

// CutoverActiveOwners names the normal-notification owners active in a phase:
// never more than one.
func CutoverActiveOwners(phase string, old, newOwner model.ID) []model.ID {
	switch phase {
	case CutoverShadow, CutoverQuiescingOld, CutoverOldActive:
		return []model.ID{old}
	case CutoverNewActive:
		return []model.ID{newOwner}
	}
	return nil
}

// ActiveOwners is CutoverActiveOwners of the record.
func (r CutoverRecord) ActiveOwners() []model.ID { return CutoverActiveOwners(r.Phase, r.Old, r.New) }

func loadCutover(st *State, key string) (CutoverRecord, bool, error) {
	raw, ok := st.CutoverBooks[key]
	if !ok {
		return CutoverRecord{}, false, nil
	}
	var r CutoverRecord
	if err := json.Unmarshal(raw, &r); err != nil {
		return CutoverRecord{}, false, model.Fail(model.Corrupt)
	}
	return r, true, nil
}

func storeCutover(st *State, key string, r CutoverRecord) error {
	raw, err := json.Marshal(r)
	if err != nil {
		return model.Fail(model.Invalid)
	}
	if st.CutoverBooks == nil {
		st.CutoverBooks = map[string]json.RawMessage{}
	}
	st.CutoverBooks[key] = raw
	return nil
}

// The bounds of one cutover record. Everything over a bound is refused, never
// truncated, except the step history, which keeps the newest steps.
const (
	maxCutoverFrontier = 16
	maxCutoverSteps    = 64
	maxCutoverReason   = 512
)

// The bounds of the barrier evidence's freshness.
const (
	// CutoverMaxEvidenceAge is how old the old-owner-disabled observation may be
	// when a barrier is verified.
	CutoverMaxEvidenceAge = model.UnixNano(60 * 60 * 1e9)
	// CutoverMaxObserverAge is how old the independent observer's last proof may
	// be: an observer that has not proved itself recently is an unknown state.
	CutoverMaxObserverAge = model.UnixNano(15 * 60 * 1e9)
	// CutoverMaxAuthorization is the longest authorization window.
	CutoverMaxAuthorization = model.UnixNano(24 * 60 * 60 * 1e9)
)

// The closed codes of the barrier checks; a failed barrier lists every one that
// did not hold.
const (
	checkEvidenceMissing       = "evidence_missing"
	checkEvidenceBinding       = "evidence_binding"
	checkManifestDigest        = "manifest_digest"
	checkSourceUnknown         = "source_unknown"
	checkSourceVersion         = "source_version"
	checkCheckpointBehind      = "checkpoint_behind"
	checkAccountingPending     = "accounting_pending"
	checkAccountingClaimed     = "accounting_claimed"
	checkAccountingUnknown     = "accounting_unknown"
	checkClaimsLive            = "claims_live"
	checkUnknownUnreviewed     = "unknown_unreviewed"
	checkOwnerEvidence         = "owner_evidence"
	checkOwnerStale            = "owner_stale"
	checkOwnerPending          = "owner_pending"
	checkAuthorization         = "authorization"
	checkRoute                 = "route"
	checkObserver              = "observer"
	checkObserverStale         = "observer_stale"
	checkObserverDomain        = "observer_domain"
	checkRestoreUnacknowledged = "restore_unacknowledged"
)

// More SafeDetails of the cutover refusals.
const (
	cutoverFrontierRegressed = "cutover_frontier_regressed"
	cutoverTimeRegressed     = "cutover_time_regressed"
)

// restoreQuarantineKey is where a disaster restore's quarantine stash lives in
// the committed state (internal/auth/restore.go). A pinned test drives the real
// auth.QuarantineRestoredState and reads it back through restoreOf, so a rename
// there fails here.
const restoreQuarantineKey = "restore:quarantine"

type restoreMarker struct {
	Generation model.ID `json:"generation"`
	At         int64    `json:"at"`
}

// restoreOf reports the committed restore quarantine, if any. A marker that
// cannot be read is present with a zero generation: nothing can acknowledge it.
func restoreOf(st *State) (restoreMarker, bool) {
	raw, ok := st.OIDC[restoreQuarantineKey]
	if !ok {
		return restoreMarker{}, false
	}
	var m restoreMarker
	_ = json.Unmarshal(raw, &m)
	return m, true
}

// restorePending reports the committed restore generation the cutover has not
// acknowledged yet.
func restorePending(st *State, rec CutoverRecord, found bool) (restoreMarker, bool) {
	m, ok := restoreOf(st)
	if !ok {
		return m, false
	}
	if found && rec.RestoreAck != nil && m.Generation != (model.ID{}) && *rec.RestoreAck == m.Generation {
		return m, false
	}
	return m, true
}

func sortedFrontier(f []CutoverFrontier) []CutoverFrontier {
	out := slices.Clone(f)
	sort.Slice(out, func(i, j int) bool { return out[i].Source.String() < out[j].Source.String() })
	return out
}

// CutoverManifestDigest identifies a source/version frontier manifest, in
// canonical (source) order: the barrier evidence is bound to the manifest of the
// command that carries it.
func CutoverManifestDigest(f []CutoverFrontier) model.Hash {
	raw, _ := json.Marshal(sortedFrontier(f))
	h := sha256.New()
	h.Write([]byte("soundpost.control.cutover.manifest.v1\x00"))
	h.Write(raw)
	var out model.Hash
	copy(out[:], h.Sum(nil))
	return out
}

// cutoverNext is the closed transition table. new_active to new_active is not
// in it: it is only the acknowledgment of a disaster restore (applyCutover).
var cutoverNext = map[string][]string{
	"":                       {CutoverShadow},
	CutoverShadow:            {CutoverQuiescingOld},
	CutoverQuiescingOld:      {CutoverBarrierVerified, CutoverShadow},
	CutoverBarrierVerified:   {CutoverNewActive, CutoverShadow},
	CutoverNewActive:         {CutoverRollbackQuiescing},
	CutoverRollbackQuiescing: {CutoverOldActive},
	CutoverOldActive:         {CutoverQuiescingOld},
}

func cutoverNeedsEvidence(phase string) bool {
	return phase == CutoverBarrierVerified || phase == CutoverNewActive || phase == CutoverOldActive
}

func cutoverReason(s string) bool {
	// A decoded JSON string is always valid UTF-8 (the decoder substitutes U+FFFD),
	// so only the length and the control characters need checking.
	if s == "" || len(s) > maxCutoverReason {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func (t CutoverTransition) validShape() error {
	if t.Project == (model.ID{}) || t.Old == (model.ID{}) || t.New == (model.ID{}) || t.Old == t.New || t.At <= 0 || !cutoverReason(t.Reason) {
		return model.Fail(model.Invalid)
	}
	if _, ok := cutoverNext[t.Phase]; !ok || t.Phase == "" {
		return model.Fail(model.Invalid)
	}
	if n := len(t.Frontier); n == 0 || n > maxCutoverFrontier {
		return model.Fail(model.Invalid)
	}
	seen := map[model.ID]bool{}
	for _, f := range t.Frontier {
		if f.Source == (model.ID{}) || f.Version == 0 || f.Cursor.Group == (model.ID{}) || seen[f.Source] {
			return model.Fail(model.Invalid)
		}
		seen[f.Source] = true
	}
	if !cutoverNeedsEvidence(t.Phase) && t.Evidence != nil {
		return model.Fail(model.Invalid)
	}
	return nil
}

// cutoverGate is what the committed state says about the product sending for
// one project.
type cutoverGate struct {
	// revision is the committed cutover revision (zero when the project has none).
	revision model.Revision
	// block is why the product may not send: the cutover is not in new_active
	// (CutoverShadow's code), or a restore has not been acknowledged
	// (DeliveryCodeRestorePending). Empty means it may.
	block string
}

func cutoverGateOf(st *State, org, project model.ID) (cutoverGate, error) {
	rec, found, err := loadCutover(st, cutoverKey(org, project))
	if err != nil {
		return cutoverGate{}, err
	}
	g := cutoverGate{}
	if found {
		g.revision = rec.Revision
	}
	switch _, pending := restorePending(st, rec, found); {
	case found && rec.Phase != CutoverNewActive:
		g.block = DeliveryCodeShadow
	case pending:
		g.block = DeliveryCodeRestorePending
	}
	return g, nil
}

// CutoverRevision is the committed cutover revision of a project: zero when the
// project has no cutover record.
func CutoverRevision(st State, org, project model.ID) model.Revision {
	rec, found, err := loadCutover(&st, cutoverKey(org, project))
	if err != nil || !found {
		return 0
	}
	return rec.Revision
}

// cutoverCounts are the product's own delivery facts of one project at an
// instant: pending deliveries, live and lapsed claims and the unknown set.
type cutoverCounts struct {
	pending, claimed, lapsed uint32
	unknown                  []model.ID
}

// cutoverCountsOf derives the counts from the committed deliveries. The unknown
// set is every delivery still outstanding whose send may have reached the
// provider: one that is uncertain, one that went pending again after an unknown
// attempt, and every claim whose lease lapsed without a completion.
func cutoverCountsOf(st *State, org, project model.ID, at model.UnixNano) (cutoverCounts, error) {
	recs, err := projectDeliveries(st, org, project)
	if err != nil {
		return cutoverCounts{}, err
	}
	var c cutoverCounts
	for _, r := range recs {
		unknown := false
		switch r.Phase {
		case DeliveryPending:
			c.pending++
			unknown = r.Uncertain
		case DeliveryClaimed:
			lapsed := len(r.Attempts) == 0 || at >= r.Attempts[len(r.Attempts)-1].Expires
			if lapsed {
				c.lapsed++
			} else {
				c.claimed++
			}
			unknown = lapsed || r.Uncertain
		case DeliveryUncertain:
			unknown = true
		}
		if unknown {
			c.unknown = append(c.unknown, r.ID)
		}
	}
	sort.Slice(c.unknown, func(i, j int) bool { return c.unknown[i].String() < c.unknown[j].String() })
	return c, nil
}

func unknownDigest(ids []model.ID) model.Hash {
	h := sha256.New()
	h.Write([]byte("soundpost.control.cutover.unknown.v1\x00"))
	for _, id := range ids {
		h.Write(id[:])
	}
	var out model.Hash
	copy(out[:], h.Sum(nil))
	return out
}

// issueCheckpoints are the project's committed issue checkpoints per data group:
// the highest journal cursor whose lifecycle effects are committed.
func issueCheckpoints(st *State, org, project model.ID) (map[model.ID]uint64, error) {
	raw, ok := st.IssueBooks[issueBookKey(org, project)]
	if !ok {
		return nil, nil
	}
	var book struct {
		Checkpoints map[string]model.Uint64 `json:"checkpoints"`
	}
	if json.Unmarshal(raw, &book) != nil {
		return nil, model.Fail(model.Corrupt)
	}
	out := make(map[model.ID]uint64, len(book.Checkpoints))
	for key, index := range book.Checkpoints {
		group, err := model.ParseID(key)
		if err != nil {
			return nil, model.Fail(model.Corrupt)
		}
		out[group] = uint64(index)
	}
	return out, nil
}

type failedChecks struct{ codes []string }

func (f *failedChecks) fail(code string) {
	if !slices.Contains(f.codes, code) {
		f.codes = append(f.codes, code)
	}
}

// verifyCutoverEvidence verifies the barrier evidence of one transition against
// the committed state and returns the closed code of every check that did not
// hold. It reads no clock: At is the command's.
func verifyCutoverEvidence(scope auth.Scope, st *State, rec CutoverRecord, t CutoverTransition, reactivation bool, marker restoreMarker, restorePend bool) ([]string, error) {
	var f failedChecks
	e := t.Evidence
	if e == nil {
		return []string{checkEvidenceMissing}, nil
	}
	org := scope.OrgID()
	counts, err := cutoverCountsOf(st, org, t.Project, t.At)
	if err != nil {
		return nil, err
	}
	forward := t.Phase != CutoverOldActive

	// Binding: evidence prepared for another cutover, an older revision or another
	// manifest is not evidence of this transition.
	if e.Cutover != rec.ID || e.ForRevision != rec.Revision {
		f.fail(checkEvidenceBinding)
	}
	if e.ManifestDigest != CutoverManifestDigest(t.Frontier) {
		f.fail(checkManifestDigest)
	}

	// The verified source checkpoints: the frontier is the old owner's; the
	// product's own committed checkpoints must have reached it.
	if forward {
		checkpoints, err := issueCheckpoints(st, org, t.Project)
		if err != nil {
			return nil, err
		}
		for _, fe := range t.Frontier {
			src, ok := st.Sources[fe.Source.String()]
			switch {
			case !ok || src.Org != org || src.Project != t.Project || src.Revoked || src.Retired || src.Closing || !src.Policy.Enabled:
				f.fail(checkSourceUnknown)
			case src.Policy.Revision != fe.Version:
				f.fail(checkSourceVersion)
			}
			if reached, ok := checkpoints[fe.Cursor.Group]; !ok || reached < uint64(fe.Cursor.Index) {
				f.fail(checkCheckpointBehind)
			}
		}
	}

	// The delivery accounting: what the operator attests must be what is committed.
	a := e.Accounting
	if a.Pending != counts.pending {
		f.fail(checkAccountingPending)
	}
	if a.Claimed != counts.claimed {
		f.fail(checkAccountingClaimed)
	}
	if counts.claimed > 0 {
		f.fail(checkClaimsLive)
	}
	if a.Unknown != uint32(len(counts.unknown)) || a.UnknownDigest != unknownDigest(counts.unknown) {
		f.fail(checkAccountingUnknown)
	}
	if len(counts.unknown) > 0 && !a.Reviewed {
		f.fail(checkUnknownUnreviewed)
	}

	// The old owner's disablement (forward only): observed after the quiescing
	// began (after the restore, when one is being acknowledged), fresh, bound to
	// the right owner and reporting nothing pending.
	if forward {
		o := e.Owner
		want := rec.Old
		if reactivation {
			want = rec.New // the previous incarnation of the new owner
		}
		if o == nil || o.Owner != want || !deliveryCode(o.Method) || o.Ref == (model.Hash{}) {
			f.fail(checkOwnerEvidence)
		}
		if o != nil {
			lower := rec.QuiesceStart
			if restorePend && model.UnixNano(marker.At) > lower {
				lower = model.UnixNano(marker.At)
			}
			if o.ObservedAt <= 0 || o.ObservedAt > t.At || t.At-o.ObservedAt > CutoverMaxEvidenceAge || o.ObservedAt < lower {
				f.fail(checkOwnerStale)
			}
			if o.Pending != 0 {
				f.fail(checkOwnerPending)
			}
			if o.Unknown > 0 && !o.UnknownReviewed {
				f.fail(checkUnknownUnreviewed)
			}
		}
	} else if e.Owner != nil {
		f.fail(checkOwnerEvidence) // a rollback attests nothing about the old owner yet
	}

	// The explicit authorization: the caller's own, bounded in time.
	if z := e.Authorization; z == nil || z.Principal != scope.PrincipalID() || z.Ref == (model.Hash{}) || z.AuthorizedAt <= 0 || z.AuthorizedAt > t.At || t.At >= z.ExpiresAt || z.ExpiresAt-z.AuthorizedAt > CutoverMaxAuthorization {
		f.fail(checkAuthorization)
	}
	if r := e.Route; r == nil || r.Owner != rec.Old || r.Ref == (model.Hash{}) {
		f.fail(checkRoute)
	}

	// The independent observer: absent or stale is an unknown state, and the
	// asserted failure domains must differ.
	switch o := e.Observer; {
	case o == nil || o.Observer == (model.ID{}) || o.Domain == (model.ID{}) || o.ProductDomain == (model.ID{}) || o.Ref == (model.Hash{}):
		f.fail(checkObserver)
	default:
		if o.ObservedAt <= 0 || o.ObservedAt > t.At || t.At-o.ObservedAt > CutoverMaxObserverAge {
			f.fail(checkObserverStale)
		}
		if o.Domain == o.ProductDomain || o.Observer == rec.Old || o.Observer == rec.New {
			f.fail(checkObserverDomain)
		}
	}

	// A committed restore must be acknowledged by the activation.
	if restorePend && t.Phase == CutoverNewActive && (e.RestoreGeneration == nil || marker.Generation == (model.ID{}) || *e.RestoreGeneration != marker.Generation) {
		f.fail(checkRestoreUnacknowledged)
	}
	return f.codes, nil
}

// revokeOpenDeliveries ends, in the cutover's own transition, every delivery that
// is still open: nothing the previous owner may already have handled is sent late
// by the next one. An unsent delivery is cancelled as revoked; one that may have
// reached the provider (a claim whose lease lapsed, a retry after an unknown
// attempt) settles as uncertain, never as success and never retried. The
// transition has already verified that no claim is live.
func revokeOpenDeliveries(st *State, org, project model.ID, at model.UnixNano, a *deliveryAudit) error {
	recs, err := projectDeliveries(st, org, project)
	if err != nil {
		return err
	}
	for _, r := range recs {
		switch r.Phase {
		case DeliveryPending:
			phase := DeliveryCancelled
			if r.Uncertain {
				phase = DeliveryUncertain
			}
			settleDelivery(&r, phase, DeliveryReasonRevoked, at)
		case DeliveryClaimed:
			closeAttempt(&r.Attempts[len(r.Attempts)-1], at, DeliveryOutcomeUnknown, DeliveryCodeClaimExpired, "system")
			r.Uncertain = true
			a.add(DeliveryOutcomeUnknown, r.ID, DeliveryCodeClaimExpired, at)
			settleDelivery(&r, DeliveryUncertain, DeliveryReasonRevoked, at)
		default:
			continue
		}
		a.add(r.Phase, r.ID, DeliveryReasonRevoked, at)
		if err = storeDelivery(st, r); err != nil {
			return err
		}
	}
	return nil
}

// applyCutover is the cutover operation of the delivery handler. The scope has
// been validated as an organization administrator of the command's project; no
// lease is involved because this is an operator command, not a worker's.
func applyCutover(scope auth.Scope, st *State, cmd Command, t CutoverTransition) (Effect, error) {
	if err := t.validShape(); err != nil {
		return Effect{}, err
	}
	org := scope.OrgID()
	key := cutoverKey(org, t.Project)
	rec, found, err := loadCutover(st, key)
	if err != nil {
		return Effect{}, err
	}
	current := model.Revision(0)
	if found {
		current = rec.Revision
	}
	if t.ExpectedRevision != current {
		return Effect{}, ruleFault(model.Conflict, CutoverRevisionConflict+" current="+strconv.FormatUint(uint64(current), 10))
	}
	if found && (t.Old != rec.Old || t.New != rec.New) {
		return Effect{}, ruleFault(model.Conflict, CutoverIdentityConflict)
	}
	from := ""
	if found {
		from = rec.Phase
		if t.At < rec.EnteredAt {
			return Effect{}, ruleFault(model.Conflict, cutoverTimeRegressed)
		}
	}
	marker, restorePend := restorePending(st, rec, found)
	reactivation := found && from == CutoverNewActive && t.Phase == CutoverNewActive && restorePend
	if !reactivation && !slices.Contains(cutoverNext[from], t.Phase) {
		return Effect{}, ruleFault(model.Conflict, CutoverTransitionInvalid)
	}
	// The frontier only moves forward: every known source stays, at the same or a
	// later version, and no cursor of the same group goes back.
	if found {
		next := map[model.ID]CutoverFrontier{}
		for _, f := range t.Frontier {
			next[f.Source] = f
		}
		for _, old := range rec.Frontier {
			n, ok := next[old.Source]
			if !ok || n.Version < old.Version || n.Cursor.Group == old.Cursor.Group && n.Cursor.Index < old.Cursor.Index {
				return Effect{}, ruleFault(model.Conflict, cutoverFrontierRegressed)
			}
		}
	}
	var payload json.RawMessage
	var evidence *model.Hash
	if cutoverNeedsEvidence(t.Phase) {
		failed, err := verifyCutoverEvidence(scope, st, rec, t, reactivation, marker, restorePend)
		if err != nil {
			return Effect{}, err
		}
		if len(failed) > 0 {
			return Effect{}, ruleFault(model.Conflict, CutoverBarrierFailed+" checks="+strings.Join(failed, ","))
		}
		if payload, err = json.Marshal(t.Evidence); err != nil {
			return Effect{}, model.Fail(model.Invalid)
		}
		d := model.Hash(sha256.Sum256(payload))
		evidence = &d
	}

	a := &deliveryAudit{st: st, scope: scope, cmd: cmd}
	if t.Phase == CutoverNewActive || t.Phase == CutoverOldActive {
		if err = revokeOpenDeliveries(st, org, t.Project, t.At, a); err != nil {
			return Effect{}, err
		}
		if err = pruneSettledDeliveries(st, org, t.Project); err != nil {
			return Effect{}, err
		}
	}
	if !found {
		rec = CutoverRecord{Org: org, Project: t.Project, ID: cmd.CommandID, Old: t.Old, New: t.New}
	}
	rec.Revision++
	switch t.Phase {
	case CutoverQuiescingOld:
		rec.QuiesceStart = t.At
	case CutoverNewActive:
		rec.Epoch++
		if restorePend {
			gen := marker.Generation
			rec.RestoreAck = &gen
		}
	}
	rec.Phase, rec.EnteredAt, rec.Frontier = t.Phase, t.At, sortedFrontier(t.Frontier)
	rec.Steps = append(rec.Steps, CutoverStep{Command: cmd.CommandID, Principal: scope.PrincipalID(), Digest: t.Digest(), From: from, To: t.Phase, Revision: rec.Revision, Epoch: rec.Epoch,
		At: t.At, Evidence: evidence, Reason: t.Reason, Payload: payload})
	if len(rec.Steps) > maxCutoverSteps {
		rec.Steps = slices.Clone(rec.Steps[len(rec.Steps)-maxCutoverSteps:])
	}
	if err = storeCutover(st, key, rec); err != nil {
		return Effect{}, err
	}
	reason := from
	if reason == "" {
		reason = "none"
	}
	st.Audits = append(st.Audits, model.ControlAudit{ID: deriveID(cmd.CommandID, 0xc001), Principal: scope.PrincipalID(), Action: "notify.cutover." + t.Phase, Reason: reason + "->" + t.Phase,
		Time: int64(t.At), Org: org.String(), PolicyEpoch: scope.PolicyEpoch(), Targets: []model.ID{rec.ID}, RequestID: cmd.CommandID, Outcome: model.AuditAllowed})
	return Effect{AffectedIDs: []model.ID{rec.ID}, Phase: t.Phase}, nil
}

// TransactCutover commits one cutover transition under the C05 command ID and
// returns the committed record. A command that only lost the race for the
// control revision (never a cutover conflict) is retried.
func (s *Store) TransactCutover(ctx context.Context, scope auth.Scope, id model.ID, t CutoverTransition) (CutoverRecord, error) {
	raw, err := json.Marshal(DeliveryCommand{Operation: DeliveryOpCutover, Cutover: &t})
	if err != nil {
		return CutoverRecord{}, model.Fail(model.Invalid)
	}
	for range 16 {
		var revision model.Revision
		if err = s.View(ctx, func(st State) error { revision = st.Revision; return nil }); err != nil {
			return CutoverRecord{}, err
		}
		_, err = s.Transact(ctx, scope, Command{CommandID: id, ExpectedRevision: revision, Kind: string(KindClaimDelivery), Payload: raw})
		var fault *model.Fault
		if errors.As(err, &fault) && fault.Code == model.Conflict && fault.SafeDetail == string(model.Conflict) {
			continue
		}
		break
	}
	if err != nil {
		return CutoverRecord{}, err
	}
	rec, found, err := s.Cutover(ctx, scope, t.Project)
	if err != nil || !found {
		return CutoverRecord{}, model.Fail(model.Corrupt)
	}
	return rec, nil
}

// Cutover reads one project's committed cutover record.
func (s *Store) Cutover(ctx context.Context, scope auth.Scope, project model.ID) (out CutoverRecord, found bool, err error) {
	err = s.View(ctx, func(st State) error {
		if e := ruleReadScope(scope, st, project); e != nil {
			return e
		}
		var e error
		out, found, e = loadCutover(&st, cutoverKey(scope.OrgID(), project))
		return e
	})
	return
}

// CutoverFacts reads the facts a barrier is verified against, at the instant at.
func (s *Store) CutoverFacts(ctx context.Context, scope auth.Scope, project model.ID, at model.UnixNano) (out CutoverFacts, err error) {
	err = s.View(ctx, func(st State) error {
		if e := ruleReadScope(scope, st, project); e != nil {
			return e
		}
		org := scope.OrgID()
		counts, e := cutoverCountsOf(&st, org, project, at)
		if e != nil {
			return e
		}
		out = CutoverFacts{Pending: counts.pending, Claimed: counts.claimed, Lapsed: counts.lapsed, Unknown: uint32(len(counts.unknown)), UnknownDigest: unknownDigest(counts.unknown)}
		checkpoints, e := issueCheckpoints(&st, org, project)
		if e != nil {
			return e
		}
		for group, index := range checkpoints {
			out.Checkpoints = append(out.Checkpoints, model.Cursor{Group: group, Index: model.Uint64(index)})
		}
		sort.Slice(out.Checkpoints, func(i, j int) bool { return out.Checkpoints[i].Group.String() < out.Checkpoints[j].Group.String() })
		rec, found, e := loadCutover(&st, cutoverKey(org, project))
		if e != nil {
			return e
		}
		if m, pending := restorePending(&st, rec, found); pending {
			gen := m.Generation
			out.Restore = &gen
		}
		return nil
	})
	return
}

// CutoverVersionOf extracts the current revision from a typed conflict.
func CutoverVersionOf(err error) (model.Revision, bool) {
	var f *model.Fault
	if !errors.As(err, &f) || !strings.HasPrefix(f.SafeDetail, CutoverRevisionConflict+" current=") {
		return 0, false
	}
	n, e := strconv.ParseUint(strings.TrimPrefix(f.SafeDetail, CutoverRevisionConflict+" current="), 10, 64)
	return model.Revision(n), e == nil
}

// The closed codes control records on a delivery it suppresses because the
// project's committed cutover state does not let the product send.
const (
	// DeliveryCodeShadow: the product is not the active owner (any phase but
	// new_active).
	DeliveryCodeShadow = "shadow"
	// DeliveryCodeRestorePending: a disaster restore was committed and the
	// activation that acknowledges it has not been.
	DeliveryCodeRestorePending = "restore_pending"
)
