// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"sort"
	"strings"
	"time"

	"soundpost/internal/auth"
	"soundpost/internal/model"
	"soundpost/internal/replica"
)

// This file is the C05 half of C08's durable notification outbox: the closed
// deterministic handler for KindClaimDelivery and KindCompleteDelivery. Like the
// incident and condition handlers it stores only leaf DTOs: the policy state
// and the delivery body are opaque JSON that the notify package computes with
// its pure reducer and decodes again; control never imports it and never
// interprets a body beyond the closed header below. What control owns,
// atomically in one command:
//
//   - enqueue (an operation of ClaimDelivery: the C05 vocabulary has no enqueue
//     kind, and enqueue is the producing half of the claim queue): the policy
//     state compare-and-set and every intent that decision produced, in ONE
//     transition, keyed by the stable intent ID. A crash can therefore never
//     separate a checkpointed decision from its deliveries, and a replayed
//     decision creates nothing twice;
//   - claim: lease and attempt together. A claim names the fence it was made
//     under, an expiry and an attempt number, all stored on the delivery;
//   - complete: the immutable close of exactly that attempt. It names the claim
//     it closes (attempt number and fence). A worker whose lease is older than
//     the highest one the project outbox accepted is stale, and a worker can
//     never close an attempt another lease opened;
//   - the unknown outcome: an attempt whose lease lapsed without a completion
//     may have reached the provider. The next claim closes it as unknown and
//     retries the SAME delivery ID; nothing here ever turns it into success;
//   - the bounded retry budget, the C12 pause/cancel of deliveries derived from
//     deleted or closing origins, and destination removal/disable as safe
//     terminal reasons, all derived from committed state, never a clock.
//
// No time, randomness or network is read here: every instant, expiry and retry
// schedule arrives in the command. A delivery is never deleted before it has
// settled; settled history is bounded, and every terminal reason is also a
// control audit entry that outlives the record.

// DeliveryCommand is the closed payload of KindClaimDelivery (operations
// enqueue and claim) and KindCompleteDelivery (operations complete and cancel):
// exactly one arm, the one named by Operation. Every arm carries the lease of
// the worker leader that decided it.
type DeliveryCommand struct {
	Operation string              `json:"operation"`
	Lease     *replica.FenceToken `json:"lease,omitempty"`
	Enqueue   *DeliveryEnqueue    `json:"enqueue,omitempty"`
	Claim     *DeliveryClaim      `json:"claim,omitempty"`
	Complete  *DeliveryComplete   `json:"complete,omitempty"`
	Cancel    *DeliveryCancel     `json:"cancel,omitempty"`
	// Cutover is the notification ownership transition of the project (plan 06
	// task 09, cutover.go). It is an operator command, not a worker command, so
	// it carries no lease.
	Cutover *CutoverTransition `json:"cutover,omitempty"`
}

// The operations of a DeliveryCommand.
const (
	DeliveryOpEnqueue  = "enqueue"
	DeliveryOpClaim    = "claim"
	DeliveryOpComplete = "complete"
	DeliveryOpCancel   = "cancel"
	// DeliveryOpCutover is the operation of the cutover arm.
	DeliveryOpCutover = "cutover"
)

// Delivery phases. pending and claimed are open; every other phase is settled.
// accepted always carries provider evidence. uncertain means the provider may
// have accepted a message the product could not confirm. queued is an in-product
// queue entry: it is never sent and never labelled accepted.
const (
	DeliveryPending    = "pending"
	DeliveryClaimed    = "claimed"
	DeliveryAccepted   = "accepted"
	DeliveryFailed     = "failed"
	DeliveryUncertain  = "uncertain"
	DeliveryCancelled  = "cancelled"
	DeliverySuppressed = "suppressed"
	DeliveryQueued     = "queued"
)

// Outcome kinds of an attempt; they mirror notify's closed outcome set.
const (
	DeliveryOutcomeAccepted = "accepted"
	DeliveryOutcomeRetry    = "retry"
	DeliveryOutcomeTerminal = "terminal"
	DeliveryOutcomeUnknown  = "unknown"
)

// Intent dispositions and routes; they mirror notify's closed sets.
const (
	DeliveryDispositionDeliver    = "deliver"
	DeliveryDispositionSuppressed = "suppressed"
	DeliveryDispositionFailed     = "failed"

	DeliveryRouteImmediate = "immediate"
	DeliveryRouteQueue     = "queue"
	DeliveryRouteDigest    = "digest"
)

// Safe reasons a delivery settles or pauses for. They are closed codes, never
// provider text.
const (
	DeliveryReasonDeleted             = "deleted"
	DeliveryReasonNoDestination       = "no_destination"
	DeliveryReasonDestinationDisabled = "destination_disabled"
	DeliveryReasonExpired             = "expired"
	DeliveryReasonExhausted           = "retry_exhausted"
	DeliveryReasonRevoked             = "revoked"
	DeliveryCodeClaimExpired          = "claim_expired"
	// DeliveryHoldPaused is a hold, not a settlement: a closing C12 deletion
	// covers the delivery's origin, so nothing may be sent until it fails (the
	// delivery resumes) or completes (the delivery is cancelled as deleted).
	DeliveryHoldPaused = "paused_deletion"
)

// Lease and retry bounds. They are the CEILING of the retry budget: a worker
// may be tighter, never looser. 12 attempts or 24 hours from first
// eligibility, whichever comes first.
const (
	DeliveryMaxAttempts = 12
	DeliveryMaxAge      = model.UnixNano(24 * time.Hour)
	DeliveryMaxClaimTTL = model.UnixNano(10 * time.Minute)

	maxDeliveryClaimLimit       = 64
	maxDeliveryIntents          = 64
	maxDeliveryBody             = 16 << 10
	maxPolicyStateBytes         = 256 << 10
	maxPolicyStatesPerProject   = 1024
	maxOpenDeliveriesPerProject = 4096
	maxSettledDeliveries        = 1024
	maxDeliveryToken            = 64
	maxDeliveryProvider         = 256
	maxDeliverySubject          = 80
)

// DeliveryEnqueue commits one policy decision: the policy state it was computed
// from (version compare-and-set), the state it produced and every intent.
type DeliveryEnqueue struct {
	Project model.ID `json:"project"`
	Policy  model.ID `json:"policy"`
	// Subject names the notification subject ("kind:id"); the policy state is
	// the opaque JSON of exactly that subject.
	Subject         string           `json:"subject"`
	ExpectedVersion model.Revision   `json:"expected_version"`
	NewVersion      model.Revision   `json:"new_version"`
	At              model.UnixNano   `json:"at_ns"`
	State           json.RawMessage  `json:"state"`
	Digest          model.Hash       `json:"digest"`
	Intents         []DeliveryIntent `json:"intents"`
}

// DeliveryIntent is one decided intent. ID is the stable idempotency ID; Body is
// the opaque canonical delivery shape (key, route, typed template) the notify
// package decodes, bound to the ID by Digest. Origin is the CLOSED evidence
// interval [OriginFrom, OriginTo] the intent was derived from, for C12 matching;
// zero means unknown, which a deletion treats as covered.
type DeliveryIntent struct {
	ID          model.ID        `json:"id"`
	Kind        string          `json:"kind"`
	Disposition string          `json:"disposition"`
	Route       string          `json:"route"`
	Code        string          `json:"code,omitempty"`
	Recipient   *model.ID       `json:"recipient,omitempty"`
	At          model.UnixNano  `json:"at_ns"`
	OriginFrom  model.UnixNano  `json:"origin_from_ns,omitempty"`
	OriginTo    model.UnixNano  `json:"origin_to_ns,omitempty"`
	Body        json.RawMessage `json:"body"`
	Digest      model.Hash      `json:"digest"`
}

// DeliveryClaim leases up to Limit due deliveries of one project to the lease
// holder until Expires, one attempt each.
type DeliveryClaim struct {
	Project model.ID       `json:"project"`
	Now     model.UnixNano `json:"now_ns"`
	Expires model.UnixNano `json:"expires_ns"`
	Limit   uint32         `json:"limit"`
	// OwnerRevision is the cutover revision the claiming worker observed (zero
	// when the project has no cutover). A claim that names another revision than
	// the committed one is stale and is refused (DeliveryOwnerStale).
	OwnerRevision model.Revision `json:"owner_revision,omitempty"`
}

// DeliveryComplete closes exactly one claimed attempt. For retry and unknown,
// Next is the absolute time the next attempt becomes eligible; RetryAfter is the
// provider's hint (a delay) and is audit only here: the worker folds it into
// Next, control only enforces the budget.
type DeliveryComplete struct {
	Project    model.ID       `json:"project"`
	Delivery   model.ID       `json:"delivery"`
	Attempt    uint32         `json:"attempt"`
	At         model.UnixNano `json:"at_ns"`
	Outcome    string         `json:"outcome"`
	Provider   string         `json:"provider,omitempty"`
	Code       string         `json:"code,omitempty"`
	RetryAfter model.UnixNano `json:"retry_after_ns,omitempty"`
	Next       model.UnixNano `json:"next_ns,omitempty"`
}

// DeliveryCancel settles one delivery that must not be sent, with a safe
// reason: an unclaimed pending delivery (Attempt 0), or the holder's own open
// claim, which is then closed as a definite non-send.
type DeliveryCancel struct {
	Project  model.ID       `json:"project"`
	Delivery model.ID       `json:"delivery"`
	Attempt  uint32         `json:"attempt,omitempty"`
	At       model.UnixNano `json:"at_ns"`
	Reason   string         `json:"reason"`
}

// DeliveryAttempt is one attempt. It is open until closed (Outcome empty), and
// never changes after it is closed.
type DeliveryAttempt struct {
	Number     uint32             `json:"number"`
	Fence      replica.FenceToken `json:"fence"`
	ClaimedAt  model.UnixNano     `json:"claimed_at_ns"`
	Expires    model.UnixNano     `json:"expires_ns"`
	Generation uint64             `json:"delete_generation,string"`
	ClosedAt   model.UnixNano     `json:"closed_at_ns,omitempty"`
	Outcome    string             `json:"outcome,omitempty"`
	Code       string             `json:"code,omitempty"`
	Provider   string             `json:"provider,omitempty"`
	RetryAfter model.UnixNano     `json:"retry_after_ns,omitempty"`
	Next       model.UnixNano     `json:"next_ns,omitempty"`
	ClosedBy   string             `json:"closed_by,omitempty"`
	// Owner is the cutover revision the claim was opened under (zero when the
	// project has no cutover): a claim is only ever valid in that revision.
	Owner model.Revision `json:"owner_revision,omitempty"`
}

// DeliveryRecord is everything control holds for one delivery. Hold is computed
// at read from committed deletion and destination state and is never stored.
type DeliveryRecord struct {
	ID          model.ID          `json:"id"`
	Org         model.ID          `json:"org"`
	Project     model.ID          `json:"project"`
	Policy      model.ID          `json:"policy"`
	Subject     string            `json:"subject"`
	Kind        string            `json:"kind"`
	Route       string            `json:"route"`
	Recipient   *model.ID         `json:"recipient,omitempty"`
	Disposition string            `json:"disposition"`
	Phase       string            `json:"phase"`
	Code        string            `json:"code,omitempty"`
	Eligible    model.UnixNano    `json:"eligible_ns"`
	Next        model.UnixNano    `json:"next_ns"`
	SettledAt   model.UnixNano    `json:"settled_ns,omitempty"`
	OriginFrom  model.UnixNano    `json:"origin_from_ns,omitempty"`
	OriginTo    model.UnixNano    `json:"origin_to_ns,omitempty"`
	Generation  uint64            `json:"delete_generation,string"`
	Created     model.Revision    `json:"created"`
	Body        json.RawMessage   `json:"body"`
	Digest      model.Hash        `json:"digest"`
	Attempts    []DeliveryAttempt `json:"attempts,omitempty"`
	// Uncertain is set by the first unknown attempt and never cleared: the
	// provider may have accepted a message the product could not confirm.
	Uncertain bool `json:"uncertain,omitempty"`
	// PossibleDuplicate says an accepted delivery was retried after an unknown
	// attempt, so the recipient may have received it more than once.
	PossibleDuplicate bool   `json:"possible_duplicate,omitempty"`
	Provider          string `json:"provider,omitempty"`
	Hold              string `json:"hold,omitempty"`
}

// Open reports that the delivery still needs work.
func (r DeliveryRecord) Open() bool { return r.Phase == DeliveryPending || r.Phase == DeliveryClaimed }

// PolicyRecord is the committed policy state of one notification subject.
type PolicyRecord struct {
	Org     model.ID        `json:"org"`
	Project model.ID        `json:"project"`
	Policy  model.ID        `json:"policy"`
	Subject string          `json:"subject"`
	Version model.Revision  `json:"version"`
	Digest  model.Hash      `json:"digest"`
	State   json.RawMessage `json:"state"`
}

// deliveryFenceRecord is the highest lease the project's outbox has accepted.
type deliveryFenceRecord struct {
	Fence replica.FenceToken `json:"fence"`
}

// The SafeDetails of the delivery outbox's typed refusals.
const (
	DeliveryLeaseStale       = "delivery_lease_stale"
	DeliveryClaimNotHeld     = "delivery_claim_not_held"
	DeliveryAttemptClosed    = "delivery_attempt_closed"
	DeliverySettled          = "delivery_settled"
	DeliveryPolicyConflict   = "delivery_policy_conflict"
	DeliveryIdentityConflict = "delivery_identity_conflict"
	// DeliveryOwnerStale refuses a claim that names another cutover revision than
	// the committed one.
	DeliveryOwnerStale = "delivery_owner_stale"
)

// BindDeliveryOutbox installs the delivery outbox handler for both
// KindClaimDelivery and KindCompleteDelivery on this Store only, like the other
// Bind* methods; it is a conflict to bind twice.
func (s *Store) BindDeliveryOutbox() error {
	if err := s.RegisterHandler(KindClaimDelivery, applyDelivery); err != nil {
		return err
	}
	return s.RegisterHandler(KindCompleteDelivery, applyDelivery)
}

func deliveryKey(id model.ID) string { return "delivery:" + id.String() }
func deliveryFenceKey(org, project model.ID) string {
	return "fence:" + org.String() + ":" + project.String()
}
func policyKey(org, project, policy model.ID, subject string) string {
	return "policy:" + org.String() + ":" + project.String() + ":" + policy.String() + ":" + subject
}

// deliveryCode is a bounded lowercase code: letters, digits and _ . : -.
func deliveryCode(s string) bool {
	if s == "" || len(s) > maxDeliveryToken {
		return false
	}
	for _, r := range s {
		if r != '_' && r != '.' && r != ':' && r != '-' && (r < 'a' || r > 'z') && (r < '0' || r > '9') {
			return false
		}
	}
	return true
}

// deliveryProviderID is a provider-assigned message identity: printable ASCII
// without spaces. It is observed evidence, never free text.
func deliveryProviderID(s string) bool {
	if s == "" || len(s) > maxDeliveryProvider {
		return false
	}
	for i := range len(s) {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

func deliverySubject(s string) bool {
	if len(s) < 3 || len(s) > maxDeliverySubject {
		return false
	}
	for _, r := range s {
		if r != '_' && r != ':' && r != '-' && (r < 'a' || r > 'z') && (r < '0' || r > '9') {
			return false
		}
	}
	return true
}

func loadDelivery(st *State, id model.ID) (DeliveryRecord, bool, error) {
	raw, ok := st.DeliveryBooks[deliveryKey(id)]
	if !ok {
		return DeliveryRecord{}, false, nil
	}
	var r DeliveryRecord
	if err := json.Unmarshal(raw, &r); err != nil {
		return DeliveryRecord{}, false, model.Fail(model.Corrupt)
	}
	return r, true, nil
}

func storeDelivery(st *State, r DeliveryRecord) error {
	r.Hold = ""
	raw, err := json.Marshal(r)
	if err != nil {
		return model.Fail(model.Invalid)
	}
	if st.DeliveryBooks == nil {
		st.DeliveryBooks = map[string]json.RawMessage{}
	}
	st.DeliveryBooks[deliveryKey(r.ID)] = raw
	return nil
}

func loadPolicy(st *State, key string) (PolicyRecord, bool, error) {
	raw, ok := st.DeliveryBooks[key]
	if !ok {
		return PolicyRecord{}, false, nil
	}
	var r PolicyRecord
	if err := json.Unmarshal(raw, &r); err != nil {
		return PolicyRecord{}, false, model.Fail(model.Corrupt)
	}
	return r, true, nil
}

// projectDeliveries decodes every delivery of one project, in (eligible, ID)
// order.
func projectDeliveries(st *State, org, project model.ID) ([]DeliveryRecord, error) {
	var out []DeliveryRecord
	for key, raw := range st.DeliveryBooks {
		if !strings.HasPrefix(key, "delivery:") {
			continue
		}
		var r DeliveryRecord
		if err := json.Unmarshal(raw, &r); err != nil {
			return nil, model.Fail(model.Corrupt)
		}
		if r.Org == org && r.Project == project {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Eligible != out[j].Eligible {
			return out[i].Eligible < out[j].Eligible
		}
		return out[i].ID.String() < out[j].ID.String()
	})
	return out, nil
}

// deriveID is a deterministic ID for the audit entries of one command.
func deriveID(command model.ID, n int) model.ID {
	h := sha256.New()
	h.Write([]byte("soundpost.control.delivery.audit.v1\x00"))
	h.Write(command[:])
	h.Write([]byte{byte(n >> 8), byte(n)})
	var id model.ID
	copy(id[:], h.Sum(nil))
	return id
}

// deliveryAudit appends the control audit entries of one command. IDs derive
// from the command ID, never from randomness, and every entry names only IDs and
// closed codes: it is the permanent trail that outlives a pruned delivery record.
type deliveryAudit struct {
	st    *State
	scope auth.Scope
	cmd   Command
	n     int
}

func (a *deliveryAudit) add(event string, id model.ID, reason string, at model.UnixNano) {
	a.n++
	a.st.Audits = append(a.st.Audits, model.ControlAudit{ID: deriveID(a.cmd.CommandID, a.n), Principal: a.scope.PrincipalID(), Action: "notify.delivery." + event, Reason: reason,
		Time: int64(at), Org: a.scope.OrgID().String(), PolicyEpoch: a.scope.PolicyEpoch(), Targets: []model.ID{id}, RequestID: a.cmd.CommandID, Outcome: model.AuditAllowed})
}

func loadDeliveryFence(st *State, org, project model.ID) (replica.FenceToken, bool, error) {
	raw, ok := st.DeliveryBooks[deliveryFenceKey(org, project)]
	if !ok {
		return replica.FenceToken{}, false, nil
	}
	var r deliveryFenceRecord
	if err := json.Unmarshal(raw, &r); err != nil {
		return replica.FenceToken{}, false, model.Fail(model.Corrupt)
	}
	return r.Fence, true, nil
}

// raiseDeliveryFence records the lease of an accepted command when it is newer
// than the highest one the project's outbox has accepted, so a deposed leader can
// never commit again, whichever delivery it names.
func raiseDeliveryFence(st *State, org, project model.ID, lease replica.FenceToken) error {
	if cur, ok, err := loadDeliveryFence(st, org, project); err != nil {
		return err
	} else if ok && !fenceBefore(cur, lease) {
		return nil
	}
	raw, err := json.Marshal(deliveryFenceRecord{Fence: lease})
	if err != nil {
		return model.Fail(model.Invalid)
	}
	if st.DeliveryBooks == nil {
		st.DeliveryBooks = map[string]json.RawMessage{}
	}
	st.DeliveryBooks[deliveryFenceKey(org, project)] = raw
	return nil
}

// deliveryCovered reports whether a deletion predicate covers the origin of a
// delivery. A retirement covers everything of its project. A historical range
// covers every delivery whose evidence interval overlaps it, for ANY signal of
// the predicate: a delivery does not record which signal it came from, and an
// unknown interval is treated as covered. An entity deletion names replay and
// profile roots, which a delivery never derives from.
func deliveryCovered(p model.DeletePredicate, r *DeliveryRecord) bool {
	if !p.CoversProject(r.Org, r.Project) {
		return false
	}
	switch p.Mode {
	case model.DeleteRetireOrg, model.DeleteRetireProject:
		return true
	case model.DeleteHistoricalRange:
		if r.OriginFrom == 0 && r.OriginTo == 0 {
			return true
		}
		return r.OriginFrom < p.End && r.OriginTo >= p.Start
	}
	return false
}

// deliveryVerdict is what committed state says about sending a delivery now:
// send it (zero value), pause it, or settle it with a safe phase and code.
type deliveryVerdict struct {
	pause       bool
	phase, code string
}

// deliveryGate revalidates, from committed state only, the destination and the C12
// deletion state of one delivery. The claim applies it atomically and the
// read side computes the same answer for the worker's check just before a send.
func deliveryGate(st *State, gate cutoverGate, gateErr error, r *DeliveryRecord) deliveryVerdict {
	if _, retired := st.RetiredOrgs[r.Org.String()]; retired {
		return deliveryVerdict{phase: DeliveryCancelled, code: DeliveryReasonDeleted}
	}
	if _, retired := st.RetiredProjects[r.Org.String()+":"+r.Project.String()]; retired {
		return deliveryVerdict{phase: DeliveryCancelled, code: DeliveryReasonDeleted}
	}
	// The product may only send while the project's committed cutover state lets it
	// (cutover.go): a delivery leased before the phase changed is revoked, and an
	// unreadable cutover record fails closed. The caller computes the gate once.
	switch {
	case gateErr != nil:
		return deliveryVerdict{pause: true}
	case gate.block != "":
		return deliveryVerdict{phase: DeliveryCancelled, code: DeliveryReasonRevoked}
	}
	paused := false
	for _, op := range st.Deletions {
		if !deliveryCovered(op.Predicate, r) {
			continue
		}
		switch op.Phase {
		case model.DeletePhaseComplete:
			return deliveryVerdict{phase: DeliveryCancelled, code: DeliveryReasonDeleted}
		case model.DeletePhaseFencing:
			paused = true
		}
	}
	if paused {
		return deliveryVerdict{pause: true}
	}
	if r.Route != DeliveryRouteQueue && r.Recipient != nil {
		raw, ok := st.Orgs[r.Org.String()].Settings["destination:"+r.Recipient.String()]
		if !ok {
			return deliveryVerdict{phase: DeliveryFailed, code: DeliveryReasonNoDestination}
		}
		var cfg struct {
			Enabled bool `json:"enabled"`
		}
		if json.Unmarshal(raw, &cfg) != nil || !cfg.Enabled {
			return deliveryVerdict{phase: DeliveryCancelled, code: DeliveryReasonDestinationDisabled}
		}
	}
	return deliveryVerdict{}
}

// deliveryHold computes, from committed state only, why a delivery may not be
// sent now. It is the read-side twin of the gate the claim applies.
func deliveryHold(st State, gate cutoverGate, gateErr error, r DeliveryRecord, now model.UnixNano) string {
	if !r.Open() {
		// A delivery the cutover revoked must never be sent by a worker that still
		// holds an older view of it.
		if r.Code == DeliveryReasonRevoked && (r.Phase == DeliveryCancelled || r.Phase == DeliveryUncertain) {
			return DeliveryReasonRevoked
		}
		return ""
	}
	switch v := deliveryGate(&st, gate, gateErr, &r); {
	case v.pause:
		return DeliveryHoldPaused
	case v.phase != "":
		return v.code
	}
	if now > 0 && now-r.Eligible >= DeliveryMaxAge {
		return DeliveryReasonExpired
	}
	return ""
}

// settleDelivery ends a delivery with a phase and a safe code.
func settleDelivery(r *DeliveryRecord, phase, code string, at model.UnixNano) {
	r.Phase, r.Code, r.SettledAt = phase, code, at
}

// exhaustedPhase is how a delivery that ran out of budget settles: a delivery that
// was never attempted expired; one that may have reached the provider stays
// uncertain; the rest failed. Never success.
func exhaustedPhase(r *DeliveryRecord) (phase, code string) {
	switch {
	case len(r.Attempts) == 0:
		return DeliveryCancelled, DeliveryReasonExpired
	case r.Uncertain:
		return DeliveryUncertain, DeliveryReasonExhausted
	}
	return DeliveryFailed, DeliveryReasonExhausted
}

func closeAttempt(a *DeliveryAttempt, at model.UnixNano, outcome, code, by string) {
	a.ClosedAt, a.Outcome, a.Code, a.ClosedBy = at, outcome, code, by
}

func applyDelivery(scope auth.Scope, st *State, cmd Command) (Effect, error) {
	var c DeliveryCommand
	if err := strictPayload(cmd.Payload, &c); err != nil {
		return Effect{}, err
	}
	arms := 0
	for _, present := range []bool{c.Enqueue != nil, c.Claim != nil, c.Complete != nil, c.Cancel != nil, c.Cutover != nil} {
		if present {
			arms++
		}
	}
	if arms != 1 {
		return Effect{}, model.Fail(model.Invalid)
	}
	var project model.ID
	var kind CommandKind
	switch {
	case c.Operation == DeliveryOpEnqueue && c.Enqueue != nil:
		project, kind = c.Enqueue.Project, KindClaimDelivery
	case c.Operation == DeliveryOpClaim && c.Claim != nil:
		project, kind = c.Claim.Project, KindClaimDelivery
	case c.Operation == DeliveryOpComplete && c.Complete != nil:
		project, kind = c.Complete.Project, KindCompleteDelivery
	case c.Operation == DeliveryOpCancel && c.Cancel != nil:
		project, kind = c.Cancel.Project, KindCompleteDelivery
	case c.Operation == DeliveryOpCutover && c.Cutover != nil:
		project, kind = c.Cutover.Project, KindClaimDelivery
	default:
		return Effect{}, model.Fail(model.Invalid)
	}
	if CommandKind(cmd.Kind) != kind {
		return Effect{}, model.Fail(model.Invalid)
	}
	org := scope.OrgID()
	// Scope and grants first: nothing about the target is looked up, parsed or
	// answered for a scope that may not act in this project.
	if err := releaseScope(scope, st, org, project); err != nil {
		return Effect{}, err
	}
	if c.Operation == DeliveryOpCutover {
		// An operator command: it carries no worker lease and a lease on it is a
		// confused request, not an authority.
		if c.Lease != nil {
			return Effect{}, model.Fail(model.Invalid)
		}
		return applyCutover(scope, st, cmd, *c.Cutover)
	}
	if c.Lease == nil || c.Lease.Group != st.Installation || c.Lease.Term == 0 {
		return Effect{}, model.Fail(model.Invalid)
	}
	lease := *c.Lease
	if cur, ok, err := loadDeliveryFence(st, org, project); err != nil {
		return Effect{}, err
	} else if ok && fenceBefore(lease, cur) {
		return Effect{}, ruleFault(model.Stale, DeliveryLeaseStale)
	}
	audit := &deliveryAudit{st: st, scope: scope, cmd: cmd}
	var effect Effect
	var err error
	switch c.Operation {
	case DeliveryOpEnqueue:
		effect, err = applyDeliveryEnqueue(st, org, *c.Enqueue, audit)
	case DeliveryOpClaim:
		effect, err = applyDeliveryClaim(st, org, lease, *c.Claim, audit)
	case DeliveryOpComplete:
		effect, err = applyDeliveryComplete(st, org, lease, *c.Complete, audit)
	default:
		effect, err = applyDeliveryCancel(st, org, lease, *c.Cancel, audit)
	}
	if err != nil {
		return Effect{}, err
	}
	if effect.Phase != "unchanged" {
		if err = raiseDeliveryFence(st, org, project, lease); err != nil {
			return Effect{}, err
		}
		// An enqueue (or a claim of a covered delivery) after the deletion
		// completed: settle and unbody what the deletion covers before the
		// settled history is pruned.
		if err = eraseLateEffect(st, org, project); err != nil {
			return Effect{}, err
		}
		if err = pruneSettledDeliveries(st, org, project); err != nil {
			return Effect{}, err
		}
	}
	return effect, nil
}

func validDeliveryIntent(in DeliveryIntent) error {
	if in.ID == (model.ID{}) || !deliveryCode(in.Kind) || in.At <= 0 || in.OriginFrom < 0 || in.OriginTo < in.OriginFrom {
		return model.Fail(model.Invalid)
	}
	switch in.Route {
	case DeliveryRouteImmediate, DeliveryRouteQueue, DeliveryRouteDigest:
	default:
		return model.Fail(model.Invalid)
	}
	if len(in.Body) > maxDeliveryBody {
		return model.Fail(model.TooLarge)
	}
	if len(in.Body) < 2 || in.Body[0] != '{' || !json.Valid(in.Body) || in.Digest != model.Hash(sha256.Sum256(in.Body)) {
		return model.Fail(model.Invalid)
	}
	switch in.Disposition {
	case DeliveryDispositionDeliver:
		// Delivered intents carry no reason. An external one needs a recipient; the
		// shared queue has none.
		if in.Code != "" || in.Route == DeliveryRouteQueue && in.Recipient != nil || in.Route != DeliveryRouteQueue && in.Recipient == nil {
			return model.Fail(model.Invalid)
		}
	case DeliveryDispositionSuppressed, DeliveryDispositionFailed:
		if !deliveryCode(in.Code) {
			return model.Fail(model.Invalid)
		}
	default:
		return model.Fail(model.Invalid)
	}
	if in.Recipient != nil && *in.Recipient == (model.ID{}) {
		return model.Fail(model.Invalid)
	}
	return nil
}

func applyDeliveryEnqueue(st *State, org model.ID, e DeliveryEnqueue, a *deliveryAudit) (Effect, error) {
	if len(e.State) > maxPolicyStateBytes {
		return Effect{}, model.Fail(model.TooLarge)
	}
	if e.Policy == (model.ID{}) || !deliverySubject(e.Subject) || e.NewVersion != e.ExpectedVersion+1 || e.At <= 0 || len(e.State) < 2 || e.State[0] != '{' || !json.Valid(e.State) ||
		e.Digest != model.Hash(sha256.Sum256(e.State)) || len(e.Intents) > maxDeliveryIntents {
		return Effect{}, model.Fail(model.Invalid)
	}
	seen := make(map[model.ID]bool, len(e.Intents))
	for _, in := range e.Intents {
		if err := validDeliveryIntent(in); err != nil {
			return Effect{}, err
		}
		if seen[in.ID] {
			return Effect{}, model.Fail(model.Invalid)
		}
		seen[in.ID] = true
	}
	key := policyKey(org, e.Project, e.Policy, e.Subject)
	rec, exists, err := loadPolicy(st, key)
	if err != nil {
		return Effect{}, err
	}
	switch {
	case !exists && e.ExpectedVersion != 0:
		return Effect{}, model.Fail(model.NotFound)
	case exists && rec.Version != e.ExpectedVersion:
		return Effect{}, ruleFault(model.Conflict, DeliveryPolicyConflict)
	case !exists:
		prefix := "policy:" + org.String() + ":" + e.Project.String() + ":"
		n := 0
		for k := range st.DeliveryBooks {
			if strings.HasPrefix(k, prefix) {
				n++
			}
		}
		if n >= maxPolicyStatesPerProject {
			return Effect{}, model.Fail(model.Quota)
		}
	}
	recs, err := projectDeliveries(st, org, e.Project)
	if err != nil {
		return Effect{}, err
	}
	open := 0
	for _, r := range recs {
		if r.Open() {
			open++
		}
	}
	revision := st.Revision + 1
	generation := st.DeleteGenerations[org.String()]
	gate, err := cutoverGateOf(st, org, e.Project)
	if err != nil {
		return Effect{}, err
	}
	var created []DeliveryRecord
	for _, in := range e.Intents {
		old, found, err := loadDelivery(st, in.ID)
		if err != nil {
			return Effect{}, err
		}
		if found {
			// The same decision twice: the committed record stands untouched. A
			// different body for a committed identity is never merged.
			if old.Digest != in.Digest || old.Org != org || old.Project != e.Project {
				return Effect{}, ruleFault(model.Conflict, DeliveryIdentityConflict)
			}
			continue
		}
		r := DeliveryRecord{ID: in.ID, Org: org, Project: e.Project, Policy: e.Policy, Subject: e.Subject, Kind: in.Kind, Route: in.Route, Recipient: in.Recipient,
			Disposition: in.Disposition, Eligible: in.At, Next: in.At, OriginFrom: in.OriginFrom, OriginTo: in.OriginTo, Generation: generation, Created: revision,
			Body: append(json.RawMessage(nil), in.Body...), Digest: in.Digest}
		switch {
		case in.Disposition == DeliveryDispositionDeliver && in.Route == DeliveryRouteQueue:
			r.Phase, r.SettledAt = DeliveryQueued, in.At
		case in.Disposition == DeliveryDispositionDeliver && gate.block != "":
			// The product is not the active owner (a shadow, a rollback, an
			// unacknowledged restore): the decision is recorded and never sent.
			r.Disposition = DeliveryDispositionSuppressed
			r.Phase, r.Code, r.SettledAt = DeliverySuppressed, gate.block, in.At
		case in.Disposition == DeliveryDispositionDeliver:
			r.Phase = DeliveryPending
			open++
		case in.Disposition == DeliveryDispositionSuppressed:
			r.Phase, r.Code, r.SettledAt = DeliverySuppressed, in.Code, in.At
		default:
			r.Phase, r.Code, r.SettledAt = DeliveryFailed, in.Code, in.At
		}
		created = append(created, r)
	}
	if open > maxOpenDeliveriesPerProject {
		return Effect{}, model.Fail(model.Quota)
	}
	affected := make([]model.ID, 0, len(created))
	for _, r := range created {
		if err = storeDelivery(st, r); err != nil {
			return Effect{}, err
		}
		affected = append(affected, r.ID)
		if r.Phase == DeliveryFailed {
			a.add(DeliveryFailed, r.ID, r.Code, r.SettledAt)
		}
	}
	raw, err := json.Marshal(PolicyRecord{Org: org, Project: e.Project, Policy: e.Policy, Subject: e.Subject, Version: e.NewVersion, Digest: e.Digest, State: append(json.RawMessage(nil), e.State...)})
	if err != nil {
		return Effect{}, model.Fail(model.Invalid)
	}
	if st.DeliveryBooks == nil {
		st.DeliveryBooks = map[string]json.RawMessage{}
	}
	st.DeliveryBooks[key] = raw
	return Effect{AffectedIDs: affected, Phase: "enqueued"}, nil
}

func applyDeliveryClaim(st *State, org model.ID, lease replica.FenceToken, c DeliveryClaim, a *deliveryAudit) (Effect, error) {
	if c.Now <= 0 || c.Expires <= c.Now || c.Expires-c.Now > DeliveryMaxClaimTTL || c.Limit == 0 || c.Limit > maxDeliveryClaimLimit {
		return Effect{}, model.Fail(model.Invalid)
	}
	gate, err := cutoverGateOf(st, org, c.Project)
	if err != nil {
		return Effect{}, err
	}
	if c.OwnerRevision != gate.revision {
		return Effect{}, ruleFault(model.Stale, DeliveryOwnerStale)
	}
	if gate.block != "" {
		// Not the active owner: nothing is leased, and nothing is settled either.
		return Effect{Phase: "empty"}, nil
	}
	recs, err := projectDeliveries(st, org, c.Project)
	if err != nil {
		return Effect{}, err
	}
	var open []DeliveryRecord
	for _, r := range recs {
		if r.Open() {
			open = append(open, r)
		}
	}
	sort.Slice(open, func(i, j int) bool {
		if open[i].Next != open[j].Next {
			return open[i].Next < open[j].Next
		}
		return open[i].ID.String() < open[j].ID.String()
	})
	generation := st.DeleteGenerations[org.String()]
	var claimed []model.ID
	for i := range open {
		r := &open[i]
		changed := false
		if r.Phase == DeliveryClaimed {
			last := &r.Attempts[len(r.Attempts)-1]
			if c.Now < last.Expires {
				continue // a live claim
			}
			// The lease lapsed without a completion: the attempt may have reached the
			// provider, so it is unknown. It is closed here, once and immutably, by the
			// system, and the SAME delivery is retried below.
			closeAttempt(last, c.Now, DeliveryOutcomeUnknown, DeliveryCodeClaimExpired, "system")
			r.Uncertain, r.Phase, r.Next = true, DeliveryPending, c.Now
			a.add(DeliveryOutcomeUnknown, r.ID, DeliveryCodeClaimExpired, c.Now)
			changed = true
		}
		switch v := deliveryGate(st, gate, nil, r); {
		case v.pause:
			// A closing deletion pauses derived sends: nothing is claimed or settled.
		case v.phase != "":
			settleDelivery(r, v.phase, v.code, c.Now)
			a.add(v.phase, r.ID, v.code, c.Now)
			changed = true
		case c.Now-r.Eligible >= DeliveryMaxAge || len(r.Attempts) >= DeliveryMaxAttempts:
			phase, code := exhaustedPhase(r)
			settleDelivery(r, phase, code, c.Now)
			a.add(phase, r.ID, code, c.Now)
			changed = true
		case r.Next <= c.Now && len(claimed) < int(c.Limit):
			r.Attempts = append(r.Attempts, DeliveryAttempt{Number: uint32(len(r.Attempts) + 1), Fence: lease, ClaimedAt: c.Now, Expires: c.Expires, Generation: generation, Owner: gate.revision})
			r.Phase = DeliveryClaimed
			claimed = append(claimed, r.ID)
			changed = true
		}
		if changed {
			if err = storeDelivery(st, *r); err != nil {
				return Effect{}, err
			}
		}
	}
	if len(claimed) == 0 {
		return Effect{Phase: "empty"}, nil
	}
	return Effect{AffectedIDs: claimed, Phase: "claimed"}, nil
}

// validOutcome validates the shape of an attempt outcome: accepted carries
// provider evidence and nothing else; retry and unknown carry a safe code and a
// schedule inside the budget horizon; terminal carries a safe code only.
func (c DeliveryComplete) validOutcome() bool {
	if c.RetryAfter < 0 || c.RetryAfter > model.UnixNano(366*24*time.Hour) {
		return false
	}
	switch c.Outcome {
	case DeliveryOutcomeAccepted:
		return deliveryProviderID(c.Provider) && c.Code == "" && c.RetryAfter == 0 && c.Next == 0
	case DeliveryOutcomeRetry, DeliveryOutcomeUnknown:
		return deliveryCode(c.Code) && c.Provider == "" && c.Next >= c.At && c.Next-c.At <= DeliveryMaxAge
	case DeliveryOutcomeTerminal:
		return deliveryCode(c.Code) && c.Provider == "" && c.RetryAfter == 0 && c.Next == 0
	}
	return false
}

// holder checks that lease is exactly the lease the open attempt was claimed
// under: an older one is a deposed leader's, any other one did not open it.
func holder(lease replica.FenceToken, at *DeliveryAttempt) error {
	switch {
	case lease == at.Fence:
		return nil
	case fenceBefore(lease, at.Fence):
		return ruleFault(model.Stale, DeliveryLeaseStale)
	}
	return ruleFault(model.Conflict, DeliveryClaimNotHeld)
}

func applyDeliveryComplete(st *State, org model.ID, lease replica.FenceToken, c DeliveryComplete, a *deliveryAudit) (Effect, error) {
	if c.Attempt == 0 || c.At <= 0 || !c.validOutcome() {
		return Effect{}, model.Fail(model.Invalid)
	}
	r, found, err := loadDelivery(st, c.Delivery)
	if err != nil {
		return Effect{}, err
	}
	if !found || r.Org != org || r.Project != c.Project {
		return Effect{}, model.Fail(model.NotFound)
	}
	if int(c.Attempt) > len(r.Attempts) {
		return Effect{}, model.Fail(model.Invalid)
	}
	at := &r.Attempts[c.Attempt-1]
	if at.Outcome != "" {
		// A closed attempt never changes. The same outcome again (a lost response, a
		// restarted worker) is a no-op; any other is a conflict.
		if at.Outcome == c.Outcome && at.Code == c.Code && at.Provider == c.Provider && at.RetryAfter == c.RetryAfter {
			return Effect{AffectedIDs: []model.ID{r.ID}, Phase: "unchanged"}, nil
		}
		return Effect{}, ruleFault(model.Conflict, DeliveryAttemptClosed)
	}
	if err = holder(lease, at); err != nil {
		return Effect{}, err
	}
	closeAttempt(at, c.At, c.Outcome, c.Code, "worker")
	at.Provider, at.RetryAfter, at.Next = c.Provider, c.RetryAfter, c.Next
	switch c.Outcome {
	case DeliveryOutcomeAccepted:
		settleDelivery(&r, DeliveryAccepted, "", c.At)
		// Accepted after an unknown attempt: the recipient may have it twice.
		r.Provider, r.PossibleDuplicate = c.Provider, r.Uncertain
		a.add(DeliveryAccepted, r.ID, DeliveryAccepted, c.At)
	case DeliveryOutcomeTerminal:
		phase := DeliveryFailed
		if r.Uncertain {
			phase = DeliveryUncertain
		}
		settleDelivery(&r, phase, c.Code, c.At)
		a.add(phase, r.ID, c.Code, c.At)
	default:
		if c.Outcome == DeliveryOutcomeUnknown {
			r.Uncertain = true
			a.add(DeliveryOutcomeUnknown, r.ID, c.Code, c.At)
		}
		if len(r.Attempts) >= DeliveryMaxAttempts || c.Next >= r.Eligible+DeliveryMaxAge {
			phase, code := exhaustedPhase(&r)
			settleDelivery(&r, phase, code, c.At)
			a.add(phase, r.ID, code, c.At)
		} else {
			r.Phase, r.Next = DeliveryPending, c.Next
		}
	}
	if err = storeDelivery(st, r); err != nil {
		return Effect{}, err
	}
	return Effect{AffectedIDs: []model.ID{r.ID}, Phase: r.Phase}, nil
}

func cancelPhase(reason string) (string, bool) {
	switch reason {
	case DeliveryReasonNoDestination:
		return DeliveryFailed, true
	case DeliveryReasonDeleted, DeliveryReasonDestinationDisabled, DeliveryReasonExpired, DeliveryReasonRevoked:
		return DeliveryCancelled, true
	}
	return "", false
}

func applyDeliveryCancel(st *State, org model.ID, lease replica.FenceToken, c DeliveryCancel, a *deliveryAudit) (Effect, error) {
	phase, ok := cancelPhase(c.Reason)
	if !ok || c.At <= 0 {
		return Effect{}, model.Fail(model.Invalid)
	}
	r, found, err := loadDelivery(st, c.Delivery)
	if err != nil {
		return Effect{}, err
	}
	if !found || r.Org != org || r.Project != c.Project {
		return Effect{}, model.Fail(model.NotFound)
	}
	switch r.Phase {
	case DeliveryPending:
		if c.Attempt != 0 {
			return Effect{}, ruleFault(model.Conflict, DeliveryClaimNotHeld)
		}
	case DeliveryClaimed:
		// A claimed delivery is cancelled by its holder only, naming its attempt:
		// the attempt closes as a definite non-send.
		last := &r.Attempts[len(r.Attempts)-1]
		if c.Attempt != last.Number {
			return Effect{}, ruleFault(model.Conflict, DeliveryClaimNotHeld)
		}
		if err = holder(lease, last); err != nil {
			return Effect{}, err
		}
		closeAttempt(last, c.At, DeliveryOutcomeTerminal, c.Reason, "worker")
	default:
		if r.Phase == phase && r.Code == c.Reason {
			return Effect{AffectedIDs: []model.ID{r.ID}, Phase: "unchanged"}, nil
		}
		return Effect{}, ruleFault(model.Conflict, DeliverySettled)
	}
	settleDelivery(&r, phase, c.Reason, c.At)
	a.add(phase, r.ID, c.Reason, c.At)
	if err = storeDelivery(st, r); err != nil {
		return Effect{}, err
	}
	return Effect{AffectedIDs: []model.ID{r.ID}, Phase: r.Phase}, nil
}

// pruneSettledDeliveries bounds the settled history of one project to
// maxSettledDeliveries, oldest first and benign entries (queued, suppressed,
// accepted) before failures and cancellations. Open deliveries are never pruned,
// and every terminal reason is also a control audit entry that outlives its record.
func pruneSettledDeliveries(st *State, org, project model.ID) error {
	recs, err := projectDeliveries(st, org, project)
	if err != nil {
		return err
	}
	var settled []DeliveryRecord
	for _, r := range recs {
		if !r.Open() {
			settled = append(settled, r)
		}
	}
	if len(settled) <= maxSettledDeliveries {
		return nil
	}
	tier := func(r DeliveryRecord) int {
		switch r.Phase {
		case DeliveryQueued, DeliverySuppressed, DeliveryAccepted:
			return 0
		}
		return 1
	}
	sort.Slice(settled, func(i, j int) bool {
		if ti, tj := tier(settled[i]), tier(settled[j]); ti != tj {
			return ti < tj
		}
		if settled[i].SettledAt != settled[j].SettledAt {
			return settled[i].SettledAt < settled[j].SettledAt
		}
		return settled[i].ID.String() < settled[j].ID.String()
	})
	for _, r := range settled[:len(settled)-maxSettledDeliveries] {
		delete(st.DeliveryBooks, deliveryKey(r.ID))
	}
	return nil
}

// ruleReadScope-based reads.

// Delivery reads one delivery's committed record through a linearizable control
// read, with its computed Hold. The scope is checked before the delivery is
// looked up; a delivery of another project is indistinguishable from an absent
// one.
func (s *Store) Delivery(ctx context.Context, scope auth.Scope, project, id model.ID, now model.UnixNano) (out DeliveryRecord, found bool, err error) {
	err = s.View(ctx, func(st State) error {
		if e := ruleReadScope(scope, st, project); e != nil {
			return e
		}
		r, ok, e := loadDelivery(&st, id)
		if e != nil || !ok || r.Org != scope.OrgID() || r.Project != project {
			return e
		}
		gate, gerr := cutoverGateOf(&st, r.Org, r.Project)
		r.Hold = deliveryHold(st, gate, gerr, r, now)
		out, found = r, true
		return nil
	})
	return
}

// Deliveries lists one project's deliveries in (eligible, ID) order, optionally
// only those in one phase (all when phase is empty). limit <= 0 means every
// match.
func (s *Store) Deliveries(ctx context.Context, scope auth.Scope, project model.ID, phase string, now model.UnixNano, limit int) (out []DeliveryRecord, err error) {
	err = s.View(ctx, func(st State) error {
		if e := ruleReadScope(scope, st, project); e != nil {
			return e
		}
		recs, e := projectDeliveries(&st, scope.OrgID(), project)
		if e != nil {
			return e
		}
		gate, gerr := cutoverGateOf(&st, scope.OrgID(), project)
		for _, r := range recs {
			if phase != "" && r.Phase != phase {
				continue
			}
			r.Hold = deliveryHold(st, gate, gerr, r, now)
			out = append(out, r)
			if limit > 0 && len(out) >= limit {
				break
			}
		}
		return nil
	})
	return
}

// PolicyRecord reads one subject's committed policy state.
func (s *Store) PolicyRecord(ctx context.Context, scope auth.Scope, project, policy model.ID, subject string) (out PolicyRecord, found bool, err error) {
	err = s.View(ctx, func(st State) error {
		if e := ruleReadScope(scope, st, project); e != nil {
			return e
		}
		var e error
		out, found, e = loadPolicy(&st, policyKey(scope.OrgID(), project, policy, subject))
		return e
	})
	return
}

// PolicyRecords lists one project's policy states in (policy, subject) order.
func (s *Store) PolicyRecords(ctx context.Context, scope auth.Scope, project model.ID) (out []PolicyRecord, err error) {
	err = s.View(ctx, func(st State) error {
		if e := ruleReadScope(scope, st, project); e != nil {
			return e
		}
		for key, raw := range st.DeliveryBooks {
			if !strings.HasPrefix(key, "policy:") {
				continue
			}
			var r PolicyRecord
			if e := json.Unmarshal(raw, &r); e != nil {
				return model.Fail(model.Corrupt)
			}
			if r.Org == scope.OrgID() && r.Project == project {
				out = append(out, r)
			}
		}
		sort.Slice(out, func(i, j int) bool {
			if out[i].Policy != out[j].Policy {
				return out[i].Policy.String() < out[j].Policy.String()
			}
			return out[i].Subject < out[j].Subject
		})
		return nil
	})
	return
}

// eraseDeliveries drops, in the caller's transition, the notification bodies a
// deletion covers (deliveryCovered: a retirement covers every delivery of its
// projects, a range every delivery whose evidence interval overlaps it, an
// unknown interval included). With settle (the operation is complete or failed)
// it also settles the ones not yet sent: an unclaimed delivery is cancelled as
// deleted at `at`; while the operation is only fencing, deliveryGate pauses it.
// A claimed delivery keeps its phase (the holder's attempt is open and closes
// through its own command). Identities, digests, attempts and codes stay. A
// retirement also
// drops the opaque policy state of its projects; a range keeps it, because it
// holds identities, configuration and counters, not evidence.
func eraseDeliveries(st *State, p model.DeletePredicate, at model.UnixNano, settle bool, principal model.ID) (dropped int, err error) {
	keys := make([]string, 0, len(st.DeliveryBooks))
	for key := range st.DeliveryBooks {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		switch {
		case strings.HasPrefix(key, "delivery:"):
			var r DeliveryRecord
			if err := json.Unmarshal(st.DeliveryBooks[key], &r); err != nil {
				return 0, model.Fail(model.Corrupt)
			}
			if !deliveryCovered(p, &r) {
				continue
			}
			changed := false
			if settle && r.Phase == DeliveryPending {
				settleDelivery(&r, DeliveryCancelled, DeliveryReasonDeleted, at)
				// The same permanent trail the claim leaves when it cancels a delivery.
				st.Audits = append(st.Audits, model.ControlAudit{ID: deriveID(r.ID, 1), Principal: principal, Action: "notify.delivery." + DeliveryCancelled, Reason: DeliveryReasonDeleted,
					Time: int64(at), Org: r.Org.String(), PolicyEpoch: st.Orgs[r.Org.String()].Epoch, Targets: []model.ID{r.ID}, RequestID: p.Operation, Outcome: model.AuditAllowed})
				changed = true
			}
			if len(r.Body) != 0 && !bytes.Equal(r.Body, []byte("null")) {
				r.Body, changed = nil, true
				dropped++
			}
			if changed {
				if err := storeDelivery(st, r); err != nil {
					return 0, err
				}
			}
		case strings.HasPrefix(key, "policy:"):
			rec, _, err := loadPolicy(st, key)
			if err != nil {
				return 0, err
			}
			if !p.RetiresProject(rec.Org, rec.Project) || len(rec.State) == 0 || bytes.Equal(rec.State, []byte("null")) {
				continue
			}
			rec.State = nil
			raw, err := json.Marshal(rec)
			if err != nil {
				return 0, model.Fail(model.Corrupt)
			}
			st.DeliveryBooks[key] = raw
			dropped++
		}
	}
	return dropped, nil
}
