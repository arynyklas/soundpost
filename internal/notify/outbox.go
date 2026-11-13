// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package notify

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math"
	"time"

	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/model"
	"soundpost/internal/replica"
)

// This file is the scoped, durable, fenced outbox: C08's Claim and Complete,
// and the commit of policy decisions. It owns no state. Everything durable is in
// control, in the closed KindClaimDelivery/KindCompleteDelivery handler
// (internal/control/delivery_outbox.go), and everything here is a transaction
// against it:
//
//   - Submit decides one policy event with the pure reducer, OUTSIDE apply, and
//     commits the new policy state together with every intent it produced in one
//     C05 transaction. The intent IDs are the stable C08 key hashes, so a replayed
//     decision (a crash between the incident commit and the worker, a lost
//     response, a second worker) creates nothing twice;
//   - Claim leases due deliveries and opens their attempt atomically, under the
//     caller's lease;
//   - Complete closes exactly the claimed attempt. C08's signature carries no
//     lease: the lease is the stored claim's, and it is validated against a fresh
//     quorum observation before the completion is committed, so a deposed worker
//     cannot complete an attempt, and control rejects a completion whose attempt
//     or fence is not the stored claim's.
//
// No provider is called here. Sends happen in the worker, through Sender, outside
// every transaction.

// FenceToken is the control group's leadership lease.
type FenceToken = replica.FenceToken

// Record is the committed view of one delivery: its stable ID, immutable attempt
// history and settled outcome. It carries IDs, enums and closed codes only.
type Record = control.DeliveryRecord

// Store is the control surface the outbox needs (*control.Store).
type Store interface {
	Transact(ctx context.Context, scope auth.Scope, cmd control.Command) (control.Result, error)
	View(ctx context.Context, fn func(control.State) error) error
	Delivery(ctx context.Context, scope auth.Scope, project, id model.ID, now model.UnixNano) (control.DeliveryRecord, bool, error)
	Deliveries(ctx context.Context, scope auth.Scope, project model.ID, phase string, now model.UnixNano, limit int) ([]control.DeliveryRecord, error)
	PolicyRecord(ctx context.Context, scope auth.Scope, project, policy model.ID, subject string) (control.PolicyRecord, bool, error)
	PolicyRecords(ctx context.Context, scope auth.Scope, project model.ID) ([]control.PolicyRecord, error)
}

// Fencer validates a lease against a fresh quorum observation (*replica.Group):
// an election term or a clock alone is not a lease.
type Fencer interface {
	ValidateFence(ctx context.Context, token FenceToken) error
}

// Clock supplies the wall clock. Nothing in the reducers or in control apply
// reads it.
type Clock interface{ Now() model.UnixNano }

// RetryPolicy is the capped, jittered backoff between attempts. The BUDGET (12
// attempts or 24 hours from first eligibility, whichever comes first) is enforced
// by control and cannot be loosened here.
type RetryPolicy struct {
	Base, Cap model.UnixNano
}

// DefaultRetry is the approved 1-second to 15-minute backoff.
func DefaultRetry() RetryPolicy {
	return RetryPolicy{Base: model.UnixNano(time.Second), Cap: model.UnixNano(15 * time.Minute)}
}

// Jitter returns a fraction in [0,1) for one attempt of one delivery. It is
// injected so no reducer or retry decision reads randomness; the default is a
// hash of the delivery ID and attempt, so it is reproducible and still spreads
// deliveries apart.
type Jitter func(id model.ID, attempt uint32) float64

func hashJitter(id model.ID, attempt uint32) float64 {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], attempt)
	sum := sha256.Sum256(append(append([]byte("soundpost.notify.jitter.v1\x00"), id[:]...), n[:]...))
	return float64(binary.BigEndian.Uint64(sum[:8])>>11) / float64(uint64(1)<<53)
}

// Option configures an Outbox.
type Option func(*Outbox)

// WithLeaseTTL sets how long a claim holds a delivery (default 2 minutes). The
// worker's send timeout must be shorter.
func WithLeaseTTL(d time.Duration) Option { return func(o *Outbox) { o.ttl = d } }

// WithRetry sets the backoff.
func WithRetry(p RetryPolicy) Option { return func(o *Outbox) { o.retry = p } }

// WithJitter injects the jitter source.
func WithJitter(j Jitter) Option { return func(o *Outbox) { o.jitter = j } }

// Outbox is the scoped durable outbox over the control store.
type Outbox struct {
	store  Store
	fencer Fencer
	clock  Clock
	ttl    time.Duration
	retry  RetryPolicy
	jitter Jitter
}

// NewOutbox builds an outbox. Every dependency is required: an outbox that could
// not validate a lease could release effects for a deposed leader.
func NewOutbox(store Store, fencer Fencer, clock Clock, opts ...Option) (*Outbox, error) {
	if store == nil || fencer == nil || clock == nil {
		return nil, model.Fail(model.Invalid)
	}
	o := &Outbox{store: store, fencer: fencer, clock: clock, ttl: 2 * time.Minute, retry: DefaultRetry(), jitter: hashJitter}
	for _, opt := range opts {
		opt(o)
	}
	if o.ttl < time.Second || model.UnixNano(o.ttl) > control.DeliveryMaxClaimTTL || o.retry.Base <= 0 || o.retry.Cap < o.retry.Base || o.jitter == nil {
		return nil, model.Fail(model.Invalid)
	}
	return o, nil
}

// LeaseTTL is how long one claim holds a delivery.
func (o *Outbox) LeaseTTL() time.Duration { return o.ttl }

// maxRevisionRetries bounds the retries of one command that only lost the race
// for the control revision, never a semantic conflict. Exhausting it answers a
// retryable unavailable with SafeDetail DetailRevisionContention.
const maxRevisionRetries = 16

// DetailRevisionContention is the SafeDetail of the retryable unavailable a
// command answers when every one of its maxRevisionRetries attempts lost the race
// for the control revision to other writers. Nothing was committed; the caller
// may retry the same command.
const DetailRevisionContention = "revision_contention"

// maxSubmitRetries bounds how often one decision is recomputed after another
// worker advanced the same policy state.
const maxSubmitRetries = 8

// MaxClaim is the largest batch one claim may lease.
const MaxClaim = 64

func (o *Outbox) project(scope auth.Scope) (model.ID, error) {
	projects := scope.ProjectIDs()
	if len(projects) != 1 || projects[0] == (model.ID{}) {
		return model.ID{}, model.Fail(model.Invalid)
	}
	return projects[0], nil
}

func validLease(l FenceToken) error {
	if l.Group == (model.ID{}) || l.Term == 0 {
		return model.Fail(model.Invalid)
	}
	return nil
}

// fenceFault maps a lease validation failure to the typed model error. A stale
// lease carries the outbox's own SafeDetail, the same one control uses.
func fenceFault(err error) error {
	var f *model.Fault
	switch {
	case err == nil:
		return nil
	case errors.As(err, &f):
		return err
	case errors.Is(err, replica.ErrStale):
		fault := model.Fail(model.Stale)
		fault.SafeDetail = control.DeliveryLeaseStale
		return fault
	case errors.Is(err, replica.ErrInvalid):
		return model.Fail(model.Invalid)
	case errors.Is(err, context.Canceled):
		return model.Fail(model.Cancelled)
	case errors.Is(err, context.DeadlineExceeded):
		return model.Fail(model.Timeout)
	}
	fault := model.Fail(model.Unavailable)
	fault.Retryable = true
	return fault
}

// commandID derives a deterministic C05 command ID: retrying the same command
// after a lost response is then a no-op, whenever and however often it happens.
func commandID(parts ...[]byte) model.ID {
	h := sha256.New()
	h.Write([]byte("soundpost.notify.command.v1\x00"))
	for _, p := range parts {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(p)))
		h.Write(n[:])
		h.Write(p)
	}
	var id model.ID
	copy(id[:], h.Sum(nil))
	return id
}

func u64(v uint64) []byte { var b [8]byte; binary.BigEndian.PutUint64(b[:], v); return b[:] }

func orgBytes(s auth.Scope) []byte { id := s.OrgID(); return id[:] }

// transact submits one delivery command. The control revision is read
// immediately before each attempt and an attempt that only lost a revision race
// is retried; any other error is returned unchanged.
func (o *Outbox) transact(ctx context.Context, scope auth.Scope, kind control.CommandKind, id model.ID, c control.DeliveryCommand) (control.Result, error) {
	raw, err := json.Marshal(c)
	if err != nil {
		return control.Result{}, model.Fail(model.Invalid)
	}
	for range maxRevisionRetries {
		var revision model.Revision
		if err = o.store.View(ctx, func(st control.State) error { revision = st.Revision; return nil }); err != nil {
			return control.Result{}, err
		}
		res, err := o.store.Transact(ctx, scope, control.Command{CommandID: id, ExpectedRevision: revision, Kind: string(kind), Payload: raw})
		if err == nil {
			return res, nil
		}
		var fault *model.Fault
		if errors.As(err, &fault) && fault.Code == model.Conflict && fault.SafeDetail == string(model.Conflict) {
			continue // the revision moved; the command did not conflict with anything
		}
		return control.Result{}, err
	}
	fault := model.Fail(model.Unavailable)
	fault.SafeDetail = DetailRevisionContention
	fault.Retryable = true
	return control.Result{}, fault
}

// Submission is the result of one policy decision.
type Submission struct {
	// Version is the policy state version after the decision.
	Version model.Revision
	// Intents are the intents the decision produced (all dispositions); each is
	// recorded in the outbox under its stable ID in the same transaction.
	Intents []Intent
	// Unchanged says the event was already applied: nothing was committed.
	Unchanged bool
}

func subjectKey(e Entity) string { return string(e.Kind) + ":" + e.ID.String() }

// origin is the evidence interval a decision's intents are derived from, for
// C12 matching: the retained evidence windows of the new state. A decision with no
// windows (a human action, an incident snapshot) has an unknown origin, which
// a deletion treats as covered.
func origin(s PolicyState) (from, to model.UnixNano) {
	for i, w := range s.Windows {
		end := w.Start + ErrorWindow - 1 // the closed interval's last nanosecond
		if i == 0 || w.Start < from {
			from = w.Start
		}
		if i == 0 || end > to {
			to = end
		}
	}
	return from, to
}

// Submit decides one policy event with the pure reducer and commits the decision.
//
// The decision happens OUTSIDE control apply: it reads the committed policy state
// (version v), runs Decide with the caller's time, and commits the new state
// together with every produced intent in ONE transaction that expects version v.
// That transaction is also the evidence checkpoint (the state carries the highest
// applied source cursors), so a worker can never checkpoint without the
// intents or enqueue without the checkpoint. An event that was already applied
// decides nothing and commits nothing (Unchanged); a lost version race
// recomputes the decision against the winner, never merging two.
func (o *Outbox) Submit(ctx context.Context, scope auth.Scope, lease FenceToken, subject Entity, ev PolicyEvent, at model.UnixNano) (Submission, error) {
	project, err := o.project(scope)
	if err != nil {
		return Submission{}, err
	}
	if err = validLease(lease); err != nil {
		return Submission{}, err
	}
	if !subject.valid() || ev.Org != scope.OrgID() || ev.Project != project {
		return Submission{}, refuse(model.Invalid, ReasonScope)
	}
	if err = o.fencer.ValidateFence(ctx, lease); err != nil {
		return Submission{}, fenceFault(err)
	}
	key := subjectKey(subject)
	for range maxSubmitRetries {
		rec, found, err := o.store.PolicyRecord(ctx, scope, project, ev.Policy, key)
		if err != nil {
			return Submission{}, err
		}
		var state PolicyState
		if found {
			if err = json.Unmarshal(rec.State, &state); err != nil {
				return Submission{}, model.Fail(model.Corrupt)
			}
		} else if state, err = NewState(scope.OrgID(), project, ev.Policy, subject); err != nil {
			return Submission{}, err
		}
		next, intents, err := Decide(state, ev, at)
		if err != nil {
			return Submission{}, err
		}
		nextRaw, err := json.Marshal(next)
		if err != nil {
			return Submission{}, model.Fail(model.Invalid)
		}
		if len(intents) == 0 {
			var before []byte
			if found {
				before = rec.State
			} else if before, err = json.Marshal(state); err != nil {
				return Submission{}, model.Fail(model.Invalid)
			}
			if bytes.Equal(before, nextRaw) {
				return Submission{Version: rec.Version, Unchanged: true}, nil
			}
		}
		from, to := origin(next)
		enqueue := control.DeliveryEnqueue{Project: project, Policy: ev.Policy, Subject: key, ExpectedVersion: rec.Version, NewVersion: rec.Version + 1, At: at,
			State: nextRaw, Digest: model.Hash(sha256.Sum256(nextRaw))}
		for _, in := range intents {
			body, err := json.Marshal(Delivery{ID: in.ID, Key: in.Key, Route: in.Route, Template: in.Template})
			if err != nil {
				return Submission{}, model.Fail(model.Invalid)
			}
			enqueue.Intents = append(enqueue.Intents, control.DeliveryIntent{ID: in.ID, Kind: string(in.Key.Kind), Disposition: string(in.Disposition), Route: string(in.Route), Code: string(in.Code),
				Recipient: in.Key.Recipient, At: in.At, OriginFrom: from, OriginTo: to, Body: body, Digest: model.Hash(sha256.Sum256(body))})
		}
		id := commandID([]byte("enqueue"), orgBytes(scope), project[:], ev.Policy[:], []byte(key), u64(uint64(rec.Version)), enqueue.Digest[:])
		_, err = o.transact(ctx, scope, control.KindClaimDelivery, id, control.DeliveryCommand{Operation: control.DeliveryOpEnqueue, Lease: &lease, Enqueue: &enqueue})
		var fault *model.Fault
		if errors.As(err, &fault) && fault.Code == model.Conflict && fault.SafeDetail == control.DeliveryPolicyConflict {
			continue // another worker advanced this state: decide again from the winner
		}
		if err != nil {
			return Submission{}, err
		}
		return Submission{Version: enqueue.NewVersion, Intents: intents}, nil
	}
	fault := model.Fail(model.Conflict)
	fault.SafeDetail = control.DeliveryPolicyConflict
	fault.Retryable = true
	return Submission{}, fault
}

// Due fires the due timers of the project's policy states: reminders, snooze and
// maintenance expiry, digests. Each is an ordinary Timer decision, so it is
// committed with its intents, replayed harmlessly and decided once. It returns how
// many decisions changed a state; at most limit states are fired per call.
func (o *Outbox) Due(ctx context.Context, scope auth.Scope, lease FenceToken, at model.UnixNano, limit int) (int, error) {
	project, err := o.project(scope)
	if err != nil {
		return 0, err
	}
	if err = validLease(lease); err != nil || at <= 0 || limit <= 0 {
		return 0, model.Fail(model.Invalid)
	}
	recs, err := o.store.PolicyRecords(ctx, scope, project)
	if err != nil {
		return 0, err
	}
	fired := 0
	for _, rec := range recs {
		var state PolicyState
		if err = json.Unmarshal(rec.State, &state); err != nil {
			return fired, model.Fail(model.Corrupt)
		}
		due, ok := state.NextDue()
		if !ok || due > at {
			continue
		}
		if fired >= limit {
			break
		}
		ev := PolicyEvent{Kind: EventTimer, Command: commandID([]byte("timer"), rec.Digest[:], u64(uint64(due))), Org: state.Org, Project: state.Project, Policy: state.Policy,
			PolicyRef: PolicyRef{Revision: state.PolicyRevision}, OwnerRevision: state.OwnerRevision, Mode: ModeLive, Timer: &Timer{}}
		sub, err := o.Submit(ctx, scope, lease, state.Subject, ev, at)
		if err != nil {
			return fired, err
		}
		if !sub.Unchanged {
			fired++
		}
	}
	return fired, nil
}

// Claim leases up to limit due deliveries of the scope's project to the lease
// holder and opens one attempt for each, atomically. The lease is validated
// against a fresh quorum observation first; control then compares it with the
// highest lease the project's outbox accepted. A delivery whose earlier claim
// lapsed without a completion is retried under the SAME ID and its earlier
// attempt is recorded unknown. Deliveries paused or cancelled by a closing
// deletion, a removed or disabled destination or an expired budget are settled
// or skipped inside the same transaction, never leased.
func (o *Outbox) Claim(ctx context.Context, scope auth.Scope, now model.UnixNano, lease FenceToken, limit int) ([]Delivery, error) {
	project, err := o.project(scope)
	if err != nil {
		return nil, err
	}
	if err = validLease(lease); err != nil || limit < 1 || limit > MaxClaim || now <= 0 {
		return nil, model.Fail(model.Invalid)
	}
	if err = o.fencer.ValidateFence(ctx, lease); err != nil {
		return nil, fenceFault(err)
	}
	expires := now + model.UnixNano(o.ttl)
	// The claim names the cutover revision this worker observed. A cutover that
	// commits between the read and the claim makes the claim stale (control refuses
	// it); the next read sees the new phase, which decides whether anything may be
	// leased at all.
	var res control.Result
	for attempt := 0; ; attempt++ {
		var owner model.Revision
		if err = o.store.View(ctx, func(st control.State) error { owner = control.CutoverRevision(st, scope.OrgID(), project); return nil }); err != nil {
			return nil, err
		}
		res, err = o.transact(ctx, scope, control.KindClaimDelivery, model.NewID(), control.DeliveryCommand{Operation: control.DeliveryOpClaim, Lease: &lease,
			Claim: &control.DeliveryClaim{Project: project, Now: now, Expires: expires, Limit: uint32(limit), OwnerRevision: owner}})
		if code, detail := faultDetail(err); err != nil && code == model.Stale && detail == control.DeliveryOwnerStale && attempt < maxOwnerRetries {
			continue
		}
		break
	}
	if err != nil {
		return nil, err
	}
	out := make([]Delivery, 0, len(res.AffectedIDs))
	for _, id := range res.AffectedIDs {
		rec, ok, err := o.store.Delivery(ctx, scope, project, id, now)
		if err != nil {
			return out, err
		}
		if !ok || rec.Phase != control.DeliveryClaimed || len(rec.Attempts) == 0 {
			continue
		}
		open := rec.Attempts[len(rec.Attempts)-1]
		if open.Fence != lease || open.ClaimedAt != now || open.Expires != expires || open.Outcome != "" {
			continue // no longer this claim's: another lease reclaimed it
		}
		var d Delivery
		if err = json.Unmarshal(rec.Body, &d); err != nil || d.ID != rec.ID {
			return out, model.Fail(model.Corrupt)
		}
		d.Attempt, d.NextAttempt, d.FenceExpiry = open.Number, rec.Next, open.Expires
		out = append(out, d)
	}
	return out, nil
}

// outcomeCode is a bounded lowercase failure code: letters, digits and _ . : -.
// Nothing a provider printed is ever stored; senders map their failures to codes.
func outcomeCode(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if r != '_' && r != '.' && r != ':' && r != '-' && (r < 'a' || r > 'z') && (r < '0' || r > '9') {
			return false
		}
	}
	return true
}

// providerID is a provider-assigned message identity: observed evidence, printable
// ASCII without spaces.
func providerID(s string) bool {
	if s == "" || len(s) > 256 {
		return false
	}
	for i := range len(s) {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

func (o Outcome) valid() bool {
	if o.RetryAfter < 0 || o.RetryAfter > model.UnixNano(366*24*time.Hour) {
		return false
	}
	switch o.Kind {
	case OutcomeAccepted:
		return providerID(o.ProviderID) && o.Code == "" && o.RetryAfter == 0
	case OutcomeRetry, OutcomeUnknown:
		return outcomeCode(o.Code) && o.ProviderID == ""
	case OutcomeTerminal:
		return outcomeCode(o.Code) && o.ProviderID == "" && o.RetryAfter == 0
	}
	return false
}

// backoff is the delay before the next attempt: half of the capped exponential
// base plus the jittered other half, so it never exceeds the cap.
func (o *Outbox) backoff(id model.ID, attempt uint32) model.UnixNano {
	base := o.retry.Base
	for i := uint32(1); i < attempt && base < o.retry.Cap; i++ {
		base *= 2
	}
	if base > o.retry.Cap {
		base = o.retry.Cap
	}
	j := o.jitter(id, attempt)
	if math.IsNaN(j) || j < 0 {
		j = 0
	}
	if j >= 1 {
		j = math.Nextafter(1, 0)
	}
	half := base / 2
	return half + model.UnixNano(float64(base-half)*j)
}

// schedule is when a retried or unknown delivery becomes eligible again: the
// backoff, or the provider's Retry-After when that is longer, never later than
// the budget horizon (control then ends the delivery visibly instead of retrying
// past it).
func (o *Outbox) schedule(rec Record, attempt uint32, outcome Outcome, now model.UnixNano) model.UnixNano {
	delay := o.backoff(rec.ID, attempt)
	if outcome.RetryAfter > delay {
		delay = outcome.RetryAfter
	}
	next := now + delay
	if horizon := rec.Eligible + control.DeliveryMaxAge; next > horizon {
		next = horizon
	}
	if next < now {
		next = now
	}
	return next
}

// Complete closes one claimed attempt with its outcome, immutably.
//
// C08's signature carries no lease: it is the stored claim's. For the OPEN
// attempt that lease is validated against a fresh quorum observation, so a worker
// that lost leadership cannot complete (a stale-fence rejection), and control
// compares it with the stored claim and with the highest lease the project's
// outbox accepted, so a worker can never complete an attempt another lease opened
// or a newer attempt than its own. A closed attempt is never changed: repeating
// its exact outcome is a no-op, anything else is a conflict. Accepted needs
// provider evidence; definite retry and unknown acceptance are distinct and keep
// the delivery ID; the retry schedule honors the provider's Retry-After inside the
// budget.
func (o *Outbox) Complete(ctx context.Context, scope auth.Scope, deliveryID model.ID, attempt uint32, outcome Outcome) error {
	project, err := o.project(scope)
	if err != nil {
		return err
	}
	if attempt == 0 || !outcome.valid() {
		return model.Fail(model.Invalid)
	}
	now := o.clock.Now()
	rec, ok, err := o.store.Delivery(ctx, scope, project, deliveryID, now)
	if err != nil {
		return err
	}
	if !ok {
		return model.Fail(model.NotFound)
	}
	if int(attempt) > len(rec.Attempts) {
		return model.Fail(model.Invalid)
	}
	claim := rec.Attempts[attempt-1]
	if claim.Outcome == "" {
		if err = o.fencer.ValidateFence(ctx, claim.Fence); err != nil {
			return fenceFault(err)
		}
	}
	c := control.DeliveryComplete{Project: project, Delivery: deliveryID, Attempt: attempt, At: now, Outcome: string(outcome.Kind), Provider: outcome.ProviderID, Code: outcome.Code, RetryAfter: outcome.RetryAfter}
	if outcome.Kind == OutcomeRetry || outcome.Kind == OutcomeUnknown {
		c.Next = o.schedule(rec, attempt, outcome, now)
	}
	id := commandID([]byte("complete"), orgBytes(scope), deliveryID[:], u64(uint64(attempt)), []byte(outcome.Kind), []byte(outcome.ProviderID), []byte(outcome.Code), u64(uint64(outcome.RetryAfter)))
	_, err = o.transact(ctx, scope, control.KindCompleteDelivery, id, control.DeliveryCommand{Operation: control.DeliveryOpComplete, Lease: &claim.Fence, Complete: &c})
	return err
}

// Cancel settles a delivery that must not be sent, with a safe reason from the
// closed set (deleted, destination_disabled, no_destination, expired, revoked).
// A pending delivery needs attempt 0; the holder of a claim names its attempt,
// which then closes as a definite non-send.
func (o *Outbox) Cancel(ctx context.Context, scope auth.Scope, lease FenceToken, deliveryID model.ID, attempt uint32, reason string) error {
	project, err := o.project(scope)
	if err != nil {
		return err
	}
	if err = validLease(lease); err != nil {
		return err
	}
	if err = o.fencer.ValidateFence(ctx, lease); err != nil {
		return fenceFault(err)
	}
	id := commandID([]byte("cancel"), orgBytes(scope), deliveryID[:], u64(uint64(attempt)), []byte(reason))
	_, err = o.transact(ctx, scope, control.KindCompleteDelivery, id, control.DeliveryCommand{Operation: control.DeliveryOpCancel, Lease: &lease,
		Cancel: &control.DeliveryCancel{Project: project, Delivery: deliveryID, Attempt: attempt, At: o.clock.Now(), Reason: reason}})
	return err
}

// Hold says why a delivery may not be sent right now, from the committed deletion
// and destination state: control.DeliveryHoldPaused while a closing C12 deletion
// covers its origin, a safe settle reason (deleted, no_destination,
// destination_disabled, expired) when it must not be sent at all, "" when nothing
// holds it. A missing delivery is not held.
func (o *Outbox) Hold(ctx context.Context, scope auth.Scope, deliveryID model.ID, now model.UnixNano) (string, error) {
	rec, ok, err := o.Record(ctx, scope, deliveryID, now)
	if err != nil || !ok {
		return "", err
	}
	return rec.Hold, nil
}

// Record reads one delivery.
func (o *Outbox) Record(ctx context.Context, scope auth.Scope, deliveryID model.ID, now model.UnixNano) (Record, bool, error) {
	project, err := o.project(scope)
	if err != nil {
		return Record{}, false, err
	}
	return o.store.Delivery(ctx, scope, project, deliveryID, now)
}

// Records lists the project's deliveries in (eligible time, ID) order, optionally
// one phase only.
func (o *Outbox) Records(ctx context.Context, scope auth.Scope, phase string, now model.UnixNano, limit int) ([]Record, error) {
	project, err := o.project(scope)
	if err != nil {
		return nil, err
	}
	return o.store.Deliveries(ctx, scope, project, phase, now, limit)
}
