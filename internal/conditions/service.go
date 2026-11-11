// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package conditions

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"sort"

	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/model"
	"soundpost/internal/replica"
)

// Control is the consumer-owned view of the C05 control authority; *control.Store
// satisfies it. The condition reads check the scope before they look anything
// up. RuleBook and RuleOutputs are the committed C07 facts this package joins:
// there is no second rule store and no second outbox.
type Control interface {
	View(ctx context.Context, fn func(control.State) error) error
	Transact(ctx context.Context, scope auth.Scope, cmd control.Command) (control.Result, error)
	Condition(ctx context.Context, scope auth.Scope, project, condition model.ID) (control.ConditionRecord, bool, error)
	Conditions(ctx context.Context, scope auth.Scope, project model.ID) ([]control.ConditionRecord, error)
	RuleBook(ctx context.Context, scope auth.Scope, project, rule model.ID) (control.RuleBook, bool, error)
	RuleOutputs(ctx context.Context, scope auth.Scope, project, rule model.ID, phase string, limit int) ([]control.RuleOutput, error)
}

// Fencer is the lease authority (the control group's *replica.Group). Fence
// returns the current leader's token; ValidateFence requires a fresh quorum
// observation that the token is still the leader's.
type Fencer interface {
	Fence(ctx context.Context) (replica.FenceToken, error)
	ValidateFence(ctx context.Context, token replica.FenceToken) error
}

// Outbox settles a consumed condition output under the lease (the control-backed
// rules outbox, *rules.OutboxStore). A condition output has no data admission, so
// settling is a state change of the internal outbox record, not a delivery.
type Outbox interface {
	Settle(ctx context.Context, scope auth.Scope, lease replica.FenceToken, item control.RuleOutput, update control.RuleOutputApply) (control.Result, error)
}

// Clock supplies the arrival time of accepted evidence. The pure reducers never
// read it.
type Clock interface{ Now() model.UnixNano }

// Service binds the pure reducers to the control group. Every dependency is
// injected; there are no package globals.
type Service struct {
	control Control
	fencer  Fencer
	outbox  Outbox
	clock   Clock
}

const (
	// maxAttempts bounds how often one transition is re-reduced after losing a
	// version race to another writer of the same condition. Each loss means another
	// event committed, and a re-reduction usually finds the event old and stops.
	maxAttempts = 32
	// maxRevisionRetries bounds retries of one command that only lost a race for
	// the control revision (never a semantic conflict).
	maxRevisionRetries = 8
	// maxConsume bounds the outputs one Consume call reads.
	maxConsume = 1024
)

// New builds a service. Every dependency is required: a service that cannot
// fence could write conditions for a deposed leader.
func New(ctl Control, fencer Fencer, outbox Outbox, clock Clock) (*Service, error) {
	if ctl == nil || fencer == nil || outbox == nil || clock == nil {
		return nil, model.Fail(model.Invalid)
	}
	return &Service{control: ctl, fencer: fencer, outbox: outbox, clock: clock}, nil
}

// wire is the committed form of a state: the state plus the org and project
// header control checks without importing this package.
type wire struct {
	State
	Org     model.ID `json:"org_id"`
	Project model.ID `json:"project_id"`
}

// decode reads one committed record. A record a deletion erased decodes to the
// erased marker (its identity and version only), provided the tombstone is that
// record's own; anything else that does not match the record is damage.
func decode(rec control.ConditionRecord) (State, error) {
	var w wire
	if rec.Erased() {
		if json.Unmarshal(rec.State, &w) != nil || w.Condition != rec.ID || w.Version != rec.Version || w.Org != rec.Org || w.Project != rec.Project {
			return State{}, model.Fail(model.Corrupt)
		}
		return State{Condition: rec.ID, Version: rec.Version, Erased: true}, nil
	}
	if json.Unmarshal(rec.State, &w) != nil || w.Condition != rec.ID || w.Version != rec.Version || w.Org != rec.Org || w.Project != rec.Project || len(w.Recent) == 0 {
		return State{}, model.Fail(model.Corrupt)
	}
	return w.State, nil
}

// worker returns the project a worker scope names: an organization administrator
// of exactly one project.
func worker(scope auth.Scope) (model.ID, error) {
	if scope.Permission() != auth.OrgAdmin {
		return model.ID{}, model.Fail(model.Forbidden)
	}
	return reader(scope)
}

func reader(scope auth.Scope) (model.ID, error) {
	projects := scope.ProjectIDs()
	if len(projects) != 1 {
		return model.ID{}, model.Fail(model.Invalid)
	}
	return projects[0], nil
}

// fenceFault maps a lease validation failure to the typed model error.
func fenceFault(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, replica.ErrStale):
		return fault(model.Stale, control.ConditionLeaseStale)
	case errors.Is(err, replica.ErrInvalid):
		return model.Fail(model.Invalid)
	case errors.Is(err, context.Canceled):
		return model.Fail(model.Cancelled)
	case errors.Is(err, context.DeadlineExceeded):
		return model.Fail(model.Timeout)
	}
	return model.Fail(model.Unavailable)
}

// Get returns one condition. The scope is checked before the condition is
// looked up; a missing condition and one outside the scope are indistinguishable.
// A condition whose state a deletion erased is found and reads as the erased
// marker (State.Erased, identity and version only), not as an error.
func (s *Service) Get(ctx context.Context, scope auth.Scope, condition model.ID) (State, bool, error) {
	project, err := reader(scope)
	if err != nil {
		return State{}, false, err
	}
	rec, found, err := s.control.Condition(ctx, scope, project, condition)
	if err != nil || !found {
		return State{}, false, err
	}
	st, err := decode(rec)
	return st, err == nil, err
}

// List returns the project's conditions in ID order, erased ones as markers.
func (s *Service) List(ctx context.Context, scope auth.Scope) ([]State, error) {
	project, err := reader(scope)
	if err != nil {
		return nil, err
	}
	recs, err := s.control.Conditions(ctx, scope, project)
	if err != nil {
		return nil, err
	}
	out := make([]State, 0, len(recs))
	for _, rec := range recs {
		st, err := decode(rec)
		if err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	return out, nil
}

// Apply folds one condition event into its condition under the C05
// ApplyCondition command and the current leader's lease, and returns the state
// as committed. An old or duplicate event commits nothing and returns the
// current state; a conflicting replay is rejected. Concurrent events for one
// condition are serialized by the control version: a writer that lost the race
// is reduced again against the new state, never merged.
//
// The project is the scope's (exactly one), the organization is the scope's, and
// the event is treated as live: it may notify.
func (s *Service) Apply(ctx context.Context, scope auth.Scope, event model.ConditionEvent) (State, error) {
	project, err := worker(scope)
	if err != nil {
		return State{}, err
	}
	lease, err := s.fencer.Fence(ctx)
	if err != nil {
		return State{}, fenceFault(err)
	}
	st, _, err := s.transition(ctx, scope, project, lease, event.Condition, input{event: &event, notify: true})
	return st, err
}

// input is one transition request: an event, an observation, or both.
type input struct {
	event       *model.ConditionEvent
	obs         *Observation
	notify      bool
	rule        *model.ID
	ruleVersion model.Revision
}

func lastRef(s State) (EventRef, bool) {
	if len(s.Recent) == 0 {
		return EventRef{}, false
	}
	return s.Recent[len(s.Recent)-1], true
}

// transition reduces the input against the committed state and commits the
// result when it changed anything. changed reports whether a command committed.
func (s *Service) transition(ctx context.Context, scope auth.Scope, project model.ID, lease replica.FenceToken, condition model.ID, in input) (State, bool, error) {
	if condition == (model.ID{}) {
		return State{}, false, fault(model.Invalid, DetailInvalidEvent)
	}
	for range maxAttempts {
		if err := ctx.Err(); err != nil {
			return State{}, false, fenceFault(err)
		}
		rec, found, err := s.control.Condition(ctx, scope, project, condition)
		if err != nil {
			return State{}, false, err
		}
		var cur State
		expected := model.Revision(0)
		if found {
			if cur, err = decode(rec); err != nil {
				return State{}, false, err
			}
			expected = rec.Version
		}
		// A condition a deletion erased has no history left: the next event starts
		// a new one on top of the preserved version (the control record is
		// compare-and-set on it), exactly as an erased job does.
		erased := cur.Erased
		if erased {
			cur = State{}
		}
		var next State
		switch {
		case in.event != nil && in.obs != nil:
			next, err = Join(cur, *in.event, *in.obs)
		case in.event != nil:
			next, err = Reduce(cur, *in.event)
		case !found || erased:
			return State{}, false, nil // nothing to observe
		default:
			next, err = Observe(cur, *in.obs)
		}
		if err != nil {
			return cur, false, err
		}
		if next.Version == cur.Version {
			return cur, false, nil // old, duplicate or already known: no effect
		}
		if erased {
			next.Version = expected + 1
		}
		before, hadBefore := lastRef(cur)
		after, _ := lastRef(next)
		if in.event != nil && (!hadBefore || before != after) {
			next.Notify = in.notify
			if in.rule != nil {
				rule := *in.rule
				next.Rule, next.RuleVersion = &rule, in.ruleVersion
			}
		}
		next.Arrived = s.clock.Now()
		change := ""
		if next.Phase != cur.Phase {
			change = string(next.Phase)
		}
		// Re-fence immediately before the effect: leadership may have moved while
		// the reduction ran.
		if err = s.fencer.ValidateFence(ctx, lease); err != nil {
			return cur, false, fenceFault(err)
		}
		committed, err := s.commit(ctx, scope, project, lease, expected, next, change)
		var f *model.Fault
		if errors.As(err, &f) && (f.Code == model.Conflict && f.SafeDetail == control.ConditionVersionConflict || f.SafeDetail == DetailVersionRace) {
			continue // another writer committed first: reduce again against its state
		}
		if err != nil {
			return cur, false, err
		}
		return committed, true, nil
	}
	f := model.Fail(model.Unavailable)
	f.Retryable = true
	return State{}, false, f
}

// commit submits one transition and returns the state as stored.
func (s *Service) commit(ctx context.Context, scope auth.Scope, project model.ID, lease replica.FenceToken, expected model.Revision, next State, change string) (State, error) {
	raw, err := json.Marshal(wire{State: next, Org: scope.OrgID(), Project: project})
	if err != nil {
		return State{}, model.Fail(model.Invalid)
	}
	digest := model.Hash(sha256.Sum256(raw))
	payload, err := json.Marshal(control.ConditionCommand{Project: project, Condition: next.Condition, Lease: &lease, ExpectedVersion: expected, NewVersion: next.Version,
		At: next.Arrived, Change: change, State: raw, Digest: digest})
	if err != nil {
		return State{}, model.Fail(model.Invalid)
	}
	org := scope.OrgID()
	id := derive("apply", org[:], project[:], next.Condition[:], u64(uint64(expected)), digest[:])
	for range maxRevisionRetries {
		var revision model.Revision
		if err = s.control.View(ctx, func(st control.State) error { revision = st.Revision; return nil }); err != nil {
			return State{}, err
		}
		_, err = s.control.Transact(ctx, scope, control.Command{CommandID: id, ExpectedRevision: revision, Kind: string(control.KindApplyCondition), Payload: payload})
		var f *model.Fault
		if errors.As(err, &f) && f.Code == model.Conflict && f.SafeDetail == string(model.Conflict) {
			continue // the revision moved; the command conflicted with nothing
		}
		if err != nil {
			return State{}, err
		}
		return decode(control.ConditionRecord{Org: org, Project: project, ID: next.Condition, Version: next.Version, State: raw})
	}
	f := model.Fail(model.Unavailable)
	f.Retryable, f.SafeDetail = true, DetailVersionRace // transition re-reduces; the caller sees Unavailable only if every attempt lost
	return State{}, f
}

// Report says what one Consume did, by rule output ID (Observed by condition ID).
type Report struct {
	// Applied outputs changed a condition's lifecycle state.
	Applied []model.ID
	// NoEffect outputs were old or duplicate events: the state already had them
	// (a retry after a crash, or evidence a newer event superseded).
	NoEffect []model.ID
	// Suppressed outputs were retired without being applied: their origin was
	// deleted or retired, they were malformed, they conflicted with an accepted
	// event, or they claimed a recovery from an unhealthy evaluation.
	Suppressed []model.ID
	// Retried outputs stay pending: the project's condition quota is exhausted.
	Retried []model.ID
	// Observed are the conditions whose freshness changed because of their rule's
	// newest evaluation.
	Observed []model.ID
}

// The closed suppression reasons.
const (
	reasonObsolete = "obsolete_origin"
	reasonMalform  = "malformed_intent"
	reasonConflict = "conflicting_event"
	reasonBlocked  = "recovery_blocked"
	reasonInvalid  = "invalid_event"
)

// intentDTO is the committed payload of a rules condition output (the closed
// shape of rules.ConditionIntent), decoded without importing the rules package.
type intentDTO struct {
	ID     model.ID             `json:"id"`
	Event  model.ConditionEvent `json:"event"`
	Notify bool                 `json:"notify"`
	Mode   string               `json:"mode"`
}

// Consume joins the project's pending C07 condition outputs into condition
// lifecycle state under lease, in (scheduled time, ID) order, then applies the
// newest evaluation health of each rule that still has an unrecovered condition.
//
// It is the consumer of the rules module's internal outbox, not a second one: an
// output is applied to the condition (idempotently, by its source order) and then
// finalized in the same outbox. A crash between the two leaves the output
// pending; the retry finds the event already applied, commits nothing, and
// finalizes. The lease is validated against a fresh quorum observation before
// anything is read, again before each commit, and every control command carries
// it, so a deposed leader neither applies nor settles anything.
func (s *Service) Consume(ctx context.Context, scope auth.Scope, lease replica.FenceToken, limit int) (Report, error) {
	var report Report
	project, err := worker(scope)
	if err != nil {
		return report, err
	}
	if limit <= 0 || limit > maxConsume || lease.Group == (model.ID{}) || lease.Term == 0 {
		return report, model.Fail(model.Invalid)
	}
	if err = s.fencer.ValidateFence(ctx, lease); err != nil {
		return report, fenceFault(err)
	}
	outs, err := s.control.RuleOutputs(ctx, scope, project, model.ID{}, control.RulePhasePending, 0)
	if err != nil {
		return report, err
	}
	n := 0
	for _, item := range outs {
		if item.Kind != control.RuleOutputCondition {
			continue
		}
		if n++; n > limit {
			break
		}
		if err = ctx.Err(); err != nil {
			return report, fenceFault(err)
		}
		if err = s.consumeOne(ctx, scope, project, lease, item, &report); err != nil {
			return report, err
		}
	}
	return report, s.observeRules(ctx, scope, project, lease, &report)
}

func (s *Service) settle(ctx context.Context, scope auth.Scope, lease replica.FenceToken, item control.RuleOutput, update control.RuleOutputApply) error {
	_, err := s.outbox.Settle(ctx, scope, lease, item, update)
	return err
}

func (s *Service) suppress(ctx context.Context, scope auth.Scope, lease replica.FenceToken, item control.RuleOutput, reason string, report *Report) error {
	if err := s.settle(ctx, scope, lease, item, control.RuleOutputApply{To: control.RulePhaseSuppress, Reason: reason}); err != nil {
		return err
	}
	report.Suppressed = append(report.Suppressed, item.ID)
	return nil
}

func (s *Service) consumeOne(ctx context.Context, scope auth.Scope, project model.ID, lease replica.FenceToken, item control.RuleOutput, report *Report) error {
	// A deletion or retirement that now covers the origin governs, not the outbox.
	if item.Obsolete {
		return s.suppress(ctx, scope, lease, item, reasonObsolete, report)
	}
	var intent intentDTO
	if model.StrictJSON(item.Payload, &intent) != nil || intent.ID != item.ID || intent.Event.Condition == (model.ID{}) {
		return s.suppress(ctx, scope, lease, item, reasonMalform, report)
	}
	obs, err := s.evaluationHealth(ctx, scope, project, item.Rule, item.Version, item.At)
	if err != nil {
		return err
	}
	rule := item.Rule
	_, changed, err := s.transition(ctx, scope, project, lease, intent.Event.Condition,
		input{event: &intent.Event, obs: obs, notify: item.Notify && intent.Notify, rule: &rule, ruleVersion: item.Version})
	switch {
	case err == nil:
	case faultDetail(err) == DetailEventConflict:
		return s.suppress(ctx, scope, lease, item, reasonConflict, report)
	case faultDetail(err) == DetailRecoveryBlocked:
		return s.suppress(ctx, scope, lease, item, reasonBlocked, report)
	case faultDetail(err) == DetailInvalidEvent:
		return s.suppress(ctx, scope, lease, item, reasonInvalid, report)
	case faultCode(err) == model.Quota:
		report.Retried = append(report.Retried, item.ID)
		return nil
	default:
		return err
	}
	if err = s.settle(ctx, scope, lease, item, control.RuleOutputApply{To: control.RulePhaseFinalized}); err != nil {
		return err
	}
	if changed {
		report.Applied = append(report.Applied, item.ID)
	} else {
		report.NoEffect = append(report.NoEffect, item.ID)
	}
	return nil
}

// evaluationHealth reads the committed health of the evaluation (rule, version,
// at) from the rule's control facts. It is nil when the evaluation record is no
// longer retained: the rules reducer itself never recovers from an unhealthy
// evaluation, and the absence of the record is not evidence either way.
func (s *Service) evaluationHealth(ctx context.Context, scope auth.Scope, project, rule model.ID, version model.Revision, at model.UnixNano) (*Observation, error) {
	book, found, err := s.control.RuleBook(ctx, scope, project, rule)
	if err != nil || !found {
		return nil, err
	}
	v, ok := book.Version(version)
	if !ok {
		return nil, nil
	}
	return observationOf(v, at), nil
}

// observationOf finds the evaluation at the scheduled time in a rule version's
// retained records.
func observationOf(v control.RuleVersionRecord, at model.UnixNano) *Observation {
	var rec *control.RuleEvaluationRecord
	if v.Last != nil && v.Last.At == at {
		rec = v.Last
	}
	for i := range v.Recent {
		if v.Recent[i].At == at {
			rec = &v.Recent[i]
		}
	}
	if rec == nil {
		return nil
	}
	return observationFrom(*rec)
}

func observationFrom(rec control.RuleEvaluationRecord) *Observation {
	obs := &Observation{At: rec.At, Health: Health(rec.Health)}
	switch obs.Health {
	case HealthOK:
		return obs
	case HealthUnknown, HealthError:
	default:
		return nil
	}
	// The closed reason code is in the retained evaluation payload; anything else
	// (a payload released with the record, an unknown code) is unspecified.
	var payload struct {
		State struct {
			Reason string `json:"reason"`
		} `json:"state"`
	}
	obs.Reason = ReasonUnspecified
	if len(rec.Payload) > 0 && json.Unmarshal(rec.Payload, &payload) == nil {
		if _, ok := reasons[payload.State.Reason]; ok {
			obs.Reason = payload.State.Reason
		}
	}
	return obs
}

// observeRules applies the newest committed evaluation health of each rule that
// still has an unrecovered condition to those conditions. An unknown or error
// evaluation emits no condition event, so this is where missing data becomes
// explicit condition history; it never moves a phase.
func (s *Service) observeRules(ctx context.Context, scope auth.Scope, project model.ID, lease replica.FenceToken, report *Report) error {
	recs, err := s.control.Conditions(ctx, scope, project)
	if err != nil {
		return err
	}
	byRule := map[model.ID][]model.ID{}
	for _, rec := range recs {
		st, err := decode(rec)
		if err != nil {
			return err
		}
		if st.Rule != nil && st.Phase != PhaseRecovered {
			byRule[*st.Rule] = append(byRule[*st.Rule], st.Condition)
		}
	}
	rulesSeen := make([]model.ID, 0, len(byRule))
	for rule := range byRule {
		rulesSeen = append(rulesSeen, rule)
	}
	sort.Slice(rulesSeen, func(i, j int) bool { return rulesSeen[i].String() < rulesSeen[j].String() })
	for _, rule := range rulesSeen {
		book, found, err := s.control.RuleBook(ctx, scope, project, rule)
		if err != nil {
			return err
		}
		if !found {
			continue
		}
		head, ok := book.Version(book.Head)
		if !ok || head.Last == nil {
			continue
		}
		rec := *head.Last
		for i := range head.Recent {
			if head.Recent[i].At == rec.At {
				rec = head.Recent[i] // the retained record carries the reason payload
			}
		}
		obs := observationFrom(rec)
		if obs == nil {
			continue
		}
		for _, id := range byRule[rule] {
			_, changed, err := s.transition(ctx, scope, project, lease, id, input{obs: obs})
			if err != nil {
				return err
			}
			if changed {
				report.Observed = append(report.Observed, id)
			}
		}
	}
	return nil
}
