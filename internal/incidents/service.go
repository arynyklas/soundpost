// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package incidents

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"

	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/model"
)

// Control is the consumer-owned view of the C05 control authority; *control.Store
// satisfies it. Incident reads check the scope before they look the incident up.
type Control interface {
	View(ctx context.Context, fn func(control.State) error) error
	Transact(ctx context.Context, scope auth.Scope, cmd control.Command) (control.Result, error)
	Incident(ctx context.Context, scope auth.Scope, project, incident model.ID) (control.IncidentRecord, bool, error)
}

// Clock supplies the action time when a caller passes none. Apply itself never
// reads it.
type Clock interface{ Now() model.UnixNano }

// Option configures a Service.
type Option func(*Service)

// WithMaxWindow overrides the 7-day default maximum snooze/maintenance window.
func WithMaxWindow(d model.UnixNano) Option { return func(s *Service) { s.maxWindow = d } }

// Service binds the pure reducer to the control group. Every dependency is
// injected; there are no package globals. C11 HTTP/UI actions call this service.
type Service struct {
	control   Control
	clock     Clock
	maxWindow model.UnixNano
}

// maxRevisionRetries bounds retries of one command that only lost a race for
// the control revision (never a semantic conflict).
const maxRevisionRetries = 8

// New builds a service.
func New(ctl Control, clock Clock, options ...Option) (*Service, error) {
	if ctl == nil || clock == nil {
		return nil, model.Fail(model.Invalid)
	}
	s := &Service{control: ctl, clock: clock}
	for _, o := range options {
		o(s)
	}
	if s.maxWindow < 0 || s.maxWindow > HardMaxWindow {
		return nil, model.Fail(model.Invalid)
	}
	return s, nil
}

// decode reads one committed record. A record a deletion erased decodes to the
// erased marker (its closed header only), provided the tombstone is that
// record's own; anything else that does not match the record is damage.
func decode(rec control.IncidentRecord) (State, error) {
	if rec.Erased() {
		var h struct {
			ID      model.ID       `json:"incident_id"`
			Org     model.ID       `json:"org_id"`
			Project model.ID       `json:"project_id"`
			Version model.Revision `json:"version"`
		}
		if json.Unmarshal(rec.State, &h) != nil || h.ID != rec.ID || h.Org != rec.Org || h.Project != rec.Project || h.Version != rec.Version {
			return State{}, model.Fail(model.Corrupt)
		}
		return State{ID: h.ID, Org: h.Org, Project: h.Project, Version: h.Version, Erased: true}, nil
	}
	var s State
	if json.Unmarshal(rec.State, &s) != nil || s.Version != rec.Version || s.ID != rec.ID || len(s.Timeline) != int(rec.Version) {
		return State{}, model.Fail(model.Corrupt)
	}
	return s, nil
}

// erasedFault is what an action on an erased incident answers: the state is
// gone, so there is nothing to act on (not found), and it is not storage damage.
func erasedFault() error { return fault(model.NotFound, DetailErased) }

// Get returns one incident. The scope is checked before the incident is looked
// up; a missing incident and one outside the scope are indistinguishable. An
// incident whose state a deletion erased reads as the erased marker (State.Erased
// with its closed header), not as an error: it is not storage damage.
func (s *Service) Get(ctx context.Context, scope auth.Scope, project, incident model.ID) (State, error) {
	rec, found, err := s.control.Incident(ctx, scope, project, incident)
	if err != nil {
		return State{}, err
	}
	if !found {
		return State{}, model.Fail(model.NotFound)
	}
	return decode(rec)
}

// Act applies one action under the C05 IncidentAction command. The actor is the
// scope's validated principal and the organization is the scope's; neither is
// taken from the action. A lost version race returns a *VersionConflict with the
// current version and is never retried as another human action. Retrying a
// committed command returns the state as it stood at that command.
func (s *Service) Act(ctx context.Context, scope auth.Scope, action Action, at model.UnixNano) (State, error) {
	if at == 0 {
		at = s.clock.Now()
	}
	// Grants are checked before the target is looked up.
	if scope.Permission() != auth.OrgAdmin {
		return State{}, model.Fail(model.Forbidden)
	}
	action.Actor, action.Target.Org, action.MaxWindow = scope.PrincipalID(), scope.OrgID(), s.maxWindow
	switch {
	case humanOnly(action.Type):
		action.Origin = OriginHuman
	case action.Type == TypeImpact:
		action.Origin = OriginSystem
	case action.Origin == "":
		action.Origin = OriginHuman
	}
	if err := validate(action, at); err != nil {
		return State{}, err
	}
	t := action.Target
	rec, found, err := s.control.Incident(ctx, scope, t.Project, t.Incident)
	if err != nil {
		return State{}, err
	}
	var before State
	if found {
		if before, err = decode(rec); err != nil {
			return State{}, err
		}
		if before.Erased {
			return State{}, erasedFault()
		}
	}
	next, effects, err := Apply(before, action, at)
	if err != nil {
		return State{}, err
	}
	if _, ok := before.Applied(action.CommandID); ok {
		return next, nil // Apply returned the original result
	}
	if next.Version == before.Version {
		return next, nil // an observation that changes nothing
	}
	if err = s.commit(ctx, scope, action, at, before.Version, next, effects); err != nil {
		return State{}, err
	}
	rec, found, err = s.control.Incident(ctx, scope, t.Project, t.Incident)
	if err != nil || !found {
		return State{}, model.Fail(model.Corrupt)
	}
	committed, err := decode(rec)
	if err != nil {
		return State{}, err
	}
	if committed.Erased {
		return State{}, erasedFault() // a deletion that covers the evidence erased it as it committed
	}
	version, ok := committed.Applied(action.CommandID)
	if !ok {
		return State{}, model.Fail(model.Corrupt)
	}
	return committed.At(version)
}

func intentID(command model.ID, index int) model.ID {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(index))
	sum := sha256.Sum256(append(append([]byte("incident-intent\x00"), command[:]...), n[:]...))
	var id model.ID
	copy(id[:], sum[:])
	return id
}

func (s *Service) commit(ctx context.Context, scope auth.Scope, a Action, at model.UnixNano, expected model.Revision, next State, effects []Effect) error {
	raw, err := json.Marshal(next)
	if err != nil {
		return model.Fail(model.Invalid)
	}
	var intents []control.IncidentIntent
	for i, e := range effects {
		if e.Kind == EffectAudit {
			continue // control writes the audit from the action itself
		}
		intents = append(intents, control.IncidentIntent{ID: intentID(a.CommandID, i), Kind: string(e.Kind), Version: e.Version, ImpactRevision: e.ImpactRevision, Eligible: e.Eligible, Code: e.Code, Until: e.Until, Subject: e.Subject})
	}
	payload, err := json.Marshal(control.IncidentCommand{Project: a.Target.Project, Incident: a.Target.Incident, Action: string(a.Type), Origin: string(a.Origin), Actor: a.Actor, At: at,
		ExpectedVersion: expected, NewVersion: next.Version, State: raw, Digest: model.Hash(sha256.Sum256(raw)), Intents: intents})
	if err != nil {
		return model.Fail(model.Invalid)
	}
	for range maxRevisionRetries {
		var revision model.Revision
		if err = s.control.View(ctx, func(st control.State) error { revision = st.Revision; return nil }); err != nil {
			return err
		}
		_, err = s.control.Transact(ctx, scope, control.Command{CommandID: a.CommandID, ExpectedRevision: revision, Kind: string(control.KindIncidentAction), Payload: payload})
		var f *model.Fault
		if !errors.As(err, &f) || f.Code != model.Conflict {
			return err
		}
		if f.SafeDetail == control.IncidentVersionConflict {
			rec, found, e := s.control.Incident(ctx, scope, a.Target.Project, a.Target.Incident)
			if e != nil || !found {
				return model.Fail(model.Corrupt)
			}
			return &VersionConflict{Current: rec.Version}
		}
		// The control revision moved; the command conflicted with nothing. The
		// command ID makes the retry a no-op if it had already committed.
	}
	f := model.Fail(model.Unavailable)
	f.Retryable = true
	return f
}
