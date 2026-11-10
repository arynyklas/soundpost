// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"sort"

	"soundpost/internal/auth"
	"soundpost/internal/model"
)

// This file is the C05 half of C08 incident response: the KindIncidentAction
// dispatcher. Like rule evaluation it stores only leaf DTOs. The incident state
// is opaque JSON that the incidents package computes with its pure reducer;
// control never imports that package and never interprets a state beyond the
// closed header (incident_id, org_id, project_id, version). What control owns,
// atomically in one command:
//
//   - scope: an organization administrator of exactly this organization and
//     project, checked before any incident is looked up, with a wrong-scope and
//     a missing incident indistinguishable;
//   - the actor: the committing session's principal, never a payload claim;
//   - the version compare-and-set: two commands that both expect version N
//     cannot both commit; the loser is a conflict, never merged or retried;
//   - the audit and the internal intent outbox, created in the same transition.
//
// Intents are safe intent records (kinds, versions, codes), not deliveries; the
// notify outbox that consumes them is a later task.

// IncidentCommand is the closed KindIncidentAction payload.
type IncidentCommand struct {
	Project         model.ID         `json:"project"`
	Incident        model.ID         `json:"incident"`
	Action          string           `json:"action"`
	Origin          string           `json:"origin"`
	Actor           model.ID         `json:"actor"`
	At              model.UnixNano   `json:"at"`
	ExpectedVersion model.Revision   `json:"expected_version"`
	NewVersion      model.Revision   `json:"new_version"`
	State           json.RawMessage  `json:"state"`
	Digest          model.Hash       `json:"digest"`
	Intents         []IncidentIntent `json:"intents,omitempty"`
}

// IncidentIntent is one safe audit/outbox intent created by an incident action.
type IncidentIntent struct {
	ID             model.ID       `json:"id"`
	Kind           string         `json:"kind"`
	Version        model.Revision `json:"version"`
	ImpactRevision uint64         `json:"impact_revision,omitempty"`
	Eligible       bool           `json:"eligible,omitempty"`
	Code           string         `json:"code,omitempty"`
	Until          model.UnixNano `json:"until,omitempty"`
	Subject        *model.ID      `json:"subject,omitempty"`
}

// IncidentRecord is everything control holds for one incident.
type IncidentRecord struct {
	Org     model.ID         `json:"org"`
	Project model.ID         `json:"project"`
	ID      model.ID         `json:"id"`
	Version model.Revision   `json:"version"`
	Digest  model.Hash       `json:"digest"`
	State   json.RawMessage  `json:"state"`
	Intents []IncidentIntent `json:"intents,omitempty"`
}

const (
	maxIncidentStateBytes     = 256 << 10
	maxIncidentsPerProject    = 1024
	maxIncidentIntents        = 1024
	maxIncidentCommandIntents = 8
	maxIncidentToken          = 32
)

// IncidentVersionConflict is the SafeDetail of a lost incident version race.
const IncidentVersionConflict = "incident_version_conflict"

// BindIncidentAction installs the KindIncidentAction dispatcher on this Store
// only, like the other Bind* methods; it is a conflict to bind twice.
func (s *Store) BindIncidentAction() error {
	return s.RegisterHandler(KindIncidentAction, applyIncidentAction)
}

func incidentKey(org, project, incident model.ID) string {
	return org.String() + ":" + project.String() + ":" + incident.String()
}

func incidentToken(s string) bool {
	if s == "" || len(s) > maxIncidentToken {
		return false
	}
	for _, r := range s {
		if r != '_' && (r < 'a' || r > 'z') {
			return false
		}
	}
	return true
}

func loadIncident(st *State, key string) (IncidentRecord, bool, error) {
	raw, ok := st.IncidentBooks[key]
	if !ok {
		return IncidentRecord{}, false, nil
	}
	var r IncidentRecord
	if err := json.Unmarshal(raw, &r); err != nil {
		return IncidentRecord{}, false, model.Fail(model.Corrupt)
	}
	return r, true, nil
}

func applyIncidentAction(scope auth.Scope, st *State, cmd Command) (Effect, error) {
	var c IncidentCommand
	if err := strictPayload(cmd.Payload, &c); err != nil {
		return Effect{}, err
	}
	org := scope.OrgID()
	// Scope and grants first: nothing about the target is looked up, parsed or
	// answered for a scope that may not act in this project.
	if err := releaseScope(scope, st, org, c.Project); err != nil {
		return Effect{}, err
	}
	if c.Incident == (model.ID{}) || c.At <= 0 || !incidentToken(c.Action) || c.Origin != "human" && c.Origin != "system" ||
		c.NewVersion != c.ExpectedVersion+1 || len(c.State) < 2 || len(c.State) > maxIncidentStateBytes ||
		c.Digest != model.Hash(sha256.Sum256(c.State)) || len(c.Intents) > maxIncidentCommandIntents {
		return Effect{}, model.Fail(model.Invalid)
	}
	// The actor is the validated session's principal, never a payload claim.
	if c.Actor != scope.PrincipalID() {
		return Effect{}, model.Fail(model.Forbidden)
	}
	var header struct {
		ID      model.ID       `json:"incident_id"`
		Org     model.ID       `json:"org_id"`
		Project model.ID       `json:"project_id"`
		Version model.Revision `json:"version"`
	}
	if json.Unmarshal(c.State, &header) != nil || header.ID != c.Incident || header.Org != org || header.Project != c.Project || header.Version != c.NewVersion {
		return Effect{}, model.Fail(model.Invalid)
	}
	key := incidentKey(org, c.Project, c.Incident)
	rec, exists, err := loadIncident(st, key)
	if err != nil {
		return Effect{}, err
	}
	switch {
	case !exists && c.ExpectedVersion != 0:
		return Effect{}, model.Fail(model.NotFound) // a missing incident
	case exists && rec.Version != c.ExpectedVersion:
		return Effect{}, ruleFault(model.Conflict, IncidentVersionConflict)
	case !exists:
		prefix := org.String() + ":" + c.Project.String() + ":"
		n := 0
		for k := range st.IncidentBooks {
			if len(k) > len(prefix) && k[:len(prefix)] == prefix {
				n++
			}
		}
		if n >= maxIncidentsPerProject {
			return Effect{}, model.Fail(model.Quota)
		}
		rec = IncidentRecord{Org: org, Project: c.Project, ID: c.Incident}
	}
	if len(rec.Intents)+len(c.Intents) > maxIncidentIntents {
		return Effect{}, model.Fail(model.Quota)
	}
	seen := make(map[model.ID]bool, len(rec.Intents)+len(c.Intents))
	for _, in := range rec.Intents {
		seen[in.ID] = true
	}
	for _, in := range c.Intents {
		if in.ID == (model.ID{}) || seen[in.ID] || !incidentToken(in.Kind) || in.Version != c.NewVersion || in.Code != "" && !incidentToken(in.Code) {
			return Effect{}, model.Fail(model.Invalid)
		}
		seen[in.ID] = true
	}
	rec.Version, rec.Digest, rec.State = c.NewVersion, c.Digest, c.State
	rec.Intents = append(rec.Intents, c.Intents...)
	raw, err := json.Marshal(rec)
	if err != nil {
		return Effect{}, model.Fail(model.Invalid)
	}
	if st.IncidentBooks == nil {
		st.IncidentBooks = map[string]json.RawMessage{}
	}
	st.IncidentBooks[key] = raw
	st.Audits = append(st.Audits, model.ControlAudit{ID: cmd.CommandID, Principal: scope.PrincipalID(), Action: "incidents." + c.Action, Reason: "incident action", Time: int64(c.At),
		Org: org.String(), PolicyEpoch: scope.PolicyEpoch(), Targets: []model.ID{c.Incident}, RequestID: cmd.CommandID, Outcome: model.AuditAllowed})
	return Effect{AffectedIDs: []model.ID{c.Incident}, Phase: "applied"}, nil
}

// Incident reads one incident's committed record through a linearizable control
// read. The scope is checked before the incident is looked up; a project the
// scope does not name is indistinguishable from an absent incident.
func (s *Store) Incident(ctx context.Context, scope auth.Scope, project, incident model.ID) (out IncidentRecord, found bool, err error) {
	err = s.View(ctx, func(st State) error {
		if e := ruleReadScope(scope, st, project); e != nil {
			return e
		}
		var e error
		out, found, e = loadIncident(&st, incidentKey(scope.OrgID(), project, incident))
		return e
	})
	return
}

// Incidents lists one project's incident records in ID order.
func (s *Store) Incidents(ctx context.Context, scope auth.Scope, project model.ID) (out []IncidentRecord, err error) {
	err = s.View(ctx, func(st State) error {
		if e := ruleReadScope(scope, st, project); e != nil {
			return e
		}
		for _, raw := range st.IncidentBooks {
			var r IncidentRecord
			if e := json.Unmarshal(raw, &r); e != nil {
				return model.Fail(model.Corrupt)
			}
			if r.Org == scope.OrgID() && r.Project == project {
				out = append(out, r)
			}
		}
		sort.Slice(out, func(i, j int) bool { return out[i].ID.String() < out[j].ID.String() })
		return nil
	})
	return
}
