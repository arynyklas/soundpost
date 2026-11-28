// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
)

// This file is the C05 half of C08 incident response: the KindIncidentAction
// dispatcher. Like rule evaluation it stores only leaf DTOs. The incident state
// is opaque JSON that the incidents package computes with its pure reducer;
// control never imports that package and never interprets a state beyond the
// closed header (incident_id, org_id, project_id, version) and, only to bound
// growth, the resolution (status, resolved_at). What control owns,
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

// Erased reports whether a deletion replaced the record's state by its
// tombstone: the identity, version and intent history remain, the state derived
// from telemetry is gone. It is not storage damage.
func (r IncidentRecord) Erased() bool { return stateIsTombstone(r.State) }

const (
	maxIncidentStateBytes     = 256 << 10
	maxIncidentsPerProject    = 1024
	maxIncidentIntents        = 1024
	maxIncidentCommandIntents = 8
	maxIncidentToken          = 32
	// maxIncidentStubs bounds the pruned-incident stubs one project keeps (R01-4):
	// four times the live cap, a few hundred bytes each.
	maxIncidentStubs = 4096

	// IncidentResolvedRetention is how long a resolved incident keeps its state
	// before it may be pruned to make room for a new one (the lifecycle retention
	// of the evidence it summarises, 90 days). Pruning happens only at the
	// per-project cap, oldest resolution first, and never touches an open incident
	// or a resolved one inside the window: a project full of recent incidents is
	// refused (Quota), not silently trimmed. A pruned incident stays as a stub (see
	// pruneResolvedIncidents).
	IncidentResolvedRetention = model.UnixNano(90 * 24 * time.Hour)
)

// IncidentVersionConflict is the SafeDetail of a lost incident version race.
const IncidentVersionConflict = "incident_version_conflict"

// BindIncidentAction installs the KindIncidentAction dispatcher on this Store
// only, like the other Bind* methods; it is a conflict to bind twice.
func (s *Store) BindIncidentAction() error {
	return s.RegisterHandler(KindIncidentAction, func(scope auth.Scope, st *State, cmd Command) (Effect, error) {
		return applyIncidentAction(scope, st, cmd, s.BoundedRules())
	})
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

// loadIncidentRO is loadIncident against a read-only control state: it reads the one record, not the books.
func loadIncidentRO(ro model.ReadOnlyControl, key string) (IncidentRecord, bool, error) {
	raw, ok := ro.BookRecord(model.BookIncidents, key)
	if !ok {
		return IncidentRecord{}, false, nil
	}
	var r IncidentRecord
	if err := json.Unmarshal(raw, &r); err != nil {
		return IncidentRecord{}, false, model.Fail(model.Corrupt)
	}
	return r, true, nil
}

// incidentActionScope admits the scope to the incident action. An organization
// administrator acts as before; a member holding incidents.write on the project
// acts as a person (decision D19, auth.AuthorizeWrite). The in-process system
// runner (not a member, holds org.admin by construction) is admitted only for
// the two system-origin observations, open and impact, on a live project its
// scope names; it can never take a human decision.
func incidentActionScope(scope auth.Scope, st *State, org model.ID, c IncidentCommand) error {
	if scope.Permission() == auth.IncidentsWrite && !scope.IsSystem() {
		authority, ok := st.Orgs[org.String()]
		if !ok || scope.OrgID() != org || !authority.Members[scope.PrincipalID().String()] || !scope.AllowsProject(c.Project) || len(scope.ProjectIDs()) != 1 {
			return model.Fail(model.NotFound)
		}
		if _, ok := authority.Projects[c.Project.String()]; !ok {
			return model.Fail(model.NotFound)
		}
		return nil
	}
	if !scope.IsSystem() {
		return releaseScope(scope, st, org, c.Project)
	}
	if scope.Permission() != auth.OrgAdmin || scope.OrgID() != org || c.Origin != "system" || c.Action != "open" && c.Action != "impact" {
		return model.Fail(model.NotFound)
	}
	return issueProjectScope(scope, st, c.Project)
}

func applyIncidentAction(scope auth.Scope, st *State, cmd Command, bounded bool) (Effect, error) {
	var c IncidentCommand
	if err := strictPayload(cmd.Payload, &c); err != nil {
		return Effect{}, err
	}
	org := scope.OrgID()
	// Scope and grants first: nothing about the target is looked up, parsed or
	// answered for a scope that may not act in this project.
	if err := incidentActionScope(scope, st, org, c); err != nil {
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
		live := 0
		for k, raw := range st.IncidentBooks {
			if len(k) > len(prefix) && k[:len(prefix)] == prefix {
				// The previous rule has no stubs: every record of the project counts.
				if !bounded {
					live++
				} else if _, stub := prunedIncidentAt(raw); !stub {
					live++
				}
			}
		}
		if live >= maxIncidentsPerProject {
			live -= pruneResolvedIncidents(st, prefix, c.At, live-maxIncidentsPerProject+1, bounded)
			if live >= maxIncidentsPerProject {
				return Effect{}, model.Fail(model.Quota)
			}
			if bounded {
				boundIncidentStubs(st, prefix, maxIncidentStubs)
			}
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
	if err = eraseLateEffect(st, org, c.Project); err != nil {
		return Effect{}, err
	}
	return Effect{AffectedIDs: []model.ID{c.Incident}, Phase: "applied"}, nil
}

// pruneResolvedIncidents turns up to need resolved incidents of one project whose
// resolution is at least IncidentResolvedRetention before at into stubs, oldest
// resolution first (key order breaks ties), and returns how many it pruned. It
// is a pure function of the state and the command's own time, so every replica
// prunes the same records. A record whose state is a tombstone or does not parse
// as resolved is never pruned. Without bounded (the previous rule, see
// bounded_rules.go) the record is removed instead.
//
// A pruned incident is not removed: the incident ID is the idempotence key of the
// producers that open incidents (they derive it from the episode and open one when
// none exists), so a missing record would let the same episode open a second
// incident and notify twice (R01-4). The record keeps its identity, version and
// digest, loses its state and its intents (it reads as erased, see
// prunedIncidentState) and does not count against maxIncidentsPerProject; the
// stubs themselves are bounded by boundIncidentStubs.
func pruneResolvedIncidents(st *State, prefix string, at model.UnixNano, need int, bounded bool) int {
	type candidate struct {
		key  string
		when model.UnixNano
		rec  IncidentRecord
	}
	var out []candidate
	for k, raw := range st.IncidentBooks {
		if len(k) <= len(prefix) || k[:len(prefix)] != prefix {
			continue
		}
		var rec IncidentRecord
		if json.Unmarshal(raw, &rec) != nil || rec.Erased() {
			continue
		}
		var head struct {
			Status     string         `json:"status"`
			ResolvedAt model.UnixNano `json:"resolved_at"`
		}
		if json.Unmarshal(rec.State, &head) != nil || head.Status != "resolved" || head.ResolvedAt <= 0 || at-head.ResolvedAt < IncidentResolvedRetention {
			continue
		}
		out = append(out, candidate{k, head.ResolvedAt, rec})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].when != out[j].when {
			return out[i].when < out[j].when
		}
		return out[i].key < out[j].key
	})
	if len(out) > need {
		out = out[:need]
	}
	pruned := 0
	for _, c := range out {
		if !bounded {
			delete(st.IncidentBooks, c.key)
			pruned++
			continue
		}
		stub := IncidentRecord{Org: c.rec.Org, Project: c.rec.Project, ID: c.rec.ID, Version: c.rec.Version, Digest: c.rec.Digest, State: prunedIncidentState(c.rec, at)}
		raw, err := json.Marshal(stub)
		if err != nil {
			continue // cannot happen for these fields; the record is then kept whole
		}
		st.IncidentBooks[c.key] = raw
		pruned++
	}
	return pruned
}

// incidentPrunedMark is the value of the "erased" member of a pruned incident's
// state: the record is a tombstone (IncidentRecord.Erased) that no deletion
// produced.
const incidentPrunedMark = "pruned"

// prunedIncidentState is the state a pruned incident keeps in place of its own: the
// closed header, the pruning time and the tombstone mark.
func prunedIncidentState(rec IncidentRecord, at model.UnixNano) json.RawMessage {
	v, _ := json.Marshal(rec.Version)
	return json.RawMessage(fmt.Sprintf(`{"incident_id":%q,"org_id":%q,"project_id":%q,"version":%s,"erased":%q,"pruned_ns":%d}`, rec.ID.String(), rec.Org.String(), rec.Project.String(), v, incidentPrunedMark, int64(at)))
}

// prunedIncidentAt reports whether the record is a pruned stub and when it was
// pruned. The cheap byte test comes first; the parse decides.
func prunedIncidentAt(raw json.RawMessage) (model.UnixNano, bool) {
	if !bytes.Contains(raw, []byte(`"erased":"`+incidentPrunedMark+`"`)) {
		return 0, false
	}
	var rec IncidentRecord
	if json.Unmarshal(raw, &rec) != nil {
		return 0, false
	}
	var head struct {
		Erased   string `json:"erased"`
		PrunedAt int64  `json:"pruned_ns"`
	}
	if json.Unmarshal(rec.State, &head) != nil || head.Erased != incidentPrunedMark {
		return 0, false
	}
	return model.UnixNano(head.PrunedAt), true
}

// boundIncidentStubs drops the oldest pruned stubs of one project (by pruning
// time, then key) beyond limit and returns how many it dropped. A producer can
// only look for the incident of an episode that is still current, one per issue
// (at most 256 issues a project holds), so a stub older than the newest limit
// of them can only be for an episode long over: this bound costs a repeated
// incident only for an issue still open after limit further prunings.
func boundIncidentStubs(st *State, prefix string, limit int) int {
	type stub struct {
		key  string
		when model.UnixNano
	}
	var all []stub
	for k, raw := range st.IncidentBooks {
		if len(k) <= len(prefix) || k[:len(prefix)] != prefix {
			continue
		}
		if at, ok := prunedIncidentAt(raw); ok {
			all = append(all, stub{k, at})
		}
	}
	if len(all) <= limit {
		return 0
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].when != all[j].when {
			return all[i].when < all[j].when
		}
		return all[i].key < all[j].key
	})
	drop := all[:len(all)-limit]
	for _, s := range drop {
		delete(st.IncidentBooks, s.key)
	}
	return len(drop)
}

// Incident reads one incident's committed record through a linearizable control
// read. The scope is checked before the incident is looked up; a project the
// scope does not name is indistinguishable from an absent incident.
func (s *Store) Incident(ctx context.Context, scope auth.Scope, project, incident model.ID) (out IncidentRecord, found bool, err error) {
	err = s.ViewShared(ctx, func(st model.ReadOnlyControl) error {
		if e := ruleReadScopeRO(scope, st, project); e != nil {
			return e
		}
		var e error
		out, found, e = loadIncidentRO(st, incidentKey(scope.OrgID(), project, incident))
		return e
	})
	return
}

// Incidents lists one project's incident records in ID order.
func (s *Store) Incidents(ctx context.Context, scope auth.Scope, project model.ID) (out []IncidentRecord, err error) {
	err = s.ViewShared(ctx, func(st model.ReadOnlyControl) error {
		if e := ruleReadScopeRO(scope, st, project); e != nil {
			return e
		}
		for _, key := range st.BookKeys(model.BookIncidents, "") {
			raw, ok := st.BookRecord(model.BookIncidents, key)
			if !ok {
				continue
			}
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

// eraseIncidents drops the incident state a deletion covers, in the caller's
// transition. The state is opaque to control, so what is covered is decided from
// what control can read: the project, and for a range the evidence times in the
// state (a state with none, or one that cannot be read, is covered: a payload
// that cannot be attributed is dropped whole, never kept). A retirement covers
// every incident of its projects. An entity deletion names replay and profile
// roots, which an incident only links by ID: it covers none. What stays is the
// record's identity, version, digest and intent history, and a tombstone state
// carrying only the closed header and the erasing operation.
func eraseIncidents(st *State, p model.DeletePredicate) (dropped int, err error) {
	dropped, _, err = eraseIncidentsBy(st, p, stateErased)
	return dropped, err
}

// eraseIncidentsBy is eraseIncidents with the rule that covers an opaque state;
// over counts the covered states that had no recorded window (CD-9).
func eraseIncidentsBy(st *State, p model.DeletePredicate, rule stateRule) (dropped, over int, err error) {
	keys := make([]string, 0, len(st.IncidentBooks))
	for key := range st.IncidentBooks {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		rec, _, err := loadIncident(st, key)
		if err != nil {
			return 0, 0, err
		}
		if !rule(p, rec.Org, rec.Project, rec.State) {
			continue
		}
		if overErasure(p, rec.State) {
			over++
		}
		rec.State = tombstoneState("incident_id", rec.ID, rec.Org, rec.Project, rec.Version, p.Operation)
		raw, err := json.Marshal(rec)
		if err != nil {
			return 0, 0, model.Fail(model.Corrupt)
		}
		st.IncidentBooks[key] = raw
		dropped++
	}
	return dropped, over, nil
}
