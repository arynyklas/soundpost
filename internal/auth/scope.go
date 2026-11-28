// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth

import (
	"context"
	"encoding/json"
	"github.com/arynyklas/soundpost/internal/model"
	"sort"
	"time"
)

type Permission string

const (
	Read          Permission = "telemetry.read"
	RawRead       Permission = "raw.read"
	OrgAdmin      Permission = "org.admin"
	InstanceAdmin Permission = "instance.admin"
	PolicyWrite   Permission = "policy.write"
	// IncidentsWrite is the human incident-response grant: assign, ack, resolve,
	// link, impact, snooze and maintenance of the incidents of the granted
	// projects (decision D19, internal/auth/write.go).
	IncidentsWrite Permission = "incidents.write"
	// RulesWrite is reserved for rule-definition writes. No human route needs it
	// yet; it is grantable and, by itself, authorizes no action.
	RulesWrite Permission = "rules.write"
)

type Scope struct {
	service          *Service
	credential       Credential
	org              model.ID
	projects         []model.ID
	action           Permission
	epoch            uint64
	fingerprint      string
	lease            *scopeLease
	elevation        model.ID
	sources          []model.ID
	elevationExpires time.Time
	sourceCredential *SourceCredential
	historical       bool
	// claimed marks a scope made of another voter's claim (ScopeOfClaim): the organization and project it carries were
	// told, not read from this voter's state, so every validation against a state checks them against it.
	claimed bool
	// release marks a scope derived by AuthorizeRelease: its token authority is release.write.
	release bool
	// expiresAt is the instant the scope's raw-read authority lapses on its
	// own (a restricted-raw source policy or source lifetime ending). Zero means
	// the scope carries no clock-based expiry.
	expiresAt time.Time
}

func (s Scope) OrgID() model.ID               { return s.org }
func (s Scope) PrincipalID() model.ID         { return s.credential.user }
func (s Scope) ProjectIDs() []model.ID        { return append([]model.ID(nil), s.projects...) }
func (s Scope) VisibilityFingerprint() string { return s.fingerprint }
func (s Scope) PolicyEpoch() uint64           { return s.epoch }

// ExpiresAt is the instant a clock-based authority window (restricted-raw
// policy or source lifetime) closes; zero when the scope has none. Caches,
// tickets and export grants must never be held past it.
func (s Scope) ExpiresAt() time.Time { return s.expiresAt }

// Now is the authority's clock, the single time source every authorization,
// ticket and export-lifetime decision must share.
func (s *Service) Now() time.Time { return s.now() }
func (s Scope) AllowsProject(id model.ID) bool {
	for _, v := range s.projects {
		if v == id {
			return true
		}
	}
	return false
}
func (s Scope) AllowsSource(id model.ID) bool { return hasID(s.sources, id) }
func (s Scope) Permission() Permission        { return s.action }
func (s Scope) UnmarshalJSON([]byte) error    { return model.Fail(model.Forbidden) }
func (s Scope) ControlAuthorize(ctx context.Context, kind string) error {
	if s.service == nil {
		return model.Fail(model.Forbidden)
	}
	if e := s.service.Revalidate(ctx, s); e != nil {
		return e
	}
	switch s.action {
	case OrgAdmin, InstanceAdmin:
		if s.release && kind != releaseWriteKind {
			return model.Fail(model.Forbidden)
		}
	case IncidentsWrite:
		// The one non-administrator write the control store accepts: the human
		// incident action, and nothing else (decision D19).
		if kind != IncidentActionKind {
			return model.Fail(model.Forbidden)
		}
	case Read:
		// The other non-administrator write the control store accepts: a saved
		// view (save or delete), committed by a caller who reads the project. The
		// handler re-checks membership, the grant and ownership against the state
		// the command applies to (internal/control/saved_views.go).
		if kind != SavedViewKind {
			return model.Fail(model.Forbidden)
		}
	default:
		return model.Fail(model.Forbidden)
	}
	return nil
}
func (s *Service) Authorize(ctx context.Context, c Credential, org model.ID, projects []model.ID, action Permission) (Scope, error) {
	if c.service != s {
		return Scope{}, model.Fail(model.Unauthenticated)
	}
	if _, err := s.Authenticate(ctx, c.token); err != nil {
		return Scope{}, err
	}
	checkedAt := s.now()
	out := Scope{service: s, credential: c, org: org, projects: append([]model.ID(nil), projects...), action: action, lease: &scopeLease{}}
	err := s.viewCore(ctx, func(st model.ControlState) error {
		if err := s.validateCredentialState(st, c); err != nil {
			return err
		}
		if !tokenAllows(st, c, org, projects, action) {
			return model.Fail(model.NotFound)
		}
		o, ok := st.Orgs[org.String()]
		if !ok {
			return model.Fail(model.NotFound)
		}
		if action == OrgAdmin {
			if !o.Admins[c.user.String()] {
				return model.Fail(model.NotFound)
			}
		} else {
			if len(projects) == 0 || !o.Members[c.user.String()] {
				return model.Fail(model.NotFound)
			}
			for _, p := range projects {
				if _, ok := o.Projects[p.String()]; !ok {
					return model.Fail(model.NotFound)
				}
				found := false
				for _, v := range o.Grants[c.user.String()+":"+p.String()] {
					if v == string(action) {
						found = true
					}
				}
				for _, team := range o.Teams {
					if team.Enabled && hasID(team.Members, c.user) && hasID(team.Projects, p) {
						for _, v := range team.Permissions {
							if v == string(action) {
								found = true
							}
						}
					}
				}
				if !found {
					return model.Fail(model.NotFound)
				}
			}
		}
		out.epoch = o.Epoch
		keys := make([]string, 0)
		if c.machine {
			keys = append(keys, "server_token:"+s.serverTokenDigest(c.token))
		} else {
			// A human session is part of the visibility identity, so logout/login
			// or rotation ends every ticket, cursor, export grant and warm entry
			// minted under the previous session.
			keys = append(keys, "session:"+hashToken(c.token))
		}
		for k, v := range o.Grants {
			if len(k) >= 32 && k[:32] == c.user.String() {
				keys = append(keys, k+":"+joinSorted(v))
			}
		}
		for id, team := range o.Teams {
			if team.Enabled && hasID(team.Members, c.user) {
				raw, _ := json.Marshal(team)
				keys = append(keys, "team:"+id+":"+string(raw))
			}
		}
		for id, raw := range o.Settings {
			if len(id) > 14 && id[:14] == "source_policy:" {
				var policy SourcePolicyConfig
				if json.Unmarshal(raw, &policy) == nil && hasID(policy.Readers, c.user) {
					keys = append(keys, "source:"+id)
				}
			}
		}
		requested := make([]string, len(projects))
		for i, p := range projects {
			requested[i] = p.String()
		}
		sort.Strings(requested)
		requestedRaw, _ := json.Marshal(requested)
		if o.Admins[c.user.String()] {
			keys = append(keys, "org.admin")
		}
		keys = append(keys, "requested:"+string(action)+":"+string(requestedRaw))
		sort.Strings(keys)
		raw, _ := json.Marshal(keys)
		out.fingerprint = hashToken(c.user.String() + org.String() + string(raw))
		return s.grantLease(out, st, checkedAt)
	})
	if err != nil {
		return Scope{}, err
	}
	return out, nil
}
func hasID(ids []model.ID, id model.ID) bool {
	for _, v := range ids {
		if v == id {
			return true
		}
	}
	return false
}
func joinSorted(v []string) string {
	x := append([]string(nil), v...)
	sort.Strings(x)
	b, _ := json.Marshal(x)
	return string(b)
}
func (s *Service) Revalidate(ctx context.Context, scope Scope) error {
	return s.revalidate(ctx, scope, nil)
}

// revalidate is Revalidate with a callback that runs, with the control state the revalidation
// just accepted, inside the same linearizable read: one ReadIndex and one decode answer both
// "is this scope still authorized" and whatever the caller needs from that same state (the cache
// binding derives the delete generation from it). The credential check is the state check
// validateCredentialState makes inside that read (session or token present, not expired, user not
// disabled): a separate Authenticate read before it would repeat it. within runs only for a
// scope that passed every check, and not at all for a source scope (RevalidateSource).
func (s *Service) revalidate(ctx context.Context, scope Scope, within func(model.ControlState) error) error {
	if scope.sourceCredential != nil {
		if scope.service != s || len(scope.projects) != 1 || len(scope.sources) != 1 {
			return model.Fail(model.Forbidden)
		}
		return scope.RevalidateSource(ctx, scope.projects[0], scope.sources[0], !scope.historical)
	}
	if scope.service != s || scope.lease == nil {
		return model.Fail(model.Forbidden)
	}
	scope.lease.mu.Lock()
	defer scope.lease.mu.Unlock()
	scope.lease.deadline = time.Time{}
	checkedAt := s.now()
	if scope.elevation != (model.ID{}) && !s.now().Before(scope.elevationExpires) {
		return model.Fail(model.Forbidden)
	}
	if !scope.expiresAt.IsZero() && !checkedAt.Before(scope.expiresAt) {
		return model.Fail(model.NotFound)
	}
	if scope.service != s {
		return model.Fail(model.Forbidden)
	}
	var check func(model.ReadOnlyControl) error
	if scope.credential.system {
		check = func(st model.ReadOnlyControl) error {
			if err := s.validateSystemStateRO(st, scope); err != nil {
				return err
			}
			return s.grantLeaseRO(scope, st, checkedAt)
		}
	} else {
		check = func(st model.ReadOnlyControl) error {
			if err := s.validateCredentialStateRO(st, scope.credential); err != nil {
				return err
			}
			if !tokenAllowsRO(st, scope.credential, scope.org, scope.projects, scope.tokenAction()) {
				return model.Fail(model.NotFound)
			}
			epoch, ok := st.OrgEpoch(scope.org.String())
			if !ok || epoch != scope.epoch {
				return model.Fail(model.NotFound)
			}
			return s.grantLeaseRO(scope, st, checkedAt)
		}
	}
	if within == nil {
		// The common case (every storage read, every pass of the workers) only asks whether the
		// scope is still authorized: it reads the shared decode of the committed state.
		return s.viewShared(ctx, check)
	}
	return s.viewCore(ctx, func(st model.ControlState) error {
		if err := check(model.ReadOnlyOf(&st)); err != nil {
			return err
		}
		return within(st)
	})
}
