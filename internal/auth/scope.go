// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth

import (
	"context"
	"encoding/json"
	"sort"
	"soundpost/internal/model"
	"time"
)

type Permission string

const (
	Read          Permission = "telemetry.read"
	RawRead       Permission = "raw.read"
	OrgAdmin      Permission = "org.admin"
	InstanceAdmin Permission = "instance.admin"
	PolicyWrite   Permission = "policy.write"
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
}

func (s Scope) OrgID() model.ID               { return s.org }
func (s Scope) PrincipalID() model.ID         { return s.credential.user }
func (s Scope) ProjectIDs() []model.ID        { return append([]model.ID(nil), s.projects...) }
func (s Scope) VisibilityFingerprint() string { return s.fingerprint }
func (s Scope) PolicyEpoch() uint64           { return s.epoch }
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
	if s.action != OrgAdmin && s.action != InstanceAdmin {
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
	err := s.store.View(ctx, func(st model.ControlState) error {
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
	if scope.service != s {
		return model.Fail(model.Forbidden)
	}
	if _, e := s.Authenticate(ctx, scope.credential.token); e != nil {
		return e
	}
	return s.store.View(ctx, func(st model.ControlState) error {
		if err := s.validateCredentialState(st, scope.credential); err != nil {
			return err
		}
		if !tokenAllows(st, scope.credential, scope.org, scope.projects, scope.action) {
			return model.Fail(model.NotFound)
		}
		o, ok := st.Orgs[scope.org.String()]
		if !ok || o.Epoch != scope.epoch {
			return model.Fail(model.NotFound)
		}
		return s.grantLease(scope, st, checkedAt)
	})
}
