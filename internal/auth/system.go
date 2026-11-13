// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth

import (
	"context"
	"crypto/sha256"
	"soundpost/internal/model"
)

// SystemRunner is the actor name of the in-process background runner. It is not
// a user, a session or a token: nothing a client can present names it.
const SystemRunner = "system:runner"

// IssuesWrite is the issue-lifecycle grant. The runner's issue producer writes
// under it; no human or token path changes.
const IssuesWrite Permission = "issues.write"

// systemPrincipalTag is the readable prefix of a system principal ID: the ASCII
// bytes of SystemRunner. An audit row, a command owner binding and a timeline
// entry carry the principal as an ID, so the ID itself says who acted.
const systemPrincipalTag = SystemRunner

// SystemPrincipal is the audit principal of the runner in one organization: the
// ASCII tag followed by three bytes of the organization's digest. Every check
// that uses it also names the organization, so a collision between two
// organizations' tags would change nothing; the tag only keeps the principals
// of different organizations apart in logs.
func SystemPrincipal(org model.ID) model.ID {
	var id model.ID
	n := copy(id[:], systemPrincipalTag)
	sum := sha256.Sum256(append([]byte("soundpost/system-runner/"), org[:]...))
	copy(id[n:], sum[:])
	return id
}

// IsSystemPrincipal reports whether id is a system principal (of any
// organization). create_user refuses such an ID, so no human or token principal
// can ever collide with one.
func IsSystemPrincipal(id model.ID) bool {
	return string(id[:len(systemPrincipalTag)]) == systemPrincipalTag
}

// systemRoles are exactly the permissions the runner needs and nothing else:
// the project read scope of the rule evaluator, the organization-administrator
// scope of the control commits (rule evaluations, conditions, delivery), the
// issue-lifecycle write of the issue producer and the policy write of the job
// producer. Raw reads, artifacts, replay, profiles, source credentials,
// instance administration and every deletion path are outside it.
func systemRole(p Permission) bool {
	switch p {
	case Read, OrgAdmin, IssuesWrite, PolicyWrite:
		return true
	}
	return false
}

// IsSystem reports whether the scope was derived by AuthorizeSystem.
func (s Scope) IsSystem() bool { return s.credential.system }

// AuthorizeSystem derives the runner's scope in one organization. It is the
// only way to obtain such a scope and it is never reachable from a request:
// no token, session or body field selects it, a scope cannot be decoded from
// JSON, and no credential Authenticate returns is a system credential. The scope
// is re-derived by every pass, so the organization or a project ending
// (retired, deleted) or the organization's policy epoch moving takes effect at
// the next pass and, through Revalidate and the control validation, at once for
// a scope already in hand.
//
// Only the roles in systemRole are available; any other permission is Forbidden.
// A permission other than OrgAdmin needs at least one project, each of which must
// exist in the organization and not be retired; an unknown, retired or deleted
// organization is the same NotFound as an unknown one.
func (s *Service) AuthorizeSystem(ctx context.Context, org model.ID, projects []model.ID, action Permission) (Scope, error) {
	if s == nil || org == (model.ID{}) {
		return Scope{}, model.Fail(model.Invalid)
	}
	if !systemRole(action) {
		return Scope{}, model.Fail(model.Forbidden)
	}
	if action != OrgAdmin && len(projects) == 0 {
		return Scope{}, model.Fail(model.Invalid)
	}
	checkedAt := s.now()
	c := Credential{service: s, user: SystemPrincipal(org), system: true}
	out := Scope{service: s, credential: c, org: org, projects: append([]model.ID(nil), projects...), action: action, lease: &scopeLease{}}
	err := s.store.View(ctx, func(st model.ControlState) error {
		if err := s.validateCredentialState(st, c); err != nil {
			return err
		}
		o, ok := st.Orgs[org.String()]
		if !ok {
			return model.Fail(model.NotFound)
		}
		if _, retired := st.RetiredOrgs[org.String()]; retired {
			return model.Fail(model.NotFound)
		}
		requested := make([]string, len(projects))
		for i, p := range projects {
			if _, ok := o.Projects[p.String()]; !ok {
				return model.Fail(model.NotFound)
			}
			if _, retired := st.RetiredProjects[org.String()+":"+p.String()]; retired {
				return model.Fail(model.NotFound)
			}
			requested[i] = p.String()
		}
		out.epoch = o.Epoch
		out.fingerprint = hashToken(SystemRunner + "|" + org.String() + "|" + string(action) + "|" + joinSorted(requested))
		return s.grantLease(out, st, checkedAt)
	})
	if err != nil {
		return Scope{}, err
	}
	return out, nil
}

// validateSystemState checks a system scope against a committed state: the
// organization still exists, is not retired, and its policy epoch is the one the
// scope was derived at. A scope that names projects needs each of them to exist
// and not be retired.
func (s *Service) validateSystemState(st model.ControlState, scope Scope) error {
	if scope.service != s || !scope.credential.system || scope.credential.user != SystemPrincipal(scope.org) {
		return model.Fail(model.Forbidden)
	}
	if !systemRole(scope.action) {
		return model.Fail(model.Forbidden)
	}
	o, ok := st.Orgs[scope.org.String()]
	if !ok || o.Epoch != scope.epoch {
		return model.Fail(model.NotFound)
	}
	if _, retired := st.RetiredOrgs[scope.org.String()]; retired {
		return model.Fail(model.NotFound)
	}
	for _, p := range scope.projects {
		if _, ok := o.Projects[p.String()]; !ok {
			return model.Fail(model.NotFound)
		}
		if _, retired := st.RetiredProjects[scope.org.String()+":"+p.String()]; retired {
			return model.Fail(model.NotFound)
		}
	}
	return nil
}
