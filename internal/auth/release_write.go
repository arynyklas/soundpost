// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth

import (
	"context"
	"encoding/json"
	"slices"
	"sort"

	"github.com/arynyklas/soundpost/internal/model"
)

// ReleaseWrite is the narrow server-token grant of a release pipeline (decision D93): register releases,
// record deploys and upload source maps for the token's projects, and nothing else. It exists only as a
// server-token permission (IssueServerToken); it is not a grant of a person (validPermission refuses it)
// and a token never holds org.admin.
const ReleaseWrite Permission = "release.write"

// releaseWriteKind is the one control command a release-write scope may commit.
const releaseWriteKind = "RegisterRelease"

// tokenAction is the permission the server token must hold for the scope: release.write for a scope derived by
// AuthorizeRelease, the scope's own action otherwise.
func (s Scope) tokenAction() Permission {
	if s.release {
		return ReleaseWrite
	}
	return s.action
}

// AuthorizeRelease derives the scope of a release pipeline: a server token that holds release.write on the project
// (and so is confined to that project and organization by the token record) for one of
//
//   - OrgAdmin: the scope the release registry and the deploy marker store accept. The token's principal must be an
//     organization administrator, as for the human path, and the scope can commit nothing but a release registration
//     (ControlAuthorize);
//   - ArtifactWrite: the scope of the source-map upload, whose artifact policy (size, type, holds, project confinement,
//     source policy) is applied unchanged. The principal must hold artifacts.write on the project (or administer the
//     organization). Private source content stays gated by raw.read, which a release-write token does not hold.
//
// A session, a token without release.write, another project or another organization is the one not-found.
func (s *Service) AuthorizeRelease(ctx context.Context, c Credential, org, project model.ID, action Permission) (Scope, error) {
	if c.service != s {
		return Scope{}, model.Fail(model.Unauthenticated)
	}
	if action != OrgAdmin && action != ArtifactWrite {
		return Scope{}, model.Fail(model.Forbidden)
	}
	if !c.machine {
		return Scope{}, model.Fail(model.NotFound)
	}
	if _, err := s.Authenticate(ctx, c.token); err != nil {
		return Scope{}, err
	}
	checkedAt := s.now()
	out := Scope{service: s, credential: c, org: org, projects: []model.ID{project}, action: action, release: true, lease: &scopeLease{}}
	err := s.store.View(ctx, func(st model.ControlState) error {
		if err := s.validateCredentialState(st, c); err != nil {
			return err
		}
		if !tokenAllows(st, c, org, []model.ID{project}, ReleaseWrite) {
			return model.Fail(model.NotFound)
		}
		if _, retired := st.RetiredOrgs[org.String()]; retired {
			return model.Fail(model.NotFound)
		}
		o, ok := st.Orgs[org.String()]
		user := c.user.String()
		if !ok {
			return model.Fail(model.NotFound)
		}
		if _, live := o.Projects[project.String()]; !live {
			return model.Fail(model.NotFound)
		}
		switch {
		case action == OrgAdmin:
			if !o.Admins[user] {
				return model.Fail(model.NotFound)
			}
		case !o.Members[user]:
			return model.Fail(model.NotFound)
		case !o.Admins[user] && !holdsGrant(o, c.user, project, ArtifactWrite):
			return model.Fail(model.NotFound)
		}
		out.epoch = o.Epoch
		keys := []string{"server_token:" + s.serverTokenDigest(c.token), "release_write:" + string(action) + ":" + project.String()}
		raw, _ := json.Marshal(keys)
		out.fingerprint = hashToken(user + org.String() + string(raw))
		return s.grantLease(out, st, checkedAt)
	})
	if err != nil {
		return Scope{}, err
	}
	return out, nil
}

// holdsGrant reports whether the user holds the permission on the project directly or through an enabled team.
func holdsGrant(o model.ControlOrg, user, project model.ID, p Permission) bool {
	if slices.Contains(o.Grants[user.String()+":"+project.String()], string(p)) {
		return true
	}
	for _, team := range o.Teams {
		if team.Enabled && hasID(team.Members, user) && hasID(team.Projects, project) && slices.Contains(team.Permissions, string(p)) {
			return true
		}
	}
	return false
}

// ServerTokenInfo is one server token as an administrator lists it: never the secret or its digest.
type ServerTokenInfo struct {
	ID          model.ID    `json:"id"`
	Principal   model.ID    `json:"principal"`
	Projects    []model.ID  `json:"projects"`
	Permissions []string    `json:"permissions"`
	Expires     model.Int64 `json:"expires"`
	State       string      `json:"state"` // active | expired | revoked
}

// ListServerTokens lists the server tokens of the organization the caller administers.
func (s *Service) ListServerTokens(ctx context.Context, c Credential, org model.ID) ([]ServerTokenInfo, error) {
	if c.service != s || c.machine {
		return nil, model.Fail(model.Unauthenticated)
	}
	out := []ServerTokenInfo{}
	err := s.store.View(ctx, func(st model.ControlState) error {
		if err := s.validateCredentialState(st, c); err != nil {
			return err
		}
		if !st.Orgs[org.String()].Admins[c.user.String()] {
			return model.Fail(model.NotFound)
		}
		for _, t := range st.ServerTokens {
			if t.Org != org {
				continue
			}
			state := "active"
			switch {
			case t.Revoked:
				state = "revoked"
			case t.Expires <= s.now().Unix():
				state = "expired"
			}
			out = append(out, ServerTokenInfo{ID: t.ID, Principal: t.Principal, Projects: slices.Clone(t.Projects), Permissions: slices.Clone(t.Permissions), Expires: model.Int64(t.Expires), State: state})
		}
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].ID.String() < out[j].ID.String() })
	return out, err
}
