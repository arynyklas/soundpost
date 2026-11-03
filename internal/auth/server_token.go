// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth

import (
	"context"
	"soundpost/internal/model"
)

type IssuedServerToken struct {
	ID      model.ID `json:"id"`
	Token   string   `json:"token"`
	Expires int64    `json:"expires,string"`
}

func (c Credential) IsServerToken() bool { return c.machine }
func (s *Service) IssueServerToken(ctx context.Context, actor Credential, org, principal model.ID, projects []model.ID, permissions []Permission, expires int64, reason string) (IssuedServerToken, error) {
	if actor.service != s || !actor.Fresh() || expires <= s.now().Unix() || reason == "" || len(reason) > 512 || len(projects) == 0 || len(permissions) == 0 {
		return IssuedServerToken{}, model.Fail(model.Forbidden)
	}
	out := IssuedServerToken{model.NewID(), randomToken(), expires}
	actions := make([]string, len(permissions))
	for i, p := range permissions {
		if !validPermission(string(p)) {
			return IssuedServerToken{}, model.Fail(model.Invalid)
		}
		actions[i] = string(p)
	}
	record := model.ControlServerToken{ID: out.ID, Principal: principal, Org: org, Projects: append([]model.ID(nil), projects...), Permissions: actions, Expires: expires}
	audit := model.ControlAudit{ID: model.NewID(), Principal: actor.user, Action: "issue_server_token", Reason: reason, Time: s.now().UnixNano(), Org: org.String(), Targets: []model.ID{out.ID, principal}, RequestID: model.RequestCorrelationID(ctx, model.ID{}), Outcome: model.AuditAllowed}
	err := s.store.Update(ctx, func(st *model.ControlState) error {
		if err := s.validateCredentialState(*st, actor); err != nil {
			return err
		}
		o, ok := st.Orgs[org.String()]
		if !ok || !o.Admins[actor.user.String()] || !o.Members[principal.String()] {
			return model.Fail(model.NotFound)
		}
		for _, project := range projects {
			if _, ok := o.Projects[project.String()]; !ok {
				return model.Fail(model.NotFound)
			}
		}
		if st.ServerTokens == nil {
			st.ServerTokens = map[string]model.ControlServerToken{}
		}
		st.ServerTokens[s.serverTokenDigest(out.Token)] = record
		audit.PolicyEpoch = o.Epoch
		st.Audits = append(st.Audits, audit)
		return nil
	})
	if err != nil {
		return IssuedServerToken{}, err
	}
	return out, nil
}
func (s *Service) RevokeServerToken(ctx context.Context, actor Credential, org, id model.ID, reason string) error {
	if actor.service != s || !actor.Fresh() || reason == "" || len(reason) > 512 {
		return model.Fail(model.Forbidden)
	}
	audit := model.ControlAudit{ID: model.NewID(), Principal: actor.user, Action: "revoke_server_token", Reason: reason, Time: s.now().UnixNano(), Org: org.String(), Targets: []model.ID{id}, RequestID: model.RequestCorrelationID(ctx, model.ID{}), Outcome: model.AuditAllowed}
	return s.store.Update(ctx, func(st *model.ControlState) error {
		if err := s.validateCredentialState(*st, actor); err != nil {
			return err
		}
		o, ok := st.Orgs[org.String()]
		if !ok || !o.Admins[actor.user.String()] {
			return model.Fail(model.NotFound)
		}
		for hash, token := range st.ServerTokens {
			if token.ID == id && token.Org == org {
				token.Revoked = true
				st.ServerTokens[hash] = token
				audit.PolicyEpoch = o.Epoch
				st.Audits = append(st.Audits, audit)
				return nil
			}
		}
		return model.Fail(model.NotFound)
	})
}
func tokenAllows(st model.ControlState, c Credential, org model.ID, projects []model.ID, action Permission) bool {
	if !c.machine {
		return true
	}
	if c.service == nil {
		return false
	}
	token, ok := st.ServerTokens[c.service.serverTokenDigest(c.token)]
	if !ok || token.Revoked || token.Org != org {
		return false
	}
	allowed := false
	for _, v := range token.Permissions {
		if v == string(action) {
			allowed = true
		}
	}
	if !allowed {
		return false
	}
	for _, project := range projects {
		if !hasID(token.Projects, project) {
			return false
		}
	}
	return true
}
