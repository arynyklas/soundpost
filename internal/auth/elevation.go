// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth

import (
	"context"
	"encoding/json"
	"soundpost/internal/model"
	"time"
)

type Elevation struct {
	service    *Service
	credential Credential
	orgs       []model.ID
	audit      model.ID
	expires    time.Time
}
type elevationRecord struct {
	User        model.ID
	SessionHash string
	Orgs        []model.ID
	Audit       model.ID
	Expires     int64
}

func (e Elevation) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		ID      model.ID    `json:"id"`
		Expires model.Int64 `json:"expires"`
	}{e.audit, model.Int64(e.expires.Unix())})
}
func (s *Service) Elevate(ctx context.Context, session Session, reason string, orgs []model.ID) (Elevation, error) {
	c, err := s.Authenticate(ctx, session.Token)
	if err != nil {
		return Elevation{}, err
	}
	if !c.admin || !c.Fresh() || reason == "" || len(reason) > 512 || len(orgs) == 0 {
		return Elevation{}, model.Fail(model.Forbidden)
	}
	a := model.ControlAudit{ID: model.NewID(), Principal: c.user, Action: "elevate", Reason: reason, Time: s.now().UnixNano(), Targets: append([]model.ID(nil), orgs...), RequestID: model.RequestCorrelationID(ctx, model.ID{}), Outcome: model.AuditAllowed}
	expires := s.now().Add(15 * time.Minute)
	record, _ := json.Marshal(elevationRecord{c.user, hashToken(c.token), append([]model.ID(nil), orgs...), a.ID, expires.Unix()})
	err = s.store.Update(ctx, func(st *model.ControlState) error {
		if err := s.validateCredentialState(*st, c); err != nil {
			return err
		}
		if !st.Users[c.user.String()].Admin {
			return model.Fail(model.Forbidden)
		}
		for _, org := range orgs {
			if _, ok := st.Orgs[org.String()]; !ok {
				return model.Fail(model.NotFound)
			}
		}
		st.Audits = append(st.Audits, a)
		st.OIDC["elevation:"+a.ID.String()] = record
		return nil
	})
	if err != nil {
		return Elevation{}, err
	}
	return Elevation{s, c, append([]model.ID(nil), orgs...), a.ID, expires}, nil
}
func (s *Service) ResolveElevation(ctx context.Context, c Credential, id model.ID) (Elevation, error) {
	if c.service != s {
		return Elevation{}, model.Fail(model.Unauthenticated)
	}
	if _, err := s.Authenticate(ctx, c.token); err != nil {
		return Elevation{}, err
	}
	var out Elevation
	err := s.store.View(ctx, func(st model.ControlState) error {
		var r elevationRecord
		if err := json.Unmarshal(st.OIDC["elevation:"+id.String()], &r); err != nil {
			return model.Fail(model.NotFound)
		}
		if r.User != c.user || r.SessionHash != hashToken(c.token) || r.Expires <= s.now().Unix() {
			return model.Fail(model.Forbidden)
		}
		out = Elevation{s, c, append([]model.ID(nil), r.Orgs...), r.Audit, time.Unix(r.Expires, 0)}
		return nil
	})
	return out, err
}
func (s *Service) ElevatedScope(ctx context.Context, e Elevation, org model.ID, projects []model.ID, action Permission) (Scope, error) {
	if e.service != s || !s.now().Before(e.expires) {
		return Scope{}, model.Fail(model.Forbidden)
	}
	if _, err := s.Authenticate(ctx, e.credential.token); err != nil {
		return Scope{}, err
	}
	found := false
	for _, v := range e.orgs {
		if v == org {
			found = true
		}
	}
	if !found {
		return Scope{}, model.Fail(model.NotFound)
	}
	checkedAt := s.now()
	out := Scope{service: s, credential: e.credential, org: org, projects: append([]model.ID(nil), projects...), action: action, elevation: e.audit, lease: &scopeLease{}, elevationExpires: e.expires}
	a := model.ControlAudit{ID: model.NewID(), Principal: e.credential.user, Action: "elevated_read", Reason: "selected organization read", Time: s.now().UnixNano(), Org: org.String(), RequestID: model.RequestCorrelationID(ctx, model.ID{}), Outcome: model.AuditAllowed}
	err := s.store.Update(ctx, func(st *model.ControlState) error {
		if err := s.validateCredentialState(*st, e.credential); err != nil {
			return err
		}
		o, ok := st.Orgs[org.String()]
		if !ok {
			return model.Fail(model.NotFound)
		}
		for _, p := range projects {
			if _, ok := o.Projects[p.String()]; !ok {
				return model.Fail(model.NotFound)
			}
		}
		out.epoch = o.Epoch
		a.PolicyEpoch = o.Epoch
		a.Targets = append([]model.ID{org}, projects...)
		projectKeys := make([]string, len(projects))
		for i, project := range projects {
			projectKeys[i] = project.String()
		}
		out.fingerprint = hashToken(e.credential.user.String() + org.String() + e.audit.String() + string(action) + joinSorted(projectKeys))
		st.Audits = append(st.Audits, a)
		return s.grantLease(out, *st, checkedAt)
	})
	if err != nil {
		return Scope{}, err
	}
	return out, nil
}
