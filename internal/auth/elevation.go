// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/arynyklas/soundpost/internal/model"
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
	if err := s.throttle.credentialCheck(&s.throttle.elevStart, "elevation-start", c.token); err != nil {
		return Elevation{}, err
	}
	s.throttle.credentialRecord(&s.throttle.elevStart, "elevation-start", c.token)
	if !c.admin || !c.Fresh() || reason == "" || len(reason) > 512 || len(orgs) == 0 {
		return Elevation{}, model.Fail(model.Forbidden)
	}
	a := model.ControlAudit{ID: model.NewID(), Principal: c.user, Action: "elevate", Reason: reason, Time: s.now().UnixNano(), Targets: append([]model.ID(nil), orgs...), RequestID: model.RequestCorrelationID(ctx, model.ID{}), Outcome: model.AuditAllowed}
	expires := s.now().Add(15 * time.Minute)
	record, _ := json.Marshal(elevationRecord{c.user, hashToken(c.token), append([]model.ID(nil), orgs...), a.ID, expires.Unix()})
	// AuthorityRevision: this write MUST bump (it is the unclassified Update on purpose, and
	// TestElevateBumpsAuthorityRevision pins it). The elevation record it stores is an access
	// grant, not bookkeeping: ResolveElevation rebuilds the Elevation (the organizations an
	// administrator's session may read across tenants, for 15 minutes) from exactly this record,
	// so committing it widens who may read which organization's data. A retention command whose
	// caller view predates it would have been decided without it; the revision it carries must
	// therefore not be accepted as "no older than the last authority change". The audit row
	// beside it would not bump on its own (see ElevatedScope), the record does.
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
	if err := s.throttle.credentialCheck(&s.throttle.elevRead, "elevation-read", c.token); err != nil {
		return Elevation{}, err
	}
	var out Elevation
	err := s.store.View(ctx, func(st model.ControlState) error {
		var r elevationRecord
		if err := json.Unmarshal(st.OIDC["elevation:"+id.String()], &r); err != nil {
			return model.Fail(model.NotFound)
		}
		// Unknown, another principal's/session's and expired elevations are one
		// NotFound: the reply never reveals whether an ID exists.
		if r.User != c.user || r.SessionHash != hashToken(c.token) || r.Expires <= s.now().Unix() {
			return model.Fail(model.NotFound)
		}
		out = Elevation{s, c, append([]model.ID(nil), r.Orgs...), r.Audit, time.Unix(r.Expires, 0)}
		return nil
	})
	var fault *model.Fault
	if errors.As(err, &fault) && fault.Code == model.NotFound {
		s.throttle.credentialRecord(&s.throttle.elevRead, "elevation-read", c.token)
	}
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
	err := s.updateAuditAppend(ctx, func(st *model.ControlState) error {
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
		out.fingerprint = hashToken(e.credential.user.String() + org.String() + e.audit.String() + string(action) + joinSorted(projectKeys) + "|session:" + hashToken(e.credential.token))
		st.Audits = append(st.Audits, a)
		return s.grantLease(out, *st, checkedAt)
	})
	if err != nil {
		return Scope{}, err
	}
	return out, nil
}

// auditAppender is implemented by *control.Store: the commit that only appends audit rows and does
// not move the control AuthorityRevision. The elevated_read audit of ElevatedScope is such a
// write: it validates the credential, reads the organization and projects, and appends one audit
// row; the scope it releases is not stored. No access decision reads the audit log back. A
// ControlStore without it falls back to Update.
//
// A type that embeds the store and overrides Update (a test double that counts or fails commits)
// has the method promoted unchanged, and a service that preferred it would skip the override:
// SharesUpdateOf says whether the service's ControlStore is the store itself, and only then is the
// optional method used (the rule of SharedViewer, service.go).
type auditAppender interface {
	UpdateAuditAppend(ctx context.Context, fn func(*model.ControlState) error) error
	SharesUpdateOf(ControlStore) bool
}

// auditDeltaAppender is implemented by *control.Store: the commit of one audit row that checks the
// committed state through the read-only interface and, once every member of the replica group
// supports it, replicates the row alone instead of the whole next state (control.Store.AppendAudit).
// Same wrapper rule as auditAppender.
type auditDeltaAppender interface {
	AppendAudit(ctx context.Context, check func(model.ReadOnlyControl) error, a model.ControlAudit) error
	SharesUpdateOf(ControlStore) bool
}

func (s *Service) updateAuditAppend(ctx context.Context, fn func(*model.ControlState) error) error {
	if u, ok := s.store.(auditAppender); ok && u.SharesUpdateOf(s.store) {
		return u.UpdateAuditAppend(ctx, fn)
	}
	return s.store.Update(ctx, fn)
}
