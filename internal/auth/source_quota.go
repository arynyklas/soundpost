// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth

import (
	"context"
	"soundpost/internal/model"
)

type AdmissionQuotaChange struct {
	CommandID        model.ID       `json:"command_id"`
	ExpectedRevision model.Revision `json:"expected_revision"`
	Org              model.ID       `json:"org"`
	Project          *model.ID      `json:"project,omitempty"`
	MaxBytes         model.Uint64   `json:"max_bytes"`
	MaxSeries        model.Uint64   `json:"max_series"`
	Reason           string         `json:"reason"`
}

func (s *Service) SetAdmissionQuota(ctx context.Context, c Credential, r AdmissionQuotaChange) (model.ControlResult, error) {
	if c.service != s || c.machine || !c.Fresh() || r.CommandID == (model.ID{}) || r.MaxBytes == 0 || r.MaxSeries == 0 || r.Reason == "" || len(r.Reason) > 512 {
		return model.ControlResult{}, model.Fail(model.Forbidden)
	}
	audit, at := model.NewID(), s.now().UnixNano()
	var out model.ControlResult
	e := s.store.Update(ctx, func(st *model.ControlState) error {
		if e := s.validateCredentialState(*st, c); e != nil {
			return e
		}
		org, ok := st.Orgs[r.Org.String()]
		if !ok || !org.Admins[c.user.String()] {
			return model.Fail(model.NotFound)
		}
		binding := c.user.String() + ":" + r.Org.String() + ":admission.quota"
		if old, ok := st.Commands[r.CommandID.String()]; ok {
			if st.CommandOwners[r.CommandID.String()] != binding {
				return model.Fail(model.NotFound)
			}
			out = old
			return nil
		}
		if st.Revision != r.ExpectedRevision {
			return model.Fail(model.Conflict)
		}
		key := "org:" + r.Org.String()
		targets := []model.ID{r.Org}
		if r.Project != nil {
			if _, ok := org.Projects[r.Project.String()]; !ok {
				return model.Fail(model.NotFound)
			}
			key = "project:" + r.Org.String() + ":" + r.Project.String()
			targets = append(targets, *r.Project)
		}
		if st.Quotas == nil {
			st.Quotas = map[string]model.QuotaState{}
		}
		q := st.Quotas[key]
		q.MaxBytes = r.MaxBytes
		q.MaxSeries = r.MaxSeries
		q.Configured = true
		st.Quotas[key] = q
		st.Audits = append(st.Audits, model.ControlAudit{ID: audit, Principal: c.user, Org: r.Org.String(), Action: "admission.quota", Reason: r.Reason, Time: at, PolicyEpoch: org.Epoch, Targets: targets, RequestID: model.RequestCorrelationID(ctx, r.CommandID), Outcome: model.AuditAllowed})
		out = model.ControlResult{Revision: st.Revision + 1, Cursor: model.Cursor{Group: st.Installation, Index: model.Uint64(st.Revision + 1)}, AffectedIDs: targets}
		if st.CommandOwners == nil {
			st.CommandOwners = map[string]string{}
		}
		st.CommandOwners[r.CommandID.String()] = binding
		st.Commands[r.CommandID.String()] = out
		return nil
	})
	return out, e
}
