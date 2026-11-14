// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/arynyklas/soundpost/internal/model"
)

type SourcePolicyChange struct {
	CommandID        model.ID           `json:"command_id"`
	Source           model.ID           `json:"source"`
	ExpectedRevision model.Revision     `json:"expected_revision"`
	Policy           model.SourcePolicy `json:"policy"`
	Reason           string             `json:"reason"`
}

func (s *Service) ChangeSourcePolicy(ctx context.Context, c Credential, r SourcePolicyChange) (model.SourceFence, error) {
	if c.service != s || c.machine || !c.Fresh() || r.CommandID == (model.ID{}) || r.Reason == "" || len(r.Reason) > 512 {
		return model.SourceFence{}, model.Fail(model.Forbidden)
	}
	if err := model.ValidateSourcePolicy(r.Policy); err != nil {
		return model.SourceFence{}, err
	}
	audit := model.NewID()
	admittedAt := s.now().UnixNano()
	var out model.SourceFence
	err := s.store.Update(ctx, func(st *model.ControlState) error {
		if err := s.validateCredentialState(*st, c); err != nil {
			return err
		}
		src, ok := st.Sources[r.Source.String()]
		org := st.Orgs[src.Org.String()]
		if !ok || !org.Admins[c.user.String()] {
			return model.Fail(model.NotFound)
		}
		binding := c.user.String() + ":" + src.Org.String() + ":source.policy"
		if _, exists := st.Commands[r.CommandID.String()]; exists {
			if st.CommandOwners[r.CommandID.String()] != binding {
				return model.Fail(model.NotFound)
			}
			old, ok := st.SourceOperations[r.CommandID.String()]
			if !ok || old.Source != r.Source {
				return model.Fail(model.NotFound)
			}
			out = old
			return nil
		}
		if src.Revoked || src.Retired || src.Closing {
			return model.Fail(model.Stale)
		}
		var cfg SourcePolicyConfig
		if json.Unmarshal(org.Settings["source_policy:"+src.ID.String()], &cfg) != nil || cfg.ProjectID != src.Project || r.Policy.Enabled && !cfg.Enabled || r.Policy.Class != src.Policy.Class {
			return model.Fail(model.Forbidden)
		}
		if r.Policy.Class == "restricted_raw" && (len(cfg.Readers) == 0 || r.Policy.RawOwner == nil || !org.Members[r.Policy.RawOwner.String()] && !org.Admins[r.Policy.RawOwner.String()] || int64(r.Policy.Expires) <= admittedAt || r.Policy.Expires > src.Expires) {
			return model.Fail(model.Forbidden)
		}
		if r.ExpectedRevision != src.Policy.Revision || r.Policy.Revision != src.Policy.Revision+1 {
			return model.Fail(model.Conflict)
		}
		// An immutable template revision can never be silently rewritten or removed.
		for _, old := range src.Policy.Templates {
			found := false
			for _, next := range r.Policy.Templates {
				if old.ID == next.ID && old.Revision == next.Revision {
					a, _ := model.CanonicalJSON(old)
					b, _ := model.CanonicalJSON(next)
					if !bytes.Equal(a, b) {
						return model.Fail(model.Conflict)
					}
					found = true
				}
			}
			if !found {
				return model.Fail(model.Conflict)
			}
		}
		src.Policy = r.Policy
		src.Closing = true
		st.Sources[r.Source.String()] = src
		org.Epoch++
		st.Orgs[src.Org.String()] = org
		out = model.SourceFence{Operation: r.CommandID, Source: r.Source, Org: src.Org, Epoch: model.Uint64(org.Epoch), Phase: "fencing"}
		if st.SourceFences == nil {
			st.SourceFences = map[string]model.SourceFence{}
		}
		st.SourceFences[r.Source.String()] = out
		if st.SourceOperations == nil {
			st.SourceOperations = map[string]model.SourceFence{}
		}
		st.SourceOperations[r.CommandID.String()] = out
		if st.CommandOwners == nil {
			st.CommandOwners = map[string]string{}
		}
		st.CommandOwners[r.CommandID.String()] = binding
		st.Commands[r.CommandID.String()] = model.ControlResult{Revision: st.Revision + 1, Cursor: model.Cursor{Group: st.Installation, Index: model.Uint64(st.Revision + 1)}, AffectedIDs: []model.ID{r.CommandID}, Phase: "fencing"}
		st.Audits = append(st.Audits, model.ControlAudit{ID: audit, Principal: c.user, Org: src.Org.String(), Action: "source.policy", Reason: r.Reason, Time: admittedAt, PolicyEpoch: org.Epoch, Targets: []model.ID{src.Project, src.ID, r.CommandID}, RequestID: model.RequestCorrelationID(ctx, r.CommandID), Outcome: model.AuditAllowed})
		return nil
	})
	return out, err
}
