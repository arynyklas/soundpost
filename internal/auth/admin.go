// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth

import (
	"context"
	"encoding/json"
	"soundpost/internal/model"
)

type AdminCommandRequest struct {
	CommandID        model.ID        `json:"command_id"`
	ExpectedRevision model.Revision  `json:"expected_revision"`
	OrgID            model.ID        `json:"org_id"`
	Kind             string          `json:"kind"`
	Payload          json.RawMessage `json:"payload"`
}
type AdminPayload struct {
	ID          model.ID        `json:"id"`
	UserID      model.ID        `json:"user_id"`
	ProjectID   model.ID        `json:"project_id"`
	Name        string          `json:"name"`
	Email       string          `json:"email"`
	Password    string          `json:"password"`
	Permissions []string        `json:"permissions"`
	Enabled     bool            `json:"enabled"`
	Secret      string          `json:"secret"`
	Reason      string          `json:"reason"`
	Config      json.RawMessage `json:"config"`
}
type AdminReadRequest struct {
	OrgID model.ID `json:"org_id"`
	Kind  string   `json:"kind"`
}
type AdminView struct {
	Revision      model.Revision             `json:"revision"`
	Organizations []OrgView                  `json:"organizations,omitempty"`
	Audits        []model.ControlAudit       `json:"audits,omitempty"`
	Settings      map[string]json.RawMessage `json:"settings,omitempty"`
}
type OrgView struct {
	ID       model.ID                     `json:"id"`
	Name     string                       `json:"name"`
	Projects map[string]string            `json:"projects,omitempty"`
	Members  map[string]bool              `json:"members,omitempty"`
	Admins   map[string]bool              `json:"admins,omitempty"`
	Grants   map[string][]string          `json:"grants,omitempty"`
	Teams    map[string]model.ControlTeam `json:"teams,omitempty"`
}

func (s *Service) AdminCommand(ctx context.Context, c Credential, r AdminCommandRequest) (model.ControlResult, error) {
	if c.service != s || !c.Fresh() {
		return model.ControlResult{}, model.Fail(model.Forbidden)
	}
	if _, e := s.Authenticate(ctx, c.token); e != nil {
		return model.ControlResult{}, e
	}
	var p AdminPayload
	if e := json.Unmarshal(r.Payload, &p); e != nil {
		return model.ControlResult{}, model.Fail(model.Invalid)
	}
	if p.Reason == "" || len(p.Reason) > 512 {
		return model.ControlResult{}, model.Fail(model.Invalid)
	}
	audit := model.ControlAudit{ID: model.NewID(), Principal: c.user, Action: r.Kind, Reason: p.Reason, Time: s.now().UnixNano(), Org: r.OrgID.String(), RequestID: model.RequestCorrelationID(ctx, r.CommandID), Outcome: model.AuditAllowed}
	var passwordHash string
	var e error
	if r.Kind == "create_user" {
		passwordHash, e = hashPassword(p.Password)
		if e != nil {
			return model.ControlResult{}, e
		}
		if !validEmail(p.Email) {
			return model.ControlResult{}, model.Fail(model.Invalid)
		}
	}
	var sealedSecret string
	if p.Secret != "" {
		sealedSecret, e = s.store.Seal(p.Secret)
		if e != nil {
			return model.ControlResult{}, model.Fail(model.Unavailable)
		}
	}
	var out model.ControlResult
	e = s.store.Update(ctx, func(st *model.ControlState) error {
		if err := s.validateCredentialState(*st, c); err != nil {
			return err
		}
		binding := c.user.String() + ":" + r.OrgID.String() + ":" + r.Kind
		if old, ok := st.Commands[r.CommandID.String()]; ok {
			if st.CommandOwners[r.CommandID.String()] != binding {
				return model.Fail(model.NotFound)
			}
			current := st.Users[c.user.String()]
			if current.Disabled {
				return model.Fail(model.Unauthenticated)
			}
			if r.Kind == "create_org" || r.Kind == "create_user" {
				if !current.Admin {
					return model.Fail(model.Forbidden)
				}
			} else if !st.Orgs[r.OrgID.String()].Admins[c.user.String()] {
				return model.Fail(model.NotFound)
			}
			out = old
			return nil
		}
		if r.CommandID == (model.ID{}) || r.ExpectedRevision != st.Revision {
			return model.Fail(model.Conflict)
		}
		o, exists := st.Orgs[r.OrgID.String()]
		if r.Kind == "create_org" || r.Kind == "create_user" {
			if !st.Users[c.user.String()].Admin {
				return model.Fail(model.Forbidden)
			}
		} else if !exists || !o.Admins[c.user.String()] {
			return model.Fail(model.NotFound)
		}
		if _, retired := st.RetiredOrgs[r.OrgID.String()]; retired && r.Kind != "create_user" {
			return model.Fail(model.NotFound) // retirement is permanent
		}
		switch r.Kind {
		case "create_org":
			if exists || r.OrgID == (model.ID{}) {
				return model.Fail(model.Conflict)
			}
			o = model.ControlOrg{ID: r.OrgID, Name: p.Name, Epoch: 1, Members: map[string]bool{}, Admins: map[string]bool{c.user.String(): true}, Projects: map[string]string{}, Grants: map[string][]string{}, Secrets: map[string]string{}, Settings: map[string]json.RawMessage{}}
		case "create_user":
			if p.ID == (model.ID{}) {
				return model.Fail(model.Invalid)
			}
			for _, u := range st.Users {
				if u.Email == p.Email {
					return model.Fail(model.Conflict)
				}
			}
			st.Users[p.ID.String()] = model.ControlUser{ID: p.ID, Email: p.Email, Password: passwordHash}
		case "create_project":
			if p.ID == (model.ID{}) {
				return model.Fail(model.Invalid)
			}
			if _, retired := st.RetiredProjects[r.OrgID.String()+":"+p.ID.String()]; retired {
				return model.Fail(model.Conflict) // a retired project ID is never reused
			}
			o.Projects[p.ID.String()] = p.Name
		case "membership":
			if _, ok := st.Users[p.UserID.String()]; !ok {
				return model.Fail(model.NotFound)
			}
			o.Members[p.UserID.String()] = p.Enabled
		case "org_admin":
			if _, ok := st.Users[p.UserID.String()]; !ok {
				return model.Fail(model.NotFound)
			}
			o.Admins[p.UserID.String()] = p.Enabled
		case "grant":
			if _, ok := o.Projects[p.ProjectID.String()]; !ok {
				return model.Fail(model.NotFound)
			}
			if !o.Members[p.UserID.String()] {
				return model.Fail(model.NotFound)
			}
			for _, v := range p.Permissions {
				if !validPermission(v) {
					return model.Fail(model.Invalid)
				}
			}
			if p.Enabled {
				o.Grants[p.UserID.String()+":"+p.ProjectID.String()] = append([]string(nil), p.Permissions...)
			} else {
				delete(o.Grants, p.UserID.String()+":"+p.ProjectID.String())
			}
		case "team", "source_policy", "sso", "destination", "retention":
			if p.ID == (model.ID{}) {
				return model.Fail(model.Invalid)
			}
			if len(p.Config) > 16384 {
				return model.Fail(model.TooLarge)
			}
			if err := validateAdminConfig(r.Kind, p, &o); err != nil {
				return err
			}
			o.Settings[r.Kind+":"+p.ID.String()] = append(json.RawMessage(nil), p.Config...)
			if r.Kind == "source_policy" {
				if src, active := st.Sources[p.ID.String()]; active {
					if src.Closing {
						return model.Fail(model.Stale)
					}
					var cfg SourcePolicyConfig
					if json.Unmarshal(p.Config, &cfg) != nil || cfg.ProjectID != src.Project || src.Org != r.OrgID {
						return model.Fail(model.Forbidden)
					}
					src.Closing = true
					src.Policy.Enabled = cfg.Enabled
					if src.Browser {
						narrowed := make([]string, 0, len(src.Origins))
						for _, origin := range src.Origins {
							for _, allowed := range cfg.Origins {
								if origin == allowed {
									narrowed = append(narrowed, origin)
									break
								}
							}
						}
						src.Origins = narrowed
					}
					src.Policy.Revision++
					if st.SourceFences == nil {
						st.SourceFences = map[string]model.SourceFence{}
					}
					st.SourceFences[p.ID.String()] = model.SourceFence{Operation: r.CommandID, Source: p.ID, Org: r.OrgID, Epoch: model.Uint64(o.Epoch + 1), Phase: "fencing"}
					if st.SourceOperations == nil {
						st.SourceOperations = map[string]model.SourceFence{}
					}
					st.SourceOperations[r.CommandID.String()] = st.SourceFences[p.ID.String()]
					st.Sources[p.ID.String()] = src
				}
			}
			if p.Secret != "" {
				o.Secrets[r.Kind+":"+p.ID.String()] = sealedSecret
			}
		default:
			return model.Fail(model.Invalid)
		}
		if r.Kind != "create_user" {
			o.Epoch++
			st.Orgs[r.OrgID.String()] = o
		}
		audit.PolicyEpoch = o.Epoch
		audit.Targets = []model.ID{r.OrgID}
		for _, target := range []model.ID{p.ID, p.UserID, p.ProjectID} {
			if target != (model.ID{}) {
				audit.Targets = append(audit.Targets, target)
			}
		}
		st.Audits = append(st.Audits, audit)
		out = model.ControlResult{Revision: st.Revision + 1, Cursor: model.Cursor{Group: st.Installation, Index: model.Uint64(st.Revision + 1)}}
		if r.Kind == "source_policy" {
			if f, ok := st.SourceFences[p.ID.String()]; ok && f.Operation == r.CommandID {
				out.Phase = f.Phase
				out.AffectedIDs = []model.ID{f.Operation}
			}
		}
		if st.CommandOwners == nil {
			st.CommandOwners = map[string]string{}
		}
		st.CommandOwners[r.CommandID.String()] = binding
		st.Commands[r.CommandID.String()] = out
		return nil
	})
	return out, e
}
func validPermission(v string) bool {
	switch v {
	case "telemetry.read", "telemetry.ingest", "raw.read", "artifacts.read", "artifacts.write", "replay.read", "profiles.read", "issues.write", "incidents.write", "rules.write", "policy.write":
		return true
	}
	return false
}
func (s *Service) AdminRead(ctx context.Context, c Credential, r AdminReadRequest) (AdminView, error) {
	if c.service != s || c.machine {
		return AdminView{}, model.Fail(model.Unauthenticated)
	}
	if _, err := s.Authenticate(ctx, c.token); err != nil {
		return AdminView{}, err
	}
	var out AdminView
	err := s.store.View(ctx, func(st model.ControlState) error {
		if err := s.validateCredentialState(st, c); err != nil {
			return err
		}
		out.Revision = st.Revision
		if r.Kind == "organizations" {
			for _, o := range st.Orgs {
				if o.Admins[c.user.String()] {
					out.Organizations = append(out.Organizations, OrgView{ID: o.ID, Name: o.Name})
				}
			}
			if len(out.Organizations) == 0 && !st.Users[c.user.String()].Admin {
				return model.Fail(model.Forbidden)
			}
			return nil
		}
		o, ok := st.Orgs[r.OrgID.String()]
		if !ok || !o.Admins[c.user.String()] {
			return model.Fail(model.NotFound)
		}
		switch r.Kind {
		case "organization":
			out.Organizations = []OrgView{{ID: o.ID, Name: o.Name, Projects: o.Projects, Members: o.Members, Admins: o.Admins, Grants: o.Grants, Teams: o.Teams}}
		case "audit":
			for _, a := range st.Audits {
				if a.Org == r.OrgID.String() {
					out.Audits = append(out.Audits, a)
				}
			}
		case "team", "source_policy", "sso", "destination", "retention":
			out.Settings = map[string]json.RawMessage{}
			for key, raw := range o.Settings {
				prefix := r.Kind + ":"
				if len(key) > len(prefix) && key[:len(prefix)] == prefix {
					out.Settings[key] = append(json.RawMessage(nil), raw...)
				}
			}
		default:
			return model.Fail(model.Invalid)
		}
		return nil
	})
	return out, err
}
