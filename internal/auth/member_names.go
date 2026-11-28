// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/arynyklas/soundpost/internal/model"
)

// This file is the directory of the console (docs/operations/console-api.md, section 3): who the
// members and projects of an organization are called, for the people allowed to see them. A member's
// display name is the organization setting member_name:<user>; a project's name is the one the
// organization already stores. Nothing here reads or returns a credential, a grant list or (for a
// plain member) an e-mail address.

const (
	memberNameKeyPrefix = "member_name:"
	// MaxMemberNameBytes bounds a display name.
	MaxMemberNameBytes = 80
	// MaxDirectoryProjects bounds the optional project filter of a directory read.
	MaxDirectoryProjects = 200
	memberNameAction     = "member_name"
)

// MemberNameSettingKey is the organization setting that holds a member's display name.
func MemberNameSettingKey(user model.ID) string { return memberNameKeyPrefix + user.String() }

type memberNameRecord struct {
	DisplayName string `json:"display_name"`
}

// DirectoryRequest selects a directory read. Projects, when present, narrows the project list to
// those of the named projects the caller may see; it never widens it.
type DirectoryRequest struct {
	Org      model.ID   `json:"org"`
	Projects []model.ID `json:"projects,omitempty"`
}

// DirectoryProject is one visible project.
type DirectoryProject struct {
	ID   model.ID `json:"id"`
	Name string   `json:"name"`
}

// DirectoryMember is one visible member. Email, Admin and Enabled are present only in an
// organization administrator's answer.
type DirectoryMember struct {
	ID          model.ID `json:"id"`
	DisplayName string   `json:"display_name,omitempty"`
	Email       string   `json:"email,omitempty"`
	Admin       *bool    `json:"admin,omitempty"`
	Enabled     *bool    `json:"enabled,omitempty"`
}

// DirectoryView is the answer of Directory.
type DirectoryView struct {
	Org         model.ID           `json:"org"`
	OrgName     string             `json:"org_name,omitempty"`
	Projects    []DirectoryProject `json:"projects"`
	Members     []DirectoryMember  `json:"members"`
	CanSetNames bool               `json:"can_set_names"`
}

// MemberNameCommand sets (a non-empty name) or clears ("") one member's display name.
type MemberNameCommand struct {
	CommandID   model.ID `json:"command_id"`
	Org         model.ID `json:"org"`
	User        model.ID `json:"user"`
	DisplayName string   `json:"display_name"`
}

// ValidMemberName reports whether name is storable: 1..MaxMemberNameBytes bytes of valid UTF-8 with
// no control character, no leading or trailing space.
func ValidMemberName(name string) bool {
	if name == "" || len(name) > MaxMemberNameBytes || !utf8.ValidString(name) || strings.TrimSpace(name) != name {
		return false
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func memberNameOf(o model.ControlOrg, user string) string {
	raw, ok := o.Settings[memberNameKeyPrefix+user]
	if !ok {
		return ""
	}
	var rec memberNameRecord
	if json.Unmarshal(raw, &rec) != nil || !ValidMemberName(rec.DisplayName) {
		return ""
	}
	return rec.DisplayName
}

// Directory answers the projects and members of org the caller may see. A server token is not a
// console principal and is refused. Not a member (or a member whose membership is disabled), a
// retired or unknown organization are the same not-found.
func (s *Service) Directory(ctx context.Context, c Credential, r DirectoryRequest) (DirectoryView, error) {
	if c.service != s || c.machine {
		return DirectoryView{}, model.Fail(model.Forbidden)
	}
	if r.Org == (model.ID{}) || len(r.Projects) > MaxDirectoryProjects {
		return DirectoryView{}, model.Fail(model.Invalid)
	}
	for i, p := range r.Projects {
		if p == (model.ID{}) || slices.Contains(r.Projects[:i], p) {
			return DirectoryView{}, model.Fail(model.Invalid)
		}
	}
	var out DirectoryView
	err := s.store.View(ctx, func(st model.ControlState) error {
		if err := s.validateCredentialState(st, c); err != nil {
			return err
		}
		if _, retired := st.RetiredOrgs[r.Org.String()]; retired {
			return model.Fail(model.NotFound)
		}
		o, ok := st.Orgs[r.Org.String()]
		if !ok {
			return model.Fail(model.NotFound)
		}
		me := c.user.String()
		admin := o.Admins[me]
		if !admin && !o.Members[me] {
			return model.Fail(model.NotFound)
		}
		out = directoryOf(st, o, c.user, admin, r.Projects)
		return nil
	})
	return out, err
}

// splitGrantKey splits a grant row key (user:project).
func splitGrantKey(key string) (user, project string, ok bool) {
	user, project, ok = strings.Cut(key, ":")
	return user, project, ok && user != "" && project != ""
}

func directoryOf(st model.ControlState, o model.ControlOrg, caller model.ID, admin bool, filter []model.ID) DirectoryView {
	me := caller.String()
	visible := map[string]bool{}
	if admin {
		for p := range o.Projects {
			visible[p] = true
		}
	} else {
		for key, perms := range o.Grants {
			if u, p, ok := splitGrantKey(key); ok && u == me && len(perms) > 0 {
				if _, live := o.Projects[p]; live {
					visible[p] = true
				}
			}
		}
		for _, team := range o.Teams {
			if !team.Enabled || len(team.Permissions) == 0 || !hasID(team.Members, caller) {
				continue
			}
			for _, p := range team.Projects {
				if _, live := o.Projects[p.String()]; live {
					visible[p.String()] = true
				}
			}
		}
	}
	out := DirectoryView{Org: o.ID, OrgName: o.Name, Projects: []DirectoryProject{}, Members: []DirectoryMember{}, CanSetNames: true}
	for p := range visible {
		id, err := model.ParseID(p)
		if err != nil || len(filter) > 0 && !hasID(filter, id) {
			continue
		}
		out.Projects = append(out.Projects, DirectoryProject{ID: id, Name: o.Projects[p]})
	}
	slices.SortFunc(out.Projects, func(a, b DirectoryProject) int { return slices.Compare(a.ID[:], b.ID[:]) })

	users := map[string]bool{}
	if admin {
		for u := range o.Members {
			users[u] = true
		}
		for u, on := range o.Admins {
			if on {
				users[u] = true
			}
		}
	} else {
		users[me] = true
		for u, on := range o.Admins {
			if on {
				users[u] = true
			}
		}
		for key, perms := range o.Grants {
			if u, p, ok := splitGrantKey(key); ok && visible[p] && len(perms) > 0 && o.Members[u] {
				users[u] = true
			}
		}
		for _, team := range o.Teams {
			if !team.Enabled || len(team.Permissions) == 0 {
				continue
			}
			for _, p := range team.Projects {
				if !visible[p.String()] {
					continue
				}
				for _, u := range team.Members {
					if o.Members[u.String()] {
						users[u.String()] = true
					}
				}
			}
		}
	}
	for u := range users {
		id, err := model.ParseID(u)
		if err != nil {
			continue
		}
		rec, exists := st.Users[u]
		if !exists || !admin && rec.Disabled {
			continue
		}
		m := DirectoryMember{ID: id, DisplayName: memberNameOf(o, u)}
		if admin {
			isAdmin, enabled := o.Admins[u], (o.Members[u] || o.Admins[u]) && !rec.Disabled
			m.Email, m.Admin, m.Enabled = rec.Email, &isAdmin, &enabled
		}
		out.Members = append(out.Members, m)
	}
	slices.SortFunc(out.Members, func(a, b DirectoryMember) int { return slices.Compare(a.ID[:], b.ID[:]) })
	return out
}

// memberNameAllowed is the authority of a display-name command over target: an organization
// administrator names any member or administrator of the organization, a member only itself. A
// stranger, and a target the organization does not know, are the same not-found.
func memberNameAllowed(o model.ControlOrg, caller, target model.ID) error {
	t := target.String()
	_, member := o.Members[t]
	if !member && !o.Admins[t] {
		return model.Fail(model.NotFound)
	}
	switch {
	case o.Admins[caller.String()]:
		return nil
	case !o.Members[caller.String()]:
		return model.Fail(model.NotFound)
	case caller == target:
		return nil
	}
	return model.Fail(model.Forbidden)
}

// payloadDigest is the identity of a command's content: a replay of a command ID with other content
// is a conflict, never the first command's result.
func payloadDigest(parts ...string) model.ID {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	var id model.ID
	copy(id[:], h.Sum(nil))
	return id
}

// SetMemberName commits one display-name change. It is the admin command transition (command-ID
// binding, audit, per-object epoch) for a setting a member may also change for itself. The audit
// names the member and never carries the text.
func (s *Service) SetMemberName(ctx context.Context, c Credential, cmd MemberNameCommand) (model.ControlResult, error) {
	if c.service != s || c.machine {
		return model.ControlResult{}, model.Fail(model.Forbidden)
	}
	if cmd.CommandID == (model.ID{}) || cmd.Org == (model.ID{}) || cmd.User == (model.ID{}) {
		return model.ControlResult{}, model.Fail(model.Invalid)
	}
	if cmd.DisplayName != "" && !ValidMemberName(cmd.DisplayName) {
		return model.ControlResult{}, model.Fail(model.Invalid)
	}
	digest := payloadDigest(memberNameAction, cmd.User.String(), cmd.DisplayName)
	req := AdminCommandRequest{CommandID: cmd.CommandID, OrgID: cmd.Org, Kind: memberNameAction}
	var out model.ControlResult
	err := s.updateAdmin(ctx, req, func(st *model.ControlState) error {
		if err := s.validateCredentialState(*st, c); err != nil {
			return err
		}
		if _, retired := st.RetiredOrgs[cmd.Org.String()]; retired {
			return model.Fail(model.NotFound)
		}
		o, ok := st.Orgs[cmd.Org.String()]
		if !ok {
			return model.Fail(model.NotFound)
		}
		binding := c.user.String() + ":" + cmd.Org.String() + ":" + memberNameAction
		if old, replay := st.Commands[cmd.CommandID.String()]; replay {
			if st.CommandOwners[cmd.CommandID.String()] != binding {
				return model.Fail(model.NotFound)
			}
			if err := memberNameAllowed(o, c.user, cmd.User); err != nil {
				return err
			}
			if len(old.AffectedIDs) != 2 || old.AffectedIDs[1] != digest {
				return model.Fail(model.Conflict)
			}
			out = old
			return nil
		}
		if err := memberNameAllowed(o, c.user, cmd.User); err != nil {
			return err
		}
		if o.Settings == nil {
			o.Settings = map[string]json.RawMessage{}
		}
		key := MemberNameSettingKey(cmd.User)
		if cmd.DisplayName == "" {
			delete(o.Settings, key)
		} else {
			raw, _ := json.Marshal(memberNameRecord{DisplayName: cmd.DisplayName})
			o.Settings[key] = raw
		}
		o.TrackChange(key)
		st.Orgs[cmd.Org.String()] = o
		st.Audits = append(st.Audits, model.ControlAudit{ID: cmd.CommandID, Principal: c.user, Action: memberNameAction, Reason: "member display name changed", Time: s.now().UnixNano(), Org: cmd.Org.String(), PolicyEpoch: o.Epoch, Targets: []model.ID{cmd.Org, cmd.User}, RequestID: model.RequestCorrelationID(ctx, cmd.CommandID), Outcome: model.AuditAllowed})
		out = model.ControlResult{Revision: st.Revision + 1, Cursor: model.Cursor{Group: st.Installation, Index: model.Uint64(st.Revision + 1)}, AffectedIDs: []model.ID{cmd.User, digest}}
		if st.CommandOwners == nil {
			st.CommandOwners = map[string]string{}
		}
		if st.Commands == nil {
			st.Commands = map[string]model.ControlResult{}
		}
		st.CommandOwners[cmd.CommandID.String()] = binding
		st.Commands[cmd.CommandID.String()] = out
		return nil
	})
	return out, err
}
