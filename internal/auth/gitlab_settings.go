// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/arynyklas/soundpost/internal/model"
)

// This file is the audited write path of an organization's GitLab connection
// (docs/operations/console-api.md section 10). It is the admin command transition
// (updateAdmin, command-ID binding, object-epoch compare, audit, write-only sealed
// secret) as a new kind, "gitlab": an organization administrator saves or
// disconnects the connection, and a token check records what GitLab said about the
// token (scopes, expiry). The token is sealed in Secrets["gitlab:connection"] and
// never leaves the control state: not in a view, an audit, an error or a log.

// Keys of the connection in the organization.
const (
	// GitLabSettingKey is the organization setting holding the connection JSON.
	GitLabSettingKey = "gitlab:connection"
	// GitLabSecretKey is the organization secret holding the sealed token.
	GitLabSecretKey = "gitlab:connection"

	gitlabKind          = "gitlab"
	gitlabTokenCheckKey = "gitlab:token_check"
	maxGitLabMappings   = 64
	maxGitLabLabels     = 10
)

// GitLab command operations.
const (
	GitLabSave       = "save"
	GitLabDisconnect = "disconnect"
	GitLabTokenCheck = "token_check"
)

// GitLabMapping maps one Soundpost project to the GitLab project its issues are
// created in.
type GitLabMapping struct {
	ProjectID     model.ID `json:"project_id"`
	GitLabProject string   `json:"gitlab_project"`
	CreateFrom    []string `json:"create_from"`
	Labels        []string `json:"labels"`
}

// GitLabTokenMeta is what the last token check said. It carries no secret.
type GitLabTokenMeta struct {
	ExpiresAt string   `json:"expires_at,omitempty"`
	Scopes    []string `json:"scopes,omitempty"`
}

// GitLabConnection is the stored (non-secret) connection.
type GitLabConnection struct {
	BaseURL  string          `json:"base_url"`
	Mappings []GitLabMapping `json:"mappings"`
	Token    GitLabTokenMeta `json:"token"`
}

// GitLabConnectionInput is the connection a save carries. An empty Token keeps the
// stored one.
type GitLabConnectionInput struct {
	BaseURL  string          `json:"base_url"`
	Token    string          `json:"token,omitempty"`
	Mappings []GitLabMapping `json:"mappings"`
}

// GitLabCommandRequest is one GitLab settings command. ExpectedEpoch is the
// organization policy epoch the caller read (GitLabView.Epoch): the command is
// refused as a conflict when the connection changed since.
type GitLabCommandRequest struct {
	CommandID     model.ID
	OrgID         model.ID
	ExpectedEpoch model.Uint64
	Op            string
	Reason        string
	// Connection is the connection of a save.
	Connection *GitLabConnectionInput
	// Token is the result of a token check.
	Token *GitLabTokenMeta
}

// GitLabView is the redacted connection a member reads.
type GitLabView struct {
	Epoch     model.Uint64
	Admin     bool
	HasToken  bool
	Connected bool
	// Connection is nil when none is set; its mappings are only the projects the
	// reader can see.
	Connection *GitLabConnection
}

func gitlabCode(code model.Code, detail string) error {
	f := model.Fail(code)
	f.SafeDetail = detail
	return f
}

func validGitLabBaseURL(raw string) (string, bool) {
	if raw == "" || len(raw) > 256 || strings.ContainsAny(raw, " \t\r\n\\") {
		return "", false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return "", false
	}
	path := strings.TrimRight(u.EscapedPath(), "/")
	for i := range len(path) {
		c := path[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '/' || c == '-' || c == '_' || c == '.') {
			return "", false
		}
	}
	if strings.Contains(path, "..") || strings.Contains(path, "//") {
		return "", false
	}
	return "https://" + u.Host + path, true
}

func validGitLabToken(t string) bool {
	if len(t) < 8 || len(t) > 512 {
		return false
	}
	for i := range len(t) {
		if t[i] <= ' ' || t[i] >= 0x7f {
			return false
		}
	}
	return true
}

func validGitLabProjectPath(s string) bool {
	if s == "" || len(s) > 200 || strings.Contains(s, "//") || strings.HasPrefix(s, "/") || strings.HasSuffix(s, "/") {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == '-' || c == '/') {
			return false
		}
	}
	return true
}

func validGitLabLabel(l string) bool {
	if l == "" || len(l) > 50 || !utf8.ValidString(l) || strings.ContainsRune(l, ',') || strings.TrimSpace(l) == "" {
		return false
	}
	for _, r := range l {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// validateGitLabMappings checks the mappings against the organization's projects
// and returns them in a canonical form (every list non-nil).
func validateGitLabMappings(o model.ControlOrg, in []GitLabMapping) ([]GitLabMapping, error) {
	if len(in) > maxGitLabMappings {
		return nil, gitlabCode(model.Invalid, "gitlab_mappings_invalid")
	}
	out := make([]GitLabMapping, 0, len(in))
	seen := map[model.ID]bool{}
	for _, m := range in {
		if _, ok := o.Projects[m.ProjectID.String()]; !ok || m.ProjectID == (model.ID{}) || seen[m.ProjectID] {
			return nil, gitlabCode(model.Invalid, "gitlab_mappings_invalid")
		}
		seen[m.ProjectID] = true
		if !validGitLabProjectPath(m.GitLabProject) || len(m.CreateFrom) == 0 || len(m.CreateFrom) > 2 || len(m.Labels) > maxGitLabLabels {
			return nil, gitlabCode(model.Invalid, "gitlab_mappings_invalid")
		}
		from := make([]string, 0, 2)
		for _, k := range m.CreateFrom {
			if k != "incident" && k != "issue" || containsString(from, k) {
				return nil, gitlabCode(model.Invalid, "gitlab_mappings_invalid")
			}
			from = append(from, k)
		}
		labels := make([]string, 0, len(m.Labels))
		for _, l := range m.Labels {
			if !validGitLabLabel(l) {
				return nil, gitlabCode(model.Invalid, "gitlab_mappings_invalid")
			}
			labels = append(labels, l)
		}
		out = append(out, GitLabMapping{ProjectID: m.ProjectID, GitLabProject: m.GitLabProject, CreateFrom: from, Labels: labels})
	}
	return out, nil
}

func containsString(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

func validGitLabTokenMeta(m GitLabTokenMeta) bool {
	if len(m.Scopes) > 16 || m.ExpiresAt != "" && (len(m.ExpiresAt) != 10 || m.ExpiresAt[4] != '-' || m.ExpiresAt[7] != '-') {
		return false
	}
	for _, c := range m.ExpiresAt {
		if c != '-' && (c < '0' || c > '9') {
			return false
		}
	}
	for _, s := range m.Scopes {
		if s == "" || len(s) > 40 {
			return false
		}
		for i := range len(s) {
			if !(s[i] >= 'a' && s[i] <= 'z' || s[i] == '_') {
				return false
			}
		}
	}
	return true
}

// ParseGitLabConnection reads the stored connection of an organization. found is
// false when none is stored; sealed is the sealed token ("" when none).
func ParseGitLabConnection(o model.ControlOrg) (conn GitLabConnection, sealed string, found bool, err error) {
	raw, ok := o.Settings[GitLabSettingKey]
	if !ok {
		return GitLabConnection{}, "", false, nil
	}
	if json.Unmarshal(raw, &conn) != nil {
		return GitLabConnection{}, "", false, model.Fail(model.Corrupt)
	}
	return conn, o.Secrets[GitLabSecretKey], true, nil
}

// GitLabCommand commits one GitLab settings command of an organization
// administrator under a fresh session: save (connection, mappings, optional new
// token), disconnect (clears the settings and the sealed token) or token_check
// (records scopes and expiry). Retrying a committed command ID returns its
// original result.
func (s *Service) GitLabCommand(ctx context.Context, c Credential, r GitLabCommandRequest) (model.ControlResult, error) {
	if c.service != s || !c.Fresh() {
		return model.ControlResult{}, model.Fail(model.Forbidden)
	}
	if _, e := s.Authenticate(ctx, c.token); e != nil {
		return model.ControlResult{}, e
	}
	reason := r.Reason
	switch r.Op {
	case GitLabSave:
		in := r.Connection
		if in == nil {
			return model.ControlResult{}, gitlabCode(model.Invalid, "gitlab_connection_invalid")
		}
		if _, ok := validGitLabBaseURL(in.BaseURL); !ok || in.Token != "" && !validGitLabToken(in.Token) {
			return model.ControlResult{}, gitlabCode(model.Invalid, "gitlab_connection_invalid")
		}
	case GitLabDisconnect:
		if r.Connection != nil || r.Token != nil {
			return model.ControlResult{}, gitlabCode(model.Invalid, "gitlab_connection_invalid")
		}
	case GitLabTokenCheck:
		if r.Token == nil || !validGitLabTokenMeta(*r.Token) || r.Connection != nil {
			return model.ControlResult{}, gitlabCode(model.Invalid, "gitlab_connection_invalid")
		}
		reason = "token check"
	default:
		return model.ControlResult{}, model.Fail(model.Invalid)
	}
	if reason == "" || len(reason) > 512 || !utf8.ValidString(reason) {
		return model.ControlResult{}, model.Fail(model.Invalid)
	}
	var sealed string
	if r.Op == GitLabSave && r.Connection.Token != "" {
		var e error
		if sealed, e = s.store.Seal(r.Connection.Token); e != nil {
			return model.ControlResult{}, model.Fail(model.Unavailable)
		}
	}
	action := "gitlab.connection"
	if r.Op == GitLabTokenCheck {
		action = "gitlab.token_check"
	}
	audit := model.ControlAudit{ID: model.NewID(), Principal: c.user, Action: action, Reason: reason, Time: s.now().UnixNano(), Org: r.OrgID.String(), RequestID: model.RequestCorrelationID(ctx, r.CommandID), Outcome: model.AuditAllowed}
	var out model.ControlResult
	e := s.updateAdmin(ctx, AdminCommandRequest{OrgID: r.OrgID, Kind: gitlabKind}, func(st *model.ControlState) error {
		if err := s.validateCredentialState(*st, c); err != nil {
			return err
		}
		binding := c.user.String() + ":" + r.OrgID.String() + ":" + gitlabKind
		if old, ok := st.Commands[r.CommandID.String()]; ok {
			if st.CommandOwners[r.CommandID.String()] != binding {
				return model.Fail(model.NotFound)
			}
			if st.Users[c.user.String()].Disabled {
				return model.Fail(model.Unauthenticated)
			}
			if !st.Orgs[r.OrgID.String()].Admins[c.user.String()] {
				return model.Fail(model.NotFound)
			}
			out = old
			return nil
		}
		if r.CommandID == (model.ID{}) {
			return model.Fail(model.Conflict)
		}
		o, exists := st.Orgs[r.OrgID.String()]
		if !exists || !o.Admins[c.user.String()] {
			return model.Fail(model.NotFound)
		}
		if _, retired := st.RetiredOrgs[r.OrgID.String()]; retired {
			return model.Fail(model.NotFound)
		}
		if o.ObjectChangedAfter(GitLabSettingKey, uint64(r.ExpectedEpoch)) {
			return model.Fail(model.Conflict)
		}
		if o.Settings == nil {
			o.Settings = map[string]json.RawMessage{}
		}
		if o.Secrets == nil {
			o.Secrets = map[string]string{}
		}
		trackKey := GitLabSettingKey
		audit.Targets = []model.ID{r.OrgID}
		switch r.Op {
		case GitLabSave:
			conn, _, _, err := ParseGitLabConnection(o)
			if err != nil {
				return err
			}
			maps, err := validateGitLabMappings(o, r.Connection.Mappings)
			if err != nil {
				return err
			}
			base, _ := validGitLabBaseURL(r.Connection.BaseURL)
			next := GitLabConnection{BaseURL: base, Mappings: maps, Token: conn.Token}
			if sealed != "" {
				o.Secrets[GitLabSecretKey] = sealed
				next.Token = GitLabTokenMeta{}
			} else if base != conn.BaseURL {
				next.Token = GitLabTokenMeta{} // a token checked against another server says nothing here
			}
			raw, merr := json.Marshal(next)
			if merr != nil {
				return model.Fail(model.Invalid)
			}
			o.Settings[GitLabSettingKey] = raw
			for _, m := range maps {
				audit.Targets = append(audit.Targets, m.ProjectID)
			}
		case GitLabDisconnect:
			delete(o.Settings, GitLabSettingKey)
			delete(o.Secrets, GitLabSecretKey)
		case GitLabTokenCheck:
			conn, _, found, err := ParseGitLabConnection(o)
			if err != nil {
				return err
			}
			if !found || o.Secrets[GitLabSecretKey] == "" {
				return model.Fail(model.NotFound)
			}
			conn.Token = GitLabTokenMeta{ExpiresAt: r.Token.ExpiresAt, Scopes: append([]string(nil), r.Token.Scopes...)}
			raw, merr := json.Marshal(conn)
			if merr != nil {
				return model.Fail(model.Invalid)
			}
			o.Settings[GitLabSettingKey] = raw
			// The check is a change to its own object: it does not make a form save that
			// read the connection before it stale.
			trackKey = gitlabTokenCheckKey
		}
		o.TrackChange(trackKey)
		st.Orgs[r.OrgID.String()] = o
		audit.PolicyEpoch = o.Epoch
		st.Audits = append(st.Audits, audit)
		out = model.ControlResult{Revision: st.Revision + 1, Cursor: model.Cursor{Group: st.Installation, Index: model.Uint64(st.Revision + 1)}}
		if st.CommandOwners == nil {
			st.CommandOwners = map[string]string{}
		}
		st.CommandOwners[r.CommandID.String()] = binding
		st.Commands[r.CommandID.String()] = out
		return nil
	})
	return out, e
}

// GitLabRead is what a member of the organization may read of the connection:
// whether one is set, the base URL, the token metadata and the mappings of the
// projects they can see (an administrator sees every mapping). It never carries the
// token. A caller who is neither member nor administrator, and a server token, get
// the one not-found.
func (s *Service) GitLabRead(ctx context.Context, c Credential, org model.ID) (GitLabView, error) {
	if c.service != s || c.machine {
		return GitLabView{}, model.Fail(model.Unauthenticated)
	}
	if _, err := s.Authenticate(ctx, c.token); err != nil {
		return GitLabView{}, err
	}
	var out GitLabView
	err := s.store.View(ctx, func(st model.ControlState) error {
		if err := s.validateCredentialState(st, c); err != nil {
			return err
		}
		o, ok := st.Orgs[org.String()]
		if _, retired := st.RetiredOrgs[org.String()]; !ok || retired {
			return model.Fail(model.NotFound)
		}
		user := c.user.String()
		out.Admin = o.Admins[user]
		if !out.Admin && !o.Members[user] {
			return model.Fail(model.NotFound)
		}
		out.Epoch = model.Uint64(o.Epoch)
		conn, sealed, found, err := ParseGitLabConnection(o)
		if err != nil {
			return err
		}
		if !found {
			return nil
		}
		out.HasToken = sealed != ""
		out.Connected = out.HasToken
		visible := conn.Mappings[:0:0]
		for _, m := range conn.Mappings {
			if out.Admin || memberSeesProject(o, c.user, m.ProjectID) {
				visible = append(visible, m)
			}
		}
		conn.Mappings = visible
		out.Connection = &conn
		return nil
	})
	return out, err
}

// memberSeesProject says whether the user holds any grant, directly or through an
// enabled team, on the project.
func memberSeesProject(o model.ControlOrg, user, project model.ID) bool {
	if len(o.Grants[user.String()+":"+project.String()]) > 0 {
		return true
	}
	for _, team := range o.Teams {
		if team.Enabled && hasID(team.Members, user) && hasID(team.Projects, project) && len(team.Permissions) > 0 {
			return true
		}
	}
	return false
}
