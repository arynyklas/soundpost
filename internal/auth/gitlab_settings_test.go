// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth_test

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

const gitlabTestToken = "tok-0123456789abcdef-test"

type gitlabEnv struct{ objEnv }

func newGitLabEnv(t *testing.T) gitlabEnv { return gitlabEnv{objEnv{newCacheFixture(t)}} }

func (e gitlabEnv) mapping(project model.ID) auth.GitLabMapping {
	return auth.GitLabMapping{ProjectID: project, GitLabProject: "shop/web", CreateFrom: []string{"incident", "issue"}, Labels: []string{"soundpost"}}
}

func (e gitlabEnv) save(c auth.Credential, epoch model.Uint64, in auth.GitLabConnectionInput) (model.ControlResult, error) {
	e.t.Helper()
	return e.service.GitLabCommand(e.ctx, c, auth.GitLabCommandRequest{CommandID: model.NewID(), OrgID: e.org, ExpectedEpoch: epoch, Op: auth.GitLabSave, Reason: "connect gitlab", Connection: &in})
}

func (e gitlabEnv) mustSave(in auth.GitLabConnectionInput) {
	e.t.Helper()
	read, err := e.service.GitLabRead(e.ctx, e.actor, e.org)
	if err != nil {
		e.t.Fatal(err)
	}
	if _, err = e.save(e.actor, read.Epoch, in); err != nil {
		e.t.Fatal(err)
	}
}

func (e gitlabEnv) stored() (setting string, sealed string, audits []model.ControlAudit) {
	e.t.Helper()
	if err := e.store.View(e.ctx, func(st control.State) error {
		o := st.Orgs[e.org.String()]
		setting, sealed = string(o.Settings[auth.GitLabSettingKey]), o.Secrets[auth.GitLabSecretKey]
		audits = append(audits, st.Audits...)
		return nil
	}); err != nil {
		e.t.Fatal(err)
	}
	return
}

func faultOf(err error) (model.Code, string) {
	var f *model.Fault
	if errors.As(err, &f) {
		return f.Code, f.SafeDetail
	}
	return "", ""
}

func TestGitLabSaveIsSealedRedactedAndAudited(t *testing.T) {
	e := newGitLabEnv(t)
	e.mustSave(auth.GitLabConnectionInput{BaseURL: "https://gitlab.example.test/gitlab/", Token: gitlabTestToken, Mappings: []auth.GitLabMapping{e.mapping(e.project)}})
	setting, sealed, audits := e.stored()
	if sealed == "" || sealed == gitlabTestToken || strings.Contains(setting, gitlabTestToken) {
		t.Fatalf("token stored in the clear: setting %q sealed %q", setting, sealed)
	}
	if plain, err := e.store.OpenSecret(sealed); err != nil || plain != gitlabTestToken {
		t.Fatalf("sealed token does not open to the token: %v", err)
	}
	view, err := e.service.GitLabRead(e.ctx, e.actor, e.org)
	if err != nil || !view.Connected || !view.HasToken || !view.Admin || view.Connection == nil || view.Connection.BaseURL != "https://gitlab.example.test/gitlab" || len(view.Connection.Mappings) != 1 {
		t.Fatalf("view %+v %v", view, err)
	}
	raw, _ := json.Marshal(view)
	if strings.Contains(string(raw), gitlabTestToken) || strings.Contains(string(raw), sealed) {
		t.Fatalf("view carries the token: %s", raw)
	}
	var found bool
	for _, a := range audits {
		raw, _ := json.Marshal(a)
		if strings.Contains(string(raw), gitlabTestToken) || strings.Contains(string(raw), sealed) || strings.Contains(string(raw), "/gitlab") || strings.Contains(string(raw), "gitlab.example.test") {
			t.Fatalf("audit carries token or URL: %s", raw)
		}
		if a.Action == "gitlab.connection" && a.Outcome == model.AuditAllowed && a.Reason == "connect gitlab" {
			found = true
		}
	}
	if !found {
		t.Fatal("no gitlab.connection audit entry")
	}
}

func TestGitLabSaveWithoutTokenKeepsTheStoredOne(t *testing.T) {
	e := newGitLabEnv(t)
	e.mustSave(auth.GitLabConnectionInput{BaseURL: "https://gitlab.example.test", Token: gitlabTestToken, Mappings: []auth.GitLabMapping{e.mapping(e.project)}})
	_, sealed1, _ := e.stored()
	next := e.mapping(e.project)
	next.Labels = []string{"a", "b"}
	e.mustSave(auth.GitLabConnectionInput{BaseURL: "https://gitlab.example.test", Mappings: []auth.GitLabMapping{next}})
	setting, sealed2, _ := e.stored()
	if sealed1 != sealed2 || !strings.Contains(setting, `"labels":["a","b"]`) {
		t.Fatalf("sealed changed or mapping not saved: %q", setting)
	}
	e.mustSave(auth.GitLabConnectionInput{BaseURL: "https://gitlab.example.test", Token: gitlabTestToken + "-rotated", Mappings: []auth.GitLabMapping{next}})
	_, sealed3, _ := e.stored()
	if plain, _ := e.store.OpenSecret(sealed3); plain != gitlabTestToken+"-rotated" {
		t.Fatal("token not replaced")
	}
}

func TestGitLabSaveRefusesAStaleEpochOnlyForItsOwnObject(t *testing.T) {
	e := newGitLabEnv(t)
	in := auth.GitLabConnectionInput{BaseURL: "https://gitlab.example.test", Token: gitlabTestToken, Mappings: []auth.GitLabMapping{e.mapping(e.project)}}
	read, err := e.service.GitLabRead(e.ctx, e.actor, e.org)
	if err != nil {
		t.Fatal(err)
	}
	// An unrelated organization change between the read and the save is no conflict.
	e.mustSave0("create_project", auth.AdminPayload{ID: model.NewID(), Name: "other"})
	if _, err = e.save(e.actor, read.Epoch, in); err != nil {
		t.Fatalf("save after an unrelated change: %v", err)
	}
	before, _, _ := e.stored()
	// A change to the connection itself since the read is a lost update.
	other := in
	other.BaseURL = "https://other.example.test"
	if _, err = e.save(e.actor, read.Epoch, other); err == nil {
		t.Fatal("a stale save was accepted")
	} else if code, _ := faultOf(err); code != model.Conflict {
		t.Fatalf("err %v", err)
	}
	if after, _, _ := e.stored(); after != before {
		t.Fatal("a refused save changed the connection")
	}
	// An epoch the organization has not reached is stale too.
	if _, err = e.save(e.actor, read.Epoch+1000, in); err == nil {
		t.Fatal("a future epoch was accepted")
	}
}

func (e gitlabEnv) mustSave0(kind string, p auth.AdminPayload) {
	e.t.Helper()
	if err := e.objEnv.save(kind, p, e.objEnv.epoch()); err != nil {
		e.t.Fatal(kind, err)
	}
}

func TestGitLabDisconnectClearsSettingsAndSecret(t *testing.T) {
	e := newGitLabEnv(t)
	e.mustSave(auth.GitLabConnectionInput{BaseURL: "https://gitlab.example.test", Token: gitlabTestToken, Mappings: []auth.GitLabMapping{e.mapping(e.project)}})
	read, _ := e.service.GitLabRead(e.ctx, e.actor, e.org)
	if _, err := e.service.GitLabCommand(e.ctx, e.actor, auth.GitLabCommandRequest{CommandID: model.NewID(), OrgID: e.org, ExpectedEpoch: read.Epoch, Op: auth.GitLabDisconnect, Reason: "left gitlab"}); err != nil {
		t.Fatal(err)
	}
	setting, sealed, audits := e.stored()
	if setting != "" || sealed != "" {
		t.Fatalf("setting %q sealed %q survived", setting, sealed)
	}
	view, err := e.service.GitLabRead(e.ctx, e.actor, e.org)
	if err != nil || view.Connected || view.HasToken || view.Connection != nil {
		t.Fatalf("view %+v %v", view, err)
	}
	last := audits[len(audits)-1]
	if last.Action != "gitlab.connection" || last.Reason != "left gitlab" {
		t.Fatalf("audit %+v", last)
	}
}

func TestGitLabSaveValidation(t *testing.T) {
	e := newGitLabEnv(t)
	good := e.mapping(e.project)
	with := func(f func(*auth.GitLabMapping)) []auth.GitLabMapping {
		m := good
		m.CreateFrom, m.Labels = append([]string(nil), good.CreateFrom...), append([]string(nil), good.Labels...)
		f(&m)
		return []auth.GitLabMapping{m}
	}
	read, _ := e.service.GitLabRead(e.ctx, e.actor, e.org)
	for name, in := range map[string]auth.GitLabConnectionInput{
		"http":            {BaseURL: "http://gitlab.example.test", Token: gitlabTestToken},
		"credentials":     {BaseURL: "https://user:pw@gitlab.example.test", Token: gitlabTestToken},
		"query":           {BaseURL: "https://gitlab.example.test/?a=1", Token: gitlabTestToken},
		"fragment":        {BaseURL: "https://gitlab.example.test/#x", Token: gitlabTestToken},
		"empty":           {BaseURL: "", Token: gitlabTestToken},
		"short token":     {BaseURL: "https://gitlab.example.test", Token: "short"},
		"token space":     {BaseURL: "https://gitlab.example.test", Token: "tok with space 1234"},
		"unknown project": {BaseURL: "https://gitlab.example.test", Mappings: with(func(m *auth.GitLabMapping) { m.ProjectID = model.NewID() })},
		"zero project":    {BaseURL: "https://gitlab.example.test", Mappings: with(func(m *auth.GitLabMapping) { m.ProjectID = model.ID{} })},
		"duplicate":       {BaseURL: "https://gitlab.example.test", Mappings: append(with(func(*auth.GitLabMapping) {}), with(func(*auth.GitLabMapping) {})...)},
		"bad kind":        {BaseURL: "https://gitlab.example.test", Mappings: with(func(m *auth.GitLabMapping) { m.CreateFrom = []string{"release"} })},
		"no kind":         {BaseURL: "https://gitlab.example.test", Mappings: with(func(m *auth.GitLabMapping) { m.CreateFrom = nil })},
		"bad path":        {BaseURL: "https://gitlab.example.test", Mappings: with(func(m *auth.GitLabMapping) { m.GitLabProject = "a b" })},
		"path query":      {BaseURL: "https://gitlab.example.test", Mappings: with(func(m *auth.GitLabMapping) { m.GitLabProject = "a/b?x=1" })},
		"comma label":     {BaseURL: "https://gitlab.example.test", Mappings: with(func(m *auth.GitLabMapping) { m.Labels = []string{"a,b"} })},
		"many labels":     {BaseURL: "https://gitlab.example.test", Mappings: with(func(m *auth.GitLabMapping) { m.Labels = make([]string, 11) })},
	} {
		before, _, _ := e.stored()
		if _, err := e.save(e.actor, read.Epoch, in); err == nil {
			t.Errorf("%s: accepted", name)
		} else if code, _ := faultOf(err); code != model.Invalid {
			t.Errorf("%s: err %v", name, err)
		}
		if after, _, _ := e.stored(); after != before {
			t.Errorf("%s: changed the connection", name)
		}
	}
	if _, err := e.service.GitLabCommand(e.ctx, e.actor, auth.GitLabCommandRequest{CommandID: model.NewID(), OrgID: e.org, ExpectedEpoch: read.Epoch, Op: auth.GitLabSave, Connection: &auth.GitLabConnectionInput{BaseURL: "https://gitlab.example.test"}}); err == nil {
		t.Error("save without a reason accepted")
	}
	if _, err := e.service.GitLabCommand(e.ctx, e.actor, auth.GitLabCommandRequest{CommandID: model.NewID(), OrgID: e.org, ExpectedEpoch: read.Epoch, Op: "other", Reason: "x"}); err == nil {
		t.Error("unknown op accepted")
	}
}

func TestGitLabSettingsAreOrganizationAdminOnlyAndReadsAreMembersOnly(t *testing.T) {
	e := newGitLabEnv(t)
	second := model.NewID()
	e.cmd("create_project", auth.AdminPayload{ID: second, Name: "second"})
	e.mustSave(auth.GitLabConnectionInput{BaseURL: "https://gitlab.example.test", Token: gitlabTestToken, Mappings: []auth.GitLabMapping{e.mapping(e.project), e.mapping(second)}})
	reader, _ := e.reader("gl-reader@example.test", auth.Read)
	read, _ := e.service.GitLabRead(e.ctx, e.actor, e.org)

	// A reader cannot write: the one not-found, nothing changes.
	before, _, _ := e.stored()
	in := auth.GitLabConnectionInput{BaseURL: "https://evil.example.test", Token: gitlabTestToken + "x"}
	if _, err := e.save(reader, read.Epoch, in); err == nil {
		t.Fatal("a reader saved the connection")
	} else if code, _ := faultOf(err); code != model.NotFound {
		t.Fatalf("err %v", err)
	}
	if _, err := e.service.GitLabCommand(e.ctx, reader, auth.GitLabCommandRequest{CommandID: model.NewID(), OrgID: e.org, ExpectedEpoch: read.Epoch, Op: auth.GitLabDisconnect, Reason: "x"}); err == nil {
		t.Fatal("a reader disconnected")
	}
	if _, err := e.service.GitLabCommand(e.ctx, reader, auth.GitLabCommandRequest{CommandID: model.NewID(), OrgID: e.org, ExpectedEpoch: read.Epoch, Op: auth.GitLabTokenCheck, Token: &auth.GitLabTokenMeta{}}); err == nil {
		t.Fatal("a reader recorded a token check")
	}
	if after, _, _ := e.stored(); after != before {
		t.Fatal("a refused write changed the connection")
	}

	// A member reads the redacted connection, only the mappings of projects they can see.
	view, err := e.service.GitLabRead(e.ctx, reader, e.org)
	if err != nil || view.Admin || !view.HasToken || view.Connection == nil || len(view.Connection.Mappings) != 1 || view.Connection.Mappings[0].ProjectID != e.project {
		t.Fatalf("member view %+v %v", view, err)
	}
	raw, _ := json.Marshal(view)
	if strings.Contains(string(raw), gitlabTestToken) || strings.Contains(string(raw), second.String()) {
		t.Fatalf("member view leaks: %s", raw)
	}
	if admin, _ := e.service.GitLabRead(e.ctx, e.actor, e.org); len(admin.Connection.Mappings) != 2 {
		t.Fatalf("admin mappings %d", len(admin.Connection.Mappings))
	}

	// Another organization's id, and a user who is not a member, are the same not-found.
	if _, err = e.service.GitLabRead(e.ctx, e.actor, model.NewID()); err == nil {
		t.Fatal("read of an unknown organization")
	}
	outsider := model.NewID()
	e.cmd("create_user", auth.AdminPayload{ID: outsider, Email: "gl-outsider@example.test", Password: "cache reader password"})
	login, err := e.service.Login(e.ctx, "gl-outsider@example.test", "cache reader password", "")
	if err != nil {
		t.Fatal(err)
	}
	oc, _ := e.service.Authenticate(e.ctx, login.Token)
	if _, err = e.service.GitLabRead(e.ctx, oc, e.org); err == nil {
		t.Fatal("a non-member read the connection")
	} else if code, _ := faultOf(err); code != model.NotFound {
		t.Fatalf("err %v", err)
	}
}

func TestGitLabCommandNeedsAFreshSession(t *testing.T) {
	e := newGitLabEnv(t)
	read, _ := e.service.GitLabRead(e.ctx, e.actor, e.org)
	e.now.Add(int64(10 * time.Minute))
	_, err := e.save(e.actor, read.Epoch, auth.GitLabConnectionInput{BaseURL: "https://gitlab.example.test", Token: gitlabTestToken})
	if code, _ := faultOf(err); code != model.Forbidden {
		t.Fatalf("err %v", err)
	}
}

func TestGitLabCommandReplayReturnsTheOriginalResult(t *testing.T) {
	e := newGitLabEnv(t)
	read, _ := e.service.GitLabRead(e.ctx, e.actor, e.org)
	req := auth.GitLabCommandRequest{CommandID: model.NewID(), OrgID: e.org, ExpectedEpoch: read.Epoch, Op: auth.GitLabSave, Reason: "connect", Connection: &auth.GitLabConnectionInput{BaseURL: "https://gitlab.example.test", Token: gitlabTestToken}}
	first, err := e.service.GitLabCommand(e.ctx, e.actor, req)
	if err != nil {
		t.Fatal(err)
	}
	after1, _ := e.service.GitLabRead(e.ctx, e.actor, e.org)
	again, err := e.service.GitLabCommand(e.ctx, e.actor, req)
	if err != nil || !reflect.DeepEqual(again, first) {
		t.Fatalf("replay %+v %v, first %+v", again, err, first)
	}
	if after2, _ := e.service.GitLabRead(e.ctx, e.actor, e.org); after2.Epoch != after1.Epoch {
		t.Fatal("the replay changed the organization")
	}
	// Another user cannot replay the command either.
	reader, _ := e.reader("gl-replay@example.test", auth.Read)
	if _, err = e.service.GitLabCommand(e.ctx, reader, req); err == nil {
		t.Fatal("another user replayed the command")
	}
}

func TestGitLabTokenCheckRecordsMetadataWithoutStalingAForm(t *testing.T) {
	e := newGitLabEnv(t)
	e.mustSave(auth.GitLabConnectionInput{BaseURL: "https://gitlab.example.test", Token: gitlabTestToken, Mappings: []auth.GitLabMapping{e.mapping(e.project)}})
	read, _ := e.service.GitLabRead(e.ctx, e.actor, e.org)
	meta := auth.GitLabTokenMeta{ExpiresAt: "2027-01-31", Scopes: []string{"api", "read_api"}}
	if _, err := e.service.GitLabCommand(e.ctx, e.actor, auth.GitLabCommandRequest{CommandID: model.NewID(), OrgID: e.org, ExpectedEpoch: read.Epoch, Op: auth.GitLabTokenCheck, Token: &meta}); err != nil {
		t.Fatal(err)
	}
	view, _ := e.service.GitLabRead(e.ctx, e.actor, e.org)
	if view.Connection.Token.ExpiresAt != "2027-01-31" || len(view.Connection.Token.Scopes) != 2 {
		t.Fatalf("meta %+v", view.Connection.Token)
	}
	// The form that read the connection before the check still saves.
	if _, err := e.save(e.actor, read.Epoch, auth.GitLabConnectionInput{BaseURL: "https://gitlab.example.test", Mappings: []auth.GitLabMapping{e.mapping(e.project)}}); err != nil {
		t.Fatalf("save after a token check: %v", err)
	}
	// A new token resets what was recorded about the old one.
	view, _ = e.service.GitLabRead(e.ctx, e.actor, e.org)
	if len(view.Connection.Token.Scopes) != 2 {
		t.Fatalf("keeping the token must keep its metadata: %+v", view.Connection.Token)
	}
	e.mustSave(auth.GitLabConnectionInput{BaseURL: "https://gitlab.example.test", Token: gitlabTestToken + "2", Mappings: []auth.GitLabMapping{e.mapping(e.project)}})
	view, _ = e.service.GitLabRead(e.ctx, e.actor, e.org)
	if len(view.Connection.Token.Scopes) != 0 || view.Connection.Token.ExpiresAt != "" {
		t.Fatalf("metadata of the replaced token survived: %+v", view.Connection.Token)
	}
	// Garbage metadata and a check without a connection are refused.
	read, _ = e.service.GitLabRead(e.ctx, e.actor, e.org)
	for _, bad := range []auth.GitLabTokenMeta{{ExpiresAt: "tomorrow"}, {Scopes: []string{"Bad Scope"}}, {Scopes: make([]string, 17)}} {
		if _, err := e.service.GitLabCommand(e.ctx, e.actor, auth.GitLabCommandRequest{CommandID: model.NewID(), OrgID: e.org, ExpectedEpoch: read.Epoch, Op: auth.GitLabTokenCheck, Token: &bad}); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	if _, err := e.service.GitLabCommand(e.ctx, e.actor, auth.GitLabCommandRequest{CommandID: model.NewID(), OrgID: e.org, ExpectedEpoch: read.Epoch, Op: auth.GitLabDisconnect, Reason: "bye"}); err != nil {
		t.Fatal(err)
	}
	read, _ = e.service.GitLabRead(e.ctx, e.actor, e.org)
	if _, err := e.service.GitLabCommand(e.ctx, e.actor, auth.GitLabCommandRequest{CommandID: model.NewID(), OrgID: e.org, ExpectedEpoch: read.Epoch, Op: auth.GitLabTokenCheck, Token: &meta}); err == nil {
		t.Fatal("a token check without a connection was recorded")
	}
}
