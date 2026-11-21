// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

// The saved-view commands are committed by the control store under the caller's
// own scope. These tests drive the real store (activated single-voter group,
// real auth scopes, real users and grants) through the handler: scope and
// ownership, the revision compare-and-set, the per-project cap, authority
// neutrality, the audit, the deletion hook and the snapshot.

const (
	svCanaryName = "SVNAMECANARY5a0c91d3"
	svCanaryExpr = "SVEXPRCANARY77be42f8"
)

type svFx struct{ *eraseFx }

func newSVFx(t *testing.T) *svFx {
	t.Helper()
	f := &svFx{newEraseFx(t)}
	if err := f.store.BindSavedViews(); err != nil {
		t.Fatal(err)
	}
	// The owner of the fixture (an organization administrator) also reads the other project.
	f.admin("grant", f.org, auth.AdminPayload{UserID: f.user, ProjectID: f.otherProject, Enabled: true, Permissions: []string{string(auth.Read)}, Reason: "fixture"})
	return f
}

type svPerson struct {
	id   model.ID
	cred auth.Credential
}

// member creates a non-administrator member holding telemetry.read on the projects.
func (f *svFx) member(email string, projects ...model.ID) svPerson {
	f.t.Helper()
	id := model.NewID()
	const password = "a long test password 2026"
	f.admin("create_user", f.org, auth.AdminPayload{ID: id, Email: email, Password: password, Reason: "fixture"})
	f.admin("membership", f.org, auth.AdminPayload{UserID: id, Enabled: true, Reason: "fixture"})
	for _, p := range projects {
		f.admin("grant", f.org, auth.AdminPayload{UserID: id, ProjectID: p, Enabled: true, Permissions: []string{string(auth.Read)}, Reason: "fixture"})
	}
	session, err := f.svc.Login(f.ctx, email, password, "")
	if err != nil {
		f.t.Fatal(err)
	}
	cred, err := f.svc.Authenticate(f.ctx, session.Token)
	if err != nil {
		f.t.Fatal(err)
	}
	return svPerson{id: id, cred: cred}
}

func (f *svFx) reader(cred auth.Credential, projects ...model.ID) auth.Scope {
	f.t.Helper()
	s, err := f.svc.Authorize(f.ctx, cred, f.org, projects, auth.Read)
	if err != nil {
		f.t.Fatal(err)
	}
	return s
}

func (f *svFx) spec(name, expr string, projects ...model.ID) auth.SavedViewSpec {
	if len(projects) == 0 {
		projects = []model.ID{f.project}
	}
	return auth.SavedViewSpec{Name: name, Language: "promql", Profile: "promql-prometheus-3.1.0", FeatureSet: "features-0123", Expression: expr, Projects: projects, Mode: "instant"}
}

func (f *svFx) at() model.UnixNano { return model.UnixNano(f.now.UnixNano()) }

func (f *svFx) command(c auth.SavedViewCommand) control.Command {
	f.t.Helper()
	if c.At == 0 {
		c.At = f.at()
	}
	return f.cmd(control.KindSavedView, model.NewID(), c)
}

func (f *svFx) save(scope auth.Scope, project, view model.ID, expected model.Revision, spec auth.SavedViewSpec) (control.Result, error) {
	f.t.Helper()
	return f.store.Transact(f.ctx, scope, f.command(auth.SavedViewCommand{Operation: auth.SavedViewOpSave, Project: project, View: view, ExpectedRevision: expected, Spec: &spec}))
}

func (f *svFx) remove(scope auth.Scope, project, view model.ID, expected model.Revision) (control.Result, error) {
	f.t.Helper()
	return f.store.Transact(f.ctx, scope, f.command(auth.SavedViewCommand{Operation: auth.SavedViewOpDelete, Project: project, View: view, ExpectedRevision: expected}))
}

func (f *svFx) mustSave(scope auth.Scope, project, view model.ID, expected model.Revision, spec auth.SavedViewSpec) control.Result {
	f.t.Helper()
	res, err := f.save(scope, project, view, expected, spec)
	if err != nil {
		f.t.Fatal("save:", err)
	}
	return res
}

func (f *svFx) books() map[string]json.RawMessage {
	f.t.Helper()
	var out map[string]json.RawMessage
	if err := f.store.View(f.ctx, func(st control.State) error { out = st.SavedViewBooks; return nil }); err != nil {
		f.t.Fatal(err)
	}
	return out
}

func (f *svFx) view(project, view model.ID) (auth.SavedView, bool) {
	f.t.Helper()
	raw, ok := f.books()[auth.SavedViewKey(f.org, project, view)]
	if !ok {
		return auth.SavedView{}, false
	}
	var v auth.SavedView
	if err := json.Unmarshal(raw, &v); err != nil {
		f.t.Fatal(err)
	}
	return v, true
}

func (f *svFx) counters() (revision, authority model.Revision, epoch uint64) {
	f.t.Helper()
	if err := f.store.View(f.ctx, func(st control.State) error {
		revision, authority, epoch = st.Revision, st.AuthorityRevision, st.Orgs[f.org.String()].Epoch
		return nil
	}); err != nil {
		f.t.Fatal(err)
	}
	return
}

func svDetail(err error) string {
	var fault *model.Fault
	if errors.As(err, &fault) {
		return fault.SafeDetail
	}
	return ""
}

func TestSavedViewKindIsPinnedToTheControlKind(t *testing.T) {
	if auth.SavedViewKind != string(control.KindSavedView) {
		t.Fatalf("auth.SavedViewKind %q must equal control.KindSavedView %q", auth.SavedViewKind, control.KindSavedView)
	}
	if !control.KindSavedView.Valid() {
		t.Fatal("KindSavedView is not a valid command kind")
	}
}

// A telemetry.read scope may commit the saved-view command and nothing else: the
// control store never takes a read grant as a write permission.
func TestReadScopeCommitsOnlySavedViews(t *testing.T) {
	f := newSVFx(t)
	scope := f.reader(f.cred, f.project)
	for _, kind := range []control.CommandKind{control.KindUpdateJob, control.KindIncidentAction, control.KindDeleteScope, control.KindAudit, control.KindGrant, control.KindApplyRuleEvaluation} {
		_, err := f.store.Transact(f.ctx, scope, f.cmd(kind, model.NewID(), map[string]any{}))
		if code(err) != model.Forbidden {
			t.Errorf("a telemetry.read scope committed %s: %v", kind, err)
		}
	}
	if _, err := f.save(scope, f.project, model.NewID(), 0, f.spec("n", "up")); err != nil {
		t.Fatalf("a telemetry.read scope may save a view: %v", err)
	}
}

func TestSavedViewLifecycleAndOwnership(t *testing.T) {
	f := newSVFx(t)
	bob := f.member("bob@example.test", f.project)
	owner, other := f.reader(f.cred, f.project), f.reader(bob.cred, f.project)
	view := model.NewID()

	res := f.mustSave(owner, f.project, view, 0, f.spec("first", "up"))
	if res.Phase != "created:1" || len(res.AffectedIDs) != 1 || res.AffectedIDs[0] != view {
		t.Fatalf("create result %+v", res)
	}
	v, ok := f.view(f.project, view)
	if !ok || v.Owner != f.user || v.Revision != 1 || v.Org != f.org || v.Project != f.project || v.CreatedNS != f.at() || v.UpdatedNS != f.at() || v.Name != "first" {
		t.Fatalf("stored view %+v", v)
	}

	// Creating a view that exists is a conflict, not an overwrite.
	if _, err := f.save(owner, f.project, view, 0, f.spec("again", "up")); code(err) != model.Conflict || svDetail(err) != control.SavedViewExists {
		t.Fatalf("create over an existing view: %v", err)
	}
	// A reader of the project who is neither the owner nor an administrator sees the
	// view and may not change it.
	if _, err := f.save(other, f.project, view, 1, f.spec("bob's", "up")); code(err) != model.Forbidden {
		t.Fatalf("a non-owner reader updated a view: %v", err)
	}
	if _, err := f.remove(other, f.project, view, 1); code(err) != model.Forbidden {
		t.Fatalf("a non-owner reader deleted a view: %v", err)
	}
	if v, _ = f.view(f.project, view); v.Name != "first" || v.Revision != 1 {
		t.Fatalf("a refused command changed the view: %+v", v)
	}
	// The revision is a compare-and-set, for an update and for a delete.
	for _, stale := range []model.Revision{2, 7} {
		if _, err := f.save(owner, f.project, view, stale, f.spec("stale", "up")); code(err) != model.Conflict || svDetail(err) != control.SavedViewRevisionConflict {
			t.Fatalf("update at revision %d: %v", stale, err)
		}
		if _, err := f.remove(owner, f.project, view, stale); code(err) != model.Conflict || svDetail(err) != control.SavedViewRevisionConflict {
			t.Fatalf("delete at revision %d: %v", stale, err)
		}
	}
	res = f.mustSave(owner, f.project, view, 1, f.spec("second", "rate(up[5m])"))
	if res.Phase != "updated:2" {
		t.Fatalf("update result %+v", res)
	}
	if v, _ = f.view(f.project, view); v.Name != "second" || v.Expression != "rate(up[5m])" || v.Revision != 2 || v.Owner != f.user || v.CreatedNS != f.at() {
		t.Fatalf("updated view %+v", v)
	}

	// An organization administrator updates and deletes a view they do not own, and
	// the owner stays the owner.
	bobsView := model.NewID()
	f.mustSave(other, f.project, bobsView, 0, f.spec("bob's view", "up"))
	f.mustSave(owner, f.project, bobsView, 1, f.spec("renamed by an administrator", "up"))
	if v, _ = f.view(f.project, bobsView); v.Owner != bob.id || v.Name != "renamed by an administrator" || v.Revision != 2 {
		t.Fatalf("administrator update %+v", v)
	}
	if res, err := f.remove(owner, f.project, bobsView, 2); err != nil || res.Phase != "deleted:3" {
		t.Fatalf("administrator delete: %+v %v", res, err)
	}
	if _, ok = f.view(f.project, bobsView); ok {
		t.Fatal("the deleted view is still stored")
	}
	// The owner deletes their own view; a repeat is an absent view.
	if res, err := f.remove(other, f.project, bobsView, 3); code(err) != model.NotFound {
		t.Fatalf("delete of an absent view: %+v %v", res, err)
	}
	mine := model.NewID()
	f.mustSave(other, f.project, mine, 0, f.spec("mine", "up"))
	if res, err := f.remove(other, f.project, mine, 1); err != nil || res.Phase != "deleted:2" {
		t.Fatalf("owner delete: %+v %v", res, err)
	}

	// The view is owned by its project: the same ID under another project is absent.
	f.mustSave(owner, f.project, view, 2, f.spec("second", "up"))
	wide := f.reader(f.cred, f.project, f.otherProject)
	if _, err := f.save(wide, f.otherProject, view, 3, f.spec("moved", "up", f.otherProject)); code(err) != model.NotFound {
		t.Fatalf("update through another project: %v", err)
	}
	if _, err := f.remove(wide, f.otherProject, view, 3); code(err) != model.NotFound {
		t.Fatalf("delete through another project: %v", err)
	}
	if v, _ = f.view(f.project, view); v.Revision != 3 {
		t.Fatalf("view changed through another project: %+v", v)
	}
}

// An organization administrator's own scope deletes a view without a read grant;
// it saves nothing, and the system runner may do neither.
func TestSavedViewAdministratorScopeDeletesOnly(t *testing.T) {
	f := newSVFx(t)
	bob := f.member("bob@example.test", f.project)
	view := model.NewID()
	f.mustSave(f.reader(bob.cred, f.project), f.project, view, 0, f.spec("bob's", "up"))

	admin := f.adminScope()
	if _, err := f.save(admin, f.project, model.NewID(), 0, f.spec("by admin scope", "up")); code(err) != model.Forbidden {
		t.Fatalf("an administrator scope saved a view: %v", err)
	}
	if _, err := f.save(admin, f.project, view, 1, f.spec("by admin scope", "up")); code(err) != model.Forbidden {
		t.Fatalf("an administrator scope updated a view: %v", err)
	}
	system, err := f.svc.AuthorizeSystem(f.ctx, f.org, []model.ID{f.project}, auth.OrgAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.remove(system, f.project, view, 1); code(err) != model.NotFound {
		t.Fatalf("the system runner deleted a view: %v", err)
	}
	if _, err = f.save(system, f.project, model.NewID(), 0, f.spec("by the runner", "up")); code(err) != model.NotFound {
		t.Fatalf("the system runner saved a view: %v", err)
	}
	if _, ok := f.view(f.project, view); !ok {
		t.Fatal("a refused delete removed the view")
	}
	// An administrator's scope for a project that does not exist is the same not-found.
	ghost := f.adminScopeFor(model.NewID())
	if _, err = f.remove(ghost, ghost.ProjectIDs()[0], view, 1); code(err) != model.NotFound {
		t.Fatalf("delete under an unknown project: %v", err)
	}
	if res, err := f.remove(f.adminScopeFor(f.project), f.project, view, 1); err != nil || res.Phase != "deleted:2" {
		t.Fatalf("administrator delete: %+v %v", res, err)
	}
}

func (f *svFx) adminScopeFor(project model.ID) auth.Scope {
	f.t.Helper()
	s, err := f.svc.Authorize(f.ctx, f.cred, f.org, []model.ID{project}, auth.OrgAdmin)
	if err != nil {
		f.t.Fatal(err)
	}
	return s
}

// The handler validates the scope against the state it commits in, for every
// project the command touches: a scope that names fewer projects than the query
// runs over, a grant revoked after the scope was minted and a member who lost
// the project are all the same not-found, and nothing is stored.
func TestSavedViewScopeIsValidatedAgainstTheCommittingState(t *testing.T) {
	f := newSVFx(t)
	narrow := f.reader(f.cred, f.project)
	if _, err := f.save(narrow, f.project, model.NewID(), 0, f.spec("wide", "up", f.project, f.otherProject)); code(err) != model.NotFound {
		t.Fatalf("a scope for one project saved a view over two: %v", err)
	}
	if _, err := f.save(narrow, f.otherProject, model.NewID(), 0, f.spec("elsewhere", "up", f.otherProject)); code(err) != model.NotFound {
		t.Fatalf("a scope for one project saved a view owned by another: %v", err)
	}
	ghost := model.NewID()
	if _, err := f.save(f.reader(f.cred, f.project), f.project, model.NewID(), 0, f.spec("ghost", "up", f.project, ghost)); code(err) != model.NotFound {
		t.Fatalf("a view over a project of no organization: %v", err)
	}
	if n := len(f.books()); n != 0 {
		t.Fatalf("refused commands stored %d views", n)
	}

	bob := f.member("bob@example.test", f.project)
	stale := f.reader(bob.cred, f.project)
	view := model.NewID()
	f.mustSave(stale, f.project, view, 0, f.spec("before the revocation", "up"))
	f.admin("grant", f.org, auth.AdminPayload{UserID: bob.id, ProjectID: f.project, Enabled: false, Reason: "revoked"})
	if _, err := f.save(stale, f.project, view, 1, f.spec("after the revocation", "up")); code(err) != model.NotFound {
		t.Fatalf("a scope minted before the revocation committed: %v", err)
	}
	if _, err := f.remove(stale, f.project, view, 1); code(err) != model.NotFound {
		t.Fatalf("a scope minted before the revocation deleted: %v", err)
	}
	if v, _ := f.view(f.project, view); v.Name != "before the revocation" || v.Revision != 1 {
		t.Fatalf("view after refused commands: %+v", v)
	}
}

// The handler re-checks the shape of the payload it applies: the service is not
// the only caller of Transact.
func TestSavedViewHandlerRefusesAMalformedCommand(t *testing.T) {
	f := newSVFx(t)
	scope := f.reader(f.cred, f.project)
	good := f.spec("n", "up")
	over := f.spec(strings.Repeat("n", auth.MaxSavedViewName+1), "up")
	// A zero ID cannot be marshalled from the DTO, so the payloads are written as maps.
	payload := func(edit func(map[string]any)) json.RawMessage {
		m := map[string]any{"operation": "save", "project": f.project.String(), "view": model.NewID().String(), "expected_revision": "0", "spec": good, "at": "5"}
		edit(m)
		raw, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	for name, tc := range map[string]struct {
		edit func(map[string]any)
		want model.Code
	}{
		"no operation":          {func(m map[string]any) { delete(m, "operation") }, model.Invalid},
		"unknown operation":     {func(m map[string]any) { m["operation"] = "rename" }, model.Invalid},
		"no project":            {func(m map[string]any) { delete(m, "project") }, model.Invalid},
		"no view":               {func(m map[string]any) { delete(m, "view") }, model.Invalid},
		"no time":               {func(m map[string]any) { m["at"] = "0" }, model.Invalid},
		"save without a spec":   {func(m map[string]any) { delete(m, "spec") }, model.Invalid},
		"delete with a spec":    {func(m map[string]any) { m["operation"], m["expected_revision"] = "delete", "1" }, model.Invalid},
		"delete at no revision": {func(m map[string]any) { m["operation"] = "delete"; delete(m, "spec") }, model.Invalid},
		"name past the bound":   {func(m map[string]any) { m["spec"] = over }, model.TooLarge},
		"an owner field":        {func(m map[string]any) { m["owner"] = f.user.String() }, model.Invalid},
		"an actor field":        {func(m map[string]any) { m["actor"] = f.user.String() }, model.Invalid},
		"a spec with no name":   {func(m map[string]any) { m["spec"] = f.spec("", "up") }, model.Invalid},
		"a view over no owner":  {func(m map[string]any) { m["spec"] = f.spec("n", "up", f.otherProject) }, model.Invalid},
	} {
		cmd := control.Command{CommandID: model.NewID(), ExpectedRevision: f.revision(), Kind: string(control.KindSavedView), Payload: payload(tc.edit)}
		if _, err := f.store.Transact(f.ctx, scope, cmd); code(err) != tc.want {
			t.Errorf("%s: %v, want %s", name, err, tc.want)
		}
	}
	huge := fmt.Sprintf(`{"operation":"save","pad":%q}`, strings.Repeat("x", 300<<10))
	if _, err := f.store.Transact(f.ctx, scope, control.Command{CommandID: model.NewID(), ExpectedRevision: f.revision(), Kind: string(control.KindSavedView), Payload: json.RawMessage(huge)}); code(err) != model.TooLarge {
		t.Errorf("an oversized payload: %v", err)
	}
	if n := len(f.books()); n != 0 {
		t.Fatalf("refused commands stored %d views", n)
	}
}

// At most 100 views per project, counted per project: the 101st is a quota
// fault (HTTP 429), never an eviction, and another project is not affected.
func TestSavedViewCapIsPerProject(t *testing.T) {
	f := newSVFx(t)
	scope := f.reader(f.cred, f.project, f.otherProject)
	ids := make([]model.ID, 0, auth.MaxSavedViewsPerProject)
	for i := range auth.MaxSavedViewsPerProject {
		id := model.NewID()
		if _, err := f.save(scope, f.project, id, 0, f.spec(fmt.Sprintf("view %d", i), "up")); err != nil {
			t.Fatalf("view %d of %d: %v", i+1, auth.MaxSavedViewsPerProject, err)
		}
		ids = append(ids, id)
	}
	if _, err := f.save(scope, f.project, model.NewID(), 0, f.spec("one too many", "up")); code(err) != model.Quota || svDetail(err) != control.SavedViewQuota {
		t.Fatalf("view %d: %v", auth.MaxSavedViewsPerProject+1, err)
	}
	if n := len(f.books()); n != auth.MaxSavedViewsPerProject {
		t.Fatalf("%d views stored, want %d", n, auth.MaxSavedViewsPerProject)
	}
	// The cap is on views, not on writes: a full project still updates a view.
	if _, err := f.save(scope, f.project, ids[7], 1, f.spec("renamed at the cap", "up")); err != nil {
		t.Fatalf("update at the cap: %v", err)
	}
	// Another project of the same organization has its own 100.
	if _, err := f.save(scope, f.otherProject, model.NewID(), 0, f.spec("other project", "up", f.otherProject)); err != nil {
		t.Fatalf("a full project filled another: %v", err)
	}
	// A delete makes room for exactly one.
	if _, err := f.remove(scope, f.project, ids[0], 1); err != nil {
		t.Fatal(err)
	}
	if _, err := f.save(scope, f.project, model.NewID(), 0, f.spec("fits again", "up")); err != nil {
		t.Fatalf("after a delete: %v", err)
	}
	if _, err := f.save(scope, f.project, model.NewID(), 0, f.spec("and not twice", "up")); code(err) != model.Quota {
		t.Fatalf("after refilling: %v", err)
	}
}

// Saving a view is a book write: it moves neither the organization's policy
// epoch (which would revoke every live stream and export of the organization)
// nor AuthorityRevision, and a scope minted before it stays valid.
func TestSavedViewCommitMovesNeitherEpochNorAuthorityRevision(t *testing.T) {
	f := newSVFx(t)
	scope := f.reader(f.cred, f.project)
	f.mustIntake()
	rev0, authority0, epoch0 := f.counters()
	if authority0 >= rev0 {
		t.Fatalf("fixture: revision %d authority %d", rev0, authority0)
	}
	view := model.NewID()
	f.mustSave(scope, f.project, view, 0, f.spec("a", "up"))
	f.mustSave(scope, f.project, view, 1, f.spec("b", "up"))
	if _, err := f.remove(scope, f.project, view, 2); err != nil {
		t.Fatal(err)
	}
	rev1, authority1, epoch1 := f.counters()
	if rev1 != rev0+3 {
		t.Fatalf("revision %d -> %d, want three commits", rev0, rev1)
	}
	if authority1 != authority0 {
		t.Fatalf("AuthorityRevision %d -> %d", authority0, authority1)
	}
	if epoch1 != epoch0 {
		t.Fatalf("policy epoch %d -> %d", epoch0, epoch1)
	}
	if err := f.svc.Revalidate(f.ctx, scope); err != nil {
		t.Fatalf("a scope minted before the saves was revoked by them: %v", err)
	}
}

// A save, an update and a delete each append one audit carrying the actor, the
// kind, the organization, the project and the view ID, and never the name or the
// expression; those live only in the view book.
func TestSavedViewAuditCarriesNoQueryText(t *testing.T) {
	f := newSVFx(t)
	scope := f.reader(f.cred, f.project)
	view := model.NewID()
	name, expr := "name "+svCanaryName, `up{token="`+svCanaryExpr+`"}`
	f.mustSave(scope, f.project, view, 0, f.spec(name, expr))
	f.mustSave(scope, f.project, view, 1, f.spec(name+" v2", expr+" == 1"))
	if _, err := f.remove(scope, f.project, view, 2); err != nil {
		t.Fatal(err)
	}
	var audits []control.Audit
	var all []byte
	if err := f.store.View(f.ctx, func(st control.State) error {
		for _, a := range st.Audits {
			if strings.HasPrefix(a.Action, "saved_view.") {
				audits = append(audits, a)
			}
		}
		var err error
		all, err = json.Marshal(st.Audits)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if len(audits) != 3 {
		t.Fatalf("%d saved-view audits, want 3: %+v", len(audits), audits)
	}
	for i, want := range []string{"saved_view.save", "saved_view.save", "saved_view.delete"} {
		a := audits[i]
		if a.Action != want || a.Principal != f.user || a.Org != f.org.String() || a.Outcome != model.AuditAllowed || len(a.Targets) != 2 || a.Targets[0] != f.project || a.Targets[1] != view || a.Reason == "" {
			t.Errorf("audit %d: %+v", i, a)
		}
	}
	if bytes.Contains(all, []byte(svCanaryName)) || bytes.Contains(all, []byte(svCanaryExpr)) {
		t.Fatalf("query text reached the audit log: %s", all)
	}
}

// A command ID that already committed answers with its first result and changes
// nothing: no second view, no second audit, no revision spent.
func TestSavedViewCommandReplayChangesNothing(t *testing.T) {
	f := newSVFx(t)
	scope := f.reader(f.cred, f.project)
	view := model.NewID()
	cmd := f.command(auth.SavedViewCommand{Operation: auth.SavedViewOpSave, Project: f.project, View: view, Spec: new(f.spec("once", "up"))})
	first, err := f.store.Transact(f.ctx, scope, cmd)
	if err != nil {
		t.Fatal(err)
	}
	revision, _, _ := f.counters()
	again, err := f.store.Transact(f.ctx, scope, cmd)
	if err != nil || again.Phase != first.Phase || again.Revision != first.Revision || len(again.AffectedIDs) != 1 || again.AffectedIDs[0] != view {
		t.Fatalf("replay: %+v %v, first %+v", again, err, first)
	}
	if after, _, _ := f.counters(); after != revision {
		t.Fatalf("a replay spent a revision: %d -> %d", revision, after)
	}
	if n := len(f.books()); n != 1 {
		t.Fatalf("%d views after a replay", n)
	}
	// Another principal cannot replay (or probe) the command.
	bob := f.member("bob@example.test", f.project)
	if _, err = f.store.Transact(f.ctx, f.reader(bob.cred, f.project), cmd); code(err) != model.NotFound {
		t.Fatalf("another principal replayed the command: %v", err)
	}
}

// CommitSavedView retries a command that only lost the race for the one global
// control revision, and returns a conflict the handler raised (a stale view
// revision) at once, unretried and typed.
func TestCommitSavedViewRetriesOnlyTheRevisionRace(t *testing.T) {
	f := newSVFx(t)
	scope := f.reader(f.cred, f.project)
	const writers = 8 // a writer can lose at most writers-1 races; the retry budget is 8
	var wg sync.WaitGroup
	errs := make([]error, writers)
	for i := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := auth.SavedViewCommand{Operation: auth.SavedViewOpSave, Project: f.project, View: model.NewID(), Spec: new(f.spec(fmt.Sprintf("racer %d", i), "up")), At: f.at()}
			raw, err := json.Marshal(c)
			if err != nil {
				errs[i] = err
				return
			}
			_, errs[i] = f.store.CommitSavedView(f.ctx, scope, control.Command{CommandID: model.NewID(), Kind: string(control.KindSavedView), Payload: raw})
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("racing writer %d: %v", i, err)
		}
	}
	if n := len(f.books()); n != writers {
		t.Fatalf("%d views after %d racing saves", n, writers)
	}

	view := model.NewID()
	f.mustSave(scope, f.project, view, 0, f.spec("v1", "up"))
	stale := auth.SavedViewCommand{Operation: auth.SavedViewOpSave, Project: f.project, View: view, ExpectedRevision: 5, Spec: new(f.spec("v?", "up")), At: f.at()}
	raw, _ := json.Marshal(stale)
	_, err := f.store.CommitSavedView(f.ctx, scope, control.Command{CommandID: model.NewID(), Kind: string(control.KindSavedView), Payload: raw})
	if code(err) != model.Conflict || svDetail(err) != control.SavedViewRevisionConflict {
		t.Fatalf("a stale view revision through CommitSavedView: %v", err)
	}
	if _, err = f.store.CommitSavedView(f.ctx, scope, control.Command{CommandID: model.NewID(), Kind: string(control.KindUpdateJob), Payload: raw}); code(err) != model.Invalid {
		t.Fatalf("another kind through CommitSavedView: %v", err)
	}
}

// A deletion that retires a project (or its organization) erases that project's
// saved views from the control state, the snapshot and control.db, and keeps
// another project's; a range or an entity deletion covers none (a view holds no
// telemetry). The retirement is the real saga.
func TestDeletionErasesSavedViewsOfTheRetiredProject(t *testing.T) {
	const (
		nameA, exprA = "NAMEAfe1c7de9b86a2d30", "EXPRAfe1c7de9b86a2d30"
		nameB, exprB = "NAMEBfe1c7de9b86a2d30", "EXPRBfe1c7de9b86a2d30"
	)
	seed := func(f *svFx) (a, b model.ID) {
		scope := f.reader(f.cred, f.project, f.otherProject)
		a, b = model.NewID(), model.NewID()
		f.mustSave(scope, f.project, a, 0, f.spec(nameA, `up{x="`+exprA+`"}`, f.project, f.otherProject))
		f.mustSave(scope, f.otherProject, b, 0, f.spec(nameB, `up{x="`+exprB+`"}`, f.otherProject))
		if !f.stateHolds(exprA) || !f.stateHolds(exprB) {
			t.Fatal("fixture: the expressions are not in the control state")
		}
		return a, b
	}
	t.Run("retire project", func(t *testing.T) {
		f := newSVFx(t)
		a, b := seed(f)
		f.saga(control.DeleteScope{Mode: model.DeleteRetireProject, Projects: []model.ID{f.project}})
		for _, canary := range []string{nameA, exprA} {
			f.expectGone(canary)
		}
		f.expectKept(nameB)
		f.expectKept(exprB)
		if _, ok := f.view(f.project, a); ok {
			t.Fatal("the retired project's view is stored")
		}
		if _, ok := f.view(f.otherProject, b); !ok {
			t.Fatal("another project's view was erased")
		}
		if n := len(f.books()); n != 1 {
			t.Fatalf("%d views left, want the other project's one", n)
		}
	})
	t.Run("retire org", func(t *testing.T) {
		f := newSVFx(t)
		seed(f)
		f.saga(control.DeleteScope{Mode: model.DeleteRetireOrg})
		for _, canary := range []string{nameA, exprA, nameB, exprB} {
			f.expectGone(canary)
		}
		if n := len(f.books()); n != 0 {
			t.Fatalf("%d views left of a retired organization", n)
		}
	})
	t.Run("historical range", func(t *testing.T) {
		f := newSVFx(t)
		seed(f)
		f.saga(f.lateRange())
		for _, canary := range []string{nameA, exprA, nameB, exprB} {
			f.expectKept(canary)
		}
	})
	t.Run("entity", func(t *testing.T) {
		f := newSVFx(t)
		seed(f)
		f.saga(control.DeleteScope{Mode: model.DeleteEntity, Projects: []model.ID{f.project}, Entities: []model.ID{model.NewID()}})
		for _, canary := range []string{nameA, exprA, nameB, exprB} {
			f.expectKept(canary)
		}
	})
	t.Run("unattributable key", func(t *testing.T) {
		f := newSVFx(t)
		seed(f)
		if err := f.store.Update(f.ctx, func(st *control.State) error {
			st.SavedViewBooks["not-a-key"] = json.RawMessage(`{"name":"ORPHANCANARYa1b2c3"}`)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		f.saga(control.DeleteScope{Mode: model.DeleteRetireOrg})
		if _, ok := f.books()["not-a-key"]; !ok {
			t.Fatal("a key that names no project was dropped by an erasure it does not belong to")
		}
	})
}

// A state that holds no saved view encodes exactly as it did before the books
// existed (the key is omitted, not null), so no digest, snapshot or golden of an
// older state changes.
func TestStateWithoutSavedViewsEncodesAsBefore(t *testing.T) {
	f := newSVFx(t)
	encode := func() string {
		var raw []byte
		if err := f.store.View(f.ctx, func(st control.State) error {
			var err error
			raw, err = json.Marshal(st)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	if raw, err := json.Marshal(control.State{Installation: model.NewID()}); err != nil || strings.Contains(string(raw), "SavedViewBooks") {
		t.Fatalf("an empty state: %v %s", err, raw)
	}
	if strings.Contains(encode(), "SavedViewBooks") {
		t.Fatal("a state with no saved view carries the key")
	}
	view := model.NewID()
	scope := f.reader(f.cred, f.project)
	f.mustSave(scope, f.project, view, 0, f.spec("n", "up"))
	if !strings.Contains(encode(), `"SavedViewBooks":{"`) {
		t.Fatal("a state with a saved view lacks the books")
	}
	if _, err := f.remove(scope, f.project, view, 1); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(encode(), "SavedViewBooks") {
		t.Fatal("a state whose last view was deleted still carries the key")
	}
}

// The books are part of the replicated control state, so a seed for a new voter
// and a restart carry them whole.
func TestSavedViewsAreCarriedBySeedAndRestart(t *testing.T) {
	f := newSVFx(t)
	scope := f.reader(f.cred, f.project, f.otherProject)
	a, b := model.NewID(), model.NewID()
	f.mustSave(scope, f.project, a, 0, f.spec("carried "+svCanaryName, "up{x=\""+svCanaryExpr+"\"}", f.project, f.otherProject))
	f.mustSave(scope, f.otherProject, b, 0, f.spec("other", "up", f.otherProject))
	f.mustSave(scope, f.project, a, 1, f.spec("carried v2", "up"))
	want := f.books()
	if len(want) != 2 {
		t.Fatalf("fixture: %d views", len(want))
	}
	same := func(where string, got map[string]json.RawMessage) {
		t.Helper()
		if len(got) != len(want) {
			t.Fatalf("%s: %d views, want %d", where, len(got), len(want))
		}
		for key, raw := range want {
			if !bytes.Equal(got[key], raw) {
				t.Fatalf("%s: view %s differs:\n got %s\nwant %s", where, key, got[key], raw)
			}
		}
	}

	seed, _, err := f.store.ReplicationSeed()
	if err != nil {
		t.Fatal(err)
	}
	seeded, err := control.OpenSeed(t.TempDir(), seed)
	if err != nil {
		t.Fatal(err)
	}
	defer seeded.Close()
	if err = seeded.View(f.ctx, func(st control.State) error { same("seed", st.SavedViewBooks); return nil }); err != nil {
		t.Fatal(err)
	}

	if err = f.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := control.Open(f.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err = reopened.EnableSingle(f.ctx, filepath.Join(f.dir, "raft-control")); err != nil {
		t.Fatal(err)
	}
	if err = reopened.View(f.ctx, func(st control.State) error { same("restart", st.SavedViewBooks); return nil }); err != nil {
		t.Fatal(err)
	}
}
