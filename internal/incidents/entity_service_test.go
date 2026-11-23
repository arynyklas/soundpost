// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package incidents_test

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/incidents"
	"github.com/arynyklas/soundpost/internal/model"
)

// member is a user holding exactly one grant on one project of the fixture's organization.
type member struct {
	cred auth.Credential
}

// addMember creates the user and its grant. A scope is invalidated by any later administration
// command (the policy epoch moves), so derive scopes with scopeOf only after every member exists.
func (f *fx) addMember(project model.ID, perm auth.Permission) member {
	f.t.Helper()
	user, email, password := model.NewID(), model.NewID().String()[:12]+"@example.test", "a member test password 2026"
	f.admin("create_user", f.org, auth.AdminPayload{ID: user, Email: email, Password: password, Reason: "fixture"})
	f.admin("membership", f.org, auth.AdminPayload{UserID: user, Enabled: true, Reason: "fixture"})
	f.admin("grant", f.org, auth.AdminPayload{UserID: user, ProjectID: project, Enabled: true, Permissions: []string{string(perm)}, Reason: "fixture"})
	login, err := f.auth.Login(f.ctx, email, password, "")
	if err != nil {
		f.t.Fatal(err)
	}
	return member{cred: f.credential(login.Token)}
}

func (f *fx) scopeOf(m member, project model.ID, perm auth.Permission) auth.Scope {
	f.t.Helper()
	scope, err := f.auth.Authorize(f.ctx, m.cred, f.org, []model.ID{project}, perm)
	if err != nil {
		f.t.Fatal(err)
	}
	return scope
}

func (f *fx) typed(id model.ID, version model.Revision, typ incidents.Type) incidents.Action {
	return incidents.Action{CommandID: model.NewID(), ExpectedVersion: version, Type: typ, Origin: incidents.OriginHuman, Target: f.target(id)}
}

func (f *fx) title(id model.ID, version model.Revision, text string) incidents.Action {
	a := f.typed(id, version, incidents.TypeTitle)
	a.Title = text
	return a
}

func (f *fx) note(id model.ID, version model.Revision, text string) incidents.Action {
	a := f.typed(id, version, incidents.TypeNote)
	a.Note = text
	return a
}

func (f *fx) actAs(scope auth.Scope, a incidents.Action) (incidents.State, error) {
	return f.svc.Act(f.ctx, scope, a, model.UnixNano(f.now.UnixNano()))
}

func (f *fx) auditsAndIntentsHold(text string, id model.ID) (inAudits, inIntents, inOtherBooks bool) {
	f.t.Helper()
	if err := f.store.View(f.ctx, func(st control.State) error {
		raw, _ := json.Marshal(st.Audits)
		inAudits = strings.Contains(string(raw), text)
		books := st.IncidentBooks
		st.IncidentBooks = nil
		rest, _ := json.Marshal(st)
		inOtherBooks = strings.Contains(string(rest), text)
		st.IncidentBooks = books
		return nil
	}); err != nil {
		f.t.Fatal(err)
	}
	intents, _ := json.Marshal(f.record(id).Intents)
	inIntents = strings.Contains(string(intents), text)
	return
}

func TestIncidentTitleNoteAndExternalThroughTheService(t *testing.T) {
	f := newFx(t)
	id := model.ID{0x91}
	f.openIncident(id)
	w, rd := f.addMember(f.project, auth.IncidentsWrite), f.addMember(f.project, auth.Read)
	writer, reader := f.scopeOf(w, f.project, auth.IncidentsWrite), f.scopeOf(rd, f.project, auth.Read)

	// A member holding only incidents.write names the incident: Service.Act trims, then validates.
	titled, err := f.actAs(writer, f.title(id, 1, "  Payment errors in eu-west  "))
	if err != nil || titled.Title != "Payment errors in eu-west" || titled.Timeline[1].Action.Title != "Payment errors in eu-west" || titled.Version != 2 {
		t.Fatalf("title: %+v %v", titled, err)
	}
	if _, err = f.actAs(writer, f.title(id, 2, " \t ")); detailOf(err) != "incident_title_invalid" {
		t.Fatalf("a blank title: %v", err)
	}
	noted, err := f.actAs(writer, f.note(id, 2, "Customer-facing: checkout returns 502 for ~3% of requests.\nOwner paged."))
	if err != nil || noted.Version != 3 || noted.Timeline[2].Action.Note == "" {
		t.Fatalf("note: %+v %v", noted, err)
	}

	// Another actor's stale view loses the race with the current version, never a silent overwrite.
	_, err = f.actAs(writer, f.note(id, 2, "stale"))
	if current, ok := incidents.IsVersionConflict(err); !ok || current != 3 {
		t.Fatalf("stale note: %v", err)
	}

	// External link through the service: begin, then end.
	marker := model.ExternalMarker(f.org, "incident", id)
	now := model.UnixNano(f.now.UnixNano())
	begin := f.typed(id, 3, incidents.TypeExternalBegin)
	begin.External = &model.ExternalOp{Provider: "gitlab", Kind: model.ExternalBegin, Marker: marker, Project: "shop/web", Until: now + 60*sec}
	st, err := f.actAs(writer, begin)
	if err != nil || len(st.External) != 1 || st.External[0].State != model.ExternalCreating || st.External[0].Actor != writer.PrincipalID() {
		t.Fatalf("begin: %+v %v", st.External, err)
	}
	again := f.typed(id, 4, incidents.TypeExternalBegin)
	again.External = begin.External
	if _, err = f.actAs(writer, again); detailOf(err) != "external_in_progress" {
		t.Fatalf("a second begin: %v", err)
	}
	end := f.typed(id, 4, incidents.TypeExternalEnd)
	end.External = &model.ExternalOp{Provider: "gitlab", Kind: model.ExternalEnd, Marker: marker, Project: "shop/web", Result: model.ExternalLinked, IID: 12, URL: "https://git.example.test/shop/web/-/issues/12"}
	st, err = f.actAs(writer, end)
	if err != nil || st.External[0].State != model.ExternalLinked || st.External[0].IID != 12 || st.Version != 5 {
		t.Fatalf("end: %+v %v", st.External, err)
	}

	// A reader sees the title, the note and the link, and cannot add any of them.
	seen, err := f.svc.Get(f.ctx, reader, f.project, id)
	if err != nil || seen.Title != "Payment errors in eu-west" || seen.Timeline[2].Action.Note == "" || len(seen.External) != 1 {
		t.Fatalf("reader sees %+v %v", seen, err)
	}
	for _, a := range []incidents.Action{f.title(id, 5, "x"), f.note(id, 5, "x"), begin} {
		if _, err = f.actAs(reader, a); !isCode(err, model.Forbidden) {
			t.Fatalf("a reader's %s: %v", a.Type, err)
		}
	}

	// The retry of a committed note returns the original state, not a second note.
	retry := f.note(id, 5, "once")
	first, err := f.actAs(writer, retry)
	if err != nil {
		t.Fatal(err)
	}
	second, err := f.svc.Act(f.ctx, writer, retry, 12345)
	if err != nil || !reflect.DeepEqual(first, second) || f.get(id).Version != 6 {
		t.Fatalf("retry: %+v %v", second, err)
	}
	// And the state is exactly the replay of the timeline the control group holds.
	replayed, err := incidents.Replay(f.get(id).Timeline)
	if err != nil || !reflect.DeepEqual(replayed, f.get(id)) {
		t.Fatalf("not a replay: %v", err)
	}
}

func detailOf(err error) string {
	var f *model.Fault
	if errors.As(err, &f) {
		return f.SafeDetail
	}
	return ""
}

// A writer without a grant on the project, one whose grant was revoked and a stranger all get
// the answer a missing incident gets, and change nothing.
func TestIncidentEntityActionsAreScoped(t *testing.T) {
	f := newFx(t)
	id := model.ID{0x92}
	f.openIncident(id)
	otherProject := model.NewID()
	f.admin("create_project", f.org, auth.AdminPayload{ID: otherProject, Name: "p2", Reason: "fixture"})
	fm, gm := f.addMember(otherProject, auth.IncidentsWrite), f.addMember(f.project, auth.IncidentsWrite)
	foreign, granted := f.scopeOf(fm, otherProject, auth.IncidentsWrite), f.scopeOf(gm, f.project, auth.IncidentsWrite)

	missing := f.note(model.ID{0x93}, 1, "x")
	_, missingErr := f.actAs(foreign, missing)
	for name, a := range map[string]incidents.Action{
		"title": f.title(id, 1, "hijacked"),
		"note":  f.note(id, 1, "hijacked"),
	} {
		_, err := f.actAs(foreign, a)
		if err == nil || err.Error() == "" || !isCode(err, model.NotFound) || detailOf(err) != detailOf(missingErr) {
			t.Fatalf("%s through a grant on another project: %v (a missing incident: %v)", name, err, missingErr)
		}
	}
	if s := f.get(id); s.Version != 1 || s.Title != "" {
		t.Fatalf("a foreign write changed the incident: %+v", s)
	}

	// Revoking the grant ends the right to write at once.
	f.admin("grant", f.org, auth.AdminPayload{UserID: granted.PrincipalID(), ProjectID: f.project, Enabled: false, Permissions: []string{string(auth.IncidentsWrite)}, Reason: "fixture"})
	if _, err := f.actAs(granted, f.title(id, 1, "after revoke")); err == nil {
		t.Fatal("a revoked grant still wrote a title")
	}
	if s := f.get(id); s.Version != 1 {
		t.Fatalf("a revoked writer changed the incident: %+v", s)
	}
}

// The text of a title or a note lives in the incident state and nowhere else: not in an audit,
// not in an intent, not in any other book of the control state.
func TestIncidentTitleAndNoteTextIsNeverAuditedOrQueued(t *testing.T) {
	f := newFx(t)
	id := model.ID{0x94}
	f.openIncident(id)
	title, note := "TITLE-SENTINEL-8f3a", "NOTE-SENTINEL-1c9d with <markup> & \"quotes\""
	f.mustAct(f.a, f.title(id, 1, title))
	f.mustAct(f.a, f.note(id, 2, note))
	f.mustAct(f.a, f.human(f.a, id, 3, incidents.TypeResolve, "done"))
	f.mustAct(f.a, f.note(id, 4, "NOTE-SENTINEL-AFTER-RESOLVE"))

	for _, text := range []string{"TITLE-SENTINEL-8f3a", "NOTE-SENTINEL-1c9d", "NOTE-SENTINEL-AFTER-RESOLVE"} {
		if a, i, o := f.auditsAndIntentsHold(text, id); a || i || o {
			t.Fatalf("%s leaked: audits=%v intents=%v other books=%v", text, a, i, o)
		}
		if !strings.Contains(string(f.record(id).State), text) {
			t.Fatalf("%s is not in the incident state", text)
		}
	}
	// The audit records who and what, with a static reason.
	var actions []string
	_ = f.store.View(f.ctx, func(st control.State) error {
		for _, a := range st.Audits {
			if strings.HasPrefix(a.Action, "incidents.") && len(a.Targets) == 1 && a.Targets[0] == id {
				actions = append(actions, a.Action+"|"+a.Reason)
			}
		}
		return nil
	})
	want := []string{"incidents.open|incident action", "incidents.title|incident action", "incidents.note|incident action", "incidents.resolve|incident action", "incidents.note|incident action"}
	if !reflect.DeepEqual(actions, want) {
		t.Fatalf("audits %v, want %v", actions, want)
	}
}

// Erasure of an incident's state erases its title and notes with it: they live only in the state
// and the entry carries `at`, which is what a range deletion's window reads. Real erase path: a
// completed historical range deletion over the project.
func TestIncidentTitleAndNotesAreErasedWithTheStateByARangeDeletion(t *testing.T) {
	f := newFx(t)
	id, survivor := model.ID{0x95}, model.ID{0x96}
	// The survivor is written at the opening time, outside the range deleted below.
	f.openIncident(survivor)
	f.mustAct(f.a, f.title(survivor, 1, "KEPT-TITLE"))
	f.mustAct(f.a, f.note(survivor, 2, "KEPT-NOTE"))
	f.openIncident(id)
	opened := model.UnixNano(f.now.UnixNano())
	f.mustAct(f.a, f.title(id, 1, "ERASE-TITLE-SENTINEL"))
	f.now = f.now.Add(10 * time.Minute) // a later note: the window of the incident spans [opened, opened+10m]
	f.mustAct(f.a, f.note(id, 2, "ERASE-NOTE-SENTINEL"))
	noteAt := model.UnixNano(f.now.UnixNano())
	if noteAt <= opened {
		t.Fatal("fixture clock")
	}

	// A range over the note's own time only (not over the opening) covers the incident: the window rule.
	f.completedRange(noteAt-model.UnixNano(time.Minute), noteAt+model.UnixNano(time.Minute))

	got, err := f.svc.Get(f.ctx, f.scope(f.a), f.project, id)
	if err != nil || !got.Erased || got.Title != "" || len(got.Timeline) != 0 {
		t.Fatalf("the incident reads as %+v (%v)", got, err)
	}
	for _, text := range []string{"ERASE-TITLE-SENTINEL", "ERASE-NOTE-SENTINEL"} {
		if strings.Contains(string(f.record(id).State), text) {
			t.Fatalf("%s survives in the incident record", text)
		}
		if err := f.store.View(f.ctx, func(st control.State) error {
			raw, _ := json.Marshal(st)
			if strings.Contains(string(raw), text) {
				t.Fatalf("%s survives somewhere in the control state", text)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = f.act(f.a, f.note(id, 2, "after erase")); !incidents.IsErased(err) {
		t.Fatalf("a note on an erased incident: %v", err)
	}

	// An incident the deletion does not cover keeps its title and notes.
	if s := f.get(survivor); s.Erased || s.Title != "KEPT-TITLE" || s.Timeline[2].Action.Note != "KEPT-NOTE" {
		t.Fatalf("an incident outside the range lost its text: %+v", s)
	}
}

// Through the real control group (which refuses a state above 256 KiB): an incident full of the
// largest, escape-heavy notes and titles can still be acknowledged and resolved.
func TestIncidentCanStillBeAcknowledgedAndResolvedWithTheNoteBudgetFull(t *testing.T) {
	f := newFx(t)
	id := model.ID{0x97}
	f.openIncident(id)
	version := model.Revision(1)
	heavy := strings.Repeat("<", incidents.MaxNoteBytes)
	for {
		st, err := f.act(f.a, f.note(id, version, heavy))
		if err != nil {
			if detailOf(err) != "incident_notes_full" {
				t.Fatalf("note %d: %v", version, err)
			}
			break
		}
		version = st.Version
	}
	for i := 0; int(version) < incidents.MaxTimeline-incidents.TimelineReserve; i++ {
		st, err := f.act(f.a, f.title(id, version, strings.Repeat("<", incidents.MaxTitleBytes-1)+string(rune('a'+i%2))))
		if err != nil {
			t.Fatalf("title at version %d: %v", version, err)
		}
		version = st.Version
	}
	if _, err := f.act(f.a, f.title(id, version, strings.Repeat("<", incidents.MaxTitleBytes))); detailOf(err) != "incident_timeline_full" {
		t.Fatalf("the reserve was not kept: %v", err)
	}
	acked, err := f.act(f.a, f.human(f.a, id, version, incidents.TypeAck, ""))
	if err != nil {
		t.Fatalf("ack with the budget full: %v", err)
	}
	resolved, err := f.act(f.a, f.human(f.a, id, acked.Version, incidents.TypeResolve, strings.Repeat("<", incidents.MaxReasonBytes)))
	if err != nil || resolved.Status != incidents.StatusResolved {
		t.Fatalf("resolve with the budget full: %v", err)
	}
	raw := f.record(id).State
	t.Logf("committed worst-case state: %d of %d bytes", len(raw), controlStateLimit)
}
