// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

// dirFixture is a cacheFixture with a second project and a few members:
// reader of p (grant), reader of q (grant on the second project), a member without any grant, and a
// member that is only in a team of p.
type dirFixture struct {
	*cacheFixture
	q                                      model.ID
	readerP, readerQ, bare, teamed         auth.Credential
	readerPID, readerQID, bareID, teamedID model.ID
}

func newDirFixture(t *testing.T) *dirFixture {
	t.Helper()
	d := &dirFixture{cacheFixture: newCacheFixture(t), q: model.NewID()}
	d.cmd("create_project", auth.AdminPayload{ID: d.q, Name: "second"})
	d.readerP, d.readerPID = d.reader("dir-p@example.test", auth.Read)
	d.readerQ, d.readerQID = d.member("dir-q@example.test", d.q, auth.Read)
	d.bare, d.bareID = d.member("dir-bare@example.test", model.ID{})
	d.teamed, d.teamedID = d.member("dir-team@example.test", model.ID{})
	team, _ := json.Marshal(model.ControlTeam{Members: []model.ID{d.teamedID}, Projects: []model.ID{d.project}, Permissions: []string{"telemetry.read"}, Enabled: true})
	d.cmd("team", auth.AdminPayload{ID: model.NewID(), Config: team})
	return d
}

// member creates a member with a grant on project (none when zero) and logs it in.
func (d *dirFixture) member(email string, project model.ID, permissions ...auth.Permission) (auth.Credential, model.ID) {
	d.t.Helper()
	id := model.NewID()
	d.cmd("create_user", auth.AdminPayload{ID: id, Email: email, Password: "cache reader password"})
	d.cmd("membership", auth.AdminPayload{UserID: id, Enabled: true})
	if project != (model.ID{}) {
		ps := make([]string, len(permissions))
		for i, p := range permissions {
			ps[i] = string(p)
		}
		d.cmd("grant", auth.AdminPayload{UserID: id, ProjectID: project, Enabled: true, Permissions: ps})
	}
	login, err := d.service.Login(d.ctx, email, "cache reader password", "")
	if err != nil {
		d.t.Fatal(err)
	}
	c, err := d.service.Authenticate(d.ctx, login.Token)
	if err != nil {
		d.t.Fatal(err)
	}
	return c, id
}

func (d *dirFixture) read(c auth.Credential, org model.ID, projects ...model.ID) (auth.DirectoryView, error) {
	return d.service.Directory(d.ctx, c, auth.DirectoryRequest{Org: org, Projects: projects})
}

func memberIDs(v auth.DirectoryView) map[model.ID]auth.DirectoryMember {
	out := map[model.ID]auth.DirectoryMember{}
	for _, m := range v.Members {
		out[m.ID] = m
	}
	return out
}

func projectIDs(v auth.DirectoryView) map[model.ID]string {
	out := map[model.ID]string{}
	for _, p := range v.Projects {
		out[p.ID] = p.Name
	}
	return out
}

func TestDirectoryAdministratorSeesEverythingMemberSeesItsOwnProjects(t *testing.T) {
	d := newDirFixture(t)

	admin, err := d.read(d.actor, d.org)
	if err != nil {
		t.Fatal(err)
	}
	if ps := projectIDs(admin); len(ps) != 2 || ps[d.project] != "p" || ps[d.q] != "second" {
		t.Fatalf("an administrator sees every project: %+v", admin.Projects)
	}
	ms := memberIDs(admin)
	for _, id := range []model.ID{d.readerPID, d.readerQID, d.bareID, d.teamedID} {
		m, ok := ms[id]
		if !ok || m.Email == "" || m.Admin == nil || m.Enabled == nil || !*m.Enabled || *m.Admin {
			t.Fatalf("an administrator sees member %s with e-mail, admin and enabled: %+v", id, m)
		}
	}
	if !admin.CanSetNames {
		t.Fatal("an administrator may set names")
	}

	// A member of project p: p only; the members of p (grant and team) and the administrators; never
	// the member of q, never the member without any grant, and never an e-mail address or a flag.
	view, err := d.read(d.readerP, d.org)
	if err != nil {
		t.Fatal(err)
	}
	if ps := projectIDs(view); len(ps) != 1 || ps[d.project] != "p" {
		t.Fatalf("a member sees only the project it holds a grant on: %+v", view.Projects)
	}
	ms = memberIDs(view)
	if _, ok := ms[d.readerPID]; !ok {
		t.Fatal("the caller resolves itself")
	}
	if _, ok := ms[d.teamedID]; !ok {
		t.Fatal("a member of a team on the project is a member of the project")
	}
	if _, ok := ms[d.readerQID]; ok {
		t.Fatal("a member holding grants only on another project is not visible")
	}
	if _, ok := ms[d.bareID]; ok {
		t.Fatal("a member without any grant is not visible to a project member")
	}
	sawAdmin := false
	for _, m := range view.Members {
		if m.Email != "" || m.Admin != nil || m.Enabled != nil {
			t.Fatalf("a plain member never sees e-mail, admin or enabled: %+v", m)
		}
		if _, isAdmin := d.adminSet()[m.ID]; isAdmin {
			sawAdmin = true
		}
	}
	if !sawAdmin {
		t.Fatal("the organization administrators resolve for every member")
	}
	raw, _ := json.Marshal(view)
	for _, secret := range []string{"@example.test", "grant", "telemetry.read", "password"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("the directory leaked %q: %s", secret, raw)
		}
	}

	// A project filter only narrows.
	narrow, err := d.read(d.readerP, d.org, d.project, d.q)
	if err != nil || len(narrow.Projects) != 1 || narrow.Projects[0].ID != d.project {
		t.Fatalf("a filter naming a project the caller has no grant on must not show it: %+v %v", narrow.Projects, err)
	}
	if only, err := d.read(d.actor, d.org, d.q); err != nil || len(only.Projects) != 1 || only.Projects[0].ID != d.q {
		t.Fatalf("an administrator's filter: %+v %v", only.Projects, err)
	}
}

// adminSet is the organization administrators of the fixture's organization.
func (d *dirFixture) adminSet() map[model.ID]bool {
	out := map[model.ID]bool{}
	_ = d.store.View(d.ctx, func(st control.State) error {
		for id, on := range st.Orgs[d.org.String()].Admins {
			if on {
				if parsed, err := model.ParseID(id); err == nil {
					out[parsed] = true
				}
			}
		}
		return nil
	})
	return out
}

func TestDirectoryMemberWithoutAnyGrantSeesNoProjects(t *testing.T) {
	d := newDirFixture(t)
	view, err := d.read(d.bare, d.org)
	if err != nil {
		t.Fatal(err)
	}
	if len(view.Projects) != 0 || view.Projects == nil {
		t.Fatalf("no grant, no project (and an empty list, not null): %+v", view.Projects)
	}
	if ms := memberIDs(view); len(ms) < 2 { // itself and the administrator
		t.Fatalf("the member resolves itself and the administrators: %+v", view.Members)
	}
	// A grant with no permission is not a grant.
	d.cmd("grant", auth.AdminPayload{UserID: d.bareID, ProjectID: d.project, Enabled: true, Permissions: []string{}})
	if view, err = d.read(d.bare, d.org); err != nil || len(view.Projects) != 0 {
		t.Fatalf("an empty grant shows a project: %+v %v", view.Projects, err)
	}
}

func TestDirectoryScopeIsolationAndRetirement(t *testing.T) {
	d := newDirFixture(t)
	other := d.otherOrg()
	_, errMissing := d.read(d.readerP, model.NewID())
	_, errOther := d.read(d.readerP, other)
	if code(errOther) != model.NotFound || !sameDenial(errOther, errMissing) {
		t.Fatalf("a user of org A asking for org B must be told what a missing organization is told: %v / %v", errOther, errMissing)
	}
	// The administrator of both organizations never sees users of the other as members of this one.
	org2, err := d.read(d.actor, other)
	if err != nil {
		t.Fatal(err)
	}
	ms := memberIDs(org2)
	for _, id := range []model.ID{d.readerPID, d.readerQID, d.bareID, d.teamedID} {
		if _, ok := ms[id]; ok {
			t.Fatalf("a user who is not a member of the organization is listed: %s", id)
		}
	}
	for _, m := range org2.Members {
		if strings.Contains(m.Email, "dir-") {
			t.Fatalf("e-mail of a user of another organization: %+v", m)
		}
	}
	if len(org2.Projects) != 0 {
		t.Fatalf("projects of another organization: %+v", org2.Projects)
	}

	// A disabled membership neither reads nor is listed for a plain member; the administrator lists it as not enabled.
	d.cmd("membership", auth.AdminPayload{UserID: d.teamedID, Enabled: false})
	if _, err = d.read(d.teamed, d.org); code(err) != model.NotFound {
		t.Fatalf("a disabled member read the directory: %v", err)
	}
	view, err := d.read(d.readerP, d.org)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := memberIDs(view)[d.teamedID]; ok {
		t.Fatal("a disabled member is listed for a plain member")
	}
	admin, _ := d.read(d.actor, d.org)
	if m, ok := memberIDs(admin)[d.teamedID]; !ok || m.Enabled == nil || *m.Enabled {
		t.Fatalf("an administrator sees the disabled member as not enabled: %+v", m)
	}

	// A retired project is gone, a retired organization is not found.
	if err = d.store.Update(d.ctx, func(st *control.State) error {
		o := st.Orgs[d.org.String()]
		delete(o.Projects, d.q.String())
		st.Orgs[d.org.String()] = o
		if st.RetiredProjects == nil {
			st.RetiredProjects = map[string]model.ID{}
		}
		st.RetiredProjects[d.org.String()+":"+d.q.String()] = model.NewID()
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if admin, _ = d.read(d.actor, d.org); len(admin.Projects) != 1 || admin.Projects[0].ID != d.project {
		t.Fatalf("a retired project is listed: %+v", admin.Projects)
	}
	if err = d.store.Update(d.ctx, func(st *control.State) error {
		delete(st.Orgs, d.org.String())
		if st.RetiredOrgs == nil {
			st.RetiredOrgs = map[string]model.ID{}
		}
		st.RetiredOrgs[d.org.String()] = model.NewID()
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = d.read(d.actor, d.org); code(err) != model.NotFound {
		t.Fatalf("a retired organization: %v", err)
	}
}

func TestDirectoryRefusesServerTokensAndBadFilters(t *testing.T) {
	d := newDirFixture(t)
	issued, err := d.service.IssueServerToken(d.ctx, d.actor, d.org, d.readerPID, []model.ID{d.project}, []auth.Permission{auth.Read}, d.at().Add(time.Hour).Unix(), "directory token")
	if err != nil {
		t.Fatal(err)
	}
	machine, err := d.service.Authenticate(d.ctx, issued.Token)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.read(machine, d.org); code(err) != model.Forbidden {
		t.Fatalf("a server token is not a console principal: %v", err)
	}
	if _, err = d.read(d.readerP, model.ID{}); code(err) != model.Invalid {
		t.Fatalf("no org: %v", err)
	}
	if _, err = d.read(d.readerP, d.org, d.project, d.project); code(err) != model.Invalid {
		t.Fatalf("duplicate projects: %v", err)
	}
}

// The directory names the caller's own organization (the console titles its sidebar with it) and no other: an administrator and every
// kind of member read the stored name of the organization they belong to, and a user of another organization is told what a missing
// organization is told, so no answer to such a user carries the name of an organization it does not belong to.
func TestDirectoryOrgNameIsTheCallersOwnOrganizationsOnly(t *testing.T) {
	d := newDirFixture(t)
	other := d.otherOrg()
	const own, foreign = "cache org", "other org"
	for who, c := range map[string]auth.Credential{
		"administrator": d.actor, "reader": d.readerP, "reader of the second project": d.readerQ,
		"member without a grant": d.bare, "member of a team": d.teamed,
	} {
		view, err := d.read(c, d.org)
		if err != nil {
			t.Fatalf("%s: %v", who, err)
		}
		if view.Org != d.org || view.OrgName != own {
			t.Fatalf("%s read organization %s named %q, want %s named %q", who, view.Org, view.OrgName, d.org, own)
		}
		wire, err := json.Marshal(view)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(wire), `"org_name":"`+own+`"`) || strings.Contains(string(wire), foreign) {
			t.Fatalf("%s: the answer on the wire is %s", who, wire)
		}
	}
	// The administrator of both organizations reads each one's own name; a project filter changes nothing about it.
	view, err := d.read(d.actor, other)
	if err != nil || view.Org != other || view.OrgName != foreign {
		t.Fatalf("the other organization read by its administrator: %+v %v, want it named %q", view, err, foreign)
	}
	if view, err = d.read(d.actor, d.org, d.project); err != nil || view.OrgName != own {
		t.Fatalf("a filtered read named %q: %v, want %q", view.OrgName, err, own)
	}
	// A user who belongs only to the first organization, asking for the second, is refused exactly as for an organization that does not
	// exist: there is no answer, so there is no name.
	_, errMissing := d.read(d.readerP, model.NewID())
	view, errOther := d.read(d.readerP, other)
	if code(errOther) != model.NotFound || !sameDenial(errOther, errMissing) {
		t.Fatalf("a member of organization A asking for organization B must be told what a missing organization is told: %v / %v", errOther, errMissing)
	}
	if wire, _ := json.Marshal(view); view.OrgName != "" || view.Org != (model.ID{}) || strings.Contains(string(wire), foreign) {
		t.Fatalf("the refusal carries an organization: %s", wire)
	}
}

func (d *dirFixture) setName(c auth.Credential, org, user model.ID, name string, command model.ID) (model.ControlResult, error) {
	return d.service.SetMemberName(d.ctx, c, auth.MemberNameCommand{CommandID: command, Org: org, User: user, DisplayName: name})
}

func TestMemberNamesSetOwnAnyByAdministratorNeverAnotherMembers(t *testing.T) {
	d := newDirFixture(t)
	nameOf := func(c auth.Credential, id model.ID) string {
		v, err := d.read(c, d.org)
		if err != nil {
			t.Fatal(err)
		}
		return memberIDs(v)[id].DisplayName
	}
	if _, err := d.setName(d.readerP, d.org, d.readerPID, "Alice Example", model.NewID()); err != nil {
		t.Fatalf("a member sets its own name: %v", err)
	}
	if got := nameOf(d.teamed, d.readerPID); got != "Alice Example" {
		t.Fatalf("the name resolves for the project's members: %q", got)
	}
	if _, err := d.setName(d.readerP, d.org, d.teamedID, "Forged", model.NewID()); code(err) != model.Forbidden {
		t.Fatalf("a member set another member's name: %v", err)
	}
	if _, err := d.setName(d.readerP, d.org, d.actorID(), "Forged", model.NewID()); code(err) != model.Forbidden {
		t.Fatalf("a member set an administrator's name: %v", err)
	}
	if got := nameOf(d.readerP, d.teamedID); got != "" {
		t.Fatalf("the refused command changed a name: %q", got)
	}
	if _, err := d.setName(d.actor, d.org, d.teamedID, "Team Member", model.NewID()); err != nil {
		t.Fatalf("an administrator sets anyone's name: %v", err)
	}
	if got := nameOf(d.readerP, d.teamedID); got != "Team Member" {
		t.Fatalf("admin-set name: %q", got)
	}
	// An administrator names an administrator too (itself), and clears.
	if _, err := d.setName(d.actor, d.org, d.actorID(), "Owner", model.NewID()); err != nil {
		t.Fatal(err)
	}
	if got := nameOf(d.readerP, d.actorID()); got != "Owner" {
		t.Fatalf("the administrator's name resolves for members: %q", got)
	}
	if _, err := d.setName(d.readerP, d.org, d.readerPID, "", model.NewID()); err != nil {
		t.Fatal(err)
	}
	if got := nameOf(d.readerP, d.readerPID); got != "" {
		t.Fatalf("cleared name: %q", got)
	}
	// A disabled member cannot name itself; a user of another organization cannot name anyone here.
	d.cmd("membership", auth.AdminPayload{UserID: d.bareID, Enabled: false})
	if _, err := d.setName(d.bare, d.org, d.bareID, "Disabled", model.NewID()); code(err) != model.NotFound {
		t.Fatalf("a disabled member set its name: %v", err)
	}
	other := d.otherOrg()
	if _, err := d.setName(d.readerP, other, d.readerPID, "Cross", model.NewID()); code(err) != model.NotFound {
		t.Fatalf("a user of org A named itself in org B: %v", err)
	}
	if _, err := d.setName(d.actor, d.org, model.NewID(), "Nobody", model.NewID()); code(err) != model.NotFound {
		t.Fatalf("naming a user the organization does not know: %v", err)
	}
	// A retired organization.
	if err := d.store.Update(d.ctx, func(st *control.State) error {
		delete(st.Orgs, other.String())
		if st.RetiredOrgs == nil {
			st.RetiredOrgs = map[string]model.ID{}
		}
		st.RetiredOrgs[other.String()] = model.NewID()
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.setName(d.actor, other, d.actorID(), "Retired", model.NewID()); code(err) != model.NotFound {
		t.Fatalf("a retired organization: %v", err)
	}
}

// actorID is the fixture administrator's user ID.
func (d *dirFixture) actorID() model.ID { return d.session.User }

func TestMemberNameValidation(t *testing.T) {
	d := newDirFixture(t)
	for name, text := range map[string]string{
		"too long":        strings.Repeat("x", auth.MaxMemberNameBytes+1),
		"control":         "bad\x00name",
		"newline":         "bad\nname",
		"not utf8":        "bad\xffname",
		"surrounding":     " padded ",
		"whitespace only": "   ",
		"tab":             "a\tb",
		"unicode control": "a\u0085b",
	} {
		if _, err := d.setName(d.readerP, d.org, d.readerPID, text, model.NewID()); code(err) != model.Invalid {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := d.setName(d.readerP, d.org, d.readerPID, "", model.NewID()); err != nil {
		t.Fatalf("clearing is not a validation failure: %v", err)
	}
	if _, err := d.setName(d.readerP, d.org, d.readerPID, strings.Repeat("я", auth.MaxMemberNameBytes/2), model.NewID()); err != nil {
		t.Fatalf("80 bytes of two-byte characters: %v", err)
	}
	if _, err := d.setName(d.readerP, d.org, d.readerPID, strings.Repeat("x", auth.MaxMemberNameBytes), model.NewID()); err != nil {
		t.Fatalf("80 bytes: %v", err)
	}
	if _, err := d.setName(d.readerP, d.org, d.readerPID, "ok", model.ID{}); code(err) != model.Invalid {
		t.Fatalf("no command id: %v", err)
	}
}

func TestMemberNameCommandIsIdempotentAndBoundToItsOwner(t *testing.T) {
	d := newDirFixture(t)
	audits := func() int {
		n := 0
		_ = d.store.View(d.ctx, func(st control.State) error {
			for _, a := range st.Audits {
				if a.Action == "member_name" {
					n++
				}
			}
			return nil
		})
		return n
	}
	cmd := model.NewID()
	first, err := d.setName(d.readerP, d.org, d.readerPID, "Alice", cmd)
	if err != nil {
		t.Fatal(err)
	}
	again, err := d.setName(d.readerP, d.org, d.readerPID, "Alice", cmd)
	if err != nil || again.Revision != first.Revision || audits() != 1 {
		t.Fatalf("a retry returns the first result and audits once: %+v %v audits=%d", again, err, audits())
	}
	if _, err = d.setName(d.readerP, d.org, d.readerPID, "Mallory", cmd); code(err) != model.Conflict {
		t.Fatalf("the same command id with other content: %v", err)
	}
	if _, err = d.setName(d.teamed, d.org, d.teamedID, "Alice", cmd); code(err) != model.NotFound {
		t.Fatalf("another principal replaying the command: %v", err)
	}
	// The replay of a command whose author lost the right: not served.
	d.cmd("membership", auth.AdminPayload{UserID: d.readerPID, Enabled: false})
	if _, err = d.setName(d.readerP, d.org, d.readerPID, "Alice", cmd); code(err) != model.NotFound {
		t.Fatalf("a replay by a disabled member: %v", err)
	}
}

func TestMemberNameTextNeverReachesTheAudit(t *testing.T) {
	d := newDirFixture(t)
	const secret = "Zebulon Quux-Unique"
	if _, err := d.setName(d.readerP, d.org, d.readerPID, secret, model.NewID()); err != nil {
		t.Fatal(err)
	}
	if _, err := d.setName(d.actor, d.org, d.readerPID, secret+" 2", model.NewID()); err != nil {
		t.Fatal(err)
	}
	if err := d.store.View(d.ctx, func(st control.State) error {
		raw, _ := json.Marshal(st.Audits)
		if strings.Contains(string(raw), "Zebulon") || strings.Contains(string(raw), "Quux") {
			t.Fatalf("the display name is in the audit: %s", raw)
		}
		var named bool
		for _, a := range st.Audits {
			if a.Action == "member_name" {
				named = true
				if a.Outcome != model.AuditAllowed || len(a.Targets) != 2 || a.Targets[1] != d.readerPID || a.Org != d.org.String() {
					t.Fatalf("audit: %+v", a)
				}
			}
		}
		if !named {
			t.Fatal("no member_name audit")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
