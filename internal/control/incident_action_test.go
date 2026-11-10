// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/model"
)

type incFx struct {
	*fenceFx
	inc model.ID
}

func newIncFx(t *testing.T) *incFx {
	t.Helper()
	f := &incFx{fenceFx: newFenceFx(t), inc: model.ID{0xa1}}
	if err := f.store.BindIncidentAction(); err != nil {
		t.Fatal(err)
	}
	return f
}

// incState is a state whose header is the closed schema control checks (the
// wire version is a C01 string); the rest is opaque to control.
func incState(org, project, inc model.ID, version uint64, tag string) json.RawMessage {
	return json.RawMessage(fmt.Sprintf(`{"incident_id":%q,"org_id":%q,"project_id":%q,"version":"%d","tag":%q}`, inc.String(), org.String(), project.String(), version, tag))
}

func digest(state json.RawMessage) model.Hash { return model.Hash(sha256.Sum256(state)) }

func (f *incFx) command(expected uint64, tag string, intents ...control.IncidentIntent) control.IncidentCommand {
	state := incState(f.org, f.project, f.inc, expected+1, tag)
	for i := range intents {
		intents[i].Version = model.Revision(expected + 1)
	}
	return control.IncidentCommand{Project: f.project, Incident: f.inc, Action: "ack", Origin: "human", Actor: f.user, At: 100, ExpectedVersion: model.Revision(expected), NewVersion: model.Revision(expected + 1),
		State: state, Digest: digest(state), Intents: intents}
}

func (f *incFx) send(id model.ID, c control.IncidentCommand) (control.Result, error) {
	f.t.Helper()
	return f.store.Transact(f.ctx, f.adminScope(), f.cmd(control.KindIncidentAction, id, c))
}

func (f *incFx) record() control.IncidentRecord {
	f.t.Helper()
	r, ok, err := f.store.Incident(f.ctx, f.adminScope(), f.project, f.inc)
	if err != nil || !ok {
		f.t.Fatalf("record: %v %v", ok, err)
	}
	return r
}

func intent(seed byte, kind string) control.IncidentIntent {
	return control.IncidentIntent{ID: model.ID{seed}, Kind: kind, Eligible: true}
}

func TestIncidentActionVersionCompareAndSet(t *testing.T) {
	f := newIncFx(t)
	first, err := f.send(model.NewID(), f.command(0, "a", intent(1, "notify_open")))
	if err != nil {
		t.Fatal(err)
	}
	if first.Phase != "applied" || len(first.AffectedIDs) != 1 || first.AffectedIDs[0] != f.inc {
		t.Fatalf("result %+v", first)
	}
	if r := f.record(); r.Version != 1 || len(r.Intents) != 1 {
		t.Fatalf("record %+v", r)
	}
	// Two commands that both expect version 1: exactly one commits.
	if _, err = f.send(model.NewID(), f.command(1, "b", intent(2, "notify_impact"))); err != nil {
		t.Fatal(err)
	}
	_, err = f.send(model.NewID(), f.command(1, "c", intent(3, "notify_impact")))
	if code(err) != model.Conflict || !strings.Contains(err.Error(), control.IncidentVersionConflict) {
		t.Fatalf("second writer at expected version 1: %v", err)
	}
	r := f.record()
	if r.Version != 2 || !strings.Contains(string(r.State), `"tag":"b"`) || len(r.Intents) != 2 {
		t.Fatalf("a loser overwrote state or left an intent: %+v", r)
	}
	// A missing incident is NotFound.
	f.inc = model.ID{0xa2}
	if _, err = f.send(model.NewID(), f.command(3, "x")); code(err) != model.NotFound {
		t.Fatalf("missing incident: %v", err)
	}
}

func TestIncidentActionRetryReturnsOriginalResult(t *testing.T) {
	f := newIncFx(t)
	id := model.NewID()
	c := f.command(0, "a", intent(1, "notify_open"))
	first, err := f.send(id, c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.send(model.NewID(), f.command(1, "b")); err != nil {
		t.Fatal(err)
	}
	audits := len(f.audits("incidents.ack"))
	retry, err := f.send(id, c)
	if err != nil || retry.Revision != first.Revision || len(retry.AffectedIDs) != 1 {
		t.Fatalf("retry %+v %v", retry, err)
	}
	if r := f.record(); r.Version != 2 || len(f.audits("incidents.ack")) != audits {
		t.Fatalf("retry changed state or audited twice: %+v", r)
	}
}

func TestIncidentActionActorIsTheSessionAndAuditIsSafe(t *testing.T) {
	f := newIncFx(t)
	forged := f.command(0, "a")
	forged.Actor = model.ID{0xee}
	if _, err := f.send(model.NewID(), forged); code(err) != model.Forbidden {
		t.Fatalf("forged actor accepted: %v", err)
	}
	if _, ok, _ := f.store.Incident(f.ctx, f.adminScope(), f.project, f.inc); ok {
		t.Fatal("rejected command left an incident")
	}
	id := model.NewID()
	if _, err := f.send(id, f.command(0, "SECRET-EVIDENCE-TEXT")); err != nil {
		t.Fatal(err)
	}
	a := f.audits("incidents.ack")
	if len(a) != 1 || a[0].Principal != f.user || a[0].ID != id || len(a[0].Targets) != 1 || a[0].Targets[0] != f.inc || a[0].Outcome != model.AuditAllowed {
		t.Fatalf("audit %+v", a)
	}
	if raw, _ := json.Marshal(a[0]); strings.Contains(string(raw), "SECRET") {
		t.Fatalf("audit holds state content: %s", raw)
	}
}

func TestIncidentActionScopeBeforeLookup(t *testing.T) {
	f := newIncFx(t)
	if _, err := f.send(model.NewID(), f.command(0, "a")); err != nil {
		t.Fatal(err)
	}
	// A project outside the scope and a missing incident answer alike; a
	// read-only grant cannot act at all.
	wrong := f.command(1, "b")
	wrong.Project = model.NewID()
	_, errWrongScope := f.send(model.NewID(), wrong)
	missing := f.command(1, "b")
	missing.Incident = model.ID{0xa9}
	missing.State = incState(f.org, f.project, missing.Incident, 2, "b")
	missing.Digest = digest(missing.State)
	_, errMissing := f.send(model.NewID(), missing)
	if code(errWrongScope) != model.NotFound || code(errMissing) != model.NotFound || errWrongScope.Error() != errMissing.Error() {
		t.Fatalf("wrong scope %v vs missing %v", errWrongScope, errMissing)
	}
	read, err := f.readScope(f.project)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(f.command(1, "b"))
	_, err = f.store.Transact(f.ctx, read, control.Command{CommandID: model.NewID(), ExpectedRevision: f.revision(), Kind: string(control.KindIncidentAction), Payload: raw})
	if code(err) != model.Forbidden {
		t.Fatalf("read-only scope acted: %v", err)
	}
	if _, _, err = f.store.Incident(f.ctx, read, model.NewID(), f.inc); code(err) != model.NotFound {
		t.Fatalf("read of a project outside the scope: %v", err)
	}
}

func TestIncidentActionRejectsMalformedCommands(t *testing.T) {
	f := newIncFx(t)
	if _, err := f.send(model.NewID(), f.command(0, "a", intent(1, "notify_open"))); err != nil {
		t.Fatal(err)
	}
	withState := func(c *control.IncidentCommand, org model.ID, version uint64) {
		c.State = incState(org, f.project, f.inc, version, "z")
		c.Digest = digest(c.State)
	}
	cases := map[string]func(c *control.IncidentCommand){
		"digest":          func(c *control.IncidentCommand) { c.Digest = model.Hash{1} },
		"skipped version": func(c *control.IncidentCommand) { c.NewVersion = 3 },
		"header version":  func(c *control.IncidentCommand) { withState(c, f.org, 5) },
		"header org":      func(c *control.IncidentCommand) { withState(c, model.ID{9}, 2) },
		"origin":          func(c *control.IncidentCommand) { c.Origin = "robot" },
		"action token":    func(c *control.IncidentCommand) { c.Action = "Ack Now" },
		"duplicate intent": func(c *control.IncidentCommand) {
			c.Intents = []control.IncidentIntent{{ID: model.ID{1}, Kind: "notify_open", Version: 2}}
		},
		"intent version": func(c *control.IncidentCommand) {
			c.Intents = []control.IncidentIntent{{ID: model.ID{7}, Kind: "notify_open", Version: 9}}
		},
		"too many intents": func(c *control.IncidentCommand) {
			for i := byte(20); i < 29; i++ {
				c.Intents = append(c.Intents, control.IncidentIntent{ID: model.ID{i}, Kind: "notify_open", Version: 2})
			}
		},
		"zero time": func(c *control.IncidentCommand) { c.At = 0 },
	}
	names := make([]string, 0, len(cases))
	for n := range cases {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		c := f.command(1, "b")
		cases[name](&c)
		if _, err := f.send(model.NewID(), c); code(err) != model.Invalid {
			t.Errorf("%s: %v", name, err)
		}
	}
	if r := f.record(); r.Version != 1 {
		t.Fatalf("a rejected command changed the record: %+v", r)
	}
	unknown := control.Command{CommandID: model.NewID(), ExpectedRevision: f.revision(), Kind: string(control.KindIncidentAction), Payload: json.RawMessage(`{"project":"` + f.project.String() + `","surprise":1}`)}
	if _, err := f.store.Transact(f.ctx, f.adminScope(), unknown); code(err) != model.Invalid {
		t.Fatalf("unknown payload field: %v", err)
	}
}

func (f *incFx) semantic() string {
	f.t.Helper()
	var out string
	if err := f.store.View(f.ctx, func(st control.State) error { out = incSemantic(f.t, st, f.org, f.project); return nil }); err != nil {
		f.t.Fatal(err)
	}
	return out
}

// incSemantic is the committed incident facts with the per-run org/project IDs
// normalized, so two independent stores can be compared.
func incSemantic(t *testing.T, st control.State, org, project model.ID) string {
	t.Helper()
	var recs []control.IncidentRecord
	for _, raw := range st.IncidentBooks {
		var r control.IncidentRecord
		if err := json.Unmarshal(raw, &r); err != nil {
			t.Fatal(err)
		}
		r.Digest = model.Hash{}
		r.Org, r.Project = model.ID{1}, model.ID{2}
		r.State = json.RawMessage(strings.NewReplacer(org.String(), "ORG", project.String(), "PROJECT").Replace(string(r.State)))
		recs = append(recs, r)
	}
	sort.Slice(recs, func(i, j int) bool { return recs[i].ID.String() < recs[j].ID.String() })
	raw, err := json.Marshal(recs)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// Two stores receive the same commands: one in order, one with early, late and
// duplicated retries interleaved. Both must end in the same state.
func TestIncidentActionDeterministicUnderReorderedRetries(t *testing.T) {
	type step struct {
		id       model.ID
		expected uint64
		tag      string
	}
	steps := []step{{model.ID{1}, 0, "a"}, {model.ID{2}, 1, "b"}, {model.ID{3}, 2, "c"}}
	run := func(order []int) string {
		f := newIncFx(t)
		for _, i := range order {
			s := steps[i]
			if _, err := f.send(s.id, f.command(s.expected, s.tag, intent(byte(10+i), "notify_impact"))); err != nil && code(err) != model.Conflict && code(err) != model.NotFound {
				t.Fatal(err)
			}
		}
		return f.semantic()
	}
	ordered := run([]int{0, 1, 2})
	// Step 2 arrives before step 1 (rejected, retried later); committed steps
	// are repeated.
	reordered := run([]int{0, 2, 1, 0, 2, 1, 0, 2, 2})
	if ordered != reordered || !strings.Contains(ordered, `"tag":"c"`) {
		t.Fatalf("state depends on retry order:\n%s\n%s", ordered, reordered)
	}
}

// Incident state, intents and command results survive a control snapshot import
// and a restart; a restarted store still answers the committed command once.
func TestIncidentActionSurvivesRestartAndSnapshotImport(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	now := time.Unix(1_800_000_000, 0)
	open := func() (*control.Store, *auth.Service) {
		store, err := control.Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		svc, err := auth.NewService(auth.AuthDependencies{Control: store, Now: func() time.Time { return now }})
		if err != nil {
			store.Close()
			t.Fatal(err)
		}
		if err = store.EnableSingle(ctx, filepath.Join(dir, "raft-control")); err != nil {
			store.Close()
			t.Fatal(err)
		}
		if err = store.BindIncidentAction(); err != nil {
			store.Close()
			t.Fatal(err)
		}
		return store, svc
	}
	store, svc := open()
	boot, _ := store.BootstrapToken()
	session, err := svc.Bootstrap(ctx, boot, "owner@example.test", "a long test password 2026")
	if err != nil {
		t.Fatal(err)
	}
	cred, err := svc.Authenticate(ctx, session.Token)
	if err != nil {
		t.Fatal(err)
	}
	org, project, inc := model.NewID(), model.NewID(), model.ID{0xa1}
	admin := func(kind string, p auth.AdminPayload) {
		var revision model.Revision
		_ = store.View(ctx, func(st control.State) error { revision = st.Revision; return nil })
		raw, _ := json.Marshal(p)
		if _, err := svc.AdminCommand(ctx, cred, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: revision, OrgID: org, Kind: kind, Payload: raw}); err != nil {
			t.Fatal(kind, err)
		}
	}
	admin("create_org", auth.AdminPayload{Name: "restart", Reason: "fixture"})
	admin("create_project", auth.AdminPayload{ID: project, Name: "p1", Reason: "fixture"})
	send := func(store *control.Store, svc *auth.Service, cred auth.Credential, id model.ID, c control.IncidentCommand) (control.Result, error) {
		scope, err := svc.Authorize(ctx, cred, org, nil, auth.OrgAdmin)
		if err != nil {
			t.Fatal(err)
		}
		var revision model.Revision
		_ = store.View(ctx, func(st control.State) error { revision = st.Revision; return nil })
		raw, _ := json.Marshal(c)
		return store.Transact(ctx, scope, control.Command{CommandID: id, ExpectedRevision: revision, Kind: string(control.KindIncidentAction), Payload: raw})
	}
	mk := func(expected uint64, tag string, in ...control.IncidentIntent) control.IncidentCommand {
		state := incState(org, project, inc, expected+1, tag)
		for i := range in {
			in[i].Version = model.Revision(expected + 1)
		}
		return control.IncidentCommand{Project: project, Incident: inc, Action: "ack", Origin: "human", Actor: session.User, At: 100, ExpectedVersion: model.Revision(expected), NewVersion: model.Revision(expected + 1), State: state, Digest: digest(state), Intents: in}
	}
	id1 := model.NewID()
	first, err := send(store, svc, cred, id1, mk(0, "a", intent(1, "notify_open")))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = send(store, svc, cred, model.NewID(), mk(1, "b", intent(2, "notify_impact"))); err != nil {
		t.Fatal(err)
	}
	var before string
	if err = store.View(ctx, func(st control.State) error { before = incSemantic(t, st, org, project); return nil }); err != nil {
		t.Fatal(err)
	}
	seed, _, err := store.ReplicationSeed()
	if err != nil {
		t.Fatal(err)
	}
	imported, err := control.OpenSeed(filepath.Join(t.TempDir(), "imported"), seed)
	if err != nil {
		t.Fatal(err)
	}
	var restored string
	if err = imported.View(ctx, func(st control.State) error { restored = incSemantic(t, st, org, project); return nil }); err != nil {
		t.Fatal(err)
	}
	imported.Close()
	if restored != before || !strings.Contains(before, `"tag":"b"`) {
		t.Fatalf("snapshot import changed the incident state:\n%s\n%s", before, restored)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	store, svc = open()
	defer store.Close()
	if cred, err = svc.Authenticate(ctx, session.Token); err != nil {
		t.Fatal(err)
	}
	var after string
	if err = store.View(ctx, func(st control.State) error { after = incSemantic(t, st, org, project); return nil }); err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("restart changed the incident state:\n%s\n%s", before, after)
	}
	again, err := send(store, svc, cred, id1, mk(0, "a", intent(1, "notify_open")))
	if err != nil || again.Revision != first.Revision {
		t.Fatalf("committed command not recognized after restart: %+v vs %+v (%v)", again, first, err)
	}
	if _, err = send(store, svc, cred, model.NewID(), mk(1, "late")); code(err) != model.Conflict {
		t.Fatalf("a stale expected version committed after restart: %v", err)
	}
}
