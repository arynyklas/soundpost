// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

// jobDef is the closed header control reads of a schedule definition, plus a
// cron text the tests use as the sensitive project-owned text.
type jobDef struct {
	Revision      model.Uint64   `json:"revision"`
	EffectiveFrom model.UnixNano `json:"effective_from_ns"`
	Cron          string         `json:"cron"`
}

func (f *jobFx) defineCmd(project, job model.ID, expected, revision uint64, effective int64, cron string) control.JobUpdateCommand {
	f.t.Helper()
	raw, err := json.Marshal(jobDef{Revision: model.Uint64(revision), EffectiveFrom: model.UnixNano(effective), Cron: cron})
	if err != nil {
		f.t.Fatal(err)
	}
	return control.JobUpdateCommand{Project: project, Job: job, Kind: control.JobKindDefine, Definition: &control.JobDefinitionApply{
		Project: project, Job: job, ExpectedRevision: model.Revision(expected), Definition: raw, Digest: model.Hash(sha256.Sum256(raw)), Reason: "author a job", At: 100}}
}

func (f *jobFx) retireCmd(project, job model.ID, expected uint64) control.JobUpdateCommand {
	return control.JobUpdateCommand{Project: project, Job: job, Kind: control.JobKindRetire, Definition: &control.JobDefinitionApply{
		Project: project, Job: job, ExpectedRevision: model.Revision(expected), Reason: "stop it", At: 200}}
}

func (f *jobFx) defRecord(job model.ID) control.JobDefinitionRecord {
	f.t.Helper()
	rec, found, err := f.store.JobDefinition(f.ctx, f.writer, f.project, job)
	if err != nil || !found {
		f.t.Fatalf("definition: found=%v err=%v", found, err)
	}
	return rec
}

// One job's catalogue record: the revision is the compare-and-set token and
// moves at every change; the definition revision moves by exactly one at a save
// and its effective instant never goes back; a repeated command ID is a replay;
// a retirement is idempotent and is not undone by a save from an older read;
// and nothing here touches authority, the job books or the audit text.
func TestJobDefinitionCatalogueRevisions(t *testing.T) {
	f := newJobFx(t)
	j := f.job(1)
	authority := f.authorityRevision()
	res, err := f.send(1, f.defineCmd(f.project, j, 0, 1, 1000, "CANARYCRON * * * * *"))
	if err != nil || res.Phase != "defined" || res.Cursor.Index != 1 {
		t.Fatalf("create: %+v %v", res, err)
	}
	rec := f.defRecord(j)
	if rec.Revision != 1 || rec.Retired || rec.CreatedNS != 100 || rec.Org != f.org || !strings.Contains(string(rec.Definition), "CANARYCRON") {
		t.Fatalf("record after create: %+v", rec)
	}
	if again, err := f.send(1, f.defineCmd(f.project, j, 0, 1, 1000, "CANARYCRON * * * * *")); err != nil || again.Phase != "replayed" || again.Cursor.Index != 1 {
		t.Fatalf("a replayed command answered %+v %v", again, err)
	}
	if f.defRecord(j).Revision != 1 {
		t.Fatal("a replayed command changed the record")
	}
	// A retry carries a later clock stamp; it is still the same command.
	later := f.defineCmd(f.project, j, 0, 1, 1000, "CANARYCRON * * * * *")
	later.Definition.At = 555
	if again, err := f.send(1, later); err != nil || again.Phase != "replayed" {
		t.Fatalf("a retry stamped later: %+v %v", again, err)
	}
	if _, err = f.send(1, f.defineCmd(f.project, j, 0, 1, 1000, "other")); code(err) != model.Conflict {
		t.Fatalf("a reused command ID with other input: %v", err)
	}
	// A save from an older read loses; so does one that treats an existing job as
	// new or a missing one as existing.
	if _, err = f.send(2, f.defineCmd(f.project, j, 0, 2, 1000, "x")); code(err) != model.Conflict || faultDetail(err) != control.JobDefinitionConflict {
		t.Fatalf("a save of an existing job as new: %v", err)
	}
	if _, err = f.send(3, f.defineCmd(f.project, f.job(9), 5, 1, 1000, "x")); code(err) != model.Conflict || faultDetail(err) != control.JobDefinitionConflict {
		t.Fatalf("a save of a missing job at a revision it never had: %v", err)
	}
	for name, c := range map[string]control.JobUpdateCommand{
		"revision skipped":        f.defineCmd(f.project, j, 1, 3, 1000, "x"),
		"revision repeated":       f.defineCmd(f.project, j, 1, 1, 1000, "x"),
		"effective goes back":     f.defineCmd(f.project, j, 1, 2, 999, "x"),
		"first revision is not 1": f.defineCmd(f.project, f.job(8), 0, 2, 1000, "x"),
		"no effective instant":    f.defineCmd(f.project, j, 1, 2, 0, "x"),
		"another job": func() control.JobUpdateCommand {
			c := f.defineCmd(f.project, j, 1, 2, 1000, "x")
			c.Definition.Job = f.job(7)
			return c
		}(),
		"another project": func() control.JobUpdateCommand {
			c := f.defineCmd(f.project, j, 1, 2, 1000, "x")
			c.Definition.Project = f.otherProject
			return c
		}(),
		"no definition":    {Project: f.project, Job: j, Kind: control.JobKindDefine, Definition: &control.JobDefinitionApply{Project: f.project, Job: j, ExpectedRevision: 1, Reason: "x", At: 100}},
		"retire with body": {Project: f.project, Job: j, Kind: control.JobKindRetire, Definition: &control.JobDefinitionApply{Project: f.project, Job: j, ExpectedRevision: 1, Definition: json.RawMessage(`{}`), Reason: "x", At: 100}},
		"no reason":        {Project: f.project, Job: j, Kind: control.JobKindRetire, Definition: &control.JobDefinitionApply{Project: f.project, Job: j, ExpectedRevision: 1, Reason: " ", At: 100}},
		"no arm":           {Project: f.project, Job: j, Kind: control.JobKindDefine},
		"with a state": func() control.JobUpdateCommand {
			c := f.defineCmd(f.project, j, 1, 2, 1000, "x")
			c.State = json.RawMessage(`{}`)
			return c
		}(),
	} {
		if _, err = f.send(4, c); code(err) != model.Invalid {
			t.Errorf("%s: %v", name, err)
		}
	}
	state := f.defineCmd(f.project, j, 1, 2, 1000, "x")
	state.Kind = "schedule"
	state.ExpectedVersion, state.NewVersion, state.InputDigest, state.State = 0, 1, model.Hash{1}, f.state(j, 1, nil)
	if _, err = f.send(4, state); code(err) != model.Invalid {
		t.Errorf("a state kind carrying a definition arm: %v", err)
	}
	bad := f.defineCmd(f.project, j, 1, 2, 1000, "x")
	bad.Definition.Digest = model.Hash{9}
	if _, err = f.send(4, bad); code(err) != model.Invalid {
		t.Errorf("a digest that is not the stored bytes: %v", err)
	}
	if _, err = f.send(4, f.defineCmd(f.project, j, 1, 2, 1000, strings.Repeat("x", control.MaxJobDefinitionBytes))); code(err) != model.TooLarge {
		t.Errorf("an oversized definition: %v", err)
	}
	if rec = f.defRecord(j); rec.Revision != 1 {
		t.Fatalf("a refused command changed the record: %+v", rec)
	}

	if _, err = f.send(5, f.defineCmd(f.project, j, 1, 2, 1000, "up2")); err != nil {
		t.Fatal(err)
	}
	if rec = f.defRecord(j); rec.Revision != 2 || !strings.Contains(string(rec.Definition), "up2") {
		t.Fatalf("record after the second save: %+v", rec)
	}

	// Retirement: the record stays, the revision moves.
	if _, err = f.send(6, f.retireCmd(f.project, j, 1)); code(err) != model.Conflict {
		t.Fatalf("a retirement from a stale read: %v", err)
	}
	if _, err = f.send(6, f.retireCmd(f.project, f.job(9), 0)); code(err) != model.NotFound {
		t.Fatalf("a retirement of an unknown job: %v", err)
	}
	if res, err = f.send(7, f.retireCmd(f.project, j, 2)); err != nil || res.Phase != "job_retired" {
		t.Fatalf("retire: %+v %v", res, err)
	}
	if rec = f.defRecord(j); !rec.Retired || rec.Revision != 3 || rec.UpdatedNS != 200 {
		t.Fatalf("record after retirement: %+v", rec)
	}
	if res, err = f.send(8, f.retireCmd(f.project, j, 3)); err != nil || res.Phase != "unchanged" || res.Cursor.Index != 3 {
		t.Fatalf("a second retirement: %+v %v", res, err)
	}
	if f.defRecord(j).Revision != 3 {
		t.Fatal("a second retirement moved the revision")
	}
	// An author who read the job before it was retired cannot silently bring it back.
	if _, err = f.send(9, f.defineCmd(f.project, j, 2, 3, 1000, "up3")); code(err) != model.Conflict {
		t.Fatalf("a save from before the retirement: %v", err)
	}
	if _, err = f.send(10, f.defineCmd(f.project, j, 3, 3, 2000, "up3")); err != nil {
		t.Fatal(err)
	}
	if rec = f.defRecord(j); rec.Retired || rec.Revision != 4 {
		t.Fatalf("record after the save that brings it back: %+v", rec)
	}

	if n := len(f.audits("jobs.define")); n != 3 {
		t.Fatalf("define audits: %d", n)
	}
	if n := len(f.audits("jobs.retire")); n != 1 {
		t.Fatalf("retire audits: %d", n)
	}
	for _, a := range append(f.audits("jobs.define"), f.audits("jobs.retire")...) {
		if strings.Contains(a.Reason, "up") || a.Principal != f.user || len(a.Targets) != 2 || a.Targets[0] != f.project || a.Targets[1] != j {
			t.Fatalf("an audit carries the definition, the wrong actor or targets: %+v", a)
		}
	}
	if len(f.books()) != 0 {
		t.Fatal("a catalogue write created a job book")
	}
	if f.authorityRevision() != authority {
		t.Fatal("a catalogue write moved the authority revision")
	}
}

// Only a human policy.write principal of the project authors: not the runner's
// system scope, not a reader, not a scope of another project; a wrong-scope
// target and a missing project are indistinguishable.
func TestJobDefinitionAuthor(t *testing.T) {
	f := newJobFx(t)
	j := f.job(1)
	system, err := f.svc.AuthorizeSystem(f.ctx, f.org, []model.ID{f.project}, auth.PolicyWrite)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.TransactJobs(f.ctx, system, f.cmdFor(1, f.defineCmd(f.project, j, 0, 1, 1000, "x"))); code(err) != model.NotFound {
		t.Fatalf("the runner authored: %v", err)
	}
	read, err := f.readScope(f.project)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.TransactJobs(f.ctx, read, f.cmdFor(1, f.defineCmd(f.project, j, 0, 1, 1000, "x"))); code(err) != model.Forbidden {
		t.Fatalf("a reader authored: %v", err)
	}
	if _, err = f.store.TransactJobs(f.ctx, f.adminScope(), f.cmdFor(1, f.defineCmd(f.project, j, 0, 1, 1000, "x"))); code(err) != model.Forbidden {
		t.Fatalf("an administrator scope authored through the job path: %v", err)
	}
	_, errOther := f.send(1, f.defineCmd(f.otherProject, j, 0, 1, 1000, "x"))
	missing := model.NewID()
	_, errMissing := f.send(1, f.defineCmd(missing, j, 0, 1, 1000, "x"))
	if code(errOther) != model.NotFound || code(errMissing) != model.NotFound || errOther.Error() != errMissing.Error() {
		t.Fatalf("wrong project %v vs missing project %v", errOther, errMissing)
	}
	if _, err = f.send(2, f.retireCmd(f.otherProject, j, 0)); code(err) != model.NotFound {
		t.Fatalf("a retirement in another project: %v", err)
	}
	if n := len(f.stateOf().JobDefinitions); n != 0 {
		t.Fatalf("refused commands left %d definitions", n)
	}
}

func (f *jobFx) stateOf() (out control.State) {
	_ = f.store.View(f.ctx, func(st control.State) error { out = st; return nil })
	return
}

// Reads: the runner's read scope and a reader see the project's catalogue in job
// ID order, retired jobs included; another project and a missing one are
// indistinguishable.
func TestJobDefinitionReads(t *testing.T) {
	f := newJobFx(t)
	for i, n := range []byte{3, 1, 2} {
		if _, err := f.send(byte(i+1), f.defineCmd(f.project, f.job(n), 0, 1, 1000, "x")); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.send(9, f.retireCmd(f.project, f.job(2), 1)); err != nil {
		t.Fatal(err)
	}
	runner, err := f.svc.AuthorizeSystem(f.ctx, f.org, []model.ID{f.project}, auth.Read)
	if err != nil {
		t.Fatal(err)
	}
	read, err := f.readScope(f.project)
	if err != nil {
		t.Fatal(err)
	}
	for name, scope := range map[string]auth.Scope{"runner": runner, "reader": read, "writer": f.writer} {
		recs, err := f.store.JobDefinitions(f.ctx, scope, f.project)
		if err != nil || len(recs) != 3 || recs[0].Job != f.job(1) || recs[1].Job != f.job(2) || recs[2].Job != f.job(3) || recs[0].Retired || !recs[1].Retired {
			t.Fatalf("%s lists %+v %v", name, recs, err)
		}
		if _, err = f.store.JobDefinitions(f.ctx, scope, f.otherProject); code(err) != model.NotFound {
			t.Fatalf("%s listed another project: %v", name, err)
		}
		if _, _, err = f.store.JobDefinition(f.ctx, scope, f.otherProject, f.job(1)); code(err) != model.NotFound {
			t.Fatalf("%s read another project's job: %v", name, err)
		}
	}
	if _, err = f.store.JobDefinitions(f.ctx, auth.Scope{}, f.project); err == nil {
		t.Fatal("the zero scope listed")
	}
	// A record that disagrees with its key is corrupt, never served.
	if err = f.store.Update(f.ctx, func(st *control.State) error {
		st.JobDefinitions = map[string]json.RawMessage{f.org.String() + ":" + f.project.String() + ":" + f.job(1).String(): json.RawMessage(`{"org":"` + f.org.String() + `"}`)}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.JobDefinitions(f.ctx, f.writer, f.project); code(err) != model.Corrupt {
		t.Fatalf("a corrupt record: %v", err)
	}
}

// A project holds at most MaxJobDefinitionsPerProject definitions, retired ones
// included; the quota is per project and an existing job can still be saved.
func TestJobDefinitionQuotaIsPerProject(t *testing.T) {
	f := newJobFx(t)
	if err := f.store.Update(f.ctx, func(st *control.State) error {
		st.JobDefinitions = map[string]json.RawMessage{}
		for i := range control.MaxJobDefinitionsPerProject {
			job := model.ID{0xc9, byte(i)}
			seedDef, _ := json.Marshal(jobDef{Revision: 1, EffectiveFrom: 1})
			raw, _ := json.Marshal(control.JobDefinitionRecord{Org: f.org, Project: f.project, Job: job, Revision: 1, Definition: seedDef, Retired: i%2 == 0, LastCommand: model.ID{0xaa, byte(i)}, LastInput: model.Hash{0xbb}})
			st.JobDefinitions[f.org.String()+":"+f.project.String()+":"+job.String()] = raw
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.send(1, f.defineCmd(f.project, f.job(1), 0, 1, 1000, "x")); code(err) != model.Quota || faultDetail(err) != control.JobDefinitionQuota {
		t.Fatalf("one more than the bound: %v", err)
	}
	if _, err := f.send(2, f.defineCmd(f.project, model.ID{0xc9, 1}, 1, 2, 1000, "x")); err != nil {
		t.Fatalf("a save of an existing job at the bound: %v", err)
	}
	// The other project has its own bound; it needs its own scope.
	f.admin("grant", f.org, auth.AdminPayload{UserID: f.user, ProjectID: f.otherProject, Enabled: true, Permissions: []string{string(auth.Read), string(auth.PolicyWrite)}, Reason: "fixture"})
	other, err := f.svc.Authorize(f.ctx, f.cred, f.org, []model.ID{f.otherProject}, auth.PolicyWrite)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.TransactJobs(f.ctx, other, f.cmdFor(3, f.defineCmd(f.otherProject, f.job(1), 0, 1, 1000, "x"))); err != nil {
		t.Fatalf("another project's first definition: %v", err)
	}
}

// The catalogue is covered by the real deletion path: a retirement of its
// project (or of its organization) drops every definition of the covered
// projects, from the committed state, the snapshot and control.db, and nothing
// of another project; a range or entity deletion erases telemetry, which no
// definition holds.
func TestDeletionErasesJobDefinitions(t *testing.T) {
	const (
		mine, other = "CANARYJOBMINEa1b2c3d4e5f60718", "CANARYJOBOTHERa1b2c3d4e5f6071"
	)
	seed := func(f *eraseFx) {
		if err := f.store.BindJobUpdate(); err != nil {
			t.Fatal(err)
		}
		for project, canary := range map[model.ID]string{f.project: mine, f.otherProject: other} {
			f.admin("grant", f.org, auth.AdminPayload{UserID: f.user, ProjectID: project, Enabled: true, Permissions: []string{string(auth.Read), string(auth.PolicyWrite)}, Reason: "fixture"})
			scope, err := f.svc.Authorize(f.ctx, f.cred, f.org, []model.ID{project}, auth.PolicyWrite)
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := json.Marshal(jobDef{Revision: 1, EffectiveFrom: 1000, Cron: canary})
			job := model.NewID()
			payload, _ := json.Marshal(control.JobUpdateCommand{Project: project, Job: job, Kind: control.JobKindDefine, Definition: &control.JobDefinitionApply{
				Project: project, Job: job, Definition: raw, Digest: model.Hash(sha256.Sum256(raw)), Reason: "seed", At: 100}})
			if _, err = f.store.TransactJobs(f.ctx, scope, control.Command{CommandID: model.NewID(), Kind: string(control.KindUpdateJob), Payload: payload}); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Run("retire project", func(t *testing.T) {
		f := newEraseFx(t)
		seed(f)
		f.expectKept(mine)
		f.saga(control.DeleteScope{Mode: model.DeleteRetireProject, Projects: []model.ID{f.project}})
		f.expectGone(mine)
		f.expectKept(other)
	})
	t.Run("retire org", func(t *testing.T) {
		f := newEraseFx(t)
		seed(f)
		f.saga(control.DeleteScope{Mode: model.DeleteRetireOrg})
		f.expectGone(mine)
		f.expectGone(other)
	})
	t.Run("range and entity", func(t *testing.T) {
		f := newEraseFx(t)
		seed(f)
		f.saga(f.lateRange())
		f.saga(control.DeleteScope{Mode: model.DeleteEntity, Projects: []model.ID{f.project}, Entities: []model.ID{model.NewID()}})
		f.expectKept(mine)
		f.expectKept(other)
	})
}
