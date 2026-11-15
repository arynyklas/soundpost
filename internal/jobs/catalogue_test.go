// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package jobs_test

import (
	"context"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/jobs"
	"github.com/arynyklas/soundpost/internal/model"
)

const catalogueNow = model.UnixNano(1_800_000_000_000_000_000)

func catalogueFor(t *testing.T, f *fixture) *jobs.Catalogue {
	t.Helper()
	c, err := jobs.NewCatalogue(f.app.Control, jobs.WithCatalogueClock(func() model.UnixNano { return catalogueNow }))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func catalogueDef(revision uint64, effective model.UnixNano, cron string) jobs.Definition {
	return jobs.Definition{Revision: model.Uint64(revision), EffectiveFrom: effective, Schedule: &jobs.Schedule{Cron: cron, Timezone: "UTC"}}
}

func catalogueErr(err error) (model.Code, string) {
	if fault, ok := err.(*model.Fault); ok {
		return fault.Code, fault.SafeDetail
	}
	return "", ""
}

func (f *fixture) runnerScope(t *testing.T, org, project model.ID) auth.Scope {
	t.Helper()
	s, err := f.app.Auth.AuthorizeSystem(context.Background(), org, []model.ID{project}, auth.Read)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// A save is judged once, at the catalogue: the schedule must parse, and the
// definition's revision is the catalogue's next one (previous + 1, 1 for a new
// job) with an effective instant that never goes back and never lies further
// ahead than MaxDefinitionLead. A retry of the committed command is answered,
// not refused as a repeated revision; a save from an older read loses.
func TestCatalogueSaveValidatesAndNumbersRevisions(t *testing.T) {
	f := getFixture(t)
	ctx := context.Background()
	c := catalogueFor(t, f)
	w := f.scope(t, "writer1@example.test", f.org1, f.project1, auth.PolicyWrite)
	job, cmd := model.NewID(), model.NewID()
	save := func(id model.ID, expected model.Revision, def jobs.Definition) (jobs.Entry, error) {
		return c.Save(ctx, w, jobs.SaveCommand{CommandID: id, Project: f.project1, Job: job, ExpectedRevision: expected, Definition: def, Reason: "schedule"})
	}
	eff := catalogueNow - model.UnixNano(time.Hour)

	for name, def := range map[string]jobs.Definition{
		"bad cron":      catalogueDef(1, eff, "not a cron"),
		"six fields":    catalogueDef(1, eff, "0 */5 * * * *"),
		"bad zone":      {Revision: 1, EffectiveFrom: eff, Schedule: &jobs.Schedule{Cron: "* * * * *", Timezone: "Mars/Base"}},
		"no revision":   catalogueDef(0, eff, "* * * * *"),
		"no effective":  catalogueDef(1, 0, "* * * * *"),
		"grace too big": {Revision: 1, EffectiveFrom: eff, Grace: jobs.Duration(25 * time.Hour), Schedule: &jobs.Schedule{Cron: "* * * * *", Timezone: "UTC"}},
		"overlap":       {Revision: 1, EffectiveFrom: eff, Overlap: "kill", Schedule: &jobs.Schedule{Cron: "* * * * *", Timezone: "UTC"}},
	} {
		if _, err := save(model.NewID(), 0, def); err == nil {
			t.Errorf("%s was saved", name)
		}
	}
	if code, detail := catalogueErr(func() error { _, e := save(model.NewID(), 0, catalogueDef(2, eff, "* * * * *")); return e }()); code != model.Invalid || detail != jobs.ReasonDefinitionRevision {
		t.Fatalf("a new job's first definition at revision 2: %v %v", code, detail)
	}
	if got, err := c.List(ctx, w, f.project1); err != nil || len(findEntry(got, job)) != 0 {
		t.Fatalf("a refused save left an entry: %+v %v", got, err)
	}

	entry, err := save(cmd, 0, catalogueDef(1, eff, "*/5 * * * *"))
	if err != nil || entry.Job != job || entry.Revision != 1 || entry.Retired || entry.Definition.Revision != 1 || entry.Definition.Grace != jobs.Duration(jobs.DefaultGrace) || entry.Definition.Overlap != "allow" {
		t.Fatalf("first save: %+v %v", entry, err)
	}
	if again, err := save(cmd, 0, catalogueDef(1, eff, "*/5 * * * *")); err != nil || again.Revision != 1 {
		t.Fatalf("a retry of the committed command: %+v %v", again, err)
	}
	if _, err = save(model.NewID(), 1, catalogueDef(1, eff, "*/6 * * * *")); err == nil {
		t.Fatal("a repeated definition revision was saved")
	} else if code, detail := catalogueErr(err); code != model.Invalid || detail != jobs.ReasonDefinitionRevision {
		t.Fatalf("a repeated definition revision: %v", err)
	}
	if _, err = save(model.NewID(), 1, catalogueDef(3, eff, "*/6 * * * *")); err == nil {
		t.Fatal("a skipped definition revision was saved")
	}
	if _, err = save(model.NewID(), 1, catalogueDef(2, eff-1, "*/6 * * * *")); err == nil {
		t.Fatal("an effective instant that goes back was saved")
	} else if code, detail := catalogueErr(err); code != model.Invalid || detail != jobs.ReasonDefinitionEffective {
		t.Fatalf("an effective instant that goes back: %v", err)
	}
	if _, err = save(model.NewID(), 1, catalogueDef(2, catalogueNow+model.UnixNano(jobs.MaxDefinitionLead)+1, "*/6 * * * *")); err == nil {
		t.Fatal("an effective instant beyond the lead was saved")
	}
	if code, _ := catalogueErr(func() error { _, e := save(model.NewID(), 0, catalogueDef(2, eff, "*/6 * * * *")); return e }()); code != model.Conflict {
		t.Fatalf("a save from an older read: %v", code)
	}
	entry, err = save(model.NewID(), 1, catalogueDef(2, eff+1, "*/6 * * * *"))
	if err != nil || entry.Revision != 2 || entry.Definition.Revision != 2 || entry.Definition.Schedule.Cron != "*/6 * * * *" {
		t.Fatalf("second save: %+v %v", entry, err)
	}

	// Retirement keeps the record and its numbering; saving brings the job back.
	r, err := c.Retire(ctx, w, jobs.RetireCommand{CommandID: model.NewID(), Project: f.project1, Job: job, ExpectedRevision: 2, Reason: "stop"})
	if err != nil || !r.Retired || r.Revision != 3 {
		t.Fatalf("retire: %+v %v", r, err)
	}
	if r, err = c.Retire(ctx, w, jobs.RetireCommand{CommandID: model.NewID(), Project: f.project1, Job: job, ExpectedRevision: 3, Reason: "stop"}); err != nil || !r.Retired || r.Revision != 3 {
		t.Fatalf("a second retirement: %+v %v", r, err)
	}
	listed, err := c.List(ctx, f.runnerScope(t, f.org1, f.project1), f.project1)
	if got := findEntry(listed, job); err != nil || len(got) != 1 || !got[0].Retired || got[0].Definition.Revision != 2 {
		t.Fatalf("the runner lists %+v %v", listed, err)
	}
	if entry, err = save(model.NewID(), 3, catalogueDef(3, eff+2, "*/7 * * * *")); err != nil || entry.Retired || entry.Revision != 4 || entry.Definition.Revision != 3 {
		t.Fatalf("save after retirement: %+v %v", entry, err)
	}
}

func findEntry(entries []jobs.Entry, job model.ID) []jobs.Entry {
	var out []jobs.Entry
	for _, e := range entries {
		if e.Job == job {
			out = append(out, e)
		}
	}
	return out
}

// Only a policy.write scope of the project saves or retires: not the runner's
// system scope, not a reader, not another project's or organization's scope; the
// reads need only a reading scope of the project.
func TestCatalogueAuthors(t *testing.T) {
	f := getFixture(t)
	ctx := context.Background()
	c := catalogueFor(t, f)
	job := model.NewID()
	eff := catalogueNow - model.UnixNano(time.Hour)
	save := func(scope auth.Scope, project model.ID) error {
		_, err := c.Save(ctx, scope, jobs.SaveCommand{CommandID: model.NewID(), Project: project, Job: job, Definition: catalogueDef(1, eff, "* * * * *"), Reason: "schedule"})
		return err
	}
	retire := func(scope auth.Scope, project model.ID) error {
		_, err := c.Retire(ctx, scope, jobs.RetireCommand{CommandID: model.NewID(), Project: project, Job: job, Reason: "stop"})
		return err
	}
	system, err := f.app.Auth.AuthorizeSystem(ctx, f.org1, []model.ID{f.project1}, auth.PolicyWrite)
	if err != nil {
		t.Fatal(err)
	}
	reader := f.scope(t, "reader1@example.test", f.org1, f.project1, auth.Read)
	other := f.scope(t, "writer2@example.test", f.org2, f.project2, auth.PolicyWrite)
	for name, tc := range map[string]struct {
		scope auth.Scope
		want  model.Code
	}{"runner": {system, model.NotFound}, "reader": {reader, model.Forbidden}, "other org's writer": {other, model.NotFound}} {
		if code, _ := catalogueErr(save(tc.scope, f.project1)); code != tc.want {
			t.Errorf("%s saved: %v", name, code)
		}
		if code, _ := catalogueErr(retire(tc.scope, f.project1)); code != tc.want {
			t.Errorf("%s retired: %v", name, code)
		}
	}
	w := f.scope(t, "writer1@example.test", f.org1, f.project1, auth.PolicyWrite)
	if code, _ := catalogueErr(save(w, f.project1b)); code != model.NotFound {
		t.Errorf("a writer saved in another project of its organization: %v", code)
	}
	if err = save(w, f.project1); err != nil {
		t.Fatal(err)
	}
	for name, scope := range map[string]auth.Scope{"runner": f.runnerScope(t, f.org1, f.project1), "reader": reader, "writer": w} {
		if got, err := c.List(ctx, scope, f.project1); err != nil || len(findEntry(got, job)) != 1 {
			t.Errorf("%s lists %+v %v", name, got, err)
		}
		if _, err := c.List(ctx, scope, f.project1b); err == nil {
			t.Errorf("%s listed another project", name)
		}
	}
	if _, err = c.List(ctx, other, f.project1); err == nil {
		t.Error("another organization's scope listed")
	}
	if _, err = jobs.NewCatalogue(nil); err == nil {
		t.Error("a catalogue over no control store")
	}
}
