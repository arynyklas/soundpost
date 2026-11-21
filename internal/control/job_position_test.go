// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"encoding/json"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

func (f *jobFx) advance(scope auth.Scope, tag byte, project model.ID, through ...model.Cursor) (control.Result, error) {
	raw, err := json.Marshal(control.JobUpdateCommand{Project: project, Job: project, Kind: control.JobKindAdvance, Position: &control.JobPositionApply{Project: project, Through: through, At: 100}})
	if err != nil {
		f.t.Fatal(err)
	}
	return f.store.TransactJobs(f.ctx, scope, control.Command{CommandID: model.ID{0xc0, tag}, Kind: string(control.KindUpdateJob), Payload: raw})
}

// The position is written by the runner's system scope only, moves forward only, merges per group, is readable to the
// project's readers, and a wrong or missing project is not told apart.
func TestJobPositionAdvancesForwardOnlyForTheRunner(t *testing.T) {
	f := newJobFx(t)
	runner, err := f.svc.AuthorizeSystem(f.ctx, f.org, []model.ID{f.project}, auth.PolicyWrite)
	if err != nil {
		t.Fatal(err)
	}
	ga, gb := model.ID{0xa1}, model.ID{0xb1}
	if _, err = f.advance(f.writer, 1, f.project, model.Cursor{Group: ga, Index: 5}); code(err) != model.Forbidden {
		t.Fatalf("a human moved the position: %v", err)
	}
	if res, err := f.advance(runner, 2, f.project, model.Cursor{Group: ga, Index: 5}); err != nil || res.Phase != "advanced" {
		t.Fatalf("first advance: %+v %v", res, err)
	}
	if res, err := f.advance(runner, 3, f.project, model.Cursor{Group: ga, Index: 3}); err != nil || res.Phase != "unchanged" {
		t.Fatalf("a lower entry: %+v %v", res, err)
	}
	if res, err := f.advance(runner, 4, f.project, model.Cursor{Group: ga, Index: 4}, model.Cursor{Group: gb, Index: 9}); err != nil || res.Phase != "advanced" {
		t.Fatalf("a new group: %+v %v", res, err)
	}
	if _, err = f.advance(runner, 5, f.project, model.Cursor{Group: ga, Index: 1}, model.Cursor{Group: ga, Index: 2}); code(err) != model.Invalid {
		t.Fatalf("a duplicated group: %v", err)
	}
	if _, err = f.advance(runner, 6, f.project); code(err) != model.Invalid {
		t.Fatalf("an empty position: %v", err)
	}
	read, err := f.readScope(f.project)
	if err != nil {
		t.Fatal(err)
	}
	for name, scope := range map[string]auth.Scope{"runner": runner, "reader": read} {
		got, err := f.store.JobPosition(f.ctx, scope, f.project)
		if err != nil || len(got) != 2 || got[0] != (model.Cursor{Group: ga, Index: 5}) || got[1] != (model.Cursor{Group: gb, Index: 9}) {
			t.Fatalf("%s reads %+v %v", name, got, err)
		}
		if _, err = f.store.JobPosition(f.ctx, scope, f.otherProject); code(err) != model.NotFound {
			t.Fatalf("%s read another project: %v", name, err)
		}
	}
}

// A retirement of a project through the real deletion path drops its position and nothing of another project's.
func TestDeletionErasesJobPositions(t *testing.T) {
	f := newEraseFx(t)
	keyOf := func(p model.ID) string { return f.org.String() + ":" + p.String() }
	if err := f.store.Update(f.ctx, func(st *control.State) error {
		st.JobPositions = map[string]json.RawMessage{}
		for _, p := range []model.ID{f.project, f.otherProject} {
			raw, _ := json.Marshal(control.JobPositionRecord{Org: f.org, Project: p, Through: []model.Cursor{{Group: model.ID{0xa1}, Index: 4}}, UpdatedNS: 1})
			st.JobPositions[keyOf(p)] = raw
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	f.saga(control.DeleteScope{Mode: model.DeleteRetireProject, Projects: []model.ID{f.project}})
	var got map[string]json.RawMessage
	_ = f.store.View(f.ctx, func(st control.State) error { got = st.JobPositions; return nil })
	if _, kept := got[keyOf(f.project)]; kept {
		t.Fatal("the retired project's position survived its deletion")
	}
	if _, kept := got[keyOf(f.otherProject)]; !kept {
		t.Fatal("another project's position was dropped")
	}
}
