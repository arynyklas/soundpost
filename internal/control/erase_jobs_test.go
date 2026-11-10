// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"soundpost/internal/model"
)

func jobTestRecord(org, project, job model.ID, version model.Revision, state string) json.RawMessage {
	raw, _ := json.Marshal(JobRecord{Org: org, Project: project, Job: job, Version: version, Digest: model.Hash{7}, State: json.RawMessage(state),
		Commands: []JobCommandEntry{{ID: model.ID{0xc0, 1}, Principal: model.ID{1}, Kind: "attempt", Digest: model.Hash{3}, Version: 1}}})
	return raw
}

func jobTestState(job model.ID, extra string) string {
	return fmt.Sprintf(`{"version":3,"org":"o","project":"p","job":%q,"latest_schedule_key":"manual:abc"%s}`, job.String(), extra)
}

func jobTestBooks() (st *State, org, projA, projB model.ID) {
	org, projA, projB = model.ID{0x10}, model.ID{0x11}, model.ID{0x12}
	st = &State{JobBooks: map[string]json.RawMessage{}}
	add := func(o, p model.ID, n byte, state string) {
		job := model.ID{0xa0, n}
		st.JobBooks[jobKey(o, p, job)] = jobTestRecord(o, p, job, 3, state)
	}
	add(org, projA, 1, jobTestState(model.ID{0xa0, 1}, `,"observer":{"observed_at_ns":"100"}`))
	add(org, projA, 2, jobTestState(model.ID{0xa0, 2}, `,"observer":{"observed_at_ns":"900"}`))
	add(org, projB, 3, jobTestState(model.ID{0xa0, 3}, `,"observer":{"observed_at_ns":"900"}`))
	add(model.ID{0x99}, projA, 4, jobTestState(model.ID{0xa0, 4}, `,"observer":{"observed_at_ns":"900"}`))
	return
}

func jobTestErased(st *State, org, project model.ID, n byte) bool {
	rec, _, _ := loadJobRecord(st, jobKey(org, project, model.ID{0xa0, n}))
	return stateIsTombstone(rec.State)
}

func TestEraseJobBooksRetireProject(t *testing.T) {
	st, org, projA, projB := jobTestBooks()
	op := model.ID{0xdd, 1}
	dropped, err := eraseJobBooks(st, model.DeletePredicate{Operation: op, Org: org, Mode: model.DeleteRetireProject, Projects: []model.ID{projA}}, 5)
	if err != nil || dropped != 2 {
		t.Fatalf("dropped %d: %v", dropped, err)
	}
	if !jobTestErased(st, org, projA, 1) || !jobTestErased(st, org, projA, 2) || jobTestErased(st, org, projB, 3) || jobTestErased(st, model.ID{0x99}, projA, 4) {
		t.Fatal("retirement covered the wrong jobs")
	}
	rec, _, _ := loadJobRecord(st, jobKey(org, projA, model.ID{0xa0, 1}))
	if rec.Version != 3 || rec.Digest != (model.Hash{7}) || len(rec.Commands) != 1 || rec.Org != org || rec.Project != projA || rec.Job != (model.ID{0xa0, 1}) {
		t.Fatalf("identity, version, digest and command records must stay: %+v", rec)
	}
	for _, leak := range []string{"manual:abc", "observed_at_ns", "latest_schedule_key"} {
		if strings.Contains(string(rec.State), leak) {
			t.Fatalf("tombstone kept %q: %s", leak, rec.State)
		}
	}
	if !strings.Contains(string(rec.State), `"job_id":"`+rec.Job.String()+`"`) || !strings.Contains(string(rec.State), `"org_id":"`+org.String()+`"`) || !strings.Contains(string(rec.State), `"project_id":"`+projA.String()+`"`) {
		t.Fatalf("tombstone header %s", rec.State)
	}
	if !strings.Contains(string(rec.State), op.String()) || !strings.Contains(string(rec.State), `"version":"3"`) {
		t.Fatalf("tombstone %s", rec.State)
	}
	// Idempotent: a tombstone is never covered again.
	if again, err := eraseJobBooks(st, model.DeletePredicate{Operation: model.ID{0xdd, 2}, Org: org, Mode: model.DeleteRetireProject, Projects: []model.ID{projA}}, 6); err != nil || again != 0 {
		t.Fatalf("second erasure dropped %d: %v", again, err)
	}
	if got, _, _ := loadJobRecord(st, jobKey(org, projA, model.ID{0xa0, 1})); !strings.Contains(string(got.State), op.String()) {
		t.Fatal("a second operation rewrote the tombstone")
	}
}

func TestEraseJobBooksRetireOrg(t *testing.T) {
	st, org, projA, projB := jobTestBooks()
	dropped, err := eraseJobBooks(st, model.DeletePredicate{Operation: model.ID{0xdd, 1}, Org: org, Mode: model.DeleteRetireOrg}, 5)
	if err != nil || dropped != 3 {
		t.Fatalf("dropped %d: %v", dropped, err)
	}
	if !jobTestErased(st, org, projA, 1) || !jobTestErased(st, org, projB, 3) || jobTestErased(st, model.ID{0x99}, projA, 4) {
		t.Fatal("org retirement covered the wrong jobs")
	}
}

func TestEraseJobBooksHistoricalRange(t *testing.T) {
	st, org, projA, projB := jobTestBooks()
	p := model.DeletePredicate{Operation: model.ID{0xdd, 1}, Org: org, Mode: model.DeleteHistoricalRange, Projects: []model.ID{projA}, Start: 500, End: 1000}
	// A job unattributable to a time is dropped whole.
	st.JobBooks[jobKey(org, projA, model.ID{0xa0, 5})] = jobTestRecord(org, projA, model.ID{0xa0, 5}, 3, `{"version":3,"org":"o","project":"p","job":"x"}`)
	st.JobBooks[jobKey(org, projA, model.ID{0xa0, 6})] = jobTestRecord(org, projA, model.ID{0xa0, 6}, 3, `{"observer":{"observed_at_ns":"not a time"}}`)
	// The newest evidence time decides, at depth, and Start itself is covered.
	st.JobBooks[jobKey(org, projA, model.ID{0xa0, 7})] = jobTestRecord(org, projA, model.ID{0xa0, 7}, 3, jobTestState(model.ID{0xa0, 7}, `,"attempts":{"x":{"observed_ns":100,"terminal":{"at_ns":500}}}`))
	st.JobBooks[jobKey(org, projA, model.ID{0xa0, 8})] = jobTestRecord(org, projA, model.ID{0xa0, 8}, 3, jobTestState(model.ID{0xa0, 8}, `,"attempts":{"x":{"observed_ns":100,"terminal":{"at_ns":499}}}`))
	dropped, err := eraseJobBooks(st, p, 5)
	if err != nil || dropped != 4 {
		t.Fatalf("dropped %d: %v", dropped, err)
	}
	for n, want := range map[byte]bool{1: false, 2: true, 5: true, 6: true, 7: true, 8: false} {
		if got := jobTestErased(st, org, projA, n); got != want {
			t.Errorf("job %d erased=%v want %v", n, got, want)
		}
	}
	if jobTestErased(st, org, projB, 3) {
		t.Error("a project outside the predicate was erased")
	}
}

func TestEraseJobBooksEntityCoversNothingAndIsDeterministic(t *testing.T) {
	st, org, projA, _ := jobTestBooks()
	p := model.DeletePredicate{Operation: model.ID{0xdd, 1}, Org: org, Mode: model.DeleteEntity, Projects: []model.ID{projA}, Entities: []model.ID{{0x77}}}
	before, _ := json.Marshal(st.JobBooks)
	if dropped, err := eraseJobBooks(st, p, 5); err != nil || dropped != 0 {
		t.Fatalf("entity deletion dropped %d: %v", dropped, err)
	}
	if after, _ := json.Marshal(st.JobBooks); string(after) != string(before) {
		t.Fatal("entity deletion changed the books")
	}
	run := func() string {
		st, org, projA, _ := jobTestBooks()
		_, err := eraseJobBooks(st, model.DeletePredicate{Operation: model.ID{0xdd, 3}, Org: org, Mode: model.DeleteRetireProject, Projects: []model.ID{projA}}, 9)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(st.JobBooks)
		return string(raw)
	}
	if a, b := run(), run(); a != b {
		t.Fatal("erasure is not deterministic")
	}
	// An unreadable record is corrupt, not silently skipped.
	st.JobBooks["bad"] = json.RawMessage(`{`)
	if _, err := eraseJobBooks(st, model.DeletePredicate{Operation: model.ID{0xdd, 1}, Org: org, Mode: model.DeleteRetireOrg}, 5); err == nil {
		t.Fatal("a corrupt record was skipped")
	}
}

func TestEraseJobBooksWithoutBooks(t *testing.T) {
	if n, err := eraseJobBooks(&State{}, model.DeletePredicate{Org: model.ID{1}, Mode: model.DeleteRetireOrg}, 1); err != nil || n != 0 {
		t.Fatalf("%d %v", n, err)
	}
}
