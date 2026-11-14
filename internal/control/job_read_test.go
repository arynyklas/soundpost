// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"bytes"
	"encoding/json"
	"sort"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

// seedJobs writes one committed book per job ID straight into the control
// state (versions 1..n), with an attempt command carrying an origin cursor.
func (f *jobFx) seedJobs(project model.ID, ids ...model.ID) {
	books := map[string]control.JobRecord{}
	for i, id := range ids {
		state, err := json.Marshal(map[string]any{"version": model.Revision(1), "org": f.org, "project": project, "job": id,
			"definition": map[string]any{"revision": 1}, "current_health": map[string]any{"status": "unknown"}, "compaction": map[string]any{"runs": 0}})
		if err != nil {
			f.t.Fatal(err)
		}
		books[f.org.String()+":"+project.String()+":"+id.String()] = control.JobRecord{Org: f.org, Project: project, Job: id, Version: 1, Digest: model.Hash{byte(i + 1)}, State: state,
			Commands: []control.JobCommandEntry{{ID: model.ID{0xc9, byte(i)}, Principal: f.user, Kind: "attempt", Digest: model.Hash{1}, Version: 1, Origin: &model.Cursor{Group: f.group, Index: model.Uint64(10 + i)}}}}
	}
	f.seed(books)
}

func jobIDs(entries []control.JobEntry) []model.ID {
	out := make([]model.ID, len(entries))
	for i, e := range entries {
		out[i] = e.Job
	}
	return out
}

// The listing is a deterministic, ID-ordered, bounded page walk of exactly one
// project's books, whatever order the books were committed in.
func TestJobBooksListsOneProjectInStableIDOrderAcrossPages(t *testing.T) {
	f := newJobFx(t)
	f.admin("grant", f.org, auth.AdminPayload{UserID: f.user, ProjectID: f.otherProject, Enabled: true, Permissions: []string{string(auth.Read), string(auth.PolicyWrite)}, Reason: "fixture"})
	mine := []model.ID{{0x50, 1}, {0x10, 9}, {0x90, 3}, {0x10, 2}, {0xf0, 0}, {0x30, 4}, {0x70, 7}}
	f.seedJobs(f.project, mine...)
	f.seedJobs(f.otherProject, model.ID{0x20, 1}, model.ID{0x60, 1})
	want := append([]model.ID(nil), mine...)
	sort.Slice(want, func(i, j int) bool { return bytes.Compare(want[i][:], want[j][:]) < 0 })

	read, err := f.readScope(f.project)
	if err != nil {
		t.Fatal(err)
	}
	var got []model.ID
	after := model.ID{}
	pages := 0
	for {
		page, err := f.store.JobBooks(f.ctx, read, f.project, after, 3)
		if err != nil {
			t.Fatal(err)
		}
		pages++
		if len(page.Entries) > 3 {
			t.Fatalf("page of %d entries over the limit", len(page.Entries))
		}
		got = append(got, jobIDs(page.Entries)...)
		if !page.More {
			break
		}
		if len(page.Entries) != 3 {
			t.Fatalf("a page that says more holds %d entries", len(page.Entries))
		}
		after = page.Entries[len(page.Entries)-1].Job
	}
	if pages != 3 || len(got) != len(want) {
		t.Fatalf("pages=%d got %v", pages, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order %v, want %v", got, want)
		}
	}
	// A page that ends exactly at the last job does not claim more.
	page, err := f.store.JobBooks(f.ctx, read, f.project, want[3], 3)
	if err != nil || page.More || len(page.Entries) != 3 {
		t.Fatalf("final exact page: %+v %v", page, err)
	}
	// The cursor is exclusive and need not name an existing job.
	page, err = f.store.JobBooks(f.ctx, read, f.project, model.ID{0x10, 5}, 2)
	if err != nil || len(page.Entries) != 2 || page.Entries[0].Job != (model.ID{0x10, 9}) || !page.More {
		t.Fatalf("cursor between jobs: %+v %v", page, err)
	}
	// Every entry carries its own committed snapshot, never a neighbour's.
	full, err := f.store.JobBooks(f.ctx, read, f.project, model.ID{}, control.MaxJobPage)
	if err != nil || full.More || len(full.Entries) != len(want) {
		t.Fatalf("full page: %+v %v", full, err)
	}
	for _, e := range full.Entries {
		var head struct {
			Job model.ID `json:"job"`
		}
		if err = json.Unmarshal(e.Snapshot.State, &head); err != nil || head.Job != e.Job || e.Snapshot.Version != 1 || e.Snapshot.Erased || e.Commands != 1 || e.Origin == nil || e.Origin.Group != f.group || e.Origin.Index < 10 {
			t.Fatalf("entry %v: %+v head %+v %v", e.Job, e, head, err)
		}
	}
}

func TestJobBooksPageSizeIsBounded(t *testing.T) {
	f := newJobFx(t)
	f.seedJobs(f.project, model.ID{1}, model.ID{2})
	read, err := f.readScope(f.project)
	if err != nil {
		t.Fatal(err)
	}
	for _, limit := range []int{0, -1, control.MaxJobPage + 1, 1 << 30} {
		if _, err = f.store.JobBooks(f.ctx, read, f.project, model.ID{}, limit); code(err) != model.Invalid {
			t.Fatalf("limit %d: %v", limit, err)
		}
	}
	if page, err := f.store.JobBooks(f.ctx, read, f.project, model.ID{}, control.MaxJobPage); err != nil || len(page.Entries) != 2 {
		t.Fatalf("limit at the bound: %+v %v", page, err)
	}
}

// Scope first: a scope that does not name the project, a project that does not
// exist and a revoked grant are the same not-found, before any book is looked up.
func TestJobBooksScopeBeforeLookup(t *testing.T) {
	f := newJobFx(t)
	f.seedJobs(f.project, model.ID{1}, model.ID{2})
	f.seedJobs(f.otherProject, model.ID{3})
	_, outside := f.store.JobBooks(f.ctx, f.writer, f.otherProject, model.ID{}, 10)
	_, missing := f.store.JobBooks(f.ctx, f.writer, model.NewID(), model.ID{}, 10)
	_, zero := f.store.JobBooks(f.ctx, f.writer, model.ID{}, model.ID{}, 10)
	_, _, outsideDetail := f.store.JobDetail(f.ctx, f.writer, f.otherProject, model.ID{3})
	_, _, missingDetail := f.store.JobDetail(f.ctx, f.writer, model.NewID(), model.ID{3})
	for name, err := range map[string]error{"outside": outside, "missing": missing, "zero project": zero, "detail outside": outsideDetail, "detail missing": missingDetail} {
		if code(err) != model.NotFound || err.Error() != outside.Error() {
			t.Fatalf("%s: %v vs %v", name, err, outside)
		}
	}
	if _, err := f.store.JobBooks(f.ctx, auth.Scope{}, f.project, model.ID{}, 10); err == nil {
		t.Fatal("zero scope listed")
	}
	if _, _, err := f.store.JobDetail(f.ctx, auth.Scope{}, f.project, model.ID{1}); err == nil {
		t.Fatal("zero scope read a job")
	}
	// A raw.read scope is not a reading permission for jobs.
	f.admin("grant", f.org, auth.AdminPayload{UserID: f.user, ProjectID: f.project, Enabled: true, Permissions: []string{string(auth.Read), string(auth.PolicyWrite), string(auth.RawRead)}, Reason: "fixture"})
	raw, err := f.svc.Authorize(f.ctx, f.cred, f.org, []model.ID{f.project}, auth.RawRead)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.JobBooks(f.ctx, raw, f.project, model.ID{}, 10); code(err) != model.Forbidden {
		t.Fatalf("raw.read listed: %v", err)
	}
	if _, _, err = f.store.JobDetail(f.ctx, raw, f.project, model.ID{1}); code(err) != model.Forbidden {
		t.Fatalf("raw.read read a job: %v", err)
	}
	// Revoking the grant without moving the epoch stops a still-valid scope.
	if err = f.store.Update(f.ctx, func(st *control.State) error {
		delete(st.Orgs[f.org.String()].Grants, f.user.String()+":"+f.project.String())
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.JobBooks(f.ctx, f.writer, f.project, model.ID{}, 10); code(err) != model.NotFound {
		t.Fatalf("a revoked grant listed: %v", err)
	}
	if _, _, err = f.store.JobDetail(f.ctx, f.writer, f.project, model.ID{1}); code(err) != model.NotFound {
		t.Fatalf("a revoked grant read a job: %v", err)
	}
}

// A listing is a read: it commits nothing and hands out copies.
func TestJobBooksReadOnlyAndOwnedCopies(t *testing.T) {
	f := newJobFx(t)
	f.seedJobs(f.project, model.ID{1})
	before, semantic := f.revision(), f.semantic()
	read, err := f.readScope(f.project)
	if err != nil {
		t.Fatal(err)
	}
	page, err := f.store.JobBooks(f.ctx, read, f.project, model.ID{}, 10)
	if err != nil || len(page.Entries) != 1 {
		t.Fatalf("%+v %v", page, err)
	}
	for i := range page.Entries[0].Snapshot.State {
		page.Entries[0].Snapshot.State[i] = 'x'
	}
	page.Entries[0].Origin.Index = 999
	if f.revision() != before || f.semantic() != semantic {
		t.Fatal("a listing changed the control state")
	}
	detail, ok, err := f.store.JobDetail(f.ctx, read, f.project, model.ID{1})
	if err != nil || !ok || detail.Origin == nil || detail.Origin.Index != 10 || detail.Snapshot.State[0] != '{' {
		t.Fatalf("a caller edit reached the store: %+v %v %v", detail, ok, err)
	}
}

// The detail read names the origin cursor of the newest ATTEMPT command, not of
// a later schedule observation or correction (which carry none).
func TestJobDetailNamesTheNewestAttemptOrigin(t *testing.T) {
	f := newJobFx(t)
	j := f.job(1)
	f.must(1, f.upd(j, 0, 1))
	f.must(2, f.upd(j, 1, 2))
	sched := f.upd(j, 2, 3)
	sched.Kind, sched.Origin = "schedule", nil
	f.must(3, sched)
	corr := f.upd(j, 3, 4)
	corr.Kind, corr.Origin = "correction", nil
	corr.Audit = &control.JobAudit{Principal: f.user, Action: "jobs.correct", Reason: "r", At: 5, Targets: []model.ID{j}}
	f.must(4, corr)
	d, ok, err := f.store.JobDetail(f.ctx, f.writer, f.project, j)
	if err != nil || !ok || d.Job != j || d.Snapshot.Version != 4 || d.Commands != 4 || d.Origin == nil || d.Origin.Group != f.group || d.Origin.Index != 2 {
		t.Fatalf("detail %+v %v %v", d, ok, err)
	}
	if _, ok, err = f.store.JobDetail(f.ctx, f.writer, f.project, f.job(9)); err != nil || ok {
		t.Fatalf("missing job in a readable project: %v %v", ok, err)
	}
	// A job with no attempt command at all has no origin.
	only := f.job(2)
	sched2 := f.upd(only, 0, 5)
	sched2.Kind, sched2.Origin = "schedule", nil
	f.must(5, sched2)
	if d, _, err = f.store.JobDetail(f.ctx, f.writer, f.project, only); err != nil || d.Origin != nil {
		t.Fatalf("origin of a schedule-only job: %+v %v", d, err)
	}
}
