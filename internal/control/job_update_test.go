// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"context"

	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/model"
)

type jobFx struct {
	*fenceFx
	writer auth.Scope
	group  model.ID
}

func newJobFx(t *testing.T) *jobFx {
	t.Helper()
	f := &jobFx{fenceFx: newFenceFx(t), group: model.ID{0xe1}}
	if err := f.store.BindJobUpdate(); err != nil {
		t.Fatal(err)
	}
	f.admin("grant", f.org, auth.AdminPayload{UserID: f.user, ProjectID: f.project, Enabled: true, Permissions: []string{string(auth.Read), string(auth.PolicyWrite)}, Reason: "fixture"})
	var err error
	if f.writer, err = f.svc.Authorize(f.ctx, f.cred, f.org, []model.ID{f.project}, auth.PolicyWrite); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *jobFx) job(n byte) model.ID { return model.ID{0xa0, n} }

func (f *jobFx) state(job model.ID, version uint64, extra map[string]any) json.RawMessage {
	m := map[string]any{"version": model.Revision(version), "org": f.org, "project": f.project, "job": job,
		"definition": map[string]any{"revision": 1}, "current_health": map[string]any{"status": "unknown"}, "compaction": map[string]any{"runs": 0}}
	for k, v := range extra {
		m[k] = v
	}
	raw, err := json.Marshal(m)
	if err != nil {
		f.t.Fatal(err)
	}
	return raw
}

// upd is an attempt update of job from expected to expected+1, tagged t.
func (f *jobFx) upd(job model.ID, expected uint64, tag byte) control.JobUpdateCommand {
	return control.JobUpdateCommand{Project: f.project, Job: job, Kind: "attempt", ExpectedVersion: model.Revision(expected), NewVersion: model.Revision(expected + 1),
		InputDigest: model.Hash{tag}, State: f.state(job, expected+1, map[string]any{"latest_schedule_key": fmt.Sprintf("k%d", tag)}), Origin: &model.Cursor{Group: f.group, Index: model.Uint64(tag)}}
}

func (f *jobFx) cmdFor(tag byte, c control.JobUpdateCommand) control.Command {
	raw, err := json.Marshal(c)
	if err != nil {
		f.t.Fatal(err)
	}
	return control.Command{CommandID: model.ID{0xc0, tag}, Kind: string(control.KindUpdateJob), Payload: raw}
}

func (f *jobFx) send(tag byte, c control.JobUpdateCommand) (control.Result, error) {
	f.t.Helper()
	return f.store.TransactJobs(f.ctx, f.writer, f.cmdFor(tag, c))
}

func (f *jobFx) must(tag byte, c control.JobUpdateCommand) control.Result {
	f.t.Helper()
	r, err := f.send(tag, c)
	if err != nil {
		f.t.Fatalf("update %d: %v", tag, err)
	}
	return r
}

func (f *jobFx) book(job model.ID) (control.JobSnapshot, bool) {
	f.t.Helper()
	s, ok, err := f.store.JobBook(f.ctx, f.writer, f.project, job)
	if err != nil {
		f.t.Fatal(err)
	}
	return s, ok
}

func (f *jobFx) books() map[string]json.RawMessage {
	var out map[string]json.RawMessage
	if err := f.store.View(f.ctx, func(st control.State) error { out = st.JobBooks; return nil }); err != nil {
		f.t.Fatal(err)
	}
	return out
}

// semantic is the books with the per-fixture identities (organization, project,
// principal) and the digests derived from them normalized away.
func (f *jobFx) semantic() string {
	out := map[string]control.JobRecord{}
	for key, raw := range f.books() {
		var rec control.JobRecord
		if err := json.Unmarshal(raw, &rec); err != nil {
			f.t.Fatal(err)
		}
		rec.Digest = model.Hash{}
		for i := range rec.Commands {
			rec.Commands[i].Principal = model.ID{0xff}
		}
		out[strings.NewReplacer(f.org.String(), "ORG", f.project.String(), "PROJECT").Replace(key)] = rec
	}
	raw, err := json.Marshal(out)
	if err != nil {
		f.t.Fatal(err)
	}
	return strings.NewReplacer(f.org.String(), "ORG", f.project.String(), "PROJECT").Replace(string(raw))
}

func (f *jobFx) audits(action string) []model.ControlAudit {
	var out []model.ControlAudit
	_ = f.store.View(f.ctx, func(st control.State) error {
		for _, a := range st.Audits {
			if a.Action == action {
				out = append(out, a)
			}
		}
		return nil
	})
	return out
}

func (f *jobFx) record(job model.ID) control.JobRecord {
	f.t.Helper()
	var rec control.JobRecord
	raw, ok := f.books()[f.org.String()+":"+f.project.String()+":"+job.String()]
	if !ok {
		f.t.Fatal("no record")
	}
	if err := json.Unmarshal(raw, &rec); err != nil {
		f.t.Fatal(err)
	}
	return rec
}

func TestJobUpdateStoresRecord(t *testing.T) {
	f := newJobFx(t)
	j := f.job(1)
	res := f.must(1, f.upd(j, 0, 1))
	if res.Phase != "applied" || res.Cursor.Index != 1 || len(res.AffectedIDs) != 1 || res.AffectedIDs[0] != j {
		t.Fatalf("result %+v", res)
	}
	snap, ok := f.book(j)
	if !ok || snap.Version != 1 || snap.Erased || snap.Digest == (model.Hash{}) {
		t.Fatalf("snapshot %+v %v", snap, ok)
	}
	var st map[string]json.RawMessage
	if err := json.Unmarshal(snap.State, &st); err != nil || string(st["latest_schedule_key"]) != `"k1"` {
		t.Fatalf("state %s", snap.State)
	}
	f.must(2, f.upd(j, 1, 2))
	rec := f.record(j)
	if rec.Version != 2 || len(rec.Commands) != 2 || rec.Commands[0].ID != (model.ID{0xc0, 1}) || rec.Commands[1].Version != 2 || rec.Commands[0].Origin == nil || rec.Commands[0].Origin.Index != 1 {
		t.Fatalf("record %+v", rec)
	}
	if _, ok = f.book(f.job(2)); ok {
		t.Fatal("a job that was never written was found")
	}
}

func TestJobUpdateVersionCompareAndSet(t *testing.T) {
	f := newJobFx(t)
	j := f.job(1)
	f.must(1, f.upd(j, 0, 1))
	f.must(2, f.upd(j, 1, 2))
	// A command that read version 1 loses to the one that already made it 2.
	_, err := f.send(3, f.upd(j, 1, 3))
	if code(err) != model.Stale || faultDetail(err) != control.JobVersionConflict+" current=2" {
		t.Fatalf("stale update: %v (%q)", err, faultDetail(err))
	}
	// A new job cannot start from a nonzero version, nor skip one.
	if _, err = f.send(4, f.upd(f.job(2), 1, 4)); code(err) != model.Stale || faultDetail(err) != control.JobVersionConflict+" current=0" {
		t.Fatalf("update of an absent job at version 1: %v (%q)", err, faultDetail(err))
	}
	skip := f.upd(j, 2, 5)
	skip.NewVersion = 4
	skip.State = f.state(j, 4, nil)
	if _, err = f.send(5, skip); code(err) != model.Invalid {
		t.Fatalf("skipped version: %v", err)
	}
	if snap, _ := f.book(j); snap.Version != 2 {
		t.Fatalf("version %d", snap.Version)
	}
}

func TestJobUpdateExactlyOnceUnderReorderedRetries(t *testing.T) {
	f := newJobFx(t)
	j := f.job(1)
	u1, u2, u3 := f.upd(j, 0, 1), f.upd(j, 1, 2), f.upd(j, 2, 3)
	first := f.must(1, u1)
	f.must(2, u2)
	f.must(3, u3)
	before := f.semantic()
	// A retry of the first command reaches the store after two others moved the
	// version on: a replay, not a stale error and not a second application.
	again, err := f.send(1, u1)
	if err != nil || again.Phase != "replayed" || again.Cursor.Index != first.Cursor.Index || len(again.AffectedIDs) != 1 {
		t.Fatalf("retry %+v %v", again, err)
	}
	for _, tag := range []byte{3, 1, 2, 2, 3, 1} {
		c := map[byte]control.JobUpdateCommand{1: u1, 2: u2, 3: u3}[tag]
		if r, err := f.send(tag, c); err != nil || r.Phase != "replayed" || r.Cursor.Index != model.Uint64(tag) {
			t.Fatalf("retry %d: %+v %v", tag, r, err)
		}
	}
	if after := f.semantic(); after != before {
		t.Fatalf("retries changed the books:\n%s\n%s", before, after)
	}
	// The same command ID with another input digest is a conflict, never applied.
	other := u1
	other.InputDigest = model.Hash{0x99}
	if _, err = f.send(1, other); code(err) != model.Conflict || faultDetail(err) != "job_command_reused" {
		t.Fatalf("reused command: %v (%q)", err, faultDetail(err))
	}
	// So is the same ID with another kind.
	kind := u1
	kind.Kind, kind.Origin = "schedule", nil
	if _, err = f.send(1, kind); code(err) != model.Conflict {
		t.Fatalf("command reused with another kind: %v", err)
	}
	// The same command ID on another job is another command.
	if _, err = f.send(1, f.upd(f.job(2), 0, 1)); err != nil {
		t.Fatalf("same ID on another job: %v", err)
	}
	if snap, _ := f.book(j); snap.Version != 3 {
		t.Fatalf("version %d", snap.Version)
	}
}

func TestJobUpdateDeterministicUnderReorderedRetries(t *testing.T) {
	run := func(retries bool) string {
		f := newJobFx(t)
		a, b := f.job(1), f.job(2)
		u1, u2, u3 := f.upd(a, 0, 1), f.upd(a, 1, 2), f.upd(b, 0, 3)
		f.must(1, u1)
		if retries {
			f.must(1, u1)
		}
		f.must(2, u2)
		if retries {
			f.must(1, u1)
		}
		f.must(3, u3)
		if retries {
			f.must(2, u2)
			f.must(3, u3)
		}
		// Job IDs are fixed; org/project are random per fixture and normalized.
		return f.semantic()
	}
	if clean, noisy := run(false), run(true); clean != noisy {
		t.Fatalf("retries changed state:\n%s\n%s", clean, noisy)
	}
}

func TestJobUpdateScopeBeforeLookup(t *testing.T) {
	f := newJobFx(t)
	j := f.job(1)
	f.must(1, f.upd(j, 0, 1))
	foreign := f.upd(j, 0, 2)
	foreign.Project = f.otherProject
	_, errOther := f.send(2, foreign)
	missing := f.upd(j, 0, 2)
	missing.Project = model.NewID()
	_, errMissing := f.send(2, missing)
	if code(errOther) != model.NotFound || code(errMissing) != model.NotFound || errOther.Error() != errMissing.Error() {
		t.Fatalf("wrong scope %v vs missing %v", errOther, errMissing)
	}
	if _, _, err := f.store.JobBook(f.ctx, f.writer, f.otherProject, j); code(err) != model.NotFound {
		t.Fatalf("read outside the scope: %v", err)
	}
	if _, _, err := f.store.JobBook(f.ctx, f.writer, model.NewID(), j); code(err) != model.NotFound {
		t.Fatalf("read of a missing project: %v", err)
	}
	if _, err := f.store.JobGaps(f.ctx, f.writer, f.otherProject); code(err) != model.NotFound {
		t.Fatalf("gaps outside the scope: %v", err)
	}
	// Read-only and org-admin scopes cannot write; the generic path is closed.
	read, err := f.readScope(f.project)
	if err != nil {
		t.Fatal(err)
	}
	next := f.cmdFor(2, f.upd(j, 1, 2))
	if _, err = f.store.TransactJobs(f.ctx, read, next); code(err) != model.Forbidden {
		t.Fatalf("read scope wrote: %v", err)
	}
	if _, err = f.store.TransactJobs(f.ctx, f.adminScope(), next); code(err) != model.Forbidden {
		t.Fatalf("admin scope wrote through the job path: %v", err)
	}
	next.ExpectedRevision = f.revision()
	if _, err = f.store.Transact(f.ctx, f.adminScope(), next); err == nil {
		t.Fatal("admin scope wrote through the generic path")
	}
	if _, err = f.store.Transact(f.ctx, f.writer, next); err == nil {
		t.Fatal("job scope wrote through the generic path")
	}
	issues, err := f.svc.Authorize(f.ctx, f.cred, f.org, []model.ID{f.project}, auth.Read)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.TransactJobs(f.ctx, issues, next); code(err) != model.Forbidden {
		t.Fatalf("telemetry.read scope wrote: %v", err)
	}
	// Reads: the read scope and the writer may read, the zero scope may not.
	if _, ok, err := f.store.JobBook(f.ctx, read, f.project, j); err != nil || !ok {
		t.Fatalf("telemetry.read cannot read: %v", err)
	}
	if _, _, err = f.store.JobBook(f.ctx, auth.Scope{}, f.project, j); err == nil {
		t.Fatal("zero scope read")
	}
	if _, err = f.store.TransactJobs(f.ctx, auth.Scope{}, next); err == nil {
		t.Fatal("zero scope wrote")
	}
	// Revoking the grant without moving the epoch stops a still-valid scope in the
	// very transaction that would apply the change.
	if err = f.store.Update(f.ctx, func(st *control.State) error {
		delete(st.Orgs[f.org.String()].Grants, f.user.String()+":"+f.project.String())
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = f.send(2, f.upd(j, 1, 2)); code(err) != model.NotFound {
		t.Fatalf("a scope with a revoked grant wrote: %v", err)
	}
	if _, _, err = f.store.JobBook(f.ctx, f.writer, f.project, j); code(err) != model.NotFound {
		t.Fatalf("a scope with a revoked grant read: %v", err)
	}
	if _, _, err = f.store.JobBook(f.ctx, read, f.project, j); code(err) != model.NotFound {
		t.Fatalf("a read scope with a revoked grant read: %v", err)
	}
	// A replay is scoped like a first command.
	if _, err = f.send(1, f.upd(j, 0, 1)); code(err) != model.NotFound {
		t.Fatalf("replay by a revoked scope: %v", err)
	}
}

func TestJobUpdateScopeIsConfinedToItsProjects(t *testing.T) {
	f := newJobFx(t)
	f.admin("grant", f.org, auth.AdminPayload{UserID: f.user, ProjectID: f.otherProject, Enabled: true, Permissions: []string{string(auth.Read), string(auth.PolicyWrite)}, Reason: "fixture"})
	one, err := f.svc.Authorize(f.ctx, f.cred, f.org, []model.ID{f.project}, auth.PolicyWrite)
	if err != nil {
		t.Fatal(err)
	}
	both, err := f.svc.Authorize(f.ctx, f.cred, f.org, []model.ID{f.project, f.otherProject}, auth.PolicyWrite)
	if err != nil {
		t.Fatal(err)
	}
	c := f.upd(f.job(1), 0, 1)
	c.Project = f.otherProject
	c.State = f.state(f.job(1), 1, map[string]any{"project": f.otherProject})
	if _, err = f.store.TransactJobs(f.ctx, one, f.cmdFor(1, c)); code(err) != model.NotFound {
		t.Fatalf("a scope naming one project wrote to another: %v", err)
	}
	if _, err = f.store.TransactJobs(f.ctx, both, f.cmdFor(1, c)); err != nil {
		t.Fatalf("a scope naming both projects: %v", err)
	}
	if _, ok, err := f.store.JobBook(f.ctx, one, f.otherProject, f.job(1)); code(err) != model.NotFound || ok {
		t.Fatalf("read outside the scope's projects: %v", err)
	}
}

func TestJobUpdateCommandBelongsToItsPrincipal(t *testing.T) {
	f := newJobFx(t)
	second := model.NewID()
	f.admin("create_user", f.org, auth.AdminPayload{ID: second, Email: "second@example.test", Password: "a long test password 2026", Reason: "fixture"})
	f.admin("membership", f.org, auth.AdminPayload{UserID: second, Enabled: true, Reason: "fixture"})
	f.admin("grant", f.org, auth.AdminPayload{UserID: second, ProjectID: f.project, Enabled: true, Permissions: []string{string(auth.PolicyWrite)}, Reason: "fixture"})
	login, err := f.svc.Login(f.ctx, "second@example.test", "a long test password 2026", "")
	if err != nil {
		t.Fatal(err)
	}
	cred, err := f.svc.Authenticate(f.ctx, login.Token)
	if err != nil {
		t.Fatal(err)
	}
	other, err := f.svc.Authorize(f.ctx, cred, f.org, []model.ID{f.project}, auth.PolicyWrite)
	if err != nil {
		t.Fatal(err)
	}
	if f.writer, err = f.svc.Authorize(f.ctx, f.cred, f.org, []model.ID{f.project}, auth.PolicyWrite); err != nil {
		t.Fatal(err)
	}
	j := f.job(1)
	u := f.upd(j, 0, 1)
	f.must(1, u)
	if _, err = f.store.TransactJobs(f.ctx, other, f.cmdFor(1, u)); code(err) != model.NotFound {
		t.Fatalf("another principal replayed a command: %v", err)
	}
	// The other principal writes as itself, and a correction names it.
	u2 := f.upd(j, 1, 2)
	u2.Kind, u2.Origin = "correction", nil
	u2.Audit = &control.JobAudit{Principal: second, Action: "jobs.correct", Reason: "theirs", At: 5, Targets: []model.ID{j}}
	if _, err = f.store.TransactJobs(f.ctx, other, f.cmdFor(2, u2)); err != nil {
		t.Fatal(err)
	}
	if a := f.audits("jobs.correct"); len(a) != 1 || a[0].Principal != second {
		t.Fatalf("audits %+v", a)
	}
	// An audit cannot name the first principal when the second acts.
	u3 := f.upd(j, 2, 3)
	u3.Kind, u3.Origin = "correction", nil
	u3.Audit = &control.JobAudit{Principal: f.user, Action: "jobs.correct", Reason: "x", At: 5, Targets: []model.ID{j}}
	if _, err = f.store.TransactJobs(f.ctx, other, f.cmdFor(3, u3)); code(err) != model.Forbidden {
		t.Fatalf("audit under another principal: %v", err)
	}
}

func TestJobUpdateAudit(t *testing.T) {
	f := newJobFx(t)
	j := f.job(1)
	f.must(1, f.upd(j, 0, 1))
	corr := func(tag byte, expected uint64, a control.JobAudit) control.JobUpdateCommand {
		c := f.upd(j, expected, tag)
		c.Kind, c.Origin = "correction", nil
		c.Audit = &a
		return c
	}
	good := control.JobAudit{Principal: f.user, Action: "jobs.correct", Reason: "mislabeled retry", At: 77, Targets: []model.ID{j, {0xaa}}}
	res := f.must(2, corr(2, 1, good))
	audits := f.audits("jobs.correct")
	if len(audits) != 1 {
		t.Fatalf("audits %+v", audits)
	}
	a := audits[0]
	if a.Principal != f.user || a.Org != f.org.String() || a.PolicyEpoch != f.writer.PolicyEpoch() || a.Outcome != model.AuditAllowed || a.Time != 77 || a.Reason != good.Reason || len(a.Targets) != 2 || a.RequestID != j || a.ID == (model.ID{}) {
		t.Fatalf("audit %+v", a)
	}
	// A replay appends no second audit, and the audit ID is a function of the command.
	if r, err := f.send(2, corr(2, 1, good)); err != nil || r.Phase != "replayed" || r.Cursor.Index != res.Cursor.Index || len(f.audits("jobs.correct")) != 1 {
		t.Fatalf("replay %+v %v", r, err)
	}
	bad := map[string]func(a *control.JobAudit){
		"other principal": func(a *control.JobAudit) { a.Principal = model.NewID() },
		"bare action":     func(a *control.JobAudit) { a.Action = "correct" },
		"foreign action":  func(a *control.JobAudit) { a.Action = "issues.correct" },
		"empty action":    func(a *control.JobAudit) { a.Action = "jobs." },
		"upper action":    func(a *control.JobAudit) { a.Action = "jobs.Correct" },
		"empty reason":    func(a *control.JobAudit) { a.Reason = "" },
		"control reason":  func(a *control.JobAudit) { a.Reason = "a\x00b" },
		"long reason":     func(a *control.JobAudit) { a.Reason = strings.Repeat("r", 513) },
		"no time":         func(a *control.JobAudit) { a.At = 0 },
		"no targets":      func(a *control.JobAudit) { a.Targets = nil },
		"many targets":    func(a *control.JobAudit) { a.Targets = []model.ID{{1}, {2}, {3}, {4}, {5}, {6}, {7}, {8}, {9}} },
	}
	for name, mutate := range bad {
		a := good
		a.Targets = append([]model.ID(nil), good.Targets...)
		mutate(&a)
		if _, err := f.send(9, corr(9, 2, a)); err == nil {
			t.Errorf("%s: committed", name)
		} else if c := code(err); c != model.Invalid && c != model.Forbidden {
			t.Errorf("%s: %v", name, err)
		}
	}
	if len(f.audits("jobs.correct")) != 1 {
		t.Fatal("a refused correction left an audit")
	}
	// An audit belongs to a correction, and a correction needs one.
	withAudit := f.upd(j, 2, 8)
	withAudit.Audit = &good
	if _, err := f.send(8, withAudit); code(err) != model.Invalid {
		t.Fatalf("attempt with audit: %v", err)
	}
	noAudit := corr(7, 2, good)
	noAudit.Audit = nil
	if _, err := f.send(7, noAudit); code(err) != model.Invalid {
		t.Fatalf("correction without audit: %v", err)
	}
	// A stale correction leaves no audit either.
	if _, err := f.send(6, corr(6, 1, good)); code(err) != model.Stale || len(f.audits("jobs.correct")) != 1 {
		t.Fatalf("stale correction: %v", err)
	}
}

func TestJobUpdateRejectsMalformedCommands(t *testing.T) {
	f := newJobFx(t)
	j := f.job(1)
	f.must(1, f.upd(j, 0, 1))
	nested := "0"
	for range 16 {
		nested = `{"a":` + nested + `}`
	}
	cases := map[string]func(c *control.JobUpdateCommand){
		"zero digest":    func(c *control.JobUpdateCommand) { c.InputDigest = model.Hash{} },
		"unknown kind":   func(c *control.JobUpdateCommand) { c.Kind = "delete" },
		"empty kind":     func(c *control.JobUpdateCommand) { c.Kind = "" },
		"no origin":      func(c *control.JobUpdateCommand) { c.Origin = nil },
		"version two up": func(c *control.JobUpdateCommand) { c.NewVersion = 3; c.State = f.state(j, 3, nil) },
		"version same":   func(c *control.JobUpdateCommand) { c.NewVersion = 1; c.State = f.state(j, 1, nil) },
		"overflow": func(c *control.JobUpdateCommand) {
			c.ExpectedVersion = ^model.Revision(0)
			c.NewVersion = 0
			c.State = f.state(j, 0, nil)
		},
		"schedule with audit": func(c *control.JobUpdateCommand) {
			c.Kind, c.Origin = "schedule", nil
			c.Audit = &control.JobAudit{Principal: f.user, Action: "jobs.correct", Reason: "x", At: 5, Targets: []model.ID{j}}
		},
		"schedule with origin": func(c *control.JobUpdateCommand) { c.Kind = "schedule" },
		"correction with origin": func(c *control.JobUpdateCommand) {
			c.Kind = "correction"
			c.Audit = &control.JobAudit{Principal: f.user, Action: "jobs.correct", Reason: "x", At: 5, Targets: []model.ID{j}}
		},
		"state version": func(c *control.JobUpdateCommand) { c.State = f.state(j, 3, nil) },
		"state org":     func(c *control.JobUpdateCommand) { c.State = f.state(j, 2, map[string]any{"org": model.NewID()}) },
		"state project": func(c *control.JobUpdateCommand) { c.State = f.state(j, 2, map[string]any{"project": f.otherProject}) },
		"state job":     func(c *control.JobUpdateCommand) { c.State = f.state(j, 2, map[string]any{"job": f.job(9)}) },
		"state no org": func(c *control.JobUpdateCommand) {
			c.State = json.RawMessage(`{"version":"2","project":"` + f.project.String() + `","job":"` + j.String() + `"}`)
		},
		"unknown key":   func(c *control.JobUpdateCommand) { c.State = f.state(j, 2, map[string]any{"message": "boom"}) },
		"exception key": func(c *control.JobUpdateCommand) { c.State = f.state(j, 2, map[string]any{"exception": "boom"}) },
		"state array":   func(c *control.JobUpdateCommand) { c.State = json.RawMessage(`[]`) },
		"state null":    func(c *control.JobUpdateCommand) { c.State = json.RawMessage(`null`) },
		"state string":  func(c *control.JobUpdateCommand) { c.State = json.RawMessage(`"x"`) },
		"long string": func(c *control.JobUpdateCommand) {
			c.State = f.state(j, 2, map[string]any{"latest_schedule_key": strings.Repeat("x", 1025)})
		},
		"control char": func(c *control.JobUpdateCommand) {
			c.State = f.state(j, 2, map[string]any{"latest_schedule_key": "a\nb"})
		},
		"nested control": func(c *control.JobUpdateCommand) {
			c.State = f.state(j, 2, map[string]any{"definition": map[string]any{"cron": "a\x07"}})
		},
		"control key": func(c *control.JobUpdateCommand) {
			c.State = f.state(j, 2, map[string]any{"occurrences": map[string]any{"k\x00": 1}})
		},
		"too deep": func(c *control.JobUpdateCommand) {
			c.State = f.state(j, 2, map[string]any{"definition": json.RawMessage(nested)})
		},
	}
	for name, mutate := range cases {
		c := f.upd(j, 1, 2)
		mutate(&c)
		if _, err := f.send(2, c); code(err) != model.Invalid {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A payload with an unknown field, trailing data, or the wrong command shape.
	base := f.cmdFor(2, f.upd(j, 1, 2))
	zero := strings.Repeat("0", 32)
	nullState := f.upd(j, 1, 2)
	nullState.State = json.RawMessage(`null`)
	np := string(f.cmdFor(2, nullState).Payload)
	for name, payload := range map[string]string{
		"empty state":     strings.Replace(np, `"state":null`, `"state":""`, 1),
		"truncated state": strings.Replace(np, `"state":null`, `"state":{"version":"2"`, 1),
		"zero job":        strings.Replace(string(base.Payload), `"job":"`+j.String()+`"`, `"job":"`+zero+`"`, 1),
		"zero origin":     strings.Replace(string(base.Payload), f.group.String(), zero, 1),
		"unknown field":   strings.Replace(string(base.Payload), `{"project"`, `{"extra":1,"project"`, 1),
		"trailing":        string(base.Payload) + `{}`,
		"not json":        `nope`,
	} {
		if _, err := f.store.TransactJobs(f.ctx, f.writer, control.Command{CommandID: base.CommandID, Kind: base.Kind, Payload: json.RawMessage(payload)}); code(err) != model.Invalid {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := f.store.TransactJobs(f.ctx, f.writer, control.Command{Kind: base.Kind, Payload: base.Payload}); code(err) != model.Invalid {
		t.Errorf("zero command ID: %v", err)
	}
	if _, err := f.store.TransactJobs(f.ctx, f.writer, control.Command{CommandID: base.CommandID, Kind: string(control.KindApplyIssueEvidence), Payload: base.Payload}); code(err) != model.Invalid {
		t.Errorf("wrong kind: %v", err)
	}
	if snap, _ := f.book(j); snap.Version != 1 {
		t.Fatalf("a malformed command changed the job: version %d", snap.Version)
	}
	if f.store.BindJobUpdate() == nil {
		t.Fatal("the handler bound twice")
	}
}

func (f *jobFx) seed(records map[string]control.JobRecord) {
	f.t.Helper()
	if err := f.store.Update(f.ctx, func(st *control.State) error {
		if st.JobBooks == nil {
			st.JobBooks = map[string]json.RawMessage{}
		}
		for k, r := range records {
			raw, err := json.Marshal(r)
			if err != nil {
				return err
			}
			st.JobBooks[k] = raw
		}
		return nil
	}); err != nil {
		f.t.Fatal(err)
	}
}

func TestJobUpdateBounds(t *testing.T) {
	f := newJobFx(t)
	j := f.job(1)
	f.must(1, f.upd(j, 0, 1))
	filler := func(n int) map[string]any {
		m := make(map[string]any, n)
		for i := range n {
			m[fmt.Sprintf("%032x", i)] = map[string]any{}
		}
		return m
	}
	arr := func(n int) []any { return make([]any, n) }
	over := map[string]map[string]any{
		"runs":        {"runs": filler(513)},
		"attempts":    {"attempts": filler(2049)},
		"occurrences": {"occurrences": filler(1025)},
		"history":     {"history": arr(65)},
		"intervals":   {"incomplete_intervals": arr(257)},
	}
	for name, extra := range over {
		if _, err := f.send(2, func() control.JobUpdateCommand { c := f.upd(j, 1, 2); c.State = f.state(j, 2, extra); return c }()); code(err) != model.Quota {
			t.Errorf("%s over the bound: %v", name, err)
		}
	}
	// At the bound is fine.
	at := map[string]any{"runs": filler(512), "attempts": filler(2048), "occurrences": filler(1024), "history": arr(64), "incomplete_intervals": arr(256)}
	c := f.upd(j, 1, 2)
	c.State = f.state(j, 2, at)
	if _, err := f.send(2, c); err != nil {
		t.Fatalf("state at the bounds: %v", err)
	}
	// A state over 512 KiB is Quota; a payload far over the limit is TooLarge.
	pad := map[string]any{}
	for i := range 500 {
		pad[fmt.Sprintf("%032x", i)] = map[string]any{"reason": strings.Repeat("x", 1000)}
	}
	big := f.upd(j, 2, 3)
	big.State = f.state(j, 3, map[string]any{"attempts": pad})
	if len(big.State) <= 512<<10 {
		t.Fatalf("test state is %d bytes", len(big.State))
	}
	if _, err := f.send(3, big); code(err) != model.Quota {
		t.Fatalf("oversized state: %v", err)
	}
	huge := f.cmdFor(3, big)
	huge.Payload = append(huge.Payload, make([]byte, 1<<20)...)
	if _, err := f.store.TransactJobs(f.ctx, f.writer, huge); code(err) != model.TooLarge {
		t.Fatalf("oversized payload: %v", err)
	}
	if snap, _ := f.book(j); snap.Version != 2 {
		t.Fatalf("version %d", snap.Version)
	}
}

func TestJobUpdateProjectBounds(t *testing.T) {
	f := newJobFx(t)
	rec := func(job model.ID, size int) control.JobRecord {
		return control.JobRecord{Org: f.org, Project: f.project, Job: job, Version: 1, State: json.RawMessage(`"` + strings.Repeat("s", size) + `"`)}
	}
	key := func(job model.ID) string { return f.org.String() + ":" + f.project.String() + ":" + job.String() }
	// Another org's or project's books never count against this project.
	foreign := map[string]control.JobRecord{}
	for i := range 70 {
		job := model.ID{0xb0, byte(i)}
		foreign[model.NewID().String()+":"+f.project.String()+":"+job.String()] = rec(job, 10)
		foreign[f.org.String()+":"+f.otherProject.String()+":"+job.String()] = rec(job, 10)
	}
	f.seed(foreign)
	seeded := map[string]control.JobRecord{}
	for i := range 64 {
		job := model.ID{0xb1, byte(i)}
		seeded[key(job)] = rec(job, 10)
	}
	f.seed(seeded)
	if _, err := f.send(1, f.upd(f.job(1), 0, 1)); code(err) != model.Quota {
		t.Fatalf("65th job: %v", err)
	}
	// An existing job still updates at the job bound.
	seeded2 := model.ID{0xb1, 0}
	c := f.upd(seeded2, 1, 2)
	if _, err := f.send(2, c); err != nil {
		t.Fatalf("update at the job bound: %v", err)
	}
	// The project's byte bound: 16 jobs of 520000 bytes leave room for a small
	// update and refuse a 100 KB one.
	g := newJobFx(t)
	grec := func(job model.ID, size int) control.JobRecord {
		return control.JobRecord{Org: g.org, Project: g.project, Job: job, Version: 1, State: json.RawMessage(`"` + strings.Repeat("s", size) + `"`)}
	}
	bulk := map[string]control.JobRecord{}
	for i := range 16 {
		job := model.ID{0xb2, byte(i)}
		bulk[g.org.String()+":"+g.project.String()+":"+job.String()] = grec(job, 520000)
	}
	g.seed(bulk)
	pad := map[string]any{}
	for i := range 90 {
		pad[fmt.Sprintf("%032x", i)] = map[string]any{"reason": strings.Repeat("x", 1000)}
	}
	large := g.upd(g.job(1), 0, 1)
	large.State = g.state(g.job(1), 1, map[string]any{"attempts": pad})
	if _, err := g.send(1, large); code(err) != model.Quota {
		t.Fatalf("project over its byte bound: %v", err)
	}
	if _, err := g.send(2, g.upd(g.job(2), 0, 2)); err != nil {
		t.Fatalf("small job under the byte bound: %v", err)
	}
}

// Other projects' and other organizations' books never count against a
// project's job bound.
func TestJobUpdateJobBoundIsPerProject(t *testing.T) {
	f := newJobFx(t)
	foreign := map[string]control.JobRecord{}
	for i := range 70 {
		job := model.ID{0xb4, byte(i)}
		other := model.NewID()
		foreign[other.String()+":"+f.project.String()+":"+job.String()] = control.JobRecord{Org: other, Project: f.project, Job: job, Version: 1, State: json.RawMessage(`"x"`)}
		foreign[f.org.String()+":"+f.otherProject.String()+":"+job.String()] = control.JobRecord{Org: f.org, Project: f.otherProject, Job: job, Version: 1, State: json.RawMessage(`"x"`)}
	}
	f.seed(foreign)
	if _, err := f.send(1, f.upd(f.job(1), 0, 1)); err != nil {
		t.Fatalf("a project's first job with 140 foreign books present: %v", err)
	}
}

// An existing job's own record does not count against the project's byte bound
// twice: a project at the bound still takes an update of one of its jobs.
func TestJobUpdateOfExistingJobAtProjectByteBound(t *testing.T) {
	f := newJobFx(t)
	bulk := map[string]control.JobRecord{}
	var first model.ID
	for i := range 16 {
		job := model.ID{0xb3, byte(i)}
		if i == 0 {
			first = job
		}
		rec := control.JobRecord{Org: f.org, Project: f.project, Job: job, Version: 1, State: json.RawMessage(`"` + strings.Repeat("s", 524288) + `"`)}
		bulk[f.org.String()+":"+f.project.String()+":"+job.String()] = rec
	}
	f.seed(bulk)
	// A seventeenth job does not fit while the project is over its bound.
	if _, err := f.send(2, f.upd(f.job(9), 0, 2)); code(err) != model.Quota {
		t.Fatalf("new job over the project bound: %v", err)
	}
	if _, err := f.send(1, f.upd(first, 1, 1)); err != nil {
		t.Fatalf("update of an existing job at the project bound: %v", err)
	}
}

func TestJobReadsNeedAReadingPermission(t *testing.T) {
	f := newJobFx(t)
	j := f.job(1)
	f.must(1, f.upd(j, 0, 1))
	f.admin("grant", f.org, auth.AdminPayload{UserID: f.user, ProjectID: f.project, Enabled: true, Permissions: []string{string(auth.Read), string(auth.PolicyWrite), string(auth.RawRead)}, Reason: "fixture"})
	raw, err := f.svc.Authorize(f.ctx, f.cred, f.org, []model.ID{f.project}, auth.RawRead)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = f.store.JobBook(f.ctx, raw, f.project, j); code(err) != model.Forbidden {
		t.Fatalf("raw.read scope read a job: %v", err)
	}
	if _, err = f.store.JobGaps(f.ctx, raw, f.project); code(err) != model.Forbidden {
		t.Fatalf("raw.read scope read gaps: %v", err)
	}
}

func TestJobUpdateCommandMemoryIsBounded(t *testing.T) {
	f := newJobFx(t)
	j := f.job(1)
	rec := control.JobRecord{Org: f.org, Project: f.project, Job: j, Version: 1, State: f.state(j, 1, nil)}
	for i := range 1024 {
		rec.Commands = append(rec.Commands, control.JobCommandEntry{ID: model.ID{0xdd, byte(i >> 8), byte(i)}, Principal: f.user, Kind: "attempt", Digest: model.Hash{1}, Version: 1})
	}
	f.seed(map[string]control.JobRecord{f.org.String() + ":" + f.project.String() + ":" + j.String(): rec})
	f.must(1, f.upd(j, 1, 1))
	got := f.record(j)
	if len(got.Commands) != 1024 || got.Commands[0].ID != (model.ID{0xdd, 0, 1}) || got.Commands[1023].ID != (model.ID{0xc0, 1}) {
		t.Fatalf("command memory: %d entries, first %v last %v", len(got.Commands), got.Commands[0].ID, got.Commands[len(got.Commands)-1].ID)
	}
	// The newest commands are still recognized.
	if r, err := f.send(1, f.upd(j, 1, 1)); err != nil || r.Phase != "replayed" {
		t.Fatalf("retry of the newest command: %+v %v", r, err)
	}
}

func TestJobUpdateConcurrentUpdatersOnOneJob(t *testing.T) {
	f := newJobFx(t)
	j := f.job(1)
	const n = 24
	var wg sync.WaitGroup
	var mu sync.Mutex
	stale := 0
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tag := byte(i + 1)
			for range 400 {
				snap, _, err := f.store.JobBook(f.ctx, f.writer, f.project, j)
				if err != nil {
					t.Error(err)
					return
				}
				_, err = f.send(tag, f.upd(j, uint64(snap.Version), tag))
				if err == nil {
					return
				}
				if code(err) != model.Stale {
					t.Error(err)
					return
				}
				mu.Lock()
				stale++
				mu.Unlock()
			}
			t.Errorf("updater %d never won", i)
		}()
	}
	wg.Wait()
	rec := f.record(j)
	if rec.Version != n || len(rec.Commands) != n {
		t.Fatalf("version %d, %d commands", rec.Version, len(rec.Commands))
	}
	seen := map[model.ID]bool{}
	for i, e := range rec.Commands {
		if seen[e.ID] || e.Version != model.Revision(i+1) {
			t.Fatalf("command %d: %+v", i, e)
		}
		seen[e.ID] = true
	}
	t.Logf("%d stale losses retried", stale)
}

func TestJobUpdateConcurrentSameCommandCommitsOnce(t *testing.T) {
	f := newJobFx(t)
	j := f.job(1)
	cmd := f.cmdFor(1, f.upd(j, 0, 1))
	results := make([]control.Result, 24)
	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := f.store.TransactJobs(f.ctx, f.writer, cmd)
			if err != nil {
				t.Error(err)
			}
			results[i] = r
		}()
	}
	wg.Wait()
	applied := 0
	for _, r := range results {
		if r.Cursor.Index != 1 || r.Phase != "applied" && r.Phase != "replayed" {
			t.Fatalf("result %+v", r)
		}
		if r.Phase == "applied" {
			applied++
		}
	}
	if rec := f.record(j); applied != 1 || rec.Version != 1 || len(rec.Commands) != 1 {
		t.Fatalf("applied %d, version %d, commands %d", applied, rec.Version, len(rec.Commands))
	}
}

func TestJobUpdateStateHoldsNoTelemetryText(t *testing.T) {
	f := newJobFx(t)
	j := f.job(1)
	c := f.upd(j, 0, 1)
	f.must(1, c)
	rec := map[string]json.RawMessage{}
	if err := json.Unmarshal(f.books()[f.org.String()+":"+f.project.String()+":"+j.String()], &rec); err != nil {
		t.Fatal(err)
	}
	keys := make([]string, 0, len(rec))
	for k := range rec {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if strings.Join(keys, ",") != "commands,digest,job,org,project,state,version" {
		t.Fatalf("record keys %v", keys)
	}
	var entry []map[string]json.RawMessage
	if err := json.Unmarshal(rec["commands"], &entry); err != nil {
		t.Fatal(err)
	}
	ek := make([]string, 0, 6)
	for k := range entry[0] {
		ek = append(ek, k)
	}
	sort.Strings(ek)
	if strings.Join(ek, ",") != "digest,id,kind,origin,principal,version" {
		t.Fatalf("command entry keys %v", ek)
	}
}

func TestJobGapsAreProjectScoped(t *testing.T) {
	f := newJobFx(t)
	var ids []model.ID
	for i, project := range []model.ID{f.project, f.project, f.otherProject} {
		g, err := f.store.RecordEvidenceGap(f.ctx, model.EvidenceGap{Org: f.org, Project: project, Group: model.ID{0xe1, byte(i)}, After: model.Uint64(10 * i), Through: model.Uint64(10*i + 1), Count: 1, RecordedAt: 5, Start: 1, End: 2, Signals: []model.Kind{model.JobAttempt}, Reason: "expired"})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, g.ID)
	}
	got, err := f.store.JobGaps(f.ctx, f.writer, f.project)
	if err != nil || len(got) != 2 || !(got[0].ID == ids[0] && got[1].ID == ids[1] || got[0].ID == ids[1] && got[1].ID == ids[0]) || got[0].ID == ids[2] || got[1].ID == ids[2] || bytes.Compare(got[0].ID[:], got[1].ID[:]) >= 0 {
		t.Fatalf("gaps %+v %v", got, err)
	}
	read, _ := f.readScope(f.project)
	if got, err = f.store.JobGaps(f.ctx, read, f.project); err != nil || len(got) != 2 {
		t.Fatalf("read scope gaps %+v %v", got, err)
	}
	// A gap of another organization that names this project's ID is not this
	// project's gap.
	if err = f.store.Update(f.ctx, func(st *control.State) error {
		foreign := model.EvidenceGap{ID: model.ID{0x9b}, Org: model.NewID(), Project: f.project, Group: model.ID{0xe1}, After: 1, Through: 2, Count: 1, RecordedAt: 5, Reason: "expired"}
		st.EvidenceGaps[foreign.ID.String()] = foreign
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got, err = f.store.JobGaps(f.ctx, f.writer, f.project); err != nil || len(got) != 2 {
		t.Fatalf("another organization's gap leaked: %+v %v", got, err)
	}
}

func TestDropRetiredJobBooksTombstonesOneProject(t *testing.T) {
	f := newJobFx(t)
	a, b := f.job(1), f.job(2)
	f.must(1, f.upd(a, 0, 1))
	f.must(2, f.upd(a, 1, 2))
	f.must(3, f.upd(b, 0, 3))
	op := model.ID{0xdd, 1}
	var dropped, again int
	if err := f.store.Update(f.ctx, func(st *control.State) error {
		// A book of another project is out of reach.
		st.JobBooks["x:"+f.otherProject.String()+":"+a.String()] = json.RawMessage(`{"org":"` + f.org.String() + `","project":"` + f.otherProject.String() + `","job":"` + a.String() + `","version":"3","state":{"version":"3"}}`)
		var err error
		if dropped, err = control.DropRetiredJobBooks(st, f.org, f.project, op); err != nil {
			return err
		}
		again, err = control.DropRetiredJobBooks(st, f.org, f.project, op)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if dropped != 2 || again != 0 {
		t.Fatalf("dropped %d then %d", dropped, again)
	}
	snap, ok := f.book(a)
	if !ok || !snap.Erased || snap.Version != 2 || snap.State != nil {
		t.Fatalf("snapshot %+v %v", snap, ok)
	}
	rec := f.record(a)
	if len(rec.Commands) != 2 || rec.Digest == (model.Hash{}) || !strings.Contains(string(rec.State), op.String()) || strings.Contains(string(rec.State), "latest_schedule_key") {
		t.Fatalf("tombstone %+v %s", rec, rec.State)
	}
	// The other project's book is untouched.
	if raw := f.books()["x:"+f.otherProject.String()+":"+a.String()]; !strings.Contains(string(raw), `"state":{"version":"3"}`) {
		t.Fatalf("another project's record changed: %s", raw)
	}
	// A retry of a command that committed before the erasure is still a replay.
	if r, err := f.send(1, f.upd(a, 0, 1)); err != nil || r.Phase != "replayed" {
		t.Fatalf("replay over a tombstone: %+v %v", r, err)
	}
	// New evidence builds on the tombstone at the preserved version.
	if r := f.must(4, f.upd(a, 2, 4)); r.Cursor.Index != 3 {
		t.Fatalf("update over a tombstone: %+v", r)
	}
	if snap, _ = f.book(a); snap.Erased || snap.Version != 3 {
		t.Fatalf("snapshot after update %+v", snap)
	}
}

// 24 goroutines each start their own job and update it once more.
func TestJobUpdateManyJobsConcurrently(t *testing.T) {
	f := newJobFx(t)
	var wg sync.WaitGroup
	for i := range 24 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			j := f.job(byte(i + 1))
			tag := byte(i + 1)
			if _, err := f.send(tag, f.upd(j, 0, tag)); err != nil {
				t.Error(err)
				return
			}
			if _, err := f.send(tag+100, f.upd(j, 1, tag+100)); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	for i := range 24 {
		if rec := f.record(f.job(byte(i + 1))); rec.Version != 2 || len(rec.Commands) != 2 {
			t.Fatalf("job %d: %+v", i, rec)
		}
	}
}

func TestJobUpdateSurvivesRestartAndSnapshotImport(t *testing.T) {
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
		if err = store.BindJobUpdate(); err != nil {
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
	org, project := model.NewID(), model.NewID()
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
	admin("membership", auth.AdminPayload{UserID: session.User, Enabled: true, Reason: "fixture"})
	admin("grant", auth.AdminPayload{UserID: session.User, ProjectID: project, Enabled: true, Permissions: []string{string(auth.PolicyWrite)}, Reason: "fixture"})
	job := model.ID{0xa0, 1}
	build := func(version uint64, tag byte) (control.Command, control.JobUpdateCommand) {
		state, _ := json.Marshal(map[string]any{"version": model.Revision(version), "org": org, "project": project, "job": job, "latest_schedule_key": fmt.Sprintf("k%d", tag)})
		c := control.JobUpdateCommand{Project: project, Job: job, Kind: "attempt", ExpectedVersion: model.Revision(version - 1), NewVersion: model.Revision(version), InputDigest: model.Hash{tag}, State: state, Origin: &model.Cursor{Group: model.ID{0xe1}, Index: model.Uint64(tag)}}
		raw, _ := json.Marshal(c)
		return control.Command{CommandID: model.ID{0xc0, tag}, Kind: string(control.KindUpdateJob), Payload: raw}, c
	}
	send := func(store *control.Store, svc *auth.Service, cred auth.Credential, cmd control.Command) (control.Result, error) {
		scope, err := svc.Authorize(ctx, cred, org, []model.ID{project}, auth.PolicyWrite)
		if err != nil {
			t.Fatal(err)
		}
		return store.TransactJobs(ctx, scope, cmd)
	}
	books := func(store *control.Store) string {
		var out string
		if err := store.View(ctx, func(st control.State) error {
			raw, _ := json.Marshal(st.JobBooks)
			out = string(raw)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return out
	}
	c1, _ := build(1, 1)
	c2, _ := build(2, 2)
	if _, err = send(store, svc, cred, c1); err != nil {
		t.Fatal(err)
	}
	if _, err = send(store, svc, cred, c2); err != nil {
		t.Fatal(err)
	}
	before := books(store)
	seed, _, err := store.ReplicationSeed()
	if err != nil {
		t.Fatal(err)
	}
	imported, err := control.OpenSeed(filepath.Join(t.TempDir(), "imported"), seed)
	if err != nil {
		t.Fatal(err)
	}
	if got := books(imported); got != before || !strings.Contains(got, "commands") {
		t.Fatalf("snapshot import changed job state:\n%s\n%s", before, got)
	}
	imported.Close()
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	store, svc = open()
	defer store.Close()
	if cred, err = svc.Authenticate(ctx, session.Token); err != nil {
		t.Fatal(err)
	}
	if after := books(store); after != before {
		t.Fatalf("restart changed job state:\n%s\n%s", before, after)
	}
	if r, err := send(store, svc, cred, c1); err != nil || r.Phase != "replayed" || r.Cursor.Index != 1 {
		t.Fatalf("committed command not recognized after restart: %+v %v", r, err)
	}
	if r, err := send(store, svc, cred, c2); err != nil || r.Phase != "replayed" || r.Cursor.Index != 2 {
		t.Fatalf("second command not recognized after restart: %+v %v", r, err)
	}
	stale, _ := build(2, 3)
	if _, err = send(store, svc, cred, stale); code(err) != model.Stale {
		t.Fatalf("a stale version committed after restart: %v", err)
	}
	if after := books(store); after != before {
		t.Fatal("replays or a stale command changed the state after restart")
	}
	c3, _ := build(3, 4)
	if r, err := send(store, svc, cred, c3); err != nil || r.Phase != "applied" || r.Cursor.Index != 3 {
		t.Fatalf("update after restart: %+v %v", r, err)
	}
}
