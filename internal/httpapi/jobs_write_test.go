// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/jobs"
	"github.com/arynyklas/soundpost/internal/model"
)

func (e *jobEnv) observe(who person, body map[string]any) (int, []byte) {
	return e.post(who, "/api/v1/jobs/schedule-evidence", body)
}
func (e *jobEnv) correct(who person, body map[string]any) (int, []byte) {
	return e.post(who, "/api/v1/jobs/correct", body)
}

func observation(w *jobWorld, job model.ID, observed, complete time.Time, healthy bool, def *jobs.Definition) map[string]any {
	b := map[string]any{"org": w.org.String(), "project": w.project.String(), "job": job.String(), "command_id": model.NewID().String(), "observer": model.ID{9}.String(),
		"observed_ns": model.UnixNano(observed.UnixNano()), "complete_through_ns": model.UnixNano(complete.UnixNano()), "healthy": healthy}
	if def != nil {
		b["definition"] = def
	}
	return b
}

// The external schedule observer feeds the job state through its own route, and the reader sees it as the product
// reports it: missed WITH the observer's evidence, an outage of the data path as unknown (never missed), a silent
// observer as stale. The route needs policy.write on the project and is not a way to read.
func TestJobScheduleEvidenceFeedDrivesMissedUnknownAndStale(t *testing.T) {
	e := newJobEnv(t, nil, true)
	w := newJobWorld(e)
	every := &jobs.Definition{Revision: 1, EffectiveFrom: at(time.Now(), -24*time.Hour), Schedule: &jobs.Schedule{Cron: "* * * * *", Timezone: "UTC"}}
	now := time.Now()
	jobMissed, jobOutage, jobStale := model.ID{0x61, 1}, model.ID{0x61, 2}, model.ID{0x61, 3}
	for _, c := range []struct {
		job              model.ID
		observed, always time.Time
	}{{jobMissed, now.Add(-time.Second), now.Add(-time.Second)}, {jobOutage, now.Add(-time.Second), now.Add(-3 * time.Hour)}, {jobStale, now.Add(-2 * time.Hour), now.Add(-2 * time.Hour)}} {
		status, raw := e.observe(w.writer, observation(w, c.job, c.observed, c.always, true, every))
		if status != 200 {
			t.Fatalf("observe %v: %d %s", c.job, status, raw)
		}
		var a httpapi.JobWriteAnswer
		if err := json.Unmarshal(raw, &a); err != nil || a.State != httpapi.ActionCommitted || a.Job != c.job || a.Version == 0 {
			t.Fatalf("answer %s %v", raw, err)
		}
	}
	get := func(job model.ID) httpapi.JobView {
		t.Helper()
		status, raw := e.view(w.reader, viewBody(w.org, w.project, job))
		if status != 200 {
			t.Fatalf("view %v: %d %s", job, status, raw)
		}
		return decodeJobView(t, raw)
	}
	if v := get(jobMissed); v.Health.Status != jobs.StatusMissed || !v.Health.Complete || v.Observer.State != "fresh" || v.Observer.Evidence == nil || v.Observer.Evidence.Stale {
		t.Fatalf("a fresh observer attesting a complete data path with no run must read missed with its evidence: %+v %+v", v.Health, v.Observer)
	}
	if v := get(jobOutage); v.Health.Status != jobs.StatusUnknown || v.Health.Complete || v.Observer.State != "fresh" {
		t.Fatalf("an outage of the data path must read unknown, never missed: %+v %+v", v.Health, v.Observer)
	}
	if v := get(jobStale); v.Observer.State != "stale" || v.Health.Complete {
		t.Fatalf("a silent observer must read stale and incomplete: %+v %+v", v.Health, v.Observer)
	}
	// Repeating the identical command is idempotent; a far-future clock is refused; the route is a write: a read-only
	// account, an account without the grant and an outsider all get the same refusal and change nothing.
	dup := observation(w, jobMissed, now.Add(-time.Second), now.Add(-time.Second), true, every)
	if s1, _ := e.observe(w.writer, dup); s1 != 200 {
		t.Fatalf("first: %d", s1)
	}
	if s2, _ := e.observe(w.writer, dup); s2 != 200 {
		t.Fatalf("a retried command must be idempotent: %d", s2)
	}
	if status, raw := e.observe(w.writer, observation(w, jobMissed, now.Add(48*time.Hour), now.Add(48*time.Hour), true, nil)); status == 200 {
		t.Fatalf("a far-future observation was accepted: %s", raw)
	}
	var refusals []int
	var bodies []string
	for _, who := range []person{w.reader, w.ung, w.outsider} {
		status, raw := e.observe(who, observation(w, jobMissed, now, now, false, nil))
		refusals, bodies = append(refusals, status), append(bodies, string(raw))
		if status == 200 {
			t.Fatalf("a caller without policy.write fed the observer route: %s", raw)
		}
	}
	for i := range refusals {
		if i > 0 && (refusals[i] != refusals[0] && refusals[i] != http.StatusForbidden && refusals[0] != http.StatusForbidden || bodies[i] == "") {
			t.Fatalf("refusals differ in a way that tells accounts apart: %v", refusals)
		}
	}
	if v := get(jobMissed); v.Observer.State != "fresh" {
		t.Fatalf("a refused write changed the observer: %+v", v.Observer)
	}
	// Unknown fields (an actor, a permission) are refused; the strict decode is the contract.
	spoof := observation(w, jobMissed, now, now, true, nil)
	spoof["actor"] = w.reader.ID.String()
	if status, _ := e.observe(w.writer, spoof); status == 200 {
		t.Fatal("an unknown body field was accepted")
	}
}

// A correction is audited: the original terminal result stays, the effective result is the correction's, and the actor
// is the caller's own principal whatever the body says; a stale expected version is a conflict and a retry of the same
// command is idempotent.
func TestJobCorrectionRouteIsAuditedScopedAndIdempotent(t *testing.T) {
	e := newJobEnv(t, nil, true)
	w := newJobWorld(e)
	p := w.project
	e.apply(w.write, p, jobJourney, run1, att(1), "manual.fix", 1, 1, "started", at(w.base, 0), nil)
	e.apply(w.write, p, jobJourney, run1, att(1), "manual.fix", 1, 2, "failed", at(w.base, 0), new(at(w.base, time.Second)))
	read := func() httpapi.JobView {
		t.Helper()
		body := viewBody(w.org, p, jobJourney)
		body["run"] = run1.String()
		status, raw := e.view(w.reader, body)
		if status != 200 {
			t.Fatalf("view: %d %s", status, raw)
		}
		return decodeJobView(t, raw)
	}
	before := read()
	correction := map[string]any{"org": w.org.String(), "project": p.String(), "job": jobJourney.String(), "command_id": model.NewID().String(), "expected_version": before.Source.Version,
		"attempt": att(1).String(), "version": "1", "state": "succeeded", "reason": "the work finished; the exit code was misreported"}
	for _, who := range []person{w.reader, w.ung, w.outsider} {
		if status, raw := e.correct(who, correction); status == 200 {
			t.Fatalf("a caller without policy.write corrected a result: %s", raw)
		}
	}
	if got := read().Run.Attempts[0]; got.Effective != jobs.AttemptFailed || len(got.Corrections) != 0 {
		t.Fatalf("a refused correction changed the attempt: %+v", got)
	}
	if status, raw := e.correct(w.writer, correction); status != 200 {
		t.Fatalf("correct: %d %s", status, raw)
	}
	after := read()
	got := after.Run.Attempts[0]
	if got.Effective != jobs.AttemptSucceeded || got.Terminal == nil || got.Terminal.State != jobs.AttemptFailed || len(got.Corrections) != 1 {
		t.Fatalf("the original failure must stay with the correction beside it: %+v", got)
	}
	c := got.Corrections[0]
	if c.Actor != w.writer.ID || c.Reason != "the work finished; the exit code was misreported" || c.Command.String() != correction["command_id"] {
		t.Fatalf("audit of the correction: %+v (writer %v)", c, w.writer.ID)
	}
	if after.Source.Version <= before.Source.Version {
		t.Fatalf("the source version did not advance: %v -> %v", before.Source.Version, after.Source.Version)
	}
	// The identical command again: idempotent. A different command against the old version: conflict.
	if status, raw := e.correct(w.writer, correction); status != 200 {
		t.Fatalf("an idempotent retry: %d %s", status, raw)
	}
	stale := map[string]any{}
	for k, v := range correction {
		stale[k] = v
	}
	stale["command_id"], stale["version"], stale["state"] = model.NewID().String(), "2", "cancelled"
	if status, raw := e.correct(w.writer, stale); status != http.StatusConflict {
		t.Fatalf("a correction on a stale version: %d %s", status, raw)
	}
	if n := len(read().Run.Attempts[0].Corrections); n != 1 {
		t.Fatalf("a refused correction was recorded: %d", n)
	}
	// The acting principal is never a body field.
	spoof := map[string]any{}
	for k, v := range correction {
		spoof[k] = v
	}
	spoof["command_id"], spoof["actor"] = model.NewID().String(), w.reader.ID.String()
	if status, _ := e.correct(w.writer, spoof); status == 200 {
		t.Fatal("a body-supplied actor was accepted")
	}
	// Reasons are required and a non-terminal target state is refused.
	bad := map[string]any{}
	for k, v := range correction {
		bad[k] = v
	}
	bad["command_id"], bad["version"], bad["reason"] = model.NewID().String(), "3", ""
	if status, _ := e.correct(w.writer, bad); status == 200 {
		t.Fatal("a correction without a reason was accepted")
	}
}
