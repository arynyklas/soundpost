// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/model"
)

// The journeys read the evidence the way an operator does: through the served product's routes, after the product was stopped
// and started again. Errors come from the trace view (which names the stored error occurrences of a trace and the issue holding
// each) and the evidence occurrence route; their frames are mapped by the evidence frame route, which owns the symbolication;
// jobs come from the job view; the runtime profile from the profile route. The harness maps nothing and scans no storage for
// these rows. It only waits (bounded) for the product's own asynchronous producers, which group errors into issues and commit
// job state, to settle after the restart.

const servedSettleLimit = 90 * time.Second

// servedPost asks one product route as the logged-in actor and records the answer untouched.
func (j *journeyRun) servedPost(actor string, s *installSite, route string, body any) (servedRead, error) {
	status, raw, err := j.post(s, route, body, j.csrf[s], "")
	if err != nil {
		return servedRead{}, err
	}
	if w := containsAny(raw, sqlWords); w != "" {
		j.obs.UnsafeStorage = append(j.obs.UnsafeStorage, route+" answer contains "+w)
	}
	return servedRead{Route: route, Actor: actor, Status: status, Body: json.RawMessage(raw)}, nil
}

// errorTargets are the available stored-error occurrences of a trace view that an issue holds.
func errorTargets(raw json.RawMessage) []httpapi.SpanTarget {
	var tv httpapi.TraceView
	if json.Unmarshal(raw, &tv) != nil {
		return nil
	}
	var out []httpapi.SpanTarget
	for _, t := range tv.Targets {
		if t.Kind == "error" && t.Available && t.Issue != nil {
			out = append(out, t)
		}
	}
	return out
}

// readServed fills the errors, frames, job and runtime-profile observations through the product's routes.
func (j *journeyRun) readServed(reader, analyst, builder *installSite, window map[string]any) error {
	e := j.exp
	// Errors: the UI trace names the occurrence and its issue (the issue producer may still be grouping it after the restart).
	var targets []httpapi.SpanTarget
	deadline := time.Now().Add(servedSettleLimit)
	for {
		rd, err := j.servedPost("reader-a", reader, "/api/v1/traces/view", map[string]any{"org": e.Org, "project": e.Project, "trace": j.obs.UITrace, "window": window})
		if err != nil {
			return err
		}
		if targets = errorTargets(rd.Body); len(targets) > 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(time.Second)
	}
	var stored []model.Frame
	for _, t := range targets {
		rd, err := j.servedPost("analyst", analyst, "/api/v1/evidence/occurrence", map[string]any{"org": e.Org, "project": e.Project, "issue": *t.Issue, "occurrence": t.ID})
		if err != nil {
			return err
		}
		j.obs.Errors = append(j.obs.Errors, observedError{Issue: *t.Issue, Occurrence: t.ID, Read: rd})
		if stored == nil {
			var v httpapi.ErrorOccurrenceView
			if json.Unmarshal(rd.Body, &v) == nil && v.Detail != nil && len(v.Detail.Frames) > 0 {
				stored = v.Detail.Frames
			}
		}
	}
	// Frames: the product maps exactly the frames the stored error carries. The sandbox has fixed budgets, so a loaded host may
	// answer `deadline`; the attempts are bounded and recorded.
	if len(stored) > 0 {
		var attempts []string
		for try := range 8 {
			if try > 0 {
				time.Sleep(time.Second)
			}
			rd, err := j.servedPost("builder", builder, "/api/v1/evidence/frames", map[string]any{"org": e.Org, "project": e.Project, "build": e.WebBuild, "frames": stored})
			if err != nil {
				return err
			}
			j.obs.Frames = &rd
			var fv httpapi.FramesView
			reason := fmt.Sprintf("http_%d", rd.Status)
			if json.Unmarshal(rd.Body, &fv) == nil && len(fv.Frames) > 0 {
				reason = fv.Frames[0].Reason
			}
			attempts = append(attempts, reason)
			if reason == "resolved" {
				break
			}
		}
		j.rep["frame_route_attempts"] = attempts
	}
	// Job: the run with its attempts, once the product's job books have committed both of them.
	for deadline = time.Now().Add(servedSettleLimit); ; time.Sleep(time.Second) {
		rd, err := j.servedPost("reader-a", reader, "/api/v1/jobs/view", map[string]any{"org": e.Org, "project": e.Project, "job": e.Job, "run": e.Run})
		if err != nil {
			return err
		}
		j.obs.JobRun = &rd
		var jv httpapi.JobView
		if (json.Unmarshal(rd.Body, &jv) == nil && jv.Run != nil && jv.Run.AttemptCount >= 2) || time.Now().After(deadline) {
			break
		}
	}
	// Runtime profile: the profile the job process stored, read back through the profile route.
	if rp := &j.obs.RuntimeProfile; rp.StoredChunks > 0 {
		rd, err := j.servedPost("analyst", analyst, "/api/v1/profiles/view", map[string]any{"org": e.Org, "project": e.Project, "profile": rp.Profile, "window": window})
		if err != nil {
			return err
		}
		rp.Read = &rd
	}
	return nil
}
