// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/jobs"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/profiles"
	"github.com/arynyklas/soundpost/internal/symbolicate"
	"github.com/arynyklas/soundpost/internal/traces"
)

// The journey assertions are checked against KNOWN application behavior: the gateway call has a
// dependency child; a click in the web app causes request -> API -> database and then fails in
// the known build; the STORED error carries the frames of the shipped bundle and the product's own
// frame route maps them to the known source location; the job's first attempt fails, the second
// succeeds and the failed attempt stays in the record; a runtime profile of the job process is
// delivered, stored and read back; the same trace read from another organization is denied; canaries
// that really flowed through the applications are never stored. Errors, frames, jobs and profiles are
// observed as the product's own route answers (servedRead), never as storage scans or harness
// symbolication. Every wrong observation below must be rejected by exactly the row it violates.

func jid(n byte) model.ID {
	var id model.ID
	id[0], id[15] = n, n
	return id
}

func sid(n byte) model.SpanID {
	var id model.SpanID
	id[7] = n
	return id
}

func mustPtr(s model.SpanID) *model.SpanID { return &s }

func testSpan(trace model.ID, id byte, parent byte, kind, op, dep string, start int64) model.Span {
	domain := model.ClockDomain{Host: jid(0xa1), Boot: jid(0xa2), Runtime: jid(0xa3)}
	begin := model.TraceClock{Wall: model.UnixNano(1_000_000_000 + start), Mono: model.MonoNano(start), Domain: domain}
	end := begin
	end.Wall += 900
	end.Mono += 900
	s := model.Span{Trace: trace, ID: sid(id), Kind: kind, Operation: op, Dependency: dep, Start: begin, End: &end, Status: "ok", SampleProbability: model.FloatBits(0x3ff0000000000000), SampleDecision: "keep", Links: []model.SpanLink{}}
	if parent != 0 {
		s.Parent = mustPtr(sid(parent))
	}
	return s
}

func traceBodyOf(t *testing.T, org, project, trace model.ID, spans []model.Span, partial bool) json.RawMessage {
	t.Helper()
	path, err := traces.CriticalPath(spans)
	if err != nil {
		t.Fatalf("critical path: %v", err)
	}
	view := httpapi.TraceView{Org: org, Project: project, Trace: trace, State: httpapi.StateReady, Partial: partial, Path: &path, Sections: []httpapi.ViewSection{{Name: "spans", State: httpapi.StateReady}}}
	if partial {
		view.State = httpapi.StateIncomplete
	}
	raw, err := json.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func directSpans(trace model.ID) []model.Span {
	return []model.Span{
		testSpan(trace, 1, 0, "server", "request", "", 0),
		testSpan(trace, 2, 1, "client", "http.call", "api", 10),
		testSpan(trace, 3, 2, "server", "request", "", 20),
		testSpan(trace, 4, 3, "client", "db.execute", "postgres", 30),
		testSpan(trace, 5, 3, "client", "http.call", "dependency", 40),
	}
}

func uiSpans(trace model.ID) []model.Span {
	return []model.Span{
		testSpan(trace, 1, 0, "internal", "ui.action", "", 0),
		testSpan(trace, 2, 1, "client", "http.call", "gateway", 10),
		testSpan(trace, 3, 2, "server", "request", "", 20),
		testSpan(trace, 4, 3, "client", "http.call", "api", 30),
		testSpan(trace, 5, 4, "server", "request", "", 40),
		testSpan(trace, 6, 5, "client", "db.execute", "postgres", 50),
		testSpan(trace, 7, 5, "client", "http.call", "dependency", 60),
	}
}

const (
	testSource   = "src/receipt.ts"
	testLine     = 24
	testColumn   = 10
	testArtifact = "fedcba9876543210fedcba9876543210"
	canaryBody   = "CANARY_BODY_7f3a"
	canaryPrompt = "CANARY_PROMPT_9b2f"
	canarySQL    = "CANARY_SQL_LITERAL_5d1e"
)

func servedBodyOf(t *testing.T, v any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// rewrite decodes one recorded product answer, lets a case make one fact wrong and stores the answer again.
func rewrite[T any](t *testing.T, r *servedRead, f func(*T)) {
	t.Helper()
	var v T
	if err := json.Unmarshal(r.Body, &v); err != nil {
		t.Fatal(err)
	}
	f(&v)
	r.Body = servedBodyOf(t, v)
}

func goodAttempt(id byte, ordinal uint64, terminal jobs.AttemptState, at int64, final bool) httpapi.AttemptView {
	return httpapi.AttemptView{ID: jid(id), Ordinal: model.Uint64(ordinal), Started: true, ObservedAt: model.UnixNano(at - 5), Terminal: &jobs.TerminalResult{State: terminal, At: model.UnixNano(at)},
		Effective: terminal, Corrections: []jobs.AppliedCorrection{}, EventsAccepted: 2, Final: final}
}

func goodObservation(t *testing.T) journeyObservation {
	t.Helper()
	exp := journeyExpected{Org: jid(1), Project: jid(2), OtherOrg: jid(3), OtherProject: jid(4), WebSource: jid(5), WebBuild: jid(6), Job: jid(7), Run: jid(8),
		ThrowSource: testSource, ThrowLine: testLine, ThrowColumn: testColumn, UnpricedItem: "sku-404",
		Canaries: []string{canaryBody, canaryPrompt, canarySQL}, RequiredVersionIDs: []string{"go", "bun", "python", "chrome", "postgres"}}
	direct, ui := jid(0x10), jid(0x11)
	o := journeyObservation{Expected: exp, DirectTrace: direct, UITrace: ui}
	for _, tr := range []struct {
		id    model.ID
		spans []model.Span
	}{{direct, directSpans(direct)}, {ui, uiSpans(ui)}} {
		o.Reads = append(o.Reads, traceRead{Actor: "reader-a", OrgSent: exp.Org, Project: exp.Project, Trace: tr.id, Status: 200, Body: traceBodyOf(t, exp.Org, exp.Project, tr.id, tr.spans, false)})
		for _, p := range []struct{ org, project model.ID }{{exp.OtherOrg, exp.Project}, {exp.Org, exp.Project}} {
			o.Reads = append(o.Reads, traceRead{Actor: "reader-b", OrgSent: p.org, Project: p.project, Trace: tr.id, Status: 404, Body: json.RawMessage(`{"code":"not_found"}`)})
		}
	}
	// The stored error of the web build, read through the occurrence route: its innermost frame names the uploaded artifact.
	span, col := sid(1), uint32(120)
	storedFrame := model.Frame{Module: "assets/index.js", Artifact: testArtifact, Line: 3, Column: &col, InApp: true}
	detail := httpapi.ErrorOccurrenceDetail{Class: "UnpricedOrderError", Mechanism: "uncaught_exception", Build: exp.WebBuild, Trace: &ui, Span: &span, Frames: []model.Frame{storedFrame}}
	occurrence, issue := jid(0x20), jid(0x21)
	o.Errors = []observedError{{Issue: issue, Occurrence: occurrence, Read: servedRead{Route: "/api/v1/evidence/occurrence", Actor: "analyst", Status: 200,
		Body: servedBodyOf(t, httpapi.ErrorOccurrenceView{Org: exp.Org, Project: exp.Project, Issue: issue, Occurrence: occurrence, State: httpapi.StateReady, Detail: &detail})}}}
	// The frame route, asked about exactly those frames, maps the innermost one through the uploaded source map.
	o.Frames = &servedRead{Route: "/api/v1/evidence/frames", Actor: "builder", Status: 200, Body: servedBodyOf(t, httpapi.FramesView{Org: exp.Org, Project: exp.Project, Build: exp.WebBuild, State: httpapi.StateReady,
		Frames: []httpapi.FrameEvidence{{Original: storedFrame, Reason: string(symbolicate.Resolved), Resolved: &symbolicate.CodeIdentity{Source: testSource, Line: testLine, Column: testColumn}, Source: httpapi.SourceView{State: "withheld"}}}})}
	o.Page = pageObservation{Found: true, Path: "assets/index.js", Line: 3, Column: 120}
	// The job route: attempt 1 failed, attempt 2 succeeded, the run recovered.
	run := httpapi.RunDetail{RunView: httpapi.RunView{ID: exp.Run, FinalAttempt: jid(0x42), Status: jobs.RunRecovered, Recovered: true, AttemptCount: 2, FailedAttempts: 1},
		Attempts: []httpapi.AttemptView{goodAttempt(0x41, 1, jobs.AttemptFailed, 200, false), goodAttempt(0x42, 2, jobs.AttemptSucceeded, 400, true)}}
	o.JobRun = &servedRead{Route: "/api/v1/jobs/view", Actor: "reader-a", Status: 200, Body: servedBodyOf(t, httpapi.JobView{Org: exp.Org, Project: exp.Project, Job: exp.Job, State: httpapi.StateReady, Runs: []httpapi.RunView{run.RunView}, Run: &run})}
	o.Artifact = artifactObservation{Uploaded: true, Build: exp.WebBuild, DebugID: "0123456789abcdef0123456789abcdef", Artifact: testArtifact}
	for _, c := range exp.Canaries {
		o.Flows = append(o.Flows, canaryFlow{Canary: c, Reached: []string{"dependency_prompt_counter"}})
	}
	o.Replay = replayObservation{Attempted: true, RecorderChunks: 1, AdmittedChunks: 1, StoredReplayRow: 1}
	o.Profile = profileObservation{Attempted: true, Capability: "available", StoredProfile: 1, SDKEnqueues: true}
	// The runtime profile the CPython SDK delivered from the job process, read back through the profile route.
	profile := jid(0x50)
	domain := model.ClockDomain{Host: jid(0xa1), Boot: jid(0xa2), Runtime: jid(0xa3)}
	view := profiles.ProfileView{Profile: profile, Process: jid(0x52), Project: exp.Project, Method: "runtime_cpu", Units: "samples", Clock: model.TraceClock{Domain: domain},
		Frames: []model.ProfileFrame{{Module: "run.py", Function: "summarise_catalog"}}, Stacks: []model.ProfileStack{{Frames: []uint32{0}}}, Samples: []model.ProfileSample{{Stack: 0}},
		Capabilities: []profiles.CapabilityRecord{{ID: jid(0x51), Value: model.Capability{Runtime: "cpython", Signal: model.Profile, Method: runtimeProfileMethod, Status: "supported", Clock: domain}}}, Completeness: "complete"}
	o.RuntimeProfile = runtimeProfileObservation{Attempted: true, Method: runtimeProfileMethod, StoredChunks: 1, StoredCapabilities: 1, Profile: profile,
		Read: &servedRead{Route: "/api/v1/profiles/view", Actor: "analyst", Status: 200, Body: servedBodyOf(t, httpapi.ProfileResponse{Org: exp.Org, Project: exp.Project, Profile: profile, State: httpapi.StateReady, View: &view})}}
	o.Versions = map[string]string{"go": "go1.27.3", "bun": "1.3.14", "python": "3.12.3", "chrome": "156", "postgres": "16.14"}
	return o
}

func rowByName(rows []journeyRow, name string) journeyRow {
	for _, r := range rows {
		if r.Name == name {
			return r
		}
	}
	return journeyRow{Name: name, Reason: "row_absent"}
}

func TestReferenceJourneyAssertions(t *testing.T) {
	good := goodObservation(t)
	rows := assessJourneys(good)
	for _, r := range rows {
		if !r.Satisfied {
			t.Fatalf("a correct observation must satisfy every row; %s: %s (%s)", r.Name, r.Reason, r.Detail)
		}
		if !r.Required {
			t.Fatalf("row %s must be required", r.Name)
		}
	}
	if len(unsatisfiedRequired(rows)) != 0 {
		t.Fatal("a correct observation leaves no required row unsatisfied")
	}

	reread := func(o *journeyObservation, trace model.ID, spans []model.Span, partial bool) {
		for i := range o.Reads {
			if o.Reads[i].Actor == "reader-a" && o.Reads[i].Trace == trace {
				o.Reads[i].Body = traceBodyOf(t, o.Expected.Org, o.Expected.Project, trace, spans, partial)
			}
		}
	}
	occ := func(o *journeyObservation, f func(*httpapi.ErrorOccurrenceView)) {
		rewrite(t, &o.Errors[0].Read, f)
	}
	framesView := func(o *journeyObservation, f func(*httpapi.FramesView)) { rewrite(t, o.Frames, f) }
	jobView := func(o *journeyObservation, f func(*httpapi.JobView)) { rewrite(t, o.JobRun, f) }
	attempt := func(v *httpapi.JobView, ordinal uint64) *httpapi.AttemptView {
		for i := range v.Run.Attempts {
			if uint64(v.Run.Attempts[i].Ordinal) == ordinal {
				return &v.Run.Attempts[i]
			}
		}
		t.Fatalf("no attempt %d", ordinal)
		return nil
	}
	profileView := func(o *journeyObservation, f func(*httpapi.ProfileResponse)) { rewrite(t, o.RuntimeProfile.Read, f) }

	cases := []struct {
		name   string
		mutate func(o *journeyObservation)
		row    string
		reason string
		also   []string // rows that legitimately fail with it
	}{
		// ---- stored errors, read through the occurrence route ----
		{"wrong build in the stored error", func(o *journeyObservation) {
			occ(o, func(v *httpapi.ErrorOccurrenceView) { v.Detail.Build = jid(0x66) })
		}, rowErrorBuild, "wrong_build", []string{rowIDs}},
		{"no stored error is linked to the trace", func(o *journeyObservation) { o.Errors = nil }, rowErrorBuild, "no_web_error_admitted", []string{rowErrorTrace, rowMappedFrame}},
		{"stored error not linked to the trace", func(o *journeyObservation) { occ(o, func(v *httpapi.ErrorOccurrenceView) { v.Detail.Trace = nil }) }, rowErrorTrace, "error_not_linked_to_trace", []string{rowMappedFrame}},
		{"stored error linked to a different trace", func(o *journeyObservation) {
			occ(o, func(v *httpapi.ErrorOccurrenceView) { v.Detail.Trace = &o.DirectTrace })
		}, rowErrorTrace, "error_not_linked_to_trace", []string{rowMappedFrame}},
		{"stored error without a span id", func(o *journeyObservation) { occ(o, func(v *httpapi.ErrorOccurrenceView) { v.Detail.Span = nil }) }, rowErrorTrace, "error_not_linked_to_trace", nil},
		{"the occurrence route refused the read", func(o *journeyObservation) { o.Errors[0].Read.Status = 404 }, rowErrorBuild, "occurrence_read_refused", []string{rowErrorTrace, rowMappedFrame, rowIDs}},
		{"the occurrence route answered another occurrence", func(o *journeyObservation) {
			occ(o, func(v *httpapi.ErrorOccurrenceView) { v.Occurrence = jid(0x77) })
		}, rowErrorBuild, "occurrence_identity_mismatch", []string{rowErrorTrace, rowMappedFrame, rowIDs}},
		{"the occurrence view is not ready", func(o *journeyObservation) {
			occ(o, func(v *httpapi.ErrorOccurrenceView) { v.State, v.Detail = httpapi.StateNotAvailable, nil })
		}, rowErrorBuild, "occurrence_not_ready", []string{rowErrorTrace, rowMappedFrame, rowIDs}},
		{"the occurrence route answered another issue", func(o *journeyObservation) {
			occ(o, func(v *httpapi.ErrorOccurrenceView) { v.Issue = jid(0x79) })
		}, rowErrorBuild, "occurrence_identity_mismatch", []string{rowErrorTrace, rowMappedFrame, rowIDs}},
		{"the occurrence view is incomplete although it carries a detail", func(o *journeyObservation) {
			occ(o, func(v *httpapi.ErrorOccurrenceView) { v.State = httpapi.StateIncomplete })
		}, rowErrorBuild, "occurrence_not_ready", []string{rowErrorTrace, rowMappedFrame, rowIDs}},
		{"an unrelated stored error is listed first", func(o *journeyObservation) {
			// The trace view names two stored errors; the first belongs to the direct request's trace and its frame is not the one the
			// frame route was asked about. The row must follow the error of the UI trace, not the first one listed.
			var other httpapi.ErrorOccurrenceView
			if err := json.Unmarshal(o.Errors[0].Read.Body, &other); err != nil {
				t.Fatal(err)
			}
			detail := *other.Detail
			detail.Trace = &o.DirectTrace
			detail.Frames = []model.Frame{{Module: "assets/other.js", Artifact: testArtifact, Line: 77, InApp: true}}
			first := observedError{Issue: jid(0x22), Occurrence: jid(0x23), Read: servedRead{Route: "/api/v1/evidence/occurrence", Actor: "analyst", Status: 200,
				Body: servedBodyOf(t, httpapi.ErrorOccurrenceView{Org: o.Expected.Org, Project: o.Expected.Project, Issue: jid(0x22), Occurrence: jid(0x23), State: httpapi.StateReady, Detail: &detail})}}
			o.Errors = append([]observedError{first}, o.Errors...)
		}, "", "", nil},

		// ---- original frames of the STORED error, mapped by the product's frame route ----
		{"the stored error carries no frames", func(o *journeyObservation) { occ(o, func(v *httpapi.ErrorOccurrenceView) { v.Detail.Frames = nil }) }, rowMappedFrame, "stored_error_has_no_frames", nil},
		{"a stored frame names another artifact", func(o *journeyObservation) {
			occ(o, func(v *httpapi.ErrorOccurrenceView) { v.Detail.Frames[0].Artifact = "00000000000000000000000000000000" })
		}, rowMappedFrame, "frame_artifact_unbound", nil},
		{"the frame route was never asked", func(o *journeyObservation) { o.Frames = nil }, rowMappedFrame, "frames_not_read", nil},
		{"the frame route refused", func(o *journeyObservation) { o.Frames.Status = 403 }, rowMappedFrame, "frames_read_refused", nil},
		{"the frame is not mapped (sandbox deadline)", func(o *journeyObservation) {
			framesView(o, func(v *httpapi.FramesView) {
				v.Frames[0].Reason, v.Frames[0].Resolved = string(symbolicate.Deadline), nil
			})
		}, rowMappedFrame, "deadline", nil},
		{"the sandbox is unavailable, which is never a pass", func(o *journeyObservation) {
			framesView(o, func(v *httpapi.FramesView) {
				v.Frames[0].Reason, v.Frames[0].Resolved = string(symbolicate.SandboxUnavailable), nil
			})
		}, rowMappedFrame, "sandbox_unavailable", nil},
		{"the frame answer is about another artifact", func(o *journeyObservation) {
			framesView(o, func(v *httpapi.FramesView) { v.Frames[0].Original.Artifact = "00000000000000000000000000000000" })
		}, rowMappedFrame, "frames_read_not_the_stored_frames", nil},
		{"the frame answer has a column the stored frame lacks", func(o *journeyObservation) {
			framesView(o, func(v *httpapi.FramesView) { v.Frames[0].Original.Column = nil })
		}, rowMappedFrame, "frames_read_not_the_stored_frames", nil},
		{"the frame answer has another column than the stored frame", func(o *journeyObservation) {
			framesView(o, func(v *httpapi.FramesView) { c := uint32(7); v.Frames[0].Original.Column = &c })
		}, rowMappedFrame, "frames_read_not_the_stored_frames", nil},
		{"an unresolved reason that still carries a position is not a pass", func(o *journeyObservation) {
			framesView(o, func(v *httpapi.FramesView) { v.Frames[0].Reason = string(symbolicate.Unmapped) })
		}, rowMappedFrame, "unmapped", nil},
		{"wrong source line", func(o *journeyObservation) {
			framesView(o, func(v *httpapi.FramesView) { v.Frames[0].Resolved.Line++ })
		}, rowMappedFrame, "wrong_source_location", nil},
		{"wrong source column", func(o *journeyObservation) {
			framesView(o, func(v *httpapi.FramesView) { v.Frames[0].Resolved.Column++ })
		}, rowMappedFrame, "wrong_source_location", nil},
		{"wrong source file", func(o *journeyObservation) {
			framesView(o, func(v *httpapi.FramesView) { v.Frames[0].Resolved.Source = "src/main.ts" })
		}, rowMappedFrame, "wrong_source_location", nil},
		{"mapped under the wrong build", func(o *journeyObservation) { framesView(o, func(v *httpapi.FramesView) { v.Build = jid(0x68) }) }, rowMappedFrame, "wrong_build", nil},
		{"the answer is about other frames than the stored ones", func(o *journeyObservation) {
			framesView(o, func(v *httpapi.FramesView) { v.Frames[0].Original.Line = 99 })
		}, rowMappedFrame, "frames_read_not_the_stored_frames", nil},
		{"the answer covers fewer frames than the stored error has", func(o *journeyObservation) {
			occ(o, func(v *httpapi.ErrorOccurrenceView) { v.Detail.Frames = append(v.Detail.Frames, v.Detail.Frames[0]) })
		}, rowMappedFrame, "frames_read_not_the_stored_frames", nil},
		{"the stored frame is not where the real browser threw", func(o *journeyObservation) { o.Page.Line = 4 }, rowMappedFrame, "stored_frame_differs_from_page_error", nil},

		// ---- the source map upload ----
		{"source map uploaded for another build", func(o *journeyObservation) { o.Artifact.Build = jid(0x67) }, rowSourceMap, "wrong_build", []string{rowIDs}},
		{"source map upload not acknowledged", func(o *journeyObservation) { o.Artifact.Uploaded = false }, rowSourceMap, "upload_not_acknowledged", nil},
		{"bundle still names its map", func(o *journeyObservation) { o.Artifact.HasSourceMapRef = true }, rowSourceMap, "map_reference_shipped", nil},

		// ---- the job, read through the job view ----
		{"the job route was never asked", func(o *journeyObservation) { o.JobRun = nil }, rowJobHistory, "no_job_read", []string{rowIDs}},
		{"the job route refused", func(o *journeyObservation) { o.JobRun.Status = 404 }, rowJobHistory, "job_read_refused", []string{rowIDs}},
		{"the job view is not ready", func(o *journeyObservation) {
			jobView(o, func(v *httpapi.JobView) {
				v.State, v.Reason = httpapi.StateNotAvailable, httpapi.ReasonJobStoreNotReadable
			})
		}, rowJobHistory, "job_not_ready", []string{rowIDs}},
		{"failed attempt missing entirely", func(o *journeyObservation) {
			jobView(o, func(v *httpapi.JobView) { v.Run.Attempts = v.Run.Attempts[1:] })
		}, rowJobHistory, "attempt_1_missing", nil},
		{"failed attempt lost its terminal fact", func(o *journeyObservation) {
			jobView(o, func(v *httpapi.JobView) { attempt(v, 1).Terminal = nil })
		}, rowJobHistory, "attempt_1_not_failed", nil},
		{"first attempt succeeded instead of failing", func(o *journeyObservation) {
			jobView(o, func(v *httpapi.JobView) {
				a := attempt(v, 1)
				a.Terminal.State, a.Effective = jobs.AttemptSucceeded, jobs.AttemptSucceeded
			})
		}, rowJobHistory, "attempt_1_not_failed", nil},
		{"first attempt was corrected away from failed", func(o *journeyObservation) {
			jobView(o, func(v *httpapi.JobView) { attempt(v, 1).Effective = jobs.AttemptSucceeded })
		}, rowJobHistory, "attempt_1_not_failed", nil},
		{"second attempt never succeeded", func(o *journeyObservation) {
			jobView(o, func(v *httpapi.JobView) { v.Run.Attempts = v.Run.Attempts[:1] })
		}, rowJobHistory, "attempt_2_missing", nil},
		{"second attempt failed too", func(o *journeyObservation) {
			jobView(o, func(v *httpapi.JobView) {
				a := attempt(v, 2)
				a.Terminal.State, a.Effective = jobs.AttemptFailed, jobs.AttemptFailed
			})
		}, rowJobHistory, "attempt_2_not_succeeded", nil},
		{"two attempts share an ordinal", func(o *journeyObservation) {
			jobView(o, func(v *httpapi.JobView) {
				extra := goodAttempt(0x43, 2, jobs.AttemptSucceeded, 500, false)
				v.Run.Attempts = append(v.Run.Attempts, extra)
			})
		}, rowJobHistory, "duplicate_ordinal", nil},
		{"a third attempt exists", func(o *journeyObservation) {
			jobView(o, func(v *httpapi.JobView) {
				v.Run.Attempts = append(v.Run.Attempts, goodAttempt(0x43, 3, jobs.AttemptSucceeded, 500, false))
			})
		}, rowJobHistory, "unexpected_extra_attempt", nil},
		{"retry reuses the failed attempt's id", func(o *journeyObservation) {
			jobView(o, func(v *httpapi.JobView) { attempt(v, 2).ID = attempt(v, 1).ID })
		}, rowJobHistory, "attempt_order_disorder", nil},
		{"retry ended before the failed attempt", func(o *journeyObservation) {
			jobView(o, func(v *httpapi.JobView) { attempt(v, 2).Terminal.At = 100 })
		}, rowJobHistory, "attempt_order_disorder", nil},
		{"the failed attempt is the final one", func(o *journeyObservation) {
			jobView(o, func(v *httpapi.JobView) { attempt(v, 1).Final, attempt(v, 2).Final = true, false })
		}, rowJobHistory, "final_attempt_wrong", nil},
		{"the run is not recovered", func(o *journeyObservation) {
			jobView(o, func(v *httpapi.JobView) { v.Run.Status, v.Run.Recovered = jobs.RunSucceeded, false })
		}, rowJobHistory, "run_not_recovered", nil},
		{"the answered run is not the expected run", func(o *journeyObservation) {
			jobView(o, func(v *httpapi.JobView) { v.Run.ID = jid(0x99) })
		}, rowJobHistory, "job_or_run_differs", []string{rowIDs}},
		{"the answered job is not the expected job", func(o *journeyObservation) { jobView(o, func(v *httpapi.JobView) { v.Job = jid(0x77) }) }, rowJobHistory, "job_or_run_differs", []string{rowIDs}},
		{"the job answer carries no run", func(o *journeyObservation) { jobView(o, func(v *httpapi.JobView) { v.Run = nil }) }, rowJobHistory, "run_missing", []string{rowIDs}},
		{"the failed attempt's original terminal fact was a success that a correction turned into a failure", func(o *journeyObservation) {
			jobView(o, func(v *httpapi.JobView) { attempt(v, 1).Terminal.State = jobs.AttemptSucceeded })
		}, rowJobHistory, "attempt_1_not_failed", nil},
		{"the successful attempt's original terminal fact was a failure that a correction turned into a success", func(o *journeyObservation) {
			jobView(o, func(v *httpapi.JobView) { attempt(v, 2).Terminal.State = jobs.AttemptFailed })
		}, rowJobHistory, "attempt_2_not_succeeded", nil},
		{"the successful attempt was corrected to a failure", func(o *journeyObservation) {
			jobView(o, func(v *httpapi.JobView) { attempt(v, 2).Effective = jobs.AttemptFailed })
		}, rowJobHistory, "attempt_2_not_succeeded", nil},
		{"the failed attempt never started", func(o *journeyObservation) { jobView(o, func(v *httpapi.JobView) { attempt(v, 1).Started = false }) }, rowJobHistory, "attempt_1_not_failed", nil},
		{"the retry never started", func(o *journeyObservation) { jobView(o, func(v *httpapi.JobView) { attempt(v, 2).Started = false }) }, rowJobHistory, "attempt_2_not_succeeded", nil},
		{"the retry was observed before the failed attempt", func(o *journeyObservation) {
			jobView(o, func(v *httpapi.JobView) { attempt(v, 2).ObservedAt = attempt(v, 1).ObservedAt - 1 })
		}, rowJobHistory, "attempt_order_disorder", nil},
		{"both attempts are final", func(o *journeyObservation) { jobView(o, func(v *httpapi.JobView) { attempt(v, 1).Final = true }) }, rowJobHistory, "final_attempt_wrong", nil},
		{"the run status is not recovered although the flag says so", func(o *journeyObservation) {
			jobView(o, func(v *httpapi.JobView) { v.Run.Status = jobs.RunSucceeded })
		}, rowJobHistory, "run_not_recovered", nil},
		{"the run says recovered but its flag does not", func(o *journeyObservation) { jobView(o, func(v *httpapi.JobView) { v.Run.Recovered = false }) }, rowJobHistory, "run_not_recovered", nil},
		{"the run counts three attempts", func(o *journeyObservation) { jobView(o, func(v *httpapi.JobView) { v.Run.AttemptCount = 3 }) }, rowJobHistory, "run_not_recovered", nil},
		{"the run counts no failed attempt", func(o *journeyObservation) { jobView(o, func(v *httpapi.JobView) { v.Run.FailedAttempts = 0 }) }, rowJobHistory, "run_not_recovered", nil},

		// ---- the runtime profile, read through the profile route ----
		{"the runtime profile scenario did not run", func(o *journeyObservation) { o.RuntimeProfile = runtimeProfileObservation{} }, rowRuntimeProfile, "not_attempted", nil},
		{"the runtime profile never reached storage", func(o *journeyObservation) { o.RuntimeProfile.StoredChunks, o.RuntimeProfile.Read = 0, nil }, rowRuntimeProfile, "runtime_profile_not_stored", nil},
		{"the stored runtime profile was never read", func(o *journeyObservation) { o.RuntimeProfile.Read = nil }, rowRuntimeProfile, "profile_not_read", nil},
		{"the profile route refused", func(o *journeyObservation) { o.RuntimeProfile.Read.Status = 404 }, rowRuntimeProfile, "profile_read_refused", nil},
		{"the profile route answered another profile", func(o *journeyObservation) {
			profileView(o, func(v *httpapi.ProfileResponse) { v.Profile = jid(0x78) })
		}, rowRuntimeProfile, "profile_identity_mismatch", nil},
		{"the profile view is not available", func(o *journeyObservation) {
			profileView(o, func(v *httpapi.ProfileResponse) { v.State, v.View = httpapi.StateNotAvailable, nil })
		}, rowRuntimeProfile, "profile_not_ready", nil},
		{"the profile has no samples", func(o *journeyObservation) {
			profileView(o, func(v *httpapi.ProfileResponse) { v.View.Samples = nil })
		}, rowRuntimeProfile, "profile_has_no_samples", nil},
		{"the profile does not show the sampled function", func(o *journeyObservation) {
			profileView(o, func(v *httpapi.ProfileResponse) { v.View.Frames[0].Function = "other_function" })
		}, rowRuntimeProfile, "profile_misses_the_sampled_function", nil},
		{"the profile names no capability record", func(o *journeyObservation) {
			profileView(o, func(v *httpapi.ProfileResponse) { v.View.Capabilities = nil })
		}, rowRuntimeProfile, "profile_capability_not_linked", nil},
		{"the profile's capability is unsupported", func(o *journeyObservation) {
			profileView(o, func(v *httpapi.ProfileResponse) { v.View.Capabilities[0].Value.Status = "denied" })
		}, rowRuntimeProfile, "profile_capability_not_linked", nil},
		{"the profile's capability is another method", func(o *journeyObservation) {
			profileView(o, func(v *httpapi.ProfileResponse) { v.View.Capabilities[0].Value.Method = "python_monitoring" })
		}, rowRuntimeProfile, "profile_capability_not_linked", nil},
		{"the profile's capability is of another signal", func(o *journeyObservation) {
			profileView(o, func(v *httpapi.ProfileResponse) { v.View.Capabilities[0].Value.Signal = model.SpanKind })
		}, rowRuntimeProfile, "profile_capability_not_linked", nil},
		{"an incomplete profile that declares no loss", func(o *journeyObservation) {
			profileView(o, func(v *httpapi.ProfileResponse) {
				v.State, v.Reason, v.Partial = httpapi.StateIncomplete, profiles.ReasonCoverageIncomplete, true
				v.View.Completeness = "partial"
			})
		}, rowRuntimeProfile, "profile_not_ready", nil},
		{"a ready profile that is partial", func(o *journeyObservation) {
			profileView(o, func(v *httpapi.ProfileResponse) { v.View.Completeness, v.View.LossCount = "partial", 5 })
		}, rowRuntimeProfile, "profile_not_ready", nil},
		{"an incomplete profile whose view claims to be complete", func(o *journeyObservation) {
			profileView(o, func(v *httpapi.ProfileResponse) {
				v.State, v.Reason, v.Partial = httpapi.StateIncomplete, profiles.ReasonCoverageIncomplete, true
				v.View.LossCount = 129
			})
		}, rowRuntimeProfile, "profile_not_ready", nil},
		{"an incomplete profile for another reason", func(o *journeyObservation) {
			profileView(o, func(v *httpapi.ProfileResponse) {
				v.State, v.Reason, v.Partial = httpapi.StateIncomplete, profiles.ReasonMissingChunk, true
				v.View.Completeness, v.View.LossCount = "partial", 3
			})
		}, rowRuntimeProfile, "profile_not_ready", nil},
		{"an incomplete profile that declares its sampling loss is the product's truth, not a failure", func(o *journeyObservation) {
			profileView(o, func(v *httpapi.ProfileResponse) {
				v.State, v.Reason, v.Partial = httpapi.StateIncomplete, profiles.ReasonCoverageIncomplete, true
				v.View.Completeness, v.View.LossCount = "partial", 129
			})
		}, "", "", nil},

		// ---- cross-organization reads ----
		{"own-project read by the other reader does not count as a probe", func(o *journeyObservation) {
			o.Reads = append(o.Reads, traceRead{Actor: "reader-b", OrgSent: o.Expected.OtherOrg, Project: o.Expected.OtherProject, Trace: o.UITrace, Status: 200, Body: json.RawMessage(`{"state":"empty"}`)})
		}, "", "", nil},
		{"denial body with an empty path object", func(o *journeyObservation) {
			for i := range o.Reads {
				if o.Reads[i].Actor == "reader-b" && o.Reads[i].Trace == o.UITrace {
					o.Reads[i].Body = json.RawMessage(`{"path":{}}`)
				}
			}
		}, rowCrossOrg, "cross_org_body_leaks_trace", nil},
		{"canary flow list empty", func(o *journeyObservation) { o.Flows[0].Reached = nil }, rowCanaries, "canary_never_flowed", nil},
		{"partial flag with ready state", func(o *journeyObservation) {
			for i := range o.Reads {
				if o.Reads[i].Actor == "reader-a" && o.Reads[i].Trace == o.DirectTrace {
					var v httpapi.TraceView
					_ = json.Unmarshal(o.Reads[i].Body, &v)
					v.Partial = true
					o.Reads[i].Body, _ = json.Marshal(v)
				}
			}
		}, rowGatewayChain, "trace_not_ready", []string{rowDBSpanSafe, rowIDs, rowCrossOrg}},
		{"two roots in the ui trace", func(o *journeyObservation) {
			spans := uiSpans(o.UITrace)
			extra := testSpan(o.UITrace, 9, 0, "internal", "ui.action", "", 5)
			reread(o, o.UITrace, append(spans, extra), false)
		}, rowUIChain, "causal_edge_issue", nil},
		{"replay admitted but not stored", func(o *journeyObservation) { o.Replay.StoredReplayRow = 0 }, rowReplay, "recorder_chunks_not_admitted", nil},
		{"profile enqueued but not stored", func(o *journeyObservation) { o.Profile.StoredProfile = 0 }, rowProfile, "sdk_profile_not_delivered", nil},
		{"same trace readable from the wrong org", func(o *journeyObservation) {
			for i := range o.Reads {
				if o.Reads[i].Actor == "reader-b" && o.Reads[i].Trace == o.UITrace && o.Reads[i].OrgSent == o.Expected.OtherOrg {
					o.Reads[i].Status = 200
				}
			}
		}, rowCrossOrg, "cross_org_read_allowed", nil},
		{"wrong org reader holding the owner's org id is allowed", func(o *journeyObservation) {
			for i := range o.Reads {
				if o.Reads[i].Actor == "reader-b" && o.Reads[i].Trace == o.DirectTrace && o.Reads[i].OrgSent == o.Expected.Org {
					o.Reads[i].Status = 200
				}
			}
		}, rowCrossOrg, "cross_org_read_allowed", nil},
		{"denial body carries the trace", func(o *journeyObservation) {
			for i := range o.Reads {
				if o.Reads[i].Actor == "reader-b" && o.Reads[i].Trace == o.UITrace {
					o.Reads[i].Body = json.RawMessage(`{"path":{"spans":[]}}`)
				}
			}
		}, rowCrossOrg, "cross_org_body_leaks_trace", nil},
		{"wrong org never probed", func(o *journeyObservation) {
			o.Reads = slices.DeleteFunc(o.Reads, func(r traceRead) bool { return r.Actor == "reader-b" && r.Trace == o.DirectTrace })
		}, rowCrossOrg, "cross_org_not_probed", nil},
		{"positive control missing", func(o *journeyObservation) {
			o.Reads = slices.DeleteFunc(o.Reads, func(r traceRead) bool { return r.Actor == "reader-a" && r.Trace == o.UITrace })
		}, rowCrossOrg, "positive_control_missing", []string{rowUIChain, rowDBSpanSafe, rowIDs}},
		{"canary found in storage", func(o *journeyObservation) {
			o.Leaks = []leakHit{{Canary: canaryBody, Where: "node data dir"}}
		}, rowCanaries, "canary_present", nil},
		{"canary found in a read answer", func(o *journeyObservation) {
			o.Leaks = []leakHit{{Canary: canarySQL, Where: "read answer"}}
		}, rowCanaries, "canary_present", nil},
		{"canary never sent so absence proves nothing", func(o *journeyObservation) { o.Flows = o.Flows[:2] }, rowCanaries, "canary_never_flowed", nil},
		{"SQL text reached a stored record", func(o *journeyObservation) { o.UnsafeStorage = []string{"error record contains SELECT"} }, rowDBSpanSafe, "sql_text_in_storage", nil},
		{"db span carries more than the safe operation", func(o *journeyObservation) {
			spans := uiSpans(o.UITrace)
			spans[5].Operation = "SELECT price_cents FROM catalog"
			reread(o, o.UITrace, spans, false)
		}, rowDBSpanSafe, "db_span_operation_unsafe", []string{rowUIChain}},
		{"api made no database call", func(o *journeyObservation) {
			spans := slices.DeleteFunc(directSpans(o.DirectTrace), func(s model.Span) bool { return s.Dependency == "postgres" })
			reread(o, o.DirectTrace, spans, false)
		}, rowGatewayChain, "api_dependency_span_missing", nil},
		{"api made no dependency call", func(o *journeyObservation) {
			spans := slices.DeleteFunc(directSpans(o.DirectTrace), func(s model.Span) bool { return s.Dependency == "dependency" })
			reread(o, o.DirectTrace, spans, false)
		}, rowGatewayChain, "api_dependency_span_missing", nil},
		{"gateway span has no api child", func(o *journeyObservation) {
			spans := slices.DeleteFunc(directSpans(o.DirectTrace), func(s model.Span) bool { return s.ID == sid(2) })
			for i := range spans {
				if spans[i].ID == sid(3) {
					spans[i].Parent = mustPtr(sid(1))
				}
			}
			reread(o, o.DirectTrace, spans, false)
		}, rowGatewayChain, "chain_link_missing", nil},
		{"api span is not parented to the gateway call", func(o *journeyObservation) {
			spans := directSpans(o.DirectTrace)
			spans[2].Parent = nil
			reread(o, o.DirectTrace, spans, false)
		}, rowGatewayChain, "causal_edge_issue", nil},
		{"partial trace is not a complete chain", func(o *journeyObservation) {
			reread(o, o.DirectTrace, directSpans(o.DirectTrace), true)
		}, rowGatewayChain, "trace_not_ready", []string{rowDBSpanSafe, rowIDs, rowCrossOrg}},
		{"browser action is not the root", func(o *journeyObservation) {
			spans := uiSpans(o.UITrace)
			spans = spans[1:]
			spans[0].Parent = nil
			reread(o, o.UITrace, spans, false)
		}, rowUIChain, "root_span_wrong", nil},
		{"request never reached the api", func(o *journeyObservation) {
			spans := uiSpans(o.UITrace)[:4]
			reread(o, o.UITrace, spans, false)
		}, rowUIChain, "chain_link_missing", []string{rowDBSpanSafe}},
		{"replay chunks refused", func(o *journeyObservation) {
			o.Replay = replayObservation{Attempted: true, RecorderChunks: 3, RefusedOrLost: "recorder_chunks_refused_by_validator"}
		}, rowReplay, "recorder_chunks_refused_by_validator", nil},
		{"replay not attempted", func(o *journeyObservation) { o.Replay = replayObservation{} }, rowReplay, "not_attempted", nil},
		{"profile never reaches the node", func(o *journeyObservation) {
			o.Profile = profileObservation{Attempted: true, Capability: "denied", Reason: "document_policy_missing"}
		}, rowProfile, "sdk_profile_not_delivered", nil},
		{"a version is not recorded", func(o *journeyObservation) { delete(o.Versions, "chrome") }, rowVersions, "version_missing", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := goodObservation(t)
			c.mutate(&o)
			rows := assessJourneys(o)
			if c.row == "" {
				if len(unsatisfiedRequired(rows)) != 0 {
					t.Fatalf("%s must not fail any row: %v", c.name, unsatisfiedRequired(rows))
				}
				return
			}
			got := rowByName(rows, c.row)
			if got.Satisfied || got.Reason != c.reason {
				t.Fatalf("row %s: satisfied=%v reason=%q (%s), want rejection %q", c.row, got.Satisfied, got.Reason, got.Detail, c.reason)
			}
			allowed := append([]string{c.row}, c.also...)
			for _, r := range rows {
				if !r.Satisfied && !slices.Contains(allowed, r.Name) {
					t.Fatalf("row %s must not fail with %q but did: %s (%s)", r.Name, c.name, r.Reason, r.Detail)
				}
			}
			if len(unsatisfiedRequired(rows)) == 0 {
				t.Fatal("an unsatisfied required row must be reported")
			}
		})
	}

	t.Run("recorded", func(t *testing.T) { recordedObservation(t) })
}

// recordedObservation feeds the assertion logic the observation the real smoke produced.
// The file is written by `journeys` (testdata/journeys/observed.json, sanitized: IDs, product route
// answers, hashes and counters only; no credentials or telemetry text).
func recordedObservation(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "journeys", "observed.json"))
	if err != nil {
		t.Fatalf("recorded real observation is required: %v", err)
	}
	var recorded struct {
		Observation journeyObservation `json:"observation"`
		Rows        []journeyRow       `json:"rows"`
	}
	if err = json.Unmarshal(raw, &recorded); err != nil {
		t.Fatal(err)
	}
	rows := assessJourneys(recorded.Observation)
	if fmt.Sprint(rows) != fmt.Sprint(recorded.Rows) {
		t.Fatalf("rows differ from the ones the smoke printed for the same observation:\nnow:  %v\nthen: %v", rows, recorded.Rows)
	}
	// What the real run found: every row holds, including the stored error's frames mapped by the product and the runtime profile.
	for _, r := range rows {
		if !r.Satisfied {
			t.Fatalf("recorded real observation: row %s %s (%s)", r.Name, r.Reason, r.Detail)
		}
	}
	// The same real answers with one fact made wrong must be rejected by the row it violates.
	clone := func() journeyObservation {
		var c struct {
			Observation journeyObservation `json:"observation"`
		}
		if err := json.Unmarshal(raw, &c); err != nil {
			t.Fatal(err)
		}
		return c.Observation
	}
	wrong := []struct {
		name   string
		mutate func(o *journeyObservation)
		row    string
		reason string
	}{
		{"wrong build", func(o *journeyObservation) {
			rewrite(t, &o.Errors[0].Read, func(v *httpapi.ErrorOccurrenceView) { v.Detail.Build = jid(0x55) })
		}, rowErrorBuild, "wrong_build"},
		{"stored error without frames", func(o *journeyObservation) {
			rewrite(t, &o.Errors[0].Read, func(v *httpapi.ErrorOccurrenceView) { v.Detail.Frames = nil })
		}, rowMappedFrame, "stored_error_has_no_frames"},
		{"wrong location", func(o *journeyObservation) {
			rewrite(t, o.Frames, func(v *httpapi.FramesView) { v.Frames[0].Resolved.Line++ })
		}, rowMappedFrame, "wrong_source_location"},
		{"missing failed attempt", func(o *journeyObservation) {
			rewrite(t, o.JobRun, func(v *httpapi.JobView) { v.Run.Attempts = v.Run.Attempts[1:] })
		}, rowJobHistory, "attempt_1_missing"},
		{"profile without the sampled function", func(o *journeyObservation) {
			rewrite(t, o.RuntimeProfile.Read, func(v *httpapi.ProfileResponse) {
				for i := range v.View.Frames {
					v.View.Frames[i].Function = "other_function"
				}
			})
		}, rowRuntimeProfile, "profile_misses_the_sampled_function"},
		{"cross-org read allowed", func(o *journeyObservation) {
			for i := range o.Reads {
				if o.Reads[i].Actor == "reader-b" && o.Reads[i].Trace == o.UITrace {
					o.Reads[i].Status = 200
				}
			}
		}, rowCrossOrg, "cross_org_read_allowed"},
		{"canary present", func(o *journeyObservation) {
			o.Leaks = append(o.Leaks, leakHit{Canary: o.Expected.Canaries[1], Where: "node data dir"})
		}, rowCanaries, "canary_present"},
	}
	for _, c := range wrong {
		o := clone()
		c.mutate(&o)
		if r := rowByName(assessJourneys(o), c.row); r.Satisfied || r.Reason != c.reason {
			t.Fatalf("%s: row %s satisfied=%v reason=%q, want rejection %q", c.name, c.row, r.Satisfied, r.Reason, c.reason)
		}
	}
}

// The ids row is a row of its own: a wrong job or run answered by the job route must fail it with its own reason, not only the job-history
// row that reads the same answer.
func TestReferenceJourneyIDsRowChecksTheJobAndRunItself(t *testing.T) {
	for _, c := range []struct {
		name   string
		mutate func(v *httpapi.JobView)
		reason string
	}{
		{"another job", func(v *httpapi.JobView) { v.Job = jid(0x77) }, "job_id_differs"},
		{"another run", func(v *httpapi.JobView) { v.Run.ID = jid(0x99) }, "run_id_missing"},
	} {
		o := goodObservation(t)
		rewrite(t, o.JobRun, c.mutate)
		if r := rowByName(assessJourneys(o), rowIDs); r.Satisfied || r.Reason != c.reason {
			t.Errorf("%s: row %s satisfied=%v reason=%q (%s), want rejection %q", c.name, rowIDs, r.Satisfied, r.Reason, r.Detail, c.reason)
		}
	}
}

// The canary scanner must find the canary where the node really stores it (commands are base64
// inside JSON inside base64) or its silence proves nothing.
func TestJourneyScannerFindsNestedCanaries(t *testing.T) {
	inner := base64.StdEncoding.EncodeToString([]byte(`{"note":"` + canaryBody + `"}`))
	outer := base64.RawURLEncoding.EncodeToString([]byte(`{"command":"` + inner + `"}`))
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "journal"), []byte("header "+outer+" trailer"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "clean"), []byte(`{"command":"`+base64.StdEncoding.EncodeToString([]byte("nothing sensitive in this record at all"))+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	hits, files, err := scanTreeForCanaries(context.Background(), dir, []string{canaryBody, canaryPrompt})
	if err != nil || files != 2 {
		t.Fatalf("scan: files=%d err=%v", files, err)
	}
	if len(hits) != 1 || hits[0].Canary != canaryBody || !strings.Contains(hits[0].Where, "journal") {
		t.Fatalf("hits=%v, want exactly the nested canary in the journal", hits)
	}
}
