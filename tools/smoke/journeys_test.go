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
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/traces"
)

// The journey assertions are checked against KNOWN application behavior: the gateway call has a
// dependency child; a click in the web app causes request -> API -> database and then fails in
// the known build at the known source location; the job's first attempt fails, the second
// succeeds and the failed attempt stays in the record; the same trace read from another
// organization is denied; canaries that really flowed through the applications are never stored.
// Every wrong observation below must be rejected by exactly the row it violates.

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
	testLine     = 17
	testColumn   = 11
	canaryBody   = "CANARY_BODY_7f3a"
	canaryPrompt = "CANARY_PROMPT_9b2f"
	canarySQL    = "CANARY_SQL_LITERAL_5d1e"
)

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
	span := sid(1)
	o.Errors = []observedError{{Source: exp.WebSource, Record: model.ErrorOccurrence{Occurrence: jid(0x20), Class: "ReceiptError", Mechanism: "manual", Build: exp.WebBuild, Handled: true, Trace: &ui, Span: &span, Frames: []model.Frame{}}}}
	terminal := func(ns int64) *model.UnixNano { v := model.UnixNano(ns); return &v }
	job := func(attempt byte, ordinal uint64, seq uint64, state string, observed int64) observedJob {
		e := model.JobAttemptEvent{Job: exp.Job, Run: exp.Run, Attempt: jid(attempt), Ordinal: model.Uint64(ordinal), Epoch: jid(0x30), Sequence: model.Uint64(seq), State: state, Observed: model.UnixNano(observed)}
		if state != "started" {
			e.Terminal = terminal(observed + 5)
		}
		return observedJob{Source: jid(9), Event: e}
	}
	o.Jobs = []observedJob{job(0x41, 1, 1, "started", 100), job(0x41, 1, 2, "failed", 200), job(0x42, 2, 3, "started", 300), job(0x42, 2, 4, "succeeded", 400)}
	o.Artifact = artifactObservation{Uploaded: true, Build: exp.WebBuild, DebugID: "0123456789abcdef0123456789abcdef", Artifact: "fedcba9876543210fedcba9876543210"}
	o.Symbol = symbolObservation{Reason: "resolved", Source: testSource, LineN: testLine, ColumnN: testColumn, Build: exp.WebBuild, FromPage: true}
	for _, c := range exp.Canaries {
		o.Flows = append(o.Flows, canaryFlow{Canary: c, Reached: []string{"dependency_prompt_counter"}})
	}
	o.Replay = replayObservation{Attempted: true, RecorderChunks: 1, AdmittedChunks: 1, StoredReplayRow: 1}
	o.Profile = profileObservation{Attempted: true, Capability: "available", StoredProfile: 1, SDKEnqueues: true}
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
	dropEvents := func(o *journeyObservation, keep func(observedJob) bool) {
		o.Jobs = slices.DeleteFunc(o.Jobs, func(j observedJob) bool { return !keep(j) })
	}

	cases := []struct {
		name   string
		mutate func(o *journeyObservation)
		row    string
		reason string
		also   []string // rows that legitimately fail with it
	}{
		{"wrong build in the admitted error", func(o *journeyObservation) { o.Errors[0].Record.Build = jid(0x66) }, rowErrorBuild, "wrong_build", []string{rowIDs}},
		{"no error admitted from the web source", func(o *journeyObservation) { o.Errors = nil }, rowErrorBuild, "no_web_error_admitted", []string{rowErrorTrace}},
		{"error not linked to the trace", func(o *journeyObservation) { o.Errors[0].Record.Trace = nil }, rowErrorTrace, "error_not_linked_to_trace", nil},
		{"error linked to a different trace", func(o *journeyObservation) { o.Errors[0].Record.Trace = &o.DirectTrace }, rowErrorTrace, "error_not_linked_to_trace", nil},
		{"source map uploaded for another build", func(o *journeyObservation) { o.Artifact.Build = jid(0x67) }, rowSourceMap, "wrong_build", []string{rowIDs}},
		{"source map upload not acknowledged", func(o *journeyObservation) { o.Artifact.Uploaded = false }, rowSourceMap, "upload_not_acknowledged", nil},
		{"bundle still names its map", func(o *journeyObservation) { o.Artifact.HasSourceMapRef = true }, rowSourceMap, "map_reference_shipped", nil},
		{"wrong source line", func(o *journeyObservation) { o.Symbol.LineN++ }, rowMappedFrame, "wrong_source_location", nil},
		{"wrong source column", func(o *journeyObservation) { o.Symbol.ColumnN++ }, rowMappedFrame, "wrong_source_location", nil},
		{"wrong source file", func(o *journeyObservation) { o.Symbol.Source = "src/main.ts" }, rowMappedFrame, "wrong_source_location", nil},
		{"mapped under the wrong build", func(o *journeyObservation) { o.Symbol.Build = jid(0x68) }, rowMappedFrame, "wrong_build", nil},
		{"sandbox unavailable is never a pass", func(o *journeyObservation) { o.Symbol = symbolObservation{Reason: "sandbox_unavailable"} }, rowMappedFrame, "sandbox_unavailable", nil},
		{"position not taken from the real page error", func(o *journeyObservation) { o.Symbol.FromPage = false }, rowMappedFrame, "generated_position_not_from_page", nil},
		{"failed attempt missing entirely", func(o *journeyObservation) {
			dropEvents(o, func(j observedJob) bool { return j.Event.Ordinal != 1 })
		}, rowJobHistory, "attempt_1_missing", nil},
		{"failed attempt lost its terminal event", func(o *journeyObservation) {
			dropEvents(o, func(j observedJob) bool { return !(j.Event.Ordinal == 1 && j.Event.State == "failed") })
		}, rowJobHistory, "attempt_1_not_failed", nil},
		{"first attempt succeeded instead of failing", func(o *journeyObservation) {
			for i := range o.Jobs {
				if o.Jobs[i].Event.Ordinal == 1 && o.Jobs[i].Event.State == "failed" {
					o.Jobs[i].Event.State = "succeeded"
				}
			}
		}, rowJobHistory, "attempt_1_not_failed", nil},
		{"second attempt never succeeded", func(o *journeyObservation) {
			dropEvents(o, func(j observedJob) bool { return !(j.Event.Ordinal == 2 && j.Event.State == "succeeded") })
		}, rowJobHistory, "attempt_2_not_succeeded", nil},
		{"retry reuses the failed attempt's id", func(o *journeyObservation) {
			for i := range o.Jobs {
				if o.Jobs[i].Event.Ordinal == 2 {
					o.Jobs[i].Event.Attempt = jid(0x41)
				}
			}
		}, rowJobHistory, "attempt_ordinal_inconsistent", nil},
		{"admitted run is not the expected run", func(o *journeyObservation) {
			for i := range o.Jobs {
				o.Jobs[i].Event.Run = jid(0x99)
			}
		}, rowJobHistory, "no_attempts_admitted", []string{rowIDs}},
		{"attempt ends before it starts", func(o *journeyObservation) {
			for i := range o.Jobs {
				if o.Jobs[i].Event.Ordinal == 1 && o.Jobs[i].Event.State == "failed" {
					o.Jobs[i].Event.Sequence = 0
				}
			}
		}, rowJobHistory, "attempt_sequence_disorder", nil},
		{"retry starts before the failed attempt ended", func(o *journeyObservation) {
			for i := range o.Jobs {
				if o.Jobs[i].Event.Ordinal == 2 && o.Jobs[i].Event.State == "started" {
					o.Jobs[i].Event.Sequence = 2
				}
			}
		}, rowJobHistory, "attempt_sequence_disorder", nil},
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
		{"second attempt failed too", func(o *journeyObservation) {
			for i := range o.Jobs {
				if o.Jobs[i].Event.Ordinal == 2 && o.Jobs[i].Event.State == "succeeded" {
					o.Jobs[i].Event.State = "failed"
				}
			}
		}, rowJobHistory, "attempt_2_not_succeeded", nil},
		{"two attempt ids share an ordinal", func(o *journeyObservation) {
			o.Jobs = append(o.Jobs, observedJob{Source: jid(9), Event: model.JobAttemptEvent{Job: o.Expected.Job, Run: o.Expected.Run, Attempt: jid(0x43), Ordinal: 2, Epoch: jid(0x30), Sequence: 9, State: "started", Observed: 500}})
		}, rowJobHistory, "duplicate_ordinal", nil},
		{"canary flow list empty", func(o *journeyObservation) { o.Flows[0].Reached = nil }, rowCanaries, "canary_never_flowed", nil},
		{"error without a span id", func(o *journeyObservation) { o.Errors[0].Record.Span = nil }, rowErrorTrace, "error_not_linked_to_trace", nil},
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
		{"job id differs", func(o *journeyObservation) {
			for i := range o.Jobs {
				o.Jobs[i].Event.Job = jid(0x77)
			}
		}, rowJobHistory, "no_attempts_admitted", []string{rowIDs}},
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
// The file is written by `journeys` (testdata/journeys/observed.json, sanitized: IDs, read
// answers, stored record fields and hashes only; no credentials or telemetry text).
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
	// What the real run found: these rows hold, and the two SDK limits are recorded as unsatisfied.
	for _, name := range []string{rowGatewayChain, rowUIChain, rowErrorBuild, rowErrorTrace, rowSourceMap, rowJobHistory, rowCrossOrg, rowCanaries, rowDBSpanSafe, rowIDs, rowVersions} {
		if r := rowByName(rows, name); !r.Satisfied {
			t.Fatalf("recorded real observation: row %s %s (%s)", name, r.Reason, r.Detail)
		}
	}
	for name, reason := range map[string]string{rowReplay: "sdk_recorder_chunks_not_enqueued", rowProfile: "sdk_profile_not_delivered"} {
		if r := rowByName(rows, name); r.Satisfied || r.Reason != reason {
			t.Fatalf("recorded real observation: row %s satisfied=%v reason=%s, want unsatisfied %s", name, r.Satisfied, r.Reason, reason)
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
			for i := range o.Errors {
				if o.Errors[i].Source == o.Expected.WebSource {
					o.Errors[i].Record.Build = jid(0x55)
				}
			}
		}, rowErrorBuild, "wrong_build"},
		{"wrong location", func(o *journeyObservation) { o.Symbol.LineN++ }, rowMappedFrame, "wrong_source_location"},
		{"missing failed attempt", func(o *journeyObservation) {
			o.Jobs = slices.DeleteFunc(o.Jobs, func(j observedJob) bool { return j.Event.Ordinal == 1 })
		}, rowJobHistory, "attempt_1_missing"},
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
		if c.name == "wrong location" && o.Symbol.Reason != "resolved" {
			t.Fatalf("the recorded run must have resolved the frame (reason %s)", o.Symbol.Reason)
		}
		c.mutate(&o)
		if r := rowByName(assessJourneys(o), c.row); r.Satisfied || r.Reason != c.reason {
			t.Fatalf("%s: row %s satisfied=%v reason=%q, want rejection %q", c.name, c.row, r.Satisfied, r.Reason, c.reason)
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
