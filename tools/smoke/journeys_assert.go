// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/jobs"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/profiles"
	"github.com/arynyklas/soundpost/internal/traces"
)

// This file holds the assertion logic of the reference journeys and nothing else: pure
// functions over RECORDED observations (real HTTP read answers, real stored records, real
// process output) so the logic can be exercised against the actual captured answers and against
// deliberately wrong ones (journeys_test.go). Expectations are known application behavior
// (which build, which source location, which attempts), never snapshots of source text.

// Row names. A row is REQUIRED unless its reason is a documented platform or SDK limit that the
// task records as unsatisfied rather than omitted; a required unsatisfied row fails the smoke.
const (
	rowGatewayChain    = "gateway_dependency_child_span"
	rowUIChain         = "frontend_request_api_db_chain"
	rowErrorBuild      = "error_admitted_with_known_build"
	rowErrorTrace      = "error_linked_to_request_trace"
	rowSourceMap       = "build_source_map_uploaded"
	rowMappedFrame     = "mapped_frame_at_known_location"
	rowJobHistory      = "job_failed_attempt_retained_then_success"
	rowCrossOrg        = "same_trace_in_wrong_org_denied"
	rowCanaries        = "canaries_absent_everywhere"
	rowDBSpanSafe      = "db_span_safe_operation_only"
	rowReplay          = "replay_masked_interaction_real_recorder"
	rowProfile         = "profile_linkage_with_capability_truth"
	rowRuntimeProfile  = "runtime_profile_delivered_stored_linked"
	rowIDs             = "actual_ids_equal_expected"
	rowVersions        = "actual_versions_recorded"
	sourceMapChainSize = 32
)

type journeyRow struct {
	Name      string `json:"name"`
	Required  bool   `json:"required"`
	Satisfied bool   `json:"satisfied"`
	Reason    string `json:"reason"`
	Detail    string `json:"detail,omitempty"`
}

// journeyExpected is what the fixture applications are KNOWN to do.
type journeyExpected struct {
	Org                model.ID `json:"org"`
	Project            model.ID `json:"project"`
	OtherOrg           model.ID `json:"other_org"`
	OtherProject       model.ID `json:"other_project"`
	WebSource          model.ID `json:"web_source"`
	WebBuild           model.ID `json:"web_build"`
	Job                model.ID `json:"job"`
	Run                model.ID `json:"run"`
	ThrowSource        string   `json:"throw_source"`
	ThrowLine          uint32   `json:"throw_line"`
	ThrowColumn        uint32   `json:"throw_column"`
	UnpricedItem       string   `json:"unpriced_item"`
	Canaries           []string `json:"canaries"`
	RequiredVersionIDs []string `json:"required_versions"`
}

// traceRead is one real answer of POST /api/v1/traces/view.
type traceRead struct {
	Actor   string          `json:"actor"`
	OrgSent model.ID        `json:"org_sent"`
	Project model.ID        `json:"project_sent"`
	Trace   model.ID        `json:"trace"`
	Status  int             `json:"status"`
	Body    json.RawMessage `json:"body"`
}

// servedRead is one real answer of a product route: the HTTP status and the unmodified body.
type servedRead struct {
	Route  string          `json:"route"`
	Actor  string          `json:"actor"`
	Status int             `json:"status"`
	Body   json.RawMessage `json:"body"`
}

// observedError is one stored error of the web source read THROUGH the product: the trace view
// linked the occurrence and its issue, the occurrence route answered for it.
type observedError struct {
	Issue      model.ID   `json:"issue"`
	Occurrence model.ID   `json:"occurrence"`
	Read       servedRead `json:"read"`
}

// pageObservation is where the real browser reported the thrown error, in the shipped bundle.
type pageObservation struct {
	Found  bool   `json:"found"`
	Path   string `json:"path"`
	Line   uint32 `json:"line"`
	Column uint32 `json:"column"`
}

// runtimeProfileObservation is the server-side runtime profile: the CPython SDK in the job process samples a named
// function, delivers it, the product stores it, and the profile route reads it back.
type runtimeProfileObservation struct {
	Attempted          bool        `json:"attempted"`
	Method             string      `json:"method"`
	StoredChunks       int         `json:"stored_profile_chunks"`
	StoredCapabilities int         `json:"stored_capability_records"`
	Profile            model.ID    `json:"profile"`
	Read               *servedRead `json:"read,omitempty"`
}

// canaryFlow proves a canary really travelled through the applications, so its absence from
// storage is a measurement and not an artifact of the canary never being sent.
type canaryFlow struct {
	Canary  string   `json:"canary"`
	Reached []string `json:"reached"`
}

type leakHit struct {
	Canary string `json:"canary"`
	Where  string `json:"where"`
}

type artifactObservation struct {
	Uploaded        bool     `json:"uploaded"`
	Build           model.ID `json:"build"`
	DebugID         string   `json:"debug_id"`
	Artifact        string   `json:"artifact_id"`
	HasSourceMapRef bool     `json:"bundle_has_sourcemap_reference"`
}

type replayObservation struct {
	Attempted       bool   `json:"attempted"`
	AdmittedChunks  int    `json:"admitted_chunks"`
	RefusedOrLost   string `json:"refusal"`
	RecorderChunks  int    `json:"recorder_chunks"`
	StoredReplayRow int    `json:"stored_replay_rows"`
}

type profileObservation struct {
	Attempted     bool   `json:"attempted"`
	Capability    string `json:"capability_status"`
	Reason        string `json:"capability_reason"`
	StoredProfile int    `json:"stored_profile_rows"`
	// StoredCapability counts the stored browser capability records; CapabilityLinked is true only when every stored profile
	// chunk names a stored capability of signal profile_chunk in the same clock domain (what the profile reader requires).
	StoredCapability int  `json:"stored_capability_rows"`
	StoredSamples    int  `json:"stored_profile_samples"`
	CapabilityLinked bool `json:"capability_linked"`
	SDKEnqueues      bool `json:"sdk_enqueues_profile"`
}

type journeyObservation struct {
	Expected       journeyExpected           `json:"expected"`
	DirectTrace    model.ID                  `json:"direct_trace"`
	UITrace        model.ID                  `json:"ui_trace"`
	Reads          []traceRead               `json:"reads"`
	Errors         []observedError           `json:"errors"`
	JobRun         *servedRead               `json:"job_run,omitempty"`
	Frames         *servedRead               `json:"frames,omitempty"`
	Page           pageObservation           `json:"page_error"`
	Artifact       artifactObservation       `json:"artifact"`
	Flows          []canaryFlow              `json:"canary_flows"`
	Leaks          []leakHit                 `json:"canary_leaks"`
	Replay         replayObservation         `json:"replay"`
	Profile        profileObservation        `json:"profile"`
	RuntimeProfile runtimeProfileObservation `json:"runtime_profile"`
	Versions       map[string]string         `json:"versions"`
	UnsafeStorage  []string                  `json:"unsafe_storage_hits"`
}

func (o *journeyObservation) read(actor string, trace model.ID, org, project model.ID) *traceRead {
	for i := range o.Reads {
		r := &o.Reads[i]
		if r.Actor == actor && r.Trace == trace && r.OrgSent == org && r.Project == project {
			return r
		}
	}
	return nil
}

// assessJourneys evaluates every row from the observation; it never reads anything else.
func assessJourneys(o journeyObservation) []journeyRow {
	rows := []journeyRow{
		rowFrom(rowGatewayChain, true, gatewayChain(o)),
		rowFrom(rowUIChain, true, uiChain(o)),
		rowFrom(rowErrorBuild, true, errorBuild(o)),
		rowFrom(rowErrorTrace, true, errorTrace(o)),
		rowFrom(rowSourceMap, true, sourceMapUploaded(o)),
		rowFrom(rowMappedFrame, true, mappedFrame(o)),
		rowFrom(rowJobHistory, true, jobHistory(o)),
		rowFrom(rowCrossOrg, true, crossOrg(o)),
		rowFrom(rowCanaries, true, canariesAbsent(o)),
		rowFrom(rowDBSpanSafe, true, dbSpanSafe(o)),
		rowFrom(rowReplay, true, replayRow(o)),
		rowFrom(rowProfile, true, profileRow(o)),
		rowFrom(rowRuntimeProfile, true, runtimeProfileRow(o)),
		rowFrom(rowIDs, true, idsEqual(o)),
		rowFrom(rowVersions, true, versionsRecorded(o)),
	}
	return rows
}

type verdict struct {
	ok     bool
	reason string
	detail string
}

func pass(detail string, args ...any) verdict {
	return verdict{ok: true, detail: fmt.Sprintf(detail, args...)}
}
func fail(reason, detail string, args ...any) verdict {
	return verdict{reason: reason, detail: fmt.Sprintf(detail, args...)}
}

func rowFrom(name string, required bool, v verdict) journeyRow {
	reason := v.reason
	if v.ok {
		reason = "ok"
	}
	return journeyRow{Name: name, Required: required, Satisfied: v.ok, Reason: reason, Detail: v.detail}
}

// unsatisfiedRequired lists the required rows that did not pass (the smoke exits nonzero if any).
func unsatisfiedRequired(rows []journeyRow) []journeyRow {
	var out []journeyRow
	for _, r := range rows {
		if r.Required && !r.Satisfied {
			out = append(out, r)
		}
	}
	return out
}

func decodeTrace(r *traceRead) (httpapi.TraceView, error) {
	var v httpapi.TraceView
	dec := json.NewDecoder(bytes.NewReader(r.Body))
	if err := dec.Decode(&v); err != nil {
		return v, err
	}
	return v, nil
}

// readyTrace returns the authorized reader's complete answer for a trace.
func readyTrace(o journeyObservation, trace model.ID) (*traces.PathResult, verdict) {
	r := o.read("reader-a", trace, o.Expected.Org, o.Expected.Project)
	if r == nil {
		return nil, fail("no_trace_read", "no authorized read of trace %s", trace)
	}
	if r.Status != 200 {
		return nil, fail("trace_read_refused", "authorized read of trace %s answered %d", trace, r.Status)
	}
	v, err := decodeTrace(r)
	if err != nil || v.Path == nil {
		return nil, fail("trace_view_undecodable", "trace %s view without a path", trace)
	}
	if v.Trace != trace || v.Path.Trace != trace {
		return nil, fail("trace_identity_mismatch", "view trace %s path trace %s want %s", v.Trace, v.Path.Trace, trace)
	}
	if v.State != httpapi.StateReady || v.Partial || v.Path.SpanCount != len(v.Path.Spans) {
		return nil, fail("trace_not_ready", "state=%s partial=%v spans=%d/%d", v.State, v.Partial, v.Path.SpanCount, len(v.Path.Spans))
	}
	return v.Path, verdict{ok: true}
}

type spanStep struct {
	Operation  string
	Dependency string
}

func (s spanStep) String() string { return s.Operation + "/" + s.Dependency }

func childrenOf(path *traces.PathResult, parent model.SpanID) []traces.SpanReport {
	var out []traces.SpanReport
	for _, s := range path.Spans {
		if s.Parent != nil && *s.Parent == parent {
			out = append(out, s)
		}
	}
	return out
}

func descendantOf(path *traces.PathResult, ancestor model.SpanID, step spanStep) bool {
	frontier := []model.SpanID{ancestor}
	seen := map[model.SpanID]bool{ancestor: true}
	for len(frontier) > 0 {
		next := frontier[0]
		frontier = frontier[1:]
		for _, c := range childrenOf(path, next) {
			if c.Operation == step.Operation && c.Dependency == step.Dependency {
				return true
			}
			if !seen[c.ID] {
				seen[c.ID] = true
				frontier = append(frontier, c.ID)
			}
		}
	}
	return false
}

// followChain walks parent -> child steps from the single root.
func followChain(path *traces.PathResult, root spanStep, steps []spanStep) (model.SpanID, verdict) {
	var roots []traces.SpanReport
	for _, s := range path.Spans {
		if s.Parent == nil {
			roots = append(roots, s)
		}
	}
	if len(roots) != 1 || len(path.Trees) != 1 || path.Trees[0].Orphan {
		return model.SpanID{}, fail("trace_not_single_rooted", "roots=%d trees=%d", len(roots), len(path.Trees))
	}
	cur := roots[0]
	if cur.Operation != root.Operation || cur.Dependency != root.Dependency {
		return model.SpanID{}, fail("root_span_wrong", "root %s/%s want %s", cur.Operation, cur.Dependency, root)
	}
	for _, step := range steps {
		var found *traces.SpanReport
		for _, c := range childrenOf(path, cur.ID) {
			if c.Operation == step.Operation && c.Dependency == step.Dependency {
				c := c
				found = &c
				break
			}
		}
		if found == nil {
			return model.SpanID{}, fail("chain_link_missing", "no child %s under %s/%s", step, cur.Operation, cur.Dependency)
		}
		cur = *found
	}
	return cur.ID, verdict{ok: true}
}

func cleanEdges(path *traces.PathResult) verdict {
	for _, e := range path.Edges {
		switch e.Kind {
		case "missing_parent", "parent_ambiguous", "parent_in_cycle", "cycle", "duplicate_span_id", "multiple_roots", "no_root":
			return fail("causal_edge_issue", "edge issue %s", e.Kind)
		}
	}
	return verdict{ok: true}
}

var (
	stepGatewayRequest = spanStep{"request", ""}
	stepGatewayToAPI   = spanStep{"http.call", "api"}
	stepAPIRequest     = spanStep{"request", ""}
	stepDB             = spanStep{"db.execute", "postgres"}
	stepDependency     = spanStep{"http.call", "dependency"}
	stepUIAction       = spanStep{"ui.action", ""}
	stepUIToGateway    = spanStep{"http.call", "gateway"}
)

func gatewayChain(o journeyObservation) verdict {
	path, v := readyTrace(o, o.DirectTrace)
	if !v.ok {
		return v
	}
	if e := cleanEdges(path); !e.ok {
		return e
	}
	api, v := followChain(path, stepGatewayRequest, []spanStep{stepGatewayToAPI, stepAPIRequest})
	if !v.ok {
		return v
	}
	for _, leaf := range []spanStep{stepDB, stepDependency} {
		if !descendantOf(path, api, leaf) {
			return fail("api_dependency_span_missing", "no %s span under the API request", leaf)
		}
	}
	return pass("trace=%s spans=%d", o.DirectTrace, len(path.Spans))
}

func uiChain(o journeyObservation) verdict {
	path, v := readyTrace(o, o.UITrace)
	if !v.ok {
		return v
	}
	if e := cleanEdges(path); !e.ok {
		return e
	}
	api, v := followChain(path, stepUIAction, []spanStep{stepUIToGateway, stepGatewayRequest, stepGatewayToAPI, stepAPIRequest})
	if !v.ok {
		return v
	}
	for _, leaf := range []spanStep{stepDB, stepDependency} {
		if !descendantOf(path, api, leaf) {
			return fail("api_dependency_span_missing", "no %s span under the API request", leaf)
		}
	}
	return pass("trace=%s spans=%d", o.UITrace, len(path.Spans))
}

// occurrenceOf decodes the occurrence route's answer for one linked error and demands that the product served it.
func occurrenceOf(e observedError) (httpapi.ErrorOccurrenceDetail, verdict) {
	if e.Read.Status != 200 {
		return httpapi.ErrorOccurrenceDetail{}, fail("occurrence_read_refused", "occurrence %s: the route answered %d", e.Occurrence, e.Read.Status)
	}
	var v httpapi.ErrorOccurrenceView
	if err := json.Unmarshal(e.Read.Body, &v); err != nil {
		return httpapi.ErrorOccurrenceDetail{}, fail("occurrence_view_undecodable", "occurrence %s", e.Occurrence)
	}
	if v.Occurrence != e.Occurrence || v.Issue != e.Issue {
		return httpapi.ErrorOccurrenceDetail{}, fail("occurrence_identity_mismatch", "asked for issue %s occurrence %s, answered issue %s occurrence %s", e.Issue, e.Occurrence, v.Issue, v.Occurrence)
	}
	if v.State != httpapi.StateReady || v.Detail == nil {
		return httpapi.ErrorOccurrenceDetail{}, fail("occurrence_not_ready", "occurrence %s state=%s reason=%s", e.Occurrence, v.State, v.Reason)
	}
	return *v.Detail, verdict{ok: true}
}

func errorBuild(o journeyObservation) verdict {
	if len(o.Errors) == 0 {
		return fail("no_web_error_admitted", "no stored error is linked to the UI trace")
	}
	for _, e := range o.Errors {
		d, v := occurrenceOf(e)
		if !v.ok {
			return v
		}
		if d.Build != o.Expected.WebBuild {
			return fail("wrong_build", "error %s carries build %s, want %s", e.Occurrence, d.Build, o.Expected.WebBuild)
		}
	}
	return pass("%d error(s) with build %s", len(o.Errors), o.Expected.WebBuild)
}

func errorTrace(o journeyObservation) verdict {
	if len(o.Errors) == 0 {
		return fail("no_web_error_admitted", "no stored error is linked to the UI trace")
	}
	for _, e := range o.Errors {
		d, v := occurrenceOf(e)
		if !v.ok {
			return v
		}
		if d.Trace != nil && *d.Trace == o.UITrace && d.Span != nil {
			return pass("error %s trace %s", e.Occurrence, o.UITrace)
		}
	}
	return fail("error_not_linked_to_trace", "no stored web error carries trace %s and a span", o.UITrace)
}

func sourceMapUploaded(o journeyObservation) verdict {
	a := o.Artifact
	switch {
	case !a.Uploaded:
		return fail("upload_not_acknowledged", "the build did not return an artifact receipt")
	case a.Build != o.Expected.WebBuild:
		return fail("wrong_build", "uploaded for build %s, want %s", a.Build, o.Expected.WebBuild)
	case len(a.DebugID) != sourceMapChainSize || strings.Trim(a.DebugID, "0123456789abcdef") != "":
		return fail("debug_id_invalid", "debug id %q", a.DebugID)
	case len(a.Artifact) != sourceMapChainSize:
		return fail("artifact_id_invalid", "artifact id %q", a.Artifact)
	case a.HasSourceMapRef:
		return fail("map_reference_shipped", "the shipped bundle still names its source map")
	}
	return pass("build=%s debug=%s artifact=%s", a.Build, a.DebugID, a.Artifact)
}

// mappedFrame is the plan-07 journey row for original error frames: the STORED error of the web build carries frames that
// name the uploaded artifact, and the product's own frame route, asked about exactly those frames, maps the innermost one
// through the uploaded source map to the known source location. Nothing is mapped by the harness.
func mappedFrame(o journeyObservation) verdict {
	var stored *httpapi.ErrorOccurrenceDetail
	var which model.ID
	for _, e := range o.Errors {
		d, v := occurrenceOf(e)
		if !v.ok {
			return v
		}
		if d.Trace != nil && *d.Trace == o.UITrace {
			stored, which = &d, e.Occurrence
			break
		}
	}
	if stored == nil {
		return fail("error_not_linked_to_trace", "no stored web error carries trace %s", o.UITrace)
	}
	if len(stored.Frames) == 0 {
		return fail("stored_error_has_no_frames", "the stored occurrence %s carries no frames", which)
	}
	for i, f := range stored.Frames {
		if f.Artifact != o.Artifact.Artifact {
			return fail("frame_artifact_unbound", "stored frame %d names artifact %q, the build uploaded %q", i, f.Artifact, o.Artifact.Artifact)
		}
	}
	r := o.Frames
	switch {
	case r == nil:
		return fail("frames_not_read", "the frame route was not asked about the stored frames")
	case r.Status != 200:
		return fail("frames_read_refused", "the frame route answered %d", r.Status)
	}
	var view httpapi.FramesView
	if err := json.Unmarshal(r.Body, &view); err != nil {
		return fail("frames_view_undecodable", "the frame route's answer does not decode")
	}
	if view.Build != o.Expected.WebBuild {
		return fail("wrong_build", "frames mapped under build %s, want %s", view.Build, o.Expected.WebBuild)
	}
	if len(view.Frames) != len(stored.Frames) {
		return fail("frames_read_not_the_stored_frames", "asked about %d stored frame(s), answered for %d", len(stored.Frames), len(view.Frames))
	}
	for i, f := range view.Frames {
		s := stored.Frames[i]
		same := f.Original.Artifact == s.Artifact && f.Original.Line == s.Line && (f.Original.Column == nil) == (s.Column == nil) && (s.Column == nil || *f.Original.Column == *s.Column)
		if !same {
			return fail("frames_read_not_the_stored_frames", "frame %d of the answer is not stored frame %d", i, i)
		}
	}
	top := view.Frames[0]
	if top.Reason != "resolved" || top.Resolved == nil {
		return fail(top.Reason, "the innermost stored frame could not be mapped (%s)", top.Reason)
	}
	r0 := top.Resolved
	if r0.Source != o.Expected.ThrowSource || r0.Line != o.Expected.ThrowLine || r0.Column != o.Expected.ThrowColumn {
		return fail("wrong_source_location", "mapped to %s:%d:%d, want %s:%d:%d", r0.Source, r0.Line, r0.Column, o.Expected.ThrowSource, o.Expected.ThrowLine, o.Expected.ThrowColumn)
	}
	if o.Page.Found && stored.Frames[0].Line != o.Page.Line {
		return fail("stored_frame_differs_from_page_error", "the stored innermost frame is at generated line %d, the real browser reported line %d", stored.Frames[0].Line, o.Page.Line)
	}
	return pass("%s:%d:%d build=%s via stored occurrence %s", r0.Source, r0.Line, r0.Column, view.Build, which)
}

// jobViewOf decodes the job route's answer for the expected run and demands that the product served it.
func jobViewOf(o journeyObservation) (httpapi.JobView, verdict) {
	r := o.JobRun
	switch {
	case r == nil:
		return httpapi.JobView{}, fail("no_job_read", "the job route was not asked about run %s", o.Expected.Run)
	case r.Status != 200:
		return httpapi.JobView{}, fail("job_read_refused", "the job route answered %d", r.Status)
	}
	var v httpapi.JobView
	if err := json.Unmarshal(r.Body, &v); err != nil {
		return httpapi.JobView{}, fail("job_view_undecodable", "the job route's answer does not decode")
	}
	if v.State != httpapi.StateReady {
		return httpapi.JobView{}, fail("job_not_ready", "state=%s reason=%s", v.State, v.Reason)
	}
	if v.Run == nil {
		return httpapi.JobView{}, fail("run_missing", "the answer carries no run for %s", o.Expected.Run)
	}
	return v, verdict{ok: true}
}

// jobHistory reads the run through the job view: attempt 1 failed and stays in the record, attempt 2 succeeded, and the run is
// recovered.
func jobHistory(o journeyObservation) verdict {
	v, vd := jobViewOf(o)
	if !vd.ok {
		return vd
	}
	if v.Job != o.Expected.Job || v.Run.ID != o.Expected.Run {
		return fail("job_or_run_differs", "answered job %s run %s, want job %s run %s", v.Job, v.Run.ID, o.Expected.Job, o.Expected.Run)
	}
	byOrdinal := map[uint64]httpapi.AttemptView{}
	for _, a := range v.Run.Attempts {
		if _, dup := byOrdinal[uint64(a.Ordinal)]; dup {
			return fail("duplicate_ordinal", "two attempts share ordinal %d", a.Ordinal)
		}
		byOrdinal[uint64(a.Ordinal)] = a
	}
	if len(byOrdinal) == 0 {
		return fail("no_attempts_admitted", "no attempt for job %s run %s", o.Expected.Job, o.Expected.Run)
	}
	first, ok1 := byOrdinal[1]
	second, ok2 := byOrdinal[2]
	failedTerminal := func(a httpapi.AttemptView) bool {
		return a.Terminal != nil && a.Terminal.State == jobs.AttemptFailed && a.Effective == jobs.AttemptFailed
	}
	succeededTerminal := func(a httpapi.AttemptView) bool {
		return a.Terminal != nil && a.Terminal.State == jobs.AttemptSucceeded && a.Effective == jobs.AttemptSucceeded
	}
	switch {
	case !ok1:
		return fail("attempt_1_missing", "no attempt with ordinal 1")
	case !first.Started || !failedTerminal(first):
		return fail("attempt_1_not_failed", "attempt 1 started=%v effective=%s", first.Started, first.Effective)
	case !ok2:
		return fail("attempt_2_missing", "no attempt with ordinal 2")
	case !second.Started || !succeededTerminal(second):
		return fail("attempt_2_not_succeeded", "attempt 2 started=%v effective=%s", second.Started, second.Effective)
	}
	for ordinal := range byOrdinal {
		if ordinal > 2 {
			return fail("unexpected_extra_attempt", "attempt %d exists", ordinal)
		}
	}
	if first.Terminal.At > second.Terminal.At || first.ObservedAt > second.ObservedAt || first.ID == second.ID {
		return fail("attempt_order_disorder", "attempt 1 ended at %d and attempt 2 at %d", first.Terminal.At, second.Terminal.At)
	}
	if first.Final || !second.Final {
		return fail("final_attempt_wrong", "final flags: attempt 1 %v, attempt 2 %v", first.Final, second.Final)
	}
	if v.Run.Status != jobs.RunRecovered || !v.Run.Recovered || v.Run.AttemptCount != 2 || v.Run.FailedAttempts != 1 {
		return fail("run_not_recovered", "run status=%s recovered=%v attempts=%d failed=%d", v.Run.Status, v.Run.Recovered, v.Run.AttemptCount, v.Run.FailedAttempts)
	}
	return pass("run=%s attempts=%d recovered", o.Expected.Run, len(byOrdinal))
}

func containsAny(raw []byte, needles []string) string {
	for _, n := range needles {
		if n != "" && bytes.Contains(raw, []byte(n)) {
			return n
		}
	}
	return ""
}

func crossOrg(o journeyObservation) verdict {
	// Positive controls first: the authorized reader sees both traces, so a denial below is
	// about the organization and not about a trace that was never admitted.
	for _, trace := range []model.ID{o.DirectTrace, o.UITrace} {
		if _, v := readyTrace(o, trace); !v.ok {
			return fail("positive_control_missing", "%s", v.detail)
		}
	}
	probes := 0
	for _, r := range o.Reads {
		if r.Actor != "reader-b" {
			continue
		}
		if r.Project != o.Expected.Project {
			continue
		}
		probes++
		if r.Status != 403 && r.Status != 404 {
			return fail("cross_org_read_allowed", "reader of org %s got %d for trace %s sending org %s", o.Expected.OtherOrg, r.Status, r.Trace, r.OrgSent)
		}
		var raw map[string]json.RawMessage
		_ = json.Unmarshal(r.Body, &raw)
		if _, leaked := raw["path"]; leaked || bytes.Contains(r.Body, []byte(`"spans"`)) && !bytes.Contains(r.Body, []byte(`"sections"`)) {
			return fail("cross_org_body_leaks_trace", "denial body carries trace data")
		}
	}
	// Both traces, each with the wrong org's own id and with the owning org's id.
	if probes < 4 {
		return fail("cross_org_not_probed", "%d probes, want 4", probes)
	}
	return pass("%d denied probes", probes)
}

func canariesAbsent(o journeyObservation) verdict {
	for _, want := range o.Expected.Canaries {
		var flow *canaryFlow
		for i := range o.Flows {
			if o.Flows[i].Canary == want {
				flow = &o.Flows[i]
			}
		}
		if flow == nil || len(flow.Reached) == 0 {
			return fail("canary_never_flowed", "canary %s was not shown to reach the applications", want)
		}
	}
	if len(o.Leaks) != 0 {
		l := o.Leaks[0]
		return fail("canary_present", "canary %s found in %s (%d hit(s))", l.Canary, l.Where, len(o.Leaks))
	}
	return pass("%d canaries flowed, none stored", len(o.Expected.Canaries))
}

var sqlWords = []string{"SELECT ", "INSERT ", "select ", "insert ", "FROM catalog", "FROM orders"}

func dbSpanSafe(o journeyObservation) verdict {
	seen := 0
	for _, trace := range []model.ID{o.DirectTrace, o.UITrace} {
		path, v := readyTrace(o, trace)
		if !v.ok {
			return v
		}
		for _, s := range path.Spans {
			if s.Dependency != "postgres" {
				continue
			}
			seen++
			if s.Operation != "db.execute" {
				return fail("db_span_operation_unsafe", "postgres span with operation %q", s.Operation)
			}
		}
		raw, _ := json.Marshal(path)
		if w := containsAny(raw, sqlWords); w != "" {
			return fail("sql_text_in_trace", "trace view contains %q", w)
		}
	}
	if seen == 0 {
		return fail("no_db_span", "no postgres span was admitted")
	}
	if len(o.UnsafeStorage) != 0 {
		return fail("sql_text_in_storage", "%s", o.UnsafeStorage[0])
	}
	return pass("%d postgres spans carry only db.execute", seen)
}

func replayRow(o journeyObservation) verdict {
	r := o.Replay
	if !r.Attempted {
		return fail("not_attempted", "the real recorder scenario did not run")
	}
	if r.AdmittedChunks == 0 || r.StoredReplayRow == 0 {
		reason := "recorder_chunks_not_admitted"
		if r.RefusedOrLost != "" {
			reason = r.RefusedOrLost
		}
		return fail(reason, "recorder emitted %d chunk(s); %d admitted, %d stored", r.RecorderChunks, r.AdmittedChunks, r.StoredReplayRow)
	}
	return pass("%d replay chunks stored", r.StoredReplayRow)
}

func profileRow(o journeyObservation) verdict {
	p := o.Profile
	if !p.Attempted {
		return fail("not_attempted", "the profile scenario did not run")
	}
	if !p.SDKEnqueues || p.StoredProfile == 0 {
		return fail("sdk_profile_not_delivered", "capability=%s/%s; the SDK profiler returns a local report and enqueues nothing; %d profile rows stored", p.Capability, p.Reason, p.StoredProfile)
	}
	return pass("capability=%s stored=%d", p.Capability, p.StoredProfile)
}

const (
	// runtimeProfileFunction is the named function of the job process the runtime profile must show.
	runtimeProfileFunction = "summarise_catalog"
	// runtimeProfileMethod is the SDK's own capability method (the stored chunk method is the closed runtime_cpu vocabulary).
	runtimeProfileMethod = "python_wall_samples"
)

// runtimeProfileRow: a Python process profiled by the real SDK delivers a profile the product stores, the profile route reads it
// back with the real capability record it is linked to, and it shows the named function.
func runtimeProfileRow(o journeyObservation) verdict {
	p := o.RuntimeProfile
	switch {
	case !p.Attempted:
		return fail("not_attempted", "the runtime profile scenario did not run")
	case p.StoredChunks == 0:
		return fail("runtime_profile_not_stored", "%d capability record(s) stored, no profile chunk", p.StoredCapabilities)
	case p.Read == nil:
		return fail("profile_not_read", "profile %s was not read through the profile route", p.Profile)
	case p.Read.Status != 200:
		return fail("profile_read_refused", "the profile route answered %d", p.Read.Status)
	}
	var resp httpapi.ProfileResponse
	if err := json.Unmarshal(p.Read.Body, &resp); err != nil {
		return fail("profile_view_undecodable", "the profile route's answer does not decode")
	}
	if resp.Profile != p.Profile {
		return fail("profile_identity_mismatch", "asked for profile %s, answered %s", p.Profile, resp.Profile)
	}
	if resp.View == nil {
		return fail("profile_not_ready", "state=%s reason=%s", resp.State, resp.Reason)
	}
	// A sampling profiler that could not see every thread or tick says so: the view is then `incomplete` with the closed reason
	// coverage_incomplete AND the loss it declares. That is the product's truth and is accepted; an incomplete view that declares
	// no loss, any other reason, or any other state is not.
	declaredLoss := resp.View.LossCount > 0 || len(resp.View.Loss) > 0 || resp.View.Truncated
	switch {
	case resp.State == httpapi.StateReady && resp.View.Completeness == "complete":
	case resp.State == httpapi.StateIncomplete && resp.Reason == profiles.ReasonCoverageIncomplete && resp.View.Completeness == "partial" && declaredLoss:
	default:
		return fail("profile_not_ready", "state=%s reason=%s completeness=%s declared_loss=%v", resp.State, resp.Reason, resp.View.Completeness, declaredLoss)
	}
	view := resp.View
	if len(view.Samples) == 0 {
		return fail("profile_has_no_samples", "the stored profile %s has no sample", p.Profile)
	}
	if !slices.ContainsFunc(view.Frames, func(f model.ProfileFrame) bool { return strings.Contains(f.Function, runtimeProfileFunction) }) {
		return fail("profile_misses_the_sampled_function", "no frame of profile %s names %s", p.Profile, runtimeProfileFunction)
	}
	linked := slices.ContainsFunc(view.Capabilities, func(c profiles.CapabilityRecord) bool {
		return c.Value.Signal == model.Profile && c.Value.Status == "supported" && c.Value.Method == runtimeProfileMethod
	})
	if !linked {
		return fail("profile_capability_not_linked", "profile %s names no supported %s capability record", p.Profile, runtimeProfileMethod)
	}
	return pass("profile=%s samples=%d state=%s loss=%d capability=supported/%s", p.Profile, len(view.Samples), resp.State, view.LossCount, runtimeProfileMethod)
}

func idsEqual(o journeyObservation) verdict {
	for _, e := range o.Errors {
		d, v := occurrenceOf(e)
		if !v.ok {
			return v
		}
		if d.Build != o.Expected.WebBuild {
			return fail("build_id_differs", "admitted build %s expected %s", d.Build, o.Expected.WebBuild)
		}
	}
	if o.Artifact.Build != o.Expected.WebBuild {
		return fail("build_id_differs", "uploaded build %s expected %s", o.Artifact.Build, o.Expected.WebBuild)
	}
	jv, vd := jobViewOf(o)
	if !vd.ok {
		return fail("run_id_missing", "%s", vd.detail)
	}
	if jv.Job != o.Expected.Job {
		return fail("job_id_differs", "admitted job %s expected %s", jv.Job, o.Expected.Job)
	}
	if jv.Run.ID != o.Expected.Run {
		return fail("run_id_missing", "answered run %s, expected %s", jv.Run.ID, o.Expected.Run)
	}
	for _, t := range []model.ID{o.DirectTrace, o.UITrace} {
		if _, v := readyTrace(o, t); !v.ok {
			return fail("trace_id_not_admitted", "trace %s: %s", t, v.detail)
		}
	}
	return pass("build=%s job=%s run=%s traces=%s,%s", o.Expected.WebBuild, o.Expected.Job, o.Expected.Run, o.DirectTrace, o.UITrace)
}

func versionsRecorded(o journeyObservation) verdict {
	for _, name := range o.Expected.RequiredVersionIDs {
		if strings.TrimSpace(o.Versions[name]) == "" {
			return fail("version_missing", "no actual version recorded for %s", name)
		}
	}
	return pass("%d components", len(o.Expected.RequiredVersionIDs))
}
