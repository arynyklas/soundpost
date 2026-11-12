// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"soundpost/internal/httpapi"
	"soundpost/internal/model"
	"soundpost/internal/traces"
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

type observedError struct {
	Source model.ID              `json:"source"`
	Record model.ErrorOccurrence `json:"record"`
}

type observedJob struct {
	Source model.ID              `json:"source"`
	Event  model.JobAttemptEvent `json:"event"`
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

type symbolObservation struct {
	Reason   string   `json:"reason"` // symbolicate.Reason, or a harness reason such as "no_page_frame"
	Source   string   `json:"source"`
	LineN    uint32   `json:"line"`
	ColumnN  uint32   `json:"column"`
	Build    model.ID `json:"build"`
	FromPage bool     `json:"generated_position_from_real_page_error"`
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
	Expected      journeyExpected     `json:"expected"`
	DirectTrace   model.ID            `json:"direct_trace"`
	UITrace       model.ID            `json:"ui_trace"`
	Reads         []traceRead         `json:"reads"`
	Errors        []observedError     `json:"errors"`
	Jobs          []observedJob       `json:"jobs"`
	Artifact      artifactObservation `json:"artifact"`
	Symbol        symbolObservation   `json:"symbolication"`
	Flows         []canaryFlow        `json:"canary_flows"`
	Leaks         []leakHit           `json:"canary_leaks"`
	Replay        replayObservation   `json:"replay"`
	Profile       profileObservation  `json:"profile"`
	Versions      map[string]string   `json:"versions"`
	UnsafeStorage []string            `json:"unsafe_storage_hits"`
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

func webErrors(o journeyObservation) []observedError {
	var out []observedError
	for _, e := range o.Errors {
		if e.Source == o.Expected.WebSource {
			out = append(out, e)
		}
	}
	return out
}

func errorBuild(o journeyObservation) verdict {
	errs := webErrors(o)
	if len(errs) == 0 {
		return fail("no_web_error_admitted", "no error record from the web source")
	}
	for _, e := range errs {
		if e.Record.Build != o.Expected.WebBuild {
			return fail("wrong_build", "error %s carries build %s, want %s", e.Record.Occurrence, e.Record.Build, o.Expected.WebBuild)
		}
	}
	return pass("%d error(s) with build %s", len(errs), o.Expected.WebBuild)
}

func errorTrace(o journeyObservation) verdict {
	errs := webErrors(o)
	if len(errs) == 0 {
		return fail("no_web_error_admitted", "no error record from the web source")
	}
	for _, e := range errs {
		if e.Record.Trace != nil && *e.Record.Trace == o.UITrace && e.Record.Span != nil {
			return pass("error %s trace %s", e.Record.Occurrence, o.UITrace)
		}
	}
	return fail("error_not_linked_to_trace", "no admitted web error carries trace %s and a span", o.UITrace)
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

func mappedFrame(o journeyObservation) verdict {
	s := o.Symbol
	if s.Reason != "resolved" {
		return fail(s.Reason, "the generated position could not be mapped (%s)", s.Reason)
	}
	switch {
	case !s.FromPage:
		return fail("generated_position_not_from_page", "the mapped position was not read from the real page error")
	case s.Build != o.Expected.WebBuild:
		return fail("wrong_build", "mapped under build %s, want %s", s.Build, o.Expected.WebBuild)
	case s.Source != o.Expected.ThrowSource || s.LineN != o.Expected.ThrowLine || s.ColumnN != o.Expected.ThrowColumn:
		return fail("wrong_source_location", "mapped to %s:%d:%d, want %s:%d:%d", s.Source, s.LineN, s.ColumnN, o.Expected.ThrowSource, o.Expected.ThrowLine, o.Expected.ThrowColumn)
	}
	return pass("%s:%d:%d build=%s", s.Source, s.LineN, s.ColumnN, s.Build)
}

type attemptFacts struct {
	ordinal  uint64
	started  bool
	failed   bool
	ok       bool
	terminal bool
	startSeq uint64
	endSeq   uint64
}

func jobHistory(o journeyObservation) verdict {
	attempts := map[model.ID]*attemptFacts{}
	var order []model.ID
	for _, j := range o.Jobs {
		e := j.Event
		if e.Job != o.Expected.Job || e.Run != o.Expected.Run {
			continue
		}
		a := attempts[e.Attempt]
		if a == nil {
			a = &attemptFacts{ordinal: uint64(e.Ordinal)}
			attempts[e.Attempt] = a
			order = append(order, e.Attempt)
		}
		if a.ordinal != uint64(e.Ordinal) {
			return fail("attempt_ordinal_inconsistent", "attempt %s has two ordinals", e.Attempt)
		}
		switch e.State {
		case "started":
			a.started, a.startSeq = true, uint64(e.Sequence)
		case "failed":
			a.failed, a.terminal, a.endSeq = true, e.Terminal != nil, uint64(e.Sequence)
		case "succeeded":
			a.ok, a.terminal, a.endSeq = true, e.Terminal != nil, uint64(e.Sequence)
		}
	}
	if len(attempts) == 0 {
		return fail("no_attempts_admitted", "no job attempt for job %s run %s", o.Expected.Job, o.Expected.Run)
	}
	byOrdinal := map[uint64]*attemptFacts{}
	for _, id := range order {
		a := attempts[id]
		if byOrdinal[a.ordinal] != nil {
			return fail("duplicate_ordinal", "two attempt ids share ordinal %d", a.ordinal)
		}
		byOrdinal[a.ordinal] = a
	}
	first, second := byOrdinal[1], byOrdinal[2]
	switch {
	case first == nil:
		return fail("attempt_1_missing", "no attempt with ordinal 1")
	case !first.started || !first.failed || !first.terminal || first.ok:
		return fail("attempt_1_not_failed", "attempt 1 started=%v failed=%v succeeded=%v", first.started, first.failed, first.ok)
	case second == nil:
		return fail("attempt_2_missing", "no attempt with ordinal 2")
	case !second.started || !second.ok || !second.terminal || second.failed:
		return fail("attempt_2_not_succeeded", "attempt 2 started=%v failed=%v succeeded=%v", second.started, second.failed, second.ok)
	}
	for ordinal, a := range byOrdinal {
		if ordinal > 2 {
			return fail("unexpected_extra_attempt", "attempt %d exists", ordinal)
		}
		if a.startSeq >= a.endSeq {
			return fail("attempt_sequence_disorder", "attempt %d started at sequence %d but ended at %d", ordinal, a.startSeq, a.endSeq)
		}
	}
	if first.endSeq >= second.startSeq {
		return fail("attempt_sequence_disorder", "attempt 2 started (sequence %d) before attempt 1 ended (%d)", second.startSeq, first.endSeq)
	}
	return pass("run=%s attempts=%d", o.Expected.Run, len(attempts))
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

func idsEqual(o journeyObservation) verdict {
	for _, e := range webErrors(o) {
		if e.Record.Build != o.Expected.WebBuild {
			return fail("build_id_differs", "admitted build %s expected %s", e.Record.Build, o.Expected.WebBuild)
		}
	}
	if o.Artifact.Build != o.Expected.WebBuild {
		return fail("build_id_differs", "uploaded build %s expected %s", o.Artifact.Build, o.Expected.WebBuild)
	}
	runs := 0
	for _, j := range o.Jobs {
		if j.Event.Run == o.Expected.Run {
			runs++
			if j.Event.Job != o.Expected.Job {
				return fail("job_id_differs", "admitted job %s expected %s", j.Event.Job, o.Expected.Job)
			}
		}
	}
	if runs == 0 {
		return fail("run_id_missing", "no admitted attempt for run %s", o.Expected.Run)
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
