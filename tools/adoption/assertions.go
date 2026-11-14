// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"

	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/jobs"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query"
	"github.com/arynyklas/soundpost/internal/symbolicate"
	"github.com/arynyklas/soundpost/internal/traces"
)

// The decision logic of the journey verifier. Every function here is pure over
// evidence already read: it decides from the product's own answers, never from a
// bare identifier. A trace ID, release ID or job ID that merely echoes back is a
// scope check, not a pass; the pass comes from the spans, hashes, positions and
// attempts the product reports for that ID.

const (
	journeyBadAttemptIDs        = "failed and recovery attempt IDs must be distinct and non-zero"
	journeyReasonAncestry       = "ancestry_unknown"
	journeyReasonFramesUnmapped = "frames_unmapped"
	journeyMaskedText           = "[masked]"
	journeyMinSentinel          = 6
	journeyMaxSentinels         = 32
)

func journeyOK(name JourneyCheckName) JourneyCheck { return JourneyCheck{Name: name, Passed: true} }
func journeyBad(name JourneyCheckName, code JourneyCode, detail string) JourneyCheck {
	return JourneyCheck{Name: name, Code: code, Detail: detail}
}
func journeyCheck(ok bool, name JourneyCheckName, code JourneyCode, detail string) JourneyCheck {
	if ok {
		return journeyOK(name)
	}
	return journeyBad(name, code, detail)
}

// journeyReadCode maps a failed read to its closed code.
func journeyReadCode(err error) JourneyCode {
	switch {
	case errors.Is(err, journeyErrNotFound):
		return JourneyCodeTargetNotFound
	case errors.Is(err, journeyErrDenied):
		return JourneyCodeCredentialDenied
	}
	return JourneyCodeReadFailed
}

func journeyLowerJSON(v any) (string, error) {
	raw, err := json.Marshal(v)
	return strings.ToLower(string(raw)), err
}

// ---------------------------------------------------------------- expectation parsing

func journeyMatchValid(m JourneySpanMatch) bool { return m.Operation != "" || m.Dependency != "" }

func journeyTraceRequest(trace string, w JourneyWindow) (model.ID, query.TimeRange, string) {
	id, err := model.ParseID(trace)
	if err != nil {
		return id, query.TimeRange{}, "trace must be a non-zero 32-hex ID"
	}
	if w.StartNS <= 0 || w.EndNS <= w.StartNS {
		return id, query.TimeRange{}, "window must be a positive half-open range"
	}
	return id, query.TimeRange{Start: model.UnixNano(w.StartNS), End: model.UnixNano(w.EndNS)}, ""
}

type journeyFrontendExpect struct {
	trace                 model.ID
	window                query.TimeRange
	release, build, issue model.ID
	artifact              model.ID
	debugID               string
	debugSHA              model.Hash
	frame                 model.Frame
	original              JourneyOriginalPosition
}

func journeyParseID(label, value string) (model.ID, string) {
	id, err := model.ParseID(value)
	if err != nil {
		return id, label + " must be a non-zero 32-hex ID"
	}
	return id, ""
}

func journeyParseFrontend(l *JourneyFrontendLink) (journeyFrontendExpect, string) {
	var e journeyFrontendExpect
	var bad string
	if e.trace, e.window, bad = journeyTraceRequest(l.Trace, l.Window); bad != "" {
		return e, bad
	}
	for _, p := range []struct {
		label, value string
		into         *model.ID
	}{{"release", l.Release, &e.release}, {"build", l.Build, &e.build}, {"issue", l.Issue, &e.issue}, {"artifact", l.Artifact, &e.artifact}} {
		if *p.into, bad = journeyParseID(p.label, p.value); bad != "" {
			return e, bad
		}
	}
	if len(l.Chain) < 3 {
		return e, "frontend chain must name at least frontend, API and database spans"
	}
	for _, m := range l.Chain {
		if !journeyMatchValid(m) {
			return e, "every chain span needs an operation or alias"
		}
	}
	if strings.TrimSpace(l.DebugID) == "" {
		return e, "debug ID is required"
	}
	e.debugID = l.DebugID
	if e.debugSHA.UnmarshalJSON([]byte(`"`+l.DebugSHA256+`"`)) != nil {
		return e, "debug SHA-256 must be 64 lowercase hex characters"
	}
	if l.Frame.Module == "" || l.Frame.Line == 0 || l.Original.Source == "" || l.Original.Line == 0 {
		return e, "frame module/line and original source/line are required"
	}
	col := l.Frame.Column
	e.frame = model.Frame{Module: l.Frame.Module, Function: l.Frame.Function, Artifact: l.Artifact, Line: l.Frame.Line, Column: &col, InApp: true}
	e.original = l.Original
	return e, ""
}

type journeySchedulerExpect struct {
	job, run, failed, recovery, trace model.ID
}

func journeyParseScheduler(l *JourneySchedulerLink) (journeySchedulerExpect, string) {
	var e journeySchedulerExpect
	var bad string
	if e.job, bad = journeyParseID("job", l.Job); bad != "" {
		return e, bad
	}
	if e.run, bad = journeyParseID("run", l.Run); bad != "" {
		return e, bad
	}
	var err error
	if e.failed, err = model.ParseID(l.FailedAttempt); err != nil {
		return e, journeyBadAttemptIDs
	}
	if e.recovery, err = model.ParseID(l.RecoveryAttempt); err != nil || e.recovery == e.failed {
		return e, journeyBadAttemptIDs
	}
	if l.FailureTrace != "" {
		if e.trace, bad = journeyParseID("failure trace", l.FailureTrace); bad != "" {
			return e, bad
		}
	}
	return e, ""
}

func journeyParseReplay(l *JourneyReplayLink) (model.ID, string) {
	id, bad := journeyParseID("replay", l.Replay)
	if bad != "" {
		return id, bad
	}
	if len(l.Sentinels) == 0 || len(l.Sentinels) > journeyMaxSentinels {
		return id, "at least one sentinel value is required; a privacy check without one is vacuous"
	}
	for _, s := range l.Sentinels {
		if len(s) < journeyMinSentinel {
			return id, "sentinel values must be at least 6 bytes to be meaningful"
		}
	}
	return id, ""
}

type journeyCapabilityExpect struct {
	profile model.ID
	window  JourneyWindow
	expect  JourneyRowStatus
}

func journeyParseCapability(r JourneyCapabilityExpectation) (journeyCapabilityExpect, string) {
	e := journeyCapabilityExpect{window: r.Window, expect: JourneyRowStatus(r.Expect)}
	if e.expect == "" {
		e.expect = JourneyRowExercised
	}
	if e.expect != JourneyRowExercised && e.expect != JourneyRowUnavailable && e.expect != JourneyRowDenied {
		return e, "capability expect must be exercised, unavailable or denied"
	}
	if strings.TrimSpace(r.Name) == "" || r.Runtime == "" || r.Method == "" {
		return e, "capability rows need a name, runtime and method"
	}
	if r.Profile == "" {
		if e.expect == JourneyRowExercised || strings.TrimSpace(r.Reason) == "" {
			return e, "a row without a profile can only be a declared unavailable/denied with a reason"
		}
		return e, ""
	}
	var bad string
	if e.profile, bad = journeyParseID("profile", r.Profile); bad != "" {
		return e, bad
	}
	if r.Window.StartNS <= 0 || r.Window.EndNS <= r.Window.StartNS {
		return e, "profile window must be a positive half-open range"
	}
	return e, ""
}

// ---------------------------------------------------------------- trace analysis

// journeyTraceGate checks that a trace view is the requested one, in this scope,
// and complete enough to decide span questions. The second result says whether
// span analysis may proceed.
func journeyTraceGate(org, project, trace model.ID, view httpapi.TraceView) ([]JourneyCheck, bool) {
	scope := view.Org == org && view.Project == project && view.Trace == trace && (view.Path == nil || view.Path.Trace == trace)
	checks := []JourneyCheck{journeyCheck(scope, JourneyCheckScope, JourneyCodeScopeMismatch, "trace view does not echo the requested org, project and trace")}
	switch {
	case !scope:
		return checks, false
	case view.State == httpapi.StateReady && !view.Partial && view.Path != nil:
		return append(checks, journeyOK(JourneyCheckCompleteness)), true
	case view.Partial || view.State == httpapi.StateIncomplete:
		return append(checks, journeyBad(JourneyCheckCompleteness, JourneyCodeEvidencePartial, "trace spans are partial")), false
	}
	return append(checks, journeyBad(JourneyCheckCompleteness, JourneyCodeViewNotReady, "trace view is not ready")), false
}

type journeyIndex struct {
	spans []traces.SpanReport
	byID  map[model.SpanID][]int
}

func newJourneyIndex(p *traces.PathResult) journeyIndex {
	ix := journeyIndex{spans: p.Spans, byID: make(map[model.SpanID][]int, len(p.Spans))}
	for i, s := range p.Spans {
		ix.byID[s.ID] = append(ix.byID[s.ID], i)
	}
	return ix
}

// parentOf resolves a span's parent by its parent span ID within the one trace
// the view covers. A parent that is missing or recorded more than once is no
// parent: causality is never guessed.
func (ix journeyIndex) parentOf(i int) (int, bool) {
	p := ix.spans[i].Parent
	if p == nil {
		return 0, false
	}
	idxs := ix.byID[*p]
	if len(idxs) != 1 {
		return 0, false
	}
	return idxs[0], true
}

// under reports whether span i is a direct child of an anchor or, when direct is
// false, any descendant of one, following parent IDs only.
func (ix journeyIndex) under(i int, anchors map[int]bool, direct bool) bool {
	for steps := 0; steps <= len(ix.spans); steps++ {
		parent, ok := ix.parentOf(i)
		if !ok {
			return false
		}
		if anchors[parent] {
			return true
		}
		if direct {
			return false
		}
		i = parent
	}
	return false
}

func journeyMatches(s traces.SpanReport, m JourneySpanMatch) bool {
	return (m.Operation == "" || s.Operation == m.Operation) && (m.Kind == "" || s.Kind == m.Kind) && (m.Dependency == "" || s.Dependency == m.Dependency) && (m.Status == "" || s.Status == m.Status)
}

var journeyBadSpanFlags = []string{"open", "end_before_start", "duplicate_id", "in_cycle", "orphan", "incomplete", "cancelled"}

// journeyUsable rejects a span that cannot be evidence of a real operation: it
// never ended, has an impossible duration, shares an ID, or has no usable parent.
func journeyUsable(s traces.SpanReport) bool {
	if !s.Duration.Known {
		return false
	}
	return !slices.ContainsFunc(s.Flags, func(f string) bool { return slices.Contains(journeyBadSpanFlags, f) })
}

// journeyResolve finds the spans matching m that sit under the anchors, and says
// why none does: absent from the trace, present but not linked by parent ID, or
// linked but unusable.
func journeyResolve(ix journeyIndex, m JourneySpanMatch, anchors map[int]bool, direct bool) ([]int, JourneyCode) {
	var matches, linked, usable []int
	for i, s := range ix.spans {
		if !anchors[i] && journeyMatches(s, m) {
			matches = append(matches, i)
		}
	}
	if len(matches) == 0 {
		return nil, JourneyCodeSpanMissing
	}
	for _, i := range matches {
		if ix.under(i, anchors, direct) {
			linked = append(linked, i)
		}
	}
	if len(linked) == 0 {
		return nil, JourneyCodeSpanUnlinked
	}
	for _, i := range linked {
		if journeyUsable(ix.spans[i]) {
			usable = append(usable, i)
		}
	}
	if len(usable) == 0 {
		return nil, JourneyCodeSpanInvalid
	}
	return usable, ""
}

func journeySet(idxs []int) map[int]bool {
	set := make(map[int]bool, len(idxs))
	for _, i := range idxs {
		set[i] = true
	}
	return set
}

// journeyRoots resolves the single request root: a parentless span matching m.
func journeyRoots(ix journeyIndex, m JourneySpanMatch) ([]int, JourneyCheck) {
	var roots []int
	for i, s := range ix.spans {
		if s.Parent == nil && journeyMatches(s, m) {
			roots = append(roots, i)
		}
	}
	switch {
	case len(roots) == 0:
		return nil, journeyBad(JourneyCheckRoot, JourneyCodeRootMissing, "no parentless span matches the expected request root")
	case len(roots) > 1:
		return nil, journeyBad(JourneyCheckRoot, JourneyCodeRootAmbiguous, "more than one parentless span matches the expected request root")
	case !journeyUsable(ix.spans[roots[0]]):
		return nil, journeyBad(JourneyCheckRoot, JourneyCodeSpanInvalid, "the request root span is open, invalid or duplicated")
	}
	return roots, journeyOK(JourneyCheckRoot)
}

// journeyClockCheck fails on a CERTAIN clock contradiction of a chosen span:
// inside one clock domain a child cannot start before or end after its parent.
// Skew within declared cross-domain uncertainty is not certain and is accepted:
// wall clocks never reorder causality, the parent edge decides.
func journeyClockCheck(p *traces.PathResult, chosen map[model.SpanID]bool) JourneyCheck {
	for _, issue := range p.Clock {
		if issue.Certain && chosen[issue.Span] {
			return journeyBad(JourneyCheckClock, JourneyCodeClockContradiction, "a verified span contradicts its parent's clock ("+issue.Kind+")")
		}
	}
	return journeyOK(JourneyCheckClock)
}

func journeyAssertGateway(link *JourneyGatewayLink, org, project, trace model.ID, view httpapi.TraceView) ([]JourneyCheck, []JourneyRow) {
	checks, ok := journeyTraceGate(org, project, trace, view)
	if !ok {
		return checks, nil
	}
	ix := newJourneyIndex(view.Path)
	roots, rootCheck := journeyRoots(ix, link.Root)
	checks = append(checks, rootCheck)
	if !rootCheck.Passed {
		return checks, nil
	}
	rootSet := journeySet(roots)
	chosen := map[model.SpanID]bool{ix.spans[roots[0]].ID: true}
	var rows []JourneyRow
	for _, dep := range link.Dependencies {
		found, code := journeyResolve(ix, dep.Span, rootSet, false)
		if code != "" {
			checks = append(checks, journeyBad(JourneyCheckDependency, code, "required dependency child span of the request is not evidence: "+string(code)))
			continue
		}
		checks = append(checks, journeyOK(JourneyCheckDependency))
		for _, i := range found {
			chosen[ix.spans[i].ID] = true
		}
		if dep.ThirdPartyInternals == nil {
			continue
		}
		if strings.TrimSpace(dep.ThirdPartyInternals.Reason) == "" {
			checks = append(checks, journeyBad(JourneyCheckInternals, JourneyCodeInternalsReason, "inaccessible third-party internals need a stated reason"))
			continue
		}
		checks = append(checks, journeyOK(JourneyCheckInternals))
		below := false
		depSet := journeySet(found)
		for i := range ix.spans {
			below = below || !depSet[i] && ix.under(i, depSet, false)
		}
		if below {
			rows = append(rows, JourneyRow{Name: dep.Name, Basis: JourneyBasisObserved, Status: JourneyRowExercised, Reason: "spans below the dependency are present in the trace"})
		} else {
			rows = append(rows, JourneyRow{Name: dep.Name, Basis: JourneyBasisDeclared, Status: JourneyRowUnavailable, Reason: dep.ThirdPartyInternals.Reason})
		}
	}
	return append(checks, journeyClockCheck(view.Path, chosen)), rows
}

// journeyAssertChain checks frontend -> API -> DB: element 0 is the parentless
// request root and each next element a DIRECT child (by parent span ID) of one
// resolved for the element before it.
func journeyAssertChain(chain []JourneySpanMatch, org, project, trace model.ID, view httpapi.TraceView) []JourneyCheck {
	checks, ok := journeyTraceGate(org, project, trace, view)
	if !ok {
		return checks
	}
	ix := newJourneyIndex(view.Path)
	roots, rootCheck := journeyRoots(ix, chain[0])
	checks = append(checks, rootCheck)
	if !rootCheck.Passed {
		return checks
	}
	chosen := map[model.SpanID]bool{ix.spans[roots[0]].ID: true}
	anchors := journeySet(roots)
	for _, m := range chain[1:] {
		found, code := journeyResolve(ix, m, anchors, true)
		if code != "" {
			return append(checks, journeyBad(JourneyCheckDependency, code, "chain span is not a direct child of the previous hop: "+string(code)))
		}
		checks = append(checks, journeyOK(JourneyCheckDependency))
		for _, i := range found {
			chosen[ix.spans[i].ID] = true
		}
		anchors = journeySet(found)
	}
	return append(checks, journeyClockCheck(view.Path, chosen))
}

// ---------------------------------------------------------------- release and source map

func journeyAssertRelease(exp journeyFrontendExpect, org, project model.ID, view httpapi.ReleaseView) []JourneyCheck {
	scope := view.Org == org && view.Project == project
	checks := []JourneyCheck{journeyCheck(scope, JourneyCheckScope, JourneyCodeScopeMismatch, "release view does not echo the requested org and project")}
	if !scope {
		return checks
	}
	// An ancestry the registry cannot fully resolve does not change which build
	// and debug artifacts the release binds.
	ready := view.State == httpapi.StateReady || view.State == httpapi.StateIncomplete && view.Reason == journeyReasonAncestry
	if !ready || view.Release == nil {
		return append(checks, journeyBad(JourneyCheckRelease, JourneyCodeViewNotReady, "release view is not ready"))
	}
	var entries []httpapi.DebugArtifactView
	for _, d := range view.Release.DebugArtifacts {
		if d.ArtifactID == exp.artifact {
			entries = append(entries, d)
		}
	}
	mapped := view.Release.ID == exp.release && view.Release.BuildID == exp.build && len(entries) == 1
	checks = append(checks, journeyCheck(mapped, JourneyCheckRelease, JourneyCodeReleaseNotMapped, "release does not bind this build to exactly one debug artifact of the expected artifact ID"))
	if !mapped {
		return checks
	}
	return append(checks, journeyCheck(entries[0].DebugID == exp.debugID && entries[0].SHA256 == exp.debugSHA, JourneyCheckDebugHash, JourneyCodeDebugHashMismatch, "the release's artifact debug ID or hash is not the expected one"))
}

func journeyAssertFrames(exp journeyFrontendExpect, org, project model.ID, view httpapi.FramesView) []JourneyCheck {
	scope := view.Org == org && view.Project == project && view.Build == exp.build
	checks := []JourneyCheck{journeyCheck(scope, JourneyCheckScope, JourneyCodeScopeMismatch, "frames view does not echo the requested org, project and build")}
	if !scope {
		return checks
	}
	if view.State != httpapi.StateReady && !(view.State == httpapi.StateIncomplete && view.Reason == journeyReasonFramesUnmapped) {
		return append(checks, journeyBad(JourneyCheckFrame, JourneyCodeViewNotReady, "symbolication is not available to this credential"))
	}
	if len(view.Frames) != 1 {
		return append(checks, journeyBad(JourneyCheckFrame, JourneyCodeFrameMismatch, "exactly one frame was requested and exactly one is expected back"))
	}
	fe := view.Frames[0]
	if !reflect.DeepEqual(fe.Original, exp.frame) {
		return append(checks, journeyBad(JourneyCheckFrame, JourneyCodeFrameMismatch, "the answer is about a different frame than the one requested"))
	}
	if fe.Reason != string(symbolicate.Resolved) || fe.Resolved == nil {
		return append(checks, journeyBad(JourneyCheckFrame, JourneyCodeFrameNotInBuild, "the frame is not mapped by this build's artifact: "+fe.Reason))
	}
	exact := fe.Resolved.Source == exp.original.Source && fe.Resolved.Line == exp.original.Line && fe.Resolved.Column == exp.original.Column && (exp.original.Function == "" || fe.Resolved.Function == exp.original.Function)
	checks = append(checks, journeyCheck(exact, JourneyCheckFrame, JourneyCodeFrameMismatch, "the mapped position is not exactly the expected original source position"))
	return append(checks, journeyCheck(fe.MapSHA256 != nil && *fe.MapSHA256 == exp.debugSHA, JourneyCheckDebugHash, JourneyCodeDebugHashMismatch, "the symbolicator used a map whose hash is not the expected one"))
}

func journeySectionReady(sections []httpapi.ViewSection, name string) bool {
	return slices.ContainsFunc(sections, func(s httpapi.ViewSection) bool { return s.Name == name && s.State == httpapi.StateReady })
}

func journeyAssertIssue(exp journeyFrontendExpect, org, project model.ID, view httpapi.IssueView) []JourneyCheck {
	scope := view.Org == org && view.Project == project && view.Issue == exp.issue
	checks := []JourneyCheck{journeyCheck(scope, JourneyCheckScope, JourneyCodeScopeMismatch, "issue view does not echo the requested org, project and issue")}
	if !scope {
		return checks
	}
	// The committed route reports an issue as incomplete/occurrence-detail even
	// when its grouping and evidence sections are fully ready.
	ready := view.State == httpapi.StateReady || view.State == httpapi.StateIncomplete && view.Reason == httpapi.ReasonOccurrenceDetail
	if !ready || view.Grouping == nil || !journeySectionReady(view.Sections, "grouping") || !journeySectionReady(view.Sections, "evidence") {
		return append(checks, journeyBad(JourneyCheckErrorMap, JourneyCodeViewNotReady, "issue evidence is not available to this credential"))
	}
	mapped := slices.ContainsFunc(view.Occurrences, func(o httpapi.OccurrenceEvidenceView) bool {
		return o.BuildID != nil && *o.BuildID == exp.build && o.ReleaseID != nil && *o.ReleaseID == exp.release && o.Ancestry == "known"
	})
	return append(checks, journeyCheck(mapped, JourneyCheckErrorMap, JourneyCodeErrorNotMapped, "no stored occurrence of the issue is mapped to the expected build and release with known ancestry"))
}

// journeyAssertLocalMap cross-checks the expectation against the operator's own
// build output: the map must hash to the expected debug hash and place the
// generated frame exactly at the expected original position. Without a supplied
// map nothing is claimed; the result is a declared-unavailable row.
func journeyAssertLocalMap(link *JourneyFrontendLink) ([]JourneyCheck, []JourneyRow) {
	if len(link.MapBytes) == 0 {
		return nil, []JourneyRow{{Name: "local_build_map", Basis: JourneyBasisDeclared, Status: JourneyRowUnavailable, Reason: "no local build map supplied; the expected position was not cross-checked against the build"}}
	}
	id, err := journeyDecodeMap(link.MapBytes)
	if err != nil {
		return []JourneyCheck{journeyBad(JourneyCheckLocalMap, JourneyCodeLocalMapInconsistent, "the supplied build map cannot be decoded")}, nil
	}
	if id.SHA256 != link.DebugSHA256 {
		return []JourneyCheck{journeyBad(JourneyCheckLocalMap, JourneyCodeLocalMapInconsistent, "the supplied build map does not hash to the expected debug hash")}, nil
	}
	pos, found, err := id.Map.Lookup(link.Frame.Line, link.Frame.Column)
	exact := err == nil && found && pos.SourceID == link.Original.Source && pos.Line == link.Original.Line && pos.Column == link.Original.Column
	return []JourneyCheck{journeyCheck(exact, JourneyCheckLocalMap, JourneyCodeLocalMapInconsistent, "the supplied build map does not place the frame at the expected original position")}, nil
}

// ---------------------------------------------------------------- scheduler / attempts

func journeyAssertScheduler(exp journeySchedulerExpect, org, project model.ID, view httpapi.JobView) []JourneyCheck {
	scope := view.Org == org && view.Project == project && view.Job == exp.job
	checks := []JourneyCheck{journeyCheck(scope, JourneyCheckScope, JourneyCodeScopeMismatch, "job view does not echo the requested org, project and job")}
	switch {
	case !scope:
		return checks
	case view.Erased || view.Reason == httpapi.ReasonJobHistoryErased:
		return append(checks, journeyBad(JourneyCheckFailed, JourneyCodeHistoryErased, "the job's attempt history is reported erased"))
	case view.State != httpapi.StateReady && !(view.State == httpapi.StateIncomplete && view.Reason == httpapi.ReasonJobEvidenceIncomplete), !journeySectionReady(view.Sections, "attempts"):
		return append(checks, journeyBad(JourneyCheckFailed, JourneyCodeViewNotReady, "job attempt history is not available"))
	case view.Run == nil || view.Run.ID != exp.run:
		return append(checks, journeyBad(JourneyCheckFailed, JourneyCodeFailedAttemptMissing, "the run's attempts were not returned"))
	}
	run := view.Run
	seen := map[model.ID]int{}
	for _, a := range run.Attempts {
		seen[a.ID]++
	}
	unique := true
	for _, n := range seen {
		unique = unique && n == 1
	}
	checks = append(checks, journeyCheck(unique, JourneyCheckIdentity, JourneyCodeAttemptIDsNotUnique, "an attempt ID occurs more than once in the run"))

	find := func(id model.ID) *httpapi.AttemptView {
		for i := range run.Attempts {
			if run.Attempts[i].ID == id {
				return &run.Attempts[i]
			}
		}
		return nil
	}
	failed, recovery := find(exp.failed), find(exp.recovery)
	switch {
	case failed == nil:
		checks = append(checks, journeyBad(JourneyCheckFailed, JourneyCodeFailedAttemptMissing, "the failed attempt is not in the run's history"))
	default:
		kept := failed.Terminal != nil && failed.Terminal.State == jobs.AttemptFailed && failed.Effective == jobs.AttemptFailed
		checks = append(checks, journeyCheck(kept, JourneyCheckFailed, JourneyCodeFailedAttemptChanged, "the failed attempt no longer reads as failed"))
	}
	switch {
	case recovery == nil:
		checks = append(checks, journeyBad(JourneyCheckRecovery, JourneyCodeRecoveryMissing, "the recovery attempt is not in the run's history"))
	default:
		ok := recovery.Terminal != nil && recovery.Terminal.State == jobs.AttemptSucceeded && recovery.Effective == jobs.AttemptSucceeded
		checks = append(checks, journeyCheck(ok, JourneyCheckRecovery, JourneyCodeRecoveryMissing, "the recovery attempt did not succeed"))
	}
	if failed != nil && recovery != nil && failed.Terminal != nil && recovery.Terminal != nil {
		// A retry is a later attempt that starts after the failure ended and
		// ends no earlier than it started.
		ordered := recovery.Ordinal > failed.Ordinal && recovery.ObservedAt >= failed.Terminal.At && recovery.Terminal.At >= recovery.ObservedAt
		checks = append(checks, journeyCheck(ordered, JourneyCheckOrder, JourneyCodeAttemptOrder, "the recovery attempt does not follow the failed attempt in ordinal and time"))
	}
	recoveredRun := run.Status == jobs.RunRecovered && run.Recovered && run.FinalAttempt == exp.recovery && run.FailedAttempts >= 1 && run.AttemptCount == len(run.Attempts) &&
		recovery != nil && recovery.Final && failed != nil && !failed.Final
	checks = append(checks, journeyCheck(recoveredRun, JourneyCheckRun, JourneyCodeRunNotRecovered, "the run is not reported recovered with the recovery attempt as its final attempt"))
	if exp.trace != (model.ID{}) {
		linked := failed != nil && failed.CauseTrace != nil && *failed.CauseTrace == exp.trace
		checks = append(checks, journeyCheck(linked, JourneyCheckCause, JourneyCodeCauseMismatch, "the failed attempt does not link to the expected cause trace"))
	}
	return checks
}

// ---------------------------------------------------------------- replay privacy

func journeyAssertReplay(link *JourneyReplayLink, org, project, replay model.ID, lines []httpapi.ReplayLine) []JourneyCheck {
	for _, l := range lines {
		if l.Type == "not_available" {
			return []JourneyCheck{journeyBad(JourneyCheckReplay, JourneyCodeViewNotReady, "the replay service is not available")}
		}
	}
	var checks []JourneyCheck
	open := len(lines) > 0 && lines[0].Type == "open"
	scope := open && lines[0].Org != nil && *lines[0].Org == org && lines[0].Project != nil && *lines[0].Project == project && lines[0].Replay != nil && *lines[0].Replay == replay
	checks = append(checks, journeyCheck(scope, JourneyCheckScope, JourneyCodeScopeMismatch, "the replay stream does not open on the requested org, project and replay"))

	complete := open && lines[len(lines)-1].Type == "end"
	checkpoints, last := 0, uint64(0)
	for i, l := range lines {
		switch l.Type {
		case "open":
			complete = complete && i == 0
		case "end":
			complete = complete && i == len(lines)-1
		case "checkpoint", "delta":
			if l.Chunk == nil || l.Chunk.Replay != replay || uint64(l.Chunk.Sequence) <= last {
				complete = false
				continue
			}
			last = uint64(l.Chunk.Sequence)
			if l.Type == "checkpoint" {
				checkpoints++
			}
		default:
			complete = false // gap, unsupported, truncated, revoke and error all leave the privacy of the unseen part unproven
		}
	}
	checks = append(checks, journeyCheck(complete && checkpoints > 0, JourneyCheckReplay, JourneyCodeReplayIncomplete, "the replay was not released as an unbroken, ordered stream with a checkpoint"))

	clean := true
	for _, l := range lines {
		if l.Chunk != nil {
			for _, n := range l.Chunk.Nodes {
				clean = clean && (n.Text == "" || n.Text == journeyMaskedText) && (n.Class == "" || n.Class == "masked")
			}
		}
		raw, err := journeyLowerJSON(l)
		if err != nil {
			clean = false
			continue
		}
		for _, s := range link.Sentinels {
			clean = clean && !strings.Contains(raw, strings.ToLower(s))
		}
	}
	return append(checks, journeyCheck(clean, JourneyCheckPrivacy, JourneyCodePrivacyViolation, "released replay content is not fully masked or contains a sentinel value"))
}

// ---------------------------------------------------------------- capabilities

// journeyAssertCapability decides one capability row from the product's own
// capability records and samples. Exercised needs both a supported record and
// samples of that method; a record alone, an unsupported record or no record is
// unavailable; a denied record is denied. The observed status must equal the
// expected one, so neither a missing capability nor an unexpected one passes.
func journeyAssertCapability(row JourneyCapabilityExpectation, exp journeyCapabilityExpect, org, project model.ID, profile *httpapi.ProfileResponse, readErr error) (JourneyCheck, JourneyRow) {
	observed := func(status JourneyRowStatus, reason string) JourneyRow {
		return JourneyRow{Name: row.Name, Basis: JourneyBasisObserved, Status: status, Reason: reason}
	}
	if exp.profile == (model.ID{}) {
		return journeyOK(JourneyCheckCapability), JourneyRow{Name: row.Name, Basis: JourneyBasisDeclared, Status: exp.expect, Reason: row.Reason}
	}
	if readErr != nil {
		return journeyBad(JourneyCheckCapability, journeyReadCode(readErr), "the capability profile could not be read"), observed(JourneyRowUnavailable, "profile_not_readable")
	}
	if profile == nil || profile.Org != org || profile.Project != project || profile.Profile != exp.profile {
		return journeyBad(JourneyCheckCapability, JourneyCodeScopeMismatch, "profile view does not echo the requested org, project and profile"), observed(JourneyRowUnavailable, "profile_not_readable")
	}
	if profile.View == nil || profile.State != httpapi.StateReady && profile.State != httpapi.StateIncomplete {
		return journeyBad(JourneyCheckCapability, JourneyCodeViewNotReady, "the profile is not available"), observed(JourneyRowUnavailable, "profile_not_readable")
	}
	status, reason := JourneyRowUnavailable, "no_capability_record"
	for _, rec := range profile.View.Capabilities {
		c := rec.Value
		if c.Runtime != row.Runtime || c.Method != row.Method || row.OS != "" && c.OS != row.OS || row.Arch != "" && c.Arch != row.Arch {
			continue
		}
		switch {
		case c.Status == "denied":
			status, reason = JourneyRowDenied, "capability_denied"
		case c.Status == "supported" && profile.View.Method == row.Method && len(profile.View.Samples) > 0:
			if status != JourneyRowDenied {
				status, reason = JourneyRowExercised, "capability_supported_with_samples"
			}
		case c.Status == "supported":
			if status == JourneyRowUnavailable {
				reason = "supported_without_samples"
			}
		default:
			if status == JourneyRowUnavailable {
				reason = "capability_" + c.Status
			}
		}
	}
	return journeyCheck(status == exp.expect, JourneyCheckCapability, JourneyCodeCapabilityMismatch, "the observed capability status is not the expected one"), observed(status, reason)
}
