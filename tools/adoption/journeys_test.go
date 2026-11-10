// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"soundpost/internal/httpapi"
	"soundpost/internal/jobs"
	"soundpost/internal/model"
	"soundpost/internal/profiles"
	"soundpost/internal/symbolicate"
	"soundpost/internal/traces"
)

// These tests prove the consumer-side verdict logic of the journey verifier
// against SYNTHETIC evidence: spans analyzed by the real traces.CriticalPath,
// positions looked up by the real sourcemap decoder, attempts reduced by the
// real jobs reducer, all served either in-process or over loopback HTTP. The
// httpapi handlers, authorization and storage are not exercised here (their own
// suites do that), and nothing here is customer evidence.

const (
	jtMs      = int64(1_000_000)
	jtBase    = int64(1_700_000_000_000_000_000)
	jtAlias   = "dep-model"
	jtDBAlias = "dep-db"
	jtRuntime = "rt-synth"
	// The synthetic build map: generated line 5 column 10 maps to src/app.ts
	// line 42 column 7 (VLQ UAyCO = col +10, source 0, line +41, col +7).
	jtMapJSON      = `{"version":3,"file":"bundle.mjs","sources":["src/app.ts"],"names":[],"mappings":";;;;UAyCO"}`
	jtOtherMapJSON = `{"version":3,"file":"bundle.mjs","sources":["src/app.ts"],"names":[],"mappings":";;;;UAyCQ"}`
	jtSentinel     = "SENTINEL-card-4242-4242"
)

func jtID(n byte) model.ID { return model.ID{0: 0xA0, 15: n} }
func jtSpanID(n uint64) model.SpanID {
	var s model.SpanID
	s[7] = byte(n)
	s[0] = 1
	return s
}
func jtDomain(d int) model.ClockDomain {
	return model.ClockDomain{Host: model.ID{0: byte(d), 15: 7}, Boot: model.ID{0: 1}, Runtime: model.ID{0: 2}}
}
func jtStamp(dom int, atMs, uncMs int64) model.TraceClock {
	return model.TraceClock{Wall: model.UnixNano(jtBase + atMs*jtMs), Mono: model.MonoNano(uint64(dom+1)*7_000_000_000_000 + uint64(atMs*jtMs)), Domain: jtDomain(dom), Uncertainty: model.MonoNano(uncMs * jtMs)}
}
func jtSpan(trace model.ID, id, parent uint64, kind, op, alias string, startMs, endMs int64, dom int) model.Span {
	end := jtStamp(dom, endMs, 0)
	s := model.Span{Trace: trace, ID: jtSpanID(id), Kind: kind, Operation: op, Dependency: alias, Start: jtStamp(dom, startMs, 0), End: &end, Status: "ok", SampleProbability: model.FloatBits(math.Float64bits(1)), SampleDecision: "keep"}
	if parent != 0 {
		p := jtSpanID(parent)
		s.Parent = &p
	}
	return s
}

// jtWorld is one synthetic tenant plus every piece of evidence its product
// reads would return. Tests mutate it, then verify.
type jtWorld struct {
	t                                                                             *testing.T
	org, project, otherOrg                                                        model.ID
	gwTrace, feTrace, release, build, issue, artifact, job, run, failed, recovery model.ID
	failTrace, replay, profile, profileDenied                                     model.ID
	spans                                                                         map[model.ID][]model.Span
	traceMut                                                                      func(model.ID, *httpapi.TraceView)
	mapBytes                                                                      []byte
	releaseView                                                                   httpapi.ReleaseView
	issueView                                                                     httpapi.IssueView
	framesFn                                                                      func(httpapi.FramesBody) httpapi.FramesView
	jobEvents                                                                     []model.JobAttemptEvent
	jobMut                                                                        func(*httpapi.JobView)
	replayLines                                                                   []httpapi.ReplayLine
	profileViews                                                                  map[model.ID]httpapi.ProfileResponse
	links                                                                         ExpectedLinks
	calls                                                                         []string
}

func jtHash(raw []byte) model.Hash { return model.HashCanonical(raw) }
func jtU64(n uint64) *model.Uint64 { v := model.Uint64(n); return &v }

func newJTWorld(t *testing.T) *jtWorld {
	t.Helper()
	w := &jtWorld{t: t, org: jtID(1), project: jtID(2), otherOrg: jtID(3), gwTrace: jtID(10), feTrace: jtID(11), release: jtID(12), build: jtID(13), issue: jtID(14), artifact: jtID(15), job: jtID(16), run: jtID(17), failed: jtID(18), recovery: jtID(19), failTrace: jtID(20), replay: jtID(21), profile: jtID(22), profileDenied: jtID(23)}
	w.mapBytes = []byte(jtMapJSON)
	w.spans = map[model.ID][]model.Span{
		w.gwTrace: {
			jtSpan(w.gwTrace, 1, 0, "server", "route.handle", "", 0, 100, 0),
			jtSpan(w.gwTrace, 2, 1, "client", "dep.call", jtAlias, 10, 90, 0),
		},
		w.feTrace: {
			jtSpan(w.feTrace, 1, 0, "client", "ui.action", "", 0, 200, 0),
			jtSpan(w.feTrace, 2, 1, "server", "api.handle", "", 20, 180, 1),
			jtSpan(w.feTrace, 3, 2, "client", "db.query", jtDBAlias, 40, 120, 1),
		},
	}
	sha := jtHash(w.mapBytes)
	w.releaseView = httpapi.ReleaseView{Org: w.org, Project: w.project, State: httpapi.StateReady, Release: &httpapi.ReleaseRecordView{ID: w.release, BuildID: w.build, DebugArtifacts: []httpapi.DebugArtifactView{{ArtifactID: w.artifact, DebugID: "debug-1", SHA256: sha}}}, Parents: []httpapi.ParentView{}, Children: []model.ID{}, Comparisons: []httpapi.ReleaseComparison{}, Sections: []httpapi.ViewSection{{Name: "release", State: httpapi.StateReady}}}
	build, release := w.build, w.release
	// The real evidence route answers an issue as incomplete/occurrence_detail
	// with the grouping and evidence sections ready; mirror that exactly.
	w.issueView = httpapi.IssueView{Org: w.org, Project: w.project, Issue: w.issue, State: httpapi.StateIncomplete, Reason: httpapi.ReasonOccurrenceDetail, Grouping: &httpapi.GroupingView{Version: 1},
		Occurrences: []httpapi.OccurrenceEvidenceView{{OccurrenceID: jtID(30), RecordID: jtID(31), GroupingVersion: 1, BuildID: &build, ReleaseID: &release, Ancestry: "known", Freshness: "fresh"}}, LateHistory: []httpapi.OccurrenceEvidenceView{},
		Sections: []httpapi.ViewSection{{Name: "grouping", State: httpapi.StateReady}, {Name: "evidence", State: httpapi.StateReady}, {Name: "occurrence_detail", State: httpapi.StateNotAvailable, Reason: httpapi.ReasonOccurrenceDetail}}}
	w.framesFn = w.resolveFrames
	w.buildJobEvents()
	w.buildReplay()
	w.profileViews = map[model.ID]httpapi.ProfileResponse{
		w.profile:       w.profileResponse(w.profile, "runtime_cpu", "supported", 3),
		w.profileDenied: w.profileResponse(w.profileDenied, "native_offcpu", "denied", 0),
	}
	win := JourneyWindow{StartNS: jtBase - int64(time.Second), EndNS: jtBase + int64(time.Minute)}
	w.links = ExpectedLinks{
		Gateway: &JourneyGatewayLink{Trace: w.gwTrace.String(), Window: win, Root: JourneySpanMatch{Operation: "route.handle", Kind: "server"}, Dependencies: []JourneyDependency{{Name: "model", Span: JourneySpanMatch{Operation: "dep.call", Kind: "client", Dependency: jtAlias}}}},
		Frontend: &JourneyFrontendLink{Trace: w.feTrace.String(), Window: win,
			Chain:   []JourneySpanMatch{{Operation: "ui.action", Kind: "client"}, {Operation: "api.handle", Kind: "server"}, {Operation: "db.query", Kind: "client", Dependency: jtDBAlias}},
			Release: w.release.String(), Build: w.build.String(), Issue: w.issue.String(), Artifact: w.artifact.String(), DebugID: "debug-1", DebugSHA256: sha.String(),
			Frame: JourneyFrame{Module: "bundle.mjs", Function: "handler", Line: 5, Column: 10}, Original: JourneyOriginalPosition{Source: "src/app.ts", Line: 42, Column: 7}, MapBytes: w.mapBytes},
		Scheduler: &JourneySchedulerLink{Job: w.job.String(), Run: w.run.String(), FailedAttempt: w.failed.String(), RecoveryAttempt: w.recovery.String(), FailureTrace: w.failTrace.String()},
		Replay:    &JourneyReplayLink{Replay: w.replay.String(), Sentinels: []string{jtSentinel}},
		Capabilities: &JourneyCapabilityLink{Rows: []JourneyCapabilityExpectation{
			{Name: "runtime-cpu", Profile: w.profile.String(), Window: win, Runtime: jtRuntime, Method: "runtime_cpu"},
			{Name: "native-offcpu", Profile: w.profileDenied.String(), Window: win, Runtime: jtRuntime, Method: "native_offcpu", Expect: "denied"},
			{Name: "native-cpu", Runtime: jtRuntime, Method: "native_cpu", Expect: "unavailable", Reason: "no native profiler exists for this runtime"},
		}},
	}
	return w
}

// resolveFrames is the symbolicator seam: the real source-map decoder places the
// frame, but only for the build and artifact the map belongs to.
func (w *jtWorld) resolveFrames(body httpapi.FramesBody) httpapi.FramesView {
	view := httpapi.FramesView{Org: body.Org, Project: body.Project, Build: body.Build, Sections: []httpapi.ViewSection{{Name: "symbolication", State: httpapi.StateReady}}}
	for _, f := range body.Frames {
		fe := httpapi.FrameEvidence{Original: f, Reason: string(symbolicate.IdentityMismatch), Source: httpapi.SourceView{State: "withheld", Reason: httpapi.ReasonSourcesNotRequested}}
		id, err := journeyDecodeMap(w.mapBytes)
		if err == nil && body.Build == w.build && f.Artifact == w.artifact.String() && f.Column != nil {
			if pos, ok, lerr := id.Map.Lookup(f.Line, *f.Column); lerr == nil && ok {
				hash := jtHash(w.mapBytes)
				fe.Reason, fe.Resolved, fe.MapSHA256 = string(symbolicate.Resolved), &symbolicate.CodeIdentity{Source: pos.SourceID, Function: pos.Name, Line: pos.Line, Column: pos.Column}, &hash
			}
		}
		view.Frames = append(view.Frames, fe)
	}
	view.State = httpapi.StateReady
	for _, fe := range view.Frames {
		if fe.Reason != string(symbolicate.Resolved) {
			view.State, view.Reason = httpapi.StateIncomplete, "frames_unmapped"
		}
	}
	return view
}

func (w *jtWorld) buildJobEvents() {
	occ := jobs.OccurrenceKey("UTC", model.UnixNano(jtBase), 0)
	sec := int64(time.Second)
	cause := w.failTrace
	ev := func(att model.ID, ord, seq uint64, state string, obs int64, term *int64, withCause bool) model.JobAttemptEvent {
		e := model.JobAttemptEvent{Job: w.job, Run: w.run, Attempt: att, Schedule: occ, Ordinal: model.Uint64(ord), Epoch: model.ID{0x77}, Sequence: model.Uint64(seq), State: state, Observed: model.UnixNano(obs)}
		if term != nil {
			v := model.UnixNano(*term)
			e.Terminal = &v
		}
		if withCause {
			c := cause
			e.CauseTrace = &c
		}
		return e
	}
	t := func(n int64) *int64 { v := jtBase + n*sec; return &v }
	w.jobEvents = []model.JobAttemptEvent{
		ev(w.failed, 1, 1, "started", jtBase, nil, true),
		ev(w.failed, 1, 2, "failed", jtBase, t(10), true),
		ev(w.recovery, 2, 1, "started", jtBase+20*sec, nil, false),
		ev(w.recovery, 2, 2, "succeeded", jtBase+20*sec, t(40), false),
	}
}

// jobView folds the events with the real reducer and shapes the read the way
// the committed job view does.
func (w *jtWorld) jobView() httpapi.JobView {
	w.t.Helper()
	var st jobs.JobState
	for _, e := range w.jobEvents {
		var err error
		if st, err = jobs.Reduce(st, e); err != nil {
			w.t.Fatalf("reduce: %v", err)
		}
	}
	view := httpapi.JobView{Org: w.org, Project: w.project, Job: w.job, State: httpapi.StateReady, Permission: "telemetry.read", Health: &jobs.Health{Complete: true}, Runs: []httpapi.RunView{}, TotalRuns: len(st.Runs), TotalAttempts: len(st.Attempts), Sections: []httpapi.ViewSection{{Name: "attempts", State: httpapi.StateReady}}}
	if run, attempts, ok := st.RunAttempts(w.run); ok {
		rv := httpapi.RunView{ID: run.ID, Occurrence: httpapi.OccurrenceView{Key: run.Occurrence}, Status: run.Status, Recovered: run.Recovered, FirstStarted: run.Started, FinalAttempt: run.Final, AttemptCount: len(run.Attempts), Overlaps: []model.ID{}}
		detail := httpapi.RunDetail{RunView: rv}
		for _, a := range attempts {
			av := httpapi.AttemptView{ID: a.ID, Ordinal: a.Ordinal, Started: a.Started, ObservedAt: a.Observed, Terminal: a.Terminal, Effective: a.Effective(), Corrections: []jobs.AppliedCorrection{}, EventsAccepted: len(a.Events), CauseTrace: a.CauseTrace, CauseError: a.CauseError, Final: a.ID == run.Final}
			if av.Effective == jobs.AttemptFailed {
				detail.FailedAttempts++
			}
			detail.Attempts = append(detail.Attempts, av)
		}
		view.Runs = append(view.Runs, detail.RunView)
		view.Run = &detail
	}
	if w.jobMut != nil {
		w.jobMut(&view)
	}
	return view
}

func (w *jtWorld) buildReplay() {
	org, project, replay := w.org, w.project, w.replay
	chunk := func(seq uint64) *model.ReplayChunk {
		return &model.ReplayChunk{Replay: w.replay, Session: jtID(40), Recorder: "rec-1", Sequence: model.Uint64(seq), CheckpointSequence: 1, PolicyRevision: 1, Clock: jtStamp(0, int64(seq), 0),
			Nodes:  []model.MaskedNode{{ID: 1, Tag: "div"}, {ID: 2, Parent: 1, Tag: "input", Class: "masked", Text: "[masked]"}},
			Events: []model.MaskedEvent{{At: 1, Kind: "input", Node: 2}}}
	}
	w.replayLines = []httpapi.ReplayLine{
		{Type: "open", Org: &org, Project: &project, Replay: &replay, State: httpapi.StateReady},
		{Type: "checkpoint", Sequence: jtU64(1), Chunk: chunk(1)},
		{Type: "delta", Sequence: jtU64(2), Chunk: chunk(2)},
		{Type: "end"},
	}
}

func (w *jtWorld) profileResponse(id model.ID, method, status string, samples int) httpapi.ProfileResponse {
	view := &profiles.ProfileView{Profile: id, Process: jtID(51), Project: w.project, Method: method, Units: "samples", Clock: jtStamp(0, 0, 0), Completeness: "complete", Reasons: []string{},
		Capabilities: []profiles.CapabilityRecord{{ID: jtID(50), Value: model.Capability{Runtime: jtRuntime, Version: "1", Build: "b1", OS: "linux", Arch: "amd64", Signal: model.Profile, Method: method, Status: status, Reason: "synthetic", Clock: jtDomain(0), Expires: 1}}}}
	for i := range samples {
		view.Samples = append(view.Samples, model.ProfileSample{At: model.MonoNano(i + 1), Count: 1, Thread: 1})
	}
	return httpapi.ProfileResponse{Org: w.org, Project: w.project, Profile: id, State: httpapi.StateReady, View: view, Sections: []httpapi.ViewSection{{Name: "profile", State: httpapi.StateReady}}}
}

// jtFake serves the world in-process, enforcing the tenant the way the product
// does: another tenant's IDs are one indistinguishable not-found.
type jtFake struct{ w *jtWorld }

func (f jtFake) scoped(org, project model.ID, call string) error {
	f.w.calls = append(f.w.calls, call)
	if org != f.w.org || project != f.w.project {
		return journeyErrNotFound
	}
	return nil
}
func (f jtFake) Trace(_ context.Context, b httpapi.TraceBody) (httpapi.TraceView, error) {
	if err := f.scoped(b.Org, b.Project, "trace"); err != nil {
		return httpapi.TraceView{}, err
	}
	spans, ok := f.w.spans[b.Trace]
	if !ok {
		return httpapi.TraceView{}, journeyErrNotFound
	}
	view := httpapi.TraceView{Org: b.Org, Project: b.Project, Trace: b.Trace, State: httpapi.StateReady, Sections: []httpapi.ViewSection{{Name: "spans", State: httpapi.StateReady}}}
	path, err := traces.CriticalPath(spans)
	if err != nil {
		view.State, view.Reason = httpapi.StateEmpty, httpapi.ReasonNoSpansInWindow
	} else {
		view.Path = &path
	}
	if f.w.traceMut != nil {
		f.w.traceMut(b.Trace, &view)
	}
	return view, nil
}
func (f jtFake) Frames(_ context.Context, b httpapi.FramesBody) (httpapi.FramesView, error) {
	if err := f.scoped(b.Org, b.Project, "frames"); err != nil {
		return httpapi.FramesView{}, err
	}
	return f.w.framesFn(b), nil
}
func (f jtFake) Release(_ context.Context, b httpapi.ReleaseBody) (httpapi.ReleaseView, error) {
	if err := f.scoped(b.Org, b.Project, "release"); err != nil {
		return httpapi.ReleaseView{}, err
	}
	if b.Release != f.w.release {
		return httpapi.ReleaseView{}, journeyErrNotFound
	}
	return f.w.releaseView, nil
}
func (f jtFake) Issue(_ context.Context, b httpapi.IssueBody) (httpapi.IssueView, error) {
	if err := f.scoped(b.Org, b.Project, "issue"); err != nil {
		return httpapi.IssueView{}, err
	}
	if b.Issue != f.w.issue {
		return httpapi.IssueView{}, journeyErrNotFound
	}
	return f.w.issueView, nil
}
func (f jtFake) Job(_ context.Context, b httpapi.JobViewBody) (httpapi.JobView, error) {
	if err := f.scoped(b.Org, b.Project, "job"); err != nil {
		return httpapi.JobView{}, err
	}
	if b.Job != f.w.job {
		return httpapi.JobView{}, journeyErrNotFound
	}
	return f.w.jobView(), nil
}
func (f jtFake) Replay(_ context.Context, b httpapi.ReplayBody) ([]httpapi.ReplayLine, error) {
	if err := f.scoped(b.Org, b.Project, "replay"); err != nil {
		return nil, err
	}
	if b.Replay != f.w.replay {
		return nil, journeyErrNotFound
	}
	return f.w.replayLines, nil
}
func (f jtFake) Profile(_ context.Context, b httpapi.ProfileBody) (httpapi.ProfileResponse, error) {
	if err := f.scoped(b.Org, b.Project, "profile"); err != nil {
		return httpapi.ProfileResponse{}, err
	}
	p, ok := f.w.profileViews[b.Profile]
	if !ok {
		return httpapi.ProfileResponse{}, journeyErrNotFound
	}
	return p, nil
}

func jtVerify(t *testing.T, w *jtWorld) JourneyReport {
	t.Helper()
	return jtVerifyWith(t, w, jtFake{w})
}
func jtVerifyWith(t *testing.T, w *jtWorld, reader JourneyReader) JourneyReport {
	t.Helper()
	rep, err := VerifyJourneys(context.Background(), JourneyTargets{Org: w.org.String(), Project: w.project.String(), Reader: reader}, w.links)
	if err != nil {
		t.Fatalf("VerifyJourneys: %v", err)
	}
	return rep
}
func jtSection(rep JourneyReport, kind JourneyKind) JourneyResult {
	for _, r := range rep.Results {
		if r.Kind == kind {
			return r
		}
	}
	return JourneyResult{}
}
func jtCodes(rep JourneyReport, kind JourneyKind) []JourneyCode {
	var out []JourneyCode
	for _, c := range jtSection(rep, kind).Checks {
		if !c.Passed {
			out = append(out, c.Code)
		}
	}
	return out
}
func jtWantPass(t *testing.T, rep JourneyReport, kind JourneyKind) {
	t.Helper()
	if s := jtSection(rep, kind); s.Status != JourneyPassed {
		t.Fatalf("%s must pass; failures %v checks %+v", kind, jtCodes(rep, kind), s.Checks)
	}
}
func jtWantFail(t *testing.T, rep JourneyReport, kind JourneyKind, code JourneyCode) {
	t.Helper()
	if s := jtSection(rep, kind); s.Status != JourneyFailed || !slices.Contains(jtCodes(rep, kind), code) {
		t.Fatalf("%s must fail with %s; status %s codes %v", kind, code, s.Status, jtCodes(rep, kind))
	}
	if rep.Passed {
		t.Fatalf("report passed although %s failed", kind)
	}
}

func TestJourneyGoldenSyntheticWorldPasses(t *testing.T) {
	w := newJTWorld(t)
	rep := jtVerify(t, w)
	if !rep.Passed || len(rep.Results) != 5 {
		t.Fatalf("golden world must pass all five sections: %+v", rep)
	}
	for _, kind := range journeyKinds {
		jtWantPass(t, rep, kind)
	}
	pub := JourneyPublicProjection(rep)
	if !pub.AllRequiredSectionsPassed || pub.SectionsFailed != 0 || pub.ChecksFailed != 0 || pub.CustomerAcceptance {
		t.Fatalf("public projection: %+v", pub)
	}
	// Two observed rows exercised/denied plus one declared unavailable; the
	// local map cross-check ran, so it is not an unavailable row.
	if pub.RowsExercised != 1 || pub.RowsDenied != 1 || pub.RowsUnavailable != 1 {
		t.Fatalf("rows: %+v", pub)
	}
}

func TestJourneyFixtureMapIsWhatItClaims(t *testing.T) {
	id, err := journeyDecodeMap([]byte(jtMapJSON))
	if err != nil {
		t.Fatal(err)
	}
	pos, ok, err := id.Map.Lookup(5, 10)
	if err != nil || !ok || pos.SourceID != "src/app.ts" || pos.Line != 42 || pos.Column != 7 {
		t.Fatalf("fixture map position: %+v ok=%v err=%v", pos, ok, err)
	}
}

// ---------------------------------------------------------------- named tests

func TestJourneyRejectsTraceIDWithoutDependencySpan(t *testing.T) {
	cases := []struct {
		name string
		edit func(w *jtWorld)
		want JourneyCode
	}{
		{"only the root span exists", func(w *jtWorld) { w.spans[w.gwTrace] = w.spans[w.gwTrace][:1] }, JourneyCodeSpanMissing},
		{"dependency alias is not the named dependency", func(w *jtWorld) { w.spans[w.gwTrace][1].Dependency = "dep-other" }, JourneyCodeSpanMissing},
		{"dependency span has the wrong kind", func(w *jtWorld) { w.spans[w.gwTrace][1].Kind = "internal" }, JourneyCodeSpanMissing},
		{"dependency span is a second root, not a child", func(w *jtWorld) { w.spans[w.gwTrace][1].Parent = nil }, JourneyCodeSpanUnlinked},
		{"dependency parent span was never recorded", func(w *jtWorld) { p := jtSpanID(99); w.spans[w.gwTrace][1].Parent = &p }, JourneyCodeSpanUnlinked},
		{"dependency span never ended", func(w *jtWorld) {
			s := &w.spans[w.gwTrace][1]
			s.End, s.Status = nil, "incomplete"
		}, JourneyCodeSpanInvalid},
		{"root operation is not the gateway request", func(w *jtWorld) { w.spans[w.gwTrace][0].Operation = "other.handle" }, JourneyCodeRootMissing},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := newJTWorld(t)
			jtWantPass(t, jtVerify(t, w), JourneyGatewayDependency)
			c.edit(w)
			rep := jtVerify(t, w)
			jtWantFail(t, rep, JourneyGatewayDependency, c.want)
		})
	}
}

func TestSourceMapRequiresExactBuildAndFrame(t *testing.T) {
	otherSHA := jtHash([]byte("another map")).String()
	cases := []struct {
		name string
		edit func(w *jtWorld)
		want JourneyCode
	}{
		{"release binds a different debug hash to the artifact", func(w *jtWorld) { w.releaseView.Release.DebugArtifacts[0].SHA256 = jtHash([]byte("another map")) }, JourneyCodeDebugHashMismatch},
		{"release binds a different debug ID", func(w *jtWorld) { w.releaseView.Release.DebugArtifacts[0].DebugID = "debug-2" }, JourneyCodeDebugHashMismatch},
		{"expected hash is not the uploaded map", func(w *jtWorld) { w.links.Frontend.DebugSHA256 = otherSHA }, JourneyCodeDebugHashMismatch},
		{"symbolicator reports a different map hash", func(w *jtWorld) {
			inner := w.framesFn
			w.framesFn = func(b httpapi.FramesBody) httpapi.FramesView {
				v := inner(b)
				h := jtHash([]byte("another map"))
				v.Frames[0].MapSHA256 = &h
				return v
			}
		}, JourneyCodeDebugHashMismatch},
		{"release does not hold the artifact at all", func(w *jtWorld) { w.releaseView.Release.DebugArtifacts = nil }, JourneyCodeReleaseNotMapped},
		{"release belongs to a different build", func(w *jtWorld) { w.releaseView.Release.BuildID = jtID(99) }, JourneyCodeReleaseNotMapped},
		{"frame belongs to a different build", func(w *jtWorld) { w.links.Frontend.Build = jtID(98).String() }, JourneyCodeFrameNotInBuild},
		{"frame cites an artifact of no build", func(w *jtWorld) { w.links.Frontend.Artifact = jtID(97).String() }, JourneyCodeFrameNotInBuild},
		{"frame line has no mapping in the build", func(w *jtWorld) { w.links.Frontend.Frame.Line = 9 }, JourneyCodeFrameNotInBuild},
		{"frame position is off by one column", func(w *jtWorld) { w.links.Frontend.Original.Column++ }, JourneyCodeFrameMismatch},
		{"frame maps to a different source file", func(w *jtWorld) { w.links.Frontend.Original.Source = "src/other.ts" }, JourneyCodeFrameMismatch},
		{"frame maps to a different line", func(w *jtWorld) { w.links.Frontend.Original.Line = 43 }, JourneyCodeFrameMismatch},
		{"symbolicator answers about a different frame", func(w *jtWorld) {
			inner := w.framesFn
			w.framesFn = func(b httpapi.FramesBody) httpapi.FramesView {
				v := inner(b)
				v.Frames[0].Original.Line++
				return v
			}
		}, JourneyCodeFrameMismatch},
		{"local build map disagrees with the expected position", func(w *jtWorld) { w.links.Frontend.MapBytes = []byte(jtOtherMapJSON) }, JourneyCodeLocalMapInconsistent},
		{"error occurrence is mapped to another build", func(w *jtWorld) { w.issueView.Occurrences[0].BuildID = new(jtID(96)) }, JourneyCodeErrorNotMapped},
		{"error occurrence release ancestry is unknown", func(w *jtWorld) { w.issueView.Occurrences[0].Ancestry = "unknown" }, JourneyCodeErrorNotMapped},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := newJTWorld(t)
			jtWantPass(t, jtVerify(t, w), JourneyFrontendAPIDB)
			c.edit(w)
			rep := jtVerify(t, w)
			jtWantFail(t, rep, JourneyFrontendAPIDB, c.want)
		})
	}
}

func TestRetryKeepsFailedAttempt(t *testing.T) {
	cases := []struct {
		name string
		edit func(w *jtWorld)
		want JourneyCode
	}{
		{"failed attempt was erased, only the recovery remains", func(w *jtWorld) {
			w.jobEvents = w.jobEvents[2:]
		}, JourneyCodeFailedAttemptMissing},
		{"retry reused the failed attempt ID and overwrote it", func(w *jtWorld) {
			w.jobMut = func(v *httpapi.JobView) {
				a := v.Run.Attempts[0]
				a.Terminal = &jobs.TerminalResult{State: jobs.AttemptSucceeded, At: v.Run.Attempts[1].Terminal.At}
				a.Effective = jobs.AttemptSucceeded
				v.Run.Attempts = []httpapi.AttemptView{a}
				v.Run.AttemptCount, v.Run.FailedAttempts = 1, 0
			}
		}, JourneyCodeFailedAttemptChanged},
		{"failed attempt was corrected into a success", func(w *jtWorld) {
			w.jobMut = func(v *httpapi.JobView) { v.Run.Attempts[0].Effective = jobs.AttemptSucceeded }
		}, JourneyCodeFailedAttemptChanged},
		{"run lost its recovery attempt", func(w *jtWorld) { w.jobEvents = w.jobEvents[:2] }, JourneyCodeRecoveryMissing},
		{"recovery attempt did not succeed", func(w *jtWorld) {
			w.jobMut = func(v *httpapi.JobView) { v.Run.Attempts[1].Effective = jobs.AttemptFailed }
		}, JourneyCodeRecoveryMissing},
		{"run is not reported recovered", func(w *jtWorld) {
			w.jobMut = func(v *httpapi.JobView) { v.Run.Status, v.Run.Recovered = jobs.RunFailed, false }
		}, JourneyCodeRunNotRecovered},
		{"final attempt is the failed one", func(w *jtWorld) {
			w.jobMut = func(v *httpapi.JobView) { v.Run.FinalAttempt = w.failed }
		}, JourneyCodeRunNotRecovered},
		{"recovery ordinal precedes the failure", func(w *jtWorld) {
			w.jobMut = func(v *httpapi.JobView) { v.Run.Attempts[1].Ordinal = 1 }
		}, JourneyCodeAttemptOrder},
		{"recovery started before the failure ended", func(w *jtWorld) {
			w.jobMut = func(v *httpapi.JobView) { v.Run.Attempts[1].ObservedAt = v.Run.Attempts[0].Terminal.At - 1 }
		}, JourneyCodeAttemptOrder},
		{"history was erased", func(w *jtWorld) {
			w.jobMut = func(v *httpapi.JobView) {
				v.Erased, v.State, v.Reason = true, httpapi.StateEmpty, httpapi.ReasonJobHistoryErased
			}
		}, JourneyCodeHistoryErased},
		{"failure no longer links to its cause trace", func(w *jtWorld) {
			w.jobMut = func(v *httpapi.JobView) { v.Run.Attempts[0].CauseTrace = nil }
		}, JourneyCodeCauseMismatch},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := newJTWorld(t)
			jtWantPass(t, jtVerify(t, w), JourneySchedulerRetry)
			c.edit(w)
			rep := jtVerify(t, w)
			jtWantFail(t, rep, JourneySchedulerRetry, c.want)
		})
	}
}

// ---------------------------------------------------------------- boundaries

func TestJourneyDuplicateAttemptIDsFail(t *testing.T) {
	w := newJTWorld(t)
	w.jobMut = func(v *httpapi.JobView) {
		dup := v.Run.Attempts[0]
		v.Run.Attempts = append(v.Run.Attempts, dup)
		v.Run.AttemptCount = len(v.Run.Attempts)
	}
	jtWantFail(t, jtVerify(t, w), JourneySchedulerRetry, JourneyCodeAttemptIDsNotUnique)

	w = newJTWorld(t)
	w.links.Scheduler.RecoveryAttempt = w.links.Scheduler.FailedAttempt
	rep := jtVerify(t, w)
	jtWantFail(t, rep, JourneySchedulerRetry, JourneyCodeAttemptIDsNotUnique)
	if len(w.calls) == 0 || slices.Contains(w.calls, "job") {
		t.Fatalf("indistinct expected attempt IDs must be refused before any read: %v", w.calls)
	}
}

func TestJourneyParentChildLinkageUsesTraceAndParentID(t *testing.T) {
	// A dependency span that exists in the trace but hangs under an unrelated
	// subtree is not a child of the gateway request.
	w := newJTWorld(t)
	w.spans[w.gwTrace] = []model.Span{
		jtSpan(w.gwTrace, 1, 0, "server", "route.handle", "", 0, 100, 0),
		jtSpan(w.gwTrace, 3, 1, "internal", "unrelated", "", 5, 95, 0),
		jtSpan(w.gwTrace, 2, 3, "client", "dep.call", jtAlias, 10, 90, 0),
	}
	rep := jtVerify(t, w)
	jtWantPass(t, rep, JourneyGatewayDependency) // a grandchild through an intermediate span is still below the request

	w.spans[w.gwTrace] = []model.Span{
		jtSpan(w.gwTrace, 1, 0, "server", "route.handle", "", 0, 100, 0),
		jtSpan(w.gwTrace, 3, 0, "internal", "other.root", "", 5, 95, 0),
		jtSpan(w.gwTrace, 2, 3, "client", "dep.call", jtAlias, 10, 90, 0),
	}
	jtWantFail(t, jtVerify(t, w), JourneyGatewayDependency, JourneyCodeSpanUnlinked)

	// The chain of a frontend request needs DIRECT parent links: the DB span
	// hanging under the frontend root instead of the API span is not the contract.
	w = newJTWorld(t)
	w.spans[w.feTrace][2] = jtSpan(w.feTrace, 3, 1, "client", "db.query", jtDBAlias, 40, 120, 1)
	jtWantFail(t, jtVerify(t, w), JourneyFrontendAPIDB, JourneyCodeSpanUnlinked)

	// A view for a different trace than the one asked about is a scope mismatch,
	// never a pass on the strength of its spans.
	w = newJTWorld(t)
	w.traceMut = func(_ model.ID, v *httpapi.TraceView) { v.Trace = jtID(77); v.Path.Trace = jtID(77) }
	jtWantFail(t, jtVerify(t, w), JourneyGatewayDependency, JourneyCodeScopeMismatch)

	// Duplicate span IDs make the parent edge ambiguous.
	w = newJTWorld(t)
	w.spans[w.gwTrace] = append(w.spans[w.gwTrace], jtSpan(w.gwTrace, 2, 1, "client", "dep.call", jtAlias, 12, 80, 0))
	rep = jtVerify(t, w)
	if jtSection(rep, JourneyGatewayDependency).Status != JourneyFailed {
		t.Fatalf("duplicate span IDs must not pass: %v", jtSection(rep, JourneyGatewayDependency).Checks)
	}
}

func TestJourneyClockOrderingContradictionFails(t *testing.T) {
	// Same clock domain: a child that starts before its parent is a certain
	// contradiction, not skew.
	w := newJTWorld(t)
	w.spans[w.gwTrace] = []model.Span{
		jtSpan(w.gwTrace, 1, 0, "server", "route.handle", "", 20, 100, 0),
		jtSpan(w.gwTrace, 2, 1, "client", "dep.call", jtAlias, 10, 90, 0),
	}
	jtWantFail(t, jtVerify(t, w), JourneyGatewayDependency, JourneyCodeClockContradiction)

	// Child outliving its parent in one domain is the same contradiction.
	w.spans[w.gwTrace] = []model.Span{
		jtSpan(w.gwTrace, 1, 0, "server", "route.handle", "", 0, 100, 0),
		jtSpan(w.gwTrace, 2, 1, "client", "dep.call", jtAlias, 10, 140, 0),
	}
	jtWantFail(t, jtVerify(t, w), JourneyGatewayDependency, JourneyCodeClockContradiction)

	// Across unlike clock domains, skew inside the declared uncertainty is not
	// a certain contradiction: wall clocks never reorder causality.
	w.spans[w.gwTrace] = []model.Span{
		jtSpan(w.gwTrace, 1, 0, "server", "route.handle", "", 20, 100, 0),
		jtSpan(w.gwTrace, 2, 1, "client", "dep.call", jtAlias, 15, 90, 1),
	}
	w.spans[w.gwTrace][1].Start.Uncertainty = model.MonoNano(10 * jtMs)
	jtWantPass(t, jtVerify(t, w), JourneyGatewayDependency)
}

func TestJourneyWrongTenantScopeFails(t *testing.T) {
	w := newJTWorld(t)
	// Reads made under another organization are one not-found for every section.
	rep, err := VerifyJourneys(context.Background(), JourneyTargets{Org: w.otherOrg.String(), Project: w.project.String(), Reader: jtFake{w}}, w.links)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Passed {
		t.Fatal("wrong tenant passed")
	}
	for _, kind := range journeyKinds {
		jtWantFail(t, rep, kind, JourneyCodeTargetNotFound)
	}
	// A response that echoes a different tenant than the one asked is refused
	// even though its content looks right.
	w = newJTWorld(t)
	w.traceMut = func(_ model.ID, v *httpapi.TraceView) { v.Org = w.otherOrg }
	w.jobMut = func(v *httpapi.JobView) { v.Project = jtID(88) }
	w.releaseView.Org = w.otherOrg
	w.issueView.Project = jtID(88)
	inner := w.framesFn
	w.framesFn = func(b httpapi.FramesBody) httpapi.FramesView { v := inner(b); v.Org = w.otherOrg; return v }
	w.replayLines[0].Org = &w.otherOrg
	pr := w.profileViews[w.profile]
	pr.Org = w.otherOrg
	w.profileViews[w.profile] = pr
	rep = jtVerify(t, w)
	for _, kind := range journeyKinds {
		jtWantFail(t, rep, kind, JourneyCodeScopeMismatch)
	}
}

func TestJourneyMissingSectionsFail(t *testing.T) {
	w := newJTWorld(t)
	w.links = ExpectedLinks{}
	rep := jtVerify(t, w)
	if rep.Passed {
		t.Fatal("no expectations must not pass")
	}
	for _, kind := range journeyKinds {
		jtWantFail(t, rep, kind, JourneyCodeExpectationMissing)
	}
	if len(w.calls) != 0 {
		t.Fatalf("no read may be made without an expectation: %v", w.calls)
	}
}

func TestJourneyInvalidExpectationsAreRefusedBeforeReading(t *testing.T) {
	cases := []struct {
		name string
		kind JourneyKind
		edit func(l *ExpectedLinks)
	}{
		{"gateway without dependencies", JourneyGatewayDependency, func(l *ExpectedLinks) { l.Gateway.Dependencies = nil }},
		{"gateway root matches everything", JourneyGatewayDependency, func(l *ExpectedLinks) { l.Gateway.Root = JourneySpanMatch{} }},
		{"gateway window empty", JourneyGatewayDependency, func(l *ExpectedLinks) { l.Gateway.Window = JourneyWindow{} }},
		{"gateway trace not an ID", JourneyGatewayDependency, func(l *ExpectedLinks) { l.Gateway.Trace = "trace" }},
		{"frontend chain shorter than frontend-API-DB", JourneyFrontendAPIDB, func(l *ExpectedLinks) { l.Frontend.Chain = l.Frontend.Chain[:2] }},
		{"frontend hash malformed", JourneyFrontendAPIDB, func(l *ExpectedLinks) { l.Frontend.DebugSHA256 = "abc" }},
		{"frontend without debug ID", JourneyFrontendAPIDB, func(l *ExpectedLinks) { l.Frontend.DebugID = "" }},
		{"scheduler without run", JourneySchedulerRetry, func(l *ExpectedLinks) { l.Scheduler.Run = "" }},
		{"replay without sentinels", JourneyReplayPrivacy, func(l *ExpectedLinks) { l.Replay.Sentinels = nil }},
		{"replay with a trivial sentinel", JourneyReplayPrivacy, func(l *ExpectedLinks) { l.Replay.Sentinels = []string{"a"} }},
		{"capabilities without rows", JourneyRuntimeCapability, func(l *ExpectedLinks) { l.Capabilities.Rows = nil }},
		{"capability expects exercised without a profile", JourneyRuntimeCapability, func(l *ExpectedLinks) { l.Capabilities.Rows[2].Expect = "exercised" }},
		{"capability declared without a reason", JourneyRuntimeCapability, func(l *ExpectedLinks) { l.Capabilities.Rows[2].Reason = "" }},
		{"capability status outside the enum", JourneyRuntimeCapability, func(l *ExpectedLinks) { l.Capabilities.Rows[0].Expect = "passed" }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := newJTWorld(t)
			c.edit(&w.links)
			rep := jtVerify(t, w)
			s := jtSection(rep, c.kind)
			if s.Status != JourneyFailed || len(s.Checks) == 0 {
				t.Fatalf("invalid expectation must fail the section: %+v", s)
			}
			for _, check := range s.Checks {
				// Refused before reading: no read-derived check ran for this section.
				if check.Name != JourneyCheckExpectation {
					t.Fatalf("a read-derived check ran for an invalid expectation: %+v", s.Checks)
				}
			}
			if !slices.Contains(jtCodes(rep, c.kind), JourneyCodeExpectationInvalid) && !slices.Contains(jtCodes(rep, c.kind), JourneyCodeAttemptIDsNotUnique) {
				t.Fatalf("code %v", jtCodes(rep, c.kind))
			}
		})
	}
}

func TestJourneyThirdPartyInternalsAreUnavailableNotInvented(t *testing.T) {
	w := newJTWorld(t)
	w.links.Gateway.Dependencies[0].ThirdPartyInternals = &JourneyThirdPartyInternals{Reason: "provider is not ours to instrument"}
	rep := jtVerify(t, w)
	jtWantPass(t, rep, JourneyGatewayDependency)
	rows := jtSection(rep, JourneyGatewayDependency).Rows
	if len(rows) != 1 || rows[0].Status != JourneyRowUnavailable || rows[0].Basis != JourneyBasisDeclared || rows[0].Reason == "" {
		t.Fatalf("inaccessible internals must be an unavailable row with a reason: %+v", rows)
	}
	pub := JourneyPublicProjection(rep)
	if pub.RowsUnavailable < 1 {
		t.Fatalf("unavailable must be counted as unavailable, not passed evidence: %+v", pub)
	}
	// Unavailable internals never turn a missing dependency into a pass.
	w.spans[w.gwTrace] = w.spans[w.gwTrace][:1]
	jtWantFail(t, jtVerify(t, w), JourneyGatewayDependency, JourneyCodeSpanMissing)
	// The declaration needs a reason.
	w = newJTWorld(t)
	w.links.Gateway.Dependencies[0].ThirdPartyInternals = &JourneyThirdPartyInternals{}
	jtWantFail(t, jtVerify(t, w), JourneyGatewayDependency, JourneyCodeInternalsReason)
	// If the provider's internals actually are in the trace, they are real
	// evidence and are reported exercised rather than as unavailable.
	w = newJTWorld(t)
	w.links.Gateway.Dependencies[0].ThirdPartyInternals = &JourneyThirdPartyInternals{Reason: "declared inaccessible"}
	w.spans[w.gwTrace] = append(w.spans[w.gwTrace], jtSpan(w.gwTrace, 3, 2, "server", "provider.work", "", 20, 80, 0))
	rep = jtVerify(t, w)
	if rows = jtSection(rep, JourneyGatewayDependency).Rows; len(rows) != 1 || rows[0].Status != JourneyRowExercised || rows[0].Basis != JourneyBasisObserved {
		t.Fatalf("present internals: %+v", rows)
	}
}

func TestJourneyPartialAndNotReadyViewsDoNotPass(t *testing.T) {
	cases := []struct {
		name string
		edit func(w *jtWorld)
		kind JourneyKind
		want JourneyCode
	}{
		{"partial trace", func(w *jtWorld) {
			w.traceMut = func(_ model.ID, v *httpapi.TraceView) {
				v.Partial, v.State, v.Reason = true, httpapi.StateIncomplete, httpapi.ReasonSpansPartial
			}
		}, JourneyGatewayDependency, JourneyCodeEvidencePartial},
		{"span source not wired", func(w *jtWorld) {
			w.traceMut = func(_ model.ID, v *httpapi.TraceView) {
				v.State, v.Reason, v.Path = httpapi.StateNotAvailable, httpapi.ReasonSpanSourceNotWired, nil
			}
		}, JourneyGatewayDependency, JourneyCodeViewNotReady},
		{"release registry needs admin", func(w *jtWorld) {
			w.releaseView = httpapi.ReleaseView{Org: w.org, Project: w.project, State: httpapi.StateNotAvailable, Reason: httpapi.ReasonReleaseNeedsAdmin}
		}, JourneyFrontendAPIDB, JourneyCodeViewNotReady},
		{"symbolicator not built", func(w *jtWorld) {
			w.framesFn = func(b httpapi.FramesBody) httpapi.FramesView {
				return httpapi.FramesView{Org: b.Org, Project: b.Project, Build: b.Build, State: httpapi.StateNotAvailable, Reason: httpapi.ReasonSymbolicatorNotBuilt, Frames: []httpapi.FrameEvidence{{Original: b.Frames[0], Reason: httpapi.ReasonSymbolicatorNotBuilt}}}
			}
		}, JourneyFrontendAPIDB, JourneyCodeViewNotReady},
		{"issue evidence needs admin", func(w *jtWorld) {
			w.issueView = httpapi.IssueView{Org: w.org, Project: w.project, Issue: w.issue, State: httpapi.StateNotAvailable, Reason: httpapi.ReasonIssueNeedsAdmin}
		}, JourneyFrontendAPIDB, JourneyCodeViewNotReady},
		{"job service not wired", func(w *jtWorld) {
			w.jobMut = func(v *httpapi.JobView) {
				v.State, v.Reason, v.Run = httpapi.StateNotAvailable, httpapi.ReasonJobServiceNotWired, nil
			}
		}, JourneySchedulerRetry, JourneyCodeViewNotReady},
		{"replay service not wired", func(w *jtWorld) {
			w.replayLines = []httpapi.ReplayLine{{Type: "not_available", State: httpapi.StateNotAvailable, Reason: httpapi.ReasonReplayServiceNotWired}}
		}, JourneyReplayPrivacy, JourneyCodeViewNotReady},
		{"profile service not wired", func(w *jtWorld) {
			p := w.profileViews[w.profile]
			p.State, p.Reason, p.View = httpapi.StateNotAvailable, httpapi.ReasonProfileServiceNotWired, nil
			w.profileViews[w.profile] = p
		}, JourneyRuntimeCapability, JourneyCodeViewNotReady},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := newJTWorld(t)
			c.edit(w)
			jtWantFail(t, jtVerify(t, w), c.kind, c.want)
		})
	}
}

func TestJourneyReplayPrivacy(t *testing.T) {
	cases := []struct {
		name string
		edit func(w *jtWorld)
		want JourneyCode
	}{
		{"sentinel leaked into node text", func(w *jtWorld) { w.replayLines[1].Chunk.Nodes[1].Text = "paid with " + jtSentinel }, JourneyCodePrivacyViolation},
		{"sentinel leaked in another case", func(w *jtWorld) { w.replayLines[2].Chunk.Nodes[0].Class = strings.ToLower(jtSentinel) }, JourneyCodePrivacyViolation},
		{"input text is not masked", func(w *jtWorld) { w.replayLines[1].Chunk.Nodes[1].Text = "visible text" }, JourneyCodePrivacyViolation},
		{"stream ends with a revoke", func(w *jtWorld) { w.replayLines[3] = httpapi.ReplayLine{Type: "revoke"} }, JourneyCodeReplayIncomplete},
		{"stream was truncated", func(w *jtWorld) {
			next := model.Uint64(3)
			w.replayLines[3] = httpapi.ReplayLine{Type: "truncated", Next: &next}
		}, JourneyCodeReplayIncomplete},
		{"stream has a gap", func(w *jtWorld) {
			w.replayLines = append(w.replayLines[:2], httpapi.ReplayLine{Type: "gap", Through: jtU64(5)}, w.replayLines[3])
		}, JourneyCodeReplayIncomplete},
		{"no checkpoint released", func(w *jtWorld) { w.replayLines = []httpapi.ReplayLine{w.replayLines[0], w.replayLines[3]} }, JourneyCodeReplayIncomplete},
		{"chunk of another replay", func(w *jtWorld) { w.replayLines[1].Chunk.Replay = jtID(60) }, JourneyCodeReplayIncomplete},
		{"sequences do not advance", func(w *jtWorld) { w.replayLines[2].Chunk.Sequence = 1 }, JourneyCodeReplayIncomplete},
		{"open line names another replay", func(w *jtWorld) { other := jtID(61); w.replayLines[0].Replay = &other }, JourneyCodeScopeMismatch},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := newJTWorld(t)
			jtWantPass(t, jtVerify(t, w), JourneyReplayPrivacy)
			c.edit(w)
			jtWantFail(t, jtVerify(t, w), JourneyReplayPrivacy, c.want)
		})
	}
}

func TestJourneyCapabilityRows(t *testing.T) {
	// The golden world has exercised, denied and declared-unavailable rows.
	w := newJTWorld(t)
	rows := jtSection(jtVerify(t, w), JourneyRuntimeCapability).Rows
	if len(rows) != 3 || rows[0].Status != JourneyRowExercised || rows[0].Basis != JourneyBasisObserved || rows[1].Status != JourneyRowDenied || rows[1].Basis != JourneyBasisObserved || rows[2].Status != JourneyRowUnavailable || rows[2].Basis != JourneyBasisDeclared {
		t.Fatalf("rows: %+v", rows)
	}
	cases := []struct {
		name string
		edit func(w *jtWorld)
	}{
		{"expected exercised but the runtime denied it", func(w *jtWorld) {
			w.links.Capabilities.Rows[0].Profile = w.profileDenied.String()
			w.links.Capabilities.Rows[0].Method = "native_offcpu"
		}},
		{"capability declared supported but no samples exist", func(w *jtWorld) {
			w.profileViews[w.profile] = w.profileResponse(w.profile, "runtime_cpu", "supported", 0)
		}},
		{"capability record is for another runtime", func(w *jtWorld) { w.links.Capabilities.Rows[0].Runtime = "another-runtime" }},
		{"capability record is for another method", func(w *jtWorld) { w.links.Capabilities.Rows[0].Method = "native_cpu" }},
		{"expected denied but it was exercised", func(w *jtWorld) {
			w.links.Capabilities.Rows[1].Profile = w.profile.String()
			w.links.Capabilities.Rows[1].Method = "runtime_cpu"
		}},
		{"expected unavailable but samples exist", func(w *jtWorld) {
			w.links.Capabilities.Rows[2] = JourneyCapabilityExpectation{Name: "x", Profile: w.profile.String(), Window: w.links.Capabilities.Rows[0].Window, Runtime: jtRuntime, Method: "runtime_cpu", Expect: "unavailable", Reason: "claimed absent"}
		}},
		{"profile unknown in this scope", func(w *jtWorld) { w.links.Capabilities.Rows[0].Profile = jtID(95).String() }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := newJTWorld(t)
			c.edit(w)
			rep := jtVerify(t, w)
			if s := jtSection(rep, JourneyRuntimeCapability); s.Status != JourneyFailed {
				t.Fatalf("must fail: %+v", s)
			}
			if rep.Passed {
				t.Fatal("report passed")
			}
		})
	}
	// An unsupported/error capability record is unavailable, never exercised.
	w = newJTWorld(t)
	w.profileViews[w.profile] = w.profileResponse(w.profile, "runtime_cpu", "unsupported", 0)
	w.links.Capabilities.Rows[0].Expect, w.links.Capabilities.Rows[0].Reason = "unavailable", "runtime lacks a sampler"
	rows = jtSection(jtVerify(t, w), JourneyRuntimeCapability).Rows
	if rows[0].Status != JourneyRowUnavailable || rows[0].Basis != JourneyBasisObserved {
		t.Fatalf("unsupported record: %+v", rows[0])
	}
}

func TestJourneyContextCancellationAbortsWithoutReport(t *testing.T) {
	w := newJTWorld(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	reader := jtCancelReader{jtFake{w}}
	rep, err := VerifyJourneys(ctx, JourneyTargets{Org: w.org.String(), Project: w.project.String(), Reader: reader}, w.links)
	if !errors.Is(err, context.Canceled) || rep.Passed || len(rep.Results) != 0 {
		t.Fatalf("a cancelled verification must be an error, not a verdict: %v %+v", err, rep)
	}
}

type jtCancelReader struct{ jtFake }

func (r jtCancelReader) Trace(ctx context.Context, b httpapi.TraceBody) (httpapi.TraceView, error) {
	return httpapi.TraceView{}, ctx.Err()
}

func TestJourneyTargetsValidation(t *testing.T) {
	w := newJTWorld(t)
	for name, targets := range map[string]JourneyTargets{
		"bad org":            {Org: "x", Project: w.project.String(), Reader: jtFake{w}},
		"zero project":       {Org: w.org.String(), Project: strings.Repeat("0", 32), Reader: jtFake{w}},
		"no evidence source": {Org: w.org.String(), Project: w.project.String()},
		"two sources":        {Org: w.org.String(), Project: w.project.String(), Reader: jtFake{w}, ServerURL: "https://example.invalid"},
		"cleartext remote":   {Org: w.org.String(), Project: w.project.String(), ServerURL: "http://203.0.113.9", Bearer: "token"},
		"empty bearer":       {Org: w.org.String(), Project: w.project.String(), ServerURL: "https://example.invalid", Bearer: ""},
		"bearer whitespace":  {Org: w.org.String(), Project: w.project.String(), ServerURL: "https://example.invalid", Bearer: "a b"},
		"credentialed URL":   {Org: w.org.String(), Project: w.project.String(), ServerURL: "https://user:pw@example.invalid", Bearer: "t"},
		"path in URL":        {Org: w.org.String(), Project: w.project.String(), ServerURL: "https://example.invalid/api", Bearer: "t"},
		"query in URL":       {Org: w.org.String(), Project: w.project.String(), ServerURL: "https://example.invalid/?a=b", Bearer: "t"},
		"file scheme":        {Org: w.org.String(), Project: w.project.String(), ServerURL: "file:///etc/passwd", Bearer: "t"},
	} {
		if _, err := VerifyJourneys(context.Background(), targets, w.links); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

// ---------------------------------------------------------------- public projection

func TestJourneyPublicProjectionIsClosed(t *testing.T) {
	typ := reflect.TypeOf(JourneyPublicSummary{})
	var walk func(reflect.Type, string)
	walk = func(rt reflect.Type, path string) {
		switch rt.Kind() {
		case reflect.Int, reflect.Bool:
		case reflect.String:
			if rt != reflect.TypeOf(JourneyKind("")) && rt != reflect.TypeOf(JourneyCode("")) {
				t.Fatalf("%s: free-form string field in the public shape", path)
			}
		case reflect.Slice:
			walk(rt.Elem(), path+"[]")
		case reflect.Struct:
			for i := range rt.NumField() {
				walk(rt.Field(i).Type, path+"."+rt.Field(i).Name)
			}
		default:
			t.Fatalf("%s: %s is not an allowed public field kind", path, rt.Kind())
		}
	}
	walk(typ, "JourneyPublicSummary")

	// Fill every evidence-derived string with a canary and make every section fail.
	canary := "CANARY-internal.customer.local-10.9.8.7-/srv/private-secret=hunter2"
	w := newJTWorld(t)
	w.links.Gateway.Dependencies[0].Name = canary
	w.links.Gateway.Dependencies[0].ThirdPartyInternals = &JourneyThirdPartyInternals{Reason: canary}
	w.links.Capabilities.Rows[2].Name, w.links.Capabilities.Rows[2].Reason = canary, canary
	w.links.Frontend.Original.Source = canary
	w.spans[w.gwTrace][1].Operation = canary
	w.jobEvents = w.jobEvents[2:]
	w.replayLines[1].Chunk.Nodes[1].Text = canary + jtSentinel
	rep := jtVerify(t, w)
	pub := JourneyPublicProjection(rep)
	raw, err := json.Marshal(pub)
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"CANARY", "customer.local", "10.9.8.7", "/srv/private", "hunter2", jtSentinel, w.gwTrace.String(), w.job.String(), w.org.String(), "src/app.ts", "route.handle", jtAlias} {
		if strings.Contains(string(raw), leak) {
			t.Fatalf("public projection leaked %q: %s", leak, raw)
		}
	}
	if pub.AllRequiredSectionsPassed || pub.SectionsFailed == 0 || pub.CustomerAcceptance || len(pub.FailureCodes) == 0 {
		t.Fatalf("failed sections must show as failed: %+v", pub)
	}
	for _, c := range pub.FailureCodes {
		if !journeyCodes[c.Code] || c.Count <= 0 {
			t.Fatalf("code outside the closed vocabulary: %+v", c)
		}
	}
	// A code or kind smuggled into a private report is dropped, never copied.
	rep.Results[0].Checks = append(rep.Results[0].Checks, JourneyCheck{Name: JourneyCheckRead, Code: JourneyCode(canary)})
	rep.Results = append(rep.Results, JourneyResult{Kind: JourneyKind(canary), Status: JourneyPassed})
	raw, _ = json.Marshal(JourneyPublicProjection(rep))
	if strings.Contains(string(raw), "CANARY") {
		t.Fatalf("smuggled enum copied: %s", raw)
	}
	// Even a fully passing private report never claims customer acceptance.
	if !JourneyPublicProjection(jtVerify(t, newJTWorld(t))).AllRequiredSectionsPassed || JourneyPublicProjection(jtVerify(t, newJTWorld(t))).CustomerAcceptance {
		t.Fatal("synthetic pass must not imply customer acceptance")
	}
}

func TestJourneyPublicProjectionRequiresEverySection(t *testing.T) {
	w := newJTWorld(t)
	rep := jtVerify(t, w)
	rep.Results = rep.Results[:4]
	if pub := JourneyPublicProjection(rep); pub.AllRequiredSectionsPassed {
		t.Fatalf("a report missing a section must not read as all-passed: %+v", pub)
	}
	rep = jtVerify(t, w)
	rep.Results = append(rep.Results, rep.Results[0])
	if pub := JourneyPublicProjection(rep); len(pub.Sections) != 5 {
		t.Fatalf("a duplicated section must not be counted twice: %+v", pub)
	}
}

// ---------------------------------------------------------------- loopback HTTP

// jtServe serves the world over loopback HTTP. Each route decodes its body with
// DisallowUnknownFields exactly as the real routes do, so a request the verifier
// builds that the product would refuse fails here too.
func jtServe(t *testing.T, w *jtWorld, bearer string, hits *atomic.Int32) *httptest.Server {
	t.Helper()
	fake := jtFake{w}
	mux := http.NewServeMux()
	handle := func(path string, out any, call func(ctx context.Context, raw []byte) (any, error)) {
		mux.HandleFunc("POST "+path, func(rw http.ResponseWriter, r *http.Request) {
			if hits != nil {
				hits.Add(1)
			}
			if r.Header.Get("Authorization") != "Bearer "+bearer {
				rw.WriteHeader(http.StatusUnauthorized)
				return
			}
			raw, _ := io.ReadAll(io.LimitReader(r.Body, 65536))
			v, err := call(r.Context(), raw)
			switch {
			case errors.Is(err, journeyErrNotFound):
				rw.WriteHeader(http.StatusNotFound)
				return
			case err != nil:
				rw.WriteHeader(http.StatusBadRequest)
				return
			}
			if lines, ok := v.([]httpapi.ReplayLine); ok {
				for _, l := range lines {
					b, merr := json.Marshal(l)
					if merr != nil {
						rw.WriteHeader(http.StatusInternalServerError)
						return
					}
					rw.Write(append(b, '\n'))
				}
				return
			}
			b, merr := json.Marshal(v)
			if merr != nil {
				rw.WriteHeader(http.StatusInternalServerError)
				return
			}
			rw.Write(b)
		})
	}
	strict := func(raw []byte, v any) error {
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		return d.Decode(v)
	}
	handle("/api/v1/traces/view", nil, func(ctx context.Context, raw []byte) (any, error) {
		var b httpapi.TraceBody
		if err := strict(raw, &b); err != nil {
			return nil, err
		}
		return fake.Trace(ctx, b)
	})
	handle("/api/v1/evidence/frames", nil, func(ctx context.Context, raw []byte) (any, error) {
		var b httpapi.FramesBody
		if err := strict(raw, &b); err != nil {
			return nil, err
		}
		return fake.Frames(ctx, b)
	})
	handle("/api/v1/evidence/release", nil, func(ctx context.Context, raw []byte) (any, error) {
		var b httpapi.ReleaseBody
		if err := strict(raw, &b); err != nil {
			return nil, err
		}
		return fake.Release(ctx, b)
	})
	handle("/api/v1/evidence/issue", nil, func(ctx context.Context, raw []byte) (any, error) {
		var b httpapi.IssueBody
		if err := strict(raw, &b); err != nil {
			return nil, err
		}
		return fake.Issue(ctx, b)
	})
	handle("/api/v1/jobs/view", nil, func(ctx context.Context, raw []byte) (any, error) {
		var b httpapi.JobViewBody
		if err := strict(raw, &b); err != nil {
			return nil, err
		}
		return fake.Job(ctx, b)
	})
	handle("/api/v1/replays/stream", nil, func(ctx context.Context, raw []byte) (any, error) {
		var b httpapi.ReplayBody
		if err := strict(raw, &b); err != nil {
			return nil, err
		}
		return fake.Replay(ctx, b)
	})
	handle("/api/v1/profiles/view", nil, func(ctx context.Context, raw []byte) (any, error) {
		var b httpapi.ProfileBody
		if err := strict(raw, &b); err != nil {
			return nil, err
		}
		return fake.Profile(ctx, b)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestJourneyVerifiesOverLoopbackHTTPWithStrictRequestBodies(t *testing.T) {
	w := newJTWorld(t)
	var hits atomic.Int32
	srv := jtServe(t, w, "synthetic-bearer", &hits)
	rep, err := VerifyJourneys(context.Background(), JourneyTargets{ServerURL: srv.URL, Bearer: "synthetic-bearer", Org: w.org.String(), Project: w.project.String()}, w.links)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range journeyKinds {
		jtWantPass(t, rep, kind)
	}
	if !rep.Passed || hits.Load() < 8 {
		t.Fatalf("passed=%v hits=%d", rep.Passed, hits.Load())
	}
	// A wrong bearer is a closed credential-denied failure that never leaks the token.
	rep, err = VerifyJourneys(context.Background(), JourneyTargets{ServerURL: srv.URL, Bearer: "wrong-bearer", Org: w.org.String(), Project: w.project.String()}, w.links)
	if err != nil || rep.Passed {
		t.Fatalf("wrong bearer: %v passed=%v", err, rep.Passed)
	}
	jtWantFail(t, rep, JourneyGatewayDependency, JourneyCodeCredentialDenied)
	raw, _ := json.Marshal(rep)
	if strings.Contains(string(raw), "wrong-bearer") || strings.Contains(string(raw), "synthetic-bearer") {
		t.Fatalf("bearer leaked into the private report: %s", raw)
	}
	// Another tenant over the wire is the same not-found.
	rep, err = VerifyJourneys(context.Background(), JourneyTargets{ServerURL: srv.URL, Bearer: "synthetic-bearer", Org: w.otherOrg.String(), Project: w.project.String()}, w.links)
	if err != nil || rep.Passed {
		t.Fatalf("other tenant: %v", err)
	}
	jtWantFail(t, rep, JourneyFrontendAPIDB, JourneyCodeTargetNotFound)
}

func TestJourneyHTTPReaderDoesNotFollowRedirectsOrLeakBearer(t *testing.T) {
	var elsewhere atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		elsewhere.Add(1)
		if r.Header.Get("Authorization") != "" {
			t.Error("bearer forwarded to a redirect target")
		}
	}))
	defer other.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		http.Redirect(rw, r, other.URL+"/steal", http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()
	reader, err := newJourneyHTTPReader(redirector.URL, "synthetic-bearer")
	if err != nil {
		t.Fatal(err)
	}
	w := newJTWorld(t)
	if _, err = reader.Release(context.Background(), httpapi.ReleaseBody{Org: w.org, Project: w.project, Release: w.release}); !errors.Is(err, journeyErrFailed) {
		t.Fatalf("redirect must be a failed read: %v", err)
	}
	if elsewhere.Load() != 0 {
		t.Fatal("redirect was followed")
	}
}

func TestJourneyHTTPReaderBoundsAndClassifiesResponses(t *testing.T) {
	status := http.StatusOK
	size := 0
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.WriteHeader(status)
		switch {
		case size < 0:
			rw.Write([]byte("{}"))
		case size > 1000: // valid JSON, so only the size bound can refuse it
			rw.Write([]byte(`{"pad":"` + strings.Repeat("x", size-10) + `"}`)) // size is the exact body length
		default:
			rw.Write([]byte(strings.Repeat("x", size)))
		}
	}))
	defer srv.Close()
	reader, err := newJourneyHTTPReader(srv.URL, "t")
	if err != nil {
		t.Fatal(err)
	}
	w := newJTWorld(t)
	read := func() error {
		_, err := reader.Release(context.Background(), httpapi.ReleaseBody{Org: w.org, Project: w.project, Release: w.release})
		return err
	}
	for _, c := range []struct {
		status int
		size   int
		want   error
	}{{404, 5, journeyErrNotFound}, {401, 5, journeyErrDenied}, {403, 5, journeyErrDenied}, {500, 5, journeyErrFailed}, {200, 5, journeyErrFailed}, {200, -1, nil}, {200, journeyMaxResponseBytes, nil}, {200, journeyMaxResponseBytes + 1, journeyErrFailed}, {200, journeyMaxResponseBytes + 10, journeyErrFailed}} {
		status, size = c.status, c.size
		if err := read(); !errors.Is(err, c.want) {
			t.Fatalf("status %d size %d: %v want %v", c.status, c.size, err, c.want)
		}
	}
	// Error text is fixed: a body that echoes a secret never reaches an error.
	status, size = 500, 0
	srv.Config.Handler = http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.WriteHeader(500)
		rw.Write([]byte("secret=hunter2"))
	})
	if err := read(); err == nil || strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("response body leaked into error: %v", err)
	}
}

// ---------------------------------------------------------------- CLI

func jtGrant(server string) Authorization {
	now := time.Now().UTC()
	return Authorization{GrantID: "synthetic-grant", Authority: "synthetic-operator", ReadOnly: true, NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), MaxEvidenceAgeSeconds: 300, Scopes: []TargetScope{{ID: "journeys", EvidenceURL: server, Collectors: []string{"product-journey-read"}}}}
}

func TestRunJourneysCLIWritesPrivateReportAndClosedSummary(t *testing.T) {
	w := newJTWorld(t)
	srv := jtServe(t, w, "synthetic-bearer", nil)
	inputs, private := t.TempDir(), privateTempDir(t)
	mapPath := filepath.Join(inputs, "build.map")
	if err := os.WriteFile(mapPath, w.mapBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	links := w.links
	front := *links.Frontend
	front.MapBytes, front.MapFile = nil, mapPath
	links.Frontend = &front
	expectedPath, grantPath, summary := filepath.Join(inputs, "expected.json"), filepath.Join(inputs, "grant.json"), filepath.Join(inputs, "public.json")
	if err := writeExclusive(expectedPath, links); err != nil {
		t.Fatal(err)
	}
	if err := writeExclusive(grantPath, jtGrant(srv.URL)); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOUNDPOST_JOURNEY_BEARER", "synthetic-bearer")
	args := []string{"--server", srv.URL, "--org", w.org.String(), "--project", w.project.String(), "--expected", expectedPath, "--authorization", grantPath, "--private-output", private, "--public-summary", summary, "--private-directory-acl-confirmed"}
	if err := runJourneys(context.Background(), args); err != nil {
		t.Fatal(err)
	}
	var pub JourneyPublicSummary
	if err := readInput(summary, &pub); err != nil {
		t.Fatal(err)
	}
	if !pub.AllRequiredSectionsPassed || pub.CustomerAcceptance || len(pub.Sections) != 5 {
		t.Fatalf("summary: %+v", pub)
	}
	var priv JourneyReport
	if err := readInput(filepath.Join(private, "journeys.json"), &priv); err != nil || !priv.Passed || len(priv.Results) != 5 {
		t.Fatalf("private report: %v %+v", err, priv.Passed)
	}
	raw, _ := os.ReadFile(filepath.Join(private, "journeys.json"))
	if strings.Contains(string(raw), "synthetic-bearer") {
		t.Fatal("bearer written to the private report")
	}
	// Outputs are created exclusively: nothing is overwritten.
	if err := runJourneys(context.Background(), args); err == nil {
		t.Fatal("overwrote previous evidence")
	}
}

func TestRunJourneysCLIFailedAcceptanceIsNonzeroButWritesEvidence(t *testing.T) {
	w := newJTWorld(t)
	w.spans[w.gwTrace] = w.spans[w.gwTrace][:1]
	srv := jtServe(t, w, "synthetic-bearer", nil)
	inputs, private := t.TempDir(), privateTempDir(t)
	expectedPath, grantPath, summary := filepath.Join(inputs, "expected.json"), filepath.Join(inputs, "grant.json"), filepath.Join(inputs, "public.json")
	links := w.links
	front := *links.Frontend
	front.MapBytes = nil
	links.Frontend = &front
	if err := writeExclusive(expectedPath, links); err != nil {
		t.Fatal(err)
	}
	if err := writeExclusive(grantPath, jtGrant(srv.URL)); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOUNDPOST_JOURNEY_BEARER", "synthetic-bearer")
	err := runJourneys(context.Background(), []string{"--server", srv.URL, "--org", w.org.String(), "--project", w.project.String(), "--expected", expectedPath, "--authorization", grantPath, "--private-output", private, "--public-summary", summary, "--private-directory-acl-confirmed"})
	if err == nil || !strings.Contains(err.Error(), "journey acceptance failed") {
		t.Fatalf("failed acceptance must be an error: %v", err)
	}
	var pub JourneyPublicSummary
	if readInput(summary, &pub) != nil || pub.AllRequiredSectionsPassed || pub.SectionsFailed != 1 {
		t.Fatalf("summary must record the failure: %+v", pub)
	}
	// Nothing about the no-local-map case is claimed as passed: the row is unavailable.
	if pub.RowsUnavailable < 1 {
		t.Fatalf("missing local map must be an unavailable row: %+v", pub)
	}
}

func TestRunJourneysCLIRefusesWithoutExactAuthorization(t *testing.T) {
	w := newJTWorld(t)
	srv := jtServe(t, w, "synthetic-bearer", nil)
	inputs, private := t.TempDir(), privateTempDir(t)
	expectedPath := filepath.Join(inputs, "expected.json")
	if err := writeExclusive(expectedPath, w.links); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOUNDPOST_JOURNEY_BEARER", "synthetic-bearer")
	now := time.Now().UTC()
	base := jtGrant(srv.URL)
	mutations := map[string]func(a *Authorization){
		"not read-only":         func(a *Authorization) { a.ReadOnly = false },
		"expired":               func(a *Authorization) { a.ExpiresAt = now.Add(-time.Second) },
		"not yet valid":         func(a *Authorization) { a.NotBefore = now.Add(time.Hour) },
		"no authority":          func(a *Authorization) { a.Authority = "" },
		"no scope":              func(a *Authorization) { a.Scopes = nil },
		"another URL":           func(a *Authorization) { a.Scopes[0].EvidenceURL = "http://127.0.0.1:1" },
		"extra collector":       func(a *Authorization) { a.Scopes[0].Collectors = []string{"product-journey-read", "git-current-ref"} },
		"intake collector only": func(a *Authorization) { a.Scopes[0].Collectors = []string{"http-live-evidence"} },
		"duplicate scopes":      func(a *Authorization) { a.Scopes = append(a.Scopes, a.Scopes[0]) },
	}
	for name, mutate := range mutations {
		grant := base
		grant.Scopes = append([]TargetScope(nil), base.Scopes...)
		grant.Scopes[0].Collectors = append([]string(nil), base.Scopes[0].Collectors...)
		mutate(&grant)
		grantPath := filepath.Join(inputs, strings.ReplaceAll(name, " ", "-")+".json")
		if err := writeExclusive(grantPath, grant); err != nil {
			t.Fatal(err)
		}
		summary := filepath.Join(inputs, strings.ReplaceAll(name, " ", "-")+".summary.json")
		err := runJourneys(context.Background(), []string{"--server", srv.URL, "--org", w.org.String(), "--project", w.project.String(), "--expected", expectedPath, "--authorization", grantPath, "--private-output", private, "--public-summary", summary, "--private-directory-acl-confirmed"})
		if err == nil {
			t.Fatalf("%s: accepted", name)
		}
		if _, statErr := os.Stat(summary); statErr == nil {
			t.Fatalf("%s: wrote a summary without authorization", name)
		}
	}
	if entries, _ := os.ReadDir(private); len(entries) != 0 {
		t.Fatalf("private output written without authorization: %v", entries)
	}
	// Missing required flags and an unbounded timeout are refused.
	if err := runJourneys(context.Background(), nil); err == nil {
		t.Fatal("no flags accepted")
	}
	grantPath := filepath.Join(inputs, "ok.json")
	if err := writeExclusive(grantPath, base); err != nil {
		t.Fatal(err)
	}
	if err := runJourneys(context.Background(), []string{"--server", srv.URL, "--org", w.org.String(), "--project", w.project.String(), "--expected", expectedPath, "--authorization", grantPath, "--private-output", private, "--public-summary", filepath.Join(inputs, "t.json"), "--timeout", "2h", "--private-directory-acl-confirmed"}); err == nil {
		t.Fatal("unbounded timeout accepted")
	}
}

// ---------------------------------------------------------------- decision boundaries
// Each case below pins one decision the mutation pass showed must be
// independently enforced (a different check can otherwise mask its absence).

func jtPathSpan(v *httpapi.TraceView, op string) *traces.SpanReport {
	for i := range v.Path.Spans {
		if v.Path.Spans[i].Operation == op {
			return &v.Path.Spans[i]
		}
	}
	return &traces.SpanReport{} // the mutation targets another trace: a scratch span absorbs it
}

func TestJourneySpanEvidenceMustBeUsable(t *testing.T) {
	for _, flag := range []string{"open", "end_before_start", "duplicate_id", "in_cycle", "orphan", "incomplete", "cancelled"} {
		t.Run("dependency flagged "+flag, func(t *testing.T) {
			w := newJTWorld(t)
			w.traceMut = func(_ model.ID, v *httpapi.TraceView) {
				s := jtPathSpan(v, "dep.call")
				s.Flags = append(s.Flags, flag)
			}
			jtWantFail(t, jtVerify(t, w), JourneyGatewayDependency, JourneyCodeSpanInvalid)
		})
		t.Run("request root flagged "+flag, func(t *testing.T) {
			w := newJTWorld(t)
			w.traceMut = func(_ model.ID, v *httpapi.TraceView) {
				s := jtPathSpan(v, "route.handle")
				s.Flags = append(s.Flags, flag)
			}
			jtWantFail(t, jtVerify(t, w), JourneyGatewayDependency, JourneyCodeSpanInvalid)
		})
	}
	// An unknown duration is unusable even with no flag naming why.
	w := newJTWorld(t)
	w.traceMut = func(_ model.ID, v *httpapi.TraceView) { jtPathSpan(v, "dep.call").Duration.Known = false }
	jtWantFail(t, jtVerify(t, w), JourneyGatewayDependency, JourneyCodeSpanInvalid)
	// Flags the analysis uses to describe legitimate shape are not rejected.
	w = newJTWorld(t)
	w.traceMut = func(_ model.ID, v *httpapi.TraceView) {
		s := jtPathSpan(v, "dep.call")
		s.Flags = append(s.Flags, "dependency_boundary", "cross_domain_duration", "async")
	}
	jtWantPass(t, jtVerify(t, w), JourneyGatewayDependency)
}

func TestJourneyTraceGateChecksEveryEcho(t *testing.T) {
	cases := []struct {
		name string
		mut  func(v *httpapi.TraceView)
		want JourneyCode
	}{
		{"only the view trace differs", func(v *httpapi.TraceView) { v.Trace = jtID(77) }, JourneyCodeScopeMismatch},
		{"only the analyzed path trace differs", func(v *httpapi.TraceView) { v.Path.Trace = jtID(77) }, JourneyCodeScopeMismatch},
		{"only the project differs", func(v *httpapi.TraceView) { v.Project = jtID(77) }, JourneyCodeScopeMismatch},
		{"partial flag with a ready state", func(v *httpapi.TraceView) { v.Partial = true }, JourneyCodeEvidencePartial},
		{"ready without an analysis", func(v *httpapi.TraceView) { v.Path = nil }, JourneyCodeViewNotReady},
		{"empty state", func(v *httpapi.TraceView) {
			v.State, v.Reason, v.Path = httpapi.StateEmpty, httpapi.ReasonNoSpansInWindow, nil
		}, JourneyCodeViewNotReady},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := newJTWorld(t)
			w.traceMut = func(_ model.ID, v *httpapi.TraceView) { c.mut(v) }
			rep := jtVerify(t, w)
			jtWantFail(t, rep, JourneyGatewayDependency, c.want)
			jtWantFail(t, rep, JourneyFrontendAPIDB, c.want)
		})
	}
}

func TestJourneyLinkageEdgeCases(t *testing.T) {
	// The DB span hangs under an intermediate span of the API, not directly
	// under the API span: not the frontend -> API -> DB contract.
	w := newJTWorld(t)
	w.spans[w.feTrace] = []model.Span{
		jtSpan(w.feTrace, 1, 0, "client", "ui.action", "", 0, 200, 0),
		jtSpan(w.feTrace, 2, 1, "server", "api.handle", "", 20, 180, 1),
		jtSpan(w.feTrace, 4, 2, "internal", "orm.layer", "", 30, 170, 1),
		jtSpan(w.feTrace, 3, 4, "client", "db.query", jtDBAlias, 40, 120, 1),
	}
	jtWantFail(t, jtVerify(t, w), JourneyFrontendAPIDB, JourneyCodeSpanUnlinked)

	// A parent span ID recorded twice is no parent: causality is not guessed.
	w = newJTWorld(t)
	w.spans[w.gwTrace] = []model.Span{
		jtSpan(w.gwTrace, 1, 0, "server", "route.handle", "", 0, 100, 0),
		jtSpan(w.gwTrace, 2, 1, "internal", "mid", "", 5, 95, 0),
		jtSpan(w.gwTrace, 2, 1, "internal", "mid-again", "", 6, 94, 0),
		jtSpan(w.gwTrace, 3, 2, "client", "dep.call", jtAlias, 10, 90, 0),
	}
	jtWantFail(t, jtVerify(t, w), JourneyGatewayDependency, JourneyCodeSpanUnlinked)

	// Two parentless spans matching the request root: which one is the request?
	w = newJTWorld(t)
	w.spans[w.gwTrace] = append(w.spans[w.gwTrace], jtSpan(w.gwTrace, 5, 0, "server", "route.handle", "", 0, 100, 0))
	jtWantFail(t, jtVerify(t, w), JourneyGatewayDependency, JourneyCodeRootAmbiguous)

	// A certain contradiction on a span the journey does not rely on is not
	// this journey's failure: only the verified spans are held to their parents.
	w = newJTWorld(t)
	w.spans[w.gwTrace] = append(w.spans[w.gwTrace], jtSpan(w.gwTrace, 6, 1, "internal", "unrelated.work", "", 150, 160, 0))
	jtWantPass(t, jtVerify(t, w), JourneyGatewayDependency)
}

func TestJourneyReleaseAndMapEdgeCases(t *testing.T) {
	sameMappings := `{"version":3,"file":"other.mjs","sources":["src/app.ts"],"names":[],"mappings":";;;;UAyCO"}`
	otherLine := `{"version":3,"file":"bundle.mjs","sources":["src/app.ts"],"names":[],"mappings":";;;;UA0CO"}`
	cases := []struct {
		name string
		edit func(w *jtWorld)
		want JourneyCode
	}{
		{"artifact appears twice in the release", func(w *jtWorld) {
			d := w.releaseView.Release.DebugArtifacts[0]
			w.releaseView.Release.DebugArtifacts = append(w.releaseView.Release.DebugArtifacts, d)
		}, JourneyCodeReleaseNotMapped},
		{"a different release was returned", func(w *jtWorld) { w.releaseView.Release.ID = jtID(94) }, JourneyCodeReleaseNotMapped},
		{"frame reason is not resolved although a position is present", func(w *jtWorld) {
			inner := w.framesFn
			w.framesFn = func(b httpapi.FramesBody) httpapi.FramesView {
				v := inner(b)
				v.Frames[0].Reason = string(symbolicate.Unmapped)
				return v
			}
		}, JourneyCodeFrameNotInBuild},
		{"occurrence is mapped to another release", func(w *jtWorld) { w.issueView.Occurrences[0].ReleaseID = new(jtID(93)) }, JourneyCodeErrorNotMapped},
		{"local map has the same mappings but is not the uploaded map", func(w *jtWorld) { w.links.Frontend.MapBytes = []byte(sameMappings) }, JourneyCodeLocalMapInconsistent},
		{"local map hashes as expected but places the frame on another line", func(w *jtWorld) {
			w.links.Frontend.MapBytes = []byte(otherLine)
			w.links.Frontend.DebugSHA256 = jtHash([]byte(otherLine)).String()
		}, JourneyCodeLocalMapInconsistent},
		{"local map is not a source map", func(w *jtWorld) { w.links.Frontend.MapBytes = []byte(`not json`) }, JourneyCodeLocalMapInconsistent},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := newJTWorld(t)
			c.edit(w)
			jtWantFail(t, jtVerify(t, w), JourneyFrontendAPIDB, c.want)
		})
	}
	// Without a local map nothing is claimed about the build; the row says so.
	w := newJTWorld(t)
	w.links.Frontend.MapBytes = nil
	rep := jtVerify(t, w)
	jtWantPass(t, rep, JourneyFrontendAPIDB)
	rows := jtSection(rep, JourneyFrontendAPIDB).Rows
	if len(rows) != 1 || rows[0].Status != JourneyRowUnavailable || rows[0].Basis != JourneyBasisDeclared || rows[0].Reason == "" {
		t.Fatalf("missing local map must be a declared unavailable row: %+v", rows)
	}
}

func TestJourneyAttemptHistoryEdgeCases(t *testing.T) {
	other := jtID(92)
	cases := []struct {
		name string
		mut  func(v *httpapi.JobView)
		want JourneyCode
	}{
		{"failed attempt lost its terminal fact", func(v *httpapi.JobView) { v.Run.Attempts[0].Terminal = nil }, JourneyCodeFailedAttemptChanged},
		{"attempt count disagrees with the attempts returned", func(v *httpapi.JobView) { v.Run.AttemptCount = 5 }, JourneyCodeRunNotRecovered},
		{"failed attempt is also marked final", func(v *httpapi.JobView) { v.Run.Attempts[0].Final = true }, JourneyCodeRunNotRecovered},
		{"recovery attempt is not marked final", func(v *httpapi.JobView) { v.Run.Attempts[1].Final = false }, JourneyCodeRunNotRecovered},
		{"run status is not recovered", func(v *httpapi.JobView) { v.Run.Status = jobs.RunSucceeded }, JourneyCodeRunNotRecovered},
		{"no failed attempt is counted", func(v *httpapi.JobView) { v.Run.FailedAttempts = 0 }, JourneyCodeRunNotRecovered},
		{"failure links to a different trace", func(v *httpapi.JobView) { v.Run.Attempts[0].CauseTrace = &other }, JourneyCodeCauseMismatch},
		{"recovery ends before it started", func(v *httpapi.JobView) { v.Run.Attempts[1].Terminal.At = v.Run.Attempts[1].ObservedAt - 1 }, JourneyCodeAttemptOrder},
		{"another run was returned", func(v *httpapi.JobView) { v.Run.ID = jtID(91) }, JourneyCodeFailedAttemptMissing},
		{"job view of another job", func(v *httpapi.JobView) { v.Job = jtID(90) }, JourneyCodeScopeMismatch},
		{"attempt section not ready", func(v *httpapi.JobView) { v.Sections = nil }, JourneyCodeViewNotReady},
		{"failed attempt's original terminal fact is not failed", func(v *httpapi.JobView) {
			terminal := *v.Run.Attempts[0].Terminal
			terminal.State = jobs.AttemptSucceeded
			v.Run.Attempts[0].Terminal = &terminal
		}, JourneyCodeFailedAttemptChanged},
		{"recovery attempt's original terminal fact is not succeeded", func(v *httpapi.JobView) {
			terminal := *v.Run.Attempts[1].Terminal
			terminal.State = jobs.AttemptFailed
			v.Run.Attempts[1].Terminal = &terminal
		}, JourneyCodeRecoveryMissing},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := newJTWorld(t)
			w.jobMut = c.mut
			jtWantFail(t, jtVerify(t, w), JourneySchedulerRetry, c.want)
		})
	}
	// Incomplete health evidence does not hide a complete attempt history.
	w := newJTWorld(t)
	w.jobMut = func(v *httpapi.JobView) {
		v.State, v.Reason = httpapi.StateIncomplete, httpapi.ReasonJobEvidenceIncomplete
	}
	jtWantPass(t, jtVerify(t, w), JourneySchedulerRetry)
	// A failure trace is optional: without one the link is simply not asserted.
	w = newJTWorld(t)
	w.links.Scheduler.FailureTrace = ""
	w.jobMut = func(v *httpapi.JobView) { v.Run.Attempts[0].CauseTrace = nil }
	jtWantPass(t, jtVerify(t, w), JourneySchedulerRetry)
}

func TestJourneyReplayAndCapabilityEdgeCases(t *testing.T) {
	w := newJTWorld(t)
	w.replayLines[1].Chunk.Nodes[1].Class = "visible"
	jtWantFail(t, jtVerify(t, w), JourneyReplayPrivacy, JourneyCodePrivacyViolation)

	// Samples of another method are not evidence that this method ran, even
	// when a supported record of this method exists.
	w = newJTWorld(t)
	pr := w.profileViews[w.profile]
	pr.View.Method = "native_cpu"
	w.profileViews[w.profile] = pr
	rep := jtVerify(t, w)
	jtWantFail(t, rep, JourneyRuntimeCapability, JourneyCodeCapabilityMismatch)
	if rows := jtSection(rep, JourneyRuntimeCapability).Rows; rows[0].Status != JourneyRowUnavailable {
		t.Fatalf("samples of another method: %+v", rows[0])
	}

	// A denied record wins over a supported one for the same row.
	w = newJTWorld(t)
	pr = w.profileViews[w.profile]
	denied := pr.View.Capabilities[0]
	denied.Value.Status = "denied"
	pr.View.Capabilities = append(pr.View.Capabilities, denied)
	w.profileViews[w.profile] = pr
	jtWantFail(t, jtVerify(t, w), JourneyRuntimeCapability, JourneyCodeCapabilityMismatch)

	// OS and architecture narrow the match when named.
	w = newJTWorld(t)
	w.links.Capabilities.Rows[0].OS, w.links.Capabilities.Rows[0].Arch = "linux", "amd64"
	jtWantPass(t, jtVerify(t, w), JourneyRuntimeCapability)
	w.links.Capabilities.Rows[0].Arch = "arm64"
	jtWantFail(t, jtVerify(t, w), JourneyRuntimeCapability, JourneyCodeCapabilityMismatch)

	// A sentinel is found wherever it appears, not only in fields the mask rules cover.
	for name, edit := range map[string]func(w *jtWorld){
		"recorder field": func(w *jtWorld) { w.replayLines[1].Chunk.Recorder = "rec-" + jtSentinel },
		"line reason":    func(w *jtWorld) { w.replayLines[2].Reason = jtSentinel },
	} {
		w = newJTWorld(t)
		edit(w)
		if rep := jtVerify(t, w); !slices.Contains(jtCodes(rep, JourneyReplayPrivacy), JourneyCodePrivacyViolation) {
			t.Fatalf("%s: sentinel outside the mask rules was not found: %v", name, jtCodes(rep, JourneyReplayPrivacy))
		}
	}

	// OS narrows the match as well.
	w = newJTWorld(t)
	w.links.Capabilities.Rows[0].OS = "windows"
	jtWantFail(t, jtVerify(t, w), JourneyRuntimeCapability, JourneyCodeCapabilityMismatch)

	// Each view must echo the requested scope and ID on its own: one wrong
	// field, everything else right, is a scope mismatch.
	other := jtID(88)
	frames := func(edit func(v *httpapi.FramesView)) func(w *jtWorld) {
		return func(w *jtWorld) {
			inner := w.framesFn
			w.framesFn = func(b httpapi.FramesBody) httpapi.FramesView { v := inner(b); edit(&v); return v }
		}
	}
	profile := func(edit func(p *httpapi.ProfileResponse)) func(w *jtWorld) {
		return func(w *jtWorld) {
			p := w.profileViews[w.profile]
			edit(&p)
			w.profileViews[w.profile] = p
		}
	}
	echoes := []struct {
		name string
		kind JourneyKind
		edit func(w *jtWorld)
	}{
		{"release org", JourneyFrontendAPIDB, func(w *jtWorld) { w.releaseView.Org = w.otherOrg }},
		{"release project", JourneyFrontendAPIDB, func(w *jtWorld) { w.releaseView.Project = other }},
		{"issue org", JourneyFrontendAPIDB, func(w *jtWorld) { w.issueView.Org = w.otherOrg }},
		{"issue project", JourneyFrontendAPIDB, func(w *jtWorld) { w.issueView.Project = other }},
		{"issue id", JourneyFrontendAPIDB, func(w *jtWorld) { w.issueView.Issue = other }},
		{"frames org", JourneyFrontendAPIDB, frames(func(v *httpapi.FramesView) { v.Org = w.otherOrg })},
		{"frames project", JourneyFrontendAPIDB, frames(func(v *httpapi.FramesView) { v.Project = other })},
		{"frames build", JourneyFrontendAPIDB, frames(func(v *httpapi.FramesView) { v.Build = other })},
		{"job org", JourneySchedulerRetry, func(w *jtWorld) { w.jobMut = func(v *httpapi.JobView) { v.Org = w.otherOrg } }},
		{"job project", JourneySchedulerRetry, func(w *jtWorld) { w.jobMut = func(v *httpapi.JobView) { v.Project = other } }},
		{"replay org", JourneyReplayPrivacy, func(w *jtWorld) { w.replayLines[0].Org = &w.otherOrg }},
		{"replay project", JourneyReplayPrivacy, func(w *jtWorld) { w.replayLines[0].Project = &other }},
		{"profile org", JourneyRuntimeCapability, profile(func(p *httpapi.ProfileResponse) { p.Org = w.otherOrg })},
		{"profile project", JourneyRuntimeCapability, profile(func(p *httpapi.ProfileResponse) { p.Project = other })},
		{"profile id", JourneyRuntimeCapability, profile(func(p *httpapi.ProfileResponse) { p.Profile = other })},
	}
	for _, c := range echoes {
		w = newJTWorld(t)
		c.edit(w)
		if rep := jtVerify(t, w); !slices.Contains(jtCodes(rep, c.kind), JourneyCodeScopeMismatch) {
			t.Fatalf("%s: a single wrong echo field was accepted: %v", c.name, jtCodes(rep, c.kind))
		}
	}

	// A symbolicator the credential may not use is not-ready, not an unmapped frame.
	w = newJTWorld(t)
	frames(func(v *httpapi.FramesView) {
		v.State, v.Reason = httpapi.StateIncomplete, httpapi.ReasonArtifactGrantAbsent
		v.Frames[0].Reason, v.Frames[0].Resolved, v.Frames[0].MapSHA256 = httpapi.ReasonArtifactGrantAbsent, nil, nil
	})(w)
	jtWantFail(t, jtVerify(t, w), JourneyFrontendAPIDB, JourneyCodeViewNotReady)
}
