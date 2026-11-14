// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/nativeperf"
	"github.com/arynyklas/soundpost/internal/profiles"
)

// fakeProfiles is a labelled test double for the profile read seam. The real
// read composition (storage scan, authenticated cursors, link resolution) is
// exercised by TestProfileViewRealComposition.
type fakeProfiles struct {
	mu     sync.Mutex
	calls  int
	scope  auth.Scope
	id     model.ID
	window profiles.Window
	answer func() (profiles.ProfileView, error)
}

func (f *fakeProfiles) Read(_ context.Context, scope auth.Scope, id model.ID, w profiles.Window) (profiles.ProfileView, error) {
	f.mu.Lock()
	f.calls++
	f.scope, f.id, f.window = scope, id, w
	f.mu.Unlock()
	return f.answer()
}
func (f *fakeProfiles) count() int { f.mu.Lock(); defer f.mu.Unlock(); return f.calls }

type pfEnv struct {
	*isoEnv
	srv *httptest.Server
}

func newPfEnv(t *testing.T, reader httpapi.ProfileReader) *pfEnv {
	t.Helper()
	e := &pfEnv{isoEnv: newIsoEnv(t)}
	h := httpapi.NewProfiles(reader)
	e.srv = httptest.NewTLSServer(httpapi.NewServer("", e.app.Auth, nil, func(mux *http.ServeMux) { httpapi.RegisterProfileRoutes(mux, e.app.Auth, h) }).Handler)
	t.Cleanup(e.srv.Close)
	return e
}

func (e *pfEnv) view(who person, body map[string]any) (int, []byte) {
	ev := &evEnv{isoEnv: e.isoEnv, srv: e.srv}
	return ev.post(who, "/api/v1/profiles/view", body, nil)
}

func profileBody(org, project, profile model.ID) map[string]any {
	return map[string]any{"org": org.String(), "project": project.String(), "profile": profile.String(), "window": map[string]any{"start": "1000", "end": "2000"}}
}

func decodeProfile(t *testing.T, raw []byte) httpapi.ProfileResponse {
	t.Helper()
	var v httpapi.ProfileResponse
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("not a profile response: %v\n%s", err, raw)
	}
	return v
}

func completeView(project, profile model.ID) profiles.ProfileView {
	return profiles.ProfileView{Profile: profile, Process: model.ID{9}, Project: project, Method: "native_cpu", Units: "samples", Clock: model.TraceClock{Domain: model.ClockDomain{Host: model.ID{1}, Boot: model.ID{2}, Runtime: model.ID{3}}}, Completeness: "complete", Frames: []model.ProfileFrame{}, Stacks: []model.ProfileStack{}, Samples: []model.ProfileSample{}, Intervals: []model.ProfileInterval{}, Capabilities: []profiles.CapabilityRecord{}, Loss: []model.LossReport{}, Links: []profiles.ResolvedReference{}, Watermarks: []model.Cursor{}, Reasons: []string{}}
}

func TestProfileViewScopeFirstSeparateGrantAndIndistinguishable(t *testing.T) {
	profile := model.NewID()
	var pA model.ID
	src := &fakeProfiles{}
	src.answer = func() (profiles.ProfileView, error) { return completeView(pA, profile), nil }
	e := newPfEnv(t, src)
	pA = model.NewID()
	pB, pX := model.NewID(), model.NewID()
	orgA, orgB := e.org("profile A", pA, pB), e.org("profile B", pX)
	reader := e.user(orgA, "profile-reader@example.test")
	e.grant(orgA, reader, pA, true, httpapi.ProfilesRead)
	telemetryOnly := e.user(orgA, "profile-telemetry@example.test")
	e.grant(orgA, telemetryOnly, pA, true, auth.Read)
	outsider := e.user(orgB, "profile-outsider@example.test")
	e.grant(orgB, outsider, pX, true, httpapi.ProfilesRead)

	status, raw := e.view(reader, profileBody(orgA, pA, profile))
	if status != 200 {
		t.Fatalf("reader: %d %s", status, raw)
	}
	v := decodeProfile(t, raw)
	if v.State != httpapi.StateReady || v.View == nil || v.View.Profile != profile || v.Org != orgA || v.Project != pA {
		t.Fatalf("view = %s", raw)
	}
	if src.scope.OrgID() != orgA || !src.scope.AllowsProject(pA) || src.scope.AllowsProject(pB) || src.scope.Permission() != httpapi.ProfilesRead || src.id != profile ||
		src.window.Start != 1000 || src.window.End != 2000 || src.window.MaxSamples != httpapi.DefaultProfileSamples {
		t.Fatalf("service saw a different request than the scoped one: %+v", src)
	}

	before := src.count()
	var want string
	for name, c := range map[string]struct {
		who      person
		org, prj model.ID
	}{
		"telemetry.read without profiles.read": {telemetryOnly, orgA, pA},
		"other org's member naming org A":      {outsider, orgA, pA},
		"ungranted sibling project":            {reader, orgA, pB},
		"guessed project":                      {reader, orgA, model.NewID()},
		"guessed org":                          {reader, model.NewID(), pA},
	} {
		status, raw = e.view(c.who, profileBody(c.org, c.prj, profile))
		if status != 404 {
			t.Fatalf("%s: %d %s", name, status, raw)
		}
		got := denial(t, status, raw)
		if want == "" {
			want = got
		} else if got != want {
			t.Fatalf("%s is distinguishable: %q vs %q", name, got, want)
		}
	}
	elevated := profileBody(orgA, pA, profile)
	elevated["elevation"] = model.NewID().String()
	if status, _ = e.view(reader, elevated); status != 403 {
		t.Fatalf("elevation: %d", status)
	}
	if src.count() != before {
		t.Fatal("the profile service was reached before scope was proven")
	}
}

func TestProfileViewNotWiredIsTypedNotAvailableAfterScope(t *testing.T) {
	e := newPfEnv(t, nil)
	pA, pX := model.NewID(), model.NewID()
	orgA, orgB := e.org("profile nw A", pA), e.org("profile nw B", pX)
	reader := e.user(orgA, "profile-nw@example.test")
	e.grant(orgA, reader, pA, true, httpapi.ProfilesRead)
	status, raw := e.view(reader, profileBody(orgA, pA, model.NewID()))
	v := decodeProfile(t, raw)
	if status != 200 || v.State != httpapi.StateNotAvailable || v.Reason != httpapi.ReasonProfileServiceNotWired || v.View != nil || len(v.Sections) != 1 || v.Sections[0].State != httpapi.StateNotAvailable {
		t.Fatalf("unwired = %d %s", status, raw)
	}
	outsider := e.user(orgB, "profile-nw-out@example.test")
	e.grant(orgB, outsider, pX, true, httpapi.ProfilesRead)
	if status, _ = e.view(outsider, profileBody(orgA, pA, model.NewID())); status != 404 {
		t.Fatalf("outsider saw %d on an unwired service", status)
	}
}

func TestProfileViewPartialStaysIncompleteWithItsReason(t *testing.T) {
	profile := model.NewID()
	var project model.ID
	cases := map[string]func(v *profiles.ProfileView){
		"service says partial":  func(v *profiles.ProfileView) { v.Completeness, v.Reasons = "partial", []string{"coverage_incomplete"} },
		"truncated only":        func(v *profiles.ProfileView) { v.Truncated = true },
		"partial without cause": func(v *profiles.ProfileView) { v.Completeness = "partial" },
	}
	want := map[string]string{"service says partial": "coverage_incomplete", "truncated only": httpapi.ReasonProfilePartial, "partial without cause": httpapi.ReasonProfilePartial}
	src := &fakeProfiles{}
	e := newPfEnv(t, src)
	project = model.NewID()
	org := e.org("profile partial", project)
	reader := e.user(org, "profile-partial@example.test")
	e.grant(org, reader, project, true, httpapi.ProfilesRead)
	for name, mutate := range cases {
		src.answer = func() (profiles.ProfileView, error) { v := completeView(project, profile); mutate(&v); return v, nil }
		status, raw := e.view(reader, profileBody(org, project, profile))
		v := decodeProfile(t, raw)
		if status != 200 || v.State != httpapi.StateIncomplete || !v.Partial || v.Reason != want[name] || v.View == nil {
			t.Fatalf("%s: %d %s", name, status, raw)
		}
	}
}

func TestProfileViewRefusesAViewOfAnotherProjectOrProfile(t *testing.T) {
	profile := model.NewID()
	var project model.ID
	src := &fakeProfiles{}
	e := newPfEnv(t, src)
	project = model.NewID()
	org := e.org("profile other", project)
	reader := e.user(org, "profile-other@example.test")
	e.grant(org, reader, project, true, httpapi.ProfilesRead)
	for name, mutate := range map[string]func(*profiles.ProfileView){
		"another project": func(v *profiles.ProfileView) { v.Project = model.NewID() },
		"another profile": func(v *profiles.ProfileView) { v.Profile = model.NewID() },
		"unknown state":   func(v *profiles.ProfileView) { v.Completeness = "fine" },
	} {
		src.answer = func() (profiles.ProfileView, error) { v := completeView(project, profile); mutate(&v); return v, nil }
		if status, raw := e.view(reader, profileBody(org, project, profile)); status != 503 {
			t.Fatalf("%s: %d %s", name, status, raw)
		}
	}
}

func TestProfileViewErrorsAreTypedAndNeverEchoServiceText(t *testing.T) {
	canary := "PROFILE-ERR-CANARY-" + model.NewID().String()
	src := &fakeProfiles{}
	e := newPfEnv(t, src)
	project := model.NewID()
	org := e.org("profile err", project)
	reader := e.user(org, "profile-err@example.test")
	e.grant(org, reader, project, true, httpapi.ProfilesRead)
	for name, c := range map[string]struct {
		err    error
		status int
	}{"not found": {model.Fail(model.NotFound), 404}, "plain error": {errors.New(canary), 503}, "too large": {model.Fail(model.TooLarge), 413}} {
		src.answer = func() (profiles.ProfileView, error) { return profiles.ProfileView{}, c.err }
		status, raw := e.view(reader, profileBody(org, project, model.NewID()))
		if status != c.status || strings.Contains(string(raw), canary) {
			t.Fatalf("%s: %d %s", name, status, raw)
		}
	}
}

func TestProfileViewRejectsMalformedRequests(t *testing.T) {
	src := &fakeProfiles{answer: func() (profiles.ProfileView, error) { t.Error("service reached"); return profiles.ProfileView{}, nil }}
	e := newPfEnv(t, src)
	project := model.NewID()
	org := e.org("profile bad", project)
	reader := e.user(org, "profile-bad@example.test")
	e.grant(org, reader, project, true, httpapi.ProfilesRead)
	ok := func() map[string]any { return profileBody(org, project, model.NewID()) }
	for name, mutate := range map[string]func(map[string]any){
		"zero profile":     func(b map[string]any) { b["profile"] = model.ID{}.String() },
		"empty window":     func(b map[string]any) { b["window"] = map[string]any{"start": "5", "end": "5"} },
		"reversed window":  func(b map[string]any) { b["window"] = map[string]any{"start": "9", "end": "5"} },
		"too many samples": func(b map[string]any) { b["max_samples"] = 8193 },
		"unknown field":    func(b map[string]any) { b["scope"] = "x" },
	} {
		b := ok()
		mutate(b)
		if status, raw := e.view(reader, b); status != 400 && status != 422 {
			t.Fatalf("%s: %d %s", name, status, raw)
		}
	}
}

func TestProfileViewPassesCursorAndSampleBound(t *testing.T) {
	profile := model.NewID()
	var project model.ID
	src := &fakeProfiles{}
	src.answer = func() (profiles.ProfileView, error) {
		v := completeView(project, profile)
		v.NextCursor = "next-opaque"
		return v, nil
	}
	e := newPfEnv(t, src)
	project = model.NewID()
	org := e.org("profile cursor", project)
	reader := e.user(org, "profile-cursor@example.test")
	e.grant(org, reader, project, true, httpapi.ProfilesRead)
	b := profileBody(org, project, profile)
	b["max_samples"], b["cursor"] = 7, "prev-opaque"
	status, raw := e.view(reader, b)
	if status != 200 || src.window.MaxSamples != 7 || src.window.Cursor != "prev-opaque" || decodeProfile(t, raw).View.NextCursor != "next-opaque" {
		t.Fatalf("%d %s %+v", status, raw, src.window)
	}
}

// TestProfileViewRealComposition reads a real native profile: chunks assembled by the
// committed nativeperf assembler (from sanitized synthetic events: no perf privileges
// exist here), admitted through the real HTTPS ingest route into the real storage
// engine, and read through the real C10 service of appcore under a profiles.read scope.
func TestProfileViewRealComposition(t *testing.T) {
	e := &pfEnv{isoEnv: newIsoEnv(t)}
	h := httpapi.NewProfiles(e.app.NewNativeProfiles())
	e.srv = httptest.NewTLSServer(httpapi.NewServer("", e.app.Auth, nil, func(mux *http.ServeMux) { httpapi.RegisterProfileRoutes(mux, e.app.Auth, h) }).Handler)
	t.Cleanup(e.srv.Close)
	project := model.NewID()
	org := e.org("profile real", project)
	ids := sharedIDs{model.NewID(), model.NewID(), model.NewID()}
	pol := model.SourcePolicy{Revision: 1, Enabled: true, Class: "structured", Kinds: []model.Kind{model.Profile, model.CapabilityKind, model.Loss}, RetentionDays: map[model.Kind]uint32{model.Profile: 7, model.CapabilityKind: 30, model.Loss: 30}, MaxBytes: 16 << 20, MaxSeries: 100}
	src := e.onboard(org, project, model.NewID(), ids, pol, auth.SourcePolicyConfig{ProjectID: project, Enabled: true})

	root, capID := model.NewID(), model.NewID()
	now := model.UnixNano(time.Now().UnixNano())
	d := nativeperf.ClockDomain{HostID: "host", BootID: "boot"}
	k := nativeperf.TaskKey{BootID: "boot", PIDNamespace: 1, TGID: 7, TID: 8, ProcessStart: 1, Generation: 1}
	caps := nativeperf.Capabilities{CPU: nativeperf.Supported, OffCPU: nativeperf.Denied, RunqueueSplit: nativeperf.Denied, Permissions: nativeperf.Permissions{CPUEventOpen: nativeperf.Supported, SchedulerEventOpen: nativeperf.Denied}, FrameCoverage: nativeperf.Coverage{Reasons: []nativeperf.Reason{nativeperf.ReasonUnmeasured}}, ThreadCoverage: nativeperf.Coverage{Reasons: []nativeperf.Reason{nativeperf.ReasonUnmeasured}}}
	var events []nativeperf.SanitizedEvent
	for i := range 3 {
		events = append(events, nativeperf.SanitizedEvent{Kind: nativeperf.EventCPU, Domain: d, Task: k, Sequence: model.Uint64(i + 1), Time: model.MonoNano(i + 1), CPUEvent: &nativeperf.CPUSample{IP: 4096, Callchain: []nativeperf.CallchainEntry{{IP: 4096}}, Method: nativeperf.MethodSoftwareCPUClock, Unit: nativeperf.UnitCPUClockNanoseconds, RequestedHz: 99, Period: 901}})
	}
	c, err := nativeperf.AssembleProfile(context.Background(), events, nil, caps, nativeperf.ProfileLimits{Profile: root, Process: model.NewID(), Capability: capID, Domain: d, PolicyRevision: 1, Sequence: 1, Start: now, End: now + 100, Clock: model.TraceClock{Wall: now, Domain: model.ClockDomain{Host: model.ID{4}, Boot: model.ID{5}, Runtime: model.ID{6}}}, Complete: true, MaxBytes: 8 << 20, MaxSamples: 8192, MaxIntervals: 8192, MaxFrames: 4096, MaxStacks: 4096})
	if err != nil {
		t.Fatal(err)
	}
	c.Frames[0] = model.ProfileFrame{Reason: "frame_unresolved"}
	e.ingest(src, model.Record{ID: model.NewID(), Kind: model.Profile, ObservedAt: now, Resource: e.resource(src), Payload: model.Payload{Profile: &c}})
	for i, method := range []string{"native_cpu", "native_offcpu", "native_runqueue_split"} {
		status, reason := "denied", "permission_denied"
		if i == 0 {
			status, reason = "supported", "coverage_unmeasured"
		}
		v := model.Capability{Runtime: "native_linux", Version: "1", Build: "owned", OS: "linux", Arch: "amd64", Signal: model.Profile, Method: method, Status: status, Reason: reason, Coverage: model.Coverage{Frames: "unknown", Threads: "unknown", Workers: "none", Tasks: "unknown"}, Clock: c.Clock.Domain, Expires: now + model.UnixNano(time.Hour)}
		e.ingest(src, model.Record{ID: c.NativeCapabilities[i], Kind: model.CapabilityKind, ObservedAt: now, Resource: e.resource(src), Payload: model.Payload{Capability: &v}})
	}
	reader := e.user(org, "profile-real@example.test")
	e.grant(org, reader, project, true, httpapi.ProfilesRead)
	body := profileBody(org, project, root)
	body["window"] = map[string]any{"start": strconv.FormatInt(int64(now), 10), "end": strconv.FormatInt(int64(now)+100, 10)}
	status, raw := e.view(reader, body)
	if status != 200 {
		t.Fatalf("%d %s", status, raw)
	}
	v := decodeProfile(t, raw)
	if v.View == nil || v.View.Method != "native_cpu" || v.View.Units != "samples" || len(v.View.Samples) != 3 || v.View.Samples[0].Native == nil || v.View.Samples[0].Native.Period != 901 || v.View.BlockedNano != nil || v.View.RunnableNano != nil || len(v.View.Capabilities) != 3 {
		t.Fatalf("real view = %s", raw)
	}
	// A native CPU read is OS on-CPU sample units: it carries no scheduler time at all, so none may be invented.
	if strings.Contains(string(raw), "blocked_ns") || strings.Contains(string(raw), "runnable_ns") || strings.Contains(string(raw), "unknown_ns") {
		t.Fatal("a CPU-only profile reported scheduler time")
	}
	e.grant(org, reader, project, false, httpapi.ProfilesRead)
	if status, _ = e.view(reader, body); status != 404 {
		t.Fatalf("revoked reader: %d", status)
	}
}

// TestWriteProfileFixture regenerates web/e2e/support/profile-fixture.json with the
// real nativeperf assembler when SOUNDPOST_WRITE_PROFILE_FIXTURE names the output
// file (cd to the repository root is not needed: the path is used as given). The
// events are sanitized SYNTHETIC kernel events: no perf privileges exist on this
// host, so the assembler, the ingest validators, storage and the C10 read are real
// and the kernel acquisition is not. Without the variable it only proves the
// fixture still assembles and the read path's scheduler/CPU units stay separate.
func TestWriteProfileFixture(t *testing.T) {
	d := nativeperf.ClockDomain{HostID: "host", BootID: "boot"}
	k := nativeperf.TaskKey{BootID: "boot", PIDNamespace: 1, TGID: 7, TID: 8, ProcessStart: 1, Generation: 1}
	t0 := model.UnixNano(1730000000000000000)
	profile, process, capID := model.ID{0x5a, 1}, model.ID{0x5a, 2}, model.ID{0x5a, 3}
	caps := nativeperf.Capabilities{CPU: nativeperf.Supported, OffCPU: nativeperf.Supported, RunqueueSplit: nativeperf.Denied, Permissions: nativeperf.Permissions{CPUEventOpen: nativeperf.Supported, SchedulerEventOpen: nativeperf.Supported}, FrameCoverage: nativeperf.Coverage{Reasons: []nativeperf.Reason{nativeperf.ReasonUnmeasured}}, ThreadCoverage: nativeperf.Coverage{Reasons: []nativeperf.Reason{nativeperf.ReasonUnmeasured}}}
	var events []nativeperf.SanitizedEvent
	for i := range 3 {
		events = append(events, nativeperf.SanitizedEvent{Kind: nativeperf.EventCPU, Domain: d, Task: k, Sequence: model.Uint64(i + 1), Time: model.MonoNano(10 * (i + 1)), CPUEvent: &nativeperf.CPUSample{IP: 4096, Callchain: []nativeperf.CallchainEntry{{IP: 4096}}, Method: nativeperf.MethodSoftwareCPUClock, Unit: nativeperf.UnitCPUClockNanoseconds, RequestedHz: 99, Period: 901}})
	}
	interval := func(start, end model.MonoNano, kind nativeperf.IntervalKind) nativeperf.Interval {
		return nativeperf.Interval{Domain: d, Task: k, Start: start, End: end, Kind: kind, Measure: nativeperf.Measure{Unit: nativeperf.UnitNanoseconds, Value: model.Uint64(end - start)}, MissingCallchain: nativeperf.ReasonMissingSwitchCallchain}
	}
	intervals := []nativeperf.Interval{interval(100, 160, nativeperf.IntervalBlocked), interval(200, 230, nativeperf.IntervalRunnable)}
	chunk, err := nativeperf.AssembleProfile(context.Background(), events, intervals, caps, nativeperf.ProfileLimits{Profile: profile, Process: process, Capability: capID, Domain: d, PolicyRevision: 1, Sequence: 1, Start: t0, End: t0 + 1000, Clock: model.TraceClock{Wall: t0, Domain: model.ClockDomain{Host: model.ID{4}, Boot: model.ID{5}, Runtime: model.ID{6}}}, Complete: true, MaxBytes: 8 << 20, MaxSamples: 8192, MaxIntervals: 8192, MaxFrames: 4096, MaxStacks: 4096})
	if err != nil {
		t.Fatal(err)
	}
	chunk.Frames[0] = model.ProfileFrame{Reason: "frame_unresolved"}
	if len(chunk.Intervals) != 2 || chunk.Samples[0].Native == nil {
		t.Fatalf("fixture lost its scheduler or CPU observations: %+v", chunk)
	}
	type capRow struct {
		ID    model.ID         `json:"id"`
		Value model.Capability `json:"value"`
	}
	var rows []capRow
	for i, method := range []string{"native_cpu", "native_offcpu", "native_runqueue_split"} {
		status, reason := "supported", "coverage_unmeasured"
		if i == 2 {
			status, reason = "denied", "permission_denied"
		}
		rows = append(rows, capRow{chunk.NativeCapabilities[i], model.Capability{Runtime: "native_linux", Version: "1", Build: "owned", OS: "linux", Arch: "amd64", Signal: model.Profile, Method: method, Status: status, Reason: reason, Coverage: model.Coverage{Frames: "unknown", Threads: "unknown", Workers: "none", Tasks: "unknown"}, Clock: chunk.Clock.Domain, Expires: t0 + model.UnixNano(24*time.Hour)}})
	}
	if out := os.Getenv("SOUNDPOST_WRITE_PROFILE_FIXTURE"); out != "" {
		raw, err := json.MarshalIndent(map[string]any{"source": "internal/httpapi TestWriteProfileFixture: nativeperf.AssembleProfile over sanitized synthetic events", "chunk": chunk, "capabilities": rows}, "", " ")
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(out, append(raw, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
