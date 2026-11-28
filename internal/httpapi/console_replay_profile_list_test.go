// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/nativeperf"
)

func (e *clEnv) windowList(who person, path string, org model.ID, projects []model.ID, from, to time.Time, extra clBody) (int, []byte) {
	e.t.Helper()
	ids := make([]string, len(projects))
	for i, p := range projects {
		ids[i] = p.String()
	}
	body := clBody{"org": org.String(), "projects": ids, "window": map[string]any{"start": strconv.FormatInt(from.UnixNano(), 10), "end": strconv.FormatInt(to.UnixNano(), 10)}}
	for k, v := range extra {
		body[k] = v
	}
	return e.post(who, path, body)
}

type windowRig struct {
	*clEnv
	org, project model.ID
	src          sourceFixture
	reader       person // telemetry.read + the separate grant
	from, to     time.Time
}

func newWindowRig(t *testing.T, kinds []model.Kind, policy model.SourcePolicy, separate auth.Permission) *windowRig {
	t.Helper()
	r := &windowRig{clEnv: newClEnv(t, 0), project: model.NewID(), from: time.Now().Add(-time.Hour), to: time.Now().Add(time.Hour)}
	r.org = r.isoEnv.org("window list org", r.project)
	ids := sharedIDs{model.NewID(), model.NewID(), model.NewID()}
	policy.Kinds = kinds
	r.src = r.onboard(r.org, r.project, model.NewID(), ids, policy, auth.SourcePolicyConfig{ProjectID: r.project, Enabled: true})
	r.reader = r.user(r.org, "window-list-reader@example.test")
	perms := []auth.Permission{auth.Read}
	if separate != "" {
		perms = append(perms, separate)
	}
	r.grant(r.org, r.reader, r.project, true, perms...)
	return r
}

func (r *windowRig) list(path string, who person, extra clBody) (int, []byte) {
	return r.windowList(who, path, r.org, []model.ID{r.project}, r.from, r.to, extra)
}

// ---- replays ----

func newReplayRig(t *testing.T) (*windowRig, *chainRecorder, *chainRecorder) {
	t.Helper()
	pol := model.SourcePolicy{Revision: 1, Enabled: true, Class: "structured", Replay: true, RetentionDays: map[model.Kind]uint32{model.Replay: 14}, MaxBytes: 1 << 30, MaxSeries: 100}
	r := newWindowRig(t, []model.Kind{model.Replay}, pol, httpapi.ReplayRead)
	lossy, whole := newChainRecorder(), newChainRecorder()
	for i := 1; i <= 10; i++ {
		c := lossy.next(t, i == 1 || i == 6)
		if i == 4 {
			continue // lost in transit
		}
		r.ingest(r.src, model.Record{ID: model.NewID(), Kind: model.Replay, ObservedAt: c.Clock.Wall, Resource: r.resource(r.src), Payload: model.Payload{Replay: &c}})
	}
	for i := 1; i <= 3; i++ {
		c := whole.next(t, i == 1)
		r.ingest(r.src, model.Record{ID: model.NewID(), Kind: model.Replay, ObservedAt: c.Clock.Wall, Resource: r.resource(r.src), Payload: model.Payload{Replay: &c}})
	}
	return r, lossy, whole
}

func TestReplayListSummarisesGapsFromRealStoredChunks(t *testing.T) {
	r, lossy, whole := newReplayRig(t)
	status, raw := r.list("/api/v1/replays/list", r.reader, nil)
	l := decodeList[httpapi.ReplayListItem](t, status, raw)
	if l.State != httpapi.StateReady || len(l.Items) != 2 || l.More {
		t.Fatalf("%s", raw)
	}
	// newest recording first: the whole one was ingested last
	w, g := l.Items[0], l.Items[1]
	if w.ReplayID != whole.replay || w.Chunks != 3 || w.Gaps != 0 || w.Recording != httpapi.RecordingComplete || w.SessionID == nil || *w.SessionID != whole.session || w.ProjectID != r.project {
		t.Fatalf("complete replay: %+v", w)
	}
	if g.ReplayID != lossy.replay || g.Chunks != 9 || g.Gaps != 1 || g.Recording != httpapi.RecordingGap || g.FirstAt <= 0 || g.LastAt < g.FirstAt {
		t.Fatalf("replay with a lost chunk: %+v", g)
	}
	for _, leak := range []string{"masked", "pointer", "nodes", "events", "div", "recorder"} {
		if strings.Contains(string(raw), leak) {
			t.Fatalf("replay content (%q) is never listed: %s", leak, raw)
		}
	}

	_, raw = r.list("/api/v1/replays/list", r.reader, clBody{"query": lossy.replay.String()[:12]})
	if l = decodeList[httpapi.ReplayListItem](t, 200, raw); len(l.Items) != 1 || l.Items[0].ReplayID != lossy.replay {
		t.Fatalf("id prefix: %s", raw)
	}
	_, raw = r.list("/api/v1/replays/list", r.reader, clBody{"query": whole.session.String()[:12]})
	if l = decodeList[httpapi.ReplayListItem](t, 200, raw); len(l.Items) != 1 || l.Items[0].ReplayID != whole.replay {
		t.Fatalf("session prefix: %s", raw)
	}
	_, raw = r.list("/api/v1/replays/list", r.reader, clBody{"sort": "first_at"})
	if l = decodeList[httpapi.ReplayListItem](t, 200, raw); len(l.Items) != 2 || l.Items[0].ReplayID != whole.replay {
		t.Fatalf("first_at order: %s", raw)
	}

	// paging with an authenticated cursor
	_, raw = r.list("/api/v1/replays/list", r.reader, clBody{"limit": 1})
	p1 := decodeList[httpapi.ReplayListItem](t, 200, raw)
	if len(p1.Items) != 1 || !p1.More || p1.NextCursor == "" || p1.Items[0].ReplayID != whole.replay {
		t.Fatalf("page 1: %s", raw)
	}
	_, raw = r.list("/api/v1/replays/list", r.reader, clBody{"limit": 1, "cursor": p1.NextCursor})
	if p2 := decodeList[httpapi.ReplayListItem](t, 200, raw); len(p2.Items) != 1 || p2.More || p2.Items[0].ReplayID != lossy.replay {
		t.Fatalf("page 2: %s", raw)
	}
	other := r.user(r.org, "window-list-other@example.test")
	r.grant(r.org, other, r.project, true, auth.Read, httpapi.ReplayRead)
	if status, raw = r.list("/api/v1/replays/list", other, clBody{"limit": 1, "cursor": p1.NextCursor}); status != 400 || !strings.Contains(string(raw), "cursor_invalid") {
		t.Fatalf("cursor replayed by another caller: %d %s", status, raw)
	}

	// a window that holds nothing is empty, never an error
	status, raw = r.windowList(r.reader, "/api/v1/replays/list", r.org, []model.ID{r.project}, r.from.Add(-48*time.Hour), r.from.Add(-24*time.Hour), nil)
	if l = decodeList[httpapi.ReplayListItem](t, status, raw); l.State != httpapi.StateEmpty || len(l.Items) != 0 {
		t.Fatalf("empty window: %s", raw)
	}
}

func TestReplayListNeedsItsOwnGrantAndProbesNothing(t *testing.T) {
	r, _, _ := newReplayRig(t)
	path := "/api/v1/replays/list"
	telemetryOnly := r.user(r.org, "window-list-telemetry@example.test")
	r.grant(r.org, telemetryOnly, r.project, true, auth.Read)
	replayOnly := r.user(r.org, "window-list-replay-only@example.test")
	r.grant(r.org, replayOnly, r.project, true, httpapi.ReplayRead)

	status, raw := r.list(path, telemetryOnly, nil)
	l := decodeList[httpapi.ReplayListItem](t, status, raw)
	if l.State != httpapi.StateNotAvailable || l.Reason != httpapi.ReasonGrantRequired || len(l.Items) != 0 || l.More || l.NextCursor != "" {
		t.Fatalf("telemetry.read without replay.read: %s", raw)
	}
	// the answer is the same whether or not replays exist: another project of the org that holds none says the same
	empty := model.NewID()
	r.cmd(r.org, "create_project", auth.AdminPayload{ID: empty, Name: "no replays"})
	r.grant(r.org, telemetryOnly, empty, true, auth.Read)
	status, raw2 := r.windowList(telemetryOnly, path, r.org, []model.ID{empty}, r.from, r.to, nil)
	if got := decodeList[httpapi.ReplayListItem](t, status, raw2); got.State != l.State || got.Reason != l.Reason || len(got.Items) != 0 {
		t.Fatalf("the typed answer reveals whether replays exist: %s", raw2)
	}
	if status, raw = r.list(path, replayOnly, nil); status != 404 {
		t.Fatalf("replay.read without telemetry.read: %d %s", status, raw)
	}
	if status, raw = r.list(path, r.user(r.org, "window-list-nogrant@example.test"), nil); status != 404 {
		t.Fatalf("no grant: %d %s", status, raw)
	}

	// the separate grant must hold on EVERY requested project
	second := model.NewID()
	r.cmd(r.org, "create_project", auth.AdminPayload{ID: second, Name: "second"})
	r.grant(r.org, r.reader, second, true, auth.Read)
	status, raw = r.windowList(r.reader, path, r.org, []model.ID{r.project, second}, r.from, r.to, nil)
	if l = decodeList[httpapi.ReplayListItem](t, status, raw); l.State != httpapi.StateNotAvailable || l.Reason != httpapi.ReasonGrantRequired || len(l.Items) != 0 {
		t.Fatalf("replay.read on one of two projects: %s", raw)
	}

	// a foreign organization sees nothing of it
	fp := model.NewID()
	fo := r.isoEnv.org("foreign replay org", fp)
	foreign := r.user(fo, "window-list-foreign@example.test")
	r.grant(fo, foreign, fp, true, auth.Read, httpapi.ReplayRead)
	if status, raw = r.windowList(foreign, path, r.org, []model.ID{r.project}, r.from, r.to, nil); status != 404 {
		t.Fatalf("foreign org: %d %s", status, raw)
	}
	if status, raw = r.windowList(foreign, path, fo, []model.ID{r.project}, r.from, r.to, nil); status != 404 {
		t.Fatalf("foreign project: %d %s", status, raw)
	}

	// withdrawing replay.read alone turns the list into the typed answer; withdrawing everything is the 404
	r.grant(r.org, r.reader, r.project, true, auth.Read)
	status, raw = r.list(path, r.reader, nil)
	if l = decodeList[httpapi.ReplayListItem](t, status, raw); l.State != httpapi.StateNotAvailable || l.Reason != httpapi.ReasonGrantRequired {
		t.Fatalf("revoked replay.read: %+v", l)
	}
	r.grant(r.org, r.reader, r.project, false, auth.Read, httpapi.ReplayRead)
	if status, raw = r.list(path, r.reader, nil); status != 404 {
		t.Fatalf("revoked reader: %d %s", status, raw)
	}
}

func TestReplayListRequestBounds(t *testing.T) {
	r, _, _ := newReplayRig(t)
	path := "/api/v1/replays/list"
	many := make([]string, 17)
	for i := range many {
		many[i] = model.NewID().String()
	}
	bad := map[string]clBody{
		"no window":        {"org": r.org.String(), "projects": []string{r.project.String()}},
		"empty window":     {"org": r.org.String(), "projects": []string{r.project.String()}, "window": map[string]any{"start": "5", "end": "5"}},
		"window over 31 d": {"org": r.org.String(), "projects": []string{r.project.String()}, "window": map[string]any{"start": "1", "end": strconv.FormatInt(int64(32*24*time.Hour), 10)}},
		"17 projects":      {"org": r.org.String(), "projects": many, "window": map[string]any{"start": "1", "end": "2"}},
		"limit 201":        {"org": r.org.String(), "projects": []string{r.project.String()}, "window": map[string]any{"start": "1", "end": "2"}, "limit": 201},
		"unknown sort":     {"org": r.org.String(), "projects": []string{r.project.String()}, "window": map[string]any{"start": "1", "end": "2"}, "sort": "chunks"},
	}
	for name, body := range bad {
		if status, raw := r.post(r.reader, path, body); status != 400 {
			t.Fatalf("%s: %d %s", name, status, raw)
		}
	}
}

// ---- profiles ----

func newProfileRig(t *testing.T) *windowRig {
	t.Helper()
	pol := model.SourcePolicy{Revision: 1, Enabled: true, Class: "structured", RetentionDays: map[model.Kind]uint32{model.Profile: 7, model.CapabilityKind: 30, model.Loss: 30}, MaxBytes: 16 << 20, MaxSeries: 100}
	return newWindowRig(t, []model.Kind{model.Profile, model.CapabilityKind, model.Loss}, pol, httpapi.ProfilesRead)
}

// ingestProfile stores one real native CPU profile (assembled by the owned assembler) and its three capability
// records; the primary capability carries the given status and reason.
func (r *windowRig) ingestProfile(t *testing.T, start model.UnixNano, status, reason string, complete bool) model.ID {
	t.Helper()
	root, capID := model.NewID(), model.NewID()
	d := nativeperf.ClockDomain{HostID: "host", BootID: "boot"}
	k := nativeperf.TaskKey{BootID: "boot", PIDNamespace: 1, TGID: 7, TID: 8, ProcessStart: 1, Generation: 1}
	caps := nativeperf.Capabilities{CPU: nativeperf.Supported, OffCPU: nativeperf.Denied, RunqueueSplit: nativeperf.Denied, Permissions: nativeperf.Permissions{CPUEventOpen: nativeperf.Supported, SchedulerEventOpen: nativeperf.Denied}, FrameCoverage: nativeperf.Coverage{Reasons: []nativeperf.Reason{nativeperf.ReasonUnmeasured}}, ThreadCoverage: nativeperf.Coverage{Reasons: []nativeperf.Reason{nativeperf.ReasonUnmeasured}}}
	var events []nativeperf.SanitizedEvent
	for i := range 3 {
		events = append(events, nativeperf.SanitizedEvent{Kind: nativeperf.EventCPU, Domain: d, Task: k, Sequence: model.Uint64(i + 1), Time: model.MonoNano(i + 1), CPUEvent: &nativeperf.CPUSample{IP: 4096, Callchain: []nativeperf.CallchainEntry{{IP: 4096}}, Method: nativeperf.MethodSoftwareCPUClock, Unit: nativeperf.UnitCPUClockNanoseconds, RequestedHz: 99, Period: 901}})
	}
	c, err := nativeperf.AssembleProfile(context.Background(), events, nil, caps, nativeperf.ProfileLimits{Profile: root, Process: model.NewID(), Capability: capID, Domain: d, PolicyRevision: 1, Sequence: 1, Start: start, End: start + 100,
		Clock: model.TraceClock{Wall: start, Domain: model.ClockDomain{Host: model.ID{4}, Boot: model.ID{5}, Runtime: model.ID{6}}}, Complete: complete, MaxBytes: 8 << 20, MaxSamples: 8192, MaxIntervals: 8192, MaxFrames: 4096, MaxStacks: 4096})
	if err != nil {
		t.Fatal(err)
	}
	c.Frames[0] = model.ProfileFrame{Reason: "frame_unresolved"}
	r.ingest(r.src, model.Record{ID: model.NewID(), Kind: model.Profile, ObservedAt: start, Resource: r.resource(r.src), Payload: model.Payload{Profile: &c}})
	for i, method := range []string{"native_cpu", "native_offcpu", "native_runqueue_split"} {
		st, why := "denied", "permission_denied"
		if i == 0 {
			st, why = status, reason
		}
		v := model.Capability{Runtime: "native_linux", Version: "1", Build: "owned", OS: "linux", Arch: "amd64", Signal: model.Profile, Method: method, Status: st, Reason: why, Coverage: model.Coverage{Frames: "unknown", Threads: "unknown", Workers: "none", Tasks: "unknown"}, Clock: c.Clock.Domain, Expires: start + model.UnixNano(time.Hour)}
		r.ingest(r.src, model.Record{ID: c.NativeCapabilities[i], Kind: model.CapabilityKind, ObservedAt: start, Resource: r.resource(r.src), Payload: model.Payload{Capability: &v}})
	}
	return root
}

func TestProfileListUnitCoverageAndUnsupportedFromRealStoredChunks(t *testing.T) {
	r := newProfileRig(t)
	now := model.UnixNano(time.Now().UnixNano())
	ok := r.ingestProfile(t, now-1_000, "supported", "coverage_unmeasured", true)
	denied := r.ingestProfile(t, now, "denied", "permission_denied", true)
	partial := r.ingestProfile(t, now+1_000, "supported", "coverage_unmeasured", false)
	path := "/api/v1/profiles/list"

	status, raw := r.list(path, r.reader, nil)
	l := decodeList[httpapi.ProfileListItem](t, status, raw)
	if l.State != httpapi.StateReady || len(l.Items) != 3 {
		t.Fatalf("%s", raw)
	}
	by := map[model.ID]httpapi.ProfileListItem{}
	for _, it := range l.Items {
		by[it.ProfileID] = it
	}
	a := by[ok]
	if a.Method != "native_cpu" || a.Unit != "samples" || a.Coverage != httpapi.CoverageComplete || a.UnsupportedReason != "" || a.SourceID == nil || *a.SourceID != r.src.ID || a.FirstAt != model.Int64(now-1_000) || a.LastAt != model.Int64(now-1_000+100) {
		t.Fatalf("complete profile: %+v", a)
	}
	if d := by[denied]; d.Coverage != httpapi.CoverageUnknown || d.UnsupportedReason != "permission_denied" || d.Unit != "samples" {
		t.Fatalf("an unsupported capability is coverage unknown with its reason, and keeps its unit: %+v", d)
	}
	if p := by[partial]; p.Coverage != httpapi.CoveragePartial {
		t.Fatalf("a chunk that is not complete is partial: %+v", p)
	}
	if l.Items[0].ProfileID != partial || l.Items[2].ProfileID != ok {
		t.Fatalf("newest first: %s", raw)
	}
	for _, leak := range []string{"samples\":[", "frames", "stacks", "frame_unresolved", "callchain"} {
		if strings.Contains(string(raw), leak) {
			t.Fatalf("profile content (%q) is never listed: %s", leak, raw)
		}
	}

	_, raw = r.list(path, r.reader, clBody{"query": denied.String()[:12]})
	if got := decodeList[httpapi.ProfileListItem](t, 200, raw); len(got.Items) != 1 || got.Items[0].ProfileID != denied {
		t.Fatalf("id prefix: %s", raw)
	}
	_, raw = r.list(path, r.reader, clBody{"limit": 2})
	p1 := decodeList[httpapi.ProfileListItem](t, 200, raw)
	if len(p1.Items) != 2 || !p1.More {
		t.Fatalf("page 1: %s", raw)
	}
	_, raw = r.list(path, r.reader, clBody{"limit": 2, "cursor": p1.NextCursor})
	if p2 := decodeList[httpapi.ProfileListItem](t, 200, raw); len(p2.Items) != 1 || p2.More || p2.Items[0].ProfileID != ok {
		t.Fatalf("page 2: %s", raw)
	}
	other := r.user(r.org, "profile-list-other@example.test")
	r.grant(r.org, other, r.project, true, auth.Read, httpapi.ProfilesRead)
	if status, raw = r.list(path, other, clBody{"limit": 2, "cursor": p1.NextCursor}); status != 400 || !strings.Contains(string(raw), "cursor_invalid") {
		t.Fatalf("cursor replayed by another caller: %d %s", status, raw)
	}
}

func TestProfileListNeedsItsOwnGrantAndTelemetryRead(t *testing.T) {
	r := newProfileRig(t)
	r.ingestProfile(t, model.UnixNano(time.Now().UnixNano()), "supported", "coverage_unmeasured", true)
	path := "/api/v1/profiles/list"
	telemetryOnly := r.user(r.org, "profile-list-telemetry@example.test")
	r.grant(r.org, telemetryOnly, r.project, true, auth.Read)
	profilesOnly := r.user(r.org, "profile-list-only@example.test")
	r.grant(r.org, profilesOnly, r.project, true, httpapi.ProfilesRead)

	status, raw := r.list(path, telemetryOnly, nil)
	if l := decodeList[httpapi.ProfileListItem](t, status, raw); l.State != httpapi.StateNotAvailable || l.Reason != httpapi.ReasonGrantRequired || len(l.Items) != 0 {
		t.Fatalf("telemetry.read without profiles.read: %s", raw)
	}
	if status, raw = r.list(path, profilesOnly, nil); status != 404 {
		t.Fatalf("profiles.read without telemetry.read: %d %s", status, raw)
	}
	fp := model.NewID()
	fo := r.isoEnv.org("foreign profile org", fp)
	foreign := r.user(fo, "profile-list-foreign@example.test")
	r.grant(fo, foreign, fp, true, auth.Read, httpapi.ProfilesRead)
	if status, raw = r.windowList(foreign, path, r.org, []model.ID{r.project}, r.from, r.to, nil); status != 404 {
		t.Fatalf("foreign org: %d %s", status, raw)
	}
	r.grant(r.org, r.reader, r.project, false, auth.Read, httpapi.ProfilesRead)
	if status, raw = r.list(path, r.reader, nil); status != 404 {
		t.Fatalf("revoked: %d %s", status, raw)
	}
}
