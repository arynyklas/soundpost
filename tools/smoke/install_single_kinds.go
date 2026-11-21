// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strconv"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/nativeperf"
)

// installKinds are the source-policy kinds the install smoke admits besides the five committed
// telemetry signals: the job, replay, profile and capability families of 07.01-W2.
var installKinds = []model.Kind{model.JobAttempt, model.Replay, model.Profile, model.CapabilityKind, model.Loss}

type installRecord struct {
	name   string
	record model.Record
}

// installExtraRecords returns one real, minimal record per extra kind: a job attempt, a replay
// chunk, a profile chunk assembled by the committed native assembler from sanitized synthetic
// events (no perf privilege exists here), and the three capability records that profile names.
func installExtraRecords(resource model.Resource, now int64) ([]installRecord, error) {
	at := model.UnixNano(now)
	clock := model.TraceClock{Wall: at, Mono: 1000, Domain: model.ClockDomain{Host: model.NewID(), Boot: model.NewID(), Runtime: model.NewID()}}
	terminal := model.UnixNano(now - int64(time.Second))
	job := model.JobAttemptEvent{Job: model.NewID(), Run: model.NewID(), Attempt: model.NewID(), Schedule: "install.smoke", Ordinal: 1, Epoch: model.NewID(), Sequence: 1, State: "succeeded", Observed: model.UnixNano(now - int64(2*time.Second)), Terminal: &terminal}
	replay := model.ReplayChunk{Replay: model.NewID(), Session: model.NewID(), Recorder: "1", Sequence: 1, CheckpointSequence: 1, PolicyRevision: 1, Clock: clock}

	d := nativeperf.ClockDomain{HostID: "host", BootID: "boot"}
	task := nativeperf.TaskKey{BootID: "boot", PIDNamespace: 1, TGID: 7, TID: 8, ProcessStart: 1, Generation: 1}
	caps := nativeperf.Capabilities{CPU: nativeperf.Supported, OffCPU: nativeperf.Denied, RunqueueSplit: nativeperf.Denied, Permissions: nativeperf.Permissions{CPUEventOpen: nativeperf.Supported, SchedulerEventOpen: nativeperf.Denied}, FrameCoverage: nativeperf.Coverage{Reasons: []nativeperf.Reason{nativeperf.ReasonUnmeasured}}, ThreadCoverage: nativeperf.Coverage{Reasons: []nativeperf.Reason{nativeperf.ReasonUnmeasured}}}
	var events []nativeperf.SanitizedEvent
	for i := range 3 {
		events = append(events, nativeperf.SanitizedEvent{Kind: nativeperf.EventCPU, Domain: d, Task: task, Sequence: model.Uint64(i + 1), Time: model.MonoNano(i + 1), CPUEvent: &nativeperf.CPUSample{IP: 4096, Callchain: []nativeperf.CallchainEntry{{IP: 4096}}, Method: nativeperf.MethodSoftwareCPUClock, Unit: nativeperf.UnitCPUClockNanoseconds, RequestedHz: 99, Period: 901}})
	}
	profile, err := nativeperf.AssembleProfile(context.Background(), events, nil, caps, nativeperf.ProfileLimits{Profile: model.NewID(), Process: model.NewID(), Capability: model.NewID(), Domain: d, PolicyRevision: 1, Sequence: 1, Start: at, End: at + 100,
		Clock: model.TraceClock{Wall: at, Domain: model.ClockDomain{Host: model.ID{4}, Boot: model.ID{5}, Runtime: model.ID{6}}}, Complete: true, MaxBytes: 8 << 20, MaxSamples: 8192, MaxIntervals: 8192, MaxFrames: 4096, MaxStacks: 4096})
	if err != nil {
		return nil, err
	}
	profile.Frames[0] = model.ProfileFrame{Reason: "frame_unresolved"}
	out := []installRecord{
		{"job_attempt", model.Record{ID: model.NewID(), Kind: model.JobAttempt, ObservedAt: job.Observed, Resource: resource, Payload: model.Payload{Job: &job}}},
		{"replay_chunk", model.Record{ID: model.NewID(), Kind: model.Replay, ObservedAt: clock.Wall, Resource: resource, Payload: model.Payload{Replay: &replay}}},
		{"profile_chunk", model.Record{ID: model.NewID(), Kind: model.Profile, ObservedAt: at, Resource: resource, Payload: model.Payload{Profile: &profile}}},
	}
	for i, method := range []string{"native_cpu", "native_offcpu", "native_runqueue_split"} {
		status, reason := "denied", "permission_denied"
		if i == 0 {
			status, reason = "supported", "coverage_unmeasured"
		}
		v := model.Capability{Runtime: "native_linux", Version: "1", Build: "owned", OS: "linux", Arch: "amd64", Signal: model.Profile, Method: method, Status: status, Reason: reason,
			Coverage: model.Coverage{Frames: "unknown", Threads: "unknown", Workers: "none", Tasks: "unknown"}, Clock: profile.Clock.Domain, Expires: at + model.UnixNano(time.Hour)}
		out = append(out, installRecord{"capability_" + method, model.Record{ID: profile.NativeCapabilities[i], Kind: model.CapabilityKind, ObservedAt: at, Resource: resource, Payload: model.Payload{Capability: &v}}})
	}
	return out, nil
}

// investigateInstalled runs the owned investigate reads as the project reader: the trace the
// installed span belongs to (through POST /api/v1/investigate and POST /api/v1/traces/view), the
// job and issue investigations. Every answer must be a 200 with a decoded, non-error state; the
// concatenated answers are compared byte for byte after the restart.
func investigateInstalled(site *installSite, fx *installFixture) ([]byte, error) {
	window := map[string]string{"start": "0", "end": strconv.FormatInt(time.Now().Add(time.Hour).UnixNano(), 10)}
	if fx.queryTime != "" {
		window["end"] = fx.queryTime
	}
	// state is the exact typed answer the served product gives today: the trace view is ready; the investigate
	// trace view is incomplete (its sections are not built); the job investigation of the ingested job is ready (job
	// and issue investigations require a target; internal/httpapi/investigate.go); the issue investigation as the
	// project reader is not_available (issue_evidence_needs_org_admin: the route derives the administrator scope only for an organization
	// administrator, and the reader is not one). A change of any of them is a change the smoke must be told about.
	reads := []struct {
		name, path, state string
		body              map[string]any
	}{
		{"investigate_trace", "/api/v1/investigate", "incomplete", map[string]any{"org": fx.org.String(), "kind": "trace", "projects": []string{fx.project.String()}, "target": fx.trace.String(), "window": window, "limit": 50}},
		{"trace_view", "/api/v1/traces/view", "ready", map[string]any{"org": fx.org.String(), "project": fx.project.String(), "trace": fx.trace.String(), "window": window}},
		{"investigate_job", "/api/v1/investigate", "ready", map[string]any{"org": fx.org.String(), "kind": "job", "projects": []string{fx.project.String()}, "target": fx.job.String(), "window": window, "limit": 50}},
		{"investigate_issue", "/api/v1/investigate", "not_available", map[string]any{"org": fx.org.String(), "kind": "issue", "projects": []string{fx.project.String()}, "target": fx.issue.String(), "window": window, "limit": 50}},
	}
	var all bytes.Buffer
	for _, r := range reads {
		status, raw, err := site.post(r.path, r.body, fx.reader.CSRF, "")
		if r.name == "investigate_job" {
			// The job book is committed by the background job producer after the ingest was acknowledged: until
			// it has, the target is the one NotFound. Wait for that commit, bounded; any other answer ends the wait.
			for deadline := time.Now().Add(90 * time.Second); err == nil && status == 404 && time.Now().Before(deadline); {
				time.Sleep(500 * time.Millisecond)
				status, raw, err = site.post(r.path, r.body, fx.reader.CSRF, "")
			}
		}
		if err = requireSmokeResponse(r.name, status, 200, raw, err); err != nil {
			return nil, err
		}
		var view struct {
			State  string `json:"state"`
			Reason string `json:"reason"`
		}
		if err = json.Unmarshal(raw, &view); err != nil || view.State == "" {
			return nil, &smokeFailure{Stage: r.name, Code: "decode"}
		}
		if view.State != r.state {
			return nil, &smokeFailure{Stage: r.name, Code: "unexpected_view_state_" + view.State + "_" + view.Reason}
		}
		all.WriteString(r.name)
		all.Write(raw)
	}
	return all.Bytes(), nil
}
