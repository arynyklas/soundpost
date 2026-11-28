// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package acceptance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/fixtures/nativeperf/realcapture"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/nativeperf"
	"github.com/arynyklas/soundpost/internal/policy"
)

// evOwnerPassword is the bootstrap password of the evidence node's instance owner.
const evOwnerPassword = "evidence owner password 2026"

// ownerCred is the owner's credential, signed in again when it is no longer fresh. Instance-level and administrative actions need a
// credential authenticated within the last five minutes (auth.Credential.Fresh); a slow run (the whole acceptance takes about 25 minutes
// under -race) would otherwise be refused by a rule that must stay as strict as it is.
func (n *evNode) ownerCred() auth.Credential {
	if n.owner.cred.Fresh() {
		return n.owner.cred
	}
	s, err := n.app.Auth.Reauthenticate(n.ctx, n.owner.session.Token, evOwnerPassword, "")
	if err != nil {
		n.t.Fatalf("owner sign-in again: %v", err)
	}
	c, err := n.app.Auth.Authenticate(n.ctx, s.Token)
	if err != nil {
		n.t.Fatalf("owner credential after sign-in again: %v", err)
	}
	n.owner.session, n.owner.cred = s, c
	return c
}

// evCaptureExitCannot is fixtures/nativeperf/e2eprofile's exit status for a host that cannot take the capture at all.
const evCaptureExitCannot = 3

// evRealCapture takes the REAL native CPU capture the profile_real_capture_or_sdk row needs: the compiled fixtures/nativeperf/cpu/loop.c
// under the native helper (perf_event_open CPU-clock samples of a real process). The capture runs in a CHILD process (the e2eprofile tool
// built with the same toolchain): the helper charges its own process's resident memory against its budget, which is right for the small
// helper process of an installation and refuses a race-instrumented test binary (resource_limit), so the helper must not be the test
// process. A host that cannot take the capture (no compiler, not Linux, the event is not openable) answers why and the row must then say
// so; any other failure of a capture that should work fails the run.
func evRealCapture(t *testing.T, dir string) (realcapture.Result, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	workload, err := realcapture.BuildWorkload(ctx, filepath.Join("..", "..", "fixtures", "nativeperf", "cpu", "loop.c"), dir)
	var cannot *realcapture.CannotCapture
	if errors.As(err, &cannot) {
		return realcapture.Result{}, cannot.Reason
	}
	if err != nil {
		t.Fatalf("the native workload does not build: %v", err)
	}
	tool := filepath.Join(dir, "e2eprofile")
	if out, err := exec.CommandContext(ctx, "go", "build", "-o", tool, filepath.Join("..", "..", "fixtures", "nativeperf", "e2eprofile")).CombinedOutput(); err != nil {
		t.Fatalf("the native capture tool does not build: %v: %s", err, out)
	}
	events := filepath.Join(dir, "capture.json")
	cmd := exec.CommandContext(ctx, tool, "-workload", workload, "-events-out", events, "-seconds", "5")
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == evCaptureExitCannot {
		return realcapture.Result{}, string(out)
	}
	if err != nil {
		t.Fatalf("a native CPU capture that this host should take failed: %v: %s", err, out)
	}
	raw, err := os.ReadFile(events)
	var got realcapture.Result
	if err != nil || json.Unmarshal(raw, &got) != nil || len(got.Events) == 0 {
		t.Fatalf("the capture tool left no readable capture: %v", err)
	}
	return got, ""
}

// realCaptureRow is the profile_real_capture_or_sdk row: the capture newEvNode took from a real process (perf_event_open CPU-clock samples,
// not constructed events) goes through the real exporter, the real HTTPS ingest route and the real C10 profile view of a reader with
// profiles.read. On a host that cannot capture the row says why and is unsatisfied; nothing constructed ever stands in for it.
func (n *evNode) realCaptureRow(r *evReport) {
	t := n.t
	t.Helper()
	if n.captureWhy != "" {
		r.add("profile_real_capture_or_sdk", true, false, "this host cannot take a real native CPU capture ("+n.captureWhy+"): no perf-captured sample exists to deliver, and constructed events never count as one")
		return
	}
	c := n.capture
	domain := c.Events[0].Domain
	wall := model.UnixNano(time.Now().UnixNano())
	last := c.FirstMono
	for _, ev := range c.Events {
		if ev.Time > last {
			last = ev.Time
		}
	}
	root := model.NewID()
	limits := nativeperf.ProfileLimits{Profile: root, Process: model.NewID(), Capability: model.NewID(), Domain: domain, PolicyRevision: 1, Sequence: 1, Start: wall, End: wall + model.UnixNano(last-c.FirstMono) + 1,
		Clock: model.TraceClock{Wall: wall, Mono: c.FirstMono, Domain: model.ClockDomain{Host: model.NewID(), Boot: model.NewID(), Runtime: model.NewID()}}, Complete: false, MaxBytes: 8 << 20, MaxSamples: 8192, MaxIntervals: 8192, MaxFrames: 4096, MaxStacks: 4096, Mappings: c.Mappings}
	exporter, err := nativeperf.NewExporter(evAdmitter{n}, evLookup{n}, nativeperf.ExportConfig{Project: n.projA, Source: n.srcA, Producer: model.NewID(), Resource: n.res, Limits: limits, Capabilities: c.Capabilities}, evLease{})
	if err != nil {
		t.Fatal(err)
	}
	defer exporter.Close()
	pol, err := policy.New(n.app.Auth, nil)
	if err != nil {
		t.Fatal(err)
	}
	g, err := pol.ResolveSource(n.ctx, n.srcCredA, n.projA, n.srcA, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = exporter.Send(n.ctx, g, nativeperf.ProfileChunk{ProfileID: root, PolicyRevision: 1, Domain: domain, Events: c.Events}); err != nil || !exporter.Stats().Admitted {
		t.Fatalf("the real exporter did not get the REAL captured profile admitted over HTTPS: %v", err)
	}
	body := func(p model.ID) map[string]any {
		return map[string]any{"org": n.orgA, "project": n.projA, "profile": p, "window": map[string]any{"start": wall, "end": wall + 10_000_000_000}}
	}
	got := n.post(n.analyst, "/api/v1/profiles/view", body(root))
	var pv httpapi.ProfileResponse
	if got.status != 200 || json.Unmarshal(got.body, &pv) != nil || pv.View == nil || pv.Profile != root {
		t.Fatalf("profile view of the real capture: %d %s", got.status, got.body)
	}
	v := *pv.View
	if v.Method != "native_cpu" || v.Units != "samples" || len(v.Samples) != c.CPUSamples || v.NextCursor != "" {
		t.Fatalf("the view of the real capture holds %d samples (next cursor %q), method %s units %s; the capture took %d CPU samples", len(v.Samples), v.NextCursor, v.Method, v.Units, c.CPUSamples)
	}
	for i, s := range v.Samples {
		if s.Native == nil || s.Native.Method != string(nativeperf.MethodSoftwareCPUClock) || uint64(s.Native.Period) != c.Period || s.Native.RequestedHz != 99 {
			t.Fatalf("sample %d does not carry the captured method and period: %+v", i, s.Native)
		}
	}
	byMethod := map[string]string{}
	for _, cr := range v.Capabilities {
		byMethod[cr.Value.Method] = cr.Value.Status
	}
	if len(v.Capabilities) != 3 || byMethod["native_cpu"] != string(nativeperf.Supported) || byMethod["native_offcpu"] != string(c.Capabilities.OffCPU) || byMethod["native_runqueue_split"] != string(c.Capabilities.RunqueueSplit) {
		t.Fatalf("the view's capability records are not the probe's: %v want cpu=%s offcpu=%s runqueue=%s", byMethod, nativeperf.Supported, c.Capabilities.OffCPU, c.Capabilities.RunqueueSplit)
	}
	if v.BlockedNano != nil || v.RunnableNano != nil || v.UnknownNano != nil {
		t.Fatal("a CPU-only capture reported scheduler time")
	}
	if st := n.post(n.plain, "/api/v1/profiles/view", body(root)).status; st == 200 {
		t.Fatalf("a reader without profiles.read opened the real profile: %d", st)
	}
	r.add("profile_real_capture_or_sdk", true, true, fmt.Sprintf("REAL perf capture (kernel %s, perf_event_open software CPU-clock, %d CPU samples, %d in the workload's hot loop, %d threads, period %d) through the real exporter, admitted over HTTPS, read through /profiles/view with the probe's capability records (off_cpu %s, runqueue_split %s); a reader without profiles.read refused", c.Capabilities.Kernel, c.CPUSamples, c.HotSamples, c.Threads, c.Period, c.Capabilities.OffCPU, c.Capabilities.RunqueueSplit))
}
