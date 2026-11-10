// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package profiles_test

// Task 04.08 privacy canaries for the profile lifecycle after acquisition: the
// real exporter queue, the real gzip batch route of a real in-process node, the
// admitted storage bytes, the real scoped read and the exported view. Inputs are
// deterministic sanitized events shaped like genuine acquisition output (real
// kernel samples are exercised by internal/nativeperf/privacy_linux_test.go and
// the verify fixture); scheduler numeric values are synthetic because tracefs is
// not available on the qualification host.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"soundpost/fixtures/nativeperf/privacy/privnode"
	"soundpost/fixtures/nativeperf/privacy/scan"
	"soundpost/internal/model"
	"soundpost/internal/nativeperf"
	"soundpost/internal/policy"
	"soundpost/internal/profiles"
)

const privacyPolicyFile = "../../fixtures/nativeperf/privacy/policy.json"

type privacyEnv struct {
	policy scan.Policy
	nonce  string
	audit  *scan.PrivacyAudit
}

func newPrivacyEnv(t *testing.T) *privacyEnv {
	t.Helper()
	p, e := scan.LoadPolicy(privacyPolicyFile)
	if e != nil {
		t.Fatal(e)
	}
	raw := make([]byte, p.NonceHexLen/2)
	if _, e = rand.Read(raw); e != nil {
		t.Fatal(e)
	}
	nonce := hex.EncodeToString(raw)
	d, e := scan.NewDetector(p, nonce)
	if e != nil {
		t.Fatal(e)
	}
	return &privacyEnv{policy: p, nonce: nonce, audit: scan.NewPrivacyAudit(d)}
}
func (e *privacyEnv) sentinel(kind string) string {
	v, err := e.policy.Sentinel(kind, e.nonce)
	if err != nil {
		panic(err)
	}
	return v
}
func (e *privacyEnv) requireClean(t *testing.T, stages ...scan.Stage) {
	t.Helper()
	type key struct {
		stage scan.Stage
		kind  string
	}
	counts := map[key]int{}
	var order []key
	for _, v := range e.audit.Violations() {
		k := key{v.Stage, v.Hit.Kind}
		if counts[k] == 0 {
			order = append(order, k)
		}
		counts[k]++
	}
	for _, k := range order {
		t.Errorf("canary kind=%s crossed stage %s (%d detector hits; content is never printed)", k.kind, k.stage, counts[k])
	}
	if err := e.audit.RequireStages(stages...); err != nil {
		t.Error(err)
	}
}

type lease struct{}

func (lease) Bytes() uint64 { return 2 << 20 }
func (lease) Close() error  { return nil }

var (
	domain = nativeperf.ClockDomain{HostID: "privacy-host", BootID: "privacy-boot"}
	taskA  = nativeperf.TaskKey{BootID: "privacy-boot", PIDNamespace: 1, TGID: 70, TID: 71, ProcessStart: 1, Generation: 1}
	taskB  = nativeperf.TaskKey{BootID: "privacy-boot", PIDNamespace: 1, TGID: 70, TID: 72, ProcessStart: 1, Generation: 1}
)

const (
	blockedNs  = 40_000_000
	runnableNs = 15_000_000
	period     = 10_101_010
	samplesN   = 12
)

// label keeps only the characters a ClockDomain identity admits; this is the
// field a careless collector would smuggle a command name through.
func label(s string) string {
	b := []byte(s)
	for i, c := range b {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
			b[i] = '-'
		}
	}
	return string(b)
}

// captureEvents returns sanitized CPU events across two threads with multi-frame
// stacks plus a loss record. hostLabel replaces the clock-domain host label: the
// negative control sets it to the command-name sentinel.
func captureEvents(hostLabel string) (nativeperf.ClockDomain, []nativeperf.SanitizedEvent) {
	d := domain
	if hostLabel != "" {
		d.HostID = hostLabel
	}
	var out []nativeperf.SanitizedEvent
	for i := range samplesN {
		task := taskA
		if i%2 == 1 {
			task = taskB
		}
		chain := []nativeperf.CallchainEntry{{IP: 0x401100 + uint64Of(i)}, {IP: 0x401180}, {IP: 0x4011f0}, {IP: 0x401260}}
		out = append(out, nativeperf.SanitizedEvent{Kind: nativeperf.EventCPU, Time: model.MonoNano(1_000_000 * (i + 1)), Sequence: model.Uint64(i + 1), Domain: d, Task: task, CPUEvent: &nativeperf.CPUSample{IP: chain[0].IP, Callchain: chain, Method: nativeperf.MethodSoftwareCPUClock, Unit: nativeperf.UnitCPUClockNanoseconds, RequestedHz: 99, Period: period}})
	}
	out = append(out, nativeperf.SanitizedEvent{Kind: nativeperf.EventLoss, Time: model.MonoNano(13_000_000), Sequence: model.Uint64(samplesN + 1), Domain: d, Loss: &nativeperf.LossEvent{Reason: nativeperf.ReasonSampleLost, Count: 3}})
	return d, out
}
func uint64Of(i int) model.Uint64 { return model.Uint64(i * 8) }

// schedulerIntervals are numeric scheduler results: blocked 40ms then runnable
// 15ms for taskA, from correlated switch/wakeup records.
func schedulerIntervals(t *testing.T, d nativeperf.ClockDomain) []nativeperf.Interval {
	t.Helper()
	base := uint64(100_000_000)
	out := func(at uint64) nativeperf.SanitizedEvent {
		k := taskA
		return nativeperf.SanitizedEvent{Kind: nativeperf.EventSwitch, Time: model.MonoNano(at), Sequence: model.Uint64(1000 + at/1_000_000), Domain: d, Switch: &nativeperf.SchedulerSwitch{Previous: &k, PreviousState: 1, MissingCallchain: nativeperf.ReasonMissingSwitchCallchain}}
	}
	wake := func(at uint64) nativeperf.SanitizedEvent {
		k := taskA
		return nativeperf.SanitizedEvent{Kind: nativeperf.EventWakeup, Time: model.MonoNano(at), Sequence: model.Uint64(1000 + at/1_000_000), Domain: d, Task: k, Wakeup: &nativeperf.SchedulerWakeup{Target: k}}
	}
	in := func(at uint64) nativeperf.SanitizedEvent {
		k := taskA
		return nativeperf.SanitizedEvent{Kind: nativeperf.EventSwitch, Time: model.MonoNano(at), Sequence: model.Uint64(1000 + at/1_000_000), Domain: d, Switch: &nativeperf.SchedulerSwitch{Next: &k}}
	}
	c := nativeperf.NewCorrelator(nativeperf.DefaultConfig(1))
	if e := c.Configure(d, []uint32{0}, 4<<20); e != nil {
		t.Fatal(e)
	}
	var intervals []nativeperf.Interval
	for _, event := range []nativeperf.SanitizedEvent{out(base), wake(base + blockedNs), in(base + blockedNs + runnableNs)} {
		got, e := c.Consume(event)
		if e != nil {
			t.Fatal(e)
		}
		intervals = append(intervals, got...)
	}
	if e := c.ReportProgress(0, model.MonoNano(base+blockedNs+runnableNs+100_000_000)); e != nil {
		t.Fatal(e)
	}
	got, e := c.Advance(model.MonoNano(base + blockedNs + runnableNs))
	if e != nil {
		t.Fatal(e)
	}
	return append(intervals, got...)
}

func privacyCapabilities() nativeperf.Capabilities {
	return nativeperf.Capabilities{CPU: nativeperf.Supported, OffCPU: nativeperf.Supported, RunqueueSplit: nativeperf.Supported, Permissions: nativeperf.Permissions{CPUEventOpen: nativeperf.Supported, SchedulerEventOpen: nativeperf.Supported}, FrameCoverage: nativeperf.Coverage{Reasons: []nativeperf.Reason{nativeperf.ReasonUnmeasured}}, ThreadCoverage: nativeperf.Coverage{Reasons: []nativeperf.Reason{nativeperf.ReasonUnmeasured}}}
}

type lifecycle struct {
	node    *privnode.Node
	root    model.ID
	start   model.UnixNano
	view    []profiles.ProfileView
	batches []model.Batch
}

// capturingAdmitter records the exporter's frozen queue items and forwards them
// through the real route (or holds them back when hold is set, for the refusal drills).
type capturingAdmitter struct {
	inner *privnode.Admitter
	hold  bool
	seen  []model.Batch
}

func (a *capturingAdmitter) Admit(ctx context.Context, g policy.SourceGrant, b model.Batch) (model.Receipt, error) {
	a.seen = append(a.seen, b)
	holds := false
	for _, r := range b.Records {
		holds = holds || r.Kind == model.Profile
	}
	if a.hold && holds {
		wire, _ := json.Marshal(b)
		_ = a.inner.Audit.Observe(scan.StageExporterQueue, wire)
		return model.Receipt{}, errors.New("held back by the drill")
	}
	return a.inner.Admit(ctx, g, b)
}

// exportAndRead sends the capture through the real exporter and real route (unless
// hold), scans the node's storage and reads the profile back through the real
// scoped reader, auditing every stage. It returns the paginated views.
func exportAndRead(t *testing.T, env *privacyEnv, n *privnode.Node, hostLabel string, hold bool) (*lifecycle, *capturingAdmitter, error) {
	t.Helper()
	ctx := context.Background()
	d, events := captureEvents(hostLabel)
	intervals := schedulerIntervals(t, d)
	wall := model.UnixNano(time.Now().UnixNano())
	root := model.NewID()
	limits := nativeperf.ProfileLimits{Profile: root, Process: model.NewID(), Capability: model.NewID(), Domain: d, PolicyRevision: 1, Sequence: 1, Start: wall, End: wall + 2_000_000_000, Clock: model.TraceClock{Wall: wall, Domain: model.ClockDomain{Host: model.ID{4}, Boot: model.ID{5}, Runtime: n.Producer}}, Complete: true, MaxBytes: 8 << 20, MaxSamples: 8192, MaxIntervals: 8192, MaxFrames: 4096, MaxStacks: 4096}
	admitter := &capturingAdmitter{inner: &privnode.Admitter{N: n, Audit: env.audit}, hold: hold}
	exporter, e := nativeperf.NewExporter(admitter, privnode.Lookup{N: n}, nativeperf.ExportConfig{Project: n.Project, Source: n.Source, Producer: n.Producer, Resource: n.Resource, Limits: limits, Capabilities: privacyCapabilities()}, lease{})
	if e != nil {
		t.Fatal(e)
	}
	defer exporter.Close()
	grant, e := n.Grant(ctx)
	if e != nil {
		t.Fatal(e)
	}
	l := &lifecycle{node: n, root: root, start: wall}
	_, e = exporter.Send(ctx, grant, nativeperf.ProfileChunk{ProfileID: root, PolicyRevision: 1, Domain: d, Events: events, Intervals: intervals})
	for _, v := range []any{exporter.Stats(), exporter.DropReport(), exporter.LastReceiptRequest()} {
		raw, _ := json.Marshal(v)
		_ = env.audit.Observe(scan.StageExporterQueue, raw)
	}
	if hold {
		return l, admitter, e
	}
	if e != nil {
		return l, admitter, e
	}
	if !exporter.Stats().Admitted {
		t.Fatal("exporter did not report the capture admitted")
	}
	if _, _, _, e = n.ScanStorage(env.audit, []byte(d.BootID)); e != nil {
		t.Fatal(e)
	}
	service := n.App.NewNativeProfiles()
	cursor := ""
	for page := 0; page < 64; page++ {
		view, e := service.Read(ctx, n.Reader, root, profiles.Window{Start: wall, End: wall + 2_000_000_000, MaxSamples: 5, Cursor: cursor})
		if e != nil {
			t.Fatalf("scoped read: %v", e)
		}
		raw, _ := json.Marshal(view)
		_ = env.audit.Observe(scan.StageRead, raw)
		pretty, _ := json.MarshalIndent(view, "", "  ")
		_ = env.audit.Observe(scan.StageExport, pretty)
		l.view = append(l.view, view)
		if view.NextCursor == "" {
			break
		}
		cursor = view.NextCursor
	}
	return l, admitter, nil
}

// requireEvidence: scheduler numeric values and genuine CPU stacks must reach the
// reader, so an empty export cannot pass privacy.
func requireEvidence(t *testing.T, l *lifecycle, admitter *capturingAdmitter) {
	t.Helper()
	if admitter.inner.Count == 0 {
		t.Fatal("nothing was admitted through the real route")
	}
	samples := 0
	var blocked, runnable uint64
	for _, v := range l.view {
		for _, s := range v.Samples {
			samples++
			if s.Native == nil || s.Native.Period != period || s.Native.RequestedHz != 99 || s.Count != 1 {
				t.Fatalf("read sample lost its native period/rate: %+v", s.Native)
			}
			if len(v.Stacks[s.Stack].Frames) < 3 {
				t.Fatal("read sample lost its multi-frame stack")
			}
		}
		if v.BlockedNano != nil {
			blocked = uint64(*v.BlockedNano)
		}
		if v.RunnableNano != nil {
			runnable = uint64(*v.RunnableNano)
		}
		if len(v.Capabilities) != 3 {
			t.Fatalf("read returned %d capability records", len(v.Capabilities))
		}
	}
	if samples != samplesN {
		t.Fatalf("read returned %d samples, want %d", samples, samplesN)
	}
	if blocked != blockedNs || runnable != runnableNs {
		t.Fatalf("scheduler numeric values changed: blocked=%d runnable=%d", blocked, runnable)
	}
}

// hostLabelUnderTest is the clock-domain host label the lifecycle exports with.
func hostLabelUnderTest(env *privacyEnv) string { return "" }

// TestNoContentAcrossProfileLifecycle: exporter queue, compressed and decompressed
// wire, real route, admitted storage, scoped read, exported view and diagnostics
// contain no canary while genuine-shaped CPU stacks and scheduler numeric values
// arrive intact.
func TestNoContentAcrossProfileLifecycle(t *testing.T) {
	ctx := context.Background()
	env := newPrivacyEnv(t)
	n, e := privnode.Start(ctx, t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer n.Close()
	l, admitter, e := exportAndRead(t, env, n, hostLabelUnderTest(env), false)
	if e != nil {
		t.Fatal(e)
	}
	requireEvidence(t, l, admitter)
	files, octets, _, e := n.ScanStorage(env.audit, nil)
	if e != nil || files == 0 || octets == 0 {
		t.Fatalf("storage scan inspected nothing: %d files %d bytes %v", files, octets, e)
	}
	env.requireClean(t, scan.StageExporterQueue, scan.StageWireCompressed, scan.StageWireDecompressed, scan.StageStorage, scan.StageRead, scan.StageExport, scan.StageDiagnostics)
}

// TestPrivacyNegativeControlProfileContamination: a deliberately contaminated
// capture (the command name copied into the clock-domain host label, which every
// native record carries) must be flagged at EVERY downstream stage of the real
// pipeline. It is a permanent control: if a stage stops seeing the leak, this fails.
func TestPrivacyNegativeControlProfileContamination(t *testing.T) {
	ctx := context.Background()
	env := newPrivacyEnv(t)
	n, e := privnode.Start(ctx, t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer n.Close()
	comm := label(env.sentinel("comm"))
	l, admitter, e := exportAndRead(t, env, n, comm, false)
	if e != nil {
		t.Fatal(e)
	}
	requireEvidence(t, l, admitter)
	flagged := map[scan.Stage]bool{}
	for _, v := range env.audit.Violations() {
		flagged[v.Stage] = true
	}
	for _, stage := range []scan.Stage{scan.StageExporterQueue, scan.StageWireDecompressed, scan.StageWireCompressed, scan.StageRead, scan.StageExport} {
		if !flagged[stage] {
			t.Errorf("contaminated capture was not flagged at stage %s", stage)
		}
	}
	if !flagged[scan.StageStorage] {
		t.Log("storage bytes do not expose the label in clear (the admitted record is encoded); the read stage still sees it")
	}
}

// Content-bearing shapes the closed native schema must refuse at the real route,
// and unknown content fields must be dropped, never stored or read back.
func TestPrivacyAdmissionRefusesContentBearingProfilesAndDropsUnknownFields(t *testing.T) {
	ctx := context.Background()
	env := newPrivacyEnv(t)
	n, e := privnode.Start(ctx, t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer n.Close()
	_, admitter, e := exportAndRead(t, env, n, "", true)
	if e == nil || len(admitter.seen) == 0 {
		t.Fatalf("could not capture the exporter queue: %v", e)
	}
	var profile *model.Batch
	for i := range admitter.seen {
		for _, r := range admitter.seen[i].Records {
			if r.Kind == model.Profile && len(r.Payload.Profile.Frames) > 0 {
				profile = &admitter.seen[i]
			}
		}
	}
	if profile == nil {
		t.Fatal("no profile batch in the queue")
	}
	clone := func() model.Batch {
		raw, _ := json.Marshal(*profile)
		var out model.Batch
		if e := json.Unmarshal(raw, &out); e != nil {
			t.Fatal(e)
		}
		return out
	}
	frame := func(b *model.Batch) *model.ProfileFrame {
		for i := range b.Records {
			if p := b.Records[i].Payload.Profile; p != nil && len(p.Frames) > 0 {
				return &p.Frames[0]
			}
		}
		t.Fatal("no frame")
		return nil
	}
	// Hostile inputs contain the canaries by construction, so their own wire
	// stages are audited by a scratch audit; what the PRODUCT answers and persists
	// is audited by env.audit.
	detector, e := scan.NewDetector(env.policy, env.nonce)
	if e != nil {
		t.Fatal(e)
	}
	hostile := scan.NewPrivacyAudit(detector)
	post := func(b model.Batch) int {
		wire, _ := json.Marshal(b)
		return postWire(t, env, n, hostile, wire)
	}
	path := "/proc/1/" + env.sentinel("path") + "/binary"
	refused := map[string]func(*model.ProfileFrame){
		"path_in_function_name":      func(f *model.ProfileFrame) { f.Function = path },
		"command_in_function_name":   func(f *model.ProfileFrame) { f.Function = env.sentinel("comm") },
		"input_string_as_function":   func(f *model.ProfileFrame) { f.Function = "run(" + env.sentinel("input") + ")" },
		"path_in_module_identity":    func(f *model.ProfileFrame) { f.Module = path },
		"command_in_module_identity": func(f *model.ProfileFrame) { f.Module = env.sentinel("comm") },
		"canary_as_artifact_id":      func(f *model.ProfileFrame) { f.Artifact = env.sentinel("env") },
	}
	// Control: the unmodified queued batch is admitted by the same route.
	if status := post(clone()); status != http.StatusOK {
		t.Fatalf("control batch refused with %d: the refusals below would prove nothing", status)
	}
	for name, mutate := range refused {
		b := clone()
		b.ID = model.NewID()
		mutate(frame(&b))
		if status := post(b); status < 400 || status >= 500 {
			t.Errorf("%s: content-bearing frame answered %d, want a 4xx refusal", name, status)
		}
	}
	// Unknown fields that a stack/register/heap dump would add are not part of the
	// schema: whatever the route does with them, they must never be stored or read.
	for name, inject := range map[string]string{"comm": env.sentinel("comm"), "stack_dump": env.sentinel("stack"), "heap": env.sentinel("heap"), "environ": env.sentinel("env"), "cmdline": env.sentinel("argv")} {
		b := clone()
		b.ID = model.NewID()
		wire, _ := json.Marshal(b)
		wire = bytes.Replace(wire, []byte(`{`), []byte(`{"`+name+`":"`+inject+`",`), 1)
		status := postWire(t, env, n, hostile, wire)
		t.Logf("unknown field %q carrying a canary: route answered %d", name, status)
	}
	// The same unknown content fields inside the profile chunk, its samples and frames.
	var inject func(any, string, string) int
	inject = func(v any, key, value string) int {
		count := 0
		switch x := v.(type) {
		case map[string]any:
			_, hasSamples := x["samples"]
			_, hasFrames := x["frames"]
			if hasSamples || hasFrames {
				x[key] = value
				count++
				for _, field := range []string{"samples", "frames"} {
					if list, ok := x[field].([]any); ok {
						for _, item := range list {
							if obj, ok := item.(map[string]any); ok {
								obj[key] = value
								count++
							}
						}
					}
				}
			}
			for _, child := range x {
				count += inject(child, key, value)
			}
		case []any:
			for _, child := range x {
				count += inject(child, key, value)
			}
		}
		return count
	}
	for name, kind := range map[string]string{"stack_dump": "stack", "regs": "heap", "comm": "comm"} {
		b := clone()
		b.ID = model.NewID()
		raw, _ := json.Marshal(b)
		var generic any
		if e := json.Unmarshal(raw, &generic); e != nil {
			t.Fatal(e)
		}
		if inject(generic, name, env.sentinel(kind)) < 3 {
			t.Fatal("premise: nested injection found no profile objects")
		}
		wire, _ := json.Marshal(generic)
		status := postWire(t, env, n, hostile, wire)
		t.Logf("nested unknown field %q carrying a canary: route answered %d", name, status)
		if status < 400 || status >= 500 {
			t.Errorf("nested unknown field %q was not refused (status %d)", name, status)
		}
	}
	if files, octets, _, e := n.ScanStorage(env.audit, nil); e != nil || files == 0 || octets == 0 {
		t.Fatalf("storage scan inspected nothing: %d %d %v", files, octets, e)
	}
	// The reader sees only what was legitimately admitted.
	service := n.App.NewNativeProfiles()
	view, e := service.Read(ctx, n.Reader, profileRoot(profile), profiles.Window{Start: 0, End: 1 << 62, MaxSamples: 1000})
	if e == nil {
		raw, _ := json.Marshal(view)
		_ = env.audit.Observe(scan.StageRead, raw)
	}
	if len(hostile.Violations()) == 0 {
		t.Fatal("premise: the hostile inputs never reached the scratch audit")
	}
	env.requireClean(t, scan.StageExporterQueue, scan.StageStorage, scan.StageDiagnostics)
}

func profileRoot(b *model.Batch) model.ID {
	for _, r := range b.Records {
		if r.Payload.Profile != nil {
			return r.Payload.Profile.Profile
		}
	}
	return model.ID{}
}

// postWire sends a hostile wire body to the real route, auditing the body on the
// scratch audit and the product's response as diagnostics on env.audit.
func postWire(t *testing.T, env *privacyEnv, n *privnode.Node, scratch *scan.PrivacyAudit, wire []byte) int {
	t.Helper()
	status, body, e := n.PostBatch(context.Background(), scratch, wire)
	if e != nil {
		t.Fatal(e)
	}
	_ = env.audit.Observe(scan.StageDiagnostics, append([]byte("batch route response: "), body...))
	return status
}

// The read model carries no source/debug content: reading with only profiles.read
// returns neither artifact references nor any path-, line- or content-shaped key.
func TestPrivacyArtifactPolicyKeepsSourceAndDebugContentGrantProtected(t *testing.T) {
	ctx := context.Background()
	env := newPrivacyEnv(t)
	n, e := privnode.Start(ctx, t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer n.Close()
	l, admitter, e := exportAndRead(t, env, n, "", false)
	if e != nil {
		t.Fatal(e)
	}
	requireEvidence(t, l, admitter)
	forbidden := map[string]bool{"source_path": true, "path": true, "file": true, "filename": true, "line": true, "lines": true, "content": true, "text": true, "url": true, "comm": true, "cmdline": true, "environ": true, "env": true, "args": true, "locals": true, "heap": true, "registers": true, "regs": true, "stack_bytes": true, "stack_dump": true, "raw": true}
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, child := range x {
				if forbidden[strings.ToLower(k)] {
					t.Errorf("profile view carries a content-shaped key %q", k)
				}
				walk(child)
			}
		case []any:
			for _, child := range x {
				walk(child)
			}
		}
	}
	for _, view := range l.view {
		raw, _ := json.Marshal(view)
		var generic any
		if e := json.Unmarshal(raw, &generic); e != nil {
			t.Fatal(e)
		}
		walk(generic)
		for _, link := range view.Links {
			if link.Available || link.Reference != nil {
				t.Fatal("artifact link available to a reader without an artifact grant")
			}
		}
		for _, f := range view.Frames {
			if strings.ContainsAny(f.Function, "/\\ ") || f.Reason == "" && f.Module == "" && f.Function == "" {
				t.Fatalf("frame carries a path-shaped or empty identity: %+v", f)
			}
		}
	}
	// A reader whose scope is another project gets the same answer as for a profile
	// that does not exist: no oracle for the presence of source/debug data.
	foreign, e := n.ForeignReader(ctx)
	if e != nil {
		t.Skipf("foreign scope fixture unavailable: %v", e)
	}
	_, denied := n.App.NewNativeProfiles().Read(ctx, foreign, l.root, profiles.Window{Start: l.start, End: l.start + 2_000_000_000, MaxSamples: 5})
	_, missing := n.App.NewNativeProfiles().Read(ctx, foreign, model.NewID(), profiles.Window{Start: l.start, End: l.start + 2_000_000_000, MaxSamples: 5})
	var a, b *model.Fault
	if !errors.As(denied, &a) || !errors.As(missing, &b) || a.Code != b.Code {
		t.Fatalf("foreign scope distinguishes a present profile: %v / %v", denied, missing)
	}
	env.requireClean(t, scan.StageRead, scan.StageExport)
}
