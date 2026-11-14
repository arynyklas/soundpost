// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/policy"
	"io"
	"os"
	"reflect"
	"testing"
)

func typedRows(resource model.Resource) []model.Record {
	id := model.NewID()
	span := model.SpanID{1}
	clock := model.TraceClock{Wall: 1, Mono: 1, Domain: model.ClockDomain{Host: model.NewID(), Boot: model.NewID(), Runtime: model.NewID()}}
	end := clock
	end.Mono = 2
	terminal := model.UnixNano(2)
	ordinal := uint32(0)
	var safe model.Scalar
	_ = json.Unmarshal([]byte(`9007199254740993`), &safe)
	cpuCapability, offCPUCapability, runqueueCapability := model.NewID(), model.NewID(), model.NewID()
	nativeDomain := &model.ProfileNativeDomain{HostID: clock.Domain.Host.String(), BootID: clock.Domain.Boot.String()}
	nativeTask := model.ProfileNativeTask{BootID: nativeDomain.BootID, PIDNamespace: 1, TGID: 10, TID: 11, ProcessStart: 1, Generation: 1}
	kinds := []model.Kind{model.Metric, model.Metric, model.Metric, model.Metric, model.Log, model.Log, model.SpanKind, model.ErrorKind, model.JobAttempt, model.Replay, model.Profile, model.CapabilityKind, model.Loss, model.Condition}
	payloads := []model.Payload{
		{Metric: &model.MetricPoint{Name: "nan", Labels: model.Labels{{Name: "zone", Value: "a"}}, SampleKind: "float", Value: ptrBits(0x7ff8000000000001), Unit: "1", Type: "gauge"}},
		{Metric: &model.MetricPoint{Name: "stale", Labels: model.Labels{}, SampleKind: "stale", Value: ptrBits(0x7ff0000000000002), Unit: "1", Type: "gauge"}},
		{Metric: &model.MetricPoint{Name: "integer", Labels: model.Labels{}, SampleKind: "integer_histogram", Histogram: &model.NativeHistogram{Integer: &model.IntegerHistogram{Flavor: "counter", Count: 9007199254740993, ZeroCount: 1, ResetHint: "reset", Sum: 0x8000000000000000, PositiveSpans: []model.HistogramSpan{{Offset: -2, Length: 2}}, PositiveBuckets: []model.DeltaBucket{4503599627370496, 0}}}, Unit: "1", Type: "histogram"}},
		{Metric: &model.MetricPoint{Name: "float", Labels: model.Labels{}, SampleKind: "float_histogram", Histogram: &model.NativeHistogram{Float: &model.FloatHistogram{Flavor: "gauge", Count: 0x4340000000000001, ZeroCount: 0, Sum: 0x7ff8000000000003, ResetHint: "not_reset", NegativeSpans: []model.HistogramSpan{{Offset: -1, Length: 1}}, NegativeBuckets: []model.FloatBits{0x4340000000000001}}}, Unit: "1", Type: "histogram"}},
		{Log: &model.LogRecord{Severity: "error", TemplateID: "failed", TemplateRevision: 1, Fields: map[string]model.Scalar{"count": safe}, Line: "same safe line", StreamLabels: model.Labels{{Name: "stream", Value: "test"}}, Metadata: map[string]model.Scalar{"count": safe}, SourceClass: "structured"}},
		{Log: &model.LogRecord{Severity: "error", TemplateID: "failed", TemplateRevision: 1, Fields: map[string]model.Scalar{"count": safe}, Line: "same safe line", StreamLabels: model.Labels{{Name: "stream", Value: "test"}}, Metadata: map[string]model.Scalar{"count": safe}, SourceClass: "structured"}},
		{Span: &model.Span{Trace: id, ID: span, Kind: "internal", Operation: "operation", Start: clock, End: &end, Status: "ok", SampleProbability: 0x3ff0000000000000, SampleDecision: "keep"}},
		{Error: &model.ErrorOccurrence{Occurrence: id, Class: "ExceptionGroup", Mechanism: "manual", Build: resource.Build, Frames: []model.Frame{}, Graph: &model.ExceptionGraph{Nodes: []model.ExceptionNode{{ID: 0, Class: "ExceptionGroup", Frames: []model.Frame{}}, {ID: 1, Class: "ValueError", Frames: []model.Frame{{Module: "main.py", Artifact: "main.py", Function: "work", Line: 900}}}}, Edges: []model.ExceptionEdge{{From: 0, To: 1, Kind: "group", Ordinal: &ordinal}}, Reasons: []string{"cycle", "project_root_unconfigured"}}}},
		{Job: &model.JobAttemptEvent{Job: id, Run: model.NewID(), Attempt: model.NewID(), Schedule: "schedule", Ordinal: 1, Epoch: model.NewID(), Sequence: 9007199254740993, State: "failed", Observed: 1, Terminal: &terminal}},
		{Replay: &model.ReplayChunk{Replay: id, Session: model.NewID(), Recorder: "fixture", Sequence: 9007199254740993, Clock: clock, CheckpointSequence: 9007199254740993, PolicyRevision: 1, Nodes: []model.MaskedNode{{ID: 1, Tag: "div", Text: "[masked]"}}, Events: []model.MaskedEvent{{Kind: "checkpoint", At: 1, Node: 1}}, Loss: 9007199254740993}},
		{Profile: &model.ProfileChunk{Profile: id, Process: model.NewID(), Capability: cpuCapability, Method: "native_cpu", Units: "samples", Start: 1, End: 2, Clock: clock, Frames: []model.ProfileFrame{{Reason: "frame_unresolved"}}, Stacks: []model.ProfileStack{{Frames: []uint32{0}}}, Samples: []model.ProfileSample{{At: 1, Stack: 0, Count: 1, Thread: 11, Native: &model.ProfileNativeSample{Task: nativeTask, Method: "software_cpu_clock", Unit: "cpu_clock_nanoseconds", RequestedHz: 99, Period: 9007199254740993, Coverage: "frame_unresolved"}}}, Loss: 3, NativeDomain: nativeDomain, PolicyRevision: 1, Sequence: 9007199254740993, NativeCapabilities: []model.ID{cpuCapability, offCPUCapability, runqueueCapability}, NativeLoss: []model.ProfileNativeLoss{{At: 1, CPU: 0, Count: 3, Reason: "records_lost"}}}},
		{Capability: &model.Capability{Runtime: "go", Version: "1", Build: "fixture", OS: "linux", Arch: "amd64", Signal: model.Profile, Method: "native_cpu", Status: "supported", Reason: "fixture_observation", Clock: clock.Domain, Expires: 10, Coverage: model.Coverage{Frames: "partial", Threads: "partial", Workers: "none", Tasks: "none"}}},
		{Loss: &model.LossReport{Source: id, Producer: model.NewID(), Epoch: model.NewID(), Start: 1, End: 2, Signal: model.Profile, Reason: "ring_overflow", Count: 9007199254740993}},
		{Condition: &model.ConditionEvent{Condition: id, Epoch: model.NewID(), Sequence: 9007199254740993, At: 1, Status: "unknown", Severity: "warning", Labels: model.Labels{}}},
	}
	rows := make([]model.Record, len(kinds))
	for i, k := range kinds {
		rows[i] = model.Record{ID: model.NewID(), Kind: k, ObservedAt: 1, Resource: resource, Payload: payloads[i]}
	}
	rows[11].ID = cpuCapability
	for _, capability := range []struct {
		id     model.ID
		method string
	}{{offCPUCapability, "native_offcpu"}, {runqueueCapability, "runqueue_split"}} {
		rows = append(rows, model.Record{ID: capability.id, Kind: model.CapabilityKind, ObservedAt: 1, Resource: resource, Payload: model.Payload{Capability: &model.Capability{Runtime: "go", Version: "1", Build: "fixture", OS: "linux", Arch: "amd64", Signal: model.Profile, Method: capability.method, Status: "unsupported", Reason: "fixture_not_acquired", Clock: clock.Domain, Expires: 10, Coverage: model.Coverage{Frames: "none", Threads: "none", Workers: "none", Tasks: "none"}}}})
	}
	return rows
}
func typedInput(t *testing.T, d model.SourceDescriptor, revision model.Revision, row model.Record) model.Batch {
	t.Helper()
	raw := mustJSON(t, row)
	var owned model.Record
	if err := model.StrictJSON(raw, &owned); err != nil {
		t.Fatal(err)
	}
	batch := model.Batch{Version: 1, Project: d.Project, Source: d.Source, Producer: model.NewID(), ID: model.NewID(), PolicyRevision: revision, Records: []model.Record{owned}}
	if loss := batch.Records[0].Payload.Loss; loss != nil {
		loss.Source = batch.Source
		loss.Producer = batch.Producer
	}
	var err error
	batch.RouteSlot, err = model.OwnerSlot(d.Org, batch.Project, batch.Source, batch.Producer, batch.Records[0])
	if err != nil {
		t.Fatal(err)
	}
	return batch
}
func appendTyped(t *testing.T, e *Engine, store *control.Store, a *auth.Service, c auth.SourceCredential, d model.SourceDescriptor, row model.Record) model.Receipt {
	t.Helper()
	ctx := context.Background()
	source, err := a.SourceAuthority(ctx, c, true)
	if err != nil {
		t.Fatal(err)
	}
	service, err := policy.New(a, nil)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := service.ResolveSource(ctx, c, d.Project, d.Source, source.Policy.Revision)
	if err != nil {
		t.Fatal(err)
	}
	batch, err := policy.Normalize(grant, typedInput(t, d, source.Policy.Revision, row))
	if err != nil {
		t.Fatalf("normalize %s %s: %v", row.Kind, row.ID, err)
	}
	scope, err := grant.Scope()
	if err != nil {
		t.Fatal(err)
	}
	batch.Reservation, err = store.ReserveAdmission(ctx, scope, batch)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := e.Append(ctx, scope, batch)
	if err != nil {
		t.Fatalf("append normalized %s %s: %v", row.Kind, row.ID, err)
	}
	retry, err := e.Append(ctx, scope, batch)
	if err != nil || retry.Cursor != receipt.Cursor {
		t.Fatal("retry changed origin", err)
	}
	return receipt
}
func TestAllClosedPayloadsHotColdCompactedTypedEquality(t *testing.T) {
	store, a, c, d := typedFixture(t)
	_, base := normalized(t, store, a, c, d)
	read := scanScope(t, store, a, d)
	dir := t.TempDir()
	e, err := openTestEngine(t, dir, a, store)
	if err != nil {
		t.Fatal(err)
	}
	rows := typedRows(base.Records[0].Resource)
	for _, row := range rows {
		appendTyped(t, e, store, a, c, d, row)
	}
	want := map[model.Kind][]model.Record{}
	for _, k := range signalKinds {
		want[k] = collectPages(t, e, read, ScanRequest{Projects: []model.ID{d.Project}, Signal: k, Start: 0, End: 2})
	}
	if len(want[model.Log]) != 2 || want[model.Log][0].ID == want[model.Log][1].ID {
		t.Fatal("equal lines lost multiplicity")
	}
	for _, step := range []func(context.Context) error{e.Flush, e.Compact} {
		if err = step(context.Background()); err != nil {
			t.Fatal(err)
		}
		for _, k := range signalKinds {
			got := collectPages(t, e, read, ScanRequest{Projects: []model.ID{d.Project}, Signal: k, End: 2})
			if !reflect.DeepEqual(want[k], got) {
				t.Fatal("typed value changed", k)
			}
		}
	}
	if err = e.Close(); err != nil {
		t.Fatal(err)
	}
	e, err = openTestEngine(t, dir, a, store)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	for _, k := range signalKinds {
		if got := collectPages(t, e, read, ScanRequest{Projects: []model.ID{d.Project}, Signal: k, End: 2}); !reflect.DeepEqual(want[k], got) {
			t.Fatal("restart changed", k)
		}
	}
}
func TestMissingRetainedSegmentIsNotEOF(t *testing.T) {
	store, a, c, d := fixture(t)
	write, b := normalized(t, store, a, c, d)
	read := scanScope(t, store, a, d)
	dir := t.TempDir()
	e, err := openTestEngine(t, dir, a, store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = e.Append(context.Background(), write, b); err != nil {
		t.Fatal(err)
	}
	if err = e.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(e.catalog.Manifest.Segments) == 0 {
		t.Fatal("segment absent")
	}
	filePath, err := segmentPath(dir, e.catalog.Manifest.Segments[0].File)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(filePath); err != nil {
		t.Fatal(err)
	}
	it, err := e.Scan(context.Background(), read, ScanRequest{Projects: []model.ID{d.Project}, Signal: model.Metric, End: 2})
	if err == nil {
		_, err = it.Next(context.Background())
		it.Close()
	}
	if err == nil || errors.Is(err, io.EOF) {
		t.Fatal("missing became EOF")
	}
	e.Close()
	if reopened, err := openTestEngine(t, dir, a, store); err == nil {
		reopened.Close()
		t.Fatal("missing retained file accepted at restart")
	}
}
func TestManifestFailurePreservesReadableCommittedCopy(t *testing.T) {
	store, a, c, d := fixture(t)
	write, b := normalized(t, store, a, c, d)
	read := scanScope(t, store, a, d)
	e, err := openTestEngine(t, t.TempDir(), a, store)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if _, err = e.Append(context.Background(), write, b); err != nil {
		t.Fatal(err)
	}
	e.fault = func(at string) error {
		if at == "manifest_publish" {
			return errors.New("fixture")
		}
		return nil
	}
	if err = e.Flush(context.Background()); err == nil {
		t.Fatal("publication fault ignored")
	}
	e.fault = nil
	if got := collectPages(t, e, read, ScanRequest{Projects: []model.ID{d.Project}, Signal: model.Metric, End: 2}); len(got) != 1 {
		t.Fatal("publication lost committed rows")
	}
}
func TestCompactionMergesPublishedSegments(t *testing.T) {
	store, a, c, d := fixture(t)
	write, b := normalized(t, store, a, c, d)
	read := scanScope(t, store, a, d)
	e, err := openTestEngine(t, t.TempDir(), a, store)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if _, err = e.Append(context.Background(), write, b); err != nil {
		t.Fatal(err)
	}
	if err = e.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	row := b.Records[0]
	row.ID = model.NewID()
	row.ObservedAt = 2
	appendTyped(t, e, store, a, c, d, row)
	if err = e.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if e.Stats().SegmentFiles != 2 {
		t.Fatal("second durable segment absent")
	}
	if err = e.Compact(context.Background()); err != nil {
		t.Fatal(err)
	}
	if e.Stats().SegmentFiles != 1 {
		t.Fatal("retained segments were not merged")
	}
	if got := collectPages(t, e, read, ScanRequest{Projects: []model.ID{d.Project}, Signal: model.Metric, End: 3}); len(got) != 2 {
		t.Fatal("compaction changed logical rows")
	}
}
func TestManifestCASRejectsTermRevisionAndEviction(t *testing.T) {
	store, a, c, d := fixture(t)
	write, b := normalized(t, store, a, c, d)
	e, err := openTestEngine(t, t.TempDir(), a, store)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if _, err = e.Append(context.Background(), write, b); err != nil {
		t.Fatal(err)
	}
	if err = e.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	original := e.catalog.Manifest
	bad := original
	bad.Term++
	if _, err = e.Publish(context.Background(), e.identity, original.Revision, bad); err == nil {
		t.Fatal("foreign leader term accepted")
	}
	if _, err = e.Publish(context.Background(), e.identity, original.Revision+1, original); err == nil {
		t.Fatal("stale expected revision accepted")
	}
	bad = original
	bad.Segments = nil
	if _, err = e.Publish(context.Background(), e.identity, original.Revision, bad); err == nil {
		t.Fatal("only committed cold copy evicted")
	}
	revision, err := e.Publish(context.Background(), e.identity, original.Revision, original)
	if err != nil {
		t.Fatal(err)
	}
	original.Segments[0].Pages[0] = model.NewID()
	if e.catalog.Manifest.Revision != revision || e.catalog.Manifest.Segments[0].Pages[0] == original.Segments[0].Pages[0] {
		t.Fatal("caller retained a mutable manifest alias")
	}
}
