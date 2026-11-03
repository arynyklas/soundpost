// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package model

import (
	"encoding/json"
	"testing"
)

func TestClosedTelemetryKindsAndSDKExceptionGraph(t *testing.T) {
	id := NewID()
	var span SpanID
	span[0] = 1
	clock := TraceClock{Wall: 1, Mono: 1, Domain: ClockDomain{Host: NewID(), Boot: NewID(), Runtime: NewID()}}
	end := clock
	end.Mono = 2
	value := FloatBits(0x7ff0000000000002)
	code := "failed"
	ordinal := uint32(0)
	terminal := UnixNano(2)
	probability := FloatBits(0x3ff0000000000000)
	serviceID, environmentID, buildID := NewID(), NewID(), NewID()
	policy := SourcePolicy{Revision: 1, Enabled: true, Class: "structured", Kinds: []Kind{Metric, Log, SpanKind, ErrorKind, JobAttempt, Replay, Profile, CapabilityKind, Loss, Condition}, Resources: ResourceRegistry{Services: []ID{serviceID}, Environments: []ID{environmentID}, Builds: []ID{buildID}, Instances: []string{"instance"}}, Operations: []string{"operation"}, Codes: []string{"failed"}, Replay: true}
	var safe Scalar
	json.Unmarshal([]byte(`503`), &safe)
	policy.Templates = []LogTemplate{{ID: "failed", Revision: 1, Line: "failed {status}", Severity: "error", Fields: []TemplateField{{Name: "status", Type: "int64", MaxBytes: 16, Sensitivity: "metadata", Values: []Scalar{safe}}}}}
	variants := []struct {
		kind    Kind
		payload Payload
	}{
		{Metric, Payload{Metric: &MetricPoint{Name: "requests", Labels: Labels{}, SampleKind: "stale", Value: &value, Type: "counter", Unit: "1"}}},
		{Log, Payload{Log: &LogRecord{TemplateID: "failed", TemplateRevision: 1, Fields: map[string]Scalar{"status": safe}, StreamLabels: Labels{}, Metadata: map[string]Scalar{"status": safe}}}},
		{SpanKind, Payload{Span: &Span{Trace: id, ID: span, Kind: "internal", Operation: "operation", Start: clock, End: &end, Status: "ok", SampleProbability: probability, SampleDecision: "keep"}}},
		{ErrorKind, Payload{Error: &ErrorOccurrence{Occurrence: id, Class: "ExceptionGroup", Mechanism: "manual", Code: &code, Build: buildID, Handled: true, Frames: []Frame{}, Graph: &ExceptionGraph{Nodes: []ExceptionNode{{ID: 0, Class: "ExceptionGroup", Frames: []Frame{}}, {ID: 1, Class: "ValueError", Frames: []Frame{{Module: "main.py", Artifact: "main.py", Function: "operation", Line: 1}}}}, Edges: []ExceptionEdge{{From: 0, To: 1, Kind: "group", Ordinal: &ordinal}}, Reasons: []string{"cycle", "project_root_unconfigured"}}}}},
		{JobAttempt, Payload{Job: &JobAttemptEvent{Job: id, Run: NewID(), Attempt: NewID(), Schedule: "schedule", Ordinal: 1, Epoch: NewID(), Sequence: 9007199254740993, State: "failed", Observed: 1, Terminal: &terminal}}},
		{Replay, Payload{Replay: &ReplayChunk{Replay: id, Session: NewID(), Recorder: "test", Clock: clock, PolicyRevision: 1, Nodes: []MaskedNode{{ID: 1, Tag: "div", Text: "[masked]"}}, Events: []MaskedEvent{{Kind: "checkpoint", At: 1, Node: 1}}}}},
		{Profile, Payload{Profile: &ProfileChunk{Profile: id, Process: NewID(), Capability: NewID(), Method: "native_cpu", Units: "samples", Start: 1, End: 2, Clock: clock, Frames: []ProfileFrame{{Module: "module", Offset: 9007199254740993, Reason: "unresolved"}}, Stacks: []ProfileStack{{Frames: []uint32{0}}}, Samples: []ProfileSample{{At: 1, Stack: 0, Count: 9007199254740993, Thread: 1}}}}},
		{CapabilityKind, Payload{Capability: &Capability{Runtime: "go", Version: "1", Build: "build", OS: "linux", Arch: "amd64", Signal: Profile, Method: "native_cpu", Status: "supported", Reason: "probed", Clock: clock.Domain, Expires: 10, Coverage: Coverage{Frames: "partial", Threads: "complete", Workers: "none", Tasks: "none"}}}},
		{Loss, Payload{Loss: &LossReport{Source: id, Producer: NewID(), Epoch: NewID(), Start: 1, End: 2, Signal: Profile, Reason: "ring_overflow", Count: 9007199254740993}}},
		{Condition, Payload{Condition: &ConditionEvent{Condition: id, Epoch: NewID(), Sequence: 9007199254740993, At: 1, Status: "unknown", Severity: "warning", Labels: Labels{}}}},
	}
	for _, v := range variants {
		t.Run(string(v.kind), func(t *testing.T) {
			r := Record{ID: NewID(), Kind: v.kind, ObservedAt: 1, Resource: Resource{Service: serviceID, Environment: environmentID, Build: buildID, Instance: "instance", Labels: Labels{}}, Payload: v.payload}
			if e := ValidateRecord(&r, policy); e != nil {
				t.Fatal(e)
			}
			raw, e := CanonicalJSON(r)
			if e != nil {
				t.Fatal(e)
			}
			var restored Record
			if e = json.Unmarshal(raw, &restored); e != nil {
				t.Fatal(e)
			}
			again, e := CanonicalJSON(restored)
			if e != nil || string(raw) != string(again) {
				t.Fatal("typed wire changed")
			}
			var wire map[string]json.RawMessage
			json.Unmarshal(raw, &wire)
			var payload map[string]json.RawMessage
			json.Unmarshal(wire["payload"], &payload)
			payload["body"] = json.RawMessage(`"forbidden"`)
			wire["payload"], _ = json.Marshal(payload)
			bad, _ := json.Marshal(wire)
			if json.Unmarshal(bad, &restored) == nil {
				t.Fatal("arbitrary payload field accepted")
			}
		})
	}
}
func TestJSONDuplicateUTF8SurrogateAndOverflowDenials(t *testing.T) {
	for _, raw := range []string{`{"a":1,"a":2}`, `{"a":"\ud800"}`, `{"a":"\udc00"}`, "{\"a\":\"\xff\"}"} {
		if ValidateJSON([]byte(raw)) == nil {
			t.Fatal("malformed JSON accepted")
		}
	}
	for _, raw := range []string{`{"a":"\\ud800"}`, `{"a":"\ud83d\ude00"}`} {
		if e := ValidateJSON([]byte(raw)); e != nil {
			t.Fatal("valid escaped Unicode rejected")
		}
	}
	var histogram IntegerHistogram
	if json.Unmarshal([]byte(`{"flavor":"counter","count":"18446744073709551616"}`), &histogram) == nil {
		t.Fatal("uint64 overflow accepted")
	}
}
