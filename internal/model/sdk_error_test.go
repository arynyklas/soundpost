// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package model

import (
	"encoding/json"
	"testing"
)

func TestSDKGraphVocabularyAndNullableColumns(t *testing.T) {
	var frame Frame
	if e := json.Unmarshal([]byte(`{"artifact_id":"main.py","module_id":"main.py","function":"operation","line":7,"column":null,"in_app":true,"async":false}`), &frame); e != nil {
		t.Fatal(e)
	}
	if frame.Column != nil {
		t.Fatal("unknown SDK column became zero")
	}
	serviceID, environmentID, buildID := NewID(), NewID(), NewID()
	policy := SourcePolicy{Kinds: []Kind{ErrorKind}, Resources: ResourceRegistry{Services: []ID{serviceID}, Environments: []ID{environmentID}, Builds: []ID{buildID}, Instances: []string{"instance"}}}
	occurrence := ErrorOccurrence{Occurrence: NewID(), Class: "Error", Mechanism: "manual", Build: buildID, Frames: []Frame{frame}, Graph: &ExceptionGraph{Nodes: []ExceptionNode{{ID: 0, Class: "Error", Frames: []Frame{frame}}}, Edges: []ExceptionEdge{}, Reasons: []string{}}}
	record := Record{ID: NewID(), Kind: ErrorKind, ObservedAt: 1, Resource: Resource{Service: serviceID, Environment: environmentID, Build: buildID, Instance: "instance"}, Payload: Payload{Error: &occurrence}}
	for _, mechanism := range []string{"manual", "uncaught_exception", "unhandled_rejection", "thread_exception", "asyncio_exception"} {
		occurrence.Mechanism = mechanism
		if e := ValidateRecord(&record, policy); e != nil {
			t.Fatalf("SDK mechanism %s: %v", mechanism, e)
		}
	}
	occurrence.Mechanism = "manual"
	for _, reason := range []string{"cycle", "node_limit", "frame_limit", "group_limit", "unknown_throw", "project_root_unconfigured", "frame_not_project_safe", "foreign_or_custom_error_class", "safe_original_stack_unavailable", "native_brand_unavailable", "cause_accessor", "group_accessor", "safe_group_boundary_unavailable", "unsafe_group_container"} {
		occurrence.Graph.Reasons = []string{reason}
		if e := ValidateRecord(&record, policy); e != nil {
			t.Fatalf("SDK reason %s: %v", reason, e)
		}
	}
	occurrence.Mechanism = "arbitrary_hook"
	if ValidateRecord(&record, policy) == nil {
		t.Fatal("open mechanism enum")
	}
	occurrence.Mechanism = "manual"
	occurrence.Graph.Reasons = []string{"arbitrary_reason"}
	if ValidateRecord(&record, policy) == nil {
		t.Fatal("open graph reason enum")
	}
	occurrence.Graph.Reasons = []string{}
	occurrence.Graph.Nodes = nil
	occurrence.Graph.Edges = nil
	for i := range 16 {
		frames := []Frame{}
		if i == 0 {
			frames = []Frame{frame}
		}
		occurrence.Graph.Nodes = append(occurrence.Graph.Nodes, ExceptionNode{ID: uint32(i), Class: "Error", Frames: frames})
	}
	for from := range 16 {
		for to := range 16 {
			ordinal := uint32(to)
			occurrence.Graph.Edges = append(occurrence.Graph.Edges, ExceptionEdge{From: uint32(from), To: uint32(to), Kind: "group", Ordinal: &ordinal})
		}
		occurrence.Graph.Edges = append(occurrence.Graph.Edges, ExceptionEdge{From: uint32(from), To: uint32((from + 1) % 16), Kind: "cause"})
	}
	if e := ValidateRecord(&record, policy); e != nil {
		t.Fatal("bounded dense SDK graph rejected", e)
	}
	occurrence.Graph.Edges[0].To = 16
	if ValidateRecord(&record, policy) == nil {
		t.Fatal("dangling graph edge accepted")
	}
}
