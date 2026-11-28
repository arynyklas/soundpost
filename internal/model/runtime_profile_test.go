// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package model

import (
	"strings"
	"testing"
)

// The chunk and capability payloads below are exactly what the Node/Bun (packages/core/src/profile_wire.ts) and Python
// (sdk/python/src/soundpost/profile.py) SDKs emit for their runtime profiles (03.09-W4 vocabulary mapping): the chunk method is the
// closed runtime_cpu, the SDK's own method is on the capability record.
const runtimeChunkJSON = `{"profile_id":"11111111111111111111111111111111","process_id":"22222222222222222222222222222222","capability_id":"33333333333333333333333333333333","method":"%METHOD%","units":"%UNITS%","start_ns":"1700000000000000000","end_ns":"1700000005000000000","clock":{"wall_ns":"1700000000000000000","mono_ns":"0","domain":{"host":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","boot":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","runtime":"cccccccccccccccccccccccccccccccc"},"uncertainty_ns":"18446744073709551615"},"frames":[{"module_id":"src/work.js","function":"busyWork","artifact_id":"src/work.js","offset":"0","reason":""},{"module_id":"external","function":"","artifact_id":"","offset":"0","reason":"not_captured"}],"stacks":[{"frames":[0,1]}],"samples":[{"at_ns":"0","stack":0,"count":"1","thread":"0"},{"at_ns":"1000000","stack":0,"count":"41","thread":"0"}],"intervals":[],"loss":"0","truncated":false}`

func runtimeProfileRecord(t *testing.T, method, units string) (Record, SourcePolicy) {
	t.Helper()
	var chunk ProfileChunk
	body := strings.NewReplacer("%METHOD%", method, "%UNITS%", units).Replace(runtimeChunkJSON)
	if e := StrictJSON([]byte(body), &chunk); e != nil {
		t.Fatalf("the SDK's chunk payload does not decode: %v", e)
	}
	serviceID, environmentID, buildID := NewID(), NewID(), NewID()
	policy := SourcePolicy{Revision: 1, Class: "structured", MaxBytes: 1 << 20, MaxSeries: 10, Kinds: []Kind{Profile, CapabilityKind}, Resources: ResourceRegistry{Services: []ID{serviceID}, Environments: []ID{environmentID}, Builds: []ID{buildID}, Instances: []string{"instance"}}}
	return Record{ID: NewID(), Kind: Profile, ObservedAt: 1700000005000000000, Resource: Resource{Service: serviceID, Environment: environmentID, Build: buildID, Instance: "instance"}, Payload: Payload{Profile: &chunk}}, policy
}

func TestRuntimeProfileChunksAreAdmittedUnderTheRuntimeCPUVocabulary(t *testing.T) {
	for _, units := range []string{"samples", "events"} {
		record, policy := runtimeProfileRecord(t, "runtime_cpu", units)
		if e := ValidateRecord(&record, policy); e != nil {
			t.Errorf("runtime_cpu chunk with units %s rejected: %v", units, e)
		}
	}
}

func TestRuntimeProfileVocabularyStaysClosed(t *testing.T) {
	for name, c := range map[string][2]string{
		"events outside runtime_cpu":        {"native_cpu", "events"},
		"events with native off-cpu":        {"native_offcpu", "events"},
		"the SDK method as a chunk method":  {"runtime_engine_samples", "samples"},
		"python_monitoring as chunk method": {"python_monitoring", "events"},
		"an invented unit":                  {"runtime_cpu", "cpu_seconds"},
	} {
		record, policy := runtimeProfileRecord(t, c[0], c[1])
		if ValidateRecord(&record, policy) == nil {
			t.Errorf("%s was admitted", name)
		}
	}
}

func TestRuntimeCapabilityRecordsCarryTheSDKMethod(t *testing.T) {
	serviceID, environmentID, buildID := NewID(), NewID(), NewID()
	policy := SourcePolicy{Revision: 1, Class: "structured", MaxBytes: 1 << 20, MaxSeries: 10, Kinds: []Kind{Profile, CapabilityKind}, Resources: ResourceRegistry{Services: []ID{serviceID}, Environments: []ID{environmentID}, Builds: []ID{buildID}, Instances: []string{"instance"}}}
	domain := ClockDomain{Host: NewID(), Boot: NewID(), Runtime: NewID()}
	for _, c := range []struct{ runtime, method, status, reason string }{
		{"node", "runtime_engine_samples", "supported", "ok"},
		{"bun", "runtime_engine_samples", "denied", "profiler_owned"},
		{"cpython", "python_monitoring", "supported", "ok"},
		{"cpython", "python_wall_samples", "unsupported", "free_threaded_unqualified"},
	} {
		capability := Capability{Runtime: c.runtime, Version: "3.13.5", Build: "build", OS: "linux", Arch: "x64", Signal: Profile, Method: c.method, Status: c.status, Reason: c.reason, Coverage: Coverage{Frames: "partial", Threads: "partial", Workers: "none", Tasks: "none"}, Clock: domain, Expires: 1700003600000000000}
		record := Record{ID: NewID(), Kind: CapabilityKind, ObservedAt: 1700000005000000000, Resource: Resource{Service: serviceID, Environment: environmentID, Build: buildID, Instance: "instance"}, Payload: Payload{Capability: &capability}}
		if e := ValidateRecord(&record, policy); e != nil {
			t.Errorf("%s/%s capability rejected: %v", c.runtime, c.method, e)
		}
		capability.Method = "python monitoring!"
		if ValidateRecord(&record, policy) == nil {
			t.Errorf("a method outside the safe code alphabet was admitted")
		}
	}
}
