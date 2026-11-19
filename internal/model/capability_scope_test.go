// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package model

import (
	"encoding/json"
	"strings"
	"testing"
)

// 04.04-C11: a capability record names how far its acquisition reaches. The vocabulary is closed, the field is optional
// (records written before it existed decode and validate unchanged) and it is absent from the wire when empty.
func TestCapabilityAcquisitionScopeIsClosedOptionalAndOmittedWhenEmpty(t *testing.T) {
	serviceID, environmentID, buildID := NewID(), NewID(), NewID()
	policy := SourcePolicy{Revision: 1, Class: "structured", MaxBytes: 1 << 20, MaxSeries: 10, Kinds: []Kind{CapabilityKind}, Resources: ResourceRegistry{Services: []ID{serviceID}, Environments: []ID{environmentID}, Builds: []ID{buildID}, Instances: []string{"instance"}}}
	domain := ClockDomain{Host: NewID(), Boot: NewID(), Runtime: NewID()}
	base := Capability{Runtime: "native_linux", Version: "1", Build: "owned", OS: "linux", Arch: "amd64", Signal: Profile, Method: "native_offcpu", Status: "supported", Reason: "probed", Coverage: Coverage{Frames: "partial", Threads: "partial", Workers: "none", Tasks: "none"}, Clock: domain, Expires: 1700003600000000000}
	admit := func(c Capability) error {
		record := Record{ID: NewID(), Kind: CapabilityKind, ObservedAt: 1700000005000000000, Resource: Resource{Service: serviceID, Environment: environmentID, Build: buildID, Instance: "instance"}, Payload: Payload{Capability: &c}}
		return ValidateRecord(&record, policy)
	}
	if e := admit(base); e != nil {
		t.Fatalf("a record without the field must stay valid: %v", e)
	}
	raw, e := json.Marshal(base)
	if e != nil || strings.Contains(string(raw), "acquisition_scope") {
		t.Fatalf("an empty scope must be omitted from the wire: %s %v", raw, e)
	}
	for _, scope := range AcquisitionScopes {
		c := base
		c.AcquisitionScope = scope
		if e := admit(c); e != nil {
			t.Errorf("scope %q rejected: %v", scope, e)
		}
		raw, _ := json.Marshal(c)
		if !strings.Contains(string(raw), `"acquisition_scope":"`+scope+`"`) {
			t.Errorf("scope %q is not on the wire: %s", scope, raw)
		}
		var back Capability
		if e := StrictJSON(raw, &back); e != nil || back.AcquisitionScope != scope {
			t.Errorf("scope %q does not round-trip through the strict decoder: %v %+v", scope, e, back)
		}
	}
	for _, bad := range []string{"host_wide", "system-wide", "System_Wide", "target_only ", "x"} {
		c := base
		c.AcquisitionScope = bad
		if admit(c) == nil {
			t.Errorf("scope %q outside the closed vocabulary was admitted", bad)
		}
	}
}
