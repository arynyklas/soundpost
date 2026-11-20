// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package profiles_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/profiles"
)

// A view always carries its capability list, empty or not: a reader tells "no capability evidence" from "a producer
// that predates the field" by the key being there (l4w33 mutation battery C).
func TestProfileViewAlwaysCarriesTheCapabilitiesKey(t *testing.T) {
	view := profiles.ProfileView{Profile: model.NewID(), Process: model.NewID(), Project: model.NewID(), Clock: model.TraceClock{Domain: model.ClockDomain{Host: model.NewID(), Boot: model.NewID(), Runtime: model.NewID()}}}
	raw, err := json.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"capabilities":null`) {
		t.Fatalf("an empty capability list is not on the wire: %s", raw)
	}
	view.Capabilities = []profiles.CapabilityRecord{{ID: model.NewID(), Value: model.Capability{Clock: view.Clock.Domain, AcquisitionScope: model.AcquisitionScopeTargetOnly}}}
	if raw, err = json.Marshal(view); err != nil || !strings.Contains(string(raw), `"capabilities":[{"id":`) || !strings.Contains(string(raw), `"acquisition_scope":"target_only"`) {
		t.Fatalf("%s %v", raw, err)
	}
}
