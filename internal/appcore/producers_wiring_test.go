// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore

import (
	"fmt"
	"testing"
)

// The served runner gets its producers from App.Producers (cmd/soundpost/workers.go). A producer that
// is built and tested but missing from that list never runs on a served node.
func TestServedProducersIncludeEveryProducer(t *testing.T) {
	a := &App{}
	got := map[string]bool{}
	for _, p := range a.Producers() {
		got[fmt.Sprintf("%T", p)] = true
	}
	for _, want := range []Producer{a.IssueProducer(), a.JournalExpiryProducer(), a.IncidentProducer(), a.IssueEffectProducer(), a.JobProducer(), a.ProfileMapProducer(), a.RecordFormatProducer()} {
		if name := fmt.Sprintf("%T", want); !got[name] {
			t.Fatalf("%s is not among the producers a served node runs: %v", name, got)
		}
	}
}
