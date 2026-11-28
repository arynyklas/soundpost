// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"os"
	"strconv"
	"strings"
	"testing"
)

// acceptance.json is hand-maintained text next to machine-checked bindings; this
// test keeps the blocker prose from drifting away from the actual bound state.
func TestAcceptanceBlockersNameExactlyTheUnboundObligations(t *testing.T) {
	var acceptance struct {
		ReleaseReady bool `json:"release_ready"`
		Bindings     []struct {
			ObligationID string `json:"obligation_id"`
		} `json:"production_bindings"`
		Blockers       []string `json:"blockers"`
		ClosedBlockers []struct {
			Blocker  string `json:"blocker"`
			ClosedBy string `json:"closed_by"`
			Evidence string `json:"evidence"`
		} `json:"closed_blockers"`
		Scope struct {
			Accepted int `json:"accepted_semantic_obligations"`
		} `json:"inventory_scope"`
	}
	if err := ReadJSON("../../../conformance/query/acceptance.json", &acceptance); err != nil {
		t.Fatal(err)
	}
	var ledger Ledger
	if err := ReadJSON("../../../conformance/query/obligations.json", &ledger); err != nil {
		t.Fatal(err)
	}
	bound := map[string]bool{}
	for _, b := range acceptance.Bindings {
		bound[b.ObligationID] = true
	}
	var unbound []string
	for _, o := range ledger.Obligations {
		if !bound[o.ID] {
			unbound = append(unbound, o.ID)
		}
	}
	if acceptance.Scope.Accepted != len(ledger.Obligations) {
		t.Fatalf("inventory_scope disagrees with the ledger: %d vs %d", acceptance.Scope.Accepted, len(ledger.Obligations))
	}
	joined := strings.Join(acceptance.Blockers, "\n")
	if len(unbound) > 0 {
		if !strings.Contains(joined, strconv.Itoa(len(ledger.Obligations)-len(unbound))+" of "+strconv.Itoa(len(ledger.Obligations))) {
			t.Fatalf("blockers do not state the bound count %d of %d: %s", len(ledger.Obligations)-len(unbound), len(ledger.Obligations), joined)
		}
		for _, id := range unbound {
			if !strings.Contains(joined, id) {
				t.Errorf("unbound obligation %s is not named by a blocker", id)
			}
		}
	}
	if len(unbound) == 0 && strings.Contains(joined, "Production bindings") {
		t.Fatal("every obligation is bound; the production-binding blocker must be closed")
	}
	if acceptance.ReleaseReady && (len(unbound) > 0 || len(acceptance.Blockers) > 0) {
		t.Fatal("release_ready cannot be true with unbound obligations or open blockers")
	}
	for _, c := range acceptance.ClosedBlockers {
		if c.Blocker == "" || c.ClosedBy == "" || c.Evidence == "" {
			t.Fatalf("closed blocker without closing evidence: %+v", c)
		}
	}
}

// The four Prometheus configuration obligations (02.12-W1, D29) are observed by
// the configuration phase; the prose around them must say so, and a blocker must
// never repeat work a strict test has closed.
func TestConfigurationObligationsAreDocumentedAsObservedNotUnbound(t *testing.T) {
	var acceptance struct {
		Bindings []struct {
			ObligationID string   `json:"obligation_id"`
			Cases        []string `json:"cases"`
		} `json:"production_bindings"`
		Blockers       []string `json:"blockers"`
		ClosedBlockers []struct {
			Blocker string `json:"blocker"`
		} `json:"closed_blockers"`
	}
	if err := ReadJSON("../../../conformance/query/acceptance.json", &acceptance); err != nil {
		t.Fatal(err)
	}
	for _, profile := range []string{"promql-prometheus-3.1.0", "promql-prometheus-3.13.5"} {
		for _, name := range []string{"protocols", "scrape-inheritance"} {
			id := profile + "/configuration/" + name
			found := false
			for _, b := range acceptance.Bindings {
				if b.ObligationID == id {
					found = len(b.Cases) == 3
				}
			}
			if !found {
				t.Errorf("%s is not bound with its three case IDs", id)
			}
		}
	}
	readme, err := os.ReadFile("../../../conformance/query/README.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, stale := range []string{"Four obligations stay unbound", "has no configuration-parsing phase", "owned product has no scrape-configuration implementation"} {
		if strings.Contains(string(readme), stale) {
			t.Errorf("README.md still says the configuration obligations are unobserved: %q", stale)
		}
	}
	// 02.02-W1: owned end ranges are qualified by TestOwnedSyntaxRangesAgainstRecordedGoLevelObservations
	// (strict, no allowlist), so no open blocker may still ask for that observation.
	for _, blocker := range acceptance.Blockers {
		if strings.Contains(blocker, "02.02-W1") || strings.Contains(blocker, "Owned end ranges are covered by unit tests only") {
			t.Errorf("a closed blocker is still listed as open: %s", blocker)
		}
	}
	closed := false
	for _, c := range acceptance.ClosedBlockers {
		closed = closed || strings.Contains(c.Blocker, "02.02-W1")
	}
	if !closed {
		t.Error("the 02.02-W1 end-range blocker is not recorded as closed")
	}
}
