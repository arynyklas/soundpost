// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
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
