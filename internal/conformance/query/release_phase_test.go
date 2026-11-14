// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"os"
	"strings"
	"testing"
)

// Every production binding of acceptance.json must cite, for each of its
// obligation's positive/negative/interaction case IDs, a real row of a
// content-locked case file in the release manifest, an implementation that is
// not pending and only Go tests that exist.
func TestReleaseBindingsResolveToLockedCaseRows(t *testing.T) {
	here, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chdir("../../.."); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(here) })
	cfg, err := LoadReleaseConfig("conformance/query", "conformance/query/release-policy.json", nil, 20261110)
	if err != nil {
		t.Fatal(err)
	}
	rows := map[string]bool{}
	for _, c := range cfg.Cases {
		if rows[PhaseKey(c.Profile, c.ID)] {
			t.Fatalf("duplicate release row %s/%s", c.Profile, c.ID)
		}
		rows[PhaseKey(c.Profile, c.ID)] = true
	}
	ledger := map[string]Obligation{}
	for _, o := range cfg.Ledger.Obligations {
		ledger[o.ID] = o
	}
	if len(cfg.Bindings) == 0 {
		t.Fatal("no production bindings")
	}
	for _, b := range cfg.Bindings {
		o, ok := ledger[b.ObligationID]
		if !ok {
			t.Fatalf("binding for unknown obligation %s", b.ObligationID)
		}
		if b.Implementation == "" || strings.HasPrefix(b.Implementation, "pending") || len(b.GoTests) == 0 {
			t.Fatalf("%s: implementation or Go tests missing", b.ObligationID)
		}
		have := map[string]bool{}
		for _, c := range b.Cases {
			have[c] = true
		}
		for _, group := range [][]string{o.PositiveCases, o.NegativeCases, o.InteractionCases} {
			if len(group) == 0 {
				t.Fatalf("%s: a case role is empty in the ledger", o.ID)
			}
			for _, c := range group {
				if !have[c] {
					t.Fatalf("%s: binding omits ledger case %s", o.ID, c)
				}
				if !rows[PhaseKey(o.Profile, c)] {
					t.Fatalf("%s: case %s is not a row of any locked release case file", o.ID, c)
				}
			}
		}
	}
}
