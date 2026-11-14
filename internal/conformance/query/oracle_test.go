// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func runSanityCases(t *testing.T) {
	t.Helper()
	root := filepath.Join("..", "..", "..")
	var lock SourceLock
	if err := ReadJSON(filepath.Join(root, "conformance/query/source-lock.json"), &lock); err != nil {
		t.Fatal(err)
	}
	if err := ValidateSourceLock(lock); err != nil {
		t.Fatal(err)
	}
	lock.LedgerPath = filepath.Join(root, "conformance/query/obligations.json")
	if _, err := Inventory(context.Background(), lock); err != nil {
		t.Fatal(err)
	}
	var cases struct {
		Cases []struct {
			ID       string          `json:"id"`
			Profiles []string        `json:"profiles"`
			Input    json.RawMessage `json:"input"`
			Expected SemanticResult  `json:"expected"`
		}
	}
	if err := ReadLockedJSON(lock, "cases/oracle-sanity.json", filepath.Join(root, "conformance/query/cases/oracle-sanity.json"), &cases); err != nil {
		t.Fatal(err)
	}
	runtime := os.Getenv("SOUNDPOST_ORACLE_RUNTIME")
	if runtime == "" {
		t.Fatal("SOUNDPOST_ORACLE_RUNTIME must name absolute OCI runtime; oracle absence is not a skip")
	}
	for _, p := range lock.Profiles {
		p := p
		t.Run(p.ID, func(t *testing.T) {
			configuration, err := os.ReadFile(filepath.Join(root, p.ConfigurationPath))
			if err != nil {
				t.Fatal(err)
			}
			applicable := 0
			for _, c := range cases.Cases {
				for _, id := range c.Profiles {
					if id != p.ID {
						continue
					}
					applicable++
					ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
					got, err := RunOracle(ctx, OracleRun{Profile: p, Input: c.Input, Configuration: configuration, Runtime: runtime})
					cancel()
					if err != nil {
						t.Fatal(err)
					}
					if mismatches := Compare(c.Expected, got, OrderingFreedom{}); len(mismatches) > 0 {
						t.Fatalf("%s: %+v", c.ID, mismatches)
					}
				}
			}
			if applicable == 0 {
				t.Fatal("no applicable sanity case")
			}
		})
	}
}
