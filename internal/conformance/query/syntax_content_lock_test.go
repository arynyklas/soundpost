// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const lockedSyntaxFixture = `{"phase":"syntax","cases":[{"id":"fixture","profiles":["promql-prometheus-3.1.0","promql-prometheus-3.13.5"],"input":{"expression":"1"},"expected":{"accepted":true,"type":"scalar"}}]}`

// This fixture proves preflight ordering without depending on the mutable live
// worktree inventory or ever supplying a reference executable.
func syntaxContentLockFixture(t *testing.T) (SourceLock, string) {
	t.Helper()
	root := t.TempDir()
	directory := filepath.Join(root, "conformance", "query")
	if err := os.MkdirAll(filepath.Join(directory, "cases"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "profiles", "query"), 0700); err != nil {
		t.Fatal(err)
	}
	lock := SourceLock{ManifestVersion: 1, LedgerPath: filepath.Join(directory, "obligations.json"), InventoryFiles: map[string]string{}, ProfileFiles: map[string]string{}}
	ledger := Ledger{ManifestVersion: 1, Complete: true}
	domains := struct {
		Complete bool         `json:"complete"`
		Domains  []GateDomain `json:"domains"`
	}{Complete: true}
	for i, id := range []string{"promql-prometheus-3.1.0", "promql-prometheus-3.13.5", "logql-loki-3.5.2"} {
		license := "Apache-2.0"
		if strings.HasPrefix(id, "logql-") {
			license = "AGPL-3.0-only"
		}
		lock.Profiles = append(lock.Profiles, SourceProfile{ID: id, Commit: exactPins[id], SourceURL: "https://example.test/source", SourceSHA256: strings.Repeat("a", 64), License: license})
		obligation := string(rune('a' + i))
		ledger.Obligations = append(ledger.Obligations, Obligation{ID: obligation, Profile: id, Kind: "syntax", SemanticRule: "isolated fixture rule", SourceRefs: []string{"fixture.go:1"}})
		manifest, _ := json.Marshal(struct {
			ID          string   `json:"id"`
			Complete    bool     `json:"complete"`
			Obligations []string `json:"obligations"`
		}{id, true, []string{obligation}})
		lock.ProfileFiles["profiles/query/"+id+".json"] = writeSyntaxLockBytes(t, filepath.Join(root, "profiles", "query", id+".json"), manifest)
		domains.Domains = append(domains.Domains, GateDomain{Profile: id, FeatureSets: []FeatureSet{{ID: "fixture-default"}}})
	}
	raw, err := json.Marshal(ledger)
	if err != nil {
		t.Fatal(err)
	}
	lock.LedgerSHA256 = writeSyntaxLockBytes(t, lock.LedgerPath, raw)
	raw, err = json.Marshal(domains)
	if err != nil {
		t.Fatal(err)
	}
	lock.InventoryFiles["gate-domains.json"] = writeSyntaxLockBytes(t, filepath.Join(directory, "gate-domains.json"), raw)
	lock.InventoryFiles["cases/promql-syntax.json"] = writeSyntaxLockBytes(t, filepath.Join(directory, "cases", "promql-syntax.json"), []byte(lockedSyntaxFixture))
	return lock, directory
}
func writeSyntaxLockBytes(t *testing.T, path string, raw []byte) string {
	t.Helper()
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func TestSyntaxPhaseAlternateBasenameRequiresOwnContentLockBeforeReference(t *testing.T) {
	lock, directory := syntaxContentLockFixture(t)
	if _, err := Inventory(context.Background(), lock); err != nil {
		t.Fatalf("isolated inventory is not valid: %v", err)
	}
	alternate := filepath.Join(directory, "cases", "promql-trim-syntax.json")
	writeSyntaxLockBytes(t, alternate, []byte(lockedSyntaxFixture)) // Same bytes as the locked original must NOT inherit its basename lock.
	report, err := RunSyntaxPhase(context.Background(), lock, alternate, filepath.Join(directory, "missing-profiles"), "no-reference-runtime")
	if err == nil || !strings.Contains(err.Error(), "missing content lock for cases/promql-trim-syntax.json") {
		t.Fatalf("alternate lock guard not reached before profile/reference work: %v", err)
	}
	if report.Compared != 0 || len(report.Cases) != 0 {
		t.Fatal("unlocked corpus produced observations")
	}
}

func TestSyntaxPhaseLockedCopyMutationRejectedBeforeReference(t *testing.T) {
	lock, directory := syntaxContentLockFixture(t)
	canonical := filepath.Join(directory, "cases", "promql-trim-syntax.json")
	lock.InventoryFiles["cases/promql-trim-syntax.json"] = writeSyntaxLockBytes(t, canonical, []byte(lockedSyntaxFixture))
	cases, err := readLockedSyntaxCases(lock, canonical)
	if err != nil || len(cases) != 1 {
		t.Fatalf("properly locked additive corpus rejected: %v", err)
	}
	alternate := filepath.Join(t.TempDir(), "promql-trim-syntax.json")
	writeSyntaxLockBytes(t, alternate, []byte(lockedSyntaxFixture+" ")) // Inventory canonical bytes remain unchanged; consumed copy must still be checked.
	report, err := RunSyntaxPhase(context.Background(), lock, alternate, filepath.Join(directory, "missing-profiles"), "no-reference-runtime")
	if err == nil || !strings.Contains(err.Error(), "locked content changed: cases/promql-trim-syntax.json") {
		t.Fatalf("consumed-copy mutation guard not reached: %v", err)
	}
	if report.Compared != 0 || len(report.Cases) != 0 {
		t.Fatal("mutated consumed copy produced observations")
	}
}

func TestLockedSyntaxCasesRetainPhaseBothPinsAndNonemptyGuards(t *testing.T) {
	for _, raw := range []string{
		`{"phase":"syntax","cases":[]}`,
		`{"phase":"evaluation","cases":[{"id":"x","profiles":["promql-prometheus-3.1.0","promql-prometheus-3.13.5"]}]}`,
		`{"phase":"syntax","cases":[{"id":"x","profiles":["promql-prometheus-3.1.0"]}]}`,
	} {
		path := filepath.Join(t.TempDir(), "promql-trim-syntax.json")
		lock := SourceLock{InventoryFiles: map[string]string{"cases/promql-trim-syntax.json": writeSyntaxLockBytes(t, path, []byte(raw))}}
		if _, err := readLockedSyntaxCases(lock, path); err == nil {
			t.Fatalf("invalid phase/profile/empty suite accepted: %s", raw)
		}
	}
}
