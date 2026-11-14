// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestSBOMIsDeterministicAndLicensesAreNeverInvented(t *testing.T) {
	f := newFixture(t)
	write(t, filepath.Join(f.root, "sdk/python/requirements-dev.lock"), "Some_Pkg==1.0 \\\n    --hash=sha256:00\n")
	// a second, conflicting record and a go.sum-only module without any record
	write(t, filepath.Join(f.root, "third_party/config-tooling-NOTICES.txt"), "===== example.com/a@v1.0.0 (Apache-2.0) =====\ntext\n")
	gen := func() (Inventory, []byte, []byte) {
		inv, err := collectInventory(f.root)
		if err != nil {
			t.Fatal(err)
		}
		cdx, err := GenerateCycloneDX(inv, "1.2.3", "2026-11-10T00:00:00Z")
		if err != nil {
			t.Fatal(err)
		}
		spdx, err := GenerateSPDX(inv, "1.2.3", "2026-11-10T00:00:00Z")
		if err != nil {
			t.Fatal(err)
		}
		return inv, cdx, spdx
	}
	inv, cdx1, spdx1 := gen()
	_, cdx2, spdx2 := gen()
	if !bytes.Equal(cdx1, cdx2) || !bytes.Equal(spdx1, spdx2) {
		t.Fatal("SBOM output differs between two runs over the same tree")
	}
	byName := map[string]Component{}
	purls := []string{}
	for _, c := range inv.Components {
		byName[c.Name] = c
		purls = append(purls, c.PURL)
	}
	if !sort.StringsAreSorted(purls) {
		t.Fatal("components are not sorted")
	}
	// conflicting committed records: neither is picked
	if c := byName["example.com/a"]; c.License != "" || !strings.Contains(c.LicenseReason, "disagree") {
		t.Fatalf("conflicting records must give NOASSERTION: %+v", c)
	}
	// no record at all
	if c := byName["example.org/testonly"]; c.License != "" || c.Scope != ScopeExcluded || !strings.Contains(c.LicenseReason, "no committed license record") {
		t.Fatalf("go.sum-only module: %+v", c)
	}
	if c := byName["some-pkg"]; c.License != "" || c.PURL != "pkg:pypi/some-pkg@1.0" || !strings.Contains(c.LicenseReason, "no committed Python license inventory") {
		t.Fatalf("python component: %+v", c)
	}
	// a committed record is carried with its source, parenthetical stripped to the SPDX id
	if c := byName["third_party/vend/v1"]; c.License != "BSD-3-Clause" || c.LicenseSource == "" || !c.NoticeText {
		t.Fatalf("vendored: %+v", c)
	}
	var doc struct {
		BOMFormat, SpecVersion string
		Components             []struct {
			Name       string
			Licenses   []map[string]any
			Properties []struct{ Name, Value string }
		}
	}
	if err := json.Unmarshal(cdx1, &doc); err != nil || doc.BOMFormat != "CycloneDX" || doc.SpecVersion != "1.5" {
		t.Fatalf("cyclonedx header: %v %+v", err, doc)
	}
	for _, c := range doc.Components {
		if c.Name == "some-pkg" {
			if len(c.Licenses) != 0 {
				t.Fatalf("CycloneDX invented a license for an unrecorded component: %v", c.Licenses)
			}
			found := false
			for _, p := range c.Properties {
				found = found || (p.Name == "soundpost:license" && strings.HasPrefix(p.Value, "NOASSERTION: "))
			}
			if !found {
				t.Fatal("NOASSERTION reason missing")
			}
		}
	}
	var sp struct {
		SPDXVersion string `json:"spdxVersion"`
		Packages    []struct {
			Name, LicenseDeclared, LicenseConcluded, LicenseComments string
		}
	}
	if err := json.Unmarshal(spdx1, &sp); err != nil || sp.SPDXVersion != "SPDX-2.3" {
		t.Fatalf("spdx header: %v", err)
	}
	for _, p := range sp.Packages {
		if p.Name == "some-pkg" && (p.LicenseDeclared != "NOASSERTION" || p.LicenseConcluded != "NOASSERTION" || p.LicenseComments == "") {
			t.Fatalf("spdx invented or silently dropped: %+v", p)
		}
	}
	if _, err := GenerateSPDX(inv, "1.2.3", ""); err == nil {
		t.Fatal("SPDX without an explicit timestamp must be refused, never read the clock")
	}
	if bytes.Contains(cdx1, []byte("serialNumber")) {
		t.Fatal("random serial numbers break determinism")
	}
}

func TestRealTreeLicensesAlwaysCarryASource(t *testing.T) {
	inv, err := collectInventory("..")
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Components) < 100 {
		t.Fatalf("real inventory has only %d components", len(inv.Components))
	}
	for _, c := range inv.Components {
		if c.License != "" && c.LicenseSource == "" {
			t.Errorf("%s@%s has license %q without a committed source", c.Name, c.Version, c.License)
		}
		if c.License == "" && c.LicenseReason == "" {
			t.Errorf("%s@%s has neither a license nor a reason", c.Name, c.Version)
		}
	}
	a, _ := GenerateCycloneDX(inv, "0.0.0", "2026-11-10T00:00:00Z")
	inv2, _ := collectInventory("..")
	b, _ := GenerateCycloneDX(inv2, "0.0.0", "2026-11-10T00:00:00Z")
	if !bytes.Equal(a, b) {
		t.Fatal("real SBOM is not deterministic")
	}
	if _, err := os.Stat("../THIRD_PARTY_NOTICES"); err != nil {
		t.Fatal(err)
	}
}
