// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func committedOverridesAndInventory(t *testing.T) (inventoryOverrides, map[string]pyEntry) {
	t.Helper()
	raw, err := os.ReadFile("dependencies/license-overrides.json")
	if err != nil {
		t.Fatal(err)
	}
	var ov inventoryOverrides
	if err = json.Unmarshal(raw, &ov); err != nil {
		t.Fatal(err)
	}
	invRaw, err := os.ReadFile("dependencies/python-licenses.json")
	if err != nil {
		t.Fatal(err)
	}
	var inv pyInventory
	if err = json.Unmarshal(invRaw, &inv); err != nil {
		t.Fatal(err)
	}
	have := map[string]pyEntry{}
	for _, p := range inv.Packages {
		have[p.Name+"@"+p.Version] = p
	}
	return ov, have
}

// M2: no committed override may rely on an implied binding; each names the metadata value it covers.
func TestEveryCommittedPyPIOverrideNamesItsDeclaredBinding(t *testing.T) {
	ov, _ := committedOverridesAndInventory(t)
	if len(ov.PyPILicense) == 0 {
		t.Fatal("no pypi overrides committed")
	}
	for key, o := range ov.PyPILicense {
		if strings.TrimSpace(o.Declared) == "" {
			t.Errorf("%s: override lacks an explicit declared binding (use NOASSERTION when metadata names no license)", key)
		}
	}
}

// M1: a source marked identical to the wheel text carries the committed license_text_sha256; every source
// says which way it relates, and the evidence wording agrees with the marker.
func TestCommittedOverrideSourceShaAgreesWithItsWheelTextClaim(t *testing.T) {
	ov, have := committedOverridesAndInventory(t)
	for key, o := range ov.PyPILicense {
		e := have[key]
		for _, s := range o.Sources {
			switch s.WheelText {
			case wheelTextIdentical:
				if s.SHA256 != e.LicenseTextSHA256 {
					t.Errorf("%s: source %s is marked identical but sha256 %s != license_text_sha256 %s", key, s.URL, s.SHA256, e.LicenseTextSHA256)
				}
				if !strings.Contains(o.Evidence, "byte-identical") {
					t.Errorf("%s: source marked identical but the evidence does not say byte-identical", key)
				}
			case wheelTextDiffers:
				if strings.Contains(o.Evidence, "byte-identical") {
					t.Errorf("%s: evidence says byte-identical but the source is marked differs", key)
				}
			default:
				t.Errorf("%s: source %s has wheel_text %q", key, s.URL, s.WheelText)
			}
		}
		if strings.Contains(o.Evidence, "byte-identical") && len(o.Sources) == 0 {
			t.Errorf("%s: evidence claims byte-identical but records no source", key)
		}
	}
}

// The generator enforces both rules, so a bad entry never reaches a committed inventory.
func TestGeneratorRefusesAnUnboundOverrideOrAMisleadingIdenticalSource(t *testing.T) {
	src, locks := newPyPIFixture(t, strings.Repeat("free text ", 8))
	plain, _, err := GeneratePythonInventory(context.Background(), src, locks, inventoryOverrides{})
	if err != nil || len(plain.Packages) != 1 {
		t.Fatalf("baseline: %v %+v", err, plain.Packages)
	}
	wheelSHA := plain.Packages[0].LicenseTextSHA256
	gen := func(o pypiOverride) error {
		_, _, err := GeneratePythonInventory(context.Background(), src, locks, inventoryOverrides{PyPILicense: map[string]pypiOverride{"foo@1.0": o}})
		return err
	}
	good := func(w, sha string) pypiOverride {
		return pypiOverride{License: "BSD-3-Clause", Declared: NoAssertion, Evidence: "e",
			Sources: []overrideSource{{URL: "https://example.com/L", SHA256: sha, WheelText: w}}}
	}
	if err := gen(good(wheelTextIdentical, wheelSHA)); err != nil {
		t.Fatalf("identical with the wheel sha must pass: %v", err)
	}
	if err := gen(good(wheelTextDiffers, strings.Repeat("b", 64))); err != nil {
		t.Fatalf("differs with another sha must pass: %v", err)
	}
	if err := gen(good(wheelTextIdentical, strings.Repeat("b", 64))); err == nil || !strings.Contains(err.Error(), "identical") {
		t.Fatalf("identical with a different sha must be refused: %v", err)
	}
	if err := gen(good("", wheelSHA)); err == nil {
		t.Fatal("a source without wheel_text must be refused")
	}
	unbound := good(wheelTextIdentical, wheelSHA)
	unbound.Declared = ""
	if err := gen(unbound); err == nil || !strings.Contains(err.Error(), "declared") {
		t.Fatalf("an override without declared must be refused: %v", err)
	}
}
