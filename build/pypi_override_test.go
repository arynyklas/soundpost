// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"
)

// pypiFixture serves one PyPI package whose JSON carries the given free-text license and whose pure-Python
// wheel holds a dist-info LICENSE file, so the inventory can pin the artifact by its sha256.
type pypiFixture struct {
	fixtureSource
	meta  string
	wheel []byte
}

func (p pypiFixture) PyPIMeta(context.Context, string, string) ([]byte, error) {
	return []byte(p.meta), nil
}
func (p pypiFixture) Download(context.Context, string) ([]byte, error) { return p.wheel, nil }

func newPyPIFixture(t *testing.T, infoLicense string) (pypiFixture, map[string][]byte) {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("foo-1.0.dist-info/LICENSE")
	if err != nil {
		t.Fatal(err)
	}
	w.Write([]byte("Redistribution and use in source and binary forms, with or without modification ...\n"))
	if err = zw.Close(); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(buf.Bytes())
	digest := hex.EncodeToString(sum[:])
	doc, _ := json.Marshal(map[string]any{
		"info": map[string]any{"license": infoLicense, "classifiers": []string{"License :: OSI Approved :: BSD License"}},
		"urls": []map[string]any{{"filename": "foo-1.0-py3-none-any.whl", "url": "https://files.example/foo-1.0-py3-none-any.whl", "packagetype": "bdist_wheel", "digests": map[string]string{"sha256": digest}}},
	})
	lock := "foo==1.0 \\\n    --hash=sha256:" + digest + "\n"
	return pypiFixture{meta: string(doc), wheel: buf.Bytes()}, map[string][]byte{
		"requirements-dev.lock": []byte(lock), "requirements-integrations.lock": []byte("# no pins\n"),
	}
}

func pyLicenseOf(t *testing.T, infoLicense string, ov pypiOverride, withOverride bool) pyEntry {
	t.Helper()
	src, locks := newPyPIFixture(t, infoLicense)
	var o inventoryOverrides
	if withOverride {
		o.PyPILicense = map[string]pypiOverride{"foo@1.0": ov}
	}
	inv, _, err := GeneratePythonInventory(context.Background(), src, locks, o)
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Packages) != 1 {
		t.Fatalf("want one package: %+v", inv.Packages)
	}
	return inv.Packages[0]
}

// The free-text PyPI license "BSD" is a valid-looking identifier that is not an SPDX one and does not say
// which BSD clause set applies; a reviewed override tied to that exact declared value resolves it, and only it.
func TestPyPIOverrideResolvesAnAmbiguousDeclaredLicenseOnlyWhenTheDeclaredValueMatches(t *testing.T) {
	ov := pypiOverride{License: "BSD-3-Clause", Declared: "BSD", Evidence: "wheel LICENSE is the three-clause text",
		Sources: []overrideSource{{URL: "https://example.com/LICENSE", SHA256: strings.Repeat("a", 64), WheelText: wheelTextDiffers}}}
	if got := pyLicenseOf(t, "BSD", ov, false); got.License != "BSD" {
		t.Fatalf("without an override the declared value stays: %+v", got)
	}
	got := pyLicenseOf(t, "BSD", ov, true)
	if got.License != "BSD-3-Clause" || !strings.Contains(got.LicenseSource, "reviewed override license-overrides.json") ||
		!strings.Contains(got.LicenseSource, "wheel LICENSE is the three-clause text") || !strings.Contains(got.LicenseSource, "https://example.com/LICENSE") {
		t.Fatalf("override must resolve the ambiguous BSD and record its evidence and source URL: %+v", got)
	}
	// the metadata changed to a different license: a review of "BSD" must never approve it
	if got = pyLicenseOf(t, "GPL-3.0-only", ov, true); got.License != "GPL-3.0-only" {
		t.Fatalf("an override reviewed for BSD must not rewrite a different declared license: %+v", got)
	}
	// an explicit NOASSERTION binding resolves only an ambiguous record, never a declared license
	bare := pypiOverride{License: "BSD-3-Clause", Declared: NoAssertion, Evidence: "reviewed"}
	if got = pyLicenseOf(t, "BSD", bare, true); got.License != "BSD" {
		t.Fatalf("a NOASSERTION binding must not rewrite a declared license: %+v", got)
	}
	long := strings.Repeat("free text ", 8)
	if got = pyLicenseOf(t, long, bare, true); got.License != "BSD-3-Clause" {
		t.Fatalf("a NOASSERTION binding resolves an ambiguous (NOASSERTION) record: %+v", got)
	}
}

var sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Every committed PyPI override states what metadata it was reviewed against, names its evidence, cites the
// upstream license files by URL and sha256, and agrees with the committed inventory entry it produced.
func TestCommittedPyPIOverridesCarryDeclaredEvidenceAndUpstreamSources(t *testing.T) {
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
	for _, key := range []string{"amqp@5.4.2", "billiard@4.3.2", "vine@5.1.0", "click-plugins@1.1.1.2", "prompt-toolkit@3.0.53"} {
		o, ok := ov.PyPILicense[key]
		if !ok {
			t.Errorf("%s: no reviewed override", key)
			continue
		}
		if o.License != "BSD-3-Clause" {
			t.Errorf("%s: override license %q, want BSD-3-Clause (the upstream LICENSE is the three-clause text)", key, o.License)
		}
		if d := o.Declared; d != "BSD" && d != NoAssertion {
			t.Errorf("%s: declared %q must name the metadata value the review covers", key, d)
		}
	}
	for key, o := range ov.PyPILicense {
		e, ok := have[key]
		switch {
		case !ok:
			t.Errorf("%s: override for a pin that is not in python-licenses.json", key)
			continue
		case e.License != o.License:
			t.Errorf("%s: inventory carries %q, override says %q (regenerate with `go run ./build inventory --python`)", key, e.License, o.License)
		}
		if !licenseApproved(o.License) {
			t.Errorf("%s: override license %q is not in the approved set", key, o.License)
		}
		if strings.TrimSpace(o.Evidence) == "" {
			t.Errorf("%s: no evidence", key)
		}
		if strings.HasPrefix(key, "amqp@") || strings.HasPrefix(key, "billiard@") || strings.HasPrefix(key, "vine@") ||
			strings.HasPrefix(key, "click-plugins@") || strings.HasPrefix(key, "prompt-toolkit@") {
			if len(o.Sources) == 0 {
				t.Errorf("%s: no upstream license file URL recorded", key)
			}
		}
		for _, s := range o.Sources {
			if !strings.HasPrefix(s.URL, "https://") || !sha256Hex.MatchString(s.SHA256) {
				t.Errorf("%s: source %+v needs an https URL and a sha256", key, s)
			}
		}
	}
}

// The real tree: with the committed inventories and an explicit creation time, the supply-chain checks of the
// release gate (inventory freshness, licenses, notices, SBOM generation) have nothing to block on.
func TestRepositorySupplyChainChecksPassWithAnExplicitCreationTime(t *testing.T) {
	var m ReleaseManifest
	for _, c := range checkSupplyChain(Reports{Root: "..", Version: "0.0.0-test", Created: "2026-11-16T00:00:00Z",
		NoticesPath: "../THIRD_PARTY_NOTICES"}, &m) {
		if len(c.Blocking) != 0 {
			t.Errorf("%s blocks the gate:\n  %s", c.Name, strings.Join(c.Blocking, "\n  "))
		}
	}
}
