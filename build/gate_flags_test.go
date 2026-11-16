// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// gateArgs is the documented invocation (docs/releases/security.md, release.yml) over a fixture root.
func (f *fixture) gateArgs(omit string, extra ...string) []string {
	set := map[string]string{"--version": testVersion, "--commit": testCommit, "--created": "2026-11-10T00:00:00Z"}
	args := []string{"--root", f.root, "--ledger", f.ledger, "--artifacts", f.art, "--json"}
	for _, k := range []string{"--version", "--commit", "--created"} {
		if k != omit {
			args = append(args, k, set[k])
		}
	}
	for _, kind := range EvidenceKinds {
		args = append(args, "--evidence", kind+"="+f.evidence[kind])
	}
	return append(args, extra...)
}

// A gate invocation that omits an input the gate cannot work without is refused before any gate result is
// computed or printed: a partial result ("blocking=0" or an SBOM failure buried among other items) is not an answer.
func TestGateRejectsMissingVersionCommitOrCreationTimeBeforePrintingAResult(t *testing.T) {
	for _, flag := range []string{"--version", "--commit", "--created"} {
		t.Run(flag, func(t *testing.T) {
			f := newFixture(t)
			var out bytes.Buffer
			err := runPackage("gate", f.gateArgs(flag), &out)
			if err == nil || !strings.Contains(err.Error(), flag) {
				t.Fatalf("gate without %s must fail naming the flag: %v", flag, err)
			}
			if out.Len() != 0 {
				t.Fatalf("gate printed a result before rejecting the missing %s:\n%s", flag, out.String())
			}
		})
	}
	f := newFixture(t)
	var out bytes.Buffer
	err := runPackage("gate", f.gateArgs("--created"), &out)
	if err == nil || !strings.Contains(err.Error(), "git show -s") {
		t.Fatalf("the rejection must show how to derive the timestamp from the commit: %v", err)
	}
}

// SPDX 2.3 requires creationInfo.created as UTC YYYY-MM-DDThh:mm:ssZ; the gate takes the one value the
// SBOM subcommand takes and refuses anything else before generating a document that would be invalid.
func TestCreationTimeMustBeASPDXUTCTimestamp(t *testing.T) {
	for _, bad := range []string{"yesterday", "2026-11-10", "2026-11-10T00:00:00+05:00", "2026-11-10T00:00:00.5Z", "2026-13-10T00:00:00Z", "2026-11-10 00:00:00Z"} {
		f := newFixture(t)
		var out bytes.Buffer
		err := runPackage("gate", f.gateArgs("--created", "--created", bad), &out)
		if err == nil || !strings.Contains(err.Error(), "--created") || out.Len() != 0 {
			t.Errorf("--created %q must be rejected before the gate runs: err=%v out=%q", bad, err, out.String())
		}
		if _, gerr := GenerateSPDX(Inventory{}, "1", bad); gerr == nil {
			t.Errorf("GenerateSPDX accepted creation time %q", bad)
		}
		if _, gerr := GenerateCycloneDX(Inventory{}, "1", bad); gerr == nil {
			t.Errorf("GenerateCycloneDX accepted creation time %q", bad)
		}
	}
	if _, err := GenerateSPDX(Inventory{}, "1", "2026-11-10T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
}

// With the documented inputs the gate's SBOM check passes on the fixture; the documented invocation names
// --created and a way to derive it from the commit time.
func TestGateWithTheDocumentedInvocationPassesTheSBOMCheck(t *testing.T) {
	f := newFixture(t).signed()
	var out bytes.Buffer
	_ = runPackage("gate", f.gateArgs(""), &out)
	var m ReleaseManifest
	if err := json.Unmarshal(out.Bytes(), &m); err != nil {
		t.Fatalf("gate --json output: %v\n%s", err, out.String())
	}
	found := false
	for _, c := range m.Checks {
		if c.Name == checkSBOM {
			found = true
			if c.Status != "pass" || len(c.Blocking) != 0 {
				t.Fatalf("sbom check with --created must pass: %+v", c)
			}
		}
	}
	if !found || m.CycloneDXSHA256 == "" || m.SPDXSHA256 == "" {
		t.Fatalf("sbom check missing or digests not recorded: %+v", m)
	}
	for _, doc := range []string{"docs/releases/checklist.md", "docs/releases/security.md"} {
		raw, err := os.ReadFile("../" + doc)
		if err != nil {
			t.Fatal(err)
		}
		text := string(raw)
		if !strings.Contains(text, "build gate") || !strings.Contains(text, "--created") {
			t.Errorf("%s must document the gate invocation with --created", doc)
		}
	}
	checklist := deployFile(t, "docs/releases/checklist.md")
	if !strings.Contains(checklist, "git show -s") {
		t.Error("docs/releases/checklist.md must show how --created is derived from the commit time")
	}
}

// A Release call that reaches the SBOM check without a creation time says what is missing and how to supply it.
func TestSBOMCheckWithoutACreationTimeNamesTheFlag(t *testing.T) {
	f := newFixture(t)
	r := f.reports()
	r.Created = ""
	var m ReleaseManifest
	var sbom Check
	for _, c := range checkSupplyChain(r, &m) {
		if c.Name == checkSBOM {
			sbom = c
		}
	}
	if len(sbom.Blocking) != 1 || !strings.Contains(sbom.Blocking[0], "--created") || strings.Contains(sbom.Blocking[0], "cyclonedx=<nil>") {
		t.Fatalf("blocking item must name --created, got %v", sbom.Blocking)
	}
}
