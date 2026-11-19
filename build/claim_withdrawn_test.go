// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/releaseevidence"
)

// withdrawnRow is a server SDK CPU overhead row of the linux/amd64 release that the release does not claim
// (owner decision D65). measuredDetail is what the qualify exporter writes for a row that was measured and missed
// its budget (tools/qualify/evidence.go suiteRow).
const (
	withdrawnRow   = "overhead.sdk.node-22.linux-amd64.http-3hash"
	measuredDetail = "server_cpu_percent observed 20.5 percent > limit 5"
)

func gateWithRuntimeRows(t *testing.T, expected []string, rows ...EvidenceRow) (ReleaseManifest, Check) {
	t.Helper()
	f := newFixture(t).signed()
	raw, _ := json.Marshal(EvidenceReport{Schema: evidenceSchema, Kind: "runtime", Commit: testCommit, SourceSHA256: testSource, Expected: expected, Rows: rows})
	write(t, f.evidence["runtime"], string(raw))
	r := f.reports()
	r.ApprovalPath = f.approve(testCommit)
	m, _ := Release(context.Background(), testCommit, r)
	for _, c := range m.Checks {
		if c.Name == "evidence_runtime" {
			return m, c
		}
	}
	t.Fatal("no evidence_runtime check")
	return m, Check{}
}

func TestGateWithdrawsTheClaimOfADeclaredFailedRowAndReportsIt(t *testing.T) {
	m, c := gateWithRuntimeRows(t, []string{withdrawnRow}, EvidenceRow{ID: withdrawnRow, Status: "failed", Detail: measuredDetail})
	if c.Status != "pass" || len(c.Blocking) != 0 {
		t.Fatalf("a declared failed row measured against its budget must not block: %+v", c)
	}
	if !strings.Contains(c.Detail, "claim withdrawn (D65)") || !strings.Contains(c.Detail, withdrawnRow) || !strings.Contains(c.Detail, "not passed") {
		t.Fatalf("the check detail must say the claim is withdrawn, name the row and that it did not pass: %q", c.Detail)
	}
	want := "runtime row " + withdrawnRow + ": claim withdrawn (D65), failed: " + measuredDetail
	if len(m.ClaimsWithdrawn) != 1 || m.ClaimsWithdrawn[0] != want {
		t.Fatalf("the manifest must list the withdrawn claim as %q, got %q", want, m.ClaimsWithdrawn)
	}
	for _, b := range m.Blocking {
		if strings.Contains(b, "evidence_runtime") {
			t.Fatalf("withdrawn row blocks the gate: %v", m.Blocking)
		}
	}
}

func TestGateTextOutputNamesEveryWithdrawnClaim(t *testing.T) {
	f := newFixture(t).signed()
	raw, _ := json.Marshal(EvidenceReport{Schema: evidenceSchema, Kind: "runtime", Commit: testCommit, SourceSHA256: testSource, Expected: []string{withdrawnRow},
		Rows: []EvidenceRow{{ID: withdrawnRow, Status: "failed", Detail: measuredDetail}}})
	write(t, f.evidence["runtime"], string(raw))
	var out bytes.Buffer
	var args []string
	for _, a := range f.gateArgs("") {
		if a != "--json" {
			args = append(args, a)
		}
	}
	_ = runPackage("gate", args, &out)
	if !strings.Contains(out.String(), "CLAIM WITHDRAWN (D65) runtime row "+withdrawnRow) {
		t.Fatalf("gate output must name the withdrawn claim:\n%s", out.String())
	}
}

func TestGateStillBlocksEveryRowThatIsNotExactlyADeclaredFailedMeasurement(t *testing.T) {
	const undeclared = "overhead.sdk.node-22.linux-amd64.queue"
	for _, tc := range []struct {
		name string
		row  EvidenceRow
		want string
	}{
		{"undeclared failed row", EvidenceRow{ID: undeclared, Status: "failed", Detail: measuredDetail}, "runtime row " + undeclared + " is failed"},
		{"undeclared row that cites D65", EvidenceRow{ID: undeclared, Status: "failed", Detail: "D65 claim withdrawn; " + measuredDetail}, "runtime row " + undeclared + " is failed"},
		{"declared row not_run", EvidenceRow{ID: withdrawnRow, Status: "not_run", Detail: "D65"}, "runtime row " + withdrawnRow + " is not_run"},
		{"declared row not_exercised", EvidenceRow{ID: withdrawnRow, Status: "not_exercised", Detail: "D65"}, "runtime row " + withdrawnRow + " is not_exercised"},
		{"declared row unsupported", EvidenceRow{ID: withdrawnRow, Status: "unsupported"}, "runtime row " + withdrawnRow + " is unsupported"},
		{"declared row denied", EvidenceRow{ID: withdrawnRow, Status: "denied"}, "runtime row " + withdrawnRow + " is denied"},
		{"declared row out of scope", EvidenceRow{ID: withdrawnRow, Status: "out_of_release_scope", Platform: "linux/amd64", Detail: "D10 D65"}, "runtime row " + withdrawnRow + " is out_of_release_scope"},
		{"declared row failed without a measurement", EvidenceRow{ID: withdrawnRow, Status: "failed", Detail: "overhead harness exited 1 without a usable result: boom"}, "runtime row " + withdrawnRow + " is failed"},
		{"declared row failed with no detail", EvidenceRow{ID: withdrawnRow, Status: "failed"}, "runtime row " + withdrawnRow + " is failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, c := gateWithRuntimeRows(t, []string{tc.row.ID}, tc.row)
			if c.Status != "blocked" || !strings.Contains(strings.Join(c.Blocking, "\n"), tc.want) {
				t.Fatalf("want a block naming %q, got %+v", tc.want, c)
			}
			if len(m.ClaimsWithdrawn) != 0 || strings.Contains(c.Detail, "withdrawn") {
				t.Fatalf("a row that is not accepted must not be reported as withdrawn: %q %q", m.ClaimsWithdrawn, c.Detail)
			}
		})
	}
}

func TestGateBlocksADeclaredRowThatHasNoResultAtAll(t *testing.T) {
	_, c := gateWithRuntimeRows(t, []string{withdrawnRow, "row-1"}, EvidenceRow{ID: "row-1", Status: "passed"})
	if c.Status != "blocked" || !strings.Contains(strings.Join(c.Blocking, "\n"), "runtime expected row "+withdrawnRow+" has no result") {
		t.Fatalf("a missing declared row must block: %+v", c)
	}
}

func TestGateDoesNotWithdrawADeclaredRowInAnotherReportKind(t *testing.T) {
	f := newFixture(t).signed()
	raw, _ := json.Marshal(EvidenceReport{Schema: evidenceSchema, Kind: "browser", Commit: testCommit, SourceSHA256: testSource, Expected: []string{withdrawnRow},
		Rows: []EvidenceRow{{ID: withdrawnRow, Status: "failed", Detail: measuredDetail}}})
	write(t, f.evidence["browser"], string(raw))
	r := f.reports()
	r.ApprovalPath = f.approve(testCommit)
	m, _ := Release(context.Background(), testCommit, r)
	if !strings.Contains(strings.Join(m.Blocking, "\n"), "browser row "+withdrawnRow+" is failed") {
		t.Fatalf("the list is per report kind: %v", m.Blocking)
	}
}

// The list is code, not input: an envelope cannot carry, add to or rename it (the gate decodes envelopes with
// unknown fields refused), and nothing a row says about itself puts it on the list.
func TestWithdrawnClaimsCannotBeDeclaredByAReport(t *testing.T) {
	f := newFixture(t).signed()
	for name, body := range map[string]string{
		"extra envelope field": `{"schema":"` + evidenceSchema + `","kind":"runtime","commit":"` + testCommit + `","source_sha256":"` + testSource + `","claims_withdrawn":["overhead.sdk.node-22.linux-amd64.queue"],"expected_rows":["overhead.sdk.node-22.linux-amd64.queue"],"rows":[{"id":"overhead.sdk.node-22.linux-amd64.queue","status":"failed","detail":"` + measuredDetail + `"}]}`,
		"extra row field":      `{"schema":"` + evidenceSchema + `","kind":"runtime","commit":"` + testCommit + `","source_sha256":"` + testSource + `","expected_rows":["overhead.sdk.node-22.linux-amd64.queue"],"rows":[{"id":"overhead.sdk.node-22.linux-amd64.queue","status":"failed","withdrawn":"D65","detail":"` + measuredDetail + `"}]}`,
	} {
		write(t, f.evidence["runtime"], body)
		r := f.reports()
		r.ApprovalPath = f.approve(testCommit)
		m, _ := Release(context.Background(), testCommit, r)
		if !strings.Contains(strings.Join(m.Blocking, "\n"), "runtime evidence report malformed") || len(m.ClaimsWithdrawn) != 0 {
			t.Fatalf("%s: a report must not be able to declare a withdrawn claim: %v", name, m.Blocking)
		}
	}
}

func TestEveryWithdrawalCitesDecisionD65(t *testing.T) {
	list := releaseevidence.ClaimWithdrawals()
	if len(list) == 0 {
		t.Fatal("the withdrawal list is empty")
	}
	for _, w := range list {
		if w.Decision != "D65" || w.Kind != releaseevidence.KindRuntime {
			t.Errorf("withdrawal %+v must cite D65 on the runtime report", w)
		}
	}
}
