// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package releaseevidence

import (
	"regexp"
	"strings"
)

// WithdrawalDecision is the owner decision that withdraws the claims below (D65, 2026-11-18): the design's 5 %
// budget for server SDK capture stays unchanged, the measured rows stay FAILED, and the release makes no claim of it.
const WithdrawalDecision = "D65"

// WithdrawalsList names the version of the closed list below. A change to the list changes this identifier.
const WithdrawalsList = "soundpost-claim-withdrawals/1"

// Withdrawal names one report row whose claim the release withdraws, with the decision that withdrew it.
type Withdrawal struct {
	Kind     string
	Row      string
	Decision string
}

// claimWithdrawals is the closed list of withdrawn claims: exactly the linux/amd64 server SDK overhead rows
// (qualification/matrix.yaml: runner overhead_sdk_server or overhead_sdk_runtime_server) that measure the design's
// "<=5% p95 latency/CPU increase, core capture" budget. It is code, never report input: an envelope is decoded with
// unknown fields refused, a row cannot put itself on it by what its detail says, and ClaimWithdrawals hands out a copy.
// TestWithdrawalsAreExactlyTheLinuxAmd64ServerOverheadRowsOfTheMatrix keeps it equal to the matrix.
var claimWithdrawals = []Withdrawal{
	{KindRuntime, "overhead.sdk.node-22.linux-amd64.http-3hash", WithdrawalDecision},
	{KindRuntime, "overhead.sdk.node-22.linux-amd64.http-100hash", WithdrawalDecision},
	{KindRuntime, "overhead.sdk.node-24.linux-amd64.http-3hash", WithdrawalDecision},
	{KindRuntime, "overhead.sdk.node-24.linux-amd64.http-100hash", WithdrawalDecision},
	{KindRuntime, "overhead.sdk.python-3.12.linux-amd64.http-3hash", WithdrawalDecision},
	{KindRuntime, "overhead.sdk.python-3.12.linux-amd64.http-100hash", WithdrawalDecision},
	{KindRuntime, "overhead.sdk.python-3.13.linux-amd64.http-3hash", WithdrawalDecision},
	{KindRuntime, "overhead.sdk.python-3.13.linux-amd64.http-100hash", WithdrawalDecision},
	{KindRuntime, "overhead.sdk.python-3.14.linux-amd64.http-3hash", WithdrawalDecision},
	{KindRuntime, "overhead.sdk.python-3.14.linux-amd64.http-100hash", WithdrawalDecision},
	{KindRuntime, "overhead.sdk.bun-1.3.14.linux-amd64.http-3hash", WithdrawalDecision},
	{KindRuntime, "overhead.sdk.bun-1.3.14.linux-amd64.http-100hash", WithdrawalDecision},
}

// ClaimWithdrawals returns a copy of the closed list of withdrawn claims.
func ClaimWithdrawals() []Withdrawal { return append([]Withdrawal(nil), claimWithdrawals...) }

// budgetMiss matches one part of the detail the qualify exporter writes for a server overhead row that was measured
// and exceeded a budget (tools/qualify/evidence.go suiteRow: "<budget> observed <v> <unit> > limit <l>").
var budgetMiss = regexp.MustCompile(`^server_(p95_latency|cpu)_percent observed -?[0-9][0-9.e+-]* percent > limit [0-9][0-9.e+-]*$`)

// measuredBudgetMiss reports whether detail consists only of measured misses of the 5 % server budgets: a row that
// failed for any other reason (the harness died, no p95 series, delivered mode dropped records) was not measured
// against the budget, so withdrawing the claim does not cover it.
func measuredBudgetMiss(detail string) bool {
	if detail == "" {
		return false
	}
	for _, part := range strings.Split(detail, "; ") {
		if !budgetMiss.MatchString(part) {
			return false
		}
	}
	return true
}

// WithdrawalAccepts reports whether row of the report kind is a declared row that FAILED a measured budget, so the
// gate may take it as a withdrawn claim instead of a blocker. It never makes the row passed: the gate reports it as
// "claim withdrawn (D65)". A declared row that is not_run, not_exercised, unsupported, denied, out of scope, missing
// or failed without a measured budget miss is not accepted, because the measurement must exist. A passed row needs
// no withdrawal and is not accepted here.
func WithdrawalAccepts(kind string, row Row) (Withdrawal, bool) {
	if row.Status != StatusFailed || !measuredBudgetMiss(row.Detail) {
		return Withdrawal{}, false
	}
	for _, w := range claimWithdrawals {
		if w.Kind == kind && w.Row == row.ID {
			return w, true
		}
	}
	return Withdrawal{}, false
}
