// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package releaseevidence

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

// WithdrawalAccepts reports whether row of the report kind is a declared row that FAILED a measured budget, so the
// gate may take it as a withdrawn claim instead of a blocker. It never makes the row passed: the gate reports it as
// "claim withdrawn (D65)". The decision rests on the row's structured FailureClass: it must be FailureBudgetMiss, which
// the exporter sets only for a row that was measured, exceeded a budget and had no other failure. The row's detail is
// never read, so a row that failed for another reason (harness, dropped records, an assertion) blocks however its detail
// reads. A declared row that is not_run, not_exercised, unsupported, denied, out of scope, missing or failed for any
// other class is not accepted, because the measurement must exist. A passed row needs no withdrawal and is not accepted.
func WithdrawalAccepts(kind string, row Row) (Withdrawal, bool) {
	if row.Status != StatusFailed || row.FailureClass != FailureBudgetMiss {
		return Withdrawal{}, false
	}
	for _, w := range claimWithdrawals {
		if w.Kind == kind && w.Row == row.ID {
			return w, true
		}
	}
	return Withdrawal{}, false
}
