// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package releaseevidence

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

const measured = "server_cpu_percent observed 20.5 percent > limit 5"

func TestWithdrawalAcceptsOnlyADeclaredFailedMeasurementOfItsOwnKind(t *testing.T) {
	list := ClaimWithdrawals()
	if len(list) == 0 {
		t.Fatal("the withdrawal list is empty")
	}
	w := list[0]
	for name, c := range map[string]struct {
		kind string
		row  Row
		want bool
	}{
		"declared failed, cpu measured":          {w.Kind, Row{ID: w.Row, Status: StatusFailed, Detail: measured}, true},
		"declared failed, both budgets measured": {w.Kind, Row{ID: w.Row, Status: StatusFailed, Detail: "server_p95_latency_percent observed 173.9 percent > limit 5; " + measured}, true},
		"declared failed, miss plus queue_full":  {w.Kind, Row{ID: w.Row, Status: StatusFailed, Detail: "delivered mode dropped 12 records as queue_full: the exporter did not keep up; " + measured}, false},
		"declared failed, miss plus other text":  {w.Kind, Row{ID: w.Row, Status: StatusFailed, Detail: measured + "; native_cpu_overhead_percent observed 9 percent > limit 3"}, false},
		"declared failed, p95 measured":          {w.Kind, Row{ID: w.Row, Status: StatusFailed, Detail: "server_p95_latency_percent observed 17.3 percent > limit 5"}, true},
		"declared failed, no detail":             {w.Kind, Row{ID: w.Row, Status: StatusFailed}, false},
		"declared failed, harness died":          {w.Kind, Row{ID: w.Row, Status: StatusFailed, Detail: "overhead harness exited 1 without a usable result"}, false},
		"declared passed":                        {w.Kind, Row{ID: w.Row, Status: StatusPassed, Detail: measured}, false},
		"declared not_run":                       {w.Kind, Row{ID: w.Row, Status: StatusNotRun, Detail: measured}, false},
		"declared not_exercised":                 {w.Kind, Row{ID: w.Row, Status: "not_exercised", Detail: measured}, false},
		"declared out of scope":                  {w.Kind, Row{ID: w.Row, Status: StatusOutOfReleaseScope, Detail: measured, Platform: "linux/arm64"}, false},
		"declared row, other kind":               {KindBrowser, Row{ID: w.Row, Status: StatusFailed, Detail: measured}, false},
		"undeclared row":                         {w.Kind, Row{ID: w.Row + ".x", Status: StatusFailed, Detail: measured}, false},
		"undeclared row citing D65":              {w.Kind, Row{ID: "overhead.sdk.node-22.linux-amd64.queue", Status: StatusFailed, Detail: "D65 " + measured}, false},
	} {
		if _, got := WithdrawalAccepts(c.kind, c.row); got != c.want {
			t.Errorf("%s: accepted=%v, want %v", name, got, c.want)
		}
	}
	got, _ := WithdrawalAccepts(w.Kind, Row{ID: w.Row, Status: StatusFailed, Detail: measured})
	if got != w || got.Decision != WithdrawalDecision {
		t.Errorf("accepted withdrawal %+v, want %+v citing %s", got, w, WithdrawalDecision)
	}
}

// The list is not a variable a caller (or a report) can reach: the accessor returns a copy.
func TestClaimWithdrawalsIsAClosedCopy(t *testing.T) {
	a := ClaimWithdrawals()
	a[0].Row = "overhead.sdk.something.else"
	a = append(a, Withdrawal{Kind: KindRuntime, Row: "extra", Decision: WithdrawalDecision})
	b := ClaimWithdrawals()
	if b[0].Row == "overhead.sdk.something.else" || len(b) == len(a) {
		t.Fatal("changing the returned list changed the closed list")
	}
	if _, ok := WithdrawalAccepts(KindRuntime, Row{ID: "extra", Status: StatusFailed, Detail: measured}); ok {
		t.Fatal("an appended entry was accepted")
	}
}

// The list is exactly the SDK server overhead rows of the release platform that the 5 % budget covers, taken from the
// matrix itself: adding a server overhead row there, or a row to the list that the matrix does not have, is a failure.
func TestWithdrawalsAreExactlyTheLinuxAmd64ServerOverheadRowsOfTheMatrix(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "qualification", "matrix.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	idRE := regexp.MustCompile(`\{id: (overhead\.sdk\.[^,]+), suite: overhead, required: true, runner: (overhead_sdk_server|overhead_sdk_runtime_server), build: [^,]*linux-amd64,`)
	var want []string
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if m := idRE.FindStringSubmatch(line); m != nil {
			want = append(want, m[1])
		}
	}
	var got []string
	seen := map[string]bool{}
	for _, w := range ClaimWithdrawals() {
		if seen[w.Row] {
			t.Errorf("row %s is listed twice", w.Row)
		}
		seen[w.Row] = true
		if w.Kind != KindRuntime || w.Decision != WithdrawalDecision || !strings.HasPrefix(w.Row, "overhead.sdk.") {
			t.Errorf("entry %+v is not an SDK overhead row of the runtime report under %s", w, WithdrawalDecision)
		}
		if strings.HasSuffix(w.Row, ".queue") || !strings.Contains(w.Row, ".linux-amd64.http-") {
			t.Errorf("entry %s is not a linux/amd64 server CPU/latency row", w.Row)
		}
		got = append(got, w.Row)
	}
	sort.Strings(want)
	sort.Strings(got)
	if len(want) == 0 || strings.Join(want, "\n") != strings.Join(got, "\n") {
		t.Fatalf("withdrawals differ from the matrix's linux/amd64 server overhead rows\nmatrix: %q\nlist:   %q", want, got)
	}
}
