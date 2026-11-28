//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/fixtures/nativeperf/qual"
)

// Node 22 and Node 24 are columns of their own, each named by the environment variable of its major; a host that names
// neither runs one Node column of whatever build it has, and a build that is not the major it was named for is no evidence.
func TestRuntimeSpecsNodeMajorsAreColumnsOfTheirOwn(t *testing.T) {
	self, err := os.Executable() // any Linux ELF
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOUNDPOST_NODE22", self)
	t.Setenv("SOUNDPOST_NODE24", self)
	t.Setenv("SOUNDPOST_NODE", "")
	a := &accept{}
	var node []runtimeSpec
	for _, sp := range a.runtimeSpecs() {
		if sp.name == "node" {
			node = append(node, sp)
		}
	}
	if len(node) != 2 || node[0].label != "node 22" || node[0].expect != "v22." || node[1].label != "node 24" || node[1].expect != "v24." {
		t.Fatalf("Node columns %+v, want node 22 (v22.) and node 24 (v24.)", node)
	}
	for _, sp := range node {
		if bin, _, why := sp.find(); bin != self {
			t.Errorf("%s: find gave %q (%s), want the binary named by its variable", sp.label, bin, why)
		}
	}

	t.Setenv("SOUNDPOST_NODE24", "")
	node = nil
	for _, sp := range a.runtimeSpecs() {
		if sp.name == "node" {
			node = append(node, sp)
		}
	}
	if len(node) != 1 || node[0].label != "node 22" {
		t.Fatalf("with only SOUNDPOST_NODE22 named the Node columns are %+v, want just node 22 (the 24 column is a not-run item, not a stand-in)", node)
	}

	// an environment variable that names no ELF binary makes the column unavailable with the variable in the reason
	notELF := t.TempDir() + "/node"
	if err := os.WriteFile(notELF, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOUNDPOST_NODE22", notELF)
	for _, sp := range a.runtimeSpecs() {
		if sp.label == "node 22" {
			if bin, _, why := sp.find(); bin != "" || !strings.Contains(why, "SOUNDPOST_NODE22") {
				t.Errorf("a non-ELF Node binary: %q (%s)", bin, why)
			}
		}
	}

	t.Setenv("SOUNDPOST_NODE22", "")
	t.Setenv("SOUNDPOST_NODE24", "")
	node = nil
	for _, sp := range a.runtimeSpecs() {
		if sp.name == "node" {
			node = append(node, sp)
		}
	}
	if len(node) != 1 || node[0].label != "node" || node[0].expect != "" {
		t.Fatalf("with no Node major named, the Node column is %+v, want the single unversioned one", node)
	}
}

// Python's columns are versioned the same way: an interpreter that is not the version its variable names is rejected by
// the column's own expectation.
func TestRuntimeSpecsPythonColumnsCarryTheirVersion(t *testing.T) {
	self, _ := os.Executable()
	t.Setenv("SOUNDPOST_QUAL_PYTHON_312_LINUX_AMD64", self)
	t.Setenv("SOUNDPOST_QUAL_PYTHON_313_LINUX_AMD64", self)
	t.Setenv("SOUNDPOST_QUAL_PYTHON_314_LINUX_AMD64", "")
	var py []runtimeSpec
	for _, sp := range (&accept{}).runtimeSpecs() {
		if sp.name == "python" {
			py = append(py, sp)
		}
	}
	if len(py) != 2 || py[0].expect != "3.12." || py[1].expect != "3.13." {
		t.Fatalf("python columns %+v, want 3.12. and 3.13.", py)
	}
}

// The three fixtures print the same wait shape: an HTTP phase and a database phase, each either run (with its kind,
// requests, round trips, the server's hold and its window) or not run / failed with a reason.
func TestRuntimeReportDecodesTheWaitPhases(t *testing.T) {
	const report = `{"runtime":"node","version":"v24.11.0","engine":{"started":true,"sample_count":7,"leaf_samples":{"jsCpuLoop":7}},"cpu":{"loop_seconds":4.8,"function":"jsCpuLoop"},` +
		`"wait":{"loop_tid":4242,"http":{"kind":"loopback HTTP (node:http server and client)","requests":53,"wait_seconds_total":3.1,"wait_seconds_min":0.05,"server_delay_s":0.05,"window_ns":[10,20]},` +
		`"database":{"kind":"PostgreSQL v3 simple query (pg_sleep) over node:net","server_version":"16.16 (Debian)","requests":12,"wait_seconds_total":2.45,"wait_seconds_min":0.2,"server_delay_s":0.2,"server_reported_s_total":2.41,"window_ns":[30,40]}}}`
	var rep runtimeReport
	if err := json.Unmarshal([]byte(report), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Wait.LoopTID != 4242 || rep.Wait.HTTP.Requests != 53 || rep.Wait.HTTP.Status != "" || rep.Wait.HTTP.WindowNs != [2]uint64{10, 20} {
		t.Errorf("http phase %+v", rep.Wait.HTTP)
	}
	truth := phaseTruth(qual.WaitKindDatabase, rep.Wait.LoopTID, rep.Wait.Database)
	if truth.Kind != qual.WaitKindDatabase || truth.Requests != 12 || truth.ServerDelayNs != 200_000_000 || truth.ServerReportedNs != 2_410_000_000 || truth.WaitTotalNs != 2_450_000_000 || truth.StartNs != 30 || truth.EndNs != 40 || truth.TID != 4242 {
		t.Errorf("database truth %+v", truth)
	}
	const notRun = `{"wait":{"loop_tid":1,"http":{"status":"not_run","reason":"phase not requested"},"database":{"status":"error","reason":"database_unreachable: connect ECONNREFUSED <ip>"}}}`
	rep = runtimeReport{}
	if err := json.Unmarshal([]byte(notRun), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Wait.HTTP.Status != "not_run" || rep.Wait.Database.Status != "error" || !strings.HasPrefix(rep.Wait.Database.Reason, "database_unreachable") {
		t.Errorf("phases %+v", rep.Wait)
	}
}

// The column's wait row is supported only on every phase it ran: a database wait that failed fails the row even though
// the HTTP wait of the same capture passed, and one that could not be judged leaves the row unqualified.
func TestCombineWaitRowsNeedsEveryPhase(t *testing.T) {
	ok := func(e string) qual.Row { return qual.Supported([]string{e}, nil) }
	for name, tc := range map[string]struct {
		phases map[string]qual.Row
		want   qual.State
		inReas string
	}{
		"both phases pass":                 {map[string]qual.Row{phaseHTTP: ok("h"), phaseDatabase: ok("d")}, qual.StateSupported, ""},
		"only the http phase ran and pass": {map[string]qual.Row{phaseHTTP: ok("h")}, qual.StateSupported, ""},
		"database fails, http passes":      {map[string]qual.Row{phaseHTTP: ok("h"), phaseDatabase: qual.Failed("blocked time below the bound", nil)}, qual.StateFailed, "database: blocked time below the bound"},
		"database could not be judged":     {map[string]qual.Row{phaseHTTP: ok("h"), phaseDatabase: qual.Unqualified("database_unreachable: refused", nil)}, qual.StateUnqualified, "database_unreachable"},
		"a failure outranks an unjudged":   {map[string]qual.Row{phaseHTTP: qual.Failed("f", nil), phaseDatabase: qual.Unqualified("u", nil)}, qual.StateFailed, "http: f"},
		"no phase ran":                     {map[string]qual.Row{}, qual.StateUnqualified, "no wait phase"},
	} {
		got := combineWaitRows(tc.phases, map[string]any{})
		if got.State != tc.want || !strings.Contains(got.Reason, tc.inReas) {
			t.Errorf("%s: %s %q, want %s containing %q", name, got.State, got.Reason, tc.want, tc.inReas)
		}
		if err := got.Validate("wait"); err != nil {
			t.Errorf("%s: invalid row: %v", name, err)
		}
		if got.State == qual.StateSupported && len(got.Evidence) != len(tc.phases) {
			t.Errorf("%s: evidence %v does not cover every phase", name, got.Evidence)
		}
	}
}

// The address of the database is the host's own: the report names only the kind of endpoint.
func TestDatabaseEndpointKindNeverNamesTheAddress(t *testing.T) {
	for addr, want := range map[string]string{"127.0.0.1:5432": "loopback_host", "localhost:5432": "loopback_host", "[::1]:5432": "loopback_host", "192.0.2.7:55433": "other_host", "db.example.invalid:5432": "other_host", "": "unknown", "nonsense": "unknown"} {
		t.Setenv(dbAddrEnv, addr)
		got := databaseEndpointKind()
		if got != want {
			t.Errorf("%q: %s, want %s", addr, got, want)
		}
		if addr != "" && strings.Contains(got, addr) {
			t.Errorf("the endpoint kind %q contains the address", got)
		}
	}
}

func TestRuntimeDBWaitScenarioIsRegisteredAndNeedsAnEndpoint(t *testing.T) {
	if _, ok := hostScenarios["runtime_db_wait"]; !ok {
		t.Fatal("runtime_db_wait is not a registered host scenario")
	}
	t.Setenv(dbAddrEnv, "")
	row := (&accept{res: &qual.QualificationResult{}}).runtimeDBWait()
	if row.State != qual.StateUnqualified || !strings.Contains(row.Reason, dbAddrEnv) || !strings.Contains(row.Reason, "database_endpoint_unavailable") {
		t.Fatalf("without an endpoint: %+v", row)
	}
	if err := row.Validate("runtime_db_wait"); err != nil {
		t.Fatal(err)
	}
}

// A column that already ran its database wait in this acceptance run is not run again: the scenario takes its row.
func TestDatabaseRowForReusesTheColumnRunOfThisRun(t *testing.T) {
	want := qual.Supported([]string{"node 22: native blocked time ... across 12 queries"}, nil)
	a := &accept{res: &qual.QualificationResult{Runtimes: []qual.RuntimeColumn{{
		Runtime: "node",
		Wait:    qual.Supported([]string{"x"}, map[string]any{"column": "node 22", "phase_rows": map[string]qual.Row{phaseHTTP: qual.Supported([]string{"h"}, nil), phaseDatabase: want}}),
	}}}}
	sp := runtimeSpec{name: "node", label: "node 22", find: func() (string, []string, string) {
		t.Fatal("the column was run again")
		return "", nil, ""
	}}
	row, source := a.databaseRowFor(sp, "")
	if row.State != qual.StateSupported || row.Evidence[0] != want.Evidence[0] || !strings.Contains(source, "this acceptance run") {
		t.Fatalf("%+v (%s)", row, source)
	}
	// a column of the same runtime and another build is not this build's evidence
	sp.label = "node 24"
	sp.find = func() (string, []string, string) { return "", nil, "not installed" }
	row, source = a.databaseRowFor(sp, t.TempDir())
	if row.State != qual.StateUnqualified || !strings.Contains(row.Reason, "not installed") || !strings.Contains(source, "database-wait run") {
		t.Fatalf("another build's column was reused: %+v (%s)", row, source)
	}
}

// A column's wait row is the verdict of two captures (HTTP, database), each with its own ledger: either one failing fails
// the column, either one that could not be judged leaves it unqualified, and a capture that could not be judged as a whole
// stands for its phase.
func TestMergeDatabaseWaitTakesEachCapturesVerdict(t *testing.T) {
	httpCapture := func(state qual.Row) qual.Row {
		return combineWaitRows(map[string]qual.Row{phaseHTTP: state}, map[string]any{"capture_rates": "http-rates", "memory_ledger": "http-ledger"})
	}
	dbCapture := func(state qual.Row) qual.Row {
		return combineWaitRows(map[string]qual.Row{phaseDatabase: state}, map[string]any{"capture_rates": "db-rates", "memory_ledger": "db-ledger", "correlation": "db-corr"})
	}
	ok := func(e string) qual.Row { return qual.Supported([]string{e}, nil) }
	for name, tc := range map[string]struct {
		http, db qual.Row
		want     qual.State
		inReason string
	}{
		"both captures pass":                                {httpCapture(ok("http ok")), dbCapture(ok("db ok")), qual.StateSupported, ""},
		"database fails, http passes":                       {httpCapture(ok("http ok")), dbCapture(qual.Failed("below the bound", nil)), qual.StateFailed, "database: below the bound"},
		"http fails, database passes":                       {httpCapture(qual.Failed("over the budget", nil)), dbCapture(ok("db ok")), qual.StateFailed, "http: over the budget"},
		"database capture could not be judged":              {httpCapture(ok("http ok")), dbCapture(qual.Unqualified("database_unreachable: refused", nil)), qual.StateUnqualified, "database_unreachable"},
		"database capture refused by the helper as a whole": {httpCapture(ok("http ok")), qual.Failed("helper refused the signed request", nil), qual.StateFailed, "database: helper refused"},
		"http capture refused by the helper as a whole":     {qual.Failed("helper refused the signed request", nil), dbCapture(ok("db ok")), qual.StateFailed, "http: helper refused"},
	} {
		got := mergeDatabaseWait(tc.http, tc.db, "node 24")
		if got.State != tc.want || !strings.Contains(got.Reason, tc.inReason) {
			t.Errorf("%s: %s %q, want %s containing %q", name, got.State, got.Reason, tc.want, tc.inReason)
		}
		if err := got.Validate("wait"); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		if got.Detail["column"] != "node 24" {
			t.Errorf("%s: the column label is %v", name, got.Detail["column"])
		}
		if _, has := databasePhaseRow(got); !has {
			t.Errorf("%s: the merged row has no database phase for the scenario to reuse", name)
		}
		if tc.http.Detail != nil && tc.db.Detail != nil && (got.Detail["capture_rates"] != "http-rates" || got.Detail["database_capture_capture_rates"] != "db-rates" || got.Detail["database_capture_memory_ledger"] != "db-ledger" || got.Detail["memory_ledger"] != "http-ledger") {
			t.Errorf("%s: the two captures' costs are mixed up: %v", name, got.Detail)
		}
	}
}
