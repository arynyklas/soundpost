//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/arynyklas/soundpost/fixtures/nativeperf/qual"
	"github.com/arynyklas/soundpost/internal/nativeperf"
)

func init() { registerHostScenario("runtime_db_wait", (*accept).runtimeDBWait) }

// requiredDBWaitRuntimes are the runtimes whose event loops have to have waited on the database: Node's success never
// qualifies Bun, and neither qualifies CPython.
var requiredDBWaitRuntimes = []string{"python", "node", "bun"}

// runtimeDBWait is the runtime_db_wait scenario: every runtime column (each CPython, each Node, Bun) ran queries of
// `select pg_sleep(0.2)` against a real PostgreSQL server over the wire protocol, so its event-loop thread blocked in a
// socket read while the server slept; the native blocked time of that thread inside the window of the queries has to match
// what the runtime measured and what the server itself reported. The server comes from dbAddrEnv; no qualification host
// runs one, so without it the row is unqualified with that reason. A column that already ran its database wait in this
// acceptance run (--runtimes) is not run again.
func (a *accept) runtimeDBWait() qual.Row {
	if os.Getenv(dbAddrEnv) == "" {
		return qual.Unqualified("database_endpoint_unavailable: "+dbAddrEnv+" is not set: no PostgreSQL server was given to this run (no qualification host runs one), so no runtime waited on a database", nil)
	}
	if a.caps.OffCPU != nativeperf.Supported {
		reason, _ := a.schedulerReason()
		return qual.Unqualified(reason, nil)
	}
	scriptDir, _ := filepath.Abs(a.o.runtimeDir)
	columns := map[string]qual.Row{}
	ran := map[string]bool{}
	var labels []string
	for _, sp := range a.runtimeSpecs() {
		row, source := a.databaseRowFor(sp, scriptDir)
		fmt.Fprintf(os.Stderr, "acceptance: runtime_db_wait %s: %s (%s)\n", sp.label, row.State, source)
		columns[sp.label] = row
		labels = append(labels, sp.label)
		ran[sp.name] = true
	}
	sort.Strings(labels)
	var evidence, failed, unjudged []string
	for _, label := range labels {
		row := columns[label]
		switch row.State {
		case qual.StateSupported:
			evidence = append(evidence, row.Evidence...)
		case qual.StateFailed:
			failed = append(failed, label+": "+row.Reason)
		default:
			unjudged = append(unjudged, label+": "+row.Reason)
		}
	}
	for _, name := range requiredDBWaitRuntimes {
		if !ran[name] {
			unjudged = append(unjudged, name+": no column of this runtime was run (--runtimes)")
		}
	}
	detail := map[string]any{"columns": columns, "database_endpoint": databaseEndpointKind(), "query": "with s as materialized (select pg_sleep(0.2)) select clock_timestamp() - statement_timestamp() from s (simple Query, one connection per runtime)"}
	switch {
	case len(failed) > 0:
		return qual.Failed(strings.Join(failed, "; "), detail)
	case len(unjudged) > 0:
		return qual.Unqualified(strings.Join(unjudged, "; "), detail)
	}
	return qual.Supported(evidence, detail)
}

// databasePhaseRow is the row of the database phase in a column's wait row, when the column ran one.
func databasePhaseRow(wait qual.Row) (qual.Row, bool) {
	phases, _ := wait.Detail["phase_rows"].(map[string]qual.Row)
	row, ok := phases[phaseDatabase]
	return row, ok
}

// databaseRowFor is the database-wait row of one runtime column: taken from the column's run in this acceptance run when it
// ran its database capture, otherwise from a run of the column of its own, and a description of where it came from.
func (a *accept) databaseRowFor(sp runtimeSpec, scriptDir string) (qual.Row, string) {
	for _, col := range a.res.Runtimes {
		if col.Wait.Detail["column"] != sp.label {
			continue
		}
		if row, ok := databasePhaseRow(col.Wait); ok {
			return row, "the runtime column run of this acceptance run"
		}
		if _, judged := col.Wait.Detail["phase_rows"]; !judged && col.Wait.State != qual.StateSupported {
			// no phase was judged at all: the capture itself could not be (the helper refused it, the correlation failed)
			return col.Wait, "the runtime column run of this acceptance run, which could not be judged"
		}
	}
	col := a.runtimeColumn(sp, scriptDir, dbWaitPlan)
	if row, ok := databasePhaseRow(col.Wait); ok {
		return row, "a database-wait run of this column"
	}
	if col.Wait.State != qual.StateSupported {
		return col.Wait, "a database-wait run of this column, which could not be judged"
	}
	return qual.Unqualified("the "+sp.label+" fixture did not run a database phase", nil), "a database-wait run of this column"
}

// withDatabaseWait adds the database wait to a runtime column that has taken its HTTP capture: the column runs once more
// with dbWaitPlan, and its wait row becomes the one of both captures.
func (a *accept) withDatabaseWait(col qual.RuntimeColumn, sp runtimeSpec, scriptDir string) qual.RuntimeColumn {
	col.Wait = mergeDatabaseWait(col.Wait, a.runtimeColumn(sp, scriptDir, dbWaitPlan).Wait, sp.label)
	return col
}

// mergeDatabaseWait is the wait row of a column from the wait row of its HTTP capture and the one of its database capture
// (each capture has its own scheduler evidence, memory ledger and verdict): the column is supported only when the phases of
// both are. A capture that could not be judged as a whole stands for its phase.
func mergeDatabaseWait(httpCapture, dbCapture qual.Row, label string) qual.Row {
	phases := map[string]qual.Row{}
	if judged, ok := httpCapture.Detail["phase_rows"].(map[string]qual.Row); ok {
		for name, row := range judged {
			phases[name] = row
		}
	} else {
		phases[phaseHTTP] = httpCapture
	}
	if row, ok := databasePhaseRow(dbCapture); ok {
		phases[phaseDatabase] = row
	} else {
		phases[phaseDatabase] = dbCapture
	}
	detail := map[string]any{}
	for k, v := range httpCapture.Detail {
		if k != "phase_rows" {
			detail[k] = v
		}
	}
	for _, k := range []string{"capture_rates", "memory_ledger", "correlation"} {
		if v, ok := dbCapture.Detail[k]; ok {
			detail["database_capture_"+k] = v
		}
	}
	detail["column"] = label
	return combineWaitRows(phases, detail)
}
