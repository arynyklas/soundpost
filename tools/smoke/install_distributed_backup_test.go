// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"errors"
	"math"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query"
)

func floatSample(at int64, value float64) query.Sample {
	bits := model.FloatBits(math.Float64bits(value))
	return query.Sample{Time: model.UnixNano(at), Float: &bits}
}

func matrixResult(series ...query.Series) query.Result {
	return query.Result{Projects: []query.ProjectResult{{Completeness: query.CompletenessComplete, Value: &query.Value{Type: query.ValueMatrix, Matrix: series}}}}
}

func failureCode(t *testing.T, err error) string {
	t.Helper()
	var failure *smokeFailure
	if !errors.As(err, &failure) {
		t.Fatalf("error %v is not a smokeFailure", err)
	}
	return failure.Code
}

func TestExpectedRowsAreTheAcknowledgedBatchesByTimeAndValue(t *testing.T) {
	fx := &installFixture{org: model.NewID(), project: model.NewID(), source: model.NewID(), service: model.NewID(), environment: model.NewID(), build: model.NewID()}
	ledger := &distLedger{}
	var batches []model.Batch
	for range 3 {
		batch := ledger.next(fx, "w")
		batches = append(batches, batch)
		ledger.accept(batch)
	}
	rows := expectedRows(ledger.accepted)
	if len(rows) != 3 {
		t.Fatalf("rows %v", rows)
	}
	for i, row := range rows {
		if row.Value != float64(i+1) || row.At != int64(batches[i].Records[0].ObservedAt) {
			t.Fatalf("row %d = %v, want value %d at %d", i, row, i+1, batches[i].Records[0].ObservedAt)
		}
	}
	// The order of acknowledgement does not matter.
	reversed := []installReceipt{ledger.accepted[2], ledger.accepted[0], ledger.accepted[1]}
	if err := requireRows("t", rows, expectedRows(reversed)); err != nil {
		t.Fatalf("a permutation of the same rows differs: %v", err)
	}
}

func TestRowsOfResultReadsOneMatrixSeriesAndNothingElse(t *testing.T) {
	good := matrixResult(query.Series{Samples: []query.Sample{floatSample(30, 3), floatSample(10, 1), floatSample(20, 2)}})
	rows, err := rowsOfResult(good)
	if err != nil {
		t.Fatal(err)
	}
	if want := []distRow{{10, 1}, {20, 2}, {30, 3}}; len(rows) != 3 || rows[0] != want[0] || rows[1] != want[1] || rows[2] != want[2] {
		t.Fatalf("rows %v, want %v", rows, want)
	}
	if rows, err = rowsOfResult(matrixResult()); err != nil || len(rows) != 0 {
		t.Fatalf("an empty matrix is no rows: %v %v", rows, err)
	}
	vector := query.Result{Projects: []query.ProjectResult{{Completeness: query.CompletenessComplete, Value: &query.Value{Type: query.ValueVector}}}}
	partial := matrixResult()
	partial.Projects[0].Completeness = "partial"
	failed := matrixResult()
	failed.Projects[0].Failure = &query.Failure{Code: "unavailable"}
	noValue := matrixResult()
	noValue.Projects[0].Value = nil
	for name, tc := range map[string]struct {
		result query.Result
		code   string
	}{
		"two series":        {matrixResult(query.Series{}, query.Series{}), "more_than_one_series"},
		"a vector":          {vector, "answer_not_a_matrix"},
		"a partial":         {partial, "answer_incomplete"},
		"a failure":         {failed, "answer_incomplete"},
		"no value":          {noValue, "answer_incomplete"},
		"no project":        {query.Result{}, "projects_not_one"},
		"a sample no float": {matrixResult(query.Series{Samples: []query.Sample{{Time: 1}}}), "sample_not_a_float"},
	} {
		if _, err := rowsOfResult(tc.result); err == nil || failureCode(t, err) != tc.code {
			t.Errorf("%s: error %v, want code %s", name, err, tc.code)
		}
	}
}

func TestRequireRowsNamesTheExactFault(t *testing.T) {
	want := []distRow{{1, 1}, {2, 2}, {3, 3}}
	if err := requireRows("t", want, []distRow{{3, 3}, {1, 1}, {2, 2}}); err != nil {
		t.Fatalf("the same rows in another order: %v", err)
	}
	// Same count, one row replaced: a count would pass this.
	for name, tc := range map[string]struct {
		got  []distRow
		code string
	}{
		"one row replaced":         {[]distRow{{1, 1}, {2, 2}, {4, 4}}, "row_missing"},
		"same time, another value": {[]distRow{{1, 1}, {2, 2}, {3, 30}}, "row_missing"},
		"one row missing":          {[]distRow{{1, 1}, {2, 2}}, "row_missing"},
		"a row from after the cut": {[]distRow{{1, 1}, {2, 2}, {3, 3}, {4, 4}}, "row_not_acknowledged_before_the_backup"},
		"a row served twice":       {[]distRow{{1, 1}, {2, 2}, {3, 3}, {3, 3}}, "row_served_twice"},
		"nothing":                  {nil, "row_missing"},
	} {
		if err := requireRows("t", want, tc.got); err == nil || failureCode(t, err) != tc.code {
			t.Errorf("%s: error %v, want code %s", name, err, tc.code)
		}
	}
	if err := requireRows("t", nil, nil); err != nil {
		t.Fatalf("no rows is the exact answer to no rows: %v", err)
	}
}

func TestRowsContainAndExcept(t *testing.T) {
	all := []distRow{{1, 1}, {2, 2}, {3, 3}}
	if !rowsContain(all, []distRow{{9, 9}, {2, 2}}) || rowsContain(all, []distRow{{9, 9}}) || rowsContain(all, nil) {
		t.Fatal("rowsContain is any-of")
	}
	rest := rowsExcept(all, []distRow{{2, 2}})
	if len(rest) != 2 || rest[0] != all[0] || rest[1] != all[2] {
		t.Fatalf("rowsExcept %v", rest)
	}
}

func TestParseBackupCreatedAndRestored(t *testing.T) {
	id := model.NewID()
	created, parsed, err := parseBackupCreated([]byte(`{"backup_id":"` + id.String() + `","voters":3,"objects":67,"duration_ms":12}` + "\n"))
	if err != nil || parsed != id || created.Voters != 3 || created.Objects != 67 {
		t.Fatalf("created %+v %v %v", created, parsed, err)
	}
	for _, bad := range []string{``, `not json`, `{"backup_id":"nope","voters":3}`, `{"voters":3}`} {
		if _, _, err := parseBackupCreated([]byte(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	restored, err := parseBackupRestored([]byte(`{"backup_id":"` + id.String() + `","source_voters":3,"objects":5}`))
	if err != nil || restored.SourceVoters != 3 || restored.BackupID != id.String() {
		t.Fatalf("restored %+v %v", restored, err)
	}
	if _, err = parseBackupRestored([]byte(`{`)); err == nil {
		t.Fatal("accepted truncated JSON")
	}
}

func TestParseInstallationReadsTheAuthorityInitLine(t *testing.T) {
	authority, installation := model.NewID(), model.NewID()
	got, err := parseInstallation([]byte("authority " + authority.String() + " bound to installation " + installation.String() + "\n"))
	if err != nil || got != installation {
		t.Fatalf("got %v %v, want %v", got, err, installation)
	}
	for _, bad := range []string{"", "authority x", "bound to installation nope", "a\nbound to installation " + installation.String()} {
		if _, err := parseInstallation([]byte(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestRestoredIdentitiesAreDisjointFromTheLostClusters(t *testing.T) {
	if err := disjointIdentities(distNodes, restoredNodes); err != nil {
		t.Fatalf("the fixture's restored identities collide with the old ones: %v", err)
	}
	reused := []distNode{restoredNodes[0], restoredNodes[1], {3, "f", distNodes[2].identity}}
	if err := disjointIdentities(distNodes, reused); err == nil || failureCode(t, err) != "restored_identity_not_fresh_3" {
		t.Fatalf("a reused identity: %v", err)
	}
	if err := disjointIdentities(distNodes, []distNode{{1, "d", ""}}); err == nil {
		t.Fatal("an empty identity")
	}
}

func TestReconcileBodyNamesOnlyTheItemsFields(t *testing.T) {
	org, user, project, source := model.NewID(), model.NewID(), model.NewID(), model.NewID()
	body := reconcileBody(auth.Reconciliation{Kind: auth.ReconcileGrant, Org: org, User: user, Project: project, Reason: "why"})
	want := map[string]string{"Kind": "grant", "Reason": "why", "Org": org.String(), "User": user.String(), "Project": project.String()}
	if len(body) != len(want) {
		t.Fatalf("body %v, want %v", body, want)
	}
	for k, v := range want {
		if body[k] != v {
			t.Fatalf("body[%s] = %q, want %q", k, body[k], v)
		}
	}
	source2 := reconcileBody(auth.Reconciliation{Kind: auth.ReconcileSource, Source: source, Reason: "r"})
	if len(source2) != 3 || source2["Source"] != source.String() {
		t.Fatalf("source body %v", source2)
	}
	if _, ok := reconcileBody(auth.Reconciliation{Kind: auth.ReconcileIntegration, Key: "sso:x", Reason: "r"})["Key"]; !ok {
		t.Fatal("a key is not carried")
	}
}
