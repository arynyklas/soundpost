// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query"
)

// The cluster backup leg of install-distributed names rows exactly: one row is one acknowledged
// batch of the distLedger, identified by its observation time (nanoseconds, unique per batch) and
// its value (the batch's sequence number). A count would pass on a wrong row set; this does not.

// distRowsExpression selects every sample of the ledger's series over a window that holds the
// whole smoke, evaluated one minute after now.
const distRowsExpression = "distributed_smoke_writes[3h]"

// distRow is one row the ledger acknowledged, or one sample a voter serves.
type distRow struct {
	At    int64
	Value float64
}

func (r distRow) String() string { return fmt.Sprintf("%d=%g", r.At, r.Value) }

func sortRows(rows []distRow) {
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].At != rows[j].At {
			return rows[i].At < rows[j].At
		}
		return rows[i].Value < rows[j].Value
	})
}

// expectedRows is the exact row set of the acknowledged batches, sorted.
func expectedRows(accepted []installReceipt) []distRow {
	rows := make([]distRow, 0, len(accepted))
	for _, a := range accepted {
		record := a.batch.Records[0]
		rows = append(rows, distRow{At: int64(record.ObservedAt), Value: math.Float64frombits(uint64(*record.Payload.Metric.Value))})
	}
	sortRows(rows)
	return rows
}

// rowsOfResult reads the rows out of a COMPLETE answer to distRowsExpression: one matrix series (or
// none) whose samples are all floats.
func rowsOfResult(result query.Result) ([]distRow, error) {
	if len(result.Projects) != 1 {
		return nil, &smokeFailure{Stage: "cluster_backup_rows", Code: "projects_not_one"}
	}
	got := result.Projects[0]
	if got.Failure != nil || got.Completeness != query.CompletenessComplete || got.Value == nil {
		return nil, &smokeFailure{Stage: "cluster_backup_rows", Code: "answer_incomplete"}
	}
	if got.Value.Type != query.ValueMatrix {
		return nil, &smokeFailure{Stage: "cluster_backup_rows", Code: "answer_not_a_matrix"}
	}
	if len(got.Value.Matrix) > 1 {
		return nil, &smokeFailure{Stage: "cluster_backup_rows", Code: "more_than_one_series"}
	}
	rows := []distRow{}
	for _, series := range got.Value.Matrix {
		for _, sample := range series.Samples {
			if sample.Float == nil {
				return nil, &smokeFailure{Stage: "cluster_backup_rows", Code: "sample_not_a_float"}
			}
			rows = append(rows, distRow{At: int64(sample.Time), Value: math.Float64frombits(uint64(*sample.Float))})
		}
	}
	sortRows(rows)
	return rows, nil
}

// diffRows names the rows of want a voter does not serve and the rows it serves beyond want.
func diffRows(want, got []distRow) (missing, unexpected []distRow) {
	has := map[distRow]bool{}
	for _, r := range got {
		has[r] = true
	}
	wanted := map[distRow]bool{}
	for _, r := range want {
		wanted[r] = true
		if !has[r] {
			missing = append(missing, r)
		}
	}
	for _, r := range got {
		if !wanted[r] {
			unexpected = append(unexpected, r)
		}
	}
	sortRows(missing)
	sortRows(unexpected)
	return missing, unexpected
}

// requireRows is nil exactly when got is want, row for row (and no row twice).
func requireRows(stage string, want, got []distRow) error {
	missing, unexpected := diffRows(want, got)
	switch {
	case len(missing) != 0:
		return &smokeFailure{Stage: stage, Code: "row_missing", Actual: len(got), Expected: len(want)}
	case len(unexpected) != 0:
		return &smokeFailure{Stage: stage, Code: "row_not_acknowledged_before_the_backup", Actual: len(got), Expected: len(want)}
	case len(got) != len(want):
		return &smokeFailure{Stage: stage, Code: "row_served_twice", Actual: len(got), Expected: len(want)}
	}
	return nil
}

// rowsContain reports whether any row of probe is among got.
func rowsContain(got, probe []distRow) bool {
	missing, _ := diffRows(probe, got)
	return len(missing) != len(probe)
}

// rowsExcept is the rows of all that are not in drop.
func rowsExcept(all, drop []distRow) []distRow {
	out := []distRow{}
	for _, r := range all {
		if !rowsContain(drop, []distRow{r}) {
			out = append(out, r)
		}
	}
	return out
}

// backupCreated is the JSON `soundpost backup create` prints.
type backupCreated struct {
	BackupID   string `json:"backup_id"`
	Voters     uint64 `json:"voters"`
	Objects    int    `json:"objects"`
	DurationMS int64  `json:"duration_ms"`
}

func parseBackupCreated(out []byte) (backupCreated, model.ID, error) {
	var created backupCreated
	if err := json.Unmarshal(bytes.TrimSpace(out), &created); err != nil {
		return created, model.ID{}, &smokeFailure{Stage: "cluster_backup_create", Code: "output_not_json"}
	}
	id, err := model.ParseID(created.BackupID)
	if err != nil {
		return created, id, &smokeFailure{Stage: "cluster_backup_create", Code: "backup_id_invalid"}
	}
	return created, id, nil
}

// backupRestored is the part of the JSON `soundpost backup restore` prints that the leg reads.
type backupRestored struct {
	BackupID     string `json:"backup_id"`
	SourceVoters uint64 `json:"source_voters"`
	Objects      int    `json:"objects"`
}

func parseBackupRestored(out []byte) (backupRestored, error) {
	var restored backupRestored
	if err := json.Unmarshal(bytes.TrimSpace(out), &restored); err != nil {
		return restored, &smokeFailure{Stage: "cluster_backup_restore", Code: "output_not_json"}
	}
	return restored, nil
}

// parseInstallation reads the installation ID out of `soundpost backup authority-init`'s one line
// "authority <id> bound to installation <id>".
func parseInstallation(out []byte) (model.ID, error) {
	const marker = " bound to installation "
	line := strings.TrimSpace(string(out))
	at := strings.LastIndex(line, marker)
	if at < 0 || strings.ContainsAny(line, "\r\n") {
		return model.ID{}, &smokeFailure{Stage: "cluster_backup_setup", Code: "authority_init_output"}
	}
	id, err := model.ParseID(strings.TrimSpace(line[at+len(marker):]))
	if err != nil {
		return id, &smokeFailure{Stage: "cluster_backup_setup", Code: "installation_id_invalid"}
	}
	return id, nil
}

// disjointIdentities requires that no node of the restored cluster carries the identity of a node of
// the lost one (the product refuses it too; this is the smoke's own statement of the fixture).
func disjointIdentities(lost, restored []distNode) error {
	seen := map[string]bool{}
	for _, n := range lost {
		seen[n.identity] = true
	}
	for _, n := range restored {
		if seen[n.identity] || n.identity == "" {
			return &smokeFailure{Stage: "cluster_backup_identities", Code: "restored_identity_not_fresh_" + strconv.FormatUint(n.id, 10)}
		}
	}
	return nil
}

// reconcileBody is the request body of POST /api/v1/restore/reconcile for one item: the fields the
// item names (a zero ID is not encodable, and the route reads an absent field as zero).
func reconcileBody(item auth.Reconciliation) map[string]string {
	body := map[string]string{"Kind": string(item.Kind), "Reason": item.Reason}
	for name, id := range map[string]model.ID{"Org": item.Org, "User": item.User, "Project": item.Project, "Source": item.Source, "ID": item.ID} {
		if id != (model.ID{}) {
			body[name] = id.String()
		}
	}
	if item.Key != "" {
		body["Key"] = item.Key
	}
	return body
}
