// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import "github.com/arynyklas/soundpost/internal/model"

// IssueCheckpointOf is the highest journal index of the data group whose issue
// effects the project's issue book has committed (zero when it has none).
// Lifecycle evidence of an error occurrence at or below it is processed.
func IssueCheckpointOf(st *State, org, project, group model.ID) (uint64, error) {
	checkpoints, err := issueCheckpoints(st, org, project)
	if err != nil {
		return 0, err
	}
	return checkpoints[group], nil
}

// JobCommandApplied reports whether the job book holds the applied command. A
// job's command log is bounded and a record the reducer rejected leaves no
// command, so false only means "not provably processed".
func JobCommandApplied(st *State, org, project, job, command model.ID) (bool, error) {
	rec, ok, err := loadJobRecord(st, jobKey(org, project, job))
	if err != nil || !ok {
		return false, err
	}
	for i := len(rec.Commands) - 1; i >= 0; i-- {
		if rec.Commands[i].ID == command {
			return true, nil
		}
	}
	return false, nil
}
