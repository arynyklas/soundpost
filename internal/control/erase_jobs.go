// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"encoding/json"
	"sort"

	"github.com/arynyklas/soundpost/internal/model"
)

// eraseJobBooks is the deletion hook's half for the job books (plan 06 task 03),
// a pure function of the state, the predicate and the transition time, like
// eraseIncidents. A retirement covers every job of its projects. A historical
// range covers the jobs whose state names an evidence time at or after its Start
// and every job whose state names none or cannot be read: a state that cannot be
// attributed to a time is dropped whole. (A definition that takes effect in the
// future is such a time, so it errs toward erasing.) An entity deletion names
// replay and profile roots, which a job only links by ID: it covers none.
//
// What stays of a covered job is its identity, version, digest and command
// records, and a tombstone state carrying only the closed header and the erasing
// operation (the jobs adapter reads it as an empty state at that version, so
// later evidence builds on it, and a redelivered command that committed before
// the erasure is still a replay: erased history is never resurrected). It returns
// how many states it dropped; a tombstone is never covered again.
//
// The deletion hook calls eraseJobBooksBy once, from eraseBooks, next to the
// others, with the rule of the pass (stateErased at begin, completion and
// import, stateErasedLate in the late re-erasure of an effect):
//
//	func() (int, error) { return eraseJobBooksBy(st, p, at, rule) },
func eraseJobBooks(st *State, p model.DeletePredicate, at model.UnixNano) (dropped int, err error) {
	dropped, _, err = eraseJobBooksBy(st, p, at, stateErased)
	return dropped, err
}

// eraseJobBooksBy is eraseJobBooks with the rule that covers an opaque state;
// over counts the covered states that had no recorded window (CD-9).
func eraseJobBooksBy(st *State, p model.DeletePredicate, at model.UnixNano, rule stateRule) (dropped, over int, err error) {
	keys := make([]string, 0, len(st.JobBooks))
	for key := range st.JobBooks {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		rec, _, err := loadJobRecord(st, key)
		if err != nil {
			return 0, 0, err
		}
		if !rule(p, rec.Org, rec.Project, rec.State) {
			continue
		}
		if overErasure(p, rec.State) {
			over++
		}
		rec.State = tombstoneState("job_id", rec.Job, rec.Org, rec.Project, rec.Version, p.Operation)
		raw, err := json.Marshal(rec)
		if err != nil {
			return 0, 0, model.Fail(model.Corrupt)
		}
		st.JobBooks[key] = raw
		dropped++
	}
	return dropped, over, nil
}

// DropRetiredJobBooks tombstones every job of one retired project, in the way
// eraseJobBooks does for a retirement: the same deterministic, idempotent
// function, scoped to the named organization and project, so a retire-time hook
// can call it inside the retiring transaction. operation is the retiring
// operation's ID, recorded in each tombstone; it returns how many states it
// dropped.
func DropRetiredJobBooks(st *State, org, project, operation model.ID) (dropped int, err error) {
	return eraseJobBooks(st, model.DeletePredicate{Operation: operation, Org: org, Mode: model.DeleteRetireProject, Projects: []model.ID{project}}, 0)
}
