// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import "soundpost/internal/model"

// eraseIssueBooks is the single seam where the issues control state joins the
// deletion hook (eraseControlPayloads). IssueBooks is being added by the 06.02
// issues control handler; until its CollectRetiredIssues exists this is a
// deliberate no-op that drops nothing. When that handler lands, its erase
// function (a pure function of the state, the predicate and the transition
// time, returning how many payloads it dropped, like eraseIncidents) is called
// here and nowhere else:
//
//	return collectRetiredIssues(st, p, at)
func eraseIssueBooks(st *State, p model.DeletePredicate, at model.UnixNano) (dropped int, err error) {
	return 0, nil
}
