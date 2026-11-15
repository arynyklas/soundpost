// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"sort"
	"strings"

	"github.com/arynyklas/soundpost/internal/model"
)

// eraseSavedViews is the deletion hook's half for the saved views (C11), a pure
// function of the state and the predicate, like eraseCutoverBooks. A saved view
// is project-owned query text, which can hold sensitive literals the caller
// typed, so a retirement of its project (or of its organization) drops every
// view of the covered projects whole: the key, the name, the expression and the
// project list go, and nothing of them stays in the committed state, the
// snapshot or, after the scrub the erasing audit owes, control.db. Another
// project's views, and every view of a historical-range or entity deletion, are
// not covered: a range erases telemetry, which no view holds.
//
// The owner is read from the key ("org:project:view"), not from the record, so
// a record that cannot be decoded is still dropped with its project. A key that
// does not name an organization and a project cannot be attributed and is left
// alone. The function returns how many views it dropped (an erasing audit and a
// scrub are owed only when it dropped something) and is idempotent.
//
// The deletion hook calls it once, from eraseBooks, next to the others:
//
//	func() (int, error) { return eraseSavedViews(st, p) },
func eraseSavedViews(st *State, p model.DeletePredicate) (dropped int, err error) {
	keys := make([]string, 0, len(st.SavedViewBooks))
	for key := range st.SavedViewBooks {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		org, project, ok := savedViewKeyOwner(key)
		if !ok || !p.RetiresProject(org, project) {
			continue
		}
		delete(st.SavedViewBooks, key)
		dropped++
	}
	return dropped, nil
}

// savedViewKeyOwner names the organization and the project a SavedViewBooks key
// belongs to.
func savedViewKeyOwner(key string) (org, project model.ID, ok bool) {
	parts := strings.Split(key, ":")
	if len(parts) != 3 {
		return model.ID{}, model.ID{}, false
	}
	org, e1 := model.ParseID(parts[0])
	project, e2 := model.ParseID(parts[1])
	return org, project, e1 == nil && e2 == nil
}
