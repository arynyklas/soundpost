// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"encoding/json"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// An issue book that cannot be read cannot be attributed from its content, but
// its key names the organization and project it belongs to: a deletion drops it
// only when its predicate covers that project (an organization retirement: that
// organization), and leaves every other project's unreadable book in place for
// its own reads to fail closed on (loadIssueBook answers Corrupt). A deletion of
// project A must never cost project B its checkpoints, command records, gaps,
// effect intents or compare-and-set revision. (01.08 review CD-4.)
func TestUnreadableIssueBookIsDroppedOnlyWhenItsProjectIsCovered(t *testing.T) {
	org, otherOrg := model.ID{0x10}, model.ID{0x20}
	a, b := model.ID{0x11}, model.ID{0x12}
	op := model.ID{0xdd, 1}
	unreadable := json.RawMessage(`{"revision":`)
	build := func() *State {
		good, _ := json.Marshal(IssueBook{Org: org, Project: a, Revision: 3})
		return &State{IssueBooks: map[string]json.RawMessage{
			issueBookKey(org, a):       good,
			issueBookKey(org, b):       unreadable, // same organization, another project
			issueBookKey(otherOrg, a):  unreadable, // another organization
			"not-an-org:not-a-project": unreadable, // a key that names no project
		}}
	}
	for _, c := range []struct {
		name         string
		predicate    model.DeletePredicate
		dropped      []string // keys that must be gone
		droppedCount int
	}{
		{"retire project", model.DeletePredicate{Operation: op, Org: org, Mode: model.DeleteRetireProject, Projects: []model.ID{b}},
			[]string{issueBookKey(org, b)}, 1},
		{"historical range", model.DeletePredicate{Operation: op, Org: org, Mode: model.DeleteHistoricalRange, Projects: []model.ID{b}, Signals: []model.Kind{model.ErrorKind}, Start: 40, End: 100},
			[]string{issueBookKey(org, b)}, 1},
		{"entity", model.DeletePredicate{Operation: op, Org: org, Mode: model.DeleteEntity, Projects: []model.ID{b}, Entities: []model.ID{{0xe7}}},
			[]string{issueBookKey(org, b)}, 1},
		{"retire org", model.DeletePredicate{Operation: op, Org: org, Mode: model.DeleteRetireOrg},
			[]string{issueBookKey(org, a), issueBookKey(org, b)}, 2},
	} {
		t.Run(c.name, func(t *testing.T) {
			st := build()
			n, err := eraseIssueBooks(st, c.predicate, 7)
			if err != nil {
				t.Fatal(err)
			}
			gone := map[string]bool{}
			for _, k := range c.dropped {
				gone[k] = true
			}
			for key := range build().IssueBooks {
				_, present := st.IssueBooks[key]
				if present == gone[key] {
					t.Errorf("book %q present=%v, want present=%v", key, present, !gone[key])
				}
			}
			if n < len(c.dropped) || n != c.droppedCount {
				t.Errorf("dropped=%d, want %d", n, c.droppedCount)
			}
		})
	}
}
