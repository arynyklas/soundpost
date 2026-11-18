// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"reflect"
	"testing"

	"github.com/arynyklas/soundpost/internal/control"
)

// authorityVisible is what a deletion Begin that judged a stale view could have decided on: the
// organization's policy epoch, members and projects, the holds, the deletion generations, the
// retirement markers and AuthorityRevision itself.
func (f *fenceFx) authorityVisible() map[string]any {
	f.t.Helper()
	out := map[string]any{}
	if err := f.store.View(f.ctx, func(st control.State) error {
		o := st.Orgs[f.org.String()]
		out["epoch"] = o.Epoch
		out["members"] = o.Members
		out["projects"] = o.Projects
		out["holds"] = st.Holds
		out["generations"] = st.DeleteGenerations
		out["retired_projects"] = st.RetiredProjects
		out["retired_orgs"] = st.RetiredOrgs
		out["authority_revision"] = st.AuthorityRevision
		return nil
	}); err != nil {
		f.t.Fatal(err)
	}
	return out
}

// A non-authority writer must leave authority state alone, not merely leave AuthorityRevision alone:
// the classification table is the only thing that lets a Begin commit on a view older than these
// writes (independent review of 10.05, F-10.05-3: the mutant "FinalizeAdmission also advances the
// organization's policy epoch" survived all 269 single-store control tests). The fixture's intake
// reaches ReserveAdmission and its quota books (the mutant "ReserveAdmission advances every
// organization's epoch" is killed here: epoch 8 -> 13); FinalizeAdmission needs an owner-group proof
// the single-store fixture does not hold, so that mutant still survives it (open, recorded in the
// wave 24 report).
func TestIntakeWritersLeaveEveryAuthorityVisibleFieldAlone(t *testing.T) {
	f := newFenceFx(t)
	f.mustIntake() // the first admission creates the quota and series books
	before := f.authorityVisible()
	revision, _ := f.revisions()
	for range 5 {
		f.mustIntake()
	}
	if after, _ := f.revisions(); after <= revision {
		t.Fatalf("setup: intake spent no control revision (%d -> %d), so it exercised no writer", revision, after)
	}
	got := f.authorityVisible()
	for k := range before {
		if !reflect.DeepEqual(before[k], got[k]) {
			t.Errorf("intake changed authority-visible state %q: %v -> %v", k, before[k], got[k])
		}
	}
}
