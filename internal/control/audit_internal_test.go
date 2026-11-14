// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"github.com/arynyklas/soundpost/internal/model"
	"testing"
)

// audit runs inside a control apply, where a panic trips the engine: a caller that passes no target
// still gets its audit recorded, with no request correlation, instead of a crash.
func TestAuditWithoutTargetsIsRecordedNotAPanic(t *testing.T) {
	st := &State{Orgs: map[string]model.ControlOrg{}}
	org, principal := model.NewID(), model.NewID()
	audit(st, principal, org, "test.action", "no targets", 5, nil)
	if len(st.Audits) != 1 || st.Audits[0].Action != "test.action" || st.Audits[0].Principal != principal || st.Audits[0].RequestID != (model.ID{}) {
		t.Fatalf("audits %+v", st.Audits)
	}
	target := model.NewID()
	audit(st, principal, org, "test.action", "one target", 6, []model.ID{target})
	if st.Audits[1].RequestID != target {
		t.Fatal("the first target is the request correlation")
	}
}
