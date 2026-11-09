// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth_test

import (
	"encoding/json"
	"testing"
	"time"

	"soundpost/internal/auth"
	"soundpost/internal/model"
)

// The stash is the bookkeeping of one restore: discarding it removes exactly that
// record, reports whether there was one, and leaves a state the NEXT generation
// can quarantine afresh (over what is active in it, not over what the previous
// generation had stashed).
func TestDiscardRestoreStashRemovesOnlyTheStash(t *testing.T) {
	f := newRestoreFixture(t)
	token, _, service := f.restore()
	recovery, err := service.Bootstrap(f.ctx, token, "recovery@example.test", "recovery long password 2026")
	if err != nil {
		t.Fatal(err)
	}
	st := controlState(t, f)
	if auth.RestorePending(st) == 0 {
		t.Fatal("fixture: the restore left nothing stashed")
	}
	st.OIDC["unrelated"] = json.RawMessage(`{}`)
	if !auth.DiscardRestoreStash(&st) {
		t.Fatal("a state that carries a stash reported none")
	}
	if auth.RestorePending(st) != 0 {
		t.Fatal("the stash survived its discard")
	}
	if _, kept := st.OIDC["unrelated"]; !kept {
		t.Fatal("discarding the stash removed another record")
	}
	if auth.DiscardRestoreStash(&st) {
		t.Fatal("discarding twice reported a stash the second time")
	}
	// The next generation quarantines what is active now: only the recovery admin.
	summary, err := auth.QuarantineRestoredState(&st, auth.RestoreInput{Generation: model.NewID(), Backup: model.NewID(), BootstrapHash: "hash", SealedBearerKey: "sealed", At: time.Now()})
	if err != nil {
		t.Fatalf("a discarded state cannot be quarantined again: %v", err)
	}
	if summary.Users != 1 || auth.RestorePending(st) != 1 || !st.Users[recovery.User.String()].Disabled {
		t.Fatalf("the new generation did not quarantine exactly the active accounts: %+v pending=%d", summary, auth.RestorePending(st))
	}
}
