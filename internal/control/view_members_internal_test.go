// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"context"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

var credentialNames = []string{"ServerTokens", "Sessions", "Users"}

func (f *installFx) viewCredentials() (sessions, users int) {
	f.t.Helper()
	if err := f.s.ViewMembers(context.Background(), credentialNames, func(st State) error {
		sessions, users = len(st.Sessions), len(st.Users)
		return nil
	}); err != nil {
		f.t.Fatal(err)
	}
	return
}

// The authentication of a request reads three members. ViewCore decodes every member a commit changed, which
// at the gate is the rule books and the outbox all the time; ViewMembers decodes the three or nothing.
func TestViewMembersDecodesNothingForACommitOfOtherMembers(t *testing.T) {
	f := newCoreFx(t)
	f.viewCredentials() // the first read decodes them
	for i, change := range []func(*State){
		func(st *State) { st.BootstrapHash = "changed" },
		func(st *State) { st.BootstrapHash = "changed again" },
	} {
		f.rewrite(change)
		_, before := f.counters()
		for range 5 {
			f.viewCredentials()
		}
		if _, after := f.counters(); after != before {
			t.Fatalf("commit %d of another member: 5 credential reads decoded %d members, want none", i, after-before)
		}
		// What ViewCore does after the same commit: it decodes the member the commit changed.
		_, before = f.counters()
		if err := f.s.ViewCore(context.Background(), func(State) error { return nil }); err != nil {
			t.Fatal(err)
		}
		if _, after := f.counters(); after-before < 1 {
			t.Fatalf("commit %d: ViewCore decoded nothing; the comparison above proves nothing", i)
		}
	}
}

// A commit of the members it reads, a rewrite of the blob (an erasure, a snapshot install: markCoreChanged) and
// a dropped decode each make the next read decode again and see what is committed, never what was cached.
func TestViewMembersNeverServesAMemberACommitChanged(t *testing.T) {
	f := newCoreFx(t)
	sessions, users := f.viewCredentials()
	f.rewrite(func(st *State) {
		st.Sessions["s1"] = model.ControlSession{User: model.ID{1}, Expires: 9_000_000_000}
		st.Users[model.ID{1}.String()] = model.ControlUser{ID: model.ID{1}}
	})
	gotS, gotU := f.viewCredentials()
	if gotS != sessions+1 || gotU != users+1 {
		t.Fatalf("after the commit: %d sessions %d users, want %d and %d", gotS, gotU, sessions+1, users+1)
	}
	f.rewrite(func(st *State) { delete(st.Sessions, "s1") }) // a revocation
	if gotS, _ = f.viewCredentials(); gotS != sessions {
		t.Fatalf("a revoked session is still served: %d sessions, want %d", gotS, sessions)
	}
	// An erasure or an install rewrites the blob and marks every member: the held decode is dropped.
	f.viewCredentials()
	f.mutantWrite(func(ctrl *bolt.Bucket) error { markCoreChanged(ctrl.Tx()); return nil })
	_, before := f.counters()
	f.viewCredentials()
	if _, after := f.counters(); after-before != uint64(len(credentialNames)) {
		t.Fatalf("after a rewrite of the core records the read decoded %d members, want %d", after-before, len(credentialNames))
	}
	f.s.DropSharedDecodeForTest()
	_, before = f.counters()
	f.viewCredentials()
	if _, after := f.counters(); after-before != uint64(len(credentialNames)) {
		t.Fatalf("after the decode was dropped the read decoded %d members, want %d", after-before, len(credentialNames))
	}
}
