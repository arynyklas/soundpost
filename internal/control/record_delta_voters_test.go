// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"bytes"
	"sync/atomic"
	"testing"
)

// D108: a group with a member at protocol 9 keeps writing job records whole (the compact gate reads false: that member would stop
// applying a rec op); once every member declared protocol 10 the same group, on the same journal, writes deltas of the records it
// already holds. Every voter holds the same books and the same record bytes after each phase.
func TestARecordDeltaGroupWithAProtocolNineMemberKeepsWholeRecordsUntilItIsUpgraded(t *testing.T) {
	v, _ := admissionVoters(t, 1)
	var gate atomic.Bool // false: a member of the group declared only protocol 9
	for _, s := range v.stores {
		s.SetCompactAdmissionGate(func() bool { return gate.Load() })
	}
	f := newJobFxOn(t, v.fx[1].fenceFx)
	job := f.job(1)
	version, tag := uint64(0), 0
	run := func(n int) {
		for range n {
			tag++
			f.must(byte(tag), f.upd(job, version, byte(tag)))
			version++
		}
	}
	key := f.org.String() + ":" + f.project.String() + ":" + job.String()
	identical := func(phase string) {
		t.Helper()
		v.converge()
		want, record := v.fx[1].canonicalState(), v.stores[1].LedgerRecordForTest("job_books", key)
		if len(record) < 3000 {
			t.Fatalf("%s: the job record is %d bytes: too small for the delta to be worth it", phase, len(record))
		}
		for _, id := range []uint64{2, 3} {
			if got := v.fx[id].canonicalState(); got != want {
				t.Fatalf("%s: voter %d holds other books than the leader's", phase, id)
			}
			if got := v.stores[id].LedgerRecordForTest("job_books", key); !bytes.Equal(got, record) {
				t.Fatalf("%s: voter %d holds other bytes of the job record than the leader's", phase, id)
			}
		}
	}
	run(30)
	identical("nine")
	if n := v.stores[1].CompactRecordOps(); n != 0 {
		t.Fatalf("%d rec ops were proposed while a member was at protocol 9", n)
	}
	gate.Store(true) // the member was replaced by a build at protocol 10 and declared it
	run(30)
	identical("ten")
	if n := v.stores[1].CompactRecordOps(); n < 20 {
		t.Fatalf("after the upgrade the group proposed %d rec ops for 30 updates of a record of %d bytes", n, len(v.stores[1].LedgerRecordForTest("job_books", key)))
	}
	if snap, ok := f.book(job); !ok || uint64(snap.Version) != version {
		t.Fatalf("the job is at version %d (found %v), want %d", snap.Version, ok, version)
	}
}
