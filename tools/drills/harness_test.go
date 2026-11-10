// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func testAllowlist() Allowlist {
	return Allowlist{
		DataRoots: []string{"/tmp/soundpost-drills"},
		Hosts:     []string{"127.0.0.1", "localhost"},
		Forbidden: []string{"/var/lib/soundpost", "/var/lib", "/data", "/home", "/root", "/etc"},
	}
}

func TestDrillRefusesUnapprovedTarget(t *testing.T) {
	a := testAllowlist()
	good := Target{Name: "isolated", DataDirs: []string{"/tmp/soundpost-drills/node-kill-1/node-a"}, Addresses: []string{"127.0.0.1:18443", "localhost:18444"}}
	if err := CheckTarget(a, good); err != nil {
		t.Fatalf("an allowlisted loopback target was refused: %v", err)
	}
	cases := map[string]Target{
		"production name":        {Name: "production", DataDirs: good.DataDirs, Addresses: good.Addresses},
		"default name":           {Name: "default", DataDirs: good.DataDirs},
		"empty name":             {Name: "", DataDirs: good.DataDirs},
		"near miss name":         {Name: "isolated2", DataDirs: good.DataDirs},
		"upper-case name":        {Name: "Isolated", DataDirs: good.DataDirs},
		"production data dir":    {Name: "isolated", DataDirs: []string{"/var/lib/soundpost"}},
		"inside production dir":  {Name: "isolated", DataDirs: []string{"/var/lib/soundpost/node-a"}},
		"default data dir":       {Name: "isolated", DataDirs: []string{"/data"}},
		"home dir":               {Name: "isolated", DataDirs: []string{"/home/user/.soundpost"}},
		"outside every root":     {Name: "isolated", DataDirs: []string{"/tmp/other/node-a"}},
		"the root itself":        {Name: "isolated", DataDirs: []string{"/tmp/soundpost-drills"}},
		"prefix lookalike":       {Name: "isolated", DataDirs: []string{"/tmp/soundpost-drills-evil/node"}},
		"parent traversal":       {Name: "isolated", DataDirs: []string{"/tmp/soundpost-drills/../../var/lib/soundpost"}},
		"relative path":          {Name: "isolated", DataDirs: []string{"soundpost-drills/node-a"}},
		"one bad dir among good": {Name: "isolated", DataDirs: []string{good.DataDirs[0], "/var/lib/soundpost"}},
		"non-loopback address":   {Name: "isolated", DataDirs: good.DataDirs, Addresses: []string{"10.0.0.5:8443"}},
		"wildcard address":       {Name: "isolated", DataDirs: good.DataDirs, Addresses: []string{"0.0.0.0:8443"}},
		"ipv6 wildcard":          {Name: "isolated", DataDirs: good.DataDirs, Addresses: []string{"[::]:8443"}},
		"hostname":               {Name: "isolated", DataDirs: good.DataDirs, Addresses: []string{"soundpost.example.invalid:8443"}},
		"port missing":           {Name: "isolated", DataDirs: good.DataDirs, Addresses: []string{"127.0.0.1"}},
		"port zero":              {Name: "isolated", DataDirs: good.DataDirs, Addresses: []string{"127.0.0.1:0"}},
		"one bad address":        {Name: "isolated", DataDirs: good.DataDirs, Addresses: []string{"127.0.0.1:1", "192.168.1.1:1"}},
	}
	for name, tgt := range cases {
		err := CheckTarget(a, tgt)
		if err == nil {
			t.Errorf("%s: the drill accepted %+v", name, tgt)
		} else if !errors.Is(err, ErrRefused) {
			t.Errorf("%s: refusal is not ErrRefused: %v", name, err)
		}
	}
	// An allowlist that lists a non-loopback host still refuses it.
	b := a
	b.Hosts = []string{"10.0.0.5", "0.0.0.0"}
	for _, addr := range []string{"10.0.0.5:1", "0.0.0.0:1"} {
		if err := CheckTarget(b, Target{Name: "isolated", Addresses: []string{addr}}); err == nil {
			t.Errorf("a non-loopback host on the allowlist was accepted: %s", addr)
		}
	}
	// An empty allowlist refuses even the good target.
	if err := CheckTarget(Allowlist{}, good); err == nil {
		t.Error("an empty allowlist accepted a target")
	}
}

func TestDrillRefusesUnapprovedTargetThroughTheRunner(t *testing.T) {
	m := &Manifest{Version: 1, Allowlist: testAllowlist(), Scenarios: []ScenarioSpec{{Name: "x", NotRun: "reason"}}}
	dir := t.TempDir()
	if _, err := Execute(t.Context(), m, "x", "production", "/", "", dir); !errors.Is(err, ErrRefused) {
		t.Fatalf("a non-isolated target ran: %v", err)
	}
	// A not_run row must not bypass the target check or be written as a pass.
	rep, err := Execute(t.Context(), m, "x", "isolated", "/", "", dir)
	if err != nil || rep.Status != StatusNotRun {
		t.Fatalf("not_run row: %v %v", rep, err)
	}
	if code := run([]string{"--scenario", "x", "--target", "production", "--report", dir, "--scenarios", "/does/not/exist"}, &strings.Builder{}, &strings.Builder{}); code != 2 {
		t.Fatalf("exit %d for an unreadable manifest, want 2", code)
	}
}

func ackFor(i int) Ack {
	return Ack{ID: fmt.Sprintf("batch-%02d", i), Group: "g1", Index: uint64(100 + i), Digest: fmt.Sprintf("digest-%02d", i)}
}

func filledLedger(t *testing.T, n int) (*Ledger, map[string]string) {
	t.Helper()
	l, retained := &Ledger{}, map[string]string{}
	for i := 1; i <= n; i++ {
		a := ackFor(i)
		if err := l.Record(a); err != nil {
			t.Fatal(err)
		}
		retained[a.ID] = a.Digest
	}
	return l, retained
}

func TestReceiptReconciliationDetectsOneMissingACK(t *testing.T) {
	l, retained := filledLedger(t, 25)
	rec, err := Reconcile(l, retained)
	if err != nil || rec.ExactMatches != 25 || rec.Acked != 25 {
		t.Fatalf("the complete retained set did not reconcile: %+v %v", rec, err)
	}
	// Exactly ONE acknowledged batch is missing from the retained data.
	delete(retained, "batch-13")
	_, err = Reconcile(l, retained)
	var re *ReconcileError
	if !errors.As(err, &re) || len(re.Missing) != 1 || re.Missing[0] != "batch-13" {
		t.Fatalf("one missing ACK was not named: %v", err)
	}
	// Equal COUNTS must not substitute for equal content: replace the missing batch with an
	// un-acknowledged one so len(retained) == len(acked).
	retained["batch-unacked"] = "digest-x"
	if len(retained) != l.Len() {
		t.Fatal("test setup: counts differ")
	}
	if _, err = Reconcile(l, retained); !errors.As(err, &re) || len(re.Missing) != 1 {
		t.Fatalf("matching counts hid a lost acknowledged batch: %v", err)
	}
	// One batch retained with different content is also a failure.
	l2, r2 := filledLedger(t, 25)
	r2["batch-07"] = "digest-07-altered"
	if _, err = Reconcile(l2, r2); !errors.As(err, &re) || len(re.Mismatched) != 1 || re.Mismatched[0].ID != "batch-07" {
		t.Fatalf("altered retained data was not detected: %v", err)
	}
	// An extra retained id (committed, acknowledgement lost) is reported, not failed.
	l3, r3 := filledLedger(t, 3)
	r3["batch-ghost"] = "digest-ghost"
	if rec, err = Reconcile(l3, r3); err != nil || len(rec.UnackedRetained) != 1 {
		t.Fatalf("an unacknowledged retained batch: %+v %v", rec, err)
	}
	// An empty retained set fails when anything was acknowledged, and an empty ledger passes only
	// with nothing retained that it knows.
	if _, err = Reconcile(l3, map[string]string{}); err == nil {
		t.Fatal("nothing retained but three acknowledged: no failure")
	}
}

func TestLedgerRetryKeepsIdentityAndReceipt(t *testing.T) {
	l := &Ledger{}
	a := ackFor(1)
	if err := l.Record(a); err != nil {
		t.Fatal(err)
	}
	if err := l.Record(a); err != nil || l.Len() != 1 {
		t.Fatalf("an identical retry must be accepted once: %v %d", err, l.Len())
	}
	changed := a
	changed.Index++
	if err := l.Record(changed); err == nil {
		t.Fatal("a retry with a different receipt was accepted")
	}
	changed = a
	changed.Digest = "other"
	if err := l.Record(changed); err == nil {
		t.Fatal("a retry with different data was accepted")
	}
	if err := l.Record(Ack{ID: "x"}); err == nil {
		t.Fatal("an acknowledgement without a digest was accepted")
	}
}

func fixedClock() func() time.Time {
	t := time.Unix(1_700_000_000, 0)
	return func() time.Time { t = t.Add(time.Second); return t }
}

func TestOutageIsNotRecovery(t *testing.T) {
	// (a) Declaring recovery while nothing was delivered is a false recovered state.
	tl := NewTimeline(fixedClock())
	tl.Fail("provider-a", "refused")
	if err := tl.Recover("provider-a"); !errors.Is(err, ErrFalseRecovery) || tl.State() != StateOutage {
		t.Fatalf("recovered with no delivery: %v state=%s", err, tl.State())
	}
	// (b) Recovery without any outage is false as well.
	if err := NewTimeline(fixedClock()).Recover("x"); !errors.Is(err, ErrFalseRecovery) {
		t.Fatalf("recovery of a healthy system: %v", err)
	}
	// (c) A delivery that PRECEDES the last failure does not end the outage.
	tl = NewTimeline(fixedClock())
	tl.Deliver("p", "ok")
	tl.Fail("p", "refused")
	if err := tl.Recover("p"); !errors.Is(err, ErrFalseRecovery) {
		t.Fatalf("an older delivery ended the outage: %v", err)
	}
	// (d) A real recovery keeps every failed attempt and verifies.
	tl.Fail("p", "refused again")
	tl.Deliver("p", "sent")
	if err := tl.Recover("p"); err != nil || tl.State() != StateRecovered {
		t.Fatalf("a genuine recovery was refused: %v", err)
	}
	ev := tl.Events()
	if FailedAttempts(ev) != 2 {
		t.Fatalf("recovery erased failed attempts: %d left", FailedAttempts(ev))
	}
	if err := VerifyTimeline(ev, 2); err != nil {
		t.Fatalf("a valid timeline failed verification: %v", err)
	}
	// (e) Forged recovered entry (no delivery after the failure) is caught when verifying.
	forged := NewTimeline(fixedClock())
	forged.Fail("p", "refused")
	forged.mu.Lock()
	forged.append("state", "p", "recovered", "")
	forged.mu.Unlock()
	if err := VerifyTimeline(forged.Events(), 1); !errors.Is(err, ErrFalseRecovery) {
		t.Fatalf("a forged recovered state verified: %v", err)
	}
	// (e1) A recovered entry after a delivery that PRECEDES the last failure is forged as well.
	older := NewTimeline(fixedClock())
	older.Deliver("p", "ok")
	older.Fail("p", "refused")
	older.mu.Lock()
	older.append("state", "p", "recovered", "")
	older.mu.Unlock()
	if err := VerifyTimeline(older.Events(), 1); !errors.Is(err, ErrFalseRecovery) {
		t.Fatalf("recovery after an older delivery verified: %v", err)
	}
	// (e2) A second recovery, and a recovery of a timeline that only ever delivered, are false.
	if err := tl.Recover("p"); !errors.Is(err, ErrFalseRecovery) {
		t.Fatalf("an already recovered outage was recovered again: %v", err)
	}
	healthy := NewTimeline(fixedClock())
	healthy.Deliver("p", "ok")
	if err := healthy.Recover("p"); !errors.Is(err, ErrFalseRecovery) || healthy.State() != StateOK {
		t.Fatalf("a system that never failed was declared recovered: %v %s", err, healthy.State())
	}
	// (e3) Rewriting only the DETAIL of a failed attempt (the count is unchanged) breaks the chain.
	edited := append([]Event(nil), ev...)
	edited[1].Detail = "rewritten after the fact"
	if err := VerifyTimeline(edited, 2); err == nil {
		t.Fatal("an edited failed attempt verified although its hash no longer matches")
	}
	// (f) OVERWRITTEN failed attempt: rewriting a failed attempt as delivered (even with its hash
	// recomputed in place) breaks the chain; dropping it is caught by the expected count.
	over := append([]Event(nil), ev...)
	over[1].Outcome = "delivered"
	if err := VerifyTimeline(over, 2); err == nil {
		t.Fatal("an overwritten failed attempt verified")
	}
	over[1].Hash = over[1].digest()
	if err := VerifyTimeline(over, 2); err == nil {
		t.Fatal("an overwritten failed attempt with a recomputed hash verified")
	}
	dropped := append(append([]Event(nil), ev[:1]...), ev[2:]...)
	for i := range dropped {
		dropped[i].Seq = i + 1
	}
	if err := VerifyTimeline(dropped, 2); err == nil {
		t.Fatal("a dropped failed attempt verified")
	}
	// Rebuilding the chain without the failure (a consistent rewrite) is caught by the count.
	rebuilt := NewTimeline(fixedClock())
	rebuilt.Fail("p", "refused again")
	rebuilt.Deliver("p", "sent")
	if err := rebuilt.Recover("p"); err != nil {
		t.Fatal(err)
	}
	if err := VerifyTimeline(rebuilt.Events(), 2); err == nil {
		t.Fatal("a consistent rewrite that lost a failed attempt verified")
	}
}

// The forbidden list and the host list must each refuse on their own, not only through the other rules.
func TestDrillForbiddenAndHostListsRefuseIndependently(t *testing.T) {
	a := Allowlist{DataRoots: []string{"/srv/area"}, Hosts: []string{"localhost"}, Forbidden: []string{"/srv/area/prod"}}
	if err := CheckTarget(a, Target{Name: "isolated", DataDirs: []string{"/srv/area/ok/node"}}); err != nil {
		t.Fatalf("a directory under the root outside the forbidden list was refused: %v", err)
	}
	for _, d := range []string{"/srv/area/prod", "/srv/area/prod/node"} {
		if err := CheckTarget(a, Target{Name: "isolated", DataDirs: []string{d}}); !errors.Is(err, ErrRefused) {
			t.Errorf("%s: a forbidden directory inside an allowlisted root was accepted: %v", d, err)
		}
	}
	if err := CheckTarget(a, Target{Name: "isolated", Addresses: []string{"127.0.0.1:1"}}); !errors.Is(err, ErrRefused) {
		t.Errorf("a loopback host that is not on the allowlist was accepted: %v", err)
	}
	if err := CheckTarget(a, Target{Name: "isolated", Addresses: []string{"localhost:1"}}); err != nil {
		t.Errorf("a listed host was refused: %v", err)
	}
}
