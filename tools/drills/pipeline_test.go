// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"fmt"
	"strings"
	"testing"

	"soundpost/internal/control"
	"soundpost/internal/model"
)

const (
	tOld = "old-owner"
	tNew = "new-owner"
)

func goodJourney() []pipeOwnerStep {
	return []pipeOwnerStep{
		{"shadow", []string{tOld}},
		{"quiescing_old", []string{tOld}},
		{"barrier_verified", nil},
		{"new_active", []string{tNew}},
		{"rollback_quiescing", nil},
		{"old_active", []string{tOld}},
	}
}

func TestPipeVerifyOwnerSteps(t *testing.T) {
	if err := pipeVerifyOwnerSteps(goodJourney(), tOld, tNew); err != nil {
		t.Fatalf("a correct journey was refused: %v", err)
	}
	mut := func(i int, owners []string) []pipeOwnerStep {
		s := goodJourney()
		s[i].Owners = owners
		return s
	}
	bad := map[string][]pipeOwnerStep{
		"two owners at new_active":           mut(3, []string{tOld, tNew}),
		"the old owner still active":         mut(3, []string{tOld}),
		"an owner before the barrier":        mut(2, []string{tNew}),
		"an owner while rolling back":        mut(4, []string{tNew}),
		"the new owner after the rollback":   mut(5, []string{tNew}),
		"no owner in shadow":                 mut(0, nil),
		"an unknown owner":                   mut(3, []string{"somebody-else"}),
		"duplicate listing of the one owner": mut(3, []string{tNew, tNew}),
		"no steps at all":                    nil,
		"unknown phase":                      append(goodJourney(), pipeOwnerStep{"limbo", nil}),
	}
	for name, steps := range bad {
		if err := pipeVerifyOwnerSteps(steps, tOld, tNew); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func call(seq int, id, kind string, attempt uint32, outcome, code, receipt string) pipeSend {
	return pipeSend{Seq: seq, ID: id, Subject: "incident:" + id[:1], Kind: kind, Attempt: attempt, Outcome: outcome, Code: code, Receipt: receipt}
}

func TestPipeVerifyRetryIdentity(t *testing.T) {
	good := []pipeSend{
		call(1, "aa", "open", 1, "retry", "provider_503", ""),
		call(2, "bb", "open", 1, "accepted", "", "rcpt-bb"),
		call(3, "aa", "open", 2, "unknown", "timeout", ""),
		call(4, "aa", "open", 3, "accepted", "", "rcpt-aa"),
	}
	if err := pipeVerifyRetryIdentity(good); err != nil {
		t.Fatalf("a correct retry history was refused: %v", err)
	}
	clone := func(f func([]pipeSend) []pipeSend) []pipeSend { return f(append([]pipeSend(nil), good...)) }
	bad := map[string][]pipeSend{
		"an attempt number was skipped":      clone(func(c []pipeSend) []pipeSend { c[3].Attempt = 4; return c }),
		"the kind drifted across a retry":    clone(func(c []pipeSend) []pipeSend { c[2].Kind = "worse_impact"; return c }),
		"the subject drifted across a retry": clone(func(c []pipeSend) []pipeSend { c[2].Subject = "incident:zz"; return c }),
		"accepted without a receipt":         clone(func(c []pipeSend) []pipeSend { c[3].Receipt = ""; return c }),
		"a send after the acceptance":        append(append([]pipeSend(nil), good...), call(5, "aa", "open", 4, "retry", "provider_503", "")),
		"accepted twice":                     append(append([]pipeSend(nil), good...), call(5, "aa", "open", 4, "accepted", "", "rcpt-aa")),
		"two receipts for one delivery":      append(append([]pipeSend(nil), good[:3]...), call(4, "aa", "open", 3, "unknown", "timeout", "rcpt-first"), call(5, "aa", "open", 4, "accepted", "", "rcpt-second")),
		"attempts do not start at one":       clone(func(c []pipeSend) []pipeSend { c[1].Attempt = 2; return c }),
	}
	for name, calls := range bad {
		if err := pipeVerifyRetryIdentity(calls); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestPipeFindDuplicateAnnouncements(t *testing.T) {
	clean := []pipeSend{
		call(1, "aa", "open", 1, "retry", "x", ""),
		call(2, "aa", "open", 2, "accepted", "", "r1"),
		call(3, "bb", "worse_impact", 1, "accepted", "", "r2"),
	}
	if got := pipeFindDuplicateAnnouncements(clean); len(got) != 0 {
		t.Fatalf("clean history flagged: %v", got)
	}
	twice := append(append([]pipeSend(nil), clean...), call(4, "aa", "open", 3, "accepted", "", "r1"))
	if got := pipeFindDuplicateAnnouncements(twice); len(got) == 0 {
		t.Error("one delivery accepted twice was not flagged")
	}
	// The same logical notification under two delivery IDs is a duplicate announcement.
	a := call(1, "aa", "open", 1, "accepted", "", "r1")
	b := call(2, "ab", "open", 1, "accepted", "", "r2")
	b.Subject = a.Subject
	a.ImpactRevision, b.ImpactRevision = 7, 7
	if got := pipeFindDuplicateAnnouncements([]pipeSend{a, b}); len(got) == 0 {
		t.Error("one logical notification accepted under two ids was not flagged")
	}
	b.ImpactRevision = 8
	if got := pipeFindDuplicateAnnouncements([]pipeSend{a, b}); len(got) != 0 {
		t.Errorf("a different impact revision is a different notification: %v", got)
	}
	// A send after the acceptance is a duplicate even when it is not accepted again.
	late := append(append([]pipeSend(nil), clean...), call(4, "bb", "worse_impact", 2, "retry", "x", ""))
	if got := pipeFindDuplicateAnnouncements(late); len(got) == 0 {
		t.Error("a send after the acceptance was not flagged")
	}
}

func TestPipeFindBacklogEmergencies(t *testing.T) {
	outage := map[string]bool{"aa": true, "bb": true}
	calls := []pipeSend{
		call(1, "aa", "worse_impact", 1, "retry", "x", ""),
		call(2, "bb", "open", 1, "unknown", "timeout", ""),
		call(3, "aa", "worse_impact", 2, "accepted", "", "r1"),
		call(4, "bb", "open", 2, "accepted", "", "r2"),
	}
	if got := pipeFindBacklogEmergencies(calls, len(calls), outage, nil); len(got) != 0 {
		t.Fatalf("nothing happened after the recovery, yet: %v", got)
	}
	// A brand new delivery after the recovery that nobody expected is a backlog emergency.
	invented := append(append([]pipeSend(nil), calls...), call(5, "cc", "open", 1, "accepted", "", "r3"))
	if got := pipeFindBacklogEmergencies(invented, 4, outage, nil); len(got) != 1 || !strings.Contains(got[0], "cc") {
		t.Errorf("an invented emergency after the recovery: %v", got)
	}
	// The same delivery is fine when the drill itself caused a genuinely new material change.
	if got := pipeFindBacklogEmergencies(invented, 4, outage, map[string]bool{"cc": true}); len(got) != 0 {
		t.Errorf("an expected new notification was flagged: %v", got)
	}
	// An outage delivery sent again after it was accepted is the backlog replayed.
	replay := append(append([]pipeSend(nil), calls...), call(5, "aa", "worse_impact", 3, "accepted", "", "r1"))
	if got := pipeFindBacklogEmergencies(replay, 4, outage, nil); len(got) == 0 {
		t.Error("an accepted outage delivery sent again after the recovery was not flagged")
	}
	// A late retry of a delivery still unaccepted at the boundary is the retry contract, not a replay.
	open := []pipeSend{call(1, "aa", "open", 1, "retry", "x", ""), call(2, "aa", "open", 2, "accepted", "", "r1")}
	if got := pipeFindBacklogEmergencies(open, 1, map[string]bool{"aa": true}, nil); len(got) != 0 {
		t.Errorf("the retry that completes a delivery was flagged: %v", got)
	}
}

func TestPipeFindSendsOutsideOwner(t *testing.T) {
	calls := []pipeSend{{ID: "a", Phase: "new_active"}, {ID: "b", Phase: "new_active"}}
	if got := pipeFindSendsOutsideOwner(calls, "new_active"); len(got) != 0 {
		t.Fatalf("flagged: %v", got)
	}
	calls = append(calls, pipeSend{ID: "c", Phase: "rollback_quiescing"}, pipeSend{ID: "d", Phase: "shadow"}, pipeSend{ID: "e"})
	if got := pipeFindSendsOutsideOwner(calls, "new_active"); len(got) != 3 {
		t.Fatalf("sends outside the owner's phase: %v", got)
	}
}

func baseSemantic() pipeSemantic {
	return pipeSemantic{ID: "aa", Subject: "incident:11", Kind: "worse_impact", Receipt: "rcpt-1", BodyDigest: "d0",
		Attempts: []pipeAttemptSemantic{{1, "retry", "provider_503"}, {2, "unknown", "timeout"}, {3, "accepted", ""}}}
}

func TestPipeDigestIsExactSemanticContent(t *testing.T) {
	base := baseSemantic()
	d := pipeDigest(base)
	if len(d) != 64 || d != pipeDigest(baseSemantic()) {
		t.Fatalf("digest %q is not a stable sha256", d)
	}
	mods := map[string]func(*pipeSemantic){
		"id":      func(s *pipeSemantic) { s.ID = "ab" },
		"subject": func(s *pipeSemantic) { s.Subject = "incident:12" },
		"kind":    func(s *pipeSemantic) { s.Kind = "open" },
		"receipt": func(s *pipeSemantic) { s.Receipt = "rcpt-2" },
		"body":    func(s *pipeSemantic) { s.BodyDigest = "d1" },
		"attempt count": func(s *pipeSemantic) {
			s.Attempts = s.Attempts[:2]
		},
		"attempt outcome": func(s *pipeSemantic) { s.Attempts[0].Outcome = "unknown" },
		"attempt code":    func(s *pipeSemantic) { s.Attempts[0].Code = "provider_500" },
		"attempt order": func(s *pipeSemantic) {
			s.Attempts[0], s.Attempts[1] = s.Attempts[1], s.Attempts[0]
		},
	}
	for name, mod := range mods {
		s := baseSemantic()
		mod(&s)
		if pipeDigest(s) == d {
			t.Errorf("a change of the %s did not change the digest", name)
		}
	}
}

func TestPipeSemanticFromSendsMatchesTheRecord(t *testing.T) {
	calls := []pipeSend{
		call(1, "aa", "worse_impact", 1, "retry", "provider_503", ""),
		call(2, "bb", "open", 1, "accepted", "", "rcpt-bb"),
		call(3, "aa", "worse_impact", 2, "unknown", "timeout", ""),
		call(4, "aa", "worse_impact", 3, "accepted", "", "rcpt-aa"),
	}
	calls[0].Subject, calls[2].Subject, calls[3].Subject = "incident:11", "incident:11", "incident:11"
	sem, err := pipeSemanticFromSends("aa", calls, "body-1")
	if err != nil {
		t.Fatal(err)
	}
	rec := control.DeliveryRecord{Subject: "incident:11", Kind: "worse_impact", Provider: "rcpt-aa", Phase: control.DeliveryAccepted,
		Attempts: []control.DeliveryAttempt{{Number: 1, Outcome: "retry", Code: "provider_503"}, {Number: 2, Outcome: "unknown", Code: "timeout"}, {Number: 3, Outcome: "accepted"}}}
	rec.ID = model.ID{0xaa}
	got := pipeSemanticFromRecord(rec)
	got.ID, got.BodyDigest = "aa", "body-1"
	if pipeDigest(sem) != pipeDigest(got) || pipeDigest(sem) == "" {
		t.Fatalf("what the sender observed and what the store holds differ:\n%+v\n%+v", sem, got)
	}
	rec.Provider = "rcpt-other"
	other := pipeSemanticFromRecord(rec)
	other.ID, other.BodyDigest = "aa", "body-1"
	if pipeDigest(sem) == pipeDigest(other) {
		t.Fatal("a different receipt in the store went unnoticed")
	}
	// The record's id is rendered the way the harness names a delivery.
	if id := pipeSemanticFromRecord(control.DeliveryRecord{ID: model.ID{0xab}}).ID; id != (model.ID{0xab}).String() {
		t.Fatalf("record id rendered as %q", id)
	}
	if _, err = pipeSemanticFromSends("zz", calls, "x"); err == nil {
		t.Fatal("a delivery that was never sent produced semantic content")
	}
	notDone := calls[:1]
	if _, err = pipeSemanticFromSends("aa", notDone, "x"); err == nil {
		t.Fatal("a delivery that was never accepted produced an acknowledgement")
	}
	// A delivery that was accepted and then sent again is not a clean acknowledgement either.
	sentAgain := append(append([]pipeSend(nil), calls[3]), call(5, "aa", "worse_impact", 4, "retry", "provider_503", ""))
	sentAgain[0].Subject, sentAgain[1].Subject = "incident:11", "incident:11"
	if _, err = pipeSemanticFromSends("aa", sentAgain, "x"); err == nil {
		t.Fatal("a delivery that was sent again after its acceptance produced an acknowledgement")
	}
}

func obsState(mods ...func(*pipeObsState)) pipeObsState {
	st := pipeObsState{Observer: "deadman-fixture", StartedNS: 10, LastCycle: 900, Armed: true,
		Components: []pipeObsComponent{{"product", "missing"}},
		Outages: []pipeObsOutage{{ID: "o1", Component: "product", LastOKNS: 100, DetectedNS: 300, Alerted: true,
			Attempts: []pipeObsAttempt{{N: 1, AtNS: 301, Kind: "alert", Status: 503, Error: "status"}, {N: 2, AtNS: 520, Kind: "alert", Status: 200}}}}}
	for _, m := range mods {
		m(&st)
	}
	return st
}

func TestPipeParseObserverState(t *testing.T) {
	raw := []byte(`{"observer":"deadman-fixture","started_ns":10,"last_cycle_ns":900,"armed":true,"components":[{"name":"product","last_ok_ns":5,"last_seq":3,"status":"ok"}],
 "outages":[{"id":"o1","component":"product","last_ok_ns":100,"detected_ns":300,"alerted":true,"recovery_notified":false,"attempts":[{"n":1,"at_ns":301,"kind":"alert","status":503,"error":"status"}]}]}`)
	st, err := pipeParseObserverState(raw)
	if err != nil || st.Observer != "deadman-fixture" || len(st.Outages) != 1 || st.Outages[0].Attempts[0].Status != 503 || st.LastCycle != 900 {
		t.Fatalf("parsed %+v, %v", st, err)
	}
	for name, bad := range map[string]string{"garbage": "not json", "empty object": "{}", "no observer": `{"started_ns":1}`, "no start": `{"observer":"x"}`, "trailing": `{"observer":"x","started_ns":1} {}`} {
		if _, err = pipeParseObserverState([]byte(bad)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestPipeCountAlertAttempts(t *testing.T) {
	st := obsState(func(s *pipeObsState) {
		s.Outages[0].Attempts = append(s.Outages[0].Attempts, pipeObsAttempt{N: 1, AtNS: 800, Kind: "recovery", Status: 503, Error: "status"}, pipeObsAttempt{N: 3, AtNS: 801, Kind: "alert", Error: "transport"})
	})
	failed, accepted := pipeCountAlertAttempts(st)
	if failed != 2 || accepted != 1 {
		t.Fatalf("failed %d accepted %d, want 2 and 1 (a recovery notice is not an alert)", failed, accepted)
	}
}

func TestPipeVerifyOutageRetained(t *testing.T) {
	before := obsState()
	if err := pipeVerifyOutageRetained(before, before); err != nil {
		t.Fatalf("an unchanged record was refused: %v", err)
	}
	recovered := obsState(func(s *pipeObsState) {
		s.Outages[0].RecoveredNS, s.Outages[0].Recovery = 700, true
		s.Outages[0].Attempts = append(s.Outages[0].Attempts, pipeObsAttempt{N: 1, AtNS: 701, Kind: "recovery", Status: 200})
	})
	if err := pipeVerifyOutageRetained(before, recovered); err != nil {
		t.Fatalf("a recovery that only appended its notice was refused: %v", err)
	}
	bad := map[string]pipeObsState{
		"the outage was dropped":                              obsState(func(s *pipeObsState) { s.Outages = nil }),
		"the failed attempt was erased":                       obsState(func(s *pipeObsState) { s.Outages[0].Attempts = s.Outages[0].Attempts[1:] }),
		"the failed attempt was rewritten to another failure": obsState(func(s *pipeObsState) { s.Outages[0].Attempts[0].Status = 502 }),
		"the failed attempt was moved in time":                obsState(func(s *pipeObsState) { s.Outages[0].Attempts[0].AtNS = 250 }),
		"the failed attempt was rewritten to a success":       obsState(func(s *pipeObsState) { s.Outages[0].Attempts[0].Status = 200; s.Outages[0].Attempts[0].Error = "" }),
		"the detection time moved":                            obsState(func(s *pipeObsState) { s.Outages[0].DetectedNS = 999 }),
		"the last healthy time moved":                         obsState(func(s *pipeObsState) { s.Outages[0].LastOKNS = 99 }),
		"the alert flag was cleared":                          obsState(func(s *pipeObsState) { s.Outages[0].Alerted = false }),
		"the outage id changed":                               obsState(func(s *pipeObsState) { s.Outages[0].ID = "o2" }),
		"a second alert was accepted": obsState(func(s *pipeObsState) {
			s.Outages[0].Attempts = append(s.Outages[0].Attempts, pipeObsAttempt{N: 3, AtNS: 800, Kind: "alert", Status: 200})
		}),
		"a new outage appeared (an emergency)": obsState(func(s *pipeObsState) {
			s.Outages = append(s.Outages, pipeObsOutage{ID: "o9", Component: "ingest", DetectedNS: 800})
		}),
		"the observer changed":      obsState(func(s *pipeObsState) { s.Observer = "someone-else" }),
		"the observer started over": obsState(func(s *pipeObsState) { s.StartedNS = 11 }),
	}
	for name, after := range bad {
		if err := pipeVerifyOutageRetained(before, after); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestPipeIsFault(t *testing.T) {
	f := model.Fail(model.Stale)
	f.SafeDetail = control.DeliveryOwnerStale
	wrapped := fmt.Errorf("claim: %w", f)
	if !pipeIsFault(wrapped, string(model.Stale), control.DeliveryOwnerStale) {
		t.Error("a wrapped stale-owner fault was not recognised")
	}
	if pipeIsFault(wrapped, string(model.Stale), control.DeliveryLeaseStale) {
		t.Error("another detail matched")
	}
	if pipeIsFault(wrapped, string(model.Conflict), control.DeliveryOwnerStale) {
		t.Error("another code matched")
	}
	if pipeIsFault(nil, string(model.Stale), "") || pipeIsFault(fmt.Errorf("plain"), string(model.Stale), "") {
		t.Error("a non-fault matched")
	}
	if !pipeIsFault(wrapped, string(model.Stale), "") {
		t.Error("an empty detail must match any detail of the code")
	}
}

func TestPipeStoreVsLedger(t *testing.T) {
	rec := func(id byte, phase string) control.DeliveryRecord {
		return control.DeliveryRecord{ID: model.ID{id}, Phase: phase}
	}
	ack := func(id byte) Ack { return Ack{ID: (model.ID{id}).String()} }
	recs := []control.DeliveryRecord{rec(1, control.DeliveryAccepted), rec(2, control.DeliveryAccepted), rec(3, control.DeliveryCancelled), rec(4, control.DeliverySuppressed)}
	if got := pipeStoreVsLedger(recs, []Ack{ack(1), ack(2)}); len(got) != 0 {
		t.Fatalf("a consistent store was flagged: %v", got)
	}
	if got := pipeStoreVsLedger(recs, []Ack{ack(1)}); len(got) != 1 || !strings.Contains(got[0], (model.ID{2}).String()) {
		t.Errorf("an accepted record nobody ACKed: %v", got)
	}
	for _, phase := range []string{control.DeliveryPending, control.DeliveryClaimed} {
		open := append(append([]control.DeliveryRecord(nil), recs...), rec(5, phase))
		if got := pipeStoreVsLedger(open, []Ack{ack(1), ack(2)}); len(got) != 1 || !strings.Contains(got[0], phase) {
			t.Errorf("a %s delivery left at the end: %v", phase, got)
		}
	}
	// An ACK for a delivery the store does not hold at all is a lost delivery.
	if got := pipeStoreVsLedger(recs, []Ack{ack(1), ack(2), ack(9)}); len(got) != 1 || !strings.Contains(got[0], (model.ID{9}).String()) {
		t.Errorf("an ACK without a record: %v", got)
	}
	// An ACKed delivery whose record is not accepted is a lost delivery too.
	if got := pipeStoreVsLedger(recs, []Ack{ack(1), ack(2), ack(3)}); len(got) != 1 {
		t.Errorf("an ACK for a record that is not accepted: %v", got)
	}
}

func TestPipeObserverEvents(t *testing.T) {
	st := obsState(func(s *pipeObsState) {
		s.Outages[0].RecoveredNS, s.Outages[0].Recovery = 700, true
		s.Outages[0].Attempts = append(s.Outages[0].Attempts, pipeObsAttempt{N: 1, AtNS: 701, Kind: "recovery", Status: 200})
		s.Outages = append(s.Outages, pipeObsOutage{ID: "o2", Component: "ingest", DetectedNS: 250, Attempts: []pipeObsAttempt{{N: 1, AtNS: 260, Kind: "alert", Error: "transport"}}})
	})
	ev := pipeObserverEvents(st)
	var keys []string
	for _, e := range ev {
		keys = append(keys, fmt.Sprintf("%d:%s:%v", e.At, e.Key, e.Fail))
	}
	want := []string{"250:o2/missing:true", "260:o2/alert#1:true", "300:o1/missing:true", "301:o1/alert#1:true", "520:o1/alert#2:false", "701:o1/recovery#1:false"}
	if fmt.Sprint(keys) != fmt.Sprint(want) {
		t.Fatalf("events\n%v\nwant\n%v", keys, want)
	}
	if ev[0].Subject != "heartbeat/ingest" || ev[1].Subject != "alert/ingest" || ev[5].Subject != "recovery/product" {
		t.Errorf("subjects %q %q %q", ev[0].Subject, ev[1].Subject, ev[5].Subject)
	}
	seen := map[string]bool{}
	for _, e := range ev {
		if seen[e.Key] {
			t.Errorf("duplicate key %s", e.Key)
		}
		seen[e.Key] = true
	}
	if got := pipeObserverEvents(pipeObsState{}); len(got) != 0 {
		t.Errorf("an empty record produced %v", got)
	}
}

func TestPipeNoticeDigest(t *testing.T) {
	d := pipeNoticeDigest("obs", "alert", "o1", "product")
	if len(d) != 64 || d != pipeNoticeDigest("obs", "alert", "o1", "product") {
		t.Fatalf("digest %q", d)
	}
	for name, other := range map[string]string{
		"observer":  pipeNoticeDigest("obs2", "alert", "o1", "product"),
		"kind":      pipeNoticeDigest("obs", "recovery", "o1", "product"),
		"outage":    pipeNoticeDigest("obs", "alert", "o2", "product"),
		"component": pipeNoticeDigest("obs", "alert", "o1", "ingest"),
		"shifted":   pipeNoticeDigest("obsa", "lert", "o1", "product"),
	} {
		if other == d {
			t.Errorf("a different %s has the same digest", name)
		}
	}
}

// The first alert attempt happens in the very cycle that detects the outage (same instant): the
// detection must still precede it on the timeline.
func TestPipeObserverEventsMissingPrecedesItsAlertAtTheSameInstant(t *testing.T) {
	st := pipeObsState{Observer: "o", StartedNS: 1, Outages: []pipeObsOutage{{ID: "a1", Component: "product", DetectedNS: 400,
		Attempts: []pipeObsAttempt{{N: 1, AtNS: 400, Kind: "alert", Status: 503, Error: "status"}, {N: 2, AtNS: 600, Kind: "alert", Status: 200}}}}}
	ev := pipeObserverEvents(st)
	if len(ev) != 3 || ev[0].Key != "a1/missing" || ev[1].Key != "a1/alert#1" || ev[2].Key != "a1/alert#2" {
		t.Fatalf("order %+v", ev)
	}
}

func TestPipeRequireChecks(t *testing.T) {
	checks := []Check{{Name: "a", OK: true}, {Name: "b", OK: true}, {Name: "c", OK: true}}
	if err := pipeRequireChecks(checks, []string{"a", "c"}); err != nil {
		t.Fatalf("every required check holds: %v", err)
	}
	if err := pipeRequireChecks(checks, []string{"a", "missing"}); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Errorf("a check that was deleted from the scenario went unnoticed: %v", err)
	}
	failed := []Check{{Name: "a", OK: true}, {Name: "b", OK: false, Detail: "x"}}
	if err := pipeRequireChecks(failed, []string{"a", "b"}); err == nil || !strings.Contains(err.Error(), "b") {
		t.Errorf("a failed required check went unnoticed: %v", err)
	}
	dup := []Check{{Name: "a", OK: true}, {Name: "a", OK: false}}
	if err := pipeRequireChecks(dup, []string{"a"}); err == nil {
		t.Error("a failed repeat of a check was hidden by an earlier pass")
	}
	if err := pipeRequireChecks(nil, nil); err == nil {
		t.Error("a scenario that requires nothing is not a drill")
	}
	if err := pipeRequireChecks(checks, []string{"a", "a"}); err == nil {
		t.Error("a duplicated requirement was accepted")
	}
}

func TestPipeScenarioCheckListsAreWellFormed(t *testing.T) {
	for name, list := range map[string][]string{"provider-failure-outage": pipeProviderChecks, "owner-cutover-rollback": pipeCutoverChecks, "external-deadman": pipeDeadmanChecks} {
		var checks []Check
		for _, n := range list {
			checks = append(checks, Check{Name: n, OK: true})
		}
		if err := pipeRequireChecks(checks, list); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		if len(list) < 20 {
			t.Errorf("%s defines only %d checks", name, len(list))
		}
	}
}
