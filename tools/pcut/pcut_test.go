// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

func TestJournalRoundTripAndEveryWayItBreaks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "j.jsonl")
	j, err := createJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := j.Append(entry{T: "ack", At: int64(i + 1), W: "w00", N: uint64(i + 1)}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := createJournal(path); err == nil {
		t.Fatal("an existing journal must not be overwritten")
	}
	r, err := readJournal(path)
	if err != nil || len(r.Entries) != 50 || r.TornTail {
		t.Fatalf("round trip: %v %d torn=%v", err, len(r.Entries), r.TornTail)
	}
	raw, _ := os.ReadFile(path)
	lines := strings.SplitAfter(string(raw), "\n")
	for name, mutated := range map[string]string{
		"changed payload": strings.Replace(string(raw), `"n":7`, `"n":8`, 1),
		"dropped line":    strings.Join(append(append([]string{}, lines[:10]...), lines[11:]...), ""),
		"swapped lines":   strings.Join(append(append(append([]string{}, lines[:3]...), lines[4], lines[3]), lines[5:]...), ""),
	} {
		p := filepath.Join(t.TempDir(), "m.jsonl")
		if err := os.WriteFile(p, []byte(mutated), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readJournal(p); err == nil {
			t.Errorf("%s was not detected", name)
		}
	}
	cut := filepath.Join(t.TempDir(), "c.jsonl")
	if err := os.WriteFile(cut, raw[:len(raw)-30], 0o600); err != nil {
		t.Fatal(err)
	}
	if r, err := readJournal(cut); err != nil || !r.TornTail || len(r.Entries) != 49 {
		t.Fatalf("a torn tail is ignored and reported: %v %v %d", err, r != nil && r.TornTail, len(r.Entries))
	}
}

func TestClassifyIngest(t *testing.T) {
	id := model.NewID()
	rec := model.Receipt{BatchID: id, Cursor: model.Cursor{Group: model.NewID(), Index: 3}}
	body, _ := json.Marshal(rec)
	if v, _, got := classifyIngest(200, body, nil, id); v != vAcked || got.BatchID != id {
		t.Fatalf("a receipt for this batch is an acknowledgement, got %s", v)
	}
	if v, _, _ := classifyIngest(200, body, nil, model.NewID()); v != vMalformed {
		t.Fatalf("a receipt for another batch is not an acknowledgement, got %s", v)
	}
	if v, _, _ := classifyIngest(200, []byte(`{}`), nil, id); v != vMalformed {
		t.Fatalf("200 without a receipt is not an acknowledgement, got %s", v)
	}
	if v, _, _ := classifyIngest(503, []byte(`{"code":"unavailable","retryable":true}`), nil, id); v != vRefusal {
		t.Fatalf("typed 503 is a retryable refusal, got %s", v)
	}
	if v, _, _ := classifyIngest(503, []byte(`<html>`), nil, id); v != vMalformed {
		t.Fatalf("untyped 503 is malformed, got %s", v)
	}
	if v, _, _ := classifyIngest(400, []byte(`{"code":"invalid"}`), nil, id); v != vRejected {
		t.Fatalf("400 is not retryable, got %s", v)
	}
}

// probe log of a 3-voter cluster: voter-a answers until t=100, is down from 101 to 260 (a 160 s outage), then answers again;
// the survivors stay ready; acknowledgements continue except for a 12 s hole right after the cut.
func syntheticProbeLog(t *testing.T, survivorsReadAfterGrace bool) string {
	path := filepath.Join(t.TempDir(), "probe.log")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	base := int64(1_800_000_000_000)
	for s := int64(0); s < 400; s++ {
		at := base + s*1000
		cg := probeLine{T: at, Ep: "voter-a", Code: 200, Ready: true}
		cgRead := probeLine{T: at, Ep: "voter-a", Q: true, QOK: true}
		if s > 100 && s < 261 {
			cg = probeLine{T: at, Ep: "voter-a", Err: "timeout"}
			cgRead = probeLine{T: at, Ep: "voter-a", Q: true, QDet: "skipped_not_ready"}
		}
		for _, l := range []probeLine{
			cg, cgRead,
			{T: at, Ep: "voter-b", Code: 200, Ready: true}, {T: at, Ep: "voter-b", Q: true, QOK: survivorsReadAfterGrace || s < 140 || s > 261, QMs: 800},
			{T: at, Ep: "voter-c", Code: 200, Ready: true}, {T: at, Ep: "voter-c", Q: true, QOK: true, QMs: 900},
		} {
			raw, _ := json.Marshal(l)
			f.Write(append(raw, '\n'))
		}
	}
	return path
}

func TestAnalyzeOutage(t *testing.T) {
	base := int64(1_800_000_000_000)
	var acks []ackRec
	for s := int64(0); s < 400; s++ {
		if s >= 101 && s < 114 { // nothing acknowledged for 13 s right after the cut
			continue
		}
		acks = append(acks, ackRec{at: (base + s*1000) * 1e6, member: "voter-c"})
	}
	o := analyzeOutage(syntheticProbeLog(t, true), "voter-a", acks, 90*time.Second, 30*time.Second)
	if !o.Observed || o.Seconds < 159 || o.Seconds > 161 {
		t.Fatalf("outage not found: %+v", o)
	}
	if o.CutReadyInWin != 0 || o.CutProbesInWin < 150 {
		t.Fatalf("the cut voter must not be ready inside the window: %+v", o)
	}
	if len(o.Others) != 2 || o.Others[0].QueryRatio != 1 || o.Others[1].ReadyRatio != 1 {
		t.Fatalf("survivors: %+v", o.Others)
	}
	if o.AckedInWindow < 140 || o.MaxAckGapSec > 2 || o.FirstAckAfter < 12.5 || o.FirstAckAfter > 13.5 {
		t.Fatalf("acks: %+v", o)
	}
	o = analyzeOutage(syntheticProbeLog(t, false), "voter-a", acks, 90*time.Second, 30*time.Second)
	if o.Others[0].Endpoint != "voter-b" || o.Others[0].QueryRatio > 0.2 {
		t.Fatalf("a survivor that stopped serving reads must show: %+v", o.Others)
	}
	if o := analyzeOutage(syntheticProbeLog(t, true), "voter-a", acks, 200*time.Second, 30*time.Second); o.Observed {
		t.Fatal("a 160 s outage is not a 200 s outage")
	}
	// a voter that never came back inside the log is not a completed power cut
	short := filepath.Join(t.TempDir(), "short.log")
	f, _ := os.Create(short)
	for s := int64(0); s < 200; s++ {
		l := probeLine{T: base + s*1000, Ep: "voter-a", Code: 200, Ready: true}
		if s > 50 {
			l = probeLine{T: base + s*1000, Ep: "voter-a", Err: "timeout"}
		}
		raw, _ := json.Marshal(l)
		f.Write(append(raw, '\n'))
	}
	f.Close()
	if o := analyzeOutage(short, "voter-a", nil, 90*time.Second, 30*time.Second); o.Observed {
		t.Fatal("a voter still down at the end of the log is not a recovered power cut")
	}
}

func failing(cs []check) map[string]bool {
	out := map[string]bool{}
	for _, c := range cs {
		if !c.Pass {
			out[c.Name] = true
		}
	}
	return out
}

func bitsOf(f float64) uint64 { return math.Float64bits(f) }

// one series "w00", one acknowledged batch of two records (n=1,2), observed at ts=1000 and 1001.
func judgeFixture(data []sample) voterReport {
	issued := map[key]issuedRec{{"w00", 1}: {"b1", 1000}, {"w00", 2}: {"b1", 1001}}
	acked := map[key]ackRec{{"w00", 1}: {at: 1, member: "m"}, {"w00", 2}: {at: 1, member: "m"}}
	batches := map[string]batchRec{"b1": {w: "w00", n: 1, cnt: 2, ts: 1000}}
	return judgeSamples("v", []string{"w00"}, map[string][]sample{"w00": data}, nil, issued, acked, batches)
}

func TestEveryVoterCheckFailsOnItsBadInput(t *testing.T) {
	good := []sample{{1000, bitsOf(1)}, {1001, bitsOf(2)}}
	base := judgeFixture(good)
	if cs := failing(voterChecks([]voterReport{base, base}, "v")); len(cs) != 0 {
		t.Fatalf("clean data must pass every check: %v", cs)
	}
	for _, tc := range []struct {
		name string
		data []sample
		want string
	}{
		{"missing acknowledged record", good[:1], "acked_all_readable_on_v"},
		{"duplicate record", append([]sample{{1000, bitsOf(1)}}, good...), "no_duplicate_records_on_v"},
		{"duplicate timestamp", []sample{{1000, bitsOf(1)}, {1000, bitsOf(2)}}, "no_duplicate_records_on_v"},
		{"torn value", []sample{{1000, bitsOf(1)}, {1001, bitsOf(2)}, {1002, bitsOf(1.5)}}, "no_torn_or_unknown_records_on_v"},
		{"foreign record", []sample{{1000, bitsOf(1)}, {1001, bitsOf(2)}, {1002, bitsOf(99)}}, "no_torn_or_unknown_records_on_v"},
		{"changed observed time", []sample{{1000, bitsOf(1)}, {1005, bitsOf(2)}}, "no_torn_or_unknown_records_on_v"},
	} {
		got := failing(voterChecks([]voterReport{judgeFixture(tc.data)}, "v"))
		if !got[tc.want] {
			t.Errorf("%s: %s did not fail, failing: %v", tc.name, tc.want, got)
		}
	}
	// a partly retained batch is torn even though one record is acknowledged and readable
	if got := failing(voterChecks([]voterReport{judgeFixture(good[1:])}, "v")); !got["no_torn_or_unknown_records_on_v"] || !got["acked_all_readable_on_v"] {
		t.Errorf("partial batch: %v", got)
	}
	// digest mismatch: the voters retain different data (the second voter holds one more sample)
	other := judgeFixture([]sample{{1000, bitsOf(1)}, {1001, bitsOf(2)}, {1002, bitsOf(99)}})
	if base.Digest == other.Digest {
		t.Fatal("different data must have a different digest")
	}
	got := failing(voterChecks([]voterReport{base, other}, "v"))
	if !got["voters_digests_equal"] {
		t.Errorf("digest mismatch not detected: %v", got)
	}
	// the cut voter that retains less than the others has not caught up
	behind := judgeFixture(good[:1])
	if got := failing(voterChecks([]voterReport{base, behind}, "v")); !got["cut_voter_caught_up"] {
		t.Errorf("cut voter behind not detected: %v", got)
	}
	// a voter that could not be read fails everything about it
	unread := voterReport{Endpoint: "v", ReadError: "boom"}
	got = failing(voterChecks([]voterReport{unread, base}, "v"))
	if !got["acked_all_readable_on_v"] || !got["voters_digests_equal"] || !got["cut_voter_caught_up"] {
		t.Errorf("read error: %v", got)
	}
}

func TestEveryOutageCheckFailsOnItsBadInput(t *testing.T) {
	base := int64(1_800_000_000_000)
	var acks []ackRec
	for s := int64(0); s < 400; s++ {
		acks = append(acks, ackRec{at: (base + s*1000) * 1e6, member: "voter-c"})
	}
	good := analyzeOutage(syntheticProbeLog(t, true), "voter-a", acks, 90*time.Second, 30*time.Second)
	run := func(o outageReport) map[string]bool {
		return failing(outageChecks(o, "voter-a", 90*time.Second, 30*time.Second, 30*time.Second, 0.9))
	}
	if got := run(good); len(got) != 0 {
		t.Fatalf("a real outage must pass: %v", got)
	}
	// no outage: the cut voter never stopped answering
	noOutage := analyzeOutage(syntheticProbeLog(t, true), "voter-a", acks, 200*time.Second, 30*time.Second)
	if got := run(noOutage); !got["outage_observed"] {
		t.Errorf("no outage: %v", got)
	}
	// the cut voter was ready inside the window: it was not down
	up := good
	up.CutReadyInWin = 3
	if got := run(up); !got["cut_voter_really_down"] {
		t.Errorf("voter not down: %v", got)
	}
	// a survivor that stopped serving reads
	deaf := analyzeOutage(syntheticProbeLog(t, false), "voter-a", acks, 90*time.Second, 30*time.Second)
	if got := run(deaf); !got["survivors_ready_and_reading_during_outage"] {
		t.Errorf("survivor not reading: %v", got)
	}
	// only one survivor probed
	one := good
	one.Others = good.Others[:1]
	if got := run(one); !got["survivors_ready_and_reading_during_outage"] {
		t.Errorf("one survivor: %v", got)
	}
	// no acknowledgement during the outage, and a gap longer than the limit
	if got := run(func() outageReport { o := good; o.AckedInWindow = 0; return o }()); !got["cluster_acknowledged_writes_during_outage"] {
		t.Errorf("no acks: %v", got)
	}
	if got := run(func() outageReport { o := good; o.MaxAckGapSec = 45; return o }()); !got["cluster_acknowledged_writes_during_outage"] {
		t.Errorf("ack gap: %v", got)
	}
}
