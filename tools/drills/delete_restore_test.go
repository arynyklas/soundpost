// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"soundpost/internal/jobs"
	"soundpost/internal/model"
)

func drMetric(project model.ID, at int64, name string, value uint64) model.Record {
	v := model.FloatBits(value)
	return model.Record{ID: model.NewID(), Kind: model.Metric, ObservedAt: model.UnixNano(at),
		Resource: model.Resource{Service: model.ID{1}, Environment: model.ID{2}, Build: model.ID{3}, Instance: "i", Labels: model.Labels{}},
		Payload:  model.Payload{Metric: &model.MetricPoint{Name: name, Labels: model.Labels{}, SampleKind: "float", Value: &v, Type: "counter", Unit: "1"}}}
}

// ---- fences ----

func drGoodFence() []drFenceSample {
	return []drFenceSample{
		{Seq: 1, Phase: model.DeletePhaseFencing, Generation: 3, Revision: 10, Barriers: 0, Physical: "pending"},
		{Seq: 2, Phase: model.DeletePhaseFencing, Generation: 3, Revision: 12, Barriers: 31, Physical: "pending"},
		{Seq: 3, Phase: model.DeletePhaseComplete, Generation: 4, Revision: 90, Barriers: 64, Physical: "pending"},
		{Seq: 4, Phase: model.DeletePhaseComplete, Generation: 5, Revision: 95, Barriers: 64, Physical: "done"},
	}
}

func TestDeleteRestoreFenceMustBeMonotoneAndComplete(t *testing.T) {
	if err := drVerifyFence(drGoodFence(), 64); err != nil {
		t.Fatalf("a monotone completed fence was refused: %v", err)
	}
	cases := map[string]func(s []drFenceSample) []drFenceSample{
		"no samples":           func(s []drFenceSample) []drFenceSample { return nil },
		"generation goes back": func(s []drFenceSample) []drFenceSample { s[2].Generation = 2; return s },
		"revision goes back":   func(s []drFenceSample) []drFenceSample { s[2].Revision = 11; return s },
		"barriers go back": func(s []drFenceSample) []drFenceSample {
			s[2].Barriers = 30
			s[2].Phase = model.DeletePhaseFencing
			return s
		},
		"more barriers than slots":      func(s []drFenceSample) []drFenceSample { s[3].Barriers = 65; return s },
		"complete with 63 barriers":     func(s []drFenceSample) []drFenceSample { s[2].Barriers = 63; s[3].Barriers = 63; return s },
		"complete goes back to fencing": func(s []drFenceSample) []drFenceSample { s[3].Phase = model.DeletePhaseFencing; return s },
		"never completes":               func(s []drFenceSample) []drFenceSample { return s[:2] },
		"held is not success":           func(s []drFenceSample) []drFenceSample { s[3].Phase = model.DeletePhaseHeld; return s },
		"failed is not success":         func(s []drFenceSample) []drFenceSample { s[1].Phase = model.DeletePhaseFailed; return s },
		"physical done goes back": func(s []drFenceSample) []drFenceSample {
			s[3].Physical = "done"
			s = append(s, drFenceSample{Seq: 5, Phase: model.DeletePhaseComplete, Generation: 5, Revision: 96, Barriers: 64, Physical: "pending"})
			return s
		},
		"unknown phase": func(s []drFenceSample) []drFenceSample { s[1].Phase = "weird"; return s },
	}
	for name, mutate := range cases {
		if err := drVerifyFence(mutate(drGoodFence()), 64); err == nil {
			t.Errorf("%s: the fence verifier accepted it", name)
		}
	}
}

func TestDeleteRestoreBarrierCoverage(t *testing.T) {
	good := func() []model.Cursor {
		out := make([]model.Cursor, 64)
		for i := range out {
			out[i] = model.Cursor{Group: model.NewID(), Index: model.Uint64(i + 1)}
		}
		return out
	}
	if err := drVerifyBarrierCoverage(good(), 64); err != nil {
		t.Fatalf("64 distinct groups refused: %v", err)
	}
	for name, mutate := range map[string]func(c []model.Cursor) []model.Cursor{
		"one group skipped":   func(c []model.Cursor) []model.Cursor { return c[:63] },
		"one group twice":     func(c []model.Cursor) []model.Cursor { c[5].Group = c[4].Group; return c },
		"zero group":          func(c []model.Cursor) []model.Cursor { c[7].Group = model.ID{}; return c },
		"zero cursor index":   func(c []model.Cursor) []model.Cursor { c[9].Index = 0; return c },
		"more than the slots": func(c []model.Cursor) []model.Cursor { return append(c, model.Cursor{Group: model.NewID(), Index: 1}) },
		"empty":               func(c []model.Cursor) []model.Cursor { return nil },
	} {
		if err := drVerifyBarrierCoverage(mutate(good()), 64); err == nil {
			t.Errorf("%s: the barrier coverage verifier accepted it", name)
		}
	}
}

// ---- stale senders ----

func TestDeleteRestoreStaleSendersAreNeverAcknowledged(t *testing.T) {
	ok := []drSend{
		{Label: "stale fresh", Stale: true, Built: 1, Fault: model.Stale},
		{Label: "stale replay", Stale: true, Built: 1, Fault: model.Stale},
		{Label: "current", Stale: false, Built: 3, Acked: true},
		{Label: "current refused by the barrier", Stale: false, Built: 3, Fault: model.Conflict},
	}
	if err := drVerifyStaleSends(ok, 2); err != nil {
		t.Fatalf("correct stale refusals were rejected: %v", err)
	}
	bad := map[string][]drSend{
		"a stale send was acknowledged":       {{Label: "a", Stale: true, Acked: true}, {Label: "b", Stale: true, Fault: model.Stale}},
		"refused with a non-stale code":       {{Label: "a", Stale: true, Fault: model.Unavailable}, {Label: "b", Stale: true, Fault: model.Stale}},
		"refused with no typed fault at all":  {{Label: "a", Stale: true}, {Label: "b", Stale: true, Fault: model.Stale}},
		"forbidden is not a stale refusal":    {{Label: "a", Stale: true, Fault: model.Forbidden}, {Label: "b", Stale: true, Fault: model.Stale}},
		"too few stale attempts to mean much": {{Label: "a", Stale: true, Fault: model.Stale}},
		"no stale attempts":                   {{Label: "c", Stale: false, Acked: true}},
		"acked and faulted at once":           {{Label: "a", Stale: true, Acked: true, Fault: model.Stale}, {Label: "b", Stale: true, Fault: model.Stale}},
	}
	for name, outcomes := range bad {
		if err := drVerifyStaleSends(outcomes, 2); err == nil {
			t.Errorf("%s: the stale-send verifier accepted it", name)
		}
	}
}

func TestDeleteRestorePolicyTimeline(t *testing.T) {
	good := func() []drPolicyStep {
		return []drPolicyStep{
			{Revision: 1, Phase: "complete", Barriers: 64, ControlRev: 10, Digest: "a"},
			{Revision: 2, Phase: "complete", Barriers: 64, ControlRev: 20, Digest: "b"},
			{Revision: 3, Phase: "complete", Barriers: 64, ControlRev: 35, Digest: "c"},
		}
	}
	if err := drVerifyPolicyTimeline(good(), 64); err != nil {
		t.Fatalf("a correct policy timeline was refused: %v", err)
	}
	for name, mutate := range map[string]func(s []drPolicyStep) []drPolicyStep{
		"a revision is skipped":          func(s []drPolicyStep) []drPolicyStep { s[2].Revision = 4; return s },
		"a revision repeats":             func(s []drPolicyStep) []drPolicyStep { s[2].Revision = 2; return s },
		"a fence is still fencing":       func(s []drPolicyStep) []drPolicyStep { s[1].Phase = "fencing"; return s },
		"a fence reached 63 slots":       func(s []drPolicyStep) []drPolicyStep { s[1].Barriers = 63; return s },
		"control revision does not grow": func(s []drPolicyStep) []drPolicyStep { s[2].ControlRev = 20; return s },
		"two revisions, one policy":      func(s []drPolicyStep) []drPolicyStep { s[2].Digest = "b"; return s },
		"a step has no digest":           func(s []drPolicyStep) []drPolicyStep { s[1].Digest = ""; return s },
		"empty":                          func(s []drPolicyStep) []drPolicyStep { return nil },
	} {
		if err := drVerifyPolicyTimeline(mutate(good()), 64); err == nil {
			t.Errorf("%s: the policy timeline verifier accepted it", name)
		}
	}
}

// ---- tombstone resurrection ----

func TestDeleteRestoreDetectsEveryResurrectedRow(t *testing.T) {
	org, project, sibling := model.NewID(), model.NewID(), model.NewID()
	tomb := model.DeletePredicate{Operation: model.NewID(), Org: org, Mode: model.DeleteHistoricalRange, Projects: []model.ID{project}, Signals: []model.Kind{model.Metric}, Start: 100, End: 200}
	row := func(id string, p model.ID, at int64) drRow {
		return drRow{BatchID: id, Org: org, Project: p, Record: drMetric(p, at, "m_"+id, 1)}
	}
	// Every retained row sits outside the tombstone: nothing is resurrected.
	clean := []drRow{row("before", project, 99), row("end-exclusive", project, 200), row("sibling", sibling, 150), row("after", project, 5000)}
	if got := drDetectResurrection(clean, []model.DeletePredicate{tomb}); len(got) != 0 {
		t.Fatalf("rows outside the tombstone were called resurrected: %v", got)
	}
	// One row inside (start inclusive), one in the middle, one with another org's id are separated exactly.
	dirty := append(append([]drRow{}, clean...), row("start-inclusive", project, 100), row("middle", project, 150), row("last-nanosecond", project, 199))
	got := drDetectResurrection(dirty, []model.DeletePredicate{tomb})
	want := []string{"last-nanosecond", "middle", "start-inclusive"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("resurrected = %v, want %v (sorted, exactly the covered rows)", got, want)
	}
	// A foreign organization's row is never covered by this org's tombstone.
	foreign := row("foreign", project, 150)
	foreign.Org = model.NewID()
	if got := drDetectResurrection([]drRow{foreign}, []model.DeletePredicate{tomb}); len(got) != 0 {
		t.Fatalf("a foreign organization's row was called resurrected: %v", got)
	}
	// A signal the tombstone does not name is not covered.
	log := row("log", project, 150)
	log.Record.Kind = model.Log
	if got := drDetectResurrection([]drRow{log}, []model.DeletePredicate{tomb}); len(got) != 0 {
		t.Fatalf("another signal was called resurrected: %v", got)
	}
	// Retirement covers everything of the project, any time.
	retire := model.DeletePredicate{Operation: model.NewID(), Org: org, Mode: model.DeleteRetireProject, Projects: []model.ID{project}}
	if got := drDetectResurrection(clean, []model.DeletePredicate{retire}); len(got) != 3 {
		t.Fatalf("a retired project's rows = %v, want all three of its rows", got)
	}
	// No tombstone, nothing can be resurrected; two tombstones are both consulted.
	if got := drDetectResurrection(dirty, nil); len(got) != 0 {
		t.Fatalf("with no tombstone %v were called resurrected", got)
	}
	second := model.DeletePredicate{Operation: model.NewID(), Org: org, Mode: model.DeleteHistoricalRange, Projects: []model.ID{sibling}, Signals: []model.Kind{model.Metric}, Start: 0, End: 1000}
	if got := drDetectResurrection(dirty, []model.DeletePredicate{tomb, second}); len(got) != 4 {
		t.Fatalf("with two tombstones resurrected = %v, want 4", got)
	}
}

func TestDeleteRestorePartitionsAcksByThePredicate(t *testing.T) {
	org, project := model.NewID(), model.NewID()
	tomb := model.DeletePredicate{Operation: model.NewID(), Org: org, Mode: model.DeleteHistoricalRange, Projects: []model.ID{project}, Signals: []model.Kind{model.Metric}, Start: 100, End: 200}
	mk := func(id string, at int64) drAcked {
		return drAcked{ID: id, Org: org, Project: project, Record: drMetric(project, at, id, 1)}
	}
	outside, inside := drPartition([]drAcked{mk("a", 50), mk("b", 100), mk("c", 199), mk("d", 200)}, []model.DeletePredicate{tomb})
	ids := func(v []drAcked) string {
		var s []string
		for _, a := range v {
			s = append(s, a.ID)
		}
		return strings.Join(s, ",")
	}
	if ids(outside) != "a,d" || ids(inside) != "b,c" {
		t.Fatalf("outside=%s inside=%s, want a,d / b,c", ids(outside), ids(inside))
	}
}

// ---- fail-closed classification ----

func TestDeleteRestoreRefusalMustBeTypedAndLeaveNothingActive(t *testing.T) {
	typed := func(c model.Code) error { return fmt.Errorf("restore: %w", model.Fail(c)) }
	good := drRefusal{Err: typed(model.Unavailable)}
	if err := drClassifyRefusal(good, model.Unavailable); err != nil {
		t.Fatalf("a typed, clean refusal was rejected: %v", err)
	}
	if err := drClassifyRefusal(drRefusal{Err: typed(model.Conflict)}, model.Unavailable, model.Conflict); err != nil {
		t.Fatalf("a typed refusal inside the allowed set was rejected: %v", err)
	}
	bad := map[string]drRefusal{
		"the restore succeeded":             {Err: nil},
		"an untyped error":                  {Err: errors.New("boom")},
		"a code outside the allowed set":    {Err: typed(model.Corrupt)},
		"a restore root was created":        {Err: typed(model.Unavailable), RootCreated: true},
		"staging leftovers":                 {Err: typed(model.Unavailable), StageLeftover: 1},
		"backup data was read first":        {Err: typed(model.Unavailable), ObjectsOpened: 1},
		"the restore reports activated":     {Err: typed(model.Unavailable), Activated: true},
		"rows were served":                  {Err: typed(model.Unavailable), ReadsServed: 1},
		"a write was admitted":              {Err: typed(model.Unavailable), Admitted: 1},
		"typed but the activation happened": {Err: typed(model.Conflict), Activated: true},
	}
	for name, o := range bad {
		if err := drClassifyRefusal(o, model.Unavailable, model.Conflict); err == nil {
			t.Errorf("%s: the classifier accepted it", name)
		}
	}
	// With no allowed set given the classifier refuses to guess one.
	if err := drClassifyRefusal(good); err == nil || !strings.Contains(err.Error(), "no allowed fault codes") {
		t.Errorf("a classifier with an empty allowed set must say it refuses to guess one, got %v", err)
	}
}

// ---- evidence gaps ----

func drEvidenceFixture() (acks []drAcked, gaps []model.EvidenceGap, group model.ID, org, project model.ID) {
	org, project, group = model.NewID(), model.NewID(), model.NewID()
	mk := func(id string, idx uint64) drAcked {
		return drAcked{ID: id, Org: org, Project: project, Record: model.Record{ID: model.NewID(), Kind: model.JobAttempt}, Cursor: model.Cursor{Group: group, Index: model.Uint64(idx)}, Digest: "d-" + id}
	}
	acks = []drAcked{mk("processed", 5), mk("gap1", 6), mk("gap2", 7), mk("live", 20)}
	gaps = []model.EvidenceGap{{ID: model.NewID(), Org: org, Project: project, Group: group, After: 5, Through: 7, Count: 2, Signals: []model.Kind{model.JobAttempt}, Reason: "unprocessed_expiry", DeclaredBy: "worker"}}
	return
}

func TestDeleteRestoreEvidenceIsAGapNeverSilence(t *testing.T) {
	acks, gaps, group, _, _ := drEvidenceFixture()
	retained := map[string]string{"live": "d-live"}
	processed := map[model.ID]uint64{group: 5}
	res, err := drClassifyEvidence(acks, retained, gaps, processed)
	if err != nil {
		t.Fatalf("a fully explained expiry was refused: %v", err)
	}
	want := map[string]drVerdict{"processed": drProcessedExpired, "gap1": drGapDeclared, "gap2": drGapDeclared, "live": drRetained}
	if len(res) != len(want) {
		t.Fatalf("%d results for %d acks", len(res), len(want))
	}
	for _, r := range res {
		if r.Verdict != want[r.ID] {
			t.Errorf("%s classified %s, want %s", r.ID, r.Verdict, want[r.ID])
		}
		if r.Verdict == drGapDeclared && (r.Gap == "" || r.Reason != "unprocessed_expiry") {
			t.Errorf("%s: a gap verdict must carry the gap and its declared reason: %+v", r.ID, r)
		}
	}

	type mutation struct {
		retained  map[string]string
		gaps      func([]model.EvidenceGap) []model.EvidenceGap
		processed map[model.ID]uint64
	}
	for name, m := range map[string]mutation{
		"the gap was never declared":               {retained, func([]model.EvidenceGap) []model.EvidenceGap { return nil }, processed},
		"an admin-declared gap authorizes nothing": {retained, func(g []model.EvidenceGap) []model.EvidenceGap { g[0].DeclaredBy = "admin"; return g }, processed},
		"a gap with no declared reason":            {retained, func(g []model.EvidenceGap) []model.EvidenceGap { g[0].Reason = ""; return g }, processed},
		"the gap stops one entry short":            {retained, func(g []model.EvidenceGap) []model.EvidenceGap { g[0].Through = 6; return g }, processed},
		"the gap starts one entry late":            {retained, func(g []model.EvidenceGap) []model.EvidenceGap { g[0].After = 6; return g }, processed},
		"the gap is another group's":               {retained, func(g []model.EvidenceGap) []model.EvidenceGap { g[0].Group = model.NewID(); return g }, processed},
		"the gap is another project's":             {retained, func(g []model.EvidenceGap) []model.EvidenceGap { g[0].Project = model.NewID(); return g }, processed},
		"the gap names another signal":             {retained, func(g []model.EvidenceGap) []model.EvidenceGap { g[0].Signals = []model.Kind{model.Metric}; return g }, processed},
		"unprocessed evidence is not covered":      {retained, func(g []model.EvidenceGap) []model.EvidenceGap { return g }, map[model.ID]uint64{group: 4}},
		"retained with other content":              {map[string]string{"live": "tampered"}, func(g []model.EvidenceGap) []model.EvidenceGap { return g }, processed},
		"retained inside a declared gap":           {map[string]string{"live": "d-live", "gap1": "d-gap1"}, func(g []model.EvidenceGap) []model.EvidenceGap { return g }, processed},
	} {
		g := append([]model.EvidenceGap(nil), gaps...)
		g = m.gaps(g)
		res, err := drClassifyEvidence(acks, m.retained, g, m.processed)
		if err == nil {
			t.Errorf("%s: the classifier accepted it (%+v)", name, res)
		}
	}
}

func TestDeleteRestoreHealthReportMustSayGap(t *testing.T) {
	gapID := model.NewID()
	gaps := []model.EvidenceGap{{ID: gapID, Signals: []model.Kind{model.JobAttempt}, Start: 10, End: 20}}
	good := func() jobs.Report {
		return jobs.Report{
			Health:    jobs.Health{Status: jobs.StatusUnknown, Complete: false, Reasons: []jobs.Reason{jobs.ReasonEvidenceGap}, Evidence: jobs.Evidence{Gaps: []model.ID{gapID}}},
			Intervals: []jobs.Interval{{ID: gapID, Start: 10, End: 20, Reason: "evidence_expired"}},
		}
	}
	if err := drVerifyHealthReportsGap(good(), gaps); err != nil {
		t.Fatalf("a report that names the gap was refused: %v", err)
	}
	for name, mutate := range map[string]func(r *jobs.Report){
		"an empty success (succeeded)":    func(r *jobs.Report) { r.Health.Status = jobs.StatusSucceeded },
		"unknown but complete":            func(r *jobs.Report) { r.Health.Complete = true },
		"no evidence-gap reason":          func(r *jobs.Report) { r.Health.Reasons = []jobs.Reason{jobs.ReasonNoEvidence} },
		"the gap is not in the evidence":  func(r *jobs.Report) { r.Health.Evidence.Gaps = nil },
		"the interval is not annotated":   func(r *jobs.Report) { r.Intervals = nil },
		"the interval has another reason": func(r *jobs.Report) { r.Intervals[0].Reason = "other" },
	} {
		r := good()
		mutate(&r)
		if err := drVerifyHealthReportsGap(r, gaps); err == nil {
			t.Errorf("%s: the health verifier accepted it", name)
		}
	}
	if err := drVerifyHealthReportsGap(good(), nil); err == nil {
		t.Errorf("a gap report with no declared gap to name was accepted")
	}
}

// ---- semantic digests ----

func TestDeleteRestoreDigestIsTheExactSemanticContent(t *testing.T) {
	project, source := model.NewID(), model.NewID()
	r := drMetric(project, 100, "requests", 0x3ff0000000000000)
	d := drRecordDigest(project, source, r)
	if d == "" {
		t.Fatal("the digest is empty")
	}
	if got := drPageRowDigest(project, source, r.ID, r.Kind, r.ObservedAt, r.Resource, r.Payload); got != d {
		t.Fatalf("the digest of a record and of the row read back for it differ: %s != %s", got, d)
	}
	if drRecordDigest(project, source, r) != d {
		t.Fatal("the digest is not deterministic")
	}
	variants := map[string]func(m *model.Record, p, s *model.ID){
		"value": func(m *model.Record, p, s *model.ID) {
			v := model.FloatBits(0x4000000000000000)
			m.Payload.Metric.Value = &v
		},
		"name":      func(m *model.Record, p, s *model.ID) { m.Payload.Metric.Name = "requests2" },
		"time":      func(m *model.Record, p, s *model.ID) { m.ObservedAt++ },
		"record id": func(m *model.Record, p, s *model.ID) { m.ID = model.NewID() },
		"project":   func(m *model.Record, p, s *model.ID) { *p = model.NewID() },
		"source":    func(m *model.Record, p, s *model.ID) { *s = model.NewID() },
		"instance":  func(m *model.Record, p, s *model.ID) { m.Resource.Instance = "other" },
		"kind":      func(m *model.Record, p, s *model.ID) { m.Kind = model.Log },
		"unit":      func(m *model.Record, p, s *model.ID) { m.Payload.Metric.Unit = "ms" },
	}
	for name, change := range variants {
		cp := r
		mp := *r.Payload.Metric
		cp.Payload.Metric = &mp
		p, s := project, source
		change(&cp, &p, &s)
		if drRecordDigest(p, s, cp) == d {
			t.Errorf("changing the %s did not change the digest", name)
		}
	}
}

// ---- the physical scanner ----

// Journals and snapshots wrap commands in base64 inside JSON inside base64; a scanner that only
// searches raw bytes would report "gone" for data that is sitting in a snapshot.
func TestDeleteRestoreScannerSeesThroughNestedBase64AndFragments(t *testing.T) {
	needle := "drill_doomed_0123456789ab_7"
	inner, _ := json.Marshal(map[string]string{"command": base64.StdEncoding.EncodeToString([]byte(`{"name":"` + needle + `","v":1}`))})
	outer := `{"state":"` + base64.RawURLEncoding.EncodeToString(inner) + `"}`
	n := []drNeedle{{"doomed", []byte(needle)}, {"other", []byte("never_present_in_this_data")}}
	hits := map[string]int{}
	drDeepHits([]byte(outer), n, 5, true, hits)
	if hits["doomed"] == 0 {
		t.Fatalf("the scanner missed a needle two base64 layers deep: %v", hits)
	}
	if hits["other"] != 0 {
		t.Fatalf("the scanner reported an absent needle: %v", hits)
	}
	// a free page starts in the middle of a base64 string: every alignment of the top level is tried
	enc := base64.StdEncoding.EncodeToString([]byte("prefix:" + needle + ":suffix"))
	for skip := 0; skip < 4; skip++ {
		hits = map[string]int{}
		drDeepHits([]byte(enc[skip:]), n, 5, true, hits)
		if hits["doomed"] == 0 {
			t.Errorf("a fragment starting %d characters into the base64 string was not searched", skip)
		}
	}
	// depth bounds the recursion: depth 0 is a plain search only
	hits = map[string]int{}
	drDeepHits([]byte(outer), n, 0, true, hits)
	if hits["doomed"] != 0 {
		t.Fatalf("depth 0 must not decode: %v", hits)
	}
	// random-looking data that merely decodes is not a hit
	hits = map[string]int{}
	drDeepHits([]byte(base64.StdEncoding.EncodeToString([]byte(strings.Repeat("noise-", 40)))), n, 5, true, hits)
	if len(hits) != 0 {
		t.Fatalf("noise produced hits %v", hits)
	}
}

func TestDeleteRestoreStoreHitsAreAttributedToTheirStore(t *testing.T) {
	for rel, want := range map[string]string{
		"data/apply.db":                               "apply.db",
		"data/segments/seg-0001.dat":                  "segments",
		"raft/data/slot-3/ready.wal":                  "raft_journal",
		"raft/data/slot-3/snapshots/s1/envelope.json": "snapshots",
		"control.db":                                  "control",
		"raft/control/ready.wal":                      "control",
		"control/raft/ready.wal":                      "control",
		"data/other.bin":                              "other:data/other.bin",
	} {
		if got := drStoreOf(rel); got != want {
			t.Errorf("drStoreOf(%q) = %q, want %q", rel, got, want)
		}
	}
	dir := t.TempDir()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(dir, "data", "segments"), 0o700))
	must(os.WriteFile(filepath.Join(dir, "data", "apply.db"), []byte("xx canary_value_1 xx"), 0o600))
	must(os.WriteFile(filepath.Join(dir, "data", "segments", "s"), []byte(base64.StdEncoding.EncodeToString([]byte("canary_value_1"))), 0o600))
	must(os.WriteFile(filepath.Join(dir, "data", "clean"), []byte("nothing here"), 0o600))
	hits, err := drStoreHits(dir, []drNeedle{{"c", []byte("canary_value_1")}})
	if err != nil {
		t.Fatal(err)
	}
	if drHitTotal(hits, "c") != 2 || strings.Join(drHitStores(hits, "c"), ",") != "apply.db,segments" {
		t.Fatalf("hits %v: want one in apply.db and one in segments, none attributed to the clean file", hits)
	}
	if drHitTotal(hits, "absent") != 0 || len(drHitStores(hits, "absent")) != 0 {
		t.Fatal("an absent label has hits")
	}
}

func TestDeleteRestoreProgressAndReceiptComparison(t *testing.T) {
	for in, want := range map[string]int{"0/64": 0, "12/64": 12, "64/64": 64, "": 0, "x/64": 0} {
		if got := drParseProgress(in); got != want {
			t.Errorf("drParseProgress(%q) = %d, want %d", in, got, want)
		}
	}
	a := model.Receipt{Version: 1, BatchID: model.NewID(), Cursor: model.Cursor{Group: model.NewID(), Index: 9}, RetainUntil: 100}
	b := a
	b.Historical = true
	if !drSameReceipt(a, b) {
		t.Error("the historical marker (how the lookup was authorized) must not make two identical ACKs differ")
	}
	b.Cursor.Index = 10
	if drSameReceipt(a, b) {
		t.Error("a receipt with another cursor was called the same ACK")
	}
	c := a
	c.RetainUntil = 101
	if drSameReceipt(a, c) {
		t.Error("a receipt with another retention deadline was called the same ACK")
	}
}

// Every ACK is accounted for on exactly one side of the deletion predicate: outside it goes into
// the report's ACK ledger (it must be retained exactly), inside it into the second ledger (it
// was acknowledged and then deleted and must be absent).
func TestDeleteRestoreLedgerSplitsAcksAtThePredicate(t *testing.T) {
	org := model.NewID()
	doomed := &drProject{id: model.NewID(), source: model.NewID()}
	sibling := &drProject{id: model.NewID(), source: model.NewID()}
	pred := model.DeletePredicate{Org: org, Mode: model.DeleteHistoricalRange, Projects: []model.ID{doomed.id}, Signals: []model.Kind{model.Metric}, Start: 100, End: 200}
	rep := &Report{}
	led := newDrLedgers(rep, pred)
	ack := func(p *drProject, at int64) (model.Batch, model.Receipt) {
		rec := drMetric(p.id, at, fmt.Sprintf("m_%d", at), 1)
		b := model.Batch{Version: 1, Project: p.id, Source: p.source, ID: model.NewID(), Records: []model.Record{rec}}
		r := model.Receipt{Version: 1, BatchID: b.ID, Cursor: model.Cursor{Group: model.NewID(), Index: 1}}
		if err := led.ack("test", org, p, b, rec, r); err != nil {
			t.Fatal(err)
		}
		return b, r
	}
	ack(doomed, 50)   // before the range
	ack(doomed, 150)  // inside: deleted
	ack(doomed, 200)  // end is exclusive
	ack(sibling, 150) // same time, another project
	if got := rep.Ledger().Len(); got != 3 {
		t.Fatalf("%d acknowledgements in the report ledger, want the 3 outside the predicate", got)
	}
	if len(led.keep) != 3 || len(led.gone) != 1 || led.gone2.Len() != 1 {
		t.Fatalf("keep=%d gone=%d goneLedger=%d, want 3/1/1", len(led.keep), len(led.gone), led.gone2.Len())
	}
	if led.gone[0].Record.ObservedAt != 150 || led.gone[0].Project != doomed.id {
		t.Fatalf("the deleted-side entry is %+v", led.gone[0])
	}
	// a retained row maps back to its batch; an unknown record stays visible to the reconciliation
	rows := map[model.ID]drScanned{led.keep[0].Record.ID: {Digest: "d"}, model.NewID(): {Digest: "x"}}
	into := map[string]string{}
	led.retained(rows, into)
	if into[led.keep[0].ID] != "d" || len(into) != 2 {
		t.Fatalf("retained = %v", into)
	}
	unknown := 0
	for k := range into {
		if strings.HasPrefix(k, "unknown-record:") {
			unknown++
		}
	}
	if unknown != 1 {
		t.Fatalf("%d unknown-record keys, want 1", unknown)
	}
	// the same batch acknowledged twice with another receipt is a harness failure, not a retry
	b, r := ack(sibling, 5)
	r.Cursor.Index = 2
	if err := led.ack("test", org, sibling, b, b.Records[0], r); err == nil {
		t.Fatal("one batch acknowledged twice with different receipts was accepted")
	}
}

// restore.json records the activation as a C01 decimal string; a parser that expected a JSON
// number would call every activated root "not activated" and make every closed-engine check pass
// vacuously.
func TestDeleteRestoreActivationMarkerIsReadFromRestoreJSON(t *testing.T) {
	root := t.TempDir()
	if drActivated(root) {
		t.Fatal("a root with no restore.json is not activated")
	}
	write := func(content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(root, "restore.json"), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(`{"version":1,"at_ns":"100"}`)
	if drActivated(root) {
		t.Fatal("a restore.json without the marker is not activated")
	}
	write(`{"version":1,"at_ns":"100","activated_ns":"0"}`)
	if drActivated(root) {
		t.Fatal("a zero marker is not activated")
	}
	write(`{"version":1,"at_ns":"100","activated_ns":"1799999999000000000"}`)
	if !drActivated(root) {
		t.Fatal("an activated root (decimal-string marker) was reported as not activated")
	}
	write(`not json`)
	if drActivated(root) {
		t.Fatal("an unreadable restore.json must not read as activated")
	}
}

func TestDeleteRestoreScenarioMustRecordEveryRequiredCheck(t *testing.T) {
	rep := &Report{Checks: []Check{{Name: "a", OK: true}, {Name: "b", OK: true}}}
	if err := drRequireRecorded(rep, "a", "b"); err != nil {
		t.Fatalf("all required checks were recorded and passed: %v", err)
	}
	if err := drRequireRecorded(rep, "a", "b", "exact_reconciliation"); err == nil || !strings.Contains(err.Error(), "exact_reconciliation") {
		t.Fatalf("a scenario that lost its reconciliation passed: %v", err)
	}
	rep.Checks = append(rep.Checks, Check{Name: "c", OK: false})
	if err := drRequireRecorded(rep, "a"); err == nil {
		t.Fatal("a failed check was ignored")
	}
	if err := drRequireRecorded(&Report{}, "a"); err == nil {
		t.Fatal("an empty report satisfied a required check")
	}
}

// A retained row nobody acknowledged must be traceable to the send that carried it.
func TestDeleteRestoreUnackedRowIsTracedToItsSend(t *testing.T) {
	led := newDrLedgers(&Report{}, model.DeletePredicate{})
	rec := drMetric(model.NewID(), 10, "m", 1)
	b := model.Batch{Version: 1, ID: model.NewID(), PolicyRevision: 3, Records: []model.Record{rec}}
	led.attempt(b, "race: in-range writer", model.Unavailable, false)
	got := led.describe("unknown-record:" + rec.ID.String())
	for _, want := range []string{"race: in-range writer", "unavailable", "revision 3"} {
		if !strings.Contains(got, want) {
			t.Errorf("%q does not mention %q", got, want)
		}
	}
	if d := led.describe("unknown-record:" + model.NewID().String()); !strings.Contains(d, "no recorded send") {
		t.Errorf("a row from no recorded send is described as %q", d)
	}
	if d := led.describe("someBatchID"); d != "someBatchID" {
		t.Errorf("a plain batch id is described as %q", d)
	}
}
