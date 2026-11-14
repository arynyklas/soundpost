// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

// The control books carry payloads derived from telemetry (rule evaluation
// values and recording batches, incident and condition state, notification
// bodies). These tests pin that a committed deletion removes every such payload
// of its scope from the control state, the control snapshot and control.db, and
// that it keeps what is not covered.

var eraseRun = regexp.MustCompile(`[A-Za-z0-9+/_-]{16,}={0,2}`)

// eraseDeep reports whether needle occurs in data, directly or inside nested
// base64 / JSON-escaped encodings (the same decoder the storage erase tests use).
func eraseDeep(data, needle []byte, depth int) bool {
	if bytes.Contains(data, needle) {
		return true
	}
	if depth == 0 {
		return false
	}
	for _, run := range eraseRun.FindAll(data, -1) {
		for skip := range 4 {
			if skip >= len(run) {
				break
			}
			for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
				text := bytes.TrimRight(run[skip:], "=")
				if len(text)%4 == 1 {
					text = text[:len(text)-1]
				}
				if d, err := enc.DecodeString(string(text)); err == nil && eraseDeep(d, needle, depth-1) {
					return true
				}
			}
		}
	}
	return false
}

// eraseFileHits lists every regular file under dir that holds needle.
func eraseFileHits(t *testing.T, dir, needle string) []string {
	t.Helper()
	var hits []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return err
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if eraseDeep(raw, []byte(needle), 6) {
			rel, _ := filepath.Rel(dir, p)
			hits = append(hits, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(hits)
	return hits
}

type eraseFx struct {
	*delFx
}

func newEraseFx(t *testing.T) *eraseFx {
	t.Helper()
	f := &eraseFx{newDelFx(t)}
	for _, bind := range []func() error{f.store.BindRuleEvaluation, f.store.BindIncidentAction, f.store.BindConditionApply} {
		if err := bind(); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

// seed identifies one project's committed control payloads; every payload
// carries the seed's canary.
type eraseSeed struct {
	project model.ID
	canary  string
	rule    model.ID
	inc     model.ID
	cond    model.ID
	policy  model.ID
	// note puts the canary into the notification policy state too (a payload only a
	// retirement drops: a range keeps the policy state).
	note bool
}

func (f *eraseFx) newSeed(project model.ID, canary string) eraseSeed {
	return eraseSeed{project: project, canary: canary, rule: model.NewID(), inc: model.NewID(), cond: model.NewID(), policy: model.NewID()}
}

// commitRule commits one evaluation at `at` with one recording intent (a whole
// batch) of the given signal, and returns the output ID.
func (f *eraseFx) commitRule(s eraseSeed, at uint64, signal model.Kind) model.ID {
	f.t.Helper()
	lease := f.lease()
	payload := fmt.Sprintf(`{"series":%q}`, s.canary)
	out := control.RuleOutputIntent{ID: model.NewID(), Kind: control.RuleOutputRecording, Signal: signal,
		Payload: json.RawMessage(fmt.Sprintf(`{"batch":{"records":[{"metric":%q}]}}`, s.canary)), Inputs: []model.Cursor{{Group: model.ID{9}, Index: 1}}}
	e := &control.RuleEvaluationApply{Project: s.project, Rule: s.rule, Version: 1, At: model.UnixNano(at), Mode: control.RuleModeLive, Health: control.RuleHealthOK,
		Digest: digestOf(payload), Payload: json.RawMessage(payload), Cursors: []model.Cursor{{Group: model.ID{9}, Index: model.Uint64(at)}}, Outputs: []control.RuleOutputIntent{out}}
	if _, err := f.store.Transact(f.ctx, f.adminScope(), f.cmd(control.KindApplyRuleEvaluation, model.NewID(), control.RuleCommand{Operation: control.RuleOpEvaluation, Lease: &lease, Evaluation: e})); err != nil {
		f.t.Fatal(err)
	}
	return out.ID
}

func (f *eraseFx) commitIncident(s eraseSeed, at int64) {
	f.t.Helper()
	state := json.RawMessage(fmt.Sprintf(`{"incident_id":%q,"org_id":%q,"project_id":%q,"version":"1","evidence":%q,"at":"%d"}`, s.inc.String(), f.org.String(), s.project.String(), s.canary, at))
	c := control.IncidentCommand{Project: s.project, Incident: s.inc, Action: "open", Origin: "human", Actor: f.user, At: 100, NewVersion: 1, State: state, Digest: digest(state)}
	if _, err := f.store.Transact(f.ctx, f.adminScope(), f.cmd(control.KindIncidentAction, model.NewID(), c)); err != nil {
		f.t.Fatal(err)
	}
}

func (f *eraseFx) commitCondition(s eraseSeed, at int64) {
	f.t.Helper()
	lease := f.lease()
	state := json.RawMessage(fmt.Sprintf(`{"condition_id":%q,"org_id":%q,"project_id":%q,"version":"1","labels":{"host":%q},"event_ns":"%d"}`, s.cond.String(), f.org.String(), s.project.String(), s.canary, at))
	c := control.ConditionCommand{Project: s.project, Condition: s.cond, Lease: &lease, NewVersion: 1, At: 100, Change: "firing", State: state, Digest: digest(state)}
	if _, err := f.store.Transact(f.ctx, f.adminScope(), f.cmd(control.KindApplyCondition, model.NewID(), c)); err != nil {
		f.t.Fatal(err)
	}
}

// commitDelivery enqueues one delivery whose body carries the canary and whose
// evidence interval is [from, to].
func (f *eraseFx) commitDelivery(s eraseSeed, from, to model.UnixNano) model.ID {
	f.t.Helper()
	body := json.RawMessage(fmt.Sprintf(`{"title":%q}`, s.canary))
	in := f.intent(byte(from%200)+1, withBody(string(body)), withOrigin(from, to))
	in.ID = model.NewID()
	note := "none"
	if s.note {
		note = s.canary
	}
	state := json.RawMessage(fmt.Sprintf(`{"org_id":%q,"version":1,"subject_note":%q}`, f.org.String(), note))
	e := control.DeliveryEnqueue{Project: s.project, Policy: s.policy, Subject: "incident:" + s.inc.String(), NewVersion: 1, At: 100, State: state, Digest: digest(state), Intents: []control.DeliveryIntent{in}}
	lease := f.lease()
	if _, err := f.send(control.KindClaimDelivery, model.NewID(), control.DeliveryCommand{Operation: control.DeliveryOpEnqueue, Lease: &lease, Enqueue: &e}); err != nil {
		f.t.Fatal(err)
	}
	return in.ID
}

// seedAll commits one of everything for a project at the given evidence time.
func (f *eraseFx) seedAll(s eraseSeed, at int64) (output, delivery model.ID) {
	f.t.Helper()
	output = f.commitRule(s, uint64(at), model.Metric)
	f.commitIncident(s, at)
	f.commitCondition(s, at)
	delivery = f.commitDelivery(s, model.UnixNano(at), model.UnixNano(at))
	return output, delivery
}

// output reads one rule output back through the control read path (Obsolete is
// computed there from the committed deletion facts).
func (f *eraseFx) output(s eraseSeed, id model.ID) control.RuleOutput {
	f.t.Helper()
	outs, err := f.store.RuleOutputs(f.ctx, f.adminScope(), s.project, s.rule, "", 0)
	if err != nil {
		f.t.Fatal(err)
	}
	for _, o := range outs {
		if o.ID == id {
			return o
		}
	}
	f.t.Fatalf("output %s of rule %s not found", id, s.rule)
	return control.RuleOutput{}
}

// stateHolds reports whether the control state (as a view returns it) holds the canary.
func (f *eraseFx) stateHolds(canary string) bool {
	f.t.Helper()
	held := false
	if err := f.store.View(f.ctx, func(st control.State) error {
		raw, err := json.Marshal(st)
		if err != nil {
			return err
		}
		held = eraseDeep(raw, []byte(canary), 3)
		return nil
	}); err != nil {
		f.t.Fatal(err)
	}
	return held
}

// snapshotHolds reports whether the control snapshot a new voter would be seeded
// with holds the canary.
func (f *eraseFx) snapshotHolds(canary string) bool {
	f.t.Helper()
	raw, _, err := f.store.ReplicationSeed()
	if err != nil {
		f.t.Fatal(err)
	}
	return eraseDeep(raw, []byte(canary), 3)
}

// saga drives one deletion through every control step a worker takes.
func (f *eraseFx) saga(req control.DeleteScope) model.ID {
	f.t.Helper()
	id, _, err := f.del(req)
	if err != nil {
		f.t.Fatal(err)
	}
	if _, err = f.store.RecordBarriers(f.ctx, id, cursors(model.DeleteSlots)); err != nil {
		f.t.Fatal(err)
	}
	at := model.UnixNano(f.now.UnixNano())
	if _, err = f.store.CompleteDeletion(f.ctx, id, at, nil); err != nil {
		f.t.Fatal(err)
	}
	if _, err = f.store.RecordPhysicalCleanup(f.ctx, f.org, []model.ID{id}, at); err != nil {
		f.t.Fatal(err)
	}
	return id
}

func controlDBHits(t *testing.T, dir, canary string) []string {
	t.Helper()
	var out []string
	for _, h := range eraseFileHits(t, dir, canary) {
		if !strings.HasPrefix(h, "raft-control/") {
			out = append(out, h)
		}
	}
	return out
}

func TestRetireProjectErasesEveryControlPayload(t *testing.T) {
	f := newEraseFx(t)
	const gone, kept = "CANARYGONE7c41e90d2b86a", "CANARYKEPT51f0aa93c7de1"
	deleted, other := f.newSeed(f.project, gone), f.newSeed(f.otherProject, kept)
	deleted.note = true
	output, delivery := f.seedAll(deleted, 50)
	otherOutput, otherDelivery := f.seedAll(other, 50)
	if !f.stateHolds(gone) || !f.stateHolds(kept) {
		t.Fatal("fixture: the canaries are not in the control state before the deletion")
	}
	if hits := eraseFileHits(t, f.dir, gone); !contains(hits, "control.db") {
		t.Fatalf("fixture: control.db does not hold the canary before the deletion: %v", hits)
	}

	f.saga(control.DeleteScope{Mode: model.DeleteRetireProject, Projects: []model.ID{f.project}})

	if f.stateHolds(gone) {
		t.Fatal("the deleted project's payloads are still in the control state")
	}
	if f.snapshotHolds(gone) {
		t.Fatal("the deleted project's payloads are still in the control snapshot")
	}
	if hits := controlDBHits(t, f.dir, gone); len(hits) != 0 {
		t.Fatalf("the deleted project's payloads are still in %v", hits)
	}
	// Another project's payloads are untouched.
	if !f.stateHolds(kept) || !f.snapshotHolds(kept) {
		t.Fatal("the deletion erased a project it does not cover")
	}
	// What stays is evidence: identities, phases and digests, never payloads. The
	// unreleased output stays pending and is obsolete at read: its consumer
	// suppresses it with its own reason, and has no payload left to release.
	if o := f.output(deleted, output); o.ID != output || o.Phase != control.RulePhasePending || !o.Obsolete || !dropped(o.Payload) || o.Digest == (model.Hash{}) {
		t.Errorf("the deleted project's output must stay as an obsolete, payload-free record: %+v", o)
	}
	if kept := f.output(other, otherOutput); kept.Phase != control.RulePhasePending || kept.Obsolete || dropped(kept.Payload) {
		t.Errorf("another project's output was touched: %+v", kept)
	}
	if err := f.store.View(f.ctx, func(st control.State) error {
		var d control.DeliveryRecord
		if err := json.Unmarshal(st.DeliveryBooks["delivery:"+delivery.String()], &d); err != nil {
			return err
		}
		if d.ID != delivery || d.Open() || !dropped(d.Body) || d.Digest == (model.Hash{}) {
			t.Errorf("the deleted project's delivery must be settled and body-free: %+v", d)
		}
		var k control.DeliveryRecord
		if err := json.Unmarshal(st.DeliveryBooks["delivery:"+otherDelivery.String()], &k); err != nil || !k.Open() || dropped(k.Body) {
			t.Errorf("another project's delivery was touched: %+v %v", k, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestRetireOrgErasesEveryControlPayload(t *testing.T) {
	f := newEraseFx(t)
	const gone = "CANARYORG0d3b86a7c41e9"
	first, second := f.newSeed(f.project, gone), f.newSeed(f.otherProject, gone)
	first.note, second.note = true, true
	f.seedAll(first, 50)
	f.seedAll(second, 60)
	f.saga(control.DeleteScope{Mode: model.DeleteRetireOrg})
	if f.stateHolds(gone) || f.snapshotHolds(gone) {
		t.Fatal("a retired organization's payloads are still in the control state")
	}
	if hits := controlDBHits(t, f.dir, gone); len(hits) != 0 {
		t.Fatalf("a retired organization's payloads are still in %v", hits)
	}
}

func TestHistoricalRangeErasesCoveredControlPayloadsOnly(t *testing.T) {
	f := newEraseFx(t)
	const covered, other = "CANARYRANGEb86a7c41e9d3", "CANARYLOGSIGNAL5f0aa93c7"
	s := f.newSeed(f.project, covered)
	coveredOutput := f.commitRule(s, 50, model.Metric) // metric evaluated inside the range
	log := f.newSeed(f.project, other)
	logOutput := f.commitRule(log, 50, model.Log) // another signal: not covered
	coveredDelivery := f.commitDelivery(s, 45, 60)
	earlyDelivery := f.commitDelivery(f.newSeed(f.project, "CANARYEARLY1c7de9f0aa53"), 10, 20)   // evidence before the range
	lateDelivery := f.commitDelivery(f.newSeed(f.project, "CANARYLATE9c7de151f0aa"), 5000, 6000) // evidence outside the range
	f.commitCondition(s, 50)
	f.commitIncident(s, 50)
	older := f.newSeed(f.project, "CANARYOLDINC7de1f0aa539c")
	f.commitIncident(older, 10) // an incident whose evidence all predates the range
	olderCondition := f.newSeed(f.project, "CANARYOLDCOND1f0aa93c7de5")
	f.commitCondition(olderCondition, 10) // and a condition

	f.saga(control.DeleteScope{Mode: model.DeleteHistoricalRange, Projects: []model.ID{f.project}, Signals: []model.Kind{model.Metric}, Start: 40, End: 100})

	if f.stateHolds(covered) || f.snapshotHolds(covered) {
		t.Fatal("a covered range's control payloads are still in the control state")
	}
	if hits := controlDBHits(t, f.dir, covered); len(hits) != 0 {
		t.Fatalf("a covered range's control payloads are still in %v", hits)
	}
	for _, kept := range []string{other, "CANARYLATE9c7de151f0aa", "CANARYEARLY1c7de9f0aa53", "CANARYOLDINC7de1f0aa539c", "CANARYOLDCOND1f0aa93c7de5"} {
		if !f.stateHolds(kept) {
			t.Fatalf("a payload outside the predicate was erased: %s", kept)
		}
	}
	if o := f.output(s, coveredOutput); o.Phase != control.RulePhasePending || !o.Obsolete || !dropped(o.Payload) {
		t.Errorf("a covered pending output must be obsolete and payload-free: %+v", o)
	}
	if o := f.output(log, logOutput); o.Phase != control.RulePhasePending || o.Obsolete || dropped(o.Payload) {
		t.Errorf("an uncovered output was touched: %+v", o)
	}
	if err := f.store.View(f.ctx, func(st control.State) error {
		var d control.DeliveryRecord
		if err := json.Unmarshal(st.DeliveryBooks["delivery:"+coveredDelivery.String()], &d); err != nil || !dropped(d.Body) || d.Open() {
			t.Errorf("a covered delivery must be settled and body-free: %+v %v", d, err)
		}
		for _, id := range []model.ID{lateDelivery, earlyDelivery} {
			if err := json.Unmarshal(st.DeliveryBooks["delivery:"+id.String()], &d); err != nil || dropped(d.Body) || !d.Open() {
				t.Errorf("an uncovered delivery was touched: %+v %v", d, err)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestEntityDeletionErasesOutputsThatCannotBeAttributed(t *testing.T) {
	f := newEraseFx(t)
	const replay, metric = "CANARYREPLAY7c41e90d2b86", "CANARYMETRIC51f0aa93c7de"
	rs := f.newSeed(f.project, replay)
	replayOutput := f.commitRule(rs, 50, model.Replay)
	ms := f.newSeed(f.project, metric)
	metricOutput := f.commitRule(ms, 50, model.Metric)
	f.saga(control.DeleteScope{Mode: model.DeleteEntity, Projects: []model.ID{f.project}, Entities: []model.ID{model.NewID()}})
	if f.stateHolds(replay) || f.snapshotHolds(replay) {
		t.Fatal("an output of a deleted entity's signal kind is still in the control state")
	}
	if hits := controlDBHits(t, f.dir, replay); len(hits) != 0 {
		t.Fatalf("an output of a deleted entity's signal kind is still in %v", hits)
	}
	if !f.stateHolds(metric) {
		t.Fatal("an entity deletion erased a metric output")
	}
	if o := f.output(rs, replayOutput); o.Phase != control.RulePhasePending || !o.Obsolete || !dropped(o.Payload) {
		t.Errorf("the replay-signal output must be obsolete and payload-free: %+v", o)
	}
	if o := f.output(ms, metricOutput); o.Phase != control.RulePhasePending || o.Obsolete || dropped(o.Payload) {
		t.Errorf("the metric output was touched: %+v", o)
	}
	// A rule's evaluation payload is attributed to its own outputs and no other
	// rule's: the replay rule's is dropped, the metric rule's stays.
	book := func(s eraseSeed) control.RuleBook {
		b, found, err := f.store.RuleBook(f.ctx, f.adminScope(), s.project, s.rule)
		if err != nil || !found {
			t.Fatalf("book: %v %v", found, err)
		}
		return b
	}
	if rb := book(rs); len(rb.Versions) != 1 || len(rb.Versions[0].Recent) != 0 {
		t.Errorf("the replay rule kept its evaluation payloads: %+v", rb.Versions)
	}
	if mb := book(ms); len(mb.Versions) != 1 || len(mb.Versions[0].Recent) != 1 || dropped(mb.Versions[0].Recent[0].Payload) {
		t.Errorf("the metric rule's evaluation payloads were erased: %+v", mb.Versions)
	}
}

// dropped reports whether a payload was removed from a record (an absent value
// reads back as JSON null).
func dropped(raw json.RawMessage) bool { return len(raw) == 0 || string(raw) == "null" }

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
