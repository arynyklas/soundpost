// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package rules

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"reflect"
	"testing"
	"time"

	"soundpost/internal/auth"
	"soundpost/internal/model"
	"soundpost/internal/query"
	"soundpost/internal/query/profile"
	"soundpost/internal/query/syntax"
	"soundpost/internal/replica"
	"soundpost/profiles"
)

type clockAt model.UnixNano

func (c clockAt) Now() model.UnixNano { return model.UnixNano(c) }

var testLease = replica.FenceToken{Group: model.ID{5}, Term: 2, Revision: 1}

type fakeExec struct {
	calls []query.Request
	fn    func(query.Request) (query.Result, error)
}

func (f *fakeExec) Execute(_ context.Context, _ auth.Scope, req query.Request) (query.Result, error) {
	f.calls = append(f.calls, req)
	return f.fn(req)
}

type fakeStore struct {
	state     State
	committed map[string]Evaluation
}

func newFakeStore() *fakeStore { return &fakeStore{committed: map[string]Evaluation{}} }
func (f *fakeStore) key(v model.Revision, at model.UnixNano) string {
	return fmt.Sprintf("%d/%d", v, at)
}
func (f *fakeStore) Read(context.Context, auth.Scope, model.ID) (State, error) { return f.state, nil }
func (f *fakeStore) ReadEvaluation(_ context.Context, _ auth.Scope, _ model.ID, v model.Revision, at model.UnixNano) (Evaluation, bool, error) {
	ev, ok := f.committed[f.key(v, at)]
	return ev, ok, nil
}
func (f *fakeStore) commit(ev Evaluation) {
	replays, missed := f.state.Replays, f.state.Missed
	f.state = ev.State
	f.state.Replays, f.state.Missed = replays, missed
	f.committed[f.key(ev.Version, ev.At)] = ev
}

type fakeFence struct{ err error }

func (f fakeFence) ValidateFence(context.Context, replica.FenceToken) error { return f.err }

func elem(v float64, pairs ...string) query.VectorElement {
	bits := model.FloatBits(math.Float64bits(v))
	return query.VectorElement{Labels: labels(pairs...), Sample: query.Sample{Float: &bits}}
}

var group9 = []model.Cursor{{Group: model.ID{9}, Index: 40}}

func vectorResult(project model.ID, elems ...query.VectorElement) query.Result {
	return query.Result{Projects: []query.ProjectResult{{ProjectID: project, Value: &query.Value{Type: query.ValueVector, Vector: elems}, Diagnostics: []query.Diagnostic{}, Watermarks: group9, Completeness: query.CompletenessComplete}}}
}

func evaluator(exec *fakeExec, store *fakeStore, now model.UnixNano, options ...Option) *Evaluator {
	return NewEvaluator(exec, store, append([]Option{WithClock(clockAt(now))}, options...)...)
}

func evaluate(t *testing.T, e *Evaluator, rule Rule, atSeconds int64) Evaluation {
	t.Helper()
	ev, err := e.Evaluate(context.Background(), auth.Scope{}, rule, model.UnixNano(atSeconds)*sec, testLease)
	if err != nil {
		t.Fatalf("evaluate at %d: %v", atSeconds, err)
	}
	return ev
}

func code(err error) model.Code {
	var f *model.Fault
	if errors.As(err, &f) {
		return f.Code
	}
	return ""
}

func TestEvaluateRequestShape(t *testing.T) {
	rule := alertRule(0, 0)
	rule.Budget = query.Budget{TimeoutNS: 5_000_000_000}
	store := newFakeStore()
	store.state = State{Org: model.ID{3}, Project: rule.Project, Rule: rule.ID, Version: rule.Version, Definition: rule.Digest(), Series: map[string]SeriesState{}, Cursors: []model.Cursor{{Group: model.ID{9}, Index: 30}}, Applied: &EvaluationRef{At: 0}}
	store.state.Applied = &EvaluationRef{ID: model.ID{1}, At: 60 * sec}
	exec := &fakeExec{fn: func(query.Request) (query.Result, error) { return vectorResult(rule.Project), nil }}
	ev := evaluate(t, evaluator(exec, store, 125*sec), rule, 120)
	if len(exec.calls) != 1 {
		t.Fatalf("%d executions", len(exec.calls))
	}
	req := exec.calls[0]
	if req.AllowPartial {
		t.Fatal("a rule query allowed a partial result")
	}
	if !req.Evaluation.Instant || req.Evaluation.Time != 120*sec || req.Evaluation.Start != 0 || req.Evaluation.End != 0 || req.Evaluation.Step != 0 {
		t.Fatalf("evaluation is not an instant at the scheduled time: %+v", req.Evaluation)
	}
	if req.Language != query.LanguagePromQL || req.Profile != rule.Profile || req.FeatureSet != rule.FeatureSet || req.Expression != rule.Expression ||
		!reflect.DeepEqual(req.Projects, []model.ID{rule.Project}) || req.Budget != rule.Budget {
		t.Fatalf("request %+v", req)
	}
	if !reflect.DeepEqual(req.MinCursors, []model.Cursor{{Group: model.ID{9}, Index: 30}}) {
		t.Fatalf("committed minimum input cursors not required: %+v", req.MinCursors)
	}
	if ev.At != 120*sec || ev.ObservedAt != 125*sec || ev.Mode != ModeLive || !reflect.DeepEqual(ev.Cursors, group9) || ev.State.Revision != 1 {
		t.Fatalf("evaluation %+v", ev)
	}
	// The next evaluation must read at least as far as this one did.
	if !reflect.DeepEqual(ev.State.Cursors, []model.Cursor{{Group: model.ID{9}, Index: 40}}) {
		t.Fatalf("state cursors %+v", ev.State.Cursors)
	}
}

// The language comes from the pinned profile, and the evaluation names the signal
// the expression reads.
func TestEvaluateNamesLanguageAndSignal(t *testing.T) {
	prom := alertRule(0, 0)
	logs := alertRule(0, 0)
	logs.Profile, logs.Expression = "logql-loki-3.5.2", `sum(count_over_time({app="web"}[5m]))`
	for _, c := range []struct {
		rule     Rule
		language string
		signal   model.Kind
	}{{prom, query.LanguagePromQL, model.Metric}, {logs, query.LanguageLogQL, model.Log}} {
		exec := &fakeExec{fn: func(query.Request) (query.Result, error) { return vectorResult(c.rule.Project), nil }}
		ev := evaluate(t, evaluator(exec, newFakeStore(), 65*sec), c.rule, 60)
		if exec.calls[0].Language != c.language || ev.Signal != c.signal {
			t.Errorf("%s: language %q signal %q", c.rule.Profile, exec.calls[0].Language, ev.Signal)
		}
	}
}

// Presence is the signal, not the number: a series whose sample is 0 (or NaN) is
// a true series.
func TestAlertMembershipNotNumericTruthiness(t *testing.T) {
	rule := alertRule(0, 0)
	store := newFakeStore()
	exec := &fakeExec{fn: func(query.Request) (query.Result, error) {
		return vectorResult(rule.Project, elem(0, "job", "zero"), elem(math.NaN(), "job", "nan"), elem(1, "job", "one")), nil
	}}
	e := evaluator(exec, store, 65*sec)
	ev := evaluate(t, e, rule, 60)
	if len(ev.State.Series) != 3 || len(ev.Members) != 3 || len(ev.Conditions) != 3 {
		t.Fatalf("series=%d members=%d conditions=%d", len(ev.State.Series), len(ev.Members), len(ev.Conditions))
	}
	for key, st := range ev.State.Series {
		if st.Phase != PhaseFiring {
			t.Fatalf("%s is %s", key, st.Phase)
		}
	}
	// Absence from a complete result is false: all three recover.
	store.commit(ev)
	exec.fn = func(query.Request) (query.Result, error) { return vectorResult(rule.Project), nil }
	ev = evaluate(t, evaluator(exec, store, 125*sec), rule, 120)
	if len(ev.State.Series) != 0 || len(ev.Conditions) != 3 || ev.Conditions[0].Event.Status != "resolved" {
		t.Fatalf("recovery on an actual empty vector: %+v", ev.State.Series)
	}
}

// A failed or incomplete read is not an empty vector: it is unknown (or error by
// policy), and it recovers nothing.
func TestUnknownInputNeverRecovers(t *testing.T) {
	cases := []struct {
		name    string
		err     error
		result  *query.Result
		policy  MissingData
		outcome Outcome
		reason  string
	}{
		{name: "timeout", err: model.Fail(model.Timeout), outcome: OutcomeUnknown, reason: ReasonTimeout},
		{name: "missing shard", err: model.Fail(model.Unavailable), outcome: OutcomeUnknown, reason: ReasonUnavailable},
		{name: "stale producer cut", err: model.Fail(model.Stale), outcome: OutcomeUnknown, reason: ReasonStaleInput},
		{name: "unclassified dependency failure", err: errors.New("boom"), outcome: OutcomeUnknown, reason: ReasonUnavailable},
		{name: "missing shard under error policy", err: model.Fail(model.Unavailable), policy: MissingError, outcome: OutcomeError, reason: ReasonUnavailable},
		{name: "budget exceeded", err: model.Fail(model.Quota), outcome: OutcomeError, reason: ReasonBudget},
		{name: "language error", err: &syntax.LanguageError{Code: "x", Category: "execution", SafeMessage: "x"}, outcome: OutcomeError, reason: ReasonQueryError},
		{name: "partial result", result: &query.Result{Projects: []query.ProjectResult{{ProjectID: model.ID{2}, Value: &query.Value{Type: query.ValueVector}, Completeness: query.CompletenessPartial}}}, outcome: OutcomeUnknown, reason: ReasonIncompleteResult},
		{name: "stale result", result: &query.Result{Projects: []query.ProjectResult{{ProjectID: model.ID{2}, Value: &query.Value{Type: query.ValueVector}, Completeness: query.CompletenessStale}}}, outcome: OutcomeUnknown, reason: ReasonIncompleteResult},
		{name: "failed project", result: &query.Result{Projects: []query.ProjectResult{{ProjectID: model.ID{2}, Completeness: query.CompletenessPartial, Failure: &query.Failure{Code: "unavailable"}}}}, outcome: OutcomeUnknown, reason: ReasonIncompleteResult},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rule := alertRule(0, 0)
			rule.MissingData = c.policy
			store := newFakeStore()
			good := &fakeExec{fn: func(query.Request) (query.Result, error) {
				return vectorResult(rule.Project, elem(1, "job", "api")), nil
			}}
			first := evaluate(t, evaluator(good, store, 65*sec), rule, 60)
			store.commit(first)
			if first.State.Series[seriesKey(labels("job", "api"))].Phase != PhaseFiring {
				t.Fatal("fixture series is not firing")
			}
			bad := &fakeExec{fn: func(query.Request) (query.Result, error) {
				if c.result != nil {
					return *c.result, nil
				}
				return query.Result{}, c.err
			}}
			ev := evaluate(t, evaluator(bad, store, 125*sec), rule, 120)
			if ev.Outcome != c.outcome || ev.Reason != c.reason {
				t.Fatalf("outcome %s/%s, want %s/%s", ev.Outcome, ev.Reason, c.outcome, c.reason)
			}
			if len(ev.Conditions) != 0 || len(ev.State.Series) != 1 || ev.State.Series[seriesKey(labels("job", "api"))].Phase != PhaseFiring {
				t.Fatalf("unknown input changed a condition: %+v %+v", ev.Conditions, ev.State.Series)
			}
			wantHealth := HealthUnknown
			if c.outcome == OutcomeError {
				wantHealth = HealthError
			}
			if ev.State.Health != wantHealth || !reflect.DeepEqual(ev.State.Cursors, first.State.Cursors) || ev.State.Revision != 2 {
				t.Fatalf("state %+v", ev.State)
			}
			if bad.calls[0].AllowPartial {
				t.Fatal("a rule query allowed a partial result")
			}
		})
	}
}

// Authorization and cancellation are failures of the caller, not evaluations.
func TestAuthorizationFailureIsNotAnEvaluation(t *testing.T) {
	rule := alertRule(0, 0)
	for _, c := range []model.Code{model.Forbidden, model.NotFound, model.Unauthenticated, model.Cancelled} {
		store := newFakeStore()
		exec := &fakeExec{fn: func(query.Request) (query.Result, error) { return query.Result{}, model.Fail(c) }}
		if _, err := evaluator(exec, store, 65*sec).Evaluate(context.Background(), auth.Scope{}, rule, 60*sec, testLease); code(err) != c {
			t.Fatalf("%s became %v", c, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	exec := &fakeExec{fn: func(query.Request) (query.Result, error) { return query.Result{}, model.Fail(model.Timeout) }}
	if _, err := evaluator(exec, newFakeStore(), 65*sec).Evaluate(ctx, auth.Scope{}, rule, 60*sec, testLease); err == nil {
		t.Fatal("a cancelled caller context produced an evaluation")
	}
}

func TestResultKindsOtherThanVectorAreErrors(t *testing.T) {
	rule := alertRule(0, 0)
	for _, value := range []query.Value{{Type: query.ValueScalar}, {Type: query.ValueMatrix}, {Type: query.ValueStreams}, {Type: query.ValueString}} {
		v := value
		exec := &fakeExec{fn: func(query.Request) (query.Result, error) {
			return query.Result{Projects: []query.ProjectResult{{ProjectID: rule.Project, Value: &v, Completeness: query.CompletenessComplete}}}, nil
		}}
		ev := evaluate(t, evaluator(exec, newFakeStore(), 65*sec), rule, 60)
		if ev.Outcome != OutcomeError || ev.Reason != ReasonResultKind || ev.State.Health != HealthError {
			t.Fatalf("%s: %s/%s", v.Type, ev.Outcome, ev.Reason)
		}
	}
	// A result for another project (or none, or two) is not this rule's result.
	for _, res := range []query.Result{{}, vectorResult(model.ID{77})} {
		r := res
		exec := &fakeExec{fn: func(query.Request) (query.Result, error) { return r, nil }}
		if ev := evaluate(t, evaluator(exec, newFakeStore(), 65*sec), rule, 60); ev.Outcome != OutcomeError {
			t.Fatalf("foreign result accepted: %s", ev.Outcome)
		}
	}
}

func testRegistry(t *testing.T) (profile.Registry, func(id string) string) {
	t.Helper()
	files, err := profiles.Query()
	if err != nil {
		t.Fatal(err)
	}
	reg, err := profile.Load(files)
	if err != nil {
		t.Fatal(err)
	}
	return reg, func(id string) string {
		raw, err := fs.ReadFile(files, id+".json")
		if err != nil {
			t.Fatal(err)
		}
		var p struct {
			FeatureSets []struct {
				ID string `json:"id"`
			} `json:"feature_sets"`
		}
		if json.Unmarshal(raw, &p) != nil || len(p.FeatureSets) == 0 {
			t.Fatal("profile has no feature set")
		}
		return p.FeatureSets[0].ID
	}
}

// Saving a rule parses and type-checks it under the pinned profile and refuses
// any result kind but an instant vector.
func TestRuleCheckRequiresInstantVector(t *testing.T) {
	reg, featureSet := testRegistry(t)
	prom, logql := "promql-prometheus-3.13.5", "logql-loki-3.5.2"
	base := func(profileID, expression string) Rule {
		r := alertRule(0, 0)
		r.Profile, r.FeatureSet, r.Expression = profileID, "x", expression
		if profileID == prom || profileID == logql {
			r.FeatureSet = featureSet(profileID)
		}
		return r
	}
	for _, c := range []struct {
		name string
		rule Rule
		ok   bool
	}{
		{"vector selector", base(prom, `up{job="api"}`), true},
		{"aggregation", base(prom, `sum by (job) (rate(http_requests_total[5m])) > 1`), true},
		{"scalar", base(prom, `1`), false},
		{"string", base(prom, `"x"`), false},
		{"range vector", base(prom, `up[5m]`), false},
		{"syntax error", base(prom, `sum(`), false},
		{"unknown profile", base("promql-prometheus-9.9.9", `up`), false},
		{"unknown feature set", func() Rule { r := base(prom, `up`); r.FeatureSet = "no-such-set"; return r }(), false},
		{"logql metric vector", base(logql, `sum(count_over_time({app="web"}[5m]))`), true},
		{"logql log streams", base(logql, `{app="web"}`), false},
		{"logql range aggregation is a vector", base(logql, `count_over_time({app="web"}[5m])`), true},
		{"logql scalar", base(logql, `1`), false},
	} {
		err := c.rule.Check(reg)
		if c.ok && err != nil {
			t.Errorf("%s: %v", c.name, err)
		}
		if !c.ok && code(err) != model.Invalid {
			t.Errorf("%s accepted or wrong error: %v", c.name, err)
		}
	}
	if code(alertRule(0, 0).Check(nil)) != model.Invalid {
		t.Error("check without a registry")
	}
}

func TestRuleValidate(t *testing.T) {
	ok := alertRule(time.Minute, time.Minute)
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	rec := Rule{ID: model.ID{1}, Project: model.ID{2}, Version: 1, Kind: KindRecording, Profile: "promql-prometheus-3.13.5", FeatureSet: "fs", Expression: "up", Interval: time.Minute, RecordName: "job:up:sum", Labels: labels("env", "prod")}
	if err := rec.Validate(); err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(r *Rule){
		"zero id":              func(r *Rule) { r.ID = model.ID{} },
		"zero version":         func(r *Rule) { r.Version = 0 },
		"unknown kind":         func(r *Rule) { r.Kind = "notify" },
		"sub-second interval":  func(r *Rule) { r.Interval = 500 * time.Millisecond },
		"fractional interval":  func(r *Rule) { r.Interval = 1500 * time.Millisecond },
		"negative for":         func(r *Rule) { r.For = -time.Second },
		"negative hold":        func(r *Rule) { r.RecoveryHold = -time.Second },
		"huge interval":        func(r *Rule) { r.Interval = 48 * time.Hour },
		"unknown missing data": func(r *Rule) { r.MissingData = "ignore" },
		"no language":          func(r *Rule) { r.Profile = "sql-1" },
		"empty expression":     func(r *Rule) { r.Expression = "" },
		"alert without sev":    func(r *Rule) { r.Severity = "" },
		"alert with name":      func(r *Rule) { r.RecordName = "x" },
		"alert with labels":    func(r *Rule) { r.Labels = labels("a", "b") },
	}
	for name, mutate := range mutations {
		r := ok
		mutate(&r)
		if code(r.Validate()) != model.Invalid {
			t.Errorf("%s accepted", name)
		}
	}
	recMutations := map[string]func(r *Rule){
		"no record name":    func(r *Rule) { r.RecordName = "" },
		"bad record name":   func(r *Rule) { r.RecordName = "9up" },
		"name label":        func(r *Rule) { r.Labels = labels("__name__", "x") },
		"bad label name":    func(r *Rule) { r.Labels = labels("a-b", "x") },
		"unsorted labels":   func(r *Rule) { r.Labels = labels("b", "1", "a", "2") },
		"duplicate labels":  func(r *Rule) { r.Labels = labels("a", "1", "a", "2") },
		"recording for":     func(r *Rule) { r.For = time.Second },
		"recording hold":    func(r *Rule) { r.RecoveryHold = time.Second },
		"recording sev":     func(r *Rule) { r.Severity = "page" },
		"huge label value":  func(r *Rule) { r.Labels = labels("a", string(make([]byte, 2000))) },
		"recording no kind": func(r *Rule) { r.Kind = "" },
	}
	for name, mutate := range recMutations {
		r := rec
		mutate(&r)
		if code(r.Validate()) != model.Invalid {
			t.Errorf("recording %s accepted", name)
		}
	}
	// The definition digest moves with every semantic field.
	a, b := ok, ok
	b.Expression = "up == 0"
	if a.Digest() == b.Digest() || a.Digest() != ok.Digest() {
		t.Fatal("rule digest")
	}
}

func producer() ProducerIdentity {
	return ProducerIdentity{Source: model.ID{0xa1}, Producer: model.ID{0xa2}, PolicyRevision: 1, Resource: model.Resource{Service: model.ID{1}, Environment: model.ID{2}, Build: model.ID{3}, Instance: "rules-1", Labels: model.Labels{}}}
}

func recordingRule() Rule {
	return Rule{ID: model.ID{1}, Project: model.ID{2}, Version: 1, Kind: KindRecording, Profile: "promql-prometheus-3.13.5", FeatureSet: "fs", Expression: "up", Interval: time.Minute, RecordName: "job:up:sum", Labels: labels("env", "prod", "region", "eu")}
}

func intHistogram() *model.NativeHistogram {
	return &model.NativeHistogram{Integer: &model.IntegerHistogram{Flavor: "counter", Schema: 0, ZeroThreshold: model.FloatBits(math.Float64bits(0.001)), Sum: model.FloatBits(math.Float64bits(2)), Count: 2, PositiveSpans: []model.HistogramSpan{{Offset: 0, Length: 1}}, NegativeSpans: []model.HistogramSpan{}, PositiveBuckets: []model.DeltaBucket{2}, NegativeBuckets: []model.DeltaBucket{}, ResetHint: "unknown"}}
}

func floatHistogram() *model.NativeHistogram {
	f := func(v float64) model.FloatBits { return model.FloatBits(math.Float64bits(v)) }
	return &model.NativeHistogram{Float: &model.FloatHistogram{Flavor: "gauge", Schema: 0, ZeroThreshold: f(0.001), Sum: f(2.5), Count: f(2.5), ZeroCount: f(0), PositiveSpans: []model.HistogramSpan{{Offset: 0, Length: 1}}, NegativeSpans: []model.HistogramSpan{}, PositiveBuckets: []model.FloatBits{f(2.5)}, NegativeBuckets: []model.FloatBits{}, ResetHint: "gauge"}}
}

// Recording rules accept float, integer-histogram and float-histogram samples,
// replace the name, apply the configured labels over the result's, and keep the
// exact bits.
func TestRecordingRuleOutputs(t *testing.T) {
	rule := recordingRule()
	nan := model.FloatBits(0x7ff8000000000001) // a non-canonical ordinary NaN
	negZero := model.FloatBits(1 << 63)
	vector := []query.VectorElement{
		{Labels: labels("__name__", "up", "job", "a", "env", "dev"), Sample: query.Sample{Float: &nan}},
		{Labels: labels("__name__", "up", "job", "b"), Sample: query.Sample{Float: &negZero}},
		{Labels: labels("__name__", "up", "job", "c"), Sample: query.Sample{Histogram: intHistogram()}},
		{Labels: labels("job", "d"), Sample: query.Sample{Histogram: floatHistogram()}},
	}
	exec := &fakeExec{fn: func(query.Request) (query.Result, error) { return vectorResult(rule.Project, vector...), nil }}
	ev := evaluate(t, evaluator(exec, newFakeStore(), 65*sec, WithProducer(producer())), rule, 60)
	if ev.Outcome != OutcomeComplete || len(ev.Recorded) != 4 || ev.Producer == nil || ev.Producer.Source != (model.ID{0xa1}) {
		t.Fatalf("outcome %s/%s recorded=%d", ev.Outcome, ev.Reason, len(ev.Recorded))
	}
	byJob := map[string]Recorded{}
	for _, r := range ev.Recorded {
		for _, l := range r.Labels {
			if l.Name == "job" {
				byJob[l.Value] = r
			}
		}
		if got := r.Labels; len(got) != 3 || got[0].Name != "env" || got[0].Value != "prod" || got[1].Name != "job" || got[2].Name != "region" || got[2].Value != "eu" {
			t.Fatalf("labels %+v: the configured labels must replace and extend, the name label must go", got)
		}
	}
	if byJob["a"].SampleKind != "float" || *byJob["a"].Value != nan || *byJob["b"].Value != negZero {
		t.Fatalf("float bits not preserved: %+v %+v", byJob["a"], byJob["b"])
	}
	if byJob["c"].SampleKind != "integer_histogram" || byJob["c"].Histogram.Integer == nil || byJob["d"].SampleKind != "float_histogram" || byJob["d"].Histogram.Float == nil {
		t.Fatalf("histogram kinds: %+v %+v", byJob["c"], byJob["d"])
	}
	if len(ev.Recording) != len(distinctSlots(ev.Recording)) || len(ev.Recording) == 0 {
		t.Fatalf("recording intents %d", len(ev.Recording))
	}
	total := 0
	for _, intent := range ev.Recording {
		if intent.ID != intent.Batch.ID || !reflect.DeepEqual(intent.Inputs, group9) {
			t.Fatalf("intent %+v", intent)
		}
		for _, r := range intent.Batch.Records {
			total++
			if r.Payload.Metric.Name != "job:up:sum" || r.ObservedAt != 60*sec {
				t.Fatalf("record %+v", r)
			}
		}
	}
	if total != 4 || len(ev.Conditions) != 0 {
		t.Fatalf("records %d conditions %d", total, len(ev.Conditions))
	}
}

func distinctSlots(in []RecordingIntent) map[uint16]bool {
	out := map[uint16]bool{}
	for _, i := range in {
		out[i.Slot] = true
	}
	return out
}

// Two source series that become one output series are rejected before any
// effect exists; so is a sample that is no sample.
func TestRecordingRejectsBeforeAnyEffect(t *testing.T) {
	rule := recordingRule()
	stale := model.FloatBits(0x7ff0000000000002)
	bothKinds := query.Sample{Float: &stale, Histogram: intHistogram()}
	neither := query.Sample{}
	badHistogram := query.Sample{Histogram: &model.NativeHistogram{}}
	one := model.FloatBits(math.Float64bits(1))
	for name, vector := range map[string][]query.VectorElement{
		"collapsing names": {
			{Labels: labels("__name__", "a", "job", "x"), Sample: query.Sample{Float: &one}},
			{Labels: labels("__name__", "b", "job", "x"), Sample: query.Sample{Float: &one}},
		},
		"configured label collapses series": {
			{Labels: labels("__name__", "a", "env", "dev"), Sample: query.Sample{Float: &one}},
			{Labels: labels("__name__", "a", "env", "qa"), Sample: query.Sample{Float: &one}},
		},
		"stale marker":        {{Labels: labels("job", "x"), Sample: query.Sample{Float: &stale}}},
		"both kinds":          {{Labels: labels("job", "x"), Sample: bothKinds}},
		"no value":            {{Labels: labels("job", "x"), Sample: neither}},
		"empty histogram":     {{Labels: labels("job", "x"), Sample: badHistogram}},
		"valid then bad":      {{Labels: labels("job", "a"), Sample: query.Sample{Float: &one}}, {Labels: labels("job", "b"), Sample: neither}},
		"repeated label name": {{Labels: model.Labels{{Name: "a", Value: "1"}, {Name: "a", Value: "2"}}, Sample: query.Sample{Float: &one}}},
	} {
		v := vector
		exec := &fakeExec{fn: func(query.Request) (query.Result, error) { return vectorResult(rule.Project, v...), nil }}
		ev := evaluate(t, evaluator(exec, newFakeStore(), 65*sec, WithProducer(producer())), rule, 60)
		if ev.Outcome != OutcomeError || len(ev.Recorded) != 0 || len(ev.Recording) != 0 || len(ev.Conditions) != 0 {
			t.Errorf("%s: outcome %s/%s recorded=%d intents=%d", name, ev.Outcome, ev.Reason, len(ev.Recorded), len(ev.Recording))
		}
		if ev.State.Health != HealthError {
			t.Errorf("%s: health %s", name, ev.State.Health)
		}
	}
	// A recording rule cannot even be evaluated without its producer identity.
	exec := &fakeExec{fn: func(query.Request) (query.Result, error) { return vectorResult(rule.Project), nil }}
	if _, err := evaluator(exec, newFakeStore(), 65*sec).Evaluate(context.Background(), auth.Scope{}, rule, 60*sec, testLease); code(err) != model.Invalid || len(exec.calls) != 0 {
		t.Fatalf("recording rule without a producer: %v (%d queries)", err, len(exec.calls))
	}
}

// An alert rule's vector with a repeated label set is an error, never two members.
func TestAlertDuplicateSeriesIsAnError(t *testing.T) {
	rule := alertRule(0, 0)
	exec := &fakeExec{fn: func(query.Request) (query.Result, error) {
		return vectorResult(rule.Project, elem(1, "job", "a"), elem(2, "job", "a")), nil
	}}
	ev := evaluate(t, evaluator(exec, newFakeStore(), 65*sec), rule, 60)
	if ev.Outcome != OutcomeError || ev.Reason != ReasonDuplicateSeries || len(ev.Conditions) != 0 {
		t.Fatalf("%s/%s", ev.Outcome, ev.Reason)
	}
}

// Batches are a pure function of the evaluation: byte-identical on every call,
// one canonical-owner slot each, at most 512 records, distinct for distinct
// scheduled times, and every record's own owner slot is its batch's slot.
func TestRecordingBatchesAreDeterministicAndPartitioned(t *testing.T) {
	rule := recordingRule()
	p := producer()
	one := model.FloatBits(math.Float64bits(1))
	ev := Evaluation{Org: model.ID{3}, Project: rule.Project, Rule: rule.ID, Version: 1, At: 60 * sec, Kind: KindRecording, Outcome: OutcomeComplete, Producer: &p}
	for i := range 40000 {
		ev.Recorded = append(ev.Recorded, Recorded{Labels: labels("env", "prod", "n", fmt.Sprint(i)), SampleKind: "float", Value: &one})
	}
	batches, err := RecordingBatches(ev, rule)
	if err != nil {
		t.Fatal(err)
	}
	again, err := RecordingBatches(ev, rule)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(batches)
	b, _ := json.Marshal(again)
	if string(a) != string(b) {
		t.Fatal("recording batches are not deterministic")
	}
	ids := map[model.ID]bool{}
	perSlot := map[uint16]int{}
	records := map[model.ID]bool{}
	total := 0
	for _, batch := range batches {
		if ids[batch.ID] || batch.Version != 1 || batch.Source != p.Source || batch.Producer != p.Producer || batch.PolicyRevision != p.PolicyRevision || batch.Project != rule.Project {
			t.Fatalf("batch identity %+v", batch)
		}
		ids[batch.ID] = true
		if len(batch.Records) == 0 || len(batch.Records) > 512 {
			t.Fatalf("batch of %d records", len(batch.Records))
		}
		perSlot[batch.RouteSlot] += len(batch.Records)
		for _, r := range batch.Records {
			slot, err := model.OwnerSlot(ev.Org, ev.Project, p.Source, p.Producer, r)
			if err != nil || slot != batch.RouteSlot || records[r.ID] {
				t.Fatalf("record in slot %d, owner %d (%v), duplicate id %v", batch.RouteSlot, slot, err, records[r.ID])
			}
			records[r.ID] = true
			total++
		}
	}
	if total != 40000 || len(perSlot) != 64 || len(batches) <= 64 {
		t.Fatalf("records %d slots %d batches %d: expected all 64 slots and 512-record chunking", total, len(perSlot), len(batches))
	}
	later := ev
	later.At = 120 * sec
	other, err := RecordingBatches(later, rule)
	if err != nil {
		t.Fatal(err)
	}
	for _, batch := range other {
		if ids[batch.ID] {
			t.Fatal("two scheduled times share a batch identity")
		}
	}
	// Preconditions.
	bad := ev
	bad.Producer = nil
	if _, err = RecordingBatches(bad, rule); code(err) != model.Invalid {
		t.Fatalf("no producer: %v", err)
	}
	bad = ev
	bad.Outcome = OutcomeUnknown
	if _, err = RecordingBatches(bad, rule); code(err) != model.Invalid {
		t.Fatalf("incomplete evaluation produced batches: %v", err)
	}
	if _, err = RecordingBatches(ev, alertRule(0, 0)); code(err) != model.Invalid {
		t.Fatalf("alert rule produced batches: %v", err)
	}
}

// A committed (rule version, at) is returned unchanged and nothing is queried;
// the fence is checked first; a reused version with another definition is refused.
func TestEvaluateReturnsCommittedEvaluationVerbatim(t *testing.T) {
	rule := alertRule(0, 0)
	store := newFakeStore()
	exec := &fakeExec{fn: func(query.Request) (query.Result, error) { return vectorResult(rule.Project, elem(1, "job", "a")), nil }}
	first := evaluate(t, evaluator(exec, store, 65*sec), rule, 60)
	store.commit(first)
	// Much later, with different data: the committed evaluation, observation and all.
	exec.fn = func(query.Request) (query.Result, error) { return vectorResult(rule.Project), nil }
	late := evaluator(exec, store, 10_000*sec)
	got := evaluate(t, late, rule, 60)
	if !reflect.DeepEqual(got, first) || got.ObservedAt != 65*sec || len(exec.calls) != 1 {
		t.Fatalf("committed evaluation changed or recomputed (%d executions): %+v", len(exec.calls), got)
	}
	// Stale lease: rejected before anything is read or computed.
	stale := evaluator(exec, store, 10_000*sec, WithFencer(fakeFence{err: replica.ErrStale}))
	if _, err := stale.Evaluate(context.Background(), auth.Scope{}, rule, 60*sec, testLease); code(err) != model.Stale {
		t.Fatalf("stale lease: %v", err)
	}
	if _, err := evaluator(exec, store, 10_000*sec, WithFencer(fakeFence{err: replica.ErrUnavailable})).Evaluate(context.Background(), auth.Scope{}, rule, 60*sec, testLease); code(err) != model.Unavailable {
		t.Fatalf("unreachable quorum: %v", err)
	}
	changed := rule
	changed.Expression = "up == 0"
	if _, err := late.Evaluate(context.Background(), auth.Scope{}, changed, 60*sec, testLease); code(err) != model.Conflict {
		t.Fatalf("a committed version evaluated under another definition: %v", err)
	}
	// Same for the next time point.
	if _, err := late.Evaluate(context.Background(), auth.Scope{}, changed, 120*sec, testLease); code(err) != model.Conflict {
		t.Fatalf("state of another definition reused: %v", err)
	}
}

func TestEvaluateTimeAndVersionRules(t *testing.T) {
	rule := alertRule(120*time.Second, 0)
	exec := &fakeExec{fn: func(query.Request) (query.Result, error) { return vectorResult(rule.Project, elem(1, "job", "a")), nil }}
	store := newFakeStore()
	e := evaluator(exec, store, 200*sec)
	for name, at := range map[string]int64{"off the grid": 61, "negative": -60} {
		if _, err := e.Evaluate(context.Background(), auth.Scope{}, rule, model.UnixNano(at)*sec, testLease); code(err) != model.Invalid {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := e.Evaluate(context.Background(), auth.Scope{}, rule, 240*sec, testLease); code(err) != model.Invalid {
		t.Errorf("an evaluation in the future: %v", err)
	}
	if _, err := e.Evaluate(context.Background(), auth.Scope{}, rule, 60*sec, replica.FenceToken{}); code(err) != model.Invalid {
		t.Errorf("zero lease: %v", err)
	}
	first := evaluate(t, e, rule, 60)
	store.commit(first)
	// Not after the last applied and not committed: out of order.
	store.state.Applied = &EvaluationRef{ID: model.ID{1}, At: 180 * sec}
	if _, err := e.Evaluate(context.Background(), auth.Scope{}, rule, 120*sec, testLease); code(err) != model.Stale {
		t.Errorf("evaluating behind the applied state: %v", err)
	}
	store.state.Applied = first.State.Applied
	// A newer committed version supersedes this one.
	newer := rule
	newer.Version = 2
	second := evaluate(t, e, newer, 120)
	store.commit(second)
	if _, err := e.Evaluate(context.Background(), auth.Scope{}, rule, 180*sec, testLease); code(err) != model.Stale {
		t.Errorf("a superseded version evaluated: %v", err)
	}
	// The new version started fresh: its first firing waits out its own for, even
	// though the series had been present since 60 under version 1.
	if got := second.State.Series[seriesKey(labels("job", "a"))]; got.Phase != PhasePending || got.Since != 120*sec || second.State.Revision != 1 || second.State.Version != 2 {
		t.Fatalf("a new version did not start fresh: %+v", second.State)
	}
}

func TestEvaluationModeFollowsScheduledTimeAndCommittedReplay(t *testing.T) {
	rule := alertRule(0, 0)
	exec := &fakeExec{fn: func(query.Request) (query.Result, error) { return vectorResult(rule.Project, elem(1, "job", "a")), nil }}
	for _, c := range []struct {
		name   string
		now    model.UnixNano
		replay []ReplayWindow
		mode   Mode
		notify bool
	}{
		{"on time", 119 * sec, nil, ModeLive, true},
		{"exactly one interval late", 120 * sec, nil, ModeBackfill, false},
		{"late", 1000 * sec, nil, ModeBackfill, false},
		{"late inside a committed replay window", 1000 * sec, []ReplayWindow{{From: 60 * sec, To: 60 * sec}}, ModeReplay, true},
		{"late outside a committed replay window", 1000 * sec, []ReplayWindow{{From: 120 * sec, To: 600 * sec}}, ModeBackfill, false},
		{"on time inside a window is still live", 119 * sec, []ReplayWindow{{From: 0, To: 600 * sec}}, ModeLive, true},
	} {
		store := newFakeStore()
		store.state.Replays = c.replay
		ev := evaluate(t, evaluator(exec, store, c.now), rule, 60)
		if ev.Mode != c.mode || len(ev.Conditions) != 1 || ev.Conditions[0].Notify != c.notify || ev.Conditions[0].Mode != c.mode {
			t.Errorf("%s: mode %s conditions %+v", c.name, ev.Mode, ev.Conditions)
		}
	}
}

type fakeEvidence struct {
	status Evidence
	err    error
	from   model.UnixNano
	to     model.UnixNano
}

func (f *fakeEvidence) Check(_ context.Context, _ auth.Scope, _ model.ID, from, to model.UnixNano) (Evidence, error) {
	f.from, f.to = from, to
	return f.status, f.err
}

// Evidence of an incomplete source blocks recovery even when the query itself
// answered completely, and an evidence source that cannot answer is not clean.
func TestIncompleteEvidenceBlocksRecovery(t *testing.T) {
	rule := alertRule(60*time.Second, 120*time.Second)
	series := seriesKey(labels("job", "a"))
	for _, c := range []struct {
		name   string
		ev     *fakeEvidence
		reason string
		fatal  model.Code
		blocks bool
	}{
		{"clean", &fakeEvidence{}, "", "", false},
		{"declared gap", &fakeEvidence{status: Evidence{Incomplete: true, Reason: ReasonEvidenceGap}}, ReasonEvidenceGap, "", true},
		{"stale producer", &fakeEvidence{status: Evidence{Incomplete: true, Reason: ReasonStaleProducer}}, ReasonStaleProducer, "", true},
		{"unreasoned incomplete", &fakeEvidence{status: Evidence{Incomplete: true}}, ReasonEvidenceGap, "", true},
		{"source unavailable", &fakeEvidence{err: model.Fail(model.Unavailable)}, ReasonUnavailable, "", true},
		{"source forbidden", &fakeEvidence{err: model.Fail(model.Forbidden)}, "", model.Forbidden, false},
	} {
		store := newFakeStore()
		store.state = State{Org: model.ID{3}, Project: rule.Project, Rule: rule.ID, Version: 1, Definition: rule.Digest(), Revision: 1, Applied: &EvaluationRef{ID: model.ID{1}, At: 60 * sec},
			Series: map[string]SeriesState{series: {Labels: labels("job", "a"), Phase: PhaseFiring, Since: 0}}, Cursors: []model.Cursor{}, Health: HealthOK}
		exec := &fakeExec{fn: func(query.Request) (query.Result, error) { return vectorResult(rule.Project), nil }}
		e := evaluator(exec, store, 125*sec, WithEvidence(c.ev))
		ev, err := e.Evaluate(context.Background(), auth.Scope{}, rule, 120*sec, testLease)
		if c.fatal != "" {
			if code(err) != c.fatal {
				t.Errorf("%s: %v", c.name, err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		// Hold is 120s: a first complete false moves firing to recovering, not
		// inactive; with blocked evidence it must not even do that.
		wantPhase := PhaseRecovering
		if c.blocks {
			wantPhase = PhaseFiring
		}
		if got := ev.State.Series[series].Phase; got != wantPhase || ev.RecoveryBlocked != c.blocks || ev.Reason != c.reason {
			t.Errorf("%s: phase %s blocked=%v reason=%q", c.name, got, ev.RecoveryBlocked, ev.Reason)
		}
		if c.blocks && ev.State.Health != HealthUnknown {
			t.Errorf("%s: health %s", c.name, ev.State.Health)
		}
		// The decision window the source is asked about covers for + hold + interval.
		if want := 120*sec - model.UnixNano(rule.For+rule.RecoveryHold+rule.Interval); c.ev.from != want || c.ev.to != 120*sec {
			t.Errorf("%s: evidence window [%d, %d]", c.name, c.ev.from, c.ev.to)
		}
	}
	// An unknown result is not asked about evidence at all.
	ev := &fakeEvidence{}
	exec := &fakeExec{fn: func(query.Request) (query.Result, error) { return query.Result{}, model.Fail(model.Timeout) }}
	evaluate(t, evaluator(exec, newFakeStore(), 65*sec, WithEvidence(ev)), rule, 60)
	if ev.to != 0 {
		t.Error("evidence consulted for an evaluation that had no answer")
	}
}

func TestPlanGrid(t *testing.T) {
	rule := alertRule(0, 0) // 60s grid
	applied := func(at int64) State {
		return State{Version: 1, Applied: &EvaluationRef{At: model.UnixNano(at) * sec}}
	}
	at := func(seconds ...int64) []model.UnixNano {
		out := make([]model.UnixNano, len(seconds))
		for i, s := range seconds {
			out[i] = model.UnixNano(s) * sec
		}
		return out
	}
	for _, c := range []struct {
		name    string
		state   State
		now     int64
		backfil int
		due     []model.UnixNano
		missed  *MissedInterval
	}{
		{"first ever evaluation starts at the newest grid point", State{}, 125, 16, at(120), nil},
		{"new version starts fresh", State{Version: 0}, 125, 16, at(120), nil},
		{"nothing due before the next grid point", applied(120), 150, 16, nil, nil},
		{"next point due", applied(120), 181, 16, at(180), nil},
		{"two missed points: backfill then live", applied(60), 245, 16, at(120, 180, 240), &MissedInterval{From: 120 * sec, To: 180 * sec, Count: 2}},
		{"backfill is bounded; the older points stay missed", applied(60), 605, 2, at(480, 540, 600), &MissedInterval{From: 120 * sec, To: 540 * sec, Count: 8}},
		{"zero backfill evaluates only the live point", applied(60), 305, 0, at(300), &MissedInterval{From: 120 * sec, To: 240 * sec, Count: 3}},
		{"too early to have a grid point", State{}, 30, 16, nil, nil},
	} {
		plan := PlanGrid(rule, c.state, model.UnixNano(c.now)*sec, c.backfil)
		if !reflect.DeepEqual(plan.Due, c.due) || !reflect.DeepEqual(plan.Missed, c.missed) {
			t.Errorf("%s: due=%v missed=%+v", c.name, plan.Due, plan.Missed)
		}
	}
	// A state of another version is not this version's progress.
	other := applied(300)
	other.Version = 7
	if plan := PlanGrid(rule, other, 365*sec, 16); !reflect.DeepEqual(plan.Due, at(360)) || plan.Missed != nil {
		t.Errorf("state of another version: %+v", plan)
	}
}
