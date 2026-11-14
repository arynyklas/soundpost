// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/syntax"
	"sort"
	"strings"
	"testing"
	"time"
)

type discoveryEnv struct {
	*env
	org     model.ID
	ps      []model.ID
	alice   person
	scope   auth.Scope
	window  TimeRange
	project model.ID
}

func newDiscovery(t *testing.T, withCache bool) *discoveryEnv {
	f := newFx(t)
	org, ps := f.newOrg("discovery", 2)
	alice := f.user(org, "alice@example.test", ps, auth.Read)
	d := &discoveryEnv{org: org, ps: ps, alice: alice, project: ps[0], window: TimeRange{Start: model.UnixNano(testEpoch), End: model.UnixNano(testEpoch + 100)}}
	d.env = f.engineWith(newStore(), testLimits(), withCache)
	d.scope = f.scope(alice, org, ps...)
	return d
}
func (d *discoveryEnv) discover(kind string, limit uint32, cursor string) (DiscoveryResult, error) {
	return d.engine.Discover(d.ctx, d.scope, DiscoveryRequest{Projects: []model.ID{d.project}, Signal: model.Metric, Kind: kind, Time: d.window, Limit: limit, Cursor: cursor})
}

func TestDiscoveryKindsAndPagination(t *testing.T) {
	d := newDiscovery(t, true)
	st := d.store
	group := model.ID{7}
	st.marks = []model.Cursor{{Group: group, Index: 42}, {Group: model.ID{2}, Index: 9}}
	names := []string{"zeta", "alpha", "gamma", "beta", "eta", "delta", "epsilon"}
	for i, n := range names {
		st.add(metricRow(d.project, n, model.Labels{{Name: "job", Value: "api"}, {Name: "zone", Value: fmt.Sprint("z", i%2)}}, testEpoch+int64(i), 1))
		st.add(metricRow(d.project, n, model.Labels{{Name: "job", Value: "worker"}}, testEpoch+int64(i), 1)) // duplicate names
	}
	st.add(metricRow(d.project, "at_end_excluded", nil, testEpoch+100, 1), metricRow(d.project, "before_start_excluded", nil, testEpoch-1, 1), metricRow(d.project, "at_start_included", nil, testEpoch, 1))
	st.add(metricRow(d.ps[1], "other_project", nil, testEpoch, 1))

	all := append([]string{"at_start_included"}, names...)
	sort.Strings(all)
	var got []string
	var cursor string
	var pages []int
	for {
		res, err := d.discover(DiscoverMetricNames, 3, cursor)
		if err != nil {
			t.Fatal(err)
		}
		pages = append(pages, len(res.Items))
		got = append(got, res.Items...)
		if res.More != (res.NextCursor != "") {
			t.Fatalf("a cursor exists exactly when more follows: %+v", res)
		}
		if res.Freshness.Completeness != CompletenessComplete || res.Freshness.Cached || len(res.Freshness.Watermarks) != 2 || !idLess(res.Freshness.Watermarks[0].Group, res.Freshness.Watermarks[1].Group) {
			t.Fatalf("freshness must carry the actual ordered read cuts: %+v", res.Freshness)
		}
		if !res.More {
			break
		}
		cursor = res.NextCursor
	}
	if fmt.Sprint(got) != fmt.Sprint(all) || fmt.Sprint(pages) != "[3 3 2]" {
		t.Fatalf("pages %v must list every distinct visible name exactly once in order:\n got %v\nwant %v", pages, got, all)
	}
	// Exactly one page of exactly `limit` items is not "more".
	res, err := d.discover(DiscoverMetricNames, uint32(len(all)), "")
	if err != nil || res.More || res.NextCursor != "" || len(res.Items) != len(all) {
		t.Fatalf("a full page that ends the data must say so: %v %+v", err, res)
	}
	// An unconfigured cursor facility must refuse, not silently truncate.
	if _, err = d.discover(DiscoverMetricNames, 3, "x"); code(err) != model.Unsupported && code(err) != model.NotFound {
		t.Fatalf("%v", err)
	}

	labelNames, err := d.discover(DiscoverLabelNames, 10, "")
	if err != nil || fmt.Sprint(labelNames.Items) != "[__name__ job zone]" {
		t.Fatalf("%v %v", err, labelNames.Items)
	}
	values, err := d.engine.Discover(d.ctx, d.scope, DiscoveryRequest{Projects: []model.ID{d.project}, Signal: model.Metric, Kind: DiscoverLabelValues, Field: "job", Time: d.window, Limit: 10})
	if err != nil || fmt.Sprint(values.Items) != "[api worker]" {
		t.Fatalf("%v %v", err, values.Items)
	}
	apiOnly, err := d.engine.Discover(d.ctx, d.scope, DiscoveryRequest{Projects: []model.ID{d.project}, Signal: model.Metric, Kind: DiscoverLabelValues, Field: "zone", Matchers: []Matcher{{Name: "job", Op: "=", Value: "api"}, {Name: "__name__", Op: "!=", Value: "alpha"}}, Time: d.window, Limit: 10})
	if err != nil || fmt.Sprint(apiOnly.Items) != "[z0 z1]" {
		t.Fatalf("%v %v", err, apiOnly.Items)
	}
	rx := DiscoveryRequest{Projects: []model.ID{d.project}, Signal: model.Metric, Kind: DiscoverMetricNames, Matchers: []Matcher{{Name: "job", Op: "=~", Value: "wor.*"}, {Name: "__name__", Op: "!~", Value: "[a-d].*"}}, Time: d.window, Limit: 10}
	if _, err = d.engine.Discover(d.ctx, d.scope, rx); code(err) != model.Invalid {
		t.Fatalf("a regular-expression matcher needs a pinned profile: %v", err)
	}
	rx.Profile, rx.FeatureSet = prom310, baseFeatureSet
	rxRes, err := d.engine.Discover(d.ctx, d.scope, rx)
	if err != nil || fmt.Sprint(rxRes.Items) != "[epsilon eta gamma zeta]" {
		t.Fatalf("%v %v", err, rxRes.Items)
	}
	if peak := d.engine.Usage().MemoryPeak; peak == 0 {
		t.Fatal("discovery must be accounted")
	}

	// Logs: label names/values (stream labels), templates and typed fields.
	d.store.add(logRow(t, d.project, testEpoch+1, "a", model.Labels{{Name: "app", Value: "web"}}))
	second := logRow(t, d.project, testEpoch+2, "b", model.Labels{{Name: "app", Value: "api"}, {Name: "tier", Value: "1"}})
	second.payload.Log.TemplateID = "t2"
	second.payload.Log.Fields = map[string]model.Scalar{"code": scalarText(t, "500")}
	d.store.add(second)
	logs := func(kind, field string) []string {
		t.Helper()
		r, err := d.engine.Discover(d.ctx, d.scope, DiscoveryRequest{Projects: []model.ID{d.project}, Signal: model.Log, Kind: kind, Field: field, Time: d.window, Limit: 10})
		if err != nil {
			t.Fatal(err)
		}
		return r.Items
	}
	if fmt.Sprint(logs(DiscoverLabelNames, "")) != "[app tier]" || fmt.Sprint(logs(DiscoverLabelValues, "app")) != "[api web]" || fmt.Sprint(logs(DiscoverTemplates, "")) != "[t1 t2]" || fmt.Sprint(logs(DiscoverFields, "")) != "[code msg]" {
		t.Fatalf("log discovery: %v %v %v %v", logs(DiscoverLabelNames, ""), logs(DiscoverLabelValues, "app"), logs(DiscoverTemplates, ""), logs(DiscoverFields, ""))
	}

	bad := func(name string, mutate func(*DiscoveryRequest), want model.Code) {
		t.Helper()
		r := DiscoveryRequest{Projects: []model.ID{d.project}, Signal: model.Metric, Kind: DiscoverMetricNames, Time: d.window, Limit: 5}
		mutate(&r)
		if _, err := d.engine.Discover(d.ctx, d.scope, r); code(err) != want {
			t.Fatalf("%s: %v", name, err)
		}
	}
	bad("zero limit", func(r *DiscoveryRequest) { r.Limit = 0 }, model.Invalid)
	bad("limit above the grant", func(r *DiscoveryRequest) { r.Limit = d.engine.limits.MaxDiscoveryItems + 1 }, model.Invalid)
	bad("empty range", func(r *DiscoveryRequest) { r.Time.End = r.Time.Start }, model.Invalid)
	bad("label values without a field", func(r *DiscoveryRequest) { r.Kind = DiscoverLabelValues }, model.Invalid)
	bad("field on names", func(r *DiscoveryRequest) { r.Field = "job" }, model.Invalid)
	bad("log kind on metrics", func(r *DiscoveryRequest) { r.Kind = DiscoverTemplates }, model.Invalid)
	bad("unknown kind", func(r *DiscoveryRequest) { r.Kind = "everything" }, model.Invalid)
	bad("unknown signal", func(r *DiscoveryRequest) { r.Signal = "bogus" }, model.Invalid)
	bad("native trace search is not PromQL discovery", func(r *DiscoveryRequest) { r.Signal = model.SpanKind }, model.Unsupported)
	bad("bad matcher op", func(r *DiscoveryRequest) { r.Matchers = []Matcher{{Name: "a", Op: "~", Value: "b"}} }, model.Invalid)
	bad("source on a telemetry.read scope", func(r *DiscoveryRequest) { id := model.NewID(); r.Source = &id }, model.Invalid)
	bad("duplicate projects", func(r *DiscoveryRequest) { r.Projects = []model.ID{d.project, d.project} }, model.Invalid)
	d.store.partialPage = 1
	bad("a partial scan is never a complete answer", func(*DiscoveryRequest) {}, model.Unavailable)
	d.store.partialPage = 0
	d.idle(t)
}

func TestDiscoveryMemoryIsBoundedByThePage(t *testing.T) {
	d := newDiscovery(t, true)
	rows := make([]trow, 20000)
	for i := range rows {
		rows[i] = metricRow(d.project, fmt.Sprintf("metric_%06d", (i*7919)%20000), nil, testEpoch+int64(i%50), 1)
	}
	d.store.add(rows...)
	res, err := d.discover(DiscoverMetricNames, 5, "")
	if err != nil || len(res.Items) != 5 || !res.More || res.Items[0] != "metric_000000" || res.Items[4] != "metric_000004" {
		t.Fatalf("%v %+v", err, res)
	}
	if peak := d.engine.Usage().MemoryPeak; peak == 0 || peak > 4096 {
		t.Fatalf("working memory %d must follow the page (6 names), not the 20000 distinct names scanned", peak)
	}
	d.idle(t)
}

func TestDiscoveryCursorBoundaries(t *testing.T) {
	d := newDiscovery(t, true)
	for i, n := range []string{"a1", "a2", "a3", "a4", "a5"} {
		d.store.add(metricRow(d.project, n, nil, testEpoch+int64(i), 1), metricRow(d.ps[1], "b"+n, nil, testEpoch+int64(i), 1))
	}
	first, err := d.discover(DiscoverMetricNames, 2, "")
	if err != nil || fmt.Sprint(first.Items) != "[a1 a2]" || !first.More {
		t.Fatalf("%v %+v", err, first)
	}
	token := first.NextCursor
	next, err := d.discover(DiscoverMetricNames, 2, token)
	if err != nil || fmt.Sprint(next.Items) != "[a3 a4]" {
		t.Fatalf("a valid cursor continues strictly after the last item: %v %+v", err, next)
	}
	scans := d.store.scans.Load()
	again, err := d.discover(DiscoverMetricNames, 2, token)
	if err != nil || !again.Freshness.Cached || d.store.scans.Load() != scans || fmt.Sprint(again.Items) != "[a3 a4]" {
		t.Fatalf("the same page by the same visibility is a cache hit: %v %+v", err, again.Freshness)
	}

	reject := func(name string, scope auth.Scope, r DiscoveryRequest, want model.Code) {
		t.Helper()
		r.Cursor = token
		_, err := d.engine.Discover(d.ctx, scope, r)
		if code(err) != want {
			t.Fatalf("%s: want %s, got %v", name, want, err)
		}
	}
	base := DiscoveryRequest{Projects: []model.ID{d.project}, Signal: model.Metric, Kind: DiscoverMetricNames, Time: d.window, Limit: 2}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range []int{0, 1, len(raw) / 2, len(raw) - 33, len(raw) - 1} {
		tampered := append([]byte(nil), raw...)
		tampered[i] ^= 0x01
		r := base
		r.Cursor = base64.RawURLEncoding.EncodeToString(tampered)
		if _, err := d.engine.Discover(d.ctx, d.scope, r); code(err) != model.NotFound {
			t.Fatalf("a cursor with byte %d flipped must be rejected: %v", i, err)
		}
	}
	for _, junk := range []string{"x", token[:len(token)/2], token + "AAAA", strings.Repeat("A", 20000)} {
		r := base
		r.Cursor = junk
		if _, err := d.engine.Discover(d.ctx, d.scope, r); err == nil {
			t.Fatalf("junk cursor accepted")
		}
	}

	// Another principal of the same org and project, and another org.
	bob := d.fx.user(d.org, "bob@example.test", d.ps, auth.Read)
	carolOrg, carolPs := d.fx.newOrg("other org", 1)
	carol := d.fx.user(carolOrg, "carol@example.test", carolPs, auth.Read)
	token0 := token
	d.fx.cmd(d.org, "create_project", auth.AdminPayload{ID: model.NewID(), Name: "epoch-bump"}) // moves the policy epoch
	freshAlice := d.fx.scope(d.alice, d.org, d.ps...)
	freshBob := d.fx.scope(bob, d.org, d.ps...)
	freshCarol := d.fx.scope(carol, carolOrg, carolPs...)
	token = token0
	reject("a changed policy epoch", freshAlice, base, model.NotFound)
	reject("another principal in the same org", freshBob, base, model.NotFound)
	carolReq := base
	carolReq.Projects = carolPs
	reject("another org", freshCarol, carolReq, model.NotFound)

	// Mint under the new epoch and test the remaining bindings.
	d.scope = freshAlice
	minted, err := d.discover(DiscoverMetricNames, 2, "")
	if err != nil {
		t.Fatal(err)
	}
	token = minted.NextCursor
	if _, err = d.discover(DiscoverMetricNames, 2, token); err != nil {
		t.Fatalf("a freshly minted cursor must work: %v", err)
	}
	other := base
	other.Kind = DiscoverLabelNames
	reject("different parameters (kind)", d.scope, other, model.Invalid)
	other = base
	other.Projects = []model.ID{d.ps[1]}
	reject("different project", d.scope, other, model.Invalid)
	other = base
	other.Time.End++
	reject("different time range", d.scope, other, model.Invalid)
	other = base
	other.Matchers = []Matcher{{Name: "x", Op: "=", Value: "y"}}
	reject("different matchers", d.scope, other, model.Invalid)
	if _, err = d.engine.Exemplars(d.ctx, d.scope, ExemplarRequest{Projects: []model.ID{d.project}, Profile: prom310, FeatureSet: baseFeatureSet, Expression: "a1", Window: d.window, Limit: 2, Cursor: token}); err == nil {
		t.Fatal("a discovery cursor must not continue an exemplar page")
	}

	d.fx.deletes.bump.Add(1)
	reject("a changed delete generation", d.scope, base, model.NotFound)
	minted, err = d.discover(DiscoverMetricNames, 2, "")
	if err != nil {
		t.Fatal(err)
	}
	token = minted.NextCursor
	d.fx.advance(14 * time.Minute)
	if _, err = d.discover(DiscoverMetricNames, 2, token); err != nil {
		t.Fatalf("a 14 minute old cursor is still valid: %v", err)
	}
	d.fx.advance(2 * time.Minute)
	reject("older than 15 minutes", d.scope, base, model.NotFound)

	// An engine with no ticket facility cannot page: it refuses.
	bare, err := New(d.store, d.svc, d.registry, testLimits())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = bare.Discover(d.ctx, d.scope, base); code(err) != model.Unsupported {
		t.Fatalf("more results with no cursor facility must be a typed refusal, not a truncation: %v", err)
	}
	base.Limit = 100
	if res, err := bare.Discover(d.ctx, d.scope, base); err != nil || res.More || len(res.Items) != 5 {
		t.Fatalf("a page that fits needs no cursor: %v %+v", err, res)
	}
	d.idle(t)
}

func TestExemplars(t *testing.T) {
	d := newDiscovery(t, true)
	traces := make([]model.ID, 5)
	for i := range traces {
		traces[i] = model.NewID()
		d.store.add(exemplarRow(d.project, "http_total", model.Labels{{Name: "route", Value: fmt.Sprint("r", i%2)}}, testEpoch+int64(i), float64(i), traces[i]))
	}
	d.store.add(metricRow(d.project, "http_total", model.Labels{{Name: "route", Value: "r0"}}, testEpoch+10, 1)) // no exemplar
	d.store.add(exemplarRow(d.project, "other_total", nil, testEpoch+1, 1, model.NewID()))
	d.store.add(exemplarRow(d.ps[1], "http_total", model.Labels{{Name: "route", Value: "r0"}}, testEpoch+1, 7, model.NewID()))
	span := model.SpanID{1, 2, 3, 4, 5, 6, 7, 8}
	spanRow := exemplarRow(d.project, "http_total", model.Labels{{Name: "route", Value: "r9"}}, testEpoch+20, 9, model.NewID())
	spanRow.payload.Metric.ExemplarSpan = &span
	d.store.add(spanRow)
	req := ExemplarRequest{Projects: []model.ID{d.project}, Profile: prom310, FeatureSet: baseFeatureSet, Expression: `rate(http_total{route=~"r[01]"}[5m])`, Window: d.window, Limit: 3}
	var got []Exemplar
	for {
		res, err := d.engine.Exemplars(d.ctx, d.scope, req)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, res.Exemplars...)
		if res.More != (res.NextCursor != "") {
			t.Fatal("cursor exists exactly when more follows")
		}
		if !res.More {
			break
		}
		req.Cursor = res.NextCursor
	}
	if len(got) != 5 {
		t.Fatalf("selector-matched exemplars of this project only: %d", len(got))
	}
	seen := map[model.ID]bool{}
	for i, x := range got {
		seen[x.Trace] = true
		if x.Project != d.project || labelValue(x.Labels, "__name__") != "http_total" || labelValue(x.Labels, "route") == "r9" || x.Sample.Float == nil {
			t.Fatalf("exemplar outside the selector: %+v", x)
		}
		if i > 0 && !(got[i-1].Project != x.Project || string(labelKeyOf(got[i-1].Labels)) < string(labelKeyOf(x.Labels)) || string(labelKeyOf(got[i-1].Labels)) == string(labelKeyOf(x.Labels)) && got[i-1].Sample.Time < x.Sample.Time) {
			t.Fatal("exemplars must be ordered by series then time")
		}
	}
	for _, tr := range traces {
		if !seen[tr] {
			t.Fatal("an exemplar was lost across pages")
		}
	}
	req.Cursor = ""
	req.Expression = `http_total{route="r9"}`
	res, err := d.engine.Exemplars(d.ctx, d.scope, req)
	if err != nil || len(res.Exemplars) != 1 || res.Exemplars[0].Span == nil || *res.Exemplars[0].Span != span {
		t.Fatalf("span identity is returned: %v %+v", err, res)
	}
	warm := d.store.scans.Load()
	if again, err := d.engine.Exemplars(d.ctx, d.scope, req); err != nil || !again.Freshness.Cached || d.store.scans.Load() != warm {
		t.Fatalf("exemplar cache: %v", err)
	}
	for name, expr := range map[string]string{"no selector": "1 + 2", "syntax error": "rate(", "type error": `sum("x")`} {
		r := req
		r.Expression = expr
		_, err := d.engine.Exemplars(d.ctx, d.scope, r)
		var language *syntax.LanguageError
		if !errors.As(err, &language) {
			t.Fatalf("%s: typed language error expected, got %v", name, err)
		}
	}
	r := req
	r.Profile = logql352
	if _, err = d.engine.Exemplars(d.ctx, d.scope, r); code(err) != model.Invalid {
		t.Fatalf("%v", err)
	}
	r = req
	r.Window.End = r.Window.Start
	if _, err = d.engine.Exemplars(d.ctx, d.scope, r); code(err) != model.Invalid {
		t.Fatalf("%v", err)
	}
	d.idle(t)
}

func labelValue(ls model.Labels, name string) string {
	for _, l := range ls {
		if l.Name == name {
			return l.Value
		}
	}
	return ""
}
func labelKeyOf(ls model.Labels) []byte {
	var b []byte
	for _, l := range ls {
		b = append(b, byte(len(l.Name)))
		b = append(b, l.Name...)
		b = append(b, byte(len(l.Value)))
		b = append(b, l.Value...)
	}
	return b
}

func TestFormat(t *testing.T) {
	d := newDiscovery(t, false)
	format := func(language, profileID, expr string) (FormatResult, error) {
		set := baseFeatureSet
		if language == LanguageLogQL {
			set = logFeatureSet
		}
		return d.engine.Format(d.ctx, d.scope, FormatRequest{Language: language, Profile: profileID, FeatureSet: set, Expression: expr})
	}
	for _, expr := range []string{
		"sum   by (job) ( rate( http_total[5m] ) ) / 2",
		`up{job="a b", zone!~"z.*"} offset 5m`,
		"histogram_quantile(0.9, sum by (le) (rate(h[5m])))",
		"-(1 + 2) * 3",
		`label_replace(up, "dst", "$1", "src", "(.*)")`,
	} {
		res, err := format(LanguagePromQL, prom310, expr)
		if err != nil {
			t.Fatalf("%q: %v", expr, err)
		}
		again, err := format(LanguagePromQL, prom310, res.Formatted)
		if err != nil || again.Formatted != res.Formatted {
			t.Fatalf("formatting must be idempotent: %q -> %q -> %q (%v)", expr, res.Formatted, again.Formatted, err)
		}
		if res.Diagnostics == nil {
			t.Fatal("diagnostics must be a (possibly empty) list")
		}
	}
	res, err := format(LanguageLogQL, logql352, "{app=\"web\"}   |=  \"a  b\"\n  | json   | level=\"error\"")
	if err != nil || res.Formatted != `{app="web"} |= "a  b" | json | level="error"` {
		t.Fatalf("log whitespace is normalized and string text is kept byte for byte: %q %v", res.Formatted, err)
	}
	res, err = format(LanguageLogQL, logql352, "sum by (app) (rate({app=`we  b`} [1m]))")
	if err != nil || res.Formatted != "sum by (app) (rate({app=`we  b`} [1m]))" {
		t.Fatalf("%q %v", res.Formatted, err)
	}
	if _, err = format(LanguageLogQL, logql352, "{app=\"web\"} # trailing comment\n| json"); code(err) != model.Unsupported {
		t.Fatalf("an expression with a comment cannot be normalized without guessing: %v", err)
	}
	for name, c := range map[string][3]string{
		"promql syntax":   {LanguagePromQL, prom310, "rate("},
		"promql type":     {LanguagePromQL, prom310, `sum("x")`},
		"logql syntax":    {LanguageLogQL, logql352, `{app=}`},
		"logql no stream": {LanguageLogQL, logql352, `|= "x"`},
	} {
		_, err := format(c[0], c[1], c[2])
		var language *syntax.LanguageError
		if !errors.As(err, &language) || language.SafeMessage == "" || strings.Contains(language.SafeMessage, c[2]) && len(c[2]) > 3 {
			t.Fatalf("%s: typed language error without source text expected, got %v", name, err)
		}
	}
	if _, err = format(LanguagePromQL, logql352, "up"); code(err) != model.Invalid {
		t.Fatalf("%v", err)
	}
	if _, err = format(LanguagePromQL, prom310, ""); code(err) != model.Invalid {
		t.Fatalf("%v", err)
	}
	d.fx.revoke(d.org, d.alice, d.ps[0], auth.Read)
	d.fx.revoke(d.org, d.alice, d.ps[1], auth.Read)
	if _, err = format(LanguagePromQL, prom310, "up"); code(err) != model.NotFound {
		t.Fatalf("formatting is behind the same scope revalidation: %v", err)
	}
}
