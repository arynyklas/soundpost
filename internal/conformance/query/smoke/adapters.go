// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package smoke

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/arynyklas/soundpost/internal/adapters/queryinput"
	"github.com/arynyklas/soundpost/internal/ingest"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query"
)

// persistedHook is one extra feed of the persisted-path runner: it admitted its
// data at setup and is re-checked at every persisted stage.
type persistedHook struct {
	name string
	// resend re-sends the feed's identical requests (a sender retry).
	resend func()
	// check returns the feed's steps for one stage.
	check func(stage string) []StepResult
	// close releases what the feed holds (a scrape target).
	close func()
	// final returns the steps that run once every stage is done.
	final func() []StepResult
}

const staleMarkerBits = 0x7ff0000000000002

// adaptersSection is the "adapters" part of persisted-path.json: every input
// adapter of internal/adapters/queryinput, each with the manifest of what its
// request admits (receipts, input kinds, record count) and the queries whose
// answers are authored from the feed.
type adaptersSection struct {
	Fixture fixture             `json:"fixture"`
	Grants  map[string][]string `json:"grants"`
	Feeds   []adapterFeedSpec   `json:"feeds"`
	// Library holds series (with the queries authored for them) that several
	// feeds send under their own name prefix: "{p}" in an expression is the
	// feed's prefix.
	Library []feedLibrary `json:"library"`
	// anchorMS is the run anchor the feeds' times are offsets from (set when the
	// feeds are admitted).
	anchorMS int64
}

type feedSample struct {
	TMS       int64                  `json:"t_ms"`
	Bits      string                 `json:"bits"`
	Histogram *model.NativeHistogram `json:"histogram"`
}

type feedSeries struct {
	Name    string            `json:"name"`
	Labels  map[string]string `json:"labels"`
	Samples []feedSample      `json:"samples"`
}

type feedLine struct {
	TNS  int64  `json:"t_ns"`
	Line string `json:"line"`
}

type feedStream struct {
	Labels map[string]string `json:"labels"`
	Lines  []feedLine        `json:"lines"`
}

type feedEvent struct {
	Condition string            `json:"condition"`
	Epoch     string            `json:"epoch"`
	Sequence  uint64            `json:"sequence"`
	TMS       int64             `json:"t_ms"`
	Status    string            `json:"status"`
	Severity  string            `json:"severity"`
	Labels    map[string]string `json:"labels"`
}

type feedQuery struct {
	ID          string     `json:"id"`
	Language    string     `json:"language"`
	Expression  string     `json:"expression"`
	AtMS        int64      `json:"at_ms"`
	ExpectBits  []string   `json:"expect_bits"`
	ExpectLines []feedLine `json:"expect_lines"`
	Streams     bool       `json:"streams"`
	// Profiles limits the query to the named pinned profiles (default: all).
	Profiles []string `json:"profiles"`
	// Order ("forward" or "backward") and Limit page a log stream query; the
	// authored lines are then compared in order.
	Order string `json:"order"`
	Limit uint64 `json:"limit"`
}

// feedManifest is the authored per-adapter manifest: how many records the
// request carries, of which input kinds, and that every child batch it was
// partitioned into is receipted.
type feedManifest struct {
	Records    int            `json:"records"`
	InputKinds map[string]int `json:"input_kinds"`
	Receipts   string         `json:"receipts"`
}

type adapterFeedSpec struct {
	ID       string       `json:"id"`
	Adapter  string       `json:"adapter"`
	Wire     string       `json:"wire"`
	Source   string       `json:"source"`
	Series   []feedSeries `json:"series"`
	Streams  []feedStream `json:"streams"`
	Events   []feedEvent  `json:"events"`
	Manifest feedManifest `json:"manifest"`
	Queries  []feedQuery  `json:"queries"`
	// Library names the shared series this feed sends, each under Prefix.
	Library []string `json:"library"`
	Prefix  string   `json:"prefix"`
}

// adapterReply is the bridge's reply body, reduced to what the manifest checks.
type adapterReply struct {
	Adapter  string `json:"adapter"`
	Admitted int    `json:"admitted"`
	Failed   int    `json:"failed"`
	Children []struct {
		BatchID string         `json:"batch_id"`
		Records int            `json:"records"`
		Status  string         `json:"status"`
		Receipt *model.Receipt `json:"receipt"`
	} `json:"children"`
}

// feedAdmission is what one admission of a feed's request produced.
type feedAdmission struct {
	IDs     []string
	Cursors []model.Cursor
	Records int
	Failed  int
	Status  int
}

func (a feedAdmission) receipts() int { return len(a.Cursors) }

// postAdapter sends one raw request to a bridge route of node (0 is the
// primary node) with a source credential.
func (e *Env) postAdapter(node uint64, s *Source, path string, headers map[string]string, body []byte) (int, []byte) {
	base, client := e.endpoint(node)
	req, err := http.NewRequestWithContext(e.ctx, "POST", base+path, bytes.NewReader(body))
	check(err)
	req.Header.Set("Authorization", "Bearer "+s.Credential)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	check(err)
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw
}

type adapterFeed struct {
	spec    adapterFeedSpec
	env     *Env
	project string
	src     *Source
	node    uint64
	anchor  int64 // ms
	fence   *cursorSet
	path    string
	headers map[string]string
	body    []byte
	want    []string
	first   feedAdmission
	retried *feedAdmission
	// scrape serves the OpenMetrics exposition the scraper pulls.
	scrape *httptest.Server
	// kind namespaces the feed's step names ("adapter" or "native").
	kind string
	// direct is the feed's fixed batches for the direct_json wire.
	direct []model.Batch
}

func (f *adapterFeed) anchorNS() int64 { return f.anchor * 1e6 }

func (f *adapterFeed) wireSeries() []wireSeries {
	var out []wireSeries
	for _, s := range f.spec.Series {
		ws := wireSeries{Name: s.Name, Labels: s.Labels}
		for _, sm := range s.Samples {
			w := wireSample{TimeMS: f.anchor + sm.TMS}
			if sm.Histogram != nil {
				w.Hist = sm.Histogram
			} else {
				w.Bits = mustHex(sm.Bits)
			}
			ws.Samples = append(ws.Samples, w)
		}
		out = append(out, ws)
	}
	return out
}

// expectedRows is the authored multiset the feed's request must leave in
// storage, derived from the logical records (not from the wire bytes).
func (f *adapterFeed) expectedRows() []string {
	var rows []rawRow
	for _, s := range f.spec.Series {
		ls := make([]string, 0, len(s.Labels))
		for _, k := range sortedLabelNames(s.Labels) {
			ls = append(ls, k+"="+s.Labels[k])
		}
		series := s.Name + "{" + strings.Join(ls, ",") + "}"
		for _, sm := range s.Samples {
			r := rawRow{Series: series, Time: (f.anchor + sm.TMS) * 1e6}
			switch {
			case sm.Histogram != nil && sm.Histogram.Integer != nil:
				r.Kind, r.Value = "integer_histogram", canonHistogram(sm.Histogram)
			case sm.Histogram != nil:
				r.Kind, r.Value = "float_histogram", canonHistogram(sm.Histogram)
			default:
				r.Kind, r.Value = "float", strings.ToLower(sm.Bits)
				if mustHex(sm.Bits) == staleMarkerBits {
					r.Kind = "stale"
				}
			}
			rows = append(rows, r)
		}
	}
	for _, s := range f.spec.Streams {
		ls := make([]string, 0, len(s.Labels))
		for _, k := range sortedLabelNames(s.Labels) {
			ls = append(ls, k+"="+s.Labels[k])
		}
		for _, l := range s.Lines {
			rows = append(rows, rawRow{Kind: "log", Series: "{" + strings.Join(ls, ",") + "}", Time: f.anchorNS() + l.TNS, Value: l.Line})
		}
	}
	for _, ev := range f.spec.Events {
		ls := make([]string, 0, len(ev.Labels))
		for _, k := range sortedLabelNames(ev.Labels) {
			ls = append(ls, k+"="+ev.Labels[k])
		}
		rows = append(rows, rawRow{Kind: "condition", Series: fmt.Sprintf("seq=%d", ev.Sequence), Time: (f.anchor + ev.TMS) * 1e6, Value: ev.Status + "|" + ev.Severity + "|" + strings.Join(ls, ",")})
	}
	return rowKeys(rows)
}

// prepare builds the request body, headers and the authored expectation.
func (f *adapterFeed) prepare() {
	switch f.spec.Wire {
	case "remote_write_v1":
		f.path = "/adapters/v1/prometheus/write"
		f.headers = map[string]string{"Content-Type": "application/x-protobuf", "Content-Encoding": "snappy"}
		f.body = snappyBlock(remoteWriteV1Body(f.wireSeries()))
	case "remote_write_v2":
		f.path = "/adapters/v1/prometheus/write"
		f.headers = map[string]string{"Content-Type": "application/x-protobuf;proto=io.prometheus.write.v2.Request", "Content-Encoding": "snappy"}
		f.body = snappyBlock(remoteWriteV2Body(f.wireSeries()))
	case "openmetrics_text":
		f.body = openMetricsBody(f.wireSeries())
	case "loki_json":
		f.path = "/adapters/v1/loki/push"
		tpl := f.src.logTemplate
		checkf(tpl != nil, "feed %s: source %s has no log template", f.spec.ID, f.spec.Source)
		f.headers = map[string]string{"Content-Type": "application/json", "X-Soundpost-Template": tpl.ID, "X-Soundpost-Template-Revision": fmt.Sprint(tpl.Revision)}
		var streams []wireStream
		for _, s := range f.spec.Streams {
			ws := wireStream{Labels: s.Labels}
			for _, l := range s.Lines {
				ws.Lines = append(ws.Lines, wireLine{TimeNS: f.anchorNS() + l.TNS, Line: l.Line})
			}
			streams = append(streams, ws)
		}
		f.body = lokiPushBody(streams)
	case "conditions_json":
		f.path = "/adapters/v1/conditions"
		f.headers = map[string]string{"Content-Type": "application/json"}
		var evs []wireCondition
		for _, ev := range f.spec.Events {
			evs = append(evs, wireCondition{Condition: ev.Condition, Epoch: ev.Epoch, Sequence: ev.Sequence, TimeNS: (f.anchor + ev.TMS) * 1e6, Status: ev.Status, Severity: ev.Severity, Labels: ev.Labels})
		}
		f.body = conditionsBody(evs)
	case "direct_json":
		f.directBatches()
	default:
		checkf(false, "feed %s: unknown wire %q", f.spec.ID, f.spec.Wire)
	}
	f.want = f.expectedRows()
	// The authored manifest must agree with the authored records.
	kinds := map[string]int{}
	for _, k := range f.want {
		kinds[strings.SplitN(k, "|", 2)[0]]++
	}
	checkf(len(f.want) == f.spec.Manifest.Records && fmt.Sprint(kinds) == fmt.Sprint(f.spec.Manifest.InputKinds), "feed %s: manifest %d records %v disagrees with the authored records %d %v", f.spec.ID, f.spec.Manifest.Records, f.spec.Manifest.InputKinds, len(f.want), kinds)
}

// admit sends the feed's request once and returns what the adapter reported.
func (f *adapterFeed) admit() feedAdmission {
	if f.spec.Wire == "openmetrics_text" {
		return f.scrapeOnce()
	}
	if f.spec.Wire == "direct_json" {
		return f.directAdmit()
	}
	code, raw := f.env.postAdapter(f.node, f.src, f.path, f.headers, f.body)
	var reply adapterReply
	check(json.Unmarshal(raw, &reply))
	a := feedAdmission{Status: code, Failed: reply.Failed}
	for _, c := range reply.Children {
		a.IDs = append(a.IDs, c.BatchID)
		a.Records += c.Records
		if c.Status == "admitted" && c.Receipt != nil {
			a.Cursors = append(a.Cursors, c.Receipt.Cursor)
		}
	}
	checkf(code == 200 && reply.Adapter != "", "feed %s: adapter answered %d: %s", f.spec.ID, code, trim(raw))
	return a
}

// scrapeOnce pulls the exposition over HTTP, decodes it with the production
// OpenMetrics translator and admits every child batch through C03, the way a
// scrape loop of the bridge would.
func (f *adapterFeed) scrapeOnce() feedAdmission {
	if f.scrape == nil {
		body := f.body
		f.scrape = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/openmetrics-text; version=1.0.0; charset=utf-8")
			_, _ = w.Write(body)
		}))
	}
	resp, err := http.Get(f.scrape.URL)
	check(err)
	defer resp.Body.Close()
	app := f.env.app
	if f.node != 0 {
		app = f.env.NodeApp(f.node)
	}
	cred := f.src.Cred
	if f.node != 0 {
		var cerr error
		cred, cerr = app.Auth.AuthenticateSource(f.env.ctx, f.src.Credential, "", false)
		check(cerr)
	}
	src, err := app.Auth.SourceAuthority(f.env.ctx, cred, true)
	check(err)
	producer := src.CredentialID
	if producer == (model.ID{}) {
		producer = src.ID
	}
	now := time.Now()
	profile := queryinput.InputProfile{
		Project: src.Project, Source: src.ID, Producer: producer, PolicyRevision: src.Policy.Revision, Resource: f.src.Resource,
		Limits:       queryinput.DefaultLimits(),
		MinTimestamp: model.UnixNano(now.Add(-7 * 24 * time.Hour).UnixNano()), MaxTimestamp: model.UnixNano(now.Add(time.Hour).UnixNano()),
		DefaultTimestamp: model.UnixNano(now.UnixNano()),
		Names:            queryinput.NamesStrict, OutOfOrder: queryinput.OutOfOrderSort,
		Histograms: queryinput.HistogramsPreserve, Exemplars: queryinput.ExemplarsReject, Help: queryinput.HelpDiscard,
	}
	probe := ingest.Batch{Project: src.Project, Source: src.ID, PolicyRevision: src.Policy.Revision}
	grant, err := app.Ingest.ResolveSource(f.env.ctx, cred, probe)
	check(err)
	batches, err := queryinput.DecodeOpenMetrics(f.env.ctx, grant, resp.Body, profile)
	check(err)
	a := feedAdmission{Status: 200}
	for i := range batches {
		g, err := app.Ingest.ResolveSource(f.env.ctx, cred, batches[i])
		check(err)
		receipt, err := app.Ingest.Admit(f.env.ctx, g, batches[i])
		check(err)
		a.IDs = append(a.IDs, batches[i].ID.String())
		a.Records += len(batches[i].Records)
		a.Cursors = append(a.Cursors, receipt.Cursor)
	}
	return a
}

func (f *adapterFeed) close() {
	if f.scrape != nil {
		f.scrape.Close()
	}
}

// signal is the storage signal of the feed's records.
func (f *adapterFeed) signal() model.Kind {
	switch {
	case len(f.spec.Streams) > 0:
		return model.Log
	case len(f.spec.Events) > 0:
		return model.Condition
	}
	return model.Metric
}

func (f *adapterFeed) stored() []rawRow {
	var out []rawRow
	for _, r := range f.env.scanRaw(f.project, f.signal(), f.fence.list()) {
		if r.Source == f.src.ID {
			out = append(out, r)
		}
	}
	return out
}

func (f *adapterFeed) check(stage string, profiles []string) []StepResult {
	var steps []StepResult
	run := func(name string, fn func() string) {
		st := StepResult{Name: stage + "/" + f.kind + "/" + f.spec.ID + "/" + name}
		func() {
			defer func() {
				switch r := recover().(type) {
				case nil:
				case failure:
					st.Detail = r.err.Error()
				default:
					panic(r)
				}
			}()
			if d := fn(); d != "" {
				st.Detail = d
				return
			}
			st.Passed = true
		}()
		steps = append(steps, st)
	}
	run("receipts", func() string {
		a := f.first
		if a.Failed != 0 || a.receipts() == 0 || len(a.IDs) != a.receipts() || a.Records != f.spec.Manifest.Records {
			return fmt.Sprintf("%d receipts for %d child batches, %d failed, %d records admitted (manifest %d)", a.receipts(), len(a.IDs), a.Failed, a.Records, f.spec.Manifest.Records)
		}
		return ""
	})
	stored := f.stored()
	run("input-kinds-and-count", func() string {
		kinds := map[string]int{}
		for _, r := range stored {
			kinds[r.Kind]++
		}
		if len(stored) != f.spec.Manifest.Records || fmt.Sprint(kinds) != fmt.Sprint(f.spec.Manifest.InputKinds) {
			return fmt.Sprintf("stored %d records %v, manifest %d %v", len(stored), kinds, f.spec.Manifest.Records, f.spec.Manifest.InputKinds)
		}
		return ""
	})
	run("stored-equals-admitted", func() string { return diffKeys(rowKeys(stored), f.want) })
	if f.retried != nil {
		run("retry-reuses-children-and-receipts", func() string {
			r := f.retried
			if r.Failed != 0 || fmt.Sprint(r.IDs) != fmt.Sprint(f.first.IDs) || fmt.Sprint(r.Cursors) != fmt.Sprint(f.first.Cursors) {
				return fmt.Sprintf("retry children %v receipts %v, first %v %v", r.IDs, r.Cursors, f.first.IDs, f.first.Cursors)
			}
			return ""
		})
	}
	for _, q := range f.spec.Queries {
		for _, p := range queryProfiles(q.Language, profiles) {
			if len(q.Profiles) > 0 && !slices.Contains(q.Profiles, p) {
				continue
			}
			q := q
			run(p+"/"+q.ID, func() string { return f.query(p, q) })
		}
	}
	return steps
}

func queryProfiles(language string, runner []string) []string {
	if language == "logql" {
		return []string{"logql-loki-3.5.2"}
	}
	return runner
}

func (f *adapterFeed) query(profileID string, q feedQuery) string {
	at := (f.anchor + q.AtMS) * 1e6
	body := f.env.QueryBody(q.Language, profileID, q.Expression, at, f.project)
	body["min_cursors"] = f.fence.list()
	if q.Streams {
		body["evaluation"] = map[string]any{"instant": false, "time": "0", "start": decimal(f.anchorNS() - 1e9), "end": decimal(f.anchorNS() + 300e9), "step": "1000000000"}
		body["log_order"] = "forward"
		if q.Order != "" {
			body["log_order"] = q.Order
		}
		if q.Limit > 0 {
			body["log_limit"] = decimal(int64(q.Limit))
		}
	}
	code, out := f.env.Post(f.env.People["reader"], "/api/v1/query", body)
	if code != 200 {
		return fmt.Sprintf("status %d %s", code, trim(out))
	}
	if q.Streams {
		var res query.Result
		check(json.Unmarshal(out, &res))
		if len(res.Projects) != 1 || res.Projects[0].Value == nil || res.Projects[0].Completeness != query.CompletenessComplete {
			return "the query did not answer completely: " + trim(out)
		}
		var got []string
		last := model.UnixNano(0)
		for _, s := range res.Projects[0].Value.Streams {
			for _, e := range s.Entries {
				if q.Order != "backward" && e.Time < last {
					return fmt.Sprintf("forward order violated at %d", e.Time)
				}
				last = e.Time
				for range int(e.Multiplicity) {
					got = append(got, fmt.Sprintf("%d|%s", int64(e.Time)-f.anchorNS(), e.Line))
				}
			}
		}
		var want []string
		for _, l := range q.ExpectLines {
			want = append(want, fmt.Sprintf("%d|%s", l.TNS, l.Line))
		}
		if q.Order == "" {
			sort.Strings(got)
			sort.Strings(want)
		}
		if fmt.Sprint(got) != fmt.Sprint(want) {
			return fmt.Sprintf("entries %v, authored %v", got, want)
		}
		return ""
	}
	got := f.env.projectVector(out)[f.project]
	want := append([]string(nil), q.ExpectBits...)
	sort.Strings(want)
	if fmt.Sprint(got) != fmt.Sprint(want) {
		return fmt.Sprintf("got %v want %v", got, want)
	}
	return ""
}

// feedLibrary is one shared series with its authored queries.
type feedLibrary struct {
	Name    string            `json:"name"`
	Labels  map[string]string `json:"labels"`
	Samples []feedSample      `json:"samples"`
	Queries []feedQuery       `json:"queries"`
}

// expandLibrary resolves a feed's library references into its series and
// queries.
func expandLibrary(spec adapterFeedSpec, lib []feedLibrary) adapterFeedSpec {
	for _, name := range spec.Library {
		found := false
		for _, l := range lib {
			if l.Name != name {
				continue
			}
			found = true
			spec.Series = append(spec.Series, feedSeries{Name: spec.Prefix + l.Name, Labels: l.Labels, Samples: l.Samples})
			for _, q := range l.Queries {
				q.Expression = strings.ReplaceAll(q.Expression, "{p}", spec.Prefix)
				spec.Queries = append(spec.Queries, q)
			}
		}
		checkf(found, "feed %s: unknown library series %s", spec.ID, name)
	}
	return spec
}

// directBatches builds the feed's records as fixed ingest batches (one per
// record), so a retry re-sends byte-identical batches.
func (f *adapterFeed) directBatches() {
	for _, s := range f.spec.Streams {
		tpl := f.src.logTemplate
		checkf(tpl != nil, "feed %s: source %s has no log template", f.spec.ID, f.spec.Source)
		ls := model.Labels{}
		for _, k := range sortedLabelNames(s.Labels) {
			ls = append(ls, model.Label{Name: k, Value: s.Labels[k]})
		}
		for _, l := range s.Lines {
			var v model.Scalar
			check(json.Unmarshal([]byte(fmt.Sprintf("%q", l.Line)), &v))
			ts := model.UnixNano(f.anchorNS() + l.TNS)
			rec := model.Record{ID: model.NewID(), Kind: model.Log, ObservedAt: ts, Resource: f.src.Resource, Payload: model.Payload{Log: &model.LogRecord{
				Timestamp: &ts, TemplateID: tpl.ID, TemplateRevision: tpl.Revision, Fields: map[string]model.Scalar{tpl.Fields[0].Name: v},
				StreamLabels: ls, Metadata: map[string]model.Scalar{}}}}
			f.direct = append(f.direct, f.directBatch(rec))
		}
	}
	for _, s := range f.spec.Series {
		for _, sm := range s.Samples {
			ts := (f.anchor + sm.TMS) * 1e6
			var rec model.Record
			if sm.Histogram != nil {
				ls := model.Labels{}
				for _, k := range sortedLabelNames(s.Labels) {
					ls = append(ls, model.Label{Name: k, Value: s.Labels[k]})
				}
				kind := "float_histogram"
				if sm.Histogram.Integer != nil {
					kind = "integer_histogram"
				}
				h := *sm.Histogram
				rec = model.Record{ID: model.NewID(), Kind: model.Metric, ObservedAt: model.UnixNano(ts), Resource: f.src.Resource,
					Payload: model.Payload{Metric: &model.MetricPoint{Name: s.Name, Labels: ls, SampleKind: kind, Histogram: &h, Unit: "1", Type: "histogram"}}}
			} else {
				rec = f.env.MetricRecord(f.src, s.Name, s.Labels, ts, mustHex(sm.Bits), nil)
			}
			f.direct = append(f.direct, f.directBatch(rec))
		}
	}
}

func (f *adapterFeed) directBatch(rec model.Record) model.Batch {
	batch := model.Batch{Version: 1, Project: f.env.Projects[f.src.Project], Source: f.src.ID, Producer: model.NewID(), ID: model.NewID(), PolicyRevision: 1, Records: []model.Record{rec}}
	var err error
	batch.RouteSlot, err = model.OwnerSlot(f.env.org, batch.Project, f.src.ID, batch.Producer, rec)
	check(err)
	return batch
}

// directAdmit posts the fixed batches to the ingest route of the feed's node.
func (f *adapterFeed) directAdmit() feedAdmission {
	a := feedAdmission{Status: 200}
	base, client := f.env.endpoint(f.node)
	for _, batch := range f.direct {
		raw, err := json.Marshal(batch)
		check(err)
		req, err := http.NewRequestWithContext(f.env.ctx, "POST", base+"/ingest/v1/batches", bytes.NewReader(raw))
		check(err)
		req.Header.Set("Authorization", "Bearer "+f.src.Credential)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		check(err)
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		checkf(resp.StatusCode == 200, "feed %s: ingest answered %d: %s", f.spec.ID, resp.StatusCode, trim(body))
		var receipt model.Receipt
		check(json.Unmarshal(body, &receipt))
		checkf(receipt.BatchID == batch.ID, "feed %s: receipt names a different batch", f.spec.ID)
		a.IDs = append(a.IDs, batch.ID.String())
		a.Records += len(batch.Records)
		a.Cursors = append(a.Cursors, receipt.Cursor)
	}
	return a
}

// adapterHooks admits every feed of the section and returns the hooks that
// re-check them at each persisted stage. kind names the feeds' steps and
// persistence scenarios ("adapter", "native").
func adapterHooks(env *Env, sec *adaptersSection, profiles []string, kind string) []persistedHook {
	if len(sec.Feeds) == 0 {
		return nil
	}
	sec.Fixture.Load(env)
	for person, perms := range sec.Grants {
		for _, p := range sec.Fixture.Projects {
			env.Grant(person, p, true, perms...)
		}
	}
	project := sec.Fixture.Projects[0]
	anchor := (time.Now().UnixMilli() - 20*60*1000) / 60000 * 60000
	sec.anchorMS = anchor
	fence := &cursorSet{}
	var feeds []*adapterFeed
	for i, spec := range sec.Feeds {
		spec = expandLibrary(spec, sec.Library)
		src := env.Sources[spec.Source]
		checkf(src != nil, "feed %s: unknown source %s", spec.ID, spec.Source)
		f := &adapterFeed{spec: spec, env: env, project: project, src: src, anchor: anchor, fence: fence, kind: kind}
		if env.layout == Distributed {
			f.node = uint64(i%3) + 1
		}
		f.prepare()
		f.first = f.admit()
		for _, c := range f.first.Cursors {
			fence.add(c)
		}
		feeds = append(feeds, f)
	}
	var hooks []persistedHook
	for _, f := range feeds {
		f := f
		hooks = append(hooks, persistedHook{
			name: kind + "-" + f.spec.ID,
			resend: func() {
				r := f.admit()
				f.retried = &r
			},
			check: func(stage string) []StepResult { return f.check(stage, profiles) },
			close: f.close,
		})
	}
	return hooks
}
