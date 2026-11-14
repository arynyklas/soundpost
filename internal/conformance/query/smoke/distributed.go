// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package smoke

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query"
	"github.com/arynyklas/soundpost/internal/smokecluster"
)

// The distributed scenario runs on three real voters (Distributed layout) and
// asserts what the C05/C06 contracts promise across nodes. Every expectation
// below is authored from the fixture and from those promises:
//
//   - a batch acknowledged through any voter is readable through every voter
//     (and a read fenced on its receipt cursor never answers short);
//   - the owned PromQL, LogQL, discovery and live routes answer on every voter;
//   - project isolation and revocation hold on every voter;
//   - with one voter gone (even the leader) the survivors keep answering and
//     acknowledging, every earlier acknowledgement stays readable, and an
//     election window yields errors without values, never an apparently
//     complete empty answer;
//   - without a quorum nothing is acknowledged and a read is an error (or, when
//     partial results are allowed, honestly marked incomplete), never a
//     complete success;
//   - restarted voters rejoin, catch up and converge on identical data, and
//     every acknowledged receipt is returned unchanged by every voter.

const (
	promProfile = "promql-prometheus-3.13.5"
	logProfile  = "logql-loki-3.5.2"
	bits1       = 0x3ff0000000000000 // 1
	bits2       = 0x4000000000000000 // 2
	bits3       = 0x4008000000000000 // 3
	bits4       = 0x4010000000000000 // 4
	bits100     = 0x4059000000000000 // 100
	second      = int64(1_000_000_000)
)

// ackedMetric is one acknowledged float sample and its receipt.
type ackedMetric struct {
	project string
	record  model.ID
	name    string
	labels  string
	time    string
	bits    string
	batch   model.Batch
	source  *Source
	receipt model.Receipt
}

// answer is one HTTP answer of a query route.
type answer struct {
	code int
	raw  []byte
	res  query.Result
}

// hasValue reports whether a body carries an evaluated value of any kind.
func (a answer) hasValue() bool {
	return bytes.Contains(a.raw, []byte(`"vector"`)) || bytes.Contains(a.raw, []byte(`"float"`)) || bytes.Contains(a.raw, []byte(`"streams"`)) || bytes.Contains(a.raw, []byte(`"matrix"`))
}

func (e *Env) ask(node uint64, who *Person, body map[string]any) answer {
	code, raw := e.PostAt(node, who, "/api/v1/query", body)
	a := answer{code: code, raw: raw}
	if code == 200 {
		check(json.Unmarshal(raw, &a.res))
	}
	return a
}

// floats returns the sorted float bits of project's vector.
func floats(pr query.ProjectResult) []string {
	var out []string
	if pr.Value != nil {
		for _, v := range pr.Value.Vector {
			if v.Sample.Float != nil {
				out = append(out, fmt.Sprintf("%016x", uint64(*v.Sample.Float)))
			}
		}
	}
	sort.Strings(out)
	return out
}

// verdict classifies an answer against the one complete answer that is correct:
// ok (that answer), unavailable (an error without any value) or a violation
// (anything else: an empty, short or incomplete success, or an error that
// carries a value).
func (e *Env) verdict(a answer, project string, want []string) (ok bool, violation string) {
	if a.code != 200 {
		if a.hasValue() {
			return false, fmt.Sprintf("status %d carries a value: %s", a.code, trim(a.raw))
		}
		return false, ""
	}
	if len(a.res.Projects) != 1 || a.res.Projects[0].ProjectID != e.Projects[project] {
		return false, fmt.Sprintf("answer names %d projects: %s", len(a.res.Projects), trim(a.raw))
	}
	pr := a.res.Projects[0]
	if pr.Failure != nil || pr.Completeness != query.CompletenessComplete || pr.Value == nil {
		return false, fmt.Sprintf("a 200 answer that is not complete (completeness %q, failure %v)", pr.Completeness, pr.Failure)
	}
	if got := floats(pr); fmt.Sprint(got) != fmt.Sprint(want) {
		return false, fmt.Sprintf("complete answer %v, want %v", got, want)
	}
	return true, ""
}

// mustAnswer requires the complete correct answer on node right now.
func (e *Env) mustAnswer(node uint64, who *Person, body map[string]any, project string, want []string) {
	a := e.ask(node, who, body)
	ok, violation := e.verdict(a, project, want)
	checkf(violation == "", "node %d: %s", node, violation)
	checkf(ok, "node %d answered %d: %s", node, a.code, trim(a.raw))
}

// eventually polls until node gives the complete correct answer. Every answer on
// the way is classified: an error must carry no value, a success must be the
// complete correct one. It returns how many attempts were refused honestly.
func (e *Env) eventually(node uint64, who *Person, body map[string]any, project string, want []string, within time.Duration) (refused int, took time.Duration) {
	start := time.Now()
	for {
		a := e.ask(node, who, body)
		ok, violation := e.verdict(a, project, want)
		checkf(violation == "", "node %d: %s", node, violation)
		if ok {
			return refused, time.Since(start)
		}
		refused++
		checkf(time.Since(start) < within, "node %d never answered completely within %v (last status %d: %s)", node, within, a.code, trim(a.raw))
		time.Sleep(200 * time.Millisecond)
	}
}

func (e *Env) promBody(expression string, at int64, project string, acked []ackedMetric) map[string]any {
	body := e.QueryBody("promql", promProfile, expression, at, project)
	if len(acked) > 0 {
		body["min_cursors"] = cursorsOf(acked)
	}
	return body
}

// cursorsOf is the read fence of a set of acknowledgements: the highest receipt
// cursor of every group (a request names each group at most once).
func cursorsOf(acked []ackedMetric) []model.Cursor {
	best := map[model.ID]model.Cursor{}
	var order []model.ID
	for _, a := range acked {
		c := a.receipt.Cursor
		cur, seen := best[c.Group]
		if !seen {
			order = append(order, c.Group)
		}
		if !seen || c.Index > cur.Index {
			best[c.Group] = c
		}
	}
	out := make([]model.Cursor, 0, len(order))
	for _, g := range order {
		out = append(out, best[g])
	}
	return out
}

// metric sends one float sample through node and returns what was acknowledged.
func (e *Env) metric(node uint64, s *Source, name, labelValue string, timeNS int64, bits uint64) ackedMetric {
	rec := e.MetricRecord(s, name, map[string]string{"job": labelValue}, timeNS, bits, nil)
	code, body, batch := e.SendBatch(node, s, rec)
	checkf(code == 200, "node %d did not acknowledge: %d %s", node, code, trim(body))
	var receipt model.Receipt
	check(json.Unmarshal(body, &receipt))
	checkf(receipt.BatchID == batch.ID, "receipt names a different batch")
	return ackedMetric{project: s.Project, record: rec.ID, name: name, labels: "job=" + labelValue, time: decimal(timeNS), bits: fmt.Sprintf("%016x", bits), batch: batch, source: s, receipt: receipt}
}

func (e *Env) row(a ackedMetric) storedRow {
	return storedRow{Project: a.project, Name: a.name, Labels: a.labels, Time: a.time, Bits: a.bits}
}

// receiptAt asks node for the original receipt of an acknowledged batch.
func (e *Env) receiptAt(node uint64, a ackedMetric) (int, model.Receipt) {
	raw, _ := json.Marshal(model.ReceiptRequest{Source: a.batch.Source, Producer: a.batch.Producer, RouteSlot: a.batch.RouteSlot, BatchID: a.receipt.BatchID, OriginalHash: a.receipt.Hash})
	base, client := e.endpoint(node)
	req, _ := http.NewRequest("POST", base+"/ingest/v1/receipts", bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+a.source.Credential)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	check(err)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var receipt model.Receipt
	if resp.StatusCode == 200 {
		check(json.Unmarshal(body, &receipt))
	}
	return resp.StatusCode, receipt
}

func (e *Env) logLine(node uint64, s *Source, name string) ackedMetric {
	var v model.Scalar
	check(json.Unmarshal([]byte(`"`+name+`"`), &v))
	e.tick++
	ts := model.UnixNano(e.tick)
	rec := model.Record{ID: model.NewID(), Kind: model.Log, ObservedAt: ts, Resource: s.Resource, Payload: model.Payload{Log: &model.LogRecord{Timestamp: &ts, TemplateID: "signin", TemplateRevision: 1, Fields: map[string]model.Scalar{"name": v}, StreamLabels: model.Labels{{Name: "app", Value: "web"}}, Metadata: map[string]model.Scalar{}}}}
	code, body, batch := e.SendBatch(node, s, rec)
	checkf(code == 200, "node %d did not acknowledge the log line: %d %s", node, code, trim(body))
	var receipt model.Receipt
	check(json.Unmarshal(body, &receipt))
	return ackedMetric{project: s.Project, record: rec.ID, batch: batch, source: s, receipt: receipt}
}

// probePeer opens a TLS connection to a voter's peer listener with the given
// client certificate (nil: none) and reports whether the listener kept the
// connection (a valid peer) or tore it down (a refused one).
func probePeer(address string, certificate *tls.Certificate) (accepted bool, detail string) {
	config := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}
	if certificate != nil {
		config.Certificates = []tls.Certificate{*certificate}
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", address, config)
	if err != nil {
		return false, err.Error()
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
	_, err = conn.Read(make([]byte, 1))
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() {
		return true, "handshake accepted; the listener waits for a request"
	}
	return false, fmt.Sprint(err)
}

func loadPair(certificate, key string) *tls.Certificate {
	pair, err := tls.LoadX509KeyPair(certificate, key)
	check(err)
	return &pair
}

// RunDistributed executes the cross-node scenario on a fresh three-voter
// installation in dir. The caller prefixes the layout in the report; every step
// name is stable.
func RunDistributed(ctx context.Context, dir string) (steps []StepResult, err error) {
	defer recoverFailure(&err)
	env, err := NewEnv(ctx, Distributed, dir)
	check(err)
	defer env.Close()
	c := env.Cluster()

	env.AddProject("project-a")
	env.AddProject("project-b")
	reader, sibling := env.AddPerson("reader"), env.AddPerson("sibling-reader")
	env.Grant("reader", "project-a", true, "telemetry.read")
	env.Grant("sibling-reader", "project-b", true, "telemetry.read")
	metricA := env.AddSource(SourceSpec{Name: "metric-a", Project: "project-a", Kinds: []model.Kind{model.Metric}, Labels: map[string][]string{"job": {"api"}}})
	metricB := env.AddSource(SourceSpec{Name: "metric-b", Project: "project-b", Kinds: []model.Kind{model.Metric}, Labels: map[string][]string{"job": {"api"}}})
	var names []model.Scalar
	for _, n := range []string{"alice", "bob", "carol", "dave", "erin", "frank"} {
		var v model.Scalar
		check(json.Unmarshal([]byte(`"`+n+`"`), &v))
		names = append(names, v)
	}
	tpl := model.LogTemplate{ID: "signin", Revision: 1, Line: "user {name} signed in", Severity: "info", Fields: []model.TemplateField{{Name: "name", Type: "string", MaxBytes: 16, Sensitivity: "metadata", Values: names}}}
	logsA := env.AddSource(SourceSpec{Name: "logs-a", Project: "project-a", Kinds: []model.Kind{model.Log}, Labels: map[string][]string{"app": {"web"}}, Logs: &tpl})

	var acked []ackedMetric
	var ackedLogs []ackedMetric
	var detail string
	run := func(name string, f func()) {
		result := StepResult{Name: name}
		detail = ""
		func() {
			defer func() {
				switch r := recover().(type) {
				case nil:
				case failure:
					result.Detail = r.err.Error()
				default:
					panic(r)
				}
			}()
			f()
			result.Passed = true
			result.Detail = detail
		}()
		steps = append(steps, result)
	}
	allNodes := []uint64{1, 2, 3}

	run("three-voters-joined-over-mtls", func() {
		deadline := time.Now().Add(20 * time.Second)
		for {
			leaders := map[string]map[uint64]bool{}
			var problem string
			for _, id := range allNodes {
				app := env.NodeApp(id)
				status := app.ReplicationStatus()
				if len(status) != 65 {
					problem = fmt.Sprintf("node %d serves %d groups, want 65 (control + 64 data)", id, len(status))
					break
				}
				for _, g := range status {
					if g.Failed || g.ID != id || len(g.Members.Nodes) != 3 {
						problem = fmt.Sprintf("node %d group %s: failed=%v id=%d voters=%d", id, g.Group, g.Failed, g.ID, len(g.Members.Nodes))
					}
					for _, m := range g.Members.Nodes {
						if m.Learner {
							problem = fmt.Sprintf("node %d group %s: a learner is a voter", id, g.Group)
						}
					}
					if g.Leader == 0 {
						problem = fmt.Sprintf("node %d group %s has no leader", id, g.Group)
					}
					key := g.Group.String()
					if leaders[key] == nil {
						leaders[key] = map[uint64]bool{}
					}
					leaders[key][g.Leader] = true
				}
			}
			if problem == "" {
				for group, set := range leaders {
					if len(set) != 1 {
						problem = fmt.Sprintf("group %s has diverging leaders %v", group, set)
					}
				}
			}
			if problem == "" {
				break
			}
			checkf(time.Now().Before(deadline), "%s", problem)
			time.Sleep(200 * time.Millisecond)
		}
		// The peer listener demands a client certificate of the cluster CA.
		foreign := filepath.Join(dir, "foreign-ca")
		check(os.MkdirAll(foreign, 0o700))
		_, foreignPairs, err := smokecluster.Certificates(foreign)
		check(err)
		_, certificate, key := c.Identity(2)
		cases := []struct {
			name   string
			cert   *tls.Certificate
			accept bool
		}{
			{"a peer certificate of the cluster CA", loadPair(certificate, key), true},
			{"no client certificate", nil, false},
			{"a certificate of a foreign CA", loadPair(foreignPairs[2][0], foreignPairs[2][1]), false},
		}
		for _, id := range allNodes {
			for _, tc := range cases {
				accepted, detail := probePeer(c.ListenAddress(id), tc.cert)
				checkf(accepted == tc.accept, "node %d peer listener, %s: accepted=%v (%s), want %v", id, tc.name, accepted, detail, tc.accept)
			}
		}
		detail = "3 voters, 65 groups each, one leader per group on every node; the peer listener accepts the cluster CA identity and refuses a missing or foreign client certificate"
	})

	run("write-through-node-1-is-readable-on-every-node", func() {
		acked = append(acked, env.metric(1, metricA, "m", "api", 10*second, bits1))
		acked = append(acked, env.metric(1, metricA, "m", "api", 20*second, bits2))
		acked = append(acked, env.metric(1, metricB, "m", "api", 10*second, bits100))
		for _, id := range allNodes {
			env.mustAnswer(id, reader, env.promBody("m", 25*second, "project-a", acked), "project-a", []string{fmt.Sprintf("%016x", uint64(bits2))})
			env.mustAnswer(id, sibling, env.promBody("m", 25*second, "project-b", acked), "project-b", []string{fmt.Sprintf("%016x", uint64(bits100))})
		}
	})

	run("write-through-a-follower-is-readable-on-every-node", func() {
		acked = append(acked, env.metric(2, metricA, "m", "api", 30*second, bits3))
		for _, id := range allNodes {
			env.mustAnswer(id, reader, env.promBody("m", 35*second, "project-a", acked), "project-a", []string{fmt.Sprintf("%016x", uint64(bits3))})
		}
	})

	run("discovery-and-format-routes-answer-on-every-node", func() {
		for _, id := range allNodes {
			code, out := env.PostAt(id, reader, "/api/v1/discover", map[string]any{"org": env.org.String(), "projects": []string{env.Projects["project-a"].String()}, "signal": "metric", "kind": "metric_names", "matchers": []any{}, "time": map[string]string{"start": "0", "end": decimal(60 * second)}, "limit": 100})
			checkf(code == 200, "node %d discovery answered %d: %s", id, code, trim(out))
			var d query.DiscoveryResult
			check(json.Unmarshal(out, &d))
			checkf(fmt.Sprint(d.Items) == "[m]" && !d.More && d.Freshness.Completeness == query.CompletenessComplete, "node %d discovery %v more=%v completeness=%q", id, d.Items, d.More, d.Freshness.Completeness)
			code, out = env.PostAt(id, reader, "/api/v1/query/format", map[string]any{"org": env.org.String(), "language": "promql", "profile": promProfile, "feature_set": env.Features[promProfile], "expression": "sum   (m )", "projects": []string{env.Projects["project-a"].String()}})
			checkf(code == 200, "node %d format answered %d: %s", id, code, trim(out))
			var f query.FormatResult
			check(json.Unmarshal(out, &f))
			checkf(f.Formatted == "sum(m)", "node %d formatted %q", id, f.Formatted)
		}
	})

	logCount := func(node uint64, at int64, bits uint64) {
		body := env.QueryBody("logql", logProfile, `count_over_time({app="web"}[1h])`, at, "project-a")
		body["min_cursors"] = cursorsOf(ackedLogs)
		env.mustAnswer(node, reader, body, "project-a", []string{fmt.Sprintf("%016x", bits)})
	}
	run("logql-query-answers-on-every-node", func() {
		ackedLogs = append(ackedLogs, env.logLine(1, logsA, "alice"))
		ackedLogs = append(ackedLogs, env.logLine(1, logsA, "bob"))
		ackedLogs = append(ackedLogs, env.logLine(2, logsA, "carol"))
		for _, id := range allNodes {
			logCount(id, second, bits3)
		}
	})

	run("live-stream-on-a-follower-delivers-writes-of-other-nodes", func() {
		body := map[string]any{"org": env.org.String(), "profile": logProfile, "feature_set": env.Features[logProfile], "expression": `{app="web"}`, "projects": []string{env.Projects["project-a"].String()}, "budget": map[string]any{"timeout_ns": "0", "memory_bytes": "0", "max_returned": "10"}}
		code, out := env.PostAt(3, reader, "/api/v1/live-tickets", body)
		checkf(code == 200, "node 3 live ticket answered %d: %s", code, trim(out))
		var t struct {
			Ticket string `json:"ticket"`
		}
		check(json.Unmarshal(out, &t))
		stream := env.openStreamAt(3, reader, t.Ticket, "")
		defer func() { stream.cancel(); <-stream.ended }()
		checkf(stream.status == 200, "node 3 stream status %d", stream.status)
		ev, ok := stream.next(10 * time.Second)
		checkf(ok && ev.Event == "open" && ev.Data.StreamID != "", "node 3 stream first event %+v", ev)
		ackedLogs = append(ackedLogs, env.logLine(2, logsA, "dave"))
		ackedLogs = append(ackedLogs, env.logLine(1, logsA, "erin"))
		// A subscription made on a follower reads the quorum cut group by group; a
		// commit of any kind that lands in that window is reported as one explicit
		// feed_catch_up gap BEFORE the first record (commits that predate the
		// subscription). That is the only gap the contract allows here: our two
		// records, written after the stream opened, must each still arrive once,
		// in order, with consecutive sequence ids and no later gap.
		wantLines := []string{"user dave signed in", "user erin signed in"}
		var prev int
		for len(wantLines) > 0 {
			ev, ok := stream.next(10 * time.Second)
			checkf(ok, "stream ended or stalled waiting for %q", wantLines[0])
			var id int
			_, err := fmt.Sscan(ev.ID, &id)
			checkf(err == nil && id == prev+1, "event id %q does not follow %d", ev.ID, prev)
			prev = id
			if ev.Event == "gap" {
				checkf(len(wantLines) == 2 && ev.Data.Gap != nil && ev.Data.Gap.Reason == "feed_catch_up", "an unexpected gap: %+v", ev.Data)
				continue
			}
			checkf(ev.Event == "record" && ev.Data.Entry != nil && ev.Data.Entry.Line == wantLines[0], "got %s id=%s %+v want record %q", ev.Event, ev.ID, ev.Data, wantLines[0])
			wantLines = wantLines[1:]
		}
		if late, got := stream.silent(500 * time.Millisecond); got {
			checkf(false, "an extra event followed: %s %+v", late.Event, late.Data)
		}
	})

	run("foreign-project-fails-closed-on-every-node", func() {
		for _, id := range allNodes {
			foreignBody := env.promBody("m", 25*second, "project-a", nil)
			code, out := env.PostAt(id, sibling, "/api/v1/query", foreignBody)
			checkf(code == 404, "node %d: a sibling reading a foreign project answered %d: %s", id, code, trim(out))
			var f struct {
				Code string `json:"code"`
			}
			check(json.Unmarshal(out, &f))
			checkf(f.Code == "not_found" && !answer{raw: out}.hasValue(), "node %d: foreign-project answer %s", id, trim(out))
			ghost := env.promBody("m", 25*second, "project-a", nil)
			ghost["projects"] = []string{model.NewID().String()}
			gcode, gout := env.PostAt(id, sibling, "/api/v1/query", ghost)
			checkf(gcode == code && stripVolatile(gout) == stripVolatile(out), "node %d: a foreign project is distinguishable from a nonexistent one: %d %s vs %d %s", id, code, trim(out), gcode, trim(gout))
		}
	})

	run("revocation-reaches-every-node", func() {
		env.Grant("reader", "project-a", false, "telemetry.read")
		for _, id := range allNodes {
			code, out := env.PostAt(id, reader, "/api/v1/query", env.promBody("m", 35*second, "project-a", nil))
			checkf(code == 404 && !(answer{raw: out}).hasValue(), "node %d still answered a revoked reader: %d %s", id, code, trim(out))
		}
		env.Grant("reader", "project-a", true, "telemetry.read")
		for _, id := range allNodes {
			env.mustAnswer(id, reader, env.promBody("m", 35*second, "project-a", acked), "project-a", []string{fmt.Sprintf("%016x", uint64(bits3))})
		}
	})

	var url1 string
	wantAt45 := []string{fmt.Sprintf("%016x", uint64(bits4))}
	run("leader-loss-survivors-answer-completely-and-acknowledge", func() {
		url1 = env.surfaces[1].server.URL
		check(env.StopNode(1))
		conn, err := net.DialTimeout("tcp", strings.TrimPrefix(url1, "https://"), time.Second)
		if err == nil {
			conn.Close()
		}
		checkf(err != nil, "node 1 still accepts connections after it was stopped")
		var refused []string
		for _, id := range []uint64{2, 3} {
			n, took := env.eventually(id, reader, env.promBody("m", 35*second, "project-a", acked), "project-a", []string{fmt.Sprintf("%016x", uint64(bits3))}, 60*time.Second)
			refused = append(refused, fmt.Sprintf("node %d: %d honest refusals, complete after %v", id, n, took.Round(time.Millisecond)))
		}
		// New writes are acknowledged by the survivors (a new leader is elected).
		deadline := time.Now().Add(60 * time.Second)
		var fresh ackedMetric
		for {
			rec := env.MetricRecord(metricA, "m", map[string]string{"job": "api"}, 40*second, bits4, nil)
			code, body, batch := env.SendBatch(3, metricA, rec)
			if code == 200 {
				var receipt model.Receipt
				check(json.Unmarshal(body, &receipt))
				fresh = ackedMetric{project: "project-a", record: rec.ID, name: "m", labels: "job=api", time: decimal(40 * second), bits: fmt.Sprintf("%016x", uint64(bits4)), batch: batch, source: metricA, receipt: receipt}
				break
			}
			checkf(code == 503, "a refused write answered %d, want 503: %s", code, trim(body))
			checkf(time.Now().Before(deadline), "the survivors never acknowledged a write after the leader was lost")
			time.Sleep(200 * time.Millisecond)
		}
		acked = append(acked, fresh)
		for _, id := range []uint64{2, 3} {
			env.mustAnswer(id, reader, env.promBody("m", 45*second, "project-a", acked), "project-a", wantAt45)
		}
		detail = strings.Join(refused, "; ")
	})

	run("below-quorum-nothing-is-acknowledged-and-reads-fail-closed", func() {
		check(env.StopNode(3))
		var parts []string
		code, body, _ := env.SendBatch(2, metricA, env.MetricRecord(metricA, "m", map[string]string{"job": "api"}, 50*second, bits1, nil))
		checkf(code == 503, "a write on a node without quorum answered %d, want 503: %s", code, trim(body))
		parts = append(parts, "write refused 503")
		start := time.Now()
		a := env.ask(2, reader, env.promBody("m", 45*second, "project-a", acked))
		checkf(a.code != 200 && !a.hasValue(), "a read without quorum answered %d with a value or success: %s", a.code, trim(a.raw))
		parts = append(parts, fmt.Sprintf("read refused %d after %v with no value", a.code, time.Since(start).Round(time.Millisecond)))
		partialBody := env.promBody("m", 45*second, "project-a", acked)
		partialBody["allow_partial"] = true
		start = time.Now()
		p := env.ask(2, reader, partialBody)
		switch {
		case p.code != 200:
			checkf(!p.hasValue(), "a partial-allowed read without quorum failed %d but carries a value: %s", p.code, trim(p.raw))
			parts = append(parts, fmt.Sprintf("allow_partial read refused %d with no value after %v", p.code, time.Since(start).Round(time.Millisecond)))
		default:
			for _, pr := range p.res.Projects {
				checkf(pr.Completeness != query.CompletenessComplete, "a partial-allowed read without quorum was reported complete: %s", trim(p.raw))
			}
			parts = append(parts, "allow_partial read answered 200 marked "+p.res.Projects[0].Completeness)
		}
		detail = strings.Join(parts, "; ")
	})

	run("restarted-voters-rejoin-and-converge-on-every-acknowledgement", func() {
		check(env.StartNodes(1, 3))
		check(env.reauthenticate())
		for _, id := range allNodes {
			env.eventually(id, reader, env.promBody("m", 45*second, "project-a", acked), "project-a", wantAt45, 60*time.Second)
		}
		want := map[storedRow]bool{}
		for _, a := range acked {
			if a.name != "" {
				want[env.row(a)] = true
			}
		}
		var reference []storedRow
		for _, id := range allNodes {
			var rows []storedRow
			for _, project := range []string{"project-a", "project-b"} {
				var mine []ackedMetric
				for _, a := range acked {
					if a.project == project {
						mine = append(mine, a)
					}
				}
				fence := cursorsOf(mine)
				rows = append(rows, env.scanMetricsOn(env.NodeApp(id), project, fence)...)
			}
			stored := distinct(rows)
			have := map[storedRow]bool{}
			for _, r := range stored {
				have[r] = true
			}
			for r := range want {
				checkf(have[r], "node %d lost the acknowledged sample %v", id, r)
			}
			if reference == nil {
				reference = stored
			} else {
				checkf(fmt.Sprint(reference) == fmt.Sprint(stored), "node %d holds %v, node 1 holds %v", id, stored, reference)
			}
		}
		for _, a := range acked {
			for _, id := range allNodes {
				code, got := env.receiptAt(id, a)
				checkf(code == 200, "node %d answered %d for the receipt of an acknowledged batch", id, code)
				got.Historical = false
				left, _ := json.Marshal(got)
				right, _ := json.Marshal(a.receipt)
				checkf(string(left) == string(right), "node %d returned a changed original receipt", id)
			}
		}
		detail = fmt.Sprintf("%d acknowledged samples present and identical on 3 nodes; %d original receipts unchanged on every node", len(want), len(acked))
	})

	run("teardown-releases-everything-on-every-node", func() {
		for _, id := range allNodes {
			app := env.NodeApp(id)
			waitFor(func() bool {
				u, l := app.Query.Usage(), app.Live.Usage()
				return app.Storage.Stats().ActiveIterators == 0 && u.OpenIterators == 0 && u.MemoryUsed == 0 && u.ActiveQueries == 0 && u.QueuedQueries == 0 && u.LeakedBytes == 0 && u.OverReleasedBytes == 0 &&
					l.OpenIterators == 0 && l.MemoryUsed == 0 && l.Streams == 0 && l.Goroutines == 0
			}, fmt.Sprintf("node %d still holds iterators, memory, streams or goroutines", id))
		}
	})
	return steps, nil
}
