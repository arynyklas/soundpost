// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package acceptance

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"io/fs"
	"math"
	"net/http"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/profiles"
)

// pbWriter is the smallest protobuf writer the Prometheus remote-write schema needs.
type pbWriter struct{ b []byte }

func (w *pbWriter) tag(num, wt uint64) { w.b = binary.AppendUvarint(w.b, num<<3|wt) }
func (w *pbWriter) varint(num, v uint64) {
	w.tag(num, 0)
	w.b = binary.AppendUvarint(w.b, v)
}
func (w *pbWriter) fixed64(num, v uint64) {
	w.tag(num, 1)
	w.b = binary.LittleEndian.AppendUint64(w.b, v)
}
func (w *pbWriter) bytes(num uint64, p []byte) {
	w.tag(num, 2)
	w.b = binary.AppendUvarint(w.b, uint64(len(p)))
	w.b = append(w.b, p...)
}
func (w *pbWriter) msg(num uint64, f func(*pbWriter)) {
	var inner pbWriter
	f(&inner)
	w.bytes(num, inner.b)
}

// snappyLiterals encodes src as a snappy block of literals only (valid by the
// published format description).
func snappyLiterals(src []byte) []byte {
	out := binary.AppendUvarint(nil, uint64(len(src)))
	for len(src) > 0 {
		n := min(len(src), 60000)
		switch {
		case n <= 60:
			out = append(out, byte(n-1)<<2)
		case n <= 256:
			out = append(out, 60<<2, byte(n-1))
		default:
			out = append(out, 61<<2, byte((n-1)&0xff), byte((n-1)>>8))
		}
		out = append(out, src[:n]...)
		src = src[n:]
	}
	return out
}

// remoteWriteSample is a prometheus.WriteRequest with one sample of one series.
func remoteWriteSample(name string, tsMS int64, value float64) []byte {
	var req pbWriter
	req.msg(1, func(ts *pbWriter) {
		ts.msg(1, func(l *pbWriter) { l.bytes(1, []byte("__name__")); l.bytes(2, []byte(name)) })
		ts.msg(1, func(l *pbWriter) { l.bytes(1, []byte("job")); l.bytes(2, []byte("canary")) })
		ts.msg(2, func(s *pbWriter) { s.fixed64(1, math.Float64bits(value)); s.varint(2, uint64(tsMS)) })
	})
	return req.b
}

// remoteWrite posts one sample through the Prometheus remote-write input adapter
// with the source credential.
func (s *servedPipeline) remoteWrite(name string, at model.UnixNano, value float64) {
	n := s.n
	n.t.Helper()
	req, err := http.NewRequest(http.MethodPost, s.srv.URL+"/adapters/v1/prometheus/write", bytes.NewReader(snappyLiterals(remoteWriteSample(name, int64(at)/1e6, value))))
	if err != nil {
		n.t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+n.issued)
	req.Header.Set("Content-Type", "application/x-protobuf")
	req.Header.Set("Content-Encoding", "snappy")
	req.Header.Set("X-Prometheus-Remote-Write-Version", "0.1.0")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		n.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		n.t.Fatalf("remote write of %s: %d %s", name, resp.StatusCode, raw)
	}
}

// ruleRequest is one request to the real rule route as the organization
// administrator (the owner's session cookie and CSRF token over TLS: the console's
// authentication, which the route requires of an organization administrator).
func (s *servedPipeline) ruleRequest(session auth.Session, body map[string]any) (int, []byte) {
	n := s.n
	n.t.Helper()
	body["org"], body["project_id"] = n.org.String(), n.project.String()
	raw, err := json.Marshal(body)
	if err != nil {
		n.t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, s.tls.URL+"/api/v1/rules", bytes.NewReader(raw))
	if err != nil {
		n.t.Fatal(err)
	}
	req.Header.Set("Cookie", "__Host-soundpost="+session.Token)
	req.Header.Set("X-CSRF-Token", session.CSRF)
	req.Header.Set("Origin", s.tls.URL)
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.tls.Client().Do(req)
	if err != nil {
		n.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

// saveRule authors one alert rule over the rule route.
func (s *servedPipeline) saveRule(session auth.Session, expression string) model.ID {
	n := s.n
	n.t.Helper()
	id := model.NewID()
	status, raw := s.ruleRequest(session, map[string]any{"operation": "save", "command_id": model.NewID().String(),
		"rule_id": id.String(), "expected_revision": "0", "reason": "condition acceptance",
		"rule": map[string]any{"kind": "alert", "profile": "promql-prometheus-3.13.5", "feature_set": ruleFeatureSet(n.t), "expression": expression, "interval_seconds": 60, "severity": "critical"}})
	var answer httpapi.RuleWriteAnswer
	if status != http.StatusOK || json.Unmarshal(raw, &answer) != nil || answer.Rule.RuleID != id {
		n.t.Fatalf("saving %q over the rule route: %d %s", expression, status, raw)
	}
	return id
}

// ruleFeatureSet is the first feature set of the pinned query profile.
func ruleFeatureSet(t *testing.T) string {
	t.Helper()
	files, err := profiles.Query()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := fs.ReadFile(files, "promql-prometheus-3.13.5.json")
	if err != nil {
		t.Fatal(err)
	}
	var p struct {
		FeatureSets []struct {
			ID string `json:"id"`
		} `json:"feature_sets"`
	}
	if json.Unmarshal(raw, &p) != nil || len(p.FeatureSets) == 0 {
		t.Fatal("the pinned profile has no feature set")
	}
	return p.FeatureSets[0].ID
}

// conditions are the condition IDs of the project's condition books ("org:project:condition").
func (n *accNode) conditions() []string {
	n.t.Helper()
	var out []string
	if err := n.app.Control.View(n.ctx, func(st control.State) error {
		for key := range st.ConditionBooks {
			out = append(out, key[strings.LastIndex(key, ":")+1:])
		}
		return nil
	}); err != nil {
		n.t.Fatal(err)
	}
	return out
}

func (n *accNode) ruleBook(id model.ID) (control.RuleBook, bool) {
	n.t.Helper()
	book, found, err := n.app.Control.RuleBook(n.ctx, n.scope(), n.project, id)
	if err != nil {
		n.t.Fatal(err)
	}
	return book, found
}

func (n *accNode) retireRule(s *servedPipeline, session auth.Session, id model.ID) {
	n.t.Helper()
	status, raw := s.ruleRequest(session, map[string]any{"operation": "retire", "command_id": model.NewID().String(), "rule_id": id.String(), "expected_revision": "1", "reason": "condition acceptance"})
	if status != http.StatusOK {
		n.t.Fatalf("retiring a rule: %d %s", status, raw)
	}
}

func TestNotificationConditionThroughTheServedPipeline(t *testing.T) {
	eachServedLayout(t, servedPipelineCondition)
}

// servedPipelineCondition is the condition leg of the served-pipeline acceptance:
// a metric sample enters through the Prometheus remote-write input adapter ->
// ingest admission -> storage; an administrator authors alert rules over the rule
// route (control state, never injected into the workers); the leader-only workers
// list the catalogue, evaluate the due rules against what was admitted, commit
// the evaluation, open the condition of the firing rule, and the production
// notification routing decides one delivery to the organization's destination
// that the delivery worker hands to the provider exactly once. A rule the data
// does not satisfy opens nothing, and a retired rule stops with the next pass.
func servedPipelineCondition(t *testing.T, n *accNode) {
	catalogue, err := n.app.RuleCatalogue()
	if err != nil {
		t.Fatal(err)
	}
	s := n.serveWith(func(c *appcore.WorkerConfig) { c.Rules = catalogue })
	session, err := n.app.Auth.Login(n.ctx, accOwnerEmail, accOwnerPassword, "")
	if err != nil {
		t.Fatal(err)
	}

	// Data first, through the adapter. Admission is the only way it gets there.
	at := n.clock.Now() - model.UnixNano(90*sec)
	s.remoteWrite("queue_depth", at, 10)

	// With nothing authored a pass evaluates nothing and sends nothing.
	if rep := s.pass(); rep.Evaluated != 0 || len(n.conditions()) != 0 || len(n.prov.snapshot()) != 0 {
		t.Fatalf("a pass over an empty catalogue: %+v", rep)
	}

	firing := s.saveRule(session, "queue_depth > 5")
	quiet := s.saveRule(session, "queue_depth > 50")
	s.passUntil("the condition of the firing rule and its notification", func() bool {
		return len(n.conditions()) == 1 && len(n.prov.snapshot()) == 1
	})
	s.pass()
	s.pass()
	if kinds := n.prov.kinds(); len(kinds) != 1 {
		t.Fatalf("the condition was announced %v, want exactly one notification", kinds)
	}
	accepted := 0
	for _, r := range n.records() {
		if r.Phase == control.DeliveryAccepted && strings.Contains(r.Subject, n.conditions()[0]) {
			accepted++
		}
	}
	if accepted != 1 {
		t.Fatalf("%d accepted deliveries for the condition %v, want 1 (records %+v)", accepted, n.conditions(), n.records())
	}
	for _, id := range []model.ID{firing, quiet} {
		book, found := n.ruleBook(id)
		if !found || len(book.Versions) != 1 || book.Versions[0].Last == nil {
			t.Fatalf("rule %s was never evaluated by the workers: %+v", id, book)
		}
	}

	// Retired: the rule is not evaluated again and nothing more is announced.
	before, _ := n.ruleBook(firing)
	n.retireRule(s, session, firing)
	for range 3 {
		n.clock.add(60 * sec)
		s.pass()
	}
	after, _ := n.ruleBook(firing)
	if after.Versions[0].Last.At != before.Versions[0].Last.At {
		t.Fatalf("a retired rule was evaluated again: %d -> %d", before.Versions[0].Last.At, after.Versions[0].Last.At)
	}
	if len(n.prov.snapshot()) != 1 {
		t.Fatalf("after the retirement the provider saw %v", n.prov.kinds())
	}
	t.Logf("served condition on %s: provider sends %v, conditions %v", n.layout, n.prov.kinds(), n.conditions())
}
