// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/model"
)

// The saved-view route over the real stack: real control store, real users and
// grants, real sessions and CSRF, the real HTTPS server. Nothing here is a
// double. A saved view is project-owned query text: these tests pin who may see
// and change it, what is refused, and what a failure or an audit may say.

const (
	svCanaryName = "SVNAMECANARY5a0c91d3"
	svCanaryExpr = "SVEXPRCANARY77be42f8"
)

// svFx is two organizations: A with three projects and five kinds of caller,
// B with one project and one reader.
//
//	alice  member, telemetry.read on p1 and p2 (the usual owner)
//	bob    member, telemetry.read on p1
//	carol  member, no grant at all
//	erin   member, organization administrator, telemetry.read on p1
//	e.actor organization administrator of both, not a member (reads nothing)
//	frank  member of B, telemetry.read on pb
type svFx struct {
	*queryEnv
	org, p1, p2, p3 model.ID
	orgB, pb        model.ID
	alice, bob      person
	carol, erin     person
	frank           person
}

func newSVFx(t *testing.T) *svFx {
	t.Helper()
	e := newQueryEnv(t, queryLimits())
	f := &svFx{queryEnv: e, p1: model.NewID(), p2: model.NewID(), p3: model.NewID(), pb: model.NewID()}
	f.org = e.org("saved views A", f.p1, f.p2, f.p3)
	f.orgB = e.org("saved views B", f.pb)
	f.alice = e.user(f.org, "sv-alice@example.test")
	f.bob = e.user(f.org, "sv-bob@example.test")
	f.carol = e.user(f.org, "sv-carol@example.test")
	f.erin = e.user(f.org, "sv-erin@example.test")
	f.frank = e.user(f.orgB, "sv-frank@example.test")
	e.grant(f.org, f.alice, f.p1, true, auth.Read)
	e.grant(f.org, f.alice, f.p2, true, auth.Read)
	e.grant(f.org, f.bob, f.p1, true, auth.Read)
	e.grant(f.org, f.erin, f.p1, true, auth.Read)
	e.grant(f.orgB, f.frank, f.pb, true, auth.Read)
	e.cmd(f.org, "org_admin", auth.AdminPayload{UserID: f.erin.ID, Enabled: true})
	return f
}

func svIDs(ids ...model.ID) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = id.String()
	}
	return out
}

// saveBody is a valid create of a promql view owned by project over projects
// (just project when none is named), with a fresh command ID.
func (f *svFx) saveBody(org, project model.ID, name, expr string, projects ...model.ID) queryBody {
	if len(projects) == 0 {
		projects = []model.ID{project}
	}
	return queryBody{"operation": "save", "org": org.String(), "project": project.String(), "command_id": model.NewID().String(),
		"name": name, "language": "promql", "profile": queryProm, "feature_set": f.promSet, "expression": expr, "projects": svIDs(projects...), "mode": "instant", "allow_partial": false}
}

func (f *svFx) updateBody(base queryBody, id model.ID, revision model.Revision) queryBody {
	out := queryBody{}
	for k, v := range base {
		out[k] = v
	}
	out["command_id"], out["id"], out["expected_revision"] = model.NewID().String(), id.String(), decimal(int64(revision))
	return out
}

func (f *svFx) deleteBody(org, project, id model.ID, revision model.Revision) queryBody {
	return queryBody{"operation": "delete", "org": org.String(), "project": project.String(), "command_id": model.NewID().String(), "id": id.String(), "expected_revision": decimal(int64(revision))}
}

func (f *svFx) listBody(org, project model.ID) queryBody {
	return queryBody{"operation": "list", "org": org.String(), "project": project.String()}
}

func (f *svFx) call(who person, body queryBody) (int, []byte) {
	f.t.Helper()
	status, raw, _ := f.post(who, "/api/v1/saved-views", body)
	return status, raw
}

func (f *svFx) mustSave(who person, body queryBody) httpapi.SavedViewCommitted {
	f.t.Helper()
	status, raw := f.call(who, body)
	var out httpapi.SavedViewCommitted
	if status != http.StatusOK || model.StrictJSON(raw, &out) != nil || out.State != httpapi.StateCommitted || out.View == nil {
		f.t.Fatalf("save: %d %s", status, raw)
	}
	return out
}

func (f *svFx) list(who person, org, project model.ID) (int, httpapi.SavedViewList, []byte) {
	f.t.Helper()
	status, raw := f.call(who, f.listBody(org, project))
	var out httpapi.SavedViewList
	if status == http.StatusOK && model.StrictJSON(raw, &out) != nil {
		f.t.Fatalf("list does not decode: %s", raw)
	}
	return status, out, raw
}

func (f *svFx) mustList(who person, org, project model.ID) httpapi.SavedViewList {
	f.t.Helper()
	status, out, raw := f.list(who, org, project)
	if status != http.StatusOK {
		f.t.Fatalf("list: %d %s", status, raw)
	}
	return out
}

func svViewIDs(l httpapi.SavedViewList) []string {
	var out []string
	for _, v := range l.Views {
		out = append(out, v.ID.String())
	}
	sort.Strings(out)
	return out
}

// raw posts a body as it is written, with the caller's session and CSRF token.
func (f *svFx) raw(who person, path string, body []byte) (int, []byte) {
	f.t.Helper()
	req, _ := http.NewRequest("POST", f.server.URL+path, bytes.NewReader(body))
	req.Header.Set("Cookie", "__Host-soundpost="+who.Session.Token)
	req.Header.Set("X-CSRF-Token", who.Session.CSRF)
	req.Header.Set("Origin", f.server.URL)
	req.Header.Set("Content-Type", "application/json")
	resp, err := f.client.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

type svCounters struct {
	revision, authority model.Revision
	epoch, epochB       uint64
	audits              []model.ControlAudit
	auditJSON, state    []byte
	views               map[string]json.RawMessage
}

func (f *svFx) counters() svCounters {
	f.t.Helper()
	var c svCounters
	if err := f.app.Control.View(f.ctx, func(st model.ControlState) error {
		c.revision, c.authority, c.views = st.Revision, st.AuthorityRevision, st.SavedViewBooks
		c.epoch, c.epochB = st.Orgs[f.org.String()].Epoch, st.Orgs[f.orgB.String()].Epoch
		for _, a := range st.Audits {
			if strings.HasPrefix(a.Action, "saved_view.") {
				c.audits = append(c.audits, a)
			}
		}
		var err error
		if c.auditJSON, err = json.Marshal(st.Audits); err != nil {
			return err
		}
		c.state, err = json.Marshal(st)
		return err
	}); err != nil {
		f.t.Fatal(err)
	}
	return c
}

func TestSavedViewsRoundTrip(t *testing.T) {
	f := newSVFx(t)
	if status, out, raw := f.list(f.alice, f.org, f.p1); status != 200 || out.State != httpapi.StateEmpty || len(out.Views) != 0 || !strings.Contains(string(raw), `"views":[]`) {
		t.Fatalf("an empty project: %d %s", status, raw)
	}

	body := f.saveBody(f.org, f.p1, "latency by route", `sum by (route) (rate(http_requests_total[5m]))`, f.p1, f.p2)
	body["mode"], body["step_seconds"], body["allow_partial"] = "range", "30", true
	before := time.Now().UnixNano()
	status, raw, header := f.post(f.alice, "/api/v1/saved-views", body)
	after := time.Now().UnixNano()
	var created httpapi.SavedViewCommitted
	if status != 200 || model.StrictJSON(raw, &created) != nil || created.State != httpapi.StateCommitted || created.View == nil || created.Revision != 1 {
		t.Fatalf("create: %d %s", status, raw)
	}
	if header.Get("Cache-Control") != "no-store" || !strings.HasPrefix(header.Get("Content-Type"), "application/json") {
		t.Fatalf("headers %v", header)
	}
	v := created.View
	if v.Revision != 1 || v.Org != f.org || v.Project != f.p1 || v.Owner != f.alice.ID || v.Name != "latency by route" || v.Language != "promql" || v.Profile != queryProm || v.FeatureSet != f.promSet ||
		v.Expression != `sum by (route) (rate(http_requests_total[5m]))` || len(v.Projects) != 2 || v.Projects[0] != f.p1 || v.Projects[1] != f.p2 || v.Mode != "range" || v.StepSeconds == nil || *v.StepSeconds != 30 || !v.AllowPartial || v.LogLimit != nil || v.LogOrder != "" {
		t.Fatalf("created view %+v", v)
	}
	if int64(v.CreatedNS) < before || int64(v.CreatedNS) > after || v.UpdatedNS != v.CreatedNS {
		t.Fatalf("times %d %d not the server clock in [%d,%d]", v.CreatedNS, v.UpdatedNS, before, after)
	}
	// The wire form: 64-bit integers are decimal strings, optional fields are omitted.
	for _, want := range []string{`"revision":"1"`, `"created_ns":"`, `"updated_ns":"`, `"step_seconds":"30"`, `"owner":"` + f.alice.ID.String() + `"`, `"allow_partial":true`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("wire form lacks %s: %s", want, raw)
		}
	}
	if strings.Contains(string(raw), "log_limit") || strings.Contains(string(raw), "log_order") {
		t.Errorf("absent optional fields are on the wire: %s", raw)
	}

	listed := f.mustList(f.alice, f.org, f.p1)
	if listed.State != httpapi.StateReady || len(listed.Views) != 1 || listed.Views[0].ID != v.ID || listed.Views[0].Revision != 1 || listed.Views[0].Expression != v.Expression {
		t.Fatalf("list after create: %+v", listed)
	}
	// Another reader of the project sees the same view.
	if other := f.mustList(f.bob, f.org, f.p1); len(other.Views) != 1 || other.Views[0].Owner != f.alice.ID {
		t.Fatalf("a second reader's list: %+v", other)
	}

	// Update: the revision is the compare-and-set token; identity, owner and
	// creation time stay.
	update := f.saveBody(f.org, f.p1, "latency by route (v2)", `histogram_quantile(0.99, sum by (le) (rate(h_bucket[5m])))`, f.p1)
	updated := f.mustSave(f.alice, f.updateBody(update, v.ID, 1))
	u := updated.View
	if updated.Revision != 2 || u.Revision != 2 || u.ID != v.ID || u.Owner != f.alice.ID || u.CreatedNS != v.CreatedNS || u.UpdatedNS < v.UpdatedNS || u.Name != "latency by route (v2)" || len(u.Projects) != 1 || u.Mode != "instant" || u.StepSeconds != nil {
		t.Fatalf("updated view %+v", u)
	}
	if listed = f.mustList(f.alice, f.org, f.p1); len(listed.Views) != 1 || listed.Views[0].Name != "latency by route (v2)" || listed.Views[0].Revision != 2 {
		t.Fatalf("list after update: %+v", listed)
	}

	// A second view lists after the first (oldest first).
	second := f.mustSave(f.alice, f.saveBody(f.org, f.p1, "second", "up"))
	if listed = f.mustList(f.alice, f.org, f.p1); len(listed.Views) != 2 || listed.Views[0].ID != v.ID || listed.Views[1].ID != second.View.ID {
		t.Fatalf("list order: %+v", listed)
	}

	// Delete answers with the revision it removed plus one and leaves nothing.
	status, raw = f.call(f.alice, f.deleteBody(f.org, f.p1, v.ID, 2))
	var deleted httpapi.SavedViewCommitted
	if status != 200 || model.StrictJSON(raw, &deleted) != nil || deleted.State != httpapi.StateCommitted || deleted.View != nil || deleted.Revision != 3 || strings.Contains(string(raw), `"view"`) {
		t.Fatalf("delete: %d %s", status, raw)
	}
	if listed = f.mustList(f.alice, f.org, f.p1); len(listed.Views) != 1 || listed.Views[0].ID != second.View.ID {
		t.Fatalf("list after delete: %+v", listed)
	}
	if status, raw = f.call(f.alice, f.deleteBody(f.org, f.p1, v.ID, 3)); status != 404 {
		t.Fatalf("delete of a deleted view: %d %s", status, raw)
	}

	// A logql view carries its page size and order; they come back as stored.
	logs := f.saveBody(f.org, f.p1, "errors", `{service="api"} |= "error"`)
	logs["language"], logs["profile"], logs["mode"], logs["log_limit"], logs["log_order"] = "logql", queryLogql, "range", "500", "forward"
	delete(logs, "step_seconds")
	if l := f.mustSave(f.alice, logs).View; l.Language != "logql" || l.LogLimit == nil || *l.LogLimit != 500 || l.LogOrder != "forward" {
		t.Fatalf("logql view %+v", l)
	}
}

// A command ID makes a save or a delete idempotent: the replay answers with the
// first result and changes nothing; a command ID that committed something else
// is a conflict, not a wrong answer.
func TestSavedViewsCommandIDReplay(t *testing.T) {
	f := newSVFx(t)
	body := f.saveBody(f.org, f.p1, "once", `up{x="`+svCanaryExpr+`"}`)
	status, first := f.call(f.alice, body)
	if status != 200 {
		t.Fatalf("create: %d %s", status, first)
	}
	spent := f.counters()
	for i := range 3 {
		if status, again := f.call(f.alice, body); status != 200 || !bytes.Equal(again, first) {
			t.Fatalf("replay %d: %d %s\nfirst %s", i, status, again, first)
		}
	}
	after := f.counters()
	if after.revision != spent.revision || len(after.audits) != 1 || len(f.mustList(f.alice, f.org, f.p1).Views) != 1 {
		t.Fatalf("a replay changed state: revision %d -> %d, %d audits", spent.revision, after.revision, len(after.audits))
	}
	var created httpapi.SavedViewCommitted
	if err := model.StrictJSON(first, &created); err != nil {
		t.Fatal(err)
	}
	id := created.View.ID

	// The replay of a create after the view moved on answers with what the command
	// committed (revision 1, no view), and does not touch the view.
	f.mustSave(f.alice, f.updateBody(f.saveBody(f.org, f.p1, "twice", "up"), id, 1))
	status, replay := f.call(f.alice, body)
	var old httpapi.SavedViewCommitted
	if status != 200 || model.StrictJSON(replay, &old) != nil || old.Revision != 1 || old.View != nil {
		t.Fatalf("replay after an update: %d %s", status, replay)
	}
	if l := f.mustList(f.alice, f.org, f.p1); len(l.Views) != 1 || l.Views[0].Revision != 2 || l.Views[0].Name != "twice" {
		t.Fatalf("a replay changed the view: %+v", l)
	}

	// The same command ID for another command is a conflict, never its answer.
	reuse := f.deleteBody(f.org, f.p1, id, 2)
	reuse["command_id"] = body["command_id"]
	if status, raw := f.call(f.alice, reuse); status != 409 || !strings.Contains(string(raw), "command_id_reused") {
		t.Fatalf("a delete under a save's command ID: %d %s", status, raw)
	}
	update := f.updateBody(f.saveBody(f.org, f.p1, "thrice", "up"), id, 2)
	update["command_id"] = body["command_id"]
	if status, raw := f.call(f.alice, update); status != 409 || !strings.Contains(string(raw), "command_id_reused") {
		t.Fatalf("an update under a create's command ID: %d %s", status, raw)
	}
	if l := f.mustList(f.alice, f.org, f.p1); len(l.Views) != 1 || l.Views[0].Name != "twice" {
		t.Fatalf("a refused reuse changed the view: %+v", l)
	}

	// Another caller cannot replay (or probe) someone else's command.
	if status, raw := f.call(f.bob, body); status != 404 {
		t.Fatalf("another principal replayed: %d %s", status, raw)
	}

	// A delete replays too: the second answer is the first, and the view is not
	// brought back or deleted twice.
	del := f.deleteBody(f.org, f.p1, id, 2)
	status, firstDelete := f.call(f.alice, del)
	if status != 200 {
		t.Fatalf("delete: %d %s", status, firstDelete)
	}
	if status, again := f.call(f.alice, del); status != 200 || !bytes.Equal(again, firstDelete) {
		t.Fatalf("delete replay: %d %s", status, again)
	}
}

func TestSavedViewsStaleRevisionIsAConflict(t *testing.T) {
	f := newSVFx(t)
	id := f.mustSave(f.alice, f.saveBody(f.org, f.p1, "v1", "up")).View.ID
	f.mustSave(f.alice, f.updateBody(f.saveBody(f.org, f.p1, "v2", "up"), id, 1))
	for _, stale := range []model.Revision{1, 3} {
		status, raw := f.call(f.alice, f.updateBody(f.saveBody(f.org, f.p1, "lost", "up"), id, stale))
		if status != 409 || !strings.Contains(string(raw), "saved_view_revision_conflict") {
			t.Fatalf("update at revision %d: %d %s", stale, status, raw)
		}
		status, raw = f.call(f.alice, f.deleteBody(f.org, f.p1, id, stale))
		if status != 409 || !strings.Contains(string(raw), "saved_view_revision_conflict") {
			t.Fatalf("delete at revision %d: %d %s", stale, status, raw)
		}
	}
	if l := f.mustList(f.alice, f.org, f.p1); len(l.Views) != 1 || l.Views[0].Name != "v2" || l.Views[0].Revision != 2 {
		t.Fatalf("a conflict changed the view: %+v", l)
	}
	// An update names its revision; two writers on one revision cannot both win.
	a := f.updateBody(f.saveBody(f.org, f.p1, "writer a", "up"), id, 2)
	b := f.updateBody(f.saveBody(f.org, f.p1, "writer b", "up"), id, 2)
	if status, raw := f.call(f.alice, a); status != 200 {
		t.Fatalf("first writer: %d %s", status, raw)
	}
	if status, raw := f.call(f.alice, b); status != 409 {
		t.Fatalf("second writer: %d %s", status, raw)
	}
}

// Every bound is enforced before anything is looked up and refused, never
// truncated; no failure says anything about the text it refused; nothing a
// refused request carried is stored.
func TestSavedViewsBoundsAndShape(t *testing.T) {
	f := newSVFx(t)
	canaryName, canaryExpr := "name "+svCanaryName, `up{x="`+svCanaryExpr+`"}`
	mutate := func(edit func(queryBody)) queryBody {
		b := f.saveBody(f.org, f.p1, canaryName, canaryExpr)
		edit(b)
		return b
	}
	manyProjects := func(n int) []string {
		out := make([]string, n)
		out[0] = f.p1.String()
		for i := 1; i < n; i++ {
			out[i] = model.NewID().String()
		}
		return out
	}
	step := func(v string) func(queryBody) {
		return func(b queryBody) { b["mode"], b["step_seconds"] = "range", v }
	}
	logql := func(edit func(queryBody)) func(queryBody) {
		return func(b queryBody) { b["language"], b["profile"] = "logql", queryLogql; edit(b) }
	}
	cases := []struct {
		name string
		body queryBody
		want int
	}{
		{"empty name", mutate(func(b queryBody) { b["name"] = "" }), 400},
		{"name past 120 bytes", mutate(func(b queryBody) { b["name"] = strings.Repeat("n", 121) + svCanaryName }), 413},
		{"name of exactly 121 bytes", mutate(func(b queryBody) { b["name"] = strings.Repeat("n", 121) }), 413},
		{"multibyte name of exactly 121 bytes", mutate(func(b queryBody) { b["name"] = strings.Repeat("é", 60) + "n" }), 413},
		{"multibyte name past 120 bytes", mutate(func(b queryBody) { b["name"] = strings.Repeat("é", 61) }), 413},
		{"name with a tab", mutate(func(b queryBody) { b["name"] = "a\tb" + svCanaryName }), 400},
		{"name with a newline", mutate(func(b queryBody) { b["name"] = "a\nb" + svCanaryName }), 400},
		{"name with NUL", mutate(func(b queryBody) { b["name"] = "a\x00b" + svCanaryName }), 400},
		{"name with DEL", mutate(func(b queryBody) { b["name"] = "a\x7fb" + svCanaryName }), 400},
		{"name with a C1 control", mutate(func(b queryBody) { b["name"] = "a\u0085b" + svCanaryName }), 400},
		{"empty expression", mutate(func(b queryBody) { b["expression"] = "" }), 400},
		{"expression past 16384 bytes", mutate(func(b queryBody) { b["expression"] = strings.Repeat("x", 16385) + svCanaryExpr }), 413},
		{"expression of exactly 16385 bytes", mutate(func(b queryBody) { b["expression"] = strings.Repeat("x", 16385) }), 413},
		{"no projects", mutate(func(b queryBody) { b["projects"] = []string{} }), 400},
		{"17 projects", mutate(func(b queryBody) { b["projects"] = manyProjects(17) }), 413},
		{"a duplicate project", mutate(func(b queryBody) { b["projects"] = []string{f.p1.String(), f.p1.String()} }), 400},
		{"the zero project", mutate(func(b queryBody) { b["projects"] = []string{f.p1.String(), model.ID{}.String()} }), 400},
		{"owning project not among the projects", mutate(func(b queryBody) { b["projects"] = []string{f.p2.String()} }), 400},
		{"unknown language", mutate(func(b queryBody) { b["language"] = "sql" }), 400},
		{"empty profile", mutate(func(b queryBody) { b["profile"] = "" }), 400},
		{"profile with a space", mutate(func(b queryBody) { b["profile"] = "promql prometheus" }), 400},
		{"profile with a slash", mutate(func(b queryBody) { b["profile"] = "../etc/passwd" }), 400},
		{"profile past 256 bytes", mutate(func(b queryBody) { b["profile"] = strings.Repeat("p", 257) }), 400},
		{"profile naming a path", mutate(func(b queryBody) { b["profile"] = queryProm + "/semantic" }), 400},
		{"profile that starts with a dot", mutate(func(b queryBody) { b["profile"] = ".hidden" }), 400},
		{"empty feature set", mutate(func(b queryBody) { b["feature_set"] = "" }), 400},
		{"feature set with markup", mutate(func(b queryBody) { b["feature_set"] = "<script>" }), 400},
		{"feature set that starts with a slash", mutate(func(b queryBody) { b["feature_set"] = "/features-ab" }), 400},
		{"feature set with a space", mutate(func(b queryBody) { b["feature_set"] = "features ab" }), 400},
		{"feature set with a backslash", mutate(func(b queryBody) { b["feature_set"] = `features\ab` }), 400},
		{"feature set past 256 bytes", mutate(func(b queryBody) { b["feature_set"] = "f" + strings.Repeat("/", 256) }), 400},
		{"unknown mode", mutate(func(b queryBody) { b["mode"] = "stream" }), 400},
		{"no mode", mutate(func(b queryBody) { delete(b, "mode") }), 400},
		{"a step on an instant view", mutate(func(b queryBody) { b["step_seconds"] = "15" }), 400},
		{"step zero", mutate(step("0")), 400},
		{"step of a year and a day", mutate(step("31622401")), 400},
		{"step not a number", mutate(step("15s")), 400},
		{"step as a JSON number", mutate(func(b queryBody) { b["mode"], b["step_seconds"] = "range", 15 }), 400},
		{"log limit on promql", mutate(func(b queryBody) { b["log_limit"] = "10" }), 400},
		{"log order on promql", mutate(func(b queryBody) { b["log_order"] = "forward" }), 400},
		{"log limit zero", mutate(logql(func(b queryBody) { b["log_limit"] = "0" })), 400},
		{"log limit past the engine's bound", mutate(logql(func(b queryBody) { b["log_limit"] = "5000001" })), 400},
		{"unknown log order", mutate(logql(func(b queryBody) { b["log_order"] = "sideways" })), 400},
		{"a client-supplied owner", mutate(func(b queryBody) { b["owner"] = f.bob.ID.String() }), 400},
		{"a client-supplied time", mutate(func(b queryBody) { b["created_ns"] = "1" }), 400},
		{"a client-supplied actor", mutate(func(b queryBody) { b["actor"] = f.bob.ID.String() }), 400},
		{"a client-supplied revision", mutate(func(b queryBody) { b["revision"] = "9" }), 400},
		{"no command ID", mutate(func(b queryBody) { delete(b, "command_id") }), 400},
		{"the zero command ID", mutate(func(b queryBody) { b["command_id"] = model.ID{}.String() }), 400},
		{"a command ID that is not hex", mutate(func(b queryBody) { b["command_id"] = "not-an-id" }), 400},
		{"an expected revision with no id", mutate(func(b queryBody) { b["expected_revision"] = "1" }), 400},
		{"an id with no expected revision", mutate(func(b queryBody) { b["id"] = model.NewID().String() }), 400},
		{"the zero id", mutate(func(b queryBody) { b["id"], b["expected_revision"] = model.ID{}.String(), "1" }), 400},
		{"expected revision zero on an update", mutate(func(b queryBody) { b["id"], b["expected_revision"] = model.NewID().String(), "0" }), 400},
		{"no operation", mutate(func(b queryBody) { delete(b, "operation") }), 400},
		{"an unknown operation", mutate(func(b queryBody) { b["operation"] = "rename" }), 400},
		{"no organization", mutate(func(b queryBody) { delete(b, "org") }), 400},
		{"no project", mutate(func(b queryBody) { delete(b, "project") }), 400},
		{"a body past the cap", mutate(func(b queryBody) { b["expression"] = strings.Repeat("x", 200<<10) + svCanaryExpr }), 413},
	}
	for _, tc := range cases {
		status, raw := f.call(f.alice, tc.body)
		if status != tc.want {
			t.Errorf("%s: %d, want %d: %.200s", tc.name, status, tc.want, raw)
			continue
		}
		if strings.Contains(string(raw), svCanaryName) || strings.Contains(string(raw), svCanaryExpr) {
			t.Errorf("%s: the failure repeats the query text: %.300s", tc.name, raw)
		}
		if code, _ := faultBody(t, raw); code == "" {
			t.Errorf("%s: not a typed failure: %s", tc.name, raw)
		}
	}
	if l := f.mustList(f.alice, f.org, f.p1); len(l.Views) != 0 {
		t.Fatalf("refused saves stored %d views", len(l.Views))
	}

	// The bounds themselves are allowed.
	edge := f.saveBody(f.org, f.p1, strings.Repeat("é", 60), strings.Repeat("x", 16384))
	edge["profile"], edge["feature_set"] = "a"+strings.Repeat(".", 255), "9:_-/"+strings.Repeat("/", 251)
	if status, raw := f.call(f.alice, edge); status != 200 {
		t.Fatalf("name of 120 bytes and expression of 16384 bytes: %d %.300s", status, raw)
	}
	// A 16384-byte expression whose every byte is escaped on the wire is still in bounds.
	escaped := f.saveBody(f.org, f.p1, "escaped", strings.Repeat("\u0001", 16384))
	if status, raw := f.call(f.alice, escaped); status != 200 {
		t.Fatalf("an escaped expression of 16384 bytes: %d %.300s", status, raw)
	}
	// The numeric bounds are inclusive.
	for name, edit := range map[string]func(queryBody){
		"step of one second":      step("1"),
		"step of 366 days":        step("31622400"),
		"log limit of one":        logql(func(b queryBody) { b["log_limit"] = "1" }),
		"log limit at the bound":  logql(func(b queryBody) { b["log_limit"] = "5000000" }),
		"logql with no limit set": logql(func(b queryBody) {}),
	} {
		b := f.saveBody(f.org, f.p1, name, "up")
		edit(b)
		if status, raw := f.call(f.alice, b); status != 200 {
			t.Errorf("%s: %d %.300s", name, status, raw)
		}
	}
}

// denials collects what a caller may compare: status, fault code and detail. The
// request ID is per request by design and is not part of it.
type svDenials struct {
	t    *testing.T
	seen map[string][]string
}

func newSVDenials(t *testing.T) *svDenials { return &svDenials{t: t, seen: map[string][]string{}} }

func (d *svDenials) add(name string, status int, raw []byte) {
	d.t.Helper()
	if status == 200 {
		d.t.Errorf("%s: answered 200: %s", name, raw)
		return
	}
	if strings.Contains(string(raw), svCanaryName) || strings.Contains(string(raw), svCanaryExpr) {
		d.t.Errorf("%s: the denial repeats query text: %s", name, raw)
	}
	key := denial(d.t, status, raw)
	d.seen[key] = append(d.seen[key], name)
}

// same asserts every collected denial is the very same status, code and detail,
// and that it is the not-found.
func (d *svDenials) same() {
	d.t.Helper()
	if len(d.seen) != 1 {
		d.t.Fatalf("denials are distinguishable: %v", d.seen)
	}
	for key := range d.seen {
		if key != "Not Found/not_found/not_found" {
			d.t.Fatalf("the denial is %q, want the plain not-found", key)
		}
	}
}

// A view is project-owned: telemetry.read on the project is what lists, saves,
// updates and deletes it. A member with no grant, a reader of another
// organization, an organization administrator who reads nothing, a revoked reader
// and a guess at a project or organization are one and the same not-found.
func TestSavedViewsNeedTelemetryRead(t *testing.T) {
	f := newSVFx(t)
	secret := f.saveBody(f.org, f.p1, "secret "+svCanaryName, `up{token="`+svCanaryExpr+`"}`)
	id := f.mustSave(f.alice, secret).View.ID
	if l := f.mustList(f.bob, f.org, f.p1); len(l.Views) != 1 || l.Views[0].ID != id || l.Views[0].Expression != `up{token="`+svCanaryExpr+`"}` {
		t.Fatalf("a reader does not see the view: %+v", l)
	}

	d := newSVDenials(t)
	strangers := map[string]person{"member without a grant": f.carol, "reader of another organization": f.frank, "administrator without a grant": f.actor}
	for name, who := range strangers {
		status, _, raw := f.list(who, f.org, f.p1)
		d.add(name+" lists", status, raw)
		status, raw = f.call(who, f.saveBody(f.org, f.p1, "mine "+svCanaryName, "up"+svCanaryExpr))
		d.add(name+" saves", status, raw)
		status, raw = f.call(who, f.updateBody(f.saveBody(f.org, f.p1, "mine "+svCanaryName, "up"+svCanaryExpr), id, 1))
		d.add(name+" updates", status, raw)
	}
	for _, name := range []string{"member without a grant", "reader of another organization"} {
		status, raw := f.call(strangers[name], f.deleteBody(f.org, f.p1, id, 1))
		d.add(name+" deletes", status, raw)
	}
	// Guesses by a caller who reads something: another project, an unknown project
	// and organization, an absent view.
	status, _, raw := f.list(f.alice, f.org, f.p3)
	d.add("alice lists a project she cannot read", status, raw)
	status, _, raw = f.list(f.alice, f.org, model.NewID())
	d.add("alice lists a guessed project", status, raw)
	status, _, raw = f.list(f.alice, model.NewID(), f.p1)
	d.add("alice lists a guessed organization", status, raw)
	status, raw = f.call(f.alice, f.saveBody(f.org, f.p3, "elsewhere", "up"))
	d.add("alice saves under a project she cannot read", status, raw)
	status, raw = f.call(f.alice, f.updateBody(f.saveBody(f.org, f.p1, "ghost", "up"), model.NewID(), 1))
	d.add("alice updates an absent view", status, raw)
	status, raw = f.call(f.alice, f.deleteBody(f.org, f.p1, model.NewID(), 1))
	d.add("alice deletes an absent view", status, raw)
	d.same()
	if l := f.mustList(f.alice, f.org, f.p1); len(l.Views) != 1 || l.Views[0].Name != "secret "+svCanaryName {
		t.Fatalf("a denied caller changed the view: %+v", l)
	}

	// A grant given through a team reads too.
	f.team(f.org, f.carol, f.p1, string(auth.Read))
	if l := f.mustList(f.carol, f.org, f.p1); len(l.Views) != 1 {
		t.Fatalf("a team reader does not see the view: %+v", l)
	}

	// A revoked reader loses the project at once: the very next request.
	f.grant(f.org, f.bob, f.p1, false)
	r := newSVDenials(t)
	status, _, raw = f.list(f.bob, f.org, f.p1)
	r.add("revoked reader lists", status, raw)
	status, raw = f.call(f.bob, f.saveBody(f.org, f.p1, "after", "up"))
	r.add("revoked reader saves", status, raw)
	status, raw = f.call(f.bob, f.updateBody(f.saveBody(f.org, f.p1, "after", "up"), id, 1))
	r.add("revoked reader updates", status, raw)
	status, raw = f.call(f.bob, f.deleteBody(f.org, f.p1, id, 1))
	r.add("revoked reader deletes", status, raw)
	r.same()
	// ... and so does the owner who loses the grant; an administrator who reads can still manage it.
	f.grant(f.org, f.alice, f.p1, false)
	status, _, raw = f.list(f.alice, f.org, f.p1)
	r2 := newSVDenials(t)
	r2.add("revoked owner lists", status, raw)
	status, raw = f.call(f.alice, f.deleteBody(f.org, f.p1, id, 1))
	r2.add("revoked owner deletes", status, raw)
	r2.same()
	if l := f.mustList(f.erin, f.org, f.p1); len(l.Views) != 1 || l.Views[0].ID != id {
		t.Fatalf("a revoked owner's view is gone: %+v", l)
	}
}

// Saving a view that runs over several projects needs telemetry.read on each of
// them; one that is not readable, unknown or another organization's is the same
// not-found as every other denial, and nothing is stored.
func TestSavedViewsEveryQueryProjectMustBeReadable(t *testing.T) {
	f := newSVFx(t)
	if v := f.mustSave(f.alice, f.saveBody(f.org, f.p1, "both", "up", f.p1, f.p2)).View; len(v.Projects) != 2 {
		t.Fatalf("a view over two readable projects: %+v", v)
	}
	d := newSVDenials(t)
	for name, projects := range map[string][]model.ID{
		"a project nobody reads":    {f.p1, f.p3},
		"an unknown project":        {f.p1, model.NewID()},
		"another organization's":    {f.p1, f.pb},
		"the unreadable one first":  {f.p3, f.p1},
		"readable among unreadable": {f.p1, f.p2, f.p3},
	} {
		status, raw := f.call(f.alice, f.saveBody(f.org, f.p1, "wide "+svCanaryName, "up"+svCanaryExpr, projects...))
		d.add(name, status, raw)
	}
	status, raw := f.call(f.bob, f.saveBody(f.org, f.p1, "wide", "up", f.p1, f.p2))
	d.add("bob cannot read the second project", status, raw)
	d.same()
	if l := f.mustList(f.alice, f.org, f.p1); len(l.Views) != 1 {
		t.Fatalf("refused saves stored views: %+v", l)
	}

	// An update that widens the view to a project the caller cannot read is refused too.
	id := f.mustSave(f.alice, f.saveBody(f.org, f.p1, "narrow", "up")).View.ID
	status, raw = f.call(f.alice, f.updateBody(f.saveBody(f.org, f.p1, "widened", "up", f.p1, f.p3), id, 1))
	d2 := newSVDenials(t)
	d2.add("widening update", status, raw)
	d2.same()
	// The listing needs only the owning project: bob reads p1 and sees the view
	// over p1 and p2 (the project IDs, nothing of p2's telemetry).
	if l := f.mustList(f.bob, f.org, f.p1); len(l.Views) != 2 {
		t.Fatalf("bob's list: %+v", l)
	}

	// Sixteen projects is the bound; each must be readable.
	ps := make([]model.ID, 16)
	ps[0] = f.p1
	for i := 1; i < len(ps); i++ {
		ps[i] = model.NewID()
		f.cmd(f.org, "create_project", auth.AdminPayload{ID: ps[i], Name: "bulk"})
		f.grant(f.org, f.alice, ps[i], true, auth.Read)
	}
	if v := f.mustSave(f.alice, f.saveBody(f.org, f.p1, "sixteen", "up", ps...)).View; len(v.Projects) != 16 {
		t.Fatalf("a view over sixteen projects: %+v", v)
	}
	f.grant(f.org, f.alice, ps[9], false)
	status, raw = f.call(f.alice, f.saveBody(f.org, f.p1, "sixteen again", "up", ps...))
	d3 := newSVDenials(t)
	d3.add("one of sixteen revoked", status, raw)
	d3.same()
}

// Another organization's and another project's views are never returned,
// counted or distinguishable.
func TestSavedViewsAreIsolatedAcrossOrgsAndProjects(t *testing.T) {
	f := newSVFx(t)
	v1 := f.mustSave(f.alice, f.saveBody(f.org, f.p1, "v1", "up")).View.ID
	v2 := f.mustSave(f.alice, f.saveBody(f.org, f.p1, "v2", "up")).View.ID
	w1 := f.mustSave(f.alice, f.saveBody(f.org, f.p2, "w1", "up")).View.ID
	x1 := f.mustSave(f.frank, f.saveBody(f.orgB, f.pb, "x1", "up")).View.ID

	want := func(who person, org, project model.ID, ids ...model.ID) {
		t.Helper()
		got, exp := svViewIDs(f.mustList(who, org, project)), svIDs(ids...)
		sort.Strings(exp)
		if fmt.Sprint(got) != fmt.Sprint(exp) {
			t.Fatalf("list %s/%s: %v, want %v", org, project, got, exp)
		}
	}
	want(f.alice, f.org, f.p1, v1, v2)
	want(f.alice, f.org, f.p2, w1)
	want(f.frank, f.orgB, f.pb, x1)

	d := newSVDenials(t)
	add := func(name string, status int, raw []byte) { t.Helper(); d.add(name, status, raw) }
	status, _, raw := f.list(f.frank, f.org, f.p1)
	add("frank lists A/p1", status, raw)
	status, _, raw = f.list(f.frank, f.orgB, f.p1)
	add("frank lists B with A's project", status, raw)
	status, _, raw = f.list(f.alice, f.orgB, f.pb)
	add("alice lists B/pb", status, raw)
	status, _, raw = f.list(f.alice, f.org, f.pb)
	add("alice lists A with B's project", status, raw)
	status, _, raw = f.list(f.bob, f.org, f.p2)
	add("bob lists a project he cannot read", status, raw)
	status, _, raw = f.list(f.alice, model.NewID(), model.NewID())
	add("alice lists a guess", status, raw)
	// A view is addressed by its own project: its ID under another project, or in
	// another organization, is an absent view.
	status, raw = f.call(f.alice, f.updateBody(f.saveBody(f.org, f.p2, "moved", "up"), v1, 1))
	add("update of p1's view through p2", status, raw)
	status, raw = f.call(f.alice, f.deleteBody(f.org, f.p2, v1, 1))
	add("delete of p1's view through p2", status, raw)
	status, raw = f.call(f.frank, f.deleteBody(f.orgB, f.pb, v1, 1))
	add("frank deletes A's view in B", status, raw)
	status, raw = f.call(f.frank, f.updateBody(f.saveBody(f.orgB, f.pb, "mine now", "up"), w1, 1))
	add("frank updates A's view in B", status, raw)
	status, raw = f.call(f.frank, f.saveBody(f.orgB, f.pb, "reaches over", "up", f.pb, f.p1))
	add("frank saves a view over A's project", status, raw)
	status, raw = f.call(f.alice, f.saveBody(f.org, f.p1, "reaches over", "up", f.p1, f.pb))
	add("alice saves a view over B's project", status, raw)
	status, raw = f.call(f.alice, f.deleteBody(f.org, f.p1, x1, 1))
	add("alice deletes B's view through A", status, raw)
	d.same()

	// Nothing above changed anything.
	want(f.alice, f.org, f.p1, v1, v2)
	want(f.alice, f.org, f.p2, w1)
	want(f.frank, f.orgB, f.pb, x1)
	if n := len(f.counters().views); n != 4 {
		t.Fatalf("the books hold %d views, want the four", n)
	}
}

// The owner changes their view; another reader of the project does not
// (forbidden: they can see it); an organization administrator may, with or
// without a read grant, and stops being one when demoted.
func TestSavedViewsOwnerReaderAndAdministrator(t *testing.T) {
	f := newSVFx(t)
	mine := f.mustSave(f.alice, f.saveBody(f.org, f.p1, "alice's", "up")).View.ID
	other := f.mustSave(f.alice, f.saveBody(f.org, f.p1, "alice's other", "up")).View.ID
	third := f.mustSave(f.alice, f.saveBody(f.org, f.p1, "alice's third", "up")).View.ID

	// A reader who is not the owner sees the view and may not change it.
	status, raw := f.call(f.bob, f.updateBody(f.saveBody(f.org, f.p1, "bob's now", "up"), mine, 1))
	if status != 403 {
		t.Fatalf("a non-owner reader updated: %d %s", status, raw)
	}
	if status, raw = f.call(f.bob, f.deleteBody(f.org, f.p1, mine, 1)); status != 403 {
		t.Fatalf("a non-owner reader deleted: %d %s", status, raw)
	}
	if l := f.mustList(f.bob, f.org, f.p1); len(l.Views) != 3 || l.Views[0].Name != "alice's" {
		t.Fatalf("a refused change changed the list: %+v", l)
	}
	// ... but creates their own and manages it.
	bobs := f.mustSave(f.bob, f.saveBody(f.org, f.p1, "bob's", "up")).View
	if bobs.Owner != f.bob.ID {
		t.Fatalf("owner %v", bobs.Owner)
	}
	f.mustSave(f.bob, f.updateBody(f.saveBody(f.org, f.p1, "bob's v2", "up"), bobs.ID, 1))

	// An organization administrator who reads the project updates and deletes anyone's view.
	renamed := f.mustSave(f.erin, f.updateBody(f.saveBody(f.org, f.p1, "renamed by erin", "up"), mine, 1)).View
	if renamed.Owner != f.alice.ID || renamed.Name != "renamed by erin" || renamed.Revision != 2 {
		t.Fatalf("administrator update: %+v", renamed)
	}
	if status, raw = f.call(f.erin, f.deleteBody(f.org, f.p1, bobs.ID, 2)); status != 200 {
		t.Fatalf("administrator delete: %d %s", status, raw)
	}

	// An administrator who reads nothing removes a view without reading it; the
	// route still tells them nothing else about the project.
	admin := person{ID: f.actor.ID, Session: f.actor.Session, Cred: f.actor.Cred}
	if status, _, _ := f.list(admin, f.org, f.p1); status != 404 {
		t.Fatalf("an administrator with no read grant listed: %d", status)
	}
	if status, raw = f.call(admin, f.saveBody(f.org, f.p1, "no read", "up")); status != 404 {
		t.Fatalf("an administrator with no read grant saved: %d %s", status, raw)
	}
	if status, raw = f.call(admin, f.updateBody(f.saveBody(f.org, f.p1, "no read", "up"), other, 1)); status != 404 {
		t.Fatalf("an administrator with no read grant updated: %d %s", status, raw)
	}
	if status, raw = f.call(admin, f.deleteBody(f.org, f.p1, other, 1)); status != 200 {
		t.Fatalf("an administrator with no read grant could not delete: %d %s", status, raw)
	}
	if status, raw = f.call(admin, f.deleteBody(f.org, f.p1, other, 2)); status != 404 {
		t.Fatalf("a deleted view: %d %s", status, raw)
	}
	// An administrator of another organization is a stranger.
	if status, raw = f.call(admin, f.deleteBody(f.orgB, f.pb, third, 1)); status != 404 {
		t.Fatalf("delete of an absent view by an administrator: %d %s", status, raw)
	}

	// The owner manages their own view, with a stale or current revision alike
	// subject to the compare-and-set.
	if status, raw = f.call(f.alice, f.deleteBody(f.org, f.p1, third, 1)); status != 200 {
		t.Fatalf("owner delete: %d %s", status, raw)
	}

	// A demoted administrator is a plain reader again.
	f.cmd(f.org, "org_admin", auth.AdminPayload{UserID: f.erin.ID, Enabled: false})
	if status, raw = f.call(f.erin, f.deleteBody(f.org, f.p1, mine, 2)); status != 403 {
		t.Fatalf("a demoted administrator deleted: %d %s", status, raw)
	}
	if status, raw = f.call(f.erin, f.updateBody(f.saveBody(f.org, f.p1, "no longer", "up"), mine, 2)); status != 403 {
		t.Fatalf("a demoted administrator updated: %d %s", status, raw)
	}
	if l := f.mustList(f.alice, f.org, f.p1); len(l.Views) != 1 || l.Views[0].ID != mine || l.Views[0].Name != "renamed by erin" {
		t.Fatalf("final list: %+v", l)
	}
}

// At most 100 views per project: the 101st is refused with 429 and the quota
// detail, nothing is evicted, another project has its own 100, and a delete
// makes room for exactly one.
func TestSavedViewsPerProjectCap(t *testing.T) {
	f := newSVFx(t)
	var first model.ID
	for i := range auth.MaxSavedViewsPerProject {
		status, raw := f.call(f.alice, f.saveBody(f.org, f.p1, fmt.Sprintf("view %d", i), "up"))
		if status != 200 {
			t.Fatalf("view %d: %d %s", i+1, status, raw)
		}
		if i == 0 {
			var c httpapi.SavedViewCommitted
			if err := model.StrictJSON(raw, &c); err != nil {
				t.Fatal(err)
			}
			first = c.View.ID
		}
	}
	status, raw := f.call(f.alice, f.saveBody(f.org, f.p1, "one too many "+svCanaryName, "up"+svCanaryExpr))
	if status != 429 || !strings.Contains(string(raw), "saved_view_quota") || strings.Contains(string(raw), svCanaryName) {
		t.Fatalf("view 101: %d %s", status, raw)
	}
	if l := f.mustList(f.alice, f.org, f.p1); len(l.Views) != 100 {
		t.Fatalf("%d views, want 100", len(l.Views))
	}
	if status, raw = f.call(f.alice, f.updateBody(f.saveBody(f.org, f.p1, "renamed at the cap", "up"), first, 1)); status != 200 {
		t.Fatalf("update at the cap: %d %s", status, raw)
	}
	if status, raw = f.call(f.alice, f.saveBody(f.org, f.p2, "another project", "up")); status != 200 {
		t.Fatalf("a full project filled another: %d %s", status, raw)
	}
	if status, raw = f.call(f.alice, f.deleteBody(f.org, f.p1, first, 2)); status != 200 {
		t.Fatalf("delete at the cap: %d %s", status, raw)
	}
	if status, raw = f.call(f.alice, f.saveBody(f.org, f.p1, "fits", "up")); status != 200 {
		t.Fatalf("after a delete: %d %s", status, raw)
	}
	if status, raw = f.call(f.alice, f.saveBody(f.org, f.p1, "but not two", "up")); status != 429 {
		t.Fatalf("after refilling: %d %s", status, raw)
	}
}

// Saving, updating and deleting a view is not an authority change: the
// organization's policy epoch (which would revoke every live stream and export
// of the organization) and the control AuthorityRevision stay, while the
// revision moves; a scope minted before stays valid.
func TestSavedViewsDoNotMoveEpochOrAuthorityRevision(t *testing.T) {
	f := newSVFx(t)
	scope, err := f.scope(f.alice, f.org, f.p1, auth.Read)
	if err != nil {
		t.Fatal(err)
	}
	before := f.counters()
	id := f.mustSave(f.alice, f.saveBody(f.org, f.p1, "a", "up")).View.ID
	f.mustSave(f.alice, f.updateBody(f.saveBody(f.org, f.p1, "b", "up"), id, 1))
	if status, raw := f.call(f.alice, f.deleteBody(f.org, f.p1, id, 2)); status != 200 {
		t.Fatalf("delete: %d %s", status, raw)
	}
	f.mustList(f.alice, f.org, f.p1)
	after := f.counters()
	if after.revision != before.revision+3 {
		t.Fatalf("revision %d -> %d, want three commits", before.revision, after.revision)
	}
	if after.authority != before.authority {
		t.Fatalf("AuthorityRevision %d -> %d", before.authority, after.authority)
	}
	if after.epoch != before.epoch || after.epochB != before.epochB {
		t.Fatalf("policy epoch %d/%d -> %d/%d", before.epoch, before.epochB, after.epoch, after.epochB)
	}
	if err = f.app.Auth.Revalidate(f.ctx, scope); err != nil {
		t.Fatalf("a scope minted before the saves was revoked by them: %v", err)
	}
}

// Each save, update and delete is audited with the actor, the kind, the
// organization, the project and the view ID, and never with the name or the
// expression, which live only in the view book and leave the state with the view.
func TestSavedViewsAuditHasNoQueryText(t *testing.T) {
	f := newSVFx(t)
	name, expr := "name "+svCanaryName, `up{token="`+svCanaryExpr+`"}`
	id := f.mustSave(f.alice, f.saveBody(f.org, f.p1, name, expr)).View.ID
	if c := f.counters(); !bytes.Contains(c.state, []byte(svCanaryExpr)) {
		t.Fatal("fixture: the expression is not in the view book")
	}
	f.mustSave(f.alice, f.updateBody(f.saveBody(f.org, f.p1, name+" v2", expr+" > 0"), id, 1))
	if status, raw := f.call(f.alice, f.deleteBody(f.org, f.p1, id, 2)); status != 200 {
		t.Fatalf("delete: %d %s", status, raw)
	}
	c := f.counters()
	if len(c.audits) != 3 {
		t.Fatalf("%d saved-view audits, want 3: %+v", len(c.audits), c.audits)
	}
	for i, want := range []string{"saved_view.save", "saved_view.save", "saved_view.delete"} {
		a := c.audits[i]
		if a.Action != want || a.Principal != f.alice.ID || a.Org != f.org.String() || a.Outcome != model.AuditAllowed || len(a.Targets) != 2 || a.Targets[0] != f.p1 || a.Targets[1] != id || a.Time == 0 || a.Reason == "" {
			t.Errorf("audit %d: %+v", i, a)
		}
	}
	if bytes.Contains(c.auditJSON, []byte(svCanaryName)) || bytes.Contains(c.auditJSON, []byte(svCanaryExpr)) {
		t.Fatalf("query text reached the audit log: %s", c.auditJSON)
	}
	if bytes.Contains(c.state, []byte(svCanaryName)) || bytes.Contains(c.state, []byte(svCanaryExpr)) {
		t.Fatal("a deleted view left its text in the control state")
	}
	// A refused save audits nothing: it did not happen.
	f.call(f.carol, f.saveBody(f.org, f.p1, name, expr))
	f.call(f.alice, f.saveBody(f.org, f.p1, "", expr))
	if n := len(f.counters().audits); n != 3 {
		t.Fatalf("refused saves left %d audits", n)
	}
}

// The route is POST-only with a JSON body (a URL carries no query text), takes
// the caller from the session, and refuses a body that smuggles another
// operation's fields.
func TestSavedViewsRoutePosture(t *testing.T) {
	f := newSVFx(t)
	id := f.mustSave(f.alice, f.saveBody(f.org, f.p1, "n", "up")).View.ID
	for _, method := range []string{"GET", "PUT", "DELETE", "PATCH"} {
		req, _ := http.NewRequest(method, f.server.URL+"/api/v1/saved-views?expression=up", nil)
		req.Header.Set("Cookie", "__Host-soundpost="+f.alice.Session.Token)
		resp, err := f.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("%s: %d, want 405", method, resp.StatusCode)
		}
	}
	good, _ := json.Marshal(f.listBody(f.org, f.p1))
	if status, raw := f.raw(f.alice, "/api/v1/saved-views?expression=up", good); status != 400 {
		t.Errorf("a query string: %d %s", status, raw)
	}
	if status, raw := f.raw(f.alice, "/api/v1/saved-views", good); status != 200 {
		t.Fatalf("the same body without one: %d %s", status, raw)
	}
	for name, body := range map[string]string{
		"duplicate keys":     `{"operation":"list","operation":"list","org":"` + f.org.String() + `","project":"` + f.p1.String() + `"}`,
		"trailing data":      string(good) + `{}`,
		"not an object":      `[]`,
		"empty":              ``,
		"invalid UTF-8":      `{"operation":"list","org":"` + f.org.String() + `","project":"` + f.p1.String() + `","name":"` + "\xff" + `"}`,
		"null operation":     `{"operation":null,"org":"` + f.org.String() + `","project":"` + f.p1.String() + `"}`,
		"org as a number":    `{"operation":"list","org":1,"project":"` + f.p1.String() + `"}`,
		"project too short":  `{"operation":"list","org":"` + f.org.String() + `","project":"abc"}`,
		"unknown field":      `{"operation":"list","org":"` + f.org.String() + `","project":"` + f.p1.String() + `","limit":10}`,
		"permission as body": `{"operation":"list","org":"` + f.org.String() + `","project":"` + f.p1.String() + `","permission":"org.admin"}`,
	} {
		if status, raw := f.raw(f.alice, "/api/v1/saved-views", []byte(body)); status != 400 {
			t.Errorf("%s: %d %s", name, status, raw)
		}
	}
	// A body of one operation that carries another's fields.
	for name, body := range map[string]queryBody{
		"list with a name":          {"operation": "list", "org": f.org.String(), "project": f.p1.String(), "name": "n"},
		"list with a command ID":    {"operation": "list", "org": f.org.String(), "project": f.p1.String(), "command_id": model.NewID().String()},
		"list with an id":           {"operation": "list", "org": f.org.String(), "project": f.p1.String(), "id": id.String()},
		"list with allow_partial":   {"operation": "list", "org": f.org.String(), "project": f.p1.String(), "allow_partial": true},
		"delete with an expression": {"operation": "delete", "org": f.org.String(), "project": f.p1.String(), "command_id": model.NewID().String(), "id": id.String(), "expected_revision": "1", "expression": "up"},
		"delete without a revision": {"operation": "delete", "org": f.org.String(), "project": f.p1.String(), "command_id": model.NewID().String(), "id": id.String()},
		"delete without an id":      {"operation": "delete", "org": f.org.String(), "project": f.p1.String(), "command_id": model.NewID().String(), "expected_revision": "1"},
		"delete without a command":  {"operation": "delete", "org": f.org.String(), "project": f.p1.String(), "id": id.String(), "expected_revision": "1"},
		"delete at revision zero":   {"operation": "delete", "org": f.org.String(), "project": f.p1.String(), "command_id": model.NewID().String(), "id": id.String(), "expected_revision": "0"},
	} {
		if status, raw := f.call(f.alice, body); status != 400 {
			t.Errorf("%s: %d %s", name, status, raw)
		}
	}
	if l := f.mustList(f.alice, f.org, f.p1); len(l.Views) != 1 || l.Views[0].ID != id || l.Views[0].Revision != 1 {
		t.Fatalf("a refused request changed the view: %+v", l)
	}

	// No session, a forged origin and a bad bearer are refused before anything is read.
	if status, raw, _ := f.post(person{}, "/api/v1/saved-views", f.listBody(f.org, f.p1)); status != 401 && status != 403 {
		t.Errorf("no session: %d %s", status, raw)
	}
	req, _ := http.NewRequest("POST", f.server.URL+"/api/v1/saved-views", bytes.NewReader(good))
	req.Header.Set("Cookie", "__Host-soundpost="+f.alice.Session.Token)
	req.Header.Set("X-CSRF-Token", f.alice.Session.CSRF)
	req.Header.Set("Origin", "https://evil.example")
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Errorf("a forged origin: %d", resp.StatusCode)
	}
	req, _ = http.NewRequest("POST", f.server.URL+"/api/v1/saved-views", bytes.NewReader(good))
	req.Header.Set("Authorization", "Bearer not-a-token")
	if resp, err = f.client.Do(req); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Errorf("a bad bearer: %d", resp.StatusCode)
	}
}

// Every profile and feature-set identifier the query engine ships can be saved
// and comes back exactly as saved: a prometheus feature set is
// `<profile>/semantic-sha256-<64 hex>` (it carries a slash), a loki one is
// `features-<64 hex>`. The identifiers are read from the pinned profile
// manifests, not typed here.
func TestSavedViewsAcceptEveryRealProfileAndFeatureSetID(t *testing.T) {
	f := newSVFx(t)
	files, err := filepath.Glob("../../profiles/query/*.json")
	if err != nil || len(files) < 3 {
		t.Fatalf("profile manifests: %v %v", files, err)
	}
	saved, slashed, longest := 0, 0, 0
	for _, file := range files {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		var p struct {
			ID          string `json:"id"`
			FeatureSets []struct {
				ID string `json:"id"`
			} `json:"feature_sets"`
		}
		if err = json.Unmarshal(raw, &p); err != nil || p.ID == "" || len(p.FeatureSets) == 0 {
			t.Fatalf("%s: %v", file, err)
		}
		language := "promql"
		if strings.HasPrefix(p.ID, "logql-") {
			language = "logql"
		}
		for _, fs := range p.FeatureSets {
			body := f.saveBody(f.org, f.p1, "real "+p.ID, "up")
			body["language"], body["profile"], body["feature_set"] = language, p.ID, fs.ID
			status, out := f.call(f.alice, body)
			var c httpapi.SavedViewCommitted
			if status != 200 || model.StrictJSON(out, &c) != nil || c.View == nil || c.View.Profile != p.ID || c.View.FeatureSet != fs.ID {
				t.Errorf("%s %s: %d %.300s", p.ID, fs.ID, status, out)
				continue
			}
			// A view is removed again so the project stays far below its cap.
			if status, out = f.call(f.alice, f.deleteBody(f.org, f.p1, c.View.ID, 1)); status != 200 {
				t.Fatalf("delete: %d %s", status, out)
			}
			saved++
			if strings.Contains(fs.ID, "/") {
				slashed++
			}
			longest = max(longest, len(fs.ID))
		}
	}
	if saved < 100 || slashed == 0 || longest < 100 {
		t.Fatalf("the manifests no longer cover the real shapes: %d saved, %d with a slash, longest %d", saved, slashed, longest)
	}
}

// svHookStore is the real control store with a hook before every read, so a test
// can change the world between two reads of one request.
type svHookStore struct {
	*control.Store
	reads  int
	before func(read int)
}

func (s *svHookStore) View(ctx context.Context, fn func(model.ControlState) error) error {
	s.reads++
	if s.before != nil {
		s.before(s.reads)
	}
	return s.Store.View(ctx, fn)
}

// The scope a request derives is validated again where the books are read and
// where a committed view is read back: a grant revoked between the scope's
// derivation and that read ends the request, it is not honoured until the next.
func TestSavedViewsRecheckTheGrantWhereTheyReadTheBooks(t *testing.T) {
	f := newSVFx(t)
	f.mustSave(f.alice, f.saveBody(f.org, f.p1, "secret "+svCanaryName, "up"+svCanaryExpr))
	hook := &svHookStore{Store: f.app.Control}
	svc, err := auth.NewService(auth.AuthDependencies{Control: hook})
	if err != nil {
		t.Fatal(err)
	}
	revokeAt := func(read int, who person) {
		hook.before = func(n int) {
			if n == read {
				hook.before = nil
				f.grant(f.org, who, f.p1, false)
			}
		}
	}
	denied := func(err error) bool { return faultCode(err) == model.NotFound }

	// A list makes a fixed number of control reads; its last one reads the books.
	bob, err := svc.Authenticate(f.ctx, f.bob.Session.Token)
	if err != nil {
		t.Fatal(err)
	}
	hook.reads = 0
	if views, err := svc.ListSavedViews(f.ctx, bob, f.org, f.p1); err != nil || len(views) != 1 {
		t.Fatalf("list: %v %v", views, err)
	}
	listReads := hook.reads
	hook.reads = 0
	revokeAt(listReads, f.bob)
	if views, err := svc.ListSavedViews(f.ctx, bob, f.org, f.p1); !denied(err) || len(views) != 0 {
		t.Fatalf("a grant revoked before the books were read still listed: %v %v", views, err)
	}

	// A save reads the committed view back as its last read.
	alice, err := svc.Authenticate(f.ctx, f.alice.Session.Token)
	if err != nil {
		t.Fatal(err)
	}
	spec := func(name string) auth.SavedViewSave {
		return auth.SavedViewSave{Org: f.org, Project: f.p1, CommandID: model.NewID(), Spec: auth.SavedViewSpec{Name: name, Language: "promql", Profile: queryProm, FeatureSet: f.promSet, Expression: "up", Projects: []model.ID{f.p1}, Mode: "instant"}}
	}
	hook.reads = 0
	if res, err := svc.SaveSavedView(f.ctx, alice, spec("probe")); err != nil || res.View == nil {
		t.Fatalf("save: %+v %v", res, err)
	}
	saveReads := hook.reads
	hook.reads = 0
	revokeAt(saveReads, f.alice)
	res, err := svc.SaveSavedView(f.ctx, alice, spec("revoked before the read-back"))
	if !denied(err) || res.View != nil {
		t.Fatalf("a view was returned to a caller whose grant was revoked: %+v %v", res, err)
	}
}
