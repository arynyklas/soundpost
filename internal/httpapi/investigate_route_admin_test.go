// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/incidents"
	"github.com/arynyklas/soundpost/internal/model"
)

// Criterion 05.02#7: over POST /api/v1/investigate the release and issue kinds are served to an organization administrator (the scope
// the dedicated evidence routes derive) and answer the typed reason to everybody else. Everything here goes through the real route, real
// sessions and the real control store of the kinds world.

// routeWorld is the kinds world behind a real HTTPS server that mounts only the investigate route.
type routeWorld struct {
	*kindsWorld
	srv *httptest.Server
}

func newRouteWorld(t *testing.T) *routeWorld {
	t.Helper()
	k := newKindsWorld(t)
	return &routeWorld{kindsWorld: k, srv: serveInvestigator(t, k, k.inv)}
}

func serveInvestigator(t *testing.T, k *kindsWorld, inv *httpapi.Investigator) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(httpapi.NewServer("", k.app.Auth, nil, func(mux *http.ServeMux) { httpapi.RegisterInvestigateRoutes(mux, k.app.Auth, inv) }).Handler)
	t.Cleanup(srv.Close)
	return srv
}

// investigate posts one typed request as who. extra adds body fields (elevation, source, permission).
func (w *routeWorld) investigate(who person, org model.ID, kind string, target model.ID, extra map[string]any, projects ...model.ID) (int, []byte) {
	w.t.Helper()
	return w.investigateAt(w.srv, who, org, kind, target, extra, projects...)
}

func (w *routeWorld) investigateAt(srv *httptest.Server, who person, org model.ID, kind string, target model.ID, extra map[string]any, projects ...model.ID) (int, []byte) {
	w.t.Helper()
	ids := make([]string, len(projects))
	for i, p := range projects {
		ids[i] = p.String()
	}
	body := map[string]any{"org": org.String(), "kind": kind, "projects": ids, "target": target.String(), "window": map[string]any{"start": "10", "end": "20"}, "limit": 10}
	for key, v := range extra {
		body[key] = v
	}
	return (&evEnv{isoEnv: w.isoEnv, srv: srv}).post(who, "/api/v1/investigate", body, nil)
}

// notFoundBody is a refusal reduced to what the caller can compare: status and body without the per-request ID.
func notFoundBody(t *testing.T, status int, raw []byte) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("not a JSON refusal (%d): %s", status, raw)
	}
	delete(m, "request_id")
	out, _ := json.Marshal(m)
	return strings.Join([]string{http.StatusText(status), string(out)}, " ")
}

func (w *routeWorld) releaseBuild(project, release model.ID) model.ID {
	w.t.Helper()
	var build model.ID
	if err := w.app.Control.View(w.ctx, func(st model.ControlState) error {
		build = st.Releases[model.ReleaseScopeKey(w.w.org, project, release)].BuildID
		return nil
	}); err != nil || build == (model.ID{}) {
		w.t.Fatalf("release build: %v", err)
	}
	return build
}

func TestInvestigateRouteServesReleaseToAnOrganizationAdministrator(t *testing.T) {
	w := newRouteWorld(t)
	p := w.w.project
	rel := w.release(p)
	build := w.releaseBuild(p, rel)

	status, raw := w.investigate(w.admin, w.w.org, "release", rel, nil, p)
	v := decodeView(t, raw)
	if status != 200 || v.State != httpapi.StateReady || v.Kind != httpapi.KindRelease || v.Org != w.w.org || v.Reason != "" {
		t.Fatalf("release over the route for an administrator: %d %s", status, raw)
	}
	if v.Release == nil || v.Release.ID != rel || v.Release.BuildID != build || v.Release.ProjectID != p || v.Release.BuildTime != 7 || v.Release.Revision == 0 || v.Release.DebugArtifacts != 1 || len(v.Release.Parents) != 0 {
		t.Fatalf("release summary: %s", raw)
	}
	if strings.Contains(string(raw), "SECRET-LABEL") {
		t.Fatalf("the summary leaked the caller-authored label: %s", raw)
	}
	// The sibling project the administrator also administers answers the same target as the one NotFound (it lives in p).
	if status, _ = w.investigate(w.admin, w.w.org, "release", rel, nil, w.w.sibling); status != 404 {
		t.Fatalf("a release asked under the sibling project: %d", status)
	}
	// Two requested projects: the first one that holds the target wins, as in process.
	status, raw = w.investigate(w.admin, w.w.org, "release", rel, nil, w.w.sibling, p)
	if v = decodeView(t, raw); status != 200 || v.Release == nil || v.Release.ID != rel {
		t.Fatalf("release over two requested projects: %d %s", status, raw)
	}
}

func TestInvestigateRouteServesIssueToAnOrganizationAdministrator(t *testing.T) {
	w := newRouteWorld(t)
	p := w.w.project
	iss, compacted := w.issue(p, false), w.issue(p, true)

	status, raw := w.investigate(w.admin, w.w.org, "issue", iss, nil, p)
	v := decodeView(t, raw)
	if status != 200 || v.State != httpapi.StateReady || v.Kind != httpapi.KindIssue || v.Reason != "" || v.Issue == nil || v.Issue.ID != iss || v.Issue.ProjectID != p ||
		v.Issue.Workflow != "open" || v.Issue.GroupingVersion != 3 || v.Issue.Revision != 4 || v.Issue.Occurrences != 2 || v.Issue.LateHistory != 1 || v.Issue.Compacted {
		t.Fatalf("issue over the route for an administrator: %d %s", status, raw)
	}
	// The truthful incompleteness of a compacted issue survives the route.
	status, raw = w.investigate(w.admin, w.w.org, "issue", compacted, nil, p)
	v = decodeView(t, raw)
	if status != 200 || v.State != httpapi.StateIncomplete || v.Reason != httpapi.ReasonEvidenceCompacted || v.Issue == nil || !v.Issue.Compacted || v.Issue.Occurrences != 7 {
		t.Fatalf("compacted issue over the route: %d %s", status, raw)
	}
}

// A project reader who is not an administrator is told the release records need administration, before any state is read, so a
// real and a guessed target are the same bytes and neither names the target. An error issue is her own project's data (D92): she
// is served it (see TestProjectReadersSeeErrorIssues for the whole matrix) and a guessed target is the one NotFound.
func TestInvestigateRouteTellsANonAdministratorTheTypedReasonAndNothingElse(t *testing.T) {
	w := newRouteWorld(t)
	p := w.w.project
	rel, iss := w.release(p), w.issue(p, false)
	var first []byte
	for name, target := range map[string]model.ID{"real": rel, "guessed": model.NewID()} {
		status, raw := w.investigate(w.w.reader, w.w.org, "release", target, nil, p)
		v := decodeView(t, raw)
		if status != 200 || v.State != httpapi.StateNotAvailable || v.Reason != httpapi.ReasonReleaseRecordsAdmin || v.Release != nil || v.Issue != nil {
			t.Fatalf("release (%s target) for a project reader: %d %s", name, status, raw)
		}
		if strings.Contains(string(raw), target.String()) || strings.Contains(string(raw), `"target`) || strings.Contains(string(raw), `"release":`) || strings.Contains(string(raw), `"issue":`) {
			t.Fatalf("release (%s target): the refusal carries target data: %s", name, raw)
		}
		if first == nil {
			first = raw
		} else if string(first) != string(raw) {
			t.Fatalf("release: a real and a guessed target are told apart: %s vs %s", first, raw)
		}
	}
	status, raw := w.investigate(w.w.reader, w.w.org, "issue", iss, nil, p)
	if v := decodeView(t, raw); status != 200 || v.State != httpapi.StateReady || v.Issue == nil || v.Issue.ID != iss || v.Release != nil {
		t.Fatalf("issue for a project reader: %d %s", status, raw)
	}
	if status, raw = w.investigate(w.w.reader, w.w.org, "issue", model.NewID(), nil, p); status != 404 {
		t.Fatalf("a guessed issue for a project reader: %d %s", status, raw)
	}
}

// Another organization's administrator, a wrong project, a sibling's record and an unknown target are all the one NotFound an
// administrator gets for a target that does not exist.
func TestInvestigateRouteRefusesForeignAndMissingTargetsAsOneNotFound(t *testing.T) {
	w := newRouteWorld(t)
	p, sibling := w.w.project, w.w.sibling
	rel, iss := w.release(p), w.issue(p, false)
	sibRel, sibIss := w.release(sibling), w.issue(sibling, false)
	pO := model.NewID()
	orgO := w.org("route other org", pO)
	adminO := w.user(orgO, "route-other-admin@example.test")
	w.cmd(orgO, "org_admin", auth.AdminPayload{UserID: adminO.ID, Enabled: true})

	for _, c := range []struct {
		kind               string
		own, sibRec, wrong model.ID
	}{{"release", rel, sibRel, model.NewID()}, {"issue", iss, sibIss, model.NewID()}} {
		baseStatus, baseRaw := w.investigate(w.admin, w.w.org, c.kind, c.wrong, nil, p)
		if baseStatus != 404 {
			t.Fatalf("%s: an administrator asking a missing target: %d %s", c.kind, baseStatus, baseRaw)
		}
		want := notFoundBody(t, baseStatus, baseRaw)
		for name, probe := range map[string]func() (int, []byte){
			"another organization's administrator asking this organization": func() (int, []byte) {
				return w.investigate(adminO, w.w.org, c.kind, c.own, nil, p)
			},
			"another organization's administrator asking this project in their own organization": func() (int, []byte) {
				return w.investigate(adminO, orgO, c.kind, c.own, nil, p)
			},
			"another organization's administrator asking their own project for this record": func() (int, []byte) {
				return w.investigate(adminO, orgO, c.kind, c.own, nil, pO)
			},
			"this organization's administrator asking the other organization": func() (int, []byte) {
				return w.investigate(w.admin, orgO, c.kind, c.own, nil, pO)
			},
			"a sibling project's record asked under this project": func() (int, []byte) {
				return w.investigate(w.admin, w.w.org, c.kind, c.sibRec, nil, p)
			},
			"a project that holds nothing": func() (int, []byte) {
				return w.investigate(w.admin, w.w.org, c.kind, c.own, nil, w.p3)
			},
			"an unknown project": func() (int, []byte) {
				return w.investigate(w.admin, w.w.org, c.kind, c.own, nil, model.NewID())
			},
		} {
			status, raw := probe()
			if got := notFoundBody(t, status, raw); status != 404 || got != want {
				t.Fatalf("%s / %s: %d %s, want the one NotFound %q", c.kind, name, status, raw, want)
			}
			for _, s := range []string{rel.String(), iss.String(), sibRel.String(), sibIss.String()} {
				if strings.Contains(string(raw), s) {
					t.Fatalf("%s / %s: the refusal names a record: %s", c.kind, name, raw)
				}
			}
		}
	}
}

// An elevation, a source or a non-read permission never combine with administration: the request keeps the scope the other reads
// would give it and answers the typed reason (or is refused), exactly as before the route derived an administrator scope.
func TestInvestigateRouteNeverCombinesAdministrationWithElevationOrSource(t *testing.T) {
	w := newRouteWorld(t)
	p := w.w.project
	rel, iss := w.release(p), w.issue(p, false)
	// The instance owner is also an organization administrator here, so the only thing that can keep her out of the registries is the
	// elevation or source the request carries.
	owner := w.actor
	w.cmd(w.w.org, "org_admin", auth.AdminPayload{UserID: owner.ID, Enabled: true})
	elev, err := w.app.Auth.Elevate(w.ctx, owner.Session, "route admin test", []model.ID{w.w.org})
	if err != nil {
		t.Fatal(err)
	}
	// The elevation's ID is only exposed on the wire (its JSON form), exactly what a client sends back.
	var elevation struct {
		ID model.ID `json:"id"`
	}
	if rawElev, merr := json.Marshal(elev); merr != nil || json.Unmarshal(rawElev, &elevation) != nil || elevation.ID == (model.ID{}) {
		t.Fatalf("elevation: %s %v", rawElev, merr)
	}
	for _, c := range []struct {
		kind   string
		target model.ID
		reason string
	}{{"release", rel, httpapi.ReasonReleaseRecordsAdmin}, {"issue", iss, ""}} {
		// Control: without elevation or source the same caller is served.
		status, raw := w.investigate(owner, w.w.org, c.kind, c.target, nil, p)
		if v := decodeView(t, raw); status != 200 || v.State != httpapi.StateReady || (v.Release == nil && v.Issue == nil) {
			t.Fatalf("%s control (administrator, no elevation): %d %s", c.kind, status, raw)
		}
		// A real elevation is a project-read scope over the route: release records stay refused (the typed reason), and an error
		// issue is not served under it either: the issue lifecycle serves the caller's own grants, and an elevation is no grant, so
		// the answer is the one NotFound and carries nothing. It is never administration.
		status, raw = w.investigate(owner, w.w.org, c.kind, c.target, map[string]any{"elevation": elevation.ID.String()}, p)
		if c.kind == "issue" {
			if status != 404 || strings.Contains(string(raw), c.target.String()) || strings.Contains(string(raw), `"issue":`) {
				t.Fatalf("issue with an elevation: %d %s, want the one NotFound", status, raw)
			}
		} else if v := decodeView(t, raw); status != 200 || v.State != httpapi.StateNotAvailable || v.Reason != c.reason || v.Release != nil || v.Issue != nil || strings.Contains(string(raw), c.target.String()) {
			t.Fatalf("%s with an elevation became administration: %d %s", c.kind, status, raw)
		}
		// An unknown elevation, a source on a read request and a raw permission with a source are refused exactly as the other reads
		// refuse them; none of them is served.
		for name, tc := range map[string]struct {
			extra  map[string]any
			status int
		}{
			"unknown elevation":              {map[string]any{"elevation": model.NewID().String()}, 404},
			"source on a read request":       {map[string]any{"source": model.NewID().String()}, 400},
			"raw permission without source":  {map[string]any{"permission": "raw.read"}, 400},
			"raw permission and a source":    {map[string]any{"permission": "raw.read", "source": model.NewID().String()}, 404},
			"elevation with raw and source":  {map[string]any{"elevation": elevation.ID.String(), "permission": "raw.read", "source": model.NewID().String()}, 403},
			"elevation with a source (read)": {map[string]any{"elevation": elevation.ID.String(), "source": model.NewID().String()}, 403},
		} {
			status, raw = w.investigate(owner, w.w.org, c.kind, c.target, tc.extra, p)
			if status != tc.status || strings.Contains(string(raw), c.target.String()) || strings.Contains(string(raw), `"release":`) || strings.Contains(string(raw), `"issue":`) {
				t.Fatalf("%s / %s: %d %s, want %d and no record", c.kind, name, status, raw, tc.status)
			}
		}
	}
}

// Only release and issue take the administrator scope: every other kind keeps the project-read scope, so an administrator who holds
// no telemetry.read grant is refused an incident exactly as before, while a reader is served.
func TestInvestigateRouteKeepsTheProjectReadScopeForTheOtherKinds(t *testing.T) {
	w := newRouteWorld(t)
	p := w.w.project
	incident := w.open(p, incidents.SeverityMajor)
	bare := w.user(w.w.org, "route-kinds-admin@example.test")
	w.cmd(w.w.org, "org_admin", auth.AdminPayload{UserID: bare.ID, Enabled: true})
	if status, raw := w.investigate(w.w.reader, w.w.org, "incident", incident, nil, p); status != 200 || decodeView(t, raw).Incident == nil {
		t.Fatalf("control: a project reader asking an incident: %d %s", status, raw)
	}
	if status, raw := w.investigate(bare, w.w.org, "incident", incident, nil, p); status != 404 || strings.Contains(string(raw), incident.String()) {
		t.Fatalf("an administrator without a read grant was served an incident: %d %s", status, raw)
	}
}

// A revoked administrator is not served as one: the next request is the typed reason for the release records when she still reads
// the project (and her own project's error issue, as a reader), and the one NotFound when she holds nothing there, never a stale ready.
func TestInvestigateRouteStopsServingARevokedAdministrator(t *testing.T) {
	w := newRouteWorld(t)
	p := w.w.project
	rel, iss := w.release(p), w.issue(p, false)
	reading := w.admin
	w.grant(w.w.org, reading, p, true, auth.Read)
	bare := w.user(w.w.org, "route-bare-admin@example.test")
	w.cmd(w.w.org, "org_admin", auth.AdminPayload{UserID: bare.ID, Enabled: true})

	served := func(who person) {
		t.Helper()
		for kind, target := range map[string]model.ID{"release": rel, "issue": iss} {
			if status, raw := w.investigate(who, w.w.org, kind, target, nil, p); status != 200 || decodeView(t, raw).State != httpapi.StateReady {
				t.Fatalf("%s before the revocation: %d %s", kind, status, raw)
			}
		}
	}
	served(reading)
	served(bare)
	w.cmd(w.w.org, "org_admin", auth.AdminPayload{UserID: reading.ID, Enabled: false})
	w.cmd(w.w.org, "org_admin", auth.AdminPayload{UserID: bare.ID, Enabled: false})
	for kind, c := range map[string]struct {
		target model.ID
		reason string
	}{"release": {rel, httpapi.ReasonReleaseRecordsAdmin}, "issue": {iss, ""}} {
		status, raw := w.investigate(reading, w.w.org, kind, c.target, nil, p)
		v := decodeView(t, raw)
		if kind == "issue" {
			// She still reads the project: the error issue is hers to read as a reader (D92), not as the administrator she was.
			if status != 200 || v.State != httpapi.StateReady || v.Issue == nil || v.Issue.ID != iss {
				t.Fatalf("issue for a revoked administrator who still reads: %d %s", status, raw)
			}
		} else if status != 200 || v.State != httpapi.StateNotAvailable || v.Reason != c.reason || v.Release != nil || v.Issue != nil {
			t.Fatalf("%s for a revoked administrator who still reads: %d %s", kind, status, raw)
		}
		if status, raw = w.investigate(bare, w.w.org, kind, c.target, nil, p); status != 404 || strings.Contains(string(raw), c.target.String()) {
			t.Fatalf("%s for a revoked administrator with no grant: %d %s", kind, status, raw)
		}
	}
}

// revokeAfterView is a labelled double of the control store the investigator reads: it behaves as the real store, and right after a
// state read has finished it runs hook once, so a revocation can land between the read and the response.
type revokeAfterView struct {
	*control.Store
	hook *func()
}

func (r revokeAfterView) View(ctx context.Context, fn func(model.ControlState) error) error {
	err := r.Store.View(ctx, fn)
	if h := *r.hook; h != nil {
		*r.hook = nil
		h()
	}
	return err
}

// The administrator scope is revalidated after the registry is read and before a single byte of the view is written: an
// administrator revoked in that window gets the NotFound, not the record.
func TestInvestigateRouteRevalidatesTheAdministratorScopeBeforeWritingTheView(t *testing.T) {
	w := newRouteWorld(t)
	p := w.w.project
	rel, iss := w.release(p), w.issue(p, false)
	var hook func()
	var fired atomic.Int32
	racing, err := httpapi.NewInvestigator(w.app.Auth, &fakeDiscovery{}, &fakeLinks{})
	if err != nil {
		t.Fatal(err)
	}
	racing.WithHealth(revokeAfterView{Store: w.app.Control, hook: &hook})
	srv := serveInvestigator(t, w.kindsWorld, racing)

	for kind, target := range map[string]model.ID{"release": rel, "issue": iss} {
		admin := w.user(w.w.org, "route-race-"+kind+"@example.test")
		w.cmd(w.w.org, "org_admin", auth.AdminPayload{UserID: admin.ID, Enabled: true})
		if status, raw := w.investigateAt(srv, admin, w.w.org, kind, target, nil, p); status != 200 || decodeView(t, raw).State != httpapi.StateReady {
			t.Fatalf("%s: the double changed the served answer: %d %s", kind, status, raw)
		}
		hook = func() {
			fired.Add(1)
			var revision model.Revision
			if err := w.app.Control.View(w.ctx, func(st model.ControlState) error { revision = st.Revision; return nil }); err != nil {
				t.Error(err)
				return
			}
			raw, _ := json.Marshal(auth.AdminPayload{UserID: admin.ID, Enabled: false, Reason: "revoked mid-request"})
			if _, err := w.app.Auth.AdminCommand(w.ctx, w.actor.Cred, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: revision, OrgID: w.w.org, Kind: "org_admin", Payload: raw}); err != nil {
				t.Error(err)
			}
		}
		status, raw := w.investigateAt(srv, admin, w.w.org, kind, target, nil, p)
		if fired.Load() == 0 {
			t.Fatalf("%s: the revocation never landed between the read and the response", kind)
		}
		fired.Store(0)
		if status != 404 || strings.Contains(string(raw), target.String()) || strings.Contains(string(raw), `"release":`) || strings.Contains(string(raw), `"issue":`) {
			t.Fatalf("%s: an administrator revoked before the response was served the record: %d %s", kind, status, raw)
		}
	}
}
