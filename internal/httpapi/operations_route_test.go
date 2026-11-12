// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"soundpost/internal/auth"
	"soundpost/internal/httpapi"
	"soundpost/internal/model"
)

// opsEnv mounts the real routes in BOTH orders on two servers: source-policy
// routes first and action routes first. The one GET /api/v1/operations/{id}
// route must answer the same either way.
type opsEnv struct {
	*delEnv
	servers map[string]*httptest.Server
}

func newOpsEnv(t *testing.T) *opsEnv {
	t.Helper()
	e := &opsEnv{delEnv: newDelEnv(t), servers: map[string]*httptest.Server{}}
	mount := func(name string, sourceFirst bool) {
		actions, err := httpapi.NewActions(e.app.Incidents, e.app.Control, e.app.Control, e.app.Retention, wallClock{})
		if err != nil {
			t.Fatal(err)
		}
		srv := httptest.NewTLSServer(httpapi.NewServer("", e.app.Auth, nil, func(mux *http.ServeMux) {
			if sourceFirst {
				httpapi.RegisterSourcePolicyRoutes(mux, e.app.Auth)
			}
			httpapi.RegisterDeletionRoutes(mux, e.app.Auth, e.deleter)
			httpapi.RegisterActionRoutes(mux, e.app.Auth, actions)
			if !sourceFirst {
				httpapi.RegisterSourcePolicyRoutes(mux, e.app.Auth)
			}
		}).Handler)
		t.Cleanup(srv.Close)
		e.servers[name] = srv
	}
	mount("source-first", true)
	mount("actions-first", false)
	return e
}

func (e *opsEnv) get(srv *httptest.Server, who *person, path string) (int, []byte) {
	e.t.Helper()
	req, _ := http.NewRequest("GET", srv.URL+path, nil)
	if who != nil {
		req.Header.Set("Cookie", "__Host-soundpost="+who.Session.Token)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

// sourceOperation begins a real source-policy change and returns its id.
func (e *opsEnv) sourceOperation(f delFixture) model.ID {
	e.t.Helper()
	ids := sharedIDs{f.source.Service, f.source.Environment, f.source.Bd}
	policy := model.SourcePolicy{Revision: 2, Enabled: true, Class: "structured", Kinds: []model.Kind{model.Metric}, Resources: model.ResourceRegistry{Services: []model.ID{ids.Service}, Environments: []model.ID{ids.Environment}, Builds: []model.ID{ids.Build}, Instances: []string{"opaque-instance"}}, RetentionDays: map[model.Kind]uint32{model.Metric: 7}, MaxBytes: 1 << 20, MaxSeries: 100}
	op, err := e.app.Auth.ChangeSourcePolicy(e.ctx, e.actor.Cred, auth.SourcePolicyChange{CommandID: model.NewID(), Source: f.source.ID, ExpectedRevision: 1, Policy: policy, Reason: "operations route test"})
	if err != nil {
		e.t.Fatal(err)
	}
	return op.Operation
}

func TestOperationsRouteAnswersBothKindsAtTheContractPath(t *testing.T) {
	e := newOpsEnv(t)
	f := e.fixture("opsroute")
	sourceOp := e.sourceOperation(f)
	status, raw := e.begin(&f.admin, e.retire(f.org, f.project), nil)
	deletion := e.receipt(status, 202, raw).OperationID
	org := f.org.String()

	for name, srv := range e.servers {
		// A deletion id answers its LifecycleOperation at the contract path, byte
		// for byte what the /lifecycle alias answers.
		cs, craw := e.get(srv, &f.admin, "/api/v1/operations/"+deletion.String()+"?org="+org)
		as, araw := e.get(srv, &f.admin, "/api/v1/lifecycle/operations/"+deletion.String()+"?org="+org)
		if cs != 200 || as != 200 {
			t.Fatalf("%s: deletion poll: contract %d %s, alias %d %s", name, cs, craw, as, araw)
		}
		var op httpapi.LifecycleOperation
		if err := model.StrictJSON(craw, &op); err != nil || op.ID != deletion || op.State != httpapi.StateReady || (op.Phase != model.DeletePhaseFencing && op.Phase != model.DeletePhaseComplete) {
			t.Fatalf("%s: not the deletion's LifecycleOperation: %v %s", name, err, craw)
		}
		if op.Phase == model.DeletePhaseFencing && string(craw) != string(araw) {
			t.Fatalf("%s: contract and alias differ: %s vs %s", name, craw, araw)
		}

		// A source-policy id answers in its own shape, with and without ?org=.
		ss, sraw := e.get(srv, &f.admin, "/api/v1/operations/"+sourceOp.String())
		if ss != 200 || !strings.Contains(string(sraw), sourceOp.String()) || strings.Contains(string(sraw), `"state"`) {
			t.Fatalf("%s: source operation: %d %s", name, ss, sraw)
		}
		ws, wraw := e.get(srv, &f.admin, "/api/v1/operations/"+sourceOp.String()+"?org="+org)
		if ws != 200 || string(wraw) != string(sraw) {
			t.Fatalf("%s: source operation with ?org= differs: %d %s vs %s", name, ws, wraw, sraw)
		}
		// A deletion id without the organization selector is a plain not-found.
		if ns, nraw := e.get(srv, &f.admin, "/api/v1/operations/"+deletion.String()); ns != 404 {
			t.Fatalf("%s: unscoped deletion id: %d %s", name, ns, nraw)
		}
		// A source id polled under another organization's selector is not found.
		other := e.org("opsroute-own-"+name, model.NewID())
		if ns, nraw := e.get(srv, &f.admin, "/api/v1/operations/"+sourceOp.String()+"?org="+other.String()); ns != 404 {
			t.Fatalf("%s: source id under the wrong org: %d %s", name, ns, nraw)
		}
		if ns, nraw := e.get(srv, &f.admin, "/api/v1/operations/"+sourceOp.String()+"?org="+org+"&x=1"); ns != 400 {
			t.Fatalf("%s: unknown query key: %d %s", name, ns, nraw)
		}
	}
}

func TestOperationsRouteForeignMissingAndAnonymousAreRefused(t *testing.T) {
	e := newOpsEnv(t)
	f := e.fixture("opsforeign")
	sourceOp := e.sourceOperation(f)
	status, raw := e.begin(&f.admin, e.retire(f.org, f.project), nil)
	deletion := e.receipt(status, 202, raw).OperationID
	stranger := e.org("opsforeign-other", model.NewID())
	foreign := e.user(stranger, "opsforeign-admin@example.test")
	e.orgAdmin(stranger, foreign)

	for name, srv := range e.servers {
		shapes := map[string]string{}
		note := func(label string, who *person, path string, want int) {
			t.Helper()
			status, raw := e.get(srv, who, path)
			if status != want {
				t.Errorf("%s %s: status %d, want %d: %s", name, label, status, want, raw)
				return
			}
			if want == 404 {
				for _, secret := range []string{deletion.String(), sourceOp.String(), f.org.String()} {
					if strings.Contains(string(raw), secret) {
						t.Errorf("%s %s: refusal echoes %s: %s", name, label, secret, raw)
					}
				}
				shapes[label] = denial(t, status, raw)
			}
		}
		for _, base := range []string{"/api/v1/operations/", "/api/v1/lifecycle/operations/"} {
			ghost := model.NewID().String()
			own := "?org=" + stranger.String()
			note(base+"foreign deletion under own org", &foreign, base+deletion.String()+own, 404)
			note(base+"foreign deletion under victim org", &foreign, base+deletion.String()+"?org="+f.org.String(), 404)
			note(base+"missing id under own org", &foreign, base+ghost+own, 404)
			note(base+"missing id under victim org", &f.admin, base+ghost+"?org="+f.org.String(), 404)
			note(base+"member", &f.member, base+deletion.String()+"?org="+f.org.String(), 404)
			note(base+"anonymous deletion", nil, base+deletion.String()+"?org="+f.org.String(), 401)
		}
		// Contract path only: source ids.
		note("foreign source id", &foreign, "/api/v1/operations/"+sourceOp.String(), 404)
		note("foreign source id under own org", &foreign, "/api/v1/operations/"+sourceOp.String()+"?org="+stranger.String(), 404)
		note("foreign source id under victim org", &foreign, "/api/v1/operations/"+sourceOp.String()+"?org="+f.org.String(), 404)
		note("missing id, no org", &foreign, "/api/v1/operations/"+model.NewID().String(), 404)
		note("anonymous source id", nil, "/api/v1/operations/"+sourceOp.String(), 401)
		note("malformed id", &f.admin, "/api/v1/operations/zz?org="+f.org.String(), 404)
		// Which store holds an id is not observable: for the same caller and the
		// same selector a source id, a deletion id of a foreign org and a ghost
		// are one answer.
		a := shapes["foreign source id under own org"]
		for _, label := range []string{"foreign source id under victim org", "/api/v1/operations/foreign deletion under own org", "/api/v1/operations/missing id under own org", "/api/v1/operations/foreign deletion under victim org"} {
			if shapes[label] != a {
				t.Errorf("%s: %q distinguishes: %q vs %q", name, label, shapes[label], a)
			}
		}
	}
}
