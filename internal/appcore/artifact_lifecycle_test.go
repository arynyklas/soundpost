// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"soundpost/internal/appcore"
	"soundpost/internal/artifacts"
	"soundpost/internal/auth"
	"soundpost/internal/httpapi"
	"soundpost/internal/model"
	"soundpost/internal/retention"
	"soundpost/internal/storage"
)

// The tests below drive the REAL application (appcore.Open: real storage, real
// control, real retention worker pass) through the artifact HTTP route. They use
// the wall clock: the retention service and the lifecycle both read time.Now in the
// served process, so an upload that must "expire" is uploaded with a short
// retention and the test waits for it. A window that a heavily loaded host
// overruns is reported as such (see wlWindow), not as a lifecycle defect.

const (
	wlBase = 4 * time.Second // the upload's own retention in these tests
	wlRef  = 40 * time.Second
)

// wlNoPins is the probe pin source of the fallback lifecycle (see lifecycleOf).
type wlNoPins struct{}

func (wlNoPins) Pinned(context.Context, model.ID, model.ID, model.ID) (bool, error) {
	return false, nil
}

type wlRig struct {
	t                           *testing.T
	ctx                         context.Context
	dir, token                  string
	user                        model.ID
	org, project, source, build model.ID
	writeToken, readToken       string
	app                         *appcore.App
	server                      *httptest.Server
	probe                       *artifacts.Lifecycle
}

func newWLRig(t *testing.T) *wlRig {
	t.Helper()
	r := &wlRig{t: t, ctx: context.Background(), dir: t.TempDir(), org: model.NewID(), project: model.NewID(), source: model.NewID(), build: model.NewID()}
	r.open()
	t.Cleanup(r.close)
	bootstrap, err := r.app.Control.BootstrapToken()
	if err != nil {
		t.Fatal(err)
	}
	session, err := r.app.Auth.Bootstrap(r.ctx, bootstrap, "lifecycle@example.test", "lifecycle wiring password 2026")
	if err != nil {
		t.Fatal(err)
	}
	r.token, r.user = session.Token, session.User
	actor, err := r.app.Auth.Authenticate(r.ctx, r.token)
	if err != nil {
		t.Fatal(err)
	}
	for _, cmd := range []struct {
		kind string
		p    auth.AdminPayload
	}{{"create_org", auth.AdminPayload{Name: "lifecycle"}}, {"create_project", auth.AdminPayload{ID: r.project, Name: "builds"}}} {
		cmd.p.Reason = "lifecycle wiring"
		raw, encodeErr := json.Marshal(cmd.p)
		if encodeErr != nil {
			t.Fatal(encodeErr)
		}
		var rev model.Revision
		if err = r.app.Control.View(r.ctx, func(st model.ControlState) error { rev = st.Revision; return nil }); err != nil {
			t.Fatal(err)
		}
		if _, err = r.app.Auth.AdminCommand(r.ctx, actor, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: rev, OrgID: r.org, Kind: cmd.kind, Payload: raw}); err != nil {
			t.Fatal(err)
		}
	}
	if err = r.app.Control.Update(r.ctx, func(st *model.ControlState) error {
		o := st.Orgs[r.org.String()]
		o.Members[session.User.String()] = true
		o.Grants[session.User.String()+":"+r.project.String()] = []string{"artifacts.write", "artifacts.read", "raw.read"}
		cfg, encodeErr := json.Marshal(auth.SourcePolicyConfig{ProjectID: r.project, Enabled: true, Readers: []model.ID{session.User}})
		if encodeErr != nil {
			return encodeErr
		}
		o.Settings["source_policy:"+r.source.String()] = cfg
		st.Orgs[r.org.String()] = o
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = r.app.Auth.OnboardSource(r.ctx, actor, auth.SourceOnboarding{
		CommandID: model.NewID(), Org: r.org, Project: r.project, Source: r.source,
		Expires: model.UnixNano(time.Now().Add(24 * time.Hour).UnixNano()),
		Policy: model.SourcePolicy{
			Enabled: true, Revision: 1, Class: "structured", Kinds: []model.Kind{model.Metric},
			Resources: model.ResourceRegistry{
				Services: []model.ID{model.NewID()}, Environments: []model.ID{model.NewID()},
				Builds: []model.ID{r.build}, Instances: []string{"lifecycle-wiring"},
			},
			RetentionDays: map[model.Kind]uint32{model.Metric: 30}, MaxBytes: 1 << 30, MaxSeries: 1000,
		},
		Reason: "lifecycle wiring real source authority",
	}); err != nil {
		t.Fatal(err)
	}
	expires := time.Now().Add(24 * time.Hour).Unix()
	w, err := r.app.Auth.IssueServerToken(r.ctx, actor, r.org, r.user, []model.ID{r.project}, []auth.Permission{auth.ArtifactWrite}, expires, "lifecycle write")
	if err != nil {
		t.Fatal(err)
	}
	rd, err := r.app.Auth.IssueServerToken(r.ctx, actor, r.org, r.user, []model.ID{r.project}, []auth.Permission{auth.ArtifactRead}, expires, "lifecycle read")
	if err != nil {
		t.Fatal(err)
	}
	r.writeToken, r.readToken = w.Token, rd.Token
	return r
}

func (r *wlRig) open() {
	r.t.Helper()
	app, err := appcore.Open(r.dir)
	if err != nil {
		r.t.Fatalf("open: %v", err)
	}
	r.app = app
	r.probe = nil
	r.server = httptest.NewTLSServer(httpapi.NewServer("", app.Auth, nil, app.Register).Handler)
}

func (r *wlRig) close() {
	if r.server != nil {
		r.server.Close()
		r.server = nil
	}
	if r.app != nil {
		r.app.Close()
		r.app = nil
	}
}

// restart is the process restart: close everything, open the same root again.
func (r *wlRig) restart() {
	r.t.Helper()
	r.close()
	r.open()
}

func (r *wlRig) scope(action auth.Permission) auth.Scope {
	r.t.Helper()
	actor, err := r.app.Auth.Authenticate(r.ctx, r.token)
	if err != nil {
		r.t.Fatal(err)
	}
	s, err := r.app.Auth.Authorize(r.ctx, actor, r.org, []model.ID{r.project}, action)
	if err != nil {
		r.t.Fatal(err)
	}
	return s
}

func (r *wlRig) adminScope() auth.Scope {
	r.t.Helper()
	actor, err := r.app.Auth.Authenticate(r.ctx, r.token)
	if err != nil {
		r.t.Fatal(err)
	}
	s, err := r.app.Auth.Authorize(r.ctx, actor, r.org, nil, auth.OrgAdmin)
	if err != nil {
		r.t.Fatal(err)
	}
	return s
}

// lifecycleOf is the served application's own lifecycle. strict: a missing one is a
// failure. Not strict: on a tree whose App has no ArtifactLifecycle field at all (the
// service is not wired into appcore.Open) the test builds a lifecycle the way the
// artifact-policy smoke does (in-process, over the app's service) so that it runs on
// and fails at the behaviour that the missing wiring breaks. A field that exists and
// is nil is always a failure.
func (r *wlRig) lifecycleOf(strict bool) *artifacts.Lifecycle {
	r.t.Helper()
	f := reflect.ValueOf(r.app).Elem().FieldByName("ArtifactLifecycle")
	if !f.IsValid() {
		if strict {
			r.t.Fatal("appcore.App has no ArtifactLifecycle: appcore.Open does not build the artifact lifecycle")
		}
		if r.probe == nil {
			life, err := artifacts.NewLifecycle(r.app.Artifacts, artifacts.LifecycleConfig{State: r.app.Control, Deletes: r.app.Retention, Pins: wlNoPins{}, CacheBytes: 1 << 20})
			if err != nil {
				r.t.Fatal(err)
			}
			r.probe = life
		}
		return r.probe
	}
	life, _ := f.Interface().(*artifacts.Lifecycle)
	if life == nil {
		r.t.Fatal("appcore.App.ArtifactLifecycle is nil after Open")
	}
	return life
}

func (r *wlRig) upload(debug string, private bool, retain time.Duration) artifacts.Artifact {
	r.t.Helper()
	raw := []byte(`{"version":3,"sources":["a.ts"],"names":[],"mappings":"AAAA","sourcesContent":["PRIVATE SOURCE ` + debug + `"]}`)
	m := artifacts.Manifest{Version: 1, Org: r.org, Project: r.project, Source: r.source, Build: r.build, DebugID: debug,
		GeneratedSHA256: model.HashCanonical([]byte("generated")), MapSHA256: model.HashCanonical(raw), Path: "dist/" + debug + ".js",
		SourceContent: private, Size: model.Uint64(len(raw)), RetainUntil: model.UnixNano(time.Now().Add(retain).UnixNano())}
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	part, _ := w.CreateFormField("manifest")
	encoded, _ := json.Marshal(m)
	part.Write(encoded)
	part, _ = w.CreateFormFile("file", "unused.map")
	part.Write(raw)
	w.Close()
	status, reply := r.post(r.writeToken, w.FormDataContentType(), body.Bytes())
	if status != 200 {
		r.t.Fatalf("upload through the artifact route: %d %s", status, reply)
	}
	var a artifacts.Artifact
	if err := model.StrictJSON(reply, &a); err != nil {
		r.t.Fatalf("upload receipt: %v", err)
	}
	return a
}

func (r *wlRig) post(token, contentType string, body []byte) (int, []byte) {
	r.t.Helper()
	req, err := http.NewRequest("POST", r.server.URL+"/api/v1/artifacts", bytes.NewReader(body))
	if err != nil {
		r.t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", contentType)
	resp, err := r.server.Client().Do(req)
	if err != nil {
		r.t.Fatal(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		r.t.Fatal(err)
	}
	return resp.StatusCode, data
}

// routeRead is the status of reading the map through the artifact route.
func (r *wlRig) routeRead(id model.ID) int {
	r.t.Helper()
	query, _ := json.Marshal(httpapi.ArtifactReadRequest{Operation: "read", Org: r.org, Project: r.project, ID: id})
	status, _ := r.post(r.readToken, "application/json", query)
	return status
}

func (r *wlRig) candidate(a artifacts.Artifact) storage.EraseCandidate {
	m := a.Map.Manifest
	return storage.EraseCandidate{Org: m.Org, Project: m.Project, Blob: &m, Cursor: a.Map.Cursor}
}

func (r *wlRig) origin(kind artifacts.ReferenceKind, index uint64) artifacts.OriginCursor {
	return artifacts.OriginCursor{Kind: kind, Cursor: model.Cursor{Group: model.NewID(), Index: model.Uint64(index)}}
}

func (r *wlRig) reference(life *artifacts.Lifecycle, a artifacts.Artifact, o artifacts.OriginCursor, until time.Time) {
	r.t.Helper()
	at := model.UnixNano(0)
	if !until.IsZero() {
		at = model.UnixNano(until.UnixNano())
	}
	if err := life.Reference(r.ctx, r.scope(auth.ArtifactWrite), a.ID, o, at); err != nil {
		r.t.Fatalf("Reference: %v", err)
	}
}

// present reports whether the artifact root still exists in the storage engine.
func (r *wlRig) present(a artifacts.Artifact) bool {
	r.t.Helper()
	err := r.app.Storage.VerifyBlob(r.ctx, a.Map)
	if err == nil {
		return true
	}
	if wlCode(err) != model.Unavailable {
		r.t.Fatalf("VerifyBlob: %v", err)
	}
	return false
}

func wlCode(err error) model.Code {
	var fault *model.Fault
	if errors.As(err, &fault) {
		return fault.Code
	}
	return ""
}

func wlSleepUntil(t time.Time) { time.Sleep(time.Until(t) + 150*time.Millisecond) }

// wlWindow fails the test when the host was too slow to make an assertion inside the
// window it is about (a retained map "before T"): a missed window says nothing about
// the lifecycle, so the failure says that instead.
func wlWindow(t *testing.T, what string, deadline time.Time) {
	t.Helper()
	if !time.Now().Before(deadline) {
		t.Fatalf("host too slow: %s was not observed before its deadline; rerun alone", what)
	}
}

func (r *wlRig) runOnce() error { return r.app.Retention.RunOnce(r.ctx) }

func (r *wlRig) ledgerKey() (string, json.RawMessage) {
	r.t.Helper()
	var key string
	var raw json.RawMessage
	if err := r.app.Control.View(r.ctx, func(st model.ControlState) error {
		for k, v := range st.Orgs[r.org.String()].Settings {
			if strings.HasPrefix(k, "artifact_refs:") {
				key, raw = k, append(json.RawMessage(nil), v...)
			}
		}
		return nil
	}); err != nil || key == "" {
		r.t.Fatalf("no durable reference ledger: %v", err)
	}
	return key, raw
}

func (r *wlRig) setSetting(key string, raw json.RawMessage) {
	r.t.Helper()
	if err := r.app.Control.Update(r.ctx, func(st *model.ControlState) error {
		o := st.Orgs[r.org.String()]
		o.Settings[key] = raw
		st.Orgs[r.org.String()] = o
		return nil
	}); err != nil {
		r.t.Fatal(err)
	}
}

// The served process builds the lifecycle, binds it to its own artifact service as
// the read gate and to its retention service as the References source, once.
func TestOpenWiresTheArtifactLifecycle(t *testing.T) {
	r := newWLRig(t)
	life := r.lifecycleOf(true)
	a := r.upload("wired", false, wlBase)
	// Bound to the app's artifact service: the lifecycle resolves an artifact that
	// was uploaded through the app's own service.
	if _, err := life.EffectiveRetention(r.ctx, r.scope(auth.ArtifactRead), a.ID); err != nil {
		t.Fatalf("the lifecycle does not see the app's artifacts: %v", err)
	}
	// Retention already has its References source: a second binding is refused, and
	// the refusal is a Conflict, never a replacement.
	err := r.app.Retention.UseReferences(life)
	if wlCode(err) != model.Conflict {
		t.Fatalf("retention accepted a second References binding (or none was bound): %v", err)
	}
	if wlCode(r.app.Retention.UseReferences(nil)) != model.Invalid {
		t.Fatal("a nil References source was accepted")
	}
}

// (a) Reads go through the lifecycle's gate on the app's own service: each case
// below is a fence only the gate adds (the common Get path has none of them).
func TestWiredLifecycleReadGate(t *testing.T) {
	t.Run("a deleted project is unreadable at once through the route", func(t *testing.T) {
		r := newWLRig(t)
		r.lifecycleOf(true)
		a := r.upload("gone", false, time.Hour)
		if status := r.routeRead(a.ID); status != 200 {
			t.Fatalf("read before deletion: %d", status)
		}
		reader, err := r.app.Artifacts.ReadAuthorized(r.ctx, r.scope(auth.ArtifactRead), a.ID, artifacts.Window{})
		if err != nil {
			t.Fatal(err)
		}
		defer reader.Close()
		var rev model.Revision
		if err = r.app.Control.View(r.ctx, func(st model.ControlState) error { rev = st.Revision; return nil }); err != nil {
			t.Fatal(err)
		}
		if _, err = r.app.Retention.Delete(r.ctx, r.adminScope(), retention.DeleteRequest{CommandID: model.NewID(), ExpectedRevision: rev, Mode: model.DeleteRetireProject, OrgID: r.org, ProjectIDs: []model.ID{r.project}, Reason: "lifecycle wiring"}); err != nil {
			t.Fatal(err)
		}
		if status := r.routeRead(a.ID); status == 200 {
			t.Fatal("the map was readable through the route after its project's deletion began")
		}
		if n, err := reader.Read(make([]byte, 16)); n != 0 || err == nil {
			t.Fatalf("an open reader released bytes after the deletion began: %d %v", n, err)
		}
	})
	t.Run("an advanced delete generation stops an open reader", func(t *testing.T) {
		r := newWLRig(t)
		r.lifecycleOf(true)
		a := r.upload("generation", false, time.Hour)
		reader, err := r.app.Artifacts.ReadAuthorized(r.ctx, r.scope(auth.ArtifactRead), a.ID, artifacts.Window{})
		if err != nil {
			t.Fatal(err)
		}
		defer reader.Close()
		if _, err = r.app.Control.AdvanceDeleteGeneration(r.ctx, r.org); err != nil {
			t.Fatal(err)
		}
		if n, err := reader.Read(make([]byte, 16)); n != 0 || err == nil {
			t.Fatalf("the reader outlived its org delete generation: %d %v", n, err)
		}
	})
	t.Run("a reference ledger that does not verify refuses the read", func(t *testing.T) {
		r := newWLRig(t)
		life := r.lifecycleOf(true)
		a := r.upload("ledger", false, time.Hour)
		r.reference(life, a, r.origin(artifacts.ReferenceError, 1), time.Now().Add(2*time.Hour))
		if status := r.routeRead(a.ID); status != 200 {
			t.Fatalf("read with a valid ledger: %d", status)
		}
		key, good := r.ledgerKey()
		r.setSetting(key, json.RawMessage(`{"Version":1}`))
		if status := r.routeRead(a.ID); status == 200 {
			t.Fatal("the map was served although its reference state does not verify")
		}
		r.setSetting(key, good)
		if status := r.routeRead(a.ID); status != 200 {
			t.Fatalf("read after the ledger was restored: %d", status)
		}
	})
	t.Run("the fence retires the intent and refuses reads while the bytes still exist", func(t *testing.T) {
		r := newWLRig(t)
		life := r.lifecycleOf(true)
		a := r.upload("fenced", false, wlBase)
		deadline := time.Now().Add(wlBase)
		wlSleepUntil(deadline)
		if _, err := life.GC(r.ctx, r.scope(auth.ArtifactWrite), a.ID); err != nil {
			t.Fatalf("GC of an expired, unreferenced map: %v", err)
		}
		if !r.present(a) {
			t.Fatal("setup: the fence erased the bytes")
		}
		if got := r.intentState(a); got != "retired" {
			t.Fatalf("the fence left the intent %q", got)
		}
		// Not gate-specific: an expired upload is refused by the scope check as well.
		if status := r.routeRead(a.ID); status != 404 {
			t.Fatalf("a fenced map is readable through the route: %d", status)
		}
	})
}

// (b) A blob referenced until T is not erased by a retention pass before T and is
// erased by the first pass after every reference ended and the upload's own
// retention is over. The pass is a real Retention.RunOnce of the real app, across a
// process restart (the reference ledger is durable).
func TestWiredLifecycleReferencedBlobIsRetainedUntilReleased(t *testing.T) {
	r := newWLRig(t)
	life := r.lifecycleOf(false)
	held := r.upload("held", false, wlBase)
	long := r.upload("default90", false, wlBase)
	refUntil := time.Now().Add(wlRef)
	r.reference(life, held, r.origin(artifacts.ReferenceError, 1), refUntil)
	r.reference(life, long, r.origin(artifacts.ReferenceBuild, 1), time.Time{}) // default: 90 days
	if eff, err := life.EffectiveRetention(r.ctx, r.scope(auth.ArtifactRead), long.ID); err != nil || time.Until(time.Unix(0, int64(eff))) < 89*24*time.Hour {
		t.Fatalf("a reference with no deadline retains the map for %v (%v), want 90 days", time.Until(time.Unix(0, int64(eff))), err)
	}
	wlSleepUntil(time.Now().Add(wlBase))
	if err := r.runOnce(); err != nil {
		t.Fatalf("pass before T: %v", err)
	}
	wlWindow(t, "the pass before T", refUntil)
	if !r.present(held) {
		t.Fatal("a blob referenced until T was erased before T")
	}
	if !r.present(long) {
		t.Fatal("a blob with a 90-day reference was erased")
	}
	if got := r.intentState(held); got != "published" {
		t.Fatalf("a retained map was fenced: intent is %q", got)
	}
	if got := r.app.Retention.Status().ExpiryErased; got != 0 {
		t.Fatalf("the pass before T erased %d roots", got)
	}

	r.restart() // the references survive, and the new process consults them
	wlSleepUntil(refUntil)
	if err := r.runOnce(); err != nil {
		t.Fatalf("pass after T: %v", err)
	}
	if r.present(held) {
		t.Fatal("the blob was not erased by the first pass after its last reference expired")
	}
	if !r.present(long) {
		t.Fatal("the pass after T erased a blob whose 90-day reference is live")
	}
	if got := r.app.Retention.Status().ExpiryErased; got != 1 {
		t.Fatalf("the pass after T erased %d roots, want exactly the unreferenced one", got)
	}
}

// A map whose only reference was released is erased by the first pass after its own
// retention; the released reference does not hold it.
func TestWiredLifecycleReleasedReferenceFreesTheMap(t *testing.T) {
	r := newWLRig(t)
	life := r.lifecycleOf(false)
	a := r.upload("released", false, wlBase)
	o := r.origin(artifacts.ReferenceError, 7)
	r.reference(life, a, o, time.Now().Add(time.Hour))
	if err := life.Unreference(r.ctx, r.scope(auth.ArtifactWrite), a.ID, o, 0); err != nil {
		t.Fatal(err)
	}
	wlSleepUntil(time.Now().Add(wlBase))
	if err := r.runOnce(); err != nil {
		t.Fatal(err)
	}
	if r.present(a) {
		t.Fatal("a map with no live reference and an expired upload survived the pass")
	}
	if status := r.routeRead(a.ID); status != 404 {
		t.Fatalf("an erased map answers %d through the route", status)
	}
}

// (c) Deletion takes precedence over a live reference: the entity deletion erases
// the root although a reference holds it for an hour, and nothing can reference,
// fence or read it afterwards.
func TestWiredLifecycleDeletionTakesPrecedenceOverALiveReference(t *testing.T) {
	r := newWLRig(t)
	life := r.lifecycleOf(false)
	a := r.upload("doomed", false, time.Hour)
	r.reference(life, a, r.origin(artifacts.ReferenceError, 3), time.Now().Add(time.Hour))
	r.deleteAndComplete(a)
	if r.present(a) {
		t.Fatal("a live reference kept a deleted artifact's bytes")
	}
	r.assertGone(life, a, "after deletion")
}

func (r *wlRig) deleteAndComplete(a artifacts.Artifact) {
	r.t.Helper()
	var rev model.Revision
	if err := r.app.Control.View(r.ctx, func(st model.ControlState) error { rev = st.Revision; return nil }); err != nil {
		r.t.Fatal(err)
	}
	receipt, err := r.app.Retention.Delete(r.ctx, r.adminScope(), retention.DeleteRequest{CommandID: model.NewID(), ExpectedRevision: rev, Mode: model.DeleteEntity, OrgID: r.org, ProjectIDs: []model.ID{r.project}, EntityIDs: []model.ID{a.ID}, Reason: "lifecycle wiring"})
	if err != nil {
		r.t.Fatal(err)
	}
	for range 8 {
		if err = r.runOnce(); err != nil {
			r.t.Fatal(err)
		}
		done, perr := r.app.Retention.PollDelete(r.ctx, r.adminScope(), receipt.OperationID)
		if perr != nil {
			r.t.Fatal(perr)
		}
		if done.Phase == model.DeletePhaseComplete {
			return
		}
	}
	r.t.Fatal("the deletion did not complete")
}

func (r *wlRig) assertGone(life *artifacts.Lifecycle, a artifacts.Artifact, label string) {
	r.t.Helper()
	read, write := r.scope(auth.ArtifactRead), r.scope(auth.ArtifactWrite)
	if _, err := r.app.Artifacts.Get(r.ctx, read, a.ID); wlCode(err) != model.NotFound {
		r.t.Fatalf("%s: Get %v", label, err)
	}
	if _, err := r.app.Artifacts.ReadAuthorized(r.ctx, read, a.ID, artifacts.Window{}); wlCode(err) != model.NotFound {
		r.t.Fatalf("%s: ReadAuthorized %v", label, err)
	}
	if status := r.routeRead(a.ID); status != 404 {
		r.t.Fatalf("%s: route read %d", label, status)
	}
	if err := life.Reference(r.ctx, write, a.ID, r.origin(artifacts.ReferenceProfile, 9), model.UnixNano(time.Now().Add(9*time.Hour).UnixNano())); wlCode(err) != model.NotFound {
		r.t.Fatalf("%s: a deleted artifact accepted a new reference: %v", label, err)
	}
	if _, err := life.GC(r.ctx, write, a.ID); wlCode(err) != model.NotFound {
		r.t.Fatalf("%s: GC %v", label, err)
	}
	if got, err := life.LatestReference(r.ctx, r.candidate(a)); err != nil || got != 0 {
		r.t.Fatalf("%s: deletion does not take precedence over the live reference: %d %v", label, got, err)
	}
}

// (d) A restore of an older control snapshot, which brings the artifact and its live
// references back, cannot revive an artifact whose deletion tombstone the current
// authority re-applies.
func TestWiredLifecycleRestoreCannotReviveADeletedArtifact(t *testing.T) {
	r := newWLRig(t)
	life := r.lifecycleOf(false)
	a := r.upload("revive", false, time.Hour)
	r.reference(life, a, r.origin(artifacts.ReferenceError, 4), time.Now().Add(5*time.Hour))
	r.deleteAndComplete(a)
	var tombstones []model.DeletePredicate
	if err := r.app.Control.View(r.ctx, func(st model.ControlState) error {
		for _, op := range st.Deletions {
			tombstones = append(tombstones, op.Predicate)
		}
		return nil
	}); err != nil || len(tombstones) != 1 {
		t.Fatalf("deletion record: %d %v", len(tombstones), err)
	}
	r.assertGone(life, a, "after deletion")
	// The older snapshot has no tombstone.
	if err := r.app.Control.Update(r.ctx, func(st *model.ControlState) error { st.Deletions = map[string]model.DeletionOperation{}; return nil }); err != nil {
		t.Fatal(err)
	}
	// The current-ledger authority re-applies it.
	if err := r.app.Control.ImportDeletions(r.ctx, tombstones, model.UnixNano(time.Now().UnixNano())); err != nil {
		t.Fatal(err)
	}
	r.assertGone(life, a, "after restore and ledger re-application")
}

// Fail closed: when the reference state of an expired map cannot be verified the
// retention pass erases nothing, reports a typed refusal, and erases the map only
// after the state is readable again.
func TestWiredLifecycleFailsClosedOnUnreadableReferenceState(t *testing.T) {
	r := newWLRig(t)
	life := r.lifecycleOf(false)
	a := r.upload("failclosed", false, wlBase)
	free := r.upload("unreferenced", false, wlBase) // no ledger of its own
	refUntil := time.Now().Add(wlBase + 2*time.Second)
	r.reference(life, a, r.origin(artifacts.ReferenceError, 5), refUntil)
	key, good := r.ledgerKey()
	r.setSetting(key, json.RawMessage(`{"Version":1}`))
	wlSleepUntil(refUntil)
	err := r.runOnce()
	if err == nil {
		t.Fatal("a pass that cannot verify the reference state reported success")
	}
	if wlCode(err) != model.Corrupt {
		t.Fatalf("the refusal is not the typed corrupt-state fault: %v", err)
	}
	if got := r.app.Retention.Status().LastError; got == "" {
		t.Fatal("the worker status does not report the refusal")
	}
	if !r.present(a) || !r.present(free) {
		t.Fatal("a pass that could not verify reference state erased a blob")
	}
	if got := r.app.Retention.Status().ExpiryErased; got != 0 {
		t.Fatalf("the failed pass reports %d erased roots", got)
	}
	r.setSetting(key, good)
	if err = r.runOnce(); err != nil {
		t.Fatalf("pass with readable state: %v", err)
	}
	if r.present(a) || r.present(free) {
		t.Fatal("the pass over readable state did not erase the expired, unreferenced maps")
	}
}

// Snapshot pins: while a durable journal pin (a backup in flight) is live in the
// control group or in a data group, an expired, unreferenced map is neither fenced
// nor erased; once the pin is released the next pass erases it.
func TestWiredLifecycleSnapshotPinsHoldMaps(t *testing.T) {
	for _, source := range []string{"control", "data"} {
		t.Run(source, func(t *testing.T) {
			r := newWLRig(t)
			r.lifecycleOf(false)
			a := r.upload("pinned", false, wlBase)
			var release func() error
			if source == "control" {
				pin, err := r.app.Control.ReplicaGroup().PinJournal(0)
				if err != nil {
					t.Fatal(err)
				}
				release = pin.Release
			} else {
				groups := r.app.Storage.ReplicaGroups()
				if len(groups) == 0 {
					t.Fatal("no data group")
				}
				pin, err := groups[0].PinJournal(0)
				if err != nil {
					t.Fatal(err)
				}
				release = pin.Release
			}
			wlSleepUntil(time.Now().Add(wlBase))
			if err := r.runOnce(); err != nil {
				t.Fatalf("pass under a live pin: %v", err)
			}
			if !r.present(a) {
				t.Fatal("a map was erased while a snapshot pin was live")
			}
			// (Reads of a map past its upload deadline are refused by the scope check whatever
			// retains the bytes, so "not fenced" is asserted on the durable state.)
			if got := r.intentState(a); got != "published" {
				t.Fatalf("a pin hold fenced the map: intent is %q", got)
			}
			if err := release(); err != nil {
				t.Fatal(err)
			}
			r.restart() // a fresh retention service: its expiry pass is due again
			if err := r.runOnce(); err != nil {
				t.Fatalf("pass after the pin was released: %v", err)
			}
			if r.present(a) {
				t.Fatal("the released pin still holds the map")
			}
		})
	}
}

func (r *wlRig) intentKey(a artifacts.Artifact) string {
	return r.org.String() + ":" + r.project.String() + ":" + a.ID.String()
}

func (r *wlRig) intentState(a artifacts.Artifact) string {
	r.t.Helper()
	var state string
	if err := r.app.Control.View(r.ctx, func(st model.ControlState) error {
		state = st.ArtifactIntents[r.intentKey(a)].State
		return nil
	}); err != nil {
		r.t.Fatal(err)
	}
	return state
}

func (r *wlRig) mustOpenAfterClose() {
	r.t.Helper()
	r.close()
	r.open()
}

// The process restarts after retention erased an expired map: the intent that names the
// erased root was retired in the transition that fenced it, before the bytes went.
func TestWiredLifecycleProcessRestartsAfterExpiryErasure(t *testing.T) {
	r := newWLRig(t)
	r.lifecycleOf(true)
	a := r.upload("restart", false, wlBase)
	wlSleepUntil(time.Now().Add(wlBase))
	if err := r.runOnce(); err != nil {
		t.Fatal(err)
	}
	if r.present(a) {
		t.Fatal("setup: the expired map was not erased")
	}
	if got := r.intentState(a); got != "retired" {
		t.Fatalf("the erased root's intent is %q, want retired", got)
	}
	r.mustOpenAfterClose()
	if r.present(a) || r.routeRead(a.ID) != 404 {
		t.Fatal("an erased and retired map came back after the restart")
	}
	if err := r.app.Control.ValidateArtifactReferences(r.ctx); err != nil {
		t.Fatal(err)
	}
	// The fence is permanent: a retired root accepts no reference and stays unreadable.
	err := r.lifecycleOf(true).Reference(r.ctx, r.scope(auth.ArtifactWrite), a.ID, r.origin(artifacts.ReferenceError, 11), model.UnixNano(time.Now().Add(time.Hour).UnixNano()))
	if wlCode(err) != model.Conflict {
		t.Fatalf("a retired root accepted a reference: %v", err)
	}
}

// Fail closed stays: a PUBLISHED intent whose blob is gone (the bytes vanished without the
// lifecycle's fence) still refuses to open.
func TestWiredLifecyclePublishedIntentWithoutBlobStillFailsOpen(t *testing.T) {
	r := newWLRig(t)
	r.lifecycleOf(true)
	a := r.upload("vanished", false, wlBase)
	// The engine's own unguarded expiry eraser: the root disappears, control is not told.
	if report, err := r.app.Storage.EraseExpired(r.ctx, model.UnixNano(time.Now().Add(time.Hour).UnixNano()), nil); err != nil || report.Blobs != 1 {
		t.Fatalf("setup: %+v %v", report, err)
	}
	if r.intentState(a) != "published" {
		t.Fatal("setup: the intent is not published")
	}
	r.close()
	if app, err := appcore.Open(r.dir); err == nil {
		app.Close()
		t.Fatal("Open accepted a published intent over a missing blob")
	} else if wlCode(err) != model.Corrupt {
		t.Fatalf("Open refused with %v, want corrupt", err)
	}
}

// A crash between the fence and the erase leaves a retired intent over PRESENT bytes: the
// process restarts, nothing reads the orphan, and the next pass erases it.
func TestWiredLifecycleCrashBetweenFenceAndEraseLeavesAnErasableOrphan(t *testing.T) {
	r := newWLRig(t)
	life := r.lifecycleOf(true)
	a := r.upload("orphan", false, wlBase)
	wlSleepUntil(time.Now().Add(wlBase))
	if _, err := life.GC(r.ctx, r.scope(auth.ArtifactWrite), a.ID); err != nil { // the fence; the crash is here
		t.Fatal(err)
	}
	if got := r.intentState(a); got != "retired" {
		t.Fatalf("the fence left the intent %q", got)
	}
	if !r.present(a) {
		t.Fatal("setup: the bytes are already gone")
	}
	r.mustOpenAfterClose()
	if !r.present(a) || r.routeRead(a.ID) != 404 {
		t.Fatal("after the crash the orphan is erased early or readable")
	}
	if err := r.runOnce(); err != nil {
		t.Fatal(err)
	}
	if r.present(a) {
		t.Fatal("the pass did not erase the orphan of the fenced root")
	}
	r.mustOpenAfterClose()
}

// A restore of an older control snapshot (intent published, ledger not retired) over data that
// no longer holds the bytes cannot revive the root: it is not readable, startup validation
// refuses it (corrupt) and only the fence retires it again. A rolled-back ledger beside a
// retired intent fails closed instead of answering.
func TestWiredLifecycleOldSnapshotCannotReviveARetiredRoot(t *testing.T) {
	r := newWLRig(t)
	life := r.lifecycleOf(true)
	a := r.upload("revive", false, wlBase)
	r.reference(life, a, r.origin(artifacts.ReferenceError, 21), time.Now().Add(wlBase+time.Second))
	oldKey, oldLedger := r.ledgerKey()
	var oldIntent model.ArtifactReferenceIntent
	if err := r.app.Control.View(r.ctx, func(st model.ControlState) error { oldIntent = st.ArtifactIntents[r.intentKey(a)]; return nil }); err != nil {
		t.Fatal(err)
	}
	wlSleepUntil(time.Now().Add(wlBase + time.Second))
	if err := r.runOnce(); err != nil {
		t.Fatal(err)
	}
	if r.present(a) || r.intentState(a) != "retired" {
		t.Fatal("setup: the root was not retired and erased")
	}
	_, newLedger := r.ledgerKey()

	// Only the ledger is rolled back: the index still pins the newer one.
	r.setSetting(oldKey, oldLedger)
	if got, err := life.LatestReference(r.ctx, r.candidate(a)); err == nil {
		t.Fatalf("a rolled-back ledger answered %d", got)
	}
	r.setSetting(oldKey, newLedger)

	// The whole old snapshot: the intent is published again over bytes that are gone.
	if err := r.app.Control.Update(r.ctx, func(st *model.ControlState) error { st.ArtifactIntents[r.intentKey(a)] = oldIntent; return nil }); err != nil {
		t.Fatal(err)
	}
	if status := r.routeRead(a.ID); status == 200 {
		t.Fatal("a root restored from an old snapshot was readable")
	}
	if err := r.app.Control.ValidateArtifactReferences(r.ctx); wlCode(err) != model.Corrupt {
		t.Fatalf("startup validation accepted a published intent over erased bytes: %v", err)
	}
	if got, err := life.LatestReference(r.ctx, r.candidate(a)); err != nil || got != 0 {
		t.Fatalf("the ledger is retired, so nothing retains the root: %d %v", got, err)
	}
	if _, err := life.GC(r.ctx, r.scope(auth.ArtifactWrite), a.ID); err != nil { // heals the intent
		t.Fatal(err)
	}
	if r.intentState(a) != "retired" {
		t.Fatal("the fence did not retire the restored intent again")
	}
	if err := r.app.Control.ValidateArtifactReferences(r.ctx); err != nil {
		t.Fatal(err)
	}
}
