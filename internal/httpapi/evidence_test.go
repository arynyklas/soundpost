// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/symbolicate"
)

// fakeResolver is a labelled test double for C07 symbolication: it needs a
// sandbox worker the unit environment does not have. It records what the handler
// hands it (scope, build, options) and answers a configured mapping. It cannot
// itself judge the private-source grant, so the real grant checks are exercised
// against the real artifact service in TestArtifactReadGrants.
type fakeResolver struct {
	calls   atomic.Int32
	scope   auth.Scope
	build   model.ID
	options symbolicate.Options
	frames  []model.Frame
	answer  func([]model.Frame, symbolicate.Options) ([]symbolicate.SymbolicatedFrame, error)
	during  func() // runs while the resolver "works", before it answers
}

func (f *fakeResolver) ResolveWithOptions(_ context.Context, scope auth.Scope, build model.ID, frames []model.Frame, options symbolicate.Options) ([]symbolicate.SymbolicatedFrame, error) {
	f.calls.Add(1)
	f.scope, f.build, f.options, f.frames = scope, build, options, frames
	if f.during != nil {
		f.during()
	}
	return f.answer(frames, options)
}

const secretSource = "PRIVATE-SOURCE-CANARY"

// mapFrames maps a frame at line 10 to src/app.ts:4:8 and refuses the others as
// an identity mismatch, carrying source text for the mapped one when it is asked.
func mapFrames(frames []model.Frame, o symbolicate.Options) ([]symbolicate.SymbolicatedFrame, error) {
	out := make([]symbolicate.SymbolicatedFrame, len(frames))
	for i, f := range frames {
		out[i] = symbolicate.SymbolicatedFrame{Original: f, Reason: symbolicate.IdentityMismatch}
		if f.Line == 10 {
			ctx := secretSource
			out[i].Reason = symbolicate.Resolved
			out[i].Resolved = &symbolicate.CodeIdentity{Source: "src/app.ts", Function: "handle", Line: 4, Column: 8}
			out[i].MapSHA256 = model.HashCanonical([]byte("map"))
			// The service only ever attaches context to an include_sources call; the
			// double attaches it unconditionally so the handler is shown not to leak.
			out[i].SourceContext = &ctx
		}
	}
	return out, nil
}

type fakeIssues struct {
	calls atomic.Int32
	issue model.GroupingIssue
}

func (f *fakeIssues) GroupingIssue(_ context.Context, scope auth.Scope, project, id model.ID) (model.GroupingIssue, error) {
	f.calls.Add(1)
	if scope.Permission() != auth.OrgAdmin || f.issue.Org != scope.OrgID() || f.issue.Project != project || f.issue.ID != id {
		return model.GroupingIssue{}, model.Fail(model.NotFound)
	}
	return f.issue, nil
}

type evEnv struct {
	*isoEnv
	resolver *fakeResolver
	issues   *fakeIssues
	srv      *httptest.Server
}

func newEvEnv(t *testing.T, resolver httpapi.FrameResolver, issues httpapi.IssueEvidenceReader, withReleases bool) *evEnv {
	t.Helper()
	e := &evEnv{isoEnv: newIsoEnv(t)}
	var rel httpapi.ReleaseReader
	if withReleases {
		rel = e.app.Releases
	}
	ev := httpapi.NewEvidence(resolver, rel, issues)
	e.srv = httptest.NewTLSServer(httpapi.NewServer("", e.app.Auth, nil, func(mux *http.ServeMux) {
		httpapi.RegisterEvidenceRoutes(mux, e.app.Auth, ev)
		e.app.RegisterArtifactRoutes(mux)
	}).Handler)
	t.Cleanup(e.srv.Close)
	return e
}

func (e *evEnv) post(who person, path string, body any, mutate func(*http.Request)) (int, []byte) {
	e.t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		e.t.Fatal(err)
	}
	req, _ := http.NewRequest("POST", e.srv.URL+path, bytes.NewReader(raw))
	if who.Session.Token != "" {
		req.Header.Set("Cookie", "__Host-soundpost="+who.Session.Token)
		req.Header.Set("X-CSRF-Token", who.Session.CSRF)
	}
	req.Header.Set("Origin", e.srv.URL)
	req.Header.Set("Content-Type", "application/json")
	if mutate != nil {
		mutate(req)
	}
	resp, err := e.srv.Client().Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

func frame(line uint32, function string) map[string]any {
	col := uint32(7)
	return map[string]any{"module_id": "app", "function": function, "artifact_id": model.NewID().String(), "line": line, "column": col, "in_app": true, "async": false}
}

func framesBody(org, project, build model.ID, includeSources bool, frames ...map[string]any) map[string]any {
	return map[string]any{"org": org.String(), "project": project.String(), "build": build.String(), "frames": frames, "include_sources": includeSources}
}

func decodeFrames(t *testing.T, raw []byte) httpapi.FramesView {
	t.Helper()
	var v httpapi.FramesView
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("not a frames view: %v\n%s", err, raw)
	}
	return v
}

func TestEvidenceFramesScopeFirstAndIndistinguishable(t *testing.T) {
	resolver := &fakeResolver{answer: mapFrames}
	e := newEvEnv(t, resolver, nil, true)
	pA, pB, pX := model.NewID(), model.NewID(), model.NewID()
	orgA, orgB := e.org("evidence A", pA, pB), e.org("evidence B", pX)
	artifactReader := e.user(orgA, "art-reader@example.test")
	e.grant(orgA, artifactReader, pA, true, auth.ArtifactRead)
	telemetry := e.user(orgA, "telemetry@example.test")
	e.grant(orgA, telemetry, pA, true, auth.Read)
	outsider := e.user(orgB, "outsider@example.test")
	e.grant(orgB, outsider, pX, true, auth.ArtifactRead, auth.Read)
	build := model.NewID()

	// An artifact reader gets the mapped frame; the handler hands the owned
	// service the exact build, the caller's own scope and no source request.
	status, raw := e.post(artifactReader, "/api/v1/evidence/frames", framesBody(orgA, pA, build, false, frame(10, "boom"), frame(11, "other")), nil)
	if status != 200 {
		t.Fatalf("artifact reader: %d %s", status, raw)
	}
	v := decodeFrames(t, raw)
	if len(v.Frames) != 2 || v.Frames[0].Resolved == nil || v.Frames[0].Resolved.Source != "src/app.ts" || v.Frames[0].Resolved.Line != 4 || v.Frames[0].Resolved.Column != 8 || v.Frames[0].Reason != "resolved" {
		t.Fatalf("mapped frame lost: %s", raw)
	}
	if v.Frames[1].Resolved != nil || v.Frames[1].Reason != "identity_mismatch" || v.Frames[1].Original.Function != "other" || v.State != httpapi.StateIncomplete {
		t.Fatalf("unmapped frame must keep the original sanitized frame with a reason: %s", raw)
	}
	if resolver.build != build || resolver.scope.OrgID() != orgA || resolver.scope.Permission() != auth.ArtifactRead || resolver.options.IncludeSources || len(resolver.frames) != 2 {
		t.Fatalf("resolver saw a different request than the scoped one: %+v", resolver)
	}
	if strings.Contains(string(raw), secretSource) {
		t.Fatalf("source text left the server without include_sources: %s", raw)
	}

	// A telemetry-only reader of the same project sees the sanitized frame
	// identities she supplied, nothing mapped, and the service is never reached.
	before := resolver.calls.Load()
	status, raw = e.post(telemetry, "/api/v1/evidence/frames", framesBody(orgA, pA, build, true, frame(10, "boom")), nil)
	v = decodeFrames(t, raw)
	if status != 200 || v.State != httpapi.StateIncomplete || v.Reason != httpapi.ReasonArtifactGrantAbsent || len(v.Frames) != 1 || v.Frames[0].Resolved != nil || v.Frames[0].Reason != httpapi.ReasonArtifactGrantAbsent || v.Frames[0].Original.Function != "boom" || v.Frames[0].Source.State != "withheld" || v.Frames[0].Source.Reason != httpapi.ReasonSourcesGrantRequired || v.Frames[0].Source.Context != nil {
		t.Fatalf("telemetry-only frames: %d %s", status, raw)
	}
	if resolver.calls.Load() != before || strings.Contains(string(raw), secretSource) || strings.Contains(string(raw), "src/app.ts") {
		t.Fatalf("telemetry-only reader reached the symbolicator or got mapped data: %s", raw)
	}

	// Wrong org member, an ungranted sibling project, a guessed project, a guessed
	// org, a member of no org: one indistinguishable answer, and the resolver is
	// never reached.
	before = resolver.calls.Load()
	var want string
	for name, c := range map[string]struct {
		who      person
		org, prj model.ID
	}{
		"other org's member naming org A": {outsider, orgA, pA},
		"ungranted sibling project":       {artifactReader, orgA, pB},
		"guessed project":                 {artifactReader, orgA, model.NewID()},
		"guessed org":                     {artifactReader, model.NewID(), pA},
		"other org's project in own org":  {outsider, orgB, pA},
		"org A's project under org B":     {artifactReader, orgB, pX},
	} {
		status, raw = e.post(c.who, "/api/v1/evidence/frames", framesBody(c.org, c.prj, build, true, frame(10, "boom")), nil)
		if status != 404 {
			t.Fatalf("%s: %d %s", name, status, raw)
		}
		got := denial(t, status, raw)
		if want == "" {
			want = got
		} else if got != want {
			t.Fatalf("%s distinguishable: %q vs %q", name, got, want)
		}
	}
	if resolver.calls.Load() != before {
		t.Fatal("the resolver was reached for an out-of-scope request")
	}

	// A body can neither name a scope nor widen it: unknown fields are refused,
	// and a project of another org does not become reachable by naming its org.
	for name, mutate := range map[string]func(map[string]any){
		"permission":  func(b map[string]any) { b["permission"] = "org.admin" },
		"projects":    func(b map[string]any) { b["projects"] = []string{pA.String(), pB.String()} },
		"elevation":   func(b map[string]any) { b["elevation"] = model.NewID().String() },
		"source":      func(b map[string]any) { b["source"] = model.NewID().String() },
		"scope":       func(b map[string]any) { b["scope"] = map[string]any{"org": orgB.String()} },
		"frame extra": func(b map[string]any) { b["frames"].([]map[string]any)[0]["source_context"] = "x" },
	} {
		body := framesBody(orgA, pA, build, false, frame(10, "boom"))
		mutate(body)
		if status, raw = e.post(artifactReader, "/api/v1/evidence/frames", body, nil); status != 400 {
			t.Fatalf("%s widened or was ignored: %d %s", name, status, raw)
		}
	}

	// Closed request validation.
	tooMany := make([]map[string]any, httpapi.MaxEvidenceFrames+1)
	for i := range tooMany {
		tooMany[i] = frame(10, "f")
	}
	for name, body := range map[string]map[string]any{
		"no frames":    framesBody(orgA, pA, build, false),
		"too many":     framesBody(orgA, pA, build, false, tooMany...),
		"zero build":   framesBody(orgA, pA, model.ID{}, false, frame(10, "f")),
		"control char": framesBody(orgA, pA, build, false, frame(10, "bad\x07name")),
		"long text":    framesBody(orgA, pA, build, false, frame(10, strings.Repeat("a", 600))),
	} {
		if status, raw = e.post(artifactReader, "/api/v1/evidence/frames", body, nil); status != 400 {
			t.Fatalf("%s accepted: %d %s", name, status, raw)
		}
	}

	// The limit is a limit, not an off-by-one: exactly MaxEvidenceFrames frames are served.
	if status, raw = e.post(artifactReader, "/api/v1/evidence/frames", framesBody(orgA, pA, build, false, tooMany[:httpapi.MaxEvidenceFrames]...), nil); status != 200 {
		t.Fatalf("exactly the maximum number of frames refused: %d %s", status, raw)
	}

	// A session POST without the CSRF binding is refused before any scope work.
	status, raw = e.post(artifactReader, "/api/v1/evidence/frames", framesBody(orgA, pA, build, false, frame(10, "boom")), func(r *http.Request) { r.Header.Del("X-CSRF-Token") })
	if status == 200 {
		t.Fatalf("session POST without CSRF accepted: %s", raw)
	}
}

func TestEvidenceFramesSourcesNeverLeakWithoutRequestOrGrant(t *testing.T) {
	resolver := &fakeResolver{answer: mapFrames}
	e := newEvEnv(t, resolver, nil, true)
	p := model.NewID()
	org := e.org("evidence sources", p)
	reader := e.user(org, "src-reader@example.test")
	e.grant(org, reader, p, true, auth.ArtifactRead)
	build := model.NewID()

	// include_sources=false: the response carries no source text even when the
	// service handed some back, and says the source is withheld because it was not
	// requested.
	_, raw := e.post(reader, "/api/v1/evidence/frames", framesBody(org, p, build, false, frame(10, "boom")), nil)
	v := decodeFrames(t, raw)
	if strings.Contains(string(raw), secretSource) || v.Frames[0].Source.State != "withheld" || v.Frames[0].Source.Reason != httpapi.ReasonSourcesNotRequested || resolver.options.IncludeSources {
		t.Fatalf("default must withhold source: %s", raw)
	}

	// include_sources=true and the service released context: it is shown as present.
	_, raw = e.post(reader, "/api/v1/evidence/frames", framesBody(org, p, build, true, frame(10, "boom"), frame(11, "other")), nil)
	v = decodeFrames(t, raw)
	if !resolver.options.IncludeSources || v.Frames[0].Source.State != "present" || v.Frames[0].Source.Context == nil || *v.Frames[0].Source.Context != secretSource {
		t.Fatalf("granted source must be present: %s", raw)
	}
	// An unmapped frame has no source context whatever the grant: absent for that
	// reason, not "withheld", which would wrongly suggest a missing grant.
	if v.Frames[1].Resolved != nil || v.Frames[1].Source.State != "absent" || v.Frames[1].Source.Reason != httpapi.ReasonFrameNotMapped || v.Frames[1].Source.Context != nil {
		t.Fatalf("unmapped frame source state: %s", raw)
	}

	// include_sources=true and the service denied it (the separate grant): no
	// context, an explicit withheld state, and the mapped identity still shown.
	resolver.answer = func(frames []model.Frame, o symbolicate.Options) ([]symbolicate.SymbolicatedFrame, error) {
		out, _ := mapFrames(frames, o)
		for i := range out {
			out[i].Reason = symbolicate.SourceDenied
			out[i].Resolved = nil
			ctx := secretSource
			out[i].SourceContext = &ctx
		}
		return out, nil
	}
	_, raw = e.post(reader, "/api/v1/evidence/frames", framesBody(org, p, build, true, frame(10, "boom")), nil)
	v = decodeFrames(t, raw)
	if strings.Contains(string(raw), secretSource) || v.Frames[0].Source.State != "withheld" || v.Frames[0].Source.Reason != httpapi.ReasonSourcesGrantRequired || v.Frames[0].Reason != "source_context_denied" || v.Frames[0].Original.Function != "boom" {
		t.Fatalf("denied source must be withheld with the original frame: %s", raw)
	}

	// Mapped but the map has no source content: absent, not withheld.
	resolver.answer = func(frames []model.Frame, o symbolicate.Options) ([]symbolicate.SymbolicatedFrame, error) {
		out, _ := mapFrames(frames, o)
		out[0].SourceContext = nil
		return out, nil
	}
	_, raw = e.post(reader, "/api/v1/evidence/frames", framesBody(org, p, build, true, frame(10, "boom")), nil)
	if v = decodeFrames(t, raw); v.Frames[0].Source.State != "absent" || v.Frames[0].Source.Reason != httpapi.ReasonNoSourceContent {
		t.Fatalf("no source content must be absent: %s", raw)
	}
}

func TestEvidenceFramesRevokedBeforeRelease(t *testing.T) {
	resolver := &fakeResolver{answer: mapFrames}
	e := newEvEnv(t, resolver, nil, true)
	p := model.NewID()
	org := e.org("evidence revoke", p)
	reader := e.user(org, "revoked@example.test")
	e.grant(org, reader, p, true, auth.ArtifactRead)
	resolver.during = func() { e.grant(org, reader, p, false, auth.ArtifactRead) }
	status, raw := e.post(reader, "/api/v1/evidence/frames", framesBody(org, p, model.NewID(), true, frame(10, "boom")), nil)
	if status == 200 || strings.Contains(string(raw), "src/app.ts") || strings.Contains(string(raw), secretSource) {
		t.Fatalf("a grant revoked while symbolicating still released the frames: %d %s", status, raw)
	}
}

func TestEvidenceFramesErrorMapping(t *testing.T) {
	resolver := &fakeResolver{}
	e := newEvEnv(t, resolver, nil, true)
	p := model.NewID()
	org := e.org("evidence errors", p)
	reader := e.user(org, "errors@example.test")
	e.grant(org, reader, p, true, auth.ArtifactRead)
	for code, want := range map[model.Code]int{model.NotFound: 404, model.Unavailable: 503, model.Timeout: 504, model.Corrupt: 503} {
		code := code
		resolver.answer = func([]model.Frame, symbolicate.Options) ([]symbolicate.SymbolicatedFrame, error) {
			return nil, model.Fail(code)
		}
		status, raw := e.post(reader, "/api/v1/evidence/frames", framesBody(org, p, model.NewID(), false, frame(10, "f")), nil)
		if status != want || status == 200 {
			t.Fatalf("%s: status %d want %d: %s", code, status, want, raw)
		}
	}
	// A resolver that returns a different number of frames is corruption, never a
	// shorter successful view.
	resolver.answer = func(frames []model.Frame, o symbolicate.Options) ([]symbolicate.SymbolicatedFrame, error) {
		out, _ := mapFrames(frames, o)
		return out[:0], nil
	}
	if status, raw := e.post(reader, "/api/v1/evidence/frames", framesBody(org, p, model.NewID(), false, frame(10, "f")), nil); status == 200 {
		t.Fatalf("short resolver answer accepted: %s", raw)
	}
}

func TestEvidenceUnwiredSeamsAreExplicitNotAvailable(t *testing.T) {
	e := newEvEnv(t, nil, nil, false)
	p := model.NewID()
	org := e.org("evidence unwired", p)
	admin := e.user(org, "unwired-admin@example.test")
	e.cmd(org, "org_admin", auth.AdminPayload{UserID: admin.ID, Enabled: true})
	e.grant(org, admin, p, true, auth.ArtifactRead, auth.Read)
	other := e.user(e.org("evidence unwired 2"), "unwired-other@example.test")

	status, raw := e.post(admin, "/api/v1/evidence/frames", framesBody(org, p, model.NewID(), false, frame(10, "f")), nil)
	v := decodeFrames(t, raw)
	if status != 200 || v.State != httpapi.StateNotAvailable || v.Reason != httpapi.ReasonSymbolicatorNotBuilt || v.Frames[0].Reason != httpapi.ReasonSymbolicatorNotBuilt || v.Frames[0].Original.Function != "f" {
		t.Fatalf("unwired symbolicator: %d %s", status, raw)
	}
	for path, body := range map[string]map[string]any{
		"/api/v1/evidence/release": {"org": org.String(), "project": p.String(), "release": model.NewID().String()},
		"/api/v1/evidence/issue":   {"org": org.String(), "project": p.String(), "issue": model.NewID().String()},
	} {
		status, raw = e.post(admin, path, body, nil)
		var generic struct {
			State  httpapi.ViewState `json:"state"`
			Reason string            `json:"reason"`
		}
		_ = json.Unmarshal(raw, &generic)
		if status != 200 || generic.State != httpapi.StateNotAvailable || generic.Reason == "" {
			t.Fatalf("%s must be an explicit not_available, got %d %s", path, status, raw)
		}
		// Scope is checked before "not built": a stranger gets the one not-found.
		body["org"] = org.String()
		if status, raw = e.post(other, path, body, nil); status != 404 {
			t.Fatalf("%s: stranger saw %d %s", path, status, raw)
		}
	}
}

func decodeRelease(t *testing.T, raw []byte) httpapi.ReleaseView {
	t.Helper()
	var v httpapi.ReleaseView
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("not a release view: %v\n%s", err, raw)
	}
	return v
}

func (e *evEnv) register(scope auth.Scope, r model.Release) {
	e.t.Helper()
	var revision model.Revision
	if err := e.app.Control.View(e.ctx, func(st model.ControlState) error { revision = st.Revision; return nil }); err != nil {
		e.t.Fatal(err)
	}
	if _, err := e.app.Releases.Register(e.ctx, scope, r, revision, model.NewID()); err != nil {
		e.t.Fatal(err)
	}
}

func TestEvidenceReleaseAncestryIsPartialOrderAndNeverGuessed(t *testing.T) {
	e := newEvEnv(t, nil, nil, true)
	p, p2 := model.NewID(), model.NewID()
	org, orgB := e.org("evidence release", p, p2), e.org("evidence release B", model.NewID())
	admin := e.user(org, "release-admin@example.test")
	e.cmd(org, "org_admin", auth.AdminPayload{UserID: admin.ID, Enabled: true})
	telemetry := e.user(org, "release-telemetry@example.test")
	e.grant(org, telemetry, p, true, auth.Read)
	stranger := e.user(orgB, "release-stranger@example.test")
	adminScope, err := e.app.Auth.Authorize(e.ctx, admin.Cred, org, []model.ID{p}, auth.OrgAdmin)
	if err != nil {
		t.Fatal(err)
	}
	a, b, c, d, sibling, missing := model.NewID(), model.NewID(), model.NewID(), model.NewID(), model.NewID(), model.NewID()
	art := model.NewID()
	mk := func(id model.ID, label string, parents ...model.ID) model.Release {
		return model.Release{ID: id, Org: org, Project: p, BuildID: model.NewID(), Parents: parents, BuildTime: 5, DisplayLabel: label,
			DebugArtifacts: []model.ReleaseDebugArtifact{{ArtifactID: art, DebugID: "debug-" + label, SHA256: model.HashCanonical([]byte(label))}}}
	}
	e.register(adminScope, mk(a, "v1"))
	e.register(adminScope, mk(b, "v2", a))
	e.register(adminScope, mk(sibling, "v2b", a))
	e.register(adminScope, mk(c, "orphan", missing)) // its parent was never registered
	e.register(adminScope, mk(d, "unrelated"))

	body := map[string]any{"org": org.String(), "project": p.String(), "release": b.String(), "compare": []string{a.String(), sibling.String(), d.String(), b.String()}}
	status, raw := e.post(admin, "/api/v1/evidence/release", body, nil)
	if status != 200 {
		t.Fatalf("release: %d %s", status, raw)
	}
	v := decodeRelease(t, raw)
	got := map[model.ID]string{}
	for _, c := range v.Comparisons {
		got[c.Release] = c.Order
	}
	if v.Release == nil || v.Release.ID != b || v.Release.Label != "v2" || len(v.Parents) != 1 || v.Parents[0].ID != a || !v.Parents[0].Known || got[a] != "descendant" || got[sibling] != "concurrent" || got[d] != "concurrent" || got[b] != "same" || v.State != httpapi.StateReady {
		t.Fatalf("ancestry: %s", raw)
	}
	if len(v.Release.DebugArtifacts) != 1 || v.Release.DebugArtifacts[0].ArtifactID != art || v.Release.DebugArtifacts[0].DebugID != "debug-v2" {
		t.Fatalf("debug artifacts lost: %s", raw)
	}
	var regression httpapi.ViewSection
	for _, s := range v.Sections {
		if s.Name == "regression" {
			regression = s
		}
	}
	if regression.State != httpapi.StateNotAvailable || regression.Reason == "" {
		t.Fatalf("a regression verdict must not be manufactured from ancestry: %s", raw)
	}

	// An unregistered parent and an unregistered comparison are unknown, never
	// ordered by id or time, and the view is incomplete.
	body = map[string]any{"org": org.String(), "project": p.String(), "release": c.String(), "compare": []string{a.String(), missing.String()}}
	_, raw = e.post(admin, "/api/v1/evidence/release", body, nil)
	v = decodeRelease(t, raw)
	if v.State != httpapi.StateIncomplete || v.Reason != "ancestry_unknown" || len(v.Parents) != 1 || v.Parents[0].ID != missing || v.Parents[0].Known {
		t.Fatalf("unknown parent must be incomplete: %s", raw)
	}
	for _, c := range v.Comparisons {
		if c.Order != "unknown" {
			t.Fatalf("unknown ancestry was ordered as %q: %s", c.Order, raw)
		}
	}
	// Each source of unknown ancestry alone makes the view incomplete: an unregistered
	// parent with no comparison, and an unregistered comparison with fully known parents.
	_, raw = e.post(admin, "/api/v1/evidence/release", map[string]any{"org": org.String(), "project": p.String(), "release": c.String()}, nil)
	if v = decodeRelease(t, raw); v.State != httpapi.StateIncomplete || v.Reason != "ancestry_unknown" {
		t.Fatalf("unregistered parent alone must be incomplete/ancestry_unknown: %s", raw)
	}
	_, raw = e.post(admin, "/api/v1/evidence/release", map[string]any{"org": org.String(), "project": p.String(), "release": b.String(), "compare": []string{missing.String()}}, nil)
	if v = decodeRelease(t, raw); v.State != httpapi.StateIncomplete || v.Reason != "ancestry_unknown" || len(v.Comparisons) != 1 || v.Comparisons[0].Order != "unknown" {
		t.Fatalf("unknown comparison alone must be incomplete/ancestry_unknown: %s", raw)
	}

	// A relabel is a new label revision of the same immutable release: the
	// debug artifact binding, and so the selected map, cannot change with it.
	_, raw = e.post(admin, "/api/v1/evidence/release", map[string]any{"org": org.String(), "project": p.String(), "release": b.String()}, nil)
	orig := decodeRelease(t, raw).Release
	if orig == nil {
		t.Fatalf("release b: %s", raw)
	}
	renamed := mk(b, "renamed-v2", a)
	renamed.BuildID = orig.BuildID
	renamed.Revision = model.Revision(orig.Revision)
	renamed.DebugArtifacts = []model.ReleaseDebugArtifact{{ArtifactID: art, DebugID: "debug-v2", SHA256: model.HashCanonical([]byte("v2"))}}
	e.register(adminScope, renamed)
	_, raw = e.post(admin, "/api/v1/evidence/release", map[string]any{"org": org.String(), "project": p.String(), "release": b.String()}, nil)
	v = decodeRelease(t, raw)
	if v.Release == nil || v.Release.Label != "renamed-v2" || len(v.Release.LabelHistory) != 2 || v.Release.LabelHistory[0].Label != "v2" || v.Release.DebugArtifacts[0].ArtifactID != art || v.Release.DebugArtifacts[0].DebugID != "debug-v2" {
		t.Fatalf("relabel changed the artifact binding or lost history: %s", raw)
	}

	// A project reader is told explicitly that release records need org admin.
	status, raw = e.post(telemetry, "/api/v1/evidence/release", map[string]any{"org": org.String(), "project": p.String(), "release": b.String()}, nil)
	v = decodeRelease(t, raw)
	if status != 200 || v.State != httpapi.StateNotAvailable || v.Reason != httpapi.ReasonReleaseNeedsAdmin || v.Release != nil {
		t.Fatalf("telemetry reader: %d %s", status, raw)
	}

	// Wrong org, wrong project, guessed release and a body that names another
	// org's release: one indistinguishable answer.
	var want string
	for name, c := range map[string]struct {
		who          person
		org, prj     model.ID
		releaseGiven model.ID
	}{
		"stranger":              {stranger, org, p, b},
		"guessed release":       {admin, org, p, model.NewID()},
		"release in other proj": {admin, org, p2, b},
		"guessed project":       {admin, org, model.NewID(), b},
		"guessed org":           {admin, model.NewID(), p, b},
	} {
		status, raw = e.post(c.who, "/api/v1/evidence/release", map[string]any{"org": c.org.String(), "project": c.prj.String(), "release": c.releaseGiven.String()}, nil)
		if status != 404 {
			t.Fatalf("%s: %d %s", name, status, raw)
		}
		if got := denial(t, status, raw); want == "" {
			want = got
		} else if got != want {
			t.Fatalf("%s distinguishable: %q vs %q", name, got, want)
		}
	}
	for name, body := range map[string]map[string]any{
		"unknown field": {"org": org.String(), "project": p.String(), "release": b.String(), "permission": "org.admin"},
		"duplicate":     {"org": org.String(), "project": p.String(), "release": b.String(), "compare": []string{a.String(), a.String()}},
		"zero release":  {"org": org.String(), "project": p.String(), "release": model.ID{}.String()},
	} {
		if status, raw = e.post(admin, "/api/v1/evidence/release", body, nil); status != 400 {
			t.Fatalf("%s: %d %s", name, status, raw)
		}
	}
}

func TestEvidenceIssueShowsGroupingLateHistoryAndUnknownAncestry(t *testing.T) {
	issues := &fakeIssues{}
	e := newEvEnv(t, nil, issues, true)
	p := model.NewID()
	org := e.org("evidence issue", p)
	admin := e.user(org, "issue-admin@example.test")
	e.cmd(org, "org_admin", auth.AdminPayload{UserID: admin.ID, Enabled: true})
	telemetry := e.user(org, "issue-telemetry@example.test")
	e.grant(org, telemetry, p, true, auth.Read)
	stranger := e.user(e.org("evidence issue B"), "issue-stranger@example.test")
	rel := model.NewID()
	fp := model.HashCanonical([]byte("fingerprint"))
	resolved := model.UnixNano(100)
	ev := func(version uint16, ancestry string, release *model.ID) model.GroupingEvidence {
		return model.GroupingEvidence{OccurrenceID: model.NewID(), RecordID: model.NewID(), GroupingVersion: version, Fingerprint: fp, EventTime: 90, ArrivalTime: 200, ReleaseID: release, Ancestry: ancestry, Freshness: "fresh"}
	}
	issues.issue = model.GroupingIssue{ID: model.NewID(), Org: org, Project: p, GroupingVersion: 3, Fingerprint: fp, Workflow: "resolved", Revision: 4, ResolutionTime: &resolved,
		Occurrences: []model.GroupingEvidence{ev(3, "known", &rel), ev(3, "known", nil), ev(3, "garbage", &rel)}, LateHistory: []model.GroupingEvidence{ev(2, "unknown", nil)}}
	body := map[string]any{"org": org.String(), "project": p.String(), "issue": issues.issue.ID.String()}

	status, raw := e.post(admin, "/api/v1/evidence/issue", body, nil)
	if status != 200 {
		t.Fatalf("issue: %d %s", status, raw)
	}
	var v httpapi.IssueView
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if v.Grouping == nil || v.Grouping.Version != 3 || v.Grouping.Fingerprint != fp || v.Grouping.Workflow != "resolved" || v.Grouping.Revision != 4 || v.Grouping.ResolutionTime == nil {
		t.Fatalf("grouping identity: %s", raw)
	}
	if len(v.Occurrences) != 3 || v.Occurrences[0].Ancestry != "known" || v.Occurrences[1].Ancestry != "unknown" || v.Occurrences[2].Ancestry != "unknown" || v.Occurrences[0].Late {
		t.Fatalf("ancestry must be known only when stated with a release: %s", raw)
	}
	if len(v.LateHistory) != 1 || !v.LateHistory[0].Late || v.LateHistory[0].GroupingVersion != 2 {
		t.Fatalf("late history lost or unflagged: %s", raw)
	}
	states := map[string]httpapi.ViewState{}
	for _, s := range v.Sections {
		states[s.Name] = s.State
	}
	if v.State == httpapi.StateReady || states["occurrence_detail"] != httpapi.StateNotAvailable || states["regression"] != httpapi.StateNotAvailable {
		t.Fatalf("unbuilt parts must be explicit not_available: %s", raw)
	}

	// A project reader is told issue evidence needs org admin; the reader is not
	// asked at all.
	before := issues.calls.Load()
	status, raw = e.post(telemetry, "/api/v1/evidence/issue", body, nil)
	if status != 200 || !strings.Contains(string(raw), httpapi.ReasonIssueNeedsAdmin) || strings.Contains(string(raw), fp.String()) || issues.calls.Load() != before {
		t.Fatalf("telemetry reader: %d %s", status, raw)
	}
	// Scope first: the stranger and a wrong project/issue are one answer and the
	// reader is only ever asked after scope.
	var want string
	for name, c := range map[string]struct {
		who      person
		org, prj model.ID
		issue    model.ID
	}{
		"stranger":        {stranger, org, p, issues.issue.ID},
		"guessed issue":   {admin, org, p, model.NewID()},
		"guessed project": {admin, org, model.NewID(), issues.issue.ID},
	} {
		before = issues.calls.Load()
		status, raw = e.post(c.who, "/api/v1/evidence/issue", map[string]any{"org": c.org.String(), "project": c.prj.String(), "issue": c.issue.String()}, nil)
		if status != 404 || strings.Contains(string(raw), fp.String()) {
			t.Fatalf("%s: %d %s", name, status, raw)
		}
		if got := denial(t, status, raw); want == "" {
			want = got
		} else if got != want {
			t.Fatalf("%s distinguishable: %q vs %q", name, got, want)
		}
		if name == "stranger" && issues.calls.Load() != before {
			t.Fatal("reader consulted for an out-of-scope caller")
		}
	}
}

// TestArtifactReadGrants exercises the committed protected artifact route with
// the REAL artifact service: the map is readable with artifacts.read, private
// source bytes only through the separate sources operation for a named source
// reader holding raw.read, and every other caller (map-only, telemetry-only,
// another org holding the same IDs, a guess, a revoked reader) gets one
// indistinguishable not-found.
func TestArtifactReadGrants(t *testing.T) {
	e := newEvEnv(t, nil, nil, true)
	p := model.NewID()
	pB := model.NewID()
	org, orgB := e.org("artifact grants", p), e.org("artifact grants B", pB)
	owner := e.user(org, "src-owner@example.test")
	e.grant(org, owner, p, true, auth.ArtifactRead, auth.ArtifactWrite, auth.RawRead)
	mapOnly := e.user(org, "map-only@example.test")
	e.grant(org, mapOnly, p, true, auth.ArtifactRead)
	telemetry := e.user(org, "tele-only@example.test")
	e.grant(org, telemetry, p, true, auth.Read)
	rawNotNamed := e.user(org, "raw-not-named@example.test")
	e.grant(org, rawNotNamed, p, true, auth.ArtifactRead, auth.RawRead)
	stranger := e.user(orgB, "artifact-stranger@example.test")
	e.grant(orgB, stranger, pB, true, auth.ArtifactRead, auth.RawRead)

	ids := sharedIDs{model.NewID(), model.NewID(), model.NewID()}
	source := model.NewID()
	policy := model.SourcePolicy{Revision: 1, Enabled: true, Class: "structured", Kinds: []model.Kind{model.Metric}, RetentionDays: map[model.Kind]uint32{model.Metric: 7}, MaxBytes: 1 << 20, MaxSeries: 100}
	e.onboard(org, p, source, ids, policy, auth.SourcePolicyConfig{ProjectID: p, Enabled: true, Readers: []model.ID{owner.ID}})

	raw := []byte(`{"version":3,"sources":["src/app.ts"],"names":[],"mappings":"AAAA","sourcesContent":["` + secretSource + `"]}`)
	manifest := model.ArtifactManifest{Version: 1, Org: org, Project: p, Source: source, Build: ids.Build, DebugID: "debug-grants", GeneratedSHA256: model.HashCanonical([]byte("generated")), MapSHA256: model.HashCanonical(raw), Path: "dist/app.js", SourceContent: true, Size: model.Uint64(len(raw)), RetainUntil: model.UnixNano(4102444800_000000000)}
	writeScope, err := e.app.Auth.Authorize(e.ctx, owner.Cred, org, []model.ID{p}, auth.ArtifactWrite)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := e.app.Artifacts.Put(e.ctx, writeScope, manifest, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	read := func(who person, org, project, id model.ID, op string) (int, []byte) {
		return e.post(who, "/api/v1/artifacts", map[string]any{"operation": op, "org": org.String(), "project": project.String(), "id": id.String()}, nil)
	}

	status, body := read(owner, org, p, artifact.ID, "sources")
	if status != 200 || !strings.Contains(string(body), secretSource) {
		t.Fatalf("the named source reader must get source bytes: %d %s", status, body)
	}
	for _, who := range []person{owner, mapOnly} {
		status, body = read(who, org, p, artifact.ID, "read")
		if status != 200 || strings.Contains(string(body), secretSource) || strings.Contains(string(body), "sourcesContent") || model.HashCanonical(body) != artifact.Map.Hash {
			t.Fatalf("the map must carry no source content: %d %s", status, body)
		}
	}
	var want string
	check := func(name string, who person, org, project, id model.ID, op string) {
		t.Helper()
		status, body := read(who, org, project, id, op)
		if status != 404 || strings.Contains(string(body), secretSource) {
			t.Fatalf("%s: %d %s", name, status, body)
		}
		if got := denial(t, status, body); want == "" {
			want = got
		} else if got != want {
			t.Fatalf("%s distinguishable: %q vs %q", name, got, want)
		}
	}
	check("map-only reader asks for sources", mapOnly, org, p, artifact.ID, "sources")
	check("raw.read but not a named source reader", rawNotNamed, org, p, artifact.ID, "sources")
	check("telemetry-only reads the map", telemetry, org, p, artifact.ID, "read")
	check("telemetry-only reads sources", telemetry, org, p, artifact.ID, "sources")
	check("other org, same artifact id and project", stranger, orgB, p, artifact.ID, "sources")
	check("other org naming this org", stranger, org, p, artifact.ID, "read")
	check("other org's own project, same id", stranger, orgB, pB, artifact.ID, "read")
	check("guessed id", owner, org, p, model.NewID(), "sources")

	// A body cannot ask for more than the closed operation set.
	if status, body = e.post(mapOnly, "/api/v1/artifacts", map[string]any{"operation": "sources", "org": org.String(), "project": p.String(), "id": artifact.ID.String(), "include_sources": true}, nil); status != 400 {
		t.Fatalf("extra body field accepted: %d %s", status, body)
	}

	// Revocation before the response ends the source read.
	e.grant(org, owner, p, false, auth.ArtifactRead, auth.ArtifactWrite, auth.RawRead)
	check("revoked source reader", owner, org, p, artifact.ID, "sources")
}
