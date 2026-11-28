// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"context"
	"errors"
	"slices"
	"sync/atomic"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/releases"
)

// relSensReader is a labelled test double of the release registry seam. The real
// registry keys every release by (org, project, id), so it can never hand the
// view a release from elsewhere; the view still re-checks that, and only a double
// that answers whatever it is told can prove it. It counts the reads made.
type relSensReader struct {
	reads atomic.Int32
	get   model.Release
	graph releases.Graph
}

func (f *relSensReader) Get(context.Context, auth.Scope, model.ID, model.ID) (model.Release, error) {
	f.reads.Add(1)
	return f.get, nil
}

func (f *relSensReader) Graph(context.Context, auth.Scope, model.ID) (releases.Graph, error) {
	f.reads.Add(1)
	return f.graph, nil
}

// relSensDirect is an evidence handler over a relSensReader that answers the
// release the caller names, together with the caller's real organization-admin
// scope for one project.
type relSensDirect struct {
	env                   *evEnv
	org, project, release model.ID
	scope                 auth.Scope
	reader                *relSensReader
	ev                    *httpapi.Evidence
}

func relSensNewDirect(t *testing.T) *relSensDirect {
	t.Helper()
	e := newEvEnv(t, nil, nil, false)
	p := model.NewID()
	org := e.org("release sens direct", p)
	admin := e.user(org, "rel-sens-direct@example.test")
	e.cmd(org, "org_admin", auth.AdminPayload{UserID: admin.ID, Enabled: true})
	scope, err := e.scope(admin, org, p, auth.OrgAdmin)
	if err != nil {
		t.Fatal(err)
	}
	d := &relSensDirect{env: e, org: org, project: p, release: model.NewID(), scope: scope}
	rel := model.Release{ID: d.release, Org: org, Project: p, BuildID: model.NewID(), DisplayLabel: "direct", BuildTime: 5}
	d.reader = &relSensReader{get: rel, graph: releases.Graph{rel.ID: rel}}
	d.ev = httpapi.NewEvidence(nil, d.reader, nil)
	return d
}

func (d *relSensDirect) body(compare ...model.ID) httpapi.ReleaseBody {
	return httpapi.ReleaseBody{Org: d.org, Project: d.project, Release: d.release, Compare: compare}
}

func relSensFault(err error) (model.Code, string) {
	var f *model.Fault
	if errors.As(err, &f) {
		return f.Code, f.SafeDetail
	}
	return "", ""
}

func relSensIDs(n int) []model.ID {
	out := make([]model.ID, n)
	for i := range out {
		out[i] = model.NewID()
	}
	return out
}

// A malformed release request is refused as invalid before the registry is read:
// every id must be present and the comparison list is bounded, holds no zero id
// and no repeat wherever the repeat sits.
func TestEvidenceSensReleaseRequestShapeIsValidatedBeforeTheRegistry(t *testing.T) {
	d := relSensNewDirect(t)
	x, y := model.NewID(), model.NewID()
	for name, body := range map[string]httpapi.ReleaseBody{
		"zero org":                {Org: model.ID{}, Project: d.project, Release: d.release},
		"zero project":            {Org: d.org, Project: model.ID{}, Release: d.release},
		"zero release":            {Org: d.org, Project: d.project, Release: model.ID{}},
		"one comparison too many": d.body(relSensIDs(httpapi.MaxEvidenceCompare + 1)...),
		"trailing zero":           d.body(x, model.ID{}),
		"leading zero":            d.body(model.ID{}, x),
		"adjacent repeat":         d.body(x, x),
		"non-adjacent repeat":     d.body(x, y, x),
	} {
		view, err := d.ev.Release(d.env.ctx, d.scope, body)
		if code, detail := relSensFault(err); code != model.Invalid || detail != "evidence_request_invalid" {
			t.Fatalf("%s: want invalid/evidence_request_invalid, got %v (view %+v)", name, err, view)
		}
	}
	if n := d.reader.reads.Load(); n != 0 {
		t.Fatalf("the registry was read %d times for malformed requests", n)
	}
	// The bound itself is allowed: exactly MaxEvidenceCompare distinct, non-zero comparisons.
	view, err := d.ev.Release(d.env.ctx, d.scope, d.body(relSensIDs(httpapi.MaxEvidenceCompare)...))
	if err != nil || len(view.Comparisons) != httpapi.MaxEvidenceCompare {
		t.Fatalf("a request at the bound: %v %+v", err, view)
	}
}

// The project of the request must be one the caller's scope covers. That is the
// first thing judged after the shape, before "not wired" and before any registry
// read: a project outside the scope is the one not-found.
func TestEvidenceSensReleaseProjectOutsideTheScopeIsNotFoundBeforeAnyRead(t *testing.T) {
	d := relSensNewDirect(t)
	other := model.NewID()
	body := httpapi.ReleaseBody{Org: d.org, Project: other, Release: d.release}

	view, err := d.ev.Release(d.env.ctx, d.scope, body)
	if code, _ := relSensFault(err); code != model.NotFound {
		t.Fatalf("project outside the scope: want not_found, got %v (view %+v)", err, view)
	}
	if n := d.reader.reads.Load(); n != 0 {
		t.Fatalf("the registry was read %d times for a project outside the scope", n)
	}
	// Not wired is judged after scope: the same project is still not-found, never "not available".
	unwired := httpapi.NewEvidence(nil, nil, nil)
	view, err = unwired.Release(d.env.ctx, d.scope, body)
	if code, _ := relSensFault(err); code != model.NotFound {
		t.Fatalf("unwired registry, project outside the scope: want not_found, got %v (view %+v)", err, view)
	}
}

// Whatever the registry answers, the view only describes a release of this very
// org, project and id: a release from anywhere else is the one not-found and its
// record is never shown.
func TestEvidenceSensReleaseRefusesWhatTheRegistryReturnsFromElsewhere(t *testing.T) {
	d := relSensNewDirect(t)
	own := d.reader.get
	view, err := d.ev.Release(d.env.ctx, d.scope, d.body())
	if err != nil || view.Release == nil || view.Release.ID != d.release || view.State != httpapi.StateReady {
		t.Fatalf("control: a matching release must be shown: %v %+v", err, view)
	}
	for name, wrong := range map[string]model.Release{
		"other org":     func() model.Release { r := own; r.Org = model.NewID(); return r }(),
		"other project": func() model.Release { r := own; r.Project = model.NewID(); return r }(),
		"other id":      func() model.Release { r := own; r.ID = model.NewID(); return r }(),
	} {
		d.reader.get = wrong
		view, err = d.ev.Release(d.env.ctx, d.scope, d.body())
		if code, _ := relSensFault(err); code != model.NotFound || view.Release != nil {
			t.Fatalf("%s: want not_found without a record, got %v %+v", name, err, view)
		}
	}
}

// A registry that is not wired is an explicit not_available naming that reason,
// not the "needs an organization admin" reason, which is a different fact.
func TestEvidenceSensReleaseUnwiredRegistryNamesItsOwnReason(t *testing.T) {
	d := relSensNewDirect(t)
	unwired := httpapi.NewEvidence(nil, nil, nil)
	view, err := unwired.Release(d.env.ctx, d.scope, d.body())
	if err != nil || view.State != httpapi.StateNotAvailable || view.Reason != httpapi.ReasonReleasesNotBuilt || view.Release != nil {
		t.Fatalf("unwired registry: %v %+v", err, view)
	}
	if view.Reason == httpapi.ReasonReleaseNeedsAdmin || len(view.Sections) != 1 || view.Sections[0].Name != "release" || view.Sections[0].State != httpapi.StateNotAvailable || view.Sections[0].Reason != httpapi.ReasonReleasesNotBuilt {
		t.Fatalf("unwired registry sections: %+v", view.Sections)
	}
	if view.Parents == nil || view.Children == nil || view.Comparisons == nil || view.Regressions == nil {
		t.Fatalf("an unavailable view still lists empty arrays, never null: %+v", view)
	}
}

// Children are the releases that declare the viewed release as a parent, no
// others (not grandchildren, not releases with some other parent, not the viewed
// release itself), listed in ascending id order whatever order the registry
// iterates in.
func TestEvidenceSensReleaseChildrenAreTheDirectOnesInAscendingIDOrder(t *testing.T) {
	e := newEvEnv(t, nil, nil, true)
	p := model.NewID()
	org := e.org("release sens children", p)
	admin := e.user(org, "rel-sens-children@example.test")
	e.cmd(org, "org_admin", auth.AdminPayload{UserID: admin.ID, Enabled: true})
	scope, err := e.scope(admin, org, p, auth.OrgAdmin)
	if err != nil {
		t.Fatal(err)
	}
	mk := func(id model.ID, parents ...model.ID) model.Release {
		return model.Release{ID: id, Org: org, Project: p, BuildID: model.NewID(), Parents: parents, BuildTime: 5, DisplayLabel: id.String()[:8]}
	}
	root, side, lone, grandchild, sideChild := model.NewID(), model.NewID(), model.NewID(), model.NewID(), model.NewID()
	kids := relSensIDs(12)
	e.register(scope, mk(root))
	e.register(scope, mk(side))
	e.register(scope, mk(lone))
	var rootKids, sideKids []model.ID
	for i, k := range kids {
		if i%3 == 0 {
			e.register(scope, mk(k, side, root)) // two parents: a child of both
			sideKids = append(sideKids, k)
		} else {
			e.register(scope, mk(k, root))
		}
		rootKids = append(rootKids, k)
	}
	e.register(scope, mk(grandchild, kids[1]))
	e.register(scope, mk(sideChild, side))
	sideKids = append(sideKids, sideChild)
	for _, ids := range [][]model.ID{rootKids, sideKids} {
		slices.SortFunc(ids, func(a, b model.ID) int { return slices.Compare(a[:], b[:]) })
	}
	children := func(of model.ID) []model.ID {
		t.Helper()
		status, raw := e.post(admin, "/api/v1/evidence/release", map[string]any{"org": org.String(), "project": p.String(), "release": of.String()}, nil)
		if status != 200 {
			t.Fatalf("release %s: %d %s", of, status, raw)
		}
		return decodeRelease(t, raw).Children
	}
	// Repeated: a registry that iterates in map order only looks sorted by luck once.
	for range 12 {
		if got := children(root); !slices.Equal(got, rootKids) {
			t.Fatalf("children of root: got %v want %v", got, rootKids)
		}
		if got := children(side); !slices.Equal(got, sideKids) {
			t.Fatalf("children of side: got %v want %v", got, sideKids)
		}
	}
	if got := children(kids[1]); !slices.Equal(got, []model.ID{grandchild}) {
		t.Fatalf("children of a release that has parents: got %v want [%v]", got, grandchild)
	}
	if got := children(lone); got == nil || len(got) != 0 {
		t.Fatalf("a release nothing declares as parent has no children: %#v", got)
	}
}

// The release record is the registry's own: build, label, entity revision, build
// time, every debug artifact binding with its exact SHA-256, and every label
// revision in stored order. Nothing is blanked, reordered or taken from another field.
func TestEvidenceSensReleaseRecordShowsEveryStoredFact(t *testing.T) {
	d := relSensNewDirect(t)
	artifacts := []model.ReleaseDebugArtifact{
		{ArtifactID: model.NewID(), DebugID: "debug-one", SHA256: model.HashCanonical([]byte("map one"))},
		{ArtifactID: model.NewID(), DebugID: "debug-two", SHA256: model.HashCanonical([]byte("map two"))},
	}
	rel := model.Release{ID: d.release, Org: d.org, Project: d.project, BuildID: model.NewID(), BuildTime: 1234, DisplayLabel: "v3-final", Revision: 2, DebugArtifacts: artifacts,
		History: []model.ReleaseLabelRevision{{ControlRevision: 7, Revision: 0, DisplayLabel: "v1"}, {ControlRevision: 8, Revision: 1, DisplayLabel: "v2"}, {ControlRevision: 9, Revision: 2, DisplayLabel: "v3-final"}}}
	d.reader.get, d.reader.graph = rel, releases.Graph{rel.ID: rel}
	view, err := d.ev.Release(d.env.ctx, d.scope, d.body())
	if err != nil || view.Release == nil {
		t.Fatalf("release: %v %+v", err, view)
	}
	got := *view.Release
	if got.ID != rel.ID || got.BuildID != rel.BuildID || got.Label != "v3-final" || got.Revision != 2 || got.BuildTime != 1234 {
		t.Fatalf("record identity: %+v", got)
	}
	if len(got.DebugArtifacts) != 2 {
		t.Fatalf("debug artifacts: %+v", got.DebugArtifacts)
	}
	for i, a := range artifacts {
		if g := got.DebugArtifacts[i]; g.ArtifactID != a.ArtifactID || g.DebugID != a.DebugID || g.SHA256 != a.SHA256 {
			t.Fatalf("debug artifact %d: got %+v want %+v", i, g, a)
		}
	}
	if len(got.LabelHistory) != 3 {
		t.Fatalf("label history: %+v", got.LabelHistory)
	}
	for i, h := range rel.History {
		if g := got.LabelHistory[i]; g.Revision != model.Uint64(h.Revision) || g.Label != h.DisplayLabel {
			t.Fatalf("label revision %d: got %+v want %+v", i, g, h)
		}
	}
}

// Ancestry that is fully known is a ready section in a ready view; any unknown
// edge makes the view and its ancestry section incomplete with the same reason,
// while the release section stays ready. The relation of the viewed release to a
// comparison is read from the viewed release's side.
func TestEvidenceSensReleaseSectionsStateEachPartAndComparisonsFaceTheViewedRelease(t *testing.T) {
	e := newEvEnv(t, nil, nil, true)
	p := model.NewID()
	org := e.org("release sens sections", p)
	admin := e.user(org, "rel-sens-sections@example.test")
	e.cmd(org, "org_admin", auth.AdminPayload{UserID: admin.ID, Enabled: true})
	scope, err := e.scope(admin, org, p, auth.OrgAdmin)
	if err != nil {
		t.Fatal(err)
	}
	mk := func(id model.ID, parents ...model.ID) model.Release {
		return model.Release{ID: id, Org: org, Project: p, BuildID: model.NewID(), Parents: parents, BuildTime: 5, DisplayLabel: "x"}
	}
	parent, child, orphan, never := model.NewID(), model.NewID(), model.NewID(), model.NewID()
	e.register(scope, mk(parent))
	e.register(scope, mk(child, parent))
	e.register(scope, mk(orphan, never))
	view := func(release model.ID, compare ...model.ID) httpapi.ReleaseView {
		t.Helper()
		body := map[string]any{"org": org.String(), "project": p.String(), "release": release.String()}
		if len(compare) > 0 {
			body["compare"] = compare
		}
		status, raw := e.post(admin, "/api/v1/evidence/release", body, nil)
		if status != 200 {
			t.Fatalf("release: %d %s", status, raw)
		}
		return decodeRelease(t, raw)
	}
	notWired := httpapi.ViewSection{Name: "regression", State: httpapi.StateNotAvailable, Reason: httpapi.ReasonRegressionDetail}

	v := view(child, parent, child)
	if v.State != httpapi.StateReady || v.Reason != "" || !slices.Equal(v.Sections, []httpapi.ViewSection{
		{Name: "release", State: httpapi.StateReady}, {Name: "ancestry", State: httpapi.StateReady}, notWired}) {
		t.Fatalf("known ancestry: %+v", v)
	}
	if got := v.Comparisons; len(got) != 2 || got[0] != (httpapi.ReleaseComparison{Release: parent, Order: "descendant"}) || got[1] != (httpapi.ReleaseComparison{Release: child, Order: "same"}) {
		t.Fatalf("comparisons of the child: %+v", got)
	}
	if got := view(parent, child).Comparisons; len(got) != 1 || got[0] != (httpapi.ReleaseComparison{Release: child, Order: "ancestor"}) {
		t.Fatalf("comparison of the parent with its child: %+v", got)
	}

	for name, v := range map[string]httpapi.ReleaseView{
		"unregistered parent":     view(orphan),
		"unregistered comparison": view(child, never),
	} {
		if v.State != httpapi.StateIncomplete || v.Reason != "ancestry_unknown" || !slices.Equal(v.Sections, []httpapi.ViewSection{
			{Name: "release", State: httpapi.StateReady}, {Name: "ancestry", State: httpapi.StateIncomplete, Reason: "ancestry_unknown"}, notWired}) {
			t.Fatalf("%s: %+v", name, v)
		}
	}
}
