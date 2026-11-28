// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/artifacts"
	"github.com/arynyklas/soundpost/internal/artifacts/refledger"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/storage"
)

// 10.09-W1 end to end on the real application: a real source credential ingests error
// occurrences whose frames name a map uploaded through the artifact service, the real issue
// producer (system principal) groups them, and the real retention service decides what is
// erased. Nothing is faked but the worker clock.

func (r *issueRig) enableArtifacts() {
	r.t.Helper()
	if err := r.app.Control.Update(r.ctx, func(st *model.ControlState) error {
		o := st.Orgs[r.org.String()]
		key := r.user.String() + ":" + r.project.String()
		o.Grants[key] = append(o.Grants[key], "artifacts.write", "artifacts.read")
		cfg, err := json.Marshal(auth.SourcePolicyConfig{ProjectID: r.project, Enabled: true})
		if err != nil {
			return err
		}
		o.Settings["source_policy:"+r.source.String()] = cfg
		st.Orgs[r.org.String()] = o
		return nil
	}); err != nil {
		r.t.Fatal(err)
	}
}

func (r *issueRig) artifactScope(p auth.Permission) auth.Scope {
	r.t.Helper()
	s, err := r.app.Auth.Authorize(r.ctx, r.actor, r.org, []model.ID{r.project}, p)
	if err != nil {
		r.t.Fatal(err)
	}
	return s
}

func (r *issueRig) uploadMap(debug string, retain time.Duration) artifacts.Artifact {
	r.t.Helper()
	raw := []byte(`{"version":3,"sources":["a.ts"],"names":[],"mappings":"AAAA"}`)
	m := artifacts.Manifest{Version: 1, Org: r.org, Project: r.project, Source: r.source, Build: r.resource.Build, DebugID: debug,
		GeneratedSHA256: model.HashCanonical([]byte("generated")), MapSHA256: model.HashCanonical(raw), Path: "dist/" + debug + ".js",
		Size: model.Uint64(len(raw)), RetainUntil: model.UnixNano(time.Now().Add(retain).UnixNano())}
	a, err := r.app.Artifacts.Put(r.ctx, r.artifactScope(auth.ArtifactWrite), m, bytes.NewReader(raw))
	if err != nil {
		r.t.Fatal(err)
	}
	return a
}

// ingestNaming admits one error occurrence of the class whose frame names the artifact.
func (r *issueRig) ingestNaming(class string, observed model.UnixNano, artifact model.ID) model.ID {
	r.t.Helper()
	occurrence := model.NewID()
	rec := r.record(class, observed, true, false, occurrence)
	col := uint32(1)
	rec.Payload.Error.Frames = []model.Frame{{Module: "app", Function: "run", Artifact: artifact.String(), Line: 1, Column: &col, InApp: true}}
	r.ingestBatch(rec)
	return occurrence
}

func (r *issueRig) issueOf(occurrence model.ID) model.GroupingIssue {
	r.t.Helper()
	for _, i := range r.snapshot().Issues {
		for _, o := range i.Occurrences {
			if o.OccurrenceID == occurrence {
				return i
			}
		}
	}
	r.t.Fatalf("no issue holds occurrence %s", occurrence)
	return model.GroupingIssue{}
}

func (r *issueRig) effective(a artifacts.Artifact) (model.UnixNano, error) {
	return r.app.ArtifactLifecycle.EffectiveRetention(r.ctx, r.artifactScope(auth.ArtifactRead), a.ID)
}

func (r *issueRig) resolve(issue model.GroupingIssue) {
	r.t.Helper()
	if err := r.app.BindIssueActions(); err != nil {
		r.t.Fatal(err)
	}
	res, err := r.app.Actions.Act(r.ctx, r.admin(), issueRequest(r.project, issue.ID, httpapi.ActionResolve, uint64(issue.Revision), httpapi.ActionPayload{Reason: "fixed"}))
	if err != nil || res.State != httpapi.ActionCommitted {
		r.t.Fatalf("resolve: %+v %v", res, err)
	}
}

func (r *issueRig) present(a artifacts.Artifact) bool {
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

func days(until model.UnixNano) float64 { return time.Until(time.Unix(0, int64(until))).Hours() / 24 }

// An occurrence naming a source map keeps it from retention expiry while its issue is open, past
// the upload's own deadline; resolving the issue releases it, and the next retention pass erases
// it. A name that is no published map of the project is ignored.
func TestWiredLifecycleIssueProducerHoldsNamedMapsUntilResolved(t *testing.T) {
	r := newIssueRig(t)
	r.enableArtifacts()
	a := r.uploadMap("produced", 3*time.Second)
	named := r.ingestNaming("TypeError", 5, a.ID)
	r.ingestNaming("RangeError", 6, model.NewID()) // a name no map has
	w := r.workers()
	r.tick(w)

	eff, err := r.effective(a)
	if err != nil || days(eff) < 89 {
		t.Fatalf("the map named by an occurrence is retained for %.2f days (%v), want the 90-day error retention", days(eff), err)
	}
	time.Sleep(time.Until(time.Unix(0, int64(a.Manifest.RetainUntil))) + 300*time.Millisecond)

	// Past the upload's deadline: still readable, and the retention pass keeps it.
	rc, err := r.app.Artifacts.Get(r.ctx, r.artifactScope(auth.ArtifactRead), a.ID)
	if err != nil {
		t.Fatalf("a held map is unreadable past its upload deadline: %v", err)
	}
	if body, _ := io.ReadAll(rc); len(body) == 0 {
		t.Fatal("empty read")
	}
	rc.Close()
	// What the retention pass asks about the expired root: the hold keeps it (the pass runs at most
	// hourly, so the one real pass is the one after the release below).
	m := a.Map.Manifest
	if got, lerr := r.app.ArtifactLifecycle.LatestReference(r.ctx, storage.EraseCandidate{Org: m.Org, Project: m.Project, Blob: &m, Cursor: a.Map.Cursor}); lerr != nil || days(got) < 89 {
		t.Fatalf("retention would erase a map an open issue holds: latest reference %.2f days, %v", days(got), lerr)
	}
	if !r.present(a) {
		t.Fatal("the map of an open issue is gone")
	}

	// Resolving the issue releases the map: it is unreadable at once and the next pass erases it.
	r.resolve(r.issueOf(named))
	r.tick(w)
	_, err = r.app.Artifacts.Get(r.ctx, r.artifactScope(auth.ArtifactRead), a.ID)
	var fault *model.Fault
	if !errors.As(err, &fault) || fault.Code != model.NotFound || fault.SafeDetail != auth.ArtifactRetentionElapsed {
		t.Fatalf("a released map past its retention: %v", err)
	}
	if err = r.app.Retention.RunOnce(r.ctx); err != nil {
		t.Fatal(err)
	}
	if r.present(a) {
		t.Fatal("the map of a resolved issue was not erased by the next retention pass")
	}
}

// A resolved issue lets go of its maps, and a regression that reopens it holds them again while
// they are still retained.
func TestWiredLifecycleIssueProducerReleasesOnResolveAndHoldsAgainOnRegression(t *testing.T) {
	r := newIssueRig(t)
	r.enableArtifacts()
	a := r.uploadMap("regress", time.Hour)
	first := r.ingestNaming("TypeError", 5, a.ID)
	w := r.workers()
	r.tick(w)
	if eff, err := r.effective(a); err != nil || days(eff) < 89 {
		t.Fatalf("held: %.2f days %v", days(eff), err)
	}
	r.resolve(r.issueOf(first))
	r.tick(w)
	if eff, err := r.effective(a); err != nil || days(eff) > 0.1 {
		t.Fatalf("after resolve the map is retained for %.2f days (%v), want only the upload's own hour", days(eff), err)
	}
	time.Sleep(20 * time.Millisecond)
	again := r.ingestNaming("TypeError", model.UnixNano(time.Now().UnixNano()), a.ID)
	r.tick(w)
	if got := r.issueOf(again); got.Workflow != "open" {
		t.Fatalf("the regression did not reopen the issue: %s", got.Workflow)
	}
	if eff, err := r.effective(a); err != nil || days(eff) < 89 {
		t.Fatalf("after the regression the map is retained for %.2f days (%v), want it held again", days(eff), err)
	}
}

// The hold comes before the occurrence is applied: a hold that cannot be taken (a ledger that does
// not verify) stops the pass with the checkpoint where it was, and the next pass over a repaired
// ledger applies the occurrence.
func TestWiredLifecycleIssueProducerFailsClosedWhenAHoldCannotBeTaken(t *testing.T) {
	r := newIssueRig(t)
	r.enableArtifacts()
	a := r.uploadMap("closed", time.Hour)
	r.ingestNaming("TypeError", 5, a.ID)
	w := r.workers()
	r.tick(w)
	key := refledger.LedgerKey(r.project, a.ID)
	var good json.RawMessage
	if err := r.app.Control.View(r.ctx, func(st model.ControlState) error {
		good = append(json.RawMessage(nil), st.Orgs[r.org.String()].Settings[key]...)
		return nil
	}); err != nil || len(good) == 0 {
		t.Fatalf("no ledger after the first pass: %v", err)
	}
	set := func(raw json.RawMessage) {
		t.Helper()
		if err := r.app.Control.Update(r.ctx, func(st *model.ControlState) error {
			o := st.Orgs[r.org.String()]
			o.Settings[key] = raw
			st.Orgs[r.org.String()] = o
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	set(json.RawMessage(`{"Version":1}`))
	before := sumCheckpoints(r.snapshot())
	second := r.ingestNaming("RangeError", 6, a.ID)
	if rep := w.Tick(r.ctx); len(rep.Errors) == 0 {
		t.Fatalf("a pass that could not hold the map reported no error: %+v", rep)
	}
	if after := sumCheckpoints(r.snapshot()); after != before || len(r.snapshot().Issues) != 1 {
		t.Fatalf("the occurrence was applied without its hold: checkpoint %d -> %d, issues %d", before, after, len(r.snapshot().Issues))
	}
	set(good)
	r.tick(w)
	if len(r.snapshot().Issues) != 2 || r.issueOf(second).Workflow != "open" {
		t.Fatalf("the repaired pass did not apply the occurrence: %+v", r.snapshot().Issues)
	}
}
