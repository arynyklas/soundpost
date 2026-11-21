// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore_test

import (
	"io"
	"strings"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/artifacts"
	"github.com/arynyklas/soundpost/internal/artifacts/refledger"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/storage"
)

// 09.04-W3 on the real application: a real source credential ingests profile chunks whose
// frames name a map uploaded through the artifact service, the real profile producer (system
// principal) holds it, and the real lifecycle answers what retention and reads see.

type profileRig struct {
	*issueRig
	admitProfile func(model.Batch) (model.Receipt, error)
	resource     model.Resource
	source       model.ID
	producer     model.ID
}

func newProfileRig(t *testing.T) *profileRig {
	t.Helper()
	ir := newIssueRig(t)
	ir.enableArtifacts()
	r := &profileRig{issueRig: ir, source: model.NewID(), producer: model.NewID()}
	service, environment, build := model.NewID(), model.NewID(), ir.resource.Build
	r.resource = model.Resource{Service: service, Environment: environment, Build: build, Instance: "profile-instance", Labels: model.Labels{}}
	policy := model.SourcePolicy{Revision: 1, Enabled: true, Class: "structured", Kinds: []model.Kind{model.Profile},
		Resources:     model.ResourceRegistry{Services: []model.ID{service}, Environments: []model.ID{environment}, Builds: []model.ID{build}, Instances: []string{"profile-instance"}},
		RetentionDays: map[model.Kind]uint32{model.Profile: 7}, MaxBytes: 64 << 20, MaxSeries: 100}
	issued, err := ir.app.Auth.OnboardSource(ir.ctx, ir.actor, auth.SourceOnboarding{CommandID: model.NewID(), Org: ir.org, Project: ir.project, Source: r.source,
		Expires: model.UnixNano(time.Now().Add(time.Hour).UnixNano()), Policy: policy, Reason: "profile producer"})
	if err != nil {
		t.Fatal(err)
	}
	cred, err := ir.app.Auth.AuthenticateSource(ir.ctx, issued.Credential, "", false)
	if err != nil {
		t.Fatal(err)
	}
	r.admitProfile = func(b model.Batch) (model.Receipt, error) {
		g, err := ir.app.Ingest.ResolveSource(ir.ctx, cred, b)
		if err != nil {
			return model.Receipt{}, err
		}
		return ir.app.Ingest.Admit(ir.ctx, g, b)
	}
	return r
}

const profileChunkJSON = `{"profile_id":"%PROFILE%","process_id":"22222222222222222222222222222222","capability_id":"33333333333333333333333333333333","method":"runtime_cpu","units":"samples","start_ns":"1700000000000000000","end_ns":"1700000005000000000","clock":{"wall_ns":"1700000000000000000","mono_ns":"0","domain":{"host":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","boot":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","runtime":"cccccccccccccccccccccccccccccccc"},"uncertainty_ns":"18446744073709551615"},"frames":[{"module_id":"src/work.js","function":"busyWork","artifact_id":"%ARTIFACT%","offset":"0","reason":""},{"module_id":"external","function":"","artifact_id":"","offset":"0","reason":"not_captured"}],"stacks":[{"frames":[0,1]}],"samples":[{"at_ns":"0","stack":0,"count":"1","thread":"0"}],"intervals":[],"loss":"0","truncated":false}`

// ingestProfile admits one chunk of profile whose first frame names artifact (a name that is
// not an artifact ID stays a plain module name).
func (r *profileRig) ingestProfile(profile model.ID, artifact string) {
	r.t.Helper()
	var chunk model.ProfileChunk
	body := strings.NewReplacer("%PROFILE%", profile.String(), "%ARTIFACT%", artifact).Replace(profileChunkJSON)
	if err := model.StrictJSON([]byte(body), &chunk); err != nil {
		r.t.Fatal(err)
	}
	rec := model.Record{ID: model.NewID(), Kind: model.Profile, ObservedAt: 1700000005000000000, Resource: r.resource, Payload: model.Payload{Profile: &chunk}}
	b := model.Batch{Version: 1, Project: r.project, Source: r.source, Producer: r.producer, ID: model.NewID(), PolicyRevision: 1, Records: []model.Record{rec}}
	var err error
	if b.RouteSlot, err = model.OwnerSlot(r.org, r.project, r.source, r.producer, rec); err != nil {
		r.t.Fatal(err)
	}
	if _, err = r.admitProfile(b); err != nil {
		r.t.Fatal(err)
	}
}

// profileEntries lists the ledger entries of kind profile of one map.
func (r *profileRig) profileEntries(a artifacts.Artifact) []refledger.Entry {
	r.t.Helper()
	var out []refledger.Entry
	if err := r.app.Control.View(r.ctx, func(st model.ControlState) error {
		led, err := refledger.Load(st.Orgs[r.org.String()].Settings, r.project, a.ID)
		if err != nil || led == nil {
			return err
		}
		for _, e := range led.Entries {
			if e.Kind == refledger.KindProfile {
				out = append(out, e)
			}
		}
		return nil
	}); err != nil {
		r.t.Fatal(err)
	}
	return out
}

// A retained profile whose frame names a published map keeps it past the upload's own deadline,
// readable and kept by the retention pass; a name that is no map of the project is ignored; a
// repeated pass writes nothing; a chunk that arrives later extends the same entry.
func TestWiredLifecycleProfileProducerHoldsNamedMaps(t *testing.T) {
	r := newProfileRig(t)
	a := r.uploadMap("profiled", 3*time.Second)
	profile := model.NewID()
	r.ingestProfile(profile, a.ID.String())
	r.ingestProfile(model.NewID(), model.NewID().String()) // an ID no map has
	r.ingestProfile(model.NewID(), "src/work.js")          // a module name, not an artifact ID
	w := r.only(r.app.ProfileMapProducer())

	if eff, err := r.effective(a); err != nil || days(eff) > 1 {
		t.Fatalf("setup: before the producer the map is retained %.2f days (%v), want only the 3 s upload deadline", days(eff), err)
	}
	r.tick(w)
	eff, err := r.effective(a)
	if err != nil || days(eff) < 6 || days(eff) > 8 {
		t.Fatalf("a profile-named map is retained %.2f days (%v), want the 7-day profile retention", days(eff), err)
	}
	entries := r.profileEntries(a)
	if len(entries) != 1 || entries[0].Cursor.Group != profile || entries[0].Cursor.Index == 0 || entries[0].Released {
		t.Fatalf("ledger entries of kind profile: %+v, want one for the profile root", entries)
	}

	time.Sleep(time.Until(time.Unix(0, int64(a.Manifest.RetainUntil))) + 300*time.Millisecond)
	rc, err := r.app.Artifacts.Get(r.ctx, r.artifactScope(auth.ArtifactRead), a.ID)
	if err != nil {
		t.Fatalf("a map held by a retained profile is unreadable past its upload deadline: %v", err)
	}
	if body, _ := io.ReadAll(rc); len(body) == 0 {
		t.Fatal("empty read")
	}
	rc.Close()
	m := a.Map.Manifest
	if got, lerr := r.app.ArtifactLifecycle.LatestReference(r.ctx, storage.EraseCandidate{Org: m.Org, Project: m.Project, Blob: &m, Cursor: a.Map.Cursor}); lerr != nil || days(got) < 6 {
		t.Fatalf("retention would erase a map a retained profile names: latest reference %.2f days, %v", days(got), lerr)
	}
	if !r.present(a) {
		t.Fatal("the map of a retained profile is gone")
	}

	// A repeated pass writes nothing; a second chunk of the same profile adds no second entry.
	rev := r.currentRevision()
	r.tick(w)
	if got := r.currentRevision(); got != rev {
		t.Fatalf("a repeated pass committed control state: revision %d -> %d", rev, got)
	}
	r.ingestProfile(profile, a.ID.String())
	r.tick(w)
	if entries = r.profileEntries(a); len(entries) != 1 {
		t.Fatalf("a second chunk of the same profile made %d entries, want 1", len(entries))
	}
}

// A map the profile names after the map's retention has elapsed cannot be revived, and the
// producer neither fails nor holds anything for it.
func TestWiredLifecycleProfileProducerCannotReviveAnExpiredMap(t *testing.T) {
	r := newProfileRig(t)
	a := r.uploadMap("expired", 3*time.Second)
	time.Sleep(time.Until(time.Unix(0, int64(a.Manifest.RetainUntil))) + 300*time.Millisecond)
	r.ingestProfile(model.NewID(), a.ID.String())
	r.tick(r.only(r.app.ProfileMapProducer()))
	if entries := r.profileEntries(a); len(entries) != 0 {
		t.Fatalf("a late profile revived an elapsed map: %+v", entries)
	}
	if _, err := r.app.Artifacts.Get(r.ctx, r.artifactScope(auth.ArtifactRead), a.ID); err == nil {
		t.Fatal("an elapsed map became readable through a late profile")
	}
}
