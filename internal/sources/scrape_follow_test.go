// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package sources

import (
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
)

// [10.16-W3] follow_policy_revision derives the revision from the live source
// policy: exactly one of the pinned and the followed form is a valid target.
func TestScrapeConfigFollowPolicyRevisionIsExclusiveWithAPinnedOne(t *testing.T) {
	specs, err := loadSpecs(t, validConfigDoc(func(_, target cfgDoc) {
		src := target["source"].(cfgDoc)
		delete(src, "policy_revision")
		src["follow_policy_revision"] = true
	}))
	if err != nil || len(specs) != 1 || !specs[0].FollowPolicy || specs[0].PolicyRevision != 0 {
		t.Fatalf("follow form: %v %+v", err, specs)
	}
	for name, mutate := range map[string]func(cfgDoc){
		"pinned and followed": func(src cfgDoc) { src["follow_policy_revision"] = true },
		"neither":             func(src cfgDoc) { delete(src, "policy_revision") },
	} {
		if _, err := loadSpecs(t, validConfigDoc(func(_, target cfgDoc) { mutate(target["source"].(cfgDoc)) })); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// A followed target needs the live policy reader; a pinned one does not.
func TestStartScrapeHostRefusesAFollowedTargetWithoutAPolicyReader(t *testing.T) {
	r := newHostRig(t)
	r.writeConfig(func(target map[string]any) {
		src := target["source"].(map[string]any)
		delete(src, "policy_revision")
		src["follow_policy_revision"] = true
	})
	cfg, specs := r.specsFromConfig(t)
	_ = cfg
	if _, err := startScrapeHost(r.f.ctx, ScrapeHostDeps{Auth: r.f.app.Auth, Ingest: r.ingest, Secrets: r.reader}, specs, nil); err == nil {
		t.Fatal("a followed target started without a policy reader")
	}
}

// A source policy change (revision 1 -> 2) stops a pinned target with a typed
// policy_stale, while a followed target keeps scraping and admitting under the
// new revision without any configuration change.
func TestScrapeHostFollowsTheLiveSourcePolicyRevision(t *testing.T) {
	for _, follow := range []bool{true, false} {
		name := "pinned"
		if follow {
			name = "followed"
		}
		t.Run(name, func(t *testing.T) {
			r := newHostRig(t)
			if follow {
				r.writeConfig(func(target map[string]any) {
					src := target["source"].(map[string]any)
					delete(src, "policy_revision")
					src["follow_policy_revision"] = true
				})
			}
			h := r.startFollow(t, true)
			waitFor(t, "a healthy admitted cycle", 20*time.Second, func() bool {
				return r.only(t, h).OK() && r.ingest.admitted.Load() >= 1
			})
			next := hostPolicy(r.f)
			next.Revision = 2
			if _, err := r.f.app.Auth.ChangeSourcePolicy(r.f.ctx, r.f.actor, auth.SourcePolicyChange{CommandID: model.NewID(), Source: r.source, ExpectedRevision: 1, Policy: next, Reason: "scrape follow regression"}); err != nil {
				t.Fatal(err)
			}
			// The change fences the source until its fence drains (the node's
			// RunFences does this in production); admission is refused meanwhile.
			if err := r.f.app.Auth.DrainSourceFences(r.f.ctx); err != nil {
				t.Fatal(err)
			}
			if !follow {
				waitFor(t, "policy_stale", 20*time.Second, func() bool { return r.only(t, h).Reason == ScrapeReasonPolicyStale })
				return
			}
			base := r.ingest.admitted.Load()
			waitFor(t, "an admission under the new revision", 20*time.Second, func() bool {
				st := r.only(t, h)
				return st.OK() && r.ingest.admitted.Load() > base+1
			})
			if st := r.only(t, h); st.Reason != ScrapeReasonNone || !st.OK() {
				t.Fatalf("status %+v", st)
			}
		})
	}
}
