// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"encoding/json"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

// The previous release (5475ef6) declares protocol 5 but does not know the per-organization rule: a
// leader of it judges a retention command against AuthorityRevision alone. A verified commit of an
// organization therefore moves AuthorityRevision as well as the organization's own revision, and this
// release reads the scalar through the installation floor, which skips such commits of other
// organizations. Those tests pin both halves; the real-binary counterpart is
// tools/smoke TestMixedBinaryStaleSameOrgCommandsAreRefusedByThePreviousReleaseLeader.

// A same-organization view older than an admin or a retention commit is refused by the previous
// release's rule and by this release's rule.
func TestStaleSameOrganizationViewIsRefusedByBothReleaseRules(t *testing.T) {
	t.Run("admin command", func(t *testing.T) {
		f := newFenceFxPatch(t)
		view, _ := f.revisions()
		f.admin("membership", f.org, auth.AdminPayload{UserID: f.user, Enabled: true, Reason: "an admin command of the organization"})
		rev, floor := f.revisions()
		if g := f.globalAuthority(); g != rev {
			t.Fatalf("AuthorityRevision %d after an admin command at revision %d: the previous release judges against it", g, rev)
		}
		if f.orgAuthority(f.org) != rev || floor != view {
			t.Fatalf("organization authority %d (want %d), floor %d (want %d)", f.orgAuthority(f.org), rev, floor, view)
		}
		if f.previousReleaseAccepts(view) {
			t.Fatal("the previous release's rule accepts a same-organization view older than the admin command")
		}
		if err := f.beginAt(view); code(err) != model.Conflict {
			t.Fatalf("this release accepted a same-organization view older than the admin command: %v", err)
		}
	})
	for _, c := range retentionActions() {
		if c.retiresOrg {
			continue
		}
		t.Run(c.name, func(t *testing.T) {
			f := newFenceFxPatch(t)
			own := f.ownActor()
			commit := c.prepare(own)
			view, _ := f.revisions()
			commit()
			rev, _ := f.revisions()
			if g := f.globalAuthority(); g != rev {
				t.Fatalf("AuthorityRevision %d after a retention-class commit at revision %d", g, rev)
			}
			if f.previousReleaseAccepts(view) {
				t.Fatal("the previous release's rule accepts a same-organization view older than the commit")
			}
			if err := f.beginAt(view); code(err) != model.Conflict {
				t.Fatalf("this release accepted a same-organization view older than the commit: %v", err)
			}
		})
	}
}

// Another organization's admin commands move the scalar (the previous release then refuses the view,
// a false conflict it always had) but not this release's floor: a new leader accepts the command.
func TestAnotherOrganizationsAdminCommandMovesTheScalarButNotTheFloor(t *testing.T) {
	f := newFenceFxPatch(t)
	other := model.NewID()
	f.admin("create_org", other, auth.AdminPayload{Name: "tenant b", Reason: "second tenant"})
	view, floor := f.revisions()
	f.admin("create_project", other, auth.AdminPayload{ID: model.NewID(), Name: "b1", Reason: "tenant b project"})
	f.admin("membership", other, auth.AdminPayload{UserID: f.user, Enabled: true, Reason: "tenant b membership"})
	rev, now := f.revisions()
	if g := f.globalAuthority(); g != rev || rev != view+2 {
		t.Fatalf("AuthorityRevision %d, revision %d (view %d)", g, rev, view)
	}
	if now != floor {
		t.Fatalf("floor %d -> %d: another organization's admin commands must not move it", floor, now)
	}
	if f.previousReleaseAccepts(view) {
		t.Fatal("the previous release's rule accepts a view older than the scalar")
	}
	if err := f.beginAt(view); err != nil {
		t.Fatalf("this release refused a view that is stale only for another organization: %v", err)
	}
}

// A commit of a binary that does not write the pair (the previous release, here an unclassified
// bump) voids it: the floor is the scalar again, so an authority change it made is never skipped even
// when a verified commit of another organization came before it.
func TestACommitThatDoesNotWriteThePairVoidsTheFloor(t *testing.T) {
	f := newFenceFxPatch(t)
	b := f.tenantB()
	b.placeHold(b.p2) // a verified commit of tenant b: the pair is written
	view, _ := f.revisions()
	if err := f.store.Update(f.ctx, func(*control.State) error { return nil }); err != nil {
		t.Fatal(err)
	}
	rev, floor := f.revisions()
	if floor != rev {
		t.Fatalf("floor %d after an unclassified bump at revision %d: the pair of the earlier commit must be void", floor, rev)
	}
	if err := f.beginAt(view); code(err) != model.Conflict {
		t.Fatalf("Begin on a view older than the bump: %v, want Conflict", err)
	}
}

// A view that is stale because another organization's command wrote a table that is not scoped to one
// organization (the user table, an evidence gap keyed by a hash, a quota, the installation key) keeps
// the global check on this release too: the floor moves with such a commit.
func TestAViewStaleThroughASharedTableStillConflictsOnThisRelease(t *testing.T) {
	t.Run("user table (create_user of another organization's admin)", func(t *testing.T) {
		f := newFenceFxPatch(t)
		b := f.tenantB()
		_ = b
		view, _ := f.revisions()
		f.admin("create_user", b.org, auth.AdminPayload{ID: model.NewID(), Email: "shared@example.test", Password: "a long test password 2026", Reason: "the user table is installation-wide"})
		rev, floor := f.revisions()
		if floor != rev {
			t.Fatalf("floor %d, revision %d: a write of the user table must move the floor", floor, rev)
		}
		if err := f.beginAt(view); code(err) != model.Conflict {
			t.Fatalf("Begin on a view older than a write of the user table: %v, want Conflict", err)
		}
	})
	t.Run("evidence gap (hash-keyed, declared by another organization)", func(t *testing.T) {
		f := newFenceFxPatch(t)
		b := f.tenantB()
		view, _ := f.revisions()
		b.must(control.KindRecordEvidenceGap, model.NewID(), b.gap(b.p1))
		if err := f.beginAt(view); code(err) != model.Conflict {
			t.Fatalf("Begin on a view older than another organization's new evidence gap: %v, want Conflict", err)
		}
		if rev, floor := f.revisions(); floor != rev {
			t.Fatalf("floor %d, revision %d", floor, rev)
		}
	})
}

// The admin kinds `source_policy` (for a live source: Sources, SourceFences, SourceOperations) and
// `retention` (RetentionPolicies) write tables outside what the admin class owns, so verification fails
// and they are ordinary bumps: the floor moves and a view that is stale only because of such a command
// of another organization still conflicts on this release.
func TestAdminSourcePolicyAndRetentionKeepTheGlobalCheck(t *testing.T) {
	beginOf := func(f *fenceFx, b *retentionActor, view model.Revision) error {
		scope, err := f.svc.Authorize(f.ctx, f.cred, b.org, nil, auth.OrgAdmin)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(control.DeleteScope{Mode: model.DeleteHistoricalRange, Projects: []model.ID{b.p1}, Signals: []model.Kind{model.Metric}, End: 100, Reason: "view stale through a shared write", At: b.at(), PhysicalDeadline: b.at() + 1e9, BackupDeadline: b.at() + 2e9})
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.store.Transact(f.ctx, scope, control.Command{CommandID: model.NewID(), ExpectedRevision: view, Kind: string(control.KindDeleteScope), Payload: raw})
		return err
	}
	t.Run("retention of another organization", func(t *testing.T) {
		f := newFenceFxPatch(t)
		b := f.tenantB()
		view, _ := f.revisions()
		cfg, _ := json.Marshal(auth.RetentionConfig{ProjectID: b.p1, Signal: "metrics", Days: 30})
		f.admin("retention", b.org, auth.AdminPayload{ID: model.NewID(), Config: cfg, Reason: "retention of tenant b"})
		rev, floor := f.revisions()
		if floor != rev || f.globalAuthority() != rev {
			t.Fatalf("floor %d, scalar %d, revision %d: an admin retention command writes RetentionPolicies and must move the floor", floor, f.globalAuthority(), rev)
		}
		if err := f.beginAt(view); code(err) != model.Conflict {
			t.Fatalf("Begin on a view older than another organization's admin retention command: %v, want Conflict", err)
		}
	})
	t.Run("source_policy of another organization", func(t *testing.T) {
		f := newFenceFxPatch(t)
		b := f.tenantB()
		view, _ := f.revisions()
		cfg, _ := json.Marshal(auth.SourcePolicyConfig{ProjectID: f.project, Enabled: true})
		f.admin("source_policy", f.org, auth.AdminPayload{ID: f.source, Config: cfg, Reason: "narrow the source"})
		rev, floor := f.revisions()
		if floor != rev || f.globalAuthority() != rev {
			t.Fatalf("floor %d, scalar %d, revision %d: a source_policy command of a live source writes the source tables and must move the floor", floor, f.globalAuthority(), rev)
		}
		if err := beginOf(f, b, view); code(err) != model.Conflict {
			t.Fatalf("Begin of another organization on a view older than a source_policy command: %v, want Conflict", err)
		}
	})
}
