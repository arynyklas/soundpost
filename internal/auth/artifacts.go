// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth

import (
	"context"
	"encoding/json"
	"soundpost/internal/model"
)

const ArtifactWrite Permission = "artifacts.write"
const ArtifactRead Permission = "artifacts.read"

// ValidateArtifactState is called inside the same control transaction as a
// reservation/reference write. Source credentials are never artifact authority.
func (scope Scope) ValidateArtifactState(st model.ControlState, m model.BlobManifest, write bool) error {
	if scope.service == nil || scope.sourceCredential != nil || scope.org != m.Org || !scope.AllowsProject(m.Project) {
		return model.Fail(model.NotFound)
	}
	want := ArtifactRead
	if write {
		want = ArtifactWrite
	}
	if scope.action != want {
		return model.Fail(model.NotFound)
	}
	if write && scope.elevation != (model.ID{}) {
		return model.Fail(model.Forbidden)
	}
	if !write && m.RetainUntil != 0 && int64(m.RetainUntil) <= scope.service.now().UnixNano() {
		return model.Fail(model.NotFound)
	}
	if err := scope.ValidateControlState(st); err != nil {
		return err
	}
	o := st.Orgs[m.Org.String()]
	if _, ok := o.Projects[m.Project.String()]; !ok {
		return model.Fail(model.NotFound)
	}
	// An artifact root under an active deletion is gone for every consumer of
	// this fence (reference lookup, byte reads, symbolication, native profile and
	// link resolution), not only for the storage engine that gates its own reads:
	// a reader that holds warm bytes must still be refused. Writes are refused the
	// way the data plane answers a tombstoned root (Conflict); reads are
	// indistinguishable from an absent artifact.
	if deletionCoversArtifact(st, m) {
		if write {
			return model.Fail(model.Conflict)
		}
		return model.Fail(model.NotFound)
	}
	src, ok := st.Sources[m.Source.String()]
	if !ok || src.Org != m.Org || src.Project != m.Project || src.Retired || src.Revoked || src.Closing || !src.Policy.Enabled || src.Browser {
		return model.Fail(model.NotFound)
	}
	if write && (uint64(m.PolicyEpoch) != scope.epoch || m.PolicyRevision != src.Policy.Revision) {
		return model.Fail(model.Stale)
	}
	if src.Policy.Expires != 0 && int64(src.Policy.Expires) <= scope.service.now().UnixNano() {
		return model.Fail(model.Stale)
	}
	found := false
	for _, build := range src.Policy.Resources.Builds {
		if build == m.Build {
			found = true
		}
	}
	if !found {
		return model.Fail(model.NotFound)
	}
	var cfg SourcePolicyConfig
	if json.Unmarshal(o.Settings["source_policy:"+m.Source.String()], &cfg) != nil || !cfg.Enabled || cfg.ProjectID != m.Project {
		return model.Fail(model.NotFound)
	}
	if m.PrivateSources {
		// Source content is independent of map access and requires both raw.read
		// (including machine-token restriction) and a named source-reader grant.
		if !tokenAllows(st, scope.credential, m.Org, []model.ID{m.Project}, RawRead) || !hasID(cfg.Readers, scope.credential.user) {
			return model.Fail(model.NotFound)
		}
		permitted := false
		for _, v := range o.Grants[scope.credential.user.String()+":"+m.Project.String()] {
			if v == string(RawRead) {
				permitted = true
			}
		}
		for _, team := range o.Teams {
			if team.Enabled && hasID(team.Members, scope.credential.user) && hasID(team.Projects, m.Project) {
				for _, v := range team.Permissions {
					if v == string(RawRead) {
						permitted = true
					}
				}
			}
		}
		if !permitted {
			return model.Fail(model.NotFound)
		}
	}
	return nil
}

// deletionCoversArtifact reports whether an operation that has begun covers the
// blob's root: fencing, complete or failed, exactly the set control.ActiveDeletions
// hands the storage engine. A held operation has not begun and hides nothing, and a
// historical_range predicate never covers an artifact (model CoversBlob).
func deletionCoversArtifact(st model.ControlState, m model.BlobManifest) bool {
	for _, op := range st.Deletions {
		if op.Phase != model.DeletePhaseHeld && op.Predicate.CoversBlob(m) {
			return true
		}
	}
	return false
}

// ValidateArtifactCleanup authorizes terminal orphan cleanup (cancel/GC). The
// durable reservation proof carries the source/policy binding, so cleanup needs
// only the caller's current artifacts.write scope over the owning org/project;
// it deliberately does not require the source to still admit writes, because
// policy/epoch changes and source retirement are exactly when orphans must be
// reclaimable.
func (scope Scope) ValidateArtifactCleanup(st model.ControlState, m model.BlobManifest) error {
	if scope.service == nil || scope.sourceCredential != nil || scope.org != m.Org || !scope.AllowsProject(m.Project) || scope.action != ArtifactWrite {
		return model.Fail(model.NotFound)
	}
	if scope.elevation != (model.ID{}) {
		return model.Fail(model.Forbidden)
	}
	if err := scope.ValidateControlState(st); err != nil {
		return err
	}
	if _, ok := st.Orgs[m.Org.String()].Projects[m.Project.String()]; !ok {
		return model.Fail(model.NotFound)
	}
	return nil
}

func (scope Scope) RevalidateArtifact(ctx context.Context, m model.BlobManifest, write bool) error {
	if scope.service == nil {
		return model.Fail(model.NotFound)
	}
	if err := scope.service.Revalidate(ctx, scope); err != nil {
		return err
	}
	return scope.service.store.View(ctx, func(st model.ControlState) error { return scope.ValidateArtifactState(st, m, write) })
}
func (scope Scope) ArtifactPolicy(ctx context.Context, project, source, build model.ID, private bool) (uint64, model.Revision, error) {
	if scope.service == nil {
		return 0, 0, model.Fail(model.NotFound)
	}
	var max uint64
	var rev model.Revision
	err := scope.service.store.View(ctx, func(st model.ControlState) error {
		src := st.Sources[source.String()]
		m := model.BlobManifest{Org: scope.org, Project: project, Source: source, Build: build, PolicyEpoch: model.Uint64(scope.epoch), PolicyRevision: src.Policy.Revision, PrivateSources: private}
		if e := scope.ValidateArtifactState(st, m, true); e != nil {
			return e
		}
		max = uint64(src.Policy.MaxBytes)
		rev = src.Policy.Revision
		return nil
	})
	return max, rev, err
}
func (scope Scope) ValidateBlobReservation(ctx context.Context, m model.BlobManifest) (model.ArtifactQuotaReservation, error) {
	if scope.service == nil {
		return model.ArtifactQuotaReservation{}, model.Fail(model.NotFound)
	}
	var out model.ArtifactQuotaReservation
	err := scope.service.store.View(ctx, func(st model.ControlState) error {
		if err := scope.ValidateArtifactState(st, m, true); err != nil {
			return err
		}
		r, ok := st.ArtifactReservations[m.ReservationID.String()]
		if !ok || r.State != "reserved" && r.State != "consumed" || r.Manifest != m || r.ManifestHash != model.BlobManifestHash(m) || r.Slot != model.BlobOwnerSlot(m.Org, m.Project, m.Root) {
			return model.Fail(model.Forbidden)
		}
		out = r
		return nil
	})
	return out, err
}

// ArtifactReadScope resolves a distinct permission using the same opaque actor.
// Audited elevations retain their committed handle and read audit.
func (scope Scope) ArtifactReadScope(ctx context.Context, project model.ID) (Scope, error) {
	if scope.service == nil || scope.sourceCredential != nil || !scope.AllowsProject(project) {
		return Scope{}, model.Fail(model.NotFound)
	}
	if err := scope.service.Revalidate(ctx, scope); err != nil {
		return Scope{}, err
	}
	if scope.elevation != (model.ID{}) {
		e, err := scope.service.ResolveElevation(ctx, scope.credential, scope.elevation)
		if err != nil {
			return Scope{}, err
		}
		return scope.service.ElevatedScope(ctx, e, scope.org, []model.ID{project}, ArtifactRead)
	}
	return scope.service.Authorize(ctx, scope.credential, scope.org, []model.ID{project}, ArtifactRead)
}

func (scope Scope) ValidateArtifactGC(ctx context.Context, proof model.ArtifactGC) error {
	if scope.service == nil {
		return model.Fail(model.Forbidden)
	}
	return scope.service.store.View(ctx, func(st model.ControlState) error {
		if err := scope.ValidateArtifactCleanup(st, proof.Manifest); err != nil {
			return err
		}
		r, ok := st.ArtifactReservations[proof.Manifest.ReservationID.String()]
		if !ok || r.Manifest != proof.Manifest || r.State != "cancelled" || r.GC == nil || r.GC.CommandID != proof.CommandID || r.GC.ControlRevision != proof.ControlRevision || proof.ControlRevision == 0 || proof.ControlRevision > st.Revision {
			return model.Fail(model.Forbidden)
		}
		for _, ref := range st.ArtifactIntents {
			if ref.Manifest.Org == proof.Manifest.Org && ref.Manifest.Project == proof.Manifest.Project && ref.ID == proof.Manifest.Root {
				return model.Fail(model.Conflict)
			}
		}
		return nil
	})
}
