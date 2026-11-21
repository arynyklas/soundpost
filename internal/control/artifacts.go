// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"bytes"
	"context"
	"github.com/arynyklas/soundpost/internal/artifacts/refledger"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
)

// The states of an artifact intent. "retired" is written by the artifact lifecycle in the
// same control transition as its GC fence (control cannot import that package).
const (
	artifactPublished = "published"
	artifactRetired   = "retired"
)

type artifactBlobProofs interface {
	VerifyBlob(context.Context, model.BlobReceipt) error
}

func (s *Store) artifactOwner() (artifactBlobProofs, error) {
	s.registryMu.RLock()
	defer s.registryMu.RUnlock()
	owner, ok := s.ownerProof.(artifactBlobProofs)
	if !ok {
		return nil, model.Fail(model.Unavailable)
	}
	return owner, nil
}
func (s *Store) ReserveArtifact(ctx context.Context, scope auth.Scope, m model.BlobManifest) (model.ArtifactQuotaReservation, error) {
	var out model.ArtifactQuotaReservation
	if m.Root == (model.ID{}) || m.Size == 0 || m.Size > model.ArtifactBundleLimit || m.RetainUntil <= 0 || m.ReservationID != (model.ID{}) {
		return out, model.Fail(model.Invalid)
	}
	err := s.updateAs(ctx, writerReserveArtifact, func(st *State) error {
		if err := scope.ValidateArtifactState(*st, m, true); err != nil {
			return err
		}
		if st.ArtifactReservations == nil {
			st.ArtifactReservations = map[string]model.ArtifactQuotaReservation{}
		}
		for _, r := range st.ArtifactReservations {
			old := r.Manifest
			if old.Org == m.Org && old.Project == m.Project && old.Build == m.Build && old.DebugID == m.DebugID && old.Path == m.Path && old.DebugID != "" && (old.GeneratedSHA256 != m.GeneratedSHA256 || old.MapSHA256 != m.MapSHA256 || old.Source != m.Source) {
				return model.Fail(model.Conflict)
			}
			if model.BlobKey(old) == model.BlobKey(m) {
				if r.State == "cancelled" || r.ManifestHash != model.BlobManifestHash(m) {
					return model.Fail(model.Conflict)
				}
				out = r
				return nil
			}
		}
		src := st.Sources[m.Source.String()]
		if src.Policy.MaxBytes == 0 {
			return model.Fail(model.Quota)
		}
		if st.Quotas == nil {
			st.Quotas = map[string]model.QuotaState{}
		}
		charge := model.AdmissionReservation{Org: m.Org, Project: m.Project, Source: m.Source}
		for _, key := range quotaKeys(charge) {
			q := st.Quotas[key]
			if !q.Configured && (q.MaxBytes == 0 || src.Policy.MaxBytes < q.MaxBytes) {
				q.MaxBytes = src.Policy.MaxBytes
			}
			if m.Size > q.MaxBytes || q.Bytes > q.MaxBytes-m.Size {
				return model.Fail(model.Quota)
			}
			q.Bytes += m.Size
			st.Quotas[key] = q
		}
		m.ReservationID = model.NewID()
		out = model.ArtifactQuotaReservation{ID: m.ReservationID, Manifest: m, ManifestHash: model.BlobManifestHash(m), Slot: model.BlobOwnerSlot(m.Org, m.Project, m.Root), State: "reserved"}
		st.ArtifactReservations[out.ID.String()] = out
		return nil
	})
	return out, err
}
func sameArtifact(a, b model.ArtifactReferenceIntent) bool {
	a.ControlRevision = 0
	b.ControlRevision = 0
	x, e := model.CanonicalJSON(a)
	y, f := model.CanonicalJSON(b)
	return e == nil && f == nil && bytes.Equal(x, y)
}
func (s *Store) PublishArtifact(ctx context.Context, scope auth.Scope, intent model.ArtifactReferenceIntent) (model.ArtifactReferenceIntent, error) {
	owner, err := s.artifactOwner()
	if err != nil {
		return model.ArtifactReferenceIntent{}, err
	}
	if err = scope.RevalidateArtifact(ctx, intent.Map.Manifest, true); err != nil {
		return model.ArtifactReferenceIntent{}, err
	}
	if err = owner.VerifyBlob(ctx, intent.Map); err != nil {
		return model.ArtifactReferenceIntent{}, err
	}
	if intent.Sources != nil {
		if err = scope.RevalidateArtifact(ctx, intent.Sources.Manifest, true); err != nil {
			return model.ArtifactReferenceIntent{}, err
		}
		if err = owner.VerifyBlob(ctx, *intent.Sources); err != nil {
			return model.ArtifactReferenceIntent{}, err
		}
	}
	intent.State = "published"
	intent.ControlRevision = 0
	intent.CommandID = intent.ID
	var out model.ArtifactReferenceIntent
	err = s.updateAs(ctx, writerPublishArtifact, func(st *State) error {
		m := intent.Manifest
		b := intent.Map.Manifest
		if intent.ID != b.Root || m.Org != b.Org || m.Project != b.Project || m.Source != b.Source || m.Build != b.Build || m.DebugID != b.DebugID || m.Path != b.Path || m.GeneratedSHA256 != b.GeneratedSHA256 || m.MapSHA256 != b.MapSHA256 || m.RetainUntil != b.RetainUntil || b.PrivateSources || m.SourceContent != (intent.Sources != nil) {
			return model.Fail(model.Invalid)
		}
		receipts := []model.BlobReceipt{intent.Map}
		if intent.Sources != nil {
			p := intent.Sources.Manifest
			if !p.PrivateSources || p.Root != b.Root || p.Org != b.Org || p.Project != b.Project || p.Source != b.Source || p.Build != b.Build || p.DebugID != b.DebugID || p.GeneratedSHA256 != b.GeneratedSHA256 || p.MapSHA256 != b.MapSHA256 || p.RetainUntil != b.RetainUntil || p.Path != b.Path {
				return model.Fail(model.Invalid)
			}
			receipts = append(receipts, *intent.Sources)
		}
		for _, receipt := range receipts {
			if err := scope.ValidateArtifactState(*st, receipt.Manifest, true); err != nil {
				return err
			}
			r, ok := st.ArtifactReservations[receipt.Manifest.ReservationID.String()]
			if !ok || r.Manifest != receipt.Manifest || r.State == "cancelled" {
				return model.Fail(model.Forbidden)
			}
			r.State = "consumed"
			owned := receipt
			r.Receipt = &owned
			st.ArtifactReservations[r.ID.String()] = r
		}
		key := m.Org.String() + ":" + m.Project.String() + ":" + intent.ID.String()
		if old, ok := st.ArtifactIntents[key]; ok {
			if !sameArtifact(old, intent) {
				return model.Fail(model.Conflict)
			}
			out = old
			return nil
		}
		if st.ArtifactIntents == nil {
			st.ArtifactIntents = map[string]model.ArtifactReferenceIntent{}
		}
		intent.ControlRevision = st.Revision + 1
		st.ArtifactIntents[key] = intent
		out = intent
		return nil
	})
	return out, err
}
func (s *Store) LookupArtifact(ctx context.Context, scope auth.Scope, id model.ID) (model.ArtifactReferenceIntent, error) {
	// Validate the scope before looking up even an absent artifact ID.
	if scope.Permission() != auth.ArtifactRead || len(scope.ProjectIDs()) != 1 {
		return model.ArtifactReferenceIntent{}, model.Fail(model.NotFound)
	}
	var out model.ArtifactReferenceIntent
	err := s.View(ctx, func(st State) error {
		if err := scope.ValidateControlState(st); err != nil {
			return err
		}
		key := scope.OrgID().String() + ":" + scope.ProjectIDs()[0].String() + ":" + id.String()
		r, ok := st.ArtifactIntents[key]
		if !ok || r.State != "published" {
			return model.Fail(model.NotFound)
		}
		if err := scope.ValidateArtifactState(st, r.Map.Manifest, false); err != nil {
			return err
		}
		if err := validateArtifactReference(st, key, r); err != nil {
			return err
		}
		out = r
		return nil
	})
	return out, err
}

// ValidateArtifactReferences gates app readiness over the exact retained bytes,
// including private source blobs. It never repairs authority from orphan files.
// An intent whose state is "retired" (written in the same control transition as the
// artifact lifecycle's GC fence, before any byte is erased) no longer owns bytes: its
// structure and reservations are still validated, but its blobs are not required, so a
// root that retention erased (or is about to erase after a crash between fence and
// erase) does not stop the process. A "published" intent whose blob is missing or
// corrupt stays Corrupt.
// A "published" intent covered by a deletion that is not held (model.DeletePredicate.CoversBlob: an
// entity deletion naming the root, retire_project, retire_org) is treated the same way: a completed
// deletion erased its bytes, and the read gate already refuses the root, so readiness does not
// require them. A held deletion keeps its bytes, so its intents are verified as before.
//
// Heal (10.09-W5): a "published" intent whose reference ledger verifies and carries the GC fence
// (Retired) is first moved to "retired". The lifecycle writes the fence and the intent state in
// one transition, so a published intent under a verified fence is the state an earlier build left
// when it erased the bytes of a fenced root, or a control snapshot older than the fence; the
// ledger is the durable record that nothing may read or reference the root any more, so its bytes
// are not required and the process may start. A ledger that does not verify heals nothing (the
// blob check below decides, as before), and so does a published intent under an unfenced ledger.
// The heal is best effort: on a node that cannot commit control state (a follower that has not
// caught up) it is skipped and the validation below answers as it always did.
func (s *Store) ValidateArtifactReferences(ctx context.Context) error {
	owner, err := s.artifactOwner()
	if err != nil {
		return err
	}
	_ = s.healFencedArtifactIntents(ctx)
	var refs []model.BlobReceipt
	if err = model.RetryWhileStale(ctx, func() error {
		return s.View(ctx, func(st State) error {
			for key, r := range st.ArtifactIntents {
				if err := validateArtifactReference(st, key, r); err != nil {
					return err
				}
				// A deletion that is not held (fencing, or complete with its bytes erased) covers the
				// root: nothing may read it and its bytes are gone or about to be, so a restart must not
				// demand them (the intent stays "published"; only an expiry or a fence retires it).
				if r.State == artifactRetired || deletedIntent(st, r) {
					continue
				}
				refs = append(refs, r.Map)
				if r.Sources != nil {
					refs = append(refs, *r.Sources)
				}
			}
			return nil
		})
	}); err != nil {
		return err
	}
	for _, r := range refs {
		if err = owner.VerifyBlob(ctx, r); err != nil {
			return model.Fail(model.Corrupt)
		}
	}
	return nil
}

// deletedIntent reports whether a deletion that is not held covers the intent's root.
func deletedIntent(st State, r model.ArtifactReferenceIntent) bool {
	for _, op := range st.Deletions {
		if op.Phase != model.DeletePhaseHeld && op.Predicate.CoversBlob(r.Map.Manifest) {
			return true
		}
	}
	return false
}

// fencedIntent reports whether the intent is published under a verified reference ledger that
// carries the GC fence.
func fencedIntent(st State, r model.ArtifactReferenceIntent) bool {
	if r.State != artifactPublished {
		return false
	}
	led, err := refledger.Load(st.Orgs[r.Manifest.Org.String()].Settings, r.Manifest.Project, r.ID)
	return err == nil && led != nil && led.Retired
}

// healFencedArtifactIntents moves every published intent under a verified GC fence to retired, in
// one control transition that re-checks each of them against the state it changes.
func (s *Store) healFencedArtifactIntents(ctx context.Context) error {
	var keys []string
	if err := model.RetryWhileStale(ctx, func() error {
		keys = keys[:0]
		return s.View(ctx, func(st State) error {
			for key, r := range st.ArtifactIntents {
				if fencedIntent(st, r) {
					keys = append(keys, key)
				}
			}
			return nil
		})
	}); err != nil || len(keys) == 0 {
		return err
	}
	return s.Update(ctx, func(st *State) error {
		for _, key := range keys {
			if r, ok := st.ArtifactIntents[key]; ok && fencedIntent(*st, r) {
				r.State = artifactRetired
				st.ArtifactIntents[key] = r
			}
		}
		return nil
	})
}

// CancelArtifact is a terminal, serialized no-reference intent. Charges remain
// reserved until a future exact cleanup release certificate; no TTL refund.
func (s *Store) CancelArtifact(ctx context.Context, scope auth.Scope, id, commandID model.ID) (model.ArtifactGC, error) {
	var out model.ArtifactGC
	if commandID == (model.ID{}) {
		return out, model.Fail(model.Invalid)
	}
	err := s.Update(ctx, func(st *State) error {
		r, ok := st.ArtifactReservations[id.String()]
		if !ok {
			return model.Fail(model.NotFound)
		}
		if err := scope.ValidateArtifactCleanup(*st, r.Manifest); err != nil {
			return err
		}
		for _, ref := range st.ArtifactIntents {
			if ref.ID == r.Manifest.Root && ref.Manifest.Org == r.Manifest.Org && ref.Manifest.Project == r.Manifest.Project {
				return model.Fail(model.Conflict)
			}
		}
		if r.State == "cancelled" {
			if r.GC == nil {
				return model.Fail(model.Corrupt)
			}
			out = *r.GC
			return nil
		}
		out = model.ArtifactGC{Manifest: r.Manifest, CommandID: commandID, ControlRevision: st.Revision + 1}
		r.State = "cancelled"
		r.GC = &out
		st.ArtifactReservations[id.String()] = r
		// GC of a root removes readable fragment bytes: every cache, cursor and
		// ticket bound to the old delete generation must die with them.
		bumpGeneration(st, r.Manifest.Org)
		return nil
	})
	return out, err
}

func validateArtifactReference(st State, key string, r model.ArtifactReferenceIntent) error {
	m, b := r.Manifest, r.Map.Manifest
	if r.State != artifactPublished && r.State != artifactRetired || r.ControlRevision == 0 || r.ControlRevision > st.Revision || r.CommandID != r.ID || key != m.Org.String()+":"+m.Project.String()+":"+r.ID.String() || r.ID != b.Root || m.Version != 1 || m.Org != b.Org || m.Project != b.Project || m.Source != b.Source || m.Build != b.Build || m.DebugID != b.DebugID || m.Path != b.Path || m.GeneratedSHA256 != b.GeneratedSHA256 || m.MapSHA256 != b.MapSHA256 || m.RetainUntil != b.RetainUntil || b.PrivateSources || m.SourceContent != (r.Sources != nil) {
		return model.Fail(model.Corrupt)
	}
	receipts := []model.BlobReceipt{r.Map}
	if r.Sources != nil {
		p := r.Sources.Manifest
		if !p.PrivateSources || p.Root != b.Root || p.Org != b.Org || p.Project != b.Project || p.Source != b.Source || p.Build != b.Build || p.DebugID != b.DebugID || p.Path != b.Path || p.GeneratedSHA256 != b.GeneratedSHA256 || p.MapSHA256 != b.MapSHA256 || p.RetainUntil != b.RetainUntil {
			return model.Fail(model.Corrupt)
		}
		receipts = append(receipts, *r.Sources)
	}
	for _, receipt := range receipts {
		reservation, ok := st.ArtifactReservations[receipt.Manifest.ReservationID.String()]
		if !ok || reservation.State != "consumed" || reservation.Manifest != receipt.Manifest || reservation.ManifestHash != model.BlobManifestHash(receipt.Manifest) || reservation.Receipt == nil {
			return model.Fail(model.Corrupt)
		}
		a, e := model.CanonicalJSON(*reservation.Receipt)
		b, f := model.CanonicalJSON(receipt)
		if e != nil || f != nil || !bytes.Equal(a, b) {
			return model.Fail(model.Corrupt)
		}
	}
	return nil
}
