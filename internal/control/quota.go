// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"bytes"
	"context"
	"errors"
	"math"
	"sort"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
)

type ReserveAdmission = model.ReserveAdmission
type FinalizeAdmission = model.FinalizeAdmission
type CancelReservation = model.CancelReservation

// newReservationID is a reservation's identity: ten random bytes after the time in milliseconds. The ledger
// keeps the reservation rows by their identity, and a reservation is written when it is made, written again
// when it is finalized shortly after, and read while its batch is appended: with identities that are
// ordered by the time they are made in, every one of those touches the few pages at the end of the table
// (the append-only part of the write set) and not a page of the table's whole history, which is what a
// random identity does. Nothing reads meaning into an identity: it is an opaque key.
func newReservationID() model.ID {
	id := model.NewID()
	ms := uint64(time.Now().UnixMilli())
	for i := 5; i >= 0; i-- {
		id[i] = byte(ms)
		ms >>= 8
	}
	return id
}

func reservationKey(r model.AdmissionReservation) string {
	return r.Org.String() + ":" + r.Project.String() + ":" + r.Source.String() + ":" + r.Producer.String() + ":" + stringSlot(r.Slot) + ":" + r.Batch.String()
}
func stringSlot(v uint16) string {
	const digits = "0123456789abcdef"
	return string([]byte{digits[v>>4], digits[v&15]})
}
func sourceQuotaKey(r model.AdmissionReservation) string {
	return "source:" + r.Org.String() + ":" + r.Project.String() + ":" + r.Source.String()
}
func quotaKeys(r model.AdmissionReservation) []string {
	return []string{"org:" + r.Org.String(), "project:" + r.Org.String() + ":" + r.Project.String(), sourceQuotaKey(r)}
}

// reserveStep is the transition of ReserveAdmission: validate the source against the state without the
// books (core), then either answer a retry of a reserved batch or charge the three quota keys and write
// the reservation. looked and admitted are the owner's answer about a batch control holds no row for
// once windows were settled. r is the reservation to write and, when the batch was reserved before, is
// replaced by the stored one.
func reserveStep(core *State, books admissionBooks, scope auth.Scope, r *model.AdmissionReservation, b model.NormalizedBatch, looked bool, admitted *model.Receipt) error {
	if e := scope.ValidateSourceState(*core, r.Project, r.Source, true); e != nil {
		return e
	}
	if scope.OrgID() != r.Org || model.Uint64(scope.PolicyEpoch()) != r.PolicyEpoch {
		return model.Fail(model.Forbidden)
	}
	key := reservationKey(*r)
	if id, exists := books.keyed(key); exists {
		old, ok, err := books.reservation(id)
		if err != nil {
			return err
		}
		if !ok {
			return model.Fail(model.Corrupt)
		}
		if old.Hash != r.Hash || old.State == "cancelled" {
			return model.Fail(model.Conflict)
		}
		if old.State == "reserved" && old.PolicyEpoch != r.PolicyEpoch {
			// A refused/ambiguous attempt left this charge bound to a retired
			// epoch. The retry was just revalidated against the current scope
			// (source enabled, not closing, epoch current) and carries the same
			// batch hash, so re-bind without recharging. A source whose policy
			// revision moved on since the batch was normalized is not a legitimate
			// retry: the batch carries the old revision and policy hash and can
			// never be admitted, so its charge is not carried into the new epoch.
			if b.PolicyRevision != core.Sources[r.Source.String()].Policy.Revision {
				return model.Fail(model.Stale)
			}
			old.PolicyEpoch = r.PolicyEpoch
			books.putReservation(old)
		}
		*r = old
		return nil
	}
	if books.hasWindows() {
		// No row for this key although windows were settled: the batch may be one of them.
		if !looked {
			return errNeedsAdmittedLookup
		}
		if admitted != nil {
			if admitted.Hash != r.Hash {
				return model.Fail(model.Conflict)
			}
			if _, ok, err := windowOf(books, admitted.Cursor); err != nil {
				return err
			} else if ok {
				// The batch is in the data and its reservation was settled: the answer its
				// row gave, consumed at the receipt's cursor, charged once already. Nothing
				// is stored for it again.
				cursor := admitted.Cursor
				r.State, r.Cursor = "consumed", &cursor
				return nil
			}
		}
	}
	p := core.Sources[r.Source.String()].Policy
	if p.MaxBytes == 0 || p.MaxSeries == 0 {
		return model.Fail(model.Quota)
	}
	sourceKey := sourceQuotaKey(*r)
	for _, tier := range quotaKeys(*r) {
		h, err := books.head(tier)
		if err != nil {
			return err
		}
		if tier == sourceKey {
			// A fenced source policy is authoritative for this tier, including
			// authorized raises. Existing charges/refcounts are never reset.
			h.MaxBytes = p.MaxBytes
			h.MaxSeries = p.MaxSeries
		} else {
			// Preserve conservative unconfigured organization/project defaults;
			// protected explicit global quota objects remain authoritative.
			if !h.Configured && (h.MaxBytes == 0 || p.MaxBytes < h.MaxBytes) {
				h.MaxBytes = p.MaxBytes
			}
			if !h.Configured && (h.MaxSeries == 0 || p.MaxSeries < h.MaxSeries) {
				h.MaxSeries = p.MaxSeries
			}
		}
		if r.Bytes > h.MaxBytes || h.Bytes > h.MaxBytes-r.Bytes {
			return model.Fail(model.Quota)
		}
		newSeries := uint64(0)
		for _, id := range r.Series {
			n := books.series(tier, id)
			if n == 0 {
				newSeries++
			}
			if n == math.MaxUint64 {
				return model.Fail(model.Quota)
			}
		}
		if newSeries > uint64(h.MaxSeries) || h.Series > uint64(h.MaxSeries)-newSeries {
			return model.Fail(model.Quota)
		}
		h.Bytes += r.Bytes
		for _, id := range r.Series {
			books.setSeries(tier, id, books.series(tier, id)+1)
		}
		books.putHead(tier, h)
	}
	books.putReservation(*r)
	books.putKey(key, r.ID.String())
	return nil
}

func (s *Store) ReserveAdmission(ctx context.Context, scope auth.Scope, b model.NormalizedBatch) (model.AdmissionReservation, error) {
	canonical, err := model.CanonicalJSON(b.Batch)
	if err != nil || !bytes.Equal(canonical, b.Canonical) || model.HashCanonical(canonical) != b.Hash {
		return model.AdmissionReservation{}, model.Fail(model.Invalid)
	}
	unique := map[string]bool{}
	for _, record := range b.Records {
		if record.Kind == model.Metric {
			id, e := model.CanonicalSeriesID(b.Project, record)
			if e != nil {
				return model.AdmissionReservation{}, e
			}
			unique[id] = true
		}
	}
	b.Series = make([]string, 0, len(unique))
	for id := range unique {
		b.Series = append(b.Series, id)
	}
	sort.Strings(b.Series)
	r := model.AdmissionReservation{ID: newReservationID(), Org: b.Org, Project: b.Project, Source: b.Source, Producer: b.Producer, Batch: b.ID, Slot: b.RouteSlot, Hash: b.Hash, PolicyEpoch: b.PolicyEpoch, Bytes: model.Uint64(len(b.Canonical)), Series: append([]string(nil), b.Series...), State: "reserved"}
	if r.Slot >= 64 || r.Bytes == 0 {
		return r, model.Fail(model.Invalid)
	}
	var looked bool
	var admitted *model.Receipt
	body := func(core *State, books admissionBooks) error {
		return reserveStep(core, books, scope, &r, b, looked, admitted)
	}
	// Once windows were settled, a key with no row may be a retry of a settled batch, which only
	// the owner's receipts can tell: the first run reports it (errNeedsAdmittedLookup, nothing
	// committed), the owner is asked, and the update runs again with its answer. A node that
	// already knows windows were settled asks before the first run.
	// A voter that is not the leader has the leader judge it (admission_remote.go); it judges it itself when no leader serves the call.
	update := func() error {
		if handled, e := s.reserveAtLeader(ctx, scope, b, &r, looked, admitted); handled {
			return e
		}
		return s.admissionUpdate(ctx, writerReserveAdmission, body)
	}
	run := func() (e error) {
		looked, admitted = true, nil
		lookFrom := time.Now()
		admitted, e = s.admittedBatch(ctx, r)
		noteStep("admitted_lookup", lookFrom)
		if e != nil {
			return e
		}
		return update()
	}
	var e error
	if s.settledSeen.Load() {
		e = run()
	} else if e = update(); errors.Is(e, errNeedsAdmittedLookup) {
		s.settledSeen.Store(true)
		e = run()
	}
	return r, e
}

// admittedBatch asks the installed owner whether the data holds the batch r names. No owner, or an
// owner that cannot tell, is Unavailable: a settled retry must never be charged twice.
func (s *Store) admittedBatch(ctx context.Context, r model.AdmissionReservation) (*model.Receipt, error) {
	s.registryMu.RLock()
	owner := s.ownerProof
	s.registryMu.RUnlock()
	lookup, ok := owner.(admittedBatches)
	if !ok {
		return nil, model.Fail(model.Unavailable)
	}
	receipt, found, err := lookup.AdmittedBatch(ctx, r)
	if err != nil || !found {
		return nil, err
	}
	return &receipt, nil
}

// finalizeStep marks the reservation r names consumed at the cursor of its receipt.
func finalizeStep(core *State, books admissionBooks, scope auth.Scope, r FinalizeAdmission) error {
	old, ok, err := books.reservation(r.ReservationID.String())
	if err != nil {
		return err
	}
	if !ok {
		if _, settled, err := windowOf(books, r.Cursor); err != nil {
			return err
		} else if settled {
			return nil // consumed and folded into a settled window already (settle.go)
		}
		return model.Fail(model.NotFound)
	}
	if e := scope.ValidateSourceState(*core, old.Project, old.Source, false); e != nil {
		return e
	}
	if old.State == "cancelled" {
		return model.Fail(model.Conflict)
	}
	if old.Cursor != nil {
		if *old.Cursor != r.Cursor {
			return model.Fail(model.Conflict)
		}
		return nil
	}
	old.State = "consumed"
	cursor := r.Cursor
	old.Cursor = &cursor
	books.putReservation(old)
	return nil
}

func (s *Store) FinalizeAdmission(ctx context.Context, scope auth.Scope, r FinalizeAdmission) error {
	s.registryMu.RLock()
	owner := s.ownerProof
	s.registryMu.RUnlock()
	if owner == nil {
		return model.Fail(model.Unavailable)
	}
	verifyFrom := time.Now()
	e := owner.VerifyFinalization(ctx, r)
	noteStep("verify_finalization", verifyFrom)
	if e != nil {
		noteFailure("verify_finalization", e)
		return e
	}
	if handled, e := s.finalizeAtLeader(ctx, scope, r); handled {
		return e
	}
	return s.admissionUpdate(ctx, writerFinalizeAdmission, func(core *State, books admissionBooks) error {
		return finalizeStep(core, books, scope, r)
	})
}

// CancelReservation takes only a committed owner-group proof verified against the
// injected group's durable state. Expiry and router death are not evidence.
type AdmissionProofs interface {
	VerifyCancellation(context.Context, model.CancelReservation) error
	VerifyFinalization(context.Context, model.FinalizeAdmission) error
}

// BindAdmissionOwner establishes this lock-order invariant: an installed engine
// may hold its order mutex and then read control authority. Verify* completes
// before the control write transaction starts; no Store.Update/Transact apply
// callback may call back into the owner/engine (that would invert the order).
//
// The one-voter cancellation proof is valid only after Open has recovered the
// complete ordered prefix and while the engine fault latch prevents uncertain
// appends/cancellation. For 01.06, receipt absence alone is insufficient: Raft
// must prove no commit against its commit-set watermark, including committed
// but unapplied proposals, before committing a cancellation fence and refund.
func (s *Store) BindAdmissionOwner(owner AdmissionProofs) error {
	s.registryMu.Lock()
	defer s.registryMu.Unlock()
	if owner == nil || s.ownerProof != nil {
		return model.Fail(model.Conflict)
	}
	s.ownerProof = owner
	return nil
}

// cancelStep marks the reservation cancelled and refunds its charge.
func cancelStep(core *State, books admissionBooks, scope auth.Scope, r CancelReservation) error {
	old, ok, err := books.reservation(r.ReservationID.String())
	if err != nil {
		return err
	}
	if !ok {
		return model.Fail(model.NotFound)
	}
	if e := scope.ValidateSourceState(*core, old.Project, old.Source, false); e != nil {
		return e
	}
	if old.Hash != r.Hash || old.State == "consumed" {
		return model.Fail(model.Conflict)
	}
	if old.State == "cancelled" {
		return nil
	}
	for _, tier := range quotaKeys(old) {
		h, err := books.head(tier)
		if err != nil {
			return err
		}
		if h.Bytes < old.Bytes {
			return model.Fail(model.Corrupt)
		}
		h.Bytes -= old.Bytes
		for _, id := range old.Series {
			if n := books.series(tier, id); n <= 1 {
				books.setSeries(tier, id, 0)
			} else {
				books.setSeries(tier, id, n-1)
			}
		}
		books.putHead(tier, h)
	}
	old.State = "cancelled"
	books.putReservation(old)
	return nil
}

func (s *Store) CancelAdmission(ctx context.Context, scope auth.Scope, r CancelReservation) error {
	s.registryMu.RLock()
	owner := s.ownerProof
	s.registryMu.RUnlock()
	if owner == nil {
		return model.Fail(model.Forbidden)
	}
	if e := owner.VerifyCancellation(ctx, r); e != nil {
		return e
	}
	return s.admissionUpdate(ctx, writerCancelAdmission, func(core *State, books admissionBooks) error {
		return cancelStep(core, books, scope, r)
	})
}
