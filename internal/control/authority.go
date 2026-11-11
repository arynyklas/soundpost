// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"context"
	"errors"

	"soundpost/internal/model"
)

// AuthorityRevision (model.ControlState.AuthorityRevision) is the control Revision of the last
// transition that could change authority, policy, retention, deletion or access state. It exists
// so that a caller whose view must be "no older than the last authority change" is not refused
// because unrelated control traffic (every intake admission commits a control transition) moved
// the one global Revision after the caller read it.
//
// The rule has two halves, both in this file:
//
//  1. replicatedUpdate sets AuthorityRevision to the new Revision after the transition function ran,
//     unless the writer is on the closed allowlist below (updateAs with a writer in
//     nonAuthorityWriters, or a Transact kind in nonAuthorityKinds). Every other writer, including
//     every Update call that is not named here and every writer of another package, bumps: a
//     writer nobody classified is treated as authority, which is the fail-safe direction.
//  2. Transact accepts cmd.ExpectedRevision for the retention kinds (retentionKinds) when
//     AuthorityRevision <= ExpectedRevision <= Revision. Every other kind keeps the strict
//     Revision == ExpectedRevision rule.
//
// The residual of the design is the classification itself: a writer wrongly put on the allowlist
// lets a deletion commit on a view older than a change that mattered. The tables below carry the
// reason for every entry, and authority_test.go scans the package for writers so that a new one
// cannot appear unclassified.

// writer names one control-package writer that is classified explicitly.
type writer string

// Non-authority writers (control package). Each entry says why it cannot change who may read,
// what is retained, a policy epoch, a source grant, an org/team/project/membership, SSO, a hold, a
// deletion operation or an authority record: it only moves admission accounting or a book of
// derived facts, and reads authority (it does not write it).
const (
	// writerReserveAdmission: reservation + quota charge of one intake batch. Writes
	// Reservations, AdmissionKeys, Quotas. The source quota tier it copies from the source policy
	// is derived from SourceAuthority.Policy, which it only reads.
	writerReserveAdmission writer = "ReserveAdmission"
	// writerFinalizeAdmission: marks a reservation consumed (Reservations only).
	writerFinalizeAdmission writer = "FinalizeAdmission"
	// writerCancelAdmission: marks a reservation cancelled and refunds its quota charge.
	writerCancelAdmission writer = "CancelAdmission"
	// writerReconcileAdmissions: consumed marking from the owner's durable outcomes.
	writerReconcileAdmissions writer = "ReconcileAdmissions"
	// writerReserveArtifact: artifact upload reservation and quota charge.
	writerReserveArtifact writer = "ReserveArtifact"
	// writerPublishArtifact: consumes artifact reservations and records the published
	// reference intent (a data reference, gated at read time by deletion predicates that this
	// writer does not touch).
	writerPublishArtifact writer = "PublishArtifact"
	// writerTransactIssues: issue lifecycle book commit (TransactIssues).
	writerTransactIssues writer = "TransactIssues"
	// writerTransactJobs: job book commit (TransactJobs).
	writerTransactJobs writer = "TransactJobs"
	// writerRedactNoop: the empty transition RedactRetainedControlCommands commits to move the
	// applied index past the journal floor. Its function changes nothing.
	writerRedactNoop writer = "RedactNoop"
)

// nonAuthorityWriters is the closed allowlist of updateAs writers that leave AuthorityRevision
// alone. A writer absent from it bumps, whatever else it does.
var nonAuthorityWriters = map[writer]string{
	writerReserveAdmission:    "reservation and quota charge of an intake batch",
	writerFinalizeAdmission:   "reservation consumed marker",
	writerCancelAdmission:     "reservation cancelled marker and quota refund",
	writerReconcileAdmissions: "reservation consumed marker from the owner's durable proof",
	writerReserveArtifact:     "artifact upload reservation and quota charge",
	writerPublishArtifact:     "published artifact reference intent",
	writerTransactIssues:      "issue lifecycle book commit",
	writerTransactJobs:        "job book commit",
	writerRedactNoop:          "empty transition that only moves the applied index",
}

// nonAuthorityKinds is the closed allowlist of Transact kinds whose commit leaves
// AuthorityRevision alone: the handlers write only their own book (rule, condition, incident,
// delivery/cutover, release/issue evidence, job) and audits of that write. A kind absent from the
// list bumps.
var nonAuthorityKinds = map[CommandKind]string{
	KindApplyIssueEvidence:  "issue evidence book",
	KindApplyCondition:      "condition book",
	KindApplyRuleEvaluation: "rule evaluation book and outputs",
	KindIncidentAction:      "incident book",
	KindClaimDelivery:       "delivery outbox and cutover books",
	KindCompleteDelivery:    "delivery outbox books",
	KindRegisterRelease:     "release registry",
	KindUpdateJob:           "job book",
}

// retentionKinds are the kinds BindRetention registers: the commands whose caller view is
// validated against AuthorityRevision rather than the global Revision.
var retentionKinds = map[CommandKind]bool{
	KindDeleteScope:       true,
	KindBeginFence:        true,
	KindCompleteFence:     true,
	KindPolicyChange:      true,
	KindRecordEvidenceGap: true,
}

// updateAs is Update for a classified writer: a writer on nonAuthorityWriters leaves
// AuthorityRevision alone, any other name bumps.
func (s *Store) updateAs(ctx context.Context, w writer, fn func(*State) error) error {
	_, keep := nonAuthorityWriters[w]
	return s.update(ctx, !keep, fn)
}

// update is the one entry to replicatedUpdate: bump says whether the transition moves
// AuthorityRevision. Update (the exported, unclassified entry) always bumps.
func (s *Store) update(ctx context.Context, bump bool, fn func(*State) error) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if s.repl == nil {
		return model.Fail(model.Unavailable)
	}
	return s.replicatedUpdate(ctx, bump, fn)
}

// authorityFloor is the oldest caller view a retention command may carry. A state that was
// written before AuthorityRevision existed has it zero while its Revision is not: its last
// authority change is unknown, so the floor is the current Revision (strict) until an
// authority transition stamps the field (Transact heals it itself, see healLegacyAuthority).
// A state with Revision 0 has no earlier transition to be older than: its floor is 0.
func authorityFloor(st *State) model.Revision {
	if st.AuthorityRevision == 0 && st.Revision > 0 {
		return st.Revision
	}
	return st.AuthorityRevision
}

// expectedRevisionOK is the whole Transact revision rule.
func expectedRevisionOK(st *State, kind string, expected model.Revision) bool {
	if !retentionKinds[CommandKind(kind)] {
		return st.Revision == expected
	}
	return authorityFloor(st) <= expected && expected <= st.Revision
}

// transactBumps says whether committing a Transact of this kind moves AuthorityRevision.
func transactBumps(kind string) bool {
	_, keep := nonAuthorityKinds[CommandKind(kind)]
	return !keep
}

// healLegacyAuthority stamps AuthorityRevision on a state that predates the field: one
// ordinary bumping transition that changes nothing else, so every voter computes the same
// state. Without it a legacy installation would stay strict, and so starvable, until its first
// authority write. It commits nothing when the field is already set.
func (s *Store) healLegacyAuthority(ctx context.Context) error {
	err := s.update(ctx, true, func(st *State) error {
		if st.AuthorityRevision != 0 || st.Revision == 0 {
			return errNothingToSettle
		}
		return nil
	})
	if errors.Is(err, errNothingToSettle) {
		return nil
	}
	return err
}
