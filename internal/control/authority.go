// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"maps"
	"strings"

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
	// writerReplayIndex: the post-admission replay index step (replays.Service.Record): it adds an
	// immutable checkpoint entry and moves a replay retention group deadline, both keyed by the
	// replay of a chunk that admission already accepted. It reads authority (the grant and the
	// deletion predicates are checked before and at read time) and writes no grant, policy,
	// hold, deletion or access state. Without this entry every replay chunk admitted would move
	// AuthorityRevision and starve a deletion Begin exactly as intake did.
	writerReplayIndex writer = "ReplayIndex"
	// writerAttestControl: a voter's own statement that its control journal and control.db are
	// clean of the erased payloads (attest.go). It writes only that voter's attestation record
	// (an st.OIDC resident under attestKeyPrefix) and prunes the records of nodes that left the
	// group: evidence about files, read by the receipt, never by an authorization decision, a
	// grant, a policy, a hold or a deletion. It is committed through updateAsGuarded with a mask
	// that removes those records, so a change to anything else bumps AuthorityRevision as an
	// unclassified writer would. Without this entry every attestation would move AuthorityRevision
	// and starve a deletion Begin that holds a caller view older than it.
	writerAttestControl writer = "AttestControl"
	// writerSessionCreate: a login (password or SSO) that only ADDS a session record. A session
	// is a credential for a user whose rights are unchanged by it: every access decision is
	// computed from Users, grants, Orgs and memberships at the time of the request, never from
	// the session's existence, so a new session cannot widen or narrow what any principal may
	// read, what is retained, a policy, grant, membership, hold or deletion. What DOES change
	// authority stays bumping: revocation (Logout), disabling a user, a credential or factor
	// change (any write to Users, including a consumed TOTP step or recovery code) and the
	// removal or alteration of an existing session. updateAsGuardedChecked therefore masks the
	// Sessions map and separately requires every session that existed before to be unchanged.
	writerSessionCreate writer = "SessionCreate"
	// writerArtifactLedger: Reference / Unreference of a published artifact map. It writes the
	// artifact's reference ledger and its index entry (org Settings artifact_refs: and
	// artifact_refs_index: keys), a book of "which retained record still needs this map" that
	// the GC fence reads. It cannot change who may read the map (the scope is validated before,
	// and a deletion predicate covering the blob refuses the write), a policy, grant, hold or
	// deletion. The transition that retires the map (ArtifactIntents state, the org
	// DeleteGenerations counter, the retired project set) is NOT masked and keeps bumping, as do
	// the GC fence callers (they use the unclassified Update).
	writerArtifactLedger writer = "ArtifactLedger"
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
	writerReplayIndex:         "replay checkpoint index entry and retention group deadline",
	writerAttestControl:       "a voter's control residue attestation record (evidence about its own files)",
	writerSessionCreate:       "a new session record for an existing user (no existing session or user changed)",
	writerArtifactLedger:      "artifact reference ledger and index entry (retention bookkeeping, not access state)",
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
	return s.replicatedUpdate(ctx, bump, nil, guardAttestations(fn))
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

// UpdateReplayIndex commits fn as one control transition for the replay index step. It leaves
// AuthorityRevision alone only if fn changed nothing but the replay index entries
// (model.ReplayIndexKeyPrefix / ReplayPinKeyPrefix keys of an organization's Settings): the
// state is encoded before and after fn with those entries masked out, and any other difference
// bumps AuthorityRevision exactly as an unclassified writer does. A misbehaving caller is never
// rejected (that would turn a classification mistake into data loss); it only loses the
// exemption. Cost: two canonical encodings of the state per call (see the 10.11 report).
func (s *Store) UpdateReplayIndex(ctx context.Context, fn func(*State) error) error {
	return s.updateAsGuarded(ctx, writerReplayIndex, stateWithoutReplayIndex, fn)
}

// UpdateSessionCreate commits fn, a login that adds a session, without moving AuthorityRevision
// when fn changed nothing but the Sessions map and left every pre-existing session byte for byte
// as it was. Any other difference (a user record, a membership, a removed or altered session)
// bumps as an unclassified writer does.
func (s *Store) UpdateSessionCreate(ctx context.Context, fn func(*State) error) error {
	return s.updateAsGuardedChecked(ctx, writerSessionCreate, stateWithoutSessions, sessionsOnlyGrow, fn)
}

// UpdateArtifactReferences commits fn, a reference-ledger write, without moving
// AuthorityRevision when fn changed nothing but ledger and ledger-index entries in organization
// Settings. The retire transition (intent state, delete generation) is outside the mask and bumps.
func (s *Store) UpdateArtifactReferences(ctx context.Context, fn func(*State) error) error {
	return s.updateAsGuarded(ctx, writerArtifactLedger, stateWithoutArtifactLedger, fn)
}

// stateWithoutSessions is the canonical encoding of st with the Sessions map removed.
func stateWithoutSessions(st *State) ([]byte, error) {
	masked := *st
	masked.Sessions = nil
	return json.Marshal(masked)
}

// sessionsOnlyGrow snapshots the sessions before fn and returns the check that every one of them
// is still present and unchanged afterwards.
func sessionsOnlyGrow(st *State) func(*State) bool {
	before := maps.Clone(st.Sessions)
	return func(after *State) bool {
		for k, v := range before {
			if got, ok := after.Sessions[k]; !ok || got != v {
				return false
			}
		}
		return true
	}
}

// stateWithoutArtifactLedger is the canonical encoding of st with every organization's artifact
// reference ledger and index entries removed from its Settings.
func stateWithoutArtifactLedger(st *State) ([]byte, error) {
	masked := *st
	masked.Orgs = make(map[string]model.ControlOrg, len(st.Orgs))
	for id, o := range st.Orgs {
		settings := make(map[string]json.RawMessage, len(o.Settings))
		for k, v := range o.Settings {
			if !strings.HasPrefix(k, model.ArtifactLedgerKeyPrefix) && !strings.HasPrefix(k, model.ArtifactLedgerIndexKeyPrefix) {
				settings[k] = v
			}
		}
		o.Settings = settings
		masked.Orgs[id] = o
	}
	return json.Marshal(masked)
}

// updateAsGuarded is updateAs for a writer whose allowlisting depends on what it wrote: mask
// encodes the state with the writer's own entries removed, and a difference across fn bumps.
func (s *Store) updateAsGuarded(ctx context.Context, w writer, mask func(*State) ([]byte, error), fn func(*State) error) error {
	return s.updateAsGuardedChecked(ctx, w, mask, nil, fn)
}

// updateAsGuardedChecked adds an optional invariant to updateAsGuarded: preserve runs before fn
// and returns a check run after it; a false check bumps like a mask difference.
func (s *Store) updateAsGuardedChecked(ctx context.Context, w writer, mask func(*State) ([]byte, error), preserve func(*State) func(*State) bool, fn func(*State) error) error {
	if _, keep := nonAuthorityWriters[w]; !keep {
		return s.update(ctx, true, fn)
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	if s.repl == nil {
		return model.Fail(model.Unavailable)
	}
	if w != writerAttestControl {
		fn = guardAttestations(fn) // only the attestation writer may change an attestation
	}
	force := false
	return s.replicatedUpdate(ctx, false, &force, func(st *State) error {
		before, err := mask(st)
		var holds func(*State) bool
		if preserve != nil {
			holds = preserve(st)
		}
		if err != nil {
			force = true
		}
		if err = fn(st); err != nil {
			return err
		}
		after, err := mask(st)
		if err != nil || !bytes.Equal(before, after) || holds != nil && !holds(st) {
			force = true
		}
		return nil
	})
}

// stateWithoutReplayIndex is the canonical encoding of st with every organization's replay
// index entries removed from its Settings. Orgs and their Settings are copied, never mutated.
func stateWithoutReplayIndex(st *State) ([]byte, error) {
	masked := *st
	masked.Orgs = make(map[string]model.ControlOrg, len(st.Orgs))
	for id, o := range st.Orgs {
		settings := make(map[string]json.RawMessage, len(o.Settings))
		for k, v := range o.Settings {
			if !strings.HasPrefix(k, model.ReplayIndexKeyPrefix) && !strings.HasPrefix(k, model.ReplayPinKeyPrefix) {
				settings[k] = v
			}
		}
		o.Settings = settings
		masked.Orgs[id] = o
	}
	return json.Marshal(masked)
}
