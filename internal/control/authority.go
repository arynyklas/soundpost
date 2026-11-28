// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"strings"

	"github.com/arynyklas/soundpost/internal/model"
)

// AuthorityRevision (model.ControlState.AuthorityRevision) is the control Revision of the last
// transition that could change authority, policy, retention, deletion or access state. It exists
// so that a caller whose view must be "no older than the last authority change" is not refused
// because unrelated control traffic (every intake admission commits a control transition) moved
// the one global Revision after the caller read it.
//
// The rule has three parts, all in this file except the last, which is in authority_org.go:
//
//  1. replicatedUpdate sets AuthorityRevision to the new Revision after the transition function ran,
//     unless the writer is on the closed allowlist below (updateAs with a writer in
//     nonAuthorityWriters, or a Transact kind in nonAuthorityKinds). Every other writer, including
//     every Update call that is not named here and every writer of another package, bumps: a
//     writer nobody classified is treated as authority, which is the fail-safe direction.
//  2. Transact accepts cmd.ExpectedRevision for the retention kinds (retentionKinds) when it is no
//     older than the later of the installation floor (installationFloor) and the organization's own
//     authority revision (expectedRevisionOK) and no newer than Revision. Every other kind keeps
//     the strict Revision == ExpectedRevision rule.
//  3. The authority of one organization is its own scalar (model.OrgAuthorityKey in the
//     organization's Settings) for the writers that authority_org.go verifies: an admin command
//     of the organization and its retention-class transitions (F-10.05-2). They move the
//     organization's revision AND AuthorityRevision (the previous release judges against that
//     scalar alone), and leave the installation floor where it was when the commit changed nothing
//     outside what the class owns, so one tenant's commands do not make another tenant's views stale
//     on this release.
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
	// writerSettleAdmissions: replaces the rows of consumed reservations of a sealed data window
	// by their settled digest and folded charge (Reservations, AdmissionKeys, Settlement). Quotas,
	// grants and policy are not touched.
	writerSettleAdmissions writer = "SettleAdmissions"
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
	// writerSessionCreate: a login (password or SSO) that ADDS a session record and, for an
	// account with a second factor, consumes that factor. A session is a credential for a user
	// whose rights are unchanged by it: every access decision is computed from Users, grants,
	// Orgs and memberships at the time of the request, never from the session's existence, so a
	// new session cannot widen or narrow what any principal may read, what is retained, a
	// policy, grant, membership, hold or deletion. Consuming a factor writes exactly two fields
	// of the account: User.LastTOTP (the replay floor of the one-time code, only ever raised)
	// and User.Recovery (a one-time recovery hash, only ever removed). Proof that this moves no
	// authority: grep of every reader of those fields finds consumeFactor and ConfirmTOTP in
	// internal/auth/local.go and nothing else, so no read, retention, deletion, grant, policy,
	// hold or admission decision looks at either; a spent code narrows only what the NEXT login
	// of that account can present, never what any existing session or principal may do. What
	// DOES change authority stays bumping: revocation (Logout), disabling a user, a password, a
	// second-factor secret or enrolment change (any other field of Users), Admin, a lowered
	// LastTOTP or a recovery list that gained or reordered a hash, and the removal or alteration
	// of an existing session. updateAsGuardedChecked therefore masks the Sessions map and the two
	// factor fields, and separately requires every session that existed before to be unchanged,
	// LastTOTP never lower and Recovery a subsequence of what it was.
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
	// writerIssueHold: the holds of the issue producer (UpdateIssueHolds): one ledger entry per
	// (issue, map) taken while an issue is open and dropped when it is resolved or ignored. It
	// writes exactly what writerArtifactLedger writes and is masked the same way. It is a
	// writer of its own because the decision to take or drop a hold reads the workflow of the
	// issue in the grouping issues of the books, which the book-free ledger writer is not given:
	// a hold evaluated over a state without them finds no issue, so it never releases one.
	writerIssueHold writer = "IssueHold"
	// writerExpireControlLog: the control log expiry (ExpireControlLog, retention.go). It drops
	// audit rows past their retention and applied-command rows past the dedup window, with the
	// owner and time rows of those commands; it writes no grant, policy, hold, deletion, access
	// or authority record. Replay protection for an id the log forgot is the expected-revision
	// rule, which does not depend on the log: a retention kind's own commit bumped
	// AuthorityRevision past the view it carried, and every other kind needs Revision to equal
	// the view. Without this entry every hourly expiry would move AuthorityRevision and make a
	// deletion Begin holding a view older than it conflict once.
	writerExpireControlLog writer = "ExpireControlLog"
	// writerSweepExpired: the auth sweep of pending OIDC logins, elevation records and sessions
	// whose expiry is at or before the sweep instant. Every such record is already refused at
	// every use (Authenticate, the callback and elevation resolution compare the same instant
	// with the same boundary), so deleting it widens and narrows nothing. updateAsGuardedChecked
	// masks Sessions and OIDC and separately requires that nothing was added or altered and
	// that every removed record was expired; anything else bumps like an unclassified writer.
	writerSweepExpired writer = "SweepExpired"
	// writerPendingLogin: the start and the consuming first step of an OIDC login (OIDCStart,
	// OIDCCallback). A pending login record (st.OIDC, keyed by the hash of its own state) holds
	// only the nonce, PKCE verifier and cookie binding of one in-flight login; it authenticates
	// nobody (the callback still needs the provider's verified id token, the org's subject
	// mapping and an enabled user before ANY session exists, and that session is written by the
	// SessionCreate writer) and it is read by no authorization decision. Adding one (start),
	// removing one (the callback consumes it, whether or not it has expired) and the sweep of
	// expired records OIDCStart folds into its commit therefore change no access state. The
	// guard masks Sessions and OIDC and requires: no session added or altered, only expired
	// sessions removed, only pending-login records added, no resident altered, only expired
	// residents or pending-login records removed. An elevation record (key "elevation:...") is an
	// access grant, is not a pending-login record, and so keeps bumping.
	writerPendingLogin writer = "PendingLogin"
	// writerAuditAppend: a commit whose only effect is to append audit rows (the elevated_read
	// audit of ElevatedScope). The audit log is evidence, not access state: no decision reads
	// it back (ExpireControlLog already treats its rows as non-authority). The guard masks
	// Audits and requires every existing row byte for byte unchanged and none removed.
	writerAuditAppend writer = "AuditAppend"
	// writerRuleLedgerMark: the one command that marks the installation as keeping the rule books and the rule outbox in the
	// ledger (rule_ledger.go, ensureRuleLedger). It writes the key model.RuleLedgerKey of st.OIDC and nothing else; every voter
	// moves the two members out of its blob when it applies it, and the state a reader sees is the same before and after. The
	// key authenticates nobody and no access decision reads it.
	writerRuleLedgerMark writer = "RuleLedgerMark"
)

// nonAuthorityWriters is the closed allowlist of updateAs writers that leave AuthorityRevision
// alone. A writer absent from it bumps, whatever else it does.
var nonAuthorityWriters = map[writer]string{
	writerReserveAdmission:    "reservation and quota charge of an intake batch",
	writerFinalizeAdmission:   "reservation consumed marker",
	writerCancelAdmission:     "reservation cancelled marker and quota refund",
	writerReconcileAdmissions: "reservation consumed marker from the owner's durable proof",
	writerSettleAdmissions:    "consumed reservation rows replaced by a settled window digest and folded charge (no quota or access change)",
	writerReserveArtifact:     "artifact upload reservation and quota charge",
	writerPublishArtifact:     "published artifact reference intent",
	writerTransactIssues:      "issue lifecycle book commit",
	writerTransactJobs:        "job book commit",
	writerRedactNoop:          "empty transition that only moves the applied index",
	writerReplayIndex:         "replay checkpoint index entry and retention group deadline",
	writerAttestControl:       "a voter's control residue attestation record (evidence about its own files)",
	writerSessionCreate:       "a new session record for an existing user, with the one-time factor it consumed (LastTOTP raised, a recovery hash spent); no other user field and no existing session changed",
	writerArtifactLedger:      "artifact reference ledger and index entry (retention bookkeeping, not access state)",
	writerIssueHold:           "artifact reference ledger and index entry of an issue's hold on a map, decided by the workflow of the issue (retention bookkeeping, not access state)",
	writerExpireControlLog:    "expired audit rows and applied-command rows (log retention, not access state)",
	writerSweepExpired:        "expired pending login, elevation and session records (already refused everywhere)",
	writerPendingLogin:        "a pending OIDC login record added or consumed (authenticates nobody; no access state)",
	writerAuditAppend:         "appended audit rows only (evidence, never read back by an access decision)",
	writerRuleLedgerMark:      "the rule-ledger mark (D108): one OIDC key naming the revision of the move; the rule books keep their content, no access state changes",
}

// nonAuthorityKinds is the closed allowlist of Transact kinds whose commit leaves
// AuthorityRevision alone: the handlers write only their own book (rule, condition, incident,
// delivery/cutover, release/issue evidence, job, saved view) and audits of that write. A kind
// absent from the list bumps.
var nonAuthorityKinds = map[CommandKind]string{
	KindApplyIssueEvidence:  "issue evidence book",
	KindApplyCondition:      "condition book",
	KindApplyRuleEvaluation: "rule evaluation book and outputs",
	KindIncidentAction:      "incident book",
	KindClaimDelivery:       "delivery outbox and cutover books",
	KindCompleteDelivery:    "delivery outbox books",
	KindRegisterRelease:     "release registry",
	KindUpdateJob:           "job book",
	KindSavedView:           "saved view book",
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

// ledgerWriters are the writers whose transition reads or writes the admission ledger (ledger.go):
// their state carries the ledger members, assembled and written back record by record. Every other
// classified writer gets the state without them.
var ledgerWriters = map[writer]bool{
	writerReserveAdmission:    true,
	writerFinalizeAdmission:   true,
	writerCancelAdmission:     true,
	writerReconcileAdmissions: true,
	writerSettleAdmissions:    true,
	writerReserveArtifact:     true,
}

// bookFreeWriters are the writers whose transition neither reads nor writes the job and issue books: they
// get the state without them. Every other writer (the two that write them, an erasure, an administrator's
// command, an unclassified one) gets them assembled, because a transition that was not written for the
// layout may look at them, and what a transition does not name is not read back for it.
var bookFreeWriters = map[writer]bool{
	writerReserveAdmission:    true,
	writerFinalizeAdmission:   true,
	writerCancelAdmission:     true,
	writerReconcileAdmissions: true,
	writerSettleAdmissions:    true,
	writerReserveArtifact:     true,
	writerPublishArtifact:     true,
	writerRedactNoop:          true,
	writerReplayIndex:         true,
	writerAttestControl:       true,
	writerSessionCreate:       true,
	writerArtifactLedger:      true,
	writerExpireControlLog:    true,
	writerSweepExpired:        true,
	writerPendingLogin:        true,
	writerAuditAppend:         true,
	writerRuleLedgerMark:      true,
}

// commandFreeWriters are the writers whose transition neither reads nor writes the applied-command log
// (Commands, CommandOwners): the bookFreeWriters but the control log expiry, the job book writer and
// the issue hold writer. Every other writer gets the log assembled.
var commandFreeWriters = func() map[writer]bool {
	free := map[writer]bool{writerTransactJobs: true, writerIssueHold: true}
	for w := range bookFreeWriters {
		if w != writerExpireControlLog {
			free[w] = true
		}
	}
	return free
}()

// membersOfWriter is the ledger members the transition of writer w names.
func membersOfWriter(w writer) (m memberScope) {
	if ledgerWriters[w] {
		m |= scopeAdmission
	}
	if !bookFreeWriters[w] {
		m |= scopeBooks
	}
	if !commandFreeWriters[w] {
		m |= scopeCommands
	}
	return m
}

// bookFreeKinds are the Transact kinds whose handler neither reads nor writes the job and issue books or the
// grouping issues.
var bookFreeKinds = map[CommandKind]bool{
	KindApplyCondition:      true,
	KindApplyRuleEvaluation: true,
	KindIncidentAction:      true,
	KindClaimDelivery:       true,
	KindCompleteDelivery:    true,
	KindRegisterRelease:     true,
	KindSavedView:           true,
}

// membersOfKind is the ledger members the generic Transact commit of a command names: the log of applied
// commands (a command records itself in it, and a retry is answered from it) and the books unless the handler
// is book free. The delivery commands are book-free except the cutover arm of the claim kind: the barrier is
// verified against the project's issue book (the checkpoints) and its jobs.
func membersOfKind(cmd Command) memberScope {
	k := CommandKind(cmd.Kind)
	if !bookFreeKinds[k] {
		return scopeBooks | scopeCommands
	}
	if k == KindClaimDelivery {
		var head struct {
			Operation string `json:"operation"`
		}
		if json.Unmarshal(cmd.Payload, &head) != nil || head.Operation == DeliveryOpCutover {
			return scopeBooks | scopeCommands
		}
	}
	return scopeCommands
}

// updateAs is Update for a classified writer: a writer on nonAuthorityWriters leaves
// AuthorityRevision alone, any other name bumps.
func (s *Store) updateAs(ctx context.Context, w writer, fn func(*State) error) error {
	_, keep := nonAuthorityWriters[w]
	return s.update(ctx, !keep, membersOfWriter(w), fn)
}

// update is the one entry to replicatedUpdate: bump says whether the transition moves
// AuthorityRevision, members which of the ledger's members it names. Update (the exported,
// unclassified entry) always bumps and always names all of them.
func (s *Store) update(ctx context.Context, bump bool, members memberScope, fn func(*State) error) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if s.repl == nil {
		return model.Fail(model.Unavailable)
	}
	return s.replicatedUpdate(ctx, bump, nil, members, guardAttestations(fn))
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

// orgAuthority is the control Revision of the last authority-class transition that changed the
// organization alone (UpdateOrgAuthority stamps it in the organization's Settings): zero when
// none did, and the current Revision (strict) when the stored value does not parse.
func orgAuthority(st *State, org model.ID) model.Revision {
	raw, ok := st.Orgs[org.String()].Settings[model.OrgAuthorityKey]
	if !ok {
		return 0
	}
	var r model.Revision
	if model.StrictJSON(raw, &r) != nil {
		return st.Revision
	}
	return r
}

// scopedAuthority is the value of model.ScopedAuthorityKey.
type scopedAuthority struct {
	Floor  model.Revision `json:"floor"`
	Global model.Revision `json:"global"`
}

// installationFloor is the revision of the last authority change that was not a verified commit of
// one organization: AuthorityRevision itself unless the pair of model.ScopedAuthorityKey is
// current (it names AuthorityRevision as its own), in which case the floor recorded with it. Any
// doubt (no pair, an unreadable one, a commit of a binary that does not write it) is the whole
// AuthorityRevision, the fail-safe direction.
func installationFloor(st *State) model.Revision {
	global := authorityFloor(st)
	raw, ok := st.OIDC[model.ScopedAuthorityKey]
	if !ok {
		return global
	}
	var p scopedAuthority
	if model.StrictJSON(raw, &p) != nil || p.Global != st.AuthorityRevision || p.Floor > p.Global {
		return global
	}
	return p.Floor
}

// expectedRevisionOK is the whole Transact revision rule. A retention command of org needs a view
// no older than the later of the installation's authority floor and the organization's own.
func expectedRevisionOK(st *State, org model.ID, kind string, expected model.Revision) bool {
	if !retentionKinds[CommandKind(kind)] {
		return st.Revision == expected
	}
	return max(installationFloor(st), orgAuthority(st, org)) <= expected && expected <= st.Revision
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
	err := s.update(ctx, true, 0, func(st *State) error {
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
// when fn changed nothing but the Sessions map (existing sessions byte for byte as they were)
// and the one-time factor state of existing users: User.LastTOTP never lower and User.Recovery
// only losing hashes (see writerSessionCreate for the proof). Any other difference (another
// field of a user, a membership, a removed or altered session) bumps as an unclassified writer
// does.
func (s *Store) UpdateSessionCreate(ctx context.Context, fn func(*State) error) error {
	return s.updateAsGuardedChecked(ctx, writerSessionCreate, stateWithoutSessionsAndFactors, sessionsGrowFactorsConsumed, fn)
}

// UpdateSweepExpired commits fn, the removal of expired sessions and expired OIDC residents,
// without moving AuthorityRevision when fn only deleted records that were expired at now
// (sessionExpires <= now; residentExpired reports an OIDC resident as expired) and left every
// other record byte for byte as it was. Any other difference bumps as an unclassified writer
// does. A commit that removed nothing leaves AuthorityRevision alone as well.
func (s *Store) UpdateSweepExpired(ctx context.Context, now int64, residentExpired func(key string, raw json.RawMessage) bool, fn func(*State) error) error {
	return s.updateAsGuardedChecked(ctx, writerSweepExpired, stateWithoutSweepable, residentsPreserve(now, residentExpired, nil), fn)
}

// UpdatePendingLogin commits fn, the start or the consuming first step of an OIDC login, without
// moving AuthorityRevision when fn only added pending-login records (pending reports one), removed
// pending-login records or records expired at now (residentExpired, sessionExpires <= now), and
// left every other record byte for byte as it was. Any other difference bumps as an unclassified
// writer does. A nil pending adds and consumes nothing (it degrades to the sweep rule).
func (s *Store) UpdatePendingLogin(ctx context.Context, now int64, pending, residentExpired func(key string, raw json.RawMessage) bool, fn func(*State) error) error {
	return s.updateAsGuardedChecked(ctx, writerPendingLogin, stateWithoutSweepable, residentsPreserve(now, residentExpired, pending), fn)
}

// UpdateAuditAppend commits fn without moving AuthorityRevision when fn changed nothing but
// appending audit rows: every existing row byte for byte as it was, none removed. Any other
// difference bumps as an unclassified writer does. Cost: one JSON encoding of every existing
// audit row per call, besides the two state encodings every guarded writer pays.
func (s *Store) UpdateAuditAppend(ctx context.Context, fn func(*State) error) error {
	return s.updateAsGuardedChecked(ctx, writerAuditAppend, stateWithoutAudits, auditsOnlyAppended, fn)
}

// stateWithoutSweepable is the canonical encoding of st with the Sessions and OIDC maps removed.
func stateWithoutSweepable(st *State) ([]byte, error) {
	masked := *st
	masked.Sessions, masked.OIDC = nil, nil
	return json.Marshal(masked)
}

// stateWithoutAudits is the canonical encoding of st with the audit log removed.
func stateWithoutAudits(st *State) ([]byte, error) {
	masked := *st
	masked.Audits = nil
	return json.Marshal(masked)
}

// auditsOnlyAppended snapshots the audit rows before fn (each as its own encoding, so an
// in-place edit of a row cannot hide) and returns the check that all are still there unchanged.
func auditsOnlyAppended(st *State) func(*State) bool {
	before := make([][]byte, len(st.Audits))
	encoded := true
	for i, row := range st.Audits {
		raw, err := json.Marshal(row)
		if err != nil {
			encoded = false
			break
		}
		before[i] = raw
	}
	return func(after *State) bool {
		if !encoded || len(after.Audits) < len(before) {
			return false
		}
		for i, raw := range before {
			now, err := json.Marshal(after.Audits[i])
			if err != nil || !bytes.Equal(raw, now) {
				return false
			}
		}
		return true
	}
}

// residentsPreserve is the preserve check of the writers that touch the Sessions and OIDC maps
// (stateWithoutSweepable masks both). No session is added or altered and only sessions expired at
// now are removed. A resident already present is never altered. A resident may be added only if
// pending reports it, and removed only if expired reports it or pending does. A nil pending adds
// and consumes nothing.
func residentsPreserve(now int64, expired, pending func(key string, raw json.RawMessage) bool) func(*State) func(*State) bool {
	return func(st *State) func(*State) bool {
		sessions, oidc := maps.Clone(st.Sessions), maps.Clone(st.OIDC)
		return func(after *State) bool {
			for k, v := range after.Sessions {
				if before, ok := sessions[k]; !ok || before != v {
					return false
				}
			}
			for k, v := range sessions {
				if _, ok := after.Sessions[k]; !ok && v.Expires > now {
					return false
				}
			}
			for k, v := range after.OIDC {
				if before, ok := oidc[k]; ok {
					if !bytes.Equal(before, v) {
						return false
					}
				} else if pending == nil || !pending(k, v) {
					return false
				}
			}
			for k, v := range oidc {
				if _, ok := after.OIDC[k]; !ok && !expired(k, v) && (pending == nil || !pending(k, v)) {
					return false
				}
			}
			return true
		}
	}
}

// UpdateArtifactReferences commits fn, a reference-ledger write, without moving
// AuthorityRevision when fn changed nothing but ledger and ledger-index entries in organization
// Settings. The retire transition (intent state, delete generation) is outside the mask and bumps.
func (s *Store) UpdateArtifactReferences(ctx context.Context, fn func(*State) error) error {
	return s.updateAsGuarded(ctx, writerArtifactLedger, stateWithoutArtifactLedger, fn)
}

// UpdateIssueHolds is UpdateArtifactReferences for the holds of the issue producer (artifacts
// HoldIssues and SettleIssues). The same ledger mask applies, so a commit that wrote nothing but
// ledger and ledger-index entries leaves AuthorityRevision alone; what differs is the state fn is
// given: it carries the job and issue books and the grouping issues, because a hold is taken or
// released by the workflow of the issue as the transaction sees it (issueWorkflow), and a state
// without them answers "unknown issue" for every issue.
func (s *Store) UpdateIssueHolds(ctx context.Context, fn func(*State) error) error {
	return s.updateAsGuarded(ctx, writerIssueHold, stateWithoutArtifactLedger, fn)
}

// stateWithoutSessionsAndFactors is the canonical encoding of st with the Sessions map removed and
// the one-time factor state (LastTOTP, Recovery) of every user zeroed.
func stateWithoutSessionsAndFactors(st *State) ([]byte, error) {
	masked := *st
	masked.Sessions = nil
	masked.Users = make(map[string]model.ControlUser, len(st.Users))
	for k, u := range st.Users {
		u.LastTOTP, u.Recovery = 0, nil
		masked.Users[k] = u
	}
	return json.Marshal(masked)
}

// sessionsGrowFactorsConsumed snapshots the sessions and every user's factor state before fn and
// returns the check that every session is still present and unchanged, and that no user's
// LastTOTP went down or Recovery gained, reordered or replaced a hash (it may only lose some).
func sessionsGrowFactorsConsumed(st *State) func(*State) bool {
	type factors struct {
		last     int64
		recovery []string
	}
	sessions := maps.Clone(st.Sessions)
	users := make(map[string]factors, len(st.Users))
	for k, u := range st.Users {
		users[k] = factors{u.LastTOTP, slices.Clone(u.Recovery)}
	}
	return func(after *State) bool {
		for k, v := range sessions {
			if got, ok := after.Sessions[k]; !ok || got != v {
				return false
			}
		}
		for k, was := range users {
			u, ok := after.Users[k]
			if !ok || u.LastTOTP < was.last || !isSubsequence(u.Recovery, was.recovery) {
				return false
			}
		}
		return true
	}
}

// isSubsequence reports whether sub is of with some elements removed and the rest in order.
func isSubsequence(sub, of []string) bool {
	i := 0
	for _, v := range of {
		if i < len(sub) && sub[i] == v {
			i++
		}
	}
	return i == len(sub)
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
		return s.update(ctx, true, membersOfWriter(w), fn)
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
	return s.replicatedUpdate(ctx, false, &force, membersOfWriter(w), func(st *State) error {
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
