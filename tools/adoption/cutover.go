// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/model"
	"soundpost/internal/notify"
)

// Task 08.06: one-owner cutover. The ownership state machine, its barrier
// checks and the one-active-owner invariant belong to the plan 06 engine
// (internal/notify, internal/control); this file only drives it, in the
// order the adoption plan requires, around two external systems it cannot
// observe: the legacy operator and the new route's delivery observer. Both are
// interfaces; the tool contains no provider or customer call.
//
// A run is five durable phases, persisted atomically after each one:
//
//	preflight                              gate, authorization, plan, engine, deadman, destination test
//	old_route_quiescence_acknowledged      engine quiescing_old, then the legacy operator disables ITS NORMAL ROUTE
//	source_version_handover                engine barrier_verified (frontier, accounting, evidence)
//	new_route_activated                    engine new_active: the one new owner
//	delivery_reconciliation                both sides' delivery IDs against what was due
//
// A crash or a timeout between any two phases leaves the state file at the
// explicit phase "incomplete"; only a clean reconciliation writes "done". A
// resume re-derives every command ID from the run ID, asks the engine which of
// its commands already committed and repeats only what did not.

// Receipt phases (closed enum).
const (
	CutoverPhaseDone       = "done"
	CutoverPhaseIncomplete = "incomplete"
	CutoverPhaseBlocked    = "reconciliation_blocked"
)

// The durable cutover phases, in order.
const (
	cutoverStepPreflight = "preflight"
	cutoverStepQuiesce   = "old_route_quiescence_acknowledged"
	cutoverStepHandover  = "source_version_handover"
	cutoverStepActivate  = "new_route_activated"
	cutoverStepReconcile = "delivery_reconciliation"
)

var cutoverSteps = []string{cutoverStepPreflight, cutoverStepQuiesce, cutoverStepHandover, cutoverStepActivate, cutoverStepReconcile}

// Delivery outcomes an observer may report.
const (
	CutoverOutcomeDelivered = "delivered"
	CutoverOutcomeUnknown   = "unknown"
)

// Environments a plan may target.
const (
	cutoverEnvStaging    = ReadinessEnvStaging
	cutoverEnvProduction = ReadinessEnvProduction
)

// The operations an Authorization may permit (carried in its Collectors).
const (
	cutoverActionCutover  = "cutover"
	cutoverActionRollback = "rollback"
)

// Closed codes of an incomplete run: why it stopped.
const (
	CutoverIncompleteTimeout          = "timeout"
	CutoverIncompleteCancelled        = "cancelled"
	CutoverIncompleteAdapter          = "adapter_error"
	CutoverIncompleteBarrier          = "barrier_refused"
	CutoverIncompleteEngine           = "engine_conflict"
	CutoverIncompleteGuard            = "guard_refused"
	CutoverIncompleteLegacyEnabled    = "legacy_sender_enabled"
	CutoverIncompleteLegacyUnexpected = "legacy_state_unexpected"
	CutoverIncompleteDeadman          = "deadman_not_armed"
	CutoverIncompleteQuiescence       = "quiescence_not_acknowledged"
	CutoverIncompleteBothSenders      = "both_senders"
	CutoverIncompleteUnknown          = "unknown_outcomes_unreviewed"
	CutoverIncompleteDestination      = "destination_test_failed"
)

// Closed blocker codes of the delivery reconciliation.
const (
	CutoverBlockGap         = "delivery_gap"
	CutoverBlockUrgentGap   = "urgent_delivery_gap"
	CutoverBlockDuplicate   = "duplicate_delivery"
	CutoverBlockUnexpected  = "unexpected_delivery"
	CutoverBlockOldLate     = "old_sender_after_quiesce"
	CutoverBlockUncertainty = "uncertainty_exceeded"
	CutoverBlockMalformed   = "malformed_observation"
)

var cutoverBlockCodes = []string{CutoverBlockGap, CutoverBlockUrgentGap, CutoverBlockDuplicate, CutoverBlockUnexpected, CutoverBlockOldLate, CutoverBlockUncertainty, CutoverBlockMalformed}

// CutoverEngine is the part of *notify.CutoverService the tool drives.
type CutoverEngine interface {
	AdvanceCutover(ctx context.Context, scope auth.Scope, command notify.CutoverCommand) (notify.CutoverState, error)
	Cutover(ctx context.Context, scope auth.Scope) (notify.CutoverState, bool, error)
	Facts(ctx context.Context, scope auth.Scope) (notify.CutoverFacts, error)
}

var _ CutoverEngine = (*notify.CutoverService)(nil)

// CutoverLegacyCommand names one idempotent operation on the legacy NORMAL
// route of Owner. The legacy operator repeats the original result for a
// command ID it has already executed.
type CutoverLegacyCommand struct {
	ID    string
	Owner model.ID
}

// CutoverLegacyState is what the legacy operator observed about the legacy
// normal sender at ObservedAt. Ref is the digest of the audited artifact;
// CommandID echoes the command that produced the state ("" for Observe).
type CutoverLegacyState struct {
	Owner      model.ID
	Enabled    bool
	Method     string
	ObservedAt time.Time
	Ref        model.Hash
	Pending    int
	Unknown    int
	CommandID  string
}

// CutoverDelivery is one observed delivery of a logical notification.
type CutoverDelivery struct {
	ID      string
	Outcome string
	At      time.Time
}

// CutoverDue is one notification the canonical policy decided the normal owner
// must deliver; Urgent ones are the work a gap must not lose.
type CutoverDue struct {
	ID     string
	Urgent bool
}

// CutoverLegacyOperator is the legacy system's operator surface. It can only
// observe, quiesce the NORMAL route, restore the normal route and list the
// route's deliveries since the pre-cutover cursor: no method deletes, disables
// or reconfigures anything else, so no code path of this tool can retire an
// old system.
type CutoverLegacyOperator interface {
	Observe(ctx context.Context, owner model.ID) (CutoverLegacyState, error)
	QuiesceNormal(ctx context.Context, cmd CutoverLegacyCommand) (CutoverLegacyState, error)
	RestoreNormal(ctx context.Context, cmd CutoverLegacyCommand) (CutoverLegacyState, error)
	Delivered(ctx context.Context) ([]CutoverDelivery, error)
}

// CutoverNewRoute is the new route's delivery observer.
type CutoverNewRoute interface {
	// TestDelivery delivers one marked test notification to the destination.
	// It repeats the original result for a probe ID it has already delivered
	// and is never part of Due or Delivered.
	TestDelivery(ctx context.Context, probeID string) (CutoverDelivery, error)
	// Due lists what the canonical policy decided must be delivered since the
	// pre-cutover cursor, including urgent work queued while nobody was
	// sending. Delivered lists the new route's observed deliveries.
	Due(ctx context.Context) ([]CutoverDue, error)
	Delivered(ctx context.Context) ([]CutoverDelivery, error)
}

// CutoverDeadmanProof is the independent deadman's own proof that it is armed.
type CutoverDeadmanProof struct {
	Observer      model.ID
	Domain        model.ID
	ProductDomain model.ID
	Armed         bool
	ObservedAt    time.Time
	Ref           model.Hash
}

// CutoverDeadman is READ-ONLY by construction: the independent deadman is
// excluded from the ownership barrier, so the tool has no way to quiesce,
// switch or reconfigure it.
type CutoverDeadman interface {
	Proof(ctx context.Context) (CutoverDeadmanProof, error)
}

// CutoverRuntime is everything outside the plan the operations need. It travels
// in the context because the entry points have fixed signatures. GateKey is
// needed by Cutover only. PollInterval paces the rollback's wait for the new
// owner to drain (default 200ms).
type CutoverRuntime struct {
	GateKey      ed25519.PublicKey
	Now          func() time.Time
	Engine       CutoverEngine
	Scope        auth.Scope
	Legacy       CutoverLegacyOperator
	Route        CutoverNewRoute
	Deadman      CutoverDeadman
	PollInterval time.Duration
}

type cutoverRuntimeKey struct{}

// CutoverWithRuntime attaches the runtime to the context of Cutover/Rollback.
func CutoverWithRuntime(ctx context.Context, rt CutoverRuntime) context.Context {
	return context.WithValue(ctx, cutoverRuntimeKey{}, rt)
}

func cutoverRuntimeFrom(ctx context.Context, needGate bool) (CutoverRuntime, error) {
	rt, _ := ctx.Value(cutoverRuntimeKey{}).(CutoverRuntime)
	if rt.Now == nil || rt.Engine == nil || rt.Legacy == nil || rt.Route == nil || rt.Deadman == nil || needGate && len(rt.GateKey) != ed25519.PublicKeySize {
		return CutoverRuntime{}, errors.New("cutover runtime is incomplete")
	}
	if rt.PollInterval <= 0 {
		rt.PollInterval = 200 * time.Millisecond
	}
	return rt, nil
}

// CutoverQuiescenceProof is the proof the plan demands that the old normal route
// is quiesced: the closed method code the legacy operator must attest.
type CutoverQuiescenceProof struct {
	Method string `json:"method"`
}

// CutoverDestinationTest is the test delivery the new route must complete
// before the old route is touched.
type CutoverDestinationTest struct {
	Destination string `json:"destination"`
	ProbeID     string `json:"probe_id"`
}

// CutoverDeadmanExclusion identifies the independent deadman and the failure
// domains asserted for it and for the product. It is observed, never an owner.
type CutoverDeadmanExclusion struct {
	Observer      model.ID `json:"observer"`
	Domain        model.ID `json:"domain"`
	ProductDomain model.ID `json:"product_domain"`
}

// OwnershipPlan is the private, operator-authored plan of one cutover run. It
// is immutable for the run: a resume with any different field is refused.
type OwnershipPlan struct {
	RunID       string `json:"run_id"`
	Scope       string `json:"scope"`
	Environment string `json:"environment"`
	StatePath   string `json:"state_path"`

	Project  model.ID `json:"project"`
	OldOwner model.ID `json:"old_owner"`
	NewOwner model.ID `json:"new_owner"`

	// PolicyGeneration is the canonical-owner epoch the new owner will run
	// under: the engine's epoch plus one.
	PolicyGeneration uint64 `json:"policy_generation"`
	// Frontier is the pre-cutover source version and journal cursor the old
	// owner had processed through.
	Frontier      []notify.FrontierEntry  `json:"frontier"`
	OldQuiescence CutoverQuiescenceProof  `json:"old_quiescence"`
	Destination   CutoverDestinationTest  `json:"destination_test"`
	Deadman       CutoverDeadmanExclusion `json:"deadman"`

	RollbackRunbookRef string `json:"rollback_runbook_ref"`
	// UnknownReviewed attests that the unknown provider outcomes on either
	// side were reviewed.
	UnknownReviewed bool `json:"unknown_reviewed"`
	// ProviderUncertainty is the declared number of notifications whose
	// provider outcome may stay unknown.
	ProviderUncertainty int `json:"provider_uncertainty"`
}

// CutoverBlocker is one closed-code blocker with its count.
type CutoverBlocker struct {
	Code  string `json:"code"`
	Count int    `json:"count"`
}

// CutoverReconciliation is the comparison of the delivery IDs observed on both
// sides with the notifications that were due.
type CutoverReconciliation struct {
	Due        int      `json:"due"`
	Delivered  int      `json:"delivered"`
	Gaps       int      `json:"gaps"`
	UrgentDue  int      `json:"urgent_due"`
	UrgentGaps int      `json:"urgent_gaps"`
	Duplicates int      `json:"duplicates"`
	Uncertain  int      `json:"uncertain"`
	Unexpected int      `json:"unexpected"`
	OldLate    int      `json:"old_after_quiesce"`
	Malformed  int      `json:"malformed"`
	GapIDs     []string `json:"gap_ids,omitempty"`
}

// CutoverReceipt is the private outcome of a Cutover call.
type CutoverReceipt struct {
	Version        int                   `json:"version"`
	RunID          string                `json:"run_id"`
	Scope          string                `json:"scope"`
	Environment    string                `json:"environment"`
	PlanDigest     string                `json:"plan_digest"`
	StatePath      string                `json:"state_path"`
	StateVersion   uint64                `json:"state_version"`
	Phase          string                `json:"phase"`
	Completed      []string              `json:"completed"`
	IncompleteCode string                `json:"incomplete_code,omitempty"`
	EnginePhase    string                `json:"engine_phase,omitempty"`
	EngineRevision model.Revision        `json:"engine_revision,omitempty"`
	Epoch          uint64                `json:"epoch,omitempty"`
	ActiveOwners   []model.ID            `json:"active_owners"`
	Reconciliation CutoverReconciliation `json:"reconciliation"`
	Blockers       []CutoverBlocker      `json:"blockers"`
}

// Reason is the explicit operator reason of a rollback.
type Reason struct {
	// Code is the closed class of the reason; Text (1 to 512 printable
	// bytes) is private operator text carried to the engine's audit trail.
	Code string `json:"code"`
	Text string `json:"text"`
	// UnknownReviewed attests that the unknown provider outcomes recorded in
	// the rollback receipt were reviewed; the old owner is not restored
	// while unreviewed unknown outcomes exist.
	UnknownReviewed bool `json:"unknown_reviewed"`
}

// RollbackUnknown records the provider outcomes that stay unresolved.
type RollbackUnknown struct {
	Engine   uint32   `json:"engine"`
	RouteIDs []string `json:"route_ids,omitempty"`
	Reviewed bool     `json:"reviewed"`
}

// RollbackReceipt is the private outcome of a Rollback call.
type RollbackReceipt struct {
	Version         int              `json:"version"`
	RunID           string           `json:"run_id"`
	Scope           string           `json:"scope"`
	PlanDigest      string           `json:"plan_digest"`
	StatePath       string           `json:"state_path"`
	StateVersion    uint64           `json:"state_version"`
	Phase           string           `json:"phase"`
	Completed       []string         `json:"completed"`
	IncompleteCode  string           `json:"incomplete_code,omitempty"`
	ReasonCode      string           `json:"reason_code"`
	EnginePhase     string           `json:"engine_phase,omitempty"`
	EngineRevision  model.Revision   `json:"engine_revision,omitempty"`
	ActiveOwners    []model.ID       `json:"active_owners"`
	OldRouteEnabled bool             `json:"old_route_enabled"`
	DeadmanArmed    bool             `json:"deadman_armed"`
	Unknown         RollbackUnknown  `json:"unknown"`
	Blockers        []CutoverBlocker `json:"blockers"`
}

// ---------------------------------------------------------------- errors

// cutoverStop is a stop with a closed code. Its text carries only the code and
// a tool-authored detail, never adapter text; the cause stays reachable with
// errors.Is/As.
type cutoverStop struct {
	code   string
	detail string
	err    error
}

func (s *cutoverStop) Error() string {
	if s.detail == "" {
		return s.code
	}
	return s.code + ": " + s.detail
}

func (s *cutoverStop) Unwrap() error { return s.err }

func cutoverStopErr(code, detail string, cause error) error {
	return &cutoverStop{code: code, detail: detail, err: cause}
}

// cutoverClassify maps an adapter or engine error to a closed code.
func cutoverClassify(err error) string {
	var stop *cutoverStop
	var barrier *notify.BarrierError
	var fault *model.Fault
	switch {
	case errors.As(err, &stop):
		return stop.code
	case errors.Is(err, context.DeadlineExceeded):
		return CutoverIncompleteTimeout
	case errors.Is(err, context.Canceled):
		return CutoverIncompleteCancelled
	case errors.As(err, &barrier):
		return CutoverIncompleteBarrier
	case errors.As(err, &fault) && fault.Code == model.Conflict:
		return CutoverIncompleteEngine
	}
	return CutoverIncompleteAdapter
}

// cutoverFail turns any error into a coded stop, keeping an existing code.
func cutoverFail(err error) error {
	var stop *cutoverStop
	if errors.As(err, &stop) {
		return err
	}
	detail := ""
	var barrier *notify.BarrierError
	if errors.As(err, &barrier) {
		detail = "checks=" + strings.Join(barrier.Checks, ",")
	}
	return &cutoverStop{code: cutoverClassify(err), detail: detail, err: err}
}

// ------------------------------------------------------------ validation

var (
	cutoverRunIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	// cutoverCodePattern is the engine's closed-code shape (lowercase letters,
	// digits and _ . : -, at most 64): the engine refuses a method outside it,
	// but only at the barrier, after the old route is quiesced.
	cutoverCodePattern = regexp.MustCompile(`^[a-z0-9_.:-]{1,64}$`)
)

// cutoverToken is a printable, space-free identifier of at most max bytes.
func cutoverToken(s string, max int) bool {
	if s == "" || len(s) > max {
		return false
	}
	for i := range len(s) {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

func cutoverValidatePlan(plan OwnershipPlan, gate ReadyGate, rt CutoverRuntime) error {
	bad := func(what string) error { return errors.New("invalid ownership plan: " + what) }
	switch {
	case !cutoverRunIDPattern.MatchString(plan.RunID):
		return bad("run id")
	case plan.Scope == "" || plan.Scope != gate.Scope:
		return bad("scope differs from the ready gate")
	case plan.Environment != cutoverEnvStaging && plan.Environment != cutoverEnvProduction:
		return bad("environment")
	case plan.Environment == cutoverEnvProduction && !gate.ProductionProven:
		return bad("a production cutover needs a production-proven gate")
	case plan.StatePath == "" || !filepath.IsAbs(plan.StatePath):
		return bad("state path must be absolute")
	case plan.Project == (model.ID{}) || plan.OldOwner == (model.ID{}) || plan.NewOwner == (model.ID{}) || plan.OldOwner == plan.NewOwner:
		return bad("project and two distinct owners are required")
	case plan.PolicyGeneration == 0:
		return bad("policy generation")
	case len(plan.Frontier) == 0:
		return bad("source frontier")
	case !cutoverCodePattern.MatchString(plan.OldQuiescence.Method):
		return bad("quiescence method")
	case !cutoverToken(plan.Destination.Destination, 128) || !cutoverToken(plan.Destination.ProbeID, 128):
		return bad("destination test")
	case !cutoverToken(plan.RollbackRunbookRef, 256):
		return bad("rollback runbook reference")
	case plan.ProviderUncertainty < 0:
		return bad("provider uncertainty")
	case plan.Deadman.Observer == (model.ID{}) || plan.Deadman.Domain == (model.ID{}) || plan.Deadman.ProductDomain == (model.ID{}):
		return bad("deadman identity and failure domains are required")
	case plan.Deadman.Domain == plan.Deadman.ProductDomain:
		return bad("the deadman must not share the product's failure domain")
	case plan.Deadman.Observer == plan.OldOwner || plan.Deadman.Observer == plan.NewOwner:
		return bad("the deadman is excluded from ownership and cannot be an owner")
	}
	if projects := rt.Scope.ProjectIDs(); len(projects) != 1 || projects[0] != plan.Project {
		return bad("project differs from the engine scope")
	}
	return nil
}

// cutoverAuthorize requires an explicit, current, non-read-only grant whose
// single scope names exactly this run's scope and permits action. The grant is
// an operator assertion, not cryptographic identity.
func cutoverAuthorize(grant Authorization, scope, action string, now time.Time) error {
	fail := errors.New("authorization validation failed")
	if grant.ReadOnly || !nonempty(grant.GrantID, grant.Authority) || now.Before(grant.NotBefore) || !now.Before(grant.ExpiresAt) ||
		grant.MaxEvidenceAgeSeconds <= 0 || grant.MaxEvidenceAgeSeconds > 86400 || grant.ExpiresAt.Sub(grant.NotBefore) > time.Duration(control.CutoverMaxAuthorization) {
		return fail
	}
	matches := 0
	for _, s := range grant.Scopes {
		if s.ID != scope {
			continue
		}
		seen := map[string]bool{}
		for _, c := range s.Collectors {
			if c != cutoverActionCutover && c != cutoverActionRollback || seen[c] {
				return fail
			}
			seen[c] = true
		}
		if !seen[action] {
			return fail
		}
		matches++
	}
	if matches != 1 {
		return fail
	}
	return nil
}

func cutoverPlanDigest(plan OwnershipPlan) (string, error) {
	b, err := json.Marshal(plan)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}

func cutoverCommandSet(runID string) map[string]string {
	out := map[string]string{}
	for _, name := range []string{cutoverCmdShadow, cutoverCmdQuiesce, cutoverCmdHandover, cutoverCmdActivate, cutoverCmdLegacyQ, cutoverCmdLegacyR, cutoverCmdRbQuiesce, cutoverCmdRbRecord, cutoverCmdRbAbort} {
		out[name] = cutoverCommandID(runID, name).String()
	}
	return out
}

// ----------------------------------------------------------------- state

// cutoverStateSchema versions the operator-private state file.
const cutoverStateSchema = 1

// Command names; every engine command and legacy command ID of a run derives
// from the run ID and the name, so a resume repeats the same IDs.
const (
	cutoverCmdShadow   = "shadow"
	cutoverCmdQuiesce  = "quiesce"
	cutoverCmdHandover = "handover"
	cutoverCmdActivate = "activate"
	cutoverCmdLegacyQ  = "legacy-quiesce"
	cutoverCmdLegacyR  = "legacy-restore"

	cutoverCmdRbQuiesce = "rollback-quiesce"
	cutoverCmdRbRecord  = "rollback-record"
	cutoverCmdRbAbort   = "rollback-abort"
)

func cutoverCommandID(runID, name string) model.ID {
	h := sha256.Sum256([]byte("soundpost/adoption/cutover/command/v1\x00" + runID + "\x00" + name))
	var id model.ID
	copy(id[:], h[:])
	return id
}

// cutoverQuiescenceRecord is what the legacy operator attested.
type cutoverQuiescenceRecord struct {
	Method     string    `json:"method"`
	ObservedAt time.Time `json:"observed_at"`
	Ref        string    `json:"ref"`
}

// cutoverState is the operator-private durable record of one run. Version is
// monotonic: every persisted change increments it by exactly one.
type cutoverState struct {
	Schema         int                      `json:"schema"`
	Version        uint64                   `json:"version"`
	Plan           OwnershipPlan            `json:"plan"`
	PlanDigest     string                   `json:"plan_digest"`
	Commands       map[string]string        `json:"commands"`
	Phase          string                   `json:"phase"`
	Completed      []string                 `json:"completed"`
	IncompleteCode string                   `json:"incomplete_code,omitempty"`
	Cutover        *model.ID                `json:"cutover,omitempty"`
	TestDelivery   string                   `json:"test_delivery,omitempty"`
	Quiescence     *cutoverQuiescenceRecord `json:"quiescence,omitempty"`
	Reconciliation *CutoverReconciliation   `json:"reconciliation,omitempty"`
	Blockers       []CutoverBlocker         `json:"blockers,omitempty"`
	Rollback       *rollbackState           `json:"rollback,omitempty"`
	Checksum       string                   `json:"checksum"`
}

func cutoverStateChecksum(st cutoverState) string {
	st.Checksum = ""
	b, _ := json.Marshal(st)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// cutoverLoadState reads the state file; (nil, nil) when there is none.
func cutoverLoadState(path string) (*cutoverState, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, errors.New("cutover state unreadable")
	}
	defer f.Close()
	var st cutoverState
	if decodeStrict(f, &st) != nil || st.Schema != cutoverStateSchema || st.Checksum != cutoverStateChecksum(st) {
		return nil, errors.New("cutover state corrupt")
	}
	return &st, nil
}

// cutoverSaveState persists st atomically (temp file, fsync, rename) with a
// compare-and-swap on the monotonic version: the file on disk must still be the
// version st was loaded at, otherwise another writer moved it. The swap detects
// a concurrent writer; it does not exclude one, so one run must have one
// process.
func cutoverSaveState(st *cutoverState) error {
	path := st.Plan.StatePath
	cur, err := cutoverLoadState(path)
	if err != nil {
		return err
	}
	var onDisk uint64
	if cur != nil {
		onDisk = cur.Version
	}
	if onDisk != st.Version {
		return errors.New("cutover state moved under this process")
	}
	next := *st
	next.Version++
	next.Checksum = cutoverStateChecksum(next)
	b, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return err
	}
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return err
	}
	tmp := path + ".tmp-" + hex.EncodeToString(suffix[:])
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		if !ok {
			os.Remove(tmp)
		}
	}()
	if _, err = f.Write(append(b, '\n')); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(tmp, path); err != nil {
		return err
	}
	ok = true
	if dir, derr := os.Open(filepath.Dir(path)); derr == nil {
		dir.Sync() // best effort: not every platform can sync a directory
		dir.Close()
	}
	*st = next
	return nil
}

// cutoverResumeCheck refuses to continue a run whose recorded plan or command
// IDs are not exactly the supplied plan's.
func cutoverResumeCheck(st *cutoverState, plan OwnershipPlan, digest string) error {
	recorded, err := cutoverPlanDigest(st.Plan)
	if err != nil || recorded != st.PlanDigest || st.PlanDigest != digest {
		return errors.New("resume refused: the state file belongs to another run or plan")
	}
	want := cutoverCommandSet(plan.RunID)
	if len(st.Commands) != len(want) {
		return errors.New("resume refused: the recorded command IDs differ from the run's")
	}
	for name, id := range want {
		if st.Commands[name] != id {
			return errors.New("resume refused: the recorded command IDs differ from the run's")
		}
	}
	return nil
}

// ---------------------------------------------------------------- invariant

// cutoverSenderViolation is the one-sender invariant. The engine's own
// ActiveOwners decide whether the product lets the new owner send in a phase
// (the engine never reports more than one owner); the old owner sends when the
// legacy operator observes its normal route enabled. The independent deadman is
// not a candidate: it is never an owner.
func cutoverSenderViolation(phase notify.CutoverPhase, old, nw model.ID, legacyEnabled bool) error {
	owners := notify.ActiveOwners(phase, old, nw)
	if slices.Contains(owners, nw) && legacyEnabled {
		return cutoverStopErr(CutoverIncompleteBothSenders, "the new owner and the old normal route are both enabled", nil)
	}
	return nil
}

func cutoverTime(n model.UnixNano) time.Time { return time.Unix(0, int64(n)).UTC() }
func cutoverNano(t time.Time) model.UnixNano { return model.UnixNano(t.UnixNano()) }

func cutoverFresh(observed, now time.Time, maxAge time.Duration) bool {
	return !observed.After(now) && now.Sub(observed) <= maxAge
}

func cutoverCommitted(es notify.CutoverState, id model.ID) bool {
	return slices.ContainsFunc(es.Timeline, func(e notify.CutoverEntry) bool { return e.Command == id })
}

// --------------------------------------------------------------- the driver

type cutoverDriver struct {
	rt      CutoverRuntime
	gate    ReadyGate
	plan    OwnershipPlan
	grant   Authorization
	st      *cutoverState
	authRef model.Hash
	// reason overrides the engine commands' default reason (a rollback's
	// explicit operator reason).
	reason string
}

// maxAge bounds how old an operator-supplied observation may be: the grant's
// bound, never beyond the engine's own limit.
func (d *cutoverDriver) maxAge(limit model.UnixNano) time.Duration {
	return min(time.Duration(d.grant.MaxEvidenceAgeSeconds)*time.Second, time.Duration(limit))
}

// guard re-verifies, at the caller's clock, the records that gate action.
func (d *cutoverDriver) guard() error {
	now := d.rt.Now()
	if err := VerifyReadyGate(d.gate, d.rt.GateKey, now); err != nil {
		return cutoverStopErr(CutoverIncompleteGuard, "ready gate", err)
	}
	if err := cutoverAuthorize(d.grant, d.plan.Scope, cutoverActionCutover, now); err != nil {
		return cutoverStopErr(CutoverIncompleteGuard, "authorization", err)
	}
	return nil
}

func (d *cutoverDriver) engineState(ctx context.Context) (notify.CutoverState, bool, error) {
	es, found, err := d.rt.Engine.Cutover(ctx, d.rt.Scope)
	if err != nil {
		return es, found, cutoverFail(err)
	}
	return es, found, nil
}

// deadmanProof reads the independent deadman's proof, which must be fresh, armed
// and exactly the deadman the plan excludes from the barrier.
func (d *cutoverDriver) deadmanProof(ctx context.Context) (CutoverDeadmanProof, error) {
	p, err := d.rt.Deadman.Proof(ctx)
	if err != nil {
		return p, cutoverFail(err)
	}
	if p.Observer != d.plan.Deadman.Observer || p.Domain != d.plan.Deadman.Domain || p.ProductDomain != d.plan.Deadman.ProductDomain || p.Ref == (model.Hash{}) {
		return p, cutoverStopErr(CutoverIncompleteDeadman, "the proof is not from the excluded deadman", nil)
	}
	if !p.Armed || !cutoverFresh(p.ObservedAt, d.rt.Now(), d.maxAge(control.CutoverMaxObserverAge)) {
		return p, cutoverStopErr(CutoverIncompleteDeadman, "the deadman is not armed or its proof is stale", nil)
	}
	return p, nil
}

// legacyState validates the identity and freshness of a legacy observation: it
// is about the old owner's normal route, repeats the command it answers, names
// the plan's method, is fresh and, when notBefore is set, was observed after the
// quiescing began. A disabled route must report nothing pending and no
// unreviewed unknown deliveries. Whether the route should be enabled is the
// caller's question.
func (d *cutoverDriver) legacyState(s CutoverLegacyState, wantCommand string, notBefore time.Time) error {
	if s.Owner != d.plan.OldOwner || s.CommandID != wantCommand || s.Ref == (model.Hash{}) || s.Method != d.plan.OldQuiescence.Method {
		return cutoverStopErr(CutoverIncompleteLegacyUnexpected, "the observation is not about the old owner's route", nil)
	}
	if !cutoverFresh(s.ObservedAt, d.rt.Now(), d.maxAge(control.CutoverMaxEvidenceAge)) || s.ObservedAt.Before(notBefore) {
		return cutoverStopErr(CutoverIncompleteQuiescence, "the observation is stale or predates the quiescing", nil)
	}
	if !s.Enabled && (s.Pending != 0 || s.Unknown != 0 && !d.plan.UnknownReviewed) {
		return cutoverStopErr(CutoverIncompleteQuiescence, "the old route reports pending or unreviewed unknown deliveries", nil)
	}
	return nil
}

// preflightChecks are read-only except for the idempotent destination test
// delivery. Nothing about the engine or the old route changes here.
func (d *cutoverDriver) preflightChecks(ctx context.Context) error {
	es, found, err := d.engineState(ctx)
	if err != nil {
		return err
	}
	epoch := uint64(0)
	if found {
		if es.OldOwner != d.plan.OldOwner || es.NewOwner != d.plan.NewOwner {
			return cutoverStopErr(CutoverIncompleteEngine, "the engine's owners differ from the plan", nil)
		}
		if es.Phase != notify.CutoverShadow && es.Phase != notify.CutoverOldActive {
			return cutoverStopErr(CutoverIncompleteEngine, "the engine cutover is at "+string(es.Phase)+", not at a start", nil)
		}
		epoch = es.Epoch
	}
	if d.plan.PolicyGeneration != epoch+1 {
		return cutoverStopErr(CutoverIncompleteEngine, "the plan's policy generation does not follow the engine's epoch", nil)
	}
	facts, err := d.rt.Engine.Facts(ctx, d.rt.Scope)
	if err != nil {
		return cutoverFail(err)
	}
	if facts.Restore != nil {
		return cutoverStopErr(CutoverIncompleteEngine, "a disaster restore awaits acknowledgement", nil)
	}
	for _, f := range d.plan.Frontier {
		reached := slices.ContainsFunc(facts.Checkpoints, func(c model.Cursor) bool { return c.Group == f.Cursor.Group && c.Index >= f.Cursor.Index })
		if !reached {
			return cutoverStopErr(CutoverIncompleteBarrier, "a source checkpoint is behind the frontier", nil)
		}
	}
	ls, err := d.rt.Legacy.Observe(ctx, d.plan.OldOwner)
	if err != nil {
		return cutoverFail(err)
	}
	if err = d.legacyState(ls, "", time.Time{}); err != nil {
		return err
	}
	if !ls.Enabled {
		return cutoverStopErr(CutoverIncompleteLegacyUnexpected, "the old normal route is not enabled", nil)
	}
	if _, err = d.deadmanProof(ctx); err != nil {
		return err
	}
	probe, err := d.rt.Route.TestDelivery(ctx, d.plan.Destination.ProbeID)
	if err != nil {
		return cutoverStopErr(cutoverDestinationCode(err), "the destination test delivery did not complete", err)
	}
	if probe.ID != d.plan.Destination.ProbeID || probe.Outcome != CutoverOutcomeDelivered {
		return cutoverStopErr(CutoverIncompleteDestination, "the destination test delivery was not confirmed", nil)
	}
	d.st.TestDelivery = probe.ID
	return nil
}

func cutoverDestinationCode(err error) string {
	if code := cutoverClassify(err); code != CutoverIncompleteAdapter {
		return code
	}
	return CutoverIncompleteDestination
}

// command builds one engine command of the run. Its ID derives from the run ID.
func (d *cutoverDriver) command(name string, phase notify.CutoverPhase, es notify.CutoverState, evidence *notify.BarrierEvidence) notify.CutoverCommand {
	reason := d.reason
	if reason == "" {
		reason = "adoption cutover " + string(phase) + " run " + d.plan.RunID
	}
	return notify.CutoverCommand{ID: cutoverCommandID(d.plan.RunID, name), ExpectedRevision: es.Revision, Frontier: d.plan.Frontier, OldOwner: d.plan.OldOwner, NewOwner: d.plan.NewOwner,
		Phase: phase, Reason: reason, Evidence: evidence}
}

// advance commits one engine command unless the engine already committed it (a
// resume after a lost response or a crash). The command is only ever built
// when it did not commit, so its evidence is fresh.
func (d *cutoverDriver) advance(ctx context.Context, name string, phase notify.CutoverPhase, build func(es notify.CutoverState) (*notify.BarrierEvidence, error)) (notify.CutoverState, error) {
	es, found, err := d.engineState(ctx)
	if err != nil {
		return es, err
	}
	if found && cutoverCommitted(es, cutoverCommandID(d.plan.RunID, name)) {
		return es, nil
	}
	var evidence *notify.BarrierEvidence
	if build != nil {
		if evidence, err = build(es); err != nil {
			return es, err
		}
	}
	next, err := d.rt.Engine.AdvanceCutover(ctx, d.rt.Scope, d.command(name, phase, es, evidence))
	if err != nil {
		return es, cutoverFail(err)
	}
	if next.Cutover != (model.ID{}) {
		cut := next.Cutover
		d.st.Cutover = &cut
	}
	return next, nil
}

// evidence is the barrier evidence of one forward transition: accounting equal
// to the product's own committed facts, the explicit authorization, the rollback
// route and the independent deadman as the observer.
func (d *cutoverDriver) evidence(es notify.CutoverState, facts notify.CutoverFacts, owner *CutoverLegacyState, proof CutoverDeadmanProof) *notify.BarrierEvidence {
	ev := &notify.BarrierEvidence{
		Cutover: es.Cutover, ForRevision: es.Revision, ManifestDigest: notify.ManifestDigest(d.plan.Frontier),
		Accounting:    notify.BarrierAccounting{Pending: facts.Pending, Claimed: facts.Claimed, Unknown: facts.Unknown, UnknownDigest: facts.UnknownDigest, Reviewed: d.plan.UnknownReviewed},
		Authorization: &notify.Authorization{Principal: d.rt.Scope.PrincipalID(), Ref: d.authRef, AuthorizedAt: cutoverNano(d.grant.NotBefore), ExpiresAt: cutoverNano(d.grant.ExpiresAt)},
		Route:         &notify.RollbackRoute{Owner: d.plan.OldOwner, Ref: model.Hash(sha256.Sum256([]byte(d.plan.RollbackRunbookRef)))},
		Observer:      &notify.ObserverProof{Observer: proof.Observer, Domain: proof.Domain, ProductDomain: proof.ProductDomain, ObservedAt: cutoverNano(proof.ObservedAt), Ref: proof.Ref},
	}
	if owner != nil {
		ev.Owner = &notify.OwnerEvidence{Owner: owner.Owner, Method: owner.Method, ObservedAt: cutoverNano(owner.ObservedAt), Ref: owner.Ref,
			Pending: uint32(owner.Pending), Unknown: uint32(owner.Unknown), UnknownReviewed: d.plan.UnknownReviewed}
	}
	return ev
}

// quiesceStart is when the engine entered quiescing_old: nothing the legacy
// operator attests may predate it.
func cutoverQuiesceStart(es notify.CutoverState) time.Time { return cutoverTime(es.EnteredAt) }

func (d *cutoverDriver) quiesce(ctx context.Context) error {
	es, found, err := d.engineState(ctx)
	if err != nil {
		return err
	}
	if !found {
		if es, err = d.advance(ctx, cutoverCmdShadow, notify.CutoverShadow, nil); err != nil {
			return err
		}
	}
	switch es.Phase {
	case notify.CutoverShadow, notify.CutoverOldActive:
		if es, err = d.advance(ctx, cutoverCmdQuiesce, notify.CutoverQuiescingOld, nil); err != nil {
			return err
		}
	case notify.CutoverQuiescingOld:
		// only this run's own command may have put the engine here
		if !cutoverCommitted(es, cutoverCommandID(d.plan.RunID, cutoverCmdQuiesce)) {
			return cutoverStopErr(CutoverIncompleteEngine, "the engine entered quiescing_old by another command", nil)
		}
	default:
		return cutoverStopErr(CutoverIncompleteEngine, "the engine cutover is at "+string(es.Phase), nil)
	}
	if es.Phase != notify.CutoverQuiescingOld {
		return cutoverStopErr(CutoverIncompleteEngine, "the engine is not quiescing the old owner", nil)
	}
	id := cutoverCommandID(d.plan.RunID, cutoverCmdLegacyQ).String()
	ack, err := d.rt.Legacy.QuiesceNormal(ctx, CutoverLegacyCommand{ID: id, Owner: d.plan.OldOwner})
	if err != nil {
		return cutoverFail(err)
	}
	if err = d.legacyState(ack, id, cutoverQuiesceStart(es)); err != nil {
		return err
	}
	if ack.Enabled {
		return cutoverStopErr(CutoverIncompleteQuiescence, "the legacy operator did not disable the normal route", nil)
	}
	if _, err = d.deadmanProof(ctx); err != nil {
		return err
	}
	d.st.Quiescence = &cutoverQuiescenceRecord{Method: ack.Method, ObservedAt: ack.ObservedAt, Ref: ack.Ref.String()}
	return nil
}

func (d *cutoverDriver) handover(ctx context.Context) error {
	next, err := d.advance(ctx, cutoverCmdHandover, notify.CutoverBarrierVerified, func(es notify.CutoverState) (*notify.BarrierEvidence, error) {
		if es.Phase != notify.CutoverQuiescingOld {
			return nil, cutoverStopErr(CutoverIncompleteEngine, "the engine is at "+string(es.Phase)+", not quiescing the old owner", nil)
		}
		obs, err := d.rt.Legacy.Observe(ctx, d.plan.OldOwner)
		if err != nil {
			return nil, cutoverFail(err)
		}
		if err = d.legacyState(obs, "", cutoverQuiesceStart(es)); err != nil {
			return nil, err
		}
		if obs.Enabled {
			return nil, cutoverStopErr(CutoverIncompleteLegacyEnabled, "the old normal route is enabled", nil)
		}
		proof, err := d.deadmanProof(ctx)
		if err != nil {
			return nil, err
		}
		facts, err := d.rt.Engine.Facts(ctx, d.rt.Scope)
		if err != nil {
			return nil, cutoverFail(err)
		}
		return d.evidence(es, facts, &obs, proof), nil
	})
	if err != nil {
		return err
	}
	if next.Phase != notify.CutoverBarrierVerified && next.Phase != notify.CutoverNewActive {
		return cutoverStopErr(CutoverIncompleteEngine, "the barrier was not recorded", nil)
	}
	return nil
}

func (d *cutoverDriver) activate(ctx context.Context) error {
	next, err := d.advance(ctx, cutoverCmdActivate, notify.CutoverNewActive, func(es notify.CutoverState) (*notify.BarrierEvidence, error) {
		if es.Phase != notify.CutoverBarrierVerified {
			return nil, cutoverStopErr(CutoverIncompleteEngine, "the engine is at "+string(es.Phase)+", not at the verified barrier", nil)
		}
		obs, err := d.rt.Legacy.Observe(ctx, d.plan.OldOwner)
		if err != nil {
			return nil, cutoverFail(err)
		}
		if err = d.legacyState(obs, "", cutoverQuiesceStart(es)); err != nil {
			return nil, err
		}
		// Activating is the one step that can create a second sender: refuse it
		// unless the engine's own owner semantics allow the new owner next to
		// the old route as observed right now.
		if err = cutoverSenderViolation(notify.CutoverNewActive, d.plan.OldOwner, d.plan.NewOwner, obs.Enabled); err != nil {
			return nil, err
		}
		proof, err := d.deadmanProof(ctx)
		if err != nil {
			return nil, err
		}
		facts, err := d.rt.Engine.Facts(ctx, d.rt.Scope)
		if err != nil {
			return nil, cutoverFail(err)
		}
		return d.evidence(es, facts, &obs, proof), nil
	})
	if err != nil {
		return err
	}
	owners := notify.ActiveOwners(next.Phase, d.plan.OldOwner, d.plan.NewOwner)
	if !slices.Equal(owners, []model.ID{d.plan.NewOwner}) || !slices.Equal(next.ActiveOwners, owners) || next.Epoch != d.plan.PolicyGeneration {
		return cutoverStopErr(CutoverIncompleteEngine, "the engine does not report the new owner as the one active owner of the planned generation", nil)
	}
	// The old route must still be disabled now that the new owner sends.
	obs, err := d.rt.Legacy.Observe(ctx, d.plan.OldOwner)
	if err != nil {
		return cutoverFail(err)
	}
	return cutoverSenderViolation(next.Phase, d.plan.OldOwner, d.plan.NewOwner, obs.Enabled)
}

func (d *cutoverDriver) reconcile(ctx context.Context) error {
	due, err := d.rt.Route.Due(ctx)
	if err != nil {
		return cutoverFail(err)
	}
	newSide, err := d.rt.Route.Delivered(ctx)
	if err != nil {
		return cutoverFail(err)
	}
	oldSide, err := d.rt.Legacy.Delivered(ctx)
	if err != nil {
		return cutoverFail(err)
	}
	var quiescedAt time.Time
	if d.st.Quiescence != nil {
		quiescedAt = d.st.Quiescence.ObservedAt
	}
	rec, blockers := cutoverReconcile(due, oldSide, newSide, d.plan.ProviderUncertainty, quiescedAt)
	d.st.Reconciliation, d.st.Blockers = &rec, blockers
	if _, err = d.deadmanProof(ctx); err != nil {
		return err
	}
	return nil
}

// cutoverReconcile compares the delivery IDs observed on both sides with what
// was due. A notification delivered once is fine; delivered twice (on either or
// both sides) is a duplicate; delivered never is a gap; a notification whose
// only observations have an unknown provider outcome is provider uncertainty,
// accepted only up to the declared count. A delivery nobody decided, and an old
// delivery after the old route was acknowledged quiesced, are blockers too.
func cutoverReconcile(due []CutoverDue, oldSide, newSide []CutoverDelivery, declared int, quiescedAt time.Time) (CutoverReconciliation, []CutoverBlocker) {
	var rec CutoverReconciliation
	dueSet := map[string]bool{}
	urgent := map[string]bool{}
	for _, item := range due {
		if !cutoverToken(item.ID, 256) || dueSet[item.ID] {
			rec.Malformed++
			continue
		}
		dueSet[item.ID] = true
		urgent[item.ID] = item.Urgent
		rec.Due++
		if item.Urgent {
			rec.UrgentDue++
		}
	}
	confirmed, unknown := map[string]int{}, map[string]int{}
	for _, side := range [][]CutoverDelivery{oldSide, newSide} {
		for _, d := range side {
			switch {
			case !cutoverToken(d.ID, 256):
				rec.Malformed++
			case d.Outcome == CutoverOutcomeDelivered:
				confirmed[d.ID]++
			case d.Outcome == CutoverOutcomeUnknown:
				unknown[d.ID]++
			default:
				rec.Malformed++
			}
		}
	}
	for _, d := range oldSide {
		if !quiescedAt.IsZero() && d.At.After(quiescedAt) {
			rec.OldLate++
		}
	}
	ids := make([]string, 0, len(dueSet))
	for id := range dueSet {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		c, u := confirmed[id], unknown[id]
		if c > 0 {
			rec.Delivered++
		}
		switch {
		case c >= 2:
			rec.Duplicates++
		case c == 0 && u == 0:
			rec.Gaps++
			rec.GapIDs = append(rec.GapIDs, id)
			if urgent[id] {
				rec.UrgentGaps++
			}
		case u > 0:
			rec.Uncertain++
		}
	}
	extra := map[string]bool{}
	for _, m := range []map[string]int{confirmed, unknown} {
		for id := range m {
			if !dueSet[id] {
				extra[id] = true
			}
		}
	}
	rec.Unexpected = len(extra)
	counts := map[string]int{CutoverBlockGap: rec.Gaps, CutoverBlockUrgentGap: rec.UrgentGaps, CutoverBlockDuplicate: rec.Duplicates, CutoverBlockUnexpected: rec.Unexpected,
		CutoverBlockOldLate: rec.OldLate, CutoverBlockMalformed: rec.Malformed}
	if rec.Uncertain > declared {
		counts[CutoverBlockUncertainty] = rec.Uncertain
	}
	blockers := []CutoverBlocker{}
	for _, code := range cutoverBlockCodes {
		if counts[code] > 0 {
			blockers = append(blockers, CutoverBlocker{Code: code, Count: counts[code]})
		}
	}
	return rec, blockers
}

func (d *cutoverDriver) run(ctx context.Context, step string) error {
	switch step {
	case cutoverStepPreflight:
		return nil // the checks ran before the state file existed
	case cutoverStepQuiesce:
		return d.quiesce(ctx)
	case cutoverStepHandover:
		return d.handover(ctx)
	case cutoverStepActivate:
		return d.activate(ctx)
	default:
		return d.reconcile(ctx)
	}
}

// receipt reports the durable state next to what the engine says now.
func (d *cutoverDriver) receipt(ctx context.Context) CutoverReceipt {
	r := CutoverReceipt{Version: 1, RunID: d.plan.RunID, Scope: d.plan.Scope, Environment: d.plan.Environment, PlanDigest: d.st.PlanDigest, StatePath: d.plan.StatePath,
		StateVersion: d.st.Version, Phase: d.st.Phase, Completed: append([]string{}, d.st.Completed...), IncompleteCode: d.st.IncompleteCode,
		ActiveOwners: []model.ID{}, Blockers: append([]CutoverBlocker{}, d.st.Blockers...)}
	if d.st.Reconciliation != nil {
		r.Reconciliation = *d.st.Reconciliation
	}
	if es, found, err := d.rt.Engine.Cutover(context.WithoutCancel(ctx), d.rt.Scope); err == nil && found {
		r.EnginePhase, r.EngineRevision, r.Epoch = string(es.Phase), es.Revision, es.Epoch
		r.ActiveOwners = append(r.ActiveOwners, notify.ActiveOwners(es.Phase, d.plan.OldOwner, d.plan.NewOwner)...)
	}
	return r
}

// stop records an incomplete or blocked run and returns its receipt and error.
func (d *cutoverDriver) stop(ctx context.Context, step, phase string, cause error) (CutoverReceipt, error) {
	d.st.Phase = phase
	d.st.IncompleteCode = ""
	if phase == CutoverPhaseIncomplete {
		d.st.IncompleteCode = cutoverStopCodeCtx(ctx, cause)
	}
	if err := cutoverSaveState(d.st); err != nil {
		return d.receipt(ctx), fmt.Errorf("cutover stopped at %s (%w) and the state could not be saved: %v", step, cause, err)
	}
	return d.receipt(ctx), fmt.Errorf("cutover %s at %s: %w", phase, step, cause)
}

func cutoverStopCode(err error) string {
	var stop *cutoverStop
	if errors.As(err, &stop) {
		return stop.code
	}
	return cutoverClassify(err)
}

// cutoverStopCodeCtx is cutoverStopCode, except that an adapter failure
// observed after the run's own deadline or cancellation is that deadline or
// cancellation: whatever the adapter returned, it was interrupted.
func cutoverStopCodeCtx(ctx context.Context, err error) string {
	code := cutoverStopCode(err)
	if cerr := ctx.Err(); cerr != nil && code == CutoverIncompleteAdapter {
		return cutoverClassify(cerr)
	}
	return code
}

// errCutoverAlreadyDone is returned, with the original receipt, when a run that
// is complete is started again: nothing is activated twice.
var errCutoverAlreadyDone = errors.New("cutover already done; refusing to run it again")

// Cutover makes the plan's new owner the one normal-notification owner. It
// verifies the ready gate (public key and the caller's clock) and the
// authorization first, runs the five durable phases, and returns a receipt whose
// phase is done only when the delivery reconciliation found no gap, duplicate or
// other blocker beyond the declared provider uncertainty. A call on a state
// file left by a crash or a timeout resumes the same run with the same command
// IDs. The runtime travels in ctx (CutoverWithRuntime).
func Cutover(ctx context.Context, gate ReadyGate, plan OwnershipPlan, grant Authorization) (CutoverReceipt, error) {
	rt, err := cutoverRuntimeFrom(ctx, true)
	if err != nil {
		return CutoverReceipt{}, err
	}
	now := rt.Now()
	if err = VerifyReadyGate(gate, rt.GateKey, now); err != nil {
		return CutoverReceipt{}, fmt.Errorf("cutover refused: ready gate: %w", err)
	}
	if err = cutoverValidatePlan(plan, gate, rt); err != nil {
		return CutoverReceipt{}, fmt.Errorf("cutover refused: %w", err)
	}
	if err = cutoverAuthorize(grant, plan.Scope, cutoverActionCutover, now); err != nil {
		return CutoverReceipt{}, fmt.Errorf("cutover refused: %w", err)
	}
	digest, err := cutoverPlanDigest(plan)
	if err != nil {
		return CutoverReceipt{}, fmt.Errorf("cutover refused: %w", err)
	}
	authDigest, err := json.Marshal(grant)
	if err != nil {
		return CutoverReceipt{}, fmt.Errorf("cutover refused: %w", err)
	}
	d := &cutoverDriver{rt: rt, gate: gate, plan: plan, grant: grant, authRef: model.Hash(sha256.Sum256(authDigest))}
	st, err := cutoverLoadState(plan.StatePath)
	if err != nil {
		return CutoverReceipt{}, fmt.Errorf("cutover refused: %w", err)
	}
	fresh := st == nil
	if fresh {
		st = &cutoverState{Schema: cutoverStateSchema, Plan: plan, PlanDigest: digest, Commands: cutoverCommandSet(plan.RunID), Phase: CutoverPhaseIncomplete, Completed: []string{}}
	} else if err = cutoverResumeCheck(st, plan, digest); err != nil {
		return CutoverReceipt{}, fmt.Errorf("cutover refused: %w", err)
	}
	d.st = st
	if !fresh {
		switch {
		case st.Rollback != nil:
			return CutoverReceipt{}, errors.New("cutover refused: a rollback was started for this run; start a new run")
		case st.Phase == CutoverPhaseDone:
			return d.receipt(ctx), errCutoverAlreadyDone
		}
	}
	if !slices.Contains(st.Completed, cutoverStepPreflight) {
		if err = d.preflightChecks(ctx); err != nil {
			return CutoverReceipt{}, fmt.Errorf("cutover refused: %w", err)
		}
		st.Completed = append(st.Completed, cutoverStepPreflight)
		if err = cutoverSaveState(st); err != nil {
			return CutoverReceipt{}, fmt.Errorf("cutover refused: %w", err)
		}
	}
	for _, step := range cutoverSteps {
		if slices.Contains(st.Completed, step) {
			continue
		}
		if err = d.guard(); err == nil {
			err = d.run(ctx, step)
		}
		if err != nil {
			return d.stop(ctx, step, CutoverPhaseIncomplete, cutoverFail(err))
		}
		if len(st.Blockers) > 0 {
			return d.stop(ctx, step, CutoverPhaseBlocked, errors.New("delivery reconciliation found blockers"))
		}
		st.Completed = append(st.Completed, step)
		st.IncompleteCode = ""
		if step == cutoverStepReconcile {
			st.Phase = CutoverPhaseDone
		}
		if err = cutoverSaveState(st); err != nil {
			return d.receipt(ctx), fmt.Errorf("cutover phase %s done but the state could not be saved: %w", step, err)
		}
	}
	return d.receipt(ctx), nil
}

// ------------------------------------------------------------ projection

// CutoverCount is one blocker-code tally of a public projection.
type CutoverCount struct {
	Code  string `json:"code"`
	Count int    `json:"count"`
}

// CutoverPublic is the closed public projection of a cutover: enums and counts
// only, no identifier, path, time, digest or free text.
type CutoverPublic struct {
	SchemaVersion      int            `json:"schema_version"`
	Phase              string         `json:"phase"`
	PhasesRequired     int            `json:"phases_required"`
	PhasesCompleted    int            `json:"phases_completed"`
	IncompleteCode     string         `json:"incomplete_code"`
	ActiveOwners       int            `json:"active_owners"`
	OldRouteQuiesced   bool           `json:"old_route_quiesced"`
	NewRouteActive     bool           `json:"new_route_active"`
	Due                int            `json:"due"`
	Delivered          int            `json:"delivered"`
	Gaps               int            `json:"gaps"`
	UrgentDue          int            `json:"urgent_due"`
	UrgentGaps         int            `json:"urgent_gaps"`
	Duplicates         int            `json:"duplicates"`
	Uncertain          int            `json:"uncertain"`
	Unexpected         int            `json:"unexpected"`
	BlockerCounts      []CutoverCount `json:"blocker_counts"`
	CustomerAcceptance bool           `json:"customer_acceptance"`
}

// CutoverPublicSummary projects a receipt onto the closed public shape.
func CutoverPublicSummary(r CutoverReceipt) CutoverPublic {
	p := CutoverPublic{SchemaVersion: 1, Phase: r.Phase, PhasesRequired: len(cutoverSteps), PhasesCompleted: len(r.Completed), IncompleteCode: r.IncompleteCode,
		ActiveOwners: len(r.ActiveOwners), OldRouteQuiesced: slices.Contains(r.Completed, cutoverStepQuiesce), NewRouteActive: slices.Contains(r.Completed, cutoverStepActivate),
		Due: r.Reconciliation.Due, Delivered: r.Reconciliation.Delivered, Gaps: r.Reconciliation.Gaps, UrgentDue: r.Reconciliation.UrgentDue, UrgentGaps: r.Reconciliation.UrgentGaps,
		Duplicates: r.Reconciliation.Duplicates, Uncertain: r.Reconciliation.Uncertain, Unexpected: r.Reconciliation.Unexpected, BlockerCounts: []CutoverCount{}}
	for _, code := range cutoverBlockCodes {
		for _, b := range r.Blockers {
			if b.Code == code && b.Count > 0 {
				p.BlockerCounts = append(p.BlockerCounts, CutoverCount{Code: code, Count: b.Count})
			}
		}
	}
	return p
}

// ------------------------------------------------------------------- CLI

// CutoverConnectTarget names what the operator's adapters must reach.
type CutoverConnectTarget struct {
	Scope       string
	Environment string
	Project     model.ID
}

var errCutoverNoAdapters = errors.New("no legacy-operator, route-observer, deadman or engine adapter is compiled into this build; the owning environment's repository supplies them")

// cutoverConnect builds the runtime for a run. The adapters are specific to the
// customer environment and are discovered under its authorization, so this
// build has none: the CLI refuses rather than pretend. A build that carries the
// environment's adapters replaces this function; tests install fakes.
var cutoverConnect = func(ctx context.Context, target CutoverConnectTarget) (CutoverRuntime, error) {
	return CutoverRuntime{}, errCutoverNoAdapters
}

func cutoverReadKey(path string) (ed25519.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("cannot read gate public key")
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, errors.New("gate public key must be 32 bytes of hex")
	}
	return key, nil
}

// runCutover is the `cutover` subcommand. The parent dispatches
// `adoption cutover <flags>` by passing the flags (without the subcommand name).
//
//	--gate FILE                     signed ReadyGate JSON (private)
//	--gate-public-key FILE          hex ed25519 public key (32 bytes) verifying the gate
//	--plan FILE                     OwnershipPlan JSON (private); state_path must be empty
//	--authorization FILE            private grant: not read-only, one scope naming the plan's scope, collector "cutover"
//	--private-directory DIRECTORY   existing operator-private directory holding the run's state and receipts
//	--public-summary FILE           new file for the closed public projection
//	--private-directory-acl-confirmed  operator verified the NTFS ACL (Windows)
//	--timeout DURATION              overall deadline, positive, at most 1h (default 10m)
//
// The state file is DIRECTORY/cutover-RUNID.state.json and each invocation
// writes DIRECTORY/cutover-RUNID.receipt-vN.json (N is the state version).
func runCutover(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("cutover", flag.ContinueOnError)
	gatePath := fs.String("gate", "", "signed ready gate JSON")
	keyPath := fs.String("gate-public-key", "", "hex ed25519 public key verifying the gate")
	planPath := fs.String("plan", "", "ownership plan JSON")
	grantPath := fs.String("authorization", "", "private authorization JSON")
	dir := fs.String("private-directory", "", "existing operator-private directory")
	summaryPath := fs.String("public-summary", "", "new public summary file")
	acl := fs.Bool("private-directory-acl-confirmed", false, "operator verified restrictive NTFS ACL")
	timeout := fs.Duration("timeout", 10*time.Minute, "overall deadline (positive, at most 1h)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || !nonempty(*gatePath, *keyPath, *planPath, *grantPath, *dir, *summaryPath) {
		return errors.New("usage: adoption cutover --gate FILE --gate-public-key FILE --plan FILE --authorization FILE --private-directory DIRECTORY --public-summary FILE")
	}
	if *timeout <= 0 || *timeout > time.Hour {
		return errors.New("timeout must be positive and at most 1h")
	}
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	var gate ReadyGate
	var plan OwnershipPlan
	var grant Authorization
	if readInput(*gatePath, &gate) != nil || readInput(*planPath, &plan) != nil || readInput(*grantPath, &grant) != nil {
		return errors.New("invalid private operator input")
	}
	key, err := cutoverReadKey(*keyPath)
	if err != nil {
		return err
	}
	if plan.StatePath != "" || !cutoverRunIDPattern.MatchString(plan.RunID) {
		return errors.New("the plan must carry a valid run id and no state path: the state file lives in the private directory")
	}
	resolved, err := privateDirectory(ctx, *dir, nil, *acl)
	if err != nil {
		return err
	}
	plan.StatePath = filepath.Join(resolved, "cutover-"+plan.RunID+".state.json")
	rt, err := cutoverConnect(ctx, CutoverConnectTarget{Scope: plan.Scope, Environment: plan.Environment, Project: plan.Project})
	if err != nil {
		return err
	}
	rt.GateKey = key
	if rt.Now == nil {
		rt.Now = func() time.Time { return time.Now().UTC() }
	}
	receipt, runErr := Cutover(CutoverWithRuntime(ctx, rt), gate, plan, grant)
	if receipt.Version == 0 || errors.Is(runErr, errCutoverAlreadyDone) {
		return runErr
	}
	out := filepath.Join(resolved, fmt.Sprintf("cutover-%s.receipt-v%d.json", plan.RunID, receipt.StateVersion))
	if err = writeExclusive(out, receipt); err != nil {
		return errors.New("private receipt creation failed")
	}
	if err = writeExclusive(*summaryPath, CutoverPublicSummary(receipt)); err != nil {
		return errors.New("summary creation failed; private receipt retained")
	}
	return runErr
}
