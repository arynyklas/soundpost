// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package model

import (
	"encoding/json"
	"strconv"
	"strings"
)

type ControlUser struct {
	ID                ID
	Email, Password   string
	Admin             bool
	TOTP, PendingTOTP string
	LastTOTP          int64
	Recovery          []string
	Disabled          bool
}
type ControlSession struct {
	User                     ID
	CSRF                     string
	Expires, Reauthenticated int64
}
type ControlTeam struct {
	Members     []ID     `json:"members"`
	Projects    []ID     `json:"projects"`
	Permissions []string `json:"permissions"`
	Enabled     bool     `json:"enabled"`
}
type ControlOrg struct {
	ID       ID
	Name     string
	Epoch    uint64
	Members  map[string]bool
	Admins   map[string]bool
	Projects map[string]string
	Grants   map[string][]string
	Secrets  map[string]string
	Settings map[string]json.RawMessage
	Teams    map[string]ControlTeam

	// Settings also holds the per-object records that make an admin save conflict only with a change to the same object (D56,
	// D59): ObjEpochKeyPrefix+key maps an object to the Epoch value its last tracked change produced, ObjFloorKey is the Epoch every
	// older object counts as changed at, ObjSeenKey is the Epoch after the last tracked change. An Epoch bump by code that does not
	// track objects (the previous release, a restore, a retirement) leaves ObjSeenKey behind, which makes every object count as
	// changed at the current Epoch (the whole-organization compare). They are Settings keys, not members of this struct, because the
	// previous release's strict decoder refuses an unknown member but accepts any key of a map, and every code path that walks
	// Settings reads the keys under a prefix of its own and ignores the others: a state, a replacement, a patch or a snapshot that
	// carries the records applies on that release and installs, so no protocol gate is needed and a voter can be rolled back at any time.
}

// The Settings keys of the per-object records of an organization. No other Settings key starts with "obj_".
const (
	ObjEpochKeyPrefix = "obj_epoch:"
	ObjFloorKey       = "obj_floor"
	ObjSeenKey        = "obj_seen"
)

// objValue reads a record's value; ok is false when it is absent or not a number.
func (o ControlOrg) objValue(key string) (v uint64, present, ok bool) {
	raw, present := o.Settings[key]
	if !present {
		return 0, false, true
	}
	return v, true, json.Unmarshal(raw, &v) == nil
}

// objFloor is the epoch every object without a record counts as changed at: the stored floor while the records are current
// (obj_seen equals Epoch), the current Epoch otherwise, and also when the floor or the seen mark is missing or unreadable (a
// record that vanished or was altered by code that does not know it can only make saves conflict, never pass).
func (o ControlOrg) objFloor() uint64 {
	seen, present, ok := o.objValue(ObjSeenKey)
	if !present || !ok || seen != o.Epoch {
		return o.Epoch
	}
	floor, present, ok := o.objValue(ObjFloorKey)
	if !present || !ok {
		return o.Epoch
	}
	return floor
}

// ObjectChangedAfter reports whether a save based on the organization epoch readEpoch is stale for the object key: the object changed
// after it, an untracked change moved the epoch past it, or it names an epoch the organization has not reached.
func (o ControlOrg) ObjectChangedAfter(key string, readEpoch uint64) bool {
	if readEpoch > o.Epoch {
		return true
	}
	changed := o.objFloor()
	v, present, ok := o.objValue(ObjEpochKeyPrefix + key)
	switch {
	case present && !ok:
		changed = o.Epoch // a record that cannot be read counts as a change at the current epoch
	case v > changed:
		changed = v
	}
	return changed > readEpoch
}

// MaxObjEpochs bounds the object records of an organization.
const MaxObjEpochs = 4096

// TrackChange advances the organization epoch for a change to the object key and records it, dropping entries the floor covers.
func (o *ControlOrg) TrackChange(key string) {
	floor := o.objFloor()
	if o.Settings == nil {
		o.Settings = map[string]json.RawMessage{}
	}
	tracked := 0
	for k := range o.Settings {
		if !strings.HasPrefix(k, ObjEpochKeyPrefix) {
			continue
		}
		if v, _, ok := o.objValue(k); ok && v <= floor {
			delete(o.Settings, k)
			continue
		}
		tracked++
	}
	if tracked >= MaxObjEpochs {
		// Bound: past MaxObjEpochs tracked objects the floor rises to the current epoch, which counts every
		// older object as changed (a save based on an older read conflicts, as in the coarse rule).
		floor = o.Epoch
		for k := range o.Settings {
			if strings.HasPrefix(k, ObjEpochKeyPrefix) {
				delete(o.Settings, k)
			}
		}
	}
	o.Epoch++
	o.Settings[ObjFloorKey] = uintRaw(floor)
	o.Settings[ObjEpochKeyPrefix+key] = uintRaw(o.Epoch)
	o.Settings[ObjSeenKey] = uintRaw(o.Epoch)
}

func uintRaw(v uint64) json.RawMessage { return json.RawMessage(strconv.FormatUint(v, 10)) }

// StartObjectRecords makes a new organization's records current: every object counts as changed at its starting Epoch.
func (o *ControlOrg) StartObjectRecords() {
	if o.Settings == nil {
		o.Settings = map[string]json.RawMessage{}
	}
	o.Settings[ObjFloorKey] = uintRaw(o.Epoch)
	o.Settings[ObjSeenKey] = uintRaw(o.Epoch)
}

type AuditOutcome string

const (
	AuditAllowed AuditOutcome = "allowed"
	AuditDenied  AuditOutcome = "denied"
	AuditFailed  AuditOutcome = "failed"
)

type ControlAudit struct {
	ID             ID
	Principal      ID
	Action, Reason string
	Time           int64
	Org            string
	PolicyEpoch    uint64
	Targets        []ID
	RequestID      ID
	Outcome        AuditOutcome
}
type ControlServerToken struct {
	ID          ID
	Principal   ID
	Org         ID
	Projects    []ID
	Permissions []string
	Expires     int64
	Revoked     bool
}
type ControlState struct {
	Installation ID
	Revision     Revision
	// AuthorityRevision is the Revision of the last control transition that could change
	// authority, policy, retention, deletion or access state (internal/control/authority.go
	// is the one place that classifies writers). The retention commands accept a caller view
	// anywhere in [AuthorityRevision, Revision]: a view at least as new as the last such
	// transition. Zero on a state written before the field existed (omitted from JSON).
	AuthorityRevision    Revision `json:"authority_revision,omitempty"`
	BootstrapHash        string
	BearerHashKey        string
	BearerHashKeyVersion uint8
	DataInitialized      bool
	Users                map[string]ControlUser
	Sessions             map[string]ControlSession
	Orgs                 map[string]ControlOrg
	Audits               []ControlAudit
	Commands             map[string]ControlResult
	CommandOwners        map[string]string
	// RevisionClock dates the control revisions coarsely, for the age of the applied-command log
	// (control.Store.ExpireControlLog): the update that commits revision R records (R, the
	// leader's clock) when the last stamp is at least a minute old, and drops every stamp that
	// is older than the dedup window except the newest of them. A command whose Revision is at
	// or below the Revision of a stamp was therefore committed no later than that stamp's time.
	// It holds at most a window's worth of minutes (about 1440 entries), whatever the traffic,
	// where a time per command would be the size of the command log. Never read for an access
	// decision.
	RevisionClock        []RevisionStamp `json:"revision_clock,omitempty"`
	OIDC                 map[string]json.RawMessage
	ServerTokens         map[string]ControlServerToken
	Sources              map[string]SourceAuthority
	SourceCredentials    map[string]string
	Reservations         map[string]AdmissionReservation
	AdmissionKeys        map[string]string
	Quotas               map[string]QuotaState
	SourceFences         map[string]SourceFence
	SourceOperations     map[string]SourceFence
	PolicySigningKey     string
	Releases             map[string]Release
	GroupingIssues       map[string]GroupingIssue
	GroupingMigrations   map[string]GroupingMigration
	ArtifactIntents      map[string]ArtifactReferenceIntent
	ArtifactReservations map[string]ArtifactQuotaReservation
	// Settlement is what control kept of the consumed admission reservations whose rows it
	// dropped (internal/control/settle.go): per data-group window one digest of the reservations
	// it held, and the charge those reservations put on every quota key. Nil until a window is
	// settled.
	Settlement *Settlement `json:"settlement,omitempty"`
	// Retention, deletion and holds (plan 01 task 08). Every map is additive and
	// keyed by canonical lowercase IDs; none of them ever shrinks (a completed
	// deletion is a permanent tombstone), so the retained-operation count and the
	// per-org generation are monotonic.
	Deletions         map[string]DeletionOperation        // operation ID -> saga record
	DeleteGenerations map[string]uint64                   // org ID -> monotonic delete generation
	RetiredOrgs       map[string]ID                       // org ID -> retiring operation
	RetiredProjects   map[string]ID                       // "org:project" -> retiring operation
	Holds             map[string]LegalHold                // hold ID -> legal hold
	EvidenceGaps      map[string]EvidenceGap              // gap ID -> durable declared gap
	RetentionPolicies map[string][]RetentionPolicyVersion // "org" or "org:project" -> audited versions
	// Rule evaluation (plan 02 task 11). Values are the control package's closed
	// JSON DTOs (RuleBook, RuleOutput): control stores them without importing the
	// rules package, and the rules read adapter reconstructs its own types.
	RuleBooks   map[string]json.RawMessage // "org:project:rule" -> committed rule facts
	RuleOutputs map[string]json.RawMessage // output ID -> internal output outbox record
	// Incident response (plan 06 task 05). Values are the control package's closed
	// IncidentRecord DTO: the incident state is opaque JSON the incidents package
	// computes and control compare-and-sets without importing it.
	IncidentBooks map[string]json.RawMessage // "org:project:incident" -> committed incident record
	// Condition lifecycle (plan 06 task 04). Values are the control package's
	// closed ConditionRecord DTO: the condition state is opaque JSON the
	// conditions package computes and control compare-and-sets under a lease.
	ConditionBooks map[string]json.RawMessage // "org:project:condition" -> committed condition record
	// Notification delivery outbox (plan 06 task 07). Values are the control
	// package's closed DTOs: "delivery:<id>" holds one DeliveryRecord (stable
	// idempotency ID, immutable attempts, claim lease), "policy:<org>:<project>:
	// <policy>:<subject>" the opaque notify policy state and its version, and
	// "fence:<org>:<project>" the highest lease the project's outbox accepted.
	// None of them ever holds a destination secret or telemetry text.
	DeliveryBooks map[string]json.RawMessage
	// Issue lifecycle (plan 06 task 02). "org:project" holds the control
	// package's closed IssueBook DTO: the project's issue state revision (the
	// compare-and-set token), per data group checkpoints, command records, gaps,
	// effect intents and the opaque per-issue regression explanations. The issues
	// themselves are the shared GroupingIssues records. No book holds telemetry
	// text, only IDs, hashes, counts, cursors and versions.
	IssueBooks map[string]json.RawMessage
	// Job health (plan 06 task 03). "org:project:job" holds the control
	// package's closed JobRecord DTO: the job's version (the compare-and-set
	// token), the opaque job state the jobs reducer computes, its digest and the
	// applied command records. After an erasure the state is a tombstone. No
	// record holds telemetry text, only IDs, ordinals, times, states and hashes.
	JobBooks map[string]json.RawMessage
	// Notification ownership cutover (plan 06 task 09). "org:project" holds the
	// control package's closed CutoverRecord DTO: the project's cutover phase,
	// its revision (the compare-and-set token), the verified source/version
	// frontier, the bounded transition history and the digests of the barrier
	// evidence. A retirement drops the operator free text and the evidence
	// payloads and keeps identities, revision, phase and the audit trail.
	CutoverBooks map[string]json.RawMessage
	// Saved views (plan 06 task 11, C11). "org:project:view" holds the closed
	// auth.SavedView DTO of one project-owned saved query. A query text can hold
	// sensitive literals, so a view is stored only through an explicit save by a
	// caller who reads the project, and a retirement of the owning project drops
	// it (internal/control/erase_saved_views.go). Saving never changes
	// authority: it moves neither an organization's policy epoch nor
	// AuthorityRevision.
	SavedViewBooks map[string]json.RawMessage `json:",omitempty"`
	// Rule catalogue (plan 02 task 11, 11.01-W1). "org:project:rule" holds the
	// control package's closed RuleDefinitionRecord DTO: the newest definition
	// of one rule (opaque JSON the rules package validates at save), its
	// revision (the compare-and-set token) and whether it is retired. A
	// retirement of the owning project drops them
	// (internal/control/rule_catalogue.go). Authoring never changes authority.
	RuleDefinitions map[string]json.RawMessage `json:",omitempty"`
	// Job schedule-definition catalogue (plan 11.01-W2). "org:project:job" holds
	// the control package's closed JobDefinitionRecord DTO: the newest schedule
	// definition of one job (opaque JSON the jobs package validates at save), its
	// revision (the compare-and-set token) and whether it is retired. A
	// retirement of the owning project drops them
	// (internal/control/job_definitions.go). Authoring never changes authority.
	JobDefinitions map[string]json.RawMessage `json:",omitempty"`
	// Job producer resume position (plan 11.01-W4). "org:project" holds the control
	// package's closed JobPositionRecord DTO: per data group, the origin index of the
	// job_attempt journal through which the producer has applied every row. Only the
	// runner advances it and it only moves forward; a retirement of the owning
	// project drops it (internal/control/job_position.go).
	JobPositions map[string]json.RawMessage `json:",omitempty"`
}
type ControlCommand struct {
	CommandID        ID
	ExpectedRevision Revision
	Kind             string
	Payload          json.RawMessage
}
type ControlResult struct {
	Revision    Revision `json:"revision"`
	AffectedIDs []ID     `json:"affected_ids"`
	Cursor      Cursor   `json:"cursor"`
	Phase       string   `json:"phase,omitempty"`
}

// The keys under which the replay index (internal/replays) keeps its entries in an
// organization's Settings. control masks exactly these keys when it decides whether a replay
// index write could have changed authority (Store.UpdateReplayIndex).
const (
	ReplayIndexKeyPrefix = "replay_index:"
	ReplayPinKeyPrefix   = "replay_pins:"
)

// The keys under which the artifact reference ledger (internal/artifacts) keeps one ledger per
// published map and one index per project in an organization's Settings. control masks exactly
// these keys when it decides whether a ledger write could have changed authority
// (Store.UpdateArtifactReferences).
const (
	ArtifactLedgerKeyPrefix      = "artifact_refs:"
	ArtifactLedgerIndexKeyPrefix = "artifact_refs_index:"
)

// IndexLayoutVersion is what a member answers to the live layout question (replica.MTLS.QueryLayout):
// 1 means the running binary reads the sharded ledger index and per-replay pins without the
// per-project values of the previous release.
const IndexLayoutVersion uint64 = 1

// IndexesContractedKey is the key of an organization's Settings that says the operator ran
// `soundpost upgrade contract-indexes` for it (D70) or that it was created on an installation this
// release bootstrapped (D72, see ControlState.BornContracted): the sharded artifact ledger index and the
// per-replay pins are then the only copy, and the per-project values the previous release reads
// (artifact_refs_index:<project> with its anchor, replay_pins:<project>) are neither kept nor
// written. Before it, a write keeps both layouts current so the previous release can still read
// everything. The key is in the ledger index family, so writing it alone does not move the control
// AuthorityRevision, and the previous release ignores it.
const IndexesContractedKey = "artifact_refs_index:contracted"

// IndexesContracted reports whether the organization's indexes are contracted.
func (o ControlOrg) IndexesContracted() bool {
	_, ok := o.Settings[IndexesContractedKey]
	return ok
}

// BornContracted reports whether the installation was bootstrapped by a release that has no previous
// release to roll back to (D72): `auth.Service.Bootstrap` wrote IndexesContractedKey into the
// replicated State.OIDC map in the very command that created the first administrator, so every voter
// holds the same mark and an organization created on the installation is contracted from its first
// write. An installation the previous release bootstrapped never carries it (that release does not
// write it); it stays expanded until the operator runs contract-indexes (D70). The key is the one the
// organizations use, so the stored-state scan of control.Store.indexesContracted finds it too and the
// layout guards of a contracted installation hold from the first start.
func (s ControlState) BornContracted() bool {
	_, ok := s.OIDC[IndexesContractedKey]
	return ok
}

// MarkBornContracted records the mark BornContracted reports.
func (s *ControlState) MarkBornContracted() {
	if s.OIDC == nil {
		s.OIDC = map[string]json.RawMessage{}
	}
	s.OIDC[IndexesContractedKey] = json.RawMessage(`true`)
}

// OrgAuthorityKey is the key of an organization's Settings that holds the control Revision of the
// last authority-class transition that changed that organization alone (an admin command of the
// organization, Store.UpdateOrgAuthority, or a retention-class command or worker transition of the
// organization, which control commits only after verifying that it wrote nothing but the
// organization's own rows, and only as a state patch). A retention command of the organization needs
// a caller view no older than the later of the installation's authority floor
// (control.installationFloor) and this value. Such a commit ALSO moves ControlState.AuthorityRevision,
// because the previous release judges a retention command against that scalar alone and must keep
// refusing a same-organization view older than the commit; this release reads the scalar through the
// floor below, which does not count a verified commit of another organization.
const OrgAuthorityKey = "authority_rev"

// ScopedAuthorityKey is the key of State.OIDC (a map the previous release carries through every
// replacement and ignores; the colon keeps the login sweep away from it) that holds
// {"floor": F, "global": G}: at the commit that moved AuthorityRevision to G, F was the installation
// floor, the revision of the last authority change that was NOT a verified commit of one
// organization. The pair is read only while AuthorityRevision == G. A commit of the previous release
// moves AuthorityRevision past G without touching the pair, which makes the pair void and the floor
// AuthorityRevision itself, so nothing an older binary committed is ever skipped.
const ScopedAuthorityKey = "authority:scope"

// RevisionStamp says that control revision Revision had been committed by At (Unix nanoseconds).
type RevisionStamp struct {
	Revision Revision `json:"revision"`
	At       int64    `json:"at"`
}
