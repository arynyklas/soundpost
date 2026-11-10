// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package model

import (
	"encoding/json"
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
	Installation         ID
	Revision             Revision
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
