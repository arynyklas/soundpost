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
