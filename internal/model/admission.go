// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package model

type TemplateField struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	MaxBytes    uint32   `json:"max_bytes"`
	Sensitivity string   `json:"sensitivity"`
	Values      []Scalar `json:"values"`
}
type LogTemplate struct {
	ID       string          `json:"id"`
	Revision Revision        `json:"revision"`
	Line     string          `json:"line"`
	Severity string          `json:"severity"`
	Fields   []TemplateField `json:"fields"`
}
type SourcePolicy struct {
	Revision      Revision            `json:"revision"`
	Enabled       bool                `json:"enabled"`
	Class         string              `json:"class"`
	Kinds         []Kind              `json:"kinds"`
	Templates     []LogTemplate       `json:"templates"`
	Resources     ResourceRegistry    `json:"resources"`
	Labels        map[string][]string `json:"labels"`
	Operations    []string            `json:"operations"`
	Dependencies  []string            `json:"dependencies"`
	Codes         []string            `json:"codes"`
	RetentionDays map[Kind]uint32     `json:"retention_days"`
	MaxBytes      Uint64              `json:"max_bytes"`
	MaxSeries     Uint64              `json:"max_series"`
	Replay        bool                `json:"replay"`
	Expires       UnixNano            `json:"expires_ns"`
	RawOwner      *ID                 `json:"raw_owner,omitempty"`
	RawRationale  string              `json:"raw_rationale,omitempty"`
	RawMaxBytes   uint32              `json:"raw_max_bytes,omitempty"`
}
type SourceAuthority struct {
	ID           ID           `json:"id"`
	Org          ID           `json:"org"`
	Project      ID           `json:"project"`
	Browser      bool         `json:"browser"`
	Origins      []string     `json:"origins"`
	Expires      UnixNano     `json:"expires_ns"`
	Revoked      bool         `json:"revoked"`
	Retired      bool         `json:"retired"`
	Closing      bool         `json:"closing"`
	Policy       SourcePolicy `json:"policy"`
	CredentialID ID           `json:"credential_id"`
}
type SourceDescriptor struct {
	Version        uint16   `json:"version"`
	Org            ID       `json:"org"`
	Project        ID       `json:"project"`
	Source         ID       `json:"source"`
	RoutingVersion uint16   `json:"routing_version"`
	Slots          uint16   `json:"slots"`
	PolicyRevision Revision `json:"policy_revision"`
}
type SignedPolicyEnvelope struct {
	Version   uint16 `json:"version"`
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}
type AdmissionReservation struct {
	ID          ID       `json:"id"`
	Org         ID       `json:"org"`
	Project     ID       `json:"project"`
	Source      ID       `json:"source"`
	Producer    ID       `json:"producer"`
	Batch       ID       `json:"batch"`
	Slot        uint16   `json:"slot"`
	Hash        Hash     `json:"hash"`
	PolicyEpoch Uint64   `json:"policy_epoch"`
	Bytes       Uint64   `json:"bytes"`
	Series      []string `json:"series"`
	State       string   `json:"state"`
	Cursor      *Cursor  `json:"cursor,omitempty"`
}
type QuotaState struct {
	Bytes      Uint64            `json:"bytes"`
	Series     map[string]uint64 `json:"series"`
	MaxBytes   Uint64            `json:"max_bytes"`
	MaxSeries  Uint64            `json:"max_series"`
	Configured bool              `json:"configured"`
}
type ReserveAdmission struct {
	Reservation     AdmissionReservation `json:"reservation"`
	OrgMaxBytes     Uint64               `json:"org_max_bytes"`
	ProjectMaxBytes Uint64               `json:"project_max_bytes"`
	MaxSeries       Uint64               `json:"max_series"`
}
type FinalizeAdmission struct {
	ReservationID ID     `json:"reservation_id"`
	Cursor        Cursor `json:"cursor"`
}
type CancelReservation struct {
	ReservationID ID     `json:"reservation_id"`
	OwnerGroup    ID     `json:"owner_group"`
	Fence         Cursor `json:"fence"`
	Hash          Hash   `json:"hash"`
}

// SourceFence remains fencing until every installed slot has a durable barrier.
type SourceFence struct {
	Operation ID       `json:"operation"`
	Source    ID       `json:"source"`
	Org       ID       `json:"org"`
	Epoch     Uint64   `json:"epoch"`
	Phase     string   `json:"phase"`
	Barriers  []Cursor `json:"barriers"`
}
