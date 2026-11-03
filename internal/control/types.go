// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

// CommandKind is the closed C05 vocabulary. Feature owners provide deterministic
// leaf DTO transitions through their injected control authority, not imports here.
type CommandKind string

const (
	CreateOrg           CommandKind = "CreateOrg"
	Grant               CommandKind = "Grant"
	PolicyChange        CommandKind = "PolicyChange"
	BeginFence          CommandKind = "BeginFence"
	CompleteFence       CommandKind = "CompleteFence"
	ReserveAdmission    CommandKind = "ReserveAdmission"
	FinalizeAdmission   CommandKind = "FinalizeAdmission"
	ApplyIssueEvidence  CommandKind = "ApplyIssueEvidence"
	ApplyCondition      CommandKind = "ApplyCondition"
	ApplyRuleEvaluation CommandKind = "ApplyRuleEvaluation"
	IncidentAction      CommandKind = "IncidentAction"
	ClaimDelivery       CommandKind = "ClaimDelivery"
	CompleteDelivery    CommandKind = "CompleteDelivery"
	DeleteScope         CommandKind = "DeleteScope"
	AuditCommand        CommandKind = "Audit"
	RegisterRelease     CommandKind = "RegisterRelease"
	UpdateJob           CommandKind = "UpdateJob"
	RecordEvidenceGap   CommandKind = "RecordEvidenceGap"
)
