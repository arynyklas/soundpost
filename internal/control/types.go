// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

// CommandKind is the closed C05 vocabulary. Feature owners provide deterministic
// leaf DTO transitions through their injected control authority, not imports here.
type CommandKind string

const (
	KindCreateOrg           CommandKind = "CreateOrg"
	KindGrant               CommandKind = "Grant"
	KindPolicyChange        CommandKind = "PolicyChange"
	KindBeginFence          CommandKind = "BeginFence"
	KindCompleteFence       CommandKind = "CompleteFence"
	KindReserveAdmission    CommandKind = "ReserveAdmission"
	KindFinalizeAdmission   CommandKind = "FinalizeAdmission"
	KindApplyIssueEvidence  CommandKind = "ApplyIssueEvidence"
	KindApplyCondition      CommandKind = "ApplyCondition"
	KindApplyRuleEvaluation CommandKind = "ApplyRuleEvaluation"
	KindIncidentAction      CommandKind = "IncidentAction"
	KindClaimDelivery       CommandKind = "ClaimDelivery"
	KindCompleteDelivery    CommandKind = "CompleteDelivery"
	KindDeleteScope         CommandKind = "DeleteScope"
	KindAudit               CommandKind = "Audit"
	KindRegisterRelease     CommandKind = "RegisterRelease"
	KindUpdateJob           CommandKind = "UpdateJob"
	KindRecordEvidenceGap   CommandKind = "RecordEvidenceGap"
)
