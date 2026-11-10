// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"
)

// Legacy history is retained, read-only and visibly linked. This file tracks
// the obligations around that history and decides whether they block closing
// the adoption. It is a tracker, not an actor: it has no code path that deletes,
// removes, exports, imports or changes anything. An eventual export or deletion
// is a separately authorized, separately audited action performed by the
// history's owner; this tool only reads the digests those actions leave behind.

// HistoryCode is the closed vocabulary of reasons history blocks closure.
type HistoryCode string

const (
	HistoryCodeEvidenceStale        HistoryCode = "evidence_stale"
	HistoryCodeEvidenceFuture       HistoryCode = "evidence_future_dated"
	HistoryCodeOriginNotReadOnly    HistoryCode = "legacy_not_read_only"
	HistoryCodeWriteAccess          HistoryCode = "legacy_write_access"
	HistoryCodeAccessInvalid        HistoryCode = "access_invalid"
	HistoryCodeAccessUnauthorized   HistoryCode = "access_unauthorized"
	HistoryCodeReaderNotKeyed       HistoryCode = "reader_identity_not_keyed"
	HistoryCodeRetentionMissing     HistoryCode = "retention_obligation_missing"
	HistoryCodeExportMissing        HistoryCode = "export_obligation_missing"
	HistoryCodeRecordMissing        HistoryCode = "obligation_record_missing"
	HistoryCodeExportRecordMissing  HistoryCode = "export_record_missing"
	HistoryCodeObligationInvalid    HistoryCode = "obligation_invalid"
	HistoryCodeObligationDuplicate  HistoryCode = "obligation_duplicate"
	HistoryCodeRetentionOverdue     HistoryCode = "retention_overdue"
	HistoryCodeExportOverdue        HistoryCode = "export_overdue"
	HistoryCodeHoldOverdue          HistoryCode = "hold_overdue"
	HistoryCodeReminderMissing      HistoryCode = "reminder_missing"
	HistoryCodeCompletionUnaudited  HistoryCode = "completion_unaudited"
	HistoryCodeCompletionInvalid    HistoryCode = "completion_invalid"
	HistoryCodeHistoryRemoved       HistoryCode = "history_removed_before_obligations"
	HistoryCodeBoundaryMissing      HistoryCode = "boundary_missing"
	HistoryCodeBoundaryNotVisible   HistoryCode = "boundary_not_visible"
	HistoryCodeBoundaryNotReadOnly  HistoryCode = "boundary_links_not_read_only"
	HistoryCodeBoundaryUnauthorized HistoryCode = "boundary_links_not_authorized"
	HistoryCodeRemovalStep          HistoryCode = "implicit_removal_step"
	HistoryCodeImportStep           HistoryCode = "mandatory_import_step"
	HistoryCodeUnsupportedStep      HistoryCode = "unsupported_step"
)

var historyCodes = map[HistoryCode]bool{
	HistoryCodeEvidenceStale: true, HistoryCodeEvidenceFuture: true, HistoryCodeOriginNotReadOnly: true,
	HistoryCodeWriteAccess: true, HistoryCodeAccessInvalid: true, HistoryCodeAccessUnauthorized: true,
	HistoryCodeReaderNotKeyed: true, HistoryCodeRetentionMissing: true, HistoryCodeExportMissing: true,
	HistoryCodeRecordMissing: true, HistoryCodeExportRecordMissing: true, HistoryCodeObligationInvalid: true,
	HistoryCodeObligationDuplicate: true, HistoryCodeRetentionOverdue: true, HistoryCodeExportOverdue: true,
	HistoryCodeHoldOverdue: true, HistoryCodeReminderMissing: true, HistoryCodeCompletionUnaudited: true,
	HistoryCodeCompletionInvalid: true, HistoryCodeHistoryRemoved: true, HistoryCodeBoundaryMissing: true,
	HistoryCodeBoundaryNotVisible: true, HistoryCodeBoundaryNotReadOnly: true, HistoryCodeBoundaryUnauthorized: true,
	HistoryCodeRemovalStep: true, HistoryCodeImportStep: true, HistoryCodeUnsupportedStep: true,
}

// HistoryObligationKind is the closed set of obligations tracked per legacy
// history. Retention and export are required exactly once; holds are optional.
type HistoryObligationKind string

const (
	HistoryKindRetention HistoryObligationKind = "retention"
	HistoryKindHold      HistoryObligationKind = "hold"
	HistoryKindExport    HistoryObligationKind = "export"
)

// HistoryAccessMode is what a grant lets a reader do to legacy history.
type HistoryAccessMode string

const (
	HistoryAccessRead  HistoryAccessMode = "read"
	HistoryAccessWrite HistoryAccessMode = "write"
)

// HistoryStepKind is the closed set of steps an adoption closure plan may
// contain. There is deliberately no removal, export or import step.
type HistoryStepKind string

const (
	HistoryStepRetain         HistoryStepKind = "retain"
	HistoryStepRemind         HistoryStepKind = "remind"
	HistoryStepVerifyReadOnly HistoryStepKind = "verify_read_only"
)

const (
	historySchemaVersion = 1
	historyMaxAgeSeconds = 30 * 24 * 3600
	historyMaxItems      = 10000
	historyMaxReminder   = 365
)

// HistoryOrigin is the state of the legacy system holding the history.
// ReadOnly: no principal can change it. Retained: the history still exists.
type HistoryOrigin struct {
	ReadOnly       bool   `json:"read_only"`
	Retained       bool   `json:"retained"`
	EvidenceDigest string `json:"evidence_digest"`
}

// HistoryAccess is one authorization to reach legacy history. ReaderKey is a
// keyed pseudonym (HistoryReaderKey), never an address or account name.
type HistoryAccess struct {
	ReaderKey           string            `json:"reader_key"`
	Mode                HistoryAccessMode `json:"mode"`
	NotBefore           time.Time         `json:"not_before"`
	ExpiresAt           time.Time         `json:"expires_at"`
	RevokedAt           time.Time         `json:"revoked_at"`
	AuthorizationDigest string            `json:"authorization_digest"`
}

// HistoryBoundary is the product-side metadata for legacy history deep links.
// Visible: the product shows where Soundpost history starts and legacy history
// ends. The links must be read-only and gated by authorization.
type HistoryBoundary struct {
	CutoverAt                 time.Time `json:"cutover_at"`
	Visible                   bool      `json:"visible"`
	Links                     int       `json:"links"`
	LinksReadOnly             bool      `json:"links_read_only"`
	LinksRequireAuthorization bool      `json:"links_require_authorization"`
	MetadataDigest            string    `json:"metadata_digest"`
}

// HistoryObligation is one retention, hold or export duty. RecordDigest is the
// obligation's record (retention policy record, hold order record, export plan
// or manifest). Completion fields are the digests an authorized, audited
// action performed elsewhere left behind; this tool never performs it.
type HistoryObligation struct {
	Kind                HistoryObligationKind `json:"kind"`
	DueAt               time.Time             `json:"due_at"`
	RecordDigest        string                `json:"record_digest"`
	ReminderLeadDays    int                   `json:"reminder_lead_days"`
	Completed           bool                  `json:"completed"`
	CompletedAt         time.Time             `json:"completed_at"`
	AuthorizationDigest string                `json:"authorization_digest"`
	AuditDigest         string                `json:"audit_digest"`
}

// HistoryObligations is the private operator-supplied snapshot. Now is the
// caller's clock; it is never read from the snapshot file.
type HistoryObligations struct {
	Now                time.Time           `json:"-"`
	ObservedAt         time.Time           `json:"observed_at"`
	MaxEvidenceAgeSecs int64               `json:"max_evidence_age_seconds"`
	Origin             HistoryOrigin       `json:"origin"`
	Access             []HistoryAccess     `json:"access"`
	Boundary           *HistoryBoundary    `json:"boundary"`
	Obligations        []HistoryObligation `json:"obligations"`
	CompletionSteps    []string            `json:"completion_steps"`
}

// HistoryState is the closed state of one obligation at evaluation time.
type HistoryState string

const (
	HistoryStateOpen      HistoryState = "open"
	HistoryStateOverdue   HistoryState = "overdue"
	HistoryStateCompleted HistoryState = "completed"
	HistoryStateInvalid   HistoryState = "invalid"
)

// HistoryObligationStatus is the private evaluation of one obligation.
type HistoryObligationStatus struct {
	Kind          HistoryObligationKind `json:"kind"`
	State         HistoryState          `json:"state"`
	DueAt         time.Time             `json:"due_at"`
	DaysRemaining int                   `json:"days_remaining"`
	ReminderDue   bool                  `json:"reminder_due"`
}

// HistoryReport is the PRIVATE status. Clear means "history does not block
// closure"; it never means obligations are complete, and it never authorizes
// deleting or exporting anything.
type HistoryReport struct {
	SchemaVersion int                       `json:"schema_version"`
	EvaluatedAt   time.Time                 `json:"evaluated_at"`
	Clear         bool                      `json:"clear"`
	Blockers      []HistoryCode             `json:"blockers"`
	Obligations   []HistoryObligationStatus `json:"obligations"`
	Open          int                       `json:"open"`
	Overdue       int                       `json:"overdue"`
	Completed     int                       `json:"completed"`
	RemindersDue  int                       `json:"reminders_due"`
	ActiveReaders int                       `json:"active_readers"`
	ActiveWriters int                       `json:"active_writers"`
	BoundaryShown bool                      `json:"boundary_visible"`
	Digest        string                    `json:"digest"`
}

// HistoryReaderKey derives the keyed pseudonym of a reader identity:
// HMAC-SHA-256 (domain separated) in lowercase hex. Only the result may be
// stored in HistoryObligations; the key and the raw identity stay with the
// operator.
func HistoryReaderKey(key []byte, raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if len(key) < 32 || raw == "" {
		return "", errors.New("reader key needs a secret of at least 32 bytes and a non-empty identity")
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("soundpost/adoption/history-reader/v1\x00"))
	mac.Write([]byte(raw))
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func historyDigestOK(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func historyDay(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format("2006-01-02")
}

func historyClassifyStep(raw string) (HistoryStepKind, HistoryCode) {
	step := strings.ToLower(strings.TrimSpace(raw))
	switch HistoryStepKind(step) {
	case HistoryStepRetain, HistoryStepRemind, HistoryStepVerifyReadOnly:
		return HistoryStepKind(step), ""
	}
	for _, frag := range []string{"delet", "remov", "purg", "drop", "decommission", "truncat", "wipe", "eras", "destroy", "shred", "expire", "cleanup", "clean_up", "retire"} {
		if strings.Contains(step, frag) {
			return "", HistoryCodeRemovalStep
		}
	}
	for _, frag := range []string{"import", "migrat", "ingest", "backfill"} {
		if strings.Contains(step, frag) {
			return "", HistoryCodeImportStep
		}
	}
	return "", HistoryCodeUnsupportedStep
}

// HistoryStatus evaluates the obligations around retained legacy history at the
// caller-supplied clock. Evidence defects are blockers in the report; only an
// unusable call (no clock, bad bounds, cancelled context) is an error.
func HistoryStatus(ctx context.Context, in HistoryObligations) (HistoryReport, error) {
	if err := ctx.Err(); err != nil {
		return HistoryReport{}, err
	}
	if in.Now.IsZero() {
		return HistoryReport{}, errors.New("a caller-supplied clock is required")
	}
	if in.MaxEvidenceAgeSecs <= 0 || in.MaxEvidenceAgeSecs > historyMaxAgeSeconds {
		return HistoryReport{}, errors.New("evidence age bound must be 1 second to 30 days")
	}
	if len(in.Access) > historyMaxItems || len(in.Obligations) > historyMaxItems || len(in.CompletionSteps) > historyMaxItems {
		return HistoryReport{}, errors.New("too many history records")
	}
	now := in.Now.UTC()
	blockers := map[HistoryCode]bool{}
	block := func(c HistoryCode) { blockers[c] = true }
	report := HistoryReport{SchemaVersion: historySchemaVersion, EvaluatedAt: now, Blockers: []HistoryCode{}, Obligations: []HistoryObligationStatus{}}

	switch {
	case in.ObservedAt.IsZero() || now.Sub(in.ObservedAt) > time.Duration(in.MaxEvidenceAgeSecs)*time.Second:
		block(HistoryCodeEvidenceStale)
	case in.ObservedAt.After(now):
		block(HistoryCodeEvidenceFuture)
	}

	// Origin: read-only, and retained until every obligation is complete.
	if !in.Origin.ReadOnly || !historyDigestOK(in.Origin.EvidenceDigest) {
		block(HistoryCodeOriginNotReadOnly)
	}

	// Access: keyed pseudonyms only; any write access that is not provably
	// over blocks closure.
	activeReaders := map[string]bool{}
	for _, a := range in.Access {
		if !historyDigestOK(a.ReaderKey) {
			block(HistoryCodeReaderNotKeyed)
		}
		if !historyDigestOK(a.AuthorizationDigest) {
			block(HistoryCodeAccessUnauthorized)
		}
		windowOK := !a.NotBefore.IsZero() && !a.ExpiresAt.IsZero() && a.ExpiresAt.After(a.NotBefore)
		over := !a.RevokedAt.IsZero() && !a.RevokedAt.After(now) || !a.ExpiresAt.IsZero() && !a.ExpiresAt.After(now)
		switch a.Mode {
		case HistoryAccessRead:
			if !windowOK {
				block(HistoryCodeAccessInvalid)
			} else if !over && !a.NotBefore.After(now) {
				activeReaders[a.ReaderKey] = true
			}
		case HistoryAccessWrite:
			if !windowOK {
				block(HistoryCodeAccessInvalid)
			}
			if !over {
				block(HistoryCodeWriteAccess)
				report.ActiveWriters++
			}
		default:
			block(HistoryCodeAccessInvalid)
			block(HistoryCodeWriteAccess) // an unknown mode may be a write.
			report.ActiveWriters++
		}
	}
	report.ActiveReaders = len(activeReaders)

	// Visible cutover boundary: read-only, authorization-gated deep links.
	if b := in.Boundary; b == nil || b.CutoverAt.IsZero() || b.CutoverAt.After(now) || b.Links <= 0 || !historyDigestOK(b.MetadataDigest) {
		block(HistoryCodeBoundaryMissing)
	} else {
		report.BoundaryShown = b.Visible
		if !b.Visible {
			block(HistoryCodeBoundaryNotVisible)
		}
		if !b.LinksReadOnly {
			block(HistoryCodeBoundaryNotReadOnly)
		}
		if !b.LinksRequireAuthorization {
			block(HistoryCodeBoundaryUnauthorized)
		}
	}

	// Obligations.
	seen := map[HistoryObligationKind]int{}
	for _, o := range in.Obligations {
		st := HistoryObligationStatus{Kind: o.Kind, DueAt: o.DueAt, State: HistoryStateOpen}
		valid := true
		switch o.Kind {
		case HistoryKindRetention, HistoryKindHold, HistoryKindExport:
		default:
			block(HistoryCodeObligationInvalid)
			st.Kind, st.State = "", HistoryStateInvalid
			report.Obligations = append(report.Obligations, st)
			continue
		}
		seen[o.Kind]++
		if o.Kind != HistoryKindHold && seen[o.Kind] > 1 {
			block(HistoryCodeObligationDuplicate)
		}
		if !historyDigestOK(o.RecordDigest) {
			valid = false
			if o.Kind == HistoryKindExport {
				block(HistoryCodeExportRecordMissing)
			} else {
				block(HistoryCodeRecordMissing)
			}
		}
		if o.DueAt.IsZero() {
			valid = false
			block(HistoryCodeObligationInvalid)
		}
		switch {
		case o.Completed:
			st.State = HistoryStateCompleted
			if o.CompletedAt.IsZero() || o.CompletedAt.After(now) {
				valid = false
				block(HistoryCodeCompletionInvalid)
			}
			if !historyDigestOK(o.AuthorizationDigest) || !historyDigestOK(o.AuditDigest) {
				valid = false
				block(HistoryCodeCompletionUnaudited)
			}
			report.Completed++
		case !o.DueAt.IsZero() && !o.DueAt.After(now):
			st.State = HistoryStateOverdue
			report.Overdue++
			report.Open++
			switch o.Kind {
			case HistoryKindRetention:
				block(HistoryCodeRetentionOverdue)
			case HistoryKindExport:
				block(HistoryCodeExportOverdue)
			default:
				block(HistoryCodeHoldOverdue)
			}
		default:
			report.Open++
		}
		if !o.Completed {
			if o.ReminderLeadDays <= 0 || o.ReminderLeadDays > historyMaxReminder {
				block(HistoryCodeReminderMissing)
			} else if !o.DueAt.IsZero() {
				st.DaysRemaining = int(o.DueAt.Sub(now) / (24 * time.Hour))
				if !now.Before(o.DueAt.AddDate(0, 0, -o.ReminderLeadDays)) {
					st.ReminderDue = true
					report.RemindersDue++
				}
			}
		}
		if !valid {
			st.State = HistoryStateInvalid
		}
		report.Obligations = append(report.Obligations, st)
	}
	if seen[HistoryKindRetention] == 0 {
		block(HistoryCodeRetentionMissing)
	}
	if seen[HistoryKindExport] == 0 {
		block(HistoryCodeExportMissing)
		block(HistoryCodeExportRecordMissing)
	}

	// Retention continues until obligations are complete: history that is gone
	// while any obligation is open (or invalid) is a silent removal.
	if !in.Origin.Retained {
		unfinished := len(in.Obligations) == 0
		for _, o := range in.Obligations {
			if !o.Completed {
				unfinished = true
			}
		}
		if unfinished {
			block(HistoryCodeHistoryRemoved)
		}
	}

	// A closure plan may only retain, remind and verify. Removal and import
	// are never completion steps.
	for _, step := range in.CompletionSteps {
		if _, code := historyClassifyStep(step); code != "" {
			block(code)
		}
	}

	for c := range blockers {
		report.Blockers = append(report.Blockers, c)
	}
	sort.Slice(report.Blockers, func(i, j int) bool { return report.Blockers[i] < report.Blockers[j] })
	report.Clear = len(report.Blockers) == 0
	raw, err := json.Marshal(report)
	if err != nil {
		return HistoryReport{}, err
	}
	sum := sha256.Sum256(raw)
	report.Digest = hex.EncodeToString(sum[:])
	return report, nil
}

// HistoryPublicSummary is the closed public projection of a HistoryReport:
// counts, booleans and members of the HistoryCode enum. It has no identifier,
// reader key, digest, path or time. CustomerAcceptance is always false.
type HistoryPublicSummary struct {
	SchemaVersion      int           `json:"schema_version"`
	Clear              bool          `json:"clear"`
	ObligationsOpen    int           `json:"obligations_open"`
	ObligationsOverdue int           `json:"obligations_overdue"`
	ObligationsDone    int           `json:"obligations_completed"`
	RemindersDue       int           `json:"reminders_due"`
	ActiveReaders      int           `json:"active_readers"`
	ActiveWriters      int           `json:"active_writers"`
	BoundaryVisible    bool          `json:"boundary_visible"`
	Blockers           []HistoryCode `json:"blockers"`
	CustomerAcceptance bool          `json:"customer_acceptance"`
}

// HistoryPublicProjection copies only counts and enum members.
func HistoryPublicProjection(r HistoryReport) HistoryPublicSummary {
	out := HistoryPublicSummary{
		SchemaVersion: historySchemaVersion, Clear: r.Clear && len(r.Blockers) == 0,
		ObligationsOpen: r.Open, ObligationsOverdue: r.Overdue, ObligationsDone: r.Completed,
		RemindersDue: r.RemindersDue, ActiveReaders: r.ActiveReaders, ActiveWriters: r.ActiveWriters,
		BoundaryVisible: r.BoundaryShown, Blockers: []HistoryCode{},
	}
	for _, c := range r.Blockers {
		if historyCodes[c] {
			out.Blockers = append(out.Blockers, c)
		}
	}
	return out
}
