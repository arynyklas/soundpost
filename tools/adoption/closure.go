// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Closing an adoption means: the verified readiness gate is complete and fresh,
// legacy history obligations do not block, and an independent deadman proved
// itself during a real all-Soundpost-processes-stopped outage while legacy
// history stayed readable and all three journeys recovered. This file decides
// that from evidence supplied by the operator. It never performs a drill,
// deletes, exports or imports anything, and never certifies a customer.

// ClosureCriterion is the closed set of generic criteria a verified ready gate
// must cover. The operator maps a verified gate onto these names (see
// docs/adoption/closure.md); closure does not re-derive them.
type ClosureCriterion string

const (
	ClosureCriterionJourneyGateway   ClosureCriterion = "journey_gateway_dependency"
	ClosureCriterionJourneyFrontend  ClosureCriterion = "journey_frontend_api_db"
	ClosureCriterionJourneyScheduler ClosureCriterion = "journey_scheduler_retry"
	ClosureCriterionSourcePolicy     ClosureCriterion = "source_policy"
	ClosureCriterionQueryProfile     ClosureCriterion = "query_profile"
	ClosureCriterionIsolation        ClosureCriterion = "tenant_isolation_matrix"
	ClosureCriterionDeliveryPolicy   ClosureCriterion = "delivery_policy"
	ClosureCriterionDeletionRestore  ClosureCriterion = "deletion_restore"
	ClosureCriterionDeadmanDomain    ClosureCriterion = "external_deadman_failure_domain"
	ClosureCriterionRetentionExport  ClosureCriterion = "retention_export_record"
)

var closureRequiredCriteria = []ClosureCriterion{
	ClosureCriterionJourneyGateway, ClosureCriterionJourneyFrontend, ClosureCriterionJourneyScheduler,
	ClosureCriterionSourcePolicy, ClosureCriterionQueryProfile, ClosureCriterionIsolation,
	ClosureCriterionDeliveryPolicy, ClosureCriterionDeletionRestore, ClosureCriterionDeadmanDomain,
	ClosureCriterionRetentionExport,
}

// ClosureJourney names the three actual journeys the outage must have
// recovered.
type ClosureJourney string

const (
	ClosureJourneyGateway   ClosureJourney = "gateway_dependency"
	ClosureJourneyFrontend  ClosureJourney = "frontend_api_db"
	ClosureJourneyScheduler ClosureJourney = "scheduler_retry"
)

var closureJourneys = []ClosureJourney{ClosureJourneyGateway, ClosureJourneyFrontend, ClosureJourneyScheduler}

// ClosureArea says which evidence a blocker comes from.
type ClosureArea string

const (
	ClosureAreaGate    ClosureArea = "gate"
	ClosureAreaHistory ClosureArea = "history"
	ClosureAreaDeadman ClosureArea = "deadman"
)

// ClosureCode is the closed vocabulary of gate and deadman blockers. History
// blockers reuse HistoryCode under ClosureAreaHistory.
type ClosureCode string

const (
	ClosureCodeGateMissing        ClosureCode = "gate_missing"
	ClosureCodeGateFuture         ClosureCode = "gate_future_dated"
	ClosureCodeGateStale          ClosureCode = "gate_stale"
	ClosureCodeCriterionMissing   ClosureCode = "gate_criterion_missing"
	ClosureCodeCriterionUnknown   ClosureCode = "gate_criterion_unknown"
	ClosureCodeProofMissing       ClosureCode = "deadman_proof_missing"
	ClosureCodeProofUnsigned      ClosureCode = "deadman_proof_unsigned"
	ClosureCodeProofUntrustedKey  ClosureCode = "deadman_proof_untrusted_key"
	ClosureCodeProofBadSignature  ClosureCode = "deadman_proof_bad_signature"
	ClosureCodeProofMalformed     ClosureCode = "deadman_proof_malformed"
	ClosureCodeProofExpired       ClosureCode = "deadman_proof_expired"
	ClosureCodeProofFuture        ClosureCode = "deadman_proof_future_dated"
	ClosureCodeProofStale         ClosureCode = "deadman_proof_stale"
	ClosureCodeProofWrongScope    ClosureCode = "deadman_proof_wrong_scope"
	ClosureCodeDomainUnrecorded   ClosureCode = "deadman_domain_unrecorded"
	ClosureCodeSharesProcess      ClosureCode = "deadman_shares_process_domain"
	ClosureCodeSharesHost         ClosureCode = "deadman_shares_host_domain"
	ClosureCodeSharesCluster      ClosureCode = "deadman_shares_cluster_domain"
	ClosureCodeSharesCredential   ClosureCode = "deadman_shares_credential_domain"
	ClosureCodeOutageWindow       ClosureCode = "outage_window_invalid"
	ClosureCodeOutageNotAllStop   ClosureCode = "outage_not_all_processes_stopped"
	ClosureCodeDeliveryMissing    ClosureCode = "deadman_delivery_missing"
	ClosureCodeRouteNotIndep      ClosureCode = "deadman_route_not_independent"
	ClosureCodeDeliveryOutside    ClosureCode = "deadman_delivery_outside_outage"
	ClosureCodeHistoryReadMissing ClosureCode = "outage_history_read_missing"
	ClosureCodeHistoryReadOutside ClosureCode = "outage_history_read_outside_window"
	ClosureCodeJourneysNotRecov   ClosureCode = "journeys_not_recovered"
)

var closureCodes = map[ClosureCode]bool{
	ClosureCodeGateMissing: true, ClosureCodeGateFuture: true, ClosureCodeGateStale: true,
	ClosureCodeCriterionMissing: true, ClosureCodeCriterionUnknown: true, ClosureCodeProofMissing: true,
	ClosureCodeProofUnsigned: true, ClosureCodeProofUntrustedKey: true, ClosureCodeProofBadSignature: true,
	ClosureCodeProofMalformed: true, ClosureCodeProofExpired: true, ClosureCodeProofFuture: true,
	ClosureCodeProofStale: true, ClosureCodeProofWrongScope: true, ClosureCodeDomainUnrecorded: true,
	ClosureCodeSharesProcess: true, ClosureCodeSharesHost: true, ClosureCodeSharesCluster: true,
	ClosureCodeSharesCredential: true, ClosureCodeOutageWindow: true, ClosureCodeOutageNotAllStop: true,
	ClosureCodeDeliveryMissing: true, ClosureCodeRouteNotIndep: true, ClosureCodeDeliveryOutside: true,
	ClosureCodeHistoryReadMissing: true, ClosureCodeHistoryReadOutside: true, ClosureCodeJourneysNotRecov: true,
}

// ClosureRoute is how the deadman's alert reached a human.
type ClosureRoute string

const (
	// ClosureRouteIndependentOperator: an operator-owned route that does not
	// pass through any Soundpost process, host, cluster or credential.
	ClosureRouteIndependentOperator ClosureRoute = "independent_operator"
	ClosureRouteProductChannel      ClosureRoute = "product_channel"
)

const (
	closureSchemaVersion = 1
	closureProofPurpose  = "soundpost/adoption/deadman-proof/v1"
	closureMinOutage     = time.Minute
	closureMaxProofLife  = 30 * 24 * time.Hour
	closureMaxPayload    = 64 << 10
	closureMaxLabel      = 128
)

// ClosureFailureDomain names what a component's survival depends on. Labels
// are opaque operator-chosen tokens (compared case-insensitively); none is
// ever published.
type ClosureFailureDomain struct {
	Process    string `json:"process"`
	Host       string `json:"host"`
	Cluster    string `json:"cluster"`
	Credential string `json:"credential"`
}

// ClosureOutage is the recorded window in which every Soundpost process was
// stopped, with the process counts the operator's stop evidence covers.
type ClosureOutage struct {
	StartedAt          time.Time `json:"started_at"`
	EndedAt            time.Time `json:"ended_at"`
	ProcessesObserved  int       `json:"processes_observed"`
	ProcessesStopped   int       `json:"processes_stopped"`
	StopEvidenceDigest string    `json:"stop_evidence_digest"`
}

// ClosureDelivery is the observed arrival of the deadman alert.
type ClosureDelivery struct {
	Route         ClosureRoute `json:"route"`
	ObservedAt    time.Time    `json:"observed_at"`
	ReceiptDigest string       `json:"receipt_digest"`
}

// ClosureHistoryRead is the observed read of legacy history during the outage.
type ClosureHistoryRead struct {
	ObservedAt    time.Time `json:"observed_at"`
	Readable      bool      `json:"readable"`
	ReadOnly      bool      `json:"read_only"`
	ReceiptDigest string    `json:"receipt_digest"`
}

// ClosureRecovery is one journey observed working again after the outage.
type ClosureRecovery struct {
	Journey        ClosureJourney `json:"journey"`
	RecoveredAt    time.Time      `json:"recovered_at"`
	EvidenceDigest string         `json:"evidence_digest"`
}

// ClosureDeadmanProof is the attested content of one outage drill. It is only
// trusted inside a verified ClosureProofEnvelope.
type ClosureDeadmanProof struct {
	Purpose       string               `json:"purpose"`
	Scope         string               `json:"scope"`
	IssuedAt      time.Time            `json:"issued_at"`
	ExpiresAt     time.Time            `json:"expires_at"`
	ProductDomain ClosureFailureDomain `json:"product_domain"`
	DeadmanDomain ClosureFailureDomain `json:"deadman_domain"`
	Outage        ClosureOutage        `json:"outage"`
	Delivery      ClosureDelivery      `json:"delivery"`
	HistoryRead   ClosureHistoryRead   `json:"history_read"`
	Recoveries    []ClosureRecovery    `json:"recoveries"`
}

// ClosureProofEnvelope is an ed25519 signature over the exact payload bytes.
// The signer is the independent operator route's attestor, never the product.
type ClosureProofEnvelope struct {
	KeyID     string `json:"key_id"`
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
}

func closureSigned(payload []byte) []byte {
	return append([]byte(closureProofPurpose+"\x00"), payload...)
}

// ClosureSignProof serializes and signs a proof. It is the attestor's side of
// the contract (it runs in the deadman's own failure domain with its own key);
// the product never holds this key.
func ClosureSignProof(key ed25519.PrivateKey, keyID string, proof ClosureDeadmanProof) (ClosureProofEnvelope, error) {
	if len(key) != ed25519.PrivateKeySize || strings.TrimSpace(keyID) == "" {
		return ClosureProofEnvelope{}, errors.New("signing needs an ed25519 key and a key ID")
	}
	payload, err := json.Marshal(proof)
	if err != nil {
		return ClosureProofEnvelope{}, err
	}
	return ClosureProofEnvelope{KeyID: keyID, Payload: payload, Signature: ed25519.Sign(key, closureSigned(payload))}, nil
}

// ClosureGate is the evidence of one verified ready gate, mapped by the
// operator: the gate's digest, when it was verified and the criteria it covers.
type ClosureGate struct {
	Digest     string             `json:"digest"`
	VerifiedAt time.Time          `json:"verified_at"`
	Criteria   []ClosureCriterion `json:"criteria"`
}

// ClosureLedger is everything closure decides on. Now and Trust come from the
// caller, never from the file: a ledger cannot vouch for its own clock or
// signer.
type ClosureLedger struct {
	Now                time.Time                    `json:"-"`
	Trust              map[string]ed25519.PublicKey `json:"-"`
	Scope              string                       `json:"scope"`
	MaxEvidenceAgeSecs int64                        `json:"max_evidence_age_seconds"`
	Gate               ClosureGate                  `json:"gate"`
	History            HistoryObligations           `json:"history"`
	DeadmanProof       *ClosureProofEnvelope        `json:"deadman_proof"`
}

// ClosureBlocker is one reason closure is refused.
type ClosureBlocker struct {
	Area ClosureArea `json:"area"`
	Code string      `json:"code"`
}

// ClosureReport is the PRIVATE closure decision.
type ClosureReport struct {
	SchemaVersion       int                `json:"schema_version"`
	EvaluatedAt         time.Time          `json:"evaluated_at"`
	Closed              bool               `json:"closed"`
	Blockers            []ClosureBlocker   `json:"blockers"`
	MissingCriteria     []ClosureCriterion `json:"missing_criteria"`
	CriteriaCovered     int                `json:"criteria_covered"`
	ProofVerified       bool               `json:"proof_verified"`
	DeadmanIndependent  bool               `json:"deadman_independent"`
	DeliveryInOutage    bool               `json:"delivery_during_outage"`
	HistoryReadInOutage bool               `json:"history_readable_during_outage"`
	JourneysRecovered   int                `json:"journeys_recovered"`
	GateVerifiedAt      time.Time          `json:"gate_verified_at"`
	OutageStartedAt     time.Time          `json:"outage_started_at"`
	GateDigest          string             `json:"gate_digest"`
	ProofDigest         string             `json:"proof_digest"`
	History             HistoryReport      `json:"history"`
	EvidenceDigest      string             `json:"evidence_digest"`
}

func closureLabelOK(s string) bool {
	s = strings.TrimSpace(s)
	return s != "" && len(s) <= closureMaxLabel
}

func closureScopeOK(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '/' || c == '-') {
			return false
		}
	}
	return true
}

func closureSameLabel(a, b string) bool {
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}

type closureFacts struct {
	verified    bool
	independent bool
	delivery    bool
	historyRead bool
	recovered   int
	outageStart time.Time
	payloadSum  string
}

// closureInWindow reports whether t lies in [from, to]. Callers establish that
// the window itself is valid (recorded, ordered, long enough) before asking.
func closureInWindow(t, from, to time.Time) bool {
	return !t.Before(from) && !t.After(to)
}

// closureVerifyProof verifies the signature first and only then reads the
// payload. A proof that fails verification contributes no facts.
func closureVerifyProof(env *ClosureProofEnvelope, l ClosureLedger, now time.Time) (closureFacts, []ClosureCode) {
	var facts closureFacts
	if env == nil || (len(env.Payload) == 0 && len(env.Signature) == 0 && env.KeyID == "") {
		return facts, []ClosureCode{ClosureCodeProofMissing}
	}
	if len(env.Signature) == 0 || env.KeyID == "" {
		return facts, []ClosureCode{ClosureCodeProofUnsigned}
	}
	pub, ok := l.Trust[env.KeyID]
	if !ok || len(pub) != ed25519.PublicKeySize {
		return facts, []ClosureCode{ClosureCodeProofUntrustedKey}
	}
	if len(env.Payload) == 0 || len(env.Payload) > closureMaxPayload || !ed25519.Verify(pub, closureSigned(env.Payload), env.Signature) {
		return facts, []ClosureCode{ClosureCodeProofBadSignature}
	}
	sum := sha256.Sum256(env.Payload)
	facts.payloadSum = hex.EncodeToString(sum[:])
	var p ClosureDeadmanProof
	if decodeStrict(bytes.NewReader(env.Payload), &p) != nil {
		return facts, []ClosureCode{ClosureCodeProofMalformed}
	}
	facts.verified = true
	codes := map[ClosureCode]bool{}
	bad := func(c ClosureCode) { codes[c] = true }

	if p.Purpose != closureProofPurpose || p.Scope != l.Scope {
		bad(ClosureCodeProofWrongScope)
	}
	switch {
	case p.IssuedAt.IsZero() || p.ExpiresAt.IsZero() || !p.ExpiresAt.After(p.IssuedAt) || p.ExpiresAt.Sub(p.IssuedAt) > closureMaxProofLife:
		bad(ClosureCodeProofMalformed)
	case p.IssuedAt.After(now):
		bad(ClosureCodeProofFuture)
	case !p.ExpiresAt.After(now):
		bad(ClosureCodeProofExpired)
	case now.Sub(p.IssuedAt) > time.Duration(l.MaxEvidenceAgeSecs)*time.Second:
		bad(ClosureCodeProofStale)
	}

	// Independence: every failure-domain dimension must differ from the product's.
	pd, dd := p.ProductDomain, p.DeadmanDomain
	pairs := []struct {
		product, deadman string
		code             ClosureCode
	}{
		{pd.Process, dd.Process, ClosureCodeSharesProcess}, {pd.Host, dd.Host, ClosureCodeSharesHost},
		{pd.Cluster, dd.Cluster, ClosureCodeSharesCluster}, {pd.Credential, dd.Credential, ClosureCodeSharesCredential},
	}
	facts.independent = true
	for _, pair := range pairs {
		if !closureLabelOK(pair.product) || !closureLabelOK(pair.deadman) {
			bad(ClosureCodeDomainUnrecorded)
			facts.independent = false
		} else if closureSameLabel(pair.product, pair.deadman) {
			bad(pair.code)
			facts.independent = false
		}
	}

	// Outage window: all Soundpost processes stopped, for a real interval that
	// ended before the proof was issued.
	o := p.Outage
	windowOK := !o.StartedAt.IsZero() && !o.EndedAt.IsZero() && o.EndedAt.Sub(o.StartedAt) >= closureMinOutage && !o.EndedAt.After(p.IssuedAt)
	if !windowOK {
		bad(ClosureCodeOutageWindow)
	} else {
		facts.outageStart = o.StartedAt
	}
	if o.ProcessesObserved <= 0 || o.ProcessesStopped != o.ProcessesObserved || !historyDigestOK(o.StopEvidenceDigest) {
		bad(ClosureCodeOutageNotAllStop)
	}

	// Observed delivery through an independent operator route, inside the window.
	d := p.Delivery
	switch {
	case d.Route != ClosureRouteIndependentOperator && d.Route != "":
		bad(ClosureCodeRouteNotIndep)
	case d.Route == "" || d.ObservedAt.IsZero() || !historyDigestOK(d.ReceiptDigest):
		bad(ClosureCodeDeliveryMissing)
	}
	if d.Route == ClosureRouteIndependentOperator && !d.ObservedAt.IsZero() && historyDigestOK(d.ReceiptDigest) {
		if windowOK && closureInWindow(d.ObservedAt, o.StartedAt, o.EndedAt) {
			facts.delivery = true
		} else {
			bad(ClosureCodeDeliveryOutside)
		}
	}

	// Legacy history readable (and still read-only) during the outage.
	h := p.HistoryRead
	switch {
	case !h.Readable || !h.ReadOnly || h.ObservedAt.IsZero() || !historyDigestOK(h.ReceiptDigest):
		bad(ClosureCodeHistoryReadMissing)
	case !windowOK || !closureInWindow(h.ObservedAt, o.StartedAt, o.EndedAt):
		bad(ClosureCodeHistoryReadOutside)
	default:
		facts.historyRead = true
	}

	// All three journeys recovered after the outage ended, each exactly once.
	seen := map[ClosureJourney]bool{}
	allValid := true
	for _, r := range p.Recoveries {
		known := false
		for _, j := range closureJourneys {
			known = known || j == r.Journey
		}
		if !known || seen[r.Journey] {
			allValid = false
			continue
		}
		seen[r.Journey] = true
		if !windowOK || r.RecoveredAt.Before(o.EndedAt) || r.RecoveredAt.After(p.IssuedAt) || !historyDigestOK(r.EvidenceDigest) {
			allValid = false
			continue
		}
		facts.recovered++
	}
	if !allValid || facts.recovered != len(closureJourneys) {
		bad(ClosureCodeJourneysNotRecov)
	}

	out := make([]ClosureCode, 0, len(codes))
	for c := range codes {
		out = append(out, c)
	}
	return facts, out
}

// CloseAdoption decides whether the adoption can be closed. Evidence defects
// are blockers in the returned report (Closed=false, nil error); only an
// unusable call is an error. Closing never deletes, exports or imports history:
// retention continues until the history's owner completes obligations through
// a separately authorized, audited action.
func CloseAdoption(ctx context.Context, l ClosureLedger) (ClosureReport, error) {
	if err := ctx.Err(); err != nil {
		return ClosureReport{}, err
	}
	if !closureScopeOK(l.Scope) {
		return ClosureReport{}, errors.New("closure scope must be 1-64 characters of a-z 0-9 . _ / -")
	}
	if l.MaxEvidenceAgeSecs <= 0 || l.MaxEvidenceAgeSecs > historyMaxAgeSeconds {
		return ClosureReport{}, errors.New("evidence age bound must be 1 second to 30 days")
	}
	now := l.Now.UTC()
	h := l.History
	switch {
	case h.Now.IsZero():
		h.Now = now
	case !h.Now.Equal(now):
		return ClosureReport{}, errors.New("history clock differs from the closure clock")
	}
	if h.MaxEvidenceAgeSecs == 0 {
		h.MaxEvidenceAgeSecs = l.MaxEvidenceAgeSecs
	}
	history, err := HistoryStatus(ctx, h)
	if err != nil {
		return ClosureReport{}, err
	}
	report := ClosureReport{SchemaVersion: closureSchemaVersion, EvaluatedAt: now, Blockers: []ClosureBlocker{}, MissingCriteria: []ClosureCriterion{}, History: history}
	block := func(area ClosureArea, code string) {
		report.Blockers = append(report.Blockers, ClosureBlocker{Area: area, Code: code})
	}
	for _, c := range history.Blockers {
		block(ClosureAreaHistory, string(c))
	}

	// Gate evidence: present, fresh, complete.
	g := l.Gate
	switch {
	case g.VerifiedAt.IsZero() || !historyDigestOK(g.Digest):
		block(ClosureAreaGate, string(ClosureCodeGateMissing))
	case g.VerifiedAt.After(now):
		block(ClosureAreaGate, string(ClosureCodeGateFuture))
	case now.Sub(g.VerifiedAt) > time.Duration(l.MaxEvidenceAgeSecs)*time.Second:
		block(ClosureAreaGate, string(ClosureCodeGateStale))
	default:
		report.GateDigest, report.GateVerifiedAt = g.Digest, g.VerifiedAt.UTC()
	}
	covered := map[ClosureCriterion]bool{}
	unknown := false
	for _, c := range g.Criteria {
		known := false
		for _, r := range closureRequiredCriteria {
			known = known || r == c
		}
		if known {
			covered[c] = true
		} else {
			unknown = true
		}
	}
	if unknown {
		block(ClosureAreaGate, string(ClosureCodeCriterionUnknown))
	}
	for _, r := range closureRequiredCriteria {
		if covered[r] {
			report.CriteriaCovered++
		} else {
			report.MissingCriteria = append(report.MissingCriteria, r)
		}
	}
	if len(report.MissingCriteria) > 0 {
		block(ClosureAreaGate, string(ClosureCodeCriterionMissing))
	}

	// Independent deadman proof.
	facts, codes := closureVerifyProof(l.DeadmanProof, l, now)
	for _, c := range codes {
		block(ClosureAreaDeadman, string(c))
	}
	report.ProofVerified = facts.verified
	report.DeadmanIndependent = facts.independent
	report.DeliveryInOutage, report.HistoryReadInOutage = facts.delivery, facts.historyRead
	report.JourneysRecovered, report.OutageStartedAt, report.ProofDigest = facts.recovered, facts.outageStart.UTC(), facts.payloadSum

	sort.Slice(report.Blockers, func(i, j int) bool {
		a, b := report.Blockers[i], report.Blockers[j]
		return a.Area < b.Area || a.Area == b.Area && a.Code < b.Code
	})
	report.Closed = len(report.Blockers) == 0
	if report.Closed {
		sum := sha256.Sum256([]byte("soundpost/adoption/closure/v1\x00" + l.Scope + "\x00" + report.GateDigest + "\x00" + report.ProofDigest + "\x00" + history.Digest))
		report.EvidenceDigest = hex.EncodeToString(sum[:])
	}
	return report, nil
}

// ClosurePublicSummary is the closed public projection of a ClosureReport:
// counts, booleans, UTC dates at day granularity, digests the tool validated
// as 64-character hex, and members of closed enums. No identifier, label, path,
// time of day or free text is copied from private evidence.
// CustomerAcceptance is always false: this tool never certifies a customer.
type ClosurePublicSummary struct {
	SchemaVersion       int                    `json:"schema_version"`
	Closed              bool                   `json:"closed"`
	EvaluatedDay        string                 `json:"evaluated_day"`
	GateVerifiedDay     string                 `json:"gate_verified_day"`
	OutageDay           string                 `json:"outage_day"`
	CriteriaRequired    int                    `json:"criteria_required"`
	CriteriaCovered     int                    `json:"criteria_covered"`
	JourneysRecovered   int                    `json:"journeys_recovered"`
	DeadmanIndependent  bool                   `json:"deadman_independent"`
	DeliveryInOutage    bool                   `json:"delivery_during_outage"`
	HistoryReadInOutage bool                   `json:"history_readable_during_outage"`
	HistoryClear        bool                   `json:"history_clear"`
	ObligationsOpen     int                    `json:"obligations_open"`
	ObligationsDone     int                    `json:"obligations_completed"`
	GateDigest          string                 `json:"gate_digest"`
	DeadmanProofDigest  string                 `json:"deadman_proof_digest"`
	HistoryDigest       string                 `json:"history_digest"`
	EvidenceDigest      string                 `json:"evidence_digest"`
	Blockers            []ClosurePublicBlocker `json:"blockers"`
	CustomerAcceptance  bool                   `json:"customer_acceptance"`
}

// ClosurePublicBlocker is an (area, code) pair, both from closed enums.
type ClosurePublicBlocker struct {
	Area ClosureArea `json:"area"`
	Code string      `json:"code"`
}

func closureHexOrEmpty(s string) string {
	if historyDigestOK(s) {
		return s
	}
	return ""
}

// ClosurePublicProjection derives the public summary. Anything outside the
// closed enums is dropped; a closed summary requires a consistent report.
func ClosurePublicProjection(r ClosureReport) ClosurePublicSummary {
	out := ClosurePublicSummary{
		SchemaVersion: closureSchemaVersion, EvaluatedDay: historyDay(r.EvaluatedAt), GateVerifiedDay: historyDay(r.GateVerifiedAt),
		OutageDay: historyDay(r.OutageStartedAt), CriteriaRequired: len(closureRequiredCriteria), CriteriaCovered: r.CriteriaCovered,
		JourneysRecovered: r.JourneysRecovered, DeadmanIndependent: r.DeadmanIndependent, DeliveryInOutage: r.DeliveryInOutage,
		HistoryReadInOutage: r.HistoryReadInOutage, HistoryClear: r.History.Clear, ObligationsOpen: r.History.Open,
		ObligationsDone: r.History.Completed, GateDigest: closureHexOrEmpty(r.GateDigest),
		DeadmanProofDigest: closureHexOrEmpty(r.ProofDigest), HistoryDigest: closureHexOrEmpty(r.History.Digest),
		Blockers: []ClosurePublicBlocker{},
	}
	for _, b := range r.Blockers {
		known := b.Area == ClosureAreaHistory && historyCodes[HistoryCode(b.Code)] ||
			(b.Area == ClosureAreaGate || b.Area == ClosureAreaDeadman) && closureCodes[ClosureCode(b.Code)]
		if known {
			out.Blockers = append(out.Blockers, ClosurePublicBlocker{Area: b.Area, Code: b.Code})
		}
	}
	out.Closed = r.Closed && len(r.Blockers) == 0 && len(out.Blockers) == 0
	if out.Closed {
		out.EvidenceDigest = closureHexOrEmpty(r.EvidenceDigest)
		out.Closed = out.EvidenceDigest != ""
	}
	return out
}

// ClosureTrust is the operator's trust root for deadman attestations: key ID to
// ed25519 public key. It is read from its own file so a ledger cannot name its
// own signer.
type ClosureTrust struct {
	Keys map[string]ed25519.PublicKey `json:"keys"`
}

// runClosure is the `closure` subcommand (args are the arguments after the
// subcommand name).
//
//	--mode history|close            history: status of legacy-history obligations;
//	                                close: full adoption closure decision
//	--ledger FILE                   private JSON: HistoryObligations (history) or ClosureLedger (close)
//	--trusted-keys FILE             close only: ClosureTrust JSON, separate from the ledger
//	--private-output DIRECTORY      existing external private directory (history.json / closure.json)
//	--public-summary FILE           new closed public summary file
//	--private-directory-acl-confirmed  operator verified a restrictive NTFS ACL (Windows)
//	--timeout 2m                    operator deadline (0 < t <= 1h)
//
// The clock is the process's UTC clock at the call. Outputs are created
// exclusively and a blocked decision is a non-zero error after both are written.
func runClosure(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("closure", flag.ContinueOnError)
	mode := fs.String("mode", "", "history or close")
	ledgerPath := fs.String("ledger", "", "private ledger JSON")
	trustPath := fs.String("trusted-keys", "", "close mode: trusted deadman keys JSON")
	output := fs.String("private-output", "", "external private directory")
	summaryPath := fs.String("public-summary", "", "new public summary file")
	acl := fs.Bool("private-directory-acl-confirmed", false, "operator verified restrictive NTFS ACL")
	timeout := fs.Duration("timeout", 2*time.Minute, "overall operator deadline (positive, at most 1h)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	usage := errors.New("usage: adoption closure --mode history|close --ledger FILE [--trusted-keys FILE] --private-output DIRECTORY --public-summary FILE")
	if fs.NArg() != 0 || !nonempty(*mode, *ledgerPath, *output, *summaryPath) || (*mode != "history" && *mode != "close") {
		return usage
	}
	if (*mode == "close") != (*trustPath != "") {
		return errors.New("--trusted-keys is required for close mode and not allowed for history mode")
	}
	if *timeout <= 0 || *timeout > time.Hour {
		return errors.New("timeout must be positive and at most 1h")
	}
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	resolved, err := privateDirectory(ctx, *output, nil, *acl)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	var (
		privateName string
		private     any
		public      any
		blocked     int
	)
	if *mode == "history" {
		var in HistoryObligations
		if readInput(*ledgerPath, &in) != nil {
			return errors.New("invalid private operator input")
		}
		in.Now = now
		report, err := HistoryStatus(ctx, in)
		if err != nil {
			return err
		}
		privateName, private, public, blocked = "history.json", report, HistoryPublicProjection(report), len(report.Blockers)
	} else {
		var l ClosureLedger
		var trust ClosureTrust
		if readInput(*ledgerPath, &l) != nil || readInput(*trustPath, &trust) != nil {
			return errors.New("invalid private operator input")
		}
		l.Now, l.Trust = now, trust.Keys
		report, err := CloseAdoption(ctx, l)
		if err != nil {
			return err
		}
		privateName, private, public, blocked = "closure.json", report, ClosurePublicProjection(report), len(report.Blockers)
	}
	if ctx.Err() != nil {
		return errors.New("closure cancelled or deadline exceeded")
	}
	if err := writeExclusive(filepath.Join(resolved, privateName), private); err != nil {
		return errors.New("private output creation failed")
	}
	if err := writeExclusive(*summaryPath, public); err != nil {
		return errors.New("summary creation failed; private evidence retained")
	}
	if blocked > 0 {
		return fmt.Errorf("%s blocked: %d blockers", *mode, blocked)
	}
	return nil
}
