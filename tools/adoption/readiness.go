// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// ReadinessKind names one criterion that must have current evidence before a
// cutover gate may be issued.
type ReadinessKind string

// The ten required criteria: three actual journeys plus seven proofs.
const (
	ReadinessJourneyGateway    ReadinessKind = "journey_gateway_model"
	ReadinessJourneyFrontend   ReadinessKind = "journey_frontend_api_db"
	ReadinessJourneyBackground ReadinessKind = "journey_background_retry"
	ReadinessSourcePolicy      ReadinessKind = "source_policy"
	ReadinessQueryProfile      ReadinessKind = "query_profile"
	ReadinessIsolationMatrix   ReadinessKind = "isolation_matrix"
	ReadinessDeliveryPolicy    ReadinessKind = "delivery_policy"
	ReadinessDeletionRestore   ReadinessKind = "deletion_restore"
	ReadinessExternalDeadman   ReadinessKind = "external_deadman"
	ReadinessLegacyRetention   ReadinessKind = "legacy_retention_export"
)

// readinessKinds is the complete, ordered required set.
var readinessKinds = []ReadinessKind{
	ReadinessJourneyGateway, ReadinessJourneyFrontend, ReadinessJourneyBackground,
	ReadinessSourcePolicy, ReadinessQueryProfile, ReadinessIsolationMatrix,
	ReadinessDeliveryPolicy, ReadinessDeletionRestore, ReadinessExternalDeadman,
	ReadinessLegacyRetention,
}

// readinessProducers lists, per kind, the committed tools whose report shapes
// may supply the evidence. Anything else is an unknown producer.
var readinessProducers = map[ReadinessKind][]string{
	ReadinessJourneyGateway:    {"adoption-journeys"},
	ReadinessJourneyFrontend:   {"adoption-journeys"},
	ReadinessJourneyBackground: {"adoption-journeys"},
	ReadinessSourcePolicy:      {"adoption-shadow", "adoption-policy-compare"},
	ReadinessQueryProfile:      {"qualify"},
	ReadinessIsolationMatrix:   {"drills", "smoke"},
	ReadinessDeliveryPolicy:    {"adoption-policy-compare", "drills"},
	ReadinessDeletionRestore:   {"drills"},
	ReadinessExternalDeadman:   {"drills"},
	ReadinessLegacyRetention:   {"adoption-retention"},
}

// Evidence environments and results.
const (
	ReadinessEnvSynthetic  = "synthetic"
	ReadinessEnvStaging    = "staging"
	ReadinessEnvProduction = "production"

	ReadinessResultPass   = "pass"
	ReadinessResultFail   = "fail"
	ReadinessResultNotRun = "not_run"
)

// Blocker codes (closed enum; the public projection only counts these).
const (
	ReadinessBlockMissing          = "missing_evidence"
	ReadinessBlockUnknownProducer  = "unknown_producer"
	ReadinessBlockBadDigest        = "bad_digest"
	ReadinessBlockStale            = "stale_observation"
	ReadinessBlockFuture           = "future_observation"
	ReadinessBlockWrongScope       = "wrong_scope"
	ReadinessBlockNotRun           = "drill_not_run"
	ReadinessBlockFailed           = "evidence_failed"
	ReadinessBlockSynthetic        = "synthetic_evidence_not_acceptable"
	ReadinessBlockProductionProof  = "production_proof_outstanding"
	ReadinessBlockUnauthorized     = "unauthorized_evidence"
	ReadinessBlockDisruptiveUnauth = "disruptive_drill_unauthorized"
	ReadinessBlockDeadmanNotIndep  = "deadman_not_independent"
	ReadinessBlockBadEvidence      = "invalid_evidence"
	ReadinessBlockBadLedger        = "invalid_ledger"
)

var readinessBlockCodes = []string{
	ReadinessBlockMissing, ReadinessBlockUnknownProducer, ReadinessBlockBadDigest,
	ReadinessBlockStale, ReadinessBlockFuture, ReadinessBlockWrongScope,
	ReadinessBlockNotRun, ReadinessBlockFailed, ReadinessBlockSynthetic,
	ReadinessBlockProductionProof, ReadinessBlockUnauthorized,
	ReadinessBlockDisruptiveUnauth, ReadinessBlockDeadmanNotIndep,
	ReadinessBlockBadEvidence, ReadinessBlockBadLedger,
}

// EvidenceRef is a typed reference to one result produced by a committed tool
// (08.02-08.04 reports, 07.07 drills, 07.06 qualify, 07.04/09.06 smoke). The
// digest is the SHA-256 of that tool's report; the report is never re-derived.
type EvidenceRef struct {
	Kind            ReadinessKind `json:"kind"`
	Producer        string        `json:"producer"`
	Digest          string        `json:"digest"` // 64 lowercase hex chars
	ObservedAt      time.Time     `json:"observed_at"`
	AuthorizationID string        `json:"authorization_id"`
	Scope           string        `json:"scope"`
	Environment     string        `json:"environment"`
	Result          string        `json:"result"`
	Disruptive      bool          `json:"disruptive,omitempty"`
	// FailureDomain is only meaningful for external_deadman evidence.
	FailureDomain string `json:"failure_domain,omitempty"`
}

// AcceptanceLedger is the private collection of evidence references for one
// cutover scope. Now is the caller-supplied clock for every freshness check.
type AcceptanceLedger struct {
	Scope string `json:"scope"`
	// Now is the caller-supplied evaluation instant (RFC 3339).
	Now time.Time `json:"now"`
	// MaxAgeSeconds is the freshness window for evidence (required, > 0).
	MaxAgeSeconds int64 `json:"max_age_seconds"`
	// RequireProduction demands production-environment evidence; staging
	// evidence is then a production_proof_outstanding blocker.
	RequireProduction bool `json:"require_production"`
	// ProductFailureDomain identifies the product's own failure domain; the
	// external deadman must be in a different, non-empty one.
	ProductFailureDomain string        `json:"product_failure_domain"`
	Evidence             []EvidenceRef `json:"evidence"`
}

// ReadinessAuthorization is an explicit owning-environment authorization.
type ReadinessAuthorization struct {
	ID          string          `json:"id"`
	Scope       string          `json:"scope"`
	Environment string          `json:"environment"`
	Kinds       []ReadinessKind `json:"kinds"`
	Disruptive  bool            `json:"disruptive"`
	NotBefore   time.Time       `json:"not_before"`
	Expires     time.Time       `json:"expires"`
}

// Authorizations is the set of authorizations offered for a ledger.
type Authorizations struct {
	Items []ReadinessAuthorization `json:"items"`
}

// ReadinessBlocker names exactly what stops the gate.
type ReadinessBlocker struct {
	Code   string        `json:"code"`
	Kind   ReadinessKind `json:"kind,omitempty"`
	Detail string        `json:"detail"`
}

// GateCriterion is one satisfied criterion bound into the gate.
type GateCriterion struct {
	Kind            ReadinessKind `json:"kind"`
	Producer        string        `json:"producer"`
	Digest          string        `json:"digest"`
	ObservedAt      time.Time     `json:"observed_at"`
	AuthorizationID string        `json:"authorization_id"`
	Environment     string        `json:"environment"`
}

// ReadyGate is the signed gate record. 08.06 consumes it via VerifyReadyGate.
// The ed25519 signature covers every other field (ledger digest, criteria,
// authorizations, instants), serialised by encoding/json.
type ReadyGate struct {
	Version          int                      `json:"version"`
	Scope            string                   `json:"scope"`
	LedgerDigest     string                   `json:"ledger_digest"`
	IssuedAt         time.Time                `json:"issued_at"`
	ExpiresAt        time.Time                `json:"expires_at"`
	ProductionProven bool                     `json:"production_proven"`
	Criteria         []GateCriterion          `json:"criteria"`
	Authorizations   []ReadinessAuthorization `json:"authorizations"`
	Signature        string                   `json:"signature,omitempty"`
}

// CutoverReadiness is the evaluation result. Gate is populated (unsigned)
// only when Ready; sign it with SignReadyGate.
type CutoverReadiness struct {
	Ready                      bool               `json:"ready"`
	Blockers                   []ReadinessBlocker `json:"blockers"`
	Satisfied                  []ReadinessKind    `json:"satisfied"`
	ProductionProofOutstanding bool               `json:"production_proof_outstanding"`
	LedgerDigest               string             `json:"ledger_digest"`
	Gate                       *ReadyGate         `json:"gate,omitempty"`
}

func readinessDigest(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:]), nil
}

func readinessHex64(s string) bool {
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

func readinessKnown(k ReadinessKind) bool {
	for _, x := range readinessKinds {
		if x == k {
			return true
		}
	}
	return false
}

func readinessProducerOK(k ReadinessKind, p string) bool {
	for _, x := range readinessProducers[k] {
		if x == p {
			return true
		}
	}
	return false
}

func readinessAuthCovers(a ReadinessAuthorization, e EvidenceRef, now time.Time, scope string) bool {
	if a.ID == "" || a.ID != e.AuthorizationID || a.Scope != scope || a.Environment != e.Environment {
		return false
	}
	if a.NotBefore.IsZero() || a.Expires.IsZero() || now.Before(a.NotBefore) || !now.Before(a.Expires) {
		return false
	}
	found := false
	for _, k := range a.Kinds {
		if k == e.Kind {
			found = true
		}
	}
	return found
}

// readinessCheckRef returns the blockers for one reference (nil when usable)
// and the matched authorization.
func readinessCheckRef(l AcceptanceLedger, e EvidenceRef, auths []ReadinessAuthorization) ([]ReadinessBlocker, *ReadinessAuthorization) {
	var bl []ReadinessBlocker
	add := func(code, detail string) {
		bl = append(bl, ReadinessBlocker{Code: code, Kind: e.Kind, Detail: detail})
	}
	if !readinessProducerOK(e.Kind, e.Producer) {
		add(ReadinessBlockUnknownProducer, string(e.Kind)+" evidence from an unrecognised producer")
	}
	if !readinessHex64(e.Digest) {
		add(ReadinessBlockBadDigest, string(e.Kind)+" evidence digest is not a sha256 hex string")
	}
	switch {
	case e.ObservedAt.IsZero():
		add(ReadinessBlockBadEvidence, string(e.Kind)+" evidence has no observation time")
	case e.ObservedAt.After(l.Now):
		add(ReadinessBlockFuture, string(e.Kind)+" evidence observed in the future")
	case l.Now.Sub(e.ObservedAt) > time.Duration(l.MaxAgeSeconds)*time.Second:
		add(ReadinessBlockStale, string(e.Kind)+" evidence is older than the freshness window")
	}
	if e.Scope != l.Scope {
		add(ReadinessBlockWrongScope, string(e.Kind)+" evidence is for a different scope")
	}
	switch e.Result {
	case ReadinessResultPass:
	case ReadinessResultNotRun:
		add(ReadinessBlockNotRun, string(e.Kind)+" drill was not run")
	case ReadinessResultFail:
		add(ReadinessBlockFailed, string(e.Kind)+" evidence reports failure")
	default:
		add(ReadinessBlockBadEvidence, string(e.Kind)+" evidence has an unknown result")
	}
	switch e.Environment {
	case ReadinessEnvSynthetic:
		add(ReadinessBlockSynthetic, string(e.Kind)+" has only synthetic evidence")
	case ReadinessEnvStaging:
		if l.RequireProduction {
			add(ReadinessBlockProductionProof, string(e.Kind)+" production proof outstanding (staging evidence is not substituted)")
		}
	case ReadinessEnvProduction:
	default:
		add(ReadinessBlockBadEvidence, string(e.Kind)+" evidence has an unknown environment")
	}
	var matched *ReadinessAuthorization
	for i := range auths {
		if readinessAuthCovers(auths[i], e, l.Now, l.Scope) {
			matched = &auths[i]
			break
		}
	}
	switch {
	case matched == nil:
		add(ReadinessBlockUnauthorized, string(e.Kind)+" evidence has no matching live authorization")
	case e.Disruptive && !matched.Disruptive:
		add(ReadinessBlockDisruptiveUnauth, string(e.Kind)+" disruptive drill lacks an explicit disruptive authorization")
	}
	if e.Kind == ReadinessExternalDeadman {
		if l.ProductFailureDomain == "" || e.FailureDomain == "" || e.FailureDomain == l.ProductFailureDomain {
			add(ReadinessBlockDeadmanNotIndep, "external_deadman failure domain is not independent of the product's")
		}
	}
	return bl, matched
}

// ReadyForCutover evaluates the ledger against every required criterion. It
// never approves from partial evidence: each of the ten kinds needs at least
// one fully valid reference. Blockers are returned (err stays nil) for
// anything the evidence fails; err is reserved for cancellation.
func ReadyForCutover(ctx context.Context, l AcceptanceLedger, a Authorizations) (CutoverReadiness, error) {
	if err := ctx.Err(); err != nil {
		return CutoverReadiness{}, err
	}
	res := CutoverReadiness{Blockers: []ReadinessBlocker{}, Satisfied: []ReadinessKind{}}
	digest, err := readinessDigest(l)
	if err != nil {
		return res, err
	}
	res.LedgerDigest = digest
	if l.Scope == "" || l.Now.IsZero() || l.MaxAgeSeconds <= 0 {
		res.Blockers = append(res.Blockers, ReadinessBlocker{Code: ReadinessBlockBadLedger, Detail: "ledger needs scope, clock instant and positive freshness window"})
		return res, nil
	}
	var crit []GateCriterion
	var used []ReadinessAuthorization
	usedIDs := map[string]bool{}
	expires := time.Time{}
	production := true
	for _, kind := range readinessKinds {
		var refs int
		var pending []ReadinessBlocker
		done := false
		for _, e := range l.Evidence {
			if e.Kind != kind {
				continue
			}
			refs++
			bl, m := readinessCheckRef(l, e, a.Items)
			if len(bl) > 0 {
				pending = append(pending, bl...)
				continue
			}
			done = true
			crit = append(crit, GateCriterion{Kind: kind, Producer: e.Producer, Digest: e.Digest, ObservedAt: e.ObservedAt.UTC(), AuthorizationID: e.AuthorizationID, Environment: e.Environment})
			if !usedIDs[m.ID] {
				usedIDs[m.ID] = true
				used = append(used, *m)
			}
			until := e.ObservedAt.Add(time.Duration(l.MaxAgeSeconds) * time.Second)
			if m.Expires.Before(until) {
				until = m.Expires
			}
			if expires.IsZero() || until.Before(expires) {
				expires = until
			}
			if e.Environment != ReadinessEnvProduction {
				production = false
			}
			break
		}
		if done {
			res.Satisfied = append(res.Satisfied, kind)
			continue
		}
		if refs == 0 {
			res.Blockers = append(res.Blockers, ReadinessBlocker{Code: ReadinessBlockMissing, Kind: kind, Detail: "missing evidence: " + string(kind)})
			continue
		}
		res.Blockers = append(res.Blockers, pending...)
	}
	for _, e := range l.Evidence {
		if !readinessKnown(e.Kind) {
			res.Blockers = append(res.Blockers, ReadinessBlocker{Code: ReadinessBlockBadEvidence, Detail: "evidence of an unknown kind"})
		}
	}
	for _, b := range res.Blockers {
		if b.Code == ReadinessBlockProductionProof {
			res.ProductionProofOutstanding = true
		}
	}
	if len(res.Blockers) > 0 {
		return res, nil
	}
	sort.Slice(used, func(i, j int) bool { return used[i].ID < used[j].ID })
	res.Ready = true
	res.ProductionProofOutstanding = !production
	res.Gate = &ReadyGate{
		Version: 1, Scope: l.Scope, LedgerDigest: digest,
		IssuedAt: l.Now.UTC(), ExpiresAt: expires.UTC(),
		ProductionProven: production, Criteria: crit, Authorizations: used,
	}
	return res, nil
}

func readinessSigningBytes(g ReadyGate) ([]byte, error) {
	g.Signature = ""
	return json.Marshal(g)
}

// SignReadyGate signs the unsigned gate of a Ready result.
func SignReadyGate(r CutoverReadiness, key ed25519.PrivateKey) (ReadyGate, error) {
	if !r.Ready || r.Gate == nil || len(r.Blockers) != 0 {
		return ReadyGate{}, errors.New("readiness is not complete; no gate is signed")
	}
	if len(key) != ed25519.PrivateKeySize {
		return ReadyGate{}, errors.New("invalid signing key")
	}
	g := *r.Gate
	if err := readinessGateShape(g); err != nil {
		return ReadyGate{}, err
	}
	b, err := readinessSigningBytes(g)
	if err != nil {
		return ReadyGate{}, err
	}
	g.Signature = hex.EncodeToString(ed25519.Sign(key, b))
	return g, nil
}

func readinessGateShape(g ReadyGate) error {
	if g.Version != 1 || g.Scope == "" || !readinessHex64(g.LedgerDigest) || g.IssuedAt.IsZero() {
		return errors.New("malformed gate")
	}
	seen := map[ReadinessKind]bool{}
	for _, c := range g.Criteria {
		if !readinessKnown(c.Kind) || seen[c.Kind] {
			return errors.New("gate has unknown or duplicate criterion")
		}
		seen[c.Kind] = true
	}
	for _, k := range readinessKinds {
		if !seen[k] {
			return errors.New("gate is missing criterion " + string(k))
		}
	}
	return nil
}

// VerifyReadyGate checks signature, shape, completeness of criteria, future
// dating and expiry against the caller-supplied clock. A nil error means the
// gate is authentic, complete and current at now.
func VerifyReadyGate(g ReadyGate, key ed25519.PublicKey, now time.Time) error {
	if len(key) != ed25519.PublicKeySize {
		return errors.New("invalid verification key")
	}
	sig, err := hex.DecodeString(g.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("gate unsigned or signature malformed")
	}
	b, err := readinessSigningBytes(g)
	if err != nil {
		return err
	}
	if !ed25519.Verify(key, b, sig) {
		return errors.New("gate signature invalid (tampered or wrong key)")
	}
	if err := readinessGateShape(g); err != nil {
		return err
	}
	if now.Before(g.IssuedAt) {
		return errors.New("gate is future-dated")
	}
	if !now.Before(g.ExpiresAt) {
		return errors.New("gate expired")
	}
	return nil
}

// ReadinessPublic is the closed public projection: counts and enums only.
type ReadinessPublic struct {
	Ready                      bool             `json:"ready"`
	CriteriaRequired           int              `json:"criteria_required"`
	CriteriaSatisfied          int              `json:"criteria_satisfied"`
	BlockerCounts              []ReadinessCount `json:"blocker_counts"`
	ProductionProofOutstanding bool             `json:"production_proof_outstanding"`
	CustomerAcceptance         bool             `json:"customer_acceptance"`
}

// ReadinessCount is one blocker-code tally.
type ReadinessCount struct {
	Code  string `json:"code"`
	Count int    `json:"count"`
}

// ReadinessPublicSummary projects a result onto the closed public shape.
func ReadinessPublicSummary(r CutoverReadiness) ReadinessPublic {
	p := ReadinessPublic{Ready: r.Ready, CriteriaRequired: len(readinessKinds), CriteriaSatisfied: len(r.Satisfied),
		BlockerCounts: []ReadinessCount{}, ProductionProofOutstanding: r.ProductionProofOutstanding}
	for _, code := range readinessBlockCodes {
		n := 0
		for _, b := range r.Blockers {
			if b.Code == code {
				n++
			}
		}
		if n > 0 {
			p.BlockerCounts = append(p.BlockerCounts, ReadinessCount{Code: code, Count: n})
		}
	}
	return p
}

// runReadiness implements `adoption readiness`.
func runReadiness(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("readiness", flag.ContinueOnError)
	ledgerPath := fs.String("ledger", "", "private acceptance ledger JSON")
	authPath := fs.String("authorizations", "", "private authorizations JSON")
	keyPath := fs.String("signing-key", "", "file holding the hex ed25519 seed (32 bytes)")
	output := fs.String("private-output", "", "new private file for the readiness result and signed gate")
	summaryPath := fs.String("public-summary", "", "new public closed summary file")
	nowStr := fs.String("now", "", "evaluation instant RFC 3339 (overrides the ledger clock; default: ledger value)")
	timeout := fs.Duration("timeout", time.Minute, "overall deadline (positive, at most 1h)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *ledgerPath == "" || *authPath == "" || *keyPath == "" || *output == "" || *summaryPath == "" {
		return errors.New("readiness requires --ledger --authorizations --signing-key --private-output --public-summary")
	}
	if *timeout <= 0 || *timeout > time.Hour {
		return errors.New("timeout must be positive and at most 1h")
	}
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	var l AcceptanceLedger
	var a Authorizations
	if readInput(*ledgerPath, &l) != nil || readInput(*authPath, &a) != nil {
		return errors.New("invalid private readiness input")
	}
	if *nowStr != "" {
		t, err := time.Parse(time.RFC3339, *nowStr)
		if err != nil {
			return errors.New("invalid --now")
		}
		l.Now = t
	}
	raw, err := os.ReadFile(*keyPath)
	if err != nil {
		return errors.New("cannot read signing key")
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return errors.New("signing key must be a 32-byte hex seed")
	}
	res, err := ReadyForCutover(ctx, l, a)
	if err != nil {
		return err
	}
	type privateResult struct {
		Readiness CutoverReadiness `json:"readiness"`
		Gate      *ReadyGate       `json:"gate,omitempty"`
	}
	pr := privateResult{Readiness: res}
	pr.Readiness.Gate = nil
	if res.Ready {
		g, err := SignReadyGate(res, ed25519.NewKeyFromSeed(seed))
		if err != nil {
			return err
		}
		pr.Gate = &g
	}
	if err := writeExclusive(*output, pr); err != nil {
		return errors.New("private output creation failed")
	}
	if err := writeExclusive(*summaryPath, ReadinessPublicSummary(res)); err != nil {
		return errors.New("summary creation failed; private result retained")
	}
	if !res.Ready {
		parts := make([]string, 0, len(res.Blockers))
		for _, b := range res.Blockers {
			parts = append(parts, fmt.Sprintf("%s:%s", b.Code, b.Kind))
		}
		return errors.New("cutover not ready; blockers: " + strings.Join(parts, ", "))
	}
	return nil
}
