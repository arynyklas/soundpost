// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/arynyklas/soundpost/tools/qualify"
)

// This file is how the readiness gate stops trusting a digest it was merely
// handed: an evidence reference names the SHA-256 of the report its producer
// wrote, and ReadyForCutover needs that report's bytes, decodes them with the
// producer's own report type and requires them to say what the reference says.
// A reference whose report is absent, altered, of another producer or kind, not
// passing, or timestamped otherwise than the reference claims blocks the gate.

const (
	readinessMaxReportBytes = 16 << 20
	readinessMaxReports     = 256
)

// ReadinessReports holds the producers' report bodies, addressed by the SHA-256
// of their bytes: a body can only be found by the digest it really has, so a
// reference cannot name one digest and be satisfied by other bytes.
type ReadinessReports struct{ byDigest map[string][]byte }

// NewReadinessReports addresses each body by its SHA-256.
func NewReadinessReports(bodies ...[]byte) ReadinessReports {
	m := make(map[string][]byte, len(bodies))
	for _, b := range bodies {
		sum := sha256.Sum256(b)
		m[hex.EncodeToString(sum[:])] = b
	}
	return ReadinessReports{byDigest: m}
}

func (r ReadinessReports) body(digest string) ([]byte, bool) {
	b, ok := r.byDigest[digest]
	return b, ok
}

// readinessReportsFromDir reads every regular file of dir (not recursively) as
// one report body. Anything else in the directory, an oversized file or too many
// files is refused: the directory is private operator input, not a free-form
// archive.
func readinessReportsFromDir(dir string) (ReadinessReports, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ReadinessReports{}, errors.New("cannot read the reports directory")
	}
	if len(entries) > readinessMaxReports {
		return ReadinessReports{}, errors.New("too many report files")
	}
	var bodies [][]byte
	for _, e := range entries {
		path := filepath.Join(dir, e.Name())
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Size() > readinessMaxReportBytes {
			return ReadinessReports{}, errors.New("the reports directory may hold only regular report files within the size bound")
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return ReadinessReports{}, errors.New("cannot read a report file")
		}
		bodies = append(bodies, raw)
	}
	return NewReadinessReports(bodies...), nil
}

// readinessVerdict is what one producer report body proves about one kind. At is
// when the report itself says it was observed: every producer's report records
// it, and ReadyForCutover requires it to be the instant the reference claims.
// Scope is the ledger scope the report says it was produced for; Scoped is false
// for qualify, smoke and drills, whose reports describe the product build or an
// isolated harness, not a customer scope.
type readinessVerdict struct {
	Pass   bool
	At     time.Time
	Scope  string
	Scoped bool
}

// errReadinessReportShape: the bytes are not a report of this producer that can
// speak for this kind.
var errReadinessReportShape = errors.New("not a report of this producer for this kind")

type readinessAdapter func(body []byte, kind ReadinessKind) (readinessVerdict, error)

// readinessAdapters are the producers a readiness reference can name: every
// producer of readinessProducers has one, so no reference stays a bare digest.
// The adoption producers (08.02, 08.03, 08.04, 08.07) are decoded with this
// package's own report types; qualify (07.05) with its exported CampaignReport;
// smoke (07.04) and drills (07.07) are package main tools, so their reports are
// decoded with a mirror of the JSON they write (readinessIsolationReport,
// readinessDrillReport). A producer added to readinessProducers needs an entry
// here (TestReadinessEveryProducerHasAnAdapter).
var readinessAdapters = map[string]readinessAdapter{
	"adoption-journeys":       readinessJourneysReport,
	"adoption-shadow":         readinessShadowReport,
	"adoption-policy-compare": readinessPolicyReport,
	"adoption-retention":      readinessHistoryReport,
	"qualify":                 readinessQualifyReport,
	"smoke":                   readinessSmokeReport,
	"drills":                  readinessDrillsReport,
}

func readinessStrictDecode(body []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if dec.Decode(v) != nil || dec.Decode(new(any)) != io.EOF {
		return errReadinessReportShape
	}
	return nil
}

var readinessJourneySection = map[ReadinessKind]JourneyKind{
	ReadinessJourneyGateway:    JourneyGatewayDependency,
	ReadinessJourneyFrontend:   JourneyFrontendAPIDB,
	ReadinessJourneyBackground: JourneySchedulerRetry,
}

// readinessJourneysReport: the section of the kind exists exactly once in the
// private journeys.json and every check of it passed. The report carries its
// verification time and the scope it was verified for.
func readinessJourneysReport(body []byte, kind ReadinessKind) (readinessVerdict, error) {
	want, ok := readinessJourneySection[kind]
	var r JourneyReport
	if !ok || readinessStrictDecode(body, &r) != nil || r.SchemaVersion != journeySchemaVersion || r.VerifiedAt.IsZero() || r.Scope == "" {
		return readinessVerdict{}, errReadinessReportShape
	}
	var section *JourneyResult
	for i := range r.Results {
		if r.Results[i].Kind != want {
			continue
		}
		if section != nil {
			return readinessVerdict{}, errReadinessReportShape
		}
		section = &r.Results[i]
	}
	if section == nil {
		return readinessVerdict{}, errReadinessReportShape
	}
	pass := section.Status == JourneyPassed && len(section.Checks) > 0
	for _, c := range section.Checks {
		pass = pass && c.Passed
	}
	return readinessVerdict{Pass: pass, At: r.VerifiedAt, Scope: r.Scope, Scoped: true}, nil
}

// readinessShadowReport: the private shadow report reconciled, broke no policy,
// sent nothing, compared something against the legacy answers and found no
// mismatch. A run that compared nothing proves nothing about equivalence. It
// carries the instant the run began and the scope it was run for.
func readinessShadowReport(body []byte, kind ReadinessKind) (readinessVerdict, error) {
	var r ShadowReport
	if kind != ReadinessSourcePolicy || readinessStrictDecode(body, &r) != nil || r.SchemaVersion != shadowSchemaVersion || r.Scope == "" || r.ObservedAt.IsZero() {
		return readinessVerdict{}, errReadinessReportShape
	}
	compared := r.Parity.QueriesCompared + r.Parity.LifecycleCompared + r.Parity.DecisionsCompared + r.Parity.LedgerCompared
	pass := r.Reconciled && len(r.PolicyViolations) == 0 && r.ExternalSendAttempts == 0 && r.NormalDeliveriesSent == 0 &&
		r.Parity.Equal() && compared > 0 && r.Records.Received > 0
	return readinessVerdict{Pass: pass, At: r.ObservedAt, Scope: r.Scope, Scoped: true}, nil
}

// readinessPolicyReport: the private policy comparison reconciled every
// difference (no blocker, nothing unresolved) over at least one comparison. It
// carries the instant the command ran and the scope it was run for.
func readinessPolicyReport(body []byte, kind ReadinessKind) (readinessVerdict, error) {
	var r PolicyReport
	if kind != ReadinessSourcePolicy && kind != ReadinessDeliveryPolicy || readinessStrictDecode(body, &r) != nil || r.SchemaVersion != 1 || r.Scope == "" || r.ObservedAt.IsZero() {
		return readinessVerdict{}, errReadinessReportShape
	}
	pass := r.Verdict == policyVerdictReconciled && r.Compared > 0 && len(r.MissingUrgency) == 0
	return readinessVerdict{Pass: pass, At: r.ObservedAt, Scope: r.Scope, Scoped: true}, nil
}

// readinessHistoryReport: the private legacy-history status does not block, has
// recorded obligations none of which is overdue, and shows no writer on the
// legacy history. It carries its evaluation time and the scope it was evaluated for.
func readinessHistoryReport(body []byte, kind ReadinessKind) (readinessVerdict, error) {
	var r HistoryReport
	if kind != ReadinessLegacyRetention || readinessStrictDecode(body, &r) != nil || r.SchemaVersion != historySchemaVersion || r.EvaluatedAt.IsZero() || r.Scope == "" {
		return readinessVerdict{}, errReadinessReportShape
	}
	pass := r.Clear && len(r.Blockers) == 0 && len(r.Obligations) > 0 && r.Overdue == 0 && r.ActiveWriters == 0
	return readinessVerdict{Pass: pass, At: r.EvaluatedAt, Scope: r.Scope, Scoped: true}, nil
}

// readinessCampaignSchema is the schema of the 07.05 query-campaign report
// (tools/qualify keeps the constant unexported).
const readinessCampaignSchema = "soundpost-query-campaign/1"

// readinessQualifyReport: the 07.05 query-campaign report names no missing
// evidence and no failure, every row of it is verified, a release row exists
// and the smoke rows cover every layout the campaign requires. The report
// carries the time the campaign verified its rows.
func readinessQualifyReport(body []byte, kind ReadinessKind) (readinessVerdict, error) {
	var r qualify.CampaignReport
	if kind != ReadinessQueryProfile || readinessStrictDecode(body, &r) != nil || r.Schema != readinessCampaignSchema || r.ObservedAt.IsZero() {
		return readinessVerdict{}, errReadinessReportShape
	}
	pass := r.Verified && len(r.Missing) == 0 && len(r.Failures) == 0
	release := false
	var layouts []string
	for _, row := range r.Rows {
		pass = pass && row.Verified && len(row.Failures) == 0
		switch row.Kind {
		case "release":
			release = true
		case "smoke":
			layouts = append(layouts, row.Layout)
		}
	}
	for _, want := range qualify.RequiredLayouts {
		pass = pass && slices.Contains(layouts, want)
	}
	return readinessVerdict{Pass: pass && release, At: r.ObservedAt}, nil
}

// readinessIsolationReport mirrors the isolation.json that `smoke isolation`
// (tools/smoke/isolation.go, package main) writes after every check held.
type readinessIsolationReport struct {
	Version       int                     `json:"Version"`
	Matrix        []readinessIsolationRow `json:"Matrix"`
	Qualification string                  `json:"Qualification"`
	ObservedAt    time.Time               `json:"ObservedAt"`
}

type readinessIsolationRow struct {
	Actor   string `json:"actor"`
	Target  string `json:"target"`
	Surface string `json:"surface"`
	Status  int    `json:"status"`
	Outcome string `json:"outcome"`
}

const (
	readinessIsolationDenied = "indistinguishable_from_guess"
	readinessIsolationOwn    = "only_own_scope"
)

// readinessSmokeReport: the isolation matrix holds only the two outcomes the
// smoke records (a denial answered like a guess with an error status, an own
// read answered 200 with only the caller's scope) and both occur. The report
// carries the time the matrix was complete.
func readinessSmokeReport(body []byte, kind ReadinessKind) (readinessVerdict, error) {
	var r readinessIsolationReport
	if kind != ReadinessIsolationMatrix || readinessStrictDecode(body, &r) != nil || r.Version != 1 || r.Qualification == "" || r.ObservedAt.IsZero() {
		return readinessVerdict{}, errReadinessReportShape
	}
	pass := true
	denied, own := 0, 0
	for _, row := range r.Matrix {
		pass = pass && row.Actor != "" && row.Target != "" && row.Surface != ""
		switch {
		case row.Outcome == readinessIsolationDenied && row.Status >= 400 && row.Status < 600:
			denied++
		case row.Outcome == readinessIsolationOwn && row.Status == 200:
			own++
		default:
			pass = false
		}
	}
	return readinessVerdict{Pass: pass && denied > 0 && own > 0, At: r.ObservedAt}, nil
}

// readinessDrillScenarios names, per kind, the drills scenarios (drills/scenarios.yaml)
// whose report may speak for it. A scenario outside the list is another kind's report.
var readinessDrillScenarios = map[ReadinessKind][]string{
	ReadinessDeliveryPolicy:  {"provider-failure-outage", "owner-cutover-rollback"},
	ReadinessDeletionRestore: {"stale-policy-delete-barrier", "backup-predates-deletion", "restore-authority-unavailable"},
	ReadinessExternalDeadman: {"external-deadman"},
}

// readinessDrillTarget is the only target the drills tool executes against.
const readinessDrillTarget = "isolated"

// readinessDrillReport mirrors the per-scenario <scenario>.json of `drills`
// (tools/drills Report, package main). The nested timelines are not read here.
type readinessDrillReport struct {
	Scenario       string                 `json:"scenario"`
	Target         string                 `json:"target"`
	Status         string                 `json:"status"`
	Reason         string                 `json:"reason,omitempty"`
	StartedAt      string                 `json:"started_at"`
	ElapsedMS      int64                  `json:"elapsed_ms"`
	AckLedger      json.RawMessage        `json:"ack_ledger"`
	FailedAttempts json.RawMessage        `json:"failed_attempts"`
	Reconciliation json.RawMessage        `json:"reconciliation,omitempty"`
	Cursors        json.RawMessage        `json:"cursors,omitempty"`
	Fences         json.RawMessage        `json:"fences,omitempty"`
	PolicyTimeline json.RawMessage        `json:"policy_timeline,omitempty"`
	Notifications  json.RawMessage        `json:"notification_timeline,omitempty"`
	Checks         []readinessDrillCheck  `json:"checks"`
	Facts          json.RawMessage        `json:"facts,omitempty"`
	NotRunItems    []readinessDrillNotRun `json:"not_run_items,omitempty"`
}

type readinessDrillCheck struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

type readinessDrillNotRun struct {
	Item   string `json:"item"`
	Reason string `json:"reason"`
}

// readinessDrillsReport: the drill report is of a scenario that can speak for
// the kind, was run against the isolated target, says it passed and every named
// check of it is ok. Parts the drill itself records as not run (not_run_items)
// are its own business and are not read. Its observation time is started_at
// (RFC 3339), the one instant a drills report records.
func readinessDrillsReport(body []byte, kind ReadinessKind) (readinessVerdict, error) {
	var r readinessDrillReport
	scenarios := readinessDrillScenarios[kind]
	if readinessStrictDecode(body, &r) != nil || r.Target != readinessDrillTarget || !slices.Contains(scenarios, r.Scenario) {
		return readinessVerdict{}, errReadinessReportShape
	}
	// An unparsable started_at parses to the zero time, which is refused too.
	startedAt, _ := time.Parse(time.RFC3339, r.StartedAt)
	if startedAt.IsZero() {
		return readinessVerdict{}, errReadinessReportShape
	}
	switch r.Status {
	case "passed", "failed", "not_run":
	default:
		return readinessVerdict{}, errReadinessReportShape
	}
	pass := r.Status == "passed" && len(r.Checks) > 0
	for _, c := range r.Checks {
		pass = pass && c.OK
	}
	return readinessVerdict{Pass: pass, At: startedAt}, nil
}

// readinessVerifyReport checks one reference's report body against the
// reference and the ledger scope. verified is true only when an adapter decoded
// the body and it confirms the reference: it passes, was observed at the instant
// the reference claims (every adapter returns the report's own time) and, for a
// producer whose report names a scope, was produced for the ledger's. Blockers
// say exactly what did not hold. A producer with no adapter yields neither.
func readinessVerifyReport(e EvidenceRef, reports ReadinessReports, scope string) (blockers []ReadinessBlocker, verified bool) {
	adapter, ok := readinessAdapters[e.Producer]
	if !ok {
		return nil, false
	}
	block := func(code, why string) []ReadinessBlocker {
		return []ReadinessBlocker{{Code: code, Kind: e.Kind, Detail: fmt.Sprintf("%s evidence: %s", e.Kind, why)}}
	}
	body, found := reports.body(e.Digest)
	if !found {
		return block(ReadinessBlockReportMissing, "no producer report with this digest was supplied"), false
	}
	v, err := adapter(body, e.Kind)
	switch {
	case err != nil:
		return block(ReadinessBlockReportInvalid, "the report with this digest is not a "+e.Producer+" report that can speak for it"), false
	case !v.Pass:
		return block(ReadinessBlockReportNotPassing, "the producer report does not pass"), false
	case v.Scoped && v.Scope != scope:
		return block(ReadinessBlockWrongScope, "the producer report was produced for a different scope"), false
	case !v.At.Equal(e.ObservedAt):
		return block(ReadinessBlockReportTime, "the producer report was observed at another time than the reference claims"), false
	}
	return nil, true
}
