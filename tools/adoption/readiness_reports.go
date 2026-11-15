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
	"time"
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
// when the report itself says it was observed; zero when the report carries no
// time (the reference's own claim is then unverified, and says so in the docs).
type readinessVerdict struct {
	Pass bool
	At   time.Time
}

// errReadinessReportShape: the bytes are not a report of this producer that can
// speak for this kind.
var errReadinessReportShape = errors.New("not a report of this producer for this kind")

type readinessAdapter func(body []byte, kind ReadinessKind) (readinessVerdict, error)

// readinessAdapters are the producers whose report shape this package owns
// (plan 08 tasks 02, 03, 04 and 07). The 07.x producers (drills, qualify, smoke)
// write their own shapes in their own tools; their digests stay references.
var readinessAdapters = map[string]readinessAdapter{
	"adoption-journeys":       readinessJourneysReport,
	"adoption-shadow":         readinessShadowReport,
	"adoption-policy-compare": readinessPolicyReport,
	"adoption-retention":      readinessHistoryReport,
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
// verification time.
func readinessJourneysReport(body []byte, kind ReadinessKind) (readinessVerdict, error) {
	want, ok := readinessJourneySection[kind]
	var r JourneyReport
	if !ok || readinessStrictDecode(body, &r) != nil || r.SchemaVersion != journeySchemaVersion || r.VerifiedAt.IsZero() {
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
	return readinessVerdict{Pass: pass, At: r.VerifiedAt}, nil
}

// readinessShadowReport: the private shadow report reconciled, broke no policy,
// sent nothing, compared something against the legacy answers and found no
// mismatch. A run that compared nothing proves nothing about equivalence.
func readinessShadowReport(body []byte, kind ReadinessKind) (readinessVerdict, error) {
	var r ShadowReport
	if kind != ReadinessSourcePolicy || readinessStrictDecode(body, &r) != nil || r.SchemaVersion != shadowSchemaVersion {
		return readinessVerdict{}, errReadinessReportShape
	}
	compared := r.Parity.QueriesCompared + r.Parity.LifecycleCompared + r.Parity.DecisionsCompared + r.Parity.LedgerCompared
	pass := r.Reconciled && len(r.PolicyViolations) == 0 && r.ExternalSendAttempts == 0 && r.NormalDeliveriesSent == 0 &&
		r.Parity.Equal() && compared > 0 && r.Records.Received > 0
	return readinessVerdict{Pass: pass}, nil
}

// readinessPolicyReport: the private policy comparison reconciled every
// difference (no blocker, nothing unresolved) over at least one comparison.
func readinessPolicyReport(body []byte, kind ReadinessKind) (readinessVerdict, error) {
	var r PolicyReport
	if kind != ReadinessSourcePolicy && kind != ReadinessDeliveryPolicy || readinessStrictDecode(body, &r) != nil || r.SchemaVersion != 1 {
		return readinessVerdict{}, errReadinessReportShape
	}
	pass := r.Verdict == policyVerdictReconciled && r.Compared > 0 && len(r.MissingUrgency) == 0
	return readinessVerdict{Pass: pass}, nil
}

// readinessHistoryReport: the private legacy-history status does not block, has
// recorded obligations none of which is overdue, and shows no writer on the
// legacy history. It carries its evaluation time.
func readinessHistoryReport(body []byte, kind ReadinessKind) (readinessVerdict, error) {
	var r HistoryReport
	if kind != ReadinessLegacyRetention || readinessStrictDecode(body, &r) != nil || r.SchemaVersion != historySchemaVersion || r.EvaluatedAt.IsZero() {
		return readinessVerdict{}, errReadinessReportShape
	}
	pass := r.Clear && len(r.Blockers) == 0 && len(r.Obligations) > 0 && r.Overdue == 0 && r.ActiveWriters == 0
	return readinessVerdict{Pass: pass, At: r.EvaluatedAt}, nil
}

// readinessVerifyReport checks one reference's report body. verified is true
// only when an adapter decoded the body and it confirms the reference; blockers
// say exactly what did not hold. A producer with no adapter yields neither.
func readinessVerifyReport(e EvidenceRef, reports ReadinessReports) (blockers []ReadinessBlocker, verified bool) {
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
	case !v.At.IsZero() && !v.At.Equal(e.ObservedAt):
		return block(ReadinessBlockReportTime, "the producer report was observed at another time than the reference claims"), false
	}
	return nil, true
}
