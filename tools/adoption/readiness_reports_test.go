// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/notify"
)

// 08.05-W1: a digest in the ledger is verified against the producer's report
// body. Every body here is synthetic; no customer report is involved.

func readinessJSON(t testing.TB, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// readinessSwap points the references of kind k at body and supplies it, with
// every other reference's honest report.
func readinessSwap(l AcceptanceLedger, k ReadinessKind, body []byte) (AcceptanceLedger, ReadinessReports) {
	sum := sha256.Sum256(body)
	l = readinessMutate(l, k, func(e *EvidenceRef) { e.Digest = hex.EncodeToString(sum[:]) })
	_, bodies := readinessSeal(l)
	return l, NewReadinessReports(append(bodies, body)...)
}

func readinessEvalWith(t *testing.T, l AcceptanceLedger, a Authorizations, reports ReadinessReports) CutoverReadiness {
	t.Helper()
	r, err := ReadyForCutover(context.Background(), l, a, reports)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func readinessReportCodes(r CutoverReadiness) map[string]int {
	out := map[string]int{}
	for _, b := range r.Blockers {
		switch b.Code {
		case ReadinessBlockReportMissing, ReadinessBlockReportInvalid, ReadinessBlockReportNotPassing, ReadinessBlockReportTime, ReadinessBlockReportUnverifiable:
			out[b.Code+":"+string(b.Kind)]++
		}
	}
	return out
}

var (
	readinessVerifiedKinds   = []ReadinessKind{ReadinessJourneyGateway, ReadinessJourneyFrontend, ReadinessJourneyBackground, ReadinessSourcePolicy, ReadinessDeliveryPolicy, ReadinessLegacyRetention}
	readinessUnverifiedKinds = []ReadinessKind{ReadinessQueryProfile, ReadinessIsolationMatrix, ReadinessDeletionRestore, ReadinessExternalDeadman}
)

func TestCutoverReadinessVerifiesDigestsAgainstProducerReports(t *testing.T) {
	l, a := readinessFixture()
	r := readinessEval(t, l, a)
	if !r.Ready || r.Gate == nil {
		t.Fatalf("honest reports must be ready: %+v", r.Blockers)
	}
	if !slices.Equal(r.UnverifiedKinds, readinessUnverifiedKinds) {
		t.Fatalf("kinds still referenced by digest only: %v", r.UnverifiedKinds)
	}
	for _, c := range r.Gate.Criteria {
		if want := !slices.Contains(readinessUnverifiedKinds, c.Kind); c.BodyVerified != want {
			t.Fatalf("%s: body verified = %v, want %v", c.Kind, c.BodyVerified, want)
		}
	}
	if p := ReadinessPublicSummary(r); p.CriteriaBodyVerified != len(readinessVerifiedKinds) || p.CriteriaSatisfied != len(readinessKinds) {
		t.Fatalf("public summary: %+v", p)
	}

	// Without the report bodies, every reference of a producer with an adapter is blocked, naming its kind.
	none := readinessEvalWith(t, l, a, ReadinessReports{})
	codes := readinessReportCodes(none)
	if none.Ready || none.Gate != nil || len(codes) != len(readinessVerifiedKinds) {
		t.Fatalf("no bodies: ready=%v %v", none.Ready, codes)
	}
	for _, k := range readinessVerifiedKinds {
		if codes[ReadinessBlockReportMissing+":"+string(k)] != 1 {
			t.Fatalf("%s must be blocked as report_body_missing: %v", k, codes)
		}
	}

	// A body altered by one byte has another digest: the reference finds nothing.
	for _, k := range readinessVerifiedKinds {
		_, bodies := readinessSeal(l)
		sum := l.Evidence[slices.IndexFunc(l.Evidence, func(e EvidenceRef) bool { return e.Kind == k })].Digest
		var tampered [][]byte
		for _, b := range bodies {
			s := sha256.Sum256(b)
			if hex.EncodeToString(s[:]) == sum {
				b = append(append([]byte(nil), b...), ' ')
				b[len(b)-1] = '\n' // still valid JSON, different bytes
			}
			tampered = append(tampered, b)
		}
		if got := readinessReportCodes(readinessEvalWith(t, l, a, NewReadinessReports(tampered...))); got[ReadinessBlockReportMissing+":"+string(k)] != 1 {
			t.Fatalf("a body changed after the digest was recorded must not satisfy %s: %v", k, got)
		}
	}

	// A body that is another producer's report, or not a report, cannot speak for the kind.
	journeys := readinessBody("adoption-journeys", readinessNow.Add(-10*time.Minute))
	shadow := readinessBody("adoption-shadow", readinessNow)
	policy := readinessBody("adoption-policy-compare", readinessNow)
	history := readinessBody("adoption-retention", readinessNow.Add(-10*time.Minute))
	for name, c := range map[string]struct {
		kind ReadinessKind
		body []byte
	}{
		"journeys report for source policy":   {ReadinessSourcePolicy, journeys},
		"shadow report for a journey":         {ReadinessJourneyGateway, shadow},
		"shadow report for delivery policy":   {ReadinessDeliveryPolicy, shadow},
		"policy report for legacy retention":  {ReadinessLegacyRetention, policy},
		"history report for source policy":    {ReadinessSourcePolicy, history},
		"not JSON":                            {ReadinessSourcePolicy, []byte("this is not a report")},
		"empty object":                        {ReadinessSourcePolicy, []byte("{}")},
		"trailing JSON":                       {ReadinessSourcePolicy, append(append([]byte(nil), shadow...), []byte(" {}")...)},
		"unknown field":                       {ReadinessSourcePolicy, []byte(strings.Replace(string(shadow), `{`, `{"x":1,`, 1))},
		"journeys report without its section": {ReadinessJourneyGateway, readinessJSON(t, JourneyReport{SchemaVersion: journeySchemaVersion, VerifiedAt: readinessNow.Add(-10 * time.Minute)})},
		"journeys report with no verification time": {ReadinessJourneyGateway, func() []byte {
			var r JourneyReport
			_ = json.Unmarshal(journeys, &r)
			r.VerifiedAt = time.Time{}
			return readinessJSON(t, r)
		}()},
		"journeys section twice": {ReadinessJourneyGateway, func() []byte {
			var r JourneyReport
			_ = json.Unmarshal(journeys, &r)
			r.Results = append(r.Results, r.Results[0])
			return readinessJSON(t, r)
		}()},
		"report of another schema": {ReadinessSourcePolicy, func() []byte {
			var r ShadowReport
			_ = json.Unmarshal(shadow, &r)
			r.SchemaVersion = 2
			return readinessJSON(t, r)
		}()},
	} {
		el, reports := readinessSwap(l, c.kind, c.body)
		if got := readinessReportCodes(readinessEvalWith(t, el, a, reports)); got[ReadinessBlockReportInvalid+":"+string(c.kind)] != 1 {
			t.Errorf("%s: want report_invalid on %s, got %v", name, c.kind, got)
		}
	}
}

func TestCutoverReadinessRequiresTheProducerReportToPass(t *testing.T) {
	l, a := readinessFixture()
	at := readinessNow.Add(-10 * time.Minute)
	edit := func(producer string, f func(v any)) []byte {
		var v any
		switch producer {
		case "adoption-journeys":
			v = new(JourneyReport)
		case "adoption-shadow":
			v = new(ShadowReport)
		case "adoption-policy-compare":
			v = new(PolicyReport)
		default:
			v = new(HistoryReport)
		}
		if err := json.Unmarshal(readinessBody(producer, at), v); err != nil {
			t.Fatal(err)
		}
		f(v)
		return readinessJSON(t, v)
	}
	journeySection := func(v any) *JourneyResult {
		r := v.(*JourneyReport)
		for i := range r.Results {
			if r.Results[i].Kind == JourneyFrontendAPIDB {
				return &r.Results[i]
			}
		}
		t.Fatal("no frontend section")
		return nil
	}
	cases := []struct {
		name     string
		kind     ReadinessKind
		producer string
		f        func(v any)
	}{
		{"journey section failed", ReadinessJourneyFrontend, "adoption-journeys", func(v any) { journeySection(v).Status = JourneyFailed }},
		{"journey check failed", ReadinessJourneyFrontend, "adoption-journeys", func(v any) {
			journeySection(v).Checks = append(journeySection(v).Checks, JourneyCheck{Name: JourneyCheckRoot})
		}},
		{"journey section without checks", ReadinessJourneyFrontend, "adoption-journeys", func(v any) { journeySection(v).Checks = nil }},
		{"shadow not reconciled", ReadinessSourcePolicy, "adoption-shadow", func(v any) { v.(*ShadowReport).Reconciled = false }},
		{"shadow policy violation", ReadinessSourcePolicy, "adoption-shadow", func(v any) { v.(*ShadowReport).PolicyViolations = []string{"unmapped_source"} }},
		{"shadow external send", ReadinessSourcePolicy, "adoption-shadow", func(v any) { v.(*ShadowReport).ExternalSendAttempts = 1 }},
		{"shadow normal delivery", ReadinessSourcePolicy, "adoption-shadow", func(v any) { v.(*ShadowReport).NormalDeliveriesSent = 1 }},
		{"shadow parity mismatch", ReadinessSourcePolicy, "adoption-shadow", func(v any) {
			v.(*ShadowReport).Parity.Mismatches = []ShadowMismatch{{Domain: "lifecycle", Field: "version"}}
		}},
		{"shadow compared nothing", ReadinessSourcePolicy, "adoption-shadow", func(v any) { v.(*ShadowReport).Parity = ShadowParityReport{Mismatches: []ShadowMismatch{}} }},
		{"shadow received nothing", ReadinessSourcePolicy, "adoption-shadow", func(v any) { v.(*ShadowReport).Records.Received = 0 }},
		{"policy verdict blocked", ReadinessDeliveryPolicy, "adoption-policy-compare", func(v any) { v.(*PolicyReport).Verdict = policyVerdictBlocked }},
		{"policy compared nothing", ReadinessDeliveryPolicy, "adoption-policy-compare", func(v any) { v.(*PolicyReport).Compared = 0 }},
		{"policy missing urgency", ReadinessDeliveryPolicy, "adoption-policy-compare", func(v any) {
			v.(*PolicyReport).MissingUrgency = []PolicyDifference{{Entity: notify.Entity{Kind: notify.EntityCondition, ID: model.ID{1}}}}
		}},
		{"history not clear", ReadinessLegacyRetention, "adoption-retention", func(v any) { v.(*HistoryReport).Clear = false }},
		{"history blocker", ReadinessLegacyRetention, "adoption-retention", func(v any) { v.(*HistoryReport).Blockers = []HistoryCode{"x"} }},
		{"history without obligations", ReadinessLegacyRetention, "adoption-retention", func(v any) { v.(*HistoryReport).Obligations = nil }},
		{"history overdue", ReadinessLegacyRetention, "adoption-retention", func(v any) { v.(*HistoryReport).Overdue = 1 }},
		{"history writers", ReadinessLegacyRetention, "adoption-retention", func(v any) { v.(*HistoryReport).ActiveWriters = 1 }},
	}
	for _, c := range cases {
		el, reports := readinessSwap(l, c.kind, edit(c.producer, c.f))
		got := readinessReportCodes(readinessEvalWith(t, el, a, reports))
		if got[ReadinessBlockReportNotPassing+":"+string(c.kind)] != 1 || len(got) != 1 {
			t.Errorf("%s: want exactly report_not_passing on %s, got %v", c.name, c.kind, got)
		}
	}
	// Each report that carries a time must carry the one the reference claims.
	for _, c := range []struct {
		kind     ReadinessKind
		producer string
		f        func(v any)
	}{
		{ReadinessJourneyGateway, "adoption-journeys", func(v any) { v.(*JourneyReport).VerifiedAt = at.Add(time.Second) }},
		{ReadinessLegacyRetention, "adoption-retention", func(v any) { v.(*HistoryReport).EvaluatedAt = at.Add(-time.Second) }},
	} {
		el, reports := readinessSwap(l, c.kind, edit(c.producer, c.f))
		got := readinessReportCodes(readinessEvalWith(t, el, a, reports))
		if got[ReadinessBlockReportTime+":"+string(c.kind)] != 1 || len(got) != 1 {
			t.Errorf("%s time: %v", c.kind, got)
		}
	}
	// The honest body edited back to its own claim is accepted: the cases above fail for their edit alone.
	el, reports := readinessSwap(l, ReadinessSourcePolicy, edit("adoption-shadow", func(any) {}))
	if r := readinessEvalWith(t, el, a, reports); !r.Ready {
		t.Fatalf("an unedited report: %+v", r.Blockers)
	}
}

func TestCutoverReadinessReportRulesOfReferences(t *testing.T) {
	l, a := readinessFixture()
	// A reference that already fails is blocked for that; its report is not read for it.
	for name, edit := range map[string]func(*EvidenceRef){
		"not run":    func(e *EvidenceRef) { e.Result = ReadinessResultNotRun },
		"failed":     func(e *EvidenceRef) { e.Result = ReadinessResultFail },
		"bad digest": func(e *EvidenceRef) { e.Digest = "abc" },
	} {
		el := readinessMutate(l, ReadinessSourcePolicy, edit)
		r := readinessEvalWith(t, el, a, ReadinessReports{})
		if got := readinessReportCodes(r); got[ReadinessBlockReportMissing+":"+string(ReadinessSourcePolicy)] != 0 || r.Ready {
			t.Errorf("%s: %v", name, got)
		}
	}
	// Any valid reference satisfies the criterion: a sibling with a bad report does not block it.
	bad := l.Evidence[slices.IndexFunc(l.Evidence, func(e EvidenceRef) bool { return e.Kind == ReadinessSourcePolicy })]
	bad.Digest = strings.Repeat("1", 64)
	l.Evidence = append([]EvidenceRef{bad}, l.Evidence...)
	if r := readinessEval(t, l, a); !r.Ready {
		t.Fatalf("a valid sibling reference satisfies the criterion: %+v", r.Blockers)
	}
	// Demanding verified reports blocks the producers whose report this package cannot verify.
	l, a = readinessFixture()
	l.RequireVerifiedReports = true
	r := readinessEval(t, l, a)
	codes := readinessReportCodes(r)
	if r.Ready || len(codes) != len(readinessUnverifiedKinds) {
		t.Fatalf("require verified reports: ready=%v %v", r.Ready, codes)
	}
	for _, k := range readinessUnverifiedKinds {
		if codes[ReadinessBlockReportUnverifiable+":"+string(k)] != 1 {
			t.Fatalf("%s must be report_unverifiable: %v", k, codes)
		}
	}
}

func TestCutoverReadinessReportsAreAddressedByTheirDigest(t *testing.T) {
	body := []byte(`{"a":1}`)
	sum := sha256.Sum256(body)
	reports := NewReadinessReports(body, body)
	if got, ok := reports.body(hex.EncodeToString(sum[:])); !ok || string(got) != string(body) {
		t.Fatal("a body is found by the SHA-256 of its bytes")
	}
	if _, ok := reports.body(strings.Repeat("0", 64)); ok {
		t.Fatal("a body is found only by its own digest")
	}
	if _, ok := (ReadinessReports{}).body(hex.EncodeToString(sum[:])); ok {
		t.Fatal("an empty set holds nothing")
	}
}

func TestCutoverReadinessReportsDirectory(t *testing.T) {
	write := func(dir, name string, body []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	dir := t.TempDir()
	write(dir, "one.json", []byte(`{"one":1}`))
	write(dir, "two", []byte(`{"two":2}`))
	reports, err := readinessReportsFromDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{`{"one":1}`, `{"two":2}`} {
		sum := sha256.Sum256([]byte(body))
		if got, ok := reports.body(hex.EncodeToString(sum[:])); !ok || string(got) != body {
			t.Fatalf("%s not addressed", body)
		}
	}
	if _, err := readinessReportsFromDir(filepath.Join(dir, "absent")); err == nil {
		t.Fatal("a missing directory is an error")
	}
	// Only regular report files within the bound.
	sub := t.TempDir()
	write(sub, "ok.json", []byte(`{}`))
	if err := os.Mkdir(filepath.Join(sub, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := readinessReportsFromDir(sub); err == nil {
		t.Fatal("a nested directory is refused")
	}
	linked := t.TempDir()
	write(linked, "target.json", []byte(`{}`))
	if os.Symlink(filepath.Join(linked, "target.json"), filepath.Join(linked, "link.json")) == nil {
		if _, err := readinessReportsFromDir(linked); err == nil {
			t.Fatal("a symbolic link is refused: it can point outside the directory")
		}
	}
	big := t.TempDir()
	f, err := os.Create(filepath.Join(big, "big.json"))
	if err != nil || f.Truncate(readinessMaxReportBytes+1) != nil {
		t.Fatal("cannot make the oversized fixture")
	}
	f.Close()
	if _, err := readinessReportsFromDir(big); err == nil {
		t.Fatal("an oversized report is refused")
	}
	edge := t.TempDir()
	f, err = os.Create(filepath.Join(edge, "edge.json"))
	if err != nil || f.Truncate(readinessMaxReportBytes) != nil {
		t.Fatal("cannot make the edge fixture")
	}
	f.Close()
	if _, err := readinessReportsFromDir(edge); err != nil {
		t.Fatalf("a report exactly at the bound is accepted: %v", err)
	}
	many := t.TempDir()
	for i := range readinessMaxReports + 1 {
		write(many, strconv.Itoa(i)+".json", []byte(`{}`))
	}
	if _, err := readinessReportsFromDir(many); err == nil {
		t.Fatal("too many report files are refused")
	}
}

func TestCutoverReadinessCLIVerifiesReports(t *testing.T) {
	dir := t.TempDir()
	l, a := readinessFixture()
	_, bodies := readinessSeal(l)
	write := func(name string, v any) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, readinessJSON(t, v), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	reports := func(name string, skip func([]byte) bool) string {
		d := filepath.Join(dir, name)
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
		for i, b := range bodies {
			if skip != nil && skip(b) {
				continue
			}
			if err := os.WriteFile(filepath.Join(d, string(rune('a'+i))+".json"), b, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return d
	}
	seed := make([]byte, ed25519.SeedSize)
	key := filepath.Join(dir, "key")
	_ = os.WriteFile(key, []byte(hex.EncodeToString(seed)+"\n"), 0o600)
	args := func(reportsDir, tag string) []string {
		out := []string{"--ledger", write("ledger.json", l), "--authorizations", write("auth.json", a), "--signing-key", key,
			"--private-output", filepath.Join(dir, tag+".private.json"), "--public-summary", filepath.Join(dir, tag+".public.json")}
		if reportsDir != "" {
			out = append(out, "--reports", reportsDir)
		}
		return out
	}
	if err := runReadiness(context.Background(), args(reports("all", nil), "ok")); err != nil {
		t.Fatalf("every report supplied: %v", err)
	}
	pb, _ := os.ReadFile(filepath.Join(dir, "ok.public.json"))
	if !strings.Contains(string(pb), `"criteria_body_verified": 6`) {
		t.Fatalf("public summary: %s", pb)
	}
	if runReadiness(context.Background(), args("", "noflag")) == nil {
		t.Fatal("--reports is required: a digest is never accepted without its report")
	}
	history := readinessBody("adoption-retention", readinessNow.Add(-10*time.Minute))
	err := runReadiness(context.Background(), args(reports("partial", func(b []byte) bool { return string(b) == string(history) }), "partial"))
	if err == nil || !strings.Contains(err.Error(), "report_body_missing:legacy_retention_export") {
		t.Fatalf("a missing report must block naming its kind: %v", err)
	}
}
