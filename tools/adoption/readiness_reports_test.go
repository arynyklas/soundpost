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
	readinessVerifiedKinds   = readinessKinds
	readinessUnverifiedKinds = []ReadinessKind{}
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
	journeys := readinessBody("adoption-journeys", ReadinessJourneyGateway, readinessNow.Add(-10*time.Minute))
	shadow := readinessBody("adoption-shadow", ReadinessSourcePolicy, readinessNow)
	policy := readinessBody("adoption-policy-compare", ReadinessDeliveryPolicy, readinessNow)
	history := readinessBody("adoption-retention", ReadinessLegacyRetention, readinessNow.Add(-10*time.Minute))
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
	edit := func(producer string, kind ReadinessKind, f func(v any)) []byte {
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
		if err := json.Unmarshal(readinessBody(producer, kind, at), v); err != nil {
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
		el, reports := readinessSwap(l, c.kind, edit(c.producer, c.kind, c.f))
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
		el, reports := readinessSwap(l, c.kind, edit(c.producer, c.kind, c.f))
		got := readinessReportCodes(readinessEvalWith(t, el, a, reports))
		if got[ReadinessBlockReportTime+":"+string(c.kind)] != 1 || len(got) != 1 {
			t.Errorf("%s time: %v", c.kind, got)
		}
	}
	// The honest body edited back to its own claim is accepted: the cases above fail for their edit alone.
	el, reports := readinessSwap(l, ReadinessSourcePolicy, edit("adoption-shadow", ReadinessSourcePolicy, func(any) {}))
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
	// Demanding verified reports blocks a producer whose report this package cannot
	// verify. Every allowlisted producer has an adapter, so the honest fixture stays ready...
	l, a = readinessFixture()
	l.RequireVerifiedReports = true
	if r := readinessEval(t, l, a); !r.Ready || len(readinessReportCodes(r)) != 0 {
		t.Fatalf("every producer has an adapter: %+v", r.Blockers)
	}
	// ...so the rule is exercised with a producer whose adapter is taken away.
	saved := readinessAdapters["qualify"]
	delete(readinessAdapters, "qualify")
	defer func() { readinessAdapters["qualify"] = saved }()
	r := readinessEval(t, l, a)
	codes := readinessReportCodes(r)
	if r.Ready || len(codes) != 1 || codes[ReadinessBlockReportUnverifiable+":"+string(ReadinessQueryProfile)] != 1 {
		t.Fatalf("require verified reports: ready=%v %v", r.Ready, codes)
	}
	l.RequireVerifiedReports = false
	if r := readinessEval(t, l, a); !r.Ready || !slices.Equal(r.UnverifiedKinds, []ReadinessKind{ReadinessQueryProfile}) {
		t.Fatalf("without the rule the reference stays a digest: %+v %v", r.Blockers, r.UnverifiedKinds)
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
	if !strings.Contains(string(pb), `"criteria_body_verified": 10`) {
		t.Fatalf("public summary: %s", pb)
	}
	if runReadiness(context.Background(), args("", "noflag")) == nil {
		t.Fatal("--reports is required: a digest is never accepted without its report")
	}
	history := readinessBody("adoption-retention", ReadinessLegacyRetention, readinessNow.Add(-10*time.Minute))
	err := runReadiness(context.Background(), args(reports("partial", func(b []byte) bool { return string(b) == string(history) }), "partial"))
	if err == nil || !strings.Contains(err.Error(), "report_body_missing:legacy_retention_export") {
		t.Fatalf("a missing report must block naming its kind: %v", err)
	}
}

// readinessEditJSON decodes a report body into a generic document, applies f and
// encodes it again.
func readinessEditJSON(t testing.TB, body []byte, f func(m map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatal(err)
	}
	f(m)
	return readinessJSON(t, m)
}

func TestReadinessEveryProducerHasAnAdapter(t *testing.T) {
	seen := map[string]bool{}
	for kind, producers := range readinessProducers {
		for _, p := range producers {
			seen[p] = true
			if readinessAdapters[p] == nil {
				t.Errorf("%s names producer %s, which has no report adapter: its digest would stay a bare reference", kind, p)
			}
		}
	}
	for p := range readinessAdapters {
		if !seen[p] {
			t.Errorf("adapter for %s, which no kind allows", p)
		}
	}
}

// 08.05-W1: the reports of qualify (07.05), smoke (07.04) and drills (07.07),
// the producers whose tools are not part of this package, are decoded and
// judged like the adoption reports.
func TestCutoverReadinessVerifiesTheDrillQualifyAndSmokeReports(t *testing.T) {
	l, a := readinessFixture()
	// A passing body of each producer, for every scenario that may speak for the kind.
	for kind, scenarios := range readinessDrillScenarios {
		for _, scenario := range scenarios {
			el := readinessMutate(l, kind, func(e *EvidenceRef) { e.Producer = "drills" })
			el, reports := readinessSwap(el, kind, readinessDrillBody(scenario))
			if r := readinessEvalWith(t, el, a, reports); !r.Ready || len(readinessReportCodes(r)) != 0 {
				t.Errorf("%s drill report for %s must pass: %+v", scenario, kind, r.Blockers)
			}
		}
	}

	campaign, isolation := readinessCampaignBody(), readinessIsolationBody()
	deletion := readinessDrillBody("backup-predates-deletion")
	deadman := readinessDrillBody("external-deadman")
	for _, c := range []struct {
		name     string
		kind     ReadinessKind
		producer string
		body     []byte
	}{
		// right shape, other kind or target
		{"smoke report for the query profile", ReadinessQueryProfile, "smoke", isolation},
		{"campaign report for the isolation matrix", ReadinessIsolationMatrix, "qualify", campaign},
		{"drills report for the isolation matrix", ReadinessIsolationMatrix, "drills", deadman},
		{"drills report for the query profile", ReadinessQueryProfile, "drills", deadman},
		{"deletion drill for the deadman", ReadinessExternalDeadman, "drills", deletion},
		{"deadman drill for deletion and restore", ReadinessDeletionRestore, "drills", deadman},
		{"deadman drill for the delivery policy", ReadinessDeliveryPolicy, "drills", deadman},
		{"retention scenario for deletion", ReadinessDeletionRestore, "drills", readinessDrillBody("evidence-gap-after-retention")},
		{"membership scenario for delivery policy", ReadinessDeliveryPolicy, "drills", readinessDrillBody("membership-replace")},
		{"drill of another target", ReadinessExternalDeadman, "drills", readinessEditJSON(t, deadman, func(m map[string]any) { m["target"] = "production" })},
		{"drill without a target", ReadinessExternalDeadman, "drills", readinessEditJSON(t, deadman, func(m map[string]any) { delete(m, "target") })},
		{"drill of an unknown status", ReadinessExternalDeadman, "drills", readinessEditJSON(t, deadman, func(m map[string]any) { m["status"] = "ok" })},
		{"drill with an unknown field", ReadinessExternalDeadman, "drills", readinessEditJSON(t, deadman, func(m map[string]any) { m["verdict"] = "passed" })},
		{"drill check of another shape", ReadinessExternalDeadman, "drills", readinessEditJSON(t, deadman, func(m map[string]any) { m["checks"] = "all ok" })},
		{"campaign of another schema", ReadinessQueryProfile, "qualify", readinessEditJSON(t, campaign, func(m map[string]any) { m["schema"] = "soundpost-query-campaign/2" })},
		{"campaign with an unknown field", ReadinessQueryProfile, "qualify", readinessEditJSON(t, campaign, func(m map[string]any) { m["passed"] = true })},
		{"isolation of another version", ReadinessIsolationMatrix, "smoke", readinessEditJSON(t, isolation, func(m map[string]any) { m["Version"] = 2 })},
		{"isolation without its qualification", ReadinessIsolationMatrix, "smoke", readinessEditJSON(t, isolation, func(m map[string]any) { m["Qualification"] = "" })},
		{"isolation with an unknown field", ReadinessIsolationMatrix, "smoke", readinessEditJSON(t, isolation, func(m map[string]any) { m["Passed"] = true })},
		{"drill report for a qualify reference", ReadinessQueryProfile, "qualify", deadman},
		{"campaign report for a smoke reference", ReadinessIsolationMatrix, "smoke", campaign},
		{"isolation report for a drills reference", ReadinessExternalDeadman, "drills", isolation},
		{"not JSON (qualify)", ReadinessQueryProfile, "qualify", []byte("this is not a report")},
		{"not JSON (smoke)", ReadinessIsolationMatrix, "smoke", []byte("this is not a report")},
		{"not JSON (drills)", ReadinessExternalDeadman, "drills", []byte("this is not a report")},
		{"empty object (qualify)", ReadinessQueryProfile, "qualify", []byte("{}")},
		{"empty object (smoke)", ReadinessIsolationMatrix, "smoke", []byte("{}")},
		{"empty object (drills)", ReadinessExternalDeadman, "drills", []byte("{}")},
		{"trailing JSON (qualify)", ReadinessQueryProfile, "qualify", append(append([]byte(nil), campaign...), []byte(" {}")...)},
		{"trailing JSON (smoke)", ReadinessIsolationMatrix, "smoke", append(append([]byte(nil), isolation...), []byte(" {}")...)},
		{"trailing JSON (drills)", ReadinessExternalDeadman, "drills", append(append([]byte(nil), deadman...), []byte(" {}")...)},
	} {
		el := readinessMutate(l, c.kind, func(e *EvidenceRef) { e.Producer = c.producer })
		el, reports := readinessSwap(el, c.kind, c.body)
		if got := readinessReportCodes(readinessEvalWith(t, el, a, reports)); got[ReadinessBlockReportInvalid+":"+string(c.kind)] != 1 || len(got) != 1 {
			t.Errorf("%s: want exactly report_invalid on %s, got %v", c.name, c.kind, got)
		}
	}

	// Bodies of the right kind whose own verdict is not a pass: report_not_passing, and nothing else.
	rows := func(m map[string]any) []any { return m["rows"].([]any) }
	row := func(m map[string]any, i int) map[string]any { return rows(m)[i].(map[string]any) }
	matrix := func(m map[string]any) []any { return m["Matrix"].([]any) }
	for _, c := range []struct {
		name string
		kind ReadinessKind
		body []byte
	}{
		{"campaign not verified", ReadinessQueryProfile, readinessEditJSON(t, campaign, func(m map[string]any) { m["verified"] = false })},
		{"campaign row not verified", ReadinessQueryProfile, readinessEditJSON(t, campaign, func(m map[string]any) { row(m, 0)["verified"] = false })},
		{"campaign row with a failure", ReadinessQueryProfile, readinessEditJSON(t, campaign, func(m map[string]any) { row(m, 1)["failures"] = []string{"unbound 785"} })},
		{"campaign missing evidence", ReadinessQueryProfile, readinessEditJSON(t, campaign, func(m map[string]any) { m["missing_evidence"] = []string{"release/default/seed/2"} })},
		{"campaign failure", ReadinessQueryProfile, readinessEditJSON(t, campaign, func(m map[string]any) { m["failures"] = []string{"matrix pin"} })},
		{"campaign without rows", ReadinessQueryProfile, readinessEditJSON(t, campaign, func(m map[string]any) { m["rows"] = []any{} })},
		{"campaign without a release row", ReadinessQueryProfile, readinessEditJSON(t, campaign, func(m map[string]any) { m["rows"] = rows(m)[1:] })},
		{"campaign without the distributed", ReadinessQueryProfile, readinessEditJSON(t, campaign, func(m map[string]any) { m["rows"] = rows(m)[:2] })},
		{"campaign without the single", ReadinessQueryProfile, readinessEditJSON(t, campaign, func(m map[string]any) { m["rows"] = append(rows(m)[:1:1], rows(m)[2]) })},
		{"isolation without rows", ReadinessIsolationMatrix, readinessEditJSON(t, isolation, func(m map[string]any) { m["Matrix"] = []any{} })},
		{"isolation extra row of an unknown outcome", ReadinessIsolationMatrix, readinessEditJSON(t, isolation, func(m map[string]any) {
			m["Matrix"] = append(matrix(m), map[string]any{"actor": "x", "target": "y", "surface": "z", "status": 200, "outcome": "leaked"})
		})},
		{"isolation without denials", ReadinessIsolationMatrix, readinessEditJSON(t, isolation, func(m map[string]any) { m["Matrix"] = matrix(m)[1:] })},
		{"isolation without own reads", ReadinessIsolationMatrix, readinessEditJSON(t, isolation, func(m map[string]any) { m["Matrix"] = matrix(m)[:1] })},
		{"isolation unknown outcome", ReadinessIsolationMatrix, readinessEditJSON(t, isolation, func(m map[string]any) { matrix(m)[0].(map[string]any)["outcome"] = "leaked" })},
		{"isolation denial answered 200", ReadinessIsolationMatrix, readinessEditJSON(t, isolation, func(m map[string]any) { matrix(m)[0].(map[string]any)["status"] = 200 })},
		{"isolation own read refused", ReadinessIsolationMatrix, readinessEditJSON(t, isolation, func(m map[string]any) { matrix(m)[1].(map[string]any)["status"] = 404 })},
		{"isolation row without an actor", ReadinessIsolationMatrix, readinessEditJSON(t, isolation, func(m map[string]any) { matrix(m)[1].(map[string]any)["actor"] = "" })},
		{"isolation row without a target", ReadinessIsolationMatrix, readinessEditJSON(t, isolation, func(m map[string]any) { matrix(m)[1].(map[string]any)["target"] = "" })},
		{"isolation row without a surface", ReadinessIsolationMatrix, readinessEditJSON(t, isolation, func(m map[string]any) { matrix(m)[1].(map[string]any)["surface"] = "" })},
		{"deadman drill failed", ReadinessExternalDeadman, readinessEditJSON(t, deadman, func(m map[string]any) { m["status"] = "failed" })},
		{"deadman drill not run", ReadinessExternalDeadman, readinessEditJSON(t, deadman, func(m map[string]any) { m["status"] = "not_run" })},
		{"deadman drill with a failed check", ReadinessExternalDeadman, readinessEditJSON(t, deadman, func(m map[string]any) {
			m["checks"] = append(m["checks"].([]any), map[string]any{"name": "outage_kept", "ok": false})
		})},
		{"deadman drill without checks", ReadinessExternalDeadman, readinessEditJSON(t, deadman, func(m map[string]any) { m["checks"] = []any{} })},
		{"deletion drill failed", ReadinessDeletionRestore, readinessEditJSON(t, deletion, func(m map[string]any) { m["status"] = "failed" })},
		{"delivery drill with a failed check", ReadinessDeliveryPolicy, readinessEditJSON(t, readinessDrillBody("owner-cutover-rollback"), func(m map[string]any) {
			m["checks"] = append(m["checks"].([]any), map[string]any{"name": "one_owner", "ok": false})
		})},
	} {
		el := l
		if c.kind == ReadinessDeliveryPolicy { // the only drills report in this table that is not the fixture's producer
			el = readinessMutate(l, c.kind, func(e *EvidenceRef) { e.Producer = "drills" })
		}
		el, reports := readinessSwap(el, c.kind, c.body)
		got := readinessReportCodes(readinessEvalWith(t, el, a, reports))
		if got[ReadinessBlockReportNotPassing+":"+string(c.kind)] != 1 || len(got) != 1 {
			t.Errorf("%s: want exactly report_not_passing on %s, got %v", c.name, c.kind, got)
		}
	}
}

// The adoption adapters judge the kind the reference claims, not only the shape
// of the body: a producer's genuine report cannot speak for a kind that producer
// does not serve, and a report of another schema is refused.
func TestCutoverReadinessAdoptionReportsOfAnotherKindOrSchema(t *testing.T) {
	l, a := readinessFixture()
	at := readinessNow.Add(-10 * time.Minute)
	journeys := readinessBody("adoption-journeys", ReadinessJourneyGateway, at)
	shadow := readinessBody("adoption-shadow", ReadinessSourcePolicy, at)
	policy := readinessBody("adoption-policy-compare", ReadinessSourcePolicy, at)
	history := readinessBody("adoption-retention", ReadinessLegacyRetention, at)
	journeysOtherSchema := func() []byte {
		var r JourneyReport
		if err := json.Unmarshal(journeys, &r); err != nil {
			t.Fatal(err)
		}
		r.SchemaVersion++
		return readinessJSON(t, r)
	}()
	policyOtherSchema := func() []byte {
		var r PolicyReport
		if err := json.Unmarshal(policy, &r); err != nil {
			t.Fatal(err)
		}
		r.SchemaVersion++
		return readinessJSON(t, r)
	}()
	historyOtherSchema := func() []byte {
		var r HistoryReport
		if err := json.Unmarshal(history, &r); err != nil {
			t.Fatal(err)
		}
		r.SchemaVersion++
		return readinessJSON(t, r)
	}()
	historyNoTime := func() []byte {
		var r HistoryReport
		if err := json.Unmarshal(history, &r); err != nil {
			t.Fatal(err)
		}
		r.EvaluatedAt = time.Time{}
		return readinessJSON(t, r)
	}()
	for _, c := range []struct {
		name     string
		kind     ReadinessKind
		producer string
		body     []byte
	}{
		{"shadow report for delivery policy", ReadinessDeliveryPolicy, "adoption-shadow", shadow},
		{"shadow report for a journey", ReadinessJourneyGateway, "adoption-shadow", shadow},
		{"policy report for legacy retention", ReadinessLegacyRetention, "adoption-policy-compare", policy},
		{"history report for source policy", ReadinessSourcePolicy, "adoption-retention", history},
		{"journeys report for source policy", ReadinessSourcePolicy, "adoption-journeys", journeys},
		{"journeys report of another schema", ReadinessJourneyGateway, "adoption-journeys", journeysOtherSchema},
		{"policy report of another schema", ReadinessDeliveryPolicy, "adoption-policy-compare", policyOtherSchema},
		{"history report of another schema", ReadinessLegacyRetention, "adoption-retention", historyOtherSchema},
		{"history report with no evaluation time", ReadinessLegacyRetention, "adoption-retention", historyNoTime},
	} {
		el := readinessMutate(l, c.kind, func(e *EvidenceRef) { e.Producer = c.producer })
		el, reports := readinessSwap(el, c.kind, c.body)
		if got := readinessReportCodes(readinessEvalWith(t, el, a, reports)); got[ReadinessBlockReportInvalid+":"+string(c.kind)] != 1 || len(got) != 1 {
			t.Errorf("%s: want exactly report_invalid on %s, got %v", c.name, c.kind, got)
		}
	}
}
