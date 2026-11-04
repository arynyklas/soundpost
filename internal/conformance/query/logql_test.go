// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"soundpost/internal/model"
	"soundpost/internal/query/profile"
)

// Removing strict row accounting must never turn a missing native row into PASS.
func TestLogQLBatchRequiresEveryInputRow(t *testing.T) {
	in := LogQLInput{Profile: logQLProfile, Commit: logQLCommit, ProfileIdentity: "identity", FeatureSet: "default", ConfigurationHash: "config", Cases: []LogQLCase{{ID: "one"}, {ID: "two"}}}
	batch := LogQLBatch{Profile: in.Profile, Commit: in.Commit, Compiler: "go1.24.5", Unicode: "15.0.0", SourceSHA256: logQLSourceSHA, ProfileIdentity: in.ProfileIdentity, FeatureSet: in.FeatureSet, ConfigurationHash: in.ConfigurationHash, Observations: []LogQLObservation{{ID: "one", Accepted: true, Type: "scalar"}, {ID: "two", Accepted: true, Type: "scalar"}}}
	if err := validateLogQLBatch(batch, in); err != nil {
		t.Fatal(err)
	}
	batch.Observations = batch.Observations[:1]
	if err := validateLogQLBatch(batch, in); err == nil {
		t.Fatal("missing reference row accepted")
	}
	batch.Observations = []LogQLObservation{{ID: "one"}, {ID: "one"}}
	if err := validateLogQLBatch(batch, in); err == nil {
		t.Fatal("duplicate reference row accepted")
	}
}
func TestLogQLComparisonPreservesExactBitsOrderAndMultiplicity(t *testing.T) {
	a := LogQLObservation{ID: "a", Type: "vector", Values: []LogQLValue{{Timestamp: "1000000001", Bits: "8000000000000000", Multiplicity: "2"}}}
	b := a
	b.Values = append([]LogQLValue(nil), a.Values...)
	b.Values[0].Bits = "0000000000000000"
	if len(CompareLogQL(a, b)) == 0 {
		t.Fatal("signed zero was rounded")
	}
	b.Values[0] = a.Values[0]
	b.Values[0].Multiplicity = "1"
	if len(CompareLogQL(a, b)) == 0 {
		t.Fatal("multiplicity disappeared")
	}
	b.Values[0] = a.Values[0]
	b.Values[0].Timestamp = "1000000000"
	if len(CompareLogQL(a, b)) == 0 {
		t.Fatal("nanoseconds rounded")
	}
}
func TestLogQLComparisonRejectsUnknownErrorFamilies(t *testing.T) {
	a := LogQLObservation{ID: "a", Error: &LogQLError{Message: "native message"}}
	b := LogQLObservation{ID: "a", Error: &LogQLError{Message: "owned safe message"}}
	if len(CompareLogQL(a, b)) == 0 {
		t.Fatal("unknown errors collapsed")
	}
	a.Error.Semantic = "selector.empty-compatible"
	b.Error.Semantic = a.Error.Semantic
	if got := CompareLogQL(a, b); len(got) != 0 {
		t.Fatalf("raw prose incorrectly compared: %v", got)
	}
}
func TestLogQLClockObservationRequiresActualWallBracket(t *testing.T) {
	c := LogQLCase{Clock: &LogQLClock{Kind: "unix", Precision: "seconds"}}
	a := LogQLObservation{ID: "now", Output: "3", ClockStart: "3000000000", ClockEnd: "3999999999"}
	b := LogQLObservation{ID: "now", Output: "4", ClockStart: "4000000000", ClockEnd: "4000000001"}
	if e := compareLogQLClock(c, a, b); e != nil {
		t.Fatal(e)
	}
	b.Output = "1"
	if e := compareLogQLClock(c, a, b); e == nil {
		t.Fatal("evaluation-time substitution accepted")
	}
}
func TestLogQLNamedTimezoneRequiresHashBoundDataset(t *testing.T) {
	p := profile.Profile{}
	if _, _, err := loadLogQLLocation("America/New_York", p); err == nil {
		t.Fatal("ambient timezone accepted")
	}
	loc, hash, err := loadLogQLLocation("UTC", p)
	if err != nil || loc != time.UTC || hash != "" {
		t.Fatal(loc, hash, err)
	}
	var raw bytes.Buffer
	z := zip.NewWriter(&raw)
	w, e := z.Create("Not/AZone")
	if e != nil {
		t.Fatal(e)
	}
	_, _ = w.Write([]byte("not tz data"))
	_ = z.Close()
	path := filepath.Join(t.TempDir(), "zoneinfo.zip")
	if e = os.WriteFile(path, raw.Bytes(), 0600); e != nil {
		t.Fatal(e)
	}
	p.Configuration = map[string]json.RawMessage{"timezone_dataset_path": json.RawMessage(strconvQuote(path)), "timezone_dataset_sha256": json.RawMessage(`"0000000000000000000000000000000000000000000000000000000000000000"`)}
	if _, _, err = loadLogQLLocation("Not/AZone", p); err == nil {
		t.Fatal("wrong dataset hash accepted")
	}
}
func strconvQuote(s string) string { b, _ := json.Marshal(s); return string(b) }
func TestLogQLCaseRejectsMissingApplicabilityAndPipelineSource(t *testing.T) {
	c := LogQLCase{ID: "x", Profiles: []string{logQLProfile}, Phase: "pipeline"}
	if err := validateLogQLCase(c); err == nil {
		t.Fatal("missing query accepted")
	}
	c.Input.Expression = `{app="api"}|json`
	c.Input.Entry = &LogQLEntry{Timestamp: 1, ID: model.ID{15: 1}, Multiplicity: 1, StreamLabels: model.Labels{{Name: "app", Value: "api"}}}
	if err := validateLogQLCase(c); err != nil {
		t.Fatal(err)
	}
	c.Profiles = nil
	if err := validateLogQLCase(c); err == nil {
		t.Fatal("unscoped row accepted")
	}
}
func TestLogQLAdapterRejectsEmptyReferenceBatch(t *testing.T) {
	var output bytes.Buffer
	if err := ServeLogQLAdapter(context.Background(), logQLProfile, &LogQLInput{Profile: logQLProfile, Commit: logQLCommit}, &output); err == nil {
		t.Fatal("empty oracle input accepted")
	}
	if output.Len() != 0 {
		t.Fatal("failure emitted semantic success")
	}
}
func TestLogQLLockedCaseReaderConsumesAllRowsAndBothPhases(t *testing.T) {
	raw := []byte(`{"schema":"soundpost-authored-logql-cases-v1","cases":[{"id":"one","phase":"syntax","profiles":["logql-loki-3.5.2"],"input":{"expression":"1"}},{"id":"two","phase":"syntax","profiles":["logql-loki-3.5.2"],"input":{"expression":"2"}},{"id":"three","phase":"pipeline","profiles":["logql-loki-3.5.2"],"input":{"expression":"{app=\"api\"}","entry":{"timestamp_ns":"1","id":"00000000000000000000000000000001","multiplicity":"1","line":"line","stream_labels":[{"name":"app","value":"api"}],"structured_metadata":[],"fields":[]}}}]}`)
	path := filepath.Join(t.TempDir(), "logql-syntax-pipeline.json")
	if e := os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(raw)
	lock := SourceLock{InventoryFiles: map[string]string{"cases/logql-syntax-pipeline.json": hex.EncodeToString(sum[:])}}
	rows, e := readLogQLCases(lock, path, "syntax,pipeline")
	if e != nil {
		t.Fatal(e)
	}
	if len(rows) != 3 || rows[1].ID != "two" || rows[2].ID != "three" {
		t.Fatalf("applicable rows lost: %#v", rows)
	}
	if _, e = readLogQLCases(lock, path, "logql-template"); e == nil {
		t.Fatal("zero applicable rows passed")
	}
	externalCopy := filepath.Join(t.TempDir(), "logql-syntax-pipeline.json")
	if e = os.WriteFile(externalCopy, raw, 0600); e != nil {
		t.Fatal(e)
	}
	copied, e := readLogQLCases(lock, externalCopy, "syntax,pipeline")
	if e != nil || len(copied) != 3 {
		t.Fatalf("canonical key did not bind actual full consumed copy path: %v %#v", e, copied)
	}
	if e = os.WriteFile(externalCopy, append(append([]byte(nil), raw...), ' '), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = readLogQLCases(lock, externalCopy, "syntax,pipeline"); e == nil {
		t.Fatal("mutated external copy escaped canonical content lock")
	}
	if original, e := readLogQLCases(lock, path, "syntax,pipeline"); e != nil || len(original) != 3 {
		t.Fatalf("mutation check consumed canonical source instead of the requested copy: %v", e)
	}
	unknownPath := filepath.Join(t.TempDir(), "unregistered.json")
	if e = os.WriteFile(unknownPath, raw, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = readLogQLCases(lock, unknownPath, "syntax,pipeline"); e == nil {
		t.Fatal("missing canonical basename lock accepted")
	}
	if e = os.WriteFile(path, append(append([]byte(nil), raw...), ' '), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = readLogQLCases(lock, path, "syntax,pipeline"); e == nil {
		t.Fatal("consumed content escaped lock")
	}
}
func TestLogQLOwnedObservationExecutesPipelineNotSource(t *testing.T) {
	p, e := resolveLogQLProfile("../../../profiles/query", nil)
	if e != nil {
		t.Fatal(e)
	}
	c := LogQLCase{ID: "whole-pipeline", Phase: "logql-template", Kind: "pipeline", Profiles: []string{logQLProfile}, Source: "WRONG", PipelineQuery: `{app="api"}|line_format "first"|line_format "{{ __line__ }}-second"`, Line: "original", Timestamp: 1, Labels: model.Labels{{Name: "app", Value: "api"}}, Timezone: "UTC"}
	o, e := observeOwnedLogQL(context.Background(), c, p)
	if e != nil {
		t.Fatal(e)
	}
	if o.Error != nil || o.Pipeline == nil || !o.Pipeline.Retained || o.Pipeline.Line != "first-second" {
		t.Fatalf("full actual owned pipeline not executed: %#v", o)
	}
}
func TestLogQLComparisonPreservesErrorDetailLanguageData(t *testing.T) {
	a := LogQLObservation{ID: "details", Accepted: true, Pipeline: &LogQLPipeline{Retained: true, Line: "original", Labels: model.Labels{{Name: "__error__", Value: "TemplateFormatErr"}, {Name: "__error_details__", Value: "native details"}}}}
	b := a
	b.Pipeline = &LogQLPipeline{Retained: true, Line: "original", Labels: model.Labels{{Name: "__error__", Value: "TemplateFormatErr"}, {Name: "__error_details__", Value: "generic masked error"}}}
	if len(CompareLogQL(a, b)) == 0 {
		t.Fatal("query-visible error details erased")
	}
}
func TestLogQLBatchRejectsWrongActualCompilerAndDataset(t *testing.T) {
	in := LogQLInput{Profile: logQLProfile, Commit: logQLCommit, ProfileIdentity: "identity", FeatureSet: "default", ConfigurationHash: "config", TimezoneSHA256: "selected-dataset", Cases: []LogQLCase{{ID: "one"}}}
	b := LogQLBatch{Profile: in.Profile, Commit: in.Commit, Compiler: "go1.24.4", Unicode: "15.0.0", SourceSHA256: logQLSourceSHA, ProfileIdentity: in.ProfileIdentity, FeatureSet: in.FeatureSet, ConfigurationHash: in.ConfigurationHash, TimezoneSHA256: in.TimezoneSHA256, Observations: []LogQLObservation{{ID: "one"}}}
	if e := validateLogQLBatch(b, in); e == nil {
		t.Fatal("recipe/compiler discrepancy accepted")
	}
	b.Compiler = "go1.24.5"
	b.TimezoneSHA256 = "different"
	if e := validateLogQLBatch(b, in); e == nil {
		t.Fatal("different native timezone bytes accepted")
	}
}
func TestLogQLOwnedClockKeepsActualMonotonicValueAndRestoresLocation(t *testing.T) {
	p, e := resolveLogQLProfile("../../../profiles/query", nil)
	if e != nil {
		t.Fatal(e)
	}
	before := time.Local
	c := LogQLCase{ID: "clock-process-location", Phase: "logql-template", Profiles: []string{logQLProfile}, Source: "{{now}}", Timezone: "UTC"}
	o, e := observeOwnedLogQL(context.Background(), c, p)
	if e != nil {
		t.Fatal(e)
	}
	if o.Error != nil || !strings.Contains(o.Output, " +0000 UTC") || !strings.Contains(o.Output, " m=") {
		t.Fatalf("actual wall/monotonic time value was converted: %#v", o)
	}
	if time.Local != before {
		t.Fatal("development observation leaked its case-local timezone")
	}
}
func TestLogQLCompareProjectsOnlyBothEmptyLabelSetsWithoutMutatingRaw(t *testing.T) {
	a := LogQLObservation{ID: "empty-labels", Accepted: true, Type: "vector", Values: []LogQLValue{{Timestamp: "1", Bits: "8000000000000000", Labels: nil}}}
	b := a
	b.Values = []LogQLValue{{Timestamp: "1", Bits: "8000000000000000", Labels: model.Labels{}}}
	if got := CompareLogQL(a, b); len(got) != 0 {
		t.Fatalf("empty label representation became mismatch: %#v", got)
	}
	if b.Values[0].Labels == nil {
		t.Fatal("raw observation mutated")
	}
	b.Values[0].Labels = model.Labels{{Name: "x", Value: ""}}
	if len(CompareLogQL(a, b)) == 0 {
		t.Fatal("nonempty label set erased")
	}
	b.Values[0].Labels = nil
	b.Values[0].Bits = "0000000000000000"
	if len(CompareLogQL(a, b)) == 0 {
		t.Fatal("signed zero normalized with labels")
	}
}
func TestLogQLNativePanicReportRetainsUnobservedRowsAndPartialFailure(t *testing.T) {
	report := LogQLPhaseReport{Compared: 1, Cases: []LogQLComparison{{ID: "observed"}}}
	rows := []LogQLCase{{ID: "observed"}, {ID: "approx"}, {ID: "variants"}}
	failure := errors.New("isolated oracle failed: native reference unavailable; panic: expected aggregation operator but got approx_topk")
	recordLogQLOracleFailure(&report, rows, failure)
	if report.Failure == nil || report.Failure.Class != "native-process-panic" || report.Failure.Stage != "native-oracle" || report.Failure.Message != failure.Error() {
		t.Fatalf("actual failure class lost: %#v", report.Failure)
	}
	if len(report.Failure.UnobservedIDs) != 2 || report.Failure.UnobservedIDs[0] != "approx" || report.Failure.UnobservedIDs[1] != "variants" || report.Compared != 1 {
		t.Fatalf("partial observations relabeled complete: %#v", report)
	}
}
