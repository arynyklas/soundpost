// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package queryinput_test

// Cross-check of the decoders against bytes produced by real upstream senders
// (conformance/query/fixtures/adapters/real, provenance in PROVENANCE.json):
// remote-write v1/v2 requests emitted by the pinned Prometheus 3.13.5 binary
// (golang/snappy block encoder, upstream protobuf) and OpenMetrics text emitted
// by Loki 3.5.2 (client_golang). Expected values come from the exposition the
// sender scraped, never from the decoder under test.

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	. "github.com/arynyklas/soundpost/internal/adapters/queryinput"
	"github.com/arynyklas/soundpost/internal/adapters/queryinput/corpus"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/policy"
)

const realDir = "../../../conformance/query/fixtures/adapters/real"

const realTraceID = "0af7651916cd43dd8448eb211c80319c" // the exemplar in fixture-exposition.om

type realEnv struct {
	h   *corpus.Harness
	g   policy.SourceGrant
	cfg InputProfile
}

func newRealEnv(t *testing.T) realEnv {
	t.Helper()
	h, err := corpus.OpenHarness(t.Context(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.Close() })
	g, err := h.Grant()
	if err != nil {
		t.Fatal(err)
	}
	cfg := h.Profile()
	cfg.MinTimestamp = model.UnixNano(1_700_000_000_000_000_000)
	cfg.MaxTimestamp = model.UnixNano(1_900_000_000_000_000_000)
	cfg.Help = HelpDiscard // D23: the served bridge discards HELP
	return realEnv{h: h, g: g, cfg: cfg}
}

func realFile(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(realDir, name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func realFiles(t *testing.T, pattern string) []string {
	t.Helper()
	m, err := filepath.Glob(filepath.Join(realDir, pattern))
	if err != nil || len(m) == 0 {
		t.Fatalf("no fixtures for %s: %v", pattern, err)
	}
	sort.Strings(m)
	return m
}

func (e realEnv) rw(t *testing.T, version WireVersion, body []byte, cfg InputProfile) ([]model.Batch, error) {
	t.Helper()
	return DecodeRemoteWrite(t.Context(), e.g, version, bytes.NewReader(body), cfg)
}

func versionOf(path string) WireVersion {
	if strings.Contains(filepath.Base(path), "-v2-") {
		return RemoteWriteV2
	}
	return RemoteWriteV1
}

func detailOf(err error) (Reason, string) {
	var qe *Error
	if errors.As(err, &qe) {
		return qe.Reason, qe.Detail
	}
	return "", ""
}

func projected(batches []model.Batch) []map[string]any {
	var out []map[string]any
	for _, o := range corpus.ProjectRecords(batches) {
		out = append(out, o.(map[string]any))
	}
	return out
}

func f64hex(v float64) string { return strconv.FormatUint(math.Float64bits(v), 16) }

// TestRealFixtureProvenanceIsPinned: every captured file is hashed in
// PROVENANCE.json, so a doctored or swapped fixture fails here.
func TestRealFixtureProvenanceIsPinned(t *testing.T) {
	var prov struct {
		Files map[string]string `json:"sha256"`
	}
	if err := json.Unmarshal(realFile(t, "PROVENANCE.json"), &prov); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(realDir)
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, e := range entries {
		if e.Name() == "PROVENANCE.json" {
			continue
		}
		seen++
		sum := sha256.Sum256(realFile(t, e.Name()))
		if want := prov.Files[e.Name()]; want != hex.EncodeToString(sum[:]) {
			t.Errorf("%s: sha256 %x not pinned (provenance %q)", e.Name(), sum, want)
		}
	}
	if seen != len(prov.Files) || seen == 0 {
		t.Fatalf("provenance lists %d files, directory has %d", len(prov.Files), seen)
	}
}

// TestRealSnappyBlocksFromUpstreamEncoder decodes the snappy framing produced by
// golang/snappy inside Prometheus: the declared length must match, the stream
// must really use copy elements (not literals only), and our encoder's output
// of the same plaintext must decode back to it.
func TestRealSnappyBlocksFromUpstreamEncoder(t *testing.T) {
	copies, missingHeaders := 0, 0
	files := realFiles(t, "rw-*.bin")
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		plain, err := SnappyDecode("t", raw, 1<<20)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		declared, n := binary.Uvarint(raw)
		if n <= 0 || declared != uint64(len(plain)) {
			t.Fatalf("%s: preamble %d vs decoded %d", f, declared, len(plain))
		}
		if len(raw) < len(plain) {
			copies++
		}
		again, err := SnappyDecode("t", snappyEncode(plain), 1<<20)
		if err != nil || !bytes.Equal(again, plain) {
			t.Fatalf("%s: re-encode round trip: %v", f, err)
		}
		rawHdr, err := os.ReadFile(strings.TrimSuffix(f, ".bin") + ".headers.json")
		if errors.Is(err, os.ErrNotExist) {
			missingHeaders++ // rw-v1-001: the capture server lost its header file; see PROVENANCE.json
			continue
		} else if err != nil {
			t.Fatal(err)
		}
		var hdr map[string]string
		if err := json.Unmarshal(rawHdr, &hdr); err != nil {
			t.Fatal(err)
		}
		if hdr["Content-Encoding"] != "snappy" || !strings.HasPrefix(hdr["User-Agent"], "Prometheus/3.13.5") {
			t.Fatalf("%s: unexpected sender headers %v", f, hdr)
		}
		wantV := "0.1.0"
		if versionOf(f) == RemoteWriteV2 {
			wantV = "2.0.0"
		}
		if hdr["X-Prometheus-Remote-Write-Version"] != wantV {
			t.Fatalf("%s: version header %q", f, hdr["X-Prometheus-Remote-Write-Version"])
		}
	}
	if missingHeaders > 1 {
		t.Fatalf("%d payloads without a header file, only rw-v1-001 is known to lack one", missingHeaders)
	}
	if copies < len(files)/2 {
		t.Fatalf("only %d of %d real payloads are copy-compressed; fixture does not exercise the copy elements", copies, len(files))
	}
}

// expected series values, derived from fixture-exposition.om (the scraped input).
var realExpected = map[string]string{
	"soundpost_fixture_requests_total|code=200,method=get":   f64hex(1027),
	"soundpost_fixture_requests_total|code=500,method=post":  f64hex(3),
	"soundpost_fixture_requests_created|code=200,method=get": f64hex(1700000000),
	"soundpost_fixture_temperature_celsius|room=lab":         f64hex(21.5),
	"soundpost_fixture_temperature_celsius|room=cellar":      f64hex(-3.25),
	"up|": f64hex(1),
}

func seriesKey(m map[string]any) string {
	labels, _ := m["labels"].(map[string]any)
	var parts []string
	for k, v := range labels {
		if k == "job" || k == "instance" {
			continue
		}
		parts = append(parts, k+"="+v.(string))
	}
	sort.Strings(parts)
	return m["name"].(string) + "|" + strings.Join(parts, ",")
}

func TestRealRemoteWriteSamplesMatchTheScrapedValues(t *testing.T) {
	e := newRealEnv(t)
	for _, v := range []WireVersion{RemoteWriteV1, RemoteWriteV2} {
		got := map[string]int{}
		decoded := 0
		for _, f := range realFiles(t, "rw-*.bin") {
			if versionOf(f) != v || bytes.Contains(unsnappy(t, f), []byte(realTraceID)) {
				continue
			}
			batches, err := e.rw(t, v, realFile(t, filepath.Base(f)), e.cfg)
			if err != nil {
				t.Fatalf("%s: %v", f, err)
			}
			if len(batches) == 0 {
				continue // metadata-only request
			}
			decoded++
			for _, m := range projected(batches) {
				if m["hist"] != nil {
					continue
				}
				key := seriesKey(m)
				want, ok := realExpected[key]
				if !ok {
					continue // scrape_* auto-series carry run-specific values
				}
				if m["bits"] != want || m["sample"] != "float" {
					t.Errorf("%s %s: bits %v want %s", f, key, m["bits"], want)
				}
				if labels := m["labels"].(map[string]any); labels["job"] != "fixture" || labels["instance"] != "cap:9000" {
					t.Errorf("%s %s: target labels %v", f, key, labels)
				}
				got[key]++
			}
		}
		if decoded < 3 {
			t.Fatalf("version %v: only %d value-bearing real requests decoded", v, decoded)
		}
		for key := range realExpected {
			if got[key] == 0 {
				t.Errorf("version %v: series %s never decoded from real output", v, key)
			}
		}
	}
}

func unsnappy(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := SnappyDecode("t", raw, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	return plain
}

// The classic histogram in the exposition (cumulative 5,12,14,15; sum 9.75;
// bounds 0.1,0.5,2.5) arrives as a native custom-bucket histogram in remote
// write v2: per-bucket counts 5,7,2,1 => deltas 5,2,-5,-1.
func TestRealRemoteWriteV2CustomBucketHistogram(t *testing.T) {
	e := newRealEnv(t)
	found := 0
	for _, f := range realFiles(t, "rw-v2-*.bin") {
		if bytes.Contains(unsnappy(t, f), []byte(realTraceID)) {
			continue
		}
		batches, err := e.rw(t, RemoteWriteV2, realFile(t, filepath.Base(f)), e.cfg)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range projected(batches) {
			if m["hist"] == nil {
				continue
			}
			if m["name"] != "soundpost_fixture_latency_seconds" {
				t.Fatalf("histogram name %v", m["name"])
			}
			raw, _ := json.Marshal(m["hist"])
			var h struct {
				Count    string   `json:"count"`
				Sum      string   `json:"sum"`
				Schema   int      `json:"schema"`
				Custom   []string `json:"custom"`
				Positive struct {
					Deltas []string   `json:"deltas"`
					Spans  [][2]int64 `json:"spans"`
				} `json:"positive"`
			}
			if err := json.Unmarshal(raw, &h); err != nil {
				t.Fatal(err)
			}
			wantBounds := []string{f64hex(0.1), f64hex(0.5), f64hex(2.5)}
			if h.Count != "15" || h.Sum != f64hex(9.75) || h.Schema != -53 ||
				strings.Join(h.Custom, ",") != strings.Join(wantBounds, ",") ||
				strings.Join(h.Positive.Deltas, ",") != "5,2,-5,-1" || len(h.Positive.Spans) != 1 || h.Positive.Spans[0] != [2]int64{0, 4} {
				t.Fatalf("histogram %s", raw)
			}
			found++
		}
	}
	if found < 2 {
		t.Fatalf("custom-bucket histogram found %d times in real v2 output", found)
	}
}

// Prometheus sends metadata in requests of their own. They carry nothing to
// admit and must be acknowledged (a 4xx makes the sender log a permanent error).
func TestRealRemoteWriteMetadataOnlyRequestIsANoOp(t *testing.T) {
	e := newRealEnv(t)
	n := 0
	for _, f := range realFiles(t, "rw-v1-*.bin") {
		batches, err := e.rw(t, RemoteWriteV1, realFile(t, filepath.Base(f)), e.cfg)
		if err == nil && len(batches) == 0 {
			n++
			// ... with the HELP-rejecting default the metadata text is still not admitted data.
			cfg := e.cfg
			cfg.Help = HelpReject
			if b, err := e.rw(t, RemoteWriteV1, realFile(t, filepath.Base(f)), cfg); err != nil || len(b) != 0 {
				t.Fatalf("%s: metadata-only under HelpReject: %v %d", f, err, len(b))
			}
		}
	}
	if n == 0 {
		t.Fatal("no metadata-only request among real v1 payloads")
	}
}

// Prometheus ships exemplars as series entries of their own (no samples). The
// decoder cannot attach such an exemplar to a point and, per D23, exemplars are
// refused: a typed unrepresentable refusal in every exemplar mode.
func TestRealRemoteWriteExemplarSeriesAreRefusedTyped(t *testing.T) {
	e := newRealEnv(t)
	n := 0
	for _, f := range realFiles(t, "rw-*.bin") {
		if !bytes.Contains(unsnappy(t, f), []byte(realTraceID)) {
			continue
		}
		n++
		for _, mode := range []ExemplarMode{ExemplarsReject, ExemplarsTraceLink} {
			cfg := e.cfg
			cfg.Exemplars = mode
			_, err := e.rw(t, versionOf(f), realFile(t, filepath.Base(f)), cfg)
			if r, d := detailOf(err); r != ReasonUnrepresentable || d != "exemplar_only_series" {
				t.Fatalf("%s mode %s: %v", f, mode, err)
			}
		}
	}
	if n == 0 {
		t.Fatal("no exemplar-bearing real payload")
	}
}

func normHex(h string) string {
	if h = strings.TrimLeft(h, "0"); h == "" {
		return "0"
	}
	return h
}

// sampleLines returns name|value-bits counts of the sample lines of an
// exposition, leaving out the "<family>_created" lines of counter families
// (start timestamps, never records of their own).
func sampleLines(t *testing.T, body []byte) map[string]int {
	t.Helper()
	type line struct{ name, rest string }
	var all []line
	names := map[string]bool{}
	for _, l := range strings.Split(string(body), "\n") {
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		if i := strings.Index(l, " # "); i >= 0 {
			l = l[:i]
		}
		name, rest := l, ""
		if i := strings.IndexAny(l, "{ "); i >= 0 {
			name, rest = l[:i], l[i:]
		}
		names[name] = true
		all = append(all, line{name, rest})
	}
	want := map[string]int{}
	for _, l := range all {
		if fam, ok := strings.CutSuffix(l.name, "_created"); ok && names[fam+"_total"] {
			continue
		}
		rest := l.rest
		if j := strings.LastIndex(rest, "}"); j >= 0 {
			rest = rest[j+1:]
		}
		fields := strings.Fields(rest)
		if len(fields) != 1 {
			t.Fatalf("sample line %q has %d value fields", l.name+l.rest, len(fields))
		}
		v, err := strconv.ParseFloat(fields[0], 64)
		if err != nil {
			t.Fatalf("sample value %q: %v", fields[0], err)
		}
		want[l.name+"|"+normHex(f64hex(v))]++
	}
	return want
}

func recordCounts(batches []model.Batch) map[string]int {
	got := map[string]int{}
	for _, m := range projected(batches) {
		if m["bits"] != nil {
			got[m["name"].(string)+"|"+normHex(m["bits"].(string))]++
		}
	}
	return got
}

func TestRealOpenMetricsFromUpstreamExposition(t *testing.T) {
	e := newRealEnv(t)

	// The exposition Prometheus was scraping (HELP before TYPE before UNIT is the
	// order every real producer uses).
	own := realFile(t, "fixture-exposition.om")
	ownCfg := e.cfg
	ownCfg.Exemplars = ExemplarsTraceLink
	batches, err := DecodeOpenMetrics(t.Context(), e.g, bytes.NewReader(own), ownCfg)
	if err != nil {
		t.Fatal(err)
	}
	got, want := recordCounts(batches), sampleLines(t, own)
	if len(got) != len(want) {
		t.Fatalf("fixture exposition: %d distinct records, %d sample lines", len(got), len(want))
	}
	for k, n := range want {
		if got[k] != n {
			t.Errorf("fixture exposition: %s decoded %d times, want %d", k, got[k], n)
		}
	}

	// Loki 3.5.2's own /metrics (client_golang OpenMetrics): 300 families.
	real := realFile(t, "loki-3.5.2-self-metrics.om")
	if _, err := DecodeOpenMetrics(t.Context(), e.g, bytes.NewReader(real), e.cfg); err == nil {
		t.Fatal("verbatim Loki exposition decoded: go_memstats_alloc_bytes is declared twice (gauge and counter) and must stay refused")
	} else if r, d := detailOf(err); r != ReasonMalformed || d != "family_redeclared" {
		t.Fatalf("verbatim Loki exposition: %v", err)
	}
	// With HELP rejected (the library default) the first HELP line refuses it.
	strict := e.cfg
	strict.Help = HelpReject
	if _, err := DecodeOpenMetrics(t.Context(), e.g, bytes.NewReader(real), strict); err == nil {
		t.Fatal("HELP text accepted under HelpReject")
	} else if r, d := detailOf(err); r != ReasonUnrepresentable || d != "help_text" {
		t.Fatalf("HelpReject: %v", err)
	}

	// The same bytes minus the second go_memstats_alloc_bytes family (its HELP,
	// TYPE and one sample line) decode, every sample line becoming a record.
	lines := strings.Split(string(real), "\n")
	var kept []string
	for i, l := range lines {
		if i >= 308 && i <= 310 {
			if !strings.Contains(l, "go_memstats_alloc_bytes") {
				t.Fatalf("line %d is %q, fixture changed", i+1, l)
			}
			continue
		}
		kept = append(kept, l)
	}
	trimmed := []byte(strings.Join(kept, "\n"))
	batches, err = DecodeOpenMetrics(t.Context(), e.g, bytes.NewReader(trimmed), e.cfg)
	if err != nil {
		t.Fatal(err)
	}
	got, want = recordCounts(batches), sampleLines(t, trimmed)
	total := 0
	for k, n := range want {
		total += n
		if got[k] != n {
			t.Errorf("loki exposition: %s decoded %d times, want %d", k, got[k], n)
		}
	}
	if total < 1000 || len(got) != len(want) {
		t.Fatalf("loki exposition: %d sample lines, %d distinct want, %d distinct got", total, len(want), len(got))
	}
}
