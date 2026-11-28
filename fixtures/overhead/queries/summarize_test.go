// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func writeRun(t *testing.T, dir, name string, content []byte) {
	t.Helper()
	path := filepath.Join(dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
}

func gz(t *testing.T, text string) []byte {
	t.Helper()
	var b strings.Builder
	zw := gzip.NewWriter(&b)
	zw.Write([]byte(text))
	zw.Close()
	return []byte(b.String())
}

const (
	testSoundpostSHA = "711a1683cf111b0b459afb23b52ec1cd56ebda232232ecb7aee5ef6e9a6c8b36"
	testHarnessSHA   = "e7a4b781fa6b27f2cbc5df57946dac182cd42d8cc6610b8d890bd9ecf62782af"
)

// syntheticRun lays out a tiny run directory: every raw file of contract.go, the loss and the restart in the server events, a preload at
// its input for every signal, and a query file that spans the 24 h.
func syntheticRun(t *testing.T, withLoss bool) string {
	t.Helper()
	dir := t.TempDir()
	host := func(id string) []byte {
		raw, _ := json.Marshal(HostFacts{HostID: id, OS: "linux", Arch: "amd64", LogicalCPUs: 8, Gomaxprocs: 8})
		return raw
	}
	writeRun(t, dir, FileServerHost, host("server"))
	writeRun(t, dir, FileIngestHost, host("ingest"))
	writeRun(t, dir, FileQueryHost, host("query"))
	events := []Event{{TMS: 1000, Event: "start", PIDAfter: 7}, {TMS: 2000, Event: "restart", Mode: "graceful", Exit: "exit status 0", ReadyMS: 900}}
	if withLoss {
		events = []Event{events[0], {TMS: 1500, Event: "shard_loss", Mode: "slots 0-31", Note: "closed 32"}, events[1]}
	}
	var lines []string
	for _, e := range events {
		lines = append(lines, string(mustJSON(e)))
	}
	writeRun(t, dir, FileServerEvents, []byte(strings.Join(lines, "\n")+"\n"))
	writeRun(t, dir, FileServerSeries, []byte("{}\n"))
	writeRun(t, dir, FileServerLog, []byte("log\n"))
	writeRun(t, dir, FileServerRules, []byte(`{"k":"e"}`+"\n"))
	writeRun(t, dir, FileServerScans, []byte(`{"req":"a"}`+"\n"))
	writeRun(t, dir, FileServerNet, []byte("{}\n"))
	writeRun(t, dir, FilePreloadAcks, gz(t, AcksHeader+"\n"))
	pre := PreloadSummary{StartUnixMS: 10, EndUnixMS: 20, EventStartNS: 1, EventEndNS: 86400e9 + 1, Signals: map[Signal]PreloadSignal{}, SlotsByProject: [][]int{{0, 1}}}
	for _, sig := range PreloadSignals {
		pre.Signals[sig] = PreloadSignal{Batches: 3, Records: 9, EncodedBytes: InputBytesPerSignal + 5, EventStartNS: 1, EventEndNS: 86400e9 + 1}
	}
	writeRun(t, dir, FilePreloadSummary, mustJSON(pre))
	writeRun(t, dir, FileIngestAcks, gz(t, AcksHeader+"\n"))
	writeRun(t, dir, FileIngestSummary, []byte(`{"t0_unix_ms":123456,"config":{"seed":42,"orgs":10,"projects":100,"routes_per_project":3,"epoch":2},
		"requests_sent":50,"requests_acked":48,"requests_refused":1,"requests_transport_failed":1,"requests_shed_by_generator":2,
		"records_acked_by_kind":{"metric":600,"log":120},"encoded_bytes_sent":4242}`))
	writeRun(t, dir, FileIngestNet, []byte("{}\n"))
	rows := queriesBody(t)
	writeRun(t, dir, FileQueries, gz(t, rows))
	writeRun(t, dir, FileQuerySummary, []byte(`{"golden_ids":["g1","g2"]}`))
	writeRun(t, dir, FileNotifications, []byte("{}\n"))
	writeRun(t, dir, FileQueryNet, []byte("{}\n"))
	build := "source_tree_sha256=86fb4676d926e0998c249d0a14399214a06a19d839146b4eb1d25c00526ddc97\nbuild_tags=soundpost_faults\n" +
		`{"version":"0.0.0-overhead","build_id":"src-86fb"}` + "\n" + testSoundpostSHA + "  /opt/b/soundpost\n" + testHarnessSHA + "  /opt/b/queries\ngo version go1.27.3 linux/amd64\n"
	writeRun(t, dir, FileBuild, []byte(build))
	return dir
}

// queriesBody builds a queries.csv.gz body: the contract's header and three rows of two classes, the last 24 h after the first.
func queriesBody(t *testing.T) string {
	t.Helper()
	row := func(start int64, class string) string {
		cols := strings.Split(QueriesHeader, ",")
		for i := range cols {
			cols[i] = "0"
		}
		cols[0], cols[indexOfColumn(QueriesHeader, "class")] = fmt.Sprint(start), class
		return strings.Join(cols, ",")
	}
	return QueriesHeader + "\n" + row(0, ClassGolden) + "\n" + row(5_000_000, ClassPromInstant) + "\n" + row(int64(SteadyS)*1_000_000, ClassPromInstant) + "\n"
}

func TestSummarizeNamesEveryRawFileAndParses(t *testing.T) {
	dir := syntheticRun(t, true)
	res, incomplete, err := buildResult(dir, DefaultConfig())
	if err != nil || len(incomplete) != 0 || !res.Complete {
		t.Fatalf("incomplete %v: %v", incomplete, err)
	}
	for _, name := range rawFiles {
		raw, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(name)))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(raw)
		if res.Files[name] != hex.EncodeToString(sum[:]) {
			t.Errorf("%s: sha256 %q", name, res.Files[name])
		}
	}
	if len(res.Files) != len(rawFiles) {
		t.Errorf("%d files named, %d raw files", len(res.Files), len(rawFiles))
	}
	if res.Build.SourceTreeSHA256 == "" || res.Build.BuildTags != "soundpost_faults" || res.Build.SoundpostSHA256 != testSoundpostSHA || res.Build.HarnessSHA256 != testHarnessSHA || res.Build.VersionJSON == "" || res.Build.Go == "" {
		t.Errorf("build: %+v", res.Build)
	}
	if res.ServerHost.HostID != "server" || res.IngestHost.HostID != "ingest" || res.QueryHost.HostID != "query" {
		t.Errorf("hosts: %q %q %q", res.ServerHost.HostID, res.IngestHost.HostID, res.QueryHost.HostID)
	}
	g := res.Gate
	if g.Seed != 42 || g.Orgs != 10 || g.Projects != 100 || g.SeriesPerProject != 30 || g.SteadyS != 86400 || g.LossAtS != 81000 || g.RestartAtS != 82800 || len(g.LossSlots) != 32 || g.LossSlots[31] != 31 || g.Interactive != 10 || g.RulesPerMinute != 100 || g.IngestRate != 100 || g.InputBytes != 1<<30 {
		t.Errorf("gate: %+v", g)
	}
	if res.Steady.T0UnixMS != 123456 || res.Ingest.Sent != 50 || res.Ingest.Acked != 48 || res.Ingest.Shed != 2 || res.Ingest.EncodedBytes != 4242 || res.Ingest.RecordsAcked["metric"] != 600 {
		t.Errorf("ingest: %+v t0 %d", res.Ingest, res.Steady.T0UnixMS)
	}
	if res.Queries.Requests != 3 || res.Queries.ByClass[ClassPromInstant] != 2 || res.Queries.ByClass[ClassGolden] != 1 || res.Queries.Workers != 10 || len(res.Queries.GoldenIDs) != 2 {
		t.Errorf("queries: %+v", res.Queries)
	}
	if len(res.Preload.Signals) != 3 || res.Preload.EventEndNS != 86400e9+1 || len(res.ServerEvents) != 3 {
		t.Errorf("preload %+v events %d", res.Preload, len(res.ServerEvents))
	}
	// the document the command writes parses and carries the schema
	runSummarize([]string{"--dir", dir})
	var back Result
	if err := sumReadJSON(filepath.Join(dir, FileResult), &back); err != nil || back.Schema != ResultSchema || back.Harness != HarnessName || !back.Complete {
		t.Fatalf("result.json: %v %+v", err, back.Schema)
	}
}

func TestResultJSONRoundTrips(t *testing.T) {
	dir := syntheticRun(t, true)
	res, _, err := buildResult(dir, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.MarshalIndent(res, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	var back Result
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(res, back) {
		t.Fatalf("round trip changed the result:\n%s", raw)
	}
	// the field names of local://queries-contract.md
	var generic map[string]json.RawMessage
	json.Unmarshal(raw, &generic)
	for _, k := range []string{"schema", "harness", "complete", "gate", "server_host", "ingest_host", "query_host", "build", "file_sha256", "steady", "preload", "ingest", "queries", "server_events"} {
		if _, ok := generic[k]; !ok {
			t.Errorf("result.json lacks %q", k)
		}
	}
	var gate map[string]json.RawMessage
	json.Unmarshal(generic["gate"], &gate)
	for _, k := range []string{"orgs", "projects", "series_per_project", "seed", "input_bytes_per_signal", "steady_s", "interactive", "rules_per_minute", "ingest_rate", "loss_at_s", "restart_at_s", "loss_slots"} {
		if _, ok := gate[k]; !ok {
			t.Errorf("gate lacks %q", k)
		}
	}
	var build map[string]json.RawMessage
	json.Unmarshal(generic["build"], &build)
	for _, k := range []string{"source_tree_sha256", "soundpost_version_json", "soundpost_sha256", "harness_sha256", "go", "build_tags"} {
		if _, ok := build[k]; !ok {
			t.Errorf("build lacks %q", k)
		}
	}
}

func TestSummarizeIsIncompleteWithoutTheLossOrTheSpan(t *testing.T) {
	dir := syntheticRun(t, false)
	res, incomplete, err := buildResult(dir, DefaultConfig())
	if err != nil || res.Complete || len(incomplete) != 1 || !strings.Contains(incomplete[0], "shard_loss") {
		t.Fatalf("complete=%v %v %v", res.Complete, incomplete, err)
	}
	// a run that did not last 24 h, with a preload below its input and a missing file
	dir = syntheticRun(t, true)
	writeRun(t, dir, FileQueries, gz(t, QueriesHeader+"\n"+strings.Repeat("0,", len(strings.Split(QueriesHeader, ","))-1)+"0\n"))
	writeRun(t, dir, FilePreloadSummary, mustJSON(PreloadSummary{Signals: map[Signal]PreloadSignal{SignalMetric: {EncodedBytes: InputBytesPerSignal}}}))
	os.Remove(filepath.Join(dir, filepath.FromSlash(FileServerScans)))
	res, incomplete, _ = buildResult(dir, DefaultConfig())
	text := strings.Join(incomplete, "\n")
	if res.Complete || !strings.Contains(text, "queries span") || !strings.Contains(text, "preload of log") || !strings.Contains(text, "preload of span") || !strings.Contains(text, "missing "+FileServerScans) {
		t.Fatalf("complete=%v:\n%s", res.Complete, text)
	}
	if _, ok := res.Files[FileServerScans]; ok {
		t.Error("a missing file was named by sha256")
	}
}
