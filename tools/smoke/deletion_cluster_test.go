// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/storage"
)

const dcTestCanary = "deletion_cluster_canary_00112233445566778899aabbccddeeff"

func writeDCFile(t *testing.T, dir, rel string, content []byte) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, content, 0o600); err != nil {
		t.Fatal(err)
	}
}

// The scan must find the canary raw, inside base64, inside JSON inside base64 (the form a
// journal and a snapshot carry it in), attribute it to the right store, and report zero for a
// directory that has none.
func TestDeletionClusterScanFindsNestedCanaryAndAttributesStores(t *testing.T) {
	dir := t.TempDir()
	inner := base64.StdEncoding.EncodeToString([]byte(`{"name":"` + dcTestCanary + `"}`))
	wrapped := base64.StdEncoding.EncodeToString([]byte(`{"command":"` + inner + `"}`))
	writeDCFile(t, dir, "data/apply.db", append([]byte("page\x00\x00"), []byte(dcTestCanary)...))
	writeDCFile(t, dir, "raft/data/ready.wal", []byte(`{"entry":"`+wrapped+`"}`))
	writeDCFile(t, dir, "raft/data/snapshots/0001/envelope.json", []byte(`{"state":"`+wrapped+`"}`))
	writeDCFile(t, dir, "data/segments/0001.seg", []byte("no canary here"))
	writeDCFile(t, dir, "server.crt", []byte("certificate"))
	got, err := dcScanDir(dir, dcTestCanary)
	if err != nil {
		t.Fatal(err)
	}
	if got.Files != 5 || got.Hits < 3 {
		t.Fatalf("scan %+v", got)
	}
	for store, want := range map[string]bool{"apply_db": true, "raft_journal": true, "snapshots": true, "segments": false, "other": false} {
		if (got.ByStore[store] > 0) != want {
			t.Fatalf("store %s hits %d, want present=%v (%+v)", store, got.ByStore[store], want, got.ByStore)
		}
	}
	if _, ok := got.HitFiles["data/apply.db"]; !ok {
		t.Fatalf("hit files %v", got.HitFiles)
	}

	clean := t.TempDir()
	writeDCFile(t, clean, "data/apply.db", []byte("nothing of interest"))
	writeDCFile(t, clean, "raft/data/ready.wal", []byte(base64.StdEncoding.EncodeToString([]byte(`{"other":"value"}`))))
	zero, err := dcScanDir(clean, dcTestCanary)
	if err != nil || zero.Hits != 0 || len(zero.ByStore) != 0 || zero.Files != 2 {
		t.Fatalf("clean directory: %+v %v", zero, err)
	}
}

func TestDeletionClusterStoreClasses(t *testing.T) {
	for rel, want := range map[string]string{
		"data/apply.db":                        "apply_db",
		"data/segments/000001.seg":             "segments",
		"raft/data/ready.wal":                  "raft_journal",
		"raft/data/snapshots/7/envelope.json":  "snapshots",
		"raft/data/snapshots/7/files/apply.db": "snapshots",
		"raft/control/ready.wal":               "raft_journal",
		"control.db":                           "control_db",
		"server.crt":                           "other",
		"cluster/seed.json":                    "other",
	} {
		if got := dcStoreOf(rel); got != want {
			t.Errorf("%s: %s, want %s", rel, got, want)
		}
	}
}

// A wait that never finishes is a typed failure naming the stage and what it waited for,
// within its bound; a poll error aborts at once; a poll that completes returns nil.
func TestDeletionClusterWaitIsBoundedAndTyped(t *testing.T) {
	r := newDCRecorder()
	r.enter("dc_wait_complete_node_3_down")
	began := time.Now()
	calls := 0
	err := r.until("operation_complete_node_1", 120*time.Millisecond, 10*time.Millisecond, func() (bool, string, error) {
		calls++
		return false, "phase_fencing_physical_pending", nil
	})
	var typed *smokeFailure
	if !errors.As(err, &typed) || typed.Smoke != dcSmoke || typed.Stage != "dc_wait_complete_node_3_down" || typed.Code != "timeout_operation_complete_node_1" {
		t.Fatalf("not a typed stage timeout: %v", err)
	}
	if took := time.Since(began); took < 100*time.Millisecond || took > 5*time.Second || calls < 2 {
		t.Fatalf("bound not honoured: %v after %d polls", took, calls)
	}
	if !strings.Contains(r.detail, "phase_fencing_physical_pending") {
		t.Fatalf("last progress lost: %q", r.detail)
	}

	boom := &smokeFailure{Stage: "poll_operation", Code: "unavailable", Actual: 500}
	err = r.until("x", time.Minute, time.Hour, func() (bool, string, error) { return false, "", boom })
	if !errors.As(err, &typed) || typed.Stage != "dc_wait_complete_node_3_down" || typed.Code != "poll_operation_unavailable" || typed.Actual != 500 {
		t.Fatalf("helper failure not folded into this stage: %v", err)
	}
	if err = r.until("x", time.Minute, time.Hour, func() (bool, string, error) { return true, "", nil }); err != nil {
		t.Fatal(err)
	}
}

// A false assertion is the typed failure (code = its name) and is kept in the artifact with
// the stage it ran in; the artifact is written for a failed run, lists every assertion and
// timing, and carries neither the canary nor any session material.
func TestDeletionClusterArtifactRecordsFailureAndLeaksNothing(t *testing.T) {
	dir := t.TempDir()
	r := newDCRecorder()
	r.artifactDir = dir
	r.enter("dc_scan_stopped_data_directories")
	if err := r.check("stopped_scan_zero_hits_node_1", true, "0 hits in 9 files"); err != nil {
		t.Fatal(err)
	}
	r.mark("all_stopped_ms")
	err := r.check("stopped_scan_zero_hits_node_2", false, "3 hits in 9 files (1024 bytes); by store map[apply_db:3]")
	if err = r.finish(err); err == nil {
		t.Fatal("a failed assertion must stay an error")
	}
	var typed *smokeFailure
	if !errors.As(err, &typed) || typed.Stage != "dc_scan_stopped_data_directories" || typed.Code != "stopped_scan_zero_hits_node_2" {
		t.Fatalf("failure not typed: %v", err)
	}
	raw, rerr := os.ReadFile(filepath.Join(dir, "deletion-cluster.json"))
	if rerr != nil {
		t.Fatal(rerr)
	}
	var got dcArtifact
	if err = json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got.Result != "failed" || got.Failure == nil || got.Failure.Stage != "dc_scan_stopped_data_directories" || got.Failure.Code != "stopped_scan_zero_hits_node_2" || !strings.Contains(got.Failure.Detail, "3 hits") {
		t.Fatalf("artifact failure: %+v", got.Failure)
	}
	if len(got.Assertions) != 2 || !got.Assertions[0].OK || got.Assertions[1].OK || got.Assertions[1].Stage != "dc_scan_stopped_data_directories" {
		t.Fatalf("assertions: %+v", got.Assertions)
	}
	if _, ok := got.TimingsMS["all_stopped_ms"]; !ok || len(got.Stages) != 1 || got.Stages[0].Name != "dc_scan_stopped_data_directories" {
		t.Fatalf("timings/stages: %+v %+v", got.TimingsMS, got.Stages)
	}
	if !strings.Contains(got.Caveat, "NOT three physical failure domains") || len(got.NotRun) == 0 {
		t.Fatalf("the artifact must state what it is not: %+v", got)
	}
	for _, secret := range []string{dcTestCanary, "csrf", "__Host-soundpost"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatalf("artifact carries %q", secret)
		}
	}

	pass := newDCRecorder()
	pass.artifactDir = t.TempDir()
	if err = pass.finish(nil); err != nil {
		t.Fatal(err)
	}
	if pass.art.Result != "passed" || pass.art.Failure != nil {
		t.Fatalf("passing run: %+v", pass.art)
	}
}

// A helper's error is folded into this smoke's stage without echoing anything the helper
// carried beyond its own typed stage/code.
func TestDeletionClusterWrapKeepsOnlyTypedBoundary(t *testing.T) {
	r := newDCRecorder()
	r.enter("dc_ready_all")
	err := r.wrap(&smokeFailure{Stage: "member_ready", Code: "timeout_no_quorum"})
	var typed *smokeFailure
	if !errors.As(err, &typed) || typed.Stage != "dc_ready_all" || typed.Code != "member_ready_timeout_no_quorum" || typed.Smoke != dcSmoke {
		t.Fatalf("wrap: %v", err)
	}
	if r.wrap(nil) != nil {
		t.Fatal("nil must stay nil")
	}
	err = r.wrap(errors.New("secret path /tmp/x and token abc"))
	if !errors.As(err, &typed) || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "abc") {
		t.Fatalf("untyped error leaked: %v", err)
	}
}

func TestDeletionClusterReceiptAndDenialClassifiers(t *testing.T) {
	if !dcNamesApplyDB([]string{"control_journal", storage.ResidualApplyDB}) || dcNamesApplyDB(nil) || dcNamesApplyDB([]string{"control_journal"}) {
		t.Fatal("residual classification")
	}
	for status, want := range map[int]bool{404: true, 403: true, 401: true, 200: false, 503: false, 500: false, 0: false} {
		if got := dcDenied(status, []byte(`{"code":"not_found"}`)); got != want {
			t.Errorf("status %d: denied=%v, want %v", status, got, want)
		}
	}
	failed := []byte(`{"projects":[{"failure":{"code":"not_found"}}]}`)
	if !dcDenied(200, failed) {
		t.Fatal("a 200 whose project carries a failure is a typed denial")
	}
	if dcDenied(200, []byte(`{"projects":[{"completeness":"complete","value":{"type":"vector"}}]}`)) || dcDenied(200, []byte(`{"projects":[]}`)) || dcDenied(200, []byte(`not json`)) {
		t.Fatal("a served or empty or undecodable 200 is not a denial")
	}
	if dcFaultCode([]byte(`{"code":"not_found"}`)) != "not_found" || dcFaultCode([]byte(`{"code":"Bad Code"}`)) != "unknown" || dcFaultCode([]byte(`x`)) != "" {
		t.Fatal("fault code")
	}
	if dcServedLatest(404, []byte(`{}`), 6) || dcServedLatest(200, []byte(`{"projects":[]}`), 6) {
		t.Fatal("not a served answer")
	}
}
