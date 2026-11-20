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
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
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

// The restored sibling is read as of the older backup, not at a time taken from the clock: the restored
// data ends at the backup and an instant query sees a sample only inside the five minute lookback, so a
// clock-relative time reads an empty vector in a default run that lasted past it (a loaded run did:
// timeout_restored_sibling_data on a healthy restore). A later ingest moving the live query time does not
// move it either.
func TestRestoredSiblingIsReadAsOfTheBackupNotTheClock(t *testing.T) {
	sample := time.Unix(1_800_000_000, 0)
	r := &dcRun{}
	r.sib.queryTime = strconv.FormatInt(sample.Add(time.Minute).UnixNano(), 10)
	r.backupAt = r.sib.queryTime
	r.sib.queryTime = strconv.FormatInt(sample.Add(250*time.Second).UnixNano(), 10)
	at, err := strconv.ParseInt(r.restoredSiblingTime(), 10, 64)
	if err != nil {
		t.Fatalf("the restored sibling query time is not an instant: %v", err)
	}
	if age := time.Duration(at - sample.UnixNano()); age <= 0 || age >= 5*time.Minute {
		t.Fatalf("the restored sibling is read %v after its sample: outside (0, 5m), the lookback of the engine", age)
	}
}

// A poll that waits for a served sample names what the last answer was, not just the status.
func TestDeletionClusterServedWhatNamesTheLastAnswer(t *testing.T) {
	empty := []byte(`{"projects":[{"completeness":"complete","value":{"type":"vector","vector":[]}}]}`)
	if got := dcServedWhat(200, empty); got != "status_200_projects_1_completeness_complete_samples_0" {
		t.Errorf("an empty vector: %q", got)
	}
	if got := dcServedWhat(503, []byte(`{"code":"unavailable"}`)); got != "status_503_code_unavailable" {
		t.Errorf("a refusal: %q", got)
	}
	if got := dcServedWhat(200, []byte(`{"projects":[{"failure":{"code":"not_found"}}]}`)); got != "status_200_projects_1_project_failure" {
		t.Errorf("a project failure: %q", got)
	}
}

// A live voter whose journals are not compacted past the lagging voter yet is named, so the smoke waits
// for it instead of judging one read taken right after its files were clean (node 2: 0 of 65 while node 1
// had 64 of 65).
func TestDeletionClusterNotCutPastNamesTheVotersStillToCompact(t *testing.T) {
	lagging := map[string]dcJournal{"raft/data/slot-1/ready.wal": {Snapshot: 4, Last: 5}, "raft/control/ready.wal": {Snapshot: 14, Last: 45}}
	cut := map[string]dcJournal{"raft/data/slot-1/ready.wal": {Snapshot: 9, Last: 12}, "raft/control/ready.wal": {Snapshot: 50, Last: 52}}
	uncut := map[string]dcJournal{"raft/data/slot-1/ready.wal": {Snapshot: 4, Last: 12}, "raft/control/ready.wal": {Snapshot: 14, Last: 52}}
	if got := dcNotCutPast(lagging, map[uint64]map[string]dcJournal{1: cut, 2: uncut}); !slices.Equal(got, []string{"node_2"}) {
		t.Fatalf("one voter still to compact: %v", got)
	}
	if got := dcNotCutPast(lagging, map[uint64]map[string]dcJournal{1: cut, 2: cut}); len(got) != 0 {
		t.Fatalf("both compacted: %v", got)
	}
}

// The runs are the lagging-node runs in order, then the replacement runs, then the early-learner
// replacement runs; "none" drops one kind and a plan with no run, a repeated node or a node that is
// not a voter is refused. Each run has its own artifact.
func TestDeletionClusterPlanOrdersLagRunsThenReplaceRuns(t *testing.T) {
	got, err := dcPlan("3,2,1", "3", "none")
	want := []dcPlanStep{{3, false, false}, {2, false, false}, {1, false, false}, {3, true, false}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("%v %v", got, err)
	}
	if got, err = dcPlan("none", "2,1", "none"); err != nil || !reflect.DeepEqual(got, []dcPlanStep{{2, true, false}, {1, true, false}}) {
		t.Fatalf("%v %v", got, err)
	}
	if got, err = dcPlan("1", "none", "none"); err != nil || !reflect.DeepEqual(got, []dcPlanStep{{1, false, false}}) {
		t.Fatalf("%v %v", got, err)
	}
	early, err := dcPlan("none", "3", "3,2")
	wantEarly := []dcPlanStep{{3, true, false}, {3, true, true}, {2, true, true}}
	if err != nil || !reflect.DeepEqual(early, wantEarly) {
		t.Fatalf("%v %v", early, err)
	}
	for _, bad := range [][3]string{{"none", "none", "none"}, {"1,1", "none", "none"}, {"4", "none", "none"}, {"1", "0", "none"}, {"1", "", "none"}, {"", "none", "none"}, {"none", "none", "3,3"}, {"none", "none", "4"}, {"none", "none", ""}} {
		if got, err = dcPlan(bad[0], bad[1], bad[2]); err == nil {
			t.Errorf("%v accepted: %v", bad, got)
		}
	}
	names := map[string]bool{}
	for _, s := range append(slices.Clone(want), dcPlanStep{3, true, true}) {
		names[dcRunArtifactName(s)] = true
	}
	if len(names) != len(want)+1 || !names["deletion-cluster-lag-3.json"] || !names["deletion-cluster-replace-3.json"] || !names["deletion-cluster-replace-early-3.json"] {
		t.Fatalf("artifact names collide or are misnamed: %v", names)
	}
}

// A voter is given the authority flags exactly when the run has an authority, and the rest of its
// command line is the shared process cluster's.
func TestDeletionClusterServeArgsCarryTheAuthorityOnlyWhenConfigured(t *testing.T) {
	plain := dcServeArgs(2, "/n/node-2.json", "/d/2", "127.0.0.1:1", nil)
	want := []string{"serve", "--mode=distributed", "--node-id", "2", "--cluster-config", "/n/node-2.json", "--data-dir", "/d/2", "--listen", "127.0.0.1:1"}
	if !reflect.DeepEqual(plain, want) {
		t.Fatalf("%v", plain)
	}
	with := dcServeArgs(2, "/n/node-2.json", "/d/2", "127.0.0.1:1", &dcAuthority{Keys: "/k/full", Restricted: "/k/restricted", Dir: "/a/dir"})
	if !reflect.DeepEqual(with, append(want, "--authority-keys", "/k/full", "--authority-dir", "/a/dir")) {
		t.Fatalf("%v", with)
	}
	for _, arg := range with {
		if arg == "/k/restricted" {
			t.Fatal("serve must be given the full keys: restricted keys cannot checkpoint a deletion")
		}
	}
}

// A command that exits 0 returns its stdout alone; one that fails is a typed {stage, command_failed}
// whose detail is the last stderr line reduced to words that cannot carry a path or a key; a command
// past its limit fails. The "binary" is a shell script (POSIX hosts only).
func TestDeletionClusterCLIFailureIsTypedAndSafe(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fake binary is a POSIX shell script")
	}
	script := func(name, body string) string {
		p := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		return p
	}
	ok := script("ok", `printf '{"backup_id":"x"}'; echo "noise on stderr" >&2`)
	out, line, err := dcCLI(ok, nil, time.Minute, "backup", "create", "--data-dir", "/secret/dir")
	if err != nil || line != "" || string(out) != `{"backup_id":"x"}` {
		t.Fatalf("%q %q %v", out, line, err)
	}
	fail := script("fail", `echo "an earlier line" >&2; echo 'soundpost backup failed: unavailable (head_unavailable) [retryable] at /tmp/secret/path key=abc123 O:\win\path' >&2; exit 1`)
	out, line, err = dcCLI(fail, nil, time.Minute, "backup", "restore", "--root", "/secret/root")
	var typed *smokeFailure
	if !errors.As(err, &typed) || typed.Code != "command_failed" || typed.Stage != "cli_backup_restore" || out != nil {
		t.Fatalf("%q %v", out, err)
	}
	if line != "soundpost backup failed: unavailable (head_unavailable) [retryable] at" {
		t.Fatalf("detail %q", line)
	}
	slow := script("slow", `exec sleep 30`)
	started := time.Now()
	if _, _, err = dcCLI(slow, nil, 200*time.Millisecond, "backup", "create"); err == nil || time.Since(started) > 20*time.Second {
		t.Fatalf("a command past its limit must fail promptly: %v after %v", err, time.Since(started))
	}
	env := script("env", `printf '%s' "$DC_PROBE"`)
	if out, _, err = dcCLI(env, []string{"DC_PROBE=seen"}, time.Minute, "x"); err != nil || string(out) != "seen" {
		t.Fatalf("the environment is passed to the command: %q %v", out, err)
	}
}

// The reports of backup create, restore and activate are read strictly: a report without a backup id or
// objects is not a backup, and a malformed one is an error.
func TestDeletionClusterCLIReportsAreParsedStrictly(t *testing.T) {
	id := model.NewID().String()
	created, err := dcParseBackupCreate([]byte(`{"backup_id":"` + id + `","objects":67,"control_revision":"12","authority_sequence":1,"authority_generation":"0","voters":3,"gaps":0}`))
	if err != nil || created.ID != id || created.Objects != 67 || created.AuthoritySequence != 1 || created.Voters != 3 || created.ControlRevision != 12 {
		t.Fatalf("%+v %v", created, err)
	}
	if _, err = dcParseBackupCreate([]byte(`{"backup_id":"` + id + `","objects":3,"voters":"three"}`)); err == nil {
		t.Error("a voter count that is not an integer accepted")
	}
	for _, bad := range []string{``, `not json`, `{}`, `{"backup_id":"x","objects":3}`, `{"backup_id":"` + id + `","objects":0}`, `{"backup_id":"` + id + `","objects":3,"authority_sequence":-1}`} {
		if _, err = dcParseBackupCreate([]byte(bad)); err == nil {
			t.Errorf("backup report %q accepted", bad)
		}
		if _, err = dcParseRestore([]byte(bad)); err == nil {
			t.Errorf("restore report %q accepted", bad)
		}
	}
	restored, err := dcParseRestore([]byte(`{"backup_id":"` + id + `","objects":67,"authority_sequence":"3","authority_generation":1,"tombstones":1,"control_revision":12}`))
	if err != nil || restored.AuthoritySequence != 3 || restored.Tombstones != 1 || restored.AuthorityGeneration != 1 {
		t.Fatalf("%+v %v", restored, err)
	}
	activated, err := dcParseActivate([]byte(`{"authority_generation":1,"tombstones":1,"ready":true,"cluster_seed":false}`))
	if err != nil || !activated.Ready || activated.Tombstones != 1 {
		t.Fatalf("%+v %v", activated, err)
	}
	if _, err = dcParseActivate([]byte(`x`)); err == nil {
		t.Fatal("a malformed activation report accepted")
	}
}

// The authority's tombstone of the deletion is found by its operation, and it counts as this smoke's
// deletion only when it retires exactly the retired project of the organization: a tombstone that
// also names the sibling, another organization, another mode or no project is not.
func TestDeletionClusterTombstoneMatching(t *testing.T) {
	org, project, sibling, op := model.NewID(), model.NewID(), model.NewID(), model.NewID()
	mine := model.DeletePredicate{Operation: op, Org: org, Mode: model.DeleteRetireProject, Projects: []model.ID{project}}
	other := model.DeletePredicate{Operation: model.NewID(), Org: org, Mode: model.DeleteRetireProject, Projects: []model.ID{sibling}}
	if got, ok := dcTombstoneOf([]model.DeletePredicate{other, mine}, op); !ok || got.Operation != op {
		t.Fatalf("%v %v", got, ok)
	}
	if _, ok := dcTombstoneOf([]model.DeletePredicate{other}, op); ok {
		t.Fatal("a ledger without the operation has no tombstone for it")
	}
	if _, ok := dcTombstoneOf(nil, op); ok {
		t.Fatal("an empty ledger has no tombstone")
	}
	if !dcRetiresOnly(mine, org, project) {
		t.Fatal("the deletion's own tombstone")
	}
	for name, bad := range map[string]model.DeletePredicate{
		"also the sibling":   {Operation: op, Org: org, Mode: model.DeleteRetireProject, Projects: []model.ID{project, sibling}},
		"the whole org":      {Operation: op, Org: org, Mode: model.DeleteRetireOrg},
		"another project":    {Operation: op, Org: org, Mode: model.DeleteRetireProject, Projects: []model.ID{sibling}},
		"another org":        {Operation: op, Org: model.NewID(), Mode: model.DeleteRetireProject, Projects: []model.ID{project}},
		"a historical range": {Operation: op, Org: org, Mode: model.DeleteHistoricalRange, Projects: []model.ID{project}},
	} {
		if dcRetiresOnly(bad, org, project) {
			t.Errorf("%s accepted", name)
		}
	}
}

// The replacement voter set, the order of "erased before the first clean receipt", and the membership
// status listing the replacement must produce (every group, exactly the wanted voters, no learner).
func TestDeletionClusterReplacementMembership(t *testing.T) {
	if got := dcReplacementMembers([]uint64{1, 2, 3}, 3, 4); !reflect.DeepEqual(got, []uint64{1, 2, 4}) {
		t.Fatalf("%v", got)
	}
	if got := dcReplacementMembers([]uint64{1, 2, 3}, 1, 4); !reflect.DeepEqual(got, []uint64{2, 3, 4}) {
		t.Fatalf("%v", got)
	}
	if got := dcReplacementMembers([]uint64{1, 2, 4}, 3, 4); !reflect.DeepEqual(got, []uint64{1, 2, 4}) {
		t.Fatalf("a voter already present is not added twice: %v", got)
	}
	for _, c := range []struct {
		lastHit, firstClean int64
		want                bool
	}{{0, 5000, true}, {0, 0, true}, {4000, 5000, true}, {5000, 5000, true}, {5001, 5000, false}, {9000, 5000, false}} {
		if got := dcErasedBefore(c.lastHit, c.firstClean); got != c.want {
			t.Errorf("last hit %d, first clean %d: %v", c.lastHit, c.firstClean, got)
		}
	}
	line := func(members string) string {
		return "group 00000000-0000-0000-0000-000000000001 leader=1 term=2 applied=77 failed=false revision=3 members=" + members + "\n"
	}
	want := map[uint64]string{1: "node-a", 2: "node-b", 4: "node-d"}
	good := line("1:voter:node-a,2:voter:node-b,4:voter:node-d") + line("4:voter:node-d,1:voter:node-a,2:voter:node-b") + "groups=2 applied=0\n"
	if !dcStatusShowsVoters(good, want, 2) {
		t.Fatal("a status listing exactly the wanted voters in every group")
	}
	if dcStatusShowsVoters(good, want, 3) {
		t.Fatal("fewer groups than required")
	}
	for name, bad := range map[string]string{
		"still lists the removed voter": line("1:voter:node-a,2:voter:node-b,3:voter:node-c,4:voter:node-d"),
		"a learner":                     line("1:voter:node-a,2:voter:node-b,4:learner:node-d"),
		"the old voter, not the new":    line("1:voter:node-a,2:voter:node-b,3:voter:node-c"),
		"a wrong identity":              line("1:voter:node-a,2:voter:node-b,4:voter:node-c"),
		"a malformed member":            line("1:voter:node-a,2:voter,4:voter:node-d"),
		"one group off among good":      good + line("1:voter:node-a,2:voter:node-b,3:voter:node-c"),
		"no group lines":                "groups=0\n",
	} {
		if dcStatusShowsVoters(bad, want, 1) {
			t.Errorf("%s accepted", name)
		}
	}
}

// The authority, its keys and the backup destination are outside every node's data tree, and the
// check refuses an authority inside a node directory, a node directory inside the authority and an empty input.
func TestDeletionClusterPathsOutsideEveryNodeDirectory(t *testing.T) {
	dirs := []string{"/w/node-a", "/w/node-b", "/w/node-c"}
	if !dcOutsideAll([]string{"/w/authority", "/w/authority.keys", "/w/backups"}, dirs) {
		t.Fatal("siblings of the node directories are outside")
	}
	for name, paths := range map[string][]string{"inside a node directory": {"/w/authority", "/w/node-b/authority"}, "the node directory itself": {"/w/node-a"}, "a parent of the node directories": {"/w"}} {
		if dcOutsideAll(paths, dirs) {
			t.Errorf("%s accepted", name)
		}
	}
	if dcOutsideAll(nil, dirs) || dcOutsideAll([]string{"/w/authority"}, nil) {
		t.Fatal("nothing to compare proves nothing")
	}
	if !dcWithin("/w", "/w/a") || !dcWithin("/w", "/w") || dcWithin("/w/a", "/w/ab") || dcWithin("/w/a", "/w") {
		t.Fatal("dcWithin")
	}
}

// A fresh voter's directory is not there yet: it holds nothing. A directory that is there is scanned.
func TestDeletionClusterScanOfAFreshDirectory(t *testing.T) {
	dir := t.TempDir()
	missing, err := dcScanIfPresent(filepath.Join(dir, "node-d"), dcTestCanary)
	if err != nil || missing.Hits != 0 || missing.Files != 0 || missing.ByStore == nil {
		t.Fatalf("%+v %v", missing, err)
	}
	writeDCFile(t, dir, "node-d/apply.db", []byte("x"+dcTestCanary+"y"))
	found, err := dcScanIfPresent(filepath.Join(dir, "node-d"), dcTestCanary)
	if err != nil || found.Hits != 1 || found.ByStore["apply_db"] != 1 {
		t.Fatalf("%+v %v", found, err)
	}
}

// A run states what it does not cover: with an authority it no longer claims "backup mode none", and a
// replacement run does not claim the restart ending (nor the reverse).
func TestDeletionClusterNotRunNamesWhatTheRunDoesNotCover(t *testing.T) {
	join := func(authority, replace bool) string { return strings.Join(dcNotRun(authority, replace), "\n") }
	if strings.Contains(join(true, false), "backup mode none") || !strings.Contains(join(false, false), "no backup authority is configured") {
		t.Fatal("authority statement")
	}
	if !strings.Contains(join(true, true), "restarting the lagging voter") || !strings.Contains(join(true, false), "replacing the lagging voter") {
		t.Fatal("ending statement")
	}
	for _, authority := range []bool{false, true} {
		for _, replace := range []bool{false, true} {
			if !strings.Contains(join(authority, replace), "physical hosts") || !strings.Contains(join(authority, replace), "container host") {
				t.Fatal("the physical-domain and container caveats stay")
			}
		}
	}
}
