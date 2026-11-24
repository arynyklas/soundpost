// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDeletionClusterHostsFlagParsing(t *testing.T) {
	good := "1=root@vm-a=192.0.2.1,2=root@vm-b=192.0.2.2,3=root@vm-c=192.0.2.3"
	hosts, err := dcParseHosts(good)
	if err != nil || len(hosts) != 3 || hosts[2].SSH != "root@vm-b" || hosts[3].Addr != "192.0.2.3" {
		t.Fatalf("valid hosts refused or misread: %v %+v", err, hosts)
	}
	for name, bad := range map[string]string{
		"two voters on one machine (same ssh destination)": "1=root@vm-a=192.0.2.1,2=root@vm-a=192.0.2.2,3=root@vm-c=192.0.2.3",
		"two voters on one address":                        "1=root@vm-a=192.0.2.1,2=root@vm-b=192.0.2.1,3=root@vm-c=192.0.2.3",
		"loopback address":                                 "1=root@vm-a=127.0.0.1,2=root@vm-b=192.0.2.2,3=root@vm-c=192.0.2.3",
		"a voter missing":                                  "1=root@vm-a=192.0.2.1,2=root@vm-b=192.0.2.2",
		"a fourth voter":                                   "1=root@vm-a=192.0.2.1,2=root@vm-b=192.0.2.2,3=root@vm-c=192.0.2.3,4=root@vm-d=192.0.2.4",
		"a voter named twice":                              "1=root@vm-a=192.0.2.1,1=root@vm-b=192.0.2.2,3=root@vm-c=192.0.2.3",
		"ssh destination read as an option":                "1=-oProxyCommand=x=192.0.2.1,2=root@vm-b=192.0.2.2,3=root@vm-c=192.0.2.3",
		"ssh destination with a shell word":                "1=root@vm-a;reboot=192.0.2.1,2=root@vm-b=192.0.2.2,3=root@vm-c=192.0.2.3",
		"not an address":                                   "1=root@vm-a=vm-a,2=root@vm-b=192.0.2.2,3=root@vm-c=192.0.2.3",
	} {
		if _, err := dcParseHosts(bad); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestDeletionClusterHostsRolesNeverTheCutVoter(t *testing.T) {
	if err := dcCheckRoles(1, 2, 3); err != nil {
		t.Fatal(err)
	}
	for _, c := range [][3]uint64{{1, 1, 3}, {1, 2, 1}, {0, 2, 3}, {1, 4, 3}} {
		if err := dcCheckRoles(c[0], c[1], c[2]); err == nil {
			t.Errorf("roles %v accepted", c)
		}
	}
}

func TestDeletionClusterHostsFailureDomainJudgement(t *testing.T) {
	three := func() map[uint64]dcHostFacts {
		return map[uint64]dcHostFacts{
			1: {Hostname: "a", MachineID: "m1", BootID: "b1"},
			2: {Hostname: "b", MachineID: "m2", BootID: "b2"},
			3: {Hostname: "c", MachineID: "m3", BootID: "b3"},
		}
	}
	if ok, why := dcDistinctDomains(three()); !ok {
		t.Fatalf("three distinct machines refused: %s", why)
	}
	for name, mutate := range map[string]func(map[uint64]dcHostFacts){
		"one machine under two hostnames": func(f map[uint64]dcHostFacts) { f[2] = dcHostFacts{Hostname: "b", MachineID: "m1", BootID: "b1"} },
		"the same hostname":               func(f map[uint64]dcHostFacts) { x := f[2]; x.Hostname = "a"; f[2] = x },
		"the same boot id":                func(f map[uint64]dcHostFacts) { x := f[3]; x.BootID = "b1"; f[3] = x },
		"an empty machine id":             func(f map[uint64]dcHostFacts) { x := f[3]; x.MachineID = ""; f[3] = x },
		"a missing machine":               func(f map[uint64]dcHostFacts) { delete(f, 3) },
	} {
		f := three()
		mutate(f)
		if ok, _ := dcDistinctDomains(f); ok {
			t.Errorf("%s: judged three distinct machines", name)
		}
	}
}

func TestDeletionClusterHostsAckJournalRefusesATamperedRecord(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "ack.jsonl")
	j, err := dcCreateAckJournal(file)
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range []struct {
		kind string
		seq  uint64
		node uint64
	}{{"issue", 1001, 0}, {"issue", 1002, 0}, {"ack", 1001, 2}, {"issue", 1003, 0}, {"ack", 1002, 3}, {"reject", 1003, 1}} {
		if err = j.add(step.kind, step.seq, int64(step.seq)*10, step.node); err != nil {
			t.Fatal(err)
		}
	}
	_ = j.close()
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	st, err := dcReadAckJournal(raw)
	if err != nil || len(st.Issued) != 3 || len(st.Acked) != 2 || !st.Rejected[1003] || st.Acked[1001] != 2 || st.Lines != 6 {
		t.Fatalf("intact journal misread: %v %+v", err, st)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	join := func(l []string) []byte { return []byte(strings.Join(l, "\n") + "\n") }
	// a second, individually valid journal of the same shape: its later lines are well-formed and numbered right, but chain to ITS history
	other, err := dcCreateAckJournal(filepath.Join(dir, "other.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range []struct {
		kind string
		seq  uint64
		node uint64
	}{{"issue", 1001, 0}, {"issue", 1002, 0}, {"ack", 1001, 2}, {"issue", 1003, 0}, {"ack", 1002, 3}, {"reject", 1003, 1}} {
		if err = other.add(step.kind, step.seq, int64(step.seq)*10+1, step.node); err != nil {
			t.Fatal(err)
		}
	}
	_ = other.close()
	otherRaw, err := os.ReadFile(filepath.Join(dir, "other.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	otherLines := strings.Split(strings.TrimRight(string(otherRaw), "\n"), "\n")
	for name, tampered := range map[string][]byte{
		"lines of another journal spliced in": join(append(append([]string{}, lines[:3]...), otherLines[3:]...)),
		"a dropped middle line":               join(append(append([]string{}, lines[:2]...), lines[3:]...)),
		"swapped lines":                       join(append([]string{lines[1], lines[0]}, lines[2:]...)),
		"a changed value":                     []byte(strings.Replace(string(raw), `"seq":1001,"at":10010`, `"seq":1001,"at":10011`, 1)),
		"a cut (torn) last line":              raw[:len(raw)-9],
		"a duplicated line":                   join(append(append([]string{}, lines...), lines[5])),
		"an empty journal":                    nil,
		"an ack with no issue line":           nil,
	} {
		if name == "an ack with no issue line" {
			f2 := filepath.Join(dir, "orphan.jsonl")
			j2, err := dcCreateAckJournal(f2)
			if err != nil {
				t.Fatal(err)
			}
			_ = j2.add("ack", 5, 5, 1)
			_ = j2.close()
			tampered, _ = os.ReadFile(f2)
		}
		if _, err := dcReadAckJournal(tampered); err == nil {
			t.Errorf("%s: journal accepted", name)
		}
	}
	if _, err := dcCreateAckJournal(file); err == nil {
		t.Error("a journal over an existing file was created (the record of an earlier run would be overwritten)")
	}
}

func TestDeletionClusterHostsRetainedSamplesAreJudgedAgainstTheJournal(t *testing.T) {
	st := dcAckState{Issued: map[uint64]int64{1: 10, 2: 20, 3: 30, 4: 40}, Acked: map[uint64]uint64{1: 1, 2: 2, 3: 3}, Rejected: map[uint64]bool{}}
	whole := []dcRetained{{1, 10}, {2, 20}, {3, 30}}
	if v := dcJudgeRetained(st, whole); len(v) != 0 {
		t.Fatalf("a voter holding every acknowledged sample was judged: %v", v)
	}
	if v := dcJudgeRetained(st, append(whole[:3:3], dcRetained{4, 40})); len(v) != 0 {
		t.Fatalf("an issued-but-unacknowledged sample that was retained must not be judged: %v", v)
	}
	for name, got := range map[string][]dcRetained{
		"an acknowledged sample missing": {{1, 10}, {3, 30}},
		"a foreign sample":               append(whole[:3:3], dcRetained{99, 5}),
		"a changed observed time":        {{1, 10}, {2, 21}, {3, 30}},
		"a duplicate sample":             append(whole[:3:3], dcRetained{2, 20}),
		"nothing retained":               nil,
	} {
		if v := dcJudgeRetained(st, got); len(v) == 0 {
			t.Errorf("%s: judged intact", name)
		}
	}
	if dcDigest(whole) != dcDigest([]dcRetained{{3, 30}, {1, 10}, {2, 20}}) || dcDigest(whole) == dcDigest([]dcRetained{{1, 10}, {2, 20}}) {
		t.Error("the digest depends on the order of samples or does not see a missing one")
	}
}

func TestDeletionClusterHostsOutagesAndTheCutInsideTheDeletion(t *testing.T) {
	var times []int64
	var ready []bool
	for ms := int64(0); ms < 60000; ms += 500 {
		times = append(times, ms)
		ready = append(ready, !(ms >= 20000 && ms < 50000) && !(ms == 5000)) // one blip at 5 s, an outage 20-50 s
	}
	outs := dcOutages(times, ready, 3)
	if len(outs) != 1 || outs[0].StartMS != 20000 || outs[0].EndMS != 50000 {
		t.Fatalf("outages: %+v (a single failed probe is noise, not an outage)", outs)
	}
	if o, ok := dcLongest(outs); !ok || o.lasted() != 30*time.Second {
		t.Fatalf("longest: %+v %v", o, ok)
	}
	unfinished := dcOutages([]int64{0, 500, 1000, 1500}, []bool{true, false, false, false}, 3)
	if _, ok := dcLongest(unfinished); ok || len(unfinished) != 1 || unfinished[0].EndMS != 0 {
		t.Fatalf("an outage that has not ended must not count as a finished one: %+v", unfinished)
	}

	pending := []dcPoint{{AtMS: 1000, Phase: "fencing", Physical: "pending"}, {AtMS: 9000, Phase: "complete", Physical: "done", Residual: []string{"data_apply_db"}}}
	cut := dcOutage{StartMS: 12000, EndMS: 150000}
	if ok, why := dcCutMidDeletion(500, pending, cut); !ok {
		t.Fatalf("a cut while the receipt still named a residual store was judged outside the deletion: %s", why)
	}
	clean := append(append([]dcPoint{}, pending...), dcPoint{AtMS: 11000, Phase: "complete", Physical: "done"})
	if ok, _ := dcCutMidDeletion(500, clean, cut); ok {
		t.Error("a cut after the receipt read clean was judged to be during the deletion")
	}
	if ok, _ := dcCutMidDeletion(20000, pending, cut); ok {
		t.Error("an outage that began before the deletion did was judged to be during it")
	}
	if ok, _ := dcCutMidDeletion(500, nil, cut); ok {
		t.Error("a cut with no observed deletion state was judged to be during the deletion")
	}
	if ok, _ := dcCutMidDeletion(0, pending, cut); ok {
		t.Error("a deletion that never began was judged to be under way")
	}
}

type dcFakeShell struct {
	commands []string
	stdin    [][]byte
	answer   map[string]string
}

func (f *dcFakeShell) exec(spec dcHostSpec, command string, stdin io.Reader, _ time.Duration) ([]byte, error) {
	f.commands = append(f.commands, spec.SSH+": "+command)
	var in []byte
	if stdin != nil {
		in, _ = io.ReadAll(stdin)
	}
	f.stdin = append(f.stdin, in)
	for key, out := range f.answer {
		if strings.Contains(command, key) {
			return []byte(out), nil
		}
	}
	return nil, nil
}

func TestDeletionClusterHostsRemoteCommandsKeepSecretsOutOfCommandLines(t *testing.T) {
	hosts, _ := dcParseHosts("1=root@vm-a=192.0.2.1,2=root@vm-b=192.0.2.2,3=root@vm-c=192.0.2.3")
	sh := &dcFakeShell{}
	rem := &dcRemote{hosts: hosts, exec: sh.exec}
	secret := []byte("-----BEGIN PRIVATE KEY-----SECRET-MATERIAL")
	sh.answer = map[string]string{"sha256sum": "wrong-digest  /x\n"}
	if err := rem.push(1, dcRemoteKeys, "0600", secret); err == nil {
		t.Fatal("a file whose digest read back from the host differs was accepted")
	}
	for _, c := range sh.commands {
		if strings.Contains(c, "SECRET-MATERIAL") {
			t.Fatalf("file content in a command line: %s", c)
		}
	}
	if !bytes.Contains(sh.stdin[0], []byte("SECRET-MATERIAL")) {
		t.Fatal("the content did not travel on stdin")
	}
	if !strings.Contains(sh.commands[0], "sync") || !strings.Contains(sh.commands[0], ".new") || !strings.Contains(sh.commands[0], "mv -f") {
		t.Fatalf("push is not write-sync-rename: %s", sh.commands[0])
	}

	sh2 := &dcFakeShell{answer: map[string]string{"deletion-cluster-scan": `{"files":3,"bytes":9,"hits":0,"hits_by_store":{}}`}}
	rem2 := &dcRemote{hosts: hosts, exec: sh2.exec}
	s, err := rem2.scan(2, dcRemoteVar+"/node-2", "canary_name_zzz")
	if err != nil || s.Files != 3 {
		t.Fatalf("scan: %v %+v", err, s)
	}
	if strings.Contains(sh2.commands[0], "canary_name_zzz") || !bytes.Contains(sh2.stdin[0], []byte("canary_name_zzz")) {
		t.Fatalf("the scanned name must reach the host on stdin, not in a process list: %v", sh2.commands)
	}
	bad := &dcFakeShell{answer: map[string]string{"deletion-cluster-scan": "not json"}}
	if _, err := (&dcRemote{hosts: hosts, exec: bad.exec}).scan(1, "/d", "x"); err == nil {
		t.Fatal("an unreadable scan answer was accepted")
	}
}

func TestDeletionClusterHostsUnitIsEnabledAndCarriesNoCredential(t *testing.T) {
	hosts, _ := dcParseHosts("1=root@vm-a=192.0.2.1,2=root@vm-b=192.0.2.2,3=root@vm-c=192.0.2.3")
	t.Setenv("SOUNDPOST_AUTHORITY_S3_ACCESS_KEY", "AKIDEXAMPLEKEY")
	t.Setenv("SOUNDPOST_AUTHORITY_S3_SECRET_KEY", "SECRETEXAMPLEVALUE")
	a := &dcAuthority{Keys: "/somewhere/else", S3: &dcS3{Endpoint: "https://s3.example.invalid:9000", Region: "us-east-1", Bucket: "journal", Prefix: "p"}}
	unit := dcUnit(hosts[2], a)
	for _, want := range []string{"--node-id 2", "--listen 192.0.2.2:" + dcPublicPort, "--authority-keys " + dcRemoteKeys, "--authority-s3-endpoint https://s3.example.invalid:9000", "--authority-s3-bucket journal", "EnvironmentFile=" + dcRemoteEnv, "Restart=on-failure", "WantedBy=multi-user.target"} {
		if !strings.Contains(unit, want) {
			t.Errorf("unit lacks %q:\n%s", want, unit)
		}
	}
	if strings.Contains(unit, "AKIDEXAMPLEKEY") || strings.Contains(unit, "SECRETEXAMPLEVALUE") || strings.Contains(unit, "/somewhere/else") {
		t.Errorf("unit carries a credential or the local key path:\n%s", unit)
	}
	env := string(dcAuthorityEnv(a))
	if !strings.Contains(env, "SOUNDPOST_AUTHORITY_S3_SECRET_KEY=SECRETEXAMPLEVALUE") || !strings.Contains(env, "SSL_CERT_FILE="+dcRemoteS3CA) {
		t.Errorf("authority.env: %q", env)
	}
	dir := &dcAuthority{Dir: "/mnt/journal"}
	if u := dcUnit(hosts[1], dir); !strings.Contains(u, "--authority-dir /mnt/journal") || strings.Contains(u, "EnvironmentFile") || dcAuthorityEnv(dir) != nil {
		t.Errorf("a directory journal needs no credentials file:\n%s", u)
	}
	if u := dcUnit(hosts[3], nil); strings.Contains(u, "authority") {
		t.Errorf("a voter without an authority was given one:\n%s", u)
	}
}

func TestDeletionClusterHostsUntarStaysInsideItsDirectory(t *testing.T) {
	build := func(name string) []byte {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: 2, Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte("ok"))
		_ = tw.Close()
		return buf.Bytes()
	}
	dir := t.TempDir()
	if err := dcUntar(build("./sub/file"), dir); err != nil {
		t.Fatal(err)
	}
	if raw, err := os.ReadFile(filepath.Join(dir, "sub", "file")); err != nil || string(raw) != "ok" {
		t.Fatalf("extracted file: %v %q", err, raw)
	}
	for _, evil := range []string{"../escape", "/abs/path", "a/../../escape"} {
		if err := dcUntar(build(evil), t.TempDir()); err == nil {
			t.Errorf("entry %q accepted", evil)
		}
	}
}

func TestDeletionClusterHostsScheduleNamesTheMachineAndTheInstant(t *testing.T) {
	hosts, _ := dcParseHosts("1=root@vm-a=192.0.2.1,2=root@vm-b=192.0.2.2,3=root@vm-c=192.0.2.3")
	begin := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	s := dcSchedule(&dcHostsOptions{hosts: hosts, cut: 1, beginAt: begin, cutLead: 25 * time.Second, minOutage: 90 * time.Second})
	if s.Node != 1 || s.Host != "root@vm-a" || s.BeginAt != "2026-11-24T12:00:00Z" || s.CutAt != "2026-11-24T12:00:25Z" || s.DownFor != "1m30s" {
		t.Fatalf("schedule: %+v", s)
	}
}

// A restarted voter may name a store in the receipt of a completed deletion until its first worker pass has attested again: the
// post-restart check waits for it, bounded, and still fails when the receipt never becomes clean or is not complete and done.
func TestDeletionClusterHostsReceiptAfterRestartWaitsBoundedAndStillFails(t *testing.T) {
	t.Run("clean once the first worker pass ran", func(t *testing.T) {
		r := newDCRecorder()
		r.enter("dc_restart_all_and_verify")
		calls := 0
		err := r.receiptStaysCleanAfterRestart("1", 5*time.Second, time.Millisecond, func() (string, string, []string, error) {
			calls++
			if calls < 4 {
				return "complete", "done", []string{"control_state", "data_apply_db"}, nil
			}
			return "complete", "done", nil, nil
		})
		if err != nil || calls != 4 {
			t.Fatalf("err %v after %d polls, want the wait to end clean at the fourth", err, calls)
		}
		last := r.art.Assertions[len(r.art.Assertions)-1]
		if last.Name != "receipt_stays_clean_after_restart_node_1" || !last.OK || !strings.Contains(last.Detail, "after 3 answer(s) that named a store") {
			t.Fatalf("assertion: %+v", last)
		}
	})
	t.Run("never clean fails at the bound with the last answer", func(t *testing.T) {
		r := newDCRecorder()
		r.enter("dc_restart_all_and_verify")
		calls := 0
		began := time.Now()
		err := r.receiptStaysCleanAfterRestart("2", 120*time.Millisecond, 10*time.Millisecond, func() (string, string, []string, error) {
			calls++
			return "complete", "done", []string{"control_state"}, nil
		})
		var typed *smokeFailure
		if !errors.As(err, &typed) || typed.Stage != "dc_restart_all_and_verify" || typed.Code != "timeout_receipt_clean_after_restart_node_2" {
			t.Fatalf("not the typed timeout: %v", err)
		}
		if took := time.Since(began); took < 100*time.Millisecond || took > 5*time.Second || calls < 2 {
			t.Fatalf("bound not honoured: %v after %d polls", took, calls)
		}
		if !strings.Contains(r.detail, "residual [control_state]") {
			t.Fatalf("the residual store of the last answer is lost: %q", r.detail)
		}
	})
	t.Run("a receipt that is not complete and done is judged at once", func(t *testing.T) {
		r := newDCRecorder()
		r.enter("dc_restart_all_and_verify")
		calls := 0
		err := r.receiptStaysCleanAfterRestart("3", time.Hour, time.Hour, func() (string, string, []string, error) {
			calls++
			return "fencing", "pending", nil, nil
		})
		var typed *smokeFailure
		if !errors.As(err, &typed) || typed.Code != "receipt_stays_clean_after_restart_node_3" || calls != 1 {
			t.Fatalf("err %v after %d polls, want the assertion failure at the first", err, calls)
		}
	})
	t.Run("a poll error is the typed failure of the stage", func(t *testing.T) {
		r := newDCRecorder()
		r.enter("dc_restart_all_and_verify")
		err := r.receiptStaysCleanAfterRestart("1", time.Hour, time.Hour, func() (string, string, []string, error) {
			return "", "", nil, &smokeFailure{Stage: "poll_operation", Code: "unavailable", Actual: 500}
		})
		var typed *smokeFailure
		if !errors.As(err, &typed) || typed.Stage != "dc_restart_all_and_verify" || typed.Code != "poll_operation_unavailable" {
			t.Fatalf("poll error not folded into the stage: %v", err)
		}
	})
}
