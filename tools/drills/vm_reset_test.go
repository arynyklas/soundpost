// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// 07.07#7: a real guest hard reset (sysrq `b`: no sync, no unmount, page cache dropped) of the machine that holds all three members.
// The scenario is two phases because the harness dies with the machine; everything that can be decided without resetting a machine is
// decided here: which preconditions refuse a start (the reset is destructive), what the second phase refuses to resume from, and
// that what the first phase wrote down is what the second phase verifies the cluster against.

func vmAllow(t *testing.T) (Allowlist, string) {
	t.Helper()
	m, err := LoadManifest(filepath.Join("..", "..", "drills", "scenarios.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	return Allowlist{DataRoots: []string{root}, Hosts: m.Allowlist.Hosts, Forbidden: m.Allowlist.Forbidden}, root
}

func vmHostNow(boot string) vmHost {
	return vmHost{Euid: 0, Hostname: "vmbox", BootID: boot, Sysrq: func() error { return nil }}
}

func TestVMHardResetRefusesEveryUnsafeStart(t *testing.T) {
	al, root := vmAllow(t)
	state := filepath.Join(root, "state")
	if err := vmCheckStart(vmHostNow("boot-1"), "vmbox", state, al); err != nil {
		t.Fatalf("a safe start was refused: %v", err)
	}
	notRoot := vmHostNow("boot-1")
	notRoot.Euid = 1000
	noSysrq := vmHostNow("boot-1")
	noSysrq.Sysrq = func() error { return errors.New("read-only file system") }
	dirty := filepath.Join(root, "dirty")
	if err := os.MkdirAll(dirty, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dirty, "old"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name  string
		host  vmHost
		allow string
		state string
	}{
		{"not root", notRoot, "vmbox", state},
		{"the flag names another machine", vmHostNow("boot-1"), "other-box", state},
		{"no machine named at all", vmHostNow("boot-1"), "", state},
		{"the flag is a prefix of the hostname", vmHostNow("boot-1"), "vm", state},
		{"state directory outside the allowlisted root", vmHostNow("boot-1"), "vmbox", "/srv/state"},
		{"state directory is a production directory", vmHostNow("boot-1"), "vmbox", "/var/lib/soundpost/state"},
		{"state directory is the data root itself", vmHostNow("boot-1"), "vmbox", root},
		{"state directory is relative", vmHostNow("boot-1"), "vmbox", "state"},
		{"state directory has a parent reference", vmHostNow("boot-1"), "vmbox", root + "/../state"},
		{"sysrq cannot be written", noSysrq, "vmbox", state},
		{"state directory already holds something", vmHostNow("boot-1"), "vmbox", dirty},
	} {
		if err := vmCheckStart(c.host, c.allow, c.state, al); !errors.Is(err, ErrRefused) {
			t.Errorf("%s: err %v, want a refusal", c.name, err)
		}
	}
}

func TestVMJournalRoundTripAndEveryWayItBreaks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "j.jsonl")
	j, err := createVMJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 3; i++ {
		if err = j.Append(map[string]any{"n": i}); err != nil {
			t.Fatal(err)
		}
	}
	n, head := j.State()
	if n != 3 || head == "" {
		t.Fatalf("state %d %q", n, head)
	}
	if err = j.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = createVMJournal(path); err == nil {
		t.Error("a journal was created over an existing one")
	}
	entries, heads, err := readVMJournal(path)
	if err != nil || len(entries) != 3 || len(heads) != 3 || heads[2] != head {
		t.Fatalf("round trip: %d entries %d heads err %v", len(entries), len(heads), err)
	}
	if string(entries[1]) != `{"n":2}` {
		t.Errorf("entry 2 is %s", entries[1])
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.SplitAfter(string(raw), "\n")
	for _, c := range []struct {
		name string
		data string
	}{
		{"cut in the middle of the last line", string(raw[:len(raw)-9])},
		{"cut after a whole line but the newline", strings.TrimSuffix(string(raw), "\n")},
		{"a payload changed", strings.Replace(string(raw), `{"n":2}`, `{"n":9}`, 1)},
		{"two lines swapped", lines[1] + lines[0] + lines[2]},
		{"a line in the middle dropped", lines[0] + lines[2]},
		{"not JSON", "garbage\n"},
	} {
		bad := filepath.Join(t.TempDir(), "bad.jsonl")
		if err := os.WriteFile(bad, []byte(c.data), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := readVMJournal(bad); err == nil {
			t.Errorf("%s: the journal was accepted", c.name)
		}
	}
	if _, _, err := readVMJournal(filepath.Join(t.TempDir(), "none")); err == nil {
		t.Error("a missing journal was accepted")
	}
}

// vmStateDir writes what the first phase leaves behind: the ledger of acknowledged batches, the journal of issued batches and the
// marker (taken after `acks` acknowledgements; `after` more were acknowledged after the marker).
func vmStateDir(t *testing.T, root string, acks, after int) string {
	t.Helper()
	dir := filepath.Join(root, "state")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	ledger, err := createVMJournal(filepath.Join(dir, vmLedgerFile))
	if err != nil {
		t.Fatal(err)
	}
	issued, err := createVMJournal(filepath.Join(dir, vmIssuedFile))
	if err != nil {
		t.Fatal(err)
	}
	var marker vmMarker
	for i := 1; i <= acks+after; i++ {
		id := fmt.Sprintf("batch-%02d", i)
		if err = issued.Append(vmIssued{ID: id, Body: json.RawMessage(fmt.Sprintf(`{"id":%q}`, id))}); err != nil {
			t.Fatal(err)
		}
		if err = ledger.Append(Ack{ID: id, Group: "g", Index: uint64(i), Digest: dcDigest(id, uint64(i))}); err != nil {
			t.Fatal(err)
		}
		if i == acks {
			marker.Acks, marker.LedgerHead = ledger.State()
			marker.Issued, marker.IssuedHead = issued.State()
		}
	}
	// One batch was issued and never acknowledged (in flight at the reset).
	if err = issued.Append(vmIssued{ID: "inflight", Body: json.RawMessage(`{"id":"inflight"}`)}); err != nil {
		t.Fatal(err)
	}
	_ = ledger.Close()
	_ = issued.Close()
	marker.Version, marker.Hostname, marker.BootID = 1, "vmbox", "boot-1"
	if err = writeVMMarker(filepath.Join(dir, vmMarkerFile), marker); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestVMHardResetResumeRefusesWhatIsNotAResetOrNotWhatPhaseOneLeft(t *testing.T) {
	al, root := vmAllow(t)
	dir := vmStateDir(t, root, 12, 3)
	res, err := vmCheckResume(vmHostNow("boot-2"), "vmbox", dir, al)
	if err != nil {
		t.Fatalf("a real resume was refused: %v", err)
	}
	if res.Marker.Acks != 12 || len(res.Acks) != 15 || len(res.Issued) != 16 {
		t.Fatalf("marker acks %d, ledger %d (12 before the marker, 3 after), issued %d (15 + 1 in flight)", res.Marker.Acks, len(res.Acks), len(res.Issued))
	}
	notRoot := vmHostNow("boot-2")
	notRoot.Euid = 1000
	file := func(name string) string { return filepath.Join(dir, name) }
	mutate := func(name string, f func(raw []byte) []byte) func() {
		raw, err := os.ReadFile(file(name))
		if err != nil {
			t.Fatal(err)
		}
		return func() {
			if err := os.WriteFile(file(name), f(raw), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	restore := func(name string) func() {
		raw, err := os.ReadFile(file(name))
		if err != nil {
			t.Fatal(err)
		}
		return func() { _ = os.WriteFile(file(name), raw, 0o600) }
	}
	ledgerLines := func(raw []byte) []string { return strings.SplitAfter(string(raw), "\n") }
	for _, c := range []struct {
		name   string
		host   vmHost
		allow  string
		state  string
		break_ func()
		file   string
	}{
		{name: "the boot id did not change: no reset happened", host: vmHostNow("boot-1"), allow: "vmbox", state: dir},
		{name: "not root", host: notRoot, allow: "vmbox", state: dir},
		{name: "the flag names another machine", host: vmHostNow("boot-2"), allow: "other-box", state: dir},
		{name: "the marker was written on another machine", host: vmHost{Euid: 0, Hostname: "elsewhere", BootID: "boot-2", Sysrq: func() error { return nil }}, allow: "elsewhere", state: dir},
		{name: "state directory outside the allowlist", host: vmHostNow("boot-2"), allow: "vmbox", state: "/srv/state"},
		{name: "the marker is missing", host: vmHostNow("boot-2"), allow: "vmbox", state: dir, file: vmMarkerFile, break_: mutate(vmMarkerFile, func([]byte) []byte { _ = os.Remove(file(vmMarkerFile)); return nil })},
		{name: "the marker is cut in half", host: vmHostNow("boot-2"), allow: "vmbox", state: dir, file: vmMarkerFile, break_: mutate(vmMarkerFile, func(b []byte) []byte { return b[:len(b)/2] })},
		{name: "the ledger is missing", host: vmHostNow("boot-2"), allow: "vmbox", state: dir, file: vmLedgerFile, break_: mutate(vmLedgerFile, func([]byte) []byte { _ = os.Remove(file(vmLedgerFile)); return nil })},
		{name: "the ledger is cut in the middle of a line", host: vmHostNow("boot-2"), allow: "vmbox", state: dir, file: vmLedgerFile, break_: mutate(vmLedgerFile, func(b []byte) []byte { return b[:len(b)-20] })},
		{name: "the ledger lost acknowledgements the marker counted", host: vmHostNow("boot-2"), allow: "vmbox", state: dir, file: vmLedgerFile, break_: mutate(vmLedgerFile, func(b []byte) []byte {
			l := ledgerLines(b)
			return []byte(strings.Join(l[:10], ""))
		})},
		{name: "an acknowledgement in the ledger was changed", host: vmHostNow("boot-2"), allow: "vmbox", state: dir, file: vmLedgerFile, break_: mutate(vmLedgerFile, func(b []byte) []byte { return []byte(strings.Replace(string(b), "batch-03", "batch-33", 1)) })},
		{name: "the journal of issued batches is missing", host: vmHostNow("boot-2"), allow: "vmbox", state: dir, file: vmIssuedFile, break_: mutate(vmIssuedFile, func([]byte) []byte { _ = os.Remove(file(vmIssuedFile)); return nil })},
		{name: "a batch body was changed", host: vmHostNow("boot-2"), allow: "vmbox", state: dir, file: vmIssuedFile, break_: mutate(vmIssuedFile, func(b []byte) []byte { return []byte(strings.Replace(string(b), "batch-05", "batch-55", 1)) })},
	} {
		if c.file != "" {
			undo := restore(c.file)
			c.break_()
			defer undo()
			if _, err := vmCheckResume(c.host, c.allow, c.state, al); err == nil {
				t.Errorf("%s: the resume was accepted", c.name)
			}
			undo()
			continue
		}
		if _, err := vmCheckResume(c.host, c.allow, c.state, al); err == nil {
			t.Errorf("%s: the resume was accepted", c.name)
		}
	}
	if _, err := vmCheckResume(vmHostNow("boot-2"), "vmbox", dir, al); err != nil {
		t.Errorf("after restoring every file the resume must work again: %v", err)
	}
}

// What phase one wrote down is the ledger phase two verifies the members against: an acknowledged batch a member does not retain
// must fail the verification, from the ledger as it was reloaded from the file.
func TestVMHardResetReloadedLedgerCatchesADroppedACK(t *testing.T) {
	al, root := vmAllow(t)
	dir := vmStateDir(t, root, 12, 3)
	res, err := vmCheckResume(vmHostNow("boot-2"), "vmbox", dir, al)
	if err != nil {
		t.Fatal(err)
	}
	led, err := vmLedgerOf(res.Acks)
	if err != nil || led.Len() != 15 {
		t.Fatalf("reloaded ledger: %d acks, err %v", led.Len(), err)
	}
	issued := map[string]bool{}
	for _, b := range res.Issued {
		issued[b.ID] = true
	}
	data := func(drop ...string) func(member uint64) (map[string]string, map[string]uint64, error) {
		return func(member uint64) (map[string]string, map[string]uint64, error) {
			digests, counts := map[string]string{}, map[string]uint64{}
			for _, a := range led.Acks() {
				digests[a.ID], counts[a.ID] = a.Digest, 1
			}
			if member == 2 {
				for _, id := range drop {
					delete(digests, id)
					delete(counts, id)
				}
			}
			return digests, counts, nil
		}
	}
	rep := &Report{Checks: []Check{}}
	rep.ledger = led
	if _, err = dcVerifyWith(data(), issued, rep, "after_reset", 1, 2, 3); err != nil {
		t.Fatalf("every member retains every acknowledged batch: %v", err)
	}
	rep = &Report{Checks: []Check{}}
	rep.ledger = led
	if _, err = dcVerifyWith(data("batch-07"), issued, rep, "after_reset", 1, 2, 3); err == nil {
		t.Fatal("a batch acknowledged before the reset and gone from member 2 passed the verification")
	}
	found := false
	for _, c := range rep.Checks {
		if c.Name == "after_reset_member_2_exact_reconciliation" && !c.OK && strings.Contains(c.Detail, "batch-07") {
			found = true
		}
	}
	if !found {
		t.Errorf("the failing check must name member 2 and the missing batch: %+v", rep.Checks)
	}
}

func TestVMStateRoundTripsTheFixtureTheMembersWereBootstrappedWith(t *testing.T) {
	fx := &dcFixture{org: model.NewID(), project: model.NewID(), source: model.NewID(), credential: "a credential", readerEmail: "reader@drills.invalid",
		service: model.NewID(), environment: model.NewID(), build: model.NewID(), pool: []model.ID{model.NewID(), model.NewID(), model.NewID()}}
	public := map[uint64]string{1: "127.0.0.1:1001", 2: "127.0.0.1:1002", 3: "127.0.0.1:1003"}
	peer := map[uint64]string{1: "127.0.0.1:2001", 2: "127.0.0.1:2002", 3: "127.0.0.1:2003"}
	raw, err := json.Marshal(vmStateOf(fx, public, peer))
	if err != nil {
		t.Fatal(err)
	}
	var back vmState
	if err = json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	got, err := back.fixture()
	if err != nil {
		t.Fatal(err)
	}
	if got.org != fx.org || got.project != fx.project || got.source != fx.source || got.credential != fx.credential || got.service != fx.service ||
		got.environment != fx.environment || got.build != fx.build || len(got.pool) != 3 || got.pool[2] != fx.pool[2] || got.readerEmail != fx.readerEmail {
		t.Errorf("fixture changed: %+v", got)
	}
	if back.Public[2] != public[2] || back.Peer[3] != peer[3] {
		t.Errorf("addresses changed: %+v", back)
	}
	bad := back
	bad.Org = "not an id"
	if _, err = bad.fixture(); err == nil {
		t.Error("a fixture with an undecodable id was accepted")
	}
}

func testWriter(t *testing.T, pool int) (*dcWriter, *dcFixture) {
	t.Helper()
	fx := &dcFixture{org: model.NewID(), project: model.NewID(), source: model.NewID(), service: model.NewID(), environment: model.NewID(), build: model.NewID(), credential: "c"}
	for range pool {
		fx.pool = append(fx.pool, model.NewID())
	}
	return newDCWriter(&dcCluster{fx: fx}, &Ledger{}, pool), fx
}

// Every batch is written down BEFORE it can be sent; a reset leaves the journal of what was in flight, and the second phase sends those
// bodies again unchanged, after which the writer goes on with new ids.
func TestVMHardResetIssuedBatchesAreJournalledBeforeSendingAndAdoptedUnchanged(t *testing.T) {
	w, fx := testWriter(t, 6)
	var ids []string
	var bodies [][]byte
	w.onIssue = func(id string, body []byte) error {
		ids, bodies = append(ids, id), append(bodies, append([]byte(nil), body...))
		return nil
	}
	first, err := w.next()
	if err != nil {
		t.Fatal(err)
	}
	second, err := w.next()
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 || ids[0] != first.ID.String() || ids[1] != second.ID.String() || string(bodies[0]) != string(w.bodies[ids[0]]) {
		t.Fatalf("the journal hook saw %v", ids)
	}
	w.onIssue = func(string, []byte) error { return errors.New("disk full") }
	if _, err = w.next(); err == nil {
		t.Fatal("a batch that could not be journalled was issued")
	}

	w2 := newDCWriter(&dcCluster{fx: fx}, &Ledger{}, 6)
	for i := range bodies {
		b, err := w2.adopt(bodies[i])
		if err != nil {
			t.Fatal(err)
		}
		id, digest, err := dcBatchSemantics(b)
		_, want, _ := dcBatchSemantics(map[string]model.Batch{ids[0]: first, ids[1]: second}[ids[i]])
		if err != nil || id != ids[i] || digest != want {
			t.Errorf("adopted batch %d: id %s digest %s want %s err %v", i, id, digest, want, err)
		}
		if string(w2.bodies[ids[i]]) != string(bodies[i]) {
			t.Errorf("batch %d: the body changed", i)
		}
		if !w2.Issued()[ids[i]] {
			t.Errorf("batch %d is not among the issued ids", i)
		}
	}
	next, err := w2.next()
	if err != nil || next.ID != fx.pool[2] {
		t.Errorf("after adopting two batches the writer must go on with the third id of the pool: %v %v", next.ID, err)
	}
	if _, err = newDCWriter(&dcCluster{fx: fx}, &Ledger{}, 6).adopt([]byte(`{"id":"x"}`)); err == nil {
		t.Error("a body that is not a batch of this installation was adopted")
	}
}

func TestLedgerSinkSeesEveryNewAcknowledgementOnceAndCanRefuseIt(t *testing.T) {
	var seen []string
	l := &Ledger{Sink: func(a Ack) error { seen = append(seen, a.ID); return nil }}
	a := Ack{ID: "a", Group: "g", Index: 1, Digest: "d"}
	for _, x := range []Ack{a, a, {ID: "b", Group: "g", Index: 2, Digest: "e"}} {
		if err := l.Record(x); err != nil {
			t.Fatal(err)
		}
	}
	if strings.Join(seen, ",") != "a,b" {
		t.Errorf("sink saw %v: a retry of an acknowledged batch is not a new acknowledgement", seen)
	}
	bad := &Ledger{Sink: func(Ack) error { return errors.New("fsync failed") }}
	if err := bad.Record(a); err == nil {
		t.Error("an acknowledgement that could not be made durable was recorded without error")
	}
}

// The first real reset took away the files the harness wrote for the members (the PKI, the node files) because they had never been
// fsynced: phase 1 now makes exactly those durable, and phase 2 says so when one is missing or empty instead of starting members that
// cannot start.
func TestVMSetupFilesAreTheHarnessOwnFilesAndEmptyOnesAreRefused(t *testing.T) {
	work := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(work, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("pki/ca.pem", "ca")
	write("pki/a.pem", "a")
	write("pki/a.key", "k")
	write("node-1.json", "{}")
	write("node-2.json", "{}")
	write("cluster.seed", "seed")
	write("node-a/control.db", "the member's own data")
	write("node-a/server.crt", "the member's own certificate")
	files, err := vmSetupFiles(work)
	if err != nil || len(files) != 6 {
		t.Fatalf("setup files %v err %v, want the 3 pki files, 2 node files and the seed", files, err)
	}
	for _, f := range files {
		if strings.Contains(f, "node-a") {
			t.Errorf("%s is a member's own data, not a setup file", f)
		}
	}
	if err = vmFsyncSetup(work); err != nil {
		t.Fatal(err)
	}
	if err = vmCheckSetupFiles(work); err != nil {
		t.Fatalf("intact setup files were refused: %v", err)
	}
	write("node-2.json", "")
	if err = vmCheckSetupFiles(work); err == nil || !strings.Contains(err.Error(), "node-2.json") {
		t.Errorf("an empty node file was accepted: %v", err)
	}
	if err = vmFsyncSetup(work); err == nil {
		t.Error("an empty setup file was made durable as if it were fine")
	}
	write("node-2.json", "{}")
	if err = os.Remove(filepath.Join(work, "cluster.seed")); err != nil {
		t.Fatal(err)
	}
	if err = vmCheckSetupFiles(work); err == nil || !strings.Contains(err.Error(), "cluster.seed") {
		t.Errorf("a missing seed was accepted: %v", err)
	}
}
