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
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/releaseevidence"
)

func init() { register("vm-hard-reset", runVMHardReset) }

// vm-hard-reset (07.07#7): a REAL guest hard reset of the machine that holds all three members. The emulated power cut of `power-loss`
// SIGKILLs processes and rolls unsynced bytes back itself; this one writes `b` to /proc/sysrq-trigger, which reboots the kernel at once
// with no sync and no unmount: the page cache and every write that was not fsynced are gone, as after a crash reboot. It is NOT a
// hypervisor power-off: a write the guest believes was flushed but the host kept in its virtual-disk cache is not exercised (a guest
// reset does not drop the host's cache), and three processes on one machine are not three failure domains.
//
// The harness dies with the machine, so the scenario has two phases that the same command distinguishes by the marker file:
//
//	phase 1  checks every precondition, bootstraps the three-process cluster with its data under the state directory (persistent),
//	         streams writes, appends every issued batch and every acknowledgement to a journal and fsyncs it before the write counts, and
//	         once enough are acknowledged writes the boot id and the marker (fsynced) and resets the machine WHILE the stream runs.
//	phase 2  after the machine is back: refuses unless the boot id changed, reloads the journals (refusing a truncated or tampered
//	         one), starts the three members on the same data, retries the batches that were in flight unchanged, and runs the
//	         verification of the whole-cluster power cut: every acknowledged id retained with identical data on every member, no
//	         unknown id, retries return the original receipt, cursors converge.

const (
	vmLedgerFile = "ledger.jsonl"
	vmIssuedFile = "issued.jsonl"
	vmMarkerFile = "marker.json"
	vmStateFile  = "state.json"
	vmWorkDir    = "work"

	vmBootIDPath  = "/proc/sys/kernel/random/boot_id"
	vmSysrqPath   = "/proc/sys/kernel/sysrq"
	vmTriggerPath = "/proc/sysrq-trigger"

	// vmMinAcks is how many batches must be acknowledged (and journalled) before the machine is reset.
	vmMinAcks = 80

	dcVMResetScope = "guest hard reset = `echo b > /proc/sysrq-trigger` on the machine that holds all three members: an immediate reboot with no sync and no unmount, so the page cache and every unsynced write are lost exactly as after a crash reboot, while the write stream is running. It is not a hypervisor power-off: data the guest believes flushed but the host still holds in its virtual-disk cache is not exercised"
)

// ---- a chained, fsynced journal ----

// vmJournal is an append-only file of JSON lines, each carrying its sequence number, the hash of the line before it and its own hash
// over both and its payload. Every Append is fsynced before it returns. A reader refuses a line cut short, a changed payload, lines
// swapped or dropped: a journal that survived a reset must be the journal that was written.
type vmJournal struct {
	mu   sync.Mutex
	f    *os.File
	n    int
	head string
}

type vmLine struct {
	Seq     int             `json:"seq"`
	Payload json.RawMessage `json:"payload"`
	Prev    string          `json:"prev"`
	Hash    string          `json:"hash"`
}

func vmChain(prev string, seq int, payload []byte) string {
	h := sha256.New()
	fmt.Fprintf(h, "soundpost.vmreset/v1\x00%s\x00%d\x00", prev, seq)
	h.Write(payload)
	return hex.EncodeToString(h.Sum(nil))
}

// vmSyncDir fsyncs a directory so a file created or renamed in it survives a reset.
func vmSyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// createVMJournal creates a new journal; an existing file is an error.
func createVMJournal(path string) (*vmJournal, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	if err = f.Sync(); err == nil {
		err = vmSyncDir(filepath.Dir(path))
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return &vmJournal{f: f}, nil
}

// Append writes one entry and fsyncs it.
func (j *vmJournal) Append(v any) error {
	payload, err := json.Marshal(v)
	if err != nil {
		return err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	seq := j.n + 1
	line, err := json.Marshal(vmLine{Seq: seq, Payload: payload, Prev: j.head, Hash: vmChain(j.head, seq, payload)})
	if err != nil {
		return err
	}
	if _, err = j.f.Write(append(line, '\n')); err != nil {
		return err
	}
	if err = j.f.Sync(); err != nil {
		return err
	}
	var l vmLine
	_ = json.Unmarshal(line, &l)
	j.n, j.head = seq, l.Hash
	return nil
}

// State is the number of entries and the chain head after the last one.
func (j *vmJournal) State() (int, string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.n, j.head
}

func (j *vmJournal) Close() error { return j.f.Close() }

// readVMJournal returns the payloads of a journal and the chain head after each of them, or an error naming what is wrong with it.
func readVMJournal(path string) ([]json.RawMessage, []string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	if len(raw) > 0 && raw[len(raw)-1] != '\n' {
		return nil, nil, errors.New("the journal ends in the middle of a line")
	}
	var payloads []json.RawMessage
	var heads []string
	prev := ""
	for i, text := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		if len(raw) == 0 {
			break
		}
		var l vmLine
		dec := json.NewDecoder(strings.NewReader(text))
		dec.DisallowUnknownFields()
		if err = dec.Decode(&l); err != nil {
			return nil, nil, fmt.Errorf("line %d does not decode", i+1)
		}
		if l.Seq != i+1 || l.Prev != prev || l.Hash != vmChain(prev, l.Seq, l.Payload) {
			return nil, nil, fmt.Errorf("line %d was changed, moved or is missing its predecessor", i+1)
		}
		prev = l.Hash
		payloads, heads = append(payloads, l.Payload), append(heads, l.Hash)
	}
	return payloads, heads, nil
}

// ---- the marker ----

// vmMarker is written last, after the journals have the acknowledgements it counts, and says which boot it was written in.
type vmMarker struct {
	Version    int    `json:"version"`
	Hostname   string `json:"hostname"`
	BootID     string `json:"boot_id"`
	Acks       int    `json:"acks"`
	LedgerHead string `json:"ledger_head"`
	Issued     int    `json:"issued"`
	IssuedHead string `json:"issued_head"`
}

// vmWriteFileSync writes a file so that it, and its name, survive a reset: temporary file, fsync, rename, fsync of the directory.
func vmWriteFileSync(path string, data []byte) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err == nil {
		err = vmSyncDir(filepath.Dir(path))
	}
	return err
}

func writeVMMarker(path string, m vmMarker) error {
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return vmWriteFileSync(path, append(raw, '\n'))
}

func readVMMarker(path string) (vmMarker, error) {
	var m vmMarker
	raw, err := os.ReadFile(path)
	if err != nil {
		return m, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&m); err != nil {
		return m, errors.New("the marker does not decode (cut short or not a marker)")
	}
	if m.Version != 1 || m.Hostname == "" || m.BootID == "" || m.Acks < 0 || m.Issued < 0 {
		return m, errors.New("the marker is incomplete")
	}
	return m, nil
}

// ---- the machine ----

// vmHost is what the preconditions look at; Sysrq enables the magic sysrq key and reports whether it can be written.
type vmHost struct {
	Euid     int
	Hostname string
	BootID   string
	Sysrq    func() error
}

func vmThisHost() (vmHost, error) {
	name, err := os.Hostname()
	if err != nil {
		return vmHost{}, err
	}
	boot, err := os.ReadFile(vmBootIDPath)
	if err != nil {
		return vmHost{}, err
	}
	return vmHost{Euid: os.Geteuid(), Hostname: name, BootID: strings.TrimSpace(string(boot)), Sysrq: func() error {
		f, err := os.OpenFile(vmSysrqPath, os.O_WRONLY, 0)
		if err != nil {
			return err
		}
		defer f.Close()
		if _, err = f.WriteString("1"); err != nil {
			return err
		}
		t, err := os.OpenFile(vmTriggerPath, os.O_WRONLY, 0)
		if err != nil {
			return err
		}
		return t.Close()
	}}, nil
}

func vmCommon(h vmHost, allowHost, stateDir string, al Allowlist) error {
	if h.Euid != 0 {
		return refuse("a hard reset of the machine is destructive and only root may trigger it")
	}
	if allowHost == "" || allowHost != h.Hostname {
		return refuse("--allow-vm-reset must name this machine exactly (hostname %q)", h.Hostname)
	}
	return CheckTarget(al, Target{Name: TargetName, DataDirs: []string{stateDir}})
}

// vmCheckStart is every precondition of phase 1; a refusal is an ErrRefused error and nothing has been touched.
func vmCheckStart(h vmHost, allowHost, stateDir string, al Allowlist) error {
	if err := vmCommon(h, allowHost, stateDir, al); err != nil {
		return err
	}
	if h.Sysrq == nil {
		return refuse("magic sysrq is not available")
	}
	if err := h.Sysrq(); err != nil {
		return refuse("magic sysrq cannot be enabled: %v", err)
	}
	entries, err := os.ReadDir(stateDir)
	switch {
	case err == nil && len(entries) > 0:
		return refuse("state directory %q is not empty", stateDir)
	case err != nil && !errors.Is(err, os.ErrNotExist):
		return refuse("state directory cannot be read: %v", err)
	}
	return nil
}

// vmIssued is one batch the drill issued: its id and the exact body that was (or was about to be) sent.
type vmIssued struct {
	ID   string          `json:"id"`
	Body json.RawMessage `json:"body"`
}

// vmResume is what phase 1 left behind, verified.
type vmResume struct {
	Marker vmMarker
	Acks   []Ack
	Issued []vmIssued
}

// vmCheckResume is every precondition of phase 2: the same machine, a boot id that is not the marker's (the machine WAS reset), and
// journals that are exactly what phase 1 wrote down (not cut short, not changed, not shorter than the marker counted). Anything
// else is a refusal: the verification would otherwise judge a cluster against a ledger nobody can vouch for.
func vmCheckResume(h vmHost, allowHost, stateDir string, al Allowlist) (vmResume, error) {
	var r vmResume
	if err := vmCommon(h, allowHost, stateDir, al); err != nil {
		return r, err
	}
	m, err := readVMMarker(filepath.Join(stateDir, vmMarkerFile))
	if err != nil {
		return r, refuse("marker: %v", err)
	}
	r.Marker = m
	if m.Hostname != h.Hostname {
		return r, refuse("the marker was written on another machine")
	}
	if m.BootID == h.BootID {
		return r, refuse("the boot id is the one the marker was written in: the machine was not reset")
	}
	load := func(name string, count int, head string) ([]json.RawMessage, error) {
		payloads, heads, err := readVMJournal(filepath.Join(stateDir, name))
		if err != nil {
			return nil, refuse("%s: %v", name, err)
		}
		if len(payloads) < count {
			return nil, refuse("%s holds %d entries, the marker counted %d", name, len(payloads), count)
		}
		if count > 0 && heads[count-1] != head {
			return nil, refuse("%s is not the journal the marker was written for", name)
		}
		return payloads, nil
	}
	acks, err := load(vmLedgerFile, m.Acks, m.LedgerHead)
	if err != nil {
		return r, err
	}
	issued, err := load(vmIssuedFile, m.Issued, m.IssuedHead)
	if err != nil {
		return r, err
	}
	known := map[string]bool{}
	for _, raw := range issued {
		var b vmIssued
		if err = strictJSON(raw, &b); err != nil || b.ID == "" {
			return r, refuse("%s holds an entry that is not an issued batch", vmIssuedFile)
		}
		known[b.ID] = true
		r.Issued = append(r.Issued, b)
	}
	for _, raw := range acks {
		var a Ack
		if err = strictJSON(raw, &a); err != nil || a.ID == "" {
			return r, refuse("%s holds an entry that is not an acknowledgement", vmLedgerFile)
		}
		if !known[a.ID] {
			return r, refuse("acknowledgement %s was never issued", a.ID)
		}
		r.Acks = append(r.Acks, a)
	}
	return r, nil
}

func strictJSON(raw []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// vmLedgerOf rebuilds the ledger of phase 1 from its journal.
func vmLedgerOf(acks []Ack) (*Ledger, error) {
	l := &Ledger{}
	for _, a := range acks {
		if err := l.Record(a); err != nil {
			return nil, err
		}
	}
	return l, nil
}

// ---- what the second phase needs of the cluster the first one bootstrapped ----

type vmState struct {
	Public      map[uint64]string `json:"public"`
	Peer        map[uint64]string `json:"peer"`
	Org         string            `json:"org"`
	Project     string            `json:"project"`
	Source      string            `json:"source"`
	Service     string            `json:"service"`
	Environment string            `json:"environment"`
	Build       string            `json:"build"`
	Credential  string            `json:"credential"`
	ReaderEmail string            `json:"reader_email"`
	Pool        []string          `json:"pool"`
}

func vmStateOf(fx *dcFixture, public, peer map[uint64]string) vmState {
	s := vmState{Public: public, Peer: peer, Org: fx.org.String(), Project: fx.project.String(), Source: fx.source.String(), Service: fx.service.String(),
		Environment: fx.environment.String(), Build: fx.build.String(), Credential: fx.credential, ReaderEmail: fx.readerEmail}
	for _, id := range fx.pool {
		s.Pool = append(s.Pool, id.String())
	}
	return s
}

func (s vmState) fixture() (*dcFixture, error) {
	fx := &dcFixture{credential: s.Credential, readerEmail: s.ReaderEmail}
	for _, f := range []struct {
		dst *model.ID
		src string
	}{{&fx.org, s.Org}, {&fx.project, s.Project}, {&fx.source, s.Source}, {&fx.service, s.Service}, {&fx.environment, s.Environment}, {&fx.build, s.Build}} {
		id, err := model.ParseID(f.src)
		if err != nil {
			return nil, errors.New("the saved fixture has an id that does not decode")
		}
		*f.dst = id
	}
	for _, p := range s.Pool {
		id, err := model.ParseID(p)
		if err != nil {
			return nil, errors.New("the saved fixture has a batch id that does not decode")
		}
		fx.pool = append(fx.pool, id)
	}
	return fx, nil
}

// dcMemberAddresses is the public and peer address of one member: new ones, or the ones phase 1 saved.
func dcMemberAddresses(opts dcOptions, id uint64) (string, string, error) {
	if opts.resume != nil {
		pub, peer := opts.resume.Public[id], opts.resume.Peer[id]
		if pub == "" || peer == "" {
			return "", "", fmt.Errorf("the saved state has no addresses for member %d", id)
		}
		return pub, peer, nil
	}
	pub, e1 := dcFreeAddress()
	peer, e2 := dcFreeAddress()
	return pub, peer, errors.Join(e1, e2)
}

// adopt registers a batch of a previous run by its exact body, so it can be sent again unchanged; the writer goes on after the last
// pool id any adopted batch used.
func (w *dcWriter) adopt(body []byte) (model.Batch, error) {
	var b model.Batch
	if err := model.StrictJSON(body, &b); err != nil {
		return b, errors.New("the body is not a batch")
	}
	fx := w.c.fx
	if b.Project != fx.project || b.Source != fx.source {
		return b, errors.New("the batch belongs to another installation")
	}
	if _, _, err := dcBatchSemantics(b); err != nil {
		return b, err
	}
	index := slices.Index(fx.pool, b.ID)
	if index < 0 {
		return b, errors.New("the batch id is not in this installation's pool")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.batches[b.ID.String()], w.bodies[b.ID.String()], w.issued[b.ID.String()] = b, bytes.Clone(body), true
	w.seq = max(w.seq, index+1)
	return b, nil
}

// mentions counts the lines of a member's output that contain word (the output itself never reaches a report).
func (s *dcLog) mentions(word string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, line := range strings.Split(s.b.String(), "\n") {
		if strings.Contains(strings.ToLower(line), word) {
			n++
		}
	}
	return n
}

// ---- the files the harness itself wrote for the members ----

// vmSetupFiles are the files the HARNESS wrote for the members, not the members' own data: the PKI, the node files and the seed. The
// first real reset showed that they are lost (zero length) when they are not fsynced, which makes the members unable to start: the
// harness must make them durable itself, and must say so when a reset took one away.
func vmSetupFiles(work string) ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(work, "pki"))
	if err != nil {
		return nil, err
	}
	var files []string
	for _, e := range entries {
		if e.Type().IsRegular() {
			files = append(files, filepath.Join(work, "pki", e.Name()))
		}
	}
	nodes, err := filepath.Glob(filepath.Join(work, "node-*.json"))
	if err != nil {
		return nil, err
	}
	return append(append(files, nodes...), filepath.Join(work, "cluster.seed")), nil
}

// vmFsyncSetup makes the setup files and their directories durable (only those: the members' data is left exactly as the members left it).
func vmFsyncSetup(work string) error {
	files, err := vmSetupFiles(work)
	if err != nil {
		return err
	}
	for _, p := range files {
		f, err := os.OpenFile(p, os.O_RDONLY, 0)
		if err != nil {
			return err
		}
		info, serr := f.Stat()
		if serr == nil && info.Size() == 0 {
			serr = fmt.Errorf("setup file %s is empty", filepath.Base(p))
		}
		if serr == nil {
			serr = f.Sync()
		}
		f.Close()
		if serr != nil {
			return serr
		}
	}
	for _, d := range []string{work, filepath.Join(work, "pki")} {
		if err = vmSyncDir(d); err != nil {
			return err
		}
	}
	return nil
}

// vmCheckSetupFiles refuses to start the members when a setup file is missing or empty.
func vmCheckSetupFiles(work string) error {
	files, err := vmSetupFiles(work)
	if err != nil {
		return err
	}
	for _, p := range files {
		info, err := os.Stat(p)
		if err != nil {
			return fmt.Errorf("setup file %s is missing", filepath.Base(p))
		}
		if info.Size() == 0 {
			return fmt.Errorf("setup file %s is empty: the reset took away a file the harness wrote without making it durable", filepath.Base(p))
		}
	}
	return nil
}

// ---- the scenario ----

func runVMHardReset(env *Env, rep *Report) error {
	if env.VMResetState == "" || env.VMAllowHost == "" {
		reason := "this scenario resets the machine it runs on: pass --vm-reset-state DIR (under an allowlisted data root that survives a reboot) and --allow-vm-reset <this machine's hostname>"
		rep.NotRun("vm-hard-reset", reason)
		return errNotRun(reason)
	}
	if runtime.GOOS != "linux" {
		reason := "the guest hard reset needs Linux (/proc/sysrq-trigger)"
		rep.NotRun("vm-hard-reset", reason)
		return errNotRun(reason)
	}
	host, err := vmThisHost()
	if err != nil {
		return err
	}
	if _, err = os.Stat(filepath.Join(env.VMResetState, vmMarkerFile)); err == nil {
		return vmResumeAfterReset(env, rep, host)
	}
	return vmStartAndReset(env, rep, host)
}

func vmUptime() string {
	raw, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return ""
	}
	return strings.Fields(string(raw))[0]
}

func vmKernel() string {
	raw, _ := os.ReadFile("/proc/sys/kernel/osrelease")
	return strings.TrimSpace(string(raw))
}

// vmWritePhaseOneReport writes what phase 1 observed, durably, before the machine goes: the harness will not be alive to write it.
func vmWritePhaseOneReport(env *Env, rep *Report, reason string) error {
	digest, err := releaseevidence.CurrentSourceDigest()
	if err != nil {
		return err
	}
	rep.Status, rep.Reason, rep.SourceSHA256 = Status("phase1_reset_issued"), reason, digest
	rep.AckLedger, rep.FailedAttempts = rep.Ledger().Acks(), rep.Ledger().Attempts()
	raw, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	return vmWriteFileSync(filepath.Join(env.ReportDir, "vm-hard-reset.phase1.json"), append(raw, '\n'))
}

func vmStartAndReset(env *Env, rep *Report, host vmHost) error {
	state := env.VMResetState
	if err := vmCheckStart(host, env.VMAllowHost, state, env.Allowlist); err != nil {
		return err
	}
	if err := os.MkdirAll(state, 0o700); err != nil {
		return err
	}
	rep.Fact("vm_reset/scope", dcVMResetScope)
	rep.Fact("vm_reset/hostname", host.Hostname)
	rep.Fact("vm_reset/boot_id_before", host.BootID)
	rep.Fact("vm_reset/uptime_seconds_before", vmUptime())
	rep.Fact("vm_reset/kernel", vmKernel())
	c, err := newDCClusterWith(env, dcOptions{workDir: filepath.Join(state, vmWorkDir)})
	if err != nil {
		return err
	}
	defer c.close()
	if err = dcBinaryFacts(c, rep); err != nil {
		return err
	}
	if err = c.bootstrapAndStart(); err != nil {
		return rep.Require("cluster_bootstrapped_and_ready", false, err.Error())
	}
	if err = rep.Require("cluster_bootstrapped_and_ready", true, "single installation bootstrapped, seed exported, three mTLS members ready, data under the persistent state directory"); err != nil {
		return err
	}
	if err = dcRecordCursors(c, rep, "baseline"); err != nil {
		return err
	}
	if err = vmFsyncSetup(filepath.Join(state, vmWorkDir)); err != nil {
		return rep.Require("vm_reset_setup_files_durable", false, err.Error())
	}
	raw, err := json.MarshalIndent(vmStateOf(c.fx, c.public, c.peer), "", "  ")
	if err != nil {
		return err
	}
	if err = vmWriteFileSync(filepath.Join(state, vmStateFile), append(raw, '\n')); err != nil {
		return err
	}
	ledger, err := createVMJournal(filepath.Join(state, vmLedgerFile))
	if err != nil {
		return err
	}
	issued, err := createVMJournal(filepath.Join(state, vmIssuedFile))
	if err != nil {
		return err
	}
	w := newDCWriter(c, rep.Ledger(), dcPoolSize)
	// Every batch is on disk (fsynced) before its first send, every acknowledgement before the drill counts it.
	w.onIssue = func(id string, body []byte) error { return issued.Append(vmIssued{ID: id, Body: body}) }
	rep.Ledger().Sink = func(a Ack) error { return ledger.Append(a) }
	w.startStream(4, 20*time.Millisecond, dcPoolSize-100, "vm_reset")
	if err = w.waitAcks(vmMinAcks, time.Time{}, 180*time.Second); err != nil {
		w.abortStream()
		return rep.Require("vm_reset_stream_acks_before_reset", false, err.Error())
	}
	acks, ledgerHead := ledger.State()
	issuedN, issuedHead := issued.State()
	marker := vmMarker{Version: 1, Hostname: host.Hostname, BootID: host.BootID, Acks: acks, LedgerHead: ledgerHead, Issued: issuedN, IssuedHead: issuedHead}
	if err = writeVMMarker(filepath.Join(state, vmMarkerFile), marker); err != nil {
		w.abortStream()
		return err
	}
	// The directories that hold the state must exist after the reset too.
	for _, d := range []string{state, filepath.Dir(state), filepath.Join(state, vmWorkDir), env.ReportDir} {
		if err = vmSyncDir(d); err != nil {
			return err
		}
	}
	rep.Fact("vm_reset/acks_before_reset", acks)
	rep.Fact("vm_reset/issued_before_reset", issuedN)
	rep.Fact("vm_reset/stream_running_at_reset", true)
	if err = rep.Require("vm_reset_acknowledgements_journalled_before_reset", acks >= vmMinAcks, fmt.Sprintf("%d acknowledgements and %d issued batches are on disk (fsynced), the stream is still running", acks, issuedN)); err != nil {
		return err
	}
	if err = vmWritePhaseOneReport(env, rep, "the machine is being reset (sysrq b) while the write stream runs; phase 2 verifies the cluster"); err != nil {
		return err
	}
	env.Logf("phase 1 done: %d acknowledgements journalled, resetting the machine now", acks)
	t, err := os.OpenFile(vmTriggerPath, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	if _, err = t.WriteString("b"); err != nil {
		return err
	}
	// The kernel reboots at once: reaching this line means it did not.
	time.Sleep(60 * time.Second)
	return errors.New("the machine did not reset after the sysrq trigger")
}

func vmResumeAfterReset(env *Env, rep *Report, host vmHost) error {
	state := env.VMResetState
	res, err := vmCheckResume(host, env.VMAllowHost, state, env.Allowlist)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(filepath.Join(state, vmStateFile))
	if err != nil {
		return refuse("state: %v", err)
	}
	var saved vmState
	if err = strictJSON(raw, &saved); err != nil {
		return refuse("state does not decode")
	}
	fx, err := saved.fixture()
	if err != nil {
		return refuse("%v", err)
	}
	rep.Fact("vm_reset/scope", dcVMResetScope)
	rep.Fact("vm_reset/hostname", host.Hostname)
	rep.Fact("vm_reset/boot_id_before", res.Marker.BootID)
	rep.Fact("vm_reset/boot_id_after", host.BootID)
	rep.Fact("vm_reset/uptime_seconds_after_reset", vmUptime())
	rep.Fact("vm_reset/kernel", vmKernel())
	rep.Fact("vm_reset/acks_at_marker", res.Marker.Acks)
	rep.Fact("vm_reset/acks_in_journal", len(res.Acks))
	rep.Fact("vm_reset/issued_in_journal", len(res.Issued))
	if err = rep.Require("vm_reset_machine_was_reset", true, fmt.Sprintf("the boot id changed from %s to %s", res.Marker.BootID, host.BootID)); err != nil {
		return err
	}
	ledger := rep.Ledger()
	for _, a := range res.Acks {
		if err = ledger.Record(a); err != nil {
			return err
		}
	}
	c, err := newDCClusterWith(env, dcOptions{workDir: filepath.Join(state, vmWorkDir), resume: &saved})
	if err != nil {
		return err
	}
	defer c.close()
	c.fx = fx
	if err = dcBinaryFacts(c, rep); err != nil {
		return err
	}
	w := newDCWriter(c, ledger, dcPoolSize)
	acked := map[string]bool{}
	for _, a := range res.Acks {
		acked[a.ID] = true
	}
	var inflight []string
	for _, b := range res.Issued {
		if _, err = w.adopt(b.Body); err != nil {
			return rep.Require("vm_reset_journal_batches_adopted", false, err.Error())
		}
		if !acked[b.ID] {
			inflight = append(inflight, b.ID)
		}
	}
	if err = vmCheckSetupFiles(filepath.Join(state, vmWorkDir)); err != nil {
		return rep.Require("vm_reset_setup_files_intact", false, err.Error())
	}
	rep.Timeline().Fail("cluster", "guest hard reset (sysrq b) of the machine while the write stream was running")
	rep.Timeline().Fail("cluster", "all three members were killed with the machine and lost their page cache")
	for _, n := range dcMembers {
		if err = c.start(n.id); err != nil {
			return rep.Require("vm_reset_members_restarted", false, err.Error())
		}
	}
	began := time.Now()
	for _, n := range dcMembers {
		if err = c.waitReady(n.id, 300*time.Second); err != nil {
			return rep.Require("vm_reset_ready_after_reset", false, fmt.Sprintf("member %d: %v; cluster at the failure: %s", n.id, err, c.diagnose()))
		}
	}
	rep.Fact("vm_reset/ready_after_start_ms", time.Since(began).Milliseconds())
	if err = rep.Require("vm_reset_ready_after_reset", true, "all three members are ready on the data the reset left"); err != nil {
		return err
	}
	rep.Fact("vm_reset/member_log_mentions_torn", map[string]int{"1": c.logs[1].mentions("torn"), "2": c.logs[2].mentions("torn"), "3": c.logs[3].mentions("torn")})
	rep.Fact("vm_reset/member_exit_reason_tokens", map[string]string{"1": c.logs[1].lastReason(), "2": c.logs[2].lastReason(), "3": c.logs[3].lastReason()})
	// The batches that were in flight at the reset are sent again, unchanged, until they are acknowledged.
	for _, id := range inflight {
		w.mu.Lock()
		b := w.batches[id]
		w.mu.Unlock()
		if _, err = w.deliver(b, c.live, 150*time.Second, "vm_reset_inflight_retry"); err != nil {
			return rep.Require("vm_reset_inflight_batches_retried_to_ack", false, err.Error())
		}
	}
	rep.Fact("vm_reset/inflight_batches_retried_to_ack", len(inflight))
	if err = rep.Require("vm_reset_inflight_batches_retried_to_ack", true, fmt.Sprintf("%d batches issued and never acknowledged before the reset were sent again unchanged and acknowledged", len(inflight))); err != nil {
		return err
	}
	rep.Timeline().Deliver("cluster", "the interrupted batches were retried unchanged and acknowledged after the reset")
	if err = rep.Timeline().Recover("cluster"); err != nil {
		return rep.Require("vm_reset_outage_recovered", false, err.Error())
	}
	if err = dcRecordCursors(c, rep, "after_reset"); err != nil {
		return err
	}
	acks := ledger.Acks()
	pick := acks[len(acks)/2].ID
	if len(inflight) > 0 {
		pick = inflight[0]
	}
	if err = dcCheckRetries(c, w, rep, "after_reset", "after a guest hard reset: a retry of a batch acknowledged before it returns the original receipt", pick); err != nil {
		return err
	}
	retained, err := dcVerifyMembers(c, w, rep, "after_reset", 300*time.Second)
	if err != nil {
		return err
	}
	if err = rep.Reconcile(retained); err != nil {
		return err
	}
	events := rep.Timeline().Events()
	terr := VerifyTimeline(events, 2)
	detail := fmt.Sprintf("%d events, %d failed attempts kept, final state %s", len(events), FailedAttempts(events), rep.Timeline().State())
	if terr != nil {
		detail = terr.Error()
	}
	if err = rep.Require("outage_timeline_verifies", terr == nil && rep.Timeline().State() == StateRecovered, detail); err != nil {
		return err
	}
	rep.Fact("acknowledged_batches", ledger.Len())
	return nil
}
