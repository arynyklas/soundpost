// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

func init() { register("node-loss-journeys", runNodeLossJourneys) }

// node-loss-journeys (07.07#16): the three-process cluster of node-kill-restart loses a member twice (SIGKILL of the initial leader,
// then of member 3) while a write stream is acknowledged, and recovers. Only when it has RECOVERED (every acknowledged id read
// back identically from every member, every member ready, the control cursors equal, the outage closed) does it run the real
// reference journeys against it: `tools/smoke journeys --cluster-attach` with the reference applications (Bun gateway, Python
// API and job, the Vite-built web app in headless Chrome), a real PostgreSQL 16 and the product's own routes, whose members are
// the three processes. The applications ingest through different members (some killed and restored), the owner of the
// installation provisions and drives them, the collect step scans the storage of the scan member in the smoke process after
// this drill stopped it, and every read of the rows goes through that member after this drill started it again. While the
// applications run, the drill's own writers keep acknowledging batches through the members. Afterwards every acknowledged id of the
// whole run is reconciled again on every member.
//
// The rows are the smoke's own (journeys_assert.go) and are copied into this report from its observation file; nothing here
// evaluates them.

// dcJourneyRowNames are the rows of tools/smoke/journeys_assert.go (TestJourneyRowNamesMatchTheSmokeAssertions keeps the
// two lists equal and every count in the drill's tests is taken from this list). A run counts only when it reports every one of them once, required and satisfied.
var dcJourneyRowNames = []string{
	"gateway_dependency_child_span",
	"frontend_request_api_db_chain",
	"error_admitted_with_known_build",
	"error_linked_to_request_trace",
	"build_source_map_uploaded",
	"mapped_frame_at_known_location",
	"job_failed_attempt_retained_then_success",
	"same_trace_in_wrong_org_denied",
	"canaries_absent_everywhere",
	"db_span_safe_operation_only",
	"replay_masked_interaction_real_recorder",
	"profile_linkage_with_capability_truth",
	"browser_profile_read_through_profile_view",
	"browser_profile_refusals_stored_capability_only",
	"browser_profile_scenarios_console_errors_explained",
	"runtime_profile_delivered_stored_linked",
	"actual_ids_equal_expected",
	"actual_versions_recorded",
}

// ---- the rows of the run ----

type dcJourneyRow struct {
	Name      string `json:"name"`
	Required  bool   `json:"required"`
	Satisfied bool   `json:"satisfied"`
	Reason    string `json:"reason"`
	Detail    string `json:"detail,omitempty"`
}

// dcJourneyRows decodes the rows of the smoke's observed.json.
func dcJourneyRows(raw []byte) ([]dcJourneyRow, error) {
	var doc struct {
		Rows []dcJourneyRow `json:"rows"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("the observation document does not decode: %w", err)
	}
	return doc.Rows, nil
}

type dcRowCheck struct {
	name   string
	ok     bool
	detail string
}

func dcClip(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r < 32 {
			return ' '
		}
		return r
	}, s)
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

// dcJourneyRowChecks is the verdict on the rows: one check per expected row, which holds only when the run reported that row
// exactly once, as required and satisfied; and one failing check for every row the run reported that is not expected.
func dcJourneyRowChecks(rows []dcJourneyRow) []dcRowCheck {
	byName := map[string][]dcJourneyRow{}
	for _, r := range rows {
		byName[r.Name] = append(byName[r.Name], r)
	}
	var out []dcRowCheck
	for _, want := range dcJourneyRowNames {
		got := byName[want]
		check := dcRowCheck{name: "journey_row_" + want}
		switch {
		case len(got) == 0:
			check.detail = "the run did not report this row"
		case len(got) > 1:
			check.detail = fmt.Sprintf("the run reported this row %d times", len(got))
		case !got[0].Required:
			check.detail = "reported as not required: only required rows count"
		case !got[0].Satisfied:
			check.detail = "NOT SATISFIED " + dcClip(got[0].Reason+" "+got[0].Detail, 300)
		default:
			check.ok, check.detail = true, dcClip(got[0].Reason+" "+got[0].Detail, 300)
		}
		out = append(out, check)
	}
	var extra []string
	for name := range byName {
		if !slices.Contains(dcJourneyRowNames, name) {
			extra = append(extra, dcSafeToken(name))
		}
	}
	if len(extra) > 0 {
		sort.Strings(extra)
		out = append(out, dcRowCheck{name: "journey_row_unexpected", detail: fmt.Sprintf("rows this scenario does not know: %v", extra)})
	}
	return out
}

// ---- what every SDK of the run says about its own delivery ----

type dcFlush struct {
	Pending  int `json:"pending"`
	Lost     int `json:"lost"`
	Receipts int `json:"receipts"`
}

// dcJourneyFlushes reads, from the smoke's details document, the flush report of every client that sent evidence to the cluster:
// the gateway, the API, the job, and the three browser pages (order, replay, profile). A client without a report is an error.
func dcJourneyFlushes(details []byte) (map[string]dcFlush, error) {
	var doc struct {
		Gateway dcFlush  `json:"gateway_flush"`
		API     dcFlush  `json:"api_flush"`
		Order   *dcFlush `json:"order_driver_flush"`
		Jobs    struct {
			Flush *dcFlush `json:"flush"`
		} `json:"jobs_output"`
		Replay struct {
			Replay struct {
				Flush *dcFlush `json:"flush"`
			} `json:"replay"`
		} `json:"replay_driver"`
		Profile struct {
			Profile struct {
				Flush *dcFlush `json:"flush"`
			} `json:"profile"`
		} `json:"profile_driver"`
	}
	if err := json.Unmarshal(details, &doc); err != nil {
		return nil, fmt.Errorf("the details document does not decode: %w", err)
	}
	var missing []string
	out := map[string]dcFlush{"gateway": doc.Gateway, "api": doc.API}
	for name, f := range map[string]*dcFlush{"order_page": doc.Order, "job": doc.Jobs.Flush, "replay_page": doc.Replay.Replay.Flush, "profile_page": doc.Profile.Profile.Flush} {
		if f == nil {
			missing = append(missing, name)
			continue
		}
		out[name] = *f
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return nil, fmt.Errorf("no flush report of: %v", missing)
	}
	return out, nil
}

// dcFlushVerdict requires every client to have delivered everything it was given: nothing pending and nothing lost in its final
// flush. A client's own receipt count only covers the batches that final flush sent (the others went out while it ran), so one
// client reporting no receipt is not a fault; the clients together must report at least one, or nothing was acknowledged at all.
func dcFlushVerdict(flushes map[string]dcFlush) (int, error) {
	names := make([]string, 0, len(flushes))
	for name := range flushes {
		names = append(names, name)
	}
	sort.Strings(names)
	total := 0
	for _, name := range names {
		f := flushes[name]
		if f.Pending != 0 || f.Lost != 0 {
			return 0, fmt.Errorf("%s ended with pending=%d lost=%d receipts=%d", name, f.Pending, f.Lost, f.Receipts)
		}
		total += f.Receipts
	}
	if total <= 0 {
		return 0, errors.New("no client reports a receipt from the cluster")
	}
	return total, nil
}

// ---- the attach document ----

// dcJourneyRoles says which member each journey leg uses (the attach document's roles).
type dcJourneyRoles struct {
	Admin    uint64 `json:"admin"`
	Gateway  uint64 `json:"gateway"`
	API      uint64 `json:"api"`
	Jobs     uint64 `json:"jobs"`
	Web      uint64 `json:"web"`
	Webbuild uint64 `json:"webbuild"`
	Scan     uint64 `json:"scan"`
}

// dcDefaultJourneyRoles spreads the legs over the members the two node losses killed (1 and 3) and the one they never touched
// (2): the gateway, its page and the web build's upload go through member 3, the job through member 1, the API and the
// provisioning through member 2; member 1 is also the one the scan stops and the reads go through, so every read of the rows is
// served by a member that was killed and restored.
var dcDefaultJourneyRoles = dcJourneyRoles{Admin: 2, Gateway: 3, API: 2, Jobs: 1, Web: 3, Webbuild: 3, Scan: 1}

type dcJourneyMember struct {
	ID         uint64 `json:"id"`
	Address    string `json:"address"`
	DataDir    string `json:"data_dir"`
	NodeConfig string `json:"node_config"`
}

// dcJourneyTopology is what the attach document is made from: the members, which of them answer now, and which were killed and
// restored.
type dcJourneyTopology struct {
	Members []dcJourneyMember
	Live    map[uint64]bool
	Victims []uint64
}

type dcAttachDocument struct {
	Version int    `json:"version"`
	Control string `json:"control"`
	TLS     struct {
		CA   string `json:"ca"`
		Cert string `json:"cert"`
		Key  string `json:"key"`
	} `json:"tls"`
	Owner struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	} `json:"owner"`
	Members   []dcJourneyMember `json:"members"`
	Recovered []uint64          `json:"recovered"`
	Roles     map[string]uint64 `json:"roles"`
}

// dcJourneyAttachDocument builds the document `smoke journeys --cluster-attach` reads. It refuses to describe a cluster in which a
// journey leg would go to a member that is not answering, in which the scan member was never killed and restored, or that has
// fewer than three members.
func dcJourneyAttachDocument(t dcJourneyTopology, tls *dcPublicTLS, email, password string, roles dcJourneyRoles) ([]byte, error) {
	if len(t.Members) < 3 {
		return nil, fmt.Errorf("the cluster has %d members, journeys run against three", len(t.Members))
	}
	known := map[uint64]bool{}
	for _, m := range t.Members {
		known[m.ID] = true
		if !t.Live[m.ID] {
			return nil, fmt.Errorf("member %d is not answering: journeys do not run against a cluster with a dead member", m.ID)
		}
	}
	named := map[string]uint64{"admin": roles.Admin, "gateway": roles.Gateway, "api": roles.API, "jobs": roles.Jobs, "web": roles.Web, "webbuild": roles.Webbuild, "scan": roles.Scan}
	for _, role := range []string{"admin", "gateway", "api", "jobs", "web", "webbuild", "scan"} {
		id := named[role]
		if !known[id] {
			return nil, fmt.Errorf("role %s names member %d, which is not in the cluster", role, id)
		}
		if !t.Live[id] {
			return nil, fmt.Errorf("role %s names member %d, which is not answering", role, id)
		}
	}
	if !slices.Contains(t.Victims, roles.Scan) {
		return nil, fmt.Errorf("the scan member %d was not killed and restored: the reads would not go through a restored member", roles.Scan)
	}
	var doc dcAttachDocument
	doc.Version, doc.Control = 1, "stdio"
	doc.TLS.CA, doc.TLS.Cert, doc.TLS.Key = tls.ca, tls.cert, tls.key
	doc.Owner.Email, doc.Owner.Password = email, password
	doc.Members, doc.Recovered, doc.Roles = t.Members, slices.Clone(t.Victims), named
	return json.MarshalIndent(doc, "", "  ")
}

// ---- the owner of the cluster, as the journeys see it ----

type dcControlRequest struct {
	Op     string `json:"op"`
	Member uint64 `json:"member,omitempty"`
	Name   string `json:"name,omitempty"`
}

type dcControlAnswer struct {
	OK   bool   `json:"ok"`
	Code string `json:"code,omitempty"`
}

// dcJourneyHost is what the owner can do to the cluster for the journeys.
type dcJourneyHost interface {
	shutdown(id uint64) error
	start(id uint64) error
	waitReady(id uint64, limit time.Duration) error
}

// dcJourneyWrites is the drill's own write stream next to the applications.
type dcJourneyWrites interface {
	begin() error
	end() error
}

// The journeys' progress as the owner has seen it: it may only go forward, one step at a time.
const (
	dcOwnerNew          = "new"
	dcOwnerDriving      = "driving"       // the applications run (drive_begin)
	dcOwnerDriven       = "driven"        // they are done (drive_end)
	dcOwnerScanStopped  = "scan_stopped"  // the scan member left
	dcOwnerScanRestored = "scan_restored" // and was started again and answers
)

// dcJourneyOwner answers the journeys' requests on the control channel. It is the only party that stops and starts members; it
// refuses a member other than the scan member, a request out of order and a request twice.
type dcJourneyOwner struct {
	host  dcJourneyHost
	wr    dcJourneyWrites
	scan  uint64
	facts func(key string, v any)

	mu    sync.Mutex
	state string
}

func (o *dcJourneyOwner) State() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.state == "" {
		return dcOwnerNew
	}
	return o.state
}

// handle runs one request and returns "" or the closed code of the refusal.
func (o *dcJourneyOwner) handle(r dcControlRequest) string {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.state == "" {
		o.state = dcOwnerNew
	}
	switch r.Op {
	case "phase":
		switch {
		case r.Name == "drive_begin" && o.state == dcOwnerNew:
			if err := o.wr.begin(); err != nil {
				return "writes_not_started"
			}
			o.state = dcOwnerDriving
			return ""
		case r.Name == "drive_end" && o.state == dcOwnerDriving:
			o.state = dcOwnerDriven
			if err := o.wr.end(); err != nil {
				return "writes_failed"
			}
			return ""
		case r.Name == "drive_begin" || r.Name == "drive_end":
			return "out_of_order"
		}
		return "unknown_phase"
	case "stop_member":
		switch {
		case r.Member != o.scan:
			return "member_not_allowed"
		case o.state != dcOwnerDriven:
			return "out_of_order"
		}
		began := time.Now()
		if err := o.host.shutdown(r.Member); err != nil {
			return "stop_failed"
		}
		o.facts("journeys/scan_member_stop_ms", time.Since(began).Milliseconds())
		o.state = dcOwnerScanStopped
		return ""
	case "start_member":
		switch {
		case r.Member != o.scan:
			return "member_not_allowed"
		case o.state != dcOwnerScanStopped:
			return "out_of_order"
		}
		began := time.Now()
		if err := o.host.start(r.Member); err != nil {
			return "start_failed"
		}
		if err := o.host.waitReady(r.Member, 180*time.Second); err != nil {
			return "not_ready_after_start"
		}
		o.facts("journeys/scan_member_ready_after_start_ms", time.Since(began).Milliseconds())
		o.state = dcOwnerScanRestored
		return ""
	}
	return "unknown_op"
}

// dcServeJourneyControl reads one JSON request per line from in and writes one answer per line to out until in ends. A line that is
// not exactly a request is answered `malformed`.
func dcServeJourneyControl(in io.Reader, out io.Writer, o interface{ handle(dcControlRequest) string }) error {
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	enc := json.NewEncoder(out)
	for sc.Scan() {
		var req dcControlRequest
		dec := json.NewDecoder(bytes.NewReader(sc.Bytes()))
		dec.DisallowUnknownFields()
		code := "malformed"
		if dec.Decode(&req) == nil {
			code = o.handle(req)
		}
		if err := enc.Encode(dcControlAnswer{OK: code == "", Code: code}); err != nil {
			return err
		}
	}
	return sc.Err()
}

// ---- the recovery gate ----

// dcRecoveryView is what the gate asks of the cluster.
type dcRecoveryView interface {
	members() []uint64
	live() []uint64
	waitReady(id uint64, limit time.Duration) error
	converged(limit time.Duration) (map[uint64]uint64, error)
}

// dcRecoveryGate is the precondition of the journeys: the cluster has RECOVERED. `retained` is what every member was read back to
// retain (identical on all of them). Every acknowledged id must be in it with its exact digest, every member must be ready now
// and none stopped or paused, the control cursors must be equal, and the outage must be closed with its failed attempts kept.
// Every part is a check of the report; the first failing part is the error.
func dcRecoveryGate(v dcRecoveryView, rep *Report, retained map[string]string, victims []uint64) error {
	var first error
	keep := func(err error) {
		if first == nil {
			first = err
		}
	}
	_, rerr := Reconcile(rep.Ledger(), retained)
	detail := fmt.Sprintf("%d acknowledged ids retained with identical semantic data on every member", rep.Ledger().Len())
	if rerr != nil {
		detail = rerr.Error()
	}
	keep(rep.Require("recovered_every_acknowledged_id_reconciled", rerr == nil, detail))
	for _, id := range v.members() {
		err := v.waitReady(id, 60*time.Second)
		detail = "ready"
		if err != nil {
			detail = err.Error()
		}
		keep(rep.Require(fmt.Sprintf("recovered_member_%d_ready", id), err == nil, detail))
	}
	members, live := slices.Clone(v.members()), slices.Clone(v.live())
	slices.Sort(members)
	slices.Sort(live)
	keep(rep.Require("recovered_no_member_down", slices.Equal(members, live), fmt.Sprintf("members %v, answering %v", members, live)))
	cursors, cerr := v.converged(120 * time.Second)
	detail = fmt.Sprintf("all %d members report the same control applied index", len(cursors))
	if cerr != nil {
		detail = cerr.Error()
	}
	for id, c := range cursors {
		rep.Cursor(fmt.Sprintf("recovered/control_applied_index/member_%d", id), c)
	}
	keep(rep.Require("recovered_applied_cursors_converged", cerr == nil, detail))
	events := rep.Timeline().Events()
	terr := VerifyTimeline(events, 2*len(victims))
	detail = fmt.Sprintf("%d events, %d failed attempts kept, state %s", len(events), FailedAttempts(events), rep.Timeline().State())
	if terr != nil {
		detail = terr.Error()
	}
	keep(rep.Require("recovered_outage_closed", terr == nil && rep.Timeline().State() == StateRecovered, detail))
	return first
}

// dcJourneysAfterRecovery runs `journeys` only after the recovery gate held; a gate that fails ends the scenario without it.
func dcJourneysAfterRecovery(v dcRecoveryView, rep *Report, retained map[string]string, victims []uint64, journeys func() error) error {
	if err := dcRecoveryGate(v, rep, retained, victims); err != nil {
		return err
	}
	return journeys()
}

// dcAckPeriodLabels are the labels the writers gave their batches in each period of the run: the streams of the two node losses
// (each starts before its member is killed and runs through the loss and the restore) and the writes next to the journeys.
var dcAckPeriodLabels = []string{"kill_initial_leader_member_1", "kill_member_3", "journeys_concurrent"}

// dcAckPeriods requires acknowledgements in every period of the run: one batch lost from any of them would be a period nobody
// can say anything about.
func dcAckPeriods(acks []Ack) error {
	count := map[string]int{}
	for _, a := range acks {
		count[a.Label]++
	}
	var missing []string
	for _, label := range dcAckPeriodLabels {
		if count[label] == 0 {
			missing = append(missing, label)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("no acknowledged batch in: %v", missing)
	}
	return nil
}

// ---- the concurrent writes ----

// dcConcurrentWrites is the drill's own write stream while the applications run: two writers, one batch each every half second,
// through whichever members answer.
type dcConcurrentWrites struct {
	w   *dcWriter
	rep *Report

	mu      sync.Mutex
	running bool
	before  int
}

func (s *dcConcurrentWrites) begin() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.before = len(s.w.Times())
	s.w.startStream(2, 500*time.Millisecond, 150, "journeys_concurrent")
	s.running = true
	return nil
}

func (s *dcConcurrentWrites) end() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running {
		return errors.New("no stream is running")
	}
	s.running = false
	err := s.w.stopStream()
	s.rep.Fact("journeys/concurrent_writes_acknowledged", len(s.w.Times())-s.before)
	return err
}

// abort ends the stream when the run ends while it is still going (a child that died mid-run).
func (s *dcConcurrentWrites) abort() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		s.running = false
		s.w.abortStream()
	}
}

// ---- the child process ----

// dcJourneysLimit bounds one run of the journeys.
const dcJourneysLimit = 40 * time.Minute

// dcRunJourneysChild runs `smoke journeys --cluster-attach` as a child of this process: its stdout/stdin are the control channel,
// its stderr (step names, versions, ids and the rows; never telemetry text) is kept in <artDir>/smoke.log. It returns the child's
// exit error (nil for exit status 0).
func dcRunJourneysChild(env *Env, attachPath, artDir string, owner *dcJourneyOwner) error {
	if err := os.MkdirAll(artDir, 0o700); err != nil {
		return err
	}
	logFile, err := os.OpenFile(filepath.Join(artDir, "smoke.log"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer logFile.Close()
	args := []string{"journeys", "--artifact-dir", artDir, "--root", env.Root, "--binary", env.Binary, "--cluster-attach", attachPath}
	args = append(args, env.SmokeArgs...)
	cmd := exec.Command(env.Smoke, args...)
	cmd.Dir = env.Root
	cmd.Env = os.Environ()
	cmd.Stderr = logFile
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err = cmd.Start(); err != nil {
		return err
	}
	timer := time.AfterFunc(dcJourneysLimit, func() { _ = cmd.Process.Kill() })
	defer timer.Stop()
	served := make(chan error, 1)
	go func() {
		err := dcServeJourneyControl(stdout, stdin, owner)
		_ = stdin.Close()
		served <- err
	}()
	// The control loop ends when the child closes its stdout (it exited); Wait must not run before it has drained the pipe.
	cerr := <-served
	werr := cmd.Wait()
	if werr != nil {
		return werr
	}
	return cerr
}

// ---- the scenario ----

const (
	dcJourneysOwnerEmail    = "owner@drills.invalid"
	dcJourneysOwnerPassword = "drills owner password 2026"
)

func runNodeLossJourneys(env *Env, rep *Report) error {
	if env.Smoke == "" {
		reason := "this host cannot run the journeys: pass --journeys-smoke (the tools/smoke binary) and the --journeys-arg flags it forwards to `smoke journeys` (--bun, --node-linux, --python, --chrome, --pg-local, ...)"
		rep.NotRun("journeys", reason)
		return errNotRun(reason)
	}
	if _, err := os.Stat(env.Smoke); err != nil {
		reason := "this host cannot run the journeys: --journeys-smoke names no readable file"
		rep.NotRun("journeys", reason)
		return errNotRun(reason)
	}
	tlsDir := filepath.Join(env.Work, "public-tls")
	if err := env.Approve([]string{tlsDir}, nil); err != nil {
		return err
	}
	public, err := dcNewPublicTLS(tlsDir)
	if err != nil {
		return err
	}
	c, err := newDCClusterWith(env, dcOptions{public: public})
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
	if err = rep.Require("cluster_bootstrapped_and_ready", true, "single installation bootstrapped, seed exported, three mTLS members ready"); err != nil {
		return err
	}
	if err = dcRecordCursors(c, rep, "baseline"); err != nil {
		return err
	}
	w := newDCWriter(c, rep.Ledger(), dcPoolSize)
	victims, err := dcKillRestartPhases(c, w, rep)
	if err != nil {
		return err
	}
	rep.Fact("node_loss/killed_and_restored_members", victims)
	retained, err := dcVerifyMembers(c, w, rep, "recovered", 120*time.Second)
	if err != nil {
		return err
	}
	writes := &dcConcurrentWrites{w: w, rep: rep}
	defer writes.abort()
	if err = dcJourneysAfterRecovery(c, rep, retained, victims, func() error { return dcJourneysOnRecovered(env, c, rep, public, victims, writes) }); err != nil {
		return err
	}

	// The whole run: every id acknowledged before the losses, during them and next to the journeys, on every member again.
	if err = dcRecordCursors(c, rep, "after_journeys"); err != nil {
		return err
	}
	acks := rep.Ledger().Acks()
	if err = dcCheckRetries(c, w, rep, "after_journeys", "after the journeys, including the member the journeys stopped and restored", acks[len(acks)/2].ID); err != nil {
		return err
	}
	final, err := dcVerifyMembers(c, w, rep, "after_journeys", 120*time.Second)
	if err != nil {
		return err
	}
	if err = rep.Reconcile(final); err != nil {
		return err
	}
	perr := dcAckPeriods(rep.Ledger().Acks())
	detail := fmt.Sprintf("%d acknowledged batches, every period of the run has some: before and during the two node losses and next to the journeys", rep.Ledger().Len())
	if perr != nil {
		detail = perr.Error()
	}
	if err = rep.Require("acks_written_before_during_and_next_to_the_journeys", perr == nil, detail); err != nil {
		return err
	}
	events := rep.Timeline().Events()
	terr := VerifyTimeline(events, 2*len(victims))
	detail = fmt.Sprintf("%d events, %d failed attempts kept, final state %s", len(events), FailedAttempts(events), rep.Timeline().State())
	if terr != nil {
		detail = terr.Error()
	}
	if err = rep.Require("outage_timeline_verifies", terr == nil && rep.Timeline().State() == StateRecovered, detail); err != nil {
		return err
	}
	attempts := map[string]int{}
	for _, a := range rep.Ledger().Attempts() {
		attempts[a.Outcome]++
	}
	rep.Fact("failed_attempts_by_outcome", attempts)
	rep.Fact("acknowledged_batches", rep.Ledger().Len())
	return nil
}

// dcJourneysOnRecovered runs the journeys against the recovered cluster and copies what they observed into the report.
func dcJourneysOnRecovered(env *Env, c *dcCluster, rep *Report, public *dcPublicTLS, victims []uint64, writes *dcConcurrentWrites) error {
	top := dcJourneyTopology{Live: map[uint64]bool{}, Victims: victims}
	for _, id := range c.members() {
		top.Members = append(top.Members, dcJourneyMember{ID: id, Address: c.public[id], DataDir: c.data[id], NodeConfig: filepath.Join(c.work, fmt.Sprintf("node-%d.json", id))})
	}
	for _, id := range c.live() {
		top.Live[id] = true
	}
	doc, err := dcJourneyAttachDocument(top, public, dcJourneysOwnerEmail, dcJourneysOwnerPassword, dcDefaultJourneyRoles)
	if err != nil {
		return rep.Require("journeys_attach_document", false, err.Error())
	}
	attachPath := filepath.Join(c.work, "journeys-attach.json")
	if err = os.WriteFile(attachPath, doc, 0o600); err != nil {
		return err
	}
	artDir := filepath.Join(env.ReportDir, env.Spec.Name+".journeys")
	rep.Fact("journeys/roles", dcDefaultJourneyRoles)
	owner := &dcJourneyOwner{host: c, wr: writes, scan: dcDefaultJourneyRoles.Scan, facts: rep.Fact}
	began := time.Now()
	runErr := dcRunJourneysChild(env, attachPath, artDir, owner)
	writes.abort()
	rep.Fact("journeys/elapsed_ms", time.Since(began).Milliseconds())
	var first error
	keep := func(err error) {
		if first == nil {
			first = err
		}
	}
	detail := "the smoke exited with status 0"
	if runErr != nil {
		detail = "the smoke failed: " + dcClip(runErr.Error(), 200)
	}
	keep(rep.Require("journeys_smoke_exit_zero", runErr == nil, detail))
	keep(rep.Require("journeys_scan_member_stopped_and_restored", owner.State() == dcOwnerScanRestored, fmt.Sprintf("the journeys left the owner in state %s", owner.State())))

	observed, oerr := os.ReadFile(filepath.Join(artDir, "observed.json"))
	rows, rerr := []dcJourneyRow(nil), oerr
	if oerr == nil {
		rows, rerr = dcJourneyRows(observed)
	}
	if rerr != nil {
		keep(rep.Require("journeys_observation_document", false, dcClip(rerr.Error(), 200)))
	} else {
		for _, ch := range dcJourneyRowChecks(rows) {
			keep(rep.Require(ch.name, ch.ok, ch.detail))
		}
		rep.Fact("journeys/rows", rows)
		var ids struct {
			Observation struct {
				DirectTrace string `json:"direct_trace"`
				UITrace     string `json:"ui_trace"`
				Expected    struct {
					WebBuild string `json:"web_build"`
					Job      string `json:"job"`
					Run      string `json:"run"`
				} `json:"expected"`
			} `json:"observation"`
		}
		if json.Unmarshal(observed, &ids) == nil {
			rep.Fact("journeys/admitted_ids", map[string]string{"direct_trace": ids.Observation.DirectTrace, "ui_trace": ids.Observation.UITrace, "web_build": ids.Observation.Expected.WebBuild, "job": ids.Observation.Expected.Job, "run": ids.Observation.Expected.Run})
		}
	}
	details, derr := os.ReadFile(filepath.Join(artDir, "details.json"))
	var flushes map[string]dcFlush
	if derr == nil {
		flushes, derr = dcJourneyFlushes(details)
	}
	if derr != nil {
		keep(rep.Require("journeys_sdk_flush_reports", false, dcClip(derr.Error(), 200)))
	} else {
		total, ferr := dcFlushVerdict(flushes)
		detail = fmt.Sprintf("%d clients ended with nothing pending and nothing lost; their final flushes report %d receipts from the cluster", len(flushes), total)
		if ferr != nil {
			detail = ferr.Error()
		}
		keep(rep.Require("journeys_sdk_delivery_acknowledged", ferr == nil, detail))
		rep.Fact("journeys/sdk_flush", flushes)
		var cluster struct {
			Cluster map[string]any `json:"cluster"`
		}
		if json.Unmarshal(details, &cluster) == nil && cluster.Cluster != nil {
			rep.Fact("journeys/cluster", cluster.Cluster)
		}
	}
	return first
}
