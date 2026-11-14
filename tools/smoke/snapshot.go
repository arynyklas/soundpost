// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"crypto/tls"
	"crypto/x509"
	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
	"github.com/arynyklas/soundpost/internal/smokecluster"
)

// The snapshot-repair smoke drives real server processes. Compaction, snapshot
// cutting and journal truncation run inside the nodes while the public HTTPS
// ingress keeps acknowledging and retrying receipts. Then a voter's disk is
// destroyed and replaced by a fresh learner that can only be repaired from a
// snapshot (the leaders' journals no longer hold the history), and a surviving
// voter is restarted from its truncated journal. Every ACKed receipt must stay
// byte-identical and every value must read back exactly.
//
// Registered by the parent as:
//
//	case "snapshot-repair": return RunSnapshotRepair(os.Args[2:])
//	case "snapshot-repair-child": return RunSnapshotRepairChild(os.Args[2:])
//
// Scope: local processes with separate private directories. It is not a
// physical-hardware or power-loss qualification.

type repairJournal struct {
	Group    model.ID `json:"group"`
	First    uint64   `json:"first,string"`
	Last     uint64   `json:"last,string"`
	Snapshot uint64   `json:"snapshot,string"`
}
type repairAnswer struct {
	clusterAnswer
	Journal []repairJournal `json:"journal,omitempty"`
}

func RunSnapshotRepairChild(args []string) (result error) {
	stage := "repair_child_flags"
	defer func() {
		if result != nil {
			recordChildFailure(stage, result)
			_ = json.NewEncoder(os.Stdout).Encode(childAddress{Failure: &childStartupFailure{Stage: stage, Code: clusterChildFailureCode(result)}})
		}
	}()
	f := flag.NewFlagSet("snapshot-repair-child", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	dir := f.String("data-dir", "", "")
	configuration := f.String("cluster-config", "", "")
	if err := f.Parse(args); err != nil {
		return err
	}
	raw, err := os.ReadFile(*configuration)
	if err != nil {
		return err
	}
	var config appcore.NodeConfig
	if model.StrictJSON(raw, &config) != nil {
		return model.Fail(model.Invalid)
	}
	stage = "repair_child_open"
	app, err := appcore.OpenDistributed(*dir, config)
	if err != nil {
		return err
	}
	defer app.Close()
	server := httptest.NewTLSServer(httpapi.NewServer("", app.Auth, nil, app.Register).Handler)
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go app.RunFences(ctx)
	stage = "repair_child_ready"
	if err = json.NewEncoder(os.Stdout).Encode(childAddress{URL: server.URL, Certificate: base64.RawStdEncoding.EncodeToString(server.Certificate().Raw)}); err != nil {
		return err
	}
	decoder := json.NewDecoder(os.Stdin)
	encoder := json.NewEncoder(os.Stdout)
	for {
		var command clusterCommand
		if err = decoder.Decode(&command); err == io.EOF {
			return nil
		} else if err != nil {
			return err
		}
		answer := repairAnswer{clusterAnswer: clusterAnswer{OK: true}}
		operation, stop := context.WithTimeout(ctx, 60*time.Second)
		switch command.Kind {
		case "repair_cycle":
			err = repairCycle(operation, app)
		case "repair_journal":
			answer.Journal = repairJournals(app)
			err = nil
		default:
			err = runClusterCommand(operation, app, command, &answer.clusterAnswer)
		}
		stop()
		if err != nil {
			answer = repairAnswer{clusterAnswer: clusterFailureAnswer(err)}
		}
		if err = encoder.Encode(answer); err != nil {
			return err
		}
	}
}

// repairCycle is one full maintenance round: flush hot pages, rewrite segments,
// cut a verified snapshot of every group and truncate each journal to it.
func repairCycle(ctx context.Context, app *appcore.App) error {
	if err := app.Storage.Flush(ctx); err != nil {
		return annotateSmokeFailure("snapshot_repair_child", "repair_flush", model.ID{}, err)
	}
	if err := app.Storage.Compact(ctx); err != nil {
		return annotateSmokeFailure("snapshot_repair_child", "repair_compact", model.ID{}, err)
	}
	if _, err := app.Storage.CreateSnapshots(ctx); err != nil {
		return annotateSmokeFailure("snapshot_repair_child", "repair_snapshot", model.ID{}, err)
	}
	if err := app.Storage.CompactJournals(ctx); err != nil {
		return annotateSmokeFailure("snapshot_repair_child", "repair_truncate", model.ID{}, err)
	}
	return nil
}

func repairJournals(app *appcore.App) []repairJournal {
	var out []repairJournal
	for _, group := range app.Storage.ReplicaGroups() {
		first, last := group.JournalRange()
		entry := repairJournal{Group: group.Status().Group, First: first, Last: last}
		if current, ok := group.Snapshots().Current(); ok {
			entry.Snapshot = current.Manifest.Index
		}
		out = append(out, entry)
	}
	return out
}

type repairProcess struct {
	*clusterProcess
}

func launchRepairProcess(dir, configuration string) (*repairProcess, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	command := exec.Command(exe, "snapshot-repair-child", "--data-dir", dir, "--cluster-config", configuration)
	stdout, err := command.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stdin, err := command.StdinPipe()
	if err != nil {
		return nil, err
	}
	command.Stderr = io.Discard
	release := keepChildStderr(command, dir)
	err = command.Start()
	release()
	if err != nil {
		return nil, err
	}
	process := &clusterProcess{child: &smokeChild{cmd: command}, input: stdin, output: bufio.NewReader(stdout), startup: make(chan error, 1)}
	go func() {
		line, err := process.output.ReadBytes('\n')
		if err != nil {
			process.startup <- err
			return
		}
		var address childAddress
		if json.Unmarshal(line, &address) != nil {
			process.startup <- errors.New("invalid child startup")
			return
		}
		if address.Failure != nil {
			process.startup <- &smokeFailure{Stage: address.Failure.Stage, Code: address.Failure.Code}
			return
		}
		der, err := base64.RawStdEncoding.DecodeString(address.Certificate)
		if err != nil {
			process.startup <- err
			return
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			process.startup <- err
			return
		}
		roots := x509.NewCertPool()
		roots.AddCert(cert)
		jar, _ := cookiejar.New(nil)
		process.child.address = address
		process.child.client = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}}, Jar: jar, Timeout: 15 * time.Second}
		process.startup <- nil
	}()
	return &repairProcess{process}, nil
}

func (p *repairProcess) journals() ([]repairJournal, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.broken {
		return nil, errors.New("child control unavailable")
	}
	if err := json.NewEncoder(p.input).Encode(clusterCommand{Kind: "repair_journal"}); err != nil {
		return nil, err
	}
	line, err := p.output.ReadBytes('\n')
	if err != nil {
		return nil, err
	}
	var answer repairAnswer
	if json.Unmarshal(line, &answer) != nil || !answer.OK {
		return nil, errors.New("journal status unavailable")
	}
	return answer.Journal, nil
}

func (p *repairProcess) cycle() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.broken {
		return errors.New("child control unavailable")
	}
	if err := json.NewEncoder(p.input).Encode(clusterCommand{Kind: "repair_cycle"}); err != nil {
		return err
	}
	line, err := p.output.ReadBytes('\n')
	if err != nil {
		return err
	}
	var answer repairAnswer
	if json.Unmarshal(line, &answer) != nil {
		return errors.New("invalid child answer")
	}
	if !answer.OK {
		return quorumAnswerFailure(answer.clusterAnswer)
	}
	return nil
}

type snapshotRepairEvidence struct {
	Version                     uint16   `json:"version"`
	Scope                       string   `json:"scope"`
	AcknowledgedBeforeRepair    int      `json:"acknowledged_before_repair"`
	AcknowledgedDuringCycles    int      `json:"acknowledged_during_cycles"`
	RetriedDuringCompaction     int      `json:"receipt_retries_during_compaction"`
	MaintenanceCycles           int      `json:"maintenance_cycles"`
	TruncatedGroupsPerNode      []int    `json:"truncated_groups_per_node"`
	ReplacementRepairedFromSnap bool     `json:"replacement_repaired_from_snapshot"`
	ReplacementFirstJournal     uint64   `json:"replacement_first_journal_index,string"`
	RestartedFromTruncated      bool     `json:"restart_from_truncated_journal"`
	VerifiedCopies              uint32   `json:"verified_copies"`
	Acknowledged                int      `json:"acknowledged_total"`
	DistinctHardwareQualified   bool     `json:"distinct_physical_hardware_qualified"`
	Missing                     string   `json:"missing_qualification"`
	Receipts                    []string `json:"receipt_batch_ids"`
}

// retryLoad keeps writing and retrying while maintenance runs: every retry of
// an ACKed batch must return the original receipt byte for byte.
type retryLoad struct {
	mu       sync.Mutex
	process  *clusterProcess
	fixture  clusterFixture
	batches  []model.Batch
	values   []clusterExpected
	retries  int
	sequence int
	err      error
	stop     chan struct{}
	done     chan struct{}
}

func (l *retryLoad) run() {
	defer close(l.done)
	for {
		select {
		case <-l.stop:
			return
		default:
		}
		l.mu.Lock()
		count := len(l.values)
		l.mu.Unlock()
		for i := range count {
			select {
			case <-l.stop:
				return
			default:
			}
			l.mu.Lock()
			batch, want := l.batches[i], l.values[i]
			l.mu.Unlock()
			status, raw, err := l.process.child.call("/ingest/v1/batches", batch, "", l.fixture.credential)
			if err != nil || status == 503 {
				time.Sleep(20 * time.Millisecond) // a transient unavailable is a retry, never an ACK
				continue
			}
			if status != 200 {
				l.fail(&smokeFailure{Stage: "repair_retry_during_compaction", Code: "status", Actual: status, Expected: 200})
				return
			}
			var got model.Receipt
			if json.Unmarshal(raw, &got) != nil {
				l.fail(errors.New("receipt decode"))
				return
			}
			left, _ := json.Marshal(got)
			right, _ := json.Marshal(want.Receipt)
			if string(left) != string(right) {
				l.fail(&smokeFailure{Stage: "repair_retry_during_compaction", Code: "receipt_changed"})
				return
			}
			l.mu.Lock()
			l.retries++
			l.mu.Unlock()
		}
		l.mu.Lock()
		sequence := 1000 + l.sequence
		l.sequence++
		l.mu.Unlock()
		batch := nextClusterBatch(l.fixture, sequence)
		value, err := appendClusterBatch(l.process, l.fixture, batch)
		if err != nil {
			l.fail(err)
			return
		}
		l.mu.Lock()
		l.batches = append(l.batches, batch)
		l.values = append(l.values, value)
		l.mu.Unlock()
	}
}
func (l *retryLoad) fail(err error) { l.mu.Lock(); l.err = err; l.mu.Unlock() }

func truncatedGroups(journals []repairJournal) int {
	count := 0
	for _, j := range journals {
		if j.First > 2 && j.Snapshot > 0 && j.First == j.Snapshot+1 {
			count++
		}
	}
	return count
}

func runSnapshotRepairScenario(root string) (evidence snapshotRepairEvidence, result error) {
	stage := "repair_fixture"
	defer func() {
		recordParentFailure(stage, result)
		result = annotateSmokeFailure("snapshot_repair", stage, model.ID{}, result)
	}()
	evidence = snapshotRepairEvidence{Version: 1, Scope: "local_process_snapshot_repair_and_journal_truncation", DistinctHardwareQualified: false, Missing: "three_distinct_physical_nodes_and_disks_and_power_loss_evidence_not_available"}
	fixture, err := provisionClusterSeed(root)
	if err != nil {
		return evidence, err
	}
	ca, pairs, err := smokecluster.Certificates(root)
	if err != nil {
		return evidence, err
	}
	relays, err := smokecluster.NewRelays(1, 2, 3, 4)
	if err != nil {
		return evidence, err
	}
	defer relays.Close()
	targets := map[uint64]string{}
	if err = smokecluster.AssignPeers(relays, targets, 1, 2, 3); err != nil {
		return evidence, err
	}
	members := replica.Members{Revision: 1}
	for node := uint64(1); node <= 3; node++ {
		members.Nodes = append(members.Nodes, replica.Member{ID: node, Address: "https://" + relays.Address(node), NodeIdentity: fmt.Sprintf("node-%d", node), FailureDomain: fmt.Sprintf("local-process-directory-%d", node)})
	}
	processes := map[uint64]*clusterProcess{}
	var all []*repairProcess
	defer func() {
		for _, process := range all {
			process.child.kill()
		}
	}()
	defer func() {
		if result != nil {
			recordClusterState(stage, processes)
		}
	}()
	configFor := func(node uint64, m replica.Members) (string, error) {
		config := appcore.NodeConfig{NodeID: node, PeerListen: targets[node], PeerSourceIP: fmt.Sprintf("127.0.0.%d", node+10), Certificate: pairs[node][0], PrivateKey: pairs[node][1], CA: ca, Seed: fixture.seed, Members: m, InitialLeader: 1}
		raw, err := json.Marshal(config)
		if err != nil {
			return "", err
		}
		path := filepath.Join(root, fmt.Sprintf("repair-node-%d.json", node))
		return path, os.WriteFile(path, raw, 0600)
	}
	launch := func(node uint64, m replica.Members) (*repairProcess, error) {
		config, err := configFor(node, m)
		if err != nil {
			return nil, err
		}
		process, err := launchRepairProcess(filepath.Join(root, fmt.Sprintf("node-%d", node)), config)
		if err != nil {
			return nil, err
		}
		all = append(all, process)
		// launch deliberately does not register the process for control commands:
		// a child still opening answers nothing, and a command waiting on it would
		// also race its startup read on the same stdout. Callers register it once
		// it is ready.
		return process, nil
	}
	stage = "repair_launch_three_processes"
	repair := map[uint64]*repairProcess{}
	for node := uint64(1); node <= 3; node++ {
		if repair[node], err = launch(node, members); err != nil {
			return evidence, err
		}
	}
	for node, process := range repair {
		if err = process.ready(); err != nil {
			return evidence, err
		}
		processes[node] = process.clusterProcess
	}
	statuses, err := processes[1].statuses()
	if err != nil || len(statuses) != 65 {
		return evidence, errors.New("missing installed groups")
	}
	controlGroup := statuses[0].Group
	dataGroup := statuses[int(fixture.batch.RouteSlot)+1].Group
	stage = "repair_leadership"
	if err = transferClusterLeader(processes, controlGroup, 1); err != nil {
		return evidence, err
	}
	if err = transferClusterLeader(processes, dataGroup, 1); err != nil {
		return evidence, err
	}
	stage = "repair_initial_acknowledgements"
	load := &retryLoad{process: processes[1], fixture: fixture, stop: make(chan struct{}), done: make(chan struct{})}
	for i := range 12 {
		batch := nextClusterBatch(fixture, i)
		value, err := appendClusterBatch(processes[1], fixture, batch)
		if err != nil {
			return evidence, err
		}
		load.batches = append(load.batches, batch)
		load.values = append(load.values, value)
	}
	evidence.AcknowledgedBeforeRepair = len(load.values)
	stage = "repair_compaction_with_live_retries"
	go load.run()
	for range 3 {
		for node := uint64(1); node <= 3; node++ {
			if err = repair[node].cycle(); err != nil {
				close(load.stop)
				<-load.done
				return evidence, err
			}
			evidence.MaintenanceCycles++
		}
	}
	close(load.stop)
	<-load.done
	if load.err != nil {
		return evidence, load.err
	}
	if load.retries == 0 {
		return evidence, &smokeFailure{Stage: "repair_retry_during_compaction", Code: "no_retry_observed"}
	}
	evidence.RetriedDuringCompaction = load.retries
	evidence.AcknowledgedDuringCycles = len(load.values) - evidence.AcknowledgedBeforeRepair
	values, batches := append([]clusterExpected(nil), load.values...), append([]model.Batch(nil), load.batches...)
	stage = "repair_journals_truncated"
	for node := uint64(1); node <= 3; node++ {
		journals, err := repair[node].journals()
		if err != nil {
			return evidence, err
		}
		truncated := truncatedGroups(journals)
		if truncated == 0 {
			return evidence, &smokeFailure{Stage: stage, Code: "journal_not_truncated"}
		}
		evidence.TruncatedGroupsPerNode = append(evidence.TruncatedGroupsPerNode, truncated)
	}
	stage = "repair_verify_before_replacement"
	for _, process := range processes {
		if err = verifyClusterValues(process, fixture, values); err != nil {
			return evidence, err
		}
	}
	stage = "repair_destroy_voter_disk"
	relays.Partition(3, true)
	if err = processes[3].child.kill(); err != nil {
		return evidence, err
	}
	if err = os.Rename(filepath.Join(root, "node-3"), filepath.Join(root, "unavailable-disk-3")); err != nil {
		return evidence, err
	}
	delete(processes, 3)
	delete(repair, 3)
	batch := nextClusterBatch(fixture, 5000)
	value, err := appendClusterBatch(processes[1], fixture, batch)
	if err != nil {
		return evidence, err
	}
	values, batches = append(values, value), append(batches, batch)
	// The running voters add the learner to all 65 groups first. A starting node
	// waits for every group to answer within its fixed startup budget, so that
	// budget must not also cover the sequential membership changes it depends on.
	stage = "repair_add_learner"
	learnerMembers := members
	learnerMembers.Revision = 2
	learnerMembers.Nodes = append(append([]replica.Member(nil), members.Nodes...), replica.Member{ID: 4, Address: "https://" + relays.Address(4), NodeIdentity: "node-4", FailureDomain: "local-process-directory-4", Learner: true})
	if err = changeClusterMembership(processes, statuses, learnerMembers); err != nil {
		return evidence, err
	}
	stage = "repair_fresh_learner_from_snapshot"
	if err = smokecluster.AssignPeers(relays, targets, 4); err != nil {
		return evidence, err
	}
	replacement, err := launch(4, learnerMembers)
	if err != nil {
		return evidence, err
	}
	if err = replacement.ready(); err != nil {
		return evidence, err
	}
	repair[4], processes[4] = replacement, replacement.clusterProcess
	if err = verifyClusterValues(replacement.clusterProcess, fixture, values); err != nil {
		return evidence, err
	}
	journals, err := replacement.journals()
	if err != nil {
		return evidence, err
	}
	for _, j := range journals {
		if j.Group == dataGroup {
			// The fresh disk cannot hold the history below the leaders' snapshot cut: it
			// was repaired from a snapshot, not replayed from index 1.
			if j.First <= 2 {
				return evidence, &smokeFailure{Stage: stage, Code: "replacement_replayed_full_history"}
			}
			evidence.ReplacementFirstJournal = j.First
		}
	}
	evidence.ReplacementRepairedFromSnap = true
	stage = "repair_promote_replacement"
	finalMembers := replica.Members{Revision: 3}
	for _, member := range learnerMembers.Nodes {
		if member.ID == 3 {
			continue
		}
		member.Learner = false
		finalMembers.Nodes = append(finalMembers.Nodes, member)
	}
	if err = changeClusterMembership(processes, statuses, finalMembers); err != nil {
		return evidence, err
	}
	stage = "repair_receipts_after_replacement"
	for _, process := range processes {
		if err = retryAll(process, fixture, batches, values); err != nil {
			return evidence, err
		}
	}
	batch = nextClusterBatch(fixture, 5001)
	value, err = appendClusterBatch(replacement.clusterProcess, fixture, batch)
	if err != nil {
		return evidence, err
	}
	values, batches = append(values, value), append(batches, batch)
	stage = "repair_restart_from_truncated_journal"
	if err = processes[1].child.kill(); err != nil {
		return evidence, err
	}
	delete(processes, 1)
	delete(repair, 1)
	if err = smokecluster.AssignPeers(relays, targets, 1); err != nil {
		return evidence, err
	}
	restarted, err := launch(1, finalMembers)
	if err != nil {
		return evidence, err
	}
	if err = restarted.ready(); err != nil {
		return evidence, err
	}
	repair[1], processes[1] = restarted, restarted.clusterProcess
	journals, err = restarted.journals()
	if err != nil {
		return evidence, err
	}
	if truncatedGroups(journals) == 0 {
		return evidence, &smokeFailure{Stage: stage, Code: "restart_journal_not_truncated"}
	}
	evidence.RestartedFromTruncated = true
	stage = "repair_reconcile_every_ack_and_exact_value"
	for _, process := range processes {
		if err = verifyClusterValues(process, fixture, values); err != nil {
			return evidence, err
		}
		if err = retryAll(process, fixture, batches, values); err != nil {
			return evidence, err
		}
		evidence.VerifiedCopies++
	}
	evidence.Acknowledged = len(values)
	for _, v := range values {
		evidence.Receipts = append(evidence.Receipts, v.Receipt.BatchID.String())
	}
	return evidence, nil
}

// retryAll re-submits every acknowledged batch through a node's public ingress.
func retryAll(process *clusterProcess, fixture clusterFixture, batches []model.Batch, values []clusterExpected) error {
	for i, batch := range batches {
		var status int
		var raw []byte
		var err error
		deadline := time.Now().Add(25 * time.Second)
		for time.Now().Before(deadline) {
			status, raw, err = process.child.call("/ingest/v1/batches", batch, "", fixture.credential)
			if err == nil && status != 503 {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		if err = requireSmokeResponse("repair_retry_receipt", status, 200, raw, err); err != nil {
			return err
		}
		var got model.Receipt
		if json.Unmarshal(raw, &got) != nil {
			return errors.New("receipt decode")
		}
		left, _ := json.Marshal(got)
		right, _ := json.Marshal(values[i].Receipt)
		if string(left) != string(right) {
			return &smokeFailure{Stage: "repair_retry_receipt", Code: "receipt_changed"}
		}
	}
	return nil
}

// RunSnapshotRepair is the `snapshot-repair` subcommand.
func RunSnapshotRepair(args []string) (result error) {
	stage := "repair_flags"
	defer func() { result = annotateSmokeFailure("snapshot_repair", stage, model.ID{}, result) }()
	f := flag.NewFlagSet("snapshot-repair", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	artifact := f.String("artifact-dir", "", "sanitized evidence directory")
	if err := f.Parse(args); err != nil {
		return err
	}
	if *artifact == "" {
		return model.Fail(model.Invalid)
	}
	if err := os.MkdirAll(*artifact, 0700); err != nil {
		return err
	}
	if err := enableClusterDiagnostics(*artifact); err != nil {
		return err
	}
	root, err := os.MkdirTemp("", "soundpost-snapshot-repair-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(root)
	stage = "repair_scenario"
	evidence, err := runSnapshotRepairScenario(root)
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		return err
	}
	stage = "repair_evidence_write"
	return os.WriteFile(filepath.Join(*artifact, "snapshot-repair.json"), raw, 0600)
}
