// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
	"github.com/arynyklas/soundpost/internal/smokecluster"
	"github.com/arynyklas/soundpost/internal/storage"
)

// Every control-pipe operation is confined to these synthetic child processes.
// Native writes use the actual public HTTPS ingress and actual source key. Value
// verification obtains an actual authenticated read scope, never a forged Scope.
type clusterExpected struct {
	Record  model.ID       `json:"record"`
	Receipt model.Receipt  `json:"receipt"`
	At      model.UnixNano `json:"at"`
	Count   model.Uint64   `json:"count"`
}
type clusterCommand struct {
	Kind     string              `json:"kind"`
	Group    *model.ID           `json:"group,omitempty"`
	To       model.Uint64        `json:"to"`
	Members  *replica.Members    `json:"members,omitempty"`
	Expected model.Revision      `json:"expected"`
	Fence    *replica.FenceToken `json:"fence,omitempty"`
	Token    string              `json:"token,omitempty"`
	Org      *model.ID           `json:"org,omitempty"`
	Project  *model.ID           `json:"project,omitempty"`
	Values   []clusterExpected   `json:"values,omitempty"`
}
type clusterAnswer struct {
	OK       bool                `json:"ok"`
	Code     string              `json:"code,omitempty"`
	Stage    string              `json:"stage,omitempty"`
	Status   []replica.Status    `json:"status,omitempty"`
	Fence    *replica.FenceToken `json:"fence,omitempty"`
	Verified uint32              `json:"verified,omitempty"`
}

func runQuorumChild(args []string) (result error) {
	stage := "cluster_child_flags"
	defer func() {
		if result != nil {
			recordChildFailure(stage, result)
			_ = json.NewEncoder(os.Stdout).Encode(childAddress{Failure: &childStartupFailure{Stage: stage, Code: clusterChildFailureCode(result)}})
		}
	}()
	f := flag.NewFlagSet("quorum-child", flag.ContinueOnError)
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
	stage = "cluster_child_open"
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
	stage = "cluster_child_ready"
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
		answer := clusterAnswer{OK: true}
		operation, stop := context.WithTimeout(ctx, 20*time.Second)
		err = runClusterCommand(operation, app, command, &answer)
		stop()
		if err != nil {
			answer = clusterFailureAnswer(err)
		}
		if err = encoder.Encode(answer); err != nil {
			return err
		}
	}
}
func runClusterCommand(ctx context.Context, app *appcore.App, c clusterCommand, out *clusterAnswer) error {
	if c.Kind == "status" {
		out.Status = app.ReplicationStatus()
		return nil
	}
	if c.Kind == "verify" {
		return verifyQuorumCommand(ctx, app, c, out)
	}
	if c.Group == nil {
		return model.Fail(model.Invalid)
	}
	group, err := app.ReplicaNode().Group(*c.Group)
	if err != nil {
		return err
	}
	switch c.Kind {
	case "transfer":
		return group.TransferLeadership(ctx, uint64(c.To))
	case "members":
		if c.Members == nil {
			return model.Fail(model.Invalid)
		}
		return group.ChangeMembers(ctx, c.Expected, *c.Members)
	case "fence":
		fence, err := group.Fence(ctx)
		if err == nil {
			out.Fence = &fence
		}
		return err
	case "check_fence":
		if c.Fence == nil {
			return model.Fail(model.Invalid)
		}
		return group.ValidateFence(ctx, *c.Fence)
	default:
		return model.Fail(model.Invalid)
	}
}

type clusterProcess struct {
	child   *smokeChild
	input   io.WriteCloser
	output  *bufio.Reader
	mu      sync.Mutex
	broken  bool
	startup chan error
}

func launchClusterProcess(dir, configuration string) (*clusterProcess, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	command := exec.Command(exe, "quorum-child", "--data-dir", dir, "--cluster-config", configuration)
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
	return process, nil
}
func (p *clusterProcess) ready() error {
	select {
	case err := <-p.startup:
		return err
	case <-time.After(90 * time.Second):
		dumpChildStacks(p.child.cmd)
		return errors.New("cluster startup deadline")
	}
}
func (p *clusterProcess) command(c clusterCommand) (clusterAnswer, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.broken {
		return clusterAnswer{}, errors.New("child control unavailable")
	}
	if err := json.NewEncoder(p.input).Encode(c); err != nil {
		return clusterAnswer{}, err
	}
	type readResult struct {
		raw []byte
		err error
	}
	done := make(chan readResult, 1)
	go func() { raw, err := p.output.ReadBytes('\n'); done <- readResult{raw: raw, err: err} }()
	select {
	case read := <-done:
		if read.err != nil {
			return clusterAnswer{}, read.err
		}
		var answer clusterAnswer
		if json.Unmarshal(read.raw, &answer) != nil {
			return clusterAnswer{}, errors.New("invalid child answer")
		}
		return answer, nil
	case <-time.After(30 * time.Second):
		p.broken = true
		return clusterAnswer{}, errors.New("child command deadline")
	}
}

// clusterChildFailureCode names a refused peer port precisely: the generic
// classification reports every network error as "transport".
func clusterChildFailureCode(err error) string {
	if errors.Is(err, syscall.EADDRINUSE) {
		return "address_in_use"
	}
	return classifySmokeError(err)
}

type clusterFixture struct {
	org, project        model.ID
	credential, session string
	batch               model.Batch
	seed                string
}

func provisionClusterSeed(dir string) (clusterFixture, error) {
	var fixture clusterFixture
	app, err := appcore.Open(filepath.Join(dir, "seed-installation"))
	if err != nil {
		return fixture, err
	}
	defer app.Close()
	server := httptest.NewTLSServer(httpapi.NewServer("", app.Auth, nil, app.Register).Handler)
	defer server.Close()
	client := server.Client()
	client.Jar, _ = cookiejar.New(nil)
	child := &smokeChild{client: client, address: childAddress{URL: server.URL}}
	token, err := app.Control.BootstrapToken()
	if err != nil {
		return fixture, err
	}
	status, raw, err := child.call("/api/v1/bootstrap", map[string]string{"Token": token, "Email": "quorum@example.test", "Password": "private quorum fixture 2026"}, "", "")
	if err = requireSmokeResponse("quorum_bootstrap", status, 200, raw, err); err != nil {
		return fixture, err
	}
	var session auth.Session
	if json.Unmarshal(raw, &session) != nil {
		return fixture, errors.New("bootstrap session decode")
	}
	fixture.org = model.NewID()
	fixture.project = model.NewID()
	admin := func(kind string, payload map[string]any) error {
		status, raw, err := child.organizationsRead(session.CSRF)
		if err = requireSmokeResponse("quorum_revision", status, 200, raw, err); err != nil {
			return err
		}
		var view auth.AdminView
		if json.Unmarshal(raw, &view) != nil {
			return errors.New("admin revision decode")
		}
		payload["reason"] = "generic local process quorum drill"
		encoded, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		status, raw, err = child.call("/api/v1/admin/commands", auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: view.Revision, OrgID: fixture.org, Kind: kind, Payload: encoded}, session.CSRF, "")
		return requireSmokeResponse("quorum_admin", status, 200, raw, err)
	}
	if err = admin("create_org", map[string]any{"name": "generic"}); err != nil {
		return fixture, err
	}
	if err = admin("create_project", map[string]any{"id": fixture.project, "name": "generic"}); err != nil {
		return fixture, err
	}
	if err = admin("membership", map[string]any{"user_id": session.User, "enabled": true}); err != nil {
		return fixture, err
	}
	if err = admin("grant", map[string]any{"user_id": session.User, "project_id": fixture.project, "permissions": []string{string(auth.Read)}, "enabled": true}); err != nil {
		return fixture, err
	}
	source, service, environment, build := model.NewID(), model.NewID(), model.NewID(), model.NewID()
	policy := model.SourcePolicy{Revision: 1, Enabled: true, Class: "structured", Kinds: []model.Kind{model.Metric}, Resources: model.ResourceRegistry{Services: []model.ID{service}, Environments: []model.ID{environment}, Builds: []model.ID{build}, Instances: []string{"instance"}}, RetentionDays: map[model.Kind]uint32{model.Metric: 30}, MaxBytes: 1 << 30, MaxSeries: 1000}
	status, raw, err = child.call("/api/v1/sources", auth.SourceOnboarding{CommandID: model.NewID(), Org: fixture.org, Project: fixture.project, Source: source, Expires: model.UnixNano(time.Now().Add(time.Hour).UnixNano()), Policy: policy, Reason: "generic local process quorum drill"}, session.CSRF, "")
	if err = requireSmokeResponse("quorum_source", status, 200, raw, err); err != nil {
		return fixture, err
	}
	var issued auth.SourceOnboarded
	if json.Unmarshal(raw, &issued) != nil {
		return fixture, errors.New("source descriptor decode")
	}
	fixture.credential = issued.Credential
	parsed, _ := url.Parse(server.URL)
	for _, cookie := range client.Jar.Cookies(parsed) {
		if cookie.Name == "__Host-soundpost" {
			fixture.session = cookie.Value
		}
	}
	if fixture.session == "" {
		return fixture, errors.New("actual session cookie missing")
	}
	fixture.batch = model.Batch{Version: 1, Project: fixture.project, Source: source, Producer: model.NewID(), ID: model.NewID(), PolicyRevision: 1, Records: []model.Record{{ID: model.NewID(), Kind: model.Metric, ObservedAt: 9007199254740993, Resource: model.Resource{Service: service, Environment: environment, Build: build, Instance: "instance", Labels: model.Labels{}}, Payload: model.Payload{Metric: &model.MetricPoint{Name: "quorum_request_count", Labels: model.Labels{}, SampleKind: "integer_histogram", Unit: "1", Type: "histogram", Histogram: &model.NativeHistogram{Integer: &model.IntegerHistogram{Flavor: "counter", Schema: 0, Count: 9007199254740993, ZeroCount: 9007199254740993, ResetHint: "unknown"}}}}}}}
	fixture.batch.RouteSlot, err = model.OwnerSlot(fixture.org, fixture.project, source, fixture.batch.Producer, fixture.batch.Records[0])
	if err != nil {
		return fixture, err
	}
	fixture.seed = filepath.Join(dir, "cluster.seed")
	err = writeAuthorizedClusterSeed(app, fixture)
	return fixture, err
}
func (p *clusterProcess) statuses() ([]replica.Status, error) {
	answer, err := p.command(clusterCommand{Kind: "status"})
	if err != nil {
		return nil, err
	}
	if !answer.OK {
		return nil, errors.New("status unavailable")
	}
	return answer.Status, nil
}
func findClusterLeader(processes map[uint64]*clusterProcess, id model.ID) (uint64, replica.Status, error) {
	for node, process := range processes {
		statuses, err := process.statuses()
		if err != nil {
			continue
		}
		for _, status := range statuses {
			if status.Group == id && !status.Failed && status.Leader == node {
				return node, status, nil
			}
		}
	}
	return 0, replica.Status{}, errors.New("current leader unavailable")
}
func waitClusterLeader(processes map[uint64]*clusterProcess, id model.ID) (uint64, replica.Status, error) {
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		node, status, err := findClusterLeader(processes, id)
		if err == nil {
			return node, status, nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return 0, replica.Status{}, errors.New("leader election deadline")
}
func transferClusterLeader(processes map[uint64]*clusterProcess, id model.ID, to uint64) error {
	leader, _, err := waitClusterLeader(processes, id)
	if err != nil {
		return err
	}
	if leader == to {
		return nil
	}
	answer, err := processes[leader].command(clusterCommand{Kind: "transfer", Group: &id, To: model.Uint64(to)})
	if err != nil {
		return err
	}
	if !answer.OK {
		return errors.New("leadership transfer refused")
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		leader, _, err = findClusterLeader(processes, id)
		if err == nil && leader == to {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return errors.New("leadership transfer deadline")
}
func appendClusterBatch(process *clusterProcess, fixture clusterFixture, batch model.Batch) (clusterExpected, error) {
	deadline := time.Now().Add(25 * time.Second)
	for time.Now().Before(deadline) {
		status, raw, err := process.child.call("/ingest/v1/batches", batch, "", fixture.credential)
		if err == nil && status == 200 {
			var receipt model.Receipt
			if json.Unmarshal(raw, &receipt) != nil {
				return clusterExpected{}, errors.New("receipt decode")
			}
			return clusterExpected{Record: batch.Records[0].ID, Receipt: receipt, At: batch.Records[0].ObservedAt, Count: 9007199254740993}, nil
		}
		if err == nil && status != 503 {
			return clusterExpected{}, &smokeFailure{Stage: "quorum_append", Code: "status", Actual: status, Expected: 200}
		}
		time.Sleep(50 * time.Millisecond)
	}
	return clusterExpected{}, errors.New("majority append deadline")
}
func nextClusterBatch(fixture clusterFixture, sequence int) model.Batch {
	batch := fixture.batch
	batch.ID = model.NewID()
	batch.Records = append([]model.Record(nil), fixture.batch.Records...)
	batch.Records[0].ID = model.NewID()
	batch.Records[0].ObservedAt = 9007199254740993 + model.UnixNano(sequence)
	return batch
}
func verifyClusterValues(process *clusterProcess, fixture clusterFixture, values []clusterExpected) error {
	answer, err := process.command(clusterCommand{Kind: "verify", Token: fixture.session, Org: &fixture.org, Project: &fixture.project, Values: values})
	if err != nil {
		return err
	}
	if !answer.OK || answer.Verified != uint32(len(values)) {
		return quorumAnswerFailure(answer)
	}
	for _, value := range values {
		status, raw, err := process.child.call("/ingest/v1/receipts", model.ReceiptRequest{Source: fixture.batch.Source, Producer: fixture.batch.Producer, RouteSlot: fixture.batch.RouteSlot, BatchID: value.Receipt.BatchID, OriginalHash: value.Receipt.Hash}, "", fixture.credential)
		if err = requireSmokeResponse("quorum_original_receipt", status, 200, raw, err); err != nil {
			return err
		}
		var got model.Receipt
		if json.Unmarshal(raw, &got) != nil {
			return errors.New("historical receipt decode")
		}
		got.Historical = false
		left, _ := json.Marshal(got)
		right, _ := json.Marshal(value.Receipt)
		if string(left) != string(right) {
			return errors.New("original receipt changed across placement")
		}
	}
	return nil
}
func changeClusterMembership(processes map[uint64]*clusterProcess, groups []replica.Status, next replica.Members) error {
	for _, entry := range groups {
		deadline := time.Now().Add(25 * time.Second)
		completed := false
		for time.Now().Before(deadline) {
			node, status, err := waitClusterLeader(processes, entry.Group)
			if err != nil {
				return err
			}
			if status.Revision > next.Revision {
				return errors.New("unexpected membership revision")
			}
			answer, err := processes[node].command(clusterCommand{Kind: "members", Group: &entry.Group, Expected: next.Revision - 1, Members: &next})
			if err != nil {
				return err
			}
			if answer.OK {
				completed = true
				break
			}
			if answer.Code != "stale" && answer.Code != "unavailable" && answer.Code != "conflict" {
				return errors.New("membership transition rejected")
			}
			time.Sleep(50 * time.Millisecond)
		}
		if !completed {
			return errors.New("joint membership deadline")
		}
	}
	return nil
}

type quorumScenarioEvidence struct {
	LostNode                  model.Uint64      `json:"lost_node"`
	ObservedControlLeaderLoss bool              `json:"observed_control_leader_loss"`
	ObservedStorageLeaderLoss bool              `json:"observed_storage_leader_loss"`
	MinorityDenied            bool              `json:"minority_denied"`
	StaleWorkerDenied         bool              `json:"stale_worker_denied"`
	DiskQuarantined           bool              `json:"disk_quarantined"`
	LearnerCaughtUp           bool              `json:"learner_caught_up"`
	JointReplacement          bool              `json:"joint_replacement"`
	VerifiedCopies            uint32            `json:"verified_copies"`
	Acknowledged              []clusterExpected `json:"acknowledged"`
}

func runQuorumScenario(root string, lost uint64) (evidence quorumScenarioEvidence, result error) {
	stage := "quorum_fixture"
	defer func() {
		recordParentFailure(stage, result)
		result = annotateSmokeFailure("quorum_node_loss", stage, model.ID{}, result)
	}()
	evidence.LostNode = model.Uint64(lost)
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
	all := []*clusterProcess{}
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
		config := appcore.NodeConfig{NodeID: node, PeerListen: targets[node], PeerSourceIP: fmt.Sprintf("127.0.0.%d", node+10), Certificate: pairs[node][0], PrivateKey: pairs[node][1], CA: ca, Seed: fixture.seed, Members: m, InitialLeader: lost}
		raw, err := json.Marshal(config)
		if err != nil {
			return "", err
		}
		path := filepath.Join(root, fmt.Sprintf("node-%d.json", node))
		err = os.WriteFile(path, raw, 0600)
		return path, err
	}
	stage = "quorum_launch_three_processes"
	for node := uint64(1); node <= 3; node++ {
		config, err := configFor(node, members)
		if err != nil {
			return evidence, err
		}
		process, err := launchClusterProcess(filepath.Join(root, fmt.Sprintf("node-%d", node)), config)
		if err != nil {
			return evidence, err
		}
		processes[node] = process
		all = append(all, process)
	}
	for _, process := range processes {
		if err = process.ready(); err != nil {
			return evidence, err
		}
	}
	statuses, err := processes[lost].statuses()
	if err != nil || len(statuses) != 65 {
		return evidence, errors.New("missing installed groups")
	}
	controlGroup := statuses[0].Group
	dataGroup := statuses[int(fixture.batch.RouteSlot)+1].Group
	stage = "quorum_real_leadership_transfer"
	if err = transferClusterLeader(processes, controlGroup, lost); err != nil {
		return evidence, err
	}
	if err = transferClusterLeader(processes, dataGroup, lost); err != nil {
		return evidence, err
	}
	stage = "quorum_initial_ack"
	first, err := appendClusterBatch(processes[lost], fixture, nextClusterBatch(fixture, 0))
	if err != nil {
		return evidence, err
	}
	values := []clusterExpected{first}
	fenceAnswer, err := processes[lost].command(clusterCommand{Kind: "fence", Group: &dataGroup})
	if err != nil || !fenceAnswer.OK || fenceAnswer.Fence == nil {
		return evidence, errors.New("worker fence unavailable")
	}
	relays.Partition(lost, true)
	majority := map[uint64]*clusterProcess{}
	for node, process := range processes {
		if node != lost {
			majority[node] = process
		}
	}
	stage = "quorum_majority_partition_append"
	var survivor *clusterProcess
	for _, process := range majority {
		survivor = process
		break
	}
	second, err := appendClusterBatch(survivor, fixture, nextClusterBatch(fixture, 1))
	if err != nil {
		return evidence, err
	}
	values = append(values, second)
	stage = "quorum_minority_no_ack"
	minorityStatus, _, minorityErr := processes[lost].child.call("/ingest/v1/batches", nextClusterBatch(fixture, 2), "", fixture.credential)
	if minorityErr == nil && minorityStatus != 503 {
		return evidence, errors.New("minority returned a non-unavailable admission")
	}
	evidence.MinorityDenied = true
	stale, err := processes[lost].command(clusterCommand{Kind: "check_fence", Group: &dataGroup, Fence: fenceAnswer.Fence})
	if err != nil || stale.OK {
		return evidence, errors.New("partitioned worker fence accepted")
	}
	evidence.StaleWorkerDenied = true
	relays.Partition(lost, false)
	stage = "quorum_heal_original_values"
	if err = verifyClusterValues(survivor, fixture, values); err != nil {
		return evidence, err
	}
	if err = transferClusterLeader(processes, controlGroup, lost); err != nil {
		return evidence, err
	}
	if err = transferClusterLeader(processes, dataGroup, lost); err != nil {
		return evidence, err
	}
	controlLeader, _, err := findClusterLeader(processes, controlGroup)
	if err != nil || controlLeader != lost {
		return evidence, errors.New("control role not transferred")
	}
	dataLeader, _, err := findClusterLeader(processes, dataGroup)
	if err != nil || dataLeader != lost {
		return evidence, errors.New("storage role not transferred")
	}
	evidence.ObservedControlLeaderLoss = true
	evidence.ObservedStorageLeaderLoss = true
	stage = "quorum_remove_leader_and_disk"
	relays.Partition(lost, true)
	if err = processes[lost].child.kill(); err != nil {
		return evidence, err
	}
	if err = os.Rename(filepath.Join(root, fmt.Sprintf("node-%d", lost)), filepath.Join(root, fmt.Sprintf("unavailable-disk-%d", lost))); err != nil {
		return evidence, err
	}
	evidence.DiskQuarantined = true
	delete(processes, lost)
	third, err := appendClusterBatch(survivor, fixture, nextClusterBatch(fixture, 3))
	if err != nil {
		return evidence, err
	}
	values = append(values, third)
	// The running voters add the learner to all 65 groups first. A starting node
	// waits for every group to answer within its fixed startup budget, so that
	// budget must not also cover the sequential membership changes it depends on.
	stage = "quorum_add_replacement_learner"
	learnerMembers := members
	learnerMembers.Revision = 2
	learnerMembers.Nodes = append(append([]replica.Member(nil), members.Nodes...), replica.Member{ID: 4, Address: "https://" + relays.Address(4), NodeIdentity: "node-4", FailureDomain: "local-process-directory-4", Learner: true})
	if err = changeClusterMembership(processes, statuses, learnerMembers); err != nil {
		return evidence, err
	}
	stage = "quorum_start_replacement_learner"
	if err = smokecluster.AssignPeers(relays, targets, 4); err != nil {
		return evidence, err
	}
	config, err := configFor(4, learnerMembers)
	if err != nil {
		return evidence, err
	}
	replacement, err := launchClusterProcess(filepath.Join(root, "node-4"), config)
	if err != nil {
		return evidence, err
	}
	all = append(all, replacement)
	if err = replacement.ready(); err != nil {
		return evidence, err
	}
	processes[4] = replacement
	if err = verifyClusterValues(replacement, fixture, values); err != nil {
		return evidence, err
	}
	evidence.LearnerCaughtUp = true
	stage = "quorum_joint_promote_replacement"
	finalMembers := replica.Members{Revision: 3}
	for _, member := range learnerMembers.Nodes {
		if member.ID == lost {
			continue
		}
		member.Learner = false
		finalMembers.Nodes = append(finalMembers.Nodes, member)
	}
	if err = changeClusterMembership(processes, statuses, finalMembers); err != nil {
		return evidence, err
	}
	evidence.JointReplacement = true
	fourth, err := appendClusterBatch(replacement, fixture, nextClusterBatch(fixture, 4))
	if err != nil {
		return evidence, err
	}
	values = append(values, fourth)
	stage = "quorum_reconcile_every_ack_and_exact_value"
	for _, process := range processes {
		if err = verifyClusterValues(process, fixture, values); err != nil {
			return evidence, err
		}
		evidence.VerifiedCopies++
	}
	evidence.Acknowledged = values
	return evidence, nil
}
func runQuorumNodeLoss(args []string) (result error) {
	stage := "quorum_flags"
	defer func() { result = annotateSmokeFailure("quorum_node_loss", stage, model.ID{}, result) }()
	f := flag.NewFlagSet("quorum-node-loss", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	nodes := f.Int("nodes", 3, "actual voter processes")
	artifact := f.String("artifact-dir", "", "sanitized evidence directory")
	if err := f.Parse(args); err != nil {
		return err
	}
	if *nodes != 3 || *artifact == "" {
		return model.Fail(model.Invalid)
	}
	if err := os.MkdirAll(*artifact, 0700); err != nil {
		return err
	}
	if err := enableClusterDiagnostics(*artifact); err != nil {
		return err
	}
	root, err := os.MkdirTemp("", "soundpost-quorum-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(root)
	evidence := struct {
		Version                           uint16                   `json:"version"`
		Scope                             string                   `json:"scope"`
		ThreeServerProcesses              bool                     `json:"three_server_processes"`
		IndependentPrivateDirectories     bool                     `json:"independent_private_directories"`
		DistinctPhysicalHardwareQualified bool                     `json:"distinct_physical_hardware_qualified"`
		MissingQualification              string                   `json:"missing_qualification"`
		Scenarios                         []quorumScenarioEvidence `json:"scenarios"`
	}{Version: 1, Scope: "local_process_failure_and_live_transport_partition", ThreeServerProcesses: true, IndependentPrivateDirectories: true, DistinctPhysicalHardwareQualified: false, MissingQualification: "three_distinct_physical_nodes_and_disks_and_power_loss_evidence_not_available"}
	for node := uint64(1); node <= 3; node++ {
		directory := filepath.Join(root, fmt.Sprintf("role-%d", node))
		if err = os.MkdirAll(directory, 0700); err != nil {
			return err
		}
		stage = fmt.Sprintf("quorum_role_%d", node)
		scenario, err := runQuorumScenario(directory, node)
		if err != nil {
			return err
		}
		evidence.Scenarios = append(evidence.Scenarios, scenario)
	}
	raw, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		return err
	}
	stage = "quorum_evidence_write"
	return os.WriteFile(filepath.Join(*artifact, "quorum-node-loss.json"), raw, 0600)
}

func quorumReadScope(ctx context.Context, app *appcore.App, token string, org, project model.ID) (auth.Scope, error) {
	credential, err := app.Auth.Authenticate(ctx, token)
	if err != nil {
		return auth.Scope{}, annotateSmokeFailure("quorum_child", "quorum_verify_authenticate", model.ID{}, err)
	}
	scope, err := app.Auth.Authorize(ctx, credential, org, []model.ID{project}, auth.Read)
	if err != nil {
		return auth.Scope{}, annotateSmokeFailure("quorum_child", "quorum_verify_authorize", model.ID{}, err)
	}
	return scope, nil
}
func writeAuthorizedClusterSeed(app *appcore.App, fixture clusterFixture) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := quorumReadScope(ctx, app, fixture.session, fixture.org, fixture.project); err != nil {
		return err
	}
	return app.WriteClusterSeed(fixture.seed)
}
func verifyQuorumCommand(ctx context.Context, app *appcore.App, c clusterCommand, out *clusterAnswer) error {
	if c.Org == nil || c.Project == nil {
		return model.Fail(model.Invalid)
	}
	scope, err := quorumReadScope(ctx, app, c.Token, *c.Org, *c.Project)
	if err != nil {
		return err
	}
	minimum := make([]model.Cursor, len(c.Values))
	expected := map[model.ID]clusterExpected{}
	for i, value := range c.Values {
		minimum[i] = value.Receipt.Cursor
		expected[value.Record] = value
	}
	iterator, err := app.Storage.Scan(ctx, scope, storage.ScanRequest{Projects: []model.ID{*c.Project}, Signal: model.Metric, Start: 0, End: model.UnixNano(math.MaxInt64), Fence: storage.ReadFence{Min: minimum}})
	if err != nil {
		return annotateSmokeFailure("quorum_child", "quorum_verify_scan_admission", model.ID{}, err)
	}
	defer iterator.Close()
	seen := map[model.ID]bool{}
	for {
		page, err := iterator.Next(ctx)
		if err == io.EOF {
			break
		}
		if err != nil {
			return annotateSmokeFailure("quorum_child", "quorum_verify_scan_next", model.ID{}, err)
		}
		for i, id := range page.IDs {
			want, ok := expected[id]
			if !ok {
				continue
			}
			metric := page.Values[i].Metric
			if seen[id] || metric == nil || metric.Histogram == nil || metric.Histogram.Integer == nil || metric.Histogram.Integer.Count != want.Count || metric.Histogram.Integer.ZeroCount != want.Count || page.ObservedTimes[i] != want.At || page.Origins[i] != want.Receipt.Cursor {
				return &smokeFailure{Stage: "quorum_verify_values", Code: "value_mismatch"}
			}
			seen[id] = true
		}
	}
	if len(seen) != len(expected) {
		return &smokeFailure{Stage: "quorum_verify_complete", Code: "missing_acknowledged_record"}
	}
	out.Verified = uint32(len(seen))
	return nil
}
func clusterFailureAnswer(err error) clusterAnswer {
	answer := clusterAnswer{Code: classifySmokeError(err), Stage: "quorum_verify_child"}
	var failure *smokeFailure
	if errors.As(err, &failure) {
		answer.Code = failure.Code
		answer.Stage = failure.Stage
	}
	return answer
}
func quorumAnswerFailure(answer clusterAnswer) error {
	if answer.OK {
		return &smokeFailure{Stage: "quorum_verify_complete", Code: "verified_count_mismatch"}
	}
	stage := "quorum_verify_child"
	switch answer.Stage {
	case "quorum_verify_authenticate", "quorum_verify_authorize", "quorum_verify_scan_admission", "quorum_verify_scan_next", "quorum_verify_values", "quorum_verify_complete":
		stage = answer.Stage
	}
	code := publicSmokeCode(model.Code(answer.Code))
	if code == "" {
		switch answer.Code {
		case "value_mismatch", "missing_acknowledged_record", "verified_count_mismatch":
			code = answer.Code
		default:
			code = "unavailable"
		}
	}
	return &smokeFailure{Stage: stage, Code: code}
}
