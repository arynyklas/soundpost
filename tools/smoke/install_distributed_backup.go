// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/config"
	"github.com/arynyklas/soundpost/internal/query"
)

// The cluster backup and restore leg of install-distributed (three real `serve` processes):
// docs/operations/backup-restore.md, "Backup and restore of a three-voter cluster".
//
//  1. Setup: backup keys, an authority bound to the installation (read from the single installation
//     the seed came from; a cluster node's directory is refused by `authority-init --data-dir`).
//  2. Stop ONE follower (SIGTERM), run the real binary's `backup create --mode distributed` against
//     that voter's directory while the other two voters hold the quorum, start the follower again.
//  3. Write one more row through the old cluster (it is not in the backup).
//  4. `backup restore` into a fresh single-voter root, `backup activate --cluster-seed-out`.
//  5. Start three NEW voters from that seed: new certificates and node identities from the same CA,
//     new ports and directories. Recover the administrator (bootstrap token of the restored root),
//     reauthorize the reader and the source, and require: every restored voter serves exactly the
//     rows acknowledged before the backup and not the later one, a write through a restored
//     follower commits and is served by all three, every certificate of an old node is refused
//     (HTTP 403) by every restored voter, a restored member's is accepted, and the old cluster keeps
//     serving and refuses the restored members the same way.
//
// The wall times of the steps are the drill's RTO (one local host, tiny data set).

const (
	distOwnerEmail       = "owner@install-smoke.invalid" // the account bootstrapInstallation creates
	distReaderPassword   = "install smoke reader password 2026"
	distRecoveryEmail    = "recovery@install-smoke.invalid"
	distRecoveryPassword = "install smoke recovery password 2026"
	distRestoreReason    = "cluster backup smoke: verified against the original administrator ticket"
)

// restoredNodes are the members of the restored cluster: the same member numbers (they are Raft
// numbers inside one cluster, not identities) and NEW node identities.
var restoredNodes = []distNode{{1, "d", "node-d"}, {2, "e", "node-e"}, {3, "f", "node-f"}}

// backupLegEnv is what the leg needs of the running smoke.
type backupLegEnv struct {
	cluster *processCluster
	sites   map[uint64]*installSite
	fx      *installFixture
	ledger  *distLedger
	login   func(id uint64) error
	nfx     func(id uint64) *installFixture
	// secrets are scanned for in everything the leg's commands printed.
	secrets []string
	outputs []string
}

// noBootHost is the host of a cluster that never bootstraps a single installation of its own.
type noBootHost struct{ installHost }

func (noBootHost) cleanup() {}

func legFailure(stage, code string) error { return &smokeFailure{Stage: stage, Code: code} }

// cli runs the real binary with the given arguments and returns its standard output. Standard error
// is kept for the secret scan and shown (static product text) when the command fails.
func (e *backupLegEnv) cli(stage string, env []string, timeout time.Duration, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, e.cluster.binary, args...)
	cmd.Env = append([]string{"PATH=" + os.Getenv("PATH")}, env...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	e.outputs = append(e.outputs, stdout.String(), stderr.String())
	if err != nil {
		if tail := stderr.String(); !e.leaks(tail) {
			if len(tail) > 400 {
				tail = tail[len(tail)-400:]
			}
			os.Stderr.WriteString("cluster backup leg: " + stage + " stderr: " + strings.TrimSpace(tail) + "\n")
		}
		return nil, legFailure(stage, "command_failed")
	}
	return stdout.Bytes(), nil
}

func (e *backupLegEnv) leaks(text string) bool {
	for _, s := range e.secrets {
		if s != "" && strings.Contains(text, s) {
			return true
		}
	}
	return false
}

// terminate stops one running member with SIGTERM (the documented stop; `kill` is the crash).
func (c *processCluster) terminate(id uint64) error {
	c.mu.Lock()
	cmd, done := c.cmds[id], c.done[id]
	c.mu.Unlock()
	if cmd == nil {
		return errors.New("member not running")
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); errors.Is(err, os.ErrProcessDone) {
		// The member already stopped by itself (a previous release refusing a data directory the
		// candidate moved to a layout it does not read exits at startup): nothing to stop.
		c.mu.Lock()
		delete(c.cmds, id)
		c.mu.Unlock()
		return nil
	} else if err != nil {
		return err
	}
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		_ = cmd.Process.Kill()
		<-done
		return legFailure("cluster_backup_stop_follower", "graceful_stop_timeout")
	}
	c.mu.Lock()
	delete(c.cmds, id)
	c.mu.Unlock()
	return nil
}

// newRestoredProcessCluster builds the three NEW voters of a restored installation: certificates
// of the same CA as the old cluster (so the old nodes' certificates are valid to TLS and only
// membership can refuse them) with new node identities, new ports and directories, the seed
// `backup activate` wrote, and node files generated by internal/config.
func newRestoredProcessCluster(old *processCluster, root, seed string) (*processCluster, error) {
	pkiDir := filepath.Join(root, "pki")
	if err := os.MkdirAll(pkiDir, 0o700); err != nil {
		return nil, err
	}
	c := &processCluster{binary: old.binary, root: root, boot: noBootHost{}, public: map[uint64]string{}, peer: map[uint64]string{}, data: map[uint64]string{}, cmds: map[uint64]*exec.Cmd{}, done: map[uint64]chan error{}, logs: map[uint64]*syncBuffer{}, certs: map[uint64]*x509.Certificate{}, sites: map[uint64]*installSite{}, seed: seed}
	pki := &processPKI{dir: pkiDir, caFile: old.pki.caFile, ca: old.pki.ca, certs: map[uint64]string{}, keys: map[uint64]string{}}
	nodes := []config.Node{}
	for _, n := range restoredNodes {
		certPEM, keyPEM, err := old.pki.ca.issue(n, old.pki.nextSerial())
		if err != nil {
			return nil, err
		}
		pki.certs[n.id], pki.keys[n.id] = filepath.Join(pkiDir, n.name+".pem"), filepath.Join(pkiDir, n.name+".key")
		if err = os.WriteFile(pki.certs[n.id], certPEM, 0o600); err != nil {
			return nil, err
		}
		if err = os.WriteFile(pki.keys[n.id], keyPEM, 0o600); err != nil {
			return nil, err
		}
		c.keys = append(c.keys, base64Body(keyPEM))
		public, e1 := freeAddress()
		peer, e2 := freeAddress()
		if e1 != nil || e2 != nil {
			return nil, errors.Join(e1, e2)
		}
		c.public[n.id], c.peer[n.id] = public, peer
		c.data[n.id] = filepath.Join(root, "node-"+n.name)
		c.logs[n.id] = &syncBuffer{}
		nodes = append(nodes, config.Node{ID: n.id, Identity: n.identity, FailureDomain: "process-directory-" + n.name, PeerAddress: config.Endpoint("https://" + peer), PeerListen: peer,
			Disk: config.Disk{ID: "directory-" + n.name, Volume: "directory-" + n.name, Path: c.data[n.id], CapacityBytes: 1 << 30}, Certificate: pki.certs[n.id], PrivateKey: config.NewSecretRef("file:" + pki.keys[n.id])})
	}
	c.pki = pki
	c.cfg = installConfigFor(nodes, old.pki.caFile, "file:"+seed, "127.0.0.1:0")
	if err := config.Validate(c.cfg); err != nil {
		return nil, err
	}
	files, err := config.NodeConfigs(c.cfg)
	if err != nil {
		return nil, err
	}
	for id, content := range files {
		if err = os.WriteFile(filepath.Join(root, "node-"+strconv.FormatUint(id, 10)+".json"), content, 0o600); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// queryRows reads the rows a voter serves, as the project reader of site's session.
func queryRows(site *installSite, fx *installFixture) ([]distRow, error) {
	at := *fx
	at.queryTime = strconv.FormatInt(time.Now().Add(time.Minute).UnixNano(), 10)
	status, raw, err := queryExpr(site, &at, distRowsExpression)
	if err != nil {
		return nil, legFailure("cluster_backup_rows", "query_transport")
	}
	if status != 200 {
		return nil, httpSmokeFailure("cluster_backup_rows", status, 200, raw)
	}
	var result query.Result
	if json.Unmarshal(raw, &result) != nil {
		return nil, legFailure("cluster_backup_rows", "answer_not_decodable")
	}
	return rowsOfResult(result)
}

// waitRows waits until the voter serves exactly the rows of want, and returns what it last served.
func waitRows(stage string, site *installSite, fx *installFixture, want []distRow, limit time.Duration) ([]distRow, error) {
	deadline := time.Now().Add(limit)
	var got []distRow
	for {
		rows, err := queryRows(site, fx)
		if err == nil {
			got = rows
			err = requireRows(stage, want, rows)
		}
		if err == nil {
			return got, nil
		}
		if time.Now().After(deadline) {
			var failure *smokeFailure
			if errors.As(err, &failure) {
				copied := *failure
				copied.Stage = stage
				return got, &copied
			}
			return got, legFailure(stage, "rows_never_exact")
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// peerStatus asks a member's peer listener for the readiness of one Raft group presenting the given
// client certificate (verified against the cluster CA) and returns the HTTP status. A refusal at the
// TLS layer is an error here: the certificates of this leg are all valid under the CA, so only the
// group's membership may refuse them.
func peerStatus(address string, ca []byte, certFile, keyFile, group string) (int, error) {
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return 0, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return 0, errors.New("trust bundle")
	}
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}, RootCAs: pool, ServerName: "localhost"}}}
	defer client.CloseIdleConnections()
	response, err := client.Get("https://" + address + "/internal/raft/v1/ready/" + group)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	return response.StatusCode, nil
}

// requirePeerStatus requires the status to be want; a member that is still catching up answers 503
// for a while, which only the accepted case waits out.
func requirePeerStatus(stage, address string, ca []byte, certFile, keyFile, group string, want int) error {
	deadline := time.Now().Add(60 * time.Second)
	for {
		status, err := peerStatus(address, ca, certFile, keyFile, group)
		if err == nil && status == want {
			return nil
		}
		if err == nil && !(want == 200 && status == 503) {
			return &smokeFailure{Stage: stage, Code: "unexpected_peer_status", Actual: status, Expected: want}
		}
		if time.Now().After(deadline) {
			return legFailure(stage, "peer_status_not_reached")
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func ms(d time.Duration) int64 { return d.Milliseconds() }

// distributedBackupRestoreLeg runs the leg above. The old cluster is three ready, converged members
// and ledger holds every row it acknowledged.
func distributedBackupRestoreLeg(env *backupLegEnv, report map[string]any) (err error) {
	c, fx, ledger := env.cluster, env.fx, env.ledger
	stage := "cluster_backup_setup"
	defer func() {
		var existing *smokeFailure
		if err != nil && !errors.As(err, &existing) {
			err = &smokeFailure{Stage: stage, Code: classifySmokeError(err)}
		}
	}()
	ids := []uint64{1, 2, 3}
	env.secrets = append(append([]string{fx.credential, fx.password, distReaderPassword, distRecoveryPassword, fx.session.Token, fx.session.CSRF, fx.reader.Token, fx.reader.CSRF}, c.keys...), c.pki.material...)
	legStarted := time.Now()
	dir := filepath.Join(c.root, "cluster-backup")
	for _, d := range []string{dir, filepath.Join(dir, "keys")} {
		if err = os.MkdirAll(d, 0o700); err != nil {
			return err
		}
	}
	keyDir, authKeys, authRestricted := filepath.Join(dir, "keys"), filepath.Join(dir, "authority.keys"), filepath.Join(dir, "authority.restricted.keys")
	authDir, destDir, restoredRoot, seed := filepath.Join(dir, "authority"), filepath.Join(dir, "destination"), filepath.Join(dir, "restored-root"), filepath.Join(dir, "restored.seed")
	leg := map[string]any{}

	// ---- 1. setup ----
	stage = "cluster_backup_setup"
	for _, id := range []string{"data-kek", "secret-kek"} {
		if _, err = env.cli(stage, nil, 60*time.Second, "backup", "keygen", "--key-dir", keyDir, "--id", id); err != nil {
			return err
		}
	}
	if _, err = env.cli(stage, nil, 60*time.Second, "backup", "authority-keygen", "--out", authKeys, "--restricted-out", authRestricted, "--id", "cluster-smoke"); err != nil {
		return err
	}
	boot, ok := c.boot.(*binaryHost)
	if !ok {
		return legFailure(stage, "no_single_installation_to_read_the_id_from")
	}
	initOut, err := env.cli(stage, nil, 60*time.Second, "backup", "authority-init", "--data-dir", boot.dir, "--authority-keys", authKeys, "--authority-dir", authDir)
	if err != nil {
		return err
	}
	installation, err := parseInstallation(initOut)
	if err != nil {
		return err
	}
	if err = disjointIdentities(distNodes, restoredNodes); err != nil {
		return err
	}

	// The rows the old cluster acknowledged, as the voters themselves serve them: the helper that
	// reads rows is proven against the live cluster before it judges a restored one.
	stage = "cluster_backup_rows_before"
	before := expectedRows(ledger.accepted)
	for _, id := range ids {
		if _, err = waitRows(stage, env.sites[id], env.nfx(id), before, 90*time.Second); err != nil {
			return err
		}
	}
	leg["rows_acknowledged_before_the_backup"] = len(before)

	// ---- 2. backup at a follower ----
	stage = "cluster_backup_pick_follower"
	view, err := leadership(env.sites, ids, 60*time.Second)
	if err != nil {
		return err
	}
	follower := uint64(0)
	for _, id := range ids {
		if id != view.leader {
			follower = id
		}
	}
	leg["leader_at_backup"], leg["backup_taken_at_follower"] = view.leader, follower

	stage = "cluster_backup_stop_follower"
	stoppedAt := time.Now()
	if err = c.terminate(follower); err != nil {
		return err
	}
	stage = "cluster_backup_create"
	createStarted := time.Now()
	createOut, err := env.cli(stage, []string{"SOUNDPOST_ADMIN_PASSWORD=" + fx.password}, 280*time.Second, "backup", "create", "--mode", "distributed", "--node-id", strconv.FormatUint(follower, 10),
		"--cluster-config", filepath.Join(c.root, "node-"+strconv.FormatUint(follower, 10)+".json"), "--data-dir", c.data[follower], "--admin-email", distOwnerEmail, "--key-dir", keyDir,
		"--data-kek", "data-kek", "--secret-kek", "secret-kek", "--authority-keys", authKeys, "--authority-dir", authDir, "--dest-dir", destDir, "--reason", "cluster backup smoke")
	createTook := time.Since(createStarted)
	if err != nil {
		return err
	}
	created, backupID, err := parseBackupCreated(createOut)
	if err != nil {
		return err
	}
	if created.Voters != 3 {
		return &smokeFailure{Stage: stage, Code: "manifest_not_a_three_voter_topology", Actual: int(created.Voters), Expected: 3}
	}
	leg["backup_objects"] = created.Objects

	stage = "cluster_backup_restart_follower"
	if err = c.start(follower); err != nil {
		return err
	}
	if env.sites[follower], err = c.site(follower); err != nil {
		return err
	}
	if err = waitNodeReady(env.sites[follower], 180*time.Second); err != nil {
		return err
	}
	if err = env.login(follower); err != nil {
		return err
	}
	leg["follower_down_s"] = time.Since(stoppedAt).Round(100 * time.Millisecond).Seconds()

	// ---- 3. one more row, through the follower the backup was taken at: not in the backup ----
	stage = "cluster_backup_row_after"
	if err = ledger.write(env.sites[follower], fx, "after_backup"); err != nil {
		return err
	}
	all := expectedRows(ledger.accepted)
	after := rowsExcept(all, before)
	if len(after) != 1 {
		return legFailure(stage, "after_row_not_one")
	}
	for _, id := range ids {
		if _, err = waitRows(stage, env.sites[id], env.nfx(id), all, 90*time.Second); err != nil {
			return err
		}
	}

	// ---- 4. restore into a fresh single-voter root, activate, write the seed ----
	recoveryStarted := time.Now()
	stage = "cluster_backup_restore"
	restoreStarted := time.Now()
	restoreOut, err := env.cli(stage, nil, 280*time.Second, "backup", "restore", "--backup-id", backupID.String(), "--root", restoredRoot, "--key-dir", keyDir,
		"--authority-keys", authRestricted, "--authority-dir", authDir, "--dest-dir", destDir)
	restoreTook := time.Since(restoreStarted)
	if err != nil {
		return err
	}
	restoredReport, err := parseBackupRestored(restoreOut)
	if err != nil {
		return err
	}
	if restoredReport.BackupID != backupID.String() || restoredReport.SourceVoters != 3 {
		return legFailure(stage, "restore_report_not_the_three_voter_backup")
	}
	stage = "cluster_backup_activate"
	activateStarted := time.Now()
	if _, err = env.cli(stage, nil, 280*time.Second, "backup", "activate", "--root", restoredRoot, "--authority-keys", authKeys, "--authority-dir", authDir, "--cluster-seed-out", seed); err != nil {
		return err
	}
	activateTook := time.Since(activateStarted)
	if info, e := os.Stat(seed); e != nil || info.Size() == 0 || info.Mode().Perm()&0o077 != 0 {
		return legFailure(stage, "seed_missing_or_not_private")
	}

	// ---- 5. three NEW voters from the seed ----
	stage = "cluster_backup_start_restored"
	restored, err := newRestoredProcessCluster(c, filepath.Join(dir, "restored-cluster"), seed)
	if err != nil {
		return err
	}
	defer restored.cleanup()
	env.secrets = append(env.secrets, restored.keys...)
	readyStarted := time.Now()
	if err = restored.start(ids...); err != nil {
		return err
	}
	rs := map[uint64]*installSite{}
	for _, id := range ids {
		if rs[id], err = restored.site(id); err != nil {
			return err
		}
	}
	stage = "cluster_backup_restored_ready"
	for _, id := range ids {
		if err = waitNodeReady(rs[id], 240*time.Second); err != nil {
			return err
		}
	}
	readyTook := time.Since(readyStarted)
	rview, err := leadership(rs, ids, 90*time.Second)
	if err != nil {
		return err
	}
	rfollower := uint64(0)
	for _, id := range ids {
		if id != rview.leader {
			rfollower = id
		}
	}
	leg["restored_leader"], leg["restored_write_through_follower"] = rview.leader, rfollower

	// Nothing old is active: the old source credential is refused by every restored voter.
	stage = "cluster_backup_old_credential_refused"
	for _, id := range ids {
		status, raw, e := rs[id].ingest(ledger.accepted[0].batch, fx.credential)
		if err = requireSmokeResponse(stage, status, 403, raw, e); err != nil {
			return err
		}
	}
	leg["old_source_credential_refused_403_by_restored_voters"] = len(ids)

	// A control write on a restored follower commits: the recovery administrator, then the
	// reauthorization of the reader and the source.
	stage = "cluster_backup_recover_administrator"
	token, err := os.ReadFile(filepath.Join(restoredRoot, "bootstrap.token"))
	if err != nil {
		return err
	}
	stale := 0
	status, raw, err := postRetryStale(rs[rfollower], "/api/v1/bootstrap", map[string]string{"Token": string(token), "Email": distRecoveryEmail, "Password": distRecoveryPassword}, "", "", &stale)
	if err = requireSmokeResponse(stage, status, 200, raw, err); err != nil {
		return err
	}
	var recovery auth.Session
	if err = json.Unmarshal(raw, &recovery); err != nil || recovery.CSRF == "" {
		return legFailure(stage, "session_decode")
	}
	env.secrets = append(env.secrets, recovery.Token, recovery.CSRF)
	stage = "cluster_backup_reauthorize"
	var issued auth.Reconciled
	for _, item := range []auth.Reconciliation{
		{Kind: auth.ReconcileAccount, User: fx.reader.User},
		{Kind: auth.ReconcileMembership, Org: fx.org, User: fx.reader.User},
		{Kind: auth.ReconcileGrant, Org: fx.org, User: fx.reader.User, Project: fx.project},
		{Kind: auth.ReconcileSource, Source: fx.source},
	} {
		item.Reason = distRestoreReason
		status, raw, err = postRetryStale(rs[rfollower], "/api/v1/restore/reconcile", reconcileBody(item), recovery.CSRF, "", &stale)
		if err = requireSmokeResponse(stage+"_"+string(item.Kind), status, 200, raw, err); err != nil {
			return err
		}
		if item.Kind == auth.ReconcileSource {
			if err = json.Unmarshal(raw, &issued); err != nil || issued.Credential == "" || issued.Credential == fx.credential {
				return legFailure(stage, "source_not_reissued")
			}
			env.secrets = append(env.secrets, issued.Credential)
		}
	}
	leg["control_writes_on_restored_follower_committed"] = true

	// Every restored voter serves exactly the rows acknowledged before the backup, and not the later one.
	stage = "cluster_backup_restored_rows"
	rsessions := map[uint64]auth.Session{}
	rfx := func(id uint64) *installFixture { copied := *fx; copied.reader = rsessions[id]; return &copied }
	for _, id := range ids {
		if rsessions[id], err = loginReader(rs[id], fx); err != nil {
			return err
		}
		env.secrets = append(env.secrets, rsessions[id].Token, rsessions[id].CSRF)
		got, e := waitRows(stage, rs[id], rfx(id), before, 90*time.Second)
		if e != nil {
			return e
		}
		if rowsContain(got, after) {
			return legFailure("cluster_backup_row_after_absent", "row_after_the_backup_served")
		}
	}
	leg["restored_voters_serve_exactly_the_rows_before_the_backup"] = len(before)
	leg["row_after_the_backup_absent_on_every_restored_voter"] = true
	recoveredAfter := time.Since(recoveryStarted)

	// The restored cluster is a working cluster: a write through its follower, with the reissued
	// credential, commits and is served by all three.
	stage = "cluster_backup_restored_write"
	reissued := *fx
	reissued.credential = issued.Credential
	restoredLedger := &distLedger{sequence: ledger.sequence}
	if err = restoredLedger.write(rs[rfollower], &reissued, "restored_follower"); err != nil {
		return err
	}
	restoredWant := append(append([]distRow{}, before...), expectedRows(restoredLedger.accepted)...)
	sortRows(restoredWant)
	for _, id := range ids {
		if _, err = waitRows(stage, rs[id], rfx(id), restoredWant, 90*time.Second); err != nil {
			return err
		}
	}
	leg["write_through_restored_follower_served_by_all_three"] = true

	// ---- 6. membership: no node of the old cluster is a member of the restored one ----
	stage = "cluster_backup_membership"
	caPEM := c.pki.ca.pem
	group := installation.String()
	for _, id := range ids {
		for _, old := range ids {
			if err = requirePeerStatus(stage+"_old_node_certificate_refused", restored.peer[id], caPEM, c.pki.certs[old], c.pki.keys[old], group, 403); err != nil {
				return err
			}
		}
		member := (id % 3) + 1
		if err = requirePeerStatus(stage+"_restored_member_accepted", restored.peer[id], caPEM, restored.pki.certs[member], restored.pki.keys[member], group, 200); err != nil {
			return err
		}
	}
	leg["old_node_certificates_refused_403_by_restored_voters"] = len(ids) * len(ids)
	leg["restored_member_certificates_accepted_by_restored_voters"] = len(ids)
	// ... and the other way: the old cluster refuses the restored members and accepts its own.
	for _, id := range ids {
		for _, member := range ids {
			if err = requirePeerStatus(stage+"_restored_member_refused_by_old_cluster", c.peer[id], caPEM, restored.pki.certs[member], restored.pki.keys[member], group, 403); err != nil {
				return err
			}
		}
		if err = requirePeerStatus(stage+"_old_member_accepted", c.peer[id], caPEM, c.pki.certs[(id%3)+1], c.pki.keys[(id%3)+1], group, 200); err != nil {
			return err
		}
	}
	leg["restored_member_certificates_refused_403_by_old_voters"] = len(ids) * len(ids)

	// ---- 7. the old cluster keeps serving, and the two clusters stay apart ----
	stage = "cluster_backup_old_cluster_serves"
	if err = ledger.write(env.sites[view.leader], fx, "after_restore"); err != nil {
		return err
	}
	allLater := expectedRows(ledger.accepted)
	for _, id := range ids {
		if _, err = waitRows(stage, env.sites[id], env.nfx(id), allLater, 90*time.Second); err != nil {
			return err
		}
	}
	if _, err = converged(env.sites, 90*time.Second); err != nil {
		return err
	}
	stage = "cluster_backup_restored_unaffected_by_old"
	for _, id := range ids {
		if _, err = waitRows(stage, rs[id], rfx(id), restoredWant, 30*time.Second); err != nil {
			return err
		}
	}
	leg["old_cluster_kept_serving_and_clusters_stay_apart"] = true

	// ---- 8. the restored voters stop cleanly, keep private modes and log no secret ----
	stage = "cluster_backup_restored_stop"
	scratch := map[string]any{}
	if err = restored.stop(scratch); err != nil {
		return err
	}
	if err = restored.checkPrivate(scratch); err != nil {
		return err
	}
	if err = restored.checkLogs(env.secrets, restored.keys); err != nil {
		return err
	}
	stage = "cluster_backup_command_output_hygiene"
	for _, text := range env.outputs {
		if env.leaks(text) {
			return legFailure(stage, "secret_in_command_output")
		}
	}
	leg["restored_private_mode_entries_checked"] = scratch["private_mode_entries_checked"]
	leg["restored_voters_logs_and_command_output_free_of_secrets"] = true
	leg["restored_node_identities"] = []string{restoredNodes[0].identity, restoredNodes[1].identity, restoredNodes[2].identity}
	leg["control_write_stale_retries"] = stale
	leg["rto_ms"] = map[string]any{
		"backup_create":               ms(createTook),
		"restore":                     ms(restoreTook),
		"activate":                    ms(activateTook),
		"three_new_voters_ready":      ms(readyTook),
		"restore_to_rows_served":      ms(recoveredAfter),
		"restored_voters_ready_total": ms(restoreTook + activateTook + readyTook),
	}
	leg["wall_s"] = time.Since(legStarted).Round(100 * time.Millisecond).Seconds()
	leg["caveat"] = "three local processes on one host, loopback; a tiny data set: the times are the shape of one drill, not a qualification"
	report["cluster_backup_restore"] = leg
	return nil
}
