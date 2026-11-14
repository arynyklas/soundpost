// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/backup"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/retention"
	"github.com/arynyklas/soundpost/internal/storage"
)

// The backup-restore smoke is the C12 disaster drill on real local processes
// with private temporary directories (no Docker, no network, no credentials in
// artifacts):
//
//  1. a live installation process ingests batches over HTTPS while the backup
//     service takes an encrypted backup into an off-host directory (copying
//     continues while intake proceeds);
//  2. more batches are ACKed after the backup sealed (they are outside the
//     backup's RPO by design) and a historical range is deleted, which completes
//     only after the independent authority checkpointed it;
//  3. the live process is killed (the disaster);
//  4. this process restores the backup into a clean storage root with the
//     authority's CURRENT ledger, then a second clean process serves the root;
//  5. the drill checks, over HTTPS and typed scans: every ACKed batch the
//     backup held is retried to a byte-identical receipt, every row is exactly
//     what was ACKed before the seal minus the deleted range, nothing ACKed after
//     the seal reappears before it is retried, old source credentials stay dead,
//     no sender is configured, and a fresh recovery admin sees no former grant
//     until an audited reauthorization;
//  6. second generation (the normal situation weeks after a disaster): the
//     restored installation takes its OWN backup, is killed, and that backup is
//     restored into a third clean root and served by a third process. Every
//     credential of generations 0 and 1 is dead again (including the user
//     reauthorized in generation 1 and the source credential reissued in
//     generation 1), the deletion tombstone still holds and every row and
//     receipt of generation 1 is intact.
//
// Registered by the parent as:
//
//	case "backup-restore": return RunBackupRestore(os.Args[2:])
//	case "backup-restore-child": return RunBackupRestoreChild(os.Args[2:])
//
// Scope: single-node, non-HA, local disks. The measured numbers describe one
// local run; they are not a qualification and no backup-based single-node RPO is
// claimed.

const (
	brOwnerEmail       = "backup-owner@example.test"
	brOwnerPassword    = "backup smoke owner password 2026"
	brRecoveryEmail    = "recovery-admin@example.test"
	brRecoveryPassword = "backup smoke recovery password 2026"
)

type brCommand struct {
	Kind     string         `json:"kind"`
	Email    string         `json:"email,omitempty"`
	Password string         `json:"password,omitempty"`
	Org      string         `json:"org,omitempty"`
	Project  string         `json:"project,omitempty"`
	Source   string         `json:"source,omitempty"`
	Owner    string         `json:"owner,omitempty"`
	Start    model.UnixNano `json:"start_ns,omitempty"`
	End      model.UnixNano `json:"end_ns,omitempty"`
}

type brBackup struct {
	ID         string `json:"id"`
	CreatedNS  int64  `json:"created_ns"`
	DoneNS     int64  `json:"completed_ns"`
	DurationMS int64  `json:"duration_ms"`
	Objects    int    `json:"objects"`
	Sequence   uint64 `json:"authority_sequence"`
}

type brAnswer struct {
	OK             bool      `json:"ok"`
	Code           string    `json:"code,omitempty"`
	Stage          string    `json:"stage,omitempty"`
	Backup         *brBackup `json:"backup,omitempty"`
	Phase          string    `json:"phase,omitempty"`
	AuthoritySeq   uint64    `json:"authority_sequence,omitempty"`
	AuthorityGen   uint64    `json:"authority_generation,omitempty"`
	Tombstones     int       `json:"tombstones,omitempty"`
	Rows           []int64   `json:"rows,omitempty"`
	SourceToken    string    `json:"source_credential,omitempty"`
	Destinations   int       `json:"destinations,omitempty"`
	Pending        int       `json:"pending_reconciliation,omitempty"`
	Ready          bool      `json:"ready,omitempty"`
	ActivateMillis int64     `json:"activate_ms,omitempty"`
}

// RunBackupRestoreChild is the installation process: mode "live" (backs up and
// deletes on command) or "restored" (activates, reconciles and reads on command).
func RunBackupRestoreChild(args []string) (result error) {
	stage := "backup_child_flags"
	defer func() {
		if result != nil {
			_ = json.NewEncoder(os.Stdout).Encode(childAddress{Failure: &childStartupFailure{Stage: stage, Code: classifySmokeError(result)}})
		}
	}()
	f := flag.NewFlagSet("backup-restore-child", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	mode := f.String("mode", "", "")
	dir := f.String("data-dir", "", "")
	offhost := f.String("offhost-dir", "", "")
	keyDir := f.String("key-dir", "", "")
	authorityDir := f.String("authority-dir", "", "")
	authorityKeys := f.String("authority-keys", "", "")
	if err := f.Parse(args); err != nil {
		return err
	}
	stage = "backup_child_open"
	open := appcore.Open
	if *mode == "restored" {
		// A restored root holds its engine closed until activation; OpenForActivation defers the
		// artifact-reference validation Open would run (App.RestoreReady runs it after the hold lifts).
		open = appcore.OpenForActivation
	}
	app, err := open(*dir)
	if err != nil {
		return err
	}
	defer app.Close()
	stage = "backup_child_authority"
	keys, err := backup.ReadAuthorityKeys(*authorityKeys)
	if err != nil {
		return err
	}
	authorityDest, err := backup.NewLocalDestination(*authorityDir)
	if err != nil {
		return err
	}
	authority, err := backup.NewAuthority(authorityDest, keys, time.Now)
	if err != nil {
		return err
	}
	if *mode == "live" {
		var installation model.ID
		if err = app.Control.View(context.Background(), func(st control.State) error { installation = st.Installation; return nil }); err != nil {
			return err
		}
		if _, err = authority.Initialize(context.Background(), installation); err != nil {
			return err
		}
	}
	svc := app.Retention
	if err = svc.UseAuthority(authority); err != nil {
		return err
	}
	var backups *backup.Service
	if *mode == "live" || *mode == "restored" { // a restored installation takes its own backups too (generation 2)
		stage = "backup_child_service"
		plane := backup.EngineDataPlane(app.Storage)
		backups, err = backup.New(backup.Config{Control: app.Control, Data: plane, Processed: backup.AppliedProcessed(plane), Authority: authority, Authorizer: app.Auth, Keys: backup.KeyDir(*keyDir), DataKEK: "smoke-data-kek", SecretKEK: "smoke-secret-kek", Attempts: backup.DirAttempts(filepath.Join(*dir, "backup-attempts")), Clock: time.Now})
		if err != nil {
			return err
		}
	}
	stage = "backup_child_https"
	server := httptest.NewTLSServer(httpapi.NewServer("", app.Auth, nil, app.Register).Handler)
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go app.RunFences(ctx)
	stage = "backup_child_ready"
	if err = json.NewEncoder(os.Stdout).Encode(childAddress{URL: server.URL, Certificate: base64.RawStdEncoding.EncodeToString(server.Certificate().Raw)}); err != nil {
		return err
	}
	h := &brChild{app: app, svc: svc, backups: backups, authority: authority, offhost: *offhost, root: *dir}
	decoder, encoder := json.NewDecoder(os.Stdin), json.NewEncoder(os.Stdout)
	for {
		var command brCommand
		if err = decoder.Decode(&command); err == io.EOF {
			return nil
		} else if err != nil {
			return err
		}
		operation, stop := context.WithTimeout(ctx, 5*time.Minute)
		answer, err := h.run(operation, command)
		stop()
		if err != nil {
			answer = brAnswer{Code: classifySmokeError(err), Stage: "backup_child_" + command.Kind}
		}
		if err = encoder.Encode(answer); err != nil {
			return err
		}
	}
}

type brChild struct {
	app       *appcore.App
	svc       *retention.Service
	backups   *backup.Service
	authority *backup.Authority
	offhost   string
	root      string
	recovery  auth.Credential
}

func (h *brChild) login(ctx context.Context, email, password string) (auth.Credential, auth.Session, error) {
	session, err := h.app.Auth.Login(ctx, email, password, "")
	if err != nil {
		return auth.Credential{}, auth.Session{}, err
	}
	c, err := h.app.Auth.Authenticate(ctx, session.Token)
	return c, session, err
}

func brID(s string) model.ID {
	id, _ := model.ParseID(s)
	return id
}

func (h *brChild) run(ctx context.Context, c brCommand) (brAnswer, error) {
	org, project, source, owner := brID(c.Org), brID(c.Project), brID(c.Source), brID(c.Owner)
	switch c.Kind {
	case "backup":
		credential, session, err := h.login(ctx, c.Email, c.Password)
		if err != nil {
			return brAnswer{}, err
		}
		defer h.app.Auth.Logout(ctx, session.Token)
		scope, err := h.app.Auth.InstanceScope(ctx, credential, "disaster drill backup")
		if err != nil {
			return brAnswer{}, err
		}
		destination, err := backup.NewLocalDestination(h.offhost)
		if err != nil {
			return brAnswer{}, err
		}
		started := time.Now()
		m, err := h.backups.Run(ctx, scope, destination)
		if err != nil {
			return brAnswer{}, err
		}
		a := brAnswer{OK: true}
		a.Backup = &brBackup{m.ID.String(), int64(m.CreatedAt), int64(m.CompletedAt), time.Since(started).Milliseconds(), len(m.Objects), uint64(m.Deletion.Sequence)}
		return a, nil
	case "delete":
		credential, session, err := h.login(ctx, c.Email, c.Password)
		if err != nil {
			return brAnswer{}, err
		}
		defer h.app.Auth.Logout(ctx, session.Token)
		scope, err := h.app.Auth.Authorize(ctx, credential, org, nil, auth.OrgAdmin)
		if err != nil {
			return brAnswer{}, err
		}
		var revision model.Revision
		if err = h.app.Control.View(ctx, func(st control.State) error { revision = st.Revision; return nil }); err != nil {
			return brAnswer{}, err
		}
		receipt, err := h.svc.Delete(ctx, scope, retention.DeleteRequest{CommandID: model.NewID(), ExpectedRevision: revision, Mode: model.DeleteHistoricalRange, OrgID: org, ProjectIDs: []model.ID{project}, Signals: []model.Kind{model.Metric}, Start: c.Start, End: c.End, Reason: "disaster drill deletion"})
		if err != nil {
			return brAnswer{}, err
		}
		for range 50 {
			if err = h.svc.RunOnce(ctx); err != nil {
				return brAnswer{}, err
			}
			if receipt, err = h.svc.PollDelete(ctx, scope, receipt.OperationID); err != nil {
				return brAnswer{}, err
			}
			if receipt.Phase == model.DeletePhaseComplete {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		current, err := h.authority.Current(ctx)
		if err != nil {
			return brAnswer{}, err
		}
		return brAnswer{OK: true, Phase: receipt.Phase, AuthoritySeq: current.Head.Sequence, AuthorityGen: current.Head.Generation, Tombstones: len(current.Tombstones)}, nil
	case "activate":
		started := time.Now()
		report, err := backup.Activate(ctx, backup.DestinationRoot(h.root), h.app, h.authority, time.Now)
		if err != nil {
			return brAnswer{}, err
		}
		return brAnswer{OK: true, Ready: h.app.Storage.RestoreReady() == nil, AuthorityGen: report.AuthorityGeneration, Tombstones: report.Tombstones, ActivateMillis: time.Since(started).Milliseconds()}, nil
	case "recover":
		token, err := h.app.Control.BootstrapToken()
		if err != nil {
			return brAnswer{}, err
		}
		session, err := h.app.Auth.Bootstrap(ctx, token, brRecoveryEmail, brRecoveryPassword)
		if err != nil {
			return brAnswer{}, err
		}
		if h.recovery, err = h.app.Auth.Authenticate(ctx, session.Token); err != nil {
			return brAnswer{}, err
		}
		reason := "disaster drill: verified against the original administrator ticket"
		for _, item := range []auth.Reconciliation{{Kind: auth.ReconcileAccount, User: owner}, {Kind: auth.ReconcileMembership, Org: org, User: owner}, {Kind: auth.ReconcileGrant, Org: org, User: owner, Project: project}} {
			item.Reason = reason
			if _, err = h.app.Auth.Reconcile(ctx, h.recovery, item); err != nil {
				return brAnswer{}, err
			}
		}
		issued, err := h.app.Auth.Reconcile(ctx, h.recovery, auth.Reconciliation{Kind: auth.ReconcileSource, Source: source, Reason: reason})
		if err != nil {
			return brAnswer{}, err
		}
		return brAnswer{OK: true, SourceToken: issued.Credential}, nil
	case "rows":
		credential, session, err := h.login(ctx, c.Email, c.Password)
		if err != nil {
			return brAnswer{}, err
		}
		defer h.app.Auth.Logout(ctx, session.Token)
		scope, err := h.app.Auth.Authorize(ctx, credential, org, []model.ID{project}, auth.Read)
		if err != nil {
			return brAnswer{}, err
		}
		it, err := h.app.Storage.Scan(ctx, scope, storage.ScanRequest{Projects: []model.ID{project}, Signal: model.Metric, End: 1 << 60})
		if err != nil {
			return brAnswer{}, err
		}
		defer it.Close()
		a := brAnswer{OK: true}
		for {
			p, err := it.Next(ctx)
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return brAnswer{}, err
			}
			for i := 0; i < p.Len(); i++ {
				a.Rows = append(a.Rows, int64(p.Times[i]))
			}
		}
		sort.Slice(a.Rows, func(i, j int) bool { return a.Rows[i] < a.Rows[j] })
		return a, nil
	case "login":
		_, session, err := h.login(ctx, c.Email, c.Password)
		if err != nil {
			return brAnswer{}, err
		}
		_ = h.app.Auth.Logout(ctx, session.Token)
		return brAnswer{OK: true}, nil
	case "state":
		a := brAnswer{OK: true}
		err := h.app.Control.View(ctx, func(st control.State) error {
			for _, o := range st.Orgs {
				for key := range o.Settings {
					if len(key) > 12 && key[:12] == "destination:" {
						a.Destinations++
					}
				}
			}
			a.Pending = auth.RestorePending(st)
			return nil
		})
		return a, err
	}
	return brAnswer{}, model.Fail(model.Invalid)
}

// ---- the drill ----

type brProcess struct {
	*smokeChild
	input  io.WriteCloser
	output *bufio.Reader
	mu     sync.Mutex
}

func launchBackupChild(args ...string) (*brProcess, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	command := exec.Command(exe, append([]string{"backup-restore-child"}, args...)...)
	stdout, err := command.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stdin, err := command.StdinPipe()
	if err != nil {
		return nil, err
	}
	command.Stderr = io.Discard
	if err = command.Start(); err != nil {
		return nil, err
	}
	p := &brProcess{smokeChild: &smokeChild{cmd: command}, input: stdin, output: bufio.NewReader(stdout)}
	type line struct {
		raw []byte
		err error
	}
	got := make(chan line, 1)
	go func() { raw, err := p.output.ReadBytes('\n'); got <- line{raw, err} }()
	select {
	case l := <-got:
		var address childAddress
		if l.err != nil || json.Unmarshal(l.raw, &address) != nil {
			p.kill()
			return nil, &smokeFailure{Stage: "backup_child_startup", Code: "decode"}
		}
		if address.Failure != nil {
			p.kill()
			return nil, &smokeFailure{Stage: address.Failure.Stage, Code: address.Failure.Code}
		}
		der, err := base64.RawStdEncoding.DecodeString(address.Certificate)
		if err != nil {
			p.kill()
			return nil, err
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			p.kill()
			return nil, err
		}
		pool := x509.NewCertPool()
		pool.AddCert(cert)
		jar, _ := cookiejar.New(nil)
		p.client = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}}, Jar: jar, Timeout: 30 * time.Second}
		p.address = address
	case <-time.After(60 * time.Second):
		p.kill()
		return nil, &smokeFailure{Stage: "backup_child_startup", Code: "timeout"}
	}
	return p, nil
}

func (p *brProcess) ask(c brCommand) (brAnswer, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	raw, err := json.Marshal(c)
	if err != nil {
		return brAnswer{}, err
	}
	if _, err = p.input.Write(append(raw, '\n')); err != nil {
		return brAnswer{}, err
	}
	type line struct {
		raw []byte
		err error
	}
	got := make(chan line, 1)
	go func() { raw, err := p.output.ReadBytes('\n'); got <- line{raw, err} }()
	select {
	case l := <-got:
		var a brAnswer
		if l.err != nil || json.Unmarshal(l.raw, &a) != nil {
			return brAnswer{}, &smokeFailure{Stage: "backup_child_" + c.Kind, Code: "decode"}
		}
		if !a.OK {
			return a, &smokeFailure{Stage: a.Stage, Code: a.Code}
		}
		return a, nil
	case <-time.After(6 * time.Minute):
		return brAnswer{}, &smokeFailure{Stage: "backup_child_" + c.Kind, Code: "timeout"}
	}
}

type brBatch struct {
	batch   model.Batch
	at      int64
	receipt model.Receipt
	raw     []byte
	ackedAt time.Time
}

func RunBackupRestore(args []string) (result error) {
	stage := "backup_flags"
	defer func() { result = annotateSmokeFailure("backup_restore", stage, model.ID{}, result) }()
	f := flag.NewFlagSet("backup-restore", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	artifact := f.String("artifact-dir", "", "sanitized artifacts")
	if err := f.Parse(args); err != nil {
		return err
	}
	if *artifact == "" {
		return errors.New("artifact directory required")
	}
	stage = "backup_directories"
	if err := os.MkdirAll(*artifact, 0700); err != nil {
		return err
	}
	work, err := os.MkdirTemp("", "soundpost-backup-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	live, offhost, authorityDir, keyDir, restored, restored2 := filepath.Join(work, "live"), filepath.Join(work, "offhost"), filepath.Join(work, "authority"), filepath.Join(work, "keys"), filepath.Join(work, "restored"), filepath.Join(work, "restored-2")
	stage = "backup_keys"
	for _, id := range []string{"smoke-data-kek", "smoke-secret-kek"} {
		key, err := backup.GenerateKey(id)
		if err != nil {
			return err
		}
		if err = backup.WriteKeyFile(keyDir, key); err != nil {
			return err
		}
	}
	authorityKeys, err := backup.GenerateAuthorityKeys("smoke-authority")
	if err != nil {
		return err
	}
	keysPath := filepath.Join(work, "authority-keys.json")
	if err = backup.WriteAuthorityKeys(keysPath, authorityKeys); err != nil {
		return err
	}
	stage = "backup_live_start"
	liveArgs := []string{"--mode", "live", "--data-dir", live, "--offhost-dir", offhost, "--key-dir", keyDir, "--authority-dir", authorityDir, "--authority-keys", keysPath}
	child, err := launchBackupChild(liveArgs...)
	if err != nil {
		return err
	}
	defer func() { child.kill() }()
	stage = "backup_bootstrap"
	token, err := os.ReadFile(filepath.Join(live, "bootstrap.token"))
	if err != nil {
		return err
	}
	status, raw, err := child.call("/api/v1/bootstrap", map[string]string{"Token": string(token), "Email": brOwnerEmail, "Password": brOwnerPassword}, "", "")
	if err = requireSmokeResponse("bootstrap", status, 200, raw, err); err != nil {
		return err
	}
	var session auth.Session
	if err = json.Unmarshal(raw, &session); err != nil {
		return err
	}
	org, project, source, sender := model.NewID(), model.NewID(), model.NewID(), model.NewID()
	admin := func(kind string, p auth.AdminPayload) error {
		status, raw, err := child.organizationsRead(session.CSRF)
		if err = requireSmokeResponse("admin_"+kind+"_revision", status, 200, raw, err); err != nil {
			return err
		}
		var view auth.AdminView
		if err = json.Unmarshal(raw, &view); err != nil {
			return err
		}
		p.Reason = "backup drill"
		payload, _ := json.Marshal(p)
		status, raw, err = child.call("/api/v1/admin/commands", auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: view.Revision, OrgID: org, Kind: kind, Payload: payload}, session.CSRF, "")
		return requireSmokeResponse("admin_"+kind, status, 200, raw, err)
	}
	stage = "backup_fixture"
	for _, step := range []struct {
		kind string
		p    auth.AdminPayload
	}{
		{"create_org", auth.AdminPayload{Name: "backup drill"}},
		{"create_project", auth.AdminPayload{ID: project, Name: "drill"}},
		{"membership", auth.AdminPayload{UserID: session.User, Enabled: true}},
		{"grant", auth.AdminPayload{UserID: session.User, ProjectID: project, Enabled: true, Permissions: []string{string(auth.Read)}}},
		{"destination", auth.AdminPayload{ID: sender, Config: json.RawMessage(`{"type":"webhook","endpoint":"https://hooks.example.test/notify","enabled":true}`), Secret: "drill sender secret"}},
	} {
		if err = admin(step.kind, step.p); err != nil {
			return err
		}
	}
	serviceID, environmentID, buildID := model.NewID(), model.NewID(), model.NewID()
	policy := model.SourcePolicy{Revision: 1, Enabled: true, Class: "structured", Kinds: []model.Kind{model.Metric}, Resources: model.ResourceRegistry{Services: []model.ID{serviceID}, Environments: []model.ID{environmentID}, Builds: []model.ID{buildID}, Instances: []string{"instance"}}, RetentionDays: map[model.Kind]uint32{model.Metric: 30}, MaxBytes: 1 << 30, MaxSeries: 100000}
	status, raw, err = child.call("/api/v1/sources", auth.SourceOnboarding{CommandID: model.NewID(), Org: org, Project: project, Source: source, Expires: model.UnixNano(time.Now().Add(time.Hour).UnixNano()), Policy: policy, Reason: "backup drill"}, session.CSRF, "")
	if err = requireSmokeResponse("source_onboard", status, 200, raw, err); err != nil {
		return err
	}
	var issued auth.SourceOnboarded
	if err = json.Unmarshal(raw, &issued); err != nil {
		return err
	}
	resource := model.Resource{Service: serviceID, Environment: environmentID, Build: buildID, Instance: "instance", Labels: model.Labels{}}
	var ledger []*brBatch
	var ledgerMu sync.Mutex
	send := func(at int64, name, credential string, cl *brProcess) (*brBatch, error) {
		v := model.FloatBits(0x3ff0000000000000)
		b := model.Batch{Version: 1, Project: project, Source: source, Producer: model.NewID(), ID: model.NewID(), PolicyRevision: 1, Records: []model.Record{{ID: model.NewID(), Kind: model.Metric, ObservedAt: model.UnixNano(at), Resource: resource, Payload: model.Payload{Metric: &model.MetricPoint{Name: name, Labels: model.Labels{}, SampleKind: "float", Value: &v, Type: "counter", Unit: "1"}}}}}
		b.RouteSlot, _ = model.OwnerSlot(org, project, source, b.Producer, b.Records[0])
		return brPost(cl, &brBatch{batch: b, at: at}, credential)
	}
	stage = "backup_phase_before"
	const before, deletedFrom, deletedTo = 40, 1000, 1010
	for i := range before {
		sent, err := send(int64(1000+i), "drill_before", issued.Credential, child)
		if err != nil {
			return err
		}
		ledger = append(ledger, sent)
	}
	// Intake continues while the backup copies: a writer ACKs batches throughout.
	stage = "backup_phase_during"
	stop := make(chan struct{})
	var during []*brBatch
	var writerErr error
	var writer sync.WaitGroup
	writer.Add(1)
	go func() {
		defer writer.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			sent, err := send(int64(2000+i), "drill_during", issued.Credential, child)
			if err != nil {
				ledgerMu.Lock()
				writerErr = err
				ledgerMu.Unlock()
				return
			}
			ledgerMu.Lock()
			during = append(during, sent)
			ledgerMu.Unlock()
		}
	}()
	backupStarted := time.Now()
	answer, err := child.ask(brCommand{Kind: "backup", Email: brOwnerEmail, Password: brOwnerPassword})
	backupFinished := time.Now()
	close(stop)
	writer.Wait()
	if err != nil {
		return err
	}
	if writerErr != nil {
		return writerErr
	}
	if answer.Backup == nil {
		return &smokeFailure{Stage: "backup_run", Code: "decode"}
	}
	stage = "backup_phase_after"
	var after []*brBatch
	for i := range 10 {
		sent, err := send(int64(3000+i), "drill_after", issued.Credential, child)
		if err != nil {
			return err
		}
		after = append(after, sent)
	}
	stage = "backup_delete"
	deletion, err := child.ask(brCommand{Kind: "delete", Email: brOwnerEmail, Password: brOwnerPassword, Org: org.String(), Project: project.String(), Start: deletedFrom, End: deletedTo})
	if err != nil {
		return err
	}
	if deletion.Phase != model.DeletePhaseComplete || deletion.AuthoritySeq < 1 || deletion.AuthoritySeq <= answer.Backup.Sequence {
		return &smokeFailure{Stage: "backup_delete", Code: "authority_checkpoint"}
	}
	stage = "backup_disaster"
	disaster := time.Now()
	if err = child.kill(); err != nil {
		return err
	}
	// ---- restore into a clean root, in this (separate) process ----
	stage = "backup_restore"
	source2, err := backup.NewLocalDestination(offhost)
	if err != nil {
		return err
	}
	keys := backup.KeyDir(keyDir)
	backupID, err := model.ParseID(answer.Backup.ID)
	if err != nil {
		return err
	}
	manifest, err := backup.LoadManifest(context.Background(), source2, backupID, keys)
	if err != nil {
		return err
	}
	authorityDest, err := backup.NewLocalDestination(authorityDir)
	if err != nil {
		return err
	}
	restoreAuthority, err := backup.NewAuthority(authorityDest, authorityKeys.Restricted(), time.Now)
	if err != nil {
		return err
	}
	restorer, err := backup.NewRestorer(backup.RestoreConfig{Keys: keys, Source: source2, Clock: time.Now})
	if err != nil {
		return err
	}
	restoreStarted := time.Now()
	report, err := restorer.Restore(context.Background(), manifest, backup.DestinationRoot(restored), restoreAuthority)
	if err != nil {
		return err
	}
	restoreDuration := time.Since(restoreStarted)
	stage = "backup_restored_start"
	second, err := launchBackupChild("--mode", "restored", "--data-dir", restored, "--authority-dir", authorityDir, "--authority-keys", keysPath, "--offhost-dir", offhost, "--key-dir", keyDir)
	if err != nil {
		return err
	}
	defer second.kill()
	// Before activation nothing is served: the old source credential is refused and so is its receipt lookup.
	stage = "backup_gated_before_activation"
	state, err := second.ask(brCommand{Kind: "state"})
	if err != nil {
		return err
	}
	if state.Pending == 0 || state.Destinations != 0 {
		return &smokeFailure{Stage: "backup_restored_state", Code: "senders_active"}
	}
	status, raw, err = second.call("/ingest/v1/batches", ledger[0].batch, "", issued.Credential)
	if err = requireSmokeResponse("old_credential_before_activation", status, 403, raw, err); err != nil {
		return err
	}
	stage = "backup_activate"
	activated, err := second.ask(brCommand{Kind: "activate"})
	if err != nil {
		return err
	}
	if !activated.Ready || activated.Tombstones != 1 || activated.AuthorityGen == 0 {
		return &smokeFailure{Stage: "backup_activate", Code: "not_ready"}
	}
	stage = "backup_old_credentials_dead"
	status, raw, err = second.call("/ingest/v1/batches", ledger[0].batch, "", issued.Credential)
	if err = requireSmokeResponse("old_credential_after_activation", status, 403, raw, err); err != nil {
		return err
	}
	stage = "backup_recover"
	recovered, err := second.ask(brCommand{Kind: "recover", Org: org.String(), Project: project.String(), Source: source.String(), Owner: session.User.String()})
	if err != nil || recovered.SourceToken == "" || recovered.SourceToken == issued.Credential {
		return &smokeFailure{Stage: "backup_recover", Code: "reconcile"}
	}
	status, raw, err = second.call("/ingest/v1/batches", ledger[0].batch, "", issued.Credential)
	if err = requireSmokeResponse("old_credential_after_reconcile", status, 403, raw, err); err != nil {
		return err
	}
	stage = "backup_rows"
	rows, err := second.ask(brCommand{Kind: "rows", Email: brOwnerEmail, Password: brOwnerPassword, Org: org.String(), Project: project.String()})
	if err != nil {
		return err
	}
	present := map[int64]bool{}
	for _, t := range rows.Rows {
		present[t] = true
	}
	// Exactness: everything ACKed before the backup started and not deleted is present; the deleted
	// range and everything ACKed after the backup finished is not.
	mustHave, mustNot := 0, 0
	for _, b := range ledger {
		deleted := b.at >= deletedFrom && b.at < deletedTo
		if deleted && present[b.at] {
			return &smokeFailure{Stage: "backup_rows", Code: "deleted_row_served"}
		}
		if !deleted {
			if !present[b.at] {
				return &smokeFailure{Stage: "backup_rows", Code: "acked_row_missing"}
			}
			mustHave++
		}
	}
	duringRestored := 0
	for _, b := range during {
		if present[b.at] {
			duringRestored++
		}
	}
	for _, b := range after {
		if present[b.at] {
			return &smokeFailure{Stage: "backup_rows", Code: "post_seal_row_present"}
		}
		mustNot++
	}
	// Receipts: a retry of every batch the backup held returns the original receipt byte for byte.
	stage = "backup_receipts"
	identical, readmitted, deletedRetries := 0, 0, 0
	gen1Receipts := map[model.ID]model.Receipt{}
	retry := func(b *brBatch) (int, model.Receipt, error) {
		status, raw, err := second.call("/ingest/v1/batches", b.batch, "", recovered.SourceToken)
		if err != nil {
			return 0, model.Receipt{}, err
		}
		var r model.Receipt
		if status == 200 {
			if err = json.Unmarshal(raw, &r); err == nil {
				gen1Receipts[b.batch.ID] = r // what generation 2 must answer for the same batch
			}
		}
		return status, r, err
	}
	for _, b := range append(append([]*brBatch{}, ledger...), during...) {
		deleted := b.at >= deletedFrom && b.at < deletedTo
		if !present[b.at] && !deleted {
			continue // not in the backup: handled below
		}
		status, got, err := retry(b)
		if err != nil {
			return err
		}
		if status != 200 {
			// A retry of a deleted batch may be refused by the restored tombstone; it must never be a success that revives data.
			if !deleted || status != 409 {
				return &smokeFailure{Stage: "backup_receipts", Code: "retry_refused", Actual: status, Expected: 200}
			}
			deletedRetries++
			continue
		}
		want, _ := model.CanonicalJSON(b.receipt)
		have, _ := model.CanonicalJSON(got)
		if !bytes.Equal(want, have) {
			return &smokeFailure{Stage: "backup_receipts", Code: "receipt_changed"}
		}
		identical++
	}
	for _, b := range after {
		if status, _, err := retry(b); err != nil || status != 200 {
			return &smokeFailure{Stage: "backup_receipts", Code: "readmit_refused", Actual: status, Expected: 200}
		}
		readmitted++ // ACKed after the seal: lost with the disaster, re-admitted when its client retries
	}
	for _, b := range during {
		if !present[b.at] {
			if status, _, err := retry(b); err != nil || status != 200 {
				return &smokeFailure{Stage: "backup_receipts", Code: "readmit_refused", Actual: status, Expected: 200}
			}
			readmitted++
		}
	}
	// A new write inside the deleted range is refused by the restored tombstone.
	inside, err := send(int64(deletedFrom+3), "late_inside_deleted_range", recovered.SourceToken, second)
	var refused *smokeFailure
	if inside != nil || !errors.As(err, &refused) || refused.Actual != 409 {
		return &smokeFailure{Stage: "backup_tombstone", Code: "late_write_not_refused"}
	}
	stage = "backup_state_after"
	final, err := second.ask(brCommand{Kind: "state"})
	if err != nil {
		return err
	}
	ledgerMu.Lock()
	all := append(append(append([]*brBatch{}, ledger...), during...), after...)
	ledgerMu.Unlock()
	sort.Slice(all, func(i, j int) bool { return all[i].at < all[j].at })
	sum := sha256.New()
	for _, b := range all {
		line, _ := model.CanonicalJSON(b.receipt)
		sum.Write([]byte(b.batch.ID.String() + " "))
		sum.Write(line)
		sum.Write([]byte("\n"))
	}
	var firstLost time.Time
	for _, b := range after {
		if firstLost.IsZero() || b.ackedAt.Before(firstLost) {
			firstLost = b.ackedAt
		}
	}
	// ---- generation 2: the restored installation takes its OWN backup, is lost, and that backup is restored ----
	stage = "backup_gen1_backup"
	gen1Backup, err := second.ask(brCommand{Kind: "backup", Email: brRecoveryEmail, Password: brRecoveryPassword})
	if err != nil {
		return err
	}
	if gen1Backup.Backup == nil {
		return &smokeFailure{Stage: "backup_gen1_backup", Code: "decode"}
	}
	stage = "backup_gen1_disaster"
	if err = second.kill(); err != nil {
		return err
	}
	stage = "backup_gen2_restore"
	gen2ID, err := model.ParseID(gen1Backup.Backup.ID)
	if err != nil {
		return err
	}
	manifest2, err := backup.LoadManifest(context.Background(), source2, gen2ID, keys)
	if err != nil {
		return err
	}
	restore2Started := time.Now()
	report2, err := restorer.Restore(context.Background(), manifest2, backup.DestinationRoot(restored2), restoreAuthority)
	if err != nil {
		return err
	}
	restore2Duration := time.Since(restore2Started)
	// What was ACTIVE in generation 1 is quarantined: the owner and the recovery admin it reauthorized,
	// the reissued source credential; senders were never reauthorized, so none is left to stash.
	if report2.Quarantined.Users != 2 || report2.Quarantined.Sources != 1 || report2.Quarantined.Integrations != 0 {
		return &smokeFailure{Stage: "backup_gen2_restore", Code: "quarantine_population"}
	}
	stage = "backup_gen2_start"
	third, err := launchBackupChild("--mode", "restored", "--data-dir", restored2, "--authority-dir", authorityDir, "--authority-keys", keysPath, "--offhost-dir", offhost, "--key-dir", keyDir)
	if err != nil {
		return err
	}
	defer third.kill()
	stage = "backup_gen2_gated_before_activation"
	state3, err := third.ask(brCommand{Kind: "state"})
	if err != nil {
		return err
	}
	if state3.Pending == 0 || state3.Destinations != 0 {
		return &smokeFailure{Stage: "backup_gen2_state", Code: "senders_active"}
	}
	oldCredentials := func(name string) error {
		for which, credential := range map[string]string{"generation_0": issued.Credential, "generation_1": recovered.SourceToken} {
			status, raw, err := third.call("/ingest/v1/batches", ledger[0].batch, "", credential)
			if err = requireSmokeResponse(which+"_source_credential_"+name, status, 403, raw, err); err != nil {
				return err
			}
		}
		return nil
	}
	if err = oldCredentials("before_activation"); err != nil {
		return err
	}
	stage = "backup_gen2_activate"
	activated2, err := third.ask(brCommand{Kind: "activate"})
	if err != nil {
		return err
	}
	if !activated2.Ready || activated2.Tombstones != 1 || activated2.AuthorityGen == 0 {
		return &smokeFailure{Stage: "backup_gen2_activate", Code: "not_ready"}
	}
	stage = "backup_gen2_old_credentials_dead"
	if err = oldCredentials("after_activation"); err != nil {
		return err
	}
	// The owner reauthorized in generation 1 and the generation 1 recovery admin are inactive again.
	for name, login := range map[string]brCommand{"owner": {Kind: "login", Email: brOwnerEmail, Password: brOwnerPassword}, "recovery_admin": {Kind: "login", Email: brRecoveryEmail, Password: brRecoveryPassword}} {
		if _, err = third.ask(login); err == nil {
			return &smokeFailure{Stage: "backup_gen2_inactive_" + name, Code: "login_without_reauthorization"}
		}
	}
	stage = "backup_gen2_recover"
	recovered2, err := third.ask(brCommand{Kind: "recover", Org: org.String(), Project: project.String(), Source: source.String(), Owner: session.User.String()})
	if err != nil || recovered2.SourceToken == "" || recovered2.SourceToken == issued.Credential || recovered2.SourceToken == recovered.SourceToken {
		return &smokeFailure{Stage: "backup_gen2_recover", Code: "reconcile"}
	}
	if err = oldCredentials("after_reconcile"); err != nil {
		return err
	}
	stage = "backup_gen2_rows"
	rows2, err := third.ask(brCommand{Kind: "rows", Email: brOwnerEmail, Password: brOwnerPassword, Org: org.String(), Project: project.String()})
	if err != nil {
		return err
	}
	present2 := map[int64]bool{}
	for _, t := range rows2.Rows {
		present2[t] = true
	}
	checkedRows2 := 0
	for _, b := range all {
		deleted := b.at >= deletedFrom && b.at < deletedTo
		if deleted && present2[b.at] {
			return &smokeFailure{Stage: "backup_gen2_rows", Code: "deleted_row_served"}
		}
		if !deleted {
			if !present2[b.at] {
				return &smokeFailure{Stage: "backup_gen2_rows", Code: "acked_row_missing"}
			}
			checkedRows2++
		}
	}
	stage = "backup_gen2_receipts"
	identical2 := 0
	for _, b := range all {
		deleted := b.at >= deletedFrom && b.at < deletedTo
		status, raw, err := third.call("/ingest/v1/batches", b.batch, "", recovered2.SourceToken)
		if err != nil {
			return err
		}
		if status != 200 {
			if !deleted || status != 409 {
				return &smokeFailure{Stage: "backup_gen2_receipts", Code: "retry_refused", Actual: status, Expected: 200}
			}
			continue
		}
		var got model.Receipt
		if err = json.Unmarshal(raw, &got); err != nil {
			return err
		}
		want, known := gen1Receipts[b.batch.ID]
		if !known {
			return &smokeFailure{Stage: "backup_gen2_receipts", Code: "receipt_unknown"}
		}
		wantJSON, _ := model.CanonicalJSON(want)
		gotJSON, _ := model.CanonicalJSON(got)
		if !bytes.Equal(wantJSON, gotJSON) {
			return &smokeFailure{Stage: "backup_gen2_receipts", Code: "receipt_changed"}
		}
		identical2++
	}
	stage = "backup_gen2_tombstone"
	inside2, err := send(int64(deletedFrom+4), "late_inside_deleted_range_generation_two", recovered2.SourceToken, third)
	var refused2 *smokeFailure
	if inside2 != nil || !errors.As(err, &refused2) || refused2.Actual != 409 {
		return &smokeFailure{Stage: "backup_gen2_tombstone", Code: "late_write_not_refused"}
	}
	final2, err := third.ask(brCommand{Kind: "state"})
	if err != nil {
		return err
	}
	stage = "backup_artifact"
	artifactJSON, err := json.MarshalIndent(map[string]any{
		"version": 1, "mode": "single-non-HA", "qualification": "local-process-drill-not-power-loss-not-multi-host",
		"backup":              map[string]any{"objects": answer.Backup.Objects, "duration_ms": answer.Backup.DurationMS, "intake_continued_during_copy": len(during) > 0, "authority_sequence_bound": answer.Backup.Sequence, "encrypted": true, "manifest_authenticated": true},
		"deletion":            map[string]any{"completed": true, "authority_sequence": deletion.AuthoritySeq, "authority_generation": deletion.AuthorityGen, "tombstones": deletion.Tombstones},
		"restore":             map[string]any{"duration_ms": restoreDuration.Milliseconds(), "authority_sequence_applied": report.AuthoritySequence, "tombstones": report.Tombstones, "gaps_verified": report.GapsVerified, "activate_ms": activated.ActivateMillis, "ready": activated.Ready, "quota_certificate": report.QuotaCertificate.String()},
		"acks":                map[string]any{"total": len(all), "before_backup": len(ledger), "during_backup": len(during), "after_backup": len(after), "ledger_sha256": hex.EncodeToString(sum.Sum(nil))},
		"results":             map[string]any{"acked_before_backup_present_or_deleted": mustHave, "deleted_range_rows_served": 0, "during_backup_restored": duringRestored, "during_backup_not_restored": len(during) - duringRestored, "after_backup_present_before_retry": 0, "after_backup_lost_then_readmitted": mustNot, "receipts_byte_identical": identical, "receipts_readmitted_after_loss": readmitted, "deleted_batch_retries_refused_by_tombstone": deletedRetries, "late_write_inside_deleted_range_refused": true},
		"measured_backup_rpo": map[string]any{"backup_window_ms": backupFinished.Sub(backupStarted).Milliseconds(), "disaster_after_backup_cut_ms": disaster.UnixMilli() - answer.Backup.CreatedNS/int64(time.Millisecond), "acked_batches_lost": len(after), "oldest_lost_ack_after_backup_done_ms": firstLost.Sub(backupFinished).Milliseconds(), "claim": "disaster RPO is the last complete verified backup; no backup-based single-node RPO is claimed"},
		"isolation":           map[string]any{"old_source_credential_refused": true, "old_source_refused_before_and_after_activation_and_reconcile": true, "recovery_admin_reconciled_items": 4, "senders_configured_after_restore": final.Destinations, "pending_reconciliation_items": final.Pending, "notifications_sent_by_restore": 0},
		"second_generation":   map[string]any{"backup_of_restored_installation_ms": gen1Backup.Backup.DurationMS, "restore_ms": restore2Duration.Milliseconds(), "activate_ms": activated2.ActivateMillis, "ready": activated2.Ready, "tombstones": activated2.Tombstones, "quarantined_users": report2.Quarantined.Users, "quarantined_sources": report2.Quarantined.Sources, "generation_0_and_1_source_credentials_refused_before_and_after_activation_and_reconcile": true, "owner_reauthorized_in_generation_1_inactive_until_reauthorized_again": true, "generation_1_recovery_admin_inactive": true, "rows_checked": checkedRows2, "receipts_byte_identical_to_generation_1": identical2, "late_write_inside_deleted_range_refused": true, "pending_reconciliation_items": final2.Pending, "senders_configured": final2.Destinations},
	}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(*artifact, "backup-restore.json"), artifactJSON, 0600)
}

func brPost(cl *brProcess, b *brBatch, credential string) (*brBatch, error) {
	status, raw, err := cl.call("/ingest/v1/batches", b.batch, "", credential)
	if err = requireSmokeResponse("ingest", status, 200, raw, err); err != nil {
		return nil, err
	}
	b.ackedAt = time.Now()
	b.raw = raw
	return b, json.Unmarshal(raw, &b.receipt)
}
