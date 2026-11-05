// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package backup_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"soundpost/internal/appcore"
	"soundpost/internal/auth"
	"soundpost/internal/backup"
	"soundpost/internal/control"
	"soundpost/internal/model"
	"soundpost/internal/replica"
	"soundpost/internal/retention"
	"soundpost/internal/storage"
)

// A live single-voter installation (the production appcore layout), a real
// retention service driving deletions into a real restore authority, and the
// backup service over the real engine. Every test below restores into a clean
// root with a real restorer; nothing is simulated beyond the failure injected.

const (
	ownerPassword = "owner long password 2026"
	userPassword  = "second user long password 2026"
)

type ack struct {
	batch   model.Batch
	at      int64
	receipt model.Receipt
	bytes   uint64
}

type live struct {
	t         *testing.T
	ctx       context.Context
	dir       string
	app       *appcore.App
	owner     auth.Credential
	ownerS    auth.Session
	org       model.ID
	project   model.ID
	source    model.ID
	sourceRaw string
	sourceC   auth.SourceCredential
	desc      model.SourceDescriptor
	sender    model.ID
	authDir   string
	authKeys  backup.AuthorityKeys
	authority *switchAuthority
	retention *retention.Service
	keys      backup.StaticKeys
	destDir   string
	dest      *backup.LocalDestination
	svc       *backup.Service
	plane     *hookPlane
	acked     []ack
}

// switchAuthority is the real authority with an injected outage.
type switchAuthority struct {
	inner *backup.Authority
	down  atomic.Bool
}

func (s *switchAuthority) fail() error {
	if s.down.Load() {
		return model.Fail(model.Unavailable)
	}
	return nil
}
func (s *switchAuthority) CheckpointDeletion(ctx context.Context, g retention.LedgerGeneration) (retention.AuthorityReceipt, error) {
	if err := s.fail(); err != nil {
		return retention.AuthorityReceipt{}, err
	}
	return s.inner.CheckpointDeletion(ctx, g)
}
func (s *switchAuthority) CurrentDeletionLedger(ctx context.Context) (replica.Ledger, error) {
	if err := s.fail(); err != nil {
		return replica.Ledger{}, err
	}
	return s.inner.CurrentDeletionLedger(ctx)
}
func (s *switchAuthority) CurrentDeletionTombstones(ctx context.Context) ([]model.DeletePredicate, error) {
	if err := s.fail(); err != nil {
		return nil, err
	}
	return s.inner.CurrentDeletionTombstones(ctx)
}
func (s *switchAuthority) Current(ctx context.Context) (backup.CurrentDeletion, error) {
	if err := s.fail(); err != nil {
		return backup.CurrentDeletion{}, err
	}
	return s.inner.Current(ctx)
}

// hookPlane lets a test commit data between the control cut and the data cut.
type hookPlane struct {
	backup.DataPlane
	afterBegin func()
}

func (p *hookPlane) Begin(ctx context.Context, cut storage.ControlCut) (backup.PlaneSession, error) {
	s, err := p.DataPlane.Begin(ctx, cut)
	if err == nil && p.afterBegin != nil {
		p.afterBegin()
	}
	return s, err
}

func newLive(t *testing.T) *live {
	t.Helper()
	l := &live{t: t, ctx: context.Background(), dir: filepath.Join(t.TempDir(), "live")}
	var err error
	if l.app, err = appcore.Open(l.dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.app.Close() })
	boot, _ := l.app.Control.BootstrapToken()
	if l.ownerS, err = l.app.Auth.Bootstrap(l.ctx, boot, "owner@example.test", ownerPassword); err != nil {
		t.Fatal(err)
	}
	if l.owner, err = l.app.Auth.Authenticate(l.ctx, l.ownerS.Token); err != nil {
		t.Fatal(err)
	}
	l.org, l.project, l.source, l.sender = model.NewID(), model.NewID(), model.NewID(), model.NewID()
	l.command("create_org", auth.AdminPayload{Name: "backed up org"})
	l.command("create_project", auth.AdminPayload{ID: l.project, Name: "p1"})
	l.command("membership", auth.AdminPayload{UserID: l.ownerS.User, Enabled: true})
	l.command("grant", auth.AdminPayload{UserID: l.ownerS.User, ProjectID: l.project, Enabled: true, Permissions: []string{string(auth.Read)}})
	l.command("destination", auth.AdminPayload{ID: l.sender, Config: json.RawMessage(`{"type":"webhook","endpoint":"https://hooks.example.test/notify","enabled":true}`), Secret: "sender signing secret"})
	policy := model.SourcePolicy{Revision: 1, Enabled: true, Class: "structured", Kinds: []model.Kind{model.Metric}, Resources: model.ResourceRegistry{Services: []model.ID{model.NewID()}, Environments: []model.ID{model.NewID()}, Builds: []model.ID{model.NewID()}, Instances: []string{"i"}}, RetentionDays: map[model.Kind]uint32{model.Metric: 14}, MaxBytes: 1 << 30, MaxSeries: 100000}
	issued, err := l.app.Auth.OnboardSource(l.ctx, l.owner, auth.SourceOnboarding{CommandID: model.NewID(), Org: l.org, Project: l.project, Source: l.source, Expires: model.UnixNano(time.Now().Add(48 * time.Hour).UnixNano()), Policy: policy, Reason: "backup fixture"})
	if err != nil {
		t.Fatal(err)
	}
	l.desc, l.sourceRaw = issued.Descriptor, issued.Credential
	if l.sourceC, err = l.app.Auth.AuthenticateSource(l.ctx, l.sourceRaw, "", false); err != nil {
		t.Fatal(err)
	}
	var installation model.ID
	_ = l.app.Control.View(l.ctx, func(st control.State) error { installation = st.Installation; return nil })
	l.authDir = filepath.Join(t.TempDir(), "authority")
	authDest, err := backup.NewLocalDestination(l.authDir)
	if err != nil {
		t.Fatal(err)
	}
	if l.authKeys, err = backup.GenerateAuthorityKeys("authority-key-1"); err != nil {
		t.Fatal(err)
	}
	real, err := backup.NewAuthority(authDest, l.authKeys, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = real.Initialize(l.ctx, installation); err != nil {
		t.Fatal(err)
	}
	l.authority = &switchAuthority{inner: real}
	l.retention = l.app.Retention
	if err = l.retention.UseAuthority(l.authority); err != nil {
		t.Fatal(err)
	}
	l.keys = backup.StaticKeys{}
	for _, id := range []string{"data-kek", "secret-kek"} {
		k, err := backup.GenerateKey(id)
		if err != nil {
			t.Fatal(err)
		}
		l.keys[id] = k
	}
	l.destDir = filepath.Join(t.TempDir(), "offhost")
	if l.dest, err = backup.NewLocalDestination(l.destDir); err != nil {
		t.Fatal(err)
	}
	plane := backup.EngineDataPlane(l.app.Storage)
	l.plane = &hookPlane{DataPlane: plane}
	l.svc, err = backup.New(backup.Config{Control: l.app.Control, Data: l.plane, Processed: backup.AppliedProcessed(plane), Authority: l.authority, Authorizer: l.app.Auth, Keys: l.keys, DataKEK: "data-kek", SecretKEK: "secret-kek", Attempts: backup.DirAttempts(filepath.Join(t.TempDir(), "attempts")), Clock: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func (l *live) command(kind string, p auth.AdminPayload) {
	l.t.Helper()
	p.Reason = "backup fixture"
	raw, _ := json.Marshal(p)
	var rev model.Revision
	if err := l.app.Control.View(l.ctx, func(st control.State) error { rev = st.Revision; return nil }); err != nil {
		l.t.Fatal(err)
	}
	if _, err := l.app.Auth.AdminCommand(l.ctx, l.owner, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: rev, OrgID: l.org, Kind: kind, Payload: raw}); err != nil {
		l.t.Fatal(kind, err)
	}
}

// normalize builds the exact normalized batch ingest would hand the engine.
func (l *live) normalize(b model.Batch) model.NormalizedBatch {
	l.t.Helper()
	scope, err := l.app.Auth.SourceScope(l.ctx, l.sourceC, false)
	if err != nil {
		l.t.Fatal(err)
	}
	src, err := l.app.Auth.SourceAuthority(l.ctx, l.sourceC, true)
	if err != nil {
		l.t.Fatal(err)
	}
	raw, err := model.CanonicalJSON(b)
	if err != nil {
		l.t.Fatal(err)
	}
	policy, _ := model.CanonicalJSON(src.Policy)
	now := time.Now()
	return model.NormalizedBatch{Batch: b, Org: l.desc.Org, Hash: model.HashCanonical(raw), Canonical: raw, PolicyEpoch: model.Uint64(scope.PolicyEpoch()), PolicyHash: model.HashCanonical(policy).String(), AdmissionAt: model.UnixNano(now.UnixNano()), Deadlines: []model.SignalDeadline{{Kind: model.Metric, RetainUntil: model.UnixNano(now.Add(14 * 24 * time.Hour).UnixNano())}}}
}
func (l *live) batchAt(at int64, name string) model.Batch {
	l.t.Helper()
	src, err := l.app.Auth.SourceAuthority(l.ctx, l.sourceC, true)
	if err != nil {
		l.t.Fatal(err)
	}
	v := model.FloatBits(0x3ff0000000000000)
	b := model.Batch{Version: 1, Project: l.desc.Project, Source: l.desc.Source, Producer: model.NewID(), ID: model.NewID(), PolicyRevision: 1, Records: []model.Record{{ID: model.NewID(), Kind: model.Metric, ObservedAt: model.UnixNano(at), Resource: model.Resource{Service: src.Policy.Resources.Services[0], Environment: src.Policy.Resources.Environments[0], Build: src.Policy.Resources.Builds[0], Instance: src.Policy.Resources.Instances[0]}, Payload: model.Payload{Metric: &model.MetricPoint{Name: name, Labels: model.Labels{}, SampleKind: "float", Value: &v, Type: "counter", Unit: "1"}}}}}
	slot, _ := model.OwnerSlot(l.desc.Org, b.Project, b.Source, b.Producer, b.Records[0])
	b.RouteSlot = slot
	return b
}

// append admits one metric row observed at `at` exactly like ingest: reserve, append, remember the ACK.
func (l *live) append(at int64, name string) ack {
	l.t.Helper()
	b := l.batchAt(at, name)
	n := l.normalize(b)
	scope, err := l.app.Auth.SourceScope(l.ctx, l.sourceC, false)
	if err != nil {
		l.t.Fatal(err)
	}
	if n.Reservation, err = l.app.Control.ReserveAdmission(l.ctx, scope, n); err != nil {
		l.t.Fatal(err)
	}
	receipt, err := l.app.Storage.Append(l.ctx, scope, n)
	if err != nil {
		l.t.Fatal(err)
	}
	a := ack{batch: b, at: at, receipt: receipt, bytes: uint64(n.Reservation.Bytes)}
	l.acked = append(l.acked, a)
	return a
}
func (l *live) reconcile() {
	l.t.Helper()
	if err := l.app.Control.ReconcileAdmissions(l.ctx); err != nil {
		l.t.Fatal(err)
	}
}
func (l *live) adminScope() auth.Scope {
	l.t.Helper()
	s, err := l.app.Auth.Authorize(l.ctx, l.owner, l.org, nil, auth.OrgAdmin)
	if err != nil {
		l.t.Fatal(err)
	}
	return s
}
func (l *live) backup() (backup.BackupManifest, error) {
	l.t.Helper()
	scope, err := l.app.Auth.InstanceScope(l.ctx, l.owner, "scheduled backup")
	if err != nil {
		l.t.Fatal(err)
	}
	return l.svc.Run(l.ctx, scope, l.dest)
}
func (l *live) mustBackup() backup.BackupManifest {
	l.t.Helper()
	m, err := l.backup()
	if err != nil {
		l.t.Fatal(err)
	}
	return m
}

// deleteRange deletes [start,end) metrics of the project through the real
// retention service and drives it until it stops making progress.
func (l *live) deleteRange(start, end int64) retention.DeleteReceipt {
	l.t.Helper()
	var rev model.Revision
	_ = l.app.Control.View(l.ctx, func(st control.State) error { rev = st.Revision; return nil })
	r, err := l.retention.Delete(l.ctx, l.adminScope(), retention.DeleteRequest{CommandID: model.NewID(), ExpectedRevision: rev, Mode: model.DeleteHistoricalRange, OrgID: l.org, ProjectIDs: []model.ID{l.project}, Signals: []model.Kind{model.Metric}, Start: model.UnixNano(start), End: model.UnixNano(end), Reason: "customer deletion request"})
	if err != nil {
		l.t.Fatal(err)
	}
	_ = l.retention.RunOnce(l.ctx)
	p, err := l.retention.PollDelete(l.ctx, l.adminScope(), r.OperationID)
	if err != nil {
		l.t.Fatal(err)
	}
	return p
}

func (l *live) rows(app *appcore.App, scope auth.Scope) (map[int64]bool, error) {
	it, err := app.Storage.Scan(l.ctx, scope, storage.ScanRequest{Projects: []model.ID{l.project}, Signal: model.Metric, End: 1 << 60})
	if err != nil {
		return nil, err
	}
	defer it.Close()
	out := map[int64]bool{}
	for {
		p, err := it.Next(l.ctx)
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return out, err
		}
		for i := 0; i < p.Len(); i++ {
			out[int64(p.Times[i])] = true
		}
	}
}
func (l *live) liveRows() map[int64]bool {
	l.t.Helper()
	scope, err := l.app.Auth.Authorize(l.ctx, l.owner, l.org, []model.ID{l.project}, auth.Read)
	if err != nil {
		l.t.Fatal(err)
	}
	rows, err := l.rows(l.app, scope)
	if err != nil {
		l.t.Fatal(err)
	}
	return rows
}

// ---- the restored side ----

type activation struct {
	*storage.Engine
	svc *retention.Service
}

func (a activation) RestoreDeletions(ctx context.Context, authority retention.Authority) error {
	return a.svc.Restore(ctx, authority)
}

type restored struct {
	l        *live
	root     string
	app      *appcore.App
	svc      *retention.Service
	recovery auth.Credential
	user     model.ID
	token    string
}

func (l *live) restorer(keys backup.KeyProvider, src backup.Destination) *backup.Restorer {
	l.t.Helper()
	r, err := backup.NewRestorer(backup.RestoreConfig{Keys: keys, Source: src, Clock: time.Now})
	if err != nil {
		l.t.Fatal(err)
	}
	return r
}
func (l *live) newRoot() string { return filepath.Join(l.t.TempDir(), "restored") }

func (l *live) restoreTo(root string, m backup.BackupManifest, ledger backup.DeletionLedger) (backup.RestoreReport, error) {
	return l.restorer(l.keys, l.dest).Restore(l.ctx, m, backup.DestinationRoot(root), ledger)
}

// open starts the restored installation exactly like a normal process start.
func (l *live) openRestored(root string) *restored {
	l.t.Helper()
	app, err := appcore.Open(root)
	if err != nil {
		l.t.Fatal(err)
	}
	l.t.Cleanup(func() { app.Close() })
	svc := app.Retention
	if err = svc.UseAuthority(l.authority); err != nil {
		l.t.Fatal(err)
	}
	return &restored{l: l, root: root, app: app, svc: svc}
}
func (r *restored) activate(ledger backup.DeletionLedger) (backup.ActivationReport, error) {
	return r.l.restorer(r.l.keys, r.l.dest).Activate(r.l.ctx, backup.DestinationRoot(r.root), activation{Engine: r.app.Storage, svc: r.svc}, ledger)
}

// recoveryAdmin bootstraps the fresh recovery admin from the one-time token the restore armed.
func (r *restored) recoveryAdmin() auth.Credential {
	r.l.t.Helper()
	token, err := r.app.Control.BootstrapToken()
	if err != nil {
		r.l.t.Fatal("the restore did not arm a one-time recovery bootstrap:", err)
	}
	s, err := r.app.Auth.Bootstrap(r.l.ctx, token, "recovery@example.test", "recovery long password 2026")
	if err != nil {
		r.l.t.Fatal(err)
	}
	r.token, r.user = token, s.User
	if r.recovery, err = r.app.Auth.Authenticate(r.l.ctx, s.Token); err != nil {
		r.l.t.Fatal(err)
	}
	return r.recovery
}
func (r *restored) reconcile(item auth.Reconciliation) auth.Reconciled {
	r.l.t.Helper()
	item.Reason = "verified against the current identity provider"
	out, err := r.app.Auth.Reconcile(r.l.ctx, r.recovery, item)
	if err != nil {
		r.l.t.Fatal(item.Kind, err)
	}
	return out
}

// reader reinstates the owner as the one explicitly reauthorized reader.
func (r *restored) reader() auth.Scope {
	r.l.t.Helper()
	r.recoveryAdmin()
	owner := r.l.ownerS.User
	r.reconcile(auth.Reconciliation{Kind: auth.ReconcileAccount, User: owner})
	r.reconcile(auth.Reconciliation{Kind: auth.ReconcileMembership, Org: r.l.org, User: owner})
	r.reconcile(auth.Reconciliation{Kind: auth.ReconcileGrant, Org: r.l.org, User: owner, Project: r.l.project})
	s, err := r.app.Auth.Login(r.l.ctx, "owner@example.test", ownerPassword, "")
	if err != nil {
		r.l.t.Fatal(err)
	}
	c, err := r.app.Auth.Authenticate(r.l.ctx, s.Token)
	if err != nil {
		r.l.t.Fatal(err)
	}
	scope, err := r.app.Auth.Authorize(r.l.ctx, c, r.l.org, []model.ID{r.l.project}, auth.Read)
	if err != nil {
		r.l.t.Fatal(err)
	}
	return scope
}

func code(err error) model.Code {
	var fault *model.Fault
	if errors.As(err, &fault) {
		return fault.Code
	}
	return ""
}
func fileExists(path string) bool { _, err := os.Stat(path); return err == nil }
func stageLeftovers(root string) []string {
	m, _ := filepath.Glob(root + ".restore-*")
	return m
}

// countingDest observes which objects a restore opens and when.
type countingDest struct {
	backup.Destination
	mu    sync.Mutex
	opens []string
}

func (c *countingDest) Open(ctx context.Context, name string) (io.ReadCloser, error) {
	c.mu.Lock()
	c.opens = append(c.opens, name)
	c.mu.Unlock()
	return c.Destination.Open(ctx, name)
}
func (c *countingDest) dataOpens() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, name := range c.opens {
		if strings.Contains(name, "/obj/") {
			n++
		}
	}
	return n
}

// ---------------------------------------------------------------------------

// A deletion completes after the backup was taken. A restore of that backup
// must suppress the deleted rows because it consults the CURRENT independent
// ledger before any data is read, not the backup's own (older) knowledge.
func TestRestoreRequiresCurrentDeletionLedger(t *testing.T) {
	l := newLive(t)
	l.append(100, "kept_early")
	l.append(200, "deleted_later")
	l.append(300, "kept_late")
	l.reconcile()
	before := l.mustBackup()
	if before.Deletion.Sequence != 0 {
		t.Fatalf("the first backup bound authority sequence %d", before.Deletion.Sequence)
	}
	staleAuthority := filepath.Join(t.TempDir(), "authority-before-deletion")
	copyTree(t, l.authDir, staleAuthority)
	if receipt := l.deleteRange(150, 250); receipt.Phase != model.DeletePhaseComplete {
		t.Fatalf("deletion did not complete: %+v", receipt)
	}
	if rows := l.liveRows(); rows[200] || !rows[100] || !rows[300] {
		t.Fatalf("live rows after deletion: %v", rows)
	}
	after := l.mustBackup()
	if after.Deletion.Sequence < 1 || after.Deletion.Tombstones != 1 {
		t.Fatalf("a backup after the deletion did not bind its authority generation: %+v", after.Deletion)
	}

	t.Run("the pre-deletion backup is restored with the current ledger applied", func(t *testing.T) {
		root := l.newRoot()
		report, err := l.restoreTo(root, before, l.authority)
		if err != nil {
			t.Fatal(err)
		}
		if report.AuthoritySequence < 1 || report.Tombstones != 1 {
			t.Fatalf("restore did not read the current authority head: %+v", report)
		}
		r := l.openRestored(root)
		if err = r.app.Storage.RestoreReady(); err == nil {
			t.Fatal("restored engine is ready before its deletion ledger was applied")
		}
		if _, err = r.activate(l.authority); err != nil {
			t.Fatal(err)
		}
		if _, err = r.activate(l.authority); err != nil {
			t.Fatalf("activation is not idempotent: %v", err)
		}
		rows, err := l.rows(r.app, r.reader())
		if err != nil {
			t.Fatal(err)
		}
		if rows[200] {
			t.Fatal("a row deleted AFTER the backup was served by the restored installation")
		}
		if !rows[100] || !rows[300] {
			t.Fatalf("restore lost ACKed rows that were never deleted: %v", rows)
		}
	})
	t.Run("no ledger, no restore", func(t *testing.T) {
		root := l.newRoot()
		dest := &countingDest{Destination: l.dest}
		if _, err := l.restorer(l.keys, dest).Restore(l.ctx, before, backup.DestinationRoot(root), nil); err == nil {
			t.Fatal("restore ran without a deletion ledger")
		}
		if dest.dataOpens() != 0 || fileExists(root) {
			t.Fatal("restore touched backup data or created a root without a ledger")
		}
	})
	t.Run("an authority older than the backup's own binding is a rollback", func(t *testing.T) {
		stale, err := backup.NewLocalDestination(staleAuthority)
		if err != nil {
			t.Fatal(err)
		}
		old, err := backup.NewAuthority(stale, l.authKeys.Restricted(), time.Now)
		if err != nil {
			t.Fatal(err)
		}
		root := l.newRoot()
		dest := &countingDest{Destination: l.dest}
		if _, err = l.restorer(l.keys, dest).Restore(l.ctx, after, backup.DestinationRoot(root), old); err == nil {
			t.Fatal("a restore accepted an authority that is behind the backup that names it")
		}
		if dest.dataOpens() != 0 || fileExists(root) || len(stageLeftovers(root)) != 0 {
			t.Fatal("a rolled-back authority let the restore read backup data")
		}
	})
	t.Run("a different authority is not this installation's authority", func(t *testing.T) {
		other, err := backup.NewLocalDestination(filepath.Join(t.TempDir(), "other"))
		if err != nil {
			t.Fatal(err)
		}
		keys, _ := backup.GenerateAuthorityKeys("other-key")
		a, _ := backup.NewAuthority(other, keys, time.Now)
		var installation model.ID
		_ = l.app.Control.View(l.ctx, func(st control.State) error { installation = st.Installation; return nil })
		if _, err = a.Initialize(l.ctx, installation); err != nil {
			t.Fatal(err)
		}
		root := l.newRoot()
		if _, err = l.restoreTo(root, before, a); err == nil || fileExists(root) {
			t.Fatal("a fresh authority with no history stood in for the real one")
		}
	})
}

// Sources and senders of the old installation never come back: not by
// possessing the old secret, not by a fresh login, not by reconciliation.
func TestRestoreDisablesSourcesAndSenders(t *testing.T) {
	l := newLive(t)
	l.append(100, "row")
	l.reconcile()
	oldDigest, err := l.app.Auth.BearerDigest(auth.SourceBearer, l.sourceRaw)
	if err != nil {
		t.Fatal(err)
	}
	m := l.mustBackup()
	root := l.newRoot()
	report, err := l.restoreTo(root, m, l.authority)
	if err != nil {
		t.Fatal(err)
	}
	if report.Quarantined.Sources != 1 || report.Quarantined.Integrations < 1 || report.Quarantined.Users < 1 {
		t.Fatalf("restore did not report what it disabled: %+v", report.Quarantined)
	}
	r := l.openRestored(root)
	if _, err = r.activate(l.authority); err != nil {
		t.Fatal(err)
	}
	// The old source secret is dead on arrival and stays dead after a recovery admin logs in.
	if _, err = r.app.Auth.AuthenticateSource(l.ctx, l.sourceRaw, "", false); code(err) != model.Forbidden {
		t.Fatalf("the old source credential works in the restored installation: %v", err)
	}
	r.recoveryAdmin()
	if _, err = r.app.Auth.AuthenticateSource(l.ctx, l.sourceRaw, "", false); code(err) != model.Forbidden {
		t.Fatalf("a recovery login revived the old source credential: %v", err)
	}
	newDigest, err := r.app.Auth.BearerDigest(auth.SourceBearer, l.sourceRaw)
	if err != nil || newDigest == oldDigest {
		t.Fatal("the bearer hash key was not replaced: a digest from before the restore can still match")
	}
	// Senders: nothing outbound is configured, and the sealed secret is not in the active org state.
	var destinations, secrets int
	_ = r.app.Control.View(l.ctx, func(st control.State) error {
		o := st.Orgs[l.org.String()]
		for key := range o.Settings {
			if strings.HasPrefix(key, "destination:") || strings.HasPrefix(key, "sso:") {
				destinations++
			}
		}
		secrets = len(o.Secrets)
		if auth.RestorePending(st) == 0 {
			t.Fatal("nothing awaits reconciliation after a restore")
		}
		return nil
	})
	if destinations != 0 || secrets != 0 {
		t.Fatalf("the restored installation can still deliver externally (%d destinations, %d secrets)", destinations, secrets)
	}
	// Explicit reconciliation returns a NEW source credential; the old one stays dead.
	issued := r.reconcile(auth.Reconciliation{Kind: auth.ReconcileSource, Source: l.source})
	if issued.Credential == "" || issued.Credential == l.sourceRaw {
		t.Fatal("reconciliation did not mint a new credential")
	}
	if _, err = r.app.Auth.AuthenticateSource(l.ctx, issued.Credential, "", false); err != nil {
		t.Fatalf("new source credential refused: %v", err)
	}
	if _, err = r.app.Auth.AuthenticateSource(l.ctx, l.sourceRaw, "", false); code(err) != model.Forbidden {
		t.Fatalf("reconciliation revived the old secret: %v", err)
	}
	// Neither secret nor sender material is anywhere on the restored disk in the clear.
	_ = filepath.WalkDir(root, func(path string, e os.DirEntry, err error) error {
		if err != nil || e.IsDir() {
			return nil
		}
		raw, _ := os.ReadFile(path)
		for _, secret := range []string{l.sourceRaw, "sender signing secret", ownerPassword} {
			if bytes.Contains(raw, []byte(secret)) {
				t.Errorf("%s holds a plaintext secret", path)
			}
		}
		return nil
	})
	// The recovery token is the only bootstrap, and it was single use.
	if _, err = r.app.Auth.Bootstrap(l.ctx, r.token, "again@example.test", "another long password 2026"); err == nil {
		t.Fatal("the one-time recovery token was reusable")
	}
}

func TestMissingObjectAndWrongKeyFailClosed(t *testing.T) {
	l := newLive(t)
	l.append(100, "row")
	l.reconcile()
	m := l.mustBackup()
	prefix := "backups/" + m.ID.String() + "/"
	names, err := l.dest.List(l.ctx, prefix)
	if err != nil || len(names) < 64+4 {
		t.Fatalf("a backup should hold the manifest, key objects, bundle, control objects and 64 snapshot streams: %d %v", len(names), err)
	}
	find := func(sub string) string {
		for _, n := range names {
			if strings.Contains(n, sub) {
				return n
			}
		}
		t.Fatalf("no object matching %q", sub)
		return ""
	}
	failed := func(t *testing.T, root string, dest backup.Destination, keys backup.KeyProvider, wantNoData bool) {
		t.Helper()
		counted := &countingDest{Destination: dest}
		_, err := l.restorer(keys, counted).Restore(l.ctx, m, backup.DestinationRoot(root), l.authority)
		if err == nil {
			t.Fatal("restore succeeded although the backup is unusable")
		}
		if fileExists(root) || len(stageLeftovers(root)) != 0 {
			t.Fatalf("a failed restore left a root or staging directory behind: %v", stageLeftovers(root))
		}
		if wantNoData && counted.dataOpens() != 0 {
			t.Fatalf("a restore with the wrong key read %d data objects", counted.dataOpens())
		}
	}
	// copyDest gives each case its own damaged copy of the backup.
	damaged := func(t *testing.T, mutate func(dir string)) backup.Destination {
		t.Helper()
		dir := filepath.Join(t.TempDir(), "copy")
		copyTree(t, l.destDir, dir)
		mutate(dir)
		d, err := backup.NewLocalDestination(dir)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	path := func(dir, name string) string { return filepath.Join(dir, filepath.FromSlash(name)) }
	t.Run("a missing snapshot object", func(t *testing.T) {
		d := damaged(t, func(dir string) {
			if err := os.Remove(path(dir, find("slot-07"))); err != nil {
				t.Fatal(err)
			}
		})
		failed(t, l.newRoot(), d, l.keys, false)
	})
	t.Run("a missing control object", func(t *testing.T) {
		d := damaged(t, func(dir string) { _ = os.Remove(path(dir, find("control-state"))) })
		failed(t, l.newRoot(), d, l.keys, false)
	})
	t.Run("a missing wrapped key", func(t *testing.T) {
		d := damaged(t, func(dir string) { _ = os.Remove(path(dir, find("/key/"))) })
		failed(t, l.newRoot(), d, l.keys, true)
	})
	t.Run("a flipped byte in a snapshot object", func(t *testing.T) {
		d := damaged(t, func(dir string) {
			p := path(dir, find("slot-31"))
			raw, _ := os.ReadFile(p)
			raw[len(raw)/2] ^= 1
			_ = os.WriteFile(p, raw, 0600)
		})
		failed(t, l.newRoot(), d, l.keys, false)
	})
	t.Run("a truncated snapshot object", func(t *testing.T) {
		d := damaged(t, func(dir string) {
			p := path(dir, find("slot-12"))
			raw, _ := os.ReadFile(p)
			_ = os.WriteFile(p, raw[:len(raw)-17], 0600)
		})
		failed(t, l.newRoot(), d, l.keys, false)
	})
	t.Run("two snapshot objects swapped", func(t *testing.T) {
		d := damaged(t, func(dir string) {
			a, b := path(dir, find("slot-01")), path(dir, find("slot-02"))
			ra, _ := os.ReadFile(a)
			rb, _ := os.ReadFile(b)
			_ = os.WriteFile(a, rb, 0600)
			_ = os.WriteFile(b, ra, 0600)
		})
		failed(t, l.newRoot(), d, l.keys, false)
	})
	t.Run("the wrong data key", func(t *testing.T) {
		wrong, _ := backup.GenerateKey("data-kek")
		keys := backup.StaticKeys{"data-kek": wrong, "secret-kek": l.keys["secret-kek"]}
		failed(t, l.newRoot(), l.dest, keys, true)
		if _, err := backup.LoadManifest(l.ctx, l.dest, m.ID, keys); err == nil {
			t.Fatal("a manifest verified under the wrong key")
		}
	})
	t.Run("the wrong secret key", func(t *testing.T) {
		wrong, _ := backup.GenerateKey("secret-kek")
		keys := backup.StaticKeys{"data-kek": l.keys["data-kek"], "secret-kek": wrong}
		failed(t, l.newRoot(), l.dest, keys, true)
	})
	t.Run("a retired key that is no longer available", func(t *testing.T) {
		failed(t, l.newRoot(), l.dest, backup.StaticKeys{"data-kek": l.keys["data-kek"]}, true)
	})
	t.Run("a manifest whose recorded authority binding was altered", func(t *testing.T) {
		raw := readDest(t, l.dest, backup.ManifestName(m.ID))
		forged := bytes.Replace(raw, []byte(`"sequence":"0"`), []byte(`"sequence":"9"`), 1)
		if bytes.Equal(raw, forged) {
			t.Fatal("fixture: manifest has no sequence field to alter")
		}
		d := damaged(t, func(dir string) { _ = os.WriteFile(path(dir, backup.ManifestName(m.ID)), forged, 0600) })
		if _, err := backup.LoadManifest(l.ctx, d, m.ID, l.keys); err == nil {
			t.Fatal("an edited manifest verified")
		}
	})
	t.Run("an expired backup is never restored", func(t *testing.T) {
		counted := &countingDest{Destination: l.dest}
		late, err := backup.NewRestorer(backup.RestoreConfig{Keys: l.keys, Source: counted, Clock: func() time.Time { return time.Now().Add(31 * 24 * time.Hour) }})
		if err != nil {
			t.Fatal(err)
		}
		root := l.newRoot()
		if _, err = late.Restore(l.ctx, m, backup.DestinationRoot(root), l.authority); code(err) != model.Stale {
			t.Fatalf("an expired backup was restored or failed for another reason: %v", err)
		}
		if counted.dataOpens() != 0 || fileExists(root) {
			t.Fatal("an expired backup was read")
		}
	})
	t.Run("the intact backup still restores", func(t *testing.T) {
		root := l.newRoot()
		if _, err := l.restoreTo(root, m, l.authority); err != nil {
			t.Fatalf("the same backup, undamaged: %v", err)
		}
		if !fileExists(filepath.Join(root, "data", "apply.db")) {
			t.Fatal("restored root is missing its data store")
		}
	})
	t.Run("an existing root is never overwritten", func(t *testing.T) {
		root := l.newRoot()
		if err := os.MkdirAll(root, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "precious"), []byte("keep"), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := l.restoreTo(root, m, l.authority); err == nil {
			t.Fatal("restore wrote into a non-empty root")
		}
		if string(mustRead(t, filepath.Join(root, "precious"))) != "keep" {
			t.Fatal("the existing root was modified")
		}
	})
}

func readDest(t *testing.T, d backup.Destination, name string) []byte {
	t.Helper()
	r, err := d.Open(context.Background(), name)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	raw, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func copyTree(t *testing.T, from, to string) {
	t.Helper()
	err := filepath.WalkDir(from, func(path string, e os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(from, path)
		target := filepath.Join(to, rel)
		if e.IsDir() {
			return os.MkdirAll(target, 0700)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, raw, 0600)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// An authority outage leaves deletion in the fencing phase: nothing is reported
// complete, the deleted data is already hidden, and neither a backup nor a
// restore proceeds without the authority.
func TestAuthorityFailurePreventsCompletedDeletion(t *testing.T) {
	l := newLive(t)
	l.append(100, "kept")
	l.append(200, "to_delete")
	l.reconcile()
	m := l.mustBackup()
	l.authority.down.Store(true)
	receipt := l.deleteRange(150, 250)
	if receipt.Phase != model.DeletePhaseFencing {
		t.Fatalf("deletion reported %q while the authority was down", receipt.Phase)
	}
	if rows := l.liveRows(); rows[200] || !rows[100] {
		t.Fatalf("a fencing deletion must already hide the data: %v", rows)
	}
	var op model.DeletionOperation
	_ = l.app.Control.View(l.ctx, func(st control.State) error { op = st.Deletions[receipt.OperationID.String()]; return nil })
	if op.Phase == model.DeletePhaseComplete || op.Authority != nil {
		t.Fatalf("the deletion recorded completion without an authority receipt: %+v", op)
	}
	// While the authority is unavailable no backup is taken and no restore starts.
	if _, err := l.backup(); err == nil {
		t.Fatal("a backup was taken without a verifiable deletion authority")
	}
	root := l.newRoot()
	dest := &countingDest{Destination: l.dest}
	if _, err := l.restorer(l.keys, dest).Restore(l.ctx, m, backup.DestinationRoot(root), l.authority); err == nil {
		t.Fatal("restore proceeded while the authority was unavailable")
	}
	if dest.dataOpens() != 0 || fileExists(root) {
		t.Fatal("restore read backup data before the authority was verified")
	}
	// Recovery: the same deletion completes with a durable, verified receipt.
	l.authority.down.Store(false)
	if err := l.retention.RunOnce(l.ctx); err != nil {
		t.Fatal(err)
	}
	p, err := l.retention.PollDelete(l.ctx, l.adminScope(), receipt.OperationID)
	if err != nil || p.Phase != model.DeletePhaseComplete {
		t.Fatalf("after recovery: %+v %v", p, err)
	}
	_ = l.app.Control.View(l.ctx, func(st control.State) error { op = st.Deletions[receipt.OperationID.String()]; return nil })
	cur, err := l.authority.Current(l.ctx)
	if err != nil || op.Authority == nil || op.Authority.Head != cur.Head.Digest || uint64(op.Authority.Generation) != cur.Head.Generation {
		t.Fatalf("control's completion receipt does not name the authority head: %+v vs %+v (%v)", op.Authority, cur.Head, err)
	}
	// And the pre-deletion backup now restores with the row suppressed.
	root = l.newRoot()
	if _, err = l.restoreTo(root, m, l.authority); err != nil {
		t.Fatal(err)
	}
	r := l.openRestored(root)
	if _, err = r.activate(l.authority); err != nil {
		t.Fatal(err)
	}
	rows, err := l.rows(r.app, r.reader())
	if err != nil || rows[200] || !rows[100] {
		t.Fatalf("restored rows %v (%v)", rows, err)
	}
}

// After the backup: a session logs out, a token is revoked, an admin is
// demoted. A restore cannot undo any of it, and a fresh login restores no
// former grant before an audited reauthorization.
func TestRestoreNeverReactivatesRevokedIdentity(t *testing.T) {
	l := newLive(t)
	l.append(100, "row")
	l.reconcile()
	// Identities that exist when the backup is taken.
	admin, reader := model.NewID(), model.NewID()
	l.command("create_user", auth.AdminPayload{ID: admin, Email: "admin2@example.test", Password: userPassword})
	l.command("create_user", auth.AdminPayload{ID: reader, Email: "reader2@example.test", Password: userPassword})
	l.command("membership", auth.AdminPayload{UserID: admin, Enabled: true})
	l.command("org_admin", auth.AdminPayload{UserID: admin, Enabled: true})
	l.command("membership", auth.AdminPayload{UserID: reader, Enabled: true})
	l.command("grant", auth.AdminPayload{UserID: reader, ProjectID: l.project, Enabled: true, Permissions: []string{string(auth.Read)}})
	readerSession, err := l.app.Auth.Login(l.ctx, "reader2@example.test", userPassword, "")
	if err != nil {
		t.Fatal(err)
	}
	token, err := l.app.Auth.IssueServerToken(l.ctx, l.owner, l.org, reader, []model.ID{l.project}, []auth.Permission{auth.Read}, time.Now().Add(time.Hour).Unix(), "automation")
	if err != nil {
		t.Fatal(err)
	}
	oldBearer, _ := l.app.Auth.BearerDigest(auth.ServerAPIBearer, token.Token)
	var oldSealedBearer string
	_ = l.app.Control.View(l.ctx, func(st control.State) error { oldSealedBearer = st.BearerHashKey; return nil })
	m := l.mustBackup()

	// After the backup: logout, token revocation, demotion.
	if err = l.app.Auth.Logout(l.ctx, readerSession.Token); err != nil {
		t.Fatal(err)
	}
	if err = l.app.Auth.RevokeServerToken(l.ctx, l.owner, l.org, token.ID, "leaked"); err != nil {
		t.Fatal(err)
	}
	l.command("org_admin", auth.AdminPayload{UserID: admin, Enabled: false})
	l.command("grant", auth.AdminPayload{UserID: reader, ProjectID: l.project, Enabled: false})

	root := l.newRoot()
	if _, err = l.restoreTo(root, m, l.authority); err != nil {
		t.Fatal(err)
	}
	r := l.openRestored(root)
	if _, err = r.activate(l.authority); err != nil {
		t.Fatal(err)
	}
	// Nothing minted before the restore authenticates: the demotion/revocation are not undone because nothing is active.
	for name, credential := range map[string]string{"owner session": l.ownerS.Token, "reader session": readerSession.Token, "revoked token": token.Token} {
		if _, err = r.app.Auth.Authenticate(l.ctx, credential); code(err) != model.Unauthenticated {
			t.Fatalf("%s authenticates after the restore: %v", name, err)
		}
	}
	if digest, _ := r.app.Auth.BearerDigest(auth.ServerAPIBearer, token.Token); digest == oldBearer {
		t.Fatal("old decryption material still derives the old bearer digest: the key was not replaced")
	}
	for _, login := range [][2]string{{"owner@example.test", ownerPassword}, {"admin2@example.test", userPassword}, {"reader2@example.test", userPassword}} {
		if _, err = r.app.Auth.Login(l.ctx, login[0], login[1], ""); code(err) != model.Unauthenticated {
			t.Fatalf("%s logged in with a restored password: %v", login[0], err)
		}
	}
	// The old envelope keys still decrypt stored secrets, and that confers nothing.
	if _, err = r.app.Control.OpenSecret(oldSealedBearer); err != nil {
		t.Fatalf("old keys must still decrypt old stored secrets: %v", err)
	}
	// A fresh recovery admin sees no former grant; being an instance admin is not an org grant.
	r.recoveryAdmin()
	if _, err = r.app.Auth.Authorize(l.ctx, r.recovery, l.org, []model.ID{l.project}, auth.Read); code(err) != model.NotFound {
		t.Fatalf("a fresh login read a restored project: %v", err)
	}
	if _, err = r.app.Auth.Authorize(l.ctx, r.recovery, l.org, nil, auth.OrgAdmin); code(err) != model.NotFound {
		t.Fatalf("a fresh login administers a restored organization: %v", err)
	}
	// Reauthorizing the owner's account alone grants nothing; the grant must be named too.
	r.reconcile(auth.Reconciliation{Kind: auth.ReconcileAccount, User: l.ownerS.User})
	s, err := r.app.Auth.Login(l.ctx, "owner@example.test", ownerPassword, "")
	if err != nil {
		t.Fatal(err)
	}
	c, _ := r.app.Auth.Authenticate(l.ctx, s.Token)
	if _, err = r.app.Auth.Authorize(l.ctx, c, l.org, []model.ID{l.project}, auth.Read); code(err) != model.NotFound {
		t.Fatalf("account reauthorization restored a grant: %v", err)
	}
	r.reconcile(auth.Reconciliation{Kind: auth.ReconcileMembership, Org: l.org, User: l.ownerS.User})
	r.reconcile(auth.Reconciliation{Kind: auth.ReconcileGrant, Org: l.org, User: l.ownerS.User, Project: l.project})
	if _, err = r.app.Auth.Authorize(l.ctx, c, l.org, []model.ID{l.project}, auth.Read); err != nil {
		t.Fatalf("the explicitly reauthorized grant does not work: %v", err)
	}
	// The demoted admin and the revoked reader were never named: they stay inactive.
	for _, login := range [][2]string{{"admin2@example.test", userPassword}, {"reader2@example.test", userPassword}} {
		if _, err = r.app.Auth.Login(l.ctx, login[0], login[1], ""); code(err) != model.Unauthenticated {
			t.Fatalf("%s became active without reauthorization: %v", login[0], err)
		}
	}
	var audited int
	_ = r.app.Control.View(l.ctx, func(st control.State) error {
		for _, a := range st.Audits {
			if strings.HasPrefix(a.Action, "restore.reconcile.") && a.Principal == r.user && a.Reason != "" {
				audited++
			}
		}
		return nil
	})
	if audited != 3 {
		t.Fatalf("%d audited reauthorizations, want 3", audited)
	}
}

// Everything ACKed up to the data cut survives: receipts stay byte-identical
// (including a batch admitted between the control cut and the data cut), typed
// rows read back, quota is charged exactly once, and a deletion's tombstone also
// rejects a late write in the restored engine.
func TestRestoreReconcilesReceiptsTypedRowsQuotaAndTombstones(t *testing.T) {
	l := newLive(t)
	first := l.append(100, "before_cut")
	mid := l.append(250, "deleted_after_backup")
	l.reconcile()
	var late ack
	l.plane.afterBegin = func() { late = l.append(400, "between_control_cut_and_data_cut"); l.reconcile() }
	m := l.mustBackup()
	l.plane.afterBegin = nil
	// ACKed after the data cut: outside the backup's RPO window by design.
	lost := l.append(500, "after_seal")
	l.reconcile()
	if receipt := l.deleteRange(150, 350); receipt.Phase != model.DeletePhaseComplete {
		t.Fatalf("deletion did not complete: %+v", receipt)
	}
	root := l.newRoot()
	report, err := l.restoreTo(root, m, l.authority)
	if err != nil {
		t.Fatal(err)
	}
	if report.QuotaCertificate == (model.Hash{}) || report.GapsVerified != 0 {
		t.Fatalf("restore report: %+v", report)
	}
	r := l.openRestored(root)
	scope := r.reader()
	if _, err = l.rows(r.app, scope); code(err) != model.Unavailable {
		t.Fatalf("the restored engine served reads before its deletion ledger was applied: %v", err)
	}
	act, err := r.activate(l.authority)
	if err != nil || act.Tombstones != 1 {
		t.Fatalf("activation: %+v %v", act, err)
	}
	if err = r.app.Storage.RestoreReady(); err != nil {
		t.Fatalf("restored engine not ready after activation: %v", err)
	}
	rows, err := l.rows(r.app, scope)
	if err != nil {
		t.Fatal(err)
	}
	if !rows[100] || !rows[400] || rows[250] || rows[500] {
		t.Fatalf("typed rows after restore (want 100 and 400 only): %v", rows)
	}
	// Quota: exactly one charge per consumed reservation in the data cut (including the one created after the control cut).
	sourceKey := "source:" + l.org.String() + ":" + l.project.String() + ":" + l.source.String()
	want := first.bytes + mid.bytes + late.bytes
	quota := func() model.QuotaState {
		var q model.QuotaState
		_ = r.app.Control.View(l.ctx, func(st control.State) error { q = st.Quotas[sourceKey]; return nil })
		return q
	}
	if q := quota(); uint64(q.Bytes) != want {
		t.Fatalf("restored quota charge is %d bytes, the data cut consumed %d", q.Bytes, want)
	}
	issued := r.reconcile(auth.Reconciliation{Kind: auth.ReconcileSource, Source: l.source})
	sourceC, err := r.app.Auth.AuthenticateSource(l.ctx, issued.Credential, "", false)
	if err != nil {
		t.Fatal(err)
	}
	retry := func(a ack) (model.Receipt, error) {
		sc, err := r.app.Auth.SourceScope(l.ctx, sourceC, false)
		if err != nil {
			t.Fatal(err)
		}
		n := l.normalizeWith(r.app, sourceC, a.batch)
		if n.Reservation, err = r.app.Control.ReserveAdmission(l.ctx, sc, n); err != nil {
			return model.Receipt{}, err
		}
		return r.app.Storage.Append(l.ctx, sc, n)
	}
	// Receipts of ACKed, undeleted batches come back byte-identical, with no second quota charge.
	for name, a := range map[string]ack{"admitted before the cut": first, "admitted between the control cut and the data cut": late} {
		got, err := retry(a)
		if err != nil || !sameJSON(t, got, a.receipt) {
			t.Fatalf("%s: receipt changed or retry refused: %v", name, err)
		}
	}
	if q := quota(); uint64(q.Bytes) != want {
		t.Fatalf("retrying ACKed batches changed the charge to %d (want %d): the reservation was not reconstructed", q.Bytes, want)
	}
	// The receipt of a deleted batch still resolves (an ACK is a historical fact; C03), while its rows stay hidden (asserted above).
	if got, err := retry(mid); err != nil || !sameJSON(t, got, mid.receipt) {
		t.Fatalf("the original receipt of a deleted batch was lost or changed: %v", err)
	}
	// Any NEW write inside the deleted range is rejected by the restored tombstone.
	inside := ack{batch: l.batchAt(260, "late_write_inside_deleted_range")}
	if _, err = retry(inside); code(err) != model.Conflict {
		t.Fatalf("a late write inside the deleted range was admitted: %v", err)
	}
	// Data ACKed after the data cut is not in the backup; its client retries and is admitted anew.
	if _, err = retry(lost); err != nil {
		t.Fatalf("a client retry of a batch the backup never held must be admitted: %v", err)
	}
	// Intake outside the deleted range works.
	if _, err = retry(ack{batch: l.batchAt(900, "after_restore")}); err != nil {
		t.Fatalf("a restored installation refuses new writes after reconciliation: %v", err)
	}
}

func mustSourceScope(t *testing.T, l *live) auth.Scope {
	t.Helper()
	s, err := l.app.Auth.SourceScope(l.ctx, l.sourceC, false)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// normalizeWith normalizes under another installation's source credential.
func (l *live) normalizeWith(app *appcore.App, c auth.SourceCredential, b model.Batch) model.NormalizedBatch {
	l.t.Helper()
	scope, err := app.Auth.SourceScope(l.ctx, c, false)
	if err != nil {
		l.t.Fatal(err)
	}
	src, err := app.Auth.SourceAuthority(l.ctx, c, true)
	if err != nil {
		l.t.Fatal(err)
	}
	raw, _ := model.CanonicalJSON(b)
	policy, _ := model.CanonicalJSON(src.Policy)
	now := time.Now()
	return model.NormalizedBatch{Batch: b, Org: l.desc.Org, Hash: model.HashCanonical(raw), Canonical: raw, PolicyEpoch: model.Uint64(scope.PolicyEpoch()), PolicyHash: model.HashCanonical(policy).String(), AdmissionAt: model.UnixNano(now.UnixNano()), Deadlines: []model.SignalDeadline{{Kind: model.Metric, RetainUntil: model.UnixNano(now.Add(14 * 24 * time.Hour).UnixNano())}}}
}
func sameJSON(t *testing.T, a, b any) bool {
	t.Helper()
	x, _ := model.CanonicalJSON(a)
	y, _ := model.CanonicalJSON(b)
	return bytes.Equal(x, y)
}

type fixedProcessed map[model.ID]uint64

func (f fixedProcessed) Processed(ctx context.Context, group model.ID) (uint64, error) {
	return f[group], nil
}

// Evidence the live processors never consumed and retention reclaimed before the
// backup began is a hole in (H, D]. The backup may declare it only as a gap control
// COMMITTED (RecordEvidenceGap) at or before the cut; the restore re-verifies every
// gap against the control state inside the backup.
func TestBackupDeclaresAndRestoreVerifiesOnlyCommittedGaps(t *testing.T) {
	l := newLive(t)
	l.append(100, "processed_before_h")
	l.reconcile()
	plane := backup.EngineDataPlane(l.app.Storage)
	h := fixedProcessed{}
	for _, c := range plane.Applied() {
		h[c.Group] = uint64(c.Index)
	}
	perSlot := map[uint16]uint64{}
	for i := range 5 {
		a := l.append(int64(200+i), "unprocessed_then_reclaimed")
		perSlot[a.batch.RouteSlot]++
	}
	l.reconcile()
	// The live retention worker reclaims the journal behind a verified snapshot.
	if _, err := l.app.Storage.CreateSnapshots(l.ctx); err != nil {
		t.Fatal(err)
	}
	if err := l.app.Storage.CompactJournals(l.ctx); err != nil {
		t.Fatal(err)
	}
	svc, err := backup.New(backup.Config{Control: l.app.Control, Data: l.plane, Processed: h, Authority: l.authority, Authorizer: l.app.Auth, Keys: l.keys, DataKEK: "data-kek", SecretKEK: "secret-kek", Attempts: backup.DirAttempts(filepath.Join(t.TempDir(), "attempts")), Clock: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	scope, err := l.app.Auth.InstanceScope(l.ctx, l.owner, "gap backup")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.Run(l.ctx, scope, l.dest); err == nil {
		t.Fatal("a backup sealed over a hole control never declared")
	}
	// Control commits the gaps (as the retention worker does before evidence expires); now the same backup succeeds.
	for slot, n := range perSlot {
		group := plane.Applied()[slot].Group
		after := h[group]
		if _, err = l.app.Control.RecordEvidenceGap(l.ctx, model.EvidenceGap{Org: l.org, Project: l.project, Group: group, After: model.Uint64(after), Through: model.Uint64(after + n), Count: model.Uint64(n), Start: 200, End: 204, Signals: []model.Kind{model.Metric}, Reason: "unprocessed_expiry", RecordedAt: model.UnixNano(time.Now().UnixNano())}); err != nil {
			t.Fatal(err)
		}
	}
	scope, err = l.app.Auth.InstanceScope(l.ctx, l.owner, "gap backup")
	if err != nil {
		t.Fatal(err)
	}
	m, err := svc.Run(l.ctx, scope, l.dest)
	if err != nil {
		t.Fatalf("committed gaps did not explain the hole: %v", err)
	}
	if len(m.Gaps) != len(perSlot) {
		t.Fatalf("manifest attests %d gaps, %d slots had holes", len(m.Gaps), len(perSlot))
	}
	for _, g := range m.Gaps {
		if g.ControlRevision != m.Control.Revision || g.Digest == (model.Hash{}) || g.Fact == (model.ID{}) {
			t.Fatalf("gap attestation incomplete: %+v", g)
		}
	}
	root := l.newRoot()
	report, err := l.restoreTo(root, m, l.authority)
	if err != nil {
		t.Fatal(err)
	}
	if report.GapsVerified != len(perSlot) {
		t.Fatalf("restore verified %d gaps, want %d", report.GapsVerified, len(perSlot))
	}
	r := l.openRestored(root)
	scopeR := r.reader()
	if _, err = r.activate(l.authority); err != nil {
		t.Fatal(err)
	}
	rows, err := l.rows(r.app, scopeR)
	if err != nil || !rows[100] || !rows[200] || !rows[204] {
		t.Fatalf("the data behind the declared gaps (snapshots hold full bytes) must restore: %v %v", rows, err)
	}
	// A manifest re-signed with a widened attestation is rejected by the restore's own re-verification.
	forged := m
	forged.Gaps = append([]backup.GapAttestation(nil), m.Gaps...)
	forged.Gaps[0].Through++
	if err = backup.ResignForTest(&forged, l.keys["data-kek"]); err != nil {
		t.Fatal(err)
	}
	if _, err = l.restoreTo(l.newRoot(), forged, l.authority); err == nil {
		t.Fatal("a widened gap attestation was accepted at restore")
	}
	dropped := m
	dropped.Gaps = nil
	if err = backup.ResignForTest(&dropped, l.keys["data-kek"]); err != nil {
		t.Fatal(err)
	}
	if _, err = l.restoreTo(l.newRoot(), dropped, l.authority); err == nil {
		t.Fatal("a certificate gap with no attestation was accepted at restore")
	}
}
