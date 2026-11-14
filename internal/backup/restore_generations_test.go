// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package backup_test

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/backup"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/retention"
)

// ---- helpers shared by the lifecycle tests below ----

// commandFor runs an admin command against org (live.command is bound to l.org).
func (l *live) commandFor(org model.ID, kind string, p auth.AdminPayload) {
	l.t.Helper()
	p.Reason = "backup fixture"
	raw, _ := json.Marshal(p)
	var rev model.Revision
	if err := l.app.Control.View(l.ctx, func(st control.State) error { rev = st.Revision; return nil }); err != nil {
		l.t.Fatal(err)
	}
	if _, err := l.app.Auth.AdminCommand(l.ctx, l.owner, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: rev, OrgID: org, Kind: kind, Payload: raw}); err != nil {
		l.t.Fatal(kind, err)
	}
}

// backup takes a backup of the RESTORED installation the way its own nightly job would:
// the service is built over the restored application, authorized by its recovery admin.
func (r *restored) backup(reason string) backup.BackupManifest {
	r.l.t.Helper()
	plane := backup.EngineDataPlane(r.app.Storage)
	svc, err := backup.New(backup.Config{Control: r.app.Control, Data: plane, Processed: backup.AppliedProcessed(plane), Authority: r.l.authority, Authorizer: r.app.Auth, Keys: r.l.keys, DataKEK: "data-kek", SecretKEK: "secret-kek", Attempts: backup.DirAttempts(filepath.Join(r.l.t.TempDir(), "attempts")), Clock: time.Now})
	if err != nil {
		r.l.t.Fatal(err)
	}
	scope, err := r.app.Auth.InstanceScope(r.l.ctx, r.recovery, reason)
	if err != nil {
		r.l.t.Fatal(err)
	}
	m, err := svc.Run(r.l.ctx, scope, r.l.dest)
	if err != nil {
		r.l.t.Fatalf("the restored installation could not take its own backup: %v", err)
	}
	return m
}

// writeRow admits one batch into the restored installation under a source credential it issued.
func (r *restored) writeRow(c auth.SourceCredential, at int64, name string) {
	r.l.t.Helper()
	b := r.l.batchAt(at, name)
	n := r.l.normalizeWith(r.app, c, b)
	scope, err := r.app.Auth.SourceScope(r.l.ctx, c, false)
	if err != nil {
		r.l.t.Fatal(err)
	}
	if n.Reservation, err = r.app.Control.ReserveAdmission(r.l.ctx, scope, n); err != nil {
		r.l.t.Fatal(err)
	}
	if _, err = r.app.Storage.Append(r.l.ctx, scope, n); err != nil {
		r.l.t.Fatal(err)
	}
	if err = r.app.Control.ReconcileAdmissions(r.l.ctx); err != nil {
		r.l.t.Fatal(err)
	}
}

func (r *restored) reconcileErr(item auth.Reconciliation) error {
	item.Reason = "verified against the current identity provider"
	_, err := r.app.Auth.Reconcile(r.l.ctx, r.recovery, item)
	return err
}

// ---- CR-1: a restored installation's own backups are restorable ----

// The normal situation weeks after a disaster: restore, bootstrap the recovery
// admin, reauthorize a user, take the nightly backup, and later restore THAT backup
// (the only surviving copy). Every generation starts from nothing: whatever was
// active in the source installation, including the previous generation's
// reauthorizations, is inactive again until named.
func TestABackupOfARestoredInstallationRestoresAgain(t *testing.T) {
	l := newLive(t)
	reader := model.NewID()
	l.command("create_user", auth.AdminPayload{ID: reader, Email: "reader2@example.test", Password: userPassword})
	l.command("membership", auth.AdminPayload{UserID: reader, Enabled: true})
	l.command("grant", auth.AdminPayload{UserID: reader, ProjectID: l.project, Enabled: true, Permissions: []string{string(auth.Read)}})
	readerSession, err := l.app.Auth.Login(l.ctx, "reader2@example.test", userPassword, "")
	if err != nil {
		t.Fatal(err)
	}
	serverToken, err := l.app.Auth.IssueServerToken(l.ctx, l.owner, l.org, reader, []model.ID{l.project}, []auth.Permission{auth.Read}, time.Now().Add(time.Hour).Unix(), "automation")
	if err != nil {
		t.Fatal(err)
	}
	l.append(100, "generation_zero")
	l.reconcile()
	m0 := l.mustBackup()

	// ---- generation 1: restore, activate, reauthorize ONE user and a new source credential ----
	root1 := l.newRoot()
	if _, err = l.restoreTo(root1, m0, l.authority); err != nil {
		t.Fatal(err)
	}
	r1 := l.openRestored(root1)
	if _, err = r1.activate(l.authority); err != nil {
		t.Fatal(err)
	}
	r1.recoveryAdmin()
	recovery1 := r1.user
	recoverySession1, err := r1.app.Auth.Login(l.ctx, "recovery@example.test", "recovery long password 2026", "")
	if err != nil {
		t.Fatal(err)
	}
	owner := l.ownerS.User
	r1.reconcile(auth.Reconciliation{Kind: auth.ReconcileAccount, User: owner})
	r1.reconcile(auth.Reconciliation{Kind: auth.ReconcileMembership, Org: l.org, User: owner})
	r1.reconcile(auth.Reconciliation{Kind: auth.ReconcileGrant, Org: l.org, User: owner, Project: l.project})
	ownerSession1, err := r1.app.Auth.Login(l.ctx, "owner@example.test", ownerPassword, "")
	if err != nil {
		t.Fatalf("the user reauthorized in generation 1 cannot log in: %v", err)
	}
	issued1 := r1.reconcile(auth.Reconciliation{Kind: auth.ReconcileSource, Source: l.source})
	source1, err := r1.app.Auth.AuthenticateSource(l.ctx, issued1.Credential, "", false)
	if err != nil {
		t.Fatal(err)
	}
	r1.writeRow(source1, 700, "generation_one")
	m1 := r1.backup("nightly backup of a restored installation")
	// The backup carries the installation's data, not the bookkeeping of the restore that built it.
	state1, err := backup.ControlStateForTest(l.ctx, l.restorer(l.keys, l.dest), m1)
	if err != nil {
		t.Fatal(err)
	}
	if _, carried := state1.OIDC["restore:quarantine"]; carried {
		t.Fatal("the backup carries the quarantine stash of the restore that built the installation")
	}
	var holdsStash bool
	_ = r1.app.Control.View(l.ctx, func(st control.State) error { _, holdsStash = st.OIDC["restore:quarantine"]; return nil })
	if !holdsStash {
		t.Fatal("fixture: the restored installation holds no stash, so there was nothing to strip")
	}

	// ---- generation 2: restore the backup the restored installation took ----
	root2 := l.newRoot()
	report, err := l.restoreTo(root2, m1, l.authority)
	if err != nil {
		t.Fatalf("a backup of a restored installation cannot be restored: %v", err)
	}
	// Quarantined are the accounts and sources that were ACTIVE in the source: the owner and the
	// recovery admin of generation 1, and the source credential reissued in generation 1.
	if report.Quarantined.Users != 2 || report.Quarantined.Sources != 1 {
		t.Fatalf("the second generation quarantined the wrong population: %+v", report.Quarantined)
	}
	r2 := l.openRestored(root2)
	if _, err = r2.activate(l.authority); err != nil {
		t.Fatal(err)
	}
	for name, token := range map[string]string{
		"generation 0 owner session":    l.ownerS.Token,
		"generation 0 reader session":   readerSession.Token,
		"generation 0 server token":     serverToken.Token,
		"generation 1 owner session":    ownerSession1.Token,
		"generation 1 recovery session": recoverySession1.Token,
	} {
		if _, err = r2.app.Auth.Authenticate(l.ctx, token); code(err) != model.Unauthenticated {
			t.Fatalf("%s authenticates in generation 2: %v", name, err)
		}
	}
	for name, credential := range map[string]string{"the original source credential": l.sourceRaw, "the credential reissued in generation 1": issued1.Credential} {
		if _, err = r2.app.Auth.AuthenticateSource(l.ctx, credential, "", false); code(err) != model.Forbidden {
			t.Fatalf("%s works in generation 2: %v", name, err)
		}
	}
	for _, login := range [][2]string{{"owner@example.test", ownerPassword}, {"reader2@example.test", userPassword}, {"recovery@example.test", "recovery long password 2026"}} {
		if _, err = r2.app.Auth.Login(l.ctx, login[0], login[1], ""); code(err) != model.Unauthenticated {
			t.Fatalf("%s is active in generation 2 without reauthorization: %v", login[0], err)
		}
	}
	var destinations, secrets int
	_ = r2.app.Control.View(l.ctx, func(st control.State) error {
		o := st.Orgs[l.org.String()]
		for key := range o.Settings {
			if strings.HasPrefix(key, "destination:") || strings.HasPrefix(key, "sso:") {
				destinations++
			}
		}
		secrets = len(o.Secrets)
		if auth.RestorePending(st) == 0 {
			t.Fatal("nothing awaits reconciliation in generation 2")
		}
		return nil
	})
	if destinations != 0 || secrets != 0 {
		t.Fatalf("generation 2 can still deliver externally (%d destinations, %d secrets)", destinations, secrets)
	}

	// The operator bootstraps the recovery admin again (same address): a NEW account that holds nothing.
	r2.recoveryAdmin()
	if r2.user == recovery1 {
		t.Fatal("generation 2 reused the generation 1 recovery account")
	}
	if _, err = r2.app.Auth.Authorize(l.ctx, r2.recovery, l.org, []model.ID{l.project}, auth.Read); code(err) != model.NotFound {
		t.Fatalf("a fresh generation 2 login read a project: %v", err)
	}
	if _, err = r2.app.Auth.Authorize(l.ctx, r2.recovery, l.org, nil, auth.OrgAdmin); code(err) != model.NotFound {
		t.Fatalf("a fresh generation 2 login administers an organization: %v", err)
	}

	// The user reauthorized in generation 1 is inactive again: the account alone grants nothing; the grant must be named again.
	r2.reconcile(auth.Reconciliation{Kind: auth.ReconcileAccount, User: owner})
	session, err := r2.app.Auth.Login(l.ctx, "owner@example.test", ownerPassword, "")
	if err != nil {
		t.Fatalf("the owner cannot log in after being reauthorized in generation 2: %v", err)
	}
	ownerCredential, err := r2.app.Auth.Authenticate(l.ctx, session.Token)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r2.app.Auth.Authorize(l.ctx, ownerCredential, l.org, []model.ID{l.project}, auth.Read); code(err) != model.NotFound {
		t.Fatalf("reauthorizing the account restored a grant: %v", err)
	}
	r2.reconcile(auth.Reconciliation{Kind: auth.ReconcileMembership, Org: l.org, User: owner})
	r2.reconcile(auth.Reconciliation{Kind: auth.ReconcileGrant, Org: l.org, User: owner, Project: l.project})
	scope, err := r2.app.Auth.Authorize(l.ctx, ownerCredential, l.org, []model.ID{l.project}, auth.Read)
	if err != nil {
		t.Fatalf("the explicitly reauthorized grant does not work in generation 2: %v", err)
	}
	rows, err := l.rows(r2.app, scope)
	if err != nil || !rows[100] || !rows[700] {
		t.Fatalf("generation 2 lost ACKed rows from generations 0 and 1: %v %v", rows, err)
	}

	// Items that generation 1 never reauthorized are not carried over by the stash of the NEXT restore:
	// they stay inactive and are not reconcilable (restore the older backup to see them).
	if err = r2.reconcileErr(auth.Reconciliation{Kind: auth.ReconcileAccount, User: reader}); code(err) != model.NotFound {
		t.Fatalf("an account nobody reauthorized in generation 1 is reconcilable in generation 2: %v", err)
	}
	if err = r2.reconcileErr(auth.Reconciliation{Kind: auth.ReconcileIntegration, Org: l.org, Key: "destination:" + l.sender.String()}); code(err) != model.NotFound {
		t.Fatalf("the sender nobody reauthorized in generation 1 is reconcilable in generation 2: %v", err)
	}
	if _, err = r2.app.Auth.Login(l.ctx, "reader2@example.test", userPassword, ""); code(err) != model.Unauthenticated {
		t.Fatalf("the unreauthorized reader became active: %v", err)
	}
	// The source is reissued once more; both earlier secrets stay dead.
	issued2 := r2.reconcile(auth.Reconciliation{Kind: auth.ReconcileSource, Source: l.source})
	if _, err = r2.app.Auth.AuthenticateSource(l.ctx, issued2.Credential, "", false); err != nil {
		t.Fatalf("the generation 2 source credential is refused: %v", err)
	}
	for _, old := range []string{l.sourceRaw, issued1.Credential} {
		if _, err = r2.app.Auth.AuthenticateSource(l.ctx, old, "", false); code(err) != model.Forbidden {
			t.Fatalf("reconciliation revived an earlier source secret: %v", err)
		}
	}
}

// ---- IMP-2: the current ledger may name organizations the backup never knew ----

// The independent authority is installation-wide and monotonic. A backup taken
// before an organization existed is restored AFTER that organization was retired,
// so the ledger Activate must apply names an organization the restored control
// state does not contain. Activation must still complete, record the tombstone as
// a deny predicate, and keep the retired organization from ever appearing.
func TestActivationAppliesALedgerNamingAnOrganizationCreatedAfterTheBackup(t *testing.T) {
	l := newLive(t)
	l.append(100, "kept")
	l.reconcile()
	before := l.mustBackup()
	if before.Deletion.Tombstones != 0 {
		t.Fatalf("the backup already holds a tombstone: %+v", before.Deletion)
	}

	x := model.NewID()
	l.commandFor(x, "create_org", auth.AdminPayload{Name: "created after the backup"})
	scope, err := l.app.Auth.Authorize(l.ctx, l.owner, x, nil, auth.OrgAdmin)
	if err != nil {
		t.Fatal(err)
	}
	var revision model.Revision
	_ = l.app.Control.View(l.ctx, func(st control.State) error { revision = st.Revision; return nil })
	receipt, err := l.retention.Delete(l.ctx, scope, retention.DeleteRequest{CommandID: model.NewID(), ExpectedRevision: revision, Mode: model.DeleteRetireOrg, OrgID: x, Reason: "customer closed the organization"})
	if err != nil {
		t.Fatal(err)
	}
	// The retired organization's own scope is dead once the retirement begins, so progress is read from control.
	var op model.DeletionOperation
	for range 20 {
		_ = l.retention.RunOnce(l.ctx)
		var found bool
		if op, found, err = l.app.Control.DeletionOperation(l.ctx, receipt.OperationID); err != nil || !found {
			t.Fatalf("the retirement operation vanished: %v", err)
		}
		if op.Phase == model.DeletePhaseComplete {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if op.Phase != model.DeletePhaseComplete {
		t.Fatalf("the retirement did not complete: %+v", op)
	}

	root := l.newRoot()
	report, err := l.restoreTo(root, before, l.authority)
	if err != nil {
		t.Fatal(err)
	}
	if report.Tombstones != 1 {
		t.Fatalf("restore did not read the current ledger: %+v", report)
	}
	r := l.openRestored(root)
	if _, err = r.activate(l.authority); err != nil {
		t.Fatalf("activation dead-ends on a ledger naming an organization the backup never knew: %v", err)
	}
	if err = r.app.Storage.RestoreReady(); err != nil {
		t.Fatalf("the restored engine is not ready after activation: %v", err)
	}
	var known bool
	var retired bool
	_ = r.app.Control.View(l.ctx, func(st control.State) error {
		_, known = st.Orgs[x.String()]
		_, retired = st.RetiredOrgs[x.String()]
		return nil
	})
	if known {
		t.Fatal("importing a tombstone invented an organization")
	}
	if !retired {
		t.Fatal("the tombstone of an unknown organization recorded no retirement")
	}
	if tombstones, err := r.app.Control.ActiveDeletions(l.ctx, x, nil); err != nil || len(tombstones) != 1 || tombstones[0].Operation != receipt.OperationID {
		t.Fatalf("the unknown organization's tombstone is not a deny predicate: %v %v", tombstones, err)
	}
	// The retired organization cannot be created again in the restored installation.
	reader := r.reader()
	var current model.Revision
	_ = r.app.Control.View(l.ctx, func(st control.State) error { current = st.Revision; return nil })
	raw, _ := json.Marshal(auth.AdminPayload{Name: "reappeared", Reason: "attempt"})
	if _, err = r.app.Auth.AdminCommand(l.ctx, r.recovery, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: current, OrgID: x, Kind: "create_org", Payload: raw}); code(err) != model.NotFound {
		t.Fatalf("a retired organization was created again: %v", err)
	}
	// The restored organization is intact.
	rows, err := l.rows(r.app, reader)
	if err != nil || !rows[100] {
		t.Fatalf("restore lost the organization the backup held: %v %v", rows, err)
	}
}

// ---- MIN-2: activation never accepts an authority older than the one restore verified ----

func TestActivationRefusesAnAuthorityOlderThanTheOneRestoreVerified(t *testing.T) {
	l := newLive(t)
	l.append(100, "kept")
	l.append(200, "deleted_later")
	l.reconcile()
	before := l.mustBackup()
	staleDir := filepath.Join(t.TempDir(), "authority-before-deletion")
	copyTree(t, l.authDir, staleDir)
	if receipt := l.deleteRange(150, 250); receipt.Phase != model.DeletePhaseComplete {
		t.Fatalf("deletion did not complete: %+v", receipt)
	}
	// Restore verifies the CURRENT ledger (it already holds the deletion)...
	root := l.newRoot()
	if report, err := l.restoreTo(root, before, l.authority); err != nil || report.AuthoritySequence < 1 {
		t.Fatalf("restore: %+v %v", report, err)
	}
	// ...and the authority is rolled back between restore and activation. The rolled-back journal is
	// a valid prefix and still satisfies the backup's own binding, so only the position restore saw
	// can notice that a completed deletion has been dropped.
	stale, err := backup.NewLocalDestination(staleDir)
	if err != nil {
		t.Fatal(err)
	}
	old, err := backup.NewAuthority(stale, l.authKeys.Restricted(), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	r := l.openRestored(root)
	if _, err = r.activate(old); code(err) != model.Conflict {
		t.Fatalf("activation accepted an authority older than the one restore verified: %v", err)
	}
	if err = r.app.Storage.RestoreReady(); err == nil {
		t.Fatal("the restored engine opened under a rolled-back deletion ledger")
	}
	if _, err = r.activate(l.authority); err != nil {
		t.Fatalf("the current authority no longer activates the root: %v", err)
	}
	rows, err := l.rows(r.app, r.reader())
	if err != nil || rows[200] || !rows[100] {
		t.Fatalf("rows after activation: %v %v", rows, err)
	}
}

// lyingLedger is the real, verified journal with one fact of its answer altered (a copy: the
// real answer is never mutated), so a test can break exactly one clause of the restore's
// comparison against a backup's binding.
type lyingLedger struct {
	real   backup.DeletionLedger
	mutate func(*backup.CurrentDeletion)
}

func (l *lyingLedger) Current(ctx context.Context) (backup.CurrentDeletion, error) {
	cur, err := l.real.Current(ctx)
	if err != nil {
		return cur, err
	}
	cur.Chain = append([]model.Hash(nil), cur.Chain...)
	cur.Tombstones = append([]model.DeletePredicate(nil), cur.Tombstones...)
	l.mutate(&cur)
	return cur, nil
}

// An installation that has not admitted a batch yet holds no admission
// reservation. Its control state then carries no reservation map at all while the
// data cut carries an empty one: both are "no reservations" and the backup (and the
// restore's own re-check) must treat them as one thing, or a new installation
// could never be backed up.
func TestAnInstallationThatNeverIngestedCanBeBackedUpAndRestored(t *testing.T) {
	l := newLive(t)
	m, err := l.backup()
	if err != nil {
		t.Fatalf("an installation with no admitted batch cannot be backed up: %v", err)
	}
	root := l.newRoot()
	if _, err = l.restoreTo(root, m, l.authority); err != nil {
		t.Fatalf("its backup cannot be restored: %v", err)
	}
	r := l.openRestored(root)
	if _, err = r.activate(l.authority); err != nil {
		t.Fatal(err)
	}
	if err = r.app.Storage.RestoreReady(); err != nil {
		t.Fatalf("the restored empty installation is not ready: %v", err)
	}
}

// The manifest asserts the digest of the control-state object it was written with.
// A re-signed manifest that names a different digest is not the backup it claims
// to be, even though every per-object check still passes.
func TestRestoreRefusesAManifestWhoseControlStateDigestWasAltered(t *testing.T) {
	l := newLive(t)
	l.append(100, "row")
	l.reconcile()
	m := l.mustBackup()
	forged := m
	forged.Control.StateSHA256[0] ^= 0xff
	if err := backup.ResignForTest(&forged, l.keys["data-kek"]); err != nil {
		t.Fatal(err)
	}
	root := l.newRoot()
	if _, err := l.restoreTo(root, forged, l.authority); code(err) != model.Corrupt {
		t.Fatalf("a manifest naming another control-state digest was restored: %v", err)
	}
	if fileExists(root) || len(stageLeftovers(root)) != 0 {
		t.Fatal("the refused restore left a root or a staging directory behind")
	}
	if _, err := l.restoreTo(l.newRoot(), m, l.authority); err != nil {
		t.Fatalf("the genuine backup no longer restores: %v", err)
	}
}
