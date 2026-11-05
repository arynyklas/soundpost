// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth_test

import (
	"context"
	"encoding/json"
	"errors"

	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/model"
	"testing"
	"time"
)

// restoreFixture is a live installation with every kind of pre-restore
// privilege: an owner, a demotable org admin, a granted reader with a password,
// a session, a server token, a source credential and a configured sender.
type restoreFixture struct {
	t       *testing.T
	ctx     context.Context
	dir     string
	store   *control.Store
	service *auth.Service
	clock   *time.Time
	owner   auth.Credential
	ownerS  auth.Session
	org     model.ID
	project model.ID
	reader  model.ID
	readerS auth.Session
	admin   model.ID
	token   string
	source  model.ID
	srcCred string
	sender  model.ID
}

const readerPassword = "reader long password 2026"

func newRestoreFixture(t *testing.T) *restoreFixture {
	t.Helper()
	f := &restoreFixture{t: t, ctx: context.Background(), dir: t.TempDir()}
	now := time.Now()
	f.clock = &now
	var err error
	if f.store, err = control.Open(f.dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.store.Close() })
	if f.service, err = auth.NewService(auth.AuthDependencies{Control: f.store, Now: func() time.Time { return *f.clock }}); err != nil {
		t.Fatal(err)
	}
	activateAuthControl(t, f.store, t.TempDir())
	boot, _ := f.store.BootstrapToken()
	if f.ownerS, err = f.service.Bootstrap(f.ctx, boot, "owner@example.test", "owner long password 2026"); err != nil {
		t.Fatal(err)
	}
	if f.owner, err = f.service.Authenticate(f.ctx, f.ownerS.Token); err != nil {
		t.Fatal(err)
	}
	f.org, f.project, f.reader, f.admin = model.NewID(), model.NewID(), model.NewID(), model.NewID()
	f.command("create_org", auth.AdminPayload{Name: "restored org"})
	f.command("create_project", auth.AdminPayload{ID: f.project, Name: "p"})
	f.command("create_user", auth.AdminPayload{ID: f.reader, Email: "reader@example.test", Password: readerPassword})
	f.command("create_user", auth.AdminPayload{ID: f.admin, Email: "admin@example.test", Password: "second admin password 2026"})
	f.command("membership", auth.AdminPayload{UserID: f.reader, Enabled: true})
	f.command("membership", auth.AdminPayload{UserID: f.admin, Enabled: true})
	f.command("org_admin", auth.AdminPayload{UserID: f.admin, Enabled: true})
	f.command("grant", auth.AdminPayload{UserID: f.reader, ProjectID: f.project, Enabled: true, Permissions: []string{string(auth.Read)}})
	f.sender = model.NewID()
	f.command("destination", auth.AdminPayload{ID: f.sender, Config: json.RawMessage(`{"type":"webhook","endpoint":"https://hooks.example.test/notify","enabled":true}`), Secret: "sender signing secret"})
	if f.readerS, err = f.service.Login(f.ctx, "reader@example.test", readerPassword, ""); err != nil {
		t.Fatal(err)
	}
	issued, err := f.service.IssueServerToken(f.ctx, f.owner, f.org, f.reader, []model.ID{f.project}, []auth.Permission{auth.Read}, now.Add(time.Hour).Unix(), "automation")
	if err != nil {
		t.Fatal(err)
	}
	f.token = issued.Token
	f.source = model.NewID()
	policy := model.SourcePolicy{Revision: 1, Enabled: true, Class: "structured", Kinds: []model.Kind{model.Metric}, Resources: model.ResourceRegistry{Services: []model.ID{model.NewID()}, Environments: []model.ID{model.NewID()}, Builds: []model.ID{model.NewID()}, Instances: []string{"i"}}, RetentionDays: map[model.Kind]uint32{model.Metric: 14}, MaxBytes: 1 << 20, MaxSeries: 100}
	onboarded, err := f.service.OnboardSource(f.ctx, f.owner, auth.SourceOnboarding{CommandID: model.NewID(), Org: f.org, Project: f.project, Source: f.source, Expires: model.UnixNano(now.Add(48 * time.Hour).UnixNano()), Policy: policy, Reason: "restore fixture"})
	if err != nil {
		t.Fatal(err)
	}
	f.srcCred = onboarded.Credential
	if _, err = f.service.AuthenticateSource(f.ctx, f.srcCred, "", false); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *restoreFixture) revision() model.Revision {
	var r model.Revision
	if err := f.store.View(f.ctx, func(st control.State) error { r = st.Revision; return nil }); err != nil {
		f.t.Fatal(err)
	}
	return r
}
func (f *restoreFixture) command(kind string, p auth.AdminPayload) {
	f.t.Helper()
	p.Reason = "restore fixture"
	raw, _ := json.Marshal(p)
	if _, err := f.service.AdminCommand(f.ctx, f.owner, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: f.revision(), OrgID: f.org, Kind: kind, Payload: raw}); err != nil {
		f.t.Fatal(kind, err)
	}
}

// restore applies the quarantine through the real replicated update path and
// reopens the auth service the way a restarted process would: the bearer key is
// loaded from control state, so the fresh key is the one in force.
func (f *restoreFixture) restore() (recoveryToken string, summary auth.RestoreSummary, service *auth.Service) {
	f.t.Helper()
	token, hash := auth.NewRecoveryBootstrap()
	sealed, err := auth.SealedBearerKey(f.store.Seal)
	if err != nil {
		f.t.Fatal(err)
	}
	err = f.store.Update(f.ctx, func(st *model.ControlState) error {
		summary, err = auth.QuarantineRestoredState(st, auth.RestoreInput{Generation: model.NewID(), Backup: model.NewID(), BootstrapHash: hash, SealedBearerKey: sealed, At: *f.clock})
		return err
	})
	if err != nil {
		f.t.Fatal(err)
	}
	service, err = auth.NewService(auth.AuthDependencies{Control: f.store, Now: func() time.Time { return *f.clock }})
	if err != nil {
		f.t.Fatal(err)
	}
	return token, summary, service
}

func authCode(err error) model.Code {
	var fault *model.Fault
	if errors.As(err, &fault) {
		return fault.Code
	}
	return ""
}

func TestQuarantineMakesEveryPreRestorePrivilegeInactive(t *testing.T) {
	f := newRestoreFixture(t)
	// Sanity: all of it is live before the restore.
	if _, err := f.service.Authenticate(f.ctx, f.readerS.Token); err != nil {
		t.Fatal(err)
	}
	if _, err := f.service.Authenticate(f.ctx, f.token); err != nil {
		t.Fatal(err)
	}
	token, summary, service := f.restore()
	if summary.Users < 3 || summary.Sessions < 2 || summary.ServerTokens != 1 || summary.Sources != 1 || summary.Integrations < 1 {
		t.Fatalf("quarantine under-counted what it deactivated: %+v", summary)
	}
	for name, credential := range map[string]string{"owner session": f.ownerS.Token, "reader session": f.readerS.Token, "server token": f.token} {
		if _, err := service.Authenticate(f.ctx, credential); authCode(err) != model.Unauthenticated {
			t.Fatalf("%s survived the restore: %v", name, err)
		}
	}
	if _, err := service.AuthenticateSource(f.ctx, f.srcCred, "", false); authCode(err) != model.Forbidden {
		t.Fatalf("old source credential survived the restore: %v", err)
	}
	// Possessing the right password is not enough: every restored account is disabled.
	for _, login := range [][2]string{{"reader@example.test", readerPassword}, {"owner@example.test", "owner long password 2026"}, {"admin@example.test", "second admin password 2026"}} {
		if _, err := service.Login(f.ctx, login[0], login[1], ""); authCode(err) != model.Unauthenticated {
			t.Fatalf("restored account %s logged in: %v", login[0], err)
		}
	}
	// A fresh recovery admin is bootstrapped from the one-time token...
	if _, err := service.Bootstrap(f.ctx, "not the recovery token", "recovery@example.test", "recovery long password 2026"); authCode(err) != model.Unauthenticated {
		t.Fatalf("bootstrap accepted a wrong token: %v", err)
	}
	session, err := service.Bootstrap(f.ctx, token, "recovery@example.test", "recovery long password 2026")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.Bootstrap(f.ctx, token, "second@example.test", "second long password 2026"); err == nil {
		t.Fatal("recovery bootstrap token was reusable")
	}
	recovery, err := service.Authenticate(f.ctx, session.Token)
	if err != nil {
		t.Fatal(err)
	}
	// ...but a fresh login restores NO former grant: no membership, no admin, no read.
	if _, err = service.Authorize(f.ctx, recovery, f.org, []model.ID{f.project}, auth.Read); authCode(err) != model.NotFound {
		t.Fatalf("fresh login read a restored project: %v", err)
	}
	if _, err = service.Authorize(f.ctx, recovery, f.org, nil, auth.OrgAdmin); authCode(err) != model.NotFound {
		t.Fatalf("fresh login became a restored org admin: %v", err)
	}
	var settings, secrets int
	_ = f.store.View(f.ctx, func(st control.State) error {
		o := st.Orgs[f.org.String()]
		for key := range o.Settings {
			if len(key) > 12 && key[:12] == "destination:" {
				settings++
			}
		}
		secrets = len(o.Secrets)
		if len(st.SourceCredentials) != 0 {
			t.Fatal("old source secret digests remained active")
		}
		return nil
	})
	if settings != 0 || secrets != 0 {
		t.Fatalf("restored sender stayed configured (%d settings, %d secrets)", settings, secrets)
	}
	if got := auth.RestorePending(controlState(t, f)); got == 0 {
		t.Fatal("nothing left to reconcile")
	}
	// The quarantine is itself one-shot: it cannot be applied over a quarantined state.
	err = f.store.Update(f.ctx, func(st *model.ControlState) error {
		_, e := auth.QuarantineRestoredState(st, auth.RestoreInput{Generation: model.NewID(), Backup: model.NewID(), BootstrapHash: "x", SealedBearerKey: "y", At: *f.clock})
		return e
	})
	if authCode(err) != model.Conflict {
		t.Fatalf("second quarantine accepted: %v", err)
	}
}

func controlState(t *testing.T, f *restoreFixture) model.ControlState {
	t.Helper()
	var out model.ControlState
	if err := f.store.View(f.ctx, func(st control.State) error { out = st; return nil }); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestReconcileReinstatesOnlyNamedItemsWithAudit(t *testing.T) {
	f := newRestoreFixture(t)
	token, _, service := f.restore()
	session, err := service.Bootstrap(f.ctx, token, "recovery@example.test", "recovery long password 2026")
	if err != nil {
		t.Fatal(err)
	}
	recovery, err := service.Authenticate(f.ctx, session.Token)
	if err != nil {
		t.Fatal(err)
	}
	reason := "verified with the identity provider ticket 4711"
	reconcile := func(r auth.Reconciliation) (auth.Reconciled, error) {
		r.Reason = reason
		return service.Reconcile(f.ctx, recovery, r)
	}
	// Reinstating the account alone grants nothing.
	if _, err = reconcile(auth.Reconciliation{Kind: auth.ReconcileAccount, User: f.reader}); err != nil {
		t.Fatal(err)
	}
	readerSession, err := service.Login(f.ctx, "reader@example.test", readerPassword, "")
	if err != nil {
		t.Fatal("a reauthorized account must be able to log in again:", err)
	}
	readerCredential, err := service.Authenticate(f.ctx, readerSession.Token)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.Authorize(f.ctx, readerCredential, f.org, []model.ID{f.project}, auth.Read); authCode(err) != model.NotFound {
		t.Fatalf("account reauthorization alone restored a grant: %v", err)
	}
	// A reauthorized (restored) account cannot vouch for other restored items.
	if _, err = service.Reconcile(f.ctx, readerCredential, auth.Reconciliation{Kind: auth.ReconcileMembership, Org: f.org, User: f.reader, Reason: reason}); authCode(err) != model.Forbidden {
		t.Fatalf("a restored non-admin reconciled itself: %v", err)
	}
	if _, err = reconcile(auth.Reconciliation{Kind: auth.ReconcileGrant, Org: f.org, User: f.reader, Project: f.project}); authCode(err) != model.NotFound {
		t.Fatalf("grant reinstated before its membership: %v", err)
	}
	if _, err = reconcile(auth.Reconciliation{Kind: auth.ReconcileMembership, Org: f.org, User: f.reader}); err != nil {
		t.Fatal(err)
	}
	if _, err = reconcile(auth.Reconciliation{Kind: auth.ReconcileGrant, Org: f.org, User: f.reader, Project: f.project}); err != nil {
		t.Fatal(err)
	}
	if _, err = service.Authorize(f.ctx, readerCredential, f.org, []model.ID{f.project}, auth.Read); err != nil {
		t.Fatalf("explicitly reconciled grant did not take effect: %v", err)
	}
	// The other restored admin was not named: still nothing.
	if _, err = service.Login(f.ctx, "admin@example.test", "second admin password 2026", ""); authCode(err) != model.Unauthenticated {
		t.Fatalf("an unnamed restored account became active: %v", err)
	}
	// Each item is consumed exactly once.
	if _, err = reconcile(auth.Reconciliation{Kind: auth.ReconcileAccount, User: f.reader}); authCode(err) != model.NotFound {
		t.Fatalf("a reconciled item was reconciled twice: %v", err)
	}
	// An unknown item is not found (and never invented).
	if _, err = reconcile(auth.Reconciliation{Kind: auth.ReconcileGrant, Org: f.org, User: model.NewID(), Project: f.project}); authCode(err) != model.NotFound {
		t.Fatalf("invented grant: %v", err)
	}
	// A source returns a NEW credential; the old secret is never revived.
	issued, err := reconcile(auth.Reconciliation{Kind: auth.ReconcileSource, Source: f.source})
	if err != nil || issued.Credential == "" || issued.Credential == f.srcCred {
		t.Fatalf("source reconciliation: %v", err)
	}
	if _, err = service.AuthenticateSource(f.ctx, issued.Credential, "", false); err != nil {
		t.Fatalf("new source credential refused: %v", err)
	}
	if _, err = service.AuthenticateSource(f.ctx, f.srcCred, "", false); authCode(err) != model.Forbidden {
		t.Fatalf("old source secret revived by reconciliation: %v", err)
	}
	// The sender stays inactive until it is named, then returns with its sealed secret.
	if len(controlStashedSettings(t, f, "destination:")) != 0 {
		t.Fatal("an unnamed sender became active")
	}
	if _, err = reconcile(auth.Reconciliation{Kind: auth.ReconcileIntegration, Org: f.org, Key: "destination:" + f.sender.String()}); err != nil {
		t.Fatal(err)
	}
	if len(controlStashedSettings(t, f, "destination:")) != 1 {
		t.Fatal("the named sender was not reinstated")
	}
	_ = f.store.View(f.ctx, func(st control.State) error {
		sealed := st.Orgs[f.org.String()].Secrets["destination:"+f.sender.String()]
		if opened, err := f.store.OpenSecret(sealed); err != nil || opened != "sender signing secret" {
			t.Fatal("the reinstated sender lost its secret")
		}
		return nil
	})
	// Audit: every reconciliation committed an audit record naming the recovery admin and the reason.
	var audits []model.ControlAudit
	_ = f.store.View(f.ctx, func(st control.State) error { audits = st.Audits; return nil })
	seen := map[string]bool{}
	for _, a := range audits {
		if len(a.Action) > 18 && a.Action[:18] == "restore.reconcile." {
			if a.Principal != session.User || a.Reason != reason || a.Outcome != model.AuditAllowed || a.RequestID == (model.ID{}) {
				t.Fatalf("reconcile audit is incomplete: %+v", a)
			}
			seen[a.Action] = true
		}
	}
	for _, want := range []string{"restore.reconcile.account", "restore.reconcile.membership", "restore.reconcile.grant", "restore.reconcile.source", "restore.reconcile.integration"} {
		if !seen[want] {
			t.Fatalf("no audit record for %s", want)
		}
	}
}

func controlStashedSettings(t *testing.T, f *restoreFixture, prefix string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	_ = f.store.View(f.ctx, func(st control.State) error {
		for k := range st.Orgs[f.org.String()].Settings {
			if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
				out[k] = true
			}
		}
		return nil
	})
	return out
}

func TestReconcileRefusesDuplicateLoginsAndUnfreshCallers(t *testing.T) {
	f := newRestoreFixture(t)
	token, _, service := f.restore()
	// The recovery admin deliberately reuses a restored account's email.
	session, err := service.Bootstrap(f.ctx, token, "reader@example.test", "recovery long password 2026")
	if err != nil {
		t.Fatal(err)
	}
	recovery, err := service.Authenticate(f.ctx, session.Token)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.Reconcile(f.ctx, recovery, auth.Reconciliation{Kind: auth.ReconcileAccount, User: f.reader, Reason: "same email"}); authCode(err) != model.Conflict {
		t.Fatalf("two enabled accounts may never share one login: %v", err)
	}
	// No reason, no reconciliation.
	if _, err = service.Reconcile(f.ctx, recovery, auth.Reconciliation{Kind: auth.ReconcileAccount, User: f.admin}); authCode(err) != model.Forbidden {
		t.Fatalf("reconciliation without a reason accepted: %v", err)
	}
	// Reauthentication freshness is required.
	*f.clock = f.clock.Add(10 * time.Minute)
	stale, err := service.Authenticate(f.ctx, session.Token)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.Reconcile(f.ctx, stale, auth.Reconciliation{Kind: auth.ReconcileAccount, User: f.admin, Reason: "stale session"}); authCode(err) != model.Forbidden {
		t.Fatalf("a stale session reconciled: %v", err)
	}
}

func TestInstanceScopeIsAuditedRevalidatedAndReadsNothing(t *testing.T) {
	f := newRestoreFixture(t)
	scope, err := f.service.InstanceScope(f.ctx, f.owner, "nightly backup")
	if err != nil {
		t.Fatal(err)
	}
	if err = f.service.RevalidateInstance(f.ctx, scope); err != nil {
		t.Fatal(err)
	}
	var audited bool
	_ = f.store.View(f.ctx, func(st control.State) error {
		a := st.Audits[len(st.Audits)-1]
		audited = a.Action == "instance.scope" && a.Reason == "nightly backup" && a.Principal == f.ownerS.User
		return nil
	})
	if !audited {
		t.Fatal("instance scope was issued without a committed audit record")
	}
	if scope.OrgID() != (model.ID{}) || len(scope.ProjectIDs()) != 0 {
		t.Fatal("instance scope names an organization or project")
	}
	// It cannot be used as any data/control scope.
	if err = scope.ControlAuthorize(f.ctx, "RecordEvidenceGap"); err == nil {
		t.Fatal("instance scope passed organization control authorization")
	}
	// A non-admin cannot obtain one.
	readerCred, err := f.service.Authenticate(f.ctx, f.readerS.Token)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.service.InstanceScope(f.ctx, readerCred, "not an admin"); authCode(err) != model.Forbidden {
		t.Fatalf("non-admin obtained an instance scope: %v", err)
	}
	// Logout revokes it; it also lapses by itself.
	if err = f.service.Logout(f.ctx, f.ownerS.Token); err != nil {
		t.Fatal(err)
	}
	if err = f.service.RevalidateInstance(f.ctx, scope); authCode(err) != model.Unauthenticated {
		t.Fatalf("instance scope survived logout: %v", err)
	}
	boot2, err := f.service.Login(f.ctx, "owner@example.test", "owner long password 2026", "")
	if err != nil {
		t.Fatal(err)
	}
	cred2, _ := f.service.Authenticate(f.ctx, boot2.Token)
	scope2, err := f.service.InstanceScope(f.ctx, cred2, "lapse")
	if err != nil {
		t.Fatal(err)
	}
	*f.clock = f.clock.Add(16 * time.Minute)
	if err = f.service.RevalidateInstance(f.ctx, scope2); authCode(err) != model.Forbidden && authCode(err) != model.Unauthenticated {
		t.Fatalf("instance scope did not lapse: %v", err)
	}

}
