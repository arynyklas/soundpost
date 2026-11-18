// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/artifacts/refledger"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/smokecluster"
)

const contractEmail, contractSecret = "owner@contract-indexes.invalid", "contract indexes test password 2026"

func contractRetryable(err error) bool {
	var f *model.Fault
	return errors.As(err, &f) && (f.Code == model.Stale || f.Code == model.Conflict || f.Code == model.Unavailable || f.Code == model.Timeout)
}

// contractLogin logs the owner in on app and returns a fresh credential.
func contractLogin(t *testing.T, app *appcore.App) auth.Credential {
	t.Helper()
	var s auth.Session
	var err error
	for range 40 {
		if s, err = app.Auth.Login(context.Background(), contractEmail, contractSecret, ""); !contractRetryable(err) {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	c, err := app.Auth.Authenticate(context.Background(), s.Token)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	return c
}

// contractOrg creates an organization with one project through admin commands and returns both IDs.
func contractOrg(t *testing.T, app *appcore.App, c auth.Credential) (org, project model.ID) {
	t.Helper()
	ctx := context.Background()
	org, project = model.NewID(), model.NewID()
	run := func(kind string, p auth.AdminPayload) {
		t.Helper()
		p.Reason = "contract indexes test"
		payload, _ := json.Marshal(p)
		var err error
		for range 60 {
			var view auth.AdminView
			if kind == "create_org" {
				view, err = app.Auth.AdminRead(ctx, c, auth.AdminReadRequest{Kind: "organizations"})
			} else {
				view, err = app.Auth.AdminRead(ctx, c, auth.AdminReadRequest{OrgID: org, Kind: "organization"})
			}
			if err == nil {
				req := auth.AdminCommandRequest{CommandID: model.NewID(), OrgID: org, Kind: kind, Payload: payload}
				if kind == "create_org" {
					req.ExpectedRevision = view.Revision
				} else {
					epoch := view.Epoch
					req.ExpectedEpoch = &epoch
				}
				_, err = app.Auth.AdminCommand(ctx, c, req)
			}
			if !contractRetryable(err) {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
	}
	run("create_org", auth.AdminPayload{Name: "contract"})
	run("create_project", auth.AdminPayload{ID: project, Name: "p"})
	return org, project
}

// contractSeed writes n ledgers of the project into the organization the way the artifact lifecycle does and
// returns their roots.
func contractSeed(t *testing.T, app *appcore.App, org, project model.ID, n int) []model.ID {
	t.Helper()
	var roots []model.ID
	err := app.Control.Update(context.Background(), func(st *model.ControlState) error {
		o := st.Orgs[org.String()]
		var ledgers []*refledger.Ledger
		for i := range n {
			var g model.ID
			g[0], g[15] = 1, byte(i+1)
			l := &refledger.Ledger{Project: project, Root: model.NewID(), Seq: 1, Entries: []refledger.Entry{{Kind: refledger.KindError, Cursor: model.Cursor{Group: g, Index: model.Uint64(i + 1)}, RetainUntil: 100}}}
			ledgers = append(ledgers, l)
			roots = append(roots, l.Root)
		}
		if err := refledger.Store(&o, project, ledgers...); err != nil {
			return err
		}
		st.Orgs[org.String()] = o
		return nil
	})
	if err != nil {
		t.Fatalf("seed ledgers: %v", err)
	}
	return roots
}

type contractView struct {
	contracted, legacyIndex, legacyAnchor bool
	loaded                                int
	audits                                int
}

func contractRead(t *testing.T, app *appcore.App, org, project model.ID, roots []model.ID) contractView {
	t.Helper()
	var v contractView
	if err := app.Control.View(context.Background(), func(st model.ControlState) error {
		o := st.Orgs[org.String()]
		v.contracted = o.IndexesContracted()
		_, v.legacyIndex = o.Settings[refledger.LegacyIndexKey(project)]
		_, v.legacyAnchor = o.Settings[refledger.LegacyAnchorKey(project)]
		for _, r := range roots {
			if l, err := refledger.Load(o.Settings, project, r); err == nil && l != nil {
				v.loaded++
			}
		}
		for _, a := range st.Audits {
			if a.Action == "contract_indexes" {
				v.audits++
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("read the control state: %v", err)
	}
	return v
}

func bootstrapOwner(t *testing.T, app *appcore.App) {
	t.Helper()
	token, err := app.Control.BootstrapToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = app.Auth.Bootstrap(context.Background(), token, contractEmail, contractSecret); err != nil {
		t.Fatal(err)
	}
}

func contractRequest(reason string) auth.ContractIndexesRequest {
	return auth.ContractIndexesRequest{CommandID: model.NewID(), Reason: reason}
}

// One voter: the step contracts every organization, deletes the previous release's values, keeps every ledger
// readable, audits once per organization and is a no-op the second time; an organization created afterwards
// starts contracted. Requests without a fresh administrator credential or a reason are refused.
func TestContractIndexesOnASingleVoter(t *testing.T) {
	dir := t.TempDir()
	app, err := appcore.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	bootstrapOwner(t, app)
	c := contractLogin(t, app)
	org, project := contractOrg(t, app, c)
	roots := contractSeed(t, app, org, project, 40)
	before := contractRead(t, app, org, project, roots)
	if before.contracted || !before.legacyIndex || !before.legacyAnchor || before.loaded != len(roots) {
		t.Fatalf("expanded organization: %+v", before)
	}
	ctx := context.Background()
	if _, err := app.Auth.ContractIndexes(ctx, c, auth.ContractIndexesRequest{CommandID: model.NewID()}); err == nil {
		t.Fatal("a request without a reason was accepted")
	}
	got, err := app.Auth.ContractIndexes(ctx, c, contractRequest("test"))
	if err != nil || !got.Changed || got.Organizations != 1 {
		t.Fatalf("contract: %+v %v", got, err)
	}
	after := contractRead(t, app, org, project, roots)
	if !after.contracted || after.legacyIndex || after.legacyAnchor || after.loaded != len(roots) || after.audits != 1 {
		t.Fatalf("contracted organization: %+v", after)
	}
	again, err := app.Auth.ContractIndexes(ctx, c, contractRequest("test again"))
	if err != nil || again.Changed || again.Organizations != 0 {
		t.Fatalf("a second contraction: %+v %v", again, err)
	}
	if v := contractRead(t, app, org, project, roots); v.audits != 1 {
		t.Fatalf("a no-op contraction wrote an audit row: %+v", v)
	}
	// Writes after the contraction do not bring the values back.
	more := contractSeed(t, app, org, project, 5)
	if v := contractRead(t, app, org, project, append(roots, more...)); v.legacyIndex || v.legacyAnchor || v.loaded != len(roots)+len(more) {
		t.Fatalf("after a write: %+v", v)
	}
	// An organization created after the step starts contracted.
	other, otherProject := contractOrg(t, app, c)
	otherRoots := contractSeed(t, app, other, otherProject, 3)
	if v := contractRead(t, app, other, otherProject, otherRoots); !v.contracted || v.legacyIndex || v.loaded != 3 {
		t.Fatalf("an organization created after the contraction: %+v", v)
	}
	// Not an administrator on a fresh session: refused.
	if _, err := app.Auth.ContractIndexes(ctx, auth.Credential{}, contractRequest("x")); err == nil {
		t.Fatal("an empty credential was accepted")
	}
}

// Three voters over real mTLS: refused, naming the member, while one member answers the live layout question
// as the previous release does (nothing changes anywhere); done once it answers; repeated, a no-op. Every voter
// ends with the same state and nobody stops applying.
func TestContractIndexesIsRefusedUntilEveryMemberAnswersTheLiveQuestion(t *testing.T) {
	work := t.TempDir()
	live := filepath.Join(work, "live")
	if err := os.MkdirAll(live, 0o700); err != nil {
		t.Fatal(err)
	}
	app, err := appcore.Open(live)
	if err != nil {
		t.Fatal(err)
	}
	bootstrapOwner(t, app)
	seed := filepath.Join(work, "cluster.seed")
	if err = app.WriteClusterSeed(seed); err != nil {
		t.Fatal(err)
	}
	if err = app.Close(); err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(filepath.Join(work, "cluster"), 0o700); err != nil {
		t.Fatal(err)
	}
	cluster, err := smokecluster.New(filepath.Join(work, "cluster"), seed)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cluster.Close)
	if err = cluster.Open(1, 2, 3); err != nil {
		t.Fatal(err)
	}
	leader := cluster.App(1)
	c := contractLogin(t, leader)
	org, project := contractOrg(t, leader, c)
	roots := contractSeed(t, leader, org, project, 20)
	old := cluster.App(2)
	old.LimitLiveLayoutForTest(true)
	ctx := context.Background()
	_, err = leader.Auth.ContractIndexes(ctx, c, contractRequest("refused"))
	var fault *model.Fault
	if !errors.As(err, &fault) || fault.Code != model.Unsupported || !strings.HasPrefix(fault.SafeDetail, "layout_unsupported_by:") {
		t.Fatalf("a member that does not answer: %v", err)
	}
	if v := contractRead(t, leader, org, project, roots); v.contracted || !v.legacyIndex || v.audits != 0 || v.loaded != len(roots) {
		t.Fatalf("a refused contraction changed the state: %+v", v)
	}
	old.LimitLiveLayoutForTest(false)
	got, err := leader.Auth.ContractIndexes(ctx, c, contractRequest("done"))
	if err != nil || !got.Changed {
		t.Fatalf("contract: %+v %v", got, err)
	}
	for _, id := range []uint64{1, 2, 3} {
		id := id
		ok := false
		for range 100 {
			if v := contractRead(t, cluster.App(id), org, project, roots); v.contracted && !v.legacyIndex && !v.legacyAnchor && v.loaded == len(roots) {
				ok = true
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if !ok {
			t.Fatalf("voter %d did not converge on the contracted state", id)
		}
		for _, st := range cluster.App(id).ReplicationStatus() {
			if st.Failed {
				t.Fatalf("voter %d stopped applying", id)
			}
		}
	}
	if again, err := leader.Auth.ContractIndexes(ctx, c, contractRequest("again")); err != nil || again.Changed {
		t.Fatalf("a repeat: %+v %v", again, err)
	}
}
