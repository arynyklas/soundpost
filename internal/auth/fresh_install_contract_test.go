// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/artifacts/refledger"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

// D72: an installation that this release bootstrapped has no previous release to go back to, so it is contracted
// from its first write and so is every organization created on it; an installation the previous release
// bootstrapped stays expanded until contract-indexes (D70). The mark is a resident of the replicated control
// state (State.OIDC[model.IndexesContractedKey]) written by the Bootstrap command itself.

func installBornContracted(t *testing.T, app *appcore.App) bool {
	t.Helper()
	var marked bool
	if err := app.Control.View(context.Background(), func(st model.ControlState) error {
		_, marked = st.OIDC[model.IndexesContractedKey]
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return marked
}

func orgSettings(t *testing.T, app *appcore.App, org model.ID) map[string]json.RawMessage {
	t.Helper()
	out := map[string]json.RawMessage{}
	if err := app.Control.View(context.Background(), func(st model.ControlState) error {
		for k, v := range st.Orgs[org.String()].Settings {
			out[k] = bytes.Clone(v)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

// changedBytes is the size of the Settings values that differ between two snapshots (keys and values).
func changedBytes(before, after map[string]json.RawMessage) int {
	n := 0
	for k, v := range after {
		if !bytes.Equal(before[k], v) {
			n += len(k) + len(v)
		}
	}
	for k, v := range before {
		if _, ok := after[k]; !ok {
			n += len(k) + len(v)
		}
	}
	return n
}

// perProjectKeys are the values of the previous release's layout that exist in settings.
func perProjectKeys(settings map[string]json.RawMessage, project model.ID) []string {
	var out []string
	for _, k := range []string{refledger.LegacyIndexKey(project), refledger.LegacyAnchorKey(project), model.ReplayPinKeyPrefix + project.String()} {
		if _, ok := settings[k]; ok {
			out = append(out, k)
		}
	}
	return out
}

func settingsDigest(settings map[string]json.RawMessage) string {
	keys := make([]string, 0, len(settings))
	for k := range settings {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	h := sha256.New()
	for _, k := range keys {
		h.Write([]byte(k))
		h.Write([]byte{0})
		h.Write(settings[k])
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)[:12])
}

// A fresh installation: Bootstrap marks it, an organization created on it is born contracted, the first ledger
// write is one ledger and one shard with none of the previous release's per-project values, a project of
// thousands of ledgers still costs one ledger and one shard per write, and contract-indexes has nothing to do.
func TestFreshInstallationIsContractedFromItsFirstWrite(t *testing.T) {
	app, err := appcore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	bootstrapFreshOwner(t, app)
	if !installBornContracted(t, app) {
		t.Fatal("Bootstrap on a fresh installation did not mark it as born contracted")
	}
	c := contractLogin(t, app)
	org, project := contractOrg(t, app, c)
	if v := contractRead(t, app, org, project, nil); !v.contracted {
		t.Fatalf("an organization created on a fresh installation is not contracted: %+v", v)
	}
	before := orgSettings(t, app, org)
	roots := contractSeed(t, app, org, project, 1)
	after := orgSettings(t, app, org)
	if keys := perProjectKeys(after, project); len(keys) > 0 {
		t.Fatalf("the first ledger write of a fresh installation wrote the previous release's values %v", keys)
	}
	if n := changedBytes(before, after); n > 8<<10 {
		t.Fatalf("the first ledger write changed %d bytes of Settings; want one ledger and one shard", n)
	}
	if v := contractRead(t, app, org, project, roots); !v.contracted || v.legacyIndex || v.legacyAnchor || v.loaded != 1 {
		t.Fatalf("after the first write: %+v", v)
	}
	more := contractSeed(t, app, org, project, 2000)
	before = orgSettings(t, app, org)
	last := contractSeed(t, app, org, project, 1)
	after = orgSettings(t, app, org)
	if n := changedBytes(before, after); n > 24<<10 {
		t.Fatalf("one ledger write changed %d bytes of Settings in a project of %d ledgers; want one ledger and one shard", n, len(more)+1)
	}
	if keys := perProjectKeys(after, project); len(keys) > 0 {
		t.Fatalf("a write wrote the previous release's values %v", keys)
	}
	if v := contractRead(t, app, org, project, append(append(roots, more...), last...)); v.legacyIndex || v.loaded != len(more)+2 {
		t.Fatalf("after the writes: %+v", v)
	}
	got, err := app.Auth.ContractIndexes(context.Background(), c, contractRequest("nothing to do"))
	if err != nil || got.Changed || got.Organizations != 0 {
		t.Fatalf("contract-indexes on a fresh installation: %+v %v", got, err)
	}
}

// An installation the previous release bootstrapped (no mark in the state it wrote) stays expanded: a new
// organization and its writes keep the previous release's per-project values, a restart of this release does not
// contract anything, and only contract-indexes does.
func TestUpgradedInstallationStaysExpandedUntilContractIndexes(t *testing.T) {
	dir := t.TempDir()
	app, err := appcore.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	bootstrapOwner(t, app)
	if installBornContracted(t, app) {
		t.Fatal("the fixture of an upgraded installation carries the mark")
	}
	c := contractLogin(t, app)
	org, project := contractOrg(t, app, c)
	roots := contractSeed(t, app, org, project, 30)
	if v := contractRead(t, app, org, project, roots); v.contracted || !v.legacyIndex || !v.legacyAnchor || v.loaded != len(roots) {
		t.Fatalf("an organization on an upgraded installation: %+v", v)
	}
	if err = app.Close(); err != nil {
		t.Fatal(err)
	}
	if app, err = appcore.Open(dir); err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	if installBornContracted(t, app) {
		t.Fatal("restarting this release marked an upgraded installation")
	}
	c = contractLogin(t, app)
	more := contractSeed(t, app, org, project, 3)
	other, otherProject := contractOrg(t, app, c)
	otherRoots := contractSeed(t, app, other, otherProject, 2)
	if v := contractRead(t, app, org, project, append(roots, more...)); v.contracted || !v.legacyIndex || v.loaded != len(roots)+len(more) {
		t.Fatalf("after the restart: %+v", v)
	}
	if v := contractRead(t, app, other, otherProject, otherRoots); v.contracted || !v.legacyIndex || v.loaded != len(otherRoots) {
		t.Fatalf("an organization created after the restart: %+v", v)
	}
	got, err := app.Auth.ContractIndexes(context.Background(), c, contractRequest("operator"))
	if err != nil || !got.Changed || got.Organizations != 2 {
		t.Fatalf("contract: %+v %v", got, err)
	}
	if v := contractRead(t, app, org, project, append(roots, more...)); !v.contracted || v.legacyIndex || v.loaded != len(roots)+len(more) {
		t.Fatalf("after contract-indexes: %+v", v)
	}
}

// Three voters over real mTLS on a fresh installation: the mark is part of the replicated state, so every voter
// holds it, an organization created through the leader is contracted on every voter, its writes carry no
// per-project value anywhere, and the stored organization is byte-identical on all three.
func TestFreshInstallationMarkIsReplicatedAndEveryVoterAgrees(t *testing.T) {
	cluster, c := contractClusterOf(t, bootstrapFreshOwner)
	leader := cluster.App(1)
	org, project := contractOrg(t, leader, c)
	roots := contractSeed(t, leader, org, project, 50)
	deadline := time.Now().Add(30 * time.Second)
	for {
		digests := map[string]bool{}
		ok := true
		for _, id := range []uint64{1, 2, 3} {
			app := cluster.App(id)
			v := contractRead(t, app, org, project, roots)
			settings := orgSettings(t, app, org)
			if !installBornContracted(t, app) || !v.contracted || v.legacyIndex || v.legacyAnchor || v.loaded != len(roots) || len(perProjectKeys(settings, project)) > 0 {
				ok = false
				break
			}
			digests[settingsDigest(settings)] = true
		}
		if ok && len(digests) == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the voters did not converge on one contracted organization (digests %d)", len(digests))
		}
		time.Sleep(100 * time.Millisecond)
	}
	for _, id := range []uint64{1, 2, 3} {
		for _, st := range cluster.App(id).ReplicationStatus() {
			if st.Failed {
				t.Fatalf("voter %d stopped applying", id)
			}
		}
	}
}

// loginAs logs email in on app and returns a fresh credential.
func loginAs(t *testing.T, app *appcore.App, email string) auth.Credential {
	t.Helper()
	var s auth.Session
	var err error
	for range 40 {
		if s, err = app.Auth.Login(context.Background(), email, contractSecret, ""); !contractRetryable(err) {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("login %s: %v", email, err)
	}
	c, err := app.Auth.Authenticate(context.Background(), s.Token)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	return c
}

func restoreStashOf(t *testing.T, app *appcore.App, token string) {
	t.Helper()
	if err := app.Control.Update(context.Background(), func(st *model.ControlState) error {
		_, err := auth.QuarantineRestoredState(st, auth.RestoreInput{Generation: model.NewID(), Backup: model.NewID(), BootstrapHash: control.Hash(token), SealedBearerKey: "sealed", At: time.Now()})
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// A restored backup keeps the phase it was taken in: the quarantine does not drop the mark of a fresh
// installation, and the Bootstrap that follows a restore does not add it to a backup of an installation the
// previous release bootstrapped (it holds data the previous release can still read).
func TestRestoreKeepsThePhaseOfTheBackup(t *testing.T) {
	for _, tc := range []struct {
		name      string
		bootstrap func(*testing.T, *appcore.App)
		born      bool
	}{{"fresh", bootstrapFreshOwner, true}, {"upgraded", bootstrapOwner, false}} {
		t.Run(tc.name, func(t *testing.T) {
			app, err := appcore.Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer app.Close()
			tc.bootstrap(t, app)
			c := contractLogin(t, app)
			org, project := contractOrg(t, app, c)
			roots := contractSeed(t, app, org, project, 4)
			restoreStashOf(t, app, "restore-token")
			if got := installBornContracted(t, app); got != tc.born {
				t.Fatalf("after the quarantine of a restore the mark is %t, want %t", got, tc.born)
			}
			if _, err = app.Auth.Bootstrap(context.Background(), "restore-token", "restored-"+contractEmail, contractSecret); err != nil {
				t.Fatal(err)
			}
			if got := installBornContracted(t, app); got != tc.born {
				t.Fatalf("after the Bootstrap that follows a restore the mark is %t, want %t", got, tc.born)
			}
			if v := contractRead(t, app, org, project, roots); v.contracted != tc.born || v.legacyIndex == tc.born || v.loaded != len(roots) {
				t.Fatalf("restored organization: %+v", v)
			}
			c = loginAs(t, app, "restored-"+contractEmail)
			other, otherProject := contractOrg(t, app, c)
			if v := contractRead(t, app, other, otherProject, nil); v.contracted != tc.born {
				t.Fatalf("an organization created after the restore: %+v (born contracted %t)", v, tc.born)
			}
		})
	}
}
