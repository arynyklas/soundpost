// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package auth_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/smokecluster"
)

// A login made at once on a voter that was just restarted commits on its first attempt even though
// another voter commits a control write while the login checks the password.
//
// This is the real restart: three appcore voters joined over real mTLS peer listeners
// (internal/smokecluster), one (or all) closed and reopened on the same directory, then the first
// login made the moment Open returned. Nothing is injected. The competing write is a real control
// commit by another voter, made as soon as the login's password KDF starts: the situation of the
// install-distributed smoke, where the leader's background workers commit control writes (job
// producer save, outbox claim, ingest admissions) all the time and a login answered the typed
// retryable `stale` for the control write that lost the race for its index
// (login_stale_retries_before_success of 5 and 6 per run).
//
// auth.KDFRuns counts attempts: a login runs one password KDF per attempt, so one run means the
// first attempt committed. Before the fix the KDF ran inside the control write, the competing commit
// landed between the write's read of the state and its proposal, and the login needed a second
// attempt (and, on the real cluster, was answered stale until the bounded wait of wave 10 was
// added). The read-index window is not the cause: the node answers its ReadIndex rounds before Open
// returns (a restarted node is not ready until every group answered one).
func TestLoginRightAfterAVoterRestartCommitsOnItsFirstAttemptDespiteACompetingWrite(t *testing.T) {
	work := t.TempDir()
	live := filepath.Join(work, "live")
	if err := os.MkdirAll(live, 0o700); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	const email, secret = "owner@restart-login.invalid", "restart login test password 2026"
	app, err := appcore.Open(live)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap, err := app.Control.BootstrapToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = app.Auth.Bootstrap(ctx, bootstrap, email, secret); err != nil {
		t.Fatal(err)
	}
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
	if err = cluster.Open(smokecluster.Voters...); err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []struct {
		name string
		ids  []uint64
	}{
		{"a follower restarts", []uint64{2}},
		{"the initial leader restarts", []uint64{1}},
		{"the whole cluster restarts (quorum loss recovery)", []uint64{1, 2, 3}},
		{"two voters restart together", []uint64{2, 3}},
	} {
		for _, id := range scenario.ids {
			if err = cluster.Stop(id); err != nil {
				t.Fatalf("%s: stop %d: %v", scenario.name, id, err)
			}
		}
		if err = cluster.Open(scenario.ids...); err != nil {
			t.Fatalf("%s: reopen %v: %v", scenario.name, scenario.ids, err)
		}
		for _, id := range scenario.ids {
			other := id%3 + 1
			before, retriesBefore := auth.KDFRuns(), auth.LoginStaleRetries()
			competed := make(chan error, 1)
			go func() {
				deadline := time.Now().Add(30 * time.Second)
				for auth.KDFRuns() == before {
					if time.Now().After(deadline) {
						competed <- context.DeadlineExceeded
						return
					}
					time.Sleep(time.Millisecond)
				}
				// The login's password check has started: another voter commits a control write now.
				competed <- cluster.App(other).Control.Update(ctx, func(*model.ControlState) error { return nil })
			}()
			began := time.Now()
			session, err := cluster.App(id).Auth.Login(ctx, email, secret, "")
			if err != nil {
				t.Fatalf("%s: login on node %d: %v", scenario.name, id, err)
			}
			if err = <-competed; err != nil {
				t.Fatalf("%s: the competing write of node %d: %v", scenario.name, other, err)
			}
			if retries := auth.LoginStaleRetries() - retriesBefore; retries != 0 {
				t.Errorf("%s: the login on node %d needed the stale wait %d time(s): it was answered stale and repeated", scenario.name, id, retries)
			}
			if attempts := auth.KDFRuns() - before; attempts != 1 {
				t.Errorf("%s: the login on node %d needed %d attempts (it took %v), want 1: the control write lost the race for its index to a commit made while the password was checked", scenario.name, id, attempts, time.Since(began).Round(time.Millisecond))
			}
			if _, err = cluster.App(other).Auth.Authenticate(ctx, session.Token); err != nil {
				t.Errorf("%s: the session of node %d does not authenticate on node %d: %v", scenario.name, id, other, err)
			}
		}
	}
}
