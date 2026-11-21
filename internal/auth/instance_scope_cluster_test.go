// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package auth_test

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/smokecluster"
)

// The instance scope of a one-shot command on a voter of a real three-voter cluster is never answered
// `stale` for an index race: another voter commits control writes all the time (the real cluster's
// background writers; here a loop of real commits), and the scope's own control write reads the state,
// computes and proposes through the leader. This is `soundpost backup create --mode distributed` on a
// node that has just joined its cluster (the deletion-cluster smoke answered `soundpost backup failed:
// stale` 2 s into the command, in the lag-1 run that takes the older backup through the stopped initial
// leader). Nothing is injected: three appcore voters over real mTLS peer listeners.
func TestInstanceScopeOnAVoterIsNotAnsweredStaleByCompetingControlWrites(t *testing.T) {
	work := t.TempDir()
	live := filepath.Join(work, "live")
	if err := os.MkdirAll(live, 0o700); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	const email, secret = "owner@instance-scope.invalid", "instance scope cluster password 2026"
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
	const caller, competitor = 3, 2
	session, err := cluster.App(caller).Auth.Login(ctx, email, secret, "")
	if err != nil {
		t.Fatal(err)
	}
	credential, err := cluster.App(caller).Auth.Authenticate(ctx, session.Token)
	if err != nil {
		t.Fatal(err)
	}

	stop := make(chan struct{})
	var competing sync.WaitGroup
	var commits int
	competing.Add(1)
	go func() {
		defer competing.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if cluster.App(competitor).Control.Update(ctx, func(*model.ControlState) error { return nil }) == nil {
				commits++
			}
		}
	}()
	stale := 0
	const scopes = 60
	for i := range scopes {
		if _, err = cluster.App(caller).Auth.InstanceScope(ctx, credential, "a backup of the cluster"); err != nil {
			stale++
			t.Logf("scope %d of %d on node %d: %v", i+1, scopes, caller, err)
		}
	}
	close(stop)
	competing.Wait()
	if commits == 0 {
		t.Fatal("the competing voter committed nothing: the test measured no race")
	}
	if stale != 0 {
		t.Fatalf("%d of %d instance scopes were refused while node %d committed %d control writes: the scope's write lost the race for its index and was answered instead of repeated", stale, scopes, competitor, commits)
	}
}
