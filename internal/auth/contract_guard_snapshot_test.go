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
	"github.com/arynyklas/soundpost/internal/smokecluster"
)

// contractCluster opens three in-process voters over mTLS on a bootstrapped installation and returns them with a
// fresh administrator credential on voter 1 (the initial leader of every group).
func contractCluster(t *testing.T) (*smokecluster.Cluster, auth.Credential) {
	t.Helper()
	return contractClusterOf(t, bootstrapOwner)
}

// contractClusterOf is contractCluster for an installation that bootstrap prepares: a fresh one (bootstrapFreshOwner)
// or one the previous release bootstrapped (bootstrapOwner).
func contractClusterOf(t *testing.T, bootstrap func(*testing.T, *appcore.App)) (*smokecluster.Cluster, auth.Credential) {
	t.Helper()
	work := t.TempDir()
	live := filepath.Join(work, "live")
	if err := os.MkdirAll(live, 0o700); err != nil {
		t.Fatal(err)
	}
	app, err := appcore.Open(live)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap(t, app)
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
	return cluster, contractLogin(t, cluster.App(1))
}

func contractNow(t *testing.T, leader *appcore.App, c auth.Credential, reason string) {
	t.Helper()
	got, err := leader.Auth.ContractIndexes(context.Background(), c, contractRequest(reason))
	if err != nil || !got.Changed {
		t.Fatalf("contract: %+v %v", got, err)
	}
}

// (b) A snapshot of a contracted state is not sent to a member that does not answer the live layout question: it
// would install state it cannot read and then report ready. Before the contraction the same member receives it.
// Once the member answers, the snapshot goes and it catches up. (It also exercises the layout route under the
// snapshot traffic of a lagging member: the route once held the transport lock across a group's lock and
// deadlocked against a group that was sending.)
func TestSnapshotOfAContractedStateIsNotSentToAMemberThatCannotReadIt(t *testing.T) {
	cluster, c := contractCluster(t)
	leader := cluster.App(1)
	org, project := contractOrg(t, leader, c)
	contractSeed(t, leader, org, project, 5)
	ctx := context.Background()
	cut := func(id uint64) {
		t.Helper()
		g := cluster.App(id).Control.ReplicaGroup()
		if _, err := g.CreateSnapshot(ctx, g.Status().ApplicationCursor); err != nil {
			t.Fatalf("voter %d: cut: %v", id, err)
		}
		if _, err := g.Snapshots().DropSuperseded(); err != nil {
			t.Fatal(err)
		}
		if _, err := g.CompactJournal(ctx); err != nil {
			t.Fatalf("voter %d: compact: %v", id, err)
		}
	}
	applied := func(id uint64) uint64 { return cluster.App(id).Control.ReplicaGroup().Status().Applied }
	// lag isolates voter 3, advances the others past what its journal can be repaired from by entries,
	// then reconnects it answering the layout question as limit says.
	lag := func(limit bool) (target uint64) {
		t.Helper()
		cluster.Partition(3, true)
		contractSeed(t, leader, org, project, 3)
		contractSeed(t, leader, org, project, 3)
		cut(1)
		cut(2)
		target = applied(1)
		cluster.App(3).LimitLiveLayoutForTest(limit)
		cluster.Partition(3, false)
		return target
	}
	caughtUp := func(target uint64, within time.Duration) bool {
		deadline := time.Now().Add(within)
		for time.Now().Before(deadline) {
			if applied(3) >= target {
				return true
			}
			time.Sleep(100 * time.Millisecond)
		}
		return false
	}
	// Not contracted: the previous release can read it, so the member is sent the snapshot.
	if target := lag(true); !caughtUp(target, 60*time.Second) {
		t.Fatalf("before the contraction a member that cannot read the contracted layout was not repaired: applied %d of %d", applied(3), target)
	}
	cluster.App(3).LimitLiveLayoutForTest(false)
	contractNow(t, leader, c, "snapshot guard")
	target := lag(true)
	if caughtUp(target, 8*time.Second) {
		t.Fatalf("a snapshot of a contracted state was installed by a member that does not answer the live layout question (applied %d of %d)", applied(3), target)
	}
	cluster.App(3).LimitLiveLayoutForTest(false)
	if !caughtUp(target, 60*time.Second) {
		t.Fatalf("the member that answers again was not repaired: applied %d of %d", applied(3), target)
	}
}
