// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package acceptance

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/notify"
	"github.com/arynyklas/soundpost/internal/smokecluster"
)

// accLayout is the control group the acceptance tests run on. Every notification
// acceptance test runs on BOTH: the one-voter node it has always used and a real
// three-voter control group (three appcore.OpenDistributed voters in this process,
// each on its own directory, joined over real mTLS peer listeners; the control
// group and the 64 data groups each have three voters). Node 1 leads and is the
// node the worker, the services and the tests drive.
type accLayout string

const (
	layoutSingle  accLayout = "single_voter"
	layoutCluster accLayout = "three_voters"
)

// eachLayout runs one hand-driven acceptance journey on every layout, each on a
// fresh node.
func eachLayout(t *testing.T, journey func(t *testing.T, n *accNode)) {
	t.Helper()
	onEachLayout(t, newAccNode, journey)
}

// eachServedLayout runs one served-pipeline journey on every layout.
func eachServedLayout(t *testing.T, journey func(t *testing.T, n *accNode)) {
	t.Helper()
	onEachLayout(t, newServedNode, journey)
}

func onEachLayout(t *testing.T, fixture func(*testing.T, accLayout) *accNode, journey func(t *testing.T, n *accNode)) {
	t.Helper()
	for _, layout := range []accLayout{layoutSingle, layoutCluster} {
		t.Run(string(layout), func(t *testing.T) {
			if layout == layoutCluster && runtime.GOOS != "linux" {
				t.Skip("the three-voter layout needs the 127.0.0.0/8 peer source addresses of Linux (internal/smokecluster); the gate is the Linux run")
			}
			journey(t, fixture(t, layout))
		})
	}
}

const (
	accOwnerEmail    = "acceptance-owner@example.test"
	accOwnerPassword = "acceptance password 2026"
)

// provisionSeed builds the installation the three voters continue: a single node
// bootstraps the owner, exports the authenticated cluster seed and closes. The
// voters never bootstrap users or keys independently.
func (n *accNode) provisionSeed() (user model.ID) {
	n.t.Helper()
	app, err := appcore.Open(filepath.Join(n.dir, "seed-installation"))
	if err != nil {
		n.t.Fatal(err)
	}
	boot, err := app.Control.BootstrapToken()
	if err != nil {
		_ = app.Close()
		n.t.Fatal(err)
	}
	session, err := app.Auth.Bootstrap(n.ctx, boot, accOwnerEmail, accOwnerPassword)
	if err != nil {
		_ = app.Close()
		n.t.Fatal(err)
	}
	if err = app.WriteClusterSeed(filepath.Join(n.dir, "cluster.seed")); err != nil {
		_ = app.Close()
		n.t.Fatal(err)
	}
	if err = app.Close(); err != nil {
		n.t.Fatal(err)
	}
	return session.User
}

// startProduct opens the product on its layout: the one node, or every voter of
// the cluster (which need each other to answer), and leaves n.app at the leader.
func (n *accNode) startProduct() {
	n.t.Helper()
	if n.layout != layoutCluster {
		var err error
		if n.app, err = appcore.Open(n.dir); err != nil {
			n.t.Fatal(err)
		}
		return
	}
	if n.cluster == nil {
		n.owner = n.provisionSeed()
		root := filepath.Join(n.dir, "cluster")
		if err := os.MkdirAll(root, 0o700); err != nil {
			n.t.Fatal(err)
		}
		c, err := smokecluster.New(root, filepath.Join(n.dir, "cluster.seed"))
		if err != nil {
			n.t.Fatal(err)
		}
		n.cluster = c
	}
	if err := n.cluster.Open(smokecluster.Voters...); err != nil {
		n.t.Fatal(err)
	}
	n.requireThreeVoters()
	n.leadNode(n.leader())
	n.app = n.cluster.App(n.leader())
}

// stopProduct is the death of the whole product: the node, or every voter.
func (n *accNode) stopProduct() {
	n.t.Helper()
	if n.layout == layoutCluster {
		for _, id := range n.cluster.Running() {
			if err := n.cluster.Stop(id); err != nil {
				n.t.Fatal(err)
			}
		}
		n.app, n.leaderID = nil, 0
		return
	}
	if err := n.app.Close(); err != nil {
		n.t.Fatal(err)
	}
	n.app = nil
}

// shutdown releases whatever is still running when the test ends.
func (n *accNode) shutdown() {
	if n.cluster != nil {
		n.cluster.Close()
		return
	}
	if n.app != nil {
		n.app.Close()
	}
}

// requireThreeVoters proves the control group the journey runs on is the cluster it
// claims to be: every node serves the control group and the 64 data groups, each with
// the same three voters and no learner.
func (n *accNode) requireThreeVoters() {
	n.t.Helper()
	for _, id := range smokecluster.Voters {
		app := n.cluster.App(id)
		if app == nil {
			n.t.Fatalf("voter %d is not running", id)
		}
		status := app.ReplicationStatus()
		if len(status) != 65 {
			n.t.Fatalf("voter %d serves %d groups, want 65 (control and 64 data)", id, len(status))
		}
		for _, g := range status {
			voters := 0
			for _, m := range g.Members.Nodes {
				if !m.Learner {
					voters++
				}
			}
			if g.Failed || g.ID != id || voters != 3 || len(g.Members.Nodes) != 3 {
				n.t.Fatalf("voter %d group %s: failed=%v id=%d voters=%d of %d members", id, g.Group, g.Failed, g.ID, voters, len(g.Members.Nodes))
			}
		}
	}
}

// leadNode makes voter id the leader of every group. A cluster that starts elects
// whichever voter wins first, and the worker that holds the control group's lease
// must be on the node the test drives, so leadership is moved there through the
// replica API and awaited as state, not assumed.
func (n *accNode) leadNode(id uint64) {
	n.t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for {
		pending := 0
		for _, s := range n.cluster.App(id).ReplicationStatus() {
			if s.Leader == id {
				continue
			}
			pending++
			if s.Leader == 0 {
				continue
			}
			if leader := n.cluster.App(s.Leader); leader != nil {
				if g, err := leader.ReplicaNode().Group(s.Group); err == nil {
					ctx, cancel := context.WithTimeout(n.ctx, 5*time.Second)
					_ = g.TransferLeadership(ctx, id)
					cancel()
				}
			}
		}
		if pending == 0 {
			return
		}
		if time.Now().After(deadline) {
			n.t.Fatalf("voter %d did not become the leader of %d groups", id, pending)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// leaseOf is the leadership lease of the node the journey drives. On the cluster a
// loss of leadership under load is answered the way an operator would: leadership
// is moved back to the node the test drives and the lease is taken again.
func (n *accNode) leaseOf() (notify.FenceToken, error) {
	l, err := n.app.Control.ReplicaGroup().Fence(n.ctx)
	if err == nil || n.cluster == nil {
		return l, err
	}
	for attempt := 0; attempt < 5 && err != nil; attempt++ {
		n.leadNode(n.leader())
		l, err = n.app.Control.ReplicaGroup().Fence(n.ctx)
	}
	return l, err
}

// leader is the voter the journey drives: voter 1 until it is lost.
func (n *accNode) leader() uint64 {
	if n.leaderID == 0 {
		return 1
	}
	return n.leaderID
}

// loseTheLeader kills voter 1, the leader of every group, the way a lost node
// disappears (its peer connections are cut first, so it cannot hand leadership
// over). The two surviving voters elect a leader, voter 2 is made the leader of every
// group, and the journey carries on through it: the services, the ingest routes and
// the workers are rebuilt over voter 2's application, exactly as a restarted worker
// process on that node would be.
func (n *accNode) loseTheLeader() *servedPipeline {
	n.t.Helper()
	if n.layout != layoutCluster || n.leader() != 1 {
		n.t.Fatal("only voter 1 of a cluster can be lost")
	}
	if err := n.cluster.Stop(1); err != nil {
		n.t.Fatal(err)
	}
	n.leaderID = 2
	n.leadNode(2)
	n.app = n.cluster.App(2)
	n.authenticate()
	var err error
	if n.srcCred, err = n.app.Auth.AuthenticateSource(n.ctx, n.issued, "", false); err != nil {
		n.t.Fatal(err)
	}
	n.build()
	return n.serve()
}
