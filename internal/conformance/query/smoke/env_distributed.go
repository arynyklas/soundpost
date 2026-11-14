// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package smoke

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/smokecluster"
)

// provisionSeed builds the installation the three voters continue: it opens a
// single node, bootstraps the owner and the organization, exports the
// authenticated cluster seed (installation secrets and the control state) and
// closes the node. The voters never bootstrap users or keys independently.
func (e *Env) provisionSeed() error {
	app, err := appcore.Open(filepath.Join(e.dir, "seed-installation"))
	if err != nil {
		return err
	}
	e.app = app
	defer func() { e.app = nil }()
	if err = e.bootstrap(); err != nil {
		_ = app.Close()
		return err
	}
	e.seed = filepath.Join(e.dir, "cluster.seed")
	if err = app.WriteClusterSeed(e.seed); err != nil {
		_ = app.Close()
		return err
	}
	return app.Close()
}

// openCluster starts (or restarts) the three voters concurrently on their
// private directories and serves the owned routes on every one of them.
func (e *Env) openCluster() error {
	if e.cluster == nil {
		root := filepath.Join(e.dir, "cluster")
		if err := os.MkdirAll(root, 0o700); err != nil {
			return err
		}
		c, err := smokecluster.New(root, e.seed)
		if err != nil {
			return err
		}
		e.cluster = c
	}
	if err := e.cluster.Open(smokecluster.Voters...); err != nil {
		return err
	}
	for _, id := range smokecluster.Voters {
		if err := e.attachNode(id); err != nil {
			return err
		}
	}
	if err := e.requireThreeVoters(); err != nil {
		return err
	}
	return e.leadNode(1)
}

// attachNode serves the owned routes of a running voter. Node 1 is the primary
// node the case-file runners drive (gated scans, control access); the others
// serve the same routes over their own application state.
func (e *Env) attachNode(id uint64) error {
	app := e.cluster.App(id)
	if app == nil {
		return fmt.Errorf("node %d is not running", id)
	}
	if id == 1 {
		if err := e.attach(app); err != nil {
			return err
		}
		e.surfaces[1] = &surface{app: app, server: e.server, client: e.client}
		return nil
	}
	server := serveOwned(app, app.Query)
	e.surfaces[id] = &surface{app: app, server: server, client: server.Client()}
	return nil
}

// Cluster is the distributed environment's cluster; nil on the single layout.
func (e *Env) Cluster() *smokecluster.Cluster { return e.cluster }

// StopNode takes one voter out of service: its routes stop and its application
// closes, so the other voters see a node that is gone.
func (e *Env) StopNode(id uint64) error {
	if s := e.surfaces[id]; s != nil {
		s.server.Close()
		delete(e.surfaces, id)
	}
	if id == 1 {
		e.app = nil
	}
	return e.cluster.Stop(id)
}

// StartNodes restarts stopped voters on their existing directories and serves
// their routes again.
func (e *Env) StartNodes(ids ...uint64) error {
	if err := e.cluster.Open(ids...); err != nil {
		return err
	}
	for _, id := range ids {
		if err := e.attachNode(id); err != nil {
			return err
		}
	}
	return nil
}

// NodeApp is the application of running voter id.
func (e *Env) NodeApp(id uint64) *appcore.App { return e.cluster.App(id) }

// requireThreeVoters proves the installation the flows run on is the cluster it
// claims to be: every node serves the control group and the 64 data groups, each
// with the same three voters and no learner.
func (e *Env) requireThreeVoters() error {
	for _, id := range smokecluster.Voters {
		app := e.cluster.App(id)
		if app == nil {
			return fmt.Errorf("node %d is not running", id)
		}
		status := app.ReplicationStatus()
		if len(status) != 65 {
			return fmt.Errorf("node %d serves %d groups, want 65 (control and 64 data)", id, len(status))
		}
		for _, g := range status {
			voters := 0
			for _, m := range g.Members.Nodes {
				if !m.Learner {
					voters++
				}
			}
			if g.Failed || g.ID != id || voters != 3 || len(g.Members.Nodes) != 3 {
				return fmt.Errorf("node %d group %s: failed=%v id=%d voters=%d of %d members", id, g.Group, g.Failed, g.ID, voters, len(g.Members.Nodes))
			}
		}
	}
	return nil
}

// leadNode makes node id the leader of every group. A cluster that starts or
// restarts elects whichever voter wins first; flows that hold a leadership
// fence (rule evaluation) need the leader they drive, so leadership is moved
// there through the replica API and awaited as state, not assumed.
func (e *Env) leadNode(id uint64) error {
	deadline := time.Now().Add(30 * time.Second)
	for {
		pending := 0
		for _, s := range e.NodeApp(id).ReplicationStatus() {
			if s.Leader == id {
				continue
			}
			pending++
			if s.Leader == 0 {
				continue
			}
			if leader := e.cluster.App(s.Leader); leader != nil {
				if g, err := leader.ReplicaNode().Group(s.Group); err == nil {
					ctx, cancel := context.WithTimeout(e.ctx, 5*time.Second)
					_ = g.TransferLeadership(ctx, id)
					cancel()
				}
			}
		}
		if pending == 0 {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("node %d did not become the leader of %d groups", id, pending)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
