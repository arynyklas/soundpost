// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package smokecluster

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"sync"

	raft "go.etcd.io/raft/v3"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/replica"
)

// Voters are the three node ids of the cluster.
var Voters = []uint64{1, 2, 3}

// Cluster is three real appcore.OpenDistributed voters in this process, each on
// its own private directory, joined over real mTLS peer listeners behind
// loopback relays. Node 1 is the initial leader of every group (it campaigns at
// every start). A node can be stopped and reopened on the same directory while
// the others keep running.
type Cluster struct {
	root    string
	seed    string
	ca      string
	pairs   map[uint64][2]string
	relays  *Relays
	targets map[uint64]string
	members replica.Members

	mu   sync.Mutex
	apps map[uint64]*appcore.App
}

// New prepares the private CA, relays and membership for the three voters. seed
// is the cluster seed file written by appcore.App.WriteClusterSeed from the
// installation the nodes continue.
func New(root, seed string) (*Cluster, error) {
	// Three voters of 65 groups each log every election at INFO to stderr; the
	// smoke reports what it observes, not the consensus library's chatter.
	raft.SetLogger(&raft.DefaultLogger{Logger: log.New(io.Discard, "", 0)})
	ca, pairs, err := Certificates(root)
	if err != nil {
		return nil, err
	}
	relays, err := NewRelays(Voters...)
	if err != nil {
		return nil, err
	}
	c := &Cluster{root: root, seed: seed, ca: ca, pairs: pairs, relays: relays, targets: map[uint64]string{}, apps: map[uint64]*appcore.App{}}
	c.members = replica.Members{Revision: 1}
	for _, id := range Voters {
		c.members.Nodes = append(c.members.Nodes, replica.Member{ID: id, Address: "https://" + relays.Address(id), NodeIdentity: fmt.Sprintf("node-%d", id), FailureDomain: fmt.Sprintf("local-process-directory-%d", id)})
	}
	return c, nil
}

// ListenAddress is the real address node id's mTLS peer listener is bound to
// (members dial the relay address; this one is for direct handshake probes).
func (c *Cluster) ListenAddress(id uint64) string { return c.targets[id] }

// Identity is the CA, certificate and private-key paths of node id.
func (c *Cluster) Identity(id uint64) (ca, certificate, key string) {
	return c.ca, c.pairs[id][0], c.pairs[id][1]
}

// NodeDir is the private data directory of node id.
func (c *Cluster) NodeDir(id uint64) string { return filepath.Join(c.root, fmt.Sprintf("node-%d", id)) }

// PeerAddress is the relay address the other voters dial for node id.
func (c *Cluster) PeerAddress(id uint64) string { return c.relays.Address(id) }

// Partition cuts (or restores) every peer connection to and from node id.
func (c *Cluster) Partition(id uint64, blocked bool) { c.relays.Partition(id, blocked) }

// Members is the configured membership.
func (c *Cluster) Members() replica.Members { return c.members }

// App is the running node id, or nil if it is stopped.
func (c *Cluster) App(id uint64) *appcore.App {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.apps[id]
}

// Running lists the running node ids in order.
func (c *Cluster) Running() []uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]uint64, 0, len(c.apps))
	for id := range c.apps {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Open starts (or restarts, on its existing directory) the listed nodes
// concurrently: a starting node waits for every group to answer, which needs a
// quorum of peers also starting. Each node gets a fresh peer listen address
// right before it starts; the relays keep the membership address valid.
func (c *Cluster) Open(ids ...uint64) error {
	c.mu.Lock()
	for _, id := range ids {
		if c.apps[id] != nil {
			c.mu.Unlock()
			return fmt.Errorf("node %d is already running", id)
		}
	}
	c.mu.Unlock()
	for _, id := range ids {
		c.relays.Partition(id, false)
	}
	if err := AssignPeers(c.relays, c.targets, ids...); err != nil {
		return err
	}
	type opened struct {
		id  uint64
		app *appcore.App
		err error
	}
	results := make(chan opened, len(ids))
	for _, id := range ids {
		config := appcore.NodeConfig{NodeID: id, PeerListen: c.targets[id], PeerSourceIP: PeerSourceIP(id), Certificate: c.pairs[id][0], PrivateKey: c.pairs[id][1], CA: c.ca, Seed: c.seed, Members: c.members, InitialLeader: 1}
		go func() {
			raw, err := json.Marshal(config)
			if err != nil {
				results <- opened{id: id, err: err}
				return
			}
			// The configuration goes through its strict wire decoder exactly as
			// `soundpost serve --cluster-config` reads it.
			var decoded appcore.NodeConfig
			if err = json.Unmarshal(raw, &decoded); err != nil {
				results <- opened{id: id, err: err}
				return
			}
			if err = os.MkdirAll(c.NodeDir(id), 0o700); err != nil {
				results <- opened{id: id, err: err}
				return
			}
			app, err := appcore.OpenDistributed(c.NodeDir(id), decoded)
			results <- opened{id: id, app: app, err: err}
		}()
	}
	var failure error
	for range ids {
		r := <-results
		if r.err != nil {
			failure = errors.Join(failure, fmt.Errorf("node %d: %w", r.id, r.err))
			continue
		}
		c.mu.Lock()
		c.apps[r.id] = r.app
		c.mu.Unlock()
	}
	return failure
}

// Stop takes node id out of service the way a lost node disappears: every peer
// connection to and from it is cut first (so it cannot hand leadership over),
// then its peer listener, groups and databases are closed. The others see a
// node that is gone.
func (c *Cluster) Stop(id uint64) error {
	c.mu.Lock()
	app := c.apps[id]
	delete(c.apps, id)
	c.mu.Unlock()
	if app == nil {
		return fmt.Errorf("node %d is not running", id)
	}
	c.relays.Partition(id, true)
	return app.Close()
}

// Close stops every running node and the relays.
func (c *Cluster) Close() {
	for _, id := range c.Running() {
		_ = c.Stop(id)
	}
	c.relays.Close()
}
