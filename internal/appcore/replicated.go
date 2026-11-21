// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sync/atomic"
	"time"

	"github.com/arynyklas/soundpost/internal/backup"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/durablefs"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
	"github.com/arynyklas/soundpost/internal/storage"
)

type ClusterSeed struct {
	Version            uint16                  `json:"version"`
	Control            []byte                  `json:"control"`
	ControlApplication model.Uint64            `json:"control_application"`
	ControlPhysical    model.Uint64            `json:"control_physical"`
	ControlTerm        model.Uint64            `json:"control_term"`
	Data               storage.ReplicationSeed `json:"data"`
	// Retired are the node identities of the cluster a disaster restore rebuilt this
	// installation from. OpenDistributed refuses a membership that names one of them, so the
	// restored cluster has fresh identities and no node of the lost cluster is a member of it.
	Retired []string `json:"retired_identities,omitempty"`
}
type NodeConfig struct {
	NodeID        uint64          `json:"node_id,string"`
	PeerListen    string          `json:"peer_listen"`
	PeerSourceIP  string          `json:"peer_source_ip,omitempty"`
	Certificate   string          `json:"certificate"`
	PrivateKey    string          `json:"private_key"`
	CA            string          `json:"ca"`
	Seed          string          `json:"seed"`
	Members       replica.Members `json:"members"`
	InitialLeader uint64          `json:"initial_leader,string"`
}
type replicationOptions struct {
	node      NodeConfig
	seed      *ClusterSeed
	transport *replica.MTLS
	server    *http.Server
	listener  net.Listener
	fresh     bool
}
type replicatedApp struct {
	transport interface{ Close() error }
	server    *http.Server
	groups    []*replica.Group
	node      *replica.Node
	// domain is the fate shared by the control group and the 64 data groups of this node: a
	// storage failure of any of them fails them all closed (replica.FailDomain).
	domain *replica.FailDomain
	// dir is the data directory this node was opened on.
	dir string
	// layoutRefused makes this member answer the live layout question as the previous release does (the
	// question is not implemented); only LimitLiveLayoutForTest sets it.
	layoutRefused atomic.Bool
}

// LimitLiveLayoutForTest makes this member answer the other members' live layout question as the previous
// release would (the question is not implemented), so that `contract-indexes` is refused naming it.
func (a *App) LimitLiveLayoutForTest(refuse bool) {
	if a.replication != nil {
		a.replication.layoutRefused.Store(refuse)
	}
}

// awaitReady waits for one ReadIndex quorum round on a group. Each round has
// its own five-second freshness window, and a group that has no leader or quorum
// yet (a peer that is still starting, a replacement learner being repaired from
// snapshots, an election in progress under disk contention) fails that window
// with ErrStale. The startup context, not one window, bounds how long a node
// waits, so a node does not abandon startup at the first slow group while its
// startup budget remains. Intake stays closed until every group answered; any
// error other than the freshness window (a failed or closed group) is final.
func awaitReady(ctx context.Context, g *replica.Group) error {
	for {
		err := g.Ready(ctx)
		if err == nil || !errors.Is(err, replica.ErrStale) || ctx.Err() != nil {
			return err
		}
	}
}
func OpenDistributed(dir string, node NodeConfig) (*App, error) {
	if err := replica.ValidateMembers(node.Members); err != nil || len(node.Members.Nodes) < 3 || node.Seed == "" || node.PeerListen == "" {
		return nil, model.Fail(model.Invalid)
	}
	_, statErr := os.Stat(filepath.Join(dir, "control.db"))
	fresh := os.IsNotExist(statErr)
	if statErr != nil && !fresh {
		return nil, statErr
	}
	raw, err := os.ReadFile(node.Seed)
	if err != nil {
		return nil, err
	}
	var seed ClusterSeed
	if model.StrictJSON(raw, &seed) != nil || seed.Version != 1 {
		return nil, model.Fail(model.Corrupt)
	}
	for _, member := range node.Members.Nodes {
		if slices.Contains(seed.Retired, member.NodeIdentity) {
			return nil, model.Fail(model.Invalid)
		}
	}
	certificate, err := tls.LoadX509KeyPair(node.Certificate, node.PrivateKey)
	if err != nil {
		return nil, err
	}
	ca, err := os.ReadFile(node.CA)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, model.Fail(model.Invalid)
	}
	identity := ""
	for _, member := range node.Members.Nodes {
		if member.ID == node.NodeID {
			identity = member.NodeIdentity
		}
	}
	transport, err := replica.NewMTLS(node.NodeID, identity, certificate, roots, node.PeerSourceIP)
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp", node.PeerListen)
	if err != nil {
		transport.Close()
		return nil, err
	}
	server := &http.Server{Handler: transport, TLSConfig: transport.ServerTLS(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second}
	go func() { _ = server.Serve(tls.NewListener(listener, server.TLSConfig)) }()
	options := &replicationOptions{node: node, seed: &seed, transport: transport, server: server, listener: listener, fresh: fresh}
	app, err := open(dir, options)
	if err != nil {
		server.Close()
		transport.Close()
		return nil, err
	}
	return app, nil
}
func openControl(dir string, options *replicationOptions) (*control.Store, error) {
	if options != nil {
		return control.OpenSeed(dir, options.seed.Control)
	}
	return control.Open(dir)
}
func (a *App) enableReplication(dir string, options *replicationOptions, budget time.Duration) (err error) {
	ctx := context.Background()
	// A node whose journal is behind what it acknowledged fails closed while it starts (a peer's heartbeat
	// commits beyond its journal); the startup step that notices it next only sees unavailable or stale.
	// Report the cause, so the operator gets reason=journal_behind_acknowledged.
	defer func() {
		if a.replication != nil {
			err = a.replication.domain.Cause(err)
		}
	}()
	var installation model.ID
	if err := a.Control.View(ctx, func(st model.ControlState) error { installation = st.Installation; return nil }); err != nil {
		return err
	}
	cfg := replica.Config{ID: 1, Group: installation, Directory: filepath.Join(dir, "raft", "control"), TickInterval: 100 * time.Millisecond, Members: replica.Members{Revision: 1, Nodes: []replica.Member{{ID: 1, Address: "https://single.invalid", NodeIdentity: "single", FailureDomain: "local-disk"}}}}
	// A restored single-voter root starts its data groups from snapshots cut in the backed-up
	// installation, possibly a cluster: their membership is this root's, not the source's.
	cfg.RebaseInstalled = options == nil && backup.IsRestoredRoot(dir)
	var register func(*replica.Group) error
	var lifecycle *replicatedApp
	var dataSeed *storage.ReplicationSeed
	if options == nil {
		local := replica.NewLoopback()
		cfg.Transport = local
		register = local.Register
		lifecycle = &replicatedApp{transport: local}
	} else {
		cfg.ID = options.node.NodeID
		cfg.Members = options.node.Members
		cfg.Transport = options.transport
		cfg.Seed = options.seed.Control
		cfg.Application = uint64(options.seed.ControlApplication)
		if options.seed.ControlPhysical == ^model.Uint64(0) || options.seed.ControlTerm == ^model.Uint64(0) {
			return model.Fail(model.Unavailable)
		}
		cfg.SeedIndex = uint64(options.seed.ControlPhysical) + 1
		cfg.SeedTerm = uint64(options.seed.ControlTerm) + 1
		register = options.transport.Register
		lifecycle = &replicatedApp{transport: options.transport, server: options.server}
		dataSeed = &options.seed.Data
		if err := a.Storage.InstallReplicationIdentity(dataSeed.Identity); err != nil {
			return err
		}
	}
	lifecycle.domain = replica.NewFailDomain()
	lifecycle.dir = dir
	cfg.Domain = lifecycle.domain
	a.replication = lifecycle
	// The bounded-state rules of control (control.Store.BoundedRules) apply once every member of the
	// slot-0 group declared the protocol: the gate is in place before the control group can decide a
	// command, and reads false until storage's replication is up and everyone declared.
	a.Control.SetBoundedRulesGate(a.Storage.ControlBoundsReady)
	// The audit delta command of control (control.Store.AppendAudit) is proposed once every member
	// declared protocol 4; the gate reads false until storage's replication is up and everyone did.
	a.Control.SetAuditDeltaGate(a.Storage.ControlAuditDeltaReady)
	// A control command is proposed as a state patch (control.Store.SetStatePatchGate), so that no
	// command grows with the control state, once every member declared protocol 5. The patch flows
	// on the control group, so the gate reads that group's own committed configuration (a
	// membership change that reached it but not slot 0 must not open the gate for its new member).
	a.Control.SetStatePatchGate(func() bool {
		group := a.Control.ReplicaGroup()
		return group != nil && a.Storage.ControlStatePatchReady(group.Status().Members.Nodes)
	})
	// D70: `soundpost upgrade contract-indexes` is refused unless the RUNNING binary of every member
	// of the control group answers the live layout question over the mesh. A stored declaration
	// cannot say it (a voter put back on the previous release keeps what it last wrote), and the
	// previous release does not implement the question, so a member that does not answer, for any
	// reason, is named and the step is refused.
	if options != nil {
		options.transport.SetLayoutSupport(func() (uint64, bool) { return model.IndexLayoutVersion, !lifecycle.layoutRefused.Load() })
	}
	self := cfg.ID
	// readsLayout is the live question to one member: nil when its running binary answers that it reads
	// the contracted layout. The same question guards a member joining the membership and the snapshot
	// sent to a member once an organization is contracted (control.Store.CheckMemberLayout).
	readsLayout := func(ctx context.Context, m replica.Member) error {
		if options == nil {
			return model.Fail(model.Unavailable)
		}
		got, qerr := options.transport.QueryLayout(ctx, m)
		if qerr == nil && got < model.IndexLayoutVersion {
			qerr = model.Fail(model.Unsupported)
		}
		return qerr
	}
	a.Control.SetMemberLayoutQuery(readsLayout)
	a.Control.SetLayoutSupportGate(func() []string {
		group := a.Control.ReplicaGroup()
		if group == nil || len(group.Status().Members.Nodes) == 0 {
			return []string{"unknown"}
		}
		var lacking []string
		for _, m := range group.Status().Members.Nodes {
			if m.ID != self && readsLayout(context.Background(), m) != nil {
				lacking = append(lacking, m.NodeIdentity)
			}
		}
		return lacking
	})
	a.Auth.SetIndexContractor(contractIndexes)
	controlGroup, err := a.Control.EnableReplication(cfg)
	if err != nil {
		return err
	}
	lifecycle.groups = append(lifecycle.groups, controlGroup)
	if err = register(controlGroup); err != nil {
		return err
	}
	campaign := options == nil || cfg.ID == options.node.InitialLeader
	if campaign {
		if err = controlGroup.Campaign(); err != nil {
			return err
		}
	}
	cfg.Directory = filepath.Join(dir, "raft", "data")
	groups, err := a.Storage.EnableReplication(cfg, dataSeed, a.Control)
	if err != nil {
		return err
	}
	for _, g := range groups {
		lifecycle.groups = append(lifecycle.groups, g)
		if err = register(g); err != nil {
			return err
		}
		if campaign {
			if err = g.Campaign(); err != nil {
				return err
			}
		}
	}
	lifecycle.node, err = replica.NewNode(lifecycle.groups)
	if err != nil {
		return err
	}
	// Opened: from here the budget is the wait for each group's quorum.
	ready, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	for _, g := range lifecycle.groups {
		if err = awaitReady(ready, g); err != nil {
			return err
		}
	}
	if controlGroup.Status().Leader == cfg.ID {
		if err = model.RetryWhileStale(ready, func() error { return a.Control.ReconcileAdmissions(ready) }); err != nil {
			return err
		}
	}
	return nil
}
func (a *App) ReplicationStatus() []replica.Status {
	if a.replication == nil {
		return nil
	}
	out := make([]replica.Status, 0, len(a.replication.groups))
	for _, g := range a.replication.groups {
		out = append(out, g.Status())
	}
	return out
}
func (a *App) CloseReplication() error {
	if a.replication == nil {
		return nil
	}
	var first error
	if a.replication.server != nil {
		first = a.replication.server.Close()
	}
	for _, g := range a.replication.groups {
		if err := g.Close(); first == nil {
			first = err
		}
	}
	if err := a.replication.transport.Close(); first == nil {
		first = err
	}
	return first
}

// WriteClusterSeed is an offline/operator action: the opened databases must have
// exclusive ownership. The file contains installation secrets and private data;
// it must be transferred through an authenticated, confidential operator channel.
func (a *App) WriteClusterSeed(path string) error {
	if a.replication == nil {
		return model.Fail(model.Unavailable)
	}
	retired, err := a.restoredSourceIdentities()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for _, g := range a.replication.groups {
		if err := g.Ready(ctx); err != nil {
			return err
		}
	}
	controlSeed, application, err := a.Control.ReplicationSeed()
	if err != nil {
		return err
	}
	position := a.replication.groups[0].Status()
	dataSeed, err := a.Storage.ReplicationSeed()
	if err != nil {
		return err
	}
	raw, err := json.Marshal(ClusterSeed{Version: 1, Control: controlSeed, ControlApplication: model.Uint64(application), ControlPhysical: model.Uint64(position.Applied), ControlTerm: model.Uint64(position.Term), Data: dataSeed, Retired: retired})
	if err != nil {
		return err
	}
	return durablefs.Exclusive(path, raw)
}

// restoredSourceIdentities are the node identities of the cluster this installation was restored
// from (none for an installation no restore built). A restored root seeds nothing until its
// activation completed: before that its engine is closed and the deletion ledger is not applied.
func (a *App) restoredSourceIdentities() ([]string, error) {
	source, restored, err := backup.ReadClusterSource(a.replication.dir)
	if err != nil || !restored {
		return nil, err
	}
	if !source.Activated || a.Storage.RestoreReady() != nil {
		return nil, model.Fail(model.Conflict)
	}
	return source.Retired, nil
}

func (a *App) ReplicaNode() *replica.Node {
	if a.replication == nil {
		return nil
	}
	return a.replication.node
}

// StorageFailStop is closed when the storage of this node failed and every replication group of
// it was failed closed, so the node neither leads nor votes in any group until it is restarted.
// It is nil (never ready) when the application is not replicated.
func (a *App) StorageFailStop() <-chan struct{} {
	if a.replication == nil || a.replication.domain == nil {
		return nil
	}
	return a.replication.domain.Done()
}

// StorageFailure is the first storage failure of this node: the group that hit it and the closed
// reason. False while the storage is healthy.
func (a *App) StorageFailure() (replica.FailStop, bool) {
	if a.replication == nil || a.replication.domain == nil {
		return replica.FailStop{}, false
	}
	return a.replication.domain.Failure()
}
func (n *NodeConfig) UnmarshalJSON(raw []byte) error {
	var wire struct {
		NodeID        model.Uint64    `json:"node_id"`
		PeerListen    string          `json:"peer_listen"`
		PeerSourceIP  string          `json:"peer_source_ip,omitempty"`
		Certificate   string          `json:"certificate"`
		PrivateKey    string          `json:"private_key"`
		CA            string          `json:"ca"`
		Seed          string          `json:"seed"`
		Members       replica.Members `json:"members"`
		InitialLeader model.Uint64    `json:"initial_leader"`
	}
	if model.StrictJSON(raw, &wire) != nil {
		return model.Fail(model.Invalid)
	}
	*n = NodeConfig{NodeID: uint64(wire.NodeID), PeerListen: wire.PeerListen, PeerSourceIP: wire.PeerSourceIP, Certificate: wire.Certificate, PrivateKey: wire.PrivateKey, CA: wire.CA, Seed: wire.Seed, Members: wire.Members, InitialLeader: uint64(wire.InitialLeader)}
	return nil
}
