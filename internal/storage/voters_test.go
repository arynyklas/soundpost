// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
	pb "go.etcd.io/raft/v3/raftpb"
)

// testMesh is an in-process wire between the three voters' 64 data groups. It
// delivers through the real Group.Step/ReportDelivery path, one ordered queue
// per destination group, and can cut one node off the way the process smokes'
// relays do.
type testMesh struct {
	mu      sync.Mutex
	groups  map[uint64]map[model.ID]*replica.Group
	queues  map[meshQueueKey]chan meshMessage
	blocked map[uint64]bool
	// holdSnap, per destination node, blocks the delivery of snapshot messages until it is closed:
	// a snapshot the sender cut and sent that is still in transit.
	holdSnap map[uint64]chan struct{}
	stop     chan struct{}
	wg       sync.WaitGroup
	once     sync.Once
}
type meshQueueKey struct {
	to    uint64
	group model.ID
}
type meshMessage struct {
	from uint64
	m    *pb.Message
}
type meshTransport struct {
	mesh *testMesh
	node uint64
}

func newTestMesh() *testMesh {
	return &testMesh{groups: map[uint64]map[model.ID]*replica.Group{}, queues: map[meshQueueKey]chan meshMessage{}, blocked: map[uint64]bool{}, holdSnap: map[uint64]chan struct{}{}, stop: make(chan struct{})}
}
func (m *testMesh) register(node uint64, groups []*replica.Group) {
	// Status takes the group mutex, which a ticking group holds while it calls
	// Send, which takes m.mu: resolve identities before locking.
	ids := make([]model.ID, len(groups))
	for i, g := range groups {
		ids[i] = g.Status().Group
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.groups[node] == nil {
		m.groups[node] = map[model.ID]*replica.Group{}
	}
	for i, g := range groups {
		m.groups[node][ids[i]] = g
	}
}
func (m *testMesh) partition(node uint64, down bool) {
	m.mu.Lock()
	m.blocked[node] = down
	m.mu.Unlock()
}

// holdSnapshots keeps every snapshot message addressed to node in transit until the returned
// function is called.
func (m *testMesh) holdSnapshots(node uint64) (release func()) {
	gate := make(chan struct{})
	m.mu.Lock()
	m.holdSnap[node] = gate
	m.mu.Unlock()
	var once sync.Once
	return func() { once.Do(func() { close(gate) }) }
}
func (m *testMesh) close() {
	m.once.Do(func() { close(m.stop) })
	m.wg.Wait()
}
func (t meshTransport) Send(group model.ID, message *pb.Message) error {
	if message == nil || message.GetFrom() != t.node {
		return replica.ErrInvalid
	}
	key := meshQueueKey{to: message.GetTo(), group: group}
	t.mesh.mu.Lock()
	queue := t.mesh.queues[key]
	if queue == nil {
		select {
		case <-t.mesh.stop: // closed: a delivery goroutine started now would outlive close's Wait
			t.mesh.mu.Unlock()
			return replica.ErrUnavailable
		default:
		}
		queue = make(chan meshMessage, 256)
		t.mesh.queues[key] = queue
		t.mesh.wg.Add(1)
		go t.mesh.deliver(key, queue)
	}
	t.mesh.mu.Unlock()
	select {
	case <-t.mesh.stop:
		return replica.ErrUnavailable
	case queue <- meshMessage{from: t.node, m: message}:
		return nil
	default:
		return replica.ErrUnavailable
	}
}
func (m *testMesh) deliver(key meshQueueKey, queue <-chan meshMessage) {
	defer m.wg.Done()
	for {
		select {
		case <-m.stop:
			return
		case in := <-queue:
			if in.m.GetType() == pb.MsgSnap {
				m.mu.Lock()
				gate := m.holdSnap[key.to]
				m.mu.Unlock()
				if gate != nil {
					select {
					case <-gate:
					case <-m.stop:
						return
					}
				}
			}
			m.mu.Lock()
			destination, source := m.groups[key.to][key.group], m.groups[in.from][key.group]
			down := m.blocked[in.from] || m.blocked[key.to]
			m.mu.Unlock()
			var err error
			switch {
			case destination == nil || down:
				err = replica.ErrUnavailable
			default:
				if stepped := destination.Step(context.Background(), in.m); errors.Is(stepped, replica.ErrUnavailable) {
					err = stepped
				}
			}
			if source != nil {
				source.ReportDelivery(key.to, in.m.GetType() == pb.MsgSnap, err)
			}
		}
	}
}

// voters are three storage engines of one installation, each with its own
// private directory, bolt database, segments and 64 Raft groups.
type voters struct {
	mesh    *testMesh
	dirs    map[uint64]string
	engines map[uint64]*Engine
	groups  map[uint64][]*replica.Group
}

func openVoters(t *testing.T, service *auth.Service, store *control.Store) *voters {
	t.Helper()
	v := &voters{mesh: newTestMesh(), dirs: map[uint64]string{}, engines: map[uint64]*Engine{}, groups: map[uint64][]*replica.Group{}}
	members := replica.Members{Revision: 1}
	for node := uint64(1); node <= 3; node++ {
		members.Nodes = append(members.Nodes, replica.Member{ID: node, Address: "https://node" + string(rune('0'+node)) + ".invalid", NodeIdentity: "node-" + string(rune('0'+node)), FailureDomain: "disk-" + string(rune('0'+node))})
	}
	var seed ReplicationSeed
	for node := uint64(1); node <= 3; node++ {
		dir := t.TempDir()
		engine, err := Open(dir, service)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { engine.Close() })
		if node == 1 {
			if seed, err = engine.ReplicationSeed(); err != nil {
				t.Fatal(err)
			}
		} else if err = engine.InstallReplicationIdentity(seed.Identity); err != nil {
			t.Fatal(err)
		}
		groups, err := engine.EnableReplication(replica.Config{ID: node, Directory: filepath.Join(dir, "raft"), Transport: meshTransport{mesh: v.mesh, node: node}, Members: members, TickInterval: 20 * time.Millisecond}, &seed, store)
		if err != nil {
			t.Fatal(err)
		}
		v.mesh.register(node, groups)
		v.dirs[node], v.engines[node], v.groups[node] = dir, engine, groups
	}
	t.Cleanup(v.mesh.close)
	return v
}

// lead makes assign(slot) the leader of every data group, using real
// campaigns and leadership transfers.
func (v *voters) lead(t *testing.T, assign func(slot int) uint64) {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for slot := range 64 {
		want := assign(slot)
		for {
			if time.Now().After(deadline) {
				t.Fatalf("slot %d never moved to node %d", slot, want)
			}
			leader := v.groups[want][slot].Status().Leader
			if leader == want {
				break
			}
			if leader == 0 {
				_ = v.groups[want][slot].Campaign()
				time.Sleep(20 * time.Millisecond)
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = v.groups[leader][slot].TransferLeadership(ctx, want)
			cancel()
		}
	}
}

// append routes one batch to its slot's current leader and retries a leadership
// move as a client would. Only a returned receipt is an ACK.
func (v *voters) append(scope auth.Scope, b model.NormalizedBatch) (model.Receipt, error) {
	deadline := time.Now().Add(45 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		leader := v.groups[1][b.RouteSlot].Status().Leader
		for _, node := range []uint64{leader, 1, 2, 3} {
			if node == 0 {
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			receipt, err := v.engines[node].Append(ctx, scope, b)
			cancel()
			if err == nil {
				return receipt, nil
			}
			var fault *model.Fault
			if !errors.As(err, &fault) || fault.Code != model.Unavailable && fault.Code != model.Stale {
				return model.Receipt{}, err
			}
			last = err
			if node == leader {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	return model.Receipt{}, last
}

// converge waits until every engine applied the same prefix of every slot and
// at least want[slot] commands.
func (v *voters) converge(t *testing.T, want map[uint16]uint64) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for {
		var first [64]uint64
		equal := true
		for node := uint64(1); node <= 3; node++ {
			e := v.engines[node]
			e.mu.Lock()
			indexes := e.indexes
			e.mu.Unlock()
			if node == 1 {
				first = indexes
			} else if indexes != first {
				equal = false
			}
		}
		for slot, n := range want {
			if first[slot] < n {
				equal = false
			}
		}
		if equal {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("voters never converged on the same applied prefix")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (v *voters) manifest(node uint64) Manifest {
	e := v.engines[node]
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.catalog.Manifest
}

// maintain is one node-local maintenance round: flush, rewrite, cut a verified
// snapshot of every group and truncate each journal to it.
func (v *voters) maintain(node uint64) error {
	e := v.engines[node]
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := e.Flush(ctx); err != nil {
		return errors.Join(errors.New("flush"), err)
	}
	if err := e.Compact(ctx); err != nil {
		return errors.Join(errors.New("compact"), err)
	}
	if _, err := e.CreateSnapshots(ctx); err != nil {
		return errors.Join(errors.New("snapshot"), err)
	}
	if err := e.CompactJournals(ctx); err != nil {
		return errors.Join(errors.New("truncate"), err)
	}
	return nil
}
