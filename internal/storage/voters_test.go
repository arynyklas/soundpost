// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
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
	// snaps counts the snapshot messages delivered to each node.
	snaps map[uint64]int
	// inflight counts, per sender and group, the messages Send accepted whose delivery (Step and ReportDelivery, or the drop
	// of a cut node's message) has not finished: what a node has answered but the receiver has not yet heard.
	inflight map[meshSource]int
	stop     chan struct{}
	wg       sync.WaitGroup
	once     sync.Once
}
type meshQueueKey struct {
	to    uint64
	group model.ID
}
type meshSource struct {
	from  uint64
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
	return &testMesh{groups: map[uint64]map[model.ID]*replica.Group{}, queues: map[meshQueueKey]chan meshMessage{}, blocked: map[uint64]bool{}, holdSnap: map[uint64]chan struct{}{}, snaps: map[uint64]int{}, inflight: map[meshSource]int{}, stop: make(chan struct{})}
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
	t.mesh.inflight[meshSource{from: t.node, group: group}]++
	t.mesh.mu.Unlock()
	select {
	case <-t.mesh.stop:
		t.mesh.finished(t.node, group)
		return replica.ErrUnavailable
	case queue <- meshMessage{from: t.node, m: message}:
		return nil
	default:
		t.mesh.finished(t.node, group)
		return replica.ErrUnavailable
	}
}

// finished records that a message of node in group is no longer in flight.
func (m *testMesh) finished(node uint64, group model.ID) {
	m.mu.Lock()
	m.inflight[meshSource{from: node, group: group}]--
	m.mu.Unlock()
}

// settled reports whether every message node sent in group has been delivered (or dropped).
func (m *testMesh) settled(node uint64, group model.ID) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.inflight[meshSource{from: node, group: group}] == 0
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
			if in.m.GetType() == pb.MsgSnap && !down && destination != nil {
				m.snaps[key.to]++
			}
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
			m.finished(in.from, key.group)
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
		engine.leadersPlaced = true // voters.lead assigns the leaders; the balancer would take them back after 10 s
		t.Cleanup(func() { engine.Close() })
		if node == 1 {
			if seed, err = engine.ReplicationSeed(); err != nil {
				t.Fatal(err)
			}
		} else if err = engine.InstallReplicationIdentity(seed.Identity); err != nil {
			t.Fatal(err)
		}
		groups, err := engine.EnableReplication(replica.Config{ID: node, Directory: filepath.Join(dir, "raft"), Transport: meshTransport{mesh: v.mesh, node: node}, Members: members, TickInterval: voterTick()}, &seed, store)
		if err != nil {
			t.Fatal(err)
		}
		v.mesh.register(node, groups)
		v.dirs[node], v.engines[node], v.groups[node] = dir, engine, groups
	}
	t.Cleanup(v.mesh.close)
	return v
}

// voterTick is the fixture's Raft tick. The race detector slows every goroutine several times
// over, and the fixture runs 192 groups on one process: with the 20 ms tick (election timeout 200
// ms) a delayed heartbeat or a starved leader's lost quorum contact moves a group's leadership
// off the voter a test just made leader, and the test's leader-bound write then answers
// unavailable (the in-process mesh has no proposal forwarder, so a follower cannot take it). The
// longer tick under -race keeps the fixture's leadership assumptions; the product's timing is not
// changed (the same fix as internal/control's voterTick, commit 21ca7d7).
func voterTick() time.Duration {
	if raceEnabled {
		return 100 * time.Millisecond
	}
	return 20 * time.Millisecond
}

// lead makes assign(slot) the leader of every data group, using real
// campaigns and leadership transfers. Slot 0 moves last: a voter that sends a snapshot first orders an
// erase notice on slot 0 (Engine.beforeSnapshotSend, 10.35#12), the test mesh has no proposal forwarder, and
// so the sender of a snapshot to a voter that lags (the stopped voter of the erase tests) must still lead
// slot 0 while the other 63 groups hand over; with slot 0 first, the groups still led by the old leader could
// never send their snapshot (166,565 refused sends in 90 s, TestStoppedVoterKeepsTheResidueNamedUntilItCatchesUp).
// Moving it last must not leave its new term's first entry behind on a voter that the test partitions next
// (TestAReceiptReadOnAnotherVoterIsDirtyFromTheNoticeOfASnapshotToAnAcknowledgedVoter relies on slot 0 needing no
// snapshot): lead returns when every voter the mesh does not hold back has committed what the leader of slot 0 holds.
func (v *voters) lead(t *testing.T, assign func(slot int) uint64) {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for slot := 1; slot < 64; slot++ {
		v.leadSlot(t, slot, assign(slot), deadline)
	}
	v.leadSlot(t, 0, assign(0), deadline)
	v.settleSlot(t, 0, assign(0), deadline)
}

// settleSlot waits until the leader of slot has committed an entry of its own term and every voter that is not partitioned
// has applied the last entry of the leader and the mesh has delivered everything that voter sent in the group.
//
// Two things the ready stage publishes later than the code before it did (Step ran the whole Ready under the group lock
// and returned after the acknowledgement had left) are waited for explicitly:
//   - a new leader's first entry of its term is in Raft's log at once but in the group's journal (Status.LastIndex) only
//     after the Ready that persists it, so a settle that read LastIndex at that moment settled on the entry before it and
//     the partition that followed left a voter without the term's first entry (a read index is answered only once the
//     leader committed an entry of its term, which is after that entry is persisted);
//   - a follower's acknowledgement leaves with the Ready that persisted the entry, after its commit index is visible,
//     and the mesh delivers it after that: a cut that follows too early drops the one answer that tells the leader the
//     entry is on that voter, which then sends a snapshot of what the voter holds once its journal is compacted.
func (v *voters) settleSlot(t *testing.T, slot int, leader uint64, deadline time.Time) {
	t.Helper()
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	for {
		settled := true
		if _, err := v.groups[leader][slot].ReadIndex(ctx); err != nil {
			settled = false
		} else {
			last := v.groups[leader][slot].Status().LastIndex
			for node := range v.groups {
				v.mesh.mu.Lock()
				down := v.mesh.blocked[node]
				v.mesh.mu.Unlock()
				if down {
					continue
				}
				status := v.groups[node][slot].Status()
				if status.Applied < last || !v.mesh.settled(node, status.Group) {
					settled = false
				}
			}
		}
		if settled {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("slot %d: the voters never applied the last entry of its leader and answered it", slot)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// leadSlot waits until node want leads the data group of slot, campaigning when the group has no
// leader and asking the current leader to hand over otherwise.
func (v *voters) leadSlot(t *testing.T, slot int, want uint64, deadline time.Time) {
	t.Helper()
	for {
		if time.Now().After(deadline) {
			t.Fatalf("slot %d never moved to node %d", slot, want)
		}
		leader := v.groups[want][slot].Status().Leader
		if leader == want {
			return
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
			t.Fatalf("voters never converged on the same applied prefix:\n%s", v.divergence(want))
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// divergence describes every slot whose applied index differs between the voters, or is below want, with each
// voter's view of the group, for the failure of converge.
func (v *voters) divergence(want map[uint16]uint64) string {
	var out strings.Builder
	indexes := map[uint64][64]uint64{}
	for node := uint64(1); node <= 3; node++ {
		e := v.engines[node]
		e.mu.Lock()
		indexes[node] = e.indexes
		e.mu.Unlock()
	}
	for slot := range 64 {
		if indexes[1][slot] == indexes[2][slot] && indexes[1][slot] == indexes[3][slot] && indexes[1][slot] >= want[uint16(slot)] {
			continue
		}
		fmt.Fprintf(&out, "slot %d (want %d):", slot, want[uint16(slot)])
		for node := uint64(1); node <= 3; node++ {
			s := v.groups[node][slot].Status()
			fmt.Fprintf(&out, " node%d{applied-index %d leader %d term %d commit %d applied %d last %d}", node, indexes[node][slot], s.Leader, s.Term, s.Commit, s.Applied, s.LastIndex)
		}
		out.WriteString("\n")
	}
	v.mesh.mu.Lock()
	fmt.Fprintf(&out, "snapshots delivered per node: %v", v.mesh.snaps)
	v.mesh.mu.Unlock()
	return out.String()
}

// slotView describes slot as each voter's group sees it: leader, term, commit, applied and last index.
func (v *voters) slotView(slot int) string {
	var out strings.Builder
	fmt.Fprintf(&out, "slot %d:", slot)
	for node := uint64(1); node <= 3; node++ {
		s := v.groups[node][slot].Status()
		fmt.Fprintf(&out, " node%d{leader %d term %d commit %d applied %d last %d}", node, s.Leader, s.Term, s.Commit, s.Applied, s.LastIndex)
	}
	return out.String()
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
