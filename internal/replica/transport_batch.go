// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	pb "go.etcd.io/raft/v3/raftpb"
	"google.golang.org/protobuf/proto"
)

// Coalesced heartbeats.
//
// Every group heartbeats every follower on every tick and every follower answers, and each message
// used to be one HTTP/2 request. An installation has 65 groups per node (one control group, 64
// storage slots): an idle three-voter installation on a 20 ms tick made ~11 000 requests a second,
// ~99 % of all the requests of the distributed smoke campaign, and ~4 goroutines per request. That
// saturated a two-CPU host under the race detector (the persisted-path campaign ran for an hour) and
// the race detector never frees ~360 bytes per goroutine ever created: ~130 MB a minute until the
// kernel killed the test binary.
//
// Every heartbeat and heartbeat response is therefore not delivered on its own request: the peer's
// batcher keeps the newest one per (group, kind) and, one batchWindow after the first arrives, sends
// every group's in one request to the peer's batch route. That is the whole idle traffic of a node
// pair: ~2 requests a window per direction instead of one per group per tick. A message that carries
// the position of a read-index round (the heartbeat that asks, the response that confirms: a read
// waits for exactly that round trip, 64 times per query) does not wait for the window: it flushes the
// batch at once, and the one request in flight per peer is what batches the rest: while it is in
// flight, everything that arrives (the rounds of other groups, the repeats raft makes every tick of a
// pending round, which a slow round made ~80 % of the campaign's traffic) goes out together in the
// next one. An unloaded node sends a read's heartbeat at once; a loaded one sends fewer, larger requests.
//
// What a batch does not do, by design:
//   - It never reports delivery. A lost heartbeat is replaced by the next tick's, and a peer that is
//     down is reported unreachable by the append lanes that need it; a report takes the group lock,
//     and the one worker that serves every group of the peer must not wait for a parked group.
//   - It never waits for a group. The receiver steps a group whose lock is free at once and hands a
//     message for a busy group to one goroutine per (group, kind) that waits for the lock and then
//     steps the newest message, so one parked applier delays its own group's heartbeats and nobody
//     else's (TestParkedGroupHandlerDoesNotStarveOtherGroupsToTheSamePeer).
//   - It is not required of the peer. A member that runs a release without the batch route answers
//     400 (the route parses as an unparsable group id); the sender then delivers that peer's
//     heartbeats one request each for batchLegacyRetry, as that release does.
const (
	batchPath            = raftPath + "batch"
	batchMaxMessages     = 4096
	batchMaxMessageBytes = 64 << 10
	batchMaxBytes        = 8 << 20
	batchLegacyRetry     = 30 * time.Second
)

// batchWindow is how long the first message of a batch waits for the others (a variable for the tests).
var batchWindow = 10 * time.Millisecond

// batchKey names one slot of a peer's batch: the newest heartbeat (kind 1) or heartbeat response (kind 2) of a group.
type batchKey struct {
	group model.ID
	kind  int
}

type batchEntry struct {
	group   model.ID
	message *pb.Message
}

// peerBatcher is the batch of one peer: its slots, the worker's wake-up and the peer's address as the
// groups last resolved it.
type peerBatcher struct {
	peer        uint64
	wake        chan struct{}
	hurry       chan struct{} // a message that carries a read-index position is waiting: flush now
	mu          sync.Mutex
	slots       map[batchKey]*pb.Message
	target      Member
	legacyUntil time.Time
}

// offer keeps m as the newest message of its slot and wakes the worker; a message that carries a read-index
// position hurries it (no window to wait for). It is false when the peer does not take batches right now:
// the caller delivers m on its lane. A plain message never replaces a slot's message that carries a position
// (the position's acknowledgement is what a read waits for).
func (b *peerBatcher) offer(group model.ID, kind int, m *pb.Message) bool {
	urgent := len(m.GetContext()) > 0
	b.mu.Lock()
	if time.Now().Before(b.legacyUntil) {
		b.mu.Unlock()
		return false
	}
	key := batchKey{group: group, kind: kind}
	if old := b.slots[key]; urgent || old == nil || len(old.GetContext()) == 0 {
		b.slots[key] = m
	}
	b.mu.Unlock()
	select {
	case b.wake <- struct{}{}:
	default:
	}
	if urgent {
		select {
		case b.hurry <- struct{}{}:
		default:
		}
	}
	return true
}

// batcher is the batch of a peer, started on first use; nil once the transport is closing.
func (t *MTLS) batcher(peer uint64) *peerBatcher {
	t.mu.RLock()
	b := t.batchers[peer]
	t.mu.RUnlock()
	if b != nil {
		return b
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closing {
		return nil
	}
	if b = t.batchers[peer]; b == nil {
		b = &peerBatcher{peer: peer, wake: make(chan struct{}, 1), hurry: make(chan struct{}, 1), slots: map[batchKey]*pb.Message{}}
		t.batchers[peer] = b
		t.workers.Add(1)
		go t.batchLoop(b)
	}
	return b
}

func (t *MTLS) batchLoop(b *peerBatcher) {
	defer t.workers.Done()
	window := time.NewTimer(batchWindow)
	window.Stop()
	for {
		select {
		case <-t.stop:
			return
		case <-b.wake:
		}
		window.Reset(batchWindow)
		select {
		case <-t.stop:
			window.Stop()
			return
		case <-b.hurry:
			window.Stop()
		case <-window.C:
		}
		t.flushBatch(b)
	}
}

// flushBatch sends everything the peer's slots hold, in as many requests as the frame limits need.
func (t *MTLS) flushBatch(b *peerBatcher) {
	select { // whatever hurried this flush is in it
	case <-b.hurry:
	default:
	}
	b.mu.Lock()
	taken := b.slots
	b.slots = make(map[batchKey]*pb.Message, len(taken))
	b.mu.Unlock()
	if len(taken) == 0 {
		return
	}
	entries := make([]batchEntry, 0, len(taken))
	for key, m := range taken {
		entries = append(entries, batchEntry{group: key.group, message: m})
	}
	target := t.batchTarget(b, entries)
	if target.ID == 0 {
		return // no group could name the peer: the next tick's heartbeats replace these
	}
	for len(entries) > 0 {
		n := min(len(entries), batchMaxMessages)
		t.sendBatch(b, target, entries[:n])
		entries = entries[n:]
	}
}

// batchTarget is the peer's address as the first group whose lock is free names it, else as it was
// last named. A group's lock is only ever tried: a parked group must not hold the batch back.
func (t *MTLS) batchTarget(b *peerBatcher, entries []batchEntry) Member {
	for _, e := range entries {
		t.mu.RLock()
		g := t.groups[e.group]
		t.mu.RUnlock()
		if g == nil || !g.mu.TryLock() {
			continue
		}
		members := g.transportMembersLocked()
		g.mu.Unlock()
		for _, m := range members.Nodes {
			if m.ID == b.peer {
				b.mu.Lock()
				b.target = m
				b.mu.Unlock()
				return m
			}
		}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.target
}

func (t *MTLS) sendBatch(b *peerBatcher, target Member, entries []batchEntry) {
	var body []byte
	for _, e := range entries {
		raw, err := proto.Marshal(e.message)
		if err != nil {
			continue
		}
		body = appendBatchFrame(body, e.group, raw)
	}
	client, err := t.peerClient(target)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, "POST", trimSlash(target.Address)+batchPath, bytes.NewReader(body))
	if err != nil {
		return
	}
	request.Header.Set("Content-Type", "application/octet-stream")
	response, err := client.Do(request)
	if err != nil {
		return
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		return
	}
	// The peer runs a release that knows no batch route: deliver its heartbeats one request each for a while.
	b.mu.Lock()
	b.legacyUntil = time.Now().Add(batchLegacyRetry)
	b.mu.Unlock()
	for _, e := range entries {
		_ = t.Send(e.group, e.message)
	}
}

func trimSlash(address string) string {
	for len(address) > 0 && address[len(address)-1] == '/' {
		address = address[:len(address)-1]
	}
	return address
}

// appendBatchFrame appends one message: the 16 byte group id, the length of the protobuf message as a
// uvarint, the message.
func appendBatchFrame(dst []byte, group model.ID, raw []byte) []byte {
	dst = append(dst, group[:]...)
	dst = binary.AppendUvarint(dst, uint64(len(raw)))
	return append(dst, raw...)
}

// decodeBatch parses a batch body; false for anything but a whole, non-empty, bounded sequence of frames.
func decodeBatch(raw []byte) ([]batchEntry, bool) {
	var out []batchEntry
	for len(raw) > 0 {
		if len(out) >= batchMaxMessages || len(raw) < len(model.ID{})+1 {
			return nil, false
		}
		var group model.ID
		copy(group[:], raw)
		raw = raw[len(group):]
		n, width := binary.Uvarint(raw)
		if width <= 0 || n == 0 || n > batchMaxMessageBytes || uint64(len(raw)-width) < n {
			return nil, false
		}
		m := &pb.Message{}
		if proto.Unmarshal(raw[width:width+int(n)], m) != nil {
			return nil, false
		}
		raw = raw[width+int(n):]
		out = append(out, batchEntry{group: group, message: m})
	}
	return out, len(out) > 0
}

var errNotAMember = errors.New("replica: the sender is not the member its message names")

// senderIs reports whether the member whose credential carries identity is the member from, as the membership the
// transport addresses lists it, without the group lock.
func (g *Group) senderIs(identity string, from uint64) bool {
	view := g.transportView.Load()
	if view == nil {
		return false
	}
	for _, member := range view.Nodes {
		if member.NodeIdentity == identity && member.ID == from {
			return true
		}
	}
	return false
}

// stepFromLocked steps a batched message after proving that the member whose credential carried it is
// the sender it names. g.mu is held.
func (g *Group) stepFromLocked(identity string, m *pb.Message) error {
	var sender uint64
	for _, member := range g.transportMembersLocked().Nodes {
		if member.NodeIdentity == identity {
			sender = member.ID
		}
	}
	if sender == 0 || m.GetFrom() != sender {
		return errNotAMember
	}
	return g.stepLocked(m)
}

// deferKey names the one waiting step of a (group, kind).
type deferKey struct {
	group model.ID
	kind  int
}

type deferredStep struct {
	identity string
	message  *pb.Message
}

// stepLater hands m to the one goroutine that waits for a busy group's lock; a message that arrives
// while it waits replaces the one it holds (a heartbeat is superseded by the next).
func (t *MTLS) stepLater(g *Group, kind int, identity string, m *pb.Message) {
	key := deferKey{group: g.group, kind: kind}
	t.dmu.Lock()
	if d := t.deferred[key]; d != nil {
		d.identity, d.message = identity, m
		t.dmu.Unlock()
		return
	}
	t.deferred[key] = &deferredStep{identity: identity, message: m}
	t.dmu.Unlock()
	go func() {
		g.mu.Lock()
		t.dmu.Lock()
		d := t.deferred[key]
		delete(t.deferred, key)
		t.dmu.Unlock()
		if d != nil {
			_ = g.stepFromLocked(d.identity, d.message)
		}
		g.mu.Unlock()
		_ = g.settle()
	}()
}

// serveBatch receives the batched heartbeats of one peer. It answers 204 once the body is whole,
// whatever became of the individual messages (a message for a group this node has not opened, or for
// a group whose member list does not contain the sender, is dropped: the next tick replaces it), and
// 403 when not one message was admissible; 422 for a body that is not a batch.
func (t *MTLS) serveBatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" || r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	identity := certificateIdentity(r.TLS.PeerCertificates[0])
	if identity == "" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, batchMaxBytes+1))
	if err != nil || len(raw) > batchMaxBytes {
		http.Error(w, "invalid", http.StatusUnprocessableEntity)
		return
	}
	entries, ok := decodeBatch(raw)
	if !ok {
		http.Error(w, "invalid", http.StatusUnprocessableEntity)
		return
	}
	forbidden := 0
	for _, e := range entries {
		kind := supersedableKind(e.message.GetType())
		if kind == 0 || e.message.GetTo() != t.id {
			forbidden++ // only heartbeats and their responses travel in a batch
			continue
		}
		t.mu.RLock()
		g := t.groups[e.group]
		t.mu.RUnlock()
		if g == nil {
			continue
		}
		if !g.senderIs(identity, e.message.GetFrom()) {
			forbidden++ // proven from the published membership: a busy group does not decide what a batch may claim
			continue
		}
		if !g.mu.TryLock() {
			t.stepLater(g, kind, identity, e.message)
			continue
		}
		err := g.stepFromLocked(identity, e.message)
		g.mu.Unlock()
		_ = g.settle()
		if errors.Is(err, errNotAMember) {
			forbidden++
		}
	}
	if forbidden == len(entries) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
