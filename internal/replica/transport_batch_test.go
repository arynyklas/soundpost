// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime/metrics"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	pb "go.etcd.io/raft/v3/raftpb"
	"google.golang.org/protobuf/proto"
)

// goroutinesCreated is how many goroutines the process has ever started. The race detector keeps
// ~360 bytes for every one of them for good, so it is what bounds the memory of a long race run.
func goroutinesCreated(t *testing.T) uint64 {
	t.Helper()
	sample := []metrics.Sample{{Name: "/sched/goroutines-created:goroutines"}}
	metrics.Read(sample)
	if sample[0].Value.Kind() != metrics.KindUint64 {
		t.Fatal("the runtime does not report /sched/goroutines-created")
	}
	return sample[0].Value.Uint64()
}

// An idle installation heartbeats every follower of every group on every tick and every follower
// answers: one HTTP/2 request each, ~4 goroutines each. 65 groups of a three-voter installation made
// ~11 000 requests and ~44 000 goroutines a second and nothing else, saturated two CPUs under the race
// detector and grew its memory by ~130 MB a minute until the test binary was killed (exit 137,
// TestDistributedPersistedPathAnswersAreIdenticalAtEveryStage). The heartbeats of all groups between
// a node pair share one request, so the request rate of an idle installation no longer grows with
// its group count.
func TestIdleHeartbeatsOfManyGroupsShareFewRequests(t *testing.T) {
	const groups = 24
	c := newMTLSCluster(t, groups)
	for group := range groups {
		if err := c.groups[0][group].Campaign(); err != nil {
			t.Fatal(err)
		}
	}
	ready, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for group := range groups {
		for {
			if _, err := c.groups[0][group].ReadIndex(ready); err == nil {
				break
			} else if ready.Err() != nil {
				t.Fatalf("group %d never elected a leader on node 1: %v", group, err)
			}
		}
	}
	time.Sleep(500 * time.Millisecond) // the elections' own traffic is over
	requests, created, started := c.requests.Load(), goroutinesCreated(t), time.Now()
	time.Sleep(2 * time.Second)
	elapsed := time.Since(started)
	requests, created = c.requests.Load()-requests, goroutinesCreated(t)-created
	ticks := int64(elapsed / (20 * time.Millisecond))
	t.Logf("idle for %v (%d ticks of %d groups): %d requests (%.1f per tick), %d goroutines created (%.1f per tick)", elapsed.Round(time.Millisecond), ticks, groups, requests, float64(requests)/float64(ticks), created, float64(created)/float64(ticks))
	// One request per group per tick would already be `groups` per tick; heartbeats and their
	// responses to two followers were four times that.
	if requests > ticks*groups {
		t.Fatalf("%d requests in %d ticks of an idle installation with %d groups: heartbeats are not shared between groups", requests, ticks, groups)
	}
	if created > uint64(ticks)*groups*3 {
		t.Fatalf("%d goroutines created in %d ticks of an idle installation with %d groups", created, ticks, groups)
	}
}

// batchPeer is a peer's listener that records what it is sent, per route.
type batchPeer struct {
	mu          sync.Mutex
	batches     [][]batchEntry
	single      []*pb.Message
	paths       []string
	batchStatus int // the answer to the batch route
	gate, first chan struct{}
	once        sync.Once
	freed       sync.Once
}

// release lets the held first batch request finish; it is safe to call more than once.
func (p *batchPeer) release() {
	if p.gate != nil {
		p.freed.Do(func() { close(p.gate) })
	}
}

func (p *batchPeer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	if r.URL.Path == batchPath && p.gate != nil {
		p.once.Do(func() { close(p.first); <-p.gate })
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.paths = append(p.paths, r.URL.Path)
	if r.URL.Path == batchPath {
		if p.batchStatus != 0 && p.batchStatus != http.StatusNoContent {
			http.Error(w, "invalid", p.batchStatus)
			return
		}
		entries, ok := decodeBatch(raw)
		if !ok {
			http.Error(w, "invalid", http.StatusUnprocessableEntity)
			return
		}
		p.batches = append(p.batches, entries)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	m := &pb.Message{}
	if proto.Unmarshal(raw, m) != nil {
		http.Error(w, "invalid", http.StatusBadRequest)
		return
	}
	p.single = append(p.single, m)
	w.WriteHeader(http.StatusNoContent)
}

func (p *batchPeer) snapshot() (batches [][]batchEntry, single []*pb.Message, paths []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([][]batchEntry(nil), p.batches...), append([]*pb.Message(nil), p.single...), append([]string(nil), p.paths...)
}

// batchSender is node 1's transport and one group of it, with node 2 being a batchPeer.
func batchSender(t *testing.T, peer *batchPeer) (*MTLS, *Group) {
	t.Helper()
	roots, certificates := testPKI(t, 3)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: peer, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificates[1]}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots, NextProtos: []string{"h2", "http/1.1"}}}
	go func() { _ = server.Serve(tls.NewListener(listener, server.TLSConfig)) }()
	t.Cleanup(func() { server.Close() })
	members := Members{Revision: 1, Nodes: []Member{
		{ID: 1, Address: "https://127.0.0.1:1", NodeIdentity: "node-1", FailureDomain: "test-disk-1"},
		{ID: 2, Address: "https://" + listener.Addr().String(), NodeIdentity: "node-2", FailureDomain: "test-disk-2"},
		{ID: 3, Address: "https://127.0.0.1:3", NodeIdentity: "node-3", FailureDomain: "test-disk-3"},
	}}
	transport, err := NewMTLS(1, "node-1", certificates[0], roots, "")
	if err != nil {
		t.Fatal(err)
	}
	// A group that is not ticked: the only messages are the ones the test sends.
	group, err := Open(Config{ID: 1, Group: model.NewID(), Directory: t.TempDir(), Members: members, Machine: newGateMachine(), Transport: transport})
	if err != nil {
		t.Fatal(err)
	}
	if err = transport.Register(group); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { transport.Close(); group.Close() })
	return transport, group
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("%s did not happen within 5s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// A storage read fences every group of the node with a read-index round. Each round is a heartbeat to both
// followers carrying the round's position and a response from each: 4 peer requests, 256 for the 64 groups
// of a fence, ~75 % of the peer requests of the distributed smoke campaign (~1 900 rounds a second). The
// rounds of groups that wait together share their requests.
func TestReadIndexRoundsOfManyGroupsStartedTogetherShareRequests(t *testing.T) {
	const groups = 24
	c := newMTLSCluster(t, groups)
	for group := range groups {
		if err := c.groups[0][group].Campaign(); err != nil {
			t.Fatal(err)
		}
	}
	ready, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for group := range groups {
		for {
			if _, err := c.groups[0][group].ReadIndex(ready); err == nil {
				break
			} else if ready.Err() != nil {
				t.Fatalf("group %d never elected a leader on node 1: %v", group, err)
			}
		}
	}
	time.Sleep(300 * time.Millisecond)
	var worst int64
	for range 5 {
		before := c.requests.Load()
		var wg sync.WaitGroup
		for group := range groups {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := c.groups[0][group].ReadIndex(ready); err != nil {
					t.Errorf("group %d: %v", group, err)
				}
			}()
		}
		wg.Wait()
		worst = max(worst, c.requests.Load()-before)
		time.Sleep(100 * time.Millisecond)
	}
	t.Logf("a fence of %d groups: at most %d peer requests (one request per heartbeat and response is %d)", groups, worst, groups*4)
	if worst > groups*2 {
		t.Fatalf("a fence of %d groups made %d peer requests: the rounds do not share requests", groups, worst)
	}
}

// A heartbeat is superseded by the next one: a batch keeps only the newest heartbeat and the newest
// heartbeat response of a group, however many were produced while it waited for its window.
func TestBatchKeepsTheNewestHeartbeatAndResponseOfAGroup(t *testing.T) {
	peer := &batchPeer{}
	transport, group := batchSender(t, peer)
	for i := 1; i <= 50; i++ {
		for _, kind := range []pb.MessageType{pb.MsgHeartbeat, pb.MsgHeartbeatResp} {
			m := laneMessage(kind, "")
			m.Commit = proto.Uint64(uint64(i))
			if err := transport.Send(group.group, m); err != nil {
				t.Fatalf("Send %v: %v", kind, err)
			}
		}
	}
	waitFor(t, "the batch", func() bool {
		batches, _, _ := peer.snapshot()
		newest := map[pb.MessageType]uint64{}
		for _, b := range batches {
			for _, e := range b {
				newest[e.message.GetType()] = e.message.GetCommit()
			}
		}
		return newest[pb.MsgHeartbeat] == 50 && newest[pb.MsgHeartbeatResp] == 50
	})
	batches, single, _ := peer.snapshot()
	delivered := 0
	for _, b := range batches {
		for _, e := range b {
			if e.group != group.group {
				t.Fatalf("a message of group %v in the batch of group %v", e.group, group.group)
			}
			delivered++
		}
	}
	if len(single) != 0 {
		t.Fatalf("%d heartbeats were delivered on their own request", len(single))
	}
	if delivered > 6 { // two kinds, a window or two of slack on a starved host; unbatched it was 100
		t.Fatalf("%d messages of 100 produced for one group reached the peer: stale heartbeats are not superseded", delivered)
	}
}

// A message that carries a read-index position is the one thing a read waits for: it must not wait for the
// batch window, and it takes every message that is waiting with it.
func TestReadIndexHeartbeatDoesNotWaitForTheBatchWindow(t *testing.T) {
	old := batchWindow
	batchWindow = time.Minute
	t.Cleanup(func() { batchWindow = old })
	peer := &batchPeer{}
	transport, group := batchSender(t, peer)
	if err := transport.Send(group.group, laneMessage(pb.MsgHeartbeatResp, "")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	if batches, single, _ := peer.snapshot(); len(batches)+len(single) != 0 {
		t.Fatalf("a plain response was delivered before its window ended: %d batches, %d single", len(batches), len(single))
	}
	if err := transport.Send(group.group, laneMessage(pb.MsgHeartbeat, "read-index-position")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the batch", func() bool { batches, _, _ := peer.snapshot(); return len(batches) == 1 })
	batches, single, _ := peer.snapshot()
	if len(single) != 0 || len(batches[0]) != 2 {
		t.Fatalf("%d single requests, batch %v: the read-index heartbeat must flush the batch with the waiting response", len(single), batches)
	}
}

// While one request is in flight to a peer, every message that arrives for it (the rounds of other reads, the
// repeats raft makes every tick of a pending round) waits for the next one, and only the newest of each slot
// is in it: a slow peer is sent fewer requests, not more.
func TestHeartbeatsArrivingWhileARequestIsInFlightShareTheNextOne(t *testing.T) {
	peer := &batchPeer{gate: make(chan struct{}), first: make(chan struct{})}
	transport, group := batchSender(t, peer)
	t.Cleanup(peer.release)
	if err := transport.Send(group.group, laneMessage(pb.MsgHeartbeat, "position-1")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-peer.first:
	case <-time.After(5 * time.Second):
		t.Fatal("the first request never reached the peer")
	}
	for i := 2; i <= 60; i++ {
		if err := transport.Send(group.group, laneMessage(pb.MsgHeartbeat, fmt.Sprint("position-", i))); err != nil {
			t.Fatal(err)
		}
	}
	peer.release()
	waitFor(t, "the second request", func() bool { batches, _, _ := peer.snapshot(); return len(batches) == 2 })
	time.Sleep(3 * batchWindow)
	batches, single, _ := peer.snapshot()
	if len(single) != 0 || len(batches) != 2 || len(batches[1]) != 1 || string(batches[1][0].message.GetContext()) != "position-60" {
		t.Fatalf("%d single requests, %d batches: the 59 heartbeats that arrived in flight must be one request carrying the newest", len(single), len(batches))
	}
}

// A member that runs a release without the batch route answers 400 for it (the route parses as an
// unparsable group id there): its heartbeats are delivered one request each from then on, none lost.
func TestBatchFallsBackToPerGroupRequestsForAPeerWithoutTheRoute(t *testing.T) {
	peer := &batchPeer{batchStatus: http.StatusBadRequest}
	transport, group := batchSender(t, peer)
	first := laneMessage(pb.MsgHeartbeat, "")
	first.Commit = proto.Uint64(1)
	if err := transport.Send(group.group, first); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the fallback delivery", func() bool { _, single, _ := peer.snapshot(); return len(single) == 1 })
	_, single, _ := peer.snapshot()
	if single[0].GetCommit() != 1 {
		t.Fatalf("the heartbeat that met the 400 was not delivered one request each: %v", single[0])
	}
	second := laneMessage(pb.MsgHeartbeat, "")
	second.Commit = proto.Uint64(2)
	if err := transport.Send(group.group, second); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the next delivery", func() bool { _, single, _ := peer.snapshot(); return len(single) == 2 })
	time.Sleep(3 * batchWindow)
	_, _, paths := peer.snapshot()
	batchRequests := 0
	for _, p := range paths {
		if p == batchPath {
			batchRequests++
		}
	}
	if batchRequests != 1 {
		t.Fatalf("%d requests on the batch route of a peer that answered 400 once (want 1): %v", batchRequests, paths)
	}
}

func TestBatchFramesRoundTripAndRefuseEveryMalformedBody(t *testing.T) {
	a, b := model.NewID(), model.NewID()
	var body []byte
	for _, e := range []batchEntry{{a, laneMessage(pb.MsgHeartbeat, "")}, {b, laneMessage(pb.MsgHeartbeatResp, "c")}} {
		raw, err := proto.Marshal(e.message)
		if err != nil {
			t.Fatal(err)
		}
		body = appendBatchFrame(body, e.group, raw)
	}
	entries, ok := decodeBatch(body)
	if !ok || len(entries) != 2 || entries[0].group != a || entries[1].group != b || entries[1].message.GetType() != pb.MsgHeartbeatResp || string(entries[1].message.GetContext()) != "c" {
		t.Fatalf("round trip: %v %v", entries, ok)
	}
	for name, bad := range map[string][]byte{
		"empty":            nil,
		"short group":      body[:10],
		"cut message":      body[:len(body)-1],
		"zero length":      append(append([]byte(nil), a[:]...), 0),
		"oversize message": append(append([]byte(nil), a[:]...), 0xff, 0xff, 0xff, 0x7f),
		"garbage message":  append(append(append([]byte(nil), a[:]...), 3), 0xff, 0xff, 0xff),
		"trailing byte":    append(append([]byte(nil), body...), 1),
	} {
		if entries, ok := decodeBatch(bad); ok {
			t.Errorf("%s: accepted as %d entries", name, len(entries))
		}
	}
}

// batchRequest is a POST of body to the batch route as the member holding certificate would send it.
func batchRequest(t *testing.T, certificate tls.Certificate, body []byte) *http.Request {
	t.Helper()
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", batchPath, bytes.NewReader(body))
	r.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{leaf}}, PeerCertificates: []*x509.Certificate{leaf}}
	return r
}

func batchBody(t *testing.T, entries ...batchEntry) []byte {
	t.Helper()
	var body []byte
	for _, e := range entries {
		raw, err := proto.Marshal(e.message)
		if err != nil {
			t.Fatal(err)
		}
		body = appendBatchFrame(body, e.group, raw)
	}
	return body
}

// heartbeatFrom is a heartbeat of member `from` to node 2.
func heartbeatFrom(from uint64, kind pb.MessageType) *pb.Message {
	return &pb.Message{Type: kind.Enum(), From: proto.Uint64(from), To: proto.Uint64(2)}
}

// The batch route admits what the per-group route admits: heartbeats and their responses of a member
// of the group, from the member whose credential carried them, and nothing else.
func TestBatchRouteAdmitsOnlyHeartbeatsOfAMemberOfTheGroup(t *testing.T) {
	c := newMTLSCluster(t, 1)
	group := c.groups[1][0].group
	serve := func(certificate tls.Certificate, entries ...batchEntry) int {
		w := httptest.NewRecorder()
		c.transports[1].ServeHTTP(w, batchRequest(t, certificate, batchBody(t, entries...)))
		return w.Code
	}
	if code := serve(c.certs[0], batchEntry{group, heartbeatFrom(1, pb.MsgHeartbeat)}); code != http.StatusNoContent {
		t.Fatalf("a heartbeat of member 1 carried by member 1's credential: %d", code)
	}
	if code := serve(c.certs[2], batchEntry{group, heartbeatFrom(1, pb.MsgHeartbeat)}); code != http.StatusForbidden {
		t.Fatalf("a heartbeat claiming member 1, carried by member 3's credential: %d", code)
	}
	if code := serve(c.outsider, batchEntry{group, heartbeatFrom(1, pb.MsgHeartbeat)}); code != http.StatusForbidden {
		t.Fatalf("a heartbeat carried by the credential of a node that is not a member: %d", code)
	}
	if code := serve(c.certs[0], batchEntry{group, heartbeatFrom(1, pb.MsgApp)}); code != http.StatusForbidden {
		t.Fatalf("an append inside a batch: %d", code)
	}
	// One admissible message is enough for the body to be taken; the rest are dropped.
	if code := serve(c.certs[0], batchEntry{group, heartbeatFrom(1, pb.MsgApp)}, batchEntry{group, heartbeatFrom(1, pb.MsgHeartbeatResp)}); code != http.StatusNoContent {
		t.Fatalf("a batch with one admissible message: %d", code)
	}
	if code := serve(c.certs[0], batchEntry{model.NewID(), heartbeatFrom(1, pb.MsgHeartbeat)}); code != http.StatusNoContent {
		t.Fatalf("a heartbeat of a group this node has not opened must be dropped, not refused: %d", code)
	}
	w := httptest.NewRecorder()
	c.transports[1].ServeHTTP(w, batchRequest(t, c.certs[0], []byte("not a batch")))
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("a body that is not a batch: %d", w.Code)
	}
	plain := httptest.NewRequest("POST", batchPath, strings.NewReader(""))
	w = httptest.NewRecorder()
	c.transports[1].ServeHTTP(w, plain)
	if w.Code != http.StatusForbidden {
		t.Fatalf("a request without a verified peer credential: %d", w.Code)
	}
}

// A group whose lock is held (an applier parked on a slow disk, on a lock of an unrelated operation)
// must delay the heartbeats of that group only: the batch that carries them returns at once and the
// other groups' heartbeats in it are stepped.
func TestBatchedHeartbeatOfAParkedGroupDoesNotHoldBackTheBatch(t *testing.T) {
	c := newMTLSCluster(t, 2)
	parked, free := 0, 1
	for group := range 2 {
		if err := c.groups[0][group].Campaign(); err != nil {
			t.Fatal(err)
		}
	}
	ready, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for group := range 2 {
		for {
			if _, err := c.groups[0][group].ReadIndex(ready); err == nil {
				break
			} else if ready.Err() != nil {
				t.Fatalf("group %d never elected a leader on node 1: %v", group, err)
			}
		}
	}
	c.machines[1][parked].arm()
	propose, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	if _, err := c.groups[0][parked].Propose(propose, Entry{ID: model.NewID(), Kind: Data, Payload: []byte("parked")}); err != nil {
		t.Fatalf("leader commit of the parked group's entry: %v", err)
	}
	select {
	case <-c.machines[1][parked].entered:
	case <-time.After(5 * time.Second):
		t.Fatal("node 2 never parked its applier")
	}
	body := batchBody(t,
		batchEntry{c.groups[1][parked].group, heartbeatFrom(1, pb.MsgHeartbeat)},
		batchEntry{c.groups[1][free].group, heartbeatFrom(1, pb.MsgHeartbeat)})
	done := make(chan int, 1)
	go func() {
		w := httptest.NewRecorder()
		c.transports[1].ServeHTTP(w, batchRequest(t, c.certs[0], body))
		done <- w.Code
	}()
	select {
	case code := <-done:
		if code != http.StatusNoContent {
			t.Fatalf("the batch was answered %d", code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a batch with a heartbeat for a parked group waited for the group's lock")
	}
}
