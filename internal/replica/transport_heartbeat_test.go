// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	pb "go.etcd.io/raft/v3/raftpb"
	"google.golang.org/protobuf/proto"
)

// slowPeer is a voter's peer listener whose first request is held until release: a receiver
// that is starved of CPU, or a slow disk, as seen by the sender's delivery lane.
type slowPeer struct {
	mu       sync.Mutex
	received []*pb.Message
	first    chan struct{}
	gate     chan struct{}
	once     sync.Once
	free     sync.Once
}

func (p *slowPeer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	m := &pb.Message{}
	if proto.Unmarshal(raw, m) != nil {
		http.Error(w, "invalid", http.StatusBadRequest)
		return
	}
	hold := false
	p.once.Do(func() { hold = true; close(p.first) })
	if hold {
		<-p.gate
	}
	p.mu.Lock()
	p.received = append(p.received, m)
	p.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (p *slowPeer) delivered() []*pb.Message {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]*pb.Message(nil), p.received...)
}

// A delivery lane that waits on a slow receiver must not accumulate a standing queue of heartbeats:
// a heartbeat is superseded by the next one, so a lane keeps only the newest of each kind. Every
// stale heartbeat in the queue is an HTTP request that delays the read-index, vote and append
// messages of the same group behind it; on a CPU-starved two-vCPU host this made one read-index
// round take seconds and a read fail with 504 (TestDistributedClusterScenarioHoldsAcrossNodesAndNodeLoss).
func TestLaneKeepsOnlyTheNewestHeartbeatBehindASlowReceiver(t *testing.T) {
	for _, kind := range []pb.MessageType{pb.MsgHeartbeat, pb.MsgHeartbeatResp} {
		t.Run(kind.String(), func(t *testing.T) {
			roots, certificates := testPKI(t, 3)
			peer := &slowPeer{first: make(chan struct{}), gate: make(chan struct{})}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			server := &http.Server{Handler: peer, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificates[1]}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots, NextProtos: []string{"h2", "http/1.1"}}}
			go func() { _ = server.Serve(tls.NewListener(listener, server.TLSConfig)) }()
			t.Cleanup(func() { peer.release(); server.Close() })

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
			send := func(m *pb.Message) {
				t.Helper()
				if err := transport.Send(group.group, m); err != nil {
					t.Fatalf("Send %v: %v", m.GetType(), err)
				}
			}

			// One append is in flight at the slow receiver.
			send(laneMessage(pb.MsgApp, ""))
			select {
			case <-peer.first:
			case <-time.After(5 * time.Second):
				t.Fatal("the first message never reached the receiver")
			}
			const stale = 100
			for i := 1; i <= stale; i++ {
				send(laneMessage(kind, fmt.Sprint(i)))
			}
			send(laneMessage(pb.MsgReadIndex, "read"))
			// The receiver recovers: the read-index message must arrive after at most one heartbeat.
			peer.release()
			deadline := time.Now().Add(5 * time.Second)
			var got []*pb.Message
			for time.Now().Before(deadline) {
				got = peer.delivered()
				if len(got) > 0 && got[len(got)-1].GetType() == pb.MsgReadIndex {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if len(got) == 0 || got[len(got)-1].GetType() != pb.MsgReadIndex {
				t.Fatalf("the read-index message was not delivered within 5s of the receiver recovering; delivered %d messages", len(got))
			}
			var heartbeats []*pb.Message
			for _, m := range got {
				if m.GetType() == kind {
					heartbeats = append(heartbeats, m)
				}
			}
			if len(heartbeats) != 1 || string(heartbeats[0].GetContext()) != fmt.Sprint(stale) {
				t.Fatalf("%d stale %v messages were delivered ahead of the read-index message (want exactly the newest, context %d)", len(heartbeats), kind, stale)
			}
			if got[0].GetType() != pb.MsgApp {
				t.Fatalf("the in-flight append is not first: %v", got[0].GetType())
			}
		})
	}
}

// laneMessage is a message from node 1 to node 2.
func laneMessage(kind pb.MessageType, context string) *pb.Message {
	return &pb.Message{Type: kind.Enum(), From: proto.Uint64(1), To: proto.Uint64(2), Context: []byte(context)}
}

// release lets the parked first request finish; it is safe to call more than once.
func (p *slowPeer) release() { p.free.Do(func() { close(p.gate) }) }
