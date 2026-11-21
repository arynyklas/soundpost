// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	pb "go.etcd.io/raft/v3/raftpb"

	"github.com/arynyklas/soundpost/internal/model"
)

// gatedMachine is a ledgerMachine that implements SnapshotGate and records what the group asked of it.
type gatedMachine struct {
	*ledgerMachine
	mu       sync.Mutex
	token    []byte
	admitted [][]byte
	released int
	admitErr error
}

func (m *gatedMachine) BeforeSnapshotSend(context.Context, uint64) ([]byte, error) {
	return m.token, nil
}
func (m *gatedMachine) AdmitSnapshot(token []byte) (func(), error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.admitErr != nil {
		return nil, m.admitErr
	}
	m.admitted = append(m.admitted, append([]byte{}, token...))
	return func() { m.mu.Lock(); m.released++; m.mu.Unlock() }, nil
}
func (m *gatedMachine) counts() (admits, releases int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.admitted), m.released
}

// capture records what a group hands its transport.
type captureTransport struct {
	*Loopback
	mu   sync.Mutex
	sent []*pb.Message
}

func (c *captureTransport) Send(g model.ID, m *pb.Message) error {
	c.mu.Lock()
	c.sent = append(c.sent, m)
	c.mu.Unlock()
	return nil
}

func openGated(t *testing.T, token []byte) (*Group, *gatedMachine, *captureTransport) {
	t.Helper()
	id, dir := model.NewID(), t.TempDir()
	inner := newLedgerMachine(id, filepath.Join(dir, "machine"))
	if err := os.MkdirAll(inner.dir, 0700); err != nil {
		t.Fatal(err)
	}
	machine := &gatedMachine{ledgerMachine: inner, token: token}
	transport := &captureTransport{Loopback: NewLoopback()}
	group, err := Open(Config{ID: 1, Group: id, Directory: filepath.Join(dir, "raft"), Transport: transport, Members: soloMembers(), Machine: machine})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { group.Close(); transport.Loopback.Close() })
	return group, machine, transport
}

func snapMessage(to uint64, context []byte) *pb.Message {
	return &pb.Message{Type: pb.MsgSnap.Enum(), To: new(to), From: new(uint64(2)), Context: context}
}

// A receiver that runs the gate refuses a snapshot whose sender does not advertise it: nothing was
// ordered before the install (11.04-W3). A sender that advertises it, with or without a token, is
// admitted and its token reaches the machine unframed.
func TestSnapshotFromASenderWithoutTheGateIsRefused(t *testing.T) {
	group, machine, _ := openGated(t, nil)
	for _, cx := range [][]byte{nil, {}, []byte("plain"), gateAdvert[:len(gateAdvert)-1]} {
		err := group.Step(t.Context(), snapMessage(1, cx))
		if !errors.Is(err, ErrUnavailable) {
			t.Fatalf("snapshot with context %q: got %v, want %v", cx, err, ErrUnavailable)
		}
	}
	if admits, _ := machine.counts(); admits != 0 {
		t.Fatalf("the gate was asked to admit %d snapshots from a sender without the gate", admits)
	}
	for _, token := range [][]byte{nil, {1, 2, 3, 4, 5, 6, 7, 8}} {
		// The message is stale for the group, so Step may answer with raft's own verdict; what
		// matters here is that the gate was consulted with the unframed token and released.
		_ = group.Step(t.Context(), snapMessage(1, gateContext(token)))
	}
	admits, releases := machine.counts()
	if admits != 2 || releases != 2 {
		t.Fatalf("advertising senders: %d admitted, %d released, want 2 and 2", admits, releases)
	}
	if len(machine.admitted[0]) != 0 || string(machine.admitted[1]) != string([]byte{1, 2, 3, 4, 5, 6, 7, 8}) {
		t.Fatalf("tokens reached the machine framed or altered: %v", machine.admitted)
	}
}

// A snapshot the sender's gate released leaves with the advertisement in front of the token.
func TestGatedSnapshotCarriesTheAdvertisementAndTheToken(t *testing.T) {
	for _, token := range [][]byte{nil, {9, 9, 9, 9, 9, 9, 9, 9}} {
		group, _, transport := openGated(t, token)
		group.mu.Lock()
		group.sendGatedSnapshot(&pb.Message{Type: pb.MsgSnap.Enum(), To: new(uint64(2)), From: new(uint64(1))})
		group.mu.Unlock()
		group.gateWG.Wait()
		transport.mu.Lock()
		var snaps []*pb.Message
		for _, m := range transport.sent {
			if m.GetType() == pb.MsgSnap {
				snaps = append(snaps, m)
			}
		}
		transport.mu.Unlock()
		if len(snaps) != 1 {
			t.Fatalf("token %v: %d snapshot messages sent, want 1", token, len(snaps))
		}
		got, ok := gateToken(snaps[0].GetContext())
		if !ok || string(got) != string(token) {
			t.Fatalf("token %v: context %q does not carry the advertisement and the token (got %v, ok=%v)", token, snaps[0].GetContext(), got, ok)
		}
	}
}
