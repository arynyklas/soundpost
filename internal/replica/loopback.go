// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"context"
	"github.com/arynyklas/soundpost/internal/model"
	pb "go.etcd.io/raft/v3/raftpb"
	"sync"
)

// Loopback drives the same Ready/Step path for a one-voter installation. It
// cannot acknowledge any other voter or pretend to provide a quorum copy.
type Loopback struct {
	mu     sync.RWMutex
	groups map[model.ID]*Group
	queue  chan outbound
	stop   chan struct{}
	done   chan struct{}
	once   sync.Once
}

func NewLoopback() *Loopback {
	t := &Loopback{groups: map[model.ID]*Group{}, queue: make(chan outbound, 128), stop: make(chan struct{}), done: make(chan struct{})}
	go t.run()
	return t
}
func (t *Loopback) Register(g *Group) error {
	if g == nil {
		return ErrInvalid
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.groups[g.group] != nil {
		return ErrConflict
	}
	t.groups[g.group] = g
	return nil
}
func (t *Loopback) Send(group model.ID, message *pb.Message) error {
	t.mu.RLock()
	g := t.groups[group]
	t.mu.RUnlock()
	if g == nil || message.GetTo() != g.id || message.GetFrom() != g.id {
		return ErrInvalid
	}
	select {
	case <-t.stop:
		return ErrUnavailable
	case t.queue <- outbound{group: group, message: message}:
		return nil
	default:
		return ErrUnavailable
	}
}
func (t *Loopback) run() {
	defer close(t.done)
	for {
		select {
		case <-t.stop:
			return
		case message := <-t.queue:
			t.mu.RLock()
			g := t.groups[message.group]
			t.mu.RUnlock()
			if g != nil {
				err := g.Step(context.Background(), message.message)
				g.ReportDelivery(message.message.GetTo(), message.message.GetType() == pb.MsgSnap, err)
			}
		}
	}
}
func (t *Loopback) Close() error { t.once.Do(func() { close(t.stop) }); <-t.done; return nil }
