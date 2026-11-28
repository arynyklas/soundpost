// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// The coalesced heartbeats travel on a connection of their own: no connection carries both a batch and a request of a group's raft
// route, so that a heartbeat is never in the socket buffer or the flow-control window of the appends it would wait behind.
func TestHeartbeatBatchesTravelOnAConnectionOfTheirOwn(t *testing.T) {
	c := newMTLSCluster(t, 1)
	leadOnNode1(t, c)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for i := range 20 {
		if _, err := c.groups[0][0].Propose(ctx, Entry{ID: model.NewID(), Kind: Data, Payload: []byte{byte(i)}}); err != nil {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	batches, raft := 0, 0
	c.connKinds.Range(func(address, kinds any) bool {
		var batch, bulk bool
		kinds.(*sync.Map).Range(func(kind, _ any) bool {
			batch = batch || kind == "batch"
			bulk = bulk || kind == "raft"
			return true
		})
		switch {
		case batch && bulk:
			t.Errorf("connection %v carried heartbeat batches and requests of the raft route", address)
		case batch:
			batches++
		case bulk:
			raft++
		}
		return true
	})
	if batches == 0 || raft == 0 {
		t.Fatalf("%d connections carried only batches and %d only raft requests: both kinds of traffic were expected", batches, raft)
	}
}
