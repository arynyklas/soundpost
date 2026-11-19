// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"context"
	"errors"
	"net"
	"testing"
)

// The layout question tells a member that is not running (nothing to connect to: the learner an operator added
// and has not started yet) from a running binary that does not answer it (the previous release refuses the
// route): only the first is ErrMemberNotRunning, both are ErrUnavailable, and a binary that answers is believed.
func TestQueryLayoutTellsAMemberNothingRunsForFromOneThatDoesNotAnswer(t *testing.T) {
	c := newMTLSCluster(t, 1)
	ctx := context.Background()
	asker, alive := c.transports[0], c.members.Nodes[1]

	// Node 2 is up and, like the previous release, does not implement the question.
	_, err := asker.QueryLayout(ctx, alive)
	if !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrMemberNotRunning) {
		t.Fatalf("a running binary that does not answer: %v, want ErrUnavailable and not ErrMemberNotRunning", err)
	}

	// Node 2 answers: its answer is returned.
	c.transports[1].SetLayoutSupport(func() (uint64, bool) { return 7, true })
	if got, err := asker.QueryLayout(ctx, alive); err != nil || got != 7 {
		t.Fatalf("a running binary that answers: %d, %v", got, err)
	}

	// Nothing listens at the learner's address.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := "https://" + l.Addr().String()
	if err = l.Close(); err != nil {
		t.Fatal(err)
	}
	learner := Member{ID: 4, Address: address, NodeIdentity: "node-4", FailureDomain: "test-disk-4", Learner: true}
	if _, err = asker.QueryLayout(ctx, learner); !errors.Is(err, ErrMemberNotRunning) || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("a member nothing runs for: %v, want ErrMemberNotRunning (an ErrUnavailable)", err)
	}
}
