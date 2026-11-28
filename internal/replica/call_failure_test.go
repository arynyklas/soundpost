// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// A call that failed before its request left the member (the leader does not accept the connection) ran nothing at the leader: it is
// ErrNoLeader, which a retry always mends, and is not ErrCallOutcomeUnknown. A call whose request was received and whose answer never
// came back (the leader's side of the connection is cut after the handler ran) may have committed: it is ErrCallOutcomeUnknown, and
// is not ErrNoLeader. Both are ErrUnavailable.
func TestACallFailureIsNoLeaderWhenNothingWasSentAndUnknownWhenTheRequestWas(t *testing.T) {
	c := newMTLSCluster(t, 1)
	leadOnNode1(t, c)
	var ran atomic.Int64
	for node := range 3 {
		c.groups[node][0].HandleCall("count", func(context.Context, uint64, []byte) ([]byte, error) {
			ran.Add(1)
			return []byte("done"), nil
		})
		c.groups[node][0].HandleCall("cut", func(context.Context, uint64, []byte) ([]byte, error) {
			ran.Add(1)
			panic(http.ErrAbortHandler) // the connection is dropped after the handler ran: no answer reaches the caller
		})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// The answer is lost: the handler ran once and the caller cannot tell.
	_, err := c.groups[1][0].CallLeader(ctx, "cut", []byte("x"))
	if !errors.Is(err, ErrCallOutcomeUnknown) || errors.Is(err, ErrNoLeader) || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("a call whose answer was lost failed with %v, want ErrCallOutcomeUnknown (an ErrUnavailable) and not ErrNoLeader", err)
	}
	if n := ran.Load(); n != 1 {
		t.Fatalf("the handler ran %d times for one call whose answer was lost, want 1", n)
	}

	// The leader does not accept a connection from this member: nothing was sent.
	node2 := c.transports[1]
	node2.mu.Lock()
	saved := map[string]*http.Client{}
	refusing := &http.Client{Transport: &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) {
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}
	}}}
	for key, client := range node2.clients {
		saved[key] = client
		node2.clients[key] = refusing
	}
	node2.mu.Unlock()
	before := ran.Load()
	_, err = c.groups[1][0].CallLeader(ctx, "count", []byte("x"))
	node2.mu.Lock()
	for key, client := range saved {
		node2.clients[key] = client
	}
	node2.mu.Unlock()
	if !errors.Is(err, ErrNoLeader) || errors.Is(err, ErrCallOutcomeUnknown) || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("a call whose connection was refused failed with %v, want ErrNoLeader (an ErrUnavailable) and not ErrCallOutcomeUnknown", err)
	}
	if ran.Load() != before {
		t.Fatal("the handler ran for a call that was never sent")
	}

	// What each means to a caller: nothing sent is retryable, a request that may have run only when the call is idempotent.
	for _, c := range []struct {
		name       string
		err        error
		idempotent bool
		retryable  bool
	}{
		{"nothing sent, not idempotent", ErrNoLeader, false, true},
		{"nothing sent, idempotent", ErrNoLeader, true, true},
		{"request sent, idempotent", ErrCallOutcomeUnknown, true, true},
		{"request sent, not idempotent", ErrCallOutcomeUnknown, false, false},
		{"plain unavailable", ErrUnavailable, true, false},
	} {
		var fault *model.Fault
		if !errors.As(CallFailure(c.err, c.idempotent), &fault) || fault.Code != model.Unavailable || fault.Retryable != c.retryable {
			t.Errorf("%s: answered %v, want unavailable with retryable %t", c.name, CallFailure(c.err, c.idempotent), c.retryable)
		}
	}
}

// A leader's fault reaches the caller with its retryable bit: a retryable unavailable and a retryable stale stay retryable (the
// caller's answer is a 503 with a Retry-After), a fault that is not stays not.
func TestACallCarriesTheRetryableBitOfTheLeadersFault(t *testing.T) {
	c := newMTLSCluster(t, 1)
	leadOnNode1(t, c)
	faults := map[string]*model.Fault{}
	for name, f := range map[string]struct {
		code      model.Code
		retryable bool
	}{
		"unavailable-retryable": {model.Unavailable, true},
		"unavailable":           {model.Unavailable, false},
		"stale-retryable":       {model.Stale, true},
		"stale":                 {model.Stale, false},
		"quota":                 {model.Quota, false},
	} {
		fault := model.Fail(f.code)
		fault.Retryable = f.retryable
		faults[name] = fault
	}
	for node := range 3 {
		for name, fault := range faults {
			c.groups[node][0].HandleCall(name, func(context.Context, uint64, []byte) ([]byte, error) { return nil, fault })
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for name, want := range faults {
		_, err := c.groups[1][0].CallLeader(ctx, name, nil)
		var got *model.Fault
		if !errors.As(err, &got) || got.Code != want.Code || got.Retryable != want.Retryable {
			t.Errorf("%s: the caller was answered %v, want code %s retryable %t", name, err, want.Code, want.Retryable)
		}
	}
}
