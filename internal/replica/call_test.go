// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// A member that is not the leader hands a call to the leader: the handler runs on the leader, learns which member called (the
// member whose certificate authenticated the hop, whatever the body says), and what it answers or refuses reaches the caller.
// The leader has nobody to call, a name no handler serves (another release) is not served, and a certificate for a node outside
// the configuration gets nothing through.
func TestACallRunsTheHandlerOnTheLeaderAndAnswersTheCaller(t *testing.T) {
	c := newMTLSCluster(t, 1)
	leadOnNode1(t, c)
	for node := range 3 {
		node := node
		c.groups[node][0].HandleCall("echo", func(_ context.Context, from uint64, body []byte) ([]byte, error) {
			if node != 0 {
				t.Errorf("node %d ran a handler: only the leader does", node+1)
			}
			return []byte(fmt.Sprintf("%d:%s", from, body)), nil
		})
		c.groups[node][0].HandleCall("refuse", func(context.Context, uint64, []byte) ([]byte, error) {
			return nil, model.Fail(model.Quota)
		})
		c.groups[node][0].HandleCall("break", func(context.Context, uint64, []byte) ([]byte, error) {
			return nil, errors.New("not a fault")
		})
		c.groups[node][0].HandleCall("unserved", func(context.Context, uint64, []byte) ([]byte, error) {
			return nil, ErrNoCall
		})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for _, node := range []int{1, 2} {
		out, err := c.groups[node][0].CallLeader(ctx, "echo", []byte("hello"))
		if err != nil || string(out) != fmt.Sprintf("%d:hello", node+1) {
			t.Fatalf("node %d: call answered %q, %v", node+1, out, err)
		}
	}
	_, err := c.groups[1][0].CallLeader(ctx, "refuse", nil)
	var fault *model.Fault
	if !errors.As(err, &fault) || fault.Code != model.Quota {
		t.Fatalf("a refusal of the handler reached the caller as %v, want the quota fault", err)
	}
	if _, err = c.groups[1][0].CallLeader(ctx, "break", nil); !errors.As(err, &fault) || fault.Code != model.Unavailable {
		t.Fatalf("an error that is not a fault reached the caller as %v, want unavailable", err)
	}
	if _, err = c.groups[1][0].CallLeader(ctx, "unknown", nil); !errors.Is(err, ErrNoCall) {
		t.Fatalf("a call no handler serves answered %v, want that the leader serves no such call", err)
	}
	if _, err = c.groups[1][0].CallLeader(ctx, "unserved", nil); !errors.Is(err, ErrNoCall) {
		t.Fatalf("a call whose handler says it serves nothing answered %v, want that the leader serves no such call", err)
	}
	if _, err = c.groups[0][0].CallLeader(ctx, "echo", nil); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("the leader's call to itself answered %v, want unavailable", err)
	}

	group := c.groups[0][0].Status().Group
	post := func(cert tls.Certificate, node int) int {
		t.Helper()
		client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, RootCAs: c.roots}, ForceAttemptHTTP2: true}}
		defer client.CloseIdleConnections()
		request, err := http.NewRequest("POST", c.members.Nodes[node].Address+callPath+group.String()+"/echo", bytes.NewReader([]byte("x")))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("X-Soundpost-Raft-Hop", "1")
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		_, _ = io.Copy(io.Discard, response.Body)
		return response.StatusCode
	}
	if status := post(c.outsider, 0); status != http.StatusForbidden {
		t.Fatalf("a certificate for a node outside the configuration got status %d, want 403", status)
	}
	if status := post(c.certs[1], 1); status != http.StatusServiceUnavailable {
		t.Fatalf("a call made to a follower got status %d, want 503", status)
	}
}
