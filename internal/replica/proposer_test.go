// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// leadOnNode1 makes node 1 the leader of group 0 and waits until it answers reads.
func leadOnNode1(t *testing.T, c *mtlsCluster) {
	t.Helper()
	if err := c.groups[0][0].Campaign(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for {
		if _, err := c.groups[0][0].ReadIndex(ctx); err == nil {
			return
		} else if ctx.Err() != nil {
			t.Fatalf("node 1 never led group 0: %v", err)
		}
	}
}

func completedProposer(g *Group, id model.ID) (*Proposer, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	c, ok := g.completed[id]
	return c.Entry.Proposer, ok
}

// A command names the member that proposed it, and only the group that ordered it says so: a
// proposal made on the leader names the leader, a proposal a follower forwarded names the member
// whose certificate authenticated the hop, and whatever either wrote into the entry about its own
// author is discarded.
func TestTheGroupRecordsWhichMemberProposedACommand(t *testing.T) {
	c := newMTLSCluster(t, 1)
	leadOnNode1(t, c)
	forged := &Proposer{Node: 3, Identity: "node-3"}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	local, err := c.groups[0][0].Propose(ctx, Entry{ID: model.NewID(), Kind: Data, Payload: []byte("from the leader"), Proposer: forged})
	if err != nil {
		t.Fatal(err)
	}
	if p := local.Entry.Proposer; p == nil || *p != (Proposer{Node: 1, Identity: "node-1"}) {
		t.Fatalf("a proposal made on the leader records %+v, want node 1", p)
	}

	forwarded, err := c.groups[1][0].Propose(ctx, Entry{ID: model.NewID(), Kind: Data, Payload: []byte("from a follower"), Proposer: forged})
	if err != nil {
		t.Fatal(err)
	}
	if p := forwarded.Entry.Proposer; p == nil || *p != (Proposer{Node: 2, Identity: "node-2"}) {
		t.Fatalf("a proposal node 2 forwarded records %+v, want node 2", p)
	}
	// Every member's copy of the committed command names the same proposer.
	for node := range 3 {
		node := node
		g := c.groups[node][0]
		deadline := time.Now().Add(10 * time.Second)
		for {
			p, ok := completedProposer(g, forwarded.Entry.ID)
			if ok && p != nil && *p == (Proposer{Node: 2, Identity: "node-2"}) {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("node %d holds the forwarded command with proposer %+v (applied %v)", node+1, p, ok)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
}

// The forwarding route accepts a proposal only from a member, and records the member the
// certificate names: a certificate the cluster's CA issued for a node that is not in the
// configuration gets nothing through, and a member cannot write another member's name.
func TestAForwardedProposalIsAttributedToTheMemberThatSentItAndANonMemberIsRefused(t *testing.T) {
	c := newMTLSCluster(t, 1)
	leadOnNode1(t, c)
	group := c.groups[0][0].Status().Group
	post := func(cert tls.Certificate, entry Entry) (int, []byte) {
		t.Helper()
		body, err := json.Marshal(entry)
		if err != nil {
			t.Fatal(err)
		}
		client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, RootCAs: c.roots}, ForceAttemptHTTP2: true}}
		defer client.CloseIdleConnections()
		request, err := http.NewRequest("POST", c.members.Nodes[0].Address+proposalPath+group.String(), bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-Soundpost-Raft-Hop", "1")
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		out, _ := io.ReadAll(response.Body)
		return response.StatusCode, out
	}
	claim := &Proposer{Node: 3, Identity: "node-3"}

	outsider := Entry{ID: model.NewID(), Kind: Data, Payload: []byte("from a node that is not a member"), Proposer: claim}
	if status, _ := post(c.outsider, outsider); status != http.StatusForbidden {
		t.Fatalf("a certificate for a node outside the configuration got status %d, want 403", status)
	}
	if _, ok := completedProposer(c.groups[0][0], outsider.ID); ok {
		t.Fatal("a proposal from a non-member was committed")
	}

	member := Entry{ID: model.NewID(), Kind: Data, Payload: []byte("from member 2"), Proposer: claim}
	status, out := post(c.certs[1], member)
	if status != http.StatusOK {
		t.Fatalf("a member's forwarded proposal got status %d: %s", status, out)
	}
	var result forwardedResult
	if err := json.Unmarshal(out, &result); err != nil || result.Committed == nil {
		t.Fatalf("answer %s: %v", out, err)
	}
	if p := result.Committed.Entry.Proposer; p == nil || *p != (Proposer{Node: 2, Identity: "node-2"}) {
		t.Fatalf("node 2's request that claimed node 3 was recorded as %+v", p)
	}
}

// The proposer is part of the committed command's wire form: it round-trips, a command written
// before it existed decodes with none, and a malformed one is not a command.
func TestEntryProposerWireForm(t *testing.T) {
	entry := Entry{ID: model.NewID(), Kind: Barrier, Payload: []byte("p"), ApplicationIndex: 4, Proposer: &Proposer{Node: 2, Identity: "node-2"}}
	raw, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	back, err := decodeEntry(raw)
	if err != nil || back.Proposer == nil || *back.Proposer != *entry.Proposer || !back.valid() {
		t.Fatalf("round trip: %+v %v (%s)", back, err, raw)
	}
	var viaJSON Entry
	if err = json.Unmarshal(raw, &viaJSON); err != nil || viaJSON.Proposer == nil || *viaJSON.Proposer != *entry.Proposer {
		t.Fatalf("json.Unmarshal: %+v %v", viaJSON, err)
	}

	entry.Proposer = nil
	legacy, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(legacy, []byte("proposer")) {
		t.Fatalf("an entry with no proposer carries the field: %s", legacy)
	}
	if old, err := decodeEntry(legacy); err != nil || old.Proposer != nil || !old.valid() {
		t.Fatalf("an entry written before the proposer existed: %+v %v", old, err)
	}

	for name, bad := range map[string]string{
		"unknown field": `{"node":"2","node_identity":"n","extra":1}`,
		"numeric node":  `{"node":2,"node_identity":"n"}`,
	} {
		doc := bytes.Replace(raw, []byte(`"proposer":{"node":"2","node_identity":"node-2"}`), []byte(`"proposer":`+bad), 1)
		if bytes.Equal(doc, raw) {
			t.Fatalf("fixture invalid: %s", raw)
		}
		if _, err := decodeEntry(doc); err == nil {
			t.Fatalf("%s decoded", name)
		}
	}
	for name, p := range map[string]*Proposer{"zero node": {Node: 0, Identity: "n"}, "empty identity": {Node: 2}} {
		entry.Proposer = p
		if entry.valid() {
			t.Fatalf("%s is a valid entry", name)
		}
	}
}
