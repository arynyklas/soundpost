// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

const proposalPath = "/internal/raft/v1/propose/"

// applicationHeader and entryHeader carry the application index a forwarded proposal names and its identity, so that the leader
// can refuse a proposal whose index has moved before the body is read.
const (
	applicationHeader = "X-Soundpost-Application-Index"
	entryHeader       = "X-Soundpost-Entry"
)

// proposalsRefusedEarly counts the forwarded proposals the leader refused as stale from their headers, proposalBodiesRead the
// bodies it read.
var proposalsRefusedEarly, proposalBodiesRead atomic.Uint64

// applicationMoved says whether the leader would refuse the entry id, which names the application index n, as stale (proposeOneLocked:
// the log's application index is not n-1). An entry the leader already holds, in flight or decided, is answered from the table
// whatever its index says, so it is never refused here.
func (g *Group) applicationMoved(id model.ID, n uint64) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, ok := g.completed[id]; ok {
		return false
	}
	if _, ok := g.logCommands[id]; ok {
		return false
	}
	return g.logApplication != ^uint64(0) && g.logApplication+1 != n
}

type forwardedResult struct {
	Committed *CommittedEntry `json:"committed,omitempty"`
	Code      model.Code      `json:"code,omitempty"`
}

func (g *Group) transportMembers() Members {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.transportMembersLocked()
}

// transportMembersLocked is the membership the transport addresses: the members plus those being retired.
// g.mu is held.
func (g *Group) transportMembersLocked() Members {
	members := cloneMembers(g.members)
	known := map[uint64]bool{}
	for _, member := range members.Nodes {
		known[member.ID] = true
	}
	for _, member := range g.retiring {
		if !known[member.ID] {
			members.Nodes = append(members.Nodes, member)
		}
	}
	return members
}

// peerClient is the HTTP client of the connection a peer's appends, calls and proposals share.
func (t *MTLS) peerClient(target Member) (*http.Client, error) { return t.laneClient(target, "") }

// beatClient is the HTTP client of a connection of its own to the peer, which only the coalesced heartbeats use
// (transport_batch.go). A heartbeat that shares the connection of the appends of 65 groups waits in its socket buffer and its
// flow-control window behind every megabyte of them, which on a link that carries 80 Mbit/s of appends is a good part of a
// leader's election timeout; on a connection of its own it is a flow the sender's queue discipline serves ahead of the bulk ones.
func (t *MTLS) beatClient(target Member) (*http.Client, error) { return t.laneClient(target, "|beat") }

func (t *MTLS) laneClient(target Member, lane string) (*http.Client, error) {
	u, err := url.Parse(target.Address)
	if err != nil || u.Scheme != "https" || target.ID == 0 {
		return nil, ErrInvalid
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	key := target.Address + "|" + target.NodeIdentity + lane
	if client := t.clients[key]; client != nil {
		return client, nil
	}
	expected := target.NodeIdentity
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{t.certificate}, RootCAs: t.roots, ServerName: u.Hostname(), VerifyConnection: func(c tls.ConnectionState) error {
		if len(c.VerifiedChains) == 0 || len(c.PeerCertificates) == 0 || certificateIdentity(c.PeerCertificates[0]) != expected {
			return ErrInvalid
		}
		return nil
	}}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg, ForceAttemptHTTP2: true, DialContext: t.dialer.DialContext, ExpectContinueTimeout: time.Second}, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrInvalid }}
	t.clients[key] = client
	return client, nil
}
func (t *MTLS) ForwardPropose(ctx context.Context, group model.ID, entry Entry) (CommittedEntry, error) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	t.mu.RLock()
	g := t.groups[group]
	t.mu.RUnlock()
	if g == nil {
		return CommittedEntry{}, ErrInvalid
	}
	status := g.Status()
	var target Member
	for _, member := range g.transportMembers().Nodes {
		if member.ID == status.Leader {
			target = member
		}
	}
	if target.ID == 0 || target.ID == t.id {
		return CommittedEntry{}, ErrNoLeader // this member knows no leader (an election), or is not the leader it names
	}
	client, err := t.peerClient(target)
	if err != nil {
		return CommittedEntry{}, err
	}
	raw, err := json.Marshal(entry)
	if err != nil {
		return CommittedEntry{}, err
	}
	request, err := http.NewRequestWithContext(ctx, "POST", strings.TrimSuffix(target.Address, "/")+proposalPath+group.String(), bytes.NewReader(raw))
	if err != nil {
		return CommittedEntry{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	if entry.ApplicationIndex != 0 {
		// Ask the leader to judge the index before the body is sent (serveProposal): a proposal that lost the race costs a header.
		request.Header.Set(applicationHeader, strconv.FormatUint(entry.ApplicationIndex, 10))
		request.Header.Set(entryHeader, entry.ID.String())
		request.Header.Set("Expect", "100-continue")
	}
	request.Header.Set("X-Soundpost-Raft-Hop", "1")
	response, err := client.Do(request)
	if err != nil {
		return CommittedEntry{}, ErrNoLeader // the leader this member knows does not answer
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 32<<20))
	if err != nil {
		return CommittedEntry{}, ErrNoLeader
	}
	var result forwardedResult
	if model.StrictJSON(body, &result) != nil {
		return CommittedEntry{}, ErrUnavailable
	}
	if result.Code != "" {
		return CommittedEntry{}, forwardedError(result.Code)
	}
	if response.StatusCode != http.StatusOK || result.Committed == nil || result.Committed.Group != group || result.Committed.Entry.ID != entry.ID {
		return CommittedEntry{}, ErrUnavailable
	}
	committed := *result.Committed
	if committed.Entry.Payload == nil && committed.Entry.Original == nil {
		committed.Entry.Payload = entry.Payload // the leader does not echo the command the forwarder sent
	}
	return committed, nil
}
func forwardedError(code model.Code) error {
	switch code {
	case model.Conflict:
		return ErrConflict
	case model.Timeout:
		return ErrNoQuorum
	case model.Stale:
		return ErrStale
	case model.Invalid:
		return ErrInvalid
	case model.Forbidden, model.NotFound, model.Quota, model.Cancelled:
		return model.Fail(code)
	default:
		// The leader could not commit it: it was deposed since this member learned it leads, or it failed
		// closed and the other voters elect again. Either way the leader's trouble is a gap this member's
		// caller outlasts, not a state of this member.
		return ErrNoLeader
	}
}
func forwardedCode(err error) model.Code {
	var fault *model.Fault
	if errors.As(err, &fault) {
		if fault.Code == model.Stale && fault.Retryable {
			return model.Timeout
		}
		switch fault.Code {
		case model.Conflict, model.Stale, model.Invalid, model.Forbidden, model.NotFound, model.Quota, model.Cancelled:
			return fault.Code
		}
	}
	switch {
	case errors.Is(err, ErrConflict):
		return model.Conflict
	case errors.Is(err, ErrNoQuorum):
		// A freshness fence the leader waited for and did not reach is not an optimistic refusal. It travels as a
		// timeout, a code this wire already answered with a gap (an older forwarder maps it to unavailable), so
		// the peer format is unchanged.
		return model.Timeout
	case errors.Is(err, ErrStale):
		return model.Stale
	case errors.Is(err, ErrInvalid):
		return model.Invalid
	default:
		return model.Unavailable
	}
}

// Peers are the non-Byzantine consensus trust boundary, not source/user grants.
// This route accepts only leaf commands already authorized by real ingress and
// revalidated by the actual leader's closed-command validator before proposal.
func (t *MTLS) serveProposal(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" || r.Header.Get("X-Soundpost-Raft-Hop") != "1" || r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	var group model.ID
	if group.UnmarshalText([]byte(strings.TrimPrefix(r.URL.Path, proposalPath))) != nil {
		http.Error(w, "invalid", http.StatusBadRequest)
		return
	}
	t.mu.RLock()
	g := t.groups[group]
	t.mu.RUnlock()
	if g == nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	identity := certificateIdentity(r.TLS.PeerCertificates[0])
	var from *Proposer
	for _, member := range g.transportMembers().Nodes {
		if member.NodeIdentity == identity {
			from = &Proposer{Node: member.ID, Identity: member.NodeIdentity}
		}
	}
	if from == nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	status := g.Status()
	// A proposal that names the application index it was computed for is judged before its body is read: a follower that lost the
	// race for the index (the control group's proposals: every one of a round is computed against the revision its proposer read)
	// is answered stale at once, and with `Expect: 100-continue` its body never leaves the follower (see applicationMoved).
	if raw := r.Header.Get(applicationHeader); raw != "" {
		var id model.ID
		n, perr := strconv.ParseUint(raw, 10, 64)
		if perr == nil && n != 0 && id.UnmarshalText([]byte(r.Header.Get(entryHeader))) == nil && status.ID == status.Leader && g.applicationMoved(id, n) {
			proposalsRefusedEarly.Add(1)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(forwardedResult{Code: model.Stale})
			return
		}
	}
	proposalBodiesRead.Add(1)
	if status.ID != status.Leader {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(forwardedResult{Code: model.Unavailable})
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 24<<20))
	if err != nil {
		http.Error(w, "invalid", http.StatusBadRequest)
		return
	}
	// Whatever proposer the forwarder wrote into the entry is discarded: the leader records the
	// member whose certificate authenticated this hop.
	var entry Entry
	if model.StrictJSON(raw, &entry) != nil {
		http.Error(w, "invalid", http.StatusBadRequest)
		return
	}
	entry.Proposer = nil
	if !entry.valid() {
		http.Error(w, "invalid", http.StatusBadRequest)
		return
	}
	committed, err := g.propose(r.Context(), entry, from)
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(forwardedResult{Code: forwardedCode(err)})
		return
	}
	committed.Entry.Payload = nil // the forwarder holds the command it sent: its payload is not carried back (a copy: the retry table is untouched)
	_ = json.NewEncoder(w).Encode(forwardedResult{Committed: &committed})
}
