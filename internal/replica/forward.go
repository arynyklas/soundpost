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
	"strings"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

const proposalPath = "/internal/raft/v1/propose/"

type forwardedResult struct {
	Committed *CommittedEntry `json:"committed,omitempty"`
	Code      model.Code      `json:"code,omitempty"`
}

func (g *Group) transportMembers() Members {
	g.mu.Lock()
	defer g.mu.Unlock()
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
func (t *MTLS) peerClient(target Member) (*http.Client, error) {
	u, err := url.Parse(target.Address)
	if err != nil || u.Scheme != "https" || target.ID == 0 {
		return nil, ErrInvalid
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	key := target.Address + "|" + target.NodeIdentity
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
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg, ForceAttemptHTTP2: true, DialContext: t.dialer.DialContext}, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrInvalid }}
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
		return CommittedEntry{}, ErrUnavailable
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
	request.Header.Set("X-Soundpost-Raft-Hop", "1")
	response, err := client.Do(request)
	if err != nil {
		return CommittedEntry{}, ErrUnavailable
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 32<<20))
	if err != nil {
		return CommittedEntry{}, ErrUnavailable
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
	return *result.Committed, nil
}
func forwardedError(code model.Code) error {
	switch code {
	case model.Conflict:
		return ErrConflict
	case model.Stale:
		return ErrStale
	case model.Invalid:
		return ErrInvalid
	case model.Forbidden, model.NotFound, model.Quota, model.Cancelled:
		return model.Fail(code)
	default:
		return ErrUnavailable
	}
}
func forwardedCode(err error) model.Code {
	var fault *model.Fault
	if errors.As(err, &fault) {
		switch fault.Code {
		case model.Conflict, model.Stale, model.Invalid, model.Forbidden, model.NotFound, model.Quota, model.Cancelled:
			return fault.Code
		}
	}
	switch {
	case errors.Is(err, ErrConflict):
		return model.Conflict
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
	_ = json.NewEncoder(w).Encode(forwardedResult{Committed: &committed})
}
