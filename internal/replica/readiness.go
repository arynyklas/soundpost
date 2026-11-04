// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"soundpost/internal/model"
	"strings"
	"time"
)

const readinessPath = "/internal/raft/v1/ready/"

type readinessResult struct {
	Status *Status    `json:"status,omitempty"`
	Code   model.Code `json:"code,omitempty"`
}

func (t *MTLS) CheckReadiness(ctx context.Context, id model.ID, node uint64) (uint64, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	t.mu.RLock()
	group := t.groups[id]
	t.mu.RUnlock()
	if group == nil {
		return 0, ErrUnavailable
	}
	var target Member
	for _, member := range group.transportMembers().Nodes {
		if member.ID == node {
			target = member
		}
	}
	if target.ID == 0 {
		return 0, ErrInvalid
	}
	client, err := t.peerClient(target)
	if err != nil {
		return 0, err
	}
	request, err := http.NewRequestWithContext(ctx, "GET", strings.TrimSuffix(target.Address, "/")+readinessPath+id.String(), nil)
	if err != nil {
		return 0, err
	}
	response, err := client.Do(request)
	if err != nil {
		return 0, ErrUnavailable
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return 0, ErrUnavailable
	}
	var result readinessResult
	if model.StrictJSON(raw, &result) != nil || response.StatusCode != 200 || result.Status == nil || result.Status.ID != node || result.Status.Group != id || result.Status.Failed {
		return 0, ErrStale
	}
	return result.Status.Applied, nil
}
func (t *MTLS) serveReadiness(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" || r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	var id model.ID
	if id.UnmarshalText([]byte(strings.TrimPrefix(r.URL.Path, readinessPath))) != nil {
		http.Error(w, "invalid", http.StatusBadRequest)
		return
	}
	t.mu.RLock()
	group := t.groups[id]
	t.mu.RUnlock()
	if group == nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	allowed := false
	identity := certificateIdentity(r.TLS.PeerCertificates[0])
	for _, member := range group.transportMembers().Nodes {
		if member.NodeIdentity == identity {
			allowed = true
		}
	}
	if !allowed {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if _, err := group.ReadIndex(r.Context()); err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(readinessResult{Code: forwardedCode(err)})
		return
	}
	status := group.Status()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(readinessResult{Status: &status})
}
