// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth

import (
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// SourceClaim is what a voter tells another voter about the scope of an ingest request it is forwarding (a transition the
// control leader judges for it): the credential's digest (never the secret), the source, and the organization, project and
// epoch the scope was made for. The receiving voter makes a Scope of it (ScopeOfClaim) and judges against its own state, which
// is what decides: the digest must be the source's credential there, the epoch the organization's there, and the project the
// source's there (ValidateSourceClaim).
type SourceClaim struct {
	Digest     string   `json:"digest"`
	Source     model.ID `json:"source"`
	Origin     string   `json:"origin,omitempty"`
	Browser    bool     `json:"browser,omitempty"`
	Org        model.ID `json:"org"`
	Project    model.ID `json:"project"`
	Epoch      uint64   `json:"epoch,string"`
	Historical bool     `json:"historical,omitempty"`
}

// SourceClaim is the claim of a source scope; false for any other scope.
func (scope Scope) SourceClaim() (SourceClaim, bool) {
	c := scope.sourceCredential
	if scope.service == nil || c == nil || scope.action != Ingest || len(scope.projects) != 1 || len(scope.sources) != 1 || c.source != scope.sources[0] {
		return SourceClaim{}, false
	}
	return SourceClaim{Digest: c.digest, Source: c.source, Origin: c.origin, Browser: c.browser, Org: scope.org, Project: scope.projects[0], Epoch: scope.epoch, Historical: scope.historical}, true
}

// ScopeOfClaim is the scope a claim describes. It decides nothing: every check of a scope (ValidateSourceState, which
// checks what a claimed scope carries against the state; ValidateSourceClaim) runs against the state of the voter that
// judges with it.
func (s *Service) ScopeOfClaim(c SourceClaim) Scope {
	credential := SourceCredential{service: s, digest: c.Digest, source: c.Source, origin: c.Origin, browser: c.Browser}
	out := Scope{service: s, org: c.Org, projects: []model.ID{c.Project}, sources: []model.ID{c.Source}, action: Ingest, epoch: c.Epoch, sourceCredential: &credential, historical: c.Historical, claimed: true, lease: &scopeLease{}, fingerprint: hashToken(c.Digest)}
	out.lease.deadline = s.now().Add(5 * time.Second)
	return out
}

// ValidateSourceClaim says whether the source the claim names is, in st, the source of the organization and project it
// claims: a scope made of a claim (ScopeOfClaim) carries them as it was told.
func ValidateSourceClaim(st model.ControlState, c SourceClaim) error {
	src, ok := st.Sources[c.Source.String()]
	if !ok || src.Org != c.Org || src.Project != c.Project {
		return model.Fail(model.Forbidden)
	}
	return nil
}
