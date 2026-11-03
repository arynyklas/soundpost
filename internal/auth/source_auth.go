// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"soundpost/internal/model"
	"strings"
	"time"
)

const Ingest Permission = "telemetry.ingest"

type SourceCredential struct {
	service *Service
	digest  string
	source  model.ID
	origin  string
	browser bool
}
type SourceOnboarding struct {
	CommandID model.ID           `json:"command_id"`
	Org       model.ID           `json:"org"`
	Project   model.ID           `json:"project"`
	Source    model.ID           `json:"source"`
	Browser   bool               `json:"browser"`
	Origins   []string           `json:"origins"`
	Expires   model.UnixNano     `json:"expires_ns"`
	Policy    model.SourcePolicy `json:"policy"`
	Reason    string             `json:"reason"`
}
type SourceOnboarded struct {
	Credential  string                     `json:"credential,omitempty"`
	Descriptor  model.SourceDescriptor     `json:"descriptor"`
	Policy      model.SignedPolicyEnvelope `json:"policy"`
	TrustedKeys map[string]string          `json:"trusted_keys"`
}

func (s *Service) AuthenticateSource(ctx context.Context, raw, origin string, browser bool) (SourceCredential, error) {
	d, e := s.BearerDigest(SourceBearer, raw)
	if e != nil {
		return SourceCredential{}, e
	}
	c := SourceCredential{service: s, digest: d, origin: origin, browser: browser}
	e = s.store.View(ctx, func(st model.ControlState) error {
		id, ok := st.SourceCredentials[d]
		if !ok {
			return model.Fail(model.Unauthenticated)
		}
		src, ok := st.Sources[id]
		if !ok {
			return model.Fail(model.Unauthenticated)
		}
		c.source = src.ID
		return s.checkSource(st, c, false)
	})
	if e != nil {
		return SourceCredential{}, e
	}
	return c, nil
}
func (s *Service) checkSource(st model.ControlState, c SourceCredential, admission bool) error {
	if c.service != s || st.SourceCredentials[c.digest] != c.source.String() {
		return model.Fail(model.Unauthenticated)
	}
	src, ok := st.Sources[c.source.String()]
	if !ok || src.Revoked || int64(src.Expires) <= s.now().UnixNano() {
		return model.Fail(model.Unauthenticated)
	}
	o, ok := st.Orgs[src.Org.String()]
	if !ok || src.Retired {
		return model.Fail(model.Forbidden)
	}
	if _, ok = o.Projects[src.Project.String()]; !ok {
		return model.Fail(model.Forbidden)
	}
	if src.Browser != c.browser {
		return model.Fail(model.Forbidden)
	}
	if src.Browser {
		allowed := false
		for _, v := range src.Origins {
			if v == c.origin {
				allowed = true
			}
		}
		if !allowed {
			return model.Fail(model.Forbidden)
		}
	} else if c.origin != "" {
		return model.Fail(model.Forbidden)
	}
	if admission {
		if src.Closing || !src.Policy.Enabled || src.Policy.Expires != 0 && int64(src.Policy.Expires) <= s.now().UnixNano() {
			return model.Fail(model.Stale)
		}
		var cfg SourcePolicyConfig
		if json.Unmarshal(o.Settings["source_policy:"+src.ID.String()], &cfg) != nil || !cfg.Enabled || cfg.ProjectID != src.Project || cfg.Restricted != (src.Policy.Class == "restricted_raw") {
			return model.Fail(model.Forbidden)
		}
		if src.Policy.Class == "restricted_raw" && (src.Browser || len(cfg.Readers) == 0 || src.Policy.RawOwner == nil || !o.Members[src.Policy.RawOwner.String()] && !o.Admins[src.Policy.RawOwner.String()]) {
			return model.Fail(model.Forbidden)
		}
		if src.Browser {
			allowed := false
			for _, v := range cfg.Origins {
				if c.origin == v {
					allowed = true
				}
			}
			if !allowed {
				return model.Fail(model.Forbidden)
			}
		}
	}
	return nil
}
func (s *Service) SourceAuthority(ctx context.Context, c SourceCredential, admission bool) (model.SourceAuthority, error) {
	var out model.SourceAuthority
	e := s.store.View(ctx, func(st model.ControlState) error {
		if e := s.checkSource(st, c, admission); e != nil {
			return e
		}
		out = st.Sources[c.source.String()]
		return nil
	})
	return out, e
}
func (s *Service) SourceScope(ctx context.Context, c SourceCredential, historical bool) (Scope, error) {
	var out Scope
	e := s.store.View(ctx, func(st model.ControlState) error {
		if e := s.checkSource(st, c, !historical); e != nil {
			return e
		}
		src := st.Sources[c.source.String()]
		o := st.Orgs[src.Org.String()]
		copyC := c
		out = Scope{service: s, org: src.Org, projects: []model.ID{src.Project}, sources: []model.ID{src.ID}, action: Ingest, epoch: o.Epoch, sourceCredential: &copyC, historical: historical, lease: &scopeLease{}, fingerprint: hashToken(c.digest)}
		out.lease.deadline = s.now().Add(5 * time.Second)
		return nil
	})
	return out, e
}
func (scope Scope) ValidateSourceState(st model.ControlState, project, source model.ID, admission bool) error {
	if scope.service == nil || scope.sourceCredential == nil || scope.action != Ingest || !scope.AllowsProject(project) || !scope.AllowsSource(source) || admission && scope.historical {
		return model.Fail(model.Forbidden)
	}
	if e := scope.service.checkSource(st, *scope.sourceCredential, admission); e != nil {
		return e
	}
	if admission && st.Orgs[scope.org.String()].Epoch != scope.epoch {
		return model.Fail(model.Stale)
	}
	return nil
}
func (scope Scope) RevalidateSource(ctx context.Context, project, source model.ID, admission bool) error {
	if scope.service == nil {
		return model.Fail(model.Forbidden)
	}
	return scope.service.store.View(ctx, func(st model.ControlState) error { return scope.ValidateSourceState(st, project, source, admission) })
}
func (s *Service) OnboardSource(ctx context.Context, c Credential, r SourceOnboarding) (SourceOnboarded, error) {
	if c.service != s || c.machine || !c.Fresh() || r.CommandID == (model.ID{}) || r.Source == (model.ID{}) || r.Project == (model.ID{}) || r.Org == (model.ID{}) || int64(r.Expires) <= s.now().UnixNano() || r.Reason == "" || len(r.Reason) > 512 {
		return SourceOnboarded{}, model.Fail(model.Invalid)
	}
	if r.Policy.Revision == 0 || !r.Policy.Enabled || r.Policy.MaxBytes == 0 || r.Policy.MaxSeries == 0 || len(r.Policy.Kinds) == 0 || r.Browser && r.Policy.Class == "restricted_raw" {
		return SourceOnboarded{}, model.Fail(model.Invalid)
	}
	if e := model.ValidateSourcePolicy(r.Policy); e != nil {
		return SourceOnboarded{}, e
	}
	for _, origin := range r.Origins {
		u, e := url.Parse(origin)
		if e != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
			return SourceOnboarded{}, model.Fail(model.Invalid)
		}
	}
	if r.Browser && len(r.Origins) == 0 {
		return SourceOnboarded{}, model.Fail(model.Invalid)
	}
	raw := randomToken()
	digest, e := s.BearerDigest(SourceBearer, raw)
	if e != nil {
		return SourceOnboarded{}, e
	}
	credentialID := model.NewID()
	auditID := model.NewID()
	var sealed string
	if e = s.store.View(ctx, func(st model.ControlState) error { sealed = st.PolicySigningKey; return nil }); e != nil {
		return SourceOnboarded{}, e
	}
	if sealed == "" {
		_, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return SourceOnboarded{}, err
		}
		sealed, e = s.store.Seal(base64.RawStdEncoding.EncodeToString(private))
		if e != nil {
			return SourceOnboarded{}, e
		}
	}
	admittedAt := s.now().UnixNano()
	var keyEnvelope string
	e = s.store.Update(ctx, func(st *model.ControlState) error {
		if e := s.validateCredentialState(*st, c); e != nil {
			return e
		}
		o, ok := st.Orgs[r.Org.String()]
		if !ok || !o.Admins[c.user.String()] {
			return model.Fail(model.NotFound)
		}
		if _, ok = o.Projects[r.Project.String()]; !ok {
			return model.Fail(model.NotFound)
		}
		if _, ok = st.Sources[r.Source.String()]; ok {
			return model.Fail(model.Conflict)
		}
		binding := c.user.String() + ":" + r.Org.String() + ":source.onboard"
		if _, exists := st.Commands[r.CommandID.String()]; exists {
			if st.CommandOwners[r.CommandID.String()] != binding {
				return model.Fail(model.NotFound)
			}
			return model.Fail(model.Conflict)
		}
		if configured, exists := o.Settings["source_policy:"+r.Source.String()]; exists {
			var cfg SourcePolicyConfig
			if json.Unmarshal(configured, &cfg) != nil || cfg.ProjectID != r.Project || !cfg.Enabled || cfg.Restricted != (r.Policy.Class == "restricted_raw") {
				return model.Fail(model.Forbidden)
			}
			if r.Policy.Class == "restricted_raw" && (len(cfg.Readers) == 0 || r.Policy.RawOwner == nil || !o.Members[r.Policy.RawOwner.String()] && !o.Admins[r.Policy.RawOwner.String()] || int64(r.Policy.Expires) <= admittedAt || r.Policy.Expires > r.Expires) {
				return model.Fail(model.Forbidden)
			}
			for _, v := range r.Origins {
				found := false
				for _, allowed := range cfg.Origins {
					if v == allowed {
						found = true
					}
				}
				if !found {
					return model.Fail(model.Forbidden)
				}
			}
		} else {
			if r.Policy.Class == "restricted_raw" {
				return model.Fail(model.Forbidden)
			}
			cfg, _ := json.Marshal(SourcePolicyConfig{ProjectID: r.Project, Origins: r.Origins, Enabled: true})
			o.Settings["source_policy:"+r.Source.String()] = cfg
		}
		if st.Sources == nil {
			st.Sources = map[string]model.SourceAuthority{}
			st.SourceCredentials = map[string]string{}
		}
		if st.PolicySigningKey == "" {
			st.PolicySigningKey = sealed
		}
		keyEnvelope = st.PolicySigningKey
		st.Sources[r.Source.String()] = model.SourceAuthority{ID: r.Source, Org: r.Org, Project: r.Project, Browser: r.Browser, Origins: append([]string(nil), r.Origins...), Expires: r.Expires, Policy: r.Policy, CredentialID: credentialID}
		st.SourceCredentials[digest] = r.Source.String()
		o.Epoch++
		st.Orgs[r.Org.String()] = o
		if st.CommandOwners == nil {
			st.CommandOwners = map[string]string{}
		}
		st.CommandOwners[r.CommandID.String()] = binding
		st.Commands[r.CommandID.String()] = model.ControlResult{Revision: st.Revision + 1, Cursor: model.Cursor{Group: st.Installation, Index: uint64(st.Revision + 1)}, AffectedIDs: []model.ID{r.Source}}
		st.Audits = append(st.Audits, model.ControlAudit{ID: auditID, Principal: c.user, Org: r.Org.String(), Action: "source.onboard", Reason: r.Reason, Time: admittedAt, Targets: []model.ID{r.Project, r.Source}, PolicyEpoch: o.Epoch, RequestID: model.RequestCorrelationID(ctx, r.CommandID), Outcome: model.AuditAllowed})
		return nil
	})
	if e != nil {
		return SourceOnboarded{}, e
	}
	secret, e := s.store.OpenSecret(keyEnvelope)
	if e != nil {
		return SourceOnboarded{}, model.Fail(model.Unavailable)
	}
	key, e := base64.RawStdEncoding.DecodeString(secret)
	if e != nil || len(key) != ed25519.PrivateKeySize {
		return SourceOnboarded{}, model.Fail(model.Corrupt)
	}
	pub := ed25519.PrivateKey(key).Public().(ed25519.PublicKey)
	expires := r.Expires
	if r.Policy.Expires != 0 && r.Policy.Expires < expires {
		expires = r.Policy.Expires
	}
	enabled := func(k model.Kind) bool {
		for _, v := range r.Policy.Kinds {
			if v == k {
				return true
			}
		}
		return false
	}
	payload, e := model.CanonicalJSON(map[string]any{"version": 1, "org": r.Org.String(), "project": r.Project.String(), "source": r.Source.String(), "revision": r.Policy.Revision, "expires_ns": expires, "errors": enabled(model.ErrorKind), "logs": enabled(model.Log), "replay": enabled(model.Replay) && r.Policy.Replay, "bodies": false})
	if e != nil {
		return SourceOnboarded{}, e
	}
	keyID := "installation-" + model.HashCanonical(pub).String()[:32]
	signature := ed25519.Sign(ed25519.PrivateKey(key), payload)
	return SourceOnboarded{Credential: raw, Descriptor: model.SourceDescriptor{Version: 1, Org: r.Org, Project: r.Project, Source: r.Source, RoutingVersion: 1, Slots: 64, PolicyRevision: r.Policy.Revision}, Policy: model.SignedPolicyEnvelope{Version: 1, Algorithm: "Ed25519", KeyID: keyID, Payload: base64.RawURLEncoding.EncodeToString(payload), Signature: base64.RawURLEncoding.EncodeToString(signature)}, TrustedKeys: map[string]string{keyID: base64.RawURLEncoding.EncodeToString(pub)}}, nil
}
func (s *Service) RevokeSource(ctx context.Context, c Credential, source model.ID, reason string) error {
	if c.service != s || c.machine || !c.Fresh() || strings.TrimSpace(reason) == "" || len(reason) > 512 {
		return model.Fail(model.Forbidden)
	}
	operation, audit := model.NewID(), model.NewID()
	revokedAt := s.now().UnixNano()
	return s.store.Update(ctx, func(st *model.ControlState) error {
		if e := s.validateCredentialState(*st, c); e != nil {
			return e
		}
		src, ok := st.Sources[source.String()]
		o := st.Orgs[src.Org.String()]
		if !ok || !o.Admins[c.user.String()] {
			return model.Fail(model.NotFound)
		}
		if src.Revoked {
			if _, exists := st.SourceFences[source.String()]; exists {
				return nil
			}
		}
		if src.Closing {
			return model.Fail(model.Stale)
		}
		src.Revoked = true
		src.Closing = true
		st.Sources[source.String()] = src
		o.Epoch++
		st.Orgs[src.Org.String()] = o
		if st.SourceFences == nil {
			st.SourceFences = map[string]model.SourceFence{}
		}
		st.SourceFences[source.String()] = model.SourceFence{Operation: operation, Source: source, Org: src.Org, Epoch: o.Epoch, Phase: "fencing"}
		if st.SourceOperations == nil {
			st.SourceOperations = map[string]model.SourceFence{}
		}
		st.SourceOperations[operation.String()] = st.SourceFences[source.String()]
		st.Audits = append(st.Audits, model.ControlAudit{ID: audit, Principal: c.user, Org: src.Org.String(), Action: "source.revoke", Reason: reason, Time: revokedAt, PolicyEpoch: o.Epoch, Targets: []model.ID{source, operation}, RequestID: model.RequestCorrelationID(ctx, source), Outcome: model.AuditAllowed})
		return nil
	})
}
