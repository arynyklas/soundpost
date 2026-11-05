// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"sort"
	"strings"
	"time"

	"soundpost/internal/model"
)

// Disaster restore (C12) installs a control state taken at some earlier
// backup. Everything in it that could authenticate or authorize someone is
// stale: the backup cannot know which sessions were logged out, which tokens
// were revoked or which accounts were demoted afterwards. A restore therefore
// never reactivates any of it. QuarantineRestoredState moves every pre-restore
// privilege out of the active structures (the only ones the rest of this
// package reads) into one opaque stash record, rotates the bearer hash key and
// arms a fresh one-time bootstrap. Reconcile is the only way an item leaves the
// stash, one at a time, performed by a newly bootstrapped instance admin with
// fresh authentication and an audit record committed in the same transaction.
// Old decryption keys decrypt stored secrets only; nothing here ever consults a
// key to decide that an old credential is valid again.

const restoreStashKey = "restore:quarantine"

// RestoreInput are the values only the restore driver can produce.
type RestoreInput struct {
	Generation      model.ID  // fresh authentication generation; never reused
	Backup          model.ID  // the backup being restored (audit)
	BootstrapHash   string    // from NewRecoveryBootstrap
	SealedBearerKey string    // from SealedBearerKey, sealed under a fresh envelope key
	At              time.Time // restore time (audit)
}

// RestoreSummary counts what was made inactive; it carries no identifiers.
type RestoreSummary struct {
	Generation   model.ID `json:"generation"`
	Users        int      `json:"users"`
	Sessions     int      `json:"sessions"`
	ServerTokens int      `json:"server_tokens"`
	Sources      int      `json:"sources"`
	Orgs         int      `json:"orgs"`
	Grants       int      `json:"grants"`
	Integrations int      `json:"integrations"`
}

type stashedIntegration struct {
	Setting json.RawMessage `json:"setting,omitempty"`
	Secret  string          `json:"secret,omitempty"`
}
type stashedOrg struct {
	Members      map[string]bool               `json:"members"`
	Admins       map[string]bool               `json:"admins"`
	Grants       map[string][]string           `json:"grants"`
	Teams        map[string]model.ControlTeam  `json:"teams"`
	Integrations map[string]stashedIntegration `json:"integrations"`
	Readers      map[string][]model.ID         `json:"readers"` // "source_policy:<id>" -> removed readers
}
type restoreStash struct {
	Version    uint16                `json:"version"`
	Generation model.ID              `json:"generation"`
	Backup     model.ID              `json:"backup"`
	At         int64                 `json:"at"`
	Users      []model.ID            `json:"users"`   // accounts that were enabled at backup time
	Sources    []model.ID            `json:"sources"` // sources that were active at backup time
	Orgs       map[string]stashedOrg `json:"orgs"`
}

// NewRecoveryBootstrap returns a fresh one-time bootstrap token and the hash
// the control state stores. The token goes only to the 0600 bootstrap file.
func NewRecoveryBootstrap() (token, hash string) {
	token = randomToken()
	return token, hashToken(token)
}

// SealedBearerKey returns a fresh bearer hash key sealed with seal (the control
// store's envelope sealing, using the fresh active envelope key). The key
// replaces the installation's bearer key, so no digest stored before the
// restore can match any credential presented afterwards.
func SealedBearerKey(seal func(string) (string, error)) (string, error) {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		return "", err
	}
	sealed, err := seal(base64.RawStdEncoding.EncodeToString(key[:]))
	clear(key[:])
	if err != nil {
		return "", model.Fail(model.Unavailable)
	}
	return sealed, nil
}

func integrationKey(key string) bool {
	return strings.HasPrefix(key, "sso:") || strings.HasPrefix(key, "destination:") || strings.HasPrefix(key, "team:")
}

// QuarantineRestoredState makes every credential, session, elevation, token,
// source secret, sender, account, grant and identity mapping of a restored
// control state inactive. It is deterministic and applies to the state it is
// given; the caller commits it through the control store's replicated update.
func QuarantineRestoredState(st *model.ControlState, in RestoreInput) (RestoreSummary, error) {
	if st == nil || in.Generation == (model.ID{}) || in.Backup == (model.ID{}) || in.BootstrapHash == "" || in.SealedBearerKey == "" || in.At.IsZero() {
		return RestoreSummary{}, model.Fail(model.Invalid)
	}
	if _, done := st.OIDC[restoreStashKey]; done {
		return RestoreSummary{}, model.Fail(model.Conflict)
	}
	sum := RestoreSummary{Generation: in.Generation}
	stash := restoreStash{Version: 1, Generation: in.Generation, Backup: in.Backup, At: in.At.UnixNano(), Users: []model.ID{}, Sources: []model.ID{}, Orgs: map[string]stashedOrg{}}
	// Accounts (and with them their passwords, TOTP, recovery codes) stay in
	// place but disabled: every login, session, token and OIDC path honours it.
	ids := make([]string, 0, len(st.Users))
	for id := range st.Users {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		u := st.Users[id]
		if !u.Disabled {
			stash.Users = append(stash.Users, u.ID)
			u.Disabled = true
			st.Users[id] = u
			sum.Users++
		}
	}
	sum.Sessions = len(st.Sessions)
	st.Sessions = map[string]model.ControlSession{}
	// Elevations and in-flight OIDC logins live in the same map; none survives.
	st.OIDC = map[string]json.RawMessage{}
	for key, token := range st.ServerTokens {
		if !token.Revoked {
			token.Revoked = true
			st.ServerTokens[key] = token
			sum.ServerTokens++
		}
	}
	sourceIDs := make([]string, 0, len(st.Sources))
	for id := range st.Sources {
		sourceIDs = append(sourceIDs, id)
	}
	sort.Strings(sourceIDs)
	for _, id := range sourceIDs {
		src := st.Sources[id]
		if !src.Revoked && !src.Retired {
			stash.Sources = append(stash.Sources, src.ID)
			src.Revoked = true
			st.Sources[id] = src
			sum.Sources++
		}
	}
	st.SourceCredentials = map[string]string{} // no old source secret digest remains
	for orgID, o := range st.Orgs {
		q := stashedOrg{Members: o.Members, Admins: o.Admins, Grants: o.Grants, Teams: o.Teams, Integrations: map[string]stashedIntegration{}, Readers: map[string][]model.ID{}}
		for _, m := range []int{len(o.Members), len(o.Admins), len(o.Grants), len(o.Teams)} {
			sum.Grants += m
		}
		o.Members, o.Admins, o.Grants, o.Teams = map[string]bool{}, map[string]bool{}, map[string][]string{}, map[string]model.ControlTeam{}
		settings := map[string]json.RawMessage{}
		for key, raw := range o.Settings {
			switch {
			case integrationKey(key):
				item := q.Integrations[key]
				item.Setting = raw
				q.Integrations[key] = item
			case strings.HasPrefix(key, "source_policy:"):
				var cfg SourcePolicyConfig
				if json.Unmarshal(raw, &cfg) == nil && len(cfg.Readers) > 0 {
					q.Readers[key] = append([]model.ID(nil), cfg.Readers...)
					cfg.Readers = []model.ID{}
					stripped, err := json.Marshal(cfg)
					if err != nil {
						return RestoreSummary{}, model.Fail(model.Corrupt)
					}
					raw = stripped
				}
				settings[key] = raw
			default:
				settings[key] = raw
			}
		}
		for key, sealed := range o.Secrets { // every stored org secret is a sender/identity secret
			item := q.Integrations[key]
			item.Secret = sealed
			q.Integrations[key] = item
		}
		sum.Integrations += len(q.Integrations)
		o.Settings, o.Secrets = settings, map[string]string{}
		o.Epoch++ // every scope, cache entry and cursor minted before dies
		st.Orgs[orgID] = o
		stash.Orgs[orgID] = q
		sum.Orgs++
	}
	raw, err := json.Marshal(stash)
	if err != nil {
		return RestoreSummary{}, model.Fail(model.Corrupt)
	}
	st.OIDC[restoreStashKey] = raw
	st.BootstrapHash = in.BootstrapHash
	st.BearerHashKey, st.BearerHashKeyVersion = in.SealedBearerKey, 1
	st.Audits = append(st.Audits, model.ControlAudit{ID: model.NewID(), Principal: st.Installation, Action: "restore.quarantine", Reason: "disaster restore: every pre-restore credential, session, token, source and sender is inactive", Time: in.At.UnixNano(), Targets: []model.ID{in.Backup, in.Generation}, Outcome: model.AuditAllowed})
	return sum, nil
}

// RestorePending reports how many stashed items still await reconciliation.
func RestorePending(st model.ControlState) int {
	raw, ok := st.OIDC[restoreStashKey]
	if !ok {
		return 0
	}
	var stash restoreStash
	if json.Unmarshal(raw, &stash) != nil {
		return 0
	}
	n := len(stash.Users) + len(stash.Sources)
	for _, o := range stash.Orgs {
		n += len(o.Members) + len(o.Admins) + len(o.Grants) + len(o.Teams) + len(o.Integrations)
		for _, r := range o.Readers {
			n += len(r)
		}
	}
	return n
}

// ReconcileKind closes the set of things an administrator can reauthorize.
type ReconcileKind string

const (
	ReconcileAccount     ReconcileKind = "account"     // User
	ReconcileOrgAdmin    ReconcileKind = "org_admin"   // Org, User
	ReconcileMembership  ReconcileKind = "membership"  // Org, User
	ReconcileGrant       ReconcileKind = "grant"       // Org, User, Project
	ReconcileTeam        ReconcileKind = "team"        // Org, ID
	ReconcileIntegration ReconcileKind = "integration" // Org, Key ("sso:<id>" or "destination:<id>")
	ReconcileReader      ReconcileKind = "reader"      // Org, ID (source policy), User
	ReconcileSource      ReconcileKind = "source"      // Source: reissues a NEW credential
)

// Reconciliation names exactly one stashed item.
type Reconciliation struct {
	Kind    ReconcileKind
	Org     model.ID
	User    model.ID
	Project model.ID
	Source  model.ID
	ID      model.ID
	Key     string
	Reason  string
}

// Reconciled is the result of one reconciliation. Credential is set only for a
// source: the old secret is never revived, a new one is returned exactly once.
type Reconciled struct {
	Kind       ReconcileKind `json:"kind"`
	Audit      model.ID      `json:"audit"`
	Credential string        `json:"credential,omitempty"`
}

// Reconcile reinstates one stashed item as of the backup, after fresh
// authentication by an instance admin who is not itself a restored account.
// The audit record is committed in the same transaction as the change.
func (s *Service) Reconcile(ctx context.Context, c Credential, r Reconciliation) (Reconciled, error) {
	if c.service != s || c.machine || !c.Fresh() || r.Reason == "" || len(r.Reason) > 512 {
		return Reconciled{}, model.Fail(model.Forbidden)
	}
	if _, err := s.Authenticate(ctx, c.token); err != nil {
		return Reconciled{}, err
	}
	out := Reconciled{Kind: r.Kind, Audit: model.NewID()}
	var raw string
	if r.Kind == ReconcileSource {
		raw = randomToken()
	}
	err := s.store.Update(ctx, func(st *model.ControlState) error {
		if err := s.validateCredentialState(*st, c); err != nil {
			return err
		}
		if !st.Users[c.user.String()].Admin {
			return model.Fail(model.Forbidden)
		}
		stashRaw, ok := st.OIDC[restoreStashKey]
		var stash restoreStash
		if !ok || json.Unmarshal(stashRaw, &stash) != nil {
			return model.Fail(model.NotFound)
		}
		for _, id := range stash.Users {
			if id == c.user {
				return model.Fail(model.Forbidden) // a restored account cannot vouch for restored accounts
			}
		}
		targets, err := s.reconcileOne(st, &stash, r, raw)
		if err != nil {
			return err
		}
		if raw != "" {
			out.Credential = raw
		}
		encoded, err := json.Marshal(stash)
		if err != nil {
			return model.Fail(model.Corrupt)
		}
		st.OIDC[restoreStashKey] = encoded
		org := ""
		if r.Org != (model.ID{}) {
			org = r.Org.String()
		}
		st.Audits = append(st.Audits, model.ControlAudit{ID: out.Audit, Principal: c.user, Action: "restore.reconcile." + string(r.Kind), Reason: r.Reason, Time: s.now().UnixNano(), Org: org, PolicyEpoch: st.Orgs[org].Epoch, Targets: targets, RequestID: model.RequestCorrelationID(ctx, model.ID{}), Outcome: model.AuditAllowed})
		return nil
	})
	if err != nil {
		return Reconciled{}, err
	}
	return out, nil
}

func removeID(ids []model.ID, id model.ID) ([]model.ID, bool) {
	for i, v := range ids {
		if v == id {
			return append(ids[:i:i], ids[i+1:]...), true
		}
	}
	return ids, false
}

func (s *Service) reconcileOne(st *model.ControlState, stash *restoreStash, r Reconciliation, rawCredential string) ([]model.ID, error) {
	if r.Kind == ReconcileAccount {
		rest, ok := removeID(stash.Users, r.User)
		u, exists := st.Users[r.User.String()]
		if !ok || !exists {
			return nil, model.Fail(model.NotFound)
		}
		for _, other := range st.Users {
			if other.ID != u.ID && !other.Disabled && other.Email == u.Email {
				return nil, model.Fail(model.Conflict) // two enabled accounts must never share a login
			}
		}
		stash.Users = rest
		u.Disabled = false
		st.Users[r.User.String()] = u
		return []model.ID{r.User}, nil
	}
	if r.Kind == ReconcileSource {
		rest, ok := removeID(stash.Sources, r.Source)
		src, exists := st.Sources[r.Source.String()]
		if !ok || !exists {
			return nil, model.Fail(model.NotFound)
		}
		digest, err := s.BearerDigest(SourceBearer, rawCredential)
		if err != nil {
			return nil, err
		}
		stash.Sources = rest
		src.Revoked = false
		src.CredentialID = model.NewID()
		st.Sources[r.Source.String()] = src
		st.SourceCredentials[digest] = src.ID.String()
		return []model.ID{r.Source}, nil
	}
	q, ok := stash.Orgs[r.Org.String()]
	o, exists := st.Orgs[r.Org.String()]
	if !ok || !exists {
		return nil, model.Fail(model.NotFound)
	}
	activeUser := func(id model.ID) bool {
		u, ok := st.Users[id.String()]
		return ok && !u.Disabled
	}
	var targets []model.ID
	switch r.Kind {
	case ReconcileOrgAdmin:
		v, ok := q.Admins[r.User.String()]
		if !ok || !activeUser(r.User) {
			return nil, model.Fail(model.NotFound)
		}
		delete(q.Admins, r.User.String())
		o.Admins[r.User.String()] = v
		targets = []model.ID{r.Org, r.User}
	case ReconcileMembership:
		v, ok := q.Members[r.User.String()]
		if !ok || !activeUser(r.User) {
			return nil, model.Fail(model.NotFound)
		}
		delete(q.Members, r.User.String())
		o.Members[r.User.String()] = v
		targets = []model.ID{r.Org, r.User}
	case ReconcileGrant:
		key := r.User.String() + ":" + r.Project.String()
		v, ok := q.Grants[key]
		if _, live := o.Projects[r.Project.String()]; !ok || !live || !activeUser(r.User) || !o.Members[r.User.String()] {
			return nil, model.Fail(model.NotFound)
		}
		delete(q.Grants, key)
		o.Grants[key] = v
		targets = []model.ID{r.Org, r.User, r.Project}
	case ReconcileTeam:
		team, ok := q.Teams[r.ID.String()]
		if !ok {
			return nil, model.Fail(model.NotFound)
		}
		delete(q.Teams, r.ID.String())
		o.Teams[r.ID.String()] = team
		if item, ok := q.Integrations["team:"+r.ID.String()]; ok {
			delete(q.Integrations, "team:"+r.ID.String())
			if len(item.Setting) > 0 {
				o.Settings["team:"+r.ID.String()] = item.Setting
			}
		}
		targets = []model.ID{r.Org, r.ID}
	case ReconcileIntegration:
		item, ok := q.Integrations[r.Key]
		if !ok || strings.HasPrefix(r.Key, "team:") {
			return nil, model.Fail(model.NotFound)
		}
		delete(q.Integrations, r.Key)
		if len(item.Setting) > 0 {
			o.Settings[r.Key] = item.Setting
		}
		if item.Secret != "" {
			o.Secrets[r.Key] = item.Secret
		}
		targets = []model.ID{r.Org}
	case ReconcileReader:
		key := "source_policy:" + r.ID.String()
		readers, ok := q.Readers[key]
		rest, found := removeID(readers, r.User)
		raw, have := o.Settings[key]
		if !ok || !found || !have || !activeUser(r.User) {
			return nil, model.Fail(model.NotFound)
		}
		var cfg SourcePolicyConfig
		if json.Unmarshal(raw, &cfg) != nil {
			return nil, model.Fail(model.Corrupt)
		}
		cfg.Readers = append(cfg.Readers, r.User)
		encoded, err := json.Marshal(cfg)
		if err != nil {
			return nil, model.Fail(model.Corrupt)
		}
		o.Settings[key] = encoded
		if len(rest) == 0 {
			delete(q.Readers, key)
		} else {
			q.Readers[key] = rest
		}
		targets = []model.ID{r.Org, r.ID, r.User}
	default:
		return nil, model.Fail(model.Invalid)
	}
	o.Epoch++
	st.Orgs[r.Org.String()] = o
	stash.Orgs[r.Org.String()] = q
	return targets, nil
}

// InstanceScope is the opaque Scope an installation-wide operation (backup)
// requires: an enabled instance admin with fresh authentication and an audit
// record committed before the scope exists. It names no organization or
// project, so no data path accepts it and it cannot read telemetry; only
// RevalidateInstance understands it. It lapses after 15 minutes.
func (s *Service) InstanceScope(ctx context.Context, c Credential, reason string) (Scope, error) {
	if c.service != s || c.machine || !c.Fresh() || reason == "" || len(reason) > 512 {
		return Scope{}, model.Fail(model.Forbidden)
	}
	if _, err := s.Authenticate(ctx, c.token); err != nil {
		return Scope{}, err
	}
	at := s.now()
	out := Scope{service: s, credential: c, action: InstanceAdmin, lease: &scopeLease{}, expiresAt: at.Add(15 * time.Minute)}
	audit := model.ControlAudit{ID: model.NewID(), Principal: c.user, Action: "instance.scope", Reason: reason, Time: at.UnixNano(), RequestID: model.RequestCorrelationID(ctx, model.ID{}), Outcome: model.AuditAllowed}
	err := s.store.Update(ctx, func(st *model.ControlState) error {
		if err := s.validateCredentialState(*st, c); err != nil {
			return err
		}
		if !st.Users[c.user.String()].Admin {
			return model.Fail(model.Forbidden)
		}
		st.Audits = append(st.Audits, audit)
		return nil
	})
	if err != nil {
		return Scope{}, err
	}
	return out, nil
}

// RevalidateInstance re-checks an InstanceScope against current control state.
func (s *Service) RevalidateInstance(ctx context.Context, scope Scope) error {
	if scope.service != s || scope.action != InstanceAdmin || scope.org != (model.ID{}) || len(scope.projects) != 0 || scope.sourceCredential != nil || scope.credential.machine {
		return model.Fail(model.Forbidden)
	}
	if !scope.expiresAt.IsZero() && !s.now().Before(scope.expiresAt) {
		return model.Fail(model.Forbidden)
	}
	if _, err := s.Authenticate(ctx, scope.credential.token); err != nil {
		return err
	}
	return s.store.View(ctx, func(st model.ControlState) error {
		if err := s.validateCredentialState(st, scope.credential); err != nil {
			return err
		}
		if !st.Users[scope.credential.user.String()].Admin {
			return model.Fail(model.Forbidden)
		}
		return nil
	})
}
