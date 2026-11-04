// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"sort"
	"soundpost/internal/model"
	"sync"
	"time"
)

// DeleteGenerations reports the monotonic deletion generation covering an
// org's projects. Any deletion/retirement that can remove readable data MUST
// advance it before the operation reports fencing complete; a cached result,
// cursor, replay position or export bound to an older generation is dead.
type DeleteGenerations interface {
	DeleteGeneration(ctx context.Context, org model.ID, projects []model.ID) (uint64, error)
}

// SourceLifecycleGenerations derives the generation from authoritative control
// state that exists today: revoked or retired sources. It is monotonic because
// those flags never clear. A retention service that owns historical-range and
// entity deletion supplies its own DeleteGenerations with the same contract.
func (s *Service) SourceLifecycleGenerations() DeleteGenerations { return sourceLifecycle{s} }

type sourceLifecycle struct{ service *Service }

func (g sourceLifecycle) DeleteGeneration(ctx context.Context, org model.ID, projects []model.ID) (uint64, error) {
	var out uint64
	err := g.service.store.View(ctx, func(st model.ControlState) error {
		if _, ok := st.Orgs[org.String()]; !ok {
			return model.Fail(model.NotFound)
		}
		for _, src := range st.Sources {
			if src.Org == org && (src.Revoked || src.Retired) {
				out++
			}
		}
		return nil
	})
	return out, err
}

const (
	cacheValueLimit = 1 << 20
	ticketMaxTTL    = 15 * time.Minute
)

// Cache keys every entry by (org, visibility fingerprint, policy epoch, delete
// generation, profile, query, time params). Scope revalidation always precedes
// any lookup, so a caller who cannot be authorized never reaches an entry, and
// a positive or negative entry is only ever reachable with the identical
// effective visibility (principal + every project/action/named-source grant).
type Cache struct {
	service *Service
	deletes DeleteGenerations
	secret  [32]byte
	limit   int
	ttl     time.Duration
	mu      sync.Mutex
	entries map[[32]byte]cacheEntry
	order   [][32]byte
}
type cacheEntry struct {
	value    []byte
	negative bool
	expires  time.Time
}

// CacheFill is the opaque proof returned by a miss; Store only accepts a value
// computed under the same authorization state the miss observed.
type CacheFill struct {
	key         [32]byte
	fingerprint string
	epoch       uint64
	deletion    uint64
}
type CacheResult struct {
	Hit      bool
	Negative bool
	Value    []byte
	Fill     CacheFill
}

func NewCache(service *Service, deletes DeleteGenerations, limit int, ttl time.Duration) (*Cache, error) {
	if service == nil || deletes == nil || limit < 1 || limit > 1<<16 || ttl <= 0 || ttl > 5*time.Minute {
		return nil, model.Fail(model.Invalid)
	}
	c := &Cache{service: service, deletes: deletes, limit: limit, ttl: ttl, entries: map[[32]byte]cacheEntry{}}
	if _, err := rand.Read(c.secret[:]); err != nil {
		return nil, model.Fail(model.Unavailable)
	}
	return c, nil
}

type cacheBinding struct {
	fingerprint string
	epoch       uint64
	deletion    uint64
}

// bind revalidates the scope (authoritative ReadIndex-backed read) and only
// then consults the deletion generation. No cache or index is touched before.
func (c *Cache) bind(ctx context.Context, scope Scope) (cacheBinding, error) {
	if scope.service != c.service || scope.sourceCredential != nil || scope.fingerprint == "" {
		return cacheBinding{}, model.Fail(model.NotFound)
	}
	if err := c.service.Revalidate(ctx, scope); err != nil {
		return cacheBinding{}, err
	}
	gen, err := c.deletes.DeleteGeneration(ctx, scope.org, scope.projects)
	if err != nil {
		return cacheBinding{}, err
	}
	return cacheBinding{scope.fingerprint, scope.epoch, gen}, nil
}
func (c *Cache) keyFor(scope Scope, b cacheBinding, profile, query, params string) [32]byte {
	h := hmac.New(sha256.New, c.secret[:])
	put := func(s string) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(s)))
		h.Write(n[:])
		h.Write([]byte(s))
	}
	projects := make([]string, len(scope.projects))
	for i, p := range scope.projects {
		projects[i] = p.String()
	}
	sort.Strings(projects)
	put(scope.org.String())
	put(b.fingerprint)
	put(string(scope.action))
	put(joinSorted(projects))
	put(joinSorted(idStrings(scope.sources)))
	var n [16]byte
	binary.BigEndian.PutUint64(n[:8], b.epoch)
	binary.BigEndian.PutUint64(n[8:], b.deletion)
	h.Write(n[:])
	put(profile)
	put(query)
	put(params)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}
func idStrings(ids []model.ID) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = id.String()
	}
	return out
}

func (c *Cache) Lookup(ctx context.Context, scope Scope, profile, query, params string) (CacheResult, error) {
	b, err := c.bind(ctx, scope)
	if err != nil {
		return CacheResult{}, err
	}
	key := c.keyFor(scope, b, profile, query, params)
	out := CacheResult{Fill: CacheFill{key: key, fingerprint: b.fingerprint, epoch: b.epoch, deletion: b.deletion}}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok || !c.service.now().Before(e.expires) {
		if ok {
			delete(c.entries, key)
		}
		return out, nil
	}
	out.Hit, out.Negative = true, e.negative
	out.Value = append([]byte(nil), e.value...)
	return out, nil
}

// Store records a computed result (or a negative result) only if the caller's
// authorization state is still exactly the state its miss observed.
func (c *Cache) Store(ctx context.Context, scope Scope, fill CacheFill, value []byte, negative bool) error {
	if len(value) > cacheValueLimit || negative && len(value) != 0 {
		return model.Fail(model.TooLarge)
	}
	b, err := c.bind(ctx, scope)
	if err != nil {
		return err
	}
	if b.fingerprint != fill.fingerprint || b.epoch != fill.epoch || b.deletion != fill.deletion {
		return model.Fail(model.Stale)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.entries[fill.key]; !exists {
		c.order = append(c.order, fill.key)
	}
	c.entries[fill.key] = cacheEntry{value: append([]byte(nil), value...), negative: negative, expires: c.service.now().Add(c.ttl)}
	for len(c.entries) > c.limit && len(c.order) > 0 {
		delete(c.entries, c.order[0])
		c.order = c.order[1:]
	}
	return nil
}

type ticketBody struct {
	Kind        string   `json:"k"`
	Org         model.ID `json:"o"`
	Fingerprint string   `json:"f"`
	Action      string   `json:"a"`
	Projects    []string `json:"p"`
	Sources     []string `json:"s"`
	Epoch       uint64   `json:"e"`
	Deletion    uint64   `json:"d"`
	Subject     model.ID `json:"i"`
	State       []byte   `json:"t"`
	Expires     int64    `json:"x"`
}

// IssueTicket mints a short-lived opaque token (pagination cursor, live-replay
// position, export grant) bound to the issuing scope's visibility fingerprint,
// policy epoch and delete generation. state is caller-defined position data.
func (c *Cache) IssueTicket(ctx context.Context, scope Scope, kind string, subject model.ID, state []byte, ttl time.Duration) (string, error) {
	if kind == "" || len(kind) > 32 || len(state) > 8192 || ttl <= 0 || ttl > ticketMaxTTL {
		return "", model.Fail(model.Invalid)
	}
	b, err := c.bind(ctx, scope)
	if err != nil {
		return "", err
	}
	projects := idStrings(scope.projects)
	sort.Strings(projects)
	sources := idStrings(scope.sources)
	sort.Strings(sources)
	raw, err := json.Marshal(ticketBody{Kind: kind, Org: scope.org, Fingerprint: b.fingerprint, Action: string(scope.action), Projects: projects, Sources: sources, Epoch: b.epoch, Deletion: b.deletion, Subject: subject, State: state, Expires: c.service.now().Add(ttl).Unix()})
	if err != nil {
		return "", model.Fail(model.Unavailable)
	}
	h := hmac.New(sha256.New, c.secret[:])
	h.Write(raw)
	return base64.RawURLEncoding.EncodeToString(append(raw, h.Sum(nil)...)), nil
}

// OpenTicket validates the presenter's scope first, then the signature and
// every binding. Any mismatch (other principal, other named-source grants,
// older epoch, deleted since, expired, forged) is the same NotFound.
func (c *Cache) OpenTicket(ctx context.Context, scope Scope, kind, token string) (model.ID, []byte, error) {
	b, err := c.bind(ctx, scope)
	if err != nil {
		return model.ID{}, nil, err
	}
	denied := model.Fail(model.NotFound)
	raw, e := base64.RawURLEncoding.DecodeString(token)
	if e != nil || len(token) > 16384 || len(raw) < 33 {
		return model.ID{}, nil, denied
	}
	body, sig := raw[:len(raw)-32], raw[len(raw)-32:]
	h := hmac.New(sha256.New, c.secret[:])
	h.Write(body)
	if !hmac.Equal(sig, h.Sum(nil)) {
		return model.ID{}, nil, denied
	}
	var t ticketBody
	if json.Unmarshal(body, &t) != nil {
		return model.ID{}, nil, denied
	}
	projects := idStrings(scope.projects)
	sort.Strings(projects)
	sources := idStrings(scope.sources)
	sort.Strings(sources)
	if t.Kind != kind || t.Org != scope.org || t.Fingerprint != b.fingerprint || t.Action != string(scope.action) || t.Epoch != b.epoch || t.Deletion != b.deletion || t.Expires <= c.service.now().Unix() || joinSorted(t.Projects) != joinSorted(projects) || joinSorted(t.Sources) != joinSorted(sources) {
		return model.ID{}, nil, denied
	}
	return t.Subject, append([]byte(nil), t.State...), nil
}

// CommitElevatedRead durably audits one release of elevated bytes. It is a
// no-op for non-elevated scopes. The caller MUST NOT release the bytes unless
// it returns nil: the audit commits (and the scope is re-validated inside the
// same control transaction) before the response/chunk.
func (s *Service) CommitElevatedRead(ctx context.Context, scope Scope, action string, targets []model.ID) error {
	if scope.service != s || scope.sourceCredential != nil || len(action) == 0 || len(action) > 64 || len(targets) > 64 {
		return model.Fail(model.Forbidden)
	}
	if scope.elevation == (model.ID{}) {
		return nil
	}
	a := model.ControlAudit{ID: model.NewID(), Principal: scope.credential.user, Action: action, Reason: "elevated response released", Time: s.now().UnixNano(), Org: scope.org.String(), PolicyEpoch: scope.epoch, Targets: append([]model.ID{scope.elevation}, targets...), RequestID: model.RequestCorrelationID(ctx, model.ID{}), Outcome: model.AuditAllowed}
	return s.store.Update(ctx, func(st *model.ControlState) error {
		if err := scope.ValidateControlState(*st); err != nil {
			return err
		}
		st.Audits = append(st.Audits, a)
		return nil
	})
}

// VisibleSource is the closed public capability descriptor of one real source.
// It never carries credentials, routing secrets, reader lists or policy text.
type VisibleSource struct {
	ID             model.ID       `json:"id"`
	Project        model.ID       `json:"project"`
	Class          string         `json:"class"`
	Kinds          []model.Kind   `json:"kinds"`
	Replay         bool           `json:"replay"`
	PolicyRevision model.Revision `json:"policy_revision"`
}

// VisibleSources lists only the active sources the scope may actually read:
// structured sources of its projects for telemetry.read, and restricted-raw
// sources only for a raw.read scope whose principal is a named reader.
func (s *Service) VisibleSources(ctx context.Context, scope Scope) ([]VisibleSource, error) {
	if scope.service != s || scope.sourceCredential != nil || scope.action != Read && scope.action != RawRead {
		return nil, model.Fail(model.NotFound)
	}
	if err := s.Revalidate(ctx, scope); err != nil {
		return nil, err
	}
	var out []VisibleSource
	err := s.store.View(ctx, func(st model.ControlState) error {
		if err := scope.ValidateControlState(st); err != nil {
			return err
		}
		o := st.Orgs[scope.org.String()]
		for _, src := range st.Sources {
			if src.Org != scope.org || !scope.AllowsProject(src.Project) || src.Revoked || src.Retired || src.Closing || !src.Policy.Enabled {
				continue
			}
			if src.Policy.Expires != 0 && int64(src.Policy.Expires) <= s.now().UnixNano() {
				continue
			}
			restricted := src.Policy.Class == "restricted_raw"
			if restricted != (scope.action == RawRead) || restricted && scope.elevation != (model.ID{}) {
				continue
			}
			if restricted {
				var cfg SourcePolicyConfig
				if json.Unmarshal(o.Settings["source_policy:"+src.ID.String()], &cfg) != nil || !cfg.Enabled || cfg.ProjectID != src.Project || !hasID(cfg.Readers, scope.credential.user) {
					continue
				}
				if len(scope.sources) != 0 && !hasID(scope.sources, src.ID) {
					continue
				}
			}
			out = append(out, VisibleSource{ID: src.ID, Project: src.Project, Class: src.Policy.Class, Kinds: append([]model.Kind(nil), src.Policy.Kinds...), Replay: src.Policy.Replay, PolicyRevision: src.Policy.Revision})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID.String() < out[j].ID.String() })
	return out, nil
}
