// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package gitlab

import (
	"context"
	"crypto/x509"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
)

// Provider is the model.ExternalLink provider name of this integration.
const Provider = "gitlab"

// Result states of an operation. Link states are the model's (linked, unknown,
// refused); not_linked says the entity has no link and none was made.
const (
	StateLinked    = model.ExternalLinked
	StateUnknown   = model.ExternalUnknown
	StateRefused   = model.ExternalRefused
	StateNotLinked = "not_linked"
)

// Closed codes of a refusal made before GitLab is called (nothing is stored).
const (
	CodeNotConnected    = "gitlab_not_connected"
	CodeMappingMissing  = "gitlab_mapping_missing"
	CodeMappingKind     = "gitlab_mapping_kind"
	CodeSourceNotLinked = "gitlab_source_not_linked"
	CodeNoMatch         = "gitlab_no_match"
	CodeNotRecorded     = "gitlab_link_not_recorded"
	CodeTokenInactive   = "gitlab_token_inactive"
)

// Mapping is the GitLab project a Soundpost project creates issues in.
type Mapping struct {
	Project       model.ID
	GitLabProject string
	CreateFrom    []string
	Labels        []string
}

// Connection is the organization's GitLab connection with its plain token. It is
// read for one call and never stored, logged or returned.
type Connection struct {
	BaseURL  string
	Token    string
	Mappings []Mapping
}

func (c Connection) mapping(project model.ID) (Mapping, bool) {
	for _, m := range c.Mappings {
		if m.Project == project {
			return m, true
		}
	}
	return Mapping{}, false
}

// Settings reads the organization's connection; found is false when none is set.
type Settings interface {
	Connection(ctx context.Context, org model.ID) (Connection, bool, error)
}

// Entity is one incident or error issue as the orchestration needs it.
type Entity struct {
	Facts Facts
	// Version is the incident version or issue revision the next write must expect.
	Version  uint64
	External []model.ExternalLink
}

// ErrVersionConflict is what Entities.Apply answers when the entity moved since
// Version.
var ErrVersionConflict = errors.New("gitlab: entity version conflict")

// Entities reads an entity and applies one external-link transition to it under
// the caller's own scope. The implementation owns authorization, the version
// compare-and-set, the audit and the durable write.
type Entities interface {
	Read(ctx context.Context, scope auth.Scope, kind string, project, id model.ID) (Entity, error)
	Apply(ctx context.Context, scope auth.Scope, kind string, project, id model.ID, expected uint64, op model.ExternalOp) (Entity, error)
}

// Options configure a Service.
type Options struct {
	Settings Settings
	Entities Entities
	// Origin is the node's public https origin; empty leaves links out.
	Origin  string
	Egress  Egress
	RootCAs *x509.CertPool
	// Timeout bounds one GitLab call (10 seconds when zero).
	Timeout time.Duration
	// Now is the clock (the system clock when nil).
	Now func() time.Time
}

// Service creates and links GitLab issues for incidents and error issues.
type Service struct {
	o       Options
	mu      sync.Mutex
	done    map[replayKey]replayEntry
	flights map[replayKey]*flight
}

// New builds a service.
func New(o Options) (*Service, error) {
	if o.Settings == nil || o.Entities == nil {
		return nil, errors.New("gitlab: settings and entities are required")
	}
	if err := o.Egress.Validate(); err != nil {
		return nil, err
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Service{o: o, done: map[replayKey]replayEntry{}, flights: map[replayKey]*flight{}}, nil
}

const (
	leaseFor       = 2 * time.Minute
	maxCASAttempts = 5
	endTimeout     = 15 * time.Second
	replayTTL      = time.Hour
	maxReplays     = 512
)

// Target names one entity.
type Target struct {
	Org     model.ID
	Project model.ID
	Kind    string
	ID      model.ID
}

func (t Target) valid() bool {
	return t.Org != (model.ID{}) && t.Project != (model.ID{}) && t.ID != (model.ID{}) && (t.Kind == KindIncident || t.Kind == KindIssue)
}

// CreateRequest is one create. Title, Description and Labels override the defaults
// when set (Labels non-nil, even empty, replaces the mapping's labels).
type CreateRequest struct {
	Target
	CommandID   model.ID
	Title       string
	Description string
	Labels      []string
}

// Result is the outcome of an operation.
type Result struct {
	State         string
	Created       bool
	Code          string
	GitLabProject string
	URL           string
	IID           uint64
}

// Existing is a link already stored on the entity or on an entity it is linked to.
type Existing struct {
	State         string
	GitLabProject string
	URL           string
	IID           uint64
	Code          string
	// From names the other entity the link is stored on; nil for the entity itself.
	From *Ref
}

// Preview is what a create would send.
type Preview struct {
	// Available is false when no create is possible; Reason says why.
	Available     bool
	Reason        string
	GitLabProject string
	Title         string
	Description   string
	Labels        []string
	Existing      *Existing
}

func inProgress() error {
	f := model.Fail(model.Conflict)
	f.SafeDetail = "in_progress"
	return f
}

func detail(err error) string {
	var f *model.Fault
	if errors.As(err, &f) {
		return f.SafeDetail
	}
	return ""
}

func (s *Service) now() model.UnixNano { return model.UnixNano(s.o.Now().UnixNano()) }

func gitlabLink(e Entity) (model.ExternalLink, bool) {
	for _, l := range e.External {
		if l.Provider == Provider {
			return l, true
		}
	}
	return model.ExternalLink{}, false
}

func linkedResult(l model.ExternalLink, created bool) Result {
	return Result{State: StateLinked, Created: created, GitLabProject: l.Project, URL: l.URL, IID: uint64(l.IID)}
}

func (s *Service) client(conn Connection) (*Client, *Error) {
	c, err := NewClient(Config{BaseURL: conn.BaseURL, Token: conn.Token, Egress: s.o.Egress, RootCAs: s.o.RootCAs, Timeout: s.o.Timeout})
	if err == nil {
		return c, nil
	}
	if IsEgressBlocked(err) {
		return nil, refused(CodeEgress)
	}
	return nil, refused(CodeInvalid)
}

// ValidBase validates a base URL under the node's egress policy.
func (s *Service) ValidBase(raw string) (base, host string, err error) {
	return ValidBaseURL(raw, s.o.Egress)
}

// ---------------------------------------------------------------- replay

type replayKey struct {
	principal model.ID
	command   model.ID
	target    Target
}

type replayEntry struct {
	res Result
	at  time.Time
}

type flight struct {
	done chan struct{}
	res  Result
	err  error
}

// once runs fn for one (principal, command, entity) at a time and remembers its
// answer: a retry of a finished command returns the first result, a retry that
// arrives while the first runs waits for it.
func (s *Service) once(ctx context.Context, key replayKey, fn func() (Result, error)) (Result, error) {
	s.mu.Lock()
	if e, ok := s.done[key]; ok && s.o.Now().Sub(e.at) < replayTTL {
		s.mu.Unlock()
		return e.res, nil
	}
	if f, ok := s.flights[key]; ok {
		s.mu.Unlock()
		select {
		case <-f.done:
			return f.res, f.err
		case <-ctx.Done():
			return Result{}, ctx.Err()
		}
	}
	f := &flight{done: make(chan struct{})}
	s.flights[key] = f
	s.mu.Unlock()

	f.res, f.err = fn()

	s.mu.Lock()
	delete(s.flights, key)
	if f.err == nil {
		if len(s.done) >= maxReplays {
			now := s.o.Now()
			for k, e := range s.done {
				if now.Sub(e.at) >= replayTTL {
					delete(s.done, k)
				}
			}
			for k := range s.done {
				if len(s.done) < maxReplays {
					break
				}
				delete(s.done, k)
			}
		}
		s.done[key] = replayEntry{res: f.res, at: s.o.Now()}
	}
	s.mu.Unlock()
	close(f.done)
	return f.res, f.err
}

// ---------------------------------------------------------------- create

// Create creates the GitLab issue of an entity, once. scope is the caller's own
// write scope for the entity's project. Outcomes: linked (created or already
// linked), unknown (the request may have reached GitLab), refused (closed code);
// a create that another request holds is a 409 in_progress fault.
func (s *Service) Create(ctx context.Context, scope auth.Scope, req CreateRequest) (Result, error) {
	if !req.valid() || req.CommandID == (model.ID{}) || req.Title != "" && !ValidTitle(req.Title) || req.Description != "" && !ValidDescription(req.Description) ||
		req.Labels != nil && !ValidLabels(req.Labels) {
		return Result{}, invalidFault("gitlab_request_invalid")
	}
	return s.once(ctx, replayKey{scope.PrincipalID(), req.CommandID, req.Target}, func() (Result, error) { return s.create(ctx, scope, req) })
}

func (r CreateRequest) valid() bool { return r.Target.valid() }

func invalidFault(d string) error {
	f := model.Fail(model.Invalid)
	f.SafeDetail = d
	return f
}

// setup is the connection and mapping of a target, or the typed refusal.
func (s *Service) setup(ctx context.Context, t Target, needKind bool) (Connection, Mapping, string, error) {
	conn, ok, err := s.o.Settings.Connection(ctx, t.Org)
	if err != nil {
		return Connection{}, Mapping{}, "", err
	}
	if !ok {
		return Connection{}, Mapping{}, CodeNotConnected, nil
	}
	m, ok := conn.mapping(t.Project)
	if !ok {
		return Connection{}, Mapping{}, CodeMappingMissing, nil
	}
	if needKind && !slices.Contains(m.CreateFrom, t.Kind) {
		return Connection{}, Mapping{}, CodeMappingKind, nil
	}
	return conn, m, "", nil
}

func (s *Service) create(ctx context.Context, scope auth.Scope, req CreateRequest) (Result, error) {
	t := req.Target
	ent, err := s.o.Entities.Read(ctx, scope, t.Kind, t.Project, t.ID)
	if err != nil {
		return Result{}, err
	}
	if l, ok := gitlabLink(ent); ok && l.State == model.ExternalLinked {
		return linkedResult(l, false), nil
	}
	conn, m, code, err := s.setup(ctx, t, true)
	if err != nil {
		return Result{}, err
	}
	if code != "" {
		return Result{State: StateRefused, Code: code}, nil
	}
	client, cerr := s.client(conn)
	if cerr != nil {
		return Result{State: StateRefused, Code: cerr.Code}, nil
	}
	defer client.Close()
	marker := model.ExternalMarker(t.Org, t.Kind, t.ID)
	ent, done, err := s.begin(ctx, scope, t, ent, marker, m.GitLabProject)
	if err != nil || done != nil {
		if done != nil {
			return *done, nil
		}
		return Result{}, err
	}

	issue, found, cerr := client.FindByMarker(ctx, m.GitLabProject, marker)
	created := false
	if cerr == nil && !found {
		title := req.Title
		if title == "" {
			title = DefaultTitle(t.Kind, t.ID)
		}
		description := req.Description
		if description == "" {
			link, _ := Link(s.o.Origin, t.Org, t.Kind, t.Project, t.ID)
			description = Description(ent.Facts, link)
		}
		labels := m.Labels
		if req.Labels != nil {
			labels = req.Labels
		}
		issue, cerr = client.CreateIssue(ctx, m.GitLabProject, title, WithMarker(description, marker), labels)
		created = cerr == nil
	}
	if cerr != nil {
		state := StateRefused
		if cerr.Unknown {
			state = StateUnknown
		}
		return s.finish(ctx, scope, t, ent, model.ExternalOp{Provider: Provider, Kind: model.ExternalEnd, Marker: marker, Result: state, Code: cerr.Code}, Result{State: state, Code: cerr.Code})
	}
	op := model.ExternalOp{Provider: Provider, Kind: model.ExternalEnd, Marker: marker, Project: m.GitLabProject, Result: model.ExternalLinked, IID: model.Uint64(issue.IID), URL: issue.URL}
	return s.finish(ctx, scope, t, ent, op, Result{State: StateLinked, Created: created, GitLabProject: m.GitLabProject, URL: issue.URL, IID: issue.IID})
}

// begin takes the durable creating lease. A non-nil done is a final answer (the
// entity turned out to be linked already); the lease being held by another request
// is a 409 in_progress fault.
func (s *Service) begin(ctx context.Context, scope auth.Scope, t Target, ent Entity, marker, project string) (Entity, *Result, error) {
	for attempt := range maxCASAttempts {
		op := model.ExternalOp{Provider: Provider, Kind: model.ExternalBegin, Marker: marker, Project: project, Until: s.now() + model.UnixNano(leaseFor)}
		next, err := s.o.Entities.Apply(ctx, scope, t.Kind, t.Project, t.ID, ent.Version, op)
		switch {
		case err == nil:
			return next, nil, nil
		case detail(err) == "external_in_progress":
			return ent, nil, inProgress()
		case detail(err) == "external_already_linked" || errors.Is(err, ErrVersionConflict):
			if attempt == maxCASAttempts-1 && errors.Is(err, ErrVersionConflict) {
				return ent, nil, model.Fail(model.Conflict)
			}
			cur, rerr := s.o.Entities.Read(ctx, scope, t.Kind, t.Project, t.ID)
			if rerr != nil {
				return ent, nil, rerr
			}
			if l, ok := gitlabLink(cur); ok && l.State == model.ExternalLinked {
				r := linkedResult(l, false)
				return cur, &r, nil
			}
			ent = cur
		default:
			return ent, nil, err
		}
	}
	return ent, nil, model.Fail(model.Conflict)
}

// finish records the end of a create. It runs on a context the caller's
// cancellation cannot stop, because the outcome of a request that may have reached
// GitLab must reach the entity. A record that cannot be made leaves the lease to
// expire; the next create or recheck finds the issue by its marker.
func (s *Service) finish(ctx context.Context, scope auth.Scope, t Target, ent Entity, op model.ExternalOp, answer Result) (Result, error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), endTimeout)
	defer cancel()
	for range maxCASAttempts {
		_, err := s.o.Entities.Apply(ctx, scope, t.Kind, t.Project, t.ID, ent.Version, op)
		if err == nil {
			return answer, nil
		}
		cur, rerr := s.o.Entities.Read(ctx, scope, t.Kind, t.Project, t.ID)
		if rerr != nil {
			break
		}
		if !errors.Is(err, ErrVersionConflict) {
			// The link left "creating" by itself (a recheck adopted the issue): what is
			// stored is the truth.
			if l, ok := gitlabLink(cur); ok && l.State == model.ExternalLinked {
				return linkedResult(l, answer.Created && l.IID == model.Uint64(answer.IID)), nil
			}
			break
		}
		ent = cur
	}
	return Result{State: StateUnknown, Code: CodeNotRecorded, GitLabProject: answer.GitLabProject, URL: answer.URL, IID: answer.IID}, nil
}

// ---------------------------------------------------------------- recheck

// Recheck looks the entity's issue up by its marker and links it if found. It
// never creates anything.
func (s *Service) Recheck(ctx context.Context, scope auth.Scope, t Target) (Result, error) {
	if !t.valid() {
		return Result{}, invalidFault("gitlab_request_invalid")
	}
	ent, err := s.o.Entities.Read(ctx, scope, t.Kind, t.Project, t.ID)
	if err != nil {
		return Result{}, err
	}
	link, has := gitlabLink(ent)
	if has && link.State == model.ExternalLinked {
		return linkedResult(link, false), nil
	}
	if has && link.State == model.ExternalCreating && link.Until > s.now() {
		return Result{}, inProgress()
	}
	conn, m, code, err := s.setup(ctx, t, false)
	if err != nil {
		return Result{}, err
	}
	if code != "" {
		return Result{State: stateOf(link, has), Code: code}, nil
	}
	project := m.GitLabProject
	if has && link.Project != "" {
		project = link.Project
	}
	client, cerr := s.client(conn)
	if cerr != nil {
		return Result{State: stateOf(link, has), Code: cerr.Code}, nil
	}
	defer client.Close()
	marker := model.ExternalMarker(t.Org, t.Kind, t.ID)
	issue, found, cerr := client.FindByMarker(ctx, project, marker)
	if cerr != nil {
		return Result{State: stateOf(link, has), Code: cerr.Code}, nil
	}
	if !found {
		return Result{State: stateOf(link, has), Code: CodeNoMatch}, nil
	}
	op := model.ExternalOp{Provider: Provider, Kind: model.ExternalAdopt, Marker: marker, Project: project, Result: model.ExternalLinked, IID: model.Uint64(issue.IID), URL: issue.URL}
	return s.adopt(ctx, scope, t, ent, op)
}

func stateOf(l model.ExternalLink, has bool) string {
	switch {
	case !has:
		return StateNotLinked
	case l.State == model.ExternalCreating:
		return StateUnknown
	}
	return l.State
}

// adopt applies an adopt transition with the version retry; an entity that turns
// out to be linked already answers with its stored link.
func (s *Service) adopt(ctx context.Context, scope auth.Scope, t Target, ent Entity, op model.ExternalOp) (Result, error) {
	for range maxCASAttempts {
		next, err := s.o.Entities.Apply(ctx, scope, t.Kind, t.Project, t.ID, ent.Version, op)
		if err == nil {
			if l, ok := gitlabLink(next); ok && l.State == model.ExternalLinked {
				return linkedResult(l, false), nil
			}
			return Result{State: StateLinked, GitLabProject: op.Project, URL: op.URL, IID: uint64(op.IID)}, nil
		}
		if detail(err) == "external_in_progress" {
			return Result{}, inProgress()
		}
		if !errors.Is(err, ErrVersionConflict) && detail(err) != "external_already_linked" {
			return Result{}, err
		}
		cur, rerr := s.o.Entities.Read(ctx, scope, t.Kind, t.Project, t.ID)
		if rerr != nil {
			return Result{}, rerr
		}
		if l, ok := gitlabLink(cur); ok && l.State == model.ExternalLinked {
			return linkedResult(l, false), nil
		}
		ent = cur
	}
	return Result{}, model.Fail(model.Conflict)
}

// ---------------------------------------------------------------- link_from

// LinkFrom links t to the GitLab issue stored on from. scope is the caller's write
// scope for t, fromScope the caller's scope for from; both entities must be in the
// same organization.
func (s *Service) LinkFrom(ctx context.Context, scope, fromScope auth.Scope, t, from Target) (Result, error) {
	if !t.valid() || !from.valid() || t.Org != from.Org || t == from {
		return Result{}, invalidFault("gitlab_request_invalid")
	}
	ent, err := s.o.Entities.Read(ctx, scope, t.Kind, t.Project, t.ID)
	if err != nil {
		return Result{}, err
	}
	if l, ok := gitlabLink(ent); ok && l.State == model.ExternalLinked {
		return linkedResult(l, false), nil
	}
	src, err := s.o.Entities.Read(ctx, fromScope, from.Kind, from.Project, from.ID)
	if err != nil {
		return Result{}, err
	}
	l, ok := gitlabLink(src)
	if !ok || l.State != model.ExternalLinked {
		return Result{State: StateRefused, Code: CodeSourceNotLinked}, nil
	}
	op := model.ExternalOp{Provider: Provider, Kind: model.ExternalAdopt, Marker: model.ExternalMarker(t.Org, t.Kind, t.ID), Project: l.Project, Result: model.ExternalLinked, IID: l.IID, URL: l.URL}
	return s.adopt(ctx, scope, t, ent, op)
}

// ---------------------------------------------------------------- preview

// Preview states what a create would send, and the link that already exists.
func (s *Service) Preview(ctx context.Context, scope auth.Scope, t Target) (Preview, error) {
	if !t.valid() {
		return Preview{}, invalidFault("gitlab_request_invalid")
	}
	ent, err := s.o.Entities.Read(ctx, scope, t.Kind, t.Project, t.ID)
	if err != nil {
		return Preview{}, err
	}
	p := Preview{Title: DefaultTitle(t.Kind, t.ID), Labels: []string{}}
	link, _ := Link(s.o.Origin, t.Org, t.Kind, t.Project, t.ID)
	p.Description = Description(ent.Facts, link)
	if l, ok := gitlabLink(ent); ok {
		p.Existing = existingOf(l, nil)
	} else if t.Kind == KindIncident {
		p.Existing = s.existingFromIssues(ctx, scope, t, ent)
	}
	_, m, code, err := s.setup(ctx, t, true)
	if err != nil {
		return Preview{}, err
	}
	if code != "" {
		p.Reason = code
		return p, nil
	}
	p.Available, p.GitLabProject = true, m.GitLabProject
	p.Labels = append([]string{}, m.Labels...)
	return p, nil
}

func existingOf(l model.ExternalLink, from *Ref) *Existing {
	e := &Existing{State: l.State, Code: l.Code, From: from}
	if l.State == model.ExternalLinked {
		e.GitLabProject, e.URL, e.IID = l.Project, l.URL, uint64(l.IID)
	}
	return e
}

const maxPreviewReads = 8

// existingFromIssues finds a link stored on an error issue the incident is linked
// to; an issue the caller cannot read is skipped.
func (s *Service) existingFromIssues(ctx context.Context, scope auth.Scope, t Target, ent Entity) *Existing {
	reads := 0
	for _, r := range ent.Facts.Related {
		if r.Kind != KindIssue {
			continue
		}
		if reads++; reads > maxPreviewReads {
			break
		}
		other, err := s.o.Entities.Read(ctx, scope, KindIssue, t.Project, r.ID)
		if err != nil {
			continue
		}
		if l, ok := gitlabLink(other); ok && l.State == model.ExternalLinked {
			ref := r
			return existingOf(l, &ref)
		}
	}
	return nil
}

// ---------------------------------------------------------------- token check

// TokenResult is the answer of a connection test.
type TokenResult struct {
	OK        bool
	Scopes    []string
	ExpiresAt string
	Code      string
}

// CheckToken calls GET /personal_access_tokens/self with the organization's token.
func (s *Service) CheckToken(ctx context.Context, org model.ID) (TokenResult, error) {
	conn, ok, err := s.o.Settings.Connection(ctx, org)
	if err != nil {
		return TokenResult{}, err
	}
	if !ok {
		return TokenResult{Code: CodeNotConnected}, nil
	}
	client, cerr := s.client(conn)
	if cerr != nil {
		return TokenResult{Code: cerr.Code}, nil
	}
	defer client.Close()
	info, cerr := client.Token(ctx)
	if cerr != nil {
		return TokenResult{Code: cerr.Code}, nil
	}
	if !info.Active {
		return TokenResult{Scopes: info.Scopes, ExpiresAt: info.ExpiresAt, Code: CodeTokenInactive}, nil
	}
	return TokenResult{OK: true, Scopes: info.Scopes, ExpiresAt: info.ExpiresAt}, nil
}
