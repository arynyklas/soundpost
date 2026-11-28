// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package exports

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/storage"
	"io"
	"sync"
	"time"
)

const (
	ChunkBytes   = 64 << 10
	MaxBytes     = 8 << 20
	grantTTL     = 10 * time.Minute
	computeLimit = 2 * time.Minute
	ticketKind   = "export"
	// transientChecks is how many consecutive times one authorization check may
	// fail without an answer from the authority before the export gives up.
	transientChecks = 4
	// scanRestarts is how many times a scan that failed for a reason other than
	// authority is started again from its beginning.
	scanRestarts = 2
	// transientBackoff is the first wait between asks of an authority check
	// that got no answer; it doubles each time.
	transientBackoff = 100 * time.Millisecond
)

// Limits bound how many live exports (running, or completed and not yet
// expired) may exist. They are enforced per principal, per organization and
// instance-wide, so one tenant exhausting its own budget never starves another.
// SweepInterval is how often expired payloads are reclaimed when nothing else
// touches the service.
type Limits struct {
	PerPrincipal  int
	PerOrg        int
	Global        int
	SweepInterval time.Duration
}

// DefaultLimits keeps the worst-case resident result set at Global * MaxBytes.
func DefaultLimits() Limits {
	return Limits{PerPrincipal: 4, PerOrg: 8, Global: 32, SweepInterval: 30 * time.Second}
}

type Scanner interface {
	Scan(context.Context, auth.Scope, storage.ScanRequest) (storage.RowIterator, error)
}

// Request is the closed export selector: one project, one signal, a time
// range and, for restricted raw data, the one named source.
type Request struct {
	Project model.ID    `json:"project"`
	Signal  model.Kind  `json:"signal"`
	Source  model.ID    `json:"source,omitempty"`
	Start   model.Int64 `json:"start_ns"`
	End     model.Int64 `json:"end_ns"`
}
type Operation struct {
	ID         model.ID     `json:"id"`
	Kind       string       `json:"kind"`
	Phase      string       `json:"phase"`
	Generation model.Uint64 `json:"generation"`
	Progress   model.Uint64 `json:"progress"`
	Chunks     model.Uint64 `json:"chunks"`
	SafeReason string       `json:"safe_reason,omitempty"`
}
type Grant struct {
	Operation Operation `json:"operation"`
	Ticket    string    `json:"ticket"`
}
type Chunk struct {
	Index uint64
	Last  bool
	Data  []byte
}

type Service struct {
	authority *auth.Service
	cache     *auth.Cache
	deletes   auth.DeleteGenerations
	scanner   Scanner
	limits    Limits
	root      context.Context
	stop      context.CancelFunc
	wg        sync.WaitGroup
	mu        sync.Mutex
	entries   map[[32]byte]*entry
}
type entry struct {
	mu        sync.Mutex
	op        Operation
	project   model.ID
	org       model.ID
	principal model.ID
	epoch     uint64
	deletion  uint64
	expires   time.Time
	chunks    [][]byte
	dropped   bool
}

// New builds the service with DefaultLimits.
func New(authority *auth.Service, cache *auth.Cache, deletes auth.DeleteGenerations, scanner Scanner) (*Service, error) {
	return NewWithLimits(authority, cache, deletes, scanner, DefaultLimits())
}

// NewWithLimits builds the service with explicit per-principal, per-org and
// global budgets (each at least 1, and Global >= PerOrg >= PerPrincipal) and a
// positive sweep interval.
func NewWithLimits(authority *auth.Service, cache *auth.Cache, deletes auth.DeleteGenerations, scanner Scanner, limits Limits) (*Service, error) {
	if authority == nil || cache == nil || deletes == nil || scanner == nil || limits.PerPrincipal < 1 || limits.PerOrg < limits.PerPrincipal || limits.Global < limits.PerOrg || limits.SweepInterval <= 0 {
		return nil, model.Fail(model.Invalid)
	}
	root, stop := context.WithCancel(context.Background())
	s := &Service{authority: authority, cache: cache, deletes: deletes, scanner: scanner, limits: limits, root: root, stop: stop, entries: map[[32]byte]*entry{}}
	s.wg.Add(1)
	go s.sweeper()
	return s, nil
}

// Close stops every computation and the sweeper, then frees every payload.
func (s *Service) Close() {
	s.stop()
	s.wg.Wait()
	s.mu.Lock()
	dead := make([]*entry, 0, len(s.entries))
	for key, e := range s.entries {
		delete(s.entries, key)
		dead = append(dead, e)
	}
	s.mu.Unlock()
	drop(dead)
}

// sweeper reclaims expired payloads even when no operation arrives.
func (s *Service) sweeper() {
	defer s.wg.Done()
	ticker := time.NewTicker(s.limits.SweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.root.Done():
			return
		case <-ticker.C:
			s.mu.Lock()
			dead := s.sweepLocked()
			s.mu.Unlock()
			drop(dead)
		}
	}
}

// sweepLocked unlinks every expired entry (by the authority's clock) and
// returns them; the caller releases their payloads after s.mu is dropped.
func (s *Service) sweepLocked() []*entry {
	now := s.authority.Now()
	var dead []*entry
	for key, e := range s.entries {
		if !now.Before(e.expires) {
			delete(s.entries, key)
			dead = append(dead, e)
		}
	}
	return dead
}

// drop frees the payload of unlinked entries. A computation still running for
// one of them keeps nothing when it finishes.
func drop(dead []*entry) {
	for _, e := range dead {
		e.mu.Lock()
		e.dropped = true
		e.chunks = nil
		e.mu.Unlock()
	}
}

// key is derived from the caller's visibility fingerprint (which includes the
// credential's session), so an operation created under any other
// principal/session/grant set is simply absent.
func (s *Service) key(scope auth.Scope, id model.ID) [32]byte {
	h := sha256.New()
	h.Write([]byte(scope.OrgID().String() + "|" + scope.VisibilityFingerprint() + "|" + id.String()))
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}
func (s *Service) validate(r Request, scope auth.Scope) error {
	if !r.Signal.Valid() || r.End < r.Start || r.Project == (model.ID{}) {
		return model.Fail(model.Invalid)
	}
	if !scope.AllowsProject(r.Project) {
		return model.Fail(model.NotFound)
	}
	switch scope.Permission() {
	case auth.Read:
		if r.Source != (model.ID{}) {
			return model.Fail(model.Invalid)
		}
	case auth.RawRead:
		if r.Source == (model.ID{}) || !scope.AllowsSource(r.Source) {
			return model.Fail(model.NotFound)
		}
	default:
		return model.Fail(model.NotFound)
	}
	return nil
}

// Create authorizes synchronously (scope first), then computes in the
// background. The returned grant is a short-lived ticket bound to the
// caller's visibility fingerprint (principal, session, grants), policy epoch
// and delete generation, and it never outlives the scope's own clock window.
func (s *Service) Create(ctx context.Context, scope auth.Scope, r Request) (Grant, error) {
	if err := s.authority.Revalidate(ctx, scope); err != nil {
		return Grant{}, err
	}
	if err := s.validate(r, scope); err != nil {
		return Grant{}, err
	}
	gen, err := s.deletes.DeleteGeneration(ctx, scope.OrgID(), scope.ProjectIDs())
	if err != nil {
		return Grant{}, err
	}
	id := model.NewID()
	ticket, err := s.cache.IssueTicket(ctx, scope, ticketKind, id, nil, grantTTL)
	if err != nil {
		return Grant{}, err
	}
	expires := s.authority.Now().Add(grantTTL)
	if end := scope.ExpiresAt(); !end.IsZero() && end.Before(expires) {
		expires = end
	}
	e := &entry{op: Operation{ID: id, Kind: "export", Phase: "running", Generation: model.Uint64(gen)}, project: r.Project, org: scope.OrgID(), principal: scope.PrincipalID(), epoch: scope.PolicyEpoch(), deletion: gen, expires: expires}
	s.mu.Lock()
	dead := s.sweepLocked()
	var byPrincipal, byOrg int
	for _, v := range s.entries {
		if v.org == e.org {
			byOrg++
			if v.principal == e.principal {
				byPrincipal++
			}
		}
	}
	if byPrincipal >= s.limits.PerPrincipal || byOrg >= s.limits.PerOrg || len(s.entries) >= s.limits.Global {
		s.mu.Unlock()
		drop(dead)
		fault := model.Fail(model.Quota)
		fault.Retryable = true
		return Grant{}, fault
	}
	s.entries[s.key(scope, id)] = e
	s.wg.Add(1)
	s.mu.Unlock()
	drop(dead)
	go s.run(scope, r, e)
	return Grant{Operation: e.snapshot(), Ticket: ticket}, nil
}
func (e *entry) snapshot() Operation {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.op
}

// finish publishes the outcome. A complete export with no rows still releases
// exactly one empty last chunk, so "complete and empty" is a real download and
// is never confused with a missing operation.
func (e *entry) finish(phase, reason string, chunks [][]byte) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.op.Phase, e.op.SafeReason = phase, reason
	if phase == "complete" && len(chunks) == 0 {
		chunks = [][]byte{{}}
	}
	if e.dropped {
		chunks = nil
	}
	e.chunks = chunks
	e.op.Chunks = model.Uint64(len(chunks))
}

type exportRow struct {
	ID       model.ID       `json:"id"`
	Time     model.Int64    `json:"time_ns"`
	Project  model.ID       `json:"project"`
	Source   model.ID       `json:"source"`
	Resource model.Resource `json:"resource"`
	Payload  model.Payload  `json:"payload"`
}

// denied reports whether err is the authority answering "no": the scope,
// grant, session, organization or project no longer exists for this caller.
// Every other failure of a read (Stale because the read outlived its lease,
// Unavailable because the control group could not answer, a cancelled context)
// is the absence of an answer, never a revocation.
func denied(err error) bool {
	var f *model.Fault
	if !errors.As(err, &f) {
		return false
	}
	switch f.Code {
	case model.NotFound, model.Forbidden, model.Unauthenticated:
		return true
	}
	return false
}

// check asks the authority once whether the original authorization is still
// exactly valid: the scope (credential, grants, organization policy epoch,
// lease) and the delete generation the export was bound to. valid is false
// with a nil err only when the authority said no, or the bound epoch or
// generation moved; err is non-nil when it gave no answer.
func (s *Service) check(ctx context.Context, scope auth.Scope, e *entry) (valid bool, err error) {
	if err = s.authority.Revalidate(ctx, scope); err != nil {
		return false, answer(err)
	}
	if scope.PolicyEpoch() != e.epoch {
		return false, nil
	}
	gen, err := s.deletes.DeleteGeneration(ctx, scope.OrgID(), scope.ProjectIDs())
	if err != nil {
		return false, answer(err)
	}
	return gen == e.deletion, nil
}

// answer is err when it carries no answer and nil when it is a denial.
func answer(err error) error {
	if denied(err) {
		return nil
	}
	return err
}

// current reports whether the original authorization is still exactly valid.
// A check that gets no answer is asked again, with a short back-off, up to
// transientChecks times in a row: an export is not revoked because one control
// read was slow or one leader change swallowed it. When no answer ever comes
// the reason is the honest one (unavailable or timeout), and the export stops.
// A change that committed meanwhile is seen by the retry, which re-reads
// everything.
func (s *Service) current(ctx context.Context, scope auth.Scope, e *entry) (bool, string) {
	backoff := transientBackoff
	for attempt := 1; ; attempt++ {
		valid, err := s.check(ctx, scope, e)
		if err == nil {
			if valid {
				return true, ""
			}
			return false, "revoked"
		}
		if attempt == transientChecks || ctx.Err() != nil {
			return false, reasonFor(err)
		}
		select {
		case <-ctx.Done():
			return false, "timeout"
		case <-time.After(backoff):
		}
		backoff *= 2
	}
}
func (s *Service) run(scope auth.Scope, r Request, e *entry) {
	defer s.wg.Done()
	ctx, cancel := context.WithTimeout(s.root, computeLimit)
	defer cancel()
	chunks, reason := s.collect(ctx, scope, r, e)
	if reason != "" {
		e.finish("failed", reason, nil)
		return
	}
	// Completion revalidates: a revoked/deleted/expired export never becomes complete.
	if ok, reason := s.current(ctx, scope, e); !ok {
		e.finish("failed", reason, nil)
		return
	}
	e.finish("complete", "", chunks)
}

// collect scans and renders the export. A scan that fails for a reason that is
// not authority (the read fence is behind, the node is not ready) is started
// again from its beginning, up to scanRestarts times: its rows are discarded
// and it reads a fresh cut. Authority failures, partial and oversize scans are
// final.
func (s *Service) collect(ctx context.Context, scope auth.Scope, r Request, e *entry) ([][]byte, string) {
	for restarts := 0; ; restarts++ {
		chunks, reason, retry := s.scanOnce(ctx, scope, r, e)
		if !retry || restarts == scanRestarts || ctx.Err() != nil {
			return chunks, reason
		}
		e.mu.Lock()
		e.op.Progress = 0
		e.mu.Unlock()
	}
}

// transient reports whether err is a failure of the read itself, which a new
// scan can get past, as opposed to an answer about the caller or the request.
func transient(err error) bool {
	var f *model.Fault
	return errors.As(err, &f) && (f.Code == model.Stale || f.Code == model.Unavailable)
}
func (s *Service) scanOnce(ctx context.Context, scope auth.Scope, r Request, e *entry) (chunks [][]byte, reason string, retry bool) {
	req := storage.ScanRequest{Projects: []model.ID{r.Project}, Signal: r.Signal, Start: model.UnixNano(r.Start), End: model.UnixNano(r.End)}
	if scope.Permission() == auth.RawRead {
		req.Selectors = []storage.Matcher{{Target: storage.MatchField, Name: "source_id", Op: storage.MatchEqual, Literal: storage.Literal{Kind: storage.LiteralString, String: r.Source.String()}}}
	}
	it, err := s.scanner.Scan(ctx, scope, req)
	if err != nil {
		return nil, reasonFor(err), transient(err)
	}
	defer it.Close()
	var current []byte
	var total uint64
	for {
		if ok, reason := s.current(ctx, scope, e); !ok {
			return nil, reason, false
		}
		page, err := it.Next(ctx)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, reasonFor(err), transient(err)
		}
		// A scan that says it is incomplete is never presented as a complete
		// export, whatever the request asked of the reader. (page.Loss is a
		// per-row column carrying a stored loss record's own count, which the
		// payload already exports; it is not a gap signal.)
		if page.Partial {
			return nil, "partial", false
		}
		for i := range page.Len() {
			line, err := json.Marshal(exportRow{ID: page.IDs[i], Time: model.Int64(page.Times[i]), Project: page.Projects[i], Source: page.Sources[i], Resource: page.Resources[i], Payload: page.Values[i]})
			if err != nil {
				return nil, "unavailable", false
			}
			line = append(line, '\n')
			total += uint64(len(line))
			if total > MaxBytes {
				return nil, "too_large", false
			}
			if len(current)+len(line) > ChunkBytes && len(current) > 0 {
				chunks = append(chunks, current)
				current = nil
			}
			current = append(current, line...)
		}
		e.mu.Lock()
		e.op.Progress = model.Uint64(total)
		e.mu.Unlock()
	}
	if len(current) > 0 {
		chunks = append(chunks, current)
	}
	return chunks, "", false
}

// reasonFor is the safe reason of a failed read: revoked only when the
// authority denied the caller; a cancelled or expired context is a timeout;
// everything else, Stale included, is unavailable.
func reasonFor(err error) string {
	if denied(err) {
		return "revoked"
	}
	var f *model.Fault
	if errors.As(err, &f) && (f.Code == model.Cancelled || f.Code == model.Timeout) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return "timeout"
	}
	return "unavailable"
}

// lookup authorizes first; the entry map is only consulted afterwards, under a
// key derived from the caller's fingerprint. Every operation entering the
// service reclaims expired entries first, and stale or deleted ones die here.
func (s *Service) lookup(ctx context.Context, scope auth.Scope, id model.ID) (*entry, error) {
	if err := s.authority.Revalidate(ctx, scope); err != nil {
		return nil, err
	}
	gen, err := s.deletes.DeleteGeneration(ctx, scope.OrgID(), scope.ProjectIDs())
	if err != nil {
		return nil, err
	}
	key := s.key(scope, id)
	s.mu.Lock()
	dead := s.sweepLocked()
	e, ok := s.entries[key]
	if ok && (e.epoch != scope.PolicyEpoch() || e.deletion != gen) {
		delete(s.entries, key)
		dead = append(dead, e)
		ok = false
	}
	s.mu.Unlock()
	drop(dead)
	if !ok {
		return nil, model.Fail(model.NotFound)
	}
	return e, nil
}
func (s *Service) Status(ctx context.Context, scope auth.Scope, id model.ID) (Operation, error) {
	e, err := s.lookup(ctx, scope, id)
	if err != nil {
		return Operation{}, err
	}
	return e.snapshot(), nil
}

// Chunk releases one chunk. The ticket, the scope, the epoch and the delete
// generation are all revalidated for this chunk; for an elevated scope the
// read audit commits before any bytes are returned. For an ordinary scope a
// revocation that commits between that last check and the response write
// cannot be observed, so a revoked reader may still receive that one chunk
// (at most 64 KiB) and no later one: the next call fails the ticket binding.
// Elevated releases have no such window because the audit commit re-runs
// ValidateControlState inside its own transaction.
func (s *Service) Chunk(ctx context.Context, scope auth.Scope, ticket string, id model.ID, index uint64) (Chunk, error) {
	subject, _, err := s.cache.OpenTicket(ctx, scope, ticketKind, ticket)
	if err != nil {
		return Chunk{}, err
	}
	if subject != id {
		return Chunk{}, model.Fail(model.NotFound)
	}
	e, err := s.lookup(ctx, scope, id)
	if err != nil {
		return Chunk{}, err
	}
	e.mu.Lock()
	phase, chunks, project := e.op.Phase, e.chunks, e.project
	e.mu.Unlock()
	if phase == "running" {
		return Chunk{}, model.Fail(model.Conflict)
	}
	if phase != "complete" || index >= uint64(len(chunks)) {
		return Chunk{}, model.Fail(model.NotFound)
	}
	if err = s.authority.CommitElevatedRead(ctx, scope, "export.chunk", []model.ID{project, id}); err != nil {
		return Chunk{}, err
	}
	return Chunk{Index: index, Last: index+1 == uint64(len(chunks)), Data: append([]byte(nil), chunks[index]...)}, nil
}
