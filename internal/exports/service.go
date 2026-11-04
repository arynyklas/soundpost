// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package exports

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"soundpost/internal/auth"
	"soundpost/internal/model"
	"soundpost/internal/storage"
	"sync"
	"time"
)

const (
	ChunkBytes   = 64 << 10
	MaxBytes     = 8 << 20
	maxActive    = 32
	grantTTL     = 10 * time.Minute
	computeLimit = 2 * time.Minute
	ticketKind   = "export"
)

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
	root      context.Context
	stop      context.CancelFunc
	wg        sync.WaitGroup
	mu        sync.Mutex
	entries   map[[32]byte]*entry
}
type entry struct {
	mu       sync.Mutex
	op       Operation
	project  model.ID
	epoch    uint64
	deletion uint64
	expires  time.Time
	chunks   [][]byte
}

func New(authority *auth.Service, cache *auth.Cache, deletes auth.DeleteGenerations, scanner Scanner) (*Service, error) {
	if authority == nil || cache == nil || deletes == nil || scanner == nil {
		return nil, model.Fail(model.Invalid)
	}
	root, stop := context.WithCancel(context.Background())
	return &Service{authority: authority, cache: cache, deletes: deletes, scanner: scanner, root: root, stop: stop, entries: map[[32]byte]*entry{}}, nil
}
func (s *Service) Close() {
	s.stop()
	s.wg.Wait()
}

// key is derived from the caller's visibility fingerprint, so an operation
// created under any other principal/grant set is simply absent.
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
// caller's visibility fingerprint, policy epoch and delete generation.
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
	e := &entry{op: Operation{ID: id, Kind: "export", Phase: "running", Generation: 1}, project: r.Project, epoch: scope.PolicyEpoch(), deletion: gen, expires: time.Now().Add(grantTTL)}
	s.mu.Lock()
	for k, v := range s.entries {
		if time.Now().After(v.expires) {
			delete(s.entries, k)
		}
	}
	if len(s.entries) >= maxActive {
		s.mu.Unlock()
		return Grant{}, model.Fail(model.Quota)
	}
	s.entries[s.key(scope, id)] = e
	s.mu.Unlock()
	s.wg.Add(1)
	go s.run(scope, r, e)
	return Grant{Operation: e.snapshot(), Ticket: ticket}, nil
}
func (e *entry) snapshot() Operation {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.op
}
func (e *entry) finish(phase, reason string, chunks [][]byte) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.op.Phase, e.op.SafeReason, e.op.Generation = phase, reason, 2
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

// current reports whether the original authorization is still exactly valid.
func (s *Service) current(ctx context.Context, scope auth.Scope, e *entry) bool {
	if s.authority.Revalidate(ctx, scope) != nil || scope.PolicyEpoch() != e.epoch {
		return false
	}
	gen, err := s.deletes.DeleteGeneration(ctx, scope.OrgID(), scope.ProjectIDs())
	return err == nil && gen == e.deletion
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
	// Completion revalidates: a revoked/deleted export never becomes complete.
	if !s.current(ctx, scope, e) {
		e.finish("failed", "revoked", nil)
		return
	}
	e.finish("complete", "", chunks)
}
func (s *Service) collect(ctx context.Context, scope auth.Scope, r Request, e *entry) ([][]byte, string) {
	req := storage.ScanRequest{Projects: []model.ID{r.Project}, Signal: r.Signal, Start: model.UnixNano(r.Start), End: model.UnixNano(r.End)}
	if scope.Permission() == auth.RawRead {
		req.Selectors = []storage.Matcher{{Target: storage.MatchField, Name: "source_id", Op: storage.MatchEqual, Literal: storage.Literal{Kind: storage.LiteralString, String: r.Source.String()}}}
	}
	it, err := s.scanner.Scan(ctx, scope, req)
	if err != nil {
		return nil, reasonFor(err)
	}
	defer it.Close()
	var chunks [][]byte
	var current []byte
	var total uint64
	for {
		if !s.current(ctx, scope, e) {
			return nil, "revoked"
		}
		page, err := it.Next(ctx)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, reasonFor(err)
		}
		for i := range page.Len() {
			line, err := json.Marshal(exportRow{ID: page.IDs[i], Time: model.Int64(page.Times[i]), Project: page.Projects[i], Source: page.Sources[i], Resource: page.Resources[i], Payload: page.Values[i]})
			if err != nil {
				return nil, "unavailable"
			}
			line = append(line, '\n')
			total += uint64(len(line))
			if total > MaxBytes {
				return nil, "too_large"
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
	return chunks, ""
}
func reasonFor(err error) string {
	var f *model.Fault
	if errors.As(err, &f) {
		switch f.Code {
		case model.NotFound, model.Forbidden, model.Unauthenticated, model.Stale:
			return "revoked"
		case model.Cancelled, model.Timeout:
			return "timeout"
		}
	}
	return "unavailable"
}

// lookup authorizes first; the entry map is only consulted afterwards, under a
// key derived from the caller's fingerprint. Stale or deleted entries die here.
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
	defer s.mu.Unlock()
	e, ok := s.entries[key]
	if !ok {
		return nil, model.Fail(model.NotFound)
	}
	if time.Now().After(e.expires) || e.epoch != scope.PolicyEpoch() || e.deletion != gen {
		delete(s.entries, key)
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
// read audit commits before any bytes are returned.
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
