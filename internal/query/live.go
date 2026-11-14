// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"context"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/logql"
	"github.com/arynyklas/soundpost/internal/query/scan"
	"github.com/arynyklas/soundpost/internal/query/value"
	"github.com/arynyklas/soundpost/internal/storage"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

// LiveService streams committed log records to an authorized caller. It is a
// push consumer of the C05 committed change feed: one subscription per retained
// stream feeds a bounded replay buffer, and attachments read that buffer. It
// never executes a query to find new data. Authorization and the delete
// generation are revalidated before every event an attachment returns, and on
// a timer for the whole life of the stream, so revocation or deletion ends the
// stream before any further record. Every loss is an explicit gap with its
// bounds; no path buffers without limit.
type LiveService struct {
	sub      ChangeSubscriber
	policy   Revalidator
	profiles Registry
	limits   Limits
	cfg      LiveLimits
	deletes  auth.DeleteGenerations
	now      func() time.Time
	pool     *memoryPool

	mu      sync.Mutex
	closed  bool
	tickets map[LiveTicketID]*liveTicket
	streams map[LiveStreamID]*liveStream
	wg      sync.WaitGroup

	openIterators atomic.Int64
	leaked        atomic.Int64
	goroutines    atomic.Int64
	attached      atomic.Int64
}

// NewLiveService builds the service over the injected committed feed, scope
// revalidator and profile registry. Options add deletion fencing, limits and
// the clock.
func NewLiveService(subscriber ChangeSubscriber, policy Revalidator, profiles Registry, limits Limits, options ...LiveOption) (*LiveService, error) {
	if subscriber == nil || policy == nil || profiles == nil || limits.validate() != nil {
		return nil, model.Fail(model.Invalid)
	}
	s := &LiveService{sub: subscriber, policy: policy, profiles: profiles, limits: limits, cfg: DefaultLiveLimits(), now: time.Now,
		tickets: map[LiveTicketID]*liveTicket{}, streams: map[LiveStreamID]*liveStream{}}
	for _, option := range options {
		option(s)
	}
	if s.cfg.validate() != nil || s.now == nil {
		return nil, model.Fail(model.Invalid)
	}
	s.pool = newMemoryPool(limits.GlobalMemory)
	return s, nil
}

// Usage snapshots live resources.
func (s *LiveService) Usage() LiveUsage {
	s.mu.Lock()
	streams, tickets := len(s.streams), len(s.tickets)
	s.mu.Unlock()
	used, _ := s.pool.snapshot()
	return LiveUsage{Streams: streams, Attached: int(s.attached.Load()), Tickets: tickets, OpenIterators: s.openIterators.Load(), MemoryUsed: used, LeakedBytes: s.leaked.Load(), Goroutines: s.goroutines.Load()}
}

// Close ends every stream and waits for every goroutine, iterator and charge to
// be released. The service refuses new tickets and attachments afterwards.
func (s *LiveService) Close() error {
	s.mu.Lock()
	s.closed = true
	streams := make([]*liveStream, 0, len(s.streams))
	for _, st := range s.streams {
		streams = append(streams, st)
	}
	s.tickets = map[LiveTicketID]*liveTicket{}
	s.mu.Unlock()
	for _, st := range streams {
		st.finish(liveTerminal(st.id, model.Fail(model.Unavailable), reasonClosed), true)
	}
	s.wg.Wait()
	return nil
}

type liveTicket struct {
	id          LiveTicketID
	org         model.ID
	principal   model.ID
	fingerprint string
	perm        auth.Permission
	session     string
	spec        liveSpec
	expires     time.Time
}

// liveSpec is a validated request: projects ordered by ID, bounds resolved and
// an identity key of the selector (never the expression text on the wire).
type liveSpec struct {
	req      LiveRequest
	duration time.Duration
	bytes    int64
	entries  uint64
	key      string
}

func (s *LiveService) normalize(req LiveRequest) (liveSpec, error) {
	invalid := func() (liveSpec, error) { return liveSpec{}, model.Fail(model.Invalid) }
	if req.Profile == "" || len(req.Profile) > 128 || req.FeatureSet == "" || len(req.FeatureSet) > 128 || !profileMatchesLanguage(LanguageLogQL, req.Profile) {
		return invalid()
	}
	if len(req.Expression) == 0 || len(req.Expression) > s.limits.MaxExpressionBytes || !validUTF8(req.Expression) {
		return invalid()
	}
	if len(req.Projects) < 1 || len(req.Projects) > s.limits.MaxProjects || len(req.Carrier) > 1024 {
		return invalid()
	}
	projects := append([]model.ID(nil), req.Projects...)
	sort.Slice(projects, func(i, j int) bool { return idLess(projects[i], projects[j]) })
	for i, id := range projects {
		if id == (model.ID{}) || i > 0 && projects[i-1] == id {
			return invalid()
		}
	}
	if req.Source != nil && *req.Source == (model.ID{}) || req.ResumeStreamID != nil && *req.ResumeStreamID == (model.ID{}) {
		return invalid()
	}
	duration, bytes, entries, err := s.cfg.resolve(req.Budget)
	if err != nil {
		return liveSpec{}, err
	}
	out := req
	out.Projects = projects
	out.Carrier = append([]byte(nil), req.Carrier...)
	if req.Source != nil {
		src := *req.Source
		out.Source = &src
	}
	key := strings.Builder{}
	for _, p := range projects {
		key.WriteString(p.String())
		key.WriteByte(',')
	}
	key.WriteString("|" + req.Profile + "|" + req.FeatureSet + "|")
	if req.Source != nil {
		key.WriteString(req.Source.String())
	}
	key.WriteString("|" + strconv.Itoa(len(req.Expression)) + ":" + req.Expression)
	return liveSpec{req: out, duration: duration, bytes: bytes, entries: entries, key: key.String()}, nil
}

func validUTF8(s string) bool { return utf8.ValidString(s) }

// authorize is the scope gate: it precedes every ticket, stream, profile and
// parse step. A project or source the scope does not name is NotFound whether
// or not it exists.
func (s *LiveService) authorize(ctx context.Context, scope auth.Scope, projects []model.ID, source *model.ID) error {
	switch scope.Permission() {
	case auth.Read:
		if source != nil {
			return model.Fail(model.Invalid)
		}
	case auth.RawRead:
		if len(projects) != 1 || source == nil {
			return model.Fail(model.Invalid)
		}
	default:
		return model.Fail(model.Forbidden)
	}
	for _, p := range projects {
		if !scope.AllowsProject(p) {
			return model.Fail(model.NotFound)
		}
	}
	if scope.Permission() == auth.RawRead && !scope.AllowsSource(*source) {
		return model.Fail(model.NotFound)
	}
	if err := ctx.Err(); err != nil {
		return ctxFault(err)
	}
	if exp := scope.ExpiresAt(); !exp.IsZero() && !s.now().Before(exp) {
		return model.Fail(model.NotFound)
	}
	return s.policy.Revalidate(ctx, scope)
}

// compile resolves the profile and plans the expression once per project: a
// LogQL plan owns its query-local regex scope. The expression must be a log
// stream selector with pipeline; metric expressions are not streamable.
func (s *LiveService) compile(spec liveSpec) (map[model.ID]logql.PipelinePlan, error) {
	prof, err := s.profiles.Resolve(spec.req.Profile, spec.req.FeatureSet)
	if err != nil || prof.ID != spec.req.Profile || !profileMatchesLanguage(LanguageLogQL, prof.ID) {
		return nil, model.Fail(model.Invalid)
	}
	plans := make(map[model.ID]logql.PipelinePlan, len(spec.req.Projects))
	for _, project := range spec.req.Projects {
		n := normalized{Request: Request{Language: LanguageLogQL, Expression: spec.req.Expression}, eval: value.Evaluation{Instant: true, Time: model.UnixNano(s.now().UnixNano())}}
		plan, _, err := n.compile(prof)
		if err != nil {
			return nil, err
		}
		if !plan.logs || plan.log == nil || plan.log.Pipeline == nil {
			return nil, model.Fail(model.Invalid)
		}
		plans[project] = *plan.log.Pipeline
	}
	return plans, nil
}

// CreateLiveTicket validates the request under the caller's scope and issues a
// one-use admission ticket bound to the caller's org, principal, effective
// visibility and session. The ticket expires after the ticket lifetime (60
// seconds by default) and never outlives the scope's own clock-based expiry.
func (s *LiveService) CreateLiveTicket(ctx context.Context, scope auth.Scope, req LiveRequest) (LiveTicket, error) {
	spec, err := s.normalize(req)
	if err != nil {
		return LiveTicket{}, err
	}
	if err = s.authorize(ctx, scope, spec.req.Projects, spec.req.Source); err != nil {
		return LiveTicket{}, err
	}
	if _, err = s.compile(spec); err != nil {
		return LiveTicket{}, err
	}
	now := s.now()
	expires := now.Add(s.cfg.TicketTTL)
	if exp := scope.ExpiresAt(); !exp.IsZero() && exp.Before(expires) {
		expires = exp
	}
	tk := &liveTicket{id: model.NewID(), org: scope.OrgID(), principal: scope.PrincipalID(), fingerprint: scope.VisibilityFingerprint(), perm: scope.Permission(), session: liveSessionOf(ctx), spec: spec, expires: expires}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return LiveTicket{}, model.Fail(model.Unavailable)
	}
	s.purgeLocked(now)
	mine := 0
	for _, t := range s.tickets {
		if t.org == tk.org && t.principal == tk.principal {
			mine++
		}
	}
	if len(s.tickets) >= s.cfg.MaxTickets || mine >= s.cfg.MaxTicketsPerPrincipal {
		return LiveTicket{}, model.Fail(model.Quota)
	}
	s.tickets[tk.id] = tk
	return LiveTicket{ID: tk.id, ExpiresAt: model.UnixNano(expires.UnixNano())}, nil
}

func (s *LiveService) purgeLocked(now time.Time) {
	for id, t := range s.tickets {
		if !now.Before(t.expires) {
			delete(s.tickets, id)
		}
	}
}

// matches reports whether the presenter is exactly the ticket's issuer.
//
// The principal term is redundant with the fingerprint, which already hashes the
// organization and the principal (auth.Scope.VisibilityFingerprint), so no
// presenter can match with a different principal and an identical fingerprint;
// it stays as defense in depth.
func (t *liveTicket) matches(scope auth.Scope, session string) bool {
	return t.org == scope.OrgID() && t.principal == scope.PrincipalID() && t.fingerprint == scope.VisibilityFingerprint() && t.perm == scope.Permission() && t.session == session
}

// LiveTicketRequest returns the stored request of a ticket to its own session
// (the HTTP layer rebuilds the scope from it without any request field naming
// authority). A different session, an expired or an unknown ticket is the same
// NotFound.
func (s *LiveService) LiveTicketRequest(ctx context.Context, id LiveTicketID) (LiveRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tk := s.tickets[id]
	if tk == nil || !s.now().Before(tk.expires) || tk.session != liveSessionOf(ctx) {
		return LiveRequest{}, model.Fail(model.NotFound)
	}
	out := tk.spec.req
	out.Projects = append([]model.ID(nil), out.Projects...)
	out.Carrier = append([]byte(nil), out.Carrier...)
	return out, nil
}

// consume takes the ticket exactly once, and only for its own issuer: a
// mismatched presenter neither succeeds nor burns the ticket, and cannot tell
// a wrong presenter from an unknown ticket.
func (s *LiveService) consume(scope auth.Scope, session string, id LiveTicketID) (*liveTicket, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, model.Fail(model.Unavailable)
	}
	tk := s.tickets[id]
	if tk == nil || !s.now().Before(tk.expires) || !tk.matches(scope, session) {
		return nil, model.Fail(model.NotFound)
	}
	delete(s.tickets, id)
	return tk, nil
}

// Live consumes the ticket and attaches to a stream. With a resumable stream
// retained (ticket's ResumeStreamID) it continues after the given sequence;
// when that stream is gone, expired, or not this caller's, a new stream starts
// with an explicit replay_expired gap, never a silent restart.
//
// A failed attach burns the ticket by design: Live consumes it before the second
// authorization and the cursor checks, so a revocation or a malformed
// Last-Event-ID between mint and attach forces a fresh mint (fail closed).
func (s *LiveService) Live(ctx context.Context, scope auth.Scope, ticket LiveTicketID, after *uint64) (LiveIterator, error) {
	session := liveSessionOf(ctx)
	tk, err := s.consume(scope, session, ticket)
	if err != nil {
		return nil, err
	}
	spec := tk.spec
	if err = s.authorize(ctx, scope, spec.req.Projects, spec.req.Source); err != nil {
		return nil, err
	}
	if after != nil && (spec.req.ResumeStreamID == nil || *after > math.MaxInt64) {
		return nil, model.Fail(model.Invalid)
	}
	if spec.req.ResumeStreamID != nil {
		s.mu.Lock()
		st := s.streams[*spec.req.ResumeStreamID]
		s.mu.Unlock()
		if st != nil && st.owns(scope, tk, spec) {
			if after != nil && *after > st.lastSequence() {
				return nil, model.Fail(model.Invalid)
			}
			from := uint64(1)
			if after != nil {
				from = *after + 1
			}
			if it := st.attach(scope, from, true); it != nil {
				return it, nil
			}
		}
	}
	return s.start(ctx, scope, tk, after)
}

func (s *LiveService) deleteGeneration(ctx context.Context, scope auth.Scope, projects []model.ID) (uint64, error) {
	if s.deletes == nil {
		return 0, nil
	}
	return s.deletes.DeleteGeneration(ctx, scope.OrgID(), projects)
}

// verify is the revalidation every event and every guard tick performs: the
// scope is still valid and no deletion has committed since the stream began.
func (s *LiveService) verify(ctx context.Context, scope auth.Scope, projects []model.ID, gen uint64) error {
	if err := ctx.Err(); err != nil {
		return ctxFault(err)
	}
	vctx, cancel := context.WithTimeout(ctx, verifyTimeout)
	defer cancel()
	if err := s.policy.Revalidate(vctx, scope); err != nil {
		return err
	}
	if s.deletes == nil {
		return nil
	}
	now, err := s.deletes.DeleteGeneration(vctx, scope.OrgID(), projects)
	if err != nil {
		return err
	}
	if now != gen {
		return model.Fail(model.Stale)
	}
	return nil
}

// start creates a new retained stream and its first attachment.
func (s *LiveService) start(ctx context.Context, scope auth.Scope, tk *liveTicket, after *uint64) (LiveIterator, error) {
	spec := tk.spec
	plans, err := s.compile(spec)
	if err != nil {
		return nil, err
	}
	gen, err := s.deleteGeneration(ctx, scope, spec.req.Projects)
	if err != nil {
		return nil, normalizeError(err, false)
	}
	life, lifeCancel := context.WithCancel(context.Background())
	feed, feedCancel := context.WithCancel(life)
	now := s.now()
	st := &liveStream{svc: s, id: model.NewID(), org: tk.org, principal: tk.principal, fingerprint: tk.fingerprint, perm: tk.perm, scope: scope,
		projects: spec.req.Projects, source: spec.req.Source, key: spec.key, plans: plans, gen: gen,
		acct: newQueryAccount(s.pool, spec.bytes+s.cfg.WorkingBytes), life: life, lifeCancel: lifeCancel, feed: feed, feedCancel: feedCancel,
		deadline: now.Add(spec.duration), maxBytes: spec.bytes, maxEntries: int(spec.entries), notify: make(chan struct{}), detachedAt: now}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		lifeCancel()
		return nil, model.Fail(model.Unavailable)
	}
	perOrg, perPrincipal := 0, 0
	for _, o := range s.streams {
		if o.org == st.org {
			perOrg++
			if o.principal == st.principal {
				perPrincipal++
			}
		}
	}
	if len(s.streams) >= s.cfg.MaxStreams || perOrg >= s.cfg.MaxStreamsPerOrg || perPrincipal >= s.cfg.MaxStreamsPerPrincipal {
		s.mu.Unlock()
		lifeCancel()
		return nil, model.Fail(model.Quota)
	}
	s.streams[st.id] = st
	s.wg.Add(1)
	s.goroutines.Add(1)
	s.mu.Unlock()

	feedReq := storage.SubscribeRequest{Projects: spec.req.Projects, Signal: model.Log}
	if spec.req.Source != nil {
		// A restricted-raw read names its one source; the feed itself is narrowed to
		// it (the pipeline never sees another source's rows).
		feedReq.Selectors = []storage.Matcher{{Target: storage.MatchField, Name: "source_id", Op: storage.MatchEqual, Literal: storage.Literal{Kind: storage.LiteralString, String: spec.req.Source.String()}}}
	}
	iter, err := s.sub.Subscribe(feed, scope, feedReq)
	if err != nil {
		st.lifeCancel()
		go st.reap() // releases the account and the map slot exactly once
		return nil, normalizeError(err, false)
	}
	st.iter = iter
	s.openIterators.Add(1)
	base := uint64(0)
	if after != nil {
		base = *after
	}
	st.nextSeq, st.evictedThrough = base, base
	if spec.req.ResumeStreamID != nil {
		through := iter.Watermarks()
		st.mu.Lock()
		_ = st.appendLocked(LiveEvent{Type: LiveGap, Gap: &LiveGapInfo{Reason: GapReplayExpired, FromSequence: model.Uint64(base + 1), ToSequence: model.Uint64(base + 1), Through: through}}, nil, now)
		st.mu.Unlock()
	}
	st.done.Add(2)
	s.wg.Add(2)
	s.goroutines.Add(2)
	go st.pump()
	go st.guard()
	go st.reap()
	it := st.attach(scope, base+1, false)
	if it == nil {
		st.finish(liveTerminal(st.id, model.Fail(model.Cancelled), reasonClosed), true)
		return nil, model.Fail(model.Cancelled)
	}
	return it, nil
}

// liveStream is one retained stream: its subscription, replay buffer and
// authorization state. Everything it holds is released exactly once by reap.
type liveStream struct {
	svc         *LiveService
	id          LiveStreamID
	org         model.ID
	principal   model.ID
	fingerprint string
	perm        auth.Permission
	scope       auth.Scope
	projects    []model.ID
	source      *model.ID
	key         string
	plans       map[model.ID]logql.PipelinePlan
	gen         uint64
	acct        *queryAccount
	deadline    time.Time
	maxBytes    int64
	maxEntries  int

	iter       storage.ChangeIterator
	iterOnce   sync.Once
	life, feed context.Context
	lifeCancel context.CancelFunc
	feedCancel context.CancelFunc
	done       sync.WaitGroup

	mu             sync.Mutex
	notify         chan struct{}
	buf            []liveEntry
	bufBytes       int64
	nextSeq        uint64
	evictedThrough uint64
	evictedCursors []model.Cursor
	marks          []pageMark
	terminal       *LiveEvent
	preempt        bool
	cur            *liveIter
	detachedAt     time.Time
	dead           bool
}

type liveEntry struct {
	ev    LiveEvent
	bytes int64
	at    time.Time
}

func (s *liveStream) owns(scope auth.Scope, tk *liveTicket, spec liveSpec) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.dead && s.org == scope.OrgID() && s.principal == scope.PrincipalID() && s.fingerprint == scope.VisibilityFingerprint() && s.perm == scope.Permission() && s.key == spec.key
}

func (s *liveStream) lastSequence() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.nextSeq
}

func (s *liveStream) broadcastLocked() {
	close(s.notify)
	s.notify = make(chan struct{})
}

// attach makes it the stream's single consumer, reading from sequence next; an
// earlier attachment is superseded with a typed event.
func (s *liveStream) attach(scope auth.Scope, next uint64, resumed bool) *liveIter {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dead {
		return nil
	}
	it := &liveIter{s: s, scope: scope, next: next, resumed: resumed}
	s.cur = it
	s.detachedAt = time.Time{}
	s.svc.attached.Add(1)
	s.broadcastLocked()
	return it
}

// appendLocked adds one event to the replay buffer, evicting the oldest first
// to stay within the entry and byte bounds.
func (s *liveStream) appendLocked(ev LiveEvent, cursors []model.Cursor, at time.Time) error {
	cost := int64(256)
	if ev.Entry != nil {
		cost += value.LogBytes(value.Log{Line: ev.Entry.Line, Labels: ev.Labels, StreamLabels: ev.Entry.StreamLabels, StructuredMetadata: ev.Entry.StructuredMetadata})
	}
	if cost > s.maxBytes {
		return model.Fail(model.Quota)
	}
	for len(s.buf) > 0 && (s.bufBytes+cost > s.maxBytes || len(s.buf) >= s.maxEntries) {
		s.evictOldestLocked()
	}
	if err := s.acct.Reserve(cost); err != nil {
		return err
	}
	s.nextSeq++
	ev.StreamID = s.id
	ev.Sequence = model.Uint64(s.nextSeq)
	if ev.Type == LiveGap && ev.Gap != nil {
		s.markLocked(s.nextSeq, ev.Gap.Through)
	}
	if ev.Type == LiveGap && ev.Gap != nil && ev.Gap.FromSequence == 0 {
		ev.Gap.FromSequence, ev.Gap.ToSequence = ev.Sequence, ev.Sequence
	}
	ev.Cursors = cursors
	s.buf = append(s.buf, liveEntry{ev: ev, bytes: cost, at: at})
	s.bufBytes += cost
	s.broadcastLocked()
	return nil
}

// pageMark is the committed-feed position after which a stream sequence is
// fully handled: the exact lower bound ("after") of a later gap.
type pageMark struct {
	seq     uint64
	cursors []model.Cursor
}

// maxPageMarks bounds the marks a stream keeps (a few dozen bytes each).
const maxPageMarks = 4096

func (s *liveStream) markLocked(seq uint64, cursors []model.Cursor) {
	if len(cursors) == 0 {
		return
	}
	s.marks = append(s.marks, pageMark{seq: seq, cursors: cloneCursors(cursors)})
	if len(s.marks) > 2*maxPageMarks {
		s.marks = append([]pageMark(nil), s.marks[len(s.marks)-maxPageMarks:]...)
	}
}

// afterLocked returns the cursors of the latest fully handled position strictly
// before sequence from, or nil when it is no longer (or never was) known.
func (s *liveStream) afterLocked(from uint64) []model.Cursor {
	i := sort.Search(len(s.marks), func(i int) bool { return s.marks[i].seq >= from })
	if i == 0 {
		return nil
	}
	return cloneCursors(s.marks[i-1].cursors)
}

func (s *liveStream) evictOldestLocked() {
	head := s.buf[0]
	s.buf[0] = liveEntry{}
	s.buf = s.buf[1:]
	if len(s.buf) == 0 {
		s.buf = nil
	}
	s.bufBytes -= head.bytes
	s.acct.Release(head.bytes)
	s.evictedThrough = uint64(head.ev.Sequence)
	if head.ev.Type == LiveGap && head.ev.Gap != nil {
		s.evictedCursors = head.ev.Gap.Through
	} else {
		s.evictedCursors = head.ev.Cursors
	}
}

func (s *liveStream) evictAgedLocked(now time.Time) {
	for len(s.buf) > 0 && now.Sub(s.buf[0].at) >= s.svc.cfg.ReplayWindow {
		s.evictOldestLocked()
	}
}

// finish records the stream's terminal event once and stops the feed. A
// preempting terminal (authorization or deletion) discards the buffer: no
// further record may be released. Otherwise buffered, already authorized
// records are delivered first.
func (s *liveStream) finish(ev LiveEvent, preempt bool) {
	s.mu.Lock()
	if s.terminal == nil {
		s.terminal = &ev
		s.preempt = preempt
		s.broadcastLocked()
	} else if preempt && !s.preempt {
		s.preempt = true
		s.broadcastLocked()
	}
	s.mu.Unlock()
	s.feedCancel()
	if preempt {
		s.destroy()
	}
}

// destroy ends the stream; reap releases what it holds.
func (s *liveStream) destroy() {
	s.mu.Lock()
	if !s.dead {
		s.dead = true
		s.broadcastLocked()
	}
	s.mu.Unlock()
	s.lifeCancel()
}

func (s *liveStream) closeIter() {
	s.iterOnce.Do(func() {
		if s.iter != nil {
			_ = s.iter.Close()
			s.svc.openIterators.Add(-1)
		}
	})
}

// reap is the single release point: after both workers stop it closes the
// subscription, returns every charge and frees the stream's slot.
func (s *liveStream) reap() {
	defer s.svc.wg.Done()
	defer s.svc.goroutines.Add(-1)
	<-s.life.Done()
	s.done.Wait()
	s.closeIter()
	s.mu.Lock()
	held := s.bufBytes
	s.buf, s.bufBytes = nil, 0
	s.dead = true
	s.broadcastLocked()
	s.mu.Unlock()
	s.acct.Release(held)
	leaked, _ := s.acct.finish()
	s.svc.leaked.Add(leaked)
	s.svc.mu.Lock()
	delete(s.svc.streams, s.id)
	s.svc.mu.Unlock()
}

// contain is the deferred recover of the stream's two workers. A panic while
// handling one stream (a row, a revalidation, the subscription) ends only that
// stream with a typed internal_error terminal event and discards its replay
// buffer; the process and every other stream carry on. The panic value is
// dropped on purpose: it may quote row content, so it is never stored, put in
// an event or returned in an error. It must run before the worker's other
// deferred releases, so it is deferred last.
func (s *liveStream) contain() {
	if recover() == nil {
		return
	}
	s.finish(liveTerminal(s.id, model.Fail(model.Unavailable), reasonInternal), true)
}

// pumpReason names a non-authorization end of the pump: a corrupt row and an
// over-budget row are not feed failures.
func pumpReason(err error) string {
	switch faultCode(err) {
	case model.Corrupt:
		return reasonCorrupt
	case model.Quota:
		return reasonQuota
	}
	return reasonFeedError
}

// guard revalidates on a timer even when no data flows, enforces the stream
// deadline and the detached-replay lifetime, and trims aged buffer entries.
func (s *liveStream) guard() {
	defer s.svc.wg.Done()
	defer s.svc.goroutines.Add(-1)
	defer s.done.Done()
	t := time.NewTicker(s.svc.limits.RevalidateInterval)
	defer t.Stop()
	defer s.contain()
	for {
		select {
		case <-s.life.Done():
			return
		case <-t.C:
		}
		now := s.svc.now()
		if err := s.svc.verify(s.life, s.scope, s.projects, s.gen); err != nil {
			if s.life.Err() != nil {
				return
			}
			s.finish(liveTerminal(s.id, err, ""), true)
			return
		}
		if !now.Before(s.deadline) {
			s.finish(liveTerminal(s.id, model.Fail(model.Timeout), reasonDeadline), false)
		}
		idle := func() bool {
			s.mu.Lock()
			defer s.mu.Unlock() // a panic must not leave the stream's lock held
			s.evictAgedLocked(now)
			return s.cur == nil && !s.detachedAt.IsZero() && now.Sub(s.detachedAt) >= s.svc.cfg.ReplayWindow
		}()
		if idle {
			s.destroy()
			return
		}
	}
}

// pump moves committed pages from the change feed into the replay buffer. It is
// the only reader of the subscription.
func (s *liveStream) pump() {
	defer s.svc.wg.Done()
	defer s.svc.goroutines.Add(-1)
	defer s.done.Done()
	defer s.closeIter()
	defer s.contain()
	for {
		page, err := s.iter.Next(s.feed)
		if err != nil {
			if s.feed.Err() != nil {
				return
			}
			s.finish(liveTerminal(s.id, err, reasonFeedError), false)
			return
		}
		if page.Revoked {
			s.finish(liveTerminal(s.id, model.Fail(model.NotFound), reasonRevoked), true)
			return
		}
		if err = s.handle(page); err != nil {
			if s.feed.Err() != nil {
				return
			}
			var p *preemptError
			if asPreempt(err, &p) {
				s.finish(liveTerminal(s.id, p.err, ""), true)
			} else {
				s.finish(liveTerminal(s.id, err, pumpReason(err)), false)
			}
			return
		}
	}
}

type preemptError struct{ err error }

func (e *preemptError) Error() string { return e.err.Error() }
func asPreempt(err error, target **preemptError) bool {
	p, ok := err.(*preemptError)
	if ok {
		*target = p
	}
	return ok
}

func gapReason(r string) string {
	switch r {
	case "slow_consumer":
		return GapFeedOverrun
	case "catch_up_required":
		return GapFeedCatchUp
	}
	return GapFeedOther
}

// handle appends one feed page. Authorization and the delete generation are
// verified before any row of the page enters the buffer.
func (s *liveStream) handle(page storage.ChangePage) error {
	now := s.svc.now()
	if page.Gap != nil {
		err := func() error {
			s.mu.Lock()
			defer s.mu.Unlock() // a panic below must not leave the stream's lock held
			return s.appendLocked(LiveEvent{Type: LiveGap, Gap: &LiveGapInfo{Reason: gapReason(page.Gap.Reason), After: cloneCursors(page.Gap.After), Through: cloneCursors(page.Gap.Through)}}, nil, now)
		}()
		return err
	}
	n := page.Page.Len()
	if n == 0 {
		return nil
	}
	if err := s.svc.verify(s.feed, s.scope, s.projects, s.gen); err != nil {
		return &preemptError{normalizeError(err, false)}
	}
	p := page.Page
	if len(p.Times) != n || len(p.Values) != n || len(p.Projects) != n || len(p.Sources) != n {
		return model.Fail(model.Corrupt)
	}
	// The whole page is converted first and published under one lock, so a
	// consumer can never see part of a page as its resume position.
	var staged []LiveEvent
	var held int64
	defer func() { s.acct.Release(held) }()
	for j := range n {
		if err := s.feed.Err(); err != nil {
			return ctxFault(err)
		}
		plan, ok := s.plans[p.Projects[j]]
		if !ok {
			return model.Fail(model.Corrupt)
		}
		if s.source != nil && p.Sources[j] != *s.source {
			continue
		}
		payload := p.Values[j]
		if _, err := payload.Value(model.Log); err != nil || payload.Log == nil {
			return model.Fail(model.Corrupt)
		}
		if err := payload.Log.StreamLabels.Validate(); err != nil {
			return model.Fail(model.Corrupt)
		}
		row := scan.LogRow{ID: p.IDs[j], Project: p.Projects[j], Source: p.Sources[j], Timestamp: p.Times[j], Multiplicity: 1, Record: *payload.Log}
		res, err := logql.RunLogRow(s.feed, plan, row, s.acct)
		if err != nil {
			return normalizeError(err, false)
		}
		if !res.Retained {
			s.acct.Release(res.Bytes)
			continue
		}
		held += res.Bytes
		project := p.Projects[j]
		var source *model.ID
		if res.Entry.Source != (model.ID{}) {
			id := res.Entry.Source
			source = &id
		}
		staged = append(staged, LiveEvent{Type: LiveRecord, Project: &project, Labels: labelsOrEmpty(value.CloneLabels(res.Labels)), Entry: &LogEntry{Time: res.Entry.Timestamp, ID: res.Entry.ID, Source: source, Multiplicity: res.Entry.Multiplicity, Line: res.Entry.Line,
			StreamLabels: labelsOrEmpty(value.CloneLabels(res.OriginalStreamLabels)), StructuredMetadata: labelsOrEmpty(value.CloneLabels(res.OriginalStructuredMetadata))}})
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if page.Page.Partial {
		if err := s.appendLocked(LiveEvent{Type: LiveGap, Gap: &LiveGapInfo{Reason: GapPartialShard, After: cloneCursors(page.Cursors), Through: cloneCursors(page.Cursors)}}, nil, now); err != nil {
			return err
		}
	}
	for i := range staged {
		if err := s.appendLocked(staged[i], cloneCursors(page.Cursors), now); err != nil {
			return err
		}
	}
	if len(staged) > 0 {
		s.markLocked(s.nextSeq, page.Cursors)
	}
	return nil
}

func cloneCursors(in []model.Cursor) []model.Cursor {
	if len(in) == 0 {
		return nil
	}
	return append([]model.Cursor(nil), in...)
}

// liveTerminal types the end of a stream. Authorization and deletion failures
// are revocations; everything else is a typed error.
func liveTerminal(id LiveStreamID, err error, reason string) LiveEvent {
	err = normalizeError(err, false)
	ev := LiveEvent{Type: LiveError, StreamID: id, Failure: failureOf(err), Reason: reason}
	switch faultCode(err) {
	case model.NotFound, model.Forbidden, model.Unauthenticated:
		ev.Type = LiveRevoke
		if reason == "" {
			ev.Reason = reasonRevoked
		}
	case model.Stale:
		ev.Type = LiveRevoke
		if reason == "" {
			ev.Reason = reasonDeleted
		}
	default:
		if ev.Reason == "" {
			ev.Reason = reasonUnavailable
		}
	}
	return ev
}

// liveIter is one attachment: its position, whether it has been handed any
// event and the cursors of the last thing it received.
type liveIter struct {
	s           *liveStream
	scope       auth.Scope
	next        uint64
	resumed     bool
	started     bool
	opened      bool
	done        bool
	slowPending bool
	closed      atomic.Bool
}

type pick struct {
	ev         *LiveEvent
	adv        uint64
	slow       bool
	term       *LiveEvent
	streamTerm bool
	wait       chan struct{}
}

func (s *liveStream) pickLocked(it *liveIter, now time.Time) pick {
	if s.cur != it {
		ev := liveTerminal(s.id, model.Fail(model.Conflict), reasonSuperseded)
		return pick{term: &ev}
	}
	if s.terminal != nil && s.preempt {
		return pick{term: s.terminal, streamTerm: true}
	}
	if it.slowPending {
		ev := liveTerminal(s.id, model.Fail(model.Quota), reasonSlow)
		return pick{term: &ev}
	}
	s.evictAgedLocked(now)
	if it.next <= s.evictedThrough {
		from, to := it.next, s.evictedThrough
		ev := LiveEvent{Type: LiveGap, StreamID: s.id, Sequence: model.Uint64(to), Gap: &LiveGapInfo{Reason: GapReplayEvicted, FromSequence: model.Uint64(from), ToSequence: model.Uint64(to), After: s.afterLocked(from), Through: cloneCursors(s.evictedCursors)}}
		// A resumed attachment's first gap is the replay boundary; any other lag
		// is a consumer that did not keep up and is disconnected after the gap.
		return pick{ev: &ev, adv: to + 1, slow: it.started || !it.resumed}
	}
	if idx := it.next - (s.evictedThrough + 1); idx < uint64(len(s.buf)) {
		ev := s.buf[idx].ev
		return pick{ev: &ev, adv: it.next + 1}
	}
	if s.terminal != nil {
		return pick{term: s.terminal, streamTerm: true}
	}
	if s.dead {
		ev := liveTerminal(s.id, model.Fail(model.Cancelled), reasonClosed)
		return pick{term: &ev}
	}
	return pick{wait: s.notify}
}

// check is the per-event revalidation of this attachment's own scope.
func (it *liveIter) check(ctx context.Context) error {
	return it.s.svc.verify(ctx, it.scope, it.s.projects, it.s.gen)
}

func (it *liveIter) terminate(err error) (LiveEvent, error) {
	ev := liveTerminal(it.s.id, err, "")
	it.done = true
	it.s.finish(ev, true)
	return ev, nil
}

func (it *liveIter) watermarks() []model.Cursor {
	s := it.s
	s.mu.Lock()
	up := s.terminal == nil && !s.dead && s.feed.Err() == nil
	s.mu.Unlock()
	if !up || s.iter == nil {
		return nil
	}
	return s.iter.Watermarks()
}

// Next returns the next event of this attachment. Every event is released only
// after this attachment's scope and the delete generation were revalidated; a
// failure yields one terminal revoke/error event and then io.EOF. A consumer
// that fell behind the bounded replay buffer receives the explicit gap and is
// then disconnected with a typed slow_consumer error.
func (it *liveIter) Next(ctx context.Context) (LiveEvent, error) {
	s := it.s
	for {
		if err := ctx.Err(); err != nil {
			return LiveEvent{}, ctxFault(err)
		}
		if it.closed.Load() {
			return LiveEvent{}, io.ErrClosedPipe
		}
		if it.done {
			return LiveEvent{}, io.EOF
		}
		if !it.opened {
			if err := it.check(ctx); err != nil {
				if ctx.Err() != nil {
					return LiveEvent{}, ctxFault(ctx.Err())
				}
				return it.terminate(err)
			}
			it.opened = true
			return LiveEvent{Type: LiveOpen, StreamID: s.id, Watermarks: it.watermarks()}, nil
		}
		s.mu.Lock()
		pk := s.pickLocked(it, s.svc.now())
		s.mu.Unlock()
		switch {
		case pk.ev != nil:
			if err := it.check(ctx); err != nil {
				if ctx.Err() != nil {
					return LiveEvent{}, ctxFault(ctx.Err())
				}
				return it.terminate(err)
			}
			s.mu.Lock()
			still := s.cur == it && !(s.terminal != nil && s.preempt)
			s.mu.Unlock()
			if !still {
				continue
			}
			it.next = pk.adv
			it.started = true
			it.slowPending = pk.slow
			return *pk.ev, nil
		case pk.term != nil:
			it.done = true
			if pk.streamTerm {
				s.destroy()
			}
			return *pk.term, nil
		}
		timer := time.NewTimer(s.svc.cfg.Heartbeat)
		select {
		case <-pk.wait:
			timer.Stop()
		case <-ctx.Done():
			timer.Stop()
			return LiveEvent{}, ctxFault(ctx.Err())
		case <-timer.C:
			if err := it.check(ctx); err != nil {
				if ctx.Err() != nil {
					return LiveEvent{}, ctxFault(ctx.Err())
				}
				return it.terminate(err)
			}
			return LiveEvent{Type: LiveHeartbeat, StreamID: s.id, Watermarks: it.watermarks()}, nil
		}
	}
}

// Close detaches this attachment. The stream stays retained, with its replay
// buffer, until the replay window lapses.
func (it *liveIter) Close() error {
	if !it.closed.CompareAndSwap(false, true) {
		return nil
	}
	s := it.s
	s.svc.attached.Add(-1)
	s.mu.Lock()
	if s.cur == it {
		s.cur = nil
		s.detachedAt = s.svc.now()
	}
	s.broadcastLocked()
	s.mu.Unlock()
	return nil
}
