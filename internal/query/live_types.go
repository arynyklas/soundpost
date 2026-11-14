// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"context"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/storage"
	"time"
)

// ChangeSubscriber is C05's committed-change feed, exactly:
// *storage.Engine implements it. The live service never polls Scan in steady
// state; every record it releases came through this feed.
type ChangeSubscriber interface {
	Subscribe(context.Context, auth.Scope, storage.SubscribeRequest) (storage.ChangeIterator, error)
}

// LiveTicketID is the non-secret, one-use admission identifier. It carries no
// authority: the service binds it to the issuing org, principal, effective
// visibility and authenticated session.
type LiveTicketID = model.ID

// LiveStreamID names one retained live stream and its replay buffer.
type LiveStreamID = model.ID

// LiveRequest is the stored selector of a live stream: a LogQL log-stream
// expression over named projects. Budget.TimeoutNS bounds the stream lifetime,
// Budget.MemoryBytes the replay buffer bytes and Budget.MaxReturned the replay
// buffer entries; zero selects the service defaults and anything above the
// operator ceiling is rejected. Source is for raw.read scopes only.
// ResumeStreamID asks to continue a retained stream. Carrier is opaque
// transport state the HTTP layer keeps next to the ticket (never evaluated).
type LiveRequest struct {
	Projects       []model.ID    `json:"projects"`
	Profile        string        `json:"profile"`
	FeatureSet     string        `json:"feature_set"`
	Expression     string        `json:"expression"`
	Source         *model.ID     `json:"source,omitempty"`
	Budget         Budget        `json:"budget"`
	ResumeStreamID *LiveStreamID `json:"resume_stream_id,omitempty"`
	Carrier        []byte        `json:"-"`
}

// LiveTicket is the result of CreateLiveTicket.
type LiveTicket struct {
	ID        LiveTicketID   `json:"ticket"`
	ExpiresAt model.UnixNano `json:"expires_at"`
}

// LiveEventType closes the event union.
type LiveEventType string

const (
	// LiveOpen is the first event of every attachment; it names the stream and
	// carries the feed watermarks. It has no sequence.
	LiveOpen LiveEventType = "open"
	// LiveRecord is one committed record that passed the pipeline.
	LiveRecord LiveEventType = "record"
	// LiveGap states that data between its bounds was not delivered.
	LiveGap LiveEventType = "gap"
	// LiveHeartbeat proves the stream is alive and still authorized; it carries
	// the feed watermarks and has no sequence.
	LiveHeartbeat LiveEventType = "heartbeat"
	// LiveRevoke is terminal: authorization or deletion ended the stream.
	LiveRevoke LiveEventType = "revoke"
	// LiveError is terminal: a typed failure ended the stream or this attachment.
	LiveError LiveEventType = "error"
)

// Gap reasons. Every one is a statement of loss, never of completeness.
//
// Terminal reasons (LiveEvent.Reason on a revoke or error event) form a closed
// vocabulary: slow_consumer, superseded, deadline, scope_revoked, deleted,
// unavailable, feed_error (the committed feed failed), service_closed,
// corrupt_record (a feed row failed validation or named a project outside the
// stream), buffer_overflow (a record exceeded the stream's memory budget) and
// internal_error (a stream worker panicked: only that stream ends; the panic
// value is never reported).
const (
	GapFeedOverrun    = "feed_overrun"    // the committed feed overran this stream's subscription
	GapFeedCatchUp    = "feed_catch_up"   // commits between the cursors predate the subscription
	GapFeedOther      = "feed_gap"        // any other feed-reported gap
	GapReplayEvicted  = "replay_evicted"  // the replay buffer dropped events the consumer had not read
	GapReplayExpired  = "replay_expired"  // the retained stream is gone; this stream starts later
	GapPartialShard   = "partial_shard"   // a page was marked partial by the storage engine
	reasonSlow        = "slow_consumer"   // terminal reasons
	reasonSuperseded  = "superseded"      //
	reasonDeadline    = "deadline"        //
	reasonRevoked     = "scope_revoked"   //
	reasonDeleted     = "deleted"         //
	reasonUnavailable = "unavailable"     //
	reasonFeedError   = "feed_error"      //
	reasonClosed      = "service_closed"  //
	reasonCorrupt     = "corrupt_record"  //
	reasonQuota       = "buffer_overflow" //
	reasonInternal    = "internal_error"  //
)

// LiveGapInfo gives the exact bounds of a loss. FromSequence and ToSequence are
// the stream sequence numbers that were not delivered (inclusive; for a
// feed gap or an expired replay they are the one sequence the gap itself
// occupies). After and Through are committed-feed cursors: everything committed
// after After and up to Through may be missing. After is empty when the consumer
// position is unknown (replay_expired).
type LiveGapInfo struct {
	Reason       string         `json:"reason"`
	FromSequence model.Uint64   `json:"from_sequence"`
	ToSequence   model.Uint64   `json:"to_sequence"`
	After        []model.Cursor `json:"after,omitempty"`
	Through      []model.Cursor `json:"through,omitempty"`
}

// LiveEvent is the C06 live event union. Project identity is outside the
// language labels. Sequence is the SSE event ID of record and gap events; a
// reconnect supplies the last one it handled. Events are read-only values.
type LiveEvent struct {
	Type       LiveEventType  `json:"type"`
	StreamID   LiveStreamID   `json:"stream_id"`
	Sequence   model.Uint64   `json:"sequence,omitempty"`
	Project    *model.ID      `json:"project,omitempty"`
	Entry      *LogEntry      `json:"entry,omitempty"`
	Labels     model.Labels   `json:"labels,omitempty"`
	Cursors    []model.Cursor `json:"cursors,omitempty"`
	Gap        *LiveGapInfo   `json:"gap,omitempty"`
	Watermarks []model.Cursor `json:"watermarks,omitempty"`
	Reason     string         `json:"reason,omitempty"`
	Failure    *Failure       `json:"failure,omitempty"`
}

// Terminal reports whether no event can follow this one on its attachment.
func (e LiveEvent) Terminal() bool { return e.Type == LiveRevoke || e.Type == LiveError }

// LiveIterator delivers one attachment's events in order. After a terminal event
// it returns io.EOF. Close releases the attachment (the stream stays retained
// for replay until its window lapses) and is safe to call repeatedly.
type LiveIterator interface {
	Next(context.Context) (LiveEvent, error)
	Close() error
}

// LiveLimits are the operator bounds of the live service.
type LiveLimits struct {
	ReplayWindow time.Duration // replay retention and detached-stream lifetime
	TicketTTL    time.Duration
	Heartbeat    time.Duration

	DefaultDuration, MaxDuration time.Duration

	DefaultBufferBytes, MaxBufferBytes     int64
	DefaultBufferEntries, MaxBufferEntries uint64
	// WorkingBytes is per-stream pipeline headroom above the replay buffer.
	WorkingBytes int64

	MaxStreams, MaxStreamsPerOrg, MaxStreamsPerPrincipal int
	MaxTickets, MaxTicketsPerPrincipal                   int
}

// DefaultLiveLimits follow the approved design: 60 second replay and ticket
// lifetime, bounded buffers, bounded per-principal and per-organization
// connections (the storage change feed itself admits 32 subscriptions).
func DefaultLiveLimits() LiveLimits {
	return LiveLimits{
		ReplayWindow: 60 * time.Second, TicketTTL: 60 * time.Second, Heartbeat: 15 * time.Second,
		DefaultDuration: 15 * time.Minute, MaxDuration: time.Hour,
		DefaultBufferBytes: 4 << 20, MaxBufferBytes: 16 << 20,
		DefaultBufferEntries: 1024, MaxBufferEntries: 8192,
		WorkingBytes: 16 << 20,
		MaxStreams:   24, MaxStreamsPerOrg: 16, MaxStreamsPerPrincipal: 4,
		MaxTickets: 1024, MaxTicketsPerPrincipal: 16,
	}
}

func (l LiveLimits) validate() error {
	switch {
	case l.ReplayWindow <= 0 || l.TicketTTL <= 0 || l.Heartbeat <= 0,
		l.DefaultDuration <= 0 || l.MaxDuration < l.DefaultDuration,
		l.DefaultBufferBytes <= 0 || l.MaxBufferBytes < l.DefaultBufferBytes,
		l.DefaultBufferEntries == 0 || l.MaxBufferEntries < l.DefaultBufferEntries,
		l.WorkingBytes <= 0,
		l.MaxStreams < 1 || l.MaxStreamsPerOrg < 1 || l.MaxStreamsPerPrincipal < 1 || l.MaxStreamsPerOrg > l.MaxStreams || l.MaxStreamsPerPrincipal > l.MaxStreamsPerOrg,
		l.MaxTickets < 1 || l.MaxTicketsPerPrincipal < 1 || l.MaxTicketsPerPrincipal > l.MaxTickets:
		return model.Fail(model.Invalid)
	}
	return nil
}

// resolve applies defaults to a requested budget and rejects anything above the
// ceiling.
func (l LiveLimits) resolve(b Budget) (duration time.Duration, bytes int64, entries uint64, err error) {
	duration, bytes, entries = l.DefaultDuration, l.DefaultBufferBytes, l.DefaultBufferEntries
	if b.TimeoutNS < 0 {
		return 0, 0, 0, model.Fail(model.Invalid)
	}
	if b.TimeoutNS != 0 {
		if time.Duration(b.TimeoutNS) > l.MaxDuration {
			return 0, 0, 0, model.Fail(model.Invalid)
		}
		duration = time.Duration(b.TimeoutNS)
	}
	if b.MemoryBytes != 0 {
		if b.MemoryBytes > model.Uint64(l.MaxBufferBytes) {
			return 0, 0, 0, model.Fail(model.Invalid)
		}
		bytes = int64(b.MemoryBytes)
	}
	if b.MaxReturned != 0 {
		if uint64(b.MaxReturned) > l.MaxBufferEntries {
			return 0, 0, 0, model.Fail(model.Invalid)
		}
		entries = uint64(b.MaxReturned)
	}
	return duration, bytes, entries, nil
}

// LiveUsage is a consistent snapshot of live resources. After every stream has
// ended all counters are zero; LeakedBytes counts accounting violations.
type LiveUsage struct {
	Streams, Attached, Tickets int
	OpenIterators              int64
	MemoryUsed                 int64
	LeakedBytes                int64
	Goroutines                 int64
}

// LiveOption configures optional collaborators at construction.
type LiveOption func(*LiveService)

// WithLiveDeleteGenerations lets a stream detect a deletion that commits while
// it runs: the stream ends before any further record.
func WithLiveDeleteGenerations(d auth.DeleteGenerations) LiveOption {
	return func(s *LiveService) { s.deletes = d }
}

// WithLiveLimits replaces the default live limits.
func WithLiveLimits(l LiveLimits) LiveOption { return func(s *LiveService) { s.cfg = l } }

// WithLiveClock replaces the wall clock (ticket lifetime, replay retention).
func WithLiveClock(now func() time.Time) LiveOption { return func(s *LiveService) { s.now = now } }

type liveSessionKey struct{}

// WithLiveSession binds ticket creation and use to one authenticated session:
// the HTTP layer passes a digest of the presented credential, never the
// credential itself. A ticket created under one binding is refused under any
// other.
func WithLiveSession(ctx context.Context, binding string) context.Context {
	return context.WithValue(ctx, liveSessionKey{}, binding)
}

func liveSessionOf(ctx context.Context) string {
	v, _ := ctx.Value(liveSessionKey{}).(string)
	return v
}
