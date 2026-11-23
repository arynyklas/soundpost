// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package notify

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"slices"
	"sort"
	"strings"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

// This file is the event webhook feed (docs/operations/event-webhooks.md). Events
// are changes of committed state a receiver may want to hear about: an incident
// opened, acknowledged or resolved, an error issue seen for the first time,
// regressed or resolved, a release registered, and the console's test ping. They
// travel through the SAME durable fenced outbox as notifications: one
// control.DeliveryEnqueue per decision, with
//
//   - policy: EventPolicy(org, project), a deterministic ID per project;
//   - subject: EventSubject, so the committed state is the feed cursor below;
//   - intents: one per (event, subscribed endpoint), ID = hash of the event
//     identity and the endpoint, recipient = the endpoint's destination ID, route
//     immediate, kind KindEvent.
//
// The feed state is the durable cursor. It remembers, per incident, how many
// timeline entries have been announced; per issue, the workflow last announced
// and the last announced reopening; per release, that it was announced; and the
// last test request handled per endpoint. The producer (appcore) diffs committed
// state against it, and the new state and every intent commit in ONE transaction
// that expects the version read, so a replayed pass, a second leader or a crash
// between "enqueue" and "next pass" creates nothing twice and loses nothing.
//
// The state is NOT a PolicyState. Every reader that decodes the policy records
// of a project as PolicyState (Outbox.Due, SyncModes, the incident queue view)
// skips IsEventSubject records.

// EventSubject is the policy subject of the per-project event feed.
const EventSubject = "event:feed"

// IsEventSubject reports whether a policy or delivery subject belongs to the event
// webhook feed rather than to a notification subject ("kind:id").
func IsEventSubject(subject string) bool { return strings.HasPrefix(subject, "event:") }

// EventName is the closed set of event names a receiver sees.
type EventName string

// The events. TestPing is only ever produced by the console's test button.
const (
	EventIncidentOpened       EventName = "incident.opened"
	EventIncidentAcknowledged EventName = "incident.acknowledged"
	EventIncidentResolved     EventName = "incident.resolved"
	EventIssueNew             EventName = "issue.new"
	EventIssueRegressed       EventName = "issue.regressed"
	EventIssueResolved        EventName = "issue.resolved"
	EventIssueReopened        EventName = "issue.reopened"
	EventReleaseRegistered    EventName = "release.registered"
	EventTestPing             EventName = "test.ping"
)

// SubscribableEvents are the events an endpoint may subscribe to, in the order the
// console lists them. test.ping is not among them: it is delivered to the one
// endpoint that was tested, whatever it subscribes to.
func SubscribableEvents() []EventName {
	return []EventName{EventIncidentOpened, EventIncidentAcknowledged, EventIncidentResolved, EventIssueNew, EventIssueRegressed, EventIssueResolved, EventReleaseRegistered, EventIssueReopened}
}

// Subscribable reports whether an endpoint may subscribe to the event.
func (e EventName) Subscribable() bool { return slices.Contains(SubscribableEvents(), e) }

// Known reports whether the event is one of the closed set (test.ping included).
func (e EventName) Known() bool { return e == EventTestPing || e.Subscribable() }

// ordinal is the stable index of the event inside IntentKey.Ordinal.
func (e EventName) ordinal() uint64 {
	if e == EventTestPing {
		return uint64(len(SubscribableEvents())) + 1
	}
	if i := slices.Index(SubscribableEvents(), e); i >= 0 {
		return uint64(i) + 1
	}
	return 0
}

// EventPolicy is the policy ID of the project's event feed: deterministic, so
// every node and every pass names the same record.
func EventPolicy(org, project model.ID) model.ID {
	return commandID([]byte("event-feed-policy"), org[:], project[:])
}

// EventFact is the identifiers-only fact of a KindEvent delivery. The rest of the
// event is the Template's Entity (the incident, issue, release or endpoint),
// Project, Severity and Service. No text of any kind is part of it.
type EventFact struct {
	Event EventName `json:"event"`
	// OccurredAt is the time of the change: the incident timeline entry's time, or the
	// time this node detected the change for events that carry no committed time.
	OccurredAt model.UnixNano `json:"occurred_at_ns"`
	// Revision is the entity's committed revision or entry number the event is about.
	Revision uint64 `json:"revision,omitempty"`
	// Release is the release the event names (the regressing occurrence's release).
	Release *model.ID `json:"release_id,omitempty"`
}

// Feed limits. The marks of every class are bounded well below the 256 KiB the
// control state accepts for one policy state; the producer prunes the marks of
// entities that no longer exist, so the live bound is the control state's own
// (1024 incidents and 256 issues per project).
const (
	MaxIncidentMarks = 1100
	MaxIssueMarks    = 300
	MaxReleaseMarks  = 1536
	MaxTestMarks     = 64
	// MaxFeedEndpoints bounds the event endpoints of one organization so one event
	// never needs more intents than one enqueue carries.
	MaxFeedEndpoints = 32
	// MaxFeedIntents is the intents one commit carries (control accepts 64).
	MaxFeedIntents = 64
	// MaxFeedStateBytes bounds the encoded feed state (control accepts 256 KiB).
	MaxFeedStateBytes = 240 << 10
)

// Mark key prefixes: i:<incident>, s:<issue>, r:<release>.
const (
	markIncident = "i:"
	markIssue    = "s:"
	markRelease  = "r:"
)

// MarkKey is the key of an entity's mark.
func MarkKey(kind EntityKind, id model.ID) string {
	switch kind {
	case EntityIncident:
		return markIncident + id.String()
	case EntityIssue:
		return markIssue + id.String()
	case EntityRelease:
		return markRelease + id.String()
	}
	return ""
}

// FeedMark is what the feed remembers of one entity. Which fields are used
// depends on the entity: an incident's Through is the timeline entries announced; an
// issue's Workflow is the workflow last announced and Last the occurrence of the
// last announced reopening; a release's Built is its build time (the eviction
// order of the bounded set).
type FeedMark struct {
	Through  uint64         `json:"t,omitempty"`
	Workflow string         `json:"w,omitempty"`
	Last     *model.ID      `json:"l,omitempty"`
	Built    model.UnixNano `json:"b,omitempty"`
}

// EventFeedState is the durable cursor of one project's event feed.
type EventFeedState struct {
	Version int `json:"v"`
	// Baselined says the first pass recorded what already existed without announcing it.
	Baselined bool `json:"base"`
	// Floor: a release whose build time is at or below it and that has no mark was
	// evicted from the bounded set (or was past it at the baseline) and is never
	// announced.
	Floor model.UnixNano      `json:"floor,omitempty"`
	Marks map[string]FeedMark `json:"marks"`
	// Audit is how many entries of the control audit log the feed has read: issue resolves
	// and human reopenings are announced from the committed audit entries, in order.
	Audit uint64 `json:"a,omitempty"`
	// Tests is the last handled test request command per endpoint.
	Tests map[string]model.ID `json:"tests,omitempty"`
}

// NewFeedState is the state of a project that has no feed yet.
func NewFeedState() EventFeedState {
	return EventFeedState{Version: 1, Marks: map[string]FeedMark{}}
}

// ParseFeedState decodes a stored feed state; anything unreadable is corrupt.
func ParseFeedState(raw []byte) (EventFeedState, error) {
	var s EventFeedState
	if err := json.Unmarshal(raw, &s); err != nil || s.Version != 1 {
		return EventFeedState{}, model.Fail(model.Corrupt)
	}
	if s.Marks == nil {
		s.Marks = map[string]FeedMark{}
	}
	return s, nil
}

func (s EventFeedState) clone() EventFeedState {
	c := s
	c.Marks = make(map[string]FeedMark, len(s.Marks))
	for k, v := range s.Marks {
		c.Marks[k] = v
	}
	if s.Tests != nil {
		c.Tests = make(map[string]model.ID, len(s.Tests))
		for k, v := range s.Tests {
			c.Tests[k] = v
		}
	}
	return c
}

// Encode is the canonical, bounded encoding (map keys sorted by encoding/json).
func (s EventFeedState) Encode() ([]byte, error) {
	raw, err := json.Marshal(s)
	if err != nil {
		return nil, model.Fail(model.Invalid)
	}
	if len(raw) > MaxFeedStateBytes {
		return nil, model.Fail(model.Quota)
	}
	return raw, nil
}

// markCap is the bound of the mark's class.
func markCap(key string) int {
	switch {
	case strings.HasPrefix(key, markIncident):
		return MaxIncidentMarks
	case strings.HasPrefix(key, markIssue):
		return MaxIssueMarks
	case strings.HasPrefix(key, markRelease):
		return MaxReleaseMarks
	}
	return 0
}

// count is how many marks of the key's class exist.
func (s EventFeedState) count(prefix string) int {
	n := 0
	for k := range s.Marks {
		if strings.HasPrefix(k, prefix) {
			n++
		}
	}
	return n
}

// MarkUpdate is the change of the feed state that follows an event once it is
// committed with its intents: a mark set or deleted, or a test request handled.
type MarkUpdate struct {
	Key    string
	Mark   FeedMark
	Delete bool
	// TestEndpoint and TestCommand record a handled test request; a zero
	// TestCommand with a TestEndpoint forgets the endpoint.
	TestEndpoint model.ID
	TestCommand  model.ID
	// AuditTo moves the audit cursor (when non-zero).
	AuditTo uint64
}

// FeedEvent is one detected change. A FeedEvent with no Name is silent: it only
// moves a mark (an entry that is no event, a workflow change nobody subscribes to,
// the baseline, a pruned entity).
type FeedEvent struct {
	Name EventName
	// Entity is the incident, issue, release or (test.ping) endpoint.
	Entity Entity
	// Seq and Ref together are the identity of the event of that entity: the timeline
	// entry number, the issue revision, or the reopening occurrence or test command.
	Seq uint64
	Ref model.ID
	// At is the occurred-at time of the payload.
	At       model.UnixNano
	Severity Severity
	Release  *model.ID
	Service  *model.ID
	Revision uint64
	// Only restricts the event to one endpoint whatever it subscribes to (test.ping).
	Only   *model.ID
	Update MarkUpdate
}

// FeedEndpoint is one enabled event endpoint of the organization.
type FeedEndpoint struct {
	ID     model.ID
	Events []EventName
}

func (e FeedEndpoint) subscribes(name EventName) bool { return slices.Contains(e.Events, name) }

// EventPlan is the decision of one commit: the new state and the intents it
// carries.
type EventPlan struct {
	State   EventFeedState
	Intents []Intent
	// Applied is how many of the offered events the plan consumed; Remaining are
	// left for the next commit (the intent budget of one enqueue was reached).
	Applied, Remaining int
	// Full says an entity could not be remembered because its class is full; its
	// events were not announced (they are announced once room exists).
	Full bool
}

// apply applies one mark update. It reports false when the class is full (the
// state is unchanged) and handles the release set's eviction.
func (s *EventFeedState) apply(u MarkUpdate) bool {
	if u.AuditTo > 0 {
		s.Audit = max(s.Audit, u.AuditTo)
		return true
	}
	if u.TestEndpoint != (model.ID{}) {
		key := u.TestEndpoint.String()
		if u.TestCommand == (model.ID{}) {
			delete(s.Tests, key)
			return true
		}
		if _, known := s.Tests[key]; !known && len(s.Tests) >= MaxTestMarks {
			return false
		}
		if s.Tests == nil {
			s.Tests = map[string]model.ID{}
		}
		s.Tests[key] = u.TestCommand
		return true
	}
	if u.Key == "" {
		return true
	}
	if u.Delete {
		delete(s.Marks, u.Key)
		return true
	}
	_, known := s.Marks[u.Key]
	if !known && s.count(u.Key[:2]) >= markCap(u.Key) {
		if !strings.HasPrefix(u.Key, markRelease) {
			return false
		}
		// The release set evicts its lowest build time and remembers it as the floor.
		lowKey, low := u.Key, u.Mark
		for k, m := range s.Marks {
			if strings.HasPrefix(k, markRelease) && (m.Built < low.Built || m.Built == low.Built && k < lowKey) {
				lowKey, low = k, m
			}
		}
		if low.Built > s.Floor {
			s.Floor = low.Built
		}
		if lowKey == u.Key {
			return true // the newcomer is the lowest: not remembered, never announced again
		}
		delete(s.Marks, lowKey)
	}
	s.Marks[u.Key] = u.Mark
	return true
}

// Plan decides which of the events fit one commit: it consumes events in order
// until the intents would exceed MaxFeedIntents, applies each consumed event's
// mark update, and builds the intents of the events that are announced to an
// endpoint. baseline marks the first pass of a project: the plan then records
// state and announces nothing (every event of a baseline is silent).
func (s EventFeedState) Plan(org, project model.ID, events []FeedEvent, endpoints []FeedEndpoint, at model.UnixNano, baseline bool) (EventPlan, error) {
	policy := EventPolicy(org, project)
	plan := EventPlan{State: s.clone()}
	plan.State.Version = 1
	for i, ev := range events {
		var targets []model.ID
		if ev.Name != "" {
			if baseline || !ev.Name.Known() || ev.Entity.ID == (model.ID{}) {
				return EventPlan{}, refuse(model.Invalid, ReasonInvalidEvent)
			}
			for _, ep := range endpoints {
				if ev.Only != nil && ep.ID == *ev.Only || ev.Only == nil && ep.subscribes(ev.Name) {
					targets = append(targets, ep.ID)
				}
			}
		}
		if len(plan.Intents)+len(targets) > MaxFeedIntents {
			plan.Remaining = len(events) - i
			break
		}
		plan.Applied++
		if !plan.State.apply(ev.Update) {
			plan.Full = true
			continue // not remembered, so not announced
		}
		for _, ep := range targets {
			plan.Intents = append(plan.Intents, eventIntent(org, project, policy, ev, ep, at))
		}
	}
	if baseline && plan.Remaining == 0 {
		plan.State.Baselined = true
	}
	return plan, nil
}

// eventIntent is the intent of one event for one endpoint. Its ID is the hash of
// the event's identity and the endpoint: the same event of the same entity to the same
// endpoint is the same delivery, whatever pass, node or leader decides it.
func eventIntent(org, project, policy model.ID, ev FeedEvent, endpoint model.ID, at model.UnixNano) Intent {
	recipient := endpoint
	id := commandID([]byte("event-delivery"), org[:], project[:], policy[:], []byte(ev.Name), []byte(ev.Entity.Kind), ev.Entity.ID[:], u64(ev.Seq), ev.Ref[:], endpoint[:])
	occurred := ev.At
	if occurred <= 0 {
		occurred = at
	}
	t := Template{Entity: ev.Entity, Project: project, Severity: ev.Severity,
		Event: &EventFact{Event: ev.Name, OccurredAt: occurred, Revision: ev.Revision, Release: ev.Release}}
	if ev.Service != nil {
		t.Service = &ServiceRef{ID: *ev.Service}
	}
	return Intent{ID: id, Route: RouteImmediate, Disposition: DispositionDeliver, At: at, Cause: ev.Ref, Template: t,
		Key: IntentKey{Org: org, Policy: policy, Entity: ev.Entity, ImpactRevision: ev.Seq, Kind: KindEvent, Recipient: &recipient, Ordinal: ev.Name.ordinal()}}
}

// EventFeed is the committed feed of one project: its state and the version the
// next commit must expect (0: no record yet).
type EventFeed struct {
	Version model.Revision
	State   EventFeedState
}

// EventFeed reads the project's feed under scope (one project). A project with no
// feed yet answers a new state at version 0. A retired project's erased record is
// the typed NotFound: there is no feed to advance.
func (o *Outbox) EventFeed(ctx context.Context, scope auth.Scope) (EventFeed, error) {
	project, err := o.project(scope)
	if err != nil {
		return EventFeed{}, err
	}
	rec, found, err := o.store.PolicyRecord(ctx, scope, project, EventPolicy(scope.OrgID(), project), EventSubject)
	if err != nil {
		return EventFeed{}, err
	}
	if !found {
		return EventFeed{State: NewFeedState()}, nil
	}
	if len(rec.State) == 0 || bytes.Equal(rec.State, []byte("null")) {
		return EventFeed{}, model.Fail(model.NotFound)
	}
	state, err := ParseFeedState(rec.State)
	if err != nil {
		return EventFeed{}, err
	}
	return EventFeed{Version: rec.Version, State: state}, nil
}

// CommitEvents commits one plan as one control transaction: the new feed state,
// version-checked against the feed that was read, together with every intent. The
// lease is validated against a fresh quorum observation first and control compares it with the
// highest lease the project's outbox accepted, exactly as for a notification. A plan that
// changes nothing is not committed (Unchanged). A lost version race is the control
// conflict (delivery_policy_conflict): the caller reads the feed again next pass.
func (o *Outbox) CommitEvents(ctx context.Context, scope auth.Scope, lease FenceToken, feed EventFeed, plan EventPlan, at model.UnixNano) (Submission, error) {
	project, err := o.project(scope)
	if err != nil {
		return Submission{}, err
	}
	if err = validLease(lease); err != nil || at <= 0 {
		return Submission{}, model.Fail(model.Invalid)
	}
	if err = o.fencer.ValidateFence(ctx, lease); err != nil {
		return Submission{}, fenceFault(err)
	}
	nextRaw, err := plan.State.Encode()
	if err != nil {
		return Submission{}, err
	}
	if len(plan.Intents) == 0 && feed.Version != 0 {
		if prev, e := feed.State.Encode(); e == nil && bytes.Equal(prev, nextRaw) {
			return Submission{Version: feed.Version, Unchanged: true}, nil
		}
	}
	policy := EventPolicy(scope.OrgID(), project)
	enqueue := control.DeliveryEnqueue{Project: project, Policy: policy, Subject: EventSubject, ExpectedVersion: feed.Version, NewVersion: feed.Version + 1, At: at,
		State: nextRaw, Digest: model.Hash(sha256.Sum256(nextRaw))}
	intents := sha256.New()
	for _, in := range plan.Intents {
		body, err := json.Marshal(Delivery{ID: in.ID, Key: in.Key, Route: in.Route, Template: in.Template})
		if err != nil {
			return Submission{}, model.Fail(model.Invalid)
		}
		from := in.Template.Event.OccurredAt
		di := control.DeliveryIntent{ID: in.ID, Kind: string(in.Key.Kind), Disposition: string(in.Disposition), Route: string(in.Route),
			Recipient: in.Key.Recipient, At: in.At, OriginFrom: from, OriginTo: from, Body: body, Digest: model.Hash(sha256.Sum256(body))}
		enqueue.Intents = append(enqueue.Intents, di)
		intents.Write(di.ID[:])
		intents.Write(di.Digest[:])
	}
	// The command identity binds the state AND every intent: two decisions that reach the
	// same state with different deliveries are never mistaken for one replayed command.
	id := commandID([]byte("event-enqueue"), orgBytes(scope), project[:], policy[:], u64(uint64(feed.Version)), enqueue.Digest[:], intents.Sum(nil))
	if _, err = o.transact(ctx, scope, control.KindClaimDelivery, id, control.DeliveryCommand{Operation: control.DeliveryOpEnqueue, Lease: &lease, Enqueue: &enqueue}); err != nil {
		return Submission{}, err
	}
	return Submission{Version: enqueue.NewVersion, Intents: plan.Intents}, nil
}

// SortedEndpoints orders endpoints by ID, the deterministic order intents are built in.
func SortedEndpoints(list []FeedEndpoint) []FeedEndpoint {
	out := append([]FeedEndpoint(nil), list...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID.String() < out[j].ID.String() })
	return out
}
