// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"sort"
	"strings"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/incidents"
	"github.com/arynyklas/soundpost/internal/issues"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/notify"
	"github.com/arynyklas/soundpost/internal/replica"
)

// EventProducer is the leader-only stage that turns committed state into event
// webhook deliveries (docs/operations/event-webhooks.md): an incident opened,
// acknowledged or resolved; an error issue new, regressed or resolved; a release
// registered; and the console's test pings. It diffs the project's committed
// incidents, issues and releases against the durable feed state (notify.EventFeedState)
// and commits the new state together with one delivery per (event, subscribed
// endpoint) in one fenced transaction (notify.Outbox.CommitEvents).
//
//   - The first pass for a project is a BASELINE: it records what exists without
//     announcing it, so a node that starts producing events never floods history.
//   - Events are produced whether or not an endpoint subscribes (the marks always
//     advance), so an endpoint added later receives only what happens after it;
//     only enabled endpoints subscribed to the event get a delivery.
//   - A pass is idempotent and crash-safe: marks and deliveries commit together and
//     the delivery IDs are deterministic, so a replayed pass, a second leader or a
//     crash between the commit and the next pass creates nothing twice and loses
//     nothing.
//   - Changes that complete inside one pass interval collapse into what the state
//     says at the pass: an issue resolved and reopened by a human between two passes
//     produces no event for either (a regression produces issue.regressed from the
//     lifecycle's own reopening record, even then).
//   - occurred_at of an incident event is its timeline entry's time; of an issue or
//     release event, the time this node detected the change.
//
// Only identifiers, enums and times are decoded or emitted. No text of an incident,
// issue or release is read.
func (a *App) EventProducer() Producer { return &eventProducer{app: a} }

type eventProducer struct{ app *App }

// eventPassCommits bounds the commits one Produce call makes (each carries at most
// notify.MaxFeedIntents deliveries); a backlog drains over consecutive passes.
const eventPassCommits = 4

func (p *eventProducer) Produce(ctx context.Context, scopes ProducerScopes, lease replica.FenceToken) (int, error) {
	if err := p.app.leaseGate(ctx, lease); err != nil {
		return 0, err
	}
	admin, err := scopes.Scope(ctx, auth.OrgAdmin)
	if err != nil {
		return 0, err
	}
	write, err := scopes.Scope(ctx, auth.IssuesWrite)
	if err != nil {
		return 0, err
	}
	group := p.app.Control.ReplicaGroup()
	if group == nil {
		return 0, model.Fail(model.Unavailable)
	}
	outbox, err := notify.NewOutbox(p.app.Control, group, scopesClock{scopes})
	if err != nil {
		return 0, err
	}
	committed := 0
	var sticky error
	for range eventPassCommits {
		feed, err := outbox.EventFeed(ctx, admin)
		if isNotFound(err) {
			return committed, nil // a retired project has no feed
		}
		if err != nil {
			return committed, err
		}
		obs, err := p.observe(ctx, admin, write, scopes, feed.State)
		if err != nil {
			return committed, err
		}
		now := scopes.Now()
		plan, err := feed.State.Plan(scopes.Org(), scopes.Project(), obs.events, obs.endpoints, now, !feed.State.Baselined)
		if err != nil {
			return committed, err
		}
		sub, err := outbox.CommitEvents(ctx, admin, lease, feed, plan, now)
		if err != nil {
			return committed, err
		}
		committed += len(sub.Intents)
		if plan.Full {
			sticky = quotaFault("event_feed_full")
		}
		if obs.corrupt {
			sticky = model.Fail(model.Corrupt)
		}
		if plan.Remaining == 0 {
			break
		}
	}
	return committed, sticky
}

func isNotFound(err error) bool {
	var f *model.Fault
	return errors.As(err, &f) && f.Code == model.NotFound
}

func quotaFault(detail string) error {
	f := model.Fail(model.Quota)
	f.SafeDetail = detail
	return f
}

// eventObservation is what one pass saw: the events to offer the plan (in order),
// the enabled endpoints, and whether a record was unreadable.
type eventObservation struct {
	events    []notify.FeedEvent
	endpoints []notify.FeedEndpoint
	corrupt   bool
}

// observe diffs the project's committed state against the feed state.
func (p *eventProducer) observe(ctx context.Context, admin, write auth.Scope, scopes ProducerScopes, state notify.EventFeedState) (eventObservation, error) {
	var obs eventObservation
	baseline := !state.Baselined
	now := scopes.Now()
	org, project := scopes.Org(), scopes.Project()
	live := map[string]bool{}

	endpoints, tests, err := p.endpoints(ctx, org, project)
	if err != nil {
		return obs, err
	}
	obs.endpoints = notify.SortedEndpoints(endpoints)

	incidentEvents, corrupt, err := p.incidentEvents(ctx, admin, project, state, baseline, live)
	if err != nil {
		return obs, err
	}
	obs.corrupt = corrupt
	issueEvents, err := p.issueEvents(ctx, write, project, state, baseline, now, live)
	if err != nil {
		return obs, err
	}
	auditEvents, err := p.auditEvents(ctx, org, project, live, state, baseline, now)
	if err != nil {
		return obs, err
	}
	releaseEvents, err := p.releaseEvents(ctx, admin, org, project, state, baseline, now, live)
	if err != nil {
		return obs, err
	}
	var all []notify.FeedEvent
	all = append(all, incidentEvents...)
	all = append(all, auditEvents...)
	all = append(all, issueEvents...)
	all = append(all, releaseEvents...)
	all = append(all, testEvents(tests, state, baseline, now)...)
	// Chronological, ties in generation order (which keeps every entity's own events in
	// order: an entity's events never go backwards in time).
	sort.SliceStable(all, func(i, j int) bool { return all[i].At < all[j].At })
	obs.events = append(all, pruneEvents(state, live, tests, now)...)
	return obs, nil
}

// endpoints reads the organization's enabled event endpoints and the pending test
// requests of this project (endpoint -> command), from committed state.
func (p *eventProducer) endpoints(ctx context.Context, org, project model.ID) ([]notify.FeedEndpoint, map[model.ID]model.ID, error) {
	var out []notify.FeedEndpoint
	tests := map[model.ID]model.ID{}
	err := p.app.Control.View(ctx, func(st model.ControlState) error {
		if _, retired := st.RetiredOrgs[org.String()]; retired {
			return model.Fail(model.NotFound)
		}
		o, ok := st.Orgs[org.String()]
		if !ok {
			return model.Fail(model.NotFound)
		}
		for key, raw := range o.Settings {
			switch {
			case strings.HasPrefix(key, "destination:"):
				id, err := model.ParseID(strings.TrimPrefix(key, "destination:"))
				if err != nil {
					continue
				}
				var cfg auth.DestinationConfig
				if json.Unmarshal(raw, &cfg) != nil {
					return model.Fail(model.Corrupt)
				}
				if cfg.Type != auth.EventWebhookType || !cfg.Enabled {
					continue
				}
				ep := notify.FeedEndpoint{ID: id}
				for _, name := range cfg.Events {
					if n := notify.EventName(name); n.Subscribable() {
						ep.Events = append(ep.Events, n)
					}
				}
				out = append(out, ep)
			case strings.HasPrefix(key, "event_test:"):
				id, err := model.ParseID(strings.TrimPrefix(key, "event_test:"))
				if err != nil {
					continue
				}
				var cfg auth.EventTestConfig
				if json.Unmarshal(raw, &cfg) != nil {
					return model.Fail(model.Corrupt)
				}
				if cfg.Project == project && cfg.Command != nil {
					tests[id] = *cfg.Command
				}
			}
		}
		return nil
	})
	return out, tests, err
}

// testEvents turns each test request this project's feed has not handled into one
// test.ping to that endpoint. A test request is a request, not history: the baseline
// (which announces nothing) leaves it unrecorded, so the next pass answers it, once.
func testEvents(tests map[model.ID]model.ID, state notify.EventFeedState, baseline bool, now model.UnixNano) []notify.FeedEvent {
	if baseline {
		return nil
	}
	ids := make([]model.ID, 0, len(tests))
	for id := range tests {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i].String() < ids[j].String() })
	var out []notify.FeedEvent
	for _, id := range ids {
		command := tests[id]
		if state.Tests[id.String()] == command {
			continue
		}
		endpoint := id
		out = append(out, notify.FeedEvent{At: now, Name: notify.EventTestPing, Entity: notify.Entity{Kind: notify.EntityEndpoint, ID: id}, Ref: command, Only: &endpoint,
			Update: notify.MarkUpdate{TestEndpoint: id, TestCommand: command}})
	}
	return out
}

// pruneEvents drops the marks of entities that no longer exist (an incident a
// deletion erased, an issue or release that is gone) and the test marks of requests
// that no longer exist, so the state stays as small as the live data.
func pruneEvents(state notify.EventFeedState, live map[string]bool, tests map[model.ID]model.ID, now model.UnixNano) []notify.FeedEvent {
	var out []notify.FeedEvent
	keys := make([]string, 0, len(state.Marks))
	for key := range state.Marks {
		if !live[key] {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	for _, key := range keys {
		out = append(out, notify.FeedEvent{At: now, Update: notify.MarkUpdate{Key: key, Delete: true}})
	}
	forgotten := make([]string, 0, len(state.Tests))
	for key := range state.Tests {
		if id, err := model.ParseID(key); err != nil || tests[id] == (model.ID{}) {
			forgotten = append(forgotten, key)
		}
	}
	sort.Strings(forgotten)
	for _, key := range forgotten {
		if id, err := model.ParseID(key); err == nil {
			out = append(out, notify.FeedEvent{At: now, Update: notify.MarkUpdate{TestEndpoint: id}})
		}
	}
	return out
}

// incidentEvents maps the timeline entries the feed has not announced to events:
// open, ack and resolve entries are events, every other entry only moves the mark.
func (p *eventProducer) incidentEvents(ctx context.Context, admin auth.Scope, project model.ID, state notify.EventFeedState, baseline bool, live map[string]bool) ([]notify.FeedEvent, bool, error) {
	records, err := p.app.Control.Incidents(ctx, admin, project)
	if err != nil {
		return nil, false, err
	}
	var out []notify.FeedEvent
	corrupt := false
	for _, rec := range records {
		if rec.Erased() {
			continue
		}
		key := notify.MarkKey(notify.EntityIncident, rec.ID)
		var st incidents.State
		if json.Unmarshal(rec.State, &st) != nil || st.ID != rec.ID || st.Version != rec.Version {
			live[key] = true // keep what we know of it; never re-announce on a bad read
			corrupt = true
			continue
		}
		live[key] = true
		timeline := st.Timeline
		mark, known := state.Marks[key]
		if baseline {
			out = append(out, notify.FeedEvent{At: lastAt(timeline), Update: notify.MarkUpdate{Key: key, Mark: notify.FeedMark{Through: uint64(len(timeline))}}})
			continue
		}
		if known && mark.Through >= uint64(len(timeline)) {
			continue
		}
		entity := notify.Entity{Kind: notify.EntityIncident, ID: rec.ID}
		var service, release *model.ID
		for _, l := range st.Links {
			link := l
			switch {
			case l.Kind == incidents.LinkService && service == nil:
				service = &link.ID
			case l.Kind == incidents.LinkRelease && release == nil:
				release = &link.ID
			}
		}
		var at model.UnixNano
		for k, entry := range timeline {
			at = max(at, entry.At) // an entity's events never go backwards in time
			if uint64(k) < mark.Through {
				continue
			}
			ev := notify.FeedEvent{Entity: entity, Seq: uint64(k + 1), At: at, Revision: uint64(k + 1), Update: notify.MarkUpdate{Key: key, Mark: notify.FeedMark{Through: uint64(k + 1)}}}
			switch entry.Action.Type {
			case incidents.TypeOpen:
				ev.Name = notify.EventIncidentOpened
			case incidents.TypeAck:
				ev.Name = notify.EventIncidentAcknowledged
			case incidents.TypeResolve:
				ev.Name = notify.EventIncidentResolved
			}
			if ev.Name != "" {
				sev := st.Severity
				if entry.Action.Type == incidents.TypeOpen && entry.Action.Impact != nil {
					sev = entry.Action.Impact.Severity
				}
				if sev >= incidents.SeverityMinor && sev <= incidents.SeverityCritical {
					ev.Severity = notify.Severity(sev)
				}
				ev.Service, ev.Release = service, release
			}
			out = append(out, ev)
		}
	}
	return out, corrupt, nil
}

func lastAt(timeline []incidents.Entry) model.UnixNano {
	var at model.UnixNano
	for _, e := range timeline {
		at = max(at, e.At)
	}
	return at
}

// issueEvents maps the issue lifecycle to events: an issue the feed has not seen is
// issue.new; every reopening after the last announced one is issue.regressed (the
// lifecycle never prunes a reopening evaluation); an issue that is resolved and was
// not announced as resolved (or that reopened and resolved again since) is
// issue.resolved.
func (p *eventProducer) issueEvents(ctx context.Context, write auth.Scope, project model.ID, state notify.EventFeedState, baseline bool, now model.UnixNano, live map[string]bool) ([]notify.FeedEvent, error) {
	store, err := issues.NewControlStore(p.app.Control)
	if err != nil {
		return nil, err
	}
	book, err := store.Load(ctx, write, project)
	if err != nil {
		return nil, err
	}
	ids := make([]model.ID, 0, len(book.Issues))
	for id := range book.Issues {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i].String() < ids[j].String() })
	var out []notify.FeedEvent
	for _, id := range ids {
		rec := book.Issues[id]
		key := notify.MarkKey(notify.EntityIssue, id)
		live[key] = true
		workflow := knownWorkflow(rec.Issue.Workflow)
		var reopened []model.ID
		for _, x := range rec.Explanations {
			if x.Reopened {
				reopened = append(reopened, x.OccurrenceID)
			}
		}
		if baseline {
			mark := notify.FeedMark{Workflow: workflow}
			if n := len(reopened); n > 0 {
				mark.Last = &reopened[n-1]
			}
			out = append(out, notify.FeedEvent{At: now, Update: notify.MarkUpdate{Key: key, Mark: mark}})
			continue
		}
		entity := notify.Entity{Kind: notify.EntityIssue, ID: id}
		revision := uint64(rec.Issue.Revision)
		cur, known := state.Marks[key]
		step := func(name notify.EventName, ref model.ID, seq uint64, mark notify.FeedMark) notify.FeedEvent {
			cur = mark
			return notify.FeedEvent{Name: name, Entity: entity, Seq: seq, Ref: ref, At: now, Revision: revision, Update: notify.MarkUpdate{Key: key, Mark: mark}}
		}
		var evs []notify.FeedEvent
		if !known {
			evs = append(evs, step(notify.EventIssueNew, model.ID{}, 0, notify.FeedMark{Workflow: "open"}))
		}
		fresh := reopened
		if cur.Last != nil {
			if i := slices.Index(reopened, *cur.Last); i >= 0 {
				fresh = reopened[i+1:]
			}
		}
		for _, occurrence := range fresh {
			ev := step(notify.EventIssueRegressed, occurrence, 0, notify.FeedMark{Workflow: "open", Last: &occurrence})
			for _, x := range rec.Explanations {
				if x.Reopened && x.OccurrenceID == occurrence && x.EvidenceRelease != (model.ID{}) {
					release := x.EvidenceRelease
					ev.Release = &release
				}
			}
			evs = append(evs, ev)
		}
		switch {
		case workflow != "" && workflow != cur.Workflow:
			e := step("", model.ID{}, 0, notify.FeedMark{Workflow: workflow, Last: cur.Last})
			evs = append(evs, e)
		}
		out = append(out, evs...)
	}
	return out, nil
}

// knownWorkflow keeps a workflow value the mark can hold: the closed set, else "".
func knownWorkflow(w string) string {
	switch w {
	case "open", "resolved", "ignored":
		return w
	}
	return ""
}

// releaseEvents announces releases the feed has not seen. At the baseline the newest
// releases fill the bounded set and the rest fall under the floor (notify.EventFeedState).
func (p *eventProducer) releaseEvents(ctx context.Context, admin auth.Scope, org, project model.ID, state notify.EventFeedState, baseline bool, now model.UnixNano, live map[string]bool) ([]notify.FeedEvent, error) {
	type built struct {
		id model.ID
		at model.UnixNano
	}
	var found []built
	err := p.app.Control.View(ctx, func(st model.ControlState) error {
		if err := admin.ValidateControlState(st); err != nil {
			return err
		}
		for _, r := range st.Releases {
			if r.Org == org && r.Project == project {
				found = append(found, built{id: r.ID, at: r.BuildTime})
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(found, func(i, j int) bool {
		if found[i].at != found[j].at {
			return found[i].at > found[j].at
		}
		return found[i].id.String() < found[j].id.String()
	})
	var out []notify.FeedEvent
	for _, r := range found {
		key := notify.MarkKey(notify.EntityRelease, r.id)
		_, known := state.Marks[key]
		if baseline {
			out = append(out, notify.FeedEvent{At: now, Update: notify.MarkUpdate{Key: key, Mark: notify.FeedMark{Built: r.at}}})
			live[key] = true
			continue
		}
		if known {
			live[key] = true
			continue
		}
		if state.Floor > 0 && r.at <= state.Floor {
			continue // evicted from the bounded set: never announced
		}
		live[key] = true
		out = append(out, notify.FeedEvent{Name: notify.EventReleaseRegistered, Entity: notify.Entity{Kind: notify.EntityRelease, ID: r.id}, At: now,
			Update: notify.MarkUpdate{Key: key, Mark: notify.FeedMark{Built: r.at}}})
	}
	return out, nil
}

// auditEvents announces the human resolves and reopenings of the project's issues from the
// append-only control audit log, in log order, from the feed's audit cursor (the baseline
// starts at the current length). A resolve and the regression that reopens the issue inside
// one pass are two committed facts with their own audit entry and reopening record, so both
// are announced, each once, under distinct delivery IDs (the audit entry ID is the identity).
func (p *eventProducer) auditEvents(ctx context.Context, org, project model.ID, live map[string]bool, state notify.EventFeedState, baseline bool, now model.UnixNano) ([]notify.FeedEvent, error) {
	var out []notify.FeedEvent
	err := p.app.Control.View(ctx, func(st model.ControlState) error {
		n := uint64(len(st.Audits))
		if baseline {
			out = append(out, notify.FeedEvent{At: now, Update: notify.MarkUpdate{AuditTo: n}})
			return nil
		}
		if state.Audit >= n {
			return nil
		}
		for i := state.Audit; i < n; i++ {
			a := st.Audits[i]
			ev := notify.FeedEvent{At: now, Update: notify.MarkUpdate{AuditTo: i + 1}}
			var name notify.EventName
			switch a.Action {
			case "issues.resolve":
				name = notify.EventIssueResolved
			case "issues.reopen":
				name = notify.EventIssueReopened
			}
			if name != "" && a.Org == org.String() && len(a.Targets) > 0 && a.Outcome == model.AuditAllowed {
				if live[notify.MarkKey(notify.EntityIssue, a.Targets[0])] {
					ev.Name, ev.Entity, ev.Ref = name, notify.Entity{Kind: notify.EntityIssue, ID: a.Targets[0]}, a.ID
				}
			}
			out = append(out, ev)
		}
		return nil
	})
	return out, err
}
