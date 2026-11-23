// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/notify"
)

// This file is the event webhook endpoint surface (POST /api/v1/events/webhooks,
// docs/operations/console-api.md section 9): list, save, test and deliveries of the
// organization's event endpoints. An endpoint is a destination of type
// event_webhook (auth.EventWebhookType), written by the audited `destination` admin
// command, so the secret is sealed, write-only and rotates with a 24 hour overlap.
// Everything here needs an organization administrator; anyone else gets the same
// not_found a missing organization gives. The deliveries are the outbox records of
// the feed (notify.EventSubject) of the organization's projects, read project by
// project under the caller's own administrator scope.

// Event webhook operations.
const (
	EventsList       = "list"
	EventsSave       = "save"
	EventsTest       = "test"
	EventsDeliveries = "deliveries"
)

// Bounds of the endpoint surface.
const (
	// MaxEventProjects bounds the projects whose deliveries one answer reads; an
	// organization with more answers state "incomplete", reason projects_capped.
	MaxEventProjects = 64
	// DefaultEventDeliveries and MaxEventDeliveries bound the deliveries list.
	DefaultEventDeliveries = 50
	MaxEventDeliveries     = 200
)

// EventWebhookRequest is the closed POST /api/v1/events/webhooks body. Endpoint is
// the endpoint object of a save and the endpoint ID of test and deliveries.
type EventWebhookRequest struct {
	Org             model.ID        `json:"org"`
	Op              string          `json:"op"`
	CommandID       model.ID        `json:"command_id,omitempty"`
	ExpectedVersion *model.Uint64   `json:"expected_version,omitempty"`
	Reason          string          `json:"reason,omitempty"`
	Endpoint        json.RawMessage `json:"endpoint,omitempty"`
	// Project names the project whose feed carries a test ping; the first project of
	// the organization by ID when absent.
	Project model.ID `json:"project,omitempty"`
	Limit   int      `json:"limit,omitempty"`
}

// EventEndpointChange is the endpoint object of a save. URL may be left out for an
// existing endpoint (the console never receives the path of the URL, which may carry
// a token): it then stays as committed. Secret is write-only; sending one rotates.
type EventEndpointChange struct {
	ID      model.ID `json:"id"`
	Name    string   `json:"name,omitempty"`
	URL     string   `json:"url,omitempty"`
	Events  []string `json:"events"`
	Enabled bool     `json:"enabled"`
	Secret  string   `json:"secret,omitempty"`
}

// EventDeliveryView is one delivery of an endpoint: identifiers, enums, counts and
// closed codes. Uncertain says the receiver may have accepted it without the product
// being able to confirm.
type EventDeliveryView struct {
	ID                model.ID     `json:"id"`
	Event             string       `json:"event"`
	EntityKind        string       `json:"entity_kind"`
	EntityID          model.ID     `json:"entity_id"`
	Project           model.ID     `json:"project"`
	Phase             string       `json:"phase"`
	Status            string       `json:"status"`
	Code              string       `json:"code,omitempty"`
	Attempts          uint32       `json:"attempts"`
	Uncertain         bool         `json:"uncertain,omitempty"`
	PossibleDuplicate bool         `json:"possible_duplicate,omitempty"`
	LastOutcome       string       `json:"last_outcome,omitempty"`
	LastCode          string       `json:"last_code,omitempty"`
	LastAt            *model.Int64 `json:"last_at,omitempty"`
	NextAt            *model.Int64 `json:"next_at,omitempty"`
	Eligible          model.Int64  `json:"eligible_at"`
}

// EventEndpointView is an endpoint as the console shows it: never the URL beyond its
// host, never the secret. State is words: working (the newest attempted delivery was
// accepted), retrying, failing (the newest attempted delivery failed or is uncertain),
// pending (deliveries exist but none was attempted yet) or no_deliveries.
type EventEndpointView struct {
	ID                  model.ID           `json:"id"`
	Name                string             `json:"name"`
	Host                string             `json:"host"`
	Events              []string           `json:"events"`
	Enabled             bool               `json:"enabled"`
	HasSecret           bool               `json:"has_secret"`
	Version             model.Uint64       `json:"version"`
	SecretRotatedAt     *model.Int64       `json:"secret_rotated_at,omitempty"`
	PreviousSecretUntil *model.Int64       `json:"previous_secret_until,omitempty"`
	State               string             `json:"state"`
	LastDelivery        *EventDeliveryView `json:"last_delivery,omitempty"`
}

// EventWebhookListAnswer answers list. State is ready, or incomplete (reason
// projects_capped) when some projects' deliveries were not read: the endpoint states
// then cover only the projects read.
type EventWebhookListAnswer struct {
	Org       model.ID            `json:"org"`
	State     ViewState           `json:"state"`
	Reason    string              `json:"reason,omitempty"`
	Endpoints []EventEndpointView `json:"endpoints"`
	Events    []string            `json:"events"`
}

// EventWebhookSaveAnswer answers a committed save: the endpoint as committed.
type EventWebhookSaveAnswer struct {
	State    ActionState       `json:"state"`
	Endpoint EventEndpointView `json:"endpoint"`
}

// EventWebhookTestAnswer answers a test request. The ping is created by the leader's
// next worker pass, in the feed of Project, and then appears in the deliveries.
type EventWebhookTestAnswer struct {
	State    string   `json:"state"`
	Endpoint model.ID `json:"endpoint"`
	Project  model.ID `json:"project"`
}

// EventWebhookDeliveriesAnswer answers deliveries, newest first.
type EventWebhookDeliveriesAnswer struct {
	Org        model.ID            `json:"org"`
	Endpoint   model.ID            `json:"endpoint"`
	State      ViewState           `json:"state"`
	Reason     string              `json:"reason,omitempty"`
	Deliveries []EventDeliveryView `json:"deliveries"`
}

// EventWebhooks serves the event endpoint surface.
type EventWebhooks struct {
	authority *auth.Service
	directory Directory
	notices   NotificationReader
	clock     ActionClock
}

// NewEventWebhooks requires every dependency.
func NewEventWebhooks(authority *auth.Service, directory Directory, notices NotificationReader, clock ActionClock) (*EventWebhooks, error) {
	if authority == nil || directory == nil || notices == nil || clock == nil {
		return nil, model.Fail(model.Invalid)
	}
	return &EventWebhooks{authority: authority, directory: directory, notices: notices, clock: clock}, nil
}

// endpointRecord is an endpoint as committed: its config and whether its sealed
// secret exists.
type endpointRecord struct {
	ID        model.ID
	Cfg       auth.DestinationConfig
	HasSecret bool
}

// orgState reads, in one view, the organization's policy epoch, its event endpoints
// (ID order) and its projects (ID order).
func (e *EventWebhooks) orgState(ctx context.Context, org model.ID) (epoch model.Uint64, endpoints []endpointRecord, projects []model.ID, err error) {
	err = e.directory.View(ctx, func(st control.State) error {
		o, ok := st.Orgs[org.String()]
		if !ok {
			return model.Fail(model.NotFound)
		}
		if _, retired := st.RetiredOrgs[org.String()]; retired {
			return model.Fail(model.NotFound)
		}
		epoch = model.Uint64(o.Epoch)
		for key, raw := range o.Settings {
			rest, found := strings.CutPrefix(key, "destination:")
			if !found {
				continue
			}
			id, perr := model.ParseID(rest)
			if perr != nil {
				continue
			}
			var cfg auth.DestinationConfig
			if json.Unmarshal(raw, &cfg) != nil {
				return model.Fail(model.Corrupt)
			}
			if cfg.Type == auth.EventWebhookType {
				endpoints = append(endpoints, endpointRecord{ID: id, Cfg: cfg, HasSecret: o.Secrets[key] != ""})
			}
		}
		for key := range o.Projects {
			id, perr := model.ParseID(key)
			if perr != nil {
				return model.Fail(model.Corrupt)
			}
			projects = append(projects, id)
		}
		return nil
	})
	sort.Slice(endpoints, func(i, j int) bool { return endpoints[i].ID.String() < endpoints[j].ID.String() })
	sort.Slice(projects, func(i, j int) bool { return projects[i].String() < projects[j].String() })
	return
}

// gather reads the feed deliveries of the organization's projects (at most
// MaxEventProjects), each under the caller's own administrator scope of that
// project, grouped by endpoint. capped says projects were left out.
func (e *EventWebhooks) gather(ctx context.Context, credential auth.Credential, org model.ID, projects []model.ID) (map[model.ID][]control.DeliveryRecord, bool, error) {
	out := map[model.ID][]control.DeliveryRecord{}
	capped := len(projects) > MaxEventProjects
	if capped {
		projects = projects[:MaxEventProjects]
	}
	now := e.clock.Now()
	for _, project := range projects {
		scope, err := e.authority.Authorize(ctx, credential, org, []model.ID{project}, auth.OrgAdmin)
		if err != nil {
			return nil, false, err
		}
		recs, err := e.notices.Deliveries(ctx, scope, project, "", now, 0)
		if err != nil {
			return nil, false, err
		}
		for _, r := range recs {
			if r.Subject == notify.EventSubject && r.Recipient != nil {
				out[*r.Recipient] = append(out[*r.Recipient], r)
			}
		}
	}
	for _, list := range out {
		sortDeliveries(list)
	}
	return out, capped, nil
}

// sortDeliveries orders newest first (eligible time, then ID).
func sortDeliveries(list []control.DeliveryRecord) {
	sort.SliceStable(list, func(i, j int) bool {
		if list[i].Eligible != list[j].Eligible {
			return list[i].Eligible > list[j].Eligible
		}
		return list[i].ID.String() > list[j].ID.String()
	})
}

func eventDeliveryView(r control.DeliveryRecord) (EventDeliveryView, error) {
	var d notify.Delivery
	if json.Unmarshal(r.Body, &d) != nil || d.Key.Kind != notify.KindEvent || d.Template.Event == nil {
		return EventDeliveryView{}, model.Fail(model.Corrupt)
	}
	v := EventDeliveryView{ID: r.ID, Event: string(d.Template.Event.Event), EntityKind: string(d.Template.Entity.Kind), EntityID: d.Template.Entity.ID, Project: r.Project, Phase: r.Phase,
		Status: deliveryStatus(r), Code: r.Code, Attempts: uint32(len(r.Attempts)), Uncertain: r.Uncertain, PossibleDuplicate: r.PossibleDuplicate, Eligible: model.Int64(r.Eligible)}
	if r.Open() && r.Next > 0 {
		next := model.Int64(r.Next)
		v.NextAt = &next
	}
	for j := len(r.Attempts) - 1; j >= 0; j-- {
		if a := r.Attempts[j]; a.Outcome != "" {
			v.LastOutcome, v.LastCode = a.Outcome, a.Code
			at := model.Int64(a.ClosedAt)
			v.LastAt = &at
			break
		}
	}
	return v, nil
}

// endpointState is the one word for an endpoint and the delivery it rests on. recs
// are newest first.
func endpointState(recs []control.DeliveryRecord) (string, *EventDeliveryView, error) {
	if len(recs) == 0 {
		return "no_deliveries", nil, nil
	}
	for _, r := range recs {
		var state string
		switch deliveryStatus(r) {
		case control.DeliveryAccepted:
			state = "working"
		case "retrying":
			state = "retrying"
		case control.DeliveryFailed, "uncertain":
			state = "failing"
		default:
			continue // not attempted yet, suppressed or cancelled: says nothing about the receiver
		}
		v, err := eventDeliveryView(r)
		if err != nil {
			return "", nil, err
		}
		return state, &v, nil
	}
	v, err := eventDeliveryView(recs[0])
	if err != nil {
		return "", nil, err
	}
	return "pending", &v, nil
}

func (e *EventWebhooks) endpointView(rec endpointRecord, recs []control.DeliveryRecord, now model.UnixNano) (EventEndpointView, error) {
	state, last, err := endpointState(recs)
	if err != nil {
		return EventEndpointView{}, err
	}
	u, _ := url.Parse(rec.Cfg.Endpoint)
	host := ""
	if u != nil {
		host = u.Host
	}
	v := EventEndpointView{ID: rec.ID, Name: rec.Cfg.Name, Host: host, Events: append([]string{}, rec.Cfg.Events...), Enabled: rec.Cfg.Enabled, HasSecret: rec.HasSecret,
		Version: model.Uint64(rec.Cfg.Revision), State: state, LastDelivery: last}
	if rec.Cfg.SecretRotated > 0 {
		at := model.Int64(rec.Cfg.SecretRotated)
		v.SecretRotatedAt = &at
	}
	if rec.Cfg.PreviousUntil > int64(now) {
		until := model.Int64(rec.Cfg.PreviousUntil)
		v.PreviousSecretUntil = &until
	}
	return v, nil
}

func (e *EventWebhooks) list(ctx context.Context, credential auth.Credential, org model.ID) (EventWebhookListAnswer, error) {
	_, endpoints, projects, err := e.orgState(ctx, org)
	if err != nil {
		return EventWebhookListAnswer{}, err
	}
	byEndpoint, capped, err := e.gather(ctx, credential, org, projects)
	if err != nil {
		return EventWebhookListAnswer{}, err
	}
	out := EventWebhookListAnswer{Org: org, State: StateReady, Endpoints: []EventEndpointView{}, Events: eventNames()}
	if capped {
		out.State, out.Reason = StateIncomplete, "projects_capped"
	}
	now := e.clock.Now()
	for _, rec := range endpoints {
		v, err := e.endpointView(rec, byEndpoint[rec.ID], now)
		if err != nil {
			return EventWebhookListAnswer{}, err
		}
		out.Endpoints = append(out.Endpoints, v)
	}
	return out, nil
}

func eventNames() []string {
	out := []string{}
	for _, n := range notify.SubscribableEvents() {
		out = append(out, string(n))
	}
	return out
}

// find is the endpoint with the ID in the organization; a missing one and one of
// another type are the same not_found.
func find(endpoints []endpointRecord, id model.ID) (endpointRecord, bool) {
	for _, r := range endpoints {
		if r.ID == id {
			return r, true
		}
	}
	return endpointRecord{}, false
}

// command commits one admin command under the caller's own credential. The
// transition's organization-epoch precondition is the epoch just read, retried while
// only the epoch moved (an unrelated change of the organization is no reason to refuse
// a save); a conflict on the endpoint's own version is final.
func (e *EventWebhooks) command(ctx context.Context, credential auth.Credential, org model.ID, kind string, id model.ID, command model.ID, expected *model.Uint64, payload auth.AdminPayload) error {
	for attempt := 0; ; attempt++ {
		epoch, endpoints, _, err := e.orgState(ctx, org)
		if err != nil {
			return err
		}
		raw, err := json.Marshal(payload)
		if err != nil {
			return model.Fail(model.Invalid)
		}
		_, err = e.authority.AdminCommand(ctx, credential, auth.AdminCommandRequest{CommandID: command, ExpectedEpoch: &epoch, OrgID: org, Kind: kind, Payload: raw})
		if err == nil {
			return nil
		}
		var f *model.Fault
		if attempt >= 2 || !errors.As(err, &f) || f.Code != model.Conflict {
			return err
		}
		if expected != nil {
			rec, found := find(endpoints, id)
			if found && model.Uint64(rec.Cfg.Revision) != *expected || !found && *expected != 0 {
				return err
			}
		}
	}
}

func (e *EventWebhooks) save(ctx context.Context, credential auth.Credential, body EventWebhookRequest) (EventWebhookSaveAnswer, error) {
	var ep EventEndpointChange
	if len(body.Endpoint) == 0 || model.StrictJSON(body.Endpoint, &ep) != nil || ep.ID == (model.ID{}) {
		return EventWebhookSaveAnswer{}, invalid("event_endpoint_invalid")
	}
	if body.CommandID == (model.ID{}) || body.ExpectedVersion == nil || body.Reason == "" || len(body.Reason) > 512 || len(ep.Events) == 0 {
		return EventWebhookSaveAnswer{}, invalid("event_request_invalid")
	}
	_, endpoints, _, err := e.orgState(ctx, body.Org)
	if err != nil {
		return EventWebhookSaveAnswer{}, err
	}
	existing, found := find(endpoints, ep.ID)
	if !found {
		// The ID may belong to a notification destination: an event endpoint never
		// replaces one (the destination type is fixed).
		var taken bool
		if err = e.directory.View(ctx, func(st control.State) error {
			_, taken = st.Orgs[body.Org.String()].Settings["destination:"+ep.ID.String()]
			return nil
		}); err != nil {
			return EventWebhookSaveAnswer{}, err
		}
		if taken {
			return EventWebhookSaveAnswer{}, invalid("event_endpoint_id_taken")
		}
	}
	endpoint := ep.URL
	if endpoint == "" && found {
		endpoint = existing.Cfg.Endpoint
	}
	config, err := json.Marshal(auth.DestinationConfig{Type: auth.EventWebhookType, Endpoint: endpoint, Enabled: ep.Enabled, Name: ep.Name, Events: ep.Events})
	if err != nil {
		return EventWebhookSaveAnswer{}, model.Fail(model.Invalid)
	}
	expected := *body.ExpectedVersion
	payload := auth.AdminPayload{ID: ep.ID, Reason: body.Reason, Secret: ep.Secret, Config: config, ExpectedVersion: &expected}
	if err = e.command(ctx, credential, body.Org, "destination", ep.ID, body.CommandID, &expected, payload); err != nil {
		return EventWebhookSaveAnswer{}, err
	}
	_, endpoints, _, err = e.orgState(ctx, body.Org)
	if err != nil {
		return EventWebhookSaveAnswer{}, err
	}
	rec, found := find(endpoints, ep.ID)
	if !found {
		return EventWebhookSaveAnswer{}, model.Fail(model.Corrupt)
	}
	view, err := e.endpointView(rec, nil, e.clock.Now())
	if err != nil {
		return EventWebhookSaveAnswer{}, err
	}
	view.State = "no_deliveries"
	return EventWebhookSaveAnswer{State: ActionCommitted, Endpoint: view}, nil
}

func (e *EventWebhooks) test(ctx context.Context, credential auth.Credential, body EventWebhookRequest) (EventWebhookTestAnswer, error) {
	id, err := endpointID(body.Endpoint)
	if err != nil || body.CommandID == (model.ID{}) {
		return EventWebhookTestAnswer{}, invalid("event_request_invalid")
	}
	_, endpoints, projects, err := e.orgState(ctx, body.Org)
	if err != nil {
		return EventWebhookTestAnswer{}, err
	}
	rec, found := find(endpoints, id)
	if !found {
		return EventWebhookTestAnswer{}, model.Fail(model.NotFound)
	}
	if !rec.Cfg.Enabled {
		return EventWebhookTestAnswer{}, invalid("event_endpoint_disabled")
	}
	project := body.Project
	switch {
	case project == (model.ID{}) && len(projects) == 0:
		return EventWebhookTestAnswer{}, invalid("event_test_no_project")
	case project == (model.ID{}):
		project = projects[0]
	case !slices.Contains(projects, project):
		return EventWebhookTestAnswer{}, model.Fail(model.NotFound)
	}
	config, err := json.Marshal(auth.EventTestConfig{Project: project})
	if err != nil {
		return EventWebhookTestAnswer{}, model.Fail(model.Invalid)
	}
	reason := body.Reason
	if reason == "" {
		reason = "event webhook test"
	}
	if len(reason) > 512 {
		return EventWebhookTestAnswer{}, invalid("event_request_invalid")
	}
	if err = e.command(ctx, credential, body.Org, "event_test", id, body.CommandID, nil, auth.AdminPayload{ID: id, Reason: reason, Config: config}); err != nil {
		return EventWebhookTestAnswer{}, err
	}
	return EventWebhookTestAnswer{State: "requested", Endpoint: id, Project: project}, nil
}

// endpointID decodes the endpoint ID of test and deliveries.
func endpointID(raw json.RawMessage) (model.ID, error) {
	var id model.ID
	if len(raw) == 0 || json.Unmarshal(raw, &id) != nil || id == (model.ID{}) {
		return model.ID{}, model.Fail(model.Invalid)
	}
	return id, nil
}

func (e *EventWebhooks) deliveries(ctx context.Context, credential auth.Credential, body EventWebhookRequest) (EventWebhookDeliveriesAnswer, error) {
	id, err := endpointID(body.Endpoint)
	limit := body.Limit
	if limit == 0 {
		limit = DefaultEventDeliveries
	}
	if err != nil || limit < 1 || limit > MaxEventDeliveries {
		return EventWebhookDeliveriesAnswer{}, invalid("event_request_invalid")
	}
	_, endpoints, projects, err := e.orgState(ctx, body.Org)
	if err != nil {
		return EventWebhookDeliveriesAnswer{}, err
	}
	if _, found := find(endpoints, id); !found {
		return EventWebhookDeliveriesAnswer{}, model.Fail(model.NotFound)
	}
	byEndpoint, capped, err := e.gather(ctx, credential, body.Org, projects)
	if err != nil {
		return EventWebhookDeliveriesAnswer{}, err
	}
	out := EventWebhookDeliveriesAnswer{Org: body.Org, Endpoint: id, State: StateReady, Deliveries: []EventDeliveryView{}}
	if capped {
		out.State, out.Reason = StateIncomplete, "projects_capped"
	}
	recs := byEndpoint[id]
	if len(recs) == 0 && !capped {
		out.State, out.Reason = StateEmpty, "no_deliveries"
	}
	for _, r := range recs[:min(len(recs), limit)] {
		v, err := eventDeliveryView(r)
		if err != nil {
			return EventWebhookDeliveriesAnswer{}, err
		}
		out.Deliveries = append(out.Deliveries, v)
	}
	return out, nil
}

// RegisterEventWebhookRoutes mounts POST /api/v1/events/webhooks.
func RegisterEventWebhookRoutes(mux *http.ServeMux, authority *auth.Service, ew *EventWebhooks) {
	mux.HandleFunc("POST /api/v1/events/webhooks", func(w http.ResponseWriter, r *http.Request) {
		credential, err := artifactCredential(authority, w, r)
		if err != nil {
			queryReply(w, nil, err)
			return
		}
		var body EventWebhookRequest
		if err = decode(w, r, &body); err != nil {
			queryReply(w, nil, err)
			return
		}
		if body.Org == (model.ID{}) {
			queryReply(w, nil, invalid("event_request_invalid"))
			return
		}
		switch body.Op {
		case EventsList, EventsSave, EventsTest, EventsDeliveries:
		default:
			queryReply(w, nil, invalid("event_request_invalid"))
			return
		}
		// Every operation needs an organization administrator; anyone else gets the
		// same not_found as a missing organization, before anything is read.
		scope, err := authority.Authorize(r.Context(), credential, body.Org, nil, auth.OrgAdmin)
		if err != nil {
			queryReply(w, nil, err)
			return
		}
		var out any
		switch body.Op {
		case EventsList:
			if body.CommandID != (model.ID{}) || body.ExpectedVersion != nil || body.Reason != "" || len(body.Endpoint) != 0 || body.Limit != 0 || body.Project != (model.ID{}) {
				err = invalid("event_request_invalid")
			} else {
				out, err = ew.list(r.Context(), credential, body.Org)
			}
		case EventsSave:
			if body.Limit != 0 || body.Project != (model.ID{}) {
				err = invalid("event_request_invalid")
			} else {
				out, err = ew.save(r.Context(), credential, body)
			}
		case EventsTest:
			if body.ExpectedVersion != nil || body.Limit != 0 {
				err = invalid("event_request_invalid")
			} else {
				out, err = ew.test(r.Context(), credential, body)
			}
		default:
			if body.CommandID != (model.ID{}) || body.ExpectedVersion != nil || body.Reason != "" || body.Project != (model.ID{}) {
				err = invalid("event_request_invalid")
			} else {
				out, err = ew.deliveries(r.Context(), credential, body)
			}
		}
		if err == nil && body.Op != EventsSave && body.Op != EventsTest {
			err = authority.Revalidate(r.Context(), scope)
		}
		queryReply(w, out, err)
	})
}
