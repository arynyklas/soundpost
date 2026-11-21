// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/notify"
)

// This file is the destination admin surface (POST /api/v1/destinations): list
// and save the organization's notification destinations through
// notify.SaveDestination. A save is the audited admin command transition under
// the caller's own policy.write scope (command ID replayed idempotently, reason
// recorded, secret sealed and write-only) with a per-destination version
// precondition instead of the organization epoch: expected_version is the
// version of the destination the caller read (0 = it must not exist), a stale
// one is a 409. A destination routes every project of the organization, so
// policy.write alone is refused; an organization administrator may save (the
// same rule as the settings page, see auth.PolicyCommand).

// Destination operations.
const (
	DestinationList = "list"
	DestinationSave = "save"
)

// DestinationRequest is the closed POST /api/v1/destinations body. Org and
// Project are selectors authorization confirms. A save carries command_id,
// expected_version, reason and the destination; a list carries none of them.
type DestinationRequest struct {
	Org             model.ID           `json:"org"`
	Project         model.ID           `json:"project_id"`
	Operation       string             `json:"operation"`
	CommandID       model.ID           `json:"command_id,omitempty"`
	ExpectedVersion *model.Uint64      `json:"expected_version,omitempty"`
	Reason          string             `json:"reason,omitempty"`
	Destination     *DestinationChange `json:"destination,omitempty"`
}

// DestinationListAnswer is the answer to a list.
type DestinationListAnswer struct {
	Org          model.ID                 `json:"org"`
	Destinations []notify.DestinationView `json:"destinations"`
}

// DestinationSaveAnswer is the answer to a committed save: the destination as
// committed (redacted, with its new version).
type DestinationSaveAnswer struct {
	State       ActionState            `json:"state"`
	Destination notify.DestinationView `json:"destination"`
}

// destinationStore commits notify.DestinationCommand through the admin command
// transition under the caller's own credential and scope.
type destinationStore struct {
	authority  *auth.Service
	credential auth.Credential
	directory  Directory
}

// state reads the organization's policy epoch and the destination as committed.
func (s destinationStore) state(ctx context.Context, org, id model.ID) (epoch model.Uint64, rec notify.DestinationRecord, found bool, err error) {
	err = s.directory.View(ctx, func(st control.State) error {
		o, ok := st.Orgs[org.String()]
		if !ok {
			return model.Fail(model.NotFound)
		}
		epoch = model.Uint64(o.Epoch)
		rec, found, err = destinationRecord(o, id)
		return err
	})
	return
}

func destinationRecord(o model.ControlOrg, id model.ID) (notify.DestinationRecord, bool, error) {
	key := "destination:" + id.String()
	raw, ok := o.Settings[key]
	if !ok {
		return notify.DestinationRecord{}, false, nil
	}
	var cfg auth.DestinationConfig
	if json.Unmarshal(raw, &cfg) != nil {
		return notify.DestinationRecord{}, false, model.Fail(model.Corrupt)
	}
	_, sealed := o.Secrets[key]
	return notify.DestinationRecord{Type: cfg.Type, Endpoint: cfg.Endpoint, Address: cfg.Address, Enabled: cfg.Enabled, HasSecret: sealed, Version: cfg.Revision}, true, nil
}

// Commit implements notify.DestinationStore. The command's own precondition is
// the destination version; the transition's organization-epoch precondition is
// supplied here from the state just read, and retried while only the epoch
// moved (an unrelated organization change is no reason to refuse a save).
func (s destinationStore) Commit(ctx context.Context, scope auth.Scope, c notify.DestinationCommand) (notify.DestinationRecord, error) {
	config, err := json.Marshal(auth.DestinationConfig{Type: string(c.Channel), Endpoint: c.Endpoint, Address: c.Address, Enabled: c.Enabled})
	if err != nil {
		return notify.DestinationRecord{}, model.Fail(model.Invalid)
	}
	expected := model.Uint64(c.ExpectedVersion)
	payload, err := json.Marshal(auth.AdminPayload{ID: c.ID, ProjectID: c.Project, Reason: c.Reason, Secret: c.Secret, Config: config, ExpectedVersion: &expected})
	if err != nil {
		return notify.DestinationRecord{}, model.Fail(model.Invalid)
	}
	for attempt := 0; ; attempt++ {
		epoch, _, _, err := s.state(ctx, c.Org, c.ID)
		if err != nil {
			return notify.DestinationRecord{}, err
		}
		_, err = s.authority.PolicyCommand(ctx, s.credential, scope, c.Project, auth.AdminCommandRequest{CommandID: c.Command, ExpectedRevision: model.Revision(epoch), OrgID: c.Org, Kind: auth.PolicyKindDestination, Payload: payload})
		if err == nil {
			break
		}
		var f *model.Fault
		if attempt >= 2 || !errors.As(err, &f) || f.Code != model.Conflict {
			return notify.DestinationRecord{}, err
		}
		// A conflict on the destination's own version is final; only a moved
		// epoch is retried.
		if _, rec, found, rerr := s.state(ctx, c.Org, c.ID); rerr != nil {
			return notify.DestinationRecord{}, rerr
		} else if (found && model.Uint64(rec.Version) != expected) || (!found && expected != 0) {
			return notify.DestinationRecord{}, err
		}
	}
	_, rec, found, err := s.state(ctx, c.Org, c.ID)
	if err != nil {
		return notify.DestinationRecord{}, err
	}
	if !found {
		return notify.DestinationRecord{}, model.Fail(model.Corrupt)
	}
	return rec, nil
}

// list is the organization's destinations, redacted, in ID order.
func (s destinationStore) list(ctx context.Context, org model.ID) ([]notify.DestinationView, error) {
	out := []notify.DestinationView{}
	err := s.directory.View(ctx, func(st control.State) error {
		o, ok := st.Orgs[org.String()]
		if !ok {
			return model.Fail(model.NotFound)
		}
		for key := range o.Settings {
			if !strings.HasPrefix(key, "destination:") {
				continue
			}
			id, err := model.ParseID(strings.TrimPrefix(key, "destination:"))
			if err != nil {
				continue
			}
			rec, _, err := destinationRecord(o, id)
			if err != nil {
				return err
			}
			out = append(out, rec.View(id))
		}
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].ID.String() < out[j].ID.String() })
	return out, err
}

func registerDestinationRoutes(mux *http.ServeMux, authority *auth.Service, policies *Policies) {
	mux.HandleFunc("POST /api/v1/destinations", func(w http.ResponseWriter, r *http.Request) {
		credential, err := artifactCredential(authority, w, r)
		if err != nil {
			queryReply(w, nil, err)
			return
		}
		var body DestinationRequest
		if err = decode(w, r, &body); err != nil {
			queryReply(w, nil, err)
			return
		}
		if body.Org == (model.ID{}) || body.Project == (model.ID{}) || body.Operation != DestinationList && body.Operation != DestinationSave {
			queryReply(w, nil, invalid("destination_request_invalid"))
			return
		}
		list := body.Operation == DestinationList
		if list && (body.CommandID != (model.ID{}) || body.ExpectedVersion != nil || body.Reason != "" || body.Destination != nil) ||
			!list && (body.CommandID == (model.ID{}) || body.ExpectedVersion == nil || body.Reason == "" || body.Destination == nil) {
			queryReply(w, nil, invalid("destination_request_invalid"))
			return
		}
		scope, err := authority.AuthorizeWrite(r.Context(), credential, body.Org, body.Project, auth.PolicyWrite)
		if err != nil {
			queryReply(w, nil, err)
			return
		}
		store := destinationStore{authority: authority, credential: credential, directory: policies.directory}
		if list {
			views, err := store.list(r.Context(), body.Org)
			if err == nil {
				err = authority.Revalidate(r.Context(), scope)
			}
			queryReply(w, DestinationListAnswer{Org: body.Org, Destinations: views}, err)
			return
		}
		d := body.Destination
		// The settings page never receives an endpoint path (it may carry a
		// token), so a change to an existing destination may leave type and
		// target out and they stay as committed.
		if err = policies.completeDestination(r.Context(), body.Org, d); err != nil {
			queryReply(w, nil, err)
			return
		}
		view, err := notify.SaveDestination(r.Context(), scope, store, notify.DestinationCommand{
			Command: body.CommandID, Org: body.Org, Project: body.Project, ID: d.ID, ExpectedVersion: model.Revision(*body.ExpectedVersion),
			Channel: notify.Channel(d.Type), Endpoint: d.Endpoint, Address: d.Address, Enabled: d.Enabled, Secret: d.Secret, Reason: body.Reason})
		queryReply(w, DestinationSaveAnswer{State: ActionCommitted, Destination: view}, err)
	})
}
