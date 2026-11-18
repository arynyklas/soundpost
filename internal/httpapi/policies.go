// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/notify"
)

// This file is the C11 /api/v1/policies surface for one project's settings
// pages: the notification policy the project's delivery runs under, the
// organization's notification destinations and the project's retention
// settings, to read and to change.
//
// Reading returns committed control state and only what a settings page may
// show: a destination's sealed secret is never read here (only whether one is
// set), and the host of its endpoint is shown without the path or query, which
// webhook URLs commonly use to carry a token.
//
// Both halves need the policy.write grant on the project, or organization
// administration (decision D20, internal/auth/write.go): "explicit admin
// grants". A write is the audited admin command transition, not a second
// store: auth.Service.PolicyCommand commits it under the caller's own scope
// with the revision compare-and-set, the command-ID binding and the audit
// record of every admin command. It changes the project's retention (the
// resolved retention versions admission uses), the project's notification
// policy (a new policy revision the notification worker adopts) and, for an
// administrator only, an organization destination. A destination's secret is
// accepted on a write and never returned.

// Policy operations.
const (
	PolicyRead  = "read"
	PolicyWrite = "write"
)

// Policy change kinds.
const (
	ChangeRetention    = auth.PolicyKindRetention
	ChangeNotification = auth.PolicyKindNotification
	ChangeDestination  = auth.PolicyKindDestination
)

// PolicyRequest is the closed POST /api/v1/policies body. Org and Project are
// selectors authorization confirms; Operation is read or write. A write names
// its command (CommandID, replayed idempotently), the organization policy epoch
// it was based on (ExpectedRevision = the Revision of the PolicyView it read; a
// 409 conflict when the targeted setting changed since), why (Reason) and
// exactly one Change; a read carries none of these.
type PolicyRequest struct {
	Org              model.ID       `json:"org"`
	Project          model.ID       `json:"project_id"`
	Operation        string         `json:"operation"`
	CommandID        model.ID       `json:"command_id,omitempty"`
	ExpectedRevision model.Revision `json:"expected_revision,omitempty"`
	Reason           string         `json:"reason,omitempty"`
	Change           *PolicyChange  `json:"change,omitempty"`
}

// PolicyChange is one settings change; the member named by Kind is the one set.
type PolicyChange struct {
	Kind         string              `json:"kind"`
	Retention    *RetentionChange    `json:"retention,omitempty"`
	Notification *NotificationChange `json:"notification,omitempty"`
	Destination  *DestinationChange  `json:"destination,omitempty"`
}

// RetentionChange sets one signal's retention days for the project.
type RetentionChange struct {
	Signal string `json:"signal"`
	Days   uint32 `json:"days"`
}

// NotificationChange is the whole notification policy of the project (a write
// replaces it as the next revision). Durations are decimal nanosecond strings.
type NotificationChange struct {
	MinOperations   uint32   `json:"min_operations"`
	MinFailures     uint32   `json:"min_failures"`
	RateBasisPoints uint32   `json:"rate_basis_points"`
	RegressionMin   uint32   `json:"regression_min"`
	CriticalCodes   []string `json:"critical_codes"`
	FirstReminder   string   `json:"first_reminder_ns"`
	ReminderEvery   string   `json:"reminder_every_ns"`
	MaxSuppression  string   `json:"max_suppression_ns"`
	DefaultZone     string   `json:"default_zone"`
}

// DestinationChange creates or replaces one organization destination (the
// caller names its ID). Secret is write-only: empty keeps the sealed one.
type DestinationChange struct {
	ID       model.ID `json:"id"`
	Type     string   `json:"type"`
	Endpoint string   `json:"endpoint,omitempty"`
	Address  string   `json:"address,omitempty"`
	Enabled  bool     `json:"enabled"`
	Secret   string   `json:"secret,omitempty"`
}

// NotificationPolicyView is the policy the project's delivery applies. Source is
// "default" until a policy is written for the project, then "project"; Revision
// is 1 for the default and the committed revision after. Durations are decimal
// nanosecond strings.
type NotificationPolicyView struct {
	Source          string         `json:"source"`
	Revision        model.Revision `json:"revision"`
	MinOperations   uint32         `json:"min_operations"`
	MinFailures     uint32         `json:"min_failures"`
	RateBasisPoints uint32         `json:"rate_basis_points"`
	RegressionMin   uint32         `json:"regression_min"`
	CriticalCodes   []string       `json:"critical_codes"`
	FirstReminder   string         `json:"first_reminder_ns"`
	ReminderEvery   string         `json:"reminder_every_ns"`
	MaxSuppression  string         `json:"max_suppression_ns"`
	DefaultZone     string         `json:"default_zone"`
}

// DestinationView is one notification destination of the organization. It never
// carries the endpoint path or query, nor any secret: HasSecret only says one
// is sealed. Address is the SMTP recipient, which is configuration, not a secret.
type DestinationView struct {
	ID           model.ID `json:"id"`
	Type         string   `json:"type"`
	EndpointHost string   `json:"endpoint_host,omitempty"`
	Address      string   `json:"address,omitempty"`
	Enabled      bool     `json:"enabled"`
	HasSecret    bool     `json:"has_secret"`
}

// RetentionView is one project retention setting (the days admission applies).
type RetentionView struct {
	Signal string `json:"signal"`
	Days   uint32 `json:"days"`
}

// PolicyView is the read answer for one project. Revision is the organization's
// policy epoch, the token a write must be based on: it moves with every
// administration or settings change of the organization, but a write conflicts
// only when the setting it targets was changed after that epoch (or an
// untracked change, such as a restore or retirement, moved the epoch).
// ManageDestinations says whether the caller
// may change organization destinations (administrators only).
type PolicyView struct {
	Org                model.ID               `json:"org"`
	Project            model.ID               `json:"project_id"`
	Revision           model.Revision         `json:"revision"`
	ManageDestinations bool                   `json:"manage_destinations"`
	Notification       NotificationPolicyView `json:"notification"`
	Destinations       []DestinationView      `json:"destinations"`
	Retention          []RetentionView        `json:"retention"`
}

// PolicyWriteAnswer is the answer to a committed write: the control revision it
// produced (for the record; the next write is based on Policy.Revision) and the
// settings as they now read.
type PolicyWriteAnswer struct {
	State    ActionState    `json:"state"`
	Revision model.Revision `json:"revision"`
	Policy   PolicyView     `json:"policy"`
}

// Policies serves the policy reads and writes over the control store.
type Policies struct {
	directory Directory
	// recording is the node's recording source (UseRecordingSource), which the
	// rule routes check recording rules against; nil on a node that has none.
	recording atomic.Pointer[recordingBinding]
}

// NewPolicies requires the committed-state reader.
func NewPolicies(directory Directory) (*Policies, error) {
	if directory == nil {
		return nil, model.Fail(model.Invalid)
	}
	return &Policies{directory: directory}, nil
}

// hostOf is the host of an https endpoint, or "" when it is not one. The path,
// query and credentials of an endpoint are never returned.
func hostOf(endpoint string) string {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return ""
	}
	return u.Host
}

func notificationView(cfg notify.Config, source string, revision model.Revision) NotificationPolicyView {
	return NotificationPolicyView{
		Source: source, Revision: revision, MinOperations: cfg.MinOperations, MinFailures: cfg.MinFailures, RateBasisPoints: cfg.RateBasisPoints, RegressionMin: cfg.RegressionMin,
		CriticalCodes: append([]string{}, cfg.CriticalCodes...), FirstReminder: decimal(int64(cfg.FirstReminder)), ReminderEvery: decimal(int64(cfg.ReminderEvery)),
		MaxSuppression: decimal(int64(cfg.MaxSuppression)), DefaultZone: cfg.DefaultZone,
	}
}

// Read answers one project's policy view under scope. The project must be one
// the scope names and the organization still has; a project outside it is the
// same not-found a missing one gives.
func (p *Policies) Read(ctx context.Context, ctxOrg auth.Scope, project model.ID) (PolicyView, error) {
	if project == (model.ID{}) || !ctxOrg.AllowsProject(project) {
		return PolicyView{}, model.Fail(model.NotFound)
	}
	out := PolicyView{Org: ctxOrg.OrgID(), Project: project, ManageDestinations: ctxOrg.Permission() == auth.OrgAdmin, Destinations: []DestinationView{}, Retention: []RetentionView{},
		Notification: notificationView(notify.DefaultConfig(), "default", 1)}
	err := p.directory.View(ctx, func(st control.State) error {
		org, ok := st.Orgs[ctxOrg.OrgID().String()]
		if !ok {
			return model.Fail(model.NotFound)
		}
		out.Revision = model.Revision(org.Epoch)
		if _, ok = org.Projects[project.String()]; !ok {
			return model.Fail(model.NotFound)
		}
		if rec, found, err := auth.ReadNotificationPolicy(org, project); err != nil {
			return err
		} else if found {
			out.Notification = notificationView(notify.Config{MinOperations: rec.MinOperations, MinFailures: rec.MinFailures, RateBasisPoints: rec.RateBasisPoints, RegressionMin: rec.RegressionMin,
				CriticalCodes: rec.CriticalCodes, FirstReminder: model.UnixNano(rec.FirstReminder), ReminderEvery: model.UnixNano(rec.ReminderEvery), MaxSuppression: model.UnixNano(rec.MaxSuppression), DefaultZone: rec.DefaultZone}, "project", rec.Revision)
		}
		// The last audited retention command naming a setting orders settings of
		// one signal written under different IDs.
		written := map[model.ID]int64{}
		for _, a := range st.Audits {
			if a.Action == auth.PolicyKindRetention && a.Org == ctxOrg.OrgID().String() {
				for _, t := range a.Targets {
					written[t] = max(written[t], a.Time)
				}
			}
		}
		type pick struct {
			days uint32
			at   int64
			id   model.ID
		}
		picks := map[string]pick{}
		for key, raw := range org.Settings {
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
				_, sealed := org.Secrets[key]
				out.Destinations = append(out.Destinations, DestinationView{ID: id, Type: cfg.Type, EndpointHost: hostOf(cfg.Endpoint), Address: cfg.Address, Enabled: cfg.Enabled, HasSecret: sealed})
			case strings.HasPrefix(key, "retention:"):
				id, err := model.ParseID(strings.TrimPrefix(key, "retention:"))
				if err != nil {
					continue
				}
				var cfg auth.RetentionConfig
				if json.Unmarshal(raw, &cfg) != nil {
					return model.Fail(model.Corrupt)
				}
				if cfg.ProjectID != project {
					continue
				}
				cand := pick{days: cfg.Days, at: written[id], id: id}
				if cur, ok := picks[cfg.Signal]; !ok || cand.at > cur.at || cand.at == cur.at && cand.id.String() > cur.id.String() {
					picks[cfg.Signal] = cand
				}
			}
		}
		for signal, c := range picks {
			out.Retention = append(out.Retention, RetentionView{Signal: signal, Days: c.days})
		}
		return nil
	})
	if err != nil {
		return PolicyView{}, err
	}
	sort.Slice(out.Destinations, func(i, j int) bool { return out.Destinations[i].ID.String() < out.Destinations[j].ID.String() })
	sort.Slice(out.Retention, func(i, j int) bool { return out.Retention[i].Signal < out.Retention[j].Signal })
	return out, nil
}

// completeDestination fills the part of a change to an existing destination the page
// cannot send: the page never receives an endpoint path (it may carry a token), so
// an enable/disable or a secret rotation names the destination and leaves its type
// and address out, and they stay as committed. The type of a destination is fixed.
// An unknown ID is a new destination and must be given whole (command checks that).
// The revision compare-and-set of the command covers the read made here.
func (p *Policies) completeDestination(ctx context.Context, org model.ID, d *DestinationChange) error {
	var existing *auth.DestinationConfig
	if err := p.directory.View(ctx, func(st control.State) error {
		o, ok := st.Orgs[org.String()]
		if !ok {
			return model.Fail(model.NotFound)
		}
		raw, ok := o.Settings["destination:"+d.ID.String()]
		if !ok {
			return nil
		}
		var cfg auth.DestinationConfig
		if json.Unmarshal(raw, &cfg) != nil {
			return model.Fail(model.Corrupt)
		}
		existing = &cfg
		return nil
	}); err != nil {
		return err
	}
	if existing == nil {
		return nil
	}
	if d.Type == "" {
		d.Type = existing.Type
	} else if d.Type != existing.Type {
		return invalid("destination_type_fixed")
	}
	if d.Endpoint == "" && d.Address == "" {
		d.Endpoint, d.Address = existing.Endpoint, existing.Address
	}
	return nil
}

func decimal(v int64) string { return strconv.FormatInt(v, 10) }

func duration(s string) (int64, bool) {
	v, err := strconv.ParseInt(s, 10, 64)
	return v, err == nil && decimal(v) == s
}

// retentionSettingID is the stable setting ID of one project's signal, so a
// write replaces the setting instead of adding a second one.
func retentionSettingID(org, project model.ID, signal string) model.ID {
	h := sha256.New()
	for _, part := range [][]byte{[]byte("soundpost/project-retention-setting"), org[:], project[:], []byte(signal)} {
		h.Write([]byte{byte(len(part))})
		h.Write(part)
	}
	var id model.ID
	copy(id[:], h.Sum(nil))
	return id
}

// command builds the admin command a change commits as. It validates everything
// that does not need the committed state; the transition validates the rest.
func (req PolicyRequest) command() (auth.AdminCommandRequest, error) {
	c := req.Change
	if req.CommandID == (model.ID{}) || req.Reason == "" || len(req.Reason) > 512 || c == nil {
		return auth.AdminCommandRequest{}, invalid("policy_write_incomplete")
	}
	payload := auth.AdminPayload{ProjectID: req.Project, Reason: req.Reason}
	set := 0
	for _, present := range []bool{c.Retention != nil, c.Notification != nil, c.Destination != nil} {
		if present {
			set++
		}
	}
	var config any
	switch {
	case set != 1:
		return auth.AdminCommandRequest{}, invalid("policy_change_shape")
	case c.Kind == ChangeRetention && c.Retention != nil:
		payload.ID = retentionSettingID(req.Org, req.Project, c.Retention.Signal)
		config = auth.RetentionConfig{ProjectID: req.Project, Signal: c.Retention.Signal, Days: c.Retention.Days}
	case c.Kind == ChangeNotification && c.Notification != nil:
		n := c.Notification
		first, ok1 := duration(n.FirstReminder)
		every, ok2 := duration(n.ReminderEvery)
		most, ok3 := duration(n.MaxSuppression)
		if !ok1 || !ok2 || !ok3 {
			return auth.AdminCommandRequest{}, invalid("notification_policy_invalid")
		}
		codes := append([]string{}, n.CriticalCodes...)
		sort.Strings(codes)
		codes = slices.Compact(codes)
		cfg := notify.Config{MinOperations: n.MinOperations, MinFailures: n.MinFailures, RateBasisPoints: n.RateBasisPoints, RegressionMin: n.RegressionMin, CriticalCodes: codes,
			FirstReminder: model.UnixNano(first), ReminderEvery: model.UnixNano(every), MaxSuppression: model.UnixNano(most), DefaultZone: n.DefaultZone}
		if cfg.Validate() != nil {
			return auth.AdminCommandRequest{}, invalid("notification_policy_invalid")
		}
		payload.ID = req.Project
		config = auth.NotificationPolicyConfig{ProjectID: req.Project, MinOperations: n.MinOperations, MinFailures: n.MinFailures, RateBasisPoints: n.RateBasisPoints, RegressionMin: n.RegressionMin,
			CriticalCodes: codes, FirstReminder: first, ReminderEvery: every, MaxSuppression: most, DefaultZone: n.DefaultZone}
	case c.Kind == ChangeDestination && c.Destination != nil:
		d := c.Destination
		if d.ID == (model.ID{}) || d.Type == "" || d.Type == "webhook" && d.Endpoint == "" || d.Type == "smtp" && d.Address == "" || len(d.Secret) > 4096 {
			return auth.AdminCommandRequest{}, invalid("destination_invalid")
		}
		payload.ID, payload.Secret = d.ID, d.Secret
		config = auth.DestinationConfig{Type: d.Type, Endpoint: d.Endpoint, Address: d.Address, Enabled: d.Enabled}
	default:
		return auth.AdminCommandRequest{}, invalid("policy_change_shape")
	}
	raw, err := json.Marshal(config)
	if err != nil {
		return auth.AdminCommandRequest{}, invalid("policy_change_shape")
	}
	payload.Config = raw
	body, err := json.Marshal(payload)
	if err != nil {
		return auth.AdminCommandRequest{}, invalid("policy_change_shape")
	}
	return auth.AdminCommandRequest{CommandID: req.CommandID, ExpectedRevision: req.ExpectedRevision, OrgID: req.Org, Kind: c.Kind, Payload: body}, nil
}

// RegisterPolicyRoutes mounts POST /api/v1/policies. The scope is derived from
// the caller's own credential before any state is read or changed: policy.write
// on the project or organization administration; a session caller needs the
// CSRF binding. A write commits through auth.Service.PolicyCommand under that
// scope.
func RegisterPolicyRoutes(mux *http.ServeMux, authority *auth.Service, policies *Policies) {
	registerDestinationRoutes(mux, authority, policies)
	registerCutoverRoutes(mux, authority, policies)
	registerRuleRoutes(mux, authority, policies)
	registerJobDefinitionRoutes(mux, authority, policies)
	mux.HandleFunc("POST /api/v1/policies", func(w http.ResponseWriter, r *http.Request) {
		credential, err := artifactCredential(authority, w, r)
		if err != nil {
			queryReply(w, nil, err)
			return
		}
		var body PolicyRequest
		if err = decode(w, r, &body); err != nil {
			queryReply(w, nil, err)
			return
		}
		if body.Org == (model.ID{}) || body.Project == (model.ID{}) || body.Operation != PolicyRead && body.Operation != PolicyWrite {
			queryReply(w, nil, invalid("policy_request_invalid"))
			return
		}
		if body.Operation == PolicyRead && (body.CommandID != (model.ID{}) || body.ExpectedRevision != 0 || body.Reason != "" || body.Change != nil) {
			queryReply(w, nil, invalid("policy_request_invalid"))
			return
		}
		scope, err := authority.AuthorizeWrite(r.Context(), credential, body.Org, body.Project, auth.PolicyWrite)
		if err != nil {
			queryReply(w, nil, err)
			return
		}
		if body.Operation == PolicyWrite {
			if body.Change != nil && body.Change.Destination != nil {
				if err = policies.completeDestination(r.Context(), body.Org, body.Change.Destination); err != nil {
					queryReply(w, nil, err)
					return
				}
			}
			command, err := body.command()
			if err != nil {
				queryReply(w, nil, err)
				return
			}
			result, err := authority.PolicyCommand(r.Context(), credential, scope, body.Project, command)
			if err != nil {
				queryReply(w, nil, err)
				return
			}
			// The command moved the organization's epoch, so the scope is not
			// revalidated: its project check is all the read needs.
			view, err := policies.Read(r.Context(), scope, body.Project)
			queryReply(w, PolicyWriteAnswer{State: ActionCommitted, Revision: result.Revision, Policy: view}, err)
			return
		}
		view, err := policies.Read(r.Context(), scope, body.Project)
		if err == nil {
			err = authority.Revalidate(r.Context(), scope)
		}
		queryReply(w, view, err)
	})
}
