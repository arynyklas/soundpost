// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/notify"
)

// This file is the C11 /api/v1/policies surface for one project's settings
// pages: the notification policy the organization's delivery runs under, the
// organization's notification destinations and the project's retention
// settings. It reads committed control state (organization settings written by
// the closed `destination` and `retention` admin commands) and returns only
// what a settings page may show: a destination's sealed secret is never read
// here (only whether one is set), and the host of its endpoint is shown without
// the path or query, which webhook URLs commonly use to carry a token.
//
// Reading needs the policy.write grant on the project, or organization
// administration (decision D19, internal/auth/write.go): "explicit admin
// grants". The write half of the contract (changing a policy) has no committed
// control transition for the notification policy yet, so a write request is an
// explicit not_available answer and nothing is changed.

// Policy operations and the reason a write is not available.
const (
	PolicyRead = "read"
	// ReasonPolicyWriteNotBuilt answers a write: the notification policy has no
	// committed, versioned control transition yet (it runs on the approved default).
	ReasonPolicyWriteNotBuilt = "notification_policy_write_not_built"
)

// PolicyRequest is the closed POST /api/v1/policies body. Org and Project are
// selectors authorization confirms; Operation is read or write.
type PolicyRequest struct {
	Org       model.ID `json:"org"`
	Project   model.ID `json:"project_id"`
	Operation string   `json:"operation"`
}

// NotificationPolicyView is the policy the organization's delivery applies to
// the project. Source is "default": there is no per-project policy catalogue,
// every project runs on the approved default. Durations are decimal
// nanosecond strings.
type NotificationPolicyView struct {
	Source          string   `json:"source"`
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

// RetentionView is one project retention setting.
type RetentionView struct {
	Signal string `json:"signal"`
	Days   uint32 `json:"days"`
}

// PolicyView is the read answer for one project.
type PolicyView struct {
	Org          model.ID               `json:"org"`
	Project      model.ID               `json:"project_id"`
	Notification NotificationPolicyView `json:"notification"`
	Destinations []DestinationView      `json:"destinations"`
	Retention    []RetentionView        `json:"retention"`
}

// PolicyWriteAnswer is the explicit not_available answer to a write.
type PolicyWriteAnswer struct {
	State  ActionState `json:"state"`
	Reason string      `json:"reason"`
}

// Policies serves the policy reads over the control store (Directory).
type Policies struct{ directory Directory }

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

// Read answers one project's policy view under scope. The project must be one
// the scope names and the organization still has; a project outside it is the
// same not-found a missing one gives.
func (p *Policies) Read(ctx context.Context, ctxOrg auth.Scope, project model.ID) (PolicyView, error) {
	if project == (model.ID{}) || !ctxOrg.AllowsProject(project) {
		return PolicyView{}, model.Fail(model.NotFound)
	}
	cfg := notify.DefaultConfig()
	out := PolicyView{Org: ctxOrg.OrgID(), Project: project, Destinations: []DestinationView{}, Retention: []RetentionView{}, Notification: NotificationPolicyView{
		Source: "default", MinOperations: cfg.MinOperations, MinFailures: cfg.MinFailures, RateBasisPoints: cfg.RateBasisPoints, RegressionMin: cfg.RegressionMin,
		CriticalCodes: append([]string{}, cfg.CriticalCodes...), FirstReminder: decimal(int64(cfg.FirstReminder)), ReminderEvery: decimal(int64(cfg.ReminderEvery)), MaxSuppression: decimal(int64(cfg.MaxSuppression)), DefaultZone: cfg.DefaultZone}}
	err := p.directory.View(ctx, func(st control.State) error {
		org, ok := st.Orgs[ctxOrg.OrgID().String()]
		if !ok {
			return model.Fail(model.NotFound)
		}
		if _, ok = org.Projects[project.String()]; !ok {
			return model.Fail(model.NotFound)
		}
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
				var cfg auth.RetentionConfig
				if json.Unmarshal(raw, &cfg) != nil {
					return model.Fail(model.Corrupt)
				}
				if cfg.ProjectID == project {
					out.Retention = append(out.Retention, RetentionView{Signal: cfg.Signal, Days: cfg.Days})
				}
			}
		}
		return nil
	})
	if err != nil {
		return PolicyView{}, err
	}
	sort.Slice(out.Destinations, func(i, j int) bool { return out.Destinations[i].ID.String() < out.Destinations[j].ID.String() })
	sort.Slice(out.Retention, func(i, j int) bool {
		if out.Retention[i].Signal != out.Retention[j].Signal {
			return out.Retention[i].Signal < out.Retention[j].Signal
		}
		return out.Retention[i].Days < out.Retention[j].Days
	})
	return out, nil
}

func decimal(v int64) string { return strconv.FormatInt(v, 10) }

// RegisterPolicyRoutes mounts POST /api/v1/policies. The scope is derived from
// the caller's own credential before any state is read: policy.write on the
// project or organization administration; a session caller needs the CSRF
// binding. A write is an explicit not_available answer.
func RegisterPolicyRoutes(mux *http.ServeMux, authority *auth.Service, policies *Policies) {
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
		if body.Org == (model.ID{}) || body.Project == (model.ID{}) || body.Operation != PolicyRead && body.Operation != "write" {
			queryReply(w, nil, invalid("policy_request_invalid"))
			return
		}
		scope, err := authority.AuthorizeWrite(r.Context(), credential, body.Org, body.Project, auth.PolicyWrite)
		if err != nil {
			queryReply(w, nil, err)
			return
		}
		if body.Operation == "write" {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotImplemented)
			_ = json.NewEncoder(w).Encode(PolicyWriteAnswer{State: ActionNotAvailable, Reason: ReasonPolicyWriteNotBuilt})
			return
		}
		view, err := policies.Read(r.Context(), scope, body.Project)
		if err == nil {
			err = authority.Revalidate(r.Context(), scope)
		}
		queryReply(w, view, err)
	})
}
