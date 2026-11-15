// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query"
)

// InvestigationKind is the closed set of investigation views. A kind whose
// backing service is not built answers with an explicit not_available view,
// never an empty success.
type InvestigationKind string

const (
	KindQueue    InvestigationKind = "queue"
	KindIncident InvestigationKind = "incident"
	KindIssue    InvestigationKind = "issue"
	KindRelease  InvestigationKind = "release"
	KindService  InvestigationKind = "service"
	KindTrace    InvestigationKind = "trace"
	KindJob      InvestigationKind = "job"
	KindReplay   InvestigationKind = "replay"
	KindProfile  InvestigationKind = "profile"
)

// Investigation limits. A page never exceeds MaxInvestigationLimit rows and a
// request never names more than MaxInvestigationProjects projects.
const (
	MaxInvestigationLimit    = 200
	MaxInvestigationProjects = 16
)

// InvestigationRequest names what to read. It never carries a scope: the
// organization, permission and elevation live in the sibling ScopeFields of the
// POST body and are re-derived from the caller's own credential. Projects are
// selectors that authorization confirms or collapses to not-found.
type InvestigationRequest struct {
	Kind     InvestigationKind `json:"kind"`
	Projects []model.ID        `json:"projects"`
	// Target is the stable typed ID of one entity (trace, service, ...).
	Target *model.ID `json:"target,omitempty"`
	// Source names the one restricted raw source of a raw.read read.
	Source *model.ID       `json:"source,omitempty"`
	Window query.TimeRange `json:"window"`
	Limit  uint32          `json:"limit"`
	// Cursor resumes a previous page of the same request; it is authenticated
	// and bound to the caller's visibility and the project set by the engine.
	Cursor string `json:"cursor,omitempty"`
	// Environment narrows a service view to the services an active source
	// policy admits in that environment (D9). It is a selector: an environment
	// no visible policy lists answers like an absent target.
	Environment *model.ID `json:"environment,omitempty"`
}

// ViewState is the server side of the browser's LoadState. unauthorized,
// rate_limited, loading and error are transport outcomes, never view states.
type ViewState string

const (
	StateReady        ViewState = "ready"
	StateEmpty        ViewState = "empty"
	StateIncomplete   ViewState = "incomplete"
	StateStale        ViewState = "stale"
	StateNotAvailable ViewState = "not_available"
)

// Reason codes are a closed vocabulary of static strings; none ever carries
// telemetry or caller text.
const (
	ReasonServiceNotBuilt = "service_not_built"
	ReasonGrantRequired   = "separate_grant_required"
	ReasonViewNotBuilt    = "view_not_built"
	ReasonSectionsAbsent  = "sections_not_available"
	ReasonShardsMissing   = "shards_missing"
	ReasonFreshnessStale  = "freshness_stale"
	ReasonNoSources       = "no_visible_sources"
	ReasonRestrictedScope = "restricted_source_discovery_unavailable"
	// ReasonServiceNotSelected: a per-service section of a list view.
	ReasonServiceNotSelected = "service_not_selected"
	// ReasonResourceFilter: the query engine has no service or environment
	// dimension, so a project-wide answer is not given for a narrowed view.
	ReasonResourceFilter = "resource_filter_unavailable"
	// ReasonHealthNotWired, ReasonHealthNotAuthorized and ReasonHealthUnreadable
	// say why the health of a service is not stated; it is never read as healthy.
	ReasonHealthNotWired      = "health_source_not_wired"
	ReasonHealthNotAuthorized = "health_not_authorized"
	ReasonHealthUnreadable    = "health_evidence_unreadable"
	// ReasonReleaseRecordsAdmin: release records (labels, ancestry) are read
	// through the release view with an organization-admin scope.
	ReasonReleaseRecordsAdmin = "release_records_need_org_admin"
)

// ProjectEvidence lists the active sources of one requested project that this
// scope may read. A restricted source of another reader is never listed.
type ProjectEvidence struct {
	ProjectID model.ID             `json:"project_id"`
	Sources   []auth.VisibleSource `json:"sources"`
}

// ViewSection is one separately qualified part of a view.
type ViewSection struct {
	Name   string    `json:"name"`
	State  ViewState `json:"state"`
	Reason string    `json:"reason,omitempty"`
}

// TargetLink is an independently authorized link: Available is true only when
// this scope resolved the target. Unavailable links are never emitted.
type TargetLink struct {
	Kind      string   `json:"kind"`
	ProjectID model.ID `json:"project_id"`
	ID        model.ID `json:"id"`
	Available bool     `json:"available"`
}

// InvestigationView is the matching typed view. Org echoes the organization the
// view was computed for so a browser can refuse a view for another scope.
type InvestigationView struct {
	Kind        InvestigationKind `json:"kind"`
	Org         model.ID          `json:"org"`
	Window      query.TimeRange   `json:"window"`
	State       ViewState         `json:"state"`
	Reason      string            `json:"reason,omitempty"`
	Projects    []ProjectEvidence `json:"projects"`
	MetricNames []string          `json:"metric_names"`
	More        bool              `json:"more"`
	NextCursor  string            `json:"next_cursor,omitempty"`
	Freshness   *query.Freshness  `json:"freshness,omitempty"`
	Sections    []ViewSection     `json:"sections"`
	Link        *TargetLink       `json:"link,omitempty"`
	// Services (service kind only) are the services the active source policies
	// of the requested projects admit (D9), narrowed by Target and Environment.
	Services []auth.VisibleService `json:"services,omitempty"`
	// Health is the stored-evidence health of the one targeted service.
	Health *ServiceHealth `json:"health,omitempty"`
}

// HealthStatus is D9: failing = an open incident links the service, degraded =
// only active conditions name it, healthy = neither exists. There is no other
// value and nothing is inferred.
type HealthStatus string

const (
	HealthHealthy  HealthStatus = "healthy"
	HealthDegraded HealthStatus = "degraded"
	HealthFailing  HealthStatus = "failing"
)

// ServiceHealth lists the stored evidence behind a status; each entry names the
// project and the ID of the incident or condition that the page links to.
type ServiceHealth struct {
	Status     HealthStatus      `json:"status"`
	Incidents  []HealthIncident  `json:"incidents"`
	Conditions []HealthCondition `json:"conditions"`
	Truncated  bool              `json:"truncated,omitempty"`
}
type HealthIncident struct {
	Project  model.ID     `json:"project_id"`
	ID       model.ID     `json:"incident_id"`
	Severity string       `json:"severity"`
	Version  model.Uint64 `json:"version"`
}
type HealthCondition struct {
	Project   model.ID `json:"project_id"`
	ID        model.ID `json:"condition_id"`
	Phase     string   `json:"phase"`
	Severity  string   `json:"severity"`
	Freshness string   `json:"freshness"`
}
