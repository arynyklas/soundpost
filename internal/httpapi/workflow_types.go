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
	ReasonGrantNotBuilt   = "separate_grant_not_built"
	ReasonViewNotBuilt    = "view_not_built"
	ReasonRegistryAbsent  = "service_registry_not_built"
	ReasonSectionsAbsent  = "sections_not_available"
	ReasonShardsMissing   = "shards_missing"
	ReasonFreshnessStale  = "freshness_stale"
	ReasonNoSources       = "no_visible_sources"
	ReasonRestrictedScope = "restricted_source_discovery_unavailable"
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
}
