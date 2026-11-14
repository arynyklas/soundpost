// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/link"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query"
	"net/http"
	"slices"
)

// SourceLister, Discoverer and TargetResolver are the owned services the
// investigation projection delegates to. Nothing here stores or caches: every
// view is computed under the scope of the request that asked for it, so a
// grant change or revocation can never be answered from an older projection.
type SourceLister interface {
	VisibleSources(context.Context, auth.Scope) ([]auth.VisibleSource, error)
}
type Discoverer interface {
	Discover(context.Context, auth.Scope, query.DiscoveryRequest) (query.DiscoveryResult, error)
}
type TargetResolver interface {
	Resolve(context.Context, auth.Scope, []link.Reference) ([]link.ResolvedReference, error)
}

// Investigator is the thin, scope-first projection behind POST /api/v1/investigate.
// It reports only what an owned service answered; a kind whose service does not
// exist yet is an explicit not_available view.
type Investigator struct {
	sources  SourceLister
	discover Discoverer
	links    TargetResolver
}

// NewInvestigator requires all three seams.
func NewInvestigator(sources SourceLister, discover Discoverer, links TargetResolver) (*Investigator, error) {
	if sources == nil || discover == nil || links == nil {
		return nil, model.Fail(model.Invalid)
	}
	return &Investigator{sources, discover, links}, nil
}

func validInvestigation(req InvestigationRequest) error {
	switch req.Kind {
	case KindQueue, KindIncident, KindIssue, KindRelease, KindService, KindTrace, KindJob, KindReplay, KindProfile:
	default:
		return model.Fail(model.Invalid)
	}
	if len(req.Projects) == 0 || len(req.Projects) > MaxInvestigationProjects {
		return model.Fail(model.Invalid)
	}
	for i, p := range req.Projects {
		if p == (model.ID{}) || slices.Contains(req.Projects[:i], p) {
			return model.Fail(model.Invalid)
		}
	}
	if req.Window.Start >= req.Window.End || req.Limit == 0 || req.Limit > MaxInvestigationLimit {
		return model.Fail(model.Invalid)
	}
	if req.Target != nil && (*req.Target == (model.ID{}) || req.Kind == KindQueue) || req.Kind == KindTrace && req.Target == nil {
		return model.Fail(model.Invalid)
	}
	if req.Cursor != "" && (req.Kind != KindService || len(req.Cursor) > 4096) {
		return model.Fail(model.Invalid)
	}
	return nil
}

// Investigate returns the view of one typed request under scope. Every
// requested project must be inside the scope; anything else is the same
// NotFound a missing project gives.
func (i *Investigator) Investigate(ctx context.Context, scope auth.Scope, req InvestigationRequest) (InvestigationView, error) {
	if err := validInvestigation(req); err != nil {
		return InvestigationView{}, err
	}
	for _, p := range req.Projects {
		if !scope.AllowsProject(p) {
			return InvestigationView{}, model.Fail(model.NotFound)
		}
	}
	view := InvestigationView{Kind: req.Kind, Org: scope.OrgID(), Window: req.Window, MetricNames: []string{}, Sections: []ViewSection{}, Projects: make([]ProjectEvidence, len(req.Projects))}
	for n, p := range req.Projects {
		view.Projects[n] = ProjectEvidence{ProjectID: p, Sources: []auth.VisibleSource{}}
	}
	switch req.Kind {
	case KindService:
		return i.service(ctx, scope, req, view)
	case KindTrace:
		return i.trace(ctx, scope, req, view)
	case KindReplay, KindProfile:
		// Their own grants (replay.read, profiles.read) are not built, so a
		// telemetry.read scope must not even probe whether the target exists.
		return unavailable(view, ReasonGrantNotBuilt), nil
	}
	return unavailable(view, ReasonServiceNotBuilt), nil
}

func unavailable(view InvestigationView, reason string) InvestigationView {
	view.State, view.Reason = StateNotAvailable, reason
	view.Sections = []ViewSection{{Name: string(view.Kind), State: StateNotAvailable, Reason: reason}}
	return view
}

func (i *Investigator) trace(ctx context.Context, scope auth.Scope, req InvestigationRequest, view InvestigationView) (InvestigationView, error) {
	refs := make([]link.Reference, len(req.Projects))
	for n, p := range req.Projects {
		refs[n] = link.Reference{Project: p, Kind: "trace", ID: *req.Target, Relation: link.RelationExplicit}
	}
	resolved, err := i.links.Resolve(ctx, scope, refs)
	if err != nil {
		return InvestigationView{}, err
	}
	for n, r := range resolved {
		if n < len(refs) && r.Available && r.Reference != nil && r.Reference.ID == refs[n].ID && r.Reference.Project == refs[n].Project {
			view.Link = &TargetLink{Kind: "trace", ProjectID: refs[n].Project, ID: refs[n].ID, Available: true}
			break
		}
	}
	if view.Link == nil {
		return InvestigationView{}, model.Fail(model.NotFound)
	}
	view.State, view.Reason = StateIncomplete, ReasonSectionsAbsent
	view.Sections = []ViewSection{{Name: "link", State: StateReady}, {Name: "content", State: StateNotAvailable, Reason: ReasonViewNotBuilt}}
	return view, nil
}

func (i *Investigator) service(ctx context.Context, scope auth.Scope, req InvestigationRequest, view InvestigationView) (InvestigationView, error) {
	sources, err := i.sources.VisibleSources(ctx, scope)
	if err != nil {
		return InvestigationView{}, err
	}
	total := 0
	for _, s := range sources {
		for n := range view.Projects {
			if view.Projects[n].ProjectID == s.Project {
				view.Projects[n].Sources = append(view.Projects[n].Sources, s)
				total++
			}
		}
	}
	for n := range view.Projects {
		slices.SortFunc(view.Projects[n].Sources, func(a, b auth.VisibleSource) int { return slices.Compare(a.ID[:], b.ID[:]) })
	}
	evidence := ViewSection{Name: "evidence", State: StateReady}
	if total == 0 {
		evidence = ViewSection{Name: "evidence", State: StateEmpty, Reason: ReasonNoSources}
	}
	telemetry := ViewSection{Name: "telemetry", State: StateNotAvailable, Reason: ReasonRestrictedScope}
	if scope.Permission() == auth.Read {
		res, err := i.discover.Discover(ctx, scope, query.DiscoveryRequest{Projects: req.Projects, Signal: model.Metric, Kind: query.DiscoverMetricNames, Matchers: []query.Matcher{}, Time: req.Window, Limit: req.Limit, Cursor: req.Cursor})
		if err != nil {
			return InvestigationView{}, err
		}
		view.Freshness = &res.Freshness
		view.More, view.NextCursor = res.More, res.NextCursor
		if res.Items != nil {
			view.MetricNames = res.Items
		}
		switch res.Freshness.Completeness {
		case query.CompletenessComplete:
			telemetry = ViewSection{Name: "telemetry", State: StateReady}
			if len(res.Items) == 0 {
				telemetry.State = StateEmpty
			}
		case query.CompletenessPartial:
			telemetry = ViewSection{Name: "telemetry", State: StateIncomplete, Reason: ReasonShardsMissing}
		case query.CompletenessStale:
			telemetry = ViewSection{Name: "telemetry", State: StateStale, Reason: ReasonFreshnessStale}
		default:
			return InvestigationView{}, model.Fail(model.Unavailable)
		}
	}
	if req.Target != nil {
		view.Sections = append(view.Sections, ViewSection{Name: "identity", State: StateNotAvailable, Reason: ReasonRegistryAbsent})
	}
	view.Sections = append(view.Sections, evidence, telemetry)
	for _, name := range []string{"health", "dependencies", "releases"} {
		view.Sections = append(view.Sections, ViewSection{Name: name, State: StateNotAvailable, Reason: ReasonServiceNotBuilt})
	}
	switch {
	case telemetry.State == StateStale:
		view.State, view.Reason = StateStale, ReasonFreshnessStale
	case telemetry.State == StateIncomplete:
		view.State, view.Reason = StateIncomplete, ReasonShardsMissing
	case evidence.State == StateEmpty && telemetry.State == StateEmpty:
		view.State, view.Reason = StateEmpty, ReasonNoSources
	default:
		view.State, view.Reason = StateIncomplete, ReasonSectionsAbsent
	}
	return view, nil
}

// InvestigateBody is the POST /api/v1/investigate body: the scope fields of
// every owned read next to the typed request. No field names another
// principal's scope.
type InvestigateBody struct {
	ScopeFields
	InvestigationRequest
}

// RegisterInvestigateRoutes mounts POST /api/v1/investigate. The scope is
// derived from the caller's own credential before any service is touched, and
// revalidated before a single byte of the view is written.
func RegisterInvestigateRoutes(mux *http.ServeMux, authority *auth.Service, investigator *Investigator) {
	mux.HandleFunc("POST /api/v1/investigate", func(w http.ResponseWriter, r *http.Request) {
		credential, err := artifactCredential(authority, w, r)
		if err != nil {
			queryReply(w, nil, err)
			return
		}
		var body InvestigateBody
		if err = decode(w, r, &body); err != nil {
			queryReply(w, nil, err)
			return
		}
		scope, err := queryScope(r.Context(), authority, credential, body.ScopeFields, body.Projects, body.Source)
		if err != nil {
			queryReply(w, nil, err)
			return
		}
		view, err := investigator.Investigate(r.Context(), scope, body.InvestigationRequest)
		if err == nil {
			err = authority.Revalidate(r.Context(), scope)
		}
		if err == nil {
			err = authority.CommitElevatedRead(r.Context(), scope, "investigate.read", body.Projects)
		}
		queryReply(w, view, err)
	})
}
