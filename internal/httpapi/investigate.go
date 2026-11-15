// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/conditions"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/incidents"
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
	VisibleServices(context.Context, auth.Scope) ([]auth.VisibleService, error)
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
	health   HealthSource
}

// NewInvestigator requires all three seams.
func NewInvestigator(sources SourceLister, discover Discoverer, links TargetResolver) (*Investigator, error) {
	if sources == nil || discover == nil || links == nil {
		return nil, model.Fail(model.Invalid)
	}
	return &Investigator{sources: sources, discover: discover, links: links}, nil
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
	if req.Target != nil && (*req.Target == (model.ID{}) || req.Kind == KindQueue) || (req.Kind == KindTrace || req.Kind == KindReplay || req.Kind == KindProfile) && req.Target == nil {
		return model.Fail(model.Invalid)
	}
	if req.Environment != nil && (*req.Environment == (model.ID{}) || req.Kind != KindService) {
		return model.Fail(model.Invalid)
	}
	if req.Cursor != "" && (req.Kind != KindService || len(req.Cursor) > 4096) {
		return model.Fail(model.Invalid)
	}
	return nil
}

// TargetGrant reports whether the caller of a request holds the separate grant a target kind needs on one project (replay.read
// for "replay", profiles.read for "profile").
type TargetGrant func(ctx context.Context, project model.ID, kind string) bool

// Investigate returns the view of one typed request under scope with no separate grant held: replay and profile requests are the
// typed grant-required answer. Every requested project must be inside the scope; anything else is the same NotFound a missing
// project gives.
func (i *Investigator) Investigate(ctx context.Context, scope auth.Scope, req InvestigationRequest) (InvestigationView, error) {
	return i.InvestigateGranted(ctx, scope, req, nil)
}

// InvestigateGranted is Investigate for a caller whose separate grants granted answers (nil: none).
func (i *Investigator) InvestigateGranted(ctx context.Context, scope auth.Scope, req InvestigationRequest, granted TargetGrant) (InvestigationView, error) {
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
		// Their own grants (replay.read, profiles.read) are separate from telemetry.read: a caller without the grant on
		// every requested project gets one typed answer and the target is never probed, so a telemetry.read scope cannot
		// learn whether a replay or profile exists.
		if granted == nil {
			return unavailable(view, ReasonGrantRequired), nil
		}
		for _, p := range req.Projects {
			if !granted(ctx, p, string(req.Kind)) {
				return unavailable(view, ReasonGrantRequired), nil
			}
		}
		view, err := i.targetLink(ctx, scope, req, view, string(req.Kind))
		if err != nil {
			return InvestigationView{}, err
		}
		// The investigation gives the way to the target; the replay stream and the profile view are their own reads.
		view.State = StateReady
		view.Sections = []ViewSection{{Name: "link", State: StateReady}}
		return view, nil
	}
	return unavailable(view, ReasonServiceNotBuilt), nil
}

func unavailable(view InvestigationView, reason string) InvestigationView {
	view.State, view.Reason = StateNotAvailable, reason
	view.Sections = []ViewSection{{Name: string(view.Kind), State: StateNotAvailable, Reason: reason}}
	return view
}

// targetLink resolves req.Target as a record of kind in the requested projects under scope and sets view.Link; a target no project
// resolves is the one NotFound.
func (i *Investigator) targetLink(ctx context.Context, scope auth.Scope, req InvestigationRequest, view InvestigationView, kind string) (InvestigationView, error) {
	refs := make([]link.Reference, len(req.Projects))
	for n, p := range req.Projects {
		refs[n] = link.Reference{Project: p, Kind: kind, ID: *req.Target, Relation: link.RelationExplicit}
	}
	resolved, err := i.links.Resolve(ctx, scope, refs)
	if err != nil {
		return InvestigationView{}, err
	}
	for n, r := range resolved {
		if n < len(refs) && r.Available && r.Reference != nil && r.Reference.ID == refs[n].ID && r.Reference.Project == refs[n].Project {
			view.Link = &TargetLink{Kind: kind, ProjectID: refs[n].Project, ID: refs[n].ID, Available: true}
			break
		}
	}
	if view.Link == nil {
		return InvestigationView{}, model.Fail(model.NotFound)
	}
	return view, nil
}

func (i *Investigator) trace(ctx context.Context, scope auth.Scope, req InvestigationRequest, view InvestigationView) (InvestigationView, error) {
	view, err := i.targetLink(ctx, scope, req, view, "trace")
	if err != nil {
		return InvestigationView{}, err
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
	catalogue, err := i.sources.VisibleServices(ctx, scope)
	if err != nil {
		return InvestigationView{}, err
	}
	// D9: the services (and environments) are the resources the active source
	// policies admit. A target that no visible policy admits, in an environment
	// no policy lists, is the same NotFound as a missing project.
	matched := []auth.VisibleService{}
	for _, s := range catalogue {
		if !slices.Contains(req.Projects, s.Project) || req.Environment != nil && !slices.Contains(s.Environments, *req.Environment) || req.Target != nil && s.ID != *req.Target {
			continue
		}
		matched = append(matched, s)
	}
	if req.Target != nil && len(matched) == 0 {
		return InvestigationView{}, model.Fail(model.NotFound)
	}
	view.Services = matched
	narrowed := req.Target != nil || req.Environment != nil
	total := 0
	for _, s := range sources {
		if narrowed && !slices.ContainsFunc(matched, func(m auth.VisibleService) bool { return m.Project == s.Project && slices.Contains(m.Sources, s.ID) }) {
			continue
		}
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
	switch {
	case scope.Permission() != auth.Read:
	case narrowed:
		// The query engine has no resource dimension: a project-wide answer
		// would pass for this service's or environment's, so none is given.
		telemetry.Reason = ReasonResourceFilter
	default:
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
		view.Sections = append(view.Sections, ViewSection{Name: "identity", State: StateReady})
	}
	view.Sections = append(view.Sections, evidence, telemetry)
	if req.Target == nil {
		for _, name := range []string{"health", "dependencies", "releases"} {
			view.Sections = append(view.Sections, ViewSection{Name: name, State: StateNotAvailable, Reason: ReasonServiceNotSelected})
		}
	} else {
		health, section, err := i.serviceHealth(ctx, scope, *req.Target, matched)
		if err != nil {
			return InvestigationView{}, err
		}
		view.Health = health
		view.Sections = append(view.Sections, section, declared("dependencies", matched, func(s auth.VisibleService) int { return len(s.Dependencies) }, ""), declared("releases", matched, func(s auth.VisibleService) int { return len(s.Builds) }, ReasonReleaseRecordsAdmin))
	}
	switch {
	case telemetry.State == StateStale:
		view.State, view.Reason = StateStale, ReasonFreshnessStale
	case telemetry.State == StateIncomplete:
		view.State, view.Reason = StateIncomplete, ReasonShardsMissing
	case evidence.State == StateEmpty && (telemetry.State == StateEmpty || narrowed && len(matched) == 0):
		view.State, view.Reason = StateEmpty, ReasonNoSources
	case slices.ContainsFunc(view.Sections, func(s ViewSection) bool { return s.State == StateNotAvailable || s.State == StateIncomplete }):
		view.State, view.Reason = StateIncomplete, ReasonSectionsAbsent
	default:
		view.State = StateReady
	}
	return view, nil
}

// declared is the section of a fact the source policies declare (dependency
// names, allowed builds): empty when none is declared, otherwise ready, or
// incomplete with the reason when the deeper records need another grant.
func declared(name string, matched []auth.VisibleService, count func(auth.VisibleService) int, deeper string) ViewSection {
	n := 0
	for _, s := range matched {
		n += count(s)
	}
	switch {
	case n == 0:
		return ViewSection{Name: name, State: StateEmpty}
	case deeper != "":
		return ViewSection{Name: name, State: StateIncomplete, Reason: deeper}
	}
	return ViewSection{Name: name, State: StateReady}
}

// HealthSource is the committed incident and condition state behind a service's
// health; *control.Store implements it. Each read validates the scope itself.
type HealthSource interface {
	Incidents(ctx context.Context, scope auth.Scope, project model.ID) ([]control.IncidentRecord, error)
	Conditions(ctx context.Context, scope auth.Scope, project model.ID) ([]control.ConditionRecord, error)
}

// WithHealth installs the health source. Without one a service's health is an
// explicit not_available section, never healthy.
func (i *Investigator) WithHealth(h HealthSource) *Investigator {
	i.health = h
	return i
}

// HealthWired reports whether a health source is installed (the application wires the control store).
func (i *Investigator) HealthWired() bool { return i.health != nil }

// MaxHealthEvidence bounds the incidents and conditions listed per service.
const MaxHealthEvidence = 64

// serviceHealth is D9: failing when an open incident links the service,
// degraded when only active conditions name it, healthy when neither exists.
// Only a typed link names a service: an incident's service link, a condition's
// link IDs. A label, a name or a timestamp is never read as a service.
func (i *Investigator) serviceHealth(ctx context.Context, scope auth.Scope, service model.ID, matched []auth.VisibleService) (*ServiceHealth, ViewSection, error) {
	if i.health == nil {
		return nil, ViewSection{Name: "health", State: StateNotAvailable, Reason: ReasonHealthNotWired}, nil
	}
	h := &ServiceHealth{Status: HealthHealthy, Incidents: []HealthIncident{}, Conditions: []HealthCondition{}}
	for _, entry := range matched {
		incs, err := i.health.Incidents(ctx, scope, entry.Project)
		if err != nil {
			return i.healthDenied(err)
		}
		for _, rec := range incs {
			if rec.Erased() {
				continue
			}
			st, err := decodeIncident(rec)
			if err != nil {
				return nil, ViewSection{Name: "health", State: StateNotAvailable, Reason: ReasonHealthUnreadable}, nil
			}
			if st.Status != incidents.StatusOpen || !slices.Contains(st.Links, incidents.Link{Kind: incidents.LinkService, ID: service}) {
				continue
			}
			if len(h.Incidents) == MaxHealthEvidence {
				h.Truncated = true
				continue
			}
			h.Incidents = append(h.Incidents, HealthIncident{Project: entry.Project, ID: st.ID, Severity: severityName(st.Severity), Version: model.Uint64(st.Version)})
		}
		conds, err := i.health.Conditions(ctx, scope, entry.Project)
		if err != nil {
			return i.healthDenied(err)
		}
		for _, rec := range conds {
			if rec.Erased() {
				continue
			}
			var st conditions.State
			if json.Unmarshal(rec.State, &st) != nil || st.Condition != rec.ID || st.Version != rec.Version {
				return nil, ViewSection{Name: "health", State: StateNotAvailable, Reason: ReasonHealthUnreadable}, nil
			}
			if !st.Phase.Active() || !slices.Contains(st.Links, service) {
				continue
			}
			if len(h.Conditions) == MaxHealthEvidence {
				h.Truncated = true
				continue
			}
			h.Conditions = append(h.Conditions, HealthCondition{Project: entry.Project, ID: st.Condition, Phase: string(st.Phase), Severity: st.Severity, Freshness: string(st.Freshness)})
		}
	}
	switch {
	case len(h.Incidents) > 0:
		h.Status = HealthFailing
	case len(h.Conditions) > 0:
		h.Status = HealthDegraded
	}
	return h, ViewSection{Name: "health", State: StateReady}, nil
}

// healthDenied answers a health read the owner refused as a section of its own:
// the rest of the view stays, and the service is never reported healthy.
func (i *Investigator) healthDenied(err error) (*ServiceHealth, ViewSection, error) {
	var f *model.Fault
	if errors.As(err, &f) && (f.Code == model.Forbidden || f.Code == model.NotFound) {
		return nil, ViewSection{Name: "health", State: StateNotAvailable, Reason: ReasonHealthNotAuthorized}, nil
	}
	return nil, ViewSection{}, err
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
		granted := func(ctx context.Context, project model.ID, kind string) bool {
			return holdsTargetGrant(ctx, authority, credential, scope.OrgID(), project, kind)
		}
		view, err := investigator.InvestigateGranted(r.Context(), scope, body.InvestigationRequest, granted)
		if err == nil {
			err = authority.Revalidate(r.Context(), scope)
		}
		if err == nil {
			err = authority.CommitElevatedRead(r.Context(), scope, "investigate.read", body.Projects)
		}
		queryReply(w, view, err)
	})
}
