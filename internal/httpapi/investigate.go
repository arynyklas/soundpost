// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/conditions"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/incidents"
	"github.com/arynyklas/soundpost/internal/jobs"
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
	// Optional owner reads installed by WithHealth from the same control store; nil means the owner is not wired.
	incidents IncidentReader
	jobs      JobDetailReader
	state     ControlView
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
	if req.Target != nil && (*req.Target == (model.ID{}) || req.Kind == KindQueue) || (req.Kind == KindTrace || req.Kind == KindReplay || req.Kind == KindProfile || req.Kind == KindIncident || req.Kind == KindIssue || req.Kind == KindRelease || req.Kind == KindJob) && req.Target == nil {
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
	case KindQueue:
		return i.queue(ctx, scope, req, view)
	case KindIncident:
		return i.incident(ctx, scope, req, view)
	case KindJob:
		return i.job(ctx, scope, req, view)
	case KindRelease:
		return i.release(ctx, scope, req, view)
	case KindIssue:
		return i.issue(ctx, scope, req, view)
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
	// The control store that is the health source is also the owner of the incident, job, release and issue records: the narrower
	// reads are installed from it by interface assertion, so the application's single WithHealth(control store) call wires them. A
	// health source that is not such a store leaves those kinds explicitly not_available.
	i.incidents, _ = h.(IncidentReader)
	i.jobs, _ = h.(JobDetailReader)
	i.state, _ = h.(ControlView)
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

// IncidentReader, JobDetailReader and ControlView are the committed owner reads behind the queue, incident, job, release and issue
// kinds; *control.Store implements all of them and validates the scope itself.
type IncidentReader interface {
	Incident(ctx context.Context, scope auth.Scope, project, incident model.ID) (control.IncidentRecord, bool, error)
	Incidents(ctx context.Context, scope auth.Scope, project model.ID) ([]control.IncidentRecord, error)
}
type JobDetailReader interface {
	JobDetail(ctx context.Context, scope auth.Scope, project, job model.ID) (control.JobEntry, bool, error)
}
type ControlView interface {
	View(ctx context.Context, fn func(model.ControlState) error) error
}

func incidentSummary(project model.ID, st incidents.State) IncidentSummary {
	s := IncidentSummary{ProjectID: project, ID: st.ID, Status: string(st.Status), Severity: severityName(st.Severity), Version: model.Uint64(st.Version)}
	if n := len(st.Timeline); n > 0 {
		s.LastActivity = model.Int64(st.Timeline[n-1].At)
	}
	return s
}

// ready answers one found record as a single-section view.
func ready(view InvestigationView, section string) InvestigationView {
	view.State = StateReady
	view.Sections = []ViewSection{{Name: section, State: StateReady}}
	return view
}

// queue lists the committed incidents of the requested projects, bounded by req.Limit.
func (i *Investigator) queue(ctx context.Context, scope auth.Scope, req InvestigationRequest, view InvestigationView) (InvestigationView, error) {
	if i.incidents == nil {
		return unavailable(view, ReasonIncidentSourceNotWired), nil
	}
	var all []IncidentSummary
	for _, p := range req.Projects {
		records, err := i.incidents.Incidents(ctx, scope, p)
		if err != nil {
			return InvestigationView{}, err
		}
		for _, rec := range records {
			if rec.Erased() {
				continue
			}
			st, err := decodeIncident(rec)
			if err != nil {
				return InvestigationView{}, err
			}
			all = append(all, incidentSummary(p, st))
		}
	}
	slices.SortFunc(all, func(x, y IncidentSummary) int {
		if ox, oy := x.Status == string(incidents.StatusOpen), y.Status == string(incidents.StatusOpen); ox != oy {
			if ox {
				return -1
			}
			return 1
		}
		if x.Severity != y.Severity {
			return -cmp.Compare(severityRank(x.Severity), severityRank(y.Severity))
		}
		if x.LastActivity != y.LastActivity {
			return -cmp.Compare(x.LastActivity, y.LastActivity)
		}
		return slices.Compare(x.ID[:], y.ID[:])
	})
	if len(all) > int(req.Limit) {
		all, view.More = all[:req.Limit], true
	}
	view.Queue = all
	if len(all) == 0 {
		view.State = StateEmpty
		view.Sections = []ViewSection{{Name: "queue", State: StateEmpty}}
		return view, nil
	}
	return ready(view, "queue"), nil
}

// incident reads the one targeted incident from the first requested project that holds it; an erased, missing or foreign one is
// the one NotFound.
func (i *Investigator) incident(ctx context.Context, scope auth.Scope, req InvestigationRequest, view InvestigationView) (InvestigationView, error) {
	if i.incidents == nil {
		return unavailable(view, ReasonIncidentSourceNotWired), nil
	}
	for _, p := range req.Projects {
		rec, found, err := i.incidents.Incident(ctx, scope, p, *req.Target)
		if err != nil {
			return InvestigationView{}, err
		}
		if !found || rec.Erased() {
			continue
		}
		st, err := decodeIncident(rec)
		if err != nil {
			return InvestigationView{}, err
		}
		s := incidentSummary(p, st)
		view.Incident = &s
		return ready(view, "incident"), nil
	}
	return InvestigationView{}, model.Fail(model.NotFound)
}

// job reads the one targeted committed job book.
func (i *Investigator) job(ctx context.Context, scope auth.Scope, req InvestigationRequest, view InvestigationView) (InvestigationView, error) {
	if i.jobs == nil {
		return unavailable(view, ReasonJobServiceNotWired), nil
	}
	for _, p := range req.Projects {
		entry, found, err := i.jobs.JobDetail(ctx, scope, p, *req.Target)
		if err != nil {
			return InvestigationView{}, err
		}
		if !found || entry.Snapshot.Erased {
			continue
		}
		var st jobs.JobState
		if json.Unmarshal(entry.Snapshot.State, &st) != nil || st.Org != scope.OrgID() || st.Project != p || st.Job != entry.Job || st.Version != entry.Snapshot.Version {
			return InvestigationView{}, model.Fail(model.Corrupt)
		}
		view.Job = &JobSummary{ProjectID: p, ID: entry.Job, Version: model.Uint64(entry.Snapshot.Version), Runs: uint32(len(st.Runs)), Attempts: uint32(len(st.Attempts))}
		return ready(view, "job"), nil
	}
	return InvestigationView{}, model.Fail(model.NotFound)
}

// adminState runs fn on the committed control state of a request that holds the organization-admin scope the release and issue
// registries need (the same gate as their dedicated views): any other scope gets the typed reason and nothing is read. fn runs
// per requested project; the first one that finds the target wins.
func (i *Investigator) adminState(ctx context.Context, scope auth.Scope, req InvestigationRequest, view InvestigationView, notWired, needsAdmin string, fn func(st model.ControlState, p model.ID) (InvestigationView, bool)) (InvestigationView, error) {
	if i.state == nil {
		return unavailable(view, notWired), nil
	}
	if scope.Permission() != auth.OrgAdmin {
		return unavailable(view, needsAdmin), nil
	}
	var out InvestigationView
	found := false
	err := i.state.View(ctx, func(st model.ControlState) error {
		if err := scope.ValidateControlState(st); err != nil {
			return err
		}
		org, ok := st.Orgs[scope.OrgID().String()]
		if !ok || !org.Admins[scope.PrincipalID().String()] {
			return model.Fail(model.NotFound)
		}
		for _, p := range req.Projects {
			if _, ok := org.Projects[p.String()]; !ok {
				return model.Fail(model.NotFound)
			}
		}
		for _, p := range req.Projects {
			if out, found = fn(st, p); found {
				return nil
			}
		}
		return nil
	})
	if err != nil {
		return InvestigationView{}, err
	}
	if !found {
		return InvestigationView{}, model.Fail(model.NotFound)
	}
	return out, nil
}

func (i *Investigator) release(ctx context.Context, scope auth.Scope, req InvestigationRequest, view InvestigationView) (InvestigationView, error) {
	return i.adminState(ctx, scope, req, view, ReasonReleasesNotBuilt, ReasonReleaseRecordsAdmin, func(st model.ControlState, p model.ID) (InvestigationView, bool) {
		rel, ok := st.Releases[model.ReleaseScopeKey(scope.OrgID(), p, *req.Target)]
		if !ok || rel.ID != *req.Target || rel.Org != scope.OrgID() || rel.Project != p {
			return InvestigationView{}, false
		}
		view.Release = &ReleaseSummary{ProjectID: p, ID: rel.ID, BuildID: rel.BuildID, Parents: append([]model.ID{}, rel.Parents...), Revision: model.Uint64(rel.Revision), BuildTime: model.Int64(rel.BuildTime), DebugArtifacts: uint32(len(rel.DebugArtifacts))}
		return ready(view, "release"), true
	})
}

func (i *Investigator) issue(ctx context.Context, scope auth.Scope, req InvestigationRequest, view InvestigationView) (InvestigationView, error) {
	return i.adminState(ctx, scope, req, view, ReasonIssueEvidenceAbsent, ReasonIssueNeedsAdmin, func(st model.ControlState, p model.ID) (InvestigationView, bool) {
		gi, ok := st.GroupingIssues[model.ReleaseScopeKey(scope.OrgID(), p, *req.Target)]
		if !ok || gi.ID != *req.Target || gi.Org != scope.OrgID() || gi.Project != p {
			return InvestigationView{}, false
		}
		s := IssueSummary{ProjectID: p, ID: gi.ID, Workflow: gi.Workflow, GroupingVersion: gi.GroupingVersion, Revision: model.Uint64(gi.Revision), Occurrences: model.Uint64(len(gi.Occurrences)), LateHistory: model.Uint64(len(gi.LateHistory))}
		if c := gi.Compacted; c != nil {
			s.Occurrences += c.Count
			s.Compacted = true
		}
		if c := gi.LateCompacted; c != nil {
			s.LateHistory += c.Count
			s.Compacted = true
		}
		view.Issue = &s
		out := ready(view, "issue")
		if s.Compacted {
			out.State, out.Reason = StateIncomplete, ReasonEvidenceCompacted
			out.Sections = []ViewSection{{Name: "issue", State: StateIncomplete, Reason: ReasonEvidenceCompacted}}
		}
		return out, true
	})
}
