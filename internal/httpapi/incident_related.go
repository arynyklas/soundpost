// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"net/http"
	"slices"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/incidents"
	"github.com/arynyklas/soundpost/internal/model"
)

// MaxRelatedProposals bounds one related-incident answer; More says there were further ones.
const MaxRelatedProposals = 64

// RelatedBody is the POST /api/v1/incidents/related body. The organization and project are selectors that the caller's own
// credential confirms (readScope); the incident is looked up only inside that project.
type RelatedBody struct {
	Org        model.ID `json:"org"`
	ProjectID  model.ID `json:"project_id"`
	IncidentID model.ID `json:"incident_id"`
}

// RelatedProposal says that another open incident shares structured evidence with the target: the links (a service, a release or
// an error issue) they have in common, and nothing else about it. It is a proposal only: nothing is merged, linked or changed.
type RelatedProposal struct {
	ProjectID  model.ID         `json:"project_id"`
	IncidentID model.ID         `json:"incident_id"`
	Status     string           `json:"status"`
	Severity   string           `json:"severity"`
	Shared     []incidents.Link `json:"shared"`
}

// RelatedView answers a related-incident request. Proposals is the empty list when there are none (never null); More is true
// when more than MaxRelatedProposals incidents are related and the list is cut.
type RelatedView struct {
	Proposals []RelatedProposal `json:"proposals"`
	More      bool              `json:"more,omitempty"`
}

// Related proposes related incidents. It reads the committed incident records of the one project the caller's scope names
// (control validates the scope before it looks at any record) and only ever answers incidents of that project: the structured
// links of an incident (issue, release and service IDs) are project-local, which is also the rule of incidents.Correlate, so an
// incident of another project, readable or not, is never read and never named.
type Related struct{ lister IncidentLister }

// NewRelated binds the incident lister (*control.Store implements it). Without one every answer is Unavailable.
func NewRelated(lister IncidentLister) *Related { return &Related{lister: lister} }

// Proposals answers the incidents related to the target under scope. The target is looked up among the project's committed,
// non-erased incidents: a missing one, an erased one and one outside the scope are the same NotFound. A resolved target has no
// proposals (only open incidents are correlated), and an erased incident is never a candidate.
func (r *Related) Proposals(ctx context.Context, scope auth.Scope, project, incident model.ID) (RelatedView, error) {
	if r == nil || r.lister == nil {
		return RelatedView{}, model.Fail(model.Unavailable)
	}
	if project == (model.ID{}) || incident == (model.ID{}) {
		return RelatedView{}, invalid("action_ids_required")
	}
	records, err := r.lister.Incidents(ctx, scope, project)
	if err != nil {
		return RelatedView{}, err
	}
	var target incidents.State
	found := false
	var others []incidents.State
	for _, rec := range records {
		if rec.Erased() {
			continue
		}
		st, err := decodeIncident(rec)
		if err != nil {
			return RelatedView{}, err
		}
		if st.Org != scope.OrgID() || st.Project != project {
			return RelatedView{}, model.Fail(model.Corrupt)
		}
		if st.ID == incident {
			target, found = st, true
			continue
		}
		others = append(others, st)
	}
	if !found {
		return RelatedView{}, model.Fail(model.NotFound)
	}
	view := RelatedView{Proposals: []RelatedProposal{}}
	if target.Status != incidents.StatusOpen {
		return view, nil
	}
	// Correlate runs on the target and one candidate at a time: the work is the number of incidents of the project (bounded by the
	// control group) times the links of two incidents, never the square of the project.
	byIncident := map[model.ID]*RelatedProposal{}
	for _, other := range others {
		for _, p := range incidents.Correlate([]incidents.State{target, other}) {
			rp := byIncident[other.ID]
			if rp == nil {
				rp = &RelatedProposal{ProjectID: project, IncidentID: other.ID, Status: string(other.Status), Severity: severityName(other.Severity), Shared: []incidents.Link{}}
				byIncident[other.ID] = rp
			}
			rp.Shared = append(rp.Shared, p.Evidence)
		}
	}
	for _, rp := range byIncident {
		view.Proposals = append(view.Proposals, *rp)
	}
	slices.SortFunc(view.Proposals, func(a, b RelatedProposal) int { return slices.Compare(a.IncidentID[:], b.IncidentID[:]) })
	if len(view.Proposals) > MaxRelatedProposals {
		view.Proposals, view.More = view.Proposals[:MaxRelatedProposals], true
	}
	return view, nil
}

// RegisterRelatedRoutes mounts the read-only related-incident route:
//
//	POST /api/v1/incidents/related   RelatedBody -> RelatedView
//
// The scope is the caller's own on the named project (readScope: telemetry.read, incidents.write or organization administration),
// derived before any record is read and revalidated before the answer is written.
func RegisterRelatedRoutes(mux *http.ServeMux, authority *auth.Service, related *Related) {
	mux.HandleFunc("POST /api/v1/incidents/related", func(w http.ResponseWriter, r *http.Request) {
		credential, err := artifactCredential(authority, w, r)
		if err != nil {
			queryReply(w, nil, err)
			return
		}
		var body RelatedBody
		if err = decode(w, r, &body); err != nil {
			queryReply(w, nil, err)
			return
		}
		scope, err := readScope(r.Context(), authority, credential, body.Org, []model.ID{body.ProjectID})
		if err != nil {
			queryReply(w, nil, err)
			return
		}
		view, err := related.Proposals(r.Context(), scope, body.ProjectID, body.IncidentID)
		if err == nil {
			err = authority.Revalidate(r.Context(), scope)
		}
		queryReply(w, view, err)
	})
}
