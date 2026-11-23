// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/gitlab"
	"github.com/arynyklas/soundpost/internal/incidents"
	"github.com/arynyklas/soundpost/internal/model"
)

// Markdown copy of an incident or error issue (docs/operations/console-api.md
// section 10a): a link, a task description (identifiers, severity, status, linked
// entity IDs, link: no telemetry text) or, for an incident, the timeline. Every
// piece of user text (reasons, titles, notes) is escaped by gitlab.Line / Quote so
// it cannot inject HTML, links, tables or headings into the place it is pasted.

// Markdown formats.
const (
	MarkdownLink        = "link"
	MarkdownDescription = "description"
	MarkdownTimeline    = "timeline"
)

// Reasons of a markdown answer that is not ready.
const (
	ReasonPublicOriginNotConfigured = "public_origin_not_configured"
	ReasonMarkdownIssuesNotBound    = ReasonIssueActionsNotBuilt
)

// MarkdownBody is the POST /api/v1/incidents/markdown and /issues/markdown body.
type MarkdownBody struct {
	Org       model.ID `json:"org"`
	ProjectID model.ID `json:"project_id"`
	ID        model.ID `json:"id"`
	Format    string   `json:"format"`
}

// MarkdownAnswer is the answer. State is ready or not_available (with Reason); the
// text is never invented.
type MarkdownAnswer struct {
	State    ViewState `json:"state"`
	Reason   string    `json:"reason,omitempty"`
	Markdown string    `json:"markdown,omitempty"`
}

// MarkdownCopy builds the copy texts under the caller's own read scope.
type MarkdownCopy struct {
	actions *Actions
	origin  string
}

// NewMarkdownCopy needs the action surface (it reads incidents and issues through
// the same services and scopes) and the node's public origin ("" when unset).
func NewMarkdownCopy(actions *Actions, origin string) (*MarkdownCopy, error) {
	if actions == nil {
		return nil, model.Fail(model.Invalid)
	}
	return &MarkdownCopy{actions: actions, origin: origin}, nil
}

func validMarkdownBody(b MarkdownBody, incident bool) error {
	if b.Org == (model.ID{}) || b.ProjectID == (model.ID{}) || b.ID == (model.ID{}) {
		return invalid("action_ids_required")
	}
	switch b.Format {
	case MarkdownLink, MarkdownDescription:
	case MarkdownTimeline:
		if !incident {
			return invalid("markdown_format_invalid")
		}
	default:
		return invalid("markdown_format_invalid")
	}
	return nil
}

func mdNotAvailable(reason string) MarkdownAnswer {
	return MarkdownAnswer{State: StateNotAvailable, Reason: reason}
}

func mdReady(text string) MarkdownAnswer { return MarkdownAnswer{State: StateReady, Markdown: text} }

// Incident renders one incident. A project outside the scope, a missing incident
// and an erased one are the answers GetIncident gives.
func (m *MarkdownCopy) Incident(ctx context.Context, scope auth.Scope, b MarkdownBody) (MarkdownAnswer, error) {
	if err := validMarkdownBody(b, true); err != nil {
		return MarkdownAnswer{}, err
	}
	st, err := m.actions.incidents.Get(ctx, scope, b.ProjectID, b.ID)
	if err != nil {
		return MarkdownAnswer{}, err
	}
	if st.Erased {
		f := model.Fail(model.NotFound)
		f.SafeDetail = incidents.DetailErased
		return MarkdownAnswer{}, f
	}
	link, hasLink := gitlab.Link(m.origin, b.Org, gitlab.KindIncident, b.ProjectID, b.ID)
	switch b.Format {
	case MarkdownLink:
		if !hasLink {
			return mdNotAvailable(ReasonPublicOriginNotConfigured), nil
		}
		return mdReady(link), nil
	case MarkdownDescription:
		related := make([]gitlab.Ref, 0, len(st.Links))
		for _, l := range st.Links {
			related = append(related, gitlab.Ref{Kind: string(l.Kind), ID: l.ID})
		}
		return mdReady(gitlab.Description(gitlab.Facts{Kind: gitlab.KindIncident, ID: st.ID, Project: st.Project, Severity: severityName(st.Severity), Status: string(st.Status), Related: related}, link)), nil
	}
	return mdReady(incidentTimeline(st, link)), nil
}

// Issue renders one error issue.
func (m *MarkdownCopy) Issue(ctx context.Context, scope auth.Scope, b MarkdownBody) (MarkdownAnswer, error) {
	if err := validMarkdownBody(b, false); err != nil {
		return MarkdownAnswer{}, err
	}
	if m.actions.issues == nil {
		return mdNotAvailable(ReasonMarkdownIssuesNotBound), nil
	}
	issue, err := m.actions.issues.Get(ctx, scope, b.ProjectID, b.ID)
	if err != nil {
		return MarkdownAnswer{}, err
	}
	link, hasLink := gitlab.Link(m.origin, b.Org, gitlab.KindIssue, b.ProjectID, b.ID)
	if b.Format == MarkdownLink {
		if !hasLink {
			return mdNotAvailable(ReasonPublicOriginNotConfigured), nil
		}
		return mdReady(link), nil
	}
	const maxReleases = 8
	related := make([]gitlab.Ref, 0, maxReleases)
	for _, r := range issue.ObservedReleases {
		if len(related) == maxReleases {
			break
		}
		related = append(related, gitlab.Ref{Kind: "release", ID: r})
	}
	return mdReady(gitlab.Description(gitlab.Facts{Kind: gitlab.KindIssue, ID: issue.ID, Project: issue.Project, Status: issue.Workflow, Related: related}, link)), nil
}

func rfc3339(ns model.UnixNano) string {
	return time.Unix(0, int64(ns)).UTC().Format(time.RFC3339)
}

// incidentTimeline is the chronological Markdown of the timeline. The actor is the
// stored ID (no directory lookup); notes are block-quoted and escaped.
func incidentTimeline(st incidents.State, link string) string {
	var b strings.Builder
	b.WriteString("# Soundpost incident " + gitlab.Code(gitlab.Short(st.ID)) + " timeline\n\n")
	b.WriteString("- Incident: " + gitlab.Code(st.ID.String()) + "\n")
	b.WriteString("- Project: " + gitlab.Code(st.Project.String()) + "\n")
	b.WriteString("- Status: " + gitlab.Code(string(st.Status)) + "\n")
	b.WriteString("- Severity: " + gitlab.Code(severityName(st.Severity)) + "\n")
	if st.Title != "" {
		b.WriteString("- Title: " + gitlab.Line(st.Title) + "\n")
	}
	if link != "" {
		b.WriteString("- Link: " + gitlab.Code(link) + "\n")
	}
	b.WriteString("\n## Timeline\n\n")
	for _, e := range st.Timeline {
		a := e.Action
		b.WriteString("- " + gitlab.Code(rfc3339(e.At)) + " " + gitlab.Code(string(a.Type)) + " by " + gitlab.Code(a.Actor.String()) + " (" + gitlab.Line(string(a.Origin)) + ")\n")
		if a.Reason != "" {
			b.WriteString("  - Reason: " + gitlab.Line(a.Reason) + "\n")
		}
		if a.Title != "" {
			b.WriteString("  - Title: " + gitlab.Line(a.Title) + "\n")
		}
		if a.Owner != nil {
			b.WriteString("  - Owner: " + gitlab.Code(a.Owner.String()) + "\n")
		}
		if a.Until != 0 {
			b.WriteString("  - Until: " + gitlab.Code(rfc3339(a.Until)) + "\n")
		}
		if a.Impact != nil {
			b.WriteString("  - Impact: " + gitlab.Code(severityName(a.Impact.Severity)) + ", " + gitlab.Code(string(a.Impact.State)) + ", " + gitlab.Code(string(a.Impact.Freshness)) + "\n")
		}
		if a.Link != nil {
			b.WriteString("  - Link: " + gitlab.Code(string(a.Link.Kind)) + " " + gitlab.Code(a.Link.ID.String()) + "\n")
		}
		if x := a.External; x != nil {
			b.WriteString("  - External: " + gitlab.Code(x.Provider) + " " + gitlab.Code(x.Kind) + " " + gitlab.Code(x.Result) + "\n")
		}
		if a.Note != "" {
			b.WriteString("  - Note:\n")
			for _, l := range strings.Split(gitlab.Quote(a.Note), "\n") {
				b.WriteString("    " + l + "\n")
			}
		}
	}
	return b.String()
}

// issueReadScope derives the scope an issue read runs under: telemetry.read,
// issues.write or organization admin on the project, whichever the caller's own
// credential holds; none of them is the one not-found.
func issueReadScope(ctx context.Context, s *auth.Service, c auth.Credential, org, project model.ID) (auth.Scope, error) {
	if org == (model.ID{}) || project == (model.ID{}) {
		return auth.Scope{}, model.Fail(model.Invalid)
	}
	scope, err := s.Authorize(ctx, c, org, []model.ID{project}, auth.Read)
	if err != nil && faultIs(err, model.NotFound) {
		for _, fallback := range []auth.Permission{auth.IssuesWrite, auth.OrgAdmin} {
			if granted, e := s.Authorize(ctx, c, org, []model.ID{project}, fallback); e == nil {
				return granted, nil
			}
		}
	}
	return scope, err
}

// RegisterMarkdownRoutes mounts the copy routes.
//
//	POST /api/v1/incidents/markdown   MarkdownBody -> MarkdownAnswer
//	POST /api/v1/issues/markdown      MarkdownBody -> MarkdownAnswer
func RegisterMarkdownRoutes(mux *http.ServeMux, authority *auth.Service, copy *MarkdownCopy) {
	route := func(path string, incident bool) {
		mux.HandleFunc("POST "+path, func(w http.ResponseWriter, r *http.Request) {
			credential, err := artifactCredential(authority, w, r)
			if err != nil {
				queryReply(w, nil, err)
				return
			}
			var body MarkdownBody
			if err = decode(w, r, &body); err != nil {
				queryReply(w, nil, err)
				return
			}
			if err = validMarkdownBody(body, incident); err != nil {
				queryReply(w, nil, err)
				return
			}
			var scope auth.Scope
			if incident {
				scope, err = readScope(r.Context(), authority, credential, body.Org, []model.ID{body.ProjectID})
			} else {
				scope, err = issueReadScope(r.Context(), authority, credential, body.Org, body.ProjectID)
			}
			if err != nil {
				queryReply(w, nil, err)
				return
			}
			var answer MarkdownAnswer
			if incident {
				answer, err = copy.Incident(r.Context(), scope, body)
			} else {
				answer, err = copy.Issue(r.Context(), scope, body)
			}
			if err == nil {
				err = authority.Revalidate(r.Context(), scope)
			}
			queryReply(w, answer, err)
		})
	}
	route("/api/v1/incidents/markdown", true)
	route("/api/v1/issues/markdown", false)
}
