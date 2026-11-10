// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"unicode"
	"unicode/utf8"

	"soundpost/internal/auth"
	"soundpost/internal/model"
	"soundpost/internal/releases"
	"soundpost/internal/symbolicate"
)

// This file is the C11 error-investigation surface of the UI: symbolicated
// frames, release ancestry and persisted issue evidence. It is a thin,
// scope-first projection over three consumer-owned seams. The committed
// artifact read/upload routes stay in artifacts.go; nothing here streams or
// stores artifact bytes, and nothing here fetches a URL: symbolication resolves
// an exact scoped ArtifactID through the owned service only.
//
// Every route derives its scope from the caller's own credential before any
// service is reached. A wrong organization, a project the caller does not hold
// and a missing target are one indistinguishable not-found. A seam that is not
// wired is an explicit not_available state, never an empty success.

// Reason codes of the evidence surface (closed vocabulary of static strings).
const (
	ReasonSymbolicatorNotBuilt = "symbolicator_not_wired"
	ReasonArtifactGrantAbsent  = "artifact_read_not_granted"
	ReasonReleasesNotBuilt     = "release_reader_not_wired"
	ReasonReleaseNeedsAdmin    = "release_records_need_org_admin"
	ReasonIssueEvidenceAbsent  = "issue_evidence_view_not_built"
	ReasonIssueNeedsAdmin      = "issue_evidence_needs_org_admin"
	ReasonOccurrenceDetail     = "occurrence_payload_view_not_built"
	ReasonRegressionDetail     = "regression_explanation_view_not_built"
	ReasonSourcesNotRequested  = "sources_not_requested"
	ReasonSourcesGrantRequired = "source_grant_required"
	ReasonNoSourceContent      = "no_source_content"
	ReasonFrameNotMapped       = "frame_not_mapped"
)

// Evidence bounds. A request never names more than MaxEvidenceFrames frames or
// MaxEvidenceCompare releases; every text field is bounded plain text.
const (
	MaxEvidenceFrames  = 64
	MaxEvidenceCompare = 16
	maxFrameText       = 512
)

// FrameResolver is C07 as the handler consumes it; *symbolicate.Service
// implements it. Source content is only ever requested through
// ResolveWithOptions{IncludeSources:true}, which the owned service answers only
// for a scope that also holds the separate private-source grant.
type FrameResolver interface {
	ResolveWithOptions(ctx context.Context, scope auth.Scope, build model.ID, frames []model.Frame, options symbolicate.Options) ([]symbolicate.SymbolicatedFrame, error)
}

// ReleaseReader is the committed release registry; *releases.Service implements
// it and needs an organization-admin scope.
type ReleaseReader interface {
	Get(ctx context.Context, scope auth.Scope, project, id model.ID) (model.Release, error)
	Graph(ctx context.Context, scope auth.Scope, project model.ID) (releases.Graph, error)
}

// IssueEvidenceReader reads one persisted issue with its grouping version,
// fingerprint and evidence; *releases.Service implements it (an org-admin
// read of the committed grouping issues). A nil reader is an explicit
// not_available state.
type IssueEvidenceReader interface {
	GroupingIssue(ctx context.Context, scope auth.Scope, project, id model.ID) (model.GroupingIssue, error)
}

// Evidence is the handler set behind /api/v1/evidence/*. Any seam may be nil.
type Evidence struct {
	frames   FrameResolver
	releases ReleaseReader
	issues   IssueEvidenceReader
}

// NewEvidence binds the three optional seams.
func NewEvidence(frames FrameResolver, releases ReleaseReader, issues IssueEvidenceReader) *Evidence {
	return &Evidence{frames: frames, releases: releases, issues: issues}
}

// FramesBody is the POST /api/v1/evidence/frames body. Org and Project are
// selectors authorization confirms; Build is the build identity the frames'
// artifacts must belong to. IncludeSources asks for private source context,
// which the owned service releases only to a reader holding the separate grant.
type FramesBody struct {
	Org            model.ID      `json:"org"`
	Project        model.ID      `json:"project"`
	Build          model.ID      `json:"build"`
	Frames         []model.Frame `json:"frames"`
	IncludeSources bool          `json:"include_sources"`
}

// SourceView says whether source text for one frame was released. Context is
// present only when State is "present".
type SourceView struct {
	State   string  `json:"state"` // present | withheld | absent
	Reason  string  `json:"reason,omitempty"`
	Context *string `json:"context,omitempty"`
}

// FrameEvidence is one frame: the original sanitized identity is always kept
// and Reason says why a mapped position is or is not given.
type FrameEvidence struct {
	Original  model.Frame               `json:"original"`
	Reason    string                    `json:"reason"`
	Resolved  *symbolicate.CodeIdentity `json:"resolved,omitempty"`
	MapSHA256 *model.Hash               `json:"map_sha256,omitempty"`
	Source    SourceView                `json:"source"`
}

// FramesView answers a frames request.
type FramesView struct {
	Org      model.ID        `json:"org"`
	Project  model.ID        `json:"project"`
	Build    model.ID        `json:"build"`
	State    ViewState       `json:"state"`
	Reason   string          `json:"reason,omitempty"`
	Frames   []FrameEvidence `json:"frames"`
	Sections []ViewSection   `json:"sections"`
}

func safeText(s string) bool {
	if len(s) > maxFrameText || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func validFrames(body FramesBody) error {
	if body.Org == (model.ID{}) || body.Project == (model.ID{}) || body.Build == (model.ID{}) || len(body.Frames) == 0 || len(body.Frames) > MaxEvidenceFrames {
		return invalid("evidence_request_invalid")
	}
	for _, f := range body.Frames {
		if !safeText(f.Module) || !safeText(f.Function) || !safeText(f.Artifact) {
			return invalid("evidence_frame_invalid")
		}
	}
	return nil
}

func copyFrame(f model.Frame) model.Frame {
	if f.Column != nil {
		c := *f.Column
		f.Column = &c
	}
	return f
}

func faultIs(err error, code model.Code) bool {
	var f *model.Fault
	return errors.As(err, &f) && f.Code == code
}

// Frames resolves the frames under the caller's own authority. A caller with
// artifacts.read on the project gets mapped positions; a telemetry-only reader
// of the same project still gets the original sanitized frames, each with an
// explicit reason and never a mapped position or source text; anyone else gets
// the one not-found.
func (e *Evidence) Frames(ctx context.Context, authority *auth.Service, credential auth.Credential, body FramesBody) (FramesView, auth.Scope, error) {
	if err := validFrames(body); err != nil {
		return FramesView{}, auth.Scope{}, err
	}
	view := FramesView{Org: body.Org, Project: body.Project, Build: body.Build, Frames: make([]FrameEvidence, len(body.Frames)), Sections: []ViewSection{}}
	sourcesState := SourceView{State: "withheld", Reason: ReasonSourcesNotRequested}
	if body.IncludeSources {
		// Requested but not (yet) released: a frame that is not mapped has no source
		// context to show, whatever the grant.
		sourcesState = SourceView{State: "absent", Reason: ReasonFrameNotMapped}
	}
	for i, f := range body.Frames {
		view.Frames[i] = FrameEvidence{Original: copyFrame(f), Reason: string(symbolicate.Unavailable), Source: sourcesState}
	}
	scope, err := authority.Authorize(ctx, credential, body.Org, []model.ID{body.Project}, auth.ArtifactRead)
	if err != nil {
		if !faultIs(err, model.NotFound) {
			return FramesView{}, auth.Scope{}, err
		}
		// Not an artifact reader: a telemetry reader of this very project may still
		// see the sanitized frame identities she supplied, nothing mapped.
		read, readErr := authority.Authorize(ctx, credential, body.Org, []model.ID{body.Project}, auth.Read)
		if readErr != nil {
			return FramesView{}, auth.Scope{}, readErr
		}
		for i := range view.Frames {
			view.Frames[i].Reason = ReasonArtifactGrantAbsent
			if body.IncludeSources {
				view.Frames[i].Source = SourceView{State: "withheld", Reason: ReasonSourcesGrantRequired}
			}
		}
		view.State, view.Reason = StateIncomplete, ReasonArtifactGrantAbsent
		view.Sections = []ViewSection{{Name: "symbolication", State: StateNotAvailable, Reason: ReasonArtifactGrantAbsent}}
		return view, read, nil
	}
	if e.frames == nil {
		for i := range view.Frames {
			view.Frames[i].Reason = ReasonSymbolicatorNotBuilt
		}
		view.State, view.Reason = StateNotAvailable, ReasonSymbolicatorNotBuilt
		view.Sections = []ViewSection{{Name: "symbolication", State: StateNotAvailable, Reason: ReasonSymbolicatorNotBuilt}}
		return view, scope, nil
	}
	frames := make([]model.Frame, len(body.Frames))
	for i, f := range body.Frames {
		frames[i] = copyFrame(f)
	}
	out, err := e.frames.ResolveWithOptions(ctx, scope, body.Build, frames, symbolicate.Options{IncludeSources: body.IncludeSources})
	if err != nil {
		return FramesView{}, auth.Scope{}, err
	}
	if len(out) != len(body.Frames) {
		return FramesView{}, auth.Scope{}, model.Fail(model.Corrupt)
	}
	mapped := 0
	for i, r := range out {
		fe := &view.Frames[i]
		fe.Reason = string(r.Reason)
		if r.Reason == symbolicate.Resolved && r.Resolved != nil {
			resolved := *r.Resolved
			hash := r.MapSHA256
			fe.Resolved, fe.MapSHA256 = &resolved, &hash
			mapped++
		}
		switch {
		case !body.IncludeSources:
		case r.SourceContext != nil && fe.Resolved != nil:
			text := *r.SourceContext
			fe.Source = SourceView{State: "present", Context: &text}
		case r.Reason == symbolicate.SourceDenied:
			fe.Source = SourceView{State: "withheld", Reason: ReasonSourcesGrantRequired}
		case fe.Resolved != nil:
			fe.Source = SourceView{State: "absent", Reason: ReasonNoSourceContent}
		}
	}
	switch {
	case mapped == len(out):
		view.State = StateReady
	default:
		view.State, view.Reason = StateIncomplete, "frames_unmapped"
	}
	view.Sections = []ViewSection{{Name: "symbolication", State: StateReady}}
	if mapped < len(out) {
		view.Sections[0].State, view.Sections[0].Reason = StateIncomplete, "frames_unmapped"
	}
	return view, scope, nil
}

// ReleaseBody is the POST /api/v1/evidence/release body.
type ReleaseBody struct {
	Org     model.ID   `json:"org"`
	Project model.ID   `json:"project"`
	Release model.ID   `json:"release"`
	Compare []model.ID `json:"compare,omitempty"`
}

// DebugArtifactView binds a release to exact immutable artifact identities.
type DebugArtifactView struct {
	ArtifactID model.ID   `json:"artifact_id"`
	DebugID    string     `json:"debug_id"`
	SHA256     model.Hash `json:"sha256"`
}

// LabelRevisionView is one display-label revision. A label is operator text and
// never selects an artifact.
type LabelRevisionView struct {
	Revision model.Uint64 `json:"revision"`
	Label    string       `json:"label"`
}

// ReleaseRecordView is the immutable release identity plus its display label.
type ReleaseRecordView struct {
	ID             model.ID            `json:"id"`
	BuildID        model.ID            `json:"build_id"`
	Label          string              `json:"label"`
	Revision       model.Uint64        `json:"revision"`
	BuildTime      model.Int64         `json:"build_time_ns"`
	DebugArtifacts []DebugArtifactView `json:"debug_artifacts"`
	LabelHistory   []LabelRevisionView `json:"label_history"`
}

// ParentView is one declared parent edge; Known is false when the parent is not
// registered, so its own ancestry is unknown, never assumed.
type ParentView struct {
	ID    model.ID `json:"id"`
	Known bool     `json:"known"`
}

// ReleaseComparison is the partial-order relation of the release to another one
// computed from immutable parent edges only. Order is: same | ancestor (the
// viewed release is an ancestor of Release) | descendant | concurrent | unknown.
// There is no lexical or time ordering and unknown is never rounded to a verdict.
type ReleaseComparison struct {
	Release model.ID `json:"release"`
	Order   string   `json:"order"`
}

// ReleaseView answers a release request.
type ReleaseView struct {
	Org         model.ID            `json:"org"`
	Project     model.ID            `json:"project"`
	State       ViewState           `json:"state"`
	Reason      string              `json:"reason,omitempty"`
	Release     *ReleaseRecordView  `json:"release,omitempty"`
	Parents     []ParentView        `json:"parents"`
	Children    []model.ID          `json:"children"`
	Comparisons []ReleaseComparison `json:"comparisons"`
	Sections    []ViewSection       `json:"sections"`
}

func validRelease(body ReleaseBody) error {
	if body.Org == (model.ID{}) || body.Project == (model.ID{}) || body.Release == (model.ID{}) || len(body.Compare) > MaxEvidenceCompare {
		return invalid("evidence_request_invalid")
	}
	for i, id := range body.Compare {
		if id == (model.ID{}) || slices.Contains(body.Compare[:i], id) {
			return invalid("evidence_request_invalid")
		}
	}
	return nil
}

func unavailableReleaseView(body ReleaseBody, reason string) ReleaseView {
	return ReleaseView{Org: body.Org, Project: body.Project, State: StateNotAvailable, Reason: reason, Parents: []ParentView{}, Children: []model.ID{}, Comparisons: []ReleaseComparison{},
		Sections: []ViewSection{{Name: "release", State: StateNotAvailable, Reason: reason}}}
}

// Release reads one release under scope. The scope is the caller's own; the
// registry itself needs organization admin, so a project reader is told so
// explicitly instead of getting an empty release.
func (e *Evidence) Release(ctx context.Context, scope auth.Scope, body ReleaseBody) (ReleaseView, error) {
	if err := validRelease(body); err != nil {
		return ReleaseView{}, err
	}
	if !scope.AllowsProject(body.Project) {
		return ReleaseView{}, model.Fail(model.NotFound)
	}
	if e.releases == nil {
		return unavailableReleaseView(body, ReasonReleasesNotBuilt), nil
	}
	if scope.Permission() != auth.OrgAdmin {
		return unavailableReleaseView(body, ReasonReleaseNeedsAdmin), nil
	}
	rel, err := e.releases.Get(ctx, scope, body.Project, body.Release)
	if err != nil {
		return ReleaseView{}, err
	}
	if rel.ID != body.Release || rel.Org != scope.OrgID() || rel.Project != body.Project {
		return ReleaseView{}, model.Fail(model.NotFound)
	}
	graph, err := e.releases.Graph(ctx, scope, body.Project)
	if err != nil {
		return ReleaseView{}, err
	}
	view := ReleaseView{Org: body.Org, Project: body.Project, State: StateReady, Parents: []ParentView{}, Children: []model.ID{}, Comparisons: []ReleaseComparison{}}
	record := ReleaseRecordView{ID: rel.ID, BuildID: rel.BuildID, Label: rel.DisplayLabel, Revision: model.Uint64(rel.Revision), BuildTime: model.Int64(rel.BuildTime), DebugArtifacts: []DebugArtifactView{}, LabelHistory: []LabelRevisionView{}}
	for _, d := range rel.DebugArtifacts {
		record.DebugArtifacts = append(record.DebugArtifacts, DebugArtifactView{ArtifactID: d.ArtifactID, DebugID: d.DebugID, SHA256: d.SHA256})
	}
	for _, h := range rel.History {
		record.LabelHistory = append(record.LabelHistory, LabelRevisionView{Revision: model.Uint64(h.Revision), Label: h.DisplayLabel})
	}
	view.Release = &record
	unknownParents := false
	for _, p := range rel.Parents {
		_, known := graph[p]
		view.Parents = append(view.Parents, ParentView{ID: p, Known: known})
		unknownParents = unknownParents || !known
	}
	for id, other := range graph {
		if slices.Contains(other.Parents, rel.ID) {
			view.Children = append(view.Children, id)
		}
	}
	slices.SortFunc(view.Children, func(a, b model.ID) int { return slices.Compare(a[:], b[:]) })
	incomplete := unknownParents
	for _, id := range body.Compare {
		order := releases.Relation(graph, rel.ID, id)
		view.Comparisons = append(view.Comparisons, ReleaseComparison{Release: id, Order: string(order)})
		incomplete = incomplete || order == releases.Unknown
	}
	ancestry := ViewSection{Name: "ancestry", State: StateReady}
	if incomplete {
		ancestry = ViewSection{Name: "ancestry", State: StateIncomplete, Reason: "ancestry_unknown"}
		view.State, view.Reason = StateIncomplete, "ancestry_unknown"
	}
	view.Sections = []ViewSection{{Name: "release", State: StateReady}, ancestry,
		{Name: "regression", State: StateNotAvailable, Reason: ReasonRegressionDetail}}
	return view, nil
}

// IssueBody is the POST /api/v1/evidence/issue body.
type IssueBody struct {
	Org     model.ID `json:"org"`
	Project model.ID `json:"project"`
	Issue   model.ID `json:"issue"`
}

// OccurrenceEvidenceView is one stored occurrence evidence record. Ancestry is
// reduced to the closed vocabulary known|unknown: anything the stored value
// does not state exactly is unknown.
type OccurrenceEvidenceView struct {
	OccurrenceID    model.ID    `json:"occurrence_id"`
	RecordID        model.ID    `json:"record_id"`
	GroupingVersion uint16      `json:"grouping_version"`
	Fingerprint     model.Hash  `json:"fingerprint"`
	EventTime       model.Int64 `json:"event_time_ns"`
	ArrivalTime     model.Int64 `json:"arrival_time_ns"`
	BuildID         *model.ID   `json:"build_id,omitempty"`
	ReleaseID       *model.ID   `json:"release_id,omitempty"`
	Ancestry        string      `json:"ancestry"`
	Freshness       string      `json:"freshness"`
	Late            bool        `json:"late"`
}

// GroupingView is the issue's grouping identity and resolution facts.
type GroupingView struct {
	Version            uint16       `json:"grouping_version"`
	Fingerprint        model.Hash   `json:"fingerprint"`
	Workflow           string       `json:"workflow"`
	Revision           model.Uint64 `json:"revision"`
	ResolutionTime     *model.Int64 `json:"resolution_time_ns,omitempty"`
	ResolutionFrontier []model.ID   `json:"resolution_frontier"`
	ObservedReleases   []model.ID   `json:"observed_releases"`
	FixedDescendants   []model.ID   `json:"fixed_descendants"`
	MigrationLinks     []model.ID   `json:"migration_links"`
}

// IssueView answers an issue evidence request.
type IssueView struct {
	Org         model.ID                 `json:"org"`
	Project     model.ID                 `json:"project"`
	Issue       model.ID                 `json:"issue"`
	State       ViewState                `json:"state"`
	Reason      string                   `json:"reason,omitempty"`
	Grouping    *GroupingView            `json:"grouping,omitempty"`
	Occurrences []OccurrenceEvidenceView `json:"occurrences"`
	LateHistory []OccurrenceEvidenceView `json:"late_history"`
	Sections    []ViewSection            `json:"sections"`
}

func unavailableIssueView(body IssueBody, reason string) IssueView {
	return IssueView{Org: body.Org, Project: body.Project, Issue: body.Issue, State: StateNotAvailable, Reason: reason, Occurrences: []OccurrenceEvidenceView{}, LateHistory: []OccurrenceEvidenceView{},
		Sections: []ViewSection{{Name: "evidence", State: StateNotAvailable, Reason: reason}}}
}

func idsOrEmpty(in []model.ID) []model.ID {
	return append([]model.ID{}, in...)
}

func evidenceView(e model.GroupingEvidence, late bool) OccurrenceEvidenceView {
	ancestry := "unknown"
	if e.Ancestry == "known" && e.ReleaseID != nil {
		ancestry = "known"
	}
	return OccurrenceEvidenceView{OccurrenceID: e.OccurrenceID, RecordID: e.RecordID, GroupingVersion: e.GroupingVersion, Fingerprint: e.Fingerprint, EventTime: model.Int64(e.EventTime), ArrivalTime: model.Int64(e.ArrivalTime),
		BuildID: e.BuildID, ReleaseID: e.ReleaseID, Ancestry: ancestry, Freshness: e.Freshness, Late: late}
}

// Issue reads one persisted issue's evidence under scope. It never computes a
// regression: the stored ancestry and the grouping version/hash are shown as
// they are, and an issue the reader cannot see is the one not-found.
func (e *Evidence) Issue(ctx context.Context, scope auth.Scope, body IssueBody) (IssueView, error) {
	if body.Org == (model.ID{}) || body.Project == (model.ID{}) || body.Issue == (model.ID{}) {
		return IssueView{}, invalid("evidence_request_invalid")
	}
	if !scope.AllowsProject(body.Project) {
		return IssueView{}, model.Fail(model.NotFound)
	}
	if e.issues == nil {
		return unavailableIssueView(body, ReasonIssueEvidenceAbsent), nil
	}
	if scope.Permission() != auth.OrgAdmin {
		return unavailableIssueView(body, ReasonIssueNeedsAdmin), nil
	}
	issue, err := e.issues.GroupingIssue(ctx, scope, body.Project, body.Issue)
	if err != nil {
		return IssueView{}, err
	}
	if issue.ID != body.Issue || issue.Org != scope.OrgID() || issue.Project != body.Project {
		return IssueView{}, model.Fail(model.NotFound)
	}
	view := IssueView{Org: body.Org, Project: body.Project, Issue: issue.ID, State: StateIncomplete, Reason: ReasonOccurrenceDetail, Occurrences: []OccurrenceEvidenceView{}, LateHistory: []OccurrenceEvidenceView{}}
	grouping := GroupingView{Version: issue.GroupingVersion, Fingerprint: issue.Fingerprint, Workflow: issue.Workflow, Revision: model.Uint64(issue.Revision), ResolutionFrontier: idsOrEmpty(issue.ResolutionFrontier),
		ObservedReleases: idsOrEmpty(issue.ObservedReleases), FixedDescendants: idsOrEmpty(issue.FixedDescendants), MigrationLinks: idsOrEmpty(issue.MigrationLinks)}
	if issue.ResolutionTime != nil {
		t := model.Int64(*issue.ResolutionTime)
		grouping.ResolutionTime = &t
	}
	view.Grouping = &grouping
	for _, o := range issue.Occurrences {
		view.Occurrences = append(view.Occurrences, evidenceView(o, false))
	}
	for _, o := range issue.LateHistory {
		view.LateHistory = append(view.LateHistory, evidenceView(o, true))
	}
	view.Sections = []ViewSection{{Name: "grouping", State: StateReady}, {Name: "evidence", State: StateReady},
		{Name: "occurrence_detail", State: StateNotAvailable, Reason: ReasonOccurrenceDetail},
		{Name: "regression", State: StateNotAvailable, Reason: ReasonRegressionDetail}}
	return view, nil
}

// RegisterEvidenceRoutes mounts the error-investigation reads. Each route needs
// the CSRF binding of artifactCredential for a session caller and derives its
// scope from the caller's own credential; no body field names a scope.
//
//	POST /api/v1/evidence/frames   FramesBody  -> FramesView
//	POST /api/v1/evidence/release  ReleaseBody -> ReleaseView
//	POST /api/v1/evidence/issue    IssueBody   -> IssueView
func RegisterEvidenceRoutes(mux *http.ServeMux, authority *auth.Service, evidence *Evidence) {
	mux.HandleFunc("POST /api/v1/evidence/frames", func(w http.ResponseWriter, r *http.Request) {
		credential, err := artifactCredential(authority, w, r)
		if err != nil {
			queryReply(w, nil, err)
			return
		}
		var body FramesBody
		if err = decode(w, r, &body); err != nil {
			queryReply(w, nil, err)
			return
		}
		view, scope, err := evidence.Frames(r.Context(), authority, credential, body)
		if err == nil {
			err = authority.Revalidate(r.Context(), scope)
		}
		queryReply(w, view, err)
	})
	mux.HandleFunc("POST /api/v1/evidence/release", func(w http.ResponseWriter, r *http.Request) {
		credential, err := artifactCredential(authority, w, r)
		if err != nil {
			queryReply(w, nil, err)
			return
		}
		var body ReleaseBody
		if err = decode(w, r, &body); err != nil {
			queryReply(w, nil, err)
			return
		}
		scope, err := readScope(r.Context(), authority, credential, body.Org, []model.ID{body.Project})
		if err != nil {
			queryReply(w, nil, err)
			return
		}
		view, err := evidence.Release(r.Context(), scope, body)
		if err == nil {
			err = authority.Revalidate(r.Context(), scope)
		}
		queryReply(w, view, err)
	})
	mux.HandleFunc("POST /api/v1/evidence/issue", func(w http.ResponseWriter, r *http.Request) {
		credential, err := artifactCredential(authority, w, r)
		if err != nil {
			queryReply(w, nil, err)
			return
		}
		var body IssueBody
		if err = decode(w, r, &body); err != nil {
			queryReply(w, nil, err)
			return
		}
		scope, err := readScope(r.Context(), authority, credential, body.Org, []model.ID{body.Project})
		if err != nil {
			queryReply(w, nil, err)
			return
		}
		view, err := evidence.Issue(r.Context(), scope, body)
		if err == nil {
			err = authority.Revalidate(r.Context(), scope)
		}
		queryReply(w, view, err)
	})
}
