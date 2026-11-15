// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"errors"
	"io"
	"math"
	"net/http"
	"slices"
	"unicode"
	"unicode/utf8"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/issues"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/releases"
	"github.com/arynyklas/soundpost/internal/storage"
	"github.com/arynyklas/soundpost/internal/symbolicate"
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
	ReasonSymbolicatorNotBuilt     = "symbolicator_not_wired"
	ReasonArtifactGrantAbsent      = "artifact_read_not_granted"
	ReasonReleasesNotBuilt         = "release_reader_not_wired"
	ReasonReleaseNeedsAdmin        = "release_records_need_org_admin"
	ReasonIssueEvidenceAbsent      = "issue_evidence_view_not_built"
	ReasonIssueNeedsAdmin          = "issue_evidence_needs_org_admin"
	ReasonOccurrenceDetail         = "occurrence_payload_view_not_built"
	ReasonRegressionDetail         = "regression_explanation_view_not_built"
	ReasonEvidenceCompacted        = "evidence_window_compacted"
	ReasonSourcesNotRequested      = "sources_not_requested"
	ReasonSourcesGrantRequired     = "source_grant_required"
	ReasonNoSourceContent          = "no_source_content"
	ReasonFrameNotMapped           = "frame_not_mapped"
	ReasonOccurrenceNeedsTelemetry = "occurrence_needs_telemetry_read"
	ReasonOccurrenceNotStored      = "occurrence_not_stored"
	ReasonOccurrenceReadPartial    = "occurrence_read_partial"
	ReasonNoRegression             = "no_regression_evaluated"
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

// ReleaseRegistrar is the write side of the release registry; *releases.Service
// implements it and needs an organization-admin scope. expected is the control
// revision the caller read, exactly as for an administration command.
type ReleaseRegistrar interface {
	Register(ctx context.Context, scope auth.Scope, release model.Release, expected model.Revision, commandID model.ID) (model.Release, error)
}

// RegisterReleaseBody is the POST /api/v1/releases/register body. A new release
// has entity revision 0; renaming its display label supplies the current entity
// revision in Release.Revision and the current control revision in ExpectedRevision.
type RegisterReleaseBody struct {
	Org              model.ID      `json:"org"`
	Project          model.ID      `json:"project"`
	CommandID        model.ID      `json:"command_id"`
	ExpectedRevision model.Uint64  `json:"expected_revision"`
	Release          model.Release `json:"release"`
}

// RegisterReleaseView names the committed release and its entity revision.
type RegisterReleaseView struct {
	ID       model.ID       `json:"id"`
	Revision model.Revision `json:"revision"`
}

// IssueEvidenceReader reads one persisted issue with its grouping version,
// fingerprint and evidence; *releases.Service implements it (an org-admin
// read of the committed grouping issues). A nil reader is an explicit
// not_available state.
type IssueEvidenceReader interface {
	GroupingIssue(ctx context.Context, scope auth.Scope, project, id model.ID) (model.GroupingIssue, error)
}

// ErrorOccurrenceReader reads the stored error record behind one piece of issue
// evidence. The scope is a telemetry-read scope for exactly one project (the
// evidence itself is an organization-admin read; the telemetry is not part of
// it). found is false when no record with that occurrence ID is stored any more
// (expired or erased); partial says some shard did not answer, so a missing
// record is not proof of absence. NewStorageErrorSource is the committed
// implementation. A nil reader is an explicit not_available state.
type ErrorOccurrenceReader interface {
	ErrorOccurrence(ctx context.Context, scope auth.Scope, project, record, occurrence model.ID, at model.UnixNano) (occ model.ErrorOccurrence, found, partial bool, err error)
}

// Evidence is the handler set behind /api/v1/evidence/*. Any seam may be nil.
type Evidence struct {
	frames      FrameResolver
	releases    ReleaseReader
	issues      IssueEvidenceReader
	occurrences ErrorOccurrenceReader
	regressions RegressionReader
}

// EvidenceOption binds one optional seam of NewEvidence.
type EvidenceOption func(*Evidence)

// WithErrorOccurrences binds the stored error reader behind /api/v1/evidence/occurrence.
func WithErrorOccurrences(r ErrorOccurrenceReader) EvidenceOption {
	return func(e *Evidence) { e.occurrences = r }
}

// RegressionReader reads the regression evaluations the issue lifecycle stored;
// *issues.Service implements it under the caller's own scope. ExplainAll answers
// every issue of one project (the release view lists the evaluations whose
// occurrence ran in it). A nil reader is an explicit not_available section.
type RegressionReader interface {
	Explain(ctx context.Context, scope auth.Scope, project, issue model.ID) ([]issues.Explanation, error)
	ExplainAll(ctx context.Context, scope auth.Scope, project model.ID) (map[model.ID][]issues.Explanation, error)
}

// WithRegressionExplanations binds the stored regression reader of the issue and release views.
func WithRegressionExplanations(r RegressionReader) EvidenceOption {
	return func(e *Evidence) { e.regressions = r }
}

func sortedIssueIDs(all map[model.ID][]issues.Explanation) []model.ID {
	ids := make([]model.ID, 0, len(all))
	for id := range all {
		ids = append(ids, id)
	}
	slices.SortFunc(ids, func(a, b model.ID) int { return slices.Compare(a[:], b[:]) })
	return ids
}

// NewEvidence binds the three required-or-nil seams and any options.
func NewEvidence(frames FrameResolver, releases ReleaseReader, issues IssueEvidenceReader, options ...EvidenceOption) *Evidence {
	e := &Evidence{frames: frames, releases: releases, issues: issues}
	for _, o := range options {
		o(e)
	}
	return e
}

// With returns a copy of the handler set with options applied; the receiver is unchanged.
func (e *Evidence) With(options ...EvidenceOption) *Evidence {
	c := *e
	for _, o := range options {
		o(&c)
	}
	return &c
}

// WithFrames returns a copy with another frame resolver: the symbolicator is
// configured after the node is open and everything else the node bound stays.
func (e *Evidence) WithFrames(frames FrameResolver) *Evidence {
	c := *e
	c.frames = frames
	return &c
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
	mapped, sandboxDown := 0, 0
	for i, r := range out {
		fe := &view.Frames[i]
		fe.Reason = string(r.Reason)
		if r.Reason == symbolicate.SandboxUnavailable {
			sandboxDown++
		}
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
	case sandboxDown == len(out) && len(out) > 0:
		// The served process could not start its sandbox for any frame: the section is
		// not available, not a partial mapping; the original frames are kept.
		view.State, view.Reason = StateNotAvailable, string(symbolicate.SandboxUnavailable)
		view.Sections = []ViewSection{{Name: "symbolication", State: StateNotAvailable, Reason: string(symbolicate.SandboxUnavailable)}}
		return view, scope, nil
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
	Org         model.ID                `json:"org"`
	Project     model.ID                `json:"project"`
	State       ViewState               `json:"state"`
	Reason      string                  `json:"reason,omitempty"`
	Release     *ReleaseRecordView      `json:"release,omitempty"`
	Parents     []ParentView            `json:"parents"`
	Children    []model.ID              `json:"children"`
	Comparisons []ReleaseComparison     `json:"comparisons"`
	Regressions []ReleaseRegressionView `json:"regressions"`
	Sections    []ViewSection           `json:"sections"`
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
	return ReleaseView{Org: body.Org, Project: body.Project, State: StateNotAvailable, Reason: reason, Parents: []ParentView{}, Children: []model.ID{}, Comparisons: []ReleaseComparison{}, Regressions: []ReleaseRegressionView{},
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
	view := ReleaseView{Org: body.Org, Project: body.Project, State: StateReady, Parents: []ParentView{}, Children: []model.ID{}, Comparisons: []ReleaseComparison{}, Regressions: []ReleaseRegressionView{}}
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
	regression := ViewSection{Name: "regression", State: StateNotAvailable, Reason: ReasonRegressionDetail}
	if e.regressions != nil {
		all, err := e.regressions.ExplainAll(ctx, scope, body.Project)
		if err != nil {
			return ReleaseView{}, err
		}
		for _, issue := range sortedIssueIDs(all) {
			for _, x := range all[issue] {
				if x.EvidenceRelease == rel.ID {
					view.Regressions = append(view.Regressions, ReleaseRegressionView{Issue: issue, RegressionExplanationView: explanationView(x)})
				}
			}
		}
		regression = ViewSection{Name: "regression", State: StateReady}
		if len(view.Regressions) == 0 {
			regression = ViewSection{Name: "regression", State: StateEmpty, Reason: ReasonNoRegression}
		}
	}
	view.Sections = []ViewSection{{Name: "release", State: StateReady}, ancestry, regression}
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

// GroupingView is the issue's grouping identity and resolution facts. The
// occurrence and late-history lists are the newest evidence window; the oldest
// evidence of a hot issue is folded into counts, so Compacted* say how many
// occurrences (and late-history items) the lists no longer carry. The full
// count is len(list) + Compacted*.
type GroupingView struct {
	Version              uint16       `json:"grouping_version"`
	Fingerprint          model.Hash   `json:"fingerprint"`
	Workflow             string       `json:"workflow"`
	Revision             model.Uint64 `json:"revision"`
	ResolutionTime       *model.Int64 `json:"resolution_time_ns,omitempty"`
	ResolutionFrontier   []model.ID   `json:"resolution_frontier"`
	ObservedReleases     []model.ID   `json:"observed_releases"`
	FixedDescendants     []model.ID   `json:"fixed_descendants"`
	MigrationLinks       []model.ID   `json:"migration_links"`
	CompactedOccurrences model.Uint64 `json:"compacted_occurrences"`
	CompactedLate        model.Uint64 `json:"compacted_late_history"`
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
	Regression  *RegressionView          `json:"regression,omitempty"`
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

// Issue reads one persisted issue's evidence under scope with no telemetry read
// (the stored occurrence detail is then reported as needing that grant).
func (e *Evidence) Issue(ctx context.Context, scope auth.Scope, body IssueBody) (IssueView, error) {
	return e.IssueWithDetail(ctx, scope, nil, body)
}

// IssueWithDetail reads one persisted issue's evidence under the
// organization-admin scope. read, when not nil, is the same caller's
// telemetry-read scope for the project: only then is the stored occurrence
// detail section ready. It never computes a regression: the stored ancestry
// and the grouping version/hash are shown as they are, and an issue the reader
// cannot see is the one not-found.
func (e *Evidence) IssueWithDetail(ctx context.Context, scope auth.Scope, read *auth.Scope, body IssueBody) (IssueView, error) {
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
	view := IssueView{Org: body.Org, Project: body.Project, Issue: issue.ID, Occurrences: []OccurrenceEvidenceView{}, LateHistory: []OccurrenceEvidenceView{}}
	grouping := GroupingView{Version: issue.GroupingVersion, Fingerprint: issue.Fingerprint, Workflow: issue.Workflow, Revision: model.Uint64(issue.Revision), ResolutionFrontier: idsOrEmpty(issue.ResolutionFrontier),
		ObservedReleases: idsOrEmpty(issue.ObservedReleases), FixedDescendants: idsOrEmpty(issue.FixedDescendants), MigrationLinks: idsOrEmpty(issue.MigrationLinks)}
	if issue.ResolutionTime != nil {
		t := model.Int64(*issue.ResolutionTime)
		grouping.ResolutionTime = &t
	}
	if c := issue.Compacted; c != nil {
		grouping.CompactedOccurrences = c.Count
	}
	if c := issue.LateCompacted; c != nil {
		grouping.CompactedLate = c.Count
	}
	view.Grouping = &grouping
	for _, o := range issue.Occurrences {
		view.Occurrences = append(view.Occurrences, evidenceView(o, false))
	}
	for _, o := range issue.LateHistory {
		view.LateHistory = append(view.LateHistory, evidenceView(o, true))
	}
	evidence := ViewSection{Name: "evidence", State: StateReady}
	if grouping.CompactedOccurrences+grouping.CompactedLate > 0 {
		evidence = ViewSection{Name: "evidence", State: StateIncomplete, Reason: ReasonEvidenceCompacted}
	}
	detail := ViewSection{Name: "occurrence_detail", State: StateNotAvailable, Reason: ReasonOccurrenceDetail}
	switch {
	case e.occurrences == nil:
	case read == nil:
		detail.Reason = ReasonOccurrenceNeedsTelemetry
	default:
		detail = ViewSection{Name: "occurrence_detail", State: StateReady}
	}
	regression, err := e.regressionSection(ctx, scope, body.Project, body.Issue, &view)
	if err != nil {
		return IssueView{}, err
	}
	view.Sections = []ViewSection{{Name: "grouping", State: StateReady}, evidence, detail, regression}
	view.State = StateReady
	for _, s := range view.Sections {
		if s.State != StateReady && s.State != StateEmpty {
			view.State, view.Reason = StateIncomplete, s.Reason
			break
		}
	}
	return view, nil
}

// RegressionExplanationView is one stored regression evaluation of an issue: the
// occurrence evaluated, the release it ran in, the decision with the reason the
// evaluator stored, the fix frontier it was compared with, the recorded policy
// (Threshold qualifying occurrences within Window nanoseconds, 0 = unbounded) and
// whether the evaluation reopened the issue. It is exactly what the lifecycle
// recorded when the evidence arrived: nothing here is computed from timestamps or
// release labels, and an occurrence whose ancestry is unknown says so.
type RegressionExplanationView struct {
	Occurrence      model.ID    `json:"occurrence"`
	EvidenceRelease *model.ID   `json:"evidence_release,omitempty"`
	EventTime       model.Int64 `json:"event_time_ns"`
	ResolutionTime  model.Int64 `json:"resolution_time_ns"`
	Eligible        bool        `json:"eligible"`
	AncestryKnown   bool        `json:"ancestry_known"`
	Reason          string      `json:"reason"`
	Frontier        []model.ID  `json:"frontier"`
	Threshold       uint32      `json:"threshold"`
	Window          model.Int64 `json:"window_ns"`
	Qualifying      uint32      `json:"qualifying"`
	Reopened        bool        `json:"reopened"`
}

// RegressionView lists an issue's stored regression evaluations, oldest first.
type RegressionView struct {
	Explanations []RegressionExplanationView `json:"explanations"`
}

// ReleaseRegressionView is one stored regression evaluation whose occurrence ran
// in the viewed release, with the issue it belongs to.
type ReleaseRegressionView struct {
	Issue model.ID `json:"issue"`
	RegressionExplanationView
}

func explanationView(x issues.Explanation) RegressionExplanationView {
	v := RegressionExplanationView{Occurrence: x.OccurrenceID, EventTime: model.Int64(x.EventTime), ResolutionTime: model.Int64(x.ResolutionTime), Eligible: x.Decision.Eligible, AncestryKnown: x.Decision.AncestryKnown,
		Reason: x.Decision.Reason, Frontier: idsOrEmpty(x.Decision.Frontier), Threshold: x.Threshold, Window: model.Int64(x.Window), Reopened: x.Reopened}
	if x.Qualifying > 0 {
		v.Qualifying = uint32(x.Qualifying)
	}
	if x.EvidenceRelease != (model.ID{}) {
		r := x.EvidenceRelease
		v.EvidenceRelease = &r
	}
	return v
}

// regressionSection reads the issue's stored explanations and sets view.Regression.
// An unwired reader is an explicit not_available section; an issue with no stored
// evaluation is an empty one, never a claim that a regression did or did not happen.
func (e *Evidence) regressionSection(ctx context.Context, scope auth.Scope, project, issue model.ID, view *IssueView) (ViewSection, error) {
	if e.regressions == nil {
		return ViewSection{Name: "regression", State: StateNotAvailable, Reason: ReasonRegressionDetail}, nil
	}
	explained, err := e.regressions.Explain(ctx, scope, project, issue)
	if err != nil && !faultIs(err, model.NotFound) {
		return ViewSection{}, err
	}
	view.Regression = &RegressionView{Explanations: make([]RegressionExplanationView, 0, len(explained))}
	for _, x := range explained {
		view.Regression.Explanations = append(view.Regression.Explanations, explanationView(x))
	}
	if len(explained) == 0 {
		return ViewSection{Name: "regression", State: StateEmpty, Reason: ReasonNoRegression}, nil
	}
	return ViewSection{Name: "regression", State: StateReady}, nil
}

// ErrorOccurrenceBody is the POST /api/v1/evidence/occurrence body. The occurrence
// must be one the named issue's evidence lists.
type ErrorOccurrenceBody struct {
	Org        model.ID `json:"org"`
	Project    model.ID `json:"project"`
	Issue      model.ID `json:"issue"`
	Occurrence model.ID `json:"occurrence"`
}

// ErrorOccurrenceDetail is what the stored error record says about one occurrence:
// the exception class, the mechanism, whether it was handled and whether it was
// fatal, the code, the sanitized frames and the exception chain (cause, context
// and group edges, with the reasons a part of the chain was not captured). It
// holds no message text or values: the record carries none. The links name
// the build, the release, the trace and the span, the replay and the profile
// the record itself carries; none is inferred.
type ErrorOccurrenceDetail struct {
	Class     string                `json:"exception_class"`
	Mechanism string                `json:"mechanism"`
	Handled   bool                  `json:"handled"`
	Fatal     bool                  `json:"fatal"`
	Code      *string               `json:"code"`
	Template  *string               `json:"template_id,omitempty"`
	Build     model.ID              `json:"build_id"`
	Release   *model.ID             `json:"release_id,omitempty"`
	Trace     *model.ID             `json:"trace_id,omitempty"`
	Span      *model.SpanID         `json:"span_id,omitempty"`
	Replay    *model.ID             `json:"replay_id,omitempty"`
	Profile   *model.ID             `json:"profile_id,omitempty"`
	Run       *model.ID             `json:"run_id,omitempty"`
	Frames    []model.Frame         `json:"frames"`
	Chain     *model.ExceptionGraph `json:"exception_graph,omitempty"`
}

// ErrorOccurrenceView answers an occurrence request. Detail is present only when
// State is ready.
type ErrorOccurrenceView struct {
	Org        model.ID               `json:"org"`
	Project    model.ID               `json:"project"`
	Issue      model.ID               `json:"issue"`
	Occurrence model.ID               `json:"occurrence"`
	State      ViewState              `json:"state"`
	Reason     string                 `json:"reason,omitempty"`
	Detail     *ErrorOccurrenceDetail `json:"detail,omitempty"`
	Sections   []ViewSection          `json:"sections"`
}

func unavailableOccurrenceView(body ErrorOccurrenceBody, state ViewState, reason string) ErrorOccurrenceView {
	return ErrorOccurrenceView{Org: body.Org, Project: body.Project, Issue: body.Issue, Occurrence: body.Occurrence, State: state, Reason: reason,
		Sections: []ViewSection{{Name: "occurrence_detail", State: state, Reason: reason}}}
}

func copyFrames(in []model.Frame) []model.Frame {
	out := make([]model.Frame, len(in))
	for i, f := range in {
		out[i] = copyFrame(f)
	}
	return out
}

func copyChain(g *model.ExceptionGraph) *model.ExceptionGraph {
	if g == nil {
		return nil
	}
	out := &model.ExceptionGraph{Nodes: make([]model.ExceptionNode, len(g.Nodes)), Edges: make([]model.ExceptionEdge, len(g.Edges)), Reasons: append([]string{}, g.Reasons...)}
	for i, n := range g.Nodes {
		n.Frames = copyFrames(n.Frames)
		out.Nodes[i] = n
	}
	for i, edge := range g.Edges {
		if edge.Ordinal != nil {
			o := *edge.Ordinal
			edge.Ordinal = &o
		}
		out.Edges[i] = edge
	}
	return out
}

func copyID(p *model.ID) *model.ID {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

func copyText(p *string) *string {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

// cloneError copies a stored error record out of a borrowed storage page.
func cloneError(o model.ErrorOccurrence) model.ErrorOccurrence {
	o.Frames = copyFrames(o.Frames)
	o.Graph = copyChain(o.Graph)
	o.Template, o.Code = copyText(o.Template), copyText(o.Code)
	o.Release, o.Trace, o.Replay, o.Profile, o.Run = copyID(o.Release), copyID(o.Trace), copyID(o.Replay), copyID(o.Profile), copyID(o.Run)
	if o.Span != nil {
		s := *o.Span
		o.Span = &s
	}
	return o
}

// Occurrence reads the stored error record behind one occurrence of an issue.
// admin is the caller's organization-admin scope (the issue evidence is an
// admin read); read is the same caller's telemetry-read scope, or nil when she
// holds none, and the record is read under it alone. The occurrence must be
// listed by the issue's own evidence: another record is never reachable through
// this route by guessing an ID.
func (e *Evidence) Occurrence(ctx context.Context, admin auth.Scope, read *auth.Scope, body ErrorOccurrenceBody) (ErrorOccurrenceView, error) {
	if body.Org == (model.ID{}) || body.Project == (model.ID{}) || body.Issue == (model.ID{}) || body.Occurrence == (model.ID{}) {
		return ErrorOccurrenceView{}, invalid("evidence_request_invalid")
	}
	if !admin.AllowsProject(body.Project) {
		return ErrorOccurrenceView{}, model.Fail(model.NotFound)
	}
	if e.issues == nil {
		return unavailableOccurrenceView(body, StateNotAvailable, ReasonIssueEvidenceAbsent), nil
	}
	if admin.Permission() != auth.OrgAdmin {
		return unavailableOccurrenceView(body, StateNotAvailable, ReasonIssueNeedsAdmin), nil
	}
	issue, err := e.issues.GroupingIssue(ctx, admin, body.Project, body.Issue)
	if err != nil {
		return ErrorOccurrenceView{}, err
	}
	if issue.ID != body.Issue || issue.Org != admin.OrgID() || issue.Project != body.Project {
		return ErrorOccurrenceView{}, model.Fail(model.NotFound)
	}
	var evidence *model.GroupingEvidence
	for _, list := range [][]model.GroupingEvidence{issue.Occurrences, issue.LateHistory} {
		for i := range list {
			if list[i].OccurrenceID == body.Occurrence {
				evidence = &list[i]
				break
			}
		}
	}
	if evidence == nil {
		// An occurrence folded into the compaction is still evidence control accounts for
		// (its ID is in the retained tail), but its record reference is gone: that is an
		// explicit incomplete state, not the not-found a guessed ID gets.
		for _, c := range []*model.GroupingCompaction{issue.Compacted, issue.LateCompacted} {
			if c != nil && slices.Contains(c.Recent, body.Occurrence) {
				return unavailableOccurrenceView(body, StateIncomplete, ReasonEvidenceCompacted), nil
			}
		}
		return ErrorOccurrenceView{}, model.Fail(model.NotFound)
	}
	if e.occurrences == nil {
		return unavailableOccurrenceView(body, StateNotAvailable, ReasonOccurrenceDetail), nil
	}
	if read == nil {
		return unavailableOccurrenceView(body, StateNotAvailable, ReasonOccurrenceNeedsTelemetry), nil
	}
	occ, found, partial, err := e.occurrences.ErrorOccurrence(ctx, *read, body.Project, evidence.RecordID, evidence.OccurrenceID, evidence.EventTime)
	if err != nil {
		return ErrorOccurrenceView{}, err
	}
	if !found {
		if partial {
			return unavailableOccurrenceView(body, StateIncomplete, ReasonOccurrenceReadPartial), nil
		}
		return unavailableOccurrenceView(body, StateNotAvailable, ReasonOccurrenceNotStored), nil
	}
	if occ.Occurrence != evidence.OccurrenceID {
		return ErrorOccurrenceView{}, model.Fail(model.Corrupt)
	}
	detail := ErrorOccurrenceDetail{Class: occ.Class, Mechanism: occ.Mechanism, Handled: occ.Handled, Fatal: occ.Fatal, Code: occ.Code, Template: occ.Template, Build: occ.Build, Release: occ.Release, Trace: occ.Trace, Span: occ.Span,
		Replay: occ.Replay, Profile: occ.Profile, Run: occ.Run, Frames: occ.Frames, Chain: occ.Graph}
	if detail.Frames == nil {
		detail.Frames = []model.Frame{}
	}
	if g := detail.Chain; g != nil {
		// The wire form has no nulls: an absent list is an empty one.
		if g.Nodes == nil {
			g.Nodes = []model.ExceptionNode{}
		}
		for i := range g.Nodes {
			if g.Nodes[i].Frames == nil {
				g.Nodes[i].Frames = []model.Frame{}
			}
		}
		if g.Edges == nil {
			g.Edges = []model.ExceptionEdge{}
		}
		if g.Reasons == nil {
			g.Reasons = []string{}
		}
	}
	return ErrorOccurrenceView{Org: body.Org, Project: body.Project, Issue: body.Issue, Occurrence: body.Occurrence, State: StateReady, Detail: &detail,
		Sections: []ViewSection{{Name: "occurrence_detail", State: StateReady}}}, nil
}

// ErrorScanner is the committed storage read seam (*storage.Engine implements it).
type ErrorScanner interface {
	Scan(ctx context.Context, scope auth.Scope, req storage.ScanRequest) (storage.RowIterator, error)
}

type storageErrors struct{ scanner ErrorScanner }

// NewStorageErrorSource reads one stored error record through the committed
// storage scan: signal error, one project, an occurrence_id equality selector
// and the one-nanosecond window of the evidence's own event time.
func NewStorageErrorSource(scanner ErrorScanner) ErrorOccurrenceReader { return storageErrors{scanner} }

func (s storageErrors) ErrorOccurrence(ctx context.Context, scope auth.Scope, project, record, occurrence model.ID, at model.UnixNano) (model.ErrorOccurrence, bool, bool, error) {
	if s.scanner == nil || at < 0 || at == math.MaxInt64 {
		return model.ErrorOccurrence{}, false, false, model.Fail(model.Unavailable)
	}
	rows, err := s.scanner.Scan(ctx, scope, storage.ScanRequest{
		Projects: []model.ID{project}, Signal: model.ErrorKind, Start: at, End: at + 1,
		Selectors:  []storage.Matcher{{Target: storage.MatchField, Name: "occurrence_id", Op: storage.MatchEqual, Literal: storage.Literal{Kind: storage.LiteralString, String: occurrence.String()}}},
		Projection: []storage.Field{storage.FieldID, storage.FieldTime, storage.FieldError},
		Fence:      storage.ReadFence{AllowPartial: true},
	})
	if err != nil {
		return model.ErrorOccurrence{}, false, false, err
	}
	if rows == nil {
		return model.ErrorOccurrence{}, false, false, model.Fail(model.Corrupt)
	}
	defer rows.Close()
	partial := false
	for {
		page, err := rows.Next(ctx)
		if errors.Is(err, io.EOF) {
			return model.ErrorOccurrence{}, false, partial, nil
		}
		if err != nil {
			return model.ErrorOccurrence{}, false, false, err
		}
		partial = partial || page.Partial
		if len(page.Values) != page.Len() || len(page.IDs) != page.Len() {
			return model.ErrorOccurrence{}, false, false, model.Fail(model.Corrupt)
		}
		for i, v := range page.Values {
			if v.Error == nil || v.Error.Occurrence != occurrence || page.IDs[i] != record {
				continue
			}
			return cloneError(*v.Error), true, partial, nil
		}
	}
}

// evidenceScope is the caller's scope for the organization-admin evidence reads:
// the administrator's own scope when she is one, and otherwise exactly what the
// other reads would give her (a project reader or an incident writer), so that
// she is told the evidence needs an administrator instead of being refused. An
// administrator who also holds telemetry.read is therefore still the
// administrator here.
func evidenceScope(ctx context.Context, authority *auth.Service, credential auth.Credential, org model.ID, projects []model.ID) (auth.Scope, error) {
	if org == (model.ID{}) || len(projects) == 0 {
		return auth.Scope{}, model.Fail(model.Invalid)
	}
	scope, err := authority.Authorize(ctx, credential, org, projects, auth.OrgAdmin)
	if err == nil || !faultIs(err, model.NotFound) {
		return scope, err
	}
	return readScope(ctx, authority, credential, org, projects)
}

// detailScope is the same caller's telemetry-read scope for the project, or nil
// when she is not an administrator or holds no telemetry.read grant there. The
// stored error records are telemetry: administration alone never reads them.
func detailScope(ctx context.Context, authority *auth.Service, credential auth.Credential, admin auth.Scope, org, project model.ID) (*auth.Scope, error) {
	if admin.Permission() != auth.OrgAdmin {
		return nil, nil
	}
	read, err := authority.Authorize(ctx, credential, org, []model.ID{project}, auth.Read)
	if err != nil {
		if faultIs(err, model.NotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &read, nil
}

func revalidateAll(ctx context.Context, authority *auth.Service, scope auth.Scope, read *auth.Scope) error {
	if err := authority.Revalidate(ctx, scope); err != nil {
		return err
	}
	if read != nil {
		return authority.Revalidate(ctx, *read)
	}
	return nil
}

// RegisterEvidenceRoutes mounts the error-investigation reads. Each route needs
// the CSRF binding of artifactCredential for a session caller and derives its
// scope from the caller's own credential; no body field names a scope.
//
//	POST /api/v1/evidence/frames   FramesBody  -> FramesView
//	POST /api/v1/evidence/release  ReleaseBody -> ReleaseView
//	POST /api/v1/evidence/issue    IssueBody   -> IssueView
//	POST /api/v1/evidence/occurrence ErrorOccurrenceBody -> ErrorOccurrenceView
//	POST /api/v1/releases/register RegisterReleaseBody -> RegisterReleaseView (only when the release registry is a ReleaseRegistrar)
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
		scope, err := evidenceScope(r.Context(), authority, credential, body.Org, []model.ID{body.Project})
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
		scope, err := evidenceScope(r.Context(), authority, credential, body.Org, []model.ID{body.Project})
		if err != nil {
			queryReply(w, nil, err)
			return
		}
		read, err := detailScope(r.Context(), authority, credential, scope, body.Org, body.Project)
		if err != nil {
			queryReply(w, nil, err)
			return
		}
		view, err := evidence.IssueWithDetail(r.Context(), scope, read, body)
		if err == nil {
			err = revalidateAll(r.Context(), authority, scope, read)
		}
		queryReply(w, view, err)
	})
	mux.HandleFunc("POST /api/v1/evidence/occurrence", func(w http.ResponseWriter, r *http.Request) {
		credential, err := artifactCredential(authority, w, r)
		if err != nil {
			queryReply(w, nil, err)
			return
		}
		var body ErrorOccurrenceBody
		if err = decode(w, r, &body); err != nil {
			queryReply(w, nil, err)
			return
		}
		scope, err := evidenceScope(r.Context(), authority, credential, body.Org, []model.ID{body.Project})
		if err != nil {
			queryReply(w, nil, err)
			return
		}
		read, err := detailScope(r.Context(), authority, credential, scope, body.Org, body.Project)
		if err != nil {
			queryReply(w, nil, err)
			return
		}
		view, err := evidence.Occurrence(r.Context(), scope, read, body)
		if err == nil {
			err = revalidateAll(r.Context(), authority, scope, read)
		}
		queryReply(w, view, err)
	})
	if registry, ok := evidence.releases.(ReleaseRegistrar); ok {
		mux.HandleFunc("POST /api/v1/releases/register", func(w http.ResponseWriter, r *http.Request) {
			credential, err := artifactCredential(authority, w, r)
			if err != nil {
				queryReply(w, nil, err)
				return
			}
			var body RegisterReleaseBody
			if err = decode(w, r, &body); err != nil {
				queryReply(w, nil, err)
				return
			}
			if body.Org == (model.ID{}) || body.Project == (model.ID{}) || body.CommandID == (model.ID{}) || body.Release.Org != body.Org || body.Release.Project != body.Project {
				queryReply(w, nil, invalid("release_ids_required"))
				return
			}
			scope, err := authority.Authorize(r.Context(), credential, body.Org, []model.ID{body.Project}, auth.OrgAdmin)
			if err != nil {
				queryReply(w, nil, err)
				return
			}
			registered, err := registry.Register(r.Context(), scope, body.Release, model.Revision(body.ExpectedRevision), body.CommandID)
			if err == nil {
				err = authority.Revalidate(r.Context(), scope)
			}
			queryReply(w, RegisterReleaseView{ID: registered.ID, Revision: registered.Revision}, err)
		})
	}
}
