// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"bytes"
	"context"
	"math"
	"net/http"
	"slices"
	"strings"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/issues"
	"github.com/arynyklas/soundpost/internal/model"
)

// The release list of the console (docs/operations/console-api.md, section 5). It lists the releases a
// project reader may see: the registry's release records (never the debug artifacts), the deploy
// markers somebody recorded and three counts derived from the issue evidence the caller may read.

// Closed reasons of the release list.
const (
	ReasonReleaseScanCapped    = "release_scan_capped"
	ReasonIssueCountsCompacted = "issue_evidence_compacted"
	ReasonIssueCountsAbsent    = "issue_counts_not_available"
	ReasonNoDeployMarkers      = "no_deploy_markers"
	releaseListOp              = "releases"
	// MaxReleaseListScan bounds the release records one project contributes to a list.
	MaxReleaseListScan = 20000
)

// Counts states of one release item.
const (
	CountsReady        = "ready"
	CountsIncomplete   = "incomplete"
	CountsNotAvailable = "not_available"
)

// ReleaseListProject is what the release list reads of one project under the caller's own scope. The
// source never returns a record the scope may not read.
type ReleaseListProject struct {
	// Releases are the registry's records without their debug artifacts or label history.
	Releases []model.Release
	// Capped says the registry holds more releases than MaxReleaseListScan.
	Capped bool
	// IssuesKnown is false when the issue evidence or the regression evaluations could not be read: the
	// counts are then unknown, not zero.
	IssuesKnown  bool
	Issues       []model.GroupingIssue
	Explanations map[model.ID][]issues.Explanation
}

// ReleaseListSource reads the releases and issue evidence of one project under scope.
type ReleaseListSource interface {
	ReleaseList(ctx context.Context, scope auth.Scope, project model.ID) (ReleaseListProject, error)
}

// ReleaseListBody is the POST /api/v1/releases/list body.
type ReleaseListBody struct {
	ListRequest
	Environment    model.ID     `json:"environment"`
	DeployedAfter  *model.Int64 `json:"deployed_after"`
	HasRegressions *bool        `json:"has_regressions"`
}

// ReleaseDeployView is one deploy of a release: the last time it was recorded for the environment.
type ReleaseDeployView struct {
	Environment model.ID    `json:"environment"`
	DeployedAt  model.Int64 `json:"deployed_at"`
}

// ReleaseListItem is one release. The counts are null with counts_state "not_available" when the
// issue evidence could not be read; counts_state "incomplete" says folded (compacted) evidence is
// involved, so a count may be too low.
type ReleaseListItem struct {
	ProjectID       model.ID            `json:"project_id"`
	ReleaseID       model.ID            `json:"release_id"`
	BuildID         model.ID            `json:"build_id"`
	Label           string              `json:"label"`
	BuildTime       model.Int64         `json:"build_time"`
	Parents         []model.ID          `json:"parents"`
	Deploys         []ReleaseDeployView `json:"deploys"`
	DeployState     string              `json:"deploy_state"`
	NewIssues       *int                `json:"new_issues"`
	RegressedIssues *int                `json:"regressed_issues"`
	ResolvedIssues  *int                `json:"resolved_issues"`
	CountsState     string              `json:"counts_state"`
}

// releaseTally is the issue counts of one release.
type releaseTally struct {
	newIssues, regressed, resolved int
	incomplete                     bool
}

// firstEvidenceRelease is the release of the earliest evidence of the issue, when that evidence names
// one. Folded evidence keeps the first event time per release, so the answer is exact after compaction;
// when the earliest evidence names no release, there is none (never the next release that does).
func firstEvidenceRelease(gi model.GroupingIssue) (model.ID, bool) {
	var earliest, relAt model.UnixNano
	var rel model.ID
	have, haveRel := false, false
	note := func(at model.UnixNano) {
		if !have || at < earliest {
			earliest, have = at, true
		}
	}
	noteRel := func(id model.ID, at model.UnixNano) {
		if id == (model.ID{}) {
			return
		}
		if !haveRel || at < relAt || at == relAt && bytes.Compare(id[:], rel[:]) < 0 {
			rel, relAt, haveRel = id, at, true
		}
	}
	for _, ledger := range [][]model.GroupingEvidence{gi.Occurrences, gi.LateHistory} {
		for _, ev := range ledger {
			note(ev.EventTime)
			if ev.ReleaseID != nil {
				noteRel(*ev.ReleaseID, ev.EventTime)
			}
		}
	}
	for _, c := range []*model.GroupingCompaction{gi.Compacted, gi.LateCompacted} {
		if c == nil || c.Count == 0 {
			continue
		}
		note(c.FirstEvent)
		for _, r := range c.Releases {
			noteRel(r.Release, r.FirstEvent)
		}
	}
	if !have || !haveRel || relAt != earliest {
		return model.ID{}, false
	}
	return rel, true
}

// tallyReleases derives the three counts of every release the issues name. new: the issue's first
// evidence is in the release. regressed: a stored regression evaluation that qualified (eligible or
// reopened) ran on evidence of the release. resolved: a resolved issue lists the release among its
// fixed descendants or its resolution frontier. Each issue counts at most once per release and kind.
func tallyReleases(p ReleaseListProject) map[model.ID]*releaseTally {
	out := map[model.ID]*releaseTally{}
	at := func(id model.ID) *releaseTally {
		t := out[id]
		if t == nil {
			t = &releaseTally{}
			out[id] = t
		}
		return t
	}
	for _, gi := range p.Issues {
		if first, ok := firstEvidenceRelease(gi); ok {
			at(first).newIssues++
		}
		regressed := map[model.ID]bool{}
		for _, x := range p.Explanations[gi.ID] {
			if x.EvidenceRelease != (model.ID{}) && (x.Decision.Eligible || x.Reopened) && !regressed[x.EvidenceRelease] {
				regressed[x.EvidenceRelease] = true
				at(x.EvidenceRelease).regressed++
			}
		}
		if gi.Workflow == "resolved" {
			resolved := map[model.ID]bool{}
			for _, list := range [][]model.ID{gi.FixedDescendants, gi.ResolutionFrontier} {
				for _, id := range list {
					if id != (model.ID{}) && !resolved[id] {
						resolved[id] = true
						at(id).resolved++
					}
				}
			}
		}
		if gi.Compacted == nil && gi.LateCompacted == nil {
			continue
		}
		// Folded evidence: every release the issue is observed in may have lost an evaluation or a
		// first-seen fact to the aggregate, so its counts are a lower bound.
		for _, id := range gi.ObservedReleases {
			at(id).incomplete = true
		}
		for _, c := range []*model.GroupingCompaction{gi.Compacted, gi.LateCompacted} {
			if c != nil {
				for _, r := range c.Releases {
					at(r.Release).incomplete = true
				}
			}
		}
	}
	return out
}

func releaseReaderScope(ctx context.Context, authority *auth.Service, c auth.Credential, org model.ID, projects []model.ID) (auth.Scope, error) {
	scope, err := authority.Authorize(ctx, c, org, projects, auth.Read)
	if err != nil && faultIs(err, model.NotFound) {
		if granted, e := authority.Authorize(ctx, c, org, projects, auth.OrgAdmin); e == nil {
			return granted, nil
		}
	}
	return scope, err
}

type releaseListParams struct {
	Org            model.ID     `json:"org"`
	Projects       []model.ID   `json:"projects"`
	Window         any          `json:"window"`
	Query          string       `json:"query"`
	Sort           string       `json:"sort"`
	Environment    string       `json:"environment"`
	DeployedAfter  *model.Int64 `json:"deployed_after"`
	HasRegressions *bool        `json:"has_regressions"`
}

func (b ReleaseListBody) validate() error {
	if err := b.ListRequest.validate(false); err != nil {
		return err
	}
	switch b.Sort {
	case "", "build_time", "deployed_at":
	default:
		return invalid("sort_invalid")
	}
	if b.DeployedAfter != nil && *b.DeployedAfter <= 0 {
		return invalid("deployed_after_invalid")
	}
	return nil
}

func (b ReleaseListBody) matches(item ReleaseListItem, deploys []auth.DeployItem) bool {
	if b.Window != nil && (model.UnixNano(item.BuildTime) < b.Window.Start || model.UnixNano(item.BuildTime) >= b.Window.End) {
		return false
	}
	if q := strings.ToLower(b.Query); q != "" {
		if !(hexPrefix(q) && strings.HasPrefix(item.ReleaseID.String(), q)) && !strings.Contains(strings.ToLower(item.Label), q) {
			return false
		}
	}
	if b.Environment != (model.ID{}) || b.DeployedAfter != nil {
		hit := false
		for _, d := range deploys {
			if b.Environment != (model.ID{}) && d.Env != b.Environment {
				continue
			}
			if b.DeployedAfter != nil && d.Last <= *b.DeployedAfter {
				continue
			}
			hit = true
			break
		}
		if !hit {
			return false
		}
	}
	if b.HasRegressions != nil {
		if item.RegressedIssues == nil || (*item.RegressedIssues > 0) != *b.HasRegressions {
			return false
		}
	}
	return true
}

type releaseRow struct {
	item ReleaseListItem
	key  int64
}

func (b ReleaseListBody) sortKey(item ReleaseListItem, deploys []auth.DeployItem) int64 {
	if b.Sort != "deployed_at" {
		return int64(item.BuildTime)
	}
	key := int64(math.MinInt64) // no recorded deploy: last, never first
	for _, d := range deploys {
		if b.Environment == (model.ID{}) || d.Env == b.Environment {
			key = max(key, int64(d.Last))
		}
	}
	return key
}

// releaseListView builds the answer for a validated body under scope.
func releaseListView(ctx context.Context, authority *auth.Service, source ReleaseListSource, tickets ListTickets, scope auth.Scope, body ReleaseListBody) (ConsoleList[ReleaseListItem], error) {
	digest, err := listDigest(releaseListOp, releaseListParams{Org: body.Org, Projects: body.Projects, Window: body.Window, Query: body.Query, Sort: body.Sort, Environment: body.Environment.String(), DeployedAfter: body.DeployedAfter, HasRegressions: body.HasRegressions})
	if err != nil {
		return ConsoleList[ReleaseListItem]{}, err
	}
	var after *listPos
	if body.Cursor != "" {
		after = &listPos{}
		if err = openListCursor(ctx, tickets, scope, releaseListOp, digest, body.Cursor, after); err != nil {
			return ConsoleList[ReleaseListItem]{}, err
		}
	}
	markers, err := authority.ListDeploys(ctx, scope, body.Projects, model.ID{})
	if err != nil {
		return ConsoleList[ReleaseListItem]{}, err
	}
	type pair struct{ project, release model.ID }
	byRelease := map[pair][]auth.DeployItem{}
	for _, m := range markers {
		k := pair{m.ProjectID, m.ReleaseID}
		byRelease[k] = append(byRelease[k], m)
	}
	var rows []releaseRow
	capped, compacted, countsAbsent := false, false, false
	for _, project := range body.Projects {
		data, err := source.ReleaseList(ctx, scope, project)
		if err != nil {
			return ConsoleList[ReleaseListItem]{}, err
		}
		capped = capped || data.Capped
		var tally map[model.ID]*releaseTally
		if data.IssuesKnown {
			tally = tallyReleases(data)
		} else {
			countsAbsent = true
		}
		for _, rel := range data.Releases {
			deploys := byRelease[pair{project, rel.ID}]
			item := ReleaseListItem{ProjectID: project, ReleaseID: rel.ID, BuildID: rel.BuildID, Label: rel.DisplayLabel, BuildTime: model.Int64(rel.BuildTime),
				Parents: append([]model.ID{}, rel.Parents...), Deploys: make([]ReleaseDeployView, 0, len(deploys)), DeployState: "unknown", CountsState: CountsNotAvailable}
			for _, d := range deploys {
				item.Deploys = append(item.Deploys, ReleaseDeployView{Environment: d.Env, DeployedAt: d.Last})
			}
			if len(deploys) > 0 {
				item.DeployState = "known"
			}
			if data.IssuesKnown {
				t := tally[rel.ID]
				if t == nil {
					t = &releaseTally{}
				}
				n, r, s := t.newIssues, t.regressed, t.resolved
				item.NewIssues, item.RegressedIssues, item.ResolvedIssues, item.CountsState = &n, &r, &s, CountsReady
				if t.incomplete {
					item.CountsState = CountsIncomplete
					compacted = true
				}
			}
			if body.matches(item, deploys) {
				rows = append(rows, releaseRow{item: item, key: body.sortKey(item, deploys)})
			}
		}
	}
	slices.SortFunc(rows, func(a, b releaseRow) int {
		ap, bp, ai, bi := a.item.ProjectID.String(), b.item.ProjectID.String(), a.item.ReleaseID.String(), b.item.ReleaseID.String()
		switch {
		case listLess(a.key, ap, ai, b.key, bp, bi):
			return -1
		case listLess(b.key, bp, bi, a.key, ap, ai):
			return 1
		}
		return 0
	})
	if after != nil {
		rows = slices.DeleteFunc(rows, func(r releaseRow) bool {
			return !after.before(r.key, r.item.ProjectID.String(), r.item.ReleaseID.String())
		})
	}
	out := newConsoleList[ReleaseListItem](body.ListRequest, StateReady, "", "releases")
	limit := body.pageLimit()
	if len(rows) > limit {
		out.More = true
		rows = rows[:limit]
	}
	for _, r := range rows {
		out.Items = append(out.Items, r.item)
	}
	if out.More {
		last := rows[len(rows)-1]
		if out.NextCursor, err = issueListCursor(ctx, tickets, scope, releaseListOp, digest, listPos{Key: last.key, Project: last.item.ProjectID.String(), ID: last.item.ReleaseID.String()}); err != nil {
			return ConsoleList[ReleaseListItem]{}, err
		}
	}
	releases := ViewSection{Name: "releases", State: StateReady}
	switch {
	case capped:
		releases = ViewSection{Name: "releases", State: StateIncomplete, Reason: ReasonReleaseScanCapped}
	case len(out.Items) == 0 && !out.More:
		releases = ViewSection{Name: "releases", State: StateEmpty, Reason: ReasonListNoItems}
	}
	deploys := ViewSection{Name: "deploys", State: StateReady}
	if len(markers) == 0 {
		deploys = ViewSection{Name: "deploys", State: StateEmpty, Reason: ReasonNoDeployMarkers}
	}
	counts := ViewSection{Name: "issue_counts", State: StateReady}
	switch {
	case countsAbsent:
		counts = ViewSection{Name: "issue_counts", State: StateNotAvailable, Reason: ReasonIssueCountsAbsent}
	case compacted:
		counts = ViewSection{Name: "issue_counts", State: StateIncomplete, Reason: ReasonIssueCountsCompacted}
	}
	out.Sections = []ViewSection{releases, deploys, counts}
	out.State, out.Reason = StateReady, ""
	switch {
	case releases.State == StateIncomplete:
		out.State, out.Reason = StateIncomplete, releases.Reason
	case counts.State != StateReady:
		out.State, out.Reason = StateIncomplete, counts.Reason
	case releases.State == StateEmpty:
		out.State, out.Reason = StateEmpty, releases.Reason
	}
	return out, nil
}

// RegisterReleaseListRoute mounts the release list:
//
//	POST /api/v1/releases/list  ReleaseListBody -> ConsoleList[ReleaseListItem]
//
// Readers of every requested project (telemetry.read, or organization admin) may call it; a project the
// credential does not cover is the one not-found. source or tickets nil is an explicit not_available
// answer, never an empty list.
func RegisterReleaseListRoute(mux *http.ServeMux, authority *auth.Service, source ReleaseListSource, tickets ListTickets) {
	listRoute(mux, authority, "/api/v1/releases/list", func(ctx context.Context, credential auth.Credential, body ReleaseListBody) (any, []auth.Scope, error) {
		if err := body.validate(); err != nil {
			return nil, nil, err
		}
		scope, err := releaseReaderScope(ctx, authority, credential, body.Org, body.Projects)
		if err != nil {
			return nil, nil, err
		}
		if err = body.allowsAll(scope); err != nil {
			return nil, nil, err
		}
		if source == nil || tickets == nil {
			return newConsoleList[ReleaseListItem](body.ListRequest, StateNotAvailable, ReasonListSourceNotWired, "releases"), []auth.Scope{scope}, nil
		}
		view, err := releaseListView(ctx, authority, source, tickets, scope, body)
		return view, []auth.Scope{scope}, err
	})
}
