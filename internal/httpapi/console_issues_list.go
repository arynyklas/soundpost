// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/issues"
	"github.com/arynyklas/soundpost/internal/model"
)

// This file is POST /api/v1/issues/list (docs/operations/console-api.md section 5): the error issues of
// the requested projects the caller may read, filtered, sorted and paged.
//
// The rows come from the committed grouping issues; first/last seen and the occurrence count are
// issues.Summarize, exact across compaction. The title is the exception type of the newest stored
// occurrence, read through the storage scan under the caller's own telemetry.read scope: a caller
// without that grant, a record that is gone or a reader that is not wired gives title:null with
// title_state:"not_available", never a guess and never frames, messages or user data.

// Bounds of the issue list.
const (
	// MaxIssueTitleBytes is the longest title the list carries.
	MaxIssueTitleBytes = 160
	// MaxIssueTitleReads bounds the stored occurrences one request reads (titles of the page and the
	// candidates of a title search).
	MaxIssueTitleReads = 256
	// maxIssueListReleases bounds the release IDs one item names.
	maxIssueListReleases = 32
)

// IssueRegressions reads the stored regression evaluations (*issues.Service implements it).
type IssueRegressions interface {
	ExplainAll(ctx context.Context, scope auth.Scope, project model.ID) (map[model.ID][]issues.Explanation, error)
}

// IssueListBody is the POST /api/v1/issues/list body.
type IssueListBody struct {
	ListRequest
	Workflow       []string     `json:"workflow,omitempty"`
	Owner          string       `json:"owner,omitempty"`
	Release        *model.ID    `json:"release,omitempty"`
	Regressed      *bool        `json:"regressed,omitempty"`
	LastSeenAfter  *model.Int64 `json:"last_seen_after,omitempty"`
	LastSeenBefore *model.Int64 `json:"last_seen_before,omitempty"`
}

// ListExternalLink is the outward summary of one link to an external tracker: identifiers and a URL, never the marker.
type ListExternalLink struct {
	Provider string       `json:"provider"`
	State    string       `json:"state"`
	Project  string       `json:"project,omitempty"`
	IID      model.Uint64 `json:"iid,omitempty"`
	URL      string       `json:"url,omitempty"`
	Code     string       `json:"code,omitempty"`
	At       model.Int64  `json:"at"`
}

// IssueListItem is one issue of the list.
type IssueListItem struct {
	ProjectID    model.ID           `json:"project_id"`
	IssueID      model.ID           `json:"issue_id"`
	Workflow     string             `json:"workflow"`
	Revision     model.Uint64       `json:"revision"`
	Owner        *model.ID          `json:"owner,omitempty"`
	Title        *string            `json:"title"`
	TitleState   ViewState          `json:"title_state"`
	FirstSeen    *model.Int64       `json:"first_seen"`
	LastSeen     *model.Int64       `json:"last_seen"`
	Occurrences  model.Uint64       `json:"occurrences"`
	Compacted    bool               `json:"compacted"`
	Releases     []model.ID         `json:"releases"`
	ReleasesMore bool               `json:"releases_truncated,omitempty"`
	External     []ListExternalLink `json:"external,omitempty"`
}

// ConsoleListsConfig binds the seams of the console list routes; any may be nil and the matching answer says so.
type ConsoleListsConfig struct {
	// State is the control store the issue rows are read from.
	State ControlView
	// Scanner is the storage scan the replay and profile lists read.
	Scanner SpanScanner
	// Titles reads one stored error occurrence (NewStorageErrorSource).
	Titles ErrorOccurrenceReader
	// Regressions reads the stored regression evaluations behind the regressed filter.
	Regressions IssueRegressions
	// Tickets mints and opens the authenticated cursors.
	Tickets ListTickets
	// TitleReadBudget narrows the stored occurrences one issue-list request may read; zero or more than
	// MaxIssueTitleReads means MaxIssueTitleReads (a bound may only shrink).
	TitleReadBudget int
}

// ConsoleLists is the handler set behind the issue, replay and profile lists.
type ConsoleLists struct{ cfg ConsoleListsConfig }

// NewConsoleLists binds the seams.
func NewConsoleLists(cfg ConsoleListsConfig) *ConsoleLists { return &ConsoleLists{cfg: cfg} }

// RegisterConsoleListRoutes mounts the console lists. Every route derives its scope from the caller's own credential.
//
//	POST /api/v1/issues/list    IssueListBody  -> ConsoleList[IssueListItem]
//	POST /api/v1/replays/list   ReplayListBody -> ConsoleList[ReplayListItem]
//	POST /api/v1/profiles/list  ProfileListBody -> ConsoleList[ProfileListItem]
func RegisterConsoleListRoutes(mux *http.ServeMux, authority *auth.Service, l *ConsoleLists) {
	listRoute(mux, authority, "/api/v1/issues/list", func(ctx context.Context, c auth.Credential, b IssueListBody) (any, []auth.Scope, error) {
		return l.Issues(ctx, authority, c, b)
	})
	listRoute(mux, authority, "/api/v1/replays/list", func(ctx context.Context, c auth.Credential, b ReplayListBody) (any, []auth.Scope, error) {
		return l.Replays(ctx, authority, c, b)
	})
	listRoute(mux, authority, "/api/v1/profiles/list", func(ctx context.Context, c auth.Credential, b ProfileListBody) (any, []auth.Scope, error) {
		return l.Profiles(ctx, authority, c, b)
	})
}

// issueRow is the part of one grouping issue a list needs, copied out of the control state.
type issueRow struct {
	project, id model.ID
	workflow    string
	revision    model.Revision
	owner       *model.ID
	external    []model.ExternalLink
	first, last model.UnixNano
	count       uint64
	compacted   bool
	releases    []model.ID
	newest      *newestEvidence
}

// newestEvidence names the stored error record behind the newest retained occurrence.
type newestEvidence struct {
	record, occurrence model.ID
	at                 model.UnixNano
}

func (r issueRow) key(sort string) int64 {
	switch sort {
	case "first_seen":
		return int64(r.first)
	case "occurrences":
		return int64(r.count)
	}
	return int64(r.last)
}

func validIssueListBody(b IssueListBody) error {
	if err := b.validate(false); err != nil {
		return err
	}
	switch b.Sort {
	case "", "last_seen", "first_seen", "occurrences":
	default:
		return invalid("sort_invalid")
	}
	for i, w := range b.Workflow {
		if w != "open" && w != "resolved" && w != "ignored" || slices.Contains(b.Workflow[:i], w) {
			return invalid("workflow_invalid")
		}
	}
	if b.Owner != "" && b.Owner != "none" {
		if _, err := model.ParseID(b.Owner); err != nil {
			return invalid("owner_invalid")
		}
	}
	if b.Release != nil && *b.Release == (model.ID{}) {
		return invalid("release_invalid")
	}
	return nil
}

// issueListDigest is the request identity a cursor binds: everything but the cursor and the page size.
func issueListDigest(b IssueListBody) ([32]byte, error) {
	b.Cursor, b.Limit = "", 0
	return listDigest("issues", b)
}

// Issues answers one issue list under the caller's own authority.
func (l *ConsoleLists) Issues(ctx context.Context, authority *auth.Service, credential auth.Credential, body IssueListBody) (any, []auth.Scope, error) {
	if err := validIssueListBody(body); err != nil {
		return nil, nil, err
	}
	scope, err := issueListScope(ctx, authority, credential, body.Org, body.Projects)
	if err != nil {
		return nil, nil, err
	}
	if err = body.allowsAll(scope); err != nil {
		return nil, nil, err
	}
	scopes := []auth.Scope{scope}
	if l == nil || l.cfg.State == nil {
		return newConsoleList[IssueListItem](body.ListRequest, StateNotAvailable, ReasonListSourceNotWired, "issues"), scopes, nil
	}
	digest, err := issueListDigest(body)
	if err != nil {
		return nil, nil, err
	}
	var after *listPos
	if body.Cursor != "" {
		after = new(listPos)
		if err = openListCursor(ctx, l.cfg.Tickets, scope, "issues", digest, body.Cursor, after); err != nil {
			return nil, nil, err
		}
	}
	rows, err := l.issueRows(ctx, scope, body)
	if err != nil {
		return nil, nil, err
	}
	sections := []ViewSection{{Name: "issues", State: StateReady}}
	if body.Regressed != nil {
		if l.cfg.Regressions == nil {
			return newConsoleList[IssueListItem](body.ListRequest, StateNotAvailable, ReasonRegressionNotWired, "regressions"), scopes, nil
		}
		if rows, err = l.filterRegressed(ctx, scope, body, rows); err != nil {
			return nil, nil, err
		}
		sections = append(sections, ViewSection{Name: "regressions", State: StateReady})
	}
	sortIssueRows(rows, body.Sort)
	start := 0
	if after != nil {
		sort := body.Sort
		start = slices.IndexFunc(rows, func(r issueRow) bool { return after.before(r.key(sort), r.project.String(), r.id.String()) })
		if start < 0 {
			start = len(rows)
		}
	}
	titles := &issueTitles{lists: l, authority: authority, credential: credential, body: body, memo: map[model.ID]issueTitle{}}
	out := newConsoleList[IssueListItem](body.ListRequest, StateReady, "", "issues")
	out.Sections = sections
	limit := body.pageLimit()
	q := strings.ToLower(strings.TrimSpace(body.Query))
	examined, capped, unreadable := start, false, 0
	for ; examined < len(rows) && len(out.Items) < limit; examined++ {
		row := rows[examined]
		if q != "" && !(hexPrefix(q) && strings.HasPrefix(row.id.String(), q)) {
			t, status, err := titles.read(ctx, row)
			if err != nil {
				return nil, nil, err
			}
			if status == titleBudget {
				capped = true
				break
			}
			if status == titleUnavailable {
				unreadable++
				continue
			}
			if !strings.Contains(strings.ToLower(t), q) {
				continue
			}
		}
		item, err := titles.item(ctx, row)
		if err != nil {
			return nil, nil, err
		}
		out.Items = append(out.Items, item)
	}
	scopes = append(scopes, titles.scopes...)
	out.More = examined < len(rows)
	if out.More && examined == start {
		// The budget ended the request before one candidate was examined: nothing to resume from but the cursor given.
		out.NextCursor = body.Cursor
	} else if out.More {
		last := rows[examined-1]
		if out.NextCursor, err = issueListCursor(ctx, l.cfg.Tickets, scope, "issues", digest, listPos{Key: last.key(body.Sort), Project: last.project.String(), ID: last.id.String()}); err != nil {
			return nil, nil, err
		}
	}
	titleSection := ViewSection{Name: "titles", State: StateReady}
	if titles.missing > 0 || unreadable > 0 {
		titleSection = ViewSection{Name: "titles", State: StateIncomplete, Reason: ReasonTitlesNotAvailable}
	}
	out.Sections = append(out.Sections, titleSection)
	switch {
	case capped:
		out.State, out.Reason = StateIncomplete, ReasonSearchScanCapped
	case unreadable > 0:
		out.State, out.Reason = StateIncomplete, listUnreadableSearchTitle
	case len(out.Items) == 0 && !out.More:
		out.State, out.Reason = StateEmpty, ReasonListNoItems
	}
	out.Sections[0] = ViewSection{Name: "issues", State: out.State, Reason: out.Reason}
	return out, scopes, nil
}

// issueRows copies the rows of the requested projects that pass the structural filters out of the control state.
func (l *ConsoleLists) issueRows(ctx context.Context, scope auth.Scope, body IssueListBody) ([]issueRow, error) {
	wanted := map[model.ID]bool{}
	for _, p := range body.Projects {
		wanted[p] = true
	}
	var owner *model.ID
	if body.Owner != "" && body.Owner != "none" {
		id, _ := model.ParseID(body.Owner)
		owner = &id
	}
	var rows []issueRow
	err := l.cfg.State.View(ctx, func(st model.ControlState) error {
		if err := scope.ValidateControlState(st); err != nil {
			return err
		}
		for _, gi := range st.GroupingIssues {
			if gi.Org != scope.OrgID() || !wanted[gi.Project] {
				continue
			}
			if len(body.Workflow) > 0 && !slices.Contains(body.Workflow, gi.Workflow) {
				continue
			}
			if o := issueOwnerOf(gi); body.Owner == "none" && o != nil || owner != nil && (o == nil || *o != *owner) {
				continue
			}
			row := issueRowOf(gi)
			if row.excluded(body) {
				continue
			}
			rows = append(rows, row)
		}
		return nil
	})
	return rows, err
}

func issueRowOf(gi model.GroupingIssue) issueRow {
	s := issues.Summarize(gi)
	row := issueRow{project: gi.Project, id: gi.ID, workflow: gi.Workflow, revision: gi.Revision, owner: issueOwnerOf(gi), external: issueExternalOf(gi), count: uint64(s.Count),
		compacted: gi.Compacted != nil && gi.Compacted.Count > 0 || gi.LateCompacted != nil && gi.LateCompacted.Count > 0}
	if s.Count > 0 {
		row.first, row.last = s.FirstSeen, s.LastSeen
	}
	seen := map[model.ID]bool{}
	add := func(id model.ID) {
		if id != (model.ID{}) && !seen[id] {
			seen[id] = true
			row.releases = append(row.releases, id)
		}
	}
	for _, id := range gi.ObservedReleases {
		add(id)
	}
	for _, c := range []*model.GroupingCompaction{gi.Compacted, gi.LateCompacted} {
		if c != nil {
			for _, r := range c.Releases {
				add(r.Release)
			}
		}
	}
	for _, list := range [][]model.GroupingEvidence{gi.Occurrences, gi.LateHistory} {
		for _, e := range list {
			if e.ReleaseID != nil {
				add(*e.ReleaseID)
			}
			if row.newest == nil || e.EventTime > row.newest.at {
				row.newest = &newestEvidence{record: e.RecordID, occurrence: e.OccurrenceID, at: e.EventTime}
			}
		}
	}
	return row
}

// excluded applies the filters that need the summary: the release and the last-seen bounds and window.
func (r issueRow) excluded(b IssueListBody) bool {
	if b.Release != nil && !slices.Contains(r.releases, *b.Release) {
		return true
	}
	if b.LastSeenAfter != nil || b.LastSeenBefore != nil || b.Window != nil {
		if r.count == 0 {
			return true // no stored evidence: its last-seen time is unknown, so it matches no time filter
		}
		if b.LastSeenAfter != nil && int64(r.last) <= int64(*b.LastSeenAfter) || b.LastSeenBefore != nil && int64(r.last) >= int64(*b.LastSeenBefore) {
			return true
		}
		if b.Window != nil && (r.last < b.Window.Start || r.last >= b.Window.End) {
			return true
		}
	}
	return false
}

func sortIssueRows(rows []issueRow, sort string) {
	slices.SortFunc(rows, func(a, b issueRow) int {
		switch {
		case listLess(a.key(sort), a.project.String(), a.id.String(), b.key(sort), b.project.String(), b.id.String()):
			return -1
		case listLess(b.key(sort), b.project.String(), b.id.String(), a.key(sort), a.project.String(), a.id.String()):
			return 1
		}
		return 0
	})
}

// filterRegressed keeps the issues whose stored regression evaluations did (or did not) reopen them.
func (l *ConsoleLists) filterRegressed(ctx context.Context, scope auth.Scope, body IssueListBody, rows []issueRow) ([]issueRow, error) {
	reopened := map[model.ID]map[model.ID]bool{}
	for _, p := range body.Projects {
		all, err := l.cfg.Regressions.ExplainAll(ctx, scope, p)
		if err != nil {
			return nil, err
		}
		set := map[model.ID]bool{}
		for id, list := range all {
			for _, x := range list {
				if x.Reopened {
					set[id] = true
				}
			}
		}
		reopened[p] = set
	}
	return slices.DeleteFunc(rows, func(r issueRow) bool { return reopened[r.project][r.id] != *body.Regressed }), nil
}

// issueTitles reads the titles of a request: one telemetry.read scope per project, a memo and the read budget.
type issueTitles struct {
	lists      *ConsoleLists
	authority  *auth.Service
	credential auth.Credential
	body       IssueListBody
	scopes     []auth.Scope
	byProject  map[model.ID]*auth.Scope
	memo       map[model.ID]issueTitle
	reads      int
	missing    int // output items whose title is not available
}

type titleStatus uint8

const (
	titleReady titleStatus = iota
	titleUnavailable
	titleBudget
)

type issueTitle struct {
	text   string
	status titleStatus
}

// projectScope is the caller's own telemetry.read scope for one project, or nil when she holds none there.
func (t *issueTitles) projectScope(ctx context.Context, project model.ID) (*auth.Scope, error) {
	if s, ok := t.byProject[project]; ok {
		return s, nil
	}
	if t.byProject == nil {
		t.byProject = map[model.ID]*auth.Scope{}
	}
	s, err := t.authority.Authorize(ctx, t.credential, t.body.Org, []model.ID{project}, auth.Read)
	var out *auth.Scope
	switch {
	case err == nil && s.AllowsProject(project):
		out = &s
		t.scopes = append(t.scopes, s)
	case err == nil || faultIs(err, model.NotFound):
	default:
		return nil, err
	}
	t.byProject[project] = out
	return out, nil
}

// read returns the title of one issue, reading the newest stored occurrence once per request.
func (t *issueTitles) read(ctx context.Context, row issueRow) (string, titleStatus, error) {
	if m, ok := t.memo[row.id]; ok {
		return m.text, m.status, nil
	}
	if row.newest == nil || t.lists == nil || t.lists.cfg.Titles == nil {
		return t.remember(row.id, issueTitle{status: titleUnavailable})
	}
	scope, err := t.projectScope(ctx, row.project)
	if err != nil {
		return "", titleUnavailable, err
	}
	if scope == nil {
		return t.remember(row.id, issueTitle{status: titleUnavailable})
	}
	if t.reads >= t.lists.titleBudget() {
		return "", titleBudget, nil
	}
	t.reads++
	occ, found, _, err := t.lists.cfg.Titles.ErrorOccurrence(ctx, *scope, row.project, row.newest.record, row.newest.occurrence, row.newest.at)
	if err != nil {
		if ctx.Err() != nil {
			return "", titleUnavailable, ctx.Err()
		}
		return t.remember(row.id, issueTitle{status: titleUnavailable}) // the one request keeps going; the final revalidation catches a revoked scope
	}
	text := ""
	if found && occ.Occurrence == row.newest.occurrence {
		text = titleOf(occ.Class)
	}
	if text == "" {
		return t.remember(row.id, issueTitle{status: titleUnavailable})
	}
	return t.remember(row.id, issueTitle{text: text, status: titleReady})
}

func (t *issueTitles) remember(id model.ID, v issueTitle) (string, titleStatus, error) {
	t.memo[id] = v
	return v.text, v.status, nil
}

// item renders one row, reading its title when the budget still allows.
func (t *issueTitles) item(ctx context.Context, row issueRow) (IssueListItem, error) {
	item := IssueListItem{ProjectID: row.project, IssueID: row.id, Workflow: row.workflow, Revision: model.Uint64(row.revision), Owner: row.owner, TitleState: StateNotAvailable,
		Occurrences: model.Uint64(row.count), Compacted: row.compacted, Releases: []model.ID{}}
	text, status, err := t.read(ctx, row)
	if err != nil {
		return item, err
	}
	if status == titleReady {
		item.Title, item.TitleState = &text, StateReady
	} else {
		t.missing++
	}
	if row.count > 0 {
		item.FirstSeen, item.LastSeen = new(model.Int64(row.first)), new(model.Int64(row.last))
	}
	item.Releases = slices.Clone(row.releases)
	if len(item.Releases) > maxIssueListReleases {
		item.Releases, item.ReleasesMore = item.Releases[:maxIssueListReleases], true
	}
	if item.Releases == nil {
		item.Releases = []model.ID{}
	}
	for _, l := range row.external {
		item.External = append(item.External, ListExternalLink{Provider: l.Provider, State: l.State, Project: l.Project, IID: l.IID, URL: l.URL, Code: l.Code, At: model.Int64(l.At)})
	}
	return item, nil
}

// titleOf is the display title of an exception type: no control characters, at most MaxIssueTitleBytes
// bytes cut on a character boundary. The stored occurrence carries the exception type and no message.
func titleOf(class string) string {
	var b strings.Builder
	for _, r := range strings.TrimSpace(class) {
		if r == utf8.RuneError || unicode.IsControl(r) {
			continue
		}
		if b.Len()+utf8.RuneLen(r) > MaxIssueTitleBytes {
			break
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}

// issueOwnerOf and issueExternalOf are the two members of a grouping issue the console adds to the list.
func issueOwnerOf(gi model.GroupingIssue) *model.ID {
	if gi.Owner == nil {
		return nil
	}
	o := *gi.Owner
	return &o
}

func issueExternalOf(gi model.GroupingIssue) []model.ExternalLink {
	return slices.Clone(gi.External)
}

// titleBudget is the number of stored occurrences one request may read.
func (l *ConsoleLists) titleBudget() int {
	if b := l.cfg.TitleReadBudget; b > 0 && b < MaxIssueTitleReads {
		return b
	}
	return MaxIssueTitleReads
}

// issueListScope is the scope an issue list runs under: telemetry.read on every named project, or issues.write on every
// one (a person who may act on an issue may read it), or organization admin. All come from the caller's own
// credential; failing every one is the one not-found.
func issueListScope(ctx context.Context, authority *auth.Service, credential auth.Credential, org model.ID, projects []model.ID) (auth.Scope, error) {
	scope, err := authority.Authorize(ctx, credential, org, projects, auth.Read)
	if err != nil && faultIs(err, model.NotFound) {
		for _, fallback := range []auth.Permission{auth.IssuesWrite, auth.OrgAdmin} {
			if granted, e := authority.Authorize(ctx, credential, org, projects, fallback); e == nil {
				return granted, nil
			}
		}
	}
	return scope, err
}
