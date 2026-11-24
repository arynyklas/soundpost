// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"slices"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query"
)

// This file holds what the console list routes (issues, replays, profiles) share:
// the request frame, the answer envelope and the authenticated pagination cursor.
// docs/operations/console-api.md section 5 is the contract.

// Bounds of a console list request.
const (
	// DefaultConsoleListLimit is the page size when the request names none.
	DefaultConsoleListLimit = 50
	// MaxConsoleListLimit is the largest page.
	MaxConsoleListLimit = 200
	// MaxConsoleListWindow is the longest window a list may read.
	MaxConsoleListWindow = 31 * 24 * time.Hour
	maxListQueryBytes    = 128
	maxListCursorBytes   = 4096
)

// Closed reasons of the console lists (a static vocabulary: none carries telemetry or caller text).
const (
	ReasonListSourceNotWired  = "list_source_not_wired"
	ReasonListNoItems         = "no_matching_items"
	ReasonListScanCapped      = "scan_capped"
	ReasonSearchScanCapped    = "search_scan_capped"
	ReasonTitlesNotAvailable  = "titles_not_available"
	ReasonRegressionNotWired  = "regression_not_available"
	ReasonCursorInvalid       = "cursor_invalid"
	listCursorTTL             = 15 * time.Minute
	listCursorStateVersion    = 1
	listCursorKindPrefix      = "cl-"
	listUnreadableSearchTitle = "search_title_unreadable"
)

// ConsoleList is the one answer envelope of every console list.
type ConsoleList[T any] struct {
	Org        model.ID      `json:"org"`
	Projects   []model.ID    `json:"projects"`
	State      ViewState     `json:"state"`
	Reason     string        `json:"reason,omitempty"`
	Items      []T           `json:"items"`
	More       bool          `json:"more"`
	NextCursor string        `json:"next_cursor,omitempty"`
	Sections   []ViewSection `json:"sections"`
}

func newConsoleList[T any](req ListRequest, state ViewState, reason string, section string) ConsoleList[T] {
	return ConsoleList[T]{Org: req.Org, Projects: slices.Clone(req.Projects), State: state, Reason: reason, Items: []T{},
		Sections: []ViewSection{{Name: section, State: state, Reason: reason}}}
}

// ListRequest is the part of every list body: org and projects are selectors the caller's own
// credential confirms, never a scope.
type ListRequest struct {
	Org      model.ID         `json:"org"`
	Projects []model.ID       `json:"projects"`
	Window   *query.TimeRange `json:"window,omitempty"`
	Limit    int              `json:"limit,omitempty"`
	Cursor   string           `json:"cursor,omitempty"`
	Query    string           `json:"query,omitempty"`
	Sort     string           `json:"sort,omitempty"`
}

// pageLimit is the validated page size.
func (r ListRequest) pageLimit() int {
	if r.Limit == 0 {
		return DefaultConsoleListLimit
	}
	return r.Limit
}

// validate checks the frame every list shares. windowRequired lists (replays, profiles) need a window.
func (r ListRequest) validate(windowRequired bool) error {
	if r.Org == (model.ID{}) || len(r.Projects) == 0 || len(r.Projects) > MaxInvestigationProjects {
		return invalid("list_request_invalid")
	}
	for i, p := range r.Projects {
		if p == (model.ID{}) || slices.Contains(r.Projects[:i], p) {
			return invalid("list_request_invalid")
		}
	}
	if r.Limit < 0 || r.Limit > MaxConsoleListLimit || len(r.Cursor) > maxListCursorBytes {
		return invalid("list_request_invalid")
	}
	if r.Window == nil && windowRequired {
		return invalid("window_required")
	}
	if r.Window != nil {
		w := *r.Window
		if w.End <= w.Start || time.Duration(w.End-w.Start) > MaxConsoleListWindow || w.Start < 0 {
			return invalid("window_invalid")
		}
	}
	if !plainText(r.Query, maxListQueryBytes) {
		return invalid("query_invalid")
	}
	return nil
}

// plainText reports whether s is valid UTF-8 without control characters and within max bytes.
func plainText(s string, max int) bool {
	if len(s) > max || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// allowsAll reports whether the scope covers every requested project; a project it does not cover is the
// same not-found a missing one gives.
func (r ListRequest) allowsAll(scope auth.Scope) error {
	for _, p := range r.Projects {
		if !scope.AllowsProject(p) {
			return model.Fail(model.NotFound)
		}
	}
	return nil
}

// ListTickets is the authenticated-cursor seam (*auth.Cache implements it): a ticket is bound to the issuing
// scope's visibility, policy epoch and delete generation.
type ListTickets interface {
	IssueTicket(ctx context.Context, scope auth.Scope, kind string, subject model.ID, state []byte, ttl time.Duration) (string, error)
	OpenTicket(ctx context.Context, scope auth.Scope, kind, token string) (model.ID, []byte, error)
}

// listCursor is the authenticated payload of a list cursor: the operation, a digest of the request
// parameters (so a cursor can only continue the request that produced it) and the position.
type listCursor struct {
	Version int             `json:"v"`
	Op      string          `json:"o"`
	Params  [32]byte        `json:"p"`
	After   json.RawMessage `json:"a"`
}

// listDigest binds a cursor to the request parameters, without the cursor and the page size.
func listDigest(op string, params any) ([32]byte, error) {
	raw, err := json.Marshal(params)
	if err != nil {
		return [32]byte{}, model.Fail(model.Invalid)
	}
	h := sha256.New()
	h.Write([]byte(op))
	h.Write([]byte{0})
	h.Write(raw)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}

func listSubject(d [32]byte) model.ID {
	var id model.ID
	copy(id[:], d[:16])
	if id == (model.ID{}) {
		id[15] = 1
	}
	return id
}

func issueListCursor(ctx context.Context, t ListTickets, scope auth.Scope, op string, digest [32]byte, after any) (string, error) {
	if t == nil {
		return "", model.Fail(model.Unavailable)
	}
	raw, err := json.Marshal(after)
	if err != nil || len(raw) > 1024 {
		return "", model.Fail(model.TooLarge)
	}
	state, err := json.Marshal(listCursor{Version: listCursorStateVersion, Op: op, Params: digest, After: raw})
	if err != nil {
		return "", model.Fail(model.Unavailable)
	}
	return t.IssueTicket(ctx, scope, listCursorKindPrefix+op, listSubject(digest), state, listCursorTTL)
}

// openListCursor validates a presented cursor and decodes its position into after. A cursor of another
// caller, scope, epoch or request, a forged or an expired one is the one typed 400 cursor_invalid.
func openListCursor(ctx context.Context, t ListTickets, scope auth.Scope, op string, digest [32]byte, token string, after any) error {
	if t == nil {
		return model.Fail(model.Unavailable)
	}
	subject, raw, err := t.OpenTicket(ctx, scope, listCursorKindPrefix+op, token)
	if err != nil {
		if faultIs(err, model.NotFound) {
			return invalid(ReasonCursorInvalid)
		}
		return err
	}
	var st listCursor
	if json.Unmarshal(raw, &st) != nil || st.Version != listCursorStateVersion || st.Op != op || st.Params != digest || subject != listSubject(digest) || json.Unmarshal(st.After, after) != nil {
		return invalid(ReasonCursorInvalid)
	}
	return nil
}

// listRoute mounts one console list route (see listHandler).
func listRoute[B any](mux *http.ServeMux, authority *auth.Service, path string, handle func(ctx context.Context, credential auth.Credential, body B) (any, []auth.Scope, error)) {
	mux.HandleFunc("POST "+path, listHandler(authority, handle))
}

// listHandler is the handler of one console list route: the credential is the session with CSRF or a bearer token, the body is decoded
// strictly, and every scope the handler used is revalidated before a byte of the answer is released.
func listHandler[B any](authority *auth.Service, handle func(ctx context.Context, credential auth.Credential, body B) (any, []auth.Scope, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		credential, err := artifactCredential(authority, w, r)
		if err != nil {
			queryReply(w, nil, err)
			return
		}
		var body B
		if err = decode(w, r, &body); err != nil {
			queryReply(w, nil, err)
			return
		}
		view, scopes, err := handle(r.Context(), credential, body)
		for _, s := range scopes {
			if err == nil {
				err = authority.Revalidate(r.Context(), s)
			}
		}
		queryReply(w, view, err)
	}
}

// listPos is the position a cursor resumes after, in the order of listLess.
type listPos struct {
	Key     int64  `json:"k"`
	Project string `json:"p"`
	ID      string `json:"i"`
}

// before reports whether an item with this key and ids sorts strictly after the position.
func (p listPos) before(key int64, project, id string) bool {
	if key != p.Key {
		return key < p.Key
	}
	if project != p.Project {
		return project > p.Project
	}
	return id > p.ID
}

// listLess is the order of every list: key descending, project then id ascending.
func listLess(ak int64, ap, ai string, bk int64, bp, bi string) bool {
	if ak != bk {
		return ak > bk
	}
	if ap != bp {
		return ap < bp
	}
	return ai < bi
}

// hexPrefix reports whether q is a non-empty lower-case hex string of at most one ID's length.
func hexPrefix(q string) bool {
	if q == "" || len(q) > 32 {
		return false
	}
	for _, c := range q {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
