// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/arynyklas/soundpost/internal/model"
)

// This file is the project-owned authorization of C11 saved views.
//
// A query text can hold sensitive literals, so a saved view exists only because
// a caller explicitly saved it under one project, and it is owned by that
// project: whoever currently holds telemetry.read on the project reads it, and
// nobody else learns that it exists. A wrong organization, a project the caller
// cannot read, a revoked reader and an absent view all answer the same
// not-found.
//
//   - list: needs telemetry.read on the project (Authorize, then the scope is
//     validated again in the very state the books are read from).
//   - save: needs telemetry.read on the owning project AND on every project the
//     query runs over (a project that is not readable is the same not-found).
//     A create makes the caller the owner; an update is allowed to the owner
//     and to an organization administrator and is a compare-and-set on the
//     view's revision.
//   - delete: allowed to the view's owner (who must still read the project) and
//     to an organization administrator of the organization, who needs no read
//     grant to remove a view.
//
// Saving changes neither an organization's policy epoch nor the control
// AuthorityRevision: it is a book write of the SavedView command kind
// (control.KindSavedView), committed by the control store under the caller's own
// scope. Time is the service clock's, never the client's; the owner is the
// authenticated principal, never a body field. A save or delete is audited with
// its actor, kind, organization, project and view ID, never with the name or the
// expression.

// SavedViewKind is the control command kind a saved-view save or delete commits
// as (control.KindSavedView; a test pins the two equal). The control store
// admits a telemetry.read scope for this kind only.
const SavedViewKind = "SavedView"

// The operations of the saved-view API. List is read-only; save and delete are
// the two commands.
const (
	SavedViewOpList   = "list"
	SavedViewOpSave   = "save"
	SavedViewOpDelete = "delete"
)

// The phases a committed saved-view command reports in its control result
// ("<phase>:<view revision>"). The revision is the view's own compare-and-set
// token after the command (the revision a delete removed plus one), so a replay
// of the command answers with what the command committed, not with what the view
// has become.
const (
	SavedViewPhaseCreated = "created"
	SavedViewPhaseUpdated = "updated"
	SavedViewPhaseDeleted = "deleted"
)

// Bounds of a saved view. A value past a bound is refused, never truncated.
const (
	MaxSavedViewName        = 120
	MaxSavedViewExpression  = 16384
	MaxSavedViewProjects    = 16
	MaxSavedViewsPerProject = 100
	MaxSavedViewStepSeconds = 366 * 24 * 3600
	MaxSavedViewLogLimit    = 5_000_000
	maxSavedViewToken       = 256
)

// SavedViewSpec is what a caller saves: everything about a view except its
// identity, its owner and its times. It is also the stored and the wire form of
// those fields. The integer fields are decimal strings like every 64-bit
// integer on the API.
type SavedViewSpec struct {
	Name         string        `json:"name"`
	Language     string        `json:"language"`
	Profile      string        `json:"profile"`
	FeatureSet   string        `json:"feature_set"`
	Expression   string        `json:"expression"`
	Projects     []model.ID    `json:"projects"`
	Mode         string        `json:"mode"`
	StepSeconds  *model.Uint64 `json:"step_seconds,omitempty"`
	AllowPartial bool          `json:"allow_partial"`
	LogLimit     *model.Uint64 `json:"log_limit,omitempty"`
	LogOrder     string        `json:"log_order,omitempty"`
}

// IsZero reports whether no field of the spec is set.
func (v SavedViewSpec) IsZero() bool {
	return v.Name == "" && v.Language == "" && v.Profile == "" && v.FeatureSet == "" && v.Expression == "" && len(v.Projects) == 0 &&
		v.Mode == "" && v.StepSeconds == nil && !v.AllowPartial && v.LogLimit == nil && v.LogOrder == ""
}

// SavedView is one committed saved view: the closed DTO stored in
// ControlState.SavedViewBooks and listed on the wire.
type SavedView struct {
	ID      model.ID `json:"id"`
	Org     model.ID `json:"org"`
	Project model.ID `json:"project"`
	SavedViewSpec
	Owner     model.ID       `json:"owner"`
	CreatedNS model.UnixNano `json:"created_ns"`
	UpdatedNS model.UnixNano `json:"updated_ns"`
	Revision  model.Revision `json:"revision"`
}

// SavedViewCommand is the closed payload of the SavedView control command.
// ExpectedRevision is zero for a create (the view must not exist) and the
// view's current revision for an update or a delete. At is the service clock's
// time; the owner and the actor are the committing scope's principal.
type SavedViewCommand struct {
	Operation        string         `json:"operation"`
	Project          model.ID       `json:"project"`
	View             model.ID       `json:"view"`
	ExpectedRevision model.Revision `json:"expected_revision"`
	Spec             *SavedViewSpec `json:"spec,omitempty"`
	At               model.UnixNano `json:"at"`
}

// SavedViewKey is the ControlState.SavedViewBooks key of one view.
func SavedViewKey(org, project, view model.ID) string {
	return savedViewPrefix(org, project) + view.String()
}

// SavedViewPrefix is the key prefix shared by every view of one project.
func SavedViewPrefix(org, project model.ID) string { return savedViewPrefix(org, project) }

func savedViewPrefix(org, project model.ID) string {
	return org.String() + ":" + project.String() + ":"
}

// SavedViewPhase is the control result phase of a committed command.
func SavedViewPhase(phase string, revision model.Revision) string {
	return phase + ":" + strconv.FormatUint(uint64(revision), 10)
}

func parseSavedViewPhase(v string) (phase string, revision model.Revision, ok bool) {
	phase, digits, ok := strings.Cut(v, ":")
	if !ok || phase != SavedViewPhaseCreated && phase != SavedViewPhaseUpdated && phase != SavedViewPhaseDeleted {
		return "", 0, false
	}
	n, err := strconv.ParseUint(digits, 10, 64)
	if err != nil || n == 0 {
		return "", 0, false
	}
	return phase, model.Revision(n), true
}

// Validate is the one shape check of a saved view, shared by the service (before
// anything is looked up) and by the control handler (before anything is
// stored): the owning project must be one of the projects, every bound is
// enforced and a value past a bound is refused, not trimmed. It reads no state:
// the same answer for every caller.
func (v SavedViewSpec) Validate(project model.ID) error {
	if project == (model.ID{}) || len(v.Name) == 0 || len(v.Expression) == 0 || len(v.Projects) == 0 {
		return model.Fail(model.Invalid)
	}
	if len(v.Name) > MaxSavedViewName || len(v.Expression) > MaxSavedViewExpression || len(v.Projects) > MaxSavedViewProjects {
		return model.Fail(model.TooLarge)
	}
	if !utf8.ValidString(v.Name) || !utf8.ValidString(v.Expression) {
		return model.Fail(model.Invalid)
	}
	for _, r := range v.Name {
		if unicode.IsControl(r) {
			return model.Fail(model.Invalid)
		}
	}
	seen := make(map[model.ID]bool, len(v.Projects))
	owned := false
	for _, p := range v.Projects {
		if p == (model.ID{}) || seen[p] {
			return model.Fail(model.Invalid)
		}
		seen[p] = true
		owned = owned || p == project
	}
	if !owned {
		return model.Fail(model.Invalid)
	}
	if v.Language != "promql" && v.Language != "logql" || !savedViewToken(v.Profile, false) || !savedViewToken(v.FeatureSet, true) {
		return model.Fail(model.Invalid)
	}
	switch v.Mode {
	case "instant":
		if v.StepSeconds != nil {
			return model.Fail(model.Invalid)
		}
	case "range":
		if v.StepSeconds != nil && (*v.StepSeconds < 1 || *v.StepSeconds > MaxSavedViewStepSeconds) {
			return model.Fail(model.Invalid)
		}
	default:
		return model.Fail(model.Invalid)
	}
	if v.Language == "logql" {
		if v.LogLimit != nil && (*v.LogLimit < 1 || *v.LogLimit > MaxSavedViewLogLimit) {
			return model.Fail(model.Invalid)
		}
		if v.LogOrder != "" && v.LogOrder != "backward" && v.LogOrder != "forward" {
			return model.Fail(model.Invalid)
		}
	} else if v.LogLimit != nil || v.LogOrder != "" {
		return model.Fail(model.Invalid)
	}
	return nil
}

// savedViewToken is a bounded safe identifier: an ASCII letter or digit first,
// then letters, digits and . _ - : only, and also / when slash is set. A profile
// is `promql-prometheus-3.13.5` or `logql-loki-3.5.2`; a feature set is
// `features-<64 hex>` or `<profile>/semantic-sha256-<64 hex>` (about 110
// bytes), so only a feature set may carry the slash. Both are checked against
// nothing else here (the query engine owns the registry).
func savedViewToken(s string, slash bool) bool {
	if s == "" || len(s) > maxSavedViewToken {
		return false
	}
	for i := range len(s) {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case i > 0 && (c == '.' || c == '_' || c == '-' || c == ':'):
		case i > 0 && slash && c == '/':
		default:
			return false
		}
	}
	return true
}

// SavedViewStore is what a ControlStore must also implement for saved views:
// *control.Store does. CommitSavedView commits one SavedView command under the
// caller's own scope (retrying only the loss of the control revision race) and
// BindSavedViews installs the command's handler on that store.
type SavedViewStore interface {
	BindSavedViews() error
	CommitSavedView(ctx context.Context, scope Scope, cmd model.ControlCommand) (model.ControlResult, error)
}

// BindSavedViews installs the SavedView command handler on the control store
// behind this service, once: a store that already has it is not an error. The
// route registration calls it, so a composition that mounts the route needs no
// other wiring. A store that cannot commit saved views is Unsupported.
func (s *Service) BindSavedViews() error {
	store, ok := s.store.(SavedViewStore)
	if !ok {
		return model.Fail(model.Unsupported)
	}
	if err := store.BindSavedViews(); err != nil {
		var f *model.Fault
		if errors.As(err, &f) && f.Code == model.Conflict {
			return nil // bound already
		}
		return err
	}
	return nil
}

// ListSavedViews lists the saved views of one project, oldest first, to a caller
// who currently holds telemetry.read on it. The scope is validated again in the
// state the books are read from, so a grant revoked an instant ago lists
// nothing. A wrong organization, an unknown or unreadable project and a revoked
// reader are the same not-found; an empty project lists an empty slice.
func (s *Service) ListSavedViews(ctx context.Context, c Credential, org, project model.ID) ([]SavedView, error) {
	if org == (model.ID{}) || project == (model.ID{}) {
		return nil, model.Fail(model.Invalid)
	}
	scope, err := s.Authorize(ctx, c, org, []model.ID{project}, Read)
	if err != nil {
		return nil, err
	}
	out := []SavedView{}
	err = s.store.View(model.WithoutBooks(ctx), func(st model.ControlState) error {
		if err := scope.ValidateControlState(st); err != nil {
			return err
		}
		prefix := savedViewPrefix(org, project)
		for key, raw := range st.SavedViewBooks {
			if !strings.HasPrefix(key, prefix) {
				continue
			}
			var v SavedView
			if json.Unmarshal(raw, &v) != nil || v.Org != org || v.Project != project || key != SavedViewKey(org, project, v.ID) {
				return model.Fail(model.Corrupt)
			}
			out = append(out, v)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedNS != out[j].CreatedNS {
			return out[i].CreatedNS < out[j].CreatedNS
		}
		return bytes.Compare(out[i].ID[:], out[j].ID[:]) < 0
	})
	return out, nil
}

// SavedViewSave is one save: a create when ID is zero (ExpectedRevision must be
// zero), otherwise an update of that view at ExpectedRevision (which must be
// set). CommandID makes the save idempotent: a replay answers with the first
// result and changes nothing.
type SavedViewSave struct {
	Org, Project     model.ID
	CommandID        model.ID
	ID               model.ID
	ExpectedRevision model.Revision
	Spec             SavedViewSpec
}

// SavedViewDelete is one delete of the view ID at ExpectedRevision.
type SavedViewDelete struct {
	Org, Project     model.ID
	CommandID        model.ID
	ID               model.ID
	ExpectedRevision model.Revision
}

// SavedViewCommit is the answer of a committed save or delete: the view as it
// was committed (absent for a delete, and for a replay whose view has been
// changed since) and the revision the command committed at.
type SavedViewCommit struct {
	View     *SavedView
	Revision model.Revision
}

// SaveSavedView creates or updates a saved view. The caller needs telemetry.read
// on the owning project and on every project of the query; anything less is the
// one not-found. The shape is refused before any state is looked at.
func (s *Service) SaveSavedView(ctx context.Context, c Credential, r SavedViewSave) (SavedViewCommit, error) {
	create := r.ID == (model.ID{})
	if r.Org == (model.ID{}) || r.Project == (model.ID{}) || r.CommandID == (model.ID{}) || create != (r.ExpectedRevision == 0) {
		return SavedViewCommit{}, model.Fail(model.Invalid)
	}
	if err := r.Spec.Validate(r.Project); err != nil {
		return SavedViewCommit{}, err
	}
	scope, err := s.Authorize(ctx, c, r.Org, r.Spec.Projects, Read)
	if err != nil {
		return SavedViewCommit{}, err
	}
	view := r.ID
	if create {
		view = model.NewID()
	}
	spec := r.Spec
	return s.commitSavedView(ctx, scope, r.CommandID, SavedViewCommand{Operation: SavedViewOpSave, Project: r.Project, View: view, ExpectedRevision: r.ExpectedRevision, Spec: &spec, At: model.UnixNano(s.now().UnixNano())})
}

// DeleteSavedView removes a saved view at its revision. An organization
// administrator of the organization may remove any view of its projects; any
// other caller must hold telemetry.read on the project and own the view.
func (s *Service) DeleteSavedView(ctx context.Context, c Credential, r SavedViewDelete) (SavedViewCommit, error) {
	if r.Org == (model.ID{}) || r.Project == (model.ID{}) || r.CommandID == (model.ID{}) || r.ID == (model.ID{}) || r.ExpectedRevision == 0 {
		return SavedViewCommit{}, model.Fail(model.Invalid)
	}
	scope, err := s.Authorize(ctx, c, r.Org, []model.ID{r.Project}, OrgAdmin)
	if err != nil {
		if !notFound(err) {
			return SavedViewCommit{}, err
		}
		if scope, err = s.Authorize(ctx, c, r.Org, []model.ID{r.Project}, Read); err != nil {
			return SavedViewCommit{}, err
		}
	}
	return s.commitSavedView(ctx, scope, r.CommandID, SavedViewCommand{Operation: SavedViewOpDelete, Project: r.Project, View: r.ID, ExpectedRevision: r.ExpectedRevision, At: model.UnixNano(s.now().UnixNano())})
}

func (s *Service) commitSavedView(ctx context.Context, scope Scope, id model.ID, c SavedViewCommand) (SavedViewCommit, error) {
	store, ok := s.store.(SavedViewStore)
	if !ok {
		return SavedViewCommit{}, model.Fail(model.Unsupported)
	}
	payload, err := json.Marshal(c)
	if err != nil {
		return SavedViewCommit{}, model.Fail(model.Invalid)
	}
	res, err := store.CommitSavedView(ctx, scope, model.ControlCommand{CommandID: id, Kind: SavedViewKind, Payload: payload})
	if err != nil {
		return SavedViewCommit{}, err
	}
	// The result is the command's own, first or replayed. A command ID that already
	// committed something else is not this request's answer.
	phase, revision, ok := parseSavedViewPhase(res.Phase)
	want := SavedViewPhaseUpdated
	switch {
	case c.Operation == SavedViewOpDelete:
		want = SavedViewPhaseDeleted
	case c.ExpectedRevision == 0:
		want = SavedViewPhaseCreated
	}
	if !ok || phase != want || len(res.AffectedIDs) != 1 || want != SavedViewPhaseCreated && res.AffectedIDs[0] != c.View {
		f := model.Fail(model.Conflict)
		f.SafeDetail = "command_id_reused"
		return SavedViewCommit{}, f
	}
	out := SavedViewCommit{Revision: revision}
	if c.Operation == SavedViewOpDelete {
		return out, nil
	}
	key := SavedViewKey(scope.org, c.Project, res.AffectedIDs[0])
	err = s.store.View(model.WithoutBooks(ctx), func(st model.ControlState) error {
		if err := scope.ValidateControlState(st); err != nil {
			return err
		}
		raw, found := st.SavedViewBooks[key]
		if !found {
			return nil
		}
		var v SavedView
		if json.Unmarshal(raw, &v) != nil {
			return model.Fail(model.Corrupt)
		}
		if v.Revision == revision {
			out.View = &v
		}
		return nil
	})
	return out, err
}
