// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/incidents"
	"github.com/arynyklas/soundpost/internal/issues"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/notify"
	"github.com/arynyklas/soundpost/internal/retention"
)

// This file is the C11 human-action surface of the investigation UI. It is a
// thin, scope-first handler over owned services: it dispatches by closed entity
// kind and implements no reducer of its own. Incident actions go to the C08
// incidents.Service and issue actions to the C07 issues.Service (which own
// validation, the version compare-and-set, the actor and the audit); an issue
// action with no lifecycle bound is an explicit not_available answer, never an
// empty success and never invented data.

// ActionEntity is the closed set of entities a human action may target.
type ActionEntity string

const (
	EntityIncident ActionEntity = "incident"
	EntityIssue    ActionEntity = "issue"
)

// ActionKind is the closed set of action kinds. Which kinds belong to which
// entity is fixed below; there is no generic arbitrary-JSON selector.
type ActionKind string

const (
	ActionAssign         ActionKind = "assign"
	ActionAck            ActionKind = "ack"
	ActionResolve        ActionKind = "resolve"
	ActionLink           ActionKind = "link"
	ActionImpact         ActionKind = "impact"
	ActionSnooze         ActionKind = "snooze"
	ActionUnsnooze       ActionKind = "unsnooze"
	ActionMaintenance    ActionKind = "maintenance"
	ActionMaintenanceEnd ActionKind = "maintenance_end"
	ActionIgnore         ActionKind = "ignore"
	ActionUnignore       ActionKind = "unignore"
	ActionReopen         ActionKind = "reopen"
	ActionGroupMigration ActionKind = "grouping_migration"
	ActionTitle          ActionKind = "title"
	ActionNote           ActionKind = "note"
)

var incidentKinds = map[ActionKind]incidents.Type{
	ActionAssign: incidents.TypeAssign, ActionAck: incidents.TypeAck, ActionResolve: incidents.TypeResolve,
	ActionLink: incidents.TypeLink, ActionImpact: incidents.TypeImpact, ActionSnooze: incidents.TypeSnooze,
	ActionUnsnooze: incidents.TypeUnsnooze, ActionMaintenance: incidents.TypeMaintenance, ActionMaintenanceEnd: incidents.TypeMaintenanceEnd,
	ActionTitle: incidents.TypeTitle, ActionNote: incidents.TypeNote,
}

var issueKinds = []ActionKind{ActionResolve, ActionIgnore, ActionUnignore, ActionReopen, ActionGroupMigration, ActionAssign}

// ImpactPayload is one operator-reported impact observation. Severity is
// minor|major|critical; State is firing|recovered|unknown; Freshness is
// fresh|stale|unknown. The reducer refuses a recovered observation that is not
// fresh: missing or stale data is never recovery.
type ImpactPayload struct {
	Condition model.ID `json:"condition"`
	Episode   model.ID `json:"episode"`
	Severity  string   `json:"severity"`
	State     string   `json:"state"`
	Freshness string   `json:"freshness"`
}

// ActionPayload is the closed union of everything an action may carry. A field
// the kind does not take is refused, not ignored. There is deliberately no
// actor, origin, organization or timestamp field: the actor is the validated
// session, the origin is fixed by the action kind and the time is the server's.
type ActionPayload struct {
	Reason string          `json:"reason,omitempty"`
	Owner  *model.ID       `json:"owner,omitempty"`
	Until  *model.Int64    `json:"until,omitempty"`
	Impact *ImpactPayload  `json:"impact,omitempty"`
	Link   *incidents.Link `json:"link,omitempty"`
	// ResolutionBoundary and FixedFrontier belong to the issue resolve action: the
	// explicit event-time boundary (default: the server's admission time) and the
	// releases that contain the fix.
	ResolutionBoundary *model.Int64 `json:"resolution_boundary,omitempty"`
	FixedFrontier      []model.ID   `json:"fixed_frontier,omitempty"`
	// Migration belongs to the issue grouping_migration action only.
	Migration *MigrationPayload `json:"migration,omitempty"`
	// Title belongs to the incident title action and Note to the incident note action only.
	Title string `json:"title,omitempty"`
	Note  string `json:"note,omitempty"`
}

// MigrationPayload names the issue the migration moves to and the grouping
// version and fingerprint it is under. The organization, project, source issue,
// source revision, reason and time are the request's own (scope, target,
// expected version, payload reason and the server clock): never claims here.
type MigrationPayload struct {
	ID              model.ID   `json:"id"`
	To              model.ID   `json:"to"`
	GroupingVersion uint16     `json:"grouping_version"`
	Fingerprint     model.Hash `json:"fingerprint"`
}

// ActionRequest is one human action. ProjectID and TargetID are selectors that
// authorization confirms or collapses to not-found; ExpectedVersion is the
// revision the caller saw. CommandID makes a retry return the original result.
type ActionRequest struct {
	CommandID       model.ID      `json:"command_id"`
	ExpectedVersion model.Uint64  `json:"expected_version"`
	ProjectID       model.ID      `json:"project_id"`
	TargetID        model.ID      `json:"target_id"`
	EntityKind      ActionEntity  `json:"entity_kind"`
	Kind            ActionKind    `json:"kind"`
	Payload         ActionPayload `json:"payload"`
}

// ActionState says whether the action reached its owner. not_available means no
// owning service exists in this installation; nothing was changed.
type ActionState string

const (
	ActionCommitted    ActionState = "committed"
	ActionNotAvailable ActionState = "not_available"
)

// Reason codes of the action surface: a closed vocabulary of static strings.
const (
	ReasonIssueActionsNotBuilt = "issue_control_handler_not_built"
	ReasonLifecycleNotWired    = "lifecycle_operation_store_not_wired"
)

// ActionResponse is what an action answers. A committed incident action carries
// the incident exactly as the control group committed it, a committed issue
// action the issue; the browser shows nothing as committed before this arrives.
type ActionResponse struct {
	State      ActionState      `json:"state"`
	Reason     string           `json:"reason,omitempty"`
	EntityKind ActionEntity     `json:"entity_kind"`
	Kind       ActionKind       `json:"kind"`
	TargetID   model.ID         `json:"target_id"`
	Revision   *model.Uint64    `json:"revision,omitempty"`
	Incident   *IncidentView    `json:"incident,omitempty"`
	Issue      *IssueActionView `json:"issue,omitempty"`
}

// IssueActionView is the safe projection of a committed issue: identity, workflow, the
// revision the next action must expect, the resolution boundary and the links a
// grouping migration made. It carries no occurrence evidence and no telemetry.
// Versions and times are decimal strings, never JavaScript numbers.
type IssueActionView struct {
	ID               model.ID     `json:"id"`
	Workflow         string       `json:"workflow"`
	Revision         model.Uint64 `json:"revision"`
	GroupingVersion  uint16       `json:"grouping_version"`
	ResolutionTime   *model.Int64 `json:"resolution_time_ns,omitempty"`
	FixedDescendants []model.ID   `json:"fixed_descendants,omitempty"`
	MigrationLinks   []model.ID   `json:"migration_links,omitempty"`
	// Owner is the member the issue is assigned to (omitted when none); External its links to an external tracker.
	Owner    *model.ID          `json:"owner,omitempty"`
	External []ExternalLinkView `json:"external,omitempty"`
}

// IssueConflict is a lost issue revision race (or a transition the issue's
// workflow does not allow): the issue is at Current, the action expected
// Expected. Nothing was applied and the handler never retries it.
type IssueConflict struct{ Current, Expected model.Revision }

func (c *IssueConflict) Error() string { return c.Detail() }

// Detail is the stable 409 detail: a moved revision is issue_version_conflict; an
// action the workflow state forbids at the revision the caller saw is
// issue_state_conflict.
func (c *IssueConflict) Detail() string {
	if c.Current != c.Expected {
		return "issue_version_conflict"
	}
	return "issue_state_conflict"
}

// ActionConflict is the HTTP 409 body of a lost optimistic-concurrency race: the
// incident is at CurrentVersion, not the version the action expected. The
// service never retries it as another human action; the caller decides.
type ActionConflict struct {
	Code           string       `json:"code"`
	Detail         string       `json:"detail"`
	CurrentVersion model.Uint64 `json:"current_version"`
	RequestID      string       `json:"request_id,omitempty"`
}

// ConditionView, AckView, WindowView, ImpactView, TimelineEntry and
// NotificationView are the safe projection of incidents.State. Nanosecond
// timestamps and versions are decimal strings, never JavaScript numbers.
type ConditionView struct {
	ID         model.ID    `json:"id"`
	State      string      `json:"state"`
	Freshness  string      `json:"freshness"`
	ObservedAt model.Int64 `json:"observed_at"`
}
type AckView struct {
	Actor          model.ID     `json:"actor"`
	At             model.Int64  `json:"at"`
	ImpactRevision model.Uint64 `json:"impact_revision"`
	Version        model.Uint64 `json:"version"`
	Current        bool         `json:"current"`
}
type WindowView struct {
	Actor   model.ID     `json:"actor"`
	Reason  string       `json:"reason"`
	From    model.Int64  `json:"from"`
	Until   model.Int64  `json:"until"`
	Ended   *model.Int64 `json:"ended,omitempty"`
	Version model.Uint64 `json:"version"`
	Active  bool         `json:"active"`
}
type ImpactView struct {
	Condition model.ID `json:"condition"`
	Episode   model.ID `json:"episode"`
	Severity  string   `json:"severity"`
	State     string   `json:"state"`
	Freshness string   `json:"freshness"`
}
type TimelineEntry struct {
	Version model.Uint64    `json:"version"`
	At      model.Int64     `json:"at"`
	Type    string          `json:"type"`
	Origin  string          `json:"origin"`
	Actor   model.ID        `json:"actor"`
	Reason  string          `json:"reason,omitempty"`
	Owner   *model.ID       `json:"owner,omitempty"`
	Until   *model.Int64    `json:"until,omitempty"`
	Impact  *ImpactView     `json:"impact,omitempty"`
	Link    *incidents.Link `json:"link,omitempty"`
	// Title and Note are the text of a title or note entry; External is the transition of a link to an external tracker.
	Title    string          `json:"title,omitempty"`
	Note     string          `json:"note,omitempty"`
	External *ExternalOpView `json:"external,omitempty"`
}

// NotificationView is what C08 says about notification eligibility plus what the
// durable outbox and the notification policy state hold for this incident (see
// queue_delivery.go). Reminders pause for a current ACK or an active snooze; a
// worse impact stays eligible unless an active maintenance window suppresses it.
type NotificationView struct {
	RemindersPaused     bool                `json:"reminders_paused"`
	PausedBy            string              `json:"paused_by,omitempty"`
	WorseImpactEligible bool                `json:"worse_impact_eligible"`
	SuppressedBy        string              `json:"suppressed_by,omitempty"`
	Urgency             UrgencyView         `json:"urgency"`
	Delivery            DeliverySummaryView `json:"delivery"`
	Digest              DigestView          `json:"digest"`
	Unread              UnreadView          `json:"unread_change"`
}

// IncidentView keeps the alert condition, the human incident-response status and
// the ack/snooze/maintenance scopes separate. SourceFiring says only what the
// linked condition last reported; resolving or acknowledging never changes it.
type IncidentView struct {
	ID              model.ID         `json:"incident_id"`
	Org             model.ID         `json:"org"`
	Project         model.ID         `json:"project_id"`
	Version         model.Uint64     `json:"version"`
	Status          string           `json:"status"`
	Owner           *model.ID        `json:"owner,omitempty"`
	Condition       ConditionView    `json:"condition"`
	Episode         model.ID         `json:"episode_id"`
	Severity        string           `json:"severity"`
	ImpactRevision  model.Uint64     `json:"impact_revision"`
	SourceFiring    bool             `json:"source_firing"`
	Ack             *AckView         `json:"ack,omitempty"`
	Snooze          *WindowView      `json:"snooze,omitempty"`
	Maintenance     *WindowView      `json:"maintenance,omitempty"`
	Notification    NotificationView `json:"notification"`
	Links           []incidents.Link `json:"links"`
	Previous        *model.ID        `json:"previous,omitempty"`
	ResolvedAt      *model.Int64     `json:"resolved_at,omitempty"`
	ObservedImpacts uint32           `json:"observed_impacts"`
	LastActivity    model.Int64      `json:"last_activity"`
	Timeline        []TimelineEntry  `json:"timeline,omitempty"`
	// Title is the human name of the incident ("" when none was ever set); External its links to an
	// external tracker (never the marker).
	Title    string             `json:"title"`
	External []ExternalLinkView `json:"external,omitempty"`
}

// LifecycleOperation is the scoped state of one long-running restriction,
// revocation or deletion. Phase fencing is pending (reads are denied, the
// all-group fence is not complete) and is never success; held and failed are
// not success either. Complete with Physical pending is logical deletion only:
// the physical and backup deadlines are the real ones the control group holds.
type LifecycleOperation struct {
	ID               model.ID           `json:"id"`
	Kind             string             `json:"kind,omitempty"`
	State            ViewState          `json:"state"`
	Reason           string             `json:"reason,omitempty"`
	Phase            string             `json:"phase,omitempty"`
	Physical         string             `json:"physical,omitempty"`
	Generation       model.Uint64       `json:"generation"`
	Progress         string             `json:"progress,omitempty"`
	PendingGroups    uint32             `json:"pending_groups"`
	AppliedBarriers  uint32             `json:"applied_barriers"`
	Holds            uint32             `json:"holds"`
	SafeFault        string             `json:"safe_fault,omitempty"`
	SafeReason       string             `json:"safe_reason,omitempty"`
	PhysicalDeadline model.Int64        `json:"physical_deadline"`
	BackupDeadline   model.Int64        `json:"backup_deadline"`
	OverErased       []model.OverErased `json:"over_erased,omitempty"`
	ResidualStores   []string           `json:"residual_stores,omitempty"`
}

// IncidentService is the committed C08 service as the handler consumes it;
// *incidents.Service implements it. The handler never reimplements a reducer.
type IncidentService interface {
	Act(ctx context.Context, scope auth.Scope, action incidents.Action, at model.UnixNano) (incidents.State, error)
	Get(ctx context.Context, scope auth.Scope, project, incident model.ID) (incidents.State, error)
}

// IncidentLister reads the committed incident records of one project under a
// scope; *control.Store implements it.
type IncidentLister interface {
	Incidents(ctx context.Context, scope auth.Scope, project model.ID) ([]control.IncidentRecord, error)
}

// Directory reads committed control state; *control.Store implements it. The
// handler uses it only to confirm that a proposed owner belongs to the scope's
// organization.
type Directory interface {
	View(ctx context.Context, fn func(control.State) error) error
}

// DeletionPoller is C11 PollDelete; *retention.Service implements it. A nil
// poller makes every lifecycle operation an explicit not_available answer.
type DeletionPoller interface {
	PollDelete(ctx context.Context, scope auth.Scope, operation model.ID) (retention.DeleteReceipt, error)
}

// ActionClock supplies the time active windows are judged at.
type ActionClock interface{ Now() model.UnixNano }

// IssueService is the committed C07 issue lifecycle as the handler consumes it;
// *issues.Service implements it. It owns the scope check, the revision compare
// and set, the command-ID retry and the audit; the handler maps the closed
// payload and implements no transition itself.
type IssueService interface {
	Act(ctx context.Context, scope auth.Scope, action issues.IssueAction) (issues.Issue, error)
	Get(ctx context.Context, scope auth.Scope, project, id model.ID) (issues.Issue, error)
}

// Actions is the human-action service behind POST /api/v1/actions.
type Actions struct {
	incidents IncidentService
	issues    IssueService
	lister    IncidentLister
	directory Directory
	deletions DeletionPoller
	notices   NotificationReader
	clock     ActionClock
}

// NewActions requires the incident service, lister, directory and clock; the
// deletion poller is optional (nil: lifecycle operations are not_available).
func NewActions(svc IncidentService, lister IncidentLister, directory Directory, deletions DeletionPoller, clock ActionClock) (*Actions, error) {
	if svc == nil || lister == nil || directory == nil || clock == nil {
		return nil, model.Fail(model.Invalid)
	}
	a := &Actions{incidents: svc, lister: lister, directory: directory, deletions: deletions, clock: clock}
	// The control store also holds the notification outbox and policy state; a
	// lister that cannot read them (a test double) leaves the sections explicitly
	// not_available rather than empty.
	a.notices, _ = lister.(NotificationReader)
	return a, nil
}

// BindIssues installs the issue lifecycle service that issue actions dispatch to.
// Until it is bound every issue action is an explicit not_available answer
// (ReasonIssueActionsNotBuilt); nothing changes and nothing is invented. A nil
// service unbinds it.
func (a *Actions) BindIssues(svc IssueService) { a.issues = svc }

// IssuesBound reports whether the issue lifecycle is installed (the application binds it at Open).
func (a *Actions) IssuesBound() bool { return a.issues != nil }

func invalid(detail string) error {
	f := model.Fail(model.Invalid)
	f.SafeDetail = detail
	return f
}

// decodeIncident reads one committed record's state, refusing a record whose
// state does not match its own header: a corrupt record is never skipped.
func decodeIncident(rec control.IncidentRecord) (incidents.State, error) {
	var s incidents.State
	if json.Unmarshal(rec.State, &s) != nil || s.Version != rec.Version || s.ID != rec.ID || len(s.Timeline) != int(rec.Version) {
		return incidents.State{}, model.Fail(model.Corrupt)
	}
	return s, nil
}

func validActionShape(req ActionRequest) error {
	if req.CommandID == (model.ID{}) || req.ProjectID == (model.ID{}) || req.TargetID == (model.ID{}) {
		return invalid("action_ids_required")
	}
	switch req.EntityKind {
	case EntityIncident:
		if _, ok := incidentKinds[req.Kind]; !ok {
			return invalid("action_kind_unknown")
		}
	case EntityIssue:
		if !slices.Contains(issueKinds, req.Kind) {
			return invalid("action_kind_unknown")
		}
	default:
		return invalid("action_entity_unknown")
	}
	return nil
}

// Act applies one human action under scope. The scope is the caller's own
// (derived from the credential by the route); a project outside it is the same
// not-found a missing target gives, answered before anything about the target
// is looked up. A lost version race returns *incidents.VersionConflict with the
// current version and is never retried here. Reusing a command ID returns the
// original result, not a second action.
func (a *Actions) Act(ctx context.Context, scope auth.Scope, req ActionRequest) (ActionResponse, error) {
	if err := validActionShape(req); err != nil {
		return ActionResponse{}, err
	}
	if p := scope.Permission(); p != auth.OrgAdmin && p != actionGrants(req)[0] {
		return ActionResponse{}, model.Fail(model.Forbidden)
	}
	if len(scope.ProjectIDs()) > 0 && !scope.AllowsProject(req.ProjectID) {
		return ActionResponse{}, model.Fail(model.NotFound)
	}
	switch req.EntityKind {
	case EntityIssue:
		return a.issueAct(ctx, scope, req)
	}
	action, err := a.incidentAction(ctx, scope, req)
	if err != nil {
		return ActionResponse{}, err
	}
	state, err := a.incidents.Act(ctx, scope, action, 0)
	if err != nil {
		return ActionResponse{}, err
	}
	facts, err := a.notificationFacts(ctx, scope, req.ProjectID)
	if err != nil {
		return ActionResponse{}, err
	}
	view := a.view(state, true, facts)
	return ActionResponse{State: ActionCommitted, EntityKind: req.EntityKind, Kind: req.Kind, TargetID: req.TargetID, Revision: &view.Version, Incident: &view}, nil
}

// issueAct dispatches one issue action to the C07 lifecycle service. The scope is
// the caller's own (issues.write held on the project, or the organization
// administrator's): the handler mints nothing and never widens it. With no
// service bound the answer is the explicit not_available; with one, the committed
// issue is answered exactly as the lifecycle committed it, and a lost revision
// race is an IssueConflict (HTTP 409), never retried here.
func (a *Actions) issueAct(ctx context.Context, scope auth.Scope, req ActionRequest) (ActionResponse, error) {
	if a.issues == nil {
		return ActionResponse{State: ActionNotAvailable, Reason: ReasonIssueActionsNotBuilt, EntityKind: req.EntityKind, Kind: req.Kind, TargetID: req.TargetID}, nil
	}
	action, err := a.issueAction(ctx, scope, req)
	if err != nil {
		return ActionResponse{}, err
	}
	issue, err := a.issues.Act(ctx, scope, action)
	if err != nil {
		var f *model.Fault
		if errors.As(err, &f) && f.Code == model.Conflict {
			// Say which revision the issue is at, so the caller can reread. A read that
			// fails leaves the plain conflict.
			if current, e := a.issues.Get(ctx, scope, req.ProjectID, req.TargetID); e == nil {
				return ActionResponse{}, &IssueConflict{Current: current.Revision, Expected: model.Revision(req.ExpectedVersion)}
			}
		}
		return ActionResponse{}, err
	}
	revision := model.Uint64(issue.Revision)
	view := IssueActionView{ID: issue.ID, Workflow: issue.Workflow, Revision: revision, GroupingVersion: issue.GroupingVersion, FixedDescendants: issue.FixedDescendants, MigrationLinks: issue.MigrationLinks, Owner: issue.Owner, External: externalViews(issue.External)}
	if issue.ResolutionTime != nil {
		t := model.Int64(*issue.ResolutionTime)
		view.ResolutionTime = &t
	}
	return ActionResponse{State: ActionCommitted, EntityKind: req.EntityKind, Kind: req.Kind, TargetID: req.TargetID, Revision: &revision, Issue: &view}, nil
}

// issueAction maps the closed payload to the C07 action. Fields a kind does not
// take are refused; the actor and organization are the scope's, the migration's
// source and revision are the request's and its time is the server's.
func (a *Actions) issueAction(ctx context.Context, scope auth.Scope, req ActionRequest) (issues.IssueAction, error) {
	p := req.Payload
	kind := req.Kind
	if p.Owner != nil && kind != ActionAssign || p.Until != nil || p.Impact != nil || p.Link != nil || p.Title != "" || p.Note != "" ||
		(p.ResolutionBoundary != nil || len(p.FixedFrontier) != 0) && kind != ActionResolve || p.Migration != nil != (kind == ActionGroupMigration) {
		return issues.IssueAction{}, invalid("action_payload_invalid")
	}
	out := issues.IssueAction{CommandID: req.CommandID, ExpectedVersion: model.Revision(req.ExpectedVersion), IssueID: req.TargetID, Kind: string(kind), Reason: p.Reason, FixedDescendantFrontier: slices.Clone(p.FixedFrontier)}
	if kind == ActionAssign && p.Owner != nil {
		// The owner must belong to the caller's own organization: a member or an administrator of it.
		if *p.Owner == (model.ID{}) {
			return issues.IssueAction{}, invalid("issue_owner_invalid")
		}
		if err := a.requireOrgPrincipal(ctx, scope.OrgID(), *p.Owner, "issue_owner_unknown"); err != nil {
			return issues.IssueAction{}, err
		}
		owner := *p.Owner
		out.Owner = &owner
	}
	if p.ResolutionBoundary != nil {
		out.ResolutionBoundary = model.UnixNano(*p.ResolutionBoundary)
	}
	if m := p.Migration; m != nil {
		out.Migration = &model.GroupingMigration{ID: m.ID, Org: scope.OrgID(), Project: req.ProjectID, From: req.TargetID, To: m.To, FromRevision: model.Revision(req.ExpectedVersion),
			GroupingVersion: m.GroupingVersion, Fingerprint: m.Fingerprint, Reason: p.Reason, At: a.clock.Now()}
	}
	return out, nil
}

func severityOf(name string) (incidents.Severity, bool) {
	switch name {
	case "minor":
		return incidents.SeverityMinor, true
	case "major":
		return incidents.SeverityMajor, true
	case "critical":
		return incidents.SeverityCritical, true
	}
	return 0, false
}

func severityName(s incidents.Severity) string {
	switch s {
	case incidents.SeverityMinor:
		return "minor"
	case incidents.SeverityMajor:
		return "major"
	case incidents.SeverityCritical:
		return "critical"
	}
	return "unknown"
}

// incidentAction maps the closed payload to the C08 action. Fields a kind does
// not take are refused; the actor, origin and organization are never set here
// (the incidents service takes them from the scope and the kind).
func (a *Actions) incidentAction(ctx context.Context, scope auth.Scope, req ActionRequest) (incidents.Action, error) {
	p := req.Payload
	kind := req.Kind
	if p.Owner != nil && kind != ActionAssign || p.Until != nil != (kind == ActionSnooze || kind == ActionMaintenance) ||
		p.Impact != nil != (kind == ActionImpact) || p.Link != nil != (kind == ActionLink) ||
		p.Title != "" && kind != ActionTitle || p.Note != "" && kind != ActionNote ||
		p.ResolutionBoundary != nil || len(p.FixedFrontier) != 0 || p.Migration != nil {
		return incidents.Action{}, invalid("action_payload_invalid")
	}
	out := incidents.Action{CommandID: req.CommandID, ExpectedVersion: model.Revision(req.ExpectedVersion), Type: incidentKinds[kind], Reason: p.Reason, Title: p.Title, Note: p.Note, Target: incidents.Target{Project: req.ProjectID, Incident: req.TargetID}}
	switch kind {
	case ActionAssign:
		if p.Owner != nil {
			if *p.Owner == (model.ID{}) {
				return incidents.Action{}, invalid("incident_owner_invalid")
			}
			if err := a.requireOrgPrincipal(ctx, scope.OrgID(), *p.Owner, "incident_owner_unknown"); err != nil {
				return incidents.Action{}, err
			}
			owner := *p.Owner
			out.Owner = &owner
		}
	case ActionSnooze, ActionMaintenance:
		out.Until = model.UnixNano(*p.Until)
	case ActionImpact:
		sev, ok := severityOf(p.Impact.Severity)
		if !ok {
			return incidents.Action{}, invalid("incident_action_invalid")
		}
		out.Impact = &incidents.Impact{Condition: p.Impact.Condition, Episode: p.Impact.Episode, Severity: sev, State: incidents.ConditionState(p.Impact.State), Freshness: incidents.Freshness(p.Impact.Freshness)}
	case ActionLink:
		link := *p.Link
		out.Link = &link
	}
	return out, nil
}

// requireOrgPrincipal refuses an owner who is neither a member nor an admin of
// the scope's own organization; detail is the closed token the refusal carries.
func (a *Actions) requireOrgPrincipal(ctx context.Context, org, user model.ID, detail string) error {
	return a.directory.View(ctx, func(st control.State) error {
		o, ok := st.Orgs[org.String()]
		if !ok || !(o.Members[user.String()] || o.Admins[user.String()]) {
			return invalid(detail)
		}
		return nil
	})
}

// GetIncident reads one incident under scope; a project outside the scope and a
// missing incident are the same not-found.
func (a *Actions) GetIncident(ctx context.Context, scope auth.Scope, project, incident model.ID) (IncidentView, error) {
	if project == (model.ID{}) || incident == (model.ID{}) {
		return IncidentView{}, invalid("action_ids_required")
	}
	state, err := a.incidents.Get(ctx, scope, project, incident)
	if err != nil {
		return IncidentView{}, err
	}
	if state.Erased {
		f := model.Fail(model.NotFound)
		f.SafeDetail = incidents.DetailErased
		return IncidentView{}, f
	}
	facts, err := a.notificationFacts(ctx, scope, project)
	if err != nil {
		return IncidentView{}, err
	}
	return a.view(state, true, facts), nil
}

// urgencyRank orders the queue by the canonical tier the policy computed; an
// incident no policy evaluated ranks with none.
func urgencyRank(v IncidentView) int {
	switch notify.Tier(v.Notification.Urgency.Tier) {
	case notify.TierUrgent:
		return 2
	case notify.TierQueue:
		return 1
	}
	return 0
}

func (a *Actions) view(st incidents.State, timeline bool, facts notificationFacts) IncidentView {
	now := a.clock.Now()
	v := IncidentView{
		ID: st.ID, Org: st.Org, Project: st.Project, Version: model.Uint64(st.Version), Status: string(st.Status), Owner: st.Owner, Title: st.Title, External: externalViews(st.External),
		Condition: ConditionView{ID: st.Condition.ID, State: string(st.Condition.State), Freshness: string(st.Condition.Freshness), ObservedAt: model.Int64(st.Condition.At)},
		Episode:   st.Episode, Severity: severityName(st.Severity), ImpactRevision: model.Uint64(st.ImpactRevision),
		SourceFiring: st.Condition.State == incidents.ConditionFiring, Links: st.Links, Previous: st.Previous,
	}
	if v.Links == nil {
		v.Links = []incidents.Link{}
	}
	if st.ResolvedAt != 0 {
		r := model.Int64(st.ResolvedAt)
		v.ResolvedAt = &r
	}
	if st.Ack != nil {
		v.Ack = &AckView{Actor: st.Ack.Actor, At: model.Int64(st.Ack.At), ImpactRevision: model.Uint64(st.Ack.ImpactRevision), Version: model.Uint64(st.Ack.Version), Current: st.AckCurrent()}
	}
	window := func(w *incidents.Window) *WindowView {
		if w == nil {
			return nil
		}
		out := &WindowView{Actor: w.Actor, Reason: w.Reason, From: model.Int64(w.From), Until: model.Int64(w.Until), Version: model.Uint64(w.Version), Active: w.Active(now)}
		if w.Ended != 0 {
			e := model.Int64(w.Ended)
			out.Ended = &e
		}
		return out
	}
	v.Snooze, v.Maintenance = window(st.Snooze), window(st.Maintenance)
	pausedBy := []string{}
	if st.Status == incidents.StatusOpen && st.AckCurrent() {
		pausedBy = append(pausedBy, "ack")
	}
	if st.Status == incidents.StatusOpen && st.Snooze.Active(now) {
		pausedBy = append(pausedBy, "snooze")
	}
	v.Notification = NotificationView{RemindersPaused: st.ReminderPaused(now), PausedBy: strings.Join(pausedBy, "+"), WorseImpactEligible: st.Status == incidents.StatusOpen && !st.Maintenance.Active(now)}
	facts.apply(&v)
	switch {
	case st.Status != incidents.StatusOpen:
		v.Notification.SuppressedBy = "resolved"
	case st.Maintenance.Active(now):
		v.Notification.SuppressedBy = "maintenance"
	}
	if n := len(st.Timeline); n > 0 {
		v.LastActivity = model.Int64(st.Timeline[n-1].At)
	}
	for i, e := range st.Timeline {
		if e.Action.Type == incidents.TypeOpen || e.Action.Type == incidents.TypeImpact {
			v.ObservedImpacts++
		}
		if !timeline {
			continue
		}
		te := TimelineEntry{Version: model.Uint64(i + 1), At: model.Int64(e.At), Type: string(e.Action.Type), Origin: string(e.Action.Origin), Actor: e.Action.Actor, Reason: e.Action.Reason, Owner: e.Action.Owner, Link: e.Action.Link,
			Title: e.Action.Title, Note: e.Action.Note, External: externalOpView(e.Action.External)}
		if e.Action.Until != 0 {
			u := model.Int64(e.Action.Until)
			te.Until = &u
		}
		if i := e.Action.Impact; i != nil {
			te.Impact = &ImpactView{Condition: i.Condition, Episode: i.Episode, Severity: severityName(i.Severity), State: string(i.State), Freshness: string(i.Freshness)}
		}
		v.Timeline = append(v.Timeline, te)
	}
	return v
}

// QueueRequest names the projects whose incidents make up the shared queue.
// There is no cursor: a page that is not the whole answer says so (Truncated).
type QueueRequest struct {
	Projects []model.ID `json:"projects"`
	Limit    uint32     `json:"limit"`
}

// QueueView is the shared incident queue. Every entry is a real committed
// incident with the urgency tier, delivery state, digest state and unread-change
// state the notification policy and the durable outbox hold for it (see
// queue_delivery.go); a section whose reader is not wired is not_available and
// never empty or healthy. The order is deterministic: open first, then the
// canonical urgency tier, then impact severity, then most recent activity, then ID.
type QueueView struct {
	Org       model.ID       `json:"org"`
	Projects  []model.ID     `json:"projects"`
	State     ViewState      `json:"state"`
	Reason    string         `json:"reason,omitempty"`
	Entries   []IncidentView `json:"entries"`
	Truncated bool           `json:"truncated"`
	Sections  []ViewSection  `json:"sections"`
}

// MaxQueueLimit bounds one queue page.
const MaxQueueLimit = 200

// Queue lists the committed incidents of the requested projects under scope.
func (a *Actions) Queue(ctx context.Context, scope auth.Scope, req QueueRequest) (QueueView, error) {
	if len(req.Projects) == 0 || len(req.Projects) > MaxInvestigationProjects || req.Limit == 0 || req.Limit > MaxQueueLimit {
		return QueueView{}, invalid("queue_request_invalid")
	}
	for i, p := range req.Projects {
		if p == (model.ID{}) || slices.Contains(req.Projects[:i], p) {
			return QueueView{}, invalid("queue_request_invalid")
		}
		if !scope.AllowsProject(p) {
			return QueueView{}, model.Fail(model.NotFound)
		}
	}
	var all []IncidentView
	for _, p := range req.Projects {
		records, err := a.lister.Incidents(ctx, scope, p)
		if err != nil {
			return QueueView{}, err
		}
		facts, err := a.notificationFacts(ctx, scope, p)
		if err != nil {
			return QueueView{}, err
		}
		for _, rec := range records {
			if rec.Erased() {
				continue // a deletion erased its state: nothing to queue, and not storage damage
			}
			st, err := decodeIncident(rec)
			if err != nil {
				return QueueView{}, err
			}
			all = append(all, a.view(st, false, facts))
		}
	}
	slices.SortFunc(all, func(x, y IncidentView) int {
		if (x.Status == string(incidents.StatusOpen)) != (y.Status == string(incidents.StatusOpen)) {
			if x.Status == string(incidents.StatusOpen) {
				return -1
			}
			return 1
		}
		if rx, ry := urgencyRank(x), urgencyRank(y); rx != ry {
			if rx > ry {
				return -1
			}
			return 1
		}
		if x.Severity != y.Severity {
			return -strings.Compare(severityRank(x.Severity), severityRank(y.Severity))
		}
		if x.LastActivity != y.LastActivity {
			if x.LastActivity > y.LastActivity {
				return -1
			}
			return 1
		}
		return strings.Compare(x.ID.String(), y.ID.String())
	})
	sections := []ViewSection{{Name: "incidents", State: StateReady}}
	for _, name := range []string{"urgency", "delivery", "digest", "unread_change"} {
		s := ViewSection{Name: name, State: StateReady}
		if a.notices == nil {
			s.State, s.Reason = StateNotAvailable, ReasonOutboxNotWired
		}
		sections = append(sections, s)
	}
	out := QueueView{Org: scope.OrgID(), Projects: req.Projects, Entries: []IncidentView{}, Sections: sections}
	if len(all) > int(req.Limit) {
		all, out.Truncated = all[:req.Limit], true
	}
	if len(all) == 0 {
		for i := range out.Sections {
			if out.Sections[i].State == StateReady {
				out.Sections[i].State = StateEmpty
			}
		}
		out.State = StateEmpty
		return out, nil
	}
	out.Entries = all
	if a.notices == nil {
		out.State, out.Reason = StateIncomplete, ReasonSectionsAbsent
	} else {
		out.State = StateReady
	}
	return out, nil
}

func severityRank(name string) string {
	switch name {
	case "critical":
		return "3"
	case "major":
		return "2"
	case "minor":
		return "1"
	}
	return "0"
}

// OperationOrg is the organization a lifecycle operation id belongs to
// (control.DeletionOrg), for a poller that has no ?org= selector. found is false
// for an id that names no operation. The answer is only a routing fact: the
// caller must authorize the organization before it reads the operation.
func (a *Actions) OperationOrg(ctx context.Context, operation model.ID) (org model.ID, found bool, err error) {
	err = a.directory.View(ctx, func(st control.State) error {
		org, found = control.DeletionOrg(st, operation)
		return nil
	})
	return org, found, err
}

// GetOperation polls one deletion/restriction operation under scope; another
// organization's operation and a missing one are the same not-found. With no
// poller wired the answer is an explicit not_available operation.
func (a *Actions) GetOperation(ctx context.Context, scope auth.Scope, operation model.ID) (LifecycleOperation, error) {
	if operation == (model.ID{}) {
		return LifecycleOperation{}, model.Fail(model.NotFound)
	}
	if a.deletions == nil {
		return LifecycleOperation{ID: operation, State: StateNotAvailable, Reason: ReasonLifecycleNotWired}, nil
	}
	r, err := a.deletions.PollDelete(ctx, scope, operation)
	if err != nil {
		return LifecycleOperation{}, err
	}
	recorded, total, ok := strings.Cut(r.Progress, "/")
	applied, e1 := strconv.ParseUint(recorded, 10, 32)
	slots, e2 := strconv.ParseUint(total, 10, 32)
	if !ok || e1 != nil || e2 != nil || applied > slots {
		// A progress the engine cannot state is not guessed.
		return LifecycleOperation{}, model.Fail(model.Unavailable)
	}
	switch r.Phase {
	case model.DeletePhaseFencing, model.DeletePhaseComplete, model.DeletePhaseHeld, model.DeletePhaseFailed:
	default:
		return LifecycleOperation{}, model.Fail(model.Unavailable)
	}
	return LifecycleOperation{ID: r.OperationID, Kind: r.Mode, State: StateReady, Phase: r.Phase, Physical: r.Physical, Generation: model.Uint64(r.Generation), Progress: r.Progress, PendingGroups: uint32(slots - applied), AppliedBarriers: uint32(applied),
		Holds: uint32(len(r.Holds)), SafeFault: r.SafeReason, SafeReason: r.SafeReason, PhysicalDeadline: model.Int64(r.PhysicalDeadline), BackupDeadline: model.Int64(r.BackupDeadline), OverErased: r.OverErased, ResidualStores: r.Residual}, nil
}

// ActionBody is the POST /api/v1/actions body. Org is a selector that
// authorization confirms; the permission is not a field (an action always needs
// organization admin) and neither are the actor, origin or a timestamp: the
// decoder rejects any other field.
type ActionBody struct {
	Org model.ID `json:"org"`
	ActionRequest
}

// IncidentGetBody is the POST /api/v1/incidents/get body.
type IncidentGetBody struct {
	Org       model.ID `json:"org"`
	ProjectID model.ID `json:"project_id"`
	TargetID  model.ID `json:"target_id"`
}

// QueueBody is the POST /api/v1/queue body.
type QueueBody struct {
	Org model.ID `json:"org"`
	QueueRequest
}

// readScope derives the scope an incident read runs under: telemetry.read on
// every named project, or incidents.write on every named project (a person who
// may act on an incident may read it, decision D19), or organization admin. All
// come from the caller's own credential; failing every one is the one not-found.
func readScope(ctx context.Context, s *auth.Service, c auth.Credential, org model.ID, projects []model.ID) (auth.Scope, error) {
	if org == (model.ID{}) || len(projects) == 0 {
		return auth.Scope{}, model.Fail(model.Invalid)
	}
	scope, err := s.Authorize(ctx, c, org, projects, auth.Read)
	var f *model.Fault
	if err != nil && errors.As(err, &f) && f.Code == model.NotFound {
		for _, fallback := range []auth.Permission{auth.IncidentsWrite, auth.OrgAdmin} {
			if granted, e := s.Authorize(ctx, c, org, projects, fallback); e == nil {
				return granted, nil
			}
		}
	}
	return scope, err
}

func actionReply(w http.ResponseWriter, v any, err error) {
	var conflict *incidents.VersionConflict
	if errors.As(err, &conflict) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(ActionConflict{Code: string(model.Conflict), Detail: control.IncidentVersionConflict, CurrentVersion: model.Uint64(conflict.Current), RequestID: w.Header().Get("X-Request-ID")})
		return
	}
	var issueConflict *IssueConflict
	if errors.As(err, &issueConflict) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(ActionConflict{Code: string(model.Conflict), Detail: issueConflict.Detail(), CurrentVersion: model.Uint64(issueConflict.Current), RequestID: w.Header().Get("X-Request-ID")})
		return
	}
	switch r := v.(type) {
	case ActionResponse:
		if err == nil && r.State == ActionNotAvailable {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotImplemented)
			_ = json.NewEncoder(w).Encode(r)
			return
		}
	}
	queryReply(w, v, err)
}

// RegisterActionRoutes mounts the human-action surface. Every route derives its
// scope from the caller's own credential before any service is touched; a
// session caller needs the CSRF binding (artifactCredential) on every route.
//
//	POST /api/v1/actions                       ActionBody -> ActionResponse (409 ActionConflict)
//	POST /api/v1/incidents/get                 IncidentGetBody -> IncidentView
//	POST /api/v1/queue                         QueueBody -> QueueView
//	GET  /api/v1/operations/{id}               [?org=] -> LifecycleOperation | source operation
//	GET  /api/v1/lifecycle/operations/{id}     ?org= -> LifecycleOperation (alias)
//
// GET /api/v1/operations/{id} is the one C11 polling route; it is mounted by
// RegisterOperationRoutes and answers source-policy operations in their own
// shape and, with ?org=, lifecycle operations as LifecycleOperation. The
// /lifecycle path is the older spelling of the same lifecycle answer and stays.
func RegisterActionRoutes(mux *http.ServeMux, authority *auth.Service, actions *Actions) {
	mux.HandleFunc("POST /api/v1/actions", func(w http.ResponseWriter, r *http.Request) {
		credential, err := artifactCredential(authority, w, r)
		if err != nil {
			queryReply(w, nil, err)
			return
		}
		var body ActionBody
		if err = decode(w, r, &body); err != nil {
			queryReply(w, nil, err)
			return
		}
		if body.Org == (model.ID{}) || body.ProjectID == (model.ID{}) {
			queryReply(w, nil, invalid("action_ids_required"))
			return
		}
		scope, err := authority.AuthorizeWrite(r.Context(), credential, body.Org, body.ProjectID, actionGrants(body.ActionRequest)...)
		if err != nil {
			queryReply(w, nil, err)
			return
		}
		resp, err := actions.Act(r.Context(), scope, body.ActionRequest)
		actionReply(w, resp, err)
	})
	mux.HandleFunc("POST /api/v1/incidents/get", func(w http.ResponseWriter, r *http.Request) {
		credential, err := artifactCredential(authority, w, r)
		if err != nil {
			queryReply(w, nil, err)
			return
		}
		var body IncidentGetBody
		if err = decode(w, r, &body); err != nil {
			queryReply(w, nil, err)
			return
		}
		scope, err := readScope(r.Context(), authority, credential, body.Org, []model.ID{body.ProjectID})
		if err != nil {
			queryReply(w, nil, err)
			return
		}
		view, err := actions.GetIncident(r.Context(), scope, body.ProjectID, body.TargetID)
		if err == nil {
			err = authority.Revalidate(r.Context(), scope)
		}
		queryReply(w, view, err)
	})
	mux.HandleFunc("POST /api/v1/queue", func(w http.ResponseWriter, r *http.Request) {
		credential, err := artifactCredential(authority, w, r)
		if err != nil {
			queryReply(w, nil, err)
			return
		}
		var body QueueBody
		if err = decode(w, r, &body); err != nil {
			queryReply(w, nil, err)
			return
		}
		scope, err := readScope(r.Context(), authority, credential, body.Org, body.Projects)
		if err != nil {
			queryReply(w, nil, err)
			return
		}
		view, err := actions.Queue(r.Context(), scope, body.QueueRequest)
		if err == nil {
			err = authority.Revalidate(r.Context(), scope)
		}
		queryReply(w, view, err)
	})
	mux.HandleFunc("GET /api/v1/lifecycle/operations/{id}", func(w http.ResponseWriter, r *http.Request) {
		credential, err := readCredential(authority, r)
		if err != nil {
			queryReply(w, nil, err)
			return
		}
		q := r.URL.Query()
		if !onlyKeys(q, "org") {
			queryReply(w, nil, model.Fail(model.Invalid))
			return
		}
		org, e1 := model.ParseID(q.Get("org"))
		id, e2 := model.ParseID(r.PathValue("id"))
		if e1 != nil || e2 != nil {
			queryReply(w, nil, model.Fail(model.NotFound))
			return
		}
		scope, err := authority.Authorize(r.Context(), credential, org, nil, auth.OrgAdmin)
		if err != nil {
			queryReply(w, nil, err)
			return
		}
		op, err := actions.GetOperation(r.Context(), scope, id)
		queryReply(w, op, err)
	})
}
