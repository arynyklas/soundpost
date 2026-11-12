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

	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/incidents"
	"soundpost/internal/model"
	"soundpost/internal/retention"
)

// This file is the C11 human-action surface of the investigation UI. It is a
// thin, scope-first handler over owned services: it dispatches by closed entity
// kind and implements no reducer of its own. Incident actions go to the C08
// incidents.Service (which owns validation, the version compare-and-set, the
// actor and the audit); issue actions, queue delivery/digest state and nothing
// else that has no owner yet are explicit not_available answers, never an empty
// success and never invented data.

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
)

var incidentKinds = map[ActionKind]incidents.Type{
	ActionAssign: incidents.TypeAssign, ActionAck: incidents.TypeAck, ActionResolve: incidents.TypeResolve,
	ActionLink: incidents.TypeLink, ActionImpact: incidents.TypeImpact, ActionSnooze: incidents.TypeSnooze,
	ActionUnsnooze: incidents.TypeUnsnooze, ActionMaintenance: incidents.TypeMaintenance, ActionMaintenanceEnd: incidents.TypeMaintenanceEnd,
}

var issueKinds = []ActionKind{ActionResolve, ActionIgnore, ActionUnignore, ActionReopen, ActionGroupMigration}

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
	ReasonDeliveryNotBuilt     = "notification_outbox_not_built"
	ReasonDigestNotBuilt       = "digest_policy_not_built"
	ReasonUrgencyNotBuilt      = "urgency_policy_not_built"
	ReasonUnreadNotBuilt       = "unread_change_tracking_not_built"
	ReasonLifecycleNotWired    = "lifecycle_operation_store_not_wired"
)

// ActionResponse is what an action answers. A committed incident action carries
// the incident exactly as the control group committed it; the browser shows
// nothing as committed before this arrives.
type ActionResponse struct {
	State      ActionState   `json:"state"`
	Reason     string        `json:"reason,omitempty"`
	EntityKind ActionEntity  `json:"entity_kind"`
	Kind       ActionKind    `json:"kind"`
	TargetID   model.ID      `json:"target_id"`
	Revision   *model.Uint64 `json:"revision,omitempty"`
	Incident   *IncidentView `json:"incident,omitempty"`
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
}

// NotificationView is what C08 says about notification eligibility. Reminders
// pause for a current ACK or an active snooze; a worse impact stays eligible
// unless an active maintenance window suppresses it. Delivery itself is a
// separate owner (the durable outbox): while it does not exist it is reported
// not_available and no delivery outcome is invented.
type NotificationView struct {
	RemindersPaused     bool        `json:"reminders_paused"`
	PausedBy            string      `json:"paused_by,omitempty"`
	WorseImpactEligible bool        `json:"worse_impact_eligible"`
	SuppressedBy        string      `json:"suppressed_by,omitempty"`
	Delivery            ViewSection `json:"delivery"`
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
}

// LifecycleOperation is the scoped state of one long-running restriction,
// revocation or deletion. Phase fencing is pending (reads are denied, the
// all-group fence is not complete) and is never success; held and failed are
// not success either. Complete with Physical pending is logical deletion only:
// the physical and backup deadlines are the real ones the control group holds.
type LifecycleOperation struct {
	ID               model.ID     `json:"id"`
	State            ViewState    `json:"state"`
	Reason           string       `json:"reason,omitempty"`
	Phase            string       `json:"phase,omitempty"`
	Physical         string       `json:"physical,omitempty"`
	Generation       model.Uint64 `json:"generation"`
	PendingGroups    uint32       `json:"pending_groups"`
	AppliedBarriers  uint32       `json:"applied_barriers"`
	Holds            uint32       `json:"holds"`
	SafeFault        string       `json:"safe_fault,omitempty"`
	PhysicalDeadline model.Int64  `json:"physical_deadline"`
	BackupDeadline   model.Int64  `json:"backup_deadline"`
	ResidualStores   []string     `json:"residual_stores,omitempty"`
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

// Actions is the human-action service behind POST /api/v1/actions.
type Actions struct {
	incidents IncidentService
	lister    IncidentLister
	directory Directory
	deletions DeletionPoller
	clock     ActionClock
}

// NewActions requires the incident service, lister, directory and clock; the
// deletion poller is optional (nil: lifecycle operations are not_available).
func NewActions(svc IncidentService, lister IncidentLister, directory Directory, deletions DeletionPoller, clock ActionClock) (*Actions, error) {
	if svc == nil || lister == nil || directory == nil || clock == nil {
		return nil, model.Fail(model.Invalid)
	}
	return &Actions{incidents: svc, lister: lister, directory: directory, deletions: deletions, clock: clock}, nil
}

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
	if scope.Permission() != auth.OrgAdmin {
		return ActionResponse{}, model.Fail(model.Forbidden)
	}
	if len(scope.ProjectIDs()) > 0 && !scope.AllowsProject(req.ProjectID) {
		return ActionResponse{}, model.Fail(model.NotFound)
	}
	switch req.EntityKind {
	case EntityIssue:
		// internal/issues has no control handler yet: an issue action has no owner
		// that can commit it, so it is not_available, never a fake success.
		return ActionResponse{State: ActionNotAvailable, Reason: ReasonIssueActionsNotBuilt, EntityKind: req.EntityKind, Kind: req.Kind, TargetID: req.TargetID}, nil
	}
	action, err := a.incidentAction(ctx, scope, req)
	if err != nil {
		return ActionResponse{}, err
	}
	state, err := a.incidents.Act(ctx, scope, action, 0)
	if err != nil {
		return ActionResponse{}, err
	}
	view := a.view(state, true)
	return ActionResponse{State: ActionCommitted, EntityKind: req.EntityKind, Kind: req.Kind, TargetID: req.TargetID, Revision: &view.Version, Incident: &view}, nil
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
		p.Impact != nil != (kind == ActionImpact) || p.Link != nil != (kind == ActionLink) {
		return incidents.Action{}, invalid("action_payload_invalid")
	}
	out := incidents.Action{CommandID: req.CommandID, ExpectedVersion: model.Revision(req.ExpectedVersion), Type: incidentKinds[kind], Reason: p.Reason, Target: incidents.Target{Project: req.ProjectID, Incident: req.TargetID}}
	switch kind {
	case ActionAssign:
		if p.Owner != nil {
			if *p.Owner == (model.ID{}) {
				return incidents.Action{}, invalid("incident_owner_invalid")
			}
			if err := a.requireOrgPrincipal(ctx, scope.OrgID(), *p.Owner); err != nil {
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
// the scope's own organization.
func (a *Actions) requireOrgPrincipal(ctx context.Context, org, user model.ID) error {
	return a.directory.View(ctx, func(st control.State) error {
		o, ok := st.Orgs[org.String()]
		if !ok || !(o.Members[user.String()] || o.Admins[user.String()]) {
			return invalid("incident_owner_unknown")
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
	return a.view(state, true), nil
}

func (a *Actions) view(st incidents.State, timeline bool) IncidentView {
	now := a.clock.Now()
	v := IncidentView{
		ID: st.ID, Org: st.Org, Project: st.Project, Version: model.Uint64(st.Version), Status: string(st.Status), Owner: st.Owner,
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
	v.Notification = NotificationView{RemindersPaused: st.ReminderPaused(now), PausedBy: strings.Join(pausedBy, "+"), WorseImpactEligible: st.Status == incidents.StatusOpen && !st.Maintenance.Active(now),
		Delivery: ViewSection{Name: "delivery", State: StateNotAvailable, Reason: ReasonDeliveryNotBuilt}}
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
		te := TimelineEntry{Version: model.Uint64(i + 1), At: model.Int64(e.At), Type: string(e.Action.Type), Origin: string(e.Action.Origin), Actor: e.Action.Actor, Reason: e.Action.Reason, Owner: e.Action.Owner, Link: e.Action.Link}
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
// incident. The canonical urgency, delivery state, digest state and unread-change
// state belong to the notification policy and outbox, which do not exist yet:
// they are listed as not_available sections and never as empty or healthy. The
// order is deterministic (open first, then impact severity, then most recent
// activity, then ID) and is NOT the canonical urgency order.
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
		for _, rec := range records {
			if rec.Erased() {
				continue // a deletion erased its state: nothing to queue, and not storage damage
			}
			st, err := decodeIncident(rec)
			if err != nil {
				return QueueView{}, err
			}
			all = append(all, a.view(st, false))
		}
	}
	slices.SortFunc(all, func(x, y IncidentView) int {
		if (x.Status == string(incidents.StatusOpen)) != (y.Status == string(incidents.StatusOpen)) {
			if x.Status == string(incidents.StatusOpen) {
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
	out := QueueView{Org: scope.OrgID(), Projects: req.Projects, Entries: []IncidentView{}, Sections: []ViewSection{
		{Name: "incidents", State: StateReady},
		{Name: "urgency", State: StateNotAvailable, Reason: ReasonUrgencyNotBuilt},
		{Name: "delivery", State: StateNotAvailable, Reason: ReasonDeliveryNotBuilt},
		{Name: "digest", State: StateNotAvailable, Reason: ReasonDigestNotBuilt},
		{Name: "unread_change", State: StateNotAvailable, Reason: ReasonUnreadNotBuilt},
	}}
	if len(all) > int(req.Limit) {
		all, out.Truncated = all[:req.Limit], true
	}
	if len(all) == 0 {
		out.Sections[0].State = StateEmpty
		out.State = StateEmpty
		return out, nil
	}
	out.Entries = all
	out.State, out.Reason = StateIncomplete, ReasonSectionsAbsent
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
	return LifecycleOperation{ID: r.OperationID, State: StateReady, Phase: r.Phase, Physical: r.Physical, Generation: model.Uint64(r.Generation), PendingGroups: uint32(slots - applied), AppliedBarriers: uint32(applied),
		Holds: uint32(len(r.Holds)), SafeFault: r.SafeReason, PhysicalDeadline: model.Int64(r.PhysicalDeadline), BackupDeadline: model.Int64(r.BackupDeadline), ResidualStores: r.Residual}, nil
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
// every named project, or organization admin (an admin who can act on an incident
// can read it). Both come from the caller's own credential; failing both is the
// one not-found.
func readScope(ctx context.Context, s *auth.Service, c auth.Credential, org model.ID, projects []model.ID) (auth.Scope, error) {
	if org == (model.ID{}) || len(projects) == 0 {
		return auth.Scope{}, model.Fail(model.Invalid)
	}
	scope, err := s.Authorize(ctx, c, org, projects, auth.Read)
	var f *model.Fault
	if err != nil && errors.As(err, &f) && f.Code == model.NotFound {
		if admin, e := s.Authorize(ctx, c, org, projects, auth.OrgAdmin); e == nil {
			return admin, nil
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
		scope, err := authority.Authorize(r.Context(), credential, body.Org, []model.ID{body.ProjectID}, auth.OrgAdmin)
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
