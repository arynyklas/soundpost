// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"soundpost/internal/auth"
	"soundpost/internal/model"
)

// This file is the C05 half of C07 issue lifecycle: the durable store of issue
// evidence, regression explanations, source checkpoints, human command records
// and declared evidence gaps. It stores leaf DTOs only: control never imports
// the issues package, and the regression explanations are opaque JSON that the
// issues adapter writes and reads back. What control owns, atomically in one
// command:
//
//   - scope: a principal that holds issues.write on exactly this project, checked
//     before the project's book or any issue is looked up, so a project the scope
//     does not name, a retired project and a missing one are indistinguishable;
//   - the project revision compare-and-set: two commits that both expect revision
//     N cannot both commit; the loser is a typed conflict that carries the
//     current revision, never merged;
//   - per-issue revisions (an issue changes only from the revision the commit
//     saw, so a concurrent grouping migration cannot be overwritten), an
//     append-only occurrence ledger, a project-wide occurrence index (one
//     occurrence, one issue) and a monotonic per-group checkpoint, all written
//     together with the evidence they cover;
//   - exactly-once commands: a retried command returns its first result and a
//     reused command ID with other content is a conflict;
//   - bounded state: every count and byte size below, refused as quota, never
//     truncated.
//
// The issues themselves are the shared model.GroupingIssue records (the ones the
// release evidence reader and the grouping migration use); the book holds
// everything else. Neither ever holds telemetry text: only IDs, hashes, counts,
// cursors, versions and the small closed enumerations of the DTOs.

// IssueCommand is the closed KindApplyIssueEvidence payload of the lifecycle
// arms. Operation selects the arm; the grouping migration arm keeps its own
// payload (model.ReleaseCommand).
//
// Command is the human command ID (or the declared gap ID) for explicit
// commands; an evidence commit leaves it nil and its command ID is derived from
// the payload (IssueCommandID), so an identical retry is recognized and any
// other content cannot reuse it.
type IssueCommand struct {
	Operation        string               `json:"operation"`
	Project          model.ID             `json:"project"`
	Command          *model.ID            `json:"command,omitempty"`
	ExpectedRevision model.Revision       `json:"expected_revision"`
	Records          []IssueRecordChange  `json:"records,omitempty"`
	Effects          []IssueEffect        `json:"effects,omitempty"`
	Audits           []model.ControlAudit `json:"audits,omitempty"`
	Checkpoint       *IssueCheckpoint     `json:"checkpoint,omitempty"`
	Action           *IssueActionRecord   `json:"action,omitempty"`
	Gap              *model.EvidenceGap   `json:"gap,omitempty"`
}

// IssueRecordChange is one changed issue with its opaque regression
// explanations (a JSON array; the whole list replaces the stored one).
type IssueRecordChange struct {
	Issue        model.GroupingIssue `json:"issue"`
	Explanations json.RawMessage     `json:"explanations,omitempty"`
}

// IssueEffect is a lifecycle intent committed with the change that caused it. It
// is an intent record (kind, IDs), not a delivery.
type IssueEffect struct {
	ID         model.ID `json:"id"`
	Kind       string   `json:"kind"`
	Issue      model.ID `json:"issue"`
	Occurrence model.ID `json:"occurrence"`
}

// IssueCheckpoint is the highest data-journal cursor of one group whose effects
// are committed with it.
type IssueCheckpoint struct {
	Group model.ID     `json:"group"`
	Index model.Uint64 `json:"index"`
}

// IssueActionRecord is the stable answer a human command ID retries to.
type IssueActionRecord struct {
	Fingerprint model.Hash `json:"fingerprint"`
	Issue       model.ID   `json:"issue"`
}

// IssueCommandEntry is one recorded explicit command: the digest of the payload
// that committed it, so a reused ID with other content is a conflict.
type IssueCommandEntry struct {
	Digest model.Hash         `json:"digest"`
	Action *IssueActionRecord `json:"action,omitempty"`
}

// IssueBook is everything control holds for one project besides the issues.
type IssueBook struct {
	Org          model.ID                     `json:"org"`
	Project      model.ID                     `json:"project"`
	Revision     model.Revision               `json:"revision"`
	Checkpoints  map[string]model.Uint64      `json:"checkpoints,omitempty"`
	Commands     map[string]IssueCommandEntry `json:"commands,omitempty"`
	Gaps         []model.EvidenceGap          `json:"gaps,omitempty"`
	Effects      []IssueEffect                `json:"effects,omitempty"`
	Explanations map[string]json.RawMessage   `json:"explanations,omitempty"`
}

// IssueSnapshot is one project's committed issue state as a private copy.
type IssueSnapshot struct {
	Revision     model.Revision
	Issues       []model.GroupingIssue
	Explanations map[model.ID]json.RawMessage
	Checkpoints  map[model.ID]model.Uint64
	Commands     map[model.ID]IssueCommandEntry
	Gaps         []model.EvidenceGap
	Effects      []IssueEffect
}

// Operations of the lifecycle arms.
const (
	issueOpCommit  = "commit"
	issueOpCollect = "collect_retired"
)

// IssueRevisionConflict is the SafeDetail prefix of a lost project revision
// race; the detail ends in " current=<revision>".
const IssueRevisionConflict = "issue_revision_conflict"

const (
	issueRecordConflict    = "issue_record_conflict"
	issueNotRetired        = "issue_project_not_retired"
	issuesWritePermission  = auth.Permission("issues.write")
	maxIssuePayload        = 4 << 20
	maxIssueRecords        = 64
	maxIssuesPerProject    = 256
	maxIssueLedger         = 1024
	maxIssueIDList         = 1024
	maxIssueLinks          = 64
	maxIssueExplanations   = 256 << 10
	maxIssueProjectBytes   = 4 << 20
	maxIssueEffectsCommand = 32
	maxIssueEffects        = 256
	maxIssueAudits         = 8
	maxIssueAuditTargets   = 64
	maxIssueCommands       = 1024
	maxIssueGaps           = 128
	maxIssueGroups         = 128
	maxIssueSignals        = 16
	maxIssueToken          = 32
	maxIssueActionName     = 64
	maxIssueReason         = 512
	maxIssueFreshness      = 32
	maxIssueDenominator    = 128
	maxIssueCursors        = 64
)

func issueBookKey(org, project model.ID) string { return org.String() + ":" + project.String() }

// IssueCommandID is the command ID of an evidence commit: a function of the
// payload bytes alone. The handler requires it, so a retry of the same commit
// is the same command and any other payload is another one.
func IssueCommandID(payload []byte) model.ID {
	h := sha256.New()
	h.Write([]byte("soundpost.issue.commit.v1"))
	h.Write(payload)
	var id model.ID
	copy(id[:], h.Sum(nil))
	return id
}

func issueRevisionConflict(current model.Revision) error {
	return ruleFault(model.Conflict, IssueRevisionConflict+" current="+strconv.FormatUint(uint64(current), 10))
}

// IssueConflictRevision returns the current project revision carried by a lost
// revision race.
func IssueConflictRevision(err error) (model.Revision, bool) {
	var f *model.Fault
	if !errors.As(err, &f) || f.Code != model.Conflict {
		return 0, false
	}
	rest, ok := strings.CutPrefix(f.SafeDetail, IssueRevisionConflict+" current=")
	if !ok {
		return 0, false
	}
	n, e := strconv.ParseUint(rest, 10, 64)
	return model.Revision(n), e == nil
}

// isIssueBookOperation reports whether the payload names a lifecycle arm; the
// release and grouping-migration payloads keep their existing dispatch.
func isIssueBookOperation(raw json.RawMessage) bool {
	var head struct {
		Operation string `json:"operation"`
	}
	if json.Unmarshal(raw, &head) != nil {
		return false
	}
	return head.Operation == issueOpCommit || head.Operation == issueOpCollect
}

func issueToken(s string, max int) bool {
	if s == "" || len(s) > max {
		return false
	}
	for _, r := range s {
		if r != '_' && (r < 'a' || r > 'z') {
			return false
		}
	}
	return true
}

func issueText(v string, max int, required bool) bool {
	if required && v == "" || len(v) > max || !utf8.ValidString(v) {
		return false
	}
	for _, r := range v {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func issueHasID(list []model.ID, id model.ID) bool {
	for _, v := range list {
		if v == id {
			return true
		}
	}
	return false
}

// issueGrantHeld mirrors the authority's grant check against the state a
// command applies to: a direct grant or an enabled team that names the principal
// and the project.
func issueGrantHeld(o model.ControlOrg, user, project model.ID, permission auth.Permission) bool {
	for _, v := range o.Grants[user.String()+":"+project.String()] {
		if v == string(permission) {
			return true
		}
	}
	for _, team := range o.Teams {
		if team.Enabled && issueHasID(team.Members, user) && issueHasID(team.Projects, project) {
			for _, v := range team.Permissions {
				if v == string(permission) {
					return true
				}
			}
		}
	}
	return false
}

// issueProjectScope admits a scope to one live project of its organization: the
// scope's own session, token and epoch are valid in this very state, the
// project is named by the scope, exists and is not retired, and the principal is
// a member holding the scope's permission there (or, for org.admin, an
// administrator). A project the scope may not touch, a retired one and a missing
// one all answer NotFound.
func issueProjectScope(scope auth.Scope, st *State, project model.ID) error {
	if err := scope.ValidateControlState(*st); err != nil {
		return err
	}
	org := scope.OrgID()
	o, ok := st.Orgs[org.String()]
	if !ok || project == (model.ID{}) {
		return model.Fail(model.NotFound)
	}
	if _, ok = o.Projects[project.String()]; !ok {
		return model.Fail(model.NotFound)
	}
	if _, retired := st.RetiredProjects[org.String()+":"+project.String()]; retired {
		return model.Fail(model.NotFound)
	}
	principal := scope.PrincipalID()
	if scope.Permission() == auth.OrgAdmin {
		if !o.Admins[principal.String()] || len(scope.ProjectIDs()) > 0 && !scope.AllowsProject(project) {
			return model.Fail(model.NotFound)
		}
		return nil
	}
	if len(scope.ProjectIDs()) == 0 || !scope.AllowsProject(project) || !o.Members[principal.String()] || !issueGrantHeld(o, principal, project, scope.Permission()) {
		return model.Fail(model.NotFound)
	}
	return nil
}

func issueWriteScope(scope auth.Scope, st *State, project model.ID) error {
	if scope.Permission() != issuesWritePermission {
		return model.Fail(model.Forbidden)
	}
	return issueProjectScope(scope, st, project)
}

func issueReadScope(scope auth.Scope, st State, project model.ID) error {
	switch scope.Permission() {
	case auth.Read, issuesWritePermission, auth.OrgAdmin:
	default:
		return model.Fail(model.Forbidden)
	}
	return issueProjectScope(scope, &st, project)
}

func loadIssueBook(st *State, org, project model.ID) (IssueBook, bool, error) {
	raw, ok := st.IssueBooks[issueBookKey(org, project)]
	if !ok {
		return IssueBook{Org: org, Project: project}, false, nil
	}
	var b IssueBook
	if err := json.Unmarshal(raw, &b); err != nil || b.Org != org || b.Project != project {
		return IssueBook{}, false, model.Fail(model.Corrupt)
	}
	return b, true, nil
}

// projectIssues returns the project's committed issues by record key.
func projectIssues(st *State, org, project model.ID) map[string]model.GroupingIssue {
	out := map[string]model.GroupingIssue{}
	for key, gi := range st.GroupingIssues {
		if gi.Org == org && gi.Project == project {
			out[key] = gi
		}
	}
	return out
}

// normalizeIssue makes empty lists nil, so a record compares and stores the same
// whether a caller sent null or an empty list.
func normalizeIssue(gi model.GroupingIssue) model.GroupingIssue {
	norm := func(list []model.GroupingEvidence) []model.GroupingEvidence {
		if len(list) == 0 {
			return nil
		}
		out := make([]model.GroupingEvidence, len(list))
		copy(out, list)
		for i := range out {
			if d := out[i].Denominator; d != nil {
				c := *d
				if len(c.Cursors) == 0 {
					c.Cursors = nil
				}
				out[i].Denominator = &c
			}
		}
		return out
	}
	ids := func(list []model.ID) []model.ID {
		if len(list) == 0 {
			return nil
		}
		return list
	}
	gi.Occurrences, gi.LateHistory = norm(gi.Occurrences), norm(gi.LateHistory)
	gi.ResolutionFrontier, gi.ObservedReleases = ids(gi.ResolutionFrontier), ids(gi.ObservedReleases)
	gi.FixedDescendants, gi.MigrationLinks = ids(gi.FixedDescendants), ids(gi.MigrationLinks)
	return gi
}

func evidencePrefix(prior, next []model.GroupingEvidence) bool {
	if len(prior) == 0 {
		return true
	}
	return len(next) >= len(prior) && reflect.DeepEqual(prior, next[:len(prior)])
}

func idPrefix(prior, next []model.ID) bool {
	if len(prior) == 0 {
		return true
	}
	return len(next) >= len(prior) && reflect.DeepEqual(prior, next[:len(prior)])
}

func validIssueEvidence(e model.GroupingEvidence, gi model.GroupingIssue) error {
	switch {
	case e.Origin.Group == (model.ID{}) || e.Origin.Index == 0, e.GroupingVersion != gi.GroupingVersion, e.Fingerprint != gi.Fingerprint,
		e.EventTime <= 0, e.ArrivalTime <= 0, !issueText(e.Freshness, maxIssueFreshness, false):
		return model.Fail(model.Invalid)
	}
	switch e.Ancestry {
	case "known":
		if e.ReleaseID == nil {
			return model.Fail(model.Invalid)
		}
	case "unknown":
	default:
		return model.Fail(model.Invalid)
	}
	if d := e.Denominator; d != nil && (!issueText(d.Name, maxIssueDenominator, true) || d.End < d.Start || len(d.Cursors) > maxIssueCursors) {
		return model.Fail(model.Invalid)
	}
	return nil
}

func validIssue(org, project model.ID, gi model.GroupingIssue) error {
	if gi.Org != org || gi.Project != project || gi.GroupingVersion == 0 || gi.Fingerprint == (model.Hash{}) || gi.Revision == 0 {
		return model.Fail(model.Invalid)
	}
	switch gi.Workflow {
	case "resolved":
		if gi.ResolutionTime == nil || *gi.ResolutionTime <= 0 {
			return model.Fail(model.Invalid)
		}
	case "open", "ignored":
		if gi.ResolutionTime != nil || len(gi.ResolutionFrontier) != 0 || len(gi.FixedDescendants) != 0 {
			return model.Fail(model.Invalid)
		}
	default:
		return model.Fail(model.Invalid)
	}
	if len(gi.Occurrences)+len(gi.LateHistory) > maxIssueLedger {
		return model.Fail(model.Quota)
	}
	if len(gi.ResolutionFrontier) > maxIssueIDList || len(gi.ObservedReleases) > maxIssueIDList || len(gi.FixedDescendants) > maxIssueLinks || len(gi.MigrationLinks) > maxIssueLinks {
		return model.Fail(model.Quota)
	}
	seen := make(map[model.ID]bool, len(gi.Occurrences)+len(gi.LateHistory))
	for _, list := range [][]model.GroupingEvidence{gi.Occurrences, gi.LateHistory} {
		for _, e := range list {
			if seen[e.OccurrenceID] {
				return model.Fail(model.Invalid)
			}
			seen[e.OccurrenceID] = true
			if err := validIssueEvidence(e, gi); err != nil {
				return err
			}
		}
	}
	return nil
}

// issueExplanations normalizes the opaque explanation list: empty means none.
func issueExplanations(raw json.RawMessage) (json.RawMessage, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil, nil
	}
	if len(trimmed) > maxIssueExplanations {
		return nil, model.Fail(model.Quota)
	}
	if !json.Valid(trimmed) || trimmed[0] != '[' {
		return nil, model.Fail(model.Invalid)
	}
	var out bytes.Buffer
	if json.Compact(&out, trimmed) != nil {
		return nil, model.Fail(model.Invalid)
	}
	if bytes.Equal(out.Bytes(), []byte("[]")) {
		return nil, nil
	}
	return json.RawMessage(out.Bytes()), nil
}

func validIssueAudit(scope auth.Scope, a model.ControlAudit) error {
	// The actor, organization and policy epoch are the validated scope's, never a
	// payload claim.
	if a.Principal != scope.PrincipalID() || a.Org != scope.OrgID().String() || a.PolicyEpoch != scope.PolicyEpoch() || a.Outcome != model.AuditAllowed {
		return model.Fail(model.Forbidden)
	}
	action, ok := strings.CutPrefix(a.Action, "issues.")
	if !ok || !issueToken(action, maxIssueActionName) || a.Time <= 0 || !issueText(a.Reason, maxIssueReason, true) || len(a.Targets) == 0 || len(a.Targets) > maxIssueAuditTargets {
		return model.Fail(model.Invalid)
	}
	return nil
}

func validIssueGap(org, project model.ID, c IssueCommand) error {
	g := c.Gap
	if g.ID == (model.ID{}) || g.Org != org || g.Project != project || g.Group == (model.ID{}) || g.Through <= g.After || g.Count == 0 || g.End < g.Start ||
		!issueText(g.Reason, maxIssueReason, true) || len(g.Signals) > maxIssueSignals || g.DeclaredBy != "" || g.Actor != nil {
		return model.Fail(model.Invalid)
	}
	// The gap commits together with the checkpoint advance over it, under the
	// gap's own ID as the command.
	if c.Checkpoint == nil || c.Checkpoint.Group != g.Group || c.Checkpoint.Index != g.Through || c.Command == nil || *c.Command != g.ID {
		return model.Fail(model.Invalid)
	}
	return nil
}

// validIssueShape checks everything that needs no committed state.
func validIssueShape(scope auth.Scope, c IssueCommand) error {
	if len(c.Records) > maxIssueRecords || len(c.Effects) > maxIssueEffectsCommand {
		return model.Fail(model.Quota)
	}
	if len(c.Audits) > maxIssueAudits {
		return model.Fail(model.Invalid)
	}
	if len(c.Records) == 0 && len(c.Effects) == 0 && len(c.Audits) == 0 && c.Checkpoint == nil && c.Gap == nil && c.Action == nil {
		return model.Fail(model.Invalid)
	}
	org := scope.OrgID()
	ids := make(map[model.ID]bool, len(c.Records))
	for _, r := range c.Records {
		if ids[r.Issue.ID] {
			return model.Fail(model.Invalid)
		}
		ids[r.Issue.ID] = true
		if err := validIssue(org, c.Project, r.Issue); err != nil {
			return err
		}
		if _, err := issueExplanations(r.Explanations); err != nil {
			return err
		}
	}
	effectIDs := make(map[model.ID]bool, len(c.Effects))
	for _, e := range c.Effects {
		if effectIDs[e.ID] || !issueToken(e.Kind, maxIssueToken) {
			return model.Fail(model.Invalid)
		}
		effectIDs[e.ID] = true
	}
	for _, a := range c.Audits {
		if err := validIssueAudit(scope, a); err != nil {
			return err
		}
	}
	if c.Checkpoint != nil && (c.Checkpoint.Group == (model.ID{}) || c.Checkpoint.Index == 0) {
		return model.Fail(model.Invalid)
	}
	if c.Action != nil && (c.Command == nil || !ids[c.Action.Issue]) {
		return model.Fail(model.Invalid)
	}
	if c.Gap != nil {
		return validIssueGap(org, c.Project, c)
	}
	return nil
}

func applyIssueBook(scope auth.Scope, st *State, cmd Command) (Effect, error) {
	if len(cmd.Payload) > maxIssuePayload {
		return Effect{}, model.Fail(model.TooLarge)
	}
	var c IssueCommand
	if err := strictPayload(cmd.Payload, &c); err != nil {
		return Effect{}, err
	}
	if c.Operation == issueOpCollect {
		return applyIssueCollect(scope, st, c)
	}
	// Scope and grants first: nothing about the project's book or issues is
	// looked up, parsed or answered for a scope that may not act in it.
	if err := issueWriteScope(scope, st, c.Project); err != nil {
		return Effect{}, err
	}
	if err := validIssueShape(scope, c); err != nil {
		return Effect{}, err
	}
	if c.Command != nil && cmd.CommandID != *c.Command || c.Command == nil && cmd.CommandID != IssueCommandID(cmd.Payload) {
		return Effect{}, model.Fail(model.Invalid)
	}
	org := scope.OrgID()
	book, _, err := loadIssueBook(st, org, c.Project)
	if err != nil {
		return Effect{}, err
	}
	if book.Revision != c.ExpectedRevision {
		return Effect{}, issueRevisionConflict(book.Revision)
	}
	issues := projectIssues(st, org, c.Project)
	explanations := make(map[string]json.RawMessage, len(book.Explanations))
	for k, v := range book.Explanations {
		explanations[k] = v
	}
	// The project-wide occurrence index of the issues this command leaves alone.
	changed := make(map[model.ID]bool, len(c.Records))
	for _, r := range c.Records {
		changed[r.Issue.ID] = true
	}
	held := map[model.ID]model.ID{}
	for _, gi := range issues {
		if changed[gi.ID] {
			continue
		}
		for _, list := range [][]model.GroupingEvidence{gi.Occurrences, gi.LateHistory} {
			for _, e := range list {
				held[e.OccurrenceID] = gi.ID
			}
		}
	}
	affected := make([]model.ID, 0, len(c.Records))
	for _, r := range c.Records {
		next := normalizeIssue(r.Issue)
		key := model.ReleaseScopeKey(org, c.Project, next.ID)
		prior, exists := issues[key]
		if exists {
			prior = normalizeIssue(prior)
			if next.Revision != prior.Revision+1 {
				return Effect{}, ruleFault(model.Conflict, issueRecordConflict)
			}
			if next.ID != prior.ID || next.GroupingVersion != prior.GroupingVersion || next.Fingerprint != prior.Fingerprint ||
				!evidencePrefix(prior.Occurrences, next.Occurrences) || !evidencePrefix(prior.LateHistory, next.LateHistory) || !idPrefix(prior.MigrationLinks, next.MigrationLinks) {
				return Effect{}, model.Fail(model.Invalid)
			}
		} else {
			if next.Revision != 1 {
				return Effect{}, ruleFault(model.Conflict, issueRecordConflict)
			}
			if len(issues) >= maxIssuesPerProject {
				return Effect{}, model.Fail(model.Quota)
			}
		}
		for _, list := range [][]model.GroupingEvidence{next.Occurrences, next.LateHistory} {
			for _, e := range list {
				if holder, taken := held[e.OccurrenceID]; taken && holder != next.ID {
					return Effect{}, ruleFault(model.Conflict, issueRecordConflict)
				}
				held[e.OccurrenceID] = next.ID
			}
		}
		issues[key] = next
		expl, err := issueExplanations(r.Explanations)
		if err != nil {
			return Effect{}, err
		}
		if expl == nil {
			delete(explanations, next.ID.String())
		} else {
			explanations[next.ID.String()] = expl
		}
		affected = append(affected, next.ID)
	}
	if len(book.Effects)+len(c.Effects) > maxIssueEffects {
		return Effect{}, model.Fail(model.Quota)
	}
	seenEffects := make(map[model.ID]bool, len(book.Effects))
	for _, e := range book.Effects {
		seenEffects[e.ID] = true
	}
	for _, e := range c.Effects {
		// An effect belongs to an issue of this project and an occurrence that issue
		// holds; its ID derives from the occurrence, so it is minted once.
		if seenEffects[e.ID] || held[e.Occurrence] != e.Issue {
			return Effect{}, model.Fail(model.Invalid)
		}
		seenEffects[e.ID] = true
	}
	book.Effects = append(book.Effects, c.Effects...)
	if c.Checkpoint != nil {
		group := c.Checkpoint.Group.String()
		current, known := book.Checkpoints[group]
		if c.Checkpoint.Index <= current {
			return Effect{}, ruleFault(model.Conflict, "issue_checkpoint_regression")
		}
		if !known && len(book.Checkpoints) >= maxIssueGroups {
			return Effect{}, model.Fail(model.Quota)
		}
		if c.Gap != nil && current != c.Gap.After {
			return Effect{}, ruleFault(model.Conflict, "issue_gap_not_at_checkpoint")
		}
		if book.Checkpoints == nil {
			book.Checkpoints = map[string]model.Uint64{}
		}
		book.Checkpoints[group] = c.Checkpoint.Index
	}
	if c.Gap != nil {
		for _, known := range book.Gaps {
			if known.ID == c.Gap.ID {
				return Effect{}, ruleFault(model.Conflict, "issue_gap_exists")
			}
		}
		if len(book.Gaps) >= maxIssueGaps {
			return Effect{}, model.Fail(model.Quota)
		}
		g := *c.Gap
		g.Signals = append([]model.Kind(nil), c.Gap.Signals...)
		book.Gaps = append(book.Gaps, g)
	}
	if c.Command != nil {
		key := c.Command.String()
		if _, exists := book.Commands[key]; exists {
			return Effect{}, ruleFault(model.Conflict, "issue_command_exists")
		}
		if len(book.Commands) >= maxIssueCommands {
			return Effect{}, model.Fail(model.Quota)
		}
		if book.Commands == nil {
			book.Commands = map[string]IssueCommandEntry{}
		}
		entry := IssueCommandEntry{Digest: model.Hash(sha256.Sum256(cmd.Payload))}
		if c.Action != nil {
			a := *c.Action
			entry.Action = &a
		}
		book.Commands[key] = entry
	}
	book.Revision++
	book.Explanations = explanations
	if len(book.Explanations) == 0 {
		book.Explanations = nil
	}
	rawBook, err := json.Marshal(book)
	if err != nil {
		return Effect{}, model.Fail(model.Invalid)
	}
	total := len(rawBook)
	for _, gi := range issues {
		raw, err := json.Marshal(gi)
		if err != nil {
			return Effect{}, model.Fail(model.Invalid)
		}
		total += len(raw)
	}
	if total > maxIssueProjectBytes {
		return Effect{}, model.Fail(model.Quota)
	}
	if st.GroupingIssues == nil {
		st.GroupingIssues = map[string]model.GroupingIssue{}
	}
	for key, gi := range issues {
		if changed[gi.ID] {
			st.GroupingIssues[key] = gi
		}
	}
	if st.IssueBooks == nil {
		st.IssueBooks = map[string]json.RawMessage{}
	}
	st.IssueBooks[issueBookKey(org, c.Project)] = rawBook
	st.Audits = append(st.Audits, c.Audits...)
	if err = eraseLateEffect(st, org, c.Project); err != nil {
		return Effect{}, err
	}
	return Effect{AffectedIDs: affected, Phase: "applied"}, nil
}

// applyIssueCollect is the collection arm: an organization administrator drops
// the payloads of a project that has been retired (deleted).
func applyIssueCollect(scope auth.Scope, st *State, c IssueCommand) (Effect, error) {
	org := scope.OrgID()
	if c.Command != nil || c.ExpectedRevision != 0 || len(c.Records)+len(c.Effects)+len(c.Audits) != 0 || c.Checkpoint != nil || c.Action != nil || c.Gap != nil {
		return Effect{}, model.Fail(model.Invalid)
	}
	if err := retiredProjectAdmin(scope, *st, org, c.Project); err != nil {
		if _, retired := st.RetiredProjects[org.String()+":"+c.Project.String()]; !retired && c.Project != (model.ID{}) && scope.Permission() == auth.OrgAdmin && st.Orgs[org.String()].Admins[scope.PrincipalID().String()] {
			return Effect{}, ruleFault(model.Conflict, issueNotRetired)
		}
		return Effect{}, err
	}
	dropped, book := DropRetiredIssueBooks(st, org, c.Project)
	if len(dropped) == 0 && !book {
		return Effect{AffectedIDs: []model.ID{}, Phase: "unchanged"}, nil
	}
	return Effect{AffectedIDs: dropped, Phase: "collected"}, nil
}

// DropRetiredIssueBooks removes every payload the issue lifecycle holds for one
// project: its issues (the evidence ledgers) and its book (explanations,
// checkpoints, command records, gaps, effect intents). It is deterministic,
// idempotent and touches only the named organization and project, so the
// retire-time hook can call it inside the retiring transaction; applyIssueCollect
// calls it for a retirement that is already committed. It returns the dropped
// issue IDs in ID order and whether a book was dropped. The retirement itself,
// the grouping migrations and the audits stay as the evidence of what happened.
func DropRetiredIssueBooks(st *State, org, project model.ID) (dropped []model.ID, book bool) {
	for key, gi := range st.GroupingIssues {
		if gi.Org == org && gi.Project == project {
			dropped = append(dropped, gi.ID)
			delete(st.GroupingIssues, key)
		}
	}
	sort.Slice(dropped, func(i, j int) bool { return bytes.Compare(dropped[i][:], dropped[j][:]) < 0 })
	key := issueBookKey(org, project)
	if _, book = st.IssueBooks[key]; book {
		delete(st.IssueBooks, key)
	}
	return dropped, book
}

// CollectRetiredIssues commits the collection of a retired project's issue
// payloads (an organization administrator's command; the project must already
// be retired) and returns the dropped issue IDs. The retire-time hook that runs
// inside the retiring transaction calls DropRetiredIssueBooks instead.
func (s *Store) CollectRetiredIssues(ctx context.Context, scope auth.Scope, project model.ID) ([]model.ID, error) {
	raw, err := json.Marshal(IssueCommand{Operation: issueOpCollect, Project: project})
	if err != nil {
		return nil, model.Fail(model.Invalid)
	}
	for range 8 {
		var revision model.Revision
		if err = s.View(ctx, func(st State) error { revision = st.Revision; return nil }); err != nil {
			return nil, err
		}
		res, err := s.Transact(ctx, scope, Command{CommandID: model.NewID(), ExpectedRevision: revision, Kind: string(KindApplyIssueEvidence), Payload: raw})
		var f *model.Fault
		if errors.As(err, &f) && f.Code == model.Conflict && f.SafeDetail != issueNotRetired {
			continue
		}
		return res.AffectedIDs, err
	}
	return nil, model.Fail(model.Conflict)
}

// TransactIssues commits one lifecycle command (operation "commit") for a scope
// that holds issues.write on the project. The generic Transact admits only
// organization administrators; the issue lifecycle is written by workers and
// reviewers that hold the narrower permission, so this entry point validates the
// scope against the very state the command applies to (session, token, epoch,
// membership and the issues.write grant) and then dispatches through the
// registered KindApplyIssueEvidence handler like Transact does. There is no
// control-wide revision to race on: the project revision is the compare-and-set
// token, so concurrent committers never fail on unrelated control changes.
//
// A command ID commits at most once; a retry returns the first result and a
// reused ID with other content is a conflict.
func (s *Store) TransactIssues(ctx context.Context, scope auth.Scope, cmd Command) (Result, error) {
	if cmd.Kind != string(KindApplyIssueEvidence) || cmd.CommandID == (model.ID{}) || !isIssueCommit(cmd.Payload) {
		return Result{}, model.Fail(model.Invalid)
	}
	if len(cmd.Payload) > maxIssuePayload {
		return Result{}, model.Fail(model.TooLarge)
	}
	if scope.Permission() != issuesWritePermission {
		return Result{}, model.Fail(model.Forbidden)
	}
	handler := s.handler(KindApplyIssueEvidence)
	if handler == nil {
		return Result{}, model.Fail(model.Unsupported)
	}
	var out Result
	err := s.updateAs(ctx, writerTransactIssues, func(st *State) error {
		binding := scope.PrincipalID().String() + ":" + scope.OrgID().String() + ":" + cmd.Kind
		if v, ok := st.Commands[cmd.CommandID.String()]; ok {
			if err := issueReplayable(scope, st, cmd, binding); err != nil {
				return err
			}
			out = v
			return nil
		}
		effect, err := handler(scope, st, cmd)
		if err != nil {
			return err
		}
		out = Result{AffectedIDs: append([]model.ID(nil), effect.AffectedIDs...), Phase: effect.Phase, Revision: st.Revision + 1, Cursor: model.Cursor{Group: st.Installation, Index: model.Uint64(st.Revision + 1)}}
		if st.CommandOwners == nil {
			st.CommandOwners = map[string]string{}
		}
		st.CommandOwners[cmd.CommandID.String()] = binding
		st.Commands[cmd.CommandID.String()] = out
		return nil
	})
	return out, err
}

func isIssueCommit(raw json.RawMessage) bool {
	var head struct {
		Operation string `json:"operation"`
	}
	return json.Unmarshal(raw, &head) == nil && head.Operation == issueOpCommit
}

// issueReplayable admits a retry of an already committed command: the scope must
// still act in the project, the command must be this principal's, and the payload
// must be the one that committed it.
func issueReplayable(scope auth.Scope, st *State, cmd Command, binding string) error {
	var head struct {
		Project model.ID  `json:"project"`
		Command *model.ID `json:"command"`
	}
	if err := scope.ValidateControlState(*st); err != nil {
		return err
	}
	if json.Unmarshal(cmd.Payload, &head) != nil {
		return model.Fail(model.Invalid)
	}
	if err := issueWriteScope(scope, st, head.Project); err != nil {
		return err
	}
	if st.CommandOwners[cmd.CommandID.String()] != binding {
		return model.Fail(model.NotFound)
	}
	if head.Command == nil {
		if cmd.CommandID != IssueCommandID(cmd.Payload) {
			return ruleFault(model.Conflict, "issue_command_reused")
		}
		return nil
	}
	book, _, err := loadIssueBook(st, scope.OrgID(), head.Project)
	if err != nil {
		return err
	}
	entry, ok := book.Commands[head.Command.String()]
	if cmd.CommandID != *head.Command || !ok || entry.Digest != model.Hash(sha256.Sum256(cmd.Payload)) {
		return ruleFault(model.Conflict, "issue_command_reused")
	}
	return nil
}

// IssueBook reads one project's committed issue state through a linearizable
// control read. The scope is checked before the project is looked up; a project
// the scope does not name, a retired one and a missing one are indistinguishable.
func (s *Store) IssueBook(ctx context.Context, scope auth.Scope, project model.ID) (out IssueSnapshot, err error) {
	err = s.View(ctx, func(st State) error {
		if e := issueReadScope(scope, st, project); e != nil {
			return e
		}
		var e error
		out, e = snapshotIssues(&st, scope.OrgID(), project)
		return e
	})
	return
}

func snapshotIssues(st *State, org, project model.ID) (IssueSnapshot, error) {
	book, _, err := loadIssueBook(st, org, project)
	if err != nil {
		return IssueSnapshot{}, err
	}
	out := IssueSnapshot{Revision: book.Revision, Explanations: map[model.ID]json.RawMessage{}, Checkpoints: map[model.ID]model.Uint64{}, Commands: map[model.ID]IssueCommandEntry{},
		Gaps: append([]model.EvidenceGap(nil), book.Gaps...), Effects: append([]IssueEffect(nil), book.Effects...)}
	for _, gi := range projectIssues(st, org, project) {
		out.Issues = append(out.Issues, gi)
	}
	sort.Slice(out.Issues, func(i, j int) bool { return bytes.Compare(out.Issues[i].ID[:], out.Issues[j].ID[:]) < 0 })
	parse := func(key string) (model.ID, error) {
		id, err := model.ParseID(key)
		if err != nil {
			return id, model.Fail(model.Corrupt)
		}
		return id, nil
	}
	for key, raw := range book.Explanations {
		id, err := parse(key)
		if err != nil {
			return IssueSnapshot{}, err
		}
		out.Explanations[id] = append(json.RawMessage(nil), raw...)
	}
	for key, index := range book.Checkpoints {
		id, err := parse(key)
		if err != nil {
			return IssueSnapshot{}, err
		}
		out.Checkpoints[id] = index
	}
	for key, entry := range book.Commands {
		id, err := parse(key)
		if err != nil {
			return IssueSnapshot{}, err
		}
		out.Commands[id] = entry
	}
	return out, nil
}
