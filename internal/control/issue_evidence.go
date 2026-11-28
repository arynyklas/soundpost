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

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
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
//     saw, so a concurrent grouping migration cannot be overwritten), a
//     compacting occurrence ledger (evidence only ever leaves a ledger by being
//     folded into an exact aggregate that control recomputes and verifies, see
//     issueLedgerPrefix), a project-wide occurrence index (one occurrence, one
//     issue; an aggregate's dedup tail IDs count) and a monotonic per-group
//     checkpoint, all written together with the evidence they cover;
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
	// Rev is the book revision that committed the command: the order the book
	// evicts by when it holds maxIssueCommands records.
	Rev model.Revision `json:"rev,omitempty"`
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
	// issueOpMigrate is the grouping migration (the model.ReleaseCommand
	// operation of the same name). It is not an issue-book arm: its payload keeps
	// the release command shape and applyIssueOperation dispatches it.
	issueOpMigrate = "grouping_migration"
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
	maxIssueLedger         = model.GroupingWindowMax
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
	return head.Operation == issueOpCommit || head.Operation == issueOpCollect || head.Operation == IssueOpAck
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
	return issueProjectLive(scope, model.ReadOnlyOf(st), project)
}

// issueProjectScopeRO is issueProjectScope against a read-only control state.
func issueProjectScopeRO(scope auth.Scope, ro model.ReadOnlyControl, project model.ID) error {
	if err := scope.ValidateControlStateRO(ro); err != nil {
		return err
	}
	return issueProjectLive(scope, ro, project)
}

// issueProjectLive is the part of issueProjectScope that follows the scope's validation.
func issueProjectLive(scope auth.Scope, ro model.ReadOnlyControl, project model.ID) error {
	org := scope.OrgID()
	if _, ok := ro.OrgEpoch(org.String()); !ok || project == (model.ID{}) {
		return model.Fail(model.NotFound)
	}
	if !ro.OrgHasProject(org.String(), project.String()) {
		return model.Fail(model.NotFound)
	}
	if ro.ProjectRetired(org.String(), project.String()) {
		return model.Fail(model.NotFound)
	}
	if scope.IsSystem() {
		// The runner holds its role by construction (auth.AuthorizeSystem), not by
		// membership or grant; it is still confined to the projects its scope names.
		if (len(scope.ProjectIDs()) > 0 || scope.Permission() != auth.OrgAdmin) && !scope.AllowsProject(project) {
			return model.Fail(model.NotFound)
		}
		return nil
	}
	principal := scope.PrincipalID()
	if scope.Permission() == auth.OrgAdmin {
		if !ro.OrgAdmin(org.String(), principal.String()) || len(scope.ProjectIDs()) > 0 && !scope.AllowsProject(project) {
			return model.Fail(model.NotFound)
		}
		return nil
	}
	if len(scope.ProjectIDs()) == 0 || !scope.AllowsProject(project) || !ro.OrgMember(org.String(), principal.String()) || !ro.OrgGrantHeld(org.String(), principal, project, string(scope.Permission())) {
		return model.Fail(model.NotFound)
	}
	return nil
}

// issueWriter reports whether a scope may write the issue lifecycle at all: the
// issues.write scope (a granted person, or the runner's own scope) and, as a
// person, an organization administrator (decision D20: administrators keep every
// right). The runner's org.admin scope is not a writer of this book.
func issueWriter(scope auth.Scope) bool {
	switch scope.Permission() {
	case issuesWritePermission:
		return true
	case auth.OrgAdmin:
		return !scope.IsSystem()
	}
	return false
}

func issueWriteScope(scope auth.Scope, st *State, project model.ID) error {
	if !issueWriter(scope) {
		return model.Fail(model.Forbidden)
	}
	return issueProjectScope(scope, st, project)
}

// migrationScope admits the scope to the grouping migration of a project: an
// organization administrator as before (releaseScope), or a member who holds BOTH
// issues.write and policy.write on the project (decision D20; the migration
// rewrites a project policy). The runner holds neither and is refused.
func migrationScope(scope auth.Scope, st *State, org, project model.ID) error {
	if err := scope.ValidateControlState(*st); err != nil {
		return err
	}
	if scope.Permission() != issuesWritePermission || scope.IsSystem() {
		return releaseScope(scope, st, org, project)
	}
	authority, ok := st.Orgs[org.String()]
	principal := scope.PrincipalID()
	if !ok || org == (model.ID{}) || project == (model.ID{}) || scope.OrgID() != org || len(scope.ProjectIDs()) != 1 || !scope.AllowsProject(project) || !authority.Members[principal.String()] ||
		!issueGrantHeld(authority, principal, project, issuesWritePermission) || !issueGrantHeld(authority, principal, project, auth.PolicyWrite) {
		return model.Fail(model.NotFound)
	}
	if _, ok := authority.Projects[project.String()]; !ok {
		return model.Fail(model.NotFound)
	}
	if _, retired := st.RetiredProjects[org.String()+":"+project.String()]; retired {
		return model.Fail(model.NotFound)
	}
	return nil
}

// AuthorizePolicyWrite answers, against the committed state, whether the scope's
// principal may also write the project's policy, which the grouping migration
// needs on top of issues.write (issues.PolicyAuthorizer). The scope itself is
// validated against the same state.
func (s *Store) AuthorizePolicyWrite(ctx context.Context, scope auth.Scope, project model.ID) error {
	return s.View(ctx, func(st State) error {
		if !issueWriter(scope) || scope.IsSystem() {
			return model.Fail(model.Forbidden)
		}
		return migrationScope(scope, &st, scope.OrgID(), project)
	})
}

// AuthorizeIssueWrite validates, against the committed state, that the scope may
// write the issue lifecycle of the project (issueWriteScope).
func (s *Store) AuthorizeIssueWrite(ctx context.Context, scope auth.Scope, project model.ID) error {
	return s.View(ctx, func(st State) error { return issueWriteScope(scope, &st, project) })
}

// issueReadScopeRO checks the issue read permission and the project against a read-only control state.
func issueReadScopeRO(scope auth.Scope, ro model.ReadOnlyControl, project model.ID) error {
	if err := issueReadPermission(scope); err != nil {
		return err
	}
	return issueProjectScopeRO(scope, ro, project)
}

// issueReadPermission refuses a scope whose permission is not an issue-read one.
func issueReadPermission(scope auth.Scope) error {
	switch scope.Permission() {
	case auth.Read, issuesWritePermission, auth.OrgAdmin:
		return nil
	}
	return model.Fail(model.Forbidden)
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

// loadIssueBookRO is loadIssueBook against a read-only control state; the book is decoded from a
// copy of the stored bytes.
func loadIssueBookRO(ro model.ReadOnlyControl, org, project model.ID) (IssueBook, bool, error) {
	raw, ok := ro.BookRecord(model.BookIssues, issueBookKey(org, project))
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
	gi.Compacted, gi.LateCompacted = gi.Compacted.Clone(), gi.LateCompacted.Clone()
	gi.ResolutionFrontier, gi.ObservedReleases = ids(gi.ResolutionFrontier), ids(gi.ObservedReleases)
	gi.FixedDescendants, gi.MigrationLinks = ids(gi.FixedDescendants), ids(gi.MigrationLinks)
	return gi
}

// issueLedgerPrefix is the verified fold rule for one ledger of an existing
// issue (06.02-W3). The next ledger must be the prior ledger without its first k
// entries (k >= 0), followed by whatever was appended. k is not trusted: it is the
// growth of the issue's aggregate Count, and the next aggregate must equal the
// prior aggregate with exactly prior[:k] folded in (recomputed here), so no
// evidence can leave a ledger except into an aggregate that accounts for it, and
// no aggregate can change any other way. Evidence folds the same on either side
// of a resolved issue's boundary: the aggregate keeps the first event per release,
// so what a later resolution observed at or before a boundary stays exact, and a
// hot resolved fingerprint can always make room (R01-3). It returns k.
func issueLedgerPrefix(prior, next []model.GroupingEvidence, priorFolded, nextFolded *model.GroupingCompaction) (int, error) {
	var had, now uint64
	if priorFolded != nil {
		had = uint64(priorFolded.Count)
	}
	if nextFolded != nil {
		now = uint64(nextFolded.Count)
	}
	if now < had || now-had > uint64(len(prior)) {
		return 0, model.Fail(model.Invalid)
	}
	k := int(now - had)
	kept := prior[k:]
	if len(next) < len(kept) || len(kept) > 0 && !reflect.DeepEqual(kept, next[:len(kept)]) {
		return 0, model.Fail(model.Invalid)
	}
	if !reflect.DeepEqual(priorFolded.Fold(prior[:k]), nextFolded.Clone()) {
		return 0, model.Fail(model.Invalid)
	}
	return k, nil
}

// verifyIssueCompaction applies issueLedgerPrefix to both ledgers of a changed
// issue. Folding is only a way to make room, so it never takes the window below
// the window the writers keep (model.GroupingWindowKeep): a writer cannot
// discard an issue's recent evidence by folding it.
func verifyIssueCompaction(prior, next model.GroupingIssue) error {
	kOccurrences, err := issueLedgerPrefix(prior.Occurrences, next.Occurrences, prior.Compacted, next.Compacted)
	if err != nil {
		return err
	}
	kLate, err := issueLedgerPrefix(prior.LateHistory, next.LateHistory, prior.LateCompacted, next.LateCompacted)
	if err != nil {
		return err
	}
	if kOccurrences+kLate > 0 && len(next.Occurrences)+len(next.LateHistory) < model.GroupingWindowKeep {
		return model.Fail(model.Invalid)
	}
	return nil
}

// issueHeldIDs visits every occurrence ID an issue accounts for: its window and
// the dedup tails of its folded evidence.
func issueHeldIDs(gi model.GroupingIssue, visit func(model.ID) bool) bool {
	for _, list := range [][]model.GroupingEvidence{gi.Occurrences, gi.LateHistory} {
		for _, e := range list {
			if !visit(e.OccurrenceID) {
				return false
			}
		}
	}
	for _, folded := range []*model.GroupingCompaction{gi.Compacted, gi.LateCompacted} {
		if folded == nil {
			continue
		}
		for _, id := range folded.Recent {
			if !visit(id) {
				return false
			}
		}
	}
	return true
}

// validIssueCompaction checks the shape of one aggregate (no state): a count, ordered
// bounds, a first event per release inside those bounds, a bounded unique dedup
// tail that is no longer than the count.
func validIssueCompaction(c *model.GroupingCompaction) error {
	if c == nil {
		return nil
	}
	if c.Count == 0 || c.FirstEvent <= 0 || c.LastEvent < c.FirstEvent || c.FirstArrival <= 0 || c.LastArrival < c.FirstArrival {
		return model.Fail(model.Invalid)
	}
	if len(c.Releases) > maxIssueIDList || len(c.Recent) > model.GroupingDedupTail {
		return model.Fail(model.Quota)
	}
	if uint64(len(c.Recent)) > uint64(c.Count) {
		return model.Fail(model.Invalid)
	}
	releases := make(map[model.ID]bool, len(c.Releases))
	for _, r := range c.Releases {
		if r.Release == (model.ID{}) || releases[r.Release] || r.FirstEvent < c.FirstEvent || r.FirstEvent > c.LastEvent {
			return model.Fail(model.Invalid)
		}
		releases[r.Release] = true
	}
	tail := make(map[model.ID]bool, len(c.Recent))
	for _, id := range c.Recent {
		if id == (model.ID{}) || tail[id] {
			return model.Fail(model.Invalid)
		}
		tail[id] = true
	}
	return nil
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
	if err := validIssueCompaction(gi.Compacted); err != nil {
		return err
	}
	if err := validIssueCompaction(gi.LateCompacted); err != nil {
		return err
	}
	// An occurrence ID is held once by an issue, whether in its window or in a
	// dedup tail.
	seen := make(map[model.ID]bool, len(gi.Occurrences)+len(gi.LateHistory))
	if !issueHeldIDs(gi, func(id model.ID) bool {
		if seen[id] {
			return false
		}
		seen[id] = true
		return true
	}) {
		return model.Fail(model.Invalid)
	}
	for _, list := range [][]model.GroupingEvidence{gi.Occurrences, gi.LateHistory} {
		for _, e := range list {
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
		!issueText(g.Reason, maxIssueReason, true) || len(g.Signals) > maxIssueSignals || g.DeclaredBy != "" || g.Actor != nil || g.Merged != 0 {
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

func applyIssueBook(scope auth.Scope, st *State, cmd Command, bounded bool) (Effect, error) {
	return applyIssueBookOn(scope, st, cmd, bounded, nil)
}

// applyIssueBookOn is applyIssueBook over the issues src holds: nil is the issues of the state st (the whole-state
// funnel); the sparse plan gives the records of the ledger, so that the commit reads and writes the issues it
// names and nothing else of the project.
func applyIssueBookOn(scope auth.Scope, st *State, cmd Command, bounded bool, src issueSource) (Effect, error) {
	if len(cmd.Payload) > maxIssuePayload {
		return Effect{}, model.Fail(model.TooLarge)
	}
	if issueOperationOf(cmd.Payload) == IssueOpAck {
		return applyIssueAck(scope, st, cmd)
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
	if src == nil {
		src = newStateIssues(st, org, c.Project)
	}
	explanations := make(map[string]json.RawMessage, len(book.Explanations))
	for k, v := range book.Explanations {
		explanations[k] = v
	}
	// The issues this command writes by record key. The occurrence index of the rest of the project is not built:
	// an occurrence a written issue newly accounts for is looked up in the others when it is first met (one
	// occurrence, one issue holds for what was committed before, so the ones an issue already held need no look).
	changedKeys := make(map[string]bool, len(c.Records))
	for _, r := range c.Records {
		changedKeys[model.ReleaseScopeKey(org, c.Project, r.Issue.ID)] = true
	}
	held := map[model.ID]model.ID{}
	nextIssues := make([]model.GroupingIssue, 0, len(c.Records))
	issueKeys := make([]string, 0, len(c.Records))
	created := 0
	affected := make([]model.ID, 0, len(c.Records))
	for _, r := range c.Records {
		next := normalizeIssue(r.Issue)
		key := model.ReleaseScopeKey(org, c.Project, next.ID)
		prior, exists, err := src.get(key)
		if err != nil {
			return Effect{}, err
		}
		var had map[model.ID]bool
		if exists {
			prior = normalizeIssue(prior)
			if next.Revision != prior.Revision+1 {
				return Effect{}, ruleFault(model.Conflict, issueRecordConflict)
			}
			if next.ID != prior.ID || next.GroupingVersion != prior.GroupingVersion || next.Fingerprint != prior.Fingerprint || !idPrefix(prior.MigrationLinks, next.MigrationLinks) {
				return Effect{}, model.Fail(model.Invalid)
			}
			if err := verifyIssueCompaction(prior, next); err != nil {
				return Effect{}, err
			}
			had = map[model.ID]bool{}
			issueHeldIDs(prior, func(id model.ID) bool {
				had[id] = true
				return true
			})
		} else {
			if next.Revision != 1 {
				return Effect{}, ruleFault(model.Conflict, issueRecordConflict)
			}
			// A new issue has folded nothing: an aggregate with no prior to fold from
			// cannot be accounted for.
			if next.Compacted != nil || next.LateCompacted != nil {
				return Effect{}, model.Fail(model.Invalid)
			}
			n, err := src.size()
			if err != nil {
				return Effect{}, err
			}
			if n+created >= maxIssuesPerProject {
				return Effect{}, model.Fail(model.Quota)
			}
			created++
		}
		var lookup error
		conflict := !issueHeldIDs(next, func(id model.ID) bool {
			if holder, taken := held[id]; taken {
				return holder == next.ID
			}
			if !had[id] {
				other, found, err := src.holder(id, changedKeys)
				if err != nil {
					lookup = err
					return false
				}
				if found && other != next.ID {
					return false
				}
			}
			held[id] = next.ID
			return true
		})
		if lookup != nil {
			return Effect{}, lookup
		}
		if conflict {
			return Effect{}, ruleFault(model.Conflict, issueRecordConflict)
		}
		nextIssues = append(nextIssues, next)
		issueKeys = append(issueKeys, key)
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
	// holds says whether the issue accounts for the occurrence: a written issue by what this command gave it, any
	// other by its record (read when an effect names it).
	holds := func(issue, occurrence model.ID) (bool, error) {
		if holder, ok := held[occurrence]; ok {
			return holder == issue, nil
		}
		key := model.ReleaseScopeKey(org, c.Project, issue)
		if changedKeys[key] {
			return false, nil
		}
		gi, ok, err := src.get(key)
		if err != nil || !ok {
			return false, err
		}
		found := false
		issueHeldIDs(gi, func(id model.ID) bool {
			found = id == occurrence
			return !found
		})
		return found, nil
	}
	for _, e := range c.Effects {
		// An effect belongs to an issue of this project and an occurrence that issue
		// holds; its ID derives from the occurrence, so it is minted once.
		ok, err := holds(e.Issue, e.Occurrence)
		if err != nil {
			return Effect{}, err
		}
		if seenEffects[e.ID] || !ok {
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
		g := *c.Gap
		g.Signals = append([]model.Kind(nil), c.Gap.Signals...)
		gaps, err := appendIssueGap(book.Gaps, g, bounded)
		if err != nil {
			return Effect{}, err
		}
		book.Gaps = gaps
	}
	if c.Command != nil {
		key := c.Command.String()
		if _, exists := book.Commands[key]; exists {
			return Effect{}, ruleFault(model.Conflict, "issue_command_exists")
		}
		if len(book.Commands) >= maxIssueCommands {
			if !bounded {
				return Effect{}, model.Fail(model.Quota)
			}
			evictOldestIssueCommand(book.Commands)
		}
		if book.Commands == nil {
			book.Commands = map[string]IssueCommandEntry{}
		}
		entry := IssueCommandEntry{Digest: model.Hash(sha256.Sum256(cmd.Payload))}
		if bounded {
			entry.Rev = book.Revision + 1
		}
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
	raws := make([][]byte, len(nextIssues))
	for i, gi := range nextIssues {
		raw, err := marshalIssue(gi)
		if err != nil {
			return Effect{}, model.Fail(model.Invalid)
		}
		raws[i] = raw
		total += len(raw)
	}
	rest, err := src.otherBytes(changedKeys)
	if err != nil {
		return Effect{}, err
	}
	if total+rest > maxIssueProjectBytes {
		return Effect{}, model.Fail(model.Quota)
	}
	for i, gi := range nextIssues {
		src.put(issueKeys[i], gi, raws[i])
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
		revision, err := s.Revision(ctx)
		if err != nil {
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

// TransactIssues commits one lifecycle command (operation "commit", or the
// grouping migration) for a scope that holds issues.write on the project, or for
// an organization administrator acting as a person (decision D20). The generic
// Transact admits only organization administrators; the issue lifecycle is
// written by workers and people that hold the narrower permission, so this entry
// point validates the scope against the very state the command applies to
// (session, token, epoch, membership and the issues.write grant, and for the
// migration also policy.write) and then dispatches through the registered
// KindApplyIssueEvidence handler like Transact does. There is no control-wide
// revision to race on: the project revision is the compare-and-set token, so
// concurrent committers never fail on unrelated control changes.
//
// A command ID commits at most once; a retry returns the first result and a
// reused ID with other content is a conflict.
func (s *Store) TransactIssues(ctx context.Context, scope auth.Scope, cmd Command) (Result, error) {
	operation := issueOperationOf(cmd.Payload)
	if cmd.Kind != string(KindApplyIssueEvidence) || cmd.CommandID == (model.ID{}) || operation != issueOpCommit && operation != issueOpMigrate && operation != IssueOpAck {
		return Result{}, model.Fail(model.Invalid)
	}
	if len(cmd.Payload) > maxIssuePayload {
		return Result{}, model.Fail(model.TooLarge)
	}
	if !issueWriter(scope) {
		return Result{}, model.Fail(model.Forbidden)
	}
	handler := s.handler(KindApplyIssueEvidence)
	if handler == nil {
		return Result{}, model.Fail(model.Unsupported)
	}
	var out Result
	bounded := s.BoundedRules()
	// A lifecycle commit writes the project's issue book, the issues it changed and the command's record:
	// those are committed as the records they are, without the whole state (sparse.go). The grouping
	// migration, a project a finished deletion covers and anything the plan cannot judge go through the
	// whole-state funnel.
	handled, err := s.sparseUpdate(ctx, func(core *State, l *ledgerTx) ([]patchOp, error) {
		return planIssueCommit(scope, cmd, operation, bounded, core, l, &out)
	})
	if handled {
		return out, err
	}
	err = s.updateAs(withCommandKey(retryLostProposals(ctx), cmd.CommandID.String()), writerTransactIssues, func(st *State) error {
		binding := scope.PrincipalID().String() + ":" + scope.OrgID().String() + ":" + cmd.Kind
		if v, ok := st.Commands[cmd.CommandID.String()]; ok {
			replay := issueReplayable
			if operation == issueOpMigrate {
				replay = migrationReplayable
			}
			if err := replay(scope, st, cmd, binding); err != nil {
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

// planIssueCommit is the plan of TransactIssues for a lifecycle commit or acknowledgement: the handler runs
// on a state that holds the project's issue book and issues and nothing the command writes besides, and what
// it left is written as records: the book, the issues that changed, the audit rows it appended and the
// command's own record.
func planIssueCommit(scope auth.Scope, cmd Command, operation string, bounded bool, core *State, l *ledgerTx, out *Result) ([]patchOp, error) {
	var head struct {
		Project model.ID `json:"project"`
	}
	if operation == issueOpMigrate || json.Unmarshal(cmd.Payload, &head) != nil {
		return nil, errSparseFallback
	}
	org := scope.OrgID()
	if lateErasureMayApply(core, org, head.Project) {
		return nil, errSparseFallback
	}
	key := issueBookKey(org, head.Project)
	before := l.t[tableIssueBooks].Get([]byte(key))
	ov := *core
	ov.IssueBooks = map[string]json.RawMessage{}
	if before != nil {
		ov.IssueBooks[key] = before
	}
	ov.Audits = nil
	// The plan reads the issues the command names (src decodes each of them once) and holds the others as the
	// records they are: what it needs of those is a count, their size and whether one of them holds an
	// occurrence, none of which decodes or encodes them (issueSource).
	src := newLedgerIssues(l, org, head.Project)
	ov.GroupingIssues = nil
	binding := scope.PrincipalID().String() + ":" + scope.OrgID().String() + ":" + cmd.Kind
	id := cmd.CommandID.String()
	if recorded := l.t[tableCommands].Get([]byte(id)); recorded != nil {
		var v Result
		if json.Unmarshal(recorded, &v) != nil {
			return nil, model.Fail(model.Corrupt)
		}
		ov.Commands = map[string]Result{id: v}
		ov.CommandOwners = map[string]string{id: string(l.t[tableCommandOwners].Get([]byte(id)))}
		replay := issueReplayable
		if err := replay(scope, &ov, cmd, binding); err != nil {
			return nil, err
		}
		*out = v
		return nil, nil
	}
	effect, err := applyIssueBookOn(scope, &ov, cmd, bounded, src)
	if err != nil {
		return nil, err
	}
	*out = Result{AffectedIDs: append([]model.ID(nil), effect.AffectedIDs...), Phase: effect.Phase, Revision: core.Revision + 1, Cursor: model.Cursor{Group: core.Installation, Index: model.Uint64(core.Revision + 1)}}
	var ops []patchOp
	if after, ok := ov.IssueBooks[key]; ok && !bytes.Equal(before, after) {
		ops = append(ops, patchOp{Op: opSet, Path: []string{"IssueBooks", key}, Value: after})
	} else if !ok && before != nil {
		return nil, errSparseFallback
	}
	written := make([]string, 0, len(src.written))
	for k := range src.written {
		written = append(written, k)
	}
	sort.Strings(written)
	for _, k := range written {
		raw := src.written[k]
		if prev, ok := src.prior[k]; ok && bytes.Equal(prev, raw) {
			continue
		}
		ops = append(ops, patchOp{Op: opSet, Path: []string{"GroupingIssues", k}, Value: raw})
	}
	result, err := json.Marshal(*out)
	if err != nil {
		return nil, model.Fail(model.Invalid)
	}
	owner, err := json.Marshal(binding)
	if err != nil {
		return nil, model.Fail(model.Invalid)
	}
	ops = append(ops, patchOp{Op: opSet, Path: []string{"Commands", id}, Value: result}, patchOp{Op: opSet, Path: []string{"CommandOwners", id}, Value: owner})
	if len(ov.Audits) != 0 {
		raw, err := json.Marshal(ov.Audits)
		if err != nil {
			return nil, model.Fail(model.Invalid)
		}
		if len(core.Audits) == 0 {
			ops = append(ops, patchOp{Op: opSet, Path: []string{"Audits"}, Value: raw})
		} else {
			ops = append(ops, patchOp{Op: opArray, Path: []string{"Audits"}, Value: raw})
		}
	}
	return ops, nil
}

// issueOperationOf is the operation named by a KindApplyIssueEvidence payload.
func issueOperationOf(raw json.RawMessage) string {
	var head struct {
		Operation string `json:"operation"`
	}
	if json.Unmarshal(raw, &head) != nil {
		return ""
	}
	return head.Operation
}

// migrationReplayable is issueReplayable for the grouping migration: the scope
// must still be admitted to the migrated project and the command must be this
// principal's. The migration payload names its project inside the migration.
func migrationReplayable(scope auth.Scope, st *State, cmd Command, binding string) error {
	var c model.ReleaseCommand
	if json.Unmarshal(cmd.Payload, &c) != nil || c.Migration == nil {
		return model.Fail(model.Invalid)
	}
	if err := migrationScope(scope, st, c.Migration.Org, c.Migration.Project); err != nil {
		return err
	}
	if st.CommandOwners[cmd.CommandID.String()] != binding {
		return model.Fail(model.NotFound)
	}
	return nil
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
	err = s.ViewShared(ctx, func(st model.ReadOnlyControl) error {
		if e := issueReadScopeRO(scope, st, project); e != nil {
			return e
		}
		var e error
		out, e = snapshotIssuesRO(st, scope.OrgID(), project)
		return e
	})
	return
}

// snapshotIssuesRO reads the project's issue book from a read-only control state; everything in the
// snapshot is a copy.
func snapshotIssuesRO(ro model.ReadOnlyControl, org, project model.ID) (IssueSnapshot, error) {
	book, _, err := loadIssueBookRO(ro, org, project)
	if err != nil {
		return IssueSnapshot{}, err
	}
	out := IssueSnapshot{Revision: book.Revision, Explanations: map[model.ID]json.RawMessage{}, Checkpoints: map[model.ID]model.Uint64{}, Commands: map[model.ID]IssueCommandEntry{},
		Gaps: append([]model.EvidenceGap(nil), book.Gaps...), Effects: append([]IssueEffect(nil), book.Effects...)}
	for _, entry := range ro.ProjectIssues(org, project) {
		out.Issues = append(out.Issues, entry.Issue)
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
