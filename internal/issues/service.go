// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package issues

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"sort"
	"soundpost/internal/auth"
	"soundpost/internal/model"
	"soundpost/internal/releases"
	"unicode"
	"unicode/utf8"
)

// The seams below are consumer-owned. Composition binds the control store (C05)
// and the existing authorities; nothing here owns a database or a global.

// Store is the durable lifecycle ledger for one org/project. Load returns a
// private snapshot; Commit applies every part of a Commit atomically under an
// optimistic revision and returns a Conflict fault when the revision moved.
type Store interface {
	Load(context.Context, auth.Scope, model.ID) (State, error)
	Commit(context.Context, auth.Scope, model.ID, Commit) error
}

// Authorizer revalidates a scope against current authority (policy epoch,
// session, grants). auth.Service satisfies it.
type Authorizer interface {
	Revalidate(context.Context, auth.Scope) error
}

// GraphSource returns the immutable release graph of one project for a scope
// that holds issues.write there.
type GraphSource interface {
	Graph(context.Context, auth.Scope, model.ID) (releases.Graph, error)
}

// Fence is the privacy/deletion/closing gate. It must deny a project whose
// deletion or closing saga has begun, before any state is read or released.
type Fence interface {
	Admit(context.Context, auth.Scope, model.ID) error
}

// PolicyAuthorizer answers whether the principal also holds project
// policy.write, which grouping migration needs on top of issues.write (a scope
// carries a single permission).
type PolicyAuthorizer interface {
	AuthorizePolicyWrite(context.Context, auth.Scope, model.ID) error
}

// Migrator performs the audited grouping migration (06.01). The migration is
// never run by the lifecycle reducer.
type Migrator interface {
	MigrateGrouping(context.Context, auth.Scope, model.GroupingMigration, model.ID) error
}

// Clock supplies action admission time outside deterministic reduction.
type Clock interface{ Now() model.UnixNano }

// State is one project's committed lifecycle state.
type State struct {
	Revision model.Revision
	Issues   map[model.ID]Record
	// Occurrences maps every deduplicated occurrence ID to the issue holding it.
	Occurrences map[model.ID]model.ID
	// Checkpoints is the per data group processed cursor.
	Checkpoints map[model.ID]model.Uint64
	// Commands maps a human command ID to its recorded fingerprint, giving
	// retries a stable answer.
	Commands map[model.ID]CommandRecord
	Gaps     []model.EvidenceGap
}

// Record is an issue with the facts needed to explain its lifecycle.
type Record struct {
	Issue Issue
	// Explanations are the regression evaluations since the last resolution
	// (and before it, for history), oldest first.
	Explanations []Explanation
}

// Explanation is the stored, reconstructible record of one post-boundary
// regression evaluation: the decision, the thresholds used and the outcome.
type Explanation struct {
	OccurrenceID    model.ID
	EvidenceRelease model.ID
	EventTime       model.UnixNano
	Decision        RegressionDecision
	// ResolutionTime is the explicit boundary of the resolution evaluated.
	ResolutionTime model.UnixNano
	// Threshold and Window are the policy used; Qualifying counts the
	// eligible occurrences (including this one) inside the window.
	Threshold  uint32
	Window     model.UnixNano
	Qualifying int
	Reopened   bool
}

type CommandRecord struct {
	Fingerprint [32]byte
	IssueID     model.ID
}

// Effect is a lifecycle intent committed with the change that caused it. Its
// ID derives from the occurrence, so no retry can mint a second one.
type Effect struct {
	ID           model.ID
	Kind         string
	IssueID      model.ID
	OccurrenceID model.ID
}

// Commit is everything one C05 transaction applies: changed issues, the
// occurrence index, effects, audits, the source checkpoint, a human command
// record or a declared gap.
type Commit struct {
	CommandID        model.ID
	ExpectedRevision model.Revision
	Records          []Record
	Occurrences      map[model.ID]model.ID
	Effects          []Effect
	Audits           []model.ControlAudit
	Checkpoint       *Checkpoint
	Command          *CommandRecord
	Gap              *model.EvidenceGap
}

// IssueAction is a typed human action. Actor and org come from the scope.
type IssueAction struct {
	CommandID       model.ID
	ExpectedVersion model.Revision
	IssueID         model.ID
	// Kind is resolve|ignore|unignore|reopen|grouping_migration.
	Kind   string
	Reason string
	// ResolutionBoundary is the explicit resolution event-time boundary;
	// zero means the admission time. Only for resolve.
	ResolutionBoundary model.UnixNano
	// FixedDescendantFrontier optionally names the releases that contain the
	// fix. Only for resolve.
	FixedDescendantFrontier []model.ID
	// Migration carries the grouping migration for kind grouping_migration.
	Migration *model.GroupingMigration
}

// RegressionPolicy is the recorded threshold/window an issue reopens by:
// MinOccurrences qualifying occurrences within Window event-time nanoseconds
// (Window 0 is unbounded). A zero MinOccurrences means one.
type RegressionPolicy struct {
	MinOccurrences uint32
	Window         model.UnixNano
}

type Deps struct {
	Store      Store
	Authorizer Authorizer
	Graphs     GraphSource
	Fence      Fence
	Policy     PolicyAuthorizer
	// Migrator may be nil; grouping_migration is then unsupported.
	Migrator   Migrator
	Clock      Clock
	Regression RegressionPolicy
}

type Service struct{ d Deps }

const (
	issuesWrite = auth.Permission("issues.write")
	maxAttempts = 4
)

func New(d Deps) (*Service, error) {
	if d.Store == nil || d.Authorizer == nil || d.Graphs == nil || d.Fence == nil || d.Policy == nil || d.Clock == nil {
		return nil, model.Fail(model.Invalid)
	}
	if d.Regression.MinOccurrences == 0 {
		d.Regression.MinOccurrences = 1
	}
	if d.Regression.Window < 0 {
		return nil, model.Fail(model.Invalid)
	}
	return &Service{d: d}, nil
}

func allowsProject(scope auth.Scope, project model.ID) bool {
	return len(scope.ProjectIDs()) > 0 && scope.AllowsProject(project)
}

// authorize revalidates the scope, requires the permission, confines it to the
// project and consults the deletion fence, in that order, before any read.
func (s *Service) authorize(ctx context.Context, scope auth.Scope, permission auth.Permission, project model.ID) error {
	if e := s.d.Authorizer.Revalidate(ctx, scope); e != nil {
		return e
	}
	if scope.Permission() != permission && !(permission == auth.Read && scope.Permission() == issuesWrite) {
		return model.Fail(model.Forbidden)
	}
	if !allowsProject(scope, project) {
		return model.Fail(model.NotFound)
	}
	return s.d.Fence.Admit(ctx, scope, project)
}
func (s *Service) read(ctx context.Context, scope auth.Scope, project model.ID) (State, error) {
	if e := s.d.Authorizer.Revalidate(ctx, scope); e != nil {
		return State{}, e
	}
	if p := scope.Permission(); p != auth.Read && p != issuesWrite {
		return State{}, model.Fail(model.Forbidden)
	}
	if !allowsProject(scope, project) {
		return State{}, model.Fail(model.NotFound)
	}
	if e := s.d.Fence.Admit(ctx, scope, project); e != nil {
		return State{}, e
	}
	return s.d.Store.Load(ctx, scope, project)
}

func safeText(v string) bool {
	if v == "" || len(v) > 512 || !utf8.ValidString(v) {
		return false
	}
	for _, r := range v {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func validateEvidence(e Evidence) error {
	if e.OccurrenceID == (model.ID{}) || e.RecordID == (model.ID{}) || e.Origin.Group == (model.ID{}) || e.Origin.Index == 0 ||
		e.GroupingVersion == 0 || e.Fingerprint == (model.Hash{}) || e.EventTime <= 0 || e.ArrivalTime <= 0 || len(e.Freshness) > 32 {
		return model.Fail(model.Invalid)
	}
	switch e.Ancestry {
	case "known":
		if e.ReleaseID == nil || *e.ReleaseID == (model.ID{}) {
			return model.Fail(model.Invalid)
		}
	case "unknown":
		if e.ReleaseID != nil && *e.ReleaseID == (model.ID{}) {
			return model.Fail(model.Invalid)
		}
	default:
		return model.Fail(model.Invalid)
	}
	if e.BuildID != nil && *e.BuildID == (model.ID{}) || e.ProducerEpoch != nil && *e.ProducerEpoch == (model.ID{}) {
		return model.Fail(model.Invalid)
	}
	if d := e.Denominator; d != nil && (d.Name == "" || len(d.Name) > 128 || d.End < d.Start) {
		return model.Fail(model.Invalid)
	}
	return nil
}

// sameOccurrence reports whether two evidence values are the same durable
// occurrence. Arrival time is deliberately excluded: the first arrival is the
// receipt and a retry never rewrites it.
func sameOccurrence(a, b Evidence) bool {
	return a.OccurrenceID == b.OccurrenceID && a.RecordID == b.RecordID && a.Origin == b.Origin &&
		a.GroupingVersion == b.GroupingVersion && a.Fingerprint == b.Fingerprint && a.EventTime == b.EventTime
}

func cloneEvidence(e Evidence) Evidence {
	if e.BuildID != nil {
		v := *e.BuildID
		e.BuildID = &v
	}
	if e.ReleaseID != nil {
		v := *e.ReleaseID
		e.ReleaseID = &v
	}
	if e.ProducerEpoch != nil {
		v := *e.ProducerEpoch
		e.ProducerEpoch = &v
	}
	if e.Denominator != nil {
		v := *e.Denominator
		v.Cursors = append([]model.Cursor(nil), v.Cursors...)
		e.Denominator = &v
	}
	return e
}
func cloneEvidences(in []Evidence) []Evidence {
	out := make([]Evidence, len(in))
	for i := range in {
		out[i] = cloneEvidence(in[i])
	}
	return out
}
func cloneIssue(i Issue) Issue {
	i.Occurrences = cloneEvidences(i.Occurrences)
	i.LateHistory = cloneEvidences(i.LateHistory)
	i.ResolutionFrontier = append([]model.ID(nil), i.ResolutionFrontier...)
	i.ObservedReleases = append([]model.ID(nil), i.ObservedReleases...)
	i.FixedDescendants = append([]model.ID(nil), i.FixedDescendants...)
	i.MigrationLinks = append([]model.ID(nil), i.MigrationLinks...)
	if i.ResolutionTime != nil {
		v := *i.ResolutionTime
		i.ResolutionTime = &v
	}
	return i
}
func cloneRecord(r Record) Record {
	r.Issue = cloneIssue(r.Issue)
	r.Explanations = append([]Explanation(nil), r.Explanations...)
	for i := range r.Explanations {
		r.Explanations[i].Decision.Frontier = append([]model.ID(nil), r.Explanations[i].Decision.Frontier...)
	}
	return r
}

// issueID is the deterministic identity of an issue created by the lifecycle
// reducer: the same scope, grouping version and fingerprint always name the
// same issue, whichever worker observes it first.
func issueID(org, project model.ID, version uint16, fingerprint model.Hash) model.ID {
	h := sha256.New()
	h.Write([]byte("soundpost.issue.v1"))
	h.Write(org[:])
	h.Write(project[:])
	var v [2]byte
	binary.BigEndian.PutUint16(v[:], version)
	h.Write(v[:])
	h.Write(fingerprint[:])
	var id model.ID
	copy(id[:], h.Sum(nil))
	return id
}
func effectID(kind string, occurrence model.ID) model.ID {
	h := sha256.New()
	h.Write([]byte("soundpost.issue.effect.v1"))
	h.Write([]byte(kind))
	h.Write(occurrence[:])
	var id model.ID
	copy(id[:], h.Sum(nil))
	return id
}

type route struct {
	version     uint16
	fingerprint model.Hash
}

func routes(state State) map[route]model.ID {
	out := map[route]model.ID{}
	for id, r := range state.Issues {
		k := route{r.Issue.GroupingVersion, r.Issue.Fingerprint}
		if cur, ok := out[k]; !ok || lessID(id, cur) {
			out[k] = id
		}
	}
	return out
}
func lessID(a, b model.ID) bool { return string(a[:]) < string(b[:]) }

// Summary is recomputed from the immutable ledger, never stored: counts and
// first/last seen follow event time, and receipt (arrival) times are reported
// as recorded.
type Summary struct {
	Count, Late               int
	FirstSeen, LastSeen       model.UnixNano
	FirstArrival, LastArrival model.UnixNano
}

func Summarize(i Issue) Summary {
	s := Summary{Count: len(i.Occurrences) + len(i.LateHistory), Late: len(i.LateHistory)}
	first := true
	visit := func(list []Evidence) {
		for _, e := range list {
			if first || e.EventTime < s.FirstSeen {
				s.FirstSeen = e.EventTime
			}
			if first || e.EventTime > s.LastSeen {
				s.LastSeen = e.EventTime
			}
			if first || e.ArrivalTime < s.FirstArrival {
				s.FirstArrival = e.ArrivalTime
			}
			if first || e.ArrivalTime > s.LastArrival {
				s.LastArrival = e.ArrivalTime
			}
			first = false
		}
	}
	visit(i.Occurrences)
	visit(i.LateHistory)
	return s
}

// ApplyEvidence applies one occurrence at its own durable cursor and returns
// the issue now holding it.
func (s *Service) ApplyEvidence(ctx context.Context, scope auth.Scope, e Evidence) (Issue, error) {
	if e := s.ApplyThrough(ctx, scope, e.Origin, []Evidence{e}); e != nil {
		return Issue{}, e
	}
	project := scope.ProjectIDs()[0]
	state, err := s.read(ctx, scope, project)
	if err != nil {
		return Issue{}, err
	}
	id, ok := state.Occurrences[e.OccurrenceID]
	if !ok {
		id, ok = routes(state)[route{e.GroupingVersion, e.Fingerprint}]
	}
	rec, found := state.Issues[id]
	if !ok || !found {
		return Issue{}, model.Fail(model.NotFound)
	}
	return cloneIssue(rec.Issue), nil
}

// ApplyThrough atomically applies the evidence and advances the checkpoint of
// the cursor's data group in one commit. Evidence at or below the existing
// checkpoint was already processed (or suppressed or declared a gap) and is
// skipped; evidence above it is deduplicated by occurrence ID, so neither a
// worker restart nor a lost acknowledgement can double count, regress or
// notify. On a concurrent commit it rereads and reduces again.
func (s *Service) ApplyThrough(ctx context.Context, scope auth.Scope, cursor model.Cursor, evidence []Evidence) error {
	if len(scope.ProjectIDs()) != 1 {
		return model.Fail(model.Invalid)
	}
	project := scope.ProjectIDs()[0]
	if e := s.authorize(ctx, scope, issuesWrite, project); e != nil {
		return e
	}
	if e := validateBatch(cursor, evidence); e != nil {
		return e
	}
	for range maxAttempts {
		state, e := s.d.Store.Load(ctx, scope, project)
		if e != nil {
			return e
		}
		commit, e := s.reduce(ctx, scope, project, state, cursor, evidence)
		if e != nil {
			return e
		}
		if commit == nil {
			return nil
		}
		e = s.d.Store.Commit(ctx, scope, project, *commit)
		if code(e) == model.Conflict {
			continue
		}
		return e
	}
	return model.Fail(model.Conflict)
}

// reduce is the deterministic lifecycle reducer for one batch. It returns nil
// when the batch changes nothing and the checkpoint is already there.
func (s *Service) reduce(ctx context.Context, scope auth.Scope, project model.ID, state State, cursor model.Cursor, evidence []Evidence) (*Commit, error) {
	checkpoint := state.Checkpoints[cursor.Group]
	index := routes(state)
	working := map[model.ID]*Record{}
	occurrences := map[model.ID]model.ID{}
	known := func(occ model.ID) (model.ID, bool) {
		if id, ok := occurrences[occ]; ok {
			return id, true
		}
		id, ok := state.Occurrences[occ]
		return id, ok
	}
	record := func(id model.ID) *Record {
		if r, ok := working[id]; ok {
			return r
		}
		if r, ok := state.Issues[id]; ok {
			c := cloneRecord(r)
			working[id] = &c
			return &c
		}
		return nil
	}
	var graph releases.Graph
	graphLoaded := false
	var effects []Effect
	for _, raw := range evidence {
		if raw.Origin.Index <= checkpoint {
			continue
		}
		e := cloneEvidence(raw)
		if holder, ok := known(e.OccurrenceID); ok {
			var held Issue
			if r, ok := working[holder]; ok {
				held = r.Issue
			} else if r, ok := state.Issues[holder]; ok {
				held = r.Issue
			} else {
				return nil, model.Fail(model.Corrupt)
			}
			if !holds(held, e) {
				return nil, model.Fail(model.Conflict)
			}
			continue
		}
		k := route{e.GroupingVersion, e.Fingerprint}
		id, ok := index[k]
		if !ok {
			id = issueID(scope.OrgID(), project, e.GroupingVersion, e.Fingerprint)
			if _, exists := state.Issues[id]; exists {
				return nil, model.Fail(model.Corrupt)
			}
			working[id] = &Record{Issue: Issue{ID: id, Org: scope.OrgID(), Project: project, GroupingVersion: e.GroupingVersion, Fingerprint: e.Fingerprint, Workflow: "open", Revision: 0}}
			index[k] = id
		}
		rec := record(id)
		i := &rec.Issue
		switch {
		case i.Workflow == "resolved" && i.ResolutionTime != nil && e.EventTime <= *i.ResolutionTime:
			i.LateHistory = append(i.LateHistory, e)
		case i.Workflow == "resolved":
			if !graphLoaded {
				g, err := s.d.Graphs.Graph(ctx, scope, project)
				if err != nil {
					return nil, err
				}
				graph, graphLoaded = g, true
			}
			i.Occurrences = append(i.Occurrences, e)
			s.evaluate(rec, e, graph, id, &effects)
		default:
			i.Occurrences = append(i.Occurrences, e)
		}
		if e.ReleaseID != nil && !containsID(i.ObservedReleases, *e.ReleaseID) {
			i.ObservedReleases = append(i.ObservedReleases, *e.ReleaseID)
		}
		occurrences[e.OccurrenceID] = id
	}
	advance := cursor.Index > checkpoint
	if len(working) == 0 && !advance {
		return nil, nil
	}
	ids := make([]model.ID, 0, len(working))
	for id := range working {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(a, b int) bool { return lessID(ids[a], ids[b]) })
	commit := &Commit{ExpectedRevision: state.Revision, Occurrences: occurrences, Effects: effects}
	for _, id := range ids {
		r := working[id]
		r.Issue.Revision++
		commit.Records = append(commit.Records, *r)
	}
	if advance {
		commit.Checkpoint = &Checkpoint{Group: cursor.Group, Index: cursor.Index}
	}
	return commit, nil
}

func holds(i Issue, e Evidence) bool {
	for _, list := range [][]Evidence{i.Occurrences, i.LateHistory} {
		for _, held := range list {
			if held.OccurrenceID == e.OccurrenceID {
				return sameOccurrence(held, e)
			}
		}
	}
	return false
}
func containsID(list []model.ID, id model.ID) bool {
	for _, v := range list {
		if v == id {
			return true
		}
	}
	return false
}

// evaluate records the regression evaluation of a post-boundary occurrence on
// a resolved issue and reopens it when the recorded policy is met.
func (s *Service) evaluate(rec *Record, e Evidence, graph releases.Graph, id model.ID, effects *[]Effect) {
	i := &rec.Issue
	decision := Regresses(*i, e, graph)
	x := Explanation{OccurrenceID: e.OccurrenceID, EventTime: e.EventTime, Decision: decision, ResolutionTime: *i.ResolutionTime, Threshold: s.d.Regression.MinOccurrences, Window: s.d.Regression.Window}
	if e.ReleaseID != nil {
		x.EvidenceRelease = *e.ReleaseID
	}
	if decision.Eligible {
		x.Qualifying = 1
		for _, prior := range rec.Explanations {
			if prior.ResolutionTime == x.ResolutionTime && prior.Decision.Eligible && (x.Window == 0 || e.EventTime-prior.EventTime <= x.Window) {
				x.Qualifying++
			}
		}
		if uint32(x.Qualifying) >= x.Threshold {
			x.Reopened = true
		}
	}
	rec.Explanations = append(rec.Explanations, x)
	if x.Reopened {
		i.Workflow = "open"
		i.ResolutionTime, i.ResolutionFrontier, i.FixedDescendants = nil, nil, nil
		*effects = append(*effects, Effect{ID: effectID("issue_regressed", e.OccurrenceID), Kind: "issue_regressed", IssueID: id, OccurrenceID: e.OccurrenceID})
	}
}

// Get returns one issue; the project must be inside the scope.
func (s *Service) Get(ctx context.Context, scope auth.Scope, project, id model.ID) (Issue, error) {
	state, e := s.read(ctx, scope, project)
	if e != nil {
		return Issue{}, e
	}
	rec, ok := state.Issues[id]
	if !ok {
		return Issue{}, model.Fail(model.NotFound)
	}
	return cloneIssue(rec.Issue), nil
}

// Explain returns the stored regression evaluations of an issue, oldest first.
func (s *Service) Explain(ctx context.Context, scope auth.Scope, project, id model.ID) ([]Explanation, error) {
	state, e := s.read(ctx, scope, project)
	if e != nil {
		return nil, e
	}
	rec, ok := state.Issues[id]
	if !ok {
		return nil, model.Fail(model.NotFound)
	}
	return cloneRecord(rec).Explanations, nil
}

var actionKinds = map[string]bool{"resolve": true, "ignore": true, "unignore": true, "reopen": true, "grouping_migration": true}

// Act applies one human action. The actor is the scope's principal; the issue
// must be at ExpectedVersion; a command ID retries to the same result.
func (s *Service) Act(ctx context.Context, scope auth.Scope, a IssueAction) (Issue, error) {
	if e := s.d.Authorizer.Revalidate(ctx, scope); e != nil {
		return Issue{}, e
	}
	if scope.Permission() != issuesWrite || len(scope.ProjectIDs()) == 0 {
		return Issue{}, model.Fail(model.Forbidden)
	}
	if a.CommandID == (model.ID{}) || a.IssueID == (model.ID{}) || !actionKinds[a.Kind] || !safeText(a.Reason) {
		return Issue{}, model.Fail(model.Invalid)
	}
	if a.Kind != "resolve" && (a.ResolutionBoundary != 0 || len(a.FixedDescendantFrontier) != 0) || a.Kind == "grouping_migration" == (a.Migration == nil) {
		return Issue{}, model.Fail(model.Invalid)
	}
	for _, f := range a.FixedDescendantFrontier {
		if f == (model.ID{}) {
			return Issue{}, model.Fail(model.Invalid)
		}
	}
	fingerprint, e := fingerprintOf(a)
	if e != nil {
		return Issue{}, e
	}
	for _, project := range scope.ProjectIDs() {
		if e := s.d.Fence.Admit(ctx, scope, project); e != nil {
			return Issue{}, e
		}
		for range maxAttempts {
			state, e := s.d.Store.Load(ctx, scope, project)
			if e != nil {
				return Issue{}, e
			}
			prior, found := state.Issues[a.IssueID]
			if !found {
				break
			}
			if done, ok := state.Commands[a.CommandID]; ok {
				if done.Fingerprint != fingerprint || done.IssueID != a.IssueID {
					return Issue{}, model.Fail(model.Conflict)
				}
				return cloneIssue(prior.Issue), nil
			}
			if prior.Issue.Revision != a.ExpectedVersion {
				return Issue{}, model.Fail(model.Conflict)
			}
			if a.Kind == "grouping_migration" {
				return s.migrate(ctx, scope, project, prior.Issue, a)
			}
			next, e := s.transition(ctx, scope, project, cloneRecord(prior), a)
			if e != nil {
				return Issue{}, e
			}
			targets := append([]model.ID{a.IssueID}, a.FixedDescendantFrontier...)
			audit := model.ControlAudit{ID: a.CommandID, Principal: scope.PrincipalID(), Action: "issues." + a.Kind, Reason: a.Reason, Time: int64(s.d.Clock.Now()), Org: scope.OrgID().String(), PolicyEpoch: scope.PolicyEpoch(), Targets: targets, RequestID: model.RequestCorrelationID(ctx, a.CommandID), Outcome: model.AuditAllowed}
			e = s.d.Store.Commit(ctx, scope, project, Commit{CommandID: a.CommandID, ExpectedRevision: state.Revision, Records: []Record{next}, Audits: []model.ControlAudit{audit}, Command: &CommandRecord{Fingerprint: fingerprint, IssueID: a.IssueID}})
			if code(e) == model.Conflict {
				continue
			}
			if e != nil {
				return Issue{}, e
			}
			return cloneIssue(next.Issue), nil
		}
		// Not in this project (or the commit kept losing races): try the next.
	}
	return Issue{}, model.Fail(model.NotFound)
}

func fingerprintOf(a IssueAction) ([32]byte, error) {
	raw, e := json.Marshal(struct {
		Version  model.Revision
		Issue    model.ID
		Kind     string
		Reason   string
		Boundary model.UnixNano
		Frontier []model.ID
		Migrate  *model.GroupingMigration
	}{a.ExpectedVersion, a.IssueID, a.Kind, a.Reason, a.ResolutionBoundary, a.FixedDescendantFrontier, a.Migration})
	if e != nil {
		return [32]byte{}, model.Fail(model.Invalid)
	}
	return sha256.Sum256(raw), nil
}

func (s *Service) transition(ctx context.Context, scope auth.Scope, project model.ID, rec Record, a IssueAction) (Record, error) {
	i := &rec.Issue
	clear := func() { i.ResolutionTime, i.ResolutionFrontier, i.FixedDescendants = nil, nil, nil }
	switch a.Kind {
	case "resolve":
		if i.Workflow != "open" {
			return rec, model.Fail(model.Conflict)
		}
		now := s.d.Clock.Now()
		boundary := a.ResolutionBoundary
		if boundary == 0 {
			boundary = now
		}
		if boundary <= 0 || boundary > now || boundary < Summarize(*i).LastSeen {
			return rec, model.Fail(model.Invalid)
		}
		if len(a.FixedDescendantFrontier) > 0 {
			graph, e := s.d.Graphs.Graph(ctx, scope, project)
			if e != nil {
				return rec, e
			}
			seen := map[model.ID]bool{}
			for _, f := range a.FixedDescendantFrontier {
				r, ok := graph[f]
				if !ok || r.ID != f || r.Org != scope.OrgID() || r.Project != project || seen[f] {
					return rec, model.Fail(model.Invalid)
				}
				seen[f] = true
			}
		}
		var observed []model.ID
		for _, list := range [][]Evidence{i.Occurrences, i.LateHistory} {
			for _, e := range list {
				if e.EventTime <= boundary && e.ReleaseID != nil && !containsID(observed, *e.ReleaseID) {
					observed = append(observed, *e.ReleaseID)
				}
			}
		}
		i.Workflow = "resolved"
		i.ResolutionTime = &boundary
		i.ResolutionFrontier = observed
		i.FixedDescendants = append([]model.ID(nil), a.FixedDescendantFrontier...)
	case "ignore":
		if i.Workflow != "open" && i.Workflow != "resolved" {
			return rec, model.Fail(model.Conflict)
		}
		i.Workflow = "ignored"
		clear()
	case "unignore":
		if i.Workflow != "ignored" {
			return rec, model.Fail(model.Conflict)
		}
		i.Workflow = "open"
	case "reopen":
		if i.Workflow != "resolved" {
			return rec, model.Fail(model.Conflict)
		}
		i.Workflow = "open"
		clear()
	}
	i.Revision++
	return rec, nil
}

// migrate delegates the audited grouping migration. It needs project
// policy.write in addition to issues.write and never rewrites issue history.
func (s *Service) migrate(ctx context.Context, scope auth.Scope, project model.ID, prior Issue, a IssueAction) (Issue, error) {
	m := *a.Migration
	if m.Org != scope.OrgID() || m.Project != project || m.From != a.IssueID || m.ID == (model.ID{}) || m.To == (model.ID{}) || m.To == m.From || m.GroupingVersion == 0 || m.Fingerprint == (model.Hash{}) || !safeText(m.Reason) {
		return Issue{}, model.Fail(model.Invalid)
	}
	if m.FromRevision != prior.Revision {
		return Issue{}, model.Fail(model.Conflict)
	}
	if s.d.Migrator == nil {
		return Issue{}, model.Fail(model.Unsupported)
	}
	if e := s.d.Policy.AuthorizePolicyWrite(ctx, scope, project); e != nil {
		return Issue{}, e
	}
	if e := s.d.Migrator.MigrateGrouping(ctx, scope, m, a.CommandID); e != nil {
		return Issue{}, e
	}
	state, e := s.d.Store.Load(ctx, scope, project)
	if e != nil {
		return Issue{}, e
	}
	rec, ok := state.Issues[a.IssueID]
	if !ok {
		return Issue{}, model.Fail(model.NotFound)
	}
	return cloneIssue(rec.Issue), nil
}
