// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"soundpost/internal/auth"
	"soundpost/internal/model"
)

// This file is the C05 half of C07 jobs: the KindUpdateJob handler and the
// durable job books. Like the incident and issue stores it holds leaf DTOs
// only: the job state is opaque JSON that the jobs package computes with its
// pure reducer outside deterministic apply. Control never imports the jobs
// package and interprets a state only through its closed header (version, org,
// project, job), a closed set of top-level keys and the size bounds below. What
// control owns, atomically in one command:
//
//   - scope: a principal holding policy.write on exactly this project (the
//     permission jobs.Service demands of every mutation), validated against the
//     very state the command applies to (session, token, epoch, membership,
//     grant, project live and named by the scope) before any job book is looked
//     up, so a wrong-scope target and a missing one are indistinguishable;
//   - the version compare-and-set: the stored job version must equal the
//     command's expected version, the new state is that version plus one, and
//     the loser of a race is model.Stale carrying the current version;
//   - exactly-once commands: a command ID that the job's book already holds is
//     answered as a replay (nothing changes) when the principal, kind and input
//     digest are the same and is a Conflict when the digest differs. The replay
//     is decided before the version check, so a retry that reached the store
//     after other updates moved the version on is still a replay;
//   - the audit of a correction, in the same transition, with the actor the
//     validated scope's principal, never a payload claim;
//   - bounded state, refused as model.Quota and never truncated (see the
//     constants).
//
// A job state holds IDs, ordinals, timestamps, enumerated states and hashes,
// plus the few short closed-vocabulary strings of the jobs types (cron and
// zone, occurrence keys, a correction's safe reason). Every string is bounded.

// Job update kinds; they equal jobs.UpdateKind.
const (
	jobKindAttempt    = "attempt"
	jobKindSchedule   = "schedule"
	jobKindCorrection = "correction"
)

// JobVersionConflict is the SafeDetail prefix of a lost job version race; the
// detail ends in " current=<version>".
const JobVersionConflict = "job_version_conflict"

const jobCommandReused = "job_command_reused"

// Job store bounds. Every refusal is model.Quota (TooLarge for the payload).
// The control state is rewritten through Raft on every commit, so the bounds are
// deliberately conservative; a job that outgrows them stalls visibly (every
// further update is refused) rather than being truncated.
const (
	maxJobState        = 512 << 10 // bytes of one job state
	maxJobPayload      = maxJobState + 64<<10
	maxJobsPerProject  = 64
	maxJobProjectBytes = 8 << 20 // job book bytes of one project, all jobs
	maxJobCommands     = 1024    // applied command records kept per job (oldest evicted)
	maxJobRuns         = 512
	maxJobAttempts     = 2048
	maxJobOccurrences  = 1024
	maxJobHistory      = 64
	maxJobIntervals    = 256
	maxJobString       = 1024
	maxJobDepth        = 12
	maxJobAuditTargets = 8
	maxJobAuditReason  = 512
)

// JobAudit is the audit a correction commits with its state. The principal must
// be the scope's own.
type JobAudit struct {
	Principal model.ID       `json:"principal"`
	Action    string         `json:"action"`
	Reason    string         `json:"reason"`
	At        model.UnixNano `json:"at_ns"`
	Targets   []model.ID     `json:"targets"`
}

// JobUpdateCommand is the closed KindUpdateJob payload. State is the complete
// resulting job state (the jobs reducer already ran); NewVersion must be
// ExpectedVersion+1 and equal the version inside State.
type JobUpdateCommand struct {
	Project         model.ID        `json:"project"`
	Job             model.ID        `json:"job"`
	Kind            string          `json:"kind"`
	ExpectedVersion model.Revision  `json:"expected_version"`
	NewVersion      model.Revision  `json:"new_version"`
	InputDigest     model.Hash      `json:"input_digest"`
	State           json.RawMessage `json:"state"`
	Origin          *model.Cursor   `json:"origin,omitempty"`
	Audit           *JobAudit       `json:"audit,omitempty"`
}

// JobCommandEntry remembers one applied command of a job.
type JobCommandEntry struct {
	ID        model.ID       `json:"id"`
	Principal model.ID       `json:"principal"`
	Kind      string         `json:"kind"`
	Digest    model.Hash     `json:"digest"`
	Version   model.Revision `json:"version"`
	Origin    *model.Cursor  `json:"origin,omitempty"`
}

// JobRecord is everything control holds for one job. After an erasure State is
// a tombstone (closed header and the erasing operation) and Version, Digest and
// Commands remain.
type JobRecord struct {
	Org      model.ID          `json:"org"`
	Project  model.ID          `json:"project"`
	Job      model.ID          `json:"job"`
	Version  model.Revision    `json:"version"`
	Digest   model.Hash        `json:"digest"`
	State    json.RawMessage   `json:"state"`
	Commands []JobCommandEntry `json:"commands,omitempty"`
}

// JobSnapshot is a committed job as a read answers it. Erased means the state
// was dropped by a deletion: State is nil and only the version remains.
type JobSnapshot struct {
	Version model.Revision
	Digest  model.Hash
	Erased  bool
	State   json.RawMessage
}

// BindJobUpdate installs the KindUpdateJob handler on this Store only, like the
// other Bind* methods; it is a conflict to bind twice. The handler admits only
// policy.write scopes, so the generic Transact (organization administrators)
// cannot commit through it: use TransactJobs.
func (s *Store) BindJobUpdate() error {
	return s.RegisterHandler(KindUpdateJob, func(scope auth.Scope, st *State, cmd Command) (Effect, error) {
		job, _, phase, err := applyJobUpdate(scope, st, cmd)
		if err != nil {
			return Effect{}, err
		}
		return Effect{AffectedIDs: []model.ID{job}, Phase: phase}, nil
	})
}

func jobKey(org, project, job model.ID) string {
	return org.String() + ":" + project.String() + ":" + job.String()
}

func jobProjectPrefix(org, project model.ID) string {
	return org.String() + ":" + project.String() + ":"
}

func jobWriteScope(scope auth.Scope, st *State, project model.ID) error {
	if scope.Permission() != auth.PolicyWrite {
		return model.Fail(model.Forbidden)
	}
	return issueProjectScope(scope, st, project)
}

func jobReadScope(scope auth.Scope, st *State, project model.ID) error {
	switch scope.Permission() {
	case auth.Read, auth.PolicyWrite, auth.OrgAdmin:
	default:
		return model.Fail(model.Forbidden)
	}
	return issueProjectScope(scope, st, project)
}

func loadJobRecord(st *State, key string) (JobRecord, bool, error) {
	raw, ok := st.JobBooks[key]
	if !ok {
		return JobRecord{}, false, nil
	}
	var r JobRecord
	if err := json.Unmarshal(raw, &r); err != nil {
		return JobRecord{}, false, model.Fail(model.Corrupt)
	}
	return r, true, nil
}

var jobStateKeys = map[string]bool{
	"version": true, "org": true, "project": true, "job": true, "definition": true, "history": true,
	"current_health": true, "latest_schedule_key": true, "occurrences": true, "runs": true, "attempts": true,
	"incomplete_intervals": true, "observer": true, "compaction": true,
}

// jobStateCounts are the sizes of a state's collections.
type jobStateCounts struct {
	Version     model.Revision             `json:"version"`
	Org         model.ID                   `json:"org"`
	Project     model.ID                   `json:"project"`
	Job         model.ID                   `json:"job"`
	History     []json.RawMessage          `json:"history"`
	Occurrences map[string]json.RawMessage `json:"occurrences"`
	Runs        map[string]json.RawMessage `json:"runs"`
	Attempts    map[string]json.RawMessage `json:"attempts"`
	Intervals   []json.RawMessage          `json:"incomplete_intervals"`
}

// jobStateHeader validates everything about a state that needs no committed
// data: it is one JSON object with only the jobs state's keys, its header names
// this org, project and job at the new version, and every string is bounded safe
// text. It returns the compact form and the collection sizes.
func jobStateHeader(raw json.RawMessage, org, project, job model.ID, version model.Revision) (json.RawMessage, jobStateCounts, error) {
	var counts jobStateCounts
	if len(raw) == 0 || len(raw) > maxJobState {
		if len(raw) > maxJobState {
			return nil, counts, model.Fail(model.Quota)
		}
		return nil, counts, model.Fail(model.Invalid)
	}
	var top map[string]json.RawMessage
	if json.Unmarshal(raw, &top) != nil || top == nil {
		return nil, counts, model.Fail(model.Invalid)
	}
	for k := range top {
		if !jobStateKeys[k] {
			return nil, counts, model.Fail(model.Invalid)
		}
	}
	for _, k := range []string{"version", "org", "project", "job"} {
		if _, ok := top[k]; !ok {
			return nil, counts, model.Fail(model.Invalid)
		}
	}
	if json.Unmarshal(raw, &counts) != nil || counts.Version != version || counts.Org != org || counts.Project != project || counts.Job != job {
		return nil, counts, model.Fail(model.Invalid)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var root any
	if dec.Decode(&root) != nil || !jobSafeValue(root, 0) {
		return nil, counts, model.Fail(model.Invalid)
	}
	var compact bytes.Buffer
	if json.Compact(&compact, raw) != nil {
		return nil, counts, model.Fail(model.Invalid)
	}
	return json.RawMessage(compact.Bytes()), counts, nil
}

func jobSafeValue(v any, depth int) bool {
	if depth > maxJobDepth {
		return false
	}
	switch t := v.(type) {
	case map[string]any:
		for k, e := range t {
			if !jobSafeString(k) || !jobSafeValue(e, depth+1) {
				return false
			}
		}
	case []any:
		for _, e := range t {
			if !jobSafeValue(e, depth+1) {
				return false
			}
		}
	case string:
		return jobSafeString(t)
	}
	return true
}

func jobSafeString(s string) bool {
	if len(s) > maxJobString || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func jobAuditEntry(scope auth.Scope, cmd Command, a JobAudit) (model.ControlAudit, error) {
	if a.Principal != scope.PrincipalID() {
		return model.ControlAudit{}, model.Fail(model.Forbidden)
	}
	action, ok := strings.CutPrefix(a.Action, "jobs.")
	if !ok || !issueToken(action, maxIssueActionName) || a.At <= 0 || !issueText(a.Reason, maxJobAuditReason, true) || len(a.Targets) == 0 || len(a.Targets) > maxJobAuditTargets {
		return model.ControlAudit{}, model.Fail(model.Invalid)
	}
	h := sha256.New()
	h.Write([]byte("soundpost.jobs.audit.v1"))
	h.Write(cmd.CommandID[:])
	var id model.ID
	copy(id[:], h.Sum(nil))
	return model.ControlAudit{ID: id, Principal: a.Principal, Action: a.Action, Reason: a.Reason, Time: int64(a.At), Org: scope.OrgID().String(), PolicyEpoch: scope.PolicyEpoch(),
		Targets: append([]model.ID(nil), a.Targets...), RequestID: a.Targets[0], Outcome: model.AuditAllowed}, nil
}

// applyJobUpdate is the whole transition. It returns the job, the version the
// command's entry committed at (the existing entry's for a replay) and the phase.
func applyJobUpdate(scope auth.Scope, st *State, cmd Command) (model.ID, model.Revision, string, error) {
	if len(cmd.Payload) > maxJobPayload {
		return model.ID{}, 0, "", model.Fail(model.TooLarge)
	}
	var c JobUpdateCommand
	if err := strictPayload(cmd.Payload, &c); err != nil {
		return model.ID{}, 0, "", err
	}
	// Scope and grants first: nothing about the project's books is looked up,
	// parsed or answered for a scope that may not act in this project.
	if err := jobWriteScope(scope, st, c.Project); err != nil {
		return model.ID{}, 0, "", err
	}
	if cmd.CommandID == (model.ID{}) || c.Job == (model.ID{}) || c.InputDigest == (model.Hash{}) || c.NewVersion != c.ExpectedVersion+1 || c.NewVersion == 0 {
		return model.ID{}, 0, "", model.Fail(model.Invalid)
	}
	switch c.Kind {
	case jobKindAttempt:
		if c.Origin == nil || c.Origin.Group == (model.ID{}) || c.Audit != nil {
			return model.ID{}, 0, "", model.Fail(model.Invalid)
		}
	case jobKindSchedule:
		if c.Origin != nil || c.Audit != nil {
			return model.ID{}, 0, "", model.Fail(model.Invalid)
		}
	case jobKindCorrection:
		if c.Origin != nil || c.Audit == nil {
			return model.ID{}, 0, "", model.Fail(model.Invalid)
		}
	default:
		return model.ID{}, 0, "", model.Fail(model.Invalid)
	}
	org := scope.OrgID()
	state, counts, err := jobStateHeader(c.State, org, c.Project, c.Job, c.NewVersion)
	if err != nil {
		return model.ID{}, 0, "", err
	}
	var audit model.ControlAudit
	if c.Audit != nil {
		if audit, err = jobAuditEntry(scope, cmd, *c.Audit); err != nil {
			return model.ID{}, 0, "", err
		}
	}
	key := jobKey(org, c.Project, c.Job)
	rec, exists, err := loadJobRecord(st, key)
	if err != nil {
		return model.ID{}, 0, "", err
	}
	principal := scope.PrincipalID()
	for _, e := range rec.Commands {
		if e.ID != cmd.CommandID {
			continue
		}
		if e.Principal != principal {
			return model.ID{}, 0, "", model.Fail(model.NotFound)
		}
		if e.Kind != c.Kind || e.Digest != c.InputDigest {
			return model.ID{}, 0, "", ruleFault(model.Conflict, jobCommandReused)
		}
		return c.Job, e.Version, "replayed", nil
	}
	if rec.Version != c.ExpectedVersion {
		return model.ID{}, 0, "", ruleFault(model.Stale, JobVersionConflict+" current="+strconv.FormatUint(uint64(rec.Version), 10))
	}
	if len(counts.Runs) > maxJobRuns || len(counts.Attempts) > maxJobAttempts || len(counts.Occurrences) > maxJobOccurrences || len(counts.History) > maxJobHistory || len(counts.Intervals) > maxJobIntervals {
		return model.ID{}, 0, "", model.Fail(model.Quota)
	}
	rec.Org, rec.Project, rec.Job, rec.Version = org, c.Project, c.Job, c.NewVersion
	rec.Digest = model.Hash(sha256.Sum256(state))
	rec.State = state
	rec.Commands = append(rec.Commands, JobCommandEntry{ID: cmd.CommandID, Principal: principal, Kind: c.Kind, Digest: c.InputDigest, Version: c.NewVersion, Origin: c.Origin})
	if n := len(rec.Commands) - maxJobCommands; n > 0 {
		rec.Commands = append([]JobCommandEntry(nil), rec.Commands[n:]...)
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		return model.ID{}, 0, "", model.Fail(model.Invalid)
	}
	prefix := jobProjectPrefix(org, c.Project)
	jobs, total := 0, len(raw)
	for k, v := range st.JobBooks {
		if k == key || !strings.HasPrefix(k, prefix) {
			continue
		}
		jobs++
		total += len(v)
	}
	if !exists && jobs >= maxJobsPerProject || total > maxJobProjectBytes {
		return model.ID{}, 0, "", model.Fail(model.Quota)
	}
	if st.JobBooks == nil {
		st.JobBooks = map[string]json.RawMessage{}
	}
	st.JobBooks[key] = raw
	if c.Audit != nil {
		st.Audits = append(st.Audits, audit)
	}
	if err = eraseLateEffect(st, org, c.Project); err != nil {
		return model.ID{}, 0, "", err
	}
	return c.Job, c.NewVersion, "applied", nil
}

// TransactJobs commits one KindUpdateJob command for a scope that holds
// policy.write on the project. The generic Transact admits only organization
// administrators; jobs.Service acts with the narrower permission, so this entry
// point validates the scope against the very state the command applies to
// (session, token, epoch, membership and the grant) and dispatches through the
// registered handler. The job version is the compare-and-set token, so
// concurrent updaters never fail on unrelated control changes. The Result's
// Phase is "applied" or "replayed" and its Cursor.Index is the job version the
// command committed at.
func (s *Store) TransactJobs(ctx context.Context, scope auth.Scope, cmd Command) (Result, error) {
	if cmd.Kind != string(KindUpdateJob) || cmd.CommandID == (model.ID{}) {
		return Result{}, model.Fail(model.Invalid)
	}
	if len(cmd.Payload) > maxJobPayload {
		return Result{}, model.Fail(model.TooLarge)
	}
	if scope.Permission() != auth.PolicyWrite {
		return Result{}, model.Fail(model.Forbidden)
	}
	if s.handler(KindUpdateJob) == nil {
		return Result{}, model.Fail(model.Unsupported)
	}
	var out Result
	err := s.Update(ctx, func(st *State) error {
		job, version, phase, err := applyJobUpdate(scope, st, cmd)
		if err != nil {
			return err
		}
		out = Result{AffectedIDs: []model.ID{job}, Phase: phase, Revision: st.Revision + 1, Cursor: model.Cursor{Group: job, Index: model.Uint64(version)}}
		return nil
	})
	return out, err
}

// JobBook reads one job through a linearizable control read. The scope is
// checked before the project is looked up; a project the scope does not name, a
// retired one and a missing one are indistinguishable, and so is a missing job.
func (s *Store) JobBook(ctx context.Context, scope auth.Scope, project, job model.ID) (out JobSnapshot, found bool, err error) {
	err = s.View(ctx, func(st State) error {
		if e := jobReadScope(scope, &st, project); e != nil {
			return e
		}
		rec, ok, e := loadJobRecord(&st, jobKey(scope.OrgID(), project, job))
		if e != nil || !ok {
			return e
		}
		if rec.Org != scope.OrgID() || rec.Project != project || rec.Job != job {
			return model.Fail(model.Corrupt)
		}
		found = true
		out = JobSnapshot{Version: rec.Version, Digest: rec.Digest, Erased: stateIsTombstone(rec.State)}
		if !out.Erased {
			out.State = append(json.RawMessage(nil), rec.State...)
		}
		return nil
	})
	return
}

// JobGaps returns the declared evidence gaps of one project, in ID order, to a
// scope that may read the project.
func (s *Store) JobGaps(ctx context.Context, scope auth.Scope, project model.ID) (out []model.EvidenceGap, err error) {
	err = s.View(ctx, func(st State) error {
		if e := jobReadScope(scope, &st, project); e != nil {
			return e
		}
		for _, g := range st.EvidenceGaps {
			if g.Org == scope.OrgID() && g.Project == project {
				out = append(out, g)
			}
		}
		sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i].ID[:], out[j].ID[:]) < 0 })
		return nil
	})
	return
}
