// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"sort"
	"strconv"
	"strings"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
)

// This file is the job schedule-definition catalogue (plan 11.01-W2): the
// committed definitions the background runner's observer stage feeds to the jobs
// reducer. It is two more kinds of the existing KindUpdateJob command
// (JobKindDefine, JobKindRetire) so it is written by the same entry point
// (TransactJobs), with the same scope validation as every job write, and no new
// command kind. Like the rule catalogue it stores only a leaf DTO: the definition
// is opaque JSON that the jobs package validates (cron, zone, grace) before it
// commits; control reads only its revision and effective_from_ns. What control
// owns, atomically in one command:
//
//   - the author: a human policy.write principal of the project. The runner's
//     system scope reads the catalogue and never writes it (refused as NotFound);
//   - the revision: the compare-and-set token of one job's catalogue record (0 =
//     it must not exist yet). It moves at every change;
//   - the definition revision: it moves by exactly one at every save, and the
//     effective_from_ns of a save never precedes the previous one;
//   - exactly-once: the last command ID of a record replays as a no-op, with a
//     different input it is a conflict; a retirement of a retired job is
//     unchanged;
//   - the digest, the size bound and the per-project quota;
//   - the audit: actor, job and reason, never the definition.

// The kinds of a JobUpdateCommand that write the catalogue. They carry no State
// and no version.
const (
	JobKindDefine = "define_job"
	JobKindRetire = "retire_job"
)

// The SafeDetail of the faults of a catalogue command.
const (
	JobDefinitionConflict = "job_definition_conflict"
	JobDefinitionQuota    = "job_definition_quota"
)

const (
	// MaxJobDefinitionBytes bounds one definition.
	MaxJobDefinitionBytes = 8 << 10
	// MaxJobDefinitionsPerProject bounds the catalogue of one project, retired
	// jobs included.
	MaxJobDefinitionsPerProject = maxJobsPerProject

	jobDefineAction = "jobs.define"
	jobRetireAction = "jobs.retire"
)

// JobDefinitionApply is the closed arm of JobKindDefine and JobKindRetire. A save
// carries the definition and its digest; a retirement neither. ExpectedRevision
// is the catalogue revision the author read (0 = the job must not exist yet).
type JobDefinitionApply struct {
	Project          model.ID        `json:"project"`
	Job              model.ID        `json:"job"`
	ExpectedRevision model.Revision  `json:"expected_revision"`
	Definition       json.RawMessage `json:"definition,omitempty"`
	Digest           model.Hash      `json:"digest"`
	Reason           string          `json:"reason"`
	At               model.UnixNano  `json:"at_ns"`
}

// JobDefinitionRecord is the committed catalogue entry of one job.
type JobDefinitionRecord struct {
	Org         model.ID        `json:"org"`
	Project     model.ID        `json:"project"`
	Job         model.ID        `json:"job"`
	Revision    model.Revision  `json:"revision"`
	Digest      model.Hash      `json:"digest"`
	Definition  json.RawMessage `json:"definition"`
	Retired     bool            `json:"retired,omitempty"`
	CreatedNS   model.UnixNano  `json:"created_ns"`
	UpdatedNS   model.UnixNano  `json:"updated_ns"`
	LastCommand model.ID        `json:"last_command"`
	LastInput   model.Hash      `json:"last_input"`
}

// jobDefinitionHeader is the part of a definition control reads.
type jobDefinitionHeader struct {
	Revision      model.Uint64   `json:"revision"`
	EffectiveFrom model.UnixNano `json:"effective_from_ns"`
}

func loadJobDefinition(st *State, key string) (JobDefinitionRecord, bool, error) {
	raw, ok := st.JobDefinitions[key]
	if !ok {
		return JobDefinitionRecord{}, false, nil
	}
	var rec JobDefinitionRecord
	if json.Unmarshal(raw, &rec) != nil || jobKey(rec.Org, rec.Project, rec.Job) != key {
		return JobDefinitionRecord{}, false, model.Fail(model.Corrupt)
	}
	return rec, true, nil
}

// applyJobDefinition commits one catalogue command (see the file comment) for a
// scope jobWriteScope already admitted. It returns the job, the catalogue
// revision the command committed at and the phase.
func applyJobDefinition(scope auth.Scope, st *State, cmd Command, c JobUpdateCommand) (model.ID, model.Revision, string, error) {
	fail := func(err error) (model.ID, model.Revision, string, error) { return model.ID{}, 0, "", err }
	d := c.Definition
	if scope.IsSystem() {
		return fail(model.Fail(model.NotFound))
	}
	if d == nil || (len(c.State) != 0 && string(c.State) != "null") || c.Origin != nil || c.Audit != nil || c.InputDigest != (model.Hash{}) || c.ExpectedVersion != 0 || c.NewVersion != 0 ||
		cmd.CommandID == (model.ID{}) || d.Project != c.Project || d.Job != c.Job {
		return fail(model.Fail(model.Invalid))
	}
	reason, ok := cleanReason(d.Reason)
	if !ok || d.Project == (model.ID{}) || d.Job == (model.ID{}) || d.At <= 0 {
		return fail(model.Fail(model.Invalid))
	}
	var header jobDefinitionHeader
	if c.Kind == JobKindDefine {
		if len(d.Definition) > MaxJobDefinitionBytes {
			return fail(model.Fail(model.TooLarge))
		}
		if len(d.Definition) < 2 || !json.Valid(d.Definition) || d.Digest == (model.Hash{}) || model.Hash(sha256.Sum256(d.Definition)) != d.Digest || json.Unmarshal(d.Definition, &header) != nil ||
			header.Revision == 0 || header.EffectiveFrom <= 0 {
			return fail(model.Fail(model.Invalid))
		}
	} else if len(d.Definition) != 0 || d.Digest != (model.Hash{}) {
		return fail(model.Fail(model.Invalid))
	}
	org := scope.OrgID()
	key := jobKey(org, d.Project, d.Job)
	rec, exists, err := loadJobDefinition(st, key)
	if err != nil {
		return fail(err)
	}
	// The digest of what the author asked: never the clock stamp, which differs
	// between a command and its retry.
	h := sha256.New()
	for _, part := range [][]byte{[]byte(c.Kind), d.Project[:], d.Job[:], []byte(strconv.FormatUint(uint64(d.ExpectedRevision), 10)), d.Digest[:], []byte(d.Reason)} {
		h.Write(part)
		h.Write([]byte{0})
	}
	var input model.Hash
	copy(input[:], h.Sum(nil))
	if exists && rec.LastCommand == cmd.CommandID {
		if rec.LastInput != input {
			return fail(ruleFault(model.Conflict, jobCommandReused))
		}
		return d.Job, rec.Revision, "replayed", nil
	}
	if !exists && c.Kind == JobKindRetire {
		return fail(model.Fail(model.NotFound))
	}
	if exists && rec.Revision != d.ExpectedRevision || !exists && d.ExpectedRevision != 0 {
		return fail(ruleFault(model.Conflict, JobDefinitionConflict))
	}
	phase, action := "defined", jobDefineAction
	if c.Kind == JobKindRetire {
		if rec.Retired {
			return d.Job, rec.Revision, "unchanged", nil
		}
		rec.Retired, phase, action = true, "job_retired", jobRetireAction
	} else {
		var prior jobDefinitionHeader
		if exists && json.Unmarshal(rec.Definition, &prior) != nil {
			return fail(model.Fail(model.Corrupt))
		}
		if header.Revision != prior.Revision+1 || header.EffectiveFrom < prior.EffectiveFrom {
			return fail(model.Fail(model.Invalid))
		}
		if !exists {
			prefix, n := jobProjectPrefix(org, d.Project), 0
			for k := range st.JobDefinitions {
				if strings.HasPrefix(k, prefix) {
					n++
				}
			}
			if n >= MaxJobDefinitionsPerProject {
				return fail(ruleFault(model.Quota, JobDefinitionQuota))
			}
			rec = JobDefinitionRecord{Org: org, Project: d.Project, Job: d.Job, CreatedNS: d.At}
		}
		rec.Digest, rec.Retired = d.Digest, false
		rec.Definition = append(json.RawMessage(nil), d.Definition...)
	}
	rec.Revision++
	rec.UpdatedNS = d.At
	rec.LastCommand, rec.LastInput = cmd.CommandID, input
	raw, err := json.Marshal(rec)
	if err != nil {
		return fail(model.Fail(model.Invalid))
	}
	if st.JobDefinitions == nil {
		st.JobDefinitions = map[string]json.RawMessage{}
	}
	st.JobDefinitions[key] = raw
	st.Audits = append(st.Audits, model.ControlAudit{ID: cmd.CommandID, Principal: scope.PrincipalID(), Action: action, Reason: reason, Time: int64(d.At), Org: org.String(),
		PolicyEpoch: scope.PolicyEpoch(), Targets: []model.ID{d.Project, d.Job}, RequestID: cmd.CommandID, Outcome: model.AuditAllowed})
	return d.Job, rec.Revision, phase, nil
}

// JobDefinitions lists one project's catalogue (retired jobs included), in job ID
// order, through a linearizable control read, to a scope that may read the
// project's job facts (the runner's read scope included). A project the scope
// does not name is indistinguishable from an absent one.
func (s *Store) JobDefinitions(ctx context.Context, scope auth.Scope, project model.ID) (out []JobDefinitionRecord, err error) {
	err = s.View(ctx, func(st State) error {
		if e := jobReadScope(scope, &st, project); e != nil {
			return e
		}
		prefix := jobProjectPrefix(scope.OrgID(), project)
		for key := range st.JobDefinitions {
			if !strings.HasPrefix(key, prefix) {
				continue
			}
			rec, _, e := loadJobDefinition(&st, key)
			if e != nil {
				return e
			}
			out = append(out, rec)
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Job.String() < out[j].Job.String() })
		return nil
	})
	return
}

// JobDefinition reads one job's catalogue record.
func (s *Store) JobDefinition(ctx context.Context, scope auth.Scope, project, job model.ID) (out JobDefinitionRecord, found bool, err error) {
	err = s.View(ctx, func(st State) error {
		if e := jobReadScope(scope, &st, project); e != nil {
			return e
		}
		var e error
		out, found, e = loadJobDefinition(&st, jobKey(scope.OrgID(), project, job))
		return e
	})
	return
}

// eraseJobDefinitions is the deletion hook's half for the job catalogue: a
// retirement of a project (or of its organization) drops every definition of the
// covered projects. A range or entity deletion erases telemetry, which no
// definition holds. The owner is read from the key, so a record that cannot be
// decoded is still dropped with its project. It is idempotent.
func eraseJobDefinitions(st *State, p model.DeletePredicate) (dropped int, err error) {
	keys := make([]string, 0, len(st.JobDefinitions))
	for key := range st.JobDefinitions {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		parts := strings.Split(key, ":")
		if len(parts) != 3 {
			continue
		}
		org, e1 := model.ParseID(parts[0])
		project, e2 := model.ParseID(parts[1])
		if e1 != nil || e2 != nil || !p.RetiresProject(org, project) {
			continue
		}
		delete(st.JobDefinitions, key)
		dropped++
	}
	return dropped, nil
}
