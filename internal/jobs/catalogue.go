// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package jobs

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

// The job schedule-definition catalogue (11.01-W2) is the committed set of
// definitions the background runner's observer stage feeds to ObserveSchedule.
// It is not a second store: a definition is one record in control state
// (control.JobDefinitionRecord, written by the KindUpdateJob handler through
// TransactJobs), and this file is its save-time validation and its read side.
//
// Saving is the one moment a definition is judged: normalizeDefinition parses the
// cron expression and the zone and bounds grace, runtime and staleness, and the
// definition's revision must be the catalogue's next one (the previous
// definition's revision plus one, 1 for a new job) with an effective instant that
// neither precedes the previous one nor lies further ahead than
// MaxDefinitionLead. A definition that fails is never committed, so the observer
// never meets one.

// SafeDetail of the refusals of a save.
const (
	ReasonDefinitionRevision  = "job_definition_revision"
	ReasonDefinitionEffective = "job_definition_effective_from"
)

// CatalogueControl is the part of the control store the catalogue uses
// (satisfied by *control.Store once BindJobUpdate has installed the handler).
type CatalogueControl interface {
	TransactJobs(ctx context.Context, scope auth.Scope, cmd control.Command) (control.Result, error)
	JobDefinitions(ctx context.Context, scope auth.Scope, project model.ID) ([]control.JobDefinitionRecord, error)
	JobDefinition(ctx context.Context, scope auth.Scope, project, job model.ID) (control.JobDefinitionRecord, bool, error)
}

// Entry is one job's catalogue record as it reads.
type Entry struct {
	Job        model.ID
	Revision   model.Revision
	Definition Definition
	Retired    bool
	CreatedNS  model.UnixNano
	UpdatedNS  model.UnixNano
}

// Catalogue saves, retires and lists job definitions over control state. It
// keeps no state of its own.
type Catalogue struct {
	c   CatalogueControl
	now func() model.UnixNano
}

// CatalogueOption configures a Catalogue.
type CatalogueOption func(*Catalogue)

// WithCatalogueClock injects the clock that stamps commits and bounds a
// definition's effective instant (default: wall time).
func WithCatalogueClock(now func() model.UnixNano) CatalogueOption {
	return func(c *Catalogue) { c.now = now }
}

// NewCatalogue builds the catalogue over the control store.
func NewCatalogue(c CatalogueControl, options ...CatalogueOption) (*Catalogue, error) {
	if c == nil {
		return nil, model.Fail(model.Invalid)
	}
	cat := &Catalogue{c: c, now: func() model.UnixNano { return model.UnixNano(time.Now().UnixNano()) }}
	for _, o := range options {
		o(cat)
	}
	return cat, nil
}

// SaveCommand saves the next definition of one job. CommandID is the idempotency
// identity (a replay of a committed command answers the first result).
// ExpectedRevision is the catalogue revision the author read, 0 for a job that
// is not in the catalogue yet. Definition.Revision must be the previous
// definition's revision plus one (1 for a new job).
type SaveCommand struct {
	CommandID        model.ID
	Project          model.ID
	Job              model.ID
	ExpectedRevision model.Revision
	Definition       Definition
	Reason           string
}

// RetireCommand takes a job out of the observer's feed. The record and its
// definition history stay; saving the next definition brings the job back.
type RetireCommand struct {
	CommandID        model.ID
	Project          model.ID
	Job              model.ID
	ExpectedRevision model.Revision
	Reason           string
}

func catalogueInvalid(detail string) error {
	return &model.Fault{Code: model.Invalid, SafeDetail: detail, RequestID: model.NewID()}
}

// author checks the scope is a human policy.write scope of the project: the
// runner's system scope reads the catalogue and never writes it.
func author(scope auth.Scope, project model.ID) error {
	if project == (model.ID{}) {
		return model.Fail(model.Invalid)
	}
	if scope.Permission() != auth.PolicyWrite {
		return model.Fail(model.Forbidden)
	}
	if scope.IsSystem() || !scope.AllowsProject(project) {
		return model.Fail(model.NotFound)
	}
	return nil
}

func (c *Catalogue) transact(ctx context.Context, scope auth.Scope, id model.ID, kind string, apply control.JobDefinitionApply) error {
	raw, err := json.Marshal(control.JobUpdateCommand{Project: apply.Project, Job: apply.Job, Kind: kind, Definition: &apply})
	if err != nil {
		return model.Fail(model.Invalid)
	}
	_, err = c.c.TransactJobs(ctx, scope, control.Command{CommandID: id, Kind: string(control.KindUpdateJob), Payload: raw})
	return err
}

// Save validates the definition, commits it as the job's next one and returns
// the committed entry.
func (c *Catalogue) Save(ctx context.Context, scope auth.Scope, cmd SaveCommand) (Entry, error) {
	if err := author(scope, cmd.Project); err != nil {
		return Entry{}, err
	}
	if cmd.CommandID == (model.ID{}) || cmd.Job == (model.ID{}) {
		return Entry{}, model.Fail(model.Invalid)
	}
	def, err := normalizeDefinition(cmd.Definition)
	if err != nil {
		return Entry{}, err
	}
	prior, found, err := c.c.JobDefinition(ctx, scope, cmd.Project, cmd.Job)
	if err != nil {
		return Entry{}, err
	}
	// A retry of the command that committed the prior record is answered by
	// control as the replay it is; judging it against its own result would refuse it.
	if !(found && prior.LastCommand == cmd.CommandID) {
		if found && prior.Revision != cmd.ExpectedRevision || !found && cmd.ExpectedRevision != 0 {
			return Entry{}, &model.Fault{Code: model.Conflict, SafeDetail: control.JobDefinitionConflict, RequestID: model.NewID()}
		}
		var want model.Uint64 = 1
		var floor model.UnixNano
		if found {
			p, err := decodeEntry(prior)
			if err != nil {
				return Entry{}, err
			}
			want, floor = p.Definition.Revision+1, p.Definition.EffectiveFrom
		}
		if def.Revision != want {
			return Entry{}, catalogueInvalid(ReasonDefinitionRevision)
		}
		if def.EffectiveFrom < floor || def.EffectiveFrom > c.now()+model.UnixNano(MaxDefinitionLead) {
			return Entry{}, catalogueInvalid(ReasonDefinitionEffective)
		}
	}
	raw, err := json.Marshal(def)
	if err != nil {
		return Entry{}, model.Fail(model.Invalid)
	}
	if err = c.transact(ctx, scope, cmd.CommandID, control.JobKindDefine, control.JobDefinitionApply{Project: cmd.Project, Job: cmd.Job, ExpectedRevision: cmd.ExpectedRevision,
		Definition: raw, Digest: model.Hash(sha256.Sum256(raw)), Reason: cmd.Reason, At: c.now()}); err != nil {
		return Entry{}, err
	}
	return c.read(ctx, scope, cmd.Project, cmd.Job)
}

// Retire takes a job out of the observer's feed. Retiring a retired job commits
// nothing.
func (c *Catalogue) Retire(ctx context.Context, scope auth.Scope, cmd RetireCommand) (Entry, error) {
	if err := author(scope, cmd.Project); err != nil {
		return Entry{}, err
	}
	if cmd.CommandID == (model.ID{}) || cmd.Job == (model.ID{}) {
		return Entry{}, model.Fail(model.Invalid)
	}
	if err := c.transact(ctx, scope, cmd.CommandID, control.JobKindRetire, control.JobDefinitionApply{Project: cmd.Project, Job: cmd.Job, ExpectedRevision: cmd.ExpectedRevision,
		Reason: cmd.Reason, At: c.now()}); err != nil {
		return Entry{}, err
	}
	return c.read(ctx, scope, cmd.Project, cmd.Job)
}

func (c *Catalogue) read(ctx context.Context, scope auth.Scope, project, job model.ID) (Entry, error) {
	rec, found, err := c.c.JobDefinition(ctx, scope, project, job)
	if err != nil {
		return Entry{}, err
	}
	if !found {
		return Entry{}, model.Fail(model.NotFound)
	}
	return decodeEntry(rec)
}

// List returns the project's entries (retired ones included), in job ID order,
// to a scope that may read the project. The observer stage feeds the Definition
// of every entry that is not Retired.
func (c *Catalogue) List(ctx context.Context, scope auth.Scope, project model.ID) ([]Entry, error) {
	recs, err := c.c.JobDefinitions(ctx, scope, project)
	if err != nil {
		return nil, err
	}
	out := make([]Entry, 0, len(recs))
	for _, rec := range recs {
		e, err := decodeEntry(rec)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}

// decodeEntry decodes a record, refusing a definition that cannot be one: a
// record that disagrees with itself is corrupt, never fed to the observer.
func decodeEntry(rec control.JobDefinitionRecord) (Entry, error) {
	var def Definition
	if json.Unmarshal(rec.Definition, &def) != nil || def.Revision == 0 || def.EffectiveFrom <= 0 {
		return Entry{}, model.Fail(model.Corrupt)
	}
	return Entry{Job: rec.Job, Revision: rec.Revision, Definition: def, Retired: rec.Retired, CreatedNS: rec.CreatedNS, UpdatedNS: rec.UpdatedNS}, nil
}
