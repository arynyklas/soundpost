// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package rules

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"sync"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/profile"
	"github.com/arynyklas/soundpost/profiles"
)

// The rule catalogue is the committed set of rule definitions the background
// runner evaluates (11.01-W1). It is not a second store: a definition is one
// record in control state (control.RuleDefinitionRecord, written by the same
// KindApplyRuleEvaluation dispatcher as every other rule fact), and this file is
// its save-time validation and its read side.
//
// Saving a rule is the one moment a definition is judged: Rule.Check parses and
// type-checks the expression under the pinned profile and feature set and
// requires an instant vector, and a recording rule is checked against the
// recording source the node writes its samples through (its configured labels
// must be values the source policy enumerates, 02.11 review M-4). A definition
// that fails is never committed, so evaluation never meets one. The pinned
// version is assigned here, as the previous version plus one; an evaluation
// commits under it for as long as it is the newest, and a changed definition is
// always a new version.

// The safe, closed reasons of a recording rule the node cannot record.
const (
	// ReasonRecordingSourceUnavailable: the node has no registered recording
	// source for the rule's project (or none that may write metrics).
	ReasonRecordingSourceUnavailable = "recording_source_unavailable"
	// ReasonRecordingLabelNotAllowed: a configured output label (name or value) is
	// not one the recording source's policy enumerates.
	ReasonRecordingLabelNotAllowed = "recording_label_not_allowed"
)

// CatalogueControl is the part of the control store the catalogue uses
// (satisfied by *control.Store).
type CatalogueControl interface {
	Control
	RuleDefinitions(ctx context.Context, scope auth.Scope, project model.ID) ([]control.RuleDefinitionRecord, error)
	RuleDefinition(ctx context.Context, scope auth.Scope, project, rule model.ID) (control.RuleDefinitionRecord, bool, error)
}

// RecordingTarget is the registered recording source of the node: the identity
// its samples are admitted as, the project the source belongs to, and the source
// policy the samples are normalized against.
type RecordingTarget struct {
	Project  model.ID
	Producer ProducerIdentity
	Policy   model.SourcePolicy
}

// RecordingSource resolves the node's registered recording source, at every call,
// so a policy revision change is seen without a restart. It fails when the node
// has none.
type RecordingSource interface {
	Recording(ctx context.Context) (RecordingTarget, error)
}

var (
	defaultRegistryOnce sync.Once
	defaultRegistry     profile.Registry
	defaultRegistryErr  error
)

// DefaultRegistry is the registry of the pinned engine profiles embedded in the
// binary, loaded once. It is the registry a definition is checked against at
// save and the one the query engine evaluates it under.
func DefaultRegistry() (profile.Registry, error) {
	defaultRegistryOnce.Do(func() {
		files, err := profiles.Query()
		if err != nil {
			defaultRegistryErr = err
			return
		}
		defaultRegistry, defaultRegistryErr = profile.Load(files)
	})
	return defaultRegistry, defaultRegistryErr
}

// Definition is one rule as the catalogue holds it.
type Definition struct {
	Rule      Rule
	Revision  model.Revision
	Retired   bool
	Digest    model.Hash
	CreatedNS model.UnixNano
	UpdatedNS model.UnixNano
}

// Catalogue saves, retires, lists and serves rule definitions over control
// state. It keeps no state of its own.
type Catalogue struct {
	store     CatalogueControl
	registry  Registry
	recording RecordingSource
	now       func() model.UnixNano
}

// CatalogueOption configures a Catalogue.
type CatalogueOption func(*Catalogue)

// WithRecordingSource names the node's recording source. Without one a recording
// rule cannot be saved: nothing could admit its samples.
func WithRecordingSource(r RecordingSource) CatalogueOption {
	return func(c *Catalogue) { c.recording = r }
}

// WithCatalogueClock injects the clock that stamps commits (default: wall time).
func WithCatalogueClock(now func() model.UnixNano) CatalogueOption {
	return func(c *Catalogue) { c.now = now }
}

// NewCatalogue builds the catalogue over the control store and the profile
// registry definitions are checked under.
func NewCatalogue(store CatalogueControl, registry Registry, options ...CatalogueOption) (*Catalogue, error) {
	if store == nil || registry == nil {
		return nil, model.Fail(model.Invalid)
	}
	c := &Catalogue{store: store, registry: registry, now: func() model.UnixNano { return model.UnixNano(time.Now().UnixNano()) }}
	for _, o := range options {
		o(c)
	}
	return c, nil
}

// SaveCommand saves a new version of one rule. Command is the idempotency
// identity (a replay of a committed command answers the first result).
// ExpectedRevision is the catalogue revision the author read, 0 for a rule that
// does not exist yet. Rule's ID is the rule's identity; its Project and Version
// are ignored: the project is Project and the version is assigned.
type SaveCommand struct {
	Command          model.ID
	Project          model.ID
	Rule             Rule
	ExpectedRevision model.Revision
	Reason           string
}

// RetireCommand takes a rule out of evaluation.
type RetireCommand struct {
	Command          model.ID
	Project          model.ID
	Rule             model.ID
	ExpectedRevision model.Revision
	Reason           string
}

func catalogueInvalid(detail string) error {
	return &model.Fault{Code: model.Invalid, SafeDetail: detail, RequestID: model.NewID()}
}

// author checks the scope is a one-project organization administrator's.
func author(scope auth.Scope, project model.ID) error {
	if project == (model.ID{}) {
		return model.Fail(model.Invalid)
	}
	if scope.Permission() != auth.OrgAdmin {
		return model.Fail(model.Forbidden)
	}
	if !scope.AllowsProject(project) || len(scope.ProjectIDs()) != 1 {
		return model.Fail(model.NotFound)
	}
	return nil
}

// Save validates the rule, commits it as the next version and returns the
// committed definition.
func (c *Catalogue) Save(ctx context.Context, scope auth.Scope, cmd SaveCommand) (Definition, error) {
	if err := author(scope, cmd.Project); err != nil {
		return Definition{}, err
	}
	if cmd.Command == (model.ID{}) || cmd.Rule.ID == (model.ID{}) {
		return Definition{}, model.Fail(model.Invalid)
	}
	rule := cmd.Rule
	rule.Project, rule.Version = cmd.Project, 1
	// The version is read, not trusted: the compare-and-set on the revision is what
	// makes a stale read lose. A replay of a committed command reads the state it
	// moved and is answered from the first result before any of this is applied.
	prior, found, err := c.store.RuleDefinition(ctx, scope, cmd.Project, rule.ID)
	if err != nil {
		return Definition{}, err
	}
	if found {
		rule.Version = prior.Version + 1
	}
	if err = rule.Check(c.registry); err != nil {
		return Definition{}, err
	}
	if err = c.checkRecording(ctx, rule); err != nil {
		return Definition{}, err
	}
	canonical, err := model.CanonicalJSON(rule)
	if err != nil {
		return Definition{}, model.Fail(model.Invalid)
	}
	// The command travels as JSON, which compacts and HTML-escapes a raw
	// definition; the digest control verifies is over those exact bytes.
	definition, err := json.Marshal(json.RawMessage(canonical))
	if err != nil {
		return Definition{}, model.Fail(model.Invalid)
	}
	if _, err = transact(ctx, c.store, scope, cmd.Command, control.RuleCommand{Operation: control.RuleOpDefine, Definition: &control.RuleDefinitionApply{
		Project: cmd.Project, Rule: rule.ID, ExpectedRevision: cmd.ExpectedRevision, Definition: definition,
		Digest: model.Hash(sha256.Sum256(definition)), Reason: cmd.Reason, At: c.now()}}); err != nil {
		return Definition{}, err
	}
	return c.read(ctx, scope, cmd.Project, rule.ID)
}

// Retire takes a rule out of evaluation. Its history stays; saving a new
// version brings it back.
func (c *Catalogue) Retire(ctx context.Context, scope auth.Scope, cmd RetireCommand) (Definition, error) {
	if err := author(scope, cmd.Project); err != nil {
		return Definition{}, err
	}
	if cmd.Command == (model.ID{}) || cmd.Rule == (model.ID{}) {
		return Definition{}, model.Fail(model.Invalid)
	}
	if _, err := transact(ctx, c.store, scope, cmd.Command, control.RuleCommand{Operation: control.RuleOpRetireRule, Definition: &control.RuleDefinitionApply{
		Project: cmd.Project, Rule: cmd.Rule, ExpectedRevision: cmd.ExpectedRevision, Reason: cmd.Reason, At: c.now()}}); err != nil {
		return Definition{}, err
	}
	return c.read(ctx, scope, cmd.Project, cmd.Rule)
}

// DeclareReplay is the operator's replay declaration for a rule of the
// catalogue: late evaluations of its grid points in [from, to] may notify. It is
// an organization administrator's, audited act (the declaration is committed by
// the same command that records an evaluation's replay window); without it a
// backfilled evaluation never notifies.
func (c *Catalogue) DeclareReplay(ctx context.Context, scope auth.Scope, project, rule model.ID, from, to model.UnixNano, reason string) error {
	if err := author(scope, project); err != nil {
		return err
	}
	d, err := c.read(ctx, scope, project, rule)
	if err != nil {
		return err
	}
	_, err = (&Committer{control: c.store}).DeclareReplay(ctx, scope, d.Rule, from, to, reason, c.now())
	return err
}

// Definition reads one rule's definition.
func (c *Catalogue) Definition(ctx context.Context, scope auth.Scope, project, rule model.ID) (Definition, error) {
	return c.read(ctx, scope, project, rule)
}

func (c *Catalogue) read(ctx context.Context, scope auth.Scope, project, rule model.ID) (Definition, error) {
	rec, found, err := c.store.RuleDefinition(ctx, scope, project, rule)
	if err != nil {
		return Definition{}, err
	}
	if !found {
		return Definition{}, model.Fail(model.NotFound)
	}
	return decodeDefinition(rec)
}

// List returns the project's definitions (retired ones included), in rule ID
// order, to a scope that may read the project.
func (c *Catalogue) List(ctx context.Context, scope auth.Scope, project model.ID) ([]Definition, error) {
	recs, err := c.store.RuleDefinitions(ctx, scope, project)
	if err != nil {
		return nil, err
	}
	out := make([]Definition, 0, len(recs))
	for _, rec := range recs {
		d, err := decodeDefinition(rec)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, nil
}

// Rules lists the active definitions of the project, the newest version of each:
// it is the RuleSource the background workers evaluate. A retired rule is not
// listed. The scope is the project-scoped read scope of the worker principal.
func (c *Catalogue) Rules(ctx context.Context, scope auth.Scope, project model.ID) ([]Rule, error) {
	defs, err := c.List(ctx, scope, project)
	if err != nil {
		return nil, err
	}
	out := make([]Rule, 0, len(defs))
	for _, d := range defs {
		if !d.Retired {
			out = append(out, d.Rule)
		}
	}
	return out, nil
}

// decodeDefinition decodes a record, refusing one that does not name its own
// rule, project and version: a record that disagrees with itself is corrupt, never
// evaluated.
func decodeDefinition(rec control.RuleDefinitionRecord) (Definition, error) {
	var rule Rule
	if json.Unmarshal(rec.Definition, &rule) != nil || rule.ID != rec.Rule || rule.Project != rec.Project || rule.Version != rec.Version {
		return Definition{}, model.Fail(model.Corrupt)
	}
	return Definition{Rule: rule, Revision: rec.Revision, Retired: rec.Retired, Digest: rec.Digest, CreatedNS: rec.CreatedNS, UpdatedNS: rec.UpdatedNS}, nil
}

// checkRecording validates a recording rule against the node's recording source:
// the source must exist, belong to the rule's project and be allowed to write
// metrics, and every configured output label must be a value the source policy
// enumerates (the same test C03 applies to each record, so a rule that is saved
// is one whose output is not refused for its configured labels).
func (c *Catalogue) checkRecording(ctx context.Context, rule Rule) error {
	if rule.Kind != KindRecording {
		return nil
	}
	if c.recording == nil {
		return catalogueInvalid(ReasonRecordingSourceUnavailable)
	}
	target, err := c.recording.Recording(ctx)
	if err != nil || target.Project != rule.Project || !target.Policy.Enabled {
		return catalogueInvalid(ReasonRecordingSourceUnavailable)
	}
	allowsMetric := false
	for _, k := range target.Policy.Kinds {
		allowsMetric = allowsMetric || k == model.Metric
	}
	if !allowsMetric {
		return catalogueInvalid(ReasonRecordingSourceUnavailable)
	}
	for _, label := range rule.Labels {
		allowed := false
		for _, v := range target.Policy.Labels[label.Name] {
			allowed = allowed || v == label.Value
		}
		if !allowed {
			return catalogueInvalid(ReasonRecordingLabelNotAllowed)
		}
	}
	return nil
}
