// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package link

import (
	"context"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/storage"
	"math"
)

const (
	RelationExplicit    = "explicit"
	RelationTimeOverlap = "time_overlap_inference"
	maxReferences       = 128
)

// Reference names a target by identity only. No field (including a build or
// content hash) is an authorization carrier.
type Reference struct {
	Project  model.ID `json:"project_id"`
	Build    model.ID `json:"build_id"`
	Kind     string   `json:"kind"`
	ID       model.ID `json:"id"`
	Relation string   `json:"relation"`
}

// ResolvedReference carries the reference only when it resolved. A missing,
// unauthorized, foreign-org or unsupported target is the same zero value.
type ResolvedReference struct {
	Reference *Reference `json:"reference,omitempty"`
	Available bool       `json:"available"`
}

type Records interface {
	Scan(context.Context, auth.Scope, storage.ScanRequest) (storage.RowIterator, error)
}
type Artifacts interface {
	Lookup(context.Context, auth.Scope, model.ID) (model.ArtifactReferenceIntent, error)
}
type Revalidator interface {
	Revalidate(context.Context, auth.Scope) error
}
type Resolver struct {
	scope     Revalidator
	records   Records
	artifacts Artifacts
	issues    IssueIndex
}

// New requires the revalidator and the record reader. artifacts may be nil, in
// which case artifact references are unavailable rather than fabricated.
func New(scope Revalidator, records Records, artifacts Artifacts) (*Resolver, error) {
	if scope == nil || records == nil {
		return nil, model.Fail(model.Invalid)
	}
	return &Resolver{scope: scope, records: records, artifacts: artifacts}, nil
}

type recordTarget struct {
	kind  model.Kind
	field string
}

func recordTargets(kind string) (recordTarget, bool) {
	switch kind {
	case "profile":
		return recordTarget{model.Profile, "profile_id"}, true
	case "trace":
		return recordTarget{model.SpanKind, "trace_id"}, true
	case "replay":
		return recordTarget{model.Replay, "replay_id"}, true
	case "error":
		return recordTarget{model.ErrorKind, "occurrence_id"}, true
	case "job":
		return recordTarget{model.JobAttempt, "job_id"}, true
	}
	return recordTarget{}, false
}

// Resolve independently authorizes every target. For each reference the
// scope's project check and a fresh revalidation come first; only then is any
// index, cache or artifact metadata consulted. Every failure to resolve is the
// identical unavailable value, so wrong-scope and missing are indistinguishable.
func (r *Resolver) Resolve(ctx context.Context, scope auth.Scope, refs []Reference) ([]ResolvedReference, error) {
	if len(refs) > maxReferences {
		return nil, model.Fail(model.TooLarge)
	}
	out := make([]ResolvedReference, len(refs))
	for i, ref := range refs {
		if err := r.scope.Revalidate(ctx, scope); err != nil {
			return nil, model.Fail(model.NotFound)
		}
		if !scope.AllowsProject(ref.Project) || ref.ID == (model.ID{}) || ref.Relation != RelationExplicit && ref.Relation != RelationTimeOverlap {
			continue
		}
		if !r.exists(ctx, scope, ref) {
			continue
		}
		owned := ref
		out[i] = ResolvedReference{Reference: &owned, Available: true}
	}
	if err := r.scope.Revalidate(ctx, scope); err != nil {
		return nil, model.Fail(model.NotFound)
	}
	return out, nil
}
func (r *Resolver) exists(ctx context.Context, scope auth.Scope, ref Reference) bool {
	if ref.Kind == "artifact" {
		if r.artifacts == nil || ref.Build == (model.ID{}) {
			return false
		}
		read, err := scope.ArtifactReadScope(ctx, ref.Project)
		if err != nil {
			return false
		}
		a, err := r.artifacts.Lookup(ctx, read, ref.ID)
		return err == nil && a.ID == ref.ID && a.Manifest.Org == scope.OrgID() && a.Manifest.Project == ref.Project && a.Manifest.Build == ref.Build
	}
	target, ok := recordTargets(ref.Kind)
	if !ok {
		return false
	}
	rows, err := r.records.Scan(ctx, scope, storage.ScanRequest{Projects: []model.ID{ref.Project}, Signal: target.kind, Start: math.MinInt64, End: math.MaxInt64, Projection: []storage.Field{storage.FieldID}, Selectors: []storage.Matcher{{Target: storage.MatchField, Name: target.field, Op: storage.MatchEqual, Literal: storage.Literal{Kind: storage.LiteralString, String: ref.ID.String()}}}})
	if err != nil {
		return false
	}
	page, err := rows.Next(ctx)
	found := err == nil && page.Len() > 0
	return rows.Close() == nil && found
}

// IssueIndex answers which issue holds each of a project's error occurrences. The read is made under the
// caller's own scope, so an index that cannot authorize it answers an error and nothing resolves.
type IssueIndex interface {
	IssuesOf(ctx context.Context, scope auth.Scope, project model.ID, occurrences []model.ID) (map[model.ID]model.ID, error)
}

// WithIssues binds the occurrence-to-issue index. Without one no occurrence resolves to an issue.
func (r *Resolver) WithIssues(index IssueIndex) *Resolver {
	r.issues = index
	return r
}

// IssuesBound reports whether an occurrence-to-issue index is bound.
func (r *Resolver) IssuesBound() bool { return r.issues != nil }

// IssuesOf maps error occurrences to the issue holding each. Scope comes first: a project outside the scope or a
// stale scope yields nothing before any index is read, and an occurrence is mapped only if the error record itself
// is readable under the scope, so an occurrence that is missing, foreign or unreadable is simply absent from the
// answer, never distinguishable. The answer holds only occurrences that resolved.
func (r *Resolver) IssuesOf(ctx context.Context, scope auth.Scope, project model.ID, occurrences []model.ID) map[model.ID]model.ID {
	out := map[model.ID]model.ID{}
	if r.issues == nil || len(occurrences) == 0 || len(occurrences) > maxReferences*2 || !scope.AllowsProject(project) || r.scope.Revalidate(ctx, scope) != nil {
		return out
	}
	var readable []model.ID
	for _, id := range occurrences {
		if id != (model.ID{}) && r.exists(ctx, scope, Reference{Project: project, Kind: "error", ID: id, Relation: RelationExplicit}) {
			readable = append(readable, id)
		}
	}
	if len(readable) == 0 {
		return out
	}
	held, err := r.issues.IssuesOf(ctx, scope, project, readable)
	if err != nil || r.scope.Revalidate(ctx, scope) != nil {
		return out
	}
	for _, id := range readable {
		if issue, ok := held[id]; ok && issue != (model.ID{}) {
			out[id] = issue
		}
	}
	return out
}
