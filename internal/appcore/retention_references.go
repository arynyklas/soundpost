// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore

import (
	"context"
	"soundpost/internal/artifacts"
	"soundpost/internal/model"
	"soundpost/internal/replays"
	"soundpost/internal/retention"
	"soundpost/internal/storage"
)

// gatedReference is one References source and the candidates it is asked about.
// Both real sources already answer zero for a candidate of another kind
// (artifacts.Lifecycle for anything that is not a blob root, replays.Service for
// anything that is not a replay chunk); the gate makes that a property of the
// composition too, so the artifact lifecycle, whose answer for an unreferenced
// expired root TAKES THE GC FENCE as a side effect, is never called for a record,
// and neither source is called for the other's candidates.
type gatedReference struct {
	handles func(storage.EraseCandidate) bool
	source  retention.References
}

// referenceSet is retention.References over several sources: a candidate is
// retained until the latest deadline any source that handles it answers, so any
// source that pins a candidate pins it. The first error of any consulted source is
// the answer (the pass fails closed: nothing is erased on the strength of the
// sources that did answer). Sources are consulted in order, and none is skipped
// after another has answered.
type referenceSet []gatedReference

func composeReferences(parts ...gatedReference) (retention.References, error) {
	if len(parts) == 0 {
		return nil, model.Fail(model.Invalid)
	}
	for _, p := range parts {
		if p.source == nil || p.handles == nil {
			return nil, model.Fail(model.Invalid)
		}
	}
	return referenceSet(append([]gatedReference(nil), parts...)), nil
}

func (s referenceSet) LatestReference(ctx context.Context, c storage.EraseCandidate) (model.UnixNano, error) {
	var latest model.UnixNano
	for _, p := range s {
		if !p.handles(c) {
			continue
		}
		ref, err := p.source.LatestReference(ctx, c)
		if err != nil {
			return 0, err
		}
		latest = max(latest, ref)
	}
	return latest, nil
}

func isBlobCandidate(c storage.EraseCandidate) bool { return c.Blob != nil }

func isReplayCandidate(c storage.EraseCandidate) bool {
	return c.Kind == model.Replay && c.Record != nil && c.Record.Payload.Replay != nil
}

// NewRetentionReferences is the composite source: the artifact lifecycle for
// artifact roots and the replay service for replay chunks (a checkpoint outlives
// its own deadline while a retained chunk depends on it).
func NewRetentionReferences(life *artifacts.Lifecycle, replay *replays.Service) (retention.References, error) {
	if life == nil || replay == nil {
		return nil, model.Fail(model.Invalid)
	}
	return composeReferences(
		gatedReference{handles: isBlobCandidate, source: life},
		gatedReference{handles: isReplayCandidate, source: replay},
	)
}

// BindRetentionReferences installs NewRetentionReferences as the References
// source of the expiry pass. retention takes one source and refuses a second
// binding, so this is the only place that binds; nothing else may call
// UseReferences.
func BindRetentionReferences(ret *retention.Service, life *artifacts.Lifecycle, replay *replays.Service) error {
	if ret == nil {
		return model.Fail(model.Invalid)
	}
	set, err := NewRetentionReferences(life, replay)
	if err != nil {
		return err
	}
	return ret.UseReferences(set)
}
