// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replays

import (
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/policy"
)

// Validate is the closed-format check run before durable admission. It never
// reads or echoes chunk content: every failure is a fixed model fault. Source
// capture policy (replay enabled, revision) is enforced by policy.Normalize and
// model validation; this adds the chain, checkpoint and masked-format rules.
func (s *Service) Validate(grant policy.SourceGrant, chunk model.ReplayChunk) error {
	if _, err := grant.Scope(); err != nil {
		return err
	}
	return ValidateChunk(chunk)
}

// ValidateJSON strictly decodes one wire chunk (unknown fields such as html,
// text, attributes, css, url, canvas or body, and duplicate keys, are Invalid)
// and then validates it. Oversized input is TooLarge before decoding.
func (s *Service) ValidateJSON(grant policy.SourceGrant, raw []byte) (model.ReplayChunk, error) {
	if len(raw) > MaxChunkBytes {
		return model.ReplayChunk{}, model.Fail(model.TooLarge)
	}
	var chunk model.ReplayChunk
	if err := model.StrictJSON(raw, &chunk); err != nil {
		return model.ReplayChunk{}, model.Fail(model.Invalid)
	}
	if err := s.Validate(grant, chunk); err != nil {
		return model.ReplayChunk{}, err
	}
	return chunk, nil
}

// ValidateChunk is the stateless closed-format validation.
func ValidateChunk(c model.ReplayChunk) error {
	if c.Replay == (model.ID{}) || c.Session == (model.ID{}) || c.PolicyRevision == 0 {
		return model.Fail(model.Invalid)
	}
	if !supportedRecorders[c.Recorder] {
		return model.Fail(model.Unsupported)
	}
	seq, cp := uint64(c.Sequence), uint64(c.CheckpointSequence)
	if seq < 1 || seq > MaxSequence || cp < 1 || cp > seq {
		return model.Fail(model.Invalid)
	}
	zero := model.Hash{}
	if (seq == 1) != (c.Previous == zero) {
		return model.Fail(model.Invalid)
	}
	if cp == seq {
		// A checkpoint names no earlier dependency: its checkpoint field repeats
		// the previous hash (the recorder cannot self-reference its own hash).
		if c.Checkpoint != c.Previous {
			return model.Fail(model.Invalid)
		}
	} else if c.Checkpoint == zero {
		return model.Fail(model.Invalid)
	}
	if seq == 1 && cp != 1 {
		return model.Fail(model.Invalid)
	}
	d := c.Clock.Domain
	if c.Clock.Wall <= 0 || d.Host == (model.ID{}) || d.Boot == (model.ID{}) || d.Runtime == (model.ID{}) {
		return model.Fail(model.Invalid)
	}
	if len(c.Nodes) > 4096 || len(c.Events) > 4096 {
		return model.Fail(model.TooLarge)
	}
	ids := make(map[model.Uint64]struct{}, len(c.Nodes))
	for _, n := range c.Nodes {
		if n.ID == 0 || n.ID > maxNodeID || n.Parent > maxNodeID || n.Parent == n.ID || !nodeTags[n.Tag] || n.Text != "" && n.Text != "[masked]" || n.Class != "" && n.Class != "masked" {
			return model.Fail(model.Invalid)
		}
		if _, dup := ids[n.ID]; dup {
			return model.Fail(model.Invalid)
		}
		ids[n.ID] = struct{}{}
	}
	for _, e := range c.Events {
		if !eventKinds[e.Kind] || e.Node > maxNodeID || e.X < -maxCoordinate || e.X > maxCoordinate || e.Y < -maxCoordinate || e.Y > maxCoordinate {
			return model.Fail(model.Invalid)
		}
	}
	raw, err := model.CanonicalJSON(c)
	if err != nil {
		return model.Fail(model.Invalid)
	}
	if len(raw) > MaxChunkBytes {
		return model.Fail(model.TooLarge)
	}
	return nil
}
