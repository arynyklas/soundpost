// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package control

import (
	"context"

	"github.com/arynyklas/soundpost/internal/model"
)

// RedactRetainedLogOnlyForTest is the first half of RedactRetainedControlCommands: it rewrites the
// retained commands of this node's control group with the pass's own redaction function and stops
// there. It cuts no snapshot and compacts nothing, so a voter that is behind the leader is still
// caught up from the rewritten retained log (the pass itself compacts onto a snapshot a lagging
// voter would install instead).
func (s *Store) RedactRetainedLogOnlyForTest(ctx context.Context) error {
	g := s.ReplicaGroup()
	st, err := s.localState()
	if err != nil {
		return err
	}
	erasures, finished := controlJournalScope(st)
	if erasures == 0 || !finished {
		return model.Fail(model.Invalid)
	}
	redactor := &controlRedactor{s: s}
	_, err = g.RedactMachineCommands(ctx, erasures, redactor.redact)
	return replicaFault(err)
}

// RetainedCommandShape counts the distinct control payloads a group retains by what they are.
type RetainedCommandShape struct {
	Patches, PatchesWithBase, PatchesWithoutBase, Replacements, Deltas int
}

// RetainedCommandShapeForTest reads every control payload the group retains (the retry table, the
// log and the journal) through a redaction that changes nothing.
func (s *Store) RetainedCommandShapeForTest(ctx context.Context) (RetainedCommandShape, error) {
	var shape RetainedCommandShape
	st, err := s.localState()
	if err != nil {
		return shape, err
	}
	erasures, _ := controlJournalScope(st)
	if erasures == 0 {
		erasures = 1
	}
	_, err = s.ReplicaGroup().RedactMachineCommands(ctx, erasures, func(payload []byte) ([]byte, bool, error) {
		cmd, derr := decodeControlCommand(payload)
		if derr != nil {
			return nil, false, derr
		}
		switch {
		case cmd.patch != nil:
			shape.Patches++
			if cmd.patch.Base == "" {
				shape.PatchesWithoutBase++
			} else {
				shape.PatchesWithBase++
			}
		case cmd.replacement != nil:
			shape.Replacements++
		case cmd.delta != nil:
			shape.Deltas++
		}
		return payload, false, nil
	})
	return shape, replicaFault(err)
}
