// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"sort"

	"github.com/arynyklas/soundpost/internal/model"
)

// eraseCutoverBooks is the deletion hook's half for the notification ownership
// books (plan 06 task 09), a pure function of the state, the predicate and the
// transition time, like eraseJobBooks. Only a retirement covers a cutover: a
// record holds no telemetry, so a historical range or an entity deletion covers
// none. What a retirement drops is what the operator typed or supplied: every
// step's free-text reason and its evidence payload. What stays is the identity
// (the cutover, the owners, the source/version frontier), the revision, the
// phase, the epoch and, per step, the command, the principal, the transition,
// the time and the digests of the command and of the evidence, so the
// ownership audit trail outlives the project without its operator text. A
// record is marked with the erasing operation and is never covered again, so
// the function is idempotent. It returns how many records it changed.
//
// The deletion hook calls it once, from eraseControlBooks, next to the others:
//
//	func() (int, error) { return eraseCutoverBooks(st, p, at) },
func eraseCutoverBooks(st *State, p model.DeletePredicate, at model.UnixNano) (dropped int, err error) {
	keys := make([]string, 0, len(st.CutoverBooks))
	for key := range st.CutoverBooks {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		rec, _, err := loadCutover(st, key)
		if err != nil {
			return 0, err
		}
		if rec.Erased != nil || !p.RetiresProject(rec.Org, rec.Project) {
			continue
		}
		op := p.Operation
		rec.Erased = &op
		for i := range rec.Steps {
			rec.Steps[i].Reason, rec.Steps[i].Payload = "", nil
		}
		if err = storeCutover(st, key, rec); err != nil {
			return 0, err
		}
		dropped++
	}
	return dropped, nil
}
