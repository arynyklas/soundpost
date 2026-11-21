// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore

import (
	"testing"

	"github.com/arynyklas/soundpost/internal/jobs"
	"github.com/arynyklas/soundpost/internal/model"
)

// A job update that committed and was erased at once by a deletion over its evidence is final for
// the journal producer (09.08x-W3): repeating the row could only erase again, so the producer
// advances past it instead of stopping the pass at the same row forever. A not-found of anything
// else, and every transient code, still stops the call so the row is retried.
func TestJobProducerTreatsAnErasedUpdateAsFinal(t *testing.T) {
	erased := model.Fail(model.NotFound)
	erased.SafeDetail = jobs.DetailErased
	if !rejectedForGood(erased) {
		t.Fatal("an update erased at once would wedge the job journal producer on its row")
	}
	for name, err := range map[string]error{
		"a missing job":  model.Fail(model.NotFound),
		"unavailable":    model.Fail(model.Unavailable),
		"corrupt":        model.Fail(model.Corrupt),
		"not a fault":    errTest("boom"),
		"another detail": func() error { f := model.Fail(model.NotFound); f.SafeDetail = "incident_erased"; return f }(),
	} {
		if rejectedForGood(err) {
			t.Errorf("%s is retried, not final", name)
		}
	}
}

type errTest string

func (e errTest) Error() string { return string(e) }
