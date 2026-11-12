// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore

import (
	"context"
	"errors"
	"testing"

	"soundpost/internal/artifacts"
	"soundpost/internal/model"
)

func fixedPins(n int, err error) func() (int, error) { return func() (int, error) { return n, err } }

func pinnedCode(err error) model.Code {
	var fault *model.Fault
	if errors.As(err, &fault) {
		return fault.Code
	}
	return ""
}

// A live journal pin in either group pins every root (a pin names no artifact), an
// unreadable source is an error and never "no pin", and a source that is not wired
// is unavailable.
func TestJournalPinsAreConservativeAndFailClosed(t *testing.T) {
	ctx := context.Background()
	root := model.NewID()
	ask := func(p journalPins) (bool, error) { return p.Pinned(ctx, model.NewID(), model.NewID(), root) }
	for name, tc := range map[string]struct {
		p      journalPins
		pinned bool
		code   model.Code
	}{
		"no pins":                 {journalPins{data: fixedPins(0, nil), control: fixedPins(0, nil)}, false, ""},
		"a data pin":              {journalPins{data: fixedPins(1, nil), control: fixedPins(0, nil)}, true, ""},
		"a control pin":           {journalPins{data: fixedPins(0, nil), control: fixedPins(2, nil)}, true, ""},
		"data pins unreadable":    {journalPins{data: fixedPins(0, model.Fail(model.Unavailable)), control: fixedPins(0, nil)}, false, model.Unavailable},
		"control pins unreadable": {journalPins{data: fixedPins(0, nil), control: fixedPins(0, model.Fail(model.Corrupt))}, false, model.Corrupt},
		"no data source":          {journalPins{control: fixedPins(0, nil)}, false, model.Unavailable},
		"no control source":       {journalPins{data: fixedPins(0, nil)}, false, model.Unavailable},
	} {
		got, err := ask(tc.p)
		if got != tc.pinned || pinnedCode(err) != tc.code {
			t.Errorf("%s: pinned=%v err=%v, want pinned=%v code=%q", name, got, err, tc.pinned, tc.code)
		}
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if got, err := (journalPins{data: fixedPins(0, nil), control: fixedPins(0, nil)}).Pinned(cancelled, model.ID{}, model.ID{}, root); got || err == nil {
		t.Errorf("a cancelled context answered %v %v", got, err)
	}
	var _ artifacts.SnapshotPins = journalPins{}
}

// The constructor refuses missing parts instead of building a lifecycle that would
// panic or silently skip a fence (a typed-nil retention service is not "set").
func TestNewArtifactLifecycleRefusesMissingParts(t *testing.T) {
	if _, err := NewArtifactLifecycle(nil, nil, nil, nil); pinnedCode(err) != model.Invalid {
		t.Fatalf("all parts missing: %v", err)
	}
	if _, err := bindArtifactLifecycle(nil, nil, journalPins{}, nil, nil); pinnedCode(err) != model.Invalid {
		t.Fatalf("no service: %v", err)
	}
}
