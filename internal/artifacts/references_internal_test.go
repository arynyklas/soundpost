// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package artifacts

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/arynyklas/soundpost/internal/artifacts/refledger"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/storage"
)

type viewOnly struct{ st model.ControlState }

func (v viewOnly) View(_ context.Context, fn func(model.ControlState) error) error { return fn(v.st) }
func (v viewOnly) Update(context.Context, func(*model.ControlState) error) error {
	return model.Fail(model.Unavailable)
}

type noGenerations struct{}

func (noGenerations) DeleteGeneration(context.Context, model.ID, []model.ID) (uint64, error) {
	return 0, nil
}

type noPinsAtAll struct{}

func (noPinsAtAll) Pinned(context.Context, model.ID, model.ID, model.ID) (bool, error) {
	return false, nil
}

func faultCode(err error) model.Code {
	var f *model.Fault
	if errors.As(err, &f) {
		return f.Code
	}
	return ""
}

type intentFx struct {
	org, project, root model.ID
	st                 model.ControlState
}

// newIntentFx is a control state with one artifact intent in the given state and, when ledger is
// not nil, its reference ledger. Nothing here is a real application: the fence's own invariant
// (the lifecycle writes the retired intent and the Retired ledger in one transition) is
// checked on hand-built states.
func newIntentFx(t *testing.T, state string, ledger *refledger.Ledger) *intentFx {
	t.Helper()
	f := &intentFx{org: model.NewID(), project: model.NewID(), root: model.NewID()}
	blob := model.BlobManifest{Org: f.org, Project: f.project, Root: f.root, RetainUntil: 100}
	intent := model.ArtifactReferenceIntent{ID: f.root, State: state,
		Manifest: model.ArtifactManifest{Org: f.org, Project: f.project, RetainUntil: 100}, Map: model.BlobReceipt{Manifest: blob}}
	o := model.ControlOrg{Settings: map[string]json.RawMessage{}}
	if ledger != nil {
		ledger.Project, ledger.Root, ledger.Seq = f.project, f.root, 1
		if err := refledger.Store(&o, f.project, ledger); err != nil {
			t.Fatal(err)
		}
	}
	f.st = model.ControlState{
		Orgs:            map[string]model.ControlOrg{f.org.String(): o},
		ArtifactIntents: map[string]model.ArtifactReferenceIntent{f.org.String() + ":" + f.project.String() + ":" + f.root.String(): intent},
	}
	return f
}

func (f *intentFx) key() string {
	return f.org.String() + ":" + f.project.String() + ":" + f.root.String()
}

func (f *intentFx) lifecycle(t *testing.T) *Lifecycle {
	t.Helper()
	l, err := NewLifecycle(&Service{}, LifecycleConfig{State: viewOnly{f.st}, Deletes: noGenerations{}, Pins: noPinsAtAll{}})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func (f *intentFx) candidate() storage.EraseCandidate {
	m := f.st.ArtifactIntents[f.key()].Map.Manifest
	return storage.EraseCandidate{Org: f.org, Project: f.project, Blob: &m}
}

func noop(model.ArtifactManifest, *refledger.Ledger, model.UnixNano) (bool, error) { return false, nil }

// 09.04-W5: the fence writes the retired intent and the Retired ledger in one transition, so a
// retired intent over a ledger that is missing, not fenced or rolled back is a ledger that was
// removed (together with its index entry and a recomputed anchor, which the digest and the
// anchor cannot tell) or rolled back: the lifecycle fails closed on it.
func TestRetiredIntentNeedsItsFenceLedger(t *testing.T) {
	for name, tc := range map[string]struct {
		ledger *refledger.Ledger
		ok     bool
	}{
		"fenced ledger":          {&refledger.Ledger{Retired: true}, true},
		"ledger removed":         {nil, false},
		"ledger rolled back":     {&refledger.Ledger{Entries: []refledger.Entry{{Kind: refledger.KindBuild, Cursor: model.Cursor{Group: model.NewID(), Index: 1}, RetainUntil: 5}}}, false},
		"ledger with no entries": {&refledger.Ledger{}, false},
	} {
		t.Run(name, func(t *testing.T) {
			f := newIntentFx(t, intentRetired, tc.ledger)
			_, err := one(f.org, f.project, f.root, nil, noop)(f.st, 1000)
			if tc.ok != (err == nil) || !tc.ok && faultCode(err) != model.Corrupt {
				t.Fatalf("one() answered %v", err)
			}
			got, err := f.lifecycle(t).LatestReference(context.Background(), f.candidate())
			switch {
			case tc.ok && (err != nil || got != 0):
				t.Fatalf("LatestReference of a fenced, retired root: %d %v", got, err)
			case !tc.ok && faultCode(err) != model.Corrupt:
				t.Fatalf("LatestReference answered %d %v over a retired intent with no fence", got, err)
			}
		})
	}
}

// A ledger fenced by an earlier build over a still-published intent is healed to retired by the
// next lifecycle operation on it; an unfenced ledger heals nothing.
func TestFencedLedgerOverPublishedIntentIsHealed(t *testing.T) {
	f := newIntentFx(t, intentPublished, &refledger.Ledger{Retired: true})
	p, err := one(f.org, f.project, f.root, nil, noop)(f.st, 1000)
	if err != nil || len(p.retire) != 1 || p.retire[0] != f.key() || len(p.ledgers) != 0 {
		t.Fatalf("plan %+v, %v", p, err)
	}
	g := newIntentFx(t, intentPublished, &refledger.Ledger{})
	if p, err = one(g.org, g.project, g.root, nil, noop)(g.st, 1000); err != nil || !p.empty() {
		t.Fatalf("an unfenced ledger planned %+v, %v", p, err)
	}
}
