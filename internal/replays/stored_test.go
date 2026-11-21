// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replays

import (
	"github.com/arynyklas/soundpost/internal/model"
	"testing"
	"time"
)

func (f *fx) checkStored(t tenant, chunks ...model.ReplayChunk) error {
	f.t.Helper()
	scope, err := f.grant(t).Scope()
	if err != nil {
		f.t.Fatal(err)
	}
	return f.svc.CheckStored(f.ctx, scope, t.project, chunks)
}

// A replay is rooted by a checkpoint, never by a delta: RecordScope refuses the delta that
// would create the index, writes nothing, and the checkpoint then roots the replay normally.
func TestRecordRefusesADeltaThatWouldRootAReplay(t *testing.T) {
	f := newFx(t)
	r := newRecorder(f.wall())
	cp, d := r.cp(), r.delta()
	g := f.grant(f.main)
	until := f.wall() + model.UnixNano(24*time.Hour)
	settled := f.revision()
	if err := f.svc.Record(f.ctx, g, f.main.project, d, until); faultCode(err) != model.Conflict {
		t.Fatalf("a delta that would root the replay: %v, want conflict", err)
	}
	if got := f.revision(); got != settled {
		t.Fatalf("the refused delta wrote the control state (revision %d -> %d)", settled, got)
	}
	if err := f.svc.Record(f.ctx, g, f.main.project, cp, until); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Record(f.ctx, g, f.main.project, d, until); err != nil {
		t.Fatalf("the delta of an indexed replay: %v", err)
	}
}

// The stored chain is checked at intake: what is refused and what is deliberately not.
func TestCheckStoredRefusesWhatContradictsStoredChunks(t *testing.T) {
	f := newFx(t)
	r := newRecorder(f.wall())
	cp, d2, d3 := r.cp(), r.delta(), r.delta()
	f.mustAdmit(f.main, cp, d2)

	forgedD2 := d2
	forgedD2.Events = []model.MaskedEvent{{At: 1, Kind: "pointer", Node: 1, X: 9, Y: 9}}
	badPrevious := d3
	badPrevious.Previous = model.Hash{9}
	badCheckpoint := d3
	badCheckpoint.Checkpoint = model.Hash{9}
	foreignSession := d3
	foreignSession.Session = model.NewID()
	forgedD3 := d3
	forgedD3.Events = []model.MaskedEvent{{At: 1, Kind: "pointer", Node: 1, X: 9, Y: 9}}
	for name, chunks := range map[string][]model.ReplayChunk{
		"a different chunk at a stored sequence":              {forgedD2},
		"a delta whose previous hash is not the stored one":   {badPrevious},
		"a delta naming another checkpoint than the stored":   {badCheckpoint},
		"a session other than the stored chunks claim":        {foreignSession},
		"two different deltas at one sequence in one batch":   {d3, forgedD3},
		"a delta contradicting a forged predecessor in-batch": {forgedD2, d3},
	} {
		if err := f.checkStored(f.main, chunks...); faultCode(err) != model.Conflict {
			t.Errorf("%s: %v, want conflict", name, err)
		}
	}

	// What is not a conflict: the identical chunk again, the genuine next delta, a delta whose
	// predecessor is not stored yet (a read-time gap, not an intake refusal), a recorder-declared
	// gap delta whose previous hash is not the stored predecessor's, and a replay nothing is
	// stored for.
	gapped := d3
	gapped.Gap = true
	gapped.Previous = model.Hash{9}
	r.delta() // sequence 4 never arrives
	d5 := r.delta()
	other := newRecorder(f.wall())
	for name, chunks := range map[string][]model.ReplayChunk{
		"the identical stored chunk":                  {d2},
		"the genuine next delta":                      {d3},
		"a delta whose predecessor is not stored yet": {d5},
		"a recorder-declared gap delta":               {gapped},
		"a replay with nothing stored":                {other.cp(), other.delta()},
	} {
		if err := f.checkStored(f.main, chunks...); err != nil {
			t.Errorf("%s: %v, want accepted", name, err)
		}
	}
	if err := f.checkStored(f.main); err != nil {
		t.Errorf("an empty batch: %v", err)
	}
}
