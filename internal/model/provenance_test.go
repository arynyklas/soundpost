// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package model

import (
	"encoding/json"
	"math/rand/v2"
	"reflect"
	"testing"
)

func TestProvenanceWithGrowsToTheEarliestAndLatestTime(t *testing.T) {
	var p *Provenance
	for _, at := range []UnixNano{50, 10, 30, 30, 70} {
		p = p.With(at)
	}
	if want := (&Provenance{From: 10, To: 70}); !reflect.DeepEqual(p, want) {
		t.Fatalf("got %+v, want %+v", p, want)
	}
	if p.Validate() != nil {
		t.Fatalf("a provenance With built is invalid: %v", p.Validate())
	}
}

func TestProvenanceWithIgnoresUnsetTimes(t *testing.T) {
	p := &Provenance{From: 10, To: 20}
	for _, at := range []UnixNano{0, -5} {
		if got := p.With(at); got != p {
			t.Errorf("With(%d) = %+v, want the receiver", at, got)
		}
	}
	if got := (*Provenance)(nil).With(0); got != nil {
		t.Errorf("an unset time started a provenance: %+v", got)
	}
}

func TestProvenanceWithNeverChangesItsReceiver(t *testing.T) {
	p := &Provenance{From: 10, To: 20}
	for _, at := range []UnixNano{5, 15, 90} {
		_ = p.With(at)
	}
	if *p != (Provenance{From: 10, To: 20}) {
		t.Fatalf("With changed its receiver: %+v", *p)
	}
}

// The interval is the join of the times folded: any order of arrival gives the same one.
func TestProvenanceDoesNotDependOnTheOrderOfArrival(t *testing.T) {
	rng := rand.New(rand.NewPCG(3, 4))
	times := make([]UnixNano, 200)
	for i := range times {
		times[i] = UnixNano(1 + rng.Int64N(1_000_000))
	}
	var want *Provenance
	for _, at := range times {
		want = want.With(at)
	}
	for range 20 {
		rng.Shuffle(len(times), func(i, j int) { times[i], times[j] = times[j], times[i] })
		var got *Provenance
		for _, at := range times {
			got = got.With(at)
		}
		if *got != *want {
			t.Fatalf("got %+v, want %+v", *got, *want)
		}
	}
	for _, at := range times {
		if !want.Meets(at, at+1) {
			t.Fatalf("time %d is not covered by %+v", at, *want)
		}
	}
}

func TestProvenanceMeetsIsHalfOpenAtTheEnd(t *testing.T) {
	p := &Provenance{From: 10, To: 40}
	for _, c := range []struct {
		start, end UnixNano
		want       bool
	}{
		{40, 100, true},  // the interval ends at the start: closed
		{41, 100, false}, // after it
		{0, 10, false},   // the interval starts at the end: half-open
		{0, 11, true},
		{20, 30, true}, // inside
		{0, 100, true}, // spans it
	} {
		if got := p.Meets(c.start, c.end); got != c.want {
			t.Errorf("Meets(%d,%d) = %v, want %v", c.start, c.end, got, c.want)
		}
	}
	if (*Provenance)(nil).Meets(0, 1<<62) {
		t.Error("a state without a provenance meets no range: the window rule reads it")
	}
}

func TestProvenanceValidate(t *testing.T) {
	for name, c := range map[string]struct {
		p  Provenance
		ok bool
	}{
		"one point":     {Provenance{From: 5, To: 5}, true},
		"an interval":   {Provenance{From: 5, To: 9}, true},
		"unset from":    {Provenance{From: 0, To: 5}, false},
		"backwards":     {Provenance{From: 9, To: 5}, false},
		"negative from": {Provenance{From: -3, To: 5}, false},
		"zero":          {Provenance{}, false},
	} {
		if err := c.p.Validate(); (err == nil) != c.ok {
			t.Errorf("%s: Validate = %v, want ok=%v", name, err, c.ok)
		}
	}
}

// The wire form is an object {from_ns,to_ns} with decimal-string times, as every other time of the state.
func TestProvenanceWireForm(t *testing.T) {
	raw, err := json.Marshal(&Provenance{From: 10, To: 20})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"from_ns":"10","to_ns":"20"}`; string(raw) != want {
		t.Fatalf("got %s, want %s", raw, want)
	}
	var back Provenance
	if err = json.Unmarshal(raw, &back); err != nil || back != (Provenance{From: 10, To: 20}) {
		t.Fatalf("round trip: %+v %v", back, err)
	}
}
