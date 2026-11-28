// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package sources

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// startState starts the rig's host over the real node with a scrape state store
// (what `soundpost serve` hands the host under the node's data directory).
func (r *hostRig) startState(t *testing.T, store *ScrapeStateStore) *ScrapeHost {
	t.Helper()
	_, specs := r.specsFromConfig(t)
	ctx, cancel := context.WithCancel(context.Background())
	h, err := startScrapeHost(ctx, ScrapeHostDeps{Auth: r.f.app.Auth, Ingest: r.ingest, Secrets: r.reader, State: store}, specs,
		func(tg *ScrapeTarget) { tg.Egress.loopbackOK = true })
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); h.Close() })
	return h
}

// A corrupt state file is a typed health reason of the target, never "nothing
// seen": the exporter is not contacted, nothing is admitted, and the target
// recovers by itself once the operator removed the file.
func TestScrapeHostSurfacesCorruptStateInHealth(t *testing.T) {
	r := newHostRig(t)
	store, err := OpenScrapeStateStore(filepath.Join(t.TempDir(), "scrape-state"))
	if err != nil {
		t.Fatal(err)
	}
	path, err := store.path("wiring")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	h := r.startState(t, store)
	waitFor(t, "state_corrupt", 20*time.Second, func() bool { return r.only(t, h).Reason == ScrapeReasonStateCorrupt })
	time.Sleep(1500 * time.Millisecond) // a second cycle over the same file
	if st := r.only(t, h); st.Reason != ScrapeReasonStateCorrupt || st.OK() || st.Cycles < 2 {
		t.Fatalf("status %+v", st)
	}
	if ok, deny := r.exporter.counts(); ok != 0 || deny != 0 || r.ingest.admitted.Load() != 0 {
		t.Fatalf("with untrusted state the exporter was contacted (%d ok, %d denied) or %d batches admitted", ok, deny, r.ingest.admitted.Load())
	}
	if raw, _ := os.ReadFile(path); string(raw) != "{broken" {
		t.Fatalf("the damaged file was rewritten: %q", raw)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "recovery", 20*time.Second, func() bool { return r.only(t, h).OK() })
}

// The host keeps the carried series across a restart of the whole host, and the
// marker it admits for the series that vanished is what the real query engine
// answers: the series is absent, not shown from its last sample for the lookback.
func TestScrapeHostRestartKeepsTheCarriedSeriesAndTheMarkerIsQueryable(t *testing.T) {
	r := newHostRig(t)
	dir := filepath.Join(t.TempDir(), "scrape-state")
	open := func() *ScrapeStateStore {
		store, err := OpenScrapeStateStore(dir)
		if err != nil {
			t.Fatal(err)
		}
		return store
	}
	r.exporter.body.Store("# TYPE " + hostMetric + " gauge\n" + hostMetric + "{job=\"api\"} 41\n# TYPE wiring_gone gauge\nwiring_gone{job=\"api\"} 7\n# EOF\n")
	first := r.startState(t, open())
	waitFor(t, "first healthy cycle", 20*time.Second, func() bool { st := r.only(t, first); return st.OK() && st.Last.Samples == 2 })
	if got := r.queryMetric(t, "wiring_gone"); len(got) != 1 || got[0] != 7 {
		t.Fatalf("the series before the restart: %v", got)
	}
	first.Close() // the node goes down

	r.exporter.body.Store("# TYPE " + hostMetric + " gauge\n" + hostMetric + "{job=\"api\"} 42\n# EOF\n")
	second := r.startState(t, open())
	waitFor(t, "the marker of the series that vanished while the node was down", 20*time.Second, func() bool {
		st := r.only(t, second)
		return st.OK() && st.Last.StaleMarkers == 1
	})
	if got := r.queryMetric(t, "wiring_gone"); len(got) != 0 {
		t.Fatalf("the series that vanished while the node was down is still visible after the restart: %v", got)
	}
	if got := r.queryMetric(t, hostMetric); len(got) != 1 || got[0] != 42 {
		t.Fatalf("the series that stayed: %v", got)
	}
}

// Each state failure is its own closed health reason.
func TestScrapeHostMapsStateErrorsToTypedReasons(t *testing.T) {
	for reason, want := range map[ScrapeStateReason]ScrapeReason{
		ScrapeStateCorrupt:     ScrapeReasonStateCorrupt,
		ScrapeStateUnavailable: ScrapeReasonStateUnavailable,
		ScrapeStateTooLarge:    ScrapeReasonStateTooLarge,
	} {
		h := &ScrapeHost{}
		tgt := &scrapeHosted{alias: "x"}
		// a state failure after the fetch carries the cycle's result; before it, none
		for _, res := range []ScrapeResult{{}, {Target: "x"}} {
			h.record(tgt, res, &ScrapeStateError{Reason: reason})
			if tgt.reason != want {
				t.Errorf("%s (result %q): reason %q, want %q", reason, res.Target, tgt.reason, want)
			}
		}
	}
	var se *ScrapeStateError
	if !errors.As(error(&ScrapeStateError{Reason: ScrapeStateCorrupt}), &se) || se.Error() != "sources: scrape state: state_corrupt" {
		t.Fatalf("error text %q", se.Error())
	}
}
