// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore_test

import (
	"context"
	"testing"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/incidents"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
)

func (n *workerNode) formatMarker() uint8 {
	n.t.Helper()
	var m uint8
	if err := n.app.Control.View(n.ctx, func(st model.ControlState) error { m = st.BearerHashKeyVersion; return nil }); err != nil {
		n.t.Fatal(err)
	}
	return m
}

func (n *workerNode) recordFormatPass() {
	n.t.Helper()
	w, err := n.app.NewWorkers(n.config(func(c *appcore.WorkerConfig) { c.Producers = []appcore.Producer{n.app.RecordFormatProducer()} }))
	if err != nil {
		n.t.Fatal(err)
	}
	n.tick(w)
}

// D94: a D92 write raises the format marker before it commits; an installation that already holds a D92 record without the marker (a build
// before D94 wrote it) gets it from the leader-only producer; one that holds none keeps the marker it has.
func TestRecordFormatMarkerIsRaisedByTheWriteAndRepairedByTheProducer(t *testing.T) {
	n := newWorkerNode(t)
	if err := n.app.Control.Update(n.ctx, func(st *model.ControlState) error {
		o := st.Orgs[n.org.String()]
		o.Settings[model.IndexesContractedKey] = []byte(`true`)
		st.Orgs[n.org.String()] = o
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	id, _, opened := n.openIncident()
	if m := n.formatMarker(); m != model.FormatMarkerBase {
		t.Fatalf("the marker before any D92 record: %d", m)
	}
	n.recordFormatPass()
	if m := n.formatMarker(); m != model.FormatMarkerBase {
		t.Fatalf("an installation with no D92 record got the marker: %d", m)
	}
	_, cred := n.member("format-writer@example.test", auth.IncidentsWrite)
	scope := n.scopeOf(cred, auth.IncidentsWrite)
	if _, err := n.app.Incidents.Act(n.ctx, scope, incidents.Action{CommandID: model.NewID(), ExpectedVersion: opened.Version, Type: incidents.TypeTitle, Title: "named", Target: incidents.Target{Project: n.project, Incident: id}}, workerNow); err != nil {
		t.Fatal(err)
	}
	if m := n.formatMarker(); m != model.FormatMarkerRecords {
		t.Fatalf("the title was committed without raising the marker: %d", m)
	}

	// an installation a build before D94 wrote: the record is there, the marker is not
	if err := n.app.Control.Update(n.ctx, func(st *model.ControlState) error { st.BearerHashKeyVersion = model.FormatMarkerBase; return nil }); err != nil {
		t.Fatal(err)
	}
	n.recordFormatPass()
	if m := n.formatMarker(); m != model.FormatMarkerRecords {
		t.Fatalf("the repair did not raise the marker: %d", m)
	}
}

// leaseTap is a producer that keeps the lease and the scopes of the pass it ran in, so a test can run another producer directly.
type leaseTap struct {
	lease  replica.FenceToken
	scopes appcore.ProducerScopes
	seen   bool
}

func (p *leaseTap) Produce(_ context.Context, scopes appcore.ProducerScopes, lease replica.FenceToken) (int, error) {
	p.lease, p.scopes, p.seen = lease, scopes, true
	return 0, nil
}

// The scan of the record-format repair reads the incident and issue books for a D92 record. It does so through the decode of the control state that
// every shared reader uses, never a decode of the whole blob of its own: it runs on every node that has not yet found the marker up.
func TestRecordFormatScanDoesNotDecodeTheControlBlob(t *testing.T) {
	n := newWorkerNode(t)
	n.openIncident() // an incident without a D92 record: the scan opens the incident book and finds nothing
	tap := &leaseTap{}
	w, err := n.app.NewWorkers(n.config(func(c *appcore.WorkerConfig) { c.Producers = []appcore.Producer{tap} }))
	if err != nil {
		t.Fatal(err)
	}
	n.tick(w)
	if !tap.seen {
		t.Fatal("the pass did not reach a producer")
	}
	scan := func() {
		t.Helper()
		if _, err := n.app.RecordFormatProducer().Produce(n.ctx, tap.scopes, tap.lease); err != nil {
			t.Fatal(err)
		}
	}
	scan() // what the first scan decodes is shared by the rest
	before := n.app.Control.DecodeStats()
	for range 10 {
		scan()
	}
	if got := n.app.Control.DecodeStats().Blobs - before.Blobs; got != 0 {
		t.Fatalf("10 scans decoded the whole blob %d times, want never", got)
	}
	if m := n.formatMarker(); m != model.FormatMarkerBase {
		t.Fatalf("a state with no D92 record got the marker: %d", m)
	}
}
