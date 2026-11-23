// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore_test

import (
	"testing"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/incidents"
	"github.com/arynyklas/soundpost/internal/model"
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
