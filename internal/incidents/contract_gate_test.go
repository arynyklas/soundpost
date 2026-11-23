// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package incidents_test

import (
	"context"
	"testing"

	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/incidents"
	"github.com/arynyklas/soundpost/internal/model"
)

// D93: title, note and external link records are unreadable by the previous release, so before the
// installation is contracted they are refused (Unsupported) and nothing is written; ack and reads work.
func TestIncidentRecordedActionsNeedAContractedInstallation(t *testing.T) {
	f := newFx(t)
	id := model.ID{0xd9}
	f.openIncident(id)
	set := func(contracted bool) {
		if err := f.store.Update(f.ctx, func(st *control.State) error {
			o := st.Orgs[f.org.String()]
			if contracted {
				o.Settings[model.IndexesContractedKey] = []byte(`true`)
			} else {
				delete(o.Settings, model.IndexesContractedKey)
			}
			st.Orgs[f.org.String()] = o
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	set(false)
	version := model.Revision(1)
	ext := f.typed(id, version, incidents.TypeExternalBegin)
	ext.External = &model.ExternalOp{Provider: "gitlab", Kind: model.ExternalBegin, Marker: "m", Project: "g/p", Until: model.UnixNano(f.now.UnixNano()) + 60*sec}
	for _, a := range []incidents.Action{f.title(id, version, "t"), f.note(id, version, "n"), ext} {
		_, err := f.act(f.a, a)
		if !isCode(err, model.Unsupported) || detailOf(err) != incidents.DetailNeedsContracted {
			t.Fatalf("%s before contraction: %v", a.Type, err)
		}
	}
	if s := f.get(id); s.Version != 1 {
		t.Fatalf("a refused action wrote: %+v", s)
	}
	if st := f.mustAct(f.a, f.human(f.a, id, 1, incidents.TypeAck, "")); st.Version != 2 {
		t.Fatalf("ack must not need contraction: %+v", st)
	}
	set(true)
	if st := f.mustAct(f.a, f.title(id, 2, "t")); st.Title != "t" {
		t.Fatalf("title after contraction: %+v", st)
	}
}

// D94: the control-state format marker goes up before the first title, note or link record (the previous release refuses to start on it),
// never for a refused action or an ack, and a marker that cannot be written refuses the write.
func TestIncidentRecordedActionsRaiseTheFormatMarkerFirst(t *testing.T) {
	f := newFx(t)
	id := model.ID{0xd4}
	f.openIncident(id)
	if err := f.store.Update(f.ctx, func(st *control.State) error {
		o := st.Orgs[f.org.String()]
		o.Settings[model.IndexesContractedKey] = []byte(`true`)
		st.Orgs[f.org.String()] = o
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	marker := func() uint8 {
		var m uint8
		if err := f.store.View(f.ctx, func(st control.State) error { m = st.BearerHashKeyVersion; return nil }); err != nil {
			t.Fatal(err)
		}
		return m
	}
	if m := marker(); m >= model.FormatMarkerRecords {
		t.Fatalf("the marker is up before any record: %d", m)
	}
	if st := f.mustAct(f.a, f.human(f.a, id, 1, incidents.TypeAck, "")); st.Version != 2 || marker() >= model.FormatMarkerRecords {
		t.Fatalf("an ack raised the marker or failed: %+v marker %d", st, marker())
	}
	if _, err := f.act(f.a, f.title(id, 2, "")); err == nil || marker() >= model.FormatMarkerRecords {
		t.Fatalf("a refused title raised the marker: %v marker %d", err, marker())
	}
	if st := f.mustAct(f.a, f.title(id, 2, "named")); st.Title != "named" || marker() != model.FormatMarkerRecords {
		t.Fatalf("title: %+v marker %d", st, marker())
	}
	if st := f.mustAct(f.a, f.note(id, 3, "n")); st.Version != 4 || marker() != model.FormatMarkerRecords {
		t.Fatalf("note: %+v marker %d", st, marker())
	}
}

type failingUpdate struct{ *control.Store }

func (failingUpdate) Update(context.Context, func(*control.State) error) error {
	return model.Fail(model.Unavailable)
}

func TestIncidentRecordedActionIsRefusedWhenTheMarkerCannotBeWritten(t *testing.T) {
	f := newFx(t)
	id := model.ID{0xd5}
	f.openIncident(id)
	if err := f.store.Update(f.ctx, func(st *control.State) error {
		o := st.Orgs[f.org.String()]
		o.Settings[model.IndexesContractedKey] = []byte(`true`)
		st.Orgs[f.org.String()] = o
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	svc, err := incidents.New(failingUpdate{f.store}, fixedClock{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.Act(f.ctx, f.scope(f.a), f.title(id, 1, "named"), model.UnixNano(f.now.UnixNano())); !isCode(err, model.Unavailable) {
		t.Fatalf("title without a writable marker: %v", err)
	}
	if s := f.get(id); s.Version != 1 || s.Title != "" {
		t.Fatalf("the refused title wrote: %+v", s)
	}
}
