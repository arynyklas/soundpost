// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"github.com/arynyklas/soundpost/internal/model"
	"testing"
	"time"
)

func TestProfilesReadNeverReadsOtherSignals(t *testing.T) {
	store, a, c, d := typedFixture(t)
	_, base := normalized(t, store, a, c, d)
	rows := typedRows(base.Records[0].Resource)
	scope := scanPermission(t, store, a, d, profilesRead)
	dir := t.TempDir()
	e, err := openTestEngine(t, dir, a, store)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { e.Close() }()
	profile, capability, loss := rows[10], rows[11], rows[12]
	otherCapability := capability
	otherCapability.ID = model.NewID()
	copyCap := *capability.Payload.Capability
	copyCap.Signal = model.Metric
	otherCapability.Payload = model.Payload{Capability: &copyCap}
	otherLoss := loss
	otherLoss.ID = model.NewID()
	copyLoss := *loss.Payload.Loss
	copyLoss.Signal = model.Log
	otherLoss.Payload = model.Payload{Loss: &copyLoss}
	for _, row := range []model.Record{profile, capability, loss, rows[14], rows[15], otherCapability, otherLoss} {
		appendTyped(t, e, store, a, c, d, row)
	}
	for _, phase := range []string{"hot", "cold", "compacted", "restarted"} {
		if phase == "cold" {
			if err = e.Flush(context.Background()); err != nil {
				t.Fatal(err)
			}
		}
		if phase == "compacted" {
			if err = e.Compact(context.Background()); err != nil {
				t.Fatal(err)
			}
		}
		if phase == "restarted" {
			if err = e.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := openTestEngine(t, dir, a, store)
			if err != nil {
				t.Fatal(err)
			}
			e = reopened
		}
		for _, kind := range []model.Kind{model.Profile, model.CapabilityKind, model.Loss} {
			before := e.Stats().PagesRead
			got := collectPages(t, e, scope, ScanRequest{Projects: []model.ID{d.Project}, Signal: kind, End: 2})
			expected := 1
			if kind == model.CapabilityKind {
				expected = 3
			}
			if len(got) != expected {
				t.Fatal("profile scope row count", phase, kind, len(got), expected)
			}
			for _, row := range got {
				if kind == model.CapabilityKind && row.Payload.Capability.Signal != model.Profile || kind == model.Loss && row.Payload.Loss.Signal != model.Profile {
					t.Fatal("profile scope exposed another signal", phase, kind)
				}
			}
			if e.Stats().PagesRead-before != uint64(expected) {
				t.Fatal("profile scan touched an unrelated sub-signal page", phase, kind)
			}
		}
		before := e.Stats().IndexLookups
		if _, err = e.Scan(context.Background(), scope, ScanRequest{Projects: []model.ID{d.Project}, Signal: model.Metric, End: 2}); err == nil {
			t.Fatal("profiles.read became telemetry.read")
		}
		if _, err = e.Subscribe(context.Background(), scope, SubscribeRequest{Projects: []model.ID{d.Project}, Signal: model.Log}); err == nil {
			t.Fatal("profiles.read subscribed to logs")
		}
		if e.Stats().IndexLookups != before {
			t.Fatal("unapproved root kind touched an index")
		}
		// Even an adversarial direct C05 selector cannot select the other signal.
		before = e.Stats().PagesRead
		got := collectPages(t, e, scope, ScanRequest{Projects: []model.ID{d.Project}, Signal: model.CapabilityKind, End: 2, Selectors: []Matcher{{Target: MatchField, Name: "signal", Op: MatchEqual, Literal: Literal{Kind: LiteralString, String: string(model.Metric)}}}})
		if len(got) != 0 || e.Stats().PagesRead != before {
			t.Fatal("foreign capability sub-signal was looked up")
		}
	}
	live, err := e.Subscribe(context.Background(), scope, SubscribeRequest{Projects: []model.ID{d.Project}, Signal: model.CapabilityKind})
	if err != nil {
		t.Fatal(err)
	}
	defer live.Close()
	otherCapability.ID = model.NewID()
	appendTyped(t, e, store, a, c, d, otherCapability)
	capability.ID = model.NewID()
	appendTyped(t, e, store, a, c, d, capability)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	change, err := live.Next(ctx)
	if err != nil || change.Page.Len() != 1 || change.Page.IDs[0] != capability.ID || change.Page.Values[0].Capability.Signal != model.Profile {
		t.Fatal("direct profile subscription exposed another signal", err)
	}
}
func TestTelemetryReadStillIncludesAllCapabilitySubjects(t *testing.T) {
	store, a, c, d := typedFixture(t)
	_, base := normalized(t, store, a, c, d)
	scope := scanScope(t, store, a, d)
	e, err := openTestEngine(t, t.TempDir(), a, store)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	row := typedRows(base.Records[0].Resource)[11]
	row.Payload.Capability.Signal = model.Metric
	appendTyped(t, e, store, a, c, d, row)
	got := collectPages(t, e, scope, ScanRequest{Projects: []model.ID{d.Project}, Signal: model.CapabilityKind, End: 2})
	if len(got) != 1 || got[0].Payload.Capability.Signal != model.Metric {
		t.Fatal("telemetry.read was narrowed")
	}
}
