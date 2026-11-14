// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"encoding/json"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/policy"
	"testing"
)

func configureTypedSource(t *testing.T, p *model.SourcePolicy) {
	t.Helper()
	var count model.Scalar
	if err := json.Unmarshal([]byte(`9007199254740993`), &count); err != nil {
		t.Fatal(err)
	}
	p.Kinds = append([]model.Kind(nil), signalKinds...)
	p.RetentionDays = make(map[model.Kind]uint32, len(signalKinds))
	for _, kind := range signalKinds {
		p.RetentionDays[kind] = 30
	}
	p.Labels = map[string][]string{"zone": {"a"}, "stream": {"test"}}
	p.Operations = []string{"operation"}
	p.Replay = true
	p.Templates = []model.LogTemplate{
		{ID: "failed", Revision: 1, Line: "same safe line", Severity: "error", Fields: []model.TemplateField{{Name: "count", Type: "int64", MaxBytes: 32, Sensitivity: "metadata", Values: []model.Scalar{count}}}},
		{ID: "safe", Revision: 1, Line: "safe", Severity: "error"},
	}
}
func TestTypedFixtureNormalizesEveryClosedPayloadUnderActualPolicy(t *testing.T) {
	_, a, c, d := typedFixture(t)
	source, err := a.SourceAuthority(context.Background(), c, true)
	if err != nil {
		t.Fatal(err)
	}
	resource := model.Resource{Service: source.Policy.Resources.Services[0], Environment: source.Policy.Resources.Environments[0], Build: source.Policy.Resources.Builds[0], Instance: source.Policy.Resources.Instances[0]}
	service, err := policy.New(a, nil)
	if err != nil {
		t.Fatal(err)
	}
	rows := typedRows(resource)
	capabilityIDs := map[model.ID]bool{}
	for _, row := range rows {
		if row.Kind == model.CapabilityKind {
			capabilityIDs[row.ID] = true
		}
	}
	for _, row := range rows {
		grant, err := service.ResolveSource(context.Background(), c, d.Project, d.Source, source.Policy.Revision)
		if err != nil {
			t.Fatal(err)
		}
		batch := typedInput(t, d, source.Policy.Revision, row)
		normalized, err := policy.Normalize(grant, batch)
		if err != nil {
			t.Fatalf("normalize %s %s: %v", row.Kind, row.ID, err)
		}
		if len(normalized.Records) != 1 || normalized.Records[0].ID != row.ID || normalized.PolicyRevision != source.Policy.Revision {
			t.Fatal("normalization changed fixture identity")
		}
		if row.Payload.Profile != nil {
			for _, id := range row.Payload.Profile.NativeCapabilities {
				if !capabilityIDs[id] {
					t.Fatal("native profile references a fabricated capability")
				}
			}
		}
	}
}
