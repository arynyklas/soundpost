// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"errors"
	"testing"

	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/ingest"
	"github.com/arynyklas/soundpost/internal/model"
)

// The bridge checks every child against the source policy before it admits any
// of them. Validating a log record renders the template into the record in
// place, so the check runs on copies: the children must reach admission exactly
// as the decoder made them, and a refusal anywhere in the request must be found.
func TestPreflightChecksCopiesOfTheRecordsAndFindsARefusalInAnyChild(t *testing.T) {
	service, environment, build, instance := model.NewID(), model.NewID(), model.NewID(), "inst-1"
	policy := model.SourcePolicy{
		Revision: 1, Enabled: true, Class: "structured", Kinds: []model.Kind{model.Log},
		Templates: []model.LogTemplate{{ID: "t", Revision: 1, Line: "{line}", Severity: "info", Fields: []model.TemplateField{
			{Name: "line", Type: "string", MaxBytes: 16, Sensitivity: "metadata", Values: []model.Scalar{scalarOf(t, "alpha")}}}}},
		Resources:     model.ResourceRegistry{Services: []model.ID{service}, Environments: []model.ID{environment}, Builds: []model.ID{build}, Instances: []string{instance}},
		Labels:        map[string][]string{"shard": {"s00"}},
		RetentionDays: map[model.Kind]uint32{model.Log: 7}, MaxBytes: 1 << 20, MaxSeries: 10,
	}
	at := model.UnixNano(1_700_000_000_000_000_000)
	record := func(shard string) model.Record {
		return model.Record{
			ID: model.NewID(), Kind: model.Log, ObservedAt: at,
			Resource: model.Resource{Service: service, Environment: environment, Build: build, Instance: instance, Labels: model.Labels{}},
			Payload: model.Payload{Log: &model.LogRecord{Timestamp: &at, TemplateID: "t", TemplateRevision: 1,
				Fields: map[string]model.Scalar{"line": scalarOf(t, "alpha")}, StreamLabels: model.Labels{{Name: "shard", Value: shard}}, Metadata: map[string]model.Scalar{}}},
		}
	}
	good := []ingest.Batch{{Records: []model.Record{record("s00")}}, {Records: []model.Record{record("s00")}}}
	if err := httpapi.PreflightForTest(policy, good); err != nil {
		t.Fatalf("a request the policy allows was refused: %v", err)
	}
	for i, b := range good {
		if l := b.Records[0].Payload.Log; l.Line != "" || l.Severity != "" || l.SourceClass != "" {
			t.Fatalf("child %d was rendered by the check: line %q severity %q class %q", i, l.Line, l.Severity, l.SourceClass)
		}
	}
	bad := []ingest.Batch{{Records: []model.Record{record("s00")}}, {Records: []model.Record{record("s00"), record("not-registered")}}}
	var fault *model.Fault
	if err := httpapi.PreflightForTest(policy, bad); !errors.As(err, &fault) || fault.Code != model.Invalid {
		t.Fatalf("an unregistered label value in the last record of the last child was not refused: %v", err)
	}
}
