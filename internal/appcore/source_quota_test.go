// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore_test

import (
	"context"
	"encoding/json"
	"errors"
	"soundpost/internal/appcore"
	"soundpost/internal/auth"
	"soundpost/internal/model"
	"testing"
	"time"
)

func TestFencedSourceQuotaRaiseTracksPolicyWithoutRefund(t *testing.T) {
	ctx := context.Background()
	app, err := appcore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	token, err := app.Control.BootstrapToken()
	if err != nil {
		t.Fatal(err)
	}
	session, err := app.Auth.Bootstrap(ctx, token, "source-quota@example.test", "source quota policy password 2026")
	if err != nil {
		t.Fatal(err)
	}
	actor, err := app.Auth.Authenticate(ctx, session.Token)
	if err != nil {
		t.Fatal(err)
	}
	org, project, source := model.NewID(), model.NewID(), model.NewID()
	revision := func() model.Revision {
		t.Helper()
		var out model.Revision
		if err := app.Control.View(ctx, func(st model.ControlState) error { out = st.Revision; return nil }); err != nil {
			t.Fatal(err)
		}
		return out
	}
	command := func(kind string, p auth.AdminPayload) {
		t.Helper()
		p.Reason = "source quota policy regression"
		payload, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = app.Auth.AdminCommand(ctx, actor, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: revision(), OrgID: org, Kind: kind, Payload: payload}); err != nil {
			t.Fatal(err)
		}
	}
	command("create_org", auth.AdminPayload{Name: "source quota"})
	command("create_project", auth.AdminPayload{ID: project, Name: "source quota"})
	for _, projectID := range []*model.ID{nil, &project} {
		if _, err = app.Auth.SetAdmissionQuota(ctx, actor, auth.AdmissionQuotaChange{CommandID: model.NewID(), ExpectedRevision: revision(), Org: org, Project: projectID, MaxBytes: 1 << 30, MaxSeries: 100, Reason: "explicit larger global caps"}); err != nil {
			t.Fatal(err)
		}
	}
	service, environment, build := model.NewID(), model.NewID(), model.NewID()
	value := model.FloatBits(0x3ff0000000000000)
	batch := func(name string, policyRevision model.Revision) model.Batch {
		t.Helper()
		b := model.Batch{Version: 1, Project: project, Source: source, Producer: model.NewID(), ID: model.NewID(), PolicyRevision: policyRevision, Records: []model.Record{{ID: model.NewID(), Kind: model.Metric, ObservedAt: 1, Resource: model.Resource{Service: service, Environment: environment, Build: build, Instance: "opaque-instance", Labels: model.Labels{}}, Payload: model.Payload{Metric: &model.MetricPoint{Name: name, Labels: model.Labels{}, SampleKind: "float", Value: &value, Unit: "1", Type: "counter"}}}}}
		var err error
		b.RouteSlot, err = model.OwnerSlot(org, project, source, b.Producer, b.Records[0])
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	first := batch("quota_first", 1)
	second := batch("quota_second", 2)
	cost := func(b model.Batch) model.Uint64 {
		t.Helper()
		raw, err := model.CanonicalJSON(b)
		if err != nil {
			t.Fatal(err)
		}
		return model.Uint64(len(raw))
	}
	firstCost, secondCost := cost(first), cost(second)
	policy := model.SourcePolicy{Revision: 1, Enabled: true, Class: "structured", Kinds: []model.Kind{model.Metric}, Resources: model.ResourceRegistry{Services: []model.ID{service}, Environments: []model.ID{environment}, Builds: []model.ID{build}, Instances: []string{"opaque-instance"}}, RetentionDays: map[model.Kind]uint32{model.Metric: 30}, MaxBytes: firstCost, MaxSeries: 1}
	issued, err := app.Auth.OnboardSource(ctx, actor, auth.SourceOnboarding{CommandID: model.NewID(), Org: org, Project: project, Source: source, Expires: model.UnixNano(time.Now().Add(time.Hour).UnixNano()), Policy: policy, Reason: "source quota policy regression"})
	if err != nil {
		t.Fatal(err)
	}
	credential, err := app.Auth.AuthenticateSource(ctx, issued.Credential, "", false)
	if err != nil {
		t.Fatal(err)
	}
	admit := func(b model.Batch) (model.Receipt, error) {
		grant, err := app.Ingest.ResolveSource(ctx, credential, b)
		if err != nil {
			return model.Receipt{}, err
		}
		return app.Ingest.Admit(ctx, grant, b)
	}
	original, err := admit(first)
	if err != nil {
		t.Fatal(err)
	}
	rejected := second
	rejected.PolicyRevision = 1
	if _, err = admit(rejected); !sourceQuotaFault(err) {
		t.Fatal("low source cap did not reject new admission")
	}
	sourceKey := "source:" + org.String() + ":" + project.String() + ":" + source.String()
	snapshot := func() (model.QuotaState, int) {
		t.Helper()
		var q model.QuotaState
		var reservations int
		if err := app.Control.View(ctx, func(st model.ControlState) error {
			q = st.Quotas[sourceKey]
			reservations = len(st.Reservations)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return q, reservations
	}
	q, n := snapshot()
	if q.Bytes != firstCost || len(q.Series) != 1 || n != 1 {
		t.Fatal("rejected source quota changed prior charge")
	}
	fence := func(next model.SourcePolicy) {
		t.Helper()
		if _, err := app.Auth.ChangeSourcePolicy(ctx, actor, auth.SourcePolicyChange{CommandID: model.NewID(), Source: source, ExpectedRevision: next.Revision - 1, Policy: next, Reason: "fenced source quota change"}); err != nil {
			t.Fatal(err)
		}
		if err := app.Auth.DrainSourceFences(ctx); err != nil {
			t.Fatal(err)
		}
	}
	raised := policy
	raised.Revision = 2
	raised.MaxBytes = firstCost + secondCost
	raised.MaxSeries = 2
	fence(raised)
	request := model.ReceiptRequest{Source: source, Producer: first.Producer, RouteSlot: first.RouteSlot, BatchID: first.ID, OriginalHash: original.Hash}
	historical, err := app.Ingest.LookupReceipt(ctx, credential, request)
	if err != nil || !historical.Historical || historical.Cursor != original.Cursor || historical.Hash != original.Hash {
		t.Fatal("policy raise rewrote historical receipt")
	}
	q, n = snapshot()
	if q.Bytes != firstCost || len(q.Series) != 1 || n != 1 {
		t.Fatal("historical lookup re-reserved or refunded")
	}
	if _, err = admit(second); err != nil {
		t.Fatal("authorized fenced source raise did not permit admission", err)
	}
	q, n = snapshot()
	if q.MaxBytes != raised.MaxBytes || q.MaxSeries != 2 || q.Bytes != firstCost+secondCost || len(q.Series) != 2 || n != 2 {
		t.Fatal("source tier did not track raised policy exactly")
	}
	lowered := raised
	lowered.Revision = 3
	lowered.MaxBytes = firstCost
	lowered.MaxSeries = 1
	fence(lowered)
	if _, err = admit(batch("quota_third", 3)); !sourceQuotaFault(err) {
		t.Fatal("restrictive source caps did not block new admission")
	}
	q, n = snapshot()
	if q.Bytes != firstCost+secondCost || len(q.Series) != 2 || n != 2 {
		t.Fatal("restrictive policy refunded or erased existing charges")
	}
	if err = app.Control.View(ctx, func(st model.ControlState) error {
		for _, key := range []string{"org:" + org.String(), "project:" + org.String() + ":" + project.String()} {
			quota := st.Quotas[key]
			if !quota.Configured || quota.MaxBytes != 1<<30 || quota.MaxSeries != 100 {
				t.Fatal("source policy rewrote explicit global quota")
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
func sourceQuotaFault(err error) bool {
	var fault *model.Fault
	return errors.As(err, &fault) && fault.Code == model.Quota
}
