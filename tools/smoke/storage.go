// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"soundpost/internal/appcore"
	"soundpost/internal/auth"
	"soundpost/internal/httpapi"
	"soundpost/internal/model"
	"soundpost/internal/storage"
	"time"
)

type storageSmokePhase struct {
	Rows, Pages, Bytes uint64
	Stats              storage.StorageStats
	Records            map[model.Kind][]json.RawMessage
}

func runStorageRoundtrip(args []string) (result error) {
	stage := "storage_flags"
	defer func() { result = annotateSmokeFailure("storage_roundtrip", stage, model.ID{}, result) }()
	flags := flag.NewFlagSet("storage-roundtrip", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	artifact := flags.String("artifact-dir", "", "sanitized artifacts")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *artifact == "" {
		return errors.New("artifact directory required")
	}
	if err := os.MkdirAll(*artifact, 0700); err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "soundpost-storage-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	stage = "storage_app_open"
	app, err := appcore.Open(dir)
	if err != nil {
		return err
	}
	defer func() {
		if app != nil {
			app.Close()
		}
	}()
	server := httptest.NewTLSServer(httpapi.NewServer("", app.Auth, nil, app.Register).Handler)
	defer func() {
		if server != nil {
			server.Close()
		}
	}()
	client := server.Client()
	client.Jar, _ = cookiejar.New(nil)
	child := &smokeChild{client: client, address: childAddress{URL: server.URL}}
	stage = "storage_bootstrap"
	bootstrap, err := app.Control.BootstrapToken()
	if err != nil {
		return err
	}
	status, raw, err := child.call("/api/v1/bootstrap", map[string]string{"Token": bootstrap, "Email": "storage@example.test", "Password": "storage smoke password 2026"}, "", "")
	if err = requireSmokeResponse(stage, status, 200, raw, err); err != nil {
		return err
	}
	var session auth.Session
	if err = json.Unmarshal(raw, &session); err != nil {
		return err
	}
	u, err := url.Parse(server.URL)
	if err != nil {
		return err
	}
	var sessionToken string
	for _, cookie := range client.Jar.Cookies(u) {
		if cookie.Name == "__Host-soundpost" {
			sessionToken = cookie.Value
		}
	}
	if sessionToken == "" {
		return errors.New("session cookie missing")
	}
	org, project, source := model.NewID(), model.NewID(), model.NewID()
	admin := func(kind string, p auth.AdminPayload) error {
		status, raw, err := child.organizationsRead(session.CSRF)
		if err = requireSmokeResponse("storage_admin_revision", status, 200, raw, err); err != nil {
			return err
		}
		var view auth.AdminView
		if err = json.Unmarshal(raw, &view); err != nil {
			return err
		}
		p.Reason = "storage smoke"
		payload, err := json.Marshal(p)
		if err != nil {
			return err
		}
		status, raw, err = child.call("/api/v1/admin/commands", auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: view.Revision, OrgID: org, Kind: kind, Payload: payload}, session.CSRF, "")
		return requireSmokeResponse("storage_admin_"+kind, status, 200, raw, err)
	}
	stage = "storage_create_namespace"
	if err = admin("create_org", auth.AdminPayload{Name: "generic"}); err != nil {
		return err
	}
	if err = admin("create_project", auth.AdminPayload{ID: project, Name: "generic"}); err != nil {
		return err
	}
	stage = "storage_reader_membership"
	if err = admin("membership", auth.AdminPayload{UserID: session.User, Enabled: true}); err != nil {
		return err
	}
	stage = "storage_reader_grant"
	if err = admin("grant", auth.AdminPayload{UserID: session.User, ProjectID: project, Enabled: true, Permissions: []string{string(auth.Read)}}); err != nil {
		return err
	}
	resource := model.Resource{Service: model.NewID(), Environment: model.NewID(), Build: model.NewID(), Instance: "fixture", Labels: model.Labels{}}
	var approved model.Scalar
	if err = json.Unmarshal([]byte(`503`), &approved); err != nil {
		return err
	}
	policy := model.SourcePolicy{Revision: 1, Enabled: true, Class: "structured", Kinds: []model.Kind{model.Metric, model.Log}, Resources: model.ResourceRegistry{Services: []model.ID{resource.Service}, Environments: []model.ID{resource.Environment}, Builds: []model.ID{resource.Build}, Instances: []string{"fixture"}}, Templates: []model.LogTemplate{{ID: "safe", Revision: 1, Line: "status {status}", Severity: "error", Fields: []model.TemplateField{{Name: "status", Type: "int64", MaxBytes: 16, Sensitivity: "metadata", Values: []model.Scalar{approved}}}}}, RetentionDays: map[model.Kind]uint32{model.Metric: 30, model.Log: 14}, MaxBytes: 1 << 30, MaxSeries: 1000}
	policy.Labels = map[string][]string{"stream": {"same"}}
	stage = "storage_source_onboard"
	status, raw, err = child.call("/api/v1/sources", auth.SourceOnboarding{CommandID: model.NewID(), Org: org, Project: project, Source: source, Expires: model.UnixNano(time.Now().Add(time.Hour).UnixNano()), Policy: policy, Reason: "storage smoke"}, session.CSRF, "")
	if err = requireSmokeResponse(stage, status, 200, raw, err); err != nil {
		return err
	}
	var issued auth.SourceOnboarded
	if err = json.Unmarshal(raw, &issued); err != nil {
		return err
	}
	readScope := func() (auth.Scope, error) {
		cred, err := app.Auth.Authenticate(context.Background(), sessionToken)
		if err != nil {
			return auth.Scope{}, err
		}
		return app.Auth.Authorize(context.Background(), cred, org, []model.ID{project}, auth.Read)
	}
	scope, err := readScope()
	if err != nil {
		return err
	}
	live, err := app.Storage.Subscribe(context.Background(), scope, storage.SubscribeRequest{Projects: []model.ID{project}, Signal: model.Log})
	if err != nil {
		return err
	}
	defer live.Close()
	producer := model.NewID()
	appendHTTP := func(records []model.Record) (model.Batch, model.Receipt, error) {
		b := model.Batch{Version: 1, Project: project, Source: source, Producer: producer, ID: model.NewID(), PolicyRevision: 1, Records: records}
		slot, err := model.OwnerSlot(org, project, source, producer, records[0])
		if err != nil {
			return b, model.Receipt{}, err
		}
		b.RouteSlot = slot
		status, raw, err := child.call("/ingest/v1/batches", b, "", issued.Credential)
		if err = requireSmokeResponse("storage_ingest", status, 200, raw, err); err != nil {
			return b, model.Receipt{}, err
		}
		var receipt model.Receipt
		err = json.Unmarshal(raw, &receipt)
		return b, receipt, err
	}
	at := model.UnixNano(9007199254740993)
	bits := model.FloatBits(0x7ff8000000000001)
	stale := model.FloatBits(0x7ff0000000000002)
	metrics := []*model.MetricPoint{{Name: "exact_integer", Labels: model.Labels{}, SampleKind: "integer_histogram", Histogram: &model.NativeHistogram{Integer: &model.IntegerHistogram{Flavor: "counter", Count: 9007199254740993, ZeroCount: 9007199254740993, ResetHint: "unknown"}}, Unit: "1", Type: "histogram"}, {Name: "nan", Labels: model.Labels{}, SampleKind: "float", Value: &bits, Unit: "1", Type: "gauge"}, {Name: "stale", Labels: model.Labels{}, SampleKind: "stale", Value: &stale, Unit: "1", Type: "gauge"}, {Name: "exact_float", Labels: model.Labels{}, SampleKind: "float_histogram", Histogram: &model.NativeHistogram{Float: &model.FloatHistogram{Flavor: "gauge", Count: 0x4340000000000001, ZeroCount: 0x4340000000000001, ResetHint: "gauge"}}, Unit: "1", Type: "histogram"}}
	stage = "storage_typed_ingest"
	for _, metric := range metrics {
		if _, _, err = appendHTTP([]model.Record{{ID: model.NewID(), Kind: model.Metric, ObservedAt: at, Resource: resource, Payload: model.Payload{Metric: metric}}}); err != nil {
			return err
		}
	}
	logRow := func() model.Record {
		return model.Record{ID: model.NewID(), Kind: model.Log, ObservedAt: at, Resource: resource, Payload: model.Payload{Log: &model.LogRecord{TemplateID: "safe", TemplateRevision: 1, Fields: map[string]model.Scalar{"status": approved}, StreamLabels: model.Labels{{Name: "stream", Value: "same"}}, Metadata: map[string]model.Scalar{}}}}
	}
	batch, receipt, err := appendHTTP([]model.Record{logRow(), logRow()})
	if err != nil {
		return err
	}
	status, raw, err = child.call("/ingest/v1/batches", batch, "", issued.Credential)
	if err = requireSmokeResponse("storage_duplicate_retry", status, 200, raw, err); err != nil {
		return err
	}
	var retry model.Receipt
	if err = json.Unmarshal(raw, &retry); err != nil || !reflect.DeepEqual(receipt, retry) {
		return errors.New("retry receipt changed")
	}
	stage = "storage_live_committed"
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	change, err := live.Next(ctx)
	if err != nil || change.Page.Len() != 2 || len(change.Cursors) != 1 || change.Cursors[0] != receipt.Cursor {
		return errors.New("committed live rows missing")
	}
	for range 66 {
		if _, _, err = appendHTTP([]model.Record{logRow()}); err != nil {
			return err
		}
	}
	change, err = live.Next(ctx)
	if err != nil || change.Gap == nil || change.Gap.Reason != "slow_consumer" {
		return errors.New("slow consumer gap missing")
	}
	gap := change.Gap
	stage = "storage_live_revoke"
	if err = admin("grant", auth.AdminPayload{UserID: session.User, ProjectID: project, Enabled: false, Permissions: []string{string(auth.Read)}}); err != nil {
		return err
	}
	change, err = live.Next(ctx)
	if err != nil || !change.Revoked || change.Page.Len() != 0 {
		return errors.New("revocation missing")
	}
	if err = admin("grant", auth.AdminPayload{UserID: session.User, ProjectID: project, Enabled: true, Permissions: []string{string(auth.Read)}}); err != nil {
		return err
	}
	scope, err = readScope()
	if err != nil {
		return err
	}
	scan := func() (storageSmokePhase, error) {
		phase := storageSmokePhase{Records: map[model.Kind][]json.RawMessage{}}
		for _, kind := range []model.Kind{model.Metric, model.Log} {
			it, err := app.Storage.Scan(ctx, scope, storage.ScanRequest{Projects: []model.ID{project}, Signal: kind, Start: at, End: at + 1})
			if err != nil {
				return phase, err
			}
			for {
				page, err := it.Next(ctx)
				if err == io.EOF {
					break
				}
				if err != nil {
					it.Close()
					return phase, err
				}
				phase.Pages++
				phase.Bytes += page.Bytes
				phase.Rows += uint64(page.Len())
				for i := range page.IDs {
					record := model.Record{ID: page.IDs[i], Kind: kind, ObservedAt: page.Times[i], Resource: page.Resources[i], Payload: page.Values[i]}
					b, err := model.CanonicalJSON(record)
					if err != nil {
						it.Close()
						return phase, err
					}
					phase.Records[kind] = append(phase.Records[kind], json.RawMessage(b))
				}
			}
			it.Close()
		}
		phase.Stats = app.Storage.Stats()
		return phase, nil
	}
	phases := map[string]storageSmokePhase{}
	stage = "storage_hot_scan"
	hot, err := scan()
	if err != nil {
		return err
	}
	if hot.Rows != 72 || len(hot.Records[model.Log]) != 68 || len(hot.Records[model.Metric]) != 4 || hot.Pages == 0 || hot.Bytes == 0 {
		return errors.New("exact row accounting mismatch")
	}
	phases["hot"] = hot
	stage = "storage_flush"
	if err = app.Storage.Flush(ctx); err != nil {
		return err
	}
	phases["cold"], err = scan()
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(hot.Records, phases["cold"].Records) {
		return errors.New("hot/cold logical equality failed")
	}
	// A second genuine committed batch and flush create two retained log
	// segments; compaction must merge them, not just rewrite one input file.
	stage = "storage_second_segment_ingest"
	if _, _, err = appendHTTP([]model.Record{logRow()}); err != nil {
		return err
	}
	phases["second_hot"], err = scan()
	if err != nil {
		return err
	}
	if phases["second_hot"].Rows != 73 {
		return errors.New("second batch row accounting mismatch")
	}
	stage = "storage_second_flush"
	if err = app.Storage.Flush(ctx); err != nil {
		return err
	}
	phases["second_cold"], err = scan()
	if err != nil {
		return err
	}
	stage = "storage_compact"
	beforeSegments := app.Storage.Stats().SegmentFiles
	if err = app.Storage.Compact(ctx); err != nil {
		return err
	}
	phases["compacted"], err = scan()
	if err != nil {
		return err
	}
	if beforeSegments <= phases["compacted"].Stats.SegmentFiles {
		return errors.New("compaction did not merge retained segments")
	}
	stage = "storage_restart"
	server.Close()
	server = nil
	if err = app.Close(); err != nil {
		return err
	}
	app = nil
	app, err = appcore.Open(dir)
	if err != nil {
		return err
	}
	server = httptest.NewTLSServer(httpapi.NewServer("", app.Auth, nil, app.Register).Handler)
	child.client = server.Client()
	child.address.URL = server.URL
	status, raw, err = child.call("/ingest/v1/batches", batch, "", issued.Credential)
	if err = requireSmokeResponse("storage_restart_receipt", status, 200, raw, err); err != nil {
		return err
	}
	if err = json.Unmarshal(raw, &retry); err != nil || !reflect.DeepEqual(receipt, retry) {
		return errors.New("restart changed original receipt")
	}
	scope, err = readScope()
	if err != nil {
		return err
	}
	phases["restarted"], err = scan()
	if err != nil {
		return err
	}
	for _, name := range []string{"second_cold", "compacted", "restarted"} {
		if !reflect.DeepEqual(phases["second_hot"].Records, phases[name].Records) {
			return errors.New("typed logical equality failed")
		}
	}
	stage = "storage_exact_values"
	expectedMetrics := map[string]*model.MetricPoint{}
	for _, point := range metrics {
		expectedMetrics[point.Name] = point
	}
	for _, raw := range hot.Records[model.Metric] {
		var record model.Record
		if err = json.Unmarshal(raw, &record); err != nil {
			return err
		}
		expected, ok := expectedMetrics[record.Payload.Metric.Name]
		if !ok || record.ObservedAt != at {
			return errors.New("unexpected typed metric")
		}
		got, err := model.CanonicalJSON(record.Payload.Metric)
		if err != nil {
			return err
		}
		want, err := model.CanonicalJSON(expected)
		if err != nil {
			return err
		}
		if string(got) != string(want) {
			return errors.New("exact float bits or histogram values changed")
		}
		delete(expectedMetrics, record.Payload.Metric.Name)
	}
	if len(expectedMetrics) != 0 {
		return errors.New("exact metric variant absent")
	}
	for _, raw := range hot.Records[model.Log] {
		var record model.Record
		if err = json.Unmarshal(raw, &record); err != nil {
			return err
		}
		if record.Payload.Log.Line != "status 503" || record.ObservedAt != at {
			return errors.New("immutable equal-line values changed")
		}
	}
	stage = "storage_artifact"
	evidence := struct {
		Version       int
		Phases        map[string]storageSmokePhase
		Gap           *storage.ChangeGap
		Revoked       bool
		Qualification string
	}{1, phases, gap, true, "real HTTPS ingest; graceful durable restart; not power-loss, HA, retention or deletion qualification"}
	data, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(*artifact, "storage-roundtrip.json"), data, 0600)
}
