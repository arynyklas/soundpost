// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"encoding/json"
	"errors"
	bolt "go.etcd.io/bbolt"
	"os"
	"path/filepath"
	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/model"
	"testing"
	"time"
)

// These tests catch ACK-before-sync, lost original receipts, and permissive WAL repair.
func fixture(t *testing.T) (*control.Store, *auth.Service, auth.SourceCredential, model.SourceDescriptor) {
	t.Helper()
	c, e := control.Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { c.Close() })
	a, e := auth.NewService(auth.AuthDependencies{Control: c})
	if e != nil {
		t.Fatal(e)
	}
	token, _ := c.BootstrapToken()
	s, e := a.Bootstrap(context.Background(), token, "owner@example.test", "a long test password 2026")
	if e != nil {
		t.Fatal(e)
	}
	cred, e := a.Authenticate(context.Background(), s.Token)
	if e != nil {
		t.Fatal(e)
	}
	org, project, source := model.NewID(), model.NewID(), model.NewID()
	for _, r := range []auth.AdminCommandRequest{{OrgID: org, Kind: "create_org", Payload: []byte(`{"name":"test","reason":"test"}`)}, {OrgID: org, Kind: "create_project", Payload: mustJSON(t, auth.AdminPayload{ID: project, Name: "test", Reason: "test"})}} {
		c.View(context.Background(), func(st model.ControlState) error { r.ExpectedRevision = st.Revision; return nil })
		r.CommandID = model.NewID()
		if _, e = a.AdminCommand(context.Background(), cred, r); e != nil {
			t.Fatal(e)
		}
	}
	serviceID, environmentID, buildID := model.NewID(), model.NewID(), model.NewID()
	issued, e := a.OnboardSource(context.Background(), cred, auth.SourceOnboarding{CommandID: model.NewID(), Org: org, Project: project, Source: source, Expires: model.UnixNano(time.Now().Add(time.Hour).UnixNano()), Policy: model.SourcePolicy{Revision: 1, Enabled: true, Class: "structured", Kinds: []model.Kind{model.Metric}, Resources: model.ResourceRegistry{Services: []model.ID{serviceID}, Environments: []model.ID{environmentID}, Builds: []model.ID{buildID}, Instances: []string{"test"}}, RetentionDays: map[model.Kind]uint32{model.Metric: 30}, MaxBytes: 1 << 30, MaxSeries: 1000}, Reason: "test"})
	if e != nil {
		t.Fatal(e)
	}
	sc, e := a.AuthenticateSource(context.Background(), issued.Credential, "", false)
	if e != nil {
		t.Fatal(e)
	}
	return c, a, sc, issued.Descriptor
}
func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, e := model.CanonicalJSON(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func normalized(t *testing.T, store *control.Store, a *auth.Service, c auth.SourceCredential, d model.SourceDescriptor) (auth.Scope, model.NormalizedBatch) {
	t.Helper()
	scope, e := a.SourceScope(context.Background(), c, false)
	if e != nil {
		t.Fatal(e)
	}
	src, e := a.SourceAuthority(context.Background(), c, true)
	if e != nil {
		t.Fatal(e)
	}
	b := model.Batch{Version: 1, Project: d.Project, Source: d.Source, Producer: model.NewID(), ID: model.NewID(), PolicyRevision: 1, Records: []model.Record{{ID: model.NewID(), Kind: model.Metric, ObservedAt: 1, Resource: model.Resource{Service: src.Policy.Resources.Services[0], Environment: src.Policy.Resources.Environments[0], Build: src.Policy.Resources.Builds[0], Instance: src.Policy.Resources.Instances[0]}, Payload: model.Payload{Metric: &model.MetricPoint{Name: "requests", Labels: model.Labels{}, SampleKind: "float", Value: ptrBits(0x3ff0000000000000), Type: "counter", Unit: "1"}}}}}
	slot, _ := model.OwnerSlot(d.Org, b.Project, b.Source, b.Producer, b.Records[0])
	b.RouteSlot = slot
	raw := mustJSON(t, b)
	h := model.HashCanonical(raw)
	policyBytes := mustJSON(t, src.Policy)
	n := model.NormalizedBatch{Batch: b, Org: d.Org, Hash: h, Canonical: raw, PolicyEpoch: scope.PolicyEpoch(), PolicyHash: model.HashCanonical(policyBytes).String(), AdmissionAt: 10, Deadlines: []model.SignalDeadline{{Kind: model.Metric, RetainUntil: 100}}}
	n.Reservation, e = store.ReserveAdmission(context.Background(), scope, n)
	if e != nil {
		t.Fatal(e)
	}
	return scope, n
}
func ptrBits(v uint64) *model.FloatBits { x := model.FloatBits(v); return &x }
func TestRetryReturnsOriginalReceiptAcrossRestart(t *testing.T) {
	store, a, c, d := fixture(t)
	scope, b := normalized(t, store, a, c, d)
	dir := t.TempDir()
	e, err := Open(dir, a)
	if err != nil {
		t.Fatal(err)
	}
	r, err := e.Append(context.Background(), scope, b)
	if err != nil {
		t.Fatal(err)
	}
	if err = e.Close(); err != nil {
		t.Fatal(err)
	}
	e, err = Open(dir, a)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	b.AdmissionAt = 999
	b.Deadlines[0].RetainUntil = 999
	got, err := e.Append(context.Background(), scope, b)
	if err != nil {
		t.Fatal(err)
	}
	if string(mustJSON(t, r)) != string(mustJSON(t, got)) {
		t.Fatal("receipt changed")
	}
	b.Hash[0] ^= 1
	if _, err = e.Append(context.Background(), scope, b); err == nil {
		t.Fatal("changed retry accepted")
	}
	var rows []model.Record
	err = e.db.View(func(tx *bolt.Tx) error {
		return json.Unmarshal(tx.Bucket([]byte("batches")).Get(batchKey(b.Org, b.Project, b.Source, b.Producer, b.RouteSlot, b.ID)), &rows)
	})
	if err != nil || len(rows) != 1 {
		t.Fatalf("logical rows: %d %v", len(rows), err)
	}
}
func TestSyncFailureNeverAcknowledges(t *testing.T) {
	for _, point := range []string{"wal_write", "wal_payload_write", "wal_sync", "before_apply", "receipt_write", "applied_cursor"} {
		t.Run(point, func(t *testing.T) {
			store, a, c, d := fixture(t)
			scope, b := normalized(t, store, a, c, d)
			engine, err := Open(t.TempDir(), a)
			if err != nil {
				t.Fatal(err)
			}
			defer engine.Close()
			engine.fault = func(at string) error {
				if at == point {
					return errors.New("disk fault")
				}
				return nil
			}
			if receipt, err := engine.Append(context.Background(), scope, b); err == nil || receipt.Cursor.Index != 0 {
				t.Fatal("false ACK")
			}
		})
	}
}
func TestTornTailRecovery(t *testing.T) {
	store, a, c, d := fixture(t)
	scope, b := normalized(t, store, a, c, d)
	dir := t.TempDir()
	e, err := Open(dir, a)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = e.Append(context.Background(), scope, b); err != nil {
		t.Fatal(err)
	}
	e.Close()
	path := filepath.Join(dir, walName(b.RouteSlot))
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	f.Write([]byte{1, 2, 3})
	f.Close()
	e, err = Open(dir, a)
	if err != nil {
		t.Fatal(err)
	}
	e.Close()
}
func TestInteriorCorruptionRefusesRead(t *testing.T) {
	store, a, c, d := fixture(t)
	scope, b := normalized(t, store, a, c, d)
	dir := t.TempDir()
	e, err := Open(dir, a)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = e.Append(context.Background(), scope, b); err != nil {
		t.Fatal(err)
	}
	e.Close()
	path := filepath.Join(dir, walName(b.RouteSlot))
	f, err := os.OpenFile(path, os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteAt([]byte{255}, 40)
	f.Close()
	if e, err = Open(dir, a); err == nil {
		e.Close()
		t.Fatal("corruption repaired")
	}
}
