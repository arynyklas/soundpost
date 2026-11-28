// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package sources

import (
	"context"
	"encoding/json"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/storage"
)

func scalarOfJSON(t testing.TB, lit string) model.Scalar {
	t.Helper()
	var s model.Scalar
	if err := json.Unmarshal([]byte(lit), &s); err != nil {
		t.Fatal(err)
	}
	return s
}

// testTemplates are the two registered templates every fixture policy uses.
func testTemplates(t testing.TB) []model.LogTemplate {
	return []model.LogTemplate{
		{ID: "svc.started", Revision: 1, Line: "service started unit {unit}", Severity: "info", Fields: []model.TemplateField{
			{Name: "unit", Type: "string", MaxBytes: 16, Sensitivity: "metadata", Values: []model.Scalar{scalarOfJSON(t, `"alpha"`), scalarOfJSON(t, `"beta"`)}},
		}},
		{ID: "http.status", Revision: 1, Line: "request status {status}", Severity: "warn", Fields: []model.TemplateField{
			{Name: "status", Type: "int64", MaxBytes: 8, Sensitivity: "metadata", Values: []model.Scalar{scalarOfJSON(t, `200`), scalarOfJSON(t, `503`)}},
		}},
	}
}

func testResource() model.Resource {
	return model.Resource{Service: model.ID{0x11}, Environment: model.ID{0x12}, Build: model.ID{0x13}, Instance: "host-1", Labels: model.Labels{}}
}

func testIdentity() Identity {
	return Identity{Org: model.ID{0x21}, Project: model.ID{0x22}, Source: model.ID{0x23}, Producer: model.ID{0x24}, Epoch: model.ID{0x25}}
}

func baseFilePolicy(t testing.TB, path string) SourcePolicy {
	return SourcePolicy{
		Name: "app", Kind: KindFile, Class: ClassStructured, Revision: 1, Resource: testResource(),
		Labels:    model.Labels{{Name: "source", Value: "app"}},
		Templates: testTemplates(t),
		File:      &FileSpec{Path: path, StartAt: StartBeginning},
	}
}

func appendLines(t testing.TB, path string, lines ...string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, l := range lines {
		if _, err := f.WriteString(l + "\n"); err != nil {
			t.Fatal(err)
		}
	}
}

func mustStore(t testing.TB) (*Store, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "state")
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	return s, dir
}

// recorder is a fake C03 admission with the real contract that matters here:
// a batch is identified by its ID and canonical bytes; the same ID with the
// same bytes returns the original receipt (no second logical admission), the
// same ID with different bytes is a conflict.
type recorder struct {
	mu       sync.Mutex
	seen     map[model.ID][]byte
	receipts map[model.ID]model.Receipt
	batches  []model.Batch // every distinct admitted batch
	calls    int
	index    uint64
	// loseAck stores the batch but reports failure to the caller, as a dropped
	// response does. failBefore rejects without storing.
	loseAck    bool
	failBefore bool
}

func newRecorder() *recorder {
	return &recorder{seen: map[model.ID][]byte{}, receipts: map[model.ID]model.Receipt{}}
}

func (r *recorder) Admit(ctx context.Context, b model.Batch) (model.Receipt, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	if r.failBefore {
		return model.Receipt{}, model.Fail(model.Unavailable)
	}
	canonical, err := model.CanonicalJSON(b)
	if err != nil {
		return model.Receipt{}, err
	}
	if old, ok := r.seen[b.ID]; ok {
		if string(old) != string(canonical) {
			return model.Receipt{}, model.Fail(model.Conflict)
		}
		return r.receipts[b.ID], nil
	}
	r.index++
	rc := model.Receipt{Version: 1, BatchID: b.ID, Hash: model.HashCanonical(canonical), Cursor: model.Cursor{Group: model.ID{0x77}, Index: model.Uint64(r.index)}}
	r.seen[b.ID], r.receipts[b.ID] = canonical, rc
	r.batches = append(r.batches, b)
	if r.loseAck {
		return model.Receipt{}, model.Fail(model.Unavailable)
	}
	return rc, nil
}

// lines are the server-rendered lines of every distinct admitted log record, in
// admission order.
func (r *recorder) lines() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, b := range r.batches {
		for _, rec := range b.Records {
			if rec.Kind == model.Log {
				out = append(out, rec.Payload.Log.Line)
			}
		}
	}
	return out
}

func (r *recorder) ids() map[model.ID]int {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := map[model.ID]int{}
	for _, b := range r.batches {
		for _, rec := range b.Records {
			out[rec.ID]++
		}
	}
	return out
}

func (r *recorder) kinds(k model.Kind) []model.Record {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []model.Record
	for _, b := range r.batches {
		for _, rec := range b.Records {
			if rec.Kind == k {
				out = append(out, rec)
			}
		}
	}
	return out
}

func newPump(t testing.TB, p SourcePolicy, store *Store, s Submitter) *Pump {
	t.Helper()
	return &Pump{Policy: p, Store: store, ID: testIdentity(), Submit: s}
}

// ---- a real node (control Raft, auth, C03 admission, C05 storage) ----

type realNode struct {
	t       *testing.T
	ctx     context.Context
	app     *appcore.App
	org     model.ID
	project model.ID
	source  model.ID
	cred    auth.SourceCredential
	actor   auth.Credential
}

func newRealNode(t *testing.T, resource model.Resource, templates []model.LogTemplate, labels map[string][]string) *realNode {
	t.Helper()
	ctx := context.Background()
	app, err := appcore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { app.Close() })
	boot, err := app.Control.BootstrapToken()
	if err != nil {
		t.Fatal(err)
	}
	session, err := app.Auth.Bootstrap(ctx, boot, "sources-owner@example.test", "sources integration password 2026")
	if err != nil {
		t.Fatal(err)
	}
	actor, err := app.Auth.Authenticate(ctx, session.Token)
	if err != nil {
		t.Fatal(err)
	}
	n := &realNode{t: t, ctx: ctx, app: app, org: model.NewID(), project: model.NewID(), source: model.NewID(), actor: actor}
	n.command("create_org", auth.AdminPayload{Name: "sources"})
	n.command("create_project", auth.AdminPayload{ID: n.project, Name: "sources"})
	n.command("membership", auth.AdminPayload{UserID: session.User, Enabled: true})
	n.command("grant", auth.AdminPayload{UserID: session.User, ProjectID: n.project, Enabled: true, Permissions: []string{string(auth.Read)}})
	pol := model.SourcePolicy{
		Revision: 1, Enabled: true, Class: ClassStructured, Kinds: []model.Kind{model.Log, model.Loss},
		Templates: templates, Labels: labels,
		Resources:     model.ResourceRegistry{Services: []model.ID{resource.Service}, Environments: []model.ID{resource.Environment}, Builds: []model.ID{resource.Build}, Instances: []string{resource.Instance}},
		RetentionDays: map[model.Kind]uint32{model.Log: 7, model.Loss: 7}, MaxBytes: 64 << 20, MaxSeries: 100,
	}
	issued, err := app.Auth.OnboardSource(ctx, actor, auth.SourceOnboarding{CommandID: model.NewID(), Org: n.org, Project: n.project, Source: n.source, Expires: model.UnixNano(time.Now().Add(time.Hour).UnixNano()), Policy: pol, Reason: "sources integration"})
	if err != nil {
		t.Fatal(err)
	}
	if n.cred, err = app.Auth.AuthenticateSource(ctx, issued.Credential, "", false); err != nil {
		t.Fatal(err)
	}
	return n
}

func (n *realNode) command(kind string, p auth.AdminPayload) {
	n.t.Helper()
	var rev model.Revision
	if err := n.app.Control.View(n.ctx, func(st model.ControlState) error { rev = st.Revision; return nil }); err != nil {
		n.t.Fatal(err)
	}
	p.Reason = "sources integration"
	raw, _ := json.Marshal(p)
	if _, err := n.app.Auth.AdminCommand(n.ctx, n.actor, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: rev, OrgID: n.org, Kind: kind, Payload: raw}); err != nil {
		n.t.Fatal(kind, err)
	}
}

func (n *realNode) identity() Identity {
	return Identity{Org: n.org, Project: n.project, Source: n.source, Producer: model.ID{0x31}, Epoch: model.ID{0x32}}
}

// Admit is the production path: resolve the source grant, then Service.Admit.
func (n *realNode) Admit(ctx context.Context, b model.Batch) (model.Receipt, error) {
	g, err := n.app.Ingest.ResolveSource(ctx, n.cred, b)
	if err != nil {
		return model.Receipt{}, err
	}
	return n.app.Ingest.Admit(ctx, g, b)
}

// storedLines returns every stored log line, read through the real C05 scope
// of the bootstrap administrator (who holds the project read grant).
func (n *realNode) storedLines() []string {
	n.t.Helper()
	scope, err := n.app.Auth.Authorize(n.ctx, n.actor, n.org, []model.ID{n.project}, auth.Read)
	if err != nil {
		n.t.Fatal(err)
	}
	return scanLogLines(n.t, n.app, scope, n.project)
}

func scanLogLines(t testing.TB, app *appcore.App, scope auth.Scope, project model.ID) []string {
	t.Helper()
	rows, err := app.Storage.Scan(context.Background(), scope, storage.ScanRequest{Projects: []model.ID{project}, Signal: model.Log, Start: math.MinInt64, End: math.MaxInt64})
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for {
		page, err := rows.Next(context.Background())
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		for i := range page.Len() {
			if l := page.Values[i].Log; l != nil {
				out = append(out, l.Line)
			}
		}
	}
}

func joinLines(l []string) string { return strings.Join(l, "\n") }
