// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

// Package privnode is the fixture-only real node used by the 04.08 privacy
// verifier and tests: the real appcore composition behind the real httpapi
// server over TLS. Batches reach it through the real POST /ingest/v1/batches
// route (gzip body, bearer source credential); profiles are read back through
// the real C05 scoped reader. Production packages must not import it.
package privnode

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"time"

	"github.com/arynyklas/soundpost/fixtures/nativeperf/privacy/scan"
	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/policy"
)

// Node is a real in-process Soundpost node with one org/project/source and one
// reader holding only profiles.read.
type Node struct {
	App       *appcore.App
	Dir       string
	Server    *httptest.Server
	Client    *http.Client
	Org       model.ID
	Project   model.ID
	Source    model.ID
	Producer  model.ID
	SourceKey string
	Cred      auth.SourceCredential
	Reader    auth.Scope
	Resource  model.Resource

	actor      auth.Credential
	readerCred auth.Credential
	user       model.ID
}

// Start opens the node in dir and provisions the fixture identities.
func Start(ctx context.Context, dir string) (*Node, error) {
	app, e := appcore.Open(dir)
	if e != nil {
		return nil, errors.New("real node unavailable")
	}
	n := &Node{App: app, Dir: dir, Org: model.NewID(), Project: model.NewID(), Source: model.NewID(), Producer: model.NewID()}
	fail := func(msg string) (*Node, error) { n.Close(); return nil, errors.New(msg) }
	boot, e := app.Control.BootstrapToken()
	if e != nil {
		return fail("bootstrap token unavailable")
	}
	session, e := app.Auth.Bootstrap(ctx, boot, "privacy-owner@example.test", "privacy fixture owner password 2026")
	if e != nil {
		return fail("bootstrap refused")
	}
	actor, e := app.Auth.Authenticate(ctx, session.Token)
	if e != nil {
		return fail("owner authentication refused")
	}
	user := model.NewID()
	command := func(kind string, p auth.AdminPayload) error {
		var rev model.Revision
		app.Control.View(ctx, func(st model.ControlState) error { rev = st.Revision; return nil })
		p.Reason = "privacy fixture"
		raw, _ := json.Marshal(p)
		_, err := app.Auth.AdminCommand(ctx, actor, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: rev, OrgID: n.Org, Kind: kind, Payload: raw})
		return err
	}
	for _, step := range []struct {
		kind string
		p    auth.AdminPayload
	}{
		{"create_org", auth.AdminPayload{Name: "privacy"}},
		{"create_project", auth.AdminPayload{ID: n.Project, Name: "privacy"}},
		{"create_user", auth.AdminPayload{ID: user, Email: "privacy-reader@example.test", Password: "privacy reader password 2026"}},
		{"membership", auth.AdminPayload{UserID: user, Enabled: true}},
		{"grant", auth.AdminPayload{UserID: user, ProjectID: n.Project, Enabled: true, Permissions: []string{"profiles.read"}}},
	} {
		if e = command(step.kind, step.p); e != nil {
			return fail("admin setup refused")
		}
	}
	n.Resource = model.Resource{Service: model.NewID(), Environment: model.NewID(), Build: model.NewID(), Instance: "privacy", Labels: model.Labels{}}
	sourcePolicy := model.SourcePolicy{Revision: 1, Enabled: true, Class: "structured", Kinds: []model.Kind{model.Profile, model.CapabilityKind, model.Loss}, Resources: model.ResourceRegistry{Services: []model.ID{n.Resource.Service}, Environments: []model.ID{n.Resource.Environment}, Builds: []model.ID{n.Resource.Build}, Instances: []string{"privacy"}}, RetentionDays: map[model.Kind]uint32{model.Profile: 7, model.CapabilityKind: 30, model.Loss: 30}, MaxBytes: 16 << 20, MaxSeries: 100}
	issued, e := app.Auth.OnboardSource(ctx, actor, auth.SourceOnboarding{CommandID: model.NewID(), Org: n.Org, Project: n.Project, Source: n.Source, Expires: model.UnixNano(time.Now().Add(time.Hour).UnixNano()), Policy: sourcePolicy, Reason: "privacy fixture"})
	if e != nil {
		return fail("source onboarding refused")
	}
	n.SourceKey = issued.Credential
	if n.Cred, e = app.Auth.AuthenticateSource(ctx, n.SourceKey, "", false); e != nil {
		return fail("source authentication refused")
	}
	login, e := app.Auth.Login(ctx, "privacy-reader@example.test", "privacy reader password 2026", "")
	if e != nil {
		return fail("reader login refused")
	}
	readerCred, e := app.Auth.Authenticate(ctx, login.Token)
	if e != nil {
		return fail("reader authentication refused")
	}
	if n.Reader, e = app.Auth.Authorize(ctx, readerCred, n.Org, []model.ID{n.Project}, auth.Permission("profiles.read")); e != nil {
		return fail("reader authorization refused")
	}
	n.actor, n.user, n.readerCred = actor, user, readerCred
	n.Server = httptest.NewTLSServer(httpapi.NewServer("", app.Auth, nil, app.Register).Handler)
	n.Client = n.Server.Client()
	n.Client.Timeout = 30 * time.Second
	return n, nil
}

// Close shuts the server and the node down.
func (n *Node) Close() {
	if n == nil {
		return
	}
	if n.Server != nil {
		n.Server.Close()
	}
	if n.App != nil {
		n.App.Close()
	}
}

// Grant resolves the current source authority in process (the exporter's
// SourceGrant); admission itself goes over HTTP.
func (n *Node) Grant(ctx context.Context) (policy.SourceGrant, error) {
	p, e := policy.New(n.App.Auth, nil)
	if e != nil {
		return policy.SourceGrant{}, e
	}
	return p.ResolveSource(ctx, n.Cred, n.Project, n.Source, 1)
}

// PostBatch sends wire (a JSON batch) to the real batch route gzip-compressed,
// auditing the body at the decompressed and compressed wire stages first. It
// returns the HTTP status and body (the body is audited as diagnostics).
func (n *Node) PostBatch(ctx context.Context, audit *scan.PrivacyAudit, wire []byte) (int, []byte, error) {
	_ = audit.Observe(scan.StageWireDecompressed, wire)
	var z bytes.Buffer
	w := gzip.NewWriter(&z)
	if _, e := w.Write(wire); e != nil {
		return 0, nil, e
	}
	if e := w.Close(); e != nil {
		return 0, nil, e
	}
	_ = audit.Observe(scan.StageWireCompressed, z.Bytes())
	request, e := http.NewRequestWithContext(ctx, http.MethodPost, n.Server.URL+"/ingest/v1/batches", bytes.NewReader(z.Bytes()))
	if e != nil {
		return 0, nil, e
	}
	request.Header.Set("Authorization", "Bearer "+n.SourceKey)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Content-Encoding", "gzip")
	response, e := n.Client.Do(request)
	if e != nil {
		return 0, nil, errors.New("batch route unreachable")
	}
	defer response.Body.Close()
	body, e := io.ReadAll(io.LimitReader(response.Body, 64<<10+1))
	if e != nil || len(body) > 64<<10 {
		return response.StatusCode, nil, errors.New("batch route response unreadable")
	}
	_ = audit.Observe(scan.StageDiagnostics, append([]byte("batch route response: "), body...))
	return response.StatusCode, body, nil
}

// Admitter is the exporter's BatchAdmitter. Every batch it receives is the
// exporter's frozen queue item; it is audited as queue content and sent through
// the real route.
type Admitter struct {
	N     *Node
	Audit *scan.PrivacyAudit
	Count int
}

// Admit implements nativeperf.BatchAdmitter.
func (a *Admitter) Admit(ctx context.Context, _ policy.SourceGrant, b model.Batch) (model.Receipt, error) {
	wire, e := json.Marshal(b)
	if e != nil {
		return model.Receipt{}, e
	}
	_ = a.Audit.Observe(scan.StageExporterQueue, wire)
	status, body, e := a.N.PostBatch(ctx, a.Audit, wire)
	if e != nil {
		return model.Receipt{}, e
	}
	if status != http.StatusOK {
		return model.Receipt{}, errors.New("batch route refused the batch")
	}
	var receipt model.Receipt
	if e = model.StrictJSON(body, &receipt); e != nil {
		return model.Receipt{}, errors.New("batch route receipt invalid")
	}
	a.Count++
	return receipt, nil
}

// Lookup recovers receipts through the real POST /ingest/v1/receipts route
// (nativeperf.ReceiptLookup).
type Lookup struct{ N *Node }

// LookupReceipt implements nativeperf.ReceiptLookup.
func (l Lookup) LookupReceipt(ctx context.Context, q model.ReceiptRequest) (model.Receipt, error) {
	raw, _ := json.Marshal(q)
	request, e := http.NewRequestWithContext(ctx, http.MethodPost, l.N.Server.URL+"/ingest/v1/receipts", bytes.NewReader(raw))
	if e != nil {
		return model.Receipt{}, e
	}
	request.Header.Set("Authorization", "Bearer "+l.N.SourceKey)
	request.Header.Set("Content-Type", "application/json")
	response, e := l.N.Client.Do(request)
	if e != nil {
		return model.Receipt{}, errors.New("receipt route unreachable")
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(response.Body, 64<<10+1))
	if response.StatusCode != http.StatusOK {
		var fault model.Fault
		if json.Unmarshal(body, &fault) == nil && fault.Code != "" {
			return model.Receipt{}, &fault
		}
		return model.Receipt{}, errors.New("receipt route refused")
	}
	var receipt model.Receipt
	if e = model.StrictJSON(body, &receipt); e != nil {
		return model.Receipt{}, errors.New("receipt invalid")
	}
	return receipt, nil
}

// ScanStorage walks the node's durable directory and audits every file's bytes
// at the admitted-storage stage, using overlapping windows so a sentinel cannot
// hide on a window boundary. positive, if non-empty, is public non-canary data
// the admitted profile contains; positiveSeen reports whether the raw storage
// bytes show it (a storage layer that compresses or encodes it cannot).
func (n *Node) ScanStorage(audit *scan.PrivacyAudit, positive []byte) (files, octets int, positiveSeen bool, err error) {
	const window, overlap = 4 << 20, 256
	err = filepath.WalkDir(n.Dir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil || d.IsDir() {
			return nil
		}
		f, e := os.Open(path)
		if e != nil {
			return nil
		}
		defer f.Close()
		files++
		buf := make([]byte, window)
		carry := 0
		for {
			m, e := f.Read(buf[carry:])
			if m > 0 {
				octets += m
				_ = audit.Observe(scan.StageStorage, buf[:carry+m])
				if len(positive) > 0 && bytes.Contains(buf[:carry+m], positive) {
					positiveSeen = true
				}
				keep := min(overlap, carry+m)
				copy(buf, buf[carry+m-keep:carry+m])
				carry = keep
			}
			if e != nil {
				break
			}
		}
		return nil
	})
	return files, octets, positiveSeen, err
}

// ForeignReader returns a reader scope for a second, unrelated org/project that
// the same principal can read, to prove foreign scopes get no oracle.
func (n *Node) ForeignReader(ctx context.Context) (auth.Scope, error) {
	org, project := model.NewID(), model.NewID()
	command := func(kind string, p auth.AdminPayload) error {
		var rev model.Revision
		n.App.Control.View(ctx, func(st model.ControlState) error { rev = st.Revision; return nil })
		p.Reason = "privacy fixture foreign scope"
		raw, _ := json.Marshal(p)
		_, err := n.App.Auth.AdminCommand(ctx, n.actor, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: rev, OrgID: org, Kind: kind, Payload: raw})
		return err
	}
	for _, step := range []struct {
		kind string
		p    auth.AdminPayload
	}{
		{"create_org", auth.AdminPayload{Name: "foreign"}},
		{"create_project", auth.AdminPayload{ID: project, Name: "foreign"}},
		{"membership", auth.AdminPayload{UserID: n.user, Enabled: true}},
		{"grant", auth.AdminPayload{UserID: n.user, ProjectID: project, Enabled: true, Permissions: []string{"profiles.read"}}},
	} {
		if e := command(step.kind, step.p); e != nil {
			return auth.Scope{}, errors.New("foreign scope setup refused")
		}
	}
	return n.App.Auth.Authorize(ctx, n.readerCred, org, []model.ID{project}, auth.Permission("profiles.read"))
}
