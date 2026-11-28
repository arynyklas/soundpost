// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package privnode

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/profiles"
)

// External is the private description of a node that ANOTHER process serves (the
// real `soundpost serve` binary) and that the verifier reaches only over its
// verified-TLS HTTP routes: batches over POST /ingest/v1/batches, receipts over
// POST /ingest/v1/receipts, profiles over POST /api/v1/profiles/view with the
// reader's bearer token.
//
// The exporter normalizes every batch against a source grant, and a grant exists
// only inside an auth service. GrantDir is therefore a copy of the served node's
// data directory taken while that node was stopped (so it holds the same source,
// policy revision and credential); it is opened in process for the grant ONLY and
// admits nothing. DataDir is the served node's own directory, read-only, for the
// stored-bytes audit.
type External struct {
	CAFile         string         `json:"ca_file"`
	SourceKey      string         `json:"source_credential"`
	ReaderToken    string         `json:"reader_token"`
	Org            model.ID       `json:"org_id"`
	Project        model.ID       `json:"project_id"`
	Source         model.ID       `json:"source_id"`
	Producer       model.ID       `json:"producer_id"`
	Resource       model.Resource `json:"resource"`
	PolicyRevision model.Revision `json:"policy_revision"`
	DataDir        string         `json:"data_dir"`
	GrantDir       string         `json:"grant_dir"`
}

// LoadExternal reads a private (0600, regular, bounded) External description.
func LoadExternal(path string) (External, error) {
	var x External
	f, e := os.Open(path)
	if e != nil {
		return x, errors.New("node description unavailable")
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0o077 != 0 || st.Size() > 1<<20 {
		return x, errors.New("node description must be a private regular file")
	}
	raw, e := io.ReadAll(io.LimitReader(f, 1<<20+1))
	if e != nil || len(raw) > 1<<20 || model.StrictJSON(raw, &x) != nil {
		return x, errors.New("node description invalid")
	}
	if x.SourceKey == "" || x.ReaderToken == "" || x.DataDir == "" || x.GrantDir == "" || x.PolicyRevision == 0 || x.Org == (model.ID{}) || x.Project == (model.ID{}) || x.Source == (model.ID{}) || x.Producer == (model.ID{}) {
		return x, errors.New("node description incomplete")
	}
	return x, nil
}

// Attach binds a Node to the served endpoint. The returned node has no in-process
// server: every request to it goes over the verified-TLS client, whose roots are
// the system roots plus x.CAFile.
func Attach(ctx context.Context, endpoint string, x External) (*Node, error) {
	u, e := url.Parse(endpoint)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return nil, errors.New("the node endpoint must be a verified https URL")
	}
	pool, e := x509.SystemCertPool()
	if e != nil {
		return nil, errors.New("tls roots unavailable")
	}
	if x.CAFile != "" {
		b, e := os.ReadFile(x.CAFile)
		if e != nil || len(b) > 1<<20 || !pool.AppendCertsFromPEM(b) {
			return nil, errors.New("tls ca invalid")
		}
	}
	app, e := appcore.Open(x.GrantDir)
	if e != nil {
		return nil, errors.New("grant directory unavailable (it is a stopped copy of the served node's data)")
	}
	n := &Node{App: app, Dir: x.DataDir, URL: u.Scheme + "://" + u.Host, Org: x.Org, Project: x.Project, Source: x.Source, Producer: x.Producer, SourceKey: x.SourceKey, Resource: x.Resource, PolicyRevision: x.PolicyRevision, ReaderToken: x.ReaderToken}
	n.Client = &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}}, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect denied") }}
	if n.Cred, e = app.Auth.AuthenticateSource(ctx, x.SourceKey, "", false); e != nil {
		n.Close()
		return nil, errors.New("source credential refused by the grant copy")
	}
	return n, nil
}

// ReadPage reads one page of a profile as the fixture reader: through the C05
// reader for an in-process node, through the canonical HTTP route with the
// reader's bearer token for an attached node.
func (n *Node) ReadPage(ctx context.Context, root model.ID, w profiles.Window) (profiles.ProfileView, error) {
	if n.ReaderToken == "" {
		return n.App.NewNativeProfiles().Read(ctx, n.Reader, root, w)
	}
	body := map[string]any{"org": n.Org.String(), "project": n.Project.String(), "profile": root.String(), "window": map[string]any{"start": strconv.FormatInt(int64(w.Start), 10), "end": strconv.FormatInt(int64(w.End), 10)}, "max_samples": w.MaxSamples}
	if w.Cursor != "" {
		body["cursor"] = w.Cursor
	}
	status, raw, e := n.ProfileView(ctx, n.ReaderToken, body)
	if e != nil {
		return profiles.ProfileView{}, e
	}
	if status != http.StatusOK {
		return profiles.ProfileView{}, errors.New("profile view refused: status " + strconv.Itoa(status))
	}
	var response httpapi.ProfileResponse
	if model.StrictJSON(raw, &response) != nil || response.View == nil {
		return profiles.ProfileView{}, errors.New("profile view response invalid")
	}
	return *response.View, nil
}
