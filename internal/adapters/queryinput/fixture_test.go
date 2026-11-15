// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package queryinput_test

// Thin test-side users of the shared corpus runner in corpus.go (one
// implementation for `soundpost-querycheck normalize` and the tests).

import (
	"context"
	"encoding/json"
	"io"
	"math"
	"os"
	"path/filepath"
	"testing"

	. "github.com/arynyklas/soundpost/internal/adapters/queryinput"
	"github.com/arynyklas/soundpost/internal/adapters/queryinput/corpus"
	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/policy"
	"github.com/arynyklas/soundpost/internal/storage"
)

type fixture struct {
	*corpus.Harness
	t        *testing.T
	ctx      context.Context
	app      *appcore.App
	actor    auth.Credential
	org      model.ID
	project  model.ID
	source   model.ID
	resource model.Resource
	cred     auth.SourceCredential
	ps       *policy.Service
	reader   *auth.Scope
}

const (
	testMin = model.UnixNano(1_600_000_000_000_000_000)
	testMax = model.UnixNano(1_800_000_000_000_000_000)
)

type (
	corpusCase = corpus.CorpusCase
	semRW      = corpus.SemRW
	semLoki    = corpus.SemLoki
)

var (
	snappyEncode = corpus.SnappyEncode
	gz           = corpus.Gz
	lokiJSON     = corpus.LokiJSON
)

func scalar(t testing.TB, s string) model.Scalar {
	t.Helper()
	var v model.Scalar
	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.UnmarshalJSON(raw); err != nil {
		t.Fatal(err)
	}
	return v
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	h, err := corpus.OpenHarness(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.Close() })
	return &fixture{Harness: h, t: t, ctx: h.Ctx, app: h.App, actor: h.Actor, org: h.Org, project: h.Project, source: h.Source, resource: h.Resource, cred: h.Cred, ps: h.PS}
}

func (f *fixture) command(kind string, p auth.AdminPayload) {
	f.t.Helper()
	if err := f.Harness.Command(kind, p); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) onboard(source model.ID, p model.SourcePolicy) auth.SourceCredential {
	f.t.Helper()
	cred, err := f.Harness.Onboard(source, p)
	if err != nil {
		f.t.Fatal(err)
	}
	return cred
}

// grant resolves a long-lived (fixed clock) grant for the fixture source.
func (f *fixture) grant() policy.SourceGrant {
	f.t.Helper()
	g, err := f.Harness.Grant()
	if err != nil {
		f.t.Fatal(err)
	}
	return g
}

// liveGrant is a real-clock grant for the production ingest service.
func (f *fixture) liveGrant(batch model.Batch) policy.SourceGrant {
	f.t.Helper()
	g, err := f.app.Ingest.ResolveSource(f.ctx, f.cred, batch)
	if err != nil {
		f.t.Fatal(err)
	}
	return g
}

func (f *fixture) readerScope() auth.Scope {
	f.t.Helper()
	if f.reader != nil {
		return *f.reader
	}
	user := model.NewID()
	f.command("create_user", auth.AdminPayload{ID: user, Email: "adapter-reader@example.test", Password: "reader password long 2026"})
	f.command("membership", auth.AdminPayload{UserID: user, Enabled: true})
	f.command("grant", auth.AdminPayload{UserID: user, ProjectID: f.project, Enabled: true, Permissions: []string{string(auth.Read)}})
	login, err := f.app.Auth.Login(f.ctx, "adapter-reader@example.test", "reader password long 2026", "")
	if err != nil {
		f.t.Fatal(err)
	}
	reader, err := f.app.Auth.Authenticate(f.ctx, login.Token)
	if err != nil {
		f.t.Fatal(err)
	}
	scope, err := f.app.Auth.Authorize(f.ctx, reader, f.org, []model.ID{f.project}, auth.Read)
	if err != nil {
		f.t.Fatal(err)
	}
	f.reader = &scope
	return scope
}

type stored struct {
	ts      model.UnixNano
	payload model.Payload
}

func (f *fixture) scan(kind model.Kind) []stored {
	f.t.Helper()
	rows, err := f.app.Storage.Scan(f.ctx, f.readerScope(), storage.ScanRequest{Projects: []model.ID{f.project}, Signal: kind, Start: math.MinInt64, End: math.MaxInt64})
	if err != nil {
		f.t.Fatal(err)
	}
	defer rows.Close()
	var out []stored
	for {
		page, err := rows.Next(f.ctx)
		if err == io.EOF {
			break
		}
		if err != nil {
			f.t.Fatal(err)
		}
		for i := range page.Len() {
			out = append(out, stored{ts: page.ObservedTimes[i], payload: page.Values[i]})
		}
	}
	return out
}

// ---- corpus access: wrappers over corpus.go that fail the test on error ----

var (
	snappyDecode    = SnappyDecode
	newMetricRecord = NewMetricRecord
)

const fmtNormalize = FmtNormalize

var reasonOf = corpus.ReasonOf

func (f *fixture) profile() InputProfile { return f.Harness.Profile() }

func repoRoot(t testing.TB) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "conformance", "query", "source-lock.json")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("repository root not found")
		}
		dir = parent
	}
}

func queryDir(t testing.TB) string { return filepath.Join(repoRoot(t), "conformance", "query") }

func loadCorpus(t testing.TB) []corpusCase {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(queryDir(t), "cases", "input-normalization.json"))
	if err != nil {
		t.Fatal(err)
	}
	cases, err := corpus.ParseCorpus(raw)
	if err != nil {
		t.Fatal(err)
	}
	return cases
}

func semanticOf(t testing.TB, c corpusCase) []byte {
	t.Helper()
	raw, err := c.Semantic(queryDir(t))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func wireOf(t testing.TB, c corpusCase, enc Encoding) []byte {
	t.Helper()
	raw, err := c.Wire(queryDir(t), enc)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func (f *fixture) profileFor(c corpusCase) InputProfile {
	f.t.Helper()
	p, err := f.Harness.ProfileFor(c)
	if err != nil {
		f.t.Fatal(err)
	}
	return p
}

func (f *fixture) decode(c corpusCase, cfg InputProfile, body []byte) ([]model.Batch, error) {
	return f.Harness.Decode(c, cfg, body)
}

func encodeRW(t testing.TB, in semRW) []byte {
	t.Helper()
	raw, err := corpus.EncodeRemoteWrite(in)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func lokiProto(t testing.TB, in semLoki) []byte {
	t.Helper()
	raw, err := corpus.EncodeLokiProto(in)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func canonical(t testing.TB, v any) any {
	t.Helper()
	out, err := corpus.CanonicalJSON(v)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func sortedProjection(t testing.TB, list []any) []string {
	t.Helper()
	out, err := corpus.SortedProjection(list)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func projectBatches(t testing.TB, batches []model.Batch) []any { return corpus.ProjectRecords(batches) }
