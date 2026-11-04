// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package symbolicate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"soundpost/internal/artifacts"
	"soundpost/internal/auth"
	"soundpost/internal/model"
	"testing"
	"time"
)

// These tests exercise the exact identity and worker protocol below the opaque
// auth boundary. The external integration tests exercise real auth/artifacts.
func testManifest() artifacts.Manifest {
	return artifacts.Manifest{Version: 1, Org: model.NewID(), Project: model.NewID(), Source: model.NewID(), Build: model.NewID(), DebugID: "debug-exact", GeneratedSHA256: model.HashCanonical([]byte("generated")), MapSHA256: model.HashCanonical([]byte("map")), Path: "dist/app.js", Size: 64, RetainUntil: model.UnixNano(time.Now().Add(time.Hour).UnixNano())}
}
func TestSymbolicationBuildNotReleaseLabel(t *testing.T) {
	m := testManifest()
	id := model.NewID()
	hash := model.HashCanonical([]byte("stored normalized map"))
	blob := model.BlobManifest{Org: m.Org, Project: m.Project, Source: m.Source, Root: id, Build: m.Build, DebugID: m.DebugID, Path: m.Path, GeneratedSHA256: m.GeneratedSHA256, MapSHA256: m.MapSHA256, Hash: hash, Size: 64, RetainUntil: m.RetainUntil}
	ref := artifacts.Artifact{ID: id, Manifest: m, Map: model.BlobReceipt{Manifest: blob, Hash: hash}}
	if !matches(id, m.Build, ref) {
		t.Fatal("authoritative exact identity rejected")
	}
	if matches(id, model.NewID(), ref) {
		t.Fatal("wrong build selected")
	}
	if matches(model.NewID(), m.Build, ref) {
		t.Fatal("wrong artifact selected")
	}
	for _, mutate := range []func(*model.ArtifactManifest){func(m *model.ArtifactManifest) { m.DebugID = "release-renamed" }, func(m *model.ArtifactManifest) { m.GeneratedSHA256 = model.HashCanonical([]byte("other")) }, func(m *model.ArtifactManifest) { m.MapSHA256 = model.HashCanonical([]byte("other")) }, func(m *model.ArtifactManifest) { m.Path = "dist/other.js" }, func(m *model.ArtifactManifest) { m.Org = model.NewID() }, func(m *model.ArtifactManifest) { m.Project = model.NewID() }, func(m *model.ArtifactManifest) { m.Source = model.NewID() }} {
		bad := ref
		mutate(&bad.Manifest)
		if matches(id, m.Build, bad) {
			t.Fatal("manifest/retained-byte identity mismatch accepted")
		}
	}
}
func TestWorkerLimitsPreserveOriginalFrames(t *testing.T) {
	col := uint32(0)
	original := model.Frame{Module: "safe/module", Function: "original", Artifact: "not-a-link", Line: 1, Column: &col, InApp: true}
	s, e := New(nil, Config{})
	if e == nil || s != nil {
		t.Fatal("nil reader accepted")
	}
	// No scoped authority is fabricated, and unsupported/denied work retains the original.
	s, e = New(&unusedReader{}, Config{})
	if e != nil {
		t.Fatal(e)
	}
	got, e := s.Resolve(context.Background(), auth.Scope{}, model.NewID(), []model.Frame{original})
	if e != nil || len(got) != 1 || !reflect.DeepEqual(got[0].Original, original) || got[0].Reason != Unavailable {
		t.Fatalf("original lost: %#v %v", got, e)
	}
	for _, raw := range []string{`{"version":3,"sources":["../private"],"names":[],"mappings":"AAAA"}`, `{"version":3,"sources":["a.ts"],"names":[],"mappings":"!"}`} {
		in := workerInput{Version: 1, Map: []byte(raw), MapHash: model.HashCanonical([]byte(raw)), Line: 1}
		result := resolveInput(in)
		if result.Reason != InvalidMap || result.Position != nil {
			t.Fatal("invalid map resolved", result)
		}
	}
	oversized := workerInput{Version: 1, Map: make([]byte, MaxMapBytes+1), Line: 1}
	if resolveInput(oversized).Reason != ResourceLimit {
		t.Fatal("map byte limit bypass")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	out, e := s.Resolve(ctx, auth.Scope{}, model.NewID(), []model.Frame{original})
	if e != nil || out[0].Reason != Deadline || !reflect.DeepEqual(out[0].Original, original) {
		t.Fatal("cancellation lost original")
	}
}
func TestSourceContextGrantSeparate(t *testing.T) {
	public := []byte(`{"version":3,"sources":["src/app.ts"],"names":[],"mappings":"AAAA","sourcesContent":["SOURCE CANARY"]}`)
	in := workerInput{Version: 1, Map: public, MapHash: model.HashCanonical(public), Line: 1}
	got := resolveInput(in)
	encoded, _ := json.Marshal(got)
	if got.Reason != Resolved || bytes.Contains(encoded, []byte("CANARY")) || got.SourceContext != nil {
		t.Fatalf("default source leaked: %s", encoded)
	}
	private := []byte(`{"sources":["src/app.ts"],"sourcesContent":["first\nsecond"]}`)
	in.Sources = private
	in.SourcesHash = model.HashCanonical(private)
	in.IncludeSources = true
	got = resolveInput(in)
	if got.SourceContext == nil || *got.SourceContext != "first" {
		t.Fatal("separately supplied granted context missing", got)
	}
	in.IncludeSources = false
	got = resolveInput(in)
	if got.SourceContext != nil {
		t.Fatal("implicit private source release")
	}
}
func TestWorkerClosedDTOAndHash(t *testing.T) {
	var in workerInput
	if decodeClosed(bytes.NewBufferString(`{"version":1,"command":"sh"}`), &in, MaxInputBytes) == nil {
		t.Fatal("open command DTO")
	}
	if decodeClosed(bytes.NewBufferString(`{"version":1} {"version":1}`), &in, MaxInputBytes) == nil {
		t.Fatal("trailing DTO")
	}
	raw := []byte(`{"version":3,"sources":["a.ts"],"names":[],"mappings":"AAAA"}`)
	if resolveInput(workerInput{Version: 1, Map: raw, MapHash: model.HashCanonical([]byte("other")), Line: 1}).Reason != CorruptArtifact {
		t.Fatal("unverified worker map")
	}
}
func TestCacheBoundedAndVisibilityKeyed(t *testing.T) {
	c := newCache(8)
	a := cacheKey{Visibility: "org-a", Root: model.NewID()}
	b := a
	b.Visibility = "org-b"
	c.put(a, []byte("123456"))
	if c.get(b) != nil {
		t.Fatal("cross-visibility cache hit")
	}
	c.put(b, []byte("abcdef"))
	if c.get(a) != nil || string(c.get(b)) != "abcdef" {
		t.Fatal("cache not bounded")
	}
}

type unusedReader struct{}

func (*unusedReader) Lookup(context.Context, auth.Scope, model.ID) (artifacts.Artifact, error) {
	return artifacts.Artifact{}, errors.New("unexpected read")
}
func (*unusedReader) Get(context.Context, auth.Scope, model.ID) (io.ReadCloser, error) {
	return nil, errors.New("unexpected read")
}
func (*unusedReader) GetSources(context.Context, auth.Scope, model.ID) (io.ReadCloser, error) {
	return nil, errors.New("unexpected read")
}
func TestAdmissionDeadlinePreservesOriginalFrames(t *testing.T) {
	s, e := New(&unusedReader{}, Config{})
	if e != nil {
		t.Fatal(e)
	}
	s.slots <- struct{}{}
	s.slots <- struct{}{}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	original := model.Frame{Module: "safe", Function: "original", Artifact: "dist/app.js", Line: 1}
	got, e := s.Resolve(ctx, auth.Scope{}, model.NewID(), []model.Frame{original})
	if e != nil || got[0].Reason != Deadline || !reflect.DeepEqual(got[0].Original, original) {
		t.Fatal("queued work bypassed bounded admission", got, e)
	}
}
func TestCacheReturnsDefensiveCopies(t *testing.T) {
	c := newCache(64)
	k := cacheKey{Root: model.NewID()}
	in := []byte("abcdef")
	c.put(k, in)
	in[0] = 'X'
	got := c.get(k)
	got[1] = 'Y'
	if string(c.get(k)) != "abcdef" {
		t.Fatal("cached bytes aliased by caller")
	}
}
