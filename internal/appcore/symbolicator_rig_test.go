// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"soundpost/internal/artifacts"
	"soundpost/internal/auth"
	"soundpost/internal/httpapi"
	"soundpost/internal/model"
	"soundpost/internal/symbolicate"
)

// fixtureMap maps generated line 1, column 0 to src/app.ts:7:3 named "boom". The
// canary rides in sourcesContent on source line 7 (the mapped line), which the artifact service must strip and no
// response, log or temp file may carry.
const (
	symCanary = "SYMBOLICATOR-SOURCE-CANARY-4c1f9a"
	symMapDoc = `{"version":3,"file":"out.js","sources":["src/app.ts"],"sourcesContent":["// 1\n// 2\n// 3\n// 4\n// 5\n// 6\n// ` + symCanary + `\n"],"names":["boom"],"mappings":"AAMGA"}`
)

type symTenant struct{ org, project, source, build model.ID }

// symRig is a real appcore.Open application served over real HTTPS with a real
// session, a real org/project/source and the real artifact upload route.
type symRig struct {
	t       *testing.T
	app     *App
	srv     *httptest.Server
	session auth.Session
	actor   auth.Credential
	a       symTenant
}

func newSymRig(t *testing.T) *symRig {
	t.Helper()
	r := &symRig{t: t}
	var err error
	if r.app, err = Open(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.app.Close() })
	ctx := context.Background()
	bootstrap, err := r.app.Control.BootstrapToken()
	if err != nil {
		t.Fatal(err)
	}
	if r.session, err = r.app.Auth.Bootstrap(ctx, bootstrap, "symbolicator@example.test", "symbolicator wiring password 2026"); err != nil {
		t.Fatal(err)
	}
	if r.actor, err = r.app.Auth.Authenticate(ctx, r.session.Token); err != nil {
		t.Fatal(err)
	}
	r.a = r.tenant("tenant-a", []string{"artifacts.write", "artifacts.read", "raw.read"}, true)
	r.serve()
	return r
}

// serve (re)starts the HTTPS server over the App's current Register routes, so a
// ConfigureSymbolicator call made before it is what the routes use.
func (r *symRig) serve() {
	r.t.Helper()
	if r.srv != nil {
		r.srv.Close()
	}
	r.srv = httptest.NewTLSServer(httpapi.NewServer("", r.app.Auth, nil, r.app.Register).Handler)
	r.t.Cleanup(r.srv.Close)
}

func (r *symRig) revision() model.Revision {
	var rev model.Revision
	if err := r.app.Control.View(context.Background(), func(st model.ControlState) error { rev = st.Revision; return nil }); err != nil {
		r.t.Fatal(err)
	}
	return rev
}

// tenant creates an organization with one project, grants the signed-in user the
// given permissions on it and, when sourced, onboards one upload source.
func (r *symRig) tenant(name string, grants []string, sourced bool) symTenant {
	r.t.Helper()
	ctx := context.Background()
	ten := symTenant{org: model.NewID(), project: model.NewID(), source: model.NewID(), build: model.NewID()}
	for _, command := range []struct {
		kind string
		p    auth.AdminPayload
	}{{"create_org", auth.AdminPayload{Name: name}}, {"create_project", auth.AdminPayload{ID: ten.project, Name: name + "-sources"}}} {
		command.p.Reason = "symbolicator wiring fixture"
		raw, err := json.Marshal(command.p)
		if err != nil {
			r.t.Fatal(err)
		}
		if _, err = r.app.Auth.AdminCommand(ctx, r.actor, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: r.revision(), OrgID: ten.org, Kind: command.kind, Payload: raw}); err != nil {
			r.t.Fatal(err)
		}
	}
	if err := r.app.Control.Update(ctx, func(st *model.ControlState) error {
		o := st.Orgs[ten.org.String()]
		o.Members[r.session.User.String()] = true
		o.Grants[r.session.User.String()+":"+ten.project.String()] = grants
		if sourced {
			cfg, err := json.Marshal(auth.SourcePolicyConfig{ProjectID: ten.project, Enabled: true, Readers: []model.ID{r.session.User}})
			if err != nil {
				return err
			}
			o.Settings["source_policy:"+ten.source.String()] = cfg
		}
		st.Orgs[ten.org.String()] = o
		return nil
	}); err != nil {
		r.t.Fatal(err)
	}
	if sourced {
		_, err := r.app.Auth.OnboardSource(ctx, r.actor, auth.SourceOnboarding{CommandID: model.NewID(), Org: ten.org, Project: ten.project, Source: ten.source, Expires: model.UnixNano(time.Now().Add(time.Hour).UnixNano()), Reason: "symbolicator wiring fixture", Policy: model.SourcePolicy{Enabled: true, Revision: 1, Class: "structured", Kinds: []model.Kind{model.Metric}, Resources: model.ResourceRegistry{Services: []model.ID{model.NewID()}, Environments: []model.ID{model.NewID()}, Builds: []model.ID{ten.build}, Instances: []string{"symbolicator-wiring"}}, RetentionDays: map[model.Kind]uint32{model.Metric: 30}, MaxBytes: 1 << 30, MaxSeries: 1000}})
		if err != nil {
			r.t.Fatal(err)
		}
	}
	return ten
}

type symResp struct {
	status int
	body   []byte
}

func (r *symRig) request(method, path, contentType string, body []byte) symResp {
	r.t.Helper()
	req, err := http.NewRequest(method, r.srv.URL+path, bytes.NewReader(body))
	if err != nil {
		r.t.Fatal(err)
	}
	req.Header.Set("Cookie", "__Host-soundpost="+r.session.Token)
	req.Header.Set("X-CSRF-Token", r.session.CSRF)
	req.Header.Set("Origin", r.srv.URL)
	req.Header.Set("Content-Type", contentType)
	resp, err := r.srv.Client().Do(req)
	if err != nil {
		r.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		r.t.Fatal(err)
	}
	return symResp{resp.StatusCode, raw}
}

// manifest0 is the exact manifest of a stored map; the generated bytes are a stub.
func (r *symRig) manifest(ten symTenant, raw []byte, path, debug string, private bool) artifacts.Manifest {
	generated := []byte("generated " + path)
	return artifacts.Manifest{Version: 1, Org: ten.org, Project: ten.project, Source: ten.source, Build: ten.build, DebugID: debug, GeneratedSHA256: model.HashCanonical(generated), MapSHA256: model.HashCanonical(raw), Path: path, SourceContent: private, Size: model.Uint64(len(raw)), RetainUntil: model.UnixNano(time.Now().Add(time.Hour).UnixNano())}
}

// upload sends the map through the real multipart artifact route.
func (r *symRig) upload(ten symTenant, raw []byte, path, debug string, private bool) (symResp, artifacts.Artifact) {
	r.t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	m, _ := json.Marshal(r.manifest(ten, raw, path, debug, private))
	w, _ := mw.CreateFormField("manifest")
	w.Write(m)
	w, _ = mw.CreateFormFile("file", "out.js.map")
	w.Write(raw)
	mw.Close()
	resp := r.request("POST", "/api/v1/artifacts", mw.FormDataContentType(), buf.Bytes())
	var a artifacts.Artifact
	if resp.status == 200 {
		if err := json.Unmarshal(resp.body, &a); err != nil {
			r.t.Fatal(err)
		}
	}
	return resp, a
}

func (r *symRig) mustUpload(ten symTenant, raw []byte, path, debug string, private bool) artifacts.Artifact {
	r.t.Helper()
	resp, a := r.upload(ten, raw, path, debug, private)
	if resp.status != 200 || a.ID == (model.ID{}) {
		r.t.Fatalf("artifact upload over the real route: %d %s", resp.status, resp.body)
	}
	return a
}

func symFrame(artifact string, line, column uint32) model.Frame {
	return model.Frame{Module: "bundle", Function: "minified", Artifact: artifact, Line: line, Column: &column}
}

// frames POSTs /api/v1/evidence/frames as the signed-in user.
func (r *symRig) frames(ten symTenant, includeSources bool, frames ...model.Frame) (symResp, httpapi.FramesView) {
	r.t.Helper()
	raw, _ := json.Marshal(httpapi.FramesBody{Org: ten.org, Project: ten.project, Build: ten.build, Frames: frames, IncludeSources: includeSources})
	resp := r.request("POST", "/api/v1/evidence/frames", "application/json", raw)
	var v httpapi.FramesView
	if resp.status == 200 {
		if err := json.Unmarshal(resp.body, &v); err != nil {
			r.t.Fatalf("frames body: %v %s", err, resp.body)
		}
	}
	return resp, v
}

// ociSandbox derives the documented OCI qualification configuration from the
// local image; it never pulls, builds or tags anything. ok is false (and the test
// skips) when this host has no runtime or image.
func ociSandbox(t *testing.T) symbolicate.Config {
	t.Helper()
	docker, err := exec.LookPath("docker")
	if err != nil {
		t.Skip("real sandbox not exercised: no docker runtime on PATH")
	}
	tag := os.Getenv("SOUNDPOST_SYMBOLICATE_IMAGE")
	if tag == "" {
		tag = "soundpost-symbolicate:qualification"
	}
	out, err := exec.Command(docker, "image", "inspect", "--format", `{{.Id}} {{index .Config.Labels "org.soundpost.worker.sha256"}}`, tag).Output()
	if err != nil {
		t.Skip("real sandbox not exercised: local image " + tag + " is not present")
	}
	fields := strings.Fields(string(out))
	if len(fields) != 2 || !strings.HasPrefix(fields[0], "sha256:") {
		t.Skip("real sandbox not exercised: image has no worker provenance label")
	}
	var h model.Hash
	if err = json.Unmarshal([]byte(`"`+fields[1]+`"`), &h); err != nil {
		t.Skip("real sandbox not exercised: image worker label is not a hash")
	}
	return symbolicate.Config{Mode: "oci", OCIRuntime: docker, OCIImage: fields[0], WorkerSHA256: h}
}

// writeConfig stores a symbolicate.Config as the private operator file `soundpost
// serve --symbolicate-config` reads.
func writeConfig(t *testing.T, c symbolicate.Config) string {
	t.Helper()
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(t.TempDir(), "symbolicate.json")
	if err = os.WriteFile(name, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return name
}
