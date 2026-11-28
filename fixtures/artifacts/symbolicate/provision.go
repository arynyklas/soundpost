// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/artifacts"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/symbolicate"
	"os"
	"path/filepath"
	"time"
)

// provision prepares the private preprovisioned state the fixture requires, for a
// throwaway local run: a fresh application state with one organization, project and
// onboarded source, one bootstrap user holding artifact read/write grants, the exact
// manifest of the actual generated simple.mjs and its map, a private token file, and
// the fixture configuration naming the operator's sandbox JSON. It never uploads
// the map (the fixture run does) and never writes a token anywhere but a 0600 file.
func provision(dir, artifactDir, sandboxFile string) error {
	var sandbox symbolicate.Config
	if e := readJSON(sandboxFile, &sandbox); e != nil {
		return errors.New("invalid sandbox configuration")
	}
	raw, e := os.ReadFile(filepath.Join(artifactDir, "simple.mjs.map"))
	if e != nil {
		return errors.New("actual generated map missing")
	}
	generated, e := os.ReadFile(filepath.Join(artifactDir, "simple.mjs"))
	if e != nil {
		return errors.New("actual generated executable missing")
	}
	if e = os.MkdirAll(dir, 0o700); e != nil {
		return e
	}
	state := filepath.Join(dir, "state")
	app, e := appcore.Open(state)
	if e != nil {
		return errors.New("application state could not be created")
	}
	defer app.Close()
	ctx := context.Background()
	bootstrap, e := app.Control.BootstrapToken()
	if e != nil {
		return e
	}
	session, e := app.Auth.Bootstrap(ctx, bootstrap, "fixture@example.test", "symbolicate fixture password 2026")
	if e != nil {
		return e
	}
	actor, e := app.Auth.Authenticate(ctx, session.Token)
	if e != nil {
		return e
	}
	org, project, source, build := model.NewID(), model.NewID(), model.NewID(), model.NewID()
	for _, command := range []struct {
		kind string
		p    auth.AdminPayload
	}{{"create_org", auth.AdminPayload{Name: "symbolicate"}}, {"create_project", auth.AdminPayload{ID: project, Name: "sources"}}} {
		command.p.Reason = "symbolication fixture"
		payload, e := json.Marshal(command.p)
		if e != nil {
			return e
		}
		var rev model.Revision
		if e = app.Control.View(ctx, func(st model.ControlState) error { rev = st.Revision; return nil }); e != nil {
			return e
		}
		if _, e = app.Auth.AdminCommand(ctx, actor, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: rev, OrgID: org, Kind: command.kind, Payload: payload}); e != nil {
			return e
		}
	}
	if e = app.Control.Update(ctx, func(st *model.ControlState) error {
		o := st.Orgs[org.String()]
		o.Members[session.User.String()] = true
		o.Grants[session.User.String()+":"+project.String()] = []string{"artifacts.write", "artifacts.read"}
		cfg, e := json.Marshal(auth.SourcePolicyConfig{ProjectID: project, Enabled: true, Readers: []model.ID{session.User}})
		if e != nil {
			return e
		}
		o.Settings["source_policy:"+source.String()] = cfg
		st.Orgs[org.String()] = o
		return nil
	}); e != nil {
		return e
	}
	if _, e = app.Auth.OnboardSource(ctx, actor, auth.SourceOnboarding{CommandID: model.NewID(), Org: org, Project: project, Source: source, Expires: model.UnixNano(time.Now().Add(time.Hour).UnixNano()), Reason: "symbolication fixture", Policy: model.SourcePolicy{Enabled: true, Revision: 1, Class: "structured", Kinds: []model.Kind{model.Metric}, Resources: model.ResourceRegistry{Services: []model.ID{model.NewID()}, Environments: []model.ID{model.NewID()}, Builds: []model.ID{build}, Instances: []string{"symbolication-fixture"}}, RetentionDays: map[model.Kind]uint32{model.Metric: 30}, MaxBytes: 1 << 30, MaxSeries: 1000}}); e != nil {
		return e
	}
	manifest := artifacts.Manifest{Version: 1, Org: org, Project: project, Source: source, Build: build, DebugID: "fixture-debug", GeneratedSHA256: model.HashCanonical(generated), MapSHA256: model.HashCanonical(raw), Path: "dist/simple.mjs", Size: model.Uint64(len(raw)), RetainUntil: model.UnixNano(time.Now().Add(time.Hour).UnixNano())}
	token := filepath.Join(dir, "token")
	files := []struct {
		name string
		v    any
	}{{"manifest.json", manifest}, {"fixture.json", fixtureConfig{StateDir: state, ManifestFile: filepath.Join(dir, "manifest.json"), UploaderTokenFile: token, ReaderTokenFile: token, Sandbox: sandbox}}}
	if e = os.WriteFile(token, []byte(session.Token+"\n"), 0o600); e != nil {
		return e
	}
	for _, f := range files {
		b, e := json.Marshal(f.v)
		if e != nil {
			return e
		}
		if e = os.WriteFile(filepath.Join(dir, f.name), b, 0o600); e != nil {
			return e
		}
	}
	fmt.Println("symbolicate fixture: provisioned private state; configuration at", filepath.Join(dir, "fixture.json"))
	return nil
}
