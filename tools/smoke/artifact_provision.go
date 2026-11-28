// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// artifactProvisionMapBytes is the smallest retained (sourcesContent-stripped) map that makes
// artifact-upload's default multi-fragment requirement hold with margin.
const artifactProvisionMapBytes = 2*model.ArtifactFragmentLimit + 64<<10

// artifactFixtureMap builds a source map whose retained part is at least retained bytes and whose
// sourcesContent (served only by the explicit sources read) has one distinct entry per source.
func artifactFixtureMap(retained int) ([]byte, error) {
	sources := []string{"src/app.ts", "src/lib/util.ts", "src/lib/format.ts"}
	content := make([]string, len(sources))
	for i, s := range sources {
		content[i] = fmt.Sprintf("// PRIVATE SOURCE %d\nexport const marker%d = %q;\n", i, i, s)
	}
	srcJSON, e := json.Marshal(sources)
	if e != nil {
		return nil, e
	}
	contentJSON, e := json.Marshal(content)
	if e != nil {
		return nil, e
	}
	const line = "AAAA;"
	head := fmt.Sprintf(`{"version":3,"sources":%s,"names":[],"mappings":"`, srcJSON)
	tail := fmt.Sprintf(`","sourcesContent":%s}`, contentJSON)
	lines := (retained - len(head) + len(line) - 1) / len(line)
	if lines < 1 {
		lines = 1
	}
	var b strings.Builder
	b.Grow(len(head) + lines*len(line) + len(tail))
	b.WriteString(head)
	b.WriteString(strings.Repeat(line, lines))
	b.WriteString(tail)
	return []byte(b.String()), nil
}

// runArtifactProvision creates the private fixture consumed by `artifact-upload --fixture-config`:
// a fresh state directory below --base-dir with an owner, two orgs, one onboarded source in the first,
// a source_content manifest, a multi-fragment map, an artifact-write and an artifact-read token for the
// first org and a live artifact-read token that belongs to the second org only (the other-org
// credential). It prints only the configuration path.
func runArtifactProvision(args []string) error {
	flags := flag.NewFlagSet("artifact-provision", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	base := flags.String("base-dir", "", "directory that receives the run-* fixture (default $HOME/sp-artifact-fixture)")
	retained := flags.Int("retained-bytes", artifactProvisionMapBytes, "retained map size in bytes")
	if e := flags.Parse(args); e != nil {
		return e
	}
	if *base == "" {
		home, e := os.UserHomeDir()
		if e != nil {
			return e
		}
		*base = filepath.Join(home, "sp-artifact-fixture")
	}
	if e := os.MkdirAll(*base, 0700); e != nil {
		return e
	}
	run, e := os.MkdirTemp(*base, "run-")
	if e != nil {
		return e
	}
	state := filepath.Join(run, "state")
	if e = os.Mkdir(state, 0700); e != nil {
		return e
	}
	mapBytes, e := artifactFixtureMap(*retained)
	if e != nil {
		return e
	}
	ctx := context.Background()
	app, e := appcore.Open(state)
	if e != nil {
		return e
	}
	closed := false
	defer func() {
		if !closed {
			app.Close()
		}
	}()
	org, project, otherOrg, otherProject := model.NewID(), model.NewID(), model.NewID(), model.NewID()
	source, build := model.NewID(), model.NewID()
	bootstrap, e := app.Control.BootstrapToken()
	if e != nil {
		return e
	}
	session, e := app.Auth.Bootstrap(ctx, bootstrap, "artifact-smoke@example.test", "artifact smoke password 2026")
	if e != nil {
		return e
	}
	actor, e := app.Auth.Authenticate(ctx, session.Token)
	if e != nil {
		return e
	}
	commands := []struct {
		org  model.ID
		kind string
		p    auth.AdminPayload
	}{
		{org, "create_org", auth.AdminPayload{Name: "artifact-smoke"}},
		{org, "create_project", auth.AdminPayload{ID: project, Name: "builds"}},
		{otherOrg, "create_org", auth.AdminPayload{Name: "artifact-smoke-other"}},
		{otherOrg, "create_project", auth.AdminPayload{ID: otherProject, Name: "other-builds"}},
	}
	for _, cmd := range commands {
		cmd.p.Reason = "artifact smoke fixture"
		raw, e := json.Marshal(cmd.p)
		if e != nil {
			return e
		}
		var rev model.Revision
		if e = app.Control.View(ctx, func(st model.ControlState) error { rev = st.Revision; return nil }); e != nil {
			return e
		}
		if _, e = app.Auth.AdminCommand(ctx, actor, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: rev, OrgID: cmd.org, Kind: cmd.kind, Payload: raw}); e != nil {
			return e
		}
	}
	if e = app.Control.Update(ctx, func(st *model.ControlState) error {
		o := st.Orgs[org.String()]
		o.Members[session.User.String()] = true
		o.Grants[session.User.String()+":"+project.String()] = []string{"artifacts.write", "artifacts.read", "raw.read"}
		cfg, e := json.Marshal(auth.SourcePolicyConfig{ProjectID: project, Enabled: true, Readers: []model.ID{session.User}})
		if e != nil {
			return e
		}
		o.Settings["source_policy:"+source.String()] = cfg
		st.Orgs[org.String()] = o
		other := st.Orgs[otherOrg.String()]
		other.Members[session.User.String()] = true
		other.Grants[session.User.String()+":"+otherProject.String()] = []string{"artifacts.read"}
		st.Orgs[otherOrg.String()] = other
		return nil
	}); e != nil {
		return e
	}
	if _, e = app.Auth.OnboardSource(ctx, actor, auth.SourceOnboarding{
		CommandID: model.NewID(), Org: org, Project: project, Source: source,
		Expires: model.UnixNano(time.Now().Add(24 * time.Hour).UnixNano()),
		Policy: model.SourcePolicy{
			Enabled: true, Revision: 1, Class: "structured", Kinds: []model.Kind{model.Metric},
			Resources: model.ResourceRegistry{
				Services: []model.ID{model.NewID()}, Environments: []model.ID{model.NewID()},
				Builds: []model.ID{build}, Instances: []string{"artifact-smoke"},
			},
			RetentionDays: map[model.Kind]uint32{model.Metric: 30}, MaxBytes: 1 << 30, MaxSeries: 1000,
		},
		Reason: "artifact smoke fixture source authority",
	}); e != nil {
		return e
	}
	expires := time.Now().Add(24 * time.Hour).Unix()
	var issueErr error
	issue := func(o, p model.ID, reason string, perms ...auth.Permission) string {
		t, e := app.Auth.IssueServerToken(ctx, actor, o, session.User, []model.ID{p}, perms, expires, reason)
		if e != nil && issueErr == nil {
			issueErr = e
		}
		return t.Token
	}
	// A source_content artifact is private: writing it and reading its sources both also need raw.read on the token (machine tokens are restricted to what they were issued).
	uploader := issue(org, project, "artifact smoke uploader", auth.ArtifactWrite, auth.RawRead)
	reader := issue(org, project, "artifact smoke reader", auth.ArtifactRead, auth.RawRead)
	denied := issue(otherOrg, otherProject, "artifact smoke other-org reader", auth.ArtifactRead)
	if issueErr != nil {
		return issueErr
	}
	closed = true
	if e = app.Close(); e != nil {
		return e
	}
	m := model.ArtifactManifest{
		Version: 1, Org: org, Project: project, Source: source, Build: build,
		DebugID: "debug-smoke-1", Path: "dist/app.js", SourceContent: true,
		GeneratedSHA256: model.HashCanonical([]byte("generated")),
		MapSHA256:       model.HashCanonical(mapBytes), Size: model.Uint64(len(mapBytes)),
		RetainUntil: model.UnixNano(time.Now().Add(24 * time.Hour).UnixNano()),
	}
	manifest, e := json.Marshal(m)
	if e != nil {
		return e
	}
	files := map[string][]byte{
		"manifest.json": manifest, "artifact.map": mapBytes,
		"uploader.token": []byte(uploader), "reader.token": []byte(reader), "denied.token": []byte(denied),
	}
	for name, data := range files {
		if e = os.WriteFile(filepath.Join(run, name), data, 0600); e != nil {
			return e
		}
	}
	cfg, e := json.Marshal(artifactSmokeConfig{
		StateDir: state, ManifestFile: filepath.Join(run, "manifest.json"), MapFile: filepath.Join(run, "artifact.map"),
		UploaderTokenFile: filepath.Join(run, "uploader.token"), ReaderTokenFile: filepath.Join(run, "reader.token"),
		DeniedTokenFile: filepath.Join(run, "denied.token"), DeniedOrg: otherOrg, DeniedProject: otherProject,
	})
	if e != nil {
		return e
	}
	path := filepath.Join(run, "config.json")
	if e = os.WriteFile(path, cfg, 0600); e != nil {
		return e
	}
	fmt.Println(path)
	return nil
}
