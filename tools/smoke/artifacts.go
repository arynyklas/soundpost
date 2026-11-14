// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/artifacts"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/durablefs"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/model"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// This private configuration is provisioned outside the public repository by the
// integration owner. Existing actual user/server/source authorities are reused.
type artifactSmokeConfig struct {
	StateDir          string `json:"state_dir"`
	ManifestFile      string `json:"manifest_file"`
	MapFile           string `json:"map_file"`
	UploaderTokenFile string `json:"uploader_token_file"`
	ReaderTokenFile   string `json:"reader_token_file"`
	DeniedTokenFile   string `json:"denied_token_file"`
}

func readArtifactSmokeConfig(path string) (artifactSmokeConfig, artifacts.Manifest, error) {
	var c artifactSmokeConfig
	var m artifacts.Manifest
	raw, e := os.ReadFile(path)
	if e != nil || model.StrictJSON(raw, &c) != nil {
		return c, m, fmt.Errorf("private artifact fixture configuration required")
	}
	if c.StateDir == "" || c.ManifestFile == "" || c.MapFile == "" || c.UploaderTokenFile == "" || c.ReaderTokenFile == "" || c.DeniedTokenFile == "" {
		return c, m, fmt.Errorf("incomplete private artifact fixture configuration")
	}
	raw, e = os.ReadFile(c.ManifestFile)
	if e != nil || model.StrictJSON(raw, &m) != nil {
		return c, m, fmt.Errorf("invalid private artifact manifest")
	}
	if e = artifacts.ValidateManifest(m); e != nil {
		return c, m, e
	}
	return c, m, nil
}
func artifactSmokeToken(path string) (string, error) {
	raw, e := os.ReadFile(path)
	if e != nil || len(raw) == 0 || len(raw) > 4096 {
		return "", fmt.Errorf("private fixture credential unavailable")
	}
	token := strings.TrimSpace(string(raw))
	if strings.ContainsAny(token, " \t\r\n") {
		return "", fmt.Errorf("invalid private fixture credential")
	}
	return token, nil
}

type artifactPublicationPause struct {
	*control.Store
	ready string
}

func (p artifactPublicationPause) PublishArtifact(ctx context.Context, scope auth.Scope, intent model.ArtifactReferenceIntent) (model.ArtifactReferenceIntent, error) {
	raw, e := json.Marshal(intent)
	if e != nil {
		return model.ArtifactReferenceIntent{}, e
	}
	if e = os.WriteFile(p.ready, raw, 0600); e != nil {
		return model.ArtifactReferenceIntent{}, e
	}
	if e = durablefs.SyncFileAndDir(p.ready); e != nil {
		return model.ArtifactReferenceIntent{}, e
	}
	timer := time.NewTimer(5 * time.Minute)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return model.ArtifactReferenceIntent{}, ctx.Err()
	case <-timer.C:
		return model.ArtifactReferenceIntent{}, model.Fail(model.Timeout)
	}
}
func runArtifactUploadChild(args []string) error {
	flags := flag.NewFlagSet("artifact-upload-child", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("fixture-config", "", "private fixture configuration")
	ready := flags.String("ready-file", "", "private synchronization file")
	if e := flags.Parse(args); e != nil {
		return e
	}
	if *ready == "" {
		return fmt.Errorf("private readiness path required")
	}
	c, m, e := readArtifactSmokeConfig(*configPath)
	if e != nil {
		return e
	}
	app, e := appcore.Open(c.StateDir)
	if e != nil {
		return e
	}
	defer app.Close()
	token, e := artifactSmokeToken(c.UploaderTokenFile)
	if e != nil {
		return e
	}
	actor, e := app.Auth.Authenticate(context.Background(), token)
	if e != nil || !actor.IsServerToken() {
		return fmt.Errorf("actual private artifact-write server token required")
	}
	scope, e := app.Auth.Authorize(context.Background(), actor, m.Org, []model.ID{m.Project}, auth.ArtifactWrite)
	if e != nil {
		return e
	}
	service, e := artifacts.New(app.Storage, artifactPublicationPause{app.Control, *ready}, app.Auth)
	if e != nil {
		return e
	}
	input, e := os.Open(c.MapFile)
	if e != nil {
		return fmt.Errorf("private fixture input unavailable")
	}
	defer input.Close()
	_, e = service.Put(context.Background(), scope, m, input)
	return e
}
func runArtifactUpload(args []string) error {
	flags := flag.NewFlagSet("artifact-upload", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("fixture-config", "", "private fixture configuration")
	artifactDir := flags.String("artifact-dir", "", "sanitized output directory")
	if e := flags.Parse(args); e != nil {
		return e
	}
	if *artifactDir == "" || *configPath == "" {
		return fmt.Errorf("artifact-dir and private fixture-config required")
	}
	c, m, e := readArtifactSmokeConfig(*configPath)
	if e != nil {
		return e
	}
	private, e := os.MkdirTemp("", "soundpost-artifact-smoke-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(private)
	ready := filepath.Join(private, "before-reference.json")
	executable, e := os.Executable()
	if e != nil {
		return e
	}
	command := exec.Command(executable, "artifact-upload-child", "--fixture-config", *configPath, "--ready-file", ready)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if e = command.Start(); e != nil {
		return e
	}
	terminated := false
	finished := make(chan error, 1)
	go func() { finished <- command.Wait() }()
	defer func() {
		if !terminated {
			command.Process.Kill()
			<-finished
		}
	}()
	deadline := time.NewTimer(45 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	var staged model.ArtifactReferenceIntent
waiting:
	for {
		select {
		case <-deadline.C:
			return fmt.Errorf("artifact child did not reach durable-byte cut")
		case <-finished:
			terminated = true
			return fmt.Errorf("artifact child exited before durable-byte cut")
		case <-ticker.C:
			raw, err := os.ReadFile(ready)
			if os.IsNotExist(err) {
				continue
			}
			if err != nil {
				return err
			}
			if model.StrictJSON(raw, &staged) != nil {
				continue
			}
			break waiting
		}
	}
	if e = command.Process.Kill(); e != nil {
		return e
	}
	<-finished
	terminated = true
	app, e := appcore.Open(c.StateDir)
	if e != nil {
		return e
	}
	defer app.Close()
	if e = app.Storage.VerifyBlob(context.Background(), staged.Map); e != nil {
		return e
	}
	if staged.Sources != nil {
		if e = app.Storage.VerifyBlob(context.Background(), *staged.Sources); e != nil {
			return e
		}
	}
	// Every byte receipt of the killed child verified durable before publication.
	killedAfterBytes := true
	reader, e := artifactSmokeToken(c.ReaderTokenFile)
	if e != nil {
		return e
	}
	actor, e := app.Auth.Authenticate(context.Background(), reader)
	if e != nil {
		return e
	}
	readScope, e := app.Auth.Authorize(context.Background(), actor, m.Org, []model.ID{m.Project}, auth.ArtifactRead)
	if e != nil {
		return e
	}
	_, orphanReadErr := app.Artifacts.Get(context.Background(), readScope, staged.ID)
	orphanDenied := orphanReadErr != nil
	if !orphanDenied {
		return fmt.Errorf("orphan artifact was publicly readable")
	}
	server := httptest.NewTLSServer(httpapi.NewServer("", app.Auth, nil, app.Register).Handler)
	defer server.Close()
	client := server.Client()
	uploader, e := artifactSmokeToken(c.UploaderTokenFile)
	if e != nil {
		return e
	}
	input, e := os.ReadFile(c.MapFile)
	if e != nil {
		return fmt.Errorf("private fixture input unavailable")
	}
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, e := writer.CreateFormField("manifest")
	if e != nil {
		return e
	}
	raw, _ := json.Marshal(m)
	if _, e = part.Write(raw); e != nil {
		return e
	}
	part, e = writer.CreateFormFile("file", "artifact.map")
	if e != nil {
		return e
	}
	if _, e = part.Write(input); e != nil {
		return e
	}
	if e = writer.Close(); e != nil {
		return e
	}
	request, e := http.NewRequest("POST", server.URL+"/api/v1/artifacts", &body)
	if e != nil {
		return e
	}
	request.Header.Set("Authorization", "Bearer "+uploader)
	request.Header.Set("Content-Type", writer.FormDataContentType())
	response, e := client.Do(request)
	if e != nil {
		return e
	}
	replyBytes, e := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	response.Body.Close()
	if e != nil || response.StatusCode != http.StatusOK {
		return fmt.Errorf("artifact resume upload status %d", response.StatusCode)
	}
	var published model.ArtifactReferenceIntent
	if model.StrictJSON(replyBytes, &published) != nil {
		return fmt.Errorf("invalid artifact receipt")
	}
	a, _ := model.CanonicalJSON(staged.Map)
	b, _ := model.CanonicalJSON(published.Map)
	sameCursors := bytes.Equal(a, b) && published.ID == staged.ID && published.CommandID == staged.ID && published.ControlRevision != 0
	if sources := staged.Sources; sources != nil {
		sc, _ := model.CanonicalJSON(*sources)
		pc, _ := model.CanonicalJSON(published.Sources)
		sameCursors = sameCursors && published.Sources != nil && bytes.Equal(sc, pc)
	}
	if !sameCursors {
		return fmt.Errorf("resumed artifact changed byte cursors or omitted reference intent")
	}
	readHTTP := func(token, operation string) (int, []byte, error) {
		payload, _ := json.Marshal(httpapi.ArtifactReadRequest{Operation: operation, Org: m.Org, Project: m.Project, ID: published.ID})
		req, err := http.NewRequest("POST", server.URL+"/api/v1/artifacts", bytes.NewReader(payload))
		if err != nil {
			return 0, nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return 0, nil, err
		}
		defer resp.Body.Close()
		data, err := io.ReadAll(io.LimitReader(resp.Body, model.ArtifactBundleLimit+1))
		return resp.StatusCode, data, err
	}
	status, download, e := readHTTP(reader, "read")
	if e != nil || status != http.StatusOK || model.HashCanonical(download) != published.Map.Hash || bytes.Contains(download, []byte("sourcesContent")) {
		return fmt.Errorf("artifact protected map read/hash mismatch")
	}
	denied, e := artifactSmokeToken(c.DeniedTokenFile)
	if e != nil {
		return e
	}
	deniedStatus, _, e := readHTTP(denied, "read")
	if e != nil || deniedStatus != 401 && deniedStatus != 403 && deniedStatus != 404 {
		return fmt.Errorf("artifact denied credential released a read")
	}
	if m.SourceContent {
		status, sourceBytes, err := readHTTP(reader, "sources")
		if err != nil || status != 200 || published.Sources == nil || model.HashCanonical(sourceBytes) != published.Sources.Hash {
			return fmt.Errorf("artifact explicit source read/hash mismatch")
		}
	}
	if e = os.MkdirAll(*artifactDir, 0700); e != nil {
		return e
	}
	report := struct {
		Version          int                         `json:"version"`
		KilledAfterBytes bool                        `json:"killed_after_bytes"`
		OrphanDenied     bool                        `json:"orphan_denied"`
		SameCursors      bool                        `json:"same_cursors"`
		MapHash          model.Hash                  `json:"map_hash"`
		Fragments        []model.BlobFragmentReceipt `json:"fragments"`
		ControlRevision  model.Revision              `json:"control_revision"`
		CommandID        model.ID                    `json:"command_id"`
		DeniedStatus     int                         `json:"denied_status"`
		Replication      string                      `json:"replication"`
	}{1, killedAfterBytes, orphanDenied, sameCursors, published.Map.Hash, published.Map.Fragments, published.ControlRevision, published.CommandID, deniedStatus, "single_voter_only"}
	raw, e = json.MarshalIndent(report, "", "  ")
	if e != nil {
		return e
	}
	return os.WriteFile(filepath.Join(*artifactDir, "artifact-upload.json"), raw, 0600)
}
