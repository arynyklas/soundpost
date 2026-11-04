// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// This opt-in local fixture uses real private app state, actual Vite output,
// protected HTTPS, and the explicitly selected OS sandbox. It never fabricates
// mappings or contacts a configured customer/remote endpoint.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"soundpost/internal/appcore"
	"soundpost/internal/artifacts"
	"soundpost/internal/auth"
	"soundpost/internal/model"
	"soundpost/internal/symbolicate"
	"strings"
)

type fixtureConfig struct {
	StateDir          string             `json:"state_dir"`
	ManifestFile      string             `json:"manifest_file"`
	UploaderTokenFile string             `json:"uploader_token_file"`
	ReaderTokenFile   string             `json:"reader_token_file"`
	Sandbox           symbolicate.Config `json:"sandbox"`
}
type request struct {
	Build  model.ID      `json:"build"`
	Frames []model.Frame `json:"frames"`
}

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, "symbolicate fixture failed:", e)
		os.Exit(1)
	}
}
func run() error {
	configFile := flag.String("config", "", "private preprovisioned fixture configuration")
	artifactDir := flag.String("artifact-dir", "", "actual Node22/Vite generator output")
	endpointEnv := flag.String("endpoint-env", "SOUNDPOST_FIXTURE_API", "variable assigned the ephemeral local HTTPS fixture endpoint; must initially be unset")
	restart := flag.Bool("restart-worker", false, "resolve again through a fresh worker")
	timeout := flag.Bool("inject-timeout", false, "kill an actual bounded busy worker before the second resolution")
	probes := flag.Bool("sandbox-probes", false, "exercise real file/network/exec denial and memory kill")
	flag.Parse()
	if *configFile == "" || *artifactDir == "" || *endpointEnv == "" || os.Getenv(*endpointEnv) != "" {
		return errors.New("private config, actual fixture directory and unused local endpoint variable required")
	}
	var config fixtureConfig
	if e := readJSON(*configFile, &config); e != nil {
		return errors.New("invalid private fixture config")
	}
	var manifest artifacts.Manifest
	if e := readJSON(config.ManifestFile, &manifest); e != nil {
		return errors.New("invalid exact manifest")
	}
	raw, e := os.ReadFile(filepath.Join(*artifactDir, "simple.mjs.map"))
	if e != nil {
		return errors.New("actual generated map missing")
	}
	generated, e := os.ReadFile(filepath.Join(*artifactDir, "simple.mjs"))
	if e != nil {
		return errors.New("actual generated executable missing")
	}
	var position struct {
		GeneratedLine   uint32 `json:"generatedLine"`
		GeneratedColumn uint32 `json:"generatedColumn"`
		SourceID        string `json:"sourceID"`
		Line            uint32 `json:"line"`
		Column          uint32 `json:"column"`
	}
	if e = readJSON(filepath.Join(*artifactDir, "simple.position.json"), &position); e != nil {
		return errors.New("actual thrown position missing")
	}
	if position.SourceID != "simple.ts" || position.Line != 4 || position.Column != 8 || position.GeneratedLine == 0 || manifest.GeneratedSHA256 != model.HashCanonical(generated) || manifest.MapSHA256 != model.HashCanonical(raw) || manifest.Size != model.Uint64(len(raw)) || manifest.SourceContent {
		return errors.New("actual build/map/position identity mismatch")
	}
	app, e := appcore.Open(config.StateDir)
	if e != nil {
		return errors.New("private app state unavailable")
	}
	defer app.Close()
	ctx := context.Background()
	uploadToken, e := readToken(config.UploaderTokenFile)
	if e != nil {
		return e
	}
	readTokenValue, e := readToken(config.ReaderTokenFile)
	if e != nil {
		return e
	}
	actor, e := app.Auth.Authenticate(ctx, uploadToken)
	if e != nil {
		return errors.New("fixture uploader denied")
	}
	write, e := app.Auth.Authorize(ctx, actor, manifest.Org, []model.ID{manifest.Project}, auth.ArtifactWrite)
	if e != nil {
		return errors.New("fixture uploader scope denied")
	}
	artifact, e := app.Artifacts.Put(ctx, write, manifest, bytes.NewReader(raw))
	if e != nil {
		return errors.New("actual artifact upload failed")
	}
	service, e := app.NewSymbolicator(config.Sandbox)
	if e != nil {
		return e
	}
	original := model.Frame{Module: "fixture", Function: "throwingFixture", Artifact: artifact.ID.String(), Line: position.GeneratedLine, Column: &position.GeneratedColumn, InApp: true}
	body := request{Build: manifest.Build, Frames: []model.Frame{original}}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/symbolicate" {
			http.NotFound(w, r)
			return
		}
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		credential, e := app.Auth.Authenticate(r.Context(), token)
		if e != nil {
			http.Error(w, "not found", 404)
			return
		}
		scope, e := app.Auth.Authorize(r.Context(), credential, manifest.Org, []model.ID{manifest.Project}, auth.ArtifactRead)
		if e != nil {
			http.Error(w, "not found", 404)
			return
		}
		var input request
		if e = decode(io.LimitReader(r.Body, 1<<20), &input); e != nil {
			http.Error(w, "invalid", 400)
			return
		}
		result, e := service.Resolve(r.Context(), scope, input.Build, input.Frames)
		if e != nil {
			http.Error(w, "invalid", 400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}))
	defer server.Close()
	if e = os.Setenv(*endpointEnv, server.URL+"/symbolicate"); e != nil {
		return e
	}
	defer os.Unsetenv(*endpointEnv)
	client := server.Client()
	client.Timeout = symbolicate.ProcessTimeout * 2
	resolve := func() error {
		encoded, e := json.Marshal(body)
		if e != nil {
			return e
		}
		req, e := http.NewRequest("POST", os.Getenv(*endpointEnv), bytes.NewReader(encoded))
		if e != nil {
			return e
		}
		req.Header.Set("Authorization", "Bearer "+readTokenValue)
		req.Header.Set("Content-Type", "application/json")
		response, e := client.Do(req)
		if e != nil {
			return errors.New("local verified-TLS request failed")
		}
		defer response.Body.Close()
		var results []symbolicate.SymbolicatedFrame
		if response.StatusCode != 200 || decode(io.LimitReader(response.Body, 1<<20), &results) != nil || len(results) != 1 {
			return errors.New("local symbolication request rejected")
		}
		r := results[0]
		if r.Reason != symbolicate.Resolved || r.Resolved == nil || r.Resolved.Source != "simple.ts" || r.Resolved.Line != 4 || r.Resolved.Column != 8 || r.SourceContext != nil || r.Original.Artifact != artifact.ID.String() || r.MapSHA256 != manifest.MapSHA256 {
			return fmt.Errorf("actual source-map result rejected: reason=%s", r.Reason)
		}
		return nil
	}
	if e = resolve(); e != nil {
		return e
	}
	if *timeout {
		r := symbolicate.Probe(ctx, config.Sandbox, symbolicate.ProbeTimeout)
		if r.Reason != symbolicate.Deadline {
			return fmt.Errorf("actual timeout not enforced: %s", r.Reason)
		}
	}
	if *restart || *timeout {
		if e = resolve(); e != nil {
			return e
		}
	}
	if *probes {
		for _, kind := range []symbolicate.ProbeKind{symbolicate.ProbeFile, symbolicate.ProbeNetwork, symbolicate.ProbeExec, symbolicate.ProbeMemory} {
			r := symbolicate.Probe(ctx, config.Sandbox, kind)
			if kind == symbolicate.ProbeMemory {
				if !r.OOMKilled {
					return errors.New("actual OS memory kill not observed")
				}
			} else if !r.Denied {
				return errors.New("actual syscall restriction not observed")
			}
		}
	}
	fmt.Println("symbolicate: exact actual Vite throw simple.ts:4:8; default sources excluded; requested sandbox/restart probes exercised")
	return nil
}
func readJSON(name string, out any) error {
	f, e := os.Open(name)
	if e != nil {
		return e
	}
	defer f.Close()
	return decode(io.LimitReader(f, 1<<20), out)
}
func decode(r io.Reader, out any) error {
	d := json.NewDecoder(r)
	d.DisallowUnknownFields()
	if e := d.Decode(out); e != nil {
		return e
	}
	var trailing any
	if d.Decode(&trailing) != io.EOF {
		return errors.New("trailing data")
	}
	return nil
}
func readToken(name string) (string, error) {
	f, e := os.Open(name)
	if e != nil {
		return "", errors.New("private token unavailable")
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, 4097))
	if e != nil || len(b) > 4096 {
		return "", errors.New("invalid private token")
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		return "", errors.New("missing private token")
	}
	return s, nil
}
