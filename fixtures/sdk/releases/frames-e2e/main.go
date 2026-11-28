// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

// Command frames-e2e is the end-to-end proof of decision D7 (original JavaScript frames):
//
//	real Vite 7 and real webpack 5 compile fixtures/sdk/releases/source.ts
//	  -> packages/build uploads each private source map to a real `soundpost serve` (verified TLS)
//	  -> a compiled release bundle throws; the Node SDK captures the thrown error (descriptor-only stack read)
//	  -> the error is delivered to the real server and acknowledged by durable receipt
//	  -> the server is stopped, the stored error is read back from the product's own storage,
//	  -> the server is restarted and the stored frames go through the real POST /api/v1/evidence/frames route
//	     (OCI sandbox symbolicator), which must answer the original source file, line and function.
//
// It runs on Linux (WSL). Windows Node runs the bundlers because their native packages are installed for
// Windows; Linux Node 22 (and optionally 24) and Bun run the captured bundle.
//
//	go run ./fixtures/sdk/releases/frames-e2e --binary <soundpost> --win-node <node.exe> --node22 <node> --bun <bun> [--node24 <node>]
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/arynyklas/soundpost/fixtures/sdk/estate"
	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/storage"
	"github.com/arynyklas/soundpost/internal/symbolicate"
)

type receipt struct{ Bundler, ID, Build, DebugID, Path string }
type capture struct {
	Bundler, Runtime string
	EventID          model.ID
	Batches          []string
}
type stored struct {
	Capture capture
	Build   model.ID
	Error   model.ErrorOccurrence
}

type run struct {
	est      *estate.Estate
	root     string
	work     string
	winNode  string
	runtimes map[string]string // label -> binary (node22, node24, bun)
	bun      string
	receipts map[string]receipt
	captures []capture
}

func main() {
	r := &run{runtimes: map[string]string{}, receipts: map[string]receipt{}}
	var binary, node22, node24 string
	flag.StringVar(&binary, "binary", "", "linux soundpost binary")
	flag.StringVar(&r.winNode, "win-node", "", "Windows node.exe that owns the installed Vite/webpack")
	flag.StringVar(&node22, "node22", "", "Linux Node 22")
	flag.StringVar(&node24, "node24", "", "Linux Node 24 (optional)")
	flag.StringVar(&r.bun, "bun", "", "Linux Bun")
	flag.StringVar(&r.root, "root", ".", "repository root")
	symImage := flag.String("symbolicate-image", "soundpost-symbolicate:qualification", "LOCAL symbolication sandbox image (never pulled)")
	out := flag.String("out", "", "evidence JSON path")
	flag.Parse()
	if binary == "" || r.winNode == "" || node22 == "" || r.bun == "" {
		estate.Fail("--binary, --win-node, --node22 and --bun are required")
	}
	r.runtimes["node22"], r.runtimes["bun"] = node22, r.bun
	if node24 != "" {
		r.runtimes["node24"] = node24
	}
	var err error
	r.root, err = filepath.Abs(r.root)
	estate.Must(err, "root")
	// The work directory lives in the checkout so Windows Node and Linux Node see the same bytes.
	r.work = filepath.Join(r.root, ".tools", fmt.Sprintf("frames-e2e-%d", time.Now().UnixNano()))
	estate.Must(os.MkdirAll(r.work, 0o755), "work dir")
	defer os.RemoveAll(r.work)
	r.est = estate.New(estate.Options{Binary: binary, Work: r.work, SymImage: *symImage, Kinds: []model.Kind{model.ErrorKind}, Builds: []string{"vite", "webpack"}, Name: "frames"})
	defer r.est.Close()
	r.est.Start()
	r.est.Provision()
	r.buildAndUpload()
	r.captureAll()
	r.est.Stop()
	found := r.readStored()
	r.est.Start()
	evidence := r.resolve(found)
	evidence["symbolicator"] = r.est.SymStatus
	raw, _ := json.MarshalIndent(evidence, "", "  ")
	fmt.Println(string(raw))
	if *out != "" {
		estate.Must(os.WriteFile(*out, append(raw, '\n'), 0o644), "evidence file")
	}
}

func wslWindows(path string) string {
	out, err := estate.RunOut("wslpath", "-w", path)
	estate.Must(err, "wslpath")
	return out
}

func (r *run) buildAndUpload() {
	for _, bundler := range []string{"vite", "webpack"} {
		dir := filepath.Join(r.work, bundler)
		cfg := filepath.Join(r.work, bundler+"-build.json")
		rcpt := filepath.Join(r.work, bundler+"-receipt.json")
		// The config carries the artifact-write token; it lives only in the run's private work directory.
		estate.WriteJSON(cfg, map[string]string{"endpoint": "https://" + r.est.Addr, "org": r.est.Org.String(), "project": r.est.Project.String(), "source": r.est.Source.String(), "build": r.est.Builds[bundler].String(), "token": r.est.WriteToken})
		cmd := exec.Command(r.winNode, wslWindows(filepath.Join(r.root, "fixtures/sdk/releases/frames-build.mjs")), "--bundler", bundler, "--config", wslWindows(cfg), "--out", wslWindows(dir), "--receipt", wslWindows(rcpt))
		cmd.Env = append(os.Environ(), "NODE_EXTRA_CA_CERTS="+wslWindows(r.est.CA), "WSLENV=NODE_EXTRA_CA_CERTS")
		out, err := cmd.CombinedOutput()
		if err != nil {
			estate.Fail("%s build+upload: %v: %s", bundler, err, estate.Tail(string(out)))
		}
		var rc receipt
		raw, err := os.ReadFile(rcpt)
		estate.Must(err, "receipt")
		estate.Must(json.Unmarshal(raw, &rc), "receipt json")
		if len(rc.ID) != 32 || rc.Path == "" {
			estate.Fail("%s receipt invalid", bundler)
		}
		r.receipts[bundler] = rc
		estate.Logf("%s: uploaded %s as artifact %s", bundler, rc.Path, rc.ID)
	}
}

func (r *run) captureAll() {
	bundle := filepath.Join(r.work, "capture.mjs")
	if out, err := estate.RunOut(r.bun, "build", filepath.Join(r.root, "fixtures/sdk/releases/frames-capture.mjs"), "--target=node", "--outfile", bundle); err != nil {
		estate.Fail("bun build capture: %v: %s", err, estate.Tail(out))
	}
	sdk := filepath.Join(r.work, "sdk.json")
	for _, bundler := range []string{"vite", "webpack"} {
		estate.WriteJSON(sdk, r.est.SDKConfig(r.est.Builds[bundler], "fixture-1"))
		rc := r.receipts[bundler]
		dist := filepath.Join(r.work, bundler)
		for _, label := range []string{"node22", "node24", "bun"} {
			bin, ok := r.runtimes[label]
			if !ok {
				continue
			}
			cmd := exec.Command(bin, bundle, "--config", sdk, "--bundle", filepath.Join(dist, rc.Path), "--root", dist, "--artifact-id", rc.Path+"="+rc.ID)
			cmd.Env = append(os.Environ(), "NODE_EXTRA_CA_CERTS="+r.est.CA)
			out, err := cmd.CombinedOutput()
			if err != nil {
				estate.Fail("%s capture under %s: %v: %s", bundler, label, err, estate.Tail(string(out)))
			}
			var res struct {
				EventID string   `json:"event_id"`
				Batches []string `json:"acknowledged_batch_ids"`
			}
			line := out[bytes.LastIndexByte(bytes.TrimSpace(out), '\n')+1:]
			estate.Must(json.Unmarshal(bytes.TrimSpace(line), &res), "capture result")
			eid, err := model.ParseID(res.EventID)
			estate.Must(err, "event id")
			r.captures = append(r.captures, capture{Bundler: bundler, Runtime: label, EventID: eid, Batches: res.Batches})
			estate.Logf("%s/%s: captured %s, acknowledged batches %v", bundler, label, res.EventID, res.Batches)
		}
	}
}

// readStored opens the stopped product's own storage and returns the captured errors as stored.
func (r *run) readStored() []stored {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	app, err := appcore.Open(r.est.DataDir)
	estate.Must(err, "open data dir")
	defer app.Close()
	scope, err := app.Auth.AuthorizeSystem(ctx, r.est.Org, []model.ID{r.est.Project}, auth.Read)
	estate.Must(err, "system read scope")
	it, err := app.Storage.Scan(ctx, scope, storage.ScanRequest{Projects: []model.ID{r.est.Project}, Signal: model.ErrorKind, Start: math.MinInt64, End: math.MaxInt64})
	estate.Must(err, "scan")
	defer it.Close()
	byEvent := map[model.ID]capture{}
	for _, c := range r.captures {
		byEvent[c.EventID] = c
	}
	var found []stored
	for {
		page, err := it.Next(ctx)
		if errors.Is(err, io.EOF) {
			break
		}
		estate.Must(err, "scan page")
		for i := range page.Len() {
			if c, ok := byEvent[page.IDs[i]]; ok && page.Values[i].Error != nil {
				found = append(found, stored{Capture: c, Build: page.Resources[i].Build, Error: *page.Values[i].Error})
			}
		}
	}
	if len(found) != len(r.captures) {
		estate.Fail("stored %d of %d captured errors", len(found), len(r.captures))
	}
	return found
}

// resolve sends every stored error's frames through the real frames route and asserts the original source position.
func (r *run) resolve(errs []stored) map[string]any {
	rows := []map[string]any{}
	for _, s := range errs {
		rc := r.receipts[s.Capture.Bundler]
		if len(s.Error.Frames) == 0 {
			estate.Fail("%s/%s: stored error has no frames", s.Capture.Bundler, s.Capture.Runtime)
		}
		status, raw := r.est.Post("/api/v1/evidence/frames", httpapi.FramesBody{Org: r.est.Org, Project: r.est.Project, Build: s.Build, Frames: s.Error.Frames}, r.est.ArtifactRead)
		estate.Expect("evidence_frames", status, raw, 200)
		var view httpapi.FramesView
		estate.Must(json.Unmarshal(raw, &view), "frames view")
		if len(view.Frames) != len(s.Error.Frames) {
			estate.Fail("frames view length")
		}
		resolved := -1
		for i, f := range view.Frames {
			if f.Original.Artifact == rc.ID && strings.Contains(f.Original.Function, "soundpostReleaseThrow") && f.Reason == string(symbolicate.Resolved) && f.Resolved != nil {
				resolved = i
				break
			}
		}
		if resolved < 0 {
			estate.Fail("%s/%s: no frame resolved to soundpostReleaseThrow: %s", s.Capture.Bundler, s.Capture.Runtime, estate.Tail(string(raw)))
		}
		f := view.Frames[resolved]
		if !strings.HasSuffix(f.Resolved.Source, "source.ts") || f.Resolved.Line != 6 {
			estate.Fail("%s/%s: resolved to %s:%d, want source.ts:6", s.Capture.Bundler, s.Capture.Runtime, f.Resolved.Source, f.Resolved.Line)
		}
		rows = append(rows, map[string]any{
			"bundler": s.Capture.Bundler, "runtime": s.Capture.Runtime, "event_id": s.Capture.EventID.String(), "acknowledged_batch_ids": s.Capture.Batches,
			"stored_frames": len(s.Error.Frames), "stored_exception_class": s.Error.Class, "artifact_id": rc.ID, "build": s.Build.String(),
			"original": map[string]any{"function": f.Original.Function, "module": f.Original.Module, "line": f.Original.Line, "column": f.Original.Column},
			"resolved": map[string]any{"source": f.Resolved.Source, "line": f.Resolved.Line, "column": f.Resolved.Column, "function": f.Resolved.Function}, "reason": f.Reason,
		})
	}
	return map[string]any{"decision": "D7", "fixture": "fixtures/sdk/releases/source.ts", "rows": rows, "restart_between_capture_and_resolve": true}
}
