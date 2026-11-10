// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"runtime"
)

// These are set at link time by build/release.go (-ldflags -X); a plain `go build` keeps
// the development values, which say so instead of pretending to be a release.
var (
	version = "0.0.0-dev"
	commit  = "unknown"
	buildID = "unknown"
)

// supportedPlatforms are the production server targets. Soundpost SDKs also run on macOS
// and Windows, but that does not certify server disk durability there.
var supportedPlatforms = []string{"linux/amd64", "linux/arm64"}

// versionInfo is the whole `soundpost version --json` document: what was built and how,
// never a hostname, path or configuration value.
type versionInfo struct {
	Version            string   `json:"version"`
	Commit             string   `json:"commit"`
	BuildID            string   `json:"build_id"`
	GoVersion          string   `json:"go_version"`
	Platform           string   `json:"platform"`
	SupportedPlatforms []string `json:"supported_platforms"`
	UIEmbedded         bool     `json:"ui_embedded"`
}

func currentVersion() versionInfo {
	_, embedded := embeddedWeb()
	return versionInfo{Version: version, Commit: commit, BuildID: buildID, GoVersion: runtime.Version(), Platform: runtime.GOOS + "/" + runtime.GOARCH, SupportedPlatforms: append([]string(nil), supportedPlatforms...), UIEmbedded: embedded}
}

func runVersion(args []string, out io.Writer) error {
	f := flag.NewFlagSet("version", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	asJSON := f.Bool("json", false, "machine-readable output")
	if err := f.Parse(args); err != nil || f.NArg() != 0 {
		return fmt.Errorf("usage: soundpost version [--json]")
	}
	v := currentVersion()
	if *asJSON {
		return json.NewEncoder(out).Encode(v)
	}
	_, err := fmt.Fprintf(out, "soundpost %s (commit %s, build %s, %s, %s)\n", v.Version, v.Commit, v.BuildID, v.GoVersion, v.Platform)
	return err
}
