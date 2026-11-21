// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"encoding/json"
	"os"
	"runtime"
	"strings"
	"testing"
)

func TestVersionJSONCarriesBuildIdentityAndNothingElse(t *testing.T) {
	oldV, oldC, oldB := version, commit, buildID
	version, commit, buildID = "1.4.0", "0123456789abcdef0123456789abcdef01234567", "sha256:feedface"
	defer func() { version, commit, buildID = oldV, oldC, oldB }()

	var out bytes.Buffer
	if err := runVersion([]string{"--json"}, &out); err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(out.Bytes()))
	decoder.DisallowUnknownFields()
	var got versionInfo
	if err := decoder.Decode(&got); err != nil {
		t.Fatalf("version --json is not the closed document: %v\n%s", err, out.String())
	}
	if got.Version != "1.4.0" || got.Commit != "0123456789abcdef0123456789abcdef01234567" || got.BuildID != "sha256:feedface" {
		t.Fatalf("build identity lost: %+v", got)
	}
	if got.GoVersion != runtime.Version() || got.Platform != runtime.GOOS+"/"+runtime.GOARCH {
		t.Fatalf("toolchain identity wrong: %+v", got)
	}
	if len(got.SupportedPlatforms) != 2 || got.SupportedPlatforms[0] != "linux/amd64" || got.SupportedPlatforms[1] != "linux/arm64" {
		t.Fatalf("server platforms: %v", got.SupportedPlatforms)
	}
	// A version document must not identify the host or the operator.
	host, _ := os.Hostname()
	home, _ := os.UserHomeDir()
	for _, private := range []string{host, home} {
		if private != "" && strings.Contains(out.String(), private) {
			t.Fatalf("version output contains %q", private)
		}
	}
}

func TestVersionTextAndUsage(t *testing.T) {
	var out bytes.Buffer
	if err := runVersion(nil, &out); err != nil || !strings.HasPrefix(out.String(), "soundpost ") || strings.Count(out.String(), "\n") != 1 {
		t.Fatalf("%q %v", out.String(), err)
	}
	for _, args := range [][]string{{"extra"}, {"--nope"}, {"--json", "extra"}} {
		if err := runVersion(args, &bytes.Buffer{}); err == nil {
			t.Fatalf("%v accepted", args)
		}
	}
}

// supported_platforms must not be mutable through the returned document.
func TestVersionDocumentDoesNotAliasTheSupportedList(t *testing.T) {
	v := currentVersion()
	v.SupportedPlatforms[0] = "plan9/arm"
	if currentVersion().SupportedPlatforms[0] != "linux/amd64" {
		t.Fatal("the supported platform list is shared")
	}
}
