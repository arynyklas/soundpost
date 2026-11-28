// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
)

// `build release` consumes a prebuilt web/dist and refuses to run without one (stageUI), so the release
// dry-run workflow must install the pinned Node and build the UI from the locked inputs before the step
// that runs `build release`. A workflow that skips this fails its first build step on a clean checkout.
func TestReleaseWorkflowBuildsTheUIBeforeBuildRelease(t *testing.T) {
	workflow := deployFile(t, ".github/workflows/release.yml")
	release := strings.Index(workflow, "go run ./build release")
	if release < 0 {
		t.Fatal("release.yml does not run `go run ./build release`")
	}
	for _, need := range []string{".node.linux_22.url", "pnpm install --frozen-lockfile", "pnpm --filter @soundpost/web build"} {
		at := strings.Index(workflow, need)
		if at < 0 {
			t.Errorf("release.yml never runs %q, so web/dist does not exist when `build release` runs", need)
		} else if at > release {
			t.Errorf("release.yml runs %q after `build release`; web/dist must exist first", need)
		}
	}
}

// `corepack enable` activates the pnpm named by package.json "packageManager"; without an integrity hash corepack
// takes whatever the registry serves for that version. The release build therefore requires an exact version with
// its sha512 (pnpm@<major.minor.patch>+sha512.<128 hex>), never a range, a tag or a bare version.
var packageManagerPin = regexp.MustCompile(`^pnpm@[0-9]+\.[0-9]+\.[0-9]+\+sha512\.[0-9a-f]{128}$`)

func TestReleaseWorkflowPinsThePackageManagerWithItsIntegrityHash(t *testing.T) {
	var pkg struct {
		PackageManager string `json:"packageManager"`
	}
	if err := json.Unmarshal([]byte(deployFile(t, "package.json")), &pkg); err != nil {
		t.Fatal(err)
	}
	if !packageManagerPin.MatchString(pkg.PackageManager) {
		t.Fatalf("package.json packageManager %q must be pnpm@<exact version>+sha512.<hash>", pkg.PackageManager)
	}
	for _, bad := range []string{"pnpm@10.20.0", "pnpm@^10.20.0+sha512." + strings.Repeat("a", 128), "pnpm@10+sha512." + strings.Repeat("a", 128), "pnpm@latest", "pnpm@10.20.0+sha256." + strings.Repeat("a", 64), "pnpm@10.20.0+sha512." + strings.Repeat("A", 128), "pnpm@10.20.0+sha512." + strings.Repeat("a", 127)} {
		if packageManagerPin.MatchString(bad) {
			t.Errorf("the pin accepts %q", bad)
		}
	}
	// The hash is the one `build verify` pins from the registry's dist.integrity of that exact version (build/toolchains.json).
	var pins struct {
		Pnpm        string `json:"pnpm"`
		PnpmTarball struct {
			Integrity string `json:"integrity"`
		} `json:"pnpm_tarball"`
	}
	if err := json.Unmarshal([]byte(deployFile(t, "build/toolchains.json")), &pins); err != nil {
		t.Fatal(err)
	}
	if want := "pnpm@" + pins.Pnpm + "+sha512." + integrityHex(pins.PnpmTarball.Integrity); pkg.PackageManager != want {
		t.Errorf("package.json packageManager %q, want %q (the toolchains.json pin)", pkg.PackageManager, want)
	}
	workflow := deployFile(t, ".github/workflows/release.yml")
	enable, install := strings.Index(workflow, "corepack enable"), strings.Index(workflow, "pnpm install --frozen-lockfile")
	if enable < 0 || install < 0 || enable > install {
		t.Error("release.yml must run `corepack enable` before `pnpm install --frozen-lockfile`, so corepack verifies the pinned hash")
	}
}
