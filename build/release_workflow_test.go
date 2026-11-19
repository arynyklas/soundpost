// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
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
