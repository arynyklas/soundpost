// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// lockEntries splits a uv-compiled, hash-locked requirements file into one normalized text per requirement
// (requirement line plus its --hash lines; comments dropped), keyed by lower-cased package name.
func lockEntries(t *testing.T, path string) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := strings.ReplaceAll(string(raw), "\r\n", "\n")
	if strings.Contains(path, "examples/reference") && text != string(raw) {
		t.Fatalf("%s must use LF line endings", path)
	}
	start := regexp.MustCompile(`^([A-Za-z0-9_.-]+)(?:\[[^\]]*\])?==`)
	out := map[string]string{}
	var name string
	var body []string
	flush := func() {
		if name != "" {
			out[name] = strings.Join(body, "\n")
		}
		name, body = "", nil
	}
	for _, line := range strings.Split(text, "\n") {
		if m := start.FindStringSubmatch(line); m != nil {
			flush()
			name = strings.ToLower(m[1])
		}
		if name == "" || strings.HasPrefix(strings.TrimSpace(line), "#") || strings.TrimSpace(line) == "" {
			continue
		}
		body = append(body, line)
	}
	flush()
	return out
}

// The reference estate installs its Python packages from examples/reference/requirements.lock; every entry must be the
// SDK's own pin, version, environment marker and hashes included, so the estate never runs an unpinned or different set.
func TestReferenceLockMatchesSDKLocks(t *testing.T) {
	reference := lockEntries(t, "../../examples/reference/requirements.lock")
	sdk := lockEntries(t, "../../sdk/python/requirements-integrations.lock")
	for name, entry := range lockEntries(t, "../../sdk/python/requirements-dev.lock") {
		if _, ok := sdk[name]; !ok {
			sdk[name] = entry
		}
	}
	// What the reference apps and the SDK integrations they use actually import (api/app.py, jobs/run.py, telemetry.py).
	for _, name := range []string{"cryptography", "psycopg", "psycopg-binary", "httpx", "httpcore", "h11", "anyio", "idna", "certifi", "typing-extensions", "cffi", "pycparser"} {
		if _, ok := reference[name]; !ok {
			t.Errorf("requirements.lock does not pin %s", name)
		}
	}
	for name, entry := range reference {
		want, ok := sdk[name]
		if !ok {
			t.Errorf("%s is pinned for the reference estate but not by the SDK locks", name)
			continue
		}
		if entry != want {
			t.Errorf("%s differs from the SDK lock:\n got %q\nwant %q", name, entry, want)
		}
		if !strings.Contains(entry, "--hash=sha256:") {
			t.Errorf("%s carries no hash", name)
		}
	}
	if len(reference) == 0 {
		t.Fatal("empty lock")
	}
}

// The estate's backing services run only from images the operator names by a local id and are never pulled: every `image:` of
// compose.yaml is a required environment reference (no tag, no registry name) and every service says `pull_policy: never`.
func TestReferenceComposeRunsOnlyNamedLocalImages(t *testing.T) {
	raw, err := os.ReadFile("../../examples/reference/compose.yaml")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if strings.Contains(text, "\r") {
		t.Fatal("compose.yaml must use LF line endings")
	}
	images := regexp.MustCompile(`(?m)^    image: (.*)$`).FindAllStringSubmatch(text, -1)
	services := regexp.MustCompile(`(?m)^  [a-z][a-z0-9_-]*:$`).FindAllString(text, -1)
	if len(images) == 0 || len(images) != len(services) {
		t.Fatalf("%d image line(s) for %d service(s)", len(images), len(services))
	}
	for _, m := range images {
		if !regexp.MustCompile(`^\$\{REFERENCE_[A-Z0-9_]+_IMAGE:\?[^}]+\}$`).MatchString(m[1]) {
			t.Errorf("image %q is not a required REFERENCE_*_IMAGE reference: a tag or registry name would be resolved by the runtime", m[1])
		}
	}
	if n := strings.Count(text, "    pull_policy: never\n"); n != len(services) {
		t.Errorf("%d of %d services say pull_policy: never", n, len(services))
	}
}
