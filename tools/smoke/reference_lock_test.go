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

// The estate runs only from content-addressed images the run never pulls. A third-party image is
// `${REFERENCE_*_IMAGE:-name@sha256:<full digest>}` (the digest is the default; an operator may name another pinned image through the
// variable, and the smoke refuses an unpinned one). A first-party image is built from this tree, so it has no digest until it is built:
// it is `${REFERENCE_{NODE,TOOLS,ESTATE}_IMAGE:?...}`, a variable with no default that the run sets to the id of the image it built
// (the smoke refuses anything that is not `sha256:<64 hex>`). Never a tag a registry could move; every service says `pull_policy: never`.
// The second form exists because of 07.04#12 (the compose file covers the whole estate, TestReferenceComposeCoversTheWholeEstate: the node,
// the provisioning tool and the applications are images built from this tree); D78's backing-services-only file had third-party images only.
func TestReferenceComposeRunsOnlyDigestPinnedImages(t *testing.T) {
	c, text := readReferenceCompose(t)
	if strings.Contains(text, "\r") {
		t.Fatal("compose.yaml must use LF line endings")
	}
	if len(c.Services) == 0 {
		t.Fatal("no services")
	}
	thirdParty := regexp.MustCompile(`^\$\{REFERENCE_[A-Z0-9_]+_IMAGE:-[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}\}$`)
	builtHere := regexp.MustCompile(`^\$\{REFERENCE_(NODE|TOOLS|ESTATE)_IMAGE:\?[^}]+\}$`)
	for name, s := range c.Services {
		if !thirdParty.MatchString(s.Image) && !builtHere.MatchString(s.Image) {
			t.Errorf("%s image %q is neither ${REFERENCE_*_IMAGE:-name@sha256:<digest>} nor a required ${REFERENCE_{NODE,TOOLS,ESTATE}_IMAGE:?...}: a tag or an abbreviated reference would be resolved by the runtime", name, s.Image)
		}
		if s.PullPolicy != "never" {
			t.Errorf("%s does not say pull_policy: never", name)
		}
	}
}
