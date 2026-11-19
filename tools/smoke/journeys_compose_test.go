// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
)

const (
	testDigest64 = "92620daddcd947f8d5ab5ba66e848702fe443d87fed30c4cea8e389fd78dfc55"
	testDigestB  = "5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b"
)

// An image reference of the estate is a content address: a full image id, or a name pinned by a full digest. A tag, a
// short id or an abbreviated digest is resolved by the runtime to whatever it holds at that moment.
func TestPinnedImageRef(t *testing.T) {
	for _, ok := range []string{
		"sha256:" + testDigest64,
		"postgres@sha256:" + testDigest64,
		"python@sha256:" + testDigestB,
		"docker.io/library/python@sha256:" + testDigestB,
		"registry.example:5000/team/img@sha256:" + testDigest64,
	} {
		if err := pinnedImageRef(ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	for name, bad := range map[string]string{
		"empty":                "",
		"short id":             "92620daddcd9",
		"tag":                  "postgres:16",
		"bare name":            "postgres",
		"latest":               "python:latest",
		"short digest":         "postgres@sha256:92620dad",
		"upper-case digest":    "postgres@sha256:" + strings.ToUpper(testDigest64),
		"tag and digest":       "postgres:16@sha256:" + testDigest64,
		"md5 digest":           "postgres@md5:" + testDigest64[:32],
		"digest of wrong size": "postgres@sha256:" + testDigest64 + "00",
		"space":                "postgres@sha256:" + testDigest64 + " ",
		"leading dash":         "-postgres@sha256:" + testDigest64,
		"id with a name":       "postgres sha256:" + testDigest64,
	} {
		if err := pinnedImageRef(bad); err == nil {
			t.Errorf("%s: %q was accepted", name, bad)
		}
	}
}

func testCompose() referenceCompose {
	return referenceCompose{File: "/repo/examples/reference/compose.yaml", Project: "soundpost-journeys-ab12cd34", TLSDir: "/work/compose-tls",
		PGPassword: "pw0123", PGPort: "40001", DependencyPort: "40002"}
}

func envMap(env []string) map[string]string {
	m := map[string]string{}
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		m[k] = v
	}
	return m
}

// The compose environment names exactly what compose.yaml requires, and an image supplied by the operator must itself be
// pinned: an unpinned one is refused before docker is asked anything.
func TestReferenceComposeEnvironment(t *testing.T) {
	c := testCompose()
	env, err := c.env()
	if err != nil {
		t.Fatal(err)
	}
	m := envMap(env)
	for k, want := range map[string]string{"REFERENCE_PG_PASSWORD": "pw0123", "REFERENCE_PG_PORT": "40001", "REFERENCE_DEPENDENCY_PORT": "40002", "REFERENCE_TLS_DIR": "/work/compose-tls"} {
		if m[k] != want {
			t.Errorf("%s = %q, want %q", k, m[k], want)
		}
	}
	for _, k := range []string{"REFERENCE_PG_IMAGE", "REFERENCE_PYTHON_IMAGE"} {
		if v, ok := m[k]; ok {
			t.Errorf("%s=%q set although no image was named: the compose file's own digest must apply", k, v)
		}
	}
	c.PGImage, c.DependencyImage = "postgres@sha256:"+testDigest64, "sha256:"+testDigestB
	if env, err = c.env(); err != nil {
		t.Fatal(err)
	}
	m = envMap(env)
	if m["REFERENCE_PG_IMAGE"] != c.PGImage || m["REFERENCE_PYTHON_IMAGE"] != c.DependencyImage {
		t.Errorf("named images not passed to compose: %v", m)
	}
	for name, mutate := range map[string]func(*referenceCompose){
		"postgres tag":      func(c *referenceCompose) { c.PGImage = "postgres:16" },
		"postgres short id": func(c *referenceCompose) { c.PGImage = "92620daddcd9" },
		"python tag":        func(c *referenceCompose) { c.DependencyImage = "python:3.12-slim" },
		"no password":       func(c *referenceCompose) { c.PGPassword = "" },
		"no postgres port":  func(c *referenceCompose) { c.PGPort = "" },
		"no dependency port": func(c *referenceCompose) {
			c.DependencyPort = ""
		},
		"no tls dir": func(c *referenceCompose) { c.TLSDir = "" },
		"no project": func(c *referenceCompose) { c.Project = "" },
		"no file":    func(c *referenceCompose) { c.File = "" },
	} {
		c := testCompose()
		mutate(&c)
		if _, err := c.env(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Every docker invocation is scoped to the run's own compose project, so two runs, and a developer's own stack, never share containers.
func TestReferenceComposeCommandIsScopedToItsProject(t *testing.T) {
	c := testCompose()
	got := c.command("up", "-d", "--wait", "postgres")
	want := []string{"docker", "compose", "-p", "soundpost-journeys-ab12cd34", "-f", "/repo/examples/reference/compose.yaml", "up", "-d", "--wait", "postgres"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("command = %v, want %v", got, want)
	}
	if got := c.command("down", "-v"); got[0] != "docker" || !slices.Contains(got, "-p") {
		t.Errorf("down is not project-scoped: %v", got)
	}
}

// The leaf key reaches the dependency container (uid 65534) through a bind mount of a directory of its own: readable by that
// user, holding the leaf and its key and nothing else (never the CA's private key, which the run does not even write).
func TestWriteComposeTLS(t *testing.T) {
	pki, err := newJourneyPKI(filepath.Join(t.TempDir(), "pki"))
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "compose-tls")
	if err = writeComposeTLS(pki, dir); err != nil {
		t.Fatal(err)
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	slices.Sort(names)
	if !reflect.DeepEqual(names, []string{"leaf.key", "leaf.pem"}) {
		t.Fatalf("files %v", names)
	}
	for src, name := range map[string]string{pki.Cert: "leaf.pem", pki.Key: "leaf.key"} {
		want, _ := os.ReadFile(src)
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || string(got) != string(want) {
			t.Errorf("%s differs from the run's own file (err %v)", name, err)
		}
		fi, _ := os.Stat(filepath.Join(dir, name))
		if fi.Mode().Perm()&0o044 != 0o044 {
			t.Errorf("%s mode %v is not readable by the container user", name, fi.Mode().Perm())
		}
	}
	fi, _ := os.Stat(dir)
	if fi.Mode().Perm()&0o055 != 0o055 {
		t.Errorf("directory mode %v cannot be entered by the container user", fi.Mode().Perm())
	}
}

// Decision (07.04#12): the estate's compose file runs the BACKING services (PostgreSQL and the uninstrumented dependency)
// and nothing else. The SDK-bearing applications and the product node are launched by the acceptance smoke, which alone
// holds the per-source credentials the node issues; this test pins that limit and the places that state it, so that
// neither the file nor the documentation can drift into claiming a whole-estate compose.
func TestReferenceComposeStartsOnlyBackingServices(t *testing.T) {
	raw, err := os.ReadFile("../../examples/reference/compose.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var services []string
	for _, m := range regexp.MustCompile(`(?m)^  ([a-z][a-z0-9_-]*):$`).FindAllStringSubmatch(string(raw), -1) {
		services = append(services, m[1])
	}
	slices.Sort(services)
	if !reflect.DeepEqual(services, []string{"dependency", "postgres"}) {
		t.Fatalf("compose services %v: the estate's compose file is the backing services only (postgres, dependency); a whole-estate compose is a different decision", services)
	}
	for _, f := range []string{"../../examples/reference/README.md", "../../docs/acceptance/reference-journeys.md"} {
		doc, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		text := strings.Join(strings.Fields(string(doc)), " ")
		for _, must := range []string{"backing services only", "host processes"} {
			if !strings.Contains(text, must) {
				t.Errorf("%s does not state %q", f, must)
			}
		}
	}
}
