// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// goArchive writes a tar.gz of files under the "go/" prefix and returns its path and sha256.
func goArchive(t *testing.T, files map[string]string) (string, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "go.tar.gz")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := gzip.NewWriter(f)
	tw := tar.NewWriter(zw)
	if err = tw.WriteHeader(&tar.Header{Name: "go/", Typeflag: tar.TypeDir, Mode: 0o755}); err != nil {
		t.Fatal(err)
	}
	for name, content := range files {
		if err = tw.WriteHeader(&tar.Header{Name: "go/" + name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(content))}); err != nil {
			t.Fatal(err)
		}
		if _, err = tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if tw.Close() != nil || zw.Close() != nil || f.Close() != nil {
		t.Fatal("archive write")
	}
	sum, err := sha256File(path)
	if err != nil {
		t.Fatal(err)
	}
	return path, sum
}

func TestCompilerTreeMustBeExactlyThePinnedArchive(t *testing.T) {
	files := map[string]string{"bin/go": "compiler", "src/fmt/print.go": "package fmt", "pkg/tool/linux_amd64/compile": "compile"}
	archive, sum := goArchive(t, files)
	install := func() string {
		root := t.TempDir()
		for name, content := range files {
			write(t, filepath.Join(root, filepath.FromSlash(name)), content)
		}
		return root
	}

	root := install()
	write(t, filepath.Join(root, "pkg", "extra-cache-file"), "unrelated")
	if n, err := verifyArchiveTree(archive, sum, root); err != nil || n != len(files) {
		t.Fatalf("the pinned tree was refused: %d %v", n, err)
	}
	if _, err := verifyArchiveTree(archive, strings.Repeat("0", 64), root); err == nil || !strings.Contains(err.Error(), "pin") {
		t.Fatalf("an archive that does not match the pin was accepted: %v", err)
	}
	for name := range files {
		tampered := install()
		write(t, filepath.Join(tampered, filepath.FromSlash(name)), files[name]+" ")
		if _, err := verifyArchiveTree(archive, sum, tampered); err == nil {
			t.Fatalf("a modified %s was accepted", name)
		}
		missing := install()
		if err := os.Remove(filepath.Join(missing, filepath.FromSlash(name))); err != nil {
			t.Fatal(err)
		}
		if _, err := verifyArchiveTree(archive, sum, missing); err == nil {
			t.Fatalf("a missing %s was accepted", name)
		}
	}
}

func TestArchiveMembersOutsideTheGoPrefixAreRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evil.tar.gz")
	f, _ := os.Create(path)
	zw := gzip.NewWriter(f)
	tw := tar.NewWriter(zw)
	_ = tw.WriteHeader(&tar.Header{Name: "../escape", Typeflag: tar.TypeReg, Mode: 0o644, Size: 1})
	_, _ = tw.Write([]byte("x"))
	_ = tw.Close()
	_ = zw.Close()
	_ = f.Close()
	sum, _ := sha256File(path)
	if _, err := verifyArchiveTree(path, sum, t.TempDir()); err == nil {
		t.Fatal("a member outside go/ was accepted")
	}
}

func TestPythonLocksMustHashEveryRequirement(t *testing.T) {
	ok := "# header\ncffi==2.1.1 \\\n    --hash=sha256:aa \\\n    --hash=sha256:bb\n    # via x\nidna==3.0 \\\n    --hash=sha256:cc\n"
	if !pythonLockHashed([]byte(ok)) {
		t.Fatal("a fully hashed lock was refused")
	}
	for name, lock := range map[string]string{
		"a requirement without a hash":  "cffi==2.1.1 \\\n    --hash=sha256:aa\nidna==3.0\n",
		"a hash with the wrong digest":  "cffi==2.1.1 \\\n    --hash=md5:aa\n",
		"an empty lock":                 "# nothing\n",
		"a range instead of a pin":      "cffi>=2\n",
		"a requirement at end of file ": "cffi==2.1.1 \\",
	} {
		if pythonLockHashed([]byte(lock)) {
			t.Fatalf("%s was accepted", name)
		}
	}
}

func TestPinsNeedAnArchiveHash(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "build", "toolchains.json"), `{"go":{"version":"1.27.3","linux_amd64":{"url":"u","sha256":"short"}}}`)
	if _, err := loadPins(root); err == nil {
		t.Fatal("a pin without a full sha256 was accepted")
	}
	write(t, filepath.Join(root, "build", "toolchains.json"), `{"go":{"version":"1.27.3","linux_amd64":{"url":"u","sha256":"`+strings.Repeat("a", 64)+`"}}}`)
	if p, err := loadPins(root); err != nil || p.Go.Version != "1.27.3" {
		t.Fatalf("%+v %v", p, err)
	}
}

func sourceTree(t *testing.T) string {
	root := t.TempDir()
	write(t, filepath.Join(root, "go.mod"), "module x\n")
	write(t, filepath.Join(root, "go.sum"), "")
	write(t, filepath.Join(root, "cmd", "soundpost", "main.go"), "package main")
	write(t, filepath.Join(root, "internal", "a", "a.go"), "package a")
	write(t, filepath.Join(root, "profiles", "query", "p.json"), "{}")
	return root
}

// The build identity must move with anything that changes the binary and stand still for
// what does not: tests and the generated UI copy are not inputs of the binary's identity
// (the UI has its own digest).
func TestBuildIdentityTracksSourcesNotTestsOrStagedUI(t *testing.T) {
	root := sourceTree(t)
	base, err := sourceDigest(root)
	if err != nil {
		t.Fatal(err)
	}
	same := func(name string, mutate func()) {
		mutate()
		if got, _ := sourceDigest(root); got != base {
			t.Fatalf("%s changed the build identity", name)
		}
	}
	differs := func(name string, mutate func()) {
		mutate()
		if got, _ := sourceDigest(root); got == base {
			t.Fatalf("%s did not change the build identity", name)
		}
	}
	same("a test file", func() { write(t, filepath.Join(root, "internal", "a", "a_test.go"), "package a") })
	same("the staged UI", func() { write(t, filepath.Join(root, "cmd", "soundpost", "webdist", "index.html"), "<html>") })
	differs("a source file", func() { write(t, filepath.Join(root, "internal", "a", "a.go"), "package a // changed") })
	base, _ = sourceDigest(root)
	differs("an embedded profile", func() { write(t, filepath.Join(root, "profiles", "query", "p.json"), `{"a":1}`) })
	base, _ = sourceDigest(root)
	differs("go.sum", func() { write(t, filepath.Join(root, "go.sum"), "x v1 h1:abc\n") })
	base, _ = sourceDigest(root)
	differs("a new package", func() { write(t, filepath.Join(root, "cmd", "soundpost", "extra.go"), "package main") })
}

func TestStageUIRequiresABuiltBundleAndDigestsItsContent(t *testing.T) {
	root := sourceTree(t)
	dist := filepath.Join(t.TempDir(), "dist")
	write(t, filepath.Join(dist, "index.html"), "<html>not built</html>")
	if _, _, err := stageUI(root, dist); err == nil {
		t.Fatal("a page without the application root was accepted as a built UI")
	}
	write(t, filepath.Join(dist, "index.html"), `<div id="root"></div><script src="/assets/a.js"></script>`)
	write(t, filepath.Join(dist, "assets", "a.js"), "console.log(1)")
	first, files, err := stageUI(root, dist)
	if err != nil || files != 2 {
		t.Fatalf("%d %v", files, err)
	}
	staged := filepath.Join(root, "cmd", "soundpost", "webdist")
	for _, name := range []string{"index.html", filepath.Join("assets", "a.js"), ".gitignore"} {
		if _, err = os.Stat(filepath.Join(staged, name)); err != nil {
			t.Fatalf("%s was not staged: %v", name, err)
		}
	}
	write(t, filepath.Join(dist, "assets", "a.js"), "console.log(2)")
	second, _, err := stageUI(root, dist)
	if err != nil || second == first {
		t.Fatalf("the bundle digest ignores file content: %v", err)
	}
}

func TestImageContextOnlyTakesTheBinaryTheReleaseListed(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "deploy", "Dockerfile"), "FROM scratch\n")
	release := t.TempDir()
	write(t, filepath.Join(release, "linux-amd64", "soundpost"), "binary")
	sum := sha256.Sum256([]byte("binary"))
	listed := hex.EncodeToString(sum[:]) + "  linux-amd64/soundpost\n"

	write(t, filepath.Join(release, "SHA256SUMS"), strings.Repeat("0", 64)+"  linux-amd64/soundpost\n")
	if err := runImageContext([]string{"--release", release, "--out", filepath.Join(t.TempDir(), "ctx"), "--root", root}); err == nil {
		t.Fatal("a binary that SHA256SUMS does not list was packaged")
	}
	write(t, filepath.Join(release, "SHA256SUMS"), listed)
	out := filepath.Join(t.TempDir(), "ctx")
	if err := runImageContext([]string{"--release", release, "--out", out, "--root", root}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"soundpost", "Dockerfile", "data"} {
		if _, err := os.Stat(filepath.Join(out, name)); err != nil {
			t.Fatalf("context lacks %s: %v", name, err)
		}
	}
	// The binary is tampered with after the release was written.
	write(t, filepath.Join(release, "linux-amd64", "soundpost"), "tampered")
	if err := runImageContext([]string{"--release", release, "--out", filepath.Join(t.TempDir(), "ctx2"), "--root", root}); err == nil {
		t.Fatal("a tampered binary was packaged")
	}
}

func TestStaticELFCheckRefusesNonELF(t *testing.T) {
	path := filepath.Join(t.TempDir(), "script")
	write(t, path, "#!/bin/sh\n")
	if static, err := isStaticELF(path); err == nil && static {
		t.Fatal("a shell script was reported as a static ELF")
	}
}

// The three operator-facing refusals of a missing compiler, a missing archive and an offline
// module cache must each name what to do, so they are triggered through verifyInputs itself.
func TestVerifyInputsMissingToolchainMessages(t *testing.T) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("verifyInputs only runs on linux/amd64")
	}
	files := map[string]string{"bin/go": "compiler"}
	archive, sum := goArchive(t, files)
	root := t.TempDir()
	write(t, filepath.Join(root, "build", "toolchains.json"), `{"go":{"version":"1.27.3","linux_amd64":{"url":"u","sha256":"`+sum+`"}}}`)
	write(t, filepath.Join(root, "go.mod"), "module x\n")
	write(t, filepath.Join(root, "go.sum"), "")

	t.Setenv("SOUNDPOST_GO", filepath.Join(root, "no-such-go"))
	if _, err := verifyInputs(root, archive); err == nil || !strings.Contains(err.Error(), "pinned Go toolchain missing") || !strings.Contains(err.Error(), "SOUNDPOST_GO") || !strings.Contains(err.Error(), "install-single.md") {
		t.Fatalf("missing compiler message: %v", err)
	}

	goroot := filepath.Join(root, "goroot")
	write(t, filepath.Join(goroot, "bin", "go"), "compiler")
	fake := filepath.Join(root, "fake-go")
	script := "#!/bin/sh\ncase \"$1\" in\nenv) echo '" + goroot + "';;\nversion) echo 'go version go1.27.3 linux/amd64';;\nmod) echo 'go: example.com/m@v1.0.0: module lookup disabled by GOPROXY=off'; exit 1;;\nesac\n"
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOUNDPOST_GO", fake)
	if _, err := verifyInputs(root, filepath.Join(root, "no-such-archive.tar.gz")); err == nil || !strings.Contains(err.Error(), "pinned Go archive missing") || !strings.Contains(err.Error(), "--archive") {
		t.Fatalf("missing archive message: %v", err)
	}
	if _, err := verifyInputs(root, archive); err == nil || !strings.Contains(err.Error(), "go mod verify failed") || !strings.Contains(err.Error(), "GOPROXY=off") || !strings.Contains(err.Error(), "go mod download") {
		t.Fatalf("offline module cache message: %v", err)
	}
}
