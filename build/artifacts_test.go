// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// artifactFixture is a tiny repository root plus a release directory whose binary SHA256SUMS lists.
func artifactFixture(t *testing.T) (root, release string) {
	t.Helper()
	root, release = t.TempDir(), t.TempDir()
	write := func(base, rel, body string) {
		p := filepath.Join(base, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(root, "LICENSE", "Apache License\n")
	write(root, "sdk/python/pyproject.toml", "[project]\nname = \"soundpost\"\nversion = \"0.1.0rc1\"\nrequires-python = \">=3.12\"\nlicense = \"Apache-2.0\"\nauthors = [{name = \"Aryn Yklas\"}]\ndependencies = [\"cryptography>=41\"]\n")
	write(root, "sdk/python/README.md", "# soundpost\n")
	write(root, "sdk/python/src/soundpost/__init__.py", "VERSION = 1\n")
	write(root, "sdk/python/src/soundpost/client.py", "def f():\n    return 1\n")
	write(root, "sdk/python/src/soundpost/__pycache__/client.cpython-313.pyc", "bytecode")
	write(root, "sdk/python/src/soundpost/stray.pyc", "bytecode")
	for _, ws := range npmWorkspaces {
		deps := ""
		if ws != "core" {
			deps = `, "dependencies": {"@soundpost/core": "workspace:*"}`
		}
		write(root, "packages/"+ws+"/package.json", `{"name": "@soundpost/`+ws+`", "version": "0.1.0"`+deps+"}\n")
		write(root, "packages/"+ws+"/README.md", "readme "+ws+"\n")
		write(root, "packages/"+ws+"/CHANGELOG.md", "changes\n")
		write(root, "packages/"+ws+"/src/index.ts", "export const x = 1;\n")
		write(root, "packages/"+ws+"/test/skip.test.ts", "not packed\n")
	}
	bin := "\x7fELF static binary stand-in\n"
	sum := sha256.Sum256([]byte(bin))
	write(release, "linux-amd64/soundpost", bin)
	helper := "\x7fELF perf helper stand-in\n"
	helperSum := sha256.Sum256([]byte(helper))
	write(release, "linux-amd64/soundpost-perf-acquire", helper)
	write(release, "SHA256SUMS", hex.EncodeToString(sum[:])+"  linux-amd64/soundpost\n"+hex.EncodeToString(helperSum[:])+"  linux-amd64/soundpost-perf-acquire\n")
	write(release, "release.json", `{"version": "1.2.3"}`)
	return root, release
}

func artifactDigests(t *testing.T, subjects []ArtifactSubject) map[string]string {
	t.Helper()
	m := map[string]string{}
	for _, s := range subjects {
		m[s.Path] = s.SHA256
	}
	return m
}

// touchAll gives every file of a tree a different modification time: a build that depends on mtimes shows it.
func touchAll(t *testing.T, root string, at time.Time) {
	t.Helper()
	filepath.Walk(root, func(p string, _ os.FileInfo, err error) error {
		if err == nil {
			os.Chtimes(p, at, at)
		}
		return nil
	})
}

func TestArtifactsAreByteIdenticalAcrossBuildsDespiteMtimesAndOutputDirs(t *testing.T) {
	root, release := artifactFixture(t)
	a, err := buildArtifacts(root, release, t.TempDir(), "amd64")
	if err != nil {
		t.Fatal(err)
	}
	touchAll(t, root, time.Date(2031, 5, 6, 7, 8, 9, 0, time.UTC))
	touchAll(t, release, time.Date(2002, 1, 2, 3, 4, 5, 0, time.UTC))
	b, err := buildArtifacts(root, release, t.TempDir(), "amd64")
	if err != nil {
		t.Fatal(err)
	}
	da, db := artifactDigests(t, a), artifactDigests(t, b)
	if len(da) != 1+len(npmWorkspaces)+2 {
		t.Fatalf("want a wheel, %d npm packages and two images (server, perf helper), got %v", len(npmWorkspaces), da)
	}
	for p, sum := range da {
		if db[p] != sum {
			t.Errorf("%s differs between two builds: %s vs %s", p, sum, db[p])
		}
	}
}

func TestArtifactDigestsFollowTheirInputs(t *testing.T) {
	root, release := artifactFixture(t)
	before, _ := buildArtifacts(root, release, t.TempDir(), "amd64")
	if err := os.WriteFile(filepath.Join(root, "sdk/python/src/soundpost/client.py"), []byte("def f():\n    return 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "packages/node/src/index.ts"), []byte("export const x = 2;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	after, _ := buildArtifacts(root, release, t.TempDir(), "amd64")
	db, da := artifactDigests(t, before), artifactDigests(t, after)
	changed := map[string]bool{}
	for p := range db {
		if db[p] != da[p] {
			changed[p] = true
		}
	}
	if !changed["python/soundpost-0.1.0rc1-py3-none-any.whl"] || !changed["npm/soundpost-node-0.1.0.tgz"] || len(changed) != 2 {
		t.Fatalf("exactly the wheel and the node package must change, got %v", changed)
	}
}

func TestWheelRecordCoversEveryFileAndHoldsNoHostData(t *testing.T) {
	root, release := artifactFixture(t)
	dir := t.TempDir()
	if _, err := buildArtifacts(root, release, dir, "amd64"); err != nil {
		t.Fatal(err)
	}
	zr, err := zip.OpenReader(filepath.Join(dir, "python", "soundpost-0.1.0rc1-py3-none-any.whl"))
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	hashes, names := map[string]string{}, []string{}
	var record string
	for _, f := range zr.File {
		if !f.Modified.UTC().Equal(zipEpoch) {
			t.Errorf("%s modified %v, want the zip epoch", f.Name, f.Modified)
		}
		if strings.Contains(f.Name, "__pycache__") || strings.HasSuffix(f.Name, ".pyc") {
			t.Errorf("bytecode packed: %s", f.Name)
		}
		rc, _ := f.Open()
		b, _ := io.ReadAll(rc)
		rc.Close()
		names = append(names, f.Name)
		if strings.HasSuffix(f.Name, ".dist-info/RECORD") {
			record = string(b)
			continue
		}
		s := sha256.Sum256(b)
		hashes[f.Name] = "sha256=" + base64.RawURLEncoding.EncodeToString(s[:]) + "," + itoa(len(b))
	}
	for i := 1; i < len(names); i++ {
		if names[i-1] >= names[i] {
			t.Fatalf("entries are not sorted: %v", names)
		}
	}
	seen := 0
	for _, line := range strings.Split(strings.TrimSpace(record), "\n") {
		parts := strings.SplitN(line, ",", 2)
		if strings.HasSuffix(parts[0], "RECORD") {
			continue
		}
		seen++
		if hashes[parts[0]] != parts[1] {
			t.Errorf("RECORD line %q does not match the file (%s)", line, hashes[parts[0]])
		}
	}
	if seen != len(hashes) {
		t.Fatalf("RECORD lists %d files, the wheel has %d", seen, len(hashes))
	}
	if !strings.Contains(record, "soundpost-0.1.0rc1.dist-info/METADATA,") {
		t.Fatal("METADATA is not in RECORD")
	}
}

func TestWheelMetadataAndWheelFilesCarryTheProjectFields(t *testing.T) {
	root, release := artifactFixture(t)
	dir := t.TempDir()
	if _, err := buildArtifacts(root, release, dir, "amd64"); err != nil {
		t.Fatal(err)
	}
	zr, err := zip.OpenReader(filepath.Join(dir, "python", "soundpost-0.1.0rc1-py3-none-any.whl"))
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	read := map[string]string{}
	for _, f := range zr.File {
		rc, _ := f.Open()
		b, _ := io.ReadAll(rc)
		rc.Close()
		read[f.Name] = string(b)
	}
	meta := read["soundpost-0.1.0rc1.dist-info/METADATA"]
	for _, want := range []string{"Metadata-Version: 2.4\n", "Name: soundpost\n", "Version: 0.1.0rc1\n", "Requires-Python: >=3.12\n", "Requires-Dist: cryptography>=41\n", "License-Expression: Apache-2.0\n", "License-File: LICENSE\n", "\n\n# soundpost\n"} {
		if !strings.Contains(meta, want) {
			t.Errorf("METADATA lacks %q:\n%s", want, meta)
		}
	}
	wheel := read["soundpost-0.1.0rc1.dist-info/WHEEL"]
	for _, want := range []string{"Wheel-Version: 1.0\n", "Root-Is-Purelib: true\n", "Tag: py3-none-any\n"} {
		if !strings.Contains(wheel, want) {
			t.Errorf("WHEEL lacks %q", want)
		}
	}
}

// Every packages/<dir> with a package.json is packed: a new workspace package must not be forgotten.
func TestEveryWorkspacePackageIsPacked(t *testing.T) {
	entries, err := os.ReadDir(filepath.Join("..", "packages"))
	if err != nil {
		t.Fatal(err)
	}
	packed := map[string]bool{}
	for _, w := range npmWorkspaces {
		packed[w] = true
	}
	for _, e := range entries {
		if _, err := os.Stat(filepath.Join("..", "packages", e.Name(), "package.json")); err == nil && !packed[e.Name()] {
			t.Errorf("packages/%s has a package.json but is not in npmWorkspaces", e.Name())
		}
	}
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

func TestNpmPackageHasFixedHeadersAndNoWorkspaceReferences(t *testing.T) {
	root, release := artifactFixture(t)
	dir := t.TempDir()
	if _, err := buildArtifacts(root, release, dir, "amd64"); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "npm", "soundpost-node-0.1.0.tgz"))
	gz, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if !gz.ModTime.IsZero() || gz.Name != "" {
		t.Errorf("gzip header carries host data: %v %q", gz.ModTime, gz.Name)
	}
	tr := tar.NewReader(gz)
	var names []string
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, h.Name)
		if h.ModTime.Unix() != 0 || h.Uid != 0 || h.Gid != 0 || h.Uname != "" || h.Gname != "" {
			t.Errorf("%s has host data: %+v", h.Name, h)
		}
		if h.Name == "package/package.json" {
			b, _ := io.ReadAll(tr)
			if strings.Contains(string(b), "workspace:") || !strings.Contains(string(b), `"@soundpost/core": "0.1.0"`) {
				t.Errorf("package.json workspace reference not resolved: %s", b)
			}
		}
	}
	want := []string{"package/CHANGELOG.md", "package/LICENSE", "package/README.md", "package/package.json", "package/src/index.ts"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("tarball members %v, want %v (tests are not packed)", names, want)
	}
}

func TestOCIImageLayerManifestAndConfigAreSelfConsistentAndMatchTheDockerfile(t *testing.T) {
	root, release := artifactFixture(t)
	dir := t.TempDir()
	subjects, err := buildArtifacts(root, release, dir, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	var imageSubject ArtifactSubject
	for _, s := range subjects {
		if s.Kind == "oci_image" {
			imageSubject = s
		}
	}
	raw, _ := os.ReadFile(filepath.Join(dir, filepath.FromSlash(imageSubject.Path)))
	files := map[string][]byte{}
	tr := tar.NewReader(bytes.NewReader(raw))
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if h.ModTime.Unix() != 0 {
			t.Errorf("%s has a modification time", h.Name)
		}
		b, _ := io.ReadAll(tr)
		files[h.Name] = b
	}
	var idx ociIndex
	if err := json.Unmarshal(files["index.json"], &idx); err != nil || len(idx.Manifests) != 1 {
		t.Fatalf("index: %v %s", err, files["index.json"])
	}
	blob := func(d string) []byte { return files["blobs/sha256/"+strings.TrimPrefix(d, "sha256:")] }
	manRaw := blob(idx.Manifests[0].Digest)
	if blobDigest(manRaw) != idx.Manifests[0].Digest || idx.Manifests[0].Digest != imageSubject.Detail {
		t.Fatal("manifest digest does not match its blob or the recorded detail")
	}
	var man ociManifest
	if err := json.Unmarshal(manRaw, &man); err != nil {
		t.Fatal(err)
	}
	if blobDigest(blob(man.Config.Digest)) != man.Config.Digest || blobDigest(blob(man.Layers[0].Digest)) != man.Layers[0].Digest {
		t.Fatal("a descriptor digest does not match its blob")
	}
	var cfg ociConfig
	if err := json.Unmarshal(blob(man.Config.Digest), &cfg); err != nil {
		t.Fatal(err)
	}
	lz, err := gzip.NewReader(bytes.NewReader(blob(man.Layers[0].Digest)))
	if err != nil {
		t.Fatal(err)
	}
	layer, _ := io.ReadAll(lz)
	if blobDigest(layer) != cfg.RootFS.DiffIDs[0] {
		t.Fatal("diff_id is not the digest of the uncompressed layer")
	}
	got := map[string]*tar.Header{}
	lt := tar.NewReader(bytes.NewReader(layer))
	for {
		h, err := lt.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		got[h.Name] = h
	}
	if h := got["soundpost"]; h == nil || h.Mode != 0o555 || h.Uid != 65532 {
		t.Fatalf("binary entry wrong: %+v", h)
	}
	if h := got["var/lib/soundpost/"]; h == nil || h.Mode != 0o700 || h.Uid != 65532 {
		t.Fatalf("data directory entry wrong: %+v", h)
	}
	// The config mirrors deploy/Dockerfile instruction by instruction.
	docker, err := os.ReadFile(filepath.Join("..", "deploy", "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(docker)
	jsonList := func(instr string) []string {
		m := regexp.MustCompile(`(?m)^` + instr + ` (\[.*\])$`).FindStringSubmatch(text)
		if m == nil {
			t.Fatalf("Dockerfile has no %s", instr)
		}
		var l []string
		if err := json.Unmarshal([]byte(m[1]), &l); err != nil {
			t.Fatal(err)
		}
		return l
	}
	single := func(instr string) string {
		m := regexp.MustCompile(`(?m)^` + instr + ` (\S+)$`).FindStringSubmatch(text)
		if m == nil {
			t.Fatalf("Dockerfile has no %s", instr)
		}
		return m[1]
	}
	c := cfg.Config
	if strings.Join(c.Entrypoint, "\x00") != strings.Join(jsonList("ENTRYPOINT"), "\x00") || strings.Join(c.Cmd, "\x00") != strings.Join(jsonList("CMD"), "\x00") {
		t.Errorf("entrypoint/cmd differ from the Dockerfile: %v %v", c.Entrypoint, c.Cmd)
	}
	if c.User != single("USER") || c.WorkingDir != single("WORKDIR") || c.StopSignal != single("STOPSIGNAL") {
		t.Errorf("user/workdir/stopsignal differ: %q %q %q", c.User, c.WorkingDir, c.StopSignal)
	}
	if _, ok := c.ExposedPorts[single("EXPOSE")+"/tcp"]; !ok {
		t.Errorf("exposed ports %v", c.ExposedPorts)
	}
	if v := jsonList("VOLUME"); len(v) != 1 {
		t.Fatalf("Dockerfile VOLUME %v", v)
	} else if _, ok := c.Volumes[v[0]]; !ok {
		t.Errorf("volumes %v", c.Volumes)
	}
	if c.Labels["org.opencontainers.image.version"] != "1.2.3" || len(c.Labels["org.soundpost.binary.sha256"]) != 64 {
		t.Errorf("labels %v", c.Labels)
	}
	if cfg.Created != dockerfileEpoch {
		t.Errorf("created %q", cfg.Created)
	}
}

func TestImageRefusesABinarySHA256SUMSDoesNotList(t *testing.T) {
	root, release := artifactFixture(t)
	if err := os.WriteFile(filepath.Join(release, "linux-amd64", "soundpost"), []byte("tampered"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := buildArtifacts(root, release, t.TempDir(), "amd64"); err == nil || !strings.Contains(err.Error(), "SHA256SUMS") {
		t.Fatalf("want a SHA256SUMS refusal, got %v", err)
	}
}

func TestPackingRefusesAWorkspaceReferenceToAnUnpackedPackage(t *testing.T) {
	root, release := artifactFixture(t)
	p := filepath.Join(root, "packages", "node", "package.json")
	if err := os.WriteFile(p, []byte(`{"name": "@soundpost/node", "version": "0.1.0", "dependencies": {"@soundpost/ghost": "workspace:*"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := buildArtifacts(root, release, t.TempDir(), "amd64"); err == nil || !strings.Contains(err.Error(), "ghost") {
		t.Fatalf("want a refusal naming the unpacked package, got %v", err)
	}
}

func TestRunArtifactsReproduceWritesManifestAndSums(t *testing.T) {
	root, release := artifactFixture(t)
	out := t.TempDir()
	sbom := t.TempDir()
	for _, n := range []string{"soundpost.cdx.json", "soundpost.spdx.json"} {
		os.WriteFile(filepath.Join(sbom, n), []byte("{}"), 0o644)
	}
	var buf bytes.Buffer
	if err := runArtifacts([]string{"--root", root, "--release", release, "--out", out, "--sbom", sbom, "--reproduce", "--commit", "abc"}, &buf); err != nil {
		t.Fatal(err)
	}
	var m ArtifactsManifest
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	if !m.Reproducibility.Checked || !m.Reproducibility.Equal || m.Commit != "abc" || len(m.SBOM) != 2 || m.ReleaseJSONSHA256 == "" {
		t.Fatalf("manifest %+v", m)
	}
	sums, _ := os.ReadFile(filepath.Join(out, "SHA256SUMS.artifacts"))
	for _, s := range m.Subjects {
		if !strings.Contains(string(sums), s.SHA256+"  "+s.Path+"\n") {
			t.Errorf("SHA256SUMS.artifacts lacks %s", s.Path)
		}
		if got, _ := sha256File(filepath.Join(out, filepath.FromSlash(s.Path))); got != s.SHA256 {
			t.Errorf("%s digest on disk %s, recorded %s", s.Path, got, s.SHA256)
		}
	}
	if err := runArtifacts([]string{"--root", root, "--release", release, "--out", out, "--sbom", filepath.Join(out, "nonexistent")}, &buf); err == nil {
		t.Fatal("a missing SBOM must be refused")
	}
}

// ociParts unpacks an OCI layout tar made by buildArtifacts: its config and its single layer's entries.
func ociParts(t *testing.T, raw []byte) (ociConfig, map[string]*tar.Header, map[string][]byte) {
	t.Helper()
	files := map[string][]byte{}
	tr := tar.NewReader(bytes.NewReader(raw))
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(tr)
		files[h.Name] = b
	}
	var idx ociIndex
	if err := json.Unmarshal(files["index.json"], &idx); err != nil || len(idx.Manifests) != 1 {
		t.Fatalf("index: %v", err)
	}
	blob := func(d string) []byte { return files["blobs/sha256/"+strings.TrimPrefix(d, "sha256:")] }
	var man ociManifest
	if err := json.Unmarshal(blob(idx.Manifests[0].Digest), &man); err != nil || len(man.Layers) != 1 {
		t.Fatalf("manifest: %v", err)
	}
	var cfg ociConfig
	if err := json.Unmarshal(blob(man.Config.Digest), &cfg); err != nil {
		t.Fatal(err)
	}
	lz, err := gzip.NewReader(bytes.NewReader(blob(man.Layers[0].Digest)))
	if err != nil {
		t.Fatal(err)
	}
	layer, _ := io.ReadAll(lz)
	if blobDigest(layer) != cfg.RootFS.DiffIDs[0] {
		t.Fatal("diff_id is not the digest of the uncompressed layer")
	}
	hdrs, bodies := map[string]*tar.Header{}, map[string][]byte{}
	lt := tar.NewReader(bytes.NewReader(layer))
	for {
		h, err := lt.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		hdrs[h.Name] = h
		bodies[h.Name], _ = io.ReadAll(lt)
	}
	return cfg, hdrs, bodies
}

// The native acquisition helper (cmd/soundpost-perf-acquire) is shipped as its own image: the
// server image never carries it, and the helper image carries nothing but the helper.
func TestPerfHelperImageHoldsOnlyTheReleaseHelperAndMirrorsItsDockerfile(t *testing.T) {
	root, release := artifactFixture(t)
	dir := t.TempDir()
	subjects, err := buildArtifacts(root, release, dir, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	var helper, server *ArtifactSubject
	for i, s := range subjects {
		switch s.Kind {
		case "oci_image_perf_helper":
			helper = &subjects[i]
		case "oci_image":
			server = &subjects[i]
		}
	}
	if helper == nil || helper.Path != "image/soundpost-perf-helper-linux-amd64.oci.tar" || server == nil {
		t.Fatalf("subjects %+v", subjects)
	}
	if helper.SHA256 == server.SHA256 || helper.Detail == server.Detail {
		t.Fatal("the helper image is the server image")
	}
	raw, _ := os.ReadFile(filepath.Join(dir, filepath.FromSlash(helper.Path)))
	cfg, hdrs, bodies := ociParts(t, raw)
	if h := hdrs["soundpost-perf-acquire"]; h == nil || h.Mode != 0o555 || h.Uid != 0 || h.Gid != 0 || h.Typeflag != tar.TypeReg {
		t.Fatalf("helper entry wrong: %+v", h)
	}
	if string(bodies["soundpost-perf-acquire"]) != "\x7fELF perf helper stand-in\n" {
		t.Fatal("the helper image does not hold the release helper binary")
	}
	for name, h := range hdrs {
		if h.Typeflag == tar.TypeReg && name != "soundpost-perf-acquire" {
			t.Errorf("unexpected file %s in the helper image (the server binary must not be in it)", name)
		}
		if h.Uid != 0 || h.Gid != 0 {
			t.Errorf("%s is owned by %d:%d; the helper image has one user, root with only CAP_PERFMON", name, h.Uid, h.Gid)
		}
	}
	// The server image does not carry the helper.
	sraw, _ := os.ReadFile(filepath.Join(dir, filepath.FromSlash(server.Path)))
	if _, shdrs, _ := ociParts(t, sraw); shdrs["soundpost-perf-acquire"] != nil {
		t.Error("the server image carries the perf helper")
	}
	// The config mirrors deploy/Dockerfile.perf-helper.
	docker, err := os.ReadFile(filepath.Join("..", "deploy", "Dockerfile.perf-helper"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(docker)
	one := func(instr string) string {
		m := regexp.MustCompile(`(?m)^` + instr + ` (.+)$`).FindStringSubmatch(text)
		if m == nil {
			t.Fatalf("Dockerfile.perf-helper has no %s", instr)
		}
		return m[1]
	}
	var entry []string
	if err := json.Unmarshal([]byte(one("ENTRYPOINT")), &entry); err != nil {
		t.Fatal(err)
	}
	c := cfg.Config
	if strings.Join(c.Entrypoint, "\x00") != strings.Join(entry, "\x00") || len(c.Cmd) != 0 {
		t.Errorf("entrypoint/cmd %v %v, Dockerfile %v", c.Entrypoint, c.Cmd, entry)
	}
	if c.User != one("USER") || c.StopSignal != one("STOPSIGNAL") || c.User != "0:0" {
		t.Errorf("user/stopsignal %q %q", c.User, c.StopSignal)
	}
	if len(c.ExposedPorts) != 0 || len(c.Volumes) != 0 {
		t.Errorf("the helper listens on a unix socket only: ports %v volumes %v", c.ExposedPorts, c.Volumes)
	}
	if c.Labels["org.opencontainers.image.title"] != "soundpost-perf-helper" || c.Labels["org.opencontainers.image.version"] != "1.2.3" || len(c.Labels["org.soundpost.binary.sha256"]) != 64 {
		t.Errorf("labels %v", c.Labels)
	}
	if !regexp.MustCompile(`(?m)^COPY --chown=0:0 --chmod=0555 soundpost-perf-acquire /soundpost-perf-acquire$`).MatchString(text) || !regexp.MustCompile(`(?m)^FROM scratch$`).MatchString(text) {
		t.Error("Dockerfile.perf-helper must be FROM scratch and copy the read-only helper")
	}
	for _, line := range directives(text) {
		for _, banned := range []string{"ADD ", "RUN ", "curl", "wget", "http://", "https://", "--privileged"} {
			if strings.Contains(line, banned) {
				t.Fatalf("the build must not fetch or execute anything: %q", line)
			}
		}
	}
}

func TestPerfHelperImageRefusesABinarySHA256SUMSDoesNotList(t *testing.T) {
	root, release := artifactFixture(t)
	if err := os.WriteFile(filepath.Join(release, "linux-amd64", "soundpost-perf-acquire"), []byte("tampered"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := buildArtifacts(root, release, t.TempDir(), "amd64"); err == nil || !strings.Contains(err.Error(), "soundpost-perf-acquire") || !strings.Contains(err.Error(), "SHA256SUMS") {
		t.Fatalf("want a SHA256SUMS refusal naming the helper, got %v", err)
	}
}
