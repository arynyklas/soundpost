// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

// Deterministic Python wheel, npm package tarballs and OCI image layout (07.08-W2).
//
//	go run ./build artifacts --release DIST --out DIR [--arch amd64] [--sbom DIR] [--reproduce]
//
// Every artifact is a pure function of the repository files and the verified release binary:
// archive entries are sorted, carry fixed owners, modes and timestamps (the zip epoch 1980-01-01 for
// the wheel, the Unix epoch for tar and OCI), compress with the pinned Go standard library and
// contain no host path, user name or clock reading. --reproduce builds everything a second time into
// a scratch directory and refuses unless every sha256 is equal. The output is artifacts.json (and
// SHA256SUMS.artifacts) next to the artifacts; it records each subject digest together with the
// source commit, the release.json and SBOM digests it was built next to, so the SBOM and provenance
// cover exactly these bytes.

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// npmWorkspaces are the packages that are packed, in a stable order.
var npmWorkspaces = []string{"core", "node", "bun", "browser", "build", "replay-viewer"}

// zipEpoch is the earliest time a zip entry can carry; every wheel entry uses it.
var zipEpoch = time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)

// ArtifactSubject is one produced file.
type ArtifactSubject struct {
	Kind   string `json:"kind"` // python_wheel, npm_package, oci_image
	Name   string `json:"name"`
	Path   string `json:"path"` // slash path relative to the output directory
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
	// Detail is the image's manifest digest (oci_image) or the package's declared version.
	Detail string `json:"detail,omitempty"`
}

// ArtifactsManifest is artifacts.json: no timestamps, sorted subjects.
type ArtifactsManifest struct {
	Schema            string            `json:"schema"`
	Commit            string            `json:"commit"`
	Subjects          []ArtifactSubject `json:"subjects"`
	ReleaseJSONSHA256 string            `json:"release_json_sha256,omitempty"`
	SBOM              map[string]string `json:"sbom_sha256,omitempty"`
	Reproducibility   Reproducibility   `json:"reproducibility"`
}

const artifactsSchema = "soundpost.artifacts.v1"

func runArtifacts(args []string, out io.Writer) error {
	f := flag.NewFlagSet("artifacts", flag.ContinueOnError)
	root := f.String("root", ".", "repository root")
	release := f.String("release", "", "release directory made by `build release` (the image binary is taken from it)")
	outDir := f.String("out", "", "output directory (created)")
	arch := f.String("arch", "amd64", "image architecture")
	sbom := f.String("sbom", "", "directory made by `build sbom` whose digests are recorded")
	commit := f.String("commit", "unknown", "source commit recorded in the manifest")
	reproduce := f.Bool("reproduce", false, "build everything a second time and compare sha256")
	if err := f.Parse(args); err != nil {
		return err
	}
	if *release == "" || *outDir == "" {
		return errors.New("--release and --out are required")
	}
	absRoot, err := filepath.Abs(*root)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(*outDir, 0o755); err != nil {
		return err
	}
	first, err := buildArtifacts(absRoot, *release, *outDir, *arch)
	if err != nil {
		return err
	}
	m := ArtifactsManifest{Schema: artifactsSchema, Commit: *commit, Subjects: first}
	if *reproduce {
		scratch, err := os.MkdirTemp("", "soundpost-artifacts-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(scratch)
		again, err := buildArtifacts(absRoot, *release, scratch, *arch)
		if err != nil {
			return err
		}
		m.Reproducibility = Reproducibility{Checked: true, Equal: len(again) == len(first)}
		for i := range again {
			if i < len(first) && (again[i].SHA256 != first[i].SHA256 || again[i].Path != first[i].Path) {
				m.Reproducibility.Equal = false
				m.Reproducibility.Detail += fmt.Sprintf("%s differs (%s vs %s); ", first[i].Path, first[i].SHA256, again[i].SHA256)
			}
		}
	}
	if sum, err := sha256File(filepath.Join(*release, "release.json")); err == nil {
		m.ReleaseJSONSHA256 = sum
	}
	if *sbom != "" {
		m.SBOM = map[string]string{}
		for _, name := range []string{"soundpost.cdx.json", "soundpost.spdx.json"} {
			sum, err := sha256File(filepath.Join(*sbom, name))
			if err != nil {
				return fmt.Errorf("sbom: %w", err)
			}
			m.SBOM[name] = sum
		}
	}
	raw, err := marshalStable(m)
	if err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(*outDir, "artifacts.json"), raw, 0o644); err != nil {
		return err
	}
	var sums bytes.Buffer
	for _, s := range m.Subjects {
		fmt.Fprintf(&sums, "%s  %s\n", s.SHA256, s.Path)
	}
	if err = os.WriteFile(filepath.Join(*outDir, "SHA256SUMS.artifacts"), sums.Bytes(), 0o644); err != nil {
		return err
	}
	if _, err = out.Write(raw); err != nil {
		return err
	}
	if m.Reproducibility.Checked && !m.Reproducibility.Equal {
		return errors.New("the two artifact builds are not byte-identical: " + m.Reproducibility.Detail)
	}
	return nil
}

// buildArtifacts writes the wheel, npm tarballs and the image into dir and returns the sorted subjects.
func buildArtifacts(root, release, dir, arch string) ([]ArtifactSubject, error) {
	var subjects []ArtifactSubject
	add := func(kind, name, rel, detail string, body []byte) error {
		full := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(full, body, 0o644); err != nil {
			return err
		}
		sum := sha256.Sum256(body)
		subjects = append(subjects, ArtifactSubject{Kind: kind, Name: name, Path: rel, SHA256: hex.EncodeToString(sum[:]), Bytes: int64(len(body)), Detail: detail})
		return nil
	}
	wheel, wheelName, version, err := buildWheel(root)
	if err != nil {
		return nil, fmt.Errorf("python wheel: %w", err)
	}
	if err = add("python_wheel", wheelName, "python/"+wheelName, version, wheel); err != nil {
		return nil, err
	}
	versions, err := workspaceVersions(root)
	if err != nil {
		return nil, err
	}
	for _, ws := range npmWorkspaces {
		body, name, ver, err := buildNpmPackage(root, ws, versions)
		if err != nil {
			return nil, fmt.Errorf("npm package %s: %w", ws, err)
		}
		if err = add("npm_package", name, "npm/"+name, ver, body); err != nil {
			return nil, err
		}
	}
	image, digest, err := buildOCIImage(root, release, arch)
	if err != nil {
		return nil, fmt.Errorf("oci image: %w", err)
	}
	if err = add("oci_image", "soundpost-linux-"+arch+".oci.tar", "image/soundpost-linux-"+arch+".oci.tar", digest, image); err != nil {
		return nil, err
	}
	sort.Slice(subjects, func(i, j int) bool { return subjects[i].Path < subjects[j].Path })
	return subjects, nil
}

// ---- Python wheel ----

var (
	pyName    = regexp.MustCompile(`(?m)^name = "([^"]+)"`)
	pyVersion = regexp.MustCompile(`(?m)^version = "([^"]+)"`)
	pyRequire = regexp.MustCompile(`(?m)^requires-python = "([^"]+)"`)
	pyDeps    = regexp.MustCompile(`(?m)^dependencies = \[([^\]]*)\]`)
	pyLicense = regexp.MustCompile(`(?m)^license = "([^"]+)"`)
	pyAuthor  = regexp.MustCompile(`(?m)^authors = \[\{name = "([^"]+)"\}\]`)
)

type fileEntry struct {
	name string // slash path inside the archive
	body []byte
	mode fs.FileMode
}

func readFileLF(p string) ([]byte, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	return bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n")), nil
}

// treeFiles lists the regular files under dir (slash paths relative to dir, sorted), skipping caches and bytecode.
func treeFiles(dir string, skip func(rel string) bool) ([]string, error) {
	var out []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if d.Name() == "__pycache__" || d.Name() == "node_modules" || d.Name() == ".pytest_cache" {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("non-regular file %s", rel)
		}
		if strings.HasSuffix(rel, ".pyc") || (skip != nil && skip(rel)) {
			return nil
		}
		out = append(out, rel)
		return nil
	})
	sort.Strings(out)
	return out, err
}

func normalizeDistName(n string) string {
	return strings.ToLower(regexp.MustCompile(`[-_.]+`).ReplaceAllString(n, "_"))
}

func buildWheel(root string) (body []byte, name, version string, err error) {
	pyproject, err := readFileLF(filepath.Join(root, "sdk", "python", "pyproject.toml"))
	if err != nil {
		return nil, "", "", err
	}
	text := string(pyproject)
	get := func(re *regexp.Regexp) string {
		if m := re.FindStringSubmatch(text); m != nil {
			return m[1]
		}
		return ""
	}
	pkg, version, requires := get(pyName), get(pyVersion), get(pyRequire)
	if pkg == "" || version == "" {
		return nil, "", "", errors.New("pyproject.toml has no project name or version")
	}
	dist := normalizeDistName(pkg)
	info := dist + "-" + version + ".dist-info"
	readme, err := readFileLF(filepath.Join(root, "sdk", "python", "README.md"))
	if err != nil {
		return nil, "", "", err
	}
	licenseText, err := readFileLF(filepath.Join(root, "LICENSE"))
	if err != nil {
		return nil, "", "", err
	}
	var meta strings.Builder
	meta.WriteString("Metadata-Version: 2.4\nName: " + pkg + "\nVersion: " + version + "\n")
	if a := get(pyAuthor); a != "" {
		meta.WriteString("Author: " + a + "\n")
	}
	if l := get(pyLicense); l != "" {
		meta.WriteString("License-Expression: " + l + "\n")
	}
	meta.WriteString("License-File: LICENSE\n")
	if requires != "" {
		meta.WriteString("Requires-Python: " + requires + "\n")
	}
	if m := pyDeps.FindStringSubmatch(text); m != nil {
		for _, d := range regexp.MustCompile(`"([^"]+)"`).FindAllStringSubmatch(m[1], -1) {
			meta.WriteString("Requires-Dist: " + d[1] + "\n")
		}
	}
	meta.WriteString("Description-Content-Type: text/markdown\n\n")
	meta.Write(readme)
	srcDir := filepath.Join(root, "sdk", "python", "src")
	files, err := treeFiles(srcDir, nil)
	if err != nil {
		return nil, "", "", err
	}
	var entries []fileEntry
	for _, rel := range files {
		b, err := os.ReadFile(filepath.Join(srcDir, filepath.FromSlash(rel)))
		if err != nil {
			return nil, "", "", err
		}
		entries = append(entries, fileEntry{name: rel, body: b, mode: 0o644})
	}
	entries = append(entries,
		fileEntry{name: info + "/METADATA", body: []byte(meta.String()), mode: 0o644},
		fileEntry{name: info + "/WHEEL", body: []byte("Wheel-Version: 1.0\nGenerator: soundpost-build\nRoot-Is-Purelib: true\nTag: py3-none-any\n"), mode: 0o644},
		fileEntry{name: info + "/licenses/LICENSE", body: licenseText, mode: 0o644},
	)
	sort.Slice(entries, func(i, j int) bool { return entries[i].name < entries[j].name })
	var record strings.Builder
	for _, e := range entries {
		sum := sha256.Sum256(e.body)
		record.WriteString(fmt.Sprintf("%s,sha256=%s,%d\n", e.name, base64.RawURLEncoding.EncodeToString(sum[:]), len(e.body)))
	}
	record.WriteString(info + "/RECORD,,\n")
	entries = append(entries, fileEntry{name: info + "/RECORD", body: []byte(record.String()), mode: 0o644})
	sort.Slice(entries, func(i, j int) bool { return entries[i].name < entries[j].name })
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	zw.RegisterCompressor(zip.Deflate, func(w io.Writer) (io.WriteCloser, error) { return flate.NewWriter(w, flate.BestCompression) })
	for _, e := range entries {
		h := &zip.FileHeader{Name: e.name, Method: zip.Deflate, Modified: zipEpoch}
		h.SetMode(e.mode)
		h.CreatorVersion = 3<<8 | 20 // unix, zip 2.0: fixed
		w, err := zw.CreateHeader(h)
		if err != nil {
			return nil, "", "", err
		}
		if _, err = w.Write(e.body); err != nil {
			return nil, "", "", err
		}
	}
	if err = zw.Close(); err != nil {
		return nil, "", "", err
	}
	return buf.Bytes(), dist + "-" + version + "-py3-none-any.whl", version, nil
}

// ---- npm packages ----

type pkgJSON struct {
	Name         string            `json:"name"`
	Version      string            `json:"version"`
	Dependencies map[string]string `json:"dependencies"`
	DevDeps      map[string]string `json:"devDependencies"`
}

func workspaceVersions(root string) (map[string]string, error) {
	out := map[string]string{}
	for _, ws := range npmWorkspaces {
		raw, err := os.ReadFile(filepath.Join(root, "packages", ws, "package.json"))
		if err != nil {
			return nil, err
		}
		var p pkgJSON
		if err = json.Unmarshal(raw, &p); err != nil {
			return nil, fmt.Errorf("packages/%s/package.json: %w", ws, err)
		}
		out[p.Name] = p.Version
	}
	return out, nil
}

func buildNpmPackage(root, ws string, versions map[string]string) (body []byte, fileName, version string, err error) {
	dir := filepath.Join(root, "packages", ws)
	raw, err := readFileLF(filepath.Join(dir, "package.json"))
	if err != nil {
		return nil, "", "", err
	}
	var p pkgJSON
	if err = json.Unmarshal(raw, &p); err != nil {
		return nil, "", "", err
	}
	// workspace:* becomes the sibling's version, as `pnpm pack` does; nothing else in package.json changes.
	manifest := string(raw)
	for dep, spec := range p.Dependencies {
		if !strings.HasPrefix(spec, "workspace:") {
			continue
		}
		v, ok := versions[dep]
		if !ok {
			return nil, "", "", fmt.Errorf("dependency %s is a workspace reference to a package that is not packed", dep)
		}
		manifest = strings.Replace(manifest, `"`+dep+`": "`+spec+`"`, `"`+dep+`": "`+v+`"`, 1)
	}
	if strings.Contains(manifest, "workspace:") {
		return nil, "", "", errors.New("a workspace: reference was left in package.json")
	}
	entries := []fileEntry{{name: "package/package.json", body: []byte(manifest), mode: 0o644}}
	for _, name := range []string{"README.md", "CHANGELOG.md"} {
		b, err := readFileLF(filepath.Join(dir, name))
		if err != nil {
			return nil, "", "", err
		}
		entries = append(entries, fileEntry{name: "package/" + name, body: b, mode: 0o644})
	}
	licenseText, err := readFileLF(filepath.Join(root, "LICENSE"))
	if err != nil {
		return nil, "", "", err
	}
	entries = append(entries, fileEntry{name: "package/LICENSE", body: licenseText, mode: 0o644})
	files, err := treeFiles(filepath.Join(dir, "src"), nil)
	if err != nil {
		return nil, "", "", err
	}
	for _, rel := range files {
		b, err := os.ReadFile(filepath.Join(dir, "src", filepath.FromSlash(rel)))
		if err != nil {
			return nil, "", "", err
		}
		entries = append(entries, fileEntry{name: "package/src/" + rel, body: b, mode: 0o644})
	}
	body, err = deterministicTarGz(entries)
	name := strings.NewReplacer("@", "", "/", "-").Replace(p.Name) + "-" + p.Version + ".tgz"
	return body, name, p.Version, err
}

// writeTar writes sorted entries with fixed owner, group, time and mode.
func writeTar(w io.Writer, entries []fileEntry) error {
	sort.Slice(entries, func(i, j int) bool { return entries[i].name < entries[j].name })
	tw := tar.NewWriter(w)
	for _, e := range entries {
		h := &tar.Header{Name: e.name, Size: int64(len(e.body)), Mode: int64(e.mode.Perm()), Typeflag: tar.TypeReg, Format: tar.FormatPAX}
		if e.mode.IsDir() {
			h.Typeflag, h.Size = tar.TypeDir, 0
			if !strings.HasSuffix(h.Name, "/") {
				h.Name += "/"
			}
		}
		if err := tw.WriteHeader(h); err != nil {
			return err
		}
		if _, err := tw.Write(e.body); err != nil {
			return err
		}
	}
	return tw.Close()
}

func deterministicTarGz(entries []fileEntry) ([]byte, error) {
	var buf bytes.Buffer
	gz, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	// The gzip header's ModTime stays the zero time, Name and OS stay unset: nothing of the host leaks.
	if err = writeTar(gz, entries); err != nil {
		return nil, err
	}
	if err = gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ---- OCI image ----

type ociConfigInner struct {
	User         string              `json:"User"`
	ExposedPorts map[string]struct{} `json:"ExposedPorts"`
	Entrypoint   []string            `json:"Entrypoint"`
	Cmd          []string            `json:"Cmd"`
	Volumes      map[string]struct{} `json:"Volumes"`
	WorkingDir   string              `json:"WorkingDir"`
	Labels       map[string]string   `json:"Labels"`
	StopSignal   string              `json:"StopSignal"`
}

type ociHistory struct {
	Created   string `json:"created"`
	CreatedBy string `json:"created_by"`
}

type ociConfig struct {
	Created      string         `json:"created"`
	Architecture string         `json:"architecture"`
	OS           string         `json:"os"`
	Config       ociConfigInner `json:"config"`
	RootFS       struct {
		Type    string   `json:"type"`
		DiffIDs []string `json:"diff_ids"`
	} `json:"rootfs"`
	History []ociHistory `json:"history"`
}

type ociDescriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int    `json:"size"`
}

type ociManifest struct {
	SchemaVersion int             `json:"schemaVersion"`
	MediaType     string          `json:"mediaType"`
	Config        ociDescriptor   `json:"config"`
	Layers        []ociDescriptor `json:"layers"`
}

type ociIndex struct {
	SchemaVersion int             `json:"schemaVersion"`
	MediaType     string          `json:"mediaType"`
	Manifests     []ociDescriptor `json:"manifests"`
}

const (
	dockerfileEpoch = "1970-01-01T00:00:00Z"
	imageUID        = 65532
)

// imageSpec is what deploy/Dockerfile declares; a test compares it with the file.
func imageSpec(version, binarySHA string) ociConfigInner {
	return ociConfigInner{
		User:         "65532:65532",
		ExposedPorts: map[string]struct{}{"8443/tcp": {}},
		Entrypoint:   []string{"/soundpost"},
		Cmd:          []string{"serve", "--mode=single", "--data-dir=/var/lib/soundpost", "--listen=0.0.0.0:8443"},
		Volumes:      map[string]struct{}{"/var/lib/soundpost": {}},
		WorkingDir:   "/var/lib/soundpost",
		Labels: map[string]string{
			"org.opencontainers.image.title":    "soundpost",
			"org.opencontainers.image.licenses": "Apache-2.0",
			"org.opencontainers.image.version":  version,
			"org.soundpost.binary.sha256":       binarySHA,
		},
		StopSignal: "SIGTERM",
	}
}

func blobDigest(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// buildOCIImage returns an OCI image-layout tar of deploy/Dockerfile's single-layer image and the
// image manifest digest. The binary must be the one release/SHA256SUMS lists.
func buildOCIImage(root, release, arch string) ([]byte, string, error) {
	binary := filepath.Join(release, "linux-"+arch, "soundpost")
	sum, err := sha256File(binary)
	if err != nil {
		return nil, "", err
	}
	sums, err := os.ReadFile(filepath.Join(release, "SHA256SUMS"))
	if err != nil {
		return nil, "", err
	}
	if !strings.Contains(string(sums), sum+"  linux-"+arch+"/soundpost\n") {
		return nil, "", errors.New("the binary is not the one SHA256SUMS lists")
	}
	raw, err := os.ReadFile(binary)
	if err != nil {
		return nil, "", err
	}
	version := "unset"
	if rel, err := os.ReadFile(filepath.Join(release, "release.json")); err == nil {
		var m struct {
			Version string `json:"version"`
		}
		if json.Unmarshal(rel, &m) == nil && m.Version != "" {
			version = m.Version
		}
	}
	// Layer: soundpost (0555) and the data directory (0700), owned by the unprivileged user like the COPY --chown lines.
	var layer bytes.Buffer
	tw := tar.NewWriter(&layer)
	for _, e := range []struct {
		name string
		dir  bool
		mode int64
		body []byte
	}{
		{"soundpost", false, 0o555, raw},
		{"var/", true, 0o755, nil},
		{"var/lib/", true, 0o755, nil},
		{"var/lib/soundpost/", true, 0o700, nil},
	} {
		h := &tar.Header{Name: e.name, Mode: e.mode, Uid: imageUID, Gid: imageUID, Size: int64(len(e.body)), Typeflag: tar.TypeReg, Format: tar.FormatPAX}
		if e.dir {
			h.Typeflag = tar.TypeDir
			if e.name != "var/lib/soundpost/" {
				h.Uid, h.Gid = 0, 0
			}
		}
		if err := tw.WriteHeader(h); err != nil {
			return nil, "", err
		}
		if _, err := tw.Write(e.body); err != nil {
			return nil, "", err
		}
	}
	if err = tw.Close(); err != nil {
		return nil, "", err
	}
	diffID := blobDigest(layer.Bytes())
	var gzLayer bytes.Buffer
	gz, _ := gzip.NewWriterLevel(&gzLayer, gzip.BestCompression)
	if _, err = gz.Write(layer.Bytes()); err != nil {
		return nil, "", err
	}
	if err = gz.Close(); err != nil {
		return nil, "", err
	}
	cfg := ociConfig{Created: dockerfileEpoch, Architecture: arch, OS: "linux", Config: imageSpec(version, sum)}
	cfg.RootFS.Type, cfg.RootFS.DiffIDs = "layers", []string{diffID}
	cfg.History = []ociHistory{{Created: dockerfileEpoch, CreatedBy: "COPY soundpost and data/ (deploy/Dockerfile)"}}
	cfgRaw, err := json.Marshal(cfg)
	if err != nil {
		return nil, "", err
	}
	man := ociManifest{SchemaVersion: 2, MediaType: "application/vnd.oci.image.manifest.v1+json",
		Config: ociDescriptor{"application/vnd.oci.image.config.v1+json", blobDigest(cfgRaw), len(cfgRaw)},
		Layers: []ociDescriptor{{"application/vnd.oci.image.layer.v1.tar+gzip", blobDigest(gzLayer.Bytes()), gzLayer.Len()}}}
	manRaw, err := json.Marshal(man)
	if err != nil {
		return nil, "", err
	}
	manDigest := blobDigest(manRaw)
	idxRaw, err := json.Marshal(ociIndex{SchemaVersion: 2, MediaType: "application/vnd.oci.image.index.v1+json",
		Manifests: []ociDescriptor{{"application/vnd.oci.image.manifest.v1+json", manDigest, len(manRaw)}}})
	if err != nil {
		return nil, "", err
	}
	blob := func(d string) string { return path.Join("blobs", "sha256", strings.TrimPrefix(d, "sha256:")) }
	entries := []fileEntry{
		{name: "oci-layout", body: []byte(`{"imageLayoutVersion":"1.0.0"}`), mode: 0o644},
		{name: "index.json", body: idxRaw, mode: 0o644},
		{name: blob(man.Config.Digest), body: cfgRaw, mode: 0o644},
		{name: blob(man.Layers[0].Digest), body: gzLayer.Bytes(), mode: 0o644},
		{name: blob(manDigest), body: manRaw, mode: 0o644},
	}
	var out bytes.Buffer
	if err = writeTar(&out, entries); err != nil {
		return nil, "", err
	}
	return out.Bytes(), manDigest, nil
}
