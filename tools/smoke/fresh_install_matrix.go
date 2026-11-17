// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/arynyklas/soundpost/internal/model"
)

// matrixRow is one row of the fresh-install matrix.
type matrixRow struct {
	Row    string `json:"row"`
	Status string `json:"status"` // passed, failed, not_run
	Detail string `json:"detail"`
}

// subjectRecord mirrors build.ArtifactSubject (artifacts.json).
type subjectRecord struct {
	Kind, Name, Path, SHA256, Detail string
	Bytes                            int64
}

// RunFreshInstallMatrix installs the PRODUCED artifacts the way a user does, from a clean directory, and records
// the digest of each artifact it used (07.08-W4):
//
//	--release DIR    `build release` output (binary, SHA256SUMS)
//	--artifacts DIR  `build artifacts` output (artifacts.json): wheel, npm tarballs, OCI image layout
//	--bun PATH       Bun used to import the npm packages (default: bun on PATH)
//	--python PATH    Python 3.12+ with the cryptography wheel importable (default: python3)
//
// Rows: digests (every artifact re-hashed against artifacts.json), image_binary and perf_helper_image_binary (each image's
// only executable is the release binary it names: soundpost, soundpost-perf-acquire), wheel_fresh_venv (pip install --no-index --no-deps into a new venv, import,
// version), npm_fresh_project (each tarball unpacked into a new node_modules, the entry imported), install_single and
// install_distributed (the existing smokes against the release binary; the UI is served from the binary and compared
// to --web-dist when given). Rows that need an OCI runtime, root, kernels, a network registry or a database
// container are recorded not_run with the reason, never passed. There are no published URLs yet: the report records
// local paths and digests.
//
// To register (tools/smoke/main.go is frozen for lanes; the parent adds it): case "fresh-install-matrix": return RunFreshInstallMatrix(os.Args[2:]).
// Until then it runs through TestFreshInstallMatrixOfProducedArtifacts (env SOUNDPOST_MATRIX_*).
func RunFreshInstallMatrix(args []string) (result error) {
	stage := "matrix_flags"
	defer func() { result = annotateSmokeFailure("fresh_install_matrix", stage, model.ID{}, result) }()
	f := flag.NewFlagSet("fresh-install-matrix", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	artifact := f.String("artifact-dir", "", "result directory")
	release := f.String("release", "", "release directory")
	artifacts := f.String("artifacts", "", "artifacts directory")
	bun := f.String("bun", "bun", "Bun executable")
	python := f.String("python", "python3", "Python executable")
	webDist := f.String("web-dist", "", "built UI bundle the served assets must equal")
	root := f.String("root", ".", "repository root (installed @noble packages are copied from it)")
	if err := f.Parse(args); err != nil {
		return err
	}
	if *artifact == "" || *release == "" || *artifacts == "" {
		return errors.New("--artifact-dir, --release and --artifacts are required")
	}
	if err := os.MkdirAll(*artifact, 0o700); err != nil {
		return err
	}
	var rows []matrixRow
	record := func(row, status, detail string) { rows = append(rows, matrixRow{row, status, detail}) }
	var failed []string
	run := func(row string, fn func() (string, error)) {
		detail, err := fn()
		switch {
		case err == nil:
			record(row, "passed", detail)
		case strings.HasPrefix(err.Error(), "not_run:"):
			record(row, "not_run", strings.TrimPrefix(err.Error(), "not_run:"))
		default:
			record(row, "failed", err.Error())
			failed = append(failed, row)
		}
	}

	stage = "matrix_digests"
	var manifest struct {
		Subjects []subjectRecord
		SBOM     map[string]string `json:"sbom_sha256"`
	}
	raw, err := os.ReadFile(filepath.Join(*artifacts, "artifacts.json"))
	if err != nil {
		return err
	}
	if err = json.Unmarshal(raw, &manifest); err != nil {
		return err
	}
	byKind := map[string][]subjectRecord{}
	digests := map[string]string{}
	run("digests", func() (string, error) {
		for _, s := range manifest.Subjects {
			sum, err := fileSHA256(filepath.Join(*artifacts, filepath.FromSlash(s.Path)))
			if err != nil {
				return "", err
			}
			if sum != s.SHA256 {
				return "", fmt.Errorf("%s is %s, artifacts.json says %s", s.Path, sum, s.SHA256)
			}
			byKind[s.Kind] = append(byKind[s.Kind], s)
			digests[s.Path] = sum
		}
		return fmt.Sprintf("%d artifacts match artifacts.json", len(manifest.Subjects)), nil
	})
	binary := filepath.Join(*release, "linux-amd64", "soundpost")
	binSum, _ := fileSHA256(binary)
	digests["release/linux-amd64/soundpost"] = binSum

	stage = "matrix_image"
	run("image_binary", func() (string, error) {
		imgs := byKind["oci_image"]
		if len(imgs) != 1 {
			return "", errors.New("artifacts.json lists no single OCI image")
		}
		sum, err := imageBinarySHA256(filepath.Join(*artifacts, filepath.FromSlash(imgs[0].Path)), "soundpost")
		if err != nil {
			return "", err
		}
		if sum != binSum {
			return "", fmt.Errorf("image binary %s is not the release binary %s", sum, binSum)
		}
		return "image layer holds exactly the release binary " + sum + "; manifest " + imgs[0].Detail + " (not started: no OCI runtime)", nil
	})
	run("perf_helper_image_binary", func() (string, error) {
		imgs := byKind["oci_image_perf_helper"]
		if len(imgs) != 1 {
			return "", errors.New("artifacts.json lists no single perf helper OCI image")
		}
		helperSum, err := fileSHA256(filepath.Join(*release, "linux-amd64", "soundpost-perf-acquire"))
		if err != nil {
			return "", err
		}
		digests["release/linux-amd64/soundpost-perf-acquire"] = helperSum
		sum, err := imageBinarySHA256(filepath.Join(*artifacts, filepath.FromSlash(imgs[0].Path)), "soundpost-perf-acquire")
		if err != nil {
			return "", err
		}
		if sum != helperSum {
			return "", fmt.Errorf("helper image binary %s is not the release helper %s", sum, helperSum)
		}
		return "helper image layer holds exactly the release soundpost-perf-acquire " + sum + "; manifest " + imgs[0].Detail + " (not started: no OCI runtime, no root, no CAP_PERFMON)", nil
	})

	stage = "matrix_wheel"
	run("wheel_fresh_venv", func() (string, error) {
		wheels := byKind["python_wheel"]
		if len(wheels) != 1 {
			return "", errors.New("artifacts.json lists no single wheel")
		}
		if _, err := exec.LookPath(*python); err != nil {
			return "", errors.New("not_run:" + *python + " not found")
		}
		dir, err := os.MkdirTemp("", "soundpost-venv-")
		if err != nil {
			return "", err
		}
		defer os.RemoveAll(dir)
		if out, err := exec.Command(*python, "-m", "venv", "--system-site-packages", dir).CombinedOutput(); err != nil {
			return "", errors.New("not_run:python -m venv failed: " + firstLine(string(out)))
		}
		py := filepath.Join(dir, "bin", "python")
		wheel, _ := filepath.Abs(filepath.Join(*artifacts, filepath.FromSlash(wheels[0].Path)))
		if out, err := exec.Command(py, "-m", "pip", "install", "--no-index", "--no-deps", "--no-cache-dir", wheel).CombinedOutput(); err != nil {
			return "", fmt.Errorf("pip install: %s", firstLine(string(out)))
		}
		cmd := exec.Command(py, "-I", "-c", "import importlib.metadata as m, soundpost; print(m.version('soundpost'), soundpost.__file__)")
		out, err := cmd.CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("import: %s", firstLine(string(out)))
		}
		if !strings.HasPrefix(string(out), wheels[0].Detail+" "+dir) {
			return "", fmt.Errorf("installed version or location unexpected: %s", firstLine(string(out)))
		}
		return "installed " + wheels[0].Name + " (" + wheels[0].SHA256 + ") into a new venv and imported it: " + strings.TrimSpace(wheels[0].Detail), nil
	})

	stage = "matrix_npm"
	run("npm_fresh_project", func() (string, error) {
		pkgs := byKind["npm_package"]
		if len(pkgs) == 0 {
			return "", errors.New("artifacts.json lists no npm package")
		}
		if _, err := exec.LookPath(*bun); err != nil {
			return "", errors.New("not_run:" + *bun + " not found (the packages export TypeScript sources)")
		}
		dir, err := os.MkdirTemp("", "soundpost-npm-")
		if err != nil {
			return "", err
		}
		defer os.RemoveAll(dir)
		names := []string{}
		for _, p := range pkgs {
			scope := strings.TrimSuffix(strings.TrimPrefix(p.Name, "soundpost-"), "-"+p.Detail+".tgz")
			if err := untarGz(filepath.Join(*artifacts, filepath.FromSlash(p.Path)), filepath.Join(dir, "node_modules", "@soundpost", scope)); err != nil {
				return "", err
			}
			names = append(names, "@soundpost/"+scope)
		}
		if err := provideNoble(*root, dir); err != nil {
			return "", errors.New("not_run:" + err.Error())
		}
		quoted, _ := json.Marshal(names)
		script := "const m = " + string(quoted) + ".map(n => import(n)); const mods = await Promise.all(m); console.log(mods.map(x => Object.keys(x).length).join(','));"
		cmd := exec.Command(*bun, "-e", script)
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("import: %s", firstLine(string(out)))
		}
		return "unpacked " + strings.Join(names, ", ") + " into a new node_modules; core and node imported (export counts " + strings.TrimSpace(string(out)) + ")", nil
	})

	stage = "matrix_install_single"
	run("install_single", func() (string, error) {
		a := filepath.Join(*artifact, "install-single")
		args := []string{"--artifact-dir", a, "--binary", binary, "--release", *release}
		if *webDist != "" {
			args = append(args, "--web-dist", *webDist)
		}
		if err := RunInstallSingle(args); err != nil {
			return "", err
		}
		return "install-single passed against release/linux-amd64/soundpost " + binSum, nil
	})
	stage = "matrix_install_distributed"
	run("install_distributed", func() (string, error) {
		if err := RunInstallDistributed([]string{"--artifact-dir", filepath.Join(*artifact, "install-distributed"), "--binary", binary, "--release", *release}); err != nil {
			return "", err
		}
		return "install-distributed (process mode) passed against " + binSum, nil
	})
	record("container_install", "not_run", "no OCI runtime and no root on the host; the image is verified structurally (image_binary) but not started")
	record("reference_journeys", "not_run", "tools/smoke journeys needs a PostgreSQL container, Chrome and Windows Vite; no OCI runtime on the host")
	record("native_profile_install", "not_run", "needs root, the installed helper and Linux kernels 6.1/6.6")
	record("published_urls", "not_run", "nothing is published; paths and digests are recorded instead")

	stage = "matrix_artifact"
	report := map[string]any{"version": 1, "rows": rows, "digests": digests, "sbom_sha256": manifest.SBOM}
	encoded, _ := json.MarshalIndent(report, "", "  ")
	if err = os.WriteFile(filepath.Join(*artifact, "fresh-install-matrix.json"), encoded, 0o600); err != nil {
		return err
	}
	if len(failed) > 0 {
		return &smokeFailure{Stage: "matrix_rows", Code: "rows_failed_" + strings.Join(failed, "_")}
	}
	return nil
}

// imageBinarySHA256 reads an OCI layout tar and returns the sha256 of the file called name, the only file of its only layer.
func imageBinarySHA256(path, name string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	files := map[string][]byte{}
	tr := tar.NewReader(bytes.NewReader(raw))
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
		b, _ := io.ReadAll(tr)
		files[h.Name] = b
	}
	var idx struct{ Manifests []struct{ Digest string } }
	if err = json.Unmarshal(files["index.json"], &idx); err != nil || len(idx.Manifests) != 1 {
		return "", errors.New("image index.json is not a single-manifest index")
	}
	blob := func(d string) []byte { return files["blobs/sha256/"+strings.TrimPrefix(d, "sha256:")] }
	check := func(d string, b []byte) error {
		sum := sha256.Sum256(b)
		if "sha256:"+hex.EncodeToString(sum[:]) != d {
			return fmt.Errorf("blob %s does not match its digest", d)
		}
		return nil
	}
	man := blob(idx.Manifests[0].Digest)
	if err = check(idx.Manifests[0].Digest, man); err != nil {
		return "", err
	}
	var m struct {
		Layers []struct{ Digest string }
	}
	if err = json.Unmarshal(man, &m); err != nil || len(m.Layers) != 1 {
		return "", errors.New("image manifest does not have exactly one layer")
	}
	if err = check(m.Layers[0].Digest, blob(m.Layers[0].Digest)); err != nil {
		return "", err
	}
	gz, err := gzip.NewReader(bytes.NewReader(blob(m.Layers[0].Digest)))
	if err != nil {
		return "", err
	}
	lt := tar.NewReader(gz)
	found := ""
	for {
		h, err := lt.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
		if h.Typeflag == tar.TypeReg {
			if h.Name != name {
				return "", fmt.Errorf("unexpected file %s in the image layer", h.Name)
			}
			b, _ := io.ReadAll(lt)
			sum := sha256.Sum256(b)
			found = hex.EncodeToString(sum[:])
		}
	}
	if found == "" {
		return "", errors.New("the image layer has no " + name + " binary")
	}
	return found, nil
}

// untarGz unpacks an npm tarball (every member under package/) into dst.
func untarGz(path, dst string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		rel := strings.TrimPrefix(h.Name, "package/")
		if h.Typeflag != tar.TypeReg || rel == h.Name || strings.Contains(rel, "..") {
			return fmt.Errorf("unexpected member %q", h.Name)
		}
		target := filepath.Join(dst, filepath.FromSlash(rel))
		if err = os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		out, err := os.Create(target)
		if err != nil {
			return err
		}
		if _, err = io.Copy(out, tr); err != nil {
			out.Close()
			return err
		}
		out.Close()
	}
}

// provideNoble copies the pinned @noble packages the core package depends on from the repository's installed
// workspace into the new project (the registry is not reachable; versions are the lockfile's).
func provideNoble(root, project string) error {
	src := filepath.Join(root, "packages", "core", "node_modules", "@noble")
	if _, err := os.Stat(src); err != nil {
		return fmt.Errorf("installed @noble packages not found at %s", src)
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	for _, e := range entries {
		pkg, err := filepath.EvalSymlinks(filepath.Join(src, e.Name()))
		if err != nil {
			return err
		}
		if err = copyTreeFiles(pkg, filepath.Join(project, "node_modules", "@noble", e.Name())); err != nil {
			return err
		}
	}

	return nil
}

func copyTreeFiles(src, dst string) error {
	return filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, raw, 0o644)
	})
}
