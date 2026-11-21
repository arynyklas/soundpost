// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// The fresh-install matrix rows that need a runtime beyond the Go toolchain. Each returns a detail on success, a
// notRun(reason) error when the host lacks the prerequisite (never a pass), and any other error as a failure.

// wheelFreshVenvRow installs the produced wheel into a new virtual environment without an index and imports it.
func wheelFreshVenvRow(python, wheel string, subject subjectRecord) (string, error) {
	if _, err := exec.LookPath(python); err != nil {
		return "", notRun(python + " not found")
	}
	dir, err := os.MkdirTemp("", "soundpost-venv-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	if out, err := exec.Command(python, "-m", "venv", "--system-site-packages", dir).CombinedOutput(); err != nil {
		return "", notRun("python -m venv failed: " + firstLine(string(out)))
	}
	py := filepath.Join(dir, "bin", "python")
	if out, err := exec.Command(py, "-m", "pip", "install", "--no-index", "--no-deps", "--no-cache-dir", wheel).CombinedOutput(); err != nil {
		return "", fmt.Errorf("pip install: %s", firstLine(string(out)))
	}
	cmd := exec.Command(py, "-I", "-c", "import importlib.metadata as m, soundpost; print(m.version('soundpost'), soundpost.__file__)")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("import: %s", firstLine(string(out)))
	}
	if !strings.HasPrefix(string(out), subject.Detail+" "+dir) {
		return "", fmt.Errorf("installed version or location unexpected: %s", firstLine(string(out)))
	}
	return "installed " + subject.Name + " (" + subject.SHA256 + ") into a new venv and imported it: " + strings.TrimSpace(subject.Detail), nil
}

type containerInstallOptions struct {
	ImageTar    string // the release's server image (OCI archive from `go run ./build artifacts`)
	ArtifactDir string
	DockerErr   string // non-empty: no usable OCI runtime
	WebDist     string
	Expected    string // the image manifest digest artifacts.json names
}

// containerInstallRow loads the produced server image into Docker and runs install-single against the container: the
// image's own nonroot user, read-only root, no capability, bootstrap, authenticated ingest and query over HTTPS, a
// forced kill and restart with the same receipts and the same query answer.
func containerInstallRow(o containerInstallOptions) (string, error) {
	if o.DockerErr != "" {
		return "", notRun("no OCI runtime on this host: " + o.DockerErr)
	}
	tag := fmt.Sprintf("soundpost-matrix-%d:install", time.Now().UnixNano()%1_000_000_000_000)
	defer dockerCombined(60*time.Second, nil, "rmi", "-f", tag)
	_, loaded, _ := ociArchiveImage(o.ImageTar)
	defer func() {
		for _, t := range loaded {
			dockerCombined(60*time.Second, nil, "rmi", "-f", t)
		}
	}()
	imageID, err := loadOCIImage(o.ImageTar, tag)
	if err != nil {
		return "", err
	}
	user, err := dockerCombined(30*time.Second, nil, "image", "inspect", "--format", "{{.Config.User}}", tag)
	if err != nil {
		return "", err
	}
	args := []string{"--artifact-dir", o.ArtifactDir, "--container", tag}
	if o.WebDist != "" {
		args = append(args, "--web-dist", o.WebDist)
	}
	if err = RunInstallSingle(args); err != nil {
		return "", err
	}
	return "install-single passed against the loaded server image (docker load of " + filepath.Base(o.ImageTar) + ", image id " + imageID + " = the archive's config digest, user " + strings.TrimSpace(user) + "; manifest " + o.Expected + "): started as nonroot, ready, authenticated ingest and query, killed and restarted with the same receipts", nil
}

type journeysOptions struct {
	ArtifactDir, Root, Release, Binary, Bun, NodeLinux, Python, Chrome, PGImage, PGLocal, CgroupRoot, EstateWheels string
	DockerErr                                                                                                      string
}

// referenceJourneysRow runs the journeys smoke (the reference estate against the produced binary, a real PostgreSQL 16,
// a real Chrome, the node's native symbolication) and requires every required row to be satisfied.
func referenceJourneysRow(j journeysOptions) (string, error) {
	if j.Chrome == "" {
		return "", notRun("no Chrome given (--chrome): the journeys drive a real headless Chrome")
	}
	if _, err := os.Stat(j.Chrome); err != nil {
		return "", notRun("Chrome is not available at " + j.Chrome)
	}
	if j.NodeLinux == "" {
		return "", notRun("no Linux Node 22 given (--node-linux)")
	}
	if _, err := os.Stat(j.NodeLinux); err != nil {
		return "", notRun("Node is not available at " + j.NodeLinux)
	}
	switch {
	case j.PGLocal == "" && j.PGImage == "":
		return "", notRun("no PostgreSQL 16 backend given (--pg-image for a local image or --pg-local for an installation)")
	case j.PGLocal == "" && j.DockerErr != "":
		return "", notRun("the PostgreSQL 16 backend is a container and there is no OCI runtime on this host: " + j.DockerErr)
	}
	if _, err := exec.LookPath(j.Bun); err != nil {
		return "", notRun("Bun not found (" + j.Bun + ")")
	}
	if _, err := exec.LookPath(j.Python); err != nil {
		return "", notRun("Python not found (" + j.Python + ")")
	}
	args := []string{"--artifact-dir", j.ArtifactDir, "--root", j.Root, "--release", j.Release, "--binary", j.Binary, "--bun", j.Bun, "--node-linux", j.NodeLinux, "--python", j.Python, "--chrome", j.Chrome}
	if j.PGLocal != "" {
		args = append(args, "--pg-local", j.PGLocal)
	} else {
		args = append(args, "--pg-image", j.PGImage)
	}
	if j.CgroupRoot != "" {
		args = append(args, "--symbolicate-cgroup-root", j.CgroupRoot)
	}
	if j.EstateWheels != "" {
		args = append(args, "--estate-wheels", j.EstateWheels)
	}
	if err := RunJourneys(args); err != nil {
		return "", err
	}
	raw, err := os.ReadFile(filepath.Join(j.ArtifactDir, "observed.json"))
	if err != nil {
		return "", err
	}
	var doc struct {
		Rows []struct {
			Name      string `json:"name"`
			Required  bool   `json:"required"`
			Satisfied bool   `json:"satisfied"`
		} `json:"rows"`
	}
	if err = json.Unmarshal(raw, &doc); err != nil || len(doc.Rows) == 0 {
		return "", errors.New("the journeys report lists no rows")
	}
	required, satisfied := 0, 0
	for _, r := range doc.Rows {
		if r.Required {
			required++
			if r.Satisfied {
				satisfied++
			}
		}
	}
	if required == 0 || satisfied != required {
		return "", fmt.Errorf("%d of %d required journey rows satisfied", satisfied, required)
	}
	backend := "the compose backing services (PostgreSQL 16 and the dependency) of examples/reference/compose.yaml, image " + j.PGImage
	if j.PGLocal != "" {
		backend = "unprivileged PostgreSQL 16 from " + j.PGLocal
	}
	return fmt.Sprintf("journeys smoke passed: %d of %d required rows satisfied against the produced binary, %s, Chrome %s, observed.json in the matrix artifact directory", satisfied, required, backend, j.Chrome), nil
}

// ociArchiveImage reads what a release image archive says about its image: the config digest (which Docker uses as the
// image ID) and the repository tags of its manifest.json, the file `docker load` reads.
func ociArchiveImage(archive string) (configDigest string, repoTags []string, err error) {
	raw, err := os.ReadFile(archive)
	if err != nil {
		return "", nil, err
	}
	files := map[string][]byte{}
	tr := tar.NewReader(bytes.NewReader(raw))
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", nil, err
		}
		files[h.Name], _ = io.ReadAll(tr)
	}
	var loader []struct {
		Config   string
		RepoTags []string
	}
	if err = json.Unmarshal(files["manifest.json"], &loader); err != nil || len(loader) != 1 {
		return "", nil, errors.New("the archive has no Docker loader manifest.json for exactly one image")
	}
	return "sha256:" + strings.TrimPrefix(loader[0].Config, "blobs/sha256/"), loader[0].RepoTags, nil
}

// loadOCIImage loads a release image archive into Docker with `docker load -i` (the archive as released, nothing
// converted), aliases it as alias and verifies that Docker's image ID is the config digest the archive names. The tags the
// archive itself carries stay on the host unless the caller removes them.
func loadOCIImage(archive, alias string) (imageID string, err error) {
	configDigest, tags, err := ociArchiveImage(archive)
	if err != nil {
		return "", err
	}
	if _, err = dockerCombined(5*time.Minute, nil, "load", "-i", archive); err != nil {
		return "", err
	}
	if _, err = dockerCombined(30*time.Second, nil, "tag", configDigest, alias); err != nil {
		return "", err
	}
	out, err := dockerCombined(30*time.Second, nil, "image", "inspect", "--format", "{{.Id}}", alias)
	if err != nil {
		return "", err
	}
	imageID = strings.TrimSpace(out)
	if imageID != configDigest {
		return imageID, fmt.Errorf("the loaded image %s is not the archive's image %s (tags %v)", imageID, configDigest, tags)
	}
	return imageID, nil
}
