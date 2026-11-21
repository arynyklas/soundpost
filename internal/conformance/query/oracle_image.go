// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"path"
	"strings"
	"sync"
	"time"
)

// IdentityBasisContent is OracleIdentity.IdentityBasis of an oracle that ran from an
// image the lock does not name by id but whose content was proven against the lock.
const IdentityBasisContent = "content-identity"

// ImageFile is one file of an oracle image and the SHA-256 of its bytes.
type ImageFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// ContentIdentity is the lock record of what makes an oracle image the pinned
// oracle independently of the id of the daemon that built it: the platform, the
// entrypoint and the SHA-256 of every file that determines the oracle's
// behaviour (the upstream release binary of the pinned base image, the reference
// driver compiled from the pinned source archive, the time zone dataset, the
// configuration file). The harness adapter (/adapter) is not listed: it is the
// harness's own code, built from the tree under test.
type ContentIdentity struct {
	Architecture string      `json:"architecture"`
	Entrypoint   []string    `json:"entrypoint"`
	Files        []ImageFile `json:"files"`
}

// Validate refuses an identity that cannot pin anything.
func (c ContentIdentity) Validate() error {
	if c.Architecture != "linux/amd64" || len(c.Entrypoint) == 0 || len(c.Files) == 0 {
		return fmt.Errorf("content identity needs linux/amd64, an entrypoint and files")
	}
	seen := map[string]bool{}
	for _, f := range c.Files {
		if !path.IsAbs(f.Path) || path.Clean(f.Path) != f.Path || !hex64.MatchString(f.SHA256) || seen[f.Path] {
			return fmt.Errorf("content identity file %q is not an absolute clean unique path with a sha256", f.Path)
		}
		seen[f.Path] = true
	}
	return nil
}

var (
	imageResolutionMu sync.Mutex
	imageResolutions  = map[string]resolvedImage{}
)

type resolvedImage struct {
	ref     string
	rebuilt bool
}

// resolveOracleImage returns the image reference the runtime must run for the
// locked image id. When the daemon holds the locked id, that id is used and
// nothing else is consulted (a locked lab host, unchanged). When the daemon
// positively reports that the id does not exist, the image tagged tag is used
// only after its platform, entrypoint and every file of want were proven
// byte for byte; without a content identity, or without such an image, the
// answer is an error that names what to build. Any other answer of the runtime
// (a runtime that is not a full docker CLI, an unreachable daemon) leaves the
// locked id in place, and the run then fails or succeeds exactly as it always did.
func resolveOracleImage(ctx context.Context, runtime, lockedID, tag string, want *ContentIdentity) (ref string, rebuilt bool, err error) {
	key := runtime + "\x00" + lockedID + "\x00" + tag
	imageResolutionMu.Lock()
	defer imageResolutionMu.Unlock()
	if r, ok := imageResolutions[key]; ok {
		return r.ref, r.rebuilt, nil
	}
	remember := func(ref string, rebuilt bool) (string, bool, error) {
		imageResolutions[key] = resolvedImage{ref: ref, rebuilt: rebuilt}
		return ref, rebuilt, nil
	}
	_, stderr, runErr := runtimeOutput(ctx, runtime, "image", "inspect", "--format", "{{.Id}}", lockedID)
	if runErr == nil {
		return remember(lockedID, false)
	}
	if !imageAbsent(stderr) || want == nil {
		return lockedID, false, nil
	}
	if err = want.Validate(); err != nil {
		return "", false, fmt.Errorf("oracle image %s: %w", tag, err)
	}
	raw, stderr, runErr := runtimeOutput(ctx, runtime, "image", "inspect", tag)
	if runErr != nil {
		if imageAbsent(stderr) {
			return "", false, fmt.Errorf("the locked oracle image %s is not on this daemon and no image %s was built from the pinned inputs: run conformance/query/oracles/build-images.sh", lockedID, tag)
		}
		return "", false, fmt.Errorf("inspect %s: %w: %s", tag, runErr, strings.TrimSpace(stderr))
	}
	var inspected []struct {
		ID           string `json:"Id"`
		Os           string `json:"Os"`
		Architecture string `json:"Architecture"`
		Config       struct {
			Entrypoint []string `json:"Entrypoint"`
		} `json:"Config"`
	}
	if err = json.Unmarshal(raw, &inspected); err != nil || len(inspected) != 1 || !strings.HasPrefix(inspected[0].ID, "sha256:") {
		return "", false, fmt.Errorf("inspect %s: unreadable answer of the runtime", tag)
	}
	got := inspected[0]
	if got.Os+"/"+got.Architecture != want.Architecture {
		return "", false, fmt.Errorf("oracle image %s is %s/%s, the lock pins %s", tag, got.Os, got.Architecture, want.Architecture)
	}
	if strings.Join(got.Config.Entrypoint, "\x00") != strings.Join(want.Entrypoint, "\x00") {
		return "", false, fmt.Errorf("oracle image %s has entrypoint %v, the lock pins %v", tag, got.Config.Entrypoint, want.Entrypoint)
	}
	if err = proveImageFiles(ctx, runtime, got.ID, want.Files); err != nil {
		return "", false, fmt.Errorf("oracle image %s (%s) is not the pinned oracle: %w", tag, got.ID, err)
	}
	return remember(got.ID, true)
}

// imageAbsent reports whether a runtime's error text says the image does not exist.
func imageAbsent(stderr string) bool {
	s := strings.ToLower(stderr)
	return strings.Contains(s, "no such image") || strings.Contains(s, "no such object") || strings.Contains(s, "image not known")
}

// runtimeOutput runs one runtime command with an empty environment, as every
// other runtime call of the harness does, and returns its stdout and stderr.
func runtimeOutput(ctx context.Context, runtime string, args ...string) ([]byte, string, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, runtime, args...)
	cmd.Env = []string{}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	return stdout.Bytes(), stderr.String(), err
}

// proveImageFiles creates (never starts) a container of the image, hashes every
// named file as the runtime copies it out, and removes the container.
func proveImageFiles(ctx context.Context, runtime, imageID string, files []ImageFile) error {
	out, stderr, err := runtimeOutput(ctx, runtime, "create", "--network=none", imageID)
	if err != nil {
		return fmt.Errorf("create: %w: %s", err, strings.TrimSpace(stderr))
	}
	cid := strings.TrimSpace(string(out))
	if len(cid) != 64 {
		return fmt.Errorf("create: unexpected container id %q", cid)
	}
	if _, err = hex.DecodeString(cid); err != nil {
		return fmt.Errorf("create: unexpected container id %q", cid)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, _, _ = runtimeOutput(cleanup, runtime, "rm", "--force", cid)
	}()
	for _, f := range files {
		sum, err := copiedFileSHA256(ctx, runtime, cid, f.Path)
		if err != nil {
			return fmt.Errorf("%s: %w", f.Path, err)
		}
		if sum != f.SHA256 {
			return fmt.Errorf("%s is sha256:%s, the lock pins sha256:%s", f.Path, sum, f.SHA256)
		}
	}
	return nil
}

// copiedFileSHA256 streams one file out of the container and hashes it. The
// stream must be a tar archive of exactly one regular file.
func copiedFileSHA256(ctx context.Context, runtime, cid, file string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, runtime, "cp", "-L", cid+":"+file, "-")
	cmd.Env = []string{}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}
	if err = cmd.Start(); err != nil {
		return "", err
	}
	sum, readErr := hashSingleTarFile(pipe, path.Base(file))
	_, _ = io.Copy(io.Discard, pipe)
	if err = cmd.Wait(); err != nil {
		return "", fmt.Errorf("cp: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return sum, readErr
}

func hashSingleTarFile(r io.Reader, name string) (string, error) {
	tr := tar.NewReader(r)
	h, err := tr.Next()
	if err != nil {
		return "", fmt.Errorf("copied archive: %w", err)
	}
	if h.Typeflag != tar.TypeReg || h.Name != name {
		return "", fmt.Errorf("copied archive entry %q (type %c) is not the regular file %q", h.Name, h.Typeflag, name)
	}
	digest := sha256.New()
	if _, err = io.Copy(digest, tr); err != nil {
		return "", err
	}
	if _, err = tr.Next(); err != io.EOF {
		return "", fmt.Errorf("copied archive holds more than %q", name)
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}
