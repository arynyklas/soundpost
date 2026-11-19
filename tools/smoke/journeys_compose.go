// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// The reference estate's compose file (examples/reference/compose.yaml) runs the BACKING services only: PostgreSQL 16 and the
// uninstrumented HTTPS dependency. The product node and the SDK-bearing applications (Python API and jobs, Bun gateway, Vite web
// build) are started by the journeys smoke itself, because they take the per-source credential, signed policy and trusted keys that
// only the running node issues (`POST /api/v1/sources`). A container run of the journeys smoke therefore takes its PostgreSQL and
// its dependency from this compose file, project-scoped and removed at the end; a host without a container runtime uses
// `--pg-local` and runs the dependency as a host process too.

// referenceComposeRel is the reference estate's compose file, relative to the repository root.
const referenceComposeRel = "examples/reference/compose.yaml"

// A content address: a full image id, or a repository name pinned by a full digest. Tags, short ids and abbreviated digests are
// resolved by the runtime to whatever it holds (or can pull) at that moment, so a run could silently use a different image.
var pinnedImageRE = func() *regexp.Regexp {
	const c = `[a-z0-9]+(?:[._-][a-z0-9]+)*`
	return regexp.MustCompile(`^(?:(?:` + c + `(?::[0-9]+)?/)?(?:` + c + `/)*` + c + `@)?sha256:[0-9a-f]{64}$`)
}()

// pinnedImageRef accepts `sha256:<64 hex>` (an image id) and `name@sha256:<64 hex>` (a digest-pinned name).
func pinnedImageRef(ref string) error {
	if !pinnedImageRE.MatchString(ref) {
		return fmt.Errorf("image %q is not pinned: name an image id (sha256:<64 hex>) or a digest (name@sha256:<64 hex>), never a tag or an abbreviation", ref)
	}
	return nil
}

// referenceCompose is how one journeys run drives examples/reference/compose.yaml.
type referenceCompose struct {
	File           string // absolute path of compose.yaml
	Project        string // compose project of this run (never the file's own name, so concurrent runs and other stacks stay apart)
	TLSDir         string // directory holding leaf.pem and leaf.key for the dependency (see writeComposeTLS)
	PGPassword     string
	PGPort         string // loopback port PostgreSQL is published on
	DependencyPort string // loopback port the dependency is published on
	// PGImage and DependencyImage are optional: empty leaves the digest the compose file itself names.
	PGImage, DependencyImage string
}

// env is the environment of every compose invocation of the run; an image named by the operator must be pinned.
func (c referenceCompose) env() ([]string, error) {
	for _, f := range []struct{ name, v string }{{"compose file", c.File}, {"compose project", c.Project}, {"TLS directory", c.TLSDir}, {"PostgreSQL password", c.PGPassword},
		{"PostgreSQL port", c.PGPort}, {"dependency port", c.DependencyPort}} {
		if f.v == "" {
			return nil, errors.New("reference compose: no " + f.name)
		}
	}
	env := []string{"REFERENCE_PG_PASSWORD=" + c.PGPassword, "REFERENCE_PG_PORT=" + c.PGPort, "REFERENCE_DEPENDENCY_PORT=" + c.DependencyPort, "REFERENCE_TLS_DIR=" + c.TLSDir}
	for _, img := range []struct{ name, variable, ref string }{{"PostgreSQL", "REFERENCE_PG_IMAGE", c.PGImage}, {"dependency", "REFERENCE_PYTHON_IMAGE", c.DependencyImage}} {
		if img.ref == "" {
			continue
		}
		if err := pinnedImageRef(img.ref); err != nil {
			return nil, fmt.Errorf("%s: %w", img.name, err)
		}
		env = append(env, img.variable+"="+img.ref)
	}
	return env, nil
}

// command is a docker compose invocation scoped to this run's project and file.
func (c referenceCompose) command(rest ...string) []string {
	return append([]string{"docker", "compose", "-p", c.Project, "-f", c.File}, rest...)
}

// writeComposeTLS puts the run's leaf certificate and key into a directory of their own for the dependency container, which
// reads them as uid 65534 through a read-only bind mount: the directory and the two files are world-readable, and the directory
// lives inside the run's private (0700) work directory, so no other user of the host reaches it. The CA's key is never written
// anywhere (the run keeps only the CA certificate).
func writeComposeTLS(pki *journeyPKI, dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		return err
	}
	for src, name := range map[string]string{pki.Cert: "leaf.pem", pki.Key: "leaf.key"} {
		raw, err := os.ReadFile(src)
		if err != nil {
			return err
		}
		dst := filepath.Join(dir, name)
		if err = os.WriteFile(dst, raw, 0o644); err != nil {
			return err
		}
		if err = os.Chmod(dst, 0o644); err != nil {
			return err
		}
	}
	return nil
}

// startComposePostgres starts the PostgreSQL service of the reference compose file under a project of this run and waits for
// its healthcheck, which passes only after the entrypoint applied examples/reference/api/schema.sql (mounted into
// docker-entrypoint-initdb.d) and the real server listens on TCP. The dependency service is started later, by startEstate.
func (j *journeyRun) startComposePostgres() error {
	var rnd [12]byte
	_, _ = rand.Read(rnd[:])
	j.pgPass = hex.EncodeToString(rnd[:])
	pgPort, err := freePort()
	if err != nil {
		return err
	}
	depPort, err := freePort()
	if err != nil {
		return err
	}
	j.pgPort = pgPort
	c := &referenceCompose{File: filepath.Join(j.root, referenceComposeRel), Project: "soundpost-journeys-" + hex.EncodeToString(rnd[:4]),
		TLSDir: filepath.Join(j.work, "compose-tls"), PGPassword: j.pgPass, PGPort: pgPort, DependencyPort: depPort, PGImage: j.pgImage, DependencyImage: j.dependencyImage}
	if err = writeComposeTLS(j.pki, c.TLSDir); err != nil {
		return err
	}
	env, err := c.env()
	if err != nil {
		return err
	}
	j.compose, j.composeEnv = c, env
	if _, err = runOut(j.root, env, c.command("up", "--detach", "--wait", "--wait-timeout", "180", "postgres")...); err != nil {
		return fmt.Errorf("compose up postgres: %w", err)
	}
	// What compose resolved and what is running: the images the file names (digests) and the id of each image behind them.
	images, err := runOut(j.root, env, c.command("config", "--images")...)
	if err != nil {
		return err
	}
	j.obs.Versions["compose_images"] = strings.Join(strings.Fields(images), " ")
	if j.obs.Versions["postgres_image_id"], err = j.composeImageID("postgres"); err != nil {
		return err
	}
	if _, err = j.psql("select count(*) from orders"); err != nil {
		return fmt.Errorf("the compose service did not apply the reference schema: %w", err)
	}
	v, err := j.psql("select version()")
	if err != nil {
		return err
	}
	j.obs.Versions["postgres"] = v
	return nil
}

// composeImageID is the id of the image a running compose service was created from.
func (j *journeyRun) composeImageID(service string) (string, error) {
	cid, err := runOut(j.root, j.composeEnv, j.compose.command("ps", "--quiet", service)...)
	if err != nil || cid == "" {
		return "", fmt.Errorf("compose service %s is not running: %v", service, err)
	}
	return runOut(j.root, nil, "docker", "inspect", "--format", "{{.Image}}", cid)
}

func freePort() (string, error) {
	addr, err := freeAddress()
	if err != nil {
		return "", err
	}
	_, port, err := net.SplitHostPort(addr)
	return port, err
}
