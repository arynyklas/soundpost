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
	"strconv"
	"strings"
)

// The reference estate's compose file (examples/reference/compose.yaml) covers the WHOLE estate: the node, the SDK-bearing applications,
// PostgreSQL and the dependency (journeys_estate.go drives it). The attached-cluster mode (--cluster-attach) has a node of its own and
// takes only PostgreSQL and the dependency from the same file, with host-process applications; `--pg-local` runs everything as host
// processes on a host without a container runtime.

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
	TLSDir         string // directory holding ca.pem, leaf.pem and leaf.key (see writeComposeTLS)
	PGPassword     string
	PGPort         string // loopback port PostgreSQL is published on
	DependencyPort string // loopback port the dependency is published on
	// PGImage and DependencyImage are optional: empty leaves the digest the compose file itself names.
	PGImage, DependencyImage string
	// The rest is the whole estate (a run that starts only the backing services leaves it empty, and compose is given inert values the
	// services it does not start never use). NodeImage, ToolsImage and EstateImage are the ids of images built from this tree.
	NodeImage, ToolsImage, EstateImage string
	NodePort, GatewayPort              string // loopback ports the node and the gateway are published on
	NodeData                           string // host directory holding the node's data (empty: the compose file's own volume)
	CgroupRoot                         string // the delegated, empty cgroup v2 subtree mounted into the node container
	HandoverUID, HandoverGID           int
	JobRunID                           string
}

// inertImage is an image id no image has: compose needs every variable of the file to interpolate, and a run that starts only the backing
// services gives the images it never starts this id (they are never pulled: `pull_policy: never`).
const inertImage = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

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
	estate := c.NodeImage != "" || c.ToolsImage != "" || c.EstateImage != ""
	if estate {
		for _, f := range []struct{ name, v string }{{"node image", c.NodeImage}, {"provisioning image", c.ToolsImage}, {"estate image", c.EstateImage}, {"node port", c.NodePort},
			{"gateway port", c.GatewayPort}, {"delegated cgroup root", c.CgroupRoot}} {
			if f.v == "" {
				return nil, errors.New("reference compose: no " + f.name)
			}
		}
	}
	for _, img := range []struct{ name, variable, ref string }{{"node", "REFERENCE_NODE_IMAGE", c.NodeImage}, {"provisioning", "REFERENCE_TOOLS_IMAGE", c.ToolsImage}, {"estate", "REFERENCE_ESTATE_IMAGE", c.EstateImage}} {
		ref := img.ref
		if ref == "" {
			ref = inertImage
		} else if err := pinnedImageRef(ref); err != nil {
			return nil, fmt.Errorf("%s image: %w", img.name, err)
		}
		env = append(env, img.variable+"="+ref)
	}
	nodePort, gatewayPort, cgroup := c.NodePort, c.GatewayPort, c.CgroupRoot
	if !estate {
		nodePort, gatewayPort, cgroup = "0", "0", "/nonexistent"
	}
	env = append(env, "REFERENCE_NODE_PORT="+nodePort, "REFERENCE_GATEWAY_PORT="+gatewayPort, "REFERENCE_CGROUP_ROOT="+cgroup,
		"REFERENCE_HANDOVER_UID="+strconv.Itoa(c.HandoverUID), "REFERENCE_HANDOVER_GID="+strconv.Itoa(c.HandoverGID), "REFERENCE_JOB_RUN_ID="+c.JobRunID)
	if c.NodeData != "" {
		env = append(env, "REFERENCE_NODE_DATA="+c.NodeData)
	}
	return env, nil
}

// command is a docker compose invocation scoped to this run's project and file.
func (c referenceCompose) command(rest ...string) []string {
	return append([]string{"docker", "compose", "-p", c.Project, "-f", c.File}, rest...)
}

// writeComposeTLS puts the run's CA certificate, leaf certificate and leaf key into a directory of their own for the containers, which
// read them as uid 65534 (or, for the provision service and the node's own copy, as root) through a read-only bind mount: the directory
// and the three files are world-readable, and the directory lives inside the run's private (0700) work directory, so no other user of the
// host reaches it. The CA's key is never written anywhere (the run keeps only the CA certificate).
func writeComposeTLS(pki *journeyPKI, dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		return err
	}
	for src, name := range map[string]string{pki.CA: "ca.pem", pki.Cert: "leaf.pem", pki.Key: "leaf.key"} {
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
