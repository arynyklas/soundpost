// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http/cookiejar"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// The compose estate (07.04#12). In container mode the whole reference estate runs as the services of examples/reference/compose.yaml:
// the node, the SDK-bearing applications (Python API and jobs, Bun gateway, the Vite web build), PostgreSQL and the dependency, from
// images this run built from the tree and from digest-pinned third-party images. The per-source credentials are provisioned at run time
// by the compose service `provision`, which is THIS binary (`smoke journeys --provision-service`): it waits for the node, bootstraps its
// owner, creates the organizations, users and sources and writes each application's source configuration to a volume only the
// applications mount. The host process drives the browser and the jobs run, stops services, reads the evidence back through the node's
// published port and, with the node stopped and its data directory handed over to the operator, scans the node's storage in-process,
// exactly as the host-process mode does.

// journeyAppSpec is one SDK-bearing source of the estate.
type journeyAppSpec struct {
	name    string
	kinds   []model.Kind
	browser bool
	replay  bool
}

var journeyAppSpecs = []journeyAppSpec{
	{"gateway", []model.Kind{model.SpanKind, model.ErrorKind}, false, false},
	{"api", []model.Kind{model.SpanKind, model.ErrorKind}, false, false},
	// The job process also runs the SDK's runtime profiler: its profile and capability records need the kinds in the policy.
	{"jobs", []model.Kind{model.SpanKind, model.ErrorKind, model.JobAttempt, model.Profile, model.CapabilityKind}, false, false},
	// profile_chunk and capability are both listed: the browser SDK delivers the capability truth record with every profile run,
	// and the server admits only kinds the source policy names.
	{"web", []model.Kind{model.SpanKind, model.ErrorKind, model.Replay, model.Profile, model.CapabilityKind}, true, true},
	// The build's private artifact source: the artifact service refuses browser sources, so the
	// source map is uploaded under a private source whose policy registers the web build.
	{"webbuild", []model.Kind{model.SpanKind}, false, false},
}

// journeyAppIdentity is the deterministic identity of one source: the same ids in every run, known before anything starts.
func journeyAppIdentity(name string, webBuild model.ID) *appCfg {
	env := journeyID("environment/reference")
	c := &appCfg{Name: name, Source: journeyID("source/" + name), Service: journeyID("service/" + name), Build: journeyID("build/" + name), Browser: name == "web"}
	if name == "web" || name == "webbuild" {
		c.Build = webBuild
	}
	c.Resource = model.Resource{Service: c.Service, Environment: env, Build: c.Build, Instance: name + "-1", Labels: model.Labels{}}
	return c
}

// setExpectations fixes everything the rows compare against: all of it is deterministic.
func (j *journeyRun) setExpectations() *journeyExpected {
	e := &j.exp
	e.Org, e.Project, e.OtherOrg, e.OtherProject = journeyID("org-a"), journeyID("project-a"), journeyID("org-b"), journeyID("project-b")
	e.Job, e.Run = journeyID("job/reference.catalog.refresh"), journeyID("run/reference.catalog.refresh/1")
	e.WebBuild = journeyID("build/web")
	e.WebSource = journeyID("source/web")
	e.UnpricedItem = "sku-404"
	e.Canaries = []string{"CANARY_BODY_7f3a", "CANARY_PROMPT_9b2f", "CANARY_SQL_LITERAL_5d1e"}
	e.RequiredVersionIDs = []string{"go", "bun", "node_linux", "python", "chrome", "postgres", "soundpost"}
	if j.localPG() {
		e.RequiredVersionIDs = append(e.RequiredVersionIDs, "postgres_server_binary")
	} else {
		e.RequiredVersionIDs = append(e.RequiredVersionIDs, "docker_server")
	}
	// Where the unpriced order's failure is thrown (src/receipt.ts); set by the web app, see README.
	e.ThrowSource, e.ThrowLine, e.ThrowColumn = journeyThrowSource, journeyThrowLine, journeyThrowColumn
	return e
}

// ---- the provision service (inside the compose estate) ----

// provisionService is the configuration of `smoke journeys --provision-service`.
type provisionService struct {
	enabled                                                                       bool
	nodeURL, tlsDir, nodeData, cfgDir, gatewayOrigin, browserIngest, serverIngest string
}

// appUID is the unprivileged uid the estate's applications run as; the configuration files are readable by it alone.
const appUID = 65534

func (s *provisionService) validate() error {
	for _, f := range []struct{ name, v string }{{"--node-url", s.nodeURL}, {"--tls-dir", s.tlsDir}, {"--node-data", s.nodeData}, {"--cfg-dir", s.cfgDir},
		{"--gateway-origin", s.gatewayOrigin}, {"--browser-ingest", s.browserIngest}, {"--server-ingest", s.serverIngest}} {
		if f.v == "" {
			return errors.New("provision service: " + f.name + " is required")
		}
	}
	if !strings.HasPrefix(s.nodeURL, "https://") {
		return errors.New("provision service: --node-url must be an https origin")
	}
	return nil
}

// ingestAddress is where an application's SDK sends: the browser reaches the node at its published address, every other application at
// the node's compose service name.
func (s *provisionService) ingestAddress(app string) string {
	if app == "web" {
		return s.browserIngest
	}
	return s.serverIngest
}

// runProvisionService is the whole of the compose service `provision`.
func (j *journeyRun) runProvisionService() (err error) {
	s := j.svc
	j.rep = map[string]any{}
	j.logs = map[string]*syncBuffer{}
	j.csrf = map[*installSite]string{}
	defer func() {
		if err != nil {
			err = &smokeFailure{Smoke: "journeys", Stage: "provision", Code: sanitizeErr(err)}
		}
	}()
	if j.work, err = os.MkdirTemp("", "provision-"); err != nil {
		return err
	}
	defer os.RemoveAll(j.work)
	if j.pki, err = loadJourneyPKI(filepath.Join(s.tlsDir, "ca.pem"), filepath.Join(s.tlsDir, "leaf.pem"), filepath.Join(s.tlsDir, "leaf.key")); err != nil {
		return err
	}
	j.nodeAddr, j.nodeDir = strings.TrimPrefix(s.nodeURL, "https://"), s.nodeData
	j.site = &installSite{base: s.nodeURL, client: j.pki.client()}
	j.site.client.Jar, _ = cookiejar.New(nil)
	if err = waitHTTPS(j.pki.client(), s.nodeURL+"/readyz", nil, 120*time.Second); err != nil {
		return err
	}
	if err = j.provision(); err != nil {
		return err
	}
	// The web build's identity and its private artifact-write credential, for the `webbuild` service.
	spec, err := json.Marshal(map[string]any{"org": j.exp.Org, "project": j.exp.Project, "source": j.apps["webbuild"].Source, "build_id": j.apps["web"].Build,
		"endpoint": "https://" + j.ingestAddress("webbuild"), "artifact_token": j.token})
	if err != nil {
		return err
	}
	return j.writePrivateConfig(filepath.Join(j.cfgs, "web-build.json"), spec)
}

// writePrivateConfig writes a source configuration. Inside the provision service the file is the applications' alone (their uid, mode
// 0400): the credential volume is mounted read-only into exactly the services that need a configuration. The file is created 0400 and then
// given away (the service holds CAP_CHOWN only: it could not change the mode of a file that is no longer its own).
func (j *journeyRun) writePrivateConfig(path string, raw []byte) error {
	if j.svc == nil {
		return os.WriteFile(path, raw, 0o600)
	}
	_ = os.Remove(path)
	if err := os.WriteFile(path, raw, 0o400); err != nil {
		return err
	}
	return os.Chown(path, appUID, appUID)
}

// ---- images built from this tree ----

// journeyLeafNames are the names the run's one TLS leaf answers to: loopback (the host's browser, driver and reads) and the compose
// services that serve or are called over TLS.
var journeyLeafNames = []string{"localhost", "node", "api", "gateway", "dependency"}

var imageIDRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// composeDefault is the default a variable of the compose file names (`${NAME:-default}`).
func (j *journeyRun) composeDefault(variable string) (string, error) {
	raw, err := os.ReadFile(filepath.Join(j.root, referenceComposeRel))
	if err != nil {
		return "", err
	}
	m := regexp.MustCompile(`\$\{` + variable + `:-([^}]+)\}`).FindSubmatch(raw)
	if m == nil {
		return "", errors.New("compose file has no default for " + variable)
	}
	return string(m[1]), nil
}

func copyFileMode(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err = os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err = io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// dockerBuild builds a context and returns the id of the image (`docker build -q` prints exactly it).
func (j *journeyRun) dockerBuild(env []string, args ...string) (string, error) {
	out, err := runOut(j.root, env, append([]string{"docker", "build", "--pull=false", "-q"}, args...)...)
	if err != nil {
		return "", err
	}
	id := lastLine(out)
	if !imageIDRE.MatchString(id) {
		return "", fmt.Errorf("docker build did not answer an image id: %q", firstLine(out))
	}
	j.builtImages = append(j.builtImages, id)
	return id, nil
}

// provisionBinary puts a static smoke binary at dst: this very process when it is one, else one built from the tree.
func (j *journeyRun) provisionBinary(dst string) error {
	if exe, err := os.Executable(); err == nil {
		if ok, _ := installStaticELF(exe); ok {
			return copyFileMode(exe, dst, 0o755)
		}
	}
	if _, err := runOut(j.root, []string{"CGO_ENABLED=0", "GOFLAGS=-mod=readonly"}, "go", "build", "-trimpath", "-o", dst, "./tools/smoke"); err != nil {
		return fmt.Errorf("static smoke binary for the provision service: %w", err)
	}
	return nil
}

// buildImages builds the three first-party images of the estate from this tree (offline), unless the operator names one:
// the node (deploy/Dockerfile over the binary under test), the provisioning service (the smoke itself) and the applications.
func (j *journeyRun) buildImages() error {
	if err := requireNodeCgroupRoot(j.cgroupRoot); err != nil {
		return err
	}
	dir := filepath.Join(j.work, "images")
	v := j.obs.Versions
	if j.nodeImage == "" {
		ctx := filepath.Join(dir, "node")
		if err := copyFileMode(j.binary, filepath.Join(ctx, "soundpost"), 0o755); err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Join(ctx, "data"), 0o755); err != nil {
			return err
		}
		if err := copyFileMode(filepath.Join(j.root, "deploy/Dockerfile"), filepath.Join(ctx, "Dockerfile"), 0o644); err != nil {
			return err
		}
		version, _, _ := strings.Cut(v["soundpost"], " ")
		id, err := j.dockerBuild(nil, "--network=none", "--build-arg", "SOUNDPOST_VERSION="+version, "--build-arg", "SOUNDPOST_SHA256="+v["soundpost_binary_sha256"], ctx)
		if err != nil {
			return fmt.Errorf("node image: %w", err)
		}
		j.nodeImage = id
	}
	if j.toolsImage == "" {
		ctx := filepath.Join(dir, "tools")
		if err := j.provisionBinary(filepath.Join(ctx, "smoke")); err != nil {
			return err
		}
		if err := copyFileMode(filepath.Join(j.root, "examples/reference/Dockerfile.tools"), filepath.Join(ctx, "Dockerfile"), 0o644); err != nil {
			return err
		}
		id, err := j.dockerBuild(nil, "--network=none", ctx)
		if err != nil {
			return fmt.Errorf("provisioning image: %w", err)
		}
		j.toolsImage = id
	}
	if j.estateImage == "" {
		id, err := j.buildEstateImage(filepath.Join(dir, "estate"))
		if err != nil {
			return fmt.Errorf("estate image: %w", err)
		}
		j.estateImage = id
	}
	v["node_image_id"], v["provision_image_id"], v["estate_image_id"] = j.nodeImage, j.toolsImage, j.estateImage
	// The runtimes the applications run on are the estate image's own.
	for key, bin := range map[string]string{"bun": "/opt/bun/bin/bun", "python": "python", "node_estate": "/opt/node/bin/node"} {
		out, err := runOut(j.root, nil, "docker", "run", "--rm", "--pull=never", "--network=none", "--entrypoint", bin, j.estateImage, "--version")
		if err != nil {
			return fmt.Errorf("estate image %s: %w", key, err)
		}
		v[key] = out
	}
	return nil
}

func (j *journeyRun) buildEstateImage(ctx string) (string, error) {
	base := j.dependencyImage
	if base == "" {
		var err error
		if base, err = j.composeDefault("REFERENCE_PYTHON_IMAGE"); err != nil {
			return "", err
		}
	}
	j.obs.Versions["estate_base_image"] = base
	if err := copyFileMode(j.nodeLinux, filepath.Join(ctx, "opt/node/bin/node"), 0o755); err != nil {
		return "", err
	}
	if err := copyFileMode(j.bun, filepath.Join(ctx, "opt/bun/bin/bun"), 0o755); err != nil {
		return "", err
	}
	app := filepath.Join(ctx, "app")
	if err := os.MkdirAll(app, 0o755); err != nil {
		return "", err
	}
	// The repository's own files, exactly as they are (the pnpm workspace's node_modules keeps its relative links).
	pack := exec.Command("tar", "-C", j.root, "--exclude=__pycache__", "--exclude=*.pyc", "-cf", "-", "examples/reference", "sdk/python/src", "packages", "node_modules",
		"package.json", "tsconfig.base.json", "pnpm-workspace.yaml")
	unpack := exec.Command("tar", "-C", app, "-xf", "-")
	pipe, err := pack.StdoutPipe()
	if err != nil {
		return "", err
	}
	unpack.Stdin = pipe
	var packErr, unpackErr syncBuffer
	pack.Stderr, unpack.Stderr = &packErr, &unpackErr
	if err = unpack.Start(); err != nil {
		return "", err
	}
	if err = pack.Run(); err != nil {
		_ = unpack.Process.Kill()
		_ = unpack.Wait()
		return "", fmt.Errorf("tar of the tree: %w: %s", err, firstLine(packErr.String()))
	}
	if err = unpack.Wait(); err != nil {
		return "", fmt.Errorf("tar into the build context: %w: %s", err, firstLine(unpackErr.String()))
	}
	wheels := filepath.Join(ctx, "wheels")
	if err = os.MkdirAll(wheels, 0o755); err != nil {
		return "", err
	}
	args := []string{"--build-arg", "BASE=" + base}
	if j.wheelDir != "" {
		names, gerr := filepath.Glob(filepath.Join(j.wheelDir, "*.whl"))
		if gerr != nil || len(names) == 0 {
			return "", fmt.Errorf("--estate-wheels %s holds no wheel", j.wheelDir)
		}
		for _, n := range names {
			if err = copyFileMode(n, filepath.Join(wheels, filepath.Base(n)), 0o644); err != nil {
				return "", err
			}
		}
		args = append(args, "--network=none", "--build-arg", "PIP_ARGS=--no-index --find-links /wheels")
	}
	if err = copyFileMode(filepath.Join(j.root, "examples/reference/Dockerfile.estate"), filepath.Join(ctx, "Dockerfile"), 0o644); err != nil {
		return "", err
	}
	// The classic builder resolves a local image id as BASE (BuildKit would look for it in a registry).
	return j.dockerBuild([]string{"DOCKER_BUILDKIT=0"}, append(args, ctx)...)
}

// ---- the estate under compose ----

type composePS struct {
	Service  string `json:"Service"`
	State    string `json:"State"`
	Health   string `json:"Health"`
	ExitCode int    `json:"ExitCode"`
}

// estateServices lists the project's containers (one JSON object per line, or one array, depending on the compose version).
func (j *journeyRun) estateServices() ([]composePS, error) {
	out, err := runOut(j.root, j.composeEnv, j.compose.command("ps", "--all", "--format", "json")...)
	if err != nil {
		return nil, err
	}
	var all []composePS
	if strings.HasPrefix(out, "[") {
		if err = json.Unmarshal([]byte(out), &all); err != nil {
			return nil, err
		}
		return all, nil
	}
	for _, line := range strings.Split(out, "\n") {
		if line = strings.TrimSpace(line); line == "" {
			continue
		}
		var p composePS
		if err = json.Unmarshal([]byte(line), &p); err != nil {
			return nil, err
		}
		all = append(all, p)
	}
	return all, nil
}

var ansiRE = regexp.MustCompile("\x1b\\[[0-9;]*[A-Za-z]")

// serviceLogs is what one service wrote (stdout and stderr), whether or not it still runs. Compose writes an erase-line escape before
// some lines even with --no-color; it is removed so the lines are the service's own.
func (j *journeyRun) serviceLogs(service string) string {
	out, _ := runOut(j.root, j.composeEnv, j.compose.command("logs", "--no-color", "--no-log-prefix", service)...)
	return ansiRE.ReplaceAllString(out, "")
}

// keepServiceLogs records a service's output for the leak scan (and returns it).
func (j *journeyRun) keepServiceLogs(service string) string {
	out := j.serviceLogs(service)
	buf := &syncBuffer{}
	buf.Write([]byte(out))
	j.logs[service+".stdout"] = buf
	return out
}

var (
	estateLong = []string{"postgres", "dependency", "node", "api", "gateway"} // running and healthy
	estateOnce = []string{"init", "provision", "webbuild"}                    // run to completion, exit 0
)

// awaitEstate waits until every long-running service is healthy and every one-shot service has exited 0; a service that died, or a one-shot
// that failed, ends the wait at once with that service named.
func (j *journeyRun) awaitEstate(limit time.Duration) error {
	deadline := time.Now().Add(limit)
	var last string
	for time.Now().Before(deadline) {
		ps, err := j.estateServices()
		if err != nil {
			return err
		}
		state := map[string]composePS{}
		for _, p := range ps {
			state[p.Service] = p
		}
		ready := true
		for _, n := range estateLong {
			p, ok := state[n]
			switch {
			case !ok:
				ready = false
			case p.State == "exited" || p.State == "dead":
				return fmt.Errorf("service %s exited (%d)", n, p.ExitCode)
			case p.State != "running" || p.Health != "healthy":
				ready = false
			}
		}
		for _, n := range estateOnce {
			p, ok := state[n]
			switch {
			case !ok || p.State != "exited":
				if ok && p.State != "running" && p.State != "created" {
					return fmt.Errorf("service %s is %s", n, p.State)
				}
				ready = false
			case p.ExitCode != 0:
				return fmt.Errorf("service %s failed (exit %d)", n, p.ExitCode)
			}
		}
		if ready {
			return nil
		}
		last = fmt.Sprint(ps)
		time.Sleep(time.Second)
	}
	return fmt.Errorf("the estate was not up within %s: %s", limit, firstLine(last))
}

// estateFailure keeps what the services said when the estate did not come up (names, status lines and closed diagnostics only).
func (j *journeyRun) estateFailure() {
	for _, n := range append(append([]string{}, estateOnce...), estateLong...) {
		out := j.serviceLogs(n)
		if len(out) > 16384 {
			out = out[len(out)-16384:]
		}
		_ = os.WriteFile(filepath.Join(j.artDir, "estate-"+n+".log.txt"), []byte(out), 0o600)
	}
}

// requireNodeCgroupRoot refuses, before anything starts, a cgroup root the node container cannot use: the node runs as uid 0 without
// capabilities, which may write only what root owns, and its sandbox needs an empty subtree it can hand controllers to.
func requireNodeCgroupRoot(root string) error {
	fsType, err := runOut(".", nil, "stat", "-f", "-c", "%T", root)
	if err != nil || fsType != "cgroup2fs" {
		return fmt.Errorf("--symbolicate-cgroup-root %s is not a cgroup v2 directory", root)
	}
	owner, err := runOut(".", nil, "stat", "-c", "%u", root)
	if err != nil {
		return err
	}
	if owner != "0" {
		return fmt.Errorf("--symbolicate-cgroup-root %s is owned by uid %s: the node container runs as uid 0 without capabilities and writes only a subtree root owns (mkdir it as root, empty, under /sys/fs/cgroup)", root, owner)
	}
	procs, err := os.ReadFile(filepath.Join(root, "cgroup.procs"))
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(procs)) != "" {
		return fmt.Errorf("--symbolicate-cgroup-root %s holds processes: the node's sandbox needs an empty subtree", root)
	}
	return nil
}

// estateUp starts the whole estate with one `compose up` and records what is running.
func (j *journeyRun) estateUp() error {
	var rnd [12]byte
	_, _ = rand.Read(rnd[:])
	j.pgPass = hex.EncodeToString(rnd[:])
	ports := map[string]string{}
	for _, n := range []string{"postgres", "dependency", "node", "gateway"} {
		p, err := freePort()
		if err != nil {
			return err
		}
		ports[n] = p
	}
	j.pgPort = ports["postgres"]
	j.nodeDir = filepath.Join(j.work, "node-data")
	if err := os.MkdirAll(j.nodeDir, 0o700); err != nil {
		return err
	}
	e := j.setExpectations()
	j.obs.Expected = *e
	j.apps = map[string]*appCfg{}
	for _, a := range journeyAppSpecs {
		j.apps[a.name] = journeyAppIdentity(a.name, e.WebBuild)
	}
	c := &referenceCompose{File: filepath.Join(j.root, referenceComposeRel), Project: "soundpost-journeys-" + hex.EncodeToString(rnd[:4]),
		TLSDir: filepath.Join(j.work, "compose-tls"), PGPassword: j.pgPass, PGPort: ports["postgres"], DependencyPort: ports["dependency"],
		PGImage: j.pgImage, DependencyImage: j.dependencyImage, NodeImage: j.nodeImage, ToolsImage: j.toolsImage, EstateImage: j.estateImage,
		NodePort: ports["node"], GatewayPort: ports["gateway"], NodeData: j.nodeDir, CgroupRoot: j.cgroupRoot, HandoverUID: os.Getuid(), HandoverGID: os.Getgid(), JobRunID: e.Run.String()}
	if err := writeComposeTLS(j.pki, c.TLSDir); err != nil {
		return err
	}
	env, err := c.env()
	if err != nil {
		return err
	}
	j.compose, j.composeEnv = c, env
	j.nodeAddr, j.gw = "127.0.0.1:"+ports["node"], "127.0.0.1:"+ports["gateway"]
	j.rep["dependency_url"], j.rep["api_url"] = "https://127.0.0.1:"+ports["dependency"], "compose service api"
	// Every service starts in dependency order: init, node, provision, web build, PostgreSQL, dependency, API, gateway. `up` returns
	// once all have started (a failed one-shot dependency makes it fail at that service); the wait that follows is for health.
	if _, err = runOut(j.root, env, c.command("up", "--detach", "--no-build")...); err == nil {
		err = j.awaitEstate(240 * time.Second)
	}
	if err != nil {
		j.estateFailure()
		return fmt.Errorf("compose estate: %w", err)
	}
	images, err := runOut(j.root, env, c.command("config", "--images")...)
	if err != nil {
		return err
	}
	v := j.obs.Versions
	v["compose_images"] = strings.Join(strings.Fields(images), " ")
	for _, n := range []string{"postgres", "dependency", "node", "api", "gateway"} {
		if v[n+"_image_id"], err = j.composeImageID(n); err != nil {
			return err
		}
	}
	pgv, err := j.psql("select version()")
	if err != nil {
		return err
	}
	v["postgres"] = pgv
	if _, err = j.psql("select count(*) from orders"); err != nil {
		return fmt.Errorf("the compose service did not apply the reference schema: %w", err)
	}
	for _, n := range []string{"provision", "webbuild"} {
		j.keepServiceLogs(n)
	}
	if err = j.readBuild(j.logsOf("webbuild")); err != nil {
		j.estateFailure()
		return err
	}
	return nil
}

func (j *journeyRun) logsOf(service string) string {
	if b, ok := j.logs[service+".stdout"]; ok {
		return b.String()
	}
	return ""
}

// readBuild takes the web build's own result (its stdout line) as the observation of the upload: the build id, the debug id and the
// artifact id the node answered, and the sizes of what the gateway ships.
func (j *journeyRun) readBuild(out string) error {
	var res struct {
		BuildID string `json:"build_id"`
		Upload  string `json:"upload"`
		Assets  []struct {
			File       string `json:"file"`
			DebugID    string `json:"debug_id"`
			ArtifactID string `json:"artifact_id"`
		} `json:"assets"`
		Sizes map[string]int64 `json:"sizes"`
	}
	if err := json.Unmarshal([]byte(lastJSONLine(out)), &res); err != nil {
		head := out
		if len(head) > 24 {
			head = head[:24]
		}
		return fmt.Errorf("the web build's output is undecodable (%d bytes, starts %q): %v", len(out), head, err)
	}
	a := &j.obs.Artifact
	a.Uploaded = res.Upload == "ok" && len(res.Assets) > 0
	if id, perr := model.ParseID(res.BuildID); perr == nil {
		a.Build = id
	}
	if len(res.Assets) > 0 {
		a.DebugID, a.Artifact = res.Assets[0].DebugID, res.Assets[0].ArtifactID
		j.built.asset = res.Assets[0].File
	}
	// build.mjs fails the build when a shipped script still names its source map; nothing is shipped that does.
	a.HasSourceMapRef = false
	j.rep["web_asset_sizes"] = res.Sizes
	return nil
}

// runJobs is the job step: attempt 1 fails (the dependency is warming up), attempt 2 succeeds. Under compose it is the `jobs` service,
// run once with the deterministic run id.
func (j *journeyRun) runJobs() (string, error) {
	if j.estate {
		// --no-deps: the estate is already up; `run` would start the completed provision service again (its one-time bootstrap token is spent).
		return runOut(j.root, j.composeEnv, j.compose.command("run", "--rm", "--no-deps", "-T", "jobs")...)
	}
	return runOut(j.root, []string{"PYTHONPATH=" + j.pyPath, "REFERENCE_DATABASE_URL=" + j.dsn(), "PYTHONDONTWRITEBYTECODE=1"},
		j.python, filepath.Join(j.root, "examples/reference/jobs/run.py"), "--config", j.apps["jobs"].Path, "--ca", j.pki.CA, "--dependency-url", j.rep["dependency_url"].(string), "--run-id", j.exp.Run.String(), "--profile")
}

// estateStop stops one service (SIGTERM, 30 s), keeps its output for the leak scan and answers it. A service that does not exit 0 is an error.
func (j *journeyRun) estateStop(service string) (string, error) {
	_, err := runOut(j.root, j.composeEnv, j.compose.command("stop", "--timeout", "30", service)...)
	out := j.keepServiceLogs(service)
	if err != nil {
		return out, err
	}
	cid, err := runOut(j.root, j.composeEnv, j.compose.command("ps", "--all", "--quiet", service)...)
	if err != nil || cid == "" {
		return out, fmt.Errorf("service %s has no container", service)
	}
	code, err := runOut(j.root, nil, "docker", "inspect", "--format", "{{.State.ExitCode}}", cid)
	if err != nil {
		return out, err
	}
	if code != "0" {
		return out, fmt.Errorf("exit code %s", code)
	}
	return out, nil
}

// estateStopNode stops the node and hands its data directory to the operator: the node's files belong to uid 0 of its container, and the
// scan opens them in this process.
func (j *journeyRun) estateStopNode() error {
	if _, err := runOut(j.root, j.composeEnv, j.compose.command("stop", "--timeout", "30", "node")...); err != nil {
		return err
	}
	j.keepServiceLogs("node")
	return j.handOver()
}

// handOver gives the node's data directory to the operator (the `handover` service; the node must not run).
func (j *journeyRun) handOver() error {
	_, err := runOut(j.root, j.composeEnv, j.compose.command("run", "--rm", "-T", "handover")...)
	return err
}

// estateStartNode starts the node again on the same data: the directory is the node's own again (init), then the node runs until healthy.
func (j *journeyRun) estateStartNode() error {
	if _, err := runOut(j.root, j.composeEnv, j.compose.command("run", "--rm", "-T", "init")...); err != nil {
		return err
	}
	_, err := runOut(j.root, j.composeEnv, j.compose.command("up", "--detach", "--no-build", "--wait", "--wait-timeout", "120", "node")...)
	return err
}

// cleanupEstate removes the project (containers, volumes, network), gives the node's files back to the operator so the work directory can
// go, and removes the images this run built. Best effort: errors are not reported at teardown.
func (j *journeyRun) cleanupEstate() {
	if !j.estate {
		return
	}
	if j.compose != nil {
		down := j.compose.command("down", "--volumes", "--remove-orphans", "--timeout", "5")
		_, _ = runOut(j.root, j.composeEnv, down...)
		if j.nodeDir != "" {
			_, _ = runOut(j.root, j.composeEnv, j.compose.command("run", "--rm", "-T", "handover")...)
			_, _ = runOut(j.root, j.composeEnv, down...)
		}
	}
	for _, id := range j.builtImages {
		_, _ = runOut(j.root, nil, "docker", "rmi", id)
	}
}
