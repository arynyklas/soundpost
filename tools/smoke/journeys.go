// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/storage"
	"github.com/arynyklas/soundpost/internal/symbolicate"
)

// RunJourneys provisions an isolated product (a REAL `soundpost serve` process over HTTPS), a REAL
// PostgreSQL container, a deterministic HTTP dependency, the Python API and jobs, the Bun gateway
// and the Vite-built web app, drives them (HTTP, a real headless Chrome, a job run), then reads the
// admitted evidence back and evaluates every journey row (journeys_assert.go). It exits nonzero
// while any REQUIRED row is unsatisfied.
//
// Registered as: case "journeys": return RunJourneys(os.Args[2:]).
func RunJourneys(args []string) (result error) {
	fs := flag.NewFlagSet("journeys", flag.ContinueOnError)
	var j journeyRun
	fs.StringVar(&j.artDir, "artifact-dir", "", "output directory for the report (required)")
	fs.StringVar(&j.root, "root", ".", "repository root")
	fs.StringVar(&j.binary, "binary", "", "soundpost static binary (default: build/release output under --release)")
	fs.StringVar(&j.release, "release", "/tmp/n0704-dist", "directory of `go run ./build release` output")
	fs.StringVar(&j.bun, "bun", "/opt/bun/bin/bun", "Linux Bun")
	fs.StringVar(&j.nodeLinux, "node-linux", "", "Linux Node 22 (default: extracted from /tmp/node22.tar.xz after its sha256 check)")
	fs.StringVar(&j.nodeWin, "node-windows", "", "Windows Node 22 for Vite (default: <root>/.tools/node-v22.23.4-win-x64/node.exe)")
	fs.StringVar(&j.python, "python", "python3", "Python 3")
	fs.StringVar(&j.chrome, "chrome", "", "Linux Chrome (default: <root>/.tools/chrome-linux156/chrome-linux64/chrome)")
	fs.StringVar(&j.pgImage, "pg-image", "92620daddcd9", "LOCAL PostgreSQL 16 image (never pulled)")
	fs.StringVar(&j.symImage, "symbolicate-image", "soundpost-symbolicate:qualification", "LOCAL symbolication sandbox image (never pulled)")
	fs.BoolVar(&j.hold, "hold", false, "provision, write hold.json and wait for SIGINT (for developing the applications)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if j.artDir == "" {
		return errors.New("--artifact-dir is required")
	}
	j.rep = map[string]any{}
	j.logs = map[string]*syncBuffer{}
	j.csrf = map[*installSite]string{}
	defer func() {
		j.cleanup()
		if result == nil && !j.hold {
			result = j.finish()
		}
	}()
	return j.run()
}

type journeyRun struct {
	artDir, root, binary, release, bun, nodeLinux, nodeWin, python, chrome, pgImage, symImage string
	hold                                                                                      bool

	work     string
	pki      *journeyPKI
	rep      map[string]any
	logs     map[string]*syncBuffer
	procs    []*jproc
	pgName   string
	pgPort   string
	pgPass   string
	nodeDir  string
	nodeAddr string
	node     *jproc
	site     *installSite
	owner    auth.Session

	exp   journeyExpected
	obs   journeyObservation
	rows  []journeyRow
	apps  map[string]*appCfg
	cfgs  string
	gw    string // gateway host:port
	built struct{ out, asset string }
	order struct {
		Drive map[string]any
		Frame map[string]any
	}
	pyPath   string
	token    string // artifact write token
	reader   map[string]*installSite
	cookie   map[string]string
	csrf     map[*installSite]string
	depStats []byte
}

type appCfg struct {
	Name     string
	Source   model.ID
	Build    model.ID
	Service  model.ID
	Path     string
	Browser  bool
	Onboard  auth.SourceOnboarded
	Resource model.Resource
}

func (j *journeyRun) logf(f string, a ...any) { fmt.Fprintf(os.Stderr, "journeys: "+f+"\n", a...) }

func (j *journeyRun) cleanup() {
	for i := len(j.procs) - 1; i >= 0; i-- {
		if !j.procs[i].exited() {
			_ = j.procs[i].cmd.Process.Kill()
		}
	}
	if j.pgName != "" {
		exec.Command("docker", "rm", "-f", "-v", j.pgName).Run()
	}
	if j.work != "" {
		os.RemoveAll(j.work)
	}
}

func (j *journeyRun) track(p *jproc) *jproc {
	j.procs = append(j.procs, p)
	j.logs[p.name] = p.err
	j.logs[p.name+".stdout"] = p.out
	return p
}

func (j *journeyRun) run() error {
	var err error
	if j.root, err = filepath.Abs(j.root); err != nil {
		return err
	}
	if err = os.MkdirAll(j.artDir, 0o700); err != nil {
		return err
	}
	if j.work, err = os.MkdirTemp("", "journeys-"); err != nil {
		return err
	}
	if j.nodeWin == "" {
		j.nodeWin = filepath.Join(j.root, ".tools", "node-v22.23.4-win-x64", "node.exe")
	}
	if j.chrome == "" {
		j.chrome = filepath.Join(j.root, ".tools", "chrome-linux156", "chrome-linux64", "chrome")
	}
	steps := []struct {
		name string
		fn   func() error
	}{
		{"toolchain", j.toolchain}, {"pki", j.setupPKI}, {"postgres", j.startPostgres}, {"node", j.startNode},
		{"provision", j.provision}, {"web_build", j.buildWeb}, {"estate", j.startEstate},
		{"journeys", j.drive}, {"stop_estate", j.stopEstate}, {"collect", j.collect}, {"reads", j.readsAfterRestart}, {"verdict", j.verdict},
	}
	for _, s := range steps {
		if s.name == "web_build" && j.hold {
			if err = j.holdFile(); err != nil {
				return err
			}
			return j.waitHold()
		}
		j.logf("step %s", s.name)
		if err = s.fn(); err != nil {
			return &smokeFailure{Smoke: "journeys", Stage: s.name, Code: sanitizeErr(err)}
		}
	}
	return nil
}

func sanitizeErr(err error) string {
	s := err.Error()
	if len(s) > 300 {
		s = s[:300]
	}
	return strings.Map(func(r rune) rune {
		if r < 32 {
			return ' '
		}
		return r
	}, s)
}

// ---- toolchain / versions ----

func (j *journeyRun) toolchain() error {
	v := map[string]string{"go": runtime.Version() + " " + runtime.GOOS + "/" + runtime.GOARCH}
	j.obs.Versions = v
	if out, err := runOut(j.root, nil, "go", "version"); err == nil {
		v["go"] = out
	} else if out, err = runOut(j.root, nil, filepath.Join(j.root, ".tools/linux/go/bin/go"), "version"); err == nil {
		v["go"] = out
	}
	var err error
	if v["bun"], err = runOut(j.root, nil, j.bun, "--version"); err != nil {
		return err
	}
	if j.nodeLinux == "" {
		if j.nodeLinux, err = j.extractNode(); err != nil {
			return err
		}
	}
	if v["node_linux"], err = runOut(j.root, nil, j.nodeLinux, "--version"); err != nil {
		return err
	}
	if v["node_windows_vite"], err = runOut(j.root, nil, j.nodeWin, "--version"); err != nil {
		return err
	}
	if v["python"], err = runOut(j.root, nil, j.python, "--version"); err != nil {
		return err
	}
	if v["docker_server"], err = runOut(j.root, nil, "docker", "version", "--format", "{{.Server.Version}}"); err != nil {
		return err
	}
	v["kernel"], _ = runOut(j.root, nil, "uname", "-r")
	if id, err := runOut(j.root, nil, "docker", "image", "inspect", "--format", "{{.Id}}", j.pgImage); err == nil {
		v["postgres_image_id"] = id
	} else {
		return fmt.Errorf("local PostgreSQL image %s is not available: %w", j.pgImage, err)
	}
	if id, err := runOut(j.root, nil, "docker", "image", "inspect", "--format", "{{.Id}}", j.symImage); err == nil {
		v["symbolicate_image_id"] = id
	}
	if j.binary == "" {
		j.binary = filepath.Join(j.release, "linux-amd64", "soundpost")
	}
	out, err := runOut(j.root, nil, j.binary, "version", "--json")
	if err != nil {
		return fmt.Errorf("soundpost binary: %w", err)
	}
	var sv struct{ Version, Commit, Platform, GoVersion string }
	_ = json.Unmarshal([]byte(out), &sv)
	v["soundpost"] = sv.Version + " " + sv.Commit + " " + sv.Platform + " built with " + sv.GoVersion
	sum, err := fileSHA256(j.binary)
	if err != nil {
		return err
	}
	v["soundpost_binary_sha256"] = sum
	if ok, err := installStaticELF(j.binary); err != nil || !ok {
		return &smokeFailure{Stage: "binary_static", Code: "not_static_elf"}
	}
	pysite := filepath.Join(j.root, "examples/reference/pysite.sh")
	if out, err = runOut(j.root, nil, "sh", pysite, filepath.Join(j.work, "pysite")); err != nil {
		return err
	}
	j.pyPath = lastLine(out)
	return nil
}

func lastLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[i+1:])
	}
	return s
}

func (j *journeyRun) extractNode() (string, error) {
	dest := "/tmp/n0704node"
	bin := filepath.Join(dest, "bin", "node")
	if _, err := os.Stat(bin); err == nil {
		return bin, nil
	}
	sums, err := os.ReadFile("/tmp/SHASUMS256.txt")
	if err != nil {
		return "", fmt.Errorf("no Linux Node: pass --node-linux or provide /tmp/node22.tar.xz and /tmp/SHASUMS256.txt: %w", err)
	}
	want := ""
	for _, l := range strings.Split(string(sums), "\n") {
		if strings.HasSuffix(l, " node-v22.23.4-linux-x64.tar.xz") {
			want = strings.Fields(l)[0]
		}
	}
	have, err := fileSHA256("/tmp/node22.tar.xz")
	if err != nil || want == "" || want != have {
		return "", errors.New("node tarball sha256 does not match SHASUMS256.txt")
	}
	tmp := dest + "-x"
	os.RemoveAll(tmp)
	if err = os.MkdirAll(tmp, 0o755); err != nil {
		return "", err
	}
	if _, err = runOut(".", nil, "tar", "-xJf", "/tmp/node22.tar.xz", "-C", tmp, "--strip-components=1"); err != nil {
		return "", err
	}
	return bin, os.Rename(tmp, dest)
}

// ---- PKI, PostgreSQL, node ----

func (j *journeyRun) setupPKI() (err error) {
	j.pki, err = newJourneyPKI(filepath.Join(j.work, "pki"))
	return err
}

func (j *journeyRun) startPostgres() error {
	var rnd [12]byte
	_, _ = rand.Read(rnd[:])
	j.pgPass = hex.EncodeToString(rnd[:])
	j.pgName = "soundpost-journeys-pg-" + hex.EncodeToString(rnd[:4])
	// log_statement=all lets the smoke prove the SQL text (with its canary literal) really reached
	// PostgreSQL; the statement log is PostgreSQL's own and never stored by the product.
	if _, err := runOut(j.root, nil, "docker", "run", "-d", "--name", j.pgName, "--tmpfs", "/var/lib/postgresql/data", "-p", "127.0.0.1::5432",
		"-e", "POSTGRES_PASSWORD="+j.pgPass, "-e", "POSTGRES_DB=reference", j.pgImage, "-c", "log_statement=all"); err != nil {
		return err
	}
	out, err := runOut(j.root, nil, "docker", "port", j.pgName, "5432/tcp")
	if err != nil {
		return err
	}
	j.pgPort = out[strings.LastIndex(out, ":")+1:]
	for i := 0; ; i++ {
		if _, err = runOut(j.root, nil, "docker", "exec", j.pgName, "psql", "-U", "postgres", "-d", "reference", "-Atc", "select 1"); err == nil {
			break
		}
		if i > 100 {
			return errors.New("postgres did not become ready")
		}
		time.Sleep(300 * time.Millisecond)
	}
	schema, err := os.ReadFile(filepath.Join(j.root, "examples/reference/api/schema.sql"))
	if err != nil {
		return err
	}
	cmd := exec.Command("docker", "exec", "-i", j.pgName, "psql", "-U", "postgres", "-d", "reference", "-v", "ON_ERROR_STOP=1", "-q")
	cmd.Stdin = bytes.NewReader(schema)
	if b, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("schema: %w: %s", err, firstLine(string(b)))
	}
	v, err := j.psql("select version()")
	if err != nil {
		return err
	}
	j.obs.Versions["postgres"] = v
	return nil
}

func (j *journeyRun) psql(q string) (string, error) {
	return runOut(j.root, nil, "docker", "exec", j.pgName, "psql", "-U", "postgres", "-d", "reference", "-Atc", q)
}

func (j *journeyRun) dsn() string {
	return "postgresql://postgres:" + j.pgPass + "@127.0.0.1:" + j.pgPort + "/reference"
}

func (j *journeyRun) startNode() error {
	j.nodeDir = filepath.Join(j.work, "node-data")
	return j.launchNode()
}

func (j *journeyRun) launchNode() error {
	if j.nodeAddr == "" {
		addr, err := freeAddress()
		if err != nil {
			return err
		}
		j.nodeAddr = addr
	}
	if err := os.MkdirAll(j.nodeDir, 0o700); err != nil {
		return err
	}
	p, err := startJProc("node", j.root, nil, j.binary, "serve", "--mode=single", "--data-dir", j.nodeDir, "--listen", j.nodeAddr, "--tls-cert", j.pki.Cert, "--tls-key", j.pki.Key)
	if err != nil {
		return err
	}
	j.node = j.track(p)
	j.site = &installSite{base: "https://" + j.nodeAddr, client: j.pki.client()}
	j.site.client.Jar, _ = cookiejar.New(nil)
	return waitHTTPS(j.pki.client(), "https://"+j.nodeAddr+"/readyz", p, 60*time.Second)
}

func (j *journeyRun) stopNode() error {
	err := j.node.stop(30 * time.Second)
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return nil
		}
	}
	return err
}

// ---- provisioning: orgs, users, sources, configs ----

var (
	journeyOps  = []string{"request", "http.call", "db.execute", "job.run", "ui.action"}
	journeyDeps = []string{"api", "postgres", "dependency", "gateway"}
)

func (j *journeyRun) adminCommand(org model.ID, kind string, p auth.AdminPayload) error {
	status, raw, err := j.site.post("/api/v1/admin/read", map[string]string{"kind": "organizations"}, j.owner.CSRF, "")
	if err = requireSmokeResponse("admin_read", status, 200, raw, err); err != nil {
		return err
	}
	var view auth.AdminView
	if err = json.Unmarshal(raw, &view); err != nil {
		return err
	}
	p.Reason = "reference journeys"
	payload, _ := json.Marshal(p)
	status, raw, err = j.site.post("/api/v1/admin/commands", auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: view.Revision, OrgID: org, Kind: kind, Payload: payload}, j.owner.CSRF, "")
	return requireSmokeResponse("admin_"+kind, status, 200, raw, err)
}

func (j *journeyRun) provision() error {
	token, err := os.ReadFile(filepath.Join(j.nodeDir, "bootstrap.token"))
	if err != nil {
		return err
	}
	status, raw, err := j.site.post("/api/v1/bootstrap", map[string]string{"Token": string(token), "Email": "owner@journeys.invalid", "Password": "journeys owner password 2026"}, "", "")
	if err = requireSmokeResponse("bootstrap", status, 200, raw, err); err != nil {
		return err
	}
	if err = json.Unmarshal(raw, &j.owner); err != nil {
		return err
	}
	e := &j.exp
	e.Org, e.Project, e.OtherOrg, e.OtherProject = journeyID("org-a"), journeyID("project-a"), journeyID("org-b"), journeyID("project-b")
	e.Job, e.Run = journeyID("job/reference.catalog.refresh"), journeyID("run/reference.catalog.refresh/1")
	e.WebBuild = journeyID("build/web")
	e.UnpricedItem = "sku-404"
	e.Canaries = []string{"CANARY_BODY_7f3a", "CANARY_PROMPT_9b2f", "CANARY_SQL_LITERAL_5d1e"}
	e.RequiredVersionIDs = []string{"go", "bun", "node_linux", "node_windows_vite", "python", "chrome", "postgres", "docker_server", "soundpost"}
	// Where the unpriced order's failure is thrown (src/receipt.ts); set by the web app, see README.
	e.ThrowSource, e.ThrowLine, e.ThrowColumn = journeyThrowSource, journeyThrowLine, journeyThrowColumn
	readerA, readerB, builder := journeyID("user/reader-a"), journeyID("user/reader-b"), journeyID("user/builder")
	pwd := func(n string) string { return n + " journeys password 2026" }
	for _, c := range []struct {
		org  model.ID
		kind string
		p    auth.AdminPayload
	}{
		{e.Org, "create_org", auth.AdminPayload{Name: "reference journeys A"}},
		{e.Org, "create_project", auth.AdminPayload{ID: e.Project, Name: "reference"}},
		{e.Org, "create_user", auth.AdminPayload{ID: readerA, Email: "reader-a@journeys.invalid", Password: pwd("reader-a")}},
		{e.Org, "membership", auth.AdminPayload{UserID: readerA, Enabled: true}},
		{e.Org, "grant", auth.AdminPayload{UserID: readerA, ProjectID: e.Project, Enabled: true, Permissions: []string{string(auth.Read)}}},
		{e.Org, "create_user", auth.AdminPayload{ID: builder, Email: "builder@journeys.invalid", Password: pwd("builder")}},
		{e.Org, "membership", auth.AdminPayload{UserID: builder, Enabled: true}},
		{e.Org, "grant", auth.AdminPayload{UserID: builder, ProjectID: e.Project, Enabled: true, Permissions: []string{"artifacts.write", "artifacts.read"}}},
		{e.OtherOrg, "create_org", auth.AdminPayload{Name: "reference journeys B"}},
		{e.OtherOrg, "create_project", auth.AdminPayload{ID: e.OtherProject, Name: "other"}},
		{e.OtherOrg, "create_user", auth.AdminPayload{ID: readerB, Email: "reader-b@journeys.invalid", Password: pwd("reader-b")}},
		{e.OtherOrg, "membership", auth.AdminPayload{UserID: readerB, Enabled: true}},
		{e.OtherOrg, "grant", auth.AdminPayload{UserID: readerB, ProjectID: e.OtherProject, Enabled: true, Permissions: []string{string(auth.Read)}}},
	} {
		if err = j.adminCommand(c.org, c.kind, c.p); err != nil {
			return err
		}
	}
	// Artifact-write credential for the build, issued to the builder, scoped to this project only.
	status, raw, err = j.site.post("/api/v1/admin/tokens/issue", map[string]any{"org_id": e.Org, "principal": builder, "projects": []model.ID{e.Project}, "permissions": []string{"artifacts.write"}, "expires": fmt.Sprint(time.Now().Add(2 * time.Hour).Unix()), "reason": "reference journeys build"}, j.owner.CSRF, "")
	if err = requireSmokeResponse("token_issue", status, 200, raw, err); err != nil {
		return err
	}
	var issued struct{ Token string }
	if err = json.Unmarshal(raw, &issued); err != nil || issued.Token == "" {
		return &smokeFailure{Stage: "token_issue", Code: "decode"}
	}
	j.token = issued.Token
	// Sources.
	gwAddr, err := freeAddress()
	if err != nil {
		return err
	}
	j.gw = gwAddr
	j.cfgs = filepath.Join(j.work, "cfg")
	if err = os.MkdirAll(j.cfgs, 0o700); err != nil {
		return err
	}
	j.apps = map[string]*appCfg{}
	env := journeyID("environment/reference")
	for _, a := range []struct {
		name    string
		kinds   []model.Kind
		browser bool
		replay  bool
	}{
		{"gateway", []model.Kind{model.SpanKind, model.ErrorKind}, false, false},
		{"api", []model.Kind{model.SpanKind, model.ErrorKind}, false, false},
		{"jobs", []model.Kind{model.SpanKind, model.ErrorKind, model.JobAttempt}, false, false},
		// profile_chunk and capability are both listed: the browser SDK delivers the capability truth record with every profile run,
		// and the server admits only kinds the source policy names.
		{"web", []model.Kind{model.SpanKind, model.ErrorKind, model.Replay, model.Profile, model.CapabilityKind}, true, true},
		// The build's private artifact source: the artifact service refuses browser sources, so the
		// source map is uploaded under a private source whose policy registers the web build.
		{"webbuild", []model.Kind{model.SpanKind}, false, false},
	} {
		c := &appCfg{Name: a.name, Source: journeyID("source/" + a.name), Service: journeyID("service/" + a.name), Build: journeyID("build/" + a.name), Browser: a.browser}
		if a.name == "web" || a.name == "webbuild" {
			c.Build = e.WebBuild
		}
		if a.name == "web" {
			e.WebSource = c.Source
		}
		c.Resource = model.Resource{Service: c.Service, Environment: env, Build: c.Build, Instance: a.name + "-1", Labels: model.Labels{}}
		retention := map[model.Kind]uint32{}
		for _, k := range a.kinds {
			retention[k] = 14
		}
		policy := model.SourcePolicy{Revision: 1, Enabled: true, Class: "structured", Kinds: a.kinds,
			Resources:  model.ResourceRegistry{Services: []model.ID{c.Service}, Environments: []model.ID{env}, Builds: []model.ID{c.Build}, Instances: []string{c.Resource.Instance}},
			Operations: journeyOps, Dependencies: journeyDeps, Codes: journeyOps, RetentionDays: retention, MaxBytes: 1 << 30, MaxSeries: 1000, Replay: a.replay}
		ob := auth.SourceOnboarding{CommandID: model.NewID(), Org: e.Org, Project: e.Project, Source: c.Source, Browser: a.browser, Expires: model.UnixNano(time.Now().Add(2 * time.Hour).UnixNano()), Policy: policy, Reason: "reference journeys"}
		if a.browser {
			ob.Origins = []string{"https://" + j.gw}
		}
		status, raw, err := j.site.post("/api/v1/sources", ob, j.owner.CSRF, "")
		if err = requireSmokeResponse("source_onboard_"+a.name, status, 200, raw, err); err != nil {
			return err
		}
		if err = json.Unmarshal(raw, &c.Onboard); err != nil {
			return err
		}
		if err = j.writeConfig(c, env); err != nil {
			return err
		}
		j.apps[a.name] = c
	}
	j.obs.Expected = *e
	return nil
}

func (j *journeyRun) writeConfig(c *appCfg, env model.ID) error {
	cfg := map[string]any{
		"org": j.exp.Org, "project": j.exp.Project, "source": c.Source, "credential": c.Onboard.Credential, "build": c.Build,
		"endpoint": "https://" + j.nodeAddr + "/ingest/v1/batches", "ca_file": j.pki.CA,
		"policy": c.Onboard.Policy, "trusted_keys": c.Onboard.TrustedKeys, "descriptor": c.Onboard.Descriptor,
		"resource":     map[string]any{"service_id": c.Service, "environment_id": env, "build_id": c.Build, "instance_pseudonym": c.Resource.Instance},
		"job_registry": map[string]any{"reference.catalog.refresh": j.exp.Job},
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	c.Path = filepath.Join(j.cfgs, c.Name+".json")
	return os.WriteFile(c.Path, raw, 0o600)
}

func (j *journeyRun) holdFile() error {
	h := map[string]any{"work": j.work, "node": "https://" + j.nodeAddr, "ca": j.pki.CA, "cert": j.pki.Cert, "key": j.pki.Key, "gateway_listen": j.gw,
		"database_url": j.dsn(), "artifact_token": j.token, "configs": map[string]string{}, "binary": j.binary, "python_path": j.pyPath, "postgres_container": j.pgName}
	for n, a := range j.apps {
		h["configs"].(map[string]string)[n] = a.Path
	}
	raw, _ := json.MarshalIndent(h, "", "  ")
	return os.WriteFile(filepath.Join(j.artDir, "hold.json"), raw, 0o600)
}

func (j *journeyRun) waitHold() error {
	j.logf("hold: provisioned; hold.json written; SIGINT to tear down")
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	<-ch
	return nil
}

// ---- web build ----

func (j *journeyRun) buildWeb() error {
	out := filepath.Join(j.work, "web-dist")
	web := j.apps["web"]
	env := []string{"REFERENCE_ORG=" + j.exp.Org.String(), "REFERENCE_PROJECT=" + j.exp.Project.String(), "REFERENCE_SOURCE=" + j.apps["webbuild"].Source.String(),
		"REFERENCE_BUILD_ID=" + web.Build.String(), "REFERENCE_ENDPOINT=https://" + j.nodeAddr, "REFERENCE_ARTIFACT_TOKEN=" + j.token,
		"REFERENCE_OUT_DIR=" + out, "NODE_EXTRA_CA_CERTS=" + j.pki.CA,
		"WSLENV=REFERENCE_ORG:REFERENCE_PROJECT:REFERENCE_SOURCE:REFERENCE_BUILD_ID:REFERENCE_ENDPOINT:REFERENCE_ARTIFACT_TOKEN:REFERENCE_OUT_DIR/p:NODE_EXTRA_CA_CERTS/p"}
	stdout, err := runOut(j.root, env, j.nodeWin, "examples/reference/web/build.mjs")
	if err != nil {
		return fmt.Errorf("vite build: %w", err)
	}
	var res struct {
		BuildID string `json:"build_id"`
		Upload  string `json:"upload"`
		Assets  []struct {
			File       string `json:"file"`
			DebugID    string `json:"debug_id"`
			ArtifactID string `json:"artifact_id"`
		} `json:"assets"`
	}
	if err = json.Unmarshal([]byte(lastJSONLine(stdout)), &res); err != nil {
		return fmt.Errorf("build output undecodable")
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
	for _, as := range res.Assets {
		raw, rerr := os.ReadFile(filepath.Join(out, filepath.FromSlash(as.File)))
		if rerr != nil {
			return fmt.Errorf("built asset unreadable: %w", rerr)
		}
		if bytes.Contains(raw, []byte("sourceMappingURL")) {
			a.HasSourceMapRef = true
		}
	}
	j.built.out = out
	// The page's own config, served by the gateway; the browser source key is public by design.
	webCfg, err := os.ReadFile(web.Path)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(j.cfgs, "web-config.json"), webCfg, 0o600)
}

// ---- the estate ----

func (j *journeyRun) startEstate() error {
	dep, err := freeAddress()
	if err != nil {
		return err
	}
	api, err := freeAddress()
	if err != nil {
		return err
	}
	pyEnv := []string{"PYTHONPATH=" + j.pyPath, "REFERENCE_DATABASE_URL=" + j.dsn(), "PYTHONDONTWRITEBYTECODE=1"}
	ref := filepath.Join(j.root, "examples/reference")
	start := func(name, addr string, env []string, argv ...string) error {
		p, err := startJProc(name, j.root, env, argv...)
		if err != nil {
			return err
		}
		j.track(p)
		return waitHTTPS(j.pki.client(), "https://"+addr+"/healthz", p, 60*time.Second)
	}
	j.rep["dependency_url"], j.rep["api_url"] = "https://"+dep, "https://"+api
	if err = start("dependency", dep, pyEnv, j.python, filepath.Join(ref, "dependency/server.py"), "--listen", dep, "--cert", j.pki.Cert, "--key", j.pki.Key); err != nil {
		return err
	}
	if err = start("api", api, pyEnv, j.python, filepath.Join(ref, "api/serve.py"), "--listen", api, "--cert", j.pki.Cert, "--key", j.pki.Key, "--config", j.apps["api"].Path, "--ca", j.pki.CA, "--dependency-url", "https://"+dep); err != nil {
		return err
	}
	return start("gateway", j.gw, nil, j.bun, filepath.Join(ref, "gateway/server.ts"), "--listen", j.gw, "--cert", j.pki.Cert, "--key", j.pki.Key, "--config", j.apps["gateway"].Path, "--ca", j.pki.CA,
		"--api-url", "https://"+api, "--web-dir", j.built.out, "--web-config", filepath.Join(j.cfgs, "web-config.json"))
}

func (j *journeyRun) proc(name string) *jproc {
	for _, p := range j.procs {
		if p.name == name {
			return p
		}
	}
	return nil
}

// ---- driving the journeys ----

type flushLine struct {
	Flush struct {
		Pending  int `json:"pending"`
		Lost     int `json:"lost"`
		Receipts int `json:"receipts"`
	} `json:"flush"`
}

func (j *journeyRun) drive() error {
	e := j.exp
	note := "journey note " + e.Canaries[0]
	// 1. direct request through the gateway (no browser): gateway -> api -> PostgreSQL + dependency.
	body, _ := json.Marshal(map[string]any{"item": "sku-100", "quantity": 2, "note": note})
	resp, err := j.pki.client().Post("https://"+j.gw+"/api/orders", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	if resp.StatusCode != 200 || !bytes.Contains(raw, []byte(`"priced"`)) {
		return fmt.Errorf("direct order answered %d", resp.StatusCode)
	}
	j.rep["direct_order_status"] = resp.StatusCode
	// 2. real browser: click -> gateway -> api -> db, then the known failure for the unpriced item.
	order, err := j.driveBrowser("order", e.UnpricedItem, note)
	if err != nil {
		return err
	}
	j.order.Drive = order
	if t, ok := order["trace_id"].(string); ok {
		if id, perr := model.ParseID(t); perr == nil {
			j.obs.UITrace = id
		}
	}
	// 3. the job: attempt 1 fails (dependency warming up), attempt 2 succeeds.
	jobsOut, err := runOut(j.root, []string{"PYTHONPATH=" + j.pyPath, "REFERENCE_DATABASE_URL=" + j.dsn(), "PYTHONDONTWRITEBYTECODE=1"},
		j.python, filepath.Join(j.root, "examples/reference/jobs/run.py"), "--config", j.apps["jobs"].Path, "--ca", j.pki.CA, "--dependency-url", j.rep["dependency_url"].(string), "--run-id", e.Run.String())
	if err != nil {
		return fmt.Errorf("jobs: %w", err)
	}
	j.rep["jobs_output"] = json.RawMessage(lastJSONLine(jobsOut))
	j.logs["jobs.stdout"] = &syncBuffer{}
	j.logs["jobs.stdout"].Write([]byte(jobsOut))
	var jr struct {
		Versions map[string]string `json:"versions"`
	}
	if json.Unmarshal([]byte(lastJSONLine(jobsOut)), &jr) == nil {
		for k, v := range jr.Versions {
			j.obs.Versions["python_"+k] = v
		}
	}
	// 4. the replay recorder and the profiler, each in its own page/client.
	if j.obs.Replay.Attempted, err = j.scenario("replay"); err != nil {
		return err
	}
	if j.obs.Profile.Attempted, err = j.scenario("profile"); err != nil {
		return err
	}
	return nil
}

func (j *journeyRun) scenario(name string) (bool, error) {
	out, err := j.driveBrowser(name, "sku-100", "scenario note "+j.exp.Canaries[0])
	if err != nil {
		return false, err
	}
	j.rep[name+"_driver"] = out
	return true, nil
}

func (j *journeyRun) browserHome() (string, error) {
	home := filepath.Join(j.work, "home")
	db := filepath.Join(home, ".pki", "nssdb")
	if _, err := os.Stat(db); err == nil {
		return home, nil
	}
	if err := os.MkdirAll(db, 0o700); err != nil {
		return "", err
	}
	env := []string{"HOME=" + home}
	if _, err := runOut(j.root, env, "certutil", "-d", "sql:"+db, "-N", "--empty-password"); err != nil {
		return "", err
	}
	if _, err := runOut(j.root, env, "certutil", "-d", "sql:"+db, "-A", "-t", "C,,", "-n", "journeys-ca", "-i", j.pki.CA); err != nil {
		return "", err
	}
	return home, nil
}

func (j *journeyRun) driveBrowser(scenario, item, note string) (map[string]any, error) {
	home, err := j.browserHome()
	if err != nil {
		return nil, err
	}
	env := []string{"HOME=" + home, "NODE_PATH=" + filepath.Join(j.root, "web/node_modules"), "REFERENCE_NOTE=" + note, "PATH=" + os.Getenv("PATH")}
	cmd := exec.Command(j.nodeLinux, "examples/reference/web/drive.mjs", "--origin", "https://"+j.gw, "--chrome", j.chrome, "--scenario", scenario, "--item", item, "--note-env", "REFERENCE_NOTE")
	cmd.Dir, cmd.Env = j.root, env
	var out, errb syncBuffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	j.logs["driver-"+scenario] = &out
	j.logs["driver-"+scenario+".stderr"] = &errb
	if err = cmd.Run(); err != nil {
		return nil, fmt.Errorf("driver %s: %w: %s", scenario, err, firstLine(errb.String()))
	}
	var res map[string]any
	if err = json.Unmarshal([]byte(lastJSONLine(out.String())), &res); err != nil {
		return nil, fmt.Errorf("driver %s output undecodable", scenario)
	}
	if c, ok := res["chrome"].(string); ok && scenario == "order" {
		j.obs.Versions["chrome"] = c
	}
	return res, nil
}

func (j *journeyRun) stopEstate() error {
	var problems []string
	if resp, err := j.pki.client().Get(j.rep["dependency_url"].(string) + "/v1/stats"); err == nil {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		j.depStats = raw
	} else {
		problems = append(problems, "dependency stats unreadable")
	}
	for _, n := range []string{"gateway", "api", "dependency"} {
		p := j.proc(n)
		if err := p.stop(30 * time.Second); err != nil && n != "dependency" {
			problems = append(problems, n+": "+err.Error())
		}
		var fl flushLine
		if json.Unmarshal([]byte(lastJSONLine(p.out.String())), &fl) == nil && n != "dependency" {
			j.rep[n+"_flush"] = fl.Flush
			if fl.Flush.Pending != 0 || fl.Flush.Lost != 0 || fl.Flush.Receipts == 0 {
				problems = append(problems, fmt.Sprintf("%s flush pending=%d lost=%d receipts=%d", n, fl.Flush.Pending, fl.Flush.Lost, fl.Flush.Receipts))
			}
		} else if n != "dependency" {
			problems = append(problems, n+": no flush report on stdout")
		}
	}
	// What the dependency saw (hashes and counters only) is read before it exits.
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

// ---- collection (node stopped; storage opened in-process) ----

func (j *journeyRun) loginReader(name, email string) (*installSite, string, error) {
	s := &installSite{base: "https://" + j.nodeAddr, client: j.pki.client()}
	s.client.Jar, _ = cookiejar.New(nil)
	status, raw, err := s.post("/api/v1/login", map[string]string{"Email": email, "Password": strings.SplitN(email, "@", 2)[0] + " journeys password 2026", "Code": ""}, "", "")
	if err = requireSmokeResponse("login_"+name, status, 200, raw, err); err != nil {
		return nil, "", err
	}
	var sess auth.Session
	_ = json.Unmarshal(raw, &sess)
	j.csrf[s] = sess.CSRF
	u, _ := url.Parse(s.base)
	for _, c := range s.client.Jar.Cookies(u) {
		if c.Name == "__Host-soundpost" {
			return s, c.Value, nil
		}
	}
	return nil, "", errors.New("no session cookie")
}

func (j *journeyRun) collect() error {
	// Logins need the node up, the scans need it down: log in first, then stop the node.
	var err error
	j.reader = map[string]*installSite{}
	j.cookie = map[string]string{}
	for _, r := range [][2]string{{"builder", "builder@journeys.invalid"}, {"reader-a", "reader-a@journeys.invalid"}} {
		s, c, err := j.loginReader(r[0], r[1])
		if err != nil {
			return err
		}
		j.reader[r[0]], j.cookie[r[0]] = s, c
	}
	// The dependency's own counters, while it is still up? It was stopped in stopEstate; its
	// stats were read there. Gather proof that canaries flowed from the surviving evidence.
	if err = j.stopNode(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	app, err := appcore.Open(j.nodeDir)
	if err != nil {
		return err
	}
	defer app.Close()
	scan := func(kind model.Kind, f func(i int, p storage.Page)) error {
		cred, err := app.Auth.Authenticate(ctx, j.cookie["reader-a"])
		if err != nil {
			return err
		}
		scope, err := app.Auth.Authorize(ctx, cred, j.exp.Org, []model.ID{j.exp.Project}, auth.Read)
		if err != nil {
			return err
		}
		it, err := app.Storage.Scan(ctx, scope, storage.ScanRequest{Projects: []model.ID{j.exp.Project}, Signal: kind, Start: math.MinInt64, End: math.MaxInt64})
		if err != nil {
			return err
		}
		defer it.Close()
		for {
			page, err := it.Next(ctx)
			if errors.Is(err, io.EOF) {
				return nil
			}
			if err != nil {
				return err
			}
			for i := range page.Len() {
				f(i, page)
			}
		}
	}
	unsafe := func(what string, v any) {
		raw, _ := json.Marshal(v)
		if w := containsAny(raw, sqlWords); w != "" {
			j.obs.UnsafeStorage = append(j.obs.UnsafeStorage, what+" contains "+w)
		}
	}
	var gatewayRoots []model.ID
	counts := map[string]int{}
	if err = scan(model.SpanKind, func(i int, p storage.Page) {
		s := p.Values[i].Span
		counts["span"]++
		unsafe("span", s)
		if p.Sources[i] == j.apps["gateway"].Source && s.Parent == nil {
			gatewayRoots = append(gatewayRoots, s.Trace)
		}
	}); err != nil {
		return err
	}
	if len(gatewayRoots) != 1 {
		return fmt.Errorf("want exactly one parentless gateway server span (the direct request), found %d", len(gatewayRoots))
	}
	j.obs.DirectTrace = gatewayRoots[0]
	if err = scan(model.ErrorKind, func(i int, p storage.Page) {
		counts["error"]++
		unsafe("error", p.Values[i].Error)
		j.obs.Errors = append(j.obs.Errors, observedError{Source: p.Sources[i], Record: *p.Values[i].Error})
	}); err != nil {
		return err
	}
	if err = scan(model.JobAttempt, func(i int, p storage.Page) {
		counts["job_attempt"]++
		unsafe("job_attempt", p.Values[i].Job)
		j.obs.Jobs = append(j.obs.Jobs, observedJob{Source: p.Sources[i], Event: *p.Values[i].Job})
	}); err != nil {
		return err
	}
	if err = scan(model.Replay, func(i int, p storage.Page) { counts["replay"]++; j.obs.Replay.StoredReplayRow++ }); err != nil {
		return err
	}
	var chunks []model.ProfileChunk
	if err = scan(model.Profile, func(i int, p storage.Page) {
		counts["profile"]++
		j.obs.Profile.StoredProfile++
		j.obs.Profile.StoredSamples += len(p.Values[i].Profile.Samples)
		chunks = append(chunks, *p.Values[i].Profile)
	}); err != nil {
		return err
	}
	capabilities := map[model.ID]model.Capability{}
	if err = scan(model.CapabilityKind, func(i int, p storage.Page) {
		if p.Sources[i] != j.apps["web"].Source {
			return
		}
		counts["capability"]++
		j.obs.Profile.StoredCapability++
		capabilities[p.IDs[i]] = *p.Values[i].Capability
	}); err != nil {
		return err
	}
	j.obs.Profile.CapabilityLinked = len(chunks) > 0
	for _, chunk := range chunks {
		c, ok := capabilities[chunk.Capability]
		if !ok || c.Signal != model.Profile || c.Clock != chunk.Clock.Domain {
			j.obs.Profile.CapabilityLinked = false
		}
	}
	j.rep["stored_counts"] = counts
	j.symbolicate(ctx, app)
	return nil
}

// symbolicate maps the generated position Chrome reported for the real thrown error through the
// real uploaded source map, in the OCI sandbox. Any failure is the recorded reason.
func (j *journeyRun) symbolicate(ctx context.Context, app *appcore.App) {
	s := &j.obs.Symbol
	frames, _ := j.order.Drive["page_errors"].([]any)
	var line, col float64
	found := false
	for _, f := range frames {
		fe, _ := f.(map[string]any)
		fr, _ := fe["frames"].([]any)
		for _, x := range fr {
			m, _ := x.(map[string]any)
			if p, _ := m["path"].(string); strings.HasSuffix(p, ".js") && !found {
				line, _ = m["line"].(float64)
				col, _ = m["column"].(float64)
				found = true
				s.FromPage = true
			}
		}
	}
	if !found {
		s.Reason = "no_page_frame"
		return
	}
	cfg, reason := j.sandboxConfig()
	if reason != "" {
		s.Reason = reason
		return
	}
	svc, err := app.NewSymbolicator(cfg)
	if err != nil {
		s.Reason = "symbolicator_unavailable"
		return
	}
	cred, err := app.Auth.Authenticate(ctx, j.cookie["builder"])
	if err != nil {
		s.Reason = "builder_session_unavailable"
		return
	}
	scope, err := app.Auth.Authorize(ctx, cred, j.exp.Org, []model.ID{j.exp.Project}, auth.ArtifactRead)
	if err != nil {
		s.Reason = "artifact_read_scope_denied"
		return
	}
	artifact, perr := model.ParseID(j.obs.Artifact.Artifact)
	if perr != nil {
		s.Reason = "artifact_id_unavailable"
		return
	}
	c := uint32(col)
	var attempts []string
	for try := 0; try < 8; try++ {
		if try > 0 {
			time.Sleep(time.Second) // the sandbox has fixed 5 s/100 ms budgets: a loaded host can miss them
		}
		out, err := svc.Resolve(ctx, scope, j.exp.WebBuild, []model.Frame{{Module: j.built.asset, Function: "", Artifact: artifact.String(), Line: uint32(line), Column: &c, InApp: true}})
		if err != nil || len(out) != 1 {
			s.Reason = "resolve_failed"
			attempts = append(attempts, s.Reason)
			continue
		}
		s.Reason, s.Build = string(out[0].Reason), out[0].Build
		attempts = append(attempts, s.Reason)
		if out[0].Resolved != nil {
			s.Source, s.LineN, s.ColumnN = out[0].Resolved.Source, out[0].Resolved.Line, out[0].Resolved.Column
		}
		if out[0].Reason == symbolicate.Resolved {
			break
		}
	}
	j.rep["symbolication_attempts"] = attempts
	if fi, err := os.ReadDir(filepath.Join(j.built.out, "assets")); err == nil {
		sizes := map[string]int64{}
		for _, f := range fi {
			if info, err := f.Info(); err == nil {
				sizes[f.Name()] = info.Size()
			}
		}
		j.rep["web_asset_sizes"] = sizes
	}
	j.rep["generated_position"] = map[string]any{"path": j.built.asset, "line": line, "column": col}
}

// sandboxConfig builds the explicit OCI mode configuration from the LOCAL image (never pulled).
func (j *journeyRun) sandboxConfig() (symbolicate.Config, string) {
	id := j.obs.Versions["symbolicate_image_id"]
	if id == "" {
		return symbolicate.Config{}, "sandbox_unavailable"
	}
	label, err := runOut(j.root, nil, "docker", "image", "inspect", "--format", `{{index .Config.Labels "org.soundpost.worker.sha256"}}`, j.symImage)
	if err != nil || label == "" {
		return symbolicate.Config{}, "sandbox_unavailable"
	}
	docker, err := exec.LookPath("docker")
	if err != nil {
		return symbolicate.Config{}, "sandbox_unavailable"
	}
	var hash model.Hash
	if raw, err := hex.DecodeString(label); err != nil || len(raw) != len(hash) {
		return symbolicate.Config{}, "sandbox_unavailable"
	} else {
		copy(hash[:], raw)
	}
	return symbolicate.Config{Mode: "oci", OCIRuntime: docker, OCIImage: id, WorkerSHA256: hash, CacheBytes: 1 << 20}, ""
}

// ---- reads through the real HTTP routes after a restart ----

func (j *journeyRun) readsAfterRestart() error {
	if err := j.launchNode(); err != nil {
		return err
	}
	a, _, err := j.loginReader("reader-a", "reader-a@journeys.invalid")
	if err != nil {
		return err
	}
	b, _, err := j.loginReader("reader-b", "reader-b@journeys.invalid")
	if err != nil {
		return err
	}
	e := j.exp
	now := time.Now()
	window := map[string]any{"start": "0", "end": fmt.Sprint(now.Add(time.Hour).UnixNano())}
	read := func(actor string, s *installSite, org, project, trace model.ID) error {
		csrf := j.csrf[s]
		status, raw, err := s.post("/api/v1/traces/view", map[string]any{"org": org, "project": project, "trace": trace, "window": window}, csrf, "")
		if err != nil {
			return err
		}
		if len(raw) > 1<<20 && actor != "reader-a" {
			raw = raw[:1<<20]
		}
		j.obs.Reads = append(j.obs.Reads, traceRead{Actor: actor, OrgSent: org, Project: project, Trace: trace, Status: status, Body: json.RawMessage(raw)})
		return nil
	}
	for _, t := range []model.ID{j.obs.DirectTrace, j.obs.UITrace} {
		if err = read("reader-a", a, e.Org, e.Project, t); err != nil {
			return err
		}
		// reader B (organization B) names the owner's project, with its own org and with the owner's.
		if err = read("reader-b", b, e.OtherOrg, e.Project, t); err != nil {
			return err
		}
		if err = read("reader-b", b, e.Org, e.Project, t); err != nil {
			return err
		}
	}
	return j.stopNode()
}

// ---- verdict ----

const (
	journeyThrowSource = "src/receipt.ts"
	// `throw new UnpricedOrderError();` is line 24 of web/src/receipt.ts and its `new` starts at
	// 0-based column 10 (source-map v3 columns are 0-based).
	journeyThrowLine   = 24
	journeyThrowColumn = 10
)

func (j *journeyRun) verdict() error {
	e := j.exp
	// Proof that every canary really travelled (so absence from storage is a measurement).
	var stats struct {
		Contains map[string]int `json:"prompt_contains"`
	}
	_ = json.Unmarshal(j.depStats, &stats)
	flow := func(c string, where ...string) {
		j.obs.Flows = append(j.obs.Flows, canaryFlow{Canary: c, Reached: where})
	}
	var bodyWhere, promptWhere, sqlWhere []string
	if stats.Contains[e.Canaries[0]] > 0 {
		bodyWhere = append(bodyWhere, "dependency_prompt_counter")
	}
	if n, err := j.psql("select count(*) from orders where note like '%" + e.Canaries[0] + "%'"); err == nil && n != "0" && n != "" {
		bodyWhere = append(bodyWhere, "database_row")
	}
	if stats.Contains[e.Canaries[1]] > 0 {
		promptWhere = append(promptWhere, "dependency_prompt_counter")
	}
	if logs, err := exec.Command("docker", "logs", j.pgName).CombinedOutput(); err == nil && strings.Contains(string(logs), e.Canaries[2]) {
		sqlWhere = append(sqlWhere, "postgres_statement_log")
	}
	flow(e.Canaries[0], bodyWhere...)
	flow(e.Canaries[1], promptWhere...)
	flow(e.Canaries[2], sqlWhere...)
	j.fillReplayProfile()
	// Leak scan: the whole node data dir (any nesting of base64), every process log and output,
	// every read answer, and the observation itself.
	ctx := context.Background()
	hits, files, err := scanTreeForCanaries(ctx, j.nodeDir, e.Canaries)
	if err != nil {
		return err
	}
	j.rep["scanned_files"] = files
	j.obs.Leaks = append(j.obs.Leaks, hits...)
	for name, buf := range j.logs {
		if w := containsAny([]byte(buf.String()), e.Canaries); w != "" {
			j.obs.Leaks = append(j.obs.Leaks, leakHit{Canary: w, Where: "process output: " + name})
		}
	}
	for _, r := range j.obs.Reads {
		if w := containsAny(r.Body, e.Canaries); w != "" {
			j.obs.Leaks = append(j.obs.Leaks, leakHit{Canary: w, Where: "read answer: " + r.Actor})
		}
	}
	// The observation itself (minus the canary labels it must name to be assessed).
	scrubbed := j.obs
	scrubbed.Expected.Canaries, scrubbed.Flows = nil, nil
	if raw, _ := json.Marshal(scrubbed); containsAny(raw, e.Canaries) != "" {
		j.obs.Leaks = append(j.obs.Leaks, leakHit{Canary: containsAny(raw, e.Canaries), Where: "observation record"})
	}
	j.rows = assessJourneys(j.obs)
	return nil
}

func (j *journeyRun) fillReplayProfile() {
	if d, ok := j.rep["replay_driver"].(map[string]any); ok {
		r := &j.obs.Replay
		if rp, ok := d["replay"].(map[string]any); ok {
			emitted, _ := rp["chunksEmitted"].(float64)
			r.RecorderChunks = int(emitted)
			queued, _ := rp["queuedBeforeFlush"].(float64)
			if emitted > 0 && queued == 0 {
				// The recorder emitted chunks but the client queued none: the SDK did not turn them into deliverable records.
				r.RefusedOrLost = "sdk_recorder_chunks_not_enqueued"
			}
			if fl, ok := rp["flush"].(map[string]any); ok {
				lost, _ := fl["lost"].(float64)
				receipts, _ := fl["receipts"].(float64)
				r.AdmittedChunks = int(receipts)
				if r.RefusedOrLost == "" && lost > 0 {
					r.RefusedOrLost = "recorder_chunks_refused_or_lost"
				}
			}
		}
	}
	if d, ok := j.rep["profile_driver"].(map[string]any); ok {
		p := &j.obs.Profile
		if pr, ok := d["profile"].(map[string]any); ok {
			p.Capability, _ = pr["status"].(string)
			p.Reason, _ = pr["reason"].(string)
		}
		// The delivery is measured, not assumed: stored profile rows and a stored, linked capability record.
		p.SDKEnqueues = p.StoredProfile > 0 && p.CapabilityLinked
	}
}

func (j *journeyRun) finish() error {
	fmt.Fprintf(os.Stderr, "\nversions (actual):\n")
	for k, v := range j.obs.Versions {
		fmt.Fprintf(os.Stderr, "  %-24s %s\n", k, v)
	}
	fmt.Fprintf(os.Stderr, "\nadmitted IDs found vs expected:\n  ui trace      %s (driver) / direct trace %s (gateway root span)\n  web build     %s (expected) / %s (admitted error) / %s (uploaded)\n  job/run       %s / %s (expected)\n",
		j.obs.UITrace, j.obs.DirectTrace, j.exp.WebBuild, firstBuild(j.obs), j.obs.Artifact.Build, j.exp.Job, j.exp.Run)
	for _, ev := range j.obs.Jobs {
		fmt.Fprintf(os.Stderr, "  admitted attempt: job=%s run=%s attempt=%s ordinal=%d state=%s\n", ev.Event.Job, ev.Event.Run, ev.Event.Attempt, ev.Event.Ordinal, ev.Event.State)
	}
	for _, er := range j.obs.Errors {
		fmt.Fprintf(os.Stderr, "  admitted error: occurrence=%s class=%s build=%s\n", er.Record.Occurrence, er.Record.Class, er.Record.Build)
	}
	fmt.Fprintf(os.Stderr, "\nrows:\n")
	for _, r := range j.rows {
		state := "PASS"
		if !r.Satisfied {
			state = "NOT SATISFIED"
		}
		fmt.Fprintf(os.Stderr, "  %-13s %-45s %s %s\n", state, r.Name, r.Reason, r.Detail)
	}
	out := map[string]any{"observation": j.obs, "rows": j.rows}
	raw, _ := json.MarshalIndent(out, "", "  ")
	if err := os.WriteFile(filepath.Join(j.artDir, "observed.json"), raw, 0o600); err != nil {
		return err
	}
	// Details: driver outputs, flush reports and timings (no credentials, no telemetry text).
	delete(j.rep, "jobs_output_raw")
	details, _ := json.MarshalIndent(j.rep, "", "  ")
	if err := os.WriteFile(filepath.Join(j.artDir, "details.json"), details, 0o600); err != nil {
		return err
	}
	if bad := unsatisfiedRequired(j.rows); len(bad) > 0 {
		names := make([]string, len(bad))
		for i, b := range bad {
			names[i] = b.Name + "=" + b.Reason
		}
		return fmt.Errorf("%d required row(s) unsatisfied: %s", len(bad), strings.Join(names, ", "))
	}
	return nil
}

func firstBuild(o journeyObservation) model.ID {
	for _, e := range o.Errors {
		if e.Source == o.Expected.WebSource {
			return e.Record.Build
		}
	}
	return model.ID{}
}

var _ = sha256.Sum256
