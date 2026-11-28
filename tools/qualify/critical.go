// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package qualify

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// criticalPGImage is the PostgreSQL 16 image the committed critical-path command starts for the database paths (its --pg-image
// default), named by the manifest digest fixtures/sdk/compose.yaml pins. A digest reference resolves on a containerd image store and on
// a classic overlay2 one alike; a bare id prefix does not. It is only ever inspected here, never pulled, rebuilt or retagged.
const criticalPGImage = "postgres@sha256:92620daddcd947f8d5ab5ba66e848702fe443d87fed30c4cea8e389fd78dfc55"

// criticalPGPresent says why the PostgreSQL critical paths cannot start on this host, or "" when Docker and the pinned image exist.
// It is a variable so a test can stand in for the host without a Docker daemon.
var criticalPGPresent = func(rc *runCtx) string {
	docker, err := exec.LookPath("docker")
	if err != nil {
		return "the HTTP/DB critical path starts a real PostgreSQL 16 container and this host has no docker on PATH"
	}
	if res := rc.exec(60*time.Second, rc.root, nil, docker, "image", "inspect", criticalPGImage); res.Exit != 0 {
		return "the HTTP/DB critical path needs the local PostgreSQL 16 image " + criticalPGImage + " and docker does not have it (it is never pulled)"
	}
	return ""
}

// criticalModes are the modes of fixtures/sdk/critical, the paths each one drives through a REAL `soundpost serve` (verified
// independently through the product's authenticated read routes, decision D8) and what each needs besides the row's pinned runner.
var criticalModes = map[string]struct {
	needsPG bool
	paths   string
}{
	"gateway": {false, "HTTP server span plus an outbound dependency call, handled errors, canary absence"},
	"jobs":    {false, "job attempts (explicit attempts and a real Celery worker for Python)"},
	"reducer": {false, "job reducer: late older run, retry, duplicate and reordered delivery against the product's job view"},
	"release": {false, "build artifacts: real Vite build, private artifact upload, independent read-back, release rename, restart"},
	"python":  {true, "HTTP server, database and errors through a real PostgreSQL 16 and the Python SDK"},
	"browser": {true, "real browser to Express to dependency to PostgreSQL 16 (HTTP, DB, errors)"},
}

type criticalResult struct {
	Rows []map[string]json.RawMessage `json:"rows"`
}

// criticalArgs maps one matrix row onto the committed command's flags: the pinned runner is the row's build, so the command is told to
// use exactly that interpreter, never another one found on PATH.
func (rc *runCtx) criticalArgs(spec RowSpec, p *probeResult) ([]string, string) {
	mode := spec.Params["mode"]
	path := rc.nativePath(p.Build.OS, p.Path)
	var needs = map[string]*probeResult{}
	for _, n := range spec.Needs {
		needs[rc.probe(n).Build.Family] = rc.probe(n)
	}
	switch mode {
	case "gateway", "reducer":
		if p.Build.Family != "bun" {
			return nil, "the " + mode + " critical path runs under the pinned Bun, and this row's build is " + p.Build.Family
		}
		return []string{"--mode", mode, "--bun", path}, ""
	case "release":
		if p.Build.Family != "node" {
			return nil, "the release critical path runs under the pinned Node, and this row's build is " + p.Build.Family
		}
		return []string{"--mode", "release", "--node", path}, ""
	case "jobs":
		switch p.Build.Family {
		case "bun":
			return []string{"--mode", "jobs", "--bun", path}, ""
		case "node":
			// The Node SDK sources are TypeScript: the pinned Bun bundles the job journey, the row's own Node runs it.
			bun := needs["bun"]
			if bun == nil {
				return nil, "the Node job-attempt path is bundled by the pinned Bun, and this row's needs name no Bun build"
			}
			return []string{"--mode", "jobs", "--node", path, "--bun", bun.Path}, ""
		}
		venv, why := pythonVenv(rc, p, jobsModules)
		if why != "" {
			return nil, why
		}
		return []string{"--mode", "jobs", "--python", pythonLabel(p) + "=" + venv}, ""
	case "python":
		venv, why := pythonVenv(rc, p, httpDBModules)
		if why != "" {
			return nil, why
		}
		return []string{"--mode", "python", "--python", pythonLabel(p) + "=" + venv}, ""
	case "browser":
		// A browser row runs its backend under the Node of its needs; a Node row runs the same path as the backend and takes the browser from
		// its needs. Either way the command is told every interpreter explicitly.
		node, browser, bun := needs["node"], p, needs["bun"]
		if p.Build.Family == "node" {
			node, browser = p, needs[strings.ToLower(spec.Params["target"])]
		}
		if node == nil || browser == nil || bun == nil {
			return nil, "the browser critical path needs a Node, a browser and a Bun build among the row's build and needs"
		}
		return []string{"--mode", "browser", "--browsers", spec.Params["target"] + "=" + rc.nativePath(browser.Build.OS, browser.Path), "--node", node.Path, "--bun", bun.Path}, ""
	}
	return nil, fmt.Sprintf("unknown critical-path mode %q", mode)
}

// Modules the committed Python fixtures import from the SDK integration lock (sdk/python/requirements-integrations.lock). A venv that
// was built from the development lock alone has none of them, and the fixture then dies on its import with the SDK blamed.
var (
	jobsModules   = []string{"celery", "kombu"}
	httpDBModules = []string{"httpx", "psycopg", "uvicorn", "starlette", "fastapi"}
)

// pythonVenv is the virtual environment root of a pinned Python build: the committed command runs <venv>/bin/python and the fixtures
// import the SDK's integration dependencies, so a bare system interpreter, or a venv without the integration lock installed, is not a
// qualified runner for them: both are reported as the missing prerequisite instead of running the command.
func pythonVenv(rc *runCtx, p *probeResult, modules []string) (string, string) {
	venv := filepath.Dir(filepath.Dir(p.Path))
	if _, err := os.Stat(filepath.Join(venv, "pyvenv.cfg")); err != nil {
		return "", fmt.Sprintf("the Python critical path needs a virtual environment (pyvenv.cfg) holding the SDK integration lock for %s, and %s is not inside one", p.Build.Version, p.Path)
	}
	probe := "import importlib.util, sys\nprint(' '.join(m for m in sys.argv[1:] if importlib.util.find_spec(m) is None))"
	res := rc.exec(60*time.Second, rc.root, nil, p.Path, append([]string{"-c", probe}, modules...)...)
	if res.Exit != 0 {
		return "", fmt.Sprintf("the pinned Python %s at %s could not be probed for the integration modules (exit %d)", p.Build.Version, p.Path, res.Exit)
	}
	if missing := strings.TrimSpace(res.Stdout); missing != "" {
		return "", fmt.Sprintf("the virtual environment of Python %s lacks %s: install the SDK integration lock (sdk/python/requirements-integrations.lock with --require-hashes) into it", p.Build.Version, strings.ReplaceAll(missing, " ", ", "))
	}
	return venv, ""
}

func pythonLabel(p *probeResult) string {
	parts := strings.SplitN(p.Build.Version, ".", 3)
	if len(parts) >= 2 {
		return parts[0] + "." + parts[1]
	}
	return p.Build.Version
}

// runSDKCriticalPath runs one mode of the committed critical-path command (fixtures/sdk/critical) against a real `soundpost serve` with
// the row's pinned runner, and is exercised only by what that command observed: exit 0, at least one row, and no row that reports a
// failing exit code. A host without the prerequisites (a Unix host, a Go toolchain, Docker with the PostgreSQL image for the database
// paths, a virtual environment for Python) reports the exact missing prerequisite as not exercised; it is never a pass.
func runSDKCriticalPath(rc *runCtx, spec RowSpec) Row {
	mode := spec.Params["mode"]
	m, ok := criticalModes[mode]
	if !ok {
		return notExercised(fmt.Sprintf("the matrix row names an unknown critical-path mode %q", mode))
	}
	p := rc.probe(spec.Build)
	if !p.Found {
		return notExercised(p.Reason)
	}
	if why := rc.needsMissing(spec); why != "" {
		return notExercised(why)
	}
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		return notExercised("the critical-path command runs on Unix hosts only (process groups)")
	}
	args, why := rc.criticalArgs(spec, p)
	if why != "" {
		return notExercised(why)
	}
	if m.needsPG {
		if why := criticalPGPresent(rc); why != "" {
			return notExercised(why)
		}
	}
	tool, why := rc.goBuild("critical", "./fixtures/sdk/critical")
	if why != "" {
		return notExercised(why)
	}
	product, why := rc.goBuild("soundpost-critical", "./cmd/soundpost")
	if why != "" {
		return notExercised(why)
	}
	_ = os.MkdirAll(filepath.Join(rc.root, ".tools"), 0o755)
	out := filepath.Join(rc.work, spec.ID+".json")
	full := append(append([]string{}, args...), "--binary", product, "--root", rc.root, "--out", out)
	res := rc.exec(40*time.Minute, rc.root, nil, tool, full...)
	row := Row{State: StateExercised, Build: &p.Build, Command: &CommandRun{Command: "critical " + strings.Join(args, " "), ExitCode: res.Exit, DurationMS: res.Duration.Milliseconds()}}
	row.Evidence = append(row.Evidence, fmt.Sprintf("fixtures/sdk/critical --mode %s against a real soundpost serve (fresh data directory per case), read back through the product's authenticated read routes (D8): %s", mode, m.paths))
	raw, readErr := os.ReadFile(out)
	if readErr == nil && len(raw) > 0 {
		row.Evidence = append(row.Evidence, rc.writeEvidence("critical-"+spec.ID+".json", raw))
	}
	if res.Exit != 0 {
		row.Outcome, row.Failures = OutcomeFailed, []string{fmt.Sprintf("critical --mode %s exited %d: %s", mode, res.Exit, tail(rc.rel(res.Stderr), 400))}
		return row
	}
	var result criticalResult
	if err := json.Unmarshal(raw, &result); err != nil || len(result.Rows) == 0 {
		row.Outcome, row.Failures = OutcomeFailed, []string{"critical exited 0 but wrote no rows: nothing was observed"}
		return row
	}
	for i, r := range result.Rows {
		if code, has := r["exit_code"]; has && strings.TrimSpace(string(code)) != "0" {
			row.Outcome, row.Failures = OutcomeFailed, []string{fmt.Sprintf("critical row %d reports exit_code %s", i, strings.TrimSpace(string(code)))}
			return row
		}
	}
	row.Series = []Series{{Name: "critical_rows_verified", Unit: "count", Values: []float64{float64(len(result.Rows))}}}
	row.Outcome = OutcomePassed
	row.Limits = []string{
		fmt.Sprintf("this row is the %s %s build only; every other runner is its own row", p.Build.Family, p.Build.Version),
		"local loopback product and a local HTTPS dependency stand in for the network; the paths are the committed fixtures', not a production workload",
	}
	if m.needsPG {
		row.Limits = append(row.Limits, "database: throwaway PostgreSQL 16 container started by the command from the local image "+criticalPGImage)
	}
	return row
}
