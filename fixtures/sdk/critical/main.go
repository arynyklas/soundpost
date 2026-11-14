//go:build unix

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

// Command critical runs only on Unix hosts (process groups, the PostgreSQL fixture).
//
// Command critical runs the SDK critical-path fixtures against a REAL `soundpost serve` and verifies the admitted
// records independently (decision D8: through the product's authenticated read routes, never through the SDK or
// private storage).
//
//	critical --mode python  --python 3.12=<venv>,3.13=<venv>,3.14=<venv>   fixtures/sdk/python/critical_path.py (real PostgreSQL 16 + HTTPS ingest)
//	critical --mode gateway --bun <bun>                                    fixtures/sdk/bun/gateway.ts (real HTTPS dependency)
//
// Every case gets a fresh product (fresh data directory) because the fixtures count project-wide records.
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/arynyklas/soundpost/fixtures/sdk/estate"
	"github.com/arynyklas/soundpost/fixtures/sdk/verifier"
	"github.com/arynyklas/soundpost/internal/model"
)

type env struct {
	binary, root, work, bun, pgImage string
}

func main() {
	var e env
	mode := flag.String("mode", "", "python | gateway")
	pythons := flag.String("python", "", "label=venv,label=venv")
	node := flag.String("node", "", "Linux Node 22 (browser mode backend and Playwright)")
	winNode := flag.String("win-node", "", "Windows node.exe (release mode: owns the installed Vite)")
	browsers := flag.String("browsers", "", "Target=executable,Target=executable (Chrome, Edge) for browser mode")
	flag.StringVar(&e.binary, "binary", "", "linux soundpost binary")
	flag.StringVar(&e.root, "root", ".", "repository root")
	flag.StringVar(&e.bun, "bun", "", "Linux Bun")
	flag.StringVar(&e.pgImage, "pg-image", "92620daddcd9", "LOCAL PostgreSQL 16 image (never pulled)")
	out := flag.String("out", "", "evidence JSON path")
	flag.Parse()
	var err error
	e.root, err = filepath.Abs(e.root)
	estate.Must(err, "root")
	e.work, err = os.MkdirTemp(filepath.Join(e.root, ".tools"), "critical-")
	estate.Must(err, "work")
	defer os.RemoveAll(e.work)
	var rows []map[string]any
	switch *mode {
	case "python":
		for _, p := range strings.Split(*pythons, ",") {
			label, venv, ok := strings.Cut(p, "=")
			if !ok {
				estate.Fail("--python wants label=venv")
			}
			rows = append(rows, e.python(label, venv))
		}
	case "gateway":
		rows = append(rows, e.gateway())
	case "release":
		rows = append(rows, e.release(*winNode))
	case "browser":
		for _, b := range strings.Split(*browsers, ",") {
			target, exe, ok := strings.Cut(b, "=")
			if !ok {
				estate.Fail("--browsers wants Target=executable")
			}
			rows = append(rows, e.browser(target, exe, *node))
		}
	default:
		estate.Fail("--mode python|gateway|browser|release")
	}
	raw, _ := json.MarshalIndent(map[string]any{"rows": rows}, "", "  ")
	fmt.Println(string(raw))
	if *out != "" {
		estate.Must(os.WriteFile(*out, append(raw, '\n'), 0o644), "evidence file")
	}
}

func (e *env) newEstate(name string) *estate.Estate {
	est := estate.New(estate.Options{Binary: e.binary, Work: filepath.Join(e.work, name), Kinds: []model.Kind{model.SpanKind, model.ErrorKind, model.Loss}, Name: name})
	est.Start()
	est.Provision()
	return est
}

// postgres starts a throwaway PostgreSQL container and returns its DSN and a remover keyed by the exact container ID.
func (e *env) postgres() (string, func()) {
	var rnd [12]byte
	_, _ = rand.Read(rnd[:])
	password := hex.EncodeToString(rnd[:])
	id, err := estate.RunOut("docker", "run", "-d", "--name", "soundpost-sdkfix-pg-"+hex.EncodeToString(rnd[:4]), "--tmpfs", "/var/lib/postgresql/data", "-p", "127.0.0.1::5432",
		"-e", "POSTGRES_PASSWORD="+password, "-e", "POSTGRES_DB=reference", e.pgImage)
	estate.Must(err, "start postgres")
	remove := func() { _, _ = estate.RunOut("docker", "rm", "-f", "-v", id) }
	estate.OnExit(remove)
	port, err := estate.RunOut("docker", "port", id, "5432/tcp")
	if err != nil {
		remove()
		estate.Fail("postgres port: %v", err)
	}
	port = port[strings.LastIndex(port, ":")+1:]
	for i := 0; ; i++ {
		if _, err := estate.RunOut("docker", "exec", id, "psql", "-U", "postgres", "-d", "reference", "-Atc", "select 1"); err == nil {
			break
		}
		if i > 120 {
			remove()
			estate.Fail("postgres did not become ready")
		}
		time.Sleep(300 * time.Millisecond)
	}
	return "postgresql://postgres:" + password + "@127.0.0.1:" + port + "/reference", remove
}

func (e *env) python(label, venv string) map[string]any {
	est := e.newEstate("python" + label)
	defer est.Close()
	dsn, removePG := e.postgres()
	defer removePG()
	version, _ := estate.RunOut(filepath.Join(venv, "bin", "python"), "--version")
	pgVersion, _ := estate.RunOut("docker", "ps", "--format", "{{.Image}}", "--filter", "ancestor="+e.pgImage)
	verifyURL, stop := verifier.Serve(est)
	defer stop()
	cfg := est.SDKConfig(est.Builds["main"], "fixture-1")
	cfg["ca_file"] = est.CA
	cfgPath := filepath.Join(e.work, "python"+label+".json")
	estate.WriteJSON(cfgPath, cfg)
	cmd := exec.Command(filepath.Join(venv, "bin", "python"), filepath.Join(e.root, "fixtures/sdk/python/critical_path.py"))
	cmd.Dir = e.root
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "PYTHONPATH=" + filepath.Join(e.root, "sdk/python/src") + ":" + filepath.Join(e.root, "fixtures/sdk/python"),
		"SOUNDPOST_FIXTURE_CONFIG=" + cfgPath, "SOUNDPOST_FIXTURE_INGEST=https://" + est.Addr + "/ingest/v1/batches", "SOUNDPOST_FIXTURE_VERIFY=" + verifyURL,
		"SOUNDPOST_FIXTURE_READ_CREDENTIAL=" + est.Reader, "SOUNDPOST_FIXTURE_PG_DSN=" + dsn, "SSL_CERT_FILE=" + est.CA, "PYTHONDONTWRITEBYTECODE=1"}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	runErr := cmd.Run()
	rc := 0
	if runErr != nil {
		rc = 1
		if ee, ok := runErr.(*exec.ExitError); ok {
			rc = ee.ExitCode()
		}
	}
	row := map[string]any{"fixture": "fixtures/sdk/python/critical_path.py", "python": version, "postgres_image": pgVersion, "exit_code": rc, "stdout": strings.TrimSpace(stdout.String()), "stderr": estate.Tail(stderr.String()), "verifier_route": "/api/v1/exports"}
	if rc != 0 {
		raw, _ := json.Marshal(row)
		fmt.Println(string(raw))
		estate.Fail("critical_path.py failed under %s", label)
	}
	return row
}

// dependency is a real HTTPS server standing in for the authorized model/HTTP dependency.
func (e *env) dependency(est *estate.Estate) (string, func()) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	estate.Must(err, "dependency listen")
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"fixture-completion","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"ok"}}]}`))
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second, TLSConfig: &tls.Config{Certificates: []tls.Certificate{est.TLSCertificate()}, MinVersion: tls.VersionTLS13}}
	go func() { _ = srv.ServeTLS(l, "", "") }()
	return "https://" + l.Addr().String() + "/v1/chat/completions", func() { _ = srv.Close() }
}

func (e *env) gateway() map[string]any {
	est := e.newEstate("gateway")
	defer est.Close()
	dependencyURL, stopDependency := e.dependency(est)
	defer stopDependency()
	cfg := est.SDKConfig(est.Builds["main"], "fixture-1")
	cfgPath := filepath.Join(e.work, "gateway.json")
	estate.WriteJSON(cfgPath, cfg)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	estate.Must(err, "gateway port")
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	cmd := exec.Command(e.bun, filepath.Join(e.root, "fixtures/sdk/bun/gateway.ts"))
	cmd.Dir = e.root
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "SOUNDPOST_FIXTURE_CONFIG=" + cfgPath, "SOUNDPOST_FIXTURE_INGEST=https://" + est.Addr + "/ingest/v1/batches",
		"SOUNDPOST_FIXTURE_DEPENDENCY_URL=" + dependencyURL, fmt.Sprintf("SOUNDPOST_FIXTURE_GATEWAY_PORT=%d", port), "NODE_EXTRA_CA_CERTS=" + est.CA}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	estate.Must(cmd.Start(), "start gateway")
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	deadline := time.Now().Add(30 * time.Second)
	for !strings.Contains(stdout.String(), "bun_real_dependency_gateway") {
		select {
		case err := <-done:
			estate.Fail("gateway exited early: %v: %s", err, estate.Tail(stderr.String()))
		default:
		}
		if time.Now().After(deadline) {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			estate.Fail("gateway did not start")
		}
		time.Sleep(100 * time.Millisecond)
	}
	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	const requests = 3
	for range requests {
		resp, err := http.Post(base+"/v1/chat/completions?CANARY_QUERY=1", "application/json", strings.NewReader(`{"model":"fixture","messages":[{"role":"user","content":"CANARY_PROMPT"}]}`))
		estate.Must(err, "gateway request")
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 || !strings.Contains(string(body), "fixture-completion") {
			estate.Fail("gateway answered %d: %s", resp.StatusCode, estate.Tail(string(body)))
		}
	}
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	var waitErr error
	select {
	case waitErr = <-done:
	case <-time.After(60 * time.Second):
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		estate.Fail("gateway did not close")
	}
	rc := 0
	if ee, ok := waitErr.(*exec.ExitError); ok {
		rc = ee.ExitCode()
	} else if waitErr != nil {
		rc = 1
	}
	if rc != 0 {
		estate.Fail("gateway close exit %d (pending or lost records): %s", rc, estate.Tail(stderr.String()))
	}
	// Independent read-back through the product's own authenticated route.
	records, err := verifier.Fetch(est, est.Reader, est.Org, est.Project)
	estate.Must(err, "verifier fetch")
	servers, calls := map[string]string{}, 0
	for _, r := range records {
		if r.Kind != "span" {
			continue
		}
		if r.Payload["span_kind"] == "server" && r.Payload["operation"] == "request" {
			servers[fmt.Sprint(r.Payload["span_id"])] = fmt.Sprint(r.Payload["trace_id"])
		}
	}
	for _, r := range records {
		if r.Kind == "span" && r.Payload["operation"] == "http.call" && r.Payload["dependency_alias"] == "dependency" && r.Payload["status"] == "ok" {
			if _, ok := servers[fmt.Sprint(r.Payload["parent_id"])]; ok {
				calls++
			}
		}
	}
	raw, _ := json.Marshal(records)
	if len(servers) != requests || calls != requests {
		estate.Fail("read-back found %d server spans and %d dependency calls under them, want %d each", len(servers), calls, requests)
	}
	if bytes.Contains(raw, []byte("CANARY_")) {
		estate.Fail("a canary reached the stored records")
	}
	version, _ := estate.RunOut(e.bun, "--version")
	return map[string]any{"fixture": "fixtures/sdk/bun/gateway.ts", "bun": version, "gateway_exit_code": rc, "requests": requests, "server_spans": len(servers), "dependency_calls_under_server_spans": calls,
		"records_read_back": len(records), "dependency": "real local HTTPS server (verified TLS), not an external model provider", "verifier_route": "/api/v1/exports"}
}

// browser is L4-P04 / 03.05-W2: a pinned real browser (Chrome 142 / Edge 142) -> Express -> real HTTPS dependency -> PostgreSQL 16
// against a real product, verified independently through the product's read route (decision D8).
func (e *env) browser(target, executable, node string) map[string]any {
	est := e.newEstate("browser" + strings.ToLower(target))
	defer est.Close()
	dsn, removePG := e.postgres()
	defer removePG()
	dependencyURL, stopDependency := e.dependency(est)
	defer stopDependency()
	verifyURL, stopVerifier := verifier.Serve(est)
	defer stopVerifier()
	freePort := func() int {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		estate.Must(err, "port")
		defer l.Close()
		return l.Addr().(*net.TCPAddr).Port
	}
	pagePort, foreignPort, backendPort := freePort(), freePort(), freePort()
	pageOrigin := fmt.Sprintf("https://127.0.0.1:%d", pagePort)
	// Backend (private source) and browser (write-only browser source) are separate sources with separate credentials.
	build := est.Builds["main"]
	backendConfig := filepath.Join(e.work, "backend-"+target+".json")
	estate.WriteJSON(backendConfig, est.SDKConfig(build, "fixture-1"))
	browserSource := est.ID("source/browser")
	browserCfg := est.SDKConfigFor(browserSource, est.Onboard(browserSource, true, []string{pageOrigin}), build, "fixture-2")
	browserCfg["sourceClass"] = "browser"
	page := filepath.Join(e.work, "page-"+target)
	estate.Must(os.MkdirAll(page, 0o755), "page dir")
	estate.WriteJSON(filepath.Join(page, "worker-config.json"), browserCfg)
	browserConfig := filepath.Join(e.work, "browser-"+target+".json")
	estate.WriteJSON(browserConfig, browserCfg)
	for _, b := range [][2]string{{"app.ts", "app.js"}, {"worker.ts", "worker.js"}} {
		if out, err := estate.RunOut(e.bun, "build", filepath.Join(e.root, "fixtures/sdk/browser", b[0]), "--target=browser", "--format=esm", "--outfile", filepath.Join(page, b[1])); err != nil {
			estate.Fail("bun build %s: %v: %s", b[0], err, estate.Tail(out))
		}
	}
	index, err := os.ReadFile(filepath.Join(e.root, "fixtures/sdk/browser/index.html"))
	estate.Must(err, "index.html")
	estate.Must(os.WriteFile(filepath.Join(page, "index.html"), index, 0o644), "index copy")
	pageServer := &http.Server{Addr: fmt.Sprintf("127.0.0.1:%d", pagePort), Handler: http.FileServer(http.Dir(page)), ReadHeaderTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{est.TLSCertificate()}, MinVersion: tls.VersionTLS13}}
	go func() { _ = pageServer.ListenAndServeTLS("", "") }()
	defer pageServer.Close()
	foreignHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		_, _ = w.Write([]byte("foreign-ok"))
	})
	foreignServer := &http.Server{Addr: fmt.Sprintf("127.0.0.1:%d", foreignPort), Handler: foreignHandler, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = foreignServer.ListenAndServe() }()
	defer foreignServer.Close()

	backendBundle := filepath.Join(e.work, "backend.mjs")
	if out, err := estate.RunOut(e.bun, "build", filepath.Join(e.root, "fixtures/sdk/node/critical-path.mjs"), "--target=node", "--outfile", backendBundle); err != nil {
		estate.Fail("bun build backend: %v: %s", err, estate.Tail(out))
	}
	backend := exec.Command(node, backendBundle, "--serve")
	backend.Dir = e.root
	backend.Env = []string{"PATH=" + os.Getenv("PATH"), "SOUNDPOST_FIXTURE_CONFIG=" + backendConfig, "SOUNDPOST_FIXTURE_WORKER_CONFIG=" + backendConfig, "SOUNDPOST_FIXTURE_INGEST=https://" + est.Addr + "/ingest/v1/batches",
		"SOUNDPOST_FIXTURE_CA_FILE=" + est.CA, "NODE_EXTRA_CA_CERTS=" + est.CA, "SOUNDPOST_FIXTURE_VERIFY=" + verifyURL, "SOUNDPOST_FIXTURE_READ_CREDENTIAL=" + est.Reader, "SOUNDPOST_FIXTURE_DATABASE_URL=" + dsn, "SOUNDPOST_FIXTURE_DEPENDENCY_URL=" + dependencyURL,
		fmt.Sprintf("SOUNDPOST_FIXTURE_NODE_PORT=%d", backendPort), "SOUNDPOST_FIXTURE_BROWSER_ORIGIN=" + pageOrigin}
	var backendOut, backendErr bytes.Buffer
	backend.Stdout, backend.Stderr = &backendOut, &backendErr
	backend.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	estate.Must(backend.Start(), "start backend")
	backendDone := make(chan error, 1)
	go func() { backendDone <- backend.Wait() }()
	deadline := time.Now().Add(30 * time.Second)
	for !strings.Contains(backendOut.String(), "node_browser_backend_ready") {
		select {
		case err := <-backendDone:
			estate.Fail("backend exited early: %v: %s", err, estate.Tail(backendErr.String()))
		default:
		}
		if time.Now().After(deadline) {
			_ = syscall.Kill(-backend.Process.Pid, syscall.SIGKILL)
			estate.Fail("backend did not start")
		}
		time.Sleep(100 * time.Millisecond)
	}
	var ready struct{ Origin, Runtime string }
	line := strings.TrimSpace(backendOut.String())
	estate.Must(json.Unmarshal([]byte(line[strings.LastIndex(line, "\n")+1:]), &ready), "backend ready line")
	if u, err := url.Parse(ready.Origin); err != nil || u.Host == "" {
		estate.Fail("backend origin invalid")
	}

	playwright := filepath.Join(e.root, "node_modules/.pnpm/@playwright+test@1.64.1/node_modules/@playwright/test/cli.js")
	pw := exec.Command(node, playwright, "test", "-c", filepath.Join(e.root, "fixtures/sdk/browser/playwright.config.ts"))
	pw.Dir = filepath.Join(e.root, "fixtures/sdk/browser")
	pw.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "NODE_PATH=" + filepath.Join(e.root, "node_modules/.pnpm/@playwright+test@1.64.1/node_modules"), "NODE_EXTRA_CA_CERTS=" + est.CA, "SOUNDPOST_FIXTURE_BROWSER_OUTPUT=" + filepath.Join(e.work, "pw-"+target),
		"SOUNDPOST_FIXTURE_BROWSER_EXECUTABLE=" + executable, "SOUNDPOST_FIXTURE_BROWSER_SPKI=" + est.LeafSPKIPin(), "SOUNDPOST_FIXTURE_BROWSER_TARGET=" + target,
		"SOUNDPOST_FIXTURE_BROWSER_URL=" + pageOrigin + "/index.html", "SOUNDPOST_FIXTURE_BACKEND_URL=" + ready.Origin, fmt.Sprintf("SOUNDPOST_FIXTURE_FOREIGN_URL=http://127.0.0.1:%d/foreign", foreignPort),
		"SOUNDPOST_FIXTURE_BROWSER_CONFIG=" + browserConfig, "SOUNDPOST_FIXTURE_VERIFY=" + verifyURL, "SOUNDPOST_FIXTURE_READ_CREDENTIAL=" + est.Reader}
	var pwOut bytes.Buffer
	pw.Stdout, pw.Stderr = &pwOut, &pwOut
	pwErr := pw.Run()
	_ = syscall.Kill(-backend.Process.Pid, syscall.SIGTERM)
	var backendExit error
	select {
	case backendExit = <-backendDone:
	case <-time.After(60 * time.Second):
		_ = syscall.Kill(-backend.Process.Pid, syscall.SIGKILL)
		backendExit = fmt.Errorf("backend did not close")
	}
	row := map[string]any{"fixture": "fixtures/sdk/browser/critical-path.spec.ts", "target": target, "backend_runtime": ready.Runtime, "postgres_image": e.pgImage, "verifier_route": "/api/v1/exports", "playwright": estate.Tail(pwOut.String())}
	if pwErr != nil || backendExit != nil {
		fmt.Fprintln(os.Stderr, pwOut.String())
		raw, _ := json.Marshal(row)
		fmt.Println(string(raw))
		estate.Fail("browser critical path failed under %s (playwright %v, backend close %v): %s", target, pwErr, backendExit, estate.Tail(backendErr.String()))
	}
	return row
}

func wslWindows(path string) string {
	out, err := estate.RunOut("wslpath", "-w", path)
	estate.Must(err, "wslpath")
	return out
}

// release is 03.06-W1: fixtures/sdk/releases/build-and-verify.mjs (real Vite build, real private artifact upload, independent
// authenticated read-back, negatives, release rename) against a real product, then again after a server restart.
func (e *env) release(winNode string) map[string]any {
	if winNode == "" {
		estate.Fail("--win-node is required in release mode")
	}
	est := estate.New(estate.Options{Binary: e.binary, Work: filepath.Join(e.work, "release"), Kinds: []model.Kind{model.SpanKind}, Builds: []string{"main", "renamed"}, Name: "release"})
	defer est.Close()
	est.Start()
	est.Provision()
	receiptFile := filepath.Join(e.work, "release-receipt.json")
	names := []string{"SOUNDPOST_FIXTURE_API", "SOUNDPOST_FIXTURE_ORG", "SOUNDPOST_FIXTURE_PROJECT", "SOUNDPOST_FIXTURE_SOURCE", "SOUNDPOST_FIXTURE_BUILD", "SOUNDPOST_FIXTURE_BUILD_RENAMED",
		"SOUNDPOST_FIXTURE_ARTIFACT_WRITE_CREDENTIAL", "SOUNDPOST_FIXTURE_ARTIFACT_READ_CREDENTIAL", "NODE_EXTRA_CA_CERTS"}
	run := func(extra ...string) (string, string) {
		cmd := exec.Command(winNode, append([]string{wslWindows(filepath.Join(e.root, "fixtures/sdk/releases/build-and-verify.mjs")), "--endpoint-env", "SOUNDPOST_FIXTURE_API"}, extra...)...)
		cmd.Env = append(os.Environ(), "SOUNDPOST_FIXTURE_API=https://"+est.Addr, "SOUNDPOST_FIXTURE_ORG="+est.Org.String(), "SOUNDPOST_FIXTURE_PROJECT="+est.Project.String(), "SOUNDPOST_FIXTURE_SOURCE="+est.Source.String(),
			"SOUNDPOST_FIXTURE_BUILD="+est.Builds["main"].String(), "SOUNDPOST_FIXTURE_BUILD_RENAMED="+est.Builds["renamed"].String(), "SOUNDPOST_FIXTURE_ARTIFACT_WRITE_CREDENTIAL="+est.WriteToken,
			"SOUNDPOST_FIXTURE_ARTIFACT_READ_CREDENTIAL="+est.ArtifactRead, "NODE_EXTRA_CA_CERTS="+wslWindows(est.CA), "WSLENV="+strings.Join(names, ":"))
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		if err := cmd.Run(); err != nil {
			estate.Fail("build-and-verify %v: %v: %s %s", extra, err, estate.Tail(stdout.String()), estate.Tail(stderr.String()))
		}
		return strings.TrimSpace(stdout.String()), strings.TrimSpace(stderr.String())
	}
	built, _ := run("--receipt-out", wslWindows(receiptFile))
	est.Stop()
	est.Start()
	restarted, _ := run("--verify-receipt", wslWindows(receiptFile))
	return map[string]any{"fixture": "fixtures/sdk/releases/build-and-verify.mjs", "build_upload_read": json.RawMessage(built), "after_restart": json.RawMessage(restarted), "route": "/api/v1/artifacts"}
}
