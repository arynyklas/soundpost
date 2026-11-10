// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"math"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"soundpost/internal/auth"
	"soundpost/internal/model"
	"soundpost/internal/query"
	"soundpost/profiles"
	"strings"
	"sync"
	"syscall"
	"time"
)

// RunInstallSingle drives the PRODUCED distribution as a real installation: either the static
// binary build/release.go made (--binary, a real subprocess; never `go run`) or the image
// built from deploy/Dockerfile (--container, a real container). It bootstraps through the HTTP
// API, ingests every signal the committed smokes ingest (float and integer-histogram metric, log,
// error, span) over real authenticated HTTPS, runs a real PromQL query, fetches the embedded UI
// assets, then force-kills and restarts and requires the SAME original receipts and query result.
// Both starts are held by --startup-hold-file so the process listens but has not opened
// storage; in that window `ready` and /readyz must say not ready and intake must not acknowledge.
// Registered as: case "install-single": return RunInstallSingle(os.Args[2:]).
func RunInstallSingle(args []string) (result error) {
	stage := "install_flags"
	defer func() { result = annotateSmokeFailure("install_single", stage, model.ID{}, result) }()
	f := flag.NewFlagSet("install-single", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	artifact := f.String("artifact-dir", "", "sanitized result directory")
	binary := f.String("binary", "", "produced static soundpost binary")
	release := f.String("release", "", "release directory (SHA256SUMS and release.json) the binary must belong to")
	container := f.String("container", "", "image built from deploy/Dockerfile (instead of --binary)")
	webDist := f.String("web-dist", "", "built UI bundle the served assets must equal (default web/dist when present)")
	if err := f.Parse(args); err != nil {
		return err
	}
	if *artifact == "" || (*binary == "") == (*container == "") {
		return errors.New("--artifact-dir and exactly one of --binary or --container are required")
	}
	if err := os.MkdirAll(*artifact, 0o700); err != nil {
		return err
	}
	if *webDist == "" {
		if _, err := os.Stat("web/dist/index.html"); err == nil {
			*webDist = "web/dist"
		}
	}
	report := map[string]any{"version": 1}

	var host installHost
	var err error
	if *binary != "" {
		stage = "install_binary_identity"
		if host, err = newBinaryHost(*binary, *release, report); err != nil {
			return err
		}
	} else {
		stage = "install_container_identity"
		if host, err = newContainerHost(*container, report); err != nil {
			return err
		}
	}
	defer host.cleanup()

	stage = "install_first_start_held"
	run, err := host.start()
	if err != nil {
		return err
	}
	defer run.kill()
	cert, err := run.waitCertificate()
	if err != nil {
		return err
	}
	site := newInstallSite(run.url(), cert)
	if err = requireHeldNotReady(run, site, report, "first"); err != nil {
		return err
	}
	if err = run.release(); err != nil {
		return err
	}
	stage = "install_first_ready"
	if err = run.waitReady(60 * time.Second); err != nil {
		return err
	}

	stage = "install_no_default_access"
	if err = requireNoDefaultAccess(site, report); err != nil {
		return err
	}
	stage = "install_bootstrap"
	token, err := run.bootstrapToken()
	if err != nil {
		return err
	}
	fx, err := bootstrapInstallation(site, token)
	if err != nil {
		return err
	}
	stage = "install_ingest"
	receipts, err := ingestEverySignal(site, fx)
	if err != nil {
		return err
	}
	report["signals_ingested"] = []string{"metric_float", "metric_integer_histogram", "log", "error", "span"}
	stage = "install_query"
	queryBefore, err := queryInstalled(site, fx)
	if err != nil {
		return err
	}
	stage = "install_ui"
	if err = fetchUIAssets(site, *webDist, report); err != nil {
		return err
	}
	stage = "install_ready_with_data"
	if status, err := run.readyOnce(); err != nil || !status.Ready || status.Applied == nil || status.Applied.Index == 0 || status.Version == "" {
		return fmt.Errorf("a node holding acknowledged data is not ready with a cursor: %+v %v", status, err)
	}

	// An unconditional force kill after the observed ACKs, then a held restart.
	stage = "install_kill"
	if err = run.kill(); err != nil {
		return err
	}
	stage = "install_second_start_held"
	run, err = host.start()
	if err != nil {
		return err
	}
	defer run.kill()
	if _, err = run.waitCertificate(); err != nil {
		return err
	}
	site.base = run.url() // the same installation, possibly on a new published port
	if err = requireHeldNotReady(run, site, report, "restart"); err != nil {
		return err
	}
	// While storage is closed, a retry of an acknowledged batch must not be answered.
	stage = "install_no_ack_before_recovery"
	status, raw, err := site.ingest(receipts[0].batch, fx.credential)
	if err == nil && status == 200 {
		return &smokeFailure{Stage: stage, Code: "acknowledged_before_recovery"}
	}
	if err == nil && status != 503 {
		return httpSmokeFailure("no_ack_before_recovery", status, 503, raw)
	}
	report["restart_intake_before_recovery_status"] = 503
	if err = run.release(); err != nil {
		return err
	}
	stage = "install_second_ready"
	if err = run.waitReady(60 * time.Second); err != nil {
		return err
	}

	stage = "install_same_receipts"
	for i, r := range receipts {
		status, raw, err := site.ingest(r.batch, fx.credential)
		if err = requireSmokeResponse("retry_"+r.name, status, 200, raw, err); err != nil {
			return err
		}
		var again model.Receipt
		if err = json.Unmarshal(raw, &again); err != nil {
			return err
		}
		before, _ := model.CanonicalJSON(r.receipt)
		after, _ := model.CanonicalJSON(again)
		if !bytes.Equal(before, after) {
			return &smokeFailure{Stage: stage, Code: "receipt_changed", Actual: i}
		}
		status, raw, err = site.receipt(r.batch, r.receipt, fx.credential)
		if err = requireSmokeResponse("historical_"+r.name, status, 200, raw, err); err != nil {
			return err
		}
		var historical model.Receipt
		if err = json.Unmarshal(raw, &historical); err != nil || !historical.Historical {
			return &smokeFailure{Stage: stage, Code: "historical_marker"}
		}
		historical.Historical = false
		after, _ = model.CanonicalJSON(historical)
		if !bytes.Equal(before, after) {
			return &smokeFailure{Stage: stage, Code: "historical_receipt_changed", Actual: i}
		}
	}
	report["original_receipts_after_restart"] = len(receipts)
	stage = "install_same_query"
	queryAfter, err := queryInstalled(site, fx)
	if err != nil {
		return err
	}
	if !bytes.Equal(queryBefore, queryAfter) {
		return &smokeFailure{Stage: stage, Code: "query_changed_across_restart"}
	}
	report["query_identical_after_restart"] = true

	stage = "install_graceful_stop"
	if err = run.stop(); err != nil {
		return err
	}
	stage = "install_private_modes"
	if err = host.checkPrivateModes(report); err != nil {
		return err
	}
	stage = "install_log_hygiene"
	if err = host.checkLogs([]string{fx.credential, fx.password, "install smoke reader password 2026", fx.session.Token, fx.session.CSRF, fx.reader.Token, fx.reader.CSRF}); err != nil {
		return err
	}
	report["server_log_free_of_credentials"] = true
	stage = "install_artifact"
	encoded, _ := json.MarshalIndent(report, "", "  ")
	return os.WriteFile(filepath.Join(*artifact, "install-single.json"), encoded, 0o600)
}

// ---- hosts: the produced binary as a subprocess, or the image as a container ----

type installHost interface {
	start() (installRun, error)
	checkPrivateModes(report map[string]any) error
	checkLogs(secrets []string) error
	cleanup()
}

type installRun interface {
	url() string
	waitCertificate() (*x509.Certificate, error)
	release() error // lets the startup hold go: storage opens
	waitReady(time.Duration) error
	readyOnce() (installReadiness, error)
	bootstrapToken() (string, error)
	kill() error
	stop() error
}

type installReadiness struct {
	Ready   bool           `json:"ready"`
	Reason  string         `json:"reason"`
	Version string         `json:"version"`
	Applied *model.Cursor  `json:"applied_cursor"`
	Code    int            `json:"-"`
	Raw     map[string]any `json:"-"`
}

func requireHeldNotReady(run installRun, site *installSite, report map[string]any, which string) error {
	// The process answers while storage is closed; it neither refuses the connection nor
	// claims readiness, and the `ready` command exits non-zero with the closed reason.
	deadline := time.Now().Add(30 * time.Second)
	var status installReadiness
	var err error
	for time.Now().Before(deadline) {
		if status, err = run.readyOnce(); err == nil && !status.Ready && status.Reason == "startup_hold" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil || status.Ready || status.Reason != "startup_hold" || status.Version != "" || status.Applied != nil {
		return &smokeFailure{Stage: "held_" + which + "_ready_command", Code: "not_unready_before_recovery"}
	}
	code, raw, err := site.get("/readyz")
	if err != nil || code != 503 || !bytes.Contains(raw, []byte(`"reason":"startup_hold"`)) || bytes.Contains(raw, []byte(`"version"`)) {
		return &smokeFailure{Stage: "held_" + which + "_readyz", Code: "readyz_before_recovery", Actual: code, Expected: 503}
	}
	if code, _, err = site.get("/"); err != nil || code != 503 {
		return &smokeFailure{Stage: "held_" + which + "_ui", Code: "ui_before_recovery", Actual: code, Expected: 503}
	}
	report["unready_reason_"+which] = "startup_hold"
	return nil
}

// ---- binary host ----

type binaryHost struct {
	path, dir, holdDir string
	logs               *syncBuffer
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.b.Len() < 1<<20 {
		s.b.Write(p)
	}
	return len(p), nil
}
func (s *syncBuffer) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func installStaticELF(path string) (bool, error) {
	f, err := elf.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP || p.Type == elf.PT_DYNAMIC {
			return false, nil
		}
	}
	libs, err := f.ImportedLibraries()
	return err == nil && len(libs) == 0, nil
}

func fileSHA256(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func newBinaryHost(path, release string, report map[string]any) (installHost, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	static, err := installStaticELF(abs)
	if err != nil || !static {
		return nil, &smokeFailure{Stage: "binary_static", Code: "not_static_elf"}
	}
	sum, err := fileSHA256(abs)
	if err != nil {
		return nil, err
	}
	if release != "" {
		sums, err := os.ReadFile(filepath.Join(release, "SHA256SUMS"))
		if err != nil {
			return nil, err
		}
		found := false
		for _, line := range strings.Split(string(sums), "\n") {
			if strings.HasPrefix(line, sum+"  ") && strings.HasSuffix(line, "/soundpost") {
				found = true
			}
		}
		if !found {
			return nil, &smokeFailure{Stage: "binary_release_sums", Code: "binary_not_in_release"}
		}
		report["release_sums_contain_binary"] = true
	}
	out, err := exec.Command(abs, "version", "--json").Output()
	if err != nil {
		return nil, err
	}
	var v struct {
		Version, Commit, BuildID string
		UIEmbedded               bool `json:"ui_embedded"`
		Platform                 string
	}
	if json.Unmarshal(out, &v) != nil {
		return nil, &smokeFailure{Stage: "binary_version", Code: "decode"}
	}
	if !v.UIEmbedded {
		return nil, &smokeFailure{Stage: "binary_version", Code: "ui_not_embedded"}
	}
	report["binary_sha256"], report["binary_version"], report["binary_platform"] = sum, v.Version, v.Platform
	dir, err := os.MkdirTemp("", "soundpost-install-")
	if err != nil {
		return nil, err
	}
	hold, err := os.MkdirTemp("", "soundpost-hold-")
	if err != nil {
		return nil, err
	}
	return &binaryHost{path: abs, dir: dir, holdDir: hold, logs: &syncBuffer{}}, nil
}

func (h *binaryHost) cleanup() { os.RemoveAll(h.dir); os.RemoveAll(h.holdDir) }

func freeAddress() (string, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	defer l.Close()
	return l.Addr().String(), nil
}

type binaryRun struct {
	host  *binaryHost
	cmd   *exec.Cmd
	addr  string
	hold  string
	done  chan error
	state sync.Once
}

func (h *binaryHost) start() (installRun, error) {
	addr, err := freeAddress()
	if err != nil {
		return nil, err
	}
	hold := filepath.Join(h.holdDir, fmt.Sprintf("hold-%d", time.Now().UnixNano()))
	cmd := exec.Command(h.path, "serve", "--mode=single", "--data-dir", h.dir, "--listen", addr, "--startup-hold-file", hold)
	cmd.Stdout, cmd.Stderr = h.logs, h.logs
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	if err = cmd.Start(); err != nil {
		return nil, err
	}
	run := &binaryRun{host: h, cmd: cmd, addr: addr, hold: hold, done: make(chan error, 1)}
	go func() { run.done <- cmd.Wait() }()
	return run, nil
}

func (r *binaryRun) url() string { return "https://" + r.addr }

func (r *binaryRun) waitCertificate() (*x509.Certificate, error) {
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-r.done:
			r.done <- err
			return nil, &smokeFailure{Stage: "server_start", Code: "exited_before_listening"}
		default:
		}
		if raw, err := os.ReadFile(filepath.Join(r.host.dir, "server.crt")); err == nil {
			if block, _ := pem.Decode(raw); block != nil {
				if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
					if c, err := net.DialTimeout("tcp", r.addr, time.Second); err == nil {
						c.Close()
						return cert, nil
					}
				}
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	return nil, &smokeFailure{Stage: "server_start", Code: "timeout"}
}

func (r *binaryRun) release() error { return os.WriteFile(r.hold, nil, 0o600) }

func (r *binaryRun) readyOnce() (installReadiness, error) {
	cmd := exec.Command(r.host.path, "ready", "--json", "--url", r.url(), "--data-dir", r.host.dir, "--timeout", "5s")
	out, err := cmd.Output()
	var st installReadiness
	if json.Unmarshal(out, &st) != nil {
		return st, &smokeFailure{Stage: "ready_command", Code: "decode"}
	}
	var exit *exec.ExitError
	switch {
	case err == nil:
		st.Code = 0
	case errors.As(err, &exit):
		st.Code = exit.ExitCode()
	default:
		return st, err
	}
	// Exit status 0 exactly when ready.
	if (st.Code == 0) != st.Ready {
		return st, &smokeFailure{Stage: "ready_command", Code: "exit_code_disagrees_with_answer"}
	}
	return st, nil
}

func (r *binaryRun) waitReady(limit time.Duration) error {
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if st, err := r.readyOnce(); err == nil && st.Ready {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return &smokeFailure{Stage: "server_ready", Code: "timeout"}
}

func (r *binaryRun) bootstrapToken() (string, error) {
	raw, err := os.ReadFile(filepath.Join(r.host.dir, "bootstrap.token"))
	return string(raw), err
}

func (r *binaryRun) kill() error {
	var err error
	r.state.Do(func() {
		_ = r.cmd.Process.Kill()
		<-r.done
	})
	return err
}

func (r *binaryRun) stop() error {
	if err := r.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		return err
	}
	var once error
	r.state.Do(func() {
		select {
		case err := <-r.done:
			once = err
		case <-time.After(20 * time.Second):
			_ = r.cmd.Process.Kill()
			<-r.done
			once = &smokeFailure{Stage: "graceful_stop", Code: "timeout"}
		}
	})
	return once
}

func (h *binaryHost) checkPrivateModes(report map[string]any) error {
	files := 0
	err := filepath.WalkDir(h.dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Mode().Perm()&0o077 != 0 {
			return &smokeFailure{Stage: "private_modes", Code: "group_or_other_access"}
		}
		files++
		return nil
	})
	report["private_mode_entries_checked"] = files
	return err
}

func (h *binaryHost) checkLogs(secrets []string) error {
	log := h.logs.String()
	for _, s := range secrets {
		if s != "" && strings.Contains(log, s) {
			return &smokeFailure{Stage: "log_hygiene", Code: "credential_in_server_log"}
		}
	}
	return nil
}

// ---- container host ----

type containerHost struct {
	image, name, volume, holdDir string
}

func dockerOut(args ...string) ([]byte, error) {
	cmd := exec.Command("docker", args...)
	var errOut bytes.Buffer
	cmd.Stderr = &errOut
	out, err := cmd.Output()
	if err != nil {
		return out, fmt.Errorf("docker %s: %w", args[0], err)
	}
	return out, nil
}

func newContainerHost(image string, report map[string]any) (installHost, error) {
	if out, err := dockerOut("image", "inspect", "--format", "{{.Config.User}} {{.Id}}", image); err != nil || !strings.HasPrefix(string(out), "65532:65532 ") {
		return nil, &smokeFailure{Stage: "container_identity", Code: "image_not_nonroot"}
	}
	report["container_user"] = "65532:65532"
	hold, err := os.MkdirTemp("", "soundpost-hold-")
	if err != nil {
		return nil, err
	}
	if err = os.Chmod(hold, 0o755); err != nil { // the container user must be able to stat the sentinel
		return nil, err
	}
	suffix := fmt.Sprint(time.Now().UnixNano())
	return &containerHost{image: image, name: "soundpost-install-" + suffix, volume: "soundpost-install-" + suffix, holdDir: hold}, nil
}

func (h *containerHost) cleanup() {
	_ = exec.Command("docker", "rm", "-f", h.name).Run()
	_ = exec.Command("docker", "volume", "rm", "-f", h.volume).Run()
	os.RemoveAll(h.holdDir)
}

type containerRun struct {
	host *containerHost
	hold string
	port string
}

func (h *containerHost) start() (installRun, error) {
	_ = exec.Command("docker", "rm", "-f", h.name).Run()
	hold := filepath.Join(h.holdDir, fmt.Sprintf("hold-%d", time.Now().UnixNano()))
	args := []string{"run", "-d", "--name", h.name, "--user", "65532:65532", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--pids-limit", "512",
		"--tmpfs", "/tmp:size=64m,mode=0700,uid=65532,gid=65532", "-p", "127.0.0.1::8443", "-v", h.volume + ":/var/lib/soundpost", "-v", h.holdDir + ":/hold:ro",
		h.image, "serve", "--mode=single", "--data-dir=/var/lib/soundpost", "--listen=0.0.0.0:8443", "--startup-hold-file=/hold/" + filepath.Base(hold)}
	if _, err := dockerOut(args...); err != nil {
		return nil, err
	}
	out, err := dockerOut("port", h.name, "8443/tcp")
	if err != nil {
		return nil, err
	}
	line := strings.TrimSpace(strings.Split(string(out), "\n")[0])
	_, port, err := net.SplitHostPort(line)
	if err != nil {
		return nil, err
	}
	return &containerRun{host: h, hold: hold, port: port}, nil
}

func (r *containerRun) url() string { return "https://127.0.0.1:" + r.port }

func (r *containerRun) copyOut(path string) ([]byte, error) {
	out, err := dockerOut("cp", r.host.name+":"+path, "-")
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(bytes.NewReader(out))
	if _, err = tr.Next(); err != nil {
		return nil, err
	}
	return io.ReadAll(tr)
}

func (r *containerRun) waitCertificate() (*x509.Certificate, error) {
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if raw, err := r.copyOut("/var/lib/soundpost/server.crt"); err == nil {
			if block, _ := pem.Decode(raw); block != nil {
				if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
					if c, err := net.DialTimeout("tcp", "127.0.0.1:"+r.port, time.Second); err == nil {
						c.Close()
						return cert, nil
					}
				}
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil, &smokeFailure{Stage: "container_start", Code: "timeout"}
}

func (r *containerRun) release() error { return os.WriteFile(r.hold, nil, 0o600) }

func (r *containerRun) readyOnce() (installReadiness, error) {
	cmd := exec.Command("docker", "exec", r.host.name, "/soundpost", "ready", "--json", "--data-dir", "/var/lib/soundpost", "--timeout", "5s")
	out, err := cmd.Output()
	var st installReadiness
	if json.Unmarshal(out, &st) != nil {
		return st, &smokeFailure{Stage: "ready_command", Code: "decode"}
	}
	var exit *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exit):
		st.Code = exit.ExitCode()
	default:
		return st, err
	}
	if (st.Code == 0) != st.Ready {
		return st, &smokeFailure{Stage: "ready_command", Code: "exit_code_disagrees_with_answer"}
	}
	return st, nil
}

func (r *containerRun) waitReady(limit time.Duration) error {
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if st, err := r.readyOnce(); err == nil && st.Ready {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return &smokeFailure{Stage: "server_ready", Code: "timeout"}
}

func (r *containerRun) bootstrapToken() (string, error) {
	raw, err := r.copyOut("/var/lib/soundpost/bootstrap.token")
	return string(raw), err
}

func (r *containerRun) kill() error {
	_, err := dockerOut("kill", r.host.name)
	if err != nil {
		return nil // already stopped
	}
	return nil
}

func (r *containerRun) stop() error {
	if _, err := dockerOut("stop", "--time", "25", r.host.name); err != nil {
		return err
	}
	out, err := dockerOut("inspect", "--format", "{{.State.ExitCode}}", r.host.name)
	if err != nil || strings.TrimSpace(string(out)) != "0" {
		return &smokeFailure{Stage: "graceful_stop", Code: "nonzero_exit"}
	}
	return nil
}

func (h *containerHost) checkPrivateModes(report map[string]any) error {
	out, err := dockerOut("cp", h.name+":/var/lib/soundpost/.", "-")
	if err != nil {
		return err
	}
	tr := tar.NewReader(bytes.NewReader(out))
	entries := 0
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if header.Mode&0o077 != 0 || header.Uid != 65532 || header.Gid != 65532 {
			return &smokeFailure{Stage: "private_modes", Code: "group_or_other_access_or_wrong_owner"}
		}
		entries++
	}
	report["private_mode_entries_checked"] = entries
	return nil
}

func (h *containerHost) checkLogs(secrets []string) error {
	out, err := exec.Command("docker", "logs", h.name).CombinedOutput()
	if err != nil {
		return err
	}
	for _, s := range secrets {
		if s != "" && strings.Contains(string(out), s) {
			return &smokeFailure{Stage: "log_hygiene", Code: "credential_in_server_log"}
		}
	}
	return nil
}

// ---- HTTPS client against the installed server ----

type installSite struct {
	base   string
	client *http.Client
}

func newInstallSite(base string, cert *x509.Certificate) *installSite {
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	jar, _ := cookiejar.New(nil)
	return &installSite{base: base, client: &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}, DisableKeepAlives: true}, Jar: jar, Timeout: 20 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func (s *installSite) do(req *http.Request) (int, []byte, http.Header, error) {
	resp, err := s.client.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	return resp.StatusCode, raw, resp.Header, err
}

func (s *installSite) get(path string) (int, []byte, error) {
	req, err := http.NewRequest("GET", s.base+path, nil)
	if err != nil {
		return 0, nil, err
	}
	status, raw, _, err := s.do(req)
	return status, raw, err
}

func (s *installSite) post(path string, body any, csrf, bearer string) (int, []byte, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return 0, nil, err
	}
	req, err := http.NewRequest("POST", s.base+path, bytes.NewReader(raw))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	client := s.client
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
		copyClient := *client
		copyClient.Jar = nil
		client = &copyClient
	} else {
		req.Header.Set("Origin", s.base)
		req.Header.Set("X-CSRF-Token", csrf)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	return resp.StatusCode, out, err
}

func (s *installSite) ingest(batch model.Batch, credential string) (int, []byte, error) {
	return s.post("/ingest/v1/batches", batch, "", credential)
}

func (s *installSite) receipt(batch model.Batch, original model.Receipt, credential string) (int, []byte, error) {
	return s.post("/ingest/v1/receipts", model.ReceiptRequest{Source: batch.Source, Producer: batch.Producer, RouteSlot: batch.RouteSlot, BatchID: original.BatchID, OriginalHash: original.Hash}, "", credential)
}

// ---- scenario ----

type installFixture struct {
	session                     auth.Session
	org, project, source        model.ID
	credential                  string
	password, readerEmail       string
	reader                      auth.Session
	service, environment, build model.ID
	queryTime                   string
}

func requireNoDefaultAccess(site *installSite, report map[string]any) error {
	// No default account: guessed credentials, unauthenticated reads and anonymous ingest all fail.
	for _, guess := range []struct{ email, password string }{{"admin@example.com", "admin"}, {"admin", "admin"}, {"soundpost", "soundpost"}, {"root", "password"}} {
		status, _, err := site.post("/api/v1/login", map[string]string{"Email": guess.email, "Password": guess.password, "Code": ""}, "", "")
		if err != nil || status == 200 {
			return &smokeFailure{Stage: "default_access", Code: "default_credentials_accepted"}
		}
	}
	if status, _, err := site.post("/ingest/v1/batches", json.RawMessage(`{}`), "", ""); err != nil || status == 200 {
		return &smokeFailure{Stage: "default_access", Code: "anonymous_ingest"}
	}
	if status, _, err := site.post("/api/v1/bootstrap", map[string]string{"Token": "not-the-token", "Email": "attacker@example.test", "Password": "attacker password 2026"}, "", ""); err != nil || status == 200 {
		return &smokeFailure{Stage: "default_access", Code: "bootstrap_with_guessed_token"}
	}
	report["default_credentials_rejected"] = true
	return nil
}

func bootstrapInstallation(site *installSite, token string) (*installFixture, error) {
	fx := &installFixture{}
	fx.password = "install smoke owner password 2026"
	status, raw, err := site.post("/api/v1/bootstrap", map[string]string{"Token": token, "Email": "owner@install-smoke.invalid", "Password": fx.password}, "", "")
	if err = requireSmokeResponse("bootstrap", status, 200, raw, err); err != nil {
		return fx, err
	}
	if err = json.Unmarshal(raw, &fx.session); err != nil {
		return fx, err
	}
	fx.org, fx.project, fx.source = model.NewID(), model.NewID(), model.NewID()
	admin := func(kind string, p auth.AdminPayload) error {
		status, raw, err := site.post("/api/v1/admin/read", struct {
			Kind string `json:"kind"`
		}{"organizations"}, fx.session.CSRF, "")
		if err = requireSmokeResponse("admin_read", status, 200, raw, err); err != nil {
			return err
		}
		var view auth.AdminView
		if err = json.Unmarshal(raw, &view); err != nil {
			return err
		}
		p.Reason = "install smoke"
		payload, _ := json.Marshal(p)
		status, raw, err = site.post("/api/v1/admin/commands", auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: view.Revision, OrgID: fx.org, Kind: kind, Payload: payload}, fx.session.CSRF, "")
		return requireSmokeResponse("admin_"+kind, status, 200, raw, err)
	}
	reader := model.NewID()
	fx.readerEmail = "reader@install-smoke.invalid"
	for _, step := range []struct {
		kind string
		p    auth.AdminPayload
	}{
		{"create_org", auth.AdminPayload{Name: "install smoke"}},
		{"create_project", auth.AdminPayload{ID: fx.project, Name: "install smoke"}},
		{"create_user", auth.AdminPayload{ID: reader, Email: fx.readerEmail, Password: "install smoke reader password 2026"}},
		{"membership", auth.AdminPayload{UserID: reader, Enabled: true}},
		{"grant", auth.AdminPayload{UserID: reader, ProjectID: fx.project, Enabled: true, Permissions: []string{string(auth.Read)}}},
	} {
		if err = admin(step.kind, step.p); err != nil {
			return fx, err
		}
	}
	fx.service, fx.environment, fx.build = model.NewID(), model.NewID(), model.NewID()
	var approved model.Scalar
	_ = json.Unmarshal([]byte(`503`), &approved)
	policy := model.SourcePolicy{Revision: 1, Enabled: true, Class: "structured", Kinds: []model.Kind{model.Metric, model.Log, model.ErrorKind, model.SpanKind},
		Resources:     model.ResourceRegistry{Services: []model.ID{fx.service}, Environments: []model.ID{fx.environment}, Builds: []model.ID{fx.build}, Instances: []string{"instance"}},
		Templates:     []model.LogTemplate{{ID: "failed", Revision: 1, Line: "operation failed: {status}", Severity: "error", Fields: []model.TemplateField{{Name: "status", Type: "int64", MaxBytes: 16, Sensitivity: "metadata", Values: []model.Scalar{approved}}}}},
		Operations:    []string{"operation"},
		RetentionDays: map[model.Kind]uint32{model.Metric: 30, model.Log: 14, model.ErrorKind: 30, model.SpanKind: 14}, MaxBytes: 1 << 30, MaxSeries: 1000}
	status, raw, err = site.post("/api/v1/sources", auth.SourceOnboarding{CommandID: model.NewID(), Org: fx.org, Project: fx.project, Source: fx.source, Expires: model.UnixNano(time.Now().Add(time.Hour).UnixNano()), Policy: policy, Reason: "install smoke"}, fx.session.CSRF, "")
	if err = requireSmokeResponse("source_onboard", status, 200, raw, err); err != nil {
		return fx, err
	}
	var issued auth.SourceOnboarded
	if err = json.Unmarshal(raw, &issued); err != nil {
		return fx, err
	}
	fx.credential = issued.Credential
	// The reader logs in with its own session; the owner session never reads telemetry.
	status, raw, err = site.post("/api/v1/login", map[string]string{"Email": fx.readerEmail, "Password": "install smoke reader password 2026", "Code": ""}, "", "")
	if err = requireSmokeResponse("reader_login", status, 200, raw, err); err != nil {
		return fx, err
	}
	return fx, json.Unmarshal(raw, &fx.reader)
}

type installReceipt struct {
	name    string
	batch   model.Batch
	receipt model.Receipt
}

func ingestEverySignal(site *installSite, fx *installFixture) ([]installReceipt, error) {
	resource := model.Resource{Service: fx.service, Environment: fx.environment, Build: fx.build, Instance: "instance", Labels: model.Labels{}}
	now := time.Now().UnixNano()
	metricAt := model.UnixNano(now - int64(5*time.Second))
	value := model.FloatBits(math.Float64bits(42.5))
	histogram := &model.NativeHistogram{Integer: &model.IntegerHistogram{Flavor: "counter", Schema: 0, ZeroThreshold: model.FloatBits(0), Sum: model.FloatBits(0), Count: 9007199254740993, ZeroCount: 9007199254740993, ResetHint: "unknown"}}
	var approved model.Scalar
	_ = json.Unmarshal([]byte(`503`), &approved)
	spanStart := model.UnixNano(now - int64(4*time.Second))
	clock := model.TraceClock{Wall: 1, Mono: 1, Domain: model.ClockDomain{Host: model.NewID(), Boot: model.NewID(), Runtime: model.NewID()}}
	end := clock
	end.Mono = 2
	var spanID model.SpanID
	spanID[0] = 1
	records := []struct {
		name   string
		record model.Record
	}{
		{"metric_float", model.Record{ID: model.NewID(), Kind: model.Metric, ObservedAt: metricAt, Resource: resource, Payload: model.Payload{Metric: &model.MetricPoint{Name: "install_smoke_requests", Labels: model.Labels{}, SampleKind: "float", Value: &value, Unit: "1", Type: "gauge"}}}},
		{"metric_integer_histogram", model.Record{ID: model.NewID(), Kind: model.Metric, ObservedAt: 9007199254740993, Resource: resource, Payload: model.Payload{Metric: &model.MetricPoint{Name: "install_smoke_latency", Labels: model.Labels{}, SampleKind: "integer_histogram", Histogram: histogram, Unit: "1", Type: "histogram"}}}},
		{"log", model.Record{ID: model.NewID(), Kind: model.Log, ObservedAt: model.UnixNano(now - int64(3*time.Second)), Resource: resource, Payload: model.Payload{Log: &model.LogRecord{TemplateID: "failed", TemplateRevision: 1, Fields: map[string]model.Scalar{"status": approved}, StreamLabels: model.Labels{}, Metadata: map[string]model.Scalar{}, SourceClass: "structured"}}}},
		{"error", model.Record{ID: model.NewID(), Kind: model.ErrorKind, ObservedAt: model.UnixNano(now - int64(2*time.Second)), Resource: resource, Payload: model.Payload{Error: &model.ErrorOccurrence{Occurrence: model.NewID(), Class: "TypeError", Mechanism: "manual", Build: fx.build, Handled: true, Frames: []model.Frame{}}}}},
		{"span", model.Record{ID: model.NewID(), Kind: model.SpanKind, ObservedAt: spanStart, Resource: resource, Payload: model.Payload{Span: &model.Span{Trace: model.NewID(), ID: spanID, Kind: "internal", Operation: "operation", Start: clock, End: &end, Status: "ok", SampleProbability: model.FloatBits(0x3ff0000000000000), SampleDecision: "keep"}}}},
	}
	var out []installReceipt
	for _, r := range records {
		batch := model.Batch{Version: 1, Project: fx.project, Source: fx.source, Producer: model.NewID(), ID: model.NewID(), PolicyRevision: 1, Records: []model.Record{r.record}}
		var err error
		if batch.RouteSlot, err = model.OwnerSlot(fx.org, fx.project, fx.source, batch.Producer, r.record); err != nil {
			return nil, err
		}
		status, raw, err := site.ingest(batch, fx.credential)
		if err = requireSmokeResponse("ingest_"+r.name, status, 200, raw, err); err != nil {
			return nil, err
		}
		var receipt model.Receipt
		if err = json.Unmarshal(raw, &receipt); err != nil || receipt.Cursor.Index == 0 {
			return nil, &smokeFailure{Stage: "ingest_" + r.name, Code: "receipt_decode"}
		}
		out = append(out, installReceipt{name: r.name, batch: batch, receipt: receipt})
	}
	return out, nil
}

func installProfile(id string) ([]byte, error) {
	files, err := profiles.Query()
	if err != nil {
		return nil, err
	}
	return fs.ReadFile(files, id+".json")
}

var installFeatureSet = regexp.MustCompile(`"feature_sets"\s*:\s*\[\s*\{\s*"id"\s*:\s*"([^"]+)"`)

// queryInstalled runs a real PromQL instant query as the project reader and requires the
// ingested value 42.5 in a complete answer. It returns the answer, minus its own execution time, for byte comparison
// after the restart (the evaluation time is fixed by the first call).
func queryInstalled(site *installSite, fx *installFixture) ([]byte, error) {
	profile := "promql-prometheus-3.1.0"
	manifest, err := installProfile(profile)
	if err != nil {
		return nil, err
	}
	match := installFeatureSet.FindSubmatch(manifest)
	if match == nil {
		return nil, &smokeFailure{Stage: "query", Code: "feature_set"}
	}
	if fx.queryTime == "" {
		fx.queryTime = fmt.Sprint(time.Now().Add(time.Minute).UnixNano())
	}
	body := map[string]any{"org": fx.org.String(), "language": "promql", "profile": profile, "feature_set": string(match[1]), "expression": "install_smoke_requests",
		"evaluation": map[string]any{"instant": true, "time": fx.queryTime, "start": "0", "end": "0", "step": "0"},
		"projects":   []string{fx.project.String()}, "budget": map[string]any{"timeout_ns": "0", "memory_bytes": "0", "max_returned": "0"}, "allow_partial": false}
	status, raw, err := site.post("/api/v1/query", body, fx.reader.CSRF, "")
	if err = requireSmokeResponse("query", status, 200, raw, err); err != nil {
		return nil, err
	}
	var result query.Result
	if err = json.Unmarshal(raw, &result); err != nil || len(result.Projects) != 1 {
		return nil, &smokeFailure{Stage: "query", Code: "decode"}
	}
	got := result.Projects[0]
	if got.Failure != nil || got.Completeness != query.CompletenessComplete || got.Value == nil || got.Value.Type != query.ValueVector || len(got.Value.Vector) != 1 {
		return nil, &smokeFailure{Stage: "query", Code: "not_a_complete_single_sample"}
	}
	sample := got.Value.Vector[0].Sample
	if sample.Float == nil || math.Float64frombits(uint64(*sample.Float)) != 42.5 {
		return nil, &smokeFailure{Stage: "query", Code: "wrong_value"}
	}
	// The answer is compared byte for byte after the restart except for the one field that
	// measures this particular execution.
	for i := range result.Projects {
		result.Projects[i].Stats.ElapsedNS = 0
	}
	return json.Marshal(result)
}

// fetchUIAssets requires the embedded UI: the page, its script and stylesheet, with the
// production security headers, byte-identical to the built bundle when one is available.
func fetchUIAssets(site *installSite, webDist string, report map[string]any) error {
	req, err := http.NewRequest("GET", site.base+"/", nil)
	if err != nil {
		return err
	}
	status, page, header, err := site.do(req)
	if err != nil || status != 200 || !bytes.Contains(page, []byte(`id="root"`)) || !strings.Contains(header.Get("Content-Type"), "text/html") || !strings.Contains(header.Get("Content-Security-Policy"), "default-src 'none'") {
		return &smokeFailure{Stage: "ui_index", Code: "not_the_built_ui", Actual: status}
	}
	refs := regexp.MustCompile(`(?:src|href)="(/assets/[^"?#]+)"`).FindAllSubmatch(page, -1)
	if len(refs) == 0 {
		return &smokeFailure{Stage: "ui_assets", Code: "no_assets_referenced"}
	}
	script := false
	for _, ref := range refs {
		name := string(ref[1])
		code, body, err := site.get(name)
		if err != nil || code != 200 || len(body) == 0 {
			return &smokeFailure{Stage: "ui_assets", Code: "asset_missing", Actual: code}
		}
		script = script || strings.HasSuffix(name, ".js")
		if webDist != "" {
			disk, err := os.ReadFile(filepath.Join(webDist, filepath.FromSlash(strings.TrimPrefix(name, "/"))))
			if err != nil || !bytes.Equal(disk, body) {
				return &smokeFailure{Stage: "ui_assets", Code: "asset_differs_from_built_bundle"}
			}
		}
	}
	if !script {
		return &smokeFailure{Stage: "ui_assets", Code: "no_script"}
	}
	report["ui_assets_served"] = len(refs)
	report["ui_compared_to_built_bundle"] = webDist != ""
	return nil
}
