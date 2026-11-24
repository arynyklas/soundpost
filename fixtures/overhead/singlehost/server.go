// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
)

// Plan is what the load generator and the verifier need to reach and address the estate. It carries credentials: it is written 0600 and
// is never part of the evidence.
type Plan struct {
	Config       Config       `json:"config"`
	Addr         string       `json:"addr"`
	Control      string       `json:"control"`
	ControlToken string       `json:"control_token"`
	Sources      []PlanSource `json:"sources"`
	Readers      []PlanReader `json:"readers"`
	StartedAt    int64        `json:"provisioned_unix_ms"`
}

// PlanSource is the credential of one project's SDK source.
type PlanSource struct {
	Project    int    `json:"project"`
	Credential string `json:"credential"`
}

// PlanReader is the read token of one organization's read-only user (all of the org's projects).
type PlanReader struct {
	Org   int    `json:"org"`
	Token string `json:"token"`
}

// Sample is one monitor sample of the server process: numbers only.
type Sample struct {
	TMS         int64    `json:"t_ms"`
	PID         int      `json:"pid"`
	RSSKiB      int64    `json:"rss_kib"`
	HWMKiB      int64    `json:"hwm_kib"`
	Threads     int64    `json:"threads"`
	FDs         int      `json:"fds"`
	IOWrite     uint64   `json:"io_write_bytes"`
	IORead      uint64   `json:"io_read_bytes"`
	IOWChar     uint64   `json:"io_wchar"`
	UTime       uint64   `json:"utime_ticks"`
	STime       uint64   `json:"stime_ticks"`
	CPUBusy     []uint64 `json:"cpu_busy_ticks"`
	CPUTotal    []uint64 `json:"cpu_total_ticks"`
	MemAvailKiB int64    `json:"mem_available_kib"`
	Load1       float64  `json:"load1"`
	DataBytes   int64    `json:"data_bytes,omitempty"`
	CgMemKiB    int64    `json:"cgroup_memory_current_kib,omitempty"`
	CgOOMKill   uint64   `json:"cgroup_oom_kill,omitempty"`
}

// Event is one lifecycle event of the server (start, restart, kill) with its measured durations.
type Event struct {
	TMS       int64        `json:"t_ms"`
	Event     string       `json:"event"`
	Mode      string       `json:"mode,omitempty"`
	PIDBefore int          `json:"pid_before,omitempty"`
	PIDAfter  int          `json:"pid_after,omitempty"`
	Exit      string       `json:"exit,omitempty"`
	StopMS    int64        `json:"stop_ms,omitempty"`
	ReadyMS   int64        `json:"ready_ms,omitempty"`
	Cpus      string       `json:"cpus_allowed,omitempty"`
	Note      string       `json:"note,omitempty"`
	Cgroup    *CgroupFacts `json:"cgroup,omitempty"`
}

type server struct {
	bin, dataDir, addr, cpus string
	gomaxprocs               int
	scope                    bool   // run in a cgroup v2 scope with the D90 limits (cgroup.go)
	coldRestart              bool   // drop the page cache between the stop and the start of every restart (root)
	memoryMax                string // MemoryMax of the scope (systemd syntax)
	cg                       CgroupFacts
	out                      string
	cert, key, ca            string
	client                   *http.Client

	mu     sync.Mutex
	cmd    *exec.Cmd
	done   chan struct{}
	exit   error
	events *os.File
	last   Sample
	csrf   string
}

func now() int64 { return time.Now().UnixMilli() }

func (s *server) event(e Event) {
	e.TMS = now()
	raw, _ := json.Marshal(e)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events.Write(append(raw, '\n'))
}

// activePID is the exact process id of the soundpost this harness started (0 when none runs): a failing harness ends it rather than leave
// an orphan on the host.
var activePID atomic.Int64

func fatalf(f string, a ...any) {
	fmt.Fprintf(os.Stderr, "singlehost: FAIL: "+f+"\n", a...)
	if p := activePID.Load(); p != 0 {
		syscall.Kill(int(p), syscall.SIGKILL)
	}
	os.Exit(1)
}

// memoryGuardKiB is the host's MemAvailable below which the harness kills the server rather than endanger other processes on the VM.
const memoryGuardKiB = 1536 * 1024

func must(err error, what string) {
	if err != nil {
		fatalf("%s: %v", what, err)
	}
}

// pki writes a private CA and a leaf valid for the advertised address and loopback.
func (s *server) pki(dir string) {
	must(os.MkdirAll(dir, 0o700), "pki dir")
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err, "ca key")
	t := time.Now()
	caTpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "soundpost single-host overhead CA"}, NotBefore: t.Add(-time.Minute), NotAfter: t.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	must(err, "ca cert")
	caCert, _ := x509.ParseCertificate(caDER)
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err, "leaf key")
	host, _, err := net.SplitHostPort(s.addr)
	must(err, "listen address")
	ips := []net.IP{net.ParseIP("127.0.0.1")}
	if ip := net.ParseIP(host); ip != nil {
		ips = append(ips, ip)
	}
	leafTpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, IPAddresses: ips, NotBefore: t.Add(-time.Minute), NotAfter: t.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTpl, caCert, &leafKey.PublicKey, caKey)
	must(err, "leaf cert")
	keyDER, _ := x509.MarshalECPrivateKey(leafKey)
	s.ca, s.cert, s.key = filepath.Join(s.out, "ca.pem"), filepath.Join(dir, "leaf.pem"), filepath.Join(dir, "leaf.key")
	for path, b := range map[string]*pem.Block{s.ca: {Type: "CERTIFICATE", Bytes: caDER}, s.cert: {Type: "CERTIFICATE", Bytes: leafDER}, s.key: {Type: "EC PRIVATE KEY", Bytes: keyDER}} {
		must(os.WriteFile(path, pem.EncodeToMemory(b), 0o600), "pki write")
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	jar, _ := cookiejar.New(nil)
	s.client = &http.Client{Timeout: 120 * time.Second, Jar: jar, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}, DisableKeepAlives: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// start launches `soundpost serve` and waits until /readyz answers 200: in a cgroup v2 scope of its own with the host shape of D90
// (cgroup.go) when the harness runs with --scope, else pinned to the CPU set with taskset. The returned process id is the id of the
// soundpost process itself: taskset and systemd-run --scope replace themselves with the command, they do not fork.
func (s *server) start() (pid int, ready time.Duration) {
	serve := []string{"serve", "--mode=single", "--data-dir", s.dataDir, "--listen", s.addr, "--tls-cert", s.cert, "--tls-key", s.key, "--symbolicate-sandbox=off"}
	logf, err := os.OpenFile(filepath.Join(s.out, "server.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	must(err, "server log")
	var cmd *exec.Cmd
	if s.scope {
		unit := fmt.Sprintf("soundpost-server-%d-%d.scope", time.Now().Unix(), scopeSeq.Add(1))
		name, args := scopeCommand(s.cpus, s.memoryMax, unit, s.bin, serve)
		cmd = exec.Command(name, args...)
	} else {
		cmd = exec.Command("taskset", append([]string{"-c", s.cpus, s.bin}, serve...)...)
	}
	cmd.Env = append(os.Environ(), "GOMAXPROCS="+strconv.Itoa(s.gomaxprocs))
	cmd.Stdout, cmd.Stderr = logf, logf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	began := time.Now()
	must(cmd.Start(), "start soundpost serve")
	done := make(chan struct{})
	s.mu.Lock()
	s.cmd, s.done, s.exit = cmd, done, nil
	activePID.Store(int64(cmd.Process.Pid))
	s.mu.Unlock()
	go func() {
		err := cmd.Wait()
		s.mu.Lock()
		s.exit = err
		s.mu.Unlock()
		logf.Close()
		close(done)
	}()
	for time.Since(began) < 180*time.Second {
		select {
		case <-done:
			fatalf("soundpost serve exited during start: %v", s.exit)
		default:
		}
		if resp, err := s.client.Get("https://" + s.addr + "/readyz"); err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				s.recordScope(cmd.Process.Pid)
				return cmd.Process.Pid, time.Since(began)
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	fatalf("soundpost serve not ready after 180 s")
	return 0, 0
}

// recordScope reads the cgroup of the running server process and keeps it for host.json; with --scope it also refuses to go on unless
// that is the host shape of D90 (the harness would otherwise measure something else than the gate).
func (s *server) recordScope(pid int) {
	cg := readCgroup(pid)
	if s.scope {
		if err := cg.checkScope(); err != nil {
			fatalf("D90 host shape: %v", err)
		}
		if g := processGomaxprocs(pid); g != scopeGomaxprocs || s.gomaxprocs != scopeGomaxprocs {
			fatalf("D90 host shape: the server runs with GOMAXPROCS %d (flag %d), the gate needs %d", g, s.gomaxprocs, scopeGomaxprocs)
		}
	}
	s.mu.Lock()
	s.cg = cg
	s.mu.Unlock()
	s.event(Event{Event: "scope", PIDAfter: pid, Cgroup: &cg})
}

func (s *server) pid() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cmd == nil {
		return 0
	}
	return s.cmd.Process.Pid
}

func cpusAllowed(pid int) string {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return ""
	}
	for _, l := range strings.Split(string(raw), "\n") {
		if v, ok := strings.CutPrefix(l, "Cpus_allowed_list:"); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// stop ends the server by the given signal sent to the exact PID and reports how it exited.
func (s *server) stop(sig syscall.Signal) (exit string, took time.Duration) {
	s.mu.Lock()
	cmd, done := s.cmd, s.done
	s.mu.Unlock()
	if cmd == nil {
		return "not running", 0
	}
	began := time.Now()
	must(syscall.Kill(cmd.Process.Pid, sig), "signal soundpost")
	select {
	case <-done:
	case <-time.After(120 * time.Second):
		syscall.Kill(cmd.Process.Pid, syscall.SIGKILL)
		<-done
		return "did not exit within 120 s after " + sig.String() + "; killed", time.Since(began)
	}
	s.mu.Lock()
	err := s.exit
	s.cmd = nil
	activePID.Store(0)
	s.mu.Unlock()
	var ee *exec.ExitError
	switch {
	case err == nil:
		exit = "exit status 0"
	case errors.As(err, &ee):
		exit = ee.String()
	default:
		exit = err.Error()
	}
	return exit, time.Since(began)
}

// dropCaches empties the host's page cache (after a sync), so that the start that follows reads every page it needs from the disk: the
// restart the startup budget is judged on is a cold one, after a crash the files are not in memory (D91).
func dropCaches() {
	syscall.Sync()
	must(os.WriteFile("/proc/sys/vm/drop_caches", []byte("3\n"), 0), "drop the page cache (--cold-restart needs root)")
}

func (s *server) restart(mode string) Event {
	sig := syscall.SIGTERM
	if mode == "kill9" {
		sig = syscall.SIGKILL
	}
	before := s.pid()
	exit, stop := s.stop(sig)
	note := ""
	if s.coldRestart {
		dropCaches()
		note = "page cache dropped between the stop and the start"
	}
	pid, ready := s.start()
	e := Event{Event: "restart", Mode: mode, PIDBefore: before, PIDAfter: pid, Exit: exit, StopMS: stop.Milliseconds(), ReadyMS: ready.Milliseconds(), Cpus: cpusAllowed(pid), Note: note}
	s.event(e)
	return e
}

// post issues a JSON POST as the owner session (CSRF bound) or with a bearer.
func (s *server) post(path string, body any, bearer string) (int, []byte) {
	raw, _ := json.Marshal(body)
	req, err := http.NewRequest("POST", "https://"+s.addr+path, bytes.NewReader(raw))
	must(err, "request")
	req.Header.Set("Content-Type", "application/json")
	client := s.client
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
		c := *client
		c.Jar = nil
		client = &c
	} else {
		req.Header.Set("Origin", "https://"+s.addr)
		req.Header.Set("X-CSRF-Token", s.csrf)
	}
	resp, err := client.Do(req)
	must(err, "POST "+path)
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	return resp.StatusCode, out
}

func expect(what string, status int, raw []byte, want int) {
	if status != want {
		msg := string(raw)
		if len(msg) > 300 {
			msg = msg[:300]
		}
		fatalf("%s: status %d (want %d): %s", what, status, want, msg)
	}
}

func (s *server) admin(org model.ID, kind string, p auth.AdminPayload) {
	p.Reason = "single-host overhead"
	payload, _ := json.Marshal(p)
	command := model.NewID()
	// The product's preconditions: create_org and create_user are based on the global control revision, every other command on the
	// organization's policy epoch (only a change to the same object conflicts). Background commits move the revision between a read and a
	// command, so a 409 is a stale precondition, not a refusal; the fixed command ID makes the retry idempotent.
	orgScoped := kind != "create_org" && kind != "create_user"
	for attempt := 0; ; attempt++ {
		req := auth.AdminCommandRequest{CommandID: command, OrgID: org, Kind: kind, Payload: payload}
		if orgScoped {
			status, raw := s.post("/api/v1/admin/read", map[string]any{"org_id": org, "kind": "organization"}, "")
			expect("admin_read_org", status, raw, 200)
			var view auth.AdminView
			must(json.Unmarshal(raw, &view), "admin org view")
			req.ExpectedRevision, req.ExpectedEpoch = view.Revision, &view.Epoch
		} else {
			status, raw := s.post("/api/v1/admin/read", map[string]string{"kind": "organizations"}, "")
			expect("admin_read", status, raw, 200)
			var view auth.AdminView
			must(json.Unmarshal(raw, &view), "admin view")
			req.ExpectedRevision = view.Revision
		}
		status, raw := s.post("/api/v1/admin/commands", req, "")
		if status == http.StatusConflict && attempt < 300 {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		expect("admin_"+kind, status, raw, 200)
		return
	}
}

// quota sets the admission quota of an organization. An organization quota nobody configured is the smallest of its sources' policies,
// the product's conservative default (one project's series budget here): an organization of ten projects of 1,000 series each is
// refused with 429 `quota` once it passes one project's worth, which the live run at the full rate reached within a minute. The
// command is based on the global control revision, so a 409 is a stale precondition and the fixed command ID makes the retry idempotent.
func (s *server) quota(org model.ID, maxBytes, maxSeries uint64) {
	command := model.NewID()
	for attempt := 0; ; attempt++ {
		status, raw := s.post("/api/v1/admin/read", map[string]string{"kind": "organizations"}, "")
		expect("admin_read", status, raw, 200)
		var view auth.AdminView
		must(json.Unmarshal(raw, &view), "admin view")
		status, raw = s.post("/api/v1/quotas", auth.AdmissionQuotaChange{CommandID: command, ExpectedRevision: view.Revision, Org: org,
			MaxBytes: model.Uint64(maxBytes), MaxSeries: model.Uint64(maxSeries), Reason: "single-host overhead"}, "")
		if status == http.StatusConflict && attempt < 300 {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		expect("admission_quota", status, raw, 200)
		return
	}
}

// provision bootstraps the product and creates every org, project, read-only user, source credential and policy of the estate.
func (s *server) provision(cfg Config, plan *Plan) {
	token, err := os.ReadFile(filepath.Join(s.dataDir, "bootstrap.token"))
	must(err, "bootstrap token")
	status, raw := s.post("/api/v1/bootstrap", map[string]string{"Token": string(token), "Email": "owner@overhead.invalid", "Password": "single host overhead owner password 2026"}, "")
	expect("bootstrap", status, raw, 200)
	var session auth.Session
	must(json.Unmarshal(raw, &session), "session")
	s.csrf = session.CSRF
	perOrg := cfg.Projects / cfg.Orgs
	for o := 0; o < cfg.Orgs; o++ {
		first := NewProject(cfg, o*perOrg)
		s.admin(first.Org, "create_org", auth.AdminPayload{Name: fmt.Sprintf("overhead-org-%d", o)})
		s.admin(first.Org, "create_user", auth.AdminPayload{ID: first.Reader, Email: fmt.Sprintf("reader%d@overhead.invalid", o), Password: "single host overhead reader password 2026"})
		s.admin(first.Org, "membership", auth.AdminPayload{UserID: first.Reader, Enabled: true})
		var projects []model.ID
		for i := 0; i < perOrg; i++ {
			pj := NewProject(cfg, o*perOrg+i)
			projects = append(projects, pj.Project)
			s.admin(pj.Org, "create_project", auth.AdminPayload{ID: pj.Project, Name: fmt.Sprintf("overhead-project-%d", pj.Index)})
			s.admin(pj.Org, "grant", auth.AdminPayload{UserID: pj.Reader, ProjectID: pj.Project, Enabled: true, Permissions: []string{string(auth.Read)}})
			ob := auth.SourceOnboarding{CommandID: model.NewID(), Org: pj.Org, Project: pj.Project, Source: pj.Source, Expires: model.UnixNano(time.Now().Add(policyCredential).UnixNano()), Policy: pj.Policy, Reason: "single-host overhead"}
			status, raw := s.post("/api/v1/sources", ob, "")
			expect(fmt.Sprintf("onboard project %d", pj.Index), status, raw, 200)
			var onboarded auth.SourceOnboarded
			must(json.Unmarshal(raw, &onboarded), "onboarded")
			if onboarded.Credential == "" {
				fatalf("project %d: empty credential", pj.Index)
			}
			plan.Sources = append(plan.Sources, PlanSource{Project: pj.Index, Credential: onboarded.Credential})
		}
		s.quota(first.Org, 1<<40, uint64(perOrg)*uint64(cfg.SeriesPerProject())*11/10)
		status, raw := s.post("/api/v1/admin/tokens/issue", map[string]any{"org_id": first.Org, "principal": first.Reader, "projects": projects, "permissions": []string{string(auth.Read)},
			"expires": fmt.Sprint(time.Now().Add(policyCredential).Unix()), "reason": "single-host overhead"}, "")
		expect("token_issue", status, raw, 200)
		var issued struct{ Token string }
		must(json.Unmarshal(raw, &issued), "token")
		plan.Readers = append(plan.Readers, PlanReader{Org: o, Token: issued.Token})
		fmt.Fprintf(os.Stderr, "singlehost: org %d provisioned (%d projects)\n", o, perOrg)
	}
}

func readProcStatus(pid int) (rss, hwm, threads int64) {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return
	}
	for _, l := range strings.Split(string(raw), "\n") {
		f := strings.Fields(l)
		if len(f) < 2 {
			continue
		}
		v, _ := strconv.ParseInt(f[1], 10, 64)
		switch f[0] {
		case "VmRSS:":
			rss = v
		case "VmHWM:":
			hwm = v
		case "Threads:":
			threads = v
		}
	}
	return
}

func readProcIO(pid int) (write, read, wchar uint64) {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/io", pid))
	if err != nil {
		return
	}
	for _, l := range strings.Split(string(raw), "\n") {
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		n, _ := strconv.ParseUint(strings.TrimSpace(v), 10, 64)
		switch k {
		case "write_bytes":
			write = n
		case "read_bytes":
			read = n
		case "wchar":
			wchar = n
		}
	}
	return
}

func readProcCPU(pid int) (utime, stime uint64) {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return
	}
	s := string(raw)
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return
	}
	f := strings.Fields(s[i+1:])
	if len(f) > 13 {
		utime, _ = strconv.ParseUint(f[11], 10, 64)
		stime, _ = strconv.ParseUint(f[12], 10, 64)
	}
	return
}

func readSystem() (busy, total []uint64, memAvail int64, load1 float64) {
	if raw, err := os.ReadFile("/proc/stat"); err == nil {
		for _, l := range strings.Split(string(raw), "\n") {
			f := strings.Fields(l)
			if len(f) < 9 || !strings.HasPrefix(f[0], "cpu") || f[0] == "cpu" {
				continue
			}
			var v [8]uint64
			var sum uint64
			for i := 0; i < 8; i++ {
				v[i], _ = strconv.ParseUint(f[i+1], 10, 64)
				sum += v[i]
			}
			busy = append(busy, sum-v[3]-v[4]) // all but idle and iowait
			total = append(total, sum)
		}
	}
	if raw, err := os.ReadFile("/proc/meminfo"); err == nil {
		for _, l := range strings.Split(string(raw), "\n") {
			if v, ok := strings.CutPrefix(l, "MemAvailable:"); ok {
				memAvail, _ = strconv.ParseInt(strings.Fields(v)[0], 10, 64)
			}
		}
	}
	if raw, err := os.ReadFile("/proc/loadavg"); err == nil {
		load1, _ = strconv.ParseFloat(strings.Fields(string(raw))[0], 64)
	}
	return
}

func dirBytes(dir string) int64 {
	var n int64
	filepath.WalkDir(dir, func(_ string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if info, e := d.Info(); e == nil {
				n += info.Size()
			}
		}
		return nil
	})
	return n
}

// sample reads one monitor sample of the current server process (all zero numbers when it is not running).
func (s *server) sample(withData bool) Sample {
	pid := s.pid()
	sm := Sample{TMS: now(), PID: pid}
	if pid != 0 {
		sm.RSSKiB, sm.HWMKiB, sm.Threads = readProcStatus(pid)
		sm.IOWrite, sm.IORead, sm.IOWChar = readProcIO(pid)
		sm.UTime, sm.STime = readProcCPU(pid)
		if fds, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid)); err == nil {
			sm.FDs = len(fds)
		}
		s.mu.Lock()
		cgPath := s.cg.Path
		s.mu.Unlock()
		if s.scope && cgPath != "" { // the memory the scope is charged (page cache included) and the kills its limit caused
			cur, _ := strconv.ParseInt(cgroupFile(cgPath, "memory.current"), 10, 64)
			sm.CgMemKiB = cur / 1024
			for _, l := range strings.Split(cgroupFileAll(cgPath, "memory.events"), "\n") {
				if v, ok := strings.CutPrefix(l, "oom_kill "); ok {
					sm.CgOOMKill, _ = strconv.ParseUint(strings.TrimSpace(v), 10, 64)
				}
			}
		}
	}
	sm.CPUBusy, sm.CPUTotal, sm.MemAvailKiB, sm.Load1 = readSystem()
	if withData {
		sm.DataBytes = dirBytes(s.dataDir)
	}
	return sm
}

func (s *server) monitor(ctx context.Context, path string, every time.Duration) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	must(err, "series file")
	defer f.Close()
	tick := time.NewTicker(every)
	defer tick.Stop()
	for n := 0; ; n++ {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		sm := s.sample(n%6 == 0)
		s.mu.Lock()
		s.last = sm
		s.mu.Unlock()
		// The VM is shared with other work: when the host is about to run out of memory the exact server PID is killed and the run is over
		// (recorded as an event), rather than let the kernel pick a victim among other tenants' processes.
		if sm.PID != 0 && sm.MemAvailKiB > 0 && sm.MemAvailKiB < memoryGuardKiB {
			s.event(Event{Event: "memory_guard", PIDBefore: sm.PID, Note: fmt.Sprintf("MemAvailable %d KiB below the guard of %d KiB with server VmRSS %d KiB: the server was killed", sm.MemAvailKiB, memoryGuardKiB, sm.RSSKiB)})
			syscall.Kill(sm.PID, syscall.SIGKILL)
		}
		raw, _ := json.Marshal(sm)
		f.Write(append(raw, '\n'))
	}
}

func (s *server) control(listen, token string, stop chan<- struct{}) {
	mux := http.NewServeMux()
	guard := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("X-Harness-Token") != token {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			h(w, r)
		}
	}
	file := func(name string) http.HandlerFunc {
		return guard(func(w http.ResponseWriter, r *http.Request) {
			raw, err := os.ReadFile(filepath.Join(s.out, name))
			if err != nil {
				http.Error(w, "not available", http.StatusNotFound)
				return
			}
			w.Write(raw)
		})
	}
	// the load host fetches the plan (credentials) and the CA from here: the control token is the shared secret of the harness.
	mux.HandleFunc("GET /plan", file("plan.json"))
	mux.HandleFunc("GET /ca", file("ca.pem"))
	mux.HandleFunc("GET /bundle", guard(func(w http.ResponseWriter, r *http.Request) {
		tw := tar.NewWriter(w)
		for _, name := range []string{"server-series.jsonl", "events.jsonl", "host.json", "server.log"} {
			raw, err := os.ReadFile(filepath.Join(s.out, name))
			if err != nil {
				continue
			}
			tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(raw)), ModTime: time.Now()})
			tw.Write(raw)
		}
		tw.Close()
	}))
	mux.HandleFunc("GET /state", guard(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		sm := s.last
		s.mu.Unlock()
		json.NewEncoder(w).Encode(sm)
	}))
	mux.HandleFunc("POST /restart", guard(func(w http.ResponseWriter, r *http.Request) {
		mode := r.URL.Query().Get("mode")
		if mode != "graceful" && mode != "kill9" {
			http.Error(w, "mode", http.StatusBadRequest)
			return
		}
		json.NewEncoder(w).Encode(s.restart(mode))
	}))
	mux.HandleFunc("POST /stop", guard(func(w http.ResponseWriter, r *http.Request) {
		exit, took := s.stop(syscall.SIGTERM)
		e := Event{Event: "stop", Mode: "graceful", Exit: exit, StopMS: took.Milliseconds()}
		s.event(e)
		json.NewEncoder(w).Encode(e)
		go func() { time.Sleep(200 * time.Millisecond); close(stop) }()
	}))
	go func() {
		if err := http.ListenAndServe(listen, mux); err != nil {
			fatalf("control listener: %v", err)
		}
	}()
}

func runServer(args []string) {
	f := flag.NewFlagSet("server", flag.ExitOnError)
	bin := f.String("soundpost", "", "soundpost binary to serve")
	dataDir := f.String("data-dir", "", "fresh private data directory (on persistent disk, not tmpfs)")
	addr := f.String("listen", "", "ip:port the product listens on (must be the address the load generator reaches)")
	controlAddr := f.String("control-listen", "", "ip:port of the harness control endpoint")
	out := f.String("out", "", "output directory for plan, CA, series and events")
	cpus := f.String("cpus", "0-3", "CPU set the server is pinned to (taskset -c; with --scope: AllowedCPUs of the scope)")
	gomax := f.Int("gomaxprocs", 4, "GOMAXPROCS of the server")
	scope := f.Bool("scope", false, "start the server in a cgroup v2 scope with the gate's limits (D90: systemd-run --scope, 8 CPUs, MemoryMax, no swap; needs root and --gomaxprocs 8)")
	cold := f.Bool("cold-restart", false, "drop the host's page cache between the stop and the start of every restart (needs root): the startup budget is judged on a cold start")
	memoryMax := f.String("memory-max", "16G", "MemoryMax of the scope with --scope (between 15,000 MiB and 16 GiB)")
	seed := f.Uint64("seed", 20261113, "workload seed")
	orgs := f.Int("orgs", 10, "organizations")
	projects := f.Int("projects", 100, "projects")
	series := f.Int("series", 100000, "active metric series")
	rate := f.Int("rate", 2000, "mixed records per second")
	window := f.Duration("window", 10*time.Second, "per-source flush window")
	sampleEvery := f.Duration("sample-every", 10*time.Second, "monitor period")
	ctlToken := f.String("control-token", "", "token of the control endpoint (default: random, written to plan.json)")
	f.Parse(args)
	cfg := Config{Seed: *seed, Orgs: *orgs, Projects: *projects, Series: *series, Rate: *rate, Window: *window}
	must(cfg.Check(), "config")
	if *bin == "" || *dataDir == "" || *addr == "" || *controlAddr == "" || *out == "" {
		fatalf("--soundpost, --data-dir, --listen, --control-listen and --out are required")
	}
	must(os.MkdirAll(*out, 0o755), "out dir")
	if entries, _ := os.ReadDir(*dataDir); len(entries) > 0 {
		fatalf("data directory %s is not empty: the run needs a fresh product", *dataDir)
	}
	must(os.MkdirAll(*dataDir, 0o700), "data dir")
	if *scope && (*gomax != scopeGomaxprocs || *memoryMax == "") {
		fatalf("--scope is the gate's host shape (D90): it needs --gomaxprocs %d and a --memory-max", scopeGomaxprocs)
	}
	s := &server{bin: *bin, dataDir: *dataDir, addr: *addr, cpus: *cpus, gomaxprocs: *gomax, scope: *scope, coldRestart: *cold, memoryMax: *memoryMax, out: *out}
	var err error
	s.events, err = os.OpenFile(filepath.Join(*out, "events.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	must(err, "events file")
	s.pki(filepath.Join(filepath.Dir(*dataDir), filepath.Base(*dataDir)+"-pki"))
	pid, ready := s.start()
	s.event(Event{Event: "start", PIDAfter: pid, ReadyMS: ready.Milliseconds(), Cpus: cpusAllowed(pid)})
	hf := hostFacts(*dataDir, *gomax)
	hf.CpusAllowed = cpusAllowed(pid) // the product process's own CPU set, not the harness's
	s.mu.Lock()
	hf.CgroupFacts = s.cg // read back from the scope of the running server (recordScope), never from the flags
	s.mu.Unlock()
	rawHF, _ := json.MarshalIndent(hf, "", " ")
	must(os.WriteFile(filepath.Join(*out, "host.json"), rawHF, 0o644), "host facts")
	var tok [16]byte
	rand.Read(tok[:])
	token := fmt.Sprintf("%x", tok)
	if *ctlToken != "" {
		token = *ctlToken
	}
	plan := &Plan{Config: cfg, Addr: *addr, Control: *controlAddr, ControlToken: token, StartedAt: now()}
	s.provision(cfg, plan)
	raw, _ := json.Marshal(plan)
	must(os.WriteFile(filepath.Join(*out, "plan.json"), raw, 0o600), "plan")
	s.event(Event{Event: "provisioned"})

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	go s.monitor(ctx, filepath.Join(*out, "server-series.jsonl"), *sampleEvery)
	stopped := make(chan struct{})
	s.control(*controlAddr, plan.ControlToken, stopped)
	fmt.Fprintf(os.Stderr, "singlehost: server up pid %d, plan %s\n", pid, filepath.Join(*out, "plan.json"))
	select {
	case <-stopped:
	case <-ctx.Done():
		exit, took := s.stop(syscall.SIGTERM)
		s.event(Event{Event: "stop", Mode: "graceful", Exit: exit, StopMS: took.Milliseconds(), Note: "harness interrupted"})
	}
}
