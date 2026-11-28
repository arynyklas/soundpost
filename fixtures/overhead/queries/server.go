// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/tar"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"debug/buildinfo"
	"encoding/hex"
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
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

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

// Event is one lifecycle event of the server (start, restart, kill, shard_loss) with its measured durations.
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

const (
	// pkiValidity outlasts the preload, the 24 h steady run and the restart at its end.
	pkiValidity = 72 * time.Hour
	// dataSampleEvery is how often a monitor sample also walks the data directory (a walk of a data set of this size is not free).
	dataSampleEvery = 60 * time.Second
	// faultAnswerWait is how long a close-groups request waits for the product to answer it.
	faultAnswerWait = 10 * time.Second
	// memoryGuardKiB is the host's MemAvailable below which the harness kills the server rather than endanger other processes on the VM.
	memoryGuardKiB = 1536 * 1024
)

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

	// the product's notification and fault-injection surface
	workerInterval time.Duration
	faultDir       string // SOUNDPOST_FAULT_DIR of every process this harness starts: close-groups in, rules.jsonl and scans.jsonl out
	egressAllow    string // --notify-egress-allow: the webhook receiver's address as a /32
	notifyCA       string // --notify-ca-file: the CA that signed the receiver's leaf
	faultWait      time.Duration

	mu     sync.Mutex
	cmd    *exec.Cmd
	done   chan struct{}
	exit   error
	events *os.File
	last   Sample
	csrf   string

	faultMu sync.Mutex // one close-groups request at a time: the product answers through a single result file
}

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

func killActive() {
	if p := activePID.Load(); p != 0 {
		syscall.Kill(int(p), syscall.SIGKILL)
	}
}

// issueCA makes a private CA valid for pkiValidity.
func issueCA(cn string, t time.Time) (*ecdsa.PrivateKey, *x509.Certificate, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn}, NotBefore: t.Add(-time.Minute), NotAfter: t.Add(pkiValidity), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	return key, cert, der, err
}

// issueLeaf makes a server leaf of ca valid for the given addresses (and localhost).
func issueLeaf(ca *x509.Certificate, caKey *ecdsa.PrivateKey, ips []net.IP, t time.Time) (certDER, keyDER []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, IPAddresses: ips, NotBefore: t.Add(-time.Minute), NotAfter: t.Add(pkiValidity), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	certDER, err = x509.CreateCertificate(rand.Reader, tpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err = x509.MarshalECPrivateKey(key)
	return certDER, keyDER, err
}

func pemOf(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

// webhookPKI is a private CA of its own and a leaf of it valid for the receiver's addresses: the product trusts exactly this CA for
// notification delivery (--notify-ca-file), the query role serves the leaf.
func webhookPKI(ips []net.IP, t time.Time) (caPEM, certPEM, keyPEM []byte, err error) {
	caKey, ca, caDER, err := issueCA("soundpost queries webhook CA", t)
	if err != nil {
		return nil, nil, nil, err
	}
	certDER, keyDER, err := issueLeaf(ca, caKey, ips, t)
	if err != nil {
		return nil, nil, nil, err
	}
	return pemOf("CERTIFICATE", caDER), pemOf("CERTIFICATE", certDER), pemOf("EC PRIVATE KEY", keyDER), nil
}

// pki writes a private CA and a leaf valid for the advertised address and loopback, and the client that trusts that CA.
func (s *server) pki(dir string) {
	must(os.MkdirAll(dir, 0o700), "pki dir")
	t := time.Now()
	caKey, caCert, caDER, err := issueCA("soundpost queries overhead CA", t)
	must(err, "ca")
	host, _, err := net.SplitHostPort(s.addr)
	must(err, "listen address")
	ips := []net.IP{net.ParseIP("127.0.0.1")}
	if ip := net.ParseIP(host); ip != nil {
		ips = append(ips, ip)
	}
	leafDER, keyDER, err := issueLeaf(caCert, caKey, ips, t)
	must(err, "leaf")
	s.ca, s.cert, s.key = filepath.Join(s.out, "ca.pem"), filepath.Join(dir, "leaf.pem"), filepath.Join(dir, "leaf.key")
	must(os.WriteFile(s.ca, pemOf("CERTIFICATE", caDER), 0o600), "pki write")
	must(os.WriteFile(s.cert, pemOf("CERTIFICATE", leafDER), 0o600), "pki write")
	must(os.WriteFile(s.key, pemOf("EC PRIVATE KEY", keyDER), 0o600), "pki write")
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	jar, _ := cookiejar.New(nil)
	s.client = &http.Client{Timeout: 120 * time.Second, Jar: jar, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}, DisableKeepAlives: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// serveArgs are the flags of `soundpost serve`. The worker interval is the cadence of the rule evaluations and notification deliveries,
// the public origin the links of a notification are built from, the egress allow-list and CA the webhook receiver of the query host.
func (s *server) serveArgs() []string {
	return []string{"serve", "--mode=single", "--data-dir", s.dataDir, "--listen", s.addr, "--tls-cert", s.cert, "--tls-key", s.key, "--symbolicate-sandbox=off",
		"--worker-interval", s.workerInterval.String(), "--public-origin", "https://" + s.addr, "--notify-egress-allow", s.egressAllow, "--notify-ca-file", s.notifyCA}
}

// start launches `soundpost serve` and waits until /readyz answers 200: in a cgroup v2 scope of its own with the host shape of D90
// (cgroup.go) when the harness runs with --scope, else pinned to the CPU set with taskset. The returned process id is the id of the
// soundpost process itself: taskset and systemd-run --scope replace themselves with the command, they do not fork.
func (s *server) start() (pid int, ready time.Duration) {
	// A restart brings every shard back (the closed groups were closed for that process only): a close-groups request the dead
	// process never consumed must not close them again in the new one.
	os.Remove(filepath.Join(s.faultDir, "close-groups"))
	os.Remove(filepath.Join(s.faultDir, "close-groups.result"))
	serve := s.serveArgs()
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
	cmd.Env = append(os.Environ(), "GOMAXPROCS="+strconv.Itoa(s.gomaxprocs), "SOUNDPOST_FAULT_DIR="+s.faultDir)
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
			s.mu.Lock()
			exit := s.exit
			s.mu.Unlock()
			fatalf("soundpost serve exited during start: %v", exit)
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

// parseSlots expands "0-31", "3,7,40-42" into the sorted, unique data slots (0..63) the product's close-groups file takes one by one.
func parseSlots(list string) ([]int, error) {
	var slots []int
	for _, part := range strings.Split(strings.TrimSpace(list), ",") {
		part = strings.TrimSpace(part)
		lo, hi, isRange := strings.Cut(part, "-")
		a, err := strconv.Atoi(lo)
		if err != nil {
			return nil, fmt.Errorf("slot %q is not a number", part)
		}
		b := a
		if isRange {
			if b, err = strconv.Atoi(hi); err != nil {
				return nil, fmt.Errorf("slot range %q is not numbers", part)
			}
		}
		if a < 0 || b > 63 || a > b {
			return nil, fmt.Errorf("slots %q outside 0..63", part)
		}
		for n := a; n <= b; n++ {
			slots = append(slots, n)
		}
	}
	slices.Sort(slots)
	return slices.Compact(slots), nil
}

// closeGroups asks the soundpost_faults build of the product to close the replica groups of the given slots and returns its answer
// ("ok N" or "error ..."). The request file is written atomically (tmp + rename): the product consumes `close-groups` as soon as it
// exists, and a stale answer of an earlier request must not be mistaken for this one's.
func (s *server) closeGroups(slots []int) (string, error) {
	s.faultMu.Lock()
	defer s.faultMu.Unlock()
	req, tmp, result := filepath.Join(s.faultDir, "close-groups"), filepath.Join(s.faultDir, "close-groups.tmp"), filepath.Join(s.faultDir, "close-groups.result")
	if err := os.Remove(result); err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	parts := make([]string, len(slots))
	for i, n := range slots {
		parts[i] = strconv.Itoa(n)
	}
	if err := os.WriteFile(tmp, []byte(strings.Join(parts, ",")), 0o600); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, req); err != nil {
		return "", err
	}
	for deadline := time.Now().Add(s.faultWait); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if raw, err := os.ReadFile(result); err == nil && len(raw) > 0 {
			return strings.TrimSpace(string(raw)), nil
		}
	}
	return "", fmt.Errorf("the product did not answer within %s (is it a soundpost_faults build with SOUNDPOST_FAULT_DIR?)", s.faultWait)
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
			for i := range 8 {
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
	var lastData time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		withData := time.Since(lastData) >= dataSampleEvery-every/2
		if withData {
			lastData = time.Now()
		}
		sm := s.sample(withData)
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

// bundleFile is one file of GET /bundle: its name in the tar (the base name of the run directory's server/ file) and where it lives.
type bundleFile struct{ name, path string }

func (s *server) bundleFiles() []bundleFile {
	return []bundleFile{
		{"server-series.jsonl", filepath.Join(s.out, "server-series.jsonl")},
		{"events.jsonl", filepath.Join(s.out, "events.jsonl")},
		{"host.json", filepath.Join(s.out, "host.json")},
		{"server.log", filepath.Join(s.out, "server.log")},
		{"rules.jsonl", filepath.Join(s.faultDir, "rules.jsonl")},
		{"scans.jsonl", filepath.Join(s.faultDir, "scans.jsonl")},
		{"net-series.jsonl", filepath.Join(s.out, "net-series.jsonl")},
	}
}

// writeBundle streams the evidence files as a tar: rules.jsonl and scans.jsonl of a 24 h run are large and still being appended to, so
// each file is copied by the size it had when its header was written, never read whole into memory.
func (s *server) writeBundle(w io.Writer) error {
	tw := tar.NewWriter(w)
	for _, bf := range s.bundleFiles() {
		f, err := os.Open(bf.path)
		if err != nil {
			continue
		}
		info, err := f.Stat()
		if err != nil {
			f.Close()
			continue
		}
		if err = tw.WriteHeader(&tar.Header{Name: bf.name, Mode: 0o644, Size: info.Size(), ModTime: time.Now()}); err == nil {
			_, err = io.CopyN(tw, f, info.Size())
		}
		f.Close()
		if err != nil {
			return fmt.Errorf("bundle %s: %w", bf.name, err)
		}
	}
	return tw.Close()
}

// controlHandler is the control endpoint: plan and CA for the other hosts, the evidence bundle, the monitor state, the restart, the
// shard loss and the stop, every one guarded by the harness token.
func (s *server) controlHandler(token string, stop chan<- struct{}) http.Handler {
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
	// the other hosts fetch the plan (credentials) and the CA from here: the control token is the shared secret of the harness.
	mux.HandleFunc("GET /plan", file("plan.json"))
	mux.HandleFunc("GET /ca", file("ca.pem"))
	mux.HandleFunc("GET /bundle", guard(func(w http.ResponseWriter, r *http.Request) {
		if err := s.writeBundle(w); err != nil {
			fmt.Fprintf(os.Stderr, "queries: %v\n", err)
		}
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
	// The shard loss: the replica groups of the given slots are closed in the running product, for the life of that process.
	mux.HandleFunc("POST /fault/close-groups", guard(func(w http.ResponseWriter, r *http.Request) {
		list := r.URL.Query().Get("slots")
		slots, err := parseSlots(list)
		if err != nil || list == "" {
			http.Error(w, fmt.Sprintf("slots: %v", err), http.StatusBadRequest)
			return
		}
		e := Event{Event: "shard_loss", Mode: "slots " + list, PIDBefore: s.pid()}
		answer, err := s.closeGroups(slots)
		status := http.StatusOK
		switch {
		case err != nil:
			e.Note, status = "error "+err.Error(), http.StatusGatewayTimeout
		case strings.HasPrefix(answer, "ok "):
			e.Note = "closed " + strings.TrimPrefix(answer, "ok ")
		default:
			e.Note, status = answer, http.StatusBadGateway
		}
		s.event(e)
		e.TMS = now()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(e)
	}))
	mux.HandleFunc("POST /stop", guard(func(w http.ResponseWriter, r *http.Request) {
		exit, took := s.stop(syscall.SIGTERM)
		e := Event{Event: "stop", Mode: "graceful", Exit: exit, StopMS: took.Milliseconds()}
		s.event(e)
		json.NewEncoder(w).Encode(e)
		go func() { time.Sleep(200 * time.Millisecond); close(stop) }()
	}))
	return mux
}

func (s *server) control(listen, token string, stop chan<- struct{}) {
	h := s.controlHandler(token, stop)
	go func() {
		if err := http.ListenAndServe(listen, h); err != nil {
			fatalf("control listener: %v", err)
		}
	}()
}

// requireFaultsBuild refuses a binary that was not built with -tags soundpost_faults: without the hooks there is neither a shard loss
// nor rules.jsonl/scans.jsonl, and the gate cannot be judged. The tags are read from the binary's own build information.
func requireFaultsBuild(bin string) string {
	info, err := buildinfo.ReadFile(bin)
	if err != nil {
		fatalf("--soundpost %s: no Go build information: %v", bin, err)
	}
	for _, kv := range info.Settings {
		if kv.Key == "-tags" {
			if slices.Contains(strings.Split(kv.Value, ","), "soundpost_faults") {
				return kv.Value
			}
			fatalf("--soundpost %s was built with -tags %s: the gate needs soundpost_faults", bin, kv.Value)
		}
	}
	fatalf("--soundpost %s was built without -tags soundpost_faults", bin)
	return ""
}

// webhookTarget validates the receiver's URL and returns its IP: the product refuses any destination outside the egress allow-list,
// which holds private prefixes only, and the receiver's leaf must name the address the product dials.
func webhookTarget(rawURL, listen string) (target netip.Addr, listenIP net.IP, err error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return netip.Addr{}, nil, fmt.Errorf("--webhook-url %q is not a plain https URL", rawURL)
	}
	if target, err = netip.ParseAddr(u.Hostname()); err != nil {
		return netip.Addr{}, nil, fmt.Errorf("--webhook-url host %q is not an IP address", u.Hostname())
	}
	cgnat := netip.MustParsePrefix("100.64.0.0/10")
	if !target.IsPrivate() && !cgnat.Contains(target) {
		return netip.Addr{}, nil, fmt.Errorf("--webhook-url host %s is not a private address: the product's notification egress allows private prefixes only", target)
	}
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return netip.Addr{}, nil, fmt.Errorf("--webhook-listen %q: %v", listen, err)
	}
	if listenIP = net.ParseIP(host); listenIP == nil {
		return netip.Addr{}, nil, fmt.Errorf("--webhook-listen host %q is not an IP address", host)
	}
	return target, listenIP, nil
}

func runServer(args []string) {
	f := flag.NewFlagSet("server", flag.ExitOnError)
	bin := f.String("soundpost", "", "soundpost binary to serve (built with -tags soundpost_faults)")
	dataDir := f.String("data-dir", "", "fresh private data directory (on persistent disk, not tmpfs)")
	addr := f.String("listen", "", "ip:port the product listens on (must be the address the other hosts reach)")
	controlAddr := f.String("control-listen", "", "ip:port of the harness control endpoint")
	out := f.String("out", "", "output directory for plan, CA, series, events and the fault directory")
	cpus := f.String("cpus", "0-7", "CPU set the server is pinned to (taskset -c; with --scope: AllowedCPUs of the scope)")
	gomax := f.Int("gomaxprocs", 8, "GOMAXPROCS of the server")
	scope := f.Bool("scope", false, "start the server in a cgroup v2 scope with the gate's limits (D90: systemd-run --scope, 8 CPUs, MemoryMax, no swap; needs root and --gomaxprocs 8)")
	cold := f.Bool("cold-restart", false, "drop the host's page cache between the stop and the start of every restart (needs root): the startup budget is judged on a cold start")
	memoryMax := f.String("memory-max", "16G", "MemoryMax of the scope with --scope (between 15,000 MiB and 16 GiB)")
	workerInterval := f.Duration("worker-interval", time.Second, "pause between the product's background runner passes (rule evaluation, notification delivery)")
	def := DefaultConfig()
	seed := f.Uint64("seed", def.Seed, "estate seed")
	orgs := f.Int("orgs", def.Orgs, "organizations")
	projects := f.Int("projects", def.Projects, "projects")
	routes := f.Int("routes", def.RoutesPerProject, "routes per project (series per project = 10 x routes)")
	webhookListen := f.String("webhook-listen", "", "ip:port the query role's webhook receiver listens on")
	webhookURL := f.String("webhook-url", "", "https URL of that receiver as the product reaches it (the query host's address)")
	faultsBuild := f.Bool("faults-build", false, "assert that --soundpost was built with -tags soundpost_faults (also checked against the binary's build information)")
	sampleEvery := f.Duration("sample-every", 10*time.Second, "monitor period")
	ctlToken := f.String("control-token", "", "token of the control endpoint (default: random, written to plan.json)")
	f.Parse(args)
	cfg := Config{Seed: *seed, Orgs: *orgs, Projects: *projects, RoutesPerProject: *routes, Epoch: def.Epoch}
	must(cfg.Check(), "config")
	if *bin == "" || *dataDir == "" || *addr == "" || *controlAddr == "" || *out == "" || *webhookListen == "" || *webhookURL == "" {
		fatalf("--soundpost, --data-dir, --listen, --control-listen, --out, --webhook-listen and --webhook-url are required")
	}
	if !*faultsBuild {
		fatalf("--faults-build is required: the gate runs a soundpost built with -tags soundpost_faults")
	}
	if *workerInterval < 10*time.Millisecond {
		fatalf("--worker-interval %s: the product needs at least 10ms", *workerInterval)
	}
	tags := requireFaultsBuild(*bin)
	target, listenIP, err := webhookTarget(*webhookURL, *webhookListen)
	must(err, "webhook")
	must(os.MkdirAll(*out, 0o755), "out dir")
	if entries, _ := os.ReadDir(*dataDir); len(entries) > 0 {
		fatalf("data directory %s is not empty: the run needs a fresh product", *dataDir)
	}
	must(os.MkdirAll(*dataDir, 0o700), "data dir")
	if *scope && (*gomax != scopeGomaxprocs || *memoryMax == "") {
		fatalf("--scope is the gate's host shape (D90): it needs --gomaxprocs %d and a --memory-max", scopeGomaxprocs)
	}
	s := &server{bin: *bin, dataDir: *dataDir, addr: *addr, cpus: *cpus, gomaxprocs: *gomax, scope: *scope, coldRestart: *cold, memoryMax: *memoryMax, out: *out,
		workerInterval: *workerInterval, faultDir: filepath.Join(*out, "fault"), egressAllow: netip.PrefixFrom(target, target.BitLen()).String(), faultWait: faultAnswerWait}
	onFatal = killActive
	must(os.MkdirAll(s.faultDir, 0o700), "fault dir")
	s.events, err = os.OpenFile(filepath.Join(*out, "events.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	must(err, "events file")
	s.pki(filepath.Join(filepath.Dir(*dataDir), filepath.Base(*dataDir)+"-pki"))
	caPEM, hookCert, hookKey, err := webhookPKI([]net.IP{target.AsSlice(), listenIP}, time.Now())
	must(err, "webhook pki")
	s.notifyCA = filepath.Join(*out, "webhook-ca.pem")
	must(os.WriteFile(s.notifyCA, caPEM, 0o644), "webhook CA")
	var sec [32]byte
	rand.Read(sec[:])
	webhook := PlanWebhook{URL: *webhookURL, Listen: *webhookListen, Secret: hex.EncodeToString(sec[:]), CertPEM: string(hookCert), KeyPEM: string(hookKey)}

	pid, ready := s.start()
	s.event(Event{Event: "start", PIDAfter: pid, ReadyMS: ready.Milliseconds(), Cpus: cpusAllowed(pid), Note: "soundpost_faults build, tags " + tags})
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
	plan := &Plan{Config: cfg, Addr: *addr, Control: *controlAddr, ControlToken: token, Webhook: webhook, StartedAt: now()}
	s.provision(cfg, plan)
	raw, _ := json.Marshal(plan)
	must(os.WriteFile(filepath.Join(*out, "plan.json"), raw, 0o600), "plan")
	s.event(Event{Event: "provisioned", Note: fmt.Sprintf("%d rules, %d destinations", len(plan.Rules), cfg.Orgs)})

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	go s.monitor(ctx, filepath.Join(*out, "server-series.jsonl"), *sampleEvery)
	startNetMon(ctx, filepath.Join(*out, "net-series.jsonl"), 10*time.Second)
	stopped := make(chan struct{})
	s.control(*controlAddr, plan.ControlToken, stopped)
	fmt.Fprintf(os.Stderr, "queries: server up pid %d, plan %s\n", pid, filepath.Join(*out, "plan.json"))
	select {
	case <-stopped:
	case <-ctx.Done():
		exit, took := s.stop(syscall.SIGTERM)
		s.event(Event{Event: "stop", Mode: "graceful", Exit: exit, StopMS: took.Milliseconds(), Note: "harness interrupted"})
	}
}
