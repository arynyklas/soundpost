// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// NodeFacts are the facts about a voter host its result is bound to: numbers and closed words, never a host name or an address. The
// identities (machine, VM, file system) are hashed; the failure-domain label is the operator's attestation of the hypervisor host and
// disk the voter lives on (the guest cannot prove it).
type NodeFacts struct {
	HostFacts
	NodeID          uint64 `json:"node_id"`
	ProductUUIDHash string `json:"vm_product_uuid_sha256_16"`
	FSUUIDHash      string `json:"data_fs_uuid_sha256_16"`
	DiskIDHash      string `json:"data_disk_id_sha256_16"` // file system uuid + disk serial + wwn
	DiskSizeBytes   int64  `json:"data_disk_size_bytes"`
	FailureDomain   string `json:"attested_failure_domain"`
	LinkMbit        int    `json:"link_limit_mbit"`
}

func hash16(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(sum[:8])
}

func commandLine(name string, args ...string) string {
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// nodeFacts reads the identities of this voter host. dataDir's file system and the disk below it are the ones described.
func nodeFacts(id uint64, dataDir, domain string, linkMbit, gomaxprocs int) NodeFacts {
	nf := NodeFacts{HostFacts: hostFacts(dataDir, gomaxprocs), NodeID: id, FailureDomain: domain, LinkMbit: linkMbit}
	nf.ProductUUIDHash = hash16(firstLine("/sys/class/dmi/id/product_uuid"))
	fsuuid := commandLine("findmnt", "-no", "UUID", "-T", dataDir)
	source := commandLine("findmnt", "-no", "SOURCE", "-T", dataDir)
	nf.FSUUIDHash = hash16(fsuuid)
	disk := strings.TrimPrefix(source, "/dev/")
	parent := commandLine("lsblk", "-no", "PKNAME", source)
	if parent != "" {
		disk = parent
	}
	serial := commandLine("lsblk", "-dno", "SERIAL", "/dev/"+disk)
	wwn := commandLine("lsblk", "-dno", "WWN", "/dev/"+disk)
	nf.DiskIDHash = hash16(fsuuid, serial, wwn)
	nf.DiskSizeBytes, _ = strconv.ParseInt(commandLine("lsblk", "-bdno", "SIZE", "/dev/"+disk), 10, 64)
	return nf
}

// node is the agent of one voter host.
type node struct {
	id                           uint64
	bin, root, dataDir, nodeJSON string
	publicPort                   int
	cert, key, ca                string
	cpus, memoryMax              string
	gomaxprocs                   int
	scope                        bool
	out                          string
	cg                           CgroupFacts
	client                       *http.Client

	mu     sync.Mutex
	cmd    *exec.Cmd
	done   chan struct{}
	exit   error
	events *os.File
	last   Sample
}

// memoryGuardKiB is the host's MemAvailable below which the harness kills the server rather than endanger other processes on the VM.
const memoryGuardKiB = 1536 * 1024

func (n *node) event(e Event) {
	e.TMS, e.Node = now(), n.id
	raw, _ := json.Marshal(e)
	n.mu.Lock()
	defer n.mu.Unlock()
	n.events.Write(append(raw, '\n'))
}

func (n *node) pid() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.cmd == nil {
		return 0
	}
	return n.cmd.Process.Pid
}

// start launches `soundpost serve --mode=distributed` in a cgroup v2 scope with the host shape of D90 (cgroup.go) and waits until its
// own /readyz answers 200 (quorum and applied backlog). A start that is not ready after the limit is a failure of the run.
func (n *node) start(limit time.Duration) (pid int, ready time.Duration) {
	serve := []string{"serve", "--mode=distributed", "--node-id", strconv.FormatUint(n.id, 10), "--cluster-config", n.nodeJSON, "--data-dir", n.dataDir,
		"--listen", "0.0.0.0:" + strconv.Itoa(n.publicPort), "--tls-cert", n.cert, "--tls-key", n.key, "--symbolicate-sandbox=off"}
	logf, err := os.OpenFile(filepath.Join(n.out, "server.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	must(err, "server log")
	var cmd *exec.Cmd
	if n.scope {
		unit := fmt.Sprintf("soundpost-node%d-%d-%d.scope", n.id, time.Now().Unix(), scopeSeq.Add(1))
		name, args := scopeCommand(n.cpus, n.memoryMax, unit, n.bin, serve)
		cmd = exec.Command(name, args...)
	} else {
		cmd = exec.Command("taskset", append([]string{"-c", n.cpus, n.bin}, serve...)...)
	}
	cmd.Env = append(os.Environ(), "GOMAXPROCS="+strconv.Itoa(n.gomaxprocs))
	cmd.Stdout, cmd.Stderr = logf, logf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	began := time.Now()
	must(cmd.Start(), "start soundpost serve")
	done := make(chan struct{})
	n.mu.Lock()
	n.cmd, n.done, n.exit = cmd, done, nil
	activePID.Store(int64(cmd.Process.Pid))
	n.mu.Unlock()
	go func() {
		err := cmd.Wait()
		n.mu.Lock()
		n.exit = err
		n.mu.Unlock()
		logf.Close()
		close(done)
	}()
	for time.Since(began) < limit {
		select {
		case <-done:
			fatalf("soundpost serve exited during start: %v", n.exit)
		default:
		}
		if resp, err := n.client.Get("https://127.0.0.1:" + strconv.Itoa(n.publicPort) + "/readyz"); err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				n.recordScope(cmd.Process.Pid)
				return cmd.Process.Pid, time.Since(began)
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	fatalf("soundpost serve not ready after %s", limit)
	return 0, 0
}

// recordScope reads the cgroup of the running server process and keeps it for host.json; with --scope it also refuses to go on unless
// that is the host shape of D90 (the harness would otherwise measure something else than the gate).
func (n *node) recordScope(pid int) {
	cg := readCgroup(pid)
	if n.scope {
		if err := cg.checkScope(); err != nil {
			fatalf("D90 host shape: %v", err)
		}
		if g := processGomaxprocs(pid); g != scopeGomaxprocs || n.gomaxprocs != scopeGomaxprocs {
			fatalf("D90 host shape: the server runs with GOMAXPROCS %d (flag %d), the gate needs %d", g, n.gomaxprocs, scopeGomaxprocs)
		}
	}
	n.mu.Lock()
	n.cg = cg
	n.mu.Unlock()
	n.event(Event{Event: "scope", PIDAfter: pid, Cgroup: &cg})
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

// signalAndWait sends sig to the exact PID of the server this agent started and reports how it exited.
func (n *node) signalAndWait(sig syscall.Signal) (exit string, took time.Duration) {
	n.mu.Lock()
	cmd, done := n.cmd, n.done
	n.mu.Unlock()
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
	n.mu.Lock()
	err := n.exit
	n.cmd = nil
	activePID.Store(0)
	n.mu.Unlock()
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

// leaders asks this node's own view of every Raft group (`soundpost membership status`, the operator socket in the data directory) who
// leads it and counts the leaderships by node id.
func (n *node) leaders() (by map[string]int, groups int, raw string, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, n.bin, "membership", "status", "--data-dir", n.dataDir).CombinedOutput()
	raw = string(out)
	if err != nil {
		return nil, 0, raw, fmt.Errorf("membership status: %w", err)
	}
	by = map[string]int{"1": 0, "2": 0, "3": 0}
	for _, l := range strings.Split(raw, "\n") {
		if !strings.HasPrefix(l, "group ") {
			continue
		}
		groups++
		for _, f := range strings.Fields(l) {
			if v, ok := strings.CutPrefix(f, "leader="); ok {
				by[v]++
			}
		}
	}
	return by, groups, raw, nil
}

// kill9 is the failure of the run: SIGKILL of the exact server PID (the caller decided which node by its leaderships), a pause during
// which the other two voters hold the quorum, then the restart of the same node from its own data directory. It answers when the restarted
// node is ready again.
func (n *node) kill9(down time.Duration) (killed, started Event) {
	before := n.pid()
	exit, took := n.signalAndWait(syscall.SIGKILL)
	killed = Event{Event: "kill9", Mode: "kill9", PIDBefore: before, Exit: exit, StopMS: took.Milliseconds()}
	n.event(killed)
	time.Sleep(down)
	pid, ready := n.start(10 * time.Minute)
	started = Event{Event: "start", Mode: "after_kill9", PIDBefore: before, PIDAfter: pid, ReadyMS: ready.Milliseconds(), DownMS: down.Milliseconds(), Cpus: cpusAllowed(pid)}
	n.event(started)
	return killed, started
}

// sample reads one monitor sample of the current server process (all zero numbers when it is not running).
func (n *node) sample(withData bool) Sample {
	pid := n.pid()
	sm := Sample{TMS: now(), PID: pid}
	if pid != 0 {
		sm.RSSKiB, sm.HWMKiB, sm.Threads = readProcStatus(pid)
		sm.IOWrite, sm.IORead, sm.IOWChar = readProcIO(pid)
		sm.UTime, sm.STime = readProcCPU(pid)
		if fds, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid)); err == nil {
			sm.FDs = len(fds)
		}
		n.mu.Lock()
		cgPath := n.cg.Path
		n.mu.Unlock()
		if n.scope && cgPath != "" { // the memory the scope is charged (page cache included), the kills its limit caused and the CPU it used
			cur, _ := strconv.ParseInt(cgroupFile(cgPath, "memory.current"), 10, 64)
			sm.CgMemKiB = cur / 1024
			for _, l := range strings.Split(cgroupFileAll(cgPath, "memory.events"), "\n") {
				if v, ok := strings.CutPrefix(l, "oom_kill "); ok {
					sm.CgOOMKill, _ = strconv.ParseUint(strings.TrimSpace(v), 10, 64)
				}
			}
			for _, l := range strings.Split(cgroupFileAll(cgPath, "cpu.stat"), "\n") {
				if v, ok := strings.CutPrefix(l, "usage_usec "); ok {
					sm.CgCPUUsec, _ = strconv.ParseUint(strings.TrimSpace(v), 10, 64)
				}
			}
		}
	}
	sm.CPUBusy, sm.CPUTotal, sm.MemAvailKiB, sm.Load1 = readSystem()
	sm.NetRxBytes, sm.NetTxBytes = readNet()
	sm.FSUsedPct = fsUsedPercent(n.dataDir)
	if withData {
		sm.DataBytes = dirBytes(n.dataDir)
	}
	return sm
}

func (n *node) monitor(ctx context.Context, path string, every time.Duration) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	must(err, "series file")
	defer f.Close()
	tick := time.NewTicker(every)
	defer tick.Stop()
	for i := 0; ; i++ {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		sm := n.sample(i%6 == 0)
		n.mu.Lock()
		n.last = sm
		n.mu.Unlock()
		// The VM is shared with other work: when the host is about to run out of memory the exact server PID is killed and the run is over
		// (recorded as an event), rather than let the kernel pick a victim among other tenants' processes.
		if sm.PID != 0 && sm.MemAvailKiB > 0 && sm.MemAvailKiB < memoryGuardKiB {
			n.event(Event{Event: "memory_guard", PIDBefore: sm.PID, Note: fmt.Sprintf("MemAvailable %d KiB below the guard of %d KiB with server VmRSS %d KiB: the server was killed", sm.MemAvailKiB, memoryGuardKiB, sm.RSSKiB)})
			syscall.Kill(sm.PID, syscall.SIGKILL)
		}
		raw, _ := json.Marshal(sm)
		f.Write(append(raw, '\n'))
	}
}

func (n *node) control(listen, token string, stop chan<- struct{}) {
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
	mux.HandleFunc("GET /state", guard(func(w http.ResponseWriter, r *http.Request) {
		n.mu.Lock()
		sm := n.last
		n.mu.Unlock()
		json.NewEncoder(w).Encode(sm)
	}))
	mux.HandleFunc("GET /ready", guard(func(w http.ResponseWriter, r *http.Request) {
		if n.pid() == 0 {
			http.Error(w, "not running", http.StatusServiceUnavailable)
			return
		}
		resp, err := n.client.Get("https://127.0.0.1:" + strconv.Itoa(n.publicPort) + "/readyz")
		if err != nil || resp.StatusCode != 200 {
			if resp != nil {
				resp.Body.Close()
			}
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		resp.Body.Close()
		fmt.Fprintln(w, "ready")
	}))
	mux.HandleFunc("GET /leaders", guard(func(w http.ResponseWriter, r *http.Request) {
		by, groups, raw, err := n.leaders()
		if err != nil {
			http.Error(w, err.Error()+": "+raw, http.StatusBadGateway)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"node": n.id, "groups": groups, "leaders": by})
	}))
	mux.HandleFunc("GET /membership", guard(func(w http.ResponseWriter, r *http.Request) {
		_, _, raw, err := n.leaders()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		fmt.Fprint(w, raw)
	}))
	mux.HandleFunc("GET /bundle", guard(func(w http.ResponseWriter, r *http.Request) {
		tw := tar.NewWriter(w)
		for _, name := range []string{"server-series.jsonl", "events.jsonl", "host.json", "server.log"} {
			raw, err := os.ReadFile(filepath.Join(n.out, name))
			if err != nil {
				continue
			}
			tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(raw)), ModTime: time.Now()})
			tw.Write(raw)
		}
		tw.Close()
	}))
	mux.HandleFunc("POST /kill9", guard(func(w http.ResponseWriter, r *http.Request) {
		down, err := time.ParseDuration(r.URL.Query().Get("down"))
		if err != nil || down < 0 || down > 10*time.Minute {
			http.Error(w, "down", http.StatusBadRequest)
			return
		}
		killed, started := n.kill9(down)
		json.NewEncoder(w).Encode(map[string]Event{"kill": killed, "start": started})
	}))
	mux.HandleFunc("POST /stop", guard(func(w http.ResponseWriter, r *http.Request) {
		exit, took := n.signalAndWait(syscall.SIGTERM)
		e := Event{Event: "stop", Mode: "graceful", Exit: exit, StopMS: took.Milliseconds()}
		n.event(e)
		json.NewEncoder(w).Encode(e)
		go func() { time.Sleep(200 * time.Millisecond); close(stop) }()
	}))
	go func() {
		if err := http.ListenAndServe(listen, mux); err != nil {
			fatalf("control listener: %v", err)
		}
	}()
}

func runNode(args []string) {
	f := flag.NewFlagSet("node", flag.ExitOnError)
	id := f.Uint64("node-id", 0, "raft id of this voter (1, 2 or 3)")
	bin := f.String("soundpost", "", "soundpost binary to serve")
	root := f.String("root", "", "node root: the bundle prepare made (node.json, cluster.seed, pki/) and the data directory data-<id> live here")
	out := f.String("out", "", "output directory for series, events, host facts and the server log")
	publicPort := f.Int("public-port", 8443, "public HTTPS port (the product listens on every address)")
	controlAddr := f.String("control-listen", "", "ip:port of the harness control endpoint")
	token := f.String("control-token", "", "token of the control endpoint (the one in plan.json)")
	cpus := f.String("cpus", "0-7", "CPU set of the scope (AllowedCPUs with --scope, taskset -c without)")
	gomax := f.Int("gomaxprocs", 8, "GOMAXPROCS of the server")
	scope := f.Bool("scope", false, "start the server in a cgroup v2 scope with the gate's limits (D90: systemd-run --scope, 8 CPUs, MemoryMax, no swap; needs root and --gomaxprocs 8)")
	memoryMax := f.String("memory-max", "16G", "MemoryMax of the scope with --scope (between 15,000 MiB and 16 GiB)")
	domain := f.String("failure-domain", "", "the operator's attestation of the hypervisor host and disk of this voter (the same string prepare put in the node configuration)")
	linkMbit := f.Int("link-mbit", 96, "the host link's rate limit in Mbit/s (stated by the lab, measured by the monitor against it)")
	sampleEvery := f.Duration("sample-every", 10*time.Second, "monitor period")
	f.Parse(args)
	if *id < 1 || *id > 3 || *bin == "" || *root == "" || *out == "" || *controlAddr == "" || *token == "" || *domain == "" {
		fatalf("--node-id (1..3), --soundpost, --root, --out, --control-listen, --control-token and --failure-domain are required")
	}
	if *scope && (*gomax != scopeGomaxprocs || *memoryMax == "") {
		fatalf("--scope is the gate's host shape (D90): it needs --gomaxprocs %d and a --memory-max", scopeGomaxprocs)
	}
	must(os.MkdirAll(*out, 0o755), "out dir")
	n := &node{id: *id, bin: *bin, root: *root, dataDir: filepath.Join(*root, fmt.Sprintf("data-%d", *id)), nodeJSON: filepath.Join(*root, "node.json"), publicPort: *publicPort,
		cert: filepath.Join(*root, "pki", fmt.Sprintf("public-%d.pem", *id)), key: filepath.Join(*root, "pki", fmt.Sprintf("public-%d.key", *id)), ca: filepath.Join(*root, "pki", "ca.pem"),
		cpus: *cpus, memoryMax: *memoryMax, gomaxprocs: *gomax, scope: *scope, out: *out}
	if entries, _ := os.ReadDir(n.dataDir); len(entries) > 0 {
		fatalf("data directory %s is not empty: the run needs a fresh product", n.dataDir)
	}
	must(os.MkdirAll(n.dataDir, 0o700), "data dir")
	pem, err := os.ReadFile(n.ca)
	must(err, "ca")
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	n.client = &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}, DisableKeepAlives: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	n.events, err = os.OpenFile(filepath.Join(*out, "events.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	must(err, "events file")

	// the control endpoint comes up first, so the caller can see the agent while the three voters are still forming their quorum.
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	stopped := make(chan struct{})
	n.control(*controlAddr, *token, stopped)
	pid, ready := n.start(10 * time.Minute)
	n.event(Event{Event: "start", Mode: "initial", PIDAfter: pid, ReadyMS: ready.Milliseconds(), Cpus: cpusAllowed(pid)})
	hf := nodeFacts(*id, n.dataDir, *domain, *linkMbit, *gomax)
	hf.CpusAllowed = cpusAllowed(pid) // the product process's own CPU set, not the harness's
	n.mu.Lock()
	hf.CgroupFacts = n.cg // read back from the scope of the running server (recordScope), never from the flags
	n.mu.Unlock()
	rawHF, _ := json.MarshalIndent(hf, "", " ")
	must(os.WriteFile(filepath.Join(*out, "host.json"), rawHF, 0o644), "host facts")
	go n.monitor(ctx, filepath.Join(*out, "server-series.jsonl"), *sampleEvery)
	fmt.Fprintf(os.Stderr, "distributed: node %d up pid %d\n", *id, pid)
	select {
	case <-stopped:
	case <-ctx.Done():
		exit, took := n.signalAndWait(syscall.SIGTERM)
		n.event(Event{Event: "stop", Mode: "graceful", Exit: exit, StopMS: took.Milliseconds(), Note: "harness interrupted"})
	}
}
