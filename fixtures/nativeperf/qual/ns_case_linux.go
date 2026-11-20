//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package qual

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/nativeperf"
)

// NSCanary is the privacy canary of the namespace cases: it is part of the directory name the target runs from, so any
// frame that leaked a path would carry it.
const NSCanary = "SOUNDPOST_NS_PATH_CANARY"

const (
	nsCaseEnv = "SPQUAL_NS_CASE"
	// nsSlackNs is how long after a transition's instant an event under the old identity may still be delivered: the
	// identity cadence (100 ms) plus scheduling margin. Events past it mean the transition was not noticed.
	nsSlackNs = 600_000_000
)

// NSSpec is one namespace case. The runner process executes it in whatever namespaces it was started in: that is the
// helper's side of the case.
type NSSpec struct {
	Name       string `json:"name"`
	Workload   string `json:"workload"` // compiled nsload, build A
	Variant    string `json:"variant"`  // compiled nsload, build B (a different GNU build ID)
	Transition string `json:"transition,omitempty"`
	// TargetSandbox starts the target in its own namespaces (the helper stays where the runner is).
	TargetSandbox *Sandbox `json:"target_sandbox,omitempty"`
	// Layer runs build B at the path where this runner (the host) sees build A: a bind mount in the target's mount namespace.
	Layer bool `json:"layer,omitempty"`
	// External names a target the outer process started and identified; the runner does not start one itself.
	External *NSExternal `json:"external,omitempty"`
	// OwnProc is the path where the runner's sandbox mounted this PID namespace's own proc (the case's /proc is the parent's).
	OwnProc string `json:"own_proc,omitempty"`
}

// NSExternal is a target the outer (host-view) process identified.
type NSExternal struct {
	Target nativeperf.Target `json:"target"`
	Facts  NSTarget          `json:"facts"`
}

// NSTarget is what the helper's view of the target looks like.
type NSTarget struct {
	PID          uint32   `json:"pid"`   // the PID in the helper's PID namespace (what /proc and perf_event_open use)
	NSpid        []uint32 `json:"nspid"` // /proc/<pid>/status NSpid, outermost (helper view) first
	PIDNS        uint64   `json:"pid_ns"`
	CgroupID     uint64   `json:"cgroup_id"`
	ProcessStart uint64   `json:"process_start"`
	BuildID      string   `json:"build_id"`
}

// NSTask is the count of CPU samples delivered under one TaskKey.
type NSTask struct {
	Key     nativeperf.TaskKey `json:"key"`
	CPU     int                `json:"cpu_samples"`
	FirstNs uint64             `json:"first_ns"`
	LastNs  uint64             `json:"last_ns"`
}

// NSSession is the observation of one capture through the real helper wire.
type NSSession struct {
	Label         string         `json:"label"`
	Mode          string         `json:"mode"`
	Ready         bool           `json:"ready"`
	ErrorCode     string         `json:"error_code,omitempty"`
	ReadError     string         `json:"read_error,omitempty"`
	ProvenThrough uint64         `json:"proven_through,omitempty"`
	TransitionNs  uint64         `json:"transition_ns,omitempty"`
	CPU           int            `json:"cpu"`
	Switch        int            `json:"switch"`
	TargetSwitch  int            `json:"target_switch"` // switches that name a task of the authorized process
	Wakeup        int            `json:"wakeup"`
	Tasks         []NSTask       `json:"tasks,omitempty"`
	Builds        []string       `json:"builds,omitempty"` // distinct module build IDs frames resolved to
	Resolved      int            `json:"resolved_frames"`
	Unresolved    map[string]int `json:"unresolved_frames,omitempty"`
	Leaks         int            `json:"canary_hits"`
	LateOld       int            `json:"events_after_transition_slack"`
	GuardRetired  bool           `json:"old_guard_retired"`
}

// NSRecord is everything one case observed.
type NSRecord struct {
	Name         string            `json:"name"`
	Kernel       string            `json:"kernel"`
	CgroupMode   string            `json:"cgroup_mode"`
	HelperPIDNS  uint64            `json:"helper_pid_ns"`
	HelperInit   bool              `json:"helper_in_initial_pid_ns"`
	Target       NSTarget          `json:"target"`
	ProbeCPU     string            `json:"probe_cpu,omitempty"`
	ProbeOffCPU  string            `json:"probe_off_cpu,omitempty"`
	ProbeReasons []string          `json:"probe_reasons,omitempty"`
	Sessions     []NSSession       `json:"sessions"`
	Facts        map[string]string `json:"facts,omitempty"`
	Error        string            `json:"error,omitempty"`
}

// CgroupMode reports how this host mounts cgroups: "v2" (unified at /sys/fs/cgroup), "hybrid" (v1 controllers plus a
// unified mount) or "v1".
func CgroupMode() string {
	info, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return "unknown"
	}
	v2, v1 := map[string]bool{}, false
	for _, line := range strings.Split(string(info), "\n") {
		head, tail, ok := strings.Cut(line, " - ")
		if !ok {
			continue
		}
		f, a := strings.Fields(head), strings.Fields(tail)
		if len(f) < 5 || len(a) < 1 {
			continue
		}
		switch a[0] {
		case "cgroup2":
			v2[f[4]] = true
		case "cgroup":
			v1 = true
		}
	}
	switch {
	case v2["/sys/fs/cgroup"] && !v1:
		return "v2"
	case len(v2) > 0 && v1:
		return "hybrid"
	case len(v2) > 0:
		return "v2"
	case v1:
		return "v1"
	}
	return "none"
}

func pidNamespaceInode(pid string) (uint64, error) {
	st, err := os.Stat("/proc/" + pid + "/ns/pid")
	if err != nil {
		return 0, err
	}
	return st.Sys().(*syscall.Stat_t).Ino, nil
}

// parseNSpid reads the NSpid line of a /proc/<pid>/status.
func parseNSpid(status []byte) []uint32 {
	for _, line := range bytes.Split(status, []byte{'\n'}) {
		if !bytes.HasPrefix(line, []byte("NSpid:")) {
			continue
		}
		var out []uint32
		for _, f := range bytes.Fields(line[6:]) {
			n, err := strconv.ParseUint(string(f), 10, 32)
			if err != nil {
				return nil
			}
			out = append(out, uint32(n))
		}
		return out
	}
	return nil
}

type nsProc struct {
	cmd   *exec.Cmd
	stdin io.WriteCloser
	lines chan string
	pid   int
	done  chan struct{}
}

func startNSProc(cmd *exec.Cmd) (*nsProc, error) {
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err = cmd.Start(); err != nil {
		return nil, err
	}
	p := &nsProc{cmd: cmd, stdin: stdin, lines: make(chan string, 64), pid: cmd.Process.Pid, done: make(chan struct{})}
	go func() {
		sc := bufio.NewScanner(out)
		for sc.Scan() {
			p.lines <- sc.Text()
		}
		close(p.lines)
	}()
	go func() { cmd.Wait(); close(p.done) }()
	if err = p.expect("ready", 15*time.Second); err != nil {
		p.kill()
		return nil, fmt.Errorf("%w (stderr: %s)", err, strings.TrimSpace(stderr.String()))
	}
	return p, nil
}

// expect waits for a line starting with prefix.
func (p *nsProc) expect(prefix string, d time.Duration) error {
	timeout := time.After(d)
	for {
		select {
		case line, ok := <-p.lines:
			if !ok {
				return errors.New("process ended before " + prefix)
			}
			if strings.HasPrefix(line, prefix) {
				return nil
			}
		case <-timeout:
			return errors.New("timeout waiting for " + prefix)
		}
	}
}

func (p *nsProc) command(line, ack string) error {
	if _, err := io.WriteString(p.stdin, line+"\n"); err != nil {
		return err
	}
	return p.expect(ack, 10*time.Second)
}

func (p *nsProc) kill() {
	p.cmd.Process.Kill()
	<-p.done
}

type nsRunner struct {
	spec    NSSpec
	ctx     context.Context
	dir     string // scratch directory; its name carries the canary
	hostApp string // path the helper side sees the target binary at
	layer   string
	rec     *NSRecord
	cleanup []func()
	targets []*nsProc
	sidecar *nsProc
}

func copyFile(src, dst string, mode os.FileMode) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, b, mode)
}

// RunNSCase executes one case in the namespaces this process is in.
func RunNSCase(ctx context.Context, spec NSSpec) (rec NSRecord) {
	rec = NSRecord{Name: spec.Name, Kernel: KernelRelease(), CgroupMode: CgroupMode(), Facts: map[string]string{}}
	if ns, err := pidNamespaceInode("self"); err == nil {
		rec.HelperPIDNS = ns
		rec.HelperInit = ns == 0xEFFFFFFC
	}
	r := &nsRunner{spec: spec, ctx: ctx, rec: &rec}
	defer func() {
		for i := len(r.cleanup) - 1; i >= 0; i-- {
			r.cleanup[i]()
		}
	}()
	if err := r.run(); err != nil {
		rec.Error = err.Error()
	}
	return rec
}

func (r *nsRunner) run() error {
	dir, err := os.MkdirTemp("", NSCanary+"-")
	if err != nil {
		return err
	}
	r.cleanup = append(r.cleanup, func() { os.RemoveAll(dir) })
	os.Chmod(dir, 0o755)
	r.dir = dir
	r.hostApp = filepath.Join(dir, "app")
	if err = copyFile(r.spec.Workload, r.hostApp, 0o755); err != nil {
		return err
	}
	if id, e := BuildIDOf(r.hostApp); e == nil {
		r.rec.Facts["host_path_build_id"] = id
	}
	if id, e := BuildIDOf(r.spec.Variant); e == nil {
		r.rec.Facts["variant_build_id"] = id
	}
	if r.spec.Layer {
		r.layer = filepath.Join(dir, "layer")
		if err = os.MkdirAll(r.layer, 0o755); err != nil {
			return err
		}
		if err = copyFile(r.spec.Variant, filepath.Join(r.layer, "app"), 0o755); err != nil {
			return err
		}
	}
	switch r.spec.Name {
	case "proc_view_mismatch":
		return r.procViewMismatch()
	case "pid_reuse_cross_ns":
		return r.pidReuseCrossNS()
	}
	return r.standard()
}

func (r *nsRunner) launchTarget(args ...string) (*nsProc, error) {
	var cmd *exec.Cmd
	var err error
	sb := r.spec.TargetSandbox
	if sb != nil {
		s := *sb
		if r.spec.Layer {
			s.Binds = append(append([]SandboxBind(nil), s.Binds...), SandboxBind{Src: filepath.Join(r.layer, "app"), Dst: r.hostApp})
		}
		if cmd, err = s.Command(r.hostApp, args...); err != nil {
			return nil, err
		}
	} else {
		cmd = exec.Command(r.hostApp, args...)
	}
	p, err := startNSProc(cmd)
	if err != nil {
		return nil, err
	}
	r.targets = append(r.targets, p)
	r.cleanup = append(r.cleanup, func() { p.kill() })
	return p, nil
}

// procDiag is a short description of how this process sees pid, for the error text of a case that could not be set up.
func procDiag(pid int) string {
	var parts []string
	if info, err := os.ReadFile("/proc/self/mountinfo"); err == nil {
		for _, line := range strings.Split(string(info), "\n") {
			if strings.Contains(line, " cgroup2 ") || strings.Contains(line, " proc proc ") {
				parts = append(parts, strings.TrimSpace(line))
			}
		}
	}
	if cg, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cgroup"); err == nil {
		parts = append(parts, "cgroup "+strings.ReplaceAll(strings.TrimSpace(string(cg)), "\n", "|"))
	}
	exe, err := os.Readlink("/proc/" + strconv.Itoa(pid) + "/exe")
	parts = append(parts, fmt.Sprintf("exe %q err %v", exe, err))
	return strings.Join(parts, "; ")
}

// identify reads the helper-side identity of the target with pid (a PID of this process's PID namespace).
func identify(pid int) (nativeperf.Target, NSTarget, error) {
	var facts NSTarget
	t, err := nativeperf.ResolveLocalTarget(pid)
	if err != nil {
		link, _ := os.Readlink("/proc/" + strconv.Itoa(pid) + "/ns/pid")
		stat, _ := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
		if len(stat) > 120 {
			stat = stat[:120]
		}
		return t, facts, fmt.Errorf("resolve target %d: %w (ns link %q, stat %q)", pid, err, link, stat)
	}
	cg, err := nativeperf.ResolveCgroupID(pid)
	if err != nil {
		return t, facts, fmt.Errorf("resolve cgroup identity: %w (%s)", err, procDiag(pid))
	}
	build, err := BuildIDOf("/proc/" + strconv.Itoa(pid) + "/exe")
	if err != nil {
		return t, facts, fmt.Errorf("target build id: %w (%s)", err, procDiag(pid))
	}
	t.CgroupID = model.Uint64(cg)
	t.AllowedBuildIDs = []string{build}
	status, _ := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
	facts = NSTarget{PID: t.TGID, NSpid: parseNSpid(status), PIDNS: uint64(t.PIDNamespace), CgroupID: cg, ProcessStart: uint64(t.ProcessStart), BuildID: build}
	return t, facts, nil
}

func (r *nsRunner) probe(t nativeperf.Target) {
	t.CgroupID, t.AllowedBuildIDs = 0, nil
	caps, err := nativeperf.Probe(r.ctx, []nativeperf.Target{t})
	r.rec.ProbeCPU, r.rec.ProbeOffCPU = string(caps.CPU), string(caps.OffCPU)
	for _, reason := range caps.Reasons {
		r.rec.ProbeReasons = append(r.rec.ProbeReasons, string(reason))
	}
	if err != nil && caps.CPU != nativeperf.Supported {
		r.rec.Facts["probe_error"] = err.Error()
	}
}

type sessionOpts struct {
	label   string
	mode    nativeperf.CaptureMode
	target  nativeperf.Target
	need    int          // progress events (CPU samples; with the scheduler also switches) before the trigger fires / the session ends
	trigger func() error // the transition; run once, when need is reached
	drain   time.Duration
}

type guardedNSSource struct {
	nativeperf.EventSource
	reader *nativeperf.MappingReader
}

func (s *guardedNSSource) Next(ctx context.Context) (nativeperf.SanitizedEvent, error) {
	if e := s.reader.Guard(); e != nil {
		return nativeperf.SanitizedEvent{}, e
	}
	event, e := s.EventSource.Next(ctx)
	if e != nil {
		if errors.Is(e, nativeperf.ErrTargetIdentity) || errors.Is(e, nativeperf.ErrThreadCoverageChanged) {
			_ = s.reader.Invalidate(2)
		}
		return nativeperf.SanitizedEvent{}, e
	}
	if e = s.reader.Guard(); e != nil {
		return nativeperf.SanitizedEvent{}, e
	}
	return event, nil
}
func (s *guardedNSSource) Close() error { e := s.EventSource.Close(); s.reader.Close(); return e }

type nsActive struct {
	reader *nativeperf.MappingReader
	table  nativeperf.MappingTable
}

// nsRaceResidentBytes is the resident size the in-process helper of a case reports for itself in a race-instrumented binary:
// half the product budget, above the 25.6 MB the same code measured as an embedded helper without the detector (the privacy
// fixture, nativeperf.measuredSharedProcessRSS) and the 19.5 to 25.7 MB this very test binary measured built without -race
// (6.1.0-54), and it leaves the budget more than the largest scheduler capture of an 8-CPU host needs.
const nsRaceResidentBytes = nativeperf.MaxMemoryBytes / 2

// nsResidentReader is the resident-size reader of the helper of one case. The real /proc reader (nil) is what the product
// measures and what every build uses, except a race-instrumented one: there the detector's own memory (its runtime's bss, the
// shadow of every touched page, a larger binary, and on a host with transparent huge pages "always" 16 to 20 MB of huge pages
// it maps before the first line of Go runs) put the process at 43 to 45 MB before the first capture and 59 to 61 MB after a
// few (6.6.162 and 6.1.0-54), so the 64 MiB budget refused the capture of a plain workload as resource_limit for a reason
// that is not the product's. The cases judge identity and namespace behaviour, not this accounting, which the non-race runs,
// the acceptance runner and the budget tests measure against the real size.
func nsResidentReader() func(int) (uint64, error) {
	if !raceBuild {
		return nil
	}
	return func(int) (uint64, error) { return nsRaceResidentBytes, nil }
}

// session runs one capture through the real helper (wire protocol, signed grant, mapping reader for CPU mode) and records
// what it delivered. It never fails the case itself: judging is separate (judgeNSRecord).
func (r *nsRunner) session(o sessionOpts) NSSession {
	s := NSSession{Label: o.label, Mode: string(o.mode)}
	fail := func(msg string) NSSession {
		if s.ReadError == "" {
			s.ReadError = msg
		}
		return s
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fail("key")
	}
	cfg := nativeperf.DefaultConfig(1)
	targets := []nativeperf.Target{o.target}
	uid := uint32(os.Getuid())
	grant, err := nativeperf.SignStart(nativeperf.StartAuthorization{Installation: "ns-case", UID: uid, Revision: 1, Expires: time.Now().Add(time.Minute).Unix(), Targets: targets, Config: cfg, Mode: o.mode}, priv)
	if err != nil {
		return fail("sign")
	}
	sockPath := filepath.Join(os.TempDir(), fmt.Sprintf("soundpost-nscase-%d-%d.sock", os.Getpid(), time.Now().UnixNano()))
	defer os.Remove(sockPath)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: sockPath, Net: "unix"})
	if err != nil {
		return fail("listen: " + err.Error())
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(r.ctx, 20*time.Second)
	defer cancel()
	state := make(chan nsActive, 1)
	helper := nativeperf.Helper{Policy: nativeperf.OperatorPolicy{Installation: "ns-case", UID: uid, Revision: 1, PublicKey: pub, Allowlist: targets}, Budget: nativeperf.NewResourceBudget(), Acquire: func(ctx context.Context, a nativeperf.AuthorizedTargets, c nativeperf.Config, res *nativeperf.Reservation) (nativeperf.EventSource, error) {
		if o.mode != nativeperf.ModeCPU {
			return nativeperf.NewNativeAcquisition(ctx, a, c, res)
		}
		policy := nativeperf.DefaultSymbolPolicy(uint64(c.PolicyRevision))
		policy.AllowMappedELF = true
		reader, e := nativeperf.NewMappingReader(a, o.target, 1, policy)
		if e != nil {
			return nil, e
		}
		table, e := reader.Read(ctx)
		if e != nil {
			reader.Close()
			return nil, e
		}
		source, e := nativeperf.NewCPUAcquisition(ctx, a, c, res)
		if e != nil {
			reader.Close()
			return nil, e
		}
		state <- nsActive{reader, table}
		return &guardedNSSource{source, reader}, nil
	}}
	helper.UseResidentSizeReader(nsResidentReader())
	go helper.Serve(ctx, listener)
	conn, err := net.DialUnix("unix", nil, listener.Addr().(*net.UnixAddr))
	if err != nil {
		return fail("dial")
	}
	defer conn.Close()
	request, _ := json.Marshal(nativeperf.CaptureRequest{Authorization: grant, Targets: targets, Config: cfg, Mode: o.mode})
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(request)))
	conn.SetDeadline(time.Now().Add(20 * time.Second))
	if _, err = conn.Write(append(length[:], request...)); err != nil {
		return fail("write request")
	}
	type frameMsg struct {
		reply wireReply
		raw   []byte
		err   error
	}
	frames := make(chan frameMsg, 64)
	quit := make(chan struct{})
	defer close(quit)
	conn.SetDeadline(time.Time{})
	go func() {
		for {
			reply, raw, err := readFrame(conn)
			select {
			case frames <- frameMsg{reply, raw, err}:
			case <-quit:
				return
			}
			if err != nil {
				return
			}
		}
	}()
	var active nsActive
	tasks := map[nativeperf.TaskKey]*NSTask{}
	builds := map[string]bool{}
	s.Unresolved = map[string]int{}
	progress, triggered := 0, false
	var triggeredAt time.Time
	deadline := time.Now().Add(18 * time.Second)
	canary := []byte(NSCanary)
	for time.Now().Before(deadline) {
		if triggered && o.drain > 0 && time.Since(triggeredAt) >= o.drain {
			break
		}
		if !triggered && o.trigger == nil && progress >= o.need && o.need > 0 {
			break
		}
		var m frameMsg
		select {
		case m = <-frames:
		case <-time.After(300 * time.Millisecond):
			continue
		}
		reply, raw, err := m.reply, m.raw, m.err
		if err != nil {
			if !s.Ready {
				s.ReadError = "no ready frame: " + err.Error()
			} else if s.ErrorCode == "" {
				head := raw
				if len(head) > 160 {
					head = head[:160]
				}
				s.ReadError = fmt.Sprintf("stream closed: %v frame %q", err, head)
			}
			break
		}
		if bytes.Contains(raw, canary) {
			s.Leaks++
		}
		if reply.Error != "" {
			s.ErrorCode, s.ProvenThrough = reply.Error, uint64(reply.ProvenThrough)
			if active.reader != nil {
				s.GuardRetired = active.reader.Guard() != nil
			}
			break
		}
		if reply.Ready {
			s.Ready = true
			if o.mode == nativeperf.ModeCPU {
				select {
				case active = <-state:
				case <-ctx.Done():
					return fail("mapping setup missing")
				}
			}
			continue
		}
		ev := reply.Event
		if ev == nil {
			continue
		}
		now := uint64(ev.Time)
		switch {
		case ev.CPUEvent != nil:
			s.CPU++
			progress++
			t := tasks[ev.Task]
			if t == nil {
				t = &NSTask{Key: ev.Task, FirstNs: now}
				tasks[ev.Task] = t
			}
			t.CPU++
			t.LastNs = now
			if s.TransitionNs != 0 && now > s.TransitionNs+nsSlackNs {
				s.LateOld++
			}
			if active.reader != nil {
				if obs, e := nativeperf.ResolveCPUObservation(ctx, ev.Task, *ev.CPUEvent, active.table, nil); e == nil {
					for _, f := range obs.Frames {
						if f.Module != nil {
							s.Resolved++
							builds[f.Module.BuildID] = true
						} else {
							s.Unresolved[string(f.Reason)]++
						}
					}
				} else {
					s.Unresolved["resolve_error"]++
				}
			}
		case ev.Switch != nil:
			s.Switch++
			progress++
			for _, k := range []*nativeperf.TaskKey{ev.Switch.Previous, ev.Switch.Next} {
				if k != nil && k.TGID == o.target.TGID {
					s.TargetSwitch++
					break
				}
			}
		case ev.Wakeup != nil:
			s.Wakeup++
		}
		if !triggered && o.trigger != nil && progress >= o.need {
			if err := o.trigger(); err != nil {
				return fail("transition: " + err.Error())
			}
			triggered, triggeredAt = true, time.Now()
			s.TransitionNs = MonotonicNow()
		}
	}
	for _, t := range tasks {
		s.Tasks = append(s.Tasks, *t)
	}
	for b := range builds {
		s.Builds = append(s.Builds, b)
	}
	sortTasks(s.Tasks)
	sortStrings(s.Builds)
	return s
}

func sortTasks(t []NSTask) {
	for i := 1; i < len(t); i++ {
		for j := i; j > 0 && t[j].FirstNs < t[j-1].FirstNs; j-- {
			t[j], t[j-1] = t[j-1], t[j]
		}
	}
}
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// cgroup2Path returns the mount point of the host's cgroup v2 hierarchy root.
func cgroup2Path() (string, error) {
	for _, p := range []string{"/sys/fs/cgroup", "/sys/fs/cgroup/unified"} {
		var fs syscall.Statfs_t
		if syscall.Statfs(p, &fs) == nil && uint64(fs.Type) == 0x63677270 {
			return p, nil
		}
	}
	return "", errors.New("no cgroup v2 mount")
}

func (r *nsRunner) standard() error {
	var target *nsProc
	var err error
	if r.spec.Transition == "mount_ns_swap" {
		// the sidecar's mount namespace has build B at the path where the target's namespace has build A
		sc := Sandbox{Mount: true, Binds: []SandboxBind{{Src: filepath.Join(r.layerDir(), "app"), Dst: r.hostApp}}}
		cmd, err := sc.Command(r.spec.Workload, "idle")
		if err != nil {
			return err
		}
		car, err := startNSProc(cmd)
		if err != nil {
			return fmt.Errorf("sidecar: %w", err)
		}
		r.cleanup = append(r.cleanup, car.kill)
		r.rec.Facts["sidecar_pid"] = strconv.Itoa(car.pid)
		r.sidecar = car
	}
	if target, err = r.launchTarget(); err != nil {
		return fmt.Errorf("start target: %w", err)
	}
	t, facts, err := identify(target.pid)
	if err != nil {
		return err
	}
	r.rec.Target = facts
	r.probe(t)
	mode := nativeperf.ModeCPU
	var trig func() error
	drain := time.Duration(0)
	switch r.spec.Transition {
	case "exec":
		trig = func() error { return target.command("exec", "ready after") }
	case "cgroup_move":
		trig = r.cgroupMove(target.pid)
	case "deleted_replaced":
		trig, drain = r.replaceBinary, 1500*time.Millisecond
	case "mount_unshare":
		// the target itself moves into a new mount namespace (a container workload that unshares between phases)
		trig, drain = func() error { return target.command("unshare-mnt", "ack unshare-mnt") }, 1500*time.Millisecond
	case "mount_ns_swap":
		trig, drain = func() error {
			return target.command("setns /proc/"+strconv.Itoa(r.sidecar.pid)+"/ns/mnt", "ack setns")
		}, 1500*time.Millisecond
	case "":
	default:
		return errors.New("unknown transition " + r.spec.Transition)
	}
	if r.spec.Transition == "" {
		drain = 0
	}
	r.rec.Sessions = append(r.rec.Sessions, r.session(sessionOpts{label: "capture", mode: mode, target: t, need: 8, trigger: trig, drain: drain}))
	switch r.spec.Transition {
	case "":
		// the scheduler path against the same target, in the same namespaces
		r.rec.Sessions = append(r.rec.Sessions, r.session(sessionOpts{label: "scheduler", mode: nativeperf.ModeCPUOffCPU, target: t, need: 12}))
	case "cgroup_move", "deleted_replaced", "mount_ns_swap", "mount_unshare":
		// a fresh authorization with the identity the operator granted before the transition
		r.rec.Sessions = append(r.rec.Sessions, r.session(sessionOpts{label: "after_transition_old_identity", mode: nativeperf.ModeCPU, target: t, need: 6}))
	}
	return nil
}

func (r *nsRunner) layerDir() string {
	d := filepath.Join(r.dir, "layer")
	os.MkdirAll(d, 0o755)
	if _, err := os.Stat(filepath.Join(d, "app")); err != nil {
		copyFile(r.spec.Variant, filepath.Join(d, "app"), 0o755)
	}
	return d
}

// replaceBinary unlinks the running executable's path and creates a different build at the same path (a container layer
// update under a running process): the process keeps the old inode, the path now names another file.
func (r *nsRunner) replaceBinary() error {
	tmp := r.hostApp + ".new"
	if err := copyFile(r.spec.Variant, tmp, 0o755); err != nil {
		return err
	}
	return os.Rename(tmp, r.hostApp)
}

// cgroupMove moves the target to a new cgroup of the unified hierarchy; the cgroup is removed again when the case ends.
func (r *nsRunner) cgroupMove(pid int) func() error {
	return func() error {
		root, err := cgroup2Path()
		if err != nil {
			return err
		}
		dir := filepath.Join(root, "l4w33-nscase-"+strconv.Itoa(os.Getpid()))
		if err = os.Mkdir(dir, 0o755); err != nil {
			return err
		}
		// Cleanups run last-registered first, and the target is a member of this cgroup until its own cleanup kills it, so this
		// one goes to the front of the list: it runs after every process of the case is gone (an empty cgroup is removable).
		remove := func() {
			for range 50 {
				if syscall.Rmdir(dir) == nil {
					return
				}
				time.Sleep(20 * time.Millisecond)
			}
		}
		r.cleanup = append([]func(){remove}, r.cleanup...)
		return os.WriteFile(filepath.Join(dir, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0o644)
	}
}

// pidReuseCrossNS: this runner is the first process of a PID namespace L1 with its own /proc (so ns_last_pid is L1's).
// The target lives in a child namespace L2 and has a PID in L1. When it dies, a new process in L1 itself is given the same
// numeric PID: same helper-view PID, different PID namespace, different start.
func (r *nsRunner) pidReuseCrossNS() error {
	if r.rec.HelperInit {
		return errors.New("refusing to steer ns_last_pid in the initial PID namespace")
	}
	sb := Sandbox{PID: true, Mount: true, ProcFS: true, UTS: true, IPC: true}
	r.spec.TargetSandbox = &sb
	target, err := r.launchTarget()
	if err != nil {
		return fmt.Errorf("start target: %w", err)
	}
	t, facts, err := identify(target.pid)
	if err != nil {
		return err
	}
	r.rec.Target = facts
	var reuser *nsProc
	trig := func() error {
		target.kill()
		for attempt := 0; attempt < 8; attempt++ {
			if err := os.WriteFile("/proc/sys/kernel/ns_last_pid", []byte(strconv.Itoa(target.pid-1)+"\n"), 0); err != nil {
				return err
			}
			cmd := exec.Command(r.hostApp)
			p, err := startNSProc(cmd)
			if err != nil {
				return err
			}
			if p.pid == target.pid {
				reuser = p
				r.cleanup = append(r.cleanup, p.kill)
				r.rec.Facts["reuse_attempts"] = strconv.Itoa(attempt + 1)
				return nil
			}
			p.kill()
		}
		return errors.New("the kernel did not hand out the same PID again")
	}
	r.rec.Sessions = append(r.rec.Sessions, r.session(sessionOpts{label: "capture", mode: nativeperf.ModeCPU, target: t, need: 6, trigger: trig, drain: 300 * time.Millisecond}))
	if reuser == nil {
		return errors.New("no PID reuse achieved")
	}
	r.rec.Sessions = append(r.rec.Sessions, r.session(sessionOpts{label: "after_transition_old_identity", mode: nativeperf.ModeCPU, target: t, need: 4}))
	t2, facts2, err := identify(reuser.pid)
	if err != nil {
		return err
	}
	r.rec.Facts["reuser_pid"] = strconv.Itoa(reuser.pid)
	r.rec.Facts["reuser_pid_ns"] = strconv.FormatUint(facts2.PIDNS, 10)
	r.rec.Facts["reuser_process_start"] = strconv.FormatUint(facts2.ProcessStart, 10)
	r.rec.Sessions = append(r.rec.Sessions, r.session(sessionOpts{label: "reuser", mode: nativeperf.ModeCPU, target: t2, need: 6}))
	return nil
}

// procViewMismatch: the helper (this runner) is in a nested PID namespace but its /proc is still the parent's, the
// misconfiguration of a container that unshares the PID namespace and forgets to mount its own proc. perf_event_open and
// pidfd_open resolve PIDs in the helper's namespace, /proc in the parent's: the target the operator authorized (an idle
// process of the parent's namespace) and the process the kernel would attach to (a busy one that holds the same number in
// the nested namespace) are different processes.
func (r *nsRunner) procViewMismatch() error {
	ext := r.spec.External
	if ext == nil || r.spec.OwnProc == "" {
		return errors.New("proc_view_mismatch needs an external target and a sandbox with its own proc")
	}
	own := r.spec.OwnProc
	r.rec.Target = ext.Facts
	n := int(ext.Target.TGID)
	if n < 3 {
		return errors.New("target PID too small to collide")
	}
	var decoy *nsProc
	for attempt := 0; attempt < 8 && decoy == nil; attempt++ {
		if err := os.WriteFile(filepath.Join(own, "sys/kernel/ns_last_pid"), []byte(strconv.Itoa(n-1)+"\n"), 0); err != nil {
			return fmt.Errorf("steer nested ns_last_pid: %w (%s)", err, procDiag(n))
		}
		p, err := startNSProc(exec.Command(r.hostApp))
		if err != nil {
			return err
		}
		if p.pid == n {
			decoy = p
			r.cleanup = append(r.cleanup, p.kill)
		} else {
			p.kill()
		}
	}
	if decoy == nil {
		return errors.New("could not give a nested process the target's number")
	}
	// the two processes are told apart by their PID namespace links (a start-time comparison can tie within one clock tick)
	ownNS, ownErr := os.Readlink(filepath.Join(own, strconv.Itoa(n), "ns/pid"))
	hostNS, hostErr := os.Readlink("/proc/" + strconv.Itoa(n) + "/ns/pid")
	r.rec.Facts["nested_process_pid"] = strconv.Itoa(decoy.pid)
	r.rec.Facts["views_differ"] = strconv.FormatBool(ownErr == nil && hostErr == nil && ownNS != hostNS && hostNS == "pid:["+strconv.FormatUint(ext.Facts.PIDNS, 10)+"]")
	r.rec.Sessions = append(r.rec.Sessions, r.session(sessionOpts{label: "capture", mode: nativeperf.ModeCPU, target: ext.Target, need: 4}))
	return nil
}

func startField(stat []byte) []byte {
	end := bytes.LastIndexByte(stat, ')')
	if end < 0 {
		return nil
	}
	f := bytes.Fields(stat[end+1:])
	if len(f) < 20 {
		return nil
	}
	return f[19]
}

// ---- the in-sandbox role ----

func init() {
	// The sandbox's own init (ns_sandbox_linux.go) must mount first: it re-executes this binary with these variables intact.
	if os.Getenv(sandboxInitEnv) != "" {
		return
	}
	if os.Getenv(nsProbeEnv) != "" {
		os.Exit(0) // NSPrerequisites: the sandbox could be created and its init ran
	}
	if os.Getenv(nsAllEnv) != "" {
		os.Unsetenv(nsAllEnv)
		// this process is the runner (the process whose resident size every capture's admission charges), so it opts out of
		// transparent huge pages first, as the acceptance and overhead runners do (D40): its resident size then does not depend
		// on the host's THP mode. A race-instrumented binary is not helped enough by this (the detector maps its huge pages
		// before any Go code runs): nsResidentReader is what keeps its admission off the detector's footprint.
		if err := DisableTransparentHugePages(); err != nil {
			fmt.Fprintln(os.Stderr, "ns cases: transparent huge pages left on:", err)
		}
		if err := json.NewEncoder(os.Stdout).Encode(RunNSCases(context.Background())); err != nil {
			os.Exit(3)
		}
		os.Exit(0)
	}
	raw := os.Getenv(nsCaseEnv)
	if raw == "" {
		return
	}
	os.Unsetenv(nsCaseEnv)
	var spec NSSpec
	if json.Unmarshal([]byte(raw), &spec) != nil {
		fmt.Fprintln(os.Stderr, "ns case: bad spec")
		os.Exit(2)
	}
	rec := RunNSCase(context.Background(), spec)
	if err := json.NewEncoder(os.Stdout).Encode(rec); err != nil {
		os.Exit(3)
	}
	os.Exit(0)
}

// RunNSCaseIn runs the case with its helper side inside sb: this binary is started as the first process of the sandbox and
// prints the record. The caller's namespaces are the "host" view.
func RunNSCaseIn(ctx context.Context, sb Sandbox, spec NSSpec) NSRecord {
	rec := NSRecord{Name: spec.Name}
	self, err := os.Executable()
	if err != nil {
		rec.Error = err.Error()
		return rec
	}
	raw, _ := json.Marshal(spec)
	cmd, err := sb.Command(self)
	if err != nil {
		rec.Error = err.Error()
		return rec
	}
	cmd.Env = append(cmd.Env, nsCaseEnv+"="+string(raw))
	var out, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &stderr
	if err = cmd.Start(); err != nil {
		rec.Error = err.Error()
		return rec
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err = <-done:
	case <-ctx.Done():
		cmd.Process.Kill()
		<-done
		rec.Error = "case timed out"
		return rec
	case <-time.After(90 * time.Second):
		cmd.Process.Kill()
		<-done
		rec.Error = "case timed out"
		return rec
	}
	if err != nil || json.Unmarshal(out.Bytes(), &rec) != nil {
		rec.Error = fmt.Sprintf("sandbox case failed: %v: %s", err, strings.TrimSpace(stderr.String()))
	}
	return rec
}

// RunAttach captures a target that already runs and is visible in this process's /proc (a workload of another container
// whose PID namespace this process joined, or of the host when this process has the host PID namespace): the target is found
// by the exact path of its executable as the kernel reports it (/proc/<pid>/exe), identified from this process's view and
// captured through the real helper, CPU and scheduler. This is the shape of the Compose recipe (pid: container:<workload>)
// and of the DaemonSet recipe (hostPID).
func RunAttach(ctx context.Context, exePath string) NSRecord {
	rec := NSRecord{Name: "attach", Kernel: KernelRelease(), CgroupMode: CgroupMode(), Facts: map[string]string{"exe": filepath.Base(exePath)}}
	if ns, err := pidNamespaceInode("self"); err == nil {
		rec.HelperPIDNS, rec.HelperInit = ns, ns == 0xEFFFFFFC
	}
	rec.Facts["tracefs"] = "unreadable"
	for _, p := range []string{"/sys/kernel/tracing/events/sched", "/sys/kernel/debug/tracing/events/sched"} {
		if _, err := os.ReadDir(p); err == nil {
			rec.Facts["tracefs"] = "readable"
		}
	}
	r := &nsRunner{ctx: ctx, rec: &rec}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		rec.Error = err.Error()
		return rec
	}
	pid := 0
	for _, e := range entries {
		n, err := strconv.Atoi(e.Name())
		if err != nil || n <= 0 {
			continue
		}
		if link, err := os.Readlink("/proc/" + e.Name() + "/exe"); err == nil && link == exePath && (pid == 0 || n < pid) {
			if status, err := os.ReadFile("/proc/" + e.Name() + "/status"); err == nil && bytes.Contains(status, []byte("\nTgid:\t"+e.Name()+"\n")) {
				pid = n
			}
		}
	}
	if pid == 0 {
		rec.Error = "no process runs " + exePath + " in this PID namespace's /proc"
		return rec
	}
	t, facts, err := identify(pid)
	if err != nil {
		rec.Error = err.Error()
		return rec
	}
	rec.Target = facts
	r.probe(t)
	rec.Sessions = append(rec.Sessions, r.session(sessionOpts{label: "capture", mode: nativeperf.ModeCPU, target: t, need: 8}))
	rec.Sessions = append(rec.Sessions, r.session(sessionOpts{label: "scheduler", mode: nativeperf.ModeCPUOffCPU, target: t, need: 12}))
	return rec
}
