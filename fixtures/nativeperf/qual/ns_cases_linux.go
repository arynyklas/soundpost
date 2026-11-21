//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package qual

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/nativeperf"
)

//go:embed nsload/nsload.c
var nsloadSource []byte

func nsUint(v uint64) model.Uint64 { return model.Uint64(v) }

// NSCaseNames are the namespace cases, in the order they run.
var NSCaseNames = []string{
	"nested_target_host_helper", "helper_in_target_ns", "nested_exec", "cgroup_move", "layer_overlay",
	"deleted_replaced", "mount_ns_swap", "mount_unshare", "pid_reuse_cross_ns", "proc_view_mismatch",
}

// container is what a runtime gives a container with its own PID, mount, cgroup, UTS, IPC and network namespaces, a proc of
// its own and a cgroup2 view of its own.
var containerSandbox = Sandbox{PID: true, Mount: true, Cgroup: true, UTS: true, IPC: true, Net: true, ProcFS: true, Cgroup2: true}

// NSResult is the outcome of all namespace cases on this host.
type NSResult struct {
	Unavailable string              // why the cases could not run (empty: they ran)
	Records     []NSRecord          // one per case that ran
	Failures    map[string][]string // case name -> failures
	Controls    []NegativeControl
	Kernel      string
	CgroupMode  string
}

// OK reports whether every case ran and passed and every negative control behaved.
func (r NSResult) OK() bool {
	if r.Unavailable != "" || len(r.Records) != len(NSCaseNames) {
		return false
	}
	for _, c := range r.Controls {
		if !c.Behaved {
			return false
		}
	}
	return len(r.Failures) == 0
}

// NSPrerequisites reports why the namespace cases cannot run here ("" when they can). Missing capability is a failure of
// the row, not a silent skip: the caller turns the reason into an unqualified row that says so.
func NSPrerequisites() string {
	if os.Geteuid() != 0 {
		return "namespace cases need root (CAP_SYS_ADMIN for new PID/mount/cgroup namespaces and CAP_PERFMON)"
	}
	if os.Getenv(nsloadDirEnv) == "" {
		if _, err := exec.LookPath("cc"); err != nil {
			return "namespace cases need a C compiler (cc) for the controlled workload (or " + nsloadDirEnv + " naming prebuilt nsload-a and nsload-b)"
		}
	}
	self, err := os.Executable()
	if err != nil {
		return "sandbox command: " + err.Error()
	}
	cmd, err := containerSandbox.Command(self)
	if err != nil {
		return "sandbox command: " + err.Error()
	}
	cmd.Env = append(cmd.Env, nsProbeEnv+"=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		return "this host cannot create the PID/mount/cgroup/UTS/IPC/net namespaces of a container: " + strings.TrimSpace(string(out)+" "+err.Error())
	}
	return ""
}

// nsloadDirEnv names a directory holding prebuilt static nsload-a and nsload-b (a container image has no compiler).
const (
	nsloadDirEnv = "SPQUAL_NSLOAD_DIR"
	nsProbeEnv   = "SPQUAL_NS_PROBE"
)

func compileNSWorkloads(dir string) (a, b string, err error) {
	if prebuilt := os.Getenv(nsloadDirEnv); prebuilt != "" {
		a, b = filepath.Join(prebuilt, "nsload-a"), filepath.Join(prebuilt, "nsload-b")
		if _, err = os.Stat(a); err == nil {
			_, err = os.Stat(b)
		}
		return
	}

	src := filepath.Join(dir, "nsload.c")
	if err = os.WriteFile(src, nsloadSource, 0o644); err != nil {
		return
	}
	build := func(out, variant string) error {
		args := []string{"-O2", "-g", "-fno-omit-frame-pointer", "-Wl,--build-id", "-DVARIANT=" + variant, "-o", out, src}
		if o, e := exec.Command("cc", args...).CombinedOutput(); e != nil {
			return fmt.Errorf("cc: %v: %s", e, strings.TrimSpace(string(o)))
		}
		return nil
	}
	a, b = filepath.Join(dir, "nsload-a"), filepath.Join(dir, "nsload-b")
	if err = build(a, "1"); err != nil {
		return
	}
	err = build(b, "2")
	return
}

// RunNSCases runs every namespace case on this host with real captures through the helper, judges each record with judge
// (judgeNS in production) after the negative controls and returns the result.
func RunNSCases(ctx context.Context) NSResult { return runNSCases(ctx, judgeNS, nil) }

const nsAllEnv = "SPQUAL_NS_ALL"

// RunNSCasesIsolated runs RunNSCases in a fresh process of this binary and returns its result: the in-process helper of the
// outer cases then has the process state of a runner (resource limits, budgets, signal dispositions) and not whatever a
// long-lived test process accumulated before.
func RunNSCasesIsolated(ctx context.Context) NSResult {
	self, err := os.Executable()
	if err != nil {
		return NSResult{Unavailable: err.Error()}
	}
	cmd := exec.CommandContext(ctx, self)
	cmd.Env = append(os.Environ(), nsAllEnv+"=1")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	var res NSResult
	if err != nil || json.Unmarshal(out, &res) != nil {
		return NSResult{Unavailable: fmt.Sprintf("isolated run failed: %v: %s", err, strings.TrimSpace(stderr.String()))}
	}
	return res
}

// RunNSCasesNamed runs only the named cases (and the controls).
func RunNSCasesNamed(ctx context.Context, names ...string) NSResult {
	return runNSCases(ctx, judgeNS, names)
}

func runNSCases(ctx context.Context, judge nsJudge, only []string) NSResult {
	res := NSResult{Kernel: KernelRelease(), CgroupMode: CgroupMode(), Failures: map[string][]string{}}
	if reason := NSPrerequisites(); reason != "" {
		res.Unavailable = reason
		return res
	}
	res.Controls = runNSControls(judge)
	dir, err := os.MkdirTemp("", "soundpost-nscases-")
	if err != nil {
		res.Unavailable = err.Error()
		return res
	}
	defer os.RemoveAll(dir)
	os.Chmod(dir, 0o755)
	a, b, err := compileNSWorkloads(dir)
	if err != nil {
		res.Unavailable = err.Error()
		return res
	}
	for _, name := range NSCaseNames {
		if len(only) > 0 && !contains(only, name) {
			continue
		}
		rec, spec := runOneNSCase(ctx, name, a, b)
		res.Records = append(res.Records, rec)
		if f := judge(spec, rec); len(f) > 0 {
			res.Failures[name] = f
		}
	}
	return res
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func runOneNSCase(ctx context.Context, name, a, b string) (NSRecord, NSSpec) {
	spec := NSSpec{Name: name, Workload: a, Variant: b}
	box := containerSandbox
	switch name {
	case "nested_target_host_helper":
		spec.TargetSandbox = &box
		return RunNSCase(ctx, spec), spec
	case "nested_exec":
		spec.Transition, spec.TargetSandbox = "exec", &box
		return RunNSCase(ctx, spec), spec
	case "cgroup_move":
		spec.Transition, spec.TargetSandbox = "cgroup_move", &box
		return RunNSCase(ctx, spec), spec
	case "layer_overlay":
		spec.Layer, spec.TargetSandbox = true, &box
		return RunNSCase(ctx, spec), spec
	case "deleted_replaced":
		spec.Transition, spec.TargetSandbox = "deleted_replaced", &box
		return RunNSCase(ctx, spec), spec
	case "mount_unshare":
		spec.Transition = "mount_unshare"
		return RunNSCase(ctx, spec), spec
	case "mount_ns_swap":
		spec.Transition = "mount_ns_swap"
		return RunNSCase(ctx, spec), spec
	case "helper_in_target_ns":
		return RunNSCaseIn(ctx, containerSandbox, spec), spec
	case "pid_reuse_cross_ns":
		return RunNSCaseIn(ctx, Sandbox{PID: true, Mount: true, ProcFS: true, UTS: true, IPC: true}, spec), spec
	case "proc_view_mismatch":
		return runProcViewMismatch(ctx, spec), spec
	}
	return NSRecord{Name: name, Error: "unknown case"}, spec
}

// runProcViewMismatch starts the idle target on the host side, identifies it from the host's /proc and runs the helper in
// a PID namespace that still has the host's /proc.
func runProcViewMismatch(ctx context.Context, spec NSSpec) NSRecord {
	rec := NSRecord{Name: spec.Name}
	dir, err := os.MkdirTemp("", NSCanary+"-")
	if err != nil {
		rec.Error = err.Error()
		return rec
	}
	defer os.RemoveAll(dir)
	os.Chmod(dir, 0o755)
	idle := filepath.Join(dir, "idle")
	if err = copyFile(spec.Workload, idle, 0o755); err != nil {
		rec.Error = err.Error()
		return rec
	}
	p, err := startNSProc(exec.Command(idle, "idle"))
	if err != nil {
		rec.Error = "idle target: " + err.Error()
		return rec
	}
	defer p.kill()
	t, facts, err := identify(p.pid)
	if err != nil {
		rec.Error = err.Error()
		return rec
	}
	spec.External = &NSExternal{Target: t, Facts: facts}
	spec.OwnProc = "/l4w33-ownproc"
	return RunNSCaseIn(ctx, Sandbox{PID: true, Mount: true, OwnProc: spec.OwnProc}, spec)
}

// ---- negative controls of the judge ----

// goodNSRecords returns, for each case, a record the judge must accept, built from the numbers a correct run shows.
func nsControlRecord(name string) (NSSpec, NSRecord) {
	key := func(ns, tgid uint32, gen uint64) nativeperf.TaskKey {
		return nativeperf.TaskKey{BootID: "b", PIDNamespace: model.Uint64(ns), TGID: tgid, TID: tgid, ProcessStart: model.MonoNano(gen), Generation: 1}
	}
	t := NSTarget{PID: 4242, NSpid: []uint32{4242, 1}, PIDNS: 4026532500, BuildID: "aa"}
	ok := func(label string, k nativeperf.TaskKey) NSSession {
		return NSSession{Label: label, Ready: true, CPU: 20, Resolved: 20, Builds: []string{"aa"}, Tasks: []NSTask{{Key: k, CPU: 20}}}
	}
	ended := func(s NSSession) NSSession {
		s.ErrorCode, s.ProvenThrough, s.TransitionNs, s.GuardRetired = "generation_changed", 900, 1000, true
		return s
	}
	refusal := func(label string) NSSession { return NSSession{Label: label, ErrorCode: "generation_changed"} }
	rec := NSRecord{Name: name, HelperPIDNS: 0xEFFFFFFC, HelperInit: true, Target: t, Facts: map[string]string{"host_path_build_id": "bb", "variant_build_id": "bb"}}
	first := key(4026532500, 4242, 7)
	switch name {
	case "nested_exec":
		rec.Sessions = []NSSession{ended(ok("capture", first))}
	case "cgroup_move":
		rec.Sessions = []NSSession{ended(ok("capture", first)), refusal("after_transition_old_identity")}
	case "pid_reuse_cross_ns":
		rec.Sessions = []NSSession{ended(ok("capture", first)), refusal("after_transition_old_identity"), ok("reuser", key(0xEFFFFFFB, 4242, 9))}
	case "proc_view_mismatch":
		rec.Facts["views_differ"] = "true"
		rec.Sessions = []NSSession{refusal("capture")}
	case "layer_overlay":
		rec.Sessions = []NSSession{ok("capture", first)}
	}
	return NSSpec{Name: name}, rec
}

// runNSControls proves the judge rejects contaminated cases: for each control a correct record is accepted and a record
// with the specific defect is rejected. A judge that accepts any of them (for example one that ignores generations) makes
// the row fail before any real case is believed.
func runNSControls(judge nsJudge) []NegativeControl {
	type control struct {
		name, base string
		defect     func(*NSRecord)
		want       string
	}
	controls := []control{
		{"joined_generation_reuser_shares_task_key", "pid_reuse_cross_ns", func(r *NSRecord) { r.Sessions[2].Tasks[0].Key = r.Sessions[0].Tasks[0].Key }, "share TaskKey"},
		{"transition_not_noticed_old_events_continue", "nested_exec", func(r *NSRecord) {
			r.Sessions[0].ErrorCode, r.Sessions[0].LateOld = "", 12
		}, "not noticed"},
		{"identity_proven_after_the_transition", "nested_exec", func(r *NSRecord) { r.Sessions[0].ProvenThrough = 2000 }, "last proven"},
		{"old_identity_capture_accepted_after_cgroup_move", "cgroup_move", func(r *NSRecord) {
			r.Sessions[1] = r.Sessions[0]
			r.Sessions[1].Label, r.Sessions[1].ErrorCode = "after_transition_old_identity", ""
		}, "expected a refusal"},
		{"events_labeled_with_nested_pid", "nested_exec", func(r *NSRecord) { r.Sessions[0].Tasks[0].Key.TGID, r.Sessions[0].Tasks[0].Key.TID = 1, 1 }, "TaskKey"},
		{"proc_mismatch_capture_delivered_samples", "proc_view_mismatch", func(r *NSRecord) {
			r.Sessions[0] = NSSession{Label: "capture", Ready: true, CPU: 9}
		}, "expected a refusal"},
		{"layer_resolved_to_host_path_build", "layer_overlay", func(r *NSRecord) { r.Facts["host_path_build_id"] = "bb"; r.Sessions[0].Builds = []string{"aa", "bb"} }, "build"},
		{"path_canary_in_frames", "nested_exec", func(r *NSRecord) { r.Sessions[0].Leaks = 1 }, "canary"},
	}
	var out []NegativeControl
	for _, c := range controls {
		spec, good := nsControlRecord(c.base)
		goodFail := judge(spec, good)
		bad := deepCopyRecord(good)
		c.defect(&bad)
		badFail := judge(spec, bad)
		nc := NegativeControl{Name: c.name}
		nc.Rejected = len(badFail) > 0
		switch {
		case len(goodFail) > 0:
			nc.Reason = "the control's correct record was rejected: " + strings.Join(goodFail, "; ")
		case !nc.Rejected:
			nc.Reason = "the contaminated record was ACCEPTED"
		default:
			hit := false
			for _, m := range badFail {
				hit = hit || strings.Contains(m, c.want)
			}
			nc.Behaved = hit
			if !hit {
				nc.Reason = "rejected, but not for the expected reason: " + strings.Join(badFail, "; ")
			}
		}
		out = append(out, nc)
	}
	return out
}

func deepCopyRecord(r NSRecord) NSRecord {
	c := r
	c.Facts = map[string]string{}
	for k, v := range r.Facts {
		c.Facts[k] = v
	}
	c.Sessions = make([]NSSession, len(r.Sessions))
	for i, s := range r.Sessions {
		s.Tasks = append([]NSTask(nil), s.Tasks...)
		s.Builds = append([]string(nil), s.Builds...)
		c.Sessions[i] = s
	}
	return c
}

// Summary is a compact, human-checkable line per case.
func (r NSResult) Summary() []string {
	var out []string
	for _, rec := range r.Records {
		line := fmt.Sprintf("%s: helper_pid_ns=%d (initial=%v) target pid=%d nspid=%v pid_ns=%d cgroup_id=%d", rec.Name, rec.HelperPIDNS, rec.HelperInit, rec.Target.PID, rec.Target.NSpid, rec.Target.PIDNS, rec.Target.CgroupID)
		for _, s := range rec.Sessions {
			line += fmt.Sprintf(" | %s[%s]: ready=%v code=%q read_error=%q cpu=%d switch=%d target_switch=%d resolved=%d unresolved=%v builds=%v proven=%d", s.Label, s.Mode, s.Ready, s.ErrorCode, s.ReadError, s.CPU, s.Switch, s.TargetSwitch, s.Resolved, s.Unresolved, s.Builds, s.ProvenThrough)
		}
		if len(rec.Facts) > 0 {
			line += fmt.Sprintf(" | facts=%v", rec.Facts)
		}
		if f := r.Failures[rec.Name]; len(f) > 0 {
			line += " | FAILED: " + strings.Join(f, "; ")
		}
		out = append(out, line)
	}
	return out
}
