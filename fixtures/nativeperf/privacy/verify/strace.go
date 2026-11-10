//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"go/ast"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"soundpost/fixtures/nativeperf/privacy/scan"
)

type syscallReport struct {
	Method           string   `json:"method"`
	Lines            int      `json:"trace_lines,omitempty"`
	PerfEventOpens   int      `json:"perf_event_open_calls,omitempty"`
	CPUOpens         int      `json:"cpu_event_opens,omitempty"`
	SchedulerOpens   int      `json:"scheduler_event_opens,omitempty"`
	PerfIoctls       int      `json:"perf_event_ioctls,omitempty"`
	ForbiddenChecked int      `json:"syscall_lines_checked_against_forbidden_list,omitempty"`
	SourceFiles      int      `json:"source_files_audited,omitempty"`
	Findings         []string `json:"findings"`
}

const straceTrace = "trace=%file,perf_event_open,ioctl,ptrace,process_vm_readv,process_vm_writev,bpf,kcmp,userfaultfd,pidfd_getfd,seccomp,mount,setns,unshare,init_module,finit_module,kexec_load,kexec_file_load"

// runUnderStrace re-runs this whole fixture (acquisition, helper, node, drills)
// under `strace -f -v` and audits the actual syscall trace against the policy:
// forbidden syscalls and /proc-memory style opens, dump file names, and the exact
// perf_event_open attribute allowlist. Without strace it falls back to the static
// Go-source audit of the acquisition path and says so.
func runUnderStrace(o options) (int, error) {
	policy, e := scan.LoadPolicy(o.policyPath)
	if e != nil {
		return exitUsage, errors.New("privacy policy unreadable")
	}
	strace, lookErr := exec.LookPath("strace")
	if lookErr != nil {
		return runStaticFallback(o, policy)
	}
	tmp, e := os.MkdirTemp("", "soundpost-privacy-strace-")
	if e != nil {
		return exitFail, e
	}
	defer os.RemoveAll(tmp)
	log, result := filepath.Join(tmp, "trace.txt"), filepath.Join(tmp, "result.json")
	self, e := os.Executable()
	if e != nil {
		return exitFail, e
	}
	args := []string{"-f", "-qq", "-v", "-s", "200", "-o", log, "-e", straceTrace, self, "--role=child",
		"--workload", o.workload, "--policy", o.policyPath, "--endpoint-env", o.endpointEnv, "--seconds", strconv.Itoa(o.seconds), "--result-file", result}
	if o.injectPeerDeath {
		args = append(args, "--inject-peer-death")
	}
	if o.injectHelperEnd {
		args = append(args, "--inject-helper-crash")
	}
	if o.negativeControl {
		args = append(args, "--negative-control")
	}
	cmd := exec.Command(strace, args...)
	cmd.Stderr = os.Stderr
	runErr := cmd.Run()
	childCode := exitOK
	if runErr != nil {
		var exit *exec.ExitError
		if errors.As(runErr, &exit) {
			childCode = exit.ExitCode()
		} else {
			return exitFail, errors.New("strace could not run the fixture")
		}
	}
	raw, e := os.ReadFile(result)
	if e != nil {
		return exitFail, errors.New("the audited fixture run produced no report")
	}
	var rep report
	if e = json.Unmarshal(raw, &rep); e != nil {
		return exitFail, errors.New("the audited fixture report is unreadable")
	}
	f, e := os.Open(log)
	if e != nil {
		return exitFail, errors.New("strace log missing")
	}
	defer f.Close()
	findings, sum, e := scan.AuditStrace(policy, f)
	if e != nil {
		return exitFail, e
	}
	sr := &syscallReport{Method: "strace -f -v over the complete fixture run (verifier, in-process helper, helper process, peers, workload)", Lines: sum.Lines, PerfEventOpens: sum.PerfEventOpens, CPUOpens: sum.CPUOpens, SchedulerOpens: sum.SchedulerOpens, PerfIoctls: sum.PerfIoctls, ForbiddenChecked: sum.ForbiddenChecked, Findings: []string{}}
	for _, finding := range findings {
		sr.Findings = append(sr.Findings, finding.String())
	}
	rep.Syscalls = sr
	code := childCode
	switch {
	case len(findings) > 0:
		rep.Failures = append(rep.Failures, "forbidden syscall/configuration observed in the real run")
		code = exitFail
	case sum.CPUOpens < 2 || sum.PerfIoctls < 2:
		// Non-vacuity: a trace without the real acquisition proves nothing.
		rep.Failures = append(rep.Failures, "the strace log does not show the real perf acquisition (audit would be vacuous)")
		code = exitFail
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if e = enc.Encode(rep); e != nil {
		return exitFail, e
	}
	if code != exitOK && code != exitNoScheduler {
		return code, errors.New(strings.Join(rep.Failures, "; "))
	}
	return code, nil
}

// runStaticFallback runs the real fixture and, because strace is not installed,
// attaches a static audit of the acquisition path's Go sources, saying so.
func runStaticFallback(o options, policy scan.Policy) (int, error) {
	rep, code, runErr := runFixture(o)
	if rep == nil {
		return code, runErr
	}
	paths, e := filepath.Glob("internal/nativeperf/*.go")
	if e != nil || len(paths) == 0 {
		return exitFail, errors.New("strace unavailable and the acquisition sources are not under the working directory")
	}
	paths = append(paths, "cmd/soundpost-perf-acquire/main.go")
	sr := &syscallReport{Method: "STATIC source audit only: strace is not installed, no real syscall trace was audited", Findings: []string{}}
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return exitFail, err
		}
		var printOK func(*ast.CallExpr) bool
		if strings.HasSuffix(path, "soundpost-perf-acquire/main.go") {
			printOK = scan.HelperMainPrintOK
		}
		sr.SourceFiles++
		sr.Findings = append(sr.Findings, scan.AuditGoSource(policy, path, string(src), printOK)...)
	}
	rep.Syscalls = sr
	rep.NotRun = append(rep.NotRun, "dynamic syscall audit: strace not installed")
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if e = enc.Encode(rep); e != nil {
		return exitFail, e
	}
	if len(sr.Findings) > 0 {
		return exitFail, errors.New("static audit found forbidden constructs")
	}
	return code, runErr
}
