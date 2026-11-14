// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"flag"
	"fmt"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/symbolicate"
)

// The default symbolication sandbox re-executes this same binary, so the release
// stays a single static file. These are the only argument vectors that make the
// binary act as a worker; all are exact (no further arguments) and meaningless to
// an operator. The worker and probe vectors read the request from stdin only after
// the OS sandbox is installed. The two staging vectors are used only on a host
// without clone3 (systemd RestrictNamespaces=yes): the process blocks on an
// inherited pipe until its parent has moved it into the limited cgroup, then execs
// the matching worker vector.
const (
	workerFlag      = "--worker-v1"
	probeFlag       = "--probe-v1"
	stageWorkerFlag = "--stage-worker-v1"
	stageProbeFlag  = "--stage-probe-v1"
)

// symbolicateWorker runs the worker, probe or staging entry when the process was
// started as one. It runs before any flag parsing, storage or network setup.
func symbolicateWorker(args []string) (int, bool) {
	if len(args) != 2 {
		return 0, false
	}
	switch args[1] {
	case workerFlag:
		return symbolicate.WorkerMain(), true
	case probeFlag:
		return symbolicate.ProbeMain(), true
	case stageWorkerFlag:
		return symbolicate.StageMain(false), true
	case stageProbeFlag:
		return symbolicate.StageMain(true), true
	}
	return 0, false
}

// symbolicatorOptions is the serve flag surface of the frame symbolicator.
type symbolicatorOptions struct {
	sandbox    *string
	config     *string
	cgroupRoot *string
}

func addSymbolicatorFlags(f *flag.FlagSet) symbolicatorOptions {
	return symbolicatorOptions{
		sandbox:    f.String("symbolicate-sandbox", "auto", "frame symbolication sandbox: auto (native sandbox re-executing this binary; the startup probe must pass or frames answer sandbox_unavailable) or off"),
		config:     f.String("symbolicate-config", "", "private JSON selecting an explicit symbolication backend (native worker or pinned OCI image); see docs/operations/symbolication.md"),
		cgroupRoot: f.String("symbolicate-cgroup-root", "", "already delegated cgroup v2 subtree for the native sandbox (default: this process's own cgroup)"),
	}
}

func (o symbolicatorOptions) settings() (appcore.SymbolicatorSettings, error) {
	switch *o.sandbox {
	case "auto":
	case "off":
		if *o.config != "" || *o.cgroupRoot != "" {
			return appcore.SymbolicatorSettings{}, fmt.Errorf("--symbolicate-sandbox=off conflicts with --symbolicate-config and --symbolicate-cgroup-root")
		}
		return appcore.SymbolicatorSettings{Disabled: true}, nil
	default:
		return appcore.SymbolicatorSettings{}, fmt.Errorf("--symbolicate-sandbox must be auto or off")
	}
	if *o.config != "" && *o.cgroupRoot != "" {
		return appcore.SymbolicatorSettings{}, fmt.Errorf("--symbolicate-config and --symbolicate-cgroup-root are exclusive")
	}
	return appcore.SymbolicatorSettings{ConfigPath: *o.config, CgroupRoot: *o.cgroupRoot}, nil
}

// symbolicatorNotice is the one stderr line serve prints about the sandbox. It
// carries only the static state and reason codes: never a path, hash or OS error.
func symbolicatorNotice(status appcore.SymbolicatorStatus) string {
	if status.State == appcore.SymbolicatorReady {
		return "symbolicator: ready (sandbox probes passed)"
	}
	return "symbolicator: " + string(status.State) + " (" + status.Reason + "): frames keep their original identity and answer sandbox_unavailable"
}
