// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

// Package qual holds the task 04.09 native qualification model: the machine
// report, the row-state rules that keep an unexercised, denied or errored row
// from ever becoming "supported", the capture-authenticity checks that reject
// staged, empty, synthetic and no-op captures, and (on Linux) the shared
// acquisition harness used by the acceptance and overhead fixtures. It is a
// fixture package: production code must not import it.
package qual

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// State is the outcome of one qualification row.
type State string

const (
	StateSupported   State = "supported"   // exercised here, criterion measured and met
	StateUnqualified State = "unqualified" // cannot be exercised here; Reason says exactly why
	StateNotRun      State = "not_run"     // exercisable but not run in this invocation
	StateDenied      State = "denied"      // the kernel/host denied the required permission
	StateError       State = "error"       // the attempt itself failed (not an assertion)
	StateFailed      State = "failed"      // exercised and the criterion was not met
)

// Exit codes shared by the acceptance, overhead and qualification commands.
const (
	ExitOK           = 0
	ExitFail         = 1
	ExitUsage        = 2
	ExitContaminated = 4  // a contaminated capture was accepted by the checker: the gate is broken
	ExitUnexercised  = 10 // required rows were not exercised (unqualified, not run or denied): NOT a pass
)

// Row is one qualification row. Evidence lists the artifacts or measurements
// that justify it; Detail carries the raw numbers.
type Row struct {
	State     State          `json:"state"`
	Reason    string         `json:"reason,omitempty"`
	Exercised bool           `json:"exercised"`
	Evidence  []string       `json:"evidence,omitempty"`
	Detail    map[string]any `json:"detail,omitempty"`
}

// Supported builds a supported row; it is rejected by Validate unless it is
// exercised and carries evidence.
func Supported(evidence []string, detail map[string]any) Row {
	return Row{State: StateSupported, Exercised: true, Evidence: evidence, Detail: detail}
}

// Unqualified is a row that this host cannot exercise.
func Unqualified(reason string, detail map[string]any) Row {
	return Row{State: StateUnqualified, Reason: reason, Detail: detail}
}

// Failed is an exercised row whose criterion was not met.
func Failed(reason string, detail map[string]any) Row {
	return Row{State: StateFailed, Reason: reason, Exercised: true, Detail: detail}
}

// Validate enforces the state rules.
func (r Row) Validate(name string) error {
	switch r.State {
	case StateSupported:
		if !r.Exercised {
			return fmt.Errorf("row %s: supported but not exercised", name)
		}
		if len(r.Evidence) == 0 {
			return fmt.Errorf("row %s: supported without evidence", name)
		}
		if r.Reason != "" {
			return fmt.Errorf("row %s: supported with a failure reason %q", name, r.Reason)
		}
	case StateUnqualified, StateNotRun, StateDenied:
		if r.Reason == "" {
			return fmt.Errorf("row %s: %s without a reason", name, r.State)
		}
		if r.Exercised {
			return fmt.Errorf("row %s: %s cannot claim to be exercised", name, r.State)
		}
	case StateError, StateFailed:
		if r.Reason == "" {
			return fmt.Errorf("row %s: %s without a reason", name, r.State)
		}
	default:
		return fmt.Errorf("row %s: unknown state %q", name, r.State)
	}
	return nil
}

// RequiredRows are the rows a release qualification needs, in report order.
var RequiredRows = []string{"cpu", "off_cpu", "runqueue_split", "frame_coverage", "loss", "overhead", "memory", "fds", "privacy"}

// KernelConfig identifies the running kernel configuration.
type KernelConfig struct {
	Source       string `json:"source"`
	SHA256       string `json:"sha256,omitempty"`
	PerfEvents   string `json:"config_perf_events,omitempty"`
	FramePointer string `json:"config_frame_pointer,omitempty"`
	Ftrace       string `json:"config_ftrace,omitempty"`
}

// TargetBuild identifies the workload build.
type TargetBuild struct {
	Compiler string `json:"compiler"`
	Flags    string `json:"flags"`
	BuildID  string `json:"build_id"`
	SHA256   string `json:"sha256"`
}

// RuntimeBuild identifies one runtime build (its own build ID, never shared).
type RuntimeBuild struct {
	Runtime string `json:"runtime"`
	Version string `json:"version"`
	Arch    string `json:"arch"`
	BuildID string `json:"build_id,omitempty"`
	SHA256  string `json:"sha256,omitempty"`
	Path    string `json:"path_class,omitempty"`
}

// HostPermissions is the host permission snapshot taken at run time.
type HostPermissions struct {
	PerfEventParanoid string           `json:"perf_event_paranoid"`
	CapEff            string           `json:"cap_eff"`
	UID               int              `json:"uid"`
	Seccomp           string           `json:"seccomp"`
	NoNewPrivs        string           `json:"no_new_privs"`
	LSM               string           `json:"lsm,omitempty"`
	TracefsMount      string           `json:"tracefs_mount"`
	TracefsAccess     string           `json:"tracefs_access"`
	PIDNamespace      string           `json:"pid_namespace"`
	Cases             []PermissionCase `json:"cases,omitempty"`
	CgroupMount       string           `json:"cgroup_mount"`
	ProcMount         string           `json:"proc_mount"`
	CPUProbe          string           `json:"cpu_probe"`
	OffCPUProbe       string           `json:"off_cpu_probe"`
}

// PermissionCase is one privilege-drop case: the real helper without any
// capability against a target owned by another or by the same unprivileged user.
type PermissionCase struct {
	Name        string `json:"name"`
	Helper      string `json:"helper"`
	Target      string `json:"target"`
	Outcome     string `json:"outcome"`
	ErrorCode   string `json:"error_code,omitempty"`
	Samples     int    `json:"cpu_samples"`
	FDsReleased bool   `json:"resources_released"`
	Note        string `json:"note,omitempty"`
}

// Command records one command of the qualification run and its own exit code.
type Command struct {
	Command string `json:"command"`
	Ran     bool   `json:"ran"`
	Exit    int    `json:"exit,omitempty"`
	Note    string `json:"note,omitempty"`
}

// EvidenceRef names a stored evidence artifact.
type EvidenceRef struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256,omitempty"`
	Bytes  int    `json:"bytes,omitempty"`
}

// NegativeControl is one contaminated capture the checker had to reject before
// the real path ran.
type NegativeControl struct {
	Name     string `json:"name"`
	Rejected bool   `json:"rejected"` // the checker returned an error
	Behaved  bool   `json:"behaved"`  // rejected for the expected reason (accepted, for the positive control)
	Reason   string `json:"reason,omitempty"`
}

// NotRunItem lists something that was not exercised, with its exact reason.
type NotRunItem struct {
	Item   string `json:"item"`
	Reason string `json:"reason"`
}

// RuntimeColumn is one runtime's SEPARATE comparison column: its own build,
// its own runtime engine-sample evidence (the C09 supplement, never native
// engine output) and the native CPU capture of that runtime process.
type RuntimeColumn struct {
	Runtime string       `json:"runtime"`
	Arch    string       `json:"arch"`
	Build   RuntimeBuild `json:"build"`
	Engine  Row          `json:"engine_samples"`
	Native  Row          `json:"native_cpu"`
	Wait    Row          `json:"wait_row"`
}

// QualificationResult is the machine report of one acceptance run.
type QualificationResult struct {
	KernelBuild    string                  `json:"kernel_build"`
	KernelConfig   KernelConfig            `json:"kernel_config"`
	Arch           string                  `json:"arch"`
	TargetBuild    TargetBuild             `json:"target_build"`
	RuntimeBuild   map[string]RuntimeBuild `json:"runtime_build"`
	Permissions    HostPermissions         `json:"permissions"`
	PolicyRevision uint64                  `json:"policy_revision"`
	Commands       []Command               `json:"commands"`
	CPU            Row                     `json:"cpu"`
	OffCPU         Row                     `json:"off_cpu"`
	RunqueueSplit  Row                     `json:"runqueue_split"`
	FrameCoverage  Row                     `json:"frame_coverage"`
	Loss           Row                     `json:"loss"`
	Overhead       Row                     `json:"overhead"`
	Memory         Row                     `json:"memory"`
	FDs            Row                     `json:"fds"`
	Privacy        Row                     `json:"privacy"`
	Evidence       []EvidenceRef           `json:"evidence"`

	Runtimes         []RuntimeColumn   `json:"runtime_columns,omitempty"`
	NegativeControls []NegativeControl `json:"negative_controls,omitempty"`
	NotRun           []NotRunItem      `json:"not_run,omitempty"`
}

// Rows returns the named required rows.
func (r *QualificationResult) Rows() map[string]*Row {
	return map[string]*Row{"cpu": &r.CPU, "off_cpu": &r.OffCPU, "runqueue_split": &r.RunqueueSplit, "frame_coverage": &r.FrameCoverage, "loss": &r.Loss, "overhead": &r.Overhead, "memory": &r.Memory, "fds": &r.FDs, "privacy": &r.Privacy}
}

// Validate checks every row (including runtime columns).
func (r *QualificationResult) Validate() error {
	rows := r.Rows()
	var errs []error
	for _, name := range RequiredRows {
		if err := rows[name].Validate(name); err != nil {
			errs = append(errs, err)
		}
	}
	for _, c := range r.Runtimes {
		for suffix, row := range map[string]Row{"engine_samples": c.Engine, "native_cpu": c.Native, "wait_row": c.Wait} {
			if err := row.Validate(c.Runtime + "." + suffix); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

// UnqualifiedRequired lists every required row that is not supported, as
// "name: state (reason)", in report order.
func (r *QualificationResult) UnqualifiedRequired() []string {
	var out []string
	rows := r.Rows()
	for _, name := range RequiredRows {
		row := rows[name]
		if row.State != StateSupported {
			out = append(out, fmt.Sprintf("%s: %s (%s)", name, row.State, row.Reason))
		}
	}
	return out
}

// ExitCode is the release-gate verdict: ExitFail for an invalid report or an
// exercised failure, ExitUnexercised when any required row was not exercised
// (so a run that could not exercise the scheduler path cannot pass vacuously)
// and ExitOK only when every required row is supported.
func (r *QualificationResult) ExitCode() int {
	if r.Validate() != nil {
		return ExitFail
	}
	rows := r.Rows()
	unexercised := false
	for _, name := range RequiredRows {
		switch rows[name].State {
		case StateSupported:
		case StateFailed, StateError:
			return ExitFail
		default:
			unexercised = true
		}
	}
	if unexercised {
		return ExitUnexercised
	}
	return ExitOK
}

// QualifiedRuntimes says which runtime+arch+exact-build columns are qualified.
// A column qualifies only on its own evidence: Node success never qualifies
// Bun, and one architecture never qualifies another.
func QualifiedRuntimes(cols []RuntimeColumn) map[string]bool {
	out := map[string]bool{}
	for _, c := range cols {
		key := c.Runtime + "/" + c.Arch + "/" + c.Build.Version
		ok := c.Engine.State == StateSupported && c.Native.State == StateSupported && c.Wait.State == StateSupported &&
			c.Runtime != "" && c.Arch != "" && c.Build.Version != "" && c.Build.Runtime == c.Runtime && c.Build.Arch == c.Arch &&
			c.Engine.Validate("e") == nil && c.Native.Validate("n") == nil && c.Wait.Validate("w") == nil
		out[key] = out[key] || ok
	}
	return out
}

// KernelSeries maps a kernel release string to its LTS series ("6.1 LTS",
// "6.6 LTS") or "" when it is neither.
func KernelSeries(release string) string {
	for _, s := range []string{"6.1", "6.6"} {
		if release == s || strings.HasPrefix(release, s+".") || strings.HasPrefix(release, s+"-") {
			return s + " LTS"
		}
	}
	return ""
}

// ManifestRow is the subset of a qualification.json row the gate evaluates.
type ManifestRow struct {
	KernelSeries string `json:"kernel_series"`
	Arch         string `json:"arch"`
	KernelBuild  string `json:"kernel_build"`
	State        string `json:"state"`
}

// MatrixVerdict evaluates the required kernel/arch matrix against the results
// that exist. A matrix row is qualified only by a result whose arch and kernel
// series equal the row's, and only when that result passed every required row;
// the in-between WSL functional row never qualifies an LTS row.
func MatrixVerdict(rows []ManifestRow, results []*QualificationResult) []string {
	var missing []string
	for _, row := range rows {
		if !strings.HasSuffix(row.KernelSeries, "LTS") {
			continue // functional-evidence rows are not part of the required matrix
		}
		qualified := false
		for _, res := range results {
			if res.Arch == row.Arch && KernelSeries(res.KernelBuild) == row.KernelSeries && res.ExitCode() == ExitOK {
				qualified = true
			}
		}
		if !qualified {
			missing = append(missing, fmt.Sprintf("kernel %s %s: no exercised result with every required row supported", row.KernelSeries, row.Arch))
		}
	}
	sort.Strings(missing)
	return missing
}
