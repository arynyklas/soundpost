// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package qual

import (
	"fmt"
	"sort"
	"strings"
)

// RequiredNegativeControls are the contaminated captures every acceptance run
// must have rejected before its real path ran.
var RequiredNegativeControls = append([]string{
	"staged_acquisition_pending_session",
	"staged_acquisition_pending_capability",
	"successful_empty_session",
	"synthetic_samples_perfect_cadence",
	"noop_sampler_no_cpu_samples",
	"noop_sampler_trickle",
	"scheduler_loss_ignored",
	"scheduler_loss_interval_straddles_loss",
	"scheduler_loss_not_provoked_is_not_a_pass",
	"scheduler_missing_wake_reported_as_blocked",
	"scheduler_missing_wake_without_evidence_is_not_a_pass",
	"scheduler_open_interval_completed_as_blocked",
	"scheduler_open_interval_without_evidence_is_not_a_pass",
	"scheduler_injection_positive_controls_accepted",
	"positive_control_plausible_capture_accepted",
}, HotplugControls...)

// ReleaseProblems lists everything that makes a result unusable as release
// evidence, independent of which rows are supported: a report that did not run
// (or did not pass) its negative controls, rows that are inconsistent, missing
// kernel/target identity.
func ReleaseProblems(r *QualificationResult) []string {
	var out []string
	if err := r.Validate(); err != nil {
		for _, line := range strings.Split(err.Error(), "\n") {
			out = append(out, "invalid report: "+line)
		}
	}
	if r.KernelBuild == "" || r.Arch == "" {
		out = append(out, "kernel build or architecture missing")
	}
	if r.TargetBuild.BuildID == "" || r.TargetBuild.SHA256 == "" {
		out = append(out, "target build identity missing")
	}
	seen := map[string]NegativeControl{}
	for _, nc := range r.NegativeControls {
		seen[nc.Name] = nc
	}
	for _, name := range RequiredNegativeControls {
		nc, ok := seen[name]
		switch {
		case !ok:
			out = append(out, "negative control "+name+" was not run")
		case !nc.Behaved:
			out = append(out, "negative control "+name+" was not rejected as required: "+nc.Reason)
		}
	}
	for _, c := range r.Runtimes {
		if c.Engine.State == StateSupported || c.Native.State == StateSupported {
			if _, ok := r.RuntimeBuild[c.Runtime]; !ok || c.Build.BuildID == "" {
				out = append(out, "runtime "+c.Runtime+" column lacks its own runtime build ID")
			}
		}
	}
	sort.Strings(out)
	return out
}

// RuntimeRequirements lists the runtime columns a release needs and whether each
// is qualified on its own evidence (the arch and build are part of the key). A requirement is a runtime name ("bun": any
// qualified build of it) or a runtime and a version prefix of whole components ("node@24", "python@3.13": a build whose
// version, without a leading "v", is that prefix or continues it after a dot); another version never qualifies it.
func RuntimeRequirements(r *QualificationResult, required []string) []string {
	qualified := QualifiedRuntimes(r.Runtimes)
	var out []string
	for _, requirement := range required {
		name, want, _ := strings.Cut(requirement, "@")
		ok := false
		for key, q := range qualified {
			version, found := strings.CutPrefix(key, name+"/"+r.Arch+"/")
			if q && found && versionMatches(version, want) {
				ok = true
			}
		}
		if !ok {
			out = append(out, fmt.Sprintf("runtime %s/%s: not qualified on its own evidence", requirement, r.Arch))
		}
	}
	return out
}

// versionMatches says whether a build version satisfies a version-prefix requirement ("" matches every version).
func versionMatches(version, want string) bool {
	if want == "" {
		return true
	}
	version = strings.TrimPrefix(version, "v")
	return version == want || strings.HasPrefix(version, want+".")
}

// ScenarioRequirements lists the scenarios a release needs (the manifest's required_scenarios) that this result did not
// exercise to a supported row, as "scenario name: state (reason)" in the order given; a scenario the run never reported is
// not_run.
func ScenarioRequirements(r *QualificationResult, required []string) []string {
	var out []string
	for _, name := range required {
		row, ok := r.Scenarios[name]
		switch {
		case !ok:
			out = append(out, fmt.Sprintf("scenario %s: %s (this run did not report it; pass --host-scenarios %s)", name, StateNotRun, name))
		case row.State != StateSupported:
			out = append(out, fmt.Sprintf("scenario %s: %s (%s)", name, row.State, row.Reason))
		}
	}
	return out
}
