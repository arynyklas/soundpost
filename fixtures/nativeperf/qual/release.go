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
var RequiredNegativeControls = []string{
	"staged_acquisition_pending_session",
	"staged_acquisition_pending_capability",
	"successful_empty_session",
	"synthetic_samples_perfect_cadence",
	"noop_sampler_no_cpu_samples",
	"noop_sampler_trickle",
	"positive_control_plausible_capture_accepted",
}

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
// is qualified on its own evidence (the arch and build are part of the key).
func RuntimeRequirements(r *QualificationResult, required []string) []string {
	qualified := QualifiedRuntimes(r.Runtimes)
	var out []string
	for _, name := range required {
		ok := false
		for key, q := range qualified {
			if q && strings.HasPrefix(key, name+"/"+r.Arch+"/") {
				ok = true
			}
		}
		if !ok {
			out = append(out, fmt.Sprintf("runtime %s/%s: not qualified on its own evidence", name, r.Arch))
		}
	}
	return out
}
