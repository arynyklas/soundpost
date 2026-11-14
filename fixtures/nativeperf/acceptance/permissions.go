//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"

	"github.com/arynyklas/soundpost/fixtures/nativeperf/qual"
	"github.com/arynyklas/soundpost/internal/nativeperf"
)

// unprivilegedUID is the account the dropped-privilege cases run as. Dropping
// privileges in a child process is not a host change: no sysctl, capability or
// mount is touched, and the parent keeps everything it had.
const unprivilegedUID = 65534

// runPermissionCases runs the real helper WITHOUT any capability against (a) a
// workload owned by another user and (b) a workload owned by the same
// unprivileged user. At perf_event_paranoid=2 the first must be a genuine,
// distinct permission denial (never staged, empty or synthetic); the second shows
// what the engine can do without CAP_PERFMON.
func (a *accept) runPermissionCases(cfg nativeperf.Config) {
	cases := []struct {
		name         string
		dropHelper   bool
		dropWorkload bool
		helper, tgt  string
	}{
		{"unprivileged_helper_foreign_uid_target", true, false, "uid 65534, no capabilities", "uid 0"},
		{"unprivileged_helper_same_uid_target", true, true, "uid 65534, no capabilities", "uid 65534"},
	}
	for _, c := range cases {
		fmt.Fprintf(os.Stderr, "acceptance: permission case %s\n", c.name)
		a.dropHelper, a.dropWorkload = c.dropHelper, c.dropWorkload
		r := a.runScenario("perm_"+c.name, "cpu", 3, cfg, 0, nil, nativeperf.ModeCPU)
		a.dropHelper, a.dropWorkload = false, false
		pc := qual.PermissionCase{Name: c.name, Helper: c.helper, Target: c.tgt, ErrorCode: r.Cap.ErrorCode, Samples: r.Stats.CPUSamples}
		if r.Err != "" {
			pc.Outcome = "fixture_error: " + r.Err
		}
		switch {
		case r.Err != "":
		case !r.Cap.Ready:
			pc.Outcome = "refused"
		case r.Stats.CPUSamples > 0 && r.CheckErr == nil:
			pc.Outcome = "captured_genuine_samples"
		default:
			pc.Outcome = "session_without_genuine_samples"
			if r.CheckErr != nil {
				pc.Note = r.CheckErr.Error()
			}
		}
		pc.FDsReleased = r.HelperFDsAfter == r.HelperBefore.FDs && r.HelperPerfAfter == 0
		a.res.Permissions.Cases = append(a.res.Permissions.Cases, pc)
		a.injections["perm_"+c.name] = r
	}
}

// permissionFailures lists permission cases that did not behave as required: a
// foreign-uid capture must be refused with the closed code permission_denied and
// release everything; a same-uid case must either be refused with a closed code
// or deliver genuine samples, never a silent empty success.
func permissionFailures(cases []qual.PermissionCase) []string {
	var out []string
	seen := map[string]bool{}
	for _, c := range cases {
		seen[c.Name] = true
		switch c.Name {
		case "unprivileged_helper_foreign_uid_target":
			if c.Outcome != "refused" || c.ErrorCode != "permission_denied" || !c.FDsReleased {
				out = append(out, fmt.Sprintf("%s: outcome %q code %q released=%v, want refused/permission_denied", c.Name, c.Outcome, c.ErrorCode, c.FDsReleased))
			}
		case "unprivileged_helper_same_uid_target":
			if !(c.Outcome == "captured_genuine_samples" || c.Outcome == "refused" && closedCodes[c.ErrorCode]) || !c.FDsReleased {
				out = append(out, fmt.Sprintf("%s: outcome %q code %q released=%v", c.Name, c.Outcome, c.ErrorCode, c.FDsReleased))
			}
		}
	}
	for _, name := range []string{"unprivileged_helper_foreign_uid_target", "unprivileged_helper_same_uid_target"} {
		if !seen[name] {
			out = append(out, name+": not run")
		}
	}
	return out
}
