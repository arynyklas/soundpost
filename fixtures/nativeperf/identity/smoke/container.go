//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/arynyklas/soundpost/fixtures/nativeperf/qual"
)

// The ns-* scenarios run real captures across PID namespace boundaries and namespace transitions (see
// qual/ns_cases_linux.go). Unlike "namespaces" (the already authorized local namespace only) they build disposable
// container-equivalent sandboxes with clone flags and mounts: they need root, a C compiler and the right to create the
// namespaces, and a host without them FAILS the scenario instead of skipping it.
var nsScenarios = map[string][]string{
	"ns-nested-target": {"nested_target_host_helper"},
	"ns-nested-helper": {"helper_in_target_ns"},
	"ns-transitions":   {"nested_exec", "cgroup_move", "pid_reuse_cross_ns", "proc_view_mismatch"},
	"ns-layers":        {"layer_overlay", "deleted_replaced", "mount_ns_swap", "mount_unshare"},
	"ns-container":     qual.NSCaseNames,
}

func nsScenario(name string) error {
	res := qual.RunNSCasesNamed(context.Background(), nsScenarios[name]...)
	if res.Unavailable != "" {
		return errors.New("namespace_cases_unavailable: " + res.Unavailable)
	}
	var failed []string
	for _, c := range res.Controls {
		if !c.Behaved {
			failed = append(failed, "negative control "+c.Name+": "+c.Reason)
		}
	}
	for _, rec := range res.Records {
		for _, f := range res.Failures[rec.Name] {
			failed = append(failed, rec.Name+": "+f)
		}
	}
	out := struct {
		Scenario   string   `json:"scenario"`
		Kernel     string   `json:"kernel"`
		CgroupMode string   `json:"cgroup_mode"`
		Cases      []string `json:"cases"`
		Failures   []string `json:"failures,omitempty"`
	}{name, res.Kernel, res.CgroupMode, res.Summary(), failed}
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		return err
	}
	if len(res.Records) != len(nsScenarios[name]) {
		return fmt.Errorf("only %d of %d namespace cases ran", len(res.Records), len(nsScenarios[name]))
	}
	if len(failed) > 0 {
		return errors.New("namespace_case_failed: " + strings.Join(failed, " | "))
	}
	return nil
}

// nsAttach captures a target that already runs in the /proc this process sees and prints the observation; it is the helper
// side of the Compose (pid: container:<workload>) and DaemonSet (hostPID) recipes.
func nsAttach(exe string) error {
	if exe == "" {
		return errors.New("attach_exe_required")
	}
	rec := qual.RunAttach(context.Background(), exe)
	failed := qual.JudgeNS(qual.NSSpec{Name: "attach"}, rec)
	out := struct {
		Scenario string        `json:"scenario"`
		Record   qual.NSRecord `json:"record"`
		Failures []string      `json:"failures,omitempty"`
	}{"ns-attach", rec, failed}
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		return err
	}
	if len(failed) > 0 {
		return errors.New("attach_failed: " + strings.Join(failed, " | "))
	}
	return nil
}
