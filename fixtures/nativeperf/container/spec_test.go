//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func shippedProfile(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("../../../deploy/seccomp/soundpost-perf.json")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func ruleNames(t *testing.T, profile map[string]any) map[string]bool {
	t.Helper()
	names := map[string]bool{}
	for _, r := range profile["syscalls"].([]map[string]any) {
		for _, n := range r["names"].([]string) {
			names[n] = true
		}
	}
	return names
}

func TestOCISeccompKeepsTheShippedProfileRuleForRule(t *testing.T) {
	raw := shippedProfile(t)
	out, err := ociSeccomp(raw)
	if err != nil {
		t.Fatal(err)
	}
	if out["defaultAction"] != "SCMP_ACT_ERRNO" || out["defaultErrnoRet"] != 1 {
		t.Errorf("the default must stay deny-by-default with EPERM: %v %v", out["defaultAction"], out["defaultErrnoRet"])
	}
	if arches := out["architectures"].([]string); len(arches) != 2 || arches[0] != "SCMP_ARCH_X86_64" {
		t.Errorf("architectures: %v", arches)
	}
	var shipped struct {
		Syscalls []struct {
			Names []string `json:"names"`
		} `json:"syscalls"`
	}
	if err = json.Unmarshal(raw, &shipped); err != nil {
		t.Fatal(err)
	}
	total := 0
	for _, r := range shipped.Syscalls {
		total += len(r.Names)
	}
	got := 0
	for _, r := range out["syscalls"].([]map[string]any) {
		got += len(r["names"].([]string))
	}
	if got != total {
		t.Errorf("every shipped syscall name must be kept: %d of %d", got, total)
	}
	names := ruleNames(t, out)
	for _, need := range []string{"perf_event_open", "execve", "fstatfs", "pidfd_open"} {
		if !names[need] {
			t.Errorf("the shipped profile allows %s", need)
		}
	}
	if names["ptrace"] || names["mount"] {
		t.Error("nothing is added to the profile")
	}
}

func TestOCISeccompWithholdsOnlyWhatWasAskedFor(t *testing.T) {
	raw := shippedProfile(t)
	full, _ := ociSeccomp(raw)
	out, err := ociSeccomp(raw, "perf_event_open")
	if err != nil {
		t.Fatal(err)
	}
	names := ruleNames(t, out)
	if names["perf_event_open"] {
		t.Fatal("perf_event_open must be withheld")
	}
	if len(names) != len(ruleNames(t, full))-1 {
		t.Errorf("exactly one syscall is withheld: %d vs %d", len(names), len(ruleNames(t, full)))
	}
	if _, err = ociSeccomp(raw, "no_such_syscall"); err == nil {
		t.Error("withholding a syscall the profile does not allow is a mistake in the scenario and must be refused")
	}
}

func TestContainerConfigIsTheShippedRecipe(t *testing.T) {
	prof, _ := ociSeccomp(shippedProfile(t))
	cfg, err := containerConfig(ctrSpec{Name: "h", Args: []string{"/helper"}, Caps: perfmonOnly, PID: pidJoined, PIDPath: "/proc/9/ns/pid", Seccomp: prof, Limits: shippedLimits(),
		Binds: []bind{{Source: "/a", Dest: "/run/soundpost-perf"}}}, "/rootfs", "/natcont/h")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(cfg)
	text := string(raw)
	if strings.Contains(text, `"network"`) {
		t.Errorf("no network namespace may be listed (host network namespace): %s", text)
	}
	var parsed struct {
		Process struct {
			NoNewPrivileges bool `json:"noNewPrivileges"`
			Capabilities    map[string][]string
			User            map[string]uint32
		}
		Root  struct{ Readonly bool }
		Linux struct {
			Namespaces  []map[string]string
			CgroupsPath string
			Seccomp     map[string]any
			Resources   struct {
				Pids   struct{ Limit int64 }
				Memory struct{ Limit, Swap int64 }
				CPU    struct{ Quota int64 }
			}
		}
	}
	if err = json.Unmarshal(raw, &parsed); err != nil {
		t.Fatal(err)
	}
	if !parsed.Process.NoNewPrivileges || !parsed.Root.Readonly {
		t.Error("no_new_privileges and a read-only root are part of the recipe")
	}
	for set, caps := range parsed.Process.Capabilities {
		want := 1
		if set == "inheritable" || set == "ambient" {
			want = 0
		}
		if len(caps) != want || want == 1 && caps[0] != "CAP_PERFMON" {
			t.Errorf("capability set %s = %v", set, caps)
		}
	}
	if parsed.Process.User["uid"] != 0 {
		t.Error("the helper runs as uid 0 (no ambient capabilities in container runtimes)")
	}
	types := map[string]string{}
	for _, ns := range parsed.Linux.Namespaces {
		types[ns["type"]] = ns["path"]
	}
	if _, ok := types["network"]; ok {
		t.Error("a network namespace was listed")
	}
	if _, ok := types["cgroup"]; ok {
		t.Error("a cgroup namespace was listed: the helper needs the host's")
	}
	if types["pid"] != "/proc/9/ns/pid" {
		t.Errorf("the PID namespace must be joined by path: %v", types)
	}
	if parsed.Linux.CgroupsPath != "/natcont/h" || parsed.Linux.Seccomp["defaultAction"] != "SCMP_ACT_ERRNO" {
		t.Errorf("cgroup path / seccomp: %v %v", parsed.Linux.CgroupsPath, parsed.Linux.Seccomp["defaultAction"])
	}
	r := parsed.Linux.Resources
	if r.Pids.Limit != 16 || r.Memory.Limit != 64<<20 || r.Memory.Swap != 64<<20 || r.CPU.Quota != 100000 {
		t.Errorf("cgroup v2 limits: %+v", r)
	}
}

func TestContainerConfigPIDModes(t *testing.T) {
	spec := ctrSpec{Name: "w", Args: []string{"/burner"}}
	for mode, wantPID := range map[pidMode]bool{pidOwn: true, pidHost: false} {
		spec.PID = mode
		cfg, err := containerConfig(spec, "/r", "/c")
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, ns := range cfg["linux"].(map[string]any)["namespaces"].([]map[string]any) {
			if ns["type"] == "pid" {
				found = true
			}
		}
		if found != wantPID {
			t.Errorf("mode %s: pid namespace listed = %v", mode, found)
		}
	}
	spec.PID = pidJoined
	if _, err := containerConfig(spec, "/r", "/c"); err == nil {
		t.Error("joining a PID namespace needs its path")
	}
	spec.PID = "weird"
	if _, err := containerConfig(spec, "/r", "/c"); err == nil {
		t.Error("an unknown PID mode must be refused")
	}
	if _, err := containerConfig(ctrSpec{PID: pidOwn}, "/r", "/c"); err == nil {
		t.Error("a container without a command must be refused")
	}
}
