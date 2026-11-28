//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"fmt"
)

// pidMode says which PID namespace a container is in.
type pidMode string

const (
	pidOwn    pidMode = "own"  // a new PID namespace (the workload container)
	pidHost   pidMode = "host" // the host's (Kubernetes hostPID)
	pidJoined pidMode = "join" // the namespace of another container (Compose `pid: container:<workload>`)
)

type bind struct {
	Source, Dest string
	ReadOnly     bool
}

type limits struct {
	Pids        int64 // pids.max
	MemoryBytes int64 // memory.max (swap is set to the same value: no swap)
	CPUQuotaUS  int64 // cpu.max quota per CPUPeriodUS
	CPUPeriodUS uint64
}

// ctrSpec is one container of the harness. Every container shares the one read-only rootfs and the host network
// namespace (no network namespace is ever created), the host cgroup namespace (the helper identifies a target by the
// inode of its cgroup directory, which a private cgroup namespace hides) and runs as the given uid with only Caps.
type ctrSpec struct {
	Name     string
	Args     []string
	UID, GID uint32
	Caps     []string // e.g. CAP_PERFMON; empty = none
	PID      pidMode
	PIDPath  string // /proc/<pid>/ns/pid of the namespace to join when PID == pidJoined
	Seccomp  map[string]any
	Binds    []bind
	Limits   *limits
}

// containerConfig builds the OCI runtime config.json of one container. No `network`, `user` or `cgroup` namespace is
// listed: the container uses the host's. The root filesystem is read-only, no_new_privs is set and the capability
// sets are exactly Caps.
func containerConfig(s ctrSpec, rootfs, cgroupPath string) (map[string]any, error) {
	if len(s.Args) == 0 {
		return nil, errors.New("container without a command")
	}
	caps := make([]string, 0, len(s.Caps))
	caps = append(caps, s.Caps...)
	namespaces := []map[string]any{{"type": "mount"}, {"type": "ipc"}, {"type": "uts"}}
	switch s.PID {
	case pidOwn:
		namespaces = append(namespaces, map[string]any{"type": "pid"})
	case pidJoined:
		if s.PIDPath == "" {
			return nil, errors.New("joined PID namespace without a path")
		}
		namespaces = append(namespaces, map[string]any{"type": "pid", "path": s.PIDPath})
	case pidHost:
	default:
		return nil, fmt.Errorf("unknown PID mode %q", s.PID)
	}
	mounts := []map[string]any{
		{"destination": "/proc", "type": "proc", "source": "proc"},
		{"destination": "/dev", "type": "tmpfs", "source": "tmpfs", "options": []string{"nosuid", "strictatime", "mode=755", "size=65536k"}},
		{"destination": "/dev/pts", "type": "devpts", "source": "devpts", "options": []string{"nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620", "gid=5"}},
		{"destination": "/dev/shm", "type": "tmpfs", "source": "shm", "options": []string{"nosuid", "noexec", "nodev", "mode=1777", "size=65536k"}},
		{"destination": "/sys", "type": "sysfs", "source": "sysfs", "options": []string{"nosuid", "noexec", "nodev", "ro"}},
		{"destination": "/sys/fs/cgroup", "type": "cgroup", "source": "cgroup", "options": []string{"nosuid", "noexec", "nodev", "relatime", "ro"}},
	}
	for _, b := range s.Binds {
		mode := "rw"
		if b.ReadOnly {
			mode = "ro"
		}
		mounts = append(mounts, map[string]any{"destination": b.Dest, "type": "bind", "source": b.Source, "options": []string{"rbind", "nosuid", "nodev", mode}})
	}
	linux := map[string]any{
		"namespaces":    namespaces,
		"cgroupsPath":   cgroupPath,
		"resources":     resources(s.Limits),
		"maskedPaths":   []string{"/proc/acpi", "/proc/asound", "/proc/kcore", "/proc/keys", "/proc/latency_stats", "/proc/timer_list", "/proc/timer_stats", "/proc/sched_debug", "/sys/firmware", "/proc/scsi"},
		"readonlyPaths": []string{"/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger"},
	}
	if s.Seccomp != nil {
		linux["seccomp"] = s.Seccomp
	}
	return map[string]any{
		"ociVersion": "1.0.2-dev",
		"process": map[string]any{
			"terminal":        false,
			"user":            map[string]any{"uid": s.UID, "gid": s.GID},
			"args":            s.Args,
			"env":             []string{"PATH=/", "TERM=dumb"},
			"cwd":             "/",
			"capabilities":    map[string]any{"bounding": caps, "effective": caps, "permitted": caps, "inheritable": []string{}, "ambient": []string{}},
			"noNewPrivileges": true,
			"rlimits":         []map[string]any{{"type": "RLIMIT_NOFILE", "hard": 1024, "soft": 1024}},
		},
		"root":     map[string]any{"path": rootfs, "readonly": true},
		"hostname": "soundpost-" + s.Name,
		"mounts":   mounts,
		"linux":    linux,
	}, nil
}

// resources is the cgroup v2 limit set. The device allow-list is runc's own default (none beyond the default devices).
func resources(l *limits) map[string]any {
	r := map[string]any{"devices": []map[string]any{{"allow": false, "access": "rwm"}}}
	if l == nil {
		return r
	}
	if l.Pids > 0 {
		r["pids"] = map[string]any{"limit": l.Pids}
	}
	if l.MemoryBytes > 0 {
		r["memory"] = map[string]any{"limit": l.MemoryBytes, "swap": l.MemoryBytes}
	}
	if l.CPUQuotaUS > 0 {
		r["cpu"] = map[string]any{"quota": l.CPUQuotaUS, "period": l.CPUPeriodUS}
	}
	return r
}

// ociSeccomp converts the shipped Docker-format profile (deploy/seccomp/soundpost-perf.json) into the OCI runtime
// config's linux.seccomp object, rule for rule. withhold names syscalls whose allow rules are dropped, so the default
// action (EPERM) applies to them: the profile that withholds perf_event_open. Nothing is added to the profile.
func ociSeccomp(profile []byte, withhold ...string) (map[string]any, error) {
	var in struct {
		DefaultAction   string `json:"defaultAction"`
		DefaultErrnoRet *int   `json:"defaultErrnoRet"`
		ArchMap         []struct {
			Architecture    string   `json:"architecture"`
			SubArchitecture []string `json:"subArchitectures"`
		} `json:"archMap"`
		Syscalls []map[string]any `json:"syscalls"`
	}
	if err := json.Unmarshal(profile, &in); err != nil {
		return nil, fmt.Errorf("seccomp profile: %w", err)
	}
	if in.DefaultAction == "" || len(in.ArchMap) == 0 || len(in.Syscalls) == 0 {
		return nil, errors.New("seccomp profile has no default action, architectures or rules")
	}
	drop := map[string]bool{}
	for _, n := range withhold {
		drop[n] = true
	}
	var arches []string
	for _, a := range in.ArchMap {
		arches = append(arches, a.Architecture)
		arches = append(arches, a.SubArchitecture...)
	}
	var rules []map[string]any
	removed := 0
	for _, rule := range in.Syscalls {
		names, _ := rule["names"].([]any)
		var keep []string
		for _, n := range names {
			name, _ := n.(string)
			if drop[name] {
				removed++
				continue
			}
			keep = append(keep, name)
		}
		if len(keep) == 0 {
			continue
		}
		out := map[string]any{}
		for k, v := range rule {
			out[k] = v
		}
		out["names"] = keep
		rules = append(rules, out)
	}
	if removed < len(drop) {
		return nil, fmt.Errorf("the profile does not contain every syscall to withhold (%v)", withhold)
	}
	out := map[string]any{"defaultAction": in.DefaultAction, "architectures": arches, "syscalls": rules}
	if in.DefaultErrnoRet != nil {
		out["defaultErrnoRet"] = *in.DefaultErrnoRet
	}
	return out, nil
}
