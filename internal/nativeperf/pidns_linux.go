//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package nativeperf

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// ErrPIDNamespaceUnproven is returned when the identity of a target cannot be tied to the PID namespace the kernel will
// resolve its PID in. It is an ErrTargetIdentity (the helper reports the closed code generation_changed): nothing is
// acquired and no event is attributed.
//
// perf_event_open and pidfd_open resolve a PID in the caller's PID namespace, while every identity this package proves
// (namespace inode, process start, executable, cgroup, thread list) is read through /proc, which shows the PID namespace
// the proc mount was made for. When the two differ (a helper that unshared its PID namespace and kept the parent's /proc,
// or a proc of a child namespace mounted over it) the same number names two processes: the one that was authorized and
// the one a capture would attach to. Across a PID namespace boundary a target is therefore acquirable only by the PID the
// helper's own namespace gives it, and only through a /proc that belongs to the helper's own PID namespace.
var ErrPIDNamespaceUnproven = fmt.Errorf("%w: /proc does not show this process's PID namespace", ErrTargetIdentity)

// procViewIsOwn proves that /proc is the proc of this process's own PID namespace: the kernel resolves /proc/self through
// the proc mount's namespace, so it names this process by the PID this process has in its own namespace (getpid) exactly
// when both are the same namespace. A proc of an ancestor namespace names it by another number, a proc of a descendant or
// unrelated namespace cannot see it at all.
func procViewIsOwn() error {
	link, e := os.Readlink("/proc/self")
	if e != nil || link != strconv.Itoa(os.Getpid()) {
		return ErrPIDNamespaceUnproven
	}
	return nil
}

// nspidOf parses the NSpid line of a /proc/<pid>/status: the process's PID in each PID namespace from the namespace of the
// proc mount down to the process's own, outermost first. It returns nil for a missing or malformed line.
func nspidOf(status []byte) []uint32 {
	for _, line := range strings.Split(string(status), "\n") {
		rest, ok := strings.CutPrefix(line, "NSpid:")
		if !ok {
			continue
		}
		var out []uint32
		for _, f := range strings.Fields(rest) {
			n, e := strconv.ParseUint(f, 10, 32)
			if e != nil || n == 0 || len(out) >= 32 {
				return nil
			}
			out = append(out, uint32(n))
		}
		return out
	}
	return nil
}

// nspidProves reports whether the kernel's two independent statements about the target agree: its ns/pid link (targetNS)
// against this process's own (ownNS), and its NSpid chain. The chain starts with the PID through which it was read (tgid,
// the number perf_event_open and pidfd_open are given) and has one entry per namespace level, so it has exactly one entry
// when the target lives in this process's own PID namespace and more when it lives in a descendant one.
func nspidProves(nspid []uint32, tgid uint32, targetNS, ownNS uint64) bool {
	if len(nspid) == 0 || nspid[0] != tgid {
		return false
	}
	return (len(nspid) == 1) == (targetNS == ownNS)
}

// checkNSpid is nspidProves for a status file read through /proc.
func checkNSpid(status []byte, tgid uint32, targetNS uint64) error {
	st, e := os.Stat("/proc/self/ns/pid")
	if e != nil {
		return ErrPIDNamespaceUnproven
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || !nspidProves(nspidOf(status), tgid, targetNS, sys.Ino) {
		return ErrPIDNamespaceUnproven
	}
	return nil
}
