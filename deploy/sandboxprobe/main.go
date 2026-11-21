//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0

// sandboxprobe runs a fixed list of syscalls inside whatever sandbox it is started in and compares each outcome
// with what the shipped policy must produce: packaging/systemd/soundpost-perf-acquire.service (--mode systemd) or
// deploy/seccomp/soundpost-perf.json under a container runtime (--mode seccomp-json). It is the evidence driver for the
// "recipe started on a real host" rows: allowed calls must reach the kernel (an argument the kernel rejects with its
// own errno proves the filter let the call through), denied calls must fail with the filter's errno, and the unit's
// resource and capability limits must be visible in /proc/self. It performs no capture and holds no capability of
// its own; every denied call uses an argument the kernel itself would reject with a different errno, so EPERM can only
// have come from the filter.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

const (
	sysPpoll        = 271
	sysBpf          = 321
	sysKcmp         = 312
	sysUserfaultfd  = 323
	sysPidfdOpen    = 434
	sysPidfdGetfd   = 438
	sysProcessVMRd  = 310
	sysPerfEvtOpen  = 298
	sysPtrace       = 101
	prSetTHPDisable = 41
	prSetDumpable   = 4
	bogusPID        = 0x7ffffff0
)

type outcome struct {
	Name     string `json:"name"`
	Want     string `json:"want"`
	Got      string `json:"got"`
	Passed   bool   `json:"passed"`
	Describe string `json:"describe"`
}

type report struct {
	Mode     string            `json:"mode"`
	Kernel   string            `json:"kernel"`
	Status   map[string]string `json:"proc_self_status"`
	CoreRlim string            `json:"rlimit_core"`
	Cases    []outcome         `json:"cases"`
	Failures []string          `json:"failures"`
	Pass     bool              `json:"pass"`
}

func main() {
	mode := flag.String("mode", "", "systemd | seccomp-json")
	flag.Parse()
	if flag.NArg() != 0 || (*mode != "systemd" && *mode != "seccomp-json") {
		fmt.Fprintln(os.Stderr, "usage: sandboxprobe --mode systemd|seccomp-json")
		os.Exit(2)
	}
	r := run(*mode)
	b, _ := json.Marshal(r)
	fmt.Println(string(b))
	if !r.Pass {
		os.Exit(1)
	}
}

func errName(e syscall.Errno) string {
	if e == 0 {
		return "ok"
	}
	switch e {
	case syscall.EPERM:
		return "EPERM"
	case syscall.EFAULT:
		return "EFAULT"
	case syscall.EINVAL:
		return "EINVAL"
	case syscall.ESRCH:
		return "ESRCH"
	case syscall.EBADF:
		return "EBADF"
	case syscall.ENOSYS:
		return "ENOSYS"
	case syscall.EAFNOSUPPORT:
		return "EAFNOSUPPORT"
	case syscall.EACCES:
		return "EACCES"
	}
	return "errno" + strconv.Itoa(int(e))
}

func call(trap uintptr, a ...uintptr) syscall.Errno {
	var v [6]uintptr
	copy(v[:], a)
	_, _, e := syscall.Syscall6(trap, v[0], v[1], v[2], v[3], v[4], v[5])
	return e
}

func run(mode string) report {
	r := report{Mode: mode, Kernel: strings.TrimSpace(readFile("/proc/sys/kernel/osrelease")), Status: map[string]string{}, Failures: []string{}}
	for _, line := range strings.Split(readFile("/proc/self/status"), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if ok && (k == "Seccomp" || k == "NoNewPrivs" || k == "CapEff" || k == "CapBnd" || k == "CapAmb" || k == "Uid") {
			r.Status[k] = strings.TrimSpace(v)
		}
	}
	var core syscall.Rlimit
	if syscall.Getrlimit(syscall.RLIMIT_CORE, &core) == nil {
		r.CoreRlim = fmt.Sprintf("%d/%d", core.Cur, core.Max)
	}
	add := func(name, want string, got syscall.Errno, describe string) {
		g := errName(got)
		o := outcome{Name: name, Want: want, Got: g, Passed: inSet(g, want), Describe: describe}
		r.Cases = append(r.Cases, o)
		if !o.Passed {
			r.Failures = append(r.Failures, fmt.Sprintf("%s: got %s, want %s", name, g, want))
		}
	}
	// A denied call fails with the filter's errno; the argument is one the kernel itself rejects with another errno.
	denied := "EPERM"
	add("getpid", "ok", call(syscall.SYS_GETPID), "allowed: reaches the kernel")
	add("perf_event_open(NULL attr, PERF_FLAG_FD_CLOEXEC)", "EFAULT", call(sysPerfEvtOpen, 0, 0, ^uintptr(0), ^uintptr(0), 8), "allowed: the kernel itself rejects the NULL attribute")
	fd, _, e := syscall.Syscall(sysPidfdOpen, uintptr(os.Getpid()), 0, 0)
	if e == 0 {
		syscall.Close(int(fd))
	}
	add("pidfd_open(self, 0)", "ok", e, "allowed")
	p := [2]int{}
	if syscall.Pipe(p[:]) == nil {
		// struct pollfd{int fd; short events, revents}: one entry, zero timeout, NULL signal mask: the helper's ring probe
		poll := struct {
			fd             int32
			events, revent int16
		}{fd: int32(p[0]), events: 1}
		ts := syscall.Timespec{}
		add("ppoll(nfds=1, NULL sigmask)", "ok", call(sysPpoll, uintptr(unsafe.Pointer(&poll)), 1, uintptr(unsafe.Pointer(&ts)), 0, 0), "allowed")
		syscall.Close(p[0])
		syscall.Close(p[1])
	}
	add("prctl(PR_SET_THP_DISABLE, 1)", "ok", call(syscall.SYS_PRCTL, prSetTHPDisable, 1, 0, 0, 0), "allowed: the helper's own THP opt-out")
	add("socket(AF_UNIX)", "ok", socketErr(syscall.AF_UNIX), "allowed: the helper's only address family")

	add("bpf(invalid command)", denied, call(sysBpf, 0x7fffffff, 0, 0), "denied: eBPF (kernel would answer EINVAL)")
	add("kcmp(bogus pids)", denied, call(sysKcmp, bogusPID, bogusPID, 99, 0, 0), "denied: descriptor comparison across processes (kernel would answer ESRCH)")
	add("process_vm_readv(bogus pid)", denied, readForeign(), "denied: cross-process memory read (kernel would answer ESRCH)")
	add("userfaultfd(invalid flags)", denied, call(sysUserfaultfd, 0x7fffffff), "denied: (kernel would answer EINVAL)")
	add("pidfd_getfd(invalid pidfd)", denied, call(sysPidfdGetfd, ^uintptr(0), 0, 0), "denied: duplicating another process's descriptor (kernel would answer EBADF)")
	add("ptrace(invalid request, bogus pid)", denied, call(sysPtrace, 0x7fff, bogusPID, 0, 0), "denied: debugger attach (kernel would answer ESRCH)")

	switch mode {
	case "systemd":
		// SystemCallErrorNumber=EPERM, RestrictAddressFamilies=AF_UNIX, MemoryDenyWriteExecute=yes, CapabilityBoundingSet=CAP_PERFMON.
		add("socket(AF_INET)", "EAFNOSUPPORT", socketErr(syscall.AF_INET), "denied: RestrictAddressFamilies=AF_UNIX")
		// systemd 252 on a 6.1 kernel enforces MemoryDenyWriteExecute with a seccomp filter (EPERM); newer systemd on a
		// 6.3+ kernel uses PR_SET_MDWE, whose refusal is EACCES. Either is the unit's declared denial.
		add("mmap(PROT_WRITE|PROT_EXEC)", "EPERM|EACCES", mapRWX(), "denied: MemoryDenyWriteExecute=yes")
		want := map[string]string{"Seccomp": "2", "NoNewPrivs": "1"}
		for k, v := range want {
			if r.Status[k] != v {
				r.Failures = append(r.Failures, fmt.Sprintf("/proc/self/status %s: %q, want %q", k, r.Status[k], v))
			}
		}
		// CAP_PERFMON is capability 38: 0x4000000000, and nothing else may be in the bounding set.
		if !strings.HasSuffix(r.Status["CapBnd"], "0000004000000000") {
			r.Failures = append(r.Failures, fmt.Sprintf("CapBnd %q, want exactly CAP_PERFMON (0000004000000000)", r.Status["CapBnd"]))
		}
		if r.CoreRlim != "0/0" {
			r.Failures = append(r.Failures, fmt.Sprintf("RLIMIT_CORE %s, want 0/0 (LimitCORE=0)", r.CoreRlim))
		}
	case "seccomp-json":
		// defaultAction SCMP_ACT_ERRNO(EPERM); only the audited argument shapes are allowed; clone3 answers ENOSYS.
		add("socket(AF_INET)", denied, socketErr(syscall.AF_INET), "denied: only AF_UNIX sockets are allowed")
		add("perf_event_open(NULL attr, flags 0)", denied, call(sysPerfEvtOpen, 0, 0, ^uintptr(0), ^uintptr(0), 0), "denied: only PERF_FLAG_FD_CLOEXEC (8) is allowed")
		add("ppoll(nfds=2)", denied, call(sysPpoll, 0, 2, 0, 0, 0), "denied: only nfds == 1 with a NULL sigmask is allowed")
		add("prctl(PR_SET_DUMPABLE, 0)", denied, call(syscall.SYS_PRCTL, prSetDumpable, 0, 0, 0, 0), "denied: only PR_SET_THP_DISABLE(1) is allowed")
		add("clone3", "ENOSYS", call(435, 0, 0), "the profile answers ENOSYS so the runtime falls back to clone")
		if r.Status["Seccomp"] != "2" {
			r.Failures = append(r.Failures, fmt.Sprintf("/proc/self/status Seccomp %q, want 2 (filter mode)", r.Status["Seccomp"]))
		}
	}
	r.Pass = len(r.Failures) == 0
	return r
}

func socketErr(domain int) syscall.Errno {
	fd, _, e := syscall.Syscall(syscall.SYS_SOCKET, uintptr(domain), syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if e == 0 {
		syscall.Close(int(fd))
	}
	return e
}

func readForeign() syscall.Errno {
	buf := make([]byte, 8)
	local := syscall.Iovec{Base: &buf[0], Len: 8}
	remote := syscall.Iovec{Base: &buf[0], Len: 8}
	return call(sysProcessVMRd, bogusPID, uintptr(unsafe.Pointer(&local)), 1, uintptr(unsafe.Pointer(&remote)), 1, 0)
}

func mapRWX() syscall.Errno {
	_, _, e := syscall.Syscall6(syscall.SYS_MMAP, 0, 4096, syscall.PROT_READ|syscall.PROT_WRITE|syscall.PROT_EXEC, syscall.MAP_PRIVATE|syscall.MAP_ANON, ^uintptr(0), 0)
	return e
}

func readFile(path string) string {
	b, e := os.ReadFile(path)
	if e != nil {
		return ""
	}
	return string(b)
}

// inSet reports whether got is one of the alternatives of want ("A|B").
func inSet(got, want string) bool {
	for _, w := range strings.Split(want, "|") {
		if got == w {
			return true
		}
	}
	return false
}
