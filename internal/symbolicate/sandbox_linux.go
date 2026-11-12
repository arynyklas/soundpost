//go:build linux && (amd64 || arm64)

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package symbolicate

import (
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

func installSandbox() error {
	runtime.LockOSThread()
	if e := verifyMemoryBoundary(); e != nil {
		return e
	}
	// RLIMIT_CPU bounds total process CPU; wall time is independently parent-owned.
	for resource, limit := range map[int]uint64{unix.RLIMIT_CPU: 5, unix.RLIMIT_CORE: 0, unix.RLIMIT_FSIZE: 0, unix.RLIMIT_NOFILE: 64} {
		if e := unix.Setrlimit(resource, &unix.Rlimit{Cur: limit, Max: limit}); e != nil {
			return e
		}
	}
	if e := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); e != nil {
		return e
	}
	const ld = unix.BPF_LD | unix.BPF_W | unix.BPF_ABS
	const jump = unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K
	const ret = unix.BPF_RET | unix.BPF_K
	filters := []unix.SockFilter{{Code: ld, K: 4}, {Code: jump, K: sandboxAuditArch, Jt: 1}, {Code: ret, K: unix.SECCOMP_RET_KILL_PROCESS}, {Code: ld, K: 0}}
	// An allowlist, not a network-only denylist: no open/stat/readlink, socket,
	// connect, exec, ptrace, process_vm, mount, namespace or filesystem mutation.
	allowed := []uint32{unix.SYS_READ, unix.SYS_WRITE, unix.SYS_CLOSE, unix.SYS_FUTEX, unix.SYS_CLOCK_GETTIME, unix.SYS_NANOSLEEP, unix.SYS_CLOCK_NANOSLEEP, unix.SYS_SCHED_YIELD, unix.SYS_MUNMAP, unix.SYS_MADVISE, unix.SYS_BRK, unix.SYS_RT_SIGACTION, unix.SYS_RT_SIGPROCMASK, unix.SYS_RT_SIGRETURN, unix.SYS_SIGALTSTACK, unix.SYS_GETPID, unix.SYS_GETTID, unix.SYS_GETRANDOM, unix.SYS_EXIT, unix.SYS_EXIT_GROUP, unix.SYS_SET_ROBUST_LIST, unix.SYS_SCHED_GETAFFINITY, unix.SYS_EPOLL_CREATE1, unix.SYS_EPOLL_CTL, unix.SYS_EPOLL_PWAIT, unix.SYS_EPOLL_PWAIT2, unix.SYS_EVENTFD2, unix.SYS_RESTART_SYSCALL}
	for _, nr := range allowed {
		filters = append(filters, unix.SockFilter{Code: jump, K: nr, Jf: 1}, unix.SockFilter{Code: ret, K: unix.SECCOMP_RET_ALLOW})
	}
	// Go's asynchronous preemption may signal only its own thread group,
	// never another same-uid host process.
	filters = append(filters, unix.SockFilter{Code: jump, K: unix.SYS_TGKILL, Jf: 4}, unix.SockFilter{Code: ld, K: 16}, unix.SockFilter{Code: jump, K: uint32(unix.Getpid()), Jf: 1}, unix.SockFilter{Code: ret, K: unix.SECCOMP_RET_ALLOW}, unix.SockFilter{Code: ret, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)})
	// Explicit hugetlb pages can be outside memory.max accounting on kernels
	// without memory_hugetlb_accounting. They and executable mappings are denied.
	filters = append(filters, unix.SockFilter{Code: jump, K: unix.SYS_MMAP, Jf: 6}, unix.SockFilter{Code: ld, K: 32}, unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K, K: unix.PROT_EXEC, Jt: 3}, unix.SockFilter{Code: ld, K: 40}, unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K, K: unix.MAP_HUGETLB, Jt: 1}, unix.SockFilter{Code: ret, K: unix.SECCOMP_RET_ALLOW}, unix.SockFilter{Code: ret, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)})
	// Only stdin/stdout/stderr pipes and Go-owned eventfd/epoll descriptors
	// exist at this point. Launchers pass no ExtraFiles or host mounts; bootstrap
	// files are closed, and the filter cannot acquire any file/socket descriptor.
	// Runtime eventfd reads/writes are needed for the independent wall watchdog.
	// Go may create runtime threads, never a separate process. clone3 returns
	// ENOSYS to use the legacy, inspectable flags ABI.
	filters = append(filters, unix.SockFilter{Code: jump, K: unix.SYS_CLONE, Jf: 4}, unix.SockFilter{Code: ld, K: 16}, unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K, K: unix.CLONE_THREAD, Jf: 1}, unix.SockFilter{Code: ret, K: unix.SECCOMP_RET_ALLOW}, unix.SockFilter{Code: ret, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)}, unix.SockFilter{Code: jump, K: unix.SYS_CLONE3, Jf: 1}, unix.SockFilter{Code: ret, K: unix.SECCOMP_RET_ERRNO | uint32(unix.ENOSYS)}, unix.SockFilter{Code: jump, K: unix.SYS_MPROTECT, Jf: 4}, unix.SockFilter{Code: ld, K: 32}, unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K, K: unix.PROT_EXEC, Jt: 1}, unix.SockFilter{Code: ret, K: unix.SECCOMP_RET_ALLOW}, unix.SockFilter{Code: ret, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)}, unix.SockFilter{Code: ret, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)})
	program := unix.SockFprog{Len: uint16(len(filters)), Filter: &filters[0]}
	result, _, errno := unix.RawSyscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, unix.SECCOMP_FILTER_FLAG_TSYNC, uintptr(unsafe.Pointer(&program)))
	runtime.KeepAlive(filters)
	if errno != 0 {
		return errno
	}
	if result != 0 {
		return errors.New("seccomp thread synchronization failed")
	}
	return nil
}

type nativeGroup struct {
	path      string
	directory *os.File
}

func newNativeGroup(root string) (*nativeGroup, error) {
	if !filepath.IsAbs(root) {
		return nil, errors.New("delegated cgroup root required")
	}
	var stat unix.Statfs_t
	if e := unix.Statfs(root, &stat); e != nil || stat.Type != unix.CGROUP2_SUPER_MAGIC {
		return nil, errors.New("cgroup v2 required")
	}
	if e := enableChildControllers(root); e != nil {
		return nil, e
	}
	p, e := os.MkdirTemp(root, "soundpost-symbolicate-")
	if e != nil {
		return nil, e
	}
	g := &nativeGroup{path: p}
	ok := false
	defer func() {
		if !ok {
			g.cleanup()
		}
	}()
	for _, setting := range []struct{ name, value string }{{"memory.max", "268435456"}, {"memory.swap.max", "0"}, {"memory.oom.group", "1"}, {"pids.max", "64"}} {
		name := filepath.Join(p, setting.name)
		if e = os.WriteFile(name, []byte(setting.value), 0600); e != nil {
			return nil, e
		}
		v, e := os.ReadFile(name)
		if e != nil || strings.TrimSpace(string(v)) != setting.value {
			return nil, errors.New("cgroup restriction not enforced")
		}
	}
	g.directory, e = os.Open(p)
	if e != nil {
		return nil, e
	}
	ok = true
	return g, nil
}

// A freshly delegated systemd subtree lists memory and pids in cgroup.controllers
// but leaves cgroup.subtree_control empty, so its children get no controller
// files. Enabling exactly those two for children is the delegatee's own right;
// the kernel refuses it (EBUSY) when the parent still holds processes, which keeps
// the "empty delegated subtree" requirement enforced. The child's limits are still
// written and read back afterwards.
func enableChildControllers(root string) error {
	b, e := os.ReadFile(filepath.Join(root, "cgroup.subtree_control"))
	if e != nil {
		return e
	}
	enabled := strings.Fields(string(b))
	var want []string
	for _, c := range []string{"memory", "pids"} {
		found := false
		for _, have := range enabled {
			found = found || have == c
		}
		if !found {
			want = append(want, "+"+c)
		}
	}
	if len(want) == 0 {
		return nil
	}
	return os.WriteFile(filepath.Join(root, "cgroup.subtree_control"), []byte(strings.Join(want, " ")), 0600)
}

// CLONE_INTO_CGROUP places the worker under the memory controller from birth;
// post-start migration would leave its preexisting memory charged elsewhere.
func (g *nativeGroup) configure(cmd *exec.Cmd) error {
	if g.directory == nil {
		return errors.New("missing cgroup descriptor")
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(g.directory.Fd())}
	return nil
}
func (g *nativeGroup) attach(pid int) error {
	b, e := os.ReadFile(filepath.Join(g.path, "cgroup.procs"))
	if e != nil {
		return e
	}
	for _, v := range strings.Fields(string(b)) {
		if v == strconv.Itoa(pid) {
			return nil
		}
	}
	return errors.New("worker not born in required cgroup")
}
func (g *nativeGroup) cleanup() {
	if g.directory != nil {
		g.directory.Close()
	}
	os.WriteFile(filepath.Join(g.path, "cgroup.kill"), []byte("1"), 0600)
	os.Remove(g.path)
}
func (g *nativeGroup) oom() bool {
	b, e := os.ReadFile(filepath.Join(g.path, "memory.events"))
	if e != nil {
		return false
	}
	for _, line := range strings.Split(string(b), "\n") {
		var key string
		var n uint64
		if _, e = fmt.Sscan(line, &key, &n); e == nil && key == "oom_kill" && n > 0 {
			return true
		}
	}
	return false
}

// Verify real controller files inside the child too. CLI flags or Docker
// HostConfig alone do not prove that a runtime/kernel enforced memory/swap.
func verifyMemoryBoundary() error {
	b, e := os.ReadFile("/proc/self/cgroup")
	if e != nil {
		return e
	}
	current := ""
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "0::") {
			current = strings.TrimPrefix(line, "0::")
		}
	}
	if current == "" || !strings.HasPrefix(current, "/") || strings.Contains(current, "..") {
		return errors.New("unavailable cgroup v2 membership")
	}
	root := filepath.Join("/sys/fs/cgroup", current)
	for _, setting := range []struct{ name, value string }{{"memory.max", "268435456"}, {"memory.swap.max", "0"}, {"pids.max", "64"}} {
		v, e := os.ReadFile(filepath.Join(root, setting.name))
		if e != nil || strings.TrimSpace(string(v)) != setting.value {
			return errors.New("required OS resource boundary unavailable")
		}
	}
	return nil
}
