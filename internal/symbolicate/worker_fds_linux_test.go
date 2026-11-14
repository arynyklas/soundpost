//go:build linux && (amd64 || arm64)

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package symbolicate

import (
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// plantInheritedFDs opens a file WITHOUT close-on-exec in the test process and
// duplicates it above fd 10, the way any library or test harness may leave
// descriptors behind (the review found /dev/ptmx fds 7 and 10 under go test). Low
// numbers can be overwritten by ExtraFiles (fd 3), so high ones are planted too.
func plantInheritedFDs(t *testing.T) []int {
	t.Helper()
	path := filepath.Join(t.TempDir(), "inherited-marker")
	if err := os.WriteFile(path, []byte("marker"), 0o600); err != nil {
		t.Fatal(err)
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY, 0) // no O_CLOEXEC
	if err != nil {
		t.Fatal(err)
	}
	fds := []int{fd}
	for range 2 {
		d, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_DUPFD, 10) // F_DUPFD: no CLOEXEC
		if errno != 0 {
			t.Fatal(errno)
		}
		fds = append(fds, int(d))
	}
	t.Cleanup(func() {
		for _, d := range fds {
			syscall.Close(d)
		}
	})
	for _, d := range fds {
		if flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(d), syscall.F_GETFD, 0); errno != 0 || flags&syscall.FD_CLOEXEC != 0 {
			t.Fatalf("planted descriptor %d is close-on-exec: flags %d errno %v", d, flags, errno)
		}
	}
	return fds
}

// workerDescriptors launches the real probe worker (staged or through clone3), takes
// it through attach and the 'R' handshake, and lists its descriptors: it is then the
// exec'd worker image with its sandbox installed, blocked reading its request.
func workerDescriptors(t *testing.T, staged bool) map[int]string {
	t.Helper()
	c := sandboxConfig(t)
	if staged {
		forceNoClone3(t)
	} else if !cloneIntoCgroupAvailable() {
		t.Skip("clone3 is unavailable on this host (the shipped unit's RestrictNamespaces=yes removes it): the clone3 path cannot be exercised here; the staged path covers this host")
	}
	ctx, cancel := context.WithTimeout(context.Background(), ProcessTimeout)
	t.Cleanup(cancel)
	p, err := (&Service{config: c}).launch(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	if err = p.cmd.Start(); err != nil {
		p.cleanup()
		t.Fatal(err)
	}
	pid := p.cmd.Process.Pid
	defer func() { p.cmd.Process.Kill(); p.cmd.Wait(); p.cleanup() }()
	if err = p.attach(); err != nil {
		t.Fatal(err)
	}
	if _, err = p.input.Write([]byte{'A'}); err != nil {
		t.Fatal(err)
	}
	var ready [33]byte
	if n, err := io.ReadFull(p.output, ready[:]); err != nil || ready[0] != 'R' {
		t.Fatalf("handshake: read %d bytes: %v", n, err)
	}
	if b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline"); err != nil || !strings.HasSuffix(string(b), "\x00"+probeArg+"\x00") {
		t.Fatalf("the process is not the exec'd probe worker: %q %v", b, err)
	}
	entries, err := os.ReadDir("/proc/" + strconv.Itoa(pid) + "/fd")
	if err != nil {
		t.Fatal(err)
	}
	fds := map[int]string{}
	for _, e := range entries {
		n, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		if dst, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "fd", e.Name())); err == nil {
			fds[n] = dst
		}
	}
	return fds
}

// The worker and probe processes start with stdio and nothing else of the parent's.
// A descriptor the parent left without close-on-exec must not survive either launch
// path; whatever sits above fd 2 afterwards must be what the worker's own Go runtime
// opened after the exec (epoll, eventfd, pipes), never a path-backed file such as
// /dev/ptmx or the planted marker.
func TestWorkerStartsWithOnlyStdio(t *testing.T) {
	for _, path := range []struct {
		name   string
		staged bool
	}{{"staged", true}, {"clone3", false}} {
		t.Run(path.name, func(t *testing.T) {
			planted := plantInheritedFDs(t)
			t.Logf("planted non-CLOEXEC descriptors %v", planted)
			fds := workerDescriptors(t, path.staged)
			var nums []int
			for n := range fds {
				nums = append(nums, n)
			}
			sort.Ints(nums)
			for _, n := range nums {
				t.Logf("worker fd %d -> %s", n, fds[n])
			}
			for _, n := range planted {
				if dst, ok := fds[n]; ok && strings.HasPrefix(dst, "/") {
					t.Errorf("worker inherited the parent's non-CLOEXEC descriptor %d (%s)", n, dst)
				}
			}
			for _, n := range nums {
				if n <= 2 {
					continue
				}
				dst := fds[n]
				if !strings.HasPrefix(dst, "anon_inode:") && !strings.HasPrefix(dst, "pipe:") {
					t.Errorf("worker fd %d is neither a runtime eventpoll/eventfd nor a pipe: %s", n, dst)
				}
			}
		})
	}
}

// The clone3 path passes the worker whatever the serving process leaves without
// close-on-exec (exec keeps such descriptors). Go opens every descriptor with
// O_CLOEXEC, so a served process should hold none above fd 2: measured here on the real
// `soundpost serve` with the native fixture config, scanning /proc/<pid>/fdinfo.
func TestServeHoldsNoInheritableDescriptors(t *testing.T) {
	c := sandboxConfig(t)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	logFile, err := os.Create(filepath.Join(t.TempDir(), "serve.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()
	logs := func() string { b, _ := os.ReadFile(logFile.Name()); return string(b) }
	cmd := exec.Command(c.WorkerPath, "serve", "--mode=single", "--data-dir", filepath.Join(t.TempDir(), "data"), "--listen", addr, "--symbolicate-config", os.Getenv("SOUNDPOST_SYMBOLICATE_TEST_CONFIG"))
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	for i := 0; i < 400 && !strings.Contains(logs(), "symbolicator:"); i++ { // up to 40 s: serve start-up took 6.5 s once and over 10 s under load
		time.Sleep(100 * time.Millisecond)
	}
	if !strings.Contains(logs(), "symbolicator: ready") {
		t.Fatalf("serve did not report a ready symbolicator: %q", logs())
	}
	entries, err := os.ReadDir("/proc/" + strconv.Itoa(cmd.Process.Pid) + "/fd")
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, e := range entries {
		n, err := strconv.Atoi(e.Name())
		if err != nil || n <= 2 {
			continue
		}
		info, err := os.ReadFile("/proc/" + strconv.Itoa(cmd.Process.Pid) + "/fdinfo/" + e.Name())
		if err != nil {
			continue // closed since the listing
		}
		var flags uint64
		for _, line := range strings.Split(string(info), "\n") {
			if rest, ok := strings.CutPrefix(line, "flags:"); ok {
				flags, _ = strconv.ParseUint(strings.TrimSpace(rest), 8, 64)
			}
		}
		seen++
		if flags&syscall.O_CLOEXEC == 0 {
			dst, _ := os.Readlink("/proc/" + strconv.Itoa(cmd.Process.Pid) + "/fd/" + e.Name())
			t.Errorf("serve holds non-CLOEXEC descriptor %d -> %s (flags %o)", n, dst, flags)
		}
	}
	t.Logf("scanned %d serve descriptors above fd 2; every one is close-on-exec", seen)
}
