//go:build linux && (amd64 || arm64)

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package symbolicate

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

func forceNoClone3(t *testing.T) {
	t.Helper()
	previous := cloneIntoCgroupAvailable
	cloneIntoCgroupAvailable = func() bool { return false }
	t.Cleanup(func() { cloneIntoCgroupAvailable = previous })
}

// With clone3 the worker is born in the group (CLONE_INTO_CGROUP); without it the
// launch is the two-step staged form. Exactly one of the two is selected.
func TestConfigureSelectsCloneIntoCgroupOrStaging(t *testing.T) {
	dir, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	previous := cloneIntoCgroupAvailable
	defer func() { cloneIntoCgroupAvailable = previous }()

	cloneIntoCgroupAvailable = func() bool { return true }
	g := &nativeGroup{directory: dir}
	cmd := exec.Command("/worker", workerArg)
	if err = g.configure(cmd); err != nil {
		t.Fatal(err)
	}
	if cmd.SysProcAttr == nil || !cmd.SysProcAttr.UseCgroupFD || cmd.SysProcAttr.CgroupFD != int(dir.Fd()) {
		t.Fatalf("clone3 available but CLONE_INTO_CGROUP not requested: %+v", cmd.SysProcAttr)
	}
	if g.releaseW != nil || len(cmd.ExtraFiles) != 0 || cmd.Args[1] != workerArg {
		t.Fatalf("clone3 available but the launch was staged: %v", cmd.Args)
	}

	cloneIntoCgroupAvailable = func() bool { return false }
	for _, c := range []struct{ in, out string }{{workerArg, stageWorkerArg}, {probeArg, stageProbeArg}} {
		g = &nativeGroup{directory: dir}
		cmd = exec.Command("/worker", c.in)
		if err = g.configure(cmd); err != nil {
			t.Fatal(err)
		}
		if cmd.SysProcAttr != nil && cmd.SysProcAttr.UseCgroupFD {
			t.Fatal("clone3 unavailable but CLONE_INTO_CGROUP requested")
		}
		if len(cmd.Args) != 2 || cmd.Args[1] != c.out || len(cmd.ExtraFiles) != 1 || g.releaseW == nil {
			t.Fatalf("%s not staged as %s: %v", c.in, c.out, cmd.Args)
		}
		g.cleanup()
	}
	for _, bad := range [][]string{{"/worker"}, {"/worker", "--other"}, {"/worker", workerArg, "extra"}} {
		g = &nativeGroup{directory: dir}
		cmd = &exec.Cmd{Path: "/worker", Args: bad}
		if err = g.configure(cmd); err == nil {
			t.Fatalf("staged launch accepted arguments %q", bad)
		}
	}
}

// startStaged launches a staged probe worker without attaching it and returns the
// service, the process and the new group's directory.
func startStaged(t *testing.T) (c Config, p *workerProcess, group string) {
	t.Helper()
	c = sandboxConfig(t)
	forceNoClone3(t)
	before := groupNames(t, c.CgroupRoot)
	s := &Service{config: c}
	ctx, cancel := context.WithTimeout(context.Background(), ProcessTimeout)
	t.Cleanup(cancel)
	var err error
	if p, err = s.launch(ctx, true); err != nil {
		t.Fatal(err)
	}
	for name := range groupNames(t, c.CgroupRoot) {
		if !before[name] {
			group = filepath.Join(c.CgroupRoot, name)
		}
	}
	if group == "" {
		t.Fatal("the launch created no private group")
	}
	if err = p.cmd.Start(); err != nil {
		p.cleanup()
		t.Fatal(err)
	}
	return c, p, group
}

func groupNames(t *testing.T, root string) map[string]bool {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "soundpost-symbolicate-") {
			names[e.Name()] = true
		}
	}
	return names
}

func readCounter(t *testing.T, path string) uint64 {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	n, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func statusKB(t *testing.T, pid int, key string) uint64 {
	t.Helper()
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, key+":") {
			f := strings.Fields(line)
			n, _ := strconv.ParseUint(f[1], 10, 64)
			return n
		}
	}
	t.Fatalf("no %s in /proc status", key)
	return 0
}

func events(t *testing.T, path, key string) uint64 {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		var k string
		var n uint64
		if _, err = fmtSscan(line, &k, &n); err == nil && k == key {
			return n
		}
	}
	return 0
}

func fmtSscan(line string, k *string, n *uint64) (int, error) {
	f := strings.Fields(line)
	if len(f) != 2 {
		return 0, errors.New("not a pair")
	}
	v, err := strconv.ParseUint(f[1], 10, 64)
	*k, *n = f[0], v
	return 2, err
}

// The worker allocates until the kernel kills it. Without clone3 it is staged, moved
// into the limited group, verified and only then released; the memory it allocates
// after the exec must be charged to that group (memory.peak reaches the 256 MiB
// limit and the group, not the parent's, records the OOM kill), the staging process
// beforehand must be small and uncharged to the group, and the process is never
// outside the group once running.
func TestStagedWorkerMemoryIsChargedToTheLimitedGroup(t *testing.T) {
	c, p, group := startStaged(t)
	pid := p.cmd.Process.Pid
	defer func() { p.cmd.Process.Kill(); p.cmd.Wait(); p.cleanup() }()

	// The staging process is blocked: give it time to finish its runtime start-up,
	// then record its footprint. It is still in the parent's group, not the child's.
	time.Sleep(300 * time.Millisecond)
	if rss, hwm := statusKB(t, pid, "VmRSS"), statusKB(t, pid, "VmHWM"); hwm > 64*1024 {
		t.Fatalf("staging process footprint is not small: VmRSS %d kB, VmHWM %d kB", rss, hwm)
	} else {
		t.Logf("staging process before release: VmRSS %d kB, VmHWM %d kB", rss, hwm)
	}
	cmdline := func() string {
		b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	if got := cmdline(); !strings.HasSuffix(got, stageProbeArg+"\x00") {
		t.Fatalf("before release the process must still be the blocked staging process: %q", got)
	}
	if cur := readCounter(t, filepath.Join(group, "memory.current")); cur > 256*1024 {
		t.Fatalf("limited group is charged %d bytes before the worker exists in it", cur)
	}
	if err := (&nativeGroup{path: group}).member(pid); err == nil {
		t.Fatal("staging process was in the limited group before attach")
	}
	// The group knows nothing of the process until attach, which migrates, verifies, releases.
	if err := p.attach(); err != nil {
		t.Fatal(err)
	}
	cg, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cgroup")
	if err != nil || !strings.HasSuffix(strings.TrimSpace(string(cg)), filepath.Base(group)) {
		t.Fatalf("/proc/%d/cgroup after attach: %q %v", pid, cg, err)
	}

	// Drive the probe protocol by hand for the memory probe.
	if _, err = p.input.Write([]byte{'A'}); err != nil {
		t.Fatal(err)
	}
	var ready [33]byte
	if n, err := io.ReadFull(p.output, ready[:]); err != nil || ready[0] != 'R' || model.Hash(ready[1:]) != c.WorkerSHA256 {
		t.Fatalf("worker handshake after staged exec: read %d bytes: %v %q", n, err, ready[:n])
	}
	if got := cmdline(); !strings.HasSuffix(got, "\x00"+probeArg+"\x00") {
		t.Fatalf("after release the process must have exec'd the worker image: %q", got)
	}
	if err = json.NewEncoder(p.input).Encode(probeInput{ProbeMemory}); err != nil {
		t.Fatal(err)
	}
	p.input.Close()
	io.Copy(io.Discard, p.output)
	p.cmd.Wait()
	peak := readCounter(t, filepath.Join(group, "memory.peak"))
	oom := events(t, filepath.Join(group, "memory.events"), "oom_kill")
	t.Logf("limited group after the worker's allocation: memory.peak %d bytes, oom_kill %d", peak, oom)
	if peak < 200<<20 || peak > 300<<20 {
		t.Fatalf("worker allocations are not charged to the limited group: memory.peak %d", peak)
	}
	if oom == 0 {
		t.Fatal("the limited group recorded no OOM kill")
	}
}

// Both probes and the denial checks pass through a staged launch.
func TestStagedProbesPass(t *testing.T) {
	c := sandboxConfig(t)
	forceNoClone3(t)
	for _, k := range []ProbeKind{ProbeFile, ProbeNetwork, ProbeExec} {
		if r := Probe(context.Background(), c, k); !r.Denied || r.Reason != Resolved {
			t.Fatalf("staged %s probe: %+v", k, r)
		}
	}
}

// A staging process that is killed, or whose parent end is closed, without ever being
// released runs no worker and leaves neither a process nor a group.
func TestStagedNeverReleasedLeavesNothing(t *testing.T) {
	c := sandboxConfig(t)
	t.Run("killed", func(t *testing.T) {
		_, p, group := startStaged(t)
		pid := p.cmd.Process.Pid
		p.cmd.Process.Kill()
		p.cmd.Wait()
		p.cleanup()
		assertGone(t, pid, group)
	})
	t.Run("pipe closed", func(t *testing.T) {
		_, p, group := startStaged(t)
		pid := p.cmd.Process.Pid
		p.cleanup() // closes the release pipe and removes the group while the stage waits
		done := make(chan error, 1)
		go func() { done <- p.cmd.Wait() }()
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("a never-released staging process exited successfully")
			}
		case <-time.After(3 * time.Second):
			p.cmd.Process.Kill()
			t.Fatal("staging process outlived the closed release pipe")
		}
		assertGone(t, pid, group)
	})
	t.Run("migrated but never released", func(t *testing.T) {
		_, p, group := startStaged(t)
		pid := p.cmd.Process.Pid
		if err := os.WriteFile(filepath.Join(group, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0o600); err != nil {
			t.Fatal(err)
		}
		p.cmd.Process.Kill()
		p.cmd.Wait()
		p.cleanup()
		assertGone(t, pid, group)
	})
	if left := groupNames(t, c.CgroupRoot); len(left) != 0 {
		t.Fatalf("private groups left behind: %v", left)
	}
}

func assertGone(t *testing.T, pid int, group string) {
	t.Helper()
	if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("process %d still exists: %v", pid, err)
	}
	if _, err := os.Stat(group); !os.IsNotExist(err) {
		t.Fatalf("group %s still exists: %v", group, err)
	}
}
