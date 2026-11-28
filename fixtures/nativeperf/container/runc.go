//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

// lockedBuffer is an output sink a goroutine writes while the harness polls it.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.b.Len() < 1<<20 {
		l.b.Write(p)
	}
	return len(p), nil
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// runtime owns everything the harness creates on the host: one state directory for runc, one temporary directory with the
// bundles, and one parent cgroup. cleanup removes all three.
type runtimeEnv struct {
	runc       string
	work       string // temporary directory: rootfs, bundles, run/policy directories
	rootfs     string
	state      string // runc --root
	cgroupRoot string // /sys/fs/cgroup
	cgroupDir  string // parent cgroup, relative to cgroupRoot
	ctrs       []*ctr
}

// ctr is one `runc run` child. The container's init is the program itself (no shell, no init process).
type ctr struct {
	env     *runtimeEnv
	spec    ctrSpec
	id      string
	cgroup  string // relative to the cgroup root
	cmd     *exec.Cmd
	stdout  *lockedBuffer
	stderr  *lockedBuffer
	done    chan struct{}
	exit    int
	hostPID int
}

func (e *runtimeEnv) runcCmd(ctx context.Context, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, e.runc, append([]string{"--root", e.state}, args...)...)
}

// runcOutput runs one runc subcommand to completion and returns its combined output.
func (e *runtimeEnv) runcOutput(timeout time.Duration, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := e.runcCmd(ctx, args...).CombinedOutput()
	if err != nil {
		err = fmt.Errorf("runc %s: %w: %s", strings.Join(args, " "), err, clip(strings.TrimSpace(string(out)), 400))
	}
	return string(out), err
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

// start writes the bundle and starts the container in the foreground of a child `runc run` (stdio is pipes, no terminal).
func (e *runtimeEnv) start(s ctrSpec, runID string) (*ctr, error) {
	c := &ctr{env: e, spec: s, id: "natcont-" + runID + "-" + s.Name, stdout: &lockedBuffer{}, stderr: &lockedBuffer{}, done: make(chan struct{})}
	c.cgroup = filepath.Join(e.cgroupDir, s.Name) // relative to the cgroup root
	// an absolute cgroupsPath is rooted at the cgroup mount; a relative one would be relative to the cgroup of this process
	cfg, err := containerConfig(s, e.rootfs, "/"+c.cgroup)
	if err != nil {
		return nil, err
	}
	bundle := filepath.Join(e.work, "bundle-"+s.Name)
	if err = os.MkdirAll(bundle, 0o700); err != nil {
		return nil, err
	}
	raw, err := json.MarshalIndent(cfg, "", " ")
	if err != nil {
		return nil, err
	}
	if err = os.WriteFile(filepath.Join(bundle, "config.json"), raw, 0o600); err != nil {
		return nil, err
	}
	c.cmd = e.runcCmd(context.Background(), "run", "--bundle", bundle, c.id)
	c.cmd.Stdout, c.cmd.Stderr = c.stdout, c.stderr
	e.ctrs = append(e.ctrs, c)
	if err = c.cmd.Start(); err != nil {
		return nil, err
	}
	go func() {
		_ = c.cmd.Wait()
		c.exit = c.cmd.ProcessState.ExitCode()
		close(c.done)
	}()
	return c, nil
}

// startRunning starts a long-lived container (workload, helper) and returns once its init exists.
func (e *runtimeEnv) startRunning(s ctrSpec, runID string) (*ctr, error) {
	c, err := e.start(s, runID)
	if err != nil {
		return c, err
	}
	return c, c.waitRunning(15 * time.Second)
}

// waitRunning polls `runc state` until the container's init exists and returns its host PID.
func (c *ctr) waitRunning(timeout time.Duration) error {
	for deadline := time.Now().Add(timeout); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		select {
		case <-c.done:
			return fmt.Errorf("container %s exited %d before it ran: %s", c.spec.Name, c.exit, clip(strings.TrimSpace(c.stderr.String()+c.stdout.String()), 500))
		default:
		}
		out, err := c.env.runcOutput(10*time.Second, "state", c.id)
		if err != nil {
			continue
		}
		var st struct {
			Pid    int    `json:"pid"`
			Status string `json:"status"`
		}
		if json.Unmarshal([]byte(out), &st) == nil && st.Status == "running" && st.Pid > 0 {
			c.hostPID = st.Pid
			return nil
		}
	}
	return fmt.Errorf("container %s did not reach running within %s: %s", c.spec.Name, timeout, clip(strings.TrimSpace(c.stderr.String()), 400))
}

// waitLine waits until the container's stdout holds substr.
func (c *ctr) waitLine(substr string, timeout time.Duration) error {
	for deadline := time.Now().Add(timeout); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if strings.Contains(c.stdout.String(), substr) {
			return nil
		}
		select {
		case <-c.done:
			return fmt.Errorf("container %s exited %d without printing %q: %s", c.spec.Name, c.exit, substr, clip(strings.TrimSpace(c.stderr.String()), 400))
		default:
		}
	}
	return fmt.Errorf("container %s did not print %q within %s", c.spec.Name, substr, timeout)
}

func (c *ctr) alive() bool {
	select {
	case <-c.done:
		return false
	default:
		return true
	}
}

// signal sends sig to the container's init through runc.
func (c *ctr) signal(sig syscall.Signal) error {
	name := map[syscall.Signal]string{syscall.SIGTERM: "TERM", syscall.SIGKILL: "KILL"}[sig]
	_, err := c.env.runcOutput(10*time.Second, "kill", c.id, name)
	return err
}

// wait waits for the container to exit and returns its exit code; on timeout the container is killed and an error returned.
func (c *ctr) wait(timeout time.Duration) (int, error) {
	select {
	case <-c.done:
		return c.exit, nil
	case <-time.After(timeout):
		_ = c.signal(syscall.SIGKILL)
		<-c.done
		return c.exit, errors.New("container " + c.spec.Name + " did not exit in time and was killed")
	}
}

// stopTERM is the service's orderly end: SIGTERM, then the exit code (a clean helper exits 0).
func (c *ctr) stopTERM(timeout time.Duration) (int, error) {
	if !c.alive() {
		return c.exit, errors.New("the container had already exited with code " + fmt.Sprint(c.exit))
	}
	if err := c.signal(syscall.SIGTERM); err != nil {
		return -1, err
	}
	return c.wait(timeout)
}

// kill ends the container without ceremony (a workload).
func (c *ctr) kill() {
	if c.alive() {
		_ = c.signal(syscall.SIGKILL)
		select {
		case <-c.done:
		case <-time.After(10 * time.Second):
		}
	}
}

// run starts a short-lived operator container, waits for it and returns its stdout.
func (e *runtimeEnv) run(s ctrSpec, runID string, timeout time.Duration) (stdout, stderr string, exit int, err error) {
	c, err := e.start(s, runID)
	if err != nil {
		if c != nil {
			c.kill()
		}
		return "", "", -1, err
	}
	exit, err = c.wait(timeout)
	return c.stdout.String(), c.stderr.String(), exit, err
}

// cleanup deletes every container (and with it its cgroup), then the parent cgroup, the runc state and the work tree.
// It is safe to call twice and returns what it could not remove.
func (e *runtimeEnv) cleanup() []string {
	left := []string{}
	for i := len(e.ctrs) - 1; i >= 0; i-- {
		c := e.ctrs[i]
		c.kill()
		if out, err := e.runcOutput(20*time.Second, "delete", "--force", c.id); err != nil && !strings.Contains(out, "does not exist") {
			left = append(left, err.Error())
		}
		_ = os.Remove(filepath.Join(e.cgroupRoot, c.cgroup))
	}
	e.ctrs = nil
	if e.cgroupDir != "" {
		if err := os.Remove(filepath.Join(e.cgroupRoot, e.cgroupDir)); err != nil && !os.IsNotExist(err) {
			left = append(left, "cgroup "+e.cgroupDir+": "+err.Error())
		}
	}
	if e.state != "" {
		_ = os.RemoveAll(e.state)
	}
	if e.work != "" {
		if err := os.RemoveAll(e.work); err != nil {
			left = append(left, "work dir: "+err.Error())
		}
	}
	return left
}

// cgWatch keeps the last successful reading of a cgroup's limit and event files. A container's cgroup disappears with
// the container (runc removes it as soon as init is gone), so counters such as memory.events oom_kill and pids.events max
// of a helper that was killed by its limit can only be read while it still lives.
type cgWatch struct {
	mu   sync.Mutex
	seen map[string]string
	stop chan struct{}
	done chan struct{}
}

// watch polls the cgroup (relative to the cgroup root) every few milliseconds until close.
func (e *runtimeEnv) watch(rel string) *cgWatch {
	w := &cgWatch{stop: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(w.done)
		for {
			if s := e.readCgroup(rel); len(s) > 0 {
				w.mu.Lock()
				w.seen = s
				w.mu.Unlock()
			}
			select {
			case <-w.stop:
				return
			case <-time.After(3 * time.Millisecond):
			}
		}
	}()
	return w
}

func (w *cgWatch) last() map[string]string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.seen
}

func (w *cgWatch) close() {
	select {
	case <-w.stop:
	default:
		close(w.stop)
	}
	<-w.done
}

// kernelLog returns the kernel log lines (at most three) that name the cgroup and contain phrase: the kernel's own
// record of an OOM kill or a rejected fork, which stays after the cgroup is gone. It returns nothing when the log is
// unreadable.
func kernelLog(cgroup, phrase string) []string {
	out, err := exec.Command("dmesg").Output()
	if err != nil {
		return nil
	}
	var lines []string
	for _, l := range strings.Split(string(out), "\n") {
		if strings.Contains(l, phrase) && strings.Contains(l, cgroup) {
			lines = append(lines, clip(strings.TrimSpace(l), 300))
		}
	}
	if len(lines) > 3 {
		lines = lines[len(lines)-3:]
	}
	return lines
}
