//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package qual

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

// A Sandbox is a disposable container-equivalent made only of kernel namespaces and mounts that vanish with its
// processes: no container runtime, no image, nothing on the host's mount table. The child is the first process of the new
// PID namespace (when PID is set), starts in a private copy of the mount tree, may get its own /proc (the one a container
// runtime mounts) and its own cgroup2 view, and bind mounts of files or directories (a "layer" over a path the host sees
// differently). Setting a namespace without its companion mount is deliberate where a case needs a misconfigured container.
type Sandbox struct {
	PID    bool `json:"pid,omitempty"`
	Mount  bool `json:"mount,omitempty"`
	Cgroup bool `json:"cgroup,omitempty"`
	UTS    bool `json:"uts,omitempty"`
	IPC    bool `json:"ipc,omitempty"`
	Net    bool `json:"net,omitempty"`
	// ProcFS mounts a new proc at /proc (needs Mount and PID to be meaningful); OwnProc mounts one at that extra path
	// instead, so a case can read this PID namespace's proc while /proc stays the parent's.
	ProcFS  bool   `json:"procfs,omitempty"`
	OwnProc string `json:"own_proc,omitempty"`
	// Cgroup2 mounts a fresh cgroup2 filesystem at /sys/fs/cgroup (what a runtime does for a container with a cgroup
	// namespace); it is the root of the cgroup namespace the child was created in.
	Cgroup2 bool          `json:"cgroup2,omitempty"`
	Binds   []SandboxBind `json:"binds,omitempty"`
}

// SandboxBind is `mount --bind Src Dst` inside the sandbox's private mount namespace.
type SandboxBind struct {
	Src string `json:"src"`
	Dst string `json:"dst"`
}

const sandboxInitEnv = "SPQUAL_NS_SANDBOX"

func (s Sandbox) cloneflags() uintptr {
	var f uintptr
	for _, c := range []struct {
		on   bool
		flag uintptr
	}{{s.PID, syscall.CLONE_NEWPID}, {s.Mount, syscall.CLONE_NEWNS}, {s.Cgroup, syscall.CLONE_NEWCGROUP}, {s.UTS, syscall.CLONE_NEWUTS}, {s.IPC, syscall.CLONE_NEWIPC}, {s.Net, syscall.CLONE_NEWNET}} {
		if c.on {
			f |= c.flag
		}
	}
	return f
}

// Command returns a command that runs path with args as the first process of a new Sandbox. The setup runs in this
// binary's init (see sandboxInit), so any binary that imports qual can be the parent: the child re-executes it, performs
// the mounts, then execs path.
func (s Sandbox) Command(path string, args ...string) (*exec.Cmd, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	spec, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(self, args...)
	cmd.Args = append([]string{"sandbox-init", path}, args...)
	cmd.Env = append(os.Environ(), sandboxInitEnv+"="+string(spec))
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: s.cloneflags()}
	return cmd, nil
}

func init() {
	spec := os.Getenv(sandboxInitEnv)
	if spec == "" || len(os.Args) < 2 {
		return
	}
	if err := sandboxInit(spec, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "sandbox init:", err)
		os.Exit(111)
	}
}

// sandboxInit runs in the new namespaces as their first process: make the mount tree private (so nothing it mounts
// propagates to the host), mount what the spec asks for and replace itself with the requested program.
func sandboxInit(spec string, argv []string) error {
	var s Sandbox
	if json.Unmarshal([]byte(spec), &s) != nil {
		return errors.New("bad sandbox spec")
	}
	if s.Mount {
		if err := syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, ""); err != nil {
			return fmt.Errorf("make mounts private: %w", err)
		}
	}
	const procFlags = syscall.MS_NOSUID | syscall.MS_NODEV | syscall.MS_NOEXEC
	if s.ProcFS {
		if err := syscall.Mount("proc", "/proc", "proc", procFlags, ""); err != nil {
			return fmt.Errorf("mount /proc: %w", err)
		}
	}
	if s.OwnProc != "" {
		if err := os.MkdirAll(s.OwnProc, 0o755); err != nil {
			return err
		}
		if err := syscall.Mount("proc", s.OwnProc, "proc", procFlags, ""); err != nil {
			return fmt.Errorf("mount own proc: %w", err)
		}
	}
	if s.Cgroup2 {
		err := syscall.Mount("cgroup2", "/sys/fs/cgroup", "cgroup2", procFlags, "")
		if err == syscall.EBUSY {
			// a pure cgroup v2 host (or container) already has a cgroup2 mount there; in this private mount namespace it is
			// detached first, as a runtime that builds its own /sys does
			if syscall.Unmount("/sys/fs/cgroup", syscall.MNT_DETACH) == nil {
				err = syscall.Mount("cgroup2", "/sys/fs/cgroup", "cgroup2", procFlags, "")
			}
		}
		if err != nil {
			return fmt.Errorf("mount cgroup2: %w", err)
		}
	}
	for _, b := range s.Binds {
		if err := syscall.Mount(b.Src, b.Dst, "", syscall.MS_BIND, ""); err != nil {
			return fmt.Errorf("bind mount: %w", err)
		}
	}
	env := make([]string, 0, len(os.Environ()))
	for _, e := range os.Environ() {
		if !strings.HasPrefix(e, sandboxInitEnv+"=") {
			env = append(env, e)
		}
	}
	return syscall.Exec(argv[0], argv, env)
}
