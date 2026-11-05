// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// clusterDiagnosticsEnv opts a multi-process cluster smoke into keeping what
// the public failure line deliberately reduces to a bare code. It is never on
// by default. When it is "1" the parent smoke writes, under
// <artifact-dir>/diagnostics/:
//
//   - launch-<n>-<dir>.stderr.log: the stderr of every cluster child process
//     (runtime panics, goroutine dumps) together with the child's own
//     unclassified startup error text, and
//   - parent-failure.txt: the unclassified cause and Go error type chain of the
//     parent-side failure.
//
// Error text and type names come from Go's net/os/runtime packages and the
// product's sentinel errors; they carry addresses, fixture paths and error
// kinds, never request bodies, tokens or credentials (the smoke never places
// those in an error value; its HTTP helpers return only status and code).
const clusterDiagnosticsEnv = "SOUNDPOST_SMOKE_DIAGNOSTICS"

var clusterDiagnostics struct {
	mu       sync.Mutex
	dir      string
	launches atomic.Uint64
}

func clusterDiagnosticsRequested() bool { return os.Getenv(clusterDiagnosticsEnv) == "1" }

// enableClusterDiagnostics prepares <artifact>/diagnostics when requested.
func enableClusterDiagnostics(artifact string) error {
	if !clusterDiagnosticsRequested() {
		return nil
	}
	dir := filepath.Join(artifact, "diagnostics")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	clusterDiagnostics.mu.Lock()
	clusterDiagnostics.dir = dir
	clusterDiagnostics.mu.Unlock()
	return nil
}
func clusterDiagnosticsDir() string {
	clusterDiagnostics.mu.Lock()
	defer clusterDiagnostics.mu.Unlock()
	return clusterDiagnostics.dir
}

// keepChildStderr routes a cluster child's stderr to a diagnostics file. It is
// a no-op unless diagnostics are enabled, in which case stderr stays discarded.
func keepChildStderr(command *exec.Cmd, dir string) (release func()) {
	release = func() {}
	diag := clusterDiagnosticsDir()
	if diag == "" {
		return release
	}
	name := fmt.Sprintf("launch-%02d-%s.stderr.log", clusterDiagnostics.launches.Add(1), filepath.Base(dir))
	file, err := os.OpenFile(filepath.Join(diag, name), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return release
	}
	command.Stderr = file
	return func() { _ = file.Close() }
}

// errorChain renders an unclassified error with its wrapped Go types.
func errorChain(err error) string {
	var b strings.Builder
	for depth := 0; err != nil && depth < 16; depth++ {
		fmt.Fprintf(&b, "%T: %v\n", err, err)
		if multi, ok := err.(interface{ Unwrap() []error }); ok {
			for _, inner := range multi.Unwrap() {
				fmt.Fprintf(&b, "  | %T: %v\n", inner, inner)
			}
			break
		}
		err = errors.Unwrap(err)
	}
	return b.String()
}

// recordChildFailure is called by a cluster child before it reports its
// classified startup failure; the parent keeps the child's stderr.
func recordChildFailure(stage string, err error) {
	if !clusterDiagnosticsRequested() || err == nil {
		return
	}
	fmt.Fprintf(os.Stderr, "%s child_failure stage=%s\n%s", time.Now().UTC().Format(time.RFC3339Nano), stage, errorChain(err))
}

// recordParentFailure stores the unclassified cause of a parent-side failure.
func recordParentFailure(stage string, err error) {
	diag := clusterDiagnosticsDir()
	if diag == "" || err == nil {
		return
	}
	file, openErr := os.OpenFile(filepath.Join(diag, "parent-failure.txt"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if openErr != nil {
		return
	}
	defer file.Close()
	fmt.Fprintf(file, "%s stage=%s\n%s", time.Now().UTC().Format(time.RFC3339Nano), stage, errorChain(err))
}

// dumpChildStacks asks a child that missed its startup deadline for a
// goroutine dump (the Go runtime writes it to the child's stderr file).
func dumpChildStacks(command *exec.Cmd) {
	if clusterDiagnosticsDir() == "" || command == nil || command.Process == nil {
		return
	}
	_ = command.Process.Signal(syscall.SIGQUIT)
	time.Sleep(500 * time.Millisecond)
}

// recordClusterState writes, for every still-controllable cluster child, the
// consensus status of each group (leader, term, commit, applied, failed) at the
// moment a stage failed: this is what distinguishes "no leader elected" from
// "leader exists but admission is refused". Only in-memory raft positions are
// captured; no values, keys or credentials.
func recordClusterState(stage string, processes map[uint64]*clusterProcess) {
	diag := clusterDiagnosticsDir()
	if diag == "" {
		return
	}
	file, err := os.OpenFile(filepath.Join(diag, "cluster-state.txt"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return
	}
	defer file.Close()
	fmt.Fprintf(file, "%s stage=%s\n", time.Now().UTC().Format(time.RFC3339Nano), stage)
	nodes := make([]uint64, 0, len(processes))
	for node := range processes {
		nodes = append(nodes, node)
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i] < nodes[j] })
	for _, node := range nodes {
		statuses, err := processes[node].statuses()
		if err != nil {
			fmt.Fprintf(file, "node=%d status_error=%v\n", node, err)
			continue
		}
		leaderless, failed := 0, 0
		for _, s := range statuses {
			if s.Leader == 0 {
				leaderless++
			}
			if s.Failed {
				failed++
			}
		}
		fmt.Fprintf(file, "node=%d groups=%d leaderless=%d failed=%d\n", node, len(statuses), leaderless, failed)
		for i, s := range statuses {
			fmt.Fprintf(file, "  node=%d group_index=%d leader=%d term=%d commit=%d applied=%d last=%d failed=%t revision=%d\n", node, i, s.Leader, s.Term, s.Commit, s.Applied, s.LastIndex, s.Failed, s.Revision)
		}
	}
}
