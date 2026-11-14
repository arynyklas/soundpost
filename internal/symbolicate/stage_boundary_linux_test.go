//go:build linux && (amd64 || arm64)

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package symbolicate

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A staged process whose parent dies without releasing it must exit by itself:
// the parent held the only write end of the release pipe, so its death is EOF on
// fd 3. If the staged process blocked forever, every crashed launcher would leave
// an un-reaped process outside any limited group. A helper (this test binary,
// re-executed) starts the staged child of the real worker binary through
// ExtraFiles and SIGKILLs itself without releasing.
func TestStagedProcessCannotOutliveItsParent(t *testing.T) {
	c := sandboxConfig(t)
	if os.Getenv("SOUNDPOST_STAGED_PARENT_HELPER") == "1" {
		r, w, err := os.Pipe()
		if err != nil {
			os.Exit(91)
		}
		cmd := exec.Command(c.WorkerPath, stageWorkerArg)
		cmd.ExtraFiles = []*os.File{r}
		cmd.Stdin = strings.NewReader("")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err = cmd.Start(); err != nil {
			os.Exit(92)
		}
		_ = w // the helper holds the only write end
		_, _ = os.Stdout.WriteString("STAGEDPID " + strconv.Itoa(cmd.Process.Pid) + "\n")
		syscall.Kill(syscall.Getpid(), syscall.SIGKILL)
		time.Sleep(2 * time.Second)
		os.Exit(93)
	}
	bin, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "-test.run", "^TestStagedProcessCannotOutliveItsParent$", "-test.v")
	cmd.Env = append(os.Environ(), "SOUNDPOST_STAGED_PARENT_HELPER=1")
	out, err := cmd.Output()
	if err != nil && !strings.Contains(string(out), "STAGEDPID") {
		t.Fatalf("helper run failed: %v\n%s", err, out)
	}
	var pid int
	for _, line := range strings.Split(string(out), "\n") {
		if rest, ok := strings.CutPrefix(line, "STAGEDPID "); ok {
			pid, _ = strconv.Atoi(strings.TrimSpace(rest))
		}
	}
	if pid == 0 {
		t.Fatalf("helper never reported the staged child: %s", out)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		err := syscall.Kill(pid, 0)
		if errors.Is(err, syscall.ESRCH) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("staged child %d outlived its SIGKILLed parent by 5 s", pid)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// The --stage-* vectors are reachable by any local user who can exec the binary,
// and anyone can write the release byte. A staged process released by something
// that is not the launcher runs WorkerMain/ProbeMain outside a limited group, and
// those must refuse to run (non-zero exit) rather than serve a request.
func TestExternalStagedReleaseStopsAtTheBoundary(t *testing.T) {
	c := sandboxConfig(t)
	for _, vector := range []string{stageWorkerArg, stageProbeArg} {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(c.WorkerPath, vector)
		cmd.ExtraFiles = []*os.File{r}
		stdin, err := cmd.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		cmd.Stderr = io.Discard
		if err = cmd.Start(); err != nil {
			t.Fatal(err)
		}
		r.Close()
		time.Sleep(200 * time.Millisecond)
		if _, err = w.Write([]byte{'G'}); err != nil {
			t.Fatal(err)
		}
		w.Close()
		go func() { _, _ = stdin.Write([]byte{'A'}); stdin.Close() }()
		done := make(chan error, 1)
		var first [1]byte
		go func() { _, e := io.ReadFull(stdout, first[:]); done <- e }()
		select {
		case <-done:
		case <-time.After(6 * time.Second):
			cmd.Process.Kill()
		}
		_ = cmd.Wait()
		code := cmd.ProcessState.ExitCode()
		t.Logf("external release of %s: exit=%d first byte %q", vector, code, first[0])
		if code == 0 {
			t.Errorf("an externally released %s exited 0 outside a limited cgroup", vector)
		}
	}
}
