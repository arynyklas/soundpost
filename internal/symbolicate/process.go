// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package symbolicate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"soundpost/internal/model"
	"strings"
	"sync"
	"time"
)

// removeRetryEvery is the pause between background container-remove retries.
// ociTransportAllowance is added to the parent-side frame wait in OCI mode only.
const ociTransportAllowance = 400 * time.Millisecond

var (
	removeRetryEvery  = 200 * time.Millisecond
	removeRetryBudget = ProcessTimeout
	// removeRetries lets tests wait for the background retries.
	removeRetries sync.WaitGroup
)

type workerProcess struct {
	cmd     *exec.Cmd
	input   io.WriteCloser
	output  io.ReadCloser
	cleanup func()
	oom     func() bool
	attach  func() error
}

func (s *Service) run(ctx context.Context, in workerInput) workerOutput {
	ctx, cancel := context.WithTimeout(ctx, ProcessTimeout)
	defer cancel()
	p, e := s.launch(ctx, false)
	if e != nil {
		return workerOutput{Reason: SandboxUnavailable}
	}
	defer p.cleanup()
	if e = p.cmd.Start(); e != nil {
		return workerOutput{Reason: SandboxUnavailable}
	}
	waited := false
	defer func() {
		if !waited {
			p.cmd.Process.Kill()
			p.cmd.Wait()
		}
	}()
	if e = p.attach(); e != nil {
		return workerOutput{Reason: SandboxUnavailable}
	}
	if _, e = p.input.Write([]byte{'A'}); e != nil {
		return workerOutput{Reason: SandboxUnavailable}
	}
	ready := make(chan error, 1)
	go func() {
		var b [33]byte
		_, e := io.ReadFull(p.output, b[:1])
		if e == nil && b[0] != 'R' {
			e = errors.New("sandbox unavailable")
		}
		if e == nil {
			_, e = io.ReadFull(p.output, b[1:])
			if e == nil && model.Hash(b[1:]) != s.config.WorkerSHA256 {
				e = errors.New("worker identity")
			}
		}
		ready <- e
	}()
	select {
	case e = <-ready:
		if e != nil {
			return workerOutput{Reason: SandboxUnavailable}
		}
	case <-ctx.Done():
		return workerOutput{Reason: Deadline}
	}
	// The worker enforces its own authoritative 100 ms processing watchdog (exit 124,
	// typed `deadline`). This parent bound is the independent wall backstop and it
	// also spans the request/reply transport: through an OCI runtime that is the
	// client -> daemon -> shim -> container stdio chain, measured at 96-162 ms
	// round trip on an idle host, so a bare 100 ms made most OCI frames answer
	// `deadline`. The allowance is OCI-only and far below ProcessTimeout.
	frameBudget := FrameTimeout
	if s.config.Mode == "oci" {
		frameBudget += ociTransportAllowance
	}
	frameCtx, frameCancel := context.WithTimeout(ctx, frameBudget)
	defer frameCancel()
	type answer struct {
		out workerOutput
		err error
	}
	done := make(chan answer, 1)
	go func() {
		writeDone := make(chan error, 1)
		go func() { e := json.NewEncoder(p.input).Encode(in); p.input.Close(); writeDone <- e }()
		var out workerOutput
		e := decodeClosed(p.output, &out, MaxOutputBytes)
		if we := <-writeDone; e == nil {
			e = we
		}
		done <- answer{out, e}
	}()
	select {
	case a := <-done:
		e = p.cmd.Wait()
		waited = true
		if e != nil || a.err != nil {
			if p.oom() {
				return workerOutput{Reason: ResourceLimit}
			}
			if p.cmd.ProcessState.ExitCode() == 124 {
				return workerOutput{Reason: Deadline}
			}
			return workerOutput{Reason: WorkerFailure}
		}
		if !validOutput(a.out, in.IncludeSources) {
			return workerOutput{Reason: WorkerFailure}
		}
		return a.out
	case <-frameCtx.Done():
		p.cmd.Process.Kill()
		return workerOutput{Reason: Deadline}
	}
}
func validOutput(o workerOutput, private bool) bool {
	switch o.Reason {
	case Resolved:
		return o.Position != nil && o.Position.Line > 0 && len(o.Position.Source) <= 4096 && len(o.Position.Function) <= 256 && (o.SourceContext == nil || private && len(*o.SourceContext) <= 4096)
	case InvalidMap, ResourceLimit, CorruptArtifact, Unmapped, SourceDenied:
		return o.Position == nil && o.SourceContext == nil
	default:
		return false
	}
}
func (s *Service) launch(ctx context.Context, probe bool) (*workerProcess, error) {
	if s.config.WorkerSHA256 == (model.Hash{}) {
		return nil, errors.New("missing worker provenance")
	}
	mode := "--worker-v1"
	if probe {
		mode = "--probe-v1"
	}
	var cmd *exec.Cmd
	cleanup := func() {}
	oom := func() bool { return false }
	attach := func() error { return nil }
	switch s.config.Mode {
	case "native":
		if !filepath.IsAbs(s.config.WorkerPath) {
			return nil, errors.New("absolute worker required")
		}
		f, e := os.Open(s.config.WorkerPath)
		if e != nil {
			return nil, e
		}
		h := sha256.New()
		_, e = io.Copy(h, f)
		f.Close()
		if e != nil || hex.EncodeToString(h.Sum(nil)) != hex.EncodeToString(s.config.WorkerSHA256[:]) {
			return nil, errors.New("worker provenance mismatch")
		}
		cmd = exec.CommandContext(ctx, s.config.WorkerPath, mode)
		cmd.Env = []string{"GOMAXPROCS=1", "GOMEMLIMIT=192MiB", "GOGC=50"}
		group, e := newNativeGroup(s.config.CgroupRoot)
		if e != nil {
			return nil, e
		}
		if e = group.configure(cmd); e != nil {
			group.cleanup()
			return nil, e
		}
		cleanup = group.cleanup
		oom = group.oom
		attach = func() error { return group.attach(cmd.Process.Pid) }
	case "oci":
		if !filepath.IsAbs(s.config.OCIRuntime) || !validImage(s.config.OCIImage) {
			return nil, errors.New("explicit pinned local OCI configuration required")
		}
		inspect := exec.CommandContext(ctx, s.config.OCIRuntime, "image", "inspect", "--format", `{{index .Config.Labels "org.soundpost.worker.sha256"}}`, s.config.OCIImage)
		var label limitBuffer
		label.max = 256
		inspect.Stdout = &label
		inspect.Stderr = io.Discard
		if inspect.Run() != nil || strings.TrimSpace(string(label.data)) != hex.EncodeToString(s.config.WorkerSHA256[:]) {
			return nil, errors.New("OCI binary provenance missing")
		}
		name := "soundpost-symbolicate-" + model.NewID().String()
		cmd = exec.CommandContext(ctx, s.config.OCIRuntime, "run", "--name", name, "--pull=never", "--network=none", "--read-only", "--memory=268435456", "--memory-swap=268435456", "--pids-limit=64", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--user=65534:65534", "--env=GOMAXPROCS=1", "--env=GOMEMLIMIT=192MiB", "--env=GOGC=50", "--entrypoint=/soundpost-symbolicate", "--interactive", s.config.OCIImage, mode)
		removeOnce := func() bool {
			// A fresh, bounded context: never the (possibly expired) request one.
			c, cancel := context.WithTimeout(context.Background(), ProcessTimeout)
			defer cancel()
			x := exec.CommandContext(c, s.config.OCIRuntime, "rm", "--force", name)
			x.Stdout = io.Discard
			x.Stderr = io.Discard
			return x.Run() == nil
		}
		cleanup = func() {
			if removeOnce() || cmd.Process == nil {
				return
			}
			// The client was started and the first remove found nothing: the runtime
			// daemon may still be creating the container for a `run` request whose
			// client was killed (deadline under load). It would appear later as a
			// never-started `Created` container, so keep removing, off the request's
			// slot, for at most ProcessTimeout in total.
			removeRetries.Add(1)
			go func() {
				defer removeRetries.Done()
				deadline := time.Now().Add(removeRetryBudget)
				for time.Now().Before(deadline) {
					time.Sleep(removeRetryEvery)
					if removeOnce() {
						return
					}
				}
			}()
		}
		oom = func() bool {
			c, cancel := context.WithTimeout(context.Background(), ProcessTimeout)
			defer cancel()
			x := exec.CommandContext(c, s.config.OCIRuntime, "inspect", "--format", "{{.State.OOMKilled}}", name)
			var b limitBuffer
			b.max = 64
			x.Stdout = &b
			x.Stderr = io.Discard
			return x.Run() == nil && strings.TrimSpace(string(b.data)) == "true"
		}
	default:
		return nil, errors.New("sandbox mode not configured")
	}
	input, e := cmd.StdinPipe()
	if e != nil {
		cleanup()
		return nil, e
	}
	output, e := cmd.StdoutPipe()
	if e != nil {
		input.Close()
		cleanup()
		return nil, e
	}
	cmd.Stderr = io.Discard
	return &workerProcess{cmd: cmd, input: input, output: output, attach: attach, oom: oom, cleanup: func() { input.Close(); output.Close(); cleanup() }}, nil
}
func validImage(s string) bool {
	if !strings.HasPrefix(s, "sha256:") || len(s) != 71 {
		return false
	}
	b, e := hex.DecodeString(s[7:])
	return e == nil && len(b) == 32 && strings.ToLower(s) == s
}

type limitBuffer struct {
	data []byte
	max  int
}

func (b *limitBuffer) Write(p []byte) (int, error) {
	if len(b.data)+len(p) > b.max {
		return 0, errors.New("bounded output exceeded")
	}
	b.data = append(b.data, p...)
	return len(p), nil
}
