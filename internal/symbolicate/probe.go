// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package symbolicate

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"soundpost/internal/model"
	"time"
)

type ProbeKind string

const (
	ProbeFile    ProbeKind = "file"
	ProbeNetwork ProbeKind = "network"
	ProbeExec    ProbeKind = "exec"
	ProbeMemory  ProbeKind = "memory"
	ProbeCPU     ProbeKind = "cpu"
	ProbeTimeout ProbeKind = "timeout"
)

type ProbeResult struct {
	Kind      ProbeKind `json:"kind"`
	Reason    Reason    `json:"reason"`
	Denied    bool      `json:"denied"`
	OOMKilled bool      `json:"oom_killed"`
	ExitCode  int       `json:"exit_code"`
}
type probeInput struct {
	Kind ProbeKind `json:"kind"`
}

func validProbe(k ProbeKind) bool {
	switch k {
	case ProbeFile, ProbeNetwork, ProbeExec, ProbeMemory, ProbeCPU, ProbeTimeout:
		return true
	}
	return false
}

// Probe performs real forbidden syscalls/allocation in exactly the selected
// production launch backend. It is an explicit operator qualification action,
// never an automatic fallback, and does not accept arbitrary commands or paths.
func Probe(ctx context.Context, config Config, kind ProbeKind) ProbeResult {
	result := ProbeResult{Kind: kind, Reason: SandboxUnavailable, ExitCode: -1}
	if !validProbe(kind) {
		return result
	}
	ctx, cancel := context.WithTimeout(ctx, ProcessTimeout)
	defer cancel()
	s := &Service{config: config}
	p, e := s.launch(ctx, true)
	if e != nil {
		return result
	}
	defer p.cleanup()
	if p.cmd.Start() != nil {
		return result
	}
	waited := false
	defer func() {
		if !waited {
			p.cmd.Process.Kill()
			p.cmd.Wait()
		}
	}()
	if p.attach() != nil {
		return result
	}
	if _, e = p.input.Write([]byte{'A'}); e != nil {
		return result
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
			if e == nil && model.Hash(b[1:]) != config.WorkerSHA256 {
				e = errors.New("worker provenance mismatch")
			}
		}
		ready <- e
	}()
	select {
	case e = <-ready:
		if e != nil {
			return result
		}
	case <-ctx.Done():
		result.Reason = Deadline
		return result
	}
	if e = json.NewEncoder(p.input).Encode(probeInput{kind}); e != nil {
		return result
	}
	p.input.Close()
	done := make(chan error, 1)
	var response ProbeResult
	go func() { done <- decodeClosed(p.output, &response, MaxOutputBytes) }()
	deadline := ProcessTimeout
	if kind == ProbeTimeout {
		deadline = FrameTimeout
	}
	timer := time.NewTimer(deadline)
	defer timer.Stop()
	select {
	case e = <-done:
		we := p.cmd.Wait()
		waited = true
		if e == nil {
			e = we
		}
		result.ExitCode = p.cmd.ProcessState.ExitCode()
		if p.oom() {
			result.Reason = ResourceLimit
			result.OOMKilled = true
			return result
		}
		if result.ExitCode == 124 {
			result.Reason = Deadline
			return result
		}
		if e == nil && response.Kind == kind && response.Denied {
			result.Denied = true
			result.Reason = Resolved
			return result
		}
		result.Reason = WorkerFailure
		return result
	case <-timer.C:
		result.Reason = Deadline
		return result
	case <-ctx.Done():
		result.Reason = Deadline
		return result
	}
}
func ProbeMain() int {
	timer := time.AfterFunc(ProcessTimeout, func() { os.Exit(124) })
	defer timer.Stop()
	hash, e := executableHash()
	if e != nil {
		return 70
	}
	var ack [1]byte
	if _, e = io.ReadFull(os.Stdin, ack[:]); e != nil || ack[0] != 'A' {
		return 70
	}
	if installSandbox() != nil {
		os.Stdout.Write([]byte{'U'})
		return 71
	}
	if _, e = os.Stdout.Write(append([]byte{'R'}, hash[:]...)); e != nil {
		return 70
	}
	var in probeInput
	if decodeClosed(os.Stdin, &in, 1024) != nil || !validProbe(in.Kind) {
		return 72
	}
	denied := probeOperation(in.Kind)
	if json.NewEncoder(os.Stdout).Encode(ProbeResult{Kind: in.Kind, Denied: denied}) != nil {
		return 70
	}
	return 0
}
