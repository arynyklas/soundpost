// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"soundpost/internal/auth"
	"soundpost/internal/httpapi"
	"soundpost/internal/model"
	"soundpost/internal/symbolicate"
)

// SymbolicatorState is the closed vocabulary of what the served process can say
// about its frame resolver.
type SymbolicatorState string

const (
	// SymbolicatorDisabled: the operator switched the sandbox off.
	SymbolicatorDisabled SymbolicatorState = "disabled"
	// SymbolicatorUnavailable: the configuration or the startup capability probe
	// failed. Frames keep their original identity and answer sandbox_unavailable.
	SymbolicatorUnavailable SymbolicatorState = "unavailable"
	// SymbolicatorReady: every startup probe was denied/contained by the sandbox.
	SymbolicatorReady SymbolicatorState = "ready"
)

// SymbolicatorStatus is the loggable outcome of ConfigureSymbolicator. Reason is
// a static code (never a path, hash, OS error or map content), so it is safe to
// print and to expose.
type SymbolicatorStatus struct {
	State  SymbolicatorState
	Reason string
}

// SymbolicatorSettings is the trusted operator configuration of `soundpost serve`.
// None of it is decoded from a request.
type SymbolicatorSettings struct {
	// Disabled switches the sandbox off. Frames then answer sandbox_unavailable.
	Disabled bool
	// ConfigPath names a private symbolicate.Config JSON that selects an explicit
	// backend (native with a specific worker, or pinned OCI). Empty selects the
	// default: native sandbox that re-executes the running binary.
	ConfigPath string
	// CgroupRoot is the delegated cgroup v2 subtree of the default native mode;
	// empty means the process's own cgroup.
	CgroupRoot string
}

// Startup probes run the real forbidden operations in the real launch backend.
// The memory/CPU/timeout probes are operator qualification actions: the memory
// probe allocates until the kernel OOM-kills the child, which is not something a
// server start performs.
var startupProbes = []symbolicate.ProbeKind{symbolicate.ProbeFile, symbolicate.ProbeNetwork, symbolicate.ProbeExec}

// seams replaced by tests.
var (
	probeSandbox   = symbolicate.Probe
	executablePath = os.Executable
	readCgroupFile = func() ([]byte, error) { return os.ReadFile("/proc/self/cgroup") }
)

// sandboxUnavailable is the frame resolver Open installs, and what an operator
// configuration that failed or disabled the sandbox leaves in place. It answers
// every frame as sandbox_unavailable with the original frame kept, without
// touching the artifact store, the caller's scope or any child process, so its
// answer is identical for an existing artifact, a deleted one and another
// organization's.
type sandboxUnavailable struct{}

// ResolveWithOptions implements httpapi.FrameResolver.
func (sandboxUnavailable) ResolveWithOptions(_ context.Context, _ auth.Scope, build model.ID, frames []model.Frame, _ symbolicate.Options) ([]symbolicate.SymbolicatedFrame, error) {
	if build == (model.ID{}) || len(frames) > symbolicate.MaxFrames {
		return nil, model.Fail(model.Invalid)
	}
	out := make([]symbolicate.SymbolicatedFrame, len(frames))
	for i, f := range frames {
		if f.Column != nil {
			c := *f.Column
			f.Column = &c
		}
		out[i] = symbolicate.SymbolicatedFrame{Original: f, Build: build, Reason: symbolicate.SandboxUnavailable}
	}
	return out, nil
}

// ConfigureSymbolicator applies the trusted operator settings to this App's frame
// resolver and reports the outcome. The real service (built over a.Artifacts, the
// protected reader every artifact route uses, and a.Retention, the delete
// generation authority) is installed only after the sandbox denied every startup
// probe; any other outcome leaves the typed sandbox_unavailable resolver.
//
// It replaces App.Evidence, so it MUST run before Register (the serve path calls
// it right after Open) and never concurrently with request handling.
func (a *App) ConfigureSymbolicator(ctx context.Context, settings SymbolicatorSettings) SymbolicatorStatus {
	if a == nil || a.Evidence == nil || a.Releases == nil || a.Artifacts == nil || a.Retention == nil {
		return SymbolicatorStatus{State: SymbolicatorUnavailable, Reason: "app_incomplete"}
	}
	resolver, status := buildFrameResolver(ctx, a.Artifacts, a.Retention, settings)
	a.Evidence = httpapi.NewEvidence(resolver, a.Releases, a.Releases)
	return status
}

func buildFrameResolver(ctx context.Context, reader symbolicate.ArtifactReader, deletes auth.DeleteGenerations, s SymbolicatorSettings) (httpapi.FrameResolver, SymbolicatorStatus) {
	unavailable := func(state SymbolicatorState, reason string) (httpapi.FrameResolver, SymbolicatorStatus) {
		return sandboxUnavailable{}, SymbolicatorStatus{State: state, Reason: reason}
	}
	if s.Disabled {
		return unavailable(SymbolicatorDisabled, "disabled_by_operator")
	}
	config, reason := resolveSymbolicatorConfig(s)
	if reason != "" {
		return unavailable(SymbolicatorUnavailable, reason)
	}
	// Remove worker containers a killed earlier process left behind (OCI mode only,
	// exact name/image/state/age match; see symbolicate.SweepOCI).
	symbolicate.SweepOCI(ctx, config)
	for _, kind := range startupProbes {
		r := probeSandbox(ctx, config, kind)
		if !r.Denied || r.Reason != symbolicate.Resolved {
			return unavailable(SymbolicatorUnavailable, "probe_"+string(kind)+"_"+string(r.Reason))
		}
	}
	svc, err := symbolicate.New(reader, deletes, config)
	if err != nil {
		return unavailable(SymbolicatorUnavailable, "service_invalid")
	}
	return svc, SymbolicatorStatus{State: SymbolicatorReady, Reason: "probe_passed"}
}

// resolveSymbolicatorConfig returns the symbolicate.Config for the settings, or
// a static failure reason.
func resolveSymbolicatorConfig(s SymbolicatorSettings) (symbolicate.Config, string) {
	if s.ConfigPath != "" {
		return loadSymbolicatorConfig(s.ConfigPath)
	}
	exe, err := executablePath()
	if err != nil {
		return symbolicate.Config{}, "worker_unresolvable"
	}
	if resolved, e := filepath.EvalSymlinks(exe); e == nil {
		exe = resolved
	}
	sum, err := fileSHA256(exe)
	if err != nil {
		return symbolicate.Config{}, "worker_unreadable"
	}
	root := s.CgroupRoot
	if root == "" {
		root = ownCgroupDirectory()
	}
	// Mode native, never OCI: native failure is reported, not retried elsewhere.
	return symbolicate.Config{Mode: "native", WorkerPath: exe, WorkerSHA256: sum, CgroupRoot: root}, ""
}

func loadSymbolicatorConfig(name string) (symbolicate.Config, string) {
	info, err := os.Stat(name)
	if err != nil || !info.Mode().IsRegular() {
		return symbolicate.Config{}, "config_unreadable"
	}
	// The file selects which executable runs; no other principal may write it.
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o022 != 0 {
		return symbolicate.Config{}, "config_not_private"
	}
	raw, err := os.ReadFile(name)
	if err != nil {
		return symbolicate.Config{}, "config_unreadable"
	}
	var c symbolicate.Config
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&c) != nil || dec.More() {
		return symbolicate.Config{}, "config_invalid"
	}
	if _, err = dec.Token(); !errors.Is(err, io.EOF) {
		return symbolicate.Config{}, "config_invalid"
	}
	if c.Mode != "native" && c.Mode != "oci" {
		return symbolicate.Config{}, "config_invalid"
	}
	return c, ""
}

func fileSHA256(name string) (model.Hash, error) {
	var h model.Hash
	f, err := os.Open(name)
	if err != nil {
		return h, err
	}
	defer f.Close()
	sum := sha256.New()
	if _, err = io.Copy(sum, f); err != nil {
		return h, err
	}
	copy(h[:], sum.Sum(nil))
	return h, nil
}

// ownCgroupDirectory is the process's cgroup v2 directory ("" when there is none,
// which makes the native launch fail closed).
func ownCgroupDirectory() string {
	raw, err := readCgroupFile()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if rest, ok := strings.CutPrefix(line, "0::"); ok {
			if !strings.HasPrefix(rest, "/") || strings.Contains(rest, "..") {
				return ""
			}
			return filepath.Join("/sys/fs/cgroup", rest)
		}
	}
	return ""
}
