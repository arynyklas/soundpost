// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/artifacts"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/retention"
	"github.com/arynyklas/soundpost/internal/symbolicate"
)

// withProbe replaces the capability probe for one test and records its calls.
func withProbe(t *testing.T, f func(symbolicate.ProbeKind) symbolicate.ProbeResult) *[]symbolicate.ProbeKind {
	t.Helper()
	var calls []symbolicate.ProbeKind
	prev := probeSandbox
	probeSandbox = func(_ context.Context, _ symbolicate.Config, kind symbolicate.ProbeKind) symbolicate.ProbeResult {
		calls = append(calls, kind)
		return f(kind)
	}
	t.Cleanup(func() { probeSandbox = prev })
	return &calls
}

func probeDenied(kind symbolicate.ProbeKind) symbolicate.ProbeResult {
	return symbolicate.ProbeResult{Kind: kind, Reason: symbolicate.Resolved, Denied: true}
}

// dummyConfig is a native config that is never executed: the probe seam answers.
func dummyConfig(t *testing.T) string {
	t.Helper()
	return writeConfig(t, symbolicate.Config{Mode: "native", WorkerPath: filepath.Join(t.TempDir(), "worker"), WorkerSHA256: model.HashCanonical([]byte("x")), CgroupRoot: t.TempDir()})
}

// installResolver swaps the evidence handler's resolver the way
// ConfigureSymbolicator does, then serves the routes again.
func (r *symRig) installResolver(f httpapi.FrameResolver) {
	r.t.Helper()
	r.app.Evidence = httpapi.NewEvidence(f, r.app.Releases, r.app.Releases)
	r.serve()
}

// mapped resolves one frame and retries only while the answer is the typed
// `deadline`: a cold container start or a loaded host can exceed the sandbox's own
// 100 ms frame / 5 s call bound, the service then keeps the original frame, and
// the bounds are never widened (the acceptance suite does the same).
func (r *symRig) mapped(ten symTenant, includeSources bool, frame model.Frame) (symResp, httpapi.FramesView, int) {
	r.t.Helper()
	for attempt := 1; ; attempt++ {
		resp, v := r.frames(ten, includeSources, frame)
		if resp.status != 200 || len(v.Frames) != 1 || v.Frames[0].Reason != string(symbolicate.Deadline) || attempt == 30 {
			return resp, v, attempt
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func (r *symRig) configure(s SymbolicatorSettings) SymbolicatorStatus {
	r.t.Helper()
	st := r.app.ConfigureSymbolicator(context.Background(), s)
	r.serve()
	return st
}

// The default Open wires a typed frame resolver: a served frame request never
// answers symbolicator_not_wired. Red while the app.go hook is absent.
func TestOpenWiresTheSymbolicator(t *testing.T) {
	r := newSymRig(t)
	frame := symFrame(model.NewID().String(), 1, 0)
	resp, v := r.frames(r.a, false, frame)
	if resp.status != 200 || len(v.Frames) != 1 {
		t.Fatalf("frames: %d %s", resp.status, resp.body)
	}
	if v.Reason == httpapi.ReasonSymbolicatorNotBuilt || v.Frames[0].Reason == httpapi.ReasonSymbolicatorNotBuilt {
		t.Fatalf("the symbolicator is not wired into appcore.Open: %s", resp.body)
	}
	if got := v.Frames[0].Reason; got != string(symbolicate.SandboxUnavailable) {
		t.Fatalf("an App with no operator sandbox configuration must answer sandbox_unavailable, got %q: %s", got, resp.body)
	}
	if !reflect.DeepEqual(v.Frames[0].Original, frame) || v.Frames[0].Resolved != nil {
		t.Fatalf("original frame not preserved or mapped: %s", resp.body)
	}
}

// A host whose sandbox cannot run: the real probe fails closed before any child
// starts, and the served answer is the typed unavailable reason.
func TestUnavailableSandboxAnswersTypedReasonAndStartsNoChild(t *testing.T) {
	r := newSymRig(t)
	dir := t.TempDir()
	marker := filepath.Join(dir, "child-started")
	worker := filepath.Join(dir, "worker")
	script := []byte("#!/bin/sh\necho started > '" + marker + "'\n")
	if err := os.WriteFile(worker, script, 0o700); err != nil {
		t.Fatal(err)
	}
	// The cgroup root is an ordinary directory, never a delegated cgroup v2
	// subtree: exactly the unprivileged host without delegation.
	cfg := writeConfig(t, symbolicate.Config{Mode: "native", WorkerPath: worker, WorkerSHA256: model.HashCanonical(script), CgroupRoot: t.TempDir()})
	st := r.configure(SymbolicatorSettings{ConfigPath: cfg})
	if st.State != SymbolicatorUnavailable || st.Reason != "probe_file_sandbox_unavailable" {
		t.Fatalf("status %+v", st)
	}
	if strings.Contains(st.Reason, dir) || strings.Contains(symbolicatorNoticeForTest(st), dir) {
		t.Fatal("status leaks a host path")
	}
	artifact := r.mustUpload(r.a, []byte(symMapDoc), "dist/out.js", "debug-1", false)
	resp, v := r.frames(r.a, false, symFrame(artifact.ID.String(), 1, 0))
	f := v.Frames[0]
	if resp.status != 200 || f.Reason != string(symbolicate.SandboxUnavailable) || f.Resolved != nil || f.MapSHA256 != nil {
		t.Fatalf("frame: %d %s", resp.status, resp.body)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("a child process was started on a host without a sandbox")
	}
}

func symbolicatorNoticeForTest(s SymbolicatorStatus) string { return string(s.State) + " " + s.Reason }

// Every startup probe must be denied: a failure of any one (or a probe that cannot
// run) leaves the typed unavailable resolver, whatever the others said.
func TestEveryProbeMustPassForTheRealServiceToBeInstalled(t *testing.T) {
	for _, bad := range []symbolicate.ProbeKind{symbolicate.ProbeFile, symbolicate.ProbeNetwork, symbolicate.ProbeExec} {
		for _, why := range []symbolicate.Reason{symbolicate.WorkerFailure, symbolicate.SandboxUnavailable, symbolicate.Deadline} {
			t.Run(string(bad)+"_"+string(why), func(t *testing.T) {
				r := newSymRig(t)
				artifact := r.mustUpload(r.a, []byte(symMapDoc), "dist/out.js", "debug-1", false)
				calls := withProbe(t, func(k symbolicate.ProbeKind) symbolicate.ProbeResult {
					if k == bad {
						return symbolicate.ProbeResult{Kind: k, Reason: why, Denied: false}
					}
					return probeDenied(k)
				})
				st := r.configure(SymbolicatorSettings{ConfigPath: dummyConfig(t)})
				if st.State != SymbolicatorUnavailable || st.Reason != "probe_"+string(bad)+"_"+string(why) {
					t.Fatalf("status %+v after %v", st, *calls)
				}
				_, v := r.frames(r.a, false, symFrame(artifact.ID.String(), 1, 0))
				if got := v.Frames[0].Reason; got != string(symbolicate.SandboxUnavailable) {
					t.Fatalf("a failed probe still reached the service: %q", got)
				}
			})
		}
	}
	// A probe that reports Denied but not a resolved verdict is also a failure.
	r := newSymRig(t)
	withProbe(t, func(k symbolicate.ProbeKind) symbolicate.ProbeResult {
		return symbolicate.ProbeResult{Kind: k, Reason: symbolicate.WorkerFailure, Denied: true}
	})
	if st := r.configure(SymbolicatorSettings{ConfigPath: dummyConfig(t)}); st.State != SymbolicatorUnavailable {
		t.Fatalf("status %+v", st)
	}
}

// All probes passing installs the real service over the protected reader: a
// frame for an absent artifact is the service's artifact_unavailable, not the
// gate's sandbox_unavailable, and exactly file, network and exec were probed.
func TestPassingProbesInstallTheRealService(t *testing.T) {
	r := newSymRig(t)
	calls := withProbe(t, probeDenied)
	st := r.configure(SymbolicatorSettings{ConfigPath: dummyConfig(t)})
	if st.State != SymbolicatorReady {
		t.Fatalf("status %+v", st)
	}
	if !reflect.DeepEqual(*calls, []symbolicate.ProbeKind{symbolicate.ProbeFile, symbolicate.ProbeNetwork, symbolicate.ProbeExec}) {
		t.Fatalf("probed %v", *calls)
	}
	_, v := r.frames(r.a, false, symFrame(model.NewID().String(), 1, 0))
	if got := v.Frames[0].Reason; got != string(symbolicate.Unavailable) {
		t.Fatalf("the real service was not installed after the probes passed: %q", got)
	}
}

// The operator's explicit off switch: no probe, no child, nothing mapped, a typed
// answer, even when a working backend is also named.
func TestDisabledSandboxNeverProbesAndNeverMapsFrames(t *testing.T) {
	r := newSymRig(t)
	artifact := r.mustUpload(r.a, []byte(symMapDoc), "dist/out.js", "debug-1", false)
	calls := withProbe(t, probeDenied)
	st := r.configure(SymbolicatorSettings{Disabled: true, ConfigPath: dummyConfig(t)})
	if st.State != SymbolicatorDisabled || st.Reason != "disabled_by_operator" || len(*calls) != 0 {
		t.Fatalf("status %+v probes %v", st, *calls)
	}
	_, v := r.frames(r.a, false, symFrame(artifact.ID.String(), 1, 0))
	if f := v.Frames[0]; f.Reason != string(symbolicate.SandboxUnavailable) || f.Resolved != nil {
		t.Fatalf("disabled sandbox answered %+v", f)
	}
}

// The default (no --symbolicate-config) derives the worker from the running
// binary and its hash, and the cgroup from the process's own cgroup, never OCI.
func TestDefaultConfigurationReExecutesTheRunningBinary(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "soundpost")
	body := []byte("not really a binary")
	if err := os.WriteFile(exe, body, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(exe, link); err != nil {
		t.Skip("no symlinks on this host")
	}
	prevExe, prevCg := executablePath, readCgroupFile
	executablePath = func() (string, error) { return link, nil }
	readCgroupFile = func() ([]byte, error) { return []byte("12:cpu:/x\n0::/system.slice/soundpost.service\n"), nil }
	t.Cleanup(func() { executablePath, readCgroupFile = prevExe, prevCg })
	c, reason := resolveSymbolicatorConfig(SymbolicatorSettings{})
	want := filepath.Join(dir, "soundpost")
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		want = resolved
	}
	if reason != "" || c.Mode != "native" || c.WorkerPath != want || c.WorkerSHA256 != model.HashCanonical(body) || c.CgroupRoot != filepath.Join("/sys/fs/cgroup", "/system.slice/soundpost.service") || c.OCIRuntime != "" || c.OCIImage != "" {
		t.Fatalf("default config %+v (%q)", c, reason)
	}
	c, _ = resolveSymbolicatorConfig(SymbolicatorSettings{CgroupRoot: "/sys/fs/cgroup/delegated"})
	if c.CgroupRoot != "/sys/fs/cgroup/delegated" {
		t.Fatalf("explicit cgroup root ignored: %+v", c)
	}
	readCgroupFile = func() ([]byte, error) { return []byte("0::/../escape\n"), nil }
	if c, _ = resolveSymbolicatorConfig(SymbolicatorSettings{}); c.CgroupRoot != "" {
		t.Fatalf("escaping cgroup path accepted: %+v", c)
	}
}

func TestOperatorConfigIsPrivateStrictAndExplicit(t *testing.T) {
	good := symbolicate.Config{Mode: "oci", OCIRuntime: "/usr/bin/docker", OCIImage: "sha256:" + strings.Repeat("a", 64), WorkerSHA256: model.HashCanonical([]byte("w"))}
	raw, _ := json.Marshal(good)
	write := func(body []byte, mode os.FileMode) string {
		name := filepath.Join(t.TempDir(), "c.json")
		if err := os.WriteFile(name, body, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(name, mode); err != nil {
			t.Fatal(err)
		}
		return name
	}
	if c, reason := resolveSymbolicatorConfig(SymbolicatorSettings{ConfigPath: write(raw, 0o600)}); reason != "" || c.Mode != "oci" || c.OCIImage != good.OCIImage {
		t.Fatalf("valid config: %+v %q", c, reason)
	}
	cases := map[string]struct {
		path   string
		reason string
	}{
		"missing":       {filepath.Join(t.TempDir(), "absent.json"), "config_unreadable"},
		"unknown_field": {write([]byte(`{"mode":"native","bogus":1}`), 0o600), "config_invalid"},
		"no_mode":       {write([]byte(`{}`), 0o600), "config_invalid"},
		"other_mode":    {write([]byte(`{"mode":"auto"}`), 0o600), "config_invalid"},
		"trailing":      {write([]byte(`{"mode":"native"} {}`), 0o600), "config_invalid"},
	}
	if os.PathSeparator == '/' {
		cases["world_writable"] = struct {
			path   string
			reason string
		}{write(raw, 0o666), "config_not_private"}
	}
	for name, c := range cases {
		if _, reason := resolveSymbolicatorConfig(SymbolicatorSettings{ConfigPath: c.path}); reason != c.reason {
			t.Errorf("%s: reason %q, want %q", name, reason, c.reason)
		}
	}
}

// ---------------------------------------------------------------------------
// Real sandbox (OCI qualification image through docker); skipped, and reported as
// not exercised, on a host without both.

// leaks lists the places a canary must never reach: the response, the data
// directory of the app and any file the run left in the process temp directory.
func (r *symRig) leaks(t *testing.T, since time.Time, responses ...[]byte) []string {
	t.Helper()
	var found []string
	for i, b := range responses {
		if bytes.Contains(b, []byte(symCanary)) {
			found = append(found, fmt.Sprintf("response %d", i))
		}
	}
	scan := func(root string, recursive bool) {
		filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info.IsDir() {
				if p != root && !recursive {
					return filepath.SkipDir
				}
				return nil
			}
			if info.ModTime().Before(since) || info.Size() > 64<<20 {
				return nil
			}
			if raw, e := os.ReadFile(p); e == nil && bytes.Contains(raw, []byte(symCanary)) {
				found = append(found, p)
			}
			return nil
		})
	}
	scan(os.TempDir(), false)
	return found
}

func (r *symRig) realSandbox(t *testing.T) symbolicate.Config {
	t.Helper()
	config := ociSandbox(t)
	st := r.configure(SymbolicatorSettings{ConfigPath: writeConfig(t, config)})
	if st.State != SymbolicatorReady {
		t.Fatalf("real sandbox did not pass its startup probes: %+v", st)
	}
	return config
}

// Through the real served stack: a real uploaded source map, a real frame, a
// mapped answer, and no canary anywhere.
func TestServedProcessMapsARealFrame(t *testing.T) {
	started := time.Now().Add(-time.Second)
	r := newSymRig(t)
	r.realSandbox(t)
	artifact := r.mustUpload(r.a, []byte(symMapDoc), "dist/out.js", "debug-real", false)
	frame := symFrame(artifact.ID.String(), 1, 0)
	resp, v, attempts := r.mapped(r.a, false, frame)
	t.Logf("attempts inside the sandbox deadline: %d", attempts)
	f := v.Frames[0]
	if resp.status != 200 || f.Reason != string(symbolicate.Resolved) || f.Resolved == nil || f.Resolved.Source != "src/app.ts" || f.Resolved.Line != 7 || f.Resolved.Function != "boom" {
		t.Fatalf("frame was not mapped by the served process: %d %s", resp.status, resp.body)
	}
	t.Logf("mapped %+v map=%s state=%s", *f.Resolved, f.MapSHA256, v.State)
	if v.State != httpapi.StateReady || strings.Contains(string(resp.body), httpapi.ReasonSymbolicatorNotBuilt) {
		t.Fatalf("view state %q: %s", v.State, resp.body)
	}
	if !reflect.DeepEqual(f.Original, frame) {
		t.Fatalf("original frame altered: %+v", f.Original)
	}
	if f.Source.State == "present" || f.Source.Context != nil {
		t.Fatalf("source context released without being requested: %+v", f.Source)
	}
	// A private-source artifact with the grant held still releases nothing unless asked.
	priv := r.mustUpload(r.a, []byte(symMapDoc), "dist/private.js", "debug-private", true)
	resp2, v2, _ := r.mapped(r.a, false, symFrame(priv.ID.String(), 1, 0))
	if v2.Frames[0].Reason != string(symbolicate.Resolved) || v2.Frames[0].Source.Context != nil {
		t.Fatalf("private map default answer: %s", resp2.body)
	}
	if bad := r.leaks(t, started, resp.body, resp2.body); len(bad) != 0 {
		t.Fatalf("source canary reached %v", bad)
	}
	// Control that the leak detector can see the canary: only an explicit
	// include_sources request of the granted reader releases the selected line.
	respSrc, vSrc, _ := r.mapped(r.a, true, symFrame(priv.ID.String(), 1, 0))
	if vSrc.Frames[0].Source.Context == nil || !strings.Contains(*vSrc.Frames[0].Source.Context, symCanary) {
		t.Fatalf("control: the granted include_sources request did not release the source line: %s", respSrc.body)
	}
	if _, vPlain, _ := r.mapped(r.a, true, frame); vPlain.Frames[0].Source.Context != nil {
		t.Fatal("include_sources released text of an artifact without private sources")
	}
}

// Same-organization only: another organization (where the signed-in user holds
// artifacts.read) naming this artifact gets exactly the answer of an artifact that
// does not exist.
func TestFrameOfAnotherOrganizationIsIndistinguishableFromAbsent(t *testing.T) {
	r := newSymRig(t)
	r.realSandbox(t)
	artifact := r.mustUpload(r.a, []byte(symMapDoc), "dist/out.js", "debug-1", false)
	other := r.tenant("tenant-b", []string{"artifacts.read"}, false)
	other.build = r.a.build
	if _, v, _ := r.mapped(r.a, false, symFrame(artifact.ID.String(), 1, 0)); v.Frames[0].Reason != string(symbolicate.Resolved) {
		t.Fatalf("positive control did not map: %+v", v.Frames[0])
	}
	cross := symFrame(artifact.ID.String(), 1, 0)
	absent := symFrame(model.NewID().String(), 1, 0)
	respCross, vCross := r.frames(other, false, cross)
	respAbsent, vAbsent := r.frames(other, false, absent)
	if respCross.status != 200 || respAbsent.status != 200 {
		t.Fatalf("status %d / %d", respCross.status, respAbsent.status)
	}
	c, a := vCross.Frames[0], vAbsent.Frames[0]
	if c.Reason != string(symbolicate.Unavailable) || c.Resolved != nil || c.MapSHA256 != nil || c.Source.Context != nil {
		t.Fatalf("cross-organization frame answered %+v", c)
	}
	c.Original, a.Original = model.Frame{}, model.Frame{}
	if !reflect.DeepEqual(c, a) {
		t.Fatalf("existence is distinguishable:\n%+v\n%+v", c, a)
	}
	if bytes.Contains(respCross.body, []byte(artifact.Manifest.Org.String())) || bytes.Contains(respCross.body, artifact.Map.Hash[:]) {
		t.Fatal("cross-organization answer names the owning organization or map")
	}
}

// A deleted artifact stops resolving, exactly like an absent one.
func TestDeletedArtifactIsNotResolvable(t *testing.T) {
	r := newSymRig(t)
	r.realSandbox(t)
	artifact := r.mustUpload(r.a, []byte(symMapDoc), "dist/out.js", "debug-1", false)
	frame := symFrame(artifact.ID.String(), 1, 0)
	if _, v, _ := r.mapped(r.a, false, frame); v.Frames[0].Reason != string(symbolicate.Resolved) {
		t.Fatalf("warm-up did not map: %+v", v.Frames[0])
	}
	ctx := context.Background()
	admin, err := r.app.Auth.Authorize(ctx, r.actor, r.a.org, nil, auth.OrgAdmin)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := r.app.Retention.Delete(ctx, admin, retention.DeleteRequest{CommandID: model.NewID(), ExpectedRevision: r.revision(), Mode: model.DeleteEntity, OrgID: r.a.org, Reason: "symbolicator wiring deletion", ProjectIDs: []model.ID{r.a.project}, EntityIDs: []model.ID{artifact.ID}})
	if err != nil {
		t.Fatal(err)
	}
	for range 6 {
		if err = r.app.Retention.RunOnce(ctx); err != nil {
			t.Fatal(err)
		}
		if receipt, err = r.app.Retention.PollDelete(ctx, admin, receipt.OperationID); err != nil {
			t.Fatal(err)
		}
		if receipt.Phase == model.DeletePhaseComplete {
			break
		}
	}
	if receipt.Phase != model.DeletePhaseComplete {
		t.Fatalf("deletion did not complete: %+v", receipt)
	}
	for range 2 {
		_, v := r.frames(r.a, false, frame)
		if f := v.Frames[0]; f.Reason != string(symbolicate.Unavailable) || f.Resolved != nil || f.MapSHA256 != nil {
			t.Fatalf("deleted artifact still answered: %+v", f)
		}
	}
}

// revokingReader revokes the uploading source at the second lookup of a resolve
// once armed, i.e. after the worker ran and before the answer is released.
type revokingReader struct {
	*artifacts.Service
	mu      sync.Mutex
	armed   bool
	lookups int
	revoke  func()
}

func (r *revokingReader) Lookup(ctx context.Context, s auth.Scope, id model.ID) (artifacts.Artifact, error) {
	r.mu.Lock()
	fire := false
	if r.armed {
		r.lookups++
		fire = r.lookups == 2
	}
	r.mu.Unlock()
	if fire {
		r.revoke()
	}
	return r.Service.Lookup(ctx, s, id)
}

func TestRevokedGrantMidResolveFailsClosed(t *testing.T) {
	r := newSymRig(t)
	config := ociSandbox(t)
	artifact := r.mustUpload(r.a, []byte(symMapDoc), "dist/out.js", "debug-1", false)
	reader := &revokingReader{Service: r.app.Artifacts}
	reader.revoke = func() {
		if err := r.app.Control.Update(context.Background(), func(st *model.ControlState) error {
			src := st.Sources[r.a.source.String()]
			src.Revoked = true
			st.Sources[r.a.source.String()] = src
			return nil
		}); err != nil {
			t.Error(err)
		}
	}
	resolver, st := buildFrameResolver(context.Background(), reader, r.app.Retention, SymbolicatorSettings{ConfigPath: writeConfig(t, config)})
	if st.State != SymbolicatorReady {
		t.Fatalf("status %+v", st)
	}
	r.installResolver(resolver)
	frame := symFrame(artifact.ID.String(), 1, 0)
	// Control: before the revocation the very same request maps.
	if resp, v, _ := r.mapped(r.a, false, frame); v.Frames[0].Reason != string(symbolicate.Resolved) {
		t.Fatalf("control did not map: %s", resp.body)
	}
	reader.mu.Lock()
	reader.armed = true
	reader.mu.Unlock()
	resp, v := r.frames(r.a, false, frame)
	reader.mu.Lock()
	lookups := reader.lookups
	reader.mu.Unlock()
	if lookups < 2 {
		t.Fatalf("the release fence was never reached (lookups=%d): %s", lookups, resp.body)
	}
	f := v.Frames[0]
	if resp.status != 200 || f.Reason != string(symbolicate.Unavailable) || f.Resolved != nil || f.MapSHA256 != nil || f.Source.Context != nil {
		t.Fatalf("a revoked source's map was released: %d %s", resp.status, resp.body)
	}
}

// ---------------------------------------------------------------------------
// Failure drills.

// Bounds are derived from ProcessTimeout: the resolver's own wall budget plus the
// time the HTTP round trip and a container teardown may take on a loaded host.
const drillSlack = 6 * time.Second

func drillBound() time.Duration { return symbolicate.ProcessTimeout + drillSlack }

// bigMap is a valid source map with n segments; the upload decoder caps a map at
// 1,048,576 segments, so this is as large as a stored table can be.
func bigMap(n int) []byte {
	var b strings.Builder
	b.WriteString(`{"version":3,"sources":["big.ts"],"names":[],"mappings":"`)
	// Each segment is "CAAA" (generated column +1, same source position).
	for i := range n {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString("CAAA")
	}
	b.WriteString(`"}`)
	return []byte(b.String())
}

func TestSandboxDrillsDegradeToTypedReasonsAndNeverWedge(t *testing.T) {
	r := newSymRig(t)
	r.realSandbox(t)
	good := r.mustUpload(r.a, []byte(symMapDoc), "dist/good.js", "debug-good", false)
	drills := []struct {
		name string
		raw  []byte
	}{
		{"huge_mapping_table", bigMap(1_040_000)},
		{"many_lines", []byte(`{"version":3,"sources":["l.ts"],"names":[],"mappings":"` + strings.Repeat(";", 3_000_000) + `AAAA"}`)},
		{"many_names", func() []byte {
			var b strings.Builder
			b.WriteString(`{"version":3,"sources":["n.ts"],"names":[`)
			for i := range 1_500_000 {
				if i > 0 {
					b.WriteString(",")
				}
				fmt.Fprintf(&b, `"n%d"`, i)
			}
			b.WriteString(`],"mappings":"AAAAA"}`)
			return []byte(b.String())
		}()},
	}
	for i, d := range drills {
		t.Run(d.name, func(t *testing.T) {
			resp, a := r.upload(r.a, d.raw, fmt.Sprintf("dist/drill-%d.js", i), fmt.Sprintf("debug-drill-%d", i), false)
			if resp.status != 200 {
				// The upload gate may refuse an oversize or invalid map before it ever
				// reaches a worker: that is a typed refusal, and then nothing can wedge.
				t.Logf("%s refused at upload: %d", d.name, resp.status)
				if resp.status >= 500 {
					t.Fatalf("upload crashed the server: %d %s", resp.status, resp.body)
				}
				return
			}
			frame := symFrame(a.ID.String(), 1, 0)
			start := time.Now()
			resp, v := r.frames(r.a, false, frame)
			took := time.Since(start)
			if resp.status != 200 || len(v.Frames) != 1 {
				t.Fatalf("frames answered %d %s", resp.status, resp.body)
			}
			f := v.Frames[0]
			t.Logf("%s: reason=%s resolved=%v took=%s", d.name, f.Reason, f.Resolved != nil, took)
			if took > drillBound() {
				t.Fatalf("request took %s, bound %s", took, drillBound())
			}
			if !reflect.DeepEqual(f.Original, frame) {
				t.Fatalf("original frame lost: %+v", f.Original)
			}
			switch symbolicate.Reason(f.Reason) {
			case symbolicate.Resolved, symbolicate.Deadline, symbolicate.ResourceLimit, symbolicate.WorkerFailure, symbolicate.InvalidMap, symbolicate.Unmapped:
			default:
				t.Fatalf("untyped degraded reason %q", f.Reason)
			}
			// The server is alive and the slot is free: a normal frame maps right after.
			start = time.Now()
			if _, v, _ = r.mapped(r.a, false, symFrame(good.ID.String(), 1, 0)); v.Frames[0].Reason != string(symbolicate.Resolved) {
				t.Fatalf("server did not recover after %s: %+v", d.name, v.Frames[0])
			}
			if time.Since(start) > drillBound() {
				t.Fatalf("recovery took %s", time.Since(start))
			}
		})
	}
}

// More concurrent requests than the two worker slots: every request returns within
// the wall budget with a typed reason and the original frame, and the server is
// healthy afterwards.
func TestConcurrentRequestsBeyondTheSlotsAreBoundedAndTyped(t *testing.T) {
	r := newSymRig(t)
	r.realSandbox(t)
	artifact := r.mustUpload(r.a, []byte(symMapDoc), "dist/out.js", "debug-1", false)
	frame := symFrame(artifact.ID.String(), 1, 0)
	const n = 8
	type result struct {
		took time.Duration
		resp symResp
		v    httpapi.FramesView
	}
	out := make([]result, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			start := time.Now()
			resp, v := r.frames(r.a, false, frame)
			out[i] = result{time.Since(start), resp, v}
		}()
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(drillBound() + 10*time.Second):
		t.Fatal("concurrent requests are stuck")
	}
	mapped, degraded := 0, 0
	for i, o := range out {
		if o.resp.status != 200 || len(o.v.Frames) != 1 {
			t.Fatalf("request %d: %d %s", i, o.resp.status, o.resp.body)
		}
		if o.took > drillBound() {
			t.Fatalf("request %d took %s, bound %s", i, o.took, drillBound())
		}
		f := o.v.Frames[0]
		if !reflect.DeepEqual(f.Original, frame) {
			t.Fatalf("request %d lost the original frame", i)
		}
		switch symbolicate.Reason(f.Reason) {
		case symbolicate.Resolved:
			mapped++
		case symbolicate.Deadline:
			degraded++
		default:
			t.Fatalf("request %d: reason %q", i, f.Reason)
		}
	}
	t.Logf("mapped=%d deadline=%d of %d", mapped, degraded, n)
	if _, v, _ := r.mapped(r.a, false, frame); v.Frames[0].Reason != string(symbolicate.Resolved) {
		t.Fatalf("not healthy afterwards: %+v", v.Frames[0])
	}
}

type stuckReader struct{ *artifacts.Service }

func (stuckReader) Get(ctx context.Context, _ auth.Scope, _ model.ID) (io.ReadCloser, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// A reader that never answers cannot hold a request past the resolver's wall
// budget, and releases its slot: the next request is not queued behind it.
func TestStuckArtifactReadIsBoundedByProcessTimeout(t *testing.T) {
	r := newSymRig(t)
	artifact := r.mustUpload(r.a, []byte(symMapDoc), "dist/out.js", "debug-1", false)
	withProbe(t, probeDenied)
	resolver, st := buildFrameResolver(context.Background(), stuckReader{r.app.Artifacts}, r.app.Retention, SymbolicatorSettings{ConfigPath: dummyConfig(t)})
	if st.State != SymbolicatorReady {
		t.Fatalf("status %+v", st)
	}
	r.installResolver(resolver)
	// A regression that lets the read hang must fail this test, not wedge the
	// server's shutdown: closing the client connections cancels the request context.
	t.Cleanup(r.srv.CloseClientConnections)
	frame := symFrame(artifact.ID.String(), 1, 0)
	type answer struct {
		resp symResp
		v    httpapi.FramesView
	}
	ask := func() (answer, time.Duration) {
		got := make(chan answer, 1)
		start := time.Now()
		go func() { resp, v := r.frames(r.a, false, frame); got <- answer{resp, v} }()
		select {
		case a := <-got:
			return a, time.Since(start)
		case <-time.After(symbolicate.ProcessTimeout + 4*time.Second):
			t.Fatalf("a stuck artifact read held the request past ProcessTimeout (%s)", symbolicate.ProcessTimeout)
			return answer{}, 0
		}
	}
	a, took := ask()
	resp, v := a.resp, a.v
	if resp.status != 200 || v.Frames[0].Resolved != nil || !reflect.DeepEqual(v.Frames[0].Original, frame) {
		t.Fatalf("stuck read answered %d %s", resp.status, resp.body)
	}
	if took > symbolicate.ProcessTimeout+2*time.Second {
		t.Fatalf("a stuck read held the request for %s (ProcessTimeout %s)", took, symbolicate.ProcessTimeout)
	}
	t.Logf("stuck read: reason=%s took=%s", v.Frames[0].Reason, took)
	// Two more in sequence must each also be bounded: no slot leaked.
	for range 2 {
		if _, took = ask(); took > symbolicate.ProcessTimeout+2*time.Second {
			t.Fatalf("a later stuck request is not bounded: %s", took)
		}
	}
}

// Only the running process's `ps` is not inspected: the drill above reaps its
// children through the service, and a leaked temp file is checked here.
func TestNoLeftoverUploadSpoolFiles(t *testing.T) {
	started := time.Now().Add(-time.Second)
	r := newSymRig(t)
	r.mustUpload(r.a, []byte(symMapDoc), "dist/out.js", "debug-1", true)
	if bad := r.leaks(t, started); len(bad) != 0 {
		t.Fatalf("canary found in %v", bad)
	}
}
