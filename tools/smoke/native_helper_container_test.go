// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"debug/elf"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func healthyHost() nativeHostFacts {
	return nativeHostFacts{GOOS: "linux", Kernel: "6.12.74", Paranoid: 2, CgroupV2: true}
}

func TestNativeHelperPrerequisiteNamesTheExactMissingThing(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*nativeHostFacts)
		want   string // "" = runnable
	}{
		{"healthy host", func(*nativeHostFacts) {}, ""},
		{"not linux", func(f *nativeHostFacts) { f.GOOS = "windows" }, "not a Linux host"},
		{"no docker", func(f *nativeHostFacts) { f.DockerErr = "executable file not found in $PATH" }, "no OCI runtime"},
		{"no compose plugin", func(f *nativeHostFacts) { f.ComposeErr = "docker: 'compose' is not a docker command" }, "docker compose"},
		{"hybrid cgroups", func(f *nativeHostFacts) { f.CgroupV2 = false }, "cgroup v2"},
		{"paranoid unreadable", func(f *nativeHostFacts) { f.Paranoid = -100 }, "perf_event_paranoid"},
	}
	for _, c := range cases {
		f := healthyHost()
		c.mutate(&f)
		got := nativeHelperPrerequisite(f)
		if c.want == "" {
			if got != "" {
				t.Errorf("%s: want runnable, got %q", c.name, got)
			}
			continue
		}
		if !strings.Contains(got, c.want) {
			t.Errorf("%s: reason %q does not name %q", c.name, got, c.want)
		}
	}
}

func hotSamples(n uint64) nativeCapture {
	return nativeCapture{Outcome: "samples", Samples: n, TargetSamples: n, WithUserFrames: n, HotSymbol: "main.soundpostHotLoop", HotSymbolSamples: n}
}

func typedDenied() nativeCapture {
	return nativeCapture{Outcome: "refused", Error: "native profiling: denied: permission_denied", ErrorStatus: "denied", ErrorReason: "permission_denied"}
}

func TestJudgeNativeCaseNeverReadsZeroOrAnotherRefusalAsEitherAnswer(t *testing.T) {
	zero := nativeCapture{Outcome: "no_samples"}
	foreign := hotSamples(100)
	foreign.TargetSamples = 40
	cold := hotSamples(100)
	cold.HotSymbolSamples = 10
	resource := nativeCapture{Outcome: "refused", ErrorStatus: "", ResourceLimit: true}
	authz := nativeCapture{Outcome: "refused", AuthorizationError: true}
	deniedWithSamples := typedDenied()
	deniedWithSamples.Samples = 3
	unsupported := nativeCapture{Outcome: "refused", ErrorStatus: "unsupported", ErrorReason: "event_unavailable"}
	cases := []struct {
		name     string
		kase     string
		paranoid int
		c        nativeCapture
		ok       bool
		observed string
	}{
		{"permitted host: real samples of the target", caseComposedPerfmon, 2, hotSamples(494), true, "samples"},
		{"permitted host: refused", caseComposedPerfmon, 2, typedDenied(), false, "denied"},
		{"permitted host: an empty successful capture", caseComposedPerfmon, 2, zero, false, "no_samples"},
		{"permitted host: samples that are not the target's", caseComposedPerfmon, 2, foreign, false, "samples"},
		{"permitted host: samples that never reach the hot function", caseComposedPerfmon, 2, cold, false, "samples"},
		{"denying host: typed denial", caseComposedPerfmon, 3, typedDenied(), true, "denied"},
		{"denying host: samples would mean the host did not deny", caseComposedPerfmon, 3, hotSamples(10), false, "samples"},
		{"denying host: an empty capture is not a denial", caseComposedPerfmon, 3, zero, false, "no_samples"},
		{"denying host: a resource refusal is not a denial", caseComposedPerfmon, 3, resource, false, "refused"},
		{"denying host: an authorization refusal is not a denial", caseComposedPerfmon, 3, authz, false, "refused"},
		{"denying host: unsupported is not denied", caseComposedPerfmon, 3, unsupported, false, "refused"},
		{"denied with samples is contradictory", caseComposedPerfmon, 3, deniedWithSamples, false, "refused"},
		{"without PERFMON on a permitted host may sample (user-only events)", caseWithoutPerfmon, 2, hotSamples(50), true, "samples"},
		{"without PERFMON on a permitted host may be denied", caseWithoutPerfmon, 2, typedDenied(), true, "denied"},
		{"without PERFMON: empty capture fails", caseWithoutPerfmon, 2, zero, false, "no_samples"},
		{"without PERFMON on a denying host must be denied", caseWithoutPerfmon, 3, hotSamples(50), false, "samples"},
		{"hidden target must be denied", caseTargetNotVisible, 2, typedDenied(), true, "denied"},
		{"hidden target sampled would be a visibility bypass", caseTargetNotVisible, 2, hotSamples(5), false, "samples"},
		{"hidden target empty capture", caseTargetNotVisible, 2, zero, false, "no_samples"},
	}
	for _, c := range cases {
		observed, ok, why := judgeNativeCase(c.kase, c.paranoid, c.c)
		if ok != c.ok || observed != c.observed {
			t.Errorf("%s: ok=%v observed=%q (%s), want ok=%v observed=%q", c.name, ok, observed, why, c.ok, c.observed)
		}
		if !ok && why == "" {
			t.Errorf("%s: a failing case must say why", c.name)
		}
	}
	if _, ok, _ := judgeNativeCase("no_such_case", 2, hotSamples(1)); ok {
		t.Error("an unknown case must not pass")
	}
}

// goBuildBurner builds the workload exactly as the smoke does and returns its path.
func goBuildBurner(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("the workload is a Linux executable")
	}
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go toolchain on PATH")
	}
	out := filepath.Join(t.TempDir(), "burner")
	cmd := exec.Command(goBin, "build", "-trimpath", "-ldflags", "-B gobuildid", "-o", out, "./nativehelper/burner")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux")
	if raw, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build burner: %v\n%s", err, raw)
	}
	return out
}

// The Go linker writes the GNU build ID note into its own section but leaves it outside the PT_NOTE segment the
// helper walks (internal/nativeperf executableBuildID), so a policy that names the build ID can never match it: the
// helper answered "invalid native target identity" for the unpatched workload on a real run (l5w24 evidence).
func TestPatchNoteSegmentMakesTheGNUBuildIDVisibleToTheHelperParser(t *testing.T) {
	path := goBuildBurner(t)
	f, err := elf.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	section := f.Section(".note.gnu.build-id")
	f.Close()
	if section == nil {
		t.Fatal("the linker wrote no GNU build ID section")
	}
	if id, err := elfNoteSegmentBuildID(path); err == nil {
		t.Fatalf("the unpatched Go executable already exposes %s through PT_NOTE; the patch step is not needed any more and must be removed", id)
	}
	if err := patchNoteSegment(path); err != nil {
		t.Fatal(err)
	}
	id, err := elfNoteSegmentBuildID(path)
	if err != nil {
		t.Fatalf("after the patch the helper's walk still finds no GNU build ID: %v", err)
	}
	want, err := sectionBuildID(path)
	if err != nil || id != want || len(id) < 8 {
		t.Fatalf("PT_NOTE build ID %q, section build ID %q (%v)", id, want, err)
	}
	if err := patchNoteSegment(path); err != nil {
		t.Fatalf("patching twice must be a no-op, got %v", err)
	}
	if again, _ := elfNoteSegmentBuildID(path); again != id {
		t.Fatalf("patching twice changed the build ID to %q", again)
	}
	// it still runs
	run := exec.Command(path)
	stdout, _ := run.StdoutPipe()
	if err := run.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { run.Process.Kill(); run.Wait() }()
	buf := make([]byte, 6)
	if _, err := stdout.Read(buf); err != nil || string(buf) != "ready\n" {
		t.Fatalf("the patched workload does not print ready: %q %v", buf, err)
	}
}

func inspectOf(host map[string]any) []byte {
	raw, _ := json.Marshal([]any{map[string]any{"HostConfig": host, "Config": map[string]any{"User": "0:0"}}})
	return raw
}

func shippedHelperHostConfig() map[string]any {
	return map[string]any{"Privileged": false, "CapAdd": []string{"CAP_PERFMON"}, "CapDrop": []string{"ALL"},
		"SecurityOpt":    []string{"no-new-privileges:true", "seccomp={\"defaultAction\":\"SCMP_ACT_ERRNO\"}"},
		"ReadonlyRootfs": true, "NetworkMode": "none", "PidMode": "container:abc", "CgroupnsMode": "host", "PidsLimit": 16}
}

func TestHelperContainerConfigRefusesEveryFallback(t *testing.T) {
	if got := helperContainerConfigProblems(inspectOf(shippedHelperHostConfig()), true); len(got) != 0 {
		t.Fatalf("the shipped configuration is refused: %v", got)
	}
	noPerfmon := shippedHelperHostConfig()
	noPerfmon["CapAdd"] = nil
	if got := helperContainerConfigProblems(inspectOf(noPerfmon), false); len(got) != 0 {
		t.Fatalf("the PERFMON-less variant is refused when it is expected: %v", got)
	}
	if got := helperContainerConfigProblems(inspectOf(noPerfmon), true); len(got) == 0 {
		t.Error("a missing PERFMON must be reported when PERFMON is expected")
	}
	mutations := map[string]func(map[string]any){
		"privileged":         func(h map[string]any) { h["Privileged"] = true },
		"SYS_ADMIN":          func(h map[string]any) { h["CapAdd"] = []string{"CAP_PERFMON", "CAP_SYS_ADMIN"} },
		"SYS_PTRACE":         func(h map[string]any) { h["CapAdd"] = []string{"CAP_PERFMON", "CAP_SYS_PTRACE"} },
		"seccomp unconfined": func(h map[string]any) { h["SecurityOpt"] = []string{"no-new-privileges:true", "seccomp=unconfined"} },
		"no seccomp profile": func(h map[string]any) { h["SecurityOpt"] = []string{"no-new-privileges:true"} },
		"apparmor unconfined": func(h map[string]any) {
			h["SecurityOpt"] = []string{"no-new-privileges:true", "seccomp={}", "apparmor=unconfined"}
		},
		"privilege escalation allowed": func(h map[string]any) { h["SecurityOpt"] = []string{"seccomp={}"} },
		"writable root":                func(h map[string]any) { h["ReadonlyRootfs"] = false },
		"network":                      func(h map[string]any) { h["NetworkMode"] = "bridge" },
		"host pid":                     func(h map[string]any) { h["PidMode"] = "host" },
		"no pid choice":                func(h map[string]any) { h["PidMode"] = "" },
		"capabilities kept":            func(h map[string]any) { h["CapDrop"] = nil },
		"private cgroup namespace":     func(h map[string]any) { h["CgroupnsMode"] = "private" },
	}
	for name, mutate := range mutations {
		h := shippedHelperHostConfig()
		mutate(h)
		if got := helperContainerConfigProblems(inspectOf(h), true); len(got) == 0 {
			t.Errorf("%s: accepted", name)
		}
	}
	if got := helperContainerConfigProblems([]byte("not json"), true); len(got) == 0 {
		t.Error("garbage inspect output accepted")
	}
}

// The matrix row must say not_run with the exact reason, never passed, when its prerequisites are missing.
func TestNativeProfileInstallRowNeverPassesWithoutItsPrerequisites(t *testing.T) {
	for name, mutate := range map[string]func(*nativeHostFacts){
		"no docker":      func(f *nativeHostFacts) { f.DockerErr = "not found" },
		"no compose":     func(f *nativeHostFacts) { f.ComposeErr = "no plugin" },
		"hybrid cgroups": func(f *nativeHostFacts) { f.CgroupV2 = false },
		"not linux":      func(f *nativeHostFacts) { f.GOOS = "darwin" },
	} {
		f := healthyHost()
		mutate(&f)
		detail, err := nativeProfileInstallRow(nativeHelperOptions{HelperTar: "does-not-exist.tar", Root: t.TempDir(), ArtifactDir: t.TempDir()}, f)
		status, text, failed := classifyMatrixRow(detail, err)
		if status != "not_run" || failed || text == "" {
			t.Errorf("%s: status=%s failed=%v text=%q err=%v", name, status, failed, text, err)
		}
	}
}

func TestClassifyMatrixRowNeverTurnsAnUnmetPrerequisiteIntoAPass(t *testing.T) {
	if s, d, failed := classifyMatrixRow("ok", nil); s != "passed" || d != "ok" || failed {
		t.Errorf("success: %s %s %v", s, d, failed)
	}
	if s, d, failed := classifyMatrixRow("ignored success text", notRun("docker is absent")); s != "not_run" || d != "docker is absent" || failed {
		t.Errorf("not run: %s %q %v", s, d, failed)
	}
	if s, _, failed := classifyMatrixRow("", os.ErrNotExist); s != "failed" || !failed {
		t.Errorf("error: %s %v", s, failed)
	}
}

// Only the published URLs may be hard-coded as not run (nothing is published). Every other row must be able to pass.
func TestOnlyPublishedURLsIsRecordedNotRunWithoutRunning(t *testing.T) {
	raw, err := os.ReadFile("fresh_install_matrix.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "record(") && strings.Contains(trimmed, `"not_run"`) && !strings.Contains(trimmed, `"published_urls"`) {
			t.Errorf("a matrix row is hard-coded not_run: %s", trimmed)
		}
	}
	if !strings.Contains(string(raw), `record("published_urls", "not_run"`) {
		t.Error("published_urls must stay recorded not_run: nothing is published")
	}
}

func TestMatrixRowsNeedingARuntimeAreNotRunWithTheirExactReason(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent")
	if _, err := containerInstallRow(containerInstallOptions{ImageTar: "x.tar", ArtifactDir: t.TempDir(), DockerErr: "docker: not found"}); err == nil || !strings.HasPrefix(err.Error(), "not_run:") || !strings.Contains(err.Error(), "docker: not found") {
		t.Errorf("container_install without an OCI runtime: %v", err)
	}
	for name, j := range map[string]journeysOptions{
		"no chrome":   {Chrome: missing, NodeLinux: os.Args[0], PGImage: "img"},
		"no node":     {Chrome: os.Args[0], NodeLinux: missing, PGImage: "img"},
		"no database": {Chrome: os.Args[0], NodeLinux: os.Args[0]},
	} {
		if _, err := referenceJourneysRow(j); err == nil || !strings.HasPrefix(err.Error(), "not_run:") {
			t.Errorf("reference_journeys %s: %v", name, err)
		}
	}
}

func TestWheelRowIsNotRunWhenThePythonCannotMakeAVenvAndNeverPassed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell stub")
	}
	stub := filepath.Join(t.TempDir(), "python-stub")
	if err := os.WriteFile(stub, []byte("#!/bin/sh\necho 'ensurepip is not available' >&2\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := wheelFreshVenvRow(stub, filepath.Join(t.TempDir(), "x.whl"), subjectRecord{Name: "soundpost-1.0.0", Detail: "1.0.0", SHA256: "abc"})
	if err == nil || !strings.HasPrefix(err.Error(), "not_run:") || !strings.Contains(err.Error(), "ensurepip") {
		t.Fatalf("want not_run naming ensurepip, got %v", err)
	}
}

// TestNativeHelperContainerOfProducedHelper runs the release's helper image under Docker (see native_helper_container.go).
// It needs the output directory of `go run ./build artifacts` (SOUNDPOST_NATIVE_HELPER_ARTIFACTS), Docker with the compose plugin
// and a unified cgroup v2 host; the report lands in SOUNDPOST_NATIVE_HELPER_OUT. On a host whose perf_event_paranoid is 3 the run
// verifies the typed denial and reports not_run for the positive capture, which fails this test only when a case failed.
func TestNativeHelperContainerOfProducedHelper(t *testing.T) {
	art := os.Getenv("SOUNDPOST_NATIVE_HELPER_ARTIFACTS")
	if art == "" {
		t.Skip("set SOUNDPOST_NATIVE_HELPER_ARTIFACTS to the output directory of `go run ./build artifacts`")
	}
	out := os.Getenv("SOUNDPOST_NATIVE_HELPER_OUT")
	if out == "" {
		out = t.TempDir()
	}
	detail, err := nativeProfileInstallRow(nativeHelperOptions{Root: "../..", HelperTar: filepath.Join(art, "image", "soundpost-perf-helper-linux-amd64.oci.tar"), ArtifactDir: out}, probeNativeHost())
	status, text, failed := classifyMatrixRow(detail, err)
	t.Logf("native_profile_install: %s: %s", status, text)
	if failed {
		t.Fatal(text)
	}
}
