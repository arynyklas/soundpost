// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"archive/tar"
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// This file runs the PRODUCED native acquisition helper image (build/artifacts.go, kind oci_image_perf_helper) under an
// OCI runtime exactly as deploy/compose.distributed.yaml's `native` profile declares it (uid 0 holding only CAP_PERFMON,
// the audited seccomp profile, no network, a read-only root, a PID namespace chosen by the operator), against a real
// CPU-burning container, with a real client that speaks the helper's signed-grant protocol from inside the helper's
// namespaces (tools/smoke/nativehelper/client). It records what the kernel and the runtime did, never what the
// manifest says:
//
//	composed_perfmon   the shipped service. On a host that permits it (perf_event_paranoid <= 2) the client must receive
//	                   real software CPU-clock samples of the target, every one attributed to the target, resolved
//	                   (verifier-side ELF lookup) to the workload's hot function. On a host that forbids it
//	                   (Debian-style perf_event_paranoid = 3) the capability must come back as the typed denied result.
//	without_perfmon    the same service without CAP_PERFMON: the typed denied result, or (on paranoid <= 2, where
//	                   user-space-only events of a same-uid process need no capability) real samples. Never zero.
//	target_not_visible the target is a non-root container (like the shipped server image); the helper, holding only
//	                   PERFMON, cannot read it: the typed denied result on every host.
//
// The sysctl is never rewritten here: the operator (or the evidence script) sets it before the run.

const (
	caseComposedPerfmon  = "composed_perfmon"
	caseWithoutPerfmon   = "without_perfmon"
	caseTargetNotVisible = "target_not_visible"
)

// notRun marks a prerequisite that does not exist on this host: the matrix records not_run with this exact reason.
func notRun(reason string) error { return errors.New("not_run:" + reason) }

// classifyMatrixRow maps a row function's result to a matrix status. A not_run error is never a pass and never a failure.
func classifyMatrixRow(detail string, err error) (status, text string, failed bool) {
	switch {
	case err == nil:
		return "passed", detail, false
	case strings.HasPrefix(err.Error(), "not_run:"):
		return "not_run", strings.TrimPrefix(err.Error(), "not_run:"), false
	default:
		return "failed", err.Error(), true
	}
}

// nativeHostFacts are the host properties the helper run depends on.
type nativeHostFacts struct {
	GOOS         string
	Kernel       string
	Paranoid     int // -100: unreadable
	CgroupV2     bool
	DockerServer string
	DockerErr    string // non-empty: no usable OCI runtime
	ComposeErr   string // non-empty: no docker compose plugin
	ComposeVer   string
}

func probeNativeHost() nativeHostFacts {
	f := nativeHostFacts{GOOS: runtime.GOOS, Paranoid: -100}
	if raw, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		f.Kernel = strings.TrimSpace(string(raw))
	}
	if raw, err := os.ReadFile("/proc/sys/kernel/perf_event_paranoid"); err == nil {
		if n, err := strconv.Atoi(strings.TrimSpace(string(raw))); err == nil {
			f.Paranoid = n
		}
	}
	if raw, err := os.ReadFile("/proc/self/mountinfo"); err == nil {
		for _, line := range strings.Split(string(raw), "\n") {
			fields := strings.Fields(line)
			if len(fields) > 9 && fields[4] == "/sys/fs/cgroup" {
				for i, v := range fields {
					if v == "-" && i+1 < len(fields) && fields[i+1] == "cgroup2" {
						f.CgroupV2 = true
					}
				}
			}
		}
	}
	if out, err := exec.Command("docker", "version", "--format", "{{.Server.Version}}").CombinedOutput(); err != nil {
		f.DockerErr = strings.TrimSpace(firstLine(string(out)) + " " + err.Error())
	} else {
		f.DockerServer = strings.TrimSpace(string(out))
	}
	if f.DockerErr == "" {
		if out, err := exec.Command("docker", "compose", "version", "--short").CombinedOutput(); err != nil {
			f.ComposeErr = strings.TrimSpace(firstLine(string(out)) + " " + err.Error())
		} else {
			f.ComposeVer = strings.TrimSpace(string(out))
		}
	}
	return f
}

// nativeHelperPrerequisite is the exact reason the helper cannot be run on this host at all ("" when it can).
func nativeHelperPrerequisite(f nativeHostFacts) string {
	switch {
	case f.GOOS != "linux":
		return "not a Linux host (" + f.GOOS + "): the helper is a Linux perf_event_open client"
	case f.DockerErr != "":
		return "no OCI runtime on this host: docker is not usable (" + f.DockerErr + ")"
	case f.ComposeErr != "":
		return "docker compose is not usable (" + f.ComposeErr + "): the shipped deploy/compose.distributed.yaml native profile is what is run"
	case !f.CgroupV2:
		return "the host does not mount a unified cgroup v2 hierarchy at /sys/fs/cgroup (hybrid or v1): the helper identifies a target by its cgroup v2 directory"
	case f.Paranoid == -100:
		return "kernel.perf_event_paranoid is not readable on this host"
	}
	return ""
}

// nativeCapture mirrors the JSON line tools/smoke/nativehelper/client prints for `capture`.
type nativeCapture struct {
	Outcome            string  `json:"outcome"`
	Error              string  `json:"error"`
	ErrorStatus        string  `json:"error_status"`
	ErrorReason        string  `json:"error_reason"`
	AuthorizationError bool    `json:"authorization_denied"`
	ResourceLimit      bool    `json:"resource_limit"`
	Samples            uint64  `json:"cpu_samples"`
	TargetSamples      uint64  `json:"samples_of_target_process"`
	WithUserFrames     uint64  `json:"samples_with_user_frames"`
	HotSymbol          string  `json:"hot_symbol"`
	HotSymbolSamples   uint64  `json:"samples_resolved_to_hot_symbol"`
	TopSymbols         []any   `json:"top_symbols"`
	Threads            int     `json:"threads_observed"`
	LossEvents         uint64  `json:"loss_events"`
	LostRecords        uint64  `json:"lost_records"`
	StreamEnd          string  `json:"stream_end"`
	CaptureSeconds     float64 `json:"capture_seconds"`
	MethodUnit         string  `json:"method_unit"`
}

func (c nativeCapture) typedDenied() bool {
	return c.Outcome == "refused" && c.ErrorStatus == "denied" && c.ErrorReason == "permission_denied" && c.Samples == 0
}

// sampled is a real capture: samples exist, every one is the target's, and most of them resolve to the hot function.
func (c nativeCapture) sampled() (bool, string) {
	switch {
	case c.Outcome != "samples" || c.Samples == 0:
		return false, "no samples were received"
	case c.TargetSamples != c.Samples:
		return false, fmt.Sprintf("only %d of %d samples are the target's", c.TargetSamples, c.Samples)
	case c.HotSymbolSamples*2 < c.Samples:
		return false, fmt.Sprintf("only %d of %d samples resolve to %s", c.HotSymbolSamples, c.Samples, c.HotSymbol)
	}
	return true, ""
}

// judgeNativeCase reports what the helper did (samples, denied, no_samples, refused) and whether that is the answer
// this case requires on a host with this perf_event_paranoid. A successful capture without samples is neither a pass
// nor a denial (a denied deployment must never look like zero or complete data).
func judgeNativeCase(name string, paranoid int, c nativeCapture) (observed string, ok bool, why string) {
	switch {
	case c.typedDenied():
		observed = "denied"
	case c.Outcome == "samples":
		observed = "samples"
	case c.Outcome == "no_samples":
		observed = "no_samples"
	default:
		observed = "refused"
	}
	samples, samplesWhy := c.sampled()
	switch name {
	case caseComposedPerfmon:
		if paranoid >= 3 {
			if !c.typedDenied() {
				return observed, false, fmt.Sprintf("perf_event_paranoid=%d forbids perf_event_open without CAP_SYS_ADMIN, so the capability must be the typed denied result, got outcome %q error %q", paranoid, c.Outcome, c.Error)
			}
			return observed, true, ""
		}
		if !samples {
			return observed, false, "the host permits the capture but " + samplesWhy + " (outcome " + strconv.Quote(c.Outcome) + ", error " + strconv.Quote(c.Error) + ")"
		}
		return observed, true, ""
	case caseWithoutPerfmon:
		if c.typedDenied() {
			return observed, true, ""
		}
		if paranoid >= 3 {
			return observed, false, "a denying host must give the typed denied result, got outcome " + strconv.Quote(c.Outcome)
		}
		if !samples {
			return observed, false, samplesWhy + " (outcome " + strconv.Quote(c.Outcome) + ", error " + strconv.Quote(c.Error) + ")"
		}
		return observed, true, ""
	case caseTargetNotVisible:
		if !c.typedDenied() {
			return observed, false, "the helper must not see a target of another uid: want the typed denied result, got outcome " + strconv.Quote(c.Outcome) + " error " + strconv.Quote(c.Error)
		}
		return observed, true, ""
	}
	return observed, false, "unknown case " + name
}

// helperContainerConfigProblems audits the RUNNING helper container's configuration (docker inspect), the settings the
// runtime actually applied: no privileged, unconfined or SYS_ADMIN fallback.
func helperContainerConfigProblems(inspect []byte, wantPerfmon bool) []string {
	var parsed []struct {
		HostConfig struct {
			Privileged     bool
			CapAdd         []string
			CapDrop        []string
			SecurityOpt    []string
			ReadonlyRootfs bool
			NetworkMode    string
			PidMode        string
			CgroupnsMode   string
		}
	}
	if err := json.Unmarshal(inspect, &parsed); err != nil || len(parsed) != 1 {
		return []string{"docker inspect output is not one container"}
	}
	h := parsed[0].HostConfig
	var out []string
	if h.Privileged {
		out = append(out, "container is privileged")
	}
	var adds []string
	for _, c := range h.CapAdd {
		adds = append(adds, strings.TrimPrefix(strings.ToUpper(c), "CAP_"))
	}
	switch {
	case wantPerfmon && !(len(adds) == 1 && adds[0] == "PERFMON"):
		out = append(out, fmt.Sprintf("capabilities added are %v, want exactly [PERFMON]", adds))
	case !wantPerfmon && len(adds) != 0:
		out = append(out, fmt.Sprintf("capabilities added are %v, want none", adds))
	}
	dropAll := false
	for _, c := range h.CapDrop {
		dropAll = dropAll || strings.EqualFold(c, "ALL")
	}
	if !dropAll {
		out = append(out, "capabilities are not dropped (cap_drop ALL missing)")
	}
	noNewPrivs, profile := false, false
	for _, o := range h.SecurityOpt {
		switch {
		case o == "no-new-privileges" || o == "no-new-privileges:true" || o == "no-new-privileges=true":
			noNewPrivs = true
		case strings.HasPrefix(o, "seccomp="):
			v := strings.TrimPrefix(o, "seccomp=")
			if v == "unconfined" || !strings.Contains(v, "SCMP_ACT_ERRNO") {
				out = append(out, "seccomp is not the deny-by-default audited profile: "+clip(v, 40))
			} else {
				profile = true
			}
		case strings.Contains(o, "unconfined") || o == "label=disable" || o == "label:disable":
			out = append(out, "confinement relaxed: "+o)
		}
	}
	if !noNewPrivs {
		out = append(out, "no-new-privileges is not set")
	}
	if !profile {
		out = append(out, "no audited seccomp profile is applied")
	}
	if !h.ReadonlyRootfs {
		out = append(out, "root filesystem is writable")
	}
	if h.NetworkMode != "none" {
		out = append(out, "network mode is "+strconv.Quote(h.NetworkMode)+", want none")
	}
	if !strings.HasPrefix(h.PidMode, "container:") {
		out = append(out, "PID namespace is "+strconv.Quote(h.PidMode)+", want the explicit container:<workload> the operator chose")
	}
	if h.CgroupnsMode != "host" {
		out = append(out, "cgroup namespace is "+strconv.Quote(h.CgroupnsMode)+": the helper identifies a target by its cgroup directory and only the host cgroup namespace shows it")
	}
	return out
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

// ---- the workload's ELF note ----

func noteDescriptor(b []byte) (string, error) {
	if len(b) < 16 {
		return "", errors.New("build ID note too short")
	}
	nameSize, descSize := binary.LittleEndian.Uint32(b), binary.LittleEndian.Uint32(b[4:])
	start := 12 + (uint64(nameSize)+3)&^3
	if descSize == 0 || start+uint64(descSize) > uint64(len(b)) {
		return "", errors.New("invalid build ID note bounds")
	}
	return hex.EncodeToString(b[start : start+uint64(descSize)]), nil
}

// sectionBuildID is the GNU build ID of the .note.gnu.build-id section.
func sectionBuildID(path string) (string, error) {
	f, err := elf.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	s := f.Section(".note.gnu.build-id")
	if s == nil {
		return "", errors.New("no .note.gnu.build-id section")
	}
	b, err := s.Data()
	if err != nil {
		return "", err
	}
	return noteDescriptor(b)
}

// elfNoteSegmentBuildID walks the PT_NOTE segments exactly as the helper does (internal/nativeperf executableBuildID):
// the build ID is found only if a note program header covers the GNU note.
func elfNoteSegmentBuildID(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if len(raw) < 64 || !bytes.Equal(raw[:4], []byte{0x7f, 'E', 'L', 'F'}) || raw[4] != 2 || raw[5] != 1 {
		return "", errors.New("not a little-endian ELF64")
	}
	order := binary.LittleEndian
	phoff, phnum, phsize := order.Uint64(raw[32:]), order.Uint16(raw[56:]), order.Uint16(raw[54:])
	if phsize != 56 {
		return "", errors.New("unexpected program header size")
	}
	for i := uint16(0); i < phnum; i++ {
		ph := raw[phoff+uint64(i)*56:]
		if order.Uint32(ph) != 4 {
			continue
		}
		start, length := order.Uint64(ph[8:]), order.Uint64(ph[32:])
		if start+length > uint64(len(raw)) {
			return "", errors.New("PT_NOTE outside the file")
		}
		b := raw[start : start+length]
		for len(b) >= 12 {
			n, d, typ := order.Uint32(b), order.Uint32(b[4:]), order.Uint32(b[8:])
			b = b[12:]
			nn, dd := (uint64(n)+3)&^3, (uint64(d)+3)&^3
			if nn+dd > uint64(len(b)) {
				return "", errors.New("invalid note")
			}
			if typ == 3 && bytes.Equal(bytes.TrimRight(b[:n], "\x00"), []byte("GNU")) && d > 0 && d <= 64 {
				return hex.EncodeToString(b[nn : nn+uint64(d)]), nil
			}
			b = b[nn+dd:]
		}
	}
	return "", errors.New("no GNU build ID inside any PT_NOTE segment")
}

// patchNoteSegment extends the PT_NOTE segment that ends where the .note.gnu.build-id section starts so that it covers
// that note. The Go linker places the note right after the Go build ID note but leaves the segment at the Go note's
// size, which hides the GNU build ID from every segment-based reader, the helper's included. A segment that already
// covers the note is left alone.
func patchNoteSegment(path string) error {
	f, err := elf.Open(path)
	if err != nil {
		return err
	}
	section := f.Section(".note.gnu.build-id")
	var phoff uint64
	var phsize uint16
	if section != nil {
		raw := make([]byte, 64)
		if file, e := os.Open(path); e == nil {
			_, _ = file.ReadAt(raw, 0)
			file.Close()
		}
		phoff, phsize = binary.LittleEndian.Uint64(raw[32:]), binary.LittleEndian.Uint16(raw[54:])
	}
	type note struct {
		index         int
		off, filesize uint64
	}
	var notes []note
	for i, p := range f.Progs {
		if p.Type == elf.PT_NOTE {
			notes = append(notes, note{i, p.Off, p.Filesz})
		}
	}
	f.Close()
	if section == nil {
		return errors.New("no .note.gnu.build-id section to expose")
	}
	if phsize != 56 {
		return errors.New("unexpected program header size")
	}
	for _, n := range notes {
		if n.off <= section.Offset && n.off+n.filesize >= section.Offset+section.Size {
			return nil // already covered
		}
	}
	for _, n := range notes {
		if n.off+n.filesize == section.Offset {
			file, err := os.OpenFile(path, os.O_RDWR, 0)
			if err != nil {
				return err
			}
			defer file.Close()
			var sizes [16]byte
			binary.LittleEndian.PutUint64(sizes[0:], n.filesize+section.Size)
			binary.LittleEndian.PutUint64(sizes[8:], n.filesize+section.Size)
			// p_filesz at +32, p_memsz at +40 of the ELF64 program header
			_, err = file.WriteAt(sizes[:], int64(phoff)+int64(n.index)*56+32)
			return err
		}
	}
	return errors.New("no PT_NOTE segment is adjacent to the GNU build ID note")
}

// ---- docker plumbing ----

func dockerCombined(timeout time.Duration, env []string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Env = append(os.Environ(), env...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	if err != nil {
		err = fmt.Errorf("docker %s: %w: %s", strings.Join(args[:min(len(args), 2)], " "), err, clip(strings.TrimSpace(out.String()), 600))
	}
	return out.String(), err
}

// importScratchImage makes an image of executables only (docker import: no base image is pulled).
func importScratchImage(name, entrypoint string, files map[string]string) error {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for target, source := range files {
		raw, err := os.ReadFile(source)
		if err != nil {
			return err
		}
		if err = tw.WriteHeader(&tar.Header{Name: target, Mode: 0o755, Size: int64(len(raw)), Typeflag: tar.TypeReg}); err != nil {
			return err
		}
		if _, err = tw.Write(raw); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	cmd := exec.Command("docker", "import", "-c", `ENTRYPOINT ["`+entrypoint+`"]`, "-", name)
	cmd.Stdin = &buf
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker import: %w: %s", err, clip(out.String(), 400))
	}
	return nil
}

func goToolchain() string {
	if p, err := exec.LookPath("go"); err == nil {
		return p
	}
	return filepath.Join(runtime.GOROOT(), "bin", "go")
}

// buildNativeHelperTools builds the in-container client and the workload (static, CGO off) and makes the workload's
// GNU build ID visible to segment readers.
func buildNativeHelperTools(root, dir string) (client, burner string, err error) {
	build := func(out string, flags []string, pkg string) error {
		args := append([]string{"build", "-trimpath"}, flags...)
		args = append(args, "-o", out, pkg)
		cmd := exec.Command(goToolchain(), args...)
		cmd.Dir = root
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOTOOLCHAIN=local")
		if raw, e := cmd.CombinedOutput(); e != nil {
			return fmt.Errorf("go build %s: %w: %s", pkg, e, clip(string(raw), 600))
		}
		return nil
	}
	client, burner = filepath.Join(dir, "client"), filepath.Join(dir, "burner")
	if err = build(client, nil, "./tools/smoke/nativehelper/client"); err != nil {
		return
	}
	if err = build(burner, []string{"-ldflags", "-B gobuildid"}, "./tools/smoke/nativehelper/burner"); err != nil {
		return
	}
	if err = patchNoteSegment(burner); err != nil {
		return
	}
	want, err := sectionBuildID(burner)
	if err != nil {
		return
	}
	got, err := elfNoteSegmentBuildID(burner)
	if err != nil || got != want {
		err = fmt.Errorf("the workload's build ID is still hidden from the helper's PT_NOTE walk (%q vs %q): %v", got, want, err)
	}
	return
}

// ---- the run ----

type nativeHelperOptions struct {
	Root        string // repository checkout: tools to build, compose file, seccomp profile
	HelperTar   string // the release's helper image (OCI archive from `go run ./build artifacts`)
	ArtifactDir string
	Seconds     int
}

type nativeCaseSpec struct {
	Name           string
	Perfmon        bool
	TargetUser     string
	OperatorPtrace bool // the operator-side client (never the helper) may read a target of another uid
}

type nativeCaseResult struct {
	Name            string         `json:"case"`
	Observed        string         `json:"observed"`
	Pass            bool           `json:"pass"`
	Why             string         `json:"why,omitempty"`
	Perfmon         bool           `json:"cap_perfmon"`
	TargetUser      string         `json:"target_user"`
	Capture         nativeCapture  `json:"capture"`
	HelperExit      int            `json:"helper_exit_code"`
	HelperLog       string         `json:"helper_log,omitempty"`
	ConfigProblems  []string       `json:"config_problems,omitempty"`
	ResolvedService map[string]any `json:"resolved_helper_service,omitempty"`
}

// nativeProfileInstallRow is the fresh-install matrix row native_profile_install. facts is injected so the row logic is
// testable without a runtime.
func nativeProfileInstallRow(o nativeHelperOptions, f nativeHostFacts) (string, error) {
	if reason := nativeHelperPrerequisite(f); reason != "" {
		return "", notRun(reason)
	}
	if o.Seconds <= 0 {
		o.Seconds = 5
	}
	o.Root, _ = filepath.Abs(o.Root)
	o.HelperTar, _ = filepath.Abs(o.HelperTar)
	o.ArtifactDir, _ = filepath.Abs(o.ArtifactDir)
	if _, err := os.Stat(o.HelperTar); err != nil {
		return "", fmt.Errorf("helper image archive: %w", err)
	}
	if err := os.MkdirAll(o.ArtifactDir, 0o700); err != nil {
		return "", err
	}
	run := &nativeRun{o: o, facts: f, suffix: strconv.FormatInt(time.Now().UnixNano()%1_000_000_000_000, 36)}
	defer run.cleanup()
	return run.execute()
}

type nativeRun struct {
	o      nativeHelperOptions
	facts  nativeHostFacts
	suffix string
	work   string

	containers, images, composeProjects []string
	composeEnv                          map[string][]string
}

func (r *nativeRun) name(kind string) string { return "soundpost-nh-" + r.suffix + "-" + kind }

func (r *nativeRun) cleanup() {
	for _, p := range r.composeProjects {
		_, _ = dockerCombined(60*time.Second, r.composeEnv[p], "compose", "-p", p, "down", "--volumes", "--remove-orphans", "--timeout", "5")
	}
	for _, c := range r.containers {
		_, _ = dockerCombined(30*time.Second, nil, "rm", "-f", c)
	}
	if r.work != "" {
		// the files the root-in-container steps made are root-owned: remove them the same way
		if r.hasClient() {
			_, _ = dockerCombined(60*time.Second, nil, "run", "--rm", "--network", "none", "-v", r.work+":/w", "--entrypoint", "/client", r.name("client"), "remove", "--dir", "/w")
		}
		os.RemoveAll(r.work)
	}
	for _, i := range r.images {
		_, _ = dockerCombined(60*time.Second, nil, "rmi", "-f", i)
	}
}

func (r *nativeRun) hasClient() bool {
	for _, i := range r.images {
		if i == r.name("client") {
			return true
		}
	}
	return false
}

func (r *nativeRun) execute() (string, error) {
	var err error
	if r.work, err = os.MkdirTemp("", "soundpost-nh-"); err != nil {
		return "", err
	}
	if err = os.Chmod(r.work, 0o755); err != nil {
		return "", err
	}
	report := map[string]any{"version": 1, "host": map[string]any{
		"kernel": r.facts.Kernel, "perf_event_paranoid": r.facts.Paranoid, "docker_server": r.facts.DockerServer, "docker_compose": r.facts.ComposeVer,
		"cgroup_v2": r.facts.CgroupV2, "apparmor_enabled": strings.TrimSpace(readSmallFile("/sys/module/apparmor/parameters/enabled")),
		"lsm": strings.TrimSpace(readSmallFile("/sys/kernel/security/lsm")), "yama_ptrace_scope": strings.TrimSpace(readSmallFile("/proc/sys/kernel/yama/ptrace_scope")),
		"sysctl_rewritten_by_this_run": false}}
	write := func() {
		encoded, _ := json.MarshalIndent(report, "", "  ")
		_ = os.WriteFile(filepath.Join(r.o.ArtifactDir, "native-helper-container.json"), encoded, 0o600)
	}
	defer write()

	client, burner, err := buildNativeHelperTools(r.o.Root, r.work)
	if err != nil {
		return "", err
	}
	// the helper image of the release
	helperImage := r.name("helper") + ":latest"
	r.images = append(r.images, helperImage)
	_, loadedTags, _ := ociArchiveImage(r.o.HelperTar)
	r.images = append(r.images, loadedTags...)
	if _, err = loadOCIImage(r.o.HelperTar, helperImage); err != nil {
		return "", err
	}
	meta, err := dockerCombined(30*time.Second, nil, "image", "inspect", "--format", "{{.Id}}|{{json .Config.Entrypoint}}|{{.Config.User}}|{{index .Config.Labels \"org.soundpost.binary.sha256\"}}", helperImage)
	if err != nil {
		return "", err
	}
	parts := strings.Split(strings.TrimSpace(meta), "|")
	if len(parts) != 4 || parts[1] != `["/soundpost-perf-acquire"]` || parts[2] != "0:0" {
		return "", fmt.Errorf("the loaded helper image is not the shipped helper (entrypoint/user): %s", strings.TrimSpace(meta))
	}
	report["helper_image"] = map[string]any{"archive": filepath.Base(r.o.HelperTar), "image_id": parts[0], "entrypoint": parts[1], "user": parts[2], "binary_sha256_label": parts[3]}

	clientImage := r.name("client")
	if err = importScratchImage(clientImage, "/client", map[string]string{"client": client, "burner": burner}); err != nil {
		return "", err
	}
	r.images = append(r.images, clientImage)

	specs := []nativeCaseSpec{
		{Name: caseComposedPerfmon, Perfmon: true, TargetUser: "0:0"},
		{Name: caseWithoutPerfmon, Perfmon: false, TargetUser: "0:0"},
		{Name: caseTargetNotVisible, Perfmon: true, TargetUser: "65532:65532", OperatorPtrace: true},
	}
	var results []nativeCaseResult
	var failures []string
	report["cases"] = &results
	for _, spec := range specs {
		res, err := r.runCase(spec, helperImage, clientImage)
		if err != nil {
			return "", fmt.Errorf("case %s: %w", spec.Name, err)
		}
		results = append(results, res)
		report["cases"] = results
		if !res.Pass {
			failures = append(failures, spec.Name+": "+res.Why)
		}
	}
	if len(failures) > 0 {
		return "", errors.New("native helper container: " + strings.Join(failures, "; "))
	}
	summary := ""
	for _, c := range results {
		summary += fmt.Sprintf("%s=%s ", c.Name, c.Observed)
	}
	host := fmt.Sprintf("kernel %s, perf_event_paranoid=%d, docker %s, compose %s", r.facts.Kernel, r.facts.Paranoid, r.facts.DockerServer, r.facts.ComposeVer)
	if r.facts.Paranoid >= 3 {
		report["positive_capture_exercised"] = false
		return "", notRun(fmt.Sprintf("perf_event_paranoid=%d (Debian-style) forbids perf_event_open without CAP_SYS_ADMIN, so a CAP_PERFMON-only helper is typed denied here and no real sample can be collected; the denial itself was observed (%s; %s). The documented operator setup needs a host whose paranoid level is <= 2 (this run never rewrites the sysctl)", r.facts.Paranoid, strings.TrimSpace(summary), host))
	}
	report["positive_capture_exercised"] = true
	first := results[0].Capture
	return fmt.Sprintf("the release helper image, started by deploy/compose.distributed.yaml's native profile (uid 0, only CAP_PERFMON, audited seccomp, no network, read-only root, host cgroup namespace), captured %d real software CPU-clock samples in %.1fs of a CPU-burning container, %d resolved to %s; observed per case: %s; %s", first.Samples, first.CaptureSeconds, first.HotSymbolSamples, first.HotSymbol, strings.TrimSpace(summary), host), nil
}

func readSmallFile(path string) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return clip(string(raw), 200)
}

// runCase starts the workload container, writes the operator policy for it, starts the shipped helper service and
// asks it for a capture.
func (r *nativeRun) runCase(spec nativeCaseSpec, helperImage, clientImage string) (nativeCaseResult, error) {
	res := nativeCaseResult{Name: spec.Name, Perfmon: spec.Perfmon, TargetUser: spec.TargetUser}
	caseDir := filepath.Join(r.work, spec.Name)
	runDir, polDir := filepath.Join(caseDir, "run"), filepath.Join(caseDir, "pol")
	for _, d := range []string{caseDir, runDir, polDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return res, err
		}
	}
	burner := r.name(spec.Name + "-target")
	r.containers = append(r.containers, burner)
	if _, err := dockerCombined(60*time.Second, nil, "run", "-d", "--name", burner, "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
		"--user", spec.TargetUser, "--entrypoint", "/burner", clientImage); err != nil {
		return res, err
	}
	ready := false
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(300 * time.Millisecond) {
		if out, _ := dockerCombined(10*time.Second, nil, "logs", burner); strings.Contains(out, "ready") {
			ready = true
			break
		}
	}
	if !ready {
		return res, errors.New("the workload container never printed ready")
	}
	clientRun := func(extra []string, mounts []string, args ...string) (string, error) {
		a := []string{"run", "--rm", "--network", "none"}
		a = append(a, extra...)
		a = append(a, mounts...)
		a = append(a, "--entrypoint", "/client", clientImage)
		return dockerCombined(2*time.Minute, nil, append(a, args...)...)
	}
	// the operator side: a root-owned 0700 socket directory and the root-owned policy naming exactly this target
	if _, err := clientRun(nil, []string{"-v", runDir + ":/run/soundpost-perf"}, "prepare"); err != nil {
		return res, err
	}
	operator := []string{"--pid", "container:" + burner, "--cgroupns", "host"}
	if spec.OperatorPtrace {
		operator = append(operator, "--cap-add", "SYS_PTRACE")
	}
	if _, err := clientRun(operator, []string{"-v", polDir + ":/policy"}, "policy", "--pid", "1", "--binary", "/burner", "--out", "/policy"); err != nil {
		return res, err
	}

	// the shipped service, by Docker Compose
	project := "slnh" + r.suffix + spec.Name[:2]
	composeFile, err := r.composeFileFor(spec, caseDir)
	if err != nil {
		return res, err
	}
	vol := func(s string) string { return "soundpost-nh-" + r.suffix + "-" + spec.Name[:2] + "-" + s }
	env := []string{
		"SOUNDPOST_IMAGE=unused-by-the-native-profile",
		"SOUNDPOST_PERF_HELPER_IMAGE=" + helperImage,
		"SOUNDPOST_PERF_PID=container:" + burner,
		"SOUNDPOST_PERF_POLICY=" + filepath.Join(polDir, "perf-policy.json"),
		"SOUNDPOST_PERF_SECCOMP=" + filepath.Join(r.o.Root, "deploy", "seccomp", "soundpost-perf.json"),
		"SOUNDPOST_PERF_RUN=" + runDir,
		"SOUNDPOST_VOLUME_A=" + vol("a"), "SOUNDPOST_VOLUME_B=" + vol("b"), "SOUNDPOST_VOLUME_C=" + vol("c"),
		"SOUNDPOST_VOLUME_CONFIG_A=" + vol("ca"), "SOUNDPOST_VOLUME_CONFIG_B=" + vol("cb"), "SOUNDPOST_VOLUME_CONFIG_C=" + vol("cc"),
	}
	if r.composeEnv == nil {
		r.composeEnv = map[string][]string{}
	}
	r.composeEnv[project] = env
	r.composeProjects = append(r.composeProjects, project)
	compose := func(args ...string) (string, error) {
		return dockerCombined(3*time.Minute, env, append([]string{"compose", "-f", composeFile, "-p", project, "--profile", "native"}, args...)...)
	}
	if _, err = compose("up", "-d", "--no-deps", "--no-build", "--pull", "never", "soundpost-perf-helper"); err != nil {
		return res, err
	}
	id, err := compose("ps", "-q", "soundpost-perf-helper")
	if err != nil {
		return res, err
	}
	helper := strings.TrimSpace(id)
	if helper == "" {
		return res, errors.New("compose started no helper container")
	}
	r.containers = append(r.containers, helper)
	time.Sleep(2 * time.Second)
	if state, _ := dockerCombined(10*time.Second, nil, "inspect", "--format", "{{.State.Running}}", helper); strings.TrimSpace(state) != "true" {
		logs, _ := dockerCombined(10*time.Second, nil, "logs", helper)
		res.HelperLog = clip(strings.TrimSpace(logs), 600)
		return res, fmt.Errorf("the helper container is not running two seconds after start: %s", res.HelperLog)
	}
	inspect, err := dockerCombined(10*time.Second, nil, "inspect", helper)
	if err != nil {
		return res, err
	}
	res.ConfigProblems = helperContainerConfigProblems([]byte(inspect), spec.Perfmon)

	captureArgs := []string{"--pid", "container:" + helper, "--cgroupns", "host"}
	if spec.OperatorPtrace {
		captureArgs = append(captureArgs, "--cap-add", "SYS_PTRACE")
	}
	out, err := clientRun(captureArgs, []string{"-v", runDir + ":/run/soundpost-perf"}, "capture", "--pid", "1", "--binary", "/burner", "--seconds", strconv.Itoa(r.o.Seconds))
	if err != nil {
		return res, err
	}
	line := ""
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "{") {
			line = strings.TrimSpace(l)
		}
	}
	if err = json.Unmarshal([]byte(line), &res.Capture); err != nil {
		return res, fmt.Errorf("the client printed no result: %s", clip(out, 400))
	}
	res.Observed, res.Pass, res.Why = judgeNativeCase(spec.Name, r.facts.Paranoid, res.Capture)

	// orderly end of the service: SIGTERM, exit 0
	if _, err = compose("stop", "--timeout", "10", "soundpost-perf-helper"); err != nil {
		return res, err
	}
	code, _ := dockerCombined(10*time.Second, nil, "inspect", "--format", "{{.State.ExitCode}}", helper)
	res.HelperExit, _ = strconv.Atoi(strings.TrimSpace(code))
	logs, _ := dockerCombined(10*time.Second, nil, "logs", helper)
	res.HelperLog = clip(strings.TrimSpace(logs), 600)
	if len(res.ConfigProblems) > 0 {
		res.Pass = false
		res.Why = strings.TrimSpace(res.Why + "; the helper container's applied configuration is wrong: " + strings.Join(res.ConfigProblems, "; "))
	}
	if res.HelperExit != 0 {
		res.Pass = false
		res.Why = strings.TrimSpace(res.Why + fmt.Sprintf("; the helper did not exit 0 on SIGTERM (exit %d): %s", res.HelperExit, res.HelperLog))
	}
	if resolved, err := compose("config", "--format", "json"); err == nil {
		var doc struct {
			Services map[string]map[string]any `json:"services"`
		}
		if json.Unmarshal([]byte(resolved), &doc) == nil {
			res.ResolvedService = doc.Services["soundpost-perf-helper"]
		}
	}
	return res, nil
}

// composeFileFor returns the compose file to run: the shipped file, or for the PERFMON-less control the shipped file
// with exactly the helper's cap_add removed.
func (r *nativeRun) composeFileFor(spec nativeCaseSpec, dir string) (string, error) {
	shipped := filepath.Join(r.o.Root, "deploy", "compose.distributed.yaml")
	if spec.Perfmon {
		return shipped, nil
	}
	raw, err := os.ReadFile(shipped)
	if err != nil {
		return "", err
	}
	var doc map[string]any
	if err = yaml.Unmarshal(raw, &doc); err != nil {
		return "", err
	}
	services, _ := doc["services"].(map[string]any)
	helper, _ := services["soundpost-perf-helper"].(map[string]any)
	if helper == nil || helper["cap_add"] == nil {
		return "", errors.New("deploy/compose.distributed.yaml has no soundpost-perf-helper cap_add to remove")
	}
	delete(helper, "cap_add")
	out, err := yaml.Marshal(doc)
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, "compose.without-perfmon.yaml")
	return path, os.WriteFile(path, out, 0o644)
}
