// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package qualify

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/elf"
	"debug/pe"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
)

// runCtx is the shared state of one RunSuite invocation.
type runCtx struct {
	ctx       context.Context
	root      string
	reportDir string
	work      string
	matrix    Matrix
	workloads Workloads
	host      HostInfo
	probes    map[string]*probeResult
	cache     map[string]any
}

// probeResult is the outcome of looking for one build on this host.
type probeResult struct {
	Found  bool
	Build  Build
	Path   string
	Reason string
}

var runners = map[string]runner{
	"build_probe":              runBuildProbe,
	"sdk_profile":              runSDKProfile,
	"unmeasured":               runUnmeasured,
	"native_capability":        runNativeCapability,
	"native_identity":          runNativeIdentity,
	"native_gap":               runNativeGap,
	"native_controls":          runNativeControls,
	"playwright_test":          runPlaywrightTest,
	"privacy_scanner_controls": runPrivacyScannerControls,
	"privacy_native":           runPrivacyNative,
	"overhead_sdk_server":      runOverheadSDKServer,
	"overhead_sdk_queue":       runOverheadSDKQueue,
	"overhead_bundle":          runOverheadBundle,
	"overhead_native":          runOverheadNative,
}

// subject is what the row claims to qualify, taken from its build or inline.
func (rc *runCtx) subject(spec RowSpec) Subject {
	if spec.Subject != nil {
		return *spec.Subject
	}
	b := rc.matrix.Builds[spec.Build]
	return Subject{Family: b.Family, Version: b.Version, OS: b.OS, Arch: b.Arch}
}

func notExercised(reason string) Row { return Row{State: StateNotExercised, Reason: reason} }

// runUnmeasured is a row whose harness does not exist in the repository.
func runUnmeasured(rc *runCtx, spec RowSpec) Row {
	reason := spec.Params["reason"]
	if reason == "" {
		reason = "no committed harness measures this row"
	}
	return notExercised(reason)
}

// binaryTarget reads the real object header: the operating system and
// architecture a file was built for, independent of its name.
func binaryTarget(path string) (osName, arch string, ok bool) {
	if f, err := elf.Open(path); err == nil {
		defer f.Close()
		switch f.Machine {
		case elf.EM_X86_64:
			return "linux", "amd64", true
		case elf.EM_AARCH64:
			return "linux", "arm64", true
		}
		return "linux", f.Machine.String(), true
	}
	if f, err := pe.Open(path); err == nil {
		defer f.Close()
		switch f.Machine {
		case pe.IMAGE_FILE_MACHINE_AMD64:
			return "windows", "amd64", true
		case pe.IMAGE_FILE_MACHINE_ARM64:
			return "windows", "arm64", true
		}
		return "windows", fmt.Sprintf("machine_%#x", f.Machine), true
	}
	return "", "", false
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// canExecute says whether this host can run a build of the given platform: its
// own, or a Windows build through WSL interop. An arm64 build never runs on
// amd64 here and is never substituted.
func (rc *runCtx) canExecute(osName, arch string) bool {
	if osName == runtime.GOOS && arch == runtime.GOARCH {
		return true
	}
	return osName == "windows" && runtime.GOOS == "linux" && arch == runtime.GOARCH && rc.host.Class == "wsl2"
}

func (rc *runCtx) candidates(b BuildSpec) []string {
	var out []string
	if b.Env != "" {
		if v := os.Getenv(b.Env); v != "" {
			out = append(out, v)
		}
	}
	for _, c := range b.Candidates {
		switch {
		case !strings.ContainsAny(c, `/\`):
			if p, err := exec.LookPath(c); err == nil {
				out = append(out, p)
			}
		default:
			out = append(out, filepath.Join(rc.root, filepath.FromSlash(c)))
			if tr := os.Getenv("SOUNDPOST_TOOLS_ROOT"); tr != "" {
				out = append(out, filepath.Join(tr, filepath.FromSlash(c)))
			}
		}
	}
	return out
}

// probe looks for the exact build a spec names. The first candidate whose object
// header, version output and platform all match wins; otherwise the build is
// absent with a stated reason.
func (rc *runCtx) probe(key string) *probeResult {
	if p, ok := rc.probes[key]; ok {
		return p
	}
	spec := rc.matrix.Builds[key]
	res := &probeResult{Reason: spec.Absent}
	rc.probes[key] = res
	var notes []string
	for _, cand := range rc.candidates(spec) {
		st, err := os.Stat(cand)
		if err != nil || st.IsDir() {
			continue
		}
		osName, arch, ok := binaryTarget(cand)
		if !ok {
			notes = append(notes, "candidate is not a native executable")
			continue
		}
		if osName != spec.OS || arch != spec.Arch {
			notes = append(notes, fmt.Sprintf("candidate is %s/%s, row needs %s/%s", osName, arch, spec.OS, spec.Arch))
			continue
		}
		if !rc.canExecute(osName, arch) {
			notes = append(notes, fmt.Sprintf("this host (%s/%s) cannot execute a %s/%s build", runtime.GOOS, runtime.GOARCH, osName, arch))
			continue
		}
		args := spec.VersionArgs
		if len(args) == 0 {
			args = []string{"--version"}
		}
		out := rc.exec(60*time.Second, rc.root, nil, cand, args...)
		text := strings.TrimSpace(out.Stdout + "\n" + out.Stderr)
		version := strings.TrimSpace(strings.SplitN(text, "\n", 2)[0])
		if spec.VersionRegex != "" {
			m := regexp.MustCompile(spec.VersionRegex).FindStringSubmatch(text)
			if m == nil {
				notes = append(notes, "candidate version output does not match the pinned pattern")
				continue
			}
			version = m[len(m)-1]
		}
		if !versionMatches(version, spec.Version) {
			notes = append(notes, fmt.Sprintf("candidate is version %s, row needs %s", version, spec.Version))
			continue
		}
		sum, err := sha256File(cand)
		if err != nil {
			continue
		}
		host := "native"
		if osName != runtime.GOOS {
			host = "wsl_interop"
		}
		res.Found, res.Path, res.Reason = true, cand, ""
		res.Build = Build{Family: spec.Family, Version: version, OS: osName, Arch: arch, ID: "sha256:" + sum, SHA256: sum, Host: host}
		return res
	}
	if len(notes) > 0 {
		res.Reason = spec.Absent + " (rejected candidates: " + strings.Join(dedupe(notes), "; ") + ")"
	}
	return res
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// needsMissing returns the reason a row's prerequisite builds are not all present.
func (rc *runCtx) needsMissing(spec RowSpec) string {
	for _, need := range spec.Needs {
		if p := rc.probe(need); !p.Found {
			return fmt.Sprintf("prerequisite build %s absent: %s", need, p.Reason)
		}
	}
	return ""
}

type execResult struct {
	Stdout, Stderr string
	Exit           int
	Duration       time.Duration
	Err            error
}

type cappedBuffer struct {
	buf bytes.Buffer
	max int
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if room := c.max - c.buf.Len(); room > 0 {
		c.buf.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

// exec runs one process with a deadline and keeps its real exit code.
func (rc *runCtx) exec(timeout time.Duration, dir string, env []string, name string, args ...string) execResult {
	ctx, cancel := context.WithTimeout(rc.ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	cmd.WaitDelay = 5 * time.Second
	stdout, stderr := &cappedBuffer{max: 32 << 20}, &cappedBuffer{max: 4 << 20}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	start := time.Now()
	err := cmd.Run()
	res := execResult{Stdout: stdout.buf.String(), Stderr: stderr.buf.String(), Duration: time.Since(start)}
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			res.Exit = ee.ExitCode()
		} else {
			res.Exit, res.Err = -1, err
		}
		if ctx.Err() != nil {
			res.Exit, res.Err = -1, ctx.Err()
		}
	}
	return res
}

// nativePath converts a host path for a Windows build launched through WSL.
func (rc *runCtx) nativePath(osName, p string) string {
	if osName == "windows" && runtime.GOOS == "linux" {
		if out := rc.exec(10*time.Second, rc.root, nil, "wslpath", "-w", p); out.Exit == 0 {
			return strings.TrimSpace(out.Stdout)
		}
	}
	return p
}

// rel makes a path or text safe for a report: no repository root, no home directory.
func (rc *runCtx) rel(s string) string {
	s = strings.ReplaceAll(s, rc.root, "<repo>")
	if r := os.Getenv("SOUNDPOST_TOOLS_ROOT"); r != "" {
		s = strings.ReplaceAll(s, r, "<tools>")
	}
	if h, err := os.UserHomeDir(); err == nil && h != "" {
		s = strings.ReplaceAll(s, h, "<home>")
	}
	return s
}

func tail(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		s = s[len(s)-n:]
	}
	return strings.ReplaceAll(s, "\n", " | ")
}

// writeEvidence stores a raw safe artifact under the report directory.
func (rc *runCtx) writeEvidence(name string, data []byte) string {
	rel := filepath.ToSlash(filepath.Join("evidence", name))
	_ = os.WriteFile(filepath.Join(rc.reportDir, "evidence", name), data, 0o644)
	return rel
}

// lastJSONObject returns the last stdout line that is a JSON object.
func lastJSONObject(out string) (map[string]any, []byte) {
	lines := strings.Split(out, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if i := strings.Index(line, "{"); i >= 0 {
			line = line[i:]
		}
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) == nil {
			return m, []byte(line)
		}
	}
	return nil, nil
}

// harvest pulls the measured numbers out of a fixture's evidence object: every
// sample_count as a series point, the requested/achieved interval pairs and the
// loss and coverage declarations. Only numbers and closed vocabulary words.
func harvest(path string, v any, series *[]Series, iv *IntervalReport, loss *[]string) {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		if req, ok := t["requested_us"].(float64); ok {
			if got, ok := firstNumber(t, "achieved_us", "achieved_mean_us"); ok && iv.RequestedUS == nil {
				iv.RequestedUS, iv.ObservedUS = &req, &got
				iv.Note = "first requested/observed pair at " + path
			}
		}
		for _, k := range keys {
			child := path + "." + k
			switch k {
			case "sample_count", "samples", "event_rows", "frame_count":
				if n, ok := t[k].(float64); ok && len(*series) < 48 {
					*series = append(*series, Series{Name: strings.TrimPrefix(child, "."), Unit: "count", Values: []float64{n}})
				}
			case "losses":
				if arr, ok := t[k].([]any); ok {
					for _, e := range arr {
						if m, ok := e.(map[string]any); ok {
							*loss = append(*loss, fmt.Sprintf("%s: %v=%v", strings.TrimPrefix(path, "."), m["reason"], m["count"]))
						}
					}
				}
			case "coverage":
				if m, ok := t[k].(map[string]any); ok {
					parts := make([]string, 0, len(m))
					for ck, cv := range m {
						parts = append(parts, fmt.Sprintf("%s=%v", ck, cv))
					}
					sort.Strings(parts)
					*loss = append(*loss, fmt.Sprintf("%s coverage: %s", strings.TrimPrefix(path, "."), strings.Join(parts, ",")))
				}
			}
			harvest(child, t[k], series, iv, loss)
		}
	case []any:
		for i, e := range t {
			if i >= 8 {
				break
			}
			harvest(fmt.Sprintf("%s[%d]", path, i), e, series, iv, loss)
		}
	}
}

func firstNumber(m map[string]any, keys ...string) (float64, bool) {
	for _, k := range keys {
		if v, ok := m[k].(float64); ok {
			return v, true
		}
	}
	return 0, false
}

// runSDKProfile runs one committed SDK profile fixture (03.09) with the exact
// build the row names, keeps its own exit code and harvests its evidence.
func runSDKProfile(rc *runCtx, spec RowSpec) Row {
	p := rc.probe(spec.Build)
	if !p.Found {
		return notExercised(p.Reason)
	}
	if why := rc.needsMissing(spec); why != "" {
		return notExercised(why)
	}
	fixture := spec.Params["fixture"]
	var env []string
	for _, need := range spec.Needs {
		if nb := rc.probe(need); nb.Build.Family == "bun" {
			env = append(env, "SOUNDPOST_BUN="+rc.nativePath(nb.Build.OS, nb.Path))
		}
	}
	timeout := 10 * time.Minute
	res := rc.exec(timeout, rc.root, env, p.Path, fixture)
	row := Row{State: StateExercised, Build: &p.Build, Command: &CommandRun{
		Command: rc.rel(filepath.Base(p.Path) + " " + fixture), ExitCode: res.Exit, DurationMS: res.Duration.Milliseconds()}}
	if obj, raw := lastJSONObject(res.Stdout); obj != nil {
		row.Evidence = append(row.Evidence, rc.writeEvidence(spec.ID+".json", raw))
		var series []Series
		var iv IntervalReport
		var loss []string
		harvest("", obj, &series, &iv, &loss)
		row.Series = series
		if iv.RequestedUS != nil {
			row.Interval = &iv
		}
		row.Loss = strings.Join(loss, "; ")
	}
	row.Evidence = append(row.Evidence, "fixture exit code and stderr tail recorded in the row")
	row.Limits = []string{"the fixture's own assertions decide the outcome; no budget applies to this row"}
	if res.Exit == 0 && res.Err == nil {
		row.Outcome = OutcomePassed
	} else {
		row.Outcome = OutcomeFailed
		why := tail(rc.rel(res.Stderr), 240)
		if res.Err != nil {
			why = res.Err.Error()
		}
		row.Failures = []string{fmt.Sprintf("fixture %s exited %d: %s", fixture, res.Exit, why)}
	}
	return row
}
