// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package qualify

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"soundpost/fixtures/nativeperf/privacy/scan"
)

// Names of the inspected surfaces.
const (
	SurfaceNetwork       = "network"
	SurfaceRecorderQueue = "recorder_queue"
	SurfaceExportQueue   = "export_queue"
	SurfaceStoredRecords = "stored_records"
	SurfaceDiagnostics   = "diagnostics"
)

// DefaultRequiredSurfaces must be observed and non-empty for a verdict: a
// scrubbed network alone says nothing about what the queues and stores hold.
var DefaultRequiredSurfaces = []string{SurfaceNetwork, SurfaceRecorderQueue, SurfaceExportQueue, SurfaceStoredRecords}

// AllowedSampleTypes is the closed perf sample_type allowlist of the native
// helper (04.08 policy: CPU = IP|TID|TIME|CALLCHAIN|CPU|PERIOD, scheduler adds
// RAW). Anything else, in particular STACK_USER, REGS_USER, REGS_INTR, DATA and
// BRANCH_STACK, would copy user memory or registers out of the target.
var AllowedSampleTypes = map[string]bool{"IP": true, "TID": true, "TIME": true, "CALLCHAIN": true, "CPU": true, "PERIOD": true, "RAW": true}

// Surface is one place bytes were observed: the network, the recorder queue,
// the export queue, stored and exported records, diagnostics.
type Surface struct {
	Name string
	Data []byte
}

// Finding names where a canary was found, never the surrounding bytes.
type Finding struct {
	Surface  string `json:"surface"`
	Canary   string `json:"canary"`
	Encoding string `json:"encoding"`
	Offset   int    `json:"offset"`
}

// NativeConfig is the perf attribute configuration the native helper opened.
type NativeConfig struct {
	SampleType []string
}

// PrivacyCase is one inspection. Canaries are literal secrets; Detector, when
// set, adds the 04.08 per-run sentinel matcher over the same surfaces.
type PrivacyCase struct {
	Canaries []string
	Detector *scan.Detector
	Surfaces []Surface
	// Required overrides DefaultRequiredSurfaces.
	Required []string
	// Native is the opened capture configuration. It must be inspected unless
	// NativeNotApplicable says this case has no native capture at all.
	Native              *NativeConfig
	NativeNotApplicable bool
}

// PrivacyVerdict is the result of InspectPrivacy.
type PrivacyVerdict struct {
	Pass     bool      `json:"pass"`
	Findings []Finding `json:"findings,omitempty"`
	Problems []string  `json:"problems,omitempty"`
	Surfaces []string  `json:"inspected_surfaces"`
	Bytes    int       `json:"inspected_bytes"`
}

// maxInflated bounds a decompressed surface so a hostile stream cannot exhaust memory.
const maxInflated = 64 << 20

func canaryDetector(canaries []string) (*scan.Detector, error) {
	p := scan.Policy{SentinelPattern: "%s%s"}
	for i, c := range canaries {
		if c == "" {
			return nil, errors.New("empty canary")
		}
		p.Kinds = append(p.Kinds, scan.Kind{ID: fmt.Sprintf("canary_%d", i), Token: c})
	}
	return scan.NewDetector(p, "")
}

// views returns the bytes of a surface plus, for gzip members, their inflated
// form: the wire is compressed but the secret is not.
func views(b []byte) [][]byte {
	out := [][]byte{b}
	magic := []byte{0x1f, 0x8b, 0x08}
	attempts := 0
	for off := 0; off+len(magic) <= len(b) && attempts < 16; {
		i := bytes.Index(b[off:], magic)
		if i < 0 {
			break
		}
		attempts++
		if zr, err := gzip.NewReader(bytes.NewReader(b[off+i:])); err == nil {
			if inflated, err := io.ReadAll(io.LimitReader(zr, maxInflated)); err == nil || len(inflated) > 0 {
				out = append(out, inflated)
			}
		}
		off += i + len(magic)
	}
	return out
}

// InspectPrivacy inspects every surface for every canary (raw, case-folded,
// reversed, hex, base64 at every alignment, UTF-16, packed words, gzip) and the
// native capture configuration. Blind inspection is a failure: a required
// surface that is absent or empty, or a native configuration that was not
// inspected, cannot be reported as clean.
func InspectPrivacy(c PrivacyCase) PrivacyVerdict {
	v := PrivacyVerdict{Surfaces: []string{}}
	det := c.Detector
	if len(c.Canaries) > 0 {
		d, err := canaryDetector(c.Canaries)
		if err != nil {
			v.Problems = append(v.Problems, "canary matcher: "+err.Error())
		} else {
			det = d
		}
	}
	if det == nil {
		v.Problems = append(v.Problems, "no canary or detector supplied: nothing was inspected")
	}
	seen := map[string]int{}
	seenFinding := map[string]bool{}
	for _, s := range c.Surfaces {
		seen[s.Name] += len(s.Data)
		v.Surfaces = append(v.Surfaces, s.Name)
		v.Bytes += len(s.Data)
		if det == nil {
			continue
		}
		for _, view := range views(s.Data) {
			for _, h := range det.Scan(view) {
				key := s.Name + "/" + h.Kind
				if seenFinding[key] {
					continue
				}
				seenFinding[key] = true
				v.Findings = append(v.Findings, Finding{Surface: s.Name, Canary: h.Kind, Encoding: h.Encoding, Offset: h.Offset})
			}
		}
	}
	required := c.Required
	if len(required) == 0 {
		required = DefaultRequiredSurfaces
	}
	for _, name := range required {
		n, ok := seen[name]
		switch {
		case !ok:
			v.Problems = append(v.Problems, "required surface not observed: "+name)
		case n == 0:
			v.Problems = append(v.Problems, "required surface empty, so it was not actually inspected: "+name)
		}
	}
	switch {
	case c.NativeNotApplicable:
	case c.Native == nil || len(c.Native.SampleType) == 0:
		v.Problems = append(v.Problems, "native capture configuration not inspected")
	default:
		for _, t := range c.Native.SampleType {
			if !AllowedSampleTypes[strings.ToUpper(t)] {
				v.Problems = append(v.Problems, "capture configuration requests "+t+" (outside the no-stack-byte allowlist)")
			}
		}
	}
	v.Pass = len(v.Findings) == 0 && len(v.Problems) == 0
	return v
}

// ControlResult is one permanent negative control.
type ControlResult struct {
	Name     string `json:"name"`
	Rejected bool   `json:"rejected"`
	Detail   string `json:"detail,omitempty"`
}

// NegativeControls contaminates a clean case in each way a prebuffer or
// native leak can hide and reports whether InspectPrivacy rejected every one.
// A scanner that accepts any of them is broken and its clean verdicts mean
// nothing; the privacy suite refuses to trust the real run in that case.
func NegativeControls(clean PrivacyCase, secret string) []ControlResult {
	return NegativeControlsWith(InspectPrivacy, clean, secret)
}

// Inspector is the scanner under control; production code uses InspectPrivacy.
type Inspector func(PrivacyCase) PrivacyVerdict

// NegativeControlsWith runs the contaminated variants through inspect.
func NegativeControlsWith(inspect Inspector, clean PrivacyCase, secret string) []ControlResult {
	contaminate := func(surface string) PrivacyCase {
		c := clean
		c.Surfaces = append([]Surface(nil), clean.Surfaces...)
		hit := false
		for i := range c.Surfaces {
			if c.Surfaces[i].Name == surface {
				c.Surfaces[i].Data = append(append([]byte(nil), c.Surfaces[i].Data...), []byte(" "+secret+" ")...)
				hit = true
			}
		}
		if !hit {
			c.Surfaces = append(c.Surfaces, Surface{Name: surface, Data: []byte(secret)})
		}
		c.Canaries = append(append([]string(nil), clean.Canaries...), secret)
		return c
	}
	var out []ControlResult
	run := func(name string, c PrivacyCase, want string) {
		v := inspect(c)
		r := ControlResult{Name: name, Rejected: !v.Pass}
		if v.Pass {
			r.Detail = "contaminated variant was accepted"
		} else if want != "" {
			joined := strings.Join(v.Problems, ";")
			for _, f := range v.Findings {
				joined += ";" + f.Surface
			}
			if !strings.Contains(joined, want) {
				r.Rejected, r.Detail = false, "rejected for the wrong reason"
			}
		}
		out = append(out, r)
	}
	for _, surface := range []string{SurfaceRecorderQueue, SurfaceExportQueue, SurfaceStoredRecords, SurfaceDiagnostics} {
		run("canary_in_"+surface+"_with_scrubbed_network", contaminate(surface), surface)
	}
	stack := clean
	stack.NativeNotApplicable = false
	stack.Native = &NativeConfig{SampleType: []string{"IP", "TID", "TIME", "CALLCHAIN", "STACK_USER", "REGS_USER"}}
	run("native_config_requests_stack_bytes_with_clean_records", stack, "STACK_USER")
	return out
}

var recorderCanary = regexp.MustCompile(`CANARY_[A-Z0-9_]+`)

// LoadRecorderCanaries extracts the 03.07 recorder canary tokens from the
// canary page, sorted and de-duplicated.
func LoadRecorderCanaries(path string) ([]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	set := map[string]bool{}
	for _, m := range recorderCanary.FindAll(raw, -1) {
		set[string(m)] = true
	}
	if len(set) == 0 {
		return nil, fmt.Errorf("no CANARY_ tokens in %s", path)
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out, nil
}

// goSubject is the build description of rows that run in this process only.
func (rc *runCtx) goBuildInfo() *Build {
	return &Build{Family: "go", Version: strings.TrimPrefix(rc.host.GoBuild, "go"), OS: rc.host.OS, Arch: rc.host.Arch, ID: "toolchain:" + rc.host.GoBuild, Host: rc.host.Class}
}

// runPrivacyScannerControls proves the scanner before any real run is trusted:
// a clean variant passes, and every contaminated variant fails (each 03.07
// recorder canary in the recorder/export queue with a scrubbed network, a 04.08
// native sentinel in the exporter queue, a stack-byte capture configuration with
// clean records). A scanner that accepts one of them cannot vouch for a run.
func runPrivacyScannerControls(rc *runCtx, spec RowSpec) Row {
	return rc.scannerControlsRow(InspectPrivacy)
}

// scannerControlsRow runs the controls through inspect (InspectPrivacy in production).
func (rc *runCtx) scannerControlsRow(inspect Inspector) Row {
	row := Row{State: StateExercised, Build: rc.goBuildInfo(), Command: &CommandRun{Command: "InspectPrivacy + NegativeControls over the 03.07 recorder canaries and the 04.08 scan detector"}}
	canaries, err := LoadRecorderCanaries(filepath.Join(rc.root, "fixtures", "sdk", "replay", "canaries.html"))
	if err != nil {
		row.Outcome, row.Failures, row.Evidence = OutcomeFailed, []string{"recorder canaries unreadable: " + err.Error()}, []string{"fixtures/sdk/replay/canaries.html"}
		return row
	}
	policy, err := scan.LoadPolicy(filepath.Join(rc.root, "fixtures", "nativeperf", "privacy", "policy.json"))
	if err != nil {
		row.Outcome, row.Failures, row.Evidence = OutcomeFailed, []string{"privacy policy unreadable: " + err.Error()}, []string{"fixtures/nativeperf/privacy/policy.json"}
		return row
	}
	const nonce = "a1b2c3"
	detector, err := scan.NewDetector(policy, nonce)
	if err != nil {
		row.Outcome, row.Failures, row.Evidence = OutcomeFailed, []string{"detector: " + err.Error()}, []string{"fixtures/nativeperf/privacy/policy.json"}
		return row
	}
	clean := PrivacyCase{
		Canaries: canaries, Detector: detector,
		Native: &NativeConfig{SampleType: []string{"IP", "TID", "TIME", "CALLCHAIN", "CPU", "PERIOD"}},
		Surfaces: []Surface{
			{Name: SurfaceNetwork, Data: []byte(`{"chunks":[{"seq":1,"masked":true,"nodes":12}]}`)},
			{Name: SurfaceRecorderQueue, Data: []byte(`{"queue":[{"seq":1,"masked":true,"nodes":12}]}`)},
			{Name: SurfaceExportQueue, Data: []byte(`{"export":[{"seq":1,"events":3}]}`)},
			{Name: SurfaceStoredRecords, Data: []byte(`{"stored":[{"seq":1,"events":3}]}`)},
			{Name: SurfaceDiagnostics, Data: []byte(`{"dropped":0}`)},
		},
	}
	total, rejected := 0.0, 0.0
	fail := func(format string, args ...any) {
		row.Outcome = OutcomeFailed
		row.Failures = append(row.Failures, fmt.Sprintf(format, args...))
	}
	row.Outcome = OutcomePassed
	if v := inspect(clean); !v.Pass {
		fail("the clean variant was rejected: %v %v", v.Problems, v.Findings)
	}
	for _, secret := range canaries {
		for _, c := range NegativeControlsWith(inspect, clean, secret) {
			total++
			if c.Rejected {
				rejected++
			} else {
				fail("control %s with a 03.07 canary: %s", c.Name, c.Detail)
			}
		}
	}
	sentinel, err := policy.Sentinel("comm", nonce)
	if err != nil {
		fail("sentinel: %v", err)
	}
	nativeLeak := clean
	nativeLeak.Canaries = nil
	nativeLeak.Surfaces = append([]Surface(nil), clean.Surfaces...)
	nativeLeak.Surfaces[2].Data = []byte(`{"export":[{"comm":"` + sentinel + `"}]}`)
	total++
	if v := inspect(nativeLeak); v.Pass {
		fail("a 04.08 sentinel in the exporter queue was accepted")
	} else {
		rejected++
	}
	row.Series = []Series{{Name: "controls_total", Unit: "count", Values: []float64{total}}, {Name: "controls_rejected", Unit: "count", Values: []float64{rejected}}, {Name: "recorder_canaries", Unit: "count", Values: []float64{float64(len(canaries))}}}
	row.Evidence = []string{fmt.Sprintf("%d contaminated variants rejected of %d, clean variant accepted; matcher = fixtures/nativeperf/privacy/scan Detector (raw, case-folded, reversed, hex, base64 x3, UTF-16, packed words) + gzip inflate", int(rejected), int(total))}
	row.Limits = []string{"synthetic surfaces: this row proves the scanner, not a product run; the real recorder run is the Playwright row and the real native run is the verify rows"}
	return row
}

// ---- native privacy (04.08 verify) ----

type verifyStage struct {
	Buffers int `json:"buffers"`
	Bytes   int `json:"bytes"`
}

type verifyReport struct {
	CPU struct {
		Samples int `json:"samples"`
		Hot     int `json:"samples_in_hot_function"`
		Loss    int `json:"loss_events"`
	} `json:"cpu"`
	Scheduler struct {
		Status   string `json:"status"`
		Reason   string `json:"reason"`
		Switches int    `json:"switch_events"`
	} `json:"scheduler"`
	Export struct {
		Batches       int  `json:"batches_admitted_over_real_route"`
		QueueObserved bool `json:"exporter_queue_observed"`
		StoragePos    bool `json:"storage_positive_control_observed"`
		StorageFiles  int  `json:"storage_files_scanned"`
		StorageBytes  int  `json:"storage_bytes_scanned"`
		ReadSamples   int  `json:"read_samples"`
	} `json:"export"`
	Stages     map[string]verifyStage `json:"stages"`
	Violations []string               `json:"canary_violations"`
	PeerDeath  struct {
		Requested bool   `json:"requested"`
		Result    string `json:"result"`
	} `json:"peer_death"`
	HelperCrash struct {
		Requested bool   `json:"requested"`
		Result    string `json:"result"`
	} `json:"helper_crash"`
	Syscalls *struct {
		Method   string   `json:"method"`
		Opens    int      `json:"perf_event_open_calls"`
		CPUOpens int      `json:"cpu_event_opens"`
		Ioctls   int      `json:"perf_event_ioctls"`
		Findings []string `json:"findings"`
	} `json:"syscall_audit"`
	Cleanup struct {
		PerfFDsBefore int `json:"perf_fds_before"`
		PerfFDsAfter  int `json:"perf_fds_after"`
		DumpFiles     int `json:"dump_files_found"`
	} `json:"cleanup"`
	Failures []string `json:"failures"`
	NotRun   []string `json:"not_run"`
}

type verifyRun struct {
	Report  *verifyReport
	Raw     []byte
	Exit    int
	Command string
	Elapsed time.Duration
	Why     string
	Failure string
}

// verify runs the committed 04.08 verifier once per mode and caches it.
func (rc *runCtx) verify(negative bool) *verifyRun {
	key := fmt.Sprintf("verify:%v", negative)
	if v, ok := rc.cache[key]; ok {
		return v.(*verifyRun)
	}
	run := &verifyRun{}
	rc.cache[key] = run
	canary, why := rc.ccBuild("canary", "fixtures/nativeperf/privacy/canary.c")
	if why != "" {
		run.Why = why
		return run
	}
	bin, why := rc.goBuild("verify", "./fixtures/nativeperf/privacy/verify")
	if why != "" {
		run.Why = why
		return run
	}
	args := []string{"--workload", canary, "--endpoint-env", "SOUNDPOST_FIXTURE_API", "--policy", filepath.Join(rc.root, "fixtures", "nativeperf", "privacy", "policy.json"),
		"--seconds", strconv.Itoa(rc.workloads.NativePrivacy.Seconds)}
	if negative {
		args = append(args, "--negative-control")
	} else {
		args = append(args, "--audit-syscalls", "--inject-peer-death", "--inject-helper-crash")
	}
	res := rc.exec(20*time.Minute, rc.root, nil, bin, args...)
	run.Exit, run.Elapsed = res.Exit, res.Duration
	run.Command = "verify --workload <built canary> --policy fixtures/nativeperf/privacy/policy.json --seconds " + strconv.Itoa(rc.workloads.NativePrivacy.Seconds) + " " + strings.Join(args[6:], " ")
	var rep verifyReport
	obj, raw := lastJSONObjectMultiline(res.Stdout)
	if obj == nil || json.Unmarshal(raw, &rep) != nil {
		run.Failure = fmt.Sprintf("verify exited %d without a readable report: %s", res.Exit, tail(rc.rel(res.Stderr), 240))
		return run
	}
	run.Report, run.Raw = &rep, raw
	return run
}

// lastJSONObjectMultiline decodes the first complete JSON object of an
// indented report printed on stdout.
func lastJSONObjectMultiline(out string) (map[string]any, []byte) {
	i := strings.Index(out, "{")
	if i < 0 {
		return nil, nil
	}
	dec := json.NewDecoder(strings.NewReader(out[i:]))
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return nil, nil
	}
	raw, _ := json.Marshal(m)
	return m, raw
}

// runPrivacyNative maps the 04.08 verifier to matrix rows after the host gate:
// every owned boundary was scanned, the stored/exported records were
// inspected, the capture configuration was audited from the real syscall
// trace, and the contaminated sanitizer exits 4.
func runPrivacyNative(rc *runCtx, spec RowSpec) Row {
	build, why := rc.nativeGate(spec)
	if why != "" {
		return notExercised(why)
	}
	capability := spec.Params["capability"]
	run := rc.verify(capability == "negative_control")
	if run.Why != "" {
		return notExercised(run.Why)
	}
	cmd := &CommandRun{Command: run.Command, ExitCode: run.Exit, DurationMS: run.Elapsed.Milliseconds()}
	failed := func(format string, args ...any) Row {
		return Row{State: StateExercised, Outcome: OutcomeFailed, Build: build, Command: cmd, Evidence: []string{"verify attempt"}, Failures: []string{fmt.Sprintf(format, args...)}}
	}
	if capability == "negative_control" {
		if run.Exit != 4 {
			return failed("the contaminated sanitizer exited %d, want 4 (a canary must cross a boundary): the detector cannot be trusted", run.Exit)
		}
		row := Row{State: StateExercised, Outcome: OutcomePassed, Build: build, Command: cmd, Evidence: []string{"verify --negative-control exited 4: the contaminated sanitizer's canary was found at a boundary"}}
		if run.Report != nil {
			row.Series = []Series{{Name: "canary_violations", Unit: "count", Values: []float64{float64(len(run.Report.Violations))}}}
			if len(run.Report.Violations) == 0 {
				return failed("verify --negative-control exited 4 but reported no canary violation")
			}
		}
		return row
	}
	if run.Report == nil {
		return failed("%s", run.Failure)
	}
	rep := run.Report
	if run.Exit != 0 && run.Exit != 10 {
		return failed("verify exited %d: %s", run.Exit, strings.Join(rep.Failures, "; "))
	}
	row := Row{State: StateExercised, Outcome: OutcomePassed, Build: build, Command: cmd}
	row.Evidence = []string{rc.writeEvidence("native-privacy-verify.json", run.Raw)}
	fail := func(format string, args ...any) {
		row.Outcome = OutcomeFailed
		row.Failures = append(row.Failures, fmt.Sprintf(format, args...))
	}
	stageNames := make([]string, 0, len(rep.Stages))
	for name := range rep.Stages {
		stageNames = append(stageNames, name)
	}
	sort.Strings(stageNames)
	for _, name := range stageNames {
		s := rep.Stages[name]
		row.Series = append(row.Series, Series{Name: "stage_" + name + "_bytes", Unit: "bytes", Values: []float64{float64(s.Bytes)}}, Series{Name: "stage_" + name + "_buffers", Unit: "count", Values: []float64{float64(s.Buffers)}})
	}
	requireBytes := func(stages ...string) {
		for _, name := range stages {
			if rep.Stages[name].Bytes == 0 {
				fail("boundary %s was not inspected (0 bytes): a blind scan is not a pass", name)
			}
		}
	}
	if len(rep.Violations) > 0 {
		fail("canary crossed a boundary: %s", strings.Join(rep.Violations, "; "))
	}
	if len(rep.Failures) > 0 {
		fail("verifier failures: %s", strings.Join(rep.Failures, "; "))
	}
	switch capability {
	case "canary_boundaries":
		requireBytes("owned_sanitized_staging", "acquisition_socket", "exporter_queue", "wire_compressed", "wire_decompressed", "admitted_storage", "profile_read", "profile_export")
		row.Series = append(row.Series, Series{Name: "cpu_samples", Unit: "count", Values: []float64{float64(rep.CPU.Samples)}}, Series{Name: "cpu_loss_events", Unit: "count", Values: []float64{float64(rep.CPU.Loss)}})
		if rep.CPU.Samples == 0 {
			fail("the real capture produced no CPU samples, so the scanned boundaries carried nothing")
		}
		row.Evidence = append(row.Evidence, fmt.Sprintf("8 sentinel kinds x 8 encodings scanned over %d boundaries; %d real CPU samples; peer-death drill %q, helper-crash drill %q", len(rep.Stages), rep.CPU.Samples, rep.PeerDeath.Result, rep.HelperCrash.Result))
	case "stored_exported_records":
		requireBytes("exporter_queue", "wire_compressed", "wire_decompressed", "admitted_storage", "profile_read", "profile_export")
		if !rep.Export.QueueObserved || !rep.Export.StoragePos || rep.Export.StorageBytes == 0 || rep.Export.ReadSamples == 0 || rep.Export.Batches == 0 {
			fail("stored/exported records were not actually inspected (queue observed %v, storage positive control %v, storage bytes %d, read samples %d, batches %d)",
				rep.Export.QueueObserved, rep.Export.StoragePos, rep.Export.StorageBytes, rep.Export.ReadSamples, rep.Export.Batches)
		}
		row.Series = append(row.Series, Series{Name: "storage_bytes_scanned", Unit: "bytes", Values: []float64{float64(rep.Export.StorageBytes)}}, Series{Name: "storage_files_scanned", Unit: "count", Values: []float64{float64(rep.Export.StorageFiles)}},
			Series{Name: "read_samples", Unit: "count", Values: []float64{float64(rep.Export.ReadSamples)}})
		row.Evidence = append(row.Evidence, fmt.Sprintf("real C03 batch route + admitted storage + scoped read scanned; storage positive control observed=%v", rep.Export.StoragePos))
	case "no_stack_bytes_config":
		sc := rep.Syscalls
		if sc == nil || !strings.HasPrefix(sc.Method, "strace") {
			fail("the capture configuration was not audited from a real syscall trace")
		} else {
			row.Series = append(row.Series, Series{Name: "perf_event_open_calls", Unit: "count", Values: []float64{float64(sc.Opens)}}, Series{Name: "cpu_event_opens", Unit: "count", Values: []float64{float64(sc.CPUOpens)}}, Series{Name: "audit_findings", Unit: "count", Values: []float64{float64(len(sc.Findings))}})
			if sc.Opens == 0 || sc.CPUOpens == 0 {
				fail("the trace shows no real perf_event_open call: the configuration audit would be vacuous")
			}
			if len(sc.Findings) > 0 {
				fail("capture configuration findings: %s", strings.Join(sc.Findings, "; "))
			}
			row.Evidence = append(row.Evidence, fmt.Sprintf("every perf_event_open attribute of the real run was checked against the closed sample_type allowlist (no STACK_USER/REGS_USER/REGS_INTR/BRANCH_STACK/DATA/RAW on CPU): %d calls, %d findings", sc.Opens, len(sc.Findings)))
		}
	case "scheduler_canaries":
		if rep.Scheduler.Status != "supported" || rep.Scheduler.Switches == 0 {
			reason := fmt.Sprintf("scheduler privacy rows were not exercised: scheduler status %q reason %q, %d switch events", rep.Scheduler.Status, rep.Scheduler.Reason, rep.Scheduler.Switches)
			if s := schedulerBlocker(); s != "" {
				reason += "; " + s
			}
			return notExercised(reason)
		}
		row.Series = append(row.Series, Series{Name: "scheduler_switch_events", Unit: "count", Values: []float64{float64(rep.Scheduler.Switches)}})
	default:
		return notExercised("unknown privacy capability " + capability)
	}
	row.Limits = []string{fmt.Sprintf("capture seconds %d (verify default 4); the kernel ring transiently carries command names: the verifier proves they never leave the helper's borrowed view, not that they never existed", rc.workloads.NativePrivacy.Seconds)}
	return row
}
