// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Stage names one observation boundary of the native capture lifecycle. There is
// deliberately no raw-ring, mmap, register or stack stage: instrumentation must
// never copy the kernel ring into an audit artifact.
type Stage string

const (
	StageStaging          Stage = "owned_sanitized_staging"
	StageSocket           Stage = "acquisition_socket"
	StageExporterQueue    Stage = "exporter_queue"
	StageWireCompressed   Stage = "wire_compressed"
	StageWireDecompressed Stage = "wire_decompressed"
	StageStorage          Stage = "admitted_storage"
	StageRead             Stage = "profile_read"
	StageExport           Stage = "profile_export"
	StageDiagnostics      Stage = "diagnostics"
)

// AllStages is the complete ordered stage list; it must equal policy.json "stages".
var AllStages = []Stage{StageStaging, StageSocket, StageExporterQueue, StageWireCompressed, StageWireDecompressed, StageStorage, StageRead, StageExport, StageDiagnostics}

// ErrUnknownStage is returned for a stage that is not an owned sanitized boundary.
var ErrUnknownStage = errors.New("privacy audit: unknown stage")

// ErrUninspectable is returned when a compressed stage cannot be decompressed.
var ErrUninspectable = errors.New("privacy audit: compressed stage is not inspectable")

// Violation is one content-free detection.
type Violation struct {
	Stage Stage
	Hit   Hit
}

func (v Violation) String() string { return string(v.Stage) + ": " + v.Hit.String() }

// Leak is the error Observe returns when a sentinel crossed a stage boundary.
type Leak struct{ Violations []Violation }

func (l *Leak) Error() string {
	parts := make([]string, len(l.Violations))
	for i, v := range l.Violations {
		parts[i] = v.String()
	}
	return "privacy canary crossed a boundary: " + strings.Join(parts, "; ")
}

// PrivacyAudit observes sanitized, owned buffers only. It keeps counts and
// content-free violation records, never the observed bytes. It is test/fixture
// code and is not a production content logger.
type PrivacyAudit struct {
	mu         sync.Mutex
	detector   *Detector
	observed   map[Stage]int
	octets     map[Stage]int
	violations []Violation
}

// maxInflated mirrors the ingest decoder's decompressed ceiling.
const maxInflated = 4<<20 + 1

// NewPrivacyAudit arms a detector for one run.
func NewPrivacyAudit(d *Detector) *PrivacyAudit {
	return &PrivacyAudit{detector: d, observed: map[Stage]int{}, octets: map[Stage]int{}}
}

func knownStage(s Stage) bool {
	for _, k := range AllStages {
		if k == s {
			return true
		}
	}
	return false
}

// Observe scans b for sentinels. The compressed wire stage is gunzipped and the
// decompressed bytes are scanned as well, so compression cannot hide a leak.
// It returns a *Leak when any sentinel is found.
func (a *PrivacyAudit) Observe(stage Stage, b []byte) error {
	if !knownStage(stage) {
		return ErrUnknownStage
	}
	hits := a.detector.Scan(b)
	var inspectErr error
	if stage == StageWireCompressed {
		z, e := gzip.NewReader(bytes.NewReader(b))
		if e != nil {
			inspectErr = ErrUninspectable
		} else {
			expanded, e := io.ReadAll(io.LimitReader(z, maxInflated))
			if e != nil || len(expanded) >= maxInflated {
				inspectErr = ErrUninspectable
			} else {
				hits = append(hits, a.detector.Scan(expanded)...)
			}
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.observed[stage]++
	a.octets[stage] += len(b)
	var violations []Violation
	for _, h := range hits {
		v := Violation{Stage: stage, Hit: h}
		violations = append(violations, v)
		a.violations = append(a.violations, v)
	}
	if len(violations) > 0 {
		return &Leak{Violations: violations}
	}
	return inspectErr
}

// Violations returns a copy of every violation recorded so far.
func (a *PrivacyAudit) Violations() []Violation {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]Violation(nil), a.violations...)
}

// Observed reports how many buffers and bytes crossed a stage.
func (a *PrivacyAudit) Observed(stage Stage) (buffers, octets int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.observed[stage], a.octets[stage]
}

// RequireStages fails unless every listed stage observed at least one nonempty
// buffer, so a skipped stage cannot pass as "zero canaries".
func (a *PrivacyAudit) RequireStages(stages ...Stage) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	var missing []string
	for _, s := range stages {
		if a.observed[s] == 0 || a.octets[s] == 0 {
			missing = append(missing, string(s))
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("privacy audit: stages never observed: %s", strings.Join(missing, ","))
	}
	return nil
}

// Finding is one syscall/configuration policy violation found in a strace log.
type Finding struct {
	Rule string
	Line int
	Text string
}

func (f Finding) String() string { return fmt.Sprintf("line %d: %s: %s", f.Line, f.Rule, f.Text) }

// StraceSummary proves an audit inspected real acquisition rather than nothing.
type StraceSummary struct {
	Lines            int
	PerfEventOpens   int
	CPUOpens         int
	SchedulerOpens   int
	PerfIoctls       int
	ForbiddenChecked int
	// Prctls counts every prctl in the trace, ThpDisables those that are prctl(PR_SET_THP_DISABLE, 1) (the helper's
	// D53 opt-out), Ppolls every ppoll (the helper's ring exit probe, which exists only in scheduler captures).
	Prctls, ThpDisables, Ppolls int
	// Attributes is every perf_event_open attribute struct the audit checked, in trace order, as strace -v printed
	// it (constants and numbers only). A truncated attribute is a finding and is not listed.
	Attributes []string
}

var (
	straceLine    = regexp.MustCompile(`^(?:\[pid\s+)?(\d+)\]?\s+([a-z_0-9]+)\((.*)$`)
	sentinelInTxt = regexp.MustCompile(`SPCNRY-[A-Za-z0-9]+-[0-9a-fA-F]+`)
	quotedFirst   = regexp.MustCompile(`"((?:[^"\\]|\\.)*)"`)
	attrField     = regexp.MustCompile(`([a-z_0-9]+)=([^,{}\s]+)`)
	prctlArgs     = regexp.MustCompile(`^\s*([A-Za-z_0-9]+)\s*(?:,\s*([A-Za-z_0-9]+))?`)
	ppollArgs     = regexp.MustCompile(`^(?:NULL|0x[0-9a-fA-F]+|\[.*?\])\s*,\s*(-?\d+|0x[0-9a-fA-F]+)\s*,\s*(?:NULL|0x[0-9a-fA-F]+|\{[^}]*\})\s*,\s*([^,\s)]+)`)
	straceResumed = regexp.MustCompile(`^(?:\[pid\s+)?(\d+)\]?\s+<\.\.\. [a-z_0-9]+ resumed>(.*)$`)
)

func redact(s string) string { return sentinelInTxt.ReplaceAllString(s, "SPCNRY-redacted") }

func inSet(set []string, v string) bool {
	for _, s := range set {
		if s == v {
			return true
		}
	}
	return false
}

// AuditStrace audits `strace -f -v` output against the policy: forbidden
// syscalls, forbidden /proc-memory style opens and dump file names, and the
// exact perf_event_open attribute allowlist (types, sample_type bits, zero/one
// fields) plus the PERF_EVENT_IOC_* allowlist. A truncated attribute (`...`) is a
// finding: the audit refuses to pass what it could not see.
func AuditStrace(p Policy, r io.Reader) ([]Finding, StraceSummary, error) {
	var out []Finding
	var sum StraceSummary
	paths := make([]*regexp.Regexp, 0, len(p.Syscalls.ForbiddenOpenPath))
	for _, expr := range p.Syscalls.ForbiddenOpenPath {
		re, e := regexp.Compile(expr)
		if e != nil {
			return nil, sum, e
		}
		paths = append(paths, re)
	}
	names := make([]*regexp.Regexp, 0, len(p.Syscalls.ForbiddenOpenName))
	for _, expr := range p.Syscalls.ForbiddenOpenName {
		re, e := regexp.Compile(expr)
		if e != nil {
			return nil, sum, e
		}
		names = append(names, re)
	}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64<<10), 4<<20)
	n := 0
	// audit checks one complete call: m is straceLine's submatches, line the number where the call began.
	audit := func(line int, m []string) {
		name, rest := m[2], m[3]
		sum.ForbiddenChecked++
		if inSet(p.Syscalls.Forbidden, name) {
			out = append(out, Finding{"forbidden_syscall", line, name})
			return
		}
		switch name {
		case "perf_event_open":
			sum.PerfEventOpens++
			out = append(out, auditPerfAttr(p, line, rest, &sum)...)
		case "prctl":
			sum.Prctls++
			out = append(out, auditPrctl(p, line, rest, &sum)...)
		case "ppoll":
			sum.Ppolls++
			out = append(out, auditPpoll(p, line, rest)...)
		case "ioctl":
			fields := strings.SplitN(rest, ",", 3)
			if len(fields) >= 2 {
				request := strings.TrimSpace(fields[1])
				if strings.HasPrefix(request, "PERF_EVENT_IOC_") {
					sum.PerfIoctls++
					if !inSet(p.Syscalls.IoctlAllow, request) {
						out = append(out, Finding{"forbidden_perf_ioctl", line, request})
					}
				}
			}
		case "open", "openat", "openat2", "creat":
			q := quotedFirst.FindStringSubmatch(rest)
			if q == nil {
				return
			}
			path := q[1]
			for _, re := range paths {
				if re.MatchString(path) {
					out = append(out, Finding{"forbidden_open_path", line, redact(path)})
				}
			}
			// A dump is a file the process WRITES; a read-only open or a directory
			// that happens to be named "core" is not one.
			writes := strings.Contains(rest, "O_WRONLY") || strings.Contains(rest, "O_RDWR") || strings.Contains(rest, "O_CREAT") || strings.Contains(rest, "O_TRUNC") || name == "creat"
			for _, re := range names {
				if writes && re.MatchString(path) {
					out = append(out, Finding{"forbidden_dump_file_name", line, redact(path)})
				}
			}
		}
	}
	// `strace -f` prints a call that another thread interrupted as `name(<args so far> <unfinished ...>` and finishes it
	// on a `<... name resumed>` line of the same pid. The two halves are joined (the perf_event_open attribute is only
	// on the resumed half); a call that never resumed (killed process) is audited with what was printed.
	type pendingCall struct {
		line   int
		prefix string
	}
	pending := map[string]pendingCall{}
	for scanner.Scan() {
		n++
		line := scanner.Text()
		sum.Lines++
		if m := straceResumed.FindStringSubmatch(line); m != nil {
			call, ok := pending[m[1]]
			if !ok {
				continue
			}
			delete(pending, m[1])
			if joined := straceLine.FindStringSubmatch(call.prefix + m[2]); joined != nil {
				audit(call.line, joined)
			}
			continue
		}
		if head, ok := strings.CutSuffix(line, " <unfinished ...>"); ok {
			if m := straceLine.FindStringSubmatch(head); m != nil {
				pending[m[1]] = pendingCall{n, head}
			}
			continue
		}
		if m := straceLine.FindStringSubmatch(line); m != nil {
			audit(n, m)
		}
	}
	for _, call := range pending {
		if m := straceLine.FindStringSubmatch(call.prefix); m != nil {
			audit(call.line, m)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Line < out[j].Line })
	return out, sum, scanner.Err()
}

func auditPerfAttr(p Policy, line int, rest string, sum *StraceSummary) []Finding {
	var out []Finding
	end := strings.Index(rest, "}")
	if end < 0 {
		return []Finding{{"perf_attr_unparseable", line, "no attribute struct"}}
	}
	attr := rest[:end]
	if strings.Contains(attr, "...") {
		return []Finding{{"perf_attr_truncated", line, "strace must run with -v so every attribute field is visible"}}
	}
	sum.Attributes = append(sum.Attributes, strings.TrimPrefix(strings.TrimSpace(attr), "{"))
	fields := map[string]string{}
	for _, f := range attrField.FindAllStringSubmatch(attr, -1) {
		fields[f[1]] = strings.TrimSpace(f[2])
	}
	policy := p.Syscalls.PerfEventOpen
	rule := policy.CPU
	if fields["type"] == "PERF_TYPE_TRACEPOINT" {
		rule = policy.Scheduler
		sum.SchedulerOpens++
	} else {
		sum.CPUOpens++
	}
	if !inSet(rule.Types, fields["type"]) {
		out = append(out, Finding{"perf_attr_type", line, fields["type"]})
	}
	got := strings.Split(fields["sample_type"], "|")
	if fields["sample_type"] == "" {
		out = append(out, Finding{"perf_attr_sample_type_missing", line, ""})
	}
	for _, bit := range got {
		if bit != "" && !inSet(rule.SampleType, bit) {
			out = append(out, Finding{"perf_attr_sample_type", line, bit})
		}
	}
	for _, f := range policy.MustZero {
		if v, ok := fields[f]; ok && v != "0" && v != "0x0" && v != "NULL" && v != "HW_BREAKPOINT_EMPTY" {
			out = append(out, Finding{"perf_attr_nonzero", line, f})
		}
	}
	// A VER0 (64-byte) attribute is a disabled capability probe that is opened and
	// closed without a ring; the sampling flags only apply to real acquisition events.
	required := rule.MustBeOne
	if fields["size"] == "PERF_ATTR_SIZE_VER0" {
		required = []string{"disabled"}
	}
	for _, f := range required {
		if v, ok := fields[f]; !ok || v != "1" {
			out = append(out, Finding{"perf_attr_required_flag", line, f})
		}
	}
	return out
}

// auditPrctl admits only the prctl calls the policy lists: the helper's PR_SET_THP_DISABLE with 1 and the naming calls
// of the runtime and the canary. Any other option (PR_SET_PTRACER, PR_SET_DUMPABLE, PR_SET_MM, THP re-enable, ...) or an
// unreadable line is a finding. The option may be printed by name or number.
func auditPrctl(p Policy, line int, rest string, sum *StraceSummary) []Finding {
	m := prctlArgs.FindStringSubmatch(rest)
	option, arg := "", ""
	if m != nil {
		option, arg = m[1], m[2]
	}
	for _, allowed := range p.Syscalls.StraceAllowedPrctl {
		number, numErr := strconv.ParseInt(option, 0, 64)
		if option == "" || option != allowed.Option && (numErr != nil || number != allowed.Number) {
			continue
		}
		if allowed.Arg != nil {
			if v, e := strconv.ParseInt(arg, 0, 64); arg == "" || e != nil || v != *allowed.Arg {
				continue
			}
		}
		if allowed.Option == "PR_SET_THP_DISABLE" {
			sum.ThpDisables++
		}
		return nil
	}
	return []Finding{{"prctl_not_allowlisted", line, option + "," + arg}}
}

// auditPpoll admits only the allowlisted ppoll shapes (the ring exit probe: nfds 1, NULL sigmask). A line whose
// arguments cannot be read is a finding: the audit refuses to pass what it could not see.
func auditPpoll(p Policy, line int, rest string) []Finding {
	m := ppollArgs.FindStringSubmatch(rest)
	if m == nil {
		return []Finding{{"ppoll_unparseable", line, "arguments not readable"}}
	}
	nfds, e := strconv.ParseInt(m[1], 0, 64)
	if e != nil {
		return []Finding{{"ppoll_unparseable", line, "nfds " + m[1]}}
	}
	for _, allowed := range p.Syscalls.StraceAllowedPpoll {
		if int64(allowed.Nfds) == nfds && allowed.Sigmask == m[2] {
			return nil
		}
	}
	return []Finding{{"ppoll_not_allowlisted", line, "nfds " + m[1] + " sigmask " + m[2]}}
}
