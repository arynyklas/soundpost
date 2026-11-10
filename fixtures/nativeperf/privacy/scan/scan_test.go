// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
)

const testNonce = "a1b2c3"

func testPolicy(t *testing.T) Policy {
	t.Helper()
	p, e := LoadPolicy("../policy.json")
	if e != nil {
		t.Fatal(e)
	}
	return p
}

func TestPolicyIsStrictAndSentinelsAreDistinct(t *testing.T) {
	p := testPolicy(t)
	seen := map[string]bool{}
	for _, k := range p.Kinds {
		v, e := p.Sentinel(k.ID, testNonce)
		if e != nil || !strings.HasPrefix(v, p.Marker) || !strings.HasSuffix(v, testNonce) || seen[v] {
			t.Fatalf("kind %s value %q err %v", k.ID, v, e)
		}
		seen[v] = true
	}
	if len(seen) != 8 {
		t.Fatalf("expected comm, stack, heap, env, argv, path, input and db sentinels, got %d", len(seen))
	}
	comm, _ := p.Sentinel("comm", testNonce)
	if len(comm) > 15 {
		t.Fatal("comm sentinel does not fit the kernel's 15-byte thread name")
	}
	stages := make([]string, len(AllStages))
	for i, s := range AllStages {
		stages[i] = string(s)
	}
	if strings.Join(stages, ",") != strings.Join(p.Stages, ",") {
		t.Fatal("stage list and policy.json drifted")
	}
	if _, e := p.Sentinel("comm", "zzzzzz"); e == nil {
		t.Fatal("non-hex nonce accepted")
	}
}

// Every encoding must be caught, including values that cross alignment.
func TestDetectorCatchesEncodings(t *testing.T) {
	p := testPolicy(t)
	d, e := NewDetector(p, testNonce)
	if e != nil {
		t.Fatal(e)
	}
	stack, _ := p.Sentinel("stack", testNonce)
	raw := []byte(stack)
	utf16 := []byte{}
	for _, c := range raw {
		utf16 = append(utf16, c, 0)
	}
	quoted, _ := json.Marshal(stack)
	word := binary.LittleEndian.Uint64(raw[:8])
	cases := map[string][]byte{
		"raw":         []byte("prefix " + stack + " suffix"),
		"upper":       []byte(strings.ToUpper(stack)),
		"lower":       []byte(strings.ToLower(stack)),
		"reversed":    reverse(raw),
		"hex":         []byte(hex.EncodeToString(raw)),
		"utf16":       utf16,
		"json":        quoted,
		"word_dec_le": []byte(`{"ip":"` + strconv.FormatUint(word, 10) + `"}`),
		"word_hex":    []byte("0x" + strconv.FormatUint(word, 16)),
		"raw_window":  []byte("xx" + stack[7:19] + "yy"),
		"nonce_word":  []byte(strconv.FormatUint(binary.LittleEndian.Uint64([]byte(stack[11:19])), 10)),
		"marker_only": []byte("xx SPCNRY- xx"),
	}
	for shift := range 3 {
		filler := bytes.Repeat([]byte{'~'}, shift)
		stream := append(append(append([]byte(nil), filler...), raw...), []byte("trailing-bytes")...)
		cases["base64_std_"+strconv.Itoa(shift)] = []byte(base64.StdEncoding.EncodeToString(stream))
		cases["base64_url_"+strconv.Itoa(shift)] = []byte(base64.URLEncoding.EncodeToString(stream))
	}
	for name, input := range cases {
		if hits := d.Scan(input); len(hits) == 0 {
			t.Errorf("%s: sentinel not detected", name)
		}
	}
	if hits := d.Scan([]byte(`{"kind":"cpu_sample","ip":"4198400","callchain":[{"ip":"4198431"}],"period":"10101010"}`)); len(hits) != 0 {
		t.Fatalf("clean numeric profile flagged: %v", hits)
	}
}

// A detector built for one run must not fire on another run's nonce.
func TestDetectorIsPerRun(t *testing.T) {
	p := testPolicy(t)
	d, _ := NewDetector(p, testNonce)
	other, _ := p.Sentinel("heap", "ffeedd")
	// Only run-independent prefix evidence may fire for another run's value; no
	// full-value encoding may.
	for _, hit := range d.Scan([]byte(other)) {
		if hit.Kind != "marker" && !strings.HasPrefix(hit.Encoding, "word_") && hit.Encoding != "raw_window" {
			t.Fatalf("matched another run's full value: %v", hit)
		}
	}
}

func TestHitNeverContainsContent(t *testing.T) {
	p := testPolicy(t)
	d, _ := NewDetector(p, testNonce)
	comm, _ := p.Sentinel("comm", testNonce)
	a := NewPrivacyAudit(d)
	e := a.Observe(StageSocket, []byte(`{"domain":{"host_id":"`+comm+`"}}`))
	var leak *Leak
	if !errors.As(e, &leak) {
		t.Fatalf("leak not reported: %v", e)
	}
	if strings.Contains(e.Error(), comm) || strings.Contains(e.Error(), testNonce) {
		t.Fatal("violation text echoes the observed content")
	}
	for _, v := range a.Violations() {
		if strings.Contains(v.String(), testNonce) {
			t.Fatal("violation record echoes the nonce")
		}
	}
}

func TestAuditDecompressesCompressedWireStage(t *testing.T) {
	p := testPolicy(t)
	d, _ := NewDetector(p, testNonce)
	heap, _ := p.Sentinel("heap", testNonce)
	var z bytes.Buffer
	w := gzip.NewWriter(&z)
	for i := range 200 {
		w.Write([]byte(`{"records":[{"n":` + strconv.Itoa(i) + `,"note":"` + heap + `"}]}` + "\n"))
	}
	w.Close()
	if len(d.Scan(z.Bytes())) != 0 {
		t.Fatal("test premise: gzip should hide the plaintext from a raw scan")
	}
	a := NewPrivacyAudit(d)
	var leak *Leak
	if e := a.Observe(StageWireCompressed, z.Bytes()); !errors.As(e, &leak) {
		t.Fatalf("compressed leak hidden: %v", e)
	}
	if e := a.Observe(StageWireCompressed, []byte("not gzip")); !errors.Is(e, ErrUninspectable) {
		t.Fatalf("uninspectable compressed stage passed: %v", e)
	}
	if e := a.Observe("raw_mmap_ring", []byte("x")); !errors.Is(e, ErrUnknownStage) {
		t.Fatalf("a raw ring stage must not exist: %v", e)
	}
}

func TestRequireStagesRefusesEmptyOrSkippedStage(t *testing.T) {
	p := testPolicy(t)
	d, _ := NewDetector(p, testNonce)
	a := NewPrivacyAudit(d)
	a.Observe(StageSocket, []byte("{}"))
	a.Observe(StageStaging, nil)
	if e := a.RequireStages(StageSocket); e != nil {
		t.Fatal(e)
	}
	if e := a.RequireStages(StageSocket, StageStaging, StageStorage); e == nil || !strings.Contains(e.Error(), "owned_sanitized_staging") || !strings.Contains(e.Error(), "admitted_storage") {
		t.Fatalf("empty/skipped stage passed: %v", e)
	}
}

const cleanAttr = `1 perf_event_open({type=PERF_TYPE_SOFTWARE, size=PERF_ATTR_SIZE_VER5, config=PERF_COUNT_SW_CPU_CLOCK, sample_freq=99, sample_type=PERF_SAMPLE_IP|PERF_SAMPLE_TID|PERF_SAMPLE_TIME|PERF_SAMPLE_CALLCHAIN|PERF_SAMPLE_CPU|PERF_SAMPLE_PERIOD, read_format=0, disabled=1, inherit=0, exclude_kernel=1, exclude_hv=1, mmap=0, comm=1, freq=1, task=1, precise_ip=0 /* arbitrary skid */, mmap_data=0, sample_id_all=1, exclude_callchain_kernel=1, mmap2=0, comm_exec=1, use_clockid=1, context_switch=0, wakeup_events=1, bp_type=HW_BREAKPOINT_EMPTY, config1=0, config2=0, branch_sample_type=0, sample_regs_user=0, sample_stack_user=0, clockid=CLOCK_MONOTONIC, sample_regs_intr=0, aux_watermark=0, sample_max_stack=127, aux_sample_size=0}, 7, -1, -1, PERF_FLAG_FD_CLOEXEC) = 17`

func TestStraceAuditAcceptsCleanAndFlagsEachForbiddenForm(t *testing.T) {
	p := testPolicy(t)
	audit := func(s string) []Finding {
		t.Helper()
		f, _, e := AuditStrace(p, strings.NewReader(s))
		if e != nil {
			t.Fatal(e)
		}
		return f
	}
	if f := audit(cleanAttr + "\n1 ioctl(17, PERF_EVENT_IOC_ENABLE, 0) = 0\n"); len(f) != 0 {
		t.Fatalf("clean run flagged: %v", f)
	}
	_, sum, _ := AuditStrace(p, strings.NewReader(cleanAttr+"\n"))
	if sum.PerfEventOpens != 1 || sum.CPUOpens != 1 {
		t.Fatalf("summary does not show the observed open: %+v", sum)
	}
	mutate := map[string]string{
		"perf_attr_sample_type":  strings.Replace(cleanAttr, "PERF_SAMPLE_PERIOD", "PERF_SAMPLE_PERIOD|PERF_SAMPLE_STACK_USER", 1),
		"perf_attr_sample_type2": strings.Replace(cleanAttr, "PERF_SAMPLE_PERIOD", "PERF_SAMPLE_PERIOD|PERF_SAMPLE_REGS_USER", 1),
		"perf_attr_nonzero":      strings.Replace(cleanAttr, "sample_regs_user=0", "sample_regs_user=0xff", 1),
		"perf_attr_nonzero2":     strings.Replace(cleanAttr, "sample_stack_user=0", "sample_stack_user=8192", 1),
		"perf_attr_nonzero3":     strings.Replace(cleanAttr, "mmap=0", "mmap=1", 1),
		"perf_attr_required":     strings.Replace(cleanAttr, "disabled=1", "disabled=0", 1),
		"perf_attr_required2":    strings.Replace(cleanAttr, "exclude_callchain_kernel=1, ", "", 1),
		"perf_attr_type":         strings.Replace(cleanAttr, "PERF_TYPE_SOFTWARE", "PERF_TYPE_BREAKPOINT", 1),
		"perf_attr_truncated":    strings.Replace(cleanAttr, ", read_format=0,", ", ...", 1),
		"forbidden_syscall":      "1 ptrace(PTRACE_SEIZE, 4242, NULL, 0) = 0",
		"forbidden_syscall2":     "1 process_vm_readv(4242, [{iov_base=0x1, iov_len=8}], 1, [{iov_base=0x2, iov_len=8}], 1, 0) = 8",
		"forbidden_syscall3":     "1 bpf(BPF_PROG_LOAD, {prog_type=BPF_PROG_TYPE_KPROBE}, 128) = 3",
		"forbidden_perf_ioctl":   "1 ioctl(17, PERF_EVENT_IOC_SET_BPF, 5) = 0",
		"forbidden_open_path":    `1 openat(AT_FDCWD, "/proc/4242/mem", O_RDONLY) = 5`,
		"forbidden_open_path2":   `1 openat(AT_FDCWD, "/proc/self/task/9/environ", O_RDONLY) = 5`,
		"forbidden_dump_name":    `1 openat(AT_FDCWD, "/var/tmp/perf.data", O_WRONLY|O_CREAT|O_TRUNC, 0600) = 5`,
		"forbidden_dump_name2":   `1 openat(AT_FDCWD, "/tmp/core.1234", O_WRONLY|O_CREAT, 0600) = 5`,
		"forbidden_tracefs":      `1 openat(AT_FDCWD, "/sys/kernel/tracing/trace_pipe", O_RDONLY) = 5`,
	}
	for name, line := range mutate {
		if f := audit(line + "\n"); len(f) == 0 {
			t.Errorf("%s: not flagged", name)
		}
	}
	// The scheduler tracepoint rule allows RAW only for PERF_TYPE_TRACEPOINT.
	cpuRaw := strings.Replace(cleanAttr, "PERF_SAMPLE_PERIOD", "PERF_SAMPLE_RAW", 1)
	if f := audit(cpuRaw + "\n"); len(f) == 0 {
		t.Fatal("PERF_SAMPLE_RAW allowed on the CPU event")
	}
	sched := strings.NewReplacer("PERF_TYPE_SOFTWARE", "PERF_TYPE_TRACEPOINT", "PERF_SAMPLE_IP|", "", "|PERF_SAMPLE_PERIOD", "|PERF_SAMPLE_RAW").Replace(cleanAttr)
	if f := audit(sched + "\n"); len(f) != 0 {
		t.Fatalf("scheduler tracepoint attribute refused: %v", f)
	}
	probe := strings.NewReplacer("PERF_ATTR_SIZE_VER5", "PERF_ATTR_SIZE_VER0", "exclude_callchain_kernel=1, ", "", "sample_id_all=1, ", "", "use_clockid=1, ", "").Replace(cleanAttr)
	if f := audit(probe + "\n"); len(f) != 0 {
		t.Fatalf("disabled VER0 capability probe flagged: %v", f)
	}
	if f := audit(strings.Replace(probe, "PERF_ATTR_SIZE_VER0", "PERF_ATTR_SIZE_VER5", 1) + "\n"); len(f) == 0 {
		t.Fatal("a VER5 sampling event without its required flags was accepted")
	}
	if f := audit(`1 openat(AT_FDCWD, "/repo/packages/core", O_RDONLY|O_DIRECTORY) = 5` + "\n"); len(f) != 0 {
		t.Fatalf("read-only open of a directory named core flagged: %v", f)
	}
	for _, f := range audit(`1 openat(AT_FDCWD, "/tmp/SPCNRY-PATH-a1b2c3/perf.data", O_WRONLY|O_CREAT) = 5` + "\n") {
		if strings.Contains(f.String(), testNonce) {
			t.Fatal("finding echoes the sentinel nonce")
		}
	}
}
