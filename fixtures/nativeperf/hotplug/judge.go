//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package main

import (
	"fmt"
	"reflect"

	"github.com/arynyklas/soundpost/internal/nativeperf"
)

type scenarioKind string

const (
	// kindControl is a capture without any hotplug: it proves the capture path of this host completes, so a refusal in
	// the hotplug scenarios is caused by the hotplug.
	kindControl scenarioKind = "control"
	// kindHold takes the CPU offline, keeps it offline and brings it back while a scheduler capture is live.
	kindHold scenarioKind = "hold"
	// kindFlap takes the CPU offline and back with nothing in between: the online set a poller compares is the same
	// before and after, but the kernel has dropped every per-CPU event of that CPU.
	kindFlap scenarioKind = "flap"
	// kindFlapSparse is kindFlap on a target that wakes only about ten times a second: the capture sees few events, so
	// it has only its periodic check to notice a CPU that was away for a few tens of milliseconds. It runs several
	// times (-sparse-runs): a capture that misses the flap completes while the ring of that CPU is dead.
	kindFlapSparse scenarioKind = "flap_sparse"
	// kindCPUOnly does the same under the per-thread CPU capture (no per-CPU ring exists to lose).
	kindCPUOnly scenarioKind = "cpu_only"
)

// window is one sysfs write, in CLOCK_MONOTONIC nanoseconds (the clock of every event): Start is taken before the
// write and End after it returned, which for the online switch is after the kernel finished the transition.
type window struct {
	Start uint64 `json:"start_ns"`
	End   uint64 `json:"end_ns"`
}

func (w window) done() bool { return w.End != 0 }

// captureView is what one capture over the helper socket showed the consumer.
type captureView struct {
	Ready       bool     `json:"ready"`
	ErrorCode   string   `json:"helper_error_code,omitempty"`
	ReadError   string   `json:"read_error,omitempty"`
	Complete    bool     `json:"complete"`
	InitialCPUs []uint32 `json:"initial_proof_cpus"`
	Progress    int      `json:"progress_proofs"`
	FinalProof  bool     `json:"final_proof"`
	FinalCPUs   []uint32 `json:"final_proof_cpus,omitempty"`
	Events      int      `json:"events"`
	LossEvents  int      `json:"loss_events"`
	StartedNs   uint64   `json:"started_ns"`
	EndedNs     uint64   `json:"ended_ns"`

	// Events of the offlined CPU (the ring of that CPU, or a task sample taken there) by window, and every event after
	// the CPU came back.
	OnCPUBefore    int `json:"events_on_cpu_before_offline"`
	OnCPUWhileOff  int `json:"events_on_cpu_while_offline"`
	OnCPUAfterPin  int `json:"events_on_cpu_after_repin"`
	AfterOnline    int `json:"events_after_online"`
	SchedOnCPUPin  int `json:"scheduler_events_on_cpu_after_repin"`
	SchedOnCPUPre  int `json:"scheduler_events_on_cpu_before_offline"`
	SchedWhileOff  int `json:"scheduler_events_on_cpu_while_offline"`
	SchedAfterBack int `json:"scheduler_events_after_online"`

	// The correlation the consumer built from the stream (scheduler captures only).
	Revoked        bool   `json:"revoked"`
	ProvenThrough  uint64 `json:"proven_through_ns"`
	Intervals      int    `json:"intervals"`
	Negative       int    `json:"negative_intervals"`
	Corrections    int    `json:"corrections"`
	CorrectionFrom uint64 `json:"correction_start_ns"`
	CorrectionTo   uint64 `json:"correction_end_ns"`
	CorrectionWhy  string `json:"correction_reason,omitempty"`
	// Overlapped intervals are measured intervals a correction replaces (the consumer drops them, splitting a straddling
	// one); NewerThanCorrection ones would be evidence from after the stream ended.
	Overlapped          int    `json:"intervals_overlapped_by_correction"`
	Straddling          int    `json:"intervals_straddling_correction_start"`
	NewerThanCorrection int    `json:"intervals_newer_than_correction"`
	Invalid             int    `json:"invalid_intervals"`
	CorrelationErr      string `json:"correlation_error,omitempty"`
}

type scenarioResult struct {
	Name   string       `json:"scenario"`
	Kind   scenarioKind `json:"kind"`
	Mode   string       `json:"mode"`
	CPU    uint32       `json:"cpu"`
	HoldMS int64        `json:"hold_ms"`

	OnlineBefore string `json:"online_before"`
	OnlineAfter  string `json:"online_after"`
	Offline      window `json:"offline_write"`
	Online       window `json:"online_write"`
	Repinned     uint64 `json:"repinned_ns"`
	// RanAfterRepin is the harness' own observation (/proc/<tid>/stat: running, on that CPU) that the target executed on
	// the CPU after it came back.
	RanAfterRepin bool         `json:"target_ran_on_cpu_after_repin"`
	Capture       captureView  `json:"capture"`
	Recapture     *captureView `json:"recapture,omitempty"`

	HelperAlive       bool `json:"helper_alive_after"`
	HelperFDsReleased bool `json:"helper_fds_back_to_baseline"`
	TargetAlive       bool `json:"target_alive_after_capture"`

	// SetupError is a failure of the harness' own setup (launch, pin, helper start, restore): never a pass.
	SetupError string `json:"setup_error,omitempty"`
	// NotExercised is set when the hotplug itself could not be done (the kernel refused the write): never a pass.
	NotExercised string   `json:"not_exercised,omitempty"`
	Failures     []string `json:"failures,omitempty"`
	Pass         bool     `json:"pass"`
}

// judge applies the plan's requirements to one scenario: CPU hotplug resets the correlation generation and is refused
// or reported explicitly, never silently complete; no interval is negative or crosses the boundary; the helper and the
// target survive; and a capture opened on the restored topology is a clean new epoch.
func judge(r *scenarioResult) {
	var fails []string
	fail := func(format string, args ...any) { fails = append(fails, fmt.Sprintf(format, args...)) }
	defer func() { r.Failures, r.Pass = fails, len(fails) == 0 && r.NotExercised == "" }()

	if r.NotExercised != "" {
		return
	}
	if r.SetupError != "" {
		fail("harness setup: %s", r.SetupError)
		return
	}
	c := &r.Capture
	if !c.Ready {
		fail("the capture was not admitted (helper code %q, read error %q)", c.ErrorCode, c.ReadError)
		return
	}
	if r.OnlineAfter != r.OnlineBefore {
		fail("the online set was %q before and %q after the scenario: the CPU was not restored", r.OnlineBefore, r.OnlineAfter)
	}
	if !r.HelperAlive {
		fail("the helper process did not survive the topology change")
	}
	if !r.HelperFDsReleased {
		fail("the helper did not release its descriptors after the stream ended")
	}
	if !r.TargetAlive {
		fail("the target workload did not survive the capture")
	}
	if c.Negative != 0 || c.Invalid != 0 {
		fail("%d negative and %d invalid intervals", c.Negative, c.Invalid)
	}
	if c.CorrelationErr != "" {
		fail("the consumer's correlation failed: %s", c.CorrelationErr)
	}

	switch r.Kind {
	case kindControl:
		judgeCompleteCapture(c, r.OnlineBefore, r.CPU, fail, "control capture")
	case kindHold, kindFlap, kindFlapSparse:
		if !r.Offline.done() || !r.Online.done() {
			fail("the hotplug did not happen (offline write %+v, online write %+v)", r.Offline, r.Online)
			return
		}
		if c.SchedOnCPUPre == 0 {
			fail("the target produced no scheduler event on cpu%d before it was taken offline: the scenario would prove nothing", r.CPU)
		}
		if c.SchedWhileOff != 0 {
			fail("%d scheduler events on cpu%d AFTER its offline write returned: the premise (an offline CPU emits nothing) does not hold", c.SchedWhileOff, r.CPU)
		}
		if !reflect.DeepEqual(c.InitialCPUs, parseList(r.OnlineBefore)) {
			fail("the capture's initial topology proof %v is not the online set %s", c.InitialCPUs, r.OnlineBefore)
		}
		refused := c.ErrorCode != "" || c.ReadError != ""
		switch {
		case refused:
			judgeRefusal(r, fail)
		case r.Kind == kindHold:
			fail("the capture ended without an error although cpu%d was offline for %d ms: it claimed a complete capture over a changed topology (complete=%t final proof=%t)", r.CPU, r.HoldMS, c.Complete, c.FinalProof)
		default:
			// An unannounced flap: the capture may only complete if every CPU stream really still delivers. The target
			// was observed running on the CPU after it came back; a complete capture with no scheduler event from there is a
			// silent loss of that CPU's coverage under a final proof that claims it.
			if !c.Complete || !c.FinalProof {
				fail("the capture ended without an error and without a final proof (complete=%t final proof=%t)", c.Complete, c.FinalProof)
			}
			if !r.RanAfterRepin {
				fail("the target was never observed running on cpu%d after it came back: the liveness check has no ground truth", r.CPU)
			} else if c.SchedOnCPUPin == 0 {
				fail("silent coverage loss: the capture completed with a final proof over cpus %v, the target ran on cpu%d after it came back, and that CPU's scheduler stream delivered no event", c.FinalCPUs, r.CPU)
			}
		}
		if r.Recapture == nil {
			fail("no capture was opened on the restored topology")
		} else {
			judgeCompleteCapture(r.Recapture, r.OnlineBefore, r.CPU, fail, "capture on the restored topology")
			if r.Recapture.Negative != 0 {
				fail("restored-topology capture: %d negative intervals", r.Recapture.Negative)
			}
			if r.Recapture.SchedOnCPUPre == 0 && r.Recapture.SchedAfterBack == 0 {
				fail("restored-topology capture: no scheduler event at all")
			}
		}
	case kindCPUOnly:
		if !r.Offline.done() || !r.Online.done() {
			fail("the hotplug did not happen (offline write %+v, online write %+v)", r.Offline, r.Online)
			return
		}
		if c.ErrorCode != "" || c.ReadError != "" {
			fail("the per-thread CPU capture was ended by the hotplug (helper code %q, read error %q): it owns no per-CPU stream", c.ErrorCode, c.ReadError)
		}
		if c.OnCPUBefore == 0 {
			fail("no CPU sample on cpu%d before it was taken offline", r.CPU)
		}
		if c.OnCPUWhileOff != 0 {
			fail("%d CPU samples on cpu%d while it was offline", c.OnCPUWhileOff, r.CPU)
		}
		if c.AfterOnline == 0 {
			fail("no CPU sample arrived after the CPU came back: the capture stopped delivering")
		}
		if !r.RanAfterRepin {
			fail("the target was never observed running on cpu%d after it came back", r.CPU)
		} else if c.OnCPUAfterPin == 0 {
			fail("the target ran on cpu%d after it came back and no CPU sample carried that CPU", r.CPU)
		}
	}
}

// judgeRefusal is the required behaviour of a scheduler capture whose topology changed: an explicit closed error, no
// final proof, and a consumer-side correction that covers the change.
func judgeRefusal(r *scenarioResult, fail func(string, ...any)) {
	c := &r.Capture
	if c.ErrorCode != string(topologyChanged) {
		fail("the capture ended with helper code %q, want %q", c.ErrorCode, topologyChanged)
	}
	if c.Complete || c.FinalProof {
		fail("a capture refused with %q still reports complete=%t final proof=%t", c.ErrorCode, c.Complete, c.FinalProof)
	}
	if latency := int64(c.EndedNs) - int64(r.Offline.Start); latency > detectionBudgetNs {
		fail("the topology change was reported %d ms after the offline write (budget %d ms)", latency/1_000_000, detectionBudgetNs/1_000_000)
	}
	if !c.Revoked {
		fail("the consumer was never told to revoke the unproven tail: no correction covers the topology change")
		return
	}
	if c.CorrectionWhy != string(nativeperf.ReasonGeneration) {
		fail("the revoked stream carries no domain-wide %q correction (%d corrections of other kinds)", nativeperf.ReasonGeneration, c.Corrections)
		return
	}
	if c.CorrectionFrom > r.Offline.End || c.CorrectionTo < r.Offline.Start {
		fail("the correction [%d, %d) does not cover the offline write [%d, %d]", c.CorrectionFrom, c.CorrectionTo, r.Offline.Start, r.Offline.End)
	}
	if c.NewerThanCorrection != 0 {
		fail("%d measured intervals end after the correction does: evidence from beyond the end of the stream", c.NewerThanCorrection)
	}
	// The stream names the last instant it verified the topology and every ring: the consumer keeps the proven prefix and
	// revokes from there, not from the first instant of the capture.
	switch {
	case c.ProvenThrough == 0:
		fail("the topology error carried no proven-through instant: the consumer had to revoke the whole capture from its first instant")
	case c.ProvenThrough > r.Offline.End:
		fail("the stream claims everything proven through %d, after the offline write returned at %d", c.ProvenThrough, r.Offline.End)
	case int64(r.Offline.Start)-int64(c.ProvenThrough) > provenBudgetNs:
		fail("the last proof is %d ms older than the offline write (budget %d ms)", (int64(r.Offline.Start)-int64(c.ProvenThrough))/1_000_000, provenBudgetNs/1_000_000)
	case c.CorrectionFrom > c.ProvenThrough:
		fail("the correction starts at %d, after the proof it was revoked from (%d): a hole between them", c.CorrectionFrom, c.ProvenThrough)
	}
}

// judgeCompleteCapture is what a capture that really ran to its end owes: no error, a final proof over the whole
// online set, and a topology proof of that set at the start.
func judgeCompleteCapture(c *captureView, online string, cpu uint32, fail func(string, ...any), what string) {
	switch {
	case !c.Ready:
		fail("%s: not admitted (helper code %q)", what, c.ErrorCode)
		return
	case c.ErrorCode != "" || c.ReadError != "":
		fail("%s: ended with helper code %q, read error %q", what, c.ErrorCode, c.ReadError)
		return
	case !c.Complete || !c.FinalProof:
		fail("%s: complete=%t final proof=%t", what, c.Complete, c.FinalProof)
		return
	}
	want := parseList(online)
	if !reflect.DeepEqual(c.InitialCPUs, want) || !reflect.DeepEqual(c.FinalCPUs, want) {
		fail("%s: proofs cover cpus %v then %v, the online set is %v", what, c.InitialCPUs, c.FinalCPUs, want)
	}
	if c.Revoked {
		fail("%s: revoked on a topology that did not change", what)
	}
	if c.SchedOnCPUPre == 0 && c.SchedAfterBack == 0 && c.OnCPUBefore == 0 && c.OnCPUAfterPin == 0 {
		fail("%s: no event from cpu%d at all", what, cpu)
	}
}

const (
	topologyChanged = "topology_changed"
	// detectionBudgetNs bounds how long after the offline write a live capture may take to report it: the product
	// compares the online set every 100 ms.
	detectionBudgetNs int64 = 3_000_000_000
	// provenBudgetNs bounds how old the last proof a topology error names may be: the topology is verified every 10 to
	// 100 ms while the capture runs.
	provenBudgetNs int64 = 1_000_000_000
)

func parseList(text string) []uint32 {
	cpus, err := parseCPUList(text)
	if err != nil {
		return nil
	}
	return cpus
}
