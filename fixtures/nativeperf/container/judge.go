//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"strings"
)

// capture is the one JSON line tools/smoke/nativehelper/client prints for `capture`: what the helper's protocol returned
// for a signed request, never something the harness inferred.
type capture struct {
	Mode               string  `json:"mode"`
	Outcome            string  `json:"outcome"` // samples, no_samples, refused
	Error              string  `json:"error,omitempty"`
	ErrorStatus        string  `json:"error_status,omitempty"`
	ErrorReason        string  `json:"error_reason,omitempty"`
	AuthorizationError bool    `json:"authorization_denied,omitempty"`
	ResourceError      bool    `json:"resource_limit,omitempty"`
	Samples            uint64  `json:"cpu_samples"`
	TargetSamples      uint64  `json:"samples_of_target_process"`
	WithUserFrames     uint64  `json:"samples_with_user_frames"`
	HotSymbol          string  `json:"hot_symbol"`
	HotSymbolSamples   uint64  `json:"samples_resolved_to_hot_symbol"`
	Threads            int     `json:"threads_observed"`
	LossEvents         uint64  `json:"loss_events"`
	LostRecords        uint64  `json:"lost_records"`
	StreamEnd          string  `json:"stream_end,omitempty"`
	CaptureSeconds     float64 `json:"capture_seconds"`
	MethodUnit         string  `json:"method_unit,omitempty"`
}

// clientStopped is the stream end the client records when it ended the capture itself, which is the only
// complete-looking end.
const clientStopped = "client stopped the capture"

// typedDenied is the closed denied result: refused with status denied and reason permission_denied, zero samples.
func (c capture) typedDenied() bool {
	return c.Outcome == "refused" && c.ErrorStatus == "denied" && c.ErrorReason == "permission_denied" && c.Samples == 0
}

// sampled is a real capture: samples exist, every one is the target's, and most resolve to the workload's hot function.
func (c capture) sampled() (bool, string) {
	switch {
	case c.Outcome != "samples" || c.Samples == 0:
		return false, "no samples were received"
	case c.TargetSamples != c.Samples:
		return false, fmt.Sprintf("only %d of %d samples are the target's", c.TargetSamples, c.Samples)
	case c.HotSymbolSamples*2 < c.Samples:
		return false, fmt.Sprintf("only %d of %d samples resolve to %s", c.HotSymbolSamples, c.Samples, c.HotSymbol)
	case c.StreamEnd != "" && c.StreamEnd != clientStopped:
		return false, "the stream ended on its own: " + c.StreamEnd
	}
	return true, ""
}

// observed names what the helper did, in the closed vocabulary of the report.
func (c capture) observed() string {
	switch {
	case c.typedDenied():
		return "denied"
	case c.Outcome == "samples":
		return "samples"
	case c.Outcome == "no_samples":
		return "no_samples"
	case c.AuthorizationError:
		return "refused_authorization"
	case c.ResourceError:
		return "refused_resources"
	case c.Outcome == "refused":
		return "refused"
	}
	return "no_result"
}

// expectation is what one scenario requires of the helper's answer.
type expectation string

const (
	// wantSamples: a complete capture of the target (samples, all the target's, resolved to the hot symbol).
	wantSamples expectation = "samples"
	// wantDenied: the typed denied result with zero samples. Never an empty capture, never unsupported.
	wantDenied expectation = "denied"
	// wantRefusedAuthorization: the request was refused as unauthorized (the policy names another instance).
	wantRefusedAuthorization expectation = "refused_authorization"
	// wantNoSuccess: whatever the helper did, it was not a success: no complete-looking capture and no zero-sample
	// success (a limit killed or refused it, and the stream says so).
	wantNoSuccess expectation = "no_success"
)

// judge decides whether the helper's answer is the one the scenario requires.
func judge(want expectation, c capture) (observed string, ok bool, why string) {
	observed = c.observed()
	switch want {
	case wantSamples:
		if ok, why := c.sampled(); !ok {
			return observed, false, why + " (outcome " + quote(c.Outcome) + ", error " + quote(c.Error) + ")"
		}
		return observed, true, ""
	case wantDenied:
		if !c.typedDenied() {
			return observed, false, "want the typed denied result (denied/permission_denied, zero samples), got outcome " + quote(c.Outcome) +
				" status " + quote(c.ErrorStatus) + " reason " + quote(c.ErrorReason) + " samples " + fmt.Sprint(c.Samples) + " error " + quote(c.Error)
		}
		return observed, true, ""
	case wantRefusedAuthorization:
		if c.Outcome != "refused" || !c.AuthorizationError || c.Samples != 0 {
			return observed, false, "want a refusal as unauthorized with zero samples, got outcome " + quote(c.Outcome) + " error " + quote(c.Error)
		}
		return observed, true, ""
	case wantNoSuccess:
		return observed, noSuccess(c) == "", noSuccess(c)
	}
	return observed, false, "unknown expectation " + string(want)
}

// noSuccess returns "" when the answer is an explicit failure and a reason when it looks like a success. A capture
// that delivered samples is only acceptable if its stream says it ended for a reason other than the client stopping it.
func noSuccess(c capture) string {
	switch {
	case c.Outcome == "no_samples":
		return "a zero-sample capture was reported as a successful capture"
	case c.Outcome == "samples" && (c.StreamEnd == "" || c.StreamEnd == clientStopped):
		return fmt.Sprintf("a capture of %d samples ended as if complete (stream end %q) although the limit was hit", c.Samples, c.StreamEnd)
	case c.Outcome != "samples" && c.Outcome != "refused":
		return "the client produced no typed outcome: " + quote(c.Outcome)
	}
	return ""
}

func quote(s string) string { return fmt.Sprintf("%q", s) }

// audit is what the kernel applied to the running helper (from /proc/<pid>/status and mountinfo): the settings the
// runtime really installed, not the ones the bundle asked for.
type audit struct {
	CapEff, CapPrm, CapBnd, CapAmb string
	NoNewPrivs                     string
	Seccomp                        string
	RootMountOptions               string
	NetNSIsHost                    bool
	PIDNS                          string
	UID                            string
}

// capPerfmon is the CAP_PERFMON (bit 38) mask in /proc/<pid>/status form.
const capPerfmon = "0000004000000000"

const capNone = "0000000000000000"

// auditProblems compares the applied settings with the shipped recipe: exactly CAP_PERFMON (or nothing), no_new_privs,
// seccomp filter mode, read-only root, host network namespace (this harness never creates a network namespace).
func auditProblems(a audit, wantPerfmon, wantSeccomp bool) []string {
	var out []string
	want := capNone
	if wantPerfmon {
		want = capPerfmon
	}
	for _, c := range [][2]string{{"CapEff", a.CapEff}, {"CapPrm", a.CapPrm}, {"CapBnd", a.CapBnd}} {
		if c[1] != want {
			out = append(out, fmt.Sprintf("%s is %s, want %s", c[0], c[1], want))
		}
	}
	if a.CapAmb != capNone {
		out = append(out, "CapAmb is "+a.CapAmb+", want none")
	}
	if a.NoNewPrivs != "1" {
		out = append(out, "NoNewPrivs is "+quote(a.NoNewPrivs)+", want 1")
	}
	if wantSeccomp && a.Seccomp != "2" {
		out = append(out, "Seccomp is "+quote(a.Seccomp)+", want 2 (filter)")
	}
	if !strings.HasPrefix(a.RootMountOptions, "ro,") && a.RootMountOptions != "ro" {
		out = append(out, "root filesystem mount options "+quote(a.RootMountOptions)+" are not read-only")
	}
	if !a.NetNSIsHost {
		out = append(out, "the container has its own network namespace (the harness must not create one)")
	}
	return out
}
