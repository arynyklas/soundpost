//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
)

func good() capture {
	return capture{Outcome: "samples", Samples: 100, TargetSamples: 100, HotSymbolSamples: 100, HotSymbol: "main.hot", StreamEnd: clientStopped}
}

func denied() capture {
	return capture{Outcome: "refused", ErrorStatus: "denied", ErrorReason: "permission_denied", Error: "native profiling: denied: permission_denied"}
}

func TestJudgeSamplesRequiresACompleteAttributedCapture(t *testing.T) {
	if _, ok, why := judge(wantSamples, good()); !ok {
		t.Fatalf("a complete capture of the target must pass: %s", why)
	}
	for name, mutate := range map[string]func(*capture){
		"zero samples as success":       func(c *capture) { c.Samples, c.TargetSamples, c.HotSymbolSamples = 0, 0, 0 },
		"samples outside the target":    func(c *capture) { c.TargetSamples = 99 },
		"samples not in the hot symbol": func(c *capture) { c.HotSymbolSamples = 40 },
		"stream cut by an error":        func(c *capture) { c.StreamEnd = "native profiling: acquisition failed" },
		"refused":                       func(c *capture) { *c = denied() },
	} {
		c := good()
		mutate(&c)
		if _, ok, _ := judge(wantSamples, c); ok {
			t.Errorf("%s must not be an approved capture", name)
		}
	}
}

func TestJudgeDeniedIsOnlyTheTypedDeniedResult(t *testing.T) {
	if obs, ok, why := judge(wantDenied, denied()); !ok || obs != "denied" {
		t.Fatalf("typed denied must pass: %s %s", obs, why)
	}
	for name, c := range map[string]capture{
		"samples":                      good(),
		"no_samples (empty success)":   {Outcome: "no_samples"},
		"unsupported":                  {Outcome: "refused", ErrorStatus: "unsupported", ErrorReason: "event_unavailable"},
		"denied with samples":          {Outcome: "refused", ErrorStatus: "denied", ErrorReason: "permission_denied", Samples: 3},
		"authorization refusal":        {Outcome: "refused", AuthorizationError: true},
		"denied with another reason":   {Outcome: "refused", ErrorStatus: "denied", ErrorReason: "target_identity"},
		"no result at all":             {},
		"resource refusal":             {Outcome: "refused", ResourceError: true},
		"client could not ask (error)": {Outcome: "client_error"},
	} {
		if _, ok, _ := judge(wantDenied, c); ok {
			t.Errorf("%s must not satisfy the denied expectation", name)
		}
	}
}

func TestJudgeAuthorizationRefusal(t *testing.T) {
	if _, ok, why := judge(wantRefusedAuthorization, capture{Outcome: "refused", AuthorizationError: true}); !ok {
		t.Fatalf("an authorization refusal must pass: %s", why)
	}
	if _, ok, _ := judge(wantRefusedAuthorization, denied()); ok {
		t.Error("a permission denial is not an authorization refusal")
	}
	if _, ok, _ := judge(wantRefusedAuthorization, capture{Outcome: "refused", AuthorizationError: true, Samples: 1}); ok {
		t.Error("an authorization refusal with samples is not a refusal")
	}
}

func TestJudgeNoSuccessNeverAcceptsACompleteLookingCapture(t *testing.T) {
	for name, c := range map[string]capture{
		"refused":                     {Outcome: "refused", Error: "native resource budget exceeded", ResourceError: true},
		"authorization":               {Outcome: "refused", AuthorizationError: true},
		"stream killed after samples": {Outcome: "samples", Samples: 120, StreamEnd: "native profiling: acquisition failed"},
	} {
		if _, ok, why := judge(wantNoSuccess, c); !ok {
			t.Errorf("%s must be accepted as a non-success: %s", name, why)
		}
	}
	for name, c := range map[string]capture{
		"complete capture":      good(),
		"zero-sample success":   {Outcome: "no_samples"},
		"samples, empty end":    {Outcome: "samples", Samples: 5},
		"samples, no result":    {Outcome: "weird"},
		"truncated but cleaner": {Outcome: "samples", Samples: 5, StreamEnd: clientStopped},
		"client error":          {Outcome: "client_error"},
	} {
		if _, ok, _ := judge(wantNoSuccess, c); ok {
			t.Errorf("%s must be rejected as a success of a limit-hit scenario", name)
		}
	}
}

func TestAuditProblems(t *testing.T) {
	ok := audit{CapEff: capPerfmon, CapPrm: capPerfmon, CapBnd: capPerfmon, CapAmb: capNone, NoNewPrivs: "1", Seccomp: "2", RootMountOptions: "ro,relatime", NetNSIsHost: true}
	if p := auditProblems(ok, true, true); len(p) != 0 {
		t.Fatalf("the shipped settings must audit clean: %v", p)
	}
	if p := auditProblems(ok, false, true); len(p) != 3 {
		t.Errorf("a PERFMON helper audited as capability-free must report CapEff, CapPrm, CapBnd: %v", p)
	}
	for name, mutate := range map[string]func(*audit){
		"extra capability":   func(a *audit) { a.CapEff = "0000004000000001" },
		"ambient capability": func(a *audit) { a.CapAmb = capPerfmon },
		"no_new_privs off":   func(a *audit) { a.NoNewPrivs = "0" },
		"no seccomp filter":  func(a *audit) { a.Seccomp = "0" },
		"writable root":      func(a *audit) { a.RootMountOptions = "rw,relatime" },
		"own network ns":     func(a *audit) { a.NetNSIsHost = false },
	} {
		a := ok
		mutate(&a)
		if p := auditProblems(a, true, true); len(p) == 0 {
			t.Errorf("%s must be reported", name)
		}
	}
	a := ok
	a.Seccomp = "0"
	if p := auditProblems(a, true, false); len(p) != 0 {
		t.Errorf("seccomp is only audited when the scenario installs a profile: %v", p)
	}
}

func TestLimitProblems(t *testing.T) {
	files := map[string]string{"pids.max": "16", "memory.max": "67108864", "cpu.max": "100000 100000", "pids.events": "max 0", "memory.events": "low 0;high 0;max 7;oom 0;oom_kill 0"}
	if p := limitProblems("helper", files, shippedLimits()); len(p) != 0 {
		t.Fatalf("applied limits without events must be clean (memory.events max is pressure only): %v", p)
	}
	files["pids.events"] = "max 2"
	files["memory.events"] = "low 0;high 0;max 7;oom 1;oom_kill 1"
	files["memory.max"] = "max"
	p := strings.Join(limitProblems("helper", files, shippedLimits()), "|")
	for _, want := range []string{"pids limit 2", "memory.max is \"max\"", "oom=1", "oom_kill=1"} {
		if !strings.Contains(p, want) {
			t.Errorf("missing %q in %s", want, p)
		}
	}
}
